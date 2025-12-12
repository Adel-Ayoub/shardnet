/// Waiter abstraction for async I/O event notification.
///
/// Provides an event-driven queue where protocol layers (TCP, UDP, ARP)
/// post readiness notifications and the POSIX / event-loop layer waits for
/// them. Each Queue is an intrusive doubly-linked list of Entry nodes so
/// registration and removal are O(1) with no heap allocation.
///
/// Thread-safety assumptions:
///   - A single Queue is accessed from one thread at a time (the stack's
///     event-loop thread). External callers that share a Queue across
///     threads must provide their own mutex.
///   - Entry nodes must outlive their registration. The Queue does not
///     take ownership.
const std = @import("std");

// ---------------------------------------------------------------------------
// Event mask constants
// ---------------------------------------------------------------------------

pub const EventMask = u16;

pub const EventIn: EventMask = 0x01; // Data available for reading (POLLIN).
pub const EventPri: EventMask = 0x02; // Urgent data (POLLPRI).
pub const EventOut: EventMask = 0x04; // Space available for writing (POLLOUT).
pub const EventErr: EventMask = 0x08; // Error condition (POLLERR).
pub const EventHUp: EventMask = 0x10; // Hang-up (POLLHUP).

const all_events: EventMask = 0x1f;

/// Convert a Linux epoll event mask to the internal EventMask.
pub fn eventMaskFromLinux(e: u32) EventMask {
    return @as(EventMask, @truncate(e)) & all_events;
}

/// Convert an internal EventMask to a Linux epoll-compatible u32.
pub fn toLinux(e: EventMask) u32 {
    return @as(u32, e);
}

// ---------------------------------------------------------------------------
// Waiter.State — observable lifecycle of a waiter
// ---------------------------------------------------------------------------

/// Observable state of a Waiter. Useful for debugging and health checks.
pub const State = enum {
    /// Not waiting; initial or post-wake state.
    idle,
    /// Blocked in wait() or timedWait(), waiting for a notification.
    waiting,
    /// A notification has been delivered; the waiter is ready to proceed.
    ready,
    /// The wait was interrupted by an explicit cancel() call.
    cancelled,
};

// ---------------------------------------------------------------------------
// Entry — intrusive list node
// ---------------------------------------------------------------------------

pub const Entry = struct {
    context: ?*anyopaque = null,
    upcall_ctx: ?*anyopaque = null,
    callback: ?*const fn (e: *Entry) void = null,
    mask: EventMask = 0,
    next: ?*Entry = null,
    prev: ?*Entry = null,
    queue: ?*Queue = null,
    is_queued: bool = false,
    active: bool = false,

    /// Current observable state. Updated by wait / notify / cancel.
    state: State = .idle,

    pub fn init(context: ?*anyopaque, callback: ?*const fn (e: *Entry) void) Entry {
        return .{
            .context = context,
            .callback = callback,
        };
    }

    pub fn initWithUpcall(context: ?*anyopaque, upcall_ctx: ?*anyopaque, callback: ?*const fn (e: *Entry) void) Entry {
        return .{
            .context = context,
            .upcall_ctx = upcall_ctx,
            .callback = callback,
        };
    }

    /// Cancel a pending wait, transitioning the entry to .cancelled.
    /// If a condition variable is used externally, the caller must also
    /// signal it after calling cancel().
    // NOTE: cancel() only sets a flag — it does not wake a sleeping thread
    // by itself. The caller's poll / wait loop must check the state or use
    // a condition variable paired with this flag.
    pub fn cancel(self: *Entry) void {
        self.state = .cancelled;
    }

    /// Non-blocking check: returns true if the entry has been notified
    /// (state == .ready) since the last reset, without blocking.
    pub fn tryWait(self: *Entry) bool {
        if (self.state == .ready) {
            // NOTE: Reset to .idle after consumption so the next wait()
            // cycle starts clean. This is intentionally not atomic because
            // we assume single-threaded access per entry.
            self.state = .idle;
            return true;
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Queue — intrusive doubly-linked list of Entry
// ---------------------------------------------------------------------------

pub const Queue = struct {
    next: ?*Queue = null,
    prev: ?*Queue = null,
    head: ?*Entry = null,
    tail: ?*Entry = null,
    ready_mask: EventMask = 0,

    /// Register an entry for the given event mask. If the entry is already
    /// registered on this queue, only the mask is updated (no list mutation).
    pub fn eventRegister(self: *Queue, e: *Entry, mask: EventMask) void {
        if (e.active) {
            if (e.queue == self) {
                e.mask = mask;
                return;
            }
            // NOTE: An entry can only belong to one queue at a time.
            // Unregister from the old queue before re-registering.
            if (e.queue) |q| q.eventUnregister(e);
        }

        e.mask = mask;
        e.active = true;
        e.queue = self;
        e.next = null;
        e.prev = self.tail;

        if (self.tail) |tail| {
            tail.next = e;
        } else {
            self.head = e;
        }
        self.tail = e;
    }

    /// Remove an entry from this queue. Safe to call on an inactive entry
    /// or one registered on a different queue (no-op in both cases).
    pub fn eventUnregister(self: *Queue, e: *Entry) void {
        if (!e.active or e.queue != self) return;

        if (e.prev) |prev| {
            prev.next = e.next;
        } else {
            self.head = e.next;
        }

        if (e.next) |next_entry| {
            next_entry.prev = e.prev;
        } else {
            self.tail = e.prev;
        }

        e.next = null;
        e.prev = null;
        e.active = false;
        e.queue = null;
    }

    /// Fire callbacks for all entries whose mask intersects `mask`.
    /// Also sets the entry's state to .ready so tryWait() callers see it.
    pub fn notify(self: *Queue, mask: EventMask) void {
        self.ready_mask |= mask;

        // Snapshot entries to avoid issues when callbacks modify the list.
        var snapshot: [16384]*Entry = undefined;
        var count: usize = 0;

        var current = self.head;
        while (current) |e| {
            if (count >= 16384) break;
            snapshot[count] = e;
            count += 1;
            current = e.next;
        }

        for (snapshot[0..count]) |e| {
            if (!e.active or e.queue != self) continue;

            if ((mask & e.mask) != 0) {
                // NOTE: Transition to .ready before calling the callback so
                // the callback can observe the state if needed.
                e.state = .ready;
                if (e.callback) |cb| {
                    cb(e);
                }
            }
        }
    }

    /// Clear specific event bits from the ready mask.
    pub fn clear(self: *Queue, mask: EventMask) void {
        self.ready_mask &= ~mask;
    }

    /// Return the union of all registered entries' masks.
    pub fn interests(self: *Queue) EventMask {
        var ret: EventMask = 0;
        var current = self.head;
        while (current) |e| {
            ret |= e.mask;
            current = e.next;
        }
        return ret;
    }

    /// Return the currently asserted events (level-triggered).
    pub fn events(self: *Queue) EventMask {
        return self.ready_mask;
    }

    pub fn isEmpty(self: *Queue) bool {
        return self.head == null;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Queue basic" {
    var q = Queue{};
    var e1 = Entry.init(null, null);
    var e2 = Entry.init(null, null);

    q.eventRegister(&e1, EventIn);
    q.eventRegister(&e2, EventOut);

    try std.testing.expectEqual(EventIn | EventOut, q.interests());
    try std.testing.expect(!q.isEmpty());

    q.eventUnregister(&e1);
    try std.testing.expectEqual(EventOut, q.interests());

    q.eventUnregister(&e2);
    try std.testing.expect(q.isEmpty());
}

test "Queue notify" {
    const Context = struct {
        notified: bool = false,
    };
    var ctx = Context{};
    const callback = struct {
        fn cb(e: *Entry) void {
            const c: *Context = @ptrCast(@alignCast(e.context.?));
            c.notified = true;
        }
    }.cb;

    var q = Queue{};
    var e = Entry.init(&ctx, callback);
    q.eventRegister(&e, EventIn);

    q.notify(EventOut);
    try std.testing.expect(!ctx.notified);

    q.notify(EventIn);
    try std.testing.expect(ctx.notified);
}

test "Entry state transitions" {
    var e = Entry.init(null, null);
    try std.testing.expectEqual(State.idle, e.state);

    // Simulate a notification.
    e.state = .ready;
    try std.testing.expect(e.tryWait());
    try std.testing.expectEqual(State.idle, e.state);

    // tryWait when not ready returns false.
    try std.testing.expect(!e.tryWait());

    // Cancel.
    e.cancel();
    try std.testing.expectEqual(State.cancelled, e.state);
}

test "Queue notify high concurrency" {
    var q = Queue{};
    const count = 10000;
    var entries = try std.testing.allocator.alloc(Entry, count);
    defer std.testing.allocator.free(entries);

    for (0..count) |i| {
        entries[i] = Entry.init(null, null);
        q.eventRegister(&entries[i], EventIn);
    }

    q.notify(EventIn);
}
