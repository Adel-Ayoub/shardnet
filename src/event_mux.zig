/// Event multiplexer bridging the user-space stack's notification model
/// with external event loops (libev, libuv, or raw epoll).
///
/// The EventMultiplexer aggregates waiter.Entry readiness signals into a
/// single eventfd that the external loop watches. When the fd becomes
/// readable, the loop calls `pollReady()` to drain all pending entries and
/// dispatches them to registered handler callbacks.
///
/// Ownership model:
///   - The EventMultiplexer owns the eventfd and the internal queues.
///   - Waiter Entries are *not* owned; callers must ensure entries outlive
///     their registration (see waiter.zig for lifetime rules).
///   - Registered fd handlers (FdHandler) are owned by the caller; the
///     mux only stores a pointer.
const std = @import("std");
const waiter = @import("waiter.zig");

// ---------------------------------------------------------------------------
// Stats — multiplexer-level counters for observability
// ---------------------------------------------------------------------------

pub const MuxStats = struct {
    /// Total events fired (i.e. handler callbacks invoked).
    events_fired: u64 = 0,
    /// Number of times pollReady() returned zero entries despite the
    /// eventfd being readable (race between signal and drain).
    spurious_wakeups: u64 = 0,
    /// Total upcalls received from the stack.
    upcalls_received: u64 = 0,
};

// ---------------------------------------------------------------------------
// FdHandler — per-fd callback for the dispatch() path
// ---------------------------------------------------------------------------

/// A registered callback for a kernel file descriptor. Used by dispatch()
/// to fan out readiness to per-fd handlers (e.g. one per NIC queue).
pub const FdHandler = struct {
    fd: std.posix.fd_t,
    /// Opaque pointer passed to the callback (typically the driver struct).
    user_data: ?*anyopaque = null,
    /// Called when the fd is ready for I/O.
    callback: *const fn (fd: std.posix.fd_t, user_data: ?*anyopaque) void,
    /// When true, the fd is added to epoll with EPOLLET (edge-triggered).
    /// Edge-triggered mode requires the caller to drain all data on each
    /// notification; missing data will not re-trigger.
    edge_triggered: bool = false,
};

// ---------------------------------------------------------------------------
// EventMultiplexer
// ---------------------------------------------------------------------------

pub const EventMultiplexer = struct {
    ready_queue: ReadyQueue,
    signal_fd: std.posix.fd_t,
    allocator: std.mem.Allocator,
    stats: MuxStats = .{},

    /// Registered fd handlers for the dispatch() path.
    fd_handlers: std.ArrayList(FdHandler),

    pub fn init(allocator: std.mem.Allocator) !*EventMultiplexer {
        const self = try allocator.create(EventMultiplexer);

        // NOTE: EFD_NONBLOCK (0x800) is set so reads never block the
        // event loop; a zero-length read simply means "no signal yet".
        const efd = try std.posix.eventfd(0, 0x800);

        self.* = .{
            .ready_queue = ReadyQueue.init(allocator),
            .signal_fd = efd,
            .allocator = allocator,
            .fd_handlers = std.ArrayList(FdHandler).init(allocator),
        };
        return self;
    }

    pub fn deinit(self: *EventMultiplexer) void {
        std.posix.close(self.signal_fd);
        self.ready_queue.deinit();
        self.fd_handlers.deinit();
        self.allocator.destroy(self);
    }

    /// Returns the file descriptor that the external event loop should
    /// watch for READ events.
    pub fn fd(self: *EventMultiplexer) std.posix.fd_t {
        return self.signal_fd;
    }

    // -- Fd handler registration --------------------------------------------

    /// Register an additional fd with a per-fd callback and optional
    /// user_data pointer. The mux does not take ownership of user_data.
    pub fn registerFd(self: *EventMultiplexer, handler: FdHandler) !void {
        try self.fd_handlers.append(handler);
    }

    /// Remove a previously registered fd handler. Compares by fd value.
    pub fn unregisterFd(self: *EventMultiplexer, target_fd: std.posix.fd_t) void {
        var i: usize = 0;
        while (i < self.fd_handlers.items.len) {
            if (self.fd_handlers.items[i].fd == target_fd) {
                _ = self.fd_handlers.orderedRemove(i);
                return;
            }
            i += 1;
        }
    }

    // -- Dispatch -----------------------------------------------------------

    /// Call the registered handler callback for every fd that is ready.
    /// This is used when the mux manages multiple kernel fds (e.g. one
    /// per NIC queue) and needs to fan out readiness.
    pub fn dispatch(self: *EventMultiplexer) void {
        for (self.fd_handlers.items) |handler| {
            handler.callback(handler.fd, handler.user_data);
            self.stats.events_fired += 1;
        }
    }

    // -- Stack-side upcall --------------------------------------------------

    /// The "soupcall" — registered on a socket's wait_queue. Fired by
    /// the stack when data arrives or send-buffer space opens up.
    pub fn upcall(entry: *waiter.Entry) void {
        const self: *EventMultiplexer = @ptrCast(@alignCast(entry.upcall_ctx.?));
        self.stats.upcalls_received += 1;
        if (self.ready_queue.push(entry) catch false) {
            const val: u64 = 1;
            _ = std.posix.write(self.signal_fd, std.mem.asBytes(&val)) catch {};
        }
    }

    // -- Drain ready queue --------------------------------------------------

    /// Drains the eventfd signal and returns all entries that have been
    /// marked ready since the last call. Should be invoked by the libev /
    /// libuv callback when the signal_fd fires.
    pub fn pollReady(self: *EventMultiplexer) ![]*waiter.Entry {
        // Clear the eventfd counter.
        var val: u64 = 0;
        _ = std.posix.read(self.signal_fd, std.mem.asBytes(&val)) catch {};

        const ready = try self.ready_queue.popAll();
        if (ready.len == 0) {
            self.stats.spurious_wakeups += 1;
        }
        self.stats.events_fired += ready.len;
        return ready;
    }

    /// Return a snapshot of the multiplexer's internal statistics.
    pub fn getStats(self: *const EventMultiplexer) MuxStats {
        return self.stats;
    }
};

// ---------------------------------------------------------------------------
// ReadyQueue — simple de-duplicating queue of ready entries
// ---------------------------------------------------------------------------

const ReadyQueue = struct {
    list: std.ArrayList(*waiter.Entry),
    results: std.ArrayList(*waiter.Entry),

    pub fn init(allocator: std.mem.Allocator) ReadyQueue {
        var self = ReadyQueue{
            .list = std.ArrayList(*waiter.Entry).init(allocator),
            .results = std.ArrayList(*waiter.Entry).init(allocator),
        };
        self.list.ensureTotalCapacity(65536) catch {};
        self.results.ensureTotalCapacity(65536) catch {};
        return self;
    }

    pub fn deinit(self: *ReadyQueue) void {
        self.list.deinit();
        self.results.deinit();
    }

    /// Push an entry. Returns true if newly enqueued, false if already
    /// present (de-duplication via the is_queued flag).
    pub fn push(self: *ReadyQueue, entry: *waiter.Entry) !bool {
        if (entry.is_queued) return false;

        try self.list.append(entry);
        entry.is_queued = true;
        return true;
    }

    /// Drain all entries, returning a slice of pointers. The slice is
    /// valid until the next call to popAll().
    pub fn popAll(self: *ReadyQueue) ![]*waiter.Entry {
        if (self.list.items.len == 0) return &[_]*waiter.Entry{};

        self.results.clearRetainingCapacity();
        try self.results.appendSlice(self.list.items);

        for (self.list.items) |entry| {
            entry.is_queued = false;
        }
        self.list.clearRetainingCapacity();

        return self.results.items;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "EventMultiplexer basic" {
    const allocator = std.testing.allocator;
    const mux = try EventMultiplexer.init(allocator);
    defer mux.deinit();

    var entry = waiter.Entry.initWithUpcall(null, mux, EventMultiplexer.upcall);

    EventMultiplexer.upcall(&entry);

    const ready = try mux.pollReady();
    try std.testing.expectEqual(@as(usize, 1), ready.len);
    try std.testing.expectEqual(&entry, ready[0]);

    // Second drain should be empty.
    const ready2 = try mux.pollReady();
    try std.testing.expectEqual(@as(usize, 0), ready2.len);
}

test "ReadyQueue deduplication" {
    const allocator = std.testing.allocator;
    var q = ReadyQueue.init(allocator);
    defer q.deinit();

    var entry = waiter.Entry.init(null, null);

    _ = try q.push(&entry);
    _ = try q.push(&entry); // duplicate

    const ready = try q.popAll();
    try std.testing.expectEqual(@as(usize, 1), ready.len);
}

test "EventMultiplexer stats tracking" {
    const allocator = std.testing.allocator;
    const mux = try EventMultiplexer.init(allocator);
    defer mux.deinit();

    // pollReady with nothing queued => spurious wakeup counted.
    _ = try mux.pollReady();
    try std.testing.expectEqual(@as(u64, 1), mux.stats.spurious_wakeups);

    // One upcall + drain.
    var entry = waiter.Entry.initWithUpcall(null, mux, EventMultiplexer.upcall);
    EventMultiplexer.upcall(&entry);
    try std.testing.expectEqual(@as(u64, 1), mux.stats.upcalls_received);

    _ = try mux.pollReady();
    try std.testing.expectEqual(@as(u64, 1), mux.stats.events_fired);
}
