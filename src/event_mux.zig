/// Event multiplexer bridging the user-space stack's notification model
/// with external event loops (libev, libuv, or raw epoll).
///
/// The EventMultiplexer aggregates waiter.Entry readiness signals into a
/// single eventfd that the external loop watches. When the fd becomes
/// readable, the loop calls `pollReady()` to drain all pending entries and
/// dispatches them to registered handler callbacks.
///
/// Timer wheel:
///   A timerfd-based timer wheel consolidates all protocol timers (TCP
///   retransmit, keepalive, ARP expiry, DNS TTL) into a single kernel fd.
///   // PERF: At 10k concurrent connections, this reduces fd count from
///   // 10k+ (one per timer) to 1, avoiding epoll scalability issues.
///
/// Ownership model:
///   - The EventMultiplexer owns the eventfd, timerfd, and the internal queues.
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
    /// Total timer callbacks invoked.
    timers_fired: u64 = 0,
    /// Current number of registered timers.
    active_timers: u64 = 0,
};

// ---------------------------------------------------------------------------
// TimerWheel — timerfd-based consolidated timer management
// ---------------------------------------------------------------------------

/// Timer callback signature.
pub const TimerCallback = *const fn (user_data: ?*anyopaque) void;

/// A registered timer entry.
pub const TimerEntry = struct {
    /// Absolute expiration time in milliseconds (monotonic).
    expires_at_ms: i64,
    /// Callback invoked when timer fires.
    callback: TimerCallback,
    /// User-provided context pointer.
    user_data: ?*anyopaque,
    /// Internal: is this entry pending in the wheel?
    active: bool = true,
};

/// Timer wheel using a single timerfd for all protocol timers.
/// // PERF: Reduces fd count from O(connections) to O(1), eliminating
/// // epoll scalability issues at high connection counts.
pub const TimerWheel = struct {
    /// Sorted list of timer entries (by expiration time).
    entries: std.ArrayList(*TimerEntry),
    /// The kernel timerfd.
    timer_fd: std.posix.fd_t,
    allocator: std.mem.Allocator,

    const CLOCK_MONOTONIC: i32 = 1;
    const TFD_NONBLOCK: u32 = 0o4000;

    pub fn init(allocator: std.mem.Allocator) !TimerWheel {
        // Create timerfd with CLOCK_MONOTONIC and non-blocking
        const fd = std.posix.timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK) catch |err| {
            // Fallback: use -1 to indicate timerfd unavailable
            if (err == error.SystemResources) return .{
                .entries = std.ArrayList(*TimerEntry).init(allocator),
                .timer_fd = -1,
                .allocator = allocator,
            };
            return err;
        };

        return .{
            .entries = std.ArrayList(*TimerEntry).init(allocator),
            .timer_fd = fd,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TimerWheel) void {
        if (self.timer_fd >= 0) {
            std.posix.close(self.timer_fd);
        }
        self.entries.deinit();
    }

    /// Schedule a timer to fire after delay_ms milliseconds.
    pub fn schedule(self: *TimerWheel, entry: *TimerEntry, delay_ms: u64) !void {
        const now_ms = std.time.milliTimestamp();
        entry.expires_at_ms = now_ms + @as(i64, @intCast(delay_ms));
        entry.active = true;

        // Insert in sorted order (earliest first)
        var insert_idx: usize = self.entries.items.len;
        for (self.entries.items, 0..) |e, i| {
            if (entry.expires_at_ms < e.expires_at_ms) {
                insert_idx = i;
                break;
            }
        }
        try self.entries.insert(insert_idx, entry);

        // If this is the earliest timer, update timerfd
        if (insert_idx == 0) {
            self.armTimer(entry.expires_at_ms);
        }
    }

    /// Cancel a scheduled timer.
    pub fn cancel(self: *TimerWheel, entry: *TimerEntry) void {
        entry.active = false;
        for (self.entries.items, 0..) |e, i| {
            if (e == entry) {
                _ = self.entries.orderedRemove(i);
                break;
            }
        }
    }

    /// Process expired timers. Returns number of timers fired.
    pub fn tick(self: *TimerWheel) u64 {
        if (self.timer_fd >= 0) {
            // Drain timerfd to clear the signal
            var expirations: u64 = 0;
            _ = std.posix.read(self.timer_fd, std.mem.asBytes(&expirations)) catch {};
        }

        const now_ms = std.time.milliTimestamp();
        var fired: u64 = 0;

        while (self.entries.items.len > 0) {
            const entry = self.entries.items[0];
            if (entry.expires_at_ms > now_ms) break;

            _ = self.entries.orderedRemove(0);
            if (entry.active) {
                entry.active = false;
                entry.callback(entry.user_data);
                fired += 1;
            }
        }

        // Arm for next timer
        if (self.entries.items.len > 0) {
            self.armTimer(self.entries.items[0].expires_at_ms);
        }

        return fired;
    }

    fn armTimer(self: *TimerWheel, expires_at_ms: i64) void {
        if (self.timer_fd < 0) return;

        const now_ms = std.time.milliTimestamp();
        const delay_ms = @max(1, expires_at_ms - now_ms);
        const delay_ns = @as(u64, @intCast(delay_ms)) * 1_000_000;

        const ts = std.posix.timespec{
            .sec = @intCast(delay_ns / 1_000_000_000),
            .nsec = @intCast(delay_ns % 1_000_000_000),
        };
        const new_value = std.posix.itimerspec{
            .interval = .{ .sec = 0, .nsec = 0 },
            .value = ts,
        };

        _ = std.posix.timerfd_settime(self.timer_fd, .{}, &new_value, null) catch {};
    }

    /// Get the timerfd for registration with epoll/event loop.
    pub fn fd(self: *const TimerWheel) std.posix.fd_t {
        return self.timer_fd;
    }
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

    /// Consolidated timer wheel for all protocol timers.
    /// // PERF: Single timerfd serves TCP retransmit, keepalive, ARP expiry,
    /// // and DNS TTL timers, reducing fd count from O(n) to O(1).
    timer_wheel: TimerWheel,

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
            .timer_wheel = try TimerWheel.init(allocator),
        };
        return self;
    }

    pub fn deinit(self: *EventMultiplexer) void {
        std.posix.close(self.signal_fd);
        self.ready_queue.deinit();
        self.fd_handlers.deinit();
        self.timer_wheel.deinit();
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

    // -- Timer wheel interface -----------------------------------------------

    /// Schedule a timer to fire after delay_ms milliseconds.
    /// The timer entry must outlive the scheduled duration.
    pub fn scheduleTimer(self: *EventMultiplexer, entry: *TimerEntry, delay_ms: u64) !void {
        try self.timer_wheel.schedule(entry, delay_ms);
        self.stats.active_timers += 1;
    }

    /// Cancel a previously scheduled timer.
    pub fn cancelTimer(self: *EventMultiplexer, entry: *TimerEntry) void {
        self.timer_wheel.cancel(entry);
        if (self.stats.active_timers > 0) {
            self.stats.active_timers -= 1;
        }
    }

    /// Process expired timers. Should be called when timerFd() is readable,
    /// or periodically if timerfd is unavailable.
    pub fn processTimers(self: *EventMultiplexer) void {
        const fired = self.timer_wheel.tick();
        self.stats.timers_fired += fired;
        if (fired <= self.stats.active_timers) {
            self.stats.active_timers -= fired;
        } else {
            self.stats.active_timers = 0;
        }
    }

    /// Returns the timerfd for registration with epoll/event loop.
    /// Returns -1 if timerfd is unavailable on this system.
    pub fn timerFd(self: *const EventMultiplexer) std.posix.fd_t {
        return self.timer_wheel.fd();
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
