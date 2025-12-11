/// Monotonic time helpers for the shardnet network stack.
///
/// Provides a hierarchical timer wheel for efficient O(1) scheduling and
/// cancellation of protocol timers (TCP retransmit, ARP expiry, keepalive,
/// etc.), a SteadyClock wrapper over CLOCK_MONOTONIC, and a Timer struct
/// with start/elapsed/reset semantics.
///
/// Platform assumptions:
///   - Linux only (uses clock_gettime, nanosleep via POSIX).
///   - CLOCK_MONOTONIC never goes backwards; resolution is typically < 1 µs
///     on modern kernels but may be coarser on virtualised guests.
const std = @import("std");

// ---------------------------------------------------------------------------
// SteadyClock — thin wrapper over CLOCK_MONOTONIC
// ---------------------------------------------------------------------------

/// A monotonic clock that never goes backwards. Suitable for measuring
/// elapsed time, timeouts, and RTT samples. Not suitable for wall-clock
/// timestamps.
pub const SteadyClock = struct {
    /// Returns the current monotonic time in nanoseconds.
    pub fn now() i128 {
        return std.time.nanoTimestamp();
    }

    /// Returns the current monotonic time in milliseconds.
    pub fn nowMs() u64 {
        const ns = std.time.nanoTimestamp();
        return @intCast(@as(u128, @intCast(ns)) / std.time.ns_per_ms);
    }
};

// ---------------------------------------------------------------------------
// Stopwatch — start / elapsed / reset
// ---------------------------------------------------------------------------

/// A simple stopwatch backed by SteadyClock for measuring durations.
///
/// Usage:
///   var sw = Stopwatch.start();
///   // ... work ...
///   const elapsed_ns = sw.elapsed();
///   sw.reset();
pub const Stopwatch = struct {
    start_ns: i128,

    /// Start (or restart) the stopwatch.
    pub fn start() Stopwatch {
        return .{ .start_ns = SteadyClock.now() };
    }

    /// Nanoseconds elapsed since the last start/reset.
    pub fn elapsed(self: Stopwatch) u64 {
        const delta = SteadyClock.now() - self.start_ns;
        return @intCast(@as(u128, @intCast(@max(delta, 0))));
    }

    /// Reset the stopwatch to the current instant.
    pub fn reset(self: *Stopwatch) void {
        self.start_ns = SteadyClock.now();
    }
};

// ---------------------------------------------------------------------------
// sleep_ns — nanosecond-precision sleep
// ---------------------------------------------------------------------------

/// Sleep for at least `ns` nanoseconds using the platform sleep primitive.
///
/// Precision guarantee: on Linux the actual sleep may overshoot by up to
/// one scheduler tick (typically 1–4 ms on HZ=250 kernels). For sub-µs
/// precision consider busy-waiting after a coarse sleep.
pub fn sleep_ns(ns: u64) void {
    std.time.sleep(ns);
}

// ---------------------------------------------------------------------------
// Timer callback and intrusive node
// ---------------------------------------------------------------------------

pub const TimerCallback = *const fn (ctx: *anyopaque) void;

/// An intrusive timer node that can be inserted into a TimerWheel.
///
/// Each Timer carries its own callback, context pointer, and doubly-linked
/// list pointers so the wheel never allocates. The caller owns the Timer
/// memory and must ensure it outlives its scheduled lifetime.
pub const Timer = struct {
    // Callback fired when the timer expires.
    callback: TimerCallback,
    context: *anyopaque,

    // Absolute tick at which this timer fires.
    expire_tick: u64 = 0,
    // Original delay in ms (retained for rescheduling).
    delay_ms: u32 = 0,

    // Intrusive doubly-linked list pointers — O(1) removal.
    next: ?*Timer = null,
    prev: ?*Timer = null,

    // Wheel coordinates — O(1) cancel without search.
    level: u8 = 0,
    slot: u8 = 0,
    active: bool = false,

    pub fn init(callback: TimerCallback, context: *anyopaque) Timer {
        return .{
            .callback = callback,
            .context = context,
        };
    }
};

// ---------------------------------------------------------------------------
// TickResult
// ---------------------------------------------------------------------------

/// Summary returned by a single tick() or tickTo() call.
pub const TickResult = struct {
    expired_count: u32 = 0,
    cascaded_count: u32 = 0,
    next_expiration: ?u64 = null,
};

// ---------------------------------------------------------------------------
// TimerWheel — hierarchical hashed timer wheel
// ---------------------------------------------------------------------------

/// A four-level hierarchical timer wheel providing O(1) schedule, cancel,
/// and per-tick expiry processing. Modelled after the Linux kernel
/// timer_list implementation.
///
/// Level 0 covers ticks 0–255, Level 1 covers 256–65 535, Level 2 covers
/// 65 536–16 777 215, and Level 3 covers 16 777 216–4 294 967 295.
///
/// Cascading from higher levels into Level 0 happens automatically when
/// the wheel rotates past a level boundary.
pub const TimerWheel = struct {
    const LEVELS = 4;
    const SLOTS_PER_LEVEL = 256;
    const SLOT_MASK = 255;
    const BITS_PER_LEVEL = 8;

    wheels: [LEVELS][SLOTS_PER_LEVEL]Slot = [_][SLOTS_PER_LEVEL]Slot{[_]Slot{.{}} ** SLOTS_PER_LEVEL} ** LEVELS,
    slot_masks: [LEVELS]SlotMask = [_]SlotMask{.{}} ** LEVELS,
    current_tick: u64 = 0,

    // -- Slot (doubly-linked list of timers) --------------------------------

    const Slot = struct {
        head: ?*Timer = null,
        tail: ?*Timer = null,
        count: u32 = 0,

        /// Append a timer to the tail of this slot's list.
        pub fn append(self: *Slot, timer: *Timer) void {
            timer.next = null;
            timer.prev = self.tail;
            if (self.tail) |t| {
                t.next = timer;
            } else {
                self.head = timer;
            }
            self.tail = timer;
            self.count += 1;
        }

        /// Remove a timer from anywhere in this slot's list in O(1).
        pub fn remove(self: *Slot, timer: *Timer) void {
            if (timer.prev) |p| {
                p.next = timer.next;
            } else {
                self.head = timer.next;
            }
            if (timer.next) |n| {
                n.prev = timer.prev;
            } else {
                self.tail = timer.prev;
            }
            timer.next = null;
            timer.prev = null;
            self.count -= 1;
        }

        /// Pop and return the first timer, or null if empty.
        pub fn popFirst(self: *Slot) ?*Timer {
            const first = self.head orelse return null;
            self.remove(first);
            return first;
        }

        pub fn isEmpty(self: Slot) bool {
            return self.count == 0;
        }
    };

    // -- SlotMask (bitmap for fast empty-slot skipping) ---------------------

    const SlotMask = struct {
        bits: [4]u64 = [_]u64{0} ** 4,

        pub fn set(self: *SlotMask, slot: u8) void {
            self.bits[slot >> 6] |= (@as(u64, 1) << @intCast(slot & 63));
        }

        pub fn unset(self: *SlotMask, slot: u8) void {
            self.bits[slot >> 6] &= ~(@as(u64, 1) << @intCast(slot & 63));
        }

        /// Find the next occupied slot at or after `start_slot`.
        pub fn findNext(self: SlotMask, start_slot: u8) ?u8 {
            var i: usize = start_slot >> 6;
            const bit_offset: u6 = @intCast(start_slot & 63);

            // Check first u64 with bit offset.
            var first_bits = self.bits[i];
            first_bits &= (@as(u64, 0xFFFFFFFFFFFFFFFF) << bit_offset);

            if (first_bits != 0) {
                return @intCast((i << 6) + @ctz(first_bits));
            }

            // Check remaining u64s.
            var checked: usize = 1;
            while (checked < 4) : (checked += 1) {
                i = (i + 1) % 4;
                if (self.bits[i] != 0) {
                    return @intCast((i << 6) + @ctz(self.bits[i]));
                }
            }
            return null;
        }

        pub fn isEmpty(self: SlotMask) bool {
            return self.bits[0] == 0 and self.bits[1] == 0 and self.bits[2] == 0 and self.bits[3] == 0;
        }
    };

    // -- Public API ---------------------------------------------------------

    pub fn init() TimerWheel {
        return .{};
    }

    /// Schedule a timer to fire after `delay_ms` ticks. If the timer is
    /// already active it is cancelled first and rescheduled.
    pub fn schedule(self: *TimerWheel, timer: *Timer, delay_ms: u64) void {
        if (timer.active) {
            self.cancel(timer);
        }

        const safe_delay = @max(delay_ms, 1);
        const expire_tick = self.current_tick + safe_delay;
        timer.expire_tick = expire_tick;
        timer.delay_ms = @intCast(@min(delay_ms, std.math.maxInt(u32)));

        const level, const slot = self.calculateLevelAndSlot(expire_tick);
        timer.level = @intCast(level);
        timer.slot = @intCast(slot);
        timer.active = true;

        self.wheels[level][slot].append(timer);
        self.slot_masks[level].set(@intCast(slot));
    }

    /// Cancel a pending timer in O(1). Safe to call on an inactive timer.
    pub fn cancel(self: *TimerWheel, timer: *Timer) void {
        if (!timer.active) return;

        const level = timer.level;
        const slot = timer.slot;
        self.wheels[level][slot].remove(timer);
        if (self.wheels[level][slot].isEmpty()) {
            self.slot_masks[level].unset(slot);
        }

        timer.active = false;
    }

    /// Advance the wheel by one tick, cascade higher levels as needed,
    /// then fire all expired Level-0 timers.
    pub fn tick(self: *TimerWheel) TickResult {
        var result = TickResult{};

        // 1. Advance time.
        self.current_tick += 1;

        // 2. Cascade from higher levels when a wheel completes a rotation.
        var cascade_level: usize = 1;
        var temp_tick = self.current_tick;
        while (cascade_level < LEVELS) : (cascade_level += 1) {
            if ((temp_tick & (@as(u64, SLOTS_PER_LEVEL) - 1)) != 0) break;
            temp_tick >>= BITS_PER_LEVEL;
            result.cascaded_count += self.cascade(cascade_level);
        }

        // 3. Fire all Level-0 timers in the current slot.
        const slot_idx: u8 = @intCast(self.current_tick & SLOT_MASK);
        while (self.wheels[0][slot_idx].popFirst()) |timer| {
            if (self.wheels[0][slot_idx].isEmpty()) {
                self.slot_masks[0].unset(slot_idx);
            }
            timer.active = false;
            timer.callback(timer.context);
            result.expired_count += 1;
        }

        result.next_expiration = self.nextExpiration();
        return result;
    }

    /// Advance the wheel to `target_tick`, firing all timers along the way.
    pub fn tickTo(self: *TimerWheel, target_tick: u64) TickResult {
        var total_result = TickResult{};
        while (self.current_tick < target_tick) {
            const res = self.tick();
            total_result.expired_count += res.expired_count;
            total_result.cascaded_count += res.cascaded_count;
        }
        total_result.next_expiration = self.nextExpiration();
        return total_result;
    }

    /// Return the number of ticks until the next pending timer fires,
    /// or null if the wheel is empty.
    pub fn nextExpiration(self: TimerWheel) ?u64 {
        const next_proc_tick = self.current_tick + 1;

        var level: usize = 0;
        while (level < LEVELS) : (level += 1) {
            const level_shift: u6 = @intCast(level * BITS_PER_LEVEL);
            const current_slot: u8 = @intCast((next_proc_tick >> level_shift) & SLOT_MASK);

            if (self.slot_masks[level].findNext(current_slot)) |next_slot| {
                if (level == 0) {
                    const diff: u64 = if (next_slot >= current_slot)
                        @as(u64, next_slot) - @as(u64, current_slot)
                    else
                        @as(u64, SLOTS_PER_LEVEL) - @as(u64, current_slot) + @as(u64, next_slot);
                    return diff + 1;
                } else {
                    const abs_slot_idx_at_level = next_proc_tick >> level_shift;
                    const rotation_base_slot = abs_slot_idx_at_level & ~@as(u64, SLOT_MASK);
                    var next_abs_slot = rotation_base_slot + next_slot;

                    var next_tick = next_abs_slot << level_shift;
                    if (next_tick < next_proc_tick) {
                        next_abs_slot += SLOTS_PER_LEVEL;
                        next_tick = next_abs_slot << level_shift;
                    }

                    return next_tick - self.current_tick;
                }
            }
        }

        return null;
    }

    pub fn currentTick(self: TimerWheel) u64 {
        return self.current_tick;
    }

    pub fn hasPendingTimers(self: TimerWheel) bool {
        for (self.slot_masks) |mask| {
            if (!mask.isEmpty()) return true;
        }
        return false;
    }

    // -- Internal -----------------------------------------------------------

    /// Cascade all timers from the given level's current slot down into
    /// lower levels so they can fire at the correct tick.
    fn cascade(self: *TimerWheel, level: usize) u32 {
        const level_shift: u6 = @intCast(level * BITS_PER_LEVEL);
        const slot_idx: u8 = @intCast((self.current_tick >> level_shift) & SLOT_MASK);
        var cascaded: u32 = 0;

        while (self.wheels[level][slot_idx].popFirst()) |timer| {
            if (self.wheels[level][slot_idx].isEmpty()) {
                self.slot_masks[level].unset(slot_idx);
            }

            const new_level, const new_slot = self.calculateLevelAndSlot(timer.expire_tick);

            timer.level = @intCast(new_level);
            timer.slot = @intCast(new_slot);
            self.wheels[new_level][new_slot].append(timer);
            self.slot_masks[new_level].set(@intCast(new_slot));

            cascaded += 1;
        }

        return cascaded;
    }

    fn calculateLevelAndSlot(self: TimerWheel, expire_tick: u64) struct { usize, usize } {
        const diff = if (expire_tick > self.current_tick) expire_tick - self.current_tick else 1;

        var level: usize = 0;
        var temp_diff = diff;
        while (level < LEVELS - 1 and temp_diff >= SLOTS_PER_LEVEL) : (level += 1) {
            temp_diff >>= BITS_PER_LEVEL;
        }

        const level_shift: u6 = @intCast(level * BITS_PER_LEVEL);
        const slot = expire_tick >> level_shift & SLOT_MASK;
        return .{ level, @intCast(slot) };
    }
};

/// Alias for backward compatibility.
pub const TimerQueue = TimerWheel;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "TimerWheel basic operations" {
    var wheel = TimerWheel.init();
    var fired = false;

    const Ctx = struct { fired: *bool };
    var ctx = Ctx{ .fired = &fired };

    const cb = struct {
        fn run(ptr: *anyopaque) void {
            const c: *Ctx = @ptrCast(@alignCast(ptr));
            c.fired.* = true;
        }
    }.run;

    var t = Timer.init(cb, &ctx);
    wheel.schedule(&t, 5);

    _ = wheel.tick(); // 1
    try std.testing.expect(!fired);
    _ = wheel.tick(); // 2
    try std.testing.expect(!fired);
    _ = wheel.tick(); // 3
    try std.testing.expect(!fired);
    _ = wheel.tick(); // 4
    try std.testing.expect(!fired);
    _ = wheel.tick(); // 5
    try std.testing.expect(fired);
}

test "TimerWheel nextExpiration" {
    var wheel = TimerWheel.init();
    const cb = struct {
        fn run(_: *anyopaque) void {}
    }.run;

    var t1 = Timer.init(cb, undefined);
    wheel.schedule(&t1, 10);
    try std.testing.expectEqual(@as(?u64, 10), wheel.nextExpiration());

    var t2 = Timer.init(cb, undefined);
    wheel.schedule(&t2, 5);
    try std.testing.expectEqual(@as(?u64, 5), wheel.nextExpiration());

    var t3 = Timer.init(cb, undefined);
    wheel.schedule(&t3, 1000);

    _ = wheel.tickTo(wheel.current_tick + 5);
    try std.testing.expectEqual(@as(?u64, 5), wheel.nextExpiration());

    _ = wheel.tickTo(wheel.current_tick + 5);
    try std.testing.expectEqual(@as(?u64, 758), wheel.nextExpiration());
}

test "TimerWheel cascading" {
    var wheel = TimerWheel.init();
    var fired_count: u32 = 0;
    const Ctx = struct { count: *u32 };
    var ctx = Ctx{ .count = &fired_count };
    const cb = struct {
        fn run(ptr: *anyopaque) void {
            const c: *Ctx = @ptrCast(@alignCast(ptr));
            c.count.* += 1;
        }
    }.run;

    var t1 = Timer.init(cb, &ctx);
    wheel.schedule(&t1, 300);

    _ = wheel.tickTo(wheel.current_tick + 299);
    try std.testing.expectEqual(@as(u32, 0), fired_count);

    _ = wheel.tick();
    try std.testing.expectEqual(@as(u32, 1), fired_count);
}

test "Stopwatch basic" {
    var sw = Stopwatch.start();
    sleep_ns(1_000_000); // 1 ms
    const elapsed = sw.elapsed();
    // Should be at least 1 ms but less than 100 ms.
    try std.testing.expect(elapsed >= 500_000);
    try std.testing.expect(elapsed < 100_000_000);
    sw.reset();
    const after_reset = sw.elapsed();
    try std.testing.expect(after_reset < elapsed);
}
