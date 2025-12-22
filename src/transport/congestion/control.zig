/// Congestion control interface and algorithms.
///
/// Provides a comptime vtable interface for congestion controllers
/// (BBR, CUBIC, NewReno) that can be swapped without runtime overhead.

const std = @import("std");

pub const BBR = @import("bbr.zig").BBR;
pub const Cubic = @import("cubic.zig").Cubic;

/// Congestion control state machine states.
pub const CongestionState = enum {
    /// Initial phase: exponential growth until ssthresh.
    slow_start,
    /// Additive increase after ssthresh.
    congestion_avoidance,
    /// After 3 duplicate ACKs: fast retransmit + recovery.
    fast_recovery,
    /// After RTO timeout: reset to slow start.
    loss,
};

/// Unit conversion helpers.
pub fn bytesToSegments(bytes: u32, mss: u32) u32 {
    return (bytes + mss - 1) / mss;
}

pub fn segmentsToBytes(segments: u32, mss: u32) u32 {
    return segments * mss;
}

/// Congestion controller interface.
/// NOTE: This is a runtime vtable interface. For comptime dispatch,
/// use the concrete types directly with generic functions.
pub const CongestionControl = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Called when an ACK is received.
        onAck: *const fn (ptr: *anyopaque, bytes_acked: u32) void,
        /// Called on packet loss detection (3 dup ACKs or SACK).
        onLoss: *const fn (ptr: *anyopaque) void,
        /// Called on RTO-triggered retransmission.
        onRetransmit: *const fn (ptr: *anyopaque) void,
        /// Called when RTT sample is available.
        onRttSample: ?*const fn (ptr: *anyopaque, rtt_us: u64) void = null,
        /// Get current congestion window in bytes.
        getCwnd: *const fn (ptr: *anyopaque) u32,
        /// Get slow start threshold.
        getSsthresh: *const fn (ptr: *anyopaque) u32,
        /// Get current congestion state.
        getState: ?*const fn (ptr: *anyopaque) CongestionState = null,
        /// Get pacing rate in bytes per second (for BBR).
        getPacingRate: ?*const fn (ptr: *anyopaque) u64 = null,
        /// Set MSS (on path MTU change).
        setMss: ?*const fn (ptr: *anyopaque, mss: u32) void = null,
        /// Reset to initial state.
        reset: ?*const fn (ptr: *anyopaque, mss: u32) void = null,
        /// Clean up resources.
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn onAck(self: CongestionControl, bytes_acked: u32) void {
        self.vtable.onAck(self.ptr, bytes_acked);
    }

    pub fn onLoss(self: CongestionControl) void {
        self.vtable.onLoss(self.ptr);
    }

    pub fn onRetransmit(self: CongestionControl) void {
        self.vtable.onRetransmit(self.ptr);
    }

    pub fn onRttSample(self: CongestionControl, rtt_us: u64) void {
        if (self.vtable.onRttSample) |f| f(self.ptr, rtt_us);
    }

    pub fn getCwnd(self: CongestionControl) u32 {
        return self.vtable.getCwnd(self.ptr);
    }

    pub fn getSsthresh(self: CongestionControl) u32 {
        return self.vtable.getSsthresh(self.ptr);
    }

    pub fn getState(self: CongestionControl) CongestionState {
        if (self.vtable.getState) |f| return f(self.ptr);
        // Default: infer from cwnd vs ssthresh
        const cwnd = self.getCwnd();
        const ssthresh = self.getSsthresh();
        return if (cwnd < ssthresh) .slow_start else .congestion_avoidance;
    }

    pub fn getPacingRate(self: CongestionControl) ?u64 {
        if (self.vtable.getPacingRate) |f| return f(self.ptr);
        return null;
    }

    pub fn setMss(self: CongestionControl, mss: u32) void {
        if (self.vtable.setMss) |f| f(self.ptr, mss);
    }

    pub fn reset(self: CongestionControl, mss: u32) !void {
        if (self.vtable.reset) |f| {
            f(self.ptr, mss);
        } else {
            return error.NotSupported;
        }
    }

    pub fn deinit(self: CongestionControl) void {
        self.vtable.deinit(self.ptr);
    }
};

/// NewReno congestion control (RFC 5681).
pub const NewReno = struct {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    state: CongestionState,
    dup_ack_count: u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, mss: u32) !CongestionControl {
        const self = try allocator.create(NewReno);
        self.* = .{
            .cwnd = 32 * mss,
            .ssthresh = 1024 * 1024 * 4,
            .mss = mss,
            .state = .slow_start,
            .dup_ack_count = 0,
            .allocator = allocator,
        };
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = CongestionControl.VTable{
        .onAck = onAck,
        .onLoss = onLoss,
        .onRetransmit = onRetransmit,
        .getCwnd = getCwnd,
        .getSsthresh = getSsthresh,
        .getState = getState,
        .setMss = setMss,
        .reset = resetFn,
        .deinit = deinit,
    };

    fn resetFn(ptr: *anyopaque, mss: u32) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        self.* = .{
            .cwnd = 32 * mss,
            .ssthresh = 1024 * 1024 * 4,
            .mss = mss,
            .state = .slow_start,
            .dup_ack_count = 0,
            .allocator = self.allocator,
        };
    }

    fn setMss(ptr: *anyopaque, mss: u32) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        const ratio = @as(f64, @floatFromInt(self.cwnd)) / @as(f64, @floatFromInt(self.mss));
        self.mss = mss;
        self.cwnd = @as(u32, @intFromFloat(ratio * @as(f64, @floatFromInt(mss))));
    }

    fn onAck(ptr: *anyopaque, bytes_acked: u32) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        self.dup_ack_count = 0;

        switch (self.state) {
            .slow_start => {
                // Exponential growth
                self.cwnd += bytes_acked;
                if (self.cwnd >= self.ssthresh) {
                    self.state = .congestion_avoidance;
                }
            },
            .congestion_avoidance => {
                // Additive increase: cwnd += MSS * bytes_acked / cwnd
                const incr = (@as(u64, self.mss) * bytes_acked) / self.cwnd;
                self.cwnd += @as(u32, @intCast(@max(1, incr)));
            },
            .fast_recovery => {
                // Exit fast recovery on new ACK
                self.cwnd = self.ssthresh;
                self.state = .congestion_avoidance;
            },
            .loss => {
                self.state = .slow_start;
            },
        }
    }

    fn onLoss(ptr: *anyopaque) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        // Multiplicative decrease
        self.ssthresh = @max(self.cwnd / 2, 2 * self.mss);
        self.cwnd = self.ssthresh + 3 * self.mss;
        self.state = .fast_recovery;
    }

    fn onRetransmit(ptr: *anyopaque) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        // RTO: reset to slow start
        self.ssthresh = @max(self.cwnd / 2, 2 * self.mss);
        self.cwnd = self.mss;
        self.state = .loss;
    }

    fn getCwnd(ptr: *anyopaque) u32 {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        return self.cwnd;
    }

    fn getSsthresh(ptr: *anyopaque) u32 {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        return self.ssthresh;
    }

    fn getState(ptr: *anyopaque) CongestionState {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        return self.state;
    }

    fn deinit(ptr: *anyopaque) void {
        const self = @as(*NewReno, @ptrCast(@alignCast(ptr)));
        self.allocator.destroy(self);
    }
};

test "NewReno slow start" {
    const allocator = std.testing.allocator;
    var cc = try NewReno.init(allocator, 1460);
    defer cc.deinit();

    const initial_cwnd = cc.getCwnd();
    try std.testing.expectEqual(CongestionState.slow_start, cc.getState());

    cc.onAck(1460);
    try std.testing.expect(cc.getCwnd() > initial_cwnd);
}

test "NewReno loss triggers fast recovery" {
    const allocator = std.testing.allocator;
    var cc = try NewReno.init(allocator, 1460);
    defer cc.deinit();

    cc.onLoss();
    try std.testing.expectEqual(CongestionState.fast_recovery, cc.getState());
}
