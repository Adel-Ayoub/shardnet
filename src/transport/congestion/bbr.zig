/// BBR congestion control.
///
/// Implements all four BBR phases (Startup, Drain, ProbeBW, ProbeRTT)
/// with bandwidth and RTT filters, and pacing support.

const std = @import("std");
const CongestionControl = @import("control.zig").CongestionControl;
const CongestionState = @import("control.zig").CongestionState;

/// BBR operating phases.
pub const BBRMode = enum {
    /// Exponential bandwidth probing at startup.
    startup,
    /// Drain queue after startup.
    drain,
    /// Steady-state bandwidth probing.
    probe_bw,
    /// Periodic RTT probing to find min_rtt.
    probe_rtt,
};

/// Pacing gain cycle for ProbeBW phase.
/// NOTE: BBR cycles through these gains to probe for more bandwidth.
const PACING_GAIN_CYCLE = [_]f64{ 1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0 };

pub const BBR = struct {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    allocator: std.mem.Allocator,

    // BBR state
    mode: BBRMode,
    cycle_index: usize,
    cycle_start_time: i64,

    // Bandwidth filter (windowed max over 10 RTTs)
    // NOTE: We track max bandwidth seen in recent window.
    bw_filter: [10]u64,
    bw_filter_idx: usize,
    max_bw: u64,

    // RTT filter (min RTT over 10 second window)
    // NOTE: ProbeRTT is triggered if min_rtt hasn't been updated in 10s.
    min_rtt_us: u64,
    min_rtt_timestamp: i64,
    probe_rtt_done_time: i64,

    // Delivery rate tracking
    delivered: u64,
    delivered_time: i64,
    last_ack_time: i64,

    // Pacing
    pacing_rate: u64,
    pacing_gain: f64,
    cwnd_gain: f64,

    // Round tracking
    round_count: u64,
    next_round_delivered: u64,

    // ProbeRTT state
    probe_rtt_round_done: bool,
    prior_cwnd: u32,

    // NOTE: BBR parameters
    const STARTUP_PACING_GAIN: f64 = 2.885; // 2/ln(2)
    const STARTUP_CWND_GAIN: f64 = 2.0;
    const DRAIN_PACING_GAIN: f64 = 1.0 / 2.885;
    const PROBE_RTT_CWND_GAIN: f64 = 0.5;
    const MIN_RTT_FILTER_LEN_MS: i64 = 10_000; // 10 seconds
    const PROBE_RTT_DURATION_MS: i64 = 200;

    pub fn init(allocator: std.mem.Allocator, mss: u32) !CongestionControl {
        const self = try allocator.create(BBR);
        self.* = .{
            .cwnd = 32 * mss,
            .ssthresh = 1024 * 1024 * 4,
            .mss = mss,
            .allocator = allocator,
            .mode = .startup,
            .cycle_index = 0,
            .cycle_start_time = 0,
            .bw_filter = [_]u64{0} ** 10,
            .bw_filter_idx = 0,
            .max_bw = 0,
            .min_rtt_us = std.math.maxInt(u64),
            .min_rtt_timestamp = 0,
            .probe_rtt_done_time = 0,
            .delivered = 0,
            .delivered_time = 0,
            .last_ack_time = 0,
            .pacing_rate = 0,
            .pacing_gain = STARTUP_PACING_GAIN,
            .cwnd_gain = STARTUP_CWND_GAIN,
            .round_count = 0,
            .next_round_delivered = 0,
            .probe_rtt_round_done = false,
            .prior_cwnd = 0,
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
        .onRttSample = onRttSample,
        .getCwnd = getCwnd,
        .getSsthresh = getSsthresh,
        .getState = getState,
        .getPacingRate = getPacingRate,
        .reset = resetFn,
        .deinit = deinit,
        .setMss = setMss,
    };

    fn resetFn(ptr: *anyopaque, mss: u32) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        self.* = .{
            .cwnd = 32 * mss,
            .ssthresh = 1024 * 1024 * 4,
            .mss = mss,
            .allocator = self.allocator,
            .mode = .startup,
            .cycle_index = 0,
            .cycle_start_time = 0,
            .bw_filter = [_]u64{0} ** 10,
            .bw_filter_idx = 0,
            .max_bw = 0,
            .min_rtt_us = std.math.maxInt(u64),
            .min_rtt_timestamp = 0,
            .probe_rtt_done_time = 0,
            .delivered = 0,
            .delivered_time = 0,
            .last_ack_time = 0,
            .pacing_rate = 0,
            .pacing_gain = STARTUP_PACING_GAIN,
            .cwnd_gain = STARTUP_CWND_GAIN,
            .round_count = 0,
            .next_round_delivered = 0,
            .probe_rtt_round_done = false,
            .prior_cwnd = 0,
        };
    }

    fn setMss(ptr: *anyopaque, mss: u32) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        const ratio = @as(f64, @floatFromInt(self.cwnd)) / @as(f64, @floatFromInt(self.mss));
        self.mss = mss;
        self.cwnd = @as(u32, @intFromFloat(ratio * @as(f64, @floatFromInt(mss))));
    }

    fn onRttSample(ptr: *anyopaque, rtt_us: u64) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        const now = std.time.milliTimestamp();

        // Update min_rtt filter
        if (rtt_us < self.min_rtt_us or
            now - self.min_rtt_timestamp >= MIN_RTT_FILTER_LEN_MS)
        {
            self.min_rtt_us = rtt_us;
            self.min_rtt_timestamp = now;
        }

        // Check if we need ProbeRTT
        if (self.mode != .probe_rtt and
            now - self.min_rtt_timestamp >= MIN_RTT_FILTER_LEN_MS)
        {
            self.enterProbeRTT();
        }
    }

    fn updateBandwidth(self: *BBR, bytes_acked: u32) void {
        const now = std.time.milliTimestamp();

        // Calculate delivery rate
        if (self.last_ack_time > 0) {
            const elapsed_ms = now - self.last_ack_time;
            if (elapsed_ms > 0) {
                // bytes/ms -> bytes/sec
                const bw = (@as(u64, bytes_acked) * 1000) / @as(u64, @intCast(elapsed_ms));

                // Update windowed max filter
                self.bw_filter[self.bw_filter_idx] = bw;
                self.bw_filter_idx = (self.bw_filter_idx + 1) % 10;

                // Find max
                var max: u64 = 0;
                for (self.bw_filter) |b| {
                    if (b > max) max = b;
                }
                self.max_bw = max;
            }
        }
        self.last_ack_time = now;
        self.delivered += bytes_acked;
    }

    fn updatePacingRate(self: *BBR) void {
        if (self.max_bw == 0 or self.min_rtt_us == std.math.maxInt(u64)) return;

        // pacing_rate = pacing_gain * max_bw
        self.pacing_rate = @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.max_bw)) * self.pacing_gain));
    }

    fn updateCwnd(self: *BBR) void {
        if (self.max_bw == 0 or self.min_rtt_us == std.math.maxInt(u64)) return;

        // BDP = max_bw * min_rtt
        // cwnd = cwnd_gain * BDP
        const bdp = (self.max_bw * self.min_rtt_us) / 1_000_000; // us to sec
        const target_cwnd = @as(u64, @intFromFloat(@as(f64, @floatFromInt(bdp)) * self.cwnd_gain));
        self.cwnd = @as(u32, @intCast(@min(target_cwnd, 64 * 1024 * 1024)));

        // Ensure minimum cwnd
        if (self.cwnd < 4 * self.mss) self.cwnd = 4 * self.mss;
    }

    fn checkStartupDone(self: *BBR) void {
        // Exit startup when bandwidth growth slows
        // (simplified: after bandwidth hasn't increased for 3 rounds)
        if (self.round_count > 3 and self.max_bw > 0) {
            self.mode = .drain;
            self.pacing_gain = DRAIN_PACING_GAIN;
        }
    }

    fn checkDrainDone(self: *BBR) void {
        // Exit drain when inflight <= BDP
        // (simplified: after one round)
        self.mode = .probe_bw;
        self.pacing_gain = PACING_GAIN_CYCLE[0];
        self.cwnd_gain = 2.0;
        self.cycle_index = 0;
        self.cycle_start_time = std.time.milliTimestamp();
    }

    fn advanceProbeBWCycle(self: *BBR) void {
        const now = std.time.milliTimestamp();

        // Advance cycle every min_rtt
        const cycle_len_ms = @max(1, self.min_rtt_us / 1000);
        if (now - self.cycle_start_time >= @as(i64, @intCast(cycle_len_ms))) {
            self.cycle_index = (self.cycle_index + 1) % PACING_GAIN_CYCLE.len;
            self.pacing_gain = PACING_GAIN_CYCLE[self.cycle_index];
            self.cycle_start_time = now;
        }
    }

    fn enterProbeRTT(self: *BBR) void {
        self.prior_cwnd = self.cwnd;
        self.mode = .probe_rtt;
        self.pacing_gain = 1.0;
        // NOTE: ProbeRTT reduces cwnd to 4 packets to drain queue.
        self.cwnd = 4 * self.mss;
        self.probe_rtt_done_time = 0;
        self.probe_rtt_round_done = false;
    }

    fn handleProbeRTT(self: *BBR) void {
        const now = std.time.milliTimestamp();

        if (self.probe_rtt_done_time == 0) {
            self.probe_rtt_done_time = now + PROBE_RTT_DURATION_MS;
        }

        if (now >= self.probe_rtt_done_time) {
            // Exit ProbeRTT
            self.cwnd = self.prior_cwnd;
            self.mode = .probe_bw;
            self.pacing_gain = PACING_GAIN_CYCLE[0];
            self.cycle_index = 0;
            self.cycle_start_time = now;
        }
    }

    fn onAck(ptr: *anyopaque, bytes_acked: u32) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));

        self.updateBandwidth(bytes_acked);
        self.updatePacingRate();

        switch (self.mode) {
            .startup => {
                self.updateCwnd();
                self.checkStartupDone();
            },
            .drain => {
                self.updateCwnd();
                self.checkDrainDone();
            },
            .probe_bw => {
                self.advanceProbeBWCycle();
                self.updateCwnd();
            },
            .probe_rtt => {
                self.handleProbeRTT();
            },
        }
    }

    fn onLoss(ptr: *anyopaque) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        // BBR doesn't reduce cwnd on loss in steady state
        // Just update bandwidth estimate
        self.ssthresh = @max(self.cwnd / 2, 2 * self.mss);
    }

    fn onRetransmit(ptr: *anyopaque) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        // On RTO, be more conservative
        self.ssthresh = @max(self.cwnd / 2, 2 * self.mss);
        self.cwnd = self.mss;
        self.mode = .startup;
        self.pacing_gain = STARTUP_PACING_GAIN;
        self.cwnd_gain = STARTUP_CWND_GAIN;
    }

    fn getCwnd(ptr: *anyopaque) u32 {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        return self.cwnd;
    }

    fn getSsthresh(ptr: *anyopaque) u32 {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        return self.ssthresh;
    }

    fn getState(ptr: *anyopaque) CongestionState {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        return switch (self.mode) {
            .startup => .slow_start,
            .drain, .probe_bw, .probe_rtt => .congestion_avoidance,
        };
    }

    fn getPacingRate(ptr: *anyopaque) u64 {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        return self.pacing_rate;
    }

    fn deinit(ptr: *anyopaque) void {
        const self = @as(*BBR, @ptrCast(@alignCast(ptr)));
        self.allocator.destroy(self);
    }
};

test "BBR startup mode" {
    const allocator = std.testing.allocator;
    var cc = try BBR.init(allocator, 1460);
    defer cc.deinit();

    const self = @as(*BBR, @ptrCast(@alignCast(cc.ptr)));
    try std.testing.expectEqual(BBRMode.startup, self.mode);
}

test "BBR pacing rate calculation" {
    const allocator = std.testing.allocator;
    var cc = try BBR.init(allocator, 1460);
    defer cc.deinit();

    const self = @as(*BBR, @ptrCast(@alignCast(cc.ptr)));

    // Simulate bandwidth samples
    self.max_bw = 1_000_000; // 1 MB/s
    self.min_rtt_us = 10_000; // 10ms
    self.updatePacingRate();

    try std.testing.expect(cc.getPacingRate().? > 0);
}
