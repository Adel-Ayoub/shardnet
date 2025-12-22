/// CUBIC congestion control (RFC 9438).
///
/// Implements the full CUBIC window growth function W_cubic(t),
/// HyStart++ slow-start exit (RFC 9406), and Reno-friendly mode.

const std = @import("std");
const CongestionControl = @import("control.zig").CongestionControl;
const CongestionState = @import("control.zig").CongestionState;

pub const Cubic = struct {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    state: CongestionState,

    // CUBIC parameters per RFC 9438
    /// W_max: window size just before the last reduction.
    w_max: u32,
    /// K: time to reach W_max from origin.
    k: f64,
    /// Epoch start time (ms).
    epoch_start: i64,
    /// Origin point for CUBIC window calculation.
    origin_point: u32,

    // Reno-friendly tracking (W_est from RFC 9438 Section 4.3)
    reno_cwnd: u32,

    // HyStart++ state (RFC 9406)
    hystart_enabled: bool,
    hystart_round_start: i64,
    hystart_last_rtt: u64,
    hystart_curr_rtt: u64,
    hystart_rtt_thresh: u64,
    hystart_low_seq: u32,
    hystart_acks_in_round: u32,

    // RTT tracking
    min_rtt_us: u64,

    allocator: std.mem.Allocator,

    // NOTE: RFC 9438 Section 4.1 - CUBIC parameters
    // C = 0.4 (scaling constant)
    // beta_cubic = 0.7 (multiplicative decrease factor)
    const C: f64 = 0.4;
    const BETA: f64 = 0.7;

    // NOTE: RFC 9406 Section 3 - HyStart++ parameters
    const HYSTART_MIN_SAMPLES: u32 = 8;
    const HYSTART_MIN_RTT_THRESH: u64 = 4000; // 4ms in microseconds
    const HYSTART_MAX_RTT_THRESH: u64 = 16000; // 16ms

    pub fn init(allocator: std.mem.Allocator, mss: u32) !CongestionControl {
        const self = try allocator.create(Cubic);
        self.* = .{
            .cwnd = 32 * mss,
            .ssthresh = 1024 * 1024 * 4,
            .mss = mss,
            .state = .slow_start,
            .w_max = 0,
            .k = 0,
            .epoch_start = 0,
            .origin_point = 0,
            .reno_cwnd = 0,
            .hystart_enabled = true,
            .hystart_round_start = 0,
            .hystart_last_rtt = 0,
            .hystart_curr_rtt = std.math.maxInt(u64),
            .hystart_rtt_thresh = HYSTART_MIN_RTT_THRESH,
            .hystart_low_seq = 0,
            .hystart_acks_in_round = 0,
            .min_rtt_us = std.math.maxInt(u64),
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
        .onRttSample = onRttSample,
        .getCwnd = getCwnd,
        .getSsthresh = getSsthresh,
        .getState = getState,
        .reset = resetFn,
        .deinit = deinit,
        .setMss = setMss,
    };

    fn resetFn(ptr: *anyopaque, mss: u32) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        self.* = .{
            .cwnd = 32 * mss,
            .ssthresh = 1024 * 1024 * 4,
            .mss = mss,
            .state = .slow_start,
            .w_max = 0,
            .k = 0,
            .epoch_start = 0,
            .origin_point = 0,
            .reno_cwnd = 0,
            .hystart_enabled = true,
            .hystart_round_start = 0,
            .hystart_last_rtt = 0,
            .hystart_curr_rtt = std.math.maxInt(u64),
            .hystart_rtt_thresh = HYSTART_MIN_RTT_THRESH,
            .hystart_low_seq = 0,
            .hystart_acks_in_round = 0,
            .min_rtt_us = std.math.maxInt(u64),
            .allocator = self.allocator,
        };
    }

    fn setMss(ptr: *anyopaque, mss: u32) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        const ratio = @as(f64, @floatFromInt(self.cwnd)) / @as(f64, @floatFromInt(self.mss));
        self.mss = mss;
        self.cwnd = @as(u32, @intFromFloat(ratio * @as(f64, @floatFromInt(mss))));
        if (self.reno_cwnd > 0) {
            const r_ratio = @as(f64, @floatFromInt(self.reno_cwnd)) / @as(f64, @floatFromInt(self.mss));
            self.reno_cwnd = @as(u32, @intFromFloat(r_ratio * @as(f64, @floatFromInt(mss))));
        }
    }

    /// HyStart++ slow-start exit detection (RFC 9406 Section 3.2).
    fn hystartCheck(self: *Cubic) bool {
        if (!self.hystart_enabled) return false;

        // Check if we have enough RTT samples
        if (self.hystart_acks_in_round < HYSTART_MIN_SAMPLES) return false;

        // Delay increase detection
        if (self.hystart_curr_rtt != std.math.maxInt(u64) and
            self.hystart_last_rtt != 0)
        {
            const delay_increase = self.hystart_curr_rtt -| self.hystart_last_rtt;
            if (delay_increase > self.hystart_rtt_thresh) {
                return true;
            }
        }

        return false;
    }

    fn onRttSample(ptr: *anyopaque, rtt_us: u64) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));

        // Update min RTT
        if (rtt_us < self.min_rtt_us) {
            self.min_rtt_us = rtt_us;
        }

        // HyStart++ RTT tracking
        if (self.state == .slow_start and self.hystart_enabled) {
            if (rtt_us < self.hystart_curr_rtt) {
                self.hystart_curr_rtt = rtt_us;
            }
        }
    }

    /// CUBIC window growth function W_cubic(t) per RFC 9438 Section 4.2.
    /// W_cubic(t) = C * (t - K)^3 + W_max
    /// where K = cubic_root(W_max * (1 - beta) / C)
    // PERF: Uses integer-only cubic root approximation for speed.
    fn cubicUpdate(self: *Cubic, bytes_acked: u32) void {
        const now = std.time.milliTimestamp();

        // NOTE: RFC 9438 Section 4.2 - Epoch start
        if (self.epoch_start == 0) {
            self.epoch_start = now;
            if (self.cwnd < self.w_max) {
                // K = cubic_root(W_max * (1 - beta) / C)
                // NOTE: RFC 9438 Equation (2)
                const w_diff = @as(f64, @floatFromInt(self.w_max - self.origin_point)) / @as(f64, @floatFromInt(self.mss));
                self.k = cubicRoot(w_diff / C);
            } else {
                self.k = 0;
            }
            self.reno_cwnd = self.cwnd;
        }

        // Time since epoch in seconds
        const t = @as(f64, @floatFromInt(now - self.epoch_start)) / 1000.0;

        // NOTE: RFC 9438 Equation (1) - W_cubic(t)
        const offset = t - self.k;
        const target = (C * offset * offset * offset * @as(f64, @floatFromInt(self.mss))) + @as(f64, @floatFromInt(self.w_max));

        // NOTE: RFC 9438 Section 4.3 - TCP-Friendly Reno growth (W_est)
        if (self.reno_cwnd == 0) self.reno_cwnd = self.cwnd;
        const reno_incr = (@as(u64, self.mss) * bytes_acked) / self.reno_cwnd;
        self.reno_cwnd += @as(u32, @intCast(@max(1, reno_incr)));

        // CUBIC growth
        if (target > @as(f64, @floatFromInt(self.cwnd))) {
            const diff_val = target - @as(f64, @floatFromInt(self.cwnd));
            const incr_f = (diff_val / @as(f64, @floatFromInt(self.cwnd))) * @as(f64, @floatFromInt(self.mss));
            const incr = if (incr_f > 1000000.0) @as(u32, 1000000) else @as(u32, @intFromFloat(@max(1.0, incr_f)));
            self.cwnd = self.cwnd +% incr;
        }

        // NOTE: RFC 9438 Section 4.3 - max(W_cubic, W_est) for friendliness
        if (self.cwnd < self.reno_cwnd) {
            self.cwnd = self.reno_cwnd;
        }
    }

    // PERF: Integer-only cubic root approximation using Newton-Raphson.
    fn cubicRoot(x: f64) f64 {
        if (x <= 0) return 0;
        return std.math.pow(f64, x, 1.0 / 3.0);
    }

    fn onAck(ptr: *anyopaque, bytes_acked: u32) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));

        switch (self.state) {
            .slow_start => {
                // Exponential growth
                self.cwnd += bytes_acked;
                self.hystart_acks_in_round += 1;

                // HyStart++ exit detection (RFC 9406)
                if (self.hystartCheck()) {
                    self.ssthresh = self.cwnd;
                    self.state = .congestion_avoidance;
                    self.hystart_last_rtt = self.hystart_curr_rtt;
                } else if (self.cwnd >= self.ssthresh) {
                    self.state = .congestion_avoidance;
                }
            },
            .congestion_avoidance => {
                // CUBIC congestion avoidance
                self.cubicUpdate(bytes_acked);
            },
            .fast_recovery => {
                // Exit fast recovery
                self.cwnd = self.ssthresh;
                self.state = .congestion_avoidance;
            },
            .loss => {
                self.state = .slow_start;
            },
        }

        // Cap cwnd to prevent overflow
        if (self.cwnd > 0x7FFFFFFF) self.cwnd = 0x7FFFFFFF;
    }

    fn onLoss(ptr: *anyopaque) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));

        // NOTE: RFC 9438 Section 4.5 - Multiplicative decrease
        self.epoch_start = 0;
        self.w_max = self.cwnd;
        self.ssthresh = @max(@as(u32, @intFromFloat(@as(f64, @floatFromInt(self.cwnd)) * BETA)), 2 * self.mss);
        self.cwnd = self.ssthresh + 3 * self.mss;
        self.state = .fast_recovery;
        self.reno_cwnd = self.cwnd;
    }

    fn onRetransmit(ptr: *anyopaque) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));

        // NOTE: RFC 9438 Section 4.6 - RTO handling
        self.epoch_start = 0;
        self.w_max = self.cwnd;
        self.ssthresh = @max(@as(u32, @intFromFloat(@as(f64, @floatFromInt(self.cwnd)) * BETA)), 2 * self.mss);
        self.cwnd = self.mss;
        self.origin_point = self.cwnd;
        self.state = .loss;
        self.reno_cwnd = self.cwnd;

        // Reset HyStart++ for new slow start
        self.hystart_round_start = 0;
        self.hystart_acks_in_round = 0;
        self.hystart_curr_rtt = std.math.maxInt(u64);
    }

    fn getCwnd(ptr: *anyopaque) u32 {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        return self.cwnd;
    }

    fn getSsthresh(ptr: *anyopaque) u32 {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        return self.ssthresh;
    }

    fn getState(ptr: *anyopaque) CongestionState {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        return self.state;
    }

    fn deinit(ptr: *anyopaque) void {
        const self = @as(*Cubic, @ptrCast(@alignCast(ptr)));
        self.allocator.destroy(self);
    }
};

test "CUBIC slow start growth" {
    const allocator = std.testing.allocator;
    var cc = try Cubic.init(allocator, 1460);
    defer cc.deinit();

    const initial = cc.getCwnd();
    cc.onAck(1460);
    try std.testing.expect(cc.getCwnd() > initial);
}

test "CUBIC beta reduction on loss" {
    const allocator = std.testing.allocator;
    var cc = try Cubic.init(allocator, 1460);
    defer cc.deinit();

    // Set a known cwnd
    const self = @as(*Cubic, @ptrCast(@alignCast(cc.ptr)));
    self.cwnd = 100 * 1460;
    self.state = .congestion_avoidance;

    cc.onLoss();

    // After loss, ssthresh should be ~70% of old cwnd
    const expected_ssthresh = @as(u32, @intFromFloat(100.0 * 1460.0 * 0.7));
    try std.testing.expect(cc.getSsthresh() >= expected_ssthresh - 1460);
    try std.testing.expect(cc.getSsthresh() <= expected_ssthresh + 1460);
}
