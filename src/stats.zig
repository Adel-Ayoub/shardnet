/// Runtime statistics counters for the shardnet network stack.
///
/// All counters use `std.atomic.Value(u64)` so they can be updated from
/// multiple threads (e.g. Rx and Tx paths) without requiring a mutex.
/// A point-in-time `Snapshot` can be captured for logging or metrics
/// export without blocking the data path.
const std = @import("std");

const Atomic = std.atomic.Value;

// ---------------------------------------------------------------------------
// Atomic helpers
// ---------------------------------------------------------------------------

fn atomicInc(counter: *Atomic(u64)) void {
    _ = counter.fetchAdd(1, .monotonic);
}

fn atomicAdd(counter: *Atomic(u64), value: u64) void {
    _ = counter.fetchAdd(value, .monotonic);
}

fn atomicLoad(counter: *const Atomic(u64)) u64 {
    return counter.load(.monotonic);
}

fn atomicStore(counter: *Atomic(u64), value: u64) void {
    counter.store(value, .monotonic);
}

// ---------------------------------------------------------------------------
// Per-direction byte and packet counters
// ---------------------------------------------------------------------------

/// Directional counters shared by all interfaces and protocol layers.
/// Thread-safe via atomics — no lock required on the hot path.
pub const DirectionStats = struct {
    rx_bytes: Atomic(u64) = Atomic(u64).init(0),
    tx_bytes: Atomic(u64) = Atomic(u64).init(0),
    rx_packets: Atomic(u64) = Atomic(u64).init(0),
    tx_packets: Atomic(u64) = Atomic(u64).init(0),
    rx_drops: Atomic(u64) = Atomic(u64).init(0),
    tx_drops: Atomic(u64) = Atomic(u64).init(0),

    pub fn recordRx(self: *DirectionStats, bytes: u64) void {
        atomicInc(&self.rx_packets);
        atomicAdd(&self.rx_bytes, bytes);
    }

    pub fn recordTx(self: *DirectionStats, bytes: u64) void {
        atomicInc(&self.tx_packets);
        atomicAdd(&self.tx_bytes, bytes);
    }

    pub fn recordRxDrop(self: *DirectionStats) void {
        atomicInc(&self.rx_drops);
    }

    pub fn recordTxDrop(self: *DirectionStats) void {
        atomicInc(&self.tx_drops);
    }

    pub fn reset(self: *DirectionStats) void {
        atomicStore(&self.rx_bytes, 0);
        atomicStore(&self.tx_bytes, 0);
        atomicStore(&self.rx_packets, 0);
        atomicStore(&self.tx_packets, 0);
        atomicStore(&self.rx_drops, 0);
        atomicStore(&self.tx_drops, 0);
    }
};

// ---------------------------------------------------------------------------
// Snapshot — point-in-time copy of all counters
// ---------------------------------------------------------------------------

/// An immutable copy of all counters captured at a single instant.
/// Useful for periodic logging, Prometheus scrapes, or delta computation.
pub const Snapshot = struct {
    ip: IPStatsSnapshot,
    tcp: TCPStatsSnapshot,
    arp: ARPStatsSnapshot,
    link: LinkStatsSnapshot,
    direction: DirectionStatsSnapshot,
};

pub const DirectionStatsSnapshot = struct {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    rx_drops: u64,
    tx_drops: u64,
};

pub const IPStatsSnapshot = struct {
    rx_packets: u64,
    tx_packets: u64,
    dropped_packets: u64,
    invalid_checksum: u64,
    no_route: u64,
};

pub const TCPStatsSnapshot = struct {
    rx_segments: u64,
    tx_segments: u64,
    retransmits: u64,
    active_opens: u64,
    passive_opens: u64,
    failed_connections: u64,
    established: u64,
    resets_sent: u64,
    resets_received: u64,
    active_endpoints: u64,
};

pub const ARPStatsSnapshot = struct {
    rx_requests: u64,
    rx_replies: u64,
    tx_requests: u64,
    tx_replies: u64,
};

pub const LinkStatsSnapshot = struct {
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_errors: u64,
    tx_errors: u64,
};

// ---------------------------------------------------------------------------
// Protocol-level stat structs (atomic)
// ---------------------------------------------------------------------------

pub const IPStats = struct {
    rx_packets: Atomic(u64) = Atomic(u64).init(0),
    tx_packets: Atomic(u64) = Atomic(u64).init(0),
    dropped_packets: Atomic(u64) = Atomic(u64).init(0),
    invalid_checksum: Atomic(u64) = Atomic(u64).init(0),
    no_route: Atomic(u64) = Atomic(u64).init(0),

    pub fn snapshot(self: *const IPStats) IPStatsSnapshot {
        return .{
            .rx_packets = atomicLoad(&self.rx_packets),
            .tx_packets = atomicLoad(&self.tx_packets),
            .dropped_packets = atomicLoad(&self.dropped_packets),
            .invalid_checksum = atomicLoad(&self.invalid_checksum),
            .no_route = atomicLoad(&self.no_route),
        };
    }

    pub fn reset(self: *IPStats) void {
        atomicStore(&self.rx_packets, 0);
        atomicStore(&self.tx_packets, 0);
        atomicStore(&self.dropped_packets, 0);
        atomicStore(&self.invalid_checksum, 0);
        atomicStore(&self.no_route, 0);
    }
};

pub const TCPStats = struct {
    rx_segments: Atomic(u64) = Atomic(u64).init(0),
    tx_segments: Atomic(u64) = Atomic(u64).init(0),
    retransmits: Atomic(u64) = Atomic(u64).init(0),
    active_opens: Atomic(u64) = Atomic(u64).init(0),
    passive_opens: Atomic(u64) = Atomic(u64).init(0),
    failed_connections: Atomic(u64) = Atomic(u64).init(0),
    established: Atomic(u64) = Atomic(u64).init(0),
    resets_sent: Atomic(u64) = Atomic(u64).init(0),
    resets_received: Atomic(u64) = Atomic(u64).init(0),
    active_endpoints: Atomic(u64) = Atomic(u64).init(0),
    pool_exhausted: Atomic(u64) = Atomic(u64).init(0),
    syncache_dropped: Atomic(u64) = Atomic(u64).init(0),
    syncache_searches: Atomic(u64) = Atomic(u64).init(0),
    syncache_max_size: Atomic(u64) = Atomic(u64).init(0),

    // TCP flags stats.
    rx_syn: Atomic(u64) = Atomic(u64).init(0),
    rx_syn_ack: Atomic(u64) = Atomic(u64).init(0),
    rx_ack: Atomic(u64) = Atomic(u64).init(0),
    rx_psh: Atomic(u64) = Atomic(u64).init(0),
    rx_fin: Atomic(u64) = Atomic(u64).init(0),
    tx_syn: Atomic(u64) = Atomic(u64).init(0),
    tx_syn_ack: Atomic(u64) = Atomic(u64).init(0),
    tx_ack: Atomic(u64) = Atomic(u64).init(0),
    tx_psh: Atomic(u64) = Atomic(u64).init(0),
    tx_fin: Atomic(u64) = Atomic(u64).init(0),

    pub fn snapshot(self: *const TCPStats) TCPStatsSnapshot {
        return .{
            .rx_segments = atomicLoad(&self.rx_segments),
            .tx_segments = atomicLoad(&self.tx_segments),
            .retransmits = atomicLoad(&self.retransmits),
            .active_opens = atomicLoad(&self.active_opens),
            .passive_opens = atomicLoad(&self.passive_opens),
            .failed_connections = atomicLoad(&self.failed_connections),
            .established = atomicLoad(&self.established),
            .resets_sent = atomicLoad(&self.resets_sent),
            .resets_received = atomicLoad(&self.resets_received),
            .active_endpoints = atomicLoad(&self.active_endpoints),
        };
    }

    pub fn reset(self: *TCPStats) void {
        atomicStore(&self.rx_segments, 0);
        atomicStore(&self.tx_segments, 0);
        atomicStore(&self.retransmits, 0);
        atomicStore(&self.active_opens, 0);
        atomicStore(&self.passive_opens, 0);
        atomicStore(&self.failed_connections, 0);
        atomicStore(&self.established, 0);
        atomicStore(&self.resets_sent, 0);
        atomicStore(&self.resets_received, 0);
        atomicStore(&self.active_endpoints, 0);
        atomicStore(&self.pool_exhausted, 0);
        atomicStore(&self.syncache_dropped, 0);
        atomicStore(&self.syncache_searches, 0);
        atomicStore(&self.syncache_max_size, 0);
        atomicStore(&self.rx_syn, 0);
        atomicStore(&self.rx_syn_ack, 0);
        atomicStore(&self.rx_ack, 0);
        atomicStore(&self.rx_psh, 0);
        atomicStore(&self.rx_fin, 0);
        atomicStore(&self.tx_syn, 0);
        atomicStore(&self.tx_syn_ack, 0);
        atomicStore(&self.tx_ack, 0);
        atomicStore(&self.tx_psh, 0);
        atomicStore(&self.tx_fin, 0);
    }
};

pub const ARPStats = struct {
    rx_requests: Atomic(u64) = Atomic(u64).init(0),
    rx_replies: Atomic(u64) = Atomic(u64).init(0),
    tx_requests: Atomic(u64) = Atomic(u64).init(0),
    tx_replies: Atomic(u64) = Atomic(u64).init(0),

    pub fn snapshot(self: *const ARPStats) ARPStatsSnapshot {
        return .{
            .rx_requests = atomicLoad(&self.rx_requests),
            .rx_replies = atomicLoad(&self.rx_replies),
            .tx_requests = atomicLoad(&self.tx_requests),
            .tx_replies = atomicLoad(&self.tx_replies),
        };
    }

    pub fn reset(self: *ARPStats) void {
        atomicStore(&self.rx_requests, 0);
        atomicStore(&self.rx_replies, 0);
        atomicStore(&self.tx_requests, 0);
        atomicStore(&self.tx_replies, 0);
    }
};

pub const PoolStats = struct {
    cluster_fallback: Atomic(u64) = Atomic(u64).init(0),
    buffer_fallback: Atomic(u64) = Atomic(u64).init(0),
    generic_fallback: Atomic(u64) = Atomic(u64).init(0),
    cluster_exhausted: Atomic(u64) = Atomic(u64).init(0),
    view_exhausted: Atomic(u64) = Atomic(u64).init(0),

    pub fn reset(self: *PoolStats) void {
        atomicStore(&self.cluster_fallback, 0);
        atomicStore(&self.buffer_fallback, 0);
        atomicStore(&self.generic_fallback, 0);
        atomicStore(&self.cluster_exhausted, 0);
        atomicStore(&self.view_exhausted, 0);
    }
};

pub const LinkStats = struct {
    rx_packets: Atomic(u64) = Atomic(u64).init(0),
    tx_packets: Atomic(u64) = Atomic(u64).init(0),
    rx_bytes: Atomic(u64) = Atomic(u64).init(0),
    tx_bytes: Atomic(u64) = Atomic(u64).init(0),
    rx_errors: Atomic(u64) = Atomic(u64).init(0),
    tx_errors: Atomic(u64) = Atomic(u64).init(0),
    rx_syscalls: Atomic(u64) = Atomic(u64).init(0),
    tx_syscalls: Atomic(u64) = Atomic(u64).init(0),

    pub fn snapshot(self: *const LinkStats) LinkStatsSnapshot {
        return .{
            .rx_packets = atomicLoad(&self.rx_packets),
            .tx_packets = atomicLoad(&self.tx_packets),
            .rx_bytes = atomicLoad(&self.rx_bytes),
            .tx_bytes = atomicLoad(&self.tx_bytes),
            .rx_errors = atomicLoad(&self.rx_errors),
            .tx_errors = atomicLoad(&self.tx_errors),
        };
    }

    pub fn reset(self: *LinkStats) void {
        atomicStore(&self.rx_packets, 0);
        atomicStore(&self.tx_packets, 0);
        atomicStore(&self.rx_bytes, 0);
        atomicStore(&self.tx_bytes, 0);
        atomicStore(&self.rx_errors, 0);
        atomicStore(&self.tx_errors, 0);
        atomicStore(&self.rx_syscalls, 0);
        atomicStore(&self.tx_syscalls, 0);
    }

    pub fn dump(self: *const LinkStats) void {
        const s = self.snapshot();
        std.debug.print("\n--- Link Statistics ---\n", .{});
        std.debug.print("  Rx: {d} packets, {d} bytes\n", .{ s.rx_packets, s.rx_bytes });
        std.debug.print("  Tx: {d} packets, {d} bytes\n", .{ s.tx_packets, s.tx_bytes });
        std.debug.print("  Rx Errors: {d}, Tx Errors: {d}\n", .{ s.rx_errors, s.tx_errors });
        std.debug.print("-------------------------\n\n", .{});
    }
};

// ---------------------------------------------------------------------------
// Latency tracking
// ---------------------------------------------------------------------------

pub const LatencyMetric = struct {
    count: u64 = 0,
    sum_ns: i64 = 0,
    min_ns: i64 = std.math.maxInt(i64),
    max_ns: i64 = 0,

    pub fn record(self: *@This(), ns: i64) void {
        self.count += 1;
        self.sum_ns += ns;
        if (ns < self.min_ns) self.min_ns = ns;
        if (ns > self.max_ns) self.max_ns = ns;
    }

    pub fn average(self: @This()) f64 {
        if (self.count == 0) return 0;
        return @as(f64, @floatFromInt(self.sum_ns)) / @as(f64, @floatFromInt(self.count));
    }
};

pub const LatencyStats = struct {
    link_layer: LatencyMetric = .{},
    network_layer: LatencyMetric = .{},
    transport_dispatch: LatencyMetric = .{},
    tcp_endpoint: LatencyMetric = .{},
    udp_endpoint: LatencyMetric = .{},
    driver_rx: LatencyMetric = .{},
    driver_tx: LatencyMetric = .{},

    pub fn dump(self: @This()) void {
        std.debug.print("\n--- Latency Statistics (ns) ---\n", .{});
        printMetric("Driver RX       ", self.driver_rx);
        printMetric("Driver TX       ", self.driver_tx);
        printMetric("Link Layer      ", self.link_layer);
        printMetric("Network Layer   ", self.network_layer);
        printMetric("Transport Disp  ", self.transport_dispatch);
        printMetric("TCP Endpoint    ", self.tcp_endpoint);
        printMetric("UDP Endpoint    ", self.udp_endpoint);
        std.debug.print("-------------------------------\n\n", .{});
    }

    fn printMetric(name: []const u8, m: LatencyMetric) void {
        if (m.count == 0) return;
        std.debug.print("{s}: avg={d:.2}, min={d}, max={d}, count={d}\n", .{ name, m.average(), m.min_ns, m.max_ns, m.count });
    }
};

// ---------------------------------------------------------------------------
// Aggregate stack stats
// ---------------------------------------------------------------------------

pub const StackStats = struct {
    ip: IPStats = .{},
    tcp: TCPStats = .{},
    arp: ARPStats = .{},
    latency: LatencyStats = .{},
    pool: PoolStats = .{},
    direction: DirectionStats = .{},

    /// Capture a point-in-time immutable copy of all counters.
    pub fn snapshot(self: *const StackStats) Snapshot {
        return .{
            .ip = self.ip.snapshot(),
            .tcp = self.tcp.snapshot(),
            .arp = self.arp.snapshot(),
            .link = .{
                .rx_packets = 0,
                .tx_packets = 0,
                .rx_bytes = 0,
                .tx_bytes = 0,
                .rx_errors = 0,
                .tx_errors = 0,
            },
            .direction = .{
                .rx_bytes = atomicLoad(&self.direction.rx_bytes),
                .tx_bytes = atomicLoad(&self.direction.tx_bytes),
                .rx_packets = atomicLoad(&self.direction.rx_packets),
                .tx_packets = atomicLoad(&self.direction.tx_packets),
                .rx_drops = atomicLoad(&self.direction.rx_drops),
                .tx_drops = atomicLoad(&self.direction.tx_drops),
            },
        };
    }

    /// Reset all counters to zero.
    pub fn reset(self: *StackStats) void {
        self.ip.reset();
        self.tcp.reset();
        self.arp.reset();
        self.latency = .{};
        self.pool.reset();
        self.direction.reset();
    }

    pub fn dump(self: *const StackStats) void {
        const s = self.snapshot();
        std.debug.print("\n--- ustack Statistics ---\n", .{});
        std.debug.print("IP:\n", .{});
        std.debug.print("  Rx: {d}, Tx: {d}, Dropped: {d}\n", .{ s.ip.rx_packets, s.ip.tx_packets, s.ip.dropped_packets });
        std.debug.print("ARP:\n", .{});
        std.debug.print("  Rx Req: {d}, Rx Rep: {d}, Tx Req: {d}, Tx Rep: {d}\n", .{ s.arp.rx_requests, s.arp.rx_replies, s.arp.tx_requests, s.arp.tx_replies });
        std.debug.print("TCP:\n", .{});
        std.debug.print("  Rx Seg: {d}, Tx Seg: {d}, Retrans: {d}\n", .{ s.tcp.rx_segments, s.tcp.tx_segments, s.tcp.retransmits });
        std.debug.print("Direction:\n", .{});
        std.debug.print("  Rx: {d} pkts / {d} bytes, Tx: {d} pkts / {d} bytes\n", .{ s.direction.rx_packets, s.direction.rx_bytes, s.direction.tx_packets, s.direction.tx_bytes });
        std.debug.print("  Rx Drops: {d}, Tx Drops: {d}\n", .{ s.direction.rx_drops, s.direction.tx_drops });
        std.debug.print("-------------------------\n", .{});
        self.latency.dump();
    }
};

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

pub var global_stats: StackStats = .{};
pub var global_link_stats: LinkStats = .{};
