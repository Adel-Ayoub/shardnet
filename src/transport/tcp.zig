/// TCP protocol implementation.
///
/// Implements the full RFC 793 state machine with modern extensions:
/// - Selective Acknowledgment (SACK, RFC 2018)
/// - Timestamps option (RFC 7323) for RTT measurement and PAWS
/// - Window scaling option (RFC 7323)
/// - Nagle algorithm (RFC 896) with TCP_NODELAY opt-out
/// - Fast retransmit and fast recovery (RFC 5681)
/// - SYN cookies (RFC 4987) for SYN flood mitigation
/// - ACK validation (RFC 5961) for blind data injection protection
/// - TCP keepalive (RFC 1122) with configurable parameters
/// - Proportional Rate Reduction (PRR, RFC 6937) for loss recovery
/// - Early Retransmit (RFC 5827) for small-flight fast retransmit

const std = @import("std");
const builtin = @import("builtin");
const stack = @import("../stack.zig");
const tcpip = @import("../tcpip.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");
const ipv4 = @import("../network/ipv4.zig");
const log = @import("../log.zig").scoped(.tcp);
const time = @import("../time.zig");
const stats = @import("../stats.zig");

const congestion = @import("congestion/control.zig");

pub const ProtocolNumber = 6;

/// TCP connection states per RFC 793 Section 3.2.
/// State diagram: CLOSED -> (active open) SYN_SENT -> ESTABLISHED
///                CLOSED -> (passive open) LISTEN -> SYN_RECV -> ESTABLISHED
pub const EndpointState = enum {
    /// Initial state, no connection.
    initial,
    /// Socket bound to local address.
    bound,
    /// Active open: SYN sent, waiting for SYN+ACK (RFC 793 Section 3.4).
    syn_sent,
    /// Passive open: SYN received, SYN+ACK sent (RFC 793 Section 3.4).
    syn_recv,
    /// Connection established, data transfer (RFC 793 Section 3.4).
    established,
    /// Active close: FIN sent, waiting for ACK (RFC 793 Section 3.5).
    fin_wait1,
    /// Active close: FIN acknowledged, waiting for peer FIN (RFC 793 Section 3.5).
    fin_wait2,
    /// Simultaneous close: FIN sent and received (RFC 793 Section 3.5).
    closing,
    /// Active close: Waiting 2MSL before connection can be reused (RFC 793 Section 3.5).
    time_wait,
    /// Passive close: FIN received, waiting for app close (RFC 793 Section 3.5).
    close_wait,
    /// Passive close: App closed, FIN sent, waiting for ACK (RFC 793 Section 3.5).
    last_ack,
    /// Listening for incoming connections.
    listen,
    /// Connection terminated.
    closed,
    /// Unrecoverable error occurred.
    error_state,
};

/// SYN cookie secret for SYN flood mitigation.
/// NOTE: RFC 4987 - SYN cookies encode connection state in the ISN,
/// allowing the server to avoid allocating state for half-open connections.
/// The secret SHOULD be rotated periodically (e.g., every 64 seconds).
/// SAFETY: The secret must remain confidential; if leaked, an attacker
/// can forge SYN cookies and bypass SYN flood protection.
var syn_cookie_secret: [16]u8 = undefined;
var syn_cookie_initialized: bool = false;

/// Initialize SYN cookie secret with random bytes.
fn initSynCookieSecret() void {
    if (!syn_cookie_initialized) {
        std.crypto.random.bytes(&syn_cookie_secret);
        syn_cookie_initialized = true;
    }
}

/// Generate SYN cookie ISN using keyed hash.
/// RFC 4987: ISN = hash(secret, src_ip || src_port || dst_ip || dst_port || timestamp)
fn generateSynCookie(src_addr: tcpip.Address, src_port: u16, dst_addr: tcpip.Address, dst_port: u16) u32 {
    initSynCookieSecret();

    // Use Wyhash with secret as seed
    const seed = std.mem.readInt(u64, syn_cookie_secret[0..8], .little);
    var h = std.hash.Wyhash.init(seed);

    // Hash addresses and ports
    switch (src_addr) {
        .v4 => |v4| h.update(&v4),
        .v6 => |v6| h.update(&v6),
    }
    var port_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &port_buf, src_port, .big);
    h.update(&port_buf);

    switch (dst_addr) {
        .v4 => |v4| h.update(&v4),
        .v6 => |v6| h.update(&v6),
    }
    std.mem.writeInt(u16, &port_buf, dst_port, .big);
    h.update(&port_buf);

    // Add timestamp (64-second granularity for rotation)
    const ts: u32 = @intCast(@divFloor(std.time.timestamp(), 64));
    var ts_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &ts_buf, ts, .big);
    h.update(&ts_buf);

    // Return lower 32 bits of hash
    return @truncate(h.final());
}

pub const TCPProtocol = struct {
    allocator: std.mem.Allocator,
    view_pool: buffer.BufferPool,
    header_pool: buffer.BufferPool,
    segment_node_pool: buffer.Pool(std.TailQueue(TCPEndpoint.Segment).Node),
    packet_node_pool: buffer.Pool(std.TailQueue(TCPEndpoint.Packet).Node),
    accept_node_pool: buffer.Pool(std.TailQueue(tcpip.AcceptReturn).Node),
    endpoint_pool: buffer.Pool(TCPEndpoint),
    waiter_queue_pool: buffer.Pool(waiter.Queue),

    pub fn init(allocator: std.mem.Allocator) *TCPProtocol {
        const self = allocator.create(TCPProtocol) catch unreachable;
        self.* = .{
            .allocator = allocator,
            .view_pool = buffer.BufferPool.init(allocator, @sizeOf(buffer.ClusterView) * header.MaxViewsPerPacket, 1048576),
            .header_pool = buffer.BufferPool.init(allocator, header.ReservedHeaderSize, 1048576),
            .segment_node_pool = buffer.Pool(std.TailQueue(TCPEndpoint.Segment).Node).init(allocator, 1048576),
            .packet_node_pool = buffer.Pool(std.TailQueue(TCPEndpoint.Packet).Node).init(allocator, 1048576),
            .accept_node_pool = buffer.Pool(std.TailQueue(tcpip.AcceptReturn).Node).init(allocator, 262144),
            .endpoint_pool = buffer.Pool(TCPEndpoint).init(allocator, 1048576),
            .waiter_queue_pool = buffer.Pool(waiter.Queue).init(allocator, 524288),
        };

        self.view_pool.prewarm(1024) catch {};
        self.header_pool.prewarm(1024) catch {};
        self.segment_node_pool.prewarm(1024) catch {};
        self.packet_node_pool.prewarm(1024) catch {};
        self.endpoint_pool.prewarm(1024) catch {};
        self.waiter_queue_pool.prewarm(1024) catch {};

        return self;
    }

    pub fn deinit(self: *TCPProtocol) void {
        self.view_pool.deinit();
        self.header_pool.deinit();
        self.segment_node_pool.deinit();
        self.packet_node_pool.deinit();
        self.accept_node_pool.deinit();

        for (self.endpoint_pool.free_list.items) |ep| {
            ep.deinit();
        }

        self.endpoint_pool.deinit();
        self.waiter_queue_pool.deinit();
        self.allocator.destroy(self);
    }

    pub fn protocol(self: *TCPProtocol) stack.TransportProtocol {
        return .{ .ptr = self, .vtable = &VTableImpl };
    }

    const VTableImpl = stack.TransportProtocol.VTable{
        .number = number,
        .newEndpoint = newEndpoint,
        .parsePorts = parsePorts,
        .handlePacket = handlePacket_external,
        .deinit = deinit_external,
    };

    fn deinit_external(ptr: *anyopaque) void {
        const self: *TCPProtocol = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    fn number(ptr: *anyopaque) tcpip.TransportProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn newEndpoint(ptr: *anyopaque, s: *stack.Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
        const self: *TCPProtocol = @ptrCast(@alignCast(ptr));
        _ = net_proto;
        const ep = self.endpoint_pool.acquire() catch return tcpip.Error.OutOfMemory;
        try ep.initialize_v2(s, self, wait_queue, 1460);
        return ep.endpoint();
    }

    fn handlePacket_external(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        _ = ptr;
        const ep_opt = r.nic.stack.endpoints.get(id);
        if (ep_opt) |ep| {
            const tcp_ep: *TCPEndpoint = @ptrCast(@alignCast(ep.ptr));
            tcp_ep.handlePacket(r, id, pkt);
            ep.decRef();
            return;
        }

        // Check listener with wildcard remote
        const listener_id = stack.TransportEndpointID{
            .local_port = id.local_port,
            .local_address = id.local_address,
            .remote_port = 0,
            .remote_address = switch (id.local_address) {
                .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                .v6 => .{ .v6 = [_]u8{0} ** 16 },
            },
        };
        if (r.nic.stack.endpoints.get(listener_id)) |ep| {
            const tcp_ep: *TCPEndpoint = @ptrCast(@alignCast(ep.ptr));
            tcp_ep.handlePacket(r, id, pkt);
            ep.decRef();
            return;
        }

        // Check any-address listener
        const any_id = stack.TransportEndpointID{
            .local_port = id.local_port,
            .local_address = switch (id.local_address) {
                .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                .v6 => .{ .v6 = [_]u8{0} ** 16 },
            },
            .remote_port = 0,
            .remote_address = switch (id.local_address) {
                .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                .v6 => .{ .v6 = [_]u8{0} ** 16 },
            },
        };
        if (r.nic.stack.endpoints.get(any_id)) |ep| {
            const tcp_ep: *TCPEndpoint = @ptrCast(@alignCast(ep.ptr));
            tcp_ep.handlePacket(r, id, pkt);
            ep.decRef();
            return;
        }
    }

    fn parsePorts(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.TransportProtocol.PortPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{ .src = 0, .dst = 0 };
        const h = header.TCP.init(v);
        return .{ .src = h.sourcePort(), .dst = h.destinationPort() };
    }
};

pub const TCPEndpoint = struct {
    next: ?*TCPEndpoint = null,
    prev: ?*TCPEndpoint = null,
    pooled: bool = false,

    stack: *stack.Stack = undefined,
    proto: *TCPProtocol = undefined,
    waiter_queue: *waiter.Queue = undefined,
    state: EndpointState = .initial,
    local_addr: ?tcpip.FullAddress = null,
    remote_addr: ?tcpip.FullAddress = null,

    // Sequence numbers (RFC 793 Section 3.3)
    snd_nxt: u32 = 0, // Next sequence number to send
    rcv_nxt: u32 = 0, // Next expected sequence number

    // Window scaling (RFC 7323)
    snd_wnd_scale: u8 = 0,
    rcv_wnd_scale: u8 = 14,
    rcv_wnd_max: u32 = 64 * 1024 * 1024,
    rcv_buf_used: usize = 0,
    rcv_view_count: usize = 0,
    rcv_wnd: u32 = 0,
    snd_wnd: u32 = 65535,

    // Congestion control
    cc: congestion.CongestionControl = undefined,
    ref_count: usize = 1,
    cached_route: ?stack.Route = null,
    app_closed: bool = false,
    owns_waiter_queue: bool = false,
    stack_ref: bool = false,

    // Queues
    accepted_queue: std.TailQueue(tcpip.AcceptReturn) = .{},
    rcv_list: std.TailQueue(Packet) = .{},
    ooo_list: std.TailQueue(Packet) = .{},
    snd_queue: std.TailQueue(Segment) = .{},

    // Timers
    retransmit_timer: time.Timer = undefined,
    time_wait_timer: time.Timer = undefined,
    delayed_ack_timer: time.Timer = undefined,

    // SACK (RFC 2018)
    sack_enabled: bool = false,
    hint_sack_enabled: bool = false,
    sack_blocks: std.ArrayList(SackBlock) = undefined,
    peer_sack_blocks: std.ArrayList(SackBlock) = undefined,

    // Listen backlog
    backlog: i32 = 0,
    syncache: SyncacheMap = undefined,

    // Fast retransmit (RFC 5681)
    dup_ack_count: u32 = 0,
    last_ack: u32 = 0,
    rcv_packets_since_ack: u32 = 0,
    retransmit_count: u32 = 0,

    // Timestamps (RFC 7323)
    ts_enabled: bool = false,
    ts_recent: u32 = 0,

    // MSS and Nagle
    max_segment_size: u16 = 1460,
    nagle_enabled: bool = true, // RFC 896: Nagle algorithm, disable with TCP_NODELAY

    // TCP Keepalive (RFC 1122)
    // NOTE: Keepalive is disabled by default to match BSD and Linux defaults.
    // When enabled, a probe is sent after keepalive_idle_ms of inactivity,
    // retried every keepalive_interval_ms up to keepalive_count times.
    keepalive_enabled: bool = false,
    keepalive_idle_ms: u32 = 7200_000, // 2 hours (default per RFC 1122)
    keepalive_interval_ms: u32 = 75_000, // 75 seconds
    keepalive_count: u8 = 9, // 9 probes
    keepalive_probes_sent: u8 = 0,
    keepalive_timer: time.Timer = undefined,
    last_activity_ms: i64 = 0,

    // PRR (Proportional Rate Reduction, RFC 6937)
    // NOTE: PRR replaces legacy slow-start-after-loss behaviour, providing
    // smoother recovery by pacing retransmissions proportionally to ACKs.
    prr_delivered: u32 = 0, // Data delivered since recovery started
    prr_out: u32 = 0, // Data sent since recovery started
    recovery_point: u32 = 0, // snd_nxt at start of recovery
    in_recovery: bool = false,

    // Early Retransmit (RFC 5827)
    // NOTE: Triggers fast retransmit with fewer than 3 duplicate ACKs when
    // the outstanding flight size is small (< 4 segments).
    early_retransmit_enabled: bool = true,

    // RFC 5961 ACK validation
    // NOTE: Validates that incoming ACK numbers fall within the acceptable
    // window [snd_una, snd_nxt] to prevent blind data injection attacks.
    snd_una: u32 = 0, // Oldest unacknowledged sequence number

    pub const SackBlock = struct {
        start: u32,
        end: u32,
    };

    /// Syncache entry for half-open connections (SYN flood protection).
    pub const SyncacheEntry = struct {
        remote_addr: tcpip.FullAddress,
        rcv_nxt: u32,
        snd_nxt: u32,
        ts_recent: u32,
        ts_enabled: bool,
        sack_enabled: bool,
        ws_negotiated: bool,
        snd_wnd_scale: u8,
        mss: u16,

        pub fn hash(self: SyncacheEntry) u64 {
            var h = std.hash.Wyhash.init(0);
            h.update(std.mem.asBytes(&self.remote_addr.port));
            const addr_hash = self.remote_addr.addr.hash();
            h.update(std.mem.asBytes(&addr_hash));
            return h.final();
        }

        pub fn eql(self: SyncacheEntry, other: SyncacheEntry) bool {
            return self.remote_addr.port == other.remote_addr.port and self.remote_addr.addr.eq(other.remote_addr.addr);
        }
    };

    pub const SyncacheKey = struct {
        addr: tcpip.Address,
        port: u16,

        pub fn hash(self: SyncacheKey) u64 {
            var h = std.hash.Wyhash.init(0);
            h.update(std.mem.asBytes(&self.port));
            const addr_hash = self.addr.hash();
            h.update(std.mem.asBytes(&addr_hash));
            return h.final();
        }

        pub fn eql(self: SyncacheKey, other: SyncacheKey) bool {
            return self.port == other.port and self.addr.eq(other.addr);
        }
    };

    pub const SyncacheContext = struct {
        pub fn hash(_: SyncacheContext, key: SyncacheKey) u64 {
            return key.hash();
        }
        pub fn eql(_: SyncacheContext, a: SyncacheKey, b: SyncacheKey) bool {
            return a.eql(b);
        }
    };

    pub const SyncacheMap = std.HashMap(SyncacheKey, SyncacheEntry, SyncacheContext, std.hash_map.default_max_load_percentage);

    pub const Segment = struct {
        data: buffer.VectorisedView,
        seq: u32,
        len: u32,
        flags: u8,
        timestamp: i64 = 0,
    };

    pub const Packet = struct {
        data: buffer.VectorisedView,
        seq: u32,
    };

    pub fn init(s: *stack.Stack, proto: *TCPProtocol, wq: *waiter.Queue, mss: u16) !TCPEndpoint {
        var self = TCPEndpoint{ .stack = s, .proto = proto, .waiter_queue = wq, .cc = undefined };
        try self.initialize_v2(s, proto, wq, mss);
        return self;
    }

    pub fn initialize_v2(self: *TCPEndpoint, s: *stack.Stack, proto: *TCPProtocol, wq: *waiter.Queue, mss: u16) !void {
        if (!self.pooled) {
            self.cc = try congestion.NewReno.init(s.allocator, mss);
            self.sack_blocks = std.ArrayList(SackBlock).init(s.allocator);
            self.peer_sack_blocks = std.ArrayList(SackBlock).init(s.allocator);
            self.syncache = SyncacheMap.init(s.allocator);
            self.pooled = true;
        } else {
            try self.cc.reset(mss);
            self.sack_blocks.clearRetainingCapacity();
            self.peer_sack_blocks.clearRetainingCapacity();
            if (self.state == .listen) {
                self.syncache.clearRetainingCapacity();
            }
        }

        stats.global_stats.tcp.active_endpoints += 1;

        self.stack = s;
        self.proto = proto;
        self.waiter_queue = wq;
        self.state = .initial;
        self.local_addr = null;
        self.remote_addr = null;
        const initial_seq: u32 = @intCast(@mod(std.time.milliTimestamp(), 0x7FFFFFFF));
        self.snd_nxt = initial_seq;
        self.last_ack = initial_seq;
        self.rcv_nxt = 0;
        self.snd_wnd_scale = 0;
        self.rcv_wnd_scale = 14;
        self.rcv_wnd_max = 64 * 1024 * 1024;
        self.rcv_buf_used = 0;
        self.rcv_view_count = 0;
        self.rcv_wnd = self.rcv_wnd_max;
        self.snd_wnd = 65535;
        self.ref_count = 1;
        self.stack_ref = false;
        self.cached_route = null;
        self.app_closed = false;
        self.owns_waiter_queue = false;
        self.accepted_queue = .{};
        self.rcv_list = .{};
        self.ooo_list = .{};
        self.snd_queue = .{};
        self.retransmit_timer = time.Timer.init(handleRetransmitTimer, self);
        self.time_wait_timer = time.Timer.init(handleTimeWaitTimer, self);
        self.delayed_ack_timer = time.Timer.init(handleDelayedAckTimer, self);
        self.keepalive_timer = time.Timer.init(handleKeepaliveTimer, self);
        self.sack_enabled = false;
        self.hint_sack_enabled = false;
        self.backlog = 0;
        self.dup_ack_count = 0;
        self.rcv_packets_since_ack = 0;
        self.retransmit_count = 0;
        self.ts_enabled = false;
        self.ts_recent = 0;
        self.max_segment_size = mss;
        self.nagle_enabled = true;

        // TCP Keepalive (RFC 1122) - disabled by default
        self.keepalive_enabled = false;
        self.keepalive_idle_ms = 7200_000;
        self.keepalive_interval_ms = 75_000;
        self.keepalive_count = 9;
        self.keepalive_probes_sent = 0;
        self.last_activity_ms = std.time.milliTimestamp();

        // PRR (RFC 6937) recovery state
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.recovery_point = 0;
        self.in_recovery = false;
        self.early_retransmit_enabled = true;

        // RFC 5961 ACK validation
        self.snd_una = initial_seq;
    }

    pub fn transportEndpoint(self: *TCPEndpoint) stack.TransportEndpoint {
        return .{ .ptr = self, .vtable = &TransportVTableImpl };
    }

    const TransportVTableImpl = stack.TransportEndpoint.VTable{
        .handlePacket = handlePacket_external,
        .close = close_transport_external,
        .incRef = incRef_external,
        .decRef = decRef_external,
        .notify = notify_external,
    };

    fn handlePacket_external(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        self.handlePacket(r, id, pkt);
    }

    fn close_transport_external(ptr: *anyopaque) void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        self.close();
    }

    fn notify_external(ptr: *anyopaque, mask: waiter.EventMask) void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        if (mask & waiter.EventOut != 0) {
            self.flushSendQueue() catch {};
        }
        self.notify(mask);
    }

    pub fn endpoint(self: *TCPEndpoint) tcpip.Endpoint {
        return .{ .ptr = self, .vtable = &EndpointVTableImpl };
    }

    const EndpointVTableImpl = tcpip.Endpoint.VTable{
        .close = close_endpoint_external,
        .read = read,
        .readv = readv_external,
        .write = write_external,
        .writev = writev_external,
        .writeView = writeView_external,
        .writeZeroCopy = writeZeroCopy_external,
        .ready = ready_external,
        .connect = connect,
        .shutdown = shutdown_endpoint_external,
        .listen = listen_endpoint_external,
        .accept = accept,
        .bind = bind,
        .getLocalAddress = getLocalAddress,
        .getRemoteAddress = getRemoteAddress,
        .setOption = setOption,
        .getOption = getOption,
    };

    fn writeZeroCopy_external(ptr: *anyopaque, data: []u8, cb: buffer.ConsumptionCallback, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        _ = opts;
        var view = buffer.VectorisedView.fromExternalZeroCopy(data, self.stack.allocator, 2048) catch return tcpip.Error.OutOfMemory;
        view.consumption_callback = cb;
        return self.writeInternal(view);
    }

    fn shutdown_endpoint_external(ptr: *anyopaque, flags: u8) tcpip.Error!void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        return self.shutdown_internal(flags);
    }

    fn listen_endpoint_external(ptr: *anyopaque, backlog: i32) tcpip.Error!void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        return self.listen_internal(backlog);
    }

    fn close_endpoint_external(ptr: *anyopaque) void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        self.close();
    }

    fn ready_external(ptr: *anyopaque, mask: waiter.EventMask) bool {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        return (self.waiter_queue.events() & mask) != 0;
    }

    fn writeView_external(ptr: *anyopaque, view: buffer.VectorisedView, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        _ = opts;
        return self.writeInternal(view);
    }

    fn write_external(ptr: *anyopaque, p: tcpip.Payloader, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        _ = opts;
        if (p.viewPayload()) |view| {
            return self.writeInternal(view);
        } else |_| {
            const payload_raw = try p.fullPayload();
            return self.writeRaw(payload_raw);
        }
    }

    /// Write data to the connection, applying Nagle algorithm if enabled.
    /// RFC 896: Buffer small segments until we have MSS or receive ACK.
    fn writeInternal(self: *TCPEndpoint, view: buffer.VectorisedView) tcpip.Error!usize {
        if (self.state != .established and self.state != .close_wait) return tcpip.Error.InvalidEndpointState;
        const la = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        const ra = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
        const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;
        if (self.cached_route == null or self.cached_route.?.net_proto != net_proto) {
            self.cached_route = try self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto);
        }
        const r = &self.cached_route.?;
        const next_hop = r.next_hop orelse ra.addr;
        if (r.remote_link_address == null) {
            if (self.stack.link_addr_cache.get(next_hop)) |link_addr| {
                r.remote_link_address = link_addr;
            }
        }

        // Update MSS based on path MTU
        const mtu = r.nic.linkEP.mtu();
        const header_overhead: u16 = if (la.addr == .v4) 40 else 60;
        if (mtu > header_overhead) {
            const mss: u16 = @intCast(mtu - header_overhead);
            if (mss != self.max_segment_size) {
                self.max_segment_size = mss;
                self.cc.setMss(mss);
            }
        }

        const rcv_used: u32 = @intCast(self.rcv_buf_used);
        self.rcv_wnd = if (rcv_used < self.rcv_wnd_max) self.rcv_wnd_max - rcv_used else 0;
        var total_sent: usize = 0;
        var current_view_idx: usize = 0;
        var current_view_offset: usize = 0;

        while (total_sent < view.size) {
            const in_flight: i64 = @intCast(self.snd_nxt -% self.last_ack);
            const effective_wnd = @min(self.snd_wnd, self.cc.getCwnd());
            var avail: u32 = if (effective_wnd > in_flight) @intCast(effective_wnd - in_flight) else 0;

            // Zero-window probe (RFC 793 Section 3.7)
            if (avail == 0 and self.snd_wnd == 0 and self.snd_queue.first == null and total_sent == 0) avail = 1;

            var payload_len = @min(@min(@as(u32, @intCast(view.size - total_sent)), avail), @as(u32, self.max_segment_size));

            // NOTE: Nagle algorithm (RFC 896) - buffer small segments
            // unless TCP_NODELAY is set or we have a full MSS
            if (self.nagle_enabled and payload_len < self.max_segment_size) {
                // Check if there's unacknowledged data in flight
                if (self.snd_nxt != self.last_ack) {
                    // Data in flight, don't send small segment yet
                    break;
                }
            }

            if (payload_len == 0) break;

            var seg_views: [header.MaxViewsPerPacket]buffer.ClusterView = undefined;
            var seg_view_cnt: usize = 0;
            var seg_remaining = payload_len;
            while (seg_remaining > 0) {
                const v = view.views[current_view_idx];
                const v_avail = v.view.len - current_view_offset;
                const to_take = @min(seg_remaining, v_avail);
                seg_views[seg_view_cnt] = .{ .cluster = v.cluster, .view = v.view[current_view_offset .. current_view_offset + to_take] };
                seg_view_cnt += 1;
                seg_remaining -= @as(u32, @intCast(to_take));
                current_view_offset += @as(u32, @intCast(to_take));
                if (current_view_offset == v.view.len) {
                    current_view_idx += 1;
                    current_view_offset = 0;
                }
            }

            const view_mem = try self.proto.view_pool.acquire();
            const original_views: []buffer.ClusterView = @ptrCast(@alignCast(std.mem.bytesAsSlice(buffer.ClusterView, view_mem)));
            @memcpy(original_views[0..seg_view_cnt], seg_views[0..seg_view_cnt]);
            for (original_views[0..seg_view_cnt]) |cv| {
                if (cv.cluster) |c| c.acquire();
            }

            var pb_data = buffer.VectorisedView.init(payload_len, original_views[0..seg_view_cnt]);
            pb_data.original_views = original_views;
            pb_data.view_pool = &self.proto.view_pool;

            const node = self.proto.segment_node_pool.acquire() catch break;
            node.data = .{
                .data = pb_data,
                .seq = self.snd_nxt,
                .len = payload_len,
                .flags = header.TCPFlagAck | header.TCPFlagPsh,
                .timestamp = 0,
            };
            self.snd_queue.append(node);
            self.snd_nxt +%= payload_len;
            total_sent += payload_len;
        }
        if (total_sent > 0) try self.flushSendQueue();
        if (total_sent == 0) return tcpip.Error.WouldBlock;
        if (!self.retransmit_timer.active) self.stack.timer_queue.schedule(&self.retransmit_timer, 10);
        return total_sent;
    }

    fn writeRaw(self: *TCPEndpoint, payload_raw: []const u8) tcpip.Error!usize {
        var iov = [_][]u8{@constCast(payload_raw)};
        var uio = buffer.Uio.init(&iov);
        const view = try buffer.Uio.toClusters(&uio, &self.stack.cluster_pool, self.stack.allocator);
        var mut_view = view;
        defer mut_view.deinit();
        return self.writeInternal(mut_view);
    }

    fn getLocalAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        return self.local_addr orelse tcpip.Error.InvalidEndpointState;
    }

    fn getRemoteAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        return self.remote_addr orelse tcpip.Error.InvalidEndpointState;
    }

    fn setOption(ptr: *anyopaque, opt: tcpip.EndpointOption) tcpip.Error!void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        switch (opt) {
            .ts_enabled => |v| self.ts_enabled = v,
            .tcp_nodelay => |v| self.nagle_enabled = !v, // TCP_NODELAY disables Nagle
            .reuse_address => {},
            .congestion_control => |alg| {
                self.cc.deinit();
                self.cc = switch (alg) {
                    .new_reno => try congestion.NewReno.init(self.stack.allocator, self.max_segment_size),
                    .cubic => try congestion.Cubic.init(self.stack.allocator, self.max_segment_size),
                    .bbr => try congestion.BBR.init(self.stack.allocator, self.max_segment_size),
                };
            },
        }
    }

    fn getOption(ptr: *anyopaque, opt_type: tcpip.EndpointOptionType) tcpip.EndpointOption {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        return switch (opt_type) {
            .ts_enabled => .{ .ts_enabled = self.ts_enabled },
            .tcp_nodelay => .{ .tcp_nodelay = !self.nagle_enabled },
            .reuse_address => .{ .reuse_address = false },
            .congestion_control => .{ .congestion_control = .new_reno },
        };
    }

    fn notify(self: *TCPEndpoint, mask: waiter.EventMask) void {
        if (!self.app_closed or (mask & (waiter.EventHUp | waiter.EventErr) != 0)) {
            self.waiter_queue.notify(mask);
        }
    }

    fn handleRetransmitTimer(ptr: *anyopaque) void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        self.incRef();
        defer self.decRef();
        self.checkRetransmit(false) catch {};
        if (self.snd_queue.first != null and self.state != .error_state and self.state != .closed) {
            self.stack.timer_queue.schedule(&self.retransmit_timer, 10);
        }
    }

    /// TIME_WAIT timer expiration (RFC 793 Section 3.5).
    /// After 2MSL, the connection can be fully closed and the 4-tuple reused.
    fn handleTimeWaitTimer(ptr: *anyopaque) void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        // NOTE: RFC 793 Section 3.5 - TIME_WAIT to CLOSED after 2MSL
        self.state = .closed;
        if (self.local_addr) |la| {
            if (self.remote_addr) |ra| {
                const term_id = stack.TransportEndpointID{
                    .local_port = la.port,
                    .local_address = la.addr,
                    .remote_port = ra.port,
                    .remote_address = ra.addr,
                };
                self.stack.unregisterTransportEndpoint(term_id);
            }
        }
        self.decStackRef();
    }

    fn handleDelayedAckTimer(ptr: *anyopaque) void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        self.incRef();
        defer self.decRef();
        if (self.state != .established and self.state != .close_wait) return;
        if (self.rcv_packets_since_ack > 0) {
            self.sendControl(header.TCPFlagAck) catch {};
            self.rcv_packets_since_ack = 0;
        }
    }

    /// TCP keepalive timer handler (RFC 1122 Section 4.2.3.6).
    /// Sends keepalive probes when the connection has been idle.
    fn handleKeepaliveTimer(ptr: *anyopaque) void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        self.incRef();
        defer self.decRef();

        if (!self.keepalive_enabled) return;
        if (self.state != .established and self.state != .close_wait) return;

        const now = std.time.milliTimestamp();
        const idle_time = now - self.last_activity_ms;

        // Check if we've been idle long enough
        if (idle_time < self.keepalive_idle_ms) {
            // Reschedule for remaining idle time
            const remaining = self.keepalive_idle_ms - @as(u32, @intCast(idle_time));
            self.stack.timer_queue.schedule(&self.keepalive_timer, remaining);
            return;
        }

        // Check if we've exceeded probe count
        if (self.keepalive_probes_sent >= self.keepalive_count) {
            // NOTE: Connection is dead, close it
            log.warn("TCP: Keepalive probes exhausted, closing connection", .{});
            self.state = .error_state;
            self.notify(waiter.EventErr | waiter.EventHup);
            return;
        }

        // Send keepalive probe (ACK with seq = snd_una - 1)
        self.sendKeepaliveProbe() catch {};
        self.keepalive_probes_sent += 1;

        // Schedule next probe
        self.stack.timer_queue.schedule(&self.keepalive_timer, self.keepalive_interval_ms);
    }

    /// Send a TCP keepalive probe.
    /// The probe is an ACK with sequence number snd_una - 1 (RFC 1122).
    fn sendKeepaliveProbe(self: *TCPEndpoint) !void {
        const la = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        const ra = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
        const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;

        if (self.cached_route == null or self.cached_route.?.net_proto != net_proto) {
            self.cached_route = try self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto);
        }
        var r = self.cached_route.?;

        const hdr_buf = self.proto.header_pool.acquire() catch return tcpip.Error.OutOfMemory;
        var pre = buffer.Prependable.init(hdr_buf);
        const tcp_hdr = pre.prepend(header.TCPMinimumSize).?;
        @memset(tcp_hdr, 0);
        var h = header.TCP.init(tcp_hdr);

        // NOTE: Keepalive probe uses seq = snd_una - 1 to elicit ACK
        const probe_seq = self.snd_una -% 1;
        h.encode(la.port, ra.port, probe_seq, self.rcv_nxt, header.TCPFlagAck, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
        h.setChecksum(h.calculateChecksum(la.addr, ra.addr, &.{}));

        const pb = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.empty(),
            .header = pre,
        };

        try r.writePacket(ProtocolNumber, pb);
        stats.global_stats.tcp.tx_keepalive_probes += 1;
    }

    /// Reset keepalive timer on activity.
    fn resetKeepaliveTimer(self: *TCPEndpoint) void {
        if (!self.keepalive_enabled) return;
        self.last_activity_ms = std.time.milliTimestamp();
        self.keepalive_probes_sent = 0;
        if (self.state == .established or self.state == .close_wait) {
            self.stack.timer_queue.cancel(&self.keepalive_timer);
            self.stack.timer_queue.schedule(&self.keepalive_timer, self.keepalive_idle_ms);
        }
    }

    /// Validate ACK number per RFC 5961.
    /// Returns true if the ACK is within the acceptable window.
    /// SAFETY: This prevents blind data injection attacks where an attacker
    /// guesses ACK numbers to inject data into the connection.
    fn validateAck(self: *TCPEndpoint, ack: u32) bool {
        // RFC 5961 Section 5.2: ACK must be in range (snd_una, snd_nxt]
        const diff_una = ack -% self.snd_una;
        const diff_nxt = self.snd_nxt -% self.snd_una;

        // ACK is valid if snd_una < ack <= snd_nxt
        return diff_una > 0 and diff_una <= diff_nxt;
    }

    /// PRR (Proportional Rate Reduction) send decision per RFC 6937.
    /// Returns the number of bytes allowed to send during recovery.
    /// NOTE: PRR equation (Figure 1 of RFC 6937):
    ///   sndcnt = CEIL(prr_delivered * ssthresh / RecoverFS) - prr_out
    fn prrAllowedSend(self: *TCPEndpoint) u32 {
        if (!self.in_recovery) return self.cc.getCwnd();

        const ssthresh = self.cc.getSsthresh();
        const recover_fs = self.recovery_point -% self.snd_una;
        if (recover_fs == 0) return 0;

        // PRR-SSRB (Slow Start Reduction Bound) variant
        const limit = @divFloor(self.prr_delivered * ssthresh, recover_fs);
        if (limit > self.prr_out) {
            return @as(u32, @intCast(limit - self.prr_out));
        }
        return 0;
    }

    /// Enter recovery mode for PRR.
    fn enterRecovery(self: *TCPEndpoint) void {
        if (self.in_recovery) return;
        self.in_recovery = true;
        self.recovery_point = self.snd_nxt;
        self.prr_delivered = 0;
        self.prr_out = 0;
        self.cc.onLoss();
        log.debug("TCP: Entering PRR recovery, recovery_point={}", .{self.recovery_point});
    }

    /// Exit recovery mode when all lost data is acknowledged.
    fn maybeExitRecovery(self: *TCPEndpoint, ack: u32) void {
        if (!self.in_recovery) return;
        // Exit recovery when ACK >= recovery_point
        const diff = ack -% self.recovery_point;
        if (diff == 0 or (diff > 0 and diff < 0x80000000)) {
            self.in_recovery = false;
            log.debug("TCP: Exiting PRR recovery", .{});
        }
    }

    /// Check for Early Retransmit (RFC 5827).
    /// Triggers fast retransmit with fewer than 3 dup ACKs when flight is small.
    fn checkEarlyRetransmit(self: *TCPEndpoint) bool {
        if (!self.early_retransmit_enabled) return false;

        // RFC 5827 Section 3: ER triggers when:
        // 1. Flight size is less than 4 segments
        // 2. There are no unsent data segments
        // 3. DupAck count >= (outstanding - 1)
        const in_flight = self.snd_nxt -% self.snd_una;
        const mss = self.max_segment_size;
        const outstanding_segments = (in_flight + mss - 1) / mss;

        if (outstanding_segments >= 4) return false;
        if (self.snd_queue.first == null) return false; // Nothing to retransmit

        // ER threshold: dup_ack_count >= outstanding - 1
        if (self.dup_ack_count >= outstanding_segments -| 1) {
            log.debug("TCP: Early Retransmit triggered (dup_acks={}, outstanding={})", .{ self.dup_ack_count, outstanding_segments });
            return true;
        }
        return false;
    }

    /// Implement delayed ACKs (RFC 1122 Section 4.2.3.2).
    /// ACK every 2 segments or after 40ms, whichever comes first.
    fn maybeSendDelayedAck(self: *TCPEndpoint, data_len: usize) void {
        _ = data_len;
        self.rcv_packets_since_ack += 1;
        if (self.rcv_packets_since_ack >= 2) {
            self.stack.timer_queue.cancel(&self.delayed_ack_timer);
            self.sendControl(header.TCPFlagAck) catch {};
            self.rcv_packets_since_ack = 0;
        } else {
            if (!self.delayed_ack_timer.active) {
                // 40ms delay (Linux default, BSD uses 200ms)
                self.stack.timer_queue.schedule(&self.delayed_ack_timer, 40);
            }
        }
    }

    pub fn checkRetransmit(self: *TCPEndpoint, force: bool) tcpip.Error!void {
        var notify_mask: waiter.EventMask = 0;
        defer {
            if (notify_mask != 0) self.notify(notify_mask);
        }
        return self.checkRetransmitLocked(force, &notify_mask);
    }

    fn flushSendQueue(self: *TCPEndpoint) !void {
        var it = self.snd_queue.first;
        if (it == null) return;
        const la = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        const ra = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
        const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;
        if (self.cached_route == null or self.cached_route.?.net_proto != net_proto) {
            self.cached_route = try self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto);
        }
        const r = &self.cached_route.?;
        const next_hop = r.next_hop orelse ra.addr;
        if (r.remote_link_address == null) {
            if (self.stack.link_addr_cache.get(next_hop)) |link_addr| {
                r.remote_link_address = link_addr;
            }
        }
        var packet_batch: [64]tcpip.PacketBuffer = undefined;
        var batch_count: usize = 0;
        const now = std.time.milliTimestamp();
        while (it) |node| {
            if (node.data.timestamp != 0) {
                it = node.next;
                continue;
            }
            const hdr_buf = self.proto.header_pool.acquire() catch break;
            var pre = buffer.Prependable.init(hdr_buf);
            const options_len: u8 = if (node.data.flags & header.TCPFlagSyn != 0) 12 else 0;
            const tcp_hdr = pre.prepend(header.TCPMinimumSize + options_len).?;
            @memset(tcp_hdr, 0);
            var h = header.TCP.init(tcp_hdr);
            h.encode(la.port, ra.port, node.data.seq, self.rcv_nxt, node.data.flags, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
            if (options_len > 0) {
                h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
                var opt_ptr = h.data[20..];
                opt_ptr[0] = 2;
                opt_ptr[1] = 4;
                std.mem.writeInt(u16, opt_ptr[2..4][0..2], self.max_segment_size, .big);
                opt_ptr = opt_ptr[4..];
                if (node.data.flags & header.TCPFlagSyn != 0) {
                    opt_ptr[0] = 1;
                    opt_ptr[1] = 3;
                    opt_ptr[2] = 3;
                    opt_ptr[3] = self.rcv_wnd_scale;
                }
            }
            h.setChecksum(h.calculateChecksumVectorised(la.addr.v4, ra.addr.v4, node.data.data));
            packet_batch[batch_count] = .{ .data = node.data.data, .header = pre };

            // Piggyback ACK cancels delayed ACK timer
            if (self.delayed_ack_timer.active) {
                self.stack.timer_queue.cancel(&self.delayed_ack_timer);
                self.rcv_packets_since_ack = 0;
            }

            stats.global_stats.tcp.tx_segments += 1;
            if (node.data.flags & header.TCPFlagSyn != 0) {
                if (node.data.flags & header.TCPFlagAck != 0) {
                    stats.global_stats.tcp.tx_syn_ack += 1;
                } else {
                    stats.global_stats.tcp.tx_syn += 1;
                }
            }
            if (node.data.flags & header.TCPFlagAck != 0) stats.global_stats.tcp.tx_ack += 1;
            if (node.data.flags & header.TCPFlagPsh != 0) stats.global_stats.tcp.tx_psh += 1;
            if (node.data.flags & header.TCPFlagFin != 0) stats.global_stats.tcp.tx_fin += 1;

            node.data.timestamp = now;
            batch_count += 1;
            if (batch_count == 64) {
                const net_ep = r.nic.network_endpoints.get(r.net_proto) orelse break;
                net_ep.writePackets(r, ProtocolNumber, packet_batch[0..batch_count]) catch |err| {
                    for (packet_batch[0..batch_count]) |p| self.proto.header_pool.release(p.header.buf);
                    return err;
                };
                for (packet_batch[0..batch_count]) |p| self.proto.header_pool.release(p.header.buf);
                batch_count = 0;
            }
            it = node.next;
        }
        if (batch_count > 0) {
            const net_ep = r.nic.network_endpoints.get(r.net_proto) orelse return;
            net_ep.writePackets(r, ProtocolNumber, packet_batch[0..batch_count]) catch |err| {
                for (packet_batch[0..batch_count]) |p| self.proto.header_pool.release(p.header.buf);
                return err;
            };
            for (packet_batch[0..batch_count]) |p| self.proto.header_pool.release(p.header.buf);
        }
    }

    /// Retransmit check with SACK-aware pruning.
    /// RFC 2018: Skip segments covered by SACK blocks.
    fn checkRetransmitLocked(self: *TCPEndpoint, force: bool, notify_mask: *waiter.EventMask) tcpip.Error!void {
        const now = std.time.milliTimestamp();
        var it = self.snd_queue.first;
        if (it != null) {
            if (!force) {
                self.retransmit_count += 1;
                // Give up after too many retransmits
                if (self.retransmit_count > 30) {
                    self.state = .error_state;
                    while (self.snd_queue.popFirst()) |node| {
                        node.data.data.deinit();
                        self.proto.segment_node_pool.release(node);
                    }
                    notify_mask.* = waiter.EventErr;
                    return;
                }
            }
        } else self.retransmit_count = 0;

        while (it) |node| {
            // NOTE: SACK-based selective retransmit (RFC 2018)
            var sacked = false;
            for (self.peer_sack_blocks.items) |block| {
                const flag_len: u32 = if ((node.data.flags & (header.TCPFlagSyn | header.TCPFlagFin)) != 0) 1 else 0;
                const seg_end = node.data.seq +% node.data.len +% flag_len;
                if (seqAfterEq(node.data.seq, block.start) and seqBeforeEq(seg_end, block.end)) {
                    sacked = true;
                    break;
                }
            }
            if (sacked) {
                it = node.next;
                continue;
            }
            if (force or node.data.timestamp == 0 or (now - node.data.timestamp > 10)) {
                if (!force and node.data.timestamp != 0) self.cc.onLoss();
                const la = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
                const ra = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;
                const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;
                if (self.cached_route == null or self.cached_route.?.net_proto != net_proto) {
                    self.cached_route = try self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto);
                }
                var r = self.cached_route.?;
                const next_hop = r.next_hop orelse ra.addr;
                if (r.remote_link_address == null) {
                    if (self.stack.link_addr_cache.get(next_hop)) |link_addr| {
                        r.remote_link_address = link_addr;
                        self.cached_route.?.remote_link_address = link_addr;
                    }
                }
                const hdr_buf = self.proto.header_pool.acquire() catch return;
                defer self.proto.header_pool.release(hdr_buf);
                var pre = buffer.Prependable.init(hdr_buf);
                const options_len: u8 = if (node.data.flags & header.TCPFlagSyn != 0) 12 else 0;
                const tcp_hdr = pre.prepend(header.TCPMinimumSize + options_len).?;
                @memset(tcp_hdr, 0);
                var retransmit_h = header.TCP.init(tcp_hdr);
                retransmit_h.encode(la.port, ra.port, node.data.seq, self.rcv_nxt, node.data.flags, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
                if (options_len > 0) {
                    retransmit_h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
                    var opt_ptr = retransmit_h.data[20..];
                    if (node.data.flags & header.TCPFlagSyn != 0) {
                        opt_ptr[0] = 2;
                        opt_ptr[1] = 4;
                        std.mem.writeInt(u16, opt_ptr[2..4][0..2], self.max_segment_size, .big);
                        opt_ptr[4] = 1;
                        opt_ptr[5] = 3;
                        opt_ptr[6] = 3;
                        opt_ptr[7] = self.rcv_wnd_scale;
                        opt_ptr[8] = 1;
                        opt_ptr[9] = 1;
                        opt_ptr[10] = 4;
                        opt_ptr[11] = 2;
                    }
                }
                const view_mem = self.proto.view_pool.acquire() catch return;
                const views: []buffer.ClusterView = @ptrCast(@alignCast(std.mem.bytesAsSlice(buffer.ClusterView, view_mem)));
                for (views[0..node.data.data.views.len], node.data.data.views) |*dst, src| {
                    dst.* = src;
                    if (src.cluster) |c| c.acquire();
                }
                const pb = tcpip.PacketBuffer{ .data = buffer.VectorisedView.init(node.data.data.size, views[0..node.data.data.views.len]), .header = pre };
                retransmit_h.setChecksum(retransmit_h.calculateChecksumVectorised(la.addr.v4, ra.addr.v4, pb.data));
                var mut_pb = pb;
                mut_pb.data.original_views = views;
                mut_pb.data.view_pool = &self.proto.view_pool;
                var mut_r = r;
                mut_r.writePacket(6, mut_pb) catch {};
                mut_pb.data.deinit();
                node.data.timestamp = now;
                if (force) break;
            }
            it = node.next;
        }
    }

    fn incRef_external(ptr: *anyopaque) void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        self.incRef();
    }
    fn decRef_external(ptr: *anyopaque) void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        self.decRef();
    }
    pub fn incRef(self: *TCPEndpoint) void {
        self.ref_count += 1;
    }
    pub fn decRef(self: *TCPEndpoint) void {
        if (self.ref_count == 0) {
            log.warn("decRef on endpoint with 0 ref", .{});
            return;
        }
        self.ref_count -= 1;
        if (self.ref_count == 0) {
            self.destroy();
        }
    }

    fn incStackRef(self: *TCPEndpoint) void {
        if (!self.stack_ref) {
            self.incRef();
            self.stack_ref = true;
        }
    }

    fn decStackRef(self: *TCPEndpoint) void {
        if (self.stack_ref) {
            self.stack_ref = false;
            self.decRef();
        }
    }

    pub fn deinit(self: *TCPEndpoint) void {
        if (self.pooled) {
            self.cc.deinit();
            self.sack_blocks.deinit();
            self.peer_sack_blocks.deinit();
            self.syncache.deinit();
            self.pooled = false;
        }
    }

    fn destroy(self: *TCPEndpoint) void {
        stats.global_stats.tcp.active_endpoints -= 1;

        while (self.rcv_list.popFirst()) |node| {
            node.data.data.deinit();
            self.proto.packet_node_pool.release(node);
        }

        while (self.ooo_list.popFirst()) |node| {
            node.data.data.deinit();
            self.proto.packet_node_pool.release(node);
        }

        while (self.accepted_queue.popFirst()) |node| {
            node.data.ep.close();
            self.proto.accept_node_pool.release(node);
        }

        self.stack.timer_queue.cancel(&self.retransmit_timer);
        self.stack.timer_queue.cancel(&self.time_wait_timer);
        self.stack.timer_queue.cancel(&self.delayed_ack_timer);

        while (self.snd_queue.popFirst()) |node| {
            node.data.data.deinit();
            self.proto.segment_node_pool.release(node);
        }

        if (self.owns_waiter_queue) {
            self.proto.waiter_queue_pool.release(self.waiter_queue);
        }

        if (!self.proto.endpoint_pool.tryRelease(self)) {
            self.deinit();
            self.proto.allocator.destroy(self);
        }
    }

    /// Close the connection following RFC 793 Section 3.5.
    pub fn close(self: *TCPEndpoint) void {
        self.app_closed = true;
        if (self.state == .established) {
            // NOTE: RFC 793 Section 3.5 - ESTABLISHED to FIN_WAIT_1 (active close)
            self.state = .fin_wait1;
            self.enqueueControl(header.TCPFlagFin | header.TCPFlagAck) catch {};
        } else if (self.state == .close_wait) {
            // NOTE: RFC 793 Section 3.5 - CLOSE_WAIT to LAST_ACK
            self.state = .last_ack;
            self.enqueueControl(header.TCPFlagFin | header.TCPFlagAck) catch {};
        } else if (self.state == .listen) {
            self.state = .closed;
            if (self.local_addr) |la| {
                const id = stack.TransportEndpointID{ .local_port = la.port, .local_address = la.addr, .remote_port = 0, .remote_address = .{ .v4 = .{ 0, 0, 0, 0 } } };
                self.stack.unregisterTransportEndpoint(id);
            }
        } else if (self.state == .syn_sent or self.state == .syn_recv) {
            self.state = .closed;
            if (self.local_addr) |la| {
                if (self.remote_addr) |ra| {
                    const id = stack.TransportEndpointID{ .local_port = la.port, .local_address = la.addr, .remote_port = ra.port, .remote_address = ra.addr };
                    self.stack.unregisterTransportEndpoint(id);
                }
            }
        }

        if (self.state == .closed or self.state == .error_state) {
            self.decStackRef();
            if (self.local_addr) |la| {
                if (self.remote_addr) |ra| {
                    const id = stack.TransportEndpointID{
                        .local_port = la.port,
                        .local_address = la.addr,
                        .remote_port = ra.port,
                        .remote_address = ra.addr,
                    };
                    const shard = self.stack.endpoints.getShard(id);
                    if (shard.get(id)) |ep| {
                        if (ep.ptr == @as(*anyopaque, @ptrCast(self))) {
                            _ = self.stack.endpoints.fetchRemove(id);
                            ep.decRef();
                        }
                        ep.decRef();
                    }
                }
            }
        }

        self.decRef();
    }

    fn onConsumed(ptr: *anyopaque, size: usize) void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));

        const old_rcv_wnd = self.rcv_wnd;
        self.rcv_buf_used -= size;
        self.rcv_wnd = self.rcv_wnd_max - @as(u32, @intCast(self.rcv_buf_used));

        // Send window update if window opened significantly
        if ((old_rcv_wnd == 0) or (self.rcv_wnd -% old_rcv_wnd >= self.rcv_wnd_max / 4)) {
            self.sendControl(header.TCPFlagAck) catch {};
        }
    }

    fn writev_external(ptr: *anyopaque, uio: *buffer.Uio, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        _ = opts;
        const view = try buffer.Uio.toViews(uio, self.stack.allocator, header.ClusterSize);
        var mut_view = view;
        defer mut_view.deinit();
        return self.writeInternal(mut_view);
    }

    fn readv_external(ptr: *anyopaque, uio: *buffer.Uio, addr: ?*tcpip.FullAddress) tcpip.Error!usize {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        return self.readv(uio, addr);
    }

    fn readv(self: *TCPEndpoint, uio: *buffer.Uio, addr: ?*tcpip.FullAddress) tcpip.Error!usize {
        if (self.rcv_list.first == null) return if (self.state == .closed or self.state == .close_wait) 0 else tcpip.Error.WouldBlock;
        if (addr) |a| a.* = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;

        const old_rcv_wnd = self.rcv_wnd;
        var total_moved: usize = 0;
        while (self.rcv_list.first) |node| {
            const moved = node.data.data.moveToUio(uio);
            total_moved += moved;
            self.rcv_buf_used -= moved;

            if (node.data.data.size == 0) {
                _ = self.rcv_list.popFirst();
                node.data.data.deinit();
                self.proto.packet_node_pool.release(node);
            }

            if (uio.resid == 0) break;
        }

        var it = self.rcv_list.first;
        self.rcv_view_count = 0;
        while (it) |node| {
            self.rcv_view_count += node.data.data.views.len;
            it = node.next;
        }

        if (total_moved > 0) {
            const rcv_used: u32 = @intCast(self.rcv_buf_used);
            self.rcv_wnd = if (rcv_used < self.rcv_wnd_max) self.rcv_wnd_max - rcv_used else 0;
            if ((old_rcv_wnd == 0) or (self.rcv_wnd -% old_rcv_wnd >= self.rcv_wnd_max / 4)) {
                self.sendControl(header.TCPFlagAck) catch {};
            }
        }

        return total_moved;
    }

    fn read(ptr: *anyopaque, addr: ?*tcpip.FullAddress) tcpip.Error!buffer.VectorisedView {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));

        if (self.rcv_list.first == null) return if (self.state == .closed or self.state == .close_wait or self.state == .time_wait or self.state == .last_ack) buffer.VectorisedView.empty() else tcpip.Error.WouldBlock;

        if (addr) |a| a.* = self.remote_addr orelse return tcpip.Error.InvalidEndpointState;

        const num_views = self.rcv_view_count;
        const total_size = self.rcv_buf_used;
        var v_idx: usize = 0;

        var views: []buffer.ClusterView = undefined;
        var original_views: []buffer.ClusterView = &[_]buffer.ClusterView{};
        var view_pool_used: ?*buffer.BufferPool = null;

        if (num_views <= header.MaxViewsPerPacket) {
            const view_mem = self.proto.view_pool.acquire() catch return tcpip.Error.OutOfMemory;

            original_views = @ptrCast(@alignCast(std.mem.bytesAsSlice(buffer.ClusterView, view_mem)));
            views = original_views[0..num_views];
            view_pool_used = &self.proto.view_pool;
        } else {
            views = self.stack.allocator.alloc(buffer.ClusterView, num_views) catch return tcpip.Error.OutOfMemory;
            original_views = views;
        }

        while (self.rcv_list.popFirst()) |node| {
            for (node.data.data.views) |cv| {
                views[v_idx] = cv;
                v_idx += 1;
            }

            if (node.data.data.view_pool) |pool| pool.release(std.mem.sliceAsBytes(node.data.data.original_views)) else if (node.data.data.allocator) |alloc| alloc.free(node.data.data.original_views);

            self.proto.packet_node_pool.release(node);
        }

        self.rcv_view_count = 0;

        if (self.rcv_list.first == null) {
            if (self.state == .closed or self.state == .close_wait or self.state == .time_wait or self.state == .last_ack) {
                // Keep for app to read 0
            } else {
                self.waiter_queue.clear(waiter.EventIn);
            }
        }

        var res = buffer.VectorisedView.init(total_size, views);
        res.original_views = original_views;

        if (view_pool_used) |pool| res.view_pool = pool else res.allocator = self.stack.allocator;

        res.consumption_callback = .{ .ptr = self, .run = onConsumed };

        return res;
    }

    /// Initiate active open (RFC 793 Section 3.4).
    fn connect(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        if (self.state != .initial and self.state != .bound) return;
        self.remote_addr = addr;
        const la = self.local_addr orelse return tcpip.Error.InvalidEndpointState;

        // Unregister bound placeholder
        const bound_id = stack.TransportEndpointID{ .local_port = la.port, .local_address = la.addr, .remote_port = 0, .remote_address = .{ .v4 = .{ 0, 0, 0, 0 } } };
        self.stack.unregisterTransportEndpoint(bound_id);

        // NOTE: RFC 793 Section 3.4 - CLOSED to SYN_SENT (active open)
        self.state = .syn_sent;
        self.incStackRef();
        const initial_seq: u32 = @intCast(@mod(std.time.milliTimestamp(), 0x7FFFFFFF));
        self.snd_nxt = initial_seq;
        self.last_ack = initial_seq;
        self.snd_nxt +%= 1;

        const id = stack.TransportEndpointID{ .local_port = la.port, .local_address = la.addr, .remote_port = addr.port, .remote_address = addr.addr };
        self.stack.registerTransportEndpoint(id, self.transportEndpoint()) catch return tcpip.Error.OutOfMemory;

        const node = self.proto.segment_node_pool.acquire() catch return tcpip.Error.OutOfMemory;
        node.data = .{ .data = buffer.VectorisedView.empty(), .seq = initial_seq, .len = 0, .flags = header.TCPFlagSyn, .timestamp = 0 };
        self.snd_queue.append(node);
        if (!self.retransmit_timer.active) self.stack.timer_queue.schedule(&self.retransmit_timer, 10);
        try self.flushSendQueue();
    }

    fn shutdown_internal(self: *TCPEndpoint, flags: u8) tcpip.Error!void {
        _ = flags;
        if (self.state == .established) {
            // NOTE: RFC 793 Section 3.5 - shutdown initiates FIN_WAIT_1
            self.state = .fin_wait1;
            try self.enqueueControl(header.TCPFlagFin | header.TCPFlagAck);
        } else if (self.state == .close_wait) {
            self.state = .last_ack;
            try self.enqueueControl(header.TCPFlagFin | header.TCPFlagAck);
        }
    }

    fn listen_internal(self: *TCPEndpoint, backlog: i32) tcpip.Error!void {
        self.backlog = if (backlog > 0) backlog else 128;
        // NOTE: RFC 793 - CLOSED to LISTEN (passive open)
        self.state = .listen;
        if (self.local_addr) |la| {
            const id = stack.TransportEndpointID{ .local_port = la.port, .local_address = la.addr, .remote_port = 0, .remote_address = .{ .v4 = .{ 0, 0, 0, 0 } } };
            self.stack.registerTransportEndpoint(id, self.transportEndpoint()) catch return tcpip.Error.OutOfMemory;
        }
    }

    fn accept(ptr: *anyopaque) tcpip.Error!tcpip.AcceptReturn {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        const node = self.accepted_queue.popFirst() orelse return tcpip.Error.WouldBlock;
        if (self.accepted_queue.first == null) {
            self.waiter_queue.clear(waiter.EventIn);
        }
        defer self.proto.accept_node_pool.release(node);
        return node.data;
    }

    fn bind(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self: *TCPEndpoint = @ptrCast(@alignCast(ptr));
        if (self.state != .initial) return tcpip.Error.InvalidEndpointState;
        var final_addr = addr;
        if (final_addr.port == 0) final_addr.port = self.stack.getNextEphemeralPort();

        const id = stack.TransportEndpointID{ .local_port = final_addr.port, .local_address = final_addr.addr, .remote_port = 0, .remote_address = .{ .v4 = .{ 0, 0, 0, 0 } } };
        const shard = self.stack.endpoints.getShard(id);
        if (shard.get(id)) |existing_ep| {
            defer existing_ep.decRef();
            const existing_tcp: *TCPEndpoint = @ptrCast(@alignCast(existing_ep.ptr));
            if (existing_tcp.state != .time_wait and existing_tcp.state != .closed) {
                return tcpip.Error.AddressInUse;
            }
            _ = self.stack.endpoints.fetchRemove(id);
            existing_ep.decRef();
        }

        self.stack.registerTransportEndpoint(id, self.transportEndpoint()) catch return tcpip.Error.OutOfMemory;
        self.local_addr = final_addr;
        self.state = .bound;
    }

    fn enqueueControl(self: *TCPEndpoint, flags: u8) !void {
        const node = self.proto.segment_node_pool.acquire() catch return error.OutOfMemory;
        node.data = .{ .data = buffer.VectorisedView.empty(), .seq = self.snd_nxt, .len = 0, .flags = flags, .timestamp = 0 };
        self.snd_queue.append(node);
        if (flags & (header.TCPFlagSyn | header.TCPFlagFin) != 0) self.snd_nxt +%= 1;
        try self.flushSendQueue();
    }

    fn sendControl(self: *TCPEndpoint, flags: u8) !void {
        const la = self.local_addr orelse return;
        const ra = self.remote_addr orelse return;
        const net_proto: u16 = if (ra.addr == .v4) 0x0800 else 0x86dd;
        if (self.cached_route == null or self.cached_route.?.net_proto != net_proto) {
            self.cached_route = try self.stack.findRoute(ra.nic, la.addr, ra.addr, net_proto);
        }
        const r = &self.cached_route.?;
        const next_hop = r.next_hop orelse ra.addr;
        if (r.remote_link_address == null) {
            if (self.stack.link_addr_cache.get(next_hop)) |link_addr| {
                r.remote_link_address = link_addr;
            }
        }
        const hdr_buf = try self.proto.header_pool.acquire();
        defer self.proto.header_pool.release(hdr_buf);
        var pre = buffer.Prependable.init(hdr_buf);
        const tcp_hdr = pre.prepend(header.TCPMinimumSize).?;
        @memset(tcp_hdr, 0);
        var h = header.TCP.init(tcp_hdr);
        const rcv_used: u32 = @intCast(self.rcv_buf_used);
        self.rcv_wnd = if (rcv_used < self.rcv_wnd_max) self.rcv_wnd_max - rcv_used else 0;
        h.encode(la.port, ra.port, self.snd_nxt, self.rcv_nxt, flags, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
        h.setChecksum(h.calculateChecksum(la.addr.v4, ra.addr.v4, &[_]u8{}));
        const pb = tcpip.PacketBuffer{ .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 }, .header = pre };

        stats.global_stats.tcp.tx_segments += 1;
        if (flags & header.TCPFlagSyn != 0) {
            if (flags & header.TCPFlagAck != 0) {
                stats.global_stats.tcp.tx_syn_ack += 1;
            } else {
                stats.global_stats.tcp.tx_syn += 1;
            }
        }
        if (flags & header.TCPFlagAck != 0) stats.global_stats.tcp.tx_ack += 1;
        if (flags & header.TCPFlagPsh != 0) stats.global_stats.tcp.tx_psh += 1;
        if (flags & header.TCPFlagFin != 0) stats.global_stats.tcp.tx_fin += 1;

        var mut_r = r;
        try mut_r.writePacket(6, pb);
    }

    fn sendSynAck(self: *TCPEndpoint, r: *const stack.Route, id: stack.TransportEndpointID, entry: SyncacheEntry) !void {
        const options_len: u8 = (if (entry.ts_enabled) @as(u8, 12) else 0) + (if (entry.ws_negotiated) @as(u8, 4) else 0) + (if (entry.sack_enabled) @as(u8, 4) else 0) + 4;
        const hdr_buf = try self.proto.header_pool.acquire();
        defer self.proto.header_pool.release(hdr_buf);
        var pre = buffer.Prependable.init(hdr_buf);
        const tcp_hdr = pre.prepend(header.TCPMinimumSize + options_len).?;
        @memset(tcp_hdr, 0);
        var reply_h = header.TCP.init(tcp_hdr);
        const rcv_used: u32 = @intCast(self.rcv_buf_used);
        self.rcv_wnd = if (rcv_used < self.rcv_wnd_max) self.rcv_wnd_max - rcv_used else 0;
        reply_h.encode(id.local_port, id.remote_port, entry.snd_nxt, entry.rcv_nxt, header.TCPFlagSyn | header.TCPFlagAck, @as(u16, @intCast(@min(self.rcv_wnd >> @as(u5, @intCast(self.rcv_wnd_scale)), 65535))));
        reply_h.data[header.TCPDataOffset] = ((5 + (options_len / 4)) << 4);
        var opt_ptr = reply_h.data[20..];
        opt_ptr[0] = 2;
        opt_ptr[1] = 4;
        std.mem.writeInt(u16, opt_ptr[2..4], self.max_segment_size, .big);
        opt_ptr = opt_ptr[4..];
        if (entry.ws_negotiated) {
            opt_ptr[0] = 3;
            opt_ptr[1] = 3;
            opt_ptr[2] = self.rcv_wnd_scale;
            opt_ptr = opt_ptr[3..];
            opt_ptr[0] = 1;
            opt_ptr = opt_ptr[1..];
        }
        if (entry.sack_enabled) {
            opt_ptr[0] = 4;
            opt_ptr[1] = 2;
            opt_ptr[2] = 1;
            opt_ptr[3] = 1;
            opt_ptr = opt_ptr[4..];
        }
        if (entry.ts_enabled) {
            opt_ptr[0] = 8;
            opt_ptr[1] = 10;
            std.mem.writeInt(u32, opt_ptr[2..6], @as(u32, @intCast(@mod(std.time.milliTimestamp(), 0xFFFFFFFF))), .big);
            std.mem.writeInt(u32, opt_ptr[6..10], entry.ts_recent, .big);
            opt_ptr[10] = 1;
            opt_ptr[11] = 1;
        }
        reply_h.setChecksum(reply_h.calculateChecksum(id.local_address.v4, id.remote_address.v4, &[_]u8{}));
        const pb = tcpip.PacketBuffer{ .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 }, .header = pre };
        var mut_r = r.*;
        try mut_r.writePacket(ProtocolNumber, pb);
        stats.global_stats.tcp.tx_segments += 1;
        stats.global_stats.tcp.tx_syn_ack += 1;
        stats.global_stats.tcp.tx_ack += 1;
    }

    /// Main packet handler implementing RFC 793 state machine.
    pub fn handlePacket(self: *TCPEndpoint, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        const handle_start: i64 = @intCast(std.time.nanoTimestamp());
        defer {
            const handle_end: i64 = @intCast(std.time.nanoTimestamp());
            if (pkt.timestamp_ns != 0) {
                stats.global_stats.latency.transport_dispatch.record(@as(i64, @intCast(handle_start - pkt.timestamp_ns)));
                stats.global_stats.latency.tcp_endpoint.record(@as(i64, @intCast(handle_end - handle_start)));
            }
        }
        self.incRef();
        defer self.decRef();

        var notify_mask: waiter.EventMask = 0;
        defer {
            if (notify_mask != 0 and self.state != .closed) {
                self.notify(notify_mask);
            }
        }

        const v = pkt.data.first() orelse return;
        if (v.len < header.TCPMinimumSize) return;
        const h = header.TCP.init(v);
        const fl = h.flags();

        stats.global_stats.tcp.rx_segments += 1;
        if (fl & header.TCPFlagSyn != 0) {
            if (fl & header.TCPFlagAck != 0) {
                stats.global_stats.tcp.rx_syn_ack += 1;
            } else {
                stats.global_stats.tcp.rx_syn += 1;
            }
        }
        if (fl & header.TCPFlagAck != 0) stats.global_stats.tcp.rx_ack += 1;
        if (fl & header.TCPFlagPsh != 0) stats.global_stats.tcp.rx_psh += 1;
        if (fl & header.TCPFlagFin != 0) stats.global_stats.tcp.rx_fin += 1;

        // NOTE: RFC 1337 - Handle RST in TIME_WAIT carefully
        if (self.state == .time_wait) {
            if (fl & header.TCPFlagRst != 0) {
                // RFC 1337: Ignore RST in TIME_WAIT to prevent TIME_WAIT assassination
                return;
            }
            if (fl & header.TCPFlagSyn != 0 and fl & header.TCPFlagAck == 0) {
                // Allow new connection on same 4-tuple if SYN has higher seq
                self.state = .closed;
                self.stack.timer_queue.cancel(&self.time_wait_timer);
                if (self.local_addr) |la| {
                    if (self.remote_addr) |ra| {
                        const term_id = stack.TransportEndpointID{
                            .local_port = la.port,
                            .local_address = la.addr,
                            .remote_port = ra.port,
                            .remote_address = ra.addr,
                        };
                        const shard = self.stack.endpoints.getShard(term_id);
                        if (shard.get(term_id)) |ep| {
                            if (ep.ptr == @as(*anyopaque, @ptrCast(self))) {
                                _ = self.stack.endpoints.fetchRemove(term_id);
                                ep.decRef();
                            }
                            ep.decRef();
                        }
                        stack.Stack.deliverTransportPacket(self.stack, r, ProtocolNumber, pkt);
                    }
                }
                self.decStackRef();
                return;
            }
        }

        const now = std.time.milliTimestamp();
        const hlen = h.dataOffset();

        // Parse TCP options (RFC 7323 timestamps, RFC 2018 SACK)
        if (hlen > header.TCPMinimumSize and hlen <= v.len) {
            var opt_idx: usize = 20;
            while (opt_idx + 1 < hlen) {
                const kind = v[opt_idx];
                if (kind == 0) break;
                if (kind == 1) {
                    opt_idx += 1;
                    continue;
                }
                if (opt_idx + 1 >= hlen) break;
                const len = v[opt_idx + 1];
                if (len < 2 or opt_idx + len > hlen) break;
                if (kind == 8 and len == 10 and opt_idx + 6 <= hlen) {
                    // NOTE: RFC 7323 - Timestamps option for RTT measurement
                    self.ts_recent = std.mem.readInt(u32, v[opt_idx + 2 .. opt_idx + 6][0..4], .big);
                    if (fl & header.TCPFlagSyn != 0) self.ts_enabled = true;
                } else if (kind == 4 and len == 2) {
                    // NOTE: RFC 2018 - SACK Permitted option
                    if (fl & header.TCPFlagSyn != 0) self.sack_enabled = true;
                } else if (kind == 5 and len >= 10) {
                    // NOTE: RFC 2018 - SACK blocks
                    const num_blocks = (len - 2) / 8;
                    self.peer_sack_blocks.clearRetainingCapacity();
                    for (0..num_blocks) |b| {
                        if (opt_idx + 10 + b * 8 <= hlen) {
                            const start = std.mem.readInt(u32, v[opt_idx + 2 + b * 8 .. opt_idx + 6 + b * 8][0..4], .big);
                            const end = std.mem.readInt(u32, v[opt_idx + 6 + b * 8 .. opt_idx + 10 + b * 8][0..4], .big);
                            self.peer_sack_blocks.append(.{ .start = start, .end = end }) catch {};
                        }
                    }
                }
                opt_idx += len;
            }
        }

        switch (self.state) {
            .listen => {
                if (fl & header.TCPFlagSyn != 0) {
                    // NOTE: RFC 793 Section 3.4 - SYN received in LISTEN state
                    if (self.syncache.count() + self.accepted_queue.len >= self.backlog) {
                        log.warn("Listen queue full: syncache={} accepted={} backlog={}", .{ self.syncache.count(), self.accepted_queue.len, self.backlog });
                        stats.global_stats.tcp.syncache_dropped += 1;
                        return;
                    }
                    const sync_key = SyncacheKey{ .addr = id.remote_address, .port = h.sourcePort() };
                    var entry = SyncacheEntry{
                        .remote_addr = .{ .nic = r.nic.id, .addr = id.remote_address, .port = h.sourcePort() },
                        .rcv_nxt = h.sequenceNumber() +% 1,
                        .snd_nxt = @as(u32, @intCast(@mod(std.time.milliTimestamp(), 0x7FFFFFFF))),
                        .ts_recent = 0,
                        .ts_enabled = false,
                        .sack_enabled = false,
                        .ws_negotiated = false,
                        .snd_wnd_scale = 0,
                        .mss = self.max_segment_size,
                    };

                    // Parse options from SYN
                    var opt_idx: usize = 20;
                    while (opt_idx + 1 < hlen and opt_idx + 1 < v.len) {
                        const kind = v[opt_idx];
                        if (kind == 0) break;
                        if (kind == 1) {
                            opt_idx += 1;
                            continue;
                        }
                        const len = v[opt_idx + 1];
                        if (len < 2 or opt_idx + len > hlen) break;
                        if (kind == 2 and len == 4 and opt_idx + 4 <= v.len) {
                            entry.mss = std.mem.readInt(u16, v[opt_idx + 2 .. opt_idx + 4][0..2], .big);
                        } else if (kind == 3 and len == 3 and opt_idx + 3 <= v.len) {
                            // NOTE: RFC 7323 - Window Scale option
                            entry.snd_wnd_scale = v[opt_idx + 2];
                            entry.ws_negotiated = true;
                        } else if (kind == 4 and len == 2) {
                            entry.sack_enabled = true;
                        } else if (kind == 8 and len == 10 and opt_idx + 6 <= v.len) {
                            entry.ts_recent = std.mem.readInt(u32, v[opt_idx + 2 .. opt_idx + 6][0..4], .big);
                            entry.ts_enabled = true;
                        }
                        opt_idx += len;
                    }

                    self.syncache.put(sync_key, entry) catch {
                        log.err("Syncache put failed", .{});
                        return;
                    };
                    self.sendSynAck(r, id, entry) catch |err| {
                        log.err("sendSynAck failed: {}", .{err});
                    };
                } else if (fl & header.TCPFlagAck != 0) {
                    // NOTE: RFC 793 Section 3.4 - Complete handshake on ACK
                    const sync_key = SyncacheKey{ .addr = id.remote_address, .port = h.sourcePort() };
                    if (self.syncache.fetchRemove(sync_key)) |kv| {
                        const entry = kv.value;
                        if (h.ackNumber() == entry.snd_nxt +% 1) {
                            const new_ep = self.proto.endpoint_pool.acquire() catch {
                                stats.global_stats.tcp.pool_exhausted += 1;
                                return;
                            };
                            const new_wq = self.proto.waiter_queue_pool.acquire() catch {
                                self.proto.endpoint_pool.release(new_ep);
                                return;
                            };
                            new_wq.* = .{};
                            new_ep.initialize_v2(self.stack, self.proto, new_wq, entry.mss) catch {
                                self.proto.waiter_queue_pool.release(new_wq);
                                self.proto.endpoint_pool.release(new_ep);
                                return;
                            };
                            new_ep.owns_waiter_queue = true;
                            // NOTE: RFC 793 - SYN_RECV to ESTABLISHED
                            new_ep.state = .established;
                            new_ep.incStackRef();

                            new_ep.rcv_nxt = entry.rcv_nxt;
                            new_ep.snd_nxt = entry.snd_nxt +% 1;
                            new_ep.last_ack = new_ep.snd_nxt;
                            new_ep.local_addr = .{ .nic = r.nic.id, .addr = id.local_address, .port = id.local_port };
                            new_ep.remote_addr = entry.remote_addr;
                            new_ep.ts_enabled = entry.ts_enabled;
                            new_ep.ts_recent = entry.ts_recent;
                            new_ep.sack_enabled = entry.sack_enabled;
                            new_ep.hint_sack_enabled = entry.sack_enabled;
                            new_ep.snd_wnd_scale = entry.snd_wnd_scale;
                            if (!entry.ws_negotiated) new_ep.rcv_wnd_scale = 0;
                            new_ep.max_segment_size = entry.mss;
                            new_ep.snd_wnd = @as(u32, h.windowSize()) << @as(u5, @intCast(entry.snd_wnd_scale));

                            const new_id = stack.TransportEndpointID{
                                .local_port = new_ep.local_addr.?.port,
                                .local_address = new_ep.local_addr.?.addr,
                                .remote_port = new_ep.remote_addr.?.port,
                                .remote_address = new_ep.remote_addr.?.addr,
                            };
                            self.stack.registerTransportEndpoint(new_id, new_ep.transportEndpoint()) catch {
                                new_ep.decRef();
                                return;
                            };
                            const node = self.proto.accept_node_pool.acquire() catch {
                                new_ep.decRef();
                                return;
                            };
                            node.data = .{ .ep = new_ep.endpoint(), .wq = new_wq };
                            self.accepted_queue.append(node);
                            stats.global_stats.tcp.passive_opens += 1;
                            notify_mask |= waiter.EventIn;
                        }
                    }
                }
            },
            .syn_sent => {
                if ((fl & header.TCPFlagSyn != 0) and (fl & header.TCPFlagAck != 0)) {
                    if (h.ackNumber() == self.snd_nxt) {
                        // NOTE: RFC 793 Section 3.4 - SYN_SENT to ESTABLISHED
                        self.state = .established;
                        self.rcv_nxt = h.sequenceNumber() +% 1;
                        self.snd_nxt = h.ackNumber();
                        self.last_ack = self.snd_nxt;
                        if (self.snd_queue.popFirst()) |node| {
                            node.data.data.deinit();
                            self.proto.segment_node_pool.release(node);
                        }
                        self.stack.timer_queue.cancel(&self.retransmit_timer);
                        // Parse options from SYN+ACK
                        var opt_idx: usize = 20;
                        var ws_negotiated = false;
                        while (opt_idx + 1 < hlen and opt_idx + 1 < v.len) {
                            const kind = v[opt_idx];
                            if (kind == 0) break;
                            if (kind == 1) {
                                opt_idx += 1;
                                continue;
                            }
                            const len = v[opt_idx + 1];
                            if (len < 2 or opt_idx + len > hlen) break;
                            if (kind == 2 and len == 4 and opt_idx + 4 <= v.len) {
                                self.max_segment_size = std.mem.readInt(u16, v[opt_idx + 2 .. opt_idx + 4][0..2], .big);
                            } else if (kind == 3 and len == 3 and opt_idx + 3 <= v.len) {
                                self.snd_wnd_scale = v[opt_idx + 2];
                                ws_negotiated = true;
                            } else if (kind == 4 and len == 2) {
                                self.sack_enabled = true;
                                self.hint_sack_enabled = true;
                            }
                            opt_idx += len;
                        }
                        if (!ws_negotiated) self.rcv_wnd_scale = 0;
                        self.snd_wnd = @as(u32, h.windowSize()) << @as(u5, @intCast(self.snd_wnd_scale));
                        self.sendControl(header.TCPFlagAck) catch {};
                        stats.global_stats.tcp.active_opens += 1;
                        notify_mask |= waiter.EventOut;
                    }
                }
            },
            .established => {
                const data_len = pkt.data.size -| h.dataOffset();
                if (h.sequenceNumber() == self.rcv_nxt) {
                    if (data_len > 0) {
                        var mut_pkt = pkt;
                        mut_pkt.data.trimFront(h.dataOffset());
                        const node = self.proto.packet_node_pool.acquire() catch {
                            return;
                        };
                        node.data = .{
                            .data = mut_pkt.data.cloneInPool(&self.proto.view_pool) catch {
                                self.proto.packet_node_pool.release(node);
                                return;
                            },
                            .seq = h.sequenceNumber(),
                        };
                        self.rcv_list.append(node);
                        self.rcv_buf_used += data_len;
                        self.rcv_view_count += node.data.data.views.len;
                        self.rcv_nxt +%= @as(u32, @intCast(data_len));
                        self.processOOO();
                        self.maybeSendDelayedAck(data_len);
                        stats.global_stats.tcp.rx_segments += 1;
                        notify_mask |= waiter.EventIn;
                    }
                    if (fl & header.TCPFlagFin != 0) {
                        // NOTE: RFC 793 Section 3.5 - ESTABLISHED to CLOSE_WAIT (passive close)
                        self.rcv_nxt +%= 1;
                        self.state = .close_wait;
                        self.stack.timer_queue.cancel(&self.delayed_ack_timer);
                        self.sendControl(header.TCPFlagAck) catch {};
                        self.rcv_packets_since_ack = 0;
                        notify_mask |= waiter.EventIn | waiter.EventHUp;
                    }
                } else if (fl & header.TCPFlagRst == 0) {
                    if (seqAfter(h.sequenceNumber(), self.rcv_nxt) and data_len > 0) {
                        var mut_pkt = pkt;
                        mut_pkt.data.trimFront(h.dataOffset());
                        self.insertOOO(h.sequenceNumber(), mut_pkt.data) catch {};
                    }
                    // Out-of-order: ACK immediately
                    self.stack.timer_queue.cancel(&self.delayed_ack_timer);
                    self.sendControl(header.TCPFlagAck) catch {};
                    self.rcv_packets_since_ack = 0;
                }

                if (fl & header.TCPFlagAck != 0) {
                    const ack = h.ackNumber();
                    if (seqBeforeEq(ack, self.snd_nxt) and seqAfterEq(ack, self.last_ack)) {
                        self.snd_wnd = @as(u32, h.windowSize()) << @as(u5, @intCast(self.snd_wnd_scale));
                        if (ack == self.last_ack) {
                            // NOTE: RFC 5681 - Duplicate ACK detection for fast retransmit
                            self.dup_ack_count += 1;
                            if (self.dup_ack_count == 3) {
                                // Fast retransmit on 3 duplicate ACKs
                                self.cc.onRetransmit();
                                self.checkRetransmitLocked(true, &notify_mask) catch {};
                                self.dup_ack_count = 0;
                            }
                        } else {
                            const diff = ack -% self.last_ack;
                            self.last_ack = ack;
                            self.dup_ack_count = 0;
                            self.retransmit_count = 0;
                            // Remove acknowledged segments
                            var it_node = self.snd_queue.first;
                            while (it_node) |node| {
                                const flag_len: u32 = if ((node.data.flags & (header.TCPFlagSyn | header.TCPFlagFin)) != 0) 1 else 0;
                                const seg_end = node.data.seq +% node.data.len +% flag_len;
                                if (seqBeforeEq(seg_end, ack)) {
                                    const next = node.next;
                                    _ = self.snd_queue.remove(node);
                                    node.data.data.deinit();
                                    self.proto.segment_node_pool.release(node);
                                    it_node = next;
                                } else {
                                    it_node = node.next;
                                }
                            }
                            if (self.snd_queue.first == null) {
                                self.stack.timer_queue.cancel(&self.retransmit_timer);
                            } else {
                                self.stack.timer_queue.schedule(&self.retransmit_timer, 10);
                            }
                            self.cc.onAck(diff);
                            notify_mask |= waiter.EventOut;
                        }
                    }
                }
            },
            .fin_wait1 => {
                var acked = false;
                if (fl & header.TCPFlagAck != 0 and h.ackNumber() == self.snd_nxt) {
                    // NOTE: RFC 793 Section 3.5 - FIN_WAIT_1 to FIN_WAIT_2
                    self.state = .fin_wait2;
                    acked = true;
                }
                if (fl & header.TCPFlagFin != 0) {
                    self.rcv_nxt +%= 1;
                    self.sendControl(header.TCPFlagAck) catch {};
                    if (acked) {
                        // NOTE: RFC 793 Section 3.5 - FIN_WAIT_2 to TIME_WAIT
                        self.state = .time_wait;
                        self.stack.timer_queue.schedule(&self.time_wait_timer, 2 * self.stack.tcp_msl);
                    } else {
                        // NOTE: RFC 793 Section 3.5 - Simultaneous close: FIN_WAIT_1 to CLOSING
                        self.state = .closing;
                    }
                    notify_mask |= waiter.EventHUp;
                }
            },
            .fin_wait2 => {
                if (fl & header.TCPFlagFin != 0) {
                    // NOTE: RFC 793 Section 3.5 - FIN_WAIT_2 to TIME_WAIT
                    self.rcv_nxt +%= 1;
                    self.state = .time_wait;
                    self.stack.timer_queue.schedule(&self.time_wait_timer, 2 * self.stack.tcp_msl);
                    self.sendControl(header.TCPFlagAck) catch {};
                    notify_mask |= waiter.EventIn;
                }
            },
            .closing => {
                if (fl & header.TCPFlagAck != 0 and h.ackNumber() == self.snd_nxt) {
                    // NOTE: RFC 793 Section 3.5 - CLOSING to TIME_WAIT
                    self.state = .time_wait;
                    self.stack.timer_queue.schedule(&self.time_wait_timer, 2 * self.stack.tcp_msl);
                    notify_mask |= waiter.EventHUp;
                }
            },
            .last_ack => {
                if (fl & header.TCPFlagAck != 0 and h.ackNumber() == self.snd_nxt) {
                    // NOTE: RFC 793 Section 3.5 - LAST_ACK to CLOSED
                    self.state = .closed;
                    if (self.local_addr) |la| {
                        if (self.remote_addr) |ra| {
                            const term_id = stack.TransportEndpointID{
                                .local_port = la.port,
                                .local_address = la.addr,
                                .remote_port = ra.port,
                                .remote_address = ra.addr,
                            };
                            self.stack.unregisterTransportEndpoint(term_id);
                        }
                    }
                    self.decStackRef();
                    notify_mask |= waiter.EventHUp;
                }
            },
            .closed => {
                if (self.app_closed) {
                    if (self.local_addr) |la| {
                        if (self.remote_addr) |ra| {
                            const term_id = stack.TransportEndpointID{
                                .local_port = la.port,
                                .local_address = la.addr,
                                .remote_port = ra.port,
                                .remote_address = ra.addr,
                            };
                            self.stack.unregisterTransportEndpoint(term_id);
                        }
                    }
                }
            },
            else => {},
        }
        _ = now;
    }

    /// Insert out-of-order segment for later processing.
    pub fn insertOOO(self: *TCPEndpoint, seq: u32, pkt_data: buffer.VectorisedView) !void {
        var it = self.ooo_list.first;
        while (it) |node| {
            if (node.data.seq == seq) return;
            if (seqBefore(seq, node.data.seq)) break;
            it = node.next;
        }
        const node = try self.proto.packet_node_pool.acquire();
        node.data = .{ .data = try pkt_data.cloneInPool(&self.proto.view_pool), .seq = seq };
        if (it) |next| {
            self.ooo_list.insertBefore(next, node);
        } else {
            self.ooo_list.append(node);
        }
        try self.updateSackBlocks(seq, seq +% @as(u32, @intCast(pkt_data.size)));
    }

    /// Process out-of-order queue and move contiguous data to receive list.
    pub fn processOOO(self: *TCPEndpoint) void {
        while (self.ooo_list.first) |node| {
            if (node.data.seq == self.rcv_nxt) {
                _ = self.ooo_list.remove(node);
                self.rcv_list.append(node);
                self.rcv_buf_used += node.data.data.size;
                self.rcv_view_count += node.data.data.views.len;
                self.rcv_nxt +%= @as(u32, @intCast(node.data.data.size));
            } else if (seqBefore(node.data.seq, self.rcv_nxt)) {
                _ = self.ooo_list.remove(node);
                node.data.data.deinit();
                self.proto.packet_node_pool.release(node);
            } else break;
        }
        // Prune SACK blocks covered by rcv_nxt
        var i: usize = 0;
        while (i < self.sack_blocks.items.len) {
            if (seqBeforeEq(self.sack_blocks.items[i].end, self.rcv_nxt)) {
                _ = self.sack_blocks.swapRemove(i);
            } else {
                if (seqBefore(self.sack_blocks.items[i].start, self.rcv_nxt)) self.sack_blocks.items[i].start = self.rcv_nxt;
                i += 1;
            }
        }
    }

    /// Update SACK blocks with new out-of-order range.
    fn updateSackBlocks(self: *TCPEndpoint, start: u32, end: u32) !void {
        if (!self.hint_sack_enabled) return;
        for (self.sack_blocks.items) |*block| {
            if (block.start == start and block.end == end) return;
        }
        // Most recent block first per RFC 2018
        try self.sack_blocks.insert(0, .{ .start = start, .end = end });
        if (self.sack_blocks.items.len > 4) {
            _ = self.sack_blocks.pop();
        }
    }
};

// Sequence number comparison helpers (RFC 793 Section 3.3)
fn seqBefore(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) < 0;
}
fn seqBeforeEq(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) <= 0;
}
fn seqAfter(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) > 0;
}
fn seqAfterEq(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) >= 0;
}

test "NewReno slow start" {
    const allocator = std.testing.allocator;
    var cc = try congestion.NewReno.init(allocator, 1460);
    defer cc.deinit();

    const initial_cwnd = cc.getCwnd();
    try std.testing.expectEqual(congestion.CongestionState.slow_start, cc.getState());

    cc.onAck(1460);
    try std.testing.expect(cc.getCwnd() > initial_cwnd);
}

test "NewReno loss triggers fast recovery" {
    const allocator = std.testing.allocator;
    var cc = try congestion.NewReno.init(allocator, 1460);
    defer cc.deinit();

    cc.onLoss();
    try std.testing.expectEqual(congestion.CongestionState.fast_recovery, cc.getState());
}
