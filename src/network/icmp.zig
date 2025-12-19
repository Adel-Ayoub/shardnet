/// ICMPv4 protocol implementation.
///
/// Handles ICMP echo request/reply, destination unreachable,
/// redirects, and includes rate limiting to prevent amplification.

const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");
const time = @import("../time.zig");
const stats = @import("../stats.zig");
const log = @import("../log.zig").scoped(.icmp);

pub const ProtocolNumber = 1;

/// ICMP message types.
pub const Type = struct {
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACHABLE: u8 = 3;
    pub const REDIRECT: u8 = 5;
    pub const ECHO: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
};

/// Destination Unreachable codes.
pub const DestUnreachableCode = struct {
    pub const NET_UNREACHABLE: u8 = 0;
    pub const HOST_UNREACHABLE: u8 = 1;
    pub const PROTOCOL_UNREACHABLE: u8 = 2;
    pub const PORT_UNREACHABLE: u8 = 3;
    pub const FRAGMENTATION_NEEDED: u8 = 4;
    pub const SOURCE_ROUTE_FAILED: u8 = 5;
};

/// Time Exceeded codes.
pub const TimeExceededCode = struct {
    pub const TTL_EXPIRED: u8 = 0;
    pub const FRAGMENT_REASSEMBLY: u8 = 1;
};

/// Rate limiter using token bucket algorithm.
/// Limits ICMP error messages to prevent amplification attacks.
pub const RateLimiter = struct {
    /// Maximum tokens (burst capacity).
    max_tokens: u32 = 100,
    /// Current available tokens.
    tokens: u32 = 100,
    /// Tokens refilled per second.
    refill_rate: u32 = 100,
    /// Last refill timestamp (ms).
    last_refill_ms: i64 = 0,

    pub fn init() RateLimiter {
        return .{
            .last_refill_ms = std.time.milliTimestamp(),
        };
    }

    /// Try to consume a token. Returns true if allowed.
    pub fn tryConsume(self: *RateLimiter) bool {
        self.refill();
        if (self.tokens > 0) {
            self.tokens -= 1;
            return true;
        }
        return false;
    }

    fn refill(self: *RateLimiter) void {
        const now = std.time.milliTimestamp();
        const elapsed_ms = now - self.last_refill_ms;
        if (elapsed_ms >= 1000) {
            const new_tokens = @as(u32, @intCast(@divFloor(elapsed_ms * self.refill_rate, 1000)));
            self.tokens = @min(self.max_tokens, self.tokens + new_tokens);
            self.last_refill_ms = now;
        }
    }
};

/// RTT measurement for echo replies.
pub const RttMeasurement = struct {
    /// Pending echo requests: sequence -> send timestamp (ns).
    pending: std.AutoHashMap(u16, i64),

    pub fn init(allocator: std.mem.Allocator) RttMeasurement {
        return .{
            .pending = std.AutoHashMap(u16, i64).init(allocator),
        };
    }

    pub fn deinit(self: *RttMeasurement) void {
        self.pending.deinit();
    }

    pub fn recordSend(self: *RttMeasurement, seq: u16) void {
        self.pending.put(seq, std.time.nanoTimestamp()) catch {};
    }

    /// Returns RTT in microseconds if matching request found.
    pub fn recordRecv(self: *RttMeasurement, seq: u16) ?u64 {
        if (self.pending.fetchRemove(seq)) |entry| {
            const now = std.time.nanoTimestamp();
            const rtt_ns = now - entry.value;
            return @as(u64, @intCast(@divFloor(rtt_ns, 1000)));
        }
        return null;
    }
};

pub const ICMPv4TransportProtocol = struct {
    rate_limiter: RateLimiter = RateLimiter.init(),

    pub fn init() ICMPv4TransportProtocol {
        return .{};
    }

    pub fn protocol(self: *ICMPv4TransportProtocol) stack.TransportProtocol {
        return .{
            .ptr = self,
            .vtable = &.{
                .number = transportNumber,
                .newEndpoint = newTransportEndpoint,
                .parsePorts = parsePorts,
                .handlePacket = handlePacket_external,
            },
        };
    }

    fn transportNumber(ptr: *anyopaque) tcpip.TransportProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn newTransportEndpoint(ptr: *anyopaque, s: *stack.Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
        _ = ptr;
        _ = s;
        _ = net_proto;
        _ = wait_queue;
        return tcpip.Error.NotPermitted;
    }

    fn parsePorts(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.TransportProtocol.PortPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{ .src = 0, .dst = 0 };
        if (v.len >= 8) {
            const id = std.mem.readInt(u16, v[4..6][0..2], .big);
            return .{ .src = id, .dst = 0 };
        }
        return .{ .src = 0, .dst = 0 };
    }

    fn handlePacket_external(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        _ = ptr;
        _ = id;
        ICMPv4PacketHandler.handlePacket(r.nic.stack, r, pkt);
    }
};

pub const ICMPv4PacketHandler = struct {
    var rate_limiter: RateLimiter = RateLimiter.init();

    pub fn handlePacket(s: *stack.Stack, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        var mut_pkt = pkt;
        const v = mut_pkt.data.first() orelse return;
        const h = header.ICMPv4.init(v);

        stats.global_stats.icmp.rx_packets += 1;

        switch (h.@"type"()) {
            Type.ECHO => {
                stats.global_stats.icmp.rx_echo_requests += 1;
                handleEchoRequest(s, r, &mut_pkt, v);
            },
            Type.ECHO_REPLY => {
                stats.global_stats.icmp.rx_echo_replies += 1;
                // RTT measurement would be handled here
            },
            Type.DEST_UNREACHABLE => {
                handleDestUnreachable(s, r, v);
            },
            Type.REDIRECT => {
                handleRedirect(s, r, v);
            },
            Type.TIME_EXCEEDED => {
                // Informational - log and ignore
                log.debug("Received Time Exceeded from {any}", .{r.remote_address.v4});
            },
            else => {
                log.debug("Unknown ICMP type: {}", .{h.@"type"()});
            },
        }
    }

    fn handleEchoRequest(s: *stack.Stack, r: *const stack.Route, pkt: *tcpip.PacketBuffer, v: []const u8) void {
        _ = pkt;
        const payload = s.allocator.alloc(u8, v.len) catch return;
        defer s.allocator.free(payload);
        @memcpy(payload, v);

        var reply_hdr = [_]u8{0} ** header.ICMPv4MinimumSize;
        @memcpy(&reply_hdr, payload[0..header.ICMPv4MinimumSize]);
        var reply_h = header.ICMPv4.init(&reply_hdr);
        reply_h.data[0] = Type.ECHO_REPLY;
        reply_h.setChecksum(0);
        const c = reply_h.calculateChecksum(payload[header.ICMPv4MinimumSize..]);
        reply_h.setChecksum(c);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = payload[header.ICMPv4MinimumSize..] }};
        const reply_pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(payload.len - header.ICMPv4MinimumSize, &views),
            .header = buffer.Prependable.initFull(&reply_hdr),
        };

        const reply_route = r.*;
        if (r.nic.network_endpoints.get(0x0800)) |ip_ep| {
            stats.global_stats.icmp.tx_echo_replies += 1;
            ip_ep.writePacket(&reply_route, ProtocolNumber, reply_pkt) catch {};
        }
    }

    fn handleDestUnreachable(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        _ = s;
        if (v.len < 8) return;
        const code = v[1];
        log.debug("Destination Unreachable code {} from {any}", .{ code, r.remote_address.v4 });
        // NOTE: Would notify upper layers (TCP/UDP) about unreachable destination
    }

    fn handleRedirect(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        if (v.len < 8) return;
        const code = v[1];
        _ = code;

        // Extract gateway address from ICMP redirect (bytes 4-7)
        const gateway = tcpip.Address{ .v4 = v[4..8][0..4].* };

        // NOTE: Security consideration - redirects should be validated
        // before updating routing table to prevent route hijacking
        log.debug("Redirect received suggesting gateway {any}", .{gateway.v4});
        _ = s;
        _ = r;
    }

    /// Send Destination Unreachable message.
    pub fn sendDestUnreachable(s: *stack.Stack, r: *const stack.Route, code: u8, original_pkt: []const u8) void {
        if (!rate_limiter.tryConsume()) {
            log.debug("ICMP rate limited", .{});
            return;
        }

        // ICMP error contains: type(1) + code(1) + checksum(2) + unused(4) + original IP header + 8 bytes
        const orig_len = @min(original_pkt.len, 28); // IP header (20 min) + 8 bytes data
        const icmp_len = 8 + orig_len;

        const buf = s.allocator.alloc(u8, icmp_len) catch return;
        defer s.allocator.free(buf);

        buf[0] = Type.DEST_UNREACHABLE;
        buf[1] = code;
        buf[2] = 0; // checksum placeholder
        buf[3] = 0;
        @memset(buf[4..8], 0); // unused
        @memcpy(buf[8..][0..orig_len], original_pkt[0..orig_len]);

        var h = header.ICMPv4.init(buf[0..header.ICMPv4MinimumSize]);
        h.setChecksum(0);
        const c = h.calculateChecksum(buf[header.ICMPv4MinimumSize..]);
        h.setChecksum(c);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const hdr_mem = s.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer s.allocator.free(hdr_mem);

        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        if (r.nic.network_endpoints.get(0x0800)) |ip_ep| {
            stats.global_stats.icmp.tx_dest_unreachable += 1;
            ip_ep.writePacket(r, ProtocolNumber, pkt) catch {};
        }
    }

    /// Send Time Exceeded message.
    pub fn sendTimeExceeded(s: *stack.Stack, r: *const stack.Route, code: u8, original_pkt: []const u8) void {
        if (!rate_limiter.tryConsume()) {
            return;
        }

        const orig_len = @min(original_pkt.len, 28);
        const icmp_len = 8 + orig_len;

        const buf = s.allocator.alloc(u8, icmp_len) catch return;
        defer s.allocator.free(buf);

        buf[0] = Type.TIME_EXCEEDED;
        buf[1] = code;
        buf[2] = 0;
        buf[3] = 0;
        @memset(buf[4..8], 0);
        @memcpy(buf[8..][0..orig_len], original_pkt[0..orig_len]);

        var h = header.ICMPv4.init(buf[0..header.ICMPv4MinimumSize]);
        h.setChecksum(0);
        const c = h.calculateChecksum(buf[header.ICMPv4MinimumSize..]);
        h.setChecksum(c);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const hdr_mem = s.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer s.allocator.free(hdr_mem);

        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        if (r.nic.network_endpoints.get(0x0800)) |ip_ep| {
            stats.global_stats.icmp.tx_time_exceeded += 1;
            ip_ep.writePacket(r, ProtocolNumber, pkt) catch {};
        }
    }
};

pub const ICMPv4Protocol = struct {
    pub fn init() ICMPv4Protocol {
        return .{};
    }

    pub fn protocol(self: *ICMPv4Protocol) stack.NetworkProtocol {
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = stack.NetworkProtocol.VTable{
        .number = number,
        .newEndpoint = newEndpoint,
        .linkAddressRequest = linkAddressRequest,
        .parseAddresses = parseAddresses,
    };

    fn number(ptr: *anyopaque) tcpip.NetworkProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn linkAddressRequest(ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *stack.NIC) tcpip.Error!void {
        _ = ptr;
        _ = addr;
        _ = local_addr;
        _ = nic;
        return tcpip.Error.NotPermitted;
    }

    fn parseAddresses(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.NetworkProtocol.AddressPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{
            .src = .{ .v4 = .{ 0, 0, 0, 0 } },
            .dst = .{ .v4 = .{ 0, 0, 0, 0 } },
        };
        const h = header.IPv4.init(v);
        return .{
            .src = .{ .v4 = h.sourceAddress() },
            .dst = .{ .v4 = h.destinationAddress() },
        };
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        const self = @as(*ICMPv4Protocol, @ptrCast(@alignCast(ptr)));
        const ep = nic.stack.allocator.create(ICMPv4Endpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = .{
            .nic = nic,
            .address = addr.address,
            .protocol = self,
        };
        _ = dispatcher;
        return ep.networkEndpoint();
    }
};

pub const ICMPv4Endpoint = struct {
    nic: *stack.NIC,
    address: tcpip.Address,
    protocol: *ICMPv4Protocol,

    pub fn networkEndpoint(self: *ICMPv4Endpoint) stack.NetworkEndpoint {
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = stack.NetworkEndpoint.VTable{
        .writePacket = writePacket,
        .handlePacket = handlePacket,
        .mtu = mtu,
        .close = close,
    };

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*ICMPv4Endpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.IPv4MinimumSize;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*ICMPv4Endpoint, @ptrCast(@alignCast(ptr)));
        self.nic.stack.allocator.destroy(self);
    }

    fn writePacket(ptr: *anyopaque, r: *const stack.Route, prot: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        _ = ptr;
        _ = r;
        _ = prot;
        _ = pkt;
        return tcpip.Error.NotPermitted;
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        const self = @as(*ICMPv4Endpoint, @ptrCast(@alignCast(ptr)));
        ICMPv4PacketHandler.handlePacket(self.nic.stack, r, pkt);
    }
};

test "ICMP rate limiter" {
    var limiter = RateLimiter.init();
    limiter.tokens = 5;

    // Should allow 5 messages
    var allowed: u32 = 0;
    for (0..10) |_| {
        if (limiter.tryConsume()) {
            allowed += 1;
        }
    }
    try std.testing.expectEqual(@as(u32, 5), allowed);
}

test "RTT measurement" {
    const allocator = std.testing.allocator;
    var rtt = RttMeasurement.init(allocator);
    defer rtt.deinit();

    rtt.recordSend(1234);
    std.time.sleep(1_000_000); // 1ms

    const measured_rtt = rtt.recordRecv(1234);
    try std.testing.expect(measured_rtt != null);
    try std.testing.expect(measured_rtt.? >= 1000); // at least 1000 us
}
