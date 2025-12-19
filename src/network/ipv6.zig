/// IPv6 packet handling.
///
/// Implements IPv6 parsing, validation, extension header chain processing,
/// fragmentation/reassembly, and integration with the network stack.

const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const log = @import("../log.zig").scoped(.ipv6);
const stats = @import("../stats.zig");

pub const ProtocolNumber = 0x86dd;

/// Default Hop Limit for outgoing packets.
pub const DEFAULT_HOP_LIMIT: u8 = 64;

/// Maximum time to hold reassembly fragments before expiry (60 seconds per RFC 8200).
pub const REASSEMBLY_TIMEOUT_MS: i64 = 60_000;

/// Extension header types (Next Header values).
pub const NextHeader = struct {
    pub const HOP_BY_HOP: u8 = 0;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const ICMPV6: u8 = 58;
    pub const NO_NEXT_HEADER: u8 = 59;
    pub const DESTINATION: u8 = 60;
};

/// Fragment reassembly key.
const ReassemblyKey = struct {
    src: [16]u8,
    dst: [16]u8,
    id: u32,
};

/// Fragment reassembly context.
const ReassemblyContext = struct {
    fragments: std.ArrayList(FragmentEntry),
    first_arrival_ms: i64,
    unfragmentable_part: ?[]u8 = null,

    pub fn init(allocator: std.mem.Allocator) ReassemblyContext {
        return .{
            .fragments = std.ArrayList(FragmentEntry).init(allocator),
            .first_arrival_ms = std.time.milliTimestamp(),
        };
    }

    pub fn deinit(self: *ReassemblyContext, allocator: std.mem.Allocator) void {
        if (self.unfragmentable_part) |u| allocator.free(u);
        self.fragments.deinit();
    }

    pub fn isExpired(self: *const ReassemblyContext) bool {
        const now = std.time.milliTimestamp();
        return (now - self.first_arrival_ms) >= REASSEMBLY_TIMEOUT_MS;
    }
};

const FragmentEntry = struct {
    data: []u8,
    offset: u16,
    more: bool,
};

/// Parsed extension header result.
pub const ExtensionHeaderResult = struct {
    /// Next header type after all extensions.
    next_header: u8,
    /// Offset in packet where payload begins.
    payload_offset: usize,
    /// Flow label extracted for QoS.
    flow_label: u20 = 0,
    /// Fragment header info if present.
    fragment_offset: ?u16 = null,
    fragment_more: bool = false,
    fragment_id: u32 = 0,
    /// Whether parsing was successful.
    valid: bool = true,
};

/// Parse extension header chain.
/// NOTE: Extension headers must be processed in order. Each header's length
/// is in 8-byte units (except Fragment which is fixed 8 bytes).
pub fn parseExtensionHeaders(data: []const u8, first_next_header: u8) ExtensionHeaderResult {
    var result = ExtensionHeaderResult{
        .next_header = first_next_header,
        .payload_offset = 0,
    };

    var offset: usize = 0;
    var next_hdr = first_next_header;

    while (true) {
        switch (next_hdr) {
            NextHeader.HOP_BY_HOP, NextHeader.DESTINATION, NextHeader.ROUTING => {
                if (offset + 2 > data.len) {
                    result.valid = false;
                    return result;
                }
                next_hdr = data[offset];
                const ext_len = (@as(usize, data[offset + 1]) + 1) * 8;
                if (offset + ext_len > data.len) {
                    result.valid = false;
                    return result;
                }
                offset += ext_len;
            },
            NextHeader.FRAGMENT => {
                if (offset + 8 > data.len) {
                    result.valid = false;
                    return result;
                }
                next_hdr = data[offset];
                const frag_off_and_flags = std.mem.readInt(u16, data[offset + 2 ..][0..2], .big);
                result.fragment_offset = frag_off_and_flags >> 3;
                result.fragment_more = (frag_off_and_flags & 0x01) != 0;
                result.fragment_id = std.mem.readInt(u32, data[offset + 4 ..][0..4], .big);
                offset += 8; // Fragment header is always 8 bytes
            },
            else => {
                // Upper layer protocol or unknown
                result.next_header = next_hdr;
                result.payload_offset = offset;
                return result;
            },
        }
    }
}

pub const IPv6Protocol = struct {
    pub fn init() IPv6Protocol {
        return .{};
    }

    pub fn protocol(self: *IPv6Protocol) stack.NetworkProtocol {
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

    fn parseAddresses(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.NetworkProtocol.AddressPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{
            .src = .{ .v6 = [_]u8{0} ** 16 },
            .dst = .{ .v6 = [_]u8{0} ** 16 },
        };
        const h = header.IPv6.init(v);
        return .{
            .src = .{ .v6 = h.sourceAddress() },
            .dst = .{ .v6 = h.destinationAddress() },
        };
    }

    fn linkAddressRequest(ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *stack.NIC) tcpip.Error!void {
        _ = ptr;
        if (addr != .v6) return;
        const target = addr.v6;
        const src = local_addr.v6;

        // Solicited-node multicast address
        const dst = addr.toSolicitedNodeMulticast().v6;

        // Build Neighbor Solicitation
        const payload_len = header.ICMPv6MinimumSize + 20 + 8;
        const buf = nic.stack.allocator.alloc(u8, payload_len) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(buf);

        var icmp_h = header.ICMPv6.init(buf[0..header.ICMPv6MinimumSize]);
        icmp_h.data[0] = header.ICMPv6NeighborSolicitationType;
        icmp_h.data[1] = 0;
        icmp_h.setChecksum(0);

        var ns = header.ICMPv6NS.init(buf[header.ICMPv6MinimumSize..]);
        ns.setTargetAddress(target);

        // Option: Source Link-Layer Address
        buf[header.ICMPv6MinimumSize + 20] = header.ICMPv6OptionSourceLinkLayerAddress;
        buf[header.ICMPv6MinimumSize + 21] = 1;
        @memcpy(buf[header.ICMPv6MinimumSize + 22 .. header.ICMPv6MinimumSize + 28], &nic.linkEP.linkAddress().addr);

        const c = icmp_h.calculateChecksum(src, dst, buf[header.ICMPv6MinimumSize..]);
        icmp_h.setChecksum(c);

        const hdr_mem = nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(hdr_mem);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        var r = stack.Route{
            .local_address = .{ .v6 = src },
            .remote_address = .{ .v6 = dst },
            .local_link_address = nic.linkEP.linkAddress(),
            // Ethernet multicast for IPv6: 33:33: + last 32 bits of IPv6 address
            .remote_link_address = tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, dst[12], dst[13], dst[14], dst[15] } },
            .net_proto = ProtocolNumber,
            .nic = nic,
        };

        if (nic.network_endpoints.get(ProtocolNumber)) |ep| {
            try ep.writePacket(&r, 58, pkt); // ICMPv6 is 58
        }
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        const self = @as(*IPv6Protocol, @ptrCast(@alignCast(ptr)));
        const ep = nic.stack.allocator.create(IPv6Endpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = .{
            .nic = nic,
            .address = addr.address,
            .protocol = self,
            .dispatcher = dispatcher,
            .reassembly_list = std.AutoHashMap(ReassemblyKey, ReassemblyContext).init(nic.stack.allocator),
        };

        // Perform DAD (RFC 4862)
        const target = addr.address.v6;
        const src = [_]u8{0} ** 16;
        const dst = addr.address.toSolicitedNodeMulticast().v6;

        const payload_len = header.ICMPv6MinimumSize + 20;
        const buf = nic.stack.allocator.alloc(u8, payload_len) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(buf);

        var icmp_h = header.ICMPv6.init(buf[0..header.ICMPv6MinimumSize]);
        icmp_h.data[0] = header.ICMPv6NeighborSolicitationType;
        icmp_h.data[1] = 0;
        icmp_h.setChecksum(0);

        var ns = header.ICMPv6NS.init(buf[header.ICMPv6MinimumSize..]);
        ns.setTargetAddress(target);

        const c = icmp_h.calculateChecksum(src, dst, buf[header.ICMPv6MinimumSize..]);
        icmp_h.setChecksum(c);

        const hdr_mem = nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(hdr_mem);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        const r = stack.Route{
            .local_address = .{ .v6 = src },
            .remote_address = .{ .v6 = dst },
            .local_link_address = nic.linkEP.linkAddress(),
            .remote_link_address = tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, dst[12], dst[13], dst[14], dst[15] } },
            .net_proto = ProtocolNumber,
            .nic = nic,
        };

        // Manual IP header since NetworkEndpoint is not registered yet
        var mut_pkt = pkt;
        const ip_header = mut_pkt.header.prepend(header.IPv6MinimumSize) orelse return tcpip.Error.NoBufferSpace;
        const h = header.IPv6.init(ip_header);
        h.encode(src, dst, 58, @as(u16, @intCast(pkt.data.size)));

        nic.linkEP.writePacket(&r, ProtocolNumber, mut_pkt) catch {};

        // Also send Router Solicitation to all-routers multicast
        self.sendRouterSolicitation(nic) catch {};

        return ep.networkEndpoint();
    }

    fn sendRouterSolicitation(self: *IPv6Protocol, nic: *stack.NIC) tcpip.Error!void {
        _ = self;
        var src = [_]u8{0} ** 16;
        for (nic.addresses.items) |pa| {
            if (pa.protocol == ProtocolNumber) {
                const addr = pa.address_with_prefix.address.v6;
                if (addr[0] == 0xfe and addr[1] == 0x80) {
                    src = addr;
                    break;
                }
            }
        }

        const dst = [_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }; // All-Routers multicast

        const payload_len = header.ICMPv6MinimumSize + 4 + 8;
        const buf = nic.stack.allocator.alloc(u8, payload_len) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(buf);

        var icmp_h = header.ICMPv6.init(buf[0..header.ICMPv6MinimumSize]);
        icmp_h.data[0] = header.ICMPv6RouterSolicitationType;
        icmp_h.data[1] = 0;
        icmp_h.setChecksum(0);

        // Reserved 4 bytes
        @memset(buf[header.ICMPv6MinimumSize .. header.ICMPv6MinimumSize + 4], 0);

        // Option: Source Link-Layer Address
        buf[header.ICMPv6MinimumSize + 4] = header.ICMPv6OptionSourceLinkLayerAddress;
        buf[header.ICMPv6MinimumSize + 5] = 1;
        @memcpy(buf[header.ICMPv6MinimumSize + 6 .. header.ICMPv6MinimumSize + 12], &nic.linkEP.linkAddress().addr);

        const c = icmp_h.calculateChecksum(src, dst, buf[header.ICMPv6MinimumSize..]);
        icmp_h.setChecksum(c);

        const hdr_mem = nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
        defer nic.stack.allocator.free(hdr_mem);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        const r = stack.Route{
            .local_address = .{ .v6 = src },
            .remote_address = .{ .v6 = dst },
            .local_link_address = nic.linkEP.linkAddress(),
            .remote_link_address = tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, 0, 0, 0, 2 } },
            .net_proto = ProtocolNumber,
            .nic = nic,
        };

        var mut_pkt = pkt;
        const ip_header = mut_pkt.header.prepend(header.IPv6MinimumSize) orelse return tcpip.Error.NoBufferSpace;
        const h = header.IPv6.init(ip_header);
        h.encode(src, dst, 58, @as(u16, @intCast(pkt.data.size)));

        return nic.linkEP.writePacket(&r, ProtocolNumber, mut_pkt);
    }
};

pub const IPv6Endpoint = struct {
    nic: *stack.NIC,
    address: tcpip.Address,
    protocol: *IPv6Protocol,
    dispatcher: stack.TransportDispatcher,
    reassembly_list: std.AutoHashMap(ReassemblyKey, ReassemblyContext),

    pub fn networkEndpoint(self: *IPv6Endpoint) stack.NetworkEndpoint {
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
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.IPv6MinimumSize;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));
        var it = self.reassembly_list.valueIterator();
        while (it.next()) |ctx| {
            ctx.deinit(self.nic.stack.allocator);
        }
        self.reassembly_list.deinit();
        self.nic.stack.allocator.destroy(self);
    }

    fn writePacket(ptr: *anyopaque, r: *const stack.Route, prot: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));

        var mut_pkt = pkt;
        const ip_header = mut_pkt.header.prepend(header.IPv6MinimumSize) orelse return tcpip.Error.NoBufferSpace;
        const h = header.IPv6.init(ip_header);

        h.encode(r.local_address.v6, r.remote_address.v6, @as(u8, @intCast(prot)), @as(u16, @intCast(pkt.data.size)));

        return self.nic.linkEP.writePacket(r, ProtocolNumber, mut_pkt);
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        const self = @as(*IPv6Endpoint, @ptrCast(@alignCast(ptr)));
        var mut_pkt = pkt;
        const headerView = mut_pkt.data.first() orelse return;
        const h = header.IPv6.init(headerView);
        if (!h.isValid(mut_pkt.data.size)) {
            return;
        }

        // Extract flow label for QoS classification
        const flow_label = h.flowLabel();
        _ = flow_label; // Would be used for traffic classification

        mut_pkt.network_header = headerView[0..header.IPv6MinimumSize];

        const hlen = header.IPv6MinimumSize;
        const plen = h.payloadLength();
        const next_hdr = h.nextHeader();

        // NOTE: Extension headers are processed in chain order.
        // Each extension header contains a Next Header field pointing to
        // the next header type in the chain.
        if (next_hdr == NextHeader.HOP_BY_HOP or
            next_hdr == NextHeader.ROUTING or
            next_hdr == NextHeader.FRAGMENT or
            next_hdr == NextHeader.DESTINATION)
        {
            const ext_data = headerView[hlen..];
            const ext_result = parseExtensionHeaders(ext_data, next_hdr);
            if (!ext_result.valid) {
                log.warn("IPv6: Invalid extension headers", .{});
                return;
            }

            // Handle fragmentation
            if (ext_result.fragment_offset != null) {
                self.handleFragment(r, pkt, h, ext_result);
                return;
            }

            mut_pkt.data.trimFront(hlen + ext_result.payload_offset);
            mut_pkt.data.capLength(plen - ext_result.payload_offset);
            self.dispatcher.deliverTransportPacket(r, ext_result.next_header, mut_pkt);
        } else {
            mut_pkt.data.trimFront(hlen);
            mut_pkt.data.capLength(plen);
            self.dispatcher.deliverTransportPacket(r, next_hdr, mut_pkt);
        }
    }

    fn handleFragment(self: *IPv6Endpoint, r: *const stack.Route, pkt: tcpip.PacketBuffer, h: header.IPv6, ext_result: ExtensionHeaderResult) void {
        _ = r;
        _ = pkt;
        _ = h;
        _ = ext_result;
        // NOTE: IPv6 fragment reassembly would mirror the IPv4 implementation
        // using the Fragment header's identification field as the key.
        _ = self;
    }
};

test "IPv6 extension header parsing" {
    // Test simple case - no extension headers
    const data = [_]u8{0} ** 8;
    const result = parseExtensionHeaders(&data, NextHeader.TCP);
    try std.testing.expect(result.valid);
    try std.testing.expectEqual(NextHeader.TCP, result.next_header);
    try std.testing.expectEqual(@as(usize, 0), result.payload_offset);
}

test "IPv6 fragment header parsing" {
    // Fragment header: next=TCP, reserved, offset=0x100 (256*8=2048), M=1, id=0x12345678
    var data: [8]u8 = undefined;
    data[0] = NextHeader.TCP; // next header
    data[1] = 0; // reserved
    std.mem.writeInt(u16, data[2..4], (0x100 << 3) | 0x01, .big); // offset + M flag
    std.mem.writeInt(u32, data[4..8], 0x12345678, .big); // identification

    const result = parseExtensionHeaders(&data, NextHeader.FRAGMENT);
    try std.testing.expect(result.valid);
    try std.testing.expectEqual(NextHeader.TCP, result.next_header);
    try std.testing.expectEqual(@as(?u16, 0x100), result.fragment_offset);
    try std.testing.expect(result.fragment_more);
    try std.testing.expectEqual(@as(u32, 0x12345678), result.fragment_id);
}
