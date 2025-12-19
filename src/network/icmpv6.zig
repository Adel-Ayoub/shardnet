/// ICMPv6 protocol implementation.
///
/// Handles ICMPv6 echo, Neighbor Discovery Protocol (NDP),
/// Router Solicitation/Advertisement, Duplicate Address Detection (DAD),
/// and Multicast Listener Discovery (MLD).

const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");
const log = @import("../log.zig").scoped(.icmpv6);
const stats = @import("../stats.zig");

pub const ProtocolNumber = 58;

/// DAD (Duplicate Address Detection) state.
/// NOTE: RFC 4862 specifies 1 second wait time for DAD.
pub const DADState = struct {
    address: [16]u8,
    retransmit_timer_ms: i64,
    retransmits_left: u8,
    completed: bool,
    conflict: bool,
};

/// MLD (Multicast Listener Discovery) group membership.
pub const MLDGroupEntry = struct {
    group_addr: [16]u8,
    filter_mode: enum { include, exclude },
    /// Timer for query response.
    response_timer_ms: i64,
};

pub const ICMPv6Protocol = struct {
    pub fn init() ICMPv6Protocol {
        return .{};
    }

    pub fn protocol(self: *ICMPv6Protocol) stack.NetworkProtocol {
        return .{
            .ptr = self,
            .vtable = &.{
                .number = number,
                .newEndpoint = newEndpoint,
                .linkAddressRequest = linkAddressRequest,
                .parseAddresses = parseAddresses,
            },
        };
    }

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
        _ = pkt;
        return .{
            .src = .{ .v6 = [_]u8{0} ** 16 },
            .dst = .{ .v6 = [_]u8{0} ** 16 },
        };
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        _ = ptr;
        _ = nic;
        _ = addr;
        _ = dispatcher;
        return tcpip.Error.NotPermitted;
    }
};

pub const ICMPv6TransportProtocol = struct {
    pub fn init() ICMPv6TransportProtocol {
        return .{};
    }

    pub fn protocol(self: *ICMPv6TransportProtocol) stack.TransportProtocol {
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
        ICMPv6PacketHandler.handlePacket(r.nic.stack, r, pkt);
    }
};

pub const ICMPv6PacketHandler = struct {
    pub fn handlePacket(s: *stack.Stack, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        var mut_pkt = pkt;
        const v = mut_pkt.data.first() orelse return;
        const h = header.ICMPv6.init(v);

        stats.global_stats.icmpv6.rx_packets += 1;

        switch (h.type()) {
            header.ICMPv6EchoRequestType => {
                stats.global_stats.icmpv6.rx_echo_requests += 1;
                handleEchoRequest(s, r, v);
            },
            header.ICMPv6EchoReplyType => {
                stats.global_stats.icmpv6.rx_echo_replies += 1;
            },
            header.ICMPv6NeighborSolicitationType => {
                stats.global_stats.icmpv6.rx_neighbor_solicitations += 1;
                handleNeighborSolicitation(s, r, v);
            },
            header.ICMPv6NeighborAdvertisementType => {
                stats.global_stats.icmpv6.rx_neighbor_advertisements += 1;
                handleNeighborAdvertisement(s, r, v);
            },
            header.ICMPv6RouterSolicitationType => {
                stats.global_stats.icmpv6.rx_router_solicitations += 1;
            },
            header.ICMPv6RouterAdvertisementType => {
                stats.global_stats.icmpv6.rx_router_advertisements += 1;
                handleRouterAdvertisement(s, r, v);
            },
            130 => { // MLD Query
                handleMLDQuery(s, r, v);
            },
            131 => { // MLDv1 Report
                handleMLDReport(s, r, v);
            },
            143 => { // MLDv2 Report
                handleMLDv2Report(s, r, v);
            },
            else => {
                log.debug("Unknown ICMPv6 type: {}", .{h.type()});
            },
        }
    }

    fn handleEchoRequest(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        const payload = s.allocator.alloc(u8, v.len) catch return;
        defer s.allocator.free(payload);
        @memcpy(payload, v);

        var reply_h = header.ICMPv6.init(payload);
        reply_h.data[0] = header.ICMPv6EchoReplyType;
        reply_h.setChecksum(0);

        const src = r.local_address.v6;
        const dst = r.remote_address.v6;
        const c = reply_h.calculateChecksum(src, dst, payload[header.ICMPv6MinimumSize..]);
        reply_h.setChecksum(c);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = payload }};
        const hdr_mem = s.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer s.allocator.free(hdr_mem);

        const reply_pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(payload.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        const reply_route = r.*;
        if (r.nic.network_endpoints.get(0x86dd)) |ep| {
            stats.global_stats.icmpv6.tx_echo_replies += 1;
            ep.writePacket(&reply_route, ProtocolNumber, reply_pkt) catch {};
        }
    }

    fn handleNeighborSolicitation(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        if (v.len < header.ICMPv6MinimumSize + 20) return;
        const ns = header.ICMPv6NS.init(v[header.ICMPv6MinimumSize..]);
        const target = ns.targetAddress();

        const src_is_unspecified = r.remote_address.eq(.{ .v6 = [_]u8{0} ** 16 });

        // Learn sender's link-layer address from SLLA option
        if (!src_is_unspecified and v.len >= header.ICMPv6MinimumSize + 28) {
            if (v[header.ICMPv6MinimumSize + 20] == header.ICMPv6OptionSourceLinkLayerAddress) {
                var mac: tcpip.LinkAddress = undefined;
                @memcpy(&mac.addr, v[header.ICMPv6MinimumSize + 22 .. header.ICMPv6MinimumSize + 28]);
                s.addLinkAddress(r.remote_address, mac) catch {};
            }
        }

        if (r.nic.hasAddress(.{ .v6 = target })) {
            // NOTE: If source is unspecified (::), this is a DAD probe.
            // We respond with NA but don't add to neighbor cache.
            const is_dad = src_is_unspecified;

            if (is_dad) {
                // NOTE: RFC 4862 Section 5.4.3 - Receiving DAD NS
                // A conflict means someone else is probing for our address.
                log.err("IPv6 DAD Conflict detected for address {any}", .{target});
            }

            sendNeighborAdvertisement(s, r, target, is_dad);
        }
    }

    fn sendNeighborAdvertisement(s: *stack.Stack, r: *const stack.Route, target: [16]u8, is_dad: bool) void {
        const na_buf = s.allocator.alloc(u8, header.ICMPv6MinimumSize + 20 + 8) catch return;
        defer s.allocator.free(na_buf);

        var na_h = header.ICMPv6.init(na_buf[0..header.ICMPv6MinimumSize]);
        na_h.data[0] = header.ICMPv6NeighborAdvertisementType;
        na_h.data[1] = 0;
        na_h.setChecksum(0);

        var na = header.ICMPv6NA.init(na_buf[header.ICMPv6MinimumSize..]);
        na.setFlags(if (is_dad) header.ICMPv6NAFlagsOverride else (header.ICMPv6NAFlagsSolicited | header.ICMPv6NAFlagsOverride));
        na.setTargetAddress(target);

        // TLLA option
        na_buf[header.ICMPv6MinimumSize + 20] = header.ICMPv6OptionTargetLinkLayerAddress;
        na_buf[header.ICMPv6MinimumSize + 21] = 1;
        @memcpy(na_buf[header.ICMPv6MinimumSize + 22 .. header.ICMPv6MinimumSize + 28], &r.nic.linkEP.linkAddress().addr);

        const src = target;
        const dst = if (is_dad) ([_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }) else r.remote_address.v6;

        const c = na_h.calculateChecksum(src, dst, na_buf[header.ICMPv6MinimumSize..]);
        na_h.setChecksum(c);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = na_buf }};
        const hdr_mem = s.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer s.allocator.free(hdr_mem);

        const na_pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(na_buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        var na_route = stack.Route{
            .local_address = .{ .v6 = src },
            .remote_address = .{ .v6 = dst },
            .local_link_address = r.nic.linkEP.linkAddress(),
            .remote_link_address = if (is_dad) tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, 0, 0, 0, 1 } } else r.remote_link_address,
            .net_proto = 0x86dd,
            .nic = r.nic,
        };

        if (r.nic.network_endpoints.get(0x86dd)) |ep| {
            stats.global_stats.icmpv6.tx_neighbor_advertisements += 1;
            ep.writePacket(&na_route, ProtocolNumber, na_pkt) catch {};
        }
    }

    fn handleNeighborAdvertisement(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        if (v.len < header.ICMPv6MinimumSize + 20) return;
        const na = header.ICMPv6NA.init(v[header.ICMPv6MinimumSize..]);
        const target = na.targetAddress();

        // Extract TLLA option
        if (v.len >= header.ICMPv6MinimumSize + 28) {
            if (v[header.ICMPv6MinimumSize + 20] == header.ICMPv6OptionTargetLinkLayerAddress) {
                var mac: tcpip.LinkAddress = undefined;
                @memcpy(&mac.addr, v[header.ICMPv6MinimumSize + 22 .. header.ICMPv6MinimumSize + 28]);
                s.addLinkAddress(.{ .v6 = target }, mac) catch {};
            }
        }
    }

    fn handleRouterAdvertisement(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        if (v.len < header.ICMPv6MinimumSize + 12) return;
        const ra = header.ICMPv6RA.init(v[header.ICMPv6MinimumSize..]);

        // Add default gateway if lifetime > 0
        if (ra.routerLifetime() > 0) {
            s.addRoute(.{
                .destination = .{ .address = .{ .v6 = [_]u8{0} ** 16 }, .prefix = 0 },
                .gateway = r.remote_address,
                .nic = r.nic.id,
                .mtu = r.nic.linkEP.mtu(),
            }) catch {};

            // Learn router's MAC
            if (r.remote_link_address) |mac| {
                s.addLinkAddress(r.remote_address, mac) catch {};
            }
        }

        // Parse Options
        var opt_idx: usize = header.ICMPv6MinimumSize + 12;
        while (opt_idx + 2 <= v.len) {
            const opt_type = v[opt_idx];
            const opt_len = @as(usize, v[opt_idx + 1]) * 8;
            if (opt_len == 0 or opt_idx + opt_len > v.len) break;

            if (opt_type == header.ICMPv6OptionPrefixInformation) {
                if (opt_len >= 32) {
                    handlePrefixOption(s, r, v[opt_idx..][0..opt_len]);
                }
            }
            opt_idx += opt_len;
        }
    }

    fn handlePrefixOption(s: *stack.Stack, r: *const stack.Route, opt: []const u8) void {
        _ = s;
        const pinfo = header.ICMPv6OptionPrefix.init(opt);
        const prefix = pinfo.prefix();
        const prefix_len = pinfo.prefixLength();

        // Flags: L=0x80, A=0x40
        const flags = opt[3];
        if (flags & 0x40 != 0) { // Autonomous address-configuration flag
            // SLAAC: Generate address from prefix + interface ID (Modified EUI-64)
            var new_addr = prefix;
            const mac = r.nic.linkEP.linkAddress();
            new_addr[8] = mac.addr[0] ^ 0x02;
            new_addr[9] = mac.addr[1];
            new_addr[10] = mac.addr[2];
            new_addr[11] = 0xff;
            new_addr[12] = 0xfe;
            new_addr[13] = mac.addr[3];
            new_addr[14] = mac.addr[4];
            new_addr[15] = mac.addr[5];

            if (!r.nic.hasAddress(.{ .v6 = new_addr })) {
                r.nic.addAddress(.{
                    .protocol = 0x86dd,
                    .address_with_prefix = .{
                        .address = .{ .v6 = new_addr },
                        .prefix_len = prefix_len,
                    },
                }) catch {};
                log.info("SLAAC: Configured address {any}/{}", .{ new_addr, prefix_len });
            }
        }
    }

    /// Handle MLD Query (type 130).
    fn handleMLDQuery(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        _ = s;
        _ = r;
        if (v.len < header.ICMPv6MinimumSize + 20) return;
        // NOTE: Would schedule MLD report for each joined multicast group
        log.debug("MLD Query received", .{});
    }

    /// Handle MLDv1 Report (type 131).
    fn handleMLDReport(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        _ = s;
        _ = r;
        _ = v;
        // Informational only for hosts
    }

    /// Handle MLDv2 Report (type 143).
    fn handleMLDv2Report(s: *stack.Stack, r: *const stack.Route, v: []const u8) void {
        _ = s;
        _ = r;
        _ = v;
        // Informational only for hosts
    }

    /// Send MLD Report for joining a multicast group.
    pub fn sendMLDReport(s: *stack.Stack, nic: *stack.NIC, group: [16]u8) void {
        const report_len = header.ICMPv6MinimumSize + 20;
        const buf = s.allocator.alloc(u8, report_len) catch return;
        defer s.allocator.free(buf);

        @memset(buf, 0);
        buf[0] = 131; // MLDv1 Report
        buf[1] = 0;
        // Checksum placeholder
        // Maximum Response Delay (2 bytes) = 0
        // Reserved (2 bytes) = 0
        @memcpy(buf[8..24], &group);

        const src = nic.getLinkLocalAddress() orelse return;
        var h = header.ICMPv6.init(buf[0..header.ICMPv6MinimumSize]);
        const c = h.calculateChecksum(src.v6, group, buf[header.ICMPv6MinimumSize..]);
        h.setChecksum(c);

        var views = [_]buffer.ClusterView{.{ .cluster = null, .view = buf }};
        const hdr_mem = s.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer s.allocator.free(hdr_mem);

        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(buf.len, &views),
            .header = buffer.Prependable.init(hdr_mem),
        };

        const r = stack.Route{
            .local_address = src,
            .remote_address = .{ .v6 = group },
            .local_link_address = nic.linkEP.linkAddress(),
            .remote_link_address = tcpip.LinkAddress{ .addr = [_]u8{ 0x33, 0x33, group[12], group[13], group[14], group[15] } },
            .net_proto = 0x86dd,
            .nic = nic,
        };

        if (nic.network_endpoints.get(0x86dd)) |ep| {
            ep.writePacket(&r, ProtocolNumber, pkt) catch {};
        }
    }
};

test "ICMPv6 Neighbor Discovery" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var ipv6_proto = @import("ipv6.zig").IPv6Protocol.init();
    try s.registerNetworkProtocol(ipv6_proto.protocol());

    var icmpv6_transport = ICMPv6TransportProtocol.init();
    try s.registerTransportProtocol(icmpv6_transport.protocol());

    var fake_link = struct {
        last_pkt: ?[]u8 = null,
        alloc: std.mem.Allocator,

        fn writePacket(ptr: *anyopaque, route: ?*const stack.Route, prot: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = route;
            _ = prot;
            const hdr_view = pkt.header.view();
            const data_len = pkt.data.size;
            if (self.last_pkt) |p| self.alloc.free(p);
            self.last_pkt = self.alloc.alloc(u8, hdr_view.len + data_len) catch return tcpip.Error.NoBufferSpace;
            @memcpy(self.last_pkt.?[0..hdr_view.len], hdr_view);
            var offset = hdr_view.len;
            for (pkt.data.views) |v| {
                @memcpy(self.last_pkt.?[offset .. offset + v.view.len], v.view);
                offset += v.view.len;
            }
            return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
            _ = ptr;
            _ = dispatcher;
        }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
            _ = ptr;
            return .{ .addr = [_]u8{ 1, 2, 3, 4, 5, 6 } };
        }
        fn getMtu(ptr: *anyopaque) u32 {
            _ = ptr;
            return 1500;
        }
        fn setMTU(ptr: *anyopaque, m: u32) void {
            _ = ptr;
            _ = m;
        }
        fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
            _ = ptr;
            return stack.CapabilityNone;
        }
    }{ .alloc = allocator };
    defer if (fake_link.last_pkt) |p| allocator.free(p);

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{
            .writePacket = @TypeOf(fake_link).writePacket,
            .attach = @TypeOf(fake_link).attach,
            .linkAddress = @TypeOf(fake_link).linkAddress,
            .mtu = @TypeOf(fake_link).getMtu,
            .setMTU = @TypeOf(fake_link).setMTU,
            .capabilities = @TypeOf(fake_link).capabilities,
        },
    };

    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;

    const my_addr = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try nic.addAddress(.{
        .protocol = 0x86dd,
        .address_with_prefix = .{ .address = .{ .v6 = my_addr }, .prefix_len = 64 },
    });

    const sender_addr = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    const sender_mac = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

    var ns_buf = try allocator.alloc(u8, header.ICMPv6MinimumSize + 20 + 8);
    defer allocator.free(ns_buf);

    var icmp_h = header.ICMPv6.init(ns_buf[0..header.ICMPv6MinimumSize]);
    icmp_h.data[0] = header.ICMPv6NeighborSolicitationType;
    icmp_h.data[1] = 0;
    icmp_h.setChecksum(0);

    var ns = header.ICMPv6NS.init(ns_buf[header.ICMPv6MinimumSize..]);
    ns.setTargetAddress(my_addr);

    ns_buf[header.ICMPv6MinimumSize + 20] = header.ICMPv6OptionSourceLinkLayerAddress;
    ns_buf[header.ICMPv6MinimumSize + 21] = 1;
    @memcpy(ns_buf[header.ICMPv6MinimumSize + 22 .. header.ICMPv6MinimumSize + 28], &sender_mac);

    const r = stack.Route{
        .local_address = .{ .v6 = my_addr },
        .remote_address = .{ .v6 = sender_addr },
        .local_link_address = .{ .addr = [_]u8{ 1, 2, 3, 4, 5, 6 } },
        .remote_link_address = .{ .addr = sender_mac },
        .net_proto = 0x86dd,
        .nic = nic,
    };

    var views = [_]buffer.ClusterView{.{ .cluster = null, .view = ns_buf }};
    const ns_pkt = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(ns_buf.len, &views),
        .header = buffer.Prependable.init(&[_]u8{}),
    };

    ICMPv6PacketHandler.handlePacket(&s, &r, ns_pkt);

    const learned_mac = s.getLinkAddress(.{ .v6 = sender_addr });
    try std.testing.expect(learned_mac != null);
    try std.testing.expectEqualStrings(&sender_mac, &learned_mac.?.addr);

    try std.testing.expect(fake_link.last_pkt != null);
    const na_pkt_data = fake_link.last_pkt.?;
    try std.testing.expect(na_pkt_data.len >= 40 + 28);
    const na_icmp = header.ICMPv6.init(na_pkt_data[40..]);
    try std.testing.expectEqual(header.ICMPv6NeighborAdvertisementType, na_icmp.type());

    const na = header.ICMPv6NA.init(na_pkt_data[40 + header.ICMPv6MinimumSize ..]);
    try std.testing.expectEqualStrings(&my_addr, &na.targetAddress());
}

test "ICMPv6 Router Advertisement & SLAAC" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var ipv6_proto = @import("ipv6.zig").IPv6Protocol.init();
    try s.registerNetworkProtocol(ipv6_proto.protocol());

    var icmpv6_transport = ICMPv6TransportProtocol.init();
    try s.registerTransportProtocol(icmpv6_transport.protocol());

    var fake_link = struct {
        last_pkt: ?[]u8 = null,
        alloc: std.mem.Allocator,

        fn writePacket(ptr: *anyopaque, route: ?*const stack.Route, prot: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            const self = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = route;
            _ = prot;
            const hdr_view = pkt.header.view();
            const data_len = pkt.data.size;
            if (self.last_pkt) |p| self.alloc.free(p);
            self.last_pkt = self.alloc.alloc(u8, hdr_view.len + data_len) catch return tcpip.Error.NoBufferSpace;
            @memcpy(self.last_pkt.?[0..hdr_view.len], hdr_view);
            var offset = hdr_view.len;
            for (pkt.data.views) |v| {
                @memcpy(self.last_pkt.?[offset .. offset + v.view.len], v.view);
                offset += v.view.len;
            }
            return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
            _ = ptr;
            _ = dispatcher;
        }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
            _ = ptr;
            return .{ .addr = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 } };
        }
        fn getMtu(ptr: *anyopaque) u32 {
            _ = ptr;
            return 1500;
        }
        fn setMTU(ptr: *anyopaque, m: u32) void {
            _ = ptr;
            _ = m;
        }
        fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
            _ = ptr;
            return stack.CapabilityNone;
        }
    }{ .alloc = allocator };
    defer if (fake_link.last_pkt) |p| allocator.free(p);

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_link,
        .vtable = &.{
            .writePacket = @TypeOf(fake_link).writePacket,
            .attach = @TypeOf(fake_link).attach,
            .linkAddress = @TypeOf(fake_link).linkAddress,
            .mtu = @TypeOf(fake_link).getMtu,
            .setMTU = @TypeOf(fake_link).setMTU,
            .capabilities = @TypeOf(fake_link).capabilities,
        },
    };

    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;

    const my_ll_addr = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    try nic.addAddress(.{
        .protocol = 0x86dd,
        .address_with_prefix = .{ .address = .{ .v6 = my_ll_addr }, .prefix_len = 64 },
    });

    const router_addr = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const router_mac = [_]u8{ 0xaa, 0x30, 0x75, 0xe0, 0x61, 0x19 };
    const prefix = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    var ra_buf = try allocator.alloc(u8, 48);
    defer allocator.free(ra_buf);
    @memset(ra_buf, 0);

    var icmp_h = header.ICMPv6.init(ra_buf[0..header.ICMPv6MinimumSize]);
    icmp_h.data[0] = header.ICMPv6RouterAdvertisementType;

    const ra = header.ICMPv6RA.init(ra_buf[header.ICMPv6MinimumSize..]);
    _ = ra;
    std.mem.writeInt(u16, ra_buf[header.ICMPv6MinimumSize + 2 .. header.ICMPv6MinimumSize + 4][0..2], 1800, .big);

    const opt_idx = header.ICMPv6MinimumSize + 12;
    ra_buf[opt_idx] = header.ICMPv6OptionPrefixInformation;
    ra_buf[opt_idx + 1] = 4;
    ra_buf[opt_idx + 2] = 64;
    ra_buf[opt_idx + 3] = 0xC0; // L=1, A=1
    @memcpy(ra_buf[opt_idx + 16 .. opt_idx + 32], &prefix);

    const r = stack.Route{
        .local_address = .{ .v6 = my_ll_addr },
        .remote_address = .{ .v6 = router_addr },
        .local_link_address = .{ .addr = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 } },
        .remote_link_address = .{ .addr = router_mac },
        .net_proto = 0x86dd,
        .nic = nic,
    };

    var views = [_]buffer.ClusterView{.{ .cluster = null, .view = ra_buf }};
    const ra_pkt = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(ra_buf.len, &views),
        .header = buffer.Prependable.init(&[_]u8{}),
    };

    ICMPv6PacketHandler.handlePacket(&s, &r, ra_pkt);

    var expected_addr = prefix;
    expected_addr[8] = 0x00;
    expected_addr[9] = 0x00;
    expected_addr[10] = 0x00;
    expected_addr[11] = 0xff;
    expected_addr[12] = 0xfe;
    expected_addr[13] = 0x00;
    expected_addr[14] = 0x00;
    expected_addr[15] = 0x02;

    try std.testing.expect(nic.hasAddress(.{ .v6 = expected_addr }));

    const routes = s.getRouteTable();
    var found_default = false;
    for (routes) |re| {
        if (re.destination.prefix == 0 and re.gateway.v6[0] == router_addr[0]) {
            found_default = true;
            break;
        }
    }
    try std.testing.expect(found_default);
}
