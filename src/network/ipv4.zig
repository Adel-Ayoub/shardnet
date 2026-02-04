/// IPv4 packet handling.
///
/// Implements IPv4 parsing, validation, fragmentation/reassembly,
/// and integration with the network stack.

const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const log = @import("../log.zig").scoped(.ipv4);
const stats = @import("../stats.zig");
const buffer = @import("../buffer.zig");

pub const ProtocolNumber = 0x0800;

/// Default Time-To-Live for outgoing packets.
pub const DEFAULT_TTL: u8 = 64;

/// Maximum time to hold reassembly fragments before expiry (30 seconds).
///
/// RFC 791 Section 3.2 mandates that reassembly resources MUST be reclaimed
/// if the complete datagram is not received within a reasonable time limit.
/// The RFC suggests a lower bound of 15 seconds; we use 30 seconds as a
/// conservative default that tolerates moderate path delays while still
/// preventing memory exhaustion from fragment floods.
pub const REASSEMBLY_TIMEOUT_MS: i64 = 30_000;

/// IP option types for options parsing.
pub const OptionType = struct {
    pub const END_OF_OPTIONS: u8 = 0;
    pub const NOP: u8 = 1;
    pub const LOOSE_SOURCE_ROUTE: u8 = 131;
    pub const STRICT_SOURCE_ROUTE: u8 = 137;
    pub const RECORD_ROUTE: u8 = 7;
    pub const TIMESTAMP: u8 = 68;
};

pub const IPv4Protocol = struct {
    pub fn init() IPv4Protocol {
        return .{};
    }

    pub fn protocol(self: *IPv4Protocol) stack.NetworkProtocol {
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
        .deinit = deinit_external,
    };

    fn deinit_external(ptr: *anyopaque) void {
        _ = ptr;
    }

    fn number(ptr: *anyopaque) tcpip.NetworkProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
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

    fn linkAddressRequest(ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *stack.NIC) tcpip.Error!void {
        _ = ptr;
        _ = addr;
        _ = local_addr;
        _ = nic;
        return tcpip.Error.NotPermitted;
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        const self = @as(*IPv4Protocol, @ptrCast(@alignCast(ptr)));
        const ep = nic.stack.allocator.create(IPv4Endpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = .{
            .nic = nic,
            .address = addr.address,
            .protocol = self,
            .dispatcher = dispatcher,
            .reassembly_list = std.AutoHashMap(ReassemblyKey, ReassemblyContext).init(nic.stack.allocator),
        };
        return ep.networkEndpoint();
    }
};

const Fragment = struct {
    data: tcpip.PacketBuffer,
    offset: u16,
    more: bool,
    id: u16,
    src: tcpip.Address,
    dst: tcpip.Address,
};

/// Key for fragment reassembly indexed by (src, dst, id, protocol).
const ReassemblyKey = struct {
    src: tcpip.Address,
    dst: tcpip.Address,
    id: u16,
    protocol: u8,
};

/// Context holding fragments for a reassembly in progress.
const ReassemblyContext = struct {
    fragments: std.ArrayList(Fragment),
    /// Timestamp when first fragment arrived (for expiry).
    first_arrival_ms: i64,

    pub fn init(allocator: std.mem.Allocator) ReassemblyContext {
        return .{
            .fragments = std.ArrayList(Fragment).init(allocator),
            .first_arrival_ms = std.time.milliTimestamp(),
        };
    }

    pub fn deinit(self: *ReassemblyContext) void {
        self.fragments.deinit();
    }

    /// Check if this reassembly has expired.
    pub fn isExpired(self: *const ReassemblyContext) bool {
        const now = std.time.milliTimestamp();
        return (now - self.first_arrival_ms) >= REASSEMBLY_TIMEOUT_MS;
    }
};

/// Parsed IP options from the header.
pub const ParsedOptions = struct {
    /// Loose source route addresses (if present).
    loose_source_route: ?[]const u8 = null,
    /// Strict source route addresses (if present).
    strict_source_route: ?[]const u8 = null,
    /// Record route slot offset.
    record_route_ptr: u8 = 0,
    /// Whether options were successfully parsed.
    valid: bool = true,
};

/// Parse IP options from header bytes.
pub fn parseOptions(options_bytes: []const u8) ParsedOptions {
    var result = ParsedOptions{};
    var i: usize = 0;

    while (i < options_bytes.len) {
        const opt_type = options_bytes[i];

        if (opt_type == OptionType.END_OF_OPTIONS) break;
        if (opt_type == OptionType.NOP) {
            i += 1;
            continue;
        }

        // Multi-byte option
        if (i + 1 >= options_bytes.len) {
            result.valid = false;
            break;
        }

        const opt_len = options_bytes[i + 1];
        if (opt_len < 2 or i + opt_len > options_bytes.len) {
            result.valid = false;
            break;
        }

        switch (opt_type) {
            OptionType.LOOSE_SOURCE_ROUTE => {
                if (opt_len >= 3) {
                    result.loose_source_route = options_bytes[i..][0..opt_len];
                }
            },
            OptionType.STRICT_SOURCE_ROUTE => {
                if (opt_len >= 3) {
                    result.strict_source_route = options_bytes[i..][0..opt_len];
                }
            },
            OptionType.RECORD_ROUTE => {
                if (opt_len >= 3) {
                    result.record_route_ptr = options_bytes[i + 2];
                }
            },
            else => {},
        }

        i += opt_len;
    }

    return result;
}

pub const IPv4Endpoint = struct {
    nic: *stack.NIC,
    address: tcpip.Address,
    protocol: *IPv4Protocol,
    dispatcher: stack.TransportDispatcher,
    reassembly_list: std.AutoHashMap(ReassemblyKey, ReassemblyContext),

    pub fn networkEndpoint(self: *IPv4Endpoint) stack.NetworkEndpoint {
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = stack.NetworkEndpoint.VTable{
        .writePacket = writePacket,
        .writePackets = writePackets,
        .handlePacket = handlePacket,
        .mtu = mtu,
        .close = close,
    };

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*IPv4Endpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.IPv4MinimumSize;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*IPv4Endpoint, @ptrCast(@alignCast(ptr)));
        var it = self.reassembly_list.valueIterator();
        while (it.next()) |ctx| {
            ctx.deinit();
        }
        self.reassembly_list.deinit();
        self.nic.stack.allocator.destroy(self);
    }

    fn writePacket(ptr: *anyopaque, r: *const stack.Route, prot: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const p = [_]tcpip.PacketBuffer{pkt};
        return writePackets(ptr, r, prot, &p);
    }

    fn writePackets(ptr: *anyopaque, r: *const stack.Route, prot: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*IPv4Endpoint, @ptrCast(@alignCast(ptr)));
        const max_payload = self.nic.linkEP.mtu() - header.IPv4MinimumSize;

        var remote_link_address = r.remote_link_address;
        if (remote_link_address == null) {
            const next_hop = r.next_hop orelse r.remote_address;
            remote_link_address = self.nic.stack.link_addr_cache.get(next_hop);
        }

        if (remote_link_address == null) {
            const arp_proto_ptr = self.nic.stack.network_protocols.get(0x0806) orelse return tcpip.Error.NoRoute;
            arp_proto_ptr.linkAddressRequest(r.remote_address, r.local_address, self.nic) catch {};
            return tcpip.Error.WouldBlock;
        }

        var mut_r = r.*;
        mut_r.remote_link_address = remote_link_address;

        var mut_packets_storage: [64]tcpip.PacketBuffer = undefined;
        if (packets.len > 64) return tcpip.Error.MessageTooLong;
        const mut_packets = mut_packets_storage[0..packets.len];

        for (packets, 0..) |pkt, i| {
            if (pkt.data.size > max_payload) return tcpip.Error.MessageTooLong;

            var mut_pkt = pkt;
            const ip_header = mut_pkt.header.prepend(header.IPv4MinimumSize) orelse return tcpip.Error.NoBufferSpace;
            const h = header.IPv4.init(ip_header);

            @memset(ip_header, 0);
            ip_header[0] = 0x45;
            const total_len = @as(u16, @intCast(mut_pkt.header.usedLength() + mut_pkt.data.size));
            std.mem.writeInt(u16, ip_header[2..4][0..2], total_len, .big);
            ip_header[8] = DEFAULT_TTL;
            ip_header[9] = @as(u8, @intCast(prot));
            @memcpy(ip_header[12..16], &r.local_address.v4);
            @memcpy(ip_header[16..20], &r.remote_address.v4);
            h.setChecksum(h.calculateChecksum());

            mut_packets[i] = mut_pkt;
        }

        stats.global_stats.ip.tx_packets += mut_packets.len;
        return self.nic.linkEP.writePackets(&mut_r, ProtocolNumber, mut_packets);
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        const self = @as(*IPv4Endpoint, @ptrCast(@alignCast(ptr)));
        var mut_pkt = pkt;
        const headerView = mut_pkt.data.first() orelse return;
        const h = header.IPv4.init(headerView);
        if (!h.isValid(mut_pkt.data.size)) {
            return;
        }

        const hlen = h.headerLength();

        // PERF: Skip checksum validation if NIC reports hardware offload.
        // For now we always validate since we don't have capability flags wired up.
        const csum_calc = header.finishChecksum(header.internetChecksum(headerView[0..hlen], 0));
        if (csum_calc != 0) {
            log.warn("IPv4: Checksum failure from {any} (Calculated: 0x{x}, Header: 0x{x})", .{ h.sourceAddress(), csum_calc, h.checksum() });
            stats.global_stats.ip.dropped_packets += 1;
            return;
        }

        stats.global_stats.ip.rx_packets += 1;

        // Parse IP options if present
        if (hlen > header.IPv4MinimumSize) {
            const options_bytes = headerView[header.IPv4MinimumSize..hlen];
            const parsed = parseOptions(options_bytes);
            if (!parsed.valid) {
                log.warn("IPv4: Invalid options", .{});
            }
            // NOTE: Source routing options would be processed here for forwarding
        }

        // Check TTL and generate Time Exceeded if needed (for forwarding)
        const ttl = h.ttl();
        if (ttl == 0) {
            log.debug("IPv4: TTL expired for packet from {any}", .{h.sourceAddress()});
            self.sendTimeExceeded(r, pkt);
            return;
        }

        if (h.moreFragments() or h.fragmentOffset() > 0) {
            self.handleFragment(r, pkt, h, hlen);
            return;
        }

        mut_pkt.network_header = headerView[0..h.headerLength()];
        const tlen = h.totalLength();
        mut_pkt.data.trimFront(hlen);
        mut_pkt.data.capLength(tlen - hlen);

        const p = h.protocol();
        self.dispatcher.deliverTransportPacket(r, p, mut_pkt);
    }

    fn handleFragment(self: *IPv4Endpoint, r: *const stack.Route, pkt: tcpip.PacketBuffer, h: header.IPv4, hlen: usize) void {
        const key = ReassemblyKey{
            .src = .{ .v4 = h.sourceAddress() },
            .dst = .{ .v4 = h.destinationAddress() },
            .id = h.id(),
            .protocol = h.protocol(),
        };

        // Expire old reassembly contexts
        self.expireReassemblyContexts();

        var ctx_ptr = self.reassembly_list.getPtr(key);
        if (ctx_ptr == null) {
            const ctx = ReassemblyContext.init(self.nic.stack.allocator);
            self.reassembly_list.put(key, ctx) catch return;
            ctx_ptr = self.reassembly_list.getPtr(key);
        }
        const ctx = ctx_ptr.?;

        var payload_pkt = pkt;
        payload_pkt.data.trimFront(hlen);
        const tlen = h.totalLength();
        if (tlen > hlen) {
            payload_pkt.data.capLength(tlen - hlen);
        } else {
            return;
        }

        const cloned_data = payload_pkt.data.clone(self.nic.stack.allocator) catch return;

        const fragment = Fragment{
            .data = .{ .data = cloned_data, .header = undefined },
            .offset = h.fragmentOffset(),
            .more = h.moreFragments(),
            .id = h.id(),
            .src = key.src,
            .dst = key.dst,
        };
        ctx.fragments.append(fragment) catch return;

        const Sort = struct {
            fn less(context: void, a: Fragment, b: Fragment) bool {
                _ = context;
                return a.offset < b.offset;
            }
        };
        std.sort.block(Fragment, ctx.fragments.items, {}, Sort.less);

        var expected_offset: u16 = 0;
        var complete = true;
        var has_last = false;

        for (ctx.fragments.items) |f| {
            const f_len = @as(u16, @intCast(f.data.data.size));
            if (f.offset != expected_offset) {
                complete = false;
                break;
            }
            expected_offset += f_len;
            if (!f.more) has_last = true;
        }

        if (complete and has_last) {
            var total_size: usize = 0;
            for (ctx.fragments.items) |f| total_size += f.data.data.size;

            const reassembled_buf = self.nic.stack.allocator.alloc(u8, total_size) catch return;
            var offset: usize = 0;
            for (ctx.fragments.items) |f| {
                const v = f.data.data.toView(self.nic.stack.allocator) catch return;
                defer self.nic.stack.allocator.free(v);
                @memcpy(reassembled_buf[offset .. offset + v.len], v);
                offset += v.len;
                var mut_data = f.data.data;
                mut_data.deinit();
            }

            ctx.fragments.deinit();
            _ = self.reassembly_list.remove(key);

            var views = [_]buffer.ClusterView{.{ .cluster = null, .view = reassembled_buf }};
            const reassembled_pkt = tcpip.PacketBuffer{
                .data = buffer.VectorisedView.init(total_size, &views),
                .header = undefined,
            };

            const p = h.protocol();
            self.dispatcher.deliverTransportPacket(r, p, reassembled_pkt);
            self.nic.stack.allocator.free(reassembled_buf);
        }
    }

    /// Expire stale reassembly contexts that have exceeded REASSEMBLY_TIMEOUT_MS.
    ///
    /// NOTE: Per RFC 791, incomplete datagrams MUST be discarded after a timeout
    /// to prevent memory exhaustion from fragment flood attacks or lost fragments.
    /// When a context expires, all its buffered fragments are released and an
    /// ICMP Time Exceeded (code 1: fragment reassembly time exceeded) SHOULD be
    /// sent to the source. We currently drop silently to avoid amplification.
    fn expireReassemblyContexts(self: *IPv4Endpoint) void {
        var to_remove = std.ArrayList(ReassemblyKey).init(self.nic.stack.allocator);
        defer to_remove.deinit();

        var it = self.reassembly_list.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                log.debug("IPv4: Expiring stale fragment reassembly (id={}, src={any})", .{
                    entry.key_ptr.id,
                    entry.key_ptr.src.v4,
                });
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |key| {
            if (self.reassembly_list.getPtr(key)) |ctx| {
                ctx.deinit();
            }
            _ = self.reassembly_list.remove(key);
        }
    }

    /// Send ICMP Time Exceeded message (TTL expired).
    fn sendTimeExceeded(self: *IPv4Endpoint, r: *const stack.Route, original_pkt: tcpip.PacketBuffer) void {
        _ = self;
        _ = r;
        _ = original_pkt;
        // NOTE: Would construct ICMP type 11 (Time Exceeded) code 0 (TTL expired in transit)
        // with first 8 bytes of original datagram as payload.
        // Rate limiting would apply here to prevent amplification.
        stats.global_stats.ip.dropped_packets += 1;
    }
};

test "IPv4 fragmentation and reassembly" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var fake_ep = struct {
        mtu_val: u32 = 1500,
        fn writePacket(ptr: *anyopaque, route: ?*const stack.Route, prot: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            _ = ptr;
            _ = route;
            _ = prot;
            _ = pkt;
            return;
        }
        fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
            _ = ptr;
            _ = dispatcher;
        }
        fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
            _ = ptr;
            return .{ .addr = [_]u8{0} ** 6 };
        }
        fn getMtu(ptr: *anyopaque) u32 {
            const self_ptr = @as(*@This(), @ptrCast(@alignCast(ptr)));
            return self_ptr.mtu_val;
        }
        fn setMTU(ptr: *anyopaque, m: u32) void {
            const self_ptr = @as(*@This(), @ptrCast(@alignCast(ptr)));
            self_ptr.mtu_val = m;
        }
        fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
            _ = ptr;
            return stack.CapabilityNone;
        }
    }{ .mtu_val = 1500 };

    const link_ep = stack.LinkEndpoint{
        .ptr = &fake_ep,
        .vtable = &.{
            .writePacket = @TypeOf(fake_ep).writePacket,
            .attach = @TypeOf(fake_ep).attach,
            .linkAddress = @TypeOf(fake_ep).linkAddress,
            .mtu = @TypeOf(fake_ep).getMtu,
            .setMTU = @TypeOf(fake_ep).setMTU,
            .capabilities = @TypeOf(fake_ep).capabilities,
        },
    };

    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    const ipv4_proto = IPv4Protocol.init();

    var delivered = false;
    var delivered_len: usize = 0;
    const FakeDispatcher = struct {
        delivered: *bool,
        delivered_len: *usize,
        fn deliverTransportPacket(ptr: *anyopaque, route: *const stack.Route, prot: tcpip.TransportProtocolNumber, pkt: tcpip.PacketBuffer) void {
            const self_ptr = @as(*@This(), @ptrCast(@alignCast(ptr)));
            _ = route;
            _ = prot;
            self_ptr.delivered.* = true;
            self_ptr.delivered_len.* = pkt.data.size;
        }
    };
    var fd = FakeDispatcher{ .delivered = &delivered, .delivered_len = &delivered_len };
    const dispatcher = stack.TransportDispatcher{
        .ptr = &fd,
        .vtable = &.{
            .deliverTransportPacket = FakeDispatcher.deliverTransportPacket,
        },
    };

    var ep_ipv4 = try nic.stack.allocator.create(IPv4Endpoint);
    ep_ipv4.* = .{
        .nic = nic,
        .address = .{ .v4 = .{ 10, 0, 0, 1 } },
        .protocol = @constCast(&ipv4_proto),
        .dispatcher = dispatcher,
        .reassembly_list = std.AutoHashMap(ReassemblyKey, ReassemblyContext).init(allocator),
    };
    defer {
        ep_ipv4.reassembly_list.deinit();
        nic.stack.allocator.destroy(ep_ipv4);
    }

    const route = stack.Route{
        .local_address = .{ .v4 = .{ 10, 0, 0, 1 } },
        .remote_address = .{ .v4 = .{ 10, 0, 0, 2 } },
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };

    const payload = "hello world this is a fragmented packet";
    var frag1_buf = [_]u8{0} ** (header.IPv4MinimumSize + 16);
    var frag1_h = header.IPv4.init(&frag1_buf);
    frag1_h.data[0] = 0x45;
    std.mem.writeInt(u16, frag1_h.data[2..4][0..2], header.IPv4MinimumSize + 16, .big);
    std.mem.writeInt(u16, frag1_h.data[4..6][0..2], 12345, .big);
    std.mem.writeInt(u16, frag1_h.data[6..8][0..2], 0x2000, .big);
    frag1_h.data[8] = 64; // TTL
    frag1_h.data[9] = 17;
    @memcpy(frag1_h.data[12..16], &[_]u8{ 10, 0, 0, 2 });
    @memcpy(frag1_h.data[16..20], &[_]u8{ 10, 0, 0, 1 });
    @memcpy(frag1_buf[20..], payload[0..16]);
    frag1_h.setChecksum(frag1_h.calculateChecksum());

    const rem_len = payload.len - 16;
    var frag2_buf = try allocator.alloc(u8, header.IPv4MinimumSize + rem_len);
    defer allocator.free(frag2_buf);
    @memset(frag2_buf, 0);
    var frag2_h = header.IPv4.init(frag2_buf);
    frag2_h.data[0] = 0x45;
    std.mem.writeInt(u16, frag2_h.data[2..4][0..2], @as(u16, @intCast(header.IPv4MinimumSize + rem_len)), .big);
    std.mem.writeInt(u16, frag2_h.data[4..6][0..2], 12345, .big);
    std.mem.writeInt(u16, frag2_h.data[6..8][0..2], 0x0002, .big);
    frag2_h.data[8] = 64; // TTL
    frag2_h.data[9] = 17;
    @memcpy(frag2_h.data[12..16], &[_]u8{ 10, 0, 0, 2 });
    @memcpy(frag2_h.data[16..20], &[_]u8{ 10, 0, 0, 1 });
    @memcpy(frag2_buf[20..], payload[16..]);
    frag2_h.setChecksum(frag2_h.calculateChecksum());

    var views1 = [_]buffer.ClusterView{.{ .cluster = null, .view = &frag1_buf }};
    const pkt1 = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(frag1_buf.len, &views1),
        .header = undefined,
    };
    ep_ipv4.networkEndpoint().handlePacket(&route, pkt1);

    try std.testing.expect(!delivered);

    var views2 = [_]buffer.ClusterView{.{ .cluster = null, .view = frag2_buf }};
    const pkt2 = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(frag2_buf.len, &views2),
        .header = undefined,
    };
    ep_ipv4.networkEndpoint().handlePacket(&route, pkt2);

    try std.testing.expect(delivered);
    try std.testing.expectEqual(payload.len, delivered_len);
}

test "IPv4 options parsing" {
    // Test NOP option
    const nop_opts = [_]u8{OptionType.NOP};
    const nop_result = parseOptions(&nop_opts);
    try std.testing.expect(nop_result.valid);

    // Test end of options
    const end_opts = [_]u8{OptionType.END_OF_OPTIONS};
    const end_result = parseOptions(&end_opts);
    try std.testing.expect(end_result.valid);

    // Test invalid option (length too short)
    const invalid_opts = [_]u8{ OptionType.RECORD_ROUTE, 1 }; // len < 2 is invalid
    const invalid_result = parseOptions(&invalid_opts);
    try std.testing.expect(!invalid_result.valid);
}
