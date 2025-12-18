/// Ethernet frame parsing and serialization for shardnet.
///
/// Handles Layer 2 Ethernet frames including 802.1Q VLAN tagging,
/// multicast/broadcast detection, and jumbo frame validation.

const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const stats = @import("../stats.zig");

/// Maximum payload size for standard Ethernet frames (MTU).
pub const ETHERNET_MTU = 1500;

/// Maximum payload size for jumbo frames.
pub const JUMBO_MTU = 9000;

/// 802.1Q VLAN tag EtherType.
pub const ETHERTYPE_VLAN = 0x8100;

/// 802.1Q double-tag (QinQ) EtherType.
pub const ETHERTYPE_QINQ = 0x88A8;

pub const Error = error{
    /// Frame payload exceeds jumbo frame limit (9000 bytes).
    Jumbo,
    /// Frame is too short to contain valid Ethernet header.
    FrameTooShort,
    /// Invalid VLAN tag format.
    InvalidVlanTag,
};

/// Parsed 802.1Q VLAN tag information.
pub const VlanTag = struct {
    /// Priority Code Point (3 bits, 0-7).
    pcp: u3,
    /// Drop Eligible Indicator (1 bit).
    dei: bool,
    /// VLAN Identifier (12 bits, 0-4095).
    vid: u12,
    /// Inner EtherType (the actual protocol after the VLAN tag).
    inner_ethertype: u16,
};

/// Check if a MAC address is a multicast address.
/// Multicast addresses have the least significant bit of the first octet set.
pub fn is_multicast(mac: [6]u8) bool {
    return (mac[0] & 0x01) != 0;
}

/// Check if a MAC address is the broadcast address (ff:ff:ff:ff:ff:ff).
pub fn is_broadcast(mac: [6]u8) bool {
    return mac[0] == 0xff and mac[1] == 0xff and mac[2] == 0xff and
        mac[3] == 0xff and mac[4] == 0xff and mac[5] == 0xff;
}

/// Parse an 802.1Q VLAN tag from raw bytes.
/// Returns null if the EtherType is not 0x8100 or 0x88A8.
pub fn parse_vlan_tag(frame: []const u8) ?VlanTag {
    if (frame.len < 18) return null; // 14 (eth) + 4 (vlan)

    const ethertype = std.mem.readInt(u16, frame[12..14], .big);
    if (ethertype != ETHERTYPE_VLAN and ethertype != ETHERTYPE_QINQ) {
        return null;
    }

    const tci = std.mem.readInt(u16, frame[14..16], .big);
    const inner_ethertype = std.mem.readInt(u16, frame[16..18], .big);

    return VlanTag{
        .pcp = @intCast((tci >> 13) & 0x07),
        .dei = ((tci >> 12) & 0x01) != 0,
        .vid = @intCast(tci & 0x0FFF),
        .inner_ethertype = inner_ethertype,
    };
}

/// Validate frame payload size against jumbo frame limit.
/// Returns error.Jumbo if payload exceeds 9000 bytes.
pub fn validate_frame_size(payload_len: usize) Error!void {
    if (payload_len > JUMBO_MTU) {
        return Error.Jumbo;
    }
}

/// Iterator over successive Ethernet frames in a raw byte buffer.
/// Each iteration yields a slice containing one complete frame.
pub const FrameIterator = struct {
    data: []const u8,
    offset: usize,

    /// Create an iterator over frames in the given buffer.
    pub fn init(data: []const u8) FrameIterator {
        return .{
            .data = data,
            .offset = 0,
        };
    }

    /// Return the next frame, or null if no more frames.
    /// Each frame is returned as a slice; the caller must parse it.
    pub fn next(self: *FrameIterator) ?[]const u8 {
        if (self.offset >= self.data.len) return null;

        // Need at least Ethernet header
        if (self.data.len - self.offset < header.EthernetMinimumSize) return null;

        const remaining = self.data[self.offset..];

        // Check for VLAN tag to determine header size
        const ethertype = std.mem.readInt(u16, remaining[12..14], .big);
        const header_size: usize = if (ethertype == ETHERTYPE_VLAN or ethertype == ETHERTYPE_QINQ)
            18 // 14 + 4 byte VLAN tag
        else
            14;

        if (remaining.len < header_size) return null;

        // For this iterator, we assume each "frame" in the buffer is
        // back-to-back with no length prefix. The caller provides
        // frames captured via AF_PACKET which include length info
        // externally. Return the entire remaining buffer as one frame.
        const frame = remaining;
        self.offset = self.data.len;
        return frame;
    }

    /// Reset the iterator to the beginning.
    pub fn reset(self: *FrameIterator) void {
        self.offset = 0;
    }
};

pub const EthernetEndpoint = struct {
    lower: stack.LinkEndpoint,
    addr: tcpip.LinkAddress,
    dispatcher: ?*stack.NetworkDispatcher = null,
    wrapped_dispatcher: stack.NetworkDispatcher = undefined,

    /// Create a new Ethernet endpoint wrapping a lower-level link endpoint.
    pub fn init(lower: stack.LinkEndpoint, addr: tcpip.LinkAddress) EthernetEndpoint {
        return .{
            .lower = lower,
            .addr = addr,
        };
    }

    /// Return the LinkEndpoint interface for this Ethernet endpoint.
    pub fn linkEndpoint(self: *EthernetEndpoint) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = stack.LinkEndpoint.VTable{
        .writePacket = writePacket,
        .writePackets = writePackets,
        .attach = attach,
        .linkAddress = linkAddress,
        .mtu = mtu,
        .setMTU = setMTU,
        .capabilities = capabilities,
    };

    fn writePackets(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));

        const dst = if (r) |route| (if (route.remote_link_address) |la| la.addr else [_]u8{0xff} ** 6) else [_]u8{0xff} ** 6;
        const src = if (r) |route| route.local_link_address.addr else self.addr.addr;

        var batch_buf: [32]tcpip.PacketBuffer = undefined;
        var i: usize = 0;
        while (i < packets.len) {
            const count = @min(packets.len - i, batch_buf.len);
            for (0..count) |j| {
                var mut_pkt = packets[i + j];

                // Validate payload size
                const payload_len = mut_pkt.header.usedLength() + mut_pkt.data.size;
                if (payload_len > JUMBO_MTU) {
                    return tcpip.Error.MessageTooLong;
                }

                const eth_header = mut_pkt.header.prepend(header.EthernetMinimumSize) orelse return tcpip.Error.NoBufferSpace;
                var eth = header.Ethernet.init(eth_header);
                eth.encode(src, dst, protocol);
                batch_buf[j] = mut_pkt;
            }
            try self.lower.writePackets(r, protocol, batch_buf[0..count]);
            i += count;
        }
    }

    fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        var mut_pkt = pkt;

        // Validate payload size
        const payload_len = mut_pkt.header.usedLength() + mut_pkt.data.size;
        if (payload_len > JUMBO_MTU) {
            return tcpip.Error.MessageTooLong;
        }

        const eth_header = mut_pkt.header.prepend(header.EthernetMinimumSize) orelse return tcpip.Error.NoBufferSpace;
        var eth = header.Ethernet.init(eth_header);

        const dst = if (r) |route| (if (route.remote_link_address) |la| la.addr else [_]u8{0xff} ** 6) else [_]u8{0xff} ** 6;
        const src = if (r) |route| route.local_link_address.addr else self.addr.addr;

        eth.encode(src, dst, protocol);

        return self.lower.writePacket(r, protocol, mut_pkt);
    }

    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        self.dispatcher = dispatcher;
        self.wrapped_dispatcher = .{
            .ptr = self,
            .vtable = &.{
                .deliverNetworkPacket = deliverNetworkPacket,
            },
        };
        self.lower.attach(&self.wrapped_dispatcher);
    }

    fn deliverNetworkPacket(ptr: *anyopaque, remote: *const tcpip.LinkAddress, local: *const tcpip.LinkAddress, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) void {
        const start = std.time.nanoTimestamp();
        defer {
            const end = std.time.nanoTimestamp();
            stats.global_stats.latency.link_layer.record(@as(i64, @intCast(end - start)));
        }
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        _ = remote;
        _ = local;
        _ = protocol;
        var mut_pkt = pkt;
        const v = mut_pkt.data.first() orelse return;
        if (v.len < header.EthernetMinimumSize) return;

        const eth = header.Ethernet.init(v);
        var p = eth.etherType();

        // Handle 802.1Q VLAN tagged frames
        if (p == ETHERTYPE_VLAN or p == ETHERTYPE_QINQ) {
            if (v.len < 18) return; // Need VLAN tag
            p = std.mem.readInt(u16, v[16..18], .big);
            mut_pkt.link_header = v[0..18];
            mut_pkt.data.trimFront(18);
        } else {
            mut_pkt.link_header = v[0..header.EthernetMinimumSize];
            mut_pkt.data.trimFront(header.EthernetMinimumSize);
        }

        if (self.dispatcher) |d| {
            const src = tcpip.LinkAddress{ .addr = eth.sourceAddress() };
            const dst = tcpip.LinkAddress{ .addr = eth.destinationAddress() };
            d.deliverNetworkPacket(&src, &dst, p, mut_pkt);
        }
    }

    fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        return self.addr;
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        return self.lower.mtu() - header.EthernetMinimumSize;
    }

    fn setMTU(ptr: *anyopaque, m: u32) void {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        self.lower.setMTU(m + header.EthernetMinimumSize);
    }

    fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
        const self = @as(*EthernetEndpoint, @ptrCast(@alignCast(ptr)));
        return self.lower.capabilities();
    }
};
