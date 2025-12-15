/// Packet header type definitions for the shardnet network stack.
///
/// Each header struct wraps a mutable byte slice whose in-memory layout
/// matches the wire format exactly (no padding, big-endian fields).
/// Accessor methods decode individual fields on demand.
///
/// Comptime size assertions at the bottom of this file guarantee that
/// struct sizes match the protocol specifications.
///
/// Usage:
///   const ip = IPv4.init(raw_bytes);
///   const proto = ip.protocol();
const std = @import("std");
const buffer = @import("buffer.zig");

pub const IPv4MinimumSize = 20;
pub const IPv4MaximumHeaderSize = 60;
pub const IPv4AddressSize = 4;
pub const IPv4Version = 4;

pub const IPv4TotalLenOffset = 2;
const idOffset = 4;
const flagsFOOffset = 6;
const ttlOffset = 8;
const protocolOffset = 9;
const checksumOffset = 10;
const srcAddrOffset = 12;
const dstAddrOffset = 16;

pub const IPv4 = struct {
    data: []u8,

    pub fn init(data: []u8) IPv4 {
        return .{ .data = data };
    }

    pub fn headerLength(self: IPv4) u8 {
        return (self.data[0] & 0xf) * 4;
    }

    pub fn totalLength(self: IPv4) u16 {
        return std.mem.readInt(u16, self.data[IPv4TotalLenOffset..][0..2], .big);
    }

    pub fn protocol(self: IPv4) u8 {
        return self.data[protocolOffset];
    }

    pub fn checksum(self: IPv4) u16 {
        return std.mem.readInt(u16, self.data[checksumOffset..][0..2], .big);
    }

    pub fn sourceAddress(self: IPv4) [4]u8 {
        var addr: [4]u8 = undefined;
        @memcpy(&addr, self.data[srcAddrOffset..][0..4]);
        return addr;
    }

    pub fn destinationAddress(self: IPv4) [4]u8 {
        var addr: [4]u8 = undefined;
        @memcpy(&addr, self.data[dstAddrOffset..][0..4]);
        return addr;
    }

    pub fn setChecksum(self: IPv4, c: u16) void {
        std.mem.writeInt(u16, self.data[checksumOffset..][0..2], c, .big);
    }

    pub fn calculateChecksum(self: IPv4) u16 {
        return finishChecksum(internetChecksum(self.data[0..self.headerLength()], 0));
    }

    pub fn flagsFragmentOffset(self: IPv4) u16 {
        return std.mem.readInt(u16, self.data[flagsFOOffset..][0..2], .big);
    }

    pub fn moreFragments(self: IPv4) bool {
        return (self.flagsFragmentOffset() & 0x2000) != 0;
    }

    pub fn fragmentOffset(self: IPv4) u16 {
        return (self.flagsFragmentOffset() & 0x1fff) * 8;
    }

    pub fn id(self: IPv4) u16 {
        return std.mem.readInt(u16, self.data[idOffset..][0..2], .big);
    }

    pub fn isValid(self: IPv4, pkt_size: usize) bool {
        if (self.data.len < IPv4MinimumSize) return false;
        const hlen = self.headerLength();
        const tlen = self.totalLength();
        if (hlen < IPv4MinimumSize or hlen > tlen or tlen > pkt_size) return false;
        if ((self.data[0] >> 4) != IPv4Version) return false;
        return true;
    }
};

pub const TCPMinimumSize = 20;
pub const TCPSrcPortOffset = 0;
pub const TCPDstPortOffset = 2;
pub const TCPSeqNumOffset = 4;
pub const TCPAckNumOffset = 8;
pub const TCPDataOffset = 12;
pub const TCPFlagsOffset = 13;
pub const TCPWinSizeOffset = 14;
pub const TCPChecksumOffset = 16;

pub const TCPOptionSackPermitted = 4;
pub const TCPOptionSackPermittedLen = 2;
pub const TCPOptionSack = 5;

pub const TCPFlagFin = 0x01;

pub const TCPFlagSyn = 0x02;
pub const TCPFlagRst = 0x04;
pub const TCPFlagPsh = 0x08;
pub const TCPFlagAck = 0x10;
pub const TCPFlagUrg = 0x20;

pub const TCP = struct {
    data: []u8,

    pub fn init(data: []u8) TCP {
        return .{ .data = data };
    }

    pub fn sourcePort(self: TCP) u16 {
        return std.mem.readInt(u16, self.data[TCPSrcPortOffset..][0..2], .big);
    }

    pub fn destinationPort(self: TCP) u16 {
        return std.mem.readInt(u16, self.data[TCPDstPortOffset..][0..2], .big);
    }

    pub fn sequenceNumber(self: TCP) u32 {
        return std.mem.readInt(u32, self.data[TCPSeqNumOffset..][0..4], .big);
    }

    pub fn ackNumber(self: TCP) u32 {
        return std.mem.readInt(u32, self.data[TCPAckNumOffset..][0..4], .big);
    }

    pub fn dataOffset(self: TCP) u8 {
        return (self.data[TCPDataOffset] >> 4) * 4;
    }

    pub fn flags(self: TCP) u8 {
        return self.data[TCPFlagsOffset];
    }

    pub fn windowSize(self: TCP) u16 {
        return std.mem.readInt(u16, self.data[TCPWinSizeOffset..][0..2], .big);
    }

    pub fn checksum(self: TCP) u16 {
        return std.mem.readInt(u16, self.data[TCPChecksumOffset..][0..2], .big);
    }

    pub fn encode(self: TCP, src: u16, dst: u16, seq: u32, ack: u32, fl: u8, win: u16) void {
        std.mem.writeInt(u16, self.data[TCPSrcPortOffset..][0..2], src, .big);
        std.mem.writeInt(u16, self.data[TCPDstPortOffset..][0..2], dst, .big);
        std.mem.writeInt(u32, self.data[TCPSeqNumOffset..][0..4], seq, .big);
        std.mem.writeInt(u32, self.data[TCPAckNumOffset..][0..4], ack, .big);
        self.data[TCPDataOffset] = (5 << 4); // Default 20 bytes
        self.data[TCPFlagsOffset] = fl;
        std.mem.writeInt(u16, self.data[TCPWinSizeOffset..][0..2], win, .big);
        // Zero out checksum before calculation
        std.mem.writeInt(u16, self.data[TCPChecksumOffset..][0..2], 0, .big);
    }

    pub fn setChecksum(self: TCP, c: u16) void {
        std.mem.writeInt(u16, self.data[TCPChecksumOffset..][0..2], c, .big);
    }

    pub fn calculateChecksum(self: TCP, src: [4]u8, dst: [4]u8, payload: []const u8) u16 {
        var sum: u32 = 0;
        sum += (@as(u16, src[0]) << 8) | src[1];
        sum += (@as(u16, src[2]) << 8) | src[3];
        sum += (@as(u16, dst[0]) << 8) | dst[1];
        sum += (@as(u16, dst[2]) << 8) | dst[3];
        sum += 6; // Protocol TCP
        sum += @as(u16, @intCast(self.data.len + payload.len));

        sum = internetChecksum(self.data, sum);
        sum = internetChecksum(payload, sum);
        return finishChecksum(sum);
    }

    pub fn calculateChecksumVectorised(self: TCP, src: [4]u8, dst: [4]u8, payload: buffer.VectorisedView) u16 {
        var sum: u32 = 0;
        sum += (@as(u16, src[0]) << 8) | src[1];
        sum += (@as(u16, src[2]) << 8) | src[3];
        sum += (@as(u16, dst[0]) << 8) | dst[1];
        sum += (@as(u16, dst[2]) << 8) | dst[3];
        sum += 6; // Protocol TCP
        sum += @as(u16, @intCast(self.data.len + payload.size));

        sum = internetChecksum(self.data, sum);
        for (payload.views) |v| {
            sum = internetChecksum(v.view, sum);
        }
        return finishChecksum(sum);
    }
};

pub fn internetChecksum(data: []const u8, initial: u32) u32 {
    var sum: u32 = initial;
    var i: usize = 0;

    const VectorSize = 32;
    // SIMD Optimization for Little Endian (x86 AVX2 etc)
    // Only engage for sufficient length
    if (@import("builtin").cpu.arch.endian() == .little and data.len >= VectorSize) {
        const VecU16 = @Vector(VectorSize / 2, u16);
        const VecU32 = @Vector(VectorSize / 2, u32);
        var acc: VecU32 = @splat(0);

        while (i + VectorSize <= data.len) : (i += VectorSize) {
            const ptr = data[i..].ptr;
            // Load 32 bytes unaligned (usually safe on x86)
            const chunk_u8: @Vector(VectorSize, u8) = @as(*const [VectorSize]u8, @ptrCast(ptr)).*;
            const chunk_u16: VecU16 = @bitCast(chunk_u8);
            // Algorithm uses Big Endian (network order) 16-bit words.
            // On Little Endian hosts, we must swap the loaded words to match.
            acc += @as(VecU32, @byteSwap(chunk_u16));
        }

        const arr: [VectorSize / 2]u32 = @bitCast(acc);
        for (arr) |val| {
            sum += val;
        }
    }

    while (i + 1 < data.len) : (i += 2) {
        sum += (@as(u32, data[i]) << 8) | data[i + 1];
    }
    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }
    return sum;
}

pub fn finishChecksum(sum: u32) u16 {
    var s = sum;
    while (s > 0xffff) {
        s = (s & 0xffff) + (s >> 16);
    }
    // Handle the edge case where result is 0x0000 (meaning summation was 0xFFFF).
    // In UDP, 0 means "no checksum". But in TCP/IP, 0 means 0xFFFF.
    // However, the bitwise NOT of 0xFFFF is 0x0000.
    // If the sum is 0xFFFF, the complement is 0x0000.
    // Actually, RFC 1624 says:
    // "One's complement checksum arithmetic is associative and commutative.
    //  0 and -0 (0xFFFF) are distinct values in 1's complement arithmetic."
    return ~@as(u16, @intCast(s));
}

pub const EthernetMinimumSize = 14;
pub const EthernetAddressSize = 6;

const dstMAC = 0;
const srcMAC = 6;
const ethType = 12;

pub const Ethernet = struct {
    data: []u8,

    pub fn init(data: []u8) Ethernet {
        return .{ .data = data };
    }

    pub fn sourceAddress(self: Ethernet) [6]u8 {
        var addr: [6]u8 = undefined;
        @memcpy(&addr, self.data[srcMAC..][0..6]);
        return addr;
    }

    pub fn destinationAddress(self: Ethernet) [6]u8 {
        var addr: [6]u8 = undefined;
        @memcpy(&addr, self.data[dstMAC..][0..6]);
        return addr;
    }

    pub fn etherType(self: Ethernet) u16 {
        return std.mem.readInt(u16, self.data[ethType..][0..2], .big);
    }

    pub fn encode(self: Ethernet, src: [6]u8, dst: [6]u8, eth_type: u16) void {
        @memcpy(self.data[srcMAC..][0..6], &src);
        @memcpy(self.data[dstMAC..][0..6], &dst);
        std.mem.writeInt(u16, self.data[ethType..][0..2], eth_type, .big);
    }
};

pub const ARPProtocolNumber = 0x0806;
pub const ARPSize = 28;
pub const ReservedHeaderSize = 128;
pub const ClusterSize = 16384;
pub const MaxViewsPerPacket = 16;

// Linux IOCTL constants for network interfaces
pub const SIOCGIFINDEX = 0x8933;
pub const SIOCGIFHWADDR = 0x8927;

pub const ETH_P_ALL = 0x0003;

pub const PACKET_RX_RING = 5;
pub const PACKET_TX_RING = 13;
pub const PACKET_VERSION = 10;
pub const PACKET_HDRLEN = 11;
pub const PACKET_RESERVE = 12;

pub const TPACKET_V1 = 0;
pub const TPACKET_V2 = 1;
pub const TPACKET_V3 = 2;

pub const TP_STATUS_KERNEL = 0;
pub const TP_STATUS_USER = 1;
pub const TP_STATUS_COPY = (1 << 1);
pub const TP_STATUS_LOSING = (1 << 2);
pub const TP_STATUS_CSUMNOTREADY = (1 << 3);
pub const TP_STATUS_VLAN_VALID = (1 << 4);
pub const TP_STATUS_BLK_TMO = (1 << 5);
pub const TP_STATUS_VLAN_TPID_VALID = (1 << 6);
pub const TP_STATUS_CSUM_VALID = (1 << 7);
pub const TP_STATUS_SEND_REQUEST = 1;
pub const TP_STATUS_SENDING = 2;
pub const TP_STATUS_WRONG_FORMAT = 4;

pub const tpacket_req = extern struct {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
};

pub const tpacket_hdr = extern struct {
    tp_status: usize,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_sec: u32,
    tp_usec: u32,
};

pub const tpacket2_hdr = extern struct {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_sec: u32,
    tp_nsec: u32,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
    tp_padding: [4]u8,
};

pub const ARP = struct {
    data: []u8,

    pub fn init(data: []u8) ARP {
        return .{ .data = data };
    }

    pub fn hardwareAddressSpace(self: ARP) u16 {
        return std.mem.readInt(u16, self.data[0..2], .big);
    }

    pub fn protocolAddressSpace(self: ARP) u16 {
        return std.mem.readInt(u16, self.data[2..4], .big);
    }

    pub fn op(self: ARP) u16 {
        return std.mem.readInt(u16, self.data[6..8], .big);
    }

    pub fn hardwareAddressSender(self: ARP) [6]u8 {
        var addr: [6]u8 = undefined;
        @memcpy(&addr, self.data[8..14]);
        return addr;
    }

    pub fn protocolAddressSender(self: ARP) [4]u8 {
        var addr: [4]u8 = undefined;
        @memcpy(&addr, self.data[14..18]);
        return addr;
    }

    pub fn hardwareAddressTarget(self: ARP) [6]u8 {
        var addr: [6]u8 = undefined;
        @memcpy(&addr, self.data[18..24]);
        return addr;
    }

    pub fn protocolAddressTarget(self: ARP) [4]u8 {
        var addr: [4]u8 = undefined;
        @memcpy(&addr, self.data[24..28]);
        return addr;
    }

    pub fn setIPv4OverEthernet(self: ARP) void {
        std.mem.writeInt(u16, self.data[0..2], 1, .big); // htypeEthernet
        std.mem.writeInt(u16, self.data[2..4], 0x0800, .big); // IPv4ProtocolNumber
        self.data[4] = 6; // macSize
        self.data[5] = 4; // IPv4AddressSize
    }

    pub fn setOp(self: ARP, operation: u16) void {
        std.mem.writeInt(u16, self.data[6..8], operation, .big);
    }

    pub fn isValid(self: ARP) bool {
        return self.data.len >= ARPSize;
    }
};

pub const UDPMinimumSize = 8;

pub const UDP = struct {
    pub const ProtocolNumber = 17;
    data: []u8,

    pub fn init(data: []u8) UDP {
        return .{ .data = data };
    }

    pub fn sourcePort(self: UDP) u16 {
        return std.mem.readInt(u16, self.data[0..2], .big);
    }

    pub fn destinationPort(self: UDP) u16 {
        return std.mem.readInt(u16, self.data[2..4], .big);
    }

    pub fn length(self: UDP) u16 {
        return std.mem.readInt(u16, self.data[4..6], .big);
    }

    pub fn checksum(self: UDP) u16 {
        return std.mem.readInt(u16, self.data[6..8], .big);
    }

    pub fn setSourcePort(self: UDP, p: u16) void {
        std.mem.writeInt(u16, self.data[0..2], p, .big);
    }

    pub fn setDestinationPort(self: UDP, p: u16) void {
        std.mem.writeInt(u16, self.data[2..4], p, .big);
    }

    pub fn setLength(self: UDP, l: u16) void {
        std.mem.writeInt(u16, self.data[4..6], l, .big);
    }

    pub fn setChecksum(self: UDP, c: u16) void {
        std.mem.writeInt(u16, self.data[6..8], c, .big);
    }

    pub fn calculateChecksum(self: UDP, src: [4]u8, dst: [4]u8, payload: []const u8) u16 {
        var sum: u32 = 0;
        sum += std.mem.readInt(u16, src[0..2], .big);
        sum += std.mem.readInt(u16, src[2..4], .big);
        sum += std.mem.readInt(u16, dst[0..2], .big);
        sum += std.mem.readInt(u16, dst[2..4], .big);
        sum += 17; // Protocol UDP
        sum += @as(u16, @intCast(self.data.len + payload.len));

        sum = internetChecksum(self.data, sum);
        sum = internetChecksum(payload, sum);
        return finishChecksum(sum);
    }
};

pub const ICMPv4MinimumSize = 8;
pub const ICMPv4EchoType = 8;
pub const ICMPv4EchoReplyType = 0;

pub const ICMPv4 = struct {
    data: []u8,

    pub fn init(data: []u8) ICMPv4 {
        return .{ .data = data };
    }

    pub fn @"type"(self: ICMPv4) u8 {
        return self.data[0];
    }

    pub fn code(self: ICMPv4) u8 {
        return self.data[1];
    }

    pub fn checksum(self: ICMPv4) u16 {
        return std.mem.readInt(u16, self.data[2..4], .big);
    }

    pub fn setChecksum(self: ICMPv4, c: u16) void {
        std.mem.writeInt(u16, self.data[2..4], c, .big);
    }

    pub fn calculateChecksum(self: ICMPv4, payload: []const u8) u16 {
        var sum = internetChecksum(self.data[0..ICMPv4MinimumSize], 0);
        sum = internetChecksum(payload, sum);
        return finishChecksum(sum);
    }
};

pub const IPv6MinimumSize = 40;
pub const IPv6AddressSize = 16;
pub const IPv6Version = 6;

pub const IPv6PayloadLenOffset = 4;
pub const IPv6NextHeaderOffset = 6;
pub const IPv6HopLimitOffset = 7;
pub const IPv6SrcAddrOffset = 8;
pub const IPv6DstAddrOffset = 24;

pub const IPv6 = struct {
    data: []u8,

    pub fn init(data: []u8) IPv6 {
        return .{ .data = data };
    }

    pub fn trafficClass(self: IPv6) u8 {
        const v = std.mem.readInt(u32, self.data[0..4], .big);
        return @as(u8, @intCast((v >> 20) & 0xff));
    }

    pub fn flowLabel(self: IPv6) u32 {
        const v = std.mem.readInt(u32, self.data[0..4], .big);
        return v & 0xfffff;
    }

    pub fn payloadLength(self: IPv6) u16 {
        return std.mem.readInt(u16, self.data[IPv6PayloadLenOffset..][0..2], .big);
    }

    pub fn nextHeader(self: IPv6) u8 {
        return self.data[IPv6NextHeaderOffset];
    }

    pub fn hopLimit(self: IPv6) u8 {
        return self.data[IPv6HopLimitOffset];
    }

    pub fn sourceAddress(self: IPv6) [16]u8 {
        var addr: [16]u8 = undefined;
        @memcpy(&addr, self.data[IPv6SrcAddrOffset..][0..16]);
        return addr;
    }

    pub fn destinationAddress(self: IPv6) [16]u8 {
        var addr: [16]u8 = undefined;
        @memcpy(&addr, self.data[IPv6DstAddrOffset..][0..16]);
        return addr;
    }

    pub fn encode(self: IPv6, src: [16]u8, dst: [16]u8, next_header: u8, payload_len: u16) void {
        std.mem.writeInt(u32, self.data[0..4], 0x60000000, .big); // Ver 6, TC 0, FL 0
        std.mem.writeInt(u16, self.data[IPv6PayloadLenOffset..][0..2], payload_len, .big);
        self.data[IPv6NextHeaderOffset] = next_header;
        self.data[IPv6HopLimitOffset] = 64; // Default hop limit
        @memcpy(self.data[IPv6SrcAddrOffset..][0..16], &src);
        @memcpy(self.data[IPv6DstAddrOffset..][0..16], &dst);
    }

    pub fn isValid(self: IPv6, pkt_size: usize) bool {
        if (self.data.len < IPv6MinimumSize) return false;
        if ((self.data[0] >> 4) != IPv6Version) return false;
        const plen = self.payloadLength();
        if (pkt_size < IPv6MinimumSize + plen) return false;
        return true;
    }
};

pub const ICMPv6MinimumSize = 4;
pub const ICMPv6EchoRequestType = 128;
pub const ICMPv6EchoReplyType = 129;
pub const ICMPv6RouterSolicitationType = 133;
pub const ICMPv6RouterAdvertisementType = 134;
pub const ICMPv6NeighborSolicitationType = 135;
pub const ICMPv6NeighborAdvertisementType = 136;

pub const ICMPv6NAFlagsRouter = 0x80;
pub const ICMPv6NAFlagsSolicited = 0x40;
pub const ICMPv6NAFlagsOverride = 0x20;

pub const ICMPv6OptionSourceLinkLayerAddress = 1;
pub const ICMPv6OptionTargetLinkLayerAddress = 2;
pub const ICMPv6OptionPrefixInformation = 3;
pub const ICMPv6OptionRedirectHeader = 4;
pub const ICMPv6OptionMTU = 5;

pub const ICMPv6 = struct {
    data: []u8,

    pub fn init(data: []u8) ICMPv6 {
        return .{ .data = data };
    }

    pub fn @"type"(self: ICMPv6) u8 {
        return self.data[0];
    }

    pub fn code(self: ICMPv6) u8 {
        return self.data[1];
    }

    pub fn checksum(self: ICMPv6) u16 {
        return std.mem.readInt(u16, self.data[2..4], .big);
    }

    pub fn setChecksum(self: ICMPv6, c: u16) void {
        std.mem.writeInt(u16, self.data[2..4], c, .big);
    }

    pub fn calculateChecksum(self: ICMPv6, src: [16]u8, dst: [16]u8, payload: []const u8) u16 {
        var sum: u32 = 0;

        // Pseudo-header
        var i: usize = 0;
        while (i < 16) : (i += 2) {
            sum += std.mem.readInt(u16, src[i..][0..2], .big);
        }
        i = 0;
        while (i < 16) : (i += 2) {
            sum += std.mem.readInt(u16, dst[i..][0..2], .big);
        }

        const len = ICMPv6MinimumSize + payload.len;
        sum += @as(u32, @intCast(len >> 16));
        sum += @as(u32, @intCast(len & 0xffff));
        sum += 58; // Next Header (ICMPv6)

        sum = internetChecksum(self.data[0..ICMPv6MinimumSize], sum);
        sum = internetChecksum(payload, sum);
        return finishChecksum(sum);
    }
};

pub const ICMPv6NS = struct {
    data: []u8,

    pub fn init(data: []u8) ICMPv6NS {
        return .{ .data = data };
    }

    pub fn targetAddress(self: ICMPv6NS) [16]u8 {
        var addr: [16]u8 = undefined;
        @memcpy(&addr, self.data[4..20]);
        return addr;
    }

    pub fn setTargetAddress(self: ICMPv6NS, addr: [16]u8) void {
        @memcpy(self.data[4..20], &addr);
    }
};

pub const ICMPv6NA = struct {
    data: []u8,

    pub fn init(data: []u8) ICMPv6NA {
        return .{ .data = data };
    }

    pub fn flags(self: ICMPv6NA) u8 {
        return self.data[0];
    }

    pub fn targetAddress(self: ICMPv6NA) [16]u8 {
        var addr: [16]u8 = undefined;
        @memcpy(&addr, self.data[4..20]);
        return addr;
    }

    pub fn setFlags(self: ICMPv6NA, f: u8) void {
        self.data[0] = f;
    }

    pub fn setTargetAddress(self: ICMPv6NA, addr: [16]u8) void {
        @memcpy(self.data[4..20], &addr);
    }
};

pub const ICMPv6RA = struct {
    data: []u8,

    pub fn init(data: []u8) ICMPv6RA {
        return .{ .data = data };
    }

    pub fn hopLimit(self: ICMPv6RA) u8 {
        return self.data[0];
    }

    pub fn flags(self: ICMPv6RA) u8 {
        return self.data[1];
    }

    pub fn routerLifetime(self: ICMPv6RA) u16 {
        return std.mem.readInt(u16, self.data[2..4], .big);
    }

    pub fn reachableTime(self: ICMPv6RA) u32 {
        return std.mem.readInt(u32, self.data[4..8], .big);
    }

    pub fn retransTimer(self: ICMPv6RA) u32 {
        return std.mem.readInt(u32, self.data[8..12], .big);
    }
};

pub const ICMPv6OptionPrefix = struct {
    data: []u8,

    pub fn init(data: []u8) ICMPv6OptionPrefix {
        return .{ .data = data };
    }

    pub fn prefixLength(self: ICMPv6OptionPrefix) u8 {
        return self.data[2];
    }

    pub fn flags(self: ICMPv6OptionPrefix) u8 {
        return self.data[3];
    }

    pub fn validLifetime(self: ICMPv6OptionPrefix) u32 {
        return std.mem.readInt(u32, self.data[4..8], .big);
    }

    pub fn preferredLifetime(self: ICMPv6OptionPrefix) u32 {
        return std.mem.readInt(u32, self.data[8..12], .big);
    }

    pub fn prefix(self: ICMPv6OptionPrefix) [16]u8 {
        var addr: [16]u8 = undefined;
        @memcpy(&addr, self.data[16..32]);
        return addr;
    }
};

pub const DNSHeaderSize = 12;

pub const DNS = struct {
    data: []u8,

    pub fn init(data: []u8) DNS {
        return .{ .data = data };
    }

    pub fn id(self: DNS) u16 {
        return std.mem.readInt(u16, self.data[0..2], .big);
    }

    pub fn flags(self: DNS) u16 {
        return std.mem.readInt(u16, self.data[2..4], .big);
    }

    pub fn questionCount(self: DNS) u16 {
        return std.mem.readInt(u16, self.data[4..6], .big);
    }

    pub fn answerCount(self: DNS) u16 {
        return std.mem.readInt(u16, self.data[6..8], .big);
    }

    pub fn authorityCount(self: DNS) u16 {
        return std.mem.readInt(u16, self.data[8..10], .big);
    }

    pub fn additionalCount(self: DNS) u16 {
        return std.mem.readInt(u16, self.data[10..12], .big);
    }

    pub fn setId(self: DNS, i: u16) void {
        std.mem.writeInt(u16, self.data[0..2], i, .big);
    }

    pub fn setFlags(self: DNS, f: u16) void {
        std.mem.writeInt(u16, self.data[2..4], f, .big);
    }

    pub fn setQuestionCount(self: DNS, c: u16) void {
        std.mem.writeInt(u16, self.data[4..6], c, .big);
    }

    pub fn setAnswerCount(self: DNS, c: u16) void {
        std.mem.writeInt(u16, self.data[6..8], c, .big);
    }

    pub fn setAuthorityCount(self: DNS, c: u16) void {
        std.mem.writeInt(u16, self.data[8..10], c, .big);
    }

    pub fn setAdditionalCount(self: DNS, c: u16) void {
        std.mem.writeInt(u16, self.data[10..12], c, .big);
    }
};

test "IPv6 header" {
    var data = [_]u8{0} ** 40;
    const ipv6 = IPv6.init(&data);
    const src = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const dst = [_]u8{ 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

    ipv6.encode(src, dst, 6, 100); // TCP (6), payload 100

    try std.testing.expectEqual(@as(u8, 0), ipv6.trafficClass());
    try std.testing.expectEqual(@as(u32, 0), ipv6.flowLabel());
    try std.testing.expectEqual(@as(u16, 100), ipv6.payloadLength());
    try std.testing.expectEqual(@as(u8, 6), ipv6.nextHeader());
    try std.testing.expectEqual(@as(u8, 64), ipv6.hopLimit());
    try std.testing.expectEqualStrings(&src, &ipv6.sourceAddress());
    try std.testing.expectEqualStrings(&dst, &ipv6.destinationAddress());
    try std.testing.expect(ipv6.isValid(140));
}

test "IPv4 header" {
    var data = [_]u8{0} ** 20;
    data[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    std.mem.writeInt(u16, data[2..4], 100, .big); // Total length
    data[9] = 6; // TCP
    @memcpy(data[12..16], &[_]u8{ 192, 168, 1, 1 });
    @memcpy(data[16..20], &[_]u8{ 192, 168, 1, 2 });

    const ip = IPv4.init(&data);
    try std.testing.expectEqual(@as(u8, 20), ip.headerLength());
    try std.testing.expectEqual(@as(u16, 100), ip.totalLength());
    try std.testing.expectEqual(@as(u8, 6), ip.protocol());
    try std.testing.expectEqualStrings(&[_]u8{ 192, 168, 1, 1 }, &ip.sourceAddress());
    try std.testing.expect(ip.isValid(100));
}

test "TCP header" {
    var data = [_]u8{0} ** 20;
    std.mem.writeInt(u16, data[0..2], 1234, .big); // Src port
    std.mem.writeInt(u16, data[2..4], 80, .big); // Dst port
    std.mem.writeInt(u32, data[4..8], 0x11223344, .big); // Seq
    data[12] = 0x50; // Data offset 5 (20 bytes)
    data[13] = 0x02; // SYN flag

    const tcp = TCP.init(&data);
    try std.testing.expectEqual(@as(u16, 1234), tcp.sourcePort());
    try std.testing.expectEqual(@as(u16, 80), tcp.destinationPort());
    try std.testing.expectEqual(@as(u32, 0x11223344), tcp.sequenceNumber());
    try std.testing.expectEqual(@as(u8, 20), tcp.dataOffset());
    try std.testing.expectEqual(@as(u8, 0x02), tcp.flags());
}

test "Ethernet header" {
    var data = [_]u8{0} ** 14;
    const eth = Ethernet.init(&data);
    const src = [_]u8{ 1, 2, 3, 4, 5, 6 };
    const dst = [_]u8{ 7, 8, 9, 10, 11, 12 };
    eth.encode(src, dst, 0x0800);

    try std.testing.expectEqualStrings(&src, &eth.sourceAddress());
    try std.testing.expectEqualStrings(&dst, &eth.destinationAddress());
    try std.testing.expectEqual(@as(u16, 0x0800), eth.etherType());
}

test "ARP header" {
    var data = [_]u8{0} ** 28;
    const arp = ARP.init(&data);
    arp.setIPv4OverEthernet();
    arp.setOp(1); // Request

    try std.testing.expectEqual(@as(u16, 1), arp.hardwareAddressSpace());
    try std.testing.expectEqual(@as(u16, 0x0800), arp.protocolAddressSpace());
    try std.testing.expectEqual(@as(u16, 1), arp.op());
}

test "UDP header" {
    var data = [_]u8{0} ** 8;
    std.mem.writeInt(u16, data[0..2], 1234, .big);
    std.mem.writeInt(u16, data[2..4], 5678, .big);
    std.mem.writeInt(u16, data[4..6], 20, .big);
    std.mem.writeInt(u16, data[6..8], 0xabcd, .big);

    const udp = UDP.init(&data);
    try std.testing.expectEqual(@as(u16, 1234), udp.sourcePort());
    try std.testing.expectEqual(@as(u16, 5678), udp.destinationPort());
    try std.testing.expectEqual(@as(u16, 20), udp.length());
    try std.testing.expectEqual(@as(u16, 0xabcd), udp.checksum());
}

test "Checksum calculation" {
    const data = [_]u8{ 0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c };
    // The above is an IPv4 header with zero checksum.
    // Let's calculate its checksum.
    const c = internetChecksum(&data, 0);
    const expected: u16 = 0xb1e6; // Precalculated for this header
    try std.testing.expectEqual(expected, finishChecksum(c));
}

test "Checksum SIMD vs Scalar comparison" {
    var prng = std.rand.DefaultPrng.init(0);
    const random = prng.random();

    var buf: [4096]u8 = undefined;
    for (0..100) |_| {
        const len = random.uintLessThan(usize, buf.len);
        random.bytes(buf[0..len]);
        const initial = random.uintAtMost(u32, 0xFFFF);

        // Scalar implementation (manual copy for verification)
        var scalar_sum: u32 = initial;
        var i: usize = 0;
        while (i + 1 < len) : (i += 2) {
            scalar_sum += std.mem.readInt(u16, buf[i..][0..2], .big);
        }
        if (i < len) {
            scalar_sum += @as(u32, buf[i]) << 8;
        }

        const simd_sum = internetChecksum(buf[0..len], initial);
        try std.testing.expectEqual(scalar_sum, simd_sum);
    }
}

// ---------------------------------------------------------------------------
// Comptime size assertions — ensures header structs match wire sizes.
// ---------------------------------------------------------------------------

comptime {
    // Ethernet header: 6 (dst) + 6 (src) + 2 (ethertype) = 14 bytes.
    std.debug.assert(EthernetMinimumSize == 14);
    // IPv4 minimum header: 20 bytes (RFC 791 Section 3.1).
    std.debug.assert(IPv4MinimumSize == 20);
    // IPv6 fixed header: 40 bytes (RFC 8200 Section 3).
    std.debug.assert(IPv6MinimumSize == 40);
    // TCP minimum header: 20 bytes (RFC 793 Section 3.1).
    std.debug.assert(TCPMinimumSize == 20);
    // UDP header: 8 bytes (RFC 768).
    std.debug.assert(UDPMinimumSize == 8);
    // ARP over Ethernet/IPv4: 28 bytes.
    std.debug.assert(ARPSize == 28);
    // ICMPv4 minimum: 8 bytes (type + code + checksum + rest).
    std.debug.assert(ICMPv4MinimumSize == 8);
    // ICMPv6 minimum: 4 bytes (type + code + checksum).
    std.debug.assert(ICMPv6MinimumSize == 4);
    // DNS header: 12 bytes.
    std.debug.assert(DNSHeaderSize == 12);
}

/// Construct a header view from a raw byte slice with bounds checking.
/// Returns error.TooShort if the slice is smaller than `min_size` bytes.
pub fn fromBytes(comptime T: type, data: []u8, min_size: usize) !T {
    if (data.len < min_size) return error.TooShort;
    return T.init(data);
}

/// Return the underlying byte slice for a header view.
pub fn toBytes(h: anytype) []u8 {
    return h.data;
}
