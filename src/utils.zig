/// RFC 1071 checksum, alignment helpers, ring index, and formatting utilities.
const std = @import("std");
const tcpip = @import("tcpip.zig");

// RFC 1071 Internet Checksum

/// RFC 1071 ones-complement checksum. Returns big-endian result.
// PERF: Uses 32-bit word accumulation with single carry-fold at end.
pub fn checksum(data: []const u8) u16 {
    var sum: u64 = 0;
    var i: usize = 0;

    // Accumulate 32-bit words for better throughput.
    while (i + 3 < data.len) : (i += 4) {
        const word: u32 = @as(u32, data[i]) << 24 |
            @as(u32, data[i + 1]) << 16 |
            @as(u32, data[i + 2]) << 8 |
            @as(u32, data[i + 3]);
        sum += word;
    }

    // Handle remaining 16-bit word.
    if (i + 1 < data.len) {
        const word: u16 = @as(u16, data[i]) << 8 | @as(u16, data[i + 1]);
        sum += word;
        i += 2;
    }

    // Handle trailing odd byte.
    if (i < data.len) {
        sum += @as(u64, data[i]) << 8;
    }

    // Single fold: reduce 64-bit to 16-bit.
    sum = (sum >> 32) + (sum & 0xFFFFFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);

    return @intCast(~sum & 0xFFFF);
}

// Alignment helpers

/// Round up to next multiple of alignment (must be power of two).
pub fn align_up(value: usize, alignment: usize) usize {
    std.debug.assert(alignment > 0 and (alignment & (alignment - 1)) == 0);
    return (value + alignment - 1) & ~(alignment - 1);
}

/// Round down to previous multiple of alignment (must be power of two).
pub fn align_down(value: usize, alignment: usize) usize {
    std.debug.assert(alignment > 0 and (alignment & (alignment - 1)) == 0);
    return value & ~(alignment - 1);
}

// RingIndex — power-of-two modular index

/// Modular index with bitmask wrap-around (cheaper than modulo).
pub fn RingIndex(comptime capacity: u32) type {
    comptime std.debug.assert(capacity > 0 and (capacity & (capacity - 1)) == 0);

    return struct {
        const Self = @This();
        const mask: u32 = capacity - 1;

        value: u32 = 0,

        /// Advance the index by `n` positions, wrapping at capacity.
        pub fn advance(self: *Self, n: u32) void {
            self.value = (self.value +% n) & mask;
        }

        /// Return the current index and advance by one.
        pub fn next(self: *Self) u32 {
            const cur = self.value;
            self.value = (self.value +% 1) & mask;
            return cur;
        }

        /// Return the raw index value.
        pub fn get(self: Self) u32 {
            return self.value;
        }

        /// Number of entries between `self` and `other` (forward distance).
        pub fn distance(self: Self, other: Self) u32 {
            return (other.value -% self.value) & mask;
        }
    };
}

// Formatting helpers

/// Format MAC address as "aa:bb:cc:dd:ee:ff".
pub fn mac_to_string(mac: [6]u8, buf: *[17]u8) []const u8 {
    const hex = "0123456789abcdef";
    var i: usize = 0;
    for (mac, 0..) |byte, idx| {
        buf[i] = hex[byte >> 4];
        buf[i + 1] = hex[byte & 0x0F];
        i += 2;
        if (idx < 5) {
            buf[i] = ':';
            i += 1;
        }
    }
    return buf[0..17];
}

/// Format IPv4 address as "a.b.c.d".
pub fn ip4_to_string(addr: [4]u8, buf: *[15]u8) []const u8 {
    var stream = std.io.fixedBufferStream(buf);
    const writer = stream.writer();
    writer.print("{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] }) catch unreachable;
    return stream.getWritten();
}

// IP address parsing

/// Parse IPv4 or IPv6 address string.
pub fn parseIp(str: []const u8) !tcpip.Address {
    if (std.mem.indexOf(u8, str, ":") != null) {
        var out: [16]u8 = undefined;
        const addr = try std.net.Ip6Address.parse(str, 0);
        @memcpy(&out, &addr.sa.addr);
        return tcpip.Address{ .v6 = out };
    } else {
        var it = std.mem.splitScalar(u8, str, '.');
        var out: [4]u8 = undefined;
        for (0..4) |i| {
            const part = it.next() orelse return error.InvalidIP;
            out[i] = try std.fmt.parseInt(u8, part, 10);
        }
        return tcpip.Address{ .v4 = out };
    }
}

/// CIDR notation (address/prefix_len).
pub const Cidr = struct {
    address: tcpip.Address,
    prefix_len: u8,
};

/// Parse "10.0.0.1/24" or "fe80::1/64" into a Cidr struct.
pub fn parseCidr(str: []const u8) !Cidr {
    var it = std.mem.splitScalar(u8, str, '/');
    const ip_part = it.first();
    const prefix_part = it.next();

    const address = try parseIp(ip_part);
    const prefix_len = if (prefix_part) |p| try std.fmt.parseInt(u8, p, 10) else switch (address) {
        .v4 => 32,
        .v6 => 128,
    };

    return Cidr{
        .address = address,
        .prefix_len = prefix_len,
    };
}

// Tests

test "checksum: RFC 1071 Section 3 test vector" {
    // Example from RFC 1071: 0x0001 + 0xf203 + ... = expected result.
    const data = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    const result = checksum(&data);
    // The ones-complement sum of the four words is 0xddf2; ~0xddf2 = 0x220d.
    try std.testing.expectEqual(@as(u16, 0x220d), result);
}

test "align_up / align_down" {
    try std.testing.expectEqual(@as(usize, 0), align_up(0, 4));
    try std.testing.expectEqual(@as(usize, 4), align_up(1, 4));
    try std.testing.expectEqual(@as(usize, 4), align_up(4, 4));
    try std.testing.expectEqual(@as(usize, 8), align_up(5, 4));

    try std.testing.expectEqual(@as(usize, 0), align_down(3, 4));
    try std.testing.expectEqual(@as(usize, 4), align_down(4, 4));
    try std.testing.expectEqual(@as(usize, 4), align_down(7, 4));
}

test "RingIndex wraps at capacity" {
    var idx = RingIndex(8){};
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        _ = idx.next();
    }
    // After 10 advances in a ring of 8, index should be 10 % 8 = 2.
    try std.testing.expectEqual(@as(u32, 2), idx.get());
}

test "mac_to_string" {
    var buf: [17]u8 = undefined;
    const mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33 };
    const result = mac_to_string(mac, &buf);
    try std.testing.expectEqualStrings("aa:bb:cc:11:22:33", result);
}

test "ip4_to_string" {
    var buf: [15]u8 = undefined;
    const result = ip4_to_string(.{ 192, 168, 1, 1 }, &buf);
    try std.testing.expectEqualStrings("192.168.1.1", result);
}
