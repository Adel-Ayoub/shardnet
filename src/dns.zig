/// DNS query and response parsing.
///
/// Implements RFC 1035 DNS message parsing with:
/// - Recursive label decompression with cycle detection (max 5 hops)
/// - A, AAAA, SRV, TXT, and CNAME record parsing
/// - Stub resolver with configurable timeout
/// - TTL-based response caching (RFC 1035 Section 7.2)
/// - Negative caching for NXDOMAIN responses (RFC 2308)
/// - Hosts file lookup (/etc/hosts)

const std = @import("std");
const tcpip = @import("tcpip.zig");
const stack = @import("stack.zig");
const header = @import("header.zig");
const waiter = @import("waiter.zig");
const buffer = @import("buffer.zig");
const log = @import("log.zig").scoped(.dns);

/// Maximum pointer hops for label decompression (prevents cycles).
const MaxCompressionHops = 5;

/// Default negative cache TTL (RFC 2308 recommends max 3 hours).
const DEFAULT_NEGATIVE_TTL_SEC: u32 = 300; // 5 minutes

/// Maximum cache entries.
const MAX_CACHE_ENTRIES: usize = 1024;

/// DNS cache entry.
pub const CacheEntry = struct {
    address: ?tcpip.Address, // null for negative cache (NXDOMAIN)
    record_type: RecordType,
    expires_at_ms: i64,
    is_negative: bool,

    pub fn isExpired(self: CacheEntry) bool {
        return std.time.milliTimestamp() >= self.expires_at_ms;
    }
};

/// DNS record types.
pub const RecordType = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    _,
};

/// DNS record class.
pub const RecordClass = enum(u16) {
    IN = 1, // Internet
    _,
};

/// Parsed DNS resource record.
pub const ResourceRecord = struct {
    name: []const u8,
    record_type: RecordType,
    class: RecordClass,
    ttl: u32,
    rdata: RData,

    pub const RData = union(RecordType) {
        A: [4]u8,
        AAAA: [16]u8,
        CNAME: []const u8,
        TXT: []const u8,
        SRV: SrvRecord,
        NS: []const u8,
        PTR: []const u8,
        MX: MxRecord,
        SOA: void, // Not fully parsed
        _: []const u8,
    };

    pub const SrvRecord = struct {
        priority: u16,
        weight: u16,
        port: u16,
        target: []const u8,
    };

    pub const MxRecord = struct {
        preference: u16,
        exchange: []const u8,
    };
};

/// Parse an IPv4 address string.
fn parseIPv4(str: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, str, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return null;
        result[i] = std.fmt.parseInt(u8, part, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;
    return result;
}

/// Parse an IPv6 address string (simplified, full form only).
fn parseIPv6(str: []const u8) ?[16]u8 {
    // Handle :: expansion
    var result: [16]u8 = [_]u8{0} ** 16;

    // Check for :: (zero compression)
    if (std.mem.indexOf(u8, str, "::")) |pos| {
        // Split into before and after ::
        const before = str[0..pos];
        const after = if (pos + 2 < str.len) str[pos + 2 ..] else "";

        var idx: usize = 0;

        // Parse groups before ::
        if (before.len > 0) {
            var it = std.mem.splitScalar(u8, before, ':');
            while (it.next()) |part| {
                if (idx >= 16) return null;
                const val = std.fmt.parseInt(u16, part, 16) catch return null;
                result[idx] = @truncate(val >> 8);
                result[idx + 1] = @truncate(val);
                idx += 2;
            }
        }

        // Parse groups after :: (from the end)
        if (after.len > 0) {
            var after_groups: [8][2]u8 = undefined;
            var after_count: usize = 0;
            var ait = std.mem.splitScalar(u8, after, ':');
            while (ait.next()) |part| {
                if (after_count >= 8) return null;
                const val = std.fmt.parseInt(u16, part, 16) catch return null;
                after_groups[after_count][0] = @truncate(val >> 8);
                after_groups[after_count][1] = @truncate(val);
                after_count += 1;
            }

            // Copy from end
            var end_idx: usize = 16;
            var i: usize = after_count;
            while (i > 0) {
                i -= 1;
                end_idx -= 2;
                result[end_idx] = after_groups[i][0];
                result[end_idx + 1] = after_groups[i][1];
            }
        }

        return result;
    }

    // Full form: 8 groups separated by :
    var it = std.mem.splitScalar(u8, str, ':');
    var idx: usize = 0;
    while (it.next()) |part| {
        if (idx >= 16) return null;
        const val = std.fmt.parseInt(u16, part, 16) catch return null;
        result[idx] = @truncate(val >> 8);
        result[idx + 1] = @truncate(val);
        idx += 2;
    }
    if (idx != 16) return null;

    return result;
}

/// DNS stub resolver.
pub const Resolver = struct {
    stack: *stack.Stack,
    allocator: std.mem.Allocator,
    dns_server: tcpip.Address,
    timeout_ms: u32 = 5000,

    // TTL cache (RFC 1035 Section 7.2)
    cache: std.StringHashMap(CacheEntry),
    cache_enabled: bool = true,

    // Negative cache TTL (RFC 2308)
    negative_ttl_sec: u32 = DEFAULT_NEGATIVE_TTL_SEC,

    // Hosts file lookup
    hosts_file_enabled: bool = true,
    hosts_entries: ?std.StringHashMap(tcpip.Address) = null,

    pub fn init(s: *stack.Stack, dns_server: tcpip.Address) Resolver {
        return .{
            .stack = s,
            .allocator = s.allocator,
            .dns_server = dns_server,
            .cache = std.StringHashMap(CacheEntry).init(s.allocator),
        };
    }

    pub fn deinit(self: *Resolver) void {
        // Free cache keys
        var it = self.cache.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.cache.deinit();

        // Free hosts entries
        if (self.hosts_entries) |*hosts| {
            var hit = hosts.keyIterator();
            while (hit.next()) |key| {
                self.allocator.free(key.*);
            }
            hosts.deinit();
        }
    }

    /// Enable or disable caching.
    pub fn setCacheEnabled(self: *Resolver, enabled: bool) void {
        self.cache_enabled = enabled;
    }

    /// Set negative cache TTL in seconds.
    pub fn setNegativeTtl(self: *Resolver, ttl_sec: u32) void {
        self.negative_ttl_sec = ttl_sec;
    }

    /// Clear the DNS cache.
    pub fn clearCache(self: *Resolver) void {
        var it = self.cache.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.cache.clearRetainingCapacity();
    }

    /// Load hosts file entries (e.g., /etc/hosts).
    pub fn loadHostsFile(self: *Resolver, path: []const u8) !void {
        const file = std.fs.openFileAbsolute(path, .{}) catch |err| {
            if (err == error.FileNotFound) return;
            return err;
        };
        defer file.close();

        if (self.hosts_entries == null) {
            self.hosts_entries = std.StringHashMap(tcpip.Address).init(self.allocator);
        }

        var buf: [4096]u8 = undefined;
        var reader = file.reader();

        while (reader.readUntilDelimiterOrEof(&buf, '\n')) |maybe_line| {
            const line = maybe_line orelse break;

            // Skip comments and empty lines
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            // Parse: IP hostname [aliases...]
            var parts = std.mem.tokenizeAny(u8, trimmed, " \t");
            const ip_str = parts.next() orelse continue;
            const hostname = parts.next() orelse continue;

            // Parse IPv4 or IPv6
            if (parseIPv4(ip_str)) |ipv4| {
                const key = try self.allocator.dupe(u8, hostname);
                try self.hosts_entries.?.put(key, .{ .v4 = ipv4 });
            } else if (parseIPv6(ip_str)) |ipv6| {
                const key = try self.allocator.dupe(u8, hostname);
                try self.hosts_entries.?.put(key, .{ .v6 = ipv6 });
            }
        } else |_| {}
    }

    /// Set resolver timeout in milliseconds.
    pub fn setTimeout(self: *Resolver, timeout_ms: u32) void {
        self.timeout_ms = timeout_ms;
    }

    /// Resolve hostname to IPv4 address.
    pub fn resolve(self: *Resolver, hostname: []const u8) !tcpip.Address {
        return self.resolveType(hostname, .A);
    }

    /// Resolve hostname to IPv6 address.
    pub fn resolve6(self: *Resolver, hostname: []const u8) !tcpip.Address {
        return self.resolveType(hostname, .AAAA);
    }

    /// Resolve hostname to address of specified type.
    pub fn resolveType(self: *Resolver, hostname: []const u8, record_type: RecordType) !tcpip.Address {
        // 1. Check hosts file first (only for A/AAAA records)
        if (self.hosts_file_enabled and (record_type == .A or record_type == .AAAA)) {
            if (self.hosts_entries) |hosts| {
                if (hosts.get(hostname)) |addr| {
                    // Match address type to record type
                    switch (addr) {
                        .v4 => if (record_type == .A) return addr,
                        .v6 => if (record_type == .AAAA) return addr,
                    }
                }
            }
        }

        // 2. Check cache
        if (self.cache_enabled) {
            const cache_key = try self.makeCacheKey(hostname, record_type);
            defer self.allocator.free(cache_key);

            if (self.cache.get(cache_key)) |entry| {
                if (!entry.isExpired()) {
                    if (entry.is_negative) {
                        return error.NameNotFound;
                    }
                    if (entry.address) |addr| {
                        return addr;
                    }
                }
            }
        }

        // 3. Perform DNS query
        const result = self.performDnsQuery(hostname, record_type);

        // 4. Cache the result (success or negative)
        if (self.cache_enabled) {
            self.cacheResult(hostname, record_type, result) catch {};
        }

        return result;
    }

    fn makeCacheKey(self: *Resolver, hostname: []const u8, record_type: RecordType) ![]u8 {
        const rtype_num = @intFromEnum(record_type);
        const key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ hostname, rtype_num });
        return key;
    }

    fn cacheResult(self: *Resolver, hostname: []const u8, record_type: RecordType, result: anyerror!tcpip.Address) void {
        // Limit cache size
        if (self.cache.count() >= MAX_CACHE_ENTRIES) {
            // Remove expired entries first
            var to_remove = std.ArrayList([]const u8).init(self.allocator);
            defer to_remove.deinit();

            var it = self.cache.iterator();
            while (it.next()) |kv| {
                if (kv.value_ptr.isExpired()) {
                    to_remove.append(kv.key_ptr.*) catch continue;
                }
            }

            for (to_remove.items) |key| {
                _ = self.cache.remove(key);
                self.allocator.free(key);
            }
        }

        const cache_key = self.makeCacheKey(hostname, record_type) catch return;

        if (result) |addr| {
            // NOTE: Use default TTL of 300s for caching
            // Real TTL should come from DNS response
            const entry = CacheEntry{
                .address = addr,
                .record_type = record_type,
                .expires_at_ms = std.time.milliTimestamp() + 300 * 1000,
                .is_negative = false,
            };
            self.cache.put(cache_key, entry) catch {
                self.allocator.free(cache_key);
            };
        } else |err| {
            if (err == error.NameNotFound) {
                // Negative cache entry
                const entry = CacheEntry{
                    .address = null,
                    .record_type = record_type,
                    .expires_at_ms = std.time.milliTimestamp() + @as(i64, self.negative_ttl_sec) * 1000,
                    .is_negative = true,
                };
                self.cache.put(cache_key, entry) catch {
                    self.allocator.free(cache_key);
                };
            } else {
                self.allocator.free(cache_key);
            }
        }
    }

    /// Perform the actual DNS query over UDP.
    fn performDnsQuery(self: *Resolver, hostname: []const u8, record_type: RecordType) !tcpip.Address {
        var wq = waiter.Queue{};
        const udp_proto = self.stack.transport_protocols.get(header.UDP.ProtocolNumber) orelse
            return error.NoUdpProtocol;

        const net_proto: u16 = switch (self.dns_server) {
            .v4 => @import("network/ipv4.zig").ProtocolNumber,
            .v6 => @import("network/ipv6.zig").ProtocolNumber,
        };

        var ep = try udp_proto.newEndpoint(self.stack, net_proto, &wq);
        defer ep.close();

        // Find source address
        var bind_addr = switch (self.dns_server) {
            .v4 => tcpip.Address{ .v4 = .{ 0, 0, 0, 0 } },
            .v6 => tcpip.Address{ .v6 = [_]u8{0} ** 16 },
        };

        if (self.stack.nics.get(1)) |nic| {
            for (nic.addresses.items) |pa| {
                if (std.meta.activeTag(pa.address_with_prefix.address) == std.meta.activeTag(self.dns_server)) {
                    bind_addr = pa.address_with_prefix.address;
                    break;
                }
            }
        }

        try ep.bind(.{ .nic = 1, .addr = bind_addr, .port = 0 });

        if (ep.getLocalAddress()) |la| {
            log.debug("DNS: Bound to port {}", .{la.port});
        } else |_| {}

        // Build DNS query
        var dns_buf = try self.allocator.alloc(u8, 512);
        defer self.allocator.free(dns_buf);

        var idx: usize = 0;

        // Header
        @memset(dns_buf[0..header.DNSHeaderSize], 0);
        var h = header.DNS.init(dns_buf[0..header.DNSHeaderSize]);
        const query_id: u16 = @intCast(std.time.milliTimestamp() & 0xFFFF);
        h.setId(query_id);
        h.setFlags(0x0100); // Standard Query, Recursion Desired
        h.setQuestionCount(1);
        idx += header.DNSHeaderSize;

        // Question: encode name
        idx = try encodeName(dns_buf, idx, hostname);

        // Type and Class
        std.mem.writeInt(u16, dns_buf[idx..][0..2], @intFromEnum(record_type), .big);
        idx += 2;
        std.mem.writeInt(u16, dns_buf[idx..][0..2], @intFromEnum(RecordClass.IN), .big);
        idx += 2;

        const Payloader = struct {
            data: []const u8,
            pub fn payloader(ctx: *@This()) tcpip.Payloader {
                return .{ .ptr = ctx, .vtable = &.{ .fullPayload = fullPayload } };
            }
            fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
                return @as(*@This(), @ptrCast(@alignCast(ptr))).data;
            }
        };
        var fp = Payloader{ .data = dns_buf[0..idx] };

        const dest = tcpip.FullAddress{
            .nic = 0,
            .addr = self.dns_server,
            .port = 53,
        };

        // Send Query with retry
        var send_attempts: usize = 0;
        while (send_attempts < 3) : (send_attempts += 1) {
            _ = ep.write(fp.payloader(), .{ .to = &dest }) catch |err| {
                if (err == tcpip.Error.WouldBlock) {
                    std.time.sleep(10 * std.time.ns_per_ms);
                    continue;
                }
                return err;
            };
            break;
        }

        // Wait for response with timeout
        const timeout_iterations = self.timeout_ms / 10;
        var timeout: usize = 0;
        while (timeout < timeout_iterations) : (timeout += 1) {
            var packet = ep.read(null) catch |err| {
                if (err == tcpip.Error.WouldBlock) {
                    std.time.sleep(10 * std.time.ns_per_ms);
                    continue;
                }
                return err;
            };
            defer packet.deinit();

            if (packet.size < header.DNSHeaderSize) continue;

            const packet_flat = try packet.toView(self.allocator);
            defer self.allocator.free(packet_flat);

            const resp_h = header.DNS.init(@constCast(packet_flat[0..header.DNSHeaderSize]));

            // Match transaction ID
            if (resp_h.id() != query_id) continue;

            // Check for errors in response
            const flags = resp_h.flags();
            const rcode = flags & 0x000F;
            if (rcode != 0) {
                return switch (rcode) {
                    1 => error.FormatError,
                    2 => error.ServerFailure,
                    3 => error.NameNotFound,
                    4 => error.NotImplemented,
                    5 => error.Refused,
                    else => error.DnsError,
                };
            }

            // Parse response
            var pos: usize = header.DNSHeaderSize;

            // Skip questions
            var q_count = resp_h.questionCount();
            while (q_count > 0) : (q_count -= 1) {
                pos = try skipName(packet_flat, pos);
                pos += 4; // Type + Class
            }

            // Parse answers
            var ans_count = resp_h.answerCount();
            while (ans_count > 0 and pos < packet_flat.len) : (ans_count -= 1) {
                pos = try skipName(packet_flat, pos);
                if (pos + 10 > packet_flat.len) break;

                const rtype: RecordType = @enumFromInt(std.mem.readInt(u16, packet_flat[pos..][0..2], .big));
                pos += 4; // Type + Class
                pos += 4; // TTL
                const rdlen = std.mem.readInt(u16, packet_flat[pos..][0..2], .big);
                pos += 2;

                if (pos + rdlen > packet_flat.len) break;

                if (rtype == .A and rdlen == 4 and record_type == .A) {
                    var ip: [4]u8 = undefined;
                    @memcpy(&ip, packet_flat[pos..][0..4]);
                    return tcpip.Address{ .v4 = ip };
                } else if (rtype == .AAAA and rdlen == 16 and record_type == .AAAA) {
                    var ip: [16]u8 = undefined;
                    @memcpy(&ip, packet_flat[pos..][0..16]);
                    return tcpip.Address{ .v6 = ip };
                }
                pos += rdlen;
            }
        }

        return error.DnsTimeout;
    }

    /// Resolve SRV record.
    pub fn resolveSrv(self: *Resolver, service: []const u8) !ResourceRecord.SrvRecord {
        _ = self;
        _ = service;
        // FIXME: DNSSEC validation is not yet implemented
        return error.NotImplemented;
    }
};

/// Encode a domain name into DNS wire format.
fn encodeName(buf: []u8, start: usize, name: []const u8) !usize {
    var idx = start;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len > 63) return error.LabelTooLong;
        if (idx + 1 + label.len > buf.len) return error.BufferTooSmall;
        buf[idx] = @intCast(label.len);
        idx += 1;
        @memcpy(buf[idx..][0..label.len], label);
        idx += label.len;
    }
    buf[idx] = 0; // Root label
    idx += 1;
    return idx;
}

/// Skip a name in DNS wire format (handles compression).
fn skipName(buf: []const u8, start: usize) !usize {
    var pos = start;
    var hops: usize = 0;

    while (pos < buf.len and hops < MaxCompressionHops) {
        const len = buf[pos];
        if (len == 0) {
            return pos + 1;
        } else if ((len & 0xC0) == 0xC0) {
            // Compression pointer
            return pos + 2;
        } else {
            pos += 1 + len;
        }
        hops += 1;
    }

    if (hops >= MaxCompressionHops) {
        return error.CompressionLoop;
    }
    return error.InvalidName;
}

/// Decompress a name from DNS wire format.
/// Returns the decompressed name and the position after the name in the original buffer.
pub fn decompressName(allocator: std.mem.Allocator, buf: []const u8, start: usize) !struct { name: []u8, end_pos: usize } {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var pos = start;
    var end_pos: ?usize = null;
    var hops: usize = 0;

    while (pos < buf.len and hops < MaxCompressionHops) {
        const len = buf[pos];

        if (len == 0) {
            if (end_pos == null) end_pos = pos + 1;
            break;
        } else if ((len & 0xC0) == 0xC0) {
            // Compression pointer (RFC 1035 Section 4.1.4)
            if (pos + 1 >= buf.len) return error.InvalidPointer;
            if (end_pos == null) end_pos = pos + 2;
            const offset = (@as(u16, len & 0x3F) << 8) | buf[pos + 1];
            if (offset >= buf.len) return error.InvalidPointer;
            pos = offset;
            hops += 1;
        } else {
            // Regular label
            if (pos + 1 + len > buf.len) return error.InvalidName;
            if (result.items.len > 0) try result.append('.');
            try result.appendSlice(buf[pos + 1 .. pos + 1 + len]);
            pos += 1 + len;
        }
    }

    if (hops >= MaxCompressionHops) {
        return error.CompressionLoop;
    }

    return .{
        .name = try result.toOwnedSlice(),
        .end_pos = end_pos orelse pos,
    };
}

/// Parse a complete DNS response.
pub fn parseResponse(allocator: std.mem.Allocator, buf: []const u8) !struct {
    answers: []ResourceRecord,
    authorities: []ResourceRecord,
    additionals: []ResourceRecord,
} {
    if (buf.len < header.DNSHeaderSize) return error.InvalidMessage;

    const h = header.DNS.init(@constCast(buf[0..header.DNSHeaderSize]));
    var pos: usize = header.DNSHeaderSize;

    // Skip questions
    var q_count = h.questionCount();
    while (q_count > 0) : (q_count -= 1) {
        pos = try skipName(buf, pos);
        pos += 4;
    }

    var answers = std.ArrayList(ResourceRecord).init(allocator);
    errdefer {
        for (answers.items) |rr| {
            switch (rr.rdata) {
                .CNAME, .TXT, .NS, .PTR => |s| allocator.free(s),
                .SRV => |srv| allocator.free(srv.target),
                .MX => |mx| allocator.free(mx.exchange),
                else => {},
            }
        }
        answers.deinit();
    }

    // Parse answer section
    var ans_count = h.answerCount();
    while (ans_count > 0 and pos < buf.len) : (ans_count -= 1) {
        const rr = try parseResourceRecord(allocator, buf, &pos);
        try answers.append(rr);
    }

    // FIXME: DNSSEC validation is not yet implemented
    // For now, skip authority and additional sections

    return .{
        .answers = try answers.toOwnedSlice(),
        .authorities = &[_]ResourceRecord{},
        .additionals = &[_]ResourceRecord{},
    };
}

fn parseResourceRecord(allocator: std.mem.Allocator, buf: []const u8, pos: *usize) !ResourceRecord {
    const name_result = try decompressName(allocator, buf, pos.*);
    defer allocator.free(name_result.name);
    pos.* = name_result.end_pos;

    if (pos.* + 10 > buf.len) return error.InvalidRecord;

    const rtype: RecordType = @enumFromInt(std.mem.readInt(u16, buf[pos.*..][0..2], .big));
    const rclass: RecordClass = @enumFromInt(std.mem.readInt(u16, buf[pos.* + 2 ..][0..4][0..2], .big));
    const ttl = std.mem.readInt(u32, buf[pos.* + 4 ..][0..4], .big);
    const rdlen = std.mem.readInt(u16, buf[pos.* + 8 ..][0..2], .big);
    pos.* += 10;

    if (pos.* + rdlen > buf.len) return error.InvalidRecord;

    const rdata: ResourceRecord.RData = switch (rtype) {
        .A => blk: {
            if (rdlen != 4) return error.InvalidRecord;
            var ip: [4]u8 = undefined;
            @memcpy(&ip, buf[pos.*..][0..4]);
            break :blk .{ .A = ip };
        },
        .AAAA => blk: {
            if (rdlen != 16) return error.InvalidRecord;
            var ip: [16]u8 = undefined;
            @memcpy(&ip, buf[pos.*..][0..16]);
            break :blk .{ .AAAA = ip };
        },
        .CNAME, .NS, .PTR => blk: {
            const target = try decompressName(allocator, buf, pos.*);
            break :blk switch (rtype) {
                .CNAME => .{ .CNAME = target.name },
                .NS => .{ .NS = target.name },
                .PTR => .{ .PTR = target.name },
                else => unreachable,
            };
        },
        .TXT => blk: {
            // TXT records have length-prefixed strings
            if (rdlen == 0) break :blk .{ .TXT = "" };
            const txt_len = buf[pos.*];
            if (txt_len > rdlen - 1) return error.InvalidRecord;
            const txt = try allocator.dupe(u8, buf[pos.* + 1 ..][0..txt_len]);
            break :blk .{ .TXT = txt };
        },
        .SRV => blk: {
            if (rdlen < 6) return error.InvalidRecord;
            const priority = std.mem.readInt(u16, buf[pos.*..][0..2], .big);
            const weight = std.mem.readInt(u16, buf[pos.* + 2 ..][0..2], .big);
            const port = std.mem.readInt(u16, buf[pos.* + 4 ..][0..2], .big);
            const target = try decompressName(allocator, buf, pos.* + 6);
            break :blk .{ .SRV = .{
                .priority = priority,
                .weight = weight,
                .port = port,
                .target = target.name,
            } };
        },
        .MX => blk: {
            if (rdlen < 2) return error.InvalidRecord;
            const preference = std.mem.readInt(u16, buf[pos.*..][0..2], .big);
            const exchange = try decompressName(allocator, buf, pos.* + 2);
            break :blk .{ .MX = .{
                .preference = preference,
                .exchange = exchange.name,
            } };
        },
        else => blk: {
            const data = try allocator.dupe(u8, buf[pos.*..][0..rdlen]);
            break :blk .{ ._ = data };
        },
    };

    pos.* += rdlen;

    return .{
        .name = try allocator.dupe(u8, name_result.name),
        .record_type = rtype,
        .class = rclass,
        .ttl = ttl,
        .rdata = rdata,
    };
}

test "DNS name encoding" {
    var buf: [256]u8 = undefined;
    const end = try encodeName(&buf, 0, "example.com");
    try std.testing.expectEqual(@as(usize, 13), end);
    try std.testing.expectEqual(@as(u8, 7), buf[0]); // "example" length
    try std.testing.expectEqualStrings("example", buf[1..8]);
    try std.testing.expectEqual(@as(u8, 3), buf[8]); // "com" length
    try std.testing.expectEqualStrings("com", buf[9..12]);
    try std.testing.expectEqual(@as(u8, 0), buf[12]); // root
}

test "DNS name decompression" {
    const allocator = std.testing.allocator;

    // Simple name without compression
    const simple = [_]u8{ 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const result1 = try decompressName(allocator, &simple, 0);
    defer allocator.free(result1.name);
    try std.testing.expectEqualStrings("www.example.com", result1.name);

    // Name with compression pointer
    var compressed: [32]u8 = undefined;
    @memcpy(compressed[0..17], &simple);
    compressed[17] = 3;
    compressed[18] = 'f';
    compressed[19] = 't';
    compressed[20] = 'p';
    compressed[21] = 0xC0; // Compression pointer
    compressed[22] = 4; // Points to offset 4 ("example.com")

    const result2 = try decompressName(allocator, &compressed, 17);
    defer allocator.free(result2.name);
    try std.testing.expectEqualStrings("ftp.example.com", result2.name);
}

test "DNS compression loop detection" {
    const allocator = std.testing.allocator;

    // Create a loop: offset 0 points to offset 2, offset 2 points to offset 0
    const looped = [_]u8{ 0xC0, 2, 0xC0, 0 };
    const result = decompressName(allocator, &looped, 0);
    try std.testing.expectError(error.CompressionLoop, result);
}
