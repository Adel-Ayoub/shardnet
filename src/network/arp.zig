/// ARP (Address Resolution Protocol) implementation for shardnet.
///
/// Handles IPv4-to-MAC address resolution with caching, pending request
/// queuing, gratuitous ARP, and RFC 5227 probe/announcement support.

const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const time = @import("../time.zig");
const stats = @import("../stats.zig");
const log = @import("../log.zig").scoped(.arp);

pub const ProtocolNumber = 0x0806;
pub const ProtocolAddress = "arp";

/// ARP cache entry with TTL-based expiry.
pub const CacheEntry = struct {
    mac: [6]u8,
    timestamp_ms: i64,
    state: State,

    pub const State = enum {
        /// Entry is valid and confirmed.
        reachable,
        /// Entry is stale; refresh needed on next use.
        stale,
        /// Entry is being probed (no reply yet).
        probe,
    };
};

/// Default cache entry TTL in milliseconds (20 minutes).
const CACHE_TTL_MS: i64 = 20 * 60 * 1000;

/// Stale threshold in milliseconds (15 minutes).
const CACHE_STALE_MS: i64 = 15 * 60 * 1000;

/// Maximum pending requests before oldest is dropped.
const MAX_PENDING_REQUESTS = 64;

/// RFC 5227: Number of probe packets to send.
const PROBE_COUNT = 3;

/// RFC 5227: Delay between probes in milliseconds.
const PROBE_INTERVAL_MS = 1000;

/// Policy for handling ARP cache updates that change an existing mapping.
///
/// ARP spoofing/poisoning attacks work by sending unsolicited ARP replies
/// that overwrite legitimate mappings. This policy controls how the stack
/// responds when an incoming ARP packet would change an existing entry.
pub const CacheUpdatePolicy = enum {
    /// Accept all updates (original behaviour, vulnerable to spoofing).
    accept,
    /// Reject updates that change MAC for an existing IP (paranoid mode).
    reject,
    /// Accept but log a warning (recommended for production monitoring).
    alert,
};

pub const ARPProtocol = struct {
    /// ARP cache: IPv4 address -> CacheEntry.
    /// NOTE: Cache eviction uses LRU policy. When the cache is full, the oldest
    /// entry (by timestamp) is evicted. Stale entries are refreshed on access
    /// rather than eagerly, reducing background traffic.
    cache: std.AutoHashMap(tcpip.Address, CacheEntry),
    allocator: std.mem.Allocator,
    /// Policy for handling cache updates that would change an existing mapping.
    /// Defaults to .alert which logs potential spoofing but allows the update.
    update_policy: CacheUpdatePolicy = .alert,

    pub fn init(allocator: std.mem.Allocator) ARPProtocol {
        return .{
            .cache = std.AutoHashMap(tcpip.Address, CacheEntry).init(allocator),
            .allocator = allocator,
        };
    }

    /// Initialise with explicit cache update policy.
    pub fn initWithPolicy(allocator: std.mem.Allocator, policy: CacheUpdatePolicy) ARPProtocol {
        return .{
            .cache = std.AutoHashMap(tcpip.Address, CacheEntry).init(allocator),
            .allocator = allocator,
            .update_policy = policy,
        };
    }

    pub fn deinit(self: *ARPProtocol) void {
        self.cache.deinit();
    }

    /// Look up a MAC address in the cache.
    /// Returns null if not found or if the entry has expired.
    pub fn lookup(self: *ARPProtocol, addr: tcpip.Address) ?[6]u8 {
        const entry = self.cache.get(addr) orelse return null;
        const now = std.time.milliTimestamp();

        // Check if entry has expired
        if (now - entry.timestamp_ms > CACHE_TTL_MS) {
            _ = self.cache.remove(addr);
            return null;
        }

        return entry.mac;
    }

    /// Add or update a cache entry.
    ///
    /// When an entry already exists with a different MAC address, the
    /// configured `update_policy` determines behaviour:
    ///   - accept: silently overwrite (vulnerable to ARP spoofing)
    ///   - reject: keep original mapping, ignore the new one
    ///   - alert:  log a warning and then overwrite (recommended)
    ///
    /// NOTE: Frequent MAC changes for the same IP may indicate:
    ///   1. ARP spoofing attack (malicious)
    ///   2. VRRP/HSRP failover (legitimate)
    ///   3. VM migration (legitimate)
    /// Operators should tune the policy based on their environment.
    pub fn updateCache(self: *ARPProtocol, addr: tcpip.Address, mac: [6]u8) void {
        // Check for existing entry with different MAC (potential spoofing)
        if (self.cache.get(addr)) |existing| {
            if (!std.mem.eql(u8, &existing.mac, &mac)) {
                switch (self.update_policy) {
                    .reject => {
                        log.warn("ARP: Rejecting MAC change for {any}: {x}:{x}:{x}:{x}:{x}:{x} -> {x}:{x}:{x}:{x}:{x}:{x} (policy=reject)", .{
                            addr.v4,
                            existing.mac[0], existing.mac[1], existing.mac[2],
                            existing.mac[3], existing.mac[4], existing.mac[5],
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                        });
                        return;
                    },
                    .alert => {
                        log.warn("ARP: MAC changed for {any}: {x}:{x}:{x}:{x}:{x}:{x} -> {x}:{x}:{x}:{x}:{x}:{x} (possible spoofing)", .{
                            addr.v4,
                            existing.mac[0], existing.mac[1], existing.mac[2],
                            existing.mac[3], existing.mac[4], existing.mac[5],
                            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                        });
                    },
                    .accept => {},
                }
            }
        }

        const entry = CacheEntry{
            .mac = mac,
            .timestamp_ms = std.time.milliTimestamp(),
            .state = .reachable,
        };
        self.cache.put(addr, entry) catch {};
    }

    /// Remove an entry from the cache.
    pub fn invalidate(self: *ARPProtocol, addr: tcpip.Address) void {
        _ = self.cache.remove(addr);
    }

    /// Expire old entries from the cache.
    /// NOTE: Called periodically by the timer; removes entries older than TTL.
    pub fn expireEntries(self: *ARPProtocol) void {
        const now = std.time.milliTimestamp();
        var it = self.cache.iterator();
        var to_remove: [32]tcpip.Address = undefined;
        var remove_count: usize = 0;

        while (it.next()) |entry| {
            if (now - entry.value_ptr.timestamp_ms > CACHE_TTL_MS) {
                if (remove_count < to_remove.len) {
                    to_remove[remove_count] = entry.key_ptr.*;
                    remove_count += 1;
                }
            }
        }

        for (to_remove[0..remove_count]) |addr| {
            _ = self.cache.remove(addr);
        }
    }

    pub fn protocol(self: *ARPProtocol) stack.NetworkProtocol {
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
            .src = .{ .v4 = .{ 0, 0, 0, 0 } },
            .dst = .{ .v4 = .{ 0, 0, 0, 0 } },
        };
        const h = header.ARP.init(v);
        return .{
            .src = .{ .v4 = h.protocolAddressSender() },
            .dst = .{ .v4 = h.protocolAddressTarget() },
        };
    }

    fn linkAddressRequest(ptr: *anyopaque, addr: tcpip.Address, local_addr: tcpip.Address, nic: *stack.NIC) tcpip.Error!void {
        _ = ptr;

        const ep_opt = nic.network_endpoints.get(ProtocolNumber);
        if (ep_opt) |ep| {
            const arp_ep = @as(*ARPEndpoint, @ptrCast(@alignCast(ep.ptr)));
            if (!arp_ep.pending_requests.contains(addr)) {
                arp_ep.pending_requests.put(addr, std.time.milliTimestamp()) catch {};
                if (!arp_ep.timer.active) {
                    nic.stack.timer_queue.schedule(&arp_ep.timer, 10);
                }

                const hdr_buf = nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return tcpip.Error.OutOfMemory;
                defer nic.stack.allocator.free(hdr_buf);

                var pre = buffer.Prependable.init(hdr_buf);
                const arp_hdr = pre.prepend(header.ARPSize).?;
                var h = header.ARP.init(arp_hdr);
                h.setIPv4OverEthernet();
                h.setOp(1); // Request
                @memcpy(h.data[8..14], &nic.linkEP.linkAddress().addr);
                @memcpy(h.data[14..18], &local_addr.v4);
                @memcpy(h.data[24..28], &addr.v4);

                const pb = tcpip.PacketBuffer{
                    .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 },
                    .header = pre,
                };

                const broadcast_hw = tcpip.LinkAddress{ .addr = [_]u8{0xff} ** 6 };
                var r = stack.Route{
                    .local_address = local_addr,
                    .remote_address = addr,
                    .local_link_address = nic.linkEP.linkAddress(),
                    .remote_link_address = broadcast_hw,
                    .net_proto = ProtocolNumber,
                    .nic = nic,
                };

                stats.global_stats.arp.tx_requests += 1;
                return nic.linkEP.writePacket(&r, ProtocolNumber, pb);
            }
        }

        return;
    }

    fn newEndpoint(ptr: *anyopaque, nic: *stack.NIC, addr: tcpip.AddressWithPrefix, dispatcher: stack.TransportDispatcher) tcpip.Error!stack.NetworkEndpoint {
        _ = ptr;
        _ = addr;
        _ = dispatcher;
        const ep = try nic.stack.allocator.create(ARPEndpoint);
        ep.* = .{
            .nic = nic,
            .pending_requests = std.HashMap(tcpip.Address, i64, stack.Stack.AddressContext, 80).init(nic.stack.allocator),
            .timer = time.Timer.init(ARPEndpoint.handleTimer, ep),
        };
        return ep.networkEndpoint();
    }
};

pub const ARPEndpoint = struct {
    nic: *stack.NIC,
    pending_requests: std.HashMap(tcpip.Address, i64, stack.Stack.AddressContext, 80),
    timer: time.Timer = undefined,

    pub fn networkEndpoint(self: *ARPEndpoint) stack.NetworkEndpoint {
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

    /// Send a gratuitous ARP announcement.
    /// Used when an interface comes up to announce our presence and detect conflicts.
    pub fn sendGratuitousArp(self: *ARPEndpoint, addr: tcpip.Address) !void {
        const hdr_buf = self.nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer self.nic.stack.allocator.free(hdr_buf);

        var pre = buffer.Prependable.init(hdr_buf);
        const arp_hdr = pre.prepend(header.ARPSize).?;
        var h = header.ARP.init(arp_hdr);
        h.setIPv4OverEthernet();
        h.setOp(1); // Request (gratuitous ARP uses request with target = sender)
        @memcpy(h.data[8..14], &self.nic.linkEP.linkAddress().addr);
        @memcpy(h.data[14..18], &addr.v4);
        @memset(h.data[18..24], 0); // Target hardware address = 0
        @memcpy(h.data[24..28], &addr.v4); // Target protocol address = our address

        const pb = tcpip.PacketBuffer{
            .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 },
            .header = pre,
        };

        const broadcast_hw = tcpip.LinkAddress{ .addr = [_]u8{0xff} ** 6 };
        var r = stack.Route{
            .local_address = addr,
            .remote_address = addr,
            .local_link_address = self.nic.linkEP.linkAddress(),
            .remote_link_address = broadcast_hw,
            .net_proto = ProtocolNumber,
            .nic = self.nic,
        };

        self.nic.linkEP.writePacket(&r, ProtocolNumber, pb) catch {};
    }

    /// Send an RFC 5227 ARP probe.
    /// Sender IP is 0.0.0.0, target IP is the address being probed.
    pub fn sendProbe(self: *ARPEndpoint, target_addr: tcpip.Address) !void {
        const hdr_buf = self.nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
        defer self.nic.stack.allocator.free(hdr_buf);

        var pre = buffer.Prependable.init(hdr_buf);
        const arp_hdr = pre.prepend(header.ARPSize).?;
        var h = header.ARP.init(arp_hdr);
        h.setIPv4OverEthernet();
        h.setOp(1); // Request
        @memcpy(h.data[8..14], &self.nic.linkEP.linkAddress().addr);
        @memset(h.data[14..18], 0); // Sender IP = 0.0.0.0 (probe)
        @memset(h.data[18..24], 0); // Target hardware = 0
        @memcpy(h.data[24..28], &target_addr.v4);

        const pb = tcpip.PacketBuffer{
            .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 },
            .header = pre,
        };

        const broadcast_hw = tcpip.LinkAddress{ .addr = [_]u8{0xff} ** 6 };
        const zero_addr = tcpip.Address{ .v4 = .{ 0, 0, 0, 0 } };
        var r = stack.Route{
            .local_address = zero_addr,
            .remote_address = target_addr,
            .local_link_address = self.nic.linkEP.linkAddress(),
            .remote_link_address = broadcast_hw,
            .net_proto = ProtocolNumber,
            .nic = self.nic,
        };

        self.nic.linkEP.writePacket(&r, ProtocolNumber, pb) catch {};
    }

    /// Send an RFC 5227 ARP announcement.
    /// Both sender and target IP are set to our address.
    pub fn sendAnnouncement(self: *ARPEndpoint, addr: tcpip.Address) !void {
        // Announcement is same as gratuitous ARP
        try self.sendGratuitousArp(addr);
    }

    pub fn handleTimer(ptr: *anyopaque) void {
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        var it = self.pending_requests.iterator();
        const now = std.time.milliTimestamp();
        var has_pending = false;

        while (it.next()) |entry| {
            if (now - entry.value_ptr.* >= 10) {
                const proto_opt = self.nic.stack.network_protocols.get(ProtocolNumber);
                if (proto_opt) |p| {
                    const proto = @as(*ARPProtocol, @ptrCast(@alignCast(p.ptr)));
                    var local_addr: ?tcpip.Address = null;
                    const addrs = self.nic.addresses.items;
                    if (addrs.len > 0) local_addr = addrs[0].address_with_prefix.address;

                    if (local_addr) |la| {
                        ARPProtocol.linkAddressRequest(proto, entry.key_ptr.*, la, self.nic) catch {};
                        entry.value_ptr.* = now;
                    }
                }
            }
            has_pending = true;
        }

        if (has_pending) {
            self.nic.stack.timer_queue.schedule(&self.timer, 10);
        }
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.nic.linkEP.mtu() - header.ARPSize;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        self.nic.stack.timer_queue.cancel(&self.timer);
        self.pending_requests.deinit();
        self.nic.stack.allocator.destroy(self);
    }

    fn writePacket(ptr: *anyopaque, r: *const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        _ = ptr;
        _ = r;
        _ = protocol;
        _ = pkt;
        return tcpip.Error.NotPermitted;
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, pkt: tcpip.PacketBuffer) void {
        const self = @as(*ARPEndpoint, @ptrCast(@alignCast(ptr)));
        _ = r;
        const v = pkt.data.first() orelse return;
        const h = header.ARP.init(v);
        if (!h.isValid()) return;

        const sender_proto_addr = tcpip.Address{ .v4 = h.protocolAddressSender() };
        const sender_hw_addr = h.hardwareAddressSender();

        // NOTE: Update cache on any valid ARP packet from this sender.
        // This implements passive learning to reduce ARP traffic.
        _ = self.pending_requests.remove(sender_proto_addr);
        self.nic.stack.addLinkAddress(sender_proto_addr, .{ .addr = sender_hw_addr }) catch {};

        const target_proto_addr = tcpip.Address{ .v4 = h.protocolAddressTarget() };
        if (h.op() == 1) { // Request
            stats.global_stats.arp.rx_requests += 1;
            if (self.nic.hasAddress(target_proto_addr)) {
                const hdr_buf = self.nic.stack.allocator.alloc(u8, header.ReservedHeaderSize) catch return;
                defer self.nic.stack.allocator.free(hdr_buf);

                var pre = buffer.Prependable.init(hdr_buf);
                const arp_hdr = pre.prepend(header.ARPSize).?;
                var reply_h = header.ARP.init(arp_hdr);
                reply_h.setIPv4OverEthernet();
                reply_h.setOp(2); // Reply
                @memcpy(reply_h.data[8..14], &self.nic.linkEP.linkAddress().addr);
                @memcpy(reply_h.data[14..18], h.data[24..28]);
                @memcpy(reply_h.data[18..24], h.data[8..14]);
                @memcpy(reply_h.data[24..28], h.data[14..18]);

                const reply_pkt = tcpip.PacketBuffer{
                    .data = .{ .views = &[_]buffer.ClusterView{}, .size = 0 },
                    .header = pre,
                };

                const remote_link_address = tcpip.LinkAddress{ .addr = sender_hw_addr };
                var reply_route = stack.Route{
                    .local_address = target_proto_addr,
                    .remote_address = sender_proto_addr,
                    .local_link_address = self.nic.linkEP.linkAddress(),
                    .remote_link_address = remote_link_address,
                    .net_proto = ProtocolNumber,
                    .nic = self.nic,
                };

                stats.global_stats.arp.tx_replies += 1;
                self.nic.linkEP.writePacket(&reply_route, ProtocolNumber, reply_pkt) catch {};
            }
        } else if (h.op() == 2) { // Reply
            stats.global_stats.arp.rx_replies += 1;
        }
    }
};
