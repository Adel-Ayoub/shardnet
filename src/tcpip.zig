/// TCP/IP stack core types and dispatch infrastructure.
///
/// Provides frame demultiplexing by EtherType/protocol number,
/// flow-based receive steering for multi-queue NICs, and
/// ARP-pending packet queueing.

const std = @import("std");
const buffer = @import("buffer.zig");
const waiter = @import("waiter.zig");

pub const NICID = i32;
pub const NetworkProtocolNumber = u16;
pub const TransportProtocolNumber = u16;

// NOTE: EtherType values for dispatch table. ARP (0x0806) is dispatched
// before IP to ensure address resolution completes before dependent packets.
pub const EtherType = struct {
    pub const ARP: NetworkProtocolNumber = 0x0806;
    pub const IPv4: NetworkProtocolNumber = 0x0800;
    pub const IPv6: NetworkProtocolNumber = 0x86DD;
};

// NOTE: IP protocol numbers for transport dispatch.
pub const IPProtocol = struct {
    pub const ICMP: TransportProtocolNumber = 1;
    pub const TCP: TransportProtocolNumber = 6;
    pub const UDP: TransportProtocolNumber = 17;
    pub const ICMPv6: TransportProtocolNumber = 58;
};

pub const Address = union(enum) {
    v4: [4]u8,
    v6: [16]u8,

    pub fn eq(self: Address, other: Address) bool {
        if (std.meta.activeTag(self) != std.meta.activeTag(other)) return false;
        return switch (self) {
            .v4 => |v| std.mem.eql(u8, &v, &other.v4),
            .v6 => |v| std.mem.eql(u8, &v, &other.v6),
        };
    }

    pub fn hash(self: Address) u64 {
        var h = std.hash.Wyhash.init(0);
        const tag = std.meta.activeTag(self);
        h.update(std.mem.asBytes(&tag));
        switch (self) {
            .v4 => |v| h.update(&v),
            .v6 => |v| h.update(&v),
        }
        return h.final();
    }

    pub fn isAny(self: Address) bool {
        return switch (self) {
            .v4 => |v| std.mem.eql(u8, &v, &[_]u8{ 0, 0, 0, 0 }),
            .v6 => |v| std.mem.eql(u8, &v, &[_]u8{0} ** 16),
        };
    }

    pub fn toSolicitedNodeMulticast(self: Address) Address {
        const v6 = switch (self) {
            .v4 => unreachable,
            .v6 => |v| v,
        };
        var res = [_]u8{0} ** 16;
        res[0] = 0xff;
        res[1] = 0x02;
        res[11] = 0x01;
        res[12] = 0xff;
        res[13] = v6[13];
        res[14] = v6[14];
        res[15] = v6[15];
        return .{ .v6 = res };
    }
};

test "Address.isAny" {
    const any_v4 = Address{ .v4 = .{ 0, 0, 0, 0 } };
    const some_v4 = Address{ .v4 = .{ 1, 2, 3, 4 } };
    const any_v6 = Address{ .v6 = [_]u8{0} ** 16 };
    const some_v6 = Address{ .v6 = [_]u8{1} ** 16 };

    try std.testing.expect(any_v4.isAny());
    try std.testing.expect(!some_v4.isAny());
    try std.testing.expect(any_v6.isAny());
    try std.testing.expect(!some_v6.isAny());
}

pub const LinkAddress = struct {
    addr: [6]u8,
    pub fn eq(self: LinkAddress, other: LinkAddress) bool {
        return std.mem.eql(u8, &self.addr, &other.addr);
    }
};

pub const FullAddress = struct {
    nic: NICID,
    addr: Address,
    port: u16,
};

pub const Error = error{
    UnknownProtocol,
    UnknownNICID,
    UnknownDevice,
    DuplicateNICID,
    DuplicateAddress,
    NoRoute,
    BadLinkEndpoint,
    InvalidEndpointState,
    WouldBlock,
    NetworkUnreachable,
    MessageTooLong,
    NoBufferSpace,
    NotPermitted,
    OutOfMemory,
    DestinationRequired,
    NotSupported,
    AddressInUse,
    ArpPending,
};

/// Flow hash for RSS-style receive steering.
/// PERF: Toeplitz hash would be ideal but Wyhash is faster for software steering.
pub const FlowKey = struct {
    src_addr: Address,
    dst_addr: Address,
    src_port: u16,
    dst_port: u16,
    protocol: TransportProtocolNumber,

    pub fn hash(self: FlowKey) u64 {
        var h = std.hash.Wyhash.init(0x5A5A5A5A);
        switch (self.src_addr) {
            .v4 => |v| h.update(&v),
            .v6 => |v| h.update(&v),
        }
        switch (self.dst_addr) {
            .v4 => |v| h.update(&v),
            .v6 => |v| h.update(&v),
        }
        h.update(std.mem.asBytes(&self.src_port));
        h.update(std.mem.asBytes(&self.dst_port));
        h.update(std.mem.asBytes(&self.protocol));
        return h.final();
    }

    /// Map flow to a queue index for multi-queue steering.
    pub fn toQueueIndex(self: FlowKey, num_queues: u16) u16 {
        return @intCast(self.hash() % num_queues);
    }
};

test "FlowKey steering consistency" {
    const flow = FlowKey{
        .src_addr = .{ .v4 = .{ 10, 0, 0, 1 } },
        .dst_addr = .{ .v4 = .{ 10, 0, 0, 2 } },
        .src_port = 12345,
        .dst_port = 80,
        .protocol = IPProtocol.TCP,
    };

    const q1 = flow.toQueueIndex(8);
    const q2 = flow.toQueueIndex(8);
    try std.testing.expectEqual(q1, q2);
}

/// Packet queued waiting for ARP resolution.
pub const ArpPendingEntry = struct {
    pkt: PacketBuffer,
    next_hop: Address,
    net_proto: NetworkProtocolNumber,
    timestamp_ms: i64,
};

/// Queue for packets pending ARP resolution.
/// NOTE: Packets are held here when the destination MAC is unknown.
/// Once ARP completes, addLinkAddress triggers drain.
pub const ArpPendingQueue = struct {
    entries: std.ArrayList(ArpPendingEntry),
    max_entries: usize,
    timeout_ms: i64,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) ArpPendingQueue {
        return .{
            .entries = std.ArrayList(ArpPendingEntry).init(allocator),
            .max_entries = max_entries,
            .timeout_ms = 1000, // 1 second default
        };
    }

    pub fn deinit(self: *ArpPendingQueue) void {
        self.entries.deinit();
    }

    pub fn enqueue(self: *ArpPendingQueue, entry: ArpPendingEntry) !void {
        if (self.entries.items.len >= self.max_entries) {
            // Drop oldest entry (FIFO eviction)
            _ = self.entries.orderedRemove(0);
        }
        try self.entries.append(entry);
    }

    /// Drain entries matching resolved address.
    pub fn drainForAddress(self: *ArpPendingQueue, addr: Address) std.ArrayList(ArpPendingEntry) {
        const allocator = self.entries.allocator;
        var result = std.ArrayList(ArpPendingEntry).init(allocator);

        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].next_hop.eq(addr)) {
                result.append(self.entries.orderedRemove(i)) catch {};
            } else {
                i += 1;
            }
        }

        return result;
    }

    /// Remove timed-out entries.
    pub fn expireOld(self: *ArpPendingQueue, now_ms: i64) usize {
        var removed: usize = 0;
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (now_ms - self.entries.items[i].timestamp_ms > self.timeout_ms) {
                _ = self.entries.orderedRemove(i);
                removed += 1;
            } else {
                i += 1;
            }
        }
        return removed;
    }
};

pub const Payloader = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        fullPayload: *const fn (ptr: *anyopaque) Error![]const u8,
        viewPayload: ?*const fn (ptr: *anyopaque) Error!buffer.VectorisedView = null,
    };

    pub fn fullPayload(self: Payloader) Error![]const u8 {
        return self.vtable.fullPayload(self.ptr);
    }

    pub fn viewPayload(self: Payloader) Error!buffer.VectorisedView {
        if (self.vtable.viewPayload) |f| return f(self.ptr);
        return Error.NotPermitted;
    }
};

pub const WriteOptions = struct {
    to: ?*const FullAddress = null,
};

pub const AcceptReturn = struct { ep: Endpoint, wq: *waiter.Queue };

pub const Endpoint = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        close: *const fn (ptr: *anyopaque) void,
        read: *const fn (ptr: *anyopaque, addr: ?*FullAddress) Error!buffer.VectorisedView,
        readv: ?*const fn (ptr: *anyopaque, uio: *buffer.Uio, addr: ?*FullAddress) Error!usize = null,
        write: *const fn (ptr: *anyopaque, p: Payloader, opts: WriteOptions) Error!usize,
        writev: ?*const fn (ptr: *anyopaque, uio: *buffer.Uio, opts: WriteOptions) Error!usize = null,
        writeView: ?*const fn (ptr: *anyopaque, view: buffer.VectorisedView, opts: WriteOptions) Error!usize = null,
        writeZeroCopy: ?*const fn (ptr: *anyopaque, data: []u8, cb: buffer.ConsumptionCallback, opts: WriteOptions) Error!usize = null,
        ready: ?*const fn (ptr: *anyopaque, mask: waiter.EventMask) bool = null,
        connect: *const fn (ptr: *anyopaque, addr: FullAddress) Error!void,
        shutdown: *const fn (ptr: *anyopaque, flags: u8) Error!void,
        listen: *const fn (ptr: *anyopaque, backlog: i32) Error!void,
        accept: *const fn (ptr: *anyopaque) Error!AcceptReturn,
        bind: *const fn (ptr: *anyopaque, addr: FullAddress) Error!void,
        getLocalAddress: *const fn (ptr: *anyopaque) Error!FullAddress,
        getRemoteAddress: *const fn (ptr: *anyopaque) Error!FullAddress,
        setReceiveWindow: ?*const fn (ptr: *anyopaque, size: u32) void = null,
        writeBatch: ?*const fn (ptr: *anyopaque, views: []const buffer.VectorisedView, opts: WriteOptions) Error!usize = null,
        setOption: *const fn (ptr: *anyopaque, opt: EndpointOption) Error!void,
        getOption: *const fn (ptr: *anyopaque, opt: EndpointOptionType) EndpointOption,
    };

    pub fn close(self: Endpoint) void {
        self.vtable.close(self.ptr);
    }
    pub fn read(self: Endpoint, addr: ?*FullAddress) Error!buffer.VectorisedView {
        return self.vtable.read(self.ptr, addr);
    }
    pub fn readv(self: Endpoint, uio: *buffer.Uio, addr: ?*FullAddress) Error!usize {
        if (self.vtable.readv) |f| return f(self.ptr, uio, addr);
        return Error.NotPermitted;
    }
    pub fn write(self: Endpoint, p: Payloader, opts: WriteOptions) Error!usize {
        return self.vtable.write(self.ptr, p, opts);
    }
    pub fn writev(self: Endpoint, uio: *buffer.Uio, opts: WriteOptions) Error!usize {
        if (self.vtable.writev) |f| return f(self.ptr, uio, opts);
        return Error.NotPermitted;
    }
    pub fn writeView(self: Endpoint, view: buffer.VectorisedView, opts: WriteOptions) Error!usize {
        if (self.vtable.writeView) |f| return f(self.ptr, view, opts);
        return Error.NotPermitted;
    }
    pub fn writeZeroCopy(self: Endpoint, data: []u8, cb: buffer.ConsumptionCallback, opts: WriteOptions) Error!usize {
        if (self.vtable.writeZeroCopy) |f| return f(self.ptr, data, cb, opts);
        return Error.NotPermitted;
    }
    pub fn ready(self: Endpoint, mask: waiter.EventMask) bool {
        if (self.vtable.ready) |f| return f(self.ptr, mask);
        return false;
    }
    pub fn connect(self: Endpoint, addr: FullAddress) Error!void {
        return self.vtable.connect(self.ptr, addr);
    }
    pub fn bind(self: Endpoint, addr: FullAddress) Error!void {
        return self.vtable.bind(self.ptr, addr);
    }
    pub fn listen(self: Endpoint, backlog: i32) Error!void {
        return self.vtable.listen(self.ptr, backlog);
    }
    pub fn accept(self: Endpoint) Error!AcceptReturn {
        return self.vtable.accept(self.ptr);
    }
    pub fn getLocalAddress(self: Endpoint) Error!FullAddress {
        return self.vtable.getLocalAddress(self.ptr);
    }
    pub fn getRemoteAddress(self: Endpoint) Error!FullAddress {
        return self.vtable.getRemoteAddress(self.ptr);
    }
    pub fn shutdown(self: Endpoint, flags: u8) Error!void {
        return self.vtable.shutdown(self.ptr, flags);
    }
    pub fn setOption(self: Endpoint, opt: EndpointOption) Error!void {
        return self.vtable.setOption(self.ptr, opt);
    }
    pub fn getOption(self: Endpoint, opt_type: EndpointOptionType) EndpointOption {
        return self.vtable.getOption(self.ptr, opt_type);
    }
};

pub const EndpointOptionType = enum {
    ts_enabled,
    reuse_address,
    congestion_control,
    tcp_nodelay,
};

pub const EndpointOption = union(EndpointOptionType) {
    ts_enabled: bool,
    reuse_address: bool,
    congestion_control: CongestionControlAlgorithm,
    tcp_nodelay: bool,
};

pub const CongestionControlAlgorithm = enum {
    new_reno,
    cubic,
    bbr,
};

pub const AddressWithPrefix = struct {
    address: Address,
    prefix_len: u8,

    pub fn toSubnet(self: AddressWithPrefix) Subnet {
        return .{
            .address = self.address,
            .prefix = self.prefix_len,
        };
    }
};

pub const Subnet = struct {
    address: Address,
    prefix: u8,

    pub fn contains(self: Subnet, addr: Address) bool {
        if (std.meta.activeTag(self.address) != std.meta.activeTag(addr)) {
            return false;
        }

        const prefix_bits = self.prefix;
        const bytes_to_check = prefix_bits / 8;
        const remaining_bits = prefix_bits % 8;
        var i: usize = 0;

        const self_buf = switch (self.address) {
            .v4 => |v| v[0..],
            .v6 => |v| v[0..],
        };
        const addr_buf = switch (addr) {
            .v4 => |v| v[0..],
            .v6 => |v| v[0..],
        };

        while (i < bytes_to_check) : (i += 1) {
            if (self_buf[i] != addr_buf[i]) {
                return false;
            }
        }

        if (remaining_bits > 0) {
            const mask = @as(u8, 0xFF) << @intCast(8 - remaining_bits);
            if ((self_buf[i] & mask) != (addr_buf[i] & mask)) {
                return false;
            }
        }

        return true;
    }

    pub fn gt(self: Subnet, other: u8) bool {
        return self.prefix > other;
    }

    pub fn getPrefix(self: Subnet) u8 {
        return self.prefix;
    }
};

pub const ProtocolAddress = struct {
    protocol: NetworkProtocolNumber,
    address_with_prefix: AddressWithPrefix,
};

pub const PacketBuffer = struct {
    data: buffer.VectorisedView,
    header: buffer.Prependable,

    link_header: ?buffer.View = null,
    network_header: ?buffer.View = null,
    transport_header: ?buffer.View = null,

    timestamp_ns: i64 = 0,

    pub fn clone(self: PacketBuffer, allocator: std.mem.Allocator) Error!PacketBuffer {
        return .{
            .data = try self.data.clone(allocator),
            .header = self.header,
            .timestamp_ns = self.timestamp_ns,
        };
    }

    /// Extract flow key from packet for receive steering.
    pub fn flowKey(self: PacketBuffer, net_proto: NetworkProtocolNumber, trans_proto: TransportProtocolNumber) ?FlowKey {
        // Would parse headers here in real implementation
        _ = self;
        _ = net_proto;
        _ = trans_proto;
        return null;
    }
};
