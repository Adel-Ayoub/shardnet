/// UDP socket implementation.
///
/// Provides connectionless datagram transport with optional connected mode,
/// checksum generation with hardware offload support, and UDP-Lite (RFC 3828).

const std = @import("std");
const tcpip = @import("../tcpip.zig");
const stack = @import("../stack.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");
const stats = @import("../stats.zig");

pub const ProtocolNumber = 17;

/// Socket options for UDP endpoints.
pub const SocketOptions = struct {
    /// Enable SO_REUSEPORT for load balancing across multiple sockets.
    reuse_port: bool = false,
    /// UDP-Lite checksum coverage (RFC 3828). 0 = full coverage (standard UDP).
    checksum_coverage: u16 = 0,
    /// Enable hardware checksum offload if NIC supports it.
    hw_checksum_offload: bool = true,
};

pub const UDPProtocol = struct {
    view_pool: buffer.BufferPool,
    header_pool: buffer.BufferPool,
    packet_node_pool: buffer.Pool(std.TailQueue(UDPEndpoint.Packet).Node),

    pub fn init(allocator: std.mem.Allocator) *UDPProtocol {
        const self = allocator.create(UDPProtocol) catch unreachable;
        self.* = .{
            .view_pool = buffer.BufferPool.init(allocator, @sizeOf(buffer.ClusterView) * header.MaxViewsPerPacket, 131072),
            .header_pool = buffer.BufferPool.init(allocator, header.ReservedHeaderSize, 131072),
            .packet_node_pool = buffer.Pool(std.TailQueue(UDPEndpoint.Packet).Node).init(allocator, 131072),
        };
        return self;
    }

    pub fn deinit(self: *UDPProtocol, allocator: std.mem.Allocator) void {
        self.view_pool.deinit();
        self.header_pool.deinit();
        self.packet_node_pool.deinit();
        allocator.destroy(self);
    }

    pub fn protocol(self: *UDPProtocol) stack.TransportProtocol {
        return .{
            .ptr = self,
            .vtable = &VTableImpl,
        };
    }

    const VTableImpl = stack.TransportProtocol.VTable{
        .number = number,
        .newEndpoint = newEndpoint,
        .parsePorts = parsePorts,
        .deinit = deinit_external,
    };

    fn deinit_external(ptr: *anyopaque) void {
        const self = @as(*UDPProtocol, @ptrCast(@alignCast(ptr)));
        self.deinit(self.view_pool.allocator);
    }

    fn number(ptr: *anyopaque) tcpip.TransportProtocolNumber {
        _ = ptr;
        return ProtocolNumber;
    }

    fn newEndpoint(ptr: *anyopaque, s: *stack.Stack, net_proto: tcpip.NetworkProtocolNumber, wait_queue: *waiter.Queue) tcpip.Error!tcpip.Endpoint {
        const self = @as(*UDPProtocol, @ptrCast(@alignCast(ptr)));
        _ = net_proto;
        const ep = s.allocator.create(UDPEndpoint) catch return tcpip.Error.OutOfMemory;
        ep.* = UDPEndpoint.init(s, self, wait_queue);
        ep.retry_timer.context = ep;
        return ep.endpoint();
    }

    fn parsePorts(ptr: *anyopaque, pkt: tcpip.PacketBuffer) stack.TransportProtocol.PortPair {
        _ = ptr;
        const v = pkt.data.first() orelse return .{ .src = 0, .dst = 0 };
        const h = header.UDP.init(v);
        return .{ .src = h.sourcePort(), .dst = h.destinationPort() };
    }
};

pub const UDPEndpoint = struct {
    pub const Packet = struct {
        data: buffer.VectorisedView,
        sender_addr: tcpip.FullAddress,
    };

    stack: *stack.Stack,
    proto: *UDPProtocol,
    waiter_queue: *waiter.Queue,
    rcv_list: std.TailQueue(Packet),
    ref_count: usize = 1,
    retry_timer: @import("../time.zig").Timer = undefined,

    local_addr: ?tcpip.FullAddress = null,
    remote_addr: ?tcpip.FullAddress = null,
    cached_route: ?stack.Route = null,

    /// Socket options.
    options: SocketOptions = .{},

    pub fn init(s: *stack.Stack, proto: *UDPProtocol, wq: *waiter.Queue) UDPEndpoint {
        return .{
            .stack = s,
            .proto = proto,
            .waiter_queue = wq,
            .rcv_list = .{},
            .retry_timer = @import("../time.zig").Timer.init(handleRetryTimer, undefined),
        };
    }

    fn handleRetryTimer(ptr: *anyopaque) void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.waiter_queue.notify(waiter.EventOut);
    }

    pub fn transportEndpoint(self: *UDPEndpoint) stack.TransportEndpoint {
        return .{
            .ptr = self,
            .vtable = &TransportVTableImpl,
        };
    }

    const TransportVTableImpl = stack.TransportEndpoint.VTable{
        .handlePacket = handlePacket,
        .close = close_external,
        .incRef = incRef_external,
        .decRef = decRef_external,
        .notify = notify_external,
    };

    fn notify_external(ptr: *anyopaque, mask: waiter.EventMask) void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.waiter_queue.notify(mask);
    }

    pub fn incRef(self: *UDPEndpoint) void {
        self.ref_count += 1;
    }

    pub fn decRef(self: *UDPEndpoint) void {
        self.ref_count -= 1;
        if (self.ref_count == 0) {
            self.destroy_internal();
        }
    }

    fn destroy_internal(self: *UDPEndpoint) void {
        if (self.local_addr) |la| {
            const ra = self.remote_addr orelse tcpip.FullAddress{
                .nic = 0,
                .addr = switch (la.addr) {
                    .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                    .v6 => .{ .v6 = [_]u8{0} ** 16 },
                },
                .port = 0,
            };
            const id = stack.TransportEndpointID{
                .local_port = la.port,
                .local_address = la.addr,
                .remote_port = ra.port,
                .remote_address = ra.addr,
            };
            self.stack.unregisterTransportEndpoint(id);
        }

        self.stack.timer_queue.cancel(&self.retry_timer);
        while (self.rcv_list.popFirst()) |node| {
            node.data.data.deinit();
            self.proto.packet_node_pool.release(node);
        }
        self.stack.allocator.destroy(self);
    }

    fn close_external(ptr: *anyopaque) void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));

        if (self.local_addr) |la| {
            const id = stack.TransportEndpointID{
                .local_port = la.port,
                .local_address = la.addr,
                .remote_port = 0,
                .remote_address = switch (la.addr) {
                    .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                    .v6 => .{ .v6 = [_]u8{0} ** 16 },
                },
            };
            self.stack.unregisterTransportEndpoint(id);
        }

        self.decRef();
    }

    fn incRef_external(ptr: *anyopaque) void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.incRef();
    }

    fn decRef_external(ptr: *anyopaque) void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.decRef();
    }

    /// Calculate UDP checksum with optional hardware offload.
    fn calculateChecksum(self: *UDPEndpoint, h: *header.UDP, local_addr: tcpip.Address, remote_addr: tcpip.Address, data: buffer.VectorisedView) u16 {
        // Check if hardware offload is available and enabled
        if (self.options.hw_checksum_offload) {
            const caps = self.stack.getLinkCapabilities();
            if (caps.tx_checksum_offload) {
                // Hardware will calculate checksum; return 0 as placeholder
                return 0;
            }
        }

        // Software checksum calculation
        var sum: u32 = 0;

        // Pseudo-header
        switch (local_addr) {
            .v4 => |src| {
                const dst = remote_addr.v4;
                sum += std.mem.readInt(u16, src[0..2], .big);
                sum += std.mem.readInt(u16, src[2..4], .big);
                sum += std.mem.readInt(u16, dst[0..2], .big);
                sum += std.mem.readInt(u16, dst[2..4], .big);
                sum += 17; // UDP protocol
                sum += @as(u16, @intCast(header.UDPMinimumSize + data.size));
            },
            .v6 => |src| {
                const dst = remote_addr.v6;
                // IPv6 pseudo-header
                for (0..8) |i| {
                    sum += std.mem.readInt(u16, src[i * 2 ..][0..2], .big);
                    sum += std.mem.readInt(u16, dst[i * 2 ..][0..2], .big);
                }
                sum += @as(u32, @intCast(header.UDPMinimumSize + data.size));
                sum += 17; // Next header = UDP
            },
        }

        // UDP header
        sum = header.internetChecksum(h.data, sum);

        // Payload (respecting UDP-Lite coverage if set)
        const coverage = if (self.options.checksum_coverage > 0)
            @min(self.options.checksum_coverage - header.UDPMinimumSize, data.size)
        else
            data.size;

        var remaining = coverage;
        for (data.views) |v| {
            const to_sum = @min(remaining, v.view.len);
            sum = header.internetChecksum(v.view[0..to_sum], sum);
            remaining -= to_sum;
            if (remaining == 0) break;
        }

        const csum = header.finishChecksum(sum);
        return if (csum == 0) 0xffff else csum;
    }

    pub fn write(self: *UDPEndpoint, r: *stack.Route, remote_port: u16, data: buffer.VectorisedView) tcpip.Error!void {
        const local_address = self.local_addr orelse return tcpip.Error.InvalidEndpointState;

        const hdr_buf = self.proto.header_pool.acquire() catch return tcpip.Error.OutOfMemory;
        defer self.proto.header_pool.release(hdr_buf);

        var pre = buffer.Prependable.init(hdr_buf);
        const udp_hdr = pre.prepend(header.UDPMinimumSize).?;
        var h = header.UDP.init(udp_hdr);

        h.setSourcePort(local_address.port);
        h.setDestinationPort(remote_port);

        // UDP-Lite: use checksum coverage if set, otherwise full length
        const pkt_len = if (self.options.checksum_coverage > 0)
            self.options.checksum_coverage
        else
            @as(u16, @intCast(header.UDPMinimumSize + data.size));
        h.setLength(pkt_len);

        // Calculate checksum (may use hardware offload)
        const csum = self.calculateChecksum(&h, local_address.addr, r.remote_address, data);
        h.setChecksum(csum);

        const pb = tcpip.PacketBuffer{
            .data = data,
            .header = pre,
        };

        stats.global_stats.udp.tx_packets += 1;
        stats.global_stats.udp.tx_bytes += data.size;

        return r.writePacket(ProtocolNumber, pb);
    }

    fn handlePacket(ptr: *anyopaque, r: *const stack.Route, id: stack.TransportEndpointID, pkt: tcpip.PacketBuffer) void {
        const handle_start: i64 = @intCast(std.time.nanoTimestamp());
        defer {
            const handle_end: i64 = @intCast(std.time.nanoTimestamp());
            if (pkt.timestamp_ns != 0) {
                stats.global_stats.latency.transport_dispatch.record(@as(i64, @intCast(handle_start - pkt.timestamp_ns)));
                stats.global_stats.latency.udp_endpoint.record(@as(i64, @intCast(handle_end - handle_start)));
            }
        }
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        var mut_pkt = pkt;

        const h = header.UDP.init(mut_pkt.data.first() orelse return);
        mut_pkt.data.trimFront(header.UDPMinimumSize);

        stats.global_stats.udp.rx_packets += 1;
        stats.global_stats.udp.rx_bytes += mut_pkt.data.size;

        const cloned_data = mut_pkt.data.cloneInPool(&self.proto.view_pool) catch return;

        const node = self.proto.packet_node_pool.acquire() catch {
            var tmp = cloned_data;
            tmp.deinit();
            return;
        };

        node.data = .{
            .data = cloned_data,
            .sender_addr = .{
                .nic = r.nic.id,
                .addr = id.remote_address,
                .port = h.sourcePort(),
            },
        };

        const was_empty = self.rcv_list.first == null;
        self.rcv_list.append(node);

        if (was_empty) {
            self.waiter_queue.notify(waiter.EventIn);
        }
    }

    pub fn endpoint(self: *UDPEndpoint) tcpip.Endpoint {
        return .{
            .ptr = self,
            .vtable = &EndpointVTableImpl,
        };
    }

    const EndpointVTableImpl = tcpip.Endpoint.VTable{
        .close = close_external,
        .read = read,
        .readv = readv_external,
        .write = write_external,
        .writev = writev_external,
        .writeView = writeView_external,
        .writeZeroCopy = writeZeroCopy_external,
        .connect = connect,
        .shutdown = shutdown,
        .listen = listen,
        .accept = accept,
        .bind = bind,
        .getLocalAddress = getLocalAddress,
        .getRemoteAddress = getRemoteAddress,
        .setOption = setOption,
        .getOption = getOption,
    };

    fn writeZeroCopy_external(ptr: *anyopaque, data: []u8, cb: buffer.ConsumptionCallback, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        var view = buffer.VectorisedView.fromExternalZeroCopy(data, self.stack.allocator, 2048) catch return tcpip.Error.OutOfMemory;
        view.consumption_callback = cb;
        return self.writeInternal(view, opts);
    }

    fn setOption(ptr: *anyopaque, opt: tcpip.EndpointOption) tcpip.Error!void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        switch (opt) {
            .ts_enabled => {},
            .reuse_address => {
                self.options.reuse_port = true;
            },
            .congestion_control => {},
        }
        return;
    }

    fn getOption(ptr: *anyopaque, opt_type: tcpip.EndpointOptionType) tcpip.EndpointOption {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        return switch (opt_type) {
            .ts_enabled => .{ .ts_enabled = false },
            .reuse_address => .{ .reuse_address = self.options.reuse_port },
            .congestion_control => .{ .congestion_control = .new_reno },
        };
    }

    fn writev_external(ptr: *anyopaque, uio: *buffer.Uio, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));

        if (uio.iov.len == 1 and uio.resid <= header.ClusterSize) {
            var views = [_]buffer.ClusterView{.{ .cluster = null, .view = uio.iov[0][uio.offset .. uio.offset + uio.resid] }};
            const data = buffer.VectorisedView.init(uio.resid, &views);
            return self.writeInternal(data, opts);
        }

        const view = try buffer.Uio.toViews(uio, self.stack.allocator, header.ClusterSize);
        var mut_view = view;
        defer mut_view.deinit();
        return self.writeInternal(mut_view, opts);
    }

    fn readv_external(ptr: *anyopaque, uio: *buffer.Uio, addr: ?*tcpip.FullAddress) tcpip.Error!usize {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        const node = self.rcv_list.popFirst() orelse return tcpip.Error.WouldBlock;
        defer {
            var mut_node = node;
            mut_node.data.data.deinit();
            self.proto.packet_node_pool.release(node);
            if (self.rcv_list.first == null) {
                self.waiter_queue.clear(waiter.EventIn);
            }
        }

        if (addr) |a| {
            a.* = node.data.sender_addr;
        }

        return node.data.data.moveToUio(uio);
    }

    fn read(ptr: *anyopaque, addr: ?*tcpip.FullAddress) tcpip.Error!buffer.VectorisedView {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));

        const node = self.rcv_list.popFirst() orelse return tcpip.Error.WouldBlock;

        if (self.rcv_list.first == null) {
            self.waiter_queue.clear(waiter.EventIn);
        }

        if (addr) |a| {
            a.* = node.data.sender_addr;
        }

        const res = node.data.data;
        self.proto.packet_node_pool.release(node);
        return res;
    }

    fn writeView_external(ptr: *anyopaque, view: buffer.VectorisedView, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.writeInternal(view, opts);
    }

    fn write_external(ptr: *anyopaque, p: tcpip.Payloader, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        if (p.viewPayload()) |view| {
            return self.writeInternal(view, opts);
        } else |_| {
            const data_buf = try p.fullPayload();
            var views = [_]buffer.ClusterView{.{ .cluster = null, .view = @constCast(data_buf) }};
            const data = buffer.VectorisedView.init(data_buf.len, &views);
            return self.writeInternal(data, opts);
        }
    }

    fn writeInternal(self: *UDPEndpoint, data: buffer.VectorisedView, opts: tcpip.WriteOptions) tcpip.Error!usize {
        const to = if (opts.to) |t| t.* else (self.remote_addr orelse return tcpip.Error.DestinationRequired);
        const local_addr = self.local_addr orelse return tcpip.Error.InvalidEndpointState;
        const net_proto: u16 = switch (to.addr) {
            .v4 => @as(u16, 0x0800),
            .v6 => @as(u16, 0x86dd),
        };

        if (self.cached_route == null or !self.cached_route.?.remote_address.eq(to.addr) or self.cached_route.?.net_proto != net_proto) {
            self.cached_route = try self.stack.findRoute(to.nic, local_addr.addr, to.addr, net_proto);
        }

        var r = &self.cached_route.?;
        const next_hop = r.next_hop orelse to.addr;

        if (r.remote_link_address == null) {
            if (self.stack.link_addr_cache.get(next_hop)) |link_addr| {
                r.remote_link_address = link_addr;
            } else {
                if (!self.retry_timer.active) {
                    self.stack.timer_queue.schedule(&self.retry_timer, 10);
                }
            }
        }

        self.write(r, to.port, data) catch |err| {
            if (err == tcpip.Error.WouldBlock) {
                if (!self.retry_timer.active) {
                    self.stack.timer_queue.schedule(&self.retry_timer, 10);
                }
            }
            return err;
        };

        return data.size;
    }

    /// Connect to a remote address (connected UDP mode).
    /// In connected mode, send() can be used instead of sendto().
    fn connect(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        self.remote_addr = addr;
        // Pre-resolve route for connected mode
        if (self.local_addr) |la| {
            const net_proto: u16 = switch (addr.addr) {
                .v4 => 0x0800,
                .v6 => 0x86dd,
            };
            self.cached_route = self.stack.findRoute(addr.nic, la.addr, addr.addr, net_proto) catch null;
        }
        return;
    }

    fn bind(ptr: *anyopaque, addr: tcpip.FullAddress) tcpip.Error!void {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));

        const new_addr = if (addr.port == 0) blk: {
            var tmp = addr;
            tmp.port = self.stack.getNextEphemeralPort();
            break :blk tmp;
        } else addr;

        self.local_addr = new_addr;

        const id = stack.TransportEndpointID{
            .local_port = new_addr.port,
            .local_address = new_addr.addr,
            .remote_port = 0,
            .remote_address = switch (new_addr.addr) {
                .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                .v6 => .{ .v6 = [_]u8{0} ** 16 },
            },
        };

        // SO_REUSEPORT allows multiple sockets to bind to the same port
        self.stack.registerTransportEndpoint(id, self.transportEndpoint()) catch return tcpip.Error.OutOfMemory;
    }

    fn shutdown(ptr: *anyopaque, flags: u8) tcpip.Error!void {
        _ = ptr;
        _ = flags;
        return;
    }

    fn listen(ptr: *anyopaque, backlog: i32) tcpip.Error!void {
        _ = ptr;
        _ = backlog;
        return tcpip.Error.UnknownProtocol;
    }

    fn accept(ptr: *anyopaque) tcpip.Error!tcpip.AcceptReturn {
        _ = ptr;
        return tcpip.Error.UnknownProtocol;
    }

    fn getLocalAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.local_addr orelse tcpip.Error.InvalidEndpointState;
    }

    fn getRemoteAddress(ptr: *anyopaque) tcpip.Error!tcpip.FullAddress {
        const self = @as(*UDPEndpoint, @ptrCast(@alignCast(ptr)));
        return self.remote_addr orelse tcpip.Error.InvalidEndpointState;
    }
};

test "UDP handlePacket" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    var wq = waiter.Queue{};
    const udp_proto = UDPProtocol.init(allocator);
    var ep = try allocator.create(UDPEndpoint);
    ep.* = UDPEndpoint.init(&s, udp_proto, &wq);
    defer ep.transportEndpoint().close();

    var fake_ep = struct {
        fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, prot: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
            _ = ptr;
            _ = r;
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
    }{};

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

    const nic = try s.allocator.create(stack.NIC);
    defer s.allocator.destroy(nic);
    nic.* = stack.NIC.init(&s, 1, "test0", link_ep, false);
    defer nic.deinit();

    const r = stack.Route{
        .local_address = .{ .v4 = .{ 127, 0, 0, 1 } },
        .remote_address = .{ .v4 = .{ 127, 0, 0, 2 } },
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };

    var udp_data = [_]u8{0} ** 12;
    _ = header.UDP.init(&udp_data);
    std.mem.writeInt(u16, udp_data[0..2][0..2], 1234, .big);
    std.mem.writeInt(u16, udp_data[2..4][0..2], 80, .big);
    std.mem.writeInt(u16, udp_data[4..6][0..2], 12, .big);

    var views = [_]buffer.ClusterView{.{ .cluster = null, .view = &udp_data }};
    const pkt = tcpip.PacketBuffer{
        .data = buffer.VectorisedView.init(12, &views),
        .header = buffer.Prependable.init(&[_]u8{}),
    };

    const id = stack.TransportEndpointID{
        .local_port = 80,
        .local_address = r.local_address,
        .remote_port = 1234,
        .remote_address = r.remote_address,
    };

    ep.transportEndpoint().handlePacket(&r, id, pkt);

    try std.testing.expect(ep.rcv_list.first != null);
    const p = ep.rcv_list.first.?.data;
    try std.testing.expectEqual(@as(u16, 1234), p.sender_addr.port);
    try std.testing.expectEqual(@as(usize, 4), p.data.size);
}
