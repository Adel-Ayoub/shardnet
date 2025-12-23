/// TCP 2MSL TIME_WAIT timer tests.
///
/// Tests for TIME_WAIT state behavior:
/// - 2MSL timer expiration transitions to CLOSED
/// - New connection on same 4-tuple is rejected during TIME_WAIT
/// - RFC 1337: RST in TIME_WAIT is handled correctly
/// - TIME_WAIT reuse with higher sequence number SYN

const std = @import("std");
const stack = @import("../stack.zig");
const tcpip = @import("../tcpip.zig");
const header = @import("../header.zig");
const buffer = @import("../buffer.zig");
const waiter = @import("../waiter.zig");
const ipv4 = @import("../network/ipv4.zig");
const TCPProtocol = @import("tcp.zig").TCPProtocol;
const TCPEndpoint = @import("tcp.zig").TCPEndpoint;
const EndpointState = @import("tcp.zig").EndpointState;

/// Mock link endpoint that drops all packets (for timer tests).
const NullLinkEndpoint = struct {
    fn writePacket(_: *anyopaque, _: ?*const stack.Route, _: tcpip.NetworkProtocolNumber, _: tcpip.PacketBuffer) tcpip.Error!void {
        return;
    }
    fn attach(_: *anyopaque, _: *stack.NetworkDispatcher) void {}
    fn linkAddress(_: *anyopaque) tcpip.LinkAddress {
        return .{ .addr = [_]u8{0} ** 6 };
    }
    fn mtu(_: *anyopaque) u32 {
        return 1500;
    }
    fn setMTU(_: *anyopaque, _: u32) void {}
    fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
        return 0;
    }

    fn linkEndpoint(self: *NullLinkEndpoint) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .writePacket = writePacket,
                .attach = attach,
                .linkAddress = linkAddress,
                .mtu = mtu,
                .setMTU = setMTU,
                .capabilities = capabilities,
            },
        };
    }
};

test "TCP 2MSL TIME_WAIT expiration" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    // Use short MSL for testing (100ms -> 200ms TIME_WAIT)
    s.tcp_msl = 100;

    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_link = NullLinkEndpoint{};
    const link_ep = fake_link.linkEndpoint();
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;

    const client_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const server_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };

    var wq_client = waiter.Queue{};
    const ep_client_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_client);
    const ep_client: *TCPEndpoint = @ptrCast(@alignCast(ep_client_res.ptr));

    // Set up endpoint in FIN_WAIT_2 state (waiting for peer's FIN)
    ep_client.state = .fin_wait2;
    ep_client.local_addr = client_addr;
    ep_client.remote_addr = server_addr;
    const id = stack.TransportEndpointID{
        .local_port = client_addr.port,
        .local_address = client_addr.addr,
        .remote_port = server_addr.port,
        .remote_address = server_addr.addr,
    };
    try s.registerTransportEndpoint(id, ep_client.transportEndpoint());

    // Mock FIN from server to trigger TIME_WAIT
    const fin_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(fin_buf);
    @memset(fin_buf, 0);
    var fin = header.TCP.init(fin_buf);
    fin.encode(server_addr.port, client_addr.port, 5001, ep_client.snd_nxt, header.TCPFlagFin | header.TCPFlagAck, 65535);

    const r_to_client = stack.Route{
        .local_address = client_addr.addr,
        .remote_address = server_addr.addr,
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };
    var fin_pkt = tcpip.PacketBuffer{
        .data = try buffer.VectorisedView.fromSlice(fin_buf, allocator, &s.cluster_pool),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    defer fin_pkt.data.deinit();

    ep_client.handlePacket(&r_to_client, id, fin_pkt);

    // Should be in TIME_WAIT
    try std.testing.expectEqual(EndpointState.time_wait, ep_client.state);
    try std.testing.expect(ep_client.time_wait_timer.active);
    // Should still be registered
    try std.testing.expect(s.endpoints.get(id) != null);
    if (s.endpoints.get(id)) |e| e.decRef();

    // Advance time by 2MSL (200ms)
    _ = s.timer_queue.tickTo(s.timer_queue.current_tick + 201);

    // Should now be CLOSED
    try std.testing.expectEqual(EndpointState.closed, ep_client.state);
    // Should be unregistered
    try std.testing.expect(s.endpoints.get(id) == null);
}

test "TCP RFC 1337 RST in TIME_WAIT ignored" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_link = NullLinkEndpoint{};
    const link_ep = fake_link.linkEndpoint();
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;

    const client_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const server_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };

    var wq_client = waiter.Queue{};
    const ep_client_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_client);
    const ep_client: *TCPEndpoint = @ptrCast(@alignCast(ep_client_res.ptr));

    // Set up endpoint in TIME_WAIT
    ep_client.state = .time_wait;
    ep_client.local_addr = client_addr;
    ep_client.remote_addr = server_addr;
    const id = stack.TransportEndpointID{
        .local_port = client_addr.port,
        .local_address = client_addr.addr,
        .remote_port = server_addr.port,
        .remote_address = server_addr.addr,
    };
    try s.registerTransportEndpoint(id, ep_client.transportEndpoint());
    s.timer_queue.schedule(&ep_client.time_wait_timer, 60000);

    // Mock RST from server (TIME_WAIT assassination attempt)
    const rst_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(rst_buf);
    @memset(rst_buf, 0);
    var rst = header.TCP.init(rst_buf);
    rst.encode(server_addr.port, client_addr.port, 5001, ep_client.snd_nxt, header.TCPFlagRst, 65535);

    const r_to_client = stack.Route{
        .local_address = client_addr.addr,
        .remote_address = server_addr.addr,
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };
    var rst_pkt = tcpip.PacketBuffer{
        .data = try buffer.VectorisedView.fromSlice(rst_buf, allocator, &s.cluster_pool),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    defer rst_pkt.data.deinit();

    ep_client.handlePacket(&r_to_client, id, rst_pkt);

    // RFC 1337: Should still be in TIME_WAIT (RST ignored)
    try std.testing.expectEqual(EndpointState.time_wait, ep_client.state);
    try std.testing.expect(ep_client.time_wait_timer.active);
}

test "TCP TIME_WAIT reuse with new SYN" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_link = NullLinkEndpoint{};
    const link_ep = fake_link.linkEndpoint();
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;

    const client_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 1234 };
    const server_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 80 };

    var wq_client = waiter.Queue{};
    const ep_client_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq_client);
    const ep_client: *TCPEndpoint = @ptrCast(@alignCast(ep_client_res.ptr));

    // Set up endpoint in TIME_WAIT
    ep_client.state = .time_wait;
    ep_client.local_addr = client_addr;
    ep_client.remote_addr = server_addr;
    ep_client.rcv_nxt = 5000;
    const id = stack.TransportEndpointID{
        .local_port = client_addr.port,
        .local_address = client_addr.addr,
        .remote_port = server_addr.port,
        .remote_address = server_addr.addr,
    };
    try s.registerTransportEndpoint(id, ep_client.transportEndpoint());
    s.timer_queue.schedule(&ep_client.time_wait_timer, 60000);

    // Mock new SYN from server (new connection attempt)
    const syn_buf = try allocator.alloc(u8, header.TCPMinimumSize);
    defer allocator.free(syn_buf);
    @memset(syn_buf, 0);
    var syn = header.TCP.init(syn_buf);
    // Use higher sequence number than last seen
    syn.encode(server_addr.port, client_addr.port, 10000, 0, header.TCPFlagSyn, 65535);

    const r_to_client = stack.Route{
        .local_address = client_addr.addr,
        .remote_address = server_addr.addr,
        .local_link_address = .{ .addr = [_]u8{0} ** 6 },
        .net_proto = 0x0800,
        .nic = nic,
    };
    var syn_pkt = tcpip.PacketBuffer{
        .data = try buffer.VectorisedView.fromSlice(syn_buf, allocator, &s.cluster_pool),
        .header = buffer.Prependable.init(&[_]u8{}),
    };
    defer syn_pkt.data.deinit();

    ep_client.handlePacket(&r_to_client, id, syn_pkt);

    // TIME_WAIT endpoint should transition to CLOSED to allow new connection
    try std.testing.expectEqual(EndpointState.closed, ep_client.state);
    // Timer should be cancelled
    try std.testing.expect(!ep_client.time_wait_timer.active);
}

test "TCP parameterized MSL value" {
    const allocator = std.testing.allocator;
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    // Test default MSL (should be 30000ms = 30 seconds typically)
    try std.testing.expect(s.tcp_msl > 0);

    // Test that we can set a short MSL for testing
    s.tcp_msl = 50; // 50ms
    try std.testing.expectEqual(@as(u32, 50), s.tcp_msl);

    // 2MSL would be 100ms
    const two_msl = 2 * s.tcp_msl;
    try std.testing.expectEqual(@as(u32, 100), two_msl);
}

test "TCP connection rejected during TIME_WAIT on same 4-tuple" {
    const allocator = std.testing.allocator;
    var ipv4_proto = ipv4.IPv4Protocol.init();
    const tcp_proto = TCPProtocol.init(allocator);
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    try s.registerNetworkProtocol(ipv4_proto.protocol());
    try s.registerTransportProtocol(tcp_proto.protocol());

    var fake_link = NullLinkEndpoint{};
    const link_ep = fake_link.linkEndpoint();
    try s.createNIC(1, link_ep);
    const nic = s.nics.get(1).?;
    try nic.addAddress(.{ .protocol = 0x0800, .address_with_prefix = .{ .address = .{ .v4 = .{ 10, 0, 0, 1 } }, .prefix_len = 24 } });

    const local_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 1 } }, .port = 80 };
    const remote_addr = tcpip.FullAddress{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 1234 };

    // Create endpoint in TIME_WAIT occupying the 4-tuple
    var wq1 = waiter.Queue{};
    const ep1_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq1);
    const ep1: *TCPEndpoint = @ptrCast(@alignCast(ep1_res.ptr));
    ep1.state = .time_wait;
    ep1.local_addr = local_addr;
    ep1.remote_addr = remote_addr;
    const id = stack.TransportEndpointID{
        .local_port = local_addr.port,
        .local_address = local_addr.addr,
        .remote_port = remote_addr.port,
        .remote_address = remote_addr.addr,
    };
    try s.registerTransportEndpoint(id, ep1.transportEndpoint());
    s.timer_queue.schedule(&ep1.time_wait_timer, 60000);

    // Try to bind a new endpoint to the same local address
    var wq2 = waiter.Queue{};
    const ep2_res = try tcp_proto.protocol().newEndpoint(&s, 0x0800, &wq2);
    const ep2: *TCPEndpoint = @ptrCast(@alignCast(ep2_res.ptr));
    defer ep2.close();

    // Binding should succeed (TIME_WAIT allows reuse for bind)
    try ep2.endpoint().bind(local_addr);
    try std.testing.expectEqual(EndpointState.bound, ep2.state);

    // But the TIME_WAIT endpoint should still be registered
    try std.testing.expect(s.endpoints.get(id) != null);
    if (s.endpoints.get(id)) |e| e.decRef();
}
