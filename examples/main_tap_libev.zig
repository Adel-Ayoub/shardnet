const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const waiter = ustack.waiter;
const buffer = ustack.buffer;
const header = ustack.header;

pub extern fn ioctl(fd: i32, request: u64, ...) i32;

const IFF_TAP = 0x0002;
const IFF_NO_PI = 0x1000;
const TUNSETIFF = 0x400454ca;

const struct_ifreq = extern struct {
    ifr_name: [16]u8,
    ifr_flags: i16,
    _padding: [22]u8,
};

pub const ev_loop = opaque {};
pub const ev_io = extern struct {
    active: i32 = 0,
    pending: i32 = 0,
    priority: i32 = 0,
    data: ?*anyopaque = null,
    cb: ?*const fn (loop: ?*ev_loop, w: *ev_io, revents: i32) callconv(.C) void = null,
    next: ?*anyopaque = null,
    fd: i32 = 0,
    events: i32 = 0,
    filled: [32]u8 = undefined,
};
pub const ev_timer = extern struct {
    active: i32 = 0,
    pending: i32 = 0,
    priority: i32 = 0,
    data: ?*anyopaque = null,
    cb: ?*const fn (loop: ?*ev_loop, w: *ev_timer, revents: i32) callconv(.C) void = null,
    at: f64 = 0,
    repeat: f64 = 0,
    filled: [32]u8 = undefined,
};

pub const EV_READ = 0x01;

pub extern fn my_ev_default_loop() ?*ev_loop;
pub extern fn my_ev_io_init(w: *ev_io, cb: ?*const fn (loop: ?*ev_loop, w: *ev_io, revents: i32) callconv(.C) void, fd: i32, events: i32) void;
pub extern fn my_ev_timer_init(w: *ev_timer, cb: ?*const fn (loop: ?*ev_loop, w: *ev_timer, revents: i32) callconv(.C) void, after: f64, repeat: f64) void;
pub extern fn my_ev_io_start(loop: ?*ev_loop, w: *ev_io) void;
pub extern fn my_ev_timer_start(loop: ?*ev_loop, w: *ev_timer) void;
pub extern fn my_ev_run(loop: ?*ev_loop) void;
pub extern fn my_tuntap_init(fd: i32, name: [*:0]const u8) i32;

// Implementation of TunTapEndpoint that actually works

// Global variables for libev callbacks
var global_stack: *stack.Stack = undefined;
var global_tap: *ustack.drivers.tap.Tap = undefined;

fn libev_io_cb(loop: ?*ev_loop, watcher: *ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    _ = global_tap.readPacket() catch |err| {
        if (err != error.WouldBlock) {
            std.debug.print("readPacket error: {}\n", .{err});
        }
    };
}

fn libev_timer_cb(loop: ?*ev_loop, watcher: *ev_timer, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    _ = global_stack.timer_queue.tick();
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var s = try ustack.init(allocator);
    global_stack = &s;

    var tap = try ustack.drivers.tap.Tap.init("tap0");
    global_tap = &tap;

    var eth_ep = ustack.link.eth.EthernetEndpoint.init(tap.linkEndpoint(), tap.address);
    try s.createNIC(1, eth_ep.linkEndpoint());

    // Configure IP
    const nic = s.nics.get(1).?;
    try nic.addAddress(.{
        .protocol = ustack.network.ipv4.ProtocolNumber,
        .address_with_prefix = .{ .address = .{ .v4 = .{ 10, 0, 0, 2 } }, .prefix_len = 24 },
    });
    try nic.addAddress(.{
        .protocol = ustack.network.arp.ProtocolNumber,
        .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 },
    });
    try nic.addAddress(.{
        .protocol = ustack.network.icmp.ProtocolNumber,
        .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 },
    });
    try nic.addAddress(.{
        .protocol = ustack.network.ipv6.ProtocolNumber,
        .address_with_prefix = .{ .address = .{ .v6 = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 } }, .prefix_len = 64 },
    });

    // Configure routing table with default gateway (10.0.0.1)
    // This enables access to internet via NAT/router on the host
    try s.addRoute(.{
        .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 },
        .gateway = .{ .v4 = .{ 10, 0, 0, 1 } },
        .nic = 1,
        .mtu = 1500,
    });

    std.debug.print("Example: TAP + Libev starting...\n", .{});

    const loop = my_ev_default_loop() orelse {
        std.debug.print("Failed to initialize libev loop\n", .{});
        return;
    };

    var io_watcher: ev_io = undefined;
    my_ev_io_init(&io_watcher, libev_io_cb, tap.fd, EV_READ);
    my_ev_io_start(loop, &io_watcher);

    var timer_watcher: ev_timer = undefined;
    my_ev_timer_init(&timer_watcher, libev_timer_cb, 0.01, 0.01); // 10ms ticks
    my_ev_timer_start(loop, &timer_watcher);

    const client_thread = try std.Thread.spawn(.{}, httpClientTask, .{&s});
    client_thread.detach();

    my_ev_run(loop);
}

fn httpClientTask(s: *stack.Stack) void {
    doHttpClient(s) catch |err| {
        std.debug.print("HTTP Client failed: {}\n", .{err});
    };
}

fn doHttpClient(s: *stack.Stack) !void {
    const hostname = "www.google.com";

    // Resolve hostname via DNS
    std.debug.print("Resolving {s}...\n", .{hostname});

    // Use ustack.dns resolver
    const dns_server = ustack.tcpip.Address{ .v4 = .{ 8, 8, 8, 8 } };
    var resolver = ustack.dns.Resolver.init(s, dns_server);

    const google_ip = resolver.resolve(hostname) catch |err| blk: {
        std.debug.print("DNS resolution failed: {}\n", .{err});
        std.debug.print("Falling back to known IP 142.250.190.4 (www.google.com)\n", .{});
        break :blk ustack.tcpip.Address{ .v4 = .{ 142, 250, 190, 4 } };
    };

    var wq = waiter.Queue{};
    const tcp_proto = s.transport_protocols.get(6).?;
    var ep = try tcp_proto.newEndpoint(s, ustack.network.ipv4.ProtocolNumber, &wq);
    defer ep.close();

    try ep.setOption(.{ .ts_enabled = true });

    try ep.bind(.{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 0 }); // ephemeral port

    // Helper to get v4 address bytes
    const dest_ip = switch (google_ip) {
        .v4 => |v| v,
        .v6 => |v| blk: {
            _ = v;
            break :blk [4]u8{ 142, 250, 190, 4 };
        },
    };

    std.debug.print("Connecting to {}.{}.{}.{}:80...\n", .{ dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3] });
    while (true) {
        ep.connect(.{ .nic = 0, .addr = google_ip, .port = 80 }) catch |err| {
            if (err == tcpip.Error.WouldBlock) {
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
        break;
    }

    // Wait for connection to be established
    const tcp_ep = @as(*ustack.transport.tcp.TCPEndpoint, @ptrCast(@alignCast(ep.ptr)));
    var connect_timeout: usize = 0;
    while (tcp_ep.state != .established) {
        if (tcp_ep.state == .error_state or tcp_ep.state == .closed) return error.ConnectFailed;
        std.time.sleep(10 * std.time.ns_per_ms);
        connect_timeout += 1;
        if (connect_timeout > 1000) return error.ConnectTimeout; // 10 seconds
    }

    std.debug.print("Connected to {s} (80)\n", .{hostname});

    // Construct HTTP request with proper Host header
    var request_buf: [256]u8 = undefined;
    const request = try std.fmt.bufPrint(&request_buf, "GET / HTTP/1.1\r\nHost: {s}\r\nUser-Agent: ustack/0.1\r\nConnection: close\r\n\r\n", .{hostname});

    const MyPayloader = struct {
        data: []const u8,
        pub fn payloader(self: *@This()) tcpip.Payloader {
            return .{ .ptr = self, .vtable = &.{ .fullPayload = fullPayload } };
        }
        fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
            return @as(*@This(), @ptrCast(@alignCast(ptr))).data;
        }
    };
    var fp = MyPayloader{ .data = request };
    while (true) {
        _ = ep.write(fp.payloader(), .{}) catch |err| {
            if (err == tcpip.Error.WouldBlock) {
                std.time.sleep(10 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
        break;
    }

    std.debug.print("Sent HTTP request to {s}\n", .{hostname});

    // Read response
    var total_received: usize = 0;
    while (true) {
        var view = ep.read(null) catch |err| {
            if (err == tcpip.Error.WouldBlock) {
                std.time.sleep(100 * std.time.ns_per_ms);
                continue;
            }
            break;
        };
        defer view.deinit();
        if (view.size == 0) {
            std.debug.print("EOF reached (peer closed connection)\n", .{});
            break;
        }
        total_received += view.size;
        const data = try view.toView(s.allocator);
        defer s.allocator.free(data);
        std.debug.print("{s}", .{data});

        // Stop after receiving reasonable amount of data
        if (total_received > 20000) break;
    }

    std.debug.print("\nTotal received: {} bytes. Closing gracefully...\n", .{total_received});

    try ep.shutdown(0);

    // Wait for stack to reach CLOSED state
    while (tcp_ep.state != .closed) {
        std.time.sleep(10 * std.time.ns_per_ms);
    }

    std.debug.print("Connection closed gracefully. Exiting in 1 second...\n", .{});
    std.time.sleep(1000 * std.time.ns_per_ms);
    std.process.exit(0);
}
