const std = @import("std");
const shardnet = @import("shardnet");
const stack = shardnet.stack;
const tcpip = shardnet.tcpip;
const waiter = shardnet.waiter;
const event_mux = shardnet.event_mux;

pub extern fn ioctl(fd: i32, request: u64, ...) i32;

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
};
pub const ev_timer = extern struct {
    active: i32 = 0,
    pending: i32 = 0,
    priority: i32 = 0,
    data: ?*anyopaque = null,
    cb: ?*const fn (loop: ?*ev_loop, w: *ev_timer, revents: i32) callconv(.C) void = null,
    at: f64 = 0,
    repeat: f64 = 0,
};

pub const EV_READ = 0x01;

pub extern fn my_ev_default_loop() ?*ev_loop;
pub extern fn my_ev_io_init(w: *ev_io, cb: ?*const fn (loop: ?*ev_loop, w: *ev_io, revents: i32) callconv(.C) void, fd: i32, events: i32) void;
pub extern fn my_ev_timer_init(w: *ev_timer, cb: ?*const fn (loop: ?*ev_loop, w: *ev_timer, revents: i32) callconv(.C) void, after: f64, repeat: f64) void;
pub extern fn my_ev_io_start(loop: ?*ev_loop, w: *ev_io) void;
pub extern fn my_ev_timer_start(loop: ?*ev_loop, w: *ev_timer) void;
pub extern fn my_ev_run(loop: ?*ev_loop) void;
pub extern fn my_set_if_up(name: [*:0]const u8) i32;
pub extern fn my_set_if_addr(name: [*:0]const u8, addr: [*:0]const u8) i32;

// Global variables for libev callbacks
var global_stack: *stack.Stack = undefined;
var global_tap: *shardnet.drivers.tap.Tap = undefined;
var global_mux: *event_mux.EventMultiplexer = undefined;

fn my_upcall(entry: *waiter.Entry) void {
    if (global_mux.ready_queue.push(entry) catch false) {
        const val: u64 = 1;
        _ = std.posix.write(global_mux.signal_fd, std.mem.asBytes(&val)) catch {};
    }
}

fn libev_tap_io_cb(loop: ?*ev_loop, watcher: *ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    _ = global_tap.readPacket() catch |err| {
        if (err != error.WouldBlock) {
            std.debug.print("readPacket error: {}\n", .{err});
        }
    };
}

var global_client: *HttpClient = undefined;
var last_retry: i64 = 0;

fn libev_timer_cb(loop: ?*ev_loop, watcher: *ev_timer, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    _ = global_stack.timer_queue.tick();

    const now = std.time.milliTimestamp();
    if (now - last_retry > 1000) {
        if (global_client.state == .sending) {
            std.debug.print("Retrying sendRequest...\n", .{});
            global_client.onEvent() catch {};
        }
        last_retry = now;
    }
}

fn libev_mux_cb(loop: ?*ev_loop, watcher: *ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    const ready_entries = global_mux.pollReady() catch return;
    for (ready_entries) |entry| {
        const client = @as(*HttpClient, @ptrCast(@alignCast(entry.context.?)));
        client.onEvent() catch |err| {
            if (err == tcpip.Error.WouldBlock) continue;
            std.debug.print("HTTP Client event error: {}\n", .{err});
            std.process.exit(1);
        };
    }
}

const HttpClient = struct {
    ep: shardnet.tcpip.Endpoint,
    wait_entry: shardnet.waiter.Entry,
    state: State = .initial,
    total_received: usize = 0,
    hostname: []const u8,
    allocator: std.mem.Allocator,

    const State = enum {
        initial,
        connecting,
        sending,
        receiving,
        done,
    };

    pub fn init(s: *stack.Stack, name: []const u8) !*HttpClient {
        const self = try s.allocator.create(HttpClient);
        const tcp_proto = s.transport_protocols.get(6).?;
        const wq = try s.allocator.create(shardnet.waiter.Queue);
        wq.* = .{};
        self.* = .{
            .ep = try tcp_proto.newEndpoint(s, shardnet.network.ipv4.ProtocolNumber, wq),
            .wait_entry = shardnet.waiter.Entry.init(self, my_upcall),
            .hostname = name,
            .allocator = s.allocator,
        };
        wq.eventRegister(&self.wait_entry, shardnet.waiter.EventIn | shardnet.waiter.EventOut | shardnet.waiter.EventErr);
        return self;
    }

    pub fn start(self: *HttpClient, ip: shardnet.tcpip.Address) !void {
        self.state = .connecting;
        std.debug.print("Connecting to {s} ({})\n", .{ self.hostname, ip });
        // Use 10.0.0.2 for shardnet endpoint
        try self.ep.bind(.{ .nic = 1, .addr = .{ .v4 = .{ 10, 0, 0, 2 } }, .port = 0 });
        self.ep.connect(.{ .nic = 0, .addr = ip, .port = 80 }) catch |err| {
            if (err != tcpip.Error.WouldBlock) return err;
        };
    }

    pub fn onEvent(self: *HttpClient) !void {
        switch (self.state) {
            .connecting => {
                const tcp_ep = @as(*shardnet.transport.tcp.TCPEndpoint, @ptrCast(@alignCast(self.ep.ptr)));
                if (tcp_ep.state == .established) {
                    std.debug.print("Connected to {s}\n", .{self.hostname});
                    self.state = .sending;
                    try self.sendRequest();
                } else if (tcp_ep.state == .error_state or tcp_ep.state == .closed) {
                    return error.ConnectFailed;
                }
            },
            .sending => {
                self.sendRequest() catch |err| {
                    if (err == tcpip.Error.WouldBlock) return;
                    std.debug.print("sendRequest error: {}\n", .{err});
                    std.process.exit(1);
                };
                self.state = .receiving;
            },
            .receiving => {
                while (true) {
                    var view = self.ep.read(null) catch |err| {
                        if (err == tcpip.Error.WouldBlock) return;
                        return err;
                    };
                    defer view.deinit();
                    // std.debug.print("Read {} bytes\n", .{view.size});
                    if (view.size == 0) {
                        std.debug.print("EOF reached. Total received: {} bytes\n", .{self.total_received});
                        self.state = .done;
                        self.ep.close();
                        std.process.exit(0);
                        return;
                    }
                    self.total_received += view.size;
                    const data = try view.toView(self.allocator);
                    defer self.allocator.free(data);
                    std.debug.print("{s}", .{data});
                    if (self.total_received > 20000) {
                        std.debug.print("SUCCESS: Received expected data from Google!\n", .{});
                        self.ep.close();
                        std.process.exit(0);
                    }
                }
            },
            else => {},
        }
    }

    fn sendRequest(self: *HttpClient) !void {
        var request_buf: [256]u8 = undefined;
        const request = try std.fmt.bufPrint(&request_buf, "GET / HTTP/1.1\r\nHost: {s}\r\nUser-Agent: shardnet/0.1\r\nConnection: close\r\n\r\n", .{self.hostname});
        const MyPayloader = struct {
            data: []const u8,
            pub fn payloader(ctx: *@This()) tcpip.Payloader {
                return .{ .ptr = ctx, .vtable = &.{ .fullPayload = fullPayload } };
            }
            fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
                return @as(*@This(), @ptrCast(@alignCast(ptr))).data;
            }
        };
        var fp = MyPayloader{ .data = request };
        _ = try self.ep.write(fp.payloader(), .{});
        std.debug.print("Sent HTTP request to {s}\n", .{self.hostname});
    }
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var s = try shardnet.init(allocator);
    global_stack = &s;

    var tap = try shardnet.drivers.tap.Tap.init("tap_mux");
    global_tap = &tap;

    // Set interface UP and IP (Gateway) from program
    _ = my_set_if_up("tap_mux");
    _ = my_set_if_addr("tap_mux", "10.0.0.1"); // Gateway address

    var eth_ep = shardnet.link.eth.EthernetEndpoint.init(tap.linkEndpoint(), tap.address);
    try s.createNIC(1, eth_ep.linkEndpoint());
    const nic = s.nics.get(1).?;
    try nic.addAddress(.{
        .protocol = shardnet.network.ipv4.ProtocolNumber,
        .address_with_prefix = .{ .address = .{ .v4 = .{ 10, 0, 0, 2 } }, .prefix_len = 24 }, // shardnet address
    });
    try nic.addAddress(.{
        .protocol = shardnet.network.arp.ProtocolNumber,
        .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 },
    });
    try s.addRoute(.{
        .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 },
        .gateway = .{ .v4 = .{ 10, 0, 0, 1 } }, // Gateway is 10.0.0.1
        .nic = 1,
        .mtu = 1500,
    });
    const loop = my_ev_default_loop() orelse return error.LibevInitFailed;
    var tap_watcher: ev_io = undefined;
    my_ev_io_init(&tap_watcher, libev_tap_io_cb, tap.fd, EV_READ);
    my_ev_io_start(loop, &tap_watcher);
    var timer_watcher: ev_timer = undefined;
    my_ev_timer_init(&timer_watcher, libev_timer_cb, 0.01, 0.01);
    my_ev_timer_start(loop, &timer_watcher);
    global_mux = try event_mux.EventMultiplexer.init(allocator);
    var mux_watcher: ev_io = undefined;
    my_ev_io_init(&mux_watcher, libev_mux_cb, global_mux.fd(), EV_READ);
    my_ev_io_start(loop, &mux_watcher);
    std.debug.print("Example: TAP + Libev + EventMux starting (No separate threads!)\n", .{});
    const client = try HttpClient.init(&s, "www.google.com");
    global_client = client;
    try client.start(.{ .v4 = .{ 142, 250, 190, 4 } });
    my_ev_run(loop);
}
