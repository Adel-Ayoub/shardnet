const std = @import("std");
const shardnet = @import("shardnet");
const stack = shardnet.stack;
const tcpip = shardnet.tcpip;
const buffer = shardnet.buffer;
const waiter = shardnet.waiter;
const header = shardnet.header;
const AfPacket = shardnet.drivers.af_packet.AfPacket;
const EventMultiplexer = shardnet.event_mux.EventMultiplexer;

const c = @cImport({
    @cInclude("ev.h");
});

var global_stack: stack.Stack = undefined;
var global_af_packet: AfPacket = undefined;
var global_eth: shardnet.link.eth.EthernetEndpoint = undefined;
var global_mux: ?*EventMultiplexer = null;

const MuxContext = union(enum) {
    server: *HttpServer,
    client: *HttpClient,
    connection: *Connection,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print("Usage: {s} <interface> <mode> <ip_address/cidr> [target_ip]\n", .{args[0]});
        return;
    }

    const ifname = args[1];
    const mode = args[2];
    const ip_cidr = args[3];

    global_stack = try shardnet.init(allocator);
    global_af_packet = try AfPacket.init(allocator, &global_stack.cluster_pool, ifname);
    global_eth = shardnet.link.eth.EthernetEndpoint.init(global_af_packet.linkEndpoint(), global_af_packet.address);
    try global_stack.createNIC(1, global_eth.linkEndpoint());

    var parts = std.mem.split(u8, ip_cidr, "/");
    const ip_str = parts.first();
    const prefix_str = parts.next() orelse "24";
    const addr_v4 = try parseIp(ip_str);
    const prefix_len = try std.fmt.parseInt(u8, prefix_str, 10);

    const nic = global_stack.nics.get(1).?;
    try nic.addAddress(.{
        .protocol = 0x0806,
        .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 },
    });
    try nic.addAddress(.{
        .protocol = 0x0800,
        .address_with_prefix = .{ .address = .{ .v4 = addr_v4 }, .prefix_len = prefix_len },
    });

    try global_stack.addRoute(.{
        .destination = .{ .address = .{ .v4 = addr_v4 }, .prefix = prefix_len },
        .gateway = .{ .v4 = .{ 0, 0, 0, 0 } },
        .nic = 1,
        .mtu = 1500,
    });
    try global_stack.addRoute(.{
        .destination = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 },
        .gateway = .{ .v4 = .{ 0, 0, 0, 0 } },
        .nic = 1,
        .mtu = 1500,
    });

    const loop = my_ev_default_loop();

    var io_watcher = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&io_watcher, libev_af_packet_cb, global_af_packet.fd, c.EV_READ);
    my_ev_io_start(loop, &io_watcher);

    var timer_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&timer_watcher, libev_timer_cb, 0.01, 0.01);
    my_ev_timer_start(loop, &timer_watcher);

    const mux = try EventMultiplexer.init(allocator);
    global_mux = mux;
    var mux_io = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&mux_io, libev_mux_cb, mux.fd(), c.EV_READ);
    my_ev_io_start(loop, &mux_io);

    if (std.mem.eql(u8, mode, "server")) {
        _ = try HttpServer.init(&global_stack, allocator, mux);
        my_ev_run(loop);
    } else if (std.mem.eql(u8, mode, "client")) {
        if (args.len < 5) return error.TargetIpRequired;
        const target_ip = try parseIp(args[4]);
        const client = try HttpClient.init(&global_stack, allocator, mux);
        try client.connect(target_ip, addr_v4);
        my_ev_run(loop);
    }
}

extern fn my_ev_default_loop() ?*anyopaque;
extern fn my_ev_io_init(w: *c.ev_io, cb: *const fn (?*anyopaque, *c.ev_io, i32) callconv(.C) void, fd: i32, events: i32) void;
extern fn my_ev_timer_init(w: *c.ev_timer, cb: *const fn (?*anyopaque, *c.ev_timer, i32) callconv(.C) void, after: f64, repeat: f64) void;
extern fn my_ev_io_start(loop: ?*anyopaque, w: *c.ev_io) void;
extern fn my_ev_timer_start(loop: ?*anyopaque, w: *c.ev_timer) void;
extern fn my_ev_run(loop: ?*anyopaque) void;

fn libev_af_packet_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    _ = global_af_packet.readPacket() catch |err| {
        std.debug.print("AF_PACKET read error: {}\n", .{err});
    };
}

fn libev_timer_cb(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    _ = global_stack.timer_queue.tick();
}

fn libev_mux_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    if (global_mux) |mux| {
        const ready = mux.pollReady() catch return;
        for (ready) |entry| {
            const ctx = @as(*MuxContext, @ptrCast(@alignCast(entry.context.?)));
            switch (ctx.*) {
                .server => |s| s.onAccept(),
                .client => |client| client.onEvent(),
                .connection => |conn| conn.onData(),
            }
        }
    }
}

const HttpServer = struct {
    listener: shardnet.tcpip.Endpoint,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    wait_entry: waiter.Entry,
    mux_ctx: MuxContext,

    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer) !*HttpServer {
        const self = try allocator.create(HttpServer);
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};
        const ep = try s.transport_protocols.get(6).?.newEndpoint(s, 0x0800, wq);
        try ep.bind(.{ .nic = 0, .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = 80 });
        try ep.listen(128);

        self.* = .{
            .listener = ep,
            .allocator = allocator,
            .mux = mux,
            .mux_ctx = .{ .server = self },
            .wait_entry = undefined,
        };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, EventMultiplexer.upcall);

        wq.eventRegister(&self.wait_entry, waiter.EventIn);
        return self;
    }

    fn onAccept(self: *HttpServer) void {
        while (true) {
            const res = self.listener.accept() catch |err| {
                if (err == tcpip.Error.WouldBlock) return;
                return;
            };
            std.debug.print("Accepted connection from {any}\n", .{res.ep.getRemoteAddress()});
            _ = Connection.init(self.allocator, res.ep, res.wq, self.mux) catch continue;
        }
    }
};

const Connection = struct {
    ep: shardnet.tcpip.Endpoint,
    wq: *waiter.Queue,
    allocator: std.mem.Allocator,
    wait_entry: waiter.Entry,
    mux_ctx: MuxContext,

    pub fn init(allocator: std.mem.Allocator, ep: shardnet.tcpip.Endpoint, wq: *waiter.Queue, mux: *EventMultiplexer) !*Connection {
        const self = try allocator.create(Connection);
        self.* = .{
            .ep = ep,
            .wq = wq,
            .allocator = allocator,
            .mux_ctx = .{ .connection = self },
            .wait_entry = undefined,
        };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, EventMultiplexer.upcall);
        wq.eventRegister(&self.wait_entry, waiter.EventIn | waiter.EventHUp | waiter.EventErr);
        return self;
    }

    fn onData(self: *Connection) void {
        var buf = self.ep.read(null) catch |err| {
            if (err == tcpip.Error.WouldBlock) return;
            self.close();
            return;
        };
        defer buf.deinit();
        if (buf.size == 0) {
            self.close();
            return;
        }
        std.debug.print("Server received {} bytes\n", .{buf.size});
        const response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nHello World!\n";
        const Payloader = struct {
            data: []const u8,
            pub fn payloader(ctx: *@This()) tcpip.Payloader {
                return .{ .ptr = ctx, .vtable = &.{ .fullPayload = fullPayload } };
            }
            fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
                return @as(*@This(), @ptrCast(@alignCast(ptr))).data;
            }
        };
        var p = Payloader{ .data = response };
        _ = self.ep.write(p.payloader(), .{}) catch {};
        self.close();
    }

    fn close(self: *Connection) void {
        std.debug.print("Closing server connection\n", .{});
        self.wq.eventUnregister(&self.wait_entry);
        self.ep.close();

        const alloc = self.allocator;
        alloc.destroy(self);
    }
};

const HttpClient = struct {
    ep: shardnet.tcpip.Endpoint,
    allocator: std.mem.Allocator,
    wait_entry: waiter.Entry,
    mux_ctx: MuxContext,
    state: enum { connecting, sending, receiving, closed } = .connecting,

    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer) !*HttpClient {
        const self = try allocator.create(HttpClient);
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};
        const ep = try s.transport_protocols.get(6).?.newEndpoint(s, 0x0800, wq);
        self.* = .{
            .ep = ep,
            .allocator = allocator,
            .mux_ctx = .{ .client = self },
            .wait_entry = undefined,
        };
        self.wait_entry = waiter.Entry.initWithUpcall(&self.mux_ctx, mux, EventMultiplexer.upcall);
        wq.eventRegister(&self.wait_entry, waiter.EventIn | waiter.EventOut | waiter.EventErr);
        return self;
    }

    pub fn connect(self: *HttpClient, target: [4]u8, local: [4]u8) !void {
        try self.ep.bind(.{ .nic = 0, .addr = .{ .v4 = local }, .port = 0 });
        _ = self.ep.connect(.{ .nic = 1, .addr = .{ .v4 = target }, .port = 80 }) catch |err| {
            if (err == tcpip.Error.WouldBlock) return;
            return err;
        };
    }

    fn onEvent(self: *HttpClient) void {
        const tcp_ep = @as(*shardnet.transport.tcp.TCPEndpoint, @ptrCast(@alignCast(self.ep.ptr)));
        switch (self.state) {
            .connecting => {
                if (tcp_ep.state == .established) {
                    std.debug.print("Client connected!\n", .{});
                    self.state = .sending;
                    self.sendRequest();
                } else if (tcp_ep.state == .error_state or tcp_ep.state == .closed) {
                    std.debug.print("Client connection failed\n", .{});
                    self.state = .closed;
                }
            },
            .sending => self.sendRequest(),
            .receiving => {
                while (true) {
                    var buf = self.ep.read(null) catch |err| {
                        if (err == tcpip.Error.WouldBlock) return;
                        self.state = .closed;
                        return;
                    };
                    defer buf.deinit();
                    if (buf.size == 0) {
                        std.debug.print("Client received EOF\n", .{});
                        return;
                    }
                    const data = buf.toView(self.allocator) catch return;
                    defer self.allocator.free(data);
                    std.debug.print("Client received: {s}", .{data});
                }
            },
            .closed => {},
        }
    }

    fn sendRequest(self: *HttpClient) void {
        const req = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";
        const Payloader = struct {
            data: []const u8,
            pub fn payloader(ctx: *@This()) tcpip.Payloader {
                return .{ .ptr = ctx, .vtable = &.{ .fullPayload = fullPayload } };
            }
            fn fullPayload(ptr: *anyopaque) tcpip.Error![]const u8 {
                return @as(*@This(), @ptrCast(@alignCast(ptr))).data;
            }
        };
        var p = Payloader{ .data = req };
        _ = self.ep.write(p.payloader(), .{}) catch |err| {
            if (err == tcpip.Error.WouldBlock) return;
            return;
        };
        self.state = .receiving;
    }
};

fn parseIp(str: []const u8) ![4]u8 {
    var it = std.mem.split(u8, str, ".");
    var out: [4]u8 = undefined;
    for (0..4) |i| out[i] = try std.fmt.parseInt(u8, it.next() orelse return error.InvalidIP, 10);
    return out;
}
