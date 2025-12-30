const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const buffer = ustack.buffer;
const waiter = ustack.waiter;
const AfXdp = ustack.drivers.af_xdp.AfXdp;
const EventMultiplexer = ustack.event_mux.EventMultiplexer;

const c = @cImport({
    @cInclude("ev.h");
});

var global_stack: stack.Stack = undefined;
var global_af_xdp: AfXdp = undefined;
var global_eth: ustack.link.eth.EthernetEndpoint = undefined;
var global_mux: ?*EventMultiplexer = null;
var global_benchmark: Benchmark = undefined;

const MuxContext = union(enum) {
    server: *HttpServer,
    client: *HttpClient,
    connection: *Connection,
};

const AppEntry = struct {
    wait_entry: waiter.Entry,
    ctx: MuxContext,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        std.debug.print("Usage: {s} <interface> <mode> <ip_address/cidr> [target_ip]\n", .{args[0]});
        std.debug.print("  mode: server | benchmark\n", .{});
        return;
    }

    const ifname = args[1];
    const mode = args[2];
    const ip_cidr = args[3];

    global_stack = try ustack.init(allocator);

    // Initialize AF_XDP (queue 0)
    global_af_xdp = try AfXdp.init(allocator, ifname, 0);

    global_eth = ustack.link.eth.EthernetEndpoint.init(global_af_xdp.linkEndpoint(), global_af_xdp.address);
    try global_stack.createNIC(1, global_eth.linkEndpoint());

    var parts = std.mem.split(u8, ip_cidr, "/");
    const ip_str = parts.first();
    const prefix_str = parts.next() orelse "24";
    const addr_v4 = try parseIp(ip_str);
    const prefix_len = try std.fmt.parseInt(u8, prefix_str, 10);

    const nic = global_stack.nics.get(1).?;
    try nic.addAddress(.{
        .protocol = 0x0806, // ARP
        .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 },
    });
    try nic.addAddress(.{
        .protocol = 0x0800, // IPv4
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

    std.debug.print("AF_XDP: Interface {s} up with IP {s}/{d}\n", .{ ifname, ip_str, prefix_len });

    const loop = my_ev_default_loop();

    // Register AF_XDP FD (xsk_fd)
    var io_watcher = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&io_watcher, libev_af_xdp_cb, global_af_xdp.fd, c.EV_READ);
    my_ev_io_start(loop, &io_watcher);

    var timer_watcher = std.mem.zeroInit(c.ev_timer, .{});
    my_ev_timer_init(&timer_watcher, libev_timer_cb, 0.001, 0.001); // 1ms for high perf
    my_ev_timer_start(loop, &timer_watcher);

    const mux = try EventMultiplexer.init(allocator);
    global_mux = mux;
    var mux_io = std.mem.zeroInit(c.ev_io, .{});
    my_ev_io_init(&mux_io, libev_mux_cb, mux.fd(), c.EV_READ);
    my_ev_io_start(loop, &mux_io);

    if (std.mem.eql(u8, mode, "server")) {
        _ = try HttpServer.init(&global_stack, allocator, mux);
        my_ev_run(loop);
    } else if (std.mem.eql(u8, mode, "benchmark")) {
        if (args.len < 5) return error.TargetIpRequired;
        const target_ip = try parseIp(args[4]);

        global_benchmark = .{
            .allocator = allocator,
            .stack = &global_stack,
            .mux = mux,
            .target_ip = target_ip,
            .local_ip = addr_v4,
            .start_time = std.time.milliTimestamp(),
        };

        global_benchmark.start();
        my_ev_run(loop);
    }
}

extern fn my_ev_default_loop() ?*anyopaque;
extern fn my_ev_io_init(w: *c.ev_io, cb: *const fn (?*anyopaque, *c.ev_io, i32) callconv(.C) void, fd: i32, events: i32) void;
extern fn my_ev_timer_init(w: *c.ev_timer, cb: *const fn (?*anyopaque, *c.ev_timer, i32) callconv(.C) void, after: f64, repeat: f64) void;
extern fn my_ev_io_start(loop: ?*anyopaque, w: *c.ev_io) void;
extern fn my_ev_timer_start(loop: ?*anyopaque, w: *c.ev_timer) void;
extern fn my_ev_run(loop: ?*anyopaque) void;

fn libev_af_xdp_cb(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    global_af_xdp.poll() catch |err| {
        std.debug.print("AF_XDP poll error: {}\n", .{err});
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
            const app_entry: *AppEntry = @fieldParentPtr("wait_entry", entry);
            switch (app_entry.ctx) {
                .server => |s| s.onAccept(),
                .client => |client| client.onEvent(),
                .connection => |conn| conn.onData(),
            }
        }
    }
}

// Benchmark Logic
const Benchmark = struct {
    allocator: std.mem.Allocator,
    stack: *stack.Stack,
    mux: *EventMultiplexer,
    target_ip: [4]u8,
    local_ip: [4]u8,

    total_target: usize = 1000,
    concurrency_target: usize = 10,

    active_count: usize = 0,
    completed_count: usize = 0,
    failed_count: usize = 0,
    start_time: i64 = 0,

    pub fn start(self: *Benchmark) void {
        std.debug.print("Benchmark started: Target={}, Concurrency={}\n", .{ self.total_target, self.concurrency_target });
        self.start_time = std.time.milliTimestamp();
        self.spawnBatch();
    }

    fn spawnBatch(self: *Benchmark) void {
        while (self.active_count < self.concurrency_target and self.completed_count + self.active_count < self.total_target) {
            self.spawnOne() catch |err| {
                std.debug.print("Failed to spawn client: {}\n", .{err});
                break;
            };
        }
    }

    fn spawnOne(self: *Benchmark) !void {
        const client = try HttpClient.init(self.stack, self.allocator, self.mux);
        client.benchmark_ref = self;
        try client.connect(self.target_ip, self.local_ip);
        self.active_count += 1;
    }

    pub fn onClientDone(self: *Benchmark, success: bool) void {
        self.active_count -= 1;
        if (success) self.completed_count += 1 else self.failed_count += 1;

        if (self.completed_count % 10 == 0) {
            std.debug.print("Progress: {}/{} (Active: {})\n", .{ self.completed_count, self.total_target, self.active_count });
        }

        if (self.completed_count + self.failed_count >= self.total_target) {
            const duration = std.time.milliTimestamp() - self.start_time;
            std.debug.print("Benchmark Complete!\n", .{});
            std.debug.print("Total: {}, Success: {}, Failed: {}\n", .{ self.total_target, self.completed_count, self.failed_count });
            if (duration > 0) {
                std.debug.print("Time: {} ms, Rate: {} req/s\n", .{ duration, @divTrunc(self.completed_count * 1000, @as(usize, @intCast(duration))) });
            }
            std.process.exit(0);
        } else {
            self.spawnBatch();
        }
    }
};

const HttpClient = struct {
    ep: ustack.tcpip.Endpoint,
    wq: *waiter.Queue,
    allocator: std.mem.Allocator,
    app_entry: AppEntry,
    benchmark_ref: ?*Benchmark = null,
    state: enum { connecting, sending, receiving, closed } = .connecting,

    pub fn init(s: *stack.Stack, allocator: std.mem.Allocator, mux: *EventMultiplexer) !*HttpClient {
        const self = try allocator.create(HttpClient);
        const wq = try allocator.create(waiter.Queue);
        wq.* = .{};
        const ep = try s.transport_protocols.get(6).?.newEndpoint(s, 0x0800, wq);
        self.* = .{
            .ep = ep,
            .wq = wq,
            .allocator = allocator,
            .app_entry = .{
                .wait_entry = waiter.Entry.initWithUpcall(null, mux, EventMultiplexer.upcall),
                .ctx = .{ .client = self },
            },
        };
        wq.eventRegister(&self.app_entry.wait_entry, waiter.EventIn | waiter.EventOut | waiter.EventErr);
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
        const tcp_ep = @as(*ustack.transport.tcp.TCPEndpoint, @ptrCast(@alignCast(self.ep.ptr)));
        switch (self.state) {
            .connecting => {
                if (tcp_ep.state == .established) {
                    // std.debug.print("Client: Connected!\n", .{});
                    self.state = .sending;
                    self.sendRequest();
                } else if (tcp_ep.state == .error_state or tcp_ep.state == .closed) {
                    std.debug.print("Client: Connection failed (state={})\n", .{tcp_ep.state});
                    self.finish(false);
                }
            },
            .sending => self.sendRequest(),
            .receiving => {
                while (true) {
                    var buf = self.ep.read(null) catch |err| {
                        if (err == tcpip.Error.WouldBlock) return;
                        self.finish(false);
                        return;
                    };
                    defer buf.deinit();
                    if (buf.size == 0) {
                        self.finish(true);
                        return;
                    }
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
            self.finish(false);
            return;
        };
        self.state = .receiving;
    }

    fn finish(self: *HttpClient, success: bool) void {
        if (self.state == .closed) return;
        self.state = .closed;
        self.wq.eventUnregister(&self.app_entry.wait_entry);
        self.ep.close();
        self.allocator.destroy(self.wq);

        if (self.benchmark_ref) |bench| {
            bench.onClientDone(success);
        }
        self.allocator.destroy(self);
    }
};

const HttpServer = struct {
    listener: ustack.tcpip.Endpoint,
    allocator: std.mem.Allocator,
    mux: *EventMultiplexer,
    app_entry: AppEntry,

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
            .app_entry = .{
                .wait_entry = waiter.Entry.initWithUpcall(null, mux, EventMultiplexer.upcall),
                .ctx = .{ .server = self },
            },
        };
        wq.eventRegister(&self.app_entry.wait_entry, waiter.EventIn);
        return self;
    }

    fn onAccept(self: *HttpServer) void {
        while (true) {
            const res = self.listener.accept() catch |err| {
                if (err == tcpip.Error.WouldBlock) return;
                std.debug.print("Server accept error: {}\n", .{err});
                return;
            };
            std.debug.print("Server: Accepted connection\n", .{});
            _ = Connection.init(self.allocator, res.ep, res.wq, self.mux) catch continue;
        }
    }
};

const Connection = struct {
    ep: ustack.tcpip.Endpoint,
    wq: *waiter.Queue,
    allocator: std.mem.Allocator,
    app_entry: AppEntry,

    pub fn init(allocator: std.mem.Allocator, ep: ustack.tcpip.Endpoint, wq: *waiter.Queue, mux: *EventMultiplexer) !*Connection {
        const self = try allocator.create(Connection);
        self.* = .{
            .ep = ep,
            .wq = wq,
            .allocator = allocator,
            .app_entry = .{
                .wait_entry = waiter.Entry.initWithUpcall(null, mux, EventMultiplexer.upcall),
                .ctx = .{ .connection = self },
            },
        };
        wq.eventRegister(&self.app_entry.wait_entry, waiter.EventIn | waiter.EventHUp | waiter.EventErr);
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
        const response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
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
        self.wq.eventUnregister(&self.app_entry.wait_entry);
        self.ep.close();
        self.allocator.destroy(self);
    }
};

fn parseIp(str: []const u8) ![4]u8 {
    var it = std.mem.split(u8, str, ".");
    var out: [4]u8 = undefined;
    for (0..4) |i| out[i] = try std.fmt.parseInt(u8, it.next() orelse return error.InvalidIP, 10);
    return out;
}
