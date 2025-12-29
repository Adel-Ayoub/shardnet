/// Network stack entry point with CLI parsing and signal handling.

const std = @import("std");
const builtin = @import("builtin");

pub const buffer = @import("buffer.zig");
pub const header = @import("header.zig");
pub const log = @import("log.zig");
pub const stack = @import("stack.zig");
pub const waiter = @import("waiter.zig");
pub const time = @import("time.zig");
pub const tcpip = @import("tcpip.zig");
pub const network = struct {
    pub const ipv4 = @import("network/ipv4.zig");
    pub const ipv6 = @import("network/ipv6.zig");
    pub const arp = @import("network/arp.zig");
    pub const icmp = @import("network/icmp.zig");
    pub const icmpv6 = @import("network/icmpv6.zig");
};
pub const transport = struct {
    pub const udp = @import("transport/udp.zig");
    pub const tcp = @import("transport/tcp.zig");
    pub const congestion = struct {
        pub const control = @import("transport/congestion/control.zig");
        pub const cubic = @import("transport/congestion/cubic.zig");
        pub const bbr = @import("transport/congestion/bbr.zig");
    };
};
pub const link = struct {
    pub const eth = @import("link/eth.zig");
};
pub const dns = @import("dns.zig");
pub const posix = @import("posix.zig");
pub const event_mux = @import("event_mux.zig");
pub const stats = @import("stats.zig");

pub const drivers = struct {
    pub const loopback = @import("drivers/loopback.zig");
    pub const tap = if (builtin.os.tag == .linux) @import("drivers/linux/tap.zig") else struct {};
    pub const af_packet = if (builtin.os.tag == .linux) @import("drivers/linux/af_packet.zig") else struct {};
    pub const af_xdp = if (builtin.os.tag == .linux) @import("drivers/linux/af_xdp.zig") else struct {};
};

const VERSION = "0.1.0";

/// CLI arguments.
pub const Args = struct {
    interface: ?[]const u8 = null,
    ip_address: ?[]const u8 = null,
    gateway: ?[]const u8 = null,
    mtu: u32 = 1500,
    driver: Driver = .loopback,
    verbose: bool = false,
    help: bool = false,

    pub const Driver = enum {
        loopback,
        tap,
        af_packet,
        af_xdp,
    };
};

var global_stack: ?*stack.Stack = null;

fn signalHandler(sig: c_int) callconv(.C) void {
    _ = sig;
    if (global_stack) |s| {
        s.shutdown();
    }
}

fn setupSignalHandlers() void {
    const act = std.posix.Sigaction{
        .handler = .{ .handler = signalHandler },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null) catch {};
    std.posix.sigaction(std.posix.SIG.TERM, &act, null) catch {};
}

fn printBanner() void {
    const banner =
        \\
        \\  ╔═══════════════════════════════════════╗
        \\  ║     Network Stack v{s:<8}          ║
        \\  ║     TCP/IP Implementation             ║
        \\  ╚═══════════════════════════════════════╝
        \\
    ;
    std.debug.print(banner, .{VERSION});
}

fn printUsage() void {
    const usage =
        \\Usage: netstack [OPTIONS]
        \\
        \\Options:
        \\  -i, --interface <name>    Network interface name
        \\  -a, --address <ip>        IP address to bind (CIDR notation)
        \\  -g, --gateway <ip>        Default gateway
        \\  -m, --mtu <size>          MTU size (default: 1500)
        \\  -d, --driver <type>       Driver type: loopback, tap, af_packet, af_xdp
        \\  -v, --verbose             Enable verbose logging
        \\  -h, --help                Show this help message
        \\
        \\Examples:
        \\  netstack -i eth0 -a 10.0.0.1/24 -g 10.0.0.254
        \\  netstack -d tap -i tap0 -a 192.168.1.1/24
        \\
    ;
    std.debug.print("{s}", .{usage});
}

fn parseArgs(allocator: std.mem.Allocator) !Args {
    _ = allocator;
    var args = Args{};

    var arg_iter = std.process.args();
    _ = arg_iter.skip(); // Skip program name

    while (arg_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            args.help = true;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            args.verbose = true;
        } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--interface")) {
            args.interface = arg_iter.next();
        } else if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--address")) {
            args.ip_address = arg_iter.next();
        } else if (std.mem.eql(u8, arg, "-g") or std.mem.eql(u8, arg, "--gateway")) {
            args.gateway = arg_iter.next();
        } else if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--mtu")) {
            if (arg_iter.next()) |mtu_str| {
                args.mtu = std.fmt.parseInt(u32, mtu_str, 10) catch 1500;
            }
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--driver")) {
            if (arg_iter.next()) |driver_str| {
                if (std.mem.eql(u8, driver_str, "loopback")) {
                    args.driver = .loopback;
                } else if (std.mem.eql(u8, driver_str, "tap")) {
                    args.driver = .tap;
                } else if (std.mem.eql(u8, driver_str, "af_packet")) {
                    args.driver = .af_packet;
                } else if (std.mem.eql(u8, driver_str, "af_xdp")) {
                    args.driver = .af_xdp;
                }
            }
        }
    }

    return args;
}

pub fn init(allocator: std.mem.Allocator) !stack.Stack {
    var s = try stack.Stack.init(allocator);
    errdefer s.deinit();

    const ipv4_proto = try allocator.create(network.ipv4.IPv4Protocol);
    ipv4_proto.* = network.ipv4.IPv4Protocol.init();
    try s.registerNetworkProtocol(ipv4_proto.protocol());

    const ipv6_proto = try allocator.create(network.ipv6.IPv6Protocol);
    ipv6_proto.* = network.ipv6.IPv6Protocol.init();
    try s.registerNetworkProtocol(ipv6_proto.protocol());

    const arp_proto = try allocator.create(network.arp.ARPProtocol);
    arp_proto.* = network.arp.ARPProtocol.init();
    try s.registerNetworkProtocol(arp_proto.protocol());

    const icmp_proto = try allocator.create(network.icmp.ICMPv4Protocol);
    icmp_proto.* = network.icmp.ICMPv4Protocol.init();
    try s.registerNetworkProtocol(icmp_proto.protocol());

    const icmpv4_transport = try allocator.create(network.icmp.ICMPv4TransportProtocol);
    icmpv4_transport.* = network.icmp.ICMPv4TransportProtocol.init();
    try s.registerTransportProtocol(icmpv4_transport.protocol());

    const tcp_proto = transport.tcp.TCPProtocol.init(allocator);
    try s.registerTransportProtocol(tcp_proto.protocol());

    const udp_proto = transport.udp.UDPProtocol.init(allocator);
    try s.registerTransportProtocol(udp_proto.protocol());

    const icmpv6_proto = try allocator.create(network.icmpv6.ICMPv6TransportProtocol);
    icmpv6_proto.* = network.icmpv6.ICMPv6TransportProtocol.init();
    try s.registerTransportProtocol(icmpv6_proto.protocol());

    return s;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try parseArgs(allocator);

    if (args.help) {
        printUsage();
        return;
    }

    printBanner();

    setupSignalHandlers();

    var s = try init(allocator);
    defer s.deinit();

    global_stack = &s;
    defer global_stack = null;

    std.debug.print("Stack initialized, running...\n", .{});
    std.debug.print("Press Ctrl+C to shutdown\n\n", .{});

    s.run();

    std.debug.print("\nShutdown complete.\n", .{});
}

pub const interface = @import("interface.zig");
pub const utils = @import("utils.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("drivers/linux/test_af_xdp.zig");
    _ = @import("transport/tcp_test.zig");
    _ = @import("transport/tcp_2msl_test.zig");
}
