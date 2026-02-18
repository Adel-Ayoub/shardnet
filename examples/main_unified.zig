/// Unified entry point with auto-detection of best available driver.
///
/// Auto-detection order (best to worst):
/// 1. AF_XDP - Zero-copy, lowest latency (requires kernel >= 5.10, CAP_NET_ADMIN)
/// 2. AF_PACKET - Raw sockets, good performance (requires CAP_NET_RAW)
/// 3. TAP - Virtual interface, moderate performance (requires CAP_NET_ADMIN)
/// 4. Loopback - In-memory only, for testing

const std = @import("std");
const builtin = @import("builtin");
const args = @import("args.zig");
const shardnet = @import("shardnet");
const stack = shardnet.stack;
const tcpip = shardnet.tcpip;

const DriverType = enum {
    af_xdp,
    af_packet,
    tap,
    loopback,

    pub fn name(self: DriverType) []const u8 {
        return switch (self) {
            .af_xdp => "AF_XDP",
            .af_packet => "AF_PACKET",
            .tap => "TAP",
            .loopback => "Loopback",
        };
    }

    pub fn reason(self: DriverType) []const u8 {
        return switch (self) {
            .af_xdp => "zero-copy, lowest latency",
            .af_packet => "raw sockets, good performance",
            .tap => "virtual interface, moderate performance",
            .loopback => "in-memory only, for testing",
        };
    }
};

/// Check if AF_XDP is available.
fn canUseAfXdp() bool {
    if (builtin.os.tag != .linux) return false;

    // Check kernel version >= 5.10
    var utsname: std.posix.utsname = undefined;
    const rc = std.posix.system.uname(&utsname);
    if (rc != 0) return false;

    const release = std.mem.sliceTo(&utsname.release, 0);
    var it = std.mem.splitScalar(u8, release, '.');
    const major = std.fmt.parseInt(u32, it.next() orelse return false, 10) catch return false;
    const minor = std.fmt.parseInt(u32, it.next() orelse return false, 10) catch return false;

    if (major < 5 or (major == 5 and minor < 10)) return false;

    // Would also check for CAP_NET_ADMIN here
    return true;
}

/// Check if AF_PACKET is available.
fn canUseAfPacket() bool {
    if (builtin.os.tag != .linux) return false;
    // Would check for CAP_NET_RAW here
    return true;
}

/// Check if TAP is available.
fn canUseTap() bool {
    if (builtin.os.tag != .linux) return false;

    // Check if /dev/net/tun exists
    const file = std.fs.openFileAbsolute("/dev/net/tun", .{}) catch return false;
    file.close();
    return true;
}

/// Auto-detect best available driver.
fn detectDriver() DriverType {
    if (canUseAfXdp()) return .af_xdp;
    if (canUseAfPacket()) return .af_packet;
    if (canUseTap()) return .tap;
    return .loopback;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    const config = try args.parseCommonArgs(argv);

    if (config.help) {
        args.printCommonUsage(argv[0], "Unified (auto-detect)");
        std.debug.print("\nDriver selection:\n", .{});
        std.debug.print("  AF_XDP     Best performance (kernel >= 5.10, CAP_NET_ADMIN)\n", .{});
        std.debug.print("  AF_PACKET  Good performance (CAP_NET_RAW)\n", .{});
        std.debug.print("  TAP        Moderate performance (CAP_NET_ADMIN)\n", .{});
        std.debug.print("  Loopback   Testing only (no capabilities needed)\n", .{});
        return;
    }

    // Auto-detect driver
    const driver = detectDriver();

    // Print banner
    std.debug.print("\n", .{});
    std.debug.print("  ╔═══════════════════════════════════════╗\n", .{});
    std.debug.print("  ║     Network Stack (Unified)           ║\n", .{});
    std.debug.print("  ╚═══════════════════════════════════════╝\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("Driver selected: {s}\n", .{driver.name()});
    std.debug.print("Reason: {s}\n", .{driver.reason()});
    std.debug.print("Interface: {s}\n", .{if (config.interface.len > 0) config.interface else "(none)"});
    std.debug.print("IP Address: {s}/{}\n", .{ if (config.ip_address.len > 0) config.ip_address else "(none)", config.prefix_len });
    std.debug.print("Log Level: {s}\n", .{@tagName(config.log_level)});
    std.debug.print("\n", .{});

    // Initialize stack
    var s = try stack.Stack.init(allocator);
    defer s.deinit();

    // Create NIC based on selected driver
    switch (driver) {
        .loopback => {
            const loopback = try allocator.create(shardnet.drivers.loopback.LoopbackEndpoint);
            loopback.* = shardnet.drivers.loopback.LoopbackEndpoint.init();
            try s.createNIC(1, loopback.linkEndpoint());
            std.debug.print("Loopback interface created.\n", .{});
        },
        else => {
            std.debug.print("Driver {s} initialization would happen here.\n", .{driver.name()});
        },
    }

    std.debug.print("\nStack running. Press Ctrl+C to stop.\n", .{});

    // Run event loop
    s.run();

    std.debug.print("\nShutdown complete.\n", .{});
}
