/// Shared argument parsing for all entry points.
///
/// All main_* entry points import this module for consistent CLI handling.

const std = @import("std");

/// Common configuration shared by all entry points.
pub const CommonConfig = struct {
    /// Network interface name (e.g., eth0, tap0).
    interface: []const u8 = "",
    /// Local IP address in dotted-decimal notation.
    ip_address: []const u8 = "",
    /// IP prefix length (CIDR notation).
    prefix_len: u8 = 24,
    /// Log level: debug, info, warn, error.
    log_level: LogLevel = .info,
    /// MTU size.
    mtu: u32 = 1500,
    /// Show help and exit.
    help: bool = false,

    pub const LogLevel = enum {
        debug,
        info,
        warn,
        err,

        pub fn fromString(s: []const u8) LogLevel {
            if (std.mem.eql(u8, s, "debug")) return .debug;
            if (std.mem.eql(u8, s, "info")) return .info;
            if (std.mem.eql(u8, s, "warn")) return .warn;
            if (std.mem.eql(u8, s, "error") or std.mem.eql(u8, s, "err")) return .err;
            return .info;
        }
    };
};

/// Parse common arguments from command line.
pub fn parseCommonArgs(args: []const []const u8) !CommonConfig {
    var config = CommonConfig{};

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--iface")) {
            i += 1;
            if (i >= args.len) return error.MissingInterface;
            config.interface = args[i];
        } else if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--ip")) {
            i += 1;
            if (i >= args.len) return error.MissingAddress;
            // Parse IP/prefix (e.g., 10.0.0.1/24)
            const ip_str = args[i];
            if (std.mem.indexOfScalar(u8, ip_str, '/')) |slash_idx| {
                config.ip_address = ip_str[0..slash_idx];
                config.prefix_len = std.fmt.parseInt(u8, ip_str[slash_idx + 1 ..], 10) catch 24;
            } else {
                config.ip_address = ip_str;
            }
        } else if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--mtu")) {
            i += 1;
            if (i >= args.len) return error.MissingMTU;
            config.mtu = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--log-level")) {
            i += 1;
            if (i >= args.len) return error.MissingLogLevel;
            config.log_level = CommonConfig.LogLevel.fromString(args[i]);
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            config.help = true;
        }
    }

    return config;
}

/// Print common usage information.
pub fn printCommonUsage(prog: []const u8, driver_name: []const u8) void {
    std.debug.print("Usage: {s} [OPTIONS]\n", .{prog});
    std.debug.print("\n{s} driver entry point\n", .{driver_name});
    std.debug.print("\nOptions:\n", .{});
    std.debug.print("  -i, --iface <name>     Network interface name\n", .{});
    std.debug.print("  -a, --ip <ip/prefix>   Local IP address (e.g., 10.0.0.1/24)\n", .{});
    std.debug.print("  -m, --mtu <size>       MTU size (default: 1500)\n", .{});
    std.debug.print("  --log-level <level>    Log level: debug, info, warn, error\n", .{});
    std.debug.print("  -h, --help             Show this help message\n", .{});
}

/// Parse IP address string to bytes.
pub fn parseIp(str: []const u8) ![4]u8 {
    var it = std.mem.splitScalar(u8, str, '.');
    var out: [4]u8 = undefined;
    for (0..4) |j| {
        out[j] = try std.fmt.parseInt(u8, it.next() orelse return error.InvalidIP, 10);
    }
    return out;
}

test "parseCommonArgs" {
    const args = [_][]const u8{ "prog", "-i", "eth0", "-a", "10.0.0.1/24", "--log-level", "debug" };
    const config = try parseCommonArgs(&args);
    try std.testing.expectEqualStrings("eth0", config.interface);
    try std.testing.expectEqualStrings("10.0.0.1", config.ip_address);
    try std.testing.expectEqual(@as(u8, 24), config.prefix_len);
    try std.testing.expectEqual(CommonConfig.LogLevel.debug, config.log_level);
}
