/// AF_XDP adapter for the network stack.
///
/// NOTE: Requires CAP_NET_RAW and CAP_NET_ADMIN capabilities.
/// Also requires kernel >= 5.10 for full zero-copy support.
/// Run with: sudo setcap cap_net_raw,cap_net_admin+ep <binary>

const std = @import("std");
const builtin = @import("builtin");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;

// Import shared config
const AdapterConfig = @import("af_packet_adapter.zig").AdapterConfig;

/// Minimum kernel version for AF_XDP zero-copy.
const MIN_KERNEL_VERSION = .{ .major = 5, .minor = 10 };

/// Check if the running kernel supports AF_XDP zero-copy.
fn checkKernelVersion() !void {
    // On Linux, parse /proc/version or use uname
    if (builtin.os.tag != .linux) {
        return error.UnsupportedOS;
    }

    var utsname: std.posix.utsname = undefined;
    const rc = std.posix.system.uname(&utsname);
    if (rc != 0) {
        return error.UnameFailure;
    }

    // Parse release string (e.g., "5.15.0-generic")
    const release = std.mem.sliceTo(&utsname.release, 0);
    var it = std.mem.splitScalar(u8, release, '.');

    const major_str = it.next() orelse return error.InvalidRelease;
    const minor_str = it.next() orelse return error.InvalidRelease;

    const major = std.fmt.parseInt(u32, major_str, 10) catch return error.InvalidRelease;
    const minor = std.fmt.parseInt(u32, minor_str, 10) catch return error.InvalidRelease;

    if (major < MIN_KERNEL_VERSION.major or
        (major == MIN_KERNEL_VERSION.major and minor < MIN_KERNEL_VERSION.minor))
    {
        std.debug.print("Error: AF_XDP zero-copy requires kernel >= {}.{}. ", .{
            MIN_KERNEL_VERSION.major,
            MIN_KERNEL_VERSION.minor,
        });
        std.debug.print("Current: {}.{}\n", .{ major, minor });
        return error.KernelTooOld;
    }
}

/// AF_XDP link endpoint wrapper using the real driver.
pub const AfXdpEndpoint = struct {
    driver: if (builtin.os.tag == .linux) ustack.drivers.af_xdp.AfXdp else void,
    config: AdapterConfig,

    pub fn init(allocator: std.mem.Allocator, if_name: []const u8, config: AdapterConfig) !AfXdpEndpoint {
        // NOTE: Check kernel version before attempting AF_XDP bind.
        if (config.zero_copy) {
            checkKernelVersion() catch |err| {
                if (err == error.KernelTooOld) {
                    std.debug.print("Falling back to copy mode.\n", .{});
                    var fallback_config = config;
                    fallback_config.zero_copy = false;
                    return initInternal(allocator, if_name, fallback_config);
                }
                return err;
            };
        }

        return initInternal(allocator, if_name, config);
    }

    fn initInternal(allocator: std.mem.Allocator, if_name: []const u8, config: AdapterConfig) !AfXdpEndpoint {
        if (builtin.os.tag != .linux) {
            return error.UnsupportedOS;
        }

        const driver = try ustack.drivers.af_xdp.AfXdp.init(allocator, if_name, 0);
        return AfXdpEndpoint{
            .driver = driver,
            .config = config,
        };
    }

    pub fn linkEndpoint(self: *AfXdpEndpoint) stack.LinkEndpoint {
        if (builtin.os.tag != .linux) {
            unreachable;
        }
        return self.driver.linkEndpoint();
    }

    pub fn deinit(self: *AfXdpEndpoint) void {
        if (builtin.os.tag == .linux) {
            self.driver.deinit();
        }
    }

    /// Call this when RX ring has data.
    pub fn onReadable(self: *AfXdpEndpoint) !void {
        if (builtin.os.tag == .linux) {
            try self.driver.poll();
        }
    }
};
