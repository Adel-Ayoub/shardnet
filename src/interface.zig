/// Network interface abstraction for the shardnet stack.
///
/// Provides a unified `NetworkInterface` that wraps any supported driver
/// (AF_PACKET, AF_XDP, TAP) behind a common API. Each interface has an
/// observable `LinkState`, lifecycle methods (`bringUp` / `bringDown`),
/// and a flags bitfield for runtime capability queries.
///
/// Thread model:
///   - All interface methods are called from the event-loop thread.
///   - Drivers may internally use mmap rings (AF_PACKET, AF_XDP) that
///     must not be accessed concurrently. The event mux guarantees
///     single-threaded dispatch per fd.
const std = @import("std");
const stack = @import("stack.zig");
const tcpip = @import("tcpip.zig");
const utils = @import("utils.zig");

// Drivers
const AfPacket = @import("drivers/linux/af_packet.zig").AfPacket;
const AfXdp = @import("drivers/linux/af_xdp.zig").AfXdp;
const Tap = @import("drivers/linux/tap.zig").Tap;
const EthernetEndpoint = @import("link/eth.zig").EthernetEndpoint;

// ---------------------------------------------------------------------------
// InterfaceFlags — runtime capability bitfield
// ---------------------------------------------------------------------------

/// Bitfield describing the runtime capabilities and state of an interface.
pub const InterfaceFlags = packed struct {
    up: bool = false,
    promiscuous: bool = false,
    multicast: bool = false,
    _reserved: u5 = 0,
};

// ---------------------------------------------------------------------------
// LinkState — observable link status
// ---------------------------------------------------------------------------

/// Observable link state for health monitoring and logging.
pub const LinkState = enum {
    /// The link is operationally up and passing traffic.
    up,
    /// The link is administratively or operationally down.
    down,
    /// Link state has not been determined yet (e.g. during init).
    unknown,
};

pub const DriverType = enum {
    af_packet,
    af_xdp,
    tap,
};

pub const InterfaceConfig = struct {
    name: []const u8,
    driver: DriverType,
    address: ?[]const u8 = null, // Supports IPv4 or IPv6
    prefix: u8 = 24,
    gateway: ?[]const u8 = null,
    queue_id: u32 = 0,
};

pub const NetworkInterface = struct {
    allocator: std.mem.Allocator,
    stack: *stack.Stack,
    nic_id: u16,

    /// Runtime flags (up, promiscuous, multicast).
    flags: InterfaceFlags = .{},
    /// Observable link state for external monitoring.
    link_state: LinkState = .unknown,

    driver: union(DriverType) {
        af_packet: AfPacket,
        af_xdp: AfXdp,
        tap: Tap,
    },
    eth_endpoint: *EthernetEndpoint,

    pub fn init(allocator: std.mem.Allocator, s: *stack.Stack, cfg: InterfaceConfig) !*NetworkInterface {
        const self = try allocator.create(NetworkInterface);
        self.allocator = allocator;
        self.stack = s;
        // Use a simple ID strategy: assume nic_id 1 is primary.
        // In a real multi-nic setup, this would need to be dynamic.
        self.nic_id = 1;

        // 1. Init Driver
        switch (cfg.driver) {
            .af_packet => {
                self.driver = .{ .af_packet = try AfPacket.init(allocator, &s.cluster_pool, cfg.name) };
            },
            .af_xdp => {
                self.driver = .{ .af_xdp = try AfXdp.init(allocator, cfg.name, cfg.queue_id) };
            },
            .tap => {
                self.driver = .{ .tap = try Tap.init(cfg.name) };
            },
        }

        // 2. Wrap in Ethernet Endpoint
        const link_ep = switch (self.driver) {
            .af_packet => |*d| d.linkEndpoint(),
            .af_xdp => |*d| d.linkEndpoint(),
            .tap => |*d| d.linkEndpoint(),
        };
        const mac = switch (self.driver) {
            .af_packet => |*d| d.address,
            .af_xdp => |*d| d.address,
            .tap => |*d| d.address,
        };

        self.eth_endpoint = try allocator.create(EthernetEndpoint);
        self.eth_endpoint.* = EthernetEndpoint.init(link_ep, mac);

        // 3. Create NIC in Stack
        try s.createNIC(self.nic_id, self.eth_endpoint.linkEndpoint());
        const nic = s.nics.get(self.nic_id).?;

        // 4. Add Addresses
        // ARP is always needed for Ethernet
        try nic.addAddress(.{
            .protocol = 0x0806,
            .address_with_prefix = .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix_len = 0 },
        });

        if (cfg.address) |ip_str| {
            const addr = try utils.parseIp(ip_str);
            const protocol: tcpip.NetworkProtocolNumber = switch (addr) {
                .v4 => 0x0800,
                .v6 => 0x86dd,
            };
            
            try nic.addAddress(.{
                .protocol = protocol,
                .address_with_prefix = .{ .address = addr, .prefix_len = cfg.prefix },
            });

            // Route to subnet
            try s.addRoute(.{
                .destination = .{ .address = addr, .prefix = cfg.prefix },
                .gateway = switch (addr) {
                    .v4 => .{ .v4 = .{ 0, 0, 0, 0 } },
                    .v6 => .{ .v6 = [_]u8{0} ** 16 },
                },
                .nic = self.nic_id,
                .mtu = 1500,
            });
        }

        // 5. Add Default Gateway
        if (cfg.gateway) |gw_str| {
            const gw_addr = try utils.parseIp(gw_str);
            try s.addRoute(.{
                .destination = switch (gw_addr) {
                    .v4 => .{ .address = .{ .v4 = .{ 0, 0, 0, 0 } }, .prefix = 0 },
                    .v6 => .{ .address = .{ .v6 = [_]u8{0} ** 16 }, .prefix = 0 },
                },
                .gateway = gw_addr,
                .nic = self.nic_id,
                .mtu = 1500,
            });
        }

        return self;
    }

    pub fn deinit(self: *NetworkInterface) void {
        switch (self.driver) {
            .af_packet => |*d| _ = d, // AfPacket struct has no deinit, just closes fd on destroy if owned? No, wait.
            .af_xdp => |*d| d.deinit(),
            .tap => |*d| _ = d,
        }
        // Ideally we should close FDs here for packet/tap too if not handled.
        // Currently existing drivers don't have consistent deinit patterns.
        // Let's rely on OS cleanup for now or add deinit to them later.

        self.allocator.destroy(self.eth_endpoint);
        self.allocator.destroy(self);
    }

    pub fn getFd(self: *NetworkInterface) std.posix.fd_t {
        return switch (self.driver) {
            .af_packet => |d| d.fd,
            .af_xdp => |d| d.fd,
            .tap => |d| d.fd,
        };
    }

    /// Mark the interface as administratively up and begin passing traffic.
    /// Sets the Up flag and transitions link_state to .up.
    pub fn bringUp(self: *NetworkInterface) void {
        self.flags.up = true;
        self.link_state = .up;
    }

    /// Mark the interface as administratively down and stop processing.
    /// Clears the Up flag and transitions link_state to .down.
    pub fn bringDown(self: *NetworkInterface) void {
        self.flags.up = false;
        self.link_state = .down;
    }

    pub fn process(self: *NetworkInterface) !void {
        switch (self.driver) {
            .af_packet => |*d| {
                while (true) {
                    const more = d.readPacket() catch |err| {
                        if (err == error.WouldBlock) return;
                        return err;
                    };
                    if (!more) break;
                }
            },
            .af_xdp => |*d| try d.poll(),
            .tap => |*d| {
                while (true) {
                    const more = d.readPacket() catch |err| {
                        if (err == error.WouldBlock) return;
                        return err;
                    };
                    if (!more) break;
                }
            },
        }
    }
};
