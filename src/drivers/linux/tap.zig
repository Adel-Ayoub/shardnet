/// Enhanced Linux TUN/TAP driver for the shardnet userspace network stack.
///
/// Provides a TAP (Layer 2 / Ethernet) device driver that communicates with
/// the Linux kernel via the `/dev/net/tun` character device.  Supports
/// single-queue and multi-queue (IFF_MULTI_QUEUE) modes, persistent devices
/// (TUNSETPERSIST), runtime MTU adjustment (SIOCSIFMTU), and event-driven
/// non-blocking I/O integrated with the shardnet EventMultiplexer.
///
/// ## /dev/net/tun open sequence
///
/// Creating a TAP device requires the following system calls.  Each step
/// that creates or configures the interface needs `CAP_NET_ADMIN`:
///
///   1. `open("/dev/net/tun", O_RDWR | O_NONBLOCK)`
///      Opens the TUN/TAP clone device.  `O_NONBLOCK` is set so that reads
///      return `EAGAIN` instead of blocking when no packet is available,
///      which is essential for event-loop integration.
///
///   2. `ioctl(fd, TUNSETIFF, &ifreq)`
///      Associates the open fd with a named TAP device.  The `ifreq`
///      carries the desired interface name (e.g. "tap0") and flags:
///        - `IFF_TAP`         (0x0002) — Layer 2 (Ethernet frames)
///        - `IFF_NO_PI`       (0x1000) — omit the 4-byte packet-info header
///        - `IFF_MULTI_QUEUE` (0x0100) — enable multi-queue mode (optional)
///
///   3. `ioctl(fd, TUNSETPERSIST, 1)`  *(optional)*
///      Makes the device persistent — it survives the closing process and
///      can be re-attached later.  Useful for orchestrator-managed topologies.
///
///   4. `ioctl(sock, SIOCSIFMTU, &ifreq)`  *(optional)*
///      Sets the kernel-side MTU on the interface.
///
///   5. Interface UP + IP assignment via `SIOCSIFFLAGS` / `SIOCSIFADDR`.
///
/// For multi-queue mode, steps 1–2 are repeated for each additional queue.
/// The kernel flow-hashes incoming packets across queues, improving RX
/// throughput on SMP systems.
///
/// ## Required capabilities
///
///   - `CAP_NET_ADMIN` — create/configure TAP devices, set routes and MTU.
///   - Alternatively, a privileged parent process can open the fd and hand
///     it to the unprivileged worker via `initFromFd()`.
///
/// ## Usage examples
///
/// Single-queue (backward compatible):
///   ```
///   var tap = try Tap.init("tap0");
///   const ep = tap.linkEndpoint();
///   ```
///
/// Multi-queue with event mux:
///   ```
///   var tap = try Tap.initWithConfig("tap0", .{
///       .num_queues = 4,
///       .persistent = true,
///       .mtu = 9000,
///   });
///   try tap.registerWithMux(mux);
///   ```
const std = @import("std");
const stack = @import("../../stack.zig");
const tcpip = @import("../../tcpip.zig");
const header = @import("../../header.zig");
const buffer = @import("../../buffer.zig");
const log = @import("../../log.zig").scoped(.tap);
const event_mux = @import("../../event_mux.zig");

// ---------------------------------------------------------------------------
// C interop — legacy helpers for single-queue TAP setup
// ---------------------------------------------------------------------------

// NOTE: The C wrapper my_tuntap_init handles the TUNSETIFF ioctl through a C
// struct to avoid Zig/C struct-layout mismatches for `struct ifreq`.  It sets
// IFF_TAP | IFF_NO_PI and issues ioctl(fd, TUNSETIFF, &ifr).  Kept for
// backward compatibility with the single-queue init path.
extern fn my_tuntap_init(fd: i32, name: [*:0]const u8) i32;

// ---------------------------------------------------------------------------
// Linux TUN/TAP ioctl constants (from <linux/if_tun.h>)
// ---------------------------------------------------------------------------

/// TUNSETIFF — associate an open /dev/net/tun fd with a named tun/tap device.
const TUNSETIFF: u32 = 0x400454ca;

/// TUNSETPERSIST — make the device persistent (1) or transient (0).
const TUNSETPERSIST: u32 = 0x400454cb;

/// TUNSETQUEUE — attach/detach a single queue on a multi-queue device.
const TUNSETQUEUE: u32 = 0x400454d9;

/// IFF_TAP — Layer 2 (Ethernet) mode, as opposed to IFF_TUN (Layer 3).
const IFF_TAP: u16 = 0x0002;

/// IFF_NO_PI — do not prepend the 4-byte packet-info header to each frame.
const IFF_NO_PI: u16 = 0x1000;

/// IFF_MULTI_QUEUE — enable multi-queue mode for SMP-scalable I/O.
/// Each open fd becomes an independent TX/RX queue; the kernel balances
/// incoming traffic across queues using flow-based hashing.
const IFF_MULTI_QUEUE: u16 = 0x0100;

// ---------------------------------------------------------------------------
// Standard Linux network ioctl constants (from <linux/sockios.h>)
// ---------------------------------------------------------------------------

/// SIOCSIFMTU — set the interface MTU.
const SIOCSIFMTU: u32 = 0x8922;

/// SIOCGIFMTU — get the interface MTU.
const SIOCGIFMTU: u32 = 0x8921;

// ---------------------------------------------------------------------------
// TunIfreq — minimal struct for the TUNSETIFF ioctl
// ---------------------------------------------------------------------------

/// Minimal ifreq-compatible layout for the TUNSETIFF ioctl.
///
/// NOTE: We define this explicitly rather than relying on std.os.linux.ifreq
/// to guarantee the field offsets match what the tun/tap driver expects.
/// `name` occupies bytes [0, 16), `flags` sits at byte 16 as a native-endian
/// i16, and the remaining 22 bytes are padding to the standard 40-byte ifreq
/// size.  Using a dedicated struct avoids the union-member ambiguity in the
/// generic ifreq definition.
const TunIfreq = extern struct {
    name: [16]u8 = [_]u8{0} ** 16,
    flags: i16 = 0,
    _pad: [22]u8 = [_]u8{0} ** 22,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Maximum number of hardware queues supported by the multi-queue TAP driver.
///
/// NOTE: 16 matches the typical NIC RSS queue limit and keeps the Tap struct
/// small enough for stack allocation (no heap-allocated fd array needed).
pub const MAX_QUEUES: u8 = 16;

/// Configuration for TAP device creation.  Sensible defaults are provided so
/// callers can simply pass `.{}` for the common single-queue case.
pub const Config = struct {
    /// Number of queues.  1 = legacy single-queue path; > 1 enables
    /// IFF_MULTI_QUEUE for SMP-scalable parallel packet processing.
    /// Each queue gets its own file descriptor that can be polled or
    /// registered with the event multiplexer independently.
    num_queues: u8 = 1,

    /// Make the TAP device persistent via TUNSETPERSIST.
    /// A persistent device is not destroyed when the creating process exits,
    /// allowing an orchestrator to pre-create topologies that worker processes
    /// attach to later.
    persistent: bool = false,

    /// Initial MTU (Maximum Transmission Unit) in bytes.
    /// Both the in-struct value and the kernel-side MTU (via SIOCSIFMTU) are
    /// set to this value.
    mtu: u32 = 1500,

    /// Bring the interface up and assign `ip_address` after creation.
    /// Set to false when the caller manages interface configuration externally
    /// (e.g. via netlink or `ip(8)`).
    auto_configure: bool = true,

    /// IPv4 address to assign when `auto_configure` is true.
    /// Passed as a null-terminated dotted-quad string (e.g. "10.0.0.1").
    ip_address: [*:0]const u8 = "10.0.0.1",
};

// ---------------------------------------------------------------------------
// Tap
// ---------------------------------------------------------------------------

/// A LinkEndpoint implementation for Linux TUN/TAP devices.
///
/// Supports single-queue and multi-queue operation, persistent devices,
/// runtime MTU changes, and integration with the shardnet EventMultiplexer
/// for non-blocking, event-driven packet I/O.
pub const Tap = struct {
    /// Primary file descriptor (queue 0).  Always valid after init.
    fd: std.posix.fd_t,

    /// Additional queue file descriptors for multi-queue mode.
    /// `queue_fds[0 .. num_queues-2]` hold the extra queues (queue 1 onward).
    /// Invalid entries are set to -1.  Only meaningful when `num_queues > 1`.
    ///
    // NOTE: Fixed-size array avoids a heap allocation for the common case
    // and keeps Tap embeddable in a tagged union (see interface.zig DriverType).
    queue_fds: [MAX_QUEUES - 1]std.posix.fd_t = [_]std.posix.fd_t{-1} ** (MAX_QUEUES - 1),

    /// Total number of active queues (always >= 1).
    num_queues: u8 = 1,

    /// Software MTU tracked by the driver.  Updated by setMTU (vtable) and
    /// setMtu (kernel ioctl) to stay in sync with the kernel interface.
    mtu_val: u32 = 1500,

    /// Link-layer (MAC) address.  Defaults to a locally-administered unicast
    /// address (02:00:00:00:00:01).
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 } },

    /// Network dispatcher set by stack.NIC.attach().  Incoming packets are
    /// delivered through this dispatcher to the protocol demux layer.
    // To be set by stack.NIC.attach()
    dispatcher: ?*stack.NetworkDispatcher = null,

    /// True if TUNSETPERSIST was successfully applied.
    persistent: bool = false,

    /// True if the device was created with IFF_MULTI_QUEUE.
    multi_queue: bool = false,

    /// Attached event multiplexer for epoll-driven I/O, or null when using
    /// manual polling.
    mux: ?*event_mux.EventMultiplexer = null,

    /// Stored device name for post-creation ioctls (SIOCSIFMTU, etc.).
    // NOTE: Stored as a fixed buffer so the name survives after the caller's
    // slice is freed, and to provide a null-terminated version for C helpers.
    dev_name_buf: [16]u8 = [_]u8{0} ** 16,
    dev_name_len: u8 = 0,

    // -- C interop externs (legacy helpers) ---------------------------------

    extern fn my_set_if_up(name: [*:0]const u8) i32;
    extern fn my_set_if_addr(name: [*:0]const u8, addr: [*:0]const u8) i32;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Initialize a TAP device by name (e.g., "tap0") with default settings.
    ///
    /// This is the backward-compatible entry point equivalent to the original
    /// driver.  Creates a single-queue TAP device, brings the interface up,
    /// and assigns IP 10.0.0.1.
    ///
    /// Equivalent to `initWithConfig(dev_name, .{})`.
    ///
    /// Note: This requires CAP_NET_ADMIN privileges.
    pub fn init(dev_name: []const u8) !Tap {
        return initWithConfig(dev_name, .{});
    }

    /// Initialize a TAP device with full configuration control.
    ///
    /// Opens `/dev/net/tun`, creates the named TAP interface, and optionally
    /// enables multi-queue mode, persistence, and auto-configuration.  See
    /// the module-level documentation for the complete open sequence.
    ///
    /// For multi-queue mode (`num_queues > 1`), the open + TUNSETIFF sequence
    /// is repeated for each queue fd.  Each fd becomes an independent I/O
    /// channel that the kernel load-balances across using flow-based hashing,
    /// improving throughput on multi-core systems.
    ///
    /// Required capabilities:
    ///   - CAP_NET_ADMIN to create/configure the TAP device.
    ///   - Alternatively, use `initFromFd()` with a pre-opened fd.
    pub fn initWithConfig(dev_name: []const u8, config: Config) !Tap {
        // -- Validate configuration -----------------------------------------
        if (config.num_queues == 0 or config.num_queues > MAX_QUEUES) {
            log.err("invalid num_queues={d}, must be 1..{d}", .{ config.num_queues, MAX_QUEUES });
            return error.InvalidConfiguration;
        }

        // -- Store device name for later ioctls (SIOCSIFMTU, etc.) ----------
        var name_buf: [16]u8 = [_]u8{0} ** 16;
        const copy_len: u8 = @intCast(@min(dev_name.len, 15));
        @memcpy(name_buf[0..copy_len], dev_name[0..copy_len]);

        const use_multi_queue = config.num_queues > 1;

        // NOTE: We initialize all fields explicitly rather than relying on
        // struct defaults to make the initial state obvious at a glance and
        // ensure no stale data leaks through from undefined memory.
        var tap = Tap{
            .fd = -1,
            .queue_fds = [_]std.posix.fd_t{-1} ** (MAX_QUEUES - 1),
            .num_queues = config.num_queues,
            .mtu_val = config.mtu,
            .address = .{ .addr = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 } },
            .dispatcher = null,
            .persistent = false,
            .multi_queue = use_multi_queue,
            .mux = null,
            .dev_name_buf = name_buf,
            .dev_name_len = copy_len,
        };

        if (use_multi_queue) {
            // -- Multi-queue path -------------------------------------------
            // NOTE: We perform the TUNSETIFF ioctl directly from Zig (via
            // openTunQueue) because the legacy C wrapper does not pass the
            // IFF_MULTI_QUEUE flag.  Each fd opened with the same interface
            // name and IFF_MULTI_QUEUE becomes a separate hardware queue.
            tap.fd = try openTunQueue(dev_name);
            errdefer std.posix.close(tap.fd);

            // Open additional queue fds
            var opened: u8 = 0;
            errdefer {
                var i: u8 = 0;
                while (i < opened) : (i += 1) {
                    std.posix.close(tap.queue_fds[i]);
                }
            }

            var q: u8 = 1;
            while (q < config.num_queues) : (q += 1) {
                tap.queue_fds[q - 1] = try openTunQueue(dev_name);
                opened += 1;
            }
        } else {
            // -- Single-queue path (legacy C wrapper) -----------------------
            // NOTE: The C wrapper my_tuntap_init handles struct layout
            // differences between Zig and C for the ifreq struct used by
            // TUNSETIFF.  We keep this path for backward compatibility with
            // existing C helper libraries.
            const fd = try std.posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR, .NONBLOCK = true }, 0);
            errdefer std.posix.close(fd);

            // Use C wrapper to avoid struct layout issues
            const name_c = try std.heap.page_allocator.dupeZ(u8, dev_name);
            defer std.heap.page_allocator.free(name_c);

            const rc = my_tuntap_init(fd, name_c);
            if (rc < 0) {
                log.err("my_tuntap_init failed: rc={}", .{rc});
                return error.TunsetiffFailed;
            }

            tap.fd = fd;
        }

        // -- Persistent mode ------------------------------------------------
        // NOTE: TUNSETPERSIST is applied after TUNSETIFF on the primary fd
        // only.  The kernel applies persistence to the interface as a whole,
        // so only one fd needs the flag.
        if (config.persistent) {
            try setPersistentRaw(tap.fd, true);
            tap.persistent = true;
            log.info("tap: enabled TUNSETPERSIST on fd={d}", .{tap.fd});
        }

        // -- Auto-configure (bring up + assign IP) --------------------------
        if (config.auto_configure) {
            const name_c = try std.heap.page_allocator.dupeZ(u8, dev_name);
            defer std.heap.page_allocator.free(name_c);

            // Set interface up and assign IP via our C helpers
            // Use the configured IP for the host side of the tap
            _ = my_set_if_up(name_c);
            _ = my_set_if_addr(name_c, config.ip_address);
        }

        // -- Set kernel MTU if non-default ----------------------------------
        // NOTE: The SIOCSIFMTU ioctl requires a regular socket fd (not the
        // tun clone fd).  setMtuKernel opens a temporary UDP socket internally.
        if (config.mtu != 1500) {
            tap.setMtuKernel(config.mtu) catch |err| {
                log.warn("tap: failed to set kernel MTU to {d}: {}", .{ config.mtu, err });
            };
        }

        log.info("tap: opened dev={s} fd={d} queues={d} persistent={} mtu={d}", .{
            dev_name,
            tap.fd,
            config.num_queues,
            config.persistent,
            config.mtu,
        });

        return tap;
    }

    /// Initialize from an existing file descriptor.
    ///
    /// Useful if the FD is passed from a privileged parent process that has
    /// already performed the `/dev/net/tun` open + TUNSETIFF sequence.  The
    /// caller is responsible for ensuring the fd is in non-blocking mode
    /// (`O_NONBLOCK`) if event-loop integration is desired.
    pub fn initFromFd(fd: std.posix.fd_t) Tap {
        return Tap{
            .fd = fd,
        };
    }

    /// Release all resources: close queue file descriptors, unregister from
    /// the event multiplexer, and close the primary fd.
    ///
    /// NOTE: Persistent mode is intentionally NOT cleared here.  If the
    /// device was made persistent, it should survive process exit.  Call
    /// `setPersistent(false)` explicitly before deinit if removal is desired.
    pub fn deinit(self: *Tap) void {
        // NOTE: Unregister from the mux first to prevent callbacks firing
        // on closed fds during the teardown window.
        if (self.mux != null) {
            self.unregisterFromMux();
        }

        // Close additional queue fds
        var i: u8 = 0;
        while (i < self.num_queues -| 1) : (i += 1) {
            if (self.queue_fds[i] != -1) {
                std.posix.close(self.queue_fds[i]);
                self.queue_fds[i] = -1;
            }
        }

        std.posix.close(self.fd);
    }

    // -----------------------------------------------------------------------
    // LinkEndpoint vtable
    // -----------------------------------------------------------------------

    /// Returns the polymorphic LinkEndpoint interface to register with the Stack.
    ///
    /// The returned vtable delegates all operations to this Tap instance,
    /// allowing the stack to drive the driver through a uniform interface
    /// regardless of the underlying transport (AF_PACKET, XDP, TAP, etc.).
    pub fn linkEndpoint(self: *Tap) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .writePacket = writePacket,
                .attach = attach,
                .linkAddress = linkAddress,
                .mtu = mtuVtable,
                .setMTU = setMTUVtable,
                .capabilities = capabilities,
                .close = closeVtable,
            },
        };
    }

    /// Vtable: write a single packet to the TAP device.
    fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        _ = r;
        _ = protocol;

        // We need to linearize the packet for write().
        const total_len = pkt.header.usedLength() + pkt.data.size;

        var buf = std.heap.page_allocator.alloc(u8, total_len) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(buf);

        const hdr_len = pkt.header.usedLength();
        @memcpy(buf[0..hdr_len], pkt.header.view());

        // Copy data
        const view = pkt.data.toView(std.heap.page_allocator) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(view);
        @memcpy(buf[hdr_len..], view);

        // NOTE: Writes always go to the primary fd (queue 0).  In multi-queue
        // mode the kernel distributes RX across queues, but TX from any single
        // queue is sufficient — the kernel handles egress scheduling internally.
        const rc = std.os.linux.write(self.fd, buf.ptr, buf.len);
        if (std.posix.errno(rc) != .SUCCESS) {
            log.err("writePacket failed: fd={}, rc={}, err={}", .{ self.fd, rc, std.posix.errno(rc) });
            return tcpip.Error.UnknownDevice;
        }
    }

    /// Vtable: attach a network dispatcher for inbound packet delivery.
    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        self.dispatcher = dispatcher;
    }

    /// Vtable: return the link-layer (MAC) address.
    fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        return self.address;
    }

    /// Vtable: return the current MTU.
    fn mtuVtable(ptr: *anyopaque) u32 {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        return self.mtu_val;
    }

    /// Vtable: update the software MTU (does not touch the kernel interface).
    fn setMTUVtable(ptr: *anyopaque, m: u32) void {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        self.mtu_val = m;
    }

    /// Vtable: return link-endpoint capabilities.
    fn capabilities(_: *anyopaque) stack.LinkEndpointCapabilities {
        // NOTE: TAP devices are behind the EthernetEndpoint wrapper (see
        // interface.zig) which adds CapabilityResolutionRequired.  At the
        // raw link level we report no special capabilities.
        return stack.CapabilityNone;
    }

    /// Vtable: close and release all resources.
    fn closeVtable(ptr: *anyopaque) void {
        const self = @as(*Tap, @ptrCast(@alignCast(ptr)));
        self.deinit();
    }

    // -----------------------------------------------------------------------
    // MTU management
    // -----------------------------------------------------------------------

    /// Set the MTU on both the kernel interface and the driver's internal value.
    ///
    /// Issues a `SIOCSIFMTU` ioctl to change the kernel-side MTU of the TAP
    /// interface, then updates the in-struct `mtu_val` to match.  This ensures
    /// the stack and the kernel agree on the maximum frame size.
    ///
    /// The device name must have been stored at init time (i.e., this does not
    /// work for Tap instances created via `initFromFd()` without a name).
    pub fn setMtu(self: *Tap, new_mtu: u32) !void {
        try self.setMtuKernel(new_mtu);
        self.mtu_val = new_mtu;
        log.info("tap: MTU set to {d}", .{new_mtu});
    }

    /// Internal helper: issue SIOCSIFMTU ioctl without updating mtu_val.
    fn setMtuKernel(self: *Tap, new_mtu: u32) !void {
        if (self.dev_name_len == 0) {
            return error.NoDeviceName;
        }

        // NOTE: SIOCSIFMTU requires a regular AF_INET socket fd, not the
        // tun clone fd.  We open a temporary UDP socket for this purpose
        // and close it immediately after the ioctl.
        const sock_fd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        defer std.posix.close(sock_fd);

        var ifr: std.os.linux.ifreq = undefined;
        @memset(std.mem.asBytes(&ifr), 0);
        @memcpy(ifr.ifrn.name[0..self.dev_name_len], self.dev_name_buf[0..self.dev_name_len]);
        ifr.ifru.ivalue = @as(i32, @intCast(new_mtu));

        try ioctlChecked(sock_fd, SIOCSIFMTU, @intFromPtr(&ifr));
    }

    // -----------------------------------------------------------------------
    // Persistent device management
    // -----------------------------------------------------------------------

    /// Enable or disable persistent mode on the TAP device.
    ///
    /// A persistent TAP device is not destroyed when the last fd referencing
    /// it is closed.  This is useful for pre-creating virtual network
    /// topologies that outlive the creating process.
    ///
    /// Requires CAP_NET_ADMIN.
    pub fn setPersistent(self: *Tap, enable: bool) !void {
        try setPersistentRaw(self.fd, enable);
        self.persistent = enable;
        log.info("tap: TUNSETPERSIST {s}", .{if (enable) "enabled" else "disabled"});
    }

    // -----------------------------------------------------------------------
    // Event multiplexer integration
    // -----------------------------------------------------------------------

    /// Register all queue file descriptors with the event multiplexer.
    ///
    /// After registration, the mux will invoke the internal read callback
    /// whenever a queue fd becomes readable.  This replaces manual polling
    /// and enables efficient epoll-driven packet reception.
    ///
    /// In multi-queue mode, each queue fd is registered separately so the mux
    /// can dispatch readiness per-queue, enabling true SMP parallelism when
    /// combined with per-CPU event loops.
    ///
    /// NOTE: The TAP fds must already be in non-blocking mode (O_NONBLOCK).
    /// The default init paths set this automatically.
    pub fn registerWithMux(self: *Tap, mux: *event_mux.EventMultiplexer) !void {
        // Register primary fd (queue 0)
        try mux.registerFd(.{
            .fd = self.fd,
            .user_data = self,
            .callback = muxReadCallback,
            // NOTE: Edge-triggered mode is used because the TAP fd is
            // non-blocking and the callback drains all available data
            // in a loop before returning.
            .edge_triggered = true,
        });

        // Register additional queue fds (queues 1..N-1)
        var i: u8 = 0;
        while (i < self.num_queues -| 1) : (i += 1) {
            if (self.queue_fds[i] != -1) {
                try mux.registerFd(.{
                    .fd = self.queue_fds[i],
                    .user_data = self,
                    .callback = muxReadCallback,
                    .edge_triggered = true,
                });
            }
        }

        self.mux = mux;
        log.info("tap: registered {d} queue(s) with event multiplexer", .{self.num_queues});
    }

    /// Unregister all queue fds from the event multiplexer.
    ///
    /// Safe to call even if not currently registered (no-op in that case).
    pub fn unregisterFromMux(self: *Tap) void {
        if (self.mux) |mux| {
            mux.unregisterFd(self.fd);

            var i: u8 = 0;
            while (i < self.num_queues -| 1) : (i += 1) {
                if (self.queue_fds[i] != -1) {
                    mux.unregisterFd(self.queue_fds[i]);
                }
            }

            self.mux = null;
        }
    }

    /// EventMultiplexer callback invoked when a queue fd is readable.
    ///
    // NOTE: The callback signature matches event_mux.FdHandler.callback.
    // We drain all available packets in a tight loop because edge-triggered
    // epoll requires exhaustive reads — missing data will not re-trigger
    // the notification.
    fn muxReadCallback(fd: std.posix.fd_t, user_data: ?*anyopaque) void {
        const self = @as(*Tap, @ptrCast(@alignCast(user_data.?)));

        while (true) {
            const got_packet = self.readPacketFromFd(fd) catch |err| {
                log.err("tap: mux read error on fd={d}: {}", .{ fd, err });
                return;
            };
            if (!got_packet) return;
        }
    }

    // -----------------------------------------------------------------------
    // RX path
    // -----------------------------------------------------------------------

    /// Read a single packet from the primary queue and deliver it to the stack.
    ///
    /// Returns `true` if a packet was read, `false` if no data was available
    /// (EAGAIN / EOF).  This is the backward-compatible entry point for
    /// single-queue polling loops.
    pub fn readPacket(self: *Tap) !bool {
        return self.readPacketFromFd(self.fd);
    }

    /// Read from all queues and deliver packets to the stack.
    ///
    /// Iterates over the primary fd and all additional queue fds, reading one
    /// available packet from each.  Returns `true` if at least one packet was
    /// read from any queue.
    ///
    /// This is the multi-queue equivalent of `readPacket()` for use in manual
    /// polling loops (without the event multiplexer).
    pub fn readAllQueues(self: *Tap) !bool {
        var any = try self.readPacketFromFd(self.fd);

        var i: u8 = 0;
        while (i < self.num_queues -| 1) : (i += 1) {
            if (self.queue_fds[i] != -1) {
                if (try self.readPacketFromFd(self.queue_fds[i])) {
                    any = true;
                }
            }
        }

        return any;
    }

    /// Read a single packet from the given fd and dispatch it to the stack.
    ///
    /// Shared implementation used by both `readPacket` (primary fd) and the
    /// multi-queue / event-mux paths.
    fn readPacketFromFd(self: *Tap, read_fd: std.posix.fd_t) !bool {
        var buf: [9000]u8 = undefined; // Support up to Jumbo frames
        const len = std.posix.read(read_fd, &buf) catch |err| {
            if (err == error.WouldBlock) return false;
            return err;
        };
        if (len == 0) return false; // EOF

        var views = [1]buffer.ClusterView{.{ .cluster = null, .view = buf[0..len] }};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(len, &views),
            .header = buffer.Prependable.init(&[_]u8{}),
            .timestamp_ns = @intCast(std.time.nanoTimestamp()),
        };

        if (self.dispatcher) |d| {
            const dst_mac = tcpip.LinkAddress{ .addr = buf[0..6].* };
            const src_mac = tcpip.LinkAddress{ .addr = buf[6..12].* };
            d.deliverNetworkPacket(&src_mac, &dst_mac, 0, pkt);
        }

        return true;
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Return the file descriptor for queue `idx`.
    ///
    /// Queue 0 is the primary fd; queues 1..num_queues-1 are the multi-queue
    /// fds.  Returns `error.InvalidQueue` if `idx` is out of range.
    pub fn queueFd(self: *const Tap, idx: u8) !std.posix.fd_t {
        if (idx == 0) return self.fd;
        if (idx >= self.num_queues) return error.InvalidQueue;
        const q_fd = self.queue_fds[idx - 1];
        if (q_fd == -1) return error.InvalidQueue;
        return q_fd;
    }

    /// Return the stored device name, or an empty slice if none was recorded.
    pub fn deviceName(self: *const Tap) []const u8 {
        return self.dev_name_buf[0..self.dev_name_len];
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Open `/dev/net/tun` and configure it as a multi-queue TAP device via
    /// a direct TUNSETIFF ioctl.
    ///
    /// Each call to this function with the same `name` attaches a new queue
    /// to the existing (or newly created) multi-queue TAP interface.
    ///
    // NOTE: This bypasses the C wrapper (my_tuntap_init) and uses a Zig-
    // defined TunIfreq struct so we can include IFF_MULTI_QUEUE in the flags.
    fn openTunQueue(name: []const u8) !std.posix.fd_t {
        // Step 1: open the clone device with O_RDWR | O_NONBLOCK.
        // O_NONBLOCK is critical for event-loop integration — reads return
        // EAGAIN instead of blocking when no packet is available.
        const fd = try std.posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR, .NONBLOCK = true }, 0);
        errdefer std.posix.close(fd);

        // Step 2: TUNSETIFF with IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE.
        var ifr = TunIfreq{};
        const copy_len = @min(name.len, 15);
        @memcpy(ifr.name[0..copy_len], name[0..copy_len]);
        ifr.flags = @bitCast(IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE);

        try ioctlChecked(fd, TUNSETIFF, @intFromPtr(&ifr));

        return fd;
    }

    /// Apply TUNSETPERSIST on a raw fd.
    ///
    // NOTE: TUNSETPERSIST takes an integer argument directly (not a pointer).
    // 1 = enable persistent mode, 0 = disable.
    fn setPersistentRaw(fd: std.posix.fd_t, enable: bool) !void {
        const arg: usize = if (enable) 1 else 0;
        try ioctlChecked(fd, TUNSETPERSIST, arg);
    }

    /// Thin ioctl wrapper that maps non-SUCCESS errno to `error.IoctlFailed`.
    fn ioctlChecked(fd: std.posix.fd_t, request: u32, arg: usize) !void {
        const rc = std.os.linux.ioctl(fd, request, arg);
        if (std.posix.errno(rc) != .SUCCESS) {
            log.err("ioctl failed: fd={d} req=0x{x} errno={}", .{ fd, request, std.posix.errno(rc) });
            return error.IoctlFailed;
        }
    }
};
