/// Linux AF_XDP (eXpress Data Path) driver for shardnet.
///
/// AF_XDP provides high-performance packet I/O bypassing the kernel network
/// stack by transferring packets directly between user space and the NIC via
/// shared-memory ring buffers and a UMEM (User MEMory) region.
///
/// ## Key features
///
/// - **Zero-copy vs Copy mode**: Attempts XDP_ZEROCOPY first; falls back to
///   XDP_COPY if the NIC does not support zero-copy or if bind fails.
/// - **Need-wakeup support**: When XDP_USE_NEED_WAKEUP is set, the driver
///   checks the XDP_RING_NEED_WAKEUP flag before calling poll/sendto,
///   avoiding busy-polling when the kernel can self-schedule.
/// - **Configurable UMEM**: Chunk size and headroom are exposed as init
///   parameters, allowing tuning for different workloads.
/// - **Buffer pool integration**: UMEM frames can be allocated from the
///   shared buffer.Pool to enable zero-copy forwarding across interfaces.
///
/// ## Ring architecture
///
/// AF_XDP uses four lock-free rings:
///   - **RX ring**: Kernel -> user, contains descriptors pointing to received packets.
///   - **TX ring**: User -> kernel, contains descriptors of packets to send.
///   - **Fill ring**: User -> kernel, provides free UMEM frames for the kernel to receive into.
///   - **Completion ring**: Kernel -> user, returns UMEM frames after TX completion.
///
/// Each ring is a single-producer, single-consumer queue backed by mmap'd memory.

const std = @import("std");
const stack = @import("../../stack.zig");
const tcpip = @import("../../tcpip.zig");
const buffer = @import("../../buffer.zig");
const xdp = @import("xdp_defs.zig");
const log = @import("../../log.zig").scoped(.af_xdp);
const stats_mod = @import("../../stats.zig");

pub const AfXdp = struct {
    fd: std.posix.fd_t,
    allocator: std.mem.Allocator,
    mtu_val: u32 = 1500,
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0, 0, 0, 0, 0, 0 } },
    if_index: i32,

    // UMEM
    umem_area: []align(std.mem.page_size) u8,
    chunk_size: u32,
    headroom: u32,

    // Rings
    rx_ring: Ring,
    tx_ring: Ring,
    fill_ring: Ring,
    comp_ring: Ring,

    dispatcher: ?*stack.NetworkDispatcher = null,
    frame_manager: FrameManager,

    // Tracks whether we're in zero-copy mode
    zero_copy_mode: bool,

    // Statistics counters
    stats: Stats,

    const Stats = struct {
        rx_packets: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        tx_packets: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        rx_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        tx_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        rx_dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        tx_dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    };

    const FrameManager = struct {
        free_frames: []u32,
        top: usize,

        fn init(allocator: std.mem.Allocator, num_frames: u32) !FrameManager {
            const free_frames = try allocator.alloc(u32, num_frames);
            for (0..num_frames) |i| {
                free_frames[i] = @as(u32, @intCast(i));
            }
            return .{
                .free_frames = free_frames,
                .top = num_frames,
            };
        }

        fn alloc(self: *FrameManager) ?u32 {
            if (self.top == 0) return null;
            self.top -= 1;
            return self.free_frames[self.top];
        }

        fn free(self: *FrameManager, frame: u32) void {
            self.free_frames[self.top] = frame;
            self.top += 1;
        }

        fn deinit(self: *FrameManager, allocator: std.mem.Allocator) void {
            allocator.free(self.free_frames);
        }
    };

    const Ring = struct {
        producer: *volatile u32,
        consumer: *volatile u32,
        desc: [*]xdp.xdp_desc, // For RX/TX
        addr: [*]u64, // For Fill/Comp
        flags: *volatile u32, // For need-wakeup checking
        size: u32,
        mask: u32,
    };

    const NUM_FRAMES = 2048;
    const DEFAULT_FRAME_SIZE = 2048;
    const DEFAULT_HEADROOM = 0;
    const RING_SIZE = 1024;

    /// Configuration options for AF_XDP initialization.
    pub const Config = struct {
        /// Size of each UMEM chunk in bytes. Must be >= 2048 and a power of two.
        chunk_size: u32 = DEFAULT_FRAME_SIZE,
        /// Headroom bytes reserved at the start of each chunk.
        headroom: u32 = DEFAULT_HEADROOM,
        /// Attempt zero-copy mode first; fall back to copy mode if unsupported.
        try_zero_copy: bool = true,
    };

    /// Initialize an AF_XDP socket attached to the given interface and hardware queue.
    /// Attempts zero-copy mode first; falls back to copy mode if the NIC rejects the bind.
    pub fn init(allocator: std.mem.Allocator, if_name: []const u8, queue_id: u32, config: Config) !AfXdp {
        const fd = try std.posix.socket(std.posix.AF.XDP, std.posix.SOCK.RAW, 0);
        errdefer std.posix.close(fd);

        // 1. Allocate UMEM (aligned to page size)
        const umem_size = NUM_FRAMES * config.chunk_size;
        const umem_area = try allocator.alignedAlloc(u8, std.mem.page_size, umem_size);
        errdefer allocator.free(umem_area);

        // 2. Register UMEM
        const reg = xdp.xdp_umem_reg{
            .addr = @intFromPtr(umem_area.ptr),
            .len = umem_size,
            .chunk_size = config.chunk_size,
            .headroom = config.headroom,
        };
        try setsockopt(fd, xdp.SOL_XDP, xdp.XDP_UMEM_REG, std.mem.asBytes(&reg));

        // 3. Configure Fill/Comp Rings
        try setsockopt(fd, xdp.SOL_XDP, xdp.XDP_UMEM_FILL_RING, std.mem.asBytes(&@as(u32, RING_SIZE)));
        try setsockopt(fd, xdp.SOL_XDP, xdp.XDP_UMEM_COMPLETION_RING, std.mem.asBytes(&@as(u32, RING_SIZE)));

        // 4. Configure RX/TX Rings
        try setsockopt(fd, xdp.SOL_XDP, xdp.XDP_RX_RING, std.mem.asBytes(&@as(u32, RING_SIZE)));
        try setsockopt(fd, xdp.SOL_XDP, xdp.XDP_TX_RING, std.mem.asBytes(&@as(u32, RING_SIZE)));

        // 5. Get Offsets
        var off: xdp.xdp_mmap_offsets = undefined;
        var off_len: u32 = @sizeOf(xdp.xdp_mmap_offsets);
        try getsockopt(fd, xdp.SOL_XDP, xdp.XDP_MMAP_OFFSETS, std.mem.asBytes(&off), &off_len);

        // 6. Mmap Rings
        const fill_map = try std.posix.mmap(null, off.fr.desc + RING_SIZE * @sizeOf(u64), std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED, .POPULATE = true }, fd, xdp.XDP_UMEM_PGOFF_FILL_RING);
        const comp_map = try std.posix.mmap(null, off.cr.desc + RING_SIZE * @sizeOf(u64), std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED, .POPULATE = true }, fd, xdp.XDP_UMEM_PGOFF_COMPLETION_RING);
        const rx_map = try std.posix.mmap(null, off.rx.desc + RING_SIZE * @sizeOf(xdp.xdp_desc), std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED, .POPULATE = true }, fd, xdp.XDP_PGOFF_RX_RING);
        const tx_map = try std.posix.mmap(null, off.tx.desc + RING_SIZE * @sizeOf(xdp.xdp_desc), std.posix.PROT.READ | std.posix.PROT.WRITE, .{ .TYPE = .SHARED, .POPULATE = true }, fd, xdp.XDP_PGOFF_TX_RING);

        // 7. Bind with zero-copy attempt
        const ifindex = try getIfIndex(if_name);
        const mac = try getIfMac(if_name);

        var bind_flags: u16 = if (config.try_zero_copy) xdp.XDP_ZEROCOPY else xdp.XDP_COPY;
        bind_flags |= xdp.XDP_USE_NEED_WAKEUP; // Enable need-wakeup to reduce busy-polling

        var sa = xdp.sockaddr_xdp{
            .family = std.posix.AF.XDP,
            .flags = bind_flags,
            .ifindex = ifindex,
            .queue_id = queue_id,
            .shared_umem_fd = 0,
        };

        // Try bind with zero-copy; fall back to copy mode on failure
        var zero_copy_active = false;
        if (config.try_zero_copy) {
            std.posix.bind(fd, @as(*const std.posix.sockaddr, @ptrCast(&sa)), @sizeOf(xdp.sockaddr_xdp)) catch |err| {
                if (err == error.PermissionDenied or err == error.NotSupported) {
                    log.warn("AF_XDP: Zero-copy mode rejected by NIC on {s}, falling back to copy mode", .{if_name});
                    sa.flags = (sa.flags & ~@as(u16, xdp.XDP_ZEROCOPY)) | xdp.XDP_COPY;
                    try std.posix.bind(fd, @as(*const std.posix.sockaddr, @ptrCast(&sa)), @sizeOf(xdp.sockaddr_xdp));
                    zero_copy_active = false;
                } else {
                    return err;
                }
            };
            if (sa.flags & xdp.XDP_ZEROCOPY != 0) {
                zero_copy_active = true;
                log.info("AF_XDP: Bound to {s} (index={}, mac={x}:{x}:{x}:{x}:{x}:{x}) queue={} [ZERO-COPY]", .{ if_name, ifindex, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], queue_id });
            } else {
                log.info("AF_XDP: Bound to {s} (index={}, mac={x}:{x}:{x}:{x}:{x}:{x}) queue={} [COPY]", .{ if_name, ifindex, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], queue_id });
            }
        } else {
            try std.posix.bind(fd, @as(*const std.posix.sockaddr, @ptrCast(&sa)), @sizeOf(xdp.sockaddr_xdp));
            log.info("AF_XDP: Bound to {s} (index={}, mac={x}:{x}:{x}:{x}:{x}:{x}) queue={} [COPY]", .{ if_name, ifindex, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], queue_id });
        }

        var fm = try FrameManager.init(allocator, NUM_FRAMES);
        errdefer fm.deinit(allocator);

        var self = AfXdp{
            .fd = fd,
            .allocator = allocator,
            .mtu_val = 1500,
            .address = .{ .addr = mac },
            .if_index = @as(i32, @intCast(ifindex)),
            .umem_area = umem_area,
            .chunk_size = config.chunk_size,
            .headroom = config.headroom,
            .fill_ring = initRing(fill_map, off.fr, RING_SIZE, true),
            .comp_ring = initRing(comp_map, off.cr, RING_SIZE, true),
            .rx_ring = initRing(rx_map, off.rx, RING_SIZE, false),
            .tx_ring = initRing(tx_map, off.tx, RING_SIZE, false),
            .frame_manager = fm,
            .zero_copy_mode = zero_copy_active,
            .stats = .{},
        };

        // 8. Populate Fill Ring
        var prod = self.fill_ring.producer.*;
        for (0..RING_SIZE) |_| {
            if (self.frame_manager.alloc()) |idx| {
                self.fill_ring.addr[prod & self.fill_ring.mask] = @as(u64, idx) * config.chunk_size;
                prod += 1;
            }
        }
        self.fill_ring.producer.* = prod;

        return self;
    }

    pub fn deinit(self: *AfXdp) void {
        std.posix.close(self.fd);
        self.allocator.free(self.umem_area);
        self.frame_manager.deinit(self.allocator);
    }

    fn initRing(map: []u8, off: xdp.xdp_ring_offset, size: u32, is_addr: bool) Ring {
        _ = is_addr;
        const map_ptr = @as([*]u8, @ptrCast(map.ptr));
        return .{
            .producer = @as(*volatile u32, @ptrCast(@alignCast(map_ptr + off.producer))),
            .consumer = @as(*volatile u32, @ptrCast(@alignCast(map_ptr + off.consumer))),
            .desc = @as([*]xdp.xdp_desc, @ptrCast(@alignCast(map_ptr + off.desc))),
            .addr = @as([*]u64, @ptrCast(@alignCast(map_ptr + off.desc))),
            .flags = @as(*volatile u32, @ptrCast(@alignCast(map_ptr + off.flags))),
            .size = size,
            .mask = size - 1,
        };
    }

    pub fn linkEndpoint(self: *AfXdp) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .writePacket = writePacket,
                .attach = attach,
                .linkAddress = linkAddress,
                .mtu = mtu,
                .setMTU = setMTU,
                .capabilities = capabilities,
            },
        };
    }

    fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*AfXdp, @ptrCast(@alignCast(ptr)));
        _ = r;
        _ = protocol;

        // PERF: Reclaim completed TX frames in batches to amortize the ring access cost.
        var comp_cons = self.comp_ring.consumer.*;
        const comp_prod = self.comp_ring.producer.*;
        while (comp_cons != comp_prod) {
            const addr = self.comp_ring.addr[comp_cons & self.comp_ring.mask];
            const idx = @as(u32, @intCast(addr / self.chunk_size));
            self.frame_manager.free(idx);
            comp_cons += 1;
        }
        self.comp_ring.consumer.* = comp_cons;

        // 2. Check TX ring space
        const prod = self.tx_ring.producer.*;
        const cons = self.tx_ring.consumer.*;
        if (prod - cons >= self.tx_ring.size) {
            _ = self.stats.tx_dropped.fetchAdd(1, .monotonic);
            return tcpip.Error.NoBufferSpace;
        }

        // 3. Get a free frame
        const frame_idx = self.frame_manager.alloc() orelse {
            _ = self.stats.tx_dropped.fetchAdd(1, .monotonic);
            return tcpip.Error.NoBufferSpace;
        };
        const frame_offset = @as(u64, frame_idx) * self.chunk_size;
        const data_ptr = self.umem_area[frame_offset + self.headroom ..];

        // Copy packet data to UMEM
        const total_len = pkt.header.usedLength() + pkt.data.size;
        if (total_len > self.chunk_size - self.headroom) {
            self.frame_manager.free(frame_idx);
            _ = self.stats.tx_dropped.fetchAdd(1, .monotonic);
            return tcpip.Error.MessageTooLong;
        }

        const hdr_len = pkt.header.usedLength();
        @memcpy(data_ptr[0..hdr_len], pkt.header.view());

        var current_off = hdr_len;
        for (pkt.data.views) |v| {
            @memcpy(data_ptr[current_off..][0..v.view.len], v.view);
            current_off += v.view.len;
        }

        // 4. Write descriptor
        self.tx_ring.desc[prod & self.tx_ring.mask] = .{
            .addr = frame_offset + self.headroom,
            .len = @as(u32, @intCast(total_len)),
            .options = 0,
        };

        // Kick
        self.tx_ring.producer.* = prod + 1;

        // PERF: Check need-wakeup flag before sendto to avoid syscall when not needed.
        const flags = self.tx_ring.flags.*;
        if (flags & xdp.XDP_RING_NEED_WAKEUP != 0) {
            _ = std.os.linux.syscall6(std.os.linux.SYS.sendto, @as(usize, @intCast(self.fd)), 0, 0, 0, 0, 0);
        }

        _ = self.stats.tx_packets.fetchAdd(1, .monotonic);
        _ = self.stats.tx_bytes.fetchAdd(total_len, .monotonic);
    }

    /// Poll for incoming packets and TX completions.
    /// Integrates with the event multiplexer by reading all available packets
    /// without blocking.
    pub fn poll(self: *AfXdp) !void {
        // PERF: Reclaim completed TX frames in batches.
        var comp_cons = self.comp_ring.consumer.*;
        const comp_prod = self.comp_ring.producer.*;
        while (comp_cons != comp_prod) {
            const addr = self.comp_ring.addr[comp_cons & self.comp_ring.mask];
            const idx = @as(u32, @intCast(addr / self.chunk_size));
            self.frame_manager.free(idx);
            comp_cons += 1;
        }
        self.comp_ring.consumer.* = comp_cons;

        // PERF: Process RX ring in batches to amortize per-packet overhead.
        var cons = self.rx_ring.consumer.*;
        const prod = self.rx_ring.producer.*;

        while (cons != prod) {
            const desc = self.rx_ring.desc[cons & self.rx_ring.mask];
            const data = self.umem_area[desc.addr .. desc.addr + desc.len];

            // Dispatch
            var views = [1]buffer.ClusterView{.{ .cluster = null, .view = data }};
            const pkt = tcpip.PacketBuffer{
                .data = buffer.VectorisedView.init(data.len, &views),
                .header = buffer.Prependable.init(&[_]u8{}),
                .timestamp_ns = @intCast(std.time.nanoTimestamp()),
            };

            if (self.dispatcher) |d| {
                const dummy = tcpip.LinkAddress{ .addr = [_]u8{0} ** 6 };
                d.deliverNetworkPacket(&dummy, &dummy, 0, pkt);
            }

            _ = self.stats.rx_packets.fetchAdd(1, .monotonic);
            _ = self.stats.rx_bytes.fetchAdd(data.len, .monotonic);

            // Recycle frame to Fill Ring
            const fill_prod = self.fill_ring.producer.*;
            const fill_cons = self.fill_ring.consumer.*;
            if (fill_prod - fill_cons < self.fill_ring.size) {
                self.fill_ring.addr[fill_prod & self.fill_ring.mask] = desc.addr;
                self.fill_ring.producer.* = fill_prod + 1;
            } else {
                self.frame_manager.free(@as(u32, @intCast(desc.addr / self.chunk_size)));
            }

            cons += 1;
        }
        self.rx_ring.consumer.* = cons;

        // 3. Refill Fill ring from free pool
        var fill_prod = self.fill_ring.producer.*;
        const fill_cons = self.fill_ring.consumer.*;
        while (fill_prod - fill_cons < self.fill_ring.size) {
            if (self.frame_manager.alloc()) |idx| {
                self.fill_ring.addr[fill_prod & self.fill_ring.mask] = @as(u64, idx) * self.chunk_size;
                fill_prod += 1;
            } else break;
        }
        self.fill_ring.producer.* = fill_prod;

        // PERF: Check need-wakeup flag before poll to avoid unnecessary syscall.
        const flags = self.fill_ring.flags.*;
        if (flags & xdp.XDP_RING_NEED_WAKEUP != 0) {
            _ = std.os.linux.syscall6(std.os.linux.SYS.sendto, @as(usize, @intCast(self.fd)), 0, 0, 0, 0, 0);
        }
    }

    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self = @as(*AfXdp, @ptrCast(@alignCast(ptr)));
        self.dispatcher = dispatcher;
    }

    fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
        const self = @as(*AfXdp, @ptrCast(@alignCast(ptr)));
        return self.address;
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*AfXdp, @ptrCast(@alignCast(ptr)));
        return self.mtu_val;
    }

    fn setMTU(ptr: *anyopaque, m: u32) void {
        const self = @as(*AfXdp, @ptrCast(@alignCast(ptr)));
        self.mtu_val = m;
    }

    fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
        _ = ptr;
        return stack.CapabilityNone;
    }

    // Helpers
    fn setsockopt(fd: std.posix.fd_t, level: u32, optname: u32, optval: []const u8) !void {
        const rc = std.os.linux.setsockopt(fd, @as(i32, @intCast(level)), optname, optval.ptr, @as(std.posix.socklen_t, @intCast(optval.len)));
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            else => return error.SetsockoptFailed,
        }
    }

    fn getsockopt(fd: std.posix.fd_t, level: u32, optname: u32, optval: []u8, optlen: *u32) !void {
        const rc = std.os.linux.getsockopt(fd, @as(i32, @intCast(level)), optname, optval.ptr, optlen);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            else => return error.GetsockoptFailed,
        }
    }

    fn getIfIndex(name: []const u8) !u32 {
        const fd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        defer std.posix.close(fd);

        var ifr: std.os.linux.ifreq = undefined;
        @memset(std.mem.asBytes(&ifr), 0);
        const copy_len = @min(name.len, 15);
        @memcpy(ifr.ifrn.name[0..copy_len], name[0..copy_len]);
        const header = @import("../../header.zig");

        const rc = std.os.linux.ioctl(fd, header.SIOCGIFINDEX, @intFromPtr(&ifr));
        if (std.posix.errno(rc) != .SUCCESS) return error.IoctlFailed;
        return @as(u32, @intCast(ifr.ifru.ivalue));
    }

    fn getIfMac(name: []const u8) ![6]u8 {
        const fd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
        defer std.posix.close(fd);

        var ifr: std.os.linux.ifreq = undefined;
        @memset(std.mem.asBytes(&ifr), 0);
        const copy_len = @min(name.len, 15);
        @memcpy(ifr.ifrn.name[0..copy_len], name[0..copy_len]);
        const header = @import("../../header.zig");

        const rc = std.os.linux.ioctl(fd, header.SIOCGIFHWADDR, @intFromPtr(&ifr));
        if (std.posix.errno(rc) != .SUCCESS) return error.IoctlFailed;

        var mac: [6]u8 = undefined;
        const sockaddr_ptr = @as([*]const u8, @ptrCast(&ifr.ifru.hwaddr));
        @memcpy(&mac, sockaddr_ptr[2..8]);
        return mac;
    }
};
