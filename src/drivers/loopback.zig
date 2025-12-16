const std = @import("std");
const stack = @import("../stack.zig");
const tcpip = @import("../tcpip.zig");
const buffer = @import("../buffer.zig");
const log = @import("../log.zig").scoped(.loopback);

/// A virtual link-layer endpoint that delivers packets back to the same
/// network stack instance.
///
/// Packets written via writePacket() are not delivered inline — they are
/// enqueued and delivered during tick(). This two-phase design prevents
/// recursive lock acquisition that would otherwise occur when the receive
/// path re-enters the stack from inside the send path.
///
/// Enhancements over a bare-bones loopback:
///   - Queue nodes are drawn from a `buffer.Pool`, removing per-packet heap
///     allocation from the hot send path.
///   - Configurable artificial latency (`delay_ns`) and random packet loss
///     (`loss_pct`) enable deterministic network-condition testing without
///     external tooling.
///   - Built-in `loopback_tx` / `loopback_rx` / `loopback_dropped` counters
///     for diagnostics and test assertions.
// NOTE: This driver is single-threaded. If concurrent send/tick is needed,
// the caller must synchronise externally (e.g. a mutex around writePacket
// and tick, or per-thread loopback instances).
pub const Loopback = struct {
    dispatcher: ?*stack.NetworkDispatcher = null,
    mtu_val: u32 = 65536,
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0, 0, 0, 0, 0, 0 } },
    queue: std.TailQueue(Packet),
    allocator: std.mem.Allocator,

    // NOTE: The node pool replaces raw allocator.create/destroy calls for
    // queue nodes. This avoids hitting the backing allocator on every packet
    // in the common case, which matters for high-throughput loopback tests.
    node_pool: NodePool,

    // NOTE: Simulation knobs are set at init time. Keeping them immutable
    // after construction lets the compiler hoist the zero-checks in tick()
    // and writePacket() when the values are comptime-known zero.
    delay_ns: u64,
    loss_pct: u8,
    prng: std.rand.DefaultPrng,

    /// Total number of packets submitted to writePacket (before loss).
    loopback_tx: u64 = 0,
    /// Total number of packets actually delivered to the dispatcher.
    loopback_rx: u64 = 0,
    /// Total number of packets discarded by the loss simulation.
    loopback_dropped: u64 = 0,

    // -- Private types -------------------------------------------------------

    const Packet = struct {
        protocol: tcpip.NetworkProtocolNumber,
        pkt: tcpip.PacketBuffer,
        /// Monotonic wall-clock timestamp (nanoseconds) captured at enqueue
        /// time. Used together with `delay_ns` to hold packets in the queue
        /// until the artificial latency window has elapsed.
        enqueue_ts: i128,
    };

    const QueueNode = std.TailQueue(Packet).Node;

    // PERF: NodePool pre-allocates queue-node wrappers so the fast path
    // (acquire → enqueue → deliver → release) never touches the heap.
    // The underlying packet data is still ref-counted via ClusterPool /
    // VectorisedView and is independent of the node pool.
    const NodePool = buffer.Pool(QueueNode);

    // -- Configuration -------------------------------------------------------

    /// Tunables for the loopback driver.
    ///
    /// Every field has a default that reproduces the original zero-overhead
    /// behaviour, so existing call-sites that pass `.{}` are unaffected.
    pub const Config = struct {
        /// Artificial one-way latency added to every packet, in nanoseconds.
        /// A packet enqueued at wall-clock time T will not be delivered before
        /// T + delay_ns. Set to 0 (default) for immediate delivery.
        delay_ns: u64 = 0,

        /// Percentage of packets to drop at random on the send path (0–100).
        /// 0 means no loss; 100 means drop everything. Values above 100 are
        /// treated the same as 100.
        loss_pct: u8 = 0,

        /// Seed for the PRNG that drives packet-loss decisions.
        /// A fixed seed (the default of 0) guarantees reproducible test runs.
        prng_seed: u64 = 0,

        /// Maximum number of idle queue nodes kept in the free-list.
        /// Excess nodes are returned to the backing allocator on release.
        node_pool_capacity: usize = 64,
    };

    /// Point-in-time snapshot of the driver counters.
    pub const Stats = struct {
        loopback_tx: u64,
        loopback_rx: u64,
        loopback_dropped: u64,
    };

    // -- Lifecycle -----------------------------------------------------------

    /// Initialise a loopback driver with default configuration (no delay,
    /// no loss, 64-node pool). This signature is backwards-compatible with
    /// the original driver.
    pub fn init(allocator: std.mem.Allocator) Loopback {
        return initWithConfig(allocator, .{});
    }

    /// Initialise a loopback driver with explicit simulation parameters.
    ///
    /// Use this entry-point in tests that need artificial latency or
    /// packet-loss injection:
    /// ```
    /// var lo = Loopback.initWithConfig(alloc, .{
    ///     .delay_ns  = 5_000_000,  // 5 ms
    ///     .loss_pct  = 10,         // 10 % random loss
    ///     .prng_seed = 42,
    /// });
    /// ```
    pub fn initWithConfig(allocator: std.mem.Allocator, config: Config) Loopback {
        return .{
            .queue = .{},
            .allocator = allocator,
            .node_pool = NodePool.init(allocator, config.node_pool_capacity),
            .delay_ns = config.delay_ns,
            .loss_pct = config.loss_pct,
            .prng = std.rand.DefaultPrng.init(config.prng_seed),
        };
    }

    /// Release all resources owned by the driver.
    ///
    /// Any packets still sitting in the queue are drained and freed so that
    /// the backing allocator sees a clean shutdown (no leaks).
    pub fn deinit(self: *Loopback) void {
        // NOTE: We must drain the queue before tearing down the pool,
        // because each queued packet holds a cloned VectorisedView that
        // owns cluster references.
        while (self.queue.popFirst()) |node| {
            node.data.pkt.data.deinit();
            self.node_pool.release(node);
        }
        self.node_pool.deinit();
    }

    /// Return a point-in-time snapshot of the driver counters.
    ///
    /// The snapshot is cheap (three u64 copies) and safe to call from a
    /// monitoring thread if external locking is already in place.
    pub fn stats(self: *const Loopback) Stats {
        return .{
            .loopback_tx = self.loopback_tx,
            .loopback_rx = self.loopback_rx,
            .loopback_dropped = self.loopback_dropped,
        };
    }

    // -- LinkEndpoint interface ----------------------------------------------

    /// Return a type-erased `LinkEndpoint` vtable suitable for registration
    /// with the network stack.
    pub fn linkEndpoint(self: *Loopback) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .writePacket = writePacket,
                .writePackets = writePackets,
                .attach = attach,
                .linkAddress = linkAddress,
                .mtu = mtu,
                .setMTU = setMTU,
                .capabilities = capabilities,
            },
        };
    }

    /// Batch-send multiple packets through the loopback.
    ///
    /// Each packet is individually subject to loss simulation, so a batch
    /// of N packets with 50 % loss will deliver roughly N/2.
    fn writePackets(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, packets: []const tcpip.PacketBuffer) tcpip.Error!void {
        for (packets) |p| {
            try writePacket(ptr, r, protocol, p);
        }
    }

    /// Enqueue a single packet for loopback delivery on the next tick().
    ///
    /// The packet buffer is cloned so the caller may release or reuse its
    /// original buffer immediately after this call returns. If loss
    /// simulation is enabled and the PRNG decides to drop this packet,
    /// the clone is skipped entirely to save work.
    pub fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self: *Loopback = @ptrCast(@alignCast(ptr));
        _ = r;

        self.loopback_tx += 1;

        // NOTE: Loss is evaluated before cloning or pooling so that dropped
        // packets never consume pool nodes or trigger a buffer clone.
        if (self.loss_pct > 0) {
            const roll = self.prng.random().intRangeLessThan(u8, 100);
            if (roll < self.loss_pct) {
                self.loopback_dropped += 1;
                log.debug("Loopback: Dropping packet proto=0x{x} (loss simulation)", .{protocol});
                return;
            }
        }

        // PERF: Acquire a queue node from the pool instead of the backing
        // allocator. Under steady-state traffic the pool satisfies every
        // request without allocation.
        const node = self.node_pool.acquire() catch return tcpip.Error.OutOfMemory;
        node.data = .{
            .protocol = protocol,
            .pkt = pkt.clone(self.allocator) catch {
                self.node_pool.release(node);
                return tcpip.Error.NoBufferSpace;
            },
            .enqueue_ts = std.time.nanoTimestamp(),
        };
        self.queue.append(node);
    }

    // -- Tick / delivery -----------------------------------------------------

    /// Deliver queued packets whose artificial delay (if any) has elapsed.
    ///
    /// The network stack's event loop should call this once per iteration.
    /// When `delay_ns` is zero (the default) every queued packet is delivered
    /// immediately, preserving the original behaviour.
    pub fn tick(self: *Loopback) void {
        // NOTE: We sample the clock once per tick rather than per packet.
        // This gives all eligibility decisions within a single tick the same
        // reference point and avoids a syscall-per-packet overhead.
        const now = std.time.nanoTimestamp();

        while (self.queue.first) |node| {
            // NOTE: Packets are strictly FIFO, so the first packet that is
            // not yet ready implies all subsequent ones are also not ready.
            if (now - node.data.enqueue_ts < @as(i128, self.delay_ns)) break;

            _ = self.queue.popFirst();

            log.debug("Loopback: Delivering packet proto=0x{x}", .{node.data.protocol});
            if (self.dispatcher) |d| {
                d.deliverNetworkPacket(&self.address, &self.address, node.data.protocol, node.data.pkt);
            }
            self.loopback_rx += 1;

            node.data.pkt.data.deinit();
            // PERF: Return the node to the pool rather than freeing it,
            // keeping the next writePacket allocation off the heap.
            self.node_pool.release(node);
        }
    }

    // -- Remaining vtable helpers (behaviour unchanged) ----------------------

    /// Register the upper-layer dispatcher that will receive delivered packets.
    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self: *Loopback = @ptrCast(@alignCast(ptr));
        self.dispatcher = dispatcher;
    }

    /// Return the link-layer (MAC) address of this endpoint.
    /// Loopback uses the all-zeroes address by convention.
    fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
        const self: *Loopback = @ptrCast(@alignCast(ptr));
        return self.address;
    }

    /// Return the current Maximum Transmission Unit in bytes.
    fn mtu(ptr: *anyopaque) u32 {
        const self: *Loopback = @ptrCast(@alignCast(ptr));
        return self.mtu_val;
    }

    /// Set a new MTU value. No packet-size validation is performed here;
    /// the upper layers are responsible for respecting the advertised MTU.
    fn setMTU(ptr: *anyopaque, m: u32) void {
        const self: *Loopback = @ptrCast(@alignCast(ptr));
        self.mtu_val = m;
    }

    /// Return the capabilities bitmap for this endpoint.
    /// The loopback driver always reports `CapabilityLoopback`.
    fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
        _ = ptr;
        return stack.CapabilityLoopback;
    }
};
