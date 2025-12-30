/// AF_PACKET adapter for the network stack.
///
/// NOTE: Requires CAP_NET_RAW capability to create raw sockets.
/// Run with: sudo setcap cap_net_raw+ep <binary>
/// Or run as root.

const std = @import("std");
const os = std.os;
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;
const header = ustack.header;
const buffer = ustack.buffer;

/// Unified adapter configuration shared with AF_XDP.
pub const AdapterConfig = struct {
    /// Receive queue depth (number of buffers).
    rx_queue_depth: u32 = 256,
    /// Transmit queue depth (number of buffers).
    tx_queue_depth: u32 = 256,
    /// Enable zero-copy mode (AF_XDP only).
    zero_copy: bool = true,
    /// Interface name to bind to.
    interface: []const u8 = "",
    /// Promiscuous mode.
    promiscuous: bool = false,
    /// MTU size.
    mtu: u32 = 1500,
};

/// AF_PACKET link endpoint wrapper.
pub const AfPacketEndpoint = struct {
    fd: std.posix.fd_t,
    mtu_val: u32 = 1500,
    address: tcpip.LinkAddress = .{ .addr = [_]u8{ 0, 0, 0, 0, 0, 0 } },
    config: AdapterConfig,

    dispatcher: ?*stack.NetworkDispatcher = null,
    wrapped_dispatcher: stack.NetworkDispatcher = undefined,

    pub fn init(if_index: i32, config: AdapterConfig) !AfPacketEndpoint {
        _ = if_index;
        // NOTE: AF_PACKET requires CAP_NET_RAW.
        // socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
        // Simplified: using mock FD for demonstration
        const fd: std.posix.fd_t = 0;

        return AfPacketEndpoint{
            .fd = fd,
            .config = config,
            .mtu_val = config.mtu,
        };
    }

    pub fn initWithConfig(config: AdapterConfig) !AfPacketEndpoint {
        return init(0, config);
    }

    pub fn deinit(self: *AfPacketEndpoint) void {
        if (self.fd >= 0) {
            std.posix.close(self.fd);
        }
    }

    pub fn linkEndpoint(self: *AfPacketEndpoint) stack.LinkEndpoint {
        return .{
            .ptr = self,
            .vtable = &.{
                .writePacket = writePacket,
                .attach = attach,
                .linkAddress = linkAddress,
                .mtu = mtu,
                .setMTU = setMTU,
                .capabilities = capabilities,
                .close = close,
            },
        };
    }

    fn writePacket(ptr: *anyopaque, r: ?*const stack.Route, protocol: tcpip.NetworkProtocolNumber, pkt: tcpip.PacketBuffer) tcpip.Error!void {
        const self = @as(*AfPacketEndpoint, @ptrCast(@alignCast(ptr)));
        _ = r;
        _ = protocol;

        const total_len = pkt.header.usedLength() + pkt.data.size;
        var buf = std.heap.page_allocator.alloc(u8, total_len) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(buf);

        const hdr_len = pkt.header.usedLength();
        @memcpy(buf[0..hdr_len], pkt.header.view());
        const view = pkt.data.toView(std.heap.page_allocator) catch return tcpip.Error.NoBufferSpace;
        defer std.heap.page_allocator.free(view);
        @memcpy(buf[hdr_len..], view);

        _ = std.posix.write(self.fd, buf) catch return tcpip.Error.UnknownDevice;
    }

    fn attach(ptr: *anyopaque, dispatcher: *stack.NetworkDispatcher) void {
        const self = @as(*AfPacketEndpoint, @ptrCast(@alignCast(ptr)));
        self.dispatcher = dispatcher;
    }

    fn linkAddress(ptr: *anyopaque) tcpip.LinkAddress {
        const self = @as(*AfPacketEndpoint, @ptrCast(@alignCast(ptr)));
        return self.address;
    }

    fn mtu(ptr: *anyopaque) u32 {
        const self = @as(*AfPacketEndpoint, @ptrCast(@alignCast(ptr)));
        return self.mtu_val;
    }

    fn setMTU(ptr: *anyopaque, m: u32) void {
        const self = @as(*AfPacketEndpoint, @ptrCast(@alignCast(ptr)));
        self.mtu_val = m;
    }

    fn capabilities(ptr: *anyopaque) stack.LinkEndpointCapabilities {
        _ = ptr;
        return stack.CapabilityNone;
    }

    fn close(ptr: *anyopaque) void {
        const self = @as(*AfPacketEndpoint, @ptrCast(@alignCast(ptr)));
        self.deinit();
    }

    pub fn onReadable(self: *AfPacketEndpoint) !void {
        var buf: [9000]u8 = undefined;
        const len = try std.posix.read(self.fd, &buf);
        if (len < header.EthernetMinimumSize) return;

        const eth = header.Ethernet.init(buf[0..len]);
        const eth_type = eth.etherType();

        const payload_buf = std.heap.page_allocator.alloc(u8, len - header.EthernetMinimumSize) catch return;
        @memcpy(payload_buf, buf[header.EthernetMinimumSize..len]);

        const views = [_]buffer.View{payload_buf};
        const pkt = tcpip.PacketBuffer{
            .data = buffer.VectorisedView.init(payload_buf.len, &views),
            .header = undefined,
        };

        if (self.dispatcher) |d| {
            const src = tcpip.LinkAddress{ .addr = eth.sourceAddress() };
            const dst = tcpip.LinkAddress{ .addr = eth.destinationAddress() };
            d.deliverNetworkPacket(&src, &dst, eth_type, pkt);
        }
        std.heap.page_allocator.free(payload_buf);
    }
};
