const std = @import("std");
const shardnet = @import("shardnet");
const stack = shardnet.stack;
const tcpip = shardnet.tcpip;
const AfPacketEndpoint = @import("af_packet_adapter.zig").AfPacketEndpoint;

// Mock UV
const uv_poll_t = opaque {};

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var s = try stack.Stack.init(allocator);

    var af_packet = try AfPacketEndpoint.init(1); // eth0
    try s.createNIC(1, af_packet.linkEndpoint());

    std.debug.print("Example: AF_PACKET + LibUV starting...\n", .{});

    // uv_poll_init(loop, &poll, af_packet.fd);
    // uv_poll_start(&poll, UV_READABLE, cb);
}

fn poll_cb(handle: *uv_poll_t, status: c_int, events: c_int) callconv(.C) void {
    _ = handle;
    _ = status;
    _ = events;
    // af_packet.onReadable()
}
