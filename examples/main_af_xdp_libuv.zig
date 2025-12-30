const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const AfXdpEndpoint = @import("af_xdp_adapter.zig").AfXdpEndpoint;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var s = try stack.Stack.init(allocator);

    var xdp = try AfXdpEndpoint.init(allocator, "eth0");
    try s.createNIC(1, xdp.linkEndpoint());

    std.debug.print("Example: AF_XDP + LibUV starting...\n", .{});

    // uv_poll_init(loop, &poll, xdp.xsk_fd);
    // uv_poll_start(&poll, UV_READABLE, cb);
}
