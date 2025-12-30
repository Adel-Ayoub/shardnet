/// Libuv event loop integration example.
///
/// NOTE: Libuv handle lifecycle:
/// - Handles must be closed with uv_close() before freeing
/// - uv_close() is async - the close callback fires when complete
/// - Never free a handle until its close callback has fired
/// - Poll handles must be stopped before the fd is closed

const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;

// Mocking UV structs for syntax checking
const uv_loop_t = opaque {};
const uv_poll_t = extern struct {
    data: ?*anyopaque = null,
};
const uv_timer_t = extern struct {
    data: ?*anyopaque = null,
};
const uv_handle_t = opaque {};

/// Wrapper state for cleanup.
const LibuvState = struct {
    loop: ?*uv_loop_t = null,
    poll_handle: uv_poll_t = .{},
    timer_handle: uv_timer_t = .{},
    poll_active: bool = false,
    timer_active: bool = false,
    s: ?*stack.Stack = null,
    tun_fd: std.posix.fd_t = -1,
    close_pending: u32 = 0,

    /// Teardown all handles and loop.
    /// NOTE: Must stop and close handles before closing fds.
    pub fn teardown(self: *LibuvState) void {
        // Stop handles first
        if (self.poll_active) {
            // uv_poll_stop(&self.poll_handle);
            self.poll_active = false;
        }
        if (self.timer_active) {
            // uv_timer_stop(&self.timer_handle);
            self.timer_active = false;
        }

        // Close handles (async - would wait for callbacks in real code)
        // uv_close(@ptrCast(&self.poll_handle), on_close);
        // uv_close(@ptrCast(&self.timer_handle), on_close);
        self.close_pending = 2;

        // In real code: run loop until close_pending == 0
        // while (self.close_pending > 0) {
        //     uv_run(self.loop, UV_RUN_ONCE);
        // }

        // Close fd after handles are closed
        if (self.tun_fd >= 0) {
            std.posix.close(self.tun_fd);
            self.tun_fd = -1;
        }

        // Destroy loop last
        if (self.loop) |_| {
            // uv_loop_close(loop);
            self.loop = null;
        }
    }
};

var g_state: LibuvState = .{};

fn on_close(handle: *uv_handle_t) callconv(.C) void {
    _ = handle;
    g_state.close_pending -= 1;
}

fn on_tun_readable(handle: *uv_poll_t, status: c_int, events: c_int) callconv(.C) void {
    _ = handle;
    _ = status;
    _ = events;
    // const ep = @as(*TunTapEndpoint, @ptrCast(@alignCast(handle.data)));
    // ep.onReadable() catch |err| {
    //     std.debug.print("Read error: {}\n", .{err});
    // };
}

fn on_stack_timer(handle: *uv_timer_t) callconv(.C) void {
    _ = handle;
    if (g_state.s) |s| {
        s.timer_queue.processExpired();
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize Stack
    var s = try stack.Stack.init(allocator);
    g_state.s = &s;
    defer {
        g_state.teardown();
        s.deinit();
    }

    // Open TUN device (mocked)
    const tun_fd: std.posix.fd_t = 0;
    g_state.tun_fd = tun_fd;

    // Configure Address
    const addr = tcpip.ProtocolAddress{
        .protocol = 0x0800,
        .address_with_prefix = .{
            .address = .{ .v4 = .{ 192, 168, 1, 2 } },
            .prefix_len = 24,
        },
    };
    if (s.nics.get(1)) |nic| {
        try nic.addAddress(addr);
    }

    std.debug.print("Stack initialized. Starting Event Loop...\n", .{});

    // In real code:
    // var loop: uv_loop_t = undefined;
    // if (uv_loop_init(&loop) != 0) {
    //     std.debug.print("Error: uv_loop_init() failed\n", .{});
    //     return error.UvLoopInitFailed;
    // }
    // g_state.loop = &loop;

    // Poll Handle for TUN FD
    // uv_poll_init(&loop, &g_state.poll_handle, tun_fd);
    // g_state.poll_handle.data = &tun_ep;
    // uv_poll_start(&g_state.poll_handle, UV_READABLE, on_tun_readable);
    // g_state.poll_active = true;

    // Timer Handle for Stack Timers
    // uv_timer_init(&loop, &g_state.timer_handle);
    // g_state.timer_handle.data = &s;
    // uv_timer_start(&g_state.timer_handle, on_stack_timer, 1, 1);
    // g_state.timer_active = true;

    // uv_run(&loop, UV_RUN_DEFAULT);

    std.debug.print("Event loop exited.\n", .{});
}
