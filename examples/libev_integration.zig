/// Libev event loop integration example.
///
/// NOTE: Libev watcher lifecycle:
/// - Watchers must be stopped with ev_io_stop/ev_timer_stop before the fd is closed
/// - Stopping a watcher that was never started is safe (no-op)
/// - A watcher can be reused after stopping by calling ev_io_set/ev_timer_set

const std = @import("std");
const ustack = @import("ustack");
const stack = ustack.stack;
const tcpip = ustack.tcpip;

const c = @cImport({
    @cInclude("ev.h");
});

/// Wrapper state for cleanup.
const LibevState = struct {
    loop: ?*c.ev_loop = null,
    io_watcher: c.ev_io = undefined,
    timer_watcher: c.ev_timer = undefined,
    io_active: bool = false,
    timer_active: bool = false,
    s: ?*stack.Stack = null,
    tap_fd: std.posix.fd_t = -1,

    /// Teardown all watchers and loop.
    /// NOTE: Must stop all watchers before closing fds or destroying loop.
    pub fn teardown(self: *LibevState) void {
        if (self.loop) |loop| {
            // Stop watchers before closing fds
            if (self.io_active) {
                c.ev_io_stop(loop, &self.io_watcher);
                self.io_active = false;
            }
            if (self.timer_active) {
                c.ev_timer_stop(loop, &self.timer_watcher);
                self.timer_active = false;
            }
        }

        // Close fd after watchers are stopped
        if (self.tap_fd >= 0) {
            std.posix.close(self.tap_fd);
            self.tap_fd = -1;
        }

        // Destroy loop last
        if (self.loop) |loop| {
            c.ev_loop_destroy(loop);
            self.loop = null;
        }
    }
};

var g_state: LibevState = .{};

extern fn my_ev_default_loop() ?*anyopaque;
extern fn my_ev_io_init(w: *c.ev_io, cb: *const fn (?*anyopaque, *c.ev_io, i32) callconv(.C) void, fd: i32, events: i32) void;
extern fn my_ev_timer_init(w: *c.ev_timer, cb: *const fn (?*anyopaque, *c.ev_timer, i32) callconv(.C) void, after: f64, repeat: f64) void;
extern fn my_ev_io_start(loop: ?*anyopaque, w: *c.ev_io) void;
extern fn my_ev_timer_start(loop: ?*anyopaque, w: *c.ev_timer) void;
extern fn my_ev_run(loop: ?*anyopaque) void;
extern fn my_ev_break(loop: ?*anyopaque) void;

fn on_io_readable(loop: ?*anyopaque, watcher: *c.ev_io, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    // tap_ep.onReadable() catch {};
    // g_state.s.?.timer_queue.processExpired();
}

fn on_timer(loop: ?*anyopaque, watcher: *c.ev_timer, revents: i32) callconv(.C) void {
    _ = loop;
    _ = watcher;
    _ = revents;
    if (g_state.s) |s| {
        s.timer_queue.processExpired();
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var s = try stack.Stack.init(allocator);
    g_state.s = &s;
    defer {
        g_state.teardown();
        s.deinit();
    }

    // Setup TAP (mocked fd for demonstration)
    const tap_fd: std.posix.fd_t = 0;
    g_state.tap_fd = tap_fd;

    std.debug.print("Stack initialized (TAP + Libev)...\n", .{});

    // Get loop - check for failure
    const loop = my_ev_default_loop();
    if (loop == null) {
        std.debug.print("Error: ev_default_loop() failed\n", .{});
        return error.EvLoopInitFailed;
    }
    g_state.loop = @ptrCast(loop);

    // Setup I/O watcher
    my_ev_io_init(&g_state.io_watcher, on_io_readable, tap_fd, c.EV_READ);
    my_ev_io_start(loop, &g_state.io_watcher);
    g_state.io_active = true;

    // Setup timer watcher (1ms tick)
    my_ev_timer_init(&g_state.timer_watcher, on_timer, 0.001, 0.001);
    my_ev_timer_start(loop, &g_state.timer_watcher);
    g_state.timer_active = true;

    // Run event loop
    my_ev_run(loop);

    std.debug.print("Event loop exited.\n", .{});
}
