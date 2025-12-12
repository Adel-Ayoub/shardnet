/// POSIX syscall wrappers for the shardnet network stack.
///
/// Every wrapper returns a typed error union derived from errno values so
/// callers get clear, documented failure modes instead of raw integers.
/// This module is Linux-only; a comptime assertion guards against accidental
/// cross-compilation to unsupported platforms.
///
/// The Socket / usocket / ubind / uconnect / ulisten / uaccept / urecv /
/// usend API surface mirrors the BSD socket interface but operates on the
/// user-space TCP/IP stack rather than the kernel's.
const std = @import("std");
const stack = @import("stack.zig");
const tcpip = @import("tcpip.zig");
const waiter = @import("waiter.zig");
const buffer = @import("buffer.zig");

// -- Platform gate ----------------------------------------------------------
// NOTE: shardnet relies on Linux-specific APIs (AF_XDP, AF_PACKET, epoll,
// eventfd, TPACKET_V3). This comptime assertion prevents silent compilation
// failures on macOS, Windows, or other POSIX variants.
comptime {
    if (@import("builtin").os.tag != .linux) {
        @compileError("shardnet requires Linux; detected " ++ @tagName(@import("builtin").os.tag));
    }
}

// ---------------------------------------------------------------------------
// PosixError — typed errno wrapper
// ---------------------------------------------------------------------------

/// Typed error set derived from common errno values surfaced by the
/// syscalls wrapped in this module. Each variant maps 1:1 to an errno.
pub const PosixError = error{
    /// EACCES — permission denied (e.g. missing CAP_NET_RAW).
    PermissionDenied,
    /// EADDRINUSE — address already in use.
    AddressInUse,
    /// EADDRNOTAVAIL — address not available on this interface.
    AddressNotAvailable,
    /// EAFNOSUPPORT — address family not supported by protocol.
    AddressFamilyNotSupported,
    /// EAGAIN / EWOULDBLOCK — resource temporarily unavailable.
    WouldBlock,
    /// EBADF — bad file descriptor.
    BadFileDescriptor,
    /// ECONNREFUSED — connection refused by remote host.
    ConnectionRefused,
    /// ECONNRESET — connection reset by peer.
    ConnectionReset,
    /// EINTR — interrupted by signal (retry is usually correct).
    Interrupted,
    /// EINVAL — invalid argument.
    InvalidArgument,
    /// EMFILE — per-process fd limit reached.
    TooManyOpenFiles,
    /// ENFILE — system-wide fd limit reached.
    SystemFdQuotaExceeded,
    /// ENOBUFS / ENOMEM — no buffer space or out of memory.
    NoBufferSpace,
    /// ENOTCONN — transport endpoint is not connected.
    NotConnected,
    /// EPERM — operation not permitted.
    OperationNotPermitted,
    /// EPROTONOSUPPORT — protocol not supported.
    ProtocolNotSupported,
    /// ESOCKTNOSUPPORT — socket type not supported.
    SocketTypeNotSupported,
    /// Generic / unmapped errno.
    Unexpected,
};

// ---------------------------------------------------------------------------
// Low-level syscall wrappers
// ---------------------------------------------------------------------------

/// Create an epoll instance.
///
/// Wraps `epoll_create1(flags)`. Common flags: EPOLL_CLOEXEC (0x80000).
/// Errno: EMFILE, ENFILE, ENOMEM, EINVAL.
pub fn epoll_create1(flags: u32) PosixError!i32 {
    const rc = std.os.linux.epoll_create1(flags);
    if (rc < 0) return mapErrno(rc);
    return @intCast(rc);
}

/// Add, modify, or remove an fd from an epoll instance.
///
/// Wraps `epoll_ctl(epfd, op, fd, event)`.
/// Errno: EBADF, EEXIST, EINVAL, ENOENT, ENOMEM, ENOSPC, EPERM.
pub fn epoll_ctl(epfd: i32, op: u32, fd: i32, event: ?*std.os.linux.epoll_event) PosixError!void {
    const rc = std.os.linux.epoll_ctl(epfd, op, fd, event);
    if (rc < 0) return mapErrno(rc);
}

/// Wait for events on an epoll instance.
///
/// Wraps `epoll_wait(epfd, events, maxevents, timeout)`.
/// Returns the number of ready file descriptors (0 on timeout).
/// Errno: EBADF, EFAULT, EINTR, EINVAL.
pub fn epoll_wait(epfd: i32, events: []std.os.linux.epoll_event, timeout_ms: i32) PosixError!usize {
    const rc = std.os.linux.epoll_wait(epfd, events.ptr, @intCast(events.len), timeout_ms);
    if (rc < 0) return mapErrno(rc);
    return @intCast(rc);
}

/// Create a socket.
///
/// Wraps `socket(domain, sock_type, protocol)`.
/// Errno: EACCES, EAFNOSUPPORT, EINVAL, EMFILE, ENFILE, ENOBUFS, ENOMEM,
///        EPROTONOSUPPORT.
pub fn sock(domain: u32, sock_type: u32, protocol: u32) PosixError!i32 {
    const rc = std.os.linux.socket(domain, sock_type, protocol);
    if (rc < 0) return mapErrno(rc);
    return @intCast(rc);
}

/// Bind a socket to a local address.
///
/// Wraps `bind(fd, addr, addrlen)`.
/// Errno: EACCES, EADDRINUSE, EBADF, EINVAL, ENOTSOCK.
pub fn bind_raw(fd: i32, addr: *const std.posix.sockaddr, addrlen: u32) PosixError!void {
    const rc = std.os.linux.bind(fd, addr, addrlen);
    if (rc < 0) return mapErrno(rc);
}

/// Set a socket option.
///
/// Wraps `setsockopt(fd, level, optname, optval, optlen)`.
/// Errno: EBADF, EFAULT, EINVAL, ENOPROTOOPT, ENOTSOCK.
pub fn setsockopt(fd: i32, level: u32, optname: u32, optval: [*]const u8, optlen: u32) PosixError!void {
    const rc = std.os.linux.setsockopt(fd, level, optname, optval, optlen);
    if (rc < 0) return mapErrno(rc);
}

/// Device / fd control.
///
/// Wraps `ioctl(fd, request, arg)`.
/// Errno: EBADF, EFAULT, EINVAL, ENOTTY.
pub fn ioctl_raw(fd: i32, request: u32, arg: usize) PosixError!i32 {
    const rc = std.os.linux.ioctl(fd, request, arg);
    if (rc < 0) return mapErrno(rc);
    return @intCast(rc);
}

/// Send a message on a socket (scatter-gather I/O).
///
/// Wraps `sendmsg(fd, msg, flags)`. Returns bytes sent.
/// Errno: EACCES, EAGAIN, EBADF, ECONNRESET, EFAULT, EINTR, EINVAL,
///        EMSGSIZE, ENOBUFS, ENOMEM, ENOTCONN, EPIPE.
pub fn sendmsg(fd: i32, msg: *const std.posix.msghdr_const, flags: u32) PosixError!usize {
    const rc = std.os.linux.sendmsg(fd, msg, flags);
    if (rc < 0) return mapErrno(rc);
    return @intCast(rc);
}

/// Receive a message from a socket (scatter-gather I/O).
///
/// Wraps `recvmsg(fd, msg, flags)`. Returns bytes received.
/// Errno: EAGAIN, EBADF, ECONNREFUSED, EFAULT, EINTR, EINVAL, ENOMEM,
///        ENOTCONN, ENOTSOCK.
pub fn recvmsg(fd: i32, msg: *std.posix.msghdr, flags: u32) PosixError!usize {
    const rc = std.os.linux.recvmsg(fd, msg, flags);
    if (rc < 0) return mapErrno(rc);
    return @intCast(rc);
}

// ---------------------------------------------------------------------------
// Errno mapping
// ---------------------------------------------------------------------------

fn mapErrno(rc: isize) PosixError {
    const e: u32 = @intCast(-rc);
    return switch (e) {
        1 => PosixError.OperationNotPermitted, // EPERM
        13 => PosixError.PermissionDenied, // EACCES
        4 => PosixError.Interrupted, // EINTR
        9 => PosixError.BadFileDescriptor, // EBADF
        11 => PosixError.WouldBlock, // EAGAIN
        12, 105 => PosixError.NoBufferSpace, // ENOMEM, ENOBUFS
        22 => PosixError.InvalidArgument, // EINVAL
        24 => PosixError.TooManyOpenFiles, // EMFILE
        23 => PosixError.SystemFdQuotaExceeded, // ENFILE
        93 => PosixError.ProtocolNotSupported, // EPROTONOSUPPORT
        94 => PosixError.SocketTypeNotSupported, // ESOCKTNOSUPPORT
        97 => PosixError.AddressFamilyNotSupported, // EAFNOSUPPORT
        98 => PosixError.AddressInUse, // EADDRINUSE
        99 => PosixError.AddressNotAvailable, // EADDRNOTAVAIL
        104 => PosixError.ConnectionReset, // ECONNRESET
        107 => PosixError.NotConnected, // ENOTCONN
        111 => PosixError.ConnectionRefused, // ECONNREFUSED
        else => PosixError.Unexpected,
    };
}

// ---------------------------------------------------------------------------
// User-space socket API
// ---------------------------------------------------------------------------

pub const Socket = struct {
    endpoint: tcpip.Endpoint,
    /// The wait queue associated with this socket.
    /// For a listening socket we create it; for an accepted socket we inherit
    /// it from the stack's TCPEndpoint.
    wait_queue: *waiter.Queue,

    blocking: bool = true,
    allocator: std.mem.Allocator,

    wait_entry: waiter.Entry,

    pub fn init(allocator: std.mem.Allocator, ep: tcpip.Endpoint, wq: *waiter.Queue) *Socket {
        const self = allocator.create(Socket) catch @panic("OOM");
        self.* = .{
            .endpoint = ep,
            .wait_queue = wq,
            .allocator = allocator,
            .wait_entry = undefined,
        };
        self.wait_entry = waiter.Entry.init(self, notifyCallback);
        self.wait_queue.eventRegister(&self.wait_entry, waiter.EventIn | waiter.EventOut | waiter.EventErr | waiter.EventHUp);
        return self;
    }

    fn notifyCallback(e: *waiter.Entry) void {
        _ = e;
        // In a single-threaded stack, upcalls are handled by the event loop.
    }

    pub fn deinit(self: *Socket) void {
        self.wait_queue.eventUnregister(&self.wait_entry);
        self.endpoint.close();
        self.allocator.destroy(self.wait_queue);
        self.allocator.destroy(self);
    }
};

// -- BSD-like API surface ---------------------------------------------------

/// Create a user-space socket bound to the shardnet stack.
/// Mirrors `socket(domain, type, protocol)`.
pub fn usocket(s: *stack.Stack, domain: i32, sock_type: i32, protocol: i32) !*Socket {
    const net_proto: tcpip.NetworkProtocolNumber = switch (domain) {
        std.posix.AF.INET => 0x0800,
        std.posix.AF.INET6 => 0x86dd,
        else => return error.AddressFamilyNotSupported,
    };

    const trans_proto_id: tcpip.TransportProtocolNumber = if (protocol != 0) @intCast(protocol) else switch (sock_type) {
        std.posix.SOCK.STREAM => 6, // TCP
        std.posix.SOCK.DGRAM => 17, // UDP
        else => return error.SocketTypeNotSupported,
    };

    const trans_proto = s.transport_protocols.get(trans_proto_id) orelse return error.ProtocolNotSupported;

    const wq = try s.allocator.create(waiter.Queue);
    wq.* = .{};

    const ep = try trans_proto.newEndpoint(s, net_proto, wq);
    errdefer {
        s.allocator.destroy(wq);
    }

    return Socket.init(s.allocator, ep, wq);
}

/// Bind a user-space socket to a local address.
pub fn ubind(socket_obj: *Socket, addr: std.posix.sockaddr, len: std.posix.socklen_t) !void {
    _ = len;
    const full_addr = fromSockAddr(addr) catch return error.AddressFamilyNotSupported;
    try socket_obj.endpoint.bind(full_addr);
}

/// Initiate a connection on a user-space socket.
pub fn uconnect(socket_obj: *Socket, addr: std.posix.sockaddr, len: std.posix.socklen_t) !void {
    _ = len;
    const full_addr = fromSockAddr(addr) catch return error.AddressFamilyNotSupported;
    try socket_obj.endpoint.connect(full_addr);
}

/// Mark a socket as listening for incoming connections.
pub fn ulisten(socket_obj: *Socket, backlog: i32) !void {
    try socket_obj.endpoint.listen(backlog);
}

/// Accept an incoming connection, returning a new socket.
pub fn uaccept(socket_obj: *Socket, addr: ?*std.posix.sockaddr, len: ?*std.posix.socklen_t) !*Socket {
    const res = try socket_obj.endpoint.accept();

    if (addr) |out_addr| {
        if (res.ep.getRemoteAddress()) |remote| {
            toSockAddr(remote, out_addr, len);
        } else |_| {}
    }

    return Socket.init(socket_obj.allocator, res.ep, res.wq);
}

/// Receive data from a connected socket.
pub fn urecv(socket_obj: *Socket, buf: []u8, flags: u32) !usize {
    _ = flags;
    var iov = [_][]u8{buf};
    var uio = buffer.Uio.init(&iov);
    return socket_obj.endpoint.readv(&uio, null) catch |err| {
        if (err == tcpip.Error.WouldBlock) return error.WouldBlock;
        return err;
    };
}

/// Send data on a connected socket.
pub fn usend(socket_obj: *Socket, buf: []const u8, flags: u32) !usize {
    _ = flags;
    var iov = [_][]u8{@constCast(buf)};
    var uio = buffer.Uio.init(&iov);
    return socket_obj.endpoint.writev(&uio, .{}) catch |err| {
        if (err == tcpip.Error.WouldBlock) return error.WouldBlock;
        return err;
    };
}

/// Vectorised read from a socket.
pub fn ureadv(socket_obj: *Socket, iov: []const []u8) !usize {
    var uio = buffer.Uio.init(iov);
    return socket_obj.endpoint.readv(&uio, null) catch |err| {
        if (err == tcpip.Error.WouldBlock) return error.WouldBlock;
        return err;
    };
}

/// Vectorised write to a socket.
pub fn uwritev(socket_obj: *Socket, iov: []const []u8) !usize {
    var uio = buffer.Uio.init(iov);
    return socket_obj.endpoint.writev(&uio, .{}) catch |err| {
        if (err == tcpip.Error.WouldBlock) return error.WouldBlock;
        return err;
    };
}

/// Receive data and sender address from a datagram socket.
pub fn urecvfrom(socket_obj: *Socket, buf: []u8, flags: u32, addr: ?*std.posix.sockaddr, len: ?*std.posix.socklen_t) !usize {
    _ = flags;
    var iov = [_][]u8{buf};
    var uio = buffer.Uio.init(&iov);
    var full_addr: tcpip.FullAddress = undefined;
    const n = socket_obj.endpoint.readv(&uio, &full_addr) catch |err| {
        if (err == tcpip.Error.WouldBlock) return error.WouldBlock;
        return err;
    };
    if (addr) |out_addr| {
        toSockAddr(full_addr, out_addr, len);
    }
    return n;
}

/// Send data to a specific destination on a datagram socket.
pub fn usendto(socket_obj: *Socket, buf: []const u8, flags: u32, addr: ?*const std.posix.sockaddr, len: std.posix.socklen_t) !usize {
    _ = flags;
    _ = len;
    var iov = [_][]u8{@constCast(buf)};
    var uio = buffer.Uio.init(&iov);
    var opts = tcpip.WriteOptions{};
    var full_addr: tcpip.FullAddress = undefined;
    if (addr) |in_addr| {
        full_addr = fromSockAddr(in_addr.*) catch return error.AddressFamilyNotSupported;
        opts.to = &full_addr;
    }
    return socket_obj.endpoint.writev(&uio, opts) catch |err| {
        if (err == tcpip.Error.WouldBlock) return error.WouldBlock;
        return err;
    };
}

/// Close and destroy a user-space socket.
pub fn uclose(socket_obj: *Socket) void {
    socket_obj.deinit();
}

// ---------------------------------------------------------------------------
// Poll
// ---------------------------------------------------------------------------

pub const PollFd = struct {
    sock: *Socket,
    events: i16,
    revents: i16,
};

pub const POLLIN = 0x0001;
pub const POLLPRI = 0x0002;
pub const POLLOUT = 0x0004;
pub const POLLERR = 0x0008;
pub const POLLHUP = 0x0010;
pub const POLLNVAL = 0x0020;

fn waiterToPoll(mask: waiter.EventMask) i16 {
    var events: i16 = 0;
    if (mask & waiter.EventIn != 0) events |= POLLIN;
    if (mask & waiter.EventOut != 0) events |= POLLOUT;
    if (mask & waiter.EventErr != 0) events |= POLLERR;
    if (mask & waiter.EventHUp != 0) events |= POLLHUP;
    if (mask & waiter.EventPri != 0) events |= POLLPRI;
    return events;
}

fn pollToWaiter(events: i16) waiter.EventMask {
    var mask: waiter.EventMask = 0;
    if (events & POLLIN != 0) mask |= waiter.EventIn;
    if (events & POLLOUT != 0) mask |= waiter.EventOut;
    if (events & POLLPRI != 0) mask |= waiter.EventPri;
    return mask;
}

/// Polls multiple sockets for events.
/// timeout_ms: < 0 (infinite), 0 (immediate), > 0 (wait time in ms).
pub fn upoll(fds: []PollFd, timeout_ms: i32) !usize {
    // Fast path — check if any sockets are already ready.
    var ready_count: usize = 0;
    for (fds) |*pfd| {
        pfd.revents = 0;
        const mask = pfd.sock.wait_queue.events();
        const interested = pollToWaiter(pfd.events);
        const fired = mask & interested;

        if (fired != 0) {
            pfd.revents = waiterToPoll(fired);
            ready_count += 1;
        }
    }

    if (ready_count > 0 or timeout_ms == 0) {
        return ready_count;
    }

    // Slow path — register a temporary waiter on every socket's queue and
    // sleep until at least one fires or the timeout expires.
    var mutex = std.Thread.Mutex{};
    var cond = std.Thread.Condition{};
    var fired_flag = false;

    const PollContext = struct {
        mutex: *std.Thread.Mutex,
        cond: *std.Thread.Condition,
        fired: *bool,
    };
    var ctx = PollContext{ .mutex = &mutex, .cond = &cond, .fired = &fired_flag };

    const callback = struct {
        fn cb(e: *waiter.Entry) void {
            const c: *PollContext = @ptrCast(@alignCast(e.context.?));
            c.mutex.lock();
            c.fired.* = true;
            c.cond.signal();
            c.mutex.unlock();
        }
    }.cb;

    const entries = try std.heap.page_allocator.alloc(waiter.Entry, fds.len);
    defer std.heap.page_allocator.free(entries);

    for (fds, 0..) |*pfd, i| {
        entries[i] = waiter.Entry.init(&ctx, callback);
        pfd.sock.wait_queue.eventRegister(&entries[i], pollToWaiter(pfd.events));
    }

    mutex.lock();
    if (!fired_flag) {
        if (timeout_ms < 0) {
            cond.wait(&mutex);
        } else {
            const ns = @as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms;
            _ = cond.timedWait(&mutex, ns) catch {};
        }
    }
    mutex.unlock();

    for (fds, 0..) |*pfd, i| {
        pfd.sock.wait_queue.eventUnregister(&entries[i]);
    }

    // Re-check events after wake.
    ready_count = 0;
    for (fds) |*pfd| {
        pfd.revents = 0;
        const mask = pfd.sock.wait_queue.events();
        const interested = pollToWaiter(pfd.events);
        const current_fired = mask & interested;
        if (current_fired != 0) {
            pfd.revents = waiterToPoll(current_fired);
            ready_count += 1;
        }
    }

    return ready_count;
}

// ---------------------------------------------------------------------------
// Address conversion helpers
// ---------------------------------------------------------------------------

fn fromSockAddr(addr: std.posix.sockaddr) !tcpip.FullAddress {
    if (addr.family == std.posix.AF.INET) {
        const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&addr));
        return tcpip.FullAddress{
            .nic = 0,
            .addr = .{ .v4 = @bitCast(in.addr) },
            .port = std.mem.bigToNative(u16, in.port),
        };
    } else if (addr.family == std.posix.AF.INET6) {
        const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(&addr));
        return tcpip.FullAddress{
            .nic = 0,
            .addr = .{ .v6 = in6.addr },
            .port = std.mem.bigToNative(u16, in6.port),
        };
    }
    return error.AddressFamilyNotSupported;
}

fn toSockAddr(addr: tcpip.FullAddress, out: *std.posix.sockaddr, len: ?*std.posix.socklen_t) void {
    switch (addr.addr) {
        .v4 => |v| {
            var in = std.posix.sockaddr.in{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, addr.port),
                .addr = @bitCast(v),
                .zero = [_]u8{0} ** 8,
            };
            const size = @sizeOf(std.posix.sockaddr.in);
            if (len) |l| {
                if (l.* < size) return;
                l.* = size;
            }
            @memcpy(@as([*]u8, @ptrCast(out))[0..size], @as([*]const u8, @ptrCast(&in))[0..size]);
        },
        .v6 => |v| {
            var in6 = std.posix.sockaddr.in6{
                .family = std.posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, addr.port),
                .flowinfo = 0,
                .addr = v,
                .scope_id = 0,
            };
            const size = @sizeOf(std.posix.sockaddr.in6);
            if (len) |l| {
                if (l.* < size) return;
                l.* = size;
            }
            @memcpy(@as([*]u8, @ptrCast(out))[0..size], @as([*]const u8, @ptrCast(&in6))[0..size]);
        },
    }
}
