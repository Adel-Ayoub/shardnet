/// Zero-copy packet buffer system with ref-counted clusters and slab allocation.
// NOTE: All pool operations are single-threaded. Use per-thread pools for concurrent Rx/Tx.
const std = @import("std");
const header = @import("header.zig");
const stats = @import("stats.zig");
const Allocator = std.mem.Allocator;

/// Cluster is a ref-counted fixed-size buffer.
pub const Cluster = struct {
    ref_count: usize,
    pool: *ClusterPool,
    next: ?*Cluster = null,
    data: [header.ClusterSize]u8 align(64),

    pub fn acquire(self: *Cluster) void {
        self.ref_count += 1;
    }

    pub fn release(self: *Cluster) void {
        // SAFETY: Cluster must belong to a valid pool.
        std.debug.assert(self.pool != undefined);
        self.ref_count -= 1;
        if (self.ref_count == 0) {
            self.pool.returnToPool(self);
        }
    }
};

/// ClusterView is a view into a Cluster.
pub const ClusterView = struct {
    cluster: ?*Cluster,
    view: []u8,
};

/// ClusterPool manages a pool of Clusters.
pub const ClusterPool = struct {
    allocator: Allocator,
    free_list: ?*Cluster = null,
    count: usize = 0,
    total_acquires: u64 = 0,
    total_releases: u64 = 0,
    allocated: usize = 0,
    peak_allocated: usize = 0,

    pub fn init(allocator: Allocator) ClusterPool {
        return .{
            .allocator = allocator,
            .free_list = null,
            .count = 0,
        };
    }

    pub fn deinit(self: *ClusterPool) void {
        var it = self.free_list;
        while (it) |c| {
            const next = c.next;
            self.allocator.destroy(c);
            it = next;
        }
        self.free_list = null;
    }

    pub fn prewarm(self: *ClusterPool, count: usize) !void {
        for (0..count) |_| {
            const c = try self.allocator.create(Cluster);
            c.* = .{
                .ref_count = 0,
                .pool = self,
                .next = self.free_list,
                .data = undefined,
            };
            self.free_list = c;
            self.count += 1;
        }
    }

    pub fn acquire(self: *ClusterPool) !*Cluster {
        self.total_acquires += 1;
        self.allocated += 1;
        if (self.allocated > self.peak_allocated) {
            self.peak_allocated = self.allocated;
        }

        if (self.free_list) |c| {
            self.free_list = c.next;
            if (self.count > 0) self.count -= 1;
            c.ref_count = 1;
            return c;
        }

        stats.global_stats.pool.cluster_fallback += 1;
        const c = try self.allocator.create(Cluster);
        c.* = .{
            .ref_count = 1,
            .pool = self,
            .next = null,
            .data = undefined,
        };
        return c;
    }

    pub fn returnToPool(self: *ClusterPool, cluster: *Cluster) void {
        // SAFETY: Cluster must belong to this pool.
        std.debug.assert(cluster.pool == self);

        self.total_releases += 1;
        if (self.allocated > 0) self.allocated -= 1;

        // Debug poison pattern to catch use-after-free.
        if (std.debug.runtime_safety) {
            @memset(&cluster.data, 0xDE);
        }

        cluster.next = self.free_list;
        self.free_list = cluster;
        self.count += 1;
    }

    pub const PoolStats = struct {
        allocated: usize,
        free: usize,
        peak_allocated: usize,
        total_acquires: u64,
        total_releases: u64,
    };

    pub fn poolStats(self: *const ClusterPool) PoolStats {
        return .{
            .allocated = self.allocated,
            .free = self.count,
            .peak_allocated = self.peak_allocated,
            .total_acquires = self.total_acquires,
            .total_releases = self.total_releases,
        };
    }
};

/// Pool is a simple generic object pool.
pub fn Pool(comptime T: type) type {
    return struct {
        const Self = @This();
        allocator: Allocator,
        free_list: std.ArrayList(*T),
        capacity: usize,

        pub fn init(allocator: Allocator, capacity: usize) Self {
            return .{
                .allocator = allocator,
                .free_list = std.ArrayList(*T).init(allocator),
                .capacity = capacity,
            };
        }

        pub fn prewarm(self: *Self, count: usize) !void {
            const to_warm = @min(count, self.capacity);
            try self.free_list.ensureTotalCapacity(to_warm);
            for (0..to_warm) |_| {
                const node = try self.allocator.create(T);
                self.release(node);
            }
        }

        pub fn deinit(self: *Self) void {
            for (self.free_list.items) |node| {
                self.allocator.destroy(node);
            }
            self.free_list.deinit();
        }

        pub fn acquire(self: *Self) !*T {
            if (self.free_list.popOrNull()) |node| {
                return node;
            }
            stats.global_stats.pool.generic_fallback += 1;
            return try self.allocator.create(T);
        }

        pub fn release(self: *Self, node: *T) void {
            if (self.free_list.items.len >= self.capacity) {
                self.allocator.destroy(node);
                return;
            }
            self.free_list.append(node) catch {
                self.allocator.destroy(node);
            };
        }

        pub fn tryRelease(self: *Self, node: *T) bool {
            if (self.free_list.items.len >= self.capacity) {
                return false;
            }
            self.free_list.append(node) catch {
                return false;
            };
            return true;
        }
    };
}

/// BufferPool manages a pool of raw buffers.
pub const BufferPool = struct {
    allocator: Allocator,
    buffer_size: usize,
    capacity: usize,
    free_list: std.ArrayList([]u8),

    pub fn init(allocator: Allocator, buffer_size: usize, capacity: usize) BufferPool {
        return .{
            .allocator = allocator,
            .buffer_size = buffer_size,
            .capacity = capacity,
            .free_list = std.ArrayList([]u8).init(allocator),
        };
    }

    pub fn prewarm(self: *BufferPool, count: usize) !void {
        const to_warm = @min(count, self.capacity);
        try self.free_list.ensureTotalCapacity(to_warm);
        for (0..to_warm) |_| {
            const buf = try self.allocator.alloc(u8, self.buffer_size);
            self.free_list.appendAssumeCapacity(buf);
        }
    }

    pub fn deinit(self: *BufferPool) void {
        for (self.free_list.items) |buf| {
            self.allocator.free(buf);
        }
        self.free_list.deinit();
    }

    pub fn acquire(self: *BufferPool) ![]u8 {
        if (self.free_list.popOrNull()) |buf| {
            return buf;
        }
        stats.global_stats.pool.buffer_fallback += 1;
        return try self.allocator.alloc(u8, self.buffer_size);
    }

    pub fn release(self: *BufferPool, buf: []u8) void {
        if (self.free_list.items.len >= self.capacity) {
            self.allocator.free(buf);
            return;
        }
        self.free_list.append(buf) catch {
            self.allocator.free(buf);
        };
    }
};

/// View is a slice of a buffer.
pub const View = []u8;

/// ConsumptionCallback allows the stack to be notified when the application
/// has finished processing zero-copy data.
pub const ConsumptionCallback = struct {
    ptr: *anyopaque,
    run: *const fn (ptr: *anyopaque, size: usize) void,
};

/// Uio represents a user-space I/O vector (iovec).
pub const Uio = struct {
    iov: []const []u8,
    iov_idx: usize = 0,
    offset: usize = 0,
    resid: usize,

    pub fn init(iov: []const []u8) Uio {
        var total: usize = 0;
        for (iov) |v| total += v.len;
        return .{
            .iov = iov,
            .resid = total,
        };
    }

    pub fn moveFrom(self: *Uio, src: []const u8) usize {
        const to_move = @min(src.len, self.resid);
        var moved: usize = 0;
        while (moved < to_move and self.iov_idx < self.iov.len) {
            const current_iov = self.iov[self.iov_idx][self.offset..];
            const chunk = @min(to_move - moved, current_iov.len);
            // In a real BSD-style uio_move, this would perform the copy between
            // the kernel/stack and user space. Since we are in the same address space
            // here, this is the final copy into the application's buffer.
            @memcpy(current_iov[0..chunk], src[moved .. moved + chunk]);
            moved += chunk;
            self.offset += chunk;
            self.resid -= chunk;
            if (self.offset == self.iov[self.iov_idx].len) {
                self.iov_idx += 1;
                self.offset = 0;
            }
        }
        return moved;
    }

    pub fn skip(self: *Uio, count: usize) void {
        var remaining = count;
        while (remaining > 0 and self.iov_idx < self.iov.len) {
            const current_iov_len = self.iov[self.iov_idx].len - self.offset;
            const to_skip = @min(remaining, current_iov_len);
            remaining -= to_skip;
            self.offset += to_skip;
            self.resid -= to_skip;
            if (self.offset == self.iov[self.iov_idx].len) {
                self.iov_idx += 1;
                self.offset = 0;
            }
        }
    }

    /// uio_memove copies data between a buffer and a Uio.
    /// If direction is .FromUio, it copies from Uio to buf.
    /// If direction is .ToUio, it copies from buf to Uio.
    pub fn uio_memove(uio: *Uio, buf: []u8, direction: enum { FromUio, ToUio }) usize {
        const to_move = @min(buf.len, uio.resid);
        var moved: usize = 0;
        while (moved < to_move and uio.iov_idx < uio.iov.len) {
            const current_iov = uio.iov[uio.iov_idx][uio.offset..];
            const chunk = @min(to_move - moved, current_iov.len);
            switch (direction) {
                .FromUio => @memcpy(buf[moved .. moved + chunk], current_iov[0..chunk]),
                .ToUio => @memcpy(current_iov[0..chunk], buf[moved .. moved + chunk]),
            }
            moved += chunk;
            uio.offset += chunk;
            uio.resid -= chunk;
            if (uio.offset == uio.iov[uio.iov_idx].len) {
                uio.iov_idx += 1;
                uio.offset = 0;
            }
        }
        return moved;
    }

    /// toClusters copies data from Uio into a VectorisedView backed by Clusters.
    /// It packs data efficiently into the stack's buffer chain (Clusters).
    pub fn toClusters(uio: *Uio, pool: *ClusterPool, allocator: Allocator) !VectorisedView {
        const num_views = (uio.resid + header.ClusterSize - 1) / header.ClusterSize;
        const views = try allocator.alloc(ClusterView, num_views);
        errdefer allocator.free(views);

        var total_copied: usize = 0;
        var view_idx: usize = 0;

        while (uio.resid > 0) {
            const cluster = try pool.acquire();
            const to_copy = @min(uio.resid, header.ClusterSize);
            _ = uio.uio_memove(cluster.data[0..to_copy], .FromUio);
            views[view_idx] = .{ .cluster = cluster, .view = cluster.data[0..to_copy] };
            view_idx += 1;
            total_copied += to_copy;
        }

        return .{
            .views = views[0..view_idx],
            .original_views = views[0..view_idx],
            .size = total_copied,
            .allocator = allocator,
        };
    }

    /// toViews constructs a VectorisedView by referencing the memory in Uio.
    /// This is BSD-style zero-copy where we "copy the source address" instead of data.
    /// If an iovec element is larger than chunk_size, it is broken into multiple views.
    pub fn toViews(uio: *Uio, allocator: Allocator, chunk_size: usize) !VectorisedView {
        // Calculate required views
        var num_views: usize = 0;
        var i: usize = uio.iov_idx;
        var off = uio.offset;
        var rem = uio.resid;
        while (rem > 0 and i < uio.iov.len) {
            const current_len = uio.iov[i].len - off;
            const to_take = @min(rem, current_len);
            num_views += (to_take + chunk_size - 1) / chunk_size;
            rem -= to_take;
            i += 1;
            off = 0;
        }

        const views = try allocator.alloc(ClusterView, num_views);
        errdefer allocator.free(views);

        var view_idx: usize = 0;
        const initial_resid = uio.resid;
        while (uio.resid > 0 and uio.iov_idx < uio.iov.len) {
            const current_iov = uio.iov[uio.iov_idx][uio.offset..];
            const to_take_from_iov = @min(uio.resid, current_iov.len);

            var iov_rem = to_take_from_iov;
            var iov_off: usize = 0;
            while (iov_rem > 0) {
                const chunk = @min(iov_rem, chunk_size);
                views[view_idx] = .{ .cluster = null, .view = current_iov[iov_off .. iov_off + chunk] };
                view_idx += 1;
                iov_rem -= chunk;
                iov_off += chunk;
            }

            uio.offset += to_take_from_iov;
            uio.resid -= to_take_from_iov;
            if (uio.offset == uio.iov[uio.iov_idx].len) {
                uio.iov_idx += 1;
                uio.offset = 0;
            }
        }

        return .{
            .views = views,
            .original_views = views,
            .size = initial_resid,
            .allocator = allocator,
        };
    }
};

/// VectorisedView is a vectorised version of View using non contiguous memory.
pub const VectorisedView = struct {
    views: []ClusterView,
    size: usize,
    allocator: ?Allocator = null,
    view_pool: ?*BufferPool = null,
    original_views: []ClusterView = &[_]ClusterView{},
    consumption_callback: ?ConsumptionCallback = null,

    pub fn init(size: usize, views: []ClusterView) VectorisedView {
        return .{
            .views = views,
            .size = size,
        };
    }

    pub fn initFromViews(views: []ClusterView) VectorisedView {
        var total: usize = 0;
        for (views) |v| total += v.view.len;
        return .{
            .views = views,
            .original_views = views,
            .size = total,
        };
    }

    pub fn fromSlice(data: []const u8, allocator: Allocator, pool: *ClusterPool) !VectorisedView {
        const cluster = try pool.acquire();
        const to_copy = @min(data.len, header.ClusterSize);
        @memcpy(cluster.data[0..to_copy], data[0..to_copy]);
        const views = try allocator.alloc(ClusterView, 1);
        views[0] = .{ .cluster = cluster, .view = cluster.data[0..to_copy] };
        return .{
            .views = views,
            .original_views = views,
            .size = to_copy,
            .allocator = allocator,
        };
    }

    pub fn fromExternal(data: []u8, views_buffer: []ClusterView) VectorisedView {
        views_buffer[0] = .{ .cluster = null, .view = data };
        return .{
            .views = views_buffer[0..1],
            .original_views = views_buffer[0..1],
            .size = data.len,
        };
    }

    pub fn fromExternals(data: []const []u8, views_buffer: []ClusterView) VectorisedView {
        for (data, 0..) |slice, i| {
            views_buffer[i] = .{ .cluster = null, .view = slice };
        }
        return initFromViews(views_buffer[0..data.len]);
    }

    pub fn fromExternalSlicing(data: []u8, views_buffer: []ClusterView, chunk_size: usize) VectorisedView {
        var remaining = data.len;
        var offset: usize = 0;
        var i: usize = 0;
        while (remaining > 0 and i < views_buffer.len) : (i += 1) {
            const to_take = @min(remaining, chunk_size);
            views_buffer[i] = .{ .cluster = null, .view = data[offset .. offset + to_take] };
            remaining -= to_take;
            offset += to_take;
        }
        return initFromViews(views_buffer[0..i]);
    }

    pub fn fromExternalZeroCopy(data: []u8, allocator: Allocator, chunk_size: usize) !VectorisedView {
        const num_views = (data.len + chunk_size - 1) / chunk_size;
        const views = try allocator.alloc(ClusterView, num_views);
        var res = fromExternalSlicing(data, views, chunk_size);
        res.allocator = allocator;
        return res;
    }

    pub fn fromUio(uio: Uio, views_buffer: []ClusterView) VectorisedView {
        var count: usize = 0;
        var total: usize = 0;
        var i: usize = uio.iov_idx;
        while (i < uio.iov.len and count < views_buffer.len) : (i += 1) {
            const data = if (i == uio.iov_idx) uio.iov[i][uio.offset..] else uio.iov[i];
            if (data.len == 0) continue;
            views_buffer[count] = .{ .cluster = null, .view = data };
            total += data.len;
            count += 1;
        }
        return .{
            .views = views_buffer[0..count],
            .original_views = views_buffer[0..count],
            .size = total,
        };
    }

    pub fn empty() VectorisedView {
        return .{ .views = &[_]ClusterView{}, .size = 0 };
    }

    pub fn deinit(self: *VectorisedView) void {
        const total_size = self.size;
        for (self.views) |cv| {
            if (cv.cluster) |c| c.release();
        }
        const ov = self.original_views;
        if (self.view_pool) |pool| {
            pool.release(std.mem.sliceAsBytes(ov));
        } else if (self.allocator) |alloc| {
            if (ov.len > 0) alloc.free(ov);
        }

        if (self.consumption_callback) |cb| {
            cb.run(cb.ptr, total_size);
        }
        self.* = undefined;
    }

    pub fn capLength(self: *VectorisedView, length: usize) void {
        if (self.size <= length) return;
        self.size = length;
        var remaining = length;
        for (self.views, 0..) |*v, i| {
            if (v.view.len >= remaining) {
                if (remaining == 0) {
                    self.views = self.views[0..i];
                } else {
                    v.view = v.view[0..remaining];
                    self.views = self.views[0 .. i + 1];
                }
                return;
            }
            remaining -= v.view.len;
        }
    }

    pub fn trimFront(self: *VectorisedView, count: usize) void {
        var remaining = count;
        while (remaining > 0 and self.views.len > 0) {
            if (remaining < self.views[0].view.len) {
                self.size -= remaining;
                self.views[0].view = self.views[0].view[remaining..];
                return;
            }
            remaining -= self.views[0].view.len;
            self.removeFirst();
        }
    }

    pub fn first(self: VectorisedView) ?[]u8 {
        if (self.views.len == 0) return null;
        return self.views[0].view;
    }

    pub fn removeFirst(self: *VectorisedView) void {
        if (self.views.len == 0) return;
        if (self.views[0].cluster) |c| c.release();
        self.size -= self.views[0].view.len;
        self.views = self.views[1..];
    }

    pub fn moveToUio(self: *VectorisedView, uio: *Uio) usize {
        var total_moved: usize = 0;
        while (self.views.len > 0 and uio.resid > 0) {
            const v = self.views[0].view;
            const to_move = @min(v.len, uio.resid);
            const moved = uio.moveFrom(v[0..to_move]);
            total_moved += moved;
            if (moved < v.len) {
                // Partial move from this view
                self.views[0].view = v[moved..];
                self.size -= moved;
                break;
            } else {
                // Entire view moved
                self.removeFirst();
            }
        }
        return total_moved;
    }

    pub fn toView(self: VectorisedView, allocator: Allocator) ![]u8 {
        const out = try allocator.alloc(u8, self.size);
        var offset: usize = 0;
        for (self.views) |v| {
            @memcpy(out[offset .. offset + v.view.len], v.view);
            offset += v.view.len;
        }
        return out;
    }

    pub fn clone(self: VectorisedView, allocator: Allocator) !VectorisedView {
        const new_views = try allocator.alloc(ClusterView, self.views.len);
        @memcpy(new_views, self.views);
        for (new_views) |cv| {
            if (cv.cluster) |c| c.acquire();
        }
        return .{
            .views = new_views,
            .original_views = new_views,
            .size = self.size,
            .allocator = allocator,
        };
    }

    pub fn cloneInPool(self: VectorisedView, pool: *BufferPool) !VectorisedView {
        const view_mem = try pool.acquire();
        const original_views = @as([]ClusterView, @ptrCast(@alignCast(std.mem.bytesAsSlice(ClusterView, view_mem))));
        if (self.views.len > original_views.len) {
            pool.release(view_mem);
            return error.OutOfMemory;
        }
        const new_views = original_views[0..self.views.len];
        @memcpy(new_views, self.views);
        for (new_views) |cv| {
            if (cv.cluster) |c| c.acquire();
        }
        return .{
            .views = new_views,
            .original_views = original_views,
            .size = self.size,
            .view_pool = pool,
        };
    }
};

pub const Prependable = struct {
    buf: []u8,
    usedIdx: usize,

    pub fn init(buf: []u8) Prependable {
        return .{ .buf = buf, .usedIdx = buf.len };
    }

    pub fn initFull(buf: []u8) Prependable {
        return .{ .buf = buf, .usedIdx = 0 };
    }

    pub fn view(self: Prependable) []u8 {
        return self.buf[self.usedIdx..];
    }

    pub fn usedLength(self: Prependable) usize {
        return self.buf.len - self.usedIdx;
    }

    pub fn prepend(self: *Prependable, size: usize) ?[]u8 {
        if (size > self.usedIdx) return null;
        self.usedIdx -= size;
        return self.buf[self.usedIdx .. self.usedIdx + size];
    }
};

test "Cluster single-threaded refcounting" {
    const allocator = std.testing.allocator;
    var pool = ClusterPool.init(allocator);
    defer pool.deinit();

    const cluster = try pool.acquire();
    try std.testing.expectEqual(@as(usize, 1), cluster.ref_count);

    cluster.acquire();
    try std.testing.expectEqual(@as(usize, 2), cluster.ref_count);

    cluster.release();
    try std.testing.expectEqual(@as(usize, 1), cluster.ref_count);

    cluster.release();
    try std.testing.expectEqual(@as(usize, 1), pool.count);
}

test "ClusterPool single-threaded usage" {
    const allocator = std.testing.allocator;
    var pool = ClusterPool.init(allocator);
    defer pool.deinit();

    const c1 = try pool.acquire();
    const c2 = try pool.acquire();
    try std.testing.expectEqual(@as(usize, 0), pool.count);

    c1.release();
    try std.testing.expectEqual(@as(usize, 1), pool.count);

    c2.release();
    try std.testing.expectEqual(@as(usize, 2), pool.count);

    const c3 = try pool.acquire();
    try std.testing.expectEqual(@as(usize, 1), pool.count);
    c3.release();
}

test "BufferPool single-threaded usage" {
    const allocator = std.testing.allocator;
    var pool = BufferPool.init(allocator, 1024, 2);
    defer pool.deinit();

    const b1 = try pool.acquire();
    const b2 = try pool.acquire();
    const b3 = try pool.acquire();

    try std.testing.expectEqual(@as(usize, 0), pool.free_list.items.len);

    pool.release(b1);
    try std.testing.expectEqual(@as(usize, 1), pool.free_list.items.len);

    pool.release(b2);
    try std.testing.expectEqual(@as(usize, 2), pool.free_list.items.len);

    pool.release(b3); // Exceeds capacity, should be freed
    try std.testing.expectEqual(@as(usize, 2), pool.free_list.items.len);
}
