// SPDX-License-Identifier: MIT
//
// Zig definitions mirroring linux/if_xdp.h for use with AF_XDP sockets.
// Every struct is declared as `extern struct` so its in-memory layout matches
// the C ABI the kernel expects.  Comptime assertions at the bottom of this
// file verify sizes and field offsets against the kernel ABI.

const std = @import("std");

// ---------------------------------------------------------------------------
// Socket option level
// ---------------------------------------------------------------------------

/// Socket option level for AF_XDP sockets, used with getsockopt and setsockopt.
// NOTE: Introduced in Linux 4.18.
pub const SOL_XDP = 283;

// ---------------------------------------------------------------------------
// Socket options (second argument to getsockopt/setsockopt with SOL_XDP)
// ---------------------------------------------------------------------------

/// Retrieves the mmap offsets for all four XDP ring queues.
// NOTE: Introduced in Linux 4.18.
pub const XDP_MMAP_OFFSETS = 1;

/// Configures the RX ring size on an AF_XDP socket.
// NOTE: Introduced in Linux 4.18.
pub const XDP_RX_RING = 2;

/// Configures the TX ring size on an AF_XDP socket.
// NOTE: Introduced in Linux 4.18.
pub const XDP_TX_RING = 3;

/// Registers a UMEM region with an AF_XDP socket.
// NOTE: Introduced in Linux 4.18.
pub const XDP_UMEM_REG = 4;

/// Configures the UMEM fill ring on an AF_XDP socket.
// NOTE: Introduced in Linux 4.18.
pub const XDP_UMEM_FILL_RING = 5;

/// Configures the UMEM completion ring on an AF_XDP socket.
// NOTE: Introduced in Linux 4.18.
pub const XDP_UMEM_COMPLETION_RING = 6;

/// Retrieves per-socket XDP statistics via getsockopt.
// NOTE: Introduced in Linux 5.0.
pub const XDP_STATISTICS = 7;

/// Retrieves XDP socket options, such as whether zero-copy is active.
// NOTE: Introduced in Linux 5.3.
pub const XDP_OPTIONS = 8;

// ---------------------------------------------------------------------------
// Bind flags (passed in the flags field of sockaddr_xdp)
// ---------------------------------------------------------------------------

/// Shares a single UMEM region between multiple AF_XDP sockets.
// NOTE: Introduced in Linux 4.18.
pub const XDP_SHARED_UMEM = 1 << 0;

/// Forces copy mode for packet delivery instead of zero-copy.
// NOTE: Introduced in Linux 4.18.
pub const XDP_COPY = 1 << 1;

/// Requests zero-copy mode for packet delivery to userspace.
// NOTE: Introduced in Linux 4.18.
pub const XDP_ZEROCOPY = 1 << 2;

/// Enables the need-wakeup mechanism on fill and TX rings.
// NOTE: Introduced in Linux 5.4.
pub const XDP_USE_NEED_WAKEUP = 1 << 3;

/// Enables scatter-gather multi-buffer mode for XDP.
// NOTE: Introduced in Linux 6.3.
pub const XDP_USE_SG = 1 << 4;

// ---------------------------------------------------------------------------
// UMEM flags (passed in the flags field of xdp_umem_reg, kernel 5.7+)
// ---------------------------------------------------------------------------

/// Allows unaligned chunk placement within the UMEM region.
// NOTE: Introduced in Linux 5.7.
pub const XDP_UMEM_UNALIGNED_CHUNK_FLAG = 1 << 0;

// ---------------------------------------------------------------------------
// Ring flags (readable from the flags word inside a mapped ring)
// ---------------------------------------------------------------------------

/// Indicates that the kernel requires a wakeup via poll or sendto.
// NOTE: Introduced in Linux 5.4.
pub const XDP_RING_NEED_WAKEUP = 1 << 0;

// ---------------------------------------------------------------------------
// XDP options flags (returned by the XDP_OPTIONS getsockopt call)
// ---------------------------------------------------------------------------

/// Indicates that the socket is currently operating in zero-copy mode.
// NOTE: Introduced in Linux 5.3.
pub const XDP_OPTIONS_ZEROCOPY = 1 << 0;

// ---------------------------------------------------------------------------
// mmap page-offset constants
// ---------------------------------------------------------------------------

/// Base mmap offset for the RX ring.
// NOTE: Introduced in Linux 4.18.
pub const XDP_PGOFF_RX_RING: i64 = 0;

/// Base mmap offset for the TX ring.
// NOTE: Introduced in Linux 4.18.
pub const XDP_PGOFF_TX_RING: i64 = 0x80000000;

/// Base mmap offset for the UMEM fill ring.
// NOTE: Introduced in Linux 4.18.
pub const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x100000000;

/// Base mmap offset for the UMEM completion ring.
// NOTE: Introduced in Linux 4.18.
pub const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x180000000;

// ---------------------------------------------------------------------------
// Structs matching the kernel ABI from linux/if_xdp.h
// ---------------------------------------------------------------------------

/// Describes a UMEM memory region for AF_XDP.  Passed to setsockopt with
/// XDP_UMEM_REG to register a contiguous block of userspace memory as the
/// packet buffer area.
// NOTE: Introduced in Linux 4.18.  A `flags` field (u32) was appended in
// Linux 5.7 for features like XDP_UMEM_UNALIGNED_CHUNK_FLAG; that field is
// omitted here to match the original 24-byte layout used by this driver.
pub const xdp_umem_reg = extern struct {
    /// Start address of the UMEM packet data area.
    addr: u64,
    /// Total length in bytes of the UMEM packet data area.
    len: u64,
    /// Size of each chunk within the UMEM region.
    chunk_size: u32,
    /// Number of bytes reserved at the beginning of each chunk for headroom.
    headroom: u32,
};

/// Byte offsets of the producer index, consumer index, descriptor array, and
/// flags word within a single mmap'd ring region.
// NOTE: Introduced in Linux 4.18.  The flags field was added in Linux 5.4.
pub const xdp_ring_offset = extern struct {
    /// Byte offset of the producer index within the mmap'd region.
    producer: u64,
    /// Byte offset of the consumer index within the mmap'd region.
    consumer: u64,
    /// Byte offset of the descriptor array within the mmap'd region.
    desc: u64,
    /// Byte offset of the flags word within the mmap'd region.
    flags: u64,
};

/// Aggregates the mmap offsets for all four XDP ring queues (RX, TX, fill,
/// and completion).  Retrieved via getsockopt with XDP_MMAP_OFFSETS.
// NOTE: Introduced in Linux 4.18.
pub const xdp_mmap_offsets = extern struct {
    /// Offsets for the RX ring.
    rx: xdp_ring_offset,
    /// Offsets for the TX ring.
    tx: xdp_ring_offset,
    /// Offsets for the UMEM fill ring.
    fr: xdp_ring_offset,
    /// Offsets for the UMEM completion ring.
    cr: xdp_ring_offset,
};

/// Describes a single packet descriptor in an XDP RX or TX ring.  Each
/// descriptor references a region within the UMEM area.
// NOTE: Introduced in Linux 4.18.
pub const xdp_desc = extern struct {
    /// Byte offset into the UMEM area where the packet data begins.
    addr: u64,
    /// Length of the packet data in bytes.
    len: u32,
    /// Per-descriptor option flags.
    options: u32,
};

/// Socket address structure for AF_XDP sockets, used with bind(2) to attach
/// the socket to a specific network interface and hardware queue.
// NOTE: Introduced in Linux 4.18.
pub const sockaddr_xdp = extern struct {
    /// Address family (always AF_XDP).
    family: u16,
    /// Bind flags such as XDP_COPY, XDP_ZEROCOPY, and XDP_SHARED_UMEM.
    flags: u16,
    /// Network interface index to bind to.
    ifindex: u32,
    /// Hardware RX queue identifier to attach to.
    queue_id: u32,
    /// File descriptor of the socket whose UMEM should be shared (when
    /// XDP_SHARED_UMEM is set in flags).
    shared_umem_fd: u32,
};

/// Per-socket statistics returned by getsockopt with XDP_STATISTICS.  The
/// first three fields are available since Linux 5.0; the remaining three
/// counters were added in Linux 5.9.
// NOTE: Introduced in Linux 5.0.  Extended with three additional counters
// in Linux 5.9.
pub const xdp_statistics = extern struct {
    /// Total packets dropped for reasons other than invalid descriptors.
    rx_dropped: u64,
    /// Packets dropped on the RX path due to an invalid descriptor.
    rx_invalid_descs: u64,
    /// Packets dropped on the TX path due to an invalid descriptor.
    tx_invalid_descs: u64,
    /// Packets dropped because the RX ring was full.
    // NOTE: Field added in Linux 5.9.
    rx_ring_full: u64,
    /// Failed fill-ring retrievals because the fill ring was empty.
    // NOTE: Field added in Linux 5.9.
    rx_fill_ring_empty_descs: u64,
    /// Failed TX-ring retrievals because the TX ring was empty.
    // NOTE: Field added in Linux 5.9.
    tx_ring_empty_descs: u64,
};

// ---------------------------------------------------------------------------
// Comptime ABI assertions
//
// These checks run at compile time and ensure that the struct sizes and field
// offsets defined above match the layout the Linux kernel expects.  A failure
// here means the definitions have drifted from the kernel ABI.
// ---------------------------------------------------------------------------

comptime {
    // -- xdp_umem_reg (24 bytes: u64 + u64 + u32 + u32) --
    std.debug.assert(@sizeOf(xdp_umem_reg) == 24);
    std.debug.assert(@offsetOf(xdp_umem_reg, "addr") == 0);
    std.debug.assert(@offsetOf(xdp_umem_reg, "len") == 8);
    std.debug.assert(@offsetOf(xdp_umem_reg, "chunk_size") == 16);
    std.debug.assert(@offsetOf(xdp_umem_reg, "headroom") == 20);

    // -- xdp_ring_offset (32 bytes: 4 x u64) --
    std.debug.assert(@sizeOf(xdp_ring_offset) == 32);
    std.debug.assert(@offsetOf(xdp_ring_offset, "producer") == 0);
    std.debug.assert(@offsetOf(xdp_ring_offset, "consumer") == 8);
    std.debug.assert(@offsetOf(xdp_ring_offset, "desc") == 16);
    std.debug.assert(@offsetOf(xdp_ring_offset, "flags") == 24);

    // -- xdp_mmap_offsets (128 bytes: 4 x xdp_ring_offset) --
    std.debug.assert(@sizeOf(xdp_mmap_offsets) == 128);
    std.debug.assert(@offsetOf(xdp_mmap_offsets, "rx") == 0);
    std.debug.assert(@offsetOf(xdp_mmap_offsets, "tx") == 32);
    std.debug.assert(@offsetOf(xdp_mmap_offsets, "fr") == 64);
    std.debug.assert(@offsetOf(xdp_mmap_offsets, "cr") == 96);

    // -- xdp_desc (16 bytes: u64 + u32 + u32) --
    std.debug.assert(@sizeOf(xdp_desc) == 16);
    std.debug.assert(@offsetOf(xdp_desc, "addr") == 0);
    std.debug.assert(@offsetOf(xdp_desc, "len") == 8);
    std.debug.assert(@offsetOf(xdp_desc, "options") == 12);

    // -- sockaddr_xdp (16 bytes: u16 + u16 + u32 + u32 + u32) --
    std.debug.assert(@sizeOf(sockaddr_xdp) == 16);
    std.debug.assert(@offsetOf(sockaddr_xdp, "family") == 0);
    std.debug.assert(@offsetOf(sockaddr_xdp, "flags") == 2);
    std.debug.assert(@offsetOf(sockaddr_xdp, "ifindex") == 4);
    std.debug.assert(@offsetOf(sockaddr_xdp, "queue_id") == 8);
    std.debug.assert(@offsetOf(sockaddr_xdp, "shared_umem_fd") == 12);

    // -- xdp_statistics (48 bytes: 6 x u64) --
    std.debug.assert(@sizeOf(xdp_statistics) == 48);
    std.debug.assert(@offsetOf(xdp_statistics, "rx_dropped") == 0);
    std.debug.assert(@offsetOf(xdp_statistics, "rx_invalid_descs") == 8);
    std.debug.assert(@offsetOf(xdp_statistics, "tx_invalid_descs") == 16);
    std.debug.assert(@offsetOf(xdp_statistics, "rx_ring_full") == 24);
    std.debug.assert(@offsetOf(xdp_statistics, "rx_fill_ring_empty_descs") == 32);
    std.debug.assert(@offsetOf(xdp_statistics, "tx_ring_empty_descs") == 40);
}
