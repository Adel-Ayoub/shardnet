# Shardnet

## A high-performance userspace TCP/IP stack written in Zig.

## Installation

```sh
# Clone
git clone https://github.com/Adel-Ayoub/shardnet.git
cd shardnet

# Build
zig build

# Run tests
zig build test

# Build examples
zig build example
```

---

## Architecture

### Network Stack Layers

```
┌─────────────────────────────────────────────────────────────┐
│                      Application                             │
├─────────────────────────────────────────────────────────────┤
│                    Socket API (POSIX)                        │
├─────────────────────────────────────────────────────────────┤
│           Transport Layer (TCP / UDP / ICMPv6)               │
├─────────────────────────────────────────────────────────────┤
│           Network Layer (IPv4 / IPv6 / ICMP / ARP)           │
├─────────────────────────────────────────────────────────────┤
│                   Link Layer (Ethernet)                      │
├─────────────────────────────────────────────────────────────┤
│     Drivers (TAP / AF_PACKET / AF_XDP / Loopback)            │
└─────────────────────────────────────────────────────────────┘
```

### Packet Flow

```
Ingress:  Driver → Ethernet → IPv4/IPv6 → TCP/UDP → Application
Egress:   Application → TCP/UDP → IPv4/IPv6 → Ethernet → Driver
```

---

## Requirements

- Zig toolchain (0.11+)
- Linux (full support) or macOS/BSD (limited support)
- libev or libuv (for event loop examples)

---

## Features

### Completed Features

#### Protocol Stack
- IPv4 Protocol: Full IPv4 with fragment reassembly (30s timeout)
- IPv6 Protocol: Full IPv6 with extension header support
- TCP Protocol: RFC 793 compliant state machine
- UDP Protocol: Connectionless datagram transport
- ICMP/ICMPv6: Echo request/reply with rate limiting
- ARP Protocol: Address resolution with cache change detection
- DNS Resolver: Recursive DNS query support

#### TCP Extensions (RFC Compliant)
- Selective Acknowledgment (SACK, RFC 2018)
- Timestamps Option (RFC 7323)
- Window Scaling (RFC 7323)
- Nagle Algorithm (RFC 896) with TCP_NODELAY
- Fast Retransmit and Recovery (RFC 5681)

#### Congestion Control
- CUBIC (RFC 9438): Default algorithm with HyStart++
- BBR: Bottleneck Bandwidth and RTT-based control
- Pluggable Interface: Easy to add custom algorithms

#### Drivers
- TAP Device: Virtual network interface
- AF_PACKET: Raw socket access with TPACKET_V3 block-mode
- AF_XDP: XDP socket for kernel bypass
- Loopback: Local testing without hardware

#### Performance Features
- Zero-Copy Buffers: Cluster-based buffer pooling
- Sharded Transport Tables: Reduced lock contention for multi-queue NICs
- Event Multiplexing: libev and libuv integration
- Memory Pooling: Pre-warmed pools for latency-critical paths
- Statistics Collection: Per-layer latency tracking

### In Progress
- TSO/GRO: TCP segmentation and receive offloading
- Multi-path TCP: Connection over multiple interfaces
- QUIC: UDP-based transport protocol

### Planned Features
- Kernel Module: Alternative to userspace for production
- DPDK Driver: For 10G/25G/100G NICs
- eBPF Integration: Programmable packet processing

---

## Build Targets

| Target | Description |
|--------|-------------|
| `zig build` | Build static and shared libraries |
| `zig build test` | Run all tests |
| `zig build bench` | Build benchmark binaries (ReleaseFast) |
| `zig build docs` | Generate documentation |
| `zig build example` | Build all example binaries |

### Build Options

| Option | Description |
|--------|-------------|
| `-Doptimize=ReleaseFast` | Build with optimizations |
| `-Dlog_level=info` | Set log level (err, warn, info, debug, none) |

---

## Usage Examples

### Basic Stack Initialization

```zig
const std = @import("std");
const ustack = @import("ustack");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize stack
    var stack = try ustack.init(allocator);
    defer stack.deinit();

    // Create NIC with TAP driver
    const tap = try ustack.drivers.tap.Tap.init("tap0");
    try stack.createNIC(1, tap.endpoint());

    // Add IP address
    try stack.nics.get(1).?.addAddress(.{
        .protocol = ustack.tcpip.EtherType.IPv4,
        .address_with_prefix = .{
            .address = .{ .v4 = .{ 10, 0, 0, 1 } },
            .prefix = 24,
        },
    });

    // Run event loop
    stack.run();
}
```

### TCP Server Example

```zig
// Create TCP socket
var wq = ustack.waiter.Queue{};
var endpoint = try stack.transport_protocols.get(6).?.newEndpoint(
    &stack,
    ustack.tcpip.EtherType.IPv4,
    &wq,
);

// Bind and listen
try endpoint.bind(.{ .addr = .{ .v4 = .{ 0, 0, 0, 0 } }, .port = 8080 });
try endpoint.listen(128);

// Accept connections
const conn = try endpoint.accept();
```

### Running Examples

```sh
# Setup virtual network (requires root)
sudo ./setup_veth.sh

# Run ping-pong benchmark
sudo zig-out/bin/bench_ping_pong -i tap0 -a 10.0.0.1/24

# Run unified example with different drivers
sudo zig-out/bin/example_unified -d tap -i tap0 -a 10.0.0.1/24
sudo zig-out/bin/example_unified -d af_packet -i eth0 -a 10.0.0.1/24
```

---

## Project Structure

```
shardnet/
├── build.zig                 # Build configuration
├── README.md
├── setup_veth.sh             # Virtual network setup script
├── src/
│   ├── main.zig              # Entry point and CLI
│   ├── stack.zig             # Stack orchestration and routing
│   ├── tcpip.zig             # Core types and dispatch
│   ├── buffer.zig            # Zero-copy buffer management
│   ├── header.zig            # Protocol header definitions
│   ├── interface.zig         # Network interface abstraction
│   ├── waiter.zig            # Async wait queue
│   ├── time.zig              # Timer management
│   ├── dns.zig               # DNS resolver
│   ├── posix.zig             # POSIX socket compatibility
│   ├── stats.zig             # Statistics collection
│   ├── link/
│   │   └── eth.zig           # Ethernet framing
│   ├── network/
│   │   ├── ipv4.zig          # IPv4 protocol
│   │   ├── ipv6.zig          # IPv6 protocol
│   │   ├── icmp.zig          # ICMPv4
│   │   ├── icmpv6.zig        # ICMPv6
│   │   └── arp.zig           # ARP protocol
│   ├── transport/
│   │   ├── tcp.zig           # TCP protocol
│   │   ├── udp.zig           # UDP protocol
│   │   └── congestion/
│   │       ├── control.zig   # Congestion control interface
│   │       ├── cubic.zig     # CUBIC algorithm
│   │       └── bbr.zig       # BBR algorithm
│   └── drivers/
│       ├── loopback.zig      # Loopback driver
│       └── linux/
│           ├── tap.zig       # TAP driver
│           ├── af_packet.zig # AF_PACKET driver
│           └── af_xdp.zig    # AF_XDP driver
└── examples/
    ├── ping_pong.zig         # Latency benchmark
    ├── uperf.zig             # Throughput benchmark
    ├── main_unified.zig      # Multi-driver example
    └── ...
```

---

## Platform Support

| Platform | Support Level | Features |
|----------|--------------|----------|
| Linux | Full | All drivers, namespaces, cgroups |
| macOS | Limited | Loopback only |
| BSD | Limited | Loopback only |

---

## RFC Compliance

| RFC | Title | Status |
|-----|-------|--------|
| RFC 793 | TCP Specification | Implemented |
| RFC 896 | Nagle Algorithm | Implemented |
| RFC 2018 | TCP SACK | Implemented |
| RFC 5681 | TCP Congestion Control | Implemented |
| RFC 7323 | TCP Extensions (Timestamps, Window Scale) | Implemented |
| RFC 9406 | HyStart++ | Implemented |
| RFC 9438 | CUBIC | Implemented |
| RFC 791 | IPv4 | Implemented |
| RFC 8200 | IPv6 | Implemented |
| RFC 826 | ARP | Implemented |
| RFC 792 | ICMP | Implemented |
| RFC 4443 | ICMPv6 | Implemented |

---

## Performance

Benchmarks on Intel Xeon E5-2680 v4, Linux 5.15:

| Metric | Value |
|--------|-------|
| TCP Throughput | ~8 Gbps (single core) |
| UDP Throughput | ~10 Gbps (single core) |
| TCP Latency (ping-pong) | ~15 us |
| Connections/sec | ~100K |

---

## Future Improvements

- [x] IPv4 with fragment reassembly
- [x] IPv6 with extension headers
- [x] TCP with SACK, timestamps, window scaling
- [x] CUBIC and BBR congestion control
- [x] AF_PACKET with TPACKET_V3
- [x] AF_XDP kernel bypass
- [x] ARP cache change detection
- [x] ICMP rate limiting
- [ ] TSO/GRO offloading
- [ ] Multi-path TCP
- [ ] QUIC transport
- [ ] DPDK driver
- [ ] eBPF integration

---

## License

Apache License 2.0 - Copyright (c) 2024 Adel-Ayoub

See [LICENSE](LICENSE) for details.
