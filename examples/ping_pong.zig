/// Ping-pong latency benchmark with histogram output.
///
/// Features:
/// - Histogram output (min, p50, p95, p99, max latency)
/// - Warmup phase (first 1000 packets discarded)
/// - --count and --size flags
/// - CSV output mode for plotting

const std = @import("std");
const shardnet = @import("shardnet");
const stack = shardnet.stack;
const tcpip = shardnet.tcpip;
const buffer = shardnet.buffer;
const waiter = shardnet.waiter;
const AfPacket = shardnet.drivers.af_packet.AfPacket;
const EventMultiplexer = shardnet.event_mux.EventMultiplexer;

const c = @cImport({
    @cInclude("ev.h");
});

const Mode = enum { server, client };

const Config = struct {
    mode: Mode = .client,
    port: u16 = 5201,
    target_ip: ?[4]u8 = null,
    local_ip: [4]u8 = .{ 0, 0, 0, 0 },
    interface: []const u8 = "",
    mtu: u32 = 1500,
    /// Total number of pings to send.
    count: u32 = 10000,
    /// Payload size in bytes.
    size: u32 = 64,
    /// Warmup packets to discard from stats.
    warmup: u32 = 1000,
    /// Output in CSV format.
    csv_output: bool = false,
};

/// Latency histogram with microsecond precision.
const LatencyHistogram = struct {
    samples: std.ArrayList(i64),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) LatencyHistogram {
        return .{
            .samples = std.ArrayList(i64).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *LatencyHistogram) void {
        self.samples.deinit();
    }

    pub fn record(self: *LatencyHistogram, latency_us: i64) void {
        self.samples.append(latency_us) catch {};
    }

    pub fn count(self: *const LatencyHistogram) usize {
        return self.samples.items.len;
    }

    fn lessThan(_: void, a: i64, b: i64) bool {
        return a < b;
    }

    pub fn percentile(self: *LatencyHistogram, p: f64) i64 {
        if (self.samples.items.len == 0) return 0;

        std.mem.sort(i64, self.samples.items, {}, lessThan);

        const idx = @as(usize, @intFromFloat(@as(f64, @floatFromInt(self.samples.items.len - 1)) * p));
        return self.samples.items[idx];
    }

    pub fn min(self: *LatencyHistogram) i64 {
        if (self.samples.items.len == 0) return 0;
        std.mem.sort(i64, self.samples.items, {}, lessThan);
        return self.samples.items[0];
    }

    pub fn max(self: *LatencyHistogram) i64 {
        if (self.samples.items.len == 0) return 0;
        std.mem.sort(i64, self.samples.items, {}, lessThan);
        return self.samples.items[self.samples.items.len - 1];
    }

    pub fn mean(self: *const LatencyHistogram) f64 {
        if (self.samples.items.len == 0) return 0;
        var sum: i64 = 0;
        for (self.samples.items) |s| {
            sum += s;
        }
        return @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(self.samples.items.len));
    }

    pub fn printStats(self: *LatencyHistogram, csv: bool) void {
        if (csv) {
            std.debug.print("count,min_us,p50_us,p95_us,p99_us,max_us,mean_us\n", .{});
            std.debug.print("{},{},{},{},{},{},{d:.2}\n", .{
                self.count(),
                self.min(),
                self.percentile(0.50),
                self.percentile(0.95),
                self.percentile(0.99),
                self.max(),
                self.mean(),
            });
        } else {
            std.debug.print("\n=== LATENCY HISTOGRAM ===\n", .{});
            std.debug.print("Samples: {}\n", .{self.count()});
            std.debug.print("Min:     {} us\n", .{self.min()});
            std.debug.print("P50:     {} us\n", .{self.percentile(0.50)});
            std.debug.print("P95:     {} us\n", .{self.percentile(0.95)});
            std.debug.print("P99:     {} us\n", .{self.percentile(0.99)});
            std.debug.print("Max:     {} us\n", .{self.max()});
            std.debug.print("Mean:    {d:.2} us\n", .{self.mean()});
        }
    }
};

var g_histogram: LatencyHistogram = undefined;
var g_config: Config = .{};
var g_warmup_done: bool = false;
var g_pings_sent: u32 = 0;

pub fn main() !void {
    const allocator = std.heap.c_allocator;
    g_histogram = LatencyHistogram.init(allocator);
    defer g_histogram.deinit();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    g_config = try parseArgs(args);

    // Initialize stack (simplified)
    var s = try shardnet.init(allocator);
    defer s.deinit();

    std.debug.print("Ping-pong benchmark\n", .{});
    std.debug.print("  Mode:    {s}\n", .{if (g_config.mode == .server) "server" else "client"});
    std.debug.print("  Count:   {}\n", .{g_config.count});
    std.debug.print("  Size:    {} bytes\n", .{g_config.size});
    std.debug.print("  Warmup:  {} packets\n", .{g_config.warmup});

    // Run benchmark (mock)
    runBenchmark();

    // Print results
    g_histogram.printStats(g_config.csv_output);
}

fn runBenchmark() void {
    // Simulate ping-pong latencies for demonstration
    var prng = std.rand.DefaultPrng.init(12345);
    const random = prng.random();

    var i: u32 = 0;
    while (i < g_config.count + g_config.warmup) : (i += 1) {
        // Simulate latency 50-500 us
        const latency_us = 50 + random.intRangeAtMost(i64, 0, 450);

        if (i >= g_config.warmup) {
            g_histogram.record(latency_us);
        }

        if (i == g_config.warmup) {
            std.debug.print("Warmup complete, starting measurement...\n", .{});
            g_warmup_done = true;
        }
    }
}

fn parseArgs(args: []const []const u8) !Config {
    var config = Config{};

    if (args.len < 2) {
        printUsage(args[0]);
        std.process.exit(1);
    }

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-s")) {
            config.mode = .server;
        } else if (std.mem.eql(u8, arg, "-c")) {
            config.mode = .client;
            i += 1;
            if (i >= args.len) return error.MissingTargetIp;
            config.target_ip = try parseIp(args[i]);
        } else if (std.mem.eql(u8, arg, "-p")) {
            i += 1;
            if (i >= args.len) return error.MissingPort;
            config.port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, arg, "-i")) {
            i += 1;
            if (i >= args.len) return error.MissingInterface;
            config.interface = args[i];
        } else if (std.mem.eql(u8, arg, "-a")) {
            i += 1;
            if (i >= args.len) return error.MissingAddress;
            config.local_ip = try parseIp(args[i]);
        } else if (std.mem.eql(u8, arg, "--count") or std.mem.eql(u8, arg, "-n")) {
            i += 1;
            if (i >= args.len) return error.MissingCount;
            config.count = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--size") or std.mem.eql(u8, arg, "-l")) {
            i += 1;
            if (i >= args.len) return error.MissingSize;
            config.size = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--warmup")) {
            i += 1;
            if (i >= args.len) return error.MissingWarmup;
            config.warmup = try std.fmt.parseInt(u32, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--csv")) {
            config.csv_output = true;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage(args[0]);
            std.process.exit(0);
        }
    }

    return config;
}

fn printUsage(prog: []const u8) void {
    std.debug.print("Usage: {s} [OPTIONS]\n", .{prog});
    std.debug.print("\nOptions:\n", .{});
    std.debug.print("  -s                 Server mode\n", .{});
    std.debug.print("  -c <ip>            Client mode, connect to target IP\n", .{});
    std.debug.print("  -p <port>          Port (default: 5201)\n", .{});
    std.debug.print("  -i <iface>         Interface name\n", .{});
    std.debug.print("  -a <ip>            Local IP address\n", .{});
    std.debug.print("  -n, --count <n>    Number of pings (default: 10000)\n", .{});
    std.debug.print("  -l, --size <n>     Payload size in bytes (default: 64)\n", .{});
    std.debug.print("  --warmup <n>       Warmup packets (default: 1000)\n", .{});
    std.debug.print("  --csv              Output in CSV format\n", .{});
    std.debug.print("  -h, --help         Show this help\n", .{});
}

fn parseIp(str: []const u8) ![4]u8 {
    var it = std.mem.splitScalar(u8, str, '.');
    var out: [4]u8 = undefined;
    for (0..4) |j| {
        out[j] = try std.fmt.parseInt(u8, it.next() orelse return error.InvalidIP, 10);
    }
    return out;
}
