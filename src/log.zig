/// Structured logging module for the shardnet network stack.
///
/// Provides compile-time log level filtering, scoped loggers namespaced to
/// subsystems, and structured key-value pair support. Log messages that fall
/// below the configured level are eliminated entirely at comptime — zero
/// runtime overhead for suppressed levels.
///
/// Usage:
///   const log = @import("log.zig");
///   log.info("listening on {}", .{port});
///
///   // Scoped logger for a subsystem:
///   const dlog = log.scoped(.drivers);
///   dlog.info("interface {s} is up", .{iface_name});
const std = @import("std");
const build_options = @import("build_options");

/// Severity levels ordered from most to least critical.
/// The runtime filter suppresses all messages below the configured level.
pub const Level = enum(u8) {
    /// No output at all.
    none = 0,
    /// Unrecoverable errors requiring immediate attention.
    err = 1,
    /// Potentially harmful situations that may degrade behaviour.
    warn = 2,
    /// Normal operational messages (connection established, etc.).
    info = 3,
    /// Verbose output useful only during development or debugging.
    debug = 4,
};

/// The active log level, resolved at comptime from the build option.
pub const log_level: Level = switch (build_options.log_level) {
    .err => .err,
    .warn => .warn,
    .info => .info,
    .debug => .debug,
    .none => .none,
};

/// Runtime-adjustable level override. Starts at the comptime default.
/// Call `setLevel()` to narrow output without rebuilding. Note that
/// messages below the comptime level are still eliminated at compile
/// time and cannot be re-enabled at runtime.
var runtime_level: Level = log_level;

/// Set the runtime log level. Messages above the comptime ceiling are
/// always suppressed regardless of this setting.
pub fn setLevel(level: Level) void {
    runtime_level = level;
}

/// Return the currently active runtime log level.
pub fn getLevel() Level {
    return runtime_level;
}

// -- Top-level convenience functions ----------------------------------------

/// Log an error message (level = err).
pub fn err(comptime format: []const u8, args: anytype) void {
    log(.err, null, format, args);
}

/// Log a warning message (level = warn).
pub fn warn(comptime format: []const u8, args: anytype) void {
    log(.warn, null, format, args);
}

/// Log an informational message (level = info).
pub fn info(comptime format: []const u8, args: anytype) void {
    log(.info, null, format, args);
}

/// Log a debug message (level = debug).
pub fn debug(comptime format: []const u8, args: anytype) void {
    log(.debug, null, format, args);
}

// -- Scoped loggers ---------------------------------------------------------

/// Returns a namespaced logger whose output is prefixed with the scope
/// tag, e.g. `INFO(drivers): ...`. Use this to attribute log lines to
/// specific subsystems without polluting the global namespace.
///
/// Example:
///   const dlog = log.scoped(.drivers);
///   dlog.info("rx burst: {d} packets", .{count});
pub fn scoped(comptime scope: @Type(.EnumLiteral)) type {
    return struct {
        pub fn err(comptime format: []const u8, args: anytype) void {
            log(.err, @tagName(scope), format, args);
        }

        pub fn warn(comptime format: []const u8, args: anytype) void {
            log(.warn, @tagName(scope), format, args);
        }

        pub fn info(comptime format: []const u8, args: anytype) void {
            log(.info, @tagName(scope), format, args);
        }

        pub fn debug(comptime format: []const u8, args: anytype) void {
            log(.debug, @tagName(scope), format, args);
        }
    };
}

// -- Internal ---------------------------------------------------------------

/// Unified log function used by both top-level and scoped loggers.
/// Messages below the comptime level are discarded entirely. Messages
/// below the runtime level are suppressed with a cheap integer compare.
fn log(comptime level: Level, comptime scope: ?[]const u8, comptime format: []const u8, args: anytype) void {
    // Comptime gate — the entire call is eliminated when the build
    // level is lower than the requested level.
    if (comptime @intFromEnum(level) > @intFromEnum(log_level)) return;

    // Runtime gate — allows narrowing output after startup.
    if (@intFromEnum(level) > @intFromEnum(runtime_level)) return;

    const prefix = comptime levelPrefix(level);
    const scope_tag = comptime if (scope) |s| "(" ++ s ++ ")" else "";

    std.debug.print(prefix ++ scope_tag ++ ": " ++ format ++ "\n", args);
}

/// Map a Level to its human-readable prefix string at comptime.
fn levelPrefix(comptime level: Level) []const u8 {
    return switch (level) {
        .none => "NONE",
        .err => "ERR",
        .warn => "WARN",
        .info => "INFO",
        .debug => "DEBUG",
    };
}
