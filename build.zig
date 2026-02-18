const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // -- Log level option ---------------------------------------------------
    const LogLevel = enum {
        err,
        warn,
        info,
        debug,
        none,
    };
    const log_level = b.option(LogLevel, "log_level", "Log level for shardnet (default: debug)") orelse .debug;

    const options = b.addOptions();
    options.addOption(LogLevel, "log_level", log_level);
    const options_mod = options.createModule();

    // -- Static library -----------------------------------------------------
    const lib = b.addStaticLibrary(.{
        .name = "shardnet",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.root_module.addImport("build_options", options_mod);
    b.installArtifact(lib);

    // -- Shared library -----------------------------------------------------
    const dylib = b.addSharedLibrary(.{
        .name = "shardnet",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    dylib.root_module.addImport("build_options", options_mod);
    b.installArtifact(dylib);

    // -- Importable module --------------------------------------------------
    const shardnet_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
    });
    shardnet_mod.addImport("build_options", options_mod);

    // -- Test step -----------------------------------------------------------
    // Discovers and runs all *_test.zig files under src/ in addition to
    // the main entry-point tests.
    const test_step = b.step("test", "Run all library and *_test.zig tests");

    const main_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    main_tests.root_module.addImport("build_options", options_mod);
    const run_main_tests = b.addRunArtifact(main_tests);
    test_step.dependOn(&run_main_tests.step);

    // Discover *_test.zig files under src/ and compile each as a standalone
    // test artifact so zig build test exercises every test in the tree.
    const test_files = [_][]const u8{
        "src/transport/tcp_test.zig",
        "src/transport/tcp_2msl_test.zig",
        "src/drivers/linux/test_af_xdp.zig",
    };

    for (test_files) |path| {
        const t = b.addTest(.{
            .root_source_file = b.path(path),
            .target = target,
            .optimize = optimize,
        });
        t.root_module.addImport("build_options", options_mod);
        t.root_module.addImport("shardnet", shardnet_mod);
        const run_t = b.addRunArtifact(t);
        test_step.dependOn(&run_t.step);
    }

    // -- Bench step ----------------------------------------------------------
    // Builds examples/uperf.zig and examples/ping_pong.zig with ReleaseFast
    // so benchmarks always run with optimizations regardless of the global
    // -Doptimize flag.
    const bench_step = b.step("bench", "Build benchmark binaries (ReleaseFast)");

    const bench_sources = [_]struct { name: []const u8, path: []const u8 }{
        .{ .name = "bench_uperf", .path = "examples/uperf.zig" },
        .{ .name = "bench_ping_pong", .path = "examples/ping_pong.zig" },
    };

    for (bench_sources) |src| {
        const exe = b.addExecutable(.{
            .name = src.name,
            .root_source_file = b.path(src.path),
            .target = target,
            .optimize = .ReleaseFast,
        });
        exe.root_module.addImport("shardnet", shardnet_mod);
        exe.linkLibC();
        exe.linkSystemLibrary("ev");
        exe.addCSourceFile(.{
            .file = b.path("examples/wrapper.c"),
            .flags = &.{ "-I/usr/include", "-I/usr/local/include" },
        });
        const install = b.addInstallArtifact(exe, .{});
        bench_step.dependOn(&install.step);
    }

    // -- Docs step -----------------------------------------------------------
    // Generates HTML documentation for the library using Zig's built-in
    // doc emission. Output lands in zig-out/docs/.
    const docs_step = b.step("docs", "Generate library documentation");

    const docs_lib = b.addStaticLibrary(.{
        .name = "shardnet",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    docs_lib.root_module.addImport("build_options", options_mod);

    const install_docs = b.addInstallDirectory(.{
        .source = docs_lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    docs_step.dependOn(&install_docs.step);

    // -- Example step --------------------------------------------------------
    const example_step = b.step("example", "Build all example binaries");

    const examples = [_]struct { name: []const u8, path: []const u8, lib: []const u8 }{
        .{ .name = "example_ping_pong", .path = "examples/ping_pong.zig", .lib = "ev" },
        .{ .name = "example_tap_libev", .path = "examples/main_tap_libev.zig", .lib = "ev" },
        .{ .name = "example_tap_libev_mux", .path = "examples/main_tap_libev_mux.zig", .lib = "ev" },
        .{ .name = "example_af_packet_libev", .path = "examples/main_af_packet_libev.zig", .lib = "ev" },
        .{ .name = "example_af_packet_libev_mux", .path = "examples/main_af_packet_libev_mux.zig", .lib = "ev" },
        .{ .name = "example_af_xdp_libev", .path = "examples/main_af_xdp_libev.zig", .lib = "ev" },
        .{ .name = "example_unified", .path = "examples/main_unified.zig", .lib = "ev" },
        .{ .name = "example_uperf_libev", .path = "examples/uperf.zig", .lib = "ev" },
    };

    for (examples) |ex| {
        const exe = b.addExecutable(.{
            .name = ex.name,
            .root_source_file = b.path(ex.path),
            .target = target,
            .optimize = optimize,
        });
        exe.root_module.addImport("shardnet", shardnet_mod);
        exe.linkLibC();
        exe.linkSystemLibrary(ex.lib);
        exe.addCSourceFile(.{
            .file = b.path("examples/wrapper.c"),
            .flags = &.{ "-I/usr/include", "-I/usr/local/include" },
        });
        const install = b.addInstallArtifact(exe, .{});
        example_step.dependOn(&install.step);
    }
}
