const std = @import("std");
const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();

    // Exe building
    {
        const exe = b.addExecutable("example", "example.zig");
        exe.setBuildMode(mode);
        exe.install();

        const run_cmd = exe.run();
        run_cmd.step.dependOn(b.getInstallStep());

        const run_step = b.step("run", "Run example.zig");
        run_step.dependOn(&run_cmd.step);
        const run_step2 = b.step("example", "Run example.zig");
        run_step2.dependOn(&run_cmd.step);
    }

    // hello example
    {
        const exe = b.addExecutable("example-hello", "example-hello.zig");
        exe.setBuildMode(mode);
        exe.linkSystemLibrary("c");
        exe.install();

        const run_cmd = exe.run();
        run_cmd.step.dependOn(b.getInstallStep());

        const run_step = b.step("example-hello", "Run the hello example");
        run_step.dependOn(&run_cmd.step);
    }

    // Library building
    {
        const lib = b.addStaticLibrary("x86-zig", "src/x86.zig");
        lib.setBuildMode(mode);
        lib.install();

        var main_tests = b.addTest("src/x86.zig");
        main_tests.setBuildMode(mode);

        const test_step = b.step("test", "Run library tests");
        test_step.dependOn(&main_tests.step);
    }
}
