pub usingnamespace(@import("x86/machine.zig"));

test "main test" {
    const x86 = @import("x86/machine.zig");
    const machine = x86.Machine.init(.x64);

    // include all the tests so zig actually compiles them
    // TODO: add more negative tests
    _ = @import("x86/tests/call.zig");
    _ = @import("x86/tests/cmp.zig");
    _ = @import("x86/tests/mov.zig");
    _ = @import("x86/tests/nop.zig");
    _ = @import("x86/tests/jmp.zig");
    _ = @import("x86/tests/xchg.zig");
    _ = @import("x86/tests/pop.zig");
    _ = @import("x86/tests/push.zig");
}
