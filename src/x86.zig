pub usingnamespace(@import("x86/machine.zig"));

test "main test" {
    const x86 = @import("x86/machine.zig");
    const machine = x86.Machine.init(.x64);

    // include all the tests so zig actually compiles them
    // TODO: add more negative tests
    const mov_test = @import("x86/tests/mov.zig");
    const nop_test = @import("x86/tests/nop.zig");
    const jmp_test = @import("x86/tests/jmp.zig");
    const xchg_test = @import("x86/tests/xchg.zig");
    const push_test = @import("x86/tests/push.zig");
}
