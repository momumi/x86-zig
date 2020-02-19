pub usingnamespace(@import("x86/machine.zig"));

test "main test" {
    // include all the tests so zig actually compiles them
    // TODO: add more negative tests

    _ = @import("x86/tests/call.zig");
    _ = @import("x86/tests/cmp.zig");
    _ = @import("x86/tests/mov.zig");
    _ = @import("x86/tests/nop.zig");
    _ = @import("x86/tests/jmp.zig");
    _ = @import("x86/tests/jcc.zig");
    _ = @import("x86/tests/xchg.zig");
    _ = @import("x86/tests/pop.zig");
    _ = @import("x86/tests/push.zig");
    _ = @import("x86/tests/rotate.zig");
    _ = @import("x86/tests/math_8086.zig");
    _ = @import("x86/tests/simple_8086.zig");
    _ = @import("x86/tests/float_x87.zig");
    _ = @import("x86/tests/extra.zig");
    _ = @import("x86/tests/80286.zig");
    _ = @import("x86/tests/80386.zig");
    _ = @import("x86/tests/80486.zig");
    _ = @import("x86/tests/pentium.zig");
    _ = @import("x86/tests/bit_manipulation.zig");
    _ = @import("x86/tests/mmx.zig");
    _ = @import("x86/tests/sse.zig");
    _ = @import("x86/tests/avx.zig");
    _ = @import("x86/tests/mask_register.zig");
    _ = @import("x86/tests/avx_512.zig");
    _ = @import("x86/tests/16bit_mode.zig");
}
