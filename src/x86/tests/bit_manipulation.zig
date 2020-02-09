const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "bit manipulation" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
        const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
        const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
        const reg16 = Operand.register(.AX);
        const reg32 = Operand.register(.EAX);
        const reg64 = Operand.register(.RAX);

        // LZCNT
        testOp2(m32, .LZCNT,  reg16, rm16, "66 F3 0F BD 00");
        testOp2(m32, .LZCNT,  reg32, rm32, "F3 0F BD 00");
        testOp2(m32, .LZCNT,  reg64, rm64, AsmError.InvalidOperand);
        // POPCNT
        testOp2(m32, .POPCNT, reg16, rm16, "66 F3 0F B8 00");
        testOp2(m32, .POPCNT, reg32, rm32, "F3 0F B8 00");
        testOp2(m32, .POPCNT, reg64, rm64, AsmError.InvalidOperand);
        // TZCNT
        testOp2(m32, .TZCNT,  reg16, rm16, "66 F3 0F BC 00");
        testOp2(m32, .TZCNT,  reg32, rm32, "F3 0F BC 00");
        testOp2(m32, .TZCNT,  reg64, rm64, AsmError.InvalidOperand);

        // LZCNT
        testOp2(m64, .LZCNT,  reg16, rm16, "66 67 F3 0F BD 00");
        testOp2(m64, .LZCNT,  reg32, rm32, "67 F3 0F BD 00");
        testOp2(m64, .LZCNT,  reg64, rm64, "67 F3 48 0F BD 00");
        // POPCNT
        testOp2(m64, .POPCNT, reg16, rm16, "66 67 F3 0F B8 00");
        testOp2(m64, .POPCNT, reg32, rm32, "67 F3 0F B8 00");
        testOp2(m64, .POPCNT, reg64, rm64, "67 F3 48 0F B8 00");
        // TZCNT
        testOp2(m64, .TZCNT,  reg16, rm16, "66 67 F3 0F BC 00");
        testOp2(m64, .TZCNT,  reg32, rm32, "67 F3 0F BC 00");
        testOp2(m64, .TZCNT,  reg64, rm64, "67 F3 48 0F BC 00");
    }

}
