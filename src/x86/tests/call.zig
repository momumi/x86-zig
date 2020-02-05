const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/call

test "call" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        const op1 = Operand.immediateSigned16(-1);
        testOp1(m32, .CALL, op1, "66 E8 ff ff");
        testOp1(m64, .CALL, op1, AsmError.InvalidOperandCombination);
    }

    {
        // Since the immediate is signed extended, need to use a different
        // encoding for this value
        const op1 = Operand.immediateSigned32(-1);
        testOp1(m32, .CALL, op1, "E8 ff ff ff ff");
        testOp1(m64, .CALL, op1, "E8 ff ff ff ff");
    }

    {
        const op1 = Operand.registerRm(.AX);
        testOp1(m32, .CALL, op1, "66 ff d0");
        testOp1(m64, .CALL, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.registerRm(.EAX);
        testOp1(m32, .CALL, op1, "ff d0");
        testOp1(m64, .CALL, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.registerRm(.RAX);
        testOp1(m32, .CALL, op1, AsmError.InvalidOperand);
        testOp1(m64, .CALL, op1, "ff d0");
    }

    {
        const op1 = Operand.far16(0x1100, 0x3322);
        testOp1(m32, .CALL, op1, "66 9A 22 33 00 11");
        testOp1(m64, .CALL, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.far32(0x1100, 0x55443322);
        testOp1(m32, .CALL, op1, "9A 22 33 44 55 00 11");
        testOp1(m64, .CALL, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .FAR_WORD, 1, .EAX, .EAX, 0x00);
        testOp1(m32, .CALL, op1, "66 FF 1C 00");
        testOp1(m64, .CALL, op1, "66 67 FF 1C 00");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .FAR_DWORD, 1, .EAX, .EAX, 0x00);
        testOp1(m32, .CALL, op1, "FF 1C 00");
        testOp1(m64, .CALL, op1, "67 FF 1C 00");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .FAR_QWORD, 1, .EAX, .EAX, 0x00);
        testOp1(m32, .CALL, op1, AsmError.InvalidOperand);
        testOp1(m64, .CALL, op1, "67 48 FF 1C 00");
    }

}
