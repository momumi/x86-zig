const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/jmp

test "jmp" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        const op1 = Operand.immediate16(0x1100);
        testOp1(m32, .JMP, op1, "66 E9 00 11");
        testOp1(m64, .JMP, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.immediate(0x80);
        testOp1(m32, .JMP, op1, "66 E9 80 00");
        testOp1(m64, .JMP, op1, "E9 80 00 00 00");
    }

    {
        const op1 = Operand.immediate8(0x80);
        testOp1(m32, .JMP, op1, AsmError.InvalidOperand);
        testOp1(m64, .JMP, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.immediateSigned8(@bitCast(i8, @as(u8, 0x80)));
        testOp1(m32, .JMP, op1, "EB 80");
        testOp1(m64, .JMP, op1, "EB 80");
    }

    {
        const op1 = Operand.immediateSigned(0x80);
        testOp1(m32, .JMP, op1, "66 E9 80 00");
        testOp1(m64, .JMP, op1, "E9 80 00 00 00");
    }

    {
        const op1 = Operand.immediateSigned(-128);
        testOp1(m32, .JMP, op1, "EB 80");
        testOp1(m64, .JMP, op1, "EB 80");
    }

    {
        const op1 = Operand.immediate(0x7F);
        testOp1(m32, .JMP, op1, "EB 7F");
        testOp1(m64, .JMP, op1, "EB 7F");
    }

    {
        const op1 = Operand.immediate8(0x00);
        testOp1(m64, .JMP, op1, "EB 00");
    }

    {
        const op1 = Operand.immediate32(0x33221100);
        testOp1(m64, .JMP, op1, "E9 00 11 22 33");
    }

    {
        const op1 = Operand.registerRm(.AX);
        testOp1(m32, .JMP, op1, "66 ff e0");
        testOp1(m64, .JMP, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.registerRm(.EAX);
        testOp1(m32, .JMP, op1, "ff e0");
        testOp1(m64, .JMP, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.registerRm(.RAX);
        testOp1(m32, .JMP, op1, AsmError.InvalidOperand);
        testOp1(m64, .JMP, op1, "ff e0");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .FAR_WORD, 1, .EAX, .EAX, 0x00);
        testOp1(m32, .JMP, op1, "66 FF 2C 00");
        testOp1(m64, .JMP, op1, "66 67 FF 2C 00");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .FAR_DWORD, 1, .EAX, .EAX, 0x00);
        testOp1(m32, .JMP, op1, "FF 2C 00");
        testOp1(m64, .JMP, op1, "67 FF 2C 00");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .FAR_QWORD, 1, .EAX, .EAX, 0x00);
        testOp1(m32, .JMP, op1, AsmError.InvalidOperand);
        testOp1(m64, .JMP, op1, "67 48 FF 2C 00");
    }

    {
        const op1 = Operand.far16(0x1100, 0x3322);
        testOp1(m32, .JMP, op1, "66 EA 22 33 00 11");
        testOp1(m64, .JMP, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.far32(0x1100, 0x55443322);
        testOp1(m32, .JMP, op1, "EA 22 33 44 55 00 11");
        testOp1(m64, .JMP, op1, AsmError.InvalidOperand);
    }
}
