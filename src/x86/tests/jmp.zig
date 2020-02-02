const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/jmp

test "jmp x64" {
    const x64 = Machine.init(.x64);

    debugPrint(false);

    {
        const op1 = Operand.immediate8(0x00);
        testOp1(x64, .JMP, op1, "EB 00");
    }

    {
        const op1 = Operand.immediate16(0x1100);
        testOp1Error(x64, .JMP, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.immediate32(0x33221100);
        testOp1(x64, .JMP, op1, "E9 00 11 22 33");
    }

    {
        const op1 = Operand.registerRm(.RAX);
        testOp1(x64, .JMP, op1, "ff e0");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .FAR_WORD, 1, .RAX, .RAX, 0x00);
        testOp1(x64, .JMP, op1, "66 FF 2C 00");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .FAR_DWORD, 1, .RAX, .RAX, 0x00);
        testOp1(x64, .JMP, op1, "FF 2C 00");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .FAR_QWORD, 1, .RAX, .RAX, 0x00);
        testOp1(x64, .JMP, op1, "48 FF 2C 00");
    }
}

test "jmp x86" {
    const x86 = Machine.init(.x86);

    debugPrint(false);

    {
        const op1 = Operand.far16(0x1100, 0x3322);
        testOp1(x86, .JMP, op1, "66 EA 22 33 00 11");
    }

    {
        const op1 = Operand.far32(0x1100, 0x55443322);
        testOp1(x86, .JMP, op1, "EA 22 33 44 55 00 11");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .FAR_WORD, 1, .EAX, .EAX, 0x00);
        testOp1(x86, .JMP, op1, "66 FF 2C 00");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .FAR_DWORD, 1, .EAX, .EAX, 0x00);
        testOp1(x86, .JMP, op1, "FF 2C 00");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .FAR_QWORD, 1, .EAX, .EAX, 0x00);
        testOp1Error(x86, .JMP, op1, AsmError.InvalidOperand);
    }
}
