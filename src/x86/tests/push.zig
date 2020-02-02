const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/push

test "push x86" {
    const x86 = Machine.init(.x86);

    debugPrint(false);

    {
        const op1 = Operand.registerSpecial(.CS);
        testOp1(x86, .PUSH, op1, "0E");
    }

    {
        const op1 = Operand.registerSpecial(.SS);
        testOp1(x86, .PUSH, op1, "16");
    }

    {
        const op1 = Operand.registerSpecial(.DS);
        testOp1(x86, .PUSH, op1, "1E");
    }

    {
        const op1 = Operand.registerSpecial(.ES);
        testOp1(x86, .PUSH, op1, "06");
    }

    {
        const op1 = Operand.register(.AX);
        testOp1(x86, .PUSH, op1, "66 50");
    }

    {
        const op1 = Operand.register(.EAX);
        testOp1(x86, .PUSH, op1, "50");
    }

    {
        const op1 = Operand.register(.RAX);
        testOp1Error(x86, .PUSH, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0x11);
        testOp1(x86, .PUSH, op1, "66 FF 70 11");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0x11);
        testOp1(x86, .PUSH, op1, "FF 70 11");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0x11);
        testOp1Error(x86, .PUSH, op1, AsmError.InvalidOperand);
    }
}

test "push x64" {
    const x64 = Machine.init(.x64);

    debugPrint(false);

    {
        const op1 = Operand.registerSpecial(.ES);
        testOp1Error(x64, .PUSH, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.registerSpecial(.FS);
        testOp1(x64, .PUSH, op1, "0F A0");
    }

    {
        const op1 = Operand.registerSpecial(.GS);
        testOp1(x64, .PUSH, op1, "0F A8");
    }

    {
        const op1 = Operand.immediate(0x00);
        testOp1(x64, .PUSH, op1, "6A 00");
    }

    {
        const op1 = Operand.immediate(0x1100);
        testOp1(x64, .PUSH, op1, "66 68 00 11");
    }

    {
        const op1 = Operand.immediate(0x33221100);
        testOp1(x64, .PUSH, op1, "68 00 11 22 33");
    }

    {
        const op1 = Operand.register(.AX);
        testOp1(x64, .PUSH, op1, "66 50");
    }

    {
        const op1 = Operand.register(.EAX);
        testOp1Error(x64, .PUSH, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.register(.RAX);
        testOp1(x64, .PUSH, op1, "50");
    }

    {
        const op1 = Operand.register(.R15);
        testOp1(x64, .PUSH, op1, "41 57");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .WORD, .RAX, 0x11);
        testOp1(x64, .PUSH, op1, "66 FF 70 11");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .DWORD, .RAX, 0x11);
        testOp1Error(x64, .PUSH, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .QWORD, .R15, 0x11);
        testOp1(x64, .PUSH, op1, "41 FF 77 11");
    }

}
