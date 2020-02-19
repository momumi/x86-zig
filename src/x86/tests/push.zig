const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/push

test "push" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        const op1 = Operand.register(.CS);
        testOp1(m32, .PUSH, op1, "0E");
        testOp1(m64, .PUSH, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.register(.SS);
        testOp1(m32, .PUSH, op1, "16");
        testOp1(m64, .PUSH, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.register(.DS);
        testOp1(m32, .PUSH, op1, "1E");
        testOp1(m64, .PUSH, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.register(.ES);
        testOp1(m32, .PUSH, op1, "06");
        testOp1(m64, .PUSH, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.register(.FS);
        testOp1(m32, .PUSH, op1, "0F A0");
        testOp1(m64, .PUSH, op1, "0F A0");
        testOp1(m32, .PUSHW, op1, "66 0F A0");
        testOp1(m64, .PUSHW, op1, "66 0F A0");
        testOp1(m32, .PUSHD, op1, "0F A0");
        testOp1(m64, .PUSHD, op1, AsmError.InvalidOperand);
        testOp1(m32, .PUSHQ, op1, AsmError.InvalidOperand);
        testOp1(m64, .PUSHQ, op1, "0F A0");
    }

    {
        const op1 = Operand.register(.GS);
        testOp1(m32, .PUSH, op1, "0F A8");
        testOp1(m64, .PUSH, op1, "0F A8");
        testOp1(m32, .PUSHW, op1, "66 0F A8");
        testOp1(m64, .PUSHW, op1, "66 0F A8");
        testOp1(m32, .PUSHD, op1, "0F A8");
        testOp1(m64, .PUSHD, op1, AsmError.InvalidOperand);
        testOp1(m32, .PUSHQ, op1, AsmError.InvalidOperand);
        testOp1(m64, .PUSHQ, op1, "0F A8");
    }

    {
        const op1 = Operand.register(.AX);
        testOp1(m32, .PUSH, op1, "66 50");
        testOp1(m64, .PUSH, op1, "66 50");
    }

    {
        const op1 = Operand.register(.EAX);
        testOp1(m32, .PUSH, op1, "50");
        testOp1(m64, .PUSH, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.register(.RAX);
        testOp1(m32, .PUSH, op1, AsmError.InvalidOperand);
        testOp1(m64, .PUSH, op1, "50");
    }

    {
        const op1 = Operand.register(.R15);
        testOp1(m32, .PUSH, op1, AsmError.InvalidOperand);
        testOp1(m64, .PUSH, op1, "41 57");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0x11);
        testOp1(m32, .PUSH, op1, "66 FF 70 11");
        testOp1(m64, .PUSH, op1, "66 67 FF 70 11");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0x11);
        testOp1(m32, .PUSH, op1, "FF 70 11");
        testOp1(m64, .PUSH, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0x11);
        testOp1(m32, .PUSH, op1, AsmError.InvalidOperand);
        testOp1(m64, .PUSH, op1, "67 FF 70 11");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .WORD, .RAX, 0x11);
        testOp1(m32, .PUSH, op1, AsmError.InvalidOperand);
        testOp1(m64, .PUSH, op1, "66 FF 70 11");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .DWORD, .RAX, 0x11);
        testOp1(m32, .PUSH, op1, AsmError.InvalidOperand);
        testOp1(m64, .PUSH, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .QWORD, .R15, 0x11);
        testOp1(m32, .PUSH, op1, AsmError.InvalidOperand);
        testOp1(m64, .PUSH, op1, "41 FF 77 11");
    }

    {
        const op1 = Operand.immediate(0x00);
        testOp1(m32, .PUSH, op1, "6A 00");
        testOp1(m64, .PUSH, op1, "6A 00");
    }

    {
        const op1 = Operand.immediate(0x1100);
        testOp1(m32, .PUSH, op1, "66 68 00 11");
        testOp1(m64, .PUSH, op1, "66 68 00 11");
    }

    {
        const op1 = Operand.immediate(0x33221100);
        testOp1(m32, .PUSH, op1, "68 00 11 22 33");
        testOp1(m64, .PUSH, op1, "68 00 11 22 33");
    }

}
