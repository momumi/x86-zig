const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/pop

test "pop" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        const op1 = Operand.register(.R15);
        testOp1(m32, .POP, op1, AsmError.InvalidOperand);
        testOp1(m64, .POP, op1, "41 5F");
    }

    {
        const op1 = Operand.register(.FS);
        testOp1(m32, .POP, op1, "0F A1");
        testOp1(m64, .POP, op1, "0F A1");
    }

    {
        const op1 = Operand.register(.FS);
        testOp1(m32, .POPW, op1, "66 0F A1");
        testOp1(m64, .POPW, op1, "66 0F A1");
    }

    {
        const op1 = Operand.register(.FS);
        testOp1(m32, .POPD, op1, "0F A1");
        testOp1(m64, .POPD, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.register(.FS);
        testOp1(m32, .POPQ, op1, AsmError.InvalidOperand);
        testOp1(m64, .POPQ, op1, "0F A1");
    }

    {
        const op1 = Operand.register(.DS);
        testOp1(m32, .POP, op1, "1F");
        testOp1(m64, .POP, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.register(.AX);
        testOp1(m32, .POP, op1, "66 58");
        testOp1(m64, .POP, op1, "66 58");
    }

    {
        const op1 = Operand.register(.EAX);
        testOp1(m32, .POP, op1, "58");
        testOp1(m64, .POP, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.register(.RAX);
        testOp1(m32, .POP, op1, AsmError.InvalidOperand);
        testOp1(m64, .POP, op1, "58");
    }

    {
        const op1 = Operand.registerRm(.RAX);
        testOp1(m32, .POP, op1, AsmError.InvalidOperand);
        testOp1(m64, .POP, op1, "8F c0");
    }

    {
        const op1 = Operand.registerRm(.R8);
        testOp1(m32, .POP, op1, AsmError.InvalidOperand);
        testOp1(m64, .POP, op1, "41 8F c0");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .WORD, 1, .EAX, .EAX, 0);
        testOp1(m32, .POP, op1, "66 8F 04 00");
        testOp1(m64, .POP, op1, "66 67 8F 04 00");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .DWORD, 1, .EAX, .EAX, 0);
        testOp1(m32, .POP, op1, "8F 04 00");
        testOp1(m64, .POP, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .QWORD, 1, .RAX, .RAX, 0);
        testOp1(m32, .POP, op1, AsmError.InvalidOperand);
        testOp1(m64, .POP, op1, "8F 04 00");
    }

}
