const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "80286" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    debugPrint(false);
    {
        testOp0(m32, .CLTS, "0F 06");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
        testOp1(m32, .LLDT, op1, "0F 00 10");
        testOp1(m32, .LMSW, op1, "0F 01 30");
        testOp1(m32, .LTR,  op1, "0F 00 18");
        testOp1(m32, .SLDT, op1, "0F 00 00");
        testOp1(m32, .SMSW, op1, "0F 01 20");
        testOp1(m32, .STR,  op1, "0F 00 08");
        testOp1(m32, .VERR, op1, "0F 00 20");
        testOp1(m32, .VERW, op1, "0F 00 28");
    }

    {
        const op1 = Operand.register(.AX);
        testOp1(m32, .LLDT, op1, "0F 00 D0");
        testOp1(m32, .LMSW, op1, "0F 01 F0");
        testOp1(m32, .LTR,  op1, "0F 00 D8");
        testOp1(m32, .SLDT, op1, "66 0F 00 C0");
        testOp1(m32, .SMSW, op1, "66 0F 01 E0");
        testOp1(m32, .STR,  op1, "66 0F 00 C8");
        testOp1(m32, .VERR, op1, "0F 00 E0");
        testOp1(m32, .VERW, op1, "0F 00 E8");
    }

    {
        const op1 = Operand.register(.EAX);
        testOp1(m32, .LLDT, op1, AsmError.InvalidOperand);
        testOp1(m32, .LMSW, op1, AsmError.InvalidOperand);
        testOp1(m32, .LTR,  op1, AsmError.InvalidOperand);
        testOp1(m32, .SLDT, op1, "0F 00 C0");
        testOp1(m32, .SMSW, op1, "0F 01 E0");
        testOp1(m32, .STR,  op1, "0F 00 C8");
        testOp1(m32, .VERR, op1, AsmError.InvalidOperand);
        testOp1(m32, .VERW, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.register(.RAX);
        testOp1(m64, .LLDT, op1, AsmError.InvalidOperand);
        testOp1(m64, .LMSW, op1, AsmError.InvalidOperand);
        testOp1(m64, .LTR,  op1, AsmError.InvalidOperand);
        testOp1(m64, .SLDT, op1, "48 0F 00 C0");
        testOp1(m64, .SMSW, op1, "48 0F 01 E0");
        testOp1(m64, .STR,  op1, "48 0F 00 C8");
        testOp1(m64, .VERR, op1, AsmError.InvalidOperand);
        testOp1(m64, .VERW, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .Void, .EAX, 0);
        testOp1(m32, .LGDT, op1, "0F 01 10");
        testOp1(m32, .LIDT, op1, "0F 01 18");
        testOp1(m32, .SGDT, op1, "0F 01 00");
        testOp1(m32, .SIDT, op1, "0F 01 08");
        testOp1(m64, .LGDT, op1, "67 0F 01 10");
        testOp1(m64, .LIDT, op1, "67 0F 01 18");
        testOp1(m64, .SGDT, op1, "67 0F 01 00");
        testOp1(m64, .SIDT, op1, "67 0F 01 08");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
        const op2 = Operand.register(.AX);
        testOp2(m32, .ARPL, op1, op2, "63 00");
        testOp2(m64, .ARPL, op1, op2, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.register(.AX);
        const op2 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
        testOp2(m32, .LAR,  op1, op2, "66 0F 02 00");
        testOp2(m32, .LSL,  op1, op2, "66 0F 03 00");
        testOp2(m64, .LAR,  op1, op2, "66 67 0F 02 00");
        testOp2(m64, .LSL,  op1, op2, "66 67 0F 03 00");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
        testOp2(m32, .LAR,  op1, op2, "0F 02 00");
        testOp2(m32, .LSL,  op1, op2, "0F 03 00");
        testOp2(m64, .LAR,  op1, op2, "67 0F 02 00");
        testOp2(m64, .LSL,  op1, op2, "67 0F 03 00");
    }

}
