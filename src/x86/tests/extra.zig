const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "x87 floating point instructions" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        testOp0(m64, .CPUID,    "0F A2");
        testOp0(m64, .SYSCALL,  "0F 05");
        testOp0(m64, .SYSRET,   "0F 07");
        testOp0(m64, .SYSRETQ,  "48 0F 07");
        testOp0(m64, .UD2,      "0F 0B");
        testOp0(m64, .SYSENTER, "0F 34");
        testOp0(m64, .SYSEXIT,  "0F 35");
        testOp0(m64, .SYSEXITQ, "48 0F 35");
    }

    {
        const op1 = Operand.register(.AX);
        const op2 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
        testOp2(m64, .UD0, op1, op2, "66 67 0F FF 00");
        testOp2(m64, .UD1, op1, op2, "66 67 0F B9 00");
    }

    {
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
            testOp1(m32, .LLDT, op1, AsmError.InvalidOperandCombination);
            testOp1(m32, .LMSW, op1, AsmError.InvalidOperandCombination);
            testOp1(m32, .LTR,  op1, AsmError.InvalidOperandCombination);
            testOp1(m32, .SLDT, op1, "0F 00 C0");
            testOp1(m32, .SMSW, op1, "0F 01 E0");
            testOp1(m32, .STR,  op1, "0F 00 C8");
            testOp1(m32, .VERR, op1, AsmError.InvalidOperandCombination);
            testOp1(m32, .VERW, op1, AsmError.InvalidOperandCombination);
        }

        {
            const op1 = Operand.register(.RAX);
            testOp1(m64, .LLDT, op1, AsmError.InvalidOperandCombination);
            testOp1(m64, .LMSW, op1, AsmError.InvalidOperandCombination);
            testOp1(m64, .LTR,  op1, AsmError.InvalidOperandCombination);
            testOp1(m64, .SLDT, op1, "48 0F 00 C0");
            testOp1(m64, .SMSW, op1, "48 0F 01 E0");
            testOp1(m64, .STR,  op1, "48 0F 00 C8");
            testOp1(m64, .VERR, op1, AsmError.InvalidOperandCombination);
            testOp1(m64, .VERW, op1, AsmError.InvalidOperandCombination);
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
            testOp2(m64, .ARPL, op1, op2, AsmError.InvalidOperandCombination);
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

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .BYTE, .RAX, 0);
        testOp1(m64, .SETA,   op1, "0F 97 00");
        testOp1(m64, .SETAE,  op1, "0F 93 00");
        testOp1(m64, .SETB,   op1, "0F 92 00");
        testOp1(m64, .SETBE,  op1, "0F 96 00");
        testOp1(m64, .SETC,   op1, "0F 92 00");
        testOp1(m64, .SETE,   op1, "0F 94 00");
        testOp1(m64, .SETG,   op1, "0F 9F 00");
        testOp1(m64, .SETGE,  op1, "0F 9D 00");
        testOp1(m64, .SETL,   op1, "0F 9C 00");
        testOp1(m64, .SETLE,  op1, "0F 9E 00");
        testOp1(m64, .SETNA,  op1, "0F 96 00");
        testOp1(m64, .SETNAE, op1, "0F 92 00");
        testOp1(m64, .SETNB,  op1, "0F 93 00");
        testOp1(m64, .SETNBE, op1, "0F 97 00");
        testOp1(m64, .SETNC,  op1, "0F 93 00");
        testOp1(m64, .SETNE,  op1, "0F 95 00");
        testOp1(m64, .SETNG,  op1, "0F 9E 00");
        testOp1(m64, .SETNGE, op1, "0F 9C 00");
        testOp1(m64, .SETNL,  op1, "0F 9D 00");
        testOp1(m64, .SETNLE, op1, "0F 9F 00");
        testOp1(m64, .SETNO,  op1, "0F 91 00");
        testOp1(m64, .SETNP,  op1, "0F 9B 00");
        testOp1(m64, .SETNS,  op1, "0F 99 00");
        testOp1(m64, .SETNZ,  op1, "0F 95 00");
        testOp1(m64, .SETO,   op1, "0F 90 00");
        testOp1(m64, .SETP,   op1, "0F 9A 00");
        testOp1(m64, .SETPE,  op1, "0F 9A 00");
        testOp1(m64, .SETPO,  op1, "0F 9B 00");
        testOp1(m64, .SETS,   op1, "0F 98 00");
        testOp1(m64, .SETZ,   op1, "0F 94 00");
    }

}
