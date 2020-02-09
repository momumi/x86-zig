const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "extra instructions" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        // Pentium MMX
        testOp0(m32, .RDPMC, "0F 33");
        testOp0(m64, .RDPMC, "0F 33");
        // Pentium Pro
        testOp0(m64, .UD2,      "0F 0B");
        // AMD K6
        testOp0(m64, .SYSCALL,  "0F 05");
        testOp0(m64, .SYSRET,   "0F 07");
        testOp0(m64, .SYSRETQ,  "48 0F 07");
        // Pentium II
        testOp0(m64, .SYSENTER, "0F 34");
        testOp0(m64, .SYSEXIT,  "0F 35");
        testOp0(m64, .SYSEXITQ, "48 0F 35");
        // x86-64
        testOp0(m32, .RDTSCP, "0F 01 F9");
        testOp0(m64, .RDTSCP, "0F 01 F9");
        testOp0(m32, .SWAPGS, "0F 01 F8");
        testOp0(m64, .SWAPGS, "0F 01 F8");

    }

    {
        const op1 = Operand.register(.AX);
        const op2 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
        testOp2(m64, .UD0, op1, op2, "66 67 0F FF 00");
        testOp2(m64, .UD1, op1, op2, "66 67 0F B9 00");
    }

    // SSE non-vector
    {
        const reg32 = Operand.register(.EAX);
        const reg64 = Operand.register(.RAX);
        const rm_mem8 = Operand.memoryRm(.DefaultSeg, .BYTE, .RAX, 0);
        const rm_mem32 = Operand.memoryRm(.DefaultSeg, .DWORD, .RAX, 0);
        const rm_mem64 = Operand.memoryRm(.DefaultSeg, .QWORD, .RAX, 0);
        testOp0(m64, .SFENCE,  "0F AE F8");
        testOp0(m64, .LFENCE,  "0F AE E8");
        testOp0(m64, .MFENCE,  "0F AE F0");
        testOp0(m64, .PAUSE,   "F3 90");
        testOp0(m64, .MONITOR, "0F 01 C8");
        testOp0(m64, .MWAIT,   "0F 01 C9");

        testOp1(m64, .CLFLUSH,     rm_mem8, "0F AE 38");
        testOp1(m64, .PREFETCHNTA, rm_mem8, "0F 18 00");
        testOp1(m64, .PREFETCHT0,  rm_mem8, "0F 18 08");
        testOp1(m64, .PREFETCHT1,  rm_mem8, "0F 18 10");
        testOp1(m64, .PREFETCHT2,  rm_mem8, "0F 18 18");

        testOp2(m64, .MOVNTI, rm_mem32, reg32, "0F C3 00");
        testOp2(m64, .MOVNTI, rm_mem64, reg64, "48 0F C3 00");
    }

    // CMOVcc Pentium Pro / P6
    {
        const reg16 = Operand.register(.AX);
        const reg32 = Operand.register(.EAX);
        const reg64 = Operand.register(.RAX);
        const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
        const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
        const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);

        testOp2(m32, .CMOVA,   reg16, rm16,  "66 0F 47 00");
        testOp2(m32, .CMOVA,   reg32, rm32,  "0F 47 00");
        testOp2(m32, .CMOVA,   reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVAE,  reg16, rm16,  "66 0F 43 00");
        testOp2(m32, .CMOVAE,  reg32, rm32,  "0F 43 00");
        testOp2(m32, .CMOVAE,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVB,   reg16, rm16,  "66 0F 42 00");
        testOp2(m32, .CMOVB,   reg32, rm32,  "0F 42 00");
        testOp2(m32, .CMOVB,   reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVBE,  reg16, rm16,  "66 0F 46 00");
        testOp2(m32, .CMOVBE,  reg32, rm32,  "0F 46 00");
        testOp2(m32, .CMOVBE,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVC,   reg16, rm16,  "66 0F 42 00");
        testOp2(m32, .CMOVC,   reg32, rm32,  "0F 42 00");
        testOp2(m32, .CMOVC,   reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVE,   reg16, rm16,  "66 0F 44 00");
        testOp2(m32, .CMOVE,   reg32, rm32,  "0F 44 00");
        testOp2(m32, .CMOVE,   reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVG,   reg16, rm16,  "66 0F 4F 00");
        testOp2(m32, .CMOVG,   reg32, rm32,  "0F 4F 00");
        testOp2(m32, .CMOVG,   reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVGE,  reg16, rm16,  "66 0F 4D 00");
        testOp2(m32, .CMOVGE,  reg32, rm32,  "0F 4D 00");
        testOp2(m32, .CMOVGE,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVL,   reg16, rm16,  "66 0F 4C 00");
        testOp2(m32, .CMOVL,   reg32, rm32,  "0F 4C 00");
        testOp2(m32, .CMOVL,   reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVLE,  reg16, rm16,  "66 0F 4E 00");
        testOp2(m32, .CMOVLE,  reg32, rm32,  "0F 4E 00");
        testOp2(m32, .CMOVLE,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNA,  reg16, rm16,  "66 0F 46 00");
        testOp2(m32, .CMOVNA,  reg32, rm32,  "0F 46 00");
        testOp2(m32, .CMOVNA,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNAE, reg16, rm16,  "66 0F 42 00");
        testOp2(m32, .CMOVNAE, reg32, rm32,  "0F 42 00");
        testOp2(m32, .CMOVNAE, reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNB,  reg16, rm16,  "66 0F 43 00");
        testOp2(m32, .CMOVNB,  reg32, rm32,  "0F 43 00");
        testOp2(m32, .CMOVNB,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNBE, reg16, rm16,  "66 0F 47 00");
        testOp2(m32, .CMOVNBE, reg32, rm32,  "0F 47 00");
        testOp2(m32, .CMOVNBE, reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNC,  reg16, rm16,  "66 0F 43 00");
        testOp2(m32, .CMOVNC,  reg32, rm32,  "0F 43 00");
        testOp2(m32, .CMOVNC,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNE,  reg16, rm16,  "66 0F 45 00");
        testOp2(m32, .CMOVNE,  reg32, rm32,  "0F 45 00");
        testOp2(m32, .CMOVNE,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNG,  reg16, rm16,  "66 0F 4E 00");
        testOp2(m32, .CMOVNG,  reg32, rm32,  "0F 4E 00");
        testOp2(m32, .CMOVNG,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNGE, reg16, rm16,  "66 0F 4C 00");
        testOp2(m32, .CMOVNGE, reg32, rm32,  "0F 4C 00");
        testOp2(m32, .CMOVNGE, reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNL,  reg16, rm16,  "66 0F 4D 00");
        testOp2(m32, .CMOVNL,  reg32, rm32,  "0F 4D 00");
        testOp2(m32, .CMOVNL,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNLE, reg16, rm16,  "66 0F 4F 00");
        testOp2(m32, .CMOVNLE, reg32, rm32,  "0F 4F 00");
        testOp2(m32, .CMOVNLE, reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNO,  reg16, rm16,  "66 0F 41 00");
        testOp2(m32, .CMOVNO,  reg32, rm32,  "0F 41 00");
        testOp2(m32, .CMOVNO,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNP,  reg16, rm16,  "66 0F 4B 00");
        testOp2(m32, .CMOVNP,  reg32, rm32,  "0F 4B 00");
        testOp2(m32, .CMOVNP,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNS,  reg16, rm16,  "66 0F 49 00");
        testOp2(m32, .CMOVNS,  reg32, rm32,  "0F 49 00");
        testOp2(m32, .CMOVNS,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVNZ,  reg16, rm16,  "66 0F 45 00");
        testOp2(m32, .CMOVNZ,  reg32, rm32,  "0F 45 00");
        testOp2(m32, .CMOVNZ,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVO,   reg16, rm16,  "66 0F 40 00");
        testOp2(m32, .CMOVO,   reg32, rm32,  "0F 40 00");
        testOp2(m32, .CMOVO,   reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVP,   reg16, rm16,  "66 0F 4A 00");
        testOp2(m32, .CMOVP,   reg32, rm32,  "0F 4A 00");
        testOp2(m32, .CMOVP,   reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVPE,  reg16, rm16,  "66 0F 4A 00");
        testOp2(m32, .CMOVPE,  reg32, rm32,  "0F 4A 00");
        testOp2(m32, .CMOVPE,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVPO,  reg16, rm16,  "66 0F 4B 00");
        testOp2(m32, .CMOVPO,  reg32, rm32,  "0F 4B 00");
        testOp2(m32, .CMOVPO,  reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVS,   reg16, rm16,  "66 0F 48 00");
        testOp2(m32, .CMOVS,   reg32, rm32,  "0F 48 00");
        testOp2(m32, .CMOVS,   reg64, rm64,  AsmError.InvalidOperand);
        testOp2(m32, .CMOVZ,   reg16, rm16,  "66 0F 44 00");
        testOp2(m32, .CMOVZ,   reg32, rm32,  "0F 44 00");
        testOp2(m32, .CMOVZ,   reg64, rm64,  AsmError.InvalidOperand);

        testOp2(m64, .CMOVA,   reg16, rm16,  "66 67 0F 47 00");
        testOp2(m64, .CMOVA,   reg32, rm32,  "67 0F 47 00");
        testOp2(m64, .CMOVA,   reg64, rm64,  "67 48 0F 47 00");
        testOp2(m64, .CMOVAE,  reg16, rm16,  "66 67 0F 43 00");
        testOp2(m64, .CMOVAE,  reg32, rm32,  "67 0F 43 00");
        testOp2(m64, .CMOVAE,  reg64, rm64,  "67 48 0F 43 00");
        testOp2(m64, .CMOVB,   reg16, rm16,  "66 67 0F 42 00");
        testOp2(m64, .CMOVB,   reg32, rm32,  "67 0F 42 00");
        testOp2(m64, .CMOVB,   reg64, rm64,  "67 48 0F 42 00");
        testOp2(m64, .CMOVBE,  reg16, rm16,  "66 67 0F 46 00");
        testOp2(m64, .CMOVBE,  reg32, rm32,  "67 0F 46 00");
        testOp2(m64, .CMOVBE,  reg64, rm64,  "67 48 0F 46 00");
        testOp2(m64, .CMOVC,   reg16, rm16,  "66 67 0F 42 00");
        testOp2(m64, .CMOVC,   reg32, rm32,  "67 0F 42 00");
        testOp2(m64, .CMOVC,   reg64, rm64,  "67 48 0F 42 00");
        testOp2(m64, .CMOVE,   reg16, rm16,  "66 67 0F 44 00");
        testOp2(m64, .CMOVE,   reg32, rm32,  "67 0F 44 00");
        testOp2(m64, .CMOVE,   reg64, rm64,  "67 48 0F 44 00");
        testOp2(m64, .CMOVG,   reg16, rm16,  "66 67 0F 4F 00");
        testOp2(m64, .CMOVG,   reg32, rm32,  "67 0F 4F 00");
        testOp2(m64, .CMOVG,   reg64, rm64,  "67 48 0F 4F 00");
        testOp2(m64, .CMOVGE,  reg16, rm16,  "66 67 0F 4D 00");
        testOp2(m64, .CMOVGE,  reg32, rm32,  "67 0F 4D 00");
        testOp2(m64, .CMOVGE,  reg64, rm64,  "67 48 0F 4D 00");
        testOp2(m64, .CMOVL,   reg16, rm16,  "66 67 0F 4C 00");
        testOp2(m64, .CMOVL,   reg32, rm32,  "67 0F 4C 00");
        testOp2(m64, .CMOVL,   reg64, rm64,  "67 48 0F 4C 00");
        testOp2(m64, .CMOVLE,  reg16, rm16,  "66 67 0F 4E 00");
        testOp2(m64, .CMOVLE,  reg32, rm32,  "67 0F 4E 00");
        testOp2(m64, .CMOVLE,  reg64, rm64,  "67 48 0F 4E 00");
        testOp2(m64, .CMOVNA,  reg16, rm16,  "66 67 0F 46 00");
        testOp2(m64, .CMOVNA,  reg32, rm32,  "67 0F 46 00");
        testOp2(m64, .CMOVNA,  reg64, rm64,  "67 48 0F 46 00");
        testOp2(m64, .CMOVNAE, reg16, rm16,  "66 67 0F 42 00");
        testOp2(m64, .CMOVNAE, reg32, rm32,  "67 0F 42 00");
        testOp2(m64, .CMOVNAE, reg64, rm64,  "67 48 0F 42 00");
        testOp2(m64, .CMOVNB,  reg16, rm16,  "66 67 0F 43 00");
        testOp2(m64, .CMOVNB,  reg32, rm32,  "67 0F 43 00");
        testOp2(m64, .CMOVNB,  reg64, rm64,  "67 48 0F 43 00");
        testOp2(m64, .CMOVNBE, reg16, rm16,  "66 67 0F 47 00");
        testOp2(m64, .CMOVNBE, reg32, rm32,  "67 0F 47 00");
        testOp2(m64, .CMOVNBE, reg64, rm64,  "67 48 0F 47 00");
        testOp2(m64, .CMOVNC,  reg16, rm16,  "66 67 0F 43 00");
        testOp2(m64, .CMOVNC,  reg32, rm32,  "67 0F 43 00");
        testOp2(m64, .CMOVNC,  reg64, rm64,  "67 48 0F 43 00");
        testOp2(m64, .CMOVNE,  reg16, rm16,  "66 67 0F 45 00");
        testOp2(m64, .CMOVNE,  reg32, rm32,  "67 0F 45 00");
        testOp2(m64, .CMOVNE,  reg64, rm64,  "67 48 0F 45 00");
        testOp2(m64, .CMOVNG,  reg16, rm16,  "66 67 0F 4E 00");
        testOp2(m64, .CMOVNG,  reg32, rm32,  "67 0F 4E 00");
        testOp2(m64, .CMOVNG,  reg64, rm64,  "67 48 0F 4E 00");
        testOp2(m64, .CMOVNGE, reg16, rm16,  "66 67 0F 4C 00");
        testOp2(m64, .CMOVNGE, reg32, rm32,  "67 0F 4C 00");
        testOp2(m64, .CMOVNGE, reg64, rm64,  "67 48 0F 4C 00");
        testOp2(m64, .CMOVNL,  reg16, rm16,  "66 67 0F 4D 00");
        testOp2(m64, .CMOVNL,  reg32, rm32,  "67 0F 4D 00");
        testOp2(m64, .CMOVNL,  reg64, rm64,  "67 48 0F 4D 00");
        testOp2(m64, .CMOVNLE, reg16, rm16,  "66 67 0F 4F 00");
        testOp2(m64, .CMOVNLE, reg32, rm32,  "67 0F 4F 00");
        testOp2(m64, .CMOVNLE, reg64, rm64,  "67 48 0F 4F 00");
        testOp2(m64, .CMOVNO,  reg16, rm16,  "66 67 0F 41 00");
        testOp2(m64, .CMOVNO,  reg32, rm32,  "67 0F 41 00");
        testOp2(m64, .CMOVNO,  reg64, rm64,  "67 48 0F 41 00");
        testOp2(m64, .CMOVNP,  reg16, rm16,  "66 67 0F 4B 00");
        testOp2(m64, .CMOVNP,  reg32, rm32,  "67 0F 4B 00");
        testOp2(m64, .CMOVNP,  reg64, rm64,  "67 48 0F 4B 00");
        testOp2(m64, .CMOVNS,  reg16, rm16,  "66 67 0F 49 00");
        testOp2(m64, .CMOVNS,  reg32, rm32,  "67 0F 49 00");
        testOp2(m64, .CMOVNS,  reg64, rm64,  "67 48 0F 49 00");
        testOp2(m64, .CMOVNZ,  reg16, rm16,  "66 67 0F 45 00");
        testOp2(m64, .CMOVNZ,  reg32, rm32,  "67 0F 45 00");
        testOp2(m64, .CMOVNZ,  reg64, rm64,  "67 48 0F 45 00");
        testOp2(m64, .CMOVO,   reg16, rm16,  "66 67 0F 40 00");
        testOp2(m64, .CMOVO,   reg32, rm32,  "67 0F 40 00");
        testOp2(m64, .CMOVO,   reg64, rm64,  "67 48 0F 40 00");
        testOp2(m64, .CMOVP,   reg16, rm16,  "66 67 0F 4A 00");
        testOp2(m64, .CMOVP,   reg32, rm32,  "67 0F 4A 00");
        testOp2(m64, .CMOVP,   reg64, rm64,  "67 48 0F 4A 00");
        testOp2(m64, .CMOVPE,  reg16, rm16,  "66 67 0F 4A 00");
        testOp2(m64, .CMOVPE,  reg32, rm32,  "67 0F 4A 00");
        testOp2(m64, .CMOVPE,  reg64, rm64,  "67 48 0F 4A 00");
        testOp2(m64, .CMOVPO,  reg16, rm16,  "66 67 0F 4B 00");
        testOp2(m64, .CMOVPO,  reg32, rm32,  "67 0F 4B 00");
        testOp2(m64, .CMOVPO,  reg64, rm64,  "67 48 0F 4B 00");
        testOp2(m64, .CMOVS,   reg16, rm16,  "66 67 0F 48 00");
        testOp2(m64, .CMOVS,   reg32, rm32,  "67 0F 48 00");
        testOp2(m64, .CMOVS,   reg64, rm64,  "67 48 0F 48 00");
        testOp2(m64, .CMOVZ,   reg16, rm16,  "66 67 0F 44 00");
        testOp2(m64, .CMOVZ,   reg32, rm32,  "67 0F 44 00");
        testOp2(m64, .CMOVZ,   reg64, rm64,  "67 48 0F 44 00");

    }
}
