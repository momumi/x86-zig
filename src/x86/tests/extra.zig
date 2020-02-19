const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "extra instructions" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    const reg = Operand.register;
    const regRm = Operand.registerRm;
    const imm = Operand.immediate;
    const imm16 = Operand.immediate16;
    const imm32 = Operand.immediate32;
    const memRm = Operand.memoryRmDef;

    const reg16 = Operand.register(.AX);
    const reg32 = Operand.register(.EAX);
    const reg64 = Operand.register(.RAX);
    const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const rm_mem = Operand.memoryRm(.DefaultSeg, .Void, .EAX, 0);
    const rm_mem8 = Operand.memoryRm(.DefaultSeg, .BYTE, .EAX, 0);
    const rm_mem16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const rm_mem32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm_mem64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const rm_mem128 = Operand.memoryRm(.DefaultSeg, .OWORD, .EAX, 0);

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
        testOp0(m64, .SFENCE,  "0F AE F8");
        testOp0(m64, .LFENCE,  "0F AE E8");
        testOp0(m64, .MFENCE,  "0F AE F0");
        testOp0(m64, .PAUSE,   "F3 90");
        testOp0(m64, .MONITOR, "0F 01 C8");
        testOp0(m64, .MWAIT,   "0F 01 C9");

        testOp1(m64, .FXSAVE,      rm_mem, "67 0F AE 00");
        testOp1(m64, .FXSAVE64,    rm_mem, "67 48 0F AE 00");
        testOp1(m64, .FXRSTOR,     rm_mem, "67 0F AE 08");
        testOp1(m64, .FXRSTOR64,   rm_mem, "67 48 0F AE 08");

        testOp1(m64, .CLFLUSH,     rm_mem8, "67 0F AE 38");
        testOp1(m64, .PREFETCHNTA, rm_mem8, "67 0F 18 00");
        testOp1(m64, .PREFETCHT0,  rm_mem8, "67 0F 18 08");
        testOp1(m64, .PREFETCHT1,  rm_mem8, "67 0F 18 10");
        testOp1(m64, .PREFETCHT2,  rm_mem8, "67 0F 18 18");

        testOp2(m64, .MOVNTI, rm_mem32, reg32, "67 0F C3 00");
        testOp2(m64, .MOVNTI, rm_mem64, reg64, "67 48 0F C3 00");

        testOp1(m32, .LDMXCSR, rm_mem32, "0F AE 10");
        testOp1(m64, .LDMXCSR, rm_mem32, "67 0F AE 10");

        testOp1(m32, .STMXCSR, rm_mem32, "0F AE 18");
        testOp1(m64, .STMXCSR, rm_mem32, "67 0F AE 18");
    }

    // ADX
    {
        // ADCX
        testOp2(m64, .ADCX, reg32, rm32, "67 66 0F 38 F6 00");
        testOp2(m64, .ADCX, reg64, rm64, "67 66 48 0F 38 F6 00");
        // ADOX
        testOp2(m64, .ADOX, reg32, rm32, "67 F3 0F 38 F6 00");
        testOp2(m64, .ADOX, reg64, rm64, "67 F3 48 0F 38 F6 00");
    }

    // BOUND
    {
        testOp2(m32, .BNDCL, reg(.BND0), rm32, "F3 0F 1A 00");
        testOp2(m32, .BNDCL, reg(.BND0), rm64, AsmError.InvalidOperand);
        testOp2(m64, .BNDCL, reg(.BND0), rm64, "67 F3 0F 1A 00");
        testOp2(m64, .BNDCL, reg(.BND0), rm32, AsmError.InvalidOperand);

        testOp2(m32, .BNDCL, reg(.BND3), rm32, "F3 0F 1A 18");
        testOp2(m32, .BNDCL, reg(.BND3), rm64, AsmError.InvalidOperand);
        testOp2(m64, .BNDCL, reg(.BND3), rm64, "67 F3 0F 1A 18");
        testOp2(m64, .BNDCL, reg(.BND3), rm32, AsmError.InvalidOperand);

        //
        testOp2(m32, .BNDCU,  reg(.BND0), rm32,       "F2 0F 1A 00");
        testOp2(m64, .BNDCU,  reg(.BND0), rm64,       "67 F2 0F 1A 00");
        testOp2(m32, .BNDCN,  reg(.BND0), rm32,       "F2 0F 1B 00");
        testOp2(m64, .BNDCN,  reg(.BND0), rm64,       "67 F2 0F 1B 00");
        //             reg(.                   "                 ");
        testOp2(m64, .BNDLDX, reg(.BND0), rm_mem,     "67 0F 1A 00");
        //             reg(.                   "                 ");
        testOp2(m32, .BNDMK,  reg(.BND0), rm_mem32,   "F3 0F 1B 00");
        testOp2(m64, .BNDMK,  reg(.BND0), rm_mem64,   "67 F3 0F 1B 00");
        //             reg(.                   "                ");
        testOp2(m32, .BNDMOV, reg(.BND0), regRm(.BND0), "66 0F 1A C0");
        testOp2(m64, .BNDMOV, reg(.BND0), regRm(.BND0), "66 0F 1A C0");
        testOp2(m32, .BNDMOV, regRm(.BND0), reg(.BND0), "66 0F 1B C0");
        testOp2(m64, .BNDMOV, regRm(.BND0), reg(.BND0), "66 0F 1B C0");
        //
        testOp2(m32, .BNDMOV, reg(.BND0), rm_mem64,   "66 0F 1A 00");
        testOp2(m64, .BNDMOV, reg(.BND0), rm_mem128,  "67 66 0F 1A 00");
        testOp2(m32, .BNDMOV, rm_mem64, reg(.BND0),   "66 0F 1B 00");
        testOp2(m64, .BNDMOV, rm_mem128, reg(.BND0),  "67 66 0F 1B 00");
        //             reg(                    "
        testOp2(m64, .BNDSTX, rm_mem, reg(.BND0),     "67 0F 1B 00");
    }

    // FSGSBASE
    {
        // RDFSBASE
        testOp1(m64, .RDFSBASE, reg32, "F3 0F AE c0");
        testOp1(m64, .RDFSBASE, reg64, "F3 48 0F AE c0");
        // RDGSBASE
        testOp1(m64, .RDGSBASE, reg32, "F3 0F AE c8");
        testOp1(m64, .RDGSBASE, reg64, "F3 48 0F AE c8");
        // WRFSBASE
        testOp1(m64, .WRFSBASE, reg32, "F3 0F AE d0");
        testOp1(m64, .WRFSBASE, reg64, "F3 48 0F AE d0");
        // WRGSBASE
        testOp1(m64, .WRGSBASE, reg32, "F3 0F AE d8");
        testOp1(m64, .WRGSBASE, reg64, "F3 48 0F AE d8");
    }

    // TDX
    {
        testOp0(m64, .XACQUIRE, "F2");
        testOp0(m64, .XRELEASE, "F3");

        testOp1(m64, .XABORT, imm(0), "C6 F8 00");

        testOp1(m64, .XBEGIN, imm(0), "66 C7 F8 00 00");
        testOp1(m64, .XBEGIN, imm16(0), "66 C7 F8 00 00");
        testOp1(m64, .XBEGIN, imm32(0), "C7 F8 00 00 00 00");

        testOp0(m64, .XEND, "0F 01 D5");

        testOp0(m64, .XTEST, "0F 01 D6");
    }

    // XSAVE
    {
        testOp0(m64, .XGETBV, "0F 01 D0");
        testOp0(m64, .XSETBV, "0F 01 D1");

        testOp1(m64, .XSAVE,      rm_mem, "67 0F AE 20");
        testOp1(m64, .XSAVE64,    rm_mem, "67 48 0F AE 20");
        testOp1(m64, .XRSTOR,     rm_mem, "67 0F AE 28");
        testOp1(m64, .XRSTOR64,   rm_mem, "67 48 0F AE 28");

        testOp1(m64, .XSAVEOPT,   rm_mem, "67 0F AE 30");
        testOp1(m64, .XSAVEOPT64, rm_mem, "67 48 0F AE 30");

        testOp1(m64, .XSAVEC,     rm_mem, "67 0F C7 20");
        testOp1(m64, .XSAVEC64,   rm_mem, "67 48 0F C7 20");

        testOp1(m64, .XSAVES,     rm_mem, "67 0F C7 28");
        testOp1(m64, .XSAVES64,   rm_mem, "67 48 0F C7 28");

        testOp1(m64, .XRSTORS,    rm_mem, "67 0F C7 18");
        testOp1(m64, .XRSTORS64,  rm_mem, "67 48 0F C7 18");
    }

    // AES
    {
        testOp2(m64, .AESDEC, reg(.XMM0), reg(.XMM0), "66 0f 38 de c0");
        testOp2(m64, .AESDECLAST, reg(.XMM0), reg(.XMM0), "66 0f 38 df c0");
        testOp2(m64, .AESENC, reg(.XMM0), reg(.XMM0), "66 0f 38 dc c0");
        testOp2(m64, .AESENCLAST, reg(.XMM0), reg(.XMM0), "66 0f 38 dd c0");
        testOp2(m64, .AESIMC, reg(.XMM0), reg(.XMM0), "66 0f 38 db c0");
        testOp3(m64, .AESKEYGENASSIST, reg(.XMM0), reg(.XMM0), imm(0), "66 0F 3A DF c0 00");
    }

    // GFNI
    {
        testOp3(m64, .GF2P8AFFINEINVQB, reg(.XMM0), reg(.XMM0), imm(0), "66 0F 3A CF c0 00");
        testOp3(m64, .GF2P8AFFINEQB,    reg(.XMM0), reg(.XMM0), imm(0), "66 0F 3A CE c0 00");
        testOp2(m64, .GF2P8MULB,        reg(.XMM0), reg(.XMM0),         "66 0F 38 CF c0");
    }

    // CLDEMOTE
    {
        testOp1(m32, .CLDEMOTE, rm_mem8, "0F 1C 00");
        testOp1(m64, .CLDEMOTE, rm_mem8, "67 0F 1C 00");
    }

    // CLWB
    {
        testOp1(m32, .CLWB, rm_mem8, "66 0F AE 30");
        testOp1(m64, .CLWB, rm_mem8, "67 66 0F AE 30");
    }

    // CLFLUSHOPT
    {
        testOp1(m32, .CLFLUSHOPT, rm_mem8, "66 0F AE 38");
        testOp1(m64, .CLFLUSHOPT, rm_mem8, "67 66 0F AE 38");
    }

    // INVPCID
    {
        testOp2(m32, .INVPCID, reg32, rm_mem128, "66 0F 38 82 00");
        testOp2(m64, .INVPCID, reg64, rm_mem128, "67 66 0F 38 82 00");
    }

    // MOVBE
    {
        testOp2(m64, .MOVBE, reg16, rm_mem16, "66 67 0F 38 F0 00");
        testOp2(m64, .MOVBE, reg32, rm_mem32, "67 0F 38 F0 00");
        testOp2(m64, .MOVBE, reg64, rm_mem64, "67 48 0F 38 F0 00");
        //
        testOp2(m64, .MOVBE, rm_mem16, reg16, "66 67 0F 38 F1 00");
        testOp2(m64, .MOVBE, rm_mem32, reg32, "67 0F 38 F1 00");
        testOp2(m64, .MOVBE, rm_mem64, reg64, "67 48 0F 38 F1 00");
    }

    // MOVDIRI
    {
        testOp2(m64, .MOVDIRI, rm_mem32, reg32, "67 0F 38 F9 00");
        testOp2(m64, .MOVDIRI, rm_mem64, reg64, "67 48 0F 38 F9 00");
    }

    // MOVDIR64B
    {
        // TODO: this should work, but we need to use 16 bit addressing
        if (false) {
            testOp2(m32, .MOVDIR64B, reg16, TODO, "67 66 0F 38 F8 00");
        }

        testOp2(m32, .MOVDIR64B, reg32, memRm(.Void, .EAX, 0), "66 0F 38 F8 00");
        testOp2(m32, .MOVDIR64B, reg64, memRm(.Void, .EAX, 0), AsmError.InvalidOperand);

        testOp2(m64, .MOVDIR64B, reg16, memRm(.Void, .EAX, 0), AsmError.InvalidOperand);
        testOp2(m64, .MOVDIR64B, reg16, memRm(.Void, .RAX, 0), AsmError.InvalidOperand);
        testOp2(m64, .MOVDIR64B, reg32, memRm(.Void, .EAX, 0), "67 66 0F 38 F8 00");
        testOp2(m64, .MOVDIR64B, reg32, memRm(.Void, .RAX, 0), AsmError.InvalidOperand);
        testOp2(m64, .MOVDIR64B, reg64, memRm(.Void, .EAX, 0), AsmError.InvalidOperand);
        testOp2(m64, .MOVDIR64B, reg64, memRm(.Void, .RAX, 0), "66 0F 38 F8 00");
    }

    // WAITPKG
    {
        testOp1(m32, .UMONITOR, reg16, "67 F3 0F AE f0");
        testOp1(m32, .UMONITOR, reg32, "F3 0F AE f0");
        testOp1(m32, .UMONITOR, reg64, AsmError.InvalidOperand);

        testOp1(m64, .UMONITOR, reg16, AsmError.InvalidOperand);
        testOp1(m64, .UMONITOR, reg32, "67 F3 0F AE f0");
        testOp1(m64, .UMONITOR, reg64, "F3 0F AE f0");

        testOp3(m32, .UMWAIT, reg32, reg(.EDX), reg(.EAX), "F2 0F AE f0");
        testOp1(m32, .UMWAIT, reg32, "F2 0F AE f0");

        testOp3(m32, .TPAUSE, reg32, reg(.EDX), reg(.EAX), "66 0F AE f0");
        testOp1(m32, .TPAUSE, reg32, "66 0F AE f0");
    }

    // SHA
    {
        testOp3(m64, .SHA1RNDS4, reg(.XMM0), reg(.XMM0), imm(0), "0f 3a cc c0 00");
        testOp2(m64, .SHA1NEXTE, reg(.XMM0), reg(.XMM0), "0f 38 c8 c0");
        testOp2(m64, .SHA1MSG1, reg(.XMM0), reg(.XMM0), "0f 38 c9 c0");
        testOp2(m64, .SHA1MSG2, reg(.XMM0), reg(.XMM0), "0f 38 ca c0");
        testOp2(m64, .SHA256RNDS2, reg(.XMM0), reg(.XMM0), "0f 38 cb c0");
        testOp3(m64, .SHA256RNDS2, reg(.XMM0), reg(.XMM0), reg(.XMM0), "0f 38 cb c0");
        testOp2(m64, .SHA256MSG1, reg(.XMM0), reg(.XMM0), "0f 38 cc c0");
        testOp2(m64, .SHA256MSG2, reg(.XMM0), reg(.XMM0), "0f 38 cd c0");
    }

    // PKRU
    {
        testOp0(m64, .RDPKRU, "0F 01 EE");
        testOp0(m64, .WRPKRU, "0F 01 EF");
    }

    // PREFETCHW
    {
        testOp1(m64, .PREFETCHW, rm_mem8, "67 0F 0D 08");
    }

    // PTWRITE
    {
        testOp1(m64, .PTWRITE, reg32, "F3 0F AE E0");
        testOp1(m64, .PTWRITE, reg64, "F3 48 0F AE E0");

        testOp1(m64, .PTWRITE, rm_mem32, "67 F3 0F AE 20");
        testOp1(m64, .PTWRITE, rm_mem64, "67 F3 48 0F AE 20");
    }

    // RDPID
    {
        testOp1(m32, .RDPID, reg32, "F3 0F C7 f8");
        testOp1(m64, .RDPID, reg64, "F3 0F C7 f8");
    }

    // RDRAND
    {
        testOp1(m64, .RDRAND, reg16, "66 0F C7 f0");
        testOp1(m64, .RDRAND, reg32, "0F C7 f0");
        testOp1(m64, .RDRAND, reg64, "48 0F C7 f0");
    }

    // RDSEED
    {
        testOp1(m64, .RDSEED, reg16, "66 0F C7 f8");
        testOp1(m64, .RDSEED, reg32, "0F C7 f8");
        testOp1(m64, .RDSEED, reg64, "48 0F C7 f8");
    }

    // SMAP
    {
        testOp0(m64, .CLAC, "0F 01 CA");
        testOp0(m64, .STAC, "0F 01 CB");
    }

    // SGX
    {
        testOp0(m64, .ENCLS, "0F 01 CF");
        testOp0(m64, .ENCLU, "0F 01 D7");
        testOp0(m64, .ENCLV, "0F 01 C0");
    }

    // SMX
    {
        testOp0(m64, .GETSEC, "0F 37");
    }

    // CMOVcc Pentium Pro / P6
    {
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
