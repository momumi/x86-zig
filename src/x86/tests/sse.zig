const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "SSE" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    const reg = Operand.register;
    const regRm = Operand.registerRm;
    const imm = Operand.immediate;

    debugPrint(false);

    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const mem_32 = rm32;
    const mem_64 = rm64;
    const rm_mem32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm_mem64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const rm_mem128 = Operand.memoryRm(.DefaultSeg, .XMM_WORD, .EAX, 0);
    const mem_128 = Operand.memoryRm(.DefaultSeg, .OWORD, .EAX, 0);


    testOp2(m32, .ADDPD,     reg(.XMM0), mem_128, "66 0f 58 00");
    testOp2(m32, .ADDPS,     reg(.XMM0), mem_128, "0f 58 00");

    testOp2(m32, .ADDSD,     reg(.XMM0), mem_64,  "f2 0f 58 00");
    testOp2(m32, .ADDSS,     reg(.XMM0), mem_32,  "f3 0f 58 00");

    testOp2(m32, .ADDSUBPD,  reg(.XMM0), mem_128, "66 0f D0 00");
    testOp2(m32, .ADDSUBPS,  reg(.XMM0), mem_128, "f2 0f D0 00");

    testOp2(m32, .ANDPD,  reg(.XMM0), mem_128, "66 0f 54 00");
    testOp2(m32, .ANDPS,  reg(.XMM0), mem_128, "0f 54 00");

    testOp2(m32, .ANDNPD,  reg(.XMM0), mem_128, "66 0f 55 00");
    testOp2(m32, .ANDNPS,  reg(.XMM0), mem_128, "0f 55 00");

    testOp3(m32, .CMPSD,   reg(.XMM0), mem_64, imm(0), "f2 0f c2 00 00");
    testOp3(m32, .CMPSS,   reg(.XMM0), mem_32, imm(0), "f3 0f c2 00 00");

    {
        // BLENDPD
        testOp3(m64, .BLENDPD,   reg(.XMM0), reg(.XMM0), imm(0), "66 0f 3a 0d c0 00");
        // BLENDPS
        testOp3(m64, .BLENDPS,   reg(.XMM0), reg(.XMM0), imm(0), "66 0f 3a 0c c0 00");
        // BLENDVPD
        testOp3(m64, .BLENDVPD,  reg(.XMM0), reg(.XMM0), reg(.XMM0), "66 0f 38 15 c0");
        testOp2(m64, .BLENDVPD,  reg(.XMM0), reg(.XMM0),  "66 0f 38 15 c0");
        // BLENDVPS
        testOp3(m64, .BLENDVPS,  reg(.XMM0), reg(.XMM0), reg(.XMM0), "66 0f 38 14 c0");
        testOp2(m64, .BLENDVPS,  reg(.XMM0), reg(.XMM0),  "66 0f 38 14 c0");
    }

    {
        // COMISD
        testOp2(m64, .COMISD,    reg(.XMM0), reg(.XMM0), "66 0f 2f c0");
        // COMISS
        testOp2(m64, .COMISS,    reg(.XMM0), reg(.XMM0), "0f 2f c0");
    }

    {
        // CVTDQ2PD
        testOp2(m64, .CVTDQ2PD,  reg(.XMM0), reg(.XMM0), "f3 0f e6 c0");
        // CVTDQ2PS
        testOp2(m64, .CVTDQ2PS,  reg(.XMM0), reg(.XMM0), "0f 5b c0");
        // CVTPD2DQ
        testOp2(m64, .CVTPD2DQ,  reg(.XMM0), reg(.XMM0), "f2 0f e6 c0");
        // CVTPD2PI
        testOp2(m64, .CVTPD2PI,  reg(.MM0), reg(.XMM0), "66 0f 2d c0");
        // CVTPD2PS
        testOp2(m64, .CVTPD2PS,  reg(.XMM0), reg(.XMM0), "66 0f 5a c0");
        // CVTPI2PD
        testOp2(m64, .CVTPI2PD,  reg(.XMM0), reg(.MM0), "66 0f 2a c0");
        // CVTPI2PS
        testOp2(m64, .CVTPI2PS,  reg(.XMM0), reg(.MM0), "0f 2a c0");
        // CVTPS2DQ
        testOp2(m64, .CVTPS2DQ,  reg(.XMM0), reg(.XMM0), "66 0f 5b c0");
        // CVTPS2PD
        testOp2(m64, .CVTPS2PD,  reg(.XMM0), reg(.XMM0), "0f 5a c0");
        // CVTPS2PI
        testOp2(m64, .CVTPS2PI,  reg(.MM0), reg(.XMM0), "0f 2d c0");
        // CVTSD2SI
        testOp2(m64, .CVTSD2SI,  reg(.EAX), reg(.XMM0), "f2 0f 2d c0");
        testOp2(m64, .CVTSD2SI,  reg(.RAX), reg(.XMM0), "f2 48 0f 2d c0");
        testOp2(m32, .CVTSD2SI,  reg(.RAX), reg(.XMM0), AsmError.InvalidOperand);
        // CVTSD2SS
        testOp2(m64, .CVTSD2SS,  reg(.XMM0), reg(.XMM0), "f2 0f 5a c0");
        // CVTSI2SD
        testOp2(m64, .CVTSI2SD,  reg(.XMM0), rm32, "67 f2 0f 2a 00");
        testOp2(m64, .CVTSI2SD,  reg(.XMM0), rm64, "67 f2 48 0f 2a 00");
        // CVTSI2SS
        testOp2(m64, .CVTSI2SS,  reg(.XMM0), rm32, "67 f3 0f 2a 00");
        testOp2(m64, .CVTSI2SS,  reg(.XMM0), rm64, "67 f3 48 0f 2a 00");
        // CVTSS2SD
        testOp2(m64, .CVTSS2SD,  reg(.XMM0), reg(.XMM0), "f3 0f 5a c0");
        // CVTSS2SI
        testOp2(m64, .CVTSS2SI,  reg(.EAX), reg(.XMM0), "f3 0f 2d c0");
        testOp2(m64, .CVTSS2SI,  reg(.RAX), reg(.XMM0), "f3 48 0f 2d c0");
        testOp2(m32, .CVTSS2SI,  reg(.RAX), reg(.XMM0), AsmError.InvalidOperand);
        // CVTTPD2DQ
        testOp2(m64, .CVTTPD2DQ, reg(.XMM0), reg(.XMM0), "66 0f e6 c0");
        // CVTTPD2PI
        testOp2(m64, .CVTTPD2PI, reg(.MM0), reg(.XMM0), "66 0f 2c c0");
        // CVTTPS2DQ
        testOp2(m64, .CVTTPS2DQ, reg(.XMM0), reg(.XMM0), "f3 0f 5b c0");
        // CVTTPS2PI
        testOp2(m64, .CVTTPS2PI, reg(.MM0), reg(.XMM0), "0f 2c c0");
        // CVTTSD2SI
        testOp2(m64, .CVTTSD2SI, reg(.EAX), reg(.XMM0), "f2 0f 2c c0");
        testOp2(m64, .CVTTSD2SI, reg(.RAX), reg(.XMM0), "f2 48 0f 2c c0");
        testOp2(m32, .CVTTSD2SI, reg(.RAX), reg(.XMM0), AsmError.InvalidOperand);
        // CVTTSS2SI
        testOp2(m64, .CVTTSS2SI, reg(.EAX), reg(.XMM0), "f3 0f 2c c0");
        testOp2(m64, .CVTTSS2SI, reg(.RAX), reg(.XMM0), "f3 48 0f 2c c0");
        testOp2(m32, .CVTTSS2SI, reg(.RAX), reg(.XMM0), AsmError.InvalidOperand);
    }

    {
        // DIVPD
        testOp2(m64, .DIVPD, reg(.XMM0),  reg(.XMM0), "66 0f 5e c0");
        // DIVPS
        testOp2(m64, .DIVPS, reg(.XMM0),  reg(.XMM0), "0f 5e c0");
        // DIVSD
        testOp2(m64, .DIVSD, reg(.XMM0),  reg(.XMM0), "f2 0f 5e c0");
        // DIVSS
        testOp2(m64, .DIVSS, reg(.XMM0),  reg(.XMM0), "f3 0f 5e c0");
        // DPPD
        testOp3(m64, .DPPD,  reg(.XMM0), reg(.XMM0), imm(0), "66 0f 3a 41 c0 00");
        // DPPS
        testOp3(m64, .DPPS,  reg(.XMM0), reg(.XMM0), imm(0), "66 0f 3a 40 c0 00");
    }

    {
        // EXTRACTPS
        testOp3(m64, .EXTRACTPS, rm32, reg(.XMM0), imm(0),      "67 66 0f 3a 17 00 00");
        testOp3(m64, .EXTRACTPS, reg(.EAX), reg(.XMM0), imm(0), "66 0f 3a 17 c0 00");
        testOp3(m64, .EXTRACTPS, reg(.RAX), reg(.XMM0), imm(0), "66 0f 3a 17 c0 00");
        testOp3(m32, .EXTRACTPS, reg(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);
    }

    {
        // HADDPD
        testOp2(m64, .HADDPD,    reg(.XMM0), reg(.XMM0), "66 0f 7c c0");
        // HADDPS
        testOp2(m64, .HADDPS,    reg(.XMM0), reg(.XMM0), "f2 0f 7c c0");
        // HSUBPD
        testOp2(m64, .HSUBPD,    reg(.XMM0), reg(.XMM0), "66 0f 7d c0");
        // HSUBPS
        testOp2(m64, .HSUBPS,    reg(.XMM0), reg(.XMM0), "f2 0f 7d c0");
    }

    {
        // INSERTPS
        testOp3(m64, .INSERTPS,  reg(.XMM0),reg(.XMM0),imm(0), "660f3a21c000");
    }

    {
        // MAXPD
        testOp2(m64, .MAXPD,     reg(.XMM0), reg(.XMM0), "66 0f 5f c0");
        // MAXPS
        testOp2(m64, .MAXPS,     reg(.XMM0), reg(.XMM0), "0f 5f c0");
        // MAXSD
        testOp2(m64, .MAXSD,     reg(.XMM0), reg(.XMM0), "f2 0f 5f c0");
        // MAXSS
        testOp2(m64, .MAXSS,     reg(.XMM0), reg(.XMM0), "f3 0f 5f c0");
        // MINPD
        testOp2(m64, .MINPD,     reg(.XMM0), reg(.XMM0), "66 0f 5d c0");
        // MINPS
        testOp2(m64, .MINPS,     reg(.XMM0), reg(.XMM0), "0f 5d c0");
        // MINSD
        testOp2(m64, .MINSD,     reg(.XMM0), reg(.XMM0), "f2 0f 5d c0");
        // MINSS
        testOp2(m64, .MINSS,     reg(.XMM0), reg(.XMM0), "f3 0f 5d c0");
    }

    {
        // LDDQU
        testOp2(m64, .LDDQU,     reg(.XMM0), rm_mem128, "67 f2 0f f0 00");
    }

    {
        // MASKMOVDQU
        testOp2(m64, .MASKMOVDQU,reg(.XMM0), reg(.XMM0), "66 0f f7 c0");
        // MASKMOVQ
        testOp2(m64, .MASKMOVQ,  reg(.MM0), reg(.MM0), "0f f7 c0");
    }

    {
        // MAXPD
        testOp2(m64, .MAXPD,     reg(.XMM0), reg(.XMM0), "66 0f 5f c0");
        // MAXPS
        testOp2(m64, .MAXPS,     reg(.XMM0), reg(.XMM0), "0f 5f c0");
        // MAXSD
        testOp2(m64, .MAXSD,     reg(.XMM0), reg(.XMM0), "f2 0f 5f c0");
        // MAXSS
        testOp2(m64, .MAXSS,     reg(.XMM0), reg(.XMM0), "f3 0f 5f c0");
        // MINPD
        testOp2(m64, .MINPD,     reg(.XMM0), reg(.XMM0), "66 0f 5d c0");
        // MINPS
        testOp2(m64, .MINPS,     reg(.XMM0), reg(.XMM0), "0f 5d c0");
        // MINSD
        testOp2(m64, .MINSD,     reg(.XMM0), reg(.XMM0), "f2 0f 5d c0");
        // MINSS
        testOp2(m64, .MINSS,     reg(.XMM0), reg(.XMM0), "f3 0f 5d c0");
    }

    {
        // MOVAPD
        testOp2(m64, .MOVAPD,    reg(.XMM0), reg(.XMM0), "660f28c0");
        testOp2(m64, .MOVAPD,    regRm(.XMM0), reg(.XMM0), "660f29c0");
        // MOVAPS
        testOp2(m64, .MOVAPS,    reg(.XMM0), reg(.XMM0), "0f28c0");
        testOp2(m64, .MOVAPS,    regRm(.XMM0), reg(.XMM0), "0f29c0");
    }

    {
        {
            testOp2(m32, .MOVD, reg(.XMM0), rm32, "66 0F 6E 00");
            testOp2(m32, .MOVD, reg(.XMM7), rm32, "66 0F 6E 38");
            testOp2(m32, .MOVD, reg(.XMM15), rm32, AsmError.InvalidMode);
            testOp2(m32, .MOVD, reg(.XMM31), rm32, AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVD, reg(.XMM0), rm32, "67 66 0F 6E 00");
            testOp2(m64, .MOVD, reg(.XMM7), rm32, "67 66 0F 6E 38");
            testOp2(m64, .MOVD, reg(.XMM15), rm32, "67 66 44 0F 6E 38");
            testOp2(m64, .MOVD, reg(.XMM31), rm32, AsmError.InvalidOperand);
        }

        {
            testOp2(m32, .MOVD, reg(.XMM0), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.XMM7), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.XMM15), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.XMM31), rm64, AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVD, reg(.XMM0), rm64, "67 66 48 0F 6E 00");
            testOp2(m64, .MOVD, reg(.XMM7), rm64, "67 66 48 0F 6E 38");
            testOp2(m64, .MOVD, reg(.XMM15), rm64, "67 66 4C 0F 6E 38");
            testOp2(m64, .MOVD, reg(.XMM31), rm64, AsmError.InvalidOperand);
        }

        {
            testOp2(m32, .MOVQ, reg(.XMM0), reg(.RAX), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.XMM15), reg(.RAX), AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVQ, reg(.XMM0), reg(.RAX), "66 48 0F 6E C0");
            testOp2(m64, .MOVQ, reg(.XMM15), reg(.RAX), "66 4C 0F 6E F8");
            testOp2(m64, .MOVQ, reg(.XMM31), reg(.RAX), AsmError.InvalidOperand);
        }

        {
            testOp2(m32, .MOVQ, reg(.RAX), reg(.XMM0), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.RAX), reg(.XMM15), AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVQ, reg(.RAX), reg(.XMM0), "66 48 0F 7E C0");
            testOp2(m64, .MOVQ, reg(.RAX), reg(.XMM7), "66 48 0F 7E F8");
            testOp2(m64, .MOVQ, reg(.RAX), reg(.XMM15), "66 4C 0F 7E F8");
            testOp2(m64, .MOVQ, reg(.RAX), reg(.XMM31), AsmError.InvalidOperand);
        }

        {
            testOp2(m32, .MOVQ, reg(.XMM0), mem_64, "F3 0F 7E 00");
            testOp2(m32, .MOVQ, reg(.XMM7), mem_64, "F3 0F 7E 38");
            testOp2(m32, .MOVQ, reg(.XMM15), mem_64, AsmError.InvalidMode);
            //
            testOp2(m64, .MOVQ, reg(.XMM0), mem_64, "67 F3 0F 7E 00");
            testOp2(m64, .MOVQ, reg(.XMM7), mem_64, "67 F3 0F 7E 38");
            testOp2(m64, .MOVQ, reg(.XMM15), mem_64, "67 F3 44 0F 7E 38");
            testOp2(m64, .MOVQ, reg(.XMM31), mem_64, AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVD, reg(.XMM0), mem_64, "67 66 48 0F 6E 00");
            testOp2(m64, .MOVD, reg(.XMM7), mem_64, "67 66 48 0F 6E 38");
            testOp2(m64, .MOVD, reg(.XMM15), mem_64, "67 66 4C 0F 6E 38");
            testOp2(m64, .MOVD, reg(.XMM31), mem_64, AsmError.InvalidOperand);
        }

        {
            testOp2(m32, .MOVQ, mem_64, reg(.XMM0), "66 0F D6 00");
            testOp2(m32, .MOVQ, mem_64, reg(.XMM7), "66 0F D6 38");
            testOp2(m32, .MOVQ, mem_64, reg(.XMM15), AsmError.InvalidMode);
            //
            testOp2(m64, .MOVQ, mem_64, reg(.XMM0), "67 66 0F D6 00");
            testOp2(m64, .MOVQ, mem_64, reg(.XMM7), "67 66 0F D6 38");
            testOp2(m64, .MOVQ, mem_64, reg(.XMM15), "67 66 44 0F D6 38");
            testOp2(m64, .MOVQ, mem_64, reg(.XMM31), AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVD, mem_64, reg(.XMM0), "67 66 48 0F 7E 00");
            testOp2(m64, .MOVD, mem_64, reg(.XMM7), "67 66 48 0F 7E 38");
            testOp2(m64, .MOVD, mem_64, reg(.XMM15), "67 66 4C 0F 7E 38");
            testOp2(m64, .MOVD, mem_64, reg(.XMM31), AsmError.InvalidOperand);
        }

        {
            testOp2(m32, .MOVQ, reg(.XMM0), reg(.XMM0), "F3 0F 7E c0");
            testOp2(m32, .MOVQ, reg(.XMM7), reg(.XMM7), "F3 0F 7E ff");
            testOp2(m32, .MOVQ, reg(.XMM15), reg(.XMM15), AsmError.InvalidMode);
            //
            testOp2(m64, .MOVQ, reg(.XMM0), reg(.XMM0),   "F3 0F 7E c0");
            testOp2(m64, .MOVQ, reg(.XMM7), reg(.XMM7),   "F3 0F 7E ff");
            testOp2(m64, .MOVQ, reg(.XMM15), reg(.XMM15), "F3 45 0F 7E ff");
            testOp2(m64, .MOVQ, reg(.XMM31), reg(.XMM15), AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVQ, regRm(.XMM0), reg(.XMM0),   "66 0F D6 c0");
            testOp2(m64, .MOVQ, regRm(.XMM7), reg(.XMM7),   "66 0F D6 ff");
            testOp2(m64, .MOVQ, regRm(.XMM15), reg(.XMM15), "66 45 0F D6 ff");
            testOp2(m64, .MOVQ, regRm(.XMM31), reg(.XMM15), AsmError.InvalidOperand);
        }
    }

    {
        // MOVDQA
        testOp2(m64, .MOVDQA,    reg(.XMM0), reg(.XMM0), "660f6fc0");
        testOp2(m64, .MOVDQA,    regRm(.XMM0), reg(.XMM0), "660f7fc0");
        // MOVDQU
        testOp2(m64, .MOVDQU,    reg(.XMM0), reg(.XMM0), "f30f6fc0");
        testOp2(m64, .MOVDQU,    regRm(.XMM0), reg(.XMM0), "f30f7fc0");
        // MOVDQ2Q
        testOp2(m64, .MOVDQ2Q,    reg(.MM0), reg(.XMM0), "f20fd6c0");
    }

    {
        testOp2(m32, .PACKSSWB, reg(.XMM0), reg(.XMM0), "66 0F 63 c0");
        testOp2(m32, .PACKSSWB, reg(.XMM0), reg(.XMM1), "66 0F 63 c1");
        testOp2(m32, .PACKSSWB, reg(.XMM1), reg(.XMM0), "66 0F 63 c8");
        testOp2(m32, .PACKSSWB, reg(.XMM0), mem_128,    "66 0F 63 00");
        testOp2(m32, .PACKSSWB, reg(.XMM0), mem_64,     AsmError.InvalidOperand);
        testOp2(m32, .PACKSSWB, mem_64, mem_64,         AsmError.InvalidOperand);
        testOp2(m32, .PACKSSWB, mem_64, reg(.XMM1),     AsmError.InvalidOperand);
        testOp2(m32, .PACKSSWB, mem_128, mem_128,       AsmError.InvalidOperand);
        testOp2(m32, .PACKSSWB, mem_128, reg(.XMM1),    AsmError.InvalidOperand);

        testOp2(m32, .PACKSSDW, reg(.XMM0), reg(.XMM0), "66 0F 6B c0");
        testOp2(m32, .PACKSSDW, reg(.XMM0), reg(.XMM1), "66 0F 6B c1");
        testOp2(m32, .PACKSSDW, reg(.XMM1), reg(.XMM0), "66 0F 6B c8");
        testOp2(m32, .PACKSSDW, reg(.XMM0), mem_128,    "66 0F 6B 00");
        testOp2(m32, .PACKSSDW, reg(.XMM0), mem_64,     AsmError.InvalidOperand);
        testOp2(m32, .PACKSSDW, mem_64, mem_64,         AsmError.InvalidOperand);
        testOp2(m32, .PACKSSDW, mem_64, reg(.XMM1),     AsmError.InvalidOperand);

        testOp2(m32, .PACKUSWB, reg(.XMM0), reg(.XMM0), "66 0F 67 c0");
        testOp2(m32, .PACKUSWB, reg(.XMM0), reg(.XMM1), "66 0F 67 c1");
        testOp2(m32, .PACKUSWB, reg(.XMM1), reg(.XMM0), "66 0F 67 c8");
        testOp2(m32, .PACKUSWB, reg(.XMM0), mem_128,    "66 0F 67 00");
        testOp2(m32, .PACKUSWB, mem_64, mem_64,         AsmError.InvalidOperand);
        testOp2(m32, .PACKUSWB, mem_64, reg(.XMM1),     AsmError.InvalidOperand);
        testOp2(m32, .PACKUSWB, mem_128, mem_128,       AsmError.InvalidOperand);
        testOp2(m32, .PACKUSWB, mem_128, reg(.XMM1),    AsmError.InvalidOperand);

        testOp2(m32, .PACKUSDW, reg(.XMM0), reg(.XMM0), "66 0F 38 2B c0");
        testOp2(m32, .PACKUSDW, reg(.XMM0), reg(.XMM1), "66 0F 38 2B c1");
        testOp2(m32, .PACKUSDW, reg(.XMM1), reg(.XMM0), "66 0F 38 2B c8");
        testOp2(m32, .PACKUSDW, reg(.XMM0), mem_128,    "66 0F 38 2B 00");
        testOp2(m32, .PACKUSDW, mem_64, mem_64,         AsmError.InvalidOperand);
        testOp2(m32, .PACKUSDW, mem_64, reg(.XMM1),     AsmError.InvalidOperand);
        testOp2(m32, .PACKUSDW, mem_128, mem_128,       AsmError.InvalidOperand);
        testOp2(m32, .PACKUSDW, mem_128, reg(.XMM1),    AsmError.InvalidOperand);
    }

    {
        testOp2(m32, .PADDB,     reg(.XMM0), reg(.XMM0), "66 0f fc c0");
        testOp2(m32, .PADDW,     reg(.XMM0), reg(.XMM0), "66 0f fd c0");
        testOp2(m32, .PADDD,     reg(.XMM0), reg(.XMM0), "66 0f fe c0");
        testOp2(m32, .PADDQ,     reg(.XMM0), reg(.XMM0), "66 0f d4 c0");

        testOp2(m32, .PADDSB,    reg(.XMM0), reg(.XMM0), "66 0f ec c0");
        testOp2(m32, .PADDSW,    reg(.XMM0), reg(.XMM0), "66 0f ed c0");

        testOp2(m32, .PADDUSB,   reg(.XMM0), reg(.XMM0), "66 0f dc c0");
        testOp2(m32, .PADDUSW,   reg(.XMM0), reg(.XMM0), "66 0f dd c0");

        testOp2(m32, .PAND,      reg(.XMM0), reg(.XMM0), "66 0f db c0");
        testOp2(m32, .PANDN,     reg(.XMM0), reg(.XMM0), "66 0f df c0");
        testOp2(m32, .POR,       reg(.XMM0), reg(.XMM0), "66 0f eb c0");
        testOp2(m32, .PXOR,      reg(.XMM0), reg(.XMM0), "66 0f ef c0");

        testOp2(m32, .PCMPEQB,   reg(.XMM0), reg(.XMM0), "66 0f 74 c0");
        testOp2(m32, .PCMPEQW,   reg(.XMM0), reg(.XMM0), "66 0f 75 c0");
        testOp2(m32, .PCMPEQD,   reg(.XMM0), reg(.XMM0), "66 0f 76 c0");

        testOp2(m32, .PCMPGTB,   reg(.XMM0), reg(.XMM0), "66 0f 64 c0");
        testOp2(m32, .PCMPGTW,   reg(.XMM0), reg(.XMM0), "66 0f 65 c0");
        testOp2(m32, .PCMPGTD,   reg(.XMM0), reg(.XMM0), "66 0f 66 c0");

        testOp3(m32, .PEXTRB,   reg(.EAX), reg(.XMM0), imm(0), "66 0f 3a 14 c0 00");
        testOp3(m32, .PEXTRB,   reg(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);
        testOp3(m64, .PEXTRB,   reg(.RAX), reg(.XMM0), imm(0), "66 0f 3a 14 c0 00");

        testOp3(m32, .PEXTRW,   reg( .AX), reg(.XMM0), imm(0), "66 0f c5 c0 00");
        testOp3(m32, .PEXTRW,   reg(.EAX), reg(.XMM0), imm(0), "66 0f c5 c0 00");
        testOp3(m32, .PEXTRW,   reg(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);
        testOp3(m64, .PEXTRW,   reg(.RAX), reg(.XMM0), imm(0), "66 0f c5 c0 00");

        testOp3(m32, .PEXTRW,   regRm( .AX), reg(.XMM0), imm(0), "66 0f 3A 15 c0 00");
        testOp3(m32, .PEXTRW,   regRm(.EAX), reg(.XMM0), imm(0), "66 0f 3A 15 c0 00");
        testOp3(m32, .PEXTRW,   regRm(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);
        testOp3(m64, .PEXTRW,   regRm(.RAX), reg(.XMM0), imm(0), "66 0f 3A 15 c0 00");

        testOp3(m32, .PEXTRD,   reg(.EAX), reg(.XMM0), imm(0), "66 0f 3a 16 c0 00");
        testOp3(m32, .PEXTRQ,   reg(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);
        testOp3(m64, .PEXTRQ,   reg(.RAX), reg(.XMM0), imm(0), "66 48 0f 3a 16 c0 00");

        testOp2(m32, .PMADDWD,   reg(.XMM0), reg(.XMM0), "66 0f f5 c0");
        testOp2(m32, .PMULHW,    reg(.XMM0), reg(.XMM0), "66 0f e5 c0");
        testOp2(m32, .PMULLW,    reg(.XMM0), reg(.XMM0), "66 0f d5 c0");

        testOp2(m32, .PSLLW,     reg(.XMM0), reg(.XMM0), "66 0f f1 c0");
        testOp2(m32, .PSLLW,     reg(.XMM0), imm(0),     "66 0f 71 f0 00");
        testOp2(m32, .PSLLD,     reg(.XMM0), reg(.XMM0), "66 0f f2 c0");
        testOp2(m32, .PSLLD,     reg(.XMM0), imm(0),     "66 0f 72 f0 00");
        testOp2(m32, .PSLLQ,     reg(.XMM0), reg(.XMM0), "66 0f f3 c0");
        testOp2(m32, .PSLLQ,     reg(.XMM0), imm(0),     "66 0f 73 f0 00");

        testOp2(m32, .PSRAW,     reg(.XMM0), reg(.XMM0), "66 0f e1 c0");
        testOp2(m32, .PSRAW,     reg(.XMM0), imm(0),     "66 0f 71 e0 00");
        testOp2(m32, .PSRAD,     reg(.XMM0), reg(.XMM0), "66 0f e2 c0");
        testOp2(m32, .PSRAD,     reg(.XMM0), imm(0),     "66 0f 72 e0 00");

        testOp2(m32, .PSRLW,     reg(.XMM0), reg(.XMM0), "66 0f d1 c0");
        testOp2(m32, .PSRLW,     reg(.XMM0), imm(0),     "66 0f 71 d0 00");
        testOp2(m32, .PSRLD,     reg(.XMM0), reg(.XMM0), "66 0f d2 c0");
        testOp2(m32, .PSRLD,     reg(.XMM0), imm(0),     "66 0f 72 d0 00");
        testOp2(m32, .PSRLQ,     reg(.XMM0), reg(.XMM0), "66 0f d3 c0");
        testOp2(m32, .PSRLQ,     reg(.XMM0), imm(0),     "66 0f 73 d0 00");

        testOp2(m32, .PSUBB,     reg(.XMM0), reg(.XMM0), "66 0f f8 c0");
        testOp2(m32, .PSUBW,     reg(.XMM0), reg(.XMM0), "66 0f f9 c0");
        testOp2(m32, .PSUBD,     reg(.XMM0), reg(.XMM0), "66 0f fa c0");

        testOp2(m32, .PSUBUSB,   reg(.XMM0), reg(.XMM0), "66 0f d8 c0");
        testOp2(m32, .PSUBUSW,   reg(.XMM0), reg(.XMM0), "66 0f d9 c0");

        testOp2(m32, .PUNPCKHBW, reg(.XMM0), reg(.XMM0), "66 0f 68 c0");
        testOp2(m32, .PUNPCKHWD, reg(.XMM0), reg(.XMM0), "66 0f 69 c0");
        testOp2(m32, .PUNPCKHDQ, reg(.XMM0), reg(.XMM0), "66 0f 6a c0");
        testOp2(m32, .PUNPCKHQDQ,reg(.XMM0), reg(.XMM0), "66 0f 6d c0");

        testOp2(m32, .PUNPCKLBW, reg(.XMM0), reg(.XMM0), "66 0f 60 c0");
        testOp2(m32, .PUNPCKLWD, reg(.XMM0), reg(.XMM0), "66 0f 61 c0");
        testOp2(m32, .PUNPCKLDQ, reg(.XMM0), reg(.XMM0), "66 0f 62 c0");
        testOp2(m32, .PUNPCKLQDQ,reg(.XMM0), reg(.XMM0), "66 0f 6c c0");
    }
}
