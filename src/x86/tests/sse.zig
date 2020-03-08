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

    const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const mem_32 = rm32;
    const mem_64 = rm64;
    const rm_mem8 = Operand.memoryRm(.DefaultSeg, .BYTE, .EAX, 0);
    const rm_mem16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
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
        // MOVDDUP
        testOp2(m64, .MOVDDUP,   reg(.XMM1), regRm(.XMM0), "f2 0f 12 c8");
        // MOVDQA
        testOp2(m64, .MOVDQA,    reg(.XMM0), reg(.XMM0), "66 0f 6f c0");
        testOp2(m64, .MOVDQA,    regRm(.XMM0), reg(.XMM0), "66 0f 7f c0");
        // MOVDQU
        testOp2(m64, .MOVDQU,    reg(.XMM0), reg(.XMM0), "f3 0f 6f c0");
        testOp2(m64, .MOVDQU,    regRm(.XMM0), reg(.XMM0), "f3 0f 7f c0");
        // MOVDQ2Q
        testOp2(m64, .MOVDQ2Q,   reg(.MM0), reg(.XMM0), "f2 0f d6 c0");
        // MOVHLPS
        testOp2(m64, .MOVHLPS,   reg(.XMM0), reg(.XMM0), "0f 12 c0");
        // MOVHPD
        testOp2(m64, .MOVHPD,    reg(.XMM0), rm_mem64, "67 66 0f 16 00");
        // MOVHPS
        testOp2(m64, .MOVHPS,    reg(.XMM0), rm_mem64, "67 0f 16 00");
        // MOVLHPS
        testOp2(m64, .MOVLHPS,   reg(.XMM0), reg(.XMM0), "0f 16 c0");
        // MOVLPD
        testOp2(m64, .MOVLPD,    reg(.XMM0), rm_mem64, "67 66 0f 12 00");
        // MOVLPS
        testOp2(m64, .MOVLPS,    reg(.XMM0), rm_mem64, "67 0f 12 00");
        // MOVMSKPD
        testOp2(m64, .MOVMSKPD,  reg(.EAX), reg(.XMM0), "66 0f 50 c0");
        testOp2(m64, .MOVMSKPD,  reg(.RAX), reg(.XMM0), "66 0f 50 c0");
        // MOVMSKPS
        testOp2(m64, .MOVMSKPS,  reg(.EAX), reg(.XMM0), "0f 50 c0");
        testOp2(m64, .MOVMSKPS,  reg(.RAX), reg(.XMM0), "0f 50 c0");
        // MOVNTDQA
        testOp2(m64, .MOVNTDQA,  reg(.XMM0), rm_mem128, "67 66 0f 38 2a 00");
        // MOVNTDQ
        testOp2(m64, .MOVNTDQ,   rm_mem128, reg(.XMM0), "67 66 0f e7 00");
        // MOVNTPD
        testOp2(m64, .MOVNTPD,   rm_mem128, reg(.XMM0), "67 66 0f 2b 00");
        // MOVNTPS
        testOp2(m64, .MOVNTPS,   rm_mem128, reg(.XMM0), "67 0f 2b 00");
        // MOVNTQ
        testOp2(m64, .MOVNTQ,    rm_mem64, reg(.MM0), "67 0f e7 00");
        // MOVQ2DQ
        testOp2(m64, .MOVQ2DQ,   reg(.XMM0), reg(.MM0), "f3 0f d6 c0");
        // MOVSD
        testOp2(m64, .MOVSD,     reg(.XMM0), reg(.XMM0), "f2 0f 10 c0");
        testOp2(m64, .MOVSD,     regRm(.XMM0), reg(.XMM0), "f2 0f 11 c0");
        // MOVSHDUP
        testOp2(m64, .MOVSHDUP,  reg(.XMM0), reg(.XMM0), "f3 0f 16 c0");
        // MOVSLDUP
        testOp2(m64, .MOVSLDUP,  reg(.XMM0), reg(.XMM0), "f3 0f 12 c0");
        // MOVSS
        testOp2(m64, .MOVSS,     reg(.XMM0), reg(.XMM0), "f3 0f 10 c0");
        testOp2(m64, .MOVSS,     regRm(.XMM0), reg(.XMM0), "f3 0f 11 c0");
        // MOVUPD
        testOp2(m64, .MOVUPD,    reg(.XMM0), reg(.XMM0), "66 0f 10 c0");
        testOp2(m64, .MOVUPD,    regRm(.XMM0), reg(.XMM0), "66 0f 11 c0");
        // MOVUPS
        testOp2(m64, .MOVUPS,    reg(.XMM0), reg(.XMM0), "0f 10 c0");
        testOp2(m64, .MOVUPS,    regRm(.XMM0), reg(.XMM0), "0f 11 c0");
    }

    {
        // MPSADBW
        testOp3(m64, .MPSADBW,   reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 3a 42 c8 00");
        // MULPD
        testOp2(m64, .MULPD,     reg(.XMM1), regRm(.XMM0), "66 0f 59 c8");
        // MULPS
        testOp2(m64, .MULPS,     reg(.XMM1), regRm(.XMM0), "0f 59 c8");
        // MULSD
        testOp2(m64, .MULSD,     reg(.XMM1), regRm(.XMM0), "f2 0f 59 c8");
        // MULSS
        testOp2(m64, .MULSS,     reg(.XMM1), regRm(.XMM0), "f3 0f 59 c8");
    }

    {
        // ORPD
        testOp2(m64, .ORPD,      reg(.XMM1), regRm(.XMM0), "66 0f 56 c8");
        // ORPS
        testOp2(m64, .ORPS,      reg(.XMM1), regRm(.XMM0), "0f 56 c8");
    }

    {
        // PABSB
        testOp2(m64, .PABSB,     reg(.MM1), regRm(.MM0), "0f 38 1c c8");
        testOp2(m64, .PABSB,     reg(.XMM1), regRm(.XMM0), "66 0f 38 1c c8");
        // PABSW
        testOp2(m64, .PABSW,     reg(.MM1), regRm(.MM0), "0f 38 1d c8");
        testOp2(m64, .PABSW,     reg(.XMM1), regRm(.XMM0), "66 0f 38 1d c8");
        // PABSD
        testOp2(m64, .PABSD,     reg(.MM1), regRm(.MM0), "0f 38 1e c8");
        testOp2(m64, .PABSD,     reg(.XMM1), regRm(.XMM0), "66 0f 38 1e c8");
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
        // PABSB / PABSW /PABSD
        // PABSB
        testOp2(m64, .PABSB,     reg(.MM1), regRm(.MM0), "0f 38 1c c8");
        testOp2(m64, .PABSB,     reg(.XMM1), regRm(.XMM0), "66 0f 38 1c c8");
        // PABSW
        testOp2(m64, .PABSW,     reg(.MM1), regRm(.MM0), "0f 38 1d c8");
        testOp2(m64, .PABSW,     reg(.XMM1), regRm(.XMM0), "66 0f 38 1d c8");
        // PABSD
        testOp2(m64, .PABSD,     reg(.MM1), regRm(.MM0), "0f 38 1e c8");
        testOp2(m64, .PABSD,     reg(.XMM1), regRm(.XMM0), "66 0f 38 1e c8");
        // PACKSSWB / PACKSSDW
        testOp2(m64, .PACKSSWB,  reg(.MM1), regRm(.MM0), "0f 63 c8");
        testOp2(m64, .PACKSSWB,  reg(.XMM1), regRm(.XMM0), "66 0f 63 c8");
        //
        testOp2(m64, .PACKSSDW,  reg(.MM1), regRm(.MM0), "0f 6b c8");
        testOp2(m64, .PACKSSDW,  reg(.XMM1), regRm(.XMM0), "66 0f 6b c8");
        // PACKUSWB
        testOp2(m64, .PACKUSWB,  reg(.MM1), regRm(.MM0), "0f 67 c8");
        testOp2(m64, .PACKUSWB,  reg(.XMM1), regRm(.XMM0), "66 0f 67 c8");
        // PACKUSDW
        testOp2(m64, .PACKUSDW,  reg(.XMM1), regRm(.XMM0), "66 0f 38 2b c8");
        // PADDB / PADDW / PADDD / PADDQ
        testOp2(m64, .PADDB,     reg(.MM1), regRm(.MM0), "0f fc c8");
        testOp2(m64, .PADDB,     reg(.XMM1), regRm(.XMM0), "66 0f fc c8");
        //
        testOp2(m64, .PADDW,     reg(.MM1), regRm(.MM0), "0f fd c8");
        testOp2(m64, .PADDW,     reg(.XMM1), regRm(.XMM0), "66 0f fd c8");
        //
        testOp2(m64, .PADDD,     reg(.MM1), regRm(.MM0), "0f fe c8");
        testOp2(m64, .PADDD,     reg(.XMM1), regRm(.XMM0), "66 0f fe c8");
        //
        testOp2(m64, .PADDQ,     reg(.MM1), regRm(.MM0), "0f d4 c8");
        testOp2(m64, .PADDQ,     reg(.XMM1), regRm(.XMM0), "66 0f d4 c8");
        // PADDSB / PADDSW
        testOp2(m64, .PADDSB,    reg(.MM1), regRm(.MM0), "0f ec c8");
        testOp2(m64, .PADDSB,    reg(.XMM1), regRm(.XMM0), "66 0f ec c8");
        //
        testOp2(m64, .PADDSW,    reg(.MM1), regRm(.MM0), "0f ed c8");
        testOp2(m64, .PADDSW,    reg(.XMM1), regRm(.XMM0), "66 0f ed c8");
        // PADDUSB / PADDSW
        testOp2(m64, .PADDUSB,   reg(.MM1), regRm(.MM0), "0f dc c8");
        testOp2(m64, .PADDUSB,   reg(.XMM1), regRm(.XMM0), "66 0f dc c8");
        //
        testOp2(m64, .PADDUSW,   reg(.MM1), regRm(.MM0), "0f dd c8");
        testOp2(m64, .PADDUSW,   reg(.XMM1), regRm(.XMM0), "66 0f dd c8");
        // PALIGNR
        testOp3(m64, .PALIGNR,   reg(.MM1),regRm(.MM0),imm(0), "0f 3a 0f c8 00");
        testOp3(m64, .PALIGNR,   reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 3a 0f c8 00");
    }

    {
        // PAND
        testOp2(m64, .PAND,      reg(.MM1), regRm(.MM0), "0f db c8");
        testOp2(m64, .PAND,      reg(.XMM1), regRm(.XMM0), "66 0f db c8");
        // PANDN
        testOp2(m64, .PANDN,     reg(.MM1), regRm(.MM0), "0f df c8");
        testOp2(m64, .PANDN,     reg(.XMM1), regRm(.XMM0), "66 0f df c8");
        // PAVGB / PAVGW
        testOp2(m64, .PAVGB,     reg(.MM1), regRm(.MM0), "0f e0 c8");
        testOp2(m64, .PAVGB,     reg(.XMM1), regRm(.XMM0), "66 0f e0 c8");
        //
        testOp2(m64, .PAVGW,     reg(.MM1), regRm(.MM0), "0f e3 c8");
        testOp2(m64, .PAVGW,     reg(.XMM1), regRm(.XMM0), "66 0f e3 c8");
        // PBLENDVB
        testOp3(m64, .PBLENDVB,  reg(.XMM1),regRm(.XMM0),reg(.XMM0), "66 0f 38 10 c8");
        testOp2(m64, .PBLENDVB,  reg(.XMM1),regRm(.XMM0), "66 0f 38 10 c8");
        // PBLENDVW
        testOp3(m64, .PBLENDW,   reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 3a 0e c8 00");
        // PCLMULQDQ
        testOp3(m64, .PCLMULQDQ, reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 3a 44 c8 00");
    }

    {
        // PCMPEQB / PCMPEQW / PCMPEQD
        testOp2(m64, .PCMPEQB,   reg(.MM1), regRm(.MM0), "0f 74 c8");
        testOp2(m64, .PCMPEQB,   reg(.XMM1), regRm(.XMM0), "66 0f 74 c8");
        //
        testOp2(m64, .PCMPEQW,   reg(.MM1), regRm(.MM0), "0f 75 c8");
        testOp2(m64, .PCMPEQW,   reg(.XMM1), regRm(.XMM0), "66 0f 75 c8");
        //
        testOp2(m64, .PCMPEQD,   reg(.MM1), regRm(.MM0), "0f 76 c8");
        testOp2(m64, .PCMPEQD,   reg(.XMM1), regRm(.XMM0), "66 0f 76 c8");
        // PCMPEQQ
        testOp2(m64, .PCMPEQQ,   reg(.XMM1), regRm(.XMM0), "66 0f 38 29 c8");
        // PCMPESTRI
        testOp3(m64, .PCMPESTRI, reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 3a 61 c8 00");
        // PCMPESTRM
        testOp3(m64, .PCMPESTRM, reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 3a 60 c8 00");
        // PCMPGTB / PCMPGTW / PCMPGTD
        testOp2(m64, .PCMPGTB,   reg(.MM1), regRm(.MM0), "0f 64 c8");
        testOp2(m64, .PCMPGTB,   reg(.XMM1), regRm(.XMM0), "66 0f 64 c8");
        //
        testOp2(m64, .PCMPGTW,   reg(.MM1), regRm(.MM0), "0f 65 c8");
        testOp2(m64, .PCMPGTW,   reg(.XMM1), regRm(.XMM0), "66 0f 65 c8");
        //
        testOp2(m64, .PCMPGTD,   reg(.MM1), regRm(.MM0), "0f 66 c8");
        testOp2(m64, .PCMPGTD,   reg(.XMM1), regRm(.XMM0), "66 0f 66 c8");
        // PCMPISTRI
        testOp3(m64, .PCMPISTRI, reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 3a 63 c8 00");
        // PCMPISTRM
        testOp3(m64, .PCMPISTRM, reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 3a 62 c8 00");
        //
        testOp2(m32, .PCMPEQB,   reg(.XMM0), reg(.XMM0), "66 0f 74 c0");
        testOp2(m32, .PCMPEQW,   reg(.XMM0), reg(.XMM0), "66 0f 75 c0");
        testOp2(m32, .PCMPEQD,   reg(.XMM0), reg(.XMM0), "66 0f 76 c0");
        //
        testOp2(m32, .PCMPGTB,   reg(.XMM0), reg(.XMM0), "66 0f 64 c0");
        testOp2(m32, .PCMPGTW,   reg(.XMM0), reg(.XMM0), "66 0f 65 c0");
        testOp2(m32, .PCMPGTD,   reg(.XMM0), reg(.XMM0), "66 0f 66 c0");

    }

    {
        // PEXTRB / PEXTRD / PEXTRQ
        testOp3(m64, .PEXTRB,    rm_mem8, reg(.XMM1), imm(0), "67 66 0f 3a 14 08 00");
        testOp3(m64, .PEXTRB,    reg(.EAX), reg(.XMM1), imm(0), "66 0f 3a 14 c8 00");
        testOp3(m64, .PEXTRB,    reg(.RAX), reg(.XMM1), imm(0), "66 0f 3a 14 c8 00");
        testOp3(m64, .PEXTRD,    rm32, reg(.XMM1), imm(0), "67 66 0f 3a 16 08 00");
        testOp3(m64, .PEXTRQ,    rm64, reg(.XMM1), imm(0), "67 66 48 0f 3a 16 08 00");
        // PEXTRW
        testOp3(m64, .PEXTRW,    reg(.EAX), reg(.MM1), imm(0), "0f c5 c1 00");
        testOp3(m64, .PEXTRW,    reg(.RAX), reg(.MM1), imm(0), "0f c5 c1 00");
        testOp3(m64, .PEXTRW,    reg(.EAX), reg(.XMM1), imm(0), "66 0f c5 c1 00");
        testOp3(m64, .PEXTRW,    reg(.RAX), reg(.XMM1), imm(0), "66 0f c5 c1 00");
        testOp3(m64, .PEXTRW,    rm_mem16, reg(.XMM1), imm(0), "67 66 0f 3a 15 08 00");
        testOp3(m64, .PEXTRW,    regRm(.EAX), reg(.XMM1), imm(0), "66 0f 3a 15 c8 00");
        testOp3(m64, .PEXTRW,    regRm(.RAX), reg(.XMM1), imm(0), "66 0f 3a 15 c8 00");
        testOp3(m64, .PEXTRW,    reg(.EAX), reg(.XMM1), imm(0), "66 0f c5 c1 00");
        testOp3(m64, .PEXTRW,    reg(.RAX), reg(.XMM1), imm(0), "66 0f c5 c1 00");
        //
        testOp3(m32, .PEXTRB,   reg(.EAX), reg(.XMM0), imm(0), "66 0f 3a 14 c0 00");
        testOp3(m32, .PEXTRB,   reg(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);
        //
        testOp3(m32, .PEXTRW,   reg(.EAX), reg(.XMM0), imm(0), "66 0f c5 c0 00");
        testOp3(m32, .PEXTRW,   reg(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);
        //
        testOp3(m32, .PEXTRW,   regRm(.EAX), reg(.XMM0), imm(0), "66 0f 3A 15 c0 00");
        testOp3(m32, .PEXTRW,   regRm(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);
        //
        testOp3(m32, .PEXTRD,   reg(.EAX), reg(.XMM0), imm(0), "66 0f 3a 16 c0 00");
        testOp3(m32, .PEXTRQ,   reg(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);
    }

    {
        // PHADDW / PHAD DD
        testOp2(m64, .PHADDW,    reg(.MM1), regRm(.MM0), "0f 38 01 c8");
        testOp2(m64, .PHADDW,    reg(.XMM1), regRm(.XMM0), "66 0f 38 01 c8");
        testOp2(m64, .PHADDD,    reg(.MM1), regRm(.MM0), "0f 38 02 c8");
        testOp2(m64, .PHADDD,    reg(.XMM1), regRm(.XMM0), "66 0f 38 02 c8");
        // PHADDSW
        testOp2(m64, .PHADDSW,   reg(.MM1), regRm(.MM0), "0f 38 03 c8");
        testOp2(m64, .PHADDSW,   reg(.XMM1), regRm(.XMM0), "66 0f 38 03 c8");
        // PHMINPOSUW
        testOp2(m64, .PHMINPOSUW,reg(.XMM1), regRm(.XMM0), "66 0f 38 41 c8");
        // PHSUBW / PHSUBD
        testOp2(m64, .PHSUBW,    reg(.MM1), regRm(.MM0), "0f 38 05 c8");
        testOp2(m64, .PHSUBW,    reg(.XMM1), regRm(.XMM0), "66 0f 38 05 c8");
        testOp2(m64, .PHSUBD,    reg(.MM1), regRm(.MM0), "0f 38 06 c8");
        testOp2(m64, .PHSUBD,    reg(.XMM1), regRm(.XMM0), "66 0f 38 06 c8");
        // PHSUBSW
        testOp2(m64, .PHSUBSW,   reg(.MM1), regRm(.MM0), "0f 38 07 c8");
        testOp2(m64, .PHSUBSW,   reg(.XMM1), regRm(.XMM0), "66 0f 38 07 c8");
        // PINSRB / PINSRD / PINSRQ
        testOp3(m64, .PINSRB,    reg(.XMM1), rm_mem8, imm(0), "67 66 0f 3a 20 08 00");
        testOp3(m64, .PINSRB,    reg(.XMM1), regRm(.EAX), imm(0), "66 0f 3a 20 c8 00");
        //
        testOp3(m64, .PINSRD,    reg(.XMM1), rm32, imm(0), "67 66 0f 3a 22 08 00");
        //
        testOp3(m64, .PINSRQ,    reg(.XMM1), rm64, imm(0), "67 66 48 0f 3a 22 08 00");
        testOp3(m32, .PINSRQ,    reg(.XMM1), rm64, imm(0), AsmError.InvalidOperand);
        // PINSRW
        testOp3(m64, .PINSRW,    reg(.MM1), rm_mem16, imm(0), "67 0f c4 08 00");
        testOp3(m64, .PINSRW,    reg(.MM1), regRm(.EAX), imm(0), "0f c4 c8 00");
        testOp3(m64, .PINSRW,    reg(.XMM1), rm_mem16, imm(0), "67 66 0f c4 08 00");
        testOp3(m64, .PINSRW,    reg(.XMM1), regRm(.EAX), imm(0), "66 0f c4 c8 00");
    }

    {
        // PMADDUBSW
        testOp2(m64, .PMADDUBSW, reg(.MM1), regRm(.MM0), "0f 38 04 c8");
        testOp2(m64, .PMADDUBSW, reg(.XMM1), regRm(.XMM0), "66 0f 38 04 c8");
        // PMADDWD
        testOp2(m64, .PMADDWD,   reg(.MM1), regRm(.MM0), "0f f5 c8");
        testOp2(m64, .PMADDWD,   reg(.XMM1), regRm(.XMM0), "66 0f f5 c8");
        // PMAXSB / PMAXSW / PMAXSD
        testOp2(m64, .PMAXSW,    reg(.MM1), regRm(.MM0), "0f ee c8");
        testOp2(m64, .PMAXSW,    reg(.XMM1), regRm(.XMM0), "66 0f ee c8");
        testOp2(m64, .PMAXSB,    reg(.XMM1), regRm(.XMM0), "66 0f 38 3c c8");
        testOp2(m64, .PMAXSD,    reg(.XMM1), regRm(.XMM0), "66 0f 38 3d c8");
        // PMAXUB / PMAXUW
        testOp2(m64, .PMAXUB,    reg(.MM1), regRm(.MM0), "0f de c8");
        testOp2(m64, .PMAXUB,    reg(.XMM1), regRm(.XMM0), "66 0f de c8");
        testOp2(m64, .PMAXUW,    reg(.XMM1), regRm(.XMM0), "66 0f 38 3e c8");
        // PMAXUD
        testOp2(m64, .PMAXUD,    reg(.XMM1), regRm(.XMM0), "66 0f 38 3f c8");
        // PMINSB / PMINSW
        testOp2(m64, .PMINSW,    reg(.MM1), regRm(.MM0), "0f ea c8");
        testOp2(m64, .PMINSW,    reg(.XMM1), regRm(.XMM0), "66 0f ea c8");
        testOp2(m64, .PMINSB,    reg(.XMM1), regRm(.XMM0), "66 0f 38 38 c8");
        // PMINSD
        testOp2(m64, .PMINSD,    reg(.XMM1), regRm(.XMM0), "66 0f 38 39 c8");
        // PMINUB / PMINUW
        testOp2(m64, .PMINUB,    reg(.MM1), regRm(.MM0), "0f da c8");
        testOp2(m64, .PMINUB,    reg(.XMM1), regRm(.XMM0), "66 0f da c8");
        testOp2(m64, .PMINUW,    reg(.XMM1), regRm(.XMM0), "66 0f 38 3a c8");
        // PMINUD
        testOp2(m64, .PMINUD,    reg(.XMM1), regRm(.XMM0), "66 0f 38 3b c8");

        {
            testOp2(m32, .PMADDWD,   reg(.XMM0), reg(.XMM0), "66 0f f5 c0");
        }

    }

    {
        // PMOVMSKB
        testOp2(m64, .PMOVMSKB,  reg(.EAX), regRm(.MM0), "0f d7 c0");
        testOp2(m64, .PMOVMSKB,  reg(.RAX), regRm(.MM0), "0f d7 c0");
        testOp2(m64, .PMOVMSKB,  reg(.EAX), regRm(.XMM0), "66 0f d7 c0");
        testOp2(m64, .PMOVMSKB,  reg(.RAX), regRm(.XMM0), "66 0f d7 c0");
        // PMOVSX
        testOp2(m64, .PMOVSXBW,  reg(.XMM1), regRm(.XMM0), "66 0f 38 20 c8");
        testOp2(m64, .PMOVSXBD,  reg(.XMM1), regRm(.XMM0), "66 0f 38 21 c8");
        testOp2(m64, .PMOVSXBQ,  reg(.XMM1), regRm(.XMM0), "66 0f 38 22 c8");
        //
        testOp2(m64, .PMOVSXWD,  reg(.XMM1), regRm(.XMM0), "66 0f 38 23 c8");
        testOp2(m64, .PMOVSXWQ,  reg(.XMM1), regRm(.XMM0), "66 0f 38 24 c8");
        testOp2(m64, .PMOVSXDQ,  reg(.XMM1), regRm(.XMM0), "66 0f 38 25 c8");
        // PMOVZX
        testOp2(m64, .PMOVZXBW,  reg(.XMM1), regRm(.XMM0), "66 0f 38 30 c8");
        testOp2(m64, .PMOVZXBD,  reg(.XMM1), regRm(.XMM0), "66 0f 38 31 c8");
        testOp2(m64, .PMOVZXBQ,  reg(.XMM1), regRm(.XMM0), "66 0f 38 32 c8");
        //
        testOp2(m64, .PMOVZXWD,  reg(.XMM1), regRm(.XMM0), "66 0f 38 33 c8");
        testOp2(m64, .PMOVZXWQ,  reg(.XMM1), regRm(.XMM0), "66 0f 38 34 c8");
        testOp2(m64, .PMOVZXDQ,  reg(.XMM1), regRm(.XMM0), "66 0f 38 35 c8");
    }

    {
        // PMULDQ
        testOp2(m64, .PMULDQ,    reg(.XMM1), regRm(.XMM0), "66 0f 38 28 c8");
        // PMULHRSW
        testOp2(m64, .PMULHRSW,  reg(.MM1), regRm(.MM0), "0f 38 0b c8");
        testOp2(m64, .PMULHRSW,  reg(.XMM1), regRm(.XMM0), "66 0f 38 0b c8");
        // PMULHUW
        testOp2(m64, .PMULHUW,   reg(.MM1), regRm(.MM0), "0f e4 c8");
        testOp2(m64, .PMULHUW,   reg(.XMM1), regRm(.XMM0), "66 0f e4 c8");
        // PMULHW
        testOp2(m64, .PMULHW,    reg(.MM1), regRm(.MM0), "0f e5 c8");
        testOp2(m64, .PMULHW,    reg(.XMM1), regRm(.XMM0), "66 0f e5 c8");
        // PMULLD
        testOp2(m64, .PMULLD,    reg(.XMM1), regRm(.XMM0), "66 0f 38 40 c8");
        // PMULLW
        testOp2(m64, .PMULLW,    reg(.MM1), regRm(.MM0), "0f d5 c8");
        testOp2(m64, .PMULLW,    reg(.XMM1), regRm(.XMM0), "66 0f d5 c8");
        // PMULUDQ
        testOp2(m64, .PMULUDQ,   reg(.MM1), regRm(.MM0), "0f f4 c8");
        testOp2(m64, .PMULUDQ,   reg(.XMM1), regRm(.XMM0), "66 0f f4 c8");
        // POR
        testOp2(m64, .POR,       reg(.MM1), regRm(.MM0), "0f eb c8");
        testOp2(m64, .POR,       reg(.XMM1), regRm(.XMM0), "66 0f eb c8");
        testOp2(m32, .POR,       reg(.XMM0), reg(.XMM0), "66 0f eb c0");
        // PSADBW
        testOp2(m64, .PSADBW,    reg(.MM1), regRm(.MM0), "0f f6 c8");
        testOp2(m64, .PSADBW,    reg(.XMM1), regRm(.XMM0), "66 0f f6 c8");
        // PSHUFB
        testOp2(m64, .PSHUFB,    reg(.MM1), regRm(.MM0), "0f 38 00 c8");
        testOp2(m64, .PSHUFB,    reg(.XMM1), regRm(.XMM0), "66 0f 38 00 c8");
        // PSHUFD
        testOp3(m64, .PSHUFD,    reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 70 c8 00");
        // PSHUFHW
        testOp3(m64, .PSHUFHW,   reg(.XMM1),regRm(.XMM0),imm(0), "f3 0f 70 c8 00");
        // PSHUFLW
        testOp3(m64, .PSHUFLW,   reg(.XMM1),regRm(.XMM0),imm(0), "f2 0f 70 c8 00");
        // PSHUFW
        testOp3(m64, .PSHUFW,    reg(.MM1), regRm(.MM0), imm(0), "0f 70 c8 00");
        // PSIGNB / PSIGNW / PSIGND
        testOp2(m64, .PSIGNB,    reg(.MM1), regRm(.MM0), "0f 38 08 c8");
        testOp2(m64, .PSIGNB,    reg(.XMM1), regRm(.XMM0), "66 0f 38 08 c8");
        //
        testOp2(m64, .PSIGNW,    reg(.MM1), regRm(.MM0), "0f 38 09 c8");
        testOp2(m64, .PSIGNW,    reg(.XMM1), regRm(.XMM0), "66 0f 38 09 c8");
        //
        testOp2(m64, .PSIGND,    reg(.MM1), regRm(.MM0), "0f 38 0a c8");
        testOp2(m64, .PSIGND,    reg(.XMM1), regRm(.XMM0), "66 0f 38 0a c8");
        {
            testOp2(m32, .PMULHW,    reg(.XMM0), reg(.XMM0), "66 0f e5 c0");
            testOp2(m32, .PMULLW,    reg(.XMM0), reg(.XMM0), "66 0f d5 c0");
        }
    }

    {
        // PSLLDQ
        testOp2(m64, .PSLLDQ,    regRm(.XMM0), imm(0), "66 0f 73 f8 00");
        // PSLLW / PSLLD / PSLLQ
        // PSLLW
        testOp2(m64, .PSLLW,     reg(.MM1), regRm(.MM0), "0f f1 c8");
        testOp2(m64, .PSLLW,     reg(.XMM1), regRm(.XMM0), "66 0f f1 c8");
        //
        testOp2(m64, .PSLLW,     regRm(.MM0), imm(0), "0f 71 f0 00");
        testOp2(m64, .PSLLW,     regRm(.XMM0), imm(0), "66 0f 71 f0 00");
        // PSLLD
        testOp2(m64, .PSLLD,     reg(.MM1), regRm(.MM0), "0f f2 c8");
        testOp2(m64, .PSLLD,     reg(.XMM1), regRm(.XMM0), "66 0f f2 c8");
        //
        testOp2(m64, .PSLLD,     regRm(.MM0), imm(0), "0f 72 f0 00");
        testOp2(m64, .PSLLD,     regRm(.XMM0), imm(0), "66 0f 72 f0 00");
        // PSLLQ
        testOp2(m64, .PSLLQ,     reg(.MM1), regRm(.MM0), "0f f3 c8");
        testOp2(m64, .PSLLQ,     reg(.XMM1), regRm(.XMM0), "66 0f f3 c8");
        //
        testOp2(m64, .PSLLQ,     regRm(.MM0), imm(0), "0f 73 f0 00");
        testOp2(m64, .PSLLQ,     regRm(.XMM0), imm(0), "66 0f 73 f0 00");
        // PSRAW / PSRAD
        // PSRAW
        testOp2(m64, .PSRAW,     reg(.MM1), regRm(.MM0), "0f e1 c8");
        testOp2(m64, .PSRAW,     reg(.XMM1), regRm(.XMM0), "66 0f e1 c8");
        //
        testOp2(m64, .PSRAW,     reg(.MM1), imm(0), "0f 71 e1 00");
        testOp2(m64, .PSRAW,     reg(.XMM1), imm(0), "66 0f 71 e1 00");
        // PSRAD
        testOp2(m64, .PSRAD,     reg(.MM1), regRm(.MM0), "0f e2 c8");
        testOp2(m64, .PSRAD,     reg(.XMM1), regRm(.XMM0), "66 0f e2 c8");
        //
        testOp2(m64, .PSRAD,     reg(.MM1), imm(0), "0f 72 e1 00");
        testOp2(m64, .PSRAD,     reg(.XMM1), imm(0), "66 0f 72 e1 00");
        // PSRLDQ
        testOp2(m64, .PSRLDQ,    regRm(.XMM0), imm(0), "66 0f 73 d8 00");
        // PSRLW / PSRLD / PSRLQ
        // PSRLW
        testOp2(m64, .PSRLW,     reg(.MM1), regRm(.MM0), "0f d1 c8");
        testOp2(m64, .PSRLW,     reg(.XMM1), regRm(.XMM0), "66 0f d1 c8");
        //
        testOp2(m64, .PSRLW,     reg(.MM1), imm(0), "0f 71 d1 00");
        testOp2(m64, .PSRLW,     reg(.XMM1), imm(0), "66 0f 71 d1 00");
        // PSRLD
        testOp2(m64, .PSRLD,     reg(.MM1), regRm(.MM0), "0f d2 c8");
        testOp2(m64, .PSRLD,     reg(.XMM1), regRm(.XMM0), "66 0f d2 c8");
        //
        testOp2(m64, .PSRLD,     reg(.MM1), imm(0), "0f 72 d1 00");
        testOp2(m64, .PSRLD,     reg(.XMM1), imm(0), "66 0f 72 d1 00");
        // PSRLQ
        testOp2(m64, .PSRLQ,     reg(.MM1), regRm(.MM0), "0f d3 c8");
        testOp2(m64, .PSRLQ,     reg(.XMM1), regRm(.XMM0), "66 0f d3 c8");
        //
        testOp2(m64, .PSRLQ,     reg(.MM1), imm(0), "0f 73 d1 00");
        testOp2(m64, .PSRLQ,     reg(.XMM1), imm(0), "66 0f 73 d1 00");
        {
            testOp2(m32, .PSLLW,     reg(.XMM0), reg(.XMM0), "66 0f f1 c0");
            testOp2(m32, .PSLLW,     reg(.XMM0), imm(0),     "66 0f 71 f0 00");
            testOp2(m32, .PSLLD,     reg(.XMM0), reg(.XMM0), "66 0f f2 c0");
            testOp2(m32, .PSLLD,     reg(.XMM0), imm(0),     "66 0f 72 f0 00");
            testOp2(m32, .PSLLQ,     reg(.XMM0), reg(.XMM0), "66 0f f3 c0");
            testOp2(m32, .PSLLQ,     reg(.XMM0), imm(0),     "66 0f 73 f0 00");
            //
            testOp2(m32, .PSRAW,     reg(.XMM0), reg(.XMM0), "66 0f e1 c0");
            testOp2(m32, .PSRAW,     reg(.XMM0), imm(0),     "66 0f 71 e0 00");
            testOp2(m32, .PSRAD,     reg(.XMM0), reg(.XMM0), "66 0f e2 c0");
            testOp2(m32, .PSRAD,     reg(.XMM0), imm(0),     "66 0f 72 e0 00");
            //
            testOp2(m32, .PSRLW,     reg(.XMM0), reg(.XMM0), "66 0f d1 c0");
            testOp2(m32, .PSRLW,     reg(.XMM0), imm(0),     "66 0f 71 d0 00");
            testOp2(m32, .PSRLD,     reg(.XMM0), reg(.XMM0), "66 0f d2 c0");
            testOp2(m32, .PSRLD,     reg(.XMM0), imm(0),     "66 0f 72 d0 00");
            testOp2(m32, .PSRLQ,     reg(.XMM0), reg(.XMM0), "66 0f d3 c0");
            testOp2(m32, .PSRLQ,     reg(.XMM0), imm(0),     "66 0f 73 d0 00");
        }
    }

    {
        // PSUBB / PSUBW / PSUBD
        // PSUBB
        testOp2(m64, .PSUBB,     reg(.MM1), regRm(.MM0), "0f f8 c8");
        testOp2(m64, .PSUBB,     reg(.XMM1), regRm(.XMM0), "66 0f f8 c8");
        // PSUBW
        testOp2(m64, .PSUBW,     reg(.MM1), regRm(.MM0), "0f f9 c8");
        testOp2(m64, .PSUBW,     reg(.XMM1), regRm(.XMM0), "66 0f f9 c8");
        // PSUBD
        testOp2(m64, .PSUBD,     reg(.MM1), regRm(.MM0), "0f fa c8");
        testOp2(m64, .PSUBD,     reg(.XMM1), regRm(.XMM0), "66 0f fa c8");
        // PSUBQ
        testOp2(m64, .PSUBQ,     reg(.MM1), regRm(.MM0), "0f fb c8");
        testOp2(m64, .PSUBQ,     reg(.XMM1), regRm(.XMM0), "66 0f fb c8");
        // PSUBSB / PSUBSW
        // PSUBSB
        testOp2(m64, .PSUBSB,    reg(.MM1), regRm(.MM0), "0f e8 c8");
        testOp2(m64, .PSUBSB,    reg(.XMM1), regRm(.XMM0), "66 0f e8 c8");
        // PSUBSW
        testOp2(m64, .PSUBSW,    reg(.MM1), regRm(.MM0), "0f e9 c8");
        testOp2(m64, .PSUBSW,    reg(.XMM1), regRm(.XMM0), "66 0f e9 c8");
        // PSUBUSB / PSUBUSW
        // PSUBUSB
        testOp2(m64, .PSUBUSB,   reg(.MM1), regRm(.MM0), "0f d8 c8");
        testOp2(m64, .PSUBUSB,   reg(.XMM1), regRm(.XMM0), "66 0f d8 c8");
        // PSUBUSW
        testOp2(m64, .PSUBUSW,   reg(.MM1), regRm(.MM0), "0f d9 c8");
        testOp2(m64, .PSUBUSW,   reg(.XMM1), regRm(.XMM0), "66 0f d9 c8");
        // PTEST
        testOp2(m64, .PTEST,     reg(.XMM1), regRm(.XMM0), "66 0f 38 17 c8");
        // PUNPCKHBW / PUNPCKHWD / PUNPCKHDQ / PUNPCKHQDQ
        testOp2(m64, .PUNPCKHBW, reg(.MM1), regRm(.MM0), "0f 68 c8");
        testOp2(m64, .PUNPCKHBW, reg(.XMM1), regRm(.XMM0), "66 0f 68 c8");
        //
        testOp2(m64, .PUNPCKHWD, reg(.MM1), regRm(.MM0), "0f 69 c8");
        testOp2(m64, .PUNPCKHWD, reg(.XMM1), regRm(.XMM0), "66 0f 69 c8");
        //
        testOp2(m64, .PUNPCKHDQ, reg(.MM1), regRm(.MM0), "0f 6a c8");
        testOp2(m64, .PUNPCKHDQ, reg(.XMM1), regRm(.XMM0), "66 0f 6a c8");
        //
        testOp2(m64, .PUNPCKHQDQ,reg(.XMM1), regRm(.XMM0), "66 0f 6d c8");
        // PUNPCKLBW / PUNPCKLWD / PUNPCKLDQ / PUNPCKLQDQ
        testOp2(m64, .PUNPCKLBW, reg(.MM1), regRm(.MM0), "0f 60 c8");
        testOp2(m64, .PUNPCKLBW, reg(.XMM1), regRm(.XMM0), "66 0f 60 c8");
        //
        testOp2(m64, .PUNPCKLWD, reg(.MM1), regRm(.MM0), "0f 61 c8");
        testOp2(m64, .PUNPCKLWD, reg(.XMM1), regRm(.XMM0), "66 0f 61 c8");
        //
        testOp2(m64, .PUNPCKLDQ, reg(.MM1), regRm(.MM0), "0f 62 c8");
        testOp2(m64, .PUNPCKLDQ, reg(.XMM1), regRm(.XMM0), "66 0f 62 c8");
        //
        testOp2(m64, .PUNPCKLQDQ,reg(.XMM1), regRm(.XMM0), "66 0f 6c c8");
        {
            testOp2(m32, .PSUBB,     reg(.XMM0), reg(.XMM0), "66 0f f8 c0");
            testOp2(m32, .PSUBW,     reg(.XMM0), reg(.XMM0), "66 0f f9 c0");
            testOp2(m32, .PSUBD,     reg(.XMM0), reg(.XMM0), "66 0f fa c0");
            //
            testOp2(m32, .PSUBUSB,   reg(.XMM0), reg(.XMM0), "66 0f d8 c0");
            testOp2(m32, .PSUBUSW,   reg(.XMM0), reg(.XMM0), "66 0f d9 c0");
            //
            testOp2(m32, .PUNPCKHBW, reg(.XMM0), reg(.XMM0), "66 0f 68 c0");
            testOp2(m32, .PUNPCKHWD, reg(.XMM0), reg(.XMM0), "66 0f 69 c0");
            testOp2(m32, .PUNPCKHDQ, reg(.XMM0), reg(.XMM0), "66 0f 6a c0");
            testOp2(m32, .PUNPCKHQDQ,reg(.XMM0), reg(.XMM0), "66 0f 6d c0");
            //
            testOp2(m32, .PUNPCKLBW, reg(.XMM0), reg(.XMM0), "66 0f 60 c0");
            testOp2(m32, .PUNPCKLWD, reg(.XMM0), reg(.XMM0), "66 0f 61 c0");
            testOp2(m32, .PUNPCKLDQ, reg(.XMM0), reg(.XMM0), "66 0f 62 c0");
            testOp2(m32, .PUNPCKLQDQ,reg(.XMM0), reg(.XMM0), "66 0f 6c c0");
        }
    }

    {
        // PXOR
        testOp2(m64, .PXOR,      reg(.MM1), regRm(.MM0), "0f ef c8");
        testOp2(m64, .PXOR,      reg(.XMM1), regRm(.XMM0), "66 0f ef c8");
        testOp2(m32, .PXOR,      reg(.XMM0), reg(.XMM0), "66 0f ef c0");
        // RCPPS
        testOp2(m64, .RCPPS,     reg(.XMM1), regRm(.XMM0), "0f 53 c8");
        // RCPSS
        testOp2(m64, .RCPSS,     reg(.XMM1), regRm(.XMM0), "f3 0f 53 c8");
        // ROUNDPD
        testOp3(m64, .ROUNDPD,   reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 3a 09 c8 00");
        // ROUNDPS
        testOp3(m64, .ROUNDPS,   reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 3a 08 c8 00");
        // ROUNDSD
        testOp3(m64, .ROUNDSD,   reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 3a 0b c8 00");
        // ROUNDSS
        testOp3(m64, .ROUNDSS,   reg(.XMM1),regRm(.XMM0),imm(0), "66 0f 3a 0a c8 00");
        // RSQRTPS
        testOp2(m64, .RSQRTPS,   reg(.XMM1), regRm(.XMM0), "0f 52 c8");
        // RSQRTSS
        testOp2(m64, .RSQRTSS,   reg(.XMM1), regRm(.XMM0), "f3 0f 52 c8");
        // SHUFPD
        testOp3(m64, .SHUFPD,    reg(.XMM1),regRm(.XMM0),imm(0), "66 0f c6 c8 00");
        // SHUFPS
        testOp3(m64, .SHUFPS,    reg(.XMM1),regRm(.XMM0),imm(0), "0f c6 c8 00");
        // SQRTPD
        testOp2(m64, .SQRTPD,    reg(.XMM1), regRm(.XMM0), "66 0f 51 c8");
        // SQRTPS
        testOp2(m64, .SQRTPS,    reg(.XMM1), regRm(.XMM0), "0f 51 c8");
        // SQRTSD
        testOp2(m64, .SQRTSD,    reg(.XMM1), regRm(.XMM0), "f2 0f 51 c8");
        // SQRTSS
        testOp2(m64, .SQRTSS,    reg(.XMM1), regRm(.XMM0), "f3 0f 51 c8");
        // SUBPD
        testOp2(m64, .SUBPD,     reg(.XMM1), regRm(.XMM0), "66 0f 5c c8");
        // SUBPS
        testOp2(m64, .SUBPS,     reg(.XMM1), regRm(.XMM0), "0f 5c c8");
        // SUBSD
        testOp2(m64, .SUBSD,     reg(.XMM1), regRm(.XMM0), "f2 0f 5c c8");
        // SUBSS
        testOp2(m64, .SUBSS,     reg(.XMM1), regRm(.XMM0), "f3 0f 5c c8");
        // UCOMISD
        testOp2(m64, .UCOMISD,   reg(.XMM1), regRm(.XMM0), "66 0f 2e c8");
        // UCOMISS
        testOp2(m64, .UCOMISS,   reg(.XMM1), regRm(.XMM0), "0f 2e c8");
        // UNPCKHPD
        testOp2(m64, .UNPCKHPD,  reg(.XMM1), regRm(.XMM0), "66 0f 15 c8");
        // UNPCKHPS
        testOp2(m64, .UNPCKHPS,  reg(.XMM1), regRm(.XMM0), "0f 15 c8");
        // UNPCKLPD
        testOp2(m64, .UNPCKLPD,  reg(.XMM1), regRm(.XMM0), "66 0f 14 c8");
        // UNPCKLPS
        testOp2(m64, .UNPCKLPS,  reg(.XMM1), regRm(.XMM0), "0f 14 c8");
        // XORPD
        testOp2(m64, .XORPD,     reg(.XMM1), regRm(.XMM0), "66 0f 57 c8");
        // XORPS
        testOp2(m64, .XORPS,     reg(.XMM1), regRm(.XMM0), "0f 57 c8");
    }

    {
        // EXTRQ
        testOp3(m64, .EXTRQ,     regRm(.XMM7), imm(0), imm(0x11), "66 0f 78 c7 00 11");
        testOp2(m64, .EXTRQ,     reg(.XMM1), regRm(.XMM7), "66 0f 79 cf");
        // INSERTQ
        testOp4(m64, .INSERTQ,   reg(.XMM1),regRm(.XMM7),imm(0),imm(0x11), "f2 0f 78 cf 00 11");
        testOp2(m64, .INSERTQ,   reg(.XMM1), regRm(.XMM7), "f2 0f 79 cf");
    }

    {
        // MOVNTSD
        testOp2(m64, .MOVNTSD,   rm_mem64, reg(.XMM1), "67 f2 0f 2b 08");
        // MOVNTSS
        testOp2(m64, .MOVNTSS,   rm_mem32, reg(.XMM1), "67 f3 0f 2b 08");
    }
}
