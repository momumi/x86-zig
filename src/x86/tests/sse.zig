const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "SSE" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    const reg = Operand.register;
    const regRm = Operand.registerRm;
    const imm = Operand.immediate;

    debugPrint(false);

    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const mem_64 = rm64;
    const mem_128 = Operand.memoryRm(.DefaultSeg, .OWORD, .EAX, 0);

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
