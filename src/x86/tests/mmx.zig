const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "MMX" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    const reg = Operand.register;
    const imm = Operand.immediate;

    debugPrint(false);

    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const mem_64 = rm64;

    {
        testOp0(m32, .EMMS, "0F 77");
        testOp0(m64, .EMMS, "0F 77");
    }

    {
        {
            testOp2(m32, .MOVD, reg(.MM0), rm32, "0F 6E 00");
            testOp2(m32, .MOVD, reg(.MM1), rm32, "0F 6E 08");
            testOp2(m32, .MOVD, reg(.MM2), rm32, "0F 6E 10");
            testOp2(m32, .MOVD, reg(.MM3), rm32, "0F 6E 18");
            testOp2(m32, .MOVD, reg(.MM4), rm32, "0F 6E 20");
            testOp2(m32, .MOVD, reg(.MM5), rm32, "0F 6E 28");
            testOp2(m32, .MOVD, reg(.MM6), rm32, "0F 6E 30");
            testOp2(m32, .MOVD, reg(.MM7), rm32, "0F 6E 38");
            //
            testOp2(m64, .MOVD, reg(.MM0), rm32, "67 0F 6E 00");
            testOp2(m64, .MOVD, reg(.MM1), rm32, "67 0F 6E 08");
            testOp2(m64, .MOVD, reg(.MM2), rm32, "67 0F 6E 10");
            testOp2(m64, .MOVD, reg(.MM3), rm32, "67 0F 6E 18");
            testOp2(m64, .MOVD, reg(.MM4), rm32, "67 0F 6E 20");
            testOp2(m64, .MOVD, reg(.MM5), rm32, "67 0F 6E 28");
            testOp2(m64, .MOVD, reg(.MM6), rm32, "67 0F 6E 30");
            testOp2(m64, .MOVD, reg(.MM7), rm32, "67 0F 6E 38");
        }

        {
            testOp2(m32, .MOVD, reg(.MM0), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM1), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM2), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM3), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM4), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM5), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM6), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM7), rm64, AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVD, reg(.MM0), rm64, "67 48 0F 6E 00");
            testOp2(m64, .MOVD, reg(.MM1), rm64, "67 48 0F 6E 08");
            testOp2(m64, .MOVD, reg(.MM2), rm64, "67 48 0F 6E 10");
            testOp2(m64, .MOVD, reg(.MM3), rm64, "67 48 0F 6E 18");
            testOp2(m64, .MOVD, reg(.MM4), rm64, "67 48 0F 6E 20");
            testOp2(m64, .MOVD, reg(.MM5), rm64, "67 48 0F 6E 28");
            testOp2(m64, .MOVD, reg(.MM6), rm64, "67 48 0F 6E 30");
            testOp2(m64, .MOVD, reg(.MM7), rm64, "67 48 0F 6E 38");
        }

        {
            testOp2(m32, .MOVQ, reg(.MM0), reg(.RAX), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM1), reg(.RAX), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM2), reg(.RAX), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM3), reg(.RAX), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM4), reg(.RAX), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM5), reg(.RAX), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM6), reg(.RAX), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM7), reg(.RAX), AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVQ, reg(.MM0), reg(.RAX), "48 0F 6E C0");
            testOp2(m64, .MOVQ, reg(.MM1), reg(.RAX), "48 0F 6E C8");
            testOp2(m64, .MOVQ, reg(.MM2), reg(.RAX), "48 0F 6E D0");
            testOp2(m64, .MOVQ, reg(.MM3), reg(.RAX), "48 0F 6E D8");
            testOp2(m64, .MOVQ, reg(.MM4), reg(.RAX), "48 0F 6E E0");
            testOp2(m64, .MOVQ, reg(.MM5), reg(.RAX), "48 0F 6E E8");
            testOp2(m64, .MOVQ, reg(.MM6), reg(.RAX), "48 0F 6E F0");
            testOp2(m64, .MOVQ, reg(.MM7), reg(.RAX), "48 0F 6E F8");
        }

        {
            testOp2(m32, .MOVQ, reg(.RAX), reg(.MM0), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.RAX), reg(.MM1), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.RAX), reg(.MM2), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.RAX), reg(.MM3), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.RAX), reg(.MM4), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.RAX), reg(.MM5), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.RAX), reg(.MM6), AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.RAX), reg(.MM7), AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVQ, reg(.RAX), reg(.MM0), "48 0F 7E C0");
            testOp2(m64, .MOVQ, reg(.RAX), reg(.MM1), "48 0F 7E C8");
            testOp2(m64, .MOVQ, reg(.RAX), reg(.MM2), "48 0F 7E D0");
            testOp2(m64, .MOVQ, reg(.RAX), reg(.MM3), "48 0F 7E D8");
            testOp2(m64, .MOVQ, reg(.RAX), reg(.MM4), "48 0F 7E E0");
            testOp2(m64, .MOVQ, reg(.RAX), reg(.MM5), "48 0F 7E E8");
            testOp2(m64, .MOVQ, reg(.RAX), reg(.MM6), "48 0F 7E F0");
            testOp2(m64, .MOVQ, reg(.RAX), reg(.MM7), "48 0F 7E F8");
        }

        {
            testOp2(m32, .MOVQ, reg(.MM0), mem_64, "0F 6F 00");
            testOp2(m32, .MOVQ, reg(.MM1), mem_64, "0F 6F 08");
            testOp2(m32, .MOVQ, reg(.MM2), mem_64, "0F 6F 10");
            testOp2(m32, .MOVQ, reg(.MM3), mem_64, "0F 6F 18");
            testOp2(m32, .MOVQ, reg(.MM4), mem_64, "0F 6F 20");
            testOp2(m32, .MOVQ, reg(.MM5), mem_64, "0F 6F 28");
            testOp2(m32, .MOVQ, reg(.MM6), mem_64, "0F 6F 30");
            testOp2(m32, .MOVQ, reg(.MM7), mem_64, "0F 6F 38");
            //
            testOp2(m64, .MOVQ, reg(.MM0), mem_64, "67 0F 6F 00");
            testOp2(m64, .MOVQ, reg(.MM1), mem_64, "67 0F 6F 08");
            testOp2(m64, .MOVQ, reg(.MM2), mem_64, "67 0F 6F 10");
            testOp2(m64, .MOVQ, reg(.MM3), mem_64, "67 0F 6F 18");
            testOp2(m64, .MOVQ, reg(.MM4), mem_64, "67 0F 6F 20");
            testOp2(m64, .MOVQ, reg(.MM5), mem_64, "67 0F 6F 28");
            testOp2(m64, .MOVQ, reg(.MM6), mem_64, "67 0F 6F 30");
            testOp2(m64, .MOVQ, reg(.MM7), mem_64, "67 0F 6F 38");
        }

        {
            testOp2(m32, .MOVQ, mem_64, reg(.MM0), "0F 7F 00");
            testOp2(m32, .MOVQ, mem_64, reg(.MM1), "0F 7F 08");
            testOp2(m32, .MOVQ, mem_64, reg(.MM2), "0F 7F 10");
            testOp2(m32, .MOVQ, mem_64, reg(.MM3), "0F 7F 18");
            testOp2(m32, .MOVQ, mem_64, reg(.MM4), "0F 7F 20");
            testOp2(m32, .MOVQ, mem_64, reg(.MM5), "0F 7F 28");
            testOp2(m32, .MOVQ, mem_64, reg(.MM6), "0F 7F 30");
            testOp2(m32, .MOVQ, mem_64, reg(.MM7), "0F 7F 38");
            //
            testOp2(m64, .MOVQ, mem_64, reg(.MM0), "67 0F 7F 00");
            testOp2(m64, .MOVQ, mem_64, reg(.MM1), "67 0F 7F 08");
            testOp2(m64, .MOVQ, mem_64, reg(.MM2), "67 0F 7F 10");
            testOp2(m64, .MOVQ, mem_64, reg(.MM3), "67 0F 7F 18");
            testOp2(m64, .MOVQ, mem_64, reg(.MM4), "67 0F 7F 20");
            testOp2(m64, .MOVQ, mem_64, reg(.MM5), "67 0F 7F 28");
            testOp2(m64, .MOVQ, mem_64, reg(.MM6), "67 0F 7F 30");
            testOp2(m64, .MOVQ, mem_64, reg(.MM7), "67 0F 7F 38");
        }

        {
            testOp2(m32, .MOVQ, reg(.MM0), reg(.MM0), "0F 6F c0");
            testOp2(m32, .MOVQ, reg(.MM1), reg(.MM1), "0F 6F c9");
            testOp2(m32, .MOVQ, reg(.MM2), reg(.MM2), "0F 6F d2");
            testOp2(m32, .MOVQ, reg(.MM3), reg(.MM3), "0F 6F db");
            testOp2(m32, .MOVQ, reg(.MM4), reg(.MM4), "0F 6F e4");
            testOp2(m32, .MOVQ, reg(.MM5), reg(.MM5), "0F 6F ed");
            testOp2(m32, .MOVQ, reg(.MM6), reg(.MM6), "0F 6F f6");
            testOp2(m32, .MOVQ, reg(.MM7), reg(.MM7), "0F 6F ff");
            //
            testOp2(m64, .MOVQ, reg(.MM0), reg(.MM0), "0F 6F c0");
            testOp2(m64, .MOVQ, reg(.MM1), reg(.MM1), "0F 6F c9");
            testOp2(m64, .MOVQ, reg(.MM2), reg(.MM2), "0F 6F d2");
            testOp2(m64, .MOVQ, reg(.MM3), reg(.MM3), "0F 6F db");
            testOp2(m64, .MOVQ, reg(.MM4), reg(.MM4), "0F 6F e4");
            testOp2(m64, .MOVQ, reg(.MM5), reg(.MM5), "0F 6F ed");
            testOp2(m64, .MOVQ, reg(.MM6), reg(.MM6), "0F 6F f6");
            testOp2(m64, .MOVQ, reg(.MM7), reg(.MM7), "0F 6F ff");
        }
    }

    {
        testOp2(m32, .PACKSSWB, reg(.MM0), reg(.MM0), "0F 63 c0");
        testOp2(m32, .PACKSSWB, reg(.MM0), reg(.MM1), "0F 63 c1");
        testOp2(m32, .PACKSSWB, reg(.MM1), reg(.MM0), "0F 63 c8");
        testOp2(m32, .PACKSSWB, reg(.MM0), mem_64,    "0F 63 00");
        testOp2(m32, .PACKSSWB, mem_64, mem_64,       AsmError.InvalidOperand);
        testOp2(m32, .PACKSSWB, mem_64, reg(.MM1),    AsmError.InvalidOperand);

        testOp2(m32, .PACKSSDW, reg(.MM0), reg(.MM0), "0F 6B c0");
        testOp2(m32, .PACKSSDW, reg(.MM0), reg(.MM1), "0F 6B c1");
        testOp2(m32, .PACKSSDW, reg(.MM1), reg(.MM0), "0F 6B c8");
        testOp2(m32, .PACKSSDW, reg(.MM0), mem_64,    "0F 6B 00");
        testOp2(m32, .PACKSSDW, mem_64, mem_64,       AsmError.InvalidOperand);
        testOp2(m32, .PACKSSDW, mem_64, reg(.MM1),    AsmError.InvalidOperand);

        testOp2(m32, .PACKUSWB, reg(.MM0), reg(.MM0), "0F 67 c0");
        testOp2(m32, .PACKUSWB, reg(.MM0), reg(.MM1), "0F 67 c1");
        testOp2(m32, .PACKUSWB, reg(.MM1), reg(.MM0), "0F 67 c8");
        testOp2(m32, .PACKUSWB, reg(.MM0), mem_64,    "0F 67 00");
        testOp2(m32, .PACKUSWB, mem_64, mem_64,       AsmError.InvalidOperand);
        testOp2(m32, .PACKUSWB, mem_64, reg(.MM1),    AsmError.InvalidOperand);
    }

    {
        testOp2(m32, .PADDB,     reg(.MM0), reg(.MM0), "0f fc c0");
        testOp2(m32, .PADDW,     reg(.MM0), reg(.MM0), "0f fd c0");
        testOp2(m32, .PADDD,     reg(.MM0), reg(.MM0), "0f fe c0");
        testOp2(m32, .PADDQ,     reg(.MM0), reg(.MM0), "0f d4 c0");

        testOp2(m32, .PADDSB,    reg(.MM0), reg(.MM0), "0f ec c0");
        testOp2(m32, .PADDSW,    reg(.MM0), reg(.MM0), "0f ed c0");

        testOp2(m32, .PADDUSB,   reg(.MM0), reg(.MM0), "0f dc c0");
        testOp2(m32, .PADDUSW,   reg(.MM0), reg(.MM0), "0f dd c0");

        testOp2(m32, .PAND,      reg(.MM0), reg(.MM0), "0f db c0");
        testOp2(m32, .PANDN,     reg(.MM0), reg(.MM0), "0f df c0");
        testOp2(m32, .POR,       reg(.MM0), reg(.MM0), "0f eb c0");
        testOp2(m32, .PXOR,      reg(.MM0), reg(.MM0), "0f ef c0");

        testOp2(m32, .PCMPEQB,   reg(.MM0), reg(.MM0), "0f 74 c0");
        testOp2(m32, .PCMPEQW,   reg(.MM0), reg(.MM0), "0f 75 c0");
        testOp2(m32, .PCMPEQD,   reg(.MM0), reg(.MM0), "0f 76 c0");

        testOp2(m32, .PCMPGTB,   reg(.MM0), reg(.MM0), "0f 64 c0");
        testOp2(m32, .PCMPGTW,   reg(.MM0), reg(.MM0), "0f 65 c0");
        testOp2(m32, .PCMPGTD,   reg(.MM0), reg(.MM0), "0f 66 c0");

        testOp3(m32, .PEXTRW,    reg( .AX), reg(.MM0), imm(0), "0f c5 c0 00");
        testOp3(m32, .PEXTRW,    reg(.EAX), reg(.MM0), imm(0), "0f c5 c0 00");
        testOp3(m64, .PEXTRW,    reg(.RAX), reg(.MM0), imm(0), "0f c5 c0 00");

        testOp2(m32, .PMADDWD,   reg(.MM0), reg(.MM0), "0f f5 c0");
        testOp2(m32, .PMULHW,    reg(.MM0), reg(.MM0), "0f e5 c0");
        testOp2(m32, .PMULLW,    reg(.MM0), reg(.MM0), "0f d5 c0");

        testOp2(m32, .PSLLW,     reg(.MM0), reg(.MM0), "0f f1 c0");
        testOp2(m32, .PSLLW,     reg(.MM0), imm(0),    "0f 71 f0 00");
        testOp2(m32, .PSLLD,     reg(.MM0), reg(.MM0), "0f f2 c0");
        testOp2(m32, .PSLLD,     reg(.MM0), imm(0),    "0f 72 f0 00");
        testOp2(m32, .PSLLQ,     reg(.MM0), reg(.MM0), "0f f3 c0");
        testOp2(m32, .PSLLQ,     reg(.MM0), imm(0),    "0f 73 f0 00");

        testOp2(m32, .PSRAW,     reg(.MM0), reg(.MM0), "0f e1 c0");
        testOp2(m32, .PSRAW,     reg(.MM0), imm(0),    "0f 71 e0 00");
        testOp2(m32, .PSRAD,     reg(.MM0), reg(.MM0), "0f e2 c0");
        testOp2(m32, .PSRAD,     reg(.MM0), imm(0),    "0f 72 e0 00");

        testOp2(m32, .PSRLW,     reg(.MM0), reg(.MM0), "0f d1 c0");
        testOp2(m32, .PSRLW,     reg(.MM0), imm(0),    "0f 71 d0 00");
        testOp2(m32, .PSRLD,     reg(.MM0), reg(.MM0), "0f d2 c0");
        testOp2(m32, .PSRLD,     reg(.MM0), imm(0),    "0f 72 d0 00");
        testOp2(m32, .PSRLQ,     reg(.MM0), reg(.MM0), "0f d3 c0");
        testOp2(m32, .PSRLQ,     reg(.MM0), imm(0),    "0f 73 d0 00");

        testOp2(m32, .PSUBB,     reg(.MM0), reg(.MM0), "0f f8 c0");
        testOp2(m32, .PSUBW,     reg(.MM0), reg(.MM0), "0f f9 c0");
        testOp2(m32, .PSUBD,     reg(.MM0), reg(.MM0), "0f fa c0");

        testOp2(m32, .PSUBUSB,   reg(.MM0), reg(.MM0), "0f d8 c0");
        testOp2(m32, .PSUBUSW,   reg(.MM0), reg(.MM0), "0f d9 c0");

        testOp2(m32, .PUNPCKHBW, reg(.MM0), reg(.MM0), "0f 68 c0");
        testOp2(m32, .PUNPCKHWD, reg(.MM0), reg(.MM0), "0f 69 c0");
        testOp2(m32, .PUNPCKHDQ, reg(.MM0), reg(.MM0), "0f 6a c0");
        // testOp2(m32, .PUNPCKHQDQ,reg(.MM0), reg(.MM0), "0f 6d c0");

        testOp2(m32, .PUNPCKLBW, reg(.MM0), reg(.MM0), "0f 60 c0");
        testOp2(m32, .PUNPCKLWD, reg(.MM0), reg(.MM0), "0f 61 c0");
        testOp2(m32, .PUNPCKLDQ, reg(.MM0), reg(.MM0), "0f 62 c0");
        // testOp2(m32, .PUNPCKLQDQ,reg(.MM0), reg(.MM0), "0f 6c c0");
    }
}
