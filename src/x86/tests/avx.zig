const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "AVX" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    const reg = Operand.register;
    const pred = Operand.registerPredicate;
    const sae = Operand.registerSae;
    const regRm = Operand.registerRm;
    const imm = Operand.immediate;

    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const mem_64 = rm64;
    const rm_mem32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const m32bcst = Operand.memoryRm(.DefaultSeg, .DWORD_BCST, .EAX, 0);
    const m64bcst = Operand.memoryRm(.DefaultSeg, .QWORD_BCST, .EAX, 0);

    debugPrint(false);

    {
        testOp0(m32, .VZEROALL,   "c5 fc 77");
        testOp0(m32, .VZEROUPPER, "c5 f8 77");

        testOp1(m32, .VLDMXCSR, rm_mem32, "c5 f8 ae 10");
        testOp1(m64, .VLDMXCSR, rm_mem32, "67 c5 f8 ae 10");

        testOp1(m32, .VSTMXCSR, rm_mem32, "c5 f8 ae 18");
        testOp1(m64, .VSTMXCSR, rm_mem32, "67 c5 f8 ae 18");
    }



    testOp4(m64, .VCMPPD, reg(.XMM0), reg(.XMM0), reg(.XMM0),  imm(0),                   "c5 f9 c2 c0 00");
    testOp4(m64, .VCMPPD, reg(.YMM0), reg(.YMM0), reg(.YMM0),  imm(0),                   "c5 fd c2 c0 00");
    testOp4(m64, .VCMPPD, pred(.K0,  .K7, .Merge), reg(.XMM0), reg(.XMM0),  imm(0),      "62 f1 fd 0f c2 c0 00");
    testOp4(m64, .VCMPPD, pred(.K0,  .K7, .Merge), reg(.YMM0), reg(.YMM0),  imm(0),      "62 f1 fd 2f c2 c0 00");
    testOp4(m64, .VCMPPD, pred(.K0,  .K7, .Merge), reg(.ZMM0), sae(.ZMM0, .SAE), imm(0), "62 f1 fd 5f c2 c0 00");

    testOp4(m64, .VCMPPS, reg(.XMM0), reg(.XMM0), reg(.XMM0),  imm(0),                   "c5 f8 c2 c0 00");
    testOp4(m64, .VCMPPS, reg(.YMM0), reg(.YMM0), reg(.YMM0),  imm(0),                   "c5 fc c2 c0 00");
    testOp4(m64, .VCMPPS, pred(.K0,  .K7, .Merge), reg(.XMM0), reg(.XMM0),  imm(0),      "62 f1 7c 0f c2 c0 00");
    testOp4(m64, .VCMPPS, pred(.K0,  .K7, .Merge), reg(.YMM0), reg(.YMM0),  imm(0),      "62 f1 7c 2f c2 c0 00");
    testOp4(m64, .VCMPPS, pred(.K0,  .K7, .Merge), reg(.ZMM0), sae(.ZMM0, .SAE), imm(0), "62 f1 7c 5f c2 c0 00");

    // GFNI
    {
        // VGF2P8AFFINEINVQB
        testOp4(m64, .VGF2P8AFFINEINVQB,  reg(.XMM0),   reg(.XMM0),   reg(.XMM0),   imm(0),  "c4 e3 f9 cf c0 00   ");
        testOp4(m64, .VGF2P8AFFINEINVQB,  reg(.YMM0),   reg(.YMM0),   reg(.YMM0),   imm(0),  "c4 e3 fd cf c0 00   ");
        testOp4(m64, .VGF2P8AFFINEINVQB,  reg(.XMM31),  reg(.XMM31),  reg(.XMM31),  imm(0),  "62 03 85 00 cf ff 00");
        testOp4(m64, .VGF2P8AFFINEINVQB,  reg(.YMM31),  reg(.YMM31),  reg(.YMM31),  imm(0),  "62 03 85 20 cf ff 00");
        testOp4(m64, .VGF2P8AFFINEINVQB,  reg(.ZMM31),  reg(.ZMM31),  reg(.ZMM31),  imm(0),  "62 03 85 40 cf ff 00");
        // VGF2P8AFFINEQB
        testOp4(m64, .VGF2P8AFFINEQB,     reg(.XMM0),   reg(.XMM0),   reg(.XMM0),   imm(0),  "c4 e3 f9 ce c0 00    ");
        testOp4(m64, .VGF2P8AFFINEQB,     reg(.YMM0),   reg(.YMM0),   reg(.YMM0),   imm(0),  "c4 e3 fd ce c0 00    ");
        testOp4(m64, .VGF2P8AFFINEQB,     reg(.XMM31),  reg(.XMM31),  reg(.XMM31),  imm(0),  "62 03 85 00 ce ff 00 ");
        testOp4(m64, .VGF2P8AFFINEQB,     reg(.YMM31),  reg(.YMM31),  reg(.YMM31),  imm(0),  "62 03 85 20 ce ff 00 ");
        testOp4(m64, .VGF2P8AFFINEQB,     reg(.ZMM31),  reg(.ZMM31),  reg(.ZMM31),  imm(0),  "62 03 85 40 ce ff 00 ");
        // VGF2P8MULB
        testOp3(m64, .VGF2P8MULB,         reg(.XMM0),   reg(.XMM0),   reg(.XMM0),            "c4 e2 79 cf c0   ");
        testOp3(m64, .VGF2P8MULB,         reg(.YMM0),   reg(.YMM0),   reg(.YMM0),            "c4 e2 7d cf c0   ");
        testOp3(m64, .VGF2P8MULB,         reg(.XMM31),  reg(.XMM31),  reg(.XMM31),           "62 02 05 00 cf ff");
        testOp3(m64, .VGF2P8MULB,         reg(.YMM31),  reg(.YMM31),  reg(.YMM31),           "62 02 05 20 cf ff");
        testOp3(m64, .VGF2P8MULB,         reg(.ZMM31),  reg(.ZMM31),  reg(.ZMM31),           "62 02 05 40 cf ff");
    }

    {
        {
            testOp2(m32, .VMOVD, reg(.XMM0), rm32, "c5 f9 6e 00");
            testOp2(m32, .VMOVD, reg(.XMM7), rm32, "c5 f9 6e 38");
            testOp2(m32, .VMOVD, reg(.XMM15), rm32, AsmError.InvalidMode);
            testOp2(m32, .VMOVD, reg(.XMM31), rm32, AsmError.InvalidMode);
            //
            testOp2(m64, .VMOVD, reg(.XMM0), rm32, "67 c5 f9 6e 00");
            testOp2(m64, .VMOVD, reg(.XMM7), rm32, "67 c5 f9 6e 38");
            testOp2(m64, .VMOVD, reg(.XMM15), rm32, "67 c5 79 6e 38");
            testOp2(m64, .VMOVD, reg(.XMM31), rm32, "67 62 61 7d 08 6e 38");
        }

        {
            testOp2(m32, .VMOVD, reg(.XMM0), rm64, AsmError.InvalidOperand);
            testOp2(m32, .VMOVD, reg(.XMM7), rm64, AsmError.InvalidOperand);
            testOp2(m32, .VMOVD, reg(.XMM15), rm64, AsmError.InvalidMode);
            testOp2(m32, .VMOVD, reg(.XMM31), rm64, AsmError.InvalidMode);
            //
            testOp2(m64, .VMOVD, reg(.XMM0), rm64,  "67 c4 e1 f9 6e 00");
            testOp2(m64, .VMOVD, reg(.XMM7), rm64,  "67 c4 e1 f9 6e 38");
            testOp2(m64, .VMOVD, reg(.XMM15), rm64, "67 c4 61 f9 6e 38");
            testOp2(m64, .VMOVD, reg(.XMM31), rm64, "67 62 61 fd 08 6e 38");
        }

        {
            testOp2(m32, .VMOVQ, reg(.XMM0), reg(.RAX), AsmError.InvalidOperand);
            testOp2(m32, .VMOVQ, reg(.XMM15), reg(.RAX), AsmError.InvalidMode);
            //
            testOp2(m64, .VMOVQ, reg(.XMM0), reg(.RAX),  "c4 e1 f9 6e C0");
            testOp2(m64, .VMOVQ, reg(.XMM15), reg(.RAX), "c4 61 f9 6e F8");
            testOp2(m64, .VMOVQ, reg(.XMM31), reg(.RAX), "62 61 fd 08 6e f8");
        }

        {
            testOp2(m32, .VMOVQ, reg(.RAX), reg(.XMM0),  AsmError.InvalidOperand);
            testOp2(m32, .VMOVQ, reg(.RAX), reg(.XMM15), AsmError.InvalidMode);
            //
            testOp2(m64, .VMOVQ, reg(.RAX), reg(.XMM0),  "c4 e1 f9 7e C0");
            testOp2(m64, .VMOVQ, reg(.RAX), reg(.XMM15), "c4 61 f9 7e F8");
            testOp2(m64, .VMOVQ, reg(.RAX), reg(.XMM31), "62 61 fd 08 7e f8");
        }

        {
            testOp2(m32, .VMOVQ, reg(.XMM0), mem_64,  "c5 fa 7e 00");
            testOp2(m32, .VMOVQ, reg(.XMM7), mem_64,  "c5 fa 7e 38");
            testOp2(m32, .VMOVQ, reg(.XMM15), mem_64, AsmError.InvalidMode);
            //
            testOp2(m64, .VMOVQ, reg(.XMM0), mem_64,  "67 c5 fa 7e 00");
            testOp2(m64, .VMOVQ, reg(.XMM7), mem_64,  "67 c5 fa 7e 38");
            testOp2(m64, .VMOVQ, reg(.XMM15), mem_64, "67 c5 7a 7e 38");
            testOp2(m64, .VMOVQ, reg(.XMM31), mem_64, "67 62 61 fe 08 7e 38");
            //
            testOp2(m64, .VMOVD, reg(.XMM0), mem_64,  "67 c4 e1 f9 6e 00");
            testOp2(m64, .VMOVD, reg(.XMM7), mem_64,  "67 c4 e1 f9 6e 38");
            testOp2(m64, .VMOVD, reg(.XMM15), mem_64, "67 c4 61 f9 6e 38");
            testOp2(m64, .VMOVD, reg(.XMM31), mem_64, "67 62 61 fd 08 6e 38");
        }

        {
            testOp2(m32, .VMOVQ, mem_64, reg(.XMM0),  "c5 f9 d6 00");
            testOp2(m32, .VMOVQ, mem_64, reg(.XMM7),  "c5 f9 d6 38");
            testOp2(m32, .VMOVQ, mem_64, reg(.XMM15), AsmError.InvalidMode);
            //
            testOp2(m64, .VMOVQ, mem_64, reg(.XMM0),  "67 c5 f9 d6 00");
            testOp2(m64, .VMOVQ, mem_64, reg(.XMM7),  "67 c5 f9 d6 38");
            testOp2(m64, .VMOVQ, mem_64, reg(.XMM15), "67 c5 79 d6 38");
            testOp2(m64, .VMOVQ, mem_64, reg(.XMM31), "67 62 61 fd 08 d6 38");
            //
            testOp2(m64, .VMOVD, mem_64, reg(.XMM0),  "67 c4 e1 f9 7e 00");
            testOp2(m64, .VMOVD, mem_64, reg(.XMM7),  "67 c4 e1 f9 7e 38");
            testOp2(m64, .VMOVD, mem_64, reg(.XMM15), "67 c4 61 f9 7e 38");
            testOp2(m64, .VMOVD, mem_64, reg(.XMM31), "67 62 61 fd 08 7e 38");
        }

        {
            testOp2(m32, .VMOVQ, reg(.XMM0), reg(.XMM0),   "c5 fa 7e c0");
            testOp2(m32, .VMOVQ, reg(.XMM7), reg(.XMM7),   "c5 fa 7e ff");
            testOp2(m32, .VMOVQ, reg(.XMM15), reg(.XMM15), AsmError.InvalidMode);
            //
            testOp2(m32, .VMOVQ, regRm(.XMM0), reg(.XMM0),   "c5 f9 d6 c0");
            testOp2(m32, .VMOVQ, regRm(.XMM7), reg(.XMM7),   "c5 f9 d6 ff");
            testOp2(m32, .VMOVQ, regRm(.XMM15), reg(.XMM15), AsmError.InvalidMode);
            //
            testOp2(m64, .VMOVQ, reg(.XMM0), reg(.XMM0),   "c5 fa 7e c0");
            testOp2(m64, .VMOVQ, reg(.XMM7), reg(.XMM7),   "c5 fa 7e ff");
            testOp2(m64, .VMOVQ, reg(.XMM15), reg(.XMM15), "c4 41 7a 7e ff");
            testOp2(m64, .VMOVQ, reg(.XMM31), reg(.XMM31), "62 01 fe 08 7e ff");
            //
            testOp2(m64, .VMOVQ, regRm(.XMM0), reg(.XMM0),   "c5 f9 d6 c0");
            testOp2(m64, .VMOVQ, regRm(.XMM7), reg(.XMM7),   "c5 f9 d6 ff");
            testOp2(m64, .VMOVQ, regRm(.XMM15), reg(.XMM15), "c4 41 79 d6 ff");
            testOp2(m64, .VMOVQ, regRm(.XMM31), reg(.XMM31), "62 01 fd 08 d6 ff");
        }
    }

    // test 4 operands
    {
        testOp4(m32, .VPBLENDVB, reg(.XMM0), reg(.XMM0), reg(.XMM0), reg(.XMM0),   "c4 e3 79 4c c0 00");
        testOp4(m64, .VPBLENDVB, reg(.XMM0), reg(.XMM0), reg(.XMM0), reg(.XMM0),   "c4 e3 79 4c c0 00");
        testOp4(m64, .VPBLENDVB, reg(.XMM0), reg(.XMM0), reg(.XMM0), reg(.XMM15),  "c4 e3 79 4c c0 F0");
        testOp4(m64, .VPBLENDVB, reg(.XMM0), reg(.XMM0), reg(.XMM0), reg(.XMM31),  AsmError.InvalidOperand);
    }


    {
        testOp4(m32, .VPBLENDVB, reg(.XMM0), reg(.XMM0), reg(.XMM0), reg(.XMM0),   "c4 e3 79 4c c0 00");
        testOp4(m64, .VPBLENDVB, reg(.XMM0), reg(.XMM0), reg(.XMM0), reg(.XMM0),   "c4 e3 79 4c c0 00");
        testOp4(m64, .VPBLENDVB, reg(.XMM0), reg(.XMM0), reg(.XMM0), reg(.XMM15),  "c4 e3 79 4c c0 F0");
        testOp4(m64, .VPBLENDVB, reg(.XMM0), reg(.XMM0), reg(.XMM0), reg(.XMM31),  AsmError.InvalidOperand);
    }

    {
        testOp3(m64, .VPEXTRB,   reg( .AL), reg(.XMM0), imm(0), "c4 e3 79 14 c0 00");
        testOp3(m64, .VPEXTRB,   reg(.EAX), reg(.XMM0), imm(0), "c4 e3 79 14 c0 00");
        testOp3(m64, .VPEXTRB,   reg(.RAX), reg(.XMM0), imm(0), "c4 e3 79 14 c0 00");
        testOp3(m32, .VPEXTRB,   reg(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);

        testOp3(m64, .VPEXTRB,   reg( .AL), reg(.XMM31), imm(0), "62 63 7d 08 14 f8 00");
        testOp3(m64, .VPEXTRB,   reg(.EAX), reg(.XMM31), imm(0), "62 63 7d 08 14 f8 00");
        testOp3(m64, .VPEXTRB,   reg(.RAX), reg(.XMM31), imm(0), "62 63 7d 08 14 f8 00");
        testOp3(m32, .VPEXTRB,   reg(.RAX), reg(.XMM31), imm(0), AsmError.InvalidOperand);

        testOp3(m32, .VPEXTRW,   reg( .AX), reg(.XMM0), imm(0), "c5 f9 c5 c0 00");
        testOp3(m32, .VPEXTRW,   reg(.EAX), reg(.XMM0), imm(0), "c5 f9 c5 c0 00");
        testOp3(m32, .VPEXTRW,   reg(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);
        testOp3(m64, .VPEXTRW,   reg(.RAX), reg(.XMM0), imm(0), "c5 f9 c5 c0 00");

        testOp3(m32, .VPEXTRW,   regRm( .AX), reg(.XMM0), imm(0), "c4 e3 79 15 c0 00");
        testOp3(m32, .VPEXTRW,   regRm(.EAX), reg(.XMM0), imm(0), "c4 e3 79 15 c0 00");
        testOp3(m32, .VPEXTRW,   regRm(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);
        testOp3(m64, .VPEXTRW,   regRm(.RAX), reg(.XMM0), imm(0), "c4 e3 79 15 c0 00");

        testOp3(m64, .VPEXTRD,   reg(.EAX), reg(.XMM0), imm(0),  "c4 e3 79 16 c0 00");
        testOp3(m64, .VPEXTRD,   reg(.EAX), reg(.XMM31), imm(0), "62 63 7d 08 16 f8 00");
        testOp3(m64, .VPEXTRQ,   reg(.RAX), reg(.XMM0), imm(0),  "c4 e3 f9 16 c0 00");
        testOp3(m64, .VPEXTRQ,   reg(.RAX), reg(.XMM31), imm(0), "62 63 fd 08 16 f8 00");
    }

}
