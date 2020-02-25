const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "AVX" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    const reg = Operand.register;
    const pred = Operand.registerPredicate;
    const predRm = Operand.rmPredicate;
    const sae = Operand.registerSae;
    const regRm = Operand.registerRm;
    const imm = Operand.immediate;

    const rm8 = Operand.memoryRm(.DefaultSeg, .BYTE, .EAX, 0);
    const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const mem_64 = rm64;
    const rm_mem8 = Operand.memoryRm(.DefaultSeg, .BYTE, .EAX, 0);
    const rm_mem16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const rm_mem32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm_mem64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const rm_mem128 = Operand.memoryRm(.DefaultSeg, .XMM_WORD, .EAX, 0);
    const rm_mem256 = Operand.memoryRm(.DefaultSeg, .YMM_WORD, .EAX, 0);
    const rm_mem512 = Operand.memoryRm(.DefaultSeg, .ZMM_WORD, .EAX, 0);
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

    // test VMOV
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

    {
        testOp4(m64, .VBLENDPD, reg(.XMM0), reg(.XMM0), reg(.XMM0), imm(0),  "c4 e3 79 0d c0 00");
        testOp4(m64, .VBLENDPD, reg(.YMM0), reg(.YMM0), reg(.YMM0), imm(0),  "c4 e3 7d 0d c0 00");

        testOp4(m64, .VBLENDPS, reg(.XMM0), reg(.XMM0), reg(.XMM0), imm(0),  "c4 e3 79 0c c0 00");
        testOp4(m64, .VBLENDPS, reg(.YMM0), reg(.YMM0), reg(.YMM0), imm(0),  "c4 e3 7d 0c c0 00");
    }

    {
        testOp4(m64, .VBLENDVPD, reg(.XMM0), reg(.XMM0), reg(.XMM0), reg(.XMM0),  "c4 e3 79 4b c0 00");
        testOp4(m64, .VBLENDVPD, reg(.YMM0), reg(.YMM0), reg(.YMM0), reg(.YMM0),  "c4 e3 7d 4b c0 00");

        testOp4(m64, .VBLENDVPS, reg(.XMM0), reg(.XMM0), reg(.XMM0), reg(.XMM0),  "c4 e3 79 4a c0 00");
        testOp4(m64, .VBLENDVPS, reg(.YMM0), reg(.YMM0), reg(.YMM0), reg(.YMM0),  "c4 e3 7d 4a c0 00");
    }

    {
        testOp3(m64, .VANDPD, reg(.XMM0), reg(.XMM0), reg(.XMM0),                "c5 f9 54 c0");
        testOp3(m64, .VANDPD, reg(.YMM0), reg(.YMM0), reg(.YMM0),                "c5 fd 54 c0");
        testOp3(m64, .VANDPD, pred(.XMM0,  .K7, .Merge), reg(.XMM0), reg(.XMM0), "62 f1 fd 0f 54 c0");
        testOp3(m64, .VANDPD, pred(.YMM0,  .K7, .Merge), reg(.YMM0), reg(.YMM0), "62 f1 fd 2f 54 c0");
        testOp3(m64, .VANDPD, pred(.ZMM0,  .K7, .Merge), reg(.ZMM0), reg(.ZMM0), "62 f1 fd 4f 54 c0");
        //
        testOp3(m64, .VANDPS, reg(.XMM0), reg(.XMM0), reg(.XMM0),                "c5 f8 54 c0");
        testOp3(m64, .VANDPS, reg(.YMM0), reg(.YMM0), reg(.YMM0),                "c5 fc 54 c0");
        testOp3(m64, .VANDPS, pred(.XMM0,  .K7, .Merge), reg(.XMM0), reg(.XMM0), "62 f1 7c 0f 54 c0");
        testOp3(m64, .VANDPS, pred(.YMM0,  .K7, .Merge), reg(.YMM0), reg(.YMM0), "62 f1 7c 2f 54 c0");
        testOp3(m64, .VANDPS, pred(.ZMM0,  .K7, .Merge), reg(.ZMM0), reg(.ZMM0), "62 f1 7c 4f 54 c0");
    }

    {
        testOp3(m64, .VANDNPD, reg(.XMM0), reg(.XMM0), reg(.XMM0),                "c5 f9 55 c0");
        testOp3(m64, .VANDNPD, reg(.YMM0), reg(.YMM0), reg(.YMM0),                "c5 fd 55 c0");
        testOp3(m64, .VANDNPD, pred(.XMM0,  .K7, .Merge), reg(.XMM0), reg(.XMM0), "62 f1 fd 0f 55 c0");
        testOp3(m64, .VANDNPD, pred(.YMM0,  .K7, .Merge), reg(.YMM0), reg(.YMM0), "62 f1 fd 2f 55 c0");
        testOp3(m64, .VANDNPD, pred(.ZMM0,  .K7, .Merge), reg(.ZMM0), reg(.ZMM0), "62 f1 fd 4f 55 c0");
        //
        testOp3(m64, .VANDNPS, reg(.XMM0), reg(.XMM0), reg(.XMM0),                "c5 f8 55 c0");
        testOp3(m64, .VANDNPS, reg(.YMM0), reg(.YMM0), reg(.YMM0),                "c5 fc 55 c0");
        testOp3(m64, .VANDNPS, pred(.XMM0,  .K7, .Merge), reg(.XMM0), reg(.XMM0), "62 f1 7c 0f 55 c0");
        testOp3(m64, .VANDNPS, pred(.YMM0,  .K7, .Merge), reg(.YMM0), reg(.YMM0), "62 f1 7c 2f 55 c0");
        testOp3(m64, .VANDNPS, pred(.ZMM0,  .K7, .Merge), reg(.ZMM0), reg(.ZMM0), "62 f1 7c 4f 55 c0");
    }

    {
        testOp4(m64, .VCMPPD, reg(.XMM0), reg(.XMM0), reg(.XMM0),  imm(0),                   "c5 f9 c2 c0 00");
        testOp4(m64, .VCMPPD, reg(.YMM0), reg(.YMM0), reg(.YMM0),  imm(0),                   "c5 fd c2 c0 00");
        testOp4(m64, .VCMPPD, pred(.K0,  .K7, .Merge), reg(.XMM0), reg(.XMM0),  imm(0),      "62 f1 fd 0f c2 c0 00");
        testOp4(m64, .VCMPPD, pred(.K0,  .K7, .Merge), reg(.YMM0), reg(.YMM0),  imm(0),      "62 f1 fd 2f c2 c0 00");
        testOp4(m64, .VCMPPD, pred(.K0,  .K7, .Merge), reg(.ZMM0), sae(.ZMM0, .SAE), imm(0), "62 f1 fd 5f c2 c0 00");
        //
        testOp4(m64, .VCMPPS, reg(.XMM0), reg(.XMM0), reg(.XMM0),  imm(0),                   "c5 f8 c2 c0 00");
        testOp4(m64, .VCMPPS, reg(.YMM0), reg(.YMM0), reg(.YMM0),  imm(0),                   "c5 fc c2 c0 00");
        testOp4(m64, .VCMPPS, pred(.K0,  .K7, .Merge), reg(.XMM0), reg(.XMM0),  imm(0),      "62 f1 7c 0f c2 c0 00");
        testOp4(m64, .VCMPPS, pred(.K0,  .K7, .Merge), reg(.YMM0), reg(.YMM0),  imm(0),      "62 f1 7c 2f c2 c0 00");
        testOp4(m64, .VCMPPS, pred(.K0,  .K7, .Merge), reg(.ZMM0), sae(.ZMM0, .SAE), imm(0), "62 f1 7c 5f c2 c0 00");
    }

    {
        testOp4(m64, .VCMPSD, reg(.XMM0), reg(.XMM0), reg(.XMM0),  imm(0),                   "c5 fb c2 c0 00");
        testOp4(m64, .VCMPSD, pred(.K0,  .K7, .Merge), reg(.XMM0), sae(.XMM0, .SAE), imm(0), "62 f1 ff 1f c2 c0 00");
        //
        testOp4(m64, .VCMPSS, reg(.XMM0), reg(.XMM0), reg(.XMM0),  imm(0),                   "c5 fa c2 c0 00");
        testOp4(m64, .VCMPSS, pred(.K0,  .K7, .Merge), reg(.XMM0), sae(.XMM0, .SAE), imm(0), "62 f1 7e 1f c2 c0 00");
    }

    {
        // VCOMISD
        testOp2(m64, .VCOMISD,    reg(.XMM0), reg(.XMM0),   "c5 f9 2f c0");
        testOp2(m64, .VCOMISD,    reg(.XMM0), sae(.XMM0, .SAE), "62 f1 fd 18 2f c0");
        // VCOMISS
        testOp2(m64, .VCOMISS,    reg(.XMM0), reg(.XMM0),   "c5 f8 2f c0");
        testOp2(m64, .VCOMISS,    reg(.XMM0), sae(.XMM0, .SAE), "62 f1 7c 18 2f c0");
    }

    {
        // VCVTDQ2PD
        testOp2(m64, .VCVTDQ2PD,  reg(.XMM0), reg(.XMM0),   "c5 fa e6 c0");
        testOp2(m64, .VCVTDQ2PD,  reg(.YMM0), reg(.XMM0),   "c5 fe e6 c0");
        testOp2(m64, .VCVTDQ2PD,  pred(.XMM0, .K7, .Zero), reg(.XMM0),  "62 f1 7e 8f e6 c0");
        testOp2(m64, .VCVTDQ2PD,  pred(.YMM0, .K7, .Zero), reg(.XMM0),  "62 f1 7e af e6 c0");
        testOp2(m64, .VCVTDQ2PD,  pred(.ZMM0, .K7, .Zero), reg(.YMM0),  "62 f1 7e cf e6 c0");
        // VCVTDQ2PS
        testOp2(m64, .VCVTDQ2PS,  reg(.XMM0), reg(.XMM0),   "c5 f8 5b c0");
        testOp2(m64, .VCVTDQ2PS,  reg(.YMM0), reg(.YMM0),   "c5 fc 5b c0");
        testOp2(m64, .VCVTDQ2PS,  pred(.XMM0, .K7, .Zero), reg(.XMM0),  "62 f1 7c 8f 5b c0");
        testOp2(m64, .VCVTDQ2PS,  pred(.YMM0, .K7, .Zero), reg(.YMM0),  "62 f1 7c af 5b c0");
        testOp2(m64, .VCVTDQ2PS,  pred(.ZMM0, .K7, .Zero), sae(.ZMM0, .RN_SAE), "62 f1 7c 9f 5b c0");
        // VCVTPD2DQ
        testOp2(m64, .VCVTPD2DQ,  reg(.XMM0), reg(.XMM0),   "c5 fb e6 c0");
        testOp2(m64, .VCVTPD2DQ,  reg(.XMM0), reg(.YMM0),   "c5 ff e6 c0");
        testOp2(m64, .VCVTPD2DQ,  pred(.XMM0, .K7, .Zero), reg(.XMM0),  "62 f1 ff 8f e6 c0");
        testOp2(m64, .VCVTPD2DQ,  pred(.XMM0, .K7, .Zero), reg(.YMM0),  "62 f1 ff af e6 c0");
        testOp2(m64, .VCVTPD2DQ,  pred(.YMM0, .K7, .Zero), sae(.ZMM0, .RN_SAE), "62 f1 ff 9f e6 c0");
        // VCVTPD2PS
        testOp2(m64, .VCVTPD2PS,  reg(.XMM0), reg(.XMM0),   "c5 f9 5a c0");
        testOp2(m64, .VCVTPD2PS,  reg(.XMM0), reg(.YMM0),   "c5 fd 5a c0");
        testOp2(m64, .VCVTPD2PS,  pred(.XMM0, .K7, .Zero), reg(.XMM0),   "62 f1 fd 8f 5a c0");
        testOp2(m64, .VCVTPD2PS,  pred(.XMM0, .K7, .Zero), reg(.YMM0),   "62 f1 fd af 5a c0");
        testOp2(m64, .VCVTPD2PS,  pred(.YMM0, .K7, .Zero), sae(.ZMM0, .RN_SAE),  "62 f1 fd 9f 5a c0");
        // VCVTPS2DQ
        testOp2(m64, .VCVTPS2DQ,  reg(.XMM0), reg(.XMM0),   "c5 f9 5b c0");
        testOp2(m64, .VCVTPS2DQ,  reg(.YMM0), reg(.YMM0),   "c5 fd 5b c0");
        testOp2(m64, .VCVTPS2DQ,  pred(.XMM0, .K7, .Zero), reg(.XMM0),  "62 f1 7d 8f 5b c0");
        testOp2(m64, .VCVTPS2DQ,  pred(.YMM0, .K7, .Zero), reg(.YMM0),  "62 f1 7d af 5b c0");
        testOp2(m64, .VCVTPS2DQ,  pred(.ZMM0, .K7, .Zero), sae(.ZMM0, .RN_SAE), "62 f1 7d 9f 5b c0");
        // VCVTPS2PD
        testOp2(m64, .VCVTPS2PD,  reg(.XMM0), reg(.XMM0),   "c5 f8 5a c0");
        testOp2(m64, .VCVTPS2PD,  reg(.YMM0), reg(.XMM0),   "c5 fc 5a c0");
        testOp2(m64, .VCVTPS2PD,  pred(.XMM0, .K7, .Zero), reg(.XMM0),  "62 f1 7c 8f 5a c0");
        testOp2(m64, .VCVTPS2PD,  pred(.YMM0, .K7, .Zero), reg(.XMM0),  "62 f1 7c af 5a c0");
        testOp2(m64, .VCVTPS2PD,  pred(.ZMM0, .K7, .Zero), sae(.YMM0, .SAE), "62 f1 7c df 5a c0");
        // VCVTSD2SI
        testOp2(m64, .VCVTSD2SI,  reg(.EAX), reg(.XMM0),    "c5 fb 2d c0");
        testOp2(m64, .VCVTSD2SI,  reg(.RAX), reg(.XMM0),    "c4 e1 fb 2d c0");
        testOp2(m64, .VCVTSD2SI,  reg(.EAX), sae(.XMM0, .RN_SAE),   "62 f1 7f 18 2d c0");
        testOp2(m64, .VCVTSD2SI,  reg(.RAX), sae(.XMM0, .RN_SAE),   "62 f1 ff 18 2d c0");
        // VCVTSD2SS
        testOp3(m64, .VCVTSD2SS,  reg(.XMM0), reg(.XMM0), reg(.XMM0),   "c5 fb 5a c0");
        testOp3(m64, .VCVTSD2SS,  pred(.XMM0, .K7, .Zero), reg(.XMM0), sae(.XMM0, .RN_SAE),  "62 f1 ff 9f 5a c0");
        // VCVTSI2SD
        testOp3(m64, .VCVTSI2SD,  reg(.XMM0), reg(.XMM0), rm32, "67 c5 fb 2a 00");
        testOp3(m64, .VCVTSI2SD,  reg(.XMM0), reg(.XMM0), rm64, "67 c4 e1 fb 2a 00");
        testOp3(m64, .VCVTSI2SD,  reg(.XMM0), reg(.XMM0), rm32, "67 c5 fb 2a 00");
        testOp3(m64, .VCVTSI2SD,  reg(.XMM0), reg(.XMM0), sae(.RAX, .RN_SAE),   "62 f1 ff 18 2a c0");
        // VCVTSI2SS
        testOp3(m64, .VCVTSI2SS,  reg(.XMM0), reg(.XMM0), rm32,    "67 c5 fa 2a 00");
        testOp3(m64, .VCVTSI2SS,  reg(.XMM0), reg(.XMM0), rm64,    "67 c4 e1 fa 2a 00");
        testOp3(m64, .VCVTSI2SS,  reg(.XMM0), reg(.XMM0), sae(.EAX, .RN_SAE),   "62 f1 7e 18 2a c0");
        testOp3(m64, .VCVTSI2SS,  reg(.XMM0), reg(.XMM0), sae(.RAX, .RN_SAE),   "62 f1 fe 18 2a c0");
        // VCVTSS2SD
        testOp3(m64, .VCVTSS2SD,  reg(.XMM0), reg(.XMM0), reg(.XMM0),   "c5 fa 5a c0");
        testOp3(m64, .VCVTSS2SD,  pred(.XMM0, .K7, .Zero), reg(.XMM0), sae(.XMM0, .SAE), "62 f1 7e 9f 5a c0");
        // VCVTSS2SI
        testOp2(m64, .VCVTSS2SI,  reg(.EAX), reg(.XMM0),    "c5 fa 2d c0");
        testOp2(m64, .VCVTSS2SI,  reg(.RAX), reg(.XMM0),    "c4 e1 fa 2d c0");
        testOp2(m64, .VCVTSS2SI,  reg(.EAX), sae(.XMM0, .RN_SAE),   "62 f1 7e 18 2d c0");
        testOp2(m64, .VCVTSS2SI,  reg(.RAX), sae(.XMM0, .RN_SAE),   "62 f1 fe 18 2d c0");
        // VCVTTPD2DQ
        testOp2(m64, .VCVTTPD2DQ, reg(.XMM0), reg(.XMM0),   "c5 f9 e6 c0");
        testOp2(m64, .VCVTTPD2DQ, reg(.XMM0), reg(.YMM0),   "c5 fd e6 c0");
        testOp2(m64, .VCVTTPD2DQ, pred(.XMM0, .K7, .Zero), reg(.XMM0),   "62 f1 fd 8f e6 c0");
        testOp2(m64, .VCVTTPD2DQ, pred(.XMM0, .K7, .Zero), reg(.YMM0),   "62 f1 fd af e6 c0");
        testOp2(m64, .VCVTTPD2DQ, pred(.YMM0, .K7, .Zero), sae(.ZMM0, .SAE), "62 f1 fd df e6 c0");
        // VCVTTPS2DQ
        testOp2(m64, .VCVTTPS2DQ, reg(.XMM0), reg(.XMM0),   "c5 fa 5b c0");
        testOp2(m64, .VCVTTPS2DQ, reg(.YMM0), reg(.YMM0),   "c5 fe 5b c0");
        testOp2(m64, .VCVTTPS2DQ, pred(.XMM0, .K7, .Zero), reg(.XMM0),  "62 f1 7e 8f 5b c0");
        testOp2(m64, .VCVTTPS2DQ, pred(.YMM0, .K7, .Zero), reg(.YMM0),  "62 f1 7e af 5b c0");
        testOp2(m64, .VCVTTPS2DQ, pred(.ZMM0, .K7, .Zero), sae(.ZMM0, .SAE),    "62 f1 7e df 5b c0");
        // VCVTTSD2SI
        testOp2(m64, .VCVTTSD2SI, reg(.EAX), reg(.XMM0),    "c5 fb 2c c0");
        testOp2(m64, .VCVTTSD2SI, reg(.RAX), reg(.XMM0),    "c4 e1 fb 2c c0");
        testOp2(m64, .VCVTTSD2SI, reg(.EAX), sae(.XMM0, .SAE),  "62 f1 7f 18 2c c0");
        testOp2(m64, .VCVTTSD2SI, reg(.RAX), sae(.XMM0, .SAE),  "62 f1 ff 18 2c c0");
        // VCVTTSS2SI
        testOp2(m64, .VCVTTSS2SI, reg(.EAX), reg(.XMM0),    "c5 fa 2c c0");
        testOp2(m64, .VCVTTSS2SI, reg(.RAX), reg(.XMM0),    "c4 e1 fa 2c c0");
        testOp2(m64, .VCVTTSS2SI, reg(.EAX), sae(.XMM0, .SAE),  "62 f1 7e 18 2c c0");
        testOp2(m64, .VCVTTSS2SI, reg(.RAX), sae(.XMM0, .SAE),  "62 f1 fe 18 2c c0");
    }

    {
        // VDIVPD
        testOp3(m64, .VDIVPD, reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 f9 5e c0");
        testOp3(m64, .VDIVPD, reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5 fd 5e c0");
        testOp3(m64, .VDIVPD, pred(.XMM31, .K7, .Zero), reg(.XMM31), reg(.XMM31), "62 01 85 87 5e ff");
        testOp3(m64, .VDIVPD, pred(.YMM31, .K7, .Zero), reg(.YMM31), reg(.YMM31), "62 01 85 a7 5e ff");
        testOp3(m64, .VDIVPD, pred(.ZMM31, .K7, .Zero), reg(.ZMM31), sae(.ZMM31, .RN_SAE), "62 01 85 97 5e ff");
        // VDIVPS
        testOp3(m64, .VDIVPS, reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 f8 5e c0");
        testOp3(m64, .VDIVPS, reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5 fc 5e c0");
        testOp3(m64, .VDIVPS, pred(.XMM31, .K7, .Zero), reg(.XMM31), reg(.XMM31), "62 01 04 87 5e ff");
        testOp3(m64, .VDIVPS, pred(.YMM31, .K7, .Zero), reg(.YMM31), reg(.YMM31), "62 01 04 a7 5e ff");
        testOp3(m64, .VDIVPS, pred(.ZMM31, .K7, .Zero), reg(.ZMM31), sae(.ZMM31, .RN_SAE), "62 01 04 97 5e ff");
        // VDIVSD
        testOp3(m64, .VDIVSD, reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 fb 5e c0");
        testOp3(m64, .VDIVSD, pred(.XMM31, .K7, .Zero), reg(.XMM31), sae(.XMM31, .RN_SAE), "62 01 87 97 5e ff");
        // VDIVSS
        testOp3(m64, .VDIVSS, reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 fa 5e c0");
        testOp3(m64, .VDIVSS, pred(.XMM31, .K7, .Zero), reg(.XMM31), sae(.XMM31, .RN_SAE), "62 01 06 97 5e ff");
        // VDPPD
        testOp4(m64, .VDPPD,  reg(.XMM0), reg(.XMM0), reg(.XMM0), imm(0), "c4 e3 79 41 c0 00");
        // VDPPS
        testOp4(m64, .VDPPS,  reg(.XMM0), reg(.XMM0), reg(.XMM0), imm(0), "c4 e3 79 40 c0 00");
        testOp4(m64, .VDPPS,  reg(.YMM0), reg(.YMM0), reg(.YMM0), imm(0), "c4 e3 7d 40 c0 00");
    }

    {
        // VEXTRACTPS
        testOp3(m64, .VEXTRACTPS, rm32, reg(.XMM0), imm(0), "67 c4 e3 79 17 00 00");
        testOp3(m64, .VEXTRACTPS, reg(.EAX), reg(.XMM0), imm(0), "c4 e3 79 17 c0 00");
        testOp3(m64, .VEXTRACTPS, reg(.RAX), reg(.XMM0), imm(0), "c4 e3 79 17 c0 00");
        testOp3(m32, .VEXTRACTPS, rm32, reg(.XMM0), imm(0), "c4 e3 79 17 00 00");
        testOp3(m32, .VEXTRACTPS, reg(.EAX), reg(.XMM0), imm(0), "c4 e3 79 17 c0 00");
        testOp3(m32, .VEXTRACTPS, reg(.RAX), reg(.XMM0), imm(0), AsmError.InvalidOperand);
    }

    { // GFNI
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
        // VHADDPD
        testOp3(m64, .VHADDPD,    reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 f9 7c c0");
        testOp3(m64, .VHADDPD,    reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5 fd 7c c0");
        // VHADDPS
        testOp3(m64, .VHADDPS,    reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 fb 7c c0");
        testOp3(m64, .VHADDPS,    reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5 ff 7c c0");
        // VHSUBPD
        testOp3(m64, .VHSUBPD,    reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 f9 7d c0");
        testOp3(m64, .VHSUBPD,    reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5 fd 7d c0");
        // VHSUBPS
        testOp3(m64, .VHSUBPS,    reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 fb 7d c0");
        testOp3(m64, .VHSUBPS,    reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5 ff 7d c0");
    }


    {
        // VINSERTPS
        testOp4(m64, .VINSERTPS,  reg(.XMM0), reg(.XMM0), reg(.XMM0), imm(0), "c4 e3 79 21 c0 00");
        testOp4(m64, .VINSERTPS,  reg(.XMM31), reg(.XMM31), reg(.XMM31), imm(0), "62 03 05 00 21 ff 00");
    }

    {
        // LDDQU
        testOp2(m64, .VLDDQU,     reg(.XMM0), rm_mem128, "67 c5 fb f0 00");
        testOp2(m64, .VLDDQU,     reg(.YMM0), rm_mem256, "67 c5 ff f0 00");

        testOp2(m64, .VLDDQU,     reg(.XMM0), rm_mem32, AsmError.InvalidOperand);
        testOp2(m64, .VLDDQU,     reg(.XMM0), rm_mem64, AsmError.InvalidOperand);
        testOp2(m64, .VLDDQU,     reg(.XMM0), rm_mem256, AsmError.InvalidOperand);
        testOp2(m64, .VLDDQU,     reg(.XMM0), rm_mem512, AsmError.InvalidOperand);
    }

    {
        // VMASKMOVDQU
        testOp2(m64, .VMASKMOVDQU,reg(.XMM0), reg(.XMM0), "c5f9f7c0");
    }

    {
        // VMAXPD
        testOp3(m64, .VMAXPD,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 f9 5f c0");
        testOp3(m64, .VMAXPD,     reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5 fd 5f c0");
        testOp3(m64, .VMAXPD,     pred(.XMM31, .K7, .Zero), reg(.XMM31), reg(.XMM31), "62 01 85 87 5f ff");
        testOp3(m64, .VMAXPD,     pred(.YMM31, .K7, .Zero), reg(.YMM31), reg(.YMM31), "62 01 85 a7 5f ff");
        testOp3(m64, .VMAXPD,     pred(.ZMM31, .K7, .Zero), reg(.ZMM31), sae(.ZMM31, .SAE), "62 01 85 d7 5f ff");
        // VMAXPS
        testOp3(m64, .VMAXPS,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 f8 5f c0");
        testOp3(m64, .VMAXPS,     reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5 fc 5f c0");
        testOp3(m64, .VMAXPS,     pred(.XMM31, .K7, .Zero), reg(.XMM31), reg(.XMM31), "62 01 04 87 5f ff");
        testOp3(m64, .VMAXPS,     pred(.YMM31, .K7, .Zero), reg(.YMM31), reg(.YMM31), "62 01 04 a7 5f ff");
        testOp3(m64, .VMAXPS,     pred(.ZMM31, .K7, .Zero), reg(.ZMM31), sae(.ZMM31, .SAE), "62 01 04 d7 5f ff");
        // VMAXSD
        testOp3(m64, .VMAXSD,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 fb 5f c0");
        testOp3(m64, .VMAXSD,     pred(.XMM31, .K7, .Zero), reg(.XMM31), sae(.XMM31, .SAE), "62 01 87 97 5f ff");
        // VMAXSS
        testOp3(m64, .VMAXSS,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 fa 5f c0");
        testOp3(m64, .VMAXSS,     pred(.XMM31, .K7, .Zero), reg(.XMM31), sae(.XMM31, .SAE), "62 01 06 97 5f ff");
        // VMINPD
        testOp3(m64, .VMINPD,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 f9 5d c0");
        testOp3(m64, .VMINPD,     reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5 fd 5d c0");
        testOp3(m64, .VMINPD,     pred(.XMM31, .K7, .Zero), reg(.XMM31), reg(.XMM31), "62 01 85 87 5d ff");
        testOp3(m64, .VMINPD,     pred(.YMM31, .K7, .Zero), reg(.YMM31), reg(.YMM31), "62 01 85 a7 5d ff");
        testOp3(m64, .VMINPD,     pred(.ZMM31, .K7, .Zero), reg(.ZMM31), sae(.ZMM31, .SAE), "62 01 85 d7 5d ff");
        // VMINPS
        testOp3(m64, .VMINPS,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 f8 5d c0");
        testOp3(m64, .VMINPS,     reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5 fc 5d c0");
        testOp3(m64, .VMINPS,     pred(.XMM31, .K7, .Zero), reg(.XMM31), reg(.XMM31), "62 01 04 87 5d ff");
        testOp3(m64, .VMINPS,     pred(.YMM31, .K7, .Zero), reg(.YMM31), reg(.YMM31), "62 01 04 a7 5d ff");
        testOp3(m64, .VMINPS,     pred(.ZMM31, .K7, .Zero), reg(.ZMM31), sae(.ZMM31, .SAE), "62 01 04 d7 5d ff");
        // VMINSD
        testOp3(m64, .VMINSD,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 fb 5d c0");
        testOp3(m64, .VMINSD,     pred(.XMM31, .K7, .Zero), reg(.XMM31), sae(.XMM31, .SAE), "62 01 87 97 5d ff");
        // VMINSS
        testOp3(m64, .VMINSS,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5 fa 5d c0");
        testOp3(m64, .VMINSS,     pred(.XMM31, .K7, .Zero), reg(.XMM31), sae(.XMM31, .SAE), "62 01 06 97 5d ff");
    }

    {
        // VMOVAPD
        testOp2(m64, .VMOVAPD,    reg(.XMM0), reg(.XMM0), "c5 f9 28 c0");
        testOp2(m64, .VMOVAPD,    reg(.YMM0), reg(.YMM0), "c5 fd 28 c0");
        testOp2(m64, .VMOVAPD,    regRm(.XMM0), reg(.XMM0), "c5 f9 29 c0");
        testOp2(m64, .VMOVAPD,    regRm(.YMM0), reg(.YMM0), "c5 fd 29 c0");
        testOp2(m64, .VMOVAPD,    pred(.XMM31, .K7, .Zero), reg(.XMM31), "62 01 fd 8f 28 ff");
        testOp2(m64, .VMOVAPD,    pred(.YMM31, .K7, .Zero), reg(.YMM31), "62 01 fd af 28 ff");
        testOp2(m64, .VMOVAPD,    pred(.ZMM31, .K7, .Zero), reg(.ZMM31), "62 01 fd cf 28 ff");
        testOp2(m64, .VMOVAPD,    predRm(reg(.XMM31), .K7, .Zero), reg(.XMM31), "62 01 fd 8f 29 ff");
        testOp2(m64, .VMOVAPD,    predRm(reg(.YMM31), .K7, .Zero), reg(.YMM31), "62 01 fd af 29 ff");
        testOp2(m64, .VMOVAPD,    predRm(reg(.ZMM31), .K7, .Zero), reg(.ZMM31), "62 01 fd cf 29 ff");
        testOp2(m64, .VMOVAPD,    predRm(rm_mem128, .K7, .Zero), reg(.XMM31), "67 62 61 fd 8f 29 38");
        testOp2(m64, .VMOVAPD,    predRm(rm_mem256, .K7, .Zero), reg(.YMM31), "67 62 61 fd af 29 38");
        testOp2(m64, .VMOVAPD,    predRm(rm_mem512, .K7, .Zero), reg(.ZMM31), "67 62 61 fd cf 29 38");
        testOp2(m64, .VMOVAPD,    pred(.XMM31, .K7, .Zero), rm_mem128, "67 62 61 fd 8f 28 38");
        testOp2(m64, .VMOVAPD,    pred(.YMM31, .K7, .Zero), rm_mem256, "67 62 61 fd af 28 38");
        testOp2(m64, .VMOVAPD,    pred(.ZMM31, .K7, .Zero), rm_mem512, "67 62 61 fd cf 28 38");
        //
        testOp2(m64, .VMOVAPD,    predRm(reg(.XMM31), .K7, .Zero), rm_mem128, AsmError.InvalidOperand);
        testOp2(m64, .VMOVAPD,    predRm(reg(.YMM31), .K7, .Zero), rm_mem256, AsmError.InvalidOperand);
        testOp2(m64, .VMOVAPD,    predRm(reg(.ZMM31), .K7, .Zero), rm_mem512, AsmError.InvalidOperand);
        testOp2(m64, .VMOVAPD,    predRm(rm_mem128, .K7, .Zero), rm_mem128, AsmError.InvalidOperand);
        testOp2(m64, .VMOVAPD,    predRm(rm_mem256, .K7, .Zero), rm_mem256, AsmError.InvalidOperand);
        testOp2(m64, .VMOVAPD,    predRm(rm_mem512, .K7, .Zero), rm_mem512, AsmError.InvalidOperand);
    }

    {
        // VMOVAPS
        testOp2(m64, .VMOVAPS,    reg(.XMM0), reg(.XMM0), "c5 f8 28 c0");
        testOp2(m64, .VMOVAPS,    reg(.YMM0), reg(.YMM0), "c5 fc 28 c0");
        testOp2(m64, .VMOVAPS,    regRm(.XMM0), reg(.XMM0), "c5 f8 29 c0");
        testOp2(m64, .VMOVAPS,    regRm(.YMM0), reg(.YMM0), "c5 fc 29 c0");
        testOp2(m64, .VMOVAPS,    pred(.XMM31, .K7, .Zero), reg(.XMM31), "62 01 7c 8f 28 ff");
        testOp2(m64, .VMOVAPS,    pred(.YMM31, .K7, .Zero), reg(.YMM31), "62 01 7c af 28 ff");
        testOp2(m64, .VMOVAPS,    pred(.ZMM31, .K7, .Zero), reg(.ZMM31), "62 01 7c cf 28 ff");
        testOp2(m64, .VMOVAPS,    predRm(reg(.XMM31), .K7, .Zero), reg(.XMM31), "62 01 7c 8f 29 ff");
        testOp2(m64, .VMOVAPS,    predRm(reg(.YMM31), .K7, .Zero), reg(.YMM31), "62 01 7c af 29 ff");
        testOp2(m64, .VMOVAPS,    predRm(reg(.ZMM31), .K7, .Zero), reg(.ZMM31), "62 01 7c cf 29 ff");
        testOp2(m64, .VMOVAPS,    predRm(rm_mem128, .K7, .Zero), reg(.XMM31), "67 62 61 7c 8f 29 38");
        testOp2(m64, .VMOVAPS,    predRm(rm_mem256, .K7, .Zero), reg(.YMM31), "67 62 61 7c af 29 38");
        testOp2(m64, .VMOVAPS,    predRm(rm_mem512, .K7, .Zero), reg(.ZMM31), "67 62 61 7c cf 29 38");
        testOp2(m64, .VMOVAPS,    pred(.XMM31, .K7, .Zero), rm_mem128, "67 62 61 7c 8f 28 38");
        testOp2(m64, .VMOVAPS,    pred(.YMM31, .K7, .Zero), rm_mem256, "67 62 61 7c af 28 38");
        testOp2(m64, .VMOVAPS,    pred(.ZMM31, .K7, .Zero), rm_mem512, "67 62 61 7c cf 28 38");
        //
        testOp2(m64, .VMOVAPS,    predRm(reg(.XMM31), .K7, .Zero), rm_mem128, AsmError.InvalidOperand);
        testOp2(m64, .VMOVAPS,    predRm(reg(.YMM31), .K7, .Zero), rm_mem256, AsmError.InvalidOperand);
        testOp2(m64, .VMOVAPS,    predRm(reg(.ZMM31), .K7, .Zero), rm_mem512, AsmError.InvalidOperand);
        testOp2(m64, .VMOVAPS,    predRm(rm_mem128, .K7, .Zero), rm_mem128, AsmError.InvalidOperand);
        testOp2(m64, .VMOVAPS,    predRm(rm_mem256, .K7, .Zero), rm_mem256, AsmError.InvalidOperand);
        testOp2(m64, .VMOVAPS,    predRm(rm_mem512, .K7, .Zero), rm_mem512, AsmError.InvalidOperand);
    }

    {
        testOp2(m64, .VMOVDDUP,   reg(.XMM0), reg(.XMM0), "c5 fb 12 c0");
        testOp2(m64, .VMOVDDUP,   reg(.YMM0), reg(.YMM0), "c5 ff 12 c0");
        testOp2(m64, .VMOVDDUP,   pred(.XMM31, .K7, .Zero), reg(.XMM31), "62 01 ff 8f 12 ff");
        testOp2(m64, .VMOVDDUP,   pred(.YMM31, .K7, .Zero), reg(.YMM31), "62 01 ff af 12 ff");
        testOp2(m64, .VMOVDDUP,   pred(.ZMM31, .K7, .Zero), reg(.ZMM31), "62 01 ff cf 12 ff");
    }

    {
        // VMOVDQA / VMOVDQA32 / VMOVDQA64
        testOp2(m64, .VMOVDQA,    reg(.XMM0), reg(.XMM0), "c5 f9 6f c0");
        testOp2(m64, .VMOVDQA,    reg(.YMM0), reg(.YMM0), "c5 fd 6f c0");
        testOp2(m64, .VMOVDQA,    regRm(.XMM0), reg(.XMM0), "c5 f9 7f c0");
        testOp2(m64, .VMOVDQA,    regRm(.YMM0), reg(.YMM0), "c5 fd 7f c0");
        // VMOVDQA32
        testOp2(m64, .VMOVDQA32,  pred(.XMM31, .K7, .Zero), reg(.XMM31), "62 01 7d 8f 6f ff");
        testOp2(m64, .VMOVDQA32,  pred(.YMM31, .K7, .Zero), reg(.YMM31), "62 01 7d af 6f ff");
        testOp2(m64, .VMOVDQA32,  pred(.ZMM31, .K7, .Zero), reg(.ZMM31), "62 01 7d cf 6f ff");
        testOp2(m64, .VMOVDQA32,  predRm(reg(.XMM31), .K7, .Zero), reg(.XMM31), "62 01 7d 8f 7f ff");
        testOp2(m64, .VMOVDQA32,  predRm(reg(.YMM31), .K7, .Zero), reg(.YMM31), "62 01 7d af 7f ff");
        testOp2(m64, .VMOVDQA32,  predRm(reg(.ZMM31), .K7, .Zero), reg(.ZMM31), "62 01 7d cf 7f ff");
        // VMOVDQA64
        testOp2(m64, .VMOVDQA64,  pred(.XMM31, .K7, .Zero), reg(.XMM31), "62 01 fd 8f 6f ff");
        testOp2(m64, .VMOVDQA64,  pred(.YMM31, .K7, .Zero), reg(.YMM31), "62 01 fd af 6f ff");
        testOp2(m64, .VMOVDQA64,  pred(.ZMM31, .K7, .Zero), reg(.ZMM31), "62 01 fd cf 6f ff");
        testOp2(m64, .VMOVDQA64,  predRm(reg(.XMM31), .K7, .Zero), reg(.XMM31), "62 01 fd 8f 7f ff");
        testOp2(m64, .VMOVDQA64,  predRm(reg(.YMM31), .K7, .Zero), reg(.YMM31), "62 01 fd af 7f ff");
        testOp2(m64, .VMOVDQA64,  predRm(reg(.ZMM31), .K7, .Zero), reg(.ZMM31), "62 01 fd cf 7f ff");
    }

    {
        testOp2(m64, .VMOVDQU,    reg(.XMM0), reg(.XMM0), "c5 fa 6f c0");
        testOp2(m64, .VMOVDQU,    reg(.YMM0), reg(.YMM0), "c5 fe 6f c0");
        testOp2(m64, .VMOVDQU,    reg(.XMM0), reg(.XMM0), "c5 fa 6f c0");
        testOp2(m64, .VMOVDQU,    reg(.YMM0), reg(.YMM0), "c5 fe 6f c0");
        // VMOVDQU8
        testOp2(m64, .VMOVDQU8,  pred(.XMM31, .K7, .Zero), reg(.XMM31), "62 01 7f 8f 6f ff");
        testOp2(m64, .VMOVDQU8,  pred(.YMM31, .K7, .Zero), reg(.YMM31), "62 01 7f af 6f ff");
        testOp2(m64, .VMOVDQU8,  pred(.ZMM31, .K7, .Zero), reg(.ZMM31), "62 01 7f cf 6f ff");
        testOp2(m64, .VMOVDQU8,  predRm(reg(.XMM31), .K7, .Zero), reg(.XMM31), "62 01 7f 8f 7f ff");
        testOp2(m64, .VMOVDQU8,  predRm(reg(.YMM31), .K7, .Zero), reg(.YMM31), "62 01 7f af 7f ff");
        testOp2(m64, .VMOVDQU8,  predRm(reg(.ZMM31), .K7, .Zero), reg(.ZMM31), "62 01 7f cf 7f ff");
        // VMOVDQU16
        testOp2(m64, .VMOVDQU16,  pred(.XMM31, .K7, .Zero), reg(.XMM31), "62 01 ff 8f 6f ff");
        testOp2(m64, .VMOVDQU16,  pred(.YMM31, .K7, .Zero), reg(.YMM31), "62 01 ff af 6f ff");
        testOp2(m64, .VMOVDQU16,  pred(.ZMM31, .K7, .Zero), reg(.ZMM31), "62 01 ff cf 6f ff");
        testOp2(m64, .VMOVDQU16,  predRm(reg(.XMM31), .K7, .Zero), reg(.XMM31), "62 01 ff 8f 7f ff");
        testOp2(m64, .VMOVDQU16,  predRm(reg(.YMM31), .K7, .Zero), reg(.YMM31), "62 01 ff af 7f ff");
        testOp2(m64, .VMOVDQU16,  predRm(reg(.ZMM31), .K7, .Zero), reg(.ZMM31), "62 01 ff cf 7f ff");
        // VMOVDQU32
        testOp2(m64, .VMOVDQU32,  pred(.XMM31, .K7, .Zero), reg(.XMM31), "62 01 7e 8f 6f ff");
        testOp2(m64, .VMOVDQU32,  pred(.YMM31, .K7, .Zero), reg(.YMM31), "62 01 7e af 6f ff");
        testOp2(m64, .VMOVDQU32,  pred(.ZMM31, .K7, .Zero), reg(.ZMM31), "62 01 7e cf 6f ff");
        testOp2(m64, .VMOVDQU32,  predRm(reg(.XMM31), .K7, .Zero), reg(.XMM31), "62 01 7e 8f 7f ff");
        testOp2(m64, .VMOVDQU32,  predRm(reg(.YMM31), .K7, .Zero), reg(.YMM31), "62 01 7e af 7f ff");
        testOp2(m64, .VMOVDQU32,  predRm(reg(.ZMM31), .K7, .Zero), reg(.ZMM31), "62 01 7e cf 7f ff");
        // VMOVDQU64
        testOp2(m64, .VMOVDQU64,  pred(.XMM31, .K7, .Zero), reg(.XMM31), "62 01 fe 8f 6f ff");
        testOp2(m64, .VMOVDQU64,  pred(.YMM31, .K7, .Zero), reg(.YMM31), "62 01 fe af 6f ff");
        testOp2(m64, .VMOVDQU64,  pred(.ZMM31, .K7, .Zero), reg(.ZMM31), "62 01 fe cf 6f ff");
        testOp2(m64, .VMOVDQU64,  predRm(reg(.XMM31), .K7, .Zero), reg(.XMM31), "62 01 fe 8f 7f ff");
        testOp2(m64, .VMOVDQU64,  predRm(reg(.YMM31), .K7, .Zero), reg(.YMM31), "62 01 fe af 7f ff");
        testOp2(m64, .VMOVDQU64,  predRm(reg(.ZMM31), .K7, .Zero), reg(.ZMM31), "62 01 fe cf 7f ff");
    }

    {
        // VMOVHLPS
        testOp3(m64, .VMOVHLPS,   reg(.XMM1), reg(.XMM2), reg(.XMM3), "c5 e8 12 cb");
        testOp3(m64, .VMOVHLPS,   reg(.XMM21), reg(.XMM22), reg(.XMM23), "62 a1 4c 00 12 ef");
        // VMOVHPD
        testOp3(m64, .VMOVHPD,    reg(.XMM1), reg(.XMM2), rm_mem64, "67 c5 e9 16 08");
        testOp2(m64, .VMOVHPD,    rm_mem64, reg(.XMM1), "67 c5 f9 17 08");
        testOp3(m64, .VMOVHPD,    reg(.XMM21), reg(.XMM22), rm_mem64, "67 62 e1 cd 00 16 28");
        testOp2(m64, .VMOVHPD,    rm_mem64, reg(.XMM21), "67 62 e1 fd 08 17 28");
        // VMOVHPS
        testOp3(m64, .VMOVHPS,    reg(.XMM1), reg(.XMM2), rm_mem64, "67 c5 e8 16 08");
        testOp2(m64, .VMOVHPS,    rm_mem64, reg(.XMM1), "67 c5 f8 17 08");
        testOp3(m64, .VMOVHPS,    reg(.XMM21), reg(.XMM22), rm_mem64, "67 62 e1 4c 00 16 28");
        testOp2(m64, .VMOVHPS,    rm_mem64, reg(.XMM21), "67 62 e1 7c 08 17 28");
        // VMOVLHPS
        testOp3(m64, .VMOVLHPS,   reg(.XMM1), reg(.XMM2), reg(.XMM3), "c5 e8 16 cb");
        testOp3(m64, .VMOVLHPS,   reg(.XMM21), reg(.XMM22), reg(.XMM23), "62 a1 4c 00 16 ef");
        // VMOVLPD
        testOp3(m64, .VMOVLPD,    reg(.XMM1), reg(.XMM2), rm_mem64, "67 c5 e9 12 08");
        testOp2(m64, .VMOVLPD,    rm_mem64, reg(.XMM1), "67 c5 f9 13 08");
        testOp3(m64, .VMOVLPD,    reg(.XMM21), reg(.XMM22), rm_mem64, "67 62 e1 cd 00 12 28");
        testOp2(m64, .VMOVLPD,    rm_mem64, reg(.XMM21), "67 62 e1 fd 08 13 28");
        // VMOVLPS
        testOp3(m64, .VMOVLPS,    reg(.XMM1), reg(.XMM2), rm_mem64, "67 c5 e8 12 08");
        testOp2(m64, .VMOVLPS,    rm_mem64, reg(.XMM1), "67 c5 f8 13 08");
        testOp3(m64, .VMOVLPS,    reg(.XMM21), reg(.XMM22), rm_mem64, "67 62 e1 4c 00 12 28");
        testOp2(m64, .VMOVLPS,    rm_mem64, reg(.XMM21), "67 62 e1 7c 08 13 28");
        // VMOVMSKPD
        testOp2(m64, .VMOVMSKPD,  reg(.EAX), reg(.XMM1), "c5 f9 50 c1");
        testOp2(m64, .VMOVMSKPD,  reg(.RAX), reg(.XMM1), "c5 f9 50 c1");
        testOp2(m64, .VMOVMSKPD,  reg(.EAX), reg(.YMM1), "c5 fd 50 c1");
        testOp2(m64, .VMOVMSKPD,  reg(.RAX), reg(.YMM1), "c5 fd 50 c1");
        // VMOVMSKPS
        testOp2(m64, .VMOVMSKPS,  reg(.EAX), reg(.XMM1), "c5 f8 50 c1");
        testOp2(m64, .VMOVMSKPS,  reg(.RAX), reg(.XMM1), "c5 f8 50 c1");
        testOp2(m64, .VMOVMSKPS,  reg(.EAX), reg(.YMM1), "c5 fc 50 c1");
        testOp2(m64, .VMOVMSKPS,  reg(.RAX), reg(.YMM1), "c5 fc 50 c1");
        // VMOVNTDQA
        testOp2(m64, .VMOVNTDQA,  reg(.XMM1), rm_mem128, "67 c4 e2 79 2a 08");
        testOp2(m64, .VMOVNTDQA,  reg(.YMM1), rm_mem256, "67 c4 e2 7d 2a 08");
        testOp2(m64, .VMOVNTDQA,  reg(.XMM21), rm_mem128, "67 62 e2 7d 08 2a 28");
        testOp2(m64, .VMOVNTDQA,  reg(.YMM21), rm_mem256, "67 62 e2 7d 28 2a 28");
        testOp2(m64, .VMOVNTDQA,  reg(.ZMM21), rm_mem512, "67 62 e2 7d 48 2a 28");
        // VMOVNTDQ
        testOp2(m64, .VMOVNTDQ,   rm_mem128, reg(.XMM1), "67 c5 f9 e7 08");
        testOp2(m64, .VMOVNTDQ,   rm_mem256, reg(.YMM1), "67 c5 fd e7 08");
        testOp2(m64, .VMOVNTDQ,   rm_mem128, reg(.XMM21), "67 62 e1 7d 08 e7 28");
        testOp2(m64, .VMOVNTDQ,   rm_mem256, reg(.YMM21), "67 62 e1 7d 28 e7 28");
        testOp2(m64, .VMOVNTDQ,   rm_mem512, reg(.ZMM21), "67 62 e1 7d 48 e7 28");
        // VMOVNTPD
        testOp2(m64, .VMOVNTPD,   rm_mem128, reg(.XMM1), "67 c5 f9 2b 08");
        testOp2(m64, .VMOVNTPD,   rm_mem256, reg(.YMM1), "67 c5 fd 2b 08");
        testOp2(m64, .VMOVNTPD,   rm_mem128, reg(.XMM21), "67 62 e1 fd 08 2b 28");
        testOp2(m64, .VMOVNTPD,   rm_mem256, reg(.YMM21), "67 62 e1 fd 28 2b 28");
        testOp2(m64, .VMOVNTPD,   rm_mem512, reg(.ZMM21), "67 62 e1 fd 48 2b 28");
        // VMOVNTPS
        testOp2(m64, .VMOVNTPS,   rm_mem128, reg(.XMM1), "67 c5 f8 2b 08");
        testOp2(m64, .VMOVNTPS,   rm_mem256, reg(.YMM1), "67 c5 fc 2b 08");
        testOp2(m64, .VMOVNTPS,   rm_mem128, reg(.XMM21), "67 62 e1 7c 08 2b 28");
        testOp2(m64, .VMOVNTPS,   rm_mem256, reg(.YMM21), "67 62 e1 7c 28 2b 28");
        testOp2(m64, .VMOVNTPS,   rm_mem512, reg(.ZMM21), "67 62 e1 7c 48 2b 28");
        // VMOVSD
        testOp3(m64, .VMOVSD,     reg(.XMM1), reg(.XMM2), reg(.XMM3), "c5 eb 10 cb");
        testOp2(m64, .VMOVSD,     reg(.XMM1), rm_mem64, "67 c5 fb 10 08");
        testOp3(m64, .VMOVSD,     regRm(.XMM1), reg(.XMM2), reg(.XMM3), "c5 eb 11 d9");
        testOp2(m64, .VMOVSD,     rm_mem64, reg(.XMM1), "67 c5 fb 11 08");
        testOp3(m64, .VMOVSD,     pred(.XMM31, .K7, .Zero), reg(.XMM21), reg(.XMM22), "62 21 d7 87 10 fe");
        testOp2(m64, .VMOVSD,     pred(.XMM31, .K7, .Zero), rm_mem64, "67 62 61 ff 8f 10 38");
        testOp3(m64, .VMOVSD,     predRm(reg(.XMM31), .K7, .Zero), reg(.XMM21), reg(.XMM22), "62 81 d7 87 11 f7");
        testOp2(m64, .VMOVSD,     predRm(rm_mem64, .K7, .Zero), reg(.XMM21), "67 62 e1 ff 8f 11 28");
        // VMOVSHDUP
        testOp2(m64, .VMOVSHDUP,  reg(.XMM1), reg(.XMM0), "c5 fa 16 c8");
        testOp2(m64, .VMOVSHDUP,  reg(.YMM1), reg(.YMM0), "c5 fe 16 c8");
        testOp2(m64, .VMOVSHDUP,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 21 7e 8f 16 fc");
        testOp2(m64, .VMOVSHDUP,  pred(.YMM31, .K7, .Zero), regRm(.YMM20), "62 21 7e af 16 fc");
        testOp2(m64, .VMOVSHDUP,  pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), "62 21 7e cf 16 fc");
        // VMOVSLDUP
        testOp2(m64, .VMOVSLDUP,  reg(.XMM1), reg(.XMM0), "c5 fa 12 c8");
        testOp2(m64, .VMOVSLDUP,  reg(.YMM1), reg(.YMM0), "c5 fe 12 c8");
        testOp2(m64, .VMOVSLDUP,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 21 7e 8f 12 fc");
        testOp2(m64, .VMOVSLDUP,  pred(.YMM31, .K7, .Zero), regRm(.YMM20), "62 21 7e af 12 fc");
        testOp2(m64, .VMOVSLDUP,  pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), "62 21 7e cf 12 fc");
        // VMOVSS
        testOp3(m64, .VMOVSS,     reg(.XMM1), reg(.XMM2), reg(.XMM3), "c5 ea 10 cb");
        testOp2(m64, .VMOVSS,     reg(.XMM1), rm_mem64, "67 c5 fa 10 08");
        testOp3(m64, .VMOVSS,     regRm(.XMM1), reg(.XMM2), reg(.XMM3), "c5 ea 11 d9");
        testOp2(m64, .VMOVSS,     rm_mem64, reg(.XMM1), "67 c5 fa 11 08");
        testOp3(m64, .VMOVSS,     pred(.XMM31, .K7, .Zero), reg(.XMM21), reg(.XMM22), "62 21 56 87 10 fe");
        testOp2(m64, .VMOVSS,     pred(.XMM31, .K7, .Zero), rm_mem64, "67 62 61 7e 8f 10 38");
        testOp3(m64, .VMOVSS,     predRm(reg(.XMM31), .K7, .Zero), reg(.XMM21), reg(.XMM22), "62 81 56 87 11 f7");
        testOp2(m64, .VMOVSS,     predRm(rm_mem64, .K7, .Zero), reg(.XMM21), "67 62 e1 7e 8f 11 28");
        // VMOVUPD
        testOp2(m64, .VMOVUPD,    reg(.XMM1), regRm(.XMM0), "c5 f9 10 c8");
        testOp2(m64, .VMOVUPD,    reg(.YMM1), regRm(.YMM0), "c5 fd 10 c8");
        testOp2(m64, .VMOVUPD,    regRm(.XMM0), reg(.XMM1), "c5 f9 11 c8");
        testOp2(m64, .VMOVUPD,    regRm(.YMM0), reg(.YMM1), "c5 fd 11 c8");
        testOp2(m64, .VMOVUPD,    pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 21 fd 8f 10 fc");
        testOp2(m64, .VMOVUPD,    pred(.YMM31, .K7, .Zero), regRm(.YMM20), "62 21 fd af 10 fc");
        testOp2(m64, .VMOVUPD,    pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), "62 21 fd cf 10 fc");
        testOp2(m64, .VMOVUPD,    reg(.XMM20), regRm(.XMM21), "62 a1 fd 08 10 e5");
        testOp2(m64, .VMOVUPD,    reg(.YMM20), regRm(.YMM21), "62 a1 fd 28 10 e5");
        testOp2(m64, .VMOVUPD,    reg(.ZMM20), regRm(.ZMM21), "62 a1 fd 48 10 e5");
        testOp2(m64, .VMOVUPD,    regRm(.XMM20), reg(.XMM21), "62 a1 fd 08 11 ec");
        testOp2(m64, .VMOVUPD,    regRm(.YMM20), reg(.YMM21), "62 a1 fd 28 11 ec");
        testOp2(m64, .VMOVUPD,    regRm(.ZMM20), reg(.ZMM21), "62 a1 fd 48 11 ec");
        // VMOVUPS
        testOp2(m64, .VMOVUPS,    reg(.XMM1), regRm(.XMM0), "c5 f8 10 c8");
        testOp2(m64, .VMOVUPS,    reg(.YMM1), regRm(.YMM0), "c5 fc 10 c8");
        testOp2(m64, .VMOVUPS,    regRm(.XMM0), reg(.XMM1), "c5 f8 11 c8");
        testOp2(m64, .VMOVUPS,    regRm(.YMM0), reg(.YMM1), "c5 fc 11 c8");
        testOp2(m64, .VMOVUPS,    pred(.XMM31, .K7, .Zero), reg(.XMM20), "62 21 7c 8f 10 fc");
        testOp2(m64, .VMOVUPS,    pred(.YMM31, .K7, .Zero), reg(.YMM20), "62 21 7c af 10 fc");
        testOp2(m64, .VMOVUPS,    pred(.ZMM31, .K7, .Zero), reg(.ZMM20), "62 21 7c cf 10 fc");
        testOp2(m64, .VMOVUPS,    reg(.XMM20), regRm(.XMM21), "62 a1 7c 08 10 e5");
        testOp2(m64, .VMOVUPS,    reg(.YMM20), regRm(.YMM21), "62 a1 7c 28 10 e5");
        testOp2(m64, .VMOVUPS,    reg(.ZMM20), regRm(.ZMM21), "62 a1 7c 48 10 e5");
        testOp2(m64, .VMOVUPS,    regRm(.XMM20), reg(.XMM21), "62 a1 7c 08 11 ec");
        testOp2(m64, .VMOVUPS,    regRm(.YMM20), reg(.YMM21), "62 a1 7c 28 11 ec");
        testOp2(m64, .VMOVUPS,    regRm(.ZMM20), reg(.ZMM21), "62 a1 7c 48 11 ec");
    }

    {
        // VMPSADBW
        testOp4(m64, .VMPSADBW,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), imm(0), "c4 e3 69 42 c8 00");
        testOp4(m64, .VMPSADBW,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), imm(0), "c4 e3 6d 42 c8 00");
        // VMULPD
        testOp3(m64, .VMULPD,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 59 c8");
        testOp3(m64, .VMULPD,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 59 c8");
        testOp3(m64, .VMULPD,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 59 fc");
        testOp3(m64, .VMULPD,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 59 fc");
        testOp3(m64, .VMULPD,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), sae(.ZMM30, .RN_SAE), "62 01 d5 97 59 fe");
        // VMULPS
        testOp3(m64, .VMULPS,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e8 59 c8");
        testOp3(m64, .VMULPS,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ec 59 c8");
        testOp3(m64, .VMULPS,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 54 87 59 fc");
        testOp3(m64, .VMULPS,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 54 a7 59 fc");
        testOp3(m64, .VMULPS,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), sae(.ZMM30, .RN_SAE), "62 01 54 97 59 fe");
        // VMULSD
        testOp3(m64, .VMULSD,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 eb 59 c8");
        testOp3(m64, .VMULSD,     pred(.XMM31, .K7, .Zero), reg(.XMM21), sae(.XMM30, .RN_SAE), "62 01 d7 97 59 fe");
        // VMULSS
        testOp3(m64, .VMULSS,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 ea 59 c8");
        testOp3(m64, .VMULSS,     pred(.XMM31, .K7, .Zero), reg(.XMM21), sae(.XMM30, .RN_SAE), "62 01 56 97 59 fe");
    }

    {
        // VORPD
        testOp3(m64, .VORPD,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 56 c8");
        testOp3(m64, .VORPD,      reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 56 c8");
        testOp3(m64, .VORPD,      pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 56 fc");
        testOp3(m64, .VORPD,      pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 56 fc");
        testOp3(m64, .VORPD,      pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 d5 c7 56 fc");
        // VORPS
        testOp3(m64, .VORPS,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e8 56 c8");
        testOp3(m64, .VORPS,      reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ec 56 c8");
        testOp3(m64, .VORPS,      pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 54 87 56 fc");
        testOp3(m64, .VORPS,      pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 54 a7 56 fc");
        testOp3(m64, .VORPS,      pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 54 c7 56 fc");
    }

    //
    // VPxxxxx
    //

    {
        // VPABSB / VPABSW / VPABSD / VPABSQ
        testOp2(m64, .VPABSB,     reg(.XMM1), regRm(.XMM0), "c4 e2 79 1c c8");
        testOp2(m64, .VPABSB,     reg(.YMM1), regRm(.YMM0), "c4 e2 7d 1c c8");
        testOp2(m64, .VPABSB,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 1c fc");
        testOp2(m64, .VPABSB,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), "62 22 7d af 1c fc");
        testOp2(m64, .VPABSB,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), "62 22 7d cf 1c fc");
        // VPABSW
        testOp2(m64, .VPABSW,     reg(.XMM1), regRm(.XMM0), "c4 e2 79 1d c8");
        testOp2(m64, .VPABSW,     reg(.YMM1), regRm(.YMM0), "c4 e2 7d 1d c8");
        testOp2(m64, .VPABSW,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 1d fc");
        testOp2(m64, .VPABSW,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), "62 22 7d af 1d fc");
        testOp2(m64, .VPABSW,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), "62 22 7d cf 1d fc");
        // VPABSD
        testOp2(m64, .VPABSD,     reg(.XMM1), regRm(.XMM0), "c4 e2 79 1e c8");
        testOp2(m64, .VPABSD,     reg(.YMM1), regRm(.YMM0), "c4 e2 7d 1e c8");
        testOp2(m64, .VPABSD,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 1e fc");
        testOp2(m64, .VPABSD,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), "62 22 7d af 1e fc");
        testOp2(m64, .VPABSD,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), "62 22 7d cf 1e fc");
        // VPABSQ
        testOp2(m64, .VPABSQ,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 fd 8f 1f fc");
        testOp2(m64, .VPABSQ,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), "62 22 fd af 1f fc");
        testOp2(m64, .VPABSQ,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), "62 22 fd cf 1f fc");
        // VPACKSSWB / PACKSSDW
        // VPACKSSWB
        testOp3(m64, .VPACKSSWB,  reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 63 c8");
        testOp3(m64, .VPACKSSWB,  reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 63 c8");
        testOp3(m64, .VPACKSSWB,  pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 63 fc");
        testOp3(m64, .VPACKSSWB,  pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 63 fc");
        testOp3(m64, .VPACKSSWB,  pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 63 fc");
        // VPACKSSDW
        testOp3(m64, .VPACKSSDW,  reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 6b c8");
        testOp3(m64, .VPACKSSDW,  reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 6b c8");
        testOp3(m64, .VPACKSSDW,  pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 6b fc");
        testOp3(m64, .VPACKSSDW,  pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 6b fc");
        testOp3(m64, .VPACKSSDW,  pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 6b fc");
        // VPACKUSWB
        testOp3(m64, .VPACKUSWB,  reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 67 c8");
        testOp3(m64, .VPACKUSWB,  reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 67 c8");
        testOp3(m64, .VPACKUSWB,  pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 67 fc");
        testOp3(m64, .VPACKUSWB,  pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 67 fc");
        testOp3(m64, .VPACKUSWB,  pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 67 fc");
        // VPACKUSDW
        testOp3(m64, .VPACKUSDW,  reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 2b c8");
        testOp3(m64, .VPACKUSDW,  reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 2b c8");
        testOp3(m64, .VPACKUSDW,  pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 2b fc");
        testOp3(m64, .VPACKUSDW,  pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 2b fc");
        testOp3(m64, .VPACKUSDW,  pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 2b fc");
        // VPADDB / PADDW / PADDD / PADDQ
        testOp3(m64, .VPADDB,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 fc c8");
        testOp3(m64, .VPADDB,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed fc c8");
        testOp3(m64, .VPADDB,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 fc fc");
        testOp3(m64, .VPADDB,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 fc fc");
        testOp3(m64, .VPADDB,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 fc fc");
        // VPADDW
        testOp3(m64, .VPADDW,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 fd c8");
        testOp3(m64, .VPADDW,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed fd c8");
        testOp3(m64, .VPADDW,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 fd fc");
        testOp3(m64, .VPADDW,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 fd fc");
        testOp3(m64, .VPADDW,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 fd fc");
        // VPADDD
        testOp3(m64, .VPADDD,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 fe c8");
        testOp3(m64, .VPADDD,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed fe c8");
        testOp3(m64, .VPADDD,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 fe fc");
        testOp3(m64, .VPADDD,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 fe fc");
        testOp3(m64, .VPADDD,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 fe fc");
        // VPADDQ
        testOp3(m64, .VPADDQ,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 d4 c8");
        testOp3(m64, .VPADDQ,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed d4 c8");
        testOp3(m64, .VPADDQ,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 d4 fc");
        testOp3(m64, .VPADDQ,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 d4 fc");
        testOp3(m64, .VPADDQ,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 d5 c7 d4 fc");
        // VPADDSB / PADDSW
        testOp3(m64, .VPADDSB,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 ec c8");
        testOp3(m64, .VPADDSB,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed ec c8");
        testOp3(m64, .VPADDSB,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 ec fc");
        testOp3(m64, .VPADDSB,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 ec fc");
        testOp3(m64, .VPADDSB,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 ec fc");
        //
        testOp3(m64, .VPADDSW,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 ed c8");
        testOp3(m64, .VPADDSW,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed ed c8");
        testOp3(m64, .VPADDSW,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 ed fc");
        testOp3(m64, .VPADDSW,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 ed fc");
        testOp3(m64, .VPADDSW,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 ed fc");
        // VPADDUSB / PADDUSW
        testOp3(m64, .VPADDUSB,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 dc c8");
        testOp3(m64, .VPADDUSB,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed dc c8");
        testOp3(m64, .VPADDUSB,   pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 dc fc");
        testOp3(m64, .VPADDUSB,   pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 dc fc");
        testOp3(m64, .VPADDUSB,   pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 dc fc");
        //
        testOp3(m64, .VPADDUSW,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 dd c8");
        testOp3(m64, .VPADDUSW,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed dd c8");
        testOp3(m64, .VPADDUSW,   pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 dd fc");
        testOp3(m64, .VPADDUSW,   pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 dd fc");
        testOp3(m64, .VPADDUSW,   pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 dd fc");
        // VPALIGNR
        testOp4(m64, .VPALIGNR,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), imm(0), "c4 e3 69 0f c8 00");
        testOp4(m64, .VPALIGNR,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), imm(0), "c4 e3 6d 0f c8 00");
        testOp4(m64, .VPALIGNR,   pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), imm(0), "62 23 55 87 0f fc 00");
        testOp4(m64, .VPALIGNR,   pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), imm(0), "62 23 55 a7 0f fc 00");
        testOp4(m64, .VPALIGNR,   pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), imm(0), "62 23 55 c7 0f fc 00");
    }

    {
        // VPAND
        testOp3(m64, .VPAND,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 db c8");
        testOp3(m64, .VPAND,      reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed db c8");
        testOp3(m64, .VPANDD,      pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 db fc");
        testOp3(m64, .VPANDD,      pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 db fc");
        testOp3(m64, .VPANDD,      pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 db fc");
        testOp3(m64, .VPANDQ,      pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 db fc");
        testOp3(m64, .VPANDQ,      pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 db fc");
        testOp3(m64, .VPANDQ,      pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 d5 c7 db fc");
        // VPANDN
        testOp3(m64, .VPANDN,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 df c8");
        testOp3(m64, .VPANDN,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed df c8");
        testOp3(m64, .VPANDND,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 df fc");
        testOp3(m64, .VPANDND,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 df fc");
        testOp3(m64, .VPANDND,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 df fc");
        testOp3(m64, .VPANDNQ,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 df fc");
        testOp3(m64, .VPANDNQ,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 df fc");
        testOp3(m64, .VPANDNQ,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 d5 c7 df fc");
        // VPAVGB / VPAVGW
        testOp3(m64, .VPAVGB,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 e0 c8");
        testOp3(m64, .VPAVGB,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed e0 c8");
        testOp3(m64, .VPAVGB,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 e0 fc");
        testOp3(m64, .VPAVGB,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 e0 fc");
        testOp3(m64, .VPAVGB,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 e0 fc");
        //
        testOp3(m64, .VPAVGW,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 e3 c8");
        testOp3(m64, .VPAVGW,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed e3 c8");
        testOp3(m64, .VPAVGW,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 e3 fc");
        testOp3(m64, .VPAVGW,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 e3 fc");
        testOp3(m64, .VPAVGW,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 e3 fc");
        // VPBLENDVB
        testOp4(m64, .VPBLENDVB,  reg(.XMM1), reg(.XMM2), regRm(.XMM0), reg(.XMM3), "c4 e3 69 4c c8 30");
        testOp4(m64, .VPBLENDVB,  reg(.YMM1), reg(.YMM2), regRm(.YMM0), reg(.YMM3), "c4 e3 6d 4c c8 30");
        // VPBLENDDW
        testOp4(m64, .VPBLENDW,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), imm(0), "c4 e3 69 0e c8 00");
        testOp4(m64, .VPBLENDW,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), imm(0), "c4 e3 6d 0e c8 00");
        // VPCLMULQDQ
        testOp4(m64, .VPCLMULQDQ, reg(.XMM1), reg(.XMM2), regRm(.XMM0), imm(0), "c4 e3 69 44 c8 00");
        testOp4(m64, .VPCLMULQDQ, reg(.YMM1), reg(.YMM2), regRm(.YMM0), imm(0), "c4 e3 6d 44 c8 00");
        testOp4(m64, .VPCLMULQDQ, reg(.XMM21), reg(.XMM22), regRm(.XMM20), imm(0), "62 a3 4d 00 44 ec 00");
        testOp4(m64, .VPCLMULQDQ, reg(.YMM21), reg(.YMM22), regRm(.YMM20), imm(0), "62 a3 4d 20 44 ec 00");
        testOp4(m64, .VPCLMULQDQ, reg(.ZMM21), reg(.ZMM22), regRm(.ZMM20), imm(0), "62 a3 4d 40 44 ec 00");
    }

    {
        // VPCMPEQB / VPCMPEQW / VPCMPEQD
        testOp3(m64, .VPCMPEQB,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 74 c8");
        testOp3(m64, .VPCMPEQB,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 74 c8");
        testOp3(m64, .VPCMPEQB,   pred(.K0, .K7, .Merge), reg(.XMM21), regRm(.XMM20), "62 b1 55 07 74 c4");
        testOp3(m64, .VPCMPEQB,   pred(.K0, .K7, .Merge), reg(.YMM21), regRm(.YMM20), "62 b1 55 27 74 c4");
        testOp3(m64, .VPCMPEQB,   pred(.K0, .K7, .Merge), reg(.ZMM21), regRm(.ZMM20), "62 b1 55 47 74 c4");
        // VPCMPEQW
        testOp3(m64, .VPCMPEQW,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 75 c8");
        testOp3(m64, .VPCMPEQW,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 75 c8");
        testOp3(m64, .VPCMPEQW,   pred(.K0, .K7, .Merge), reg(.XMM21), regRm(.XMM20), "62 b1 55 07 75 c4");
        testOp3(m64, .VPCMPEQW,   pred(.K0, .K7, .Merge), reg(.YMM21), regRm(.YMM20), "62 b1 55 27 75 c4");
        testOp3(m64, .VPCMPEQW,   pred(.K0, .K7, .Merge), reg(.ZMM21), regRm(.ZMM20), "62 b1 55 47 75 c4");
        // VPCMPEQD
        testOp3(m64, .VPCMPEQD,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 76 c8");
        testOp3(m64, .VPCMPEQD,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 76 c8");
        testOp3(m64, .VPCMPEQD,   pred(.K0, .K7, .Merge), reg(.XMM21), regRm(.XMM20), "62 b1 55 07 76 c4");
        testOp3(m64, .VPCMPEQD,   pred(.K0, .K7, .Merge), reg(.YMM21), regRm(.YMM20), "62 b1 55 27 76 c4");
        testOp3(m64, .VPCMPEQD,   pred(.K0, .K7, .Merge), reg(.ZMM21), regRm(.ZMM20), "62 b1 55 47 76 c4");
        // VPCMPEQQ
        testOp3(m64, .VPCMPEQQ,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 29 c8");
        testOp3(m64, .VPCMPEQQ,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 29 c8");
        testOp3(m64, .VPCMPEQQ,   pred(.K0, .K7, .Merge), reg(.XMM21), regRm(.XMM20), "62 b2 d5 07 29 c4");
        testOp3(m64, .VPCMPEQQ,   pred(.K0, .K7, .Merge), reg(.YMM21), regRm(.YMM20), "62 b2 d5 27 29 c4");
        testOp3(m64, .VPCMPEQQ,   pred(.K0, .K7, .Merge), reg(.ZMM21), regRm(.ZMM20), "62 b2 d5 47 29 c4");
        // VPCMPESTRI
        testOp3(m64, .VPCMPESTRI, reg(.XMM1),regRm(.XMM0),imm(0), "c4 e3 79 61 c8 00");
        // VPCMPESTRM
        testOp3(m64, .VPCMPESTRM, reg(.XMM1),regRm(.XMM0),imm(0), "c4 e3 79 60 c8 00");
        // VPCMPGTB / VPCMPGTW / VPCMPGTD
        testOp3(m64, .VPCMPGTB,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 64 c8");
        testOp3(m64, .VPCMPGTB,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 64 c8");
        testOp3(m64, .VPCMPGTB,   pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 64 fc");
        testOp3(m64, .VPCMPGTB,   pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 64 fc");
        testOp3(m64, .VPCMPGTB,   pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 64 fc");
        // VPCMPGTW
        testOp3(m64, .VPCMPGTW,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 65 c8");
        testOp3(m64, .VPCMPGTW,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 65 c8");
        testOp3(m64, .VPCMPGTW,   pred(.K0, .K7, .Merge),reg(.XMM21),regRm(.XMM20), "62 b1 55 07 65 c4");
        testOp3(m64, .VPCMPGTW,   pred(.K0, .K7, .Merge),reg(.YMM21),regRm(.YMM20), "62 b1 55 27 65 c4");
        testOp3(m64, .VPCMPGTW,   pred(.K0, .K7, .Merge),reg(.ZMM21),regRm(.ZMM20), "62 b1 55 47 65 c4");
        // VPCMPGTD
        testOp3(m64, .VPCMPGTD,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 66 c8");
        testOp3(m64, .VPCMPGTD,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 66 c8");
        testOp3(m64, .VPCMPGTD,   pred(.K0, .K7, .Merge),reg(.XMM21),regRm(.XMM20), "62 b1 55 07 66 c4");
        testOp3(m64, .VPCMPGTD,   pred(.K0, .K7, .Merge),reg(.YMM21),regRm(.YMM20), "62 b1 55 27 66 c4");
        testOp3(m64, .VPCMPGTD,   pred(.K0, .K7, .Merge),reg(.ZMM21),regRm(.ZMM20), "62 b1 55 47 66 c4");
        // VPCMPGTQ
        testOp3(m64, .VPCMPGTQ,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 37 c8");
        testOp3(m64, .VPCMPGTQ,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 37 c8");
        testOp3(m64, .VPCMPGTQ,   pred(.K0, .K7, .Merge),reg(.XMM21),regRm(.XMM20), "62 b2 d5 07 37 c4");
        testOp3(m64, .VPCMPGTQ,   pred(.K0, .K7, .Merge),reg(.YMM21),regRm(.YMM20), "62 b2 d5 27 37 c4");
        testOp3(m64, .VPCMPGTQ,   pred(.K0, .K7, .Merge),reg(.ZMM21),regRm(.ZMM20), "62 b2 d5 47 37 c4");
        // VPCMPISTRI
        testOp3(m64, .VPCMPISTRI, reg(.XMM1),regRm(.XMM0),imm(0), "c4 e3 79 63 c8 00");
        // VPCMPISTRM
        testOp3(m64, .VPCMPISTRM, reg(.XMM1),regRm(.XMM0),imm(0), "c4 e3 79 62 c8 00");
    }

    {
        // VPEXTRB / VPEXTRD / VPEXTRQ
        testOp3(m64, .VPEXTRB,    rm_mem8, reg(.XMM1), imm(0), "67 c4 e3 79 14 08 00");
        testOp3(m64, .VPEXTRB,    regRm(.EAX), reg(.XMM1), imm(0), "c4 e3 79 14 c8 00");
        testOp3(m64, .VPEXTRB,    regRm(.RAX), reg(.XMM1), imm(0), "c4 e3 79 14 c8 00");
        testOp3(m64, .VPEXTRB,    rm_mem8, reg(.XMM21), imm(0), "67 62 e3 7d 08 14 28 00");
        testOp3(m64, .VPEXTRB,    reg(.EAX), reg(.XMM21), imm(0), "62 e3 7d 08 14 e8 00");
        testOp3(m64, .VPEXTRB,    reg(.RAX), reg(.XMM21), imm(0), "62 e3 7d 08 14 e8 00");
        //
        testOp3(m64, .VPEXTRD,    rm32, reg(.XMM1), imm(0), "67 c4 e3 79 16 08 00");
        testOp3(m64, .VPEXTRD,    rm32, reg(.XMM21), imm(0), "67 62 e3 7d 08 16 28 00");
        //
        testOp3(m64, .VPEXTRQ,    rm64, reg(.XMM1), imm(0), "67 c4 e3 f9 16 08 00");
        testOp3(m64, .VPEXTRQ,    rm64, reg(.XMM21), imm(0), "67 62 e3 fd 08 16 28 00");
        // VPEXTRW
        testOp3(m64, .VPEXTRW,    reg(.EAX), reg(.XMM1), imm(0), "c5 f9 c5 c1 00");
        testOp3(m64, .VPEXTRW,    reg(.RAX), reg(.XMM1), imm(0), "c5 f9 c5 c1 00");
        testOp3(m64, .VPEXTRW,    rm_mem16, reg(.XMM1), imm(0), "67 c4 e3 79 15 08 00");
        testOp3(m64, .VPEXTRW,    regRm(.EAX), reg(.XMM1), imm(0), "c4 e3 79 15 c8 00");
        testOp3(m64, .VPEXTRW,    regRm(.RAX), reg(.XMM1), imm(0), "c4 e3 79 15 c8 00");
        testOp3(m64, .VPEXTRW,    reg(.EAX), reg(.XMM21), imm(0), "62 b1 7d 08 c5 c5 00");
        testOp3(m64, .VPEXTRW,    reg(.RAX), reg(.XMM21), imm(0), "62 b1 7d 08 c5 c5 00");
        testOp3(m64, .VPEXTRW,    rm_mem16, reg(.XMM21), imm(0), "67 62 e3 7d 08 15 28 00");
        testOp3(m64, .VPEXTRW,    regRm(.EAX), reg(.XMM21), imm(0), "62 e3 7d 08 15 e8 00");
        testOp3(m64, .VPEXTRW,    regRm(.RAX), reg(.XMM21), imm(0), "62 e3 7d 08 15 e8 00");
    }

    {
        // VPHADDW / VPHADDD
        testOp3(m64, .VPHADDW,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 01 c8");
        testOp3(m64, .VPHADDW,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 01 c8");
        //
        testOp3(m64, .VPHADDD,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 02 c8");
        testOp3(m64, .VPHADDD,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 02 c8");
        // VPHADDSW
        testOp3(m64, .VPHADDSW,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 03 c8");
        testOp3(m64, .VPHADDSW,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 03 c8");
        // VPHMINPOSUW
        testOp2(m64, .VPHMINPOSUW,reg(.XMM1), regRm(.XMM0), "c4 e2 79 41 c8");
        // VPHSUBW / VPHSUBD
        testOp3(m64, .VPHSUBW,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 05 c8");
        testOp3(m64, .VPHSUBW,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 05 c8");
        //
        testOp3(m64, .VPHSUBD,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 06 c8");
        testOp3(m64, .VPHSUBD,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 06 c8");
        // VPHSUBSW
        testOp3(m64, .VPHSUBSW,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 07 c8");
        testOp3(m64, .VPHSUBSW,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 07 c8");
        // VPINSRB / VPINSRD / VPINSRQ
        testOp4(m64, .VPINSRB,    reg(.XMM1), reg(.XMM2), rm_mem8, imm(0), "67 c4 e3 69 20 08 00");
        testOp4(m64, .VPINSRB,    reg(.XMM1), reg(.XMM2), regRm(.EAX), imm(0), "c4 e3 69 20 c8 00");
        testOp4(m64, .VPINSRB,    reg(.XMM21), reg(.XMM22), rm_mem8, imm(0), "67 62 e3 4d 00 20 28 00");
        testOp4(m64, .VPINSRB,    reg(.XMM21), reg(.XMM22), regRm(.EAX), imm(0), "62 e3 4d 00 20 e8 00");
        //
        testOp4(m64, .VPINSRD,    reg(.XMM1), reg(.XMM2), rm32, imm(0), "67 c4 e3 69 22 08 00");
        testOp4(m64, .VPINSRD,    reg(.XMM21), reg(.XMM22), rm32, imm(0), "67 62 e3 4d 00 22 28 00");
        //
        testOp4(m64, .VPINSRQ,    reg(.XMM1), reg(.XMM2), rm64, imm(0), "67 c4 e3 e9 22 08 00");
        testOp4(m64, .VPINSRQ,    reg(.XMM21), reg(.XMM22), rm64, imm(0), "67 62 e3 cd 00 22 28 00");
        // VPINSRW
        testOp4(m64, .VPINSRW,    reg(.XMM1), reg(.XMM2), rm_mem16, imm(0), "67 c5 e9 c4 08 00");
        testOp4(m64, .VPINSRW,    reg(.XMM1), reg(.XMM2), regRm(.EAX), imm(0), "c5 e9 c4 c8 00");
        testOp4(m64, .VPINSRW,    reg(.XMM1), reg(.XMM2), regRm(.RAX), imm(0), "c5 e9 c4 c8 00");
        testOp4(m64, .VPINSRW,    reg(.XMM21), reg(.XMM22), rm_mem16, imm(0), "67 62 e1 4d 00 c4 28 00");
        testOp4(m64, .VPINSRW,    reg(.XMM21), reg(.XMM22), regRm(.EAX), imm(0), "62 e1 4d 00 c4 e8 00");
        testOp4(m64, .VPINSRW,    reg(.XMM21), reg(.XMM22), regRm(.RAX), imm(0), "62 e1 4d 00 c4 e8 00");
        // VPMADDUBSW
        testOp3(m64, .VPMADDUBSW, reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 04 c8");
        testOp3(m64, .VPMADDUBSW, reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 04 c8");
        testOp3(m64, .VPMADDUBSW, pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 04 fc");
        testOp3(m64, .VPMADDUBSW, pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 04 fc");
        testOp3(m64, .VPMADDUBSW, pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 04 fc");
        // VPMADDWD
        testOp3(m64, .VPMADDWD,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 f5 c8");
        testOp3(m64, .VPMADDWD,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed f5 c8");
        testOp3(m64, .VPMADDWD,   pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 f5 fc");
        testOp3(m64, .VPMADDWD,   pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 f5 fc");
        testOp3(m64, .VPMADDWD,   pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 f5 fc");
        // VPMAXSB / VPMAXSW / VPMAXSD / VPMAXSQ
        // VPMAXSB
        testOp3(m64, .VPMAXSB,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 3c c8");
        testOp3(m64, .VPMAXSB,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 3c c8");
        testOp3(m64, .VPMAXSB,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 3c fc");
        testOp3(m64, .VPMAXSB,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 3c fc");
        testOp3(m64, .VPMAXSB,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 3c fc");
        // VPMAXSW
        testOp3(m64, .VPMAXSW,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 ee c8");
        testOp3(m64, .VPMAXSW,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed ee c8");
        testOp3(m64, .VPMAXSW,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 ee fc");
        testOp3(m64, .VPMAXSW,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 ee fc");
        testOp3(m64, .VPMAXSW,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 ee fc");
        // VPMAXSD
        testOp3(m64, .VPMAXSD,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 3d c8");
        testOp3(m64, .VPMAXSD,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 3d c8");
        testOp3(m64, .VPMAXSD,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 3d fc");
        testOp3(m64, .VPMAXSD,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 3d fc");
        testOp3(m64, .VPMAXSD,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 3d fc");
        // VPMAXSQ
        testOp3(m64, .VPMAXSQ,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 d5 87 3d fc");
        testOp3(m64, .VPMAXSQ,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 d5 a7 3d fc");
        testOp3(m64, .VPMAXSQ,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 d5 c7 3d fc");
        // VPMAXUB / VPMAXUW
        // VPMAXUB
        testOp3(m64, .VPMAXUB,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 de c8");
        testOp3(m64, .VPMAXUB,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed de c8");
        testOp3(m64, .VPMAXUB,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 de fc");
        testOp3(m64, .VPMAXUB,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 de fc");
        testOp3(m64, .VPMAXUB,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 de fc");
        // VPMAXUW
        testOp3(m64, .VPMAXUW,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 3e c8");
        testOp3(m64, .VPMAXUW,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 3e c8");
        testOp3(m64, .VPMAXUW,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 3e fc");
        testOp3(m64, .VPMAXUW,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 3e fc");
        testOp3(m64, .VPMAXUW,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 3e fc");
        // VPMAXUD / VPMAXUQ
        // VPMAXUD
        testOp3(m64, .VPMAXUD,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 3f c8");
        testOp3(m64, .VPMAXUD,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 3f c8");
        testOp3(m64, .VPMAXUD,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 3f fc");
        testOp3(m64, .VPMAXUD,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 3f fc");
        testOp3(m64, .VPMAXUD,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 3f fc");
        // VPMAXUQ
        testOp3(m64, .VPMAXUQ,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 d5 87 3f fc");
        testOp3(m64, .VPMAXUQ,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 d5 a7 3f fc");
        testOp3(m64, .VPMAXUQ,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 d5 c7 3f fc");
        // VPMINSB / VPMINSW
        // VPMINSB
        testOp3(m64, .VPMINSB,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 38 c8");
        testOp3(m64, .VPMINSB,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 38 c8");
        testOp3(m64, .VPMINSB,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 38 fc");
        testOp3(m64, .VPMINSB,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 38 fc");
        testOp3(m64, .VPMINSB,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 38 fc");
        // VPMINSW
        testOp3(m64, .VPMINSW,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 ea c8");
        testOp3(m64, .VPMINSW,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed ea c8");
        testOp3(m64, .VPMINSW,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 ea fc");
        testOp3(m64, .VPMINSW,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 ea fc");
        testOp3(m64, .VPMINSW,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 ea fc");
        // VPMINSD / VPMINSQ
        // VPMINSD
        testOp3(m64, .VPMINSD,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 39 c8");
        testOp3(m64, .VPMINSD,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 39 c8");
        testOp3(m64, .VPMINSD,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 39 fc");
        testOp3(m64, .VPMINSD,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 39 fc");
        testOp3(m64, .VPMINSD,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 39 fc");
        // VPMINSQ
        testOp3(m64, .VPMINSQ,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 d5 87 39 fc");
        testOp3(m64, .VPMINSQ,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 d5 a7 39 fc");
        testOp3(m64, .VPMINSQ,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 d5 c7 39 fc");
        // VPMINUB / VPMINUW
        // VPMINUB
        testOp3(m64, .VPMINUB,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 da c8");
        testOp3(m64, .VPMINUB,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed da c8");
        testOp3(m64, .VPMINUB,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 da fc");
        testOp3(m64, .VPMINUB,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 da fc");
        testOp3(m64, .VPMINUB,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 da fc");
        // VPMINUW
        testOp3(m64, .VPMINUW,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 3a c8");
        testOp3(m64, .VPMINUW,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 3a c8");
        testOp3(m64, .VPMINUW,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 3a fc");
        testOp3(m64, .VPMINUW,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 3a fc");
        testOp3(m64, .VPMINUW,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 3a fc");
        // VPMINUD / VPMINUQ
        // VPMINUD
        testOp3(m64, .VPMINUD,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 3b c8");
        testOp3(m64, .VPMINUD,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 3b c8");
        testOp3(m64, .VPMINUD,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 3b fc");
        testOp3(m64, .VPMINUD,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 3b fc");
        testOp3(m64, .VPMINUD,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 3b fc");
        // VPMINUQ
        testOp3(m64, .VPMINUQ,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 d5 87 3b fc");
        testOp3(m64, .VPMINUQ,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 d5 a7 3b fc");
        testOp3(m64, .VPMINUQ,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 d5 c7 3b fc");
    }

    {
        // VPMOVSX
        // VPMOVSXBW
        testOp2(m64, .VPMOVSXBW,  reg(.XMM1), regRm(.XMM0), "c4 e2 79 20 c8");
        testOp2(m64, .VPMOVSXBW,  reg(.YMM1), regRm(.XMM0), "c4 e2 7d 20 c8");
        testOp2(m64, .VPMOVSXBW,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 20 fc");
        testOp2(m64, .VPMOVSXBW,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 20 fc");
        testOp2(m64, .VPMOVSXBW,  pred(.ZMM31, .K7, .Zero), regRm(.YMM20), "62 22 7d cf 20 fc");
        // VPMOVSXBD
        testOp2(m64, .VPMOVSXBD,  reg(.XMM1), regRm(.XMM0), "c4 e2 79 21 c8");
        testOp2(m64, .VPMOVSXBD,  reg(.YMM1), regRm(.XMM0), "c4 e2 7d 21 c8");
        testOp2(m64, .VPMOVSXBD,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 21 fc");
        testOp2(m64, .VPMOVSXBD,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 21 fc");
        testOp2(m64, .VPMOVSXBD,  pred(.ZMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d cf 21 fc");
        // VPMOVSXBQ
        testOp2(m64, .VPMOVSXBQ,  reg(.XMM1), regRm(.XMM0), "c4 e2 79 22 c8");
        testOp2(m64, .VPMOVSXBQ,  reg(.YMM1), regRm(.XMM0), "c4 e2 7d 22 c8");
        testOp2(m64, .VPMOVSXBQ,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 22 fc");
        testOp2(m64, .VPMOVSXBQ,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 22 fc");
        testOp2(m64, .VPMOVSXBQ,  pred(.ZMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d cf 22 fc");
        // VPMOVSXWD
        testOp2(m64, .VPMOVSXWD,  reg(.XMM1), regRm(.XMM0), "c4 e2 79 23 c8");
        testOp2(m64, .VPMOVSXWD,  reg(.YMM1), regRm(.XMM0), "c4 e2 7d 23 c8");
        testOp2(m64, .VPMOVSXWD,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 23 fc");
        testOp2(m64, .VPMOVSXWD,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 23 fc");
        testOp2(m64, .VPMOVSXWD,  pred(.ZMM31, .K7, .Zero), regRm(.YMM20), "62 22 7d cf 23 fc");
        // VPMOVSXWQ
        testOp2(m64, .VPMOVSXWQ,  reg(.XMM1), regRm(.XMM0), "c4 e2 79 24 c8");
        testOp2(m64, .VPMOVSXWQ,  reg(.YMM1), regRm(.XMM0), "c4 e2 7d 24 c8");
        testOp2(m64, .VPMOVSXWQ,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 24 fc");
        testOp2(m64, .VPMOVSXWQ,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 24 fc");
        testOp2(m64, .VPMOVSXWQ,  pred(.ZMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d cf 24 fc");
        // VPMOVSXDQ
        testOp2(m64, .VPMOVSXDQ,  reg(.XMM1), regRm(.XMM0), "c4 e2 79 25 c8");
        testOp2(m64, .VPMOVSXDQ,  reg(.YMM1), regRm(.XMM0), "c4 e2 7d 25 c8");
        testOp2(m64, .VPMOVSXDQ,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 25 fc");
        testOp2(m64, .VPMOVSXDQ,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 25 fc");
        testOp2(m64, .VPMOVSXDQ,  pred(.ZMM31, .K7, .Zero), regRm(.YMM20), "62 22 7d cf 25 fc");
    }

    {
        // VPMOVZX
        // VPMOVZXBW
        testOp2(m64, .VPMOVZXBW,  reg(.XMM1), regRm(.XMM0), "c4 e2 79 30 c8");
        testOp2(m64, .VPMOVZXBW,  reg(.YMM1), regRm(.XMM0), "c4 e2 7d 30 c8");
        testOp2(m64, .VPMOVZXBW,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 30 fc");
        testOp2(m64, .VPMOVZXBW,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 30 fc");
        testOp2(m64, .VPMOVZXBW,  pred(.ZMM31, .K7, .Zero), regRm(.YMM20), "62 22 7d cf 30 fc");
        // VPMOVZXBD
        testOp2(m64, .VPMOVZXBD,  reg(.XMM1), regRm(.XMM0), "c4 e2 79 31 c8");
        testOp2(m64, .VPMOVZXBD,  reg(.YMM1), regRm(.XMM0), "c4 e2 7d 31 c8");
        testOp2(m64, .VPMOVZXBD,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 31 fc");
        testOp2(m64, .VPMOVZXBD,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 31 fc");
        testOp2(m64, .VPMOVZXBD,  pred(.ZMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d cf 31 fc");
        // VPMOVZXBQ
        testOp2(m64, .VPMOVZXBQ,  reg(.XMM1), regRm(.XMM0), "c4 e2 79 32 c8");
        testOp2(m64, .VPMOVZXBQ,  reg(.YMM1), regRm(.XMM0), "c4 e2 7d 32 c8");
        testOp2(m64, .VPMOVZXBQ,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 32 fc");
        testOp2(m64, .VPMOVZXBQ,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 32 fc");
        testOp2(m64, .VPMOVZXBQ,  pred(.ZMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d cf 32 fc");
        // VPMOVZXWD
        testOp2(m64, .VPMOVZXWD,  reg(.XMM1), regRm(.XMM0), "c4 e2 79 33 c8");
        testOp2(m64, .VPMOVZXWD,  reg(.YMM1), regRm(.XMM0), "c4 e2 7d 33 c8");
        testOp2(m64, .VPMOVZXWD,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 33 fc");
        testOp2(m64, .VPMOVZXWD,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 33 fc");
        testOp2(m64, .VPMOVZXWD,  pred(.ZMM31, .K7, .Zero), regRm(.YMM20), "62 22 7d cf 33 fc");
        // VPMOVZXWQ
        testOp2(m64, .VPMOVZXWQ,  reg(.XMM1), regRm(.XMM0), "c4 e2 79 34 c8");
        testOp2(m64, .VPMOVZXWQ,  reg(.YMM1), regRm(.XMM0), "c4 e2 7d 34 c8");
        testOp2(m64, .VPMOVZXWQ,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 34 fc");
        testOp2(m64, .VPMOVZXWQ,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 34 fc");
        testOp2(m64, .VPMOVZXWQ,  pred(.ZMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d cf 34 fc");
        // VPMOVZXDQ
        testOp2(m64, .VPMOVZXDQ,  reg(.XMM1), regRm(.XMM0), "c4 e2 79 35 c8");
        testOp2(m64, .VPMOVZXDQ,  reg(.YMM1), regRm(.XMM0), "c4 e2 7d 35 c8");
        testOp2(m64, .VPMOVZXDQ,  pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 35 fc");
        testOp2(m64, .VPMOVZXDQ,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 35 fc");
        testOp2(m64, .VPMOVZXDQ,  pred(.ZMM31, .K7, .Zero), regRm(.YMM20), "62 22 7d cf 35 fc");
    }

    {
        // VPMULDQ
        testOp3(m64, .VPMULDQ,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 28 c8");
        testOp3(m64, .VPMULDQ,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 28 c8");
        testOp3(m64, .VPMULDQ,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 d5 87 28 fc");
        testOp3(m64, .VPMULDQ,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 d5 a7 28 fc");
        testOp3(m64, .VPMULDQ,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 d5 c7 28 fc");
        // VPMULHRSW
        testOp3(m64, .VPMULHRSW,  reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 0b c8");
        testOp3(m64, .VPMULHRSW,  reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 0b c8");
        testOp3(m64, .VPMULHRSW,  pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 0b fc");
        testOp3(m64, .VPMULHRSW,  pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 0b fc");
        testOp3(m64, .VPMULHRSW,  pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 0b fc");
        // VPMULHUW
        testOp3(m64, .VPMULHUW,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 e4 c8");
        testOp3(m64, .VPMULHUW,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed e4 c8");
        testOp3(m64, .VPMULHUW,   pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 e4 fc");
        testOp3(m64, .VPMULHUW,   pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 e4 fc");
        testOp3(m64, .VPMULHUW,   pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 e4 fc");
        // VPMULHW
        testOp3(m64, .VPMULHW,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 e5 c8");
        testOp3(m64, .VPMULHW,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed e5 c8");
        testOp3(m64, .VPMULHW,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 e5 fc");
        testOp3(m64, .VPMULHW,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 e5 fc");
        testOp3(m64, .VPMULHW,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 e5 fc");
        // VPMULLD / VPMULLQ
        // VPMULLD
        testOp3(m64, .VPMULLD,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 40 c8");
        testOp3(m64, .VPMULLD,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 40 c8");
        testOp3(m64, .VPMULLD,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 40 fc");
        testOp3(m64, .VPMULLD,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 40 fc");
        testOp3(m64, .VPMULLD,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 40 fc");
        // VPMULLQ
        testOp3(m64, .VPMULLQ,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 d5 87 40 fc");
        testOp3(m64, .VPMULLQ,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 d5 a7 40 fc");
        testOp3(m64, .VPMULLQ,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 d5 c7 40 fc");
        // VPMULLW
        testOp3(m64, .VPMULLW,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 d5 c8");
        testOp3(m64, .VPMULLW,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed d5 c8");
        testOp3(m64, .VPMULLW,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 d5 fc");
        testOp3(m64, .VPMULLW,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 d5 fc");
        testOp3(m64, .VPMULLW,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 d5 fc");
        // VPMULUDQ
        testOp3(m64, .VPMULUDQ,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 f4 c8");
        testOp3(m64, .VPMULUDQ,   reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed f4 c8");
        testOp3(m64, .VPMULUDQ,   pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 f4 fc");
        testOp3(m64, .VPMULUDQ,   pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 f4 fc");
        testOp3(m64, .VPMULUDQ,   pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 d5 c7 f4 fc");
    }

    {
        // VPOR
        testOp3(m64, .VPOR,       reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 eb c8");
        testOp3(m64, .VPOR,       reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed eb c8");
        //
        testOp3(m64, .VPORD,      pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 eb fc");
        testOp3(m64, .VPORD,      pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 eb fc");
        testOp3(m64, .VPORD,      pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 eb fc");
        //
        testOp3(m64, .VPORQ,      pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 eb fc");
        testOp3(m64, .VPORQ,      pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 eb fc");
        testOp3(m64, .VPORQ,      pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 d5 c7 eb fc");
        // VPSADBW
        testOp3(m64, .VPSADBW,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 f6 c8");
        testOp3(m64, .VPSADBW,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed f6 c8");
        testOp3(m64, .VPSADBW,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 f6 fc");
        testOp3(m64, .VPSADBW,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 f6 fc");
        testOp3(m64, .VPSADBW,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 f6 fc");
        // VPSHUFB
        testOp3(m64, .VPSHUFB,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 00 c8");
        testOp3(m64, .VPSHUFB,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 00 c8");
        testOp3(m64, .VPSHUFB,    pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 00 fc");
        testOp3(m64, .VPSHUFB,    pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 00 fc");
        testOp3(m64, .VPSHUFB,    pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 00 fc");
        // VPSHUFD
        testOp3(m64, .VPSHUFD,    reg(.XMM1), regRm(.XMM0), imm(0), "c5 f9 70 c8 00");
        testOp3(m64, .VPSHUFD,    reg(.YMM1), regRm(.YMM0), imm(0), "c5 fd 70 c8 00");
        testOp3(m64, .VPSHUFD,    pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 21 7d 8f 70 fc 00");
        testOp3(m64, .VPSHUFD,    pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 21 7d af 70 fc 00");
        testOp3(m64, .VPSHUFD,    pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 21 7d cf 70 fc 00");
        // VPSHUFHW
        testOp3(m64, .VPSHUFHW,   reg(.XMM1), regRm(.XMM0), imm(0), "c5 fa 70 c8 00");
        testOp3(m64, .VPSHUFHW,   reg(.YMM1), regRm(.YMM0), imm(0), "c5 fe 70 c8 00");
        testOp3(m64, .VPSHUFHW,   pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 21 7e 8f 70 fc 00");
        testOp3(m64, .VPSHUFHW,   pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 21 7e af 70 fc 00");
        testOp3(m64, .VPSHUFHW,   pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 21 7e cf 70 fc 00");
        // VPSHUFLW
        testOp3(m64, .VPSHUFLW,   reg(.XMM1), regRm(.XMM0), imm(0), "c5 fb 70 c8 00");
        testOp3(m64, .VPSHUFLW,   reg(.YMM1), regRm(.YMM0), imm(0), "c5 ff 70 c8 00");
        testOp3(m64, .VPSHUFLW,   pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 21 7f 8f 70 fc 00");
        testOp3(m64, .VPSHUFLW,   pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 21 7f af 70 fc 00");
        testOp3(m64, .VPSHUFLW,   pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 21 7f cf 70 fc 00");
    }

    {
        // VPSIGNB / VPSIGNW / VPSIGND
        // VPSIGNB
        testOp3(m64, .VPSIGNB,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 08 c8");
        testOp3(m64, .VPSIGNB,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 08 c8");
        // VPSIGNW
        testOp3(m64, .VPSIGNW,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 09 c8");
        testOp3(m64, .VPSIGNW,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 09 c8");
        // VPSIGND
        testOp3(m64, .VPSIGND,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c4 e2 69 0a c8");
        testOp3(m64, .VPSIGND,    reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c4 e2 6d 0a c8");
    }

    {
        // VPSLLDQ
        testOp3(m64, .VPSLLDQ,    reg(.XMM1), regRm(.XMM0), imm(0), "c5 f1 73 f8 00");
        testOp3(m64, .VPSLLDQ,    reg(.YMM1), regRm(.YMM0), imm(0), "c5 f5 73 f8 00");
        testOp3(m64, .VPSLLDQ,    pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 b1 05 87 73 fc 00");
        testOp3(m64, .VPSLLDQ,    pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 b1 05 a7 73 fc 00");
        testOp3(m64, .VPSLLDQ,    pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 b1 05 c7 73 fc 00");
        // VPSLLW / VPSLLD / VPSLLQ
        // VPSLLW
        testOp3(m64, .VPSLLW,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 f1 c8");
        testOp3(m64, .VPSLLW,     reg(.XMM1), regRm(.XMM0), imm(0), "c5 f1 71 f0 00");
        testOp3(m64, .VPSLLW,     reg(.YMM1), reg(.YMM2), regRm(.XMM0), "c5 ed f1 c8");
        testOp3(m64, .VPSLLW,     reg(.YMM1), regRm(.YMM0), imm(0), "c5 f5 71 f0 00");
        testOp3(m64, .VPSLLW,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 f1 fc");
        testOp3(m64, .VPSLLW,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.XMM20), "62 21 55 a7 f1 fc");
        testOp3(m64, .VPSLLW,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.XMM20), "62 21 55 c7 f1 fc");
        testOp3(m64, .VPSLLW,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 b1 05 87 71 f4 00");
        testOp3(m64, .VPSLLW,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 b1 05 a7 71 f4 00");
        testOp3(m64, .VPSLLW,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 b1 05 c7 71 f4 00");
        // VPSLLD
        testOp3(m64, .VPSLLD,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 f2 c8");
        testOp3(m64, .VPSLLD,     reg(.XMM1), regRm(.XMM0), imm(0), "c5 f1 72 f0 00");
        testOp3(m64, .VPSLLD,     reg(.YMM1), reg(.YMM2), regRm(.XMM0), "c5 ed f2 c8");
        testOp3(m64, .VPSLLD,     reg(.YMM1), regRm(.YMM0), imm(0), "c5 f5 72 f0 00");
        testOp3(m64, .VPSLLD,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 f2 fc");
        testOp3(m64, .VPSLLD,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.XMM20), "62 21 55 a7 f2 fc");
        testOp3(m64, .VPSLLD,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.XMM20), "62 21 55 c7 f2 fc");
        testOp3(m64, .VPSLLD,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 b1 05 87 72 f4 00");
        testOp3(m64, .VPSLLD,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 b1 05 a7 72 f4 00");
        testOp3(m64, .VPSLLD,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 b1 05 c7 72 f4 00");
        // VPSLLQ
        testOp3(m64, .VPSLLQ,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 f3 c8");
        testOp3(m64, .VPSLLQ,     reg(.XMM1), regRm(.XMM0), imm(0), "c5 f1 73 f0 00");
        testOp3(m64, .VPSLLQ,     reg(.YMM1), reg(.YMM2), regRm(.XMM0), "c5 ed f3 c8");
        testOp3(m64, .VPSLLQ,     reg(.YMM1), regRm(.YMM0), imm(0), "c5 f5 73 f0 00");
        testOp3(m64, .VPSLLQ,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 f3 fc");
        testOp3(m64, .VPSLLQ,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.XMM20), "62 21 d5 a7 f3 fc");
        testOp3(m64, .VPSLLQ,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.XMM20), "62 21 d5 c7 f3 fc");
        testOp3(m64, .VPSLLQ,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 b1 85 87 73 f4 00");
        testOp3(m64, .VPSLLQ,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 b1 85 a7 73 f4 00");
        testOp3(m64, .VPSLLQ,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 b1 85 c7 73 f4 00");
        // VPSRAW / VPSRAD / VPSRAQ
        // VPSRAW
        testOp3(m64, .VPSRAW,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 e1 c8");
        testOp3(m64, .VPSRAW,     reg(.XMM1), regRm(.XMM0), imm(0), "c5 f1 71 e0 00");
        testOp3(m64, .VPSRAW,     reg(.YMM1), reg(.YMM2), regRm(.XMM0), "c5 ed e1 c8");
        testOp3(m64, .VPSRAW,     reg(.YMM1), regRm(.YMM0), imm(0), "c5 f5 71 e0 00");
        testOp3(m64, .VPSRAW,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 e1 fc");
        testOp3(m64, .VPSRAW,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.XMM20), "62 21 55 a7 e1 fc");
        testOp3(m64, .VPSRAW,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.XMM20), "62 21 55 c7 e1 fc");
        testOp3(m64, .VPSRAW,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 b1 05 87 71 e4 00");
        testOp3(m64, .VPSRAW,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 b1 05 a7 71 e4 00");
        testOp3(m64, .VPSRAW,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 b1 05 c7 71 e4 00");
        // VPSRAD
        testOp3(m64, .VPSRAD,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 e2 c8");
        testOp3(m64, .VPSRAD,     reg(.XMM1), regRm(.XMM0), imm(0), "c5 f1 72 e0 00");
        testOp3(m64, .VPSRAD,     reg(.YMM1), reg(.YMM2), regRm(.XMM0), "c5 ed e2 c8");
        testOp3(m64, .VPSRAD,     reg(.YMM1), regRm(.YMM0), imm(0), "c5 f5 72 e0 00");
        testOp3(m64, .VPSRAD,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 e2 fc");
        testOp3(m64, .VPSRAD,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.XMM20), "62 21 55 a7 e2 fc");
        testOp3(m64, .VPSRAD,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.XMM20), "62 21 55 c7 e2 fc");
        testOp3(m64, .VPSRAD,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 b1 05 87 72 e4 00");
        testOp3(m64, .VPSRAD,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 b1 05 a7 72 e4 00");
        testOp3(m64, .VPSRAD,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 b1 05 c7 72 e4 00");
        // VPSRAQ
        testOp3(m64, .VPSRAQ,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 e2 fc");
        testOp3(m64, .VPSRAQ,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.XMM20), "62 21 d5 a7 e2 fc");
        testOp3(m64, .VPSRAQ,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.XMM20), "62 21 d5 c7 e2 fc");
        testOp3(m64, .VPSRAQ,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 b1 85 87 72 e4 00");
        testOp3(m64, .VPSRAQ,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 b1 85 a7 72 e4 00");
        testOp3(m64, .VPSRAQ,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 b1 85 c7 72 e4 00");
        // VPSRLDQ
        testOp3(m64, .VPSRLDQ,    reg(.XMM1), regRm(.XMM0), imm(0), "c5 f1 73 d8 00");
        testOp3(m64, .VPSRLDQ,    reg(.YMM1), regRm(.YMM0), imm(0), "c5 f5 73 d8 00");
        testOp3(m64, .VPSRLDQ,    pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 b1 05 87 73 dc 00");
        testOp3(m64, .VPSRLDQ,    pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 b1 05 a7 73 dc 00");
        testOp3(m64, .VPSRLDQ,    pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 b1 05 c7 73 dc 00");
        // VPSRLW / VPSRLD / VPSRLQ
        // VPSRLW
        testOp3(m64, .VPSRLW,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 d1 c8");
        testOp3(m64, .VPSRLW,     reg(.XMM1), regRm(.XMM0), imm(0), "c5 f1 71 d0 00");
        testOp3(m64, .VPSRLW,     reg(.YMM1), reg(.YMM2), regRm(.XMM0), "c5 ed d1 c8");
        testOp3(m64, .VPSRLW,     reg(.YMM1), regRm(.YMM0), imm(0), "c5 f5 71 d0 00");
        testOp3(m64, .VPSRLW,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 d1 fc");
        testOp3(m64, .VPSRLW,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.XMM20), "62 21 55 a7 d1 fc");
        testOp3(m64, .VPSRLW,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.XMM20), "62 21 55 c7 d1 fc");
        testOp3(m64, .VPSRLW,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 b1 05 87 71 d4 00");
        testOp3(m64, .VPSRLW,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 b1 05 a7 71 d4 00");
        testOp3(m64, .VPSRLW,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 b1 05 c7 71 d4 00");
        // VPSRLD
        testOp3(m64, .VPSRLD,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 d2 c8");
        testOp3(m64, .VPSRLD,     reg(.XMM1), regRm(.XMM0), imm(0), "c5 f1 72 d0 00");
        testOp3(m64, .VPSRLD,     reg(.YMM1), reg(.YMM2), regRm(.XMM0), "c5 ed d2 c8");
        testOp3(m64, .VPSRLD,     reg(.YMM1), regRm(.YMM0), imm(0), "c5 f5 72 d0 00");
        testOp3(m64, .VPSRLD,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 d2 fc");
        testOp3(m64, .VPSRLD,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.XMM20), "62 21 55 a7 d2 fc");
        testOp3(m64, .VPSRLD,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.XMM20), "62 21 55 c7 d2 fc");
        testOp3(m64, .VPSRLD,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 b1 05 87 72 d4 00");
        testOp3(m64, .VPSRLD,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 b1 05 a7 72 d4 00");
        testOp3(m64, .VPSRLD,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 b1 05 c7 72 d4 00");
        // VPSRLQ
        testOp3(m64, .VPSRLQ,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 d3 c8");
        testOp3(m64, .VPSRLQ,     reg(.XMM1), regRm(.XMM0), imm(0), "c5 f1 73 d0 00");
        testOp3(m64, .VPSRLQ,     reg(.YMM1), reg(.YMM2), regRm(.XMM0), "c5 ed d3 c8");
        testOp3(m64, .VPSRLQ,     reg(.YMM1), regRm(.YMM0), imm(0), "c5 f5 73 d0 00");
        testOp3(m64, .VPSRLQ,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 d3 fc");
        testOp3(m64, .VPSRLQ,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.XMM20), "62 21 d5 a7 d3 fc");
        testOp3(m64, .VPSRLQ,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.XMM20), "62 21 d5 c7 d3 fc");
        testOp3(m64, .VPSRLQ,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), imm(0), "62 b1 85 87 73 d4 00");
        testOp3(m64, .VPSRLQ,     pred(.YMM31, .K7, .Zero), regRm(.YMM20), imm(0), "62 b1 85 a7 73 d4 00");
        testOp3(m64, .VPSRLQ,     pred(.ZMM31, .K7, .Zero), regRm(.ZMM20), imm(0), "62 b1 85 c7 73 d4 00");
    }

    {
        testOp2(m64, .VPTEST,     reg(.XMM1), regRm(.XMM0), "c4 e2 79 17 c8");
        testOp2(m64, .VPTEST,     reg(.YMM1), regRm(.YMM0), "c4 e2 7d 17 c8");
    }

    {
        // VPUNPCKHBW / VPUNPCKHWD / VPUNPCKHDQ / VPUNPCKHQDQ
        // VPUNPCKHBW
        testOp3(m64, .VPUNPCKHBW, reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 68 c8");
        testOp3(m64, .VPUNPCKHBW, reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 68 c8");
        testOp3(m64, .VPUNPCKHBW, pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 68 fc");
        testOp3(m64, .VPUNPCKHBW, pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 68 fc");
        testOp3(m64, .VPUNPCKHBW, pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 68 fc");
        // VPUNPCKHWD
        testOp3(m64, .VPUNPCKHWD, reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 69 c8");
        testOp3(m64, .VPUNPCKHWD, reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 69 c8");
        testOp3(m64, .VPUNPCKHWD, pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 69 fc");
        testOp3(m64, .VPUNPCKHWD, pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 69 fc");
        testOp3(m64, .VPUNPCKHWD, pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 69 fc");
        // VPUNPCKHDQ
        testOp3(m64, .VPUNPCKHDQ, reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 6a c8");
        testOp3(m64, .VPUNPCKHDQ, reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 6a c8");
        testOp3(m64, .VPUNPCKHDQ, pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 6a fc");
        testOp3(m64, .VPUNPCKHDQ, pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 6a fc");
        testOp3(m64, .VPUNPCKHDQ, pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 6a fc");
        // VPUNPCKHQDQ
        testOp3(m64, .VPUNPCKHQDQ,reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 6d c8");
        testOp3(m64, .VPUNPCKHQDQ,reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 6d c8");
        testOp3(m64, .VPUNPCKHQDQ,pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 6d fc");
        testOp3(m64, .VPUNPCKHQDQ,pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 6d fc");
        testOp3(m64, .VPUNPCKHQDQ,pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 d5 c7 6d fc");
        // VPUNPCKLBW / VPUNPCKLWD / VPUNPCKLDQ / VPUNPCKLQDQ
        // VPUNPCKLBW
        testOp3(m64, .VPUNPCKLBW, reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 60 c8");
        testOp3(m64, .VPUNPCKLBW, reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 60 c8");
        testOp3(m64, .VPUNPCKLBW, pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 60 fc");
        testOp3(m64, .VPUNPCKLBW, pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 60 fc");
        testOp3(m64, .VPUNPCKLBW, pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 60 fc");
        // VPUNPCKLWD
        testOp3(m64, .VPUNPCKLWD, reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 61 c8");
        testOp3(m64, .VPUNPCKLWD, reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 61 c8");
        testOp3(m64, .VPUNPCKLWD, pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 61 fc");
        testOp3(m64, .VPUNPCKLWD, pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 61 fc");
        testOp3(m64, .VPUNPCKLWD, pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 61 fc");
        // VPUNPCKLDQ
        testOp3(m64, .VPUNPCKLDQ, reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 62 c8");
        testOp3(m64, .VPUNPCKLDQ, reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 62 c8");
        testOp3(m64, .VPUNPCKLDQ, pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 62 fc");
        testOp3(m64, .VPUNPCKLDQ, pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 62 fc");
        testOp3(m64, .VPUNPCKLDQ, pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 62 fc");
        // VPUNPCKLQDQ
        testOp3(m64, .VPUNPCKLQDQ,reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 6c c8");
        testOp3(m64, .VPUNPCKLQDQ,reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 6c c8");
        testOp3(m64, .VPUNPCKLQDQ,pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 6c fc");
        testOp3(m64, .VPUNPCKLQDQ,pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 6c fc");
        testOp3(m64, .VPUNPCKLQDQ,pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 d5 c7 6c fc");
    }

    {
        // VPXOR
        testOp3(m64, .VPXOR,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 ef c8");
        testOp3(m64, .VPXOR,      reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed ef c8");
        //
        testOp3(m64, .VPXORD,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 55 87 ef fc");
        testOp3(m64, .VPXORD,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 55 a7 ef fc");
        testOp3(m64, .VPXORD,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 55 c7 ef fc");
        //
        testOp3(m64, .VPXORQ,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 ef fc");
        testOp3(m64, .VPXORQ,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 ef fc");
        testOp3(m64, .VPXORQ,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 d5 c7 ef fc");
    }

    {
        // VRCPPS
        testOp2(m64, .VRCPPS,     reg(.XMM1), regRm(.XMM0), "c5 f8 53 c8");
        testOp2(m64, .VRCPPS,     reg(.YMM1), regRm(.YMM0), "c5 fc 53 c8");
        // VRCPSS
        testOp3(m64, .VRCPSS,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 ea 53 c8");
        // VROUNDPD
        testOp3(m64, .VROUNDPD,   reg(.XMM1), regRm(.XMM0), imm(0), "c4 e3 79 09 c8 00");
        testOp3(m64, .VROUNDPD,   reg(.YMM1), regRm(.YMM0), imm(0), "c4 e3 7d 09 c8 00");
        // VROUNDPS
        testOp3(m64, .VROUNDPS,   reg(.XMM1), regRm(.XMM0), imm(0), "c4 e3 79 08 c8 00");
        testOp3(m64, .VROUNDPS,   reg(.YMM1), regRm(.YMM0), imm(0), "c4 e3 7d 08 c8 00");
        // VROUNDSD
        testOp4(m64, .VROUNDSD,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), imm(0), "c4 e3 69 0b c8 00");
        // VROUNDSS
        testOp4(m64, .VROUNDSS,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), imm(0), "c4 e3 69 0a c8 00");
        // VRSQRTPS
        testOp2(m64, .VRSQRTPS,   reg(.XMM1), regRm(.XMM0), "c5 f8 52 c8");
        testOp2(m64, .VRSQRTPS,   reg(.YMM1), regRm(.YMM0), "c5 fc 52 c8");
        // VRSQRTSS
        testOp3(m64, .VRSQRTSS,   reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 ea 52 c8");
    }

    {
        // VSHUFPD
        testOp4(m64, .VSHUFPD,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), imm(0), "c5 e9 c6 c8 00");
        testOp4(m64, .VSHUFPD,    reg(.YMM1), reg(.XMM1), regRm(.YMM0), imm(0), "c5 f5 c6 c8 00");
        testOp4(m64, .VSHUFPD,    pred(.XMM31, .K7, .Zero),reg(.XMM21),regRm(.XMM20),imm(0), "62 21 d5 87 c6 fc 00");
        testOp4(m64, .VSHUFPD,    pred(.YMM31, .K7, .Zero),reg(.XMM21),regRm(.YMM20),imm(0), "62 21 d5 a7 c6 fc 00");
        testOp4(m64, .VSHUFPD,    pred(.ZMM31, .K7, .Zero),reg(.XMM21),regRm(.ZMM20),imm(0), "62 21 d5 c7 c6 fc 00");
        // VSHUFPS
        testOp4(m64, .VSHUFPS,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), imm(0), "c5 e8 c6 c8 00");
        testOp4(m64, .VSHUFPS,    reg(.YMM1), reg(.XMM1), regRm(.YMM0), imm(0), "c5 f4 c6 c8 00");
        testOp4(m64, .VSHUFPS,    pred(.XMM31, .K7, .Zero),reg(.XMM21),regRm(.XMM20),imm(0), "62 21 54 87 c6 fc 00");
        testOp4(m64, .VSHUFPS,    pred(.YMM31, .K7, .Zero),reg(.XMM21),regRm(.YMM20),imm(0), "62 21 54 a7 c6 fc 00");
        testOp4(m64, .VSHUFPS,    pred(.ZMM31, .K7, .Zero),reg(.XMM21),regRm(.ZMM20),imm(0), "62 21 54 c7 c6 fc 00");
        // VSQRTPD
        testOp2(m64, .VSQRTPD,    reg(.XMM1), regRm(.XMM0), "c5 f9 51 c8");
        testOp2(m64, .VSQRTPD,    reg(.YMM1), regRm(.YMM0), "c5 fd 51 c8");
        testOp2(m64, .VSQRTPD,    pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 21 fd 8f 51 fc");
        testOp2(m64, .VSQRTPD,    pred(.YMM31, .K7, .Zero), regRm(.YMM20), "62 21 fd af 51 fc");
        testOp2(m64, .VSQRTPD,    pred(.ZMM31, .K7, .Zero), sae(.ZMM30, .RN_SAE), "62 01 fd 9f 51 fe");
        // VSQRTPS
        testOp2(m64, .VSQRTPS,    reg(.XMM1), regRm(.XMM0), "c5 f8 51 c8");
        testOp2(m64, .VSQRTPS,    reg(.YMM1), regRm(.YMM0), "c5 fc 51 c8");
        testOp2(m64, .VSQRTPS,    pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 21 7c 8f 51 fc");
        testOp2(m64, .VSQRTPS,    pred(.YMM31, .K7, .Zero), regRm(.YMM20), "62 21 7c af 51 fc");
        testOp2(m64, .VSQRTPS,    pred(.ZMM31, .K7, .Zero), sae(.ZMM30, .RN_SAE), "62 01 7c 9f 51 fe");
        // VSQRTSD
        testOp3(m64, .VSQRTSD,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 eb 51 c8");
        testOp3(m64, .VSQRTSD,    pred(.XMM31, .K7, .Zero), reg(.XMM21), sae(.XMM30, .RN_SAE), "62 01 d7 97 51 fe");
        // VSQRTSS
        testOp3(m64, .VSQRTSS,    reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 ea 51 c8");
        testOp3(m64, .VSQRTSS,    pred(.XMM31, .K7, .Zero), reg(.XMM21), sae(.XMM30, .RN_SAE), "62 01 56 97 51 fe");
        // VSTMXCSR
        testOp1(m64, .VSTMXCSR,   rm_mem32, "67 c5 f8 ae 18");
    }

    {
        // VSUBPD
        testOp3(m64, .VSUBPD,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 5c c8");
        testOp3(m64, .VSUBPD,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 5c c8");
        testOp3(m64, .VSUBPD,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 5c fc");
        testOp3(m64, .VSUBPD,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 5c fc");
        testOp3(m64, .VSUBPD,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), sae(.ZMM30, .RN_SAE), "62 01 d5 97 5c fe");
        // VSUBPS
        testOp3(m64, .VSUBPS,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e8 5c c8");
        testOp3(m64, .VSUBPS,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ec 5c c8");
        testOp3(m64, .VSUBPS,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 54 87 5c fc");
        testOp3(m64, .VSUBPS,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 54 a7 5c fc");
        testOp3(m64, .VSUBPS,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), sae(.ZMM30, .RN_SAE), "62 01 54 97 5c fe");
        // VSUBSD
        testOp3(m64, .VSUBSD,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 eb 5c c8");
        testOp3(m64, .VSUBSD,     pred(.XMM31, .K7, .Zero), reg(.XMM21), sae(.XMM30, .RN_SAE), "62 01 d7 97 5c fe");
        // VSUBSS
        testOp3(m64, .VSUBSS,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 ea 5c c8");
        testOp3(m64, .VSUBSS,     pred(.XMM31, .K7, .Zero), reg(.XMM21), sae(.XMM30, .RN_SAE), "62 01 56 97 5c fe");
    }

    {
        // VUCOMISD
        testOp2(m64, .VUCOMISD,   reg(.XMM1), regRm(.XMM0), "c5 f9 2e c8");
        testOp2(m64, .VUCOMISD,   pred(.XMM31, .K7, .Zero), sae(.XMM30, .SAE), "62 01 fd 9f 2e fe");
        // VUCOMISS
        testOp2(m64, .VUCOMISS,   reg(.XMM1), regRm(.XMM0), "c5 f8 2e c8");
        testOp2(m64, .VUCOMISS,   pred(.XMM31, .K7, .Zero), sae(.XMM30, .SAE), "62 01 7c 9f 2e fe");
    }

    {
        // VUNPCKHPD
        testOp3(m64, .VUNPCKHPD,  reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 15 c8");
        testOp3(m64, .VUNPCKHPD,  reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 15 c8");
        testOp3(m64, .VUNPCKHPD,  pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 15 fc");
        testOp3(m64, .VUNPCKHPD,  pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 15 fc");
        testOp3(m64, .VUNPCKHPD,  pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 d5 c7 15 fc");
        // VUNPCKHPS
        testOp3(m64, .VUNPCKHPS,  reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e8 15 c8");
        testOp3(m64, .VUNPCKHPS,  reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ec 15 c8");
        testOp3(m64, .VUNPCKHPS,  pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 54 87 15 fc");
        testOp3(m64, .VUNPCKHPS,  pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 54 a7 15 fc");
        testOp3(m64, .VUNPCKHPS,  pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 54 c7 15 fc");
        // VUNPCKLPD
        testOp3(m64, .VUNPCKLPD,  reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 14 c8");
        testOp3(m64, .VUNPCKLPD,  reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 14 c8");
        testOp3(m64, .VUNPCKLPD,  pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 14 fc");
        testOp3(m64, .VUNPCKLPD,  pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 14 fc");
        testOp3(m64, .VUNPCKLPD,  pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 d5 c7 14 fc");
        // VUNPCKLPS
        testOp3(m64, .VUNPCKLPS,  reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e8 14 c8");
        testOp3(m64, .VUNPCKLPS,  reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ec 14 c8");
        testOp3(m64, .VUNPCKLPS,  pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 54 87 14 fc");
        testOp3(m64, .VUNPCKLPS,  pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 54 a7 14 fc");
        testOp3(m64, .VUNPCKLPS,  pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 54 c7 14 fc");
    }

    //
    // Instructions V-Z
    //

    {
        // VALIGND / VALIGNQ
        // VALIGND
        testOp4(m64, .VALIGND,    pred(.XMM31, .K7, .Zero),reg(.XMM21),regRm(.XMM20),imm(0), "62 23 55 87 03 fc 00");
        testOp4(m64, .VALIGND,    pred(.YMM31, .K7, .Zero),reg(.XMM21),regRm(.YMM20),imm(0), "62 23 55 a7 03 fc 00");
        testOp4(m64, .VALIGND,    pred(.ZMM31, .K7, .Zero),reg(.XMM21),regRm(.ZMM20),imm(0), "62 23 55 c7 03 fc 00");
        // VALIGNQ
        testOp4(m64, .VALIGNQ,    pred(.XMM31, .K7, .Zero),reg(.XMM21),regRm(.XMM20),imm(0), "62 23 d5 87 03 fc 00");
        testOp4(m64, .VALIGNQ,    pred(.YMM31, .K7, .Zero),reg(.XMM21),regRm(.YMM20),imm(0), "62 23 d5 a7 03 fc 00");
        testOp4(m64, .VALIGNQ,    pred(.ZMM31, .K7, .Zero),reg(.XMM21),regRm(.ZMM20),imm(0), "62 23 d5 c7 03 fc 00");
        // VBLENDMPD / VBLENDMPS
        // VBLENDMPD
        testOp3(m64, .VBLENDMPD,  pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 d5 87 65 fc");
        testOp3(m64, .VBLENDMPD,  pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 d5 a7 65 fc");
        testOp3(m64, .VBLENDMPD,  pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 d5 c7 65 fc");
        // VBLENDMPS
        testOp3(m64, .VBLENDMPS,  pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 22 55 87 65 fc");
        testOp3(m64, .VBLENDMPS,  pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 22 55 a7 65 fc");
        testOp3(m64, .VBLENDMPS,  pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 22 55 c7 65 fc");
    }

    {
        // VBROADCAST
        // VBROADCASTSS
        testOp2(m64, .VBROADCASTSS,     reg(.XMM1), rm_mem32, "67 c4 e2 79 18 08");
        testOp2(m64, .VBROADCASTSS,     reg(.YMM1), rm_mem32, "67 c4 e2 7d 18 08");
        testOp2(m64, .VBROADCASTSS,     reg(.XMM1), regRm(.XMM0), "c4 e2 79 18 c8");
        testOp2(m64, .VBROADCASTSS,     reg(.YMM1), regRm(.XMM0), "c4 e2 7d 18 c8");
        testOp2(m64, .VBROADCASTSS,     pred(.XMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d 8f 18 fc");
        testOp2(m64, .VBROADCASTSS,     pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 18 fc");
        testOp2(m64, .VBROADCASTSS,     pred(.ZMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d cf 18 fc");
        // VBROADCASTSD
        testOp2(m64, .VBROADCASTSD,     reg(.YMM1), rm_mem64, "67 c4 e2 7d 19 08");
        testOp2(m64, .VBROADCASTSD,     reg(.YMM1), regRm(.XMM0), "c4 e2 7d 19 c8");
        testOp2(m64, .VBROADCASTSD,     pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 fd af 19 fc");
        testOp2(m64, .VBROADCASTSD,     pred(.ZMM31, .K7, .Zero), regRm(.XMM20), "62 22 fd cf 19 fc");
        // VBROADCASTF1 28
        testOp2(m64, .VBROADCASTF128,   reg(.YMM1), rm_mem128, "67 c4 e2 7d 1a 08");
        // VBROADCASTF32X2
        testOp2(m64, .VBROADCASTF32X2,  pred(.YMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d af 19 fc");
        testOp2(m64, .VBROADCASTF32X2,  pred(.ZMM31, .K7, .Zero), regRm(.XMM20), "62 22 7d cf 19 fc");
        // VBROADCASTF32X4
        testOp2(m64, .VBROADCASTF32X4,  pred(.YMM31, .K7, .Zero), rm_mem128, "67 62 62 7d af 1a 38");
        testOp2(m64, .VBROADCASTF32X4,  pred(.ZMM31, .K7, .Zero), rm_mem128, "67 62 62 7d cf 1a 38");
        // VBROADCASTF64X2
        testOp2(m64, .VBROADCASTF64X2,  pred(.YMM31, .K7, .Zero), rm_mem128, "67 62 62 fd af 1a 38");
        testOp2(m64, .VBROADCASTF64X2,  pred(.ZMM31, .K7, .Zero), rm_mem128, "67 62 62 fd cf 1a 38");
        // VBROADCASTF32X8
        testOp2(m64, .VBROADCASTF32X8,  pred(.ZMM31, .K7, .Zero), rm_mem256, "67 62 62 7d cf 1b 38");
        // VBROADCASTF64X4
        testOp2(m64, .VBROADCASTF64X4,  pred(.ZMM31, .K7, .Zero), rm_mem256, "67 62 62 fd cf 1b 38");
    }

    {
        // VCOMPRESSPD
        testOp2(m64, .VCOMPRESSPD,      regRm(.XMM20), reg(.XMM21), "62 a2 fd 08 8a ec");
        testOp2(m64, .VCOMPRESSPD,      regRm(.YMM20), reg(.YMM21), "62 a2 fd 28 8a ec");
        testOp2(m64, .VCOMPRESSPD,      regRm(.ZMM20), reg(.ZMM21), "62 a2 fd 48 8a ec");
        // VCOMPRESSPS
        testOp2(m64, .VCOMPRESSPS,      regRm(.XMM20), reg(.XMM21), "62 a2 7d 08 8a ec");
        testOp2(m64, .VCOMPRESSPS,      regRm(.YMM20), reg(.YMM21), "62 a2 7d 28 8a ec");
        testOp2(m64, .VCOMPRESSPS,      regRm(.ZMM20), reg(.ZMM21), "62 a2 7d 48 8a ec");
    }

    {
        // VXORPD
        testOp3(m64, .VXORPD,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e9 57 c8");
        testOp3(m64, .VXORPD,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ed 57 c8");
        testOp3(m64, .VXORPD,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 d5 87 57 fc");
        testOp3(m64, .VXORPD,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 d5 a7 57 fc");
        testOp3(m64, .VXORPD,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 d5 c7 57 fc");
        // VXXORPS
        testOp3(m64, .VXORPS,     reg(.XMM1), reg(.XMM2), regRm(.XMM0), "c5 e8 57 c8");
        testOp3(m64, .VXORPS,     reg(.YMM1), reg(.YMM2), regRm(.YMM0), "c5 ec 57 c8");
        testOp3(m64, .VXORPS,     pred(.XMM31, .K7, .Zero), reg(.XMM21), regRm(.XMM20), "62 21 54 87 57 fc");
        testOp3(m64, .VXORPS,     pred(.YMM31, .K7, .Zero), reg(.YMM21), regRm(.YMM20), "62 21 54 a7 57 fc");
        testOp3(m64, .VXORPS,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), regRm(.ZMM20), "62 21 54 c7 57 fc");
    }
}
