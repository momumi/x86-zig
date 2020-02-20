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

    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const mem_64 = rm64;
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
        testOp3(m64, .VMAXPD,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5f95fc0");
        testOp3(m64, .VMAXPD,     reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5fd5fc0");
        testOp3(m64, .VMAXPD,     pred(.XMM31, .K7, .Zero), reg(.XMM31), reg(.XMM31), "620185875fff");
        testOp3(m64, .VMAXPD,     pred(.YMM31, .K7, .Zero), reg(.YMM31), reg(.YMM31), "620185a75fff");
        testOp3(m64, .VMAXPD,     pred(.ZMM31, .K7, .Zero), reg(.ZMM31), sae(.ZMM31, .SAE), "620185d75fff");
        // VMAXPS
        testOp3(m64, .VMAXPS,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5f85fc0");
        testOp3(m64, .VMAXPS,     reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5fc5fc0");
        testOp3(m64, .VMAXPS,     pred(.XMM31, .K7, .Zero), reg(.XMM31), reg(.XMM31), "620104875fff");
        testOp3(m64, .VMAXPS,     pred(.YMM31, .K7, .Zero), reg(.YMM31), reg(.YMM31), "620104a75fff");
        testOp3(m64, .VMAXPS,     pred(.ZMM31, .K7, .Zero), reg(.ZMM31), sae(.ZMM31, .SAE), "620104d75fff");
        // VMAXSD
        testOp3(m64, .VMAXSD,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5fb5fc0");
        testOp3(m64, .VMAXSD,     pred(.XMM31, .K7, .Zero), reg(.XMM31), sae(.XMM31, .SAE), "620187975fff");
        // VMAXSS
        testOp3(m64, .VMAXSS,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5fa5fc0");
        testOp3(m64, .VMAXSS,     pred(.XMM31, .K7, .Zero), reg(.XMM31), sae(.XMM31, .SAE), "620106975fff");
        // VMINPD
        testOp3(m64, .VMINPD,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5f95dc0");
        testOp3(m64, .VMINPD,     reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5fd5dc0");
        testOp3(m64, .VMINPD,     pred(.XMM31, .K7, .Zero), reg(.XMM31), reg(.XMM31), "620185875dff");
        testOp3(m64, .VMINPD,     pred(.YMM31, .K7, .Zero), reg(.YMM31), reg(.YMM31), "620185a75dff");
        testOp3(m64, .VMINPD,     pred(.ZMM31, .K7, .Zero), reg(.ZMM31), sae(.ZMM31, .SAE), "620185d75dff");
        // VMINPS
        testOp3(m64, .VMINPS,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5f85dc0");
        testOp3(m64, .VMINPS,     reg(.YMM0), reg(.YMM0), reg(.YMM0), "c5fc5dc0");
        testOp3(m64, .VMINPS,     pred(.XMM31, .K7, .Zero), reg(.XMM31), reg(.XMM31), "620104875dff");
        testOp3(m64, .VMINPS,     pred(.YMM31, .K7, .Zero), reg(.YMM31), reg(.YMM31), "620104a75dff");
        testOp3(m64, .VMINPS,     pred(.ZMM31, .K7, .Zero), reg(.ZMM31), sae(.ZMM31, .SAE), "620104d75dff");
        // VMINSD
        testOp3(m64, .VMINSD,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5fb5dc0");
        testOp3(m64, .VMINSD,     pred(.XMM31, .K7, .Zero), reg(.XMM31), sae(.XMM31, .SAE), "620187975dff");
        // VMINSS
        testOp3(m64, .VMINSS,     reg(.XMM0), reg(.XMM0), reg(.XMM0), "c5fa5dc0");
        testOp3(m64, .VMINSS,     pred(.XMM31, .K7, .Zero), reg(.XMM31), sae(.XMM31, .SAE), "620106975dff");
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

    //
    // VPxxxxx
    //

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
