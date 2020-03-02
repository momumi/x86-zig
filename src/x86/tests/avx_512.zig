const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "AVX-512" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    const reg = Operand.register;
    const pred = Operand.registerPredicate;
    const predRm = Operand.rmPredicate;
    const sae = Operand.registerSae;
    const regRm = Operand.registerRm;
    const imm = Operand.immediate;

    const memRm = Operand.memoryRmDef;
    const memSib = Operand.memorySibDef;
    const memRm16 = Operand.memory16Bit;
    const memRel = Operand.relMemory;

    const mem_void = Operand.memoryRm(.DefaultSeg, .Void, .EAX, 0);
    const mem_32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const mem_64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const rm_mem128 = Operand.memoryRm(.DefaultSeg, .XMM_WORD, .EAX, 0);
    const rm_mem256 = Operand.memoryRm(.DefaultSeg, .YMM_WORD, .EAX, 0);
    const rm_mem512 = Operand.memoryRm(.DefaultSeg, .ZMM_WORD, .EAX, 0);
    const m32bcst = Operand.memoryRm(.DefaultSeg, .DWORD_BCST, .EAX, 0);
    const m64bcst = Operand.memoryRm(.DefaultSeg, .QWORD_BCST, .EAX, 0);

    debugPrint(false);

    // test predicate registers
    {
        testOp3(m32, .VPADDB, pred(.XMM0,  .NoMask, .Merge), reg(.XMM0),  reg(.XMM0),  "62 f1 7d 08 fc c0");
        testOp3(m32, .VPADDB, pred(.XMM0,  .NoMask, .Zero),  reg(.XMM0),  reg(.XMM0),  "62 f1 7d 88 fc c0");
        testOp3(m32, .VPADDB, pred(.XMM0,  .K1,     .Zero),  reg(.XMM0),  reg(.XMM0),  "62 f1 7d 89 fc c0");
        testOp3(m32, .VPADDB, pred(.XMM0,  .K2,     .Zero),  reg(.XMM0),  reg(.XMM0),  "62 f1 7d 8a fc c0");
        testOp3(m32, .VPADDB, pred(.XMM0,  .K3,     .Merge), reg(.XMM0),  reg(.XMM0),  "62 f1 7d 0b fc c0");
        testOp3(m32, .VPADDB, pred(.XMM15, .K4,     .Merge), reg(.XMM16), reg(.XMM31), AsmError.InvalidMode);
        testOp3(m64, .VPADDB, pred(.XMM15, .K5,     .Merge), reg(.XMM16), reg(.XMM31), "62 11 7d 05 fc ff");
        testOp3(m64, .VPADDB, pred(.XMM15, .K6,     .Zero),  reg(.XMM16), reg(.XMM31), "62 11 7d 86 fc ff");
        testOp3(m64, .VPADDB, pred(.XMM31, .K7,     .Zero),  reg(.XMM31), reg(.XMM31), "62 01 05 87 fc ff");
        testOp3(m64, .VPADDB, pred(.YMM31, .K7,     .Zero),  reg(.YMM31), reg(.YMM31), "62 01 05 a7 fc ff");
        testOp3(m64, .VPADDB, pred(.ZMM31, .NoMask, .Zero),  reg(.ZMM31), reg(.ZMM31), "62 01 05 c0 fc ff");
        testOp3(m64, .VPADDB, pred(.XMM0,  .NoMask, .Merge), reg(.XMM0),  reg(.XMM0),  "62 f1 7d 08 fc c0");
        testOp3(m64, .VPADDB, pred(.YMM0,  .NoMask, .Merge), reg(.YMM0),  reg(.YMM0),  "62 f1 7d 28 fc c0");
        testOp3(m64, .VPADDB, pred(.ZMM0,  .NoMask, .Merge), reg(.ZMM0),  reg(.ZMM0),  "62 f1 7d 48 fc c0");

        testOp3(m64, .VPADDB, reg(.K7), reg(.XMM16), reg(.XMM31),                 AsmError.InvalidOperand);
        testOp3(m64, .VPADDB, pred(.YMM15, .K7, .Zero), reg(.XMM16), reg(.XMM31), AsmError.InvalidOperand);
        testOp3(m64, .VPADDB, pred(.ZMM15, .K7, .Zero), reg(.XMM16), reg(.XMM31), AsmError.InvalidOperand);
        testOp3(m64, .VPADDB, pred(.RAX, .K7, .Zero), reg(.XMM16), reg(.XMM31),   AsmError.InvalidOperand);
        testOp3(m64, .VPADDB, sae(.XMM0, .AE), reg(.XMM0), reg(.XMM0),            AsmError.InvalidOperand);
        testOp3(m64, .VPADDB, sae(.XMM0, .SAE), reg(.XMM0), reg(.XMM0),           AsmError.InvalidOperand);
        testOp3(m64, .VPADDB, sae(.XMM0, .RU_SAE), reg(.XMM0), reg(.XMM0),        AsmError.InvalidOperand);
        testOp3(m64, .VPADDB, reg(.XMM0), pred(.XMM16, .K1, .Merge), reg(.XMM31), AsmError.InvalidOperand);
        testOp3(m64, .VPADDB, reg(.XMM0), reg(.XMM0), pred(.XMM31, .K1, .Merge),  AsmError.InvalidOperand);
        testOp3(m64, .VPADDB, reg(.MM0), reg(.MM0), pred(.MM7, .K1, .Merge),      AsmError.InvalidOperand);
        testOp3(m64, .VPADDB, reg(.AL), reg(.AH), pred(.BH, .K1, .Merge),         AsmError.InvalidOperand);
    }

    // broadcast test
    {
        testOp3(m64, .VADDPS, pred(.ZMM0,  .K7, .Zero), reg(.ZMM0),  m32bcst,  "67 62 f1 7c df 58 00");
        testOp3(m64, .VADDPS, pred(.ZMM0,  .K7, .Zero), reg(.ZMM0),  m64bcst,  AsmError.InvalidOperand);
        testOp3(m64, .VADDPD, pred(.ZMM0,  .K7, .Zero), reg(.ZMM0),  m32bcst,  AsmError.InvalidOperand);
        testOp3(m64, .VADDPD, pred(.ZMM0,  .K7, .Zero), reg(.ZMM0),  m64bcst,  "67 62 f1 fd df 58 00");

        testOp3(m64, .VADDPS, pred(.ZMM0,  .K7, .Zero), reg(.ZMM0),  mem_void, AsmError.InvalidOperand);
        testOp3(m64, .VADDPS, pred(.ZMM0,  .K7, .Zero), reg(.ZMM0),  mem_32,   AsmError.InvalidOperand);
        testOp3(m64, .VADDPS, pred(.ZMM0,  .K7, .Zero), reg(.ZMM0),  mem_64,   AsmError.InvalidOperand);
        testOp3(m64, .VADDPD, pred(.ZMM0,  .K7, .Zero), reg(.ZMM0),  mem_void, AsmError.InvalidOperand);
        testOp3(m64, .VADDPD, pred(.ZMM0,  .K7, .Zero), reg(.ZMM0),  mem_32,   AsmError.InvalidOperand);
        testOp3(m64, .VADDPD, pred(.ZMM0,  .K7, .Zero), reg(.ZMM0),  mem_64,   AsmError.InvalidOperand);
    }

    // test sae/rounding register
    {
        testOp3(m64, .VADDPD, pred(.ZMM0,  .K7, .Zero), reg(.ZMM0),  sae(.ZMM0, .RN_SAE), "62 f1 fd 9f 58 c0");

        testOp3(m64, .VADDPD, pred(.ZMM0,  .K7, .Zero), sae(.ZMM0, .SAE), reg(.ZMM0),  AsmError.InvalidOperand);
        testOp3(m64, .VADDPD, pred(.ZMM0,  .K7, .Zero), sae(.ZMM0, .RN_SAE), reg(.ZMM0),  AsmError.InvalidOperand);
        testOp3(m64, .VADDPD, sae(.ZMM0, .RN_SAE), reg(.ZMM0), pred(.ZMM0,  .K7, .Zero),  AsmError.InvalidOperand);
        testOp3(m64, .VADDPD, sae(.ZMM0, .RN_SAE), reg(.ZMM0), pred(.ZMM0,  .K7, .Zero),  AsmError.InvalidOperand);

        testOp4(m64, .VCMPPD, pred(.K0,  .K7, .Merge), reg(.ZMM0), sae(.ZMM0, .AE),  imm(0), "62 f1 fd 4f c2 c0 00");
        testOp4(m64, .VCMPPD, pred(.K0,  .K7, .Merge), reg(.ZMM0), sae(.ZMM0, .SAE), imm(0), "62 f1 fd 5f c2 c0 00");

        testOp4(m64, .VCMPPD, pred(.K0,  .K7, .Merge), reg(.ZMM0), sae(.ZMM0, .RU_SAE), imm(0), AsmError.InvalidOperand);
        testOp4(m64, .VCMPPD, pred(.K0,  .K7, .Merge), reg(.ZMM0), sae(.ZMM0, .RN_SAE), imm(0), AsmError.InvalidOperand);
        testOp4(m64, .VCMPPD, pred(.K0,  .K7, .Merge), reg(.ZMM0), sae(.ZMM0, .RD_SAE), imm(0), AsmError.InvalidOperand);
        testOp4(m64, .VCMPPD, pred(.K0,  .K7, .Merge), reg(.ZMM0), sae(.ZMM0, .RZ_SAE), imm(0), AsmError.InvalidOperand);
    }

    // test vsib addressing
    {
        const vm32xl = Operand.memoryVecSib(.DefaultSeg, .DWORD, 8, .XMM7, .EAX, 0);
        const vm32yl = Operand.memoryVecSib(.DefaultSeg, .DWORD, 8, .YMM7, .EAX, 0);

        const vm64xl = Operand.memoryVecSib(.DefaultSeg, .QWORD, 8, .XMM7, .EAX, 0);
        const vm64yl = Operand.memoryVecSib(.DefaultSeg, .QWORD, 8, .YMM7, .EAX, 0);

        const vm32x = Operand.memoryVecSib(.DefaultSeg, .DWORD, 8, .XMM30, .EAX, 0);
        const vm32y = Operand.memoryVecSib(.DefaultSeg, .DWORD, 8, .YMM30, .EAX, 0);
        const vm32z = Operand.memoryVecSib(.DefaultSeg, .DWORD, 8, .ZMM30, .EAX, 0);

        const vm64x = Operand.memoryVecSib(.DefaultSeg, .QWORD, 8, .XMM30, .EAX, 0);
        const vm64y = Operand.memoryVecSib(.DefaultSeg, .QWORD, 8, .YMM30, .EAX, 0);
        const vm64z = Operand.memoryVecSib(.DefaultSeg, .QWORD, 8, .ZMM30, .EAX, 0);

        testOp3(m64, .VGATHERDPD,   reg(.XMM1), vm32xl, reg(.XMM2), "67 c4 e2 e9 92 0c f8");
        testOp3(m64, .VGATHERDPD,   reg(.YMM1), vm32xl, reg(.YMM2), "67 c4 e2 ed 92 0c f8");
        testOp3(m64, .VGATHERDPD,   reg(.XMM1), vm32x, reg(.XMM2), AsmError.InvalidOperand);
        testOp3(m64, .VGATHERDPD,   reg(.YMM1), vm32x, reg(.YMM2), AsmError.InvalidOperand);
        testOp3(m64, .VGATHERDPD,   reg(.XMM1), vm32yl, reg(.XMM2), AsmError.InvalidOperand);
        testOp3(m64, .VGATHERDPD,   reg(.YMM1), vm32yl, reg(.YMM2), AsmError.InvalidOperand);
        testOp3(m64, .VGATHERDPD,   reg(.YMM1), vm32z, reg(.YMM2), AsmError.InvalidOperand);
        testOp3(m64, .VGATHERDPD,   reg(.XMM1), vm64xl, reg(.XMM2), AsmError.InvalidOperand);
        testOp2(m64, .VGATHERDPD,   pred(.XMM31, .K7, .Zero), vm32x, "67 62 22 fd 87 92 3c f0");
        testOp2(m64, .VGATHERDPD,   pred(.YMM31, .K7, .Zero), vm32x, "67 62 22 fd a7 92 3c f0");
        testOp2(m64, .VGATHERDPD,   pred(.ZMM31, .K7, .Zero), vm32y, "67 62 22 fd c7 92 3c f0");
    }

    // test disp8*N compressed displacement
    {
        // no displacement
        {
            testOp3(m64, .VADDPD, reg(.XMM1), reg(.XMM2), memRm(.XMM_WORD, .RAX, 0), "c5 e9 58 08");
            testOp3(m64, .VADDPD, reg(.YMM1), reg(.YMM2), memRm(.YMM_WORD, .RAX, 0), "c5 ed 58 08");
            testOp3(m64, .VADDPD, reg(.XMM31), reg(.XMM21), memRm(.XMM_WORD, .RAX, 0), "62 61 d5 00 58 38");
            testOp3(m64, .VADDPD, reg(.YMM31), reg(.YMM21), memRm(.YMM_WORD, .RAX, 0), "62 61 d5 20 58 38");
            testOp3(m64, .VADDPD, reg(.ZMM31), reg(.ZMM21), memRm(.ZMM_WORD, .RAX, 0), "62 61 d5 40 58 38");
        }

        // full
        {
            // vec_len * 1
            testOp3(m64, .VADDPD, reg(.XMM1), reg(.XMM2), memRm(.XMM_WORD, .RAX, 16 * 1), "c5 e9 58 48 10");
            testOp3(m64, .VADDPD, reg(.YMM1), reg(.YMM2), memRm(.YMM_WORD, .RAX, 32 * 1), "c5 ed 58 48 20");
            testOp3(m64, .VADDPD, reg(.XMM31), reg(.XMM21), memRm(.XMM_WORD, .RAX, 16 * 1), "62 61 d5 00 58 78 01");
            testOp3(m64, .VADDPD, reg(.YMM31), reg(.YMM21), memRm(.YMM_WORD, .RAX, 32 * 1), "62 61 d5 20 58 78 01");
            testOp3(m64, .VADDPD, reg(.ZMM31), reg(.ZMM21), memRm(.ZMM_WORD, .RAX, 64 * 1), "62 61 d5 40 58 78 01");
            // vec_len * -1
            testOp3(m64, .VADDPD, reg(.XMM1), reg(.XMM2), memRm(.XMM_WORD, .RAX, 16 * -1), "c5 e9 58 48 f0");
            testOp3(m64, .VADDPD, reg(.YMM1), reg(.YMM2), memRm(.YMM_WORD, .RAX, 32 * -1), "c5 ed 58 48 e0");
            testOp3(m64, .VADDPD, reg(.XMM31), reg(.XMM21), memRm(.XMM_WORD, .RAX, 16 * -1), "62 61 d5 00 58 78 ff");
            testOp3(m64, .VADDPD, reg(.YMM31), reg(.YMM21), memRm(.YMM_WORD, .RAX, 32 * -1), "62 61 d5 20 58 78 ff");
            testOp3(m64, .VADDPD, reg(.ZMM31), reg(.ZMM21), memRm(.ZMM_WORD, .RAX, 64 * -1), "62 61 d5 40 58 78 ff");
            // vec_len * 127
            testOp3(m64, .VADDPD, reg(.XMM1), reg(.XMM2), memRm(.XMM_WORD, .RAX, 16 * 127), "c5 e9 58 88 f0 07 00 00");
            testOp3(m64, .VADDPD, reg(.YMM1), reg(.YMM2), memRm(.YMM_WORD, .RAX, 32 * 127), "c5 ed 58 88 e0 0f 00 00");
            testOp3(m64, .VADDPD, reg(.XMM31), reg(.XMM21), memRm(.XMM_WORD, .RAX, 16 * 127), "62 61 d5 00 58 78 7f");
            testOp3(m64, .VADDPD, reg(.YMM31), reg(.YMM21), memRm(.YMM_WORD, .RAX, 32 * 127), "62 61 d5 20 58 78 7f");
            testOp3(m64, .VADDPD, reg(.ZMM31), reg(.ZMM21), memRm(.ZMM_WORD, .RAX, 64 * 127), "62 61 d5 40 58 78 7f");
            // vec_len * -128
            testOp3(m64, .VADDPD, reg(.XMM1), reg(.XMM2), memRm(.XMM_WORD, .RAX, 16 * -128), "c5 e9 58 88 00 f8 ff ff");
            testOp3(m64, .VADDPD, reg(.YMM1), reg(.YMM2), memRm(.YMM_WORD, .RAX, 32 * -128), "c5 ed 58 88 00 f0 ff ff");
            testOp3(m64, .VADDPD, reg(.XMM31), reg(.XMM21), memRm(.XMM_WORD, .RAX, 16 * -128), "62 61 d5 00 58 78 80");
            testOp3(m64, .VADDPD, reg(.YMM31), reg(.YMM21), memRm(.YMM_WORD, .RAX, 32 * -128), "62 61 d5 20 58 78 80");
            testOp3(m64, .VADDPD, reg(.ZMM31), reg(.ZMM21), memRm(.ZMM_WORD, .RAX, 64 * -128), "62 61 d5 40 58 78 80");
            // vec_len * 128
            testOp3(m64, .VADDPD, reg(.XMM1), reg(.XMM2), memRm(.XMM_WORD, .RAX, 16 * 128), "c5 e9 58 88 00 08 00 00");
            testOp3(m64, .VADDPD, reg(.YMM1), reg(.YMM2), memRm(.YMM_WORD, .RAX, 32 * 128), "c5 ed 58 88 00 10 00 00");
            testOp3(m64, .VADDPD, reg(.XMM31), reg(.XMM21), memRm(.XMM_WORD, .RAX, 16 * 128), "62 61 d5 00 58 b8 00 08 00 00");
            testOp3(m64, .VADDPD, reg(.YMM31), reg(.YMM21), memRm(.YMM_WORD, .RAX, 32 * 128), "62 61 d5 20 58 b8 00 10 00 00");
            testOp3(m64, .VADDPD, reg(.ZMM31), reg(.ZMM21), memRm(.ZMM_WORD, .RAX, 64 * 128), "62 61 d5 40 58 b8 00 20 00 00");
            // vec_len * -129
            testOp3(m64, .VADDPD, reg(.XMM1), reg(.XMM2), memRm(.XMM_WORD, .RAX, 16 * -129), "c5 e9 58 88 f0 f7 ff ff");
            testOp3(m64, .VADDPD, reg(.YMM1), reg(.YMM2), memRm(.YMM_WORD, .RAX, 32 * -129), "c5 ed 58 88 e0 ef ff ff");
            testOp3(m64, .VADDPD, reg(.XMM31), reg(.XMM21), memRm(.XMM_WORD, .RAX, 16 * -129), "62 61 d5 00 58 b8 f0 f7 ff ff");
            testOp3(m64, .VADDPD, reg(.YMM31), reg(.YMM21), memRm(.YMM_WORD, .RAX, 32 * -129), "62 61 d5 20 58 b8 e0 ef ff ff");
            testOp3(m64, .VADDPD, reg(.ZMM31), reg(.ZMM21), memRm(.ZMM_WORD, .RAX, 64 * -129), "62 61 d5 40 58 b8 c0 df ff ff");
            // vec_len * 1 + 1
            testOp3(m64, .VADDPD, reg(.XMM31), reg(.XMM21), memRm(.XMM_WORD, .RAX, 16 * 1 + 1), "62 61 d5 00 58 b8 11 00 00 00");
            testOp3(m64, .VADDPD, reg(.YMM31), reg(.YMM21), memRm(.YMM_WORD, .RAX, 32 * 1 + 1), "62 61 d5 20 58 b8 21 00 00 00");
            testOp3(m64, .VADDPD, reg(.ZMM31), reg(.ZMM21), memRm(.ZMM_WORD, .RAX, 64 * 1 + 1), "62 61 d5 40 58 b8 41 00 00 00");
            // vec_len * 1 - 1
            testOp3(m64, .VADDPD, reg(.XMM31), reg(.XMM21), memRm(.XMM_WORD, .RAX, 16 * 1 - 1), "62 61 d5 00 58 b8 0f 00 00 00");
            testOp3(m64, .VADDPD, reg(.YMM31), reg(.YMM21), memRm(.YMM_WORD, .RAX, 32 * 1 - 1), "62 61 d5 20 58 b8 1f 00 00 00");
            testOp3(m64, .VADDPD, reg(.ZMM31), reg(.ZMM21), memRm(.ZMM_WORD, .RAX, 64 * 1 - 1), "62 61 d5 40 58 b8 3f 00 00 00");
            // m64_bcst
            testOp3(m64, .VADDPD, reg(.XMM31), reg(.XMM21), memRm(.QWORD_BCST, .RAX, 8 * 1), "62 61 d5 10 58 78 01");
            testOp3(m64, .VADDPD, reg(.YMM31), reg(.YMM21), memRm(.QWORD_BCST, .RAX, 8 * 1), "62 61 d5 30 58 78 01");
            testOp3(m64, .VADDPD, reg(.ZMM31), reg(.ZMM21), memRm(.QWORD_BCST, .RAX, 8 * 1), "62 61 d5 50 58 78 01");
            // m32_bcst
            testOp3(m64, .VADDPS, reg(.XMM31), reg(.XMM21), memRm(.DWORD_BCST, .RAX, 4 * 1), "62 61 54 10 58 78 01");
            testOp3(m64, .VADDPS, reg(.YMM31), reg(.YMM21), memRm(.DWORD_BCST, .RAX, 4 * 1), "62 61 54 30 58 78 01");
            testOp3(m64, .VADDPS, reg(.ZMM31), reg(.ZMM21), memRm(.DWORD_BCST, .RAX, 4 * 1), "62 61 54 50 58 78 01");
            // vec_len * 1
            testOp3(m64, .VADDPD, pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRel(.DS, .XMM_WORD, .EIP, 16 * 1), "3e 67 62 f1 ed 08 58 0d 10 00 00 00");
            testOp3(m64, .VADDPD, pred(.YMM1, .NoMask, .Merge), reg(.YMM2), memRel(.DS, .YMM_WORD, .EIP, 32 * 1), "3e 67 62 f1 ed 28 58 0d 20 00 00 00");
            testOp3(m64, .VADDPD, pred(.ZMM1, .NoMask, .Merge), reg(.ZMM2), memRel(.DS, .ZMM_WORD, .EIP, 64 * 1), "3e 67 62 f1 ed 48 58 0d 40 00 00 00");
            // vec_len * 1
            testOp3(m64, .VADDPD, pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memSib(.XMM_WORD, 2, .EAX, .ECX, 16 * 1), "67 62 f1 ed 08 58 4c 41 01");
            testOp3(m64, .VADDPD, pred(.YMM1, .NoMask, .Merge), reg(.YMM2), memSib(.YMM_WORD, 2, .EAX, .ECX, 32 * 1), "67 62 f1 ed 28 58 4c 41 01");
            testOp3(m64, .VADDPD, pred(.ZMM1, .NoMask, .Merge), reg(.ZMM2), memSib(.ZMM_WORD, 2, .EAX, .ECX, 64 * 1), "67 62 f1 ed 48 58 4c 41 01");
            // vec_len * 1
            testOp3(m32, .VADDPD, pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm16(.DS, .XMM_WORD, .BX, .SI, 16 * 1), "3e 67 62 f1 ed 08 58 48 01");
            testOp3(m32, .VADDPD, pred(.YMM1, .NoMask, .Merge), reg(.YMM2), memRm16(.DS, .YMM_WORD, .BX, .SI, 32 * 1), "3e 67 62 f1 ed 28 58 48 01");
            testOp3(m32, .VADDPD, pred(.ZMM1, .NoMask, .Merge), reg(.ZMM2), memRm16(.DS, .ZMM_WORD, .BX, .SI, 64 * 1), "3e 67 62 f1 ed 48 58 48 01");
            // vec_len * 1
            testOp3(m32, .VADDPD, pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm16(.DS, .XMM_WORD, .BX, .SI, 16 * -1), "3e 67 62 f1 ed 08 58 48 ff");
            testOp3(m32, .VADDPD, pred(.YMM1, .NoMask, .Merge), reg(.YMM2), memRm16(.DS, .YMM_WORD, .BX, .SI, 32 * -1), "3e 67 62 f1 ed 28 58 48 ff");
            testOp3(m32, .VADDPD, pred(.ZMM1, .NoMask, .Merge), reg(.ZMM2), memRm16(.DS, .ZMM_WORD, .BX, .SI, 64 * -1), "3e 67 62 f1 ed 48 58 48 ff");
            // vec_len * 127
            testOp3(m32, .VADDPD, pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm16(.DS, .XMM_WORD, .BX, .SI, 16 * 127), "3e 67 62 f1 ed 08 58 48 7f");
            testOp3(m32, .VADDPD, pred(.YMM1, .NoMask, .Merge), reg(.YMM2), memRm16(.DS, .YMM_WORD, .BX, .SI, 32 * 127), "3e 67 62 f1 ed 28 58 48 7f");
            testOp3(m32, .VADDPD, pred(.ZMM1, .NoMask, .Merge), reg(.ZMM2), memRm16(.DS, .ZMM_WORD, .BX, .SI, 64 * 127), "3e 67 62 f1 ed 48 58 48 7f");
            // vec_len * -128
            testOp3(m32, .VADDPD, pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm16(.DS, .XMM_WORD, .BX, .SI, 16 * -128), "3e 67 62 f1 ed 08 58 48 80");
            testOp3(m32, .VADDPD, pred(.YMM1, .NoMask, .Merge), reg(.YMM2), memRm16(.DS, .YMM_WORD, .BX, .SI, 32 * -128), "3e 67 62 f1 ed 28 58 48 80");
            testOp3(m32, .VADDPD, pred(.ZMM1, .NoMask, .Merge), reg(.ZMM2), memRm16(.DS, .ZMM_WORD, .BX, .SI, 64 * -128), "3e 67 62 f1 ed 48 58 48 80");
            // vec_len * 128
            testOp3(m32, .VADDPD, pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm16(.DS, .XMM_WORD, .BX, .SI, 16 * 128), "3e 67 62 f1 ed 08 58 88 00 08");
            testOp3(m32, .VADDPD, pred(.YMM1, .NoMask, .Merge), reg(.YMM2), memRm16(.DS, .YMM_WORD, .BX, .SI, 32 * 128), "3e 67 62 f1 ed 28 58 88 00 10");
            testOp3(m32, .VADDPD, pred(.ZMM1, .NoMask, .Merge), reg(.ZMM2), memRm16(.DS, .ZMM_WORD, .BX, .SI, 64 * 128), "3e 67 62 f1 ed 48 58 88 00 20");
            // vec_len * -129
            testOp3(m32, .VADDPD, pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm16(.DS, .XMM_WORD, .BX, .SI, 16 * -129), "3e 67 62 f1 ed 08 58 88 f0 f7");
            testOp3(m32, .VADDPD, pred(.YMM1, .NoMask, .Merge), reg(.YMM2), memRm16(.DS, .YMM_WORD, .BX, .SI, 32 * -129), "3e 67 62 f1 ed 28 58 88 e0 ef");
            testOp3(m32, .VADDPD, pred(.ZMM1, .NoMask, .Merge), reg(.ZMM2), memRm16(.DS, .ZMM_WORD, .BX, .SI, 64 * -129), "3e 67 62 f1 ed 48 58 88 c0 df");
            // vec_len * 1 - 1
            testOp3(m32, .VADDPD, pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm16(.DS, .XMM_WORD, .BX, .SI, 16 * 1 - 1), "3e 67 62 f1 ed 08 58 88 0f 00");
            testOp3(m32, .VADDPD, pred(.YMM1, .NoMask, .Merge), reg(.YMM2), memRm16(.DS, .YMM_WORD, .BX, .SI, 32 * 1 - 1), "3e 67 62 f1 ed 28 58 88 1f 00");
            testOp3(m32, .VADDPD, pred(.ZMM1, .NoMask, .Merge), reg(.ZMM2), memRm16(.DS, .ZMM_WORD, .BX, .SI, 64 * 1 - 1), "3e 67 62 f1 ed 48 58 88 3f 00");
            // vec_len * 1 + 1
            testOp3(m32, .VADDPD, pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm16(.DS, .XMM_WORD, .BX, .SI, 16 * 1 - 1), "3e 67 62 f1 ed 08 58 88 0f 00");
            testOp3(m32, .VADDPD, pred(.YMM1, .NoMask, .Merge), reg(.YMM2), memRm16(.DS, .YMM_WORD, .BX, .SI, 32 * 1 - 1), "3e 67 62 f1 ed 28 58 88 1f 00");
            testOp3(m32, .VADDPD, pred(.ZMM1, .NoMask, .Merge), reg(.ZMM2), memRm16(.DS, .ZMM_WORD, .BX, .SI, 64 * 1 - 1), "3e 67 62 f1 ed 48 58 88 3f 00");
        }

        // half
        {
            // 1
            testOp2(m64, .VCVTDQ2PD,  pred(.XMM0, .NoMask, .Merge), memRm(.XMM_WORD, .RAX, 1), "62 f1 7e 08 e6 80 01 00 00 00");
            testOp2(m64, .VCVTDQ2PD,  pred(.YMM0, .NoMask, .Merge), memRm(.XMM_WORD, .RAX, 1), "62 f1 7e 28 e6 80 01 00 00 00");
            testOp2(m64, .VCVTDQ2PD,  pred(.ZMM0, .NoMask, .Merge), memRm(.YMM_WORD, .RAX, 1), "62 f1 7e 48 e6 80 01 00 00 00");
            // -1
            testOp2(m64, .VCVTDQ2PD,  pred(.XMM0, .NoMask, .Merge), memRm(.XMM_WORD, .RAX, -1), "62 f1 7e 08 e6 80 ff ff ff ff");
            testOp2(m64, .VCVTDQ2PD,  pred(.YMM0, .NoMask, .Merge), memRm(.XMM_WORD, .RAX, -1), "62 f1 7e 28 e6 80 ff ff ff ff");
            testOp2(m64, .VCVTDQ2PD,  pred(.ZMM0, .NoMask, .Merge), memRm(.YMM_WORD, .RAX, -1), "62 f1 7e 48 e6 80 ff ff ff ff");
            // vec_len * 1
            testOp2(m64, .VCVTDQ2PD,  pred(.XMM0, .NoMask, .Merge), memRm(.XMM_WORD, .RAX, 8), "62 f1 7e 08 e6 40 01");
            testOp2(m64, .VCVTDQ2PD,  pred(.YMM0, .NoMask, .Merge), memRm(.XMM_WORD, .RAX, 16), "62 f1 7e 28 e6 40 01");
            testOp2(m64, .VCVTDQ2PD,  pred(.ZMM0, .NoMask, .Merge), memRm(.YMM_WORD, .RAX, 32), "62 f1 7e 48 e6 40 01");
            // vec_len * -1
            testOp2(m64, .VCVTDQ2PD,  pred(.XMM0, .NoMask, .Merge), memRm(.XMM_WORD, .RAX, -8), "62 f1 7e 08 e6 40 ff");
            testOp2(m64, .VCVTDQ2PD,  pred(.YMM0, .NoMask, .Merge), memRm(.XMM_WORD, .RAX, -16), "62 f1 7e 28 e6 40 ff");
            testOp2(m64, .VCVTDQ2PD,  pred(.ZMM0, .NoMask, .Merge), memRm(.YMM_WORD, .RAX, -32), "62 f1 7e 48 e6 40 ff");
            // m32_bcst
            testOp2(m64, .VCVTDQ2PD,  pred(.XMM0, .NoMask, .Merge), memRm(.DWORD_BCST, .RAX, 0), "62 f1 7e 18 e6 00");
            testOp2(m64, .VCVTDQ2PD,  pred(.YMM0, .NoMask, .Merge), memRm(.DWORD_BCST, .RAX, 0), "62 f1 7e 38 e6 00");
            testOp2(m64, .VCVTDQ2PD,  pred(.ZMM0, .NoMask, .Merge), memRm(.DWORD_BCST, .RAX, 0), "62 f1 7e 58 e6 00");
            // m32_bcst
            testOp2(m64, .VCVTDQ2PD,  pred(.XMM0, .NoMask, .Merge), memRm(.DWORD_BCST, .RAX, -1), "62 f1 7e 18 e6 80 ff ff ff ff");
            testOp2(m64, .VCVTDQ2PD,  pred(.YMM0, .NoMask, .Merge), memRm(.DWORD_BCST, .RAX, -1), "62 f1 7e 38 e6 80 ff ff ff ff");
            testOp2(m64, .VCVTDQ2PD,  pred(.ZMM0, .NoMask, .Merge), memRm(.DWORD_BCST, .RAX, -1), "62 f1 7e 58 e6 80 ff ff ff ff");
            // m32_bcst
            testOp2(m64, .VCVTDQ2PD,  pred(.XMM0, .NoMask, .Merge), memRm(.DWORD_BCST, .RAX, 4), "62 f1 7e 18 e6 40 01");
            testOp2(m64, .VCVTDQ2PD,  pred(.YMM0, .NoMask, .Merge), memRm(.DWORD_BCST, .RAX, 4), "62 f1 7e 38 e6 40 01");
            testOp2(m64, .VCVTDQ2PD,  pred(.ZMM0, .NoMask, .Merge), memRm(.DWORD_BCST, .RAX, 4), "62 f1 7e 58 e6 40 01");
            // m32_bcst
            testOp2(m64, .VCVTDQ2PD,  pred(.XMM0, .NoMask, .Merge), memRm(.DWORD_BCST, .RAX, -4), "62 f1 7e 18 e6 40 ff");
            testOp2(m64, .VCVTDQ2PD,  pred(.YMM0, .NoMask, .Merge), memRm(.DWORD_BCST, .RAX, -4), "62 f1 7e 38 e6 40 ff");
            testOp2(m64, .VCVTDQ2PD,  pred(.ZMM0, .NoMask, .Merge), memRm(.DWORD_BCST, .RAX, -4), "62 f1 7e 58 e6 40 ff");
        }

        // tuple 1 scalar
        {
            testOp3(m64, .VADDSD,     reg(.XMM1), reg(.XMM2), memRm(.QWORD, .RAX, 0), "c5 eb 58 08");
            testOp3(m64, .VADDSS,     reg(.XMM1), reg(.XMM2), memRm(.DWORD, .RAX, 0), "c5 ea 58 08");
            testOp3(m64, .VADDSD,     reg(.XMM1), reg(.XMM2), memRm(.QWORD, .RAX, 0x10), "c5 eb 58 48 10");
            testOp3(m64, .VADDSS,     reg(.XMM1), reg(.XMM2), memRm(.DWORD, .RAX, 0x10), "c5 ea 58 48 10");
            // 8 bit
            testOp3(m64, .VPEXTRB,    memRm(.BYTE, .RAX, 0), reg(.XMM21), imm(0), "62 e3 7d 08 14 28 00");
            testOp3(m64, .VPEXTRB,    memRm(.BYTE, .RAX, 1), reg(.XMM21), imm(0), "62 e3 7d 08 14 68 01 00");
            testOp3(m64, .VPEXTRB,    memRm(.BYTE, .RAX, -1), reg(.XMM21), imm(0), "62 e3 7d 08 14 68 ff 00");
            testOp3(m64, .VPEXTRB,    memRm(.BYTE, .RAX, 0x10), reg(.XMM21), imm(0), "62 e3 7d 08 14 68 10 00");
            testOp3(m64, .VPEXTRB,    memRm(.BYTE, .RAX, -0x10), reg(.XMM21), imm(0), "62 e3 7d 08 14 68 f0 00");
            testOp3(m64, .VPEXTRB,    memRm(.BYTE, .RAX, 0x100), reg(.XMM21), imm(0), "62 e3 7d 08 14 a8 00 01 00 00 00");
            testOp3(m64, .VPEXTRB,    memRm(.BYTE, .RAX, -0x100), reg(.XMM21), imm(0), "62 e3 7d 08 14 a8 00 ff ff ff 00");
            // 16 bit
            testOp3(m64, .VPEXTRW,    memRm(.WORD, .RAX, 0), reg(.XMM21), imm(0), "62 e3 7d 08 15 28 00");
            testOp3(m64, .VPEXTRW,    memRm(.WORD, .RAX, 1), reg(.XMM21), imm(0), "62 e3 7d 08 15 a8 01 00 00 00 00");
            testOp3(m64, .VPEXTRW,    memRm(.WORD, .RAX, -1), reg(.XMM21), imm(0), "62 e3 7d 08 15 a8 ff ff ff ff 00");
            testOp3(m64, .VPEXTRW,    memRm(.WORD, .RAX, 2), reg(.XMM21), imm(0), "62 e3 7d 08 15 68 01 00");
            testOp3(m64, .VPEXTRW,    memRm(.WORD, .RAX, -2), reg(.XMM21), imm(0), "62 e3 7d 08 15 68 ff 00");
            testOp3(m64, .VPEXTRW,    memRm(.WORD, .RAX, 0x80), reg(.XMM21), imm(0), "62 e3 7d 08 15 68 40 00");
            testOp3(m64, .VPEXTRW,    memRm(.WORD, .RAX, -0x80), reg(.XMM21), imm(0), "62 e3 7d 08 15 68 c0 00");
            // 32 bit
            testOp3(m64, .VADDSS,     pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm(.DWORD, .RAX, 0), "62 f1 6e 08 58 08");
            testOp3(m64, .VADDSS,     pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm(.DWORD, .RAX, 1), "62 f1 6e 08 58 88 01 00 00 00");
            testOp3(m64, .VADDSS,     pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm(.DWORD, .RAX, -1), "62 f1 6e 08 58 88 ff ff ff ff");
            testOp3(m64, .VADDSS,     pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm(.DWORD, .RAX, 4), "62 f1 6e 08 58 48 01");
            testOp3(m64, .VADDSS,     pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm(.DWORD, .RAX, -4), "62 f1 6e 08 58 48 ff");
            // 64 bit
            testOp3(m64, .VADDSD,     pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm(.QWORD, .RAX, 0), "62 f1 ef 08 58 08");
            testOp3(m64, .VADDSD,     pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm(.QWORD, .RAX, 1), "62 f1 ef 08 58 88 01 00 00 00");
            testOp3(m64, .VADDSD,     pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm(.QWORD, .RAX, -1), "62 f1 ef 08 58 88 ff ff ff ff");
            testOp3(m64, .VADDSD,     pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm(.QWORD, .RAX, 8), "62 f1 ef 08 58 48 01");
            testOp3(m64, .VADDSD,     pred(.XMM1, .NoMask, .Merge), reg(.XMM2), memRm(.QWORD, .RAX, -8), "62 f1 ef 08 58 48 ff");
        }

        // tuple 1 fixed
        {
            // VCVTSD2USI reg32, xmml_m64_er
            testOp2(m64, .VCVTSD2USI,  reg(.EAX), memRm(.QWORD, .RAX, 0), "62 f1 7f 08 79 00");
            testOp2(m64, .VCVTSD2USI,  reg(.EAX), memRm(.QWORD, .RAX, 1), "62 f1 7f 08 79 80 01 00 00 00");
            testOp2(m64, .VCVTSD2USI,  reg(.EAX), memRm(.QWORD, .RAX, -1), "62 f1 7f 08 79 80 ff ff ff ff");
            testOp2(m64, .VCVTSD2USI,  reg(.EAX), memRm(.QWORD, .RAX, 8), "62 f1 7f 08 79 40 01");
            testOp2(m64, .VCVTSD2USI,  reg(.EAX), memRm(.QWORD, .RAX, -8), "62 f1 7f 08 79 40 ff");
            // VCVTSD2USI reg64, xmml_m64_er
            testOp2(m64, .VCVTSD2USI,  reg(.RAX), memRm(.QWORD, .RAX, 0), "62 f1 ff 08 79 00");
            testOp2(m64, .VCVTSD2USI,  reg(.RAX), memRm(.QWORD, .RAX, 1), "62 f1 ff 08 79 80 01 00 00 00");
            testOp2(m64, .VCVTSD2USI,  reg(.RAX), memRm(.QWORD, .RAX, -1), "62 f1 ff 08 79 80 ff ff ff ff");
            testOp2(m64, .VCVTSD2USI,  reg(.RAX), memRm(.QWORD, .RAX, 8), "62 f1 ff 08 79 40 01");
            testOp2(m64, .VCVTSD2USI,  reg(.RAX), memRm(.QWORD, .RAX, -8), "62 f1 ff 08 79 40 ff");
            // VCVTSS2USI reg32, xmm_m32_er
            testOp2(m64, .VCVTSS2USI,  reg(.EAX), memRm(.DWORD, .RAX, 0), "62 f1 7e 08 79 00");
            testOp2(m64, .VCVTSS2USI,  reg(.EAX), memRm(.DWORD, .RAX, 1), "62 f1 7e 08 79 80 01 00 00 00");
            testOp2(m64, .VCVTSS2USI,  reg(.EAX), memRm(.DWORD, .RAX, -1), "62 f1 7e 08 79 80 ff ff ff ff");
            testOp2(m64, .VCVTSS2USI,  reg(.EAX), memRm(.DWORD, .RAX, 4), "62 f1 7e 08 79 40 01");
            testOp2(m64, .VCVTSS2USI,  reg(.EAX), memRm(.DWORD, .RAX, -4), "62 f1 7e 08 79 40 ff");
            // VCVTSS2USI reg64, xmm_m32_er
            testOp2(m64, .VCVTSS2USI,  reg(.RAX), memRm(.DWORD, .RAX, 0), "62 f1 fe 08 79 00");
            testOp2(m64, .VCVTSS2USI,  reg(.RAX), memRm(.DWORD, .RAX, 1), "62 f1 fe 08 79 80 01 00 00 00");
            testOp2(m64, .VCVTSS2USI,  reg(.RAX), memRm(.DWORD, .RAX, -1), "62 f1 fe 08 79 80 ff ff ff ff");
            testOp2(m64, .VCVTSS2USI,  reg(.RAX), memRm(.DWORD, .RAX, 4), "62 f1 fe 08 79 40 01");
            testOp2(m64, .VCVTSS2USI,  reg(.RAX), memRm(.DWORD, .RAX, -4), "62 f1 fe 08 79 40 ff");
        }

        // tuple 2
        {
            // 32 bit: W=0
            testOp2(m64, .VBROADCASTF32X2,  pred(.ZMM31, .K7, .Zero), memRm(.QWORD, .RAX, 0), "62 62 7d cf 19 38");
            testOp2(m64, .VBROADCASTF32X2,  pred(.ZMM31, .K7, .Zero), memRm(.QWORD, .RAX, 1), "62 62 7d cf 19 b8 01 00 00 00");
            testOp2(m64, .VBROADCASTF32X2,  pred(.ZMM31, .K7, .Zero), memRm(.QWORD, .RAX, -1), "62 62 7d cf 19 b8 ff ff ff ff");
            testOp2(m64, .VBROADCASTF32X2,  pred(.ZMM31, .K7, .Zero), memRm(.QWORD, .RAX, 8), "62 62 7d cf 19 78 01");
            testOp2(m64, .VBROADCASTF32X2,  pred(.ZMM31, .K7, .Zero), memRm(.QWORD, .RAX, -8), "62 62 7d cf 19 78 ff");
            // 64 bit: W=1
            testOp2(m64, .VBROADCASTF64X2,  pred(.ZMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, 0), "62 62 fd cf 1a 38");
            testOp2(m64, .VBROADCASTF64X2,  pred(.ZMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, 1), "62 62 fd cf 1a b8 01 00 00 00");
            testOp2(m64, .VBROADCASTF64X2,  pred(.ZMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, -1), "62 62 fd cf 1a b8 ff ff ff ff");
            testOp2(m64, .VBROADCASTF64X2,  pred(.ZMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, 16), "62 62 fd cf 1a 78 01");
            testOp2(m64, .VBROADCASTF64X2,  pred(.ZMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, -16), "62 62 fd cf 1a 78 ff");
        }

        // tuple 4
        {
            // 32 bit: W=0
            testOp2(m64, .VBROADCASTF32X4,  pred(.ZMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, 0), "62 62 7d cf 1a 38");
            testOp2(m64, .VBROADCASTF32X4,  pred(.ZMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, 1), "62 62 7d cf 1a b8 01 00 00 00");
            testOp2(m64, .VBROADCASTF32X4,  pred(.ZMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, -1), "62 62 7d cf 1a b8 ff ff ff ff");
            testOp2(m64, .VBROADCASTF32X4,  pred(.ZMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, 16), "62 62 7d cf 1a 78 01");
            testOp2(m64, .VBROADCASTF32X4,  pred(.ZMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, -16), "62 62 7d cf 1a 78 ff");
            // 64 bit: W=1
            testOp2(m64, .VBROADCASTF64X4,  pred(.ZMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, 0), "62 62 fd cf 1b 38");
            testOp2(m64, .VBROADCASTF64X4,  pred(.ZMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, 1), "62 62 fd cf 1b b8 01 00 00 00");
            testOp2(m64, .VBROADCASTF64X4,  pred(.ZMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, -1), "62 62 fd cf 1b b8 ff ff ff ff");
            testOp2(m64, .VBROADCASTF64X4,  pred(.ZMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, 32), "62 62 fd cf 1b 78 01");
            testOp2(m64, .VBROADCASTF64X4,  pred(.ZMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, -32), "62 62 fd cf 1b 78 ff");
        }

        // tuple 8
        {
            // 32 bit: W=0
            testOp2(m64, .VBROADCASTF32X8,  pred(.ZMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, 0), "62 62 7d cf 1b 38");
            testOp2(m64, .VBROADCASTF32X8,  pred(.ZMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, 1), "62 62 7d cf 1b b8 01 00 00 00");
            testOp2(m64, .VBROADCASTF32X8,  pred(.ZMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, -1), "62 62 7d cf 1b b8 ff ff ff ff");
            testOp2(m64, .VBROADCASTF32X8,  pred(.ZMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, 32), "62 62 7d cf 1b 78 01");
            testOp2(m64, .VBROADCASTF32X8,  pred(.ZMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, -32), "62 62 7d cf 1b 78 ff");
        }

        // full mem
        {
            testOp2(m64, .VPABSB,  pred(.XMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, 1), "62 62 7d 8f 1c b8 01 00 00 00");
            testOp2(m64, .VPABSB,  pred(.YMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, 1), "62 62 7d af 1c b8 01 00 00 00");
            testOp2(m64, .VPABSB,  pred(.ZMM31, .K7, .Zero), memRm(.ZMM_WORD, .RAX, 1), "62 62 7d cf 1c b8 01 00 00 00");
            //
            testOp2(m64, .VPABSB,  pred(.XMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, 16), "62 62 7d 8f 1c 78 01");
            testOp2(m64, .VPABSB,  pred(.YMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, 32), "62 62 7d af 1c 78 01");
            testOp2(m64, .VPABSB,  pred(.ZMM31, .K7, .Zero), memRm(.ZMM_WORD, .RAX, 64), "62 62 7d cf 1c 78 01");
        }

        // half mem
        {
            testOp2(m64, .VPMOVSXBW,  pred(.XMM31, .K7, .Zero), memRm(.QWORD, .RAX, 1), "62 62 7d 8f 20 b8 01 00 00 00");
            testOp2(m64, .VPMOVSXBW,  pred(.YMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, 1), "62 62 7d af 20 b8 01 00 00 00");
            testOp2(m64, .VPMOVSXBW,  pred(.ZMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, 1), "62 62 7d cf 20 b8 01 00 00 00");
            //
            testOp2(m64, .VPMOVSXBW,  pred(.XMM31, .K7, .Zero), memRm(.QWORD, .RAX, 8), "62 62 7d 8f 20 78 01");
            testOp2(m64, .VPMOVSXBW,  pred(.YMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, 16), "62 62 7d af 20 78 01");
            testOp2(m64, .VPMOVSXBW,  pred(.ZMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, 32), "62 62 7d cf 20 78 01");
        }

        // quarter mem
        {
            testOp2(m64, .VPMOVSXBD,  pred(.XMM31, .K7, .Zero), memRm(.DWORD, .RAX, 1), "62 62 7d 8f 21 b8 01 00 00 00");
            testOp2(m64, .VPMOVSXBD,  pred(.YMM31, .K7, .Zero), memRm(.QWORD, .RAX, 1), "62 62 7d af 21 b8 01 00 00 00");
            testOp2(m64, .VPMOVSXBD,  pred(.ZMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, 1), "62 62 7d cf 21 b8 01 00 00 00");
            //
            testOp2(m64, .VPMOVSXBD,  pred(.XMM31, .K7, .Zero), memRm(.DWORD, .RAX, 4), "62 62 7d 8f 21 78 01");
            testOp2(m64, .VPMOVSXBD,  pred(.YMM31, .K7, .Zero), memRm(.QWORD, .RAX, 8), "62 62 7d af 21 78 01");
            testOp2(m64, .VPMOVSXBD,  pred(.ZMM31, .K7, .Zero), memRm(.XMM_WORD, .RAX, 16), "62 62 7d cf 21 78 01");
        }

        // eigth mem
        {
            testOp2(m64, .VPMOVSXBQ,  pred(.XMM31, .K7, .Zero), memRm(.WORD, .RAX, 1), "62 62 7d 8f 22 b8 01 00 00 00");
            testOp2(m64, .VPMOVSXBQ,  pred(.YMM31, .K7, .Zero), memRm(.DWORD, .RAX, 1), "62 62 7d af 22 b8 01 00 00 00");
            testOp2(m64, .VPMOVSXBQ,  pred(.ZMM31, .K7, .Zero), memRm(.QWORD, .RAX, 1), "62 62 7d cf 22 b8 01 00 00 00");
            //
            testOp2(m64, .VPMOVSXBQ,  pred(.XMM31, .K7, .Zero), memRm(.WORD, .RAX, 2), "62 62 7d 8f 22 78 01");
            testOp2(m64, .VPMOVSXBQ,  pred(.YMM31, .K7, .Zero), memRm(.DWORD, .RAX, 4), "62 62 7d af 22 78 01");
            testOp2(m64, .VPMOVSXBQ,  pred(.ZMM31, .K7, .Zero), memRm(.QWORD, .RAX, 8), "62 62 7d cf 22 78 01");
        }

        // mem 128
        {
            testOp3(m64, .VPSLLW,     pred(.XMM31, .K7, .Zero), reg(.XMM21), memRm(.XMM_WORD, .RAX, 1), "62 61 55 87 f1 b8 01 00 00 00");
            testOp3(m64, .VPSLLW,     pred(.YMM31, .K7, .Zero), reg(.YMM21), memRm(.XMM_WORD, .RAX, 1), "62 61 55 a7 f1 b8 01 00 00 00");
            testOp3(m64, .VPSLLW,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), memRm(.XMM_WORD, .RAX, 1), "62 61 55 c7 f1 b8 01 00 00 00");
            //
            testOp3(m64, .VPSLLW,     pred(.XMM31, .K7, .Zero), reg(.XMM21), memRm(.XMM_WORD, .RAX, 16), "62 61 55 87 f1 78 01");
            testOp3(m64, .VPSLLW,     pred(.YMM31, .K7, .Zero), reg(.YMM21), memRm(.XMM_WORD, .RAX, 16), "62 61 55 a7 f1 78 01");
            testOp3(m64, .VPSLLW,     pred(.ZMM31, .K7, .Zero), reg(.ZMM21), memRm(.XMM_WORD, .RAX, 16), "62 61 55 c7 f1 78 01");
        }

        // MOVDDUP
        {
            testOp2(m64, .VMOVDDUP,   pred(.XMM31, .K7, .Zero), memRm(.QWORD, .RAX, 1), "62 61 ff 8f 12 b8 01 00 00 00");
            testOp2(m64, .VMOVDDUP,   pred(.YMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, 1), "62 61 ff af 12 b8 01 00 00 00");
            testOp2(m64, .VMOVDDUP,   pred(.ZMM31, .K7, .Zero), memRm(.ZMM_WORD, .RAX, 1), "62 61 ff cf 12 b8 01 00 00 00");
            //
            testOp2(m64, .VMOVDDUP,   pred(.XMM31, .K7, .Zero), memRm(.QWORD, .RAX, 8), "62 61 ff 8f 12 78 01");
            testOp2(m64, .VMOVDDUP,   pred(.YMM31, .K7, .Zero), memRm(.YMM_WORD, .RAX, 32), "62 61 ff af 12 78 01");
            testOp2(m64, .VMOVDDUP,   pred(.ZMM31, .K7, .Zero), memRm(.ZMM_WORD, .RAX, 64), "62 61 ff cf 12 78 01");
        }
    }

}
