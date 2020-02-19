const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "AVX-512" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    const reg = Operand.register;
    const pred = Operand.registerPredicate;
    const sae = Operand.registerSae;
    const regRm = Operand.registerRm;
    const imm = Operand.immediate;

    const mem_void = Operand.memoryRm(.DefaultSeg, .Void, .EAX, 0);
    const mem_32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const mem_64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
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

}
