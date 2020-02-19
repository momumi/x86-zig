const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "16 bit mode" {
    const m16 = Machine.init(.x86_16);
    const m64 = Machine.init(.x64);

    const reg = Operand.register;
    const pred = Operand.registerPredicate;

    const m32bcst = Operand.memory16Bit(.ES, .DWORD_BCST, .BX, .SI, 0);
    const memory16 = Operand.memory16Bit;
    const memRm = Operand.memoryRmDef;

    debugPrint(false);

    testOp2(m16, .MOV, reg(.BH), memory16(.SS, .BYTE, null, .DI, 0x10),  "36 8a 7d 10");
    testOp2(m16, .MOV, reg(.AX), memory16(.CS, .WORD, null, .SI, 0),  "2e 8b 04");
    testOp2(m16, .MOV, reg(.ECX), memory16(.ES, .DWORD, .BX, null, 0x1100),  "26 66 8b 8f 00 11");
    testOp2(m16, .MOV, reg(.EDI), memory16(.GS, .DWORD, null, null, 0x10),  "65 66 8b be 10 00");
    testOp2(m16, .MOV, reg(.RAX), memory16(.FS, .DWORD, .BX, .SI, 0x10),  AsmError.InvalidOperand);

    testOp2(m16, .MOV, reg(.BH), memRm(.BYTE, .EAX, 0x00),  "67 8a 38");
    testOp2(m16, .MOV, reg(.AX), memRm(.WORD, .EAX, 0x00),  "67 8b 00");
    testOp2(m16, .MOV, reg(.EAX), memRm(.DWORD, .EAX, 0x00),  "66 67 8b 00");
    testOp2(m16, .MOV, reg(.EAX), memRm(.DWORD, .RAX, 0x00),  AsmError.InvalidOperand);

    testOp2(m16, .MOV, reg(.R8B), reg(.R8B),  AsmError.InvalidMode);
    testOp2(m16, .MOV, reg(.SIL), reg(.AL), AsmError.InvalidMode);
    testOp2(m16, .MOV, reg(.AL), reg(.SIL), AsmError.InvalidMode);
    testOp2(m16, .MOV, reg(.RAX), reg(.RAX), AsmError.InvalidOperand);

    testOp3(m16, .VADDPS, pred(.ZMM3,  .K7, .Zero), reg(.ZMM7), m32bcst,  "26 62 f1 44 df 58 18");
    testOp3(m16, .VADDPS, pred(.ZMM3,  .K7, .Zero), reg(.ZMM8), m32bcst,  AsmError.InvalidMode);
    testOp3(m16, .VADDPS, pred(.ZMM8,  .K7, .Zero), reg(.ZMM0), m32bcst,  AsmError.InvalidMode);
}
