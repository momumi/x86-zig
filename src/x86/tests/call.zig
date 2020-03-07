const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

const imm = Operand.immediate;
const imm8 = Operand.immediate8;
const imm16 = Operand.immediate16;
const imm32 = Operand.immediate32;
const imm64 = Operand.immediate64;

const immSign = Operand.immediateSigned;
const immSign8 = Operand.immediateSigned8;
const immSign16 = Operand.immediateSigned16;
const immSign32 = Operand.immediateSigned32;
const immSign64 = Operand.immediateSigned64;

const reg = Operand.register;
const regRm = Operand.registerRm;
const memSib = Operand.memorySibDef;
const far16 = Operand.far16;
const far32 = Operand.far32;

test "call" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        testOp1(m32, .CALL, immSign16(-1), "66 E8 ff ff");
        testOp1(m64, .CALL, immSign16(-1), AsmError.InvalidOperand);
        //
        testOp1(m32, .CALL, immSign32(-1), "E8 ff ff ff ff");
        testOp1(m64, .CALL, immSign32(-1), "E8 ff ff ff ff");
    }

    {
        testOp1(m32, .CALL, reg(.AX), "66 ff d0");
        testOp1(m64, .CALL, reg(.AX), AsmError.InvalidOperand);
        //
        testOp1(m32, .CALL, regRm(.AX), "66 ff d0");
        testOp1(m64, .CALL, regRm(.AX), AsmError.InvalidOperand);
        //
        testOp1(m32, .CALL, regRm(.EAX), "ff d0");
        testOp1(m64, .CALL, regRm(.EAX), AsmError.InvalidOperand);
        //
        testOp1(m32, .CALL, regRm(.RAX), AsmError.InvalidOperand);
        testOp1(m64, .CALL, regRm(.RAX), "ff d0");
    }

    {
        testOp1(m32, .CALL, far16(0x1100, 0x3322), "66 9A 22 33 00 11");
        testOp1(m64, .CALL, far16(0x1100, 0x3322), AsmError.InvalidOperand);
        //
        testOp1(m32, .CALL, far32(0x1100, 0x55443322), "9A 22 33 44 55 00 11");
        testOp1(m64, .CALL, far32(0x1100, 0x55443322), AsmError.InvalidOperand);
    }

    {
        testOp1(m32, .CALL, memSib(.FAR_WORD, 1, .EAX, .EAX, 0), "66 FF 1C 00");
        testOp1(m64, .CALL, memSib(.FAR_WORD, 1, .EAX, .EAX, 0), "66 67 FF 1C 00");
        //
        testOp1(m32, .CALL, memSib(.FAR_DWORD, 1, .EAX, .EAX, 0), "FF 1C 00");
        testOp1(m64, .CALL, memSib(.FAR_DWORD, 1, .EAX, .EAX, 0), "67 FF 1C 00");
        //
        testOp1(m32, .CALL, memSib(.FAR_QWORD, 1, .EAX, .EAX, 0), AsmError.InvalidOperand);
        testOp1(m64, .CALL, memSib(.FAR_QWORD, 1, .EAX, .EAX, 0), "67 48 FF 1C 00");
    }
}
