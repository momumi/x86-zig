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

const regRm = Operand.registerRm;
const memSib = Operand.memorySibDef;
const far16 = Operand.far16;
const far32 = Operand.far32;


test "jmp" {
    const m16 = Machine.init(.x86_16);
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        testOp1(m32, .JMP, imm16(0x1100), "66 E9 00 11");
        testOp1(m64, .JMP, imm16(0x1100), AsmError.InvalidOperand);

        testOp1(m32, .JMP, imm(0x80), "66 E9 80 00");
        testOp1(m64, .JMP, imm(0x80), "E9 80 00 00 00");

        testOp1(m32, .JMP, imm8(0x80), AsmError.InvalidOperand);
        testOp1(m64, .JMP, imm8(0x80), AsmError.InvalidOperand);

        testOp1(m32, .JMP, immSign8(-128), "EB 80");
        testOp1(m64, .JMP, immSign8(-128), "EB 80");

        testOp1(m32, .JMP, immSign(0x80), "66 E9 80 00");
        testOp1(m64, .JMP, immSign(0x80), "E9 80 00 00 00");

        testOp1(m32, .JMP, immSign(-128), "EB 80");
        testOp1(m64, .JMP, immSign(-128), "EB 80");

        testOp1(m32, .JMP, imm(0x7F), "EB 7F");
        testOp1(m64, .JMP, imm(0x7F), "EB 7F");

        testOp1(m32, .JMP, imm8(0), "EB 00");
        testOp1(m64, .JMP, imm8(0), "EB 00");

        testOp1(m16, .JMP, imm32(0x33221100), "66 E9 00 11 22 33");
        testOp1(m32, .JMP, imm32(0x33221100), "E9 00 11 22 33");
        testOp1(m64, .JMP, imm32(0x33221100), "E9 00 11 22 33");

        testOp1(m16, .JMP, imm64(0), AsmError.InvalidOperand);
        testOp1(m32, .JMP, imm64(0), AsmError.InvalidOperand);
        testOp1(m64, .JMP, imm64(0), AsmError.InvalidOperand);

        testOp1(m16, .JMP, immSign64(0), AsmError.InvalidOperand);
        testOp1(m32, .JMP, immSign64(0), AsmError.InvalidOperand);
        testOp1(m64, .JMP, immSign64(0), AsmError.InvalidOperand);
    }

    {
        testOp1(m32, .JMP, regRm(.AX), "66 ff e0");
        testOp1(m64, .JMP, regRm(.AX), AsmError.InvalidOperand);
        //
        testOp1(m32, .JMP, regRm(.EAX), "ff e0");
        testOp1(m64, .JMP, regRm(.EAX), AsmError.InvalidOperand);
        //
        testOp1(m32, .JMP, regRm(.RAX), AsmError.InvalidOperand);
        testOp1(m64, .JMP, regRm(.RAX), "ff e0");

    }

    {
        testOp1(m32, .JMP, memSib(.FAR_WORD, 1, .EAX, .EAX, 0), "66 FF 2C 00");
        testOp1(m64, .JMP, memSib(.FAR_WORD, 1, .EAX, .EAX, 0), "66 67 FF 2C 00");
        //
        testOp1(m32, .JMP, memSib(.FAR_DWORD, 1, .EAX, .EAX, 0), "FF 2C 00");
        testOp1(m64, .JMP, memSib(.FAR_DWORD, 1, .EAX, .EAX, 0), "67 FF 2C 00");
        //
        testOp1(m32, .JMP, memSib(.FAR_QWORD, 1, .EAX, .EAX, 0), AsmError.InvalidOperand);
        testOp1(m64, .JMP, memSib(.FAR_QWORD, 1, .EAX, .EAX, 0), "67 48 FF 2C 00");
    }

    {
        testOp1(m32, .JMP, far16(0x1100, 0x3322), "66 EA 22 33 00 11");
        testOp1(m64, .JMP, far16(0x1100, 0x3322), AsmError.InvalidOperand);
        //
        testOp1(m32, .JMP, far32(0x1100, 0x55443322), "EA 22 33 44 55 00 11");
        testOp1(m64, .JMP, far32(0x1100, 0x55443322), AsmError.InvalidOperand);
    }
}
