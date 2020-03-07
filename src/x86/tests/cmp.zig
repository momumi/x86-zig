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

test "cmp" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        testOp2(m32, .CMP, reg(.RAX), imm(0), AsmError.InvalidOperand);
        testOp2(m64, .CMP, reg(.RAX), imm(0), "48 83 f8 00");
        //
        testOp2(m32, .CMP, reg(.RAX), imm(0xff), AsmError.InvalidOperand);
        testOp2(m64, .CMP, reg(.RAX), imm(0xff), "48 3d ff 00 00 00");
        //
        testOp2(m32, .CMP, reg(.RAX), immSign(-1), AsmError.InvalidOperand);
        testOp2(m64, .CMP, reg(.RAX), immSign(-1), "48 83 f8 ff");
        //
        testOp2(m32, .CMP, reg(.AL), immSign(-1), "3C ff");
        testOp2(m64, .CMP, reg(.AL), immSign(-1), "3C ff");
        //
        testOp2(m32, .CMP, reg(.AX), imm16(0xff), "66 3D ff 00");
        testOp2(m64, .CMP, reg(.AX), imm16(0xff), "66 3D ff 00");
        //
        testOp2(m32, .CMP, reg(.EAX), imm32(0xff), "3D ff 00 00 00");
        testOp2(m64, .CMP, reg(.EAX), imm32(0xff), "3D ff 00 00 00");
        //
        testOp2(m32, .CMP, reg(.RAX), immSign64(0xff), AsmError.InvalidOperand);
        testOp2(m64, .CMP, reg(.RAX), immSign64(0xff), AsmError.InvalidOperand);
        //
        testOp2(m32, .CMP, reg(.RAX), immSign32(0xff), AsmError.InvalidOperand);
        testOp2(m64, .CMP, reg(.RAX), immSign32(0xff), "48 3D ff 00 00 00");
        //
        testOp2(m32, .CMP, reg(.AX), immSign(-1), "66 83 f8 ff");
        testOp2(m64, .CMP, reg(.AX), immSign(-1), "66 83 f8 ff");
        //
        testOp2(m32, .CMP, reg(.EAX), immSign(-1), "83 f8 ff");
        testOp2(m64, .CMP, reg(.EAX), immSign(-1), "83 f8 ff");
        //
        testOp2(m32, .CMP, reg(.EAX), immSign(-1), "83 f8 ff");
        testOp2(m64, .CMP, reg(.EAX), immSign(-1), "83 f8 ff");
        //
        testOp2(m32, .CMP, reg(.EAX), immSign32(-1), "3d ff ff ff ff");
        testOp2(m64, .CMP, reg(.EAX), immSign32(-1), "3d ff ff ff ff");
    }

    {
        testOp2(m32, .CMP, reg(.EAX), reg(.EAX), "3b c0");
        testOp2(m64, .CMP, reg(.EAX), reg(.EAX), "3b c0");
        //
        testOp2(m32, .CMP, reg(.EAX), regRm(.EAX), "3b c0");
        testOp2(m64, .CMP, reg(.EAX), regRm(.EAX), "3b c0");
        //
        testOp2(m32, .CMP, regRm(.EAX), reg(.EAX), "39 c0");
        testOp2(m64, .CMP, regRm(.EAX), reg(.EAX), "39 c0");
    }

    {
        testOp2(m32, .CMP, reg(.AL), regRm(.AL), "3a c0");
        testOp2(m64, .CMP, reg(.AL), regRm(.AL), "3a c0");
        //
        testOp2(m32, .CMP, regRm(.AL), reg(.AL), "38 c0");
        testOp2(m64, .CMP, regRm(.AL), reg(.AL), "38 c0");
    }

    {
        testOp2(m32, .CMP, regRm(.EAX), imm32(0x33221100), "81 f8 00 11 22 33");
        testOp2(m64, .CMP, regRm(.EAX), imm32(0x33221100), "81 f8 00 11 22 33");
        //
        testOp2(m32, .CMP, regRm(.AL), imm8(0), "80 f8 00");
        testOp2(m64, .CMP, regRm(.AL), imm8(0), "80 f8 00");
    }
}
