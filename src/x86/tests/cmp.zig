const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/cmp

test "cmp" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        const op1 = Operand.register(.RAX);
        const op2 = Operand.immediate(0x00);
        testOp2(m32, .CMP, op1, op2, AsmError.InvalidOperand);
        testOp2(m64, .CMP, op1, op2, "48 83 f8 00");
    }

    {
        // Since the immediate is signed extended, need to use a different
        // encoding for this value
        const op1 = Operand.register(.RAX);
        const op2 = Operand.immediate(0xff);
        testOp2(m32, .CMP, op1, op2, AsmError.InvalidOperand);
        testOp2(m64, .CMP, op1, op2, "48 3d ff 00 00 00");
    }

    {
        // However, if the immediate is marked as Signed, then we can use the
        // shorter encoding.
        const op1 = Operand.register(.RAX);
        const op2 = Operand.immediateSigned(-1);
        testOp2(m32, .CMP, op1, op2, AsmError.InvalidOperand);
        testOp2(m64, .CMP, op1, op2, "48 83 f8 ff");
    }

    {
        const op1 = Operand.register(.AL);
        const op2 = Operand.immediateSigned(-1);
        testOp2(m32, .CMP, op1, op2, "3C ff");
        testOp2(m64, .CMP, op1, op2, "3C ff");
    }

    {
        const op1 = Operand.register(.AX);
        const op2 = Operand.immediate16(0xff);
        testOp2(m32, .CMP, op1, op2, "66 3D ff 00");
        testOp2(m64, .CMP, op1, op2, "66 3D ff 00");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.immediateSigned32(0xff);
        testOp2(m32, .CMP, op1, op2, "3D ff 00 00 00");
        testOp2(m64, .CMP, op1, op2, "3D ff 00 00 00");
    }

    {
        const op1 = Operand.register(.RAX);
        const op2 = Operand.immediateSigned64(0xff);
        testOp2(m32, .CMP, op1, op2, AsmError.InvalidOperand);
        testOp2(m64, .CMP, op1, op2, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.register(.RAX);
        const op2 = Operand.immediateSigned32(0xff);
        testOp2(m32, .CMP, op1, op2, AsmError.InvalidOperand);
        testOp2(m64, .CMP, op1, op2, "48 3D ff 00 00 00");
    }

    {
        const op1 = Operand.register(.AX);
        const op2 = Operand.immediateSigned(-1);
        testOp2(m32, .CMP, op1, op2, "66 83 f8 ff");
        testOp2(m64, .CMP, op1, op2, "66 83 f8 ff");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.immediateSigned(-1);
        testOp2(m32, .CMP, op1, op2, "83 f8 ff");
        testOp2(m64, .CMP, op1, op2, "83 f8 ff");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.immediateSigned8(-1);
        testOp2(m32, .CMP, op1, op2, "83 f8 ff");
        testOp2(m64, .CMP, op1, op2, "83 f8 ff");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.immediateSigned32(-1);
        testOp2(m32, .CMP, op1, op2, "3d ff ff ff ff");
        testOp2(m64, .CMP, op1, op2, "3d ff ff ff ff");
    }

    {
        const op1 = Operand.registerRm(.EAX);
        const op2 = Operand.register(.EAX);
        testOp2(m32, .CMP, op1, op2, "39 c0");
        testOp2(m64, .CMP, op1, op2, "39 c0");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.registerRm(.EAX);
        testOp2(m32, .CMP, op1, op2, "3b c0");
        testOp2(m64, .CMP, op1, op2, "3b c0");
    }

    {
        const op1 = Operand.registerRm(.AL);
        const op2 = Operand.register(.AL);
        testOp2(m32, .CMP, op1, op2, "38 c0");
        testOp2(m64, .CMP, op1, op2, "38 c0");
    }

    {
        const op1 = Operand.register(.AL);
        const op2 = Operand.registerRm(.AL);
        testOp2(m32, .CMP, op1, op2, "3a c0");
        testOp2(m64, .CMP, op1, op2, "3a c0");
    }

    {
        const op1 = Operand.registerRm(.EAX);
        const op2 = Operand.immediate32(0x33221100);
        testOp2(m32, .CMP, op1, op2, "81 f8 00 11 22 33");
        testOp2(m64, .CMP, op1, op2, "81 f8 00 11 22 33");
    }

    {
        const op1 = Operand.registerRm(.AL);
        const op2 = Operand.immediate8(0x00);
        testOp2(m32, .CMP, op1, op2, "80 f8 00");
        testOp2(m64, .CMP, op1, op2, "80 f8 00");
    }
}
