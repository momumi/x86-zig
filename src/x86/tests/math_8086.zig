const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "add / adc / and / cmp / or / sbb / sub / xor" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        const op1 = Operand.register(.AL);
        const op2 = Operand.immediate8(0x00);
        testOp2(m64, .ADD, op1, op2, "04 00");
        testOp2(m64, .ADC, op1, op2, "14 00");
        testOp2(m64, .AND, op1, op2, "24 00");
        testOp2(m64, .OR,  op1, op2, "0c 00");
        testOp2(m64, .SBB, op1, op2, "1c 00");
        testOp2(m64, .SUB, op1, op2, "2c 00");
        testOp2(m64, .XOR, op1, op2, "34 00");
        testOp2(m64, .CMP, op1, op2, "3c 00");
    }

    {
        const op1 = Operand.register(.AX);
        const op2 = Operand.immediate16(0x00);
        testOp2(m64, .ADD, op1, op2, "66 05 00 00");
        testOp2(m64, .ADC, op1, op2, "66 15 00 00");
        testOp2(m64, .AND, op1, op2, "66 25 00 00");
        testOp2(m64, .OR,  op1, op2, "66 0d 00 00");
        testOp2(m64, .SBB, op1, op2, "66 1d 00 00");
        testOp2(m64, .SUB, op1, op2, "66 2d 00 00");
        testOp2(m64, .XOR, op1, op2, "66 35 00 00");
        testOp2(m64, .CMP, op1, op2, "66 3d 00 00");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.immediate32(0x00);
        testOp2(m64, .ADD, op1, op2, "05 00 00 00 00");
        testOp2(m64, .ADC, op1, op2, "15 00 00 00 00");
        testOp2(m64, .AND, op1, op2, "25 00 00 00 00");
        testOp2(m64, .OR,  op1, op2, "0d 00 00 00 00");
        testOp2(m64, .SBB, op1, op2, "1d 00 00 00 00");
        testOp2(m64, .SUB, op1, op2, "2d 00 00 00 00");
        testOp2(m64, .XOR, op1, op2, "35 00 00 00 00");
        testOp2(m64, .CMP, op1, op2, "3d 00 00 00 00");
    }

    {
        const op1 = Operand.register(.RAX);
        const op2 = Operand.immediate32(0x00);
        testOp2(m64, .ADD, op1, op2, "48 05 00 00 00 00");
        testOp2(m64, .ADC, op1, op2, "48 15 00 00 00 00");
        testOp2(m64, .AND, op1, op2, "48 25 00 00 00 00");
        testOp2(m64, .OR,  op1, op2, "48 0d 00 00 00 00");
        testOp2(m64, .SBB, op1, op2, "48 1d 00 00 00 00");
        testOp2(m64, .SUB, op1, op2, "48 2d 00 00 00 00");
        testOp2(m64, .XOR, op1, op2, "48 35 00 00 00 00");
        testOp2(m64, .CMP, op1, op2, "48 3d 00 00 00 00");
    }

    {
        const op1 = Operand.register(.RAX);
        const op2 = Operand.immediate8(0x00);
        testOp2(m64, .ADD, op1, op2, "48 83 c0 00");
        testOp2(m64, .ADC, op1, op2, "48 83 d0 00");
        testOp2(m64, .AND, op1, op2, "48 83 e0 00");
        testOp2(m64, .OR,  op1, op2, "48 83 c8 00");
        testOp2(m64, .SBB, op1, op2, "48 83 d8 00");
        testOp2(m64, .SUB, op1, op2, "48 83 e8 00");
        testOp2(m64, .XOR, op1, op2, "48 83 f0 00");
        testOp2(m64, .CMP, op1, op2, "48 83 f8 00");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.immediate8(0x00);
        testOp2(m64, .ADD, op1, op2, "83 c0 00");
        testOp2(m64, .ADC, op1, op2, "83 d0 00");
        testOp2(m64, .AND, op1, op2, "83 e0 00");
        testOp2(m64, .OR,  op1, op2, "83 c8 00");
        testOp2(m64, .SBB, op1, op2, "83 d8 00");
        testOp2(m64, .SUB, op1, op2, "83 e8 00");
        testOp2(m64, .XOR, op1, op2, "83 f0 00");
        testOp2(m64, .CMP, op1, op2, "83 f8 00");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.immediate8(0x00);
        testOp2(m64, .ADD, op1, op2, "83 c0 00");
        testOp2(m64, .ADC, op1, op2, "83 d0 00");
        testOp2(m64, .AND, op1, op2, "83 e0 00");
        testOp2(m64, .OR,  op1, op2, "83 c8 00");
        testOp2(m64, .SBB, op1, op2, "83 d8 00");
        testOp2(m64, .SUB, op1, op2, "83 e8 00");
        testOp2(m64, .XOR, op1, op2, "83 f0 00");
        testOp2(m64, .CMP, op1, op2, "83 f8 00");
    }

    {
        const op1 = Operand.register(.AX);
        const op2 = Operand.immediate8(0x00);
        testOp2(m64, .ADD, op1, op2, "66 83 c0 00");
        testOp2(m64, .ADC, op1, op2, "66 83 d0 00");
        testOp2(m64, .AND, op1, op2, "66 83 e0 00");
        testOp2(m64, .OR,  op1, op2, "66 83 c8 00");
        testOp2(m64, .SBB, op1, op2, "66 83 d8 00");
        testOp2(m64, .SUB, op1, op2, "66 83 e8 00");
        testOp2(m64, .XOR, op1, op2, "66 83 f0 00");
        testOp2(m64, .CMP, op1, op2, "66 83 f8 00");
    }

    {
        const op1 = Operand.registerRm(.R8W);
        const op2 = Operand.immediate16(0x00);
        testOp2(m64, .ADD, op1, op2, "66 41 81 c0 00 00");
        testOp2(m64, .ADC, op1, op2, "66 41 81 d0 00 00");
        testOp2(m64, .AND, op1, op2, "66 41 81 e0 00 00");
        testOp2(m64, .OR,  op1, op2, "66 41 81 c8 00 00");
        testOp2(m64, .SBB, op1, op2, "66 41 81 d8 00 00");
        testOp2(m64, .SUB, op1, op2, "66 41 81 e8 00 00");
        testOp2(m64, .XOR, op1, op2, "66 41 81 f0 00 00");
        testOp2(m64, .CMP, op1, op2, "66 41 81 f8 00 00");
    }

    {
        const op1 = Operand.registerRm(.R8D);
        const op2 = Operand.immediate32(0x00);
        testOp2(m64, .ADD, op1, op2, "41 81 c0 00 00 00 00");
        testOp2(m64, .ADC, op1, op2, "41 81 d0 00 00 00 00");
        testOp2(m64, .AND, op1, op2, "41 81 e0 00 00 00 00");
        testOp2(m64, .OR,  op1, op2, "41 81 c8 00 00 00 00");
        testOp2(m64, .SBB, op1, op2, "41 81 d8 00 00 00 00");
        testOp2(m64, .SUB, op1, op2, "41 81 e8 00 00 00 00");
        testOp2(m64, .XOR, op1, op2, "41 81 f0 00 00 00 00");
        testOp2(m64, .CMP, op1, op2, "41 81 f8 00 00 00 00");
    }

    {
        const op1 = Operand.registerRm(.R8);
        const op2 = Operand.immediate32(0x00);
        testOp2(m64, .ADD, op1, op2, "49 81 c0 00 00 00 00");
        testOp2(m64, .ADC, op1, op2, "49 81 d0 00 00 00 00");
        testOp2(m64, .AND, op1, op2, "49 81 e0 00 00 00 00");
        testOp2(m64, .OR,  op1, op2, "49 81 c8 00 00 00 00");
        testOp2(m64, .SBB, op1, op2, "49 81 d8 00 00 00 00");
        testOp2(m64, .SUB, op1, op2, "49 81 e8 00 00 00 00");
        testOp2(m64, .XOR, op1, op2, "49 81 f0 00 00 00 00");
        testOp2(m64, .CMP, op1, op2, "49 81 f8 00 00 00 00");
    }

    {
        const op1 = Operand.registerRm(.R8B);
        const op2 = Operand.immediate8(0x00);
        testOp2(m64, .ADD, op1, op2, "41 80 c0 00");
        testOp2(m64, .ADC, op1, op2, "41 80 d0 00");
        testOp2(m64, .AND, op1, op2, "41 80 e0 00");
        testOp2(m64, .OR,  op1, op2, "41 80 c8 00");
        testOp2(m64, .SBB, op1, op2, "41 80 d8 00");
        testOp2(m64, .SUB, op1, op2, "41 80 e8 00");
        testOp2(m64, .XOR, op1, op2, "41 80 f0 00");
        testOp2(m64, .CMP, op1, op2, "41 80 f8 00");
    }

    {
        const op1 = Operand.registerRm(.AL);
        const op2 = Operand.register(.AL);
        testOp2(m64, .ADD, op1, op2, "00 c0");
        testOp2(m64, .ADC, op1, op2, "10 c0");
        testOp2(m64, .AND, op1, op2, "20 c0");
        testOp2(m64, .OR,  op1, op2, "08 c0");
        testOp2(m64, .SBB, op1, op2, "18 c0");
        testOp2(m64, .SUB, op1, op2, "28 c0");
        testOp2(m64, .XOR, op1, op2, "30 c0");
        testOp2(m64, .CMP, op1, op2, "38 c0");
    }

    {
        const op1 = Operand.registerRm(.AX);
        const op2 = Operand.register(.AX);
        testOp2(m64, .ADD, op1, op2, "66 01 c0");
        testOp2(m64, .ADC, op1, op2, "66 11 c0");
        testOp2(m64, .AND, op1, op2, "66 21 c0");
        testOp2(m64, .OR,  op1, op2, "66 09 c0");
        testOp2(m64, .SBB, op1, op2, "66 19 c0");
        testOp2(m64, .SUB, op1, op2, "66 29 c0");
        testOp2(m64, .XOR, op1, op2, "66 31 c0");
        testOp2(m64, .CMP, op1, op2, "66 39 c0");
    }

    {
        const op1 = Operand.registerRm(.EAX);
        const op2 = Operand.register(.EAX);
        testOp2(m64, .ADD, op1, op2, "01 c0");
        testOp2(m64, .ADC, op1, op2, "11 c0");
        testOp2(m64, .AND, op1, op2, "21 c0");
        testOp2(m64, .OR,  op1, op2, "09 c0");
        testOp2(m64, .SBB, op1, op2, "19 c0");
        testOp2(m64, .SUB, op1, op2, "29 c0");
        testOp2(m64, .XOR, op1, op2, "31 c0");
        testOp2(m64, .CMP, op1, op2, "39 c0");
    }

    {
        const op1 = Operand.registerRm(.RAX);
        const op2 = Operand.register(.RAX);
        testOp2(m64, .ADD, op1, op2, "48 01 c0");
        testOp2(m64, .ADC, op1, op2, "48 11 c0");
        testOp2(m64, .AND, op1, op2, "48 21 c0");
        testOp2(m64, .OR,  op1, op2, "48 09 c0");
        testOp2(m64, .SBB, op1, op2, "48 19 c0");
        testOp2(m64, .SUB, op1, op2, "48 29 c0");
        testOp2(m64, .XOR, op1, op2, "48 31 c0");
        testOp2(m64, .CMP, op1, op2, "48 39 c0");
    }

    {
        const op1 = Operand.register(.AL);
        const op2 = Operand.registerRm(.AL);
        testOp2(m64, .ADD, op1, op2, "02 c0");
        testOp2(m64, .ADC, op1, op2, "12 c0");
        testOp2(m64, .AND, op1, op2, "22 c0");
        testOp2(m64, .OR,  op1, op2, "0A c0");
        testOp2(m64, .SBB, op1, op2, "1A c0");
        testOp2(m64, .SUB, op1, op2, "2A c0");
        testOp2(m64, .XOR, op1, op2, "32 c0");
        testOp2(m64, .CMP, op1, op2, "3A c0");
    }

    {
        const op1 = Operand.register(.AX);
        const op2 = Operand.registerRm(.AX);
        testOp2(m64, .ADD, op1, op2, "66 03 c0");
        testOp2(m64, .ADC, op1, op2, "66 13 c0");
        testOp2(m64, .AND, op1, op2, "66 23 c0");
        testOp2(m64, .OR,  op1, op2, "66 0B c0");
        testOp2(m64, .SBB, op1, op2, "66 1B c0");
        testOp2(m64, .SUB, op1, op2, "66 2B c0");
        testOp2(m64, .XOR, op1, op2, "66 33 c0");
        testOp2(m64, .CMP, op1, op2, "66 3B c0");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.registerRm(.EAX);
        testOp2(m64, .ADD, op1, op2, "03 c0");
        testOp2(m64, .ADC, op1, op2, "13 c0");
        testOp2(m64, .AND, op1, op2, "23 c0");
        testOp2(m64, .OR,  op1, op2, "0B c0");
        testOp2(m64, .SBB, op1, op2, "1B c0");
        testOp2(m64, .SUB, op1, op2, "2B c0");
        testOp2(m64, .XOR, op1, op2, "33 c0");
        testOp2(m64, .CMP, op1, op2, "3B c0");
    }

    {
        const op1 = Operand.register(.RAX);
        const op2 = Operand.registerRm(.RAX);
        testOp2(m64, .ADD, op1, op2, "48 03 c0");
        testOp2(m64, .ADC, op1, op2, "48 13 c0");
        testOp2(m64, .AND, op1, op2, "48 23 c0");
        testOp2(m64, .OR,  op1, op2, "48 0B c0");
        testOp2(m64, .SBB, op1, op2, "48 1B c0");
        testOp2(m64, .SUB, op1, op2, "48 2B c0");
        testOp2(m64, .XOR, op1, op2, "48 33 c0");
        testOp2(m64, .CMP, op1, op2, "48 3B c0");
    }

}
