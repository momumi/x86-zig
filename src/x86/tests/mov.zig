const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/mov

test "mov x64 register" {
    const x64 = Machine.init(.x64);

    debugPrint(false);

    {
        const op1 = Operand.register(.AL);
        const op2 = Operand.immediate8(0x00);
        testOp2(x64, .MOV, op1, op2, "B0 00");
    }

    {
        const op1 = Operand.register(.AH);
        const op2 = Operand.immediate8(0x00);
        testOp2(x64, .MOV, op1, op2, "B4 00");
    }

    {
        const op1 = Operand.register(.SPL);
        const op2 = Operand.immediate8(0x00);
        testOp2(x64, .MOV, op1, op2, "40 B4 00");
    }

    {
        const op1 = Operand.register(.AX);
        const op2 = Operand.immediate16(0x1100);
        testOp2(x64, .MOV, op1, op2, "66 B8 00 11");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.immediate32(0x33221100);
        testOp2(x64, .MOV, op1, op2, "B8 00 11 22 33");
    }

    {
        const op1 = Operand.register(.RAX);
        const op2 = Operand.immediate64(0x7766554433221100);
        testOp2(x64, .MOV, op1, op2, "48 B8 00 11 22 33 44 55 66 77");
    }

    {
        const op1 = Operand.register(.R9);
        const op2 = Operand.immediate64(0x7766554433221100);
        testOp2(x64, .MOV, op1, op2, "49 B9 00 11 22 33 44 55 66 77");
    }
}

test "mov x64 RM" {
    const x64 = Machine.init(.x64);

    debugPrint(false);

    {
        const op1 = Operand.memorySib(.DefaultSeg, .BYTE, 1, .RAX, .RAX, 0x00);
        const op2 = Operand.immediate8(0x00);
        testOp2(x64, .MOV, op1, op2, "C6 04 00 00");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .WORD, 1, .EAX, .EAX, 0x00);
        const op2 = Operand.immediate16(0x1100);
        testOp2(x64, .MOV, op1, op2, "66 67 C7 04 00 00 11");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .DWORD, 1, .RAX, .RAX, 0x00);
        const op2 = Operand.immediate32(0x33221100);
        testOp2(x64, .MOV, op1, op2, "C7 04 00 00 11 22 33");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .QWORD, 1, .RAX, .RAX, 0x00);
        const op2 = Operand.immediate32(0x33221100);
        testOp2(x64, .MOV, op1, op2, "48 C7 04 00 00 11 22 33");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .QWORD, 1, .RAX, .RAX, 0x00);
        const op2 = Operand.register(.RAX);
        testOp2(x64, .MOV, op1, op2, "48 89 04 00");
    }

    {
        const op1 = Operand.memorySib(.DefaultSeg, .BYTE, 1, .RAX, .RAX, 0x00);
        const op2 = Operand.register(.AL);
        testOp2(x64, .MOV, op1, op2, "88 04 00");
    }

    {
        const op1 = Operand.register(.AL);
        const op2 = Operand.registerRm(.AL);
        testOp2(x64, .MOV, op1, op2, "8a c0");
    }

    {
        const op1 = Operand.registerRm(.AL);
        const op2 = Operand.register(.AL);
        testOp2(x64, .MOV, op1, op2, "88 c0");
    }

    {
        const op1 = Operand.registerRm(.AL);
        const op2 = Operand.register(.R9B);
        testOp2(x64, .MOV, op1, op2, "44 88 c8");
    }

    {
        const op1 = Operand.registerRm(.R9B);
        const op2 = Operand.register(.AL);
        testOp2(x64, .MOV, op1, op2, "41 88 c1");
    }

    {
        const op1 = Operand.registerRm(.R9B);
        const op2 = Operand.register(.R15B);
        testOp2(x64, .MOV, op1, op2, "45 88 f9");
    }

    {
        const op1 = Operand.register(.AX);
        const op2 = Operand.memoryRm(.FS, .WORD, .EAX, 0x00);
        testOp2(x64, .MOV, op1, op2, "64 66 67 8b 00");
    }

    {
        const op1 = Operand.memoryRm(.GS, .BYTE, .EDI, 0x11);
        const op2 = Operand.register(.AH);
        testOp2(x64, .MOV, op1, op2, "65 67 88 67 11");
    }

    {
        const op1 = Operand.registerSpecial(.FS);
        const op2 = Operand.memoryRm(.GS, .QWORD, .EDI, 0x33221100);
        testOp2(x64, .MOV, op1, op2, "65 67 48 8e a7 00 11 22 33");
    }

    {
        const op1 = Operand.registerSpecial(.FS);
        const op2 = Operand.memoryRm(.GS, .WORD, .EDI, 0x33221100);
        testOp2(x64, .MOV, op1, op2, "65 67 8e a7 00 11 22 33");
    }

    {
        const op1 = Operand.registerSpecial(.FS);
        const op2 = Operand.memoryRm(.GS, .DWORD, .EDI, 0x33221100);
        testOp2(x64, .MOV, op1, op2, "65 66 67 8e a7 00 11 22 33");
    }

    {
        const op1 = Operand.registerSpecial(.FS);
        const op2 = Operand.memoryRm(.GS, .BYTE, .EDI, 0x33221100);
        testOp2(x64, .MOV, op1, op2, AsmError.InvalidOperandCombination);
    }

    {
        const op1 = Operand.register(.AL);
        const op2 = Operand.moffset64(.DefaultSeg, .BYTE, 0x7766554433221100);
        testOp2(x64, .MOV, op1, op2, "A0 00 11 22 33 44 55 66 77");
    }

    {
        const op1 = Operand.register(.AX);
        const op2 = Operand.moffset64(.DefaultSeg, .WORD, 0x7766554433221100);
        testOp2(x64, .MOV, op1, op2, "66 A1 00 11 22 33 44 55 66 77");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.moffset64(.DefaultSeg, .DWORD, 0x7766554433221100);
        testOp2(x64, .MOV, op1, op2, "A1 00 11 22 33 44 55 66 77");
    }

    {
        const op1 = Operand.register(.RAX);
        const op2 = Operand.moffset64(.DefaultSeg, .QWORD, 0x7766554433221100);
        testOp2(x64, .MOV, op1, op2, "48 A1 00 11 22 33 44 55 66 77");
    }

    {
        const op1 = Operand.moffset64(.DefaultSeg, .QWORD, 0x7766554433221100);
        const op2 = Operand.register(.AL);
        testOp2(x64, .MOV, op1, op2, AsmError.InvalidOperandCombination);
    }

    {
        const op1 = Operand.moffset64(.DefaultSeg, .WORD, 0x7766554433221100);
        const op2 = Operand.register(.AX);
        testOp2(x64, .MOV, op1, op2, "66 A3 00 11 22 33 44 55 66 77");
    }

    {
        const op1 = Operand.moffset64(.DefaultSeg, .DWORD, 0x7766554433221100);
        const op2 = Operand.register(.EAX);
        testOp2(x64, .MOV, op1, op2, "A3 00 11 22 33 44 55 66 77");
    }

    {
        const op1 = Operand.moffset64(.DefaultSeg, .QWORD, 0x7766554433221100);
        const op2 = Operand.register(.RAX);
        testOp2(x64, .MOV, op1, op2, "48 A3 00 11 22 33 44 55 66 77");
    }
}
