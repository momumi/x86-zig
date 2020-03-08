const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/mov

const reg = Operand.register;
const regRm = Operand.registerRm;

const mem = Operand.memoryDef;
const memRm = Operand.memoryRmDef;
const memRmSeg = Operand.memoryRm;
const memRm8 = Operand.memoryRm8;
const memSib = Operand.memorySibDef;
const memSib8 = Operand.memorySib8;

const imm = Operand.immediate;
const imm8 = Operand.immediate8;
const imm16 = Operand.immediate16;
const imm32 = Operand.immediate32;
const imm64 = Operand.immediate64;
const immSigned = Operand.immediateSigned;

const moffset8 = Operand.moffset8;
const moffset16 = Operand.moffset16;
const moffset32 = Operand.moffset32;
const moffset64 = Operand.moffset64;

test "mov x64 register" {
    const m16 = Machine.init(.x86_16);
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    const rm8 = Operand.memoryRm(.DefaultSeg, .BYTE, .EAX, 0);
    const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);

    const rm_mem8 = Operand.memoryRm(.DefaultSeg, .BYTE, .EAX, 0);
    const rm_mem16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const rm_mem32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm_mem64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);

    const moffs8_addr16  = moffset16(.DefaultSeg, .BYTE, 0);
    const moffs16_addr16 = moffset16(.DefaultSeg, .WORD, 0);
    const moffs32_addr16 = moffset16(.DefaultSeg, .DWORD, 0);
    const moffs64_addr16 = moffset16(.DefaultSeg, .QWORD, 0);

    const moffs8_addr32  = moffset32(.DefaultSeg, .BYTE, 0);
    const moffs16_addr32 = moffset32(.DefaultSeg, .WORD, 0);
    const moffs32_addr32 = moffset32(.DefaultSeg, .DWORD, 0);
    const moffs64_addr32 = moffset32(.DefaultSeg, .QWORD, 0);

    const moffs8_addr64  = moffset64(.DefaultSeg, .BYTE, 0);
    const moffs16_addr64 = moffset64(.DefaultSeg, .WORD, 0);
    const moffs32_addr64 = moffset64(.DefaultSeg, .DWORD, 0);
    const moffs64_addr64 = moffset64(.DefaultSeg, .QWORD, 0);

    debugPrint(false);

    {
        testOp2(m64, .MOV, reg(.AL), imm8(0), "B0 00");
        testOp2(m64, .MOV, reg(.CL), imm8(0), "B1 00");
        testOp2(m64, .MOV, reg(.DL), imm8(0), "B2 00");
        testOp2(m64, .MOV, reg(.BL), imm8(0), "B3 00");
        testOp2(m64, .MOV, reg(.AH), imm8(0), "B4 00");
        testOp2(m64, .MOV, reg(.CH), imm8(0), "B5 00");
        testOp2(m64, .MOV, reg(.DH), imm8(0), "B6 00");
        testOp2(m64, .MOV, reg(.BH), imm8(0), "B7 00");
        testOp2(m64, .MOV, reg(.SPL), imm8(0), "40 B4 00");
        testOp2(m64, .MOV, reg(.BPL), imm8(0), "40 B5 00");
        testOp2(m64, .MOV, reg(.SIL), imm8(0), "40 B6 00");
        testOp2(m64, .MOV, reg(.DIL), imm8(0), "40 B7 00");

        testOp2(m32, .MOV, reg(.SPL), imm8(0), AsmError.InvalidMode);
        testOp2(m32, .MOV, reg(.BPL), imm8(0), AsmError.InvalidMode);
        testOp2(m32, .MOV, reg(.SIL), imm8(0), AsmError.InvalidMode);
        testOp2(m32, .MOV, reg(.DIL), imm8(0), AsmError.InvalidMode);

        testOp2(m64, .MOV, reg(.MM0), imm8(0), AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.XMM0), imm8(0), AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.YMM0), imm8(0), AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.ZMM0), imm8(0), AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.CR0), imm8(0), AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.DR0), imm8(0), AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.DR0), imm8(0), AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.SS), imm8(0), AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.SS), imm8(0), AsmError.InvalidOperand);
    }

    {
        testOp2(m64, .MOV, reg(.SPL), imm8(0), "40 B4 00");
        testOp2(m64, .MOV, reg(.AX), imm16(0x1100), "66 B8 00 11");
        testOp2(m64, .MOV, reg(.EAX), imm32(0x33221100), "B8 00 11 22 33");
        testOp2(m64, .MOV, reg(.RAX), imm64(0x7766554433221100), "48 B8 00 11 22 33 44 55 66 77");
        //
        testOp2(m64, .MOV, reg(.RAX), imm(0), "B8 00 00 00 00");
        testOp2(m64, .MOV, reg(.RAX), immSigned(0), "B8 00 00 00 00");
        testOp2(m64, .MOV, reg(.RAX), imm(0x80000000), "B8 00 00 00 80");
        testOp2(m64, .MOV, reg(.RAX), immSigned(-1), "48 B8 FFFF FFFF FFFF FFFF");
        testOp2(m64, .MOV, reg(.RAX), immSigned(-0x8000), "48 B8 00 80 FFFF FFFF FFFF");
        //
        testOp2(m64, .MOV, reg(.R9), immSigned(0x7766554433221100), "49 B9 00 11 22 33 44 55 66 77");
    }

    {
        testOp2(m64, .MOV, reg(.AH), regRm(.SIL), AsmError.InvalidRegisterCombination);
        testOp2(m64, .MOV, reg(.MM0),     reg(.RAX),     AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.YMM28),   reg(.CR9),     AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.ST0),     reg(.ST1),     AsmError.InvalidOperand);
        testOp2(m64, .MOV, regRm(.ST3),   regRm(.ST7),   AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.RAX),     reg(.ST0),     AsmError.InvalidOperand);
        testOp2(m64, .MOV, regRm(.XMM9),  regRm(.YMM28), AsmError.InvalidOperand);
        testOp2(m64, .MOV, regRm(.ZMM31), reg(.SS),      AsmError.InvalidOperand);
        testOp2(m64, .MOV, regRm(.CR0),   regRm(.DR0),   AsmError.InvalidOperand);
    }

    {
        testOp2(m64, .MOV, memSib(.BYTE, 1, .RAX, .RAX, 0), imm8(0), "C6 04 00 00");
        testOp2(m64, .MOV, memSib(.WORD, 1, .EAX, .EAX, 0), imm16(0x1100), "66 67 C7 04 00 00 11");
        testOp2(m64, .MOV, memSib(.DWORD, 1, .RAX, .RAX, 0), imm32(0x33221100), "C7 04 00 00 11 22 33");
        testOp2(m64, .MOV, memSib(.QWORD, 1, .RAX, .RAX, 0), imm32(0x33221100), "48 C7 04 00 00 11 22 33");
        //
        testOp2(m64, .MOV, memSib(.QWORD, 1, .RAX, .RAX, -1), imm32(0x33221100), "48 C7 44 00 ff 00 11 22 33");
        testOp2(m64, .MOV, memSib(.QWORD, 1, .RAX, .RAX, -129), imm32(0x33221100), "48 C7 84 00 7f ff ff ff 00 11 22 33");
        testOp2(m64, .MOV, memSib(.QWORD, 1, .RAX, .RAX, 0x80), imm32(0x33221100), "48 C7 84 00 80 00 00 00 00 11 22 33");
    }

    {
        testOp2(m64, .MOV, memSib(.QWORD, 1, .RAX, .RAX, 0), reg(.RAX), "48 89 04 00");
        testOp2(m64, .MOV, mem(.QWORD, 1, null, .RBP, 0), reg(.RAX), "48 89 45 00");
        testOp2(m64, .MOV, mem(.QWORD, 1, null, .R13, 0), reg(.RAX), "49 89 45 00");
        testOp2(m64, .MOV, mem(.QWORD, 4, .RSP, null, 0), reg(.RAX), AsmError.InvalidMemoryAddressing);
        testOp2(m64, .MOV, mem(.QWORD, 4, .RBP, null, 0), reg(.RAX), "48 89 04 ad 00 00 00 00");
        testOp2(m64, .MOV, mem(.QWORD, 4, .R13, null, 0), reg(.RAX), "4a 89 04 ad 00 00 00 00");
        testOp2(m64, .MOV, memSib8(.DefaultSeg, .QWORD, 4, .RBP, null, 0), reg(.RAX), AsmError.InvalidMemoryAddressing);
        testOp2(m64, .MOV, memSib8(.DefaultSeg, .QWORD, 1, null, null, 0), reg(.RAX), AsmError.InvalidMemoryAddressing);
        testOp2(m64, .MOV, memRm8(.DefaultSeg, .QWORD, .RSP, 0), reg(.RAX), AsmError.InvalidMemoryAddressing);
    }

    {
        testOp2(m64, .MOV, mem(.QWORD, 1, null, .RSP, 0), reg(.RAX), "48 89 04 24");
        testOp2(m64, .MOV, memSib(.BYTE, 1, .RAX, .RAX, 0), reg(.AL), "88 04 00");
    }

    {
        testOp2(m64, .MOV, reg(.AL), reg(.AL), "88 c0");
        testOp2(m64, .MOV, reg(.AL), regRm(.AL), "8a c0");
        testOp2(m64, .MOV, regRm(.AL), reg(.AL), "88 c0");
        testOp2(m64, .MOV, regRm(.AL), reg(.R9B), "44 88 c8");
        testOp2(m64, .MOV, regRm(.R9B), reg(.AL), "41 88 c1");
        testOp2(m64, .MOV, regRm(.R9B), reg(.R15B), "45 88 f9");
        testOp2(m64, .MOV, regRm(.R9B), regRm(.R15B), AsmError.InvalidOperand);
    }

    {
        testOp2(m64, .MOV, reg(.AX), memRmSeg(.FS, .WORD, .EAX, 0), "64 66 67 8b 00");
        testOp2(m64, .MOV, memRmSeg(.GS, .BYTE, .EDI, 0x11), reg(.AH), "65 67 88 67 11");
        testOp2(m64, .MOV, reg(.FS), memRmSeg(.GS, .WORD, .EDI, 0x33221100), "65 66 67 8e a7 00 11 22 33");
        const op2 = Operand.memoryRm(.GS, .DWORD, .EDI, 0x33221100);
        testOp2(m64, .MOV, reg(.FS), op2, "65 67 8e a7 00 11 22 33");
    }

    {
        const op2 = Operand.memoryRm(.GS, .QWORD, .EDI, 0x33221100);
        testOp2(m64, .MOV, reg(.FS), op2, "65 67 48 8e a7 00 11 22 33");
    }


    {
        const op2 = Operand.memoryRm(.GS, .BYTE, .EDI, 0x33221100);
        testOp2(m64, .MOV, reg(.FS), op2, AsmError.InvalidOperand);
    }

    {
        testOp2(m64, .MOV, reg(.AL), moffset64(.DefaultSeg, .BYTE, 0x7766554433221100), "A0 00 11 22 33 44 55 66 77");
        testOp2(m64, .MOV, reg(.AX), moffset64(.DefaultSeg, .WORD, 0x7766554433221100), "66 A1 00 11 22 33 44 55 66 77");
        testOp2(m64, .MOV, reg(.EAX), moffset64(.DefaultSeg, .DWORD, 0x7766554433221100), "A1 00 11 22 33 44 55 66 77");
        testOp2(m64, .MOV, reg(.RAX), moffset64(.DefaultSeg, .QWORD, 0x7766554433221100), "48 A1 00 11 22 33 44 55 66 77");
        testOp2(m64, .MOV, moffset64(.DefaultSeg, .WORD, 0x7766554433221100), reg(.AX), "66 A3 00 11 22 33 44 55 66 77");
        testOp2(m64, .MOV, moffset64(.DefaultSeg, .DWORD, 0x7766554433221100), reg(.EAX), "A3 00 11 22 33 44 55 66 77");
        testOp2(m64, .MOV, moffset64(.DefaultSeg, .QWORD, 0x7766554433221100), reg(.RAX), "48 A3 00 11 22 33 44 55 66 77");
        testOp2(m64, .MOV, moffset64(.DefaultSeg, .QWORD, 0x7766554433221100), reg(.AL), AsmError.InvalidOperand);
    }

    {
        // MOV
        testOp2(m64, .MOV, reg(.AL), rm8, "678a00");
        testOp2(m64, .MOV, reg(.AX), rm16, "66678b00");
        testOp2(m64, .MOV, reg(.EAX), rm32, "678b00");
        testOp2(m64, .MOV, reg(.RAX), rm64, "67488b00");
        //
        testOp2(m64, .MOV, rm8,  reg(.AL), "678800");
        testOp2(m64, .MOV, rm16, reg(.AX), "66678900");
        testOp2(m64, .MOV, rm32, reg(.EAX), "678900");
        testOp2(m64, .MOV, rm64, reg(.RAX), "67488900");
        //
        testOp2(m64, .MOV, rm16, reg(.FS), "66678c20");
        testOp2(m64, .MOV, rm32, reg(.FS), "678c20");
        testOp2(m64, .MOV, rm64, reg(.FS), "67488c20");
        //
        testOp2(m64, .MOV, reg(.FS), rm16, "66678e20");
        testOp2(m64, .MOV, reg(.FS), rm32, "678e20");
        testOp2(m64, .MOV, reg(.FS), rm64, "67488e20");
    }

    {
        {
            testOp2(m16, .MOV, reg(.AL), moffs8_addr16, "a00000");
            testOp2(m16, .MOV, reg(.AX), moffs16_addr16, "a10000");
            testOp2(m16, .MOV, reg(.EAX), moffs32_addr16, "66a10000");
            testOp2(m16, .MOV, reg(.RAX), moffs64_addr16, AsmError.InvalidOperand);
            //
            testOp2(m16, .MOV, moffs8_addr16, reg(.AL), "a20000");
            testOp2(m16, .MOV, moffs16_addr16, reg(.AX), "a30000");
            testOp2(m16, .MOV, moffs32_addr16, reg(.EAX), "66a30000");
            testOp2(m16, .MOV, moffs64_addr16, reg(.RAX), AsmError.InvalidOperand);
            //
            testOp2(m16, .MOV, moffs8_addr32, reg(.AL), AsmError.InvalidOperand);
            testOp2(m16, .MOV, moffs8_addr64, reg(.AL), AsmError.InvalidOperand);
        }

        {
            testOp2(m32, .MOV, reg(.AL), moffs8_addr32, "a000000000");
            testOp2(m32, .MOV, reg(.AX), moffs16_addr32, "66a100000000");
            testOp2(m32, .MOV, reg(.EAX), moffs32_addr32, "a100000000");
            testOp2(m32, .MOV, reg(.RAX), moffs64_addr32, AsmError.InvalidOperand);
            //
            testOp2(m32, .MOV, moffs8_addr32, reg(.AL), "a200000000");
            testOp2(m32, .MOV, moffs16_addr32, reg(.AX), "66a300000000");
            testOp2(m32, .MOV, moffs32_addr32, reg(.EAX), "a300000000");
            testOp2(m32, .MOV, moffs64_addr32, reg(.RAX), AsmError.InvalidOperand);
            //
            testOp2(m32, .MOV, moffs8_addr16, reg(.AL), AsmError.InvalidOperand);
            testOp2(m32, .MOV, moffs8_addr64, reg(.AL), AsmError.InvalidOperand);
        }

        {
            testOp2(m64, .MOV, reg(.AL), moffs8_addr64, "a00000000000000000");
            testOp2(m64, .MOV, reg(.AX), moffs16_addr64, "66a10000000000000000");
            testOp2(m64, .MOV, reg(.EAX), moffs32_addr64, "a10000000000000000");
            testOp2(m64, .MOV, reg(.RAX), moffs64_addr64, "48a10000000000000000");
            //
            testOp2(m64, .MOV, moffs8_addr64, reg(.AL), "a20000000000000000");
            testOp2(m64, .MOV, moffs16_addr64, reg(.AX), "66a30000000000000000");
            testOp2(m64, .MOV, moffs32_addr64, reg(.EAX), "a30000000000000000");
            testOp2(m64, .MOV, moffs64_addr64, reg(.RAX), "48a30000000000000000");
            //
            testOp2(m64, .MOV, moffs8_addr16, reg(.AL), AsmError.InvalidOperand);
            testOp2(m64, .MOV, moffs8_addr32, reg(.AL), AsmError.InvalidOperand);
        }
    }

    {
        testOp2(m64, .MOV, reg(.AL), imm(0), "b000");
        testOp2(m64, .MOV, reg(.AX), imm(0x7FFF), "66b8ff7f");
        testOp2(m64, .MOV, reg(.EAX), imm(0x7FFFFFFF), "b8ffffff7f");
        testOp2(m64, .MOV, reg(.RAX), imm(0x7FFFFFFF), "b8ffffff7f");
        testOp2(m64, .MOV, reg(.RAX), imm(0x7FFFFFFFFFFFFFFF), "48b8ffffffffffffff7f");
        //
        testOp2(m64, .MOV, rm8, imm(0), "67c60000");
        testOp2(m64, .MOV, rm16, imm(0x7FFF), "6667c700ff7f");
        testOp2(m64, .MOV, rm32, imm(0x7FFFFFFF), "67c700ffffff7f");
        testOp2(m64, .MOV, rm64, imm(0x7FFFFFFF), "6748c700ffffff7f");
        // 386 MOV to/from Control Registers
        testOp2(m64, .MOV, reg(.EAX), reg(.CR0), AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.RAX), reg(.CR0), "0f20c0");
        //
        testOp2(m64, .MOV, reg(.CR0), reg(.EAX), AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.CR0), reg(.RAX), "0f22c0");
        // 386 MOV to/from Debug Registers
        testOp2(m64, .MOV, reg(.EAX), reg(.DR0), AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.RAX), reg(.DR0), "0f21c0");
        //
        testOp2(m64, .MOV, reg(.DR0), reg(.EAX), AsmError.InvalidOperand);
        testOp2(m64, .MOV, reg(.DR0), reg(.RAX), "0f23c0");
    }
}
