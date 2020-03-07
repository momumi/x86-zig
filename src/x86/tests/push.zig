const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/push

const imm = Operand.immediate;
const reg = Operand.register;
const regRm = Operand.registerRm;

const memRm = Operand.memoryRmDef;

test "push" {
    const m16 = Machine.init(.x86_16);
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        testOp1(m16, .PUSH, reg(.CS), "0E");
        testOp1(m32, .PUSH, reg(.CS), "0E");
        testOp1(m64, .PUSH, reg(.CS), AsmError.InvalidOperand);
        //
        testOp1(m16, .PUSH, reg(.SS), "16");
        testOp1(m32, .PUSH, reg(.SS), "16");
        testOp1(m64, .PUSH, reg(.SS), AsmError.InvalidOperand);
        //
        testOp1(m16, .PUSH, reg(.DS), "1E");
        testOp1(m32, .PUSH, reg(.DS), "1E");
        testOp1(m64, .PUSH, reg(.DS), AsmError.InvalidOperand);
        //
        testOp1(m16, .PUSH, reg(.ES), "06");
        testOp1(m32, .PUSH, reg(.ES), "06");
        testOp1(m64, .PUSH, reg(.ES), AsmError.InvalidOperand);
    }

    {
        testOp1(m16, .PUSH, reg(.FS), "0F A0");
        testOp1(m32, .PUSH, reg(.FS), "0F A0");
        testOp1(m64, .PUSH, reg(.FS), "0F A0");
        //
        testOp1(m16, .PUSHW, reg(.FS), "0F A0");
        testOp1(m32, .PUSHW, reg(.FS), "66 0F A0");
        testOp1(m64, .PUSHW, reg(.FS), "66 0F A0");
        //
        testOp1(m16, .PUSHD, reg(.FS), "66 0F A0");
        testOp1(m32, .PUSHD, reg(.FS), "0F A0");
        testOp1(m64, .PUSHD, reg(.FS), AsmError.InvalidOperand);
        //
        testOp1(m16, .PUSHQ, reg(.FS), AsmError.InvalidOperand);
        testOp1(m32, .PUSHQ, reg(.FS), AsmError.InvalidOperand);
        testOp1(m64, .PUSHQ, reg(.FS), "0F A0");
    }

    {
        testOp1(m16, .PUSH, reg(.GS), "0F A8");
        testOp1(m32, .PUSH, reg(.GS), "0F A8");
        testOp1(m64, .PUSH, reg(.GS), "0F A8");
        //
        testOp1(m16, .PUSHW, reg(.GS), "0F A8");
        testOp1(m32, .PUSHW, reg(.GS), "66 0F A8");
        testOp1(m64, .PUSHW, reg(.GS), "66 0F A8");
        //
        testOp1(m16, .PUSHD, reg(.GS), "66 0F A8");
        testOp1(m32, .PUSHD, reg(.GS), "0F A8");
        testOp1(m64, .PUSHD, reg(.GS), AsmError.InvalidOperand);
        //
        testOp1(m16, .PUSHQ, reg(.GS), AsmError.InvalidOperand);
        testOp1(m32, .PUSHQ, reg(.GS), AsmError.InvalidOperand);
        testOp1(m64, .PUSHQ, reg(.GS), "0F A8");
    }

    {
        testOp1(m16, .PUSH, reg(.AX), "50");
        testOp1(m32, .PUSH, reg(.AX), "66 50");
        testOp1(m64, .PUSH, reg(.AX), "66 50");
        //
        testOp1(m16, .PUSH, reg(.EAX), "66 50");
        testOp1(m32, .PUSH, reg(.EAX), "50");
        testOp1(m64, .PUSH, reg(.EAX), AsmError.InvalidOperand);
        //
        testOp1(m16, .PUSH, reg(.RAX), AsmError.InvalidOperand);
        testOp1(m32, .PUSH, reg(.RAX), AsmError.InvalidOperand);
        testOp1(m64, .PUSH, reg(.RAX), "50");
        //
        testOp1(m16, .PUSH, reg(.R15), AsmError.InvalidOperand);
        testOp1(m32, .PUSH, reg(.R15), AsmError.InvalidOperand);
        testOp1(m64, .PUSH, reg(.R15), "41 57");
    }

    {
        testOp1(m16, .PUSH, memRm(.WORD, .EAX, 0x11), "67 FF 70 11");
        testOp1(m32, .PUSH, memRm(.WORD, .EAX, 0x11), "66 FF 70 11");
        testOp1(m64, .PUSH, memRm(.WORD, .EAX, 0x11), "66 67 FF 70 11");
        //
        testOp1(m16, .PUSH, memRm(.DWORD, .EAX, 0x11), "66 67 FF 70 11");
        testOp1(m32, .PUSH, memRm(.DWORD, .EAX, 0x11), "FF 70 11");
        testOp1(m64, .PUSH, memRm(.DWORD, .EAX, 0x11), AsmError.InvalidOperand);
        //
        testOp1(m16, .PUSH, memRm(.QWORD, .EAX, 0x11), AsmError.InvalidOperand);
        testOp1(m32, .PUSH, memRm(.QWORD, .EAX, 0x11), AsmError.InvalidOperand);
        testOp1(m64, .PUSH, memRm(.QWORD, .EAX, 0x11), "67 FF 70 11");
        //
        testOp1(m16, .PUSH, memRm(.WORD, .RAX, 0x11), AsmError.InvalidOperand);
        testOp1(m32, .PUSH, memRm(.WORD, .RAX, 0x11), AsmError.InvalidOperand);
        testOp1(m64, .PUSH, memRm(.WORD, .RAX, 0x11), "66 FF 70 11");
        //
        testOp1(m16, .PUSH, memRm(.DWORD, .RAX, 0x11), AsmError.InvalidOperand);
        testOp1(m32, .PUSH, memRm(.DWORD, .RAX, 0x11), AsmError.InvalidOperand);
        testOp1(m64, .PUSH, memRm(.DWORD, .RAX, 0x11), AsmError.InvalidOperand);
        //
        testOp1(m16, .PUSH, memRm(.QWORD, .R15, 0x11), AsmError.InvalidOperand);
        testOp1(m32, .PUSH, memRm(.QWORD, .R15, 0x11), AsmError.InvalidOperand);
        testOp1(m64, .PUSH, memRm(.QWORD, .R15, 0x11), "41 FF 77 11");
    }

    {
        testOp1(m16, .PUSH, imm(0), "6A 00");
        testOp1(m32, .PUSH, imm(0), "6A 00");
        testOp1(m64, .PUSH, imm(0), "6A 00");
        //
        testOp1(m16, .PUSH, imm(0x1100), "68 00 11");
        testOp1(m32, .PUSH, imm(0x1100), "66 68 00 11");
        testOp1(m64, .PUSH, imm(0x1100), "66 68 00 11");
        //
        testOp1(m16, .PUSH, imm(0x33221100), "66 68 00 11 22 33");
        testOp1(m32, .PUSH, imm(0x33221100), "68 00 11 22 33");
        testOp1(m64, .PUSH, imm(0x33221100), "68 00 11 22 33");
    }

}
