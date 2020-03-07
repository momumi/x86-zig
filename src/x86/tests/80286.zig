const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

const reg = Operand.register;
const memRm = Operand.memoryRmDef;

test "80286" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        testOp0(m32, .CLTS, "0F 06");
    }

    {
        testOp1(m32, .LLDT, memRm(.WORD, .EAX, 0), "0F 00 10");
        testOp1(m32, .LMSW, memRm(.WORD, .EAX, 0), "0F 01 30");
        testOp1(m32, .LTR,  memRm(.WORD, .EAX, 0), "0F 00 18");
        testOp1(m32, .SLDT, memRm(.WORD, .EAX, 0), "0F 00 00");
        testOp1(m32, .SMSW, memRm(.WORD, .EAX, 0), "0F 01 20");
        testOp1(m32, .STR,  memRm(.WORD, .EAX, 0), "0F 00 08");
        testOp1(m32, .VERR, memRm(.WORD, .EAX, 0), "0F 00 20");
        testOp1(m32, .VERW, memRm(.WORD, .EAX, 0), "0F 00 28");
    }

    {
        testOp1(m32, .LLDT, reg(.AX), "0F 00 D0");
        testOp1(m32, .LMSW, reg(.AX), "0F 01 F0");
        testOp1(m32, .LTR,  reg(.AX), "0F 00 D8");
        testOp1(m32, .SLDT, reg(.AX), "66 0F 00 C0");
        testOp1(m32, .SMSW, reg(.AX), "66 0F 01 E0");
        testOp1(m32, .STR,  reg(.AX), "66 0F 00 C8");
        testOp1(m32, .VERR, reg(.AX), "0F 00 E0");
        testOp1(m32, .VERW, reg(.AX), "0F 00 E8");
    }

    {
        testOp1(m32, .LLDT, reg(.EAX), AsmError.InvalidOperand);
        testOp1(m32, .LMSW, reg(.EAX), AsmError.InvalidOperand);
        testOp1(m32, .LTR,  reg(.EAX), AsmError.InvalidOperand);
        testOp1(m32, .SLDT, reg(.EAX), "0F 00 C0");
        testOp1(m32, .SMSW, reg(.EAX), "0F 01 E0");
        testOp1(m32, .STR,  reg(.EAX), "0F 00 C8");
        testOp1(m32, .VERR, reg(.EAX), AsmError.InvalidOperand);
        testOp1(m32, .VERW, reg(.EAX), AsmError.InvalidOperand);
    }

    {
        testOp1(m64, .LLDT, reg(.RAX), AsmError.InvalidOperand);
        testOp1(m64, .LMSW, reg(.RAX), AsmError.InvalidOperand);
        testOp1(m64, .LTR,  reg(.RAX), AsmError.InvalidOperand);
        testOp1(m64, .SLDT, reg(.RAX), "48 0F 00 C0");
        testOp1(m64, .SMSW, reg(.RAX), "48 0F 01 E0");
        testOp1(m64, .STR,  reg(.RAX), "48 0F 00 C8");
        testOp1(m64, .VERR, reg(.RAX), AsmError.InvalidOperand);
        testOp1(m64, .VERW, reg(.RAX), AsmError.InvalidOperand);
    }

    {
        testOp1(m32, .LGDT, memRm(.Void, .EAX, 0), "0F 01 10");
        testOp1(m32, .LIDT, memRm(.Void, .EAX, 0), "0F 01 18");
        testOp1(m32, .SGDT, memRm(.Void, .EAX, 0), "0F 01 00");
        testOp1(m32, .SIDT, memRm(.Void, .EAX, 0), "0F 01 08");
        testOp1(m64, .LGDT, memRm(.Void, .EAX, 0), "67 0F 01 10");
        testOp1(m64, .LIDT, memRm(.Void, .EAX, 0), "67 0F 01 18");
        testOp1(m64, .SGDT, memRm(.Void, .EAX, 0), "67 0F 01 00");
        testOp1(m64, .SIDT, memRm(.Void, .EAX, 0), "67 0F 01 08");
    }

    {
        testOp2(m32, .ARPL, memRm(.WORD, .EAX, 0), reg(.AX), "63 00");
        testOp2(m64, .ARPL, memRm(.WORD, .EAX, 0), reg(.AX), AsmError.InvalidOperand);
    }

    {
        testOp2(m32, .LAR,  reg(.AX), memRm(.WORD, .EAX, 0), "66 0F 02 00");
        testOp2(m32, .LSL,  reg(.AX), memRm(.WORD, .EAX, 0), "66 0F 03 00");
        testOp2(m64, .LAR,  reg(.AX), memRm(.WORD, .EAX, 0), "66 67 0F 02 00");
        testOp2(m64, .LSL,  reg(.AX), memRm(.WORD, .EAX, 0), "66 67 0F 03 00");
    }

    {
        testOp2(m32, .LAR,  reg(.EAX), memRm(.DWORD, .EAX, 0), "0F 02 00");
        testOp2(m32, .LSL,  reg(.EAX), memRm(.DWORD, .EAX, 0), "0F 03 00");
        testOp2(m64, .LAR,  reg(.EAX), memRm(.DWORD, .EAX, 0), "67 0F 02 00");
        testOp2(m64, .LSL,  reg(.EAX), memRm(.DWORD, .EAX, 0), "67 0F 03 00");
    }

}
