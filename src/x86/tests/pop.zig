const std = @import("std");

usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/pop

const reg = Operand.register;
const regRm = Operand.registerRm;
const memSib = Operand.memorySibDef;

test "pop" {
    const m16 = Machine.init(.x86_16);
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        testOp1(m32, .POP, reg(.R15), AsmError.InvalidOperand);
        testOp1(m64, .POP, reg(.R15), "41 5F");
    }

    {
        testOp1(m16, .POP, reg(.FS), "0F A1");
        testOp1(m32, .POP, reg(.FS), "0F A1");
        testOp1(m64, .POP, reg(.FS), "0F A1");
        //
        testOp1(m16, .POPW, reg(.FS), "0F A1");
        testOp1(m32, .POPW, reg(.FS), "66 0F A1");
        testOp1(m64, .POPW, reg(.FS), "66 0F A1");
        //
        testOp1(m16, .POPD, reg(.FS), "66 0F A1");
        testOp1(m32, .POPD, reg(.FS), "0F A1");
        testOp1(m64, .POPD, reg(.FS), AsmError.InvalidOperand);
        //
        testOp1(m16, .POPQ, reg(.FS), AsmError.InvalidOperand);
        testOp1(m32, .POPQ, reg(.FS), AsmError.InvalidOperand);
        testOp1(m64, .POPQ, reg(.FS), "0F A1");
    }

    {
        testOp1(m16, .POP, reg(.DS), "1F");
        testOp1(m32, .POP, reg(.DS), "1F");
        testOp1(m64, .POP, reg(.DS), AsmError.InvalidOperand);
        //
        testOp1(m16, .POPW, reg(.DS), "1F");
        testOp1(m32, .POPW, reg(.DS), "66 1F");
        testOp1(m64, .POPW, reg(.DS), AsmError.InvalidOperand);
        //
        testOp1(m16, .POPD, reg(.DS), "66 1F");
        testOp1(m32, .POPD, reg(.DS), "1F");
        testOp1(m64, .POPD, reg(.DS), AsmError.InvalidOperand);
        //
        testOp1(m16, .POPQ, reg(.DS), AsmError.InvalidOperand);
        testOp1(m32, .POPQ, reg(.DS), AsmError.InvalidOperand);
        testOp1(m64, .POPQ, reg(.DS), AsmError.InvalidOperand);
    }

    {
        testOp1(m16, .POP, reg(.AX), "58");
        testOp1(m32, .POP, reg(.AX), "66 58");
        testOp1(m64, .POP, reg(.AX), "66 58");
        //
        testOp1(m16, .POP, reg(.EAX), "66 58");
        testOp1(m32, .POP, reg(.EAX), "58");
        testOp1(m64, .POP, reg(.EAX), AsmError.InvalidOperand);
        //
        testOp1(m16, .POP, reg(.RAX), AsmError.InvalidOperand);
        testOp1(m32, .POP, reg(.RAX), AsmError.InvalidOperand);
        testOp1(m64, .POP, reg(.RAX), "58");
        //
        testOp1(m16, .POP, regRm(.RAX), AsmError.InvalidOperand);
        testOp1(m32, .POP, regRm(.RAX), AsmError.InvalidOperand);
        testOp1(m64, .POP, regRm(.RAX), "8f c0");
        //
        testOp1(m16, .POP, regRm(.R8), AsmError.InvalidOperand);
        testOp1(m32, .POP, regRm(.R8), AsmError.InvalidOperand);
        testOp1(m64, .POP, regRm(.R8), "41 8f c0");
    }

    {
        testOp1(m16, .POP, memSib(.WORD, 1, .EAX, .EAX, 0), "67 8F 04 00");
        testOp1(m32, .POP, memSib(.WORD, 1, .EAX, .EAX, 0), "66 8F 04 00");
        testOp1(m64, .POP, memSib(.WORD, 1, .EAX, .EAX, 0), "66 67 8F 04 00");
        //
        testOp1(m16, .POP, memSib(.DWORD, 1, .EAX, .EAX, 0), "66 67 8F 04 00");
        testOp1(m32, .POP, memSib(.DWORD, 1, .EAX, .EAX, 0), "8F 04 00");
        testOp1(m64, .POP, memSib(.DWORD, 1, .EAX, .EAX, 0), AsmError.InvalidOperand);
        //
        testOp1(m16, .POP, memSib(.QWORD, 1, .RAX, .RAX, 0), AsmError.InvalidOperand);
        testOp1(m32, .POP, memSib(.QWORD, 1, .RAX, .RAX, 0), AsmError.InvalidOperand);
        testOp1(m64, .POP, memSib(.QWORD, 1, .RAX, .RAX, 0), "8F 04 00");
    }

}
