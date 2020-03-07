const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/xchg

const reg = Operand.register;
const regRm = Operand.registerRm;
const memRm = Operand.memoryRmDef;
const memRmSeg = Operand.memoryRm;

test "xchg" {
    const m16 = Machine.init(.x86_16);
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        // This is a special edge case on x86-64. Cant use encoding 90 for
        // XCHG EAX, EAX
        testOp2(m64, .XCHG, reg(.AX), reg(.AX), "66 90");
        testOp2(m64, .XCHG, reg(.EAX), reg(.EAX), "87 c0");
        testOp2(m64, .XCHG, reg(.RAX), reg(.RAX), "48 90");

        testOp2(m64, .XCHG, reg(.AX), regRm(.AX), "66 87 c0");
        testOp2(m64, .XCHG, reg(.EAX), regRm(.EAX), "87 c0");
        testOp2(m64, .XCHG, reg(.RAX), regRm(.RAX), "48 87 c0");

        // other register combinations still work same way on x86-64
        testOp2(m64, .XCHG, reg(.AX), reg(.CX), "66 91");
        testOp2(m64, .XCHG, reg(.EAX), reg(.ECX), "91");
        testOp2(m64, .XCHG, reg(.RAX), reg(.RCX), "48 91");

        testOp2(m64, .XCHG, reg(.AX), reg(.DI), "66 97");
        testOp2(m64, .XCHG, reg(.EAX), reg(.EDI), "97");
        testOp2(m64, .XCHG, reg(.RAX), reg(.RDI), "48 97");

        testOp2(m64, .XCHG, reg(.AX), reg(.SI), "66 96");
        testOp2(m64, .XCHG, reg(.EAX), reg(.ESI), "96");
        testOp2(m64, .XCHG, reg(.RAX), reg(.RSI), "48 96");

        // on 16/32 bit can use encoding 90 for XCHG EAX, EAX
        testOp2(m32, .XCHG, reg(.AX), reg(.AX), "66 90");
        testOp2(m32, .XCHG, reg(.EAX), reg(.EAX), "90");
        testOp2(m32, .XCHG, reg(.RAX), reg(.RAX), AsmError.InvalidOperand);

        testOp2(m16, .XCHG, reg(.AX), reg(.AX), "90");
        testOp2(m16, .XCHG, reg(.EAX), reg(.EAX), "66 90");
        testOp2(m16, .XCHG, reg(.RAX), reg(.RAX), AsmError.InvalidOperand);
    }

    {
        testOp2(m64, .XCHG, reg(.EAX), reg(.R15D), "41 97");
        testOp2(m64, .XCHG, reg(.R15W), reg(.AX), "66 41 97");
        testOp2(m64, .XCHG, reg(.R15), reg(.RAX), "49 97");

        testOp2(m64, .XCHG, reg(.R15), regRm(.R14), "4d 87 fe");
        testOp2(m64, .XCHG, regRm(.R15), reg(.R14), "4d 87 f7");
        testOp2(m64, .XCHG, reg(.R15), regRm(.R14), "4d 87 fe");
        testOp2(m64, .XCHG, reg(.R15B), regRm(.SIL), "44 86 fe");
        testOp2(m64, .XCHG, regRm(.R15B), reg(.SIL), "41 86 f7");

        testOp2(m64, .XCHG, reg(.R15), reg(.AX), AsmError.InvalidOperand);
        testOp2(m64, .XCHG, reg(.EAX), reg(.R15W), AsmError.InvalidOperand);
    }

    {
        testOp2(m64, .XCHG, reg(.EAX), memRm(.DWORD, .RAX, 0x11), "87 40 11");
        testOp2(m64, .XCHG, memRm(.DWORD, .RAX, 0x11), reg(.EAX), "87 40 11");
    }

}
