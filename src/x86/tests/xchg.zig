const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/xchg

test "xchg x64" {
    const x64 = Machine.init(.x64);

    debugPrint(false);

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.register(.EAX);
        testOp2(x64, .XCHG, op1, op2, "90");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.register(.ECX);
        testOp2(x64, .XCHG, op1, op2, "91");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.register(.R15D);
        testOp2(x64, .XCHG, op1, op2, "41 97");
    }

    {
        const op1 = Operand.register(.R15W);
        const op2 = Operand.register(.AX);
        testOp2(x64, .XCHG, op1, op2, "66 41 97");
    }

    {
        const op1 = Operand.register(.R15);
        const op2 = Operand.register(.RAX);
        testOp2(x64, .XCHG, op1, op2, "49 97");
    }

    {
        const op1 = Operand.registerRm(.R15);
        const op2 = Operand.register(.R14);
        testOp2(x64, .XCHG, op1, op2, "4d 87 f7");
    }

    {
        const op1 = Operand.register(.R15);
        const op2 = Operand.registerRm(.R14);
        testOp2(x64, .XCHG, op1, op2, "4d 87 fe");
    }

    {
        const op1 = Operand.register(.R15);
        const op2 = Operand.register(.AX);
        testOp2Error(x64, .XCHG, op1, op2, AsmError.InvalidOperandCombination);
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.register(.R15W);
        testOp2Error(x64, .XCHG, op1, op2, AsmError.InvalidOperandCombination);
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.memoryRm(.DefaultSeg, .DWORD, .RAX, 0x11);
        testOp2(x64, .XCHG, op1, op2, "87 40 11");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .DWORD, .RAX, 0x11);
        const op2 = Operand.register(.EAX);
        testOp2(x64, .XCHG, op1, op2, "87 40 11");
    }

    {
        const op1 = Operand.register(.EAX);
        const op2 = Operand.registerRm(.EAX);
        testOp2(x64, .XCHG, op1, op2, "87 c0");
    }

    {
        const op1 = Operand.register(.R15);
        const op2 = Operand.registerRm(.R14);
        testOp2(x64, .XCHG, op1, op2, "4d 87 fe");
    }

    {
        const op1 = Operand.register(.R15B);
        const op2 = Operand.registerRm(.SIL);
        testOp2(x64, .XCHG, op1, op2, "44 86 fe");
    }

    {
        const op1 = Operand.registerRm(.R15B);
        const op2 = Operand.register(.SIL);
        testOp2(x64, .XCHG, op1, op2, "41 86 f7");
    }
}
