const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

// QuickRef: https://www.felixcloutier.com/x86/nop

test "nop" {
    const x64 = Machine.init(.x64);

    debugPrint(false);

    // nop
    {
        testOp0(x64, .NOP, "90");
    }

    // nop WORD [RAX]
    {
        const op1 = Operand.memoryRm(.DefaultSeg, .WORD, .RAX, 0);
        testOp1(x64, .NOP, op1, "66 0f 1f 00");
    }

    // nop DWORD [RAX]
    {
        const op1 = Operand.memoryRm(.DefaultSeg, .DWORD, .RAX, 0);
        testOp1(x64, .NOP, op1, "0f 1f 00");
    }

    // nop QWORD [RAX]
    {
        const op1 = Operand.memoryRm(.DefaultSeg, .QWORD, .RAX, 0);
        testOp1(x64, .NOP, op1, "48 0f 1f 00");
    }

    // nop WORD [EAX]
    {
        const op1 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
        testOp1(x64, .NOP, op1, "66 67 0f 1f 00");
    }

    // nop DWORD [EAX]
    {
        const op1 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
        testOp1(x64, .NOP, op1, "67 0f 1f 00");
    }

    // nop QWORD [EAX]
    {
        const op1 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
        testOp1(x64, .NOP, op1, "67 48 0f 1f 00");
    }

    // nop WORD [RIP]
    {
        const op1 = Operand.relMemory(.DefaultSeg, .WORD, .RIP, 0);
        testOp1(x64, .NOP, op1, "66 0f 1f 05 00 00 00 00");
    }

    // nop DWORD [RIP]
    {
        const op1 = Operand.relMemory(.DefaultSeg, .DWORD, .RIP, 0);
        testOp1(x64, .NOP, op1, "0f 1f 05 00 00 00 00");
    }

    // nop QWORD [RIP]
    {
        const op1 = Operand.relMemory(.DefaultSeg, .QWORD, .RIP, 0);
        testOp1(x64, .NOP, op1, "48 0f 1f 05 00 00 00 00");
    }

    // nop WORD [EIP]
    {
        const op1 = Operand.relMemory(.DefaultSeg, .WORD, .EIP, 0);
        testOp1(x64, .NOP, op1, "66 67 0f 1f 05 00 00 00 00");
    }

    // nop DWORD [EIP]
    {
        const op1 = Operand.relMemory(.DefaultSeg, .DWORD, .EIP, 0);
        testOp1(x64, .NOP, op1, "67 0f 1f 05 00 00 00 00");
    }

    // nop QWORD [EIP]
    {
        const op1 = Operand.relMemory(.DefaultSeg, .QWORD, .EIP, 0);
        testOp1(x64, .NOP, op1, "67 48 0f 1f 05 00 00 00 00");
    }

}
