const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

const memRm = Operand.memoryRmDef;
const memRel = Operand.relMemoryDef;

test "nop" {
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        // nop
        testOp0(m64, .NOP, "90");
        // nop WORD [RAX]
        // nop DWORD [RAX]
        // nop QWORD [RAX]
        testOp1(m64, .NOP, memRm(.WORD, .RAX, 0), "66 0f 1f 00");
        testOp1(m64, .NOP, memRm(.DWORD, .RAX, 0), "0f 1f 00");
        testOp1(m64, .NOP, memRm(.QWORD, .RAX, 0), "48 0f 1f 00");
        // nop WORD [EAX]
        // nop DWORD [EAX]
        // nop QWORD [EAX]
        testOp1(m64, .NOP, memRm(.WORD, .EAX, 0), "66 67 0f 1f 00");
        testOp1(m64, .NOP, memRm(.DWORD, .EAX, 0), "67 0f 1f 00");
        testOp1(m64, .NOP, memRm(.QWORD, .EAX, 0), "67 48 0f 1f 00");
    }

    {
        testOp1(m64, .NOP, memRel(.WORD, .RIP, 0), "66 0f 1f 05 00 00 00 00");
        testOp1(m64, .NOP, memRel(.DWORD, .RIP, 0), "0f 1f 05 00 00 00 00");
        testOp1(m64, .NOP, memRel(.QWORD, .RIP, 0), "48 0f 1f 05 00 00 00 00");
        //
        testOp1(m64, .NOP, memRel(.WORD, .EIP, 0), "66 67 0f 1f 05 00 00 00 00");
        testOp1(m64, .NOP, memRel(.DWORD, .EIP, 0), "67 0f 1f 05 00 00 00 00");
        testOp1(m64, .NOP, memRel(.QWORD, .EIP, 0), "67 48 0f 1f 05 00 00 00 00");
    }

}
