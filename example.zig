const warn = @import("std").debug.warn;

const x86 = @import("src/x86.zig");

pub fn main() anyerror!void {
    const machine64 = x86.Machine.init(.x64);

    {
        const op1 = x86.Operand.register(.RAX);
        const op2 = x86.Operand.register(.R15);
        const instr = try machine64.build2(.MOV, op1, op2);
        warn("{x}\t\t\tMOV\t{}, {}\n", .{instr.asSlice(), op1, op2});
    }

    {
        const op1 = x86.Operand.register(.RAX);
        const op2 = x86.Operand.memoryRm(.GS, .QWORD, .RAX, 0x33221100);
        const instr = try machine64.build2_pre(.Lock, .MOV, op1, op2);
        warn("{x}\tLOCK MOV\t{}, {}\n", .{instr.asSlice(), op1, op2});
    }

    {
        const op1 = x86.Operand.memorySib(.FS, .DWORD, 8, .ECX, .EBX, 0x33221100);
        const op2 = x86.Operand.register(.EAX);
        const instr1 = try machine64.build2_pre(.Lock, .MOV, op1, op2);
        warn("{x}\tLOCK MOV\t{}, {}\n", .{instr1.asSlice(), op1, op2});

        // Same as above except with default segment
        const op3 = x86.Operand.memorySibDef(.DWORD, 8, .ECX, .EBX, 0x33221100);
        const op4 = x86.Operand.register(.EAX);
        const instr2 = try machine64.build2_pre(.Lock, .MOV, op3, op4);
        warn("{x}\tLOCK MOV\t{}, {}\n", .{instr2.asSlice(), op3, op4});
    }

    {
        // Operand.memory will use a shorter encoding when possible whereas
        // Operand.memorySib will always use an encoding with a SIB byte.
        const op1 = x86.Operand.memoryDef(.DWORD, 0, null, .RBX, 0);
        const op2 = x86.Operand.register(.EAX);
        const instr1 = try machine64.build2(.MOV, op1, op2);
        warn("{x}\t\t\tMOV\t{}, {}\n", .{instr1.asSlice(), op1, op2});

        // NOTE: the scale must not be zero, since it always gets encoded in
        // the SIB byte even when it's not used.
        const op3 = x86.Operand.memorySibDef(.DWORD, 1, null, .RBX, 0);
        const op4 = x86.Operand.register(.EAX);
        const instr2 = try machine64.build2(.MOV, op3, op4);
        warn("{x}\t\t\tMOV\t{}, {}\n", .{instr2.asSlice(), op3, op4});
    }

    {
        const op1 = x86.Operand.register(.SIL);
        const op2 = x86.Operand.memoryRmDef(.BYTE, .R14, 0);
        const instr = try machine64.build2(.MOV, op1, op2);
        warn("{x}\t\t\tMOV\t{}, {}\n", .{instr.asSlice(), op1, op2});
    }

    {
        const op1 = x86.Operand.immediateSigned(-20);
        const instr = try machine64.build1(.JMP, op1);
        warn("{x}\t\t\tJMP\t{}\n", .{instr.asSlice(), op1});
    }
}
