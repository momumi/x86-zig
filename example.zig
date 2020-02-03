const warn = @import("std").debug.warn;

const x86 = @import("src/x86.zig");

pub fn main() anyerror!void {
    const machine64 = x86.Machine.init(.x64);

    {
        const op1 = x86.Operand.register(.RAX);
        const op2 = x86.Operand.register(.R15);
        const instr = try machine64.build(.MOV, &op1, &op2, null, null);
        warn("{x}\t\t\tMOV\t{}, {}\n", .{instr.asSlice(), op1, op2});
    }

    {
        const op1 = x86.Operand.register(.RAX);
        const op2 = x86.Operand.memoryRm(.GS, .QWORD, .RAX, 0x33221100);
        const instr = try machine64.build2(.MOV, op1, op2);
        warn("{x}\tMOV\t{}, {}\n", .{instr.asSlice(), op1, op2});
    }

    {
        const op1 = x86.Operand.memorySib(.FS, .DWORD, 8, .ECX, .EBX, 0x33221100);
        const op2 = x86.Operand.register(.EAX);
        const instr = try machine64.build2(.MOV, op1, op2);
        warn("{x}\tMOV\t{}, {}\n", .{instr.asSlice(), op1, op2});
    }


    {
        const op1 = x86.Operand.register(.AX);
        const op2 = x86.Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
        const instr = try machine64.build2(.MOV, op1, op2);
        warn("{x}\t\tMOV\t{}, {}\n", .{instr.asSlice(), op1, op2});
    }

    {
        const op1 = x86.Operand.register(.SIL);
        const op2 = x86.Operand.memoryRm(.DefaultSeg, .BYTE, .R14, 0);
        const instr = try machine64.build2(.MOV, op1, op2);
        warn("{x}\t\t\tMOV\t{}, {}\n", .{instr.asSlice(), op1, op2});
    }

    {
        const op1 = x86.Operand.immediateSigned(-20);
        const instr = try machine64.build1(.JMP, op1);
        warn("{x}\t\t\tJMP\t{}\n", .{instr.asSlice(), op1});
    }
}
