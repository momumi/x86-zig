const std = @import("std");
const x86 = @import("src/x86.zig");

const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("sys/mman.h");
});

const reg = x86.Operand.register;
const imm = x86.Operand.immediate;

const SyscallLinux64 = struct {
    // /usr/include/asm/unistd_64.h
    pub const write = 1;
    pub const exit = 60;
};

const STDIN  = 0;
const STDOUT = 1;
const STDERR = 2;

// Our memory is not executable by default, so we need to mmap an executable
// block from which to run our program
fn makeExecutableMemory(instr_list: []const x86.Instruction) *c_void {
    const buffer_size = instr_list.len * x86.Instruction.max_length;
    var buf = c.mmap(
        null,
        buffer_size,
        c.PROT_READ | c.PROT_WRITE | c.PROT_EXEC,
        c.MAP_PRIVATE | c.MAP_ANON,
        -1,
        0
    );

    // *c_void -> []u8
    const buf_slice = @ptrCast([*]u8, buf)[0..buffer_size];

    // copy the program into the buffer
    var pos: usize = 0;
    for (instr_list) |instr| {
        std.mem.copy(u8, buf_slice[pos..], instr.asSlice());
        pos += instr.len;
    }

    return buf;
}

pub fn main() anyerror!void {
    const m64 = x86.Machine.init(.x64);

    const message = "hello world!\n";

    const instr_list = [_]x86.Instruction {
        try m64.build2(.MOV, reg(.RAX), imm(SyscallLinux64.write)),
        try m64.build2(.MOV, reg(.RDI), imm(STDOUT)),
        try m64.build2(.MOV, reg(.RSI), imm(@ptrToInt(message))),
        try m64.build2(.MOV, reg(.RDX), imm(message.len)),
        try m64.build0(.SYSCALL),

        try m64.build2(.MOV, reg(.RAX), imm(SyscallLinux64.exit)),
        try m64.build2(.MOV, reg(.RDI), imm(0)),
        try m64.build0(.SYSCALL),
    };

    const buf = makeExecutableMemory(instr_list[0..]);

    const program = @ptrCast(fn () void, buf);
    program();
}
