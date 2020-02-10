const x86 = @import("src/x86.zig");

const example = @import("example-hello.zig");

const SyscallLinux64 = example.SyscallLinux64;
const STDOUT = example.STDOUT;

const reg = x86.Operand.register;
const imm = x86.Operand.immediate;
const memRm = x86.Operand.memoryRmDef;
const m64 = x86.Machine.init(.x64);

// program data
var data1: u64 align(16) = 0x4141414141414141; // "AAAAAAAA"
var data2: u64 align(16) = 0x2020202020202020;
var message  = "hello world!\n".*;

pub fn main() anyerror!void {

    const instr_list = [_]x86.Instruction {
        // Print the string hello world
        try m64.build2(.MOV, reg(.RAX), imm(SyscallLinux64.write)),
        try m64.build2(.MOV, reg(.RDI), imm(STDOUT)),
        try m64.build2(.MOV, reg(.RSI), imm(@ptrToInt(&message))),
        try m64.build2(.MOV, reg(.RDX), imm(message.len)),
        try m64.build0(.SYSCALL),

        // Use MM registers to flip case of "AAAAAAAA" string
        // Then move the string into [message]
        try m64.build2(.MOV, reg(.RAX), imm(@ptrToInt(&data1))),
        try m64.build2(.MOV, reg(.RBX), imm(@ptrToInt(&data2))),
        try m64.build2(.MOVD, reg(.MM0), memRm(.QWORD, .RAX, 0)),
        try m64.build2(.MOVD, reg(.MM1), memRm(.QWORD, .RBX, 0)),
        try m64.build2(.PADDB, reg(.MM0), reg(.MM1)),
        try m64.build2(.MOVQ, reg(.RAX), reg(.MM0)),
        try m64.build2(.MOV, reg(.RCX), imm(@ptrToInt(&message))),
        try m64.build2(.MOV, memRm(.QWORD, .RCX, 0), reg(.RAX)),

        // print modified message string, first 8 bytes should contain 'aaaaaaaa'
        try m64.build2(.MOV, reg(.RAX), imm(SyscallLinux64.write)),
        try m64.build2(.MOV, reg(.RDI), imm(STDOUT)),
        try m64.build2(.MOV, reg(.RSI), imm(@ptrToInt(&message))),
        try m64.build2(.MOV, reg(.RDX), imm(message.len)),
        try m64.build0(.SYSCALL),

        // invert the bytes again, first 8 bytes should now contain 'AAAAAAAA'
        try m64.build2(.PXOR, reg(.MM0), reg(.MM1)),
        try m64.build2(.MOV, reg(.RCX), imm(@ptrToInt(&message))),
        try m64.build2(.MOVQ, memRm(.QWORD, .RCX, 0), reg(.MM0)),

        // print the message again
        try m64.build2(.MOV, reg(.RAX), imm(SyscallLinux64.write)),
        try m64.build2(.MOV, reg(.RDI), imm(STDOUT)),
        try m64.build2(.MOV, reg(.RSI), imm(@ptrToInt(&message))),
        try m64.build2(.MOV, reg(.RDX), imm(message.len)),
        try m64.build0(.SYSCALL),

        // exit(0)
        try m64.build2(.MOV, reg(.RAX), imm(SyscallLinux64.exit)),
        try m64.build2(.MOV, reg(.RDI), imm(0)),
        try m64.build0(.SYSCALL),
    };

    const buf = example.makeExecutableMemory(instr_list[0..]);

    const program = @ptrCast(fn () void, buf);
    program();
}
