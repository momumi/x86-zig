const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const x86 = @import("machine.zig");
const Instruction = x86.Instruction;
const AsmError = x86.AsmError;
const Machine = x86.Machine;
const Operand = x86.Operand;
const Mnemonic = x86.Mnemonic;

var debug_print: bool = false;

pub fn rexValue(w: u1, r: u1, x: u1, b: u1) u8 {
    // 0b0100_WRXB
    return (
        (0b0100 << 4)
        | (@as(u8, w) << 3)
        | (@as(u8, r) << 2)
        | (@as(u8, x) << 1)
        | (@as(u8, b) << 0)
    );
}

pub fn modrmValue(mod: u2, reg: u3, rm: u3) u8 {
    // mm_rrr_rrr
    return (
        (@as(u8, mod) << 6)
        | (@as(u8, reg) << 3)
        | (@as(u8, rm) << 0)
    );
}

pub fn sibValue(scale: u2, index: u3, base: u3) u8 {
    return (
        (@as(u8, scale) << 6)
        | (@as(u8, index) << 3)
        | (@as(u8, base) << 0)
    );
}

pub fn warnDummy(a: var, b: var) void {}

pub fn hexStrSize(comptime str: []const u8) usize {
    var res: usize = 0;
    for (str) |c| {
        switch (c) {
            '0'...'9' => {},
            'a'...'f' => {},
            'A'...'F' => {},
            ' ' => continue,
            else => unreachable,
        }
        res += 1;
    }
    std.debug.assert(res % 2 == 0);
    return res/2;
}

pub fn hexify(comptime str: []const u8) [hexStrSize(str)]u8 {
    var res: [hexStrSize(str)]u8 = undefined;
    var lo: u8 = undefined;
    var hi: ?u8 = null;
    var pos: usize = 0;

    for (str) |c| {
        if (c == ' ') {
            continue;
        }
        if (hi == null) {
            hi = std.fmt.charToDigit(c, 16) catch unreachable;
        } else {
            lo = std.fmt.charToDigit(c, 16) catch unreachable;
            res[pos] = (hi.? << 4) | (lo << 0);
            pos += 1;
            hi = null;
        }
    }
    return res;
}

pub fn testMem(instr: AsmError!Instruction, comptime hex: []const u8) void {
    if (instr) |temp| {
        testing.expect(std.mem.eql(u8, temp.asSlice(), &hexify(hex)));
    } else |err| {
        std.debug.panic("expected Instruction, found {}", .{err});
    }
}

pub fn debugPrint(on: bool) void {
    debug_print = on;
}

pub fn printOp(
    machine: Machine,
    mnem: Mnemonic,
    instr: AsmError!Instruction,
    op1: ?*const Operand,
    op2: ?*const Operand,
    op3: ?*const Operand,
    op4: ?*const Operand,
) void {
    if (!debug_print) {
        return;
    }

    switch (machine.mode) {
        .x86_16 => std.debug.warn("x86-16: {} ", .{@tagName(mnem)}),
        .x86 => std.debug.warn("x86:    {} ", .{@tagName(mnem)}),
        .x64 => std.debug.warn("x86-64: {} ", .{@tagName(mnem)}),
    }
    if (op1) |op| {
        std.debug.warn("{} ", .{op1});
    }
    if (op2) |op| {
        std.debug.warn(", {} ", .{op2});
    }
    if (op3) |op| {
        std.debug.warn(", {} ", .{op3});
    }
    if (op4) |op| {
        std.debug.warn(", {} ", .{op4});
    }

    if (instr) |temp| {
        std.debug.warn(": {x}\n", .{temp.asSlice()});
    } else |err| {
        std.debug.warn(": {}\n", .{err});
    }
}

pub fn testOp(
    machine: Machine,
    mnem: Mnemonic,
    op1: ?*const Operand,
    op2: ?*const Operand,
    op3: ?*const Operand,
    op4: ?*const Operand,
    comptime thing_to_match: var,
) void {
    switch (@TypeOf(thing_to_match)) {
        AsmError => {
            testOpError(machine, mnem, op1, op2, op3, op4, thing_to_match);
        },
        else => {
            testOpInstruction(machine, mnem, op1, op2, op3, op4, thing_to_match);
        },
    }
}

pub fn testOpInstruction(
    machine: Machine,
    mnem: Mnemonic,
    op1: ?*const Operand,
    op2: ?*const Operand,
    op3: ?*const Operand,
    op4: ?*const Operand,
    comptime hex: []const u8
) void {
    const instr = machine.build(mnem, op1, op2, op3, op4);
    printOp(machine, mnem, instr, op1, op2, op3, op4);
    testMem(instr, hex);
}

pub fn testOpError(
    machine: Machine,
    mnem: Mnemonic,
    op1: ?*const Operand,
    op2: ?*const Operand,
    op3: ?*const Operand,
    op4: ?*const Operand,
    comptime err: AsmError,
) void {
    const instr = machine.build(mnem, op1, op2, op3, op4);
    printOp(machine, mnem, instr, op1, op2, op3, op4);
    testError(instr, err);
}

pub fn testError(instr: AsmError!Instruction, err: AsmError) void {
    if (instr) |temp| {
        std.debug.panic("expected {}, found Instr: {x}", .{err, temp.asSlice()});
    } else |actual_error| {
        testing.expect(actual_error == err);
    }
}

pub fn testOp0(machine: Machine, mnem: Mnemonic, comptime expected: var) void {
    testOp(machine, mnem, null, null, null, null, expected);
}

pub fn testOp1(machine: Machine, mnem: Mnemonic, op1: Operand, comptime expected: var) void {
    testOp(machine, mnem, &op1, null, null, null, expected);
}

pub fn testOp2(machine: Machine, mnem: Mnemonic, op1: Operand, op2: Operand, comptime expected: var) void {
    testOp(machine, mnem, &op1, &op2, null, null, expected);
}

