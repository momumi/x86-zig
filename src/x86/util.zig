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

pub fn printOp(mnem: Mnemonic, instr: AsmError!Instruction, op1: ?Operand, op2: ?Operand) void {
    if (!debug_print) {
        return;
    }

    std.debug.warn("{} ", .{@tagName(mnem)});
    if (op1) |op| {
        std.debug.warn("{} ", .{op1});
    }
    if (op2) |op| {
        std.debug.warn(", {} ", .{op2});
    }

    if (instr) |temp| {
        std.debug.warn(": {x}\n", .{temp.asSlice()});
    } else |err| {
        std.debug.warn(": {}\n", .{err});
    }
}

pub fn testOp0(machine: Machine, mnem: Mnemonic, comptime hex: []const u8) void {
    const instr = machine.build(mnem, null, null, null, null);
    printOp(mnem, instr, null, null);
    testMem(instr, hex);
}

pub fn testOp1(machine: Machine, mnem: Mnemonic, op1: Operand, comptime hex: []const u8) void {
    const instr = machine.build1(mnem, op1);
    printOp(mnem, instr, op1, null);
    testMem(instr, hex);
}

pub fn testOp2(machine: Machine, mnem: Mnemonic, op1: Operand, op2: Operand, comptime hex: []const u8) void {
    const instr = machine.build2(mnem, op1, op2);
    printOp(mnem, instr, op1, op2);
    testMem(instr, hex);
}

pub fn testOp0Error(machine: Machine, mnem: Mnemonic, op1: Operand, op2: Operand, err:AsmError) void {
    const instr = machine.build(mnem, null, null, null, null);
    printOp(mnem, instr, null, null);
    testError(instr, err);
}

pub fn testOp1Error(machine: Machine, mnem: Mnemonic, op1: Operand, err:AsmError) void {
    const instr = machine.build1(mnem, op1);
    printOp(mnem, instr, op1, null);
    testError(instr, err);
}

pub fn testOp2Error(machine: Machine, mnem: Mnemonic, op1: Operand, op2: Operand, err:AsmError) void {
    const instr = machine.build2(mnem, op1, op2);
    printOp(mnem, instr, op1, op2);
    testError(instr, err);
}

pub fn testError(instr: AsmError!Instruction, err: AsmError) void {
    if (instr) |temp| {
        std.debug.panic("expected {}, found Instr: {x}", .{err, temp.asSlice()});
    } else |actual_error| {
        testing.expect(actual_error == err);
    }
}
