const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const x86 = @import("machine.zig");
const Instruction = x86.Instruction;
const AsmError = x86.AsmError;
const Machine = x86.Machine;
const Operand = x86.Operand;
const Mnemonic = x86.Mnemonic;
const EncodingControl = x86.EncodingControl;

pub const debug: bool = true;
var hide_debug: bool = true;

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

/// Returns true if bytes matches the given hex string. ie:
/// matchesHexString(&[3]u8{0xaa, 0xbb, 0xcc}, "aa bb cc") -> true
pub fn matchesHexString(bytes: []const u8, str: []const u8) bool {
    var lo: ?u8 = null;
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
            const cur_byte = (hi.? << 4) | (lo.? << 0);

            // bytes string is too short to be a match
            if (pos >= bytes.len) {
                return false;
            }

            if (bytes[pos] != cur_byte) {
                return false;
            }

            pos += 1;
            hi = null;
            lo = null;
        }
    }

    if (pos != bytes.len) {
        // not enough bytes in bytes[] array
        return false;
    }

    if (hi != null and lo == null) {
        std.debug.panic("invalid hex string: must have even number of hex digits", .{});
    }

    return true;
}

pub fn isMatchingMemory(instr: AsmError!Instruction, hex_str: []const u8) bool {
    if (instr) |temp| {
        return matchesHexString(temp.asSlice(), hex_str);
    } else |err| {
        return false;
    }
}

pub fn debugPrint(on: bool) void {
    if (on) {
        // automatically added newline to work around the test runners formating
        std.debug.warn("\n", .{});
    }
    hide_debug = !on;
}

pub fn printOp(
    hide_message: bool,
    machine: Machine,
    ctrl: ?*const EncodingControl,
    mnem: Mnemonic,
    instr: AsmError!Instruction,
    op1: ?*const Operand,
    op2: ?*const Operand,
    op3: ?*const Operand,
    op4: ?*const Operand,
    op5: ?*const Operand,
) void {
    if (hide_message) {
        return;
    }

    switch (machine.mode) {
        .x86_16 => std.debug.warn("x86-16: ", .{}),
        .x86_32 => std.debug.warn("x86-32: ", .{}),
        .x64 => std.debug.warn("x86-64: ", .{}),
    }

    if (ctrl) |c| {
        for (c.prefixes) |pre| {
            if (pre == .None) {
                break;
            }
            std.debug.warn("{} ", .{@tagName(pre)});
        }
    }

    std.debug.warn("{} ", .{@tagName(mnem)});

    if (op1) |op| {
        std.debug.warn("{}", .{op1});
    }
    if (op2) |op| {
        std.debug.warn(", {}", .{op2});
    }
    if (op3) |op| {
        std.debug.warn(", {}", .{op3});
    }
    if (op4) |op| {
        std.debug.warn(", {}", .{op4});
    }
    if (op5) |op| {
        std.debug.warn(", {}", .{op5});
    }

    if (instr) |temp| {
        std.debug.warn(": {x}\n", .{temp.asSlice()});
    } else |err| {
        std.debug.warn(": {}\n", .{err});
    }
}

pub fn testOp(
    machine: Machine,
    ctrl: ?*const EncodingControl,
    mnem: Mnemonic,
    op1: ?*const Operand,
    op2: ?*const Operand,
    op3: ?*const Operand,
    op4: ?*const Operand,
    op5: ?*const Operand,
    comptime thing_to_match: var,
) void {
    switch (@TypeOf(thing_to_match)) {
        AsmError => {
            testOpError(machine, ctrl, mnem, op1, op2, op3, op4, op5, thing_to_match);
        },
        else => {
            testOpInstruction(machine, ctrl, mnem, op1, op2, op3, op4, op5, thing_to_match);
        },
    }
}

pub fn testOpInstruction(
    machine: Machine,
    ctrl: ?*const EncodingControl,
    mnem: Mnemonic,
    op1: ?*const Operand,
    op2: ?*const Operand,
    op3: ?*const Operand,
    op4: ?*const Operand,
    op5: ?*const Operand,
    hex_str: []const u8
) void {
    const instr = machine.build(ctrl, mnem, op1, op2, op3, op4, op5);
    printOp(hide_debug, machine, ctrl, mnem, instr, op1, op2, op3, op4, op5);
    if (!isMatchingMemory(instr, hex_str)) {
        // strip any spaces from the string to unify formating
        var expected_hex: [128]u8 = undefined;
        var pos: usize = 0;
        for (hex_str) |c| {
            if (c != ' ') {
                expected_hex[pos] = c;
                pos += 1;
            }
        }

        std.debug.warn("Test failed:\n", .{});
        std.debug.warn("Expeced: {}\n", .{expected_hex[0..pos]});
        if (instr) |ins| {
            std.debug.warn("But got: {x}\n", .{ins.asSlice()});
        } else |err| {
            std.debug.warn("But got: {}\n", .{err});
        }
        printOp(false, machine, ctrl, mnem, instr, op1, op2, op3, op4, op5);
        std.debug.warn("\n", .{});
        testing.expect(false);
    }
}

pub fn testOpError(
    machine: Machine,
    ctrl: ?*const EncodingControl,
    mnem: Mnemonic,
    op1: ?*const Operand,
    op2: ?*const Operand,
    op3: ?*const Operand,
    op4: ?*const Operand,
    op5: ?*const Operand,
    comptime err: AsmError,
) void {
    const instr = machine.build(ctrl, mnem, op1, op2, op3, op4, op5);
    printOp(hide_debug, machine, ctrl, mnem, instr, op1, op2, op3, op4, op5);
    if (!isErrorMatch(instr, err)) {
        std.debug.warn("Test failed:\n", .{});
        std.debug.warn("Expeced error: {}\n", .{err});
        if (instr) |ins| {
            std.debug.warn("But got instr: {x}\n", .{ins.asSlice()});
        } else |actual_error| {
            std.debug.warn("But got error: {}\n", .{actual_error});
        }
        printOp(false, machine, ctrl, mnem, instr, op1, op2, op3, op4, op5);
        std.debug.warn("\n", .{});
        testing.expect(false);
    }
}

pub fn isErrorMatch(instr: AsmError!Instruction, err: AsmError) bool {
    if (instr) |temp| {
        return false;
    } else |actual_error| {
        return actual_error == err;
    }
}

pub fn testOp0(machine: Machine, mnem: Mnemonic, comptime expected: var) void {
    testOp(machine, null, mnem, null, null, null, null, null, expected);
}

pub fn testOp1(machine: Machine, mnem: Mnemonic, op1: Operand, comptime expected: var) void {
    testOp(machine, null, mnem, &op1, null, null, null, null, expected);
}

pub fn testOp2(machine: Machine, mnem: Mnemonic, op1: Operand, op2: Operand, comptime expected: var) void {
    testOp(machine, null, mnem, &op1, &op2, null, null, null, expected);
}

pub fn testOp3(machine: Machine, mnem: Mnemonic, op1: Operand, op2: Operand, op3: Operand, comptime expected: var) void {
    testOp(machine, null, mnem, &op1, &op2, &op3, null, null, expected);
}

pub fn testOp4(
    machine: Machine,
    mnem: Mnemonic,
    op1: Operand,
    op2: Operand,
    op3: Operand,
    op4: Operand,
    comptime expected: var
) void {
    testOp(machine, null, mnem, &op1, &op2, &op3, &op4, null, expected);
}

pub fn testOp5(
    machine: Machine,
    mnem: Mnemonic,
    op1: Operand,
    op2: Operand,
    op3: Operand,
    op4: Operand,
    op5: Operand,
    comptime expected: var
) void {
    testOp(machine, null, mnem, &op1, &op2, &op3, &op4, &op5, expected);
}

pub fn testOpCtrl0(
    machine: Machine,
    ctrl: EncodingControl,
    mnem: Mnemonic,
    comptime expected: var
) void {
    testOp(machine, &ctrl, mnem, null, null, null, null, null, expected);
}

pub fn testOpCtrl1(
    machine: Machine,
    ctrl: EncodingControl,
    mnem: Mnemonic,
    op1: Operand,
    comptime expected: var
) void {
    testOp(machine, &ctrl, mnem, &op1, null, null, null, null, expected);
}

pub fn testOpCtrl2(
    machine: Machine,
    ctrl: EncodingControl,
    mnem: Mnemonic,
    op1: Operand,
    op2: Operand,
    comptime expected: var
) void {
    testOp(machine, &ctrl, mnem, &op1, &op2, null, null, null, expected);
}

pub fn testOpCtrl3(
    machine: Machine,
    ctrl: EncodingControl,
    mnem: Mnemonic,
    op1: Operand,
    op2: Operand,
    op3: Operand,
    comptime expected: var
) void {
    testOp(machine, &ctrl, mnem, &op1, &op2, &op3, null, null, expected);
}

pub fn testOpCtrl4(
    machine: Machine,
    ctrl: EncodingControl,
    mnem: Mnemonic,
    op1: Operand,
    op2: Operand,
    op3: Operand,
    op4: Operand,
    comptime expected: var
) void {
    testOp(machine, &ctrl, mnem, &op1, &op2, &op3, &op4, null, expected);
}

pub fn testOpCtrl5(
    machine: Machine,
    ctrl: EncodingControl,
    mnem: Mnemonic,
    op1: Operand,
    op2: Operand,
    op3: Operand,
    op4: Operand,
    op5: Operand,
    comptime expected: var
) void {
    testOp(machine, &ctrl, mnem, &op1, &op2, &op3, &op4, &op5, expected);
}
