const std = @import("std");
usingnamespace (@import("machine.zig"));

pub fn syscall(self: Machine) AsmError!Instruction {
    var res = Instruction{};
    if (self.mode != .x64) {
        return AsmError.InvalidMode;
    }

    res.opcode(&[2]u8{0x0F, 0x05});

    return res;
}

pub fn sysret(self: Machine, mode: Mode86) AsmError!Instruction {
    var res = Instruction{};
    if (self.mode != .x64) {
        return AsmError.InvalidMode;
    }

    if (mode == .x64) {
        try res.addRex(self.mode, 1, null, null);
    }

    res.opcode(&[2]u8{0x0F, 0x07});

    return res;
}


pub fn sysenter(self: Machine) AsmError!Instruction {
    var res = Instruction{};
    // if (self.mode != .x64) {
    //     return AsmError.InvalidMode;
    // }

    res.opcode(&[2]u8{0x0F, 0x34});

    return res;
}

// TODO: maybe take the mode as a parameter

pub fn sysexit(self: Machine, mode: Mode86) AsmError!Instruction {
    var res = Instruction{};
    if (mode == .x64) {
        try res.addRex(self.mode, 1, null, null);
    }

    res.opcode(&[2]u8{0x0F, 0x35});

    return res;
}

