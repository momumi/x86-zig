const std = @import("std");
const assert = std.debug.assert;
const util = @import("util.zig");
const testing = std.testing;

pub usingnamespace(@import("types.zig"));

pub const avx = @import("avx.zig");
pub const database = @import("database.zig");
pub const operand = @import("operand.zig");
pub const register = @import("register.zig");
pub const instruction = @import("instruction.zig");
pub const mnemonic = @import("mnemonic.zig");

pub const Immediate = operand.Immediate;
pub const Instruction = instruction.Instruction;
pub const Mnemonic = mnemonic.Mnemonic;
pub const Operand = operand.Operand;
pub const Register = register.Register;

const Address = operand.Address;
const Signature = database.Signature;

const warn = if (util.debug) std.debug.warn else util.warnDummy;

pub const Machine = struct {
    mode: Mode86,
    /// TODO: Used for instructions were the mod field of modrm is ignored by CPU
    /// Eg: MOV Control/Debug registers
    mod_fill: u2 = 0b11,
    /// Used for instructions where reg field of modrm is ignored by CPU, (eg: SETcc)
    reg_bits_fill: u3 = 0b000,
    // TODO: might not need these
    base_fill: u3 = 0b000,
    index_fill: u3 = 0b000,
    /// For avx when W value is ignoreg (.WIG)
    w_fill: u1 = 0b0,
    /// For vex/evex for opcodes that ignore L field (LIG)
    l_fill: u2 = 0b0,
    // prefix_order: ? = null;

    pub fn init(mode: Mode86) Machine {
        return Machine {
            .mode = mode,
        };
    }

    pub fn addressSize(self: Machine) BitSize {
        return switch (self.mode) {
            .x86_16 => .Bit16,
            .x86 => .Bit32,
            .x64 => .Bit64,
        };
    }

    pub fn dataSize(self: Machine) DataSize {
        return switch (self.mode) {
            .x86_16 => .WORD,
            .x86 => .DWORD,
            .x64 => .QWORD,
        };
    }

    /// If the operand is a .Reg, convert it to the equivalent .Rm
    pub fn coerceRm(self: Machine, op: Operand) Operand {
        switch (op) {
            .Reg => |reg| return Operand.registerRm(reg),
            .Rm => return op,
            else => unreachable,
        }
    }


    pub fn encodeOpcode(self: Machine, opcode: Opcode, void_op: ?*const Operand, default_size: DefaultSize) AsmError!Instruction {
        var res = Instruction{};
        var prefixes = Prefixes {};
        var rex_w: u1 = 0;
        const addressing_size = BitSize.None;
        const operand_size = if (void_op) |op| x: {
            switch (op.operandDataSize()) {
                .Default => break :x default_size.bitSize(self.mode),
                else => |op_size| break :x op_size.bitSize(),
            }
        } else x: {
            break :x default_size.bitSize(self.mode);
        };

        try prefixes.addOverides(self.mode, &rex_w, operand_size, addressing_size, default_size);

        res.addPrefixes(prefixes, opcode);
        if (rex_w != 0) {
            try res.addRex(self.mode, Register.RAX, Register.RAX, default_size);
        }
        res.addOpcode(opcode);
        return res;
    }

    /// Encode an instruction where the register number used is added to the opcode.
    /// The second operand is an immediate.
    ///
    /// Example opcodes:
    ///
    /// B0+ rb ib    MOV r8, imm8           ( 0xB0 + 8 bit register number (8 opcodes))
    /// B8+ rw iw    MOV r16, imm16         ( 0xB8 + 16/32/64 bit register number (8 opcodes))
    ///
    pub fn encodeOpcodeRegNumImmediate(self: Machine, opcode: Opcode, reg: Operand, imm: Immediate, default_size: DefaultSize) AsmError!Instruction {
        var res = try self.encodeOpcodeRegNum(opcode, reg, default_size);
        res.addImm(imm);
        return res;
    }

    pub fn encodeOpcodeRegNum(self: Machine, opcode: Opcode, op_reg: Operand, default_size: DefaultSize) AsmError!Instruction {
        var res = Instruction{};
        var prefixes = Prefixes {};
        var rex_w: u1 = 0;
        const reg = switch (op_reg) {
            .Reg => |reg| reg,
            else => unreachable,
        };

        // compute prefixes
        {
            const operand_size = reg.bitSize();
            const addressing_size = BitSize.None;

            try prefixes.addOverides(self.mode, &rex_w, operand_size, addressing_size, default_size);
        }

        res.addPrefixes(prefixes, opcode);
        try res.addRex(self.mode, null, reg, default_size);
        res.addOpcodeRegNum(opcode, reg);
        return res;
    }

    pub fn encodeRmImmediate(self: Machine, opcode: Opcode, rm_op: Operand, imm: Immediate, default_size: DefaultSize) AsmError!Instruction {
        var res = Instruction{};
        const rm = self.coerceRm(rm_op).Rm;

        switch (default_size) {
            .RM8, .RM32 => {
                if (rm.operandSize() == .Bit64 and imm.bitSize() == .Bit32) {
                    // skip: can't encode 64 bit immediate and r/m64 at the same time
                    // but we can do r/m64 with a 32 bit immediate
                } else if (rm.operandSize() != imm.bitSize()) {
                    return AsmError.InvalidOperand;
                }
            },

            .RM32_I8 => {
                if (imm.bitSize() != .Bit8) {
                    return AsmError.InvalidOperand;
                }
            },

            else => if (default_size.needsSizeCheck() and imm.bitSize() != rm.operandSize()) {
                return AsmError.InvalidOperand;
            }
,
        }

        const reg_bits = if (opcode.reg_bits) |bits| bits else self.reg_bits_fill;
        const modrm = try rm.encodeOpcodeRm(self.mode, reg_bits, default_size);

        res.addPrefixes(modrm.prefixes, opcode);
        try res.addRexRm(self.mode, 0, modrm);
        res.addOpcode(opcode);
        res.modrm(modrm);
        res.addImm(imm);
        return res;
    }

    pub fn encodeRm(self: Machine, opcode: Opcode, op_rm: Operand, def_size: DefaultSize) AsmError!Instruction {
        var res = Instruction{};

        const rm = self.coerceRm(op_rm).Rm;
        const reg_bits = if (opcode.reg_bits) |bits| bits else self.reg_bits_fill;
        const modrm = try rm.encodeOpcodeRm(self.mode, reg_bits, def_size);

        res.addPrefixes(modrm.prefixes, opcode);
        try res.addRexRm(self.mode, 0, modrm);
        res.addOpcode(opcode);
        res.modrm(modrm);
        return res;
    }

    pub fn encodeImmediate(self: Machine, opcode: Opcode, void_op: ?*const Operand, imm: Immediate, def_size: DefaultSize) AsmError!Instruction {
        var res = Instruction{};
        var prefixes = Prefixes {};
        var rex_w: u1 = 0;

        const addressing_size = BitSize.None;
        const operand_size = if (void_op) |op| x: {
            break :x op.operandDataSize().bitSize();
        } else x: {
            break :x imm.bitSize();
        };

        try prefixes.addOverides(self.mode, &rex_w, operand_size, addressing_size, def_size);

        res.addPrefixes(prefixes, opcode);
        if (void_op) |op| {
            switch (op.*) {
                .Reg => try res.addRex(self.mode, op.Reg, Register.AX, def_size),
                else => unreachable,
            }
        }
        res.addOpcode(opcode);
        res.addImm(imm);
        return res;
    }

    pub fn encodeImmImm(
        self: Machine,
        opcode: Opcode,
        void_op: ?*const Operand,
        imm1: Immediate,
        imm2: Immediate,
        def_size: DefaultSize
    ) AsmError!Instruction {
        var res = try self.encodeImmediate(opcode, void_op, imm1, def_size);
        res.addImm(imm2);

        return res;
    }

    pub fn encodeAddress(self: Machine, opcode: Opcode, op: Operand, def_size: DefaultSize) AsmError!Instruction {
        var res = Instruction{};
        var prefixes = Prefixes {};
        var rex_w: u1 = 0;

        // compute prefixes
        {
            const operand_size = op.Addr.getDisp().bitSize();
            const addressing_size = BitSize.None;

            try prefixes.addOverides(self.mode, &rex_w, operand_size, addressing_size, def_size);
        }

        res.addPrefixes(prefixes, opcode);
        res.addOpcode(opcode);
        res.addAddress(op.Addr);

        return res;
    }

    pub fn encodeRegRm(self: Machine, opcode: Opcode, op_reg: Operand, op_rm: Operand, def_size: DefaultSize) AsmError!Instruction {
        var res = Instruction{};
        const reg = op_reg.Reg;
        const rm = self.coerceRm(op_rm).Rm;

        if (def_size.needsSizeCheck() and reg.bitSize() != rm.operandSize()) {
            warn("operand size mismatch: reg({}), rm({})\n", .{reg.bitSize(), rm.operandSize()});
            return AsmError.InvalidOperand;
        }

        const modrm = try rm.encodeReg(self.mode, reg, def_size);

        res.addPrefixes(modrm.prefixes, opcode);
        try res.addRexRm(self.mode, 0, modrm);
        res.addOpcode(opcode);
        res.modrm(modrm);

        return res;
    }

    pub fn encodeRegRmImmediate(
        self: Machine,
        opcode: Opcode,
        op_reg: Operand,
        op_rm: Operand,
        imm: Immediate,
        default_size: DefaultSize
    ) AsmError!Instruction {

        const rm = self.coerceRm(op_rm);

        switch (default_size) {
            .RM8, .RM32 => {
                if (rm.operandSize() == .Bit64 and imm.bitSize() == .Bit32) {
                    // skip: can't encode 64 bit immediate and r/m64 at the same time
                    // but we can do r/m64 with a 32 bit immediate
                } else if (rm.Rm.operandSize() != imm.bitSize()) {
                    return AsmError.InvalidOperand;
                }
            },

            .RM32_I8 => {
                if (imm.bitSize() != .Bit8) {
                    return AsmError.InvalidOperand;
                }
            },

            .RM32_RM, .ZO => {},

            else => unreachable,
        }

        var res = try self.encodeRegRm(opcode, op_reg, rm, default_size);
        res.addImm(imm);

        return res;
    }

    pub fn encodeMOffset(self: Machine, opcode: Opcode, op_reg: Operand, op_moff: Operand, def_size: DefaultSize) AsmError!Instruction {
        var res = Instruction{};
        const reg = op_reg.Reg;
        const moff = op_moff.Addr.MOffset;
        // MOffset can only use AL, AX, EAX, RAX
        if (reg.number() != Register.AX.number()) {
            return AsmError.InvalidOperand;
        }

        if (moff.disp.bitSize() != self.addressSize()) {
            return AsmError.InvalidOperand;
        }

        var prefixes = Prefixes {};
        var rex_w: u1 = 0;

        // compute prefixes
        {
            if (moff.segment != .DefaultSeg) {
                prefixes.addSegmentOveride(moff.segment);
            }

            const operand_size = reg.bitSize();
            const addressing_size = moff.disp.bitSize();

            try prefixes.addOverides(self.mode, &rex_w, operand_size, addressing_size, def_size);
        }

        res.addPrefixes(prefixes, opcode);
        try res.rexRaw(self.mode, util.rexValue(rex_w, 0, 0, 0));
        res.addOpcode(opcode);

        switch (moff.disp) {
            .Disp16 => |disp| res.addImm16(disp),
            .Disp32 => |disp| res.addImm32(disp),
            .Disp64 => |disp| res.addImm64(disp),
        }

        return res;
    }

    pub fn encodeAvx(
        self: Machine,
        avx_opcode: avx.AvxOpcode,
        vec1: ?*const Operand,
        vec2: ?*const Operand,
        rm_op: ?*const Operand,
        vec4: ?*const Operand,
        imm_op: ?*const Operand,
        default_size: DefaultSize
    ) AsmError!Instruction {
        var res = Instruction{};

        const rm = self.coerceRm(rm_op.?.*).Rm;

        const avx_res = try avx_opcode.encode(self, vec1, vec2, rm_op);

        const modrm = if (vec1) |v| x: {
            break :x try rm.encodeReg(self.mode, v.Reg, default_size);
        } else x: {
            const fake_reg = Register.create(.Bit32, avx_opcode.reg_bits.?);
            break :x try rm.encodeReg(self.mode, fake_reg, default_size);
        };

        res.addPrefixes(modrm.prefixes, Opcode{});
        try res.addAvx(self.mode, avx_res);
        res.addOpcodeByte(avx_opcode.opcode);
        res.modrm(modrm);

        if (vec4) |vec| {
            // currently EVEX support for 4 operands is not officialy documented
            assert(avx_opcode.encoding != .EVEX);

            // imm8[7:4] <- vec_number
            var imm8: u8 = 0x00;
            const vec_num = vec.Reg.number();
            imm8 |= vec_num << 4;

            // imm8[3:0] <- immediate payload if present
            if (imm_op) |imm| {
                const imm_val = imm.Imm.as8();
                if (imm_val > 0x0F) {
                    return AsmError.InvalidOperand;
                }
                imm8 |= imm_val << 0;
            }
            res.addImm8(imm8);
        } else if (imm_op) |imm| {
            res.addImm(imm.Imm);
        }

        return res;
    }

    pub fn build0(self: Machine, mnem: Mnemonic) AsmError!Instruction {
        return self.build(mnem, null, null, null, null);
    }

    pub fn build1(self: Machine, mnem: Mnemonic, ops1: Operand) AsmError!Instruction {
        return self.build(mnem, &ops1, null, null, null);
    }

    pub fn build2(self: Machine, mnem: Mnemonic, ops1: Operand, ops2: Operand) AsmError!Instruction {
        return self.build(mnem, &ops1, &ops2, null, null);
    }

    pub fn build3(self: Machine, mnem: Mnemonic, ops1: Operand, ops2: Operand, ops3: Operand) AsmError!Instruction {
        return self.build(mnem, &ops1, &ops2, &ops3, null);
    }

    pub fn build4(self: Machine, mnem: Mnemonic, ops1: Operand, ops2: Operand, ops3: Operand) AsmError!Instruction {
        return self.build(mnem, &ops1, &ops2, &ops3, &ops4);
    }

    pub fn build(self: Machine, mnem: Mnemonic, ops1: ?*const Operand, ops2: ?*const Operand, ops3: ?*const Operand, ops4: ?*const Operand) AsmError!Instruction {
        const sig = database.Signature.fromOperands(ops1, ops2, ops3, ops4);

        // sig.debugPrint();
        var i = database.lookupMnemonic(mnem);

        while (database.getDatabaseItem(i).mnemonic == mnem) : (i += 1) {
            const item = database.getDatabaseItem(i);
            // all the opcodes with the same mnemonic are stored adjacent to
            // each other. So when we reach the end of this section no point
            // looking anymore.
            if (item.mnemonic != mnem) {
                break;
            }

            if (Signature.matchTemplate(item.signature, sig)) {
                // item.signature.debugPrint();
                if (item.hasEdgeCase() and item.matchesEdgeCase(self, ops1, ops2, ops3, ops4)) {
                    continue;
                }
                if (!item.isMachineMatch(self)) {
                    continue;
                }
                return item.encode(self, ops1, ops2, ops3, ops4);
            }
        }

        return AsmError.InvalidOperand;
    }

};
