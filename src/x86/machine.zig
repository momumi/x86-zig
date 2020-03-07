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
pub const CpuFeature = database.CpuFeature;

const Address = operand.Address;
const Signature = database.Signature;
const InstructionItem = database.InstructionItem;

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

    cpu_feature_mask: CpuFeature.MaskType = CpuFeature.all_features_mask,

    pub fn init(mode: Mode86) Machine {
        return Machine {
            .mode = mode,
        };
    }

    pub fn init_with_features(mode: Mode86, features: []const CpuFeature) Machine {
        return Machine {
            .mode = mode,
            .cpu_feature_mask = CpuFeature.arrayToMask(features),
        };
    }

    pub fn addressSize(self: Machine) BitSize {
        return switch (self.mode) {
            .x86_16 => .Bit16,
            .x86_32 => .Bit32,
            .x64 => .Bit64,
        };
    }

    /// If the operand is a .Reg, convert it to the equivalent .Rm
    pub fn coerceRm(self: Machine, op: Operand) Operand {
        switch (op) {
            .Reg => |reg| return Operand.registerRm(reg),
            .RegSae => |reg_sae| return Operand.registerRm(reg_sae.reg),
            .Rm => return op,
            .RmPred => |rm_pred| return Operand { .Rm = rm_pred.rm },
            else => unreachable,
        }
    }

    pub fn encodeRMI(
        self: Machine,
        instr_item: *const InstructionItem,
        op_reg: ?*const Operand,
        op_rm: ?*const Operand,
        imm: ?Immediate,
        overides: Overides
    ) AsmError!Instruction {
        const opcode = instr_item.opcode.Op;
        var res = Instruction{};
        var prefixes = Prefixes {};
        var rex_w: u1 = 0;

        const reg = if (op_reg) |r| x: {
            break :x r.Reg;
        } else if (opcode.reg_bits) |reg_bits| x: {
            const fake_reg = @intToEnum(Register, reg_bits + @enumToInt(Register.AX));
            break :x fake_reg;
        } else x: {
            const fake_reg = @intToEnum(Register, self.reg_bits_fill + @enumToInt(Register.AX));
            break :x fake_reg;
        };

        const has_rm = (op_rm != null);
        var modrm: operand.ModRmResult = undefined;

        if (has_rm) {
            const rm = self.coerceRm(op_rm.?.*).Rm;
            modrm = try rm.encodeReg(self.mode, reg, overides);
        }

        res.addCompoundOpcode(opcode);
        if (has_rm) {
            res.addPrefixes(modrm.prefixes, opcode);
        } else if (imm) |im| {
            const op_size = im.bitSize();
            const addr_size = .None;
            try prefixes.addOverides(self.mode, &rex_w, op_size, addr_size, overides);
            res.addPrefixes(prefixes, opcode);
        } else {
            try prefixes.addOverides(self.mode, &rex_w, .None, .None, overides);
            res.addPrefixes(prefixes, opcode);
        }

        try res.addRexRm(self.mode, rex_w, modrm);
        res.addOpcode(opcode);
        if (has_rm) {
            res.modrm(modrm);
        }
        if (imm) |im| {
            res.addImm(im);
        }

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
    pub fn encodeOI(
        self: Machine,
        instr_item: *const InstructionItem,
        op_reg: ?*const Operand,
        imm: ?Immediate,
        overides: Overides
    ) AsmError!Instruction {
        const opcode = instr_item.opcode.Op;
        var res = Instruction{};
        var prefixes = Prefixes {};
        var rex_w: u1 = 0;
        const reg = switch (op_reg.?.*) {
            .Reg => |reg| reg,
            else => unreachable,
        };

        // compute prefixes
        {
            const operand_size = reg.bitSize();
            const addressing_size = BitSize.None;

            try prefixes.addOverides(self.mode, &rex_w, operand_size, addressing_size, overides);
        }

        res.addPrefixes(prefixes, opcode);
        try res.addRex(self.mode, null, reg, overides);
        res.addOpcodeRegNum(opcode, reg);

        if (imm) |im| {
            res.addImm(im);
        }

        return res;
    }

    pub fn encodeImmImm(
        self: Machine,
        instr_item: *const InstructionItem,
        imm1: Immediate,
        imm2: Immediate,
        overides: Overides
    ) AsmError!Instruction {
        var res = try self.encodeRMI(instr_item, null, null, imm1, overides);
        res.addImm(imm2);

        return res;
    }

    pub fn encodeAddress(
        self: Machine,
        instr_item: *const InstructionItem,
        op_addr: ?*const Operand,
        overides: Overides
    ) AsmError!Instruction {
        const opcode = instr_item.opcode.Op;
        var res = Instruction{};
        var prefixes = Prefixes {};
        var rex_w: u1 = 0;

        const addr = op_addr.?.Addr;

        // compute prefixes
        {
            const operand_size = addr.getDisp().bitSize();
            const addressing_size = BitSize.None;

            try prefixes.addOverides(self.mode, &rex_w, operand_size, addressing_size, overides);
        }

        res.addCompoundOpcode(opcode);
        res.addPrefixes(prefixes, opcode);
        res.addOpcode(opcode);
        res.addAddress(addr);

        return res;
    }

    fn getSpecialAddrSize(op: *const Operand, name: register.RegisterName, seg: *Segment) BitSize {
        switch (op.*) {
            .Rm => {},
            else => return .None,
        }

        switch (op.Rm) {
            // [base_reg16 + index_reg16 + disp0/8/16]
            .Mem16 => |mem| {
                seg.* = mem.segment;
                if (
                    mem.index == null
                    or mem.index.?.name() != name
                    or mem.disp.size != .None
                ) {
                    return .None;
                } else {
                    return mem.index.?.bitSize();
                }
            },

            // [reg + disp0/8/32]
            .Mem => |mem| {
                seg.* = mem.segment;
                if (
                    mem.reg.name() != name
                    or mem.disp.size != .None
                ) {
                    return .None;
                } else {
                    return mem.reg.bitSize();
                }
            },

            else => return .None,
        }
    }

    pub fn encodeMSpecial(
        self: Machine,
        instr_item: *const InstructionItem,
        op_1: ?*const Operand,
        op_2: ?*const Operand,
        overides: Overides,
    ) AsmError!Instruction {
        const mnem = instr_item.mnemonic;
        const opcode = instr_item.opcode.Op;
        var res = Instruction{};

        var operand_size: BitSize = .None;
        var addressing_size: BitSize = .None;
        var def_seg: Segment = .DefaultSeg;
        var overide_seg: Segment = .DefaultSeg;
        var di_seg: Segment = .DefaultSeg;
        var si_seg: Segment = .DefaultSeg;

        const di_op_size = if (op_1) |op_| op_.operandSize() else .None;
        const si_op_size = if (op_2) |op_| op_.operandSize() else .None;

        const di_addr_size = if (op_1) |op_| getSpecialAddrSize(op_, .DI, &di_seg) else .None;
        const si_addr_size = if (op_2) |op_| getSpecialAddrSize(op_, .SI, &si_seg) else .None;

        switch (mnem) {
            // ES:[DI], __
            //
            // INS   BYTE ES:[(E/R)DI], DX
            // INS   WORD ES:[(E/R)DI], DX
            // INS   DWORD ES:[(E/R)DI], DX
            //
            // STOS  BYTE ES:[(E/R)DI], AL
            // STOS  WORD ES:[(E/R)DI], AX
            // STOS  DWORD ES:[(E/R)DI], EAX
            // STOS  QWORD ES:[(E/R)DI], RAX
            //
            // SCAS  BYTE ES:[(E/R)DI], AL
            // SCAS  WORD ES:[(E/R)DI], AX
            // SCAS  DWORD ES:[(E/R)DI], EAX
            // SCAS  QWORD ES:[(E/R)DI], RAX
            .SCAS, .STOS, .INS => {
                if (
                    di_addr_size == .None
                    or (mnem == .INS and si_op_size != .Bit16)
                    or (mnem != .INS and di_op_size != si_op_size)
                ) {
                    return AsmError.InvalidOperand;
                }
                addressing_size = di_addr_size;
                operand_size = di_op_size;
                overide_seg = di_seg;
                def_seg = .ES;
            },

            // __, DS:[SI]
            //
            // OUTS  DX, BYTE DS:[(E/R)SI]
            // OUTS  DX, WORD DS:[(E/R)SI]
            // OUTS  DX, DWORD DS:[(E/R)SI]
            //
            // LODS  AL, BYTE DS:[(E/R)SI]
            // LODS  AX, WORD DS:[(E/R)SI]
            // LODS  EAX, DWORD DS:[(E/R)SI]
            // LODS  RAX, QWORD DS:[(E/R)SI]
            .LODS, .OUTS => {
                if (
                    si_addr_size == .None
                    or (mnem == .OUTS and di_op_size != .Bit16)
                    or (mnem != .OUTS and di_op_size != si_op_size)
                ) {
                    return AsmError.InvalidOperand;
                }
                addressing_size = si_addr_size;
                operand_size = si_op_size;
                overide_seg = si_seg;
                def_seg = .DS;
            },

            // ES:[DI], DS:[SI]
            //
            // MOVS  BYTE ES:[(E/R)DI], BYTE DS:[(E/R)SI]
            // MOVS  WORD ES:[(E/R)DI], WORD DS:[(E/R)SI]
            // MOVS  DWORD ES:[(E/R)DI], DWORD DS:[(E/R)SI]
            // MOVS  QWORD ES:[(E/R)DI], QWORD DS:[(E/R)SI]
            //
            // CMPS  BYTE ES:[(R/E)DI], BYTE DS:[(R/E)SI]
            // CMPS  WORD ES:[(R/E)DI], WORD DS:[(R/E)SI]
            // CMPS  DWORD ES:[(R/E)DI], DWORD DS:[(R/E)SI]
            // CMPS  QWORD ES:[(R/E)DI], QWORD DS:[(R/E)SI]
            .CMPS, .MOVS => {
                if (
                    di_addr_size == .None
                    or si_addr_size == .None
                    or di_addr_size != si_addr_size
                    or di_op_size != si_op_size
                    or !(di_seg == .ES or di_seg == .DefaultSeg)
                ) {
                    return AsmError.InvalidOperand;
                }
                addressing_size = di_addr_size;
                operand_size = di_op_size;
                overide_seg = si_seg;
                def_seg = .DS;
            },

            // XLAT AL, BYTE DS:[(E/R)BX + AL]
            .XLAT => {
                const rm = if (op_2) |op_2_| op_2_.Rm else op_1.?.Rm;
                operand_size = .Bit8;
                def_seg = .DS;
                switch (rm) {
                    .Sib => |sib| {
                        overide_seg = sib.segment;
                        if (sib.base == null or sib.index == null) {
                            return AsmError.InvalidOperand;
                        } else if (sib.base.?.name() == .BX and sib.index.? == .AL) {
                            addressing_size = sib.base.?.bitSize();
                        } else if (sib.base.? == .AL and sib.index.?.name() == .BX) {
                            addressing_size = sib.index.?.bitSize();
                        } else {
                            return AsmError.InvalidOperand;
                        }

                        // x86_64 doesn't use a default segment for these instructions
                        if (self.mode == .x64 and addressing_size == .Bit64) {
                            def_seg = .DefaultSeg;
                        }
                    },
                    else => return AsmError.InvalidOperand,
                }
            },
            else => unreachable,
        }


        // compute the prefixes
        var prefixes = Prefixes {};
        var rex_w: u1 = 0;
        if (overide_seg != def_seg) {
            prefixes.addSegmentOveride(overide_seg);
        }
        try prefixes.addOverides(self.mode, &rex_w, operand_size, addressing_size, overides);

        res.addPrefixes(prefixes, opcode);
        try res.rexRaw(self.mode, util.rexValue(rex_w, 0, 0, 0));
        res.addOpcode(opcode);

        return res;
    }

    pub fn encodeMOffset(
        self: Machine,
        instr_item: *const InstructionItem,
        op_reg: ?*const Operand,
        op_moff: ?*const Operand,
        overides: Overides
    ) AsmError!Instruction {
        const opcode = instr_item.opcode.Op;
        var res = Instruction{};
        const reg = op_reg.?.Reg;
        const moff = op_moff.?.Addr.MOffset;
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

            try prefixes.addOverides(self.mode, &rex_w, operand_size, addressing_size, overides);
        }

        res.addCompoundOpcode(opcode);
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
        instr_item: *const InstructionItem,
        vec1_r: ?*const Operand,
        vec2_v: ?*const Operand,
        rm_op: ?*const Operand,
        vec4_is: ?*const Operand,
        imm_op: ?*const Operand,
        /// 8 bit displacement multiplier
        disp_n: u8,
    ) AsmError!Instruction {
        const avx_opcode = instr_item.opcode.Avx;
        var res = Instruction{};

        var modrm: operand.ModRmResult = undefined;
        var has_modrm: bool = undefined;

        if (vec1_r == null and rm_op == null) {
            has_modrm = false;
        } else if (vec1_r) |v| {
            var rm = self.coerceRm(rm_op.?.*).Rm;
            rm.scaleAvx512Displacement(disp_n);
            const reg = switch (v.*) {
                .Reg => v.Reg,
                .RegPred => v.RegPred.reg,
                .RegSae => v.RegSae.reg,
                else => unreachable,
            };
            modrm = try rm.encodeReg(self.mode, reg, .ZO);
            has_modrm = true;
        } else {
            var rm = self.coerceRm(rm_op.?.*).Rm;
            rm.scaleAvx512Displacement(disp_n);
            const fake_reg = Register.create(.Bit32, avx_opcode.reg_bits.?);
            modrm = try rm.encodeReg(self.mode, fake_reg, .ZO);
            has_modrm = true;
        }

        if (has_modrm) {
            res.addPrefixes(modrm.prefixes, Opcode{});
        }

        const modrm_ptr: ?*const operand.ModRmResult = if (has_modrm) &modrm else null;
        const avx_res = try avx_opcode.encode(self, vec1_r, vec2_v, rm_op, modrm_ptr);
        try res.addAvx(self.mode, avx_res);
        res.addOpcodeByte(avx_opcode.opcode);

        if (has_modrm) {
            res.modrm(modrm);
        }

        if (vec4_is) |vec| {
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

    pub fn build4(
        self: Machine,
        mnem: Mnemonic,
        ops1: Operand,
        ops2: Operand,
        ops3: Operand,
        ops4: Operand
    ) AsmError!Instruction {
        return self.build(mnem, &ops1, &ops2, &ops3, &ops4);
    }

    pub fn build(
        self: Machine,
        mnem: Mnemonic,
        ops1: ?*const Operand,
        ops2: ?*const Operand,
        ops3: ?*const Operand,
        ops4: ?*const Operand
    ) AsmError!Instruction {
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
