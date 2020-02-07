const std = @import("std");

pub const register = @import("register.zig");
pub const machine = @import("machine.zig");

usingnamespace(@import("types.zig"));

const Register = register.Register;
const RegisterSpecial = register.RegisterSpecial;

pub const OperandType = enum(u16) {
    const tag_reg8 = 0x00;
    const tag_reg16 = 0x10;
    const tag_reg32 = 0x20;
    const tag_reg64 = 0x30;
    const tag_rm8 = 0x40;
    const tag_rm16 = 0x50;
    const tag_rm32 = 0x60;
    const tag_rm64 = 0x70;
    const tag_seg_reg = 0x80;
    const tag_imm = 0x90;
    const tag_imm_any = 0xA0;
    const tag_moffs = 0xB0;
    const tag_void = 0xC0;
    const tag_rm_mem = 0xD0;
    reg8 = 0 | tag_reg8,
    reg_al = 1 | tag_reg8,
    reg_cl = 2 | tag_reg8,
    reg_dl = 3 | tag_reg8,
    reg_bl = 4 | tag_reg8,

    reg16 = 0 | tag_reg16,
    reg_ax = 1 | tag_reg16,
    reg_cx = 2 | tag_reg16,
    reg_dx = 3 | tag_reg16,
    reg_bx = 4 | tag_reg16,

    reg32 = 0 | tag_reg32,
    reg_eax = 1 | tag_reg32,
    reg_ecx = 2 | tag_reg32,
    reg_edx = 3 | tag_reg32,
    reg_ebx = 4 | tag_reg32,

    reg64 = 0 | tag_reg64,
    reg_rax = 1 | tag_reg64,
    reg_rcx = 2 | tag_reg64,
    reg_rdx = 3 | tag_reg64,
    reg_rbx = 4 | tag_reg64,

    rm8 = 0 | tag_rm8,
    rm_reg8 = 1 | tag_rm8,
    rm_mem8 = 2 | tag_rm8,

    rm16 = 0 | tag_rm16,
    rm_reg16 = 1 | tag_rm16,
    rm_mem16 = 2 | tag_rm16,

    rm32 = 0 | tag_rm32,
    rm_reg32 = 1 | tag_rm32,
    rm_mem32 = 2 | tag_rm32,

    rm64 = 0 | tag_rm64,
    rm_reg64 = 1 | tag_rm64,
    rm_mem64 = 2 | tag_rm64,

    reg_seg = 0 | tag_seg_reg,
    reg_es = 1 | tag_seg_reg,
    reg_cs = 2 | tag_seg_reg,
    reg_ss = 3 | tag_seg_reg,
    reg_ds = 4 | tag_seg_reg,
    reg_fs = 5 | tag_seg_reg,
    reg_gs = 6 | tag_seg_reg,

    imm = 0 | tag_imm,
    imm8 = 1 | tag_imm,
    imm16 = 2 | tag_imm,
    imm32 = 3 | tag_imm,
    imm64 = 4 | tag_imm,

    imm_any = 0 | tag_imm_any,
    imm8_any = 1 | tag_imm_any,
    imm16_any = 2 | tag_imm_any,
    imm32_any = 3 | tag_imm_any,
    imm64_any = 4 | tag_imm_any,
    imm_1 = 5 | tag_imm_any,

    moffs = 0 | tag_moffs,
    moffs8 = 1 | tag_moffs,
    moffs16 = 2 | tag_moffs,
    moffs32 = 3 | tag_moffs,
    moffs64 = 4 | tag_moffs,
    // moffs8 = 0xD0,
    // moffs16 = 0xE0,
    // moffs32 = 0xF0,
    // moffs64 = 0x100,

    _void = 0 | tag_void,
    _void8 = 1 | tag_void,
    _void16 = 2 | tag_void,
    _void32 = 3 | tag_void,
    _void64 = 4 | tag_void,

    // matches memory of any type
    rm_mem = 0 | tag_rm_mem,

    ptr16_16 = 0x110,
    ptr16_32 = 0x120,

    m16_16 = 0x130,
    m16_32 = 0x140,
    m16_64 = 0x150,



    // creg,
    // dreg,

    invalid,

    pub fn getContainerType(self: OperandType) OperandType {
        return @intToEnum(OperandType, @enumToInt(self) & 0xFFF0);
    }

    pub fn fromRegister(reg: Register) OperandType {
        if (reg.number() <= Register.BX.number()) {
            return @intToEnum(OperandType, (@enumToInt(reg) & 0x33) + 1);
        } else {
            return switch (reg.size()) {
                .Reg8 => OperandType.reg8,
                .Reg16 => OperandType.reg16,
                .Reg32 => OperandType.reg32,
                .Reg64 => OperandType.reg64,
            };
        }
    }

    pub fn fromImmediate(imm: Immediate) OperandType {
        switch (imm.size) {
            .Imm8 => return OperandType.imm8,
            .Imm16 => return OperandType.imm16,
            .Imm32 => return OperandType.imm32,
            .Imm64 => return OperandType.imm64,

            .Imm8_any => {
                if (imm.value() == 1) {
                    return OperandType.imm_1;
                } else {
                    return OperandType.imm8_any;
                }
            },
            .Imm16_any => return OperandType.imm16_any,
            .Imm32_any => return OperandType.imm32_any,
            .Imm64_any => return OperandType.imm64_any,
        }
    }

    pub fn fromRegisterSpecial(reg: RegisterSpecial) OperandType {
        switch (reg.registerSpecialType()) {
            .Segment => {
                return @intToEnum(OperandType, ((@enumToInt(reg) & 0x07) + 1) | tag_seg_reg);
            },

            .Float => unreachable,
            .MMX => unreachable,
            .Control => unreachable,
            .Debug => unreachable,
        }
    }

    // For user supplied immediates without an explicit size are allowed to match
    // against larger immediate sizes:
    //      * imm8  <-> imm8,  imm16, imm32, imm64
    //      * imm16 <-> imm16, imm32, imm64
    //      * imm32 <-> imm32, imm64
    //  however since imm64 are used only in limited cases, we only need to check:
    //      * imm8  <-> imm8,  imm16, imm32
    //      * imm16 <-> imm16, imm32
    pub fn matchTemplate(template: OperandType, other: OperandType) bool {
        const other_tag = other.getContainerType();
        return switch (template) {
            .rm8 => (other_tag == .rm8 or other_tag == .reg8),
            .rm16 => (other_tag == .rm16 or other_tag == .reg16),
            .rm32 => (other_tag == .rm32 or other_tag == .reg32),
            .rm64 => (other_tag == .rm64 or other_tag == .reg64),
            .imm8 => (other == .imm8 or other == .imm8_any or other == .imm_1),
            .imm16 => (other == .imm16 or other == .imm8_any or other == .imm16_any or other == .imm_1),
            .imm32 => (other == .imm32 or other == .imm8_any or other == .imm16_any or other == .imm32_any or other == .imm_1),
            .imm64 => (other == .imm64 or other == .imm8_any or other == .imm16_any or other == .imm32_any or other == .imm64_any or other == .imm_1),
            else => (template == other or template == other_tag),
        };
    }
};

const MemDispSize = enum {
    None,
    Disp8,
    Disp32,
};

/// Encodes a displacement for memory addressing for 32/64 modes
const MemDisp = union(MemDispSize) {
    None,
    Disp8: u8,
    Disp32: u32,

    pub fn disp(disp_: u32) MemDisp {
        return switch (disp_) {
            0           => MemDisp.None,
            0x01...0xFF => MemDisp.disp8(@intCast(u8, disp_)),
            else        => MemDisp.disp32(disp_),
        };
    }

    pub fn value(self: MemDisp) u32 {
        switch (self) {
            .None => unreachable,
            .Disp8 => return self.Disp8,
            .Disp32 => return self.Disp32,
        }
    }

    pub fn disp8(disp_: u8) MemDisp {
        return MemDisp{ .Disp8 = disp_ };
    }

    pub fn disp32(disp_: u32) MemDisp {
        return MemDisp{ .Disp32 = disp_ };
    }

    pub fn size(self: @This()) MemDispSize {
        return @as(MemDispSize, self);
    }

    pub fn byteSize(self: @This()) u8 {
        return switch (self) {
            .None => 0,
            .Disp8 => 1,
            .Disp32 => 4,
        };
    }
};

const SibScale = enum(u2) {
    Scale1 = 0b00,
    Scale2 = 0b01,
    Scale4 = 0b10,
    Scale8 = 0b11,

    pub fn value(self: @This()) u8 {
        return @as(u8, 1) << @enumToInt(self);
    }

    pub fn toInt(self: @This()) u8 {
        return @enumToInt(self);
    }

    pub fn scale(s: u8) SibScale {
        return switch (s) {
            1 => .Scale1,
            2 => .Scale2,
            4 => .Scale4,
            8 => .Scale8,
            else => unreachable,
        };
    }
};

/// Encodes memory addressing of the form: [r/m + disp]
const Memory = struct {
    reg: Register,
    disp: MemDisp,
    data_size: DataSize,
    segment: Segment,
};

/// Encodes memory addressing using the SIB byte: [(s * index) + base + disp]
const MemorySib = struct {
    scale: SibScale,
    base: ?Register,
    index: ?Register,
    disp: MemDisp,
    data_size: DataSize,
    segment: Segment,
};

const RelRegister = enum {
    EIP,
    RIP,

    pub fn bitSize(self: @This()) BitSize {
        return switch(self) {
            .EIP => .Bit32,
            .RIP => .Bit64,
        };
    }
};

/// Encodes memory addressing relative to RIP/EIP: [RIP + disp] or [EIP + disp]
const RelMemory = struct {
    reg: RelRegister,
    disp: u32,
    data_size: DataSize,
    segment: Segment,

    pub fn relMemory(seg: Segment, data_size: DataSize, reg: RelRegister, disp: u32) RelMemory {
        return RelMemory {
            .reg = reg,
            .disp = disp,
            .data_size = data_size,
            .segment = seg,
        };
    }

};

pub const ModRmResult = struct {
    needs_rex: bool = false,
    needs_no_rex: bool = false,
    prefixes: Prefixes = Prefixes {},
    reg_size: BitSize = .None,
    operand_size: BitSize = .None,
    addressing_size: BitSize = .None,
    rex_w: u1 = 0,
    rex_r: u1 = 0,
    rex_x: u1 = 0,
    rex_b: u1 = 0,
    mod: u2 = 0,
    reg: u3 = 0,
    rm: u3 = 0,
    sib: ?u8 = null,
    disp: MemDisp = MemDisp.None,
    segment: Segment = .DefaultSeg,

    pub fn rexRequirements(self: *@This(), reg: Register, default_size: DefaultSize) void {
        // Don't need to check this if the instruction uses 64 bit by default
        if (!default_size.is64()) {
            self.needs_rex = self.needs_rex or reg.needsRex();
        }
        self.needs_no_rex = self.needs_no_rex or reg.needsNoRex();
    }

    pub fn rex(self: @This(), w: u1) u8 {
        return (
            (0x40)
            | (@as(u8, self.rex_w | w) << 3)
            | (@as(u8, self.rex_r) << 2)
            | (@as(u8, self.rex_x) << 1)
            | (@as(u8, self.rex_b) << 0)
        );
    }

    pub fn modrm(self: @This()) u8 {
        return (
            (@as(u8, self.mod) << 6)
            | (@as(u8, self.reg) << 3)
            | (@as(u8, self.rm ) << 0)
        );
    }
};

/// Encodes an R/M operand
pub const ModRm = union(enum) {
    Reg: Register,
    Mem: Memory,
    Sib: MemorySib,
    Rel: RelMemory,

    pub fn operandSize(self: @This()) BitSize {
        return switch (self) {
            .Reg => |reg| reg.bitSize(),
            .Mem => |mem| mem.data_size.bitSize(),
            .Sib => |sib| sib.data_size.bitSize(),
            .Rel => |reg| reg.data_size.bitSize(),
        };
    }

    pub fn operandDataSize(self: @This()) DataSize {
        return switch (self) {
            .Reg => |reg| reg.dataSize(),
            .Mem => |mem| mem.data_size,
            .Sib => |sib| sib.data_size,
            .Rel => |reg| reg.data_size,
        };
    }

    pub fn operandDataType(self: @This()) DataType {
        return switch (self) {
            .Reg => |reg| DataType.Register,
            .Mem => |mem| mem.data_size.dataType(),
            .Sib => |sib| sib.data_size.dataType(),
            .Rel => |reg| reg.data_size.dataType(),
        };
    }

    pub fn operandType(self: @This()) OperandType {
        return switch (self) {
            .Reg => |reg| switch (reg.size()) {
                .Reg8 => OperandType.rm_reg8,
                .Reg16 => OperandType.rm_reg16,
                .Reg32 => OperandType.rm_reg32,
                .Reg64 => OperandType.rm_reg64,
            },

            .Mem,
            .Sib,
            .Rel => switch (self.operandDataSize()) {
                .None => OperandType.rm_mem,
                .BYTE => OperandType.rm_mem8,
                .WORD => OperandType.rm_mem16,
                .DWORD  => OperandType.rm_mem32,
                .QWORD  => OperandType.rm_mem64,
                .FAR_WORD  => OperandType.m16_16,
                .FAR_DWORD  => OperandType.m16_32,
                .FAR_QWORD  => OperandType.m16_64,
                // TODO:
                else => unreachable,
            },
        };
    }

    pub fn encodeOpcodeRm(self: @This(), mode: Mode86, reg_bits: u3, default_size: DefaultSize) AsmError!ModRmResult {
        const fake_reg = @intToEnum(Register, reg_bits + @enumToInt(Register.AX));
        var res = try self.encodeReg(mode, fake_reg, default_size);
        res.reg_size = .None;
        return res;
    }

    // TODO: probably change the asserts in this function to errors
    pub fn encodeReg(self: @This(), mode: Mode86, modrm_reg: Register, default_size: DefaultSize) AsmError!ModRmResult {
        var res = ModRmResult{};
        res.rex_r = modrm_reg.numberRex();
        res.reg = modrm_reg.numberRm();
        res.reg_size = modrm_reg.bitSize();
        res.rexRequirements(modrm_reg, default_size);
        if (modrm_reg.bitSize() == .Bit64 and !default_size.is64()) {
            res.rex_w = 1;
        }

        switch (self) {
            .Reg => |reg| {
                res.mod = 0b11;

                res.rexRequirements(reg, default_size);
                res.rm = reg.numberRm();
                res.rex_b = reg.numberRex();
                res.operand_size = reg.bitSize();
            },
            .Mem => |mem| {
                // Can't use SP or R12 without a SIB byte since they are used to encode it.
                if ((mem.reg.name() == .SP) or (mem.reg.name() == .R12)){
                    return AsmError.InvalidMemoryAddressing;
                }

                res.operand_size = mem.data_size.bitSize();
                res.addressing_size = mem.reg.bitSize();
                res.segment = mem.segment;

                if (mem.disp.size() != .None)  {
                    // ModRM addressing: [r/m + ]
                    switch (mem.disp) {
                        .Disp8 => res.mod = 0b01,
                        .Disp32 => res.mod = 0b10,
                        .None => unreachable,
                    }
                    res.rm = mem.reg.numberRm();
                    res.rex_b = mem.reg.numberRex();
                    res.disp = mem.disp;
                } else {
                    // ModRM addressing: [r/m]
                    // Can't use BP or R13 and no displacement without a SIB byte
                    // (it is used to encode RIP/EIP relative addressing)
                    if ((mem.reg.name() == .BP) or (mem.reg.name() == .R13)) {
                        return AsmError.InvalidMemoryAddressing;
                    }

                    res.mod = 0b00;
                    res.rm = mem.reg.numberRm();
                    res.rex_b = mem.reg.numberRex();
                }
            },
            .Sib => |sib| {
                var base: u3 = undefined;
                var index: u3 = undefined;
                res.mod = 0b00; // most modes use this value, so set it here
                res.rm = Register.SP.numberRm(); // 0b100, magic value for SIB addressing
                const disp = sib.disp.size();

                res.operand_size = sib.data_size.bitSize();
                res.segment = sib.segment;

                // Check that the base and index registers are valid (if present)
                // and that their sizes match.
                if (sib.base) |base_reg| {
                    res.addressing_size = base_reg.bitSize();
                }
                if (sib.index) |index_reg| {
                    if (res.addressing_size == .None) {
                        res.addressing_size = index_reg.bitSize();
                    } else {
                        if (res.addressing_size != index_reg.bitSize()) {
                            return AsmError.InvalidMemoryAddressing;
                        }
                    }
                }

                if (sib.base != null and sib.index != null and disp != .None) {
                    // SIB addressing: [base + (index * scale) + disp8/32]
                    if (sib.index.?.name() == .SP) {
                        return AsmError.InvalidMemoryAddressing;
                    }

                    switch (disp) {
                        .Disp8  => res.mod = 0b01,
                        .Disp32 => res.mod = 0b10,
                        else => unreachable,
                    }
                    // encode the base
                    base = sib.base.?.numberRm();
                    res.rex_b = sib.base.?.numberRex();
                    // encode the index
                    index = sib.index.?.numberRm();
                    res.rex_x = sib.index.?.numberRex();
                    // encode displacement
                    res.disp = sib.disp;
                } else if (sib.base != null and sib.index == null and disp != .None) {
                    // SIB addressing: [base + disp8/32]
                    const magic_index = Register.SP;

                    switch (disp) {
                        .Disp8  => res.mod = 0b01,
                        .Disp32 => res.mod = 0b10,
                        else => unreachable,
                    }
                    // encode the base
                    base = sib.base.?.numberRm();
                    res.rex_b = sib.base.?.numberRex();
                    // encode magic index
                    index = magic_index.numberRm();
                    res.rex_x = magic_index.numberRex();
                    // encode displacement
                    res.disp = sib.disp;
                } else if (disp == .None and sib.index != null and sib.base != null) {
                    // SIB addressing: [base + (index * s)]
                    if ((sib.base.?.name() == .BP) or (sib.base.?.name() == .R13)) {
                        return AsmError.InvalidMemoryAddressing;
                    }

                    base = sib.base.?.numberRm();
                    res.rex_b = sib.base.?.numberRex();
                    index = sib.index.?.numberRm();
                    res.rex_x = sib.index.?.numberRex();
                } else if (disp == .Disp32 and sib.index != null and sib.base == null) {
                    // SIB addressing: [(index * s) + disp32]
                    if (sib.index.?.name() == .SP) {
                        return AsmError.InvalidMemoryAddressing;
                    }
                    const magic_base = switch (0) {
                        0 => Register.BP,
                        1 => Register.R13,
                        else => unreachable,
                    };

                    base = magic_base.numberRm();
                    res.rex_b = magic_base.numberRex();
                    index = sib.index.?.numberRm();
                    res.rex_x = sib.index.?.numberRex();
                    res.disp = sib.disp;
                } else if (disp == .None and sib.index == null and sib.base != null) {
                    // SIB addressing: [base]
                    // NOTE: illegal to use BP or R13 as the base
                    if ((sib.base.?.name() == .BP) or (sib.base.?.name() == .R13)){
                        return AsmError.InvalidMemoryAddressing;
                    }
                    const magic_index = Register.SP;

                    base = sib.base.?.numberRm();
                    res.rex_b = sib.base.?.numberRex();
                    index = magic_index.numberRm();
                    res.rex_x = magic_index.numberRex();
                } else if (disp == .Disp32 and sib.index == null and sib.base == null) {
                    // SIB addressing: [disp32]
                    const magic_index = Register.SP;
                    const magic_base = switch (0) {
                        0 => Register.BP,
                        1 => Register.R13,
                        else => unreachable,
                    };

                    base = magic_base.numberRm();
                    res.rex_b = magic_base.numberRex();
                    index = magic_index.numberRm();
                    res.rex_x = magic_index.numberRex();
                    res.disp = sib.disp;
                } else {
                    // other forms are impossible to encode on x86
                    unreachable;
                }

                res.sib = (
                    (@as(u8, sib.scale.toInt()) << 6)
                    | (@as(u8, index) << 3)
                    | (@as(u8, base)  << 0)
                );
            },
            .Rel => |rel| {
                res.mod = 0b00;

                // NOTE: We can use either SP or R13 for relative addressing.
                // We use SP here because it works for both 32/64 bit.
                const tmp_reg = switch (0) {
                    0 => Register.BP,
                    1 => Register.R13,
                    else => unreachable,
                };

                res.rm = tmp_reg.numberRm();
                res.rex_b = tmp_reg.numberRex();

                res.segment = rel.segment;
                res.disp = MemDisp.disp32(rel.disp);
                res.operand_size = rel.data_size.bitSize();
                res.addressing_size = switch (rel.reg) {
                    .EIP => .Bit32,
                    .RIP => .Bit64,
                };
            },
        }

        if (res.segment != .DefaultSeg) {
            res.prefixes.addSegmentOveride(res.segment);
        }

        try res.prefixes.addOverides(
            mode, &res.rex_w, res.operand_size, res.addressing_size, default_size
        );

        return res;
    }

    pub fn register(reg: Register) ModRm {
        return ModRm { .Reg = reg };
    }

    pub fn relMemory(seg: Segment, data_size: DataSize, reg: RelRegister, disp: u32) ModRm {
        return ModRm { .Rel = RelMemory.relMemory(seg, data_size, reg, disp) };
    }

    /// data_size [reg + disp]
    pub fn memoryRm(seg: Segment, data_size: DataSize, reg: Register, disp: u32) ModRm {
        return ModRm {
            .Mem = Memory {
                .reg = reg,
                .disp = MemDisp.disp(disp),
                .data_size = data_size,
                .segment = seg,
            }
        };
    }

    /// data_size [reg + disp8]
    pub fn memoryRm8(seg: Segment, data_size: DataSize, reg: Register, disp: u8) ModRm {
        return ModRm {
            .Mem = Memory {
                .reg = reg,
                .disp = MemDisp.disp8(disp),
                .data_size = data_size,
                .segment = seg,
            }
        };
    }

    /// data_size [reg + disp32]
    pub fn memoryRm32(seg: Segment, data_size: DataSize, reg: Register, disp: u32) ModRm {
        return ModRm {
            .Mem = Memory {
                .reg = reg,
                .disp = MemDisp.disp32(disp),
                .data_size = data_size,
                .segment = seg,
            }
        };
    }

    /// data_size [(scale*index) + base + disp8]
    pub fn memorySib8(seg: Segment, data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp8: u8) ModRm {
        return ModRm {
            .Sib = MemorySib {
                .scale = SibScale.scale(scale),
                .index = index,
                .base = base,
                .disp = MemDisp.disp8(disp8),
                .data_size = data_size,
                .segment = seg,
            }
        };
    }

    /// data_size [(scale*index) + base + disp32]
    pub fn memorySib32(seg: Segment, data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp32: u32) ModRm {
        return ModRm {
            .Sib = MemorySib {
                .scale = SibScale.scale(scale),
                .index = index,
                .base = base,
                .disp = MemDisp.disp32(disp32),
                .data_size = data_size,
                .segment = seg,
            }
        };
    }

    /// data_size [(scale*index) + base + disp]
    pub fn memorySib(seg: Segment, data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp: u32) ModRm {
        // When base is not used, only 32bit diplacements are valid
        const mem_disp = if (base == null) x: {
            break :x MemDisp.disp32(disp);
        } else x: {
            break :x MemDisp.disp(disp);
        };

        return ModRm {
            .Sib = MemorySib {
                .scale = SibScale.scale(scale),
                .index = index,
                .base = base,
                .disp = mem_disp,
                .data_size = data_size,
                .segment = seg,
            }
        };
    }

    pub fn format(
        self: ModRm,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        context: var,
        comptime FmtError: type,
        output: fn (@TypeOf(context), []const u8) FmtError!void,
    ) FmtError!void {
        switch (self) {
            .Reg => |reg| {
                try output(context, "RM.");
                try output(context, @tagName(reg));
            },
            .Mem => |mem| {
                try output(context, @tagName(mem.data_size));
                try output(context, " [");
                if (mem.segment != .DefaultSeg) {
                    try output(context, @tagName(mem.segment));
                    try output(context, ": ");
                }
                try output(context, @tagName(mem.reg));
                if (mem.disp !=  .None) {
                    try output(context, " + ");
                    try std.fmt.format(context, FmtError, output, "0x{x}", .{mem.disp.value()});
                }
                try output(context, "]");
            },
            .Sib => |sib| {
                try output(context, @tagName(sib.data_size));
                try output(context, " [");
                if (sib.segment != .DefaultSeg) {
                    try output(context, @tagName(sib.segment));
                    try output(context, ": ");
                }
                if (sib.index) |index| {
                    try std.fmt.format(context, FmtError, output, "{}*{}", .{sib.scale.value(), @tagName(index)});
                    if (sib.base != null or sib.disp != .None) {
                        try output(context, " + ");
                    }
                }
                if (sib.base) |base| {
                    try output(context, @tagName(base));
                    if (sib.disp != .None) {
                        try output(context, " + ");
                    }
                }
                if (sib.disp !=  .None) {
                    try std.fmt.format(context, FmtError, output, "0x{x}", .{sib.disp.value()});
                }
                try output(context, "]");
            },
            .Rel => |rel| {
                try output(context, @tagName(rel.data_size));
                try output(context, " [");
                if (rel.segment != .DefaultSeg) {
                    try output(context, @tagName(rel.segment));
                    try output(context, ": ");
                }
                try output(context, @tagName(rel.reg));
                try output(context, " + ");
                try std.fmt.format(context, FmtError, output, "0x{x}", .{rel.disp});
                try output(context, "]");
            },
            else => {},
        }
    }
};

pub const MOffsetDisp = union(enum) {
    Disp16: u16,
    Disp32: u32,
    Disp64: u64,

    pub fn bitSize(self: MOffsetDisp) BitSize {
        return switch (self) {
            .Disp16 => .Bit16,
            .Disp32 => .Bit32,
            .Disp64 => .Bit64,
        };
    }

    pub fn value(self: MOffsetDisp) u64 {
        return switch (self) {
            .Disp16 => |dis| dis,
            .Disp32 => |dis| dis,
            .Disp64 => |dis| dis,
        };
    }
};

pub const MemoryOffsetFarJmp = struct {
    addr: MOffsetDisp,
    segment: u16,
    operand_size: DataSize,
};

pub const MemoryOffset = struct {
    disp: MOffsetDisp,
    segment: Segment,
    operand_size: DataSize,
};

pub const Address = union(enum) {
    MOffset: MemoryOffset,
    FarJmp: MemoryOffsetFarJmp,

    pub fn getDisp(self: Address) MOffsetDisp {
        return switch (self) {
            .FarJmp => |far| far.addr,
            .MOffset => |moff| moff.disp,
        };
    }

    pub fn operandType(self: Address) OperandType {
        return switch (self) {
            .MOffset => |moff| switch (moff.operand_size.bitSize()) {
                .Bit8 => OperandType.moffs8,
                .Bit16 => OperandType.moffs16,
                .Bit32 => OperandType.moffs32,
                .Bit64 => OperandType.moffs64,
                else => unreachable,
            },
            .FarJmp => switch(self.getDisp().bitSize()) {
                .Bit16 => OperandType.ptr16_16,
                .Bit32 => OperandType.ptr16_32,
                else => unreachable,
            },
        };
    }

    pub fn operandSize(self: Address) BitSize {
        return self.operandDataSize().bitSize();
    }

    pub fn operandDataSize(self: Address) DataSize {
        return switch (self) {
            .MOffset => |moff| moff.operand_size,
            .FarJmp => |far| far.operand_size,
        };
    }

    pub fn moffset16(seg: Segment, size: DataSize, disp: u16) Address {
        return Address {
            .MOffset = MemoryOffset {
                .disp = MOffsetDisp { .Disp16 = disp },
                .segment = seg,
                .operand_size = size,
            }
        };
    }

    pub fn moffset32(seg: Segment, size: DataSize, disp: u32) Address {
        return Address {
            .MOffset = MemoryOffset {
                .disp = MOffsetDisp { .Disp32 = disp },
                .segment = seg,
                .operand_size = size,
            }
        };
    }

    pub fn moffset64(seg: Segment, size: DataSize, disp: u64) Address {
        return Address {
            .MOffset = MemoryOffset {
                .disp = MOffsetDisp { .Disp64 = disp },
                .segment = seg,
                .operand_size = size,
            }
        };
    }

    pub fn far16(seg: u16, size: DataSize, addr: u16) Address {
        return Address {
            .FarJmp = MemoryOffsetFarJmp {
                .addr = MOffsetDisp { .Disp16 = addr },
                .segment = seg,
                .operand_size = size,
            }
        };
    }

    pub fn far32(seg: u16, size: DataSize, addr: u32) Address {
        return Address {
            .FarJmp = MemoryOffsetFarJmp {
                .addr = MOffsetDisp { .Disp32 = addr },
                .segment = seg,
                .operand_size = size,
            }
        };
    }

    pub fn format(
        self: Address,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        context: var,
        comptime FmtError: type,
        output: fn (@TypeOf(context), []const u8) FmtError!void,
    ) FmtError!void {
        switch (self) {
            .MOffset => |moff| {
                try std.fmt.format(context, FmtError, output, "{}:0x{x}", .{@tagName(moff.segment), moff.disp.value()});
            },
            .FarJmp => |far| {
                try std.fmt.format(context, FmtError, output, "0x{x}:0x{x}", .{far.segment, far.addr.value()});
            },
            else => {},
        }
    }
};

pub const ImmediateSize = enum(u8) {
    const strict_flag: u8 = 0x10;
    const size_mask: u8 = 0x03;
    Imm8_any = 0x00,
    Imm16_any = 0x01,
    Imm32_any = 0x02,
    Imm64_any = 0x03,
    Imm8 = 0x00  | strict_flag,
    Imm16 = 0x01 | strict_flag,
    Imm32 = 0x02 | strict_flag,
    Imm64 = 0x03 | strict_flag,
};

pub const ImmediateSign = enum (u1) {
    Unsigned = 0,
    Signed = 1,
};

/// Encodes an immediate value
pub const Immediate = struct {
    size: ImmediateSize,
    _value: u64,
    sign: ImmediateSign = .Unsigned,

    pub fn value(self: Immediate) u64 {
        return self._value;
    }

    pub fn isStrict(self: Immediate) bool {
        return (@enumToInt(self.size) & ImmediateSize.strict_flag) != 0;
    }

    pub fn bitSize(self: Immediate) BitSize {
        const size: u8 = @enumToInt(self.size) & ImmediateSize.size_mask;
        return @intToEnum(BitSize, @as(u8,1) << (@intCast(u3,size)));
    }

    pub fn dataSize(self: Immediate) DataSize {
        return DataSize.fromByteValue(self.bitSize().valueBytes());
    }

    pub fn as8(self: Immediate) u8 {
        std.debug.assert(self.bitSize() == .Bit8);
        return @intCast(u8, self._value);
    }

    pub fn as16(self: Immediate) u16 {
        std.debug.assert(self.bitSize() == .Bit16);
        return @intCast(u16, self._value);
    }

    pub fn as32(self: Immediate) u32 {
        std.debug.assert(self.bitSize() == .Bit32);
        return @intCast(u32, self._value);
    }

    pub fn as64(self: Immediate) u64 {
        std.debug.assert(self.bitSize() == .Bit64);
        return self._value;
    }

    pub fn willSignExtend(self: Immediate, op_type: OperandType) bool {
        switch (op_type) {
            .imm8_any, .imm8 => return  (self._value & 0x80) != 0,
            .imm16_any, .imm16 => return (self._value & 0x8000) != 0,
            .imm32_any, .imm32 => return (self._value & 0x80000000) != 0,
            .imm64_any, .imm64 => return false,
            else => return false,
        }
    }

    pub fn coerce(self: Immediate, bit_size: BitSize) Immediate {
        switch (bit_size) {
            .Bit8  => return Immediate.imm8(self.sign, @intCast(u8, self._value)),
            .Bit16 => return Immediate.imm16(self.sign, @intCast(u16, self._value)),
            .Bit32 => return Immediate.imm32(self.sign, @intCast(u32, self._value)),
            .Bit64 => return Immediate.imm64(self.sign, @intCast(u64, self._value)),
            else => unreachable,
        }
    }

    pub fn immSigned(im: i64) Immediate {
        const minInt = std.math.minInt;
        const maxInt = std.math.maxInt;

        if (minInt(i8) <= im and im <= maxInt(i8)) {
            return Immediate {
                .size = .Imm8_any,
                ._value = @bitCast(u64, im) & 0xff,
                .sign = .Signed,
            };
        } else if (minInt(i16) <= im and im <= maxInt(i16)) {
            return Immediate {
                .size = .Imm16_any,
                ._value = @bitCast(u64, im) & 0xffff,
                .sign = .Signed,
            };
        } else if (minInt(i32) <= im and im <= maxInt(i32)) {
            return Immediate {
                .size = .Imm32_any,
                ._value = @bitCast(u64, im) & 0xffffffff,
                .sign = .Signed,
            };
        } else {
            return Immediate {
                .size = .Imm64_any,
                ._value = @bitCast(u64, im),
                .sign = .Signed,
            };
        }
    }

    pub fn immUnsigned(im : u64) Immediate {
        const maxInt = std.math.maxInt;

        if (im <= maxInt(u8)) {
            return Immediate {
                .size = .Imm8_any,
                ._value = im & 0xff,
                .sign = .Unsigned,
            };
        } else if (im <= maxInt(u16)) {
            return Immediate {
                .size = .Imm16_any,
                ._value = im & 0xffff,
                .sign = .Unsigned,
            };
        } else if (im <= maxInt(u32)) {
            return Immediate {
                .size = .Imm32_any,
                ._value = im & 0xffffffff,
                .sign = .Unsigned,
            };
        } else {
            return Immediate {
                .size = .Imm64_any,
                ._value = im,
                .sign = .Unsigned,
            };
        }
    }

    pub fn imm8(sign: ImmediateSign, im: u8) Immediate {
        return Immediate {
            .size = .Imm8,
            ._value = im,
            .sign = sign,
        };
    }

    pub fn imm16(sign: ImmediateSign, im: u16) Immediate {
        return Immediate {
            .size = .Imm16,
            ._value = im,
            .sign = sign,
        };
    }

    pub fn imm32(sign: ImmediateSign, im: u32) Immediate {
        return Immediate {
            .size = .Imm32,
            ._value = im,
            .sign = sign,
        };
    }

    pub fn imm64(sign: ImmediateSign, im: u64) Immediate {
        return Immediate {
            .size = .Imm64,
            ._value = im,
            .sign = sign,
        };
    }
};

pub const VoidOperand = struct {
    operand_size: DataSize,
};

pub const RegisterSpecialOperand = struct {
    register: RegisterSpecial,
    /// Overides the default size of the register
    operand_size: DataSize,
};

pub const OperandTag = enum {
    None,
    Reg,
    Imm,
    Rm,
    RegSpecial,
    Addr,
};

pub const Operand = union(OperandTag) {
    None: VoidOperand,
    Reg: Register,
    Imm: Immediate,
    Rm: ModRm,
    RegSpecial: RegisterSpecialOperand,
    Addr: Address,

    pub fn tag(self: Operand) OperandTag {
        return @as(OperandTag, self);
    }

    pub fn operandType(self: Operand) OperandType {
        switch (self) {
            .Reg => |reg| return OperandType.fromRegister(reg),
            .Imm => |imm_| return OperandType.fromImmediate(imm_),
            .Rm => |rm| return rm.operandType(),
            .RegSpecial => |sreg| return OperandType.fromRegisterSpecial(sreg.register),
            .Addr => |addr| return addr.operandType(),
            // TODO: get size
            .None => return OperandType._void,
            else => unreachable,
        }
    }

    pub fn operandSize(self: Operand) BitSize {
        switch (self) {
            .Reg => |reg| return reg.bitSize(),
            .Imm => |imm_| return (imm_.bitSize()),
            .Rm => |rm| return rm.operandSize(),
            .RegSpecial => |sreg| {
                if (sreg.operand_size == .Default) {
                    return sreg.register.bitSize();
                } else {
                    return sreg.operand_size.bitSize();
                }
            },
            .Addr => |addr| return addr.operandSize(),
            .None => |none| return none.operand_size.bitSize(),
        }
    }

    /// If the operand has a size overide get it instead of the underlying
    /// operand size.
    pub fn operandDataSize(self: Operand) DataSize {
        switch (self) {
            .Reg => |reg| return reg.dataSize(),
            .Imm => |imm_| return (imm_.dataSize()),
            .Rm => |rm| return rm.operandDataSize(),
            .RegSpecial => |sreg| return sreg.operand_size,
            .Addr => |addr| return addr.operandDataSize(),
            .None => |none| return none.operand_size,
        }
    }

    /// If the operand is a .Reg, convert it to the equivalent .Rm
    pub fn coerceRm(self: Operand) Operand {
        switch (self) {
            .Reg => |reg| return Operand.registerRm(reg),
            .Rm => return self,
            else => unreachable,
        }
    }

    pub fn register(reg: Register) Operand {
        return Operand { .Reg = reg };
    }

    pub fn registerRm(reg: Register) Operand {
        return Operand { .Rm = ModRm.register(reg) };
    }

    pub fn registerSpecial(reg: RegisterSpecial) Operand {
        return Operand {
            .RegSpecial = RegisterSpecialOperand {
                .register = reg,
                .operand_size = .Default,
            }
        };
    }

    pub fn registerSpecialSized(data_size: DataSize, reg: RegisterSpecial) Operand {
        return Operand {
            .RegSpecial = RegisterSpecialOperand {
                .register = reg,
                .operand_size = data_size,
            }
        };
    }

    pub fn voidOperand(data_size: DataSize) Operand {
        return Operand { .None = VoidOperand { .operand_size = data_size } };
    }

    pub fn immediate(im: u64) Operand {
        return Operand { .Imm = Immediate.immUnsigned(im) };
    }

    pub fn immediate8(im: u8) Operand {
        return Operand { .Imm = Immediate.imm8(.Unsigned, im) };
    }
    pub fn immediate16(im: u16) Operand {
        return Operand { .Imm = Immediate.imm16(.Unsigned, im) };
    }
    pub fn immediate32(im: u32) Operand {
        return Operand { .Imm = Immediate.imm32(.Unsigned, im) };
    }
    pub fn immediate64(im: u64) Operand {
        return Operand { .Imm = Immediate.imm64(.Unsigned, im) };
    }

    pub fn immediateSigned(im: i64) Operand {
        return Operand { .Imm = Immediate.immSigned(im) };
    }

    pub fn immediateSigned8(im: i8) Operand {
        return Operand { .Imm = Immediate.imm8(.Signed, @bitCast(u8, im)) };
    }
    pub fn immediateSigned16(im: i16) Operand {
        return Operand { .Imm = Immediate.imm16(.Signed, @bitCast(u16, im)) };
    }
    pub fn immediateSigned32(im: i32) Operand {
        return Operand { .Imm = Immediate.imm32(.Signed, @bitCast(u32, im)) };
    }
    pub fn immediateSigned64(im: i64) Operand {
        return Operand { .Imm = Immediate.imm64(.Signed, @bitCast(u64, im)) };
    }

    pub fn memory(seg: Segment, data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp: u32) Operand {
        var modrm: ModRm = undefined;
        if (index == null and base != null) edge_case: {
            const reg_name = base.?.name();

            // These are the edge cases that we won't be able to encode
            if (reg_name == .SP) { break :edge_case; }
            if (reg_name == .R12) { break :edge_case; }
            if (reg_name == .BP and disp == 0) { break :edge_case; }
            if (reg_name == .R13 and disp == 0) { break :edge_case; }

            return Operand { .Rm = ModRm.memoryRm(seg, data_size, base.?, disp) };
        }

        return Operand { .Rm = ModRm.memorySib(seg, data_size, scale, index, base, disp) };
    }

    pub fn memoryRm(seg: Segment, data_size: DataSize, reg: Register, disp: u32) Operand {
        return Operand { .Rm = ModRm.memoryRm(seg, data_size, reg, disp) };
    }

    pub fn memorySib(seg: Segment, data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp: u32) Operand {
        return Operand { .Rm = ModRm.memorySib(seg, data_size, scale, index, base, disp) };
    }

    pub fn relMemory(seg: Segment, data_size: DataSize, reg: RelRegister, disp: u32) Operand {
        return Operand { .Rm = ModRm.relMemory(seg, data_size, reg, disp) };
    }

    pub fn moffset16(seg: Segment, size: DataSize, disp: u16) Operand {
        return Operand { .Addr = Address.moffset16(seg, size, disp) };
    }

    pub fn moffset32(seg: Segment, size: DataSize, disp: u32) Operand {
        return Operand { .Addr = Address.moffset32(seg, size, disp) };
    }

    pub fn moffset64(seg: Segment, size: DataSize, disp: u64) Operand {
        return Operand { .Addr = Address.moffset64(seg, size, disp) };
    }

    // pub fn far16(seg: u16, size: DataSize, addr: u16) Operand {
    pub fn far16(seg: u16, addr: u16) Operand {
        return Operand { .Addr = Address.far16(seg, .Default, addr) };
    }

    pub fn far32(seg: u16, addr: u32) Operand {
        return Operand { .Addr = Address.far32(seg, .Default, addr) };
    }


    /// fn format(value: ?, comptime fmt: []const u8, options: std.fmt.FormatOptions, context: var, comptime Errors: type, output: fn (@TypeOf(context), []const u8) Errors!void) Errors!void
    pub fn format(
        self: Operand,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        context: var,
        comptime FmtError: type,
        output: fn (@TypeOf(context), []const u8) FmtError!void,
    ) FmtError!void {
        // self.assertWritable();
        // TODO look at fmt and support other bases
        // TODO support read-only fixed integers
        switch (self) {
            .Reg => |reg| try output(context, @tagName(reg)),
            .Rm => |rm| try rm.format(fmt, options, context, FmtError, output),
            .Imm => |im| {
                try std.fmt.format(context, FmtError, output, "0x{x}", .{im.value()});
            },
            .RegSpecial => |reg| {
                if (reg.operand_size != .Default) {
                    try output(context, @tagName(reg.operand_size));
                    try output(context, " ");
                }
                try output(context, @tagName(reg.register));
            },
            .Addr => |addr| {
                if (addr.operandDataSize() != .Default) {
                    try output(context, @tagName(addr.operandDataSize()));
                    try output(context, " ");
                }
                try addr.format(fmt, options, context, FmtError, output);
            },
            else => {},
        }
    }
};

test "ModRm Encoding" {
    const testing = std.testing;
    const warn = if (true) std.debug.warn else util.warnDummy;
    const expect = testing.expect;

    {
        const modrm = ModRm.register(.RAX);
        const result = try modrm.encodeOpcodeRm(.x64, 0, .RM32);
        expect(result.rex(0)  == 0b01001000);
        expect(result.rex(1)  == 0b01001000);
        expect(result.modrm() == 0b11000000);
        expect(result.sib == null);
        expect(result.disp == .None);
    }

    {
        const modrm = ModRm.register(.R15);
        const result = try modrm.encodeReg(.x64, .R9, .RM32);
        expect(result.rex(0)  == 0b01001101);
        expect(result.rex(1)  == 0b01001101);
        expect(result.modrm() == 0b11001111);
        expect(result.sib == null);
        expect(result.disp == .None);
        expect(result.prefixes.len == 0);
    }

    {
        const modrm = ModRm.relMemory(.DefaultSeg, .DWORD, .EIP, 0x76543210);
        const result = try modrm.encodeReg(.x64, .R8, .RM32);
        expect(result.rex(0)  == 0b01001100);
        expect(result.rex(1)  == 0b01001100);
        expect(result.modrm() == 0b00000101);
        expect(result.sib == null);
        expect(result.disp.Disp32 == 0x76543210);
        expect(std.mem.eql(u8, result.prefixes.asSlice(), &[_]u8{0x67}));
    }

    {
        const modrm = ModRm.relMemory(.DefaultSeg, .QWORD, .RIP, 0x76543210);
        const result = try modrm.encodeReg(.x64, .R8, .RM32);
        expect(result.rex(0)  == 0b01001100);
        expect(result.rex(1)  == 0b01001100);
        expect(result.modrm() == 0b00000101);
        expect(result.sib == null);
        expect(result.disp.Disp32 == 0x76543210);
        expect(result.prefixes.len == 0);
    }

    {
        const modrm = ModRm.memoryRm(.DefaultSeg, .QWORD, .R9, 0x0);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(0)  == 0b01001001);
        expect(result.rex(1)  == 0b01001001);
        expect(result.modrm() == 0b00000001);
        expect(result.sib == null);
        expect(result.disp == .None);
    }

    {
        const modrm = ModRm.memoryRm(.DefaultSeg, .QWORD, .R9, 0x10);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(0)  == 0b01001001);
        expect(result.rex(1)  == 0b01001001);
        expect(result.modrm() == 0b01000001);
        expect(result.sib == null);
        expect(result.disp.Disp8 == 0x10);
    }

    {
        const modrm = ModRm.memoryRm(.DefaultSeg, .QWORD, .R9, 0x76543210);
        const result = try modrm.encodeReg(.x64, .R15, .RM32);
        expect(result.rex(0)  == 0b01001101);
        expect(result.rex(1)  == 0b01001101);
        expect(result.modrm() == 0b10111001);
        expect(result.sib == null);
        expect(result.disp.Disp32 == 0x76543210);
    }

    // [2*R15 + R15 + 0x10]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 2, .R15, .R15, 0x10);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001011);
        expect(result.modrm() == 0b01000100);
        expect(result.sib.? == 0b01111111);
        expect(result.disp.Disp8 == 0x10);
    }

    // [2*R15 + R15 + 0x76543210]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 1, .R15, .R15, 0x76543210);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001011);
        expect(result.modrm() == 0b10000100);
        expect(result.sib.? == 0b00111111);
        expect(result.disp.Disp32 == 0x76543210);
    }

    // [R15 + 0x10]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 2, null, .R15, 0x10);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001001);
        expect(result.modrm() == 0b01000100);
        expect(result.sib.? == 0b01100111);
        expect(result.disp.Disp8 == 0x10);
    }

    // [R15 + 0x3210]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 2, null, .R15, 0x3210);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001001);
        expect(result.modrm() == 0b10000100);
        expect(result.sib.? == 0b01100111);
        expect(result.disp.Disp32 == 0x3210);
    }

    // [4*R15 + R15]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 4, .R15, .R15, 0x00);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001011);
        expect(result.modrm() == 0b00000100);
        expect(result.sib.? == 0b10111111);
        expect(result.disp == .None);
    }

    // [4*R15 + 0x10]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 4, .R15, null, 0x10);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001010);
        expect(result.modrm() == 0b00000100);
        expect(result.sib.? == 0b10111101);
        expect(result.disp.Disp32 == 0x10);
    }

    // [0x10]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 8, null, null, 0x10);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001000);
        expect(result.modrm() == 0b00000100);
        expect(result.sib.? == 0b11100101);
        expect(result.disp.Disp32 == 0x10);
    }

    // [R15]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 4, null, .R15, 0x00);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001001);
        expect(result.modrm() == 0b00000100);
        expect(result.sib.? == 0b10100111);
        expect(result.disp == .None);
    }
}
