const std = @import("std");
const assert = std.debug.assert;
usingnamespace(@import("types.zig"));

// When we want to refer to a register but don't care about it's bit size
pub const RegisterName = enum (u8) {
    AX = 0x00,
    CX,
    DX,
    BX,
    SP,
    BP,
    SI,
    DI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15 = 0x0F,
};

pub const RegisterType = enum(u16) {
    General = 0x0000,
    Segment = 0x0800,
    Float = 0x0F00,
    Control = 0x1000,
    Debug = 0x1100,
    MMX = 0x1700,
    XMM = 0x1800,
    YMM = 0x1900,
    ZMM = 0x1A00,
    Mask = 0x1F00,
};

/// Special control and debug registers
pub const Register = enum (u16) {
    const tag_mask = 0xFF00;
    const tag_general = @enumToInt(RegisterType.General);
    const tag_segment = @enumToInt(RegisterType.Segment);
    const tag_float = @enumToInt(RegisterType.Float);
    const tag_control = @enumToInt(RegisterType.Control);
    const tag_debug = @enumToInt(RegisterType.Debug);
    const tag_mmx = @enumToInt(RegisterType.MMX);
    const tag_xmm = @enumToInt(RegisterType.XMM);
    const tag_ymm = @enumToInt(RegisterType.YMM);
    const tag_zmm = @enumToInt(RegisterType.ZMM);
    const tag_mask_reg = @enumToInt(RegisterType.Mask);

    // We use special format for these registers:
    // u8: .RSSNNNN
    //
    // N: register number
    // S: size (1 << 0bSS) bytes
    // R: needs REX prefix
    // .: unused

    const rex_flag: u8 = 0x40;
    const gpr_size_mask: u8 = 0x30;
    AL = 0x00 | tag_general,
    CL,
    DL,
    BL,
    AH, // becomes SPL when using REX prefix
    CH, // becomes BPL when using REX prefix
    DH, // becomes SIL when using REX prefix
    BH, // becomes DIL when using REX prefix
    R8B,
    R9B,
    R10B,
    R11B,
    R12B,
    R13B,
    R14B,
    R15B = 0x0F | tag_general,

    // 16 bit registers
    AX = 0x10 | tag_general,
    CX,
    DX,
    BX,
    SP,
    BP,
    SI,
    DI,
    R8W,
    R9W,
    R10W,
    R11W,
    R12W,
    R13W,
    R14W,
    R15W = 0x1F | tag_general,

    // 32 bit registers
    EAX = 0x20 | tag_general,
    ECX,
    EDX,
    EBX,
    ESP,
    EBP,
    ESI,
    EDI,
    R8D,
    R9D,
    R10D,
    R11D,
    R12D,
    R13D,
    R14D,
    R15D = 0x2F | tag_general,

    // We use a flag 0x80 to mark registers that require REX prefix
    // 64 bit register
    RAX = 0x30 | rex_flag | tag_general,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15 = 0x3F | rex_flag | tag_general,

    // special 8 bit registers added in x86-64:
    SPL = 0x04 | rex_flag | tag_general, // would be AH without REX flag
    BPL = 0x05 | rex_flag | tag_general, // would be CH without REX flag
    SIL = 0x06 | rex_flag | tag_general, // would be DH without REX flag
    DIL = 0x07 | rex_flag | tag_general, // would be BH without REX flag

    // Segment registers
    ES = 0x00 | tag_segment,
    CS,
    SS,
    DS,
    FS,
    GS = 0x05 | tag_segment,

    /// Segment registers with extension bit set in REX
    /// These registers are identical to the other segment registers, but we
    /// include them for completness.
    ES_ = 0x08 | tag_segment,
    CS_,
    SS_,
    DS_,
    FS_,
    GS_ = 0x0d | tag_segment,

    ST0 = 0x00 | tag_float,
    ST1,
    ST2,
    ST3,
    ST4,
    ST5,
    ST6,
    ST7 = 0x07 | tag_float,
    // ST0_ = 0x18 | tag_float,
    // ST1_,
    // ST2_,
    // ST3_,
    // ST4_,
    // ST5_,
    // ST6_,
    // ST7_ = 0x1F | tag_float,

    MM0 = 0x00 | tag_mmx,
    MM1,
    MM2,
    MM3,
    MM4,
    MM5,
    MM6,
    MM7,
    MM0_,
    MM1_,
    MM2_,
    MM3_,
    MM4_,
    MM5_,
    MM6_,
    MM7_ = 0x0F | tag_mmx,

    // Most of these are not valid to use, but keep them for completeness
    CR0 = 0x00 | tag_control,
    CR1,
    CR2,
    CR3,
    CR4,
    CR5,
    CR6,
    CR7,
    CR8,
    CR9,
    CR10,
    CR11,
    CR12,
    CR13,
    CR14,
    CR15 = 0x0F | tag_control,

    // Most of these are not valid to use, but keep them for completeness
    DR0 = 0x00 | tag_debug,
    DR1,
    DR2,
    DR3,
    DR4,
    DR5,
    DR6,
    DR7,
    DR8,
    DR9,
    DR10,
    DR11,
    DR12,
    DR13,
    DR14,
    DR15 = 0x0F | tag_debug,

    XMM0 = 0x00 | tag_xmm,
    XMM1,
    XMM2,
    XMM3,
    XMM4,
    XMM5,
    XMM6,
    XMM7,
    XMM8,
    XMM9,
    XMM10,
    XMM11,
    XMM12,
    XMM13,
    XMM14,
    XMM15,
    XMM16,
    XMM17,
    XMM18,
    XMM19,
    XMM20,
    XMM21,
    XMM22,
    XMM23,
    XMM24,
    XMM25,
    XMM26,
    XMM27,
    XMM28,
    XMM29,
    XMM30,
    XMM31 = 0x1F | tag_xmm,

    YMM0 = 0x00 | tag_ymm,
    YMM1,
    YMM2,
    YMM3,
    YMM4,
    YMM5,
    YMM6,
    YMM7,
    YMM8,
    YMM9,
    YMM10,
    YMM11,
    YMM12,
    YMM13,
    YMM14,
    YMM15,
    YMM16,
    YMM17,
    YMM18,
    YMM19,
    YMM20,
    YMM21,
    YMM22,
    YMM23,
    YMM24,
    YMM25,
    YMM26,
    YMM27,
    YMM28,
    YMM29,
    YMM30,
    YMM31 = 0x1F | tag_ymm,

    ZMM0 = 0x00 | tag_zmm,
    ZMM1,
    ZMM2,
    ZMM3,
    ZMM4,
    ZMM5,
    ZMM6,
    ZMM7,
    ZMM8,
    ZMM9,
    ZMM10,
    ZMM11,
    ZMM12,
    ZMM13,
    ZMM14,
    ZMM15,
    ZMM16,
    ZMM17,
    ZMM18,
    ZMM19,
    ZMM20,
    ZMM21,
    ZMM22,
    ZMM23,
    ZMM24,
    ZMM25,
    ZMM26,
    ZMM27,
    ZMM28,
    ZMM29,
    ZMM30,
    ZMM31 = 0x1F | tag_zmm,

    K0 = 0x00 | tag_mask_reg,
    K1,
    K2,
    K3,
    K4,
    K5,
    K6,
    K7 = 0x07 | tag_mask_reg,

    pub fn create(reg_size: BitSize, reg_num: u8) Register {
        std.debug.assert(reg_num <= 0x0F);
        switch (reg_size) {
            // TODO: does this need to handle AH vs SIL edge case?
            .Bit8 => return @intToEnum(Register, (0<<4) | reg_num),
            .Bit16 => return @intToEnum(Register, (1<<4) | reg_num),
            .Bit32 => return @intToEnum(Register, (2<<4) | reg_num),
            .Bit64 => return @intToEnum(Register, (3<<4) | reg_num | rex_flag),
            else => unreachable,
        }
    }

    pub fn needsRex(self: Register) bool {
        if (self.registerType() == .General) {
            return (@enumToInt(self) & rex_flag) == rex_flag;
        } else {
            return false;
        }
    }

    pub fn needsNoRex(self: Register) bool {
        return switch (self) {
            .AH, .CH, .DH, .BH => true,
            else => false,
        };
    }

    pub fn name(self: Register) RegisterName {
        assert(self.registerType() == .General);
        return switch (self) {
            .AH, .CH, .DH, .BH => @intToEnum(RegisterName, self.number() & 0x03),
            else => @intToEnum(RegisterName, self.number()),
        };
    }

    pub fn number(self: Register) u8 {
        if (self.registerType() == .General) {
            return @intCast(u8, @enumToInt(self) & 0x0F);
        } else {
            return @intCast(u8, @enumToInt(self) & 0xFF);
        }
    }

    pub fn numberRm(self: Register) u3 {
        return @intCast(u3, @enumToInt(self) & 0x07);
    }

    pub fn numberRex(self: Register) u1 {
        return @intCast(u1, (@enumToInt(self) >> 3) & 0x01);
    }

    pub fn registerType(self: Register) RegisterType {
        return @intToEnum(RegisterType, tag_mask & @enumToInt(self));
    }

    pub fn dataSize(self: Register) DataSize {
        switch (self.registerType()) {
            .General => {
                const masked = @intCast(u8, @enumToInt(self) & gpr_size_mask);
                const byte_size = @as(u8, 1) << @intCast(u3, (masked >> 4));
                return DataSize.fromByteValue(byte_size);
            },
            .Segment => return DataSize.WORD,

            // TODO: These registers do have a size, but this is a hack to
            // make modrm encoding work
            .Control,
            .Debug,
            .MMX,
            .XMM,
            .YMM,
            .ZMM,
            .Float => return DataSize.Void,

            // .MMX => return DataSize.QWORD,
            // .XMM => return DataSize.OWORD,
            // .XMM => return DataSize.XMM_WORD,
            // .YMM => return DataSize.YMM_WORD,
            // .ZMM => return DataSize.ZMM_WORD,
            else => unreachable,
        }
    }

    pub fn bitSize(self: Register) BitSize {
        return self.dataSize().bitSize();
    }

};
