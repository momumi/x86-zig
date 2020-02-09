const std = @import("std");
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

pub const RegisterSize = enum (u8) {
    Reg8  = 0,
    Reg16 = 1,
    Reg32 = 2,
    Reg64 = 3,
};

/// General purpose registers 8/16/32/64 bits
pub const Register = enum(u8) {
    const rex_flag: u8 = 0x40;

    // We use special format for these registers:
    // u8: .RSSNNNN
    //
    // N: register number
    // S: size (1 << 0bSS) bytes
    // R: needs REX prefix
    // .: unused

    AL = 0x00,
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
    R15B = 0x0F,

    // 16 bit registers
    AX = 0x10,
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
    R15W = 0x1F,

    // 32 bit registers
    EAX = 0x20,
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
    R15D = 0x2F,

    // We use a flag 0x80 to mark registers that require REX prefix
    // 64 bit register
    RAX = 0x30 | rex_flag,
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
    R15 = 0x3F | rex_flag,

    // special 8 bit registers added in x86-64:
    SPL = 0x04 | rex_flag, // would be AH without REX flag
    BPL = 0x05 | rex_flag, // would be CH without REX flag
    SIL = 0x06 | rex_flag, // would be DH without REX flag
    DIL = 0x07 | rex_flag, // would be BH without REX flag

    pub fn create(reg_size: RegisterSize, reg_num: u8) Register {
        std.debug.assert(reg_num <= 0x0F);
        switch (reg_size) {
            .Reg64 => return @intToEnum(Register, (@enumToInt(reg_size)<<4) | reg_num | rex_flag),
            else => return @intToEnum(Register, (@enumToInt(reg_size)<<4) | reg_num),
        }
    }

    pub fn needsRex(self: Register) bool {
        return (@enumToInt(self) & Register.rex_flag) == Register.rex_flag;
    }

    pub fn needsNoRex(self: Register) bool {
        return switch (self) {
            .AH, .CH, .DH, .BH => true,
            else => false,
        };
    }

    pub fn toOperand(self: Register) Operand {
        return Operand { .Reg = self };
    }

    pub fn size(self: Register) RegisterSize {
        return @intToEnum(RegisterSize, @intCast(u2, (@enumToInt(self) >> 4) & 0x03));
    }

    pub fn bitSize(self: Register) BitSize {
        return @intToEnum(BitSize, @as(u8,1) << @intCast(u3, @enumToInt(self.size())));
    }

    pub fn dataSize(self: Register) DataSize {
        return @intToEnum(DataSize, @as(u8,1) << @intCast(u3, @enumToInt(self.size())));
    }

    pub fn name(self: Register) RegisterName {
        return switch (self) {
            .AH, .CH, .DH, .BH => @intToEnum(RegisterName, self.number() & 0x03),
            else => @intToEnum(RegisterName, self.number()),
        };
    }

    pub fn number(self: Register) u8 {
        return (@enumToInt(self) & 0x0F);
    }

    pub fn numberLowBits(self: Register) u8 {
        return @intCast(u3, (@enumToInt(self) & 0x07));
    }

    pub fn numberRm(self: Register) u3 {
        return @intCast(u3, (@enumToInt(self) & 0x07));
    }

    pub fn numberRex(self: Register) u1 {
        return @intCast(u1, (@enumToInt(self) >> 3) & 0x01);
    }
};

pub const RegisterSpecialType = enum(u8) {
    Segment = 0x00,
    Float = 0x10,
    MMX = 0x20,
    Control = 0x30,
    Debug = 0x40,
};

/// Special control and debug registers
pub const RegisterSpecial = enum (u8) {
    // TODO:
    // Segment registers
    ES = 0x00,
    CS,
    SS,
    DS,
    FS,
    GS = 0x05,

    /// Segment registers with extension bit set in REX
    /// These registers are identical to the other segment registers, but we
    /// include them for completness.
    ES_ = 0x08,
    CS_,
    SS_,
    DS_,
    FS_,
    GS_ = 0x0d,

    ST0 = 0x10,
    ST1,
    ST2,
    ST3,
    ST4,
    ST5,
    ST6,
    ST7 = 0x17,
    // ST0_ = 0x18,
    // ST1_,
    // ST2_,
    // ST3_,
    // ST4_,
    // ST5_,
    // ST6_,
    // ST7_ = 0x1F,

    MM0 = 0x20,
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
    MM7_ = 0x2F,

    // Most of these are not valid to use, but keep them for completeness
    CR0 = 0x30,
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
    CR15 = 0x3F,

    // Most of these are not valid to use, but keep them for completeness
    DR0 = 0x40,
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
    DR15 = 0x4F,

    pub fn registerSpecialType(self: RegisterSpecial) RegisterSpecialType {
        return @intToEnum(RegisterSpecialType, 0xf0 & @enumToInt(self));
    }

    pub fn dataSize(self: RegisterSpecial) DataSize {
        const val = @enumToInt(self);
        if (val <= @enumToInt(RegisterSpecial.GS_)) {
            return DataSize.WORD;
        } else {
            unreachable;
        }
    }

    pub fn bitSize(self: RegisterSpecial) BitSize {
        return self.dataSize().bitSize();
    }

    pub fn toRegister(self: RegisterSpecial, mode: Mode86) Register {
        switch (self.registerSpecialType()) {
            .Float, .Segment => return Register.create(.Reg16, 0x0f & @enumToInt(self)),
            .Debug, .Control => {
                const reg_size = switch (mode) {
                    .x86_16 => unreachable,
                    .x86 => RegisterSize.Reg32,
                    .x64 => RegisterSize.Reg64,
                };
                return Register.create(reg_size, 0x0f & @enumToInt(self));
            },
            else => unreachable,
        }
    }
};

const RegisterSimd = enum(u8) {
    const avx_mask = 0xC0;
    const xmm_tag = 0x40;
    const ymm_tag = 0x80;
    const zmm_tag = 0xC0;

    XMM0 = 0x00 | xmm_tag,
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
    XMM31 = 0x1F | xmm_tag,

    YMM0 = 0x00 | ymm_tag,
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
    YMM31 = 0x1F | ymm_tag,

    ZMM0 = 0x1F | zmm_tag,
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
    ZMM31 = 0x1F | zmm_tag,
};
