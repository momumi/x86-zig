const std = @import("std");
const assert = std.debug.assert;

pub const Mode86 = enum {
    x86_16 = 0,
    x86_32 = 1,
    x64 = 2,
};

// NOTE: the names of these rules are written from the point of view of 64 bit
// mode.  However, they also define the behavior of 32/16 bit modes as well.
//
pub const DefaultSize = enum (u8) {
    /// Default operand is 8 bit, other operand sizes are invalid
    RM8 = 0x00,
    /// 64 bit mode:
    ///   Default operand is 16 bit, REX prefix for 64 bit, 0x66 prefix for 32 bit
    /// 32 bit mode:
    ///   Default operand is 16 bit, 0x66 prefix for 32 bit
    /// 16 bit mode:
    ///   Default operand is 16 bit, 0x66 prefix for 32 bit
    RM16 = 0x01,
    /// 64 bit mode:
    ///   Default operand is 32 bit, REX prefix for 64 bit, 0x66 prefix for 16 bit
    /// 32 bit mode:
    ///   Default operand is 32 bit, 0x66 prefix for 16 bit
    /// 16 bit mode:
    ///   Default operand is 16 bit, 0x66 prefix for 32 bit
    RM32 = 0x02,
    /// Default operand is 64 bit, other operand sizes are invalid
    // TODO: might change this behavior later
    RM64 = 0x03,

    /// Same as RM32, except operand accepts an 8 bit immediate
    RM32_I8,

    /// No prefix used, valid all sizes
    RM,

    /// Same as RM32, but use the r/m operand size only ignoring the other operand
    RM32_RM,

    /// Same as RM32, but use the reg operand size only ignoring the other operand
    RM32_Reg,

    /// Same as RM64, but use the r/m operand size only ignoring the other operand
    RM64_RM,

    /// Same as RM64, but use the reg operand size only ignoring the other operand
    RM64_Reg,

    /// 64 bit mode:
    ///     Default operand is 32 bit, 16/64 bit invalid
    /// 32 bit mode:
    ///     Default operand is 32 bit, 0x66 prefix for 16 bit
    RM32Strict,

    /// 64 bit mode:
    ///     Default operand is 64 bit, 16/32 bit invalid
    /// 32 bit mode:
    ///     Default operand is 32 bit, 0x66 prefix for 16 bit
    RM64Strict,

    /// 64 bit mode:
    ///     invalid
    /// 32 bit mode:
    ///     Default operand is 32 bit, 0x66 prefix for 16 bit
    /// 16 bit mode:
    ///     Default operand is 16 bit, 0x66 prefix for 32 bit
    RM32Only,

    /// 64 bit mode:
    ///     Default operand is 64 bit, 0x66 prefix for 16 bit, 32 bit invalid
    /// 32 bit mode:
    ///     Default operand is 32 bit, 0x66 prefix for 16 bit
    RM64_16,

    /// Used for instructions that use 0x67 to determine register size
    ///
    /// 64 bit mode:
    ///     Invalid
    /// 32 bit mode:
    ///     address overide prefix 0x67, memory addressing must be 16 bit if used
    R_Over16,

    /// 64 bit mode:
    ///     address overide prefix 0x67, memory addressing must be 32 bit if used
    /// 32 bit mode:
    ///     no prefix
    R_Over32,

    /// 64 bit mode:
    ///     no prefix, memory addressing must use 64 bit registers if used
    /// 32 bit mode:
    ///     invalid
    R_Over64,

    /// 64 bit mode:
    ///     Default operand is 8 bit
    /// 32/16 bit mode:
    ///     Invalid
    RM8_64Only,

    /// 64 bit mode:

    /// 64 bit mode:
    ///     zero operands, valid
    /// 32 bit mode:
    ///     zero operands, valid
    /// 16 bit mode:
    ///     zero operands, valid
    ZO,

    /// 64 bit mode:
    ///     zero operands, invalid
    /// 32 bit mode:
    ///     zero operands, valid
    /// 16 bit mode:
    ///     zero operands, valid
    ZO32Only,

    /// Behaves like RM64_16, but the encoding uses zero operands
    ZO64_16,

    /// Forces REX.W bit set
    REX_W,

    pub fn bitSize32(self: DefaultSize) BitSize {
        return switch (self) {
            .R_Over16,
            .R_Over32,
            .R_Over64,
            .RM8_64Only,
            .RM8 => .Bit8,

            .RM16 => .Bit16,

            .RM64_16,
            .ZO64_16,
            .RM64Strict,
            .RM32_I8,
            .RM32_RM,
            .RM32_Reg,
            .RM32Strict,
            .RM32Only,
            .RM32 => .Bit32,

            .RM64_RM,
            .RM64_Reg,
            .RM64 => .Bit64,

            .RM,
            .ZO,
            .REX_W,
            .ZO32Only => .Bit0,
        };
    }

    pub fn bitSize64(self: DefaultSize) BitSize {
        return switch (self) {
            .R_Over16,
            .R_Over32,
            .R_Over64,
            .RM8_64Only,
            .RM8 => .Bit8,

            .RM16 => .Bit16,

            .RM32_I8,
            .RM32_RM,
            .RM32_Reg,
            .RM32Strict,
            .RM32Only,
            .RM32 => .Bit32,

            .RM64Strict,
            .ZO64_16,
            .RM64_16,
            .RM64_RM,
            .RM64_Reg,
            .RM64 => .Bit64,

            .RM,
            .ZO,
            .REX_W,
            .ZO32Only => .Bit0,
        };
    }

    pub fn bitSize(self: DefaultSize, mode: Mode86) BitSize {
        return switch (mode) {
            .x86_16 => unreachable, // TODO:
            .x86_32 => self.bitSize32(),
            .x64 => self.bitSize64(),
        };
    }

    pub fn is64Default(self: DefaultSize) bool {
        return switch (self) {
            .ZO64_16, .RM64, .RM64Strict, .RM64_16, .RM64_RM, .RM64_Reg, .ZO, .R_Over64 => true,
            else => false,
        };
    }

    pub fn needsSizeCheck(self: DefaultSize) bool {
        return switch (self) {
            .RM32_RM, .RM32_Reg, .RM64_RM, .RM64_Reg,
            .ZO, .R_Over16, .R_Over32, .R_Over64 => false,
            else => true,
        };
    }
};

pub const Segment = enum (u8) {
    ES = 0x00,
    CS,
    SS,
    DS,
    FS,
    GS = 0x05,

    DefaultSeg = 0x10,
};

pub const AsmError = error {
    InvalidMemoryAddressing,
    InvalidOperand,
    InvalidMode,
    InvalidRegisterCombination,
    InvalidRegister,
    RelativeImmediateOverflow,
    // InvalidImmediate,
};

pub const BitSize = enum (u16) {
    Bit0  = 0,
    Bit8  = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
    Bit80 = 10,
    Bit128 = 16,
    Bit256 = 32,
    Bit512 = 64,

    None = 0xffff,

    pub fn value(self: BitSize) u16 {
        return 8 * @enumToInt(self);
    }

    pub fn valueBytes(self: BitSize) u16 {
        return @enumToInt(self);
    }
};

pub const OpcodePrefixType = enum {
    /// Opcode permits prefixes
    Prefixable,
    /// No Prefix:
    ///
    /// Indicates the use of 66/F2/F3 prefixes (beyond those already part of
    /// the instructions opcode) are not allowed with the instruction.
    NP,
    /// Mandatory prefix
    Mandatory,
    /// No Fx prefix
    ///
    /// Indicates the use of F2/F3 prefixes (beyond those already part of the
    /// instructions opcode) are not allowed with the instruction.
    NFx,
};

pub const Opcode = struct {
    const max_length:u8 = 4;
    opcode: [max_length]u8 = undefined,
    len: u8 = 0,
    prefix: u8 = 0,
    prefix_type: OpcodePrefixType = .Prefixable,
    reg_bits: ?u3 = null,

    pub fn asSlice(self: Opcode) []const u8 {
        return self.opcode[0..self.len];
    }

    pub fn prefixesAsSlice(self: Opcode) []const u8 {
        return self.prefixes[0..self.prefix_count];
    }

    fn create_generic(
        prefix_type: OpcodePrefixType,
        prefix: u8,
        opcode_bytes: [4]u8,
        len: u8,
        reg_bits: ?u3
    ) Opcode {
        return Opcode {
            .opcode = opcode_bytes,
            .len = len,
            .prefix = prefix,
            .prefix_type = prefix_type,
            .reg_bits = reg_bits,
        };
    }

    pub fn op1r(byte0: u8, reg_bits: u3) Opcode {
        return create_generic(.Prefixable, 0, [_]u8{byte0, 0, 0, 0}, 1, reg_bits);
    }

    pub fn op2r(byte0: u8, byte1: u8, reg_bits: u3) Opcode {
        return create_generic(.Prefixable, 0, [_]u8{byte0, byte1, 0, 0}, 2, reg_bits);
    }

    pub fn op3r(byte0: u8, byte1: u8, byte2: u8, reg_bits: u3) Opcode {
        return create_generic(.Prefixable, 0, [_]u8{byte0, byte1, byte2, 0}, 3, reg_bits);
    }

    pub fn op4r(byte0: u8, byte1: u8, byte2: u8, byte3: u8, reg_bits: u3) Opcode {
        return create_generic(.Prefixable, 0, [_]u8{byte0, byte1, byte2, byte3, 0}, 4, reg_bits);
    }

    pub fn preOp1r(prefix: u8, byte0: u8, reg_bits: u3) Opcode {
        return create_generic(.Mandatory, prefix, [_]u8{byte0, 0, 0, 0}, 1, reg_bits);
    }

    pub fn preOp2r(prefix: u8, byte0: u8, byte1: u8, reg_bits: u3) Opcode {
        return create_generic(.Mandatory, prefix, [_]u8{byte0, byte1, 0, 0}, 2, reg_bits);
    }

    pub fn preOp3r(prefix: u8, byte0: u8, byte1: u8, byte2: u8, reg_bits: u3) Opcode {
        return create_generic(.Mandatory, prefix, [_]u8{byte0, byte1, byte2, 0}, 3, reg_bits);
    }

    pub fn npOp1r(byte0: u8, reg_bits: u3) Opcode {
        return create_generic(.NP, 0, [_]u8{byte0, 0, 0}, 1, reg_bits);
    }

    pub fn npOp2r(byte0: u8, byte1: u8, reg_bits: u3) Opcode {
        return create_generic(.NP, 0, [_]u8{byte0, byte1, 0, 0}, 2, reg_bits);
    }

    pub fn nfxOp1r(byte0: u8, reg_bits: u3) Opcode {
        return create_generic(.NFx, 0, [_]u8{byte0, 0, 0, 0}, 1, reg_bits);
    }

    pub fn nfxOp2r(byte0: u8, byte1: u8, reg_bits: u3) Opcode {
        return create_generic(.NFx, 0, [_]u8{byte0, byte1, 0, 0}, 2, reg_bits);
    }

    pub fn op1(byte0: u8) Opcode {
        return create_generic(.Prefixable, 0, [_]u8{byte0, 0, 0, 0}, 1, null);
    }

    pub fn op2(byte0: u8, byte1: u8) Opcode {
        return create_generic(.Prefixable, 0, [_]u8{byte0, byte1, 0, 0}, 2, null);
    }

    pub fn op3(byte0: u8, byte1: u8, byte2: u8) Opcode {
        return create_generic(.Prefixable, 0, [_]u8{byte0, byte1, byte2, 0}, 3, null);
    }

    pub fn preOp1(prefix: u8, byte0: u8) Opcode {
        return create_generic(.Mandatory, prefix, [_]u8{byte0, 0, 0, 0}, 1, null);
    }

    pub fn preOp2(prefix: u8, byte0: u8, byte1: u8) Opcode {
        return create_generic(.Mandatory, prefix, [_]u8{byte0, byte1, 0, 0}, 2, null);
    }

    pub fn preOp3(prefix: u8, byte0: u8, byte1: u8, byte2: u8) Opcode {
        return create_generic(.Mandatory, prefix, [_]u8{byte0, byte1, byte2, 0}, 3, null);
    }

    pub fn npOp1(byte0: u8) Opcode {
        return create_generic(.NP, 0, [_]u8{byte0, 0, 0, 0}, 1, null);
    }

    pub fn npOp2(byte0: u8, byte1: u8) Opcode {
        return create_generic(.NP, 0, [_]u8{byte0, byte1, 0, 0}, 2, null);
    }

    pub fn npOp3(byte0: u8, byte1: u8, byte2: u8) Opcode {
        return create_generic(.NP, 0, [_]u8{byte0, byte1, byte2, 0}, 3, null);
    }
};


pub const DataType = enum (u16) {
    NormalMemory = 0x0000,
    FarAddress = 0x01000,
    FloatingPoint = 0x0200,
    VoidPointer = 0x0300,
    Broadcast = 0x0400,
    Vector = 0x0500,
    Register = 0x0F00,
};

pub const DataSize = enum (u16) {
    const tag_mask: u16 = 0xFF00;
    const size_mask: u16 = 0x00FF;
    const normal_tag: u16 = @enumToInt(DataType.NormalMemory);
    const far_address_tag: u16 = @enumToInt(DataType.FarAddress);
    const floating_point_tag: u16 = @enumToInt(DataType.FloatingPoint);
    const void_tag: u16 = @enumToInt(DataType.VoidPointer);
    const broadcast_tag: u16 = @enumToInt(DataType.Broadcast);
    const vector_tag: u16 = @enumToInt(DataType.Vector);

    /// 8 bit data size
    BYTE = 1 | normal_tag,
    /// 16 bit data size
    WORD = 2 | normal_tag,
    /// 32 bit data size
    DWORD = 4 | normal_tag,
    /// 64 bit data size
    QWORD = 8 | normal_tag,
    /// 80 bit data size
    TBYTE = 10 | normal_tag,
    /// 128 bit data size (DQWORD)
    OWORD = 16 | normal_tag,

    /// 128 bit data size
    XMM_WORD = 16 | vector_tag,
    /// 256 bit data size
    YMM_WORD = 32 | vector_tag,
    /// 512 bit data size
    ZMM_WORD = 64 | vector_tag,

    /// 32 bit broadcast for AVX512
    DWORD_BCST = 4 | broadcast_tag,
    /// 64 bit broadcast for AVX512
    QWORD_BCST = 8 | broadcast_tag,

    // FIXME:
    //
    // Right now this doesn't represent the real size of the data. Rather it
    // contains the size of how the value behaves with respect to the operand
    // size overide and the REX.W prefixes.
    //
    // It would be better to encode this data into the type, and then the
    // data size can be include correctly as well.
    /// 16:16 bit data size (16 bit addr followed by 16 bit segment)
    FAR_WORD = 2 | far_address_tag,
    /// 16:32 bit data size (32 bit addr followed by 16 bit segment)
    FAR_DWORD = 4 | far_address_tag,
    /// 16:64 bit data size (64 bit addr followed by 16 bit segment)
    FAR_QWORD = 8 | far_address_tag,

    Void = 0 | void_tag,

    Default = @enumToInt(BitSize.None),

    pub fn fromByteValue(bytes: u16) DataSize {
        return @intToEnum(DataSize, bytes | normal_tag);
    }

    pub fn bitSize(self: DataSize) BitSize {
        return @intToEnum(BitSize, @enumToInt(self) & size_mask);
    }

    pub fn dataType(self: DataSize) DataType {
        return @intToEnum(DataType, @enumToInt(self) & tag_mask);
    }

    pub fn defaultBitSize(self: DataSize, mode: Mode86) BitSize {
        return switch (self) {
            .Default => default_size.bitSize(mode),
            else => self.bitSize(),
        };
    }
};

pub const PrefixGroup = enum {
    Group1 = 0,
    Group2 = 1,
    Group3 = 2,
    Group4 = 3,
    None,
};

/// Legacy prefixes
pub const Prefix = enum(u8) {
    None = 0x00,

    // Group 1
    Lock = 0xF0,
    Repne = 0xF2,
    Rep = 0xF3,

    // Group 2
    // BranchTaken = 0x2E, // aliases with SegmentCS
    // BranchNotTaken = 0x3E, // aliases with SegmentDS
    SegmentCS = 0x2E,
    SegmentES = 0x26,
    SegmentSS = 0x36,
    SegmentDS = 0x3E,
    SegmentFS = 0x64,
    SegmentGS = 0x65,

    // Group 3
    OperandOveride = 0x66,

    // Group 4
    AddressOveride = 0x67,

    pub fn getGroup(self: Prefix) PrefixGroup {
        return switch (self) {
            .Lock, .Repne, .Rep => .Group1,

            .SegmentCS,
            .SegmentES,
            .SegmentSS,
            .SegmentDS,
            .SegmentFS,
            .SegmentGS,
            => .Group2,

            .OperandOveride => .Group2,
            .AddressOveride => .Group3,
            .None => .None,
        };
    }

    pub fn value(self: Prefix) u8 {
        return @enumToInt(self);
    }
};

/// Prefixes
pub const Prefixes = struct {
    const max_count = 4;
    prefixes: [max_count]Prefix = [1]Prefix{.None} ** max_count,
    len: u8 = 0,

    pub fn single(prefix: Prefix) Prefixes {
        return Prefixes {
            .prefixes = [max_count]Prefix { prefix, .None, .None, .None },
            .len = 1,
        };
    }

    pub fn singleRaw(prefix: u8) Prefixes {
        return Prefixes.single(@intToEnum(Prefix, prefix));
    }

    pub fn multiple(prefixes_: []const Prefix) Prefixes {
        var res: Prefixes = undefined;
        res.len = 0;

        for (prefixes_) |p| {
            if (p != .None) {
                res.addPrefix(p);
            }
        }
        return res;
    }

    pub fn addSegmentOveride(self: *Prefixes, seg: Segment) void {
        switch (seg) {
            .ES => self.addPrefix(.SegmentES),
            .CS => self.addPrefix(.SegmentCS),
            .SS => self.addPrefix(.SegmentSS),
            .DS => self.addPrefix(.SegmentDS),
            .FS => self.addPrefix(.SegmentFS),
            .GS => self.addPrefix(.SegmentGS),
            else => unreachable,
        }
    }

    pub fn addPrefix(self: *Prefixes, prefix: Prefix) void {
        assert(!self.hasPrefix(prefix));
        assert(self.len < max_count);
        assert(prefix != .None);
        self.prefixes[self.len] = prefix;
        self.len += 1;
    }

    pub fn addRawPrefix(self: *Prefixes, prefix: u8) void {
        self.addPrefix(@intToEnum(Prefix, prefix));
    }

    pub fn hasPrefix(self: Prefixes, prefix: Prefix) bool {
        for (self.prefixes[0..self.len]) |p| {
            if (p == prefix) {
                return true;
            }
        }
        return false;
    }

    pub fn asSlice(self: Prefixes) []const u8 {
        return @sliceToBytes(self.prefixes[0..self.len]);
    }

    pub fn addOverides64(
        self: *Prefixes,
        rex_w: *u1,
        operand_size: BitSize,
        addressing_size: BitSize,
        default_size: DefaultSize
    ) AsmError!void {
        switch (default_size) {
            .RM8_64Only,
            .RM8 => switch (operand_size) {
                .Bit8 => {},
                else => return AsmError.InvalidOperand,
            },

            .RM16 => switch (operand_size) {
                .Bit16 => {}, // default
                .Bit32 => self.addPrefix(.OperandOveride),
                .Bit64 => rex_w.* = 1,
                else => return AsmError.InvalidOperand,
            },

            .RM32_I8,
            .RM32_RM,
            .RM32_Reg,
            .RM32 => switch (operand_size) {
                .Bit16 => self.addPrefix(.OperandOveride),
                .Bit32 => {}, // default
                .Bit64 => rex_w.* = 1,
                else => return AsmError.InvalidOperand,
            },

            .RM64_RM,
            .RM64_Reg,
            .RM64 => switch (operand_size) {
                .Bit64 => {},
                else => return AsmError.InvalidOperand,
            },

            .ZO64_16,
            .RM64_16 => switch (operand_size) {
                .Bit16 => self.addPrefix(.OperandOveride),
                .Bit64 => rex_w.* = 0,
                else => return AsmError.InvalidOperand,
            },

            .RM64Strict => switch (operand_size) {
                .Bit64 => {},
                else => return AsmError.InvalidOperand,
            },

            .RM32Strict => switch (operand_size) {
                .Bit16 => return AsmError.InvalidOperand,
                .Bit32 => {},
                else => return AsmError.InvalidOperand,
            },

            // Invalid in 64 bit mode
            .RM32Only,
            .ZO32Only => return AsmError.InvalidOperand,

            .RM, .ZO => {}, // zero operand

            .REX_W => rex_w.* = 1,

            .R_Over16 => return AsmError.InvalidOperand,
            .R_Over32 => {
                if (addressing_size == .None) {
                    self.addPrefix(.AddressOveride);
                } else if (addressing_size != .Bit32) {
                    // Using this mode the addressing size must match register size
                    return AsmError.InvalidOperand;
                }
            },
            .R_Over64 => {
                if (addressing_size == .None) {
                    // okay
                } else if (addressing_size != .Bit64) {
                    // Using this mode the addressing size must match register size
                    return AsmError.InvalidOperand;
                }
            },
        }

        switch (addressing_size) {
            .None => {},
            .Bit32 => self.addPrefix(.AddressOveride),
            .Bit64 => {}, // default, no prefix needed
            else => return AsmError.InvalidOperand,
        }
    }

    pub fn addOverides32(
        self: *Prefixes,
        rex_w: *u1,
        operand_size: BitSize,
        addressing_size: BitSize,
        default_size: DefaultSize
    ) AsmError!void {

        switch (default_size) {
            .RM8 => switch (operand_size) {
                .Bit8 => {},
                else => return AsmError.InvalidOperand,
            },
            .RM16 => switch (operand_size) {
                .Bit16 => {}, // default
                .Bit32 => self.addPrefix(.OperandOveride),
                else => return AsmError.InvalidOperand,
            },

            .RM32_I8,
            .RM32,
            .RM32_RM,
            .RM32_Reg,
            .RM32Strict,
            .RM32Only,
            .ZO64_16,
            .RM64_16,
            .RM64Strict => switch (operand_size) {
                .Bit16 => self.addPrefix(.OperandOveride),
                .Bit32 => {},
                else => return AsmError.InvalidOperand,
            },

            .REX_W,
            .RM64_Reg,
            .RM64_RM,
            .RM64 => return AsmError.InvalidOperand,

            .RM8_64Only => return AsmError.InvalidOperand,

            .RM,
            .ZO32Only,
            .ZO => {}, // zero operand

            .R_Over16 => {
                if (addressing_size == .None) {
                    self.addPrefix(.AddressOveride);
                } else if (addressing_size != .Bit16) {
                    // Using this mode the addressing size must match register size
                    return AsmError.InvalidOperand;
                }
            },
            .R_Over32 => {
                if (addressing_size == .None) {
                    // okay
                } else if (addressing_size != .Bit32) {
                    // Using this mode the addressing size must match register size
                    return AsmError.InvalidOperand;
                }
            },
            .R_Over64 => unreachable,
        }

        switch (addressing_size) {
            .None => {},
            .Bit16 => self.addPrefix(.AddressOveride),
            .Bit32 => {}, // default
            else => return AsmError.InvalidOperand,
        }

    }

    pub fn addOverides16(
        self: *Prefixes,
        rex_w: *u1,
        operand_size: BitSize,
        addressing_size: BitSize,
        default_size: DefaultSize
    ) AsmError!void {

        switch (default_size) {
            .RM8 => switch (operand_size) {
                .Bit8 => {},
                else => return AsmError.InvalidOperand,
            },
            .RM16 => switch (operand_size) {
                .Bit16 => {}, // default
                .Bit32 => self.addPrefix(.OperandOveride),
                else => return AsmError.InvalidOperand,
            },

            .RM32_I8,
            .RM32,
            .RM32_RM,
            .RM32_Reg,
            .RM32Strict,
            .RM32Only,
            .ZO64_16,
            .RM64_16,
            .RM64Strict => switch (operand_size) {
                .Bit16 => {},
                .Bit32 => self.addPrefix(.OperandOveride),
                else => return AsmError.InvalidOperand,
            },

            .REX_W,
            .RM64_Reg,
            .RM64_RM,
            .RM64 => return AsmError.InvalidOperand,

            .RM8_64Only => return AsmError.InvalidOperand,

            .RM,
            .ZO32Only,
            .ZO => {}, // zero operand

            .R_Over16 => {
                if (addressing_size == .None) {
                    // okay
                } else if (addressing_size != .Bit16) {
                    // Using this mode the addressing size must match register size
                    return AsmError.InvalidOperand;
                }
            },
            .R_Over32 => {
                if (addressing_size == .None) {
                    self.addPrefix(.AddressOveride);
                } else if (addressing_size != .Bit32) {
                    // Using this mode the addressing size must match register size
                    return AsmError.InvalidOperand;
                }
            },
            .R_Over64 => unreachable,
        }

        switch (addressing_size) {
            .None => {},
            .Bit16 => {},
            .Bit32 => self.addPrefix(.AddressOveride), // default
            else => return AsmError.InvalidOperand,
        }

    }

    pub fn addOverides(
        self: *Prefixes,
        mode: Mode86,
        rex_w: *u1,
        operand_size: BitSize,
        addressing_size: BitSize,
        default_size: DefaultSize
    ) AsmError!void {
        switch (mode) {
            .x86_16 => try self.addOverides16(rex_w, operand_size, addressing_size, default_size),
            .x86_32 => try self.addOverides32(rex_w, operand_size, addressing_size, default_size),
            .x64 => try self.addOverides64(rex_w, operand_size, addressing_size, default_size),
        }
    }
};

