const std = @import("std");
const assert = std.debug.assert;

pub const Mode86 = enum {
    x86_16 = 0,
    x86 = 1,
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

    /// Used for JCXZ:
    ///
    /// 64 bit mode:
    ///     Invalid
    /// 32 bit mode:
    ///     Default operand is 8 bit + address overide prefix 0x67
    RM8_Over16,

    /// Used for JECXZ:
    ///
    /// 64 bit mode:
    ///     Default operand is 8 bit + address overide prefix 0x67
    /// 32 bit mode:
    ///     Default operand is 8 bit
    RM8_Over32,

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


    pub fn bitSize32(self: DefaultSize) BitSize {
        return switch (self) {
            .RM8_Over16,
            .RM8_Over32,
            .RM8_64Only,
            .RM8 => .Bit8,

            .RM16 => .Bit16,

            .RM64_16,
            .ZO64_16,
            .RM64Strict,
            .RM32_I8,
            .RM32Strict,
            .RM32Only,
            .RM32 => .Bit32,

            .RM64 => .Bit64,

            .ZO,
            .ZO32Only => .Bit0,
        };
    }

    pub fn bitSize64(self: DefaultSize) BitSize {
        return switch (self) {
            .RM8_Over16,
            .RM8_Over32,
            .RM8_64Only,
            .RM8 => .Bit8,

            .RM16 => .Bit16,

            .RM32_I8,
            .RM32Strict,
            .RM32Only,
            .RM32 => .Bit32,

            .RM64Strict,
            .ZO64_16,
            .RM64_16,
            .RM64 => .Bit64,

            .ZO,
            .ZO32Only => .Bit0,
        };
    }

    pub fn bitSize(self: DefaultSize, mode: Mode86) BitSize {
        return switch (mode) {
            .x86_16 => unreachable, // TODO:
            .x86 => self.bitSize32(),
            .x64 => self.bitSize64(),
        };
    }

    pub fn is64(self: DefaultSize) bool {
        return switch (self) {
            .ZO64_16, .RM64, .RM64Strict, .RM64_16 => true,
            else => false,
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
    InvalidOperandCombination,
    InvalidMode,
    InvalidRegister,
    RelativeImmediateOverflow,
    // InvalidImmediate,
};

pub const BitSize = enum (u8) {
    Bit0  = 0,
    Bit8  = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
    Bit80 = 10,

    None = 0xf0,

    pub fn value(self: BitSize) u16 {
        return 8 * @enumToInt(self);
    }

    pub fn valueBytes(self: BitSize) u8 {
        return @enumToInt(self);
    }
};

pub const Opcode = struct {
    const max_length:u8 = 4;
    opcode: [max_length]u8 = undefined,
    reg_bits: ?u3 = null,
    len: u8 = 0,

    pub fn asSlice(self: Opcode) []const u8 {
        return self.opcode[0..self.len];
    }

    pub fn asMutSlice(self: Opcode) []u8 {
        return self.opcode[0..self.len];
    }

    pub fn op1r(byte0: u8, reg_bits: u3) Opcode {
        var res = Opcode.op1(byte0);
        res.reg_bits = reg_bits;
        return res;
    }

    pub fn op2r(byte0: u8, byte1: u8, reg_bits: u3) Opcode {
        var res = Opcode.op2(byte0, byte1);
        res.reg_bits = reg_bits;
        return res;
    }

    pub fn op3r(byte0: u8, byte1: u8, byte2: u8, reg_bits: u3) Opcode {
        var res = Opcode.op3(byte0, byte1, byte2);
        res.reg_bits = reg_bits;
        return res;
    }

    pub fn op4r(byte0: u8, byte1: u8, byte2: u8, byte3: u8, reg_bits: u3) Opcode {
        var res = Opcode.op4(byte0, byte1, byte2, byte3);
        res.reg_bits = reg_bits;
        return res;
    }

    pub fn op1(byte0: u8) Opcode {
        var res = Opcode {};
        res.opcode[0] = byte0;
        res.len = 1;
        return res;
    }

    pub fn op2(byte0: u8, byte1: u8) Opcode {
        var res = Opcode {};
        res.opcode[0] = byte0;
        res.opcode[1] = byte1;
        res.len = 2;
        return res;
    }

    pub fn op3(byte0: u8, byte1: u8, byte2: u8) Opcode {
        var res = Opcode {};
        res.opcode[0] = byte0;
        res.opcode[1] = byte1;
        res.opcode[2] = byte2;
        res.len = 3;
        return res;
    }

    pub fn op4(byte0: u8, byte1: u8, byte2: u8, byte3: u8) Opcode {
        var res = Opcode {};
        res.opcode[0] = byte0;
        res.opcode[1] = byte1;
        res.opcode[2] = byte2;
        res.opcode[3] = byte3;
        res.len = 3;
        return res;
    }
};

pub const DataType = enum (u8) {
    NormalMemory = 0x00,
    FarAddress = 0x10,
    FloatingPoint = 0x20,
    Register = 0xF0,
};

pub const DataSize = enum (u8) {
    const tag_mask: u8 = 0xF0;
    const size_mask: u8 = 0x0F;
    const normal_tag: u8 = @enumToInt(DataType.NormalMemory);
    const far_address_tag: u8 = @enumToInt(DataType.FarAddress);
    const floating_point_tag: u8 = @enumToInt(DataType.FloatingPoint);

    /// 8 bit data size
    BYTE = 1 | normal_tag,
    /// 16 bit data size
    WORD = 2 | normal_tag,
    /// 32 bit data size
    DWORD = 4 | normal_tag,
    /// 64 bit data size
    QWORD = 8 | normal_tag,

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

    /// 16:16 bit data size (16 bit addr followed by 16 bit segment)
    FP32 = 4 | floating_point_tag,
    /// 16:32 bit data size (32 bit addr followed by 16 bit segment)
    FP64 = 8 | floating_point_tag,
    /// 16:64 bit data size (64 bit addr followed by 16 bit segment)
    FP80 = 10 | floating_point_tag,

    Default = @enumToInt(BitSize.None),

    // /// 128 bit data size
    // XWORD = 4,

    // /// 256 bit data size
    // YWORD = 5,

    // /// 512 bit data size
    // ZWORD = 6,

    pub fn fromByteValue(bytes: u8) DataSize {
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
            .RM32 => switch (operand_size) {
                .Bit16 => self.addPrefix(.OperandOveride),
                .Bit32 => {}, // default
                .Bit64 => rex_w.* = 1,
                else => return AsmError.InvalidOperand,
            },

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

            .ZO => {}, // zero operand

            .RM8_Over16 => return AsmError.InvalidOperand,
            .RM8_Over32 => {
                self.addPrefix(.AddressOveride);
                assert(addressing_size == .None);
            }
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
            .RM32Strict,
            .RM32Only,
            .ZO64_16,
            .RM64_16,
            .RM64Strict => switch (operand_size) {
                .Bit16 => self.addPrefix(.OperandOveride),
                .Bit32 => {},
                else => return AsmError.InvalidOperand,
            },

            .RM64 => return AsmError.InvalidOperand,
            .RM8_64Only => return AsmError.InvalidOperandCombination,

            .ZO32Only,
            .ZO => {}, // zero operand

            .RM8_Over16 => {
                self.addPrefix(.AddressOveride);
                assert(addressing_size == .None);
            },
            .RM8_Over32 => {},
        }

        switch (addressing_size) {
            .None => {},
            .Bit16 => self.addPrefix(.AddressOveride),
            .Bit32 => {}, // default
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
        // TODO: handle all cases properly
        switch (mode) {
            // .x86_16 => try self.addOverides64()
            .x86_16 => unreachable,
            .x86 => try self.addOverides32(rex_w, operand_size, addressing_size, default_size),
            .x64 => try self.addOverides64(rex_w, operand_size, addressing_size, default_size),
        }
        if (mode == Mode86.x64) {
        } else if (mode == Mode86.x86) {

        }
    }
};

