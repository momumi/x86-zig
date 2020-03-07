const std = @import("std");
const assert = std.debug.assert;

pub const Mode86 = enum {
    x86_16 = 0,
    x86_32 = 1,
    x64 = 2,
};

pub const AsmError = error {
    InvalidOperand,
    InvalidMode,
    InvalidMemoryAddressing,
    InvalidRegisterCombination,
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

pub const BitSize = enum (u16) {
    None  = 0,
    Bit8  = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
    Bit80 = 10,
    Bit128 = 16,
    Bit256 = 32,
    Bit512 = 64,

    pub fn value(self: BitSize) u16 {
        return 8 * @enumToInt(self);
    }

    pub fn valueBytes(self: BitSize) u16 {
        return @enumToInt(self);
    }
};


pub const Overides = enum (u8) {
    /// 64 bit mode:
    ///     zero overides, valid
    /// 32 bit mode:
    ///     zero overides, valid
    /// 16 bit mode:
    ///     zero overides, valid
    ZO,

    /// 64 bit mode:
    ///     0x66 size overide prefix
    /// 32 bit mode:
    ///     0x66 size overide prefix
    /// 16 bit mode:
    ///     no overide prefix
    Op16,

    /// 64 bit mode:
    ///     no overide prefix
    /// 32 bit mode:
    ///     no overide prefix
    /// 16 bit mode:
    ///     0x66 size overide prefix
    Op32,

    /// Forces REX.W bit set, only valid in 64 bit mode
    REX_W,

    /// Used for instructions that use 0x67 to determine register size
    ///
    /// 64 bit mode:
    ///     Invalid
    /// 32 bit mode:
    ///     address overide prefix 0x67, memory addressing must be 16 bit if used
    /// 16 bit mode:
    ///     no address overide, memory addressing must be 16 bit if used
    Addr16,

    /// 64 bit mode:
    ///     address overide prefix 0x67, memory addressing must be 32 bit if used
    /// 32 bit mode:
    ///     no prefix
    /// 16 bit mode:
    ///     address overide prefix 0x67, memory addressing must be 32 bit if used
    Addr32,

    /// 64 bit mode:
    ///     no address overide, memory addressing must use 64 bit registers if used
    /// 32 bit mode:
    ///     invalid
    /// 16 bit mode:
    ///     invalid
    Addr64,

    pub fn is64Default(self: Overides) bool {
        return switch (self) {
            .ZO, .Addr64 => true,
            else => false,
        };
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
    /// No Fx prefix
    ///
    /// Indicates the use of F2/F3 prefixes (beyond those already part of the
    /// instructions opcode) are not allowed with the instruction.
    NFx,
    /// Mandatory prefix
    Mandatory,
    /// Opcode is composed of multiple separate instructions
    Compound,
};

pub const OpcodePrefix = enum(u8) {
    Any = 0x00,
    NFx = 0x01,
    _NP = 0x02,
    _66 = 0x66,
    _F3 = 0xF3,
    _F2 = 0xF2,
    _,

    pub fn opcode(op: u8) OpcodePrefix {
        return @intToEnum(OpcodePrefix, op);
    }
};

pub const CompoundInstruction = enum (u8) {
    None = 0x66,
    FWAIT = 0x9B,
};

pub const Opcode = struct {
    const max_length:u8 = 3;
    opcode: [max_length]u8 = undefined,
    len: u8 = 0,
    compound_op: CompoundInstruction = .None,
    prefix: OpcodePrefix = .Any,
    prefix_type: OpcodePrefixType = .Prefixable,
    reg_bits: ?u3 = null,

    pub fn asSlice(self: Opcode) []const u8 {
        return self.opcode[0..self.len];
    }

    pub fn prefixesAsSlice(self: Opcode) []const u8 {
        return self.prefixes[0..self.prefix_count];
    }

    pub fn isPrefixable(self: Opcode) bool {
        return self.prefix_type == .Prefixable;
    }

    pub fn hasPrefixByte(self: Opcode) bool {
        return switch (self.prefix_type) {
            .Mandatory, .Compound => true,
            else => false,
        };
    }

    fn create_generic(
        prefix: OpcodePrefix,
        opcode_bytes: [3]u8,
        len: u8,
        reg_bits: ?u3
    ) Opcode {
        const prefix_type = switch (prefix) {
            .Any => OpcodePrefixType.Prefixable,
            .NFx => OpcodePrefixType.NFx,
            ._NP => OpcodePrefixType.NP,
            ._66, ._F3, ._F2 => OpcodePrefixType.Mandatory,
            else => OpcodePrefixType.Compound,
        };
        return Opcode {
            .opcode = opcode_bytes,
            .len = len,
            .prefix = prefix,
            .prefix_type = prefix_type,
            .reg_bits = reg_bits,
        };
    }

    pub fn op1(byte0: u8) Opcode {
        return create_generic(.Any, [_]u8{byte0, 0, 0}, 1, null);
    }

    pub fn op2(byte0: u8, byte1: u8) Opcode {
        return create_generic(.Any, [_]u8{byte0, byte1, 0}, 2, null);
    }

    pub fn op3(byte0: u8, byte1: u8, byte2: u8) Opcode {
        return create_generic(.Any, [_]u8{byte0, byte1, byte2}, 3, null);
    }

    pub fn op1r(byte0: u8, reg_bits: u3) Opcode {
        return create_generic(.Any, [_]u8{byte0, 0, 0}, 1, reg_bits);
    }

    pub fn op2r(byte0: u8, byte1: u8, reg_bits: u3) Opcode {
        return create_generic(.Any, [_]u8{byte0, byte1, 0}, 2, reg_bits);
    }

    pub fn op3r(byte0: u8, byte1: u8, byte2: u8, reg_bits: u3) Opcode {
        return create_generic(.Any, [_]u8{byte0, byte1, byte2}, 3, reg_bits);
    }

    pub fn preOp1r(prefix: OpcodePrefix, byte0: u8, reg_bits: u3) Opcode {
        return create_generic(prefix, [_]u8{byte0, 0, 0}, 1, reg_bits);
    }

    pub fn preOp2r(prefix: OpcodePrefix, byte0: u8, byte1: u8, reg_bits: u3) Opcode {
        return create_generic(prefix, [_]u8{byte0, byte1, 0}, 2, reg_bits);
    }

    pub fn preOp3r(prefix: OpcodePrefix, byte0: u8, byte1: u8, byte2: u8, reg_bits: u3) Opcode {
        return create_generic(prefix, [_]u8{byte0, byte1, byte2}, 3, reg_bits);
    }

    pub fn preOp1(prefix: OpcodePrefix, byte0: u8) Opcode {
        return create_generic(prefix, [_]u8{byte0, 0, 0}, 1, null);
    }

    pub fn preOp2(prefix: OpcodePrefix, byte0: u8, byte1: u8) Opcode {
        return create_generic(prefix, [_]u8{byte0, byte1, 0}, 2, null);
    }

    pub fn preOp3(prefix: OpcodePrefix, byte0: u8, byte1: u8, byte2: u8) Opcode {
        return create_generic(prefix, [_]u8{byte0, byte1, byte2}, 3, null);
    }

    pub fn compOp1r(compound_op: CompoundInstruction, byte0: u8, reg_bits: u3) Opcode {
        var res = create_generic(.Any, [_]u8{byte0, 0, 0}, 1, reg_bits);
        res.compound_op = compound_op;
        return res;
    }

    pub fn compOp2(compound_op: CompoundInstruction, byte0: u8, byte1: u8) Opcode {
        var res = create_generic(.Any, [_]u8{byte0, byte1, 0}, 2, null);
        res.compound_op = compound_op;
        return res;
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
};

pub const PrefixGroup = enum {
    Group1 = 0,
    Group2 = 1,
    Group3 = 2,
    Group4 = 3,
    None,
};

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

    pub fn addSegmentOveride(self: *Prefixes, seg: Segment) void {
        switch (seg) {
            .ES => self.addPrefix(.SegmentES),
            .CS => self.addPrefix(.SegmentCS),
            .SS => self.addPrefix(.SegmentSS),
            .DS => self.addPrefix(.SegmentDS),
            .FS => self.addPrefix(.SegmentFS),
            .GS => self.addPrefix(.SegmentGS),
            .DefaultSeg => {},
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
        overides: Overides
    ) AsmError!void {
        switch (overides) {
            // zero overides
            .ZO => {},
            // size overide, 16 bit
            .Op16 => self.addPrefix(.OperandOveride),
            // size overide, 32 bit
            .Op32 => {},
            //
            .REX_W => rex_w.* = 1,

            .Addr16 => return AsmError.InvalidOperand,
            .Addr32 => {
                if (addressing_size == .None) {
                    self.addPrefix(.AddressOveride);
                } else if (addressing_size != .Bit32) {
                    // Using this mode the addressing size must match register size
                    return AsmError.InvalidOperand;
                }
            },
            .Addr64 => {
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
        overides: Overides
    ) AsmError!void {

        switch (overides) {
            // zero overides
            .ZO => {},
            // size overide, 16 bit
            .Op16 => self.addPrefix(.OperandOveride),
            // size overide, 32 bit
            .Op32 => {},
            //
            .REX_W => return AsmError.InvalidOperand,


            .Addr16 => {
                if (addressing_size == .None) {
                    self.addPrefix(.AddressOveride);
                } else if (addressing_size != .Bit16) {
                    // Using this mode the addressing size must match register size
                    return AsmError.InvalidOperand;
                }
            },
            .Addr32 => {
                if (addressing_size == .None) {
                    // okay
                } else if (addressing_size != .Bit32) {
                    // Using this mode the addressing size must match register size
                    return AsmError.InvalidOperand;
                }
            },
            .Addr64 => unreachable,
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
        overides: Overides
    ) AsmError!void {

        switch (overides) {
            // zero overides
            .ZO => {},
            // size overide, 16 bit
            .Op16 => {},
            // size overide, 32 bit
            .Op32 => self.addPrefix(.OperandOveride),
            //
            .REX_W => return AsmError.InvalidOperand,

            .Addr16 => {
                if (addressing_size == .None) {
                    // okay
                } else if (addressing_size != .Bit16) {
                    // Using this mode the addressing size must match register size
                    return AsmError.InvalidOperand;
                }
            },
            .Addr32 => {
                if (addressing_size == .None) {
                    self.addPrefix(.AddressOveride);
                } else if (addressing_size != .Bit32) {
                    // Using this mode the addressing size must match register size
                    return AsmError.InvalidOperand;
                }
            },
            .Addr64 => unreachable,
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
        overides: Overides
    ) AsmError!void {
        switch (mode) {
            .x86_16 => try self.addOverides16(rex_w, operand_size, addressing_size, overides),
            .x86_32 => try self.addOverides32(rex_w, operand_size, addressing_size, overides),
            .x64 => try self.addOverides64(rex_w, operand_size, addressing_size, overides),
        }
    }
};

