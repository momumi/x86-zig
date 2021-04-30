const std = @import("std");
const assert = std.debug.assert;

pub const Mode86 = enum {
    x86_16 = 0,
    x86_32 = 1,
    x64 = 2,
};

pub const AsmError = error{
    InvalidOperand,
    InvalidMode,
    InvalidImmediate,
    InvalidMemoryAddressing,
    InvalidRegisterCombination,
    InstructionTooLong,
    InvalidPrefixes,
};

pub const Segment = enum(u8) {
    ES = 0x00,
    CS,
    SS,
    DS,
    FS,
    GS = 0x05,

    DefaultSeg = 0x10,
};

pub const BitSize = enum(u8) {
    None = 0,
    Bit8 = 1,
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

    pub fn valueBytes(self: BitSize) u8 {
        return @enumToInt(self);
    }
};

pub const Overides = enum(u8) {
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
    /// 3DNow! opcode, uses imm8 after instruction to extend the opcode
    Postfix,
};

pub const OpcodePrefix = enum(u8) {
    Any = 0x00,
    NFx = 0x01,
    _NP = 0x02,
    _66 = 0x66,
    _F3 = 0xF3,
    _F2 = 0xF2,
    _,

    pub fn byte(op: u8) OpcodePrefix {
        return @intToEnum(OpcodePrefix, op);
    }
};

pub const CompoundInstruction = enum(u8) {
    None = 0x66,
    FWAIT = 0x9B,
};

pub const Opcode = struct {
    const max_length: u8 = 3;
    opcode: [max_length]u8 = undefined,
    len: u8 = 0,
    compound_op: CompoundInstruction = .None,
    /// Note: can also be used to store the postfix for 3DNow opcodes
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

    pub fn hasPostfix(self: Opcode) bool {
        return self.prefix_type == .Postfix;
    }

    pub fn getPostfix(self: Opcode) u8 {
        return @enumToInt(self.prefix);
    }

    /// Calculate how many bytes are in the opcode excluding mandatory prefixes.
    pub fn byteCount(self: Opcode) u8 {
        const extra: u8 = switch (self.prefix_type) {
            .Compound, .Postfix => 1,
            else => 0,
        };
        return self.len + extra;
    }

    fn create_generic(
        prefix: OpcodePrefix,
        opcode_bytes: [3]u8,
        len: u8,
        reg_bits: ?u3,
    ) Opcode {
        const prefix_type = switch (prefix) {
            .Any => OpcodePrefixType.Prefixable,
            .NFx => OpcodePrefixType.NFx,
            ._NP => OpcodePrefixType.NP,
            ._66, ._F3, ._F2 => OpcodePrefixType.Mandatory,
            else => OpcodePrefixType.Compound,
        };
        return Opcode{
            .opcode = opcode_bytes,
            .len = len,
            .prefix = prefix,
            .prefix_type = prefix_type,
            .reg_bits = reg_bits,
        };
    }

    pub fn op1(byte0: u8) Opcode {
        return create_generic(.Any, [_]u8{ byte0, 0, 0 }, 1, null);
    }

    pub fn op2(byte0: u8, byte1: u8) Opcode {
        return create_generic(.Any, [_]u8{ byte0, byte1, 0 }, 2, null);
    }

    pub fn op3(byte0: u8, byte1: u8, byte2: u8) Opcode {
        return create_generic(.Any, [_]u8{ byte0, byte1, byte2 }, 3, null);
    }

    pub fn op1r(byte0: u8, reg_bits: u3) Opcode {
        return create_generic(.Any, [_]u8{ byte0, 0, 0 }, 1, reg_bits);
    }

    pub fn op2r(byte0: u8, byte1: u8, reg_bits: u3) Opcode {
        return create_generic(.Any, [_]u8{ byte0, byte1, 0 }, 2, reg_bits);
    }

    pub fn op3r(byte0: u8, byte1: u8, byte2: u8, reg_bits: u3) Opcode {
        return create_generic(.Any, [_]u8{ byte0, byte1, byte2 }, 3, reg_bits);
    }

    pub fn preOp1r(prefix: OpcodePrefix, byte0: u8, reg_bits: u3) Opcode {
        return create_generic(prefix, [_]u8{ byte0, 0, 0 }, 1, reg_bits);
    }

    pub fn preOp2r(prefix: OpcodePrefix, byte0: u8, byte1: u8, reg_bits: u3) Opcode {
        return create_generic(prefix, [_]u8{ byte0, byte1, 0 }, 2, reg_bits);
    }

    pub fn preOp3r(prefix: OpcodePrefix, byte0: u8, byte1: u8, byte2: u8, reg_bits: u3) Opcode {
        return create_generic(prefix, [_]u8{ byte0, byte1, byte2 }, 3, reg_bits);
    }

    pub fn preOp1(prefix: OpcodePrefix, byte0: u8) Opcode {
        return create_generic(prefix, [_]u8{ byte0, 0, 0 }, 1, null);
    }

    pub fn preOp2(prefix: OpcodePrefix, byte0: u8, byte1: u8) Opcode {
        return create_generic(prefix, [_]u8{ byte0, byte1, 0 }, 2, null);
    }

    pub fn preOp3(prefix: OpcodePrefix, byte0: u8, byte1: u8, byte2: u8) Opcode {
        return create_generic(prefix, [_]u8{ byte0, byte1, byte2 }, 3, null);
    }

    pub fn compOp1r(compound_op: CompoundInstruction, byte0: u8, reg_bits: u3) Opcode {
        var res = create_generic(.Any, [_]u8{ byte0, 0, 0 }, 1, reg_bits);
        res.compound_op = compound_op;
        return res;
    }

    pub fn compOp2(compound_op: CompoundInstruction, byte0: u8, byte1: u8) Opcode {
        var res = create_generic(.Any, [_]u8{ byte0, byte1, 0 }, 2, null);
        res.compound_op = compound_op;
        return res;
    }

    pub fn op3DNow(byte0: u8, byte1: u8, imm_byte: u8) Opcode {
        var res = create_generic(OpcodePrefix.byte(imm_byte), [_]u8{ byte0, byte1, 0 }, 2, null);
        res.prefix_type = .Postfix;
        return res;
    }
};

pub const DataType = enum(u16) {
    NormalMemory = 0x0000,
    FarAddress = 0x01000,
    FloatingPoint = 0x0200,
    VoidPointer = 0x0300,
    Broadcast = 0x0400,
    Vector = 0x0500,
    Register = 0x0F00,
};

pub const DataSize = enum(u16) {
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
        return @intToEnum(BitSize, @intCast(u8, @enumToInt(self) & size_mask));
    }

    pub fn dataType(self: DataSize) DataType {
        return @intToEnum(DataType, @enumToInt(self) & tag_mask);
    }
};

pub const PrefixGroup = enum {
    const count = 6;

    Group0 = 0,
    Group1 = 1,
    Group2 = 2,
    Group3 = 3,
    Group4 = 4,
    Rex = 5,
    None,
};

pub const Prefix = enum(u8) {
    None = 0x00,

    // Group 1
    Lock = 0xF0,
    Repne = 0xF2,
    Rep = 0xF3,

    // Bnd = 0xF2, // BND prefix aliases with Repne
    // Xacquire = 0xF2, // XACQUIRE prefix aliases with Repne
    // Xrelease = 0xF3, // XRELEASE prefix aliases with Rep

    // Group 2
    // BranchTaken = 0x2E, // aliases with SegmentCS
    // BranchNotTaken = 0x3E, // aliases with SegmentDS
    SegmentCS = 0x2E,
    SegmentDS = 0x3E,
    SegmentES = 0x26,
    SegmentSS = 0x36,
    SegmentFS = 0x64,
    SegmentGS = 0x65,

    // Group 3
    OpSize = 0x66,

    // Group 4
    AddrSize = 0x67,

    REX = 0x40,
    REX_B = 0x41,
    REX_X = 0x42,
    REX_XB = 0x43,
    REX_R = 0x44,
    REX_RB = 0x45,
    REX_RX = 0x46,
    REX_RXB = 0x47,
    REX_W = 0x48,
    REX_WB = 0x49,
    REX_WX = 0x4A,
    REX_WXB = 0x4B,
    REX_WR = 0x4C,
    REX_WRB = 0x4D,
    REX_WRX = 0x4E,
    REX_WRXB = 0x4F,

    pub fn getGroupNumber(self: Prefix) u8 {
        return @enumToInt(self.getGroup());
    }

    pub fn getGroup(self: Prefix) PrefixGroup {
        return switch (self) {
            .Lock => .Group0,
            .Repne, .Rep => .Group1,

            .SegmentCS, .SegmentDS, .SegmentES, .SegmentSS, .SegmentFS, .SegmentGS => .Group2,

            .OpSize => .Group2,
            .AddrSize => .Group3,

            .REX, .REX_B, .REX_X, .REX_XB, .REX_R, .REX_RB, .REX_RX, .REX_RXB, .REX_W, .REX_WB, .REX_WX, .REX_WXB, .REX_WR, .REX_WRB, .REX_WRX, .REX_WRXB => .Rex,

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
        return std.mem.asBytes(&self.prefixes)[0..self.len];
    }

    pub fn addOverides64(
        self: *Prefixes,
        rex_w: *u1,
        addressing_size: BitSize,
        overides: Overides,
    ) AsmError!void {
        switch (overides) {
            // zero overides
            .ZO => {},
            // size overide, 16 bit
            .Op16 => self.addPrefix(.OpSize),
            // size overide, 32 bit
            .Op32 => {},
            //
            .REX_W => rex_w.* = 1,

            .Addr16 => return AsmError.InvalidOperand,
            .Addr32 => {
                if (addressing_size == .None) {
                    self.addPrefix(.AddrSize);
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
            .Bit32 => self.addPrefix(.AddrSize),
            .Bit64 => {}, // default, no prefix needed
            else => return AsmError.InvalidOperand,
        }
    }

    pub fn addOverides32(
        self: *Prefixes,
        rex_w: *u1,
        addressing_size: BitSize,
        overides: Overides,
    ) AsmError!void {
        switch (overides) {
            // zero overides
            .ZO => {},
            // size overide, 16 bit
            .Op16 => self.addPrefix(.OpSize),
            // size overide, 32 bit
            .Op32 => {},
            //
            .REX_W => return AsmError.InvalidOperand,

            .Addr16 => {
                if (addressing_size == .None) {
                    self.addPrefix(.AddrSize);
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
            .Bit16 => self.addPrefix(.AddrSize),
            .Bit32 => {}, // default
            else => return AsmError.InvalidOperand,
        }
    }

    pub fn addOverides16(
        self: *Prefixes,
        rex_w: *u1,
        addressing_size: BitSize,
        overides: Overides,
    ) AsmError!void {
        switch (overides) {
            // zero overides
            .ZO => {},
            // size overide, 16 bit
            .Op16 => {},
            // size overide, 32 bit
            .Op32 => self.addPrefix(.OpSize),
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
                    self.addPrefix(.AddrSize);
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
            .Bit32 => self.addPrefix(.AddrSize), // default
            else => return AsmError.InvalidOperand,
        }
    }

    pub fn addOverides(
        self: *Prefixes,
        mode: Mode86,
        rex_w: *u1,
        addressing_size: BitSize,
        overides: Overides,
    ) AsmError!void {
        switch (mode) {
            .x86_16 => try self.addOverides16(rex_w, addressing_size, overides),
            .x86_32 => try self.addOverides32(rex_w, addressing_size, overides),
            .x64 => try self.addOverides64(rex_w, addressing_size, overides),
        }
    }
};

pub const EncodingHint = enum(u8) {
    NoHint,
    /// For AVX instructions use 2 Byte VEX encoding
    Vex2,
    /// For AVX instructions use 3 Byte VEX encoding
    Vex3,
    /// For AVX instructions use EVEX encoding
    Evex,
};

pub const PrefixingTechnique = enum {
    AddPrefixes,
    ExactPrefixes,
};

pub const EncodingControl = struct {
    const max_prefix_count = 14;

    prefixes: [max_prefix_count]Prefix = [1]Prefix{.None} ** max_prefix_count,
    encoding_hint: EncodingHint = .NoHint,

    /// Provide the prefixes in the exact order given and do not generate any
    /// other prefixes automatically.
    prefixing_technique: PrefixingTechnique = .AddPrefixes,

    pub fn init(
        hint: EncodingHint,
        prefixing_technique: PrefixingTechnique,
        prefixes: []const Prefix,
    ) EncodingControl {
        var res: EncodingControl = undefined;
        assert(prefixes.len <= max_prefix_count);
        for (prefixes) |pre, i| {
            res.prefixes[i] = pre;
        }
        if (prefixes.len < max_prefix_count) {
            res.prefixes[prefixes.len] = .None;
        }
        res.encoding_hint = hint;
        res.prefixing_technique = prefixing_technique;
        return res;
    }

    pub fn useExactPrefixes(self: EncodingControl) bool {
        return self.prefixing_technique == .ExactPrefixes;
    }

    pub fn prefix(pre: Prefix) EncodingControl {
        var res = EncodingControl{};
        res.prefixes[0] = pre;
        return res;
    }

    pub fn prefix2(pre1: Prefix, pre2: Prefix) EncodingControl {
        var res = EncodingControl{};
        res.prefixes[0] = pre1;
        res.prefixes[1] = pre2;
        return res;
    }

    pub fn encodingHint(hint: EncodingHint) EncodingControl {
        var res = EncodingControl{};
        res.encoding_hint = hint;
        return res;
    }

    /// If multiple prefixes from the same group are used then only the one
    /// closest to the instruction is actually effective.
    pub fn calcEffectivePrefixes(self: EncodingControl) [PrefixGroup.count]Prefix {
        var res = [1]Prefix{.None} ** PrefixGroup.count;

        for (self.prefixes) |pre| {
            if (pre == .None) {
                break;
            }
            const group = pre.getGroupNumber();
            res[group] = pre;
        }
        return res;
    }

    pub fn prefixCount(self: EncodingControl) u8 {
        var res: u8 = 0;
        for (self.prefixes) |pre| {
            if (pre == .None) {
                break;
            }
            res += 1;
        }
        return res;
    }

    pub fn hasNecessaryPrefixes(self: EncodingControl, prefixes: Prefixes) bool {
        const effective_prefixes = self.calcEffectivePrefixes();
        for (prefixes.prefixes) |pre| {
            if (pre == .None) {
                break;
            }

            const group = pre.getGroupNumber();
            if (effective_prefixes[group] != pre) {
                return false;
            }
        }
        return true;
    }
};
