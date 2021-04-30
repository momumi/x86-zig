const std = @import("std");

pub usingnamespace @import("types.zig");

const x86 = @import("machine.zig");

const Operand = x86.operand.Operand;
const OperandType = x86.operand.OperandType;
const ModRm = x86.operand.ModRm;
const ModRmResult = x86.operand.ModRmResult;
const Register = x86.register.Register;
const Machine = x86.Machine;

pub const AvxMagic = enum(u8) {
    Vex2 = 0xC4,
    Vex3 = 0xC5,
    Xop = 0x8F,
    Evex = 0x62,

    pub fn value(self: AvxMagic) u8 {
        return @enumToInt(self);
    }
};

/// NOTE: We don't store any of the values like R/X/B inverted, they only
/// get inverted when they get encoded.
pub const AvxResult = struct {
    encoding: AvxMagic = undefined,
    /// R'
    R_: u1 = 0,
    R: u1 = 0,
    X: u1 = 0,
    B: u1 = 0,
    W: u1 = 0,
    map: u5 = 0,
    /// V'
    V_: u1 = 0,
    vvvv: u4 = 0b0000,
    /// L'
    L_: u1 = 0,
    L: u1 = 0,
    pp: u2 = 0b00,
    is4: ?u4 = null,
    z: u1 = 0,
    b: u1 = 0,
    aaa: u3 = 0,

    pub fn needs64Bit(self: AvxResult) bool {
        return self.R == 1 or
            self.X == 1 or
            self.B == 1 or
            self.W == 1 or
            self.R_ == 1 or
            self.V_ == 1 or
            self.vvvv > 7 or
            (self.is4 != null and self.is4.? > 7);
    }

    pub fn addVecLen(self: *AvxResult, machine: Machine, vec_len: EvexLength) void {
        switch (vec_len) {
            .L128, .LZ => self.L = 0,
            .L256, .L1 => self.L = 1,

            .L512 => {
                self.L = 0;
                self.L_ = 1;
            },

            .LIG => {
                self.L = @intCast(u1, (machine.l_fill >> 0) & 0x01);
                self.L_ = @intCast(u1, (machine.l_fill >> 1) & 0x01);
            },

            ._11 => unreachable,

            .LRC => {
                // TODO:
                unreachable;
            },
        }
    }

    pub fn addModRm(self: *AvxResult, modrm: *const ModRmResult) void {
        self.X = modrm.rex_x;
        self.B = modrm.rex_b;
        self.V_ |= modrm.evex_v;

        switch (modrm.data_size) {
            .DWORD_BCST, .QWORD_BCST => self.b = 1,
            else => {},
        }
    }

    pub fn addPred(self: *AvxResult, mask: MaskRegister, z: ZeroOrMerge) void {
        self.aaa = @enumToInt(mask);
        self.z = @enumToInt(z);
    }

    pub fn addSae(self: *AvxResult, sae: SuppressAllExceptions) void {
        switch (sae) {
            .AE => {},
            .SAE => {
                self.b = 1;
            },
            else => {
                self.b = 1;
                const LL_ = @enumToInt(sae);
                self.L = @intCast(u1, (LL_ >> 0) & 0x01);
                self.L_ = @intCast(u1, (LL_ >> 1) & 0x01);
            },
        }
    }

    pub fn addVecR(self: *AvxResult, num: u8) void {
        self.R = @intCast(u1, (num & 0x08) >> 3);
        self.R_ = @intCast(u1, (num & 0x10) >> 4);
    }

    pub fn addVecV(self: *AvxResult, num: u8) void {
        self.vvvv = @intCast(u4, (num & 0x0f));
        self.V_ = @intCast(u1, (num & 0x10) >> 4);
    }

    pub fn addVecRm(self: *AvxResult, reg: Register) void {
        const reg_num = reg.number();
        self.B = @intCast(u1, (reg_num & 0x08) >> 3);
        self.X = @intCast(u1, (reg_num & 0x10) >> 4);
    }

    /// Generate EVEX prefix bytes
    ///
    ///       7   6   5   4   3   2   1   0
    /// 62  | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 0 |
    /// P0: | R | X | B | R'| 0 | 0 | m | m |
    /// P1: | W | v | v | v | v | 1 | p | p |
    /// P2: | z | L'| L | b | V'| a | a | a |
    pub fn makeEvex(self: AvxResult) [4]u8 {
        const P0: u8 = (@as(u8, ~self.R) << 7) |
            (@as(u8, ~self.X) << 6) |
            (@as(u8, ~self.B) << 5) |
            (@as(u8, ~self.R_) << 4) |
            // (0b00 << 2) |
            (@as(u8, self.map) << 0);
        const P1: u8 = (@as(u8, self.W) << 7) |
            (@as(u8, ~self.vvvv) << 3) |
            (@as(u8, 1) << 2) |
            (@as(u8, self.pp) << 0);
        const P2: u8 = (@as(u8, self.z) << 7) |
            (@as(u8, self.L_) << 6) |
            (@as(u8, self.L) << 5) |
            (@as(u8, self.b) << 4) |
            (@as(u8, ~self.V_) << 3) |
            (@as(u8, self.aaa) << 0);
        return [4]u8{ 0x62, P0, P1, P2 };
    }

    /// Generate VEX2 prefix bytes
    ///
    ///       7   6   5   4   3   2   1   0
    /// C5  | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 1 |
    /// P0: | R | v | v | v | v | L | p | p |
    pub fn makeVex2(self: AvxResult) [2]u8 {
        const P0: u8 = (@as(u8, ~self.R) << 7) | (@as(u8, ~self.vvvv) << 3) | (@as(u8, self.L) << 2) | (@as(u8, self.pp) << 0);
        return [2]u8{ 0xC5, P0 };
    }

    fn makeCommonXopVex3(self: AvxResult, magic: u8) [3]u8 {
        const P0: u8 = (@as(u8, ~self.R) << 7) |
            (@as(u8, ~self.X) << 6) |
            (@as(u8, ~self.B) << 5) |
            // (0b000 << 2) |
            (@as(u8, self.map) << 0);
        const P1: u8 = (@as(u8, self.W) << 7) |
            (@as(u8, ~self.vvvv) << 3) |
            (@as(u8, self.L) << 2) |
            (@as(u8, self.pp) << 0);
        return [3]u8{ magic, P0, P1 };
    }

    /// Generate VEX3 prefix bytes
    ///
    ///       7   6   5   4   3   2   1   0
    /// C4  | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
    /// P0: | R | X | B | 0 | 0 | 0 | m | m |
    /// P1: | W | v | v | v | v | L | p | p |
    pub fn makeVex3(self: AvxResult) [3]u8 {
        return self.makeCommonXopVex3(0xC4);
    }

    /// Generate XOP prefix bytes
    ///
    ///       7   6   5   4   3   2   1   0
    /// 8F  | 1 | 0 | 0 | 0 | 1 | 1 | 1 | 1 |
    /// P0: | R | X | B | 0 | 0 | 0 | m | m |
    /// P1: | W | v | v | v | v | L | p | p |
    pub fn makeXop(self: AvxResult) [3]u8 {
        return self.makeCommonXopVex3(0x8F);
    }
};

pub const AvxEncoding = enum {
    VEX,
    XOP,
    EVEX,
};

pub const VexPrefix = enum(u2) {
    /// No prefix
    _NP = 0b00,
    _66 = 0b01,
    _F3 = 0b10,
    _F2 = 0b11,
};

// NOTE: Technically this is 5 bit, but 3 high bits are reserved and should be 0
pub const VexEscape = enum(u2) {
    _0F = 0b01,
    _0F38 = 0b10,
    _0F3A = 0b11,
};

pub const XopMapSelect = enum(u5) {
    _08h = 0b01000,
    _09h = 0b01001,
    _0Ah = 0b01010,
};

pub const VexW = enum {
    W0 = 0,
    W1 = 1,
    /// W ignored
    WIG,
    /// W acts as REX.W
    W,
};

pub const VexLength = enum(u8) {
    L128 = 0b0,
    L256 = 0b1,
    /// L ignored
    LIG = 0x80,
    /// L = 0
    LZ = 0x81,
    /// L = 1
    L1 = 0x82,
};

pub const EvexLength = enum(u8) {
    L128 = 0b00,
    L256 = 0b01,
    L512 = 0b10,
    _11 = 0b11,
    /// LL ignored
    LIG = 0x80,
    /// LZ: LL = 0 (used in VEX, not normaly used in EVEX)
    LZ = 0x81,
    /// L1: LL = 1 (used in VEX, not normaly used in EVEX)
    L1 = 0x82,
    /// LL is used for rounding control
    LRC = 0x83,
};

pub const MaskRegister = enum(u3) {
    NoMask = 0b000,
    K1 = 0b001,
    K2,
    K3,
    K4,
    K5,
    K6,
    K7 = 0b111,
};

pub const ZeroOrMerge = enum(u1) {
    Merge = 0,
    Zero = 1,
};

pub const RegisterPredicate = struct {
    reg: Register,
    mask: MaskRegister,
    z: ZeroOrMerge,

    pub fn create(r: Register, k: MaskRegister, z: ZeroOrMerge) RegisterPredicate {
        return RegisterPredicate{
            .reg = r,
            .mask = k,
            .z = z,
        };
    }
};

pub const RmPredicate = struct {
    rm: ModRm,
    mask: MaskRegister,
    z: ZeroOrMerge,

    pub fn create(rm: ModRm, k: MaskRegister, z: ZeroOrMerge) RmPredicate {
        return RmPredicate{
            .rm = rm,
            .mask = k,
            .z = z,
        };
    }
};

pub const RegisterSae = struct {
    reg: Register,
    sae: SuppressAllExceptions,

    pub fn create(r: Register, sae: SuppressAllExceptions) RegisterSae {
        return RegisterSae{
            .reg = r,
            .sae = sae,
        };
    }
};

pub const SuppressAllExceptions = enum(u3) {
    /// Round toward nearest and SAE
    RN_SAE = 0b00,
    /// Round toward -inf and SAE
    RD_SAE = 0b01,
    /// Round toward +inf and SAE
    RU_SAE = 0b10,
    /// Round toward 0 and SAE
    RZ_SAE = 0b11,
    /// Allow exceptions (AE)
    AE,
    /// Suppress all exceptions (SAE)
    SAE,
};

pub const TupleType = enum(u8) {
    None,
    NoMem,
    Full,
    Half,
    Tuple1Scalar,
    Tuple1Fixed,
    Tuple2,
    Tuple4,
    Tuple8,
    FullMem,
    HalfMem,
    QuarterMem,
    EighthMem,
    Mem128,
    Movddup,
};

/// Calultate N for disp8*N compressed displacement in AVX512
///
/// NOTE: this does not take into account EVEX.b broadcast bit.  If a broadcast
/// is used, should pick N according to:
///     * m32bcst -> N = 4
///     * m64bcst -> N = 8
pub fn calcDispMultiplier(op: AvxOpcode, op_type: OperandType) u8 {
    if (op.encoding != .EVEX) {
        return 1;
    }

    const full: u8 = switch (op.vec_len) {
        .L128 => 16,
        .L256 => 32,
        .L512 => 64,
        else => 0,
    };

    const tup_size: u8 = switch (op.vex_w) {
        .W0 => 4,
        .W1 => 8,
        else => 0,
    };

    const result: u8 = switch (op.tuple_type) {
        .None => unreachable,
        .NoMem => 0,
        .Tuple1Scalar => switch (op_type.getMemClass()) {
            .mem8 => 1,
            .mem16 => 2,
            .mem32 => 4,
            .mem64 => 8,
            else => tup_size,
        },
        .Tuple1Fixed => switch (op_type.getMemClass()) {
            .mem32 => @as(u8, 4),
            .mem64 => @as(u8, 8),
            else => unreachable,
        },
        .Tuple2 => tup_size * 2,
        .Tuple4 => tup_size * 4,
        .Tuple8 => tup_size * 8,
        .Full, .FullMem => full,
        .Half, .HalfMem => full / 2,
        .QuarterMem => full / 4,
        .EighthMem => full / 8,
        .Mem128 => 16,
        .Movddup => switch (op.vec_len) {
            .L128 => @as(u8, 8),
            .L256 => @as(u8, 32),
            .L512 => @as(u8, 64),
            else => unreachable,
        },
    };

    return result;
}

pub const AvxOpcode = struct {
    encoding: AvxEncoding,
    vec_len: EvexLength,
    prefix: VexPrefix,
    map_select: u5,
    opcode: u8,
    reg_bits: ?u3 = null,
    vex_w: VexW,
    tuple_type: TupleType = .None,

    pub fn encode(
        self: AvxOpcode,
        machine: Machine,
        vec1_r: ?*const Operand,
        vec2_v: ?*const Operand,
        vec3_rm: ?*const Operand,
        modrm_result: ?*const ModRmResult,
    ) AsmError!AvxResult {
        var res = AvxResult{};

        res.pp = @enumToInt(self.prefix);
        res.map = self.map_select;
        res.addVecLen(machine, self.vec_len);

        // handle (E)VEX modrm.reg register
        if (vec1_r) |v| {
            switch (v.*) {
                .Reg => |reg| {
                    res.addVecR(reg.number());
                },
                .RegPred => |reg_pred| {
                    res.addVecR(reg_pred.reg.number());
                    res.addPred(reg_pred.mask, reg_pred.z);
                },
                .RegSae => |reg_sae| {
                    res.addVecR(reg_sae.reg.number());
                    res.addSae(reg_sae.sae);
                },
                else => unreachable,
            }
        } else if (self.reg_bits) |reg_bits| {
            res.addVecR(reg_bits);
        } else {
            res.addVecR(0);
        }

        // handle (E)VEX.V'vvvv register
        if (vec2_v) |v| {
            switch (v.*) {
                .Reg => |reg| {
                    res.addVecV(reg.number());
                },
                .RegPred => |reg_pred| {
                    res.addVecV(reg_pred.reg.number());
                    res.addPred(reg_pred.mask, reg_pred.z);
                },
                else => unreachable,
            }
        } else {
            res.addVecV(0);
        }

        // handle (E)VEX modrm.rm register
        if (vec3_rm) |vec| {
            switch (vec.*) {
                .Reg => |reg| {
                    res.addVecRm(reg);
                },

                .Rm => |rm| switch (rm) {
                    .Reg => |reg| res.addVecRm(reg),
                    else => res.addModRm(modrm_result.?),
                },

                .RegSae => |reg_sae| {
                    res.addVecRm(reg_sae.reg);
                    res.addSae(reg_sae.sae);
                },

                .RmPred => |rm_pred| {
                    res.addPred(rm_pred.mask, rm_pred.z);
                    switch (rm_pred.rm) {
                        .Reg => |reg| res.addVecRm(reg),
                        else => res.addModRm(modrm_result.?),
                    }
                },
                else => unreachable,
            }
        }

        if (machine.mode != .x64 and res.needs64Bit()) {
            return AsmError.InvalidMode;
        }

        switch (self.vex_w) {
            .WIG => res.W = machine.w_fill,
            .W0 => res.W = 0,
            .W1 => res.W = 1,
            .W => unreachable, // TODO
        }

        switch (self.encoding) {
            // TODO: some way to force 3 byte Vex encoding
            .VEX => {
                std.debug.assert((res.L_ == 0) and
                    (res.R_ == 0) and
                    (vec2_v == null or res.V_ == 0) and
                    (res.aaa == 0) and
                    (res.b == 0) and
                    (res.z == 0));

                if (res.X == 0 and res.B == 0 and res.W == 0 and res.map == 0b01) {
                    res.encoding = .Vex2;
                } else {
                    res.encoding = .Vex3;
                }
            },

            .EVEX => res.encoding = .Evex,
            .XOP => res.encoding = .Xop,
        }

        return res;
    }

    pub fn evex(
        len: EvexLength,
        pre: VexPrefix,
        esc: VexEscape,
        w: VexW,
        op: u8,
        tuple: TupleType,
    ) AvxOpcode {
        return evexr(len, pre, esc, w, op, null, tuple);
    }

    pub fn evexr(
        len: EvexLength,
        pre: VexPrefix,
        esc: VexEscape,
        w: VexW,
        op: u8,
        reg: ?u3,
        tuple: TupleType,
    ) AvxOpcode {
        return AvxOpcode{
            .encoding = .EVEX,
            .vec_len = len,
            .prefix = pre,
            .map_select = @enumToInt(esc),
            .vex_w = w,
            .opcode = op,
            .reg_bits = reg,
            .tuple_type = tuple,
        };
    }

    pub fn vex(len: VexLength, pre: VexPrefix, esc: VexEscape, w: VexW, op: u8) AvxOpcode {
        return vex_r(len, pre, esc, w, op, null);
    }

    pub fn vexr(len: VexLength, pre: VexPrefix, esc: VexEscape, w: VexW, op: u8, r: u3) AvxOpcode {
        return vex_r(len, pre, esc, w, op, r);
    }

    pub fn vex_r(
        len: VexLength,
        pre: VexPrefix,
        esc: VexEscape,
        w: VexW,
        op: u8,
        reg: ?u3,
    ) AvxOpcode {
        return vex_common(.VEX, len, pre, @enumToInt(esc), w, op, reg);
    }

    pub fn xop(
        len: VexLength,
        pre: VexPrefix,
        map: XopMapSelect,
        w: VexW,
        op: u8,
    ) AvxOpcode {
        return xop_r(len, pre, map, w, op, null);
    }

    pub fn xopr(len: VexLength, pre: VexPrefix, map: XopMapSelect, w: VexW, op: u8, r: u3) AvxOpcode {
        return xop_r(len, pre, map, w, op, r);
    }

    pub fn xop_r(
        len: VexLength,
        pre: VexPrefix,
        map: XopMapSelect,
        w: VexW,
        op: u8,
        reg: ?u3,
    ) AvxOpcode {
        return vex_common(.XOP, len, pre, @enumToInt(map), w, op, reg);
    }

    pub fn vex_common(
        enc: AvxEncoding,
        len: VexLength,
        pre: VexPrefix,
        map_select: u5,
        w: VexW,
        op: u8,
        reg: ?u3,
    ) AvxOpcode {
        return AvxOpcode{
            .encoding = enc,
            .vec_len = @intToEnum(EvexLength, @enumToInt(len)),
            .prefix = pre,
            .map_select = map_select,
            .vex_w = w,
            .opcode = op,
            .reg_bits = reg,
        };
    }

    pub fn format(
        self: AvxOpcode,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        context: anytype,
        comptime FmtError: type,
        output: fn (@TypeOf(context), []const u8) FmtError!void,
    ) FmtError!void {
        try output(context, @tagName(self.encoding));
        try output(context, ".");
        try output(context, @tagName(self.vec_len));
        switch (self.prefix) {
            .NP => {},
            ._66 => try output(context, ".66"),
            ._F3 => try output(context, ".F3"),
            ._F2 => try output(context, ".F2"),
        }
        switch (self.map_select) {
            0b01 => try output(context, ".0F."),
            0b10 => try output(context, ".0F3A."),
            0b11 => try output(context, ".0F38."),

            0b01000 => try output(context, ".map(08h)."),
            0b01001 => try output(context, ".map(09h)."),
            0b01010 => try output(context, ".map(0Ah)."),
        }
        try output(context, @tagName(self.vex_w));
        try std.fmt.format(context, FmtError, output, " {X}", .{self.opcode});
        if (self.reg_bits) |r| {
            try std.fmt.format(context, FmtError, output, " /{}", .{self.opcode});
        } else {
            try output(context, " /r");
        }
    }
};
