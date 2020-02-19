const std = @import("std");

pub usingnamespace(@import("types.zig"));

const Operand = @import("operand.zig").Operand;
const Register = @import("register.zig").Register;
const Machine = @import("machine.zig").Machine;

pub const AvxMagic = enum (u8) {
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
    mm: u2 = 0,
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
        return (
            self.R == 1
            or self.X == 1
            or self.B == 1
            or self.W == 1
            or self.R_ == 1
            or self.V_ == 1
            or self.vvvv > 7
            or (self.is4 != null and self.is4.? > 7)
        );
    }

    /// Generate EVEX prefix bytes
    ///
    ///       7   6   5   4   3   2   1   0
    /// 62  | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 0 |
    /// P0: | R | X | B | R'| 0 | 0 | m | m |
    /// P1: | W | v | v | v | v | 1 | p | p |
    /// P2: | z | L'| L | b | V'| a | a | a |
    pub fn makeEvex(self: AvxResult) [4]u8 {
        const P0: u8 = (
            (@as(u8, ~self.R) << 7)
            | (@as(u8, ~self.X) << 6)
            | (@as(u8, ~self.B) << 5)
            | (@as(u8, ~self.R_) << 4)
            // | (0b00 << 2)
            | (@as(u8, self.mm) << 0)
        );
        const P1: u8 = (
            (@as(u8, self.W) << 7)
            | (@as(u8, ~self.vvvv) << 3)
            | (@as(u8, 1) << 2)
            | (@as(u8, self.pp) << 0)
        );
        const P2: u8 = (
            (@as(u8, self.z) << 7)
            | (@as(u8, self.L_) << 6)
            | (@as(u8, self.L) << 5)
            | (@as(u8, self.b) << 4)
            | (@as(u8, ~self.V_) << 3)
            | (@as(u8, self.aaa) << 0)
        );
        return [4]u8 { 0x62, P0, P1, P2 };
    }

    /// Generate VEX2 prefix bytes
    ///
    ///       7   6   5   4   3   2   1   0
    /// C5  | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 1 |
    /// P0: | R | v | v | v | v | L | p | p |
    pub fn makeVex2(self: AvxResult) [2]u8 {
        const P0: u8 = (
            (@as(u8, ~self.R) << 7)
            | (@as(u8, ~self.vvvv) << 3)
            | (@as(u8, self.L) << 2)
            | (@as(u8, self.pp) << 0)
        );
        return [2]u8 { 0xC5, P0 };
    }

    /// Generate VEX3 prefix bytes
    ///
    ///       7   6   5   4   3   2   1   0
    /// C4  | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
    /// P0: | R | X | B | 0 | 0 | 0 | m | m |
    /// P1: | W | v | v | v | v | L | p | p |
    pub fn makeVex3(self: AvxResult) [3]u8 {
        const P0: u8 = (
            (@as(u8, ~self.R) << 7)
            | (@as(u8, ~self.X) << 6)
            | (@as(u8, ~self.B) << 5)
            // | (0b000 << 2)
            | (@as(u8, self.mm) << 0)
        );
        const P1: u8 = (
            (@as(u8, self.W) << 7)
            | (@as(u8, ~self.vvvv) << 3)
            | (@as(u8, self.L) << 2)
            | (@as(u8, self.pp) << 0)
        );
        return [3]u8 { 0xC4, P0, P1 };
    }

};

pub const AvxEncoding = enum {
    VEX,
    XOP,
    EVEX,
};

pub const VexPrefix = enum(u2) {
    /// No prefix
    NP = 0b00,
    _66 = 0b01,
    _F3 = 0b10,
    _F2 = 0b11,
};

// NOTE: Technically this is 5 bit, but 3 high bits are reserved and should be 0
pub const VexEscape = enum (u2) {
    _0F = 0b01,
    _0F38 = 0b10,
    _0F3A = 0b11,
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

pub const MaskRegister = enum (u3) {
    NoMask = 0b000,
    K1 = 0b001,
    K2,
    K3,
    K4,
    K5,
    K6,
    K7 = 0b111,
};

pub const ZeroOrMerge = enum (u1) {
    Merge = 0,
    Zero = 1,
};

pub const RegisterPredicate = struct {
    reg: Register,
    mask: MaskRegister,
    z: ZeroOrMerge,

    pub fn create(r: Register, k: MaskRegister, z: ZeroOrMerge) RegisterPredicate {
        return RegisterPredicate {
            .reg = r,
            .mask = k,
            .z = z,
        };
    }
};

pub const RegisterSae = struct {
    reg: Register,
    sae: SuppressAllExceptions,

    pub fn create(r: Register, sae: SuppressAllExceptions) RegisterSae {
        return RegisterSae {
            .reg = r,
            .sae = sae,
        };
    }
};

pub const SuppressAllExceptions = enum (u3) {
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

pub const AvxOpcode = struct {
    encoding: AvxEncoding,
    vec_len: EvexLength,
    prefix: VexPrefix,
    escape: VexEscape,
    opcode: u8,
    reg_bits: ?u3 = null,
    vex_w: VexW,
    immSourceOp: bool = false,

    pub fn encode(
        self: AvxOpcode,
        machine: Machine,
        vec1: ?*const Operand,
        vec2: ?*const Operand,
        vec3: ?*const Operand,
    ) AsmError!AvxResult {
        var res = AvxResult{};

        res.pp = @enumToInt(self.prefix);
        res.mm = @enumToInt(self.escape);

        switch (self.vec_len) {
            .L128, .LZ => res.L = 0,
            .L256, .L1 => res.L = 1,

            .L512 => {
                res.L = 0;
                res.L_ = 1;
            },

            .LIG => {
                res.L = @intCast(u1, (machine.l_fill >> 0) & 0x01);
                res.L_ = @intCast(u1, (machine.l_fill >> 1) & 0x01);
            },

            ._11 => unreachable,

            .LRC => {
                // TODO:
                unreachable;
            },
        }

        if (vec1) |v| {
            switch (v.*) {
                .RegPred => |reg_pred| {
                    res.aaa = @enumToInt(reg_pred.mask);
                    res.z = @enumToInt(reg_pred.z);
                },

                else => {},
            }
        }

        const vec_num1: u8 = if (vec1) |v| x: {
            break :x switch (v.*) {
                .Reg => v.Reg.number(),
                .RegPred => v.RegPred.reg.number(),
                .RegSae => v.RegSae.reg.number(),
                else => unreachable,
            };
        } else if (self.reg_bits) |reg_bits| x: {
            break :x reg_bits;
        } else x: {
            break :x 0;
        };
        res.R = @intCast(u1, (vec_num1 & 0x08) >> 3);
        res.R_ = @intCast(u1, (vec_num1 & 0x10) >> 4);

        const vec_num2 = if (vec2) |vec| vec.Reg.number() else 0;
        res.vvvv = @intCast(u4, (vec_num2 & 0x0f));
        res.V_ = @intCast(u1, (vec_num2 & 0x10) >> 4);

        if (vec3) |vec| {
            switch (vec.*) {
                .Reg => |reg| {
                    const num3 = reg.number();
                    res.B = @intCast(u1, (num3 & 0x08) >> 3);
                    res.X = @intCast(u1, (num3 & 0x10) >> 4);
                },
                .Rm => |rm| switch (rm) {
                    .Reg => |reg| {
                        const num3 = reg.number();
                        res.B = @intCast(u1, (num3 & 0x08) >> 3);
                        res.X = @intCast(u1, (num3 & 0x10) >> 4);
                    },

                    else => {
                        // TODO: probably want to handle this better.  This value
                        // also gets computed in Machine.encodeAvx().
                        const modrm = try rm.encodeReg(machine.mode, .AX, .ZO);
                        res.X = modrm.rex_x;
                        res.B = modrm.rex_b;

                        switch (rm.operandType()) {
                            .rm_m32bcst, .rm_m64bcst => res.b = 1,
                            else => {},
                        }
                        // unreachable;
                    },
                },

                .RegSae => |reg_sae| {
                    switch (reg_sae.sae) {
                        .AE => {},
                        .SAE => {
                            res.b = 1;
                        },
                        else => {
                            res.b = 1;
                            const LL_ = @enumToInt(reg_sae.sae);
                            res.L = @intCast(u1, (LL_ >> 0) & 0x01);
                            res.L_ = @intCast(u1, (LL_ >> 1) & 0x01);
                        },
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
            .W => { unreachable; }, // TODO
        }

        switch (self.encoding) {
            // TODO: some way to force 3 byte Vex encoding
            .VEX => {
                std.debug.assert(
                    (res.L_ == 0)
                    and (res.R_ == 0)
                    and (vec2 == null or res.V_ == 0)
                    and (res.aaa == 0)
                    and (res.b == 0)
                    and (res.z == 0)
                );
                if (res.X == 0 and res.B == 0 and res.W == 0 and res.mm == 0b01) {
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
        op: u8
    ) AvxOpcode {
        return evex_r(len, pre, esc, w, op, null);
    }


    pub fn evex_r(
        len: EvexLength,
        pre: VexPrefix,
        esc: VexEscape,
        w: VexW,
        op: u8,
        reg: ?u3,
    ) AvxOpcode {
        return AvxOpcode {
            .encoding = .EVEX,
            .vec_len = len,
            .prefix = pre,
            .escape = esc,
            .vex_w = w,
            .opcode = op,
            .reg_bits = reg,
            .immSourceOp = false,
        };
    }

    pub fn vex(len: VexLength, pre: VexPrefix, esc: VexEscape, w: VexW, op: u8) AvxOpcode {
        return vex_r(len, pre, esc, w, op, null, false);
    }

    pub fn vexr(len: VexLength, pre: VexPrefix, esc: VexEscape, w: VexW, op: u8, r: u3) AvxOpcode {
        return vex_r(len, pre, esc, w, op, r, false);
    }

    pub fn vex_r(
        len: VexLength,
        pre: VexPrefix,
        esc: VexEscape,
        w: VexW,
        op: u8,
        reg: ?u3,
        immS4: bool,
    ) AvxOpcode {
        return vex_common(.VEX, len, pre, esc, w, op, reg, immS4);
    }


    pub fn xop(len: VexLength, pre: VexPrefix, esc: VexEscape, w: VexW, op: u8,) AvxOpcode {
        return xop_r(len, pre, esc, w, op, null, false);
    }

    pub fn xop_r(
        len: VexLength,
        pre: VexPrefix,
        esc: VexEscape,
        w: VexW,
        op: u8,
        reg: ?u3,
        immS4: bool,
    ) AvxOpcode {
        return vex_common(.XOP, len, pre, esc, w, op, reg, immS4);
    }

    pub fn vex_common(
        enc: AvxEncoding,
        len: VexLength,
        pre: VexPrefix,
        esc: VexEscape,
        w: VexW,
        op: u8,
        reg: ?u3,
        immS4: bool,
    ) AvxOpcode {
        return AvxOpcode {
            .encoding = enc,
            .vec_len = @intToEnum(EvexLength, @enumToInt(len)),
            .prefix = pre,
            .escape = esc,
            .vex_w = w,
            .opcode = op,
            .reg_bits = reg,
            .immSourceOp = immS4,
        };
    }

    pub fn format(
        self: AvxOpcode,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        context: var,
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
        switch (self.escape) {
            ._0F => try output(context, ".0F."),
            ._0F3A => try output(context, ".0F3A."),
            ._0F38 => try output(context, ".0F38."),
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
