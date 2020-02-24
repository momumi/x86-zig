const std = @import("std");

const minInt = std.math.minInt;
const maxInt = std.math.maxInt;

pub const register = @import("register.zig");
pub const machine = @import("machine.zig");
pub const avx = @import("avx.zig");

usingnamespace(@import("types.zig"));

const Register = register.Register;


pub const OperandType = enum(u32) {
    const num_pos = 0;

    pub const Class = enum (u8) {
        const Type = u8;
        const mask = 0xff;
        const pos = 8;

        reg8 = 0x00,
        reg16 = 0x01,
        reg32 = 0x02,
        reg64 = 0x03,

        reg_seg,
        reg_st,
        reg_cr,
        reg_dr,
        reg_bnd,
        reg_k,
        mm,
        xmm,
        ymm,
        zmm,

        mem,
        imm,
        moffs,
        ptr16_16,
        ptr16_32,
        _void,

        invalid = 0xfe,
        none = 0xff,

        pub fn asTag(self: Class) u16 {
            return @intCast(u16, @enumToInt(self)) << Class.pos;
        }
    };

    pub const MemClass = enum (u4) {
        const pos = 16;
        const Type = u4;
        const mask = 0x0f;

        no_mem = 0,
        mem_void,
        mem8,
        mem16,
        mem32,
        mem64,
        mem80,
        mem128,
        mem256,
        mem512,
        mem16_16,
        mem16_32,
        mem16_64,
    };

    pub const RmClass = enum (u1) {
        const pos = 20;
        const Type = u1;
        const mask = 0x01;

        no_rm = 0,
        rm = 1,
    };

    pub const Modifier = enum (u3) {
        const pos = 21;
        const Type = u3;
        const mask = 0x07;

        no_mod = 0b000,
        k      = 0b001,
        kz     = 0b010,
        sae    = 0b011,
        er     = 0b100,
    };

    pub const Broadcast = enum(u2) {
        const pos = 24;
        const Type = u2;
        const mask = 0x03;

        no_bcst = 0b00,
        m32bcst = 0b01,
        m64bcst = 0b10,
    };

    pub const SpecialCase = enum (u2) {
        const pos = 26;
        const Type = u2;
        const mask = 0x03;

        no_special = 0,
        low16 = 1,
        match_larger_versions = 2,
    };

    pub fn create(
        num: u8,
        class: Class,
        mem: MemClass,
        rm: RmClass,
        mod: Modifier,
        bcst: Broadcast,
        special: SpecialCase,
    ) u32 {
        return (
            @intCast(u32, num) << num_pos
            | @intCast(u32, @enumToInt(class)) << Class.pos
            | @intCast(u32, @enumToInt(mem)) << MemClass.pos
            | @intCast(u32, @enumToInt(rm)) << RmClass.pos
            | @intCast(u32, @enumToInt(mod)) << Modifier.pos
            | @intCast(u32, @enumToInt(bcst)) << Broadcast.pos
            | @intCast(u32, @enumToInt(special)) << SpecialCase.pos
        );
    }

    pub fn create_basic(num: u8, reg_class: Class) u32 {
        return create(num, reg_class, .no_mem, .no_rm, .no_mod, .no_bcst, .no_special);
    }

    pub fn create_rm(num: u8, reg_class: Class, mem: MemClass) u32 {
        return create(num, reg_class, mem, .rm, .no_mod, .no_bcst, .no_special);
    }

    fn _getCommon(self: OperandType, comptime T: type) T {
        return @intToEnum(T, @intCast(T.Type, (@enumToInt(self) >> T.pos) & T.mask));
    }

    pub fn getNum(self: OperandType) u8 {
        return @intCast(u8, (@enumToInt(self) >> num_pos) & 0xff);
    }

    pub fn getClass(self: OperandType) Class {
        return self._getCommon(Class);
    }

    pub fn getMemClass(self: OperandType) MemClass {
        return self._getCommon(MemClass);
    }

    pub fn getRmClass(self: OperandType) RmClass {
        return self._getCommon(RmClass);
    }

    pub fn getModifier(self: OperandType) Modifier {
        return self._getCommon(Modifier);
    }

    pub fn getBroadcast(self: OperandType) Broadcast {
        return self._getCommon(Broadcast);
    }

    pub fn getSpecialCase(self: OperandType) SpecialCase {
        return self._getCommon(SpecialCase);
    }

    fn matchRmClass(template: OperandType, other: OperandType) bool {
        // 0 = no_rm
        // 1 = rm
        return @enumToInt(other.getRmClass()) <= @enumToInt(template.getRmClass());
    }

    fn matchModifer(template: OperandType, other: OperandType) bool {
        // no_mod = 0b000,
        // k      = 0b001,
        // kz     = 0b010,
        // sae    = 0b011,
        // er     = 0b100,
        const temp_mod = template.getModifier();
        const other_mod = other.getModifier();

        return (
            temp_mod == other_mod
            or (temp_mod == .kz and other_mod == .k)
            or (other_mod == .no_mod)
        );
    }

    reg8 = create_basic(0, .reg8),
    reg_al,
    reg_cl,
    reg_dl,
    reg_bl,

    reg16 = create_basic(0, .reg16),
    reg_ax,
    reg_cx,
    reg_dx,
    reg_bx,

    reg32 = create_basic(0, .reg32),
    reg_eax,
    reg_ecx,
    reg_edx,
    reg_ebx,

    reg64 = create_basic(0, .reg64),
    reg_rax,
    reg_rcx,
    reg_rdx,
    reg_rbx,

    reg_seg = create_basic(0, .reg_seg),
    reg_es = create_basic(1, .reg_seg),
    reg_cs,
    reg_ss,
    reg_ds,
    reg_fs,
    reg_gs = create_basic(6, .reg_seg),

    reg_st = create_basic(0, .reg_st),
    reg_st0,
    reg_st1,
    reg_st2,
    reg_st3,
    reg_st4,
    reg_st5,
    reg_st6,
    reg_st7 = create_basic(8, .reg_st),

    reg_cr = create_basic(0, .reg_cr),
    reg_cr0,
    reg_cr1,
    reg_cr2,
    reg_cr3,
    reg_cr4,
    reg_cr5,
    reg_cr6,
    reg_cr7,
    reg_cr8,
    reg_cr9,
    reg_cr10,
    reg_cr11,
    reg_cr12,
    reg_cr13,
    reg_cr14,
    reg_cr15 = create_basic(16, .reg_cr),

    reg_dr = create_basic(0, .reg_dr),
    reg_dr0,
    reg_dr1,
    reg_dr2,
    reg_dr3,
    reg_dr4,
    reg_dr5,
    reg_dr6,
    reg_dr7,
    reg_dr8,
    reg_dr9,
    reg_dr10,
    reg_dr11,
    reg_dr12,
    reg_dr13,
    reg_dr14,
    reg_dr15 = create_basic(16, .reg_dr),

    mm = create_basic(0, .mm),
    mm0,
    mm1,
    mm2,
    mm3,
    mm4,
    mm5,
    mm6,
    mm7 = create_basic(8, .mm),

    xmm = create_basic(0, .xmm),
    xmm0,
    xmm1,
    xmm2,
    xmm3,
    xmm4,
    xmm5,
    xmm6,
    xmm7,
    xmm8,
    xmm9,
    xmm10,
    xmm11,
    xmm12,
    xmm13,
    xmm14,
    xmm15,
    xmm16,
    xmm17,
    xmm18,
    xmm19,
    xmm20,
    xmm21,
    xmm22,
    xmm23,
    xmm24,
    xmm25,
    xmm26,
    xmm27,
    xmm28,
    xmm29,
    xmm30,
    xmm31 = create_basic(32, .xmm),

    ymm = create_basic(0, .ymm),
    ymm0,
    ymm1,
    ymm2,
    ymm3,
    ymm4,
    ymm5,
    ymm6,
    ymm7,
    ymm8,
    ymm9,
    ymm10,
    ymm11,
    ymm12,
    ymm13,
    ymm14,
    ymm15,
    ymm16,
    ymm17,
    ymm18,
    ymm19,
    ymm20,
    ymm21,
    ymm22,
    ymm23,
    ymm24,
    ymm25,
    ymm26,
    ymm27,
    ymm28,
    ymm29,
    ymm30,
    ymm31 = create_basic(32, .ymm),

    zmm = create_basic(0, .zmm),
    zmm0,
    zmm1,
    zmm2,
    zmm3,
    zmm4,
    zmm5,
    zmm6,
    zmm7,
    zmm8,
    zmm9,
    zmm10,
    zmm11,
    zmm12,
    zmm13,
    zmm14,
    zmm15,
    zmm16,
    zmm17,
    zmm18,
    zmm19,
    zmm20,
    zmm21,
    zmm22,
    zmm23,
    zmm24,
    zmm25,
    zmm26,
    zmm27,
    zmm28,
    zmm29,
    zmm30,
    zmm31 = create_basic(32, .zmm),

    reg_k = create_basic(0, .reg_k),
    reg_k0,
    reg_k1,
    reg_k2,
    reg_k3,
    reg_k4,
    reg_k5,
    reg_k6,
    reg_k7 = create_basic(8, .reg_k),

    bnd = create_basic(0, .reg_bnd),
    bnd0,
    bnd1,
    bnd2,
    bnd3 = create_basic(4, .reg_bnd),

    rm8 = create_rm(0, .reg8, .mem8),
    rm_reg8 = create_rm(0, .reg8, .no_mem),
    rm_mem8 = create_rm(0, .mem, .mem8),

    rm16 = create_rm(0, .reg16, .mem16),
    rm_reg16 = create_rm(0, .reg16, .no_mem),
    rm_mem16 = create_rm(0, .mem, .mem16),

    rm32 = create_rm(0, .reg32, .mem32),
    rm_reg32 = create_rm(0, .reg32, .no_mem),
    rm_mem32 = create_rm(0, .mem, .mem32),

    rm64 = create_rm(0, .reg64, .mem64),
    rm_reg64 = create_rm(0, .reg64, .no_mem),
    rm_mem64 = create_rm(0, .mem, .mem64),

    // matches memory of any type
    rm_mem = create_rm(0, .mem, .mem_void),
    rm_mem80 = create_rm(0, .mem, .mem80),
    rm_mem128 = create_rm(0, .mem, .mem128),
    rm_mem256 = create_rm(0, .mem, .mem256),
    rm_mem512 = create_rm(0, .mem, .mem512),
    rm_m32bcst = create(0, .mem, .no_mem, .rm, .no_mod, .m32bcst, .no_special),
    rm_m64bcst = create(0, .mem, .no_mem, .rm, .no_mod, .m64bcst, .no_special),

    m16_16 = create_rm(0, .mem, .mem16_16),
    m16_32 = create_rm(0, .mem, .mem16_32),
    m16_64 = create_rm(0, .mem, .mem16_64),

    rm_st = create_rm(0, .reg_st, .no_mem),
    rm_seg = create_rm(0, .reg_seg, .no_mem),
    rm_cr = create_rm(0, .reg_cr, .no_mem),
    rm_dr = create_rm(0, .reg_dr, .no_mem),
    rm_k = create_rm(0, .reg_k, .no_mem),
    rm_bnd = create_rm(0, .reg_bnd, .no_mem),
    rm_mm = create_rm(0, .mm, .no_mem),
    rm_xmml = create(0, .xmm, .no_mem, .rm, .no_mod, .no_bcst, .low16),
    rm_ymml = create(0, .ymm, .no_mem, .rm, .no_mod, .no_bcst, .low16),
    rm_xmm = create_rm(0, .xmm, .no_mem),
    rm_ymm = create_rm(0, .ymm, .no_mem),
    rm_zmm = create_rm(0, .zmm, .no_mem),
    rm_xmm_kz = create(0, .xmm, .no_mem, .rm,    .kz,     .no_bcst, .no_special),
    rm_ymm_kz = create(0, .ymm, .no_mem, .rm,    .kz,     .no_bcst, .no_special),
    rm_zmm_kz = create(0, .zmm, .no_mem, .rm,    .kz,     .no_bcst, .no_special),

    moffs = create_basic(0, .moffs),
    moffs8,
    moffs16,
    moffs32,
    moffs64,

    _void = create_basic(0, ._void),
    _void8,
    _void16,
    _void32,
    _void64,

    invalid = create_basic(0, .invalid),
    none = create_basic(0, .none),

    imm = create_basic(0, .imm),
    // imm_1,
    imm8 = create_basic(2, .imm),
    imm16,
    imm32,
    imm64,

    imm_any = create(0, .imm, .no_mem, .no_rm, .no_mod, .no_bcst, .match_larger_versions),
    imm_1,
    imm8_any = create(2, .imm, .no_mem, .no_rm, .no_mod, .no_bcst, .match_larger_versions),
    imm16_any,
    imm32_any,
    imm64_any,

    ptr16_16 = create_basic(0, .ptr16_16),
    ptr16_32 = create_basic(0, .ptr16_32),

    mm_m64 = create(0, .mm, .mem64, .rm, .no_mod, .no_bcst, .no_special),

    bnd_m64 = create(0, .reg_bnd, .mem64, .rm, .no_mod, .no_bcst, .no_special),
    bnd_m128 = create(0, .reg_bnd, .mem128, .rm, .no_mod, .no_bcst, .no_special),

    reg32_er     = create(0, .reg32, .no_mem, .rm, .er, .no_bcst, .no_special),
    reg64_er     = create(0, .reg64, .no_mem, .rm, .er, .no_bcst, .no_special),
    rm32_er      = create(0, .reg32, .mem32,  .rm, .er, .no_bcst, .no_special),
    rm64_er      = create(0, .reg64, .mem64,  .rm, .er, .no_bcst, .no_special),
    rm_mem64_kz  = create(0, .mem,   .mem64,  .rm, .kz, .no_bcst, .no_special),
    rm_mem128_kz = create(0, .mem,   .mem128, .rm, .kz, .no_bcst, .no_special),
    rm_mem256_kz = create(0, .mem,   .mem256, .rm, .kz, .no_bcst, .no_special),
    rm_mem512_kz = create(0, .mem,   .mem512, .rm, .kz, .no_bcst, .no_special),

    reg_k_k  = create(0, .reg_k, .no_mem, .no_rm, .k,      .no_bcst, .no_special),
    reg_k_kz = create(0, .reg_k, .no_mem, .no_rm, .kz,     .no_bcst, .no_special),
    k_m8     = create(0, .reg_k, .mem8,   .rm,    .no_mod, .no_bcst, .no_special),
    k_m16    = create(0, .reg_k, .mem16,  .rm,    .no_mod, .no_bcst, .no_special),
    k_m32    = create(0, .reg_k, .mem32,  .rm,    .no_mod, .no_bcst, .no_special),
    k_m64    = create(0, .reg_k, .mem64,  .rm,    .no_mod, .no_bcst, .no_special),

    /// Only matches xmm[0..15]
    xmml      = create(0, .xmm, .no_mem, .no_rm, .no_mod, .no_bcst, .low16),
    xmml_m16  = create(0, .xmm, .mem16,  .rm,    .no_mod, .no_bcst, .low16),
    xmml_m32  = create(0, .xmm, .mem32,  .rm,    .no_mod, .no_bcst, .low16),
    xmml_m64  = create(0, .xmm, .mem64,  .rm,    .no_mod, .no_bcst, .low16),
    xmml_m128 = create(0, .xmm, .mem128, .rm,    .no_mod, .no_bcst, .low16),

    /// Only matches ymm[0..15]
    ymml      = create(0, .ymm, .no_mem, .no_rm, .no_mod, .no_bcst, .low16),
    ymml_m256 = create(0, .ymm, .mem256, .rm,    .no_mod, .no_bcst, .low16),

    /// xmm[0..31]
    xmm_k                = create(0, .xmm, .no_mem, .no_rm, .k,      .no_bcst, .no_special),
    xmm_kz               = create(0, .xmm, .no_mem, .no_rm, .kz,     .no_bcst, .no_special),
    xmm_sae              = create(0, .xmm, .no_mem, .no_rm, .sae,    .no_bcst, .no_special),
    xmm_er               = create(0, .xmm, .no_mem, .no_rm, .er,     .no_bcst, .no_special),
    xmm_m16              = create(0, .xmm, .mem16,  .rm,    .no_mod, .no_bcst, .no_special),
    xmm_m32              = create(0, .xmm, .mem32,  .rm,    .no_mod, .no_bcst, .no_special),
    xmm_m32_er           = create(0, .xmm, .mem32,  .rm,    .er,     .no_bcst, .no_special),
    xmm_m32_sae          = create(0, .xmm, .mem32,  .rm,    .sae,    .no_bcst, .no_special),
    xmm_m64              = create(0, .xmm, .mem64,  .rm,    .no_mod, .no_bcst, .no_special),
    xmm_m64_er           = create(0, .xmm, .mem64,  .rm,    .er,     .no_bcst, .no_special),
    xmm_m64_sae          = create(0, .xmm, .mem64,  .rm,    .sae,    .no_bcst, .no_special),
    xmm_m64_m32bcst      = create(0, .xmm, .mem64,  .rm,    .no_mod, .m32bcst, .no_special),
    xmm_m128             = create(0, .xmm, .mem128, .rm,    .no_mod, .no_bcst, .no_special),
    xmm_m128_kz          = create(0, .xmm, .mem128, .rm,    .kz,     .no_bcst, .no_special),
    xmm_m128_sae         = create(0, .xmm, .mem128, .rm,    .sae,    .no_bcst, .no_special),
    xmm_m128_er          = create(0, .xmm, .mem128, .rm,    .er,     .no_bcst, .no_special),
    xmm_m128_m32bcst     = create(0, .xmm, .mem128, .rm,    .no_mod, .m32bcst, .no_special),
    xmm_m128_m32bcst_sae = create(0, .xmm, .mem128, .rm,    .sae,    .m32bcst, .no_special),
    xmm_m128_m32bcst_er  = create(0, .xmm, .mem128, .rm,    .er,     .m32bcst, .no_special),
    xmm_m128_m64bcst     = create(0, .xmm, .mem128, .rm,    .no_mod, .m64bcst, .no_special),
    xmm_m128_m64bcst_sae = create(0, .xmm, .mem128, .rm,    .sae,    .m64bcst, .no_special),
    xmm_m128_m64bcst_er  = create(0, .xmm, .mem128, .rm,    .er,     .m64bcst, .no_special),

    /// ymm[0..31]
    ymm_k                = create(0, .ymm, .no_mem, .no_rm, .k,      .no_bcst, .no_special),
    ymm_kz               = create(0, .ymm, .no_mem, .no_rm, .kz,     .no_bcst, .no_special),
    ymm_sae              = create(0, .ymm, .no_mem, .no_rm, .sae,    .no_bcst, .no_special),
    ymm_er               = create(0, .ymm, .no_mem, .no_rm, .er,     .no_bcst, .no_special),
    ymm_m256             = create(0, .ymm, .mem256, .rm,    .no_mod, .no_bcst, .no_special),
    ymm_m256_kz          = create(0, .ymm, .mem256, .rm,    .kz,     .no_bcst, .no_special),
    ymm_m256_sae         = create(0, .ymm, .mem256, .rm,    .sae,    .no_bcst, .no_special),
    ymm_m256_er          = create(0, .ymm, .mem256, .rm,    .er,     .no_bcst, .no_special),
    ymm_m256_m32bcst     = create(0, .ymm, .mem256, .rm,    .no_mod, .m32bcst, .no_special),
    ymm_m256_m32bcst_sae = create(0, .ymm, .mem256, .rm,    .sae,    .m32bcst, .no_special),
    ymm_m256_m32bcst_er  = create(0, .ymm, .mem256, .rm,    .er,     .m32bcst, .no_special),
    ymm_m256_m64bcst     = create(0, .ymm, .mem256, .rm,    .no_mod, .m64bcst, .no_special),
    ymm_m256_m64bcst_sae = create(0, .ymm, .mem256, .rm,    .sae,    .m64bcst, .no_special),
    ymm_m256_m64bcst_er  = create(0, .ymm, .mem256, .rm,    .er,     .m64bcst, .no_special),

    /// Zmm[0..31]
    zmm_k                = create(0, .zmm, .no_mem, .no_rm, .k,      .no_bcst, .no_special),
    zmm_kz               = create(0, .zmm, .no_mem, .no_rm, .kz,     .no_bcst, .no_special),
    zmm_sae              = create(0, .zmm, .no_mem, .no_rm, .sae,    .no_bcst, .no_special),
    zmm_er               = create(0, .zmm, .no_mem, .no_rm, .er,     .no_bcst, .no_special),
    zmm_m512             = create(0, .zmm, .mem512, .rm,    .no_mod, .no_bcst, .no_special),
    zmm_m512_kz          = create(0, .zmm, .mem512, .rm,    .kz,     .no_bcst, .no_special),
    zmm_m512_sae         = create(0, .zmm, .mem512, .rm,    .sae,    .no_bcst, .no_special),
    zmm_m512_er          = create(0, .zmm, .mem512, .rm,    .er,     .no_bcst, .no_special),
    zmm_m512_m32bcst     = create(0, .zmm, .mem512, .rm,    .no_mod, .m32bcst, .no_special),
    zmm_m512_m32bcst_sae = create(0, .zmm, .mem512, .rm,    .sae,    .m32bcst, .no_special),
    zmm_m512_m32bcst_er  = create(0, .zmm, .mem512, .rm,    .er,     .m32bcst, .no_special),
    zmm_m512_m64bcst     = create(0, .zmm, .mem512, .rm,    .no_mod, .m64bcst, .no_special),
    zmm_m512_m64bcst_sae = create(0, .zmm, .mem512, .rm,    .sae,    .m64bcst, .no_special),
    zmm_m512_m64bcst_er  = create(0, .zmm, .mem512, .rm,    .er,     .m64bcst, .no_special),

    _,

    fn isLowReg(self: OperandType) bool {
        const max_reg_num = 15 + 1;
        return (@enumToInt(self) & 0xff) <= max_reg_num ;
    }

    pub fn fromRegister(reg: Register) OperandType {
        if (reg.registerType() != .General) {
            return @intToEnum(OperandType, @enumToInt(reg) + 1);
        }

        // General purpose register
        if (reg.number() <= Register.BX.number()) {
            const size_tag: u16 = @as(u16, @enumToInt(reg) & 0x30) << 4;
            const num_tag: u16 = @as(u16, @enumToInt(reg) & 0x03) + 1;
            return @intToEnum(OperandType, size_tag | num_tag);
        } else {
            return switch (reg.bitSize()) {
                .Bit8 => OperandType.reg8,
                .Bit16 => OperandType.reg16,
                .Bit32 => OperandType.reg32,
                .Bit64 => OperandType.reg64,
                else => unreachable,
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

    pub fn fromAddress(self: Address) OperandType {
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

    pub fn fromRegisterPredicate(reg_pred: avx.RegisterPredicate) OperandType {
        return switch (reg_pred.z) {
            .Merge => switch (reg_pred.reg.registerType()) {
                .XMM => OperandType.xmm_k,
                .YMM => OperandType.ymm_k,
                .ZMM => OperandType.zmm_k,
                .Mask => OperandType.reg_k_k,
                else => OperandType.invalid,
            },
            .Zero => switch (reg_pred.reg.registerType()) {
                .XMM => OperandType.xmm_kz,
                .YMM => OperandType.ymm_kz,
                .ZMM => OperandType.zmm_kz,
                .Mask => OperandType.reg_k_kz,
                else => OperandType.invalid,
            },
        };
    }

    pub fn fromModRm(self: ModRm) OperandType {
        return switch (self) {
            .Reg => |reg| switch (reg.registerType()) {
                .General => switch (reg.bitSize()) {
                    .Bit8 => OperandType.rm_reg8,
                    .Bit16 => OperandType.rm_reg16,
                    .Bit32 => OperandType.rm_reg32,
                    .Bit64 => OperandType.rm_reg64,
                    else => unreachable,
                },

                .Float => OperandType.reg_st,

                .Segment => OperandType.rm_seg,
                .Control => OperandType.rm_cr,
                .Debug => OperandType.rm_dr,
                .MMX => OperandType.rm_mm,
                .XMM => if (reg.number() <= 15) OperandType.rm_xmml else OperandType.rm_xmm,
                .YMM => if (reg.number() <= 15) OperandType.rm_ymml else OperandType.rm_ymm,
                .ZMM => OperandType.rm_zmm,
                .Mask => OperandType.rm_k,
                .Bound => OperandType.rm_bnd,
            },

            .Mem,
            .Mem16,
            .Sib,
            .Rel => switch (self.operandDataSize()) {
                .Void => OperandType.rm_mem,
                .BYTE => OperandType.rm_mem8,
                .WORD => OperandType.rm_mem16,
                .DWORD  => OperandType.rm_mem32,
                .QWORD  => OperandType.rm_mem64,
                .TBYTE  => OperandType.rm_mem80,
                .OWORD, .XMM_WORD => OperandType.rm_mem128,
                .YMM_WORD => OperandType.rm_mem256,
                .ZMM_WORD => OperandType.rm_mem512,
                .DWORD_BCST => OperandType.rm_m32bcst,
                .QWORD_BCST => OperandType.rm_m64bcst,
                .FAR_WORD  => OperandType.m16_16,
                .FAR_DWORD  => OperandType.m16_32,
                .FAR_QWORD  => OperandType.m16_64,

                // TODO:
                else => unreachable,
            },
        };
    }


    pub fn fromRmPredicate(rm_pred: avx.RmPredicate) OperandType {
        const modifier = switch (rm_pred.z) {
            .Zero => OperandType.Modifier.kz,
            else => OperandType.Modifier.k,
        };

        const base_type = OperandType.fromModRm(rm_pred.rm);
        const mod_tag = @intCast(u32, @enumToInt(modifier)) << Modifier.pos;
        const mod_type = @enumToInt(base_type) | mod_tag;
        return @intToEnum(OperandType, mod_type);
    }

    pub fn fromSae(reg_sae: avx.RegisterSae) OperandType {
        return switch (reg_sae.sae) {
            .SAE, .AE => switch (reg_sae.reg.registerType()) {
                .XMM => OperandType.xmm_sae,
                .YMM => OperandType.ymm_sae,
                .ZMM => OperandType.zmm_sae,
                else => unreachable,
            },
            .RN_SAE, .RD_SAE, .RU_SAE, .RZ_SAE => switch (reg_sae.reg.registerType()) {
                .General => switch (reg_sae.reg.bitSize()) {
                    .Bit32 => OperandType.reg32_er,
                    .Bit64 => OperandType.reg64_er,
                    else => unreachable,
                },
                .XMM => OperandType.xmm_er,
                .YMM => OperandType.ymm_er,
                .ZMM => OperandType.zmm_er,
                else => unreachable,
            },
        };
    }

    pub fn matchTemplate(template: OperandType, other: OperandType) bool {
        const num = template.getNum();
        const class = template.getClass();

        const other_num = other.getNum();
        const other_special = other.getSpecialCase();

        // if the template and operand type have matching classes
        const class_match = (class == other.getClass());

        // if the OperandType have matching register numbers:
        // eg: template .xmm matches xmm0..xmm31
        // eg: template .xmm1 matches only .xmm1
        const num_match = (num == 0) or (num == other.getNum());

        // if template is rm type, then it can match other OperandType with or without rm
        // if template is no_rm type, 
        // eg: rm8 matches either .rm_reg8 or .reg8
        // eg: reg8 matches only .reg8 but not .rm_reg8
        const rm_match = matchRmClass(template, other);

        // if template allows memory operand and other OperandType matches that memory type
        // eg: .xmm_m128 matches .rm_mem128
        const mem_match = (other.getClass() == .mem and (template.getMemClass() == other.getMemClass()));

        // if template allows a broadcast and other OperandType is a matching broadcast type
        // eg: .xmm_m128_m32bcst matches .rm_m32bcst
        const bcst_match = (
            other.getClass() == .mem
            and (template.getBroadcast() != .no_bcst)
            and (template.getBroadcast() == other.getBroadcast())
        );

        // For user supplied immediates without an explicit size are allowed to match
        // against larger immediate sizes:
        //      * .imm8_any  <-> imm8,  imm16, imm32, imm64
        //      * .imm16_any <-> imm16, imm32, imm64
        //      * .imm32_any <-> imm32, imm64
        //      * .imm64_any <-> imm64
        // NOTE: .match_larger_versions only used for immediates
        const special_match = (other_special == .match_larger_versions and num >= other_num);

        // Matches register number <= 15.
        // eg: .xmml (.low16) matches .xmm0..15
        // eg: .xmm (.no_mod) matches .xmm0..31
        const invalid_size = (template.getSpecialCase() == .low16 and other_num != 0 and other_num > 16);

        // eg: rm_xmml (num = 0 and .low16 and .rm)
        const invalid_size_rm = (
            other_num == 0 and template.getSpecialCase() == .low16 and other.getSpecialCase() != .low16
        );

        // modifier type matches ie sae/er/mask
        // eg: .xmm_kz matches .xmm and .xmm_k and .xmm_kz
        // eg: .reg_k_k matches .reg_k and reg_k_k
        // eg: .xmm_sae matches .xmm and .xmm_sae
        // eg: .rm32_er matches .rm_reg8 and rm_reg8_er and rm_mem32 and rm_mem32_er
        const modifier_match = matchModifer(template, other);

        const extra_critera = class != .mem and !invalid_size and !invalid_size_rm;
        const normal_class_match = (num_match and class_match and rm_match and modifier_match and extra_critera);

        const special_class_match = (special_match and class_match);
        const mem_class_match = mem_match or bcst_match;

        return normal_class_match or special_class_match or mem_class_match;
    }
};

/// Possible displacement sizes for 16 bit addressing
const MemDisp16Size = enum(u8) {
    None = 0,
    Disp8 = 1,
    Disp16 = 2,
};

/// Possible displacement sizes for 32 and 64 bit addressing
const MemDispSize = enum(u8) {
    None = 0,
    Disp8 = 1,
    Disp32 = 4,
};

/// Generic struct representing a memory displacement
fn memDispCommon(comptime DispSize: type, comptime IntType: type, comptime disp_max: DispSize) type {
    return struct {
        displacement: IntType = 0,
        size: DispSize = .None,

        pub fn create(dis_size: DispSize, dis: IntType) @This() {
            return @This() {
                .displacement = dis,
                .size = dis_size,
            };
        }

        pub fn disp(dis: IntType) @This() {
            if (dis == 0) {
                return @This().create(.None, 0);
            } else if (minInt(i8) <= dis and dis <= maxInt(i8)) {
                return @This().create(.Disp8, dis);
            } else {
                return @This().create(disp_max, dis);
            }
        }

        pub fn value(self: @This()) IntType {
            return self.displacement;
        }

        pub fn dispSize(self: @This()) DispSize {
            return self.size;
        }

        pub fn bitSize(self: @This()) BitSize {
            return @intToEnum(BitSize, @enumToInt(self.size));
        }
    };
}

/// Encodes a displacement for 16 bit addressing
const MemDisp16 = memDispCommon(MemDisp16Size, i16, .Disp16);

/// Encodes a displacement for 32 and 64 bit addressing
const MemDisp = memDispCommon(MemDispSize, i32, .Disp32);

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

/// Encodes memory addressing of the form: [BP,BX] + [DI,SI] + disp0/8/16
const Memory16Bit = struct {
    /// Base register either BP or BX
    base: ?Register,
    /// Index register either DI or SI
    index: ?Register,
    /// 0, 8 or 16 bit memory displacement
    disp: MemDisp16,
    /// Size of the data this memory address points to
    data_size: DataSize,
    /// Segment register to offset the memory address
    segment: Segment,

    pub fn hasValidRegisters(self: Memory16Bit) bool {
        if (self.base) |base| {
            switch (base) {
                .BX, .BP => {},
                else => return false,
            }
        }
        if (self.index) |index| {
            switch (index) {
                .DI, .SI => {},
                else => return false,
            }
        }
        return true;
    }
};

/// Encodes memory addressing of the form: [r/m + disp]
const Memory = struct {
    reg: Register,
    /// 0, 8 or 32 bit memory displacement
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
    disp: i32,
    data_size: DataSize,
    segment: Segment,

    pub fn relMemory(seg: Segment, data_size: DataSize, reg: RelRegister, disp: i32) RelMemory {
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
    disp_bit_size: BitSize = .Bit0,
    disp: i32 = 0,
    segment: Segment = .DefaultSeg,

    pub fn rexRequirements(self: *@This(), reg: Register, default_size: DefaultSize) void {
        // Don't need to check this if the instruction uses 64 bit by default
        if (!default_size.is64Default()) {
            self.needs_rex = self.needs_rex or reg.needsRex();
        }
        self.needs_no_rex = self.needs_no_rex or reg.needsNoRex();
    }

    pub fn addMemDisp(self: *@This(), disp: var) void {
        self.disp_bit_size = disp.bitSize();
        self.disp = disp.value();
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
    Mem16: Memory16Bit,
    Mem: Memory,
    Sib: MemorySib,
    Rel: RelMemory,

    pub fn operandSize(self: @This()) BitSize {
        return switch (self) {
            .Reg => |reg| reg.bitSize(),
            .Mem16 => |mem| mem.data_size.bitSize(),
            .Mem => |mem| mem.data_size.bitSize(),
            .Sib => |sib| sib.data_size.bitSize(),
            .Rel => |reg| reg.data_size.bitSize(),
        };
    }

    pub fn operandDataSize(self: @This()) DataSize {
        return switch (self) {
            .Reg => |reg| reg.dataSize(),
            .Mem16 => |mem| mem.data_size,
            .Mem => |mem| mem.data_size,
            .Sib => |sib| sib.data_size,
            .Rel => |reg| reg.data_size,
        };
    }

    pub fn operandDataType(self: @This()) DataType {
        return switch (self) {
            .Reg => |reg| DataType.Register,
            .Mem16 => |mem| mem.data_size.dataType(),
            .Mem => |mem| mem.data_size.dataType(),
            .Sib => |sib| sib.data_size.dataType(),
            .Rel => |reg| reg.data_size.dataType(),
        };
    }

    pub fn encodeOpcodeRm(self: @This(), mode: Mode86, reg_bits: u3, default_size: DefaultSize) AsmError!ModRmResult {
        const fake_reg = @intToEnum(Register, reg_bits + @enumToInt(Register.AX));
        var res = try self.encodeReg(mode, fake_reg, default_size);
        res.reg_size = .None;
        return res;
    }

    pub fn encodeMem16(mem: Memory16Bit, mode:Mode86, modrm_reg: Register) AsmError!ModRmResult {
        var res = ModRmResult{};

        if (modrm_reg.needsRex()) {
            return AsmError.InvalidMemoryAddressing;
        }

        // base ∈ {BX, BP, null}, index ∈ {DI, SI, null}
        if (!mem.hasValidRegisters()) {
            return AsmError.InvalidMemoryAddressing;
        }

        res.reg = modrm_reg.numberRm();
        res.mod = switch (mem.disp.dispSize()) {
            .None => 0b00,
            .Disp8 => 0b01,
            .Disp16 => 0b10,
        };
        res.addMemDisp(mem.disp);

        res.operand_size = mem.data_size.bitSize();
        res.addressing_size = .Bit16;
        res.segment = mem.segment;

        const base = mem.base;
        const index = mem.index;

        if (base == null and index == null and mem.disp.dispSize() != .None) {
            // [disp16]  = 0b110
            res.rm = 0b110;
            res.disp_bit_size = .Bit16;
        } else if (base != null and index != null) {
            // [BX + SI] = 0b000
            // [BX + DI] = 0b001
            // [BP + SI] = 0b010
            // [BP + DI] = 0b011
            const base_val: u3 = if (base.? == .BP) 0b010 else 0;
            const index_val: u3 = if (index.? == .DI) 0b001 else 0;
            res.rm = 0b000 | base_val | index_val;
        } else if (base == null and index != null) {
            // [SI] = 0b100
            // [DI] = 0b101
            const index_val: u3 = if (index.? == .DI) 0b001 else 0;
            res.rm = 0b100 | index_val;
        } else if (base != null and index == null) {
            // [BP] = 0b110 (use this when there is no displacement)
            // [BX] = 0b111
            if (mem.disp.dispSize() == .None and base.? == .BP) {
                return AsmError.InvalidMemoryAddressing;
            }
            const base_val: u3 = if (base.? == .BX) 0b001 else 0;
            res.rm = 0b110 | base_val;
        } else {
            return AsmError.InvalidMemoryAddressing;
        }

        return res;
    }

    // TODO: probably change the asserts in this function to errors
    pub fn encodeReg(self: @This(), mode: Mode86, modrm_reg: Register, default_size: DefaultSize) AsmError!ModRmResult {
        var res = ModRmResult{};
        res.rex_r = modrm_reg.numberRex();
        res.reg = modrm_reg.numberRm();
        res.reg_size = modrm_reg.bitSize();
        res.rexRequirements(modrm_reg, default_size);
        if (modrm_reg.bitSize() == .Bit64 and !default_size.is64Default()) {
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
            .Mem16 => |mem| res = try encodeMem16(mem, mode, modrm_reg),
            .Mem => |mem| {
                // Can't use SP or R12 without a SIB byte since they are used to encode it.
                if ((mem.reg.name() == .SP) or (mem.reg.name() == .R12)){
                    return AsmError.InvalidMemoryAddressing;
                }

                res.operand_size = mem.data_size.bitSize();
                res.addressing_size = mem.reg.bitSize();
                res.segment = mem.segment;

                if (mem.disp.dispSize() != .None)  {
                    // ModRM addressing: [r/m + ]
                    switch (mem.disp.dispSize()) {
                        .Disp8 => res.mod = 0b01,
                        .Disp32 => res.mod = 0b10,
                        .None => unreachable,
                    }
                    res.rm = mem.reg.numberRm();
                    res.rex_b = mem.reg.numberRex();
                    res.addMemDisp(mem.disp);
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
                const disp_size = sib.disp.dispSize();

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

                if (sib.base != null and sib.index != null and disp_size != .None) {
                    // SIB addressing: [base + (index * scale) + disp8/32]
                    if (sib.index.?.name() == .SP) {
                        return AsmError.InvalidMemoryAddressing;
                    }

                    switch (disp_size) {
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
                    res.addMemDisp(sib.disp);
                } else if (sib.base != null and sib.index == null and disp_size != .None) {
                    // SIB addressing: [base + disp8/32]
                    const magic_index = Register.SP;

                    switch (disp_size) {
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
                    res.addMemDisp(sib.disp);
                } else if (disp_size == .None and sib.index != null and sib.base != null) {
                    // SIB addressing: [base + (index * s)]
                    if ((sib.base.?.name() == .BP) or (sib.base.?.name() == .R13)) {
                        return AsmError.InvalidMemoryAddressing;
                    }

                    base = sib.base.?.numberRm();
                    res.rex_b = sib.base.?.numberRex();
                    index = sib.index.?.numberRm();
                    res.rex_x = sib.index.?.numberRex();
                } else if (disp_size == .Disp32 and sib.index != null and sib.base == null) {
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
                    res.addMemDisp(sib.disp);
                } else if (disp_size == .None and sib.index == null and sib.base != null) {
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
                } else if (disp_size == .Disp32 and sib.index == null and sib.base == null) {
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
                    res.addMemDisp(sib.disp);
                } else {
                    // other forms are impossible to encode on x86
                    return AsmError.InvalidMemoryAddressing;
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
                res.disp_bit_size = .Bit32;
                res.disp = rel.disp;
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

        if (default_size == .RM32_Reg) {
            res.operand_size = res.reg_size;
        }

        try res.prefixes.addOverides(
            mode, &res.rex_w, res.operand_size, res.addressing_size, default_size
        );

        return res;
    }

    pub fn register(reg: Register) ModRm {
        return ModRm { .Reg = reg };
    }

    pub fn relMemory(seg: Segment, data_size: DataSize, reg: RelRegister, disp: i32) ModRm {
        return ModRm { .Rel = RelMemory.relMemory(seg, data_size, reg, disp) };
    }

    pub fn memory16Bit(
        seg: Segment,
        data_size: DataSize,
        base: ?Register,
        index: ?Register,
        disp: i16
    ) ModRm {
        var displacement: MemDisp16 = undefined;
        if (base == null and index == null) {
            // need to use 16 bit displacement
            displacement = MemDisp16.create(.Disp16, disp);
        } else {
            displacement = MemDisp16.disp(disp);
        }
        return ModRm {
            .Mem16 = Memory16Bit {
                .base = base,
                .index = index,
                .disp = displacement,
                .data_size = data_size,
                .segment = seg,
            }
        };
    }

    /// data_size [seg: reg + disp]
    pub fn memoryRm(seg: Segment, data_size: DataSize, reg: Register, disp: i32) ModRm {
        var displacement: MemDisp = undefined;
        // can encode these, but need to choose 8 bit displacement
        if ((reg.name() == .BP or reg.name() == .R13) and disp == 0) {
            displacement = MemDisp.create(.Disp8, 0);
        } else {
            displacement = MemDisp.disp(disp);
        }
        return ModRm {
            .Mem = Memory {
                .reg = reg,
                .disp = displacement,
                .data_size = data_size,
                .segment = seg,
            }
        };
    }

    /// data_size [reg + disp8]
    pub fn memoryRm8(seg: Segment, data_size: DataSize, reg: Register, disp: i8) ModRm {
        return ModRm {
            .Mem = Memory {
                .reg = reg,
                .disp = MemDisp.create(.Disp8, disp),
                .data_size = data_size,
                .segment = seg,
            }
        };
    }

    /// data_size [reg + disp32]
    pub fn memoryRm32(seg: Segment, data_size: DataSize, reg: Register, disp: i32) ModRm {
        return ModRm {
            .Mem = Memory {
                .reg = reg,
                .disp = MemDisp.create(.Disp32, disp),
                .data_size = data_size,
                .segment = seg,
            }
        };
    }

    /// data_size [(scale*index) + base + disp8]
    pub fn memorySib8(seg: Segment, data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp8: i8) ModRm {
        return ModRm {
            .Sib = MemorySib {
                .scale = SibScale.scale(scale),
                .index = index,
                .base = base,
                .disp = MemDisp.create(.Disp8, disp8),
                .data_size = data_size,
                .segment = seg,
            }
        };
    }

    /// data_size [(scale*index) + base + disp32]
    pub fn memorySib32(seg: Segment, data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp32: i32) ModRm {
        return ModRm {
            .Sib = MemorySib {
                .scale = SibScale.scale(scale),
                .index = index,
                .base = base,
                .disp = MemDisp.create(.Disp32, disp32),
                .data_size = data_size,
                .segment = seg,
            }
        };
    }

    /// data_size [seg: (scale*index) + base + disp]
    pub fn memorySib(seg: Segment, data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp: i32) ModRm {
        // When base is not used, only 32bit diplacements are valid
        const mem_disp = if (base == null) x: {
            break :x MemDisp.create(.Disp32, disp);
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
        comptime output: fn (@TypeOf(context), []const u8) FmtError!void,
    ) FmtError!void {
        switch (self) {
            .Reg => |reg| {
                try output(context, "RM.");
                try output(context, @tagName(reg));
            },
            .Mem16 => |mem| {
                try output(context, @tagName(mem.data_size));
                try output(context, " ");
                if (mem.segment != .DefaultSeg) {
                    try output(context, @tagName(mem.segment));
                    try output(context, ":");
                }
                try output(context, "[");
                if (mem.base) |base| {
                    try output(context, @tagName(base));
                    if (mem.index != null or mem.disp.dispSize() != .None) {
                        try output(context, " + ");
                    }
                }
                if (mem.index) |index| {
                    try output(context, @tagName(index));
                    if (mem.disp.dispSize() != .None ) {
                        try output(context, " + ");
                    }
                }
                if (mem.disp.dispSize() != .None) {
                    const disp = mem.disp.value();
                    if (disp < 0) {
                        try std.fmt.format(context, FmtError, output, "-0x{x}", .{-disp});
                    } else {
                        try std.fmt.format(context, FmtError, output, "0x{x}", .{disp});
                    }
                }
                try output(context, "]");
            },
            .Mem => |mem| {
                try output(context, @tagName(mem.data_size));
                try output(context, " ");
                if (mem.segment != .DefaultSeg) {
                    try output(context, @tagName(mem.segment));
                    try output(context, ": ");
                }
                try output(context, "[");
                try output(context, @tagName(mem.reg));
                if (mem.disp.dispSize() !=  .None) {
                    const disp = mem.disp.value();
                    if (disp < 0) {
                        try std.fmt.format(context, FmtError, output, " - 0x{x}", .{-disp});
                    } else {
                        try std.fmt.format(context, FmtError, output, " + 0x{x}", .{disp});
                    }
                    try std.fmt.format(context, FmtError, output, "{}", .{disp});
                }
                try output(context, "]");
            },
            .Sib => |sib| {
                try output(context, @tagName(sib.data_size));
                try output(context, " ");
                if (sib.segment != .DefaultSeg) {
                    try output(context, @tagName(sib.segment));
                    try output(context, ":");
                }
                try output(context, "[");
                if (sib.index) |index| {
                    try std.fmt.format(context, FmtError, output, "{}*{}", .{sib.scale.value(), @tagName(index)});
                    if (sib.base != null or sib.disp.dispSize() != .None) {
                        try output(context, " + ");
                    }
                }
                if (sib.base) |base| {
                    try output(context, @tagName(base));
                    if (sib.disp.dispSize() != .None ) {
                        try output(context, " + ");
                    }
                }
                if (sib.disp.dispSize() != .None) {
                    const disp = sib.disp.value();
                    if (disp < 0) {
                        try std.fmt.format(context, FmtError, output, "-0x{x}", .{-disp});
                    } else {
                        try std.fmt.format(context, FmtError, output, "0x{x}", .{disp});
                    }
                }
                try output(context, "]");
            },
            .Rel => |rel| {
                try output(context, @tagName(rel.data_size));
                try output(context, " ");
                if (rel.segment != .DefaultSeg) {
                    try output(context, @tagName(rel.segment));
                    try output(context, ": ");
                }
                try output(context, "[");
                try output(context, @tagName(rel.reg));
                const disp = rel.disp;
                if (disp < 0) {
                    try std.fmt.format(context, FmtError, output, " - 0x{x}", .{-disp});
                } else {
                    try std.fmt.format(context, FmtError, output, " + 0x{x}", .{disp});
                }
                try output(context, "]");
            },

            else => {
                try output(context, "<Format TODO>");
            },
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
        comptime output: fn (@TypeOf(context), []const u8) FmtError!void,
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
    sign: ImmediateSign,

    pub fn value(self: Immediate) u64 {
        return self._value;
    }

    pub fn asSignedValue(self: Immediate) i64 {
        std.debug.assert(self.sign == .Signed);
        return @bitCast(i64, self._value);
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
        return @intCast(u8, self._value & 0xff);
    }

    pub fn as16(self: Immediate) u16 {
        std.debug.assert(self.bitSize() == .Bit16);
        return @intCast(u16, self._value & 0xffff);
    }

    pub fn as32(self: Immediate) u32 {
        std.debug.assert(self.bitSize() == .Bit32);
        return @intCast(u32, self._value & 0xffffffff);
    }

    pub fn as64(self: Immediate) u64 {
        std.debug.assert(self.bitSize() == .Bit64);
        return self._value;
    }

    pub fn willSignExtend(self: Immediate, op_type: OperandType) bool {
        switch (op_type) {
            .imm8_any, .imm8 => return (self._value & (1<<7)) == (1<<7),
            .imm16_any, .imm16 => return (self._value & (1<<15)) == (1<<15),
            .imm32_any, .imm32 => return (self._value & (1<<31)) == (1<<31),
            .imm64_any, .imm64 => return (self._value & (1<<63)) == (1<<63),
            else => unreachable,
        }
    }

    pub fn isNegative(self: Immediate) bool {
        if (self.sign == .Unsigned) {
            return false;
        }
        switch (self.size) {
            .Imm8_any, .Imm8 => return (self._value & (1<<7)) == (1<<7),
            .Imm16_any, .Imm16 => return (self._value & (1<<15)) == (1<<15),
            .Imm32_any, .Imm32 => return (self._value & (1<<31)) == (1<<31),
            .Imm64_any, .Imm64 => return (self._value & (1<<63)) == (1<<63),
        }
    }

    pub fn coerce(self: Immediate, bit_size: BitSize) Immediate {
        var result = self;
        switch (bit_size) {
            .Bit8  => result.size = .Imm8,
            .Bit16 => result.size = .Imm16,
            .Bit32 => result.size = .Imm32,
            .Bit64 => result.size = .Imm64,
            else => unreachable,
        }
        return result;
    }

    pub fn immSigned(im: i64) Immediate {
        if (minInt(i8) <= im and im <= maxInt(i8)) {
            return createSigned(.Imm8_any, im);
        } else if (minInt(i16) <= im and im <= maxInt(i16)) {
            return createSigned(.Imm16_any, im);
        } else if (minInt(i32) <= im and im <= maxInt(i32)) {
            return createSigned(.Imm32_any, im);
        } else {
            return createSigned(.Imm64_any, im);
        }
    }

    pub fn immUnsigned(im : u64) Immediate {
        if (im <= maxInt(u8)) {
            return createUnsigned(.Imm8_any, im);
        } else if (im <= maxInt(u16)) {
            return createUnsigned(.Imm16_any, im);
        } else if (im <= maxInt(u32)) {
            return createUnsigned(.Imm32_any, im);
        } else {
            return createUnsigned(.Imm64_any, im);
        }
    }

    pub fn createUnsigned(size: ImmediateSize, val: u64) Immediate {
        return Immediate {
            .size = size,
            ._value = val,
            .sign = .Unsigned,
        };
    }

    pub fn createSigned(size: ImmediateSize, val: i64) Immediate {
        return Immediate {
            .size = size,
            ._value = @bitCast(u64, val),
            .sign = .Signed,
        };
    }

};

pub const VoidOperand = struct {
    operand_size: DataSize,
};

pub const OperandTag = enum {
    None,
    Reg,
    Imm,
    Rm,
    Addr,
    RegPred,
    RmPred,
    RegSae,
};

pub const Operand = union(OperandTag) {
    None: VoidOperand,
    Reg: Register,
    Imm: Immediate,
    Rm: ModRm,
    Addr: Address,
    RegPred: avx.RegisterPredicate,
    RmPred: avx.RmPredicate,
    RegSae: avx.RegisterSae,

    pub fn tag(self: Operand) OperandTag {
        return @as(OperandTag, self);
    }

    pub fn operandType(self: Operand) OperandType {
        return switch (self) {
            .Reg => |reg| OperandType.fromRegister(reg),
            .Imm => |imm_| OperandType.fromImmediate(imm_),
            .Rm => |rm| OperandType.fromModRm(rm),
            .Addr => |addr| OperandType.fromAddress(addr),
            .RegPred => |reg_pred| OperandType.fromRegisterPredicate(reg_pred),
            .RmPred => |rm_pred| OperandType.fromRmPredicate(rm_pred),
            .RegSae => |sae| OperandType.fromSae(sae),
            // TODO: get size
            .None => OperandType._void,
        };
    }

    pub fn operandSize(self: Operand) BitSize {
        return switch (self) {
            .Reg => |reg| reg.bitSize(),
            .Imm => |imm_| (imm_.bitSize()),
            .Rm => |rm| rm.operandSize(),
            .Addr => |addr| addr.operandSize(),
            .None => |none| none.operand_size.bitSize(),
            .RegPred => |reg_pred| reg_pred.reg.bitSize(),
            .RmPred => |rm_pred| rm_pred.rm.operandSize(),
            .RegSae => |reg_sae| reg_sae.reg.bitSize(),
        };
    }

    /// If the operand has a size overide get it instead of the underlying
    /// operand size.
    pub fn operandDataSize(self: Operand) DataSize {
        return switch (self) {
            .Reg => |reg| reg.dataSize(),
            .Imm => |imm_| (imm_.dataSize()),
            .Rm => |rm| rm.operandDataSize(),
            .Addr => |addr| addr.operandDataSize(),
            .None => |none| none.operand_size,
            .RegPred => |reg_pred| reg_pred.reg.dataSize(),
            .RmPred => |rm_pred| rm_pred.rm.operandDataSize(),
            .RegSae => |rc| DataSize.Void,
        };
    }

    pub fn register(reg: Register) Operand {
        return Operand { .Reg = reg };
    }

    pub fn registerRm(reg: Register) Operand {
        return Operand { .Rm = ModRm.register(reg) };
    }

    pub fn registerPredicate(reg: Register, mask: avx.MaskRegister, z: avx.ZeroOrMerge) Operand {
        return Operand { .RegPred = avx.RegisterPredicate.create(reg, mask, z) };
    }

    pub fn rmPredicate(op: Operand, mask: avx.MaskRegister, z: avx.ZeroOrMerge) Operand {
        return switch (op) {
            .Reg => |reg| Operand { .RmPred = avx.RmPredicate.create(ModRm.register(reg), mask, z) },
            .Rm => |rm| Operand { .RmPred = avx.RmPredicate.create(rm, mask, z) },
            else => {
                std.debug.panic("Expected Operand.Register or Operand.ModRm, got: {}", .{op});
            },
        };
    }

    pub fn registerSae(reg: Register, sae: avx.SuppressAllExceptions) Operand {
        return Operand { .RegSae = avx.RegisterSae.create(reg, sae) };
    }

    pub fn voidOperand(data_size: DataSize) Operand {
        return Operand { .None = VoidOperand { .operand_size = data_size } };
    }

    pub fn immediate(im: u64) Operand {
        return Operand { .Imm = Immediate.immUnsigned(im) };
    }

    pub fn immediate8(im: u8) Operand {
        return Operand { .Imm = Immediate.createUnsigned(.Imm8, im) };
    }
    pub fn immediate16(im: u16) Operand {
        return Operand { .Imm = Immediate.createUnsigned(.Imm16, im) };
    }
    pub fn immediate32(im: u32) Operand {
        return Operand { .Imm = Immediate.createUnsigned(.Imm32, im) };
    }
    pub fn immediate64(im: u64) Operand {
        return Operand { .Imm = Immediate.createUnsigned(.Imm64, im) };
    }

    pub fn immediateSigned(im: i64) Operand {
        return Operand { .Imm = Immediate.immSigned(im) };
    }

    pub fn immediateSigned8(im: i8) Operand {
        return Operand { .Imm = Immediate.createSigned(.Imm8, @intCast(i64, im)) };
    }
    pub fn immediateSigned16(im: i16) Operand {
        return Operand { .Imm = Immediate.createSigned(.Imm16, @intCast(i64, im)) };
    }
    pub fn immediateSigned32(im: i32) Operand {
        return Operand { .Imm = Immediate.createSigned(.Imm32, @intCast(i64, im)) };
    }
    pub fn immediateSigned64(im: i64) Operand {
        return Operand { .Imm = Immediate.createSigned(.Imm64, @intCast(i64, im)) };
    }

    pub fn memory16Bit(seg: Segment, data_size: DataSize, base: ?Register, index: ?Register, disp: i16) Operand {
        return Operand { .Rm = ModRm.memory16Bit(seg, data_size, base, index, disp) };
    }

    /// Same as memorySib, except it may choose to encode it as memoryRm if the encoding is shorter
    pub fn memory(seg: Segment, data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp: i32) Operand {
        var modrm: ModRm = undefined;
        if (index == null and base != null) edge_case: {
            const reg_name = base.?.name();
            // Can encode these, but need to choose 32 bit displacement and SIB byte
            if (reg_name == .SP or reg_name == .R12) {
                break :edge_case;
            }

            return Operand { .Rm = ModRm.memoryRm(seg, data_size, base.?, disp) };
        }

        return Operand { .Rm = ModRm.memorySib(seg, data_size, scale, index, base, disp) };
    }

    /// Same memory() except uses the default segment
    pub fn memoryDef(data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp: i32) Operand {
        return memory(.DefaultSeg, data_size, scale, index, base, disp);
    }

    /// data_size [seg: reg + disp0/8/32]
    pub fn memoryRm(seg: Segment, data_size: DataSize, reg: Register, disp: i32) Operand {
        return Operand { .Rm = ModRm.memoryRm(seg, data_size, reg, disp) };
    }

    /// data_size [DefaultSeg: reg + disp0/8/32]
    pub fn memoryRmDef(data_size: DataSize, reg: Register, disp: i32) Operand {
        return Operand { .Rm = ModRm.memoryRm(.DefaultSeg, data_size, reg, disp) };
    }

    /// data_size [seg: reg + disp8]
    pub fn memoryRm8(seg: Segment, data_size: DataSize, reg: Register, disp: i8) Operand {
        return Operand { .Rm = ModRm.memoryRm8(seg, data_size, reg, disp) };
    }

    /// data_size [seg: reg + disp32]
    pub fn memoryRm32(seg: Segment, data_size: DataSize, reg: Register, disp: i32) Operand {
        return Operand { .Rm = ModRm.memoryRm32(seg, data_size, reg, disp) };
    }

    /// data_size [seg: (scale*index) + base + disp0/8/32]
    pub fn memorySib(seg: Segment, data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp: i32) Operand {
        return Operand { .Rm = ModRm.memorySib(seg, data_size, scale, index, base, disp) };
    }

    /// data_size [seg: (scale*index) + base + disp8]
    pub fn memorySib8(seg: Segment, data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp: i8) Operand {
        return Operand { .Rm = ModRm.memorySib8(seg, data_size, scale, index, base, disp) };
    }

    /// data_size [seg: (scale*index) + base + disp32]
    pub fn memorySib32(seg: Segment, data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp: i32) Operand {
        return Operand { .Rm = ModRm.memorySib32(seg, data_size, scale, index, base, disp) };
    }

    /// data_size [DefaultSeg: (scale*index) + base + disp]
    pub fn memorySibDef(data_size: DataSize, scale: u8, index: ?Register, base: ?Register, disp: i32) Operand {
        return Operand { .Rm = ModRm.memorySib(.DefaultSeg, data_size, scale, index, base, disp) };
    }

    /// data_size [Seg: EIP/RIP + disp]
    pub fn relMemory(seg: Segment, data_size: DataSize, reg: RelRegister, disp: i32) Operand {
        return Operand { .Rm = ModRm.relMemory(seg, data_size, reg, disp) };
    }

    /// data_size [DefaultSeg: EIP/RIP + disp]
    pub fn relMemoryDef(data_size: DataSize, reg: RelRegister, disp: i32) Operand {
        return Operand { .Rm = ModRm.relMemory(.DefaultSeg, data_size, reg, disp) };
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
        comptime output: fn (@TypeOf(context), []const u8) FmtError!void,
    ) FmtError!void {
        // self.assertWritable();
        // TODO look at fmt and support other bases
        // TODO support read-only fixed integers
        switch (self) {
            .Reg => |reg| try output(context, @tagName(reg)),
            .Rm => |rm| try rm.format(fmt, options, context, FmtError, output),
            .Imm => |im| {
                if (im.sign == .Signed and im.isNegative()) {
                    try std.fmt.format(context, FmtError, output, "{}", .{im.asSignedValue()});
                } else {
                    try std.fmt.format(context, FmtError, output, "0x{x}", .{im.value()});
                }
            },
            .Addr => |addr| {
                if (addr.operandDataSize() != .Default) {
                    try output(context, @tagName(addr.operandDataSize()));
                    try output(context, " ");
                }
                try addr.format(fmt, options, context, FmtError, output);
            },

            .RegPred => |pred| {
                try output(context, @tagName(pred.reg));
                if (pred.mask != .NoMask) {
                    try output(context, " {");
                    try output(context, @tagName(pred.mask));
                    try output(context, "}");
                }

                if (pred.z == .Zero) {
                    try output(context, " {z}");
                }
            },

            .RegSae => |sae_reg| {
                try output(context, @tagName(sae_reg.reg));
                switch (sae_reg.sae) {
                    .AE => {},
                    .SAE => try output(context, " {sae}"),
                    .RN_SAE => try output(context, " {rn-sae}"),
                    .RD_SAE => try output(context, " {rd-sae}"),
                    .RU_SAE => try output(context, " {ru-sae}"),
                    .RZ_SAE => try output(context, " {rz-sae}"),
                }
            },

            else => {
                try output(context, "<Format TODO>");
            },
        }
    }
};

test "ModRm Encoding" {
    const testing = std.testing;
    const warn = if (true) std.debug.warn else util.warnDummy;
    const expect = testing.expect;
    const expectError = testing.expectError;

    // x86_16: [BP + SI]
    {
        const modrm = ModRm.memory16Bit(.DefaultSeg, .WORD, .BP, .SI, 0);
        const result = try modrm.encodeOpcodeRm(.x86_16, 7, .RM32);
        expect(result.modrm() == 0b00111010);
        expect(result.disp_bit_size == .Bit0);
        expect(result.disp          == 0);
        expect(std.mem.eql(u8, result.prefixes.asSlice(), &[_]u8{}));
    }

    // x86_32: WORD [BP + DI + 0x10], (RM32)
    {
        const modrm = ModRm.memory16Bit(.DefaultSeg, .WORD, .BP, .DI, 0x10);
        const result = try modrm.encodeOpcodeRm(.x86_32, 7, .RM32);
        expect(result.modrm() == 0b01111011);
        expect(result.disp_bit_size == .Bit8);
        expect(result.disp          == 0x10);
        expect(std.mem.eql(u8, result.prefixes.asSlice(), &[_]u8{0x66, 0x67}));
    }

    // x86_16: DWORD [BX], (RM32)
    {
        const modrm = ModRm.memory16Bit(.DefaultSeg, .DWORD, .BX, null, 0x1100);
        const result = try modrm.encodeOpcodeRm(.x86_16, 5, .RM32);
        expect(result.modrm() == 0b10101111);
        expect(result.disp_bit_size == .Bit16);
        expect(result.disp          == 0x1100);
        expect(std.mem.eql(u8, result.prefixes.asSlice(), &[_]u8{0x66}));
    }

    {
        const modrm = ModRm.register(.RAX);
        const result = try modrm.encodeOpcodeRm(.x64, 0, .RM32);
        expect(result.rex(0)  == 0b01001000);
        expect(result.rex(1)  == 0b01001000);
        expect(result.modrm() == 0b11000000);
        expect(result.sib == null);
        expect(result.disp_bit_size == .Bit0);
    }

    {
        const modrm = ModRm.register(.R15);
        const result = try modrm.encodeReg(.x64, .R9, .RM32);
        expect(result.rex(0)  == 0b01001101);
        expect(result.rex(1)  == 0b01001101);
        expect(result.modrm() == 0b11001111);
        expect(result.sib == null);
        expect(result.disp_bit_size == .Bit0);
        expect(result.prefixes.len == 0);
    }

    {
        const modrm = ModRm.relMemory(.DefaultSeg, .DWORD, .EIP, 0x76543210);
        const result = try modrm.encodeReg(.x64, .R8, .RM32);
        expect(result.rex(0)  == 0b01001100);
        expect(result.rex(1)  == 0b01001100);
        expect(result.modrm() == 0b00000101);
        expect(result.sib == null);
        expect(result.disp == 0x76543210);
        expect(std.mem.eql(u8, result.prefixes.asSlice(), &[_]u8{0x67}));
    }

    {
        const modrm = ModRm.relMemory(.DefaultSeg, .QWORD, .RIP, 0x76543210);
        const result = try modrm.encodeReg(.x64, .R8, .RM32);
        expect(result.rex(0)  == 0b01001100);
        expect(result.rex(1)  == 0b01001100);
        expect(result.modrm() == 0b00000101);
        expect(result.sib == null);
        expect(result.disp == 0x76543210);
        expect(result.prefixes.len == 0);
    }

    {
        const modrm = ModRm.memoryRm(.DefaultSeg, .QWORD, .R9, 0x0);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(0)  == 0b01001001);
        expect(result.rex(1)  == 0b01001001);
        expect(result.modrm() == 0b00000001);
        expect(result.sib == null);
        expect(result.disp_bit_size == .Bit0);
    }

    {
        const modrm = ModRm.memoryRm(.DefaultSeg, .QWORD, .R9, 0x10);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(0)  == 0b01001001);
        expect(result.rex(1)  == 0b01001001);
        expect(result.modrm() == 0b01000001);
        expect(result.sib == null);
        expect(result.disp == 0x10);
    }

    {
        const modrm = ModRm.memoryRm(.DefaultSeg, .QWORD, .R9, 0x76543210);
        const result = try modrm.encodeReg(.x64, .R15, .RM32);
        expect(result.rex(0)  == 0b01001101);
        expect(result.rex(1)  == 0b01001101);
        expect(result.modrm() == 0b10111001);
        expect(result.sib == null);
        expect(result.disp == 0x76543210);
    }

    // [2*R15 + R15 + 0x10]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 2, .R15, .R15, 0x10);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001011);
        expect(result.modrm() == 0b01000100);
        expect(result.sib.? == 0b01111111);
        expect(result.disp == 0x10);
    }

    // [2*R15 + R15 + 0x76543210]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 1, .R15, .R15, 0x76543210);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001011);
        expect(result.modrm() == 0b10000100);
        expect(result.sib.? == 0b00111111);
        expect(result.disp == 0x76543210);
    }

    // [R15 + 0x10]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 2, null, .R15, 0x10);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001001);
        expect(result.modrm() == 0b01000100);
        expect(result.sib.? == 0b01100111);
        expect(result.disp == 0x10);
    }

    // [R15 + 0x3210]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 2, null, .R15, 0x3210);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001001);
        expect(result.modrm() == 0b10000100);
        expect(result.sib.? == 0b01100111);
        expect(result.disp == 0x3210);
    }

    // [4*R15 + R15]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 4, .R15, .R15, 0x00);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001011);
        expect(result.modrm() == 0b00000100);
        expect(result.sib.? == 0b10111111);
        expect(result.disp_bit_size == .Bit0);
    }

    // [4*R15 + 0x10]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 4, .R15, null, 0x10);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001010);
        expect(result.modrm() == 0b00000100);
        expect(result.sib.? == 0b10111101);
        expect(result.disp_bit_size == .Bit32);
    }

    // [0x10]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 8, null, null, 0x10);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001000);
        expect(result.modrm() == 0b00000100);
        expect(result.sib.? == 0b11100101);
        expect(result.disp_bit_size == .Bit32);
    }

    // [R15]
    {
        const modrm = ModRm.memorySib(.DefaultSeg, .QWORD, 4, null, .R15, 0x00);
        const result = try modrm.encodeReg(.x64, .RAX, .RM32);
        expect(result.rex(1)  == 0b01001001);
        expect(result.modrm() == 0b00000100);
        expect(result.sib.? == 0b10100111);
        expect(result.disp_bit_size == .Bit0);
    }
}
