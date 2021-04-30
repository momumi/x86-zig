const x86 = @import("machine.zig");
const std = @import("std");

const assert = std.debug.assert;

usingnamespace @import("types.zig");

const AvxOpcode = x86.avx.AvxOpcode;

const Mnemonic = x86.Mnemonic;
const Instruction = x86.Instruction;
const Machine = x86.Machine;
const Operand = x86.operand.Operand;
const Immediate = x86.Immediate;
const OperandType = x86.operand.OperandType;

pub const Signature = struct {
    const max_ops = 5;
    operands: [max_ops]OperandType,

    pub fn ops(
        o1: OperandType,
        o2: OperandType,
        o3: OperandType,
        o4: OperandType,
        o5: OperandType,
    ) Signature {
        return Signature{
            .operands = [max_ops]OperandType{ o1, o2, o3, o4, o5 },
        };
    }

    pub fn ops0() Signature {
        return ops(.none, .none, .none, .none, .none);
    }

    pub fn ops1(o1: OperandType) Signature {
        return ops(o1, .none, .none, .none, .none);
    }

    pub fn ops2(o1: OperandType, o2: OperandType) Signature {
        return ops(o1, o2, .none, .none, .none);
    }

    pub fn ops3(o1: OperandType, o2: OperandType, o3: OperandType) Signature {
        return ops(o1, o2, o3, .none, .none);
    }

    pub fn ops4(o1: OperandType, o2: OperandType, o3: OperandType, o4: OperandType) Signature {
        return ops(o1, o2, o3, o4, .none);
    }

    pub fn ops5(
        o1: OperandType,
        o2: OperandType,
        o3: OperandType,
        o4: OperandType,
        o5: OperandType,
    ) Signature {
        return ops(o1, o2, o3, o4, o5);
    }

    pub fn fromOperands(
        operand1: ?*const Operand,
        operand2: ?*const Operand,
        operand3: ?*const Operand,
        operand4: ?*const Operand,
        operand5: ?*const Operand,
    ) Signature {
        const o1 = if (operand1) |op| op.operandType() else OperandType.none;
        const o2 = if (operand2) |op| op.operandType() else OperandType.none;
        const o3 = if (operand3) |op| op.operandType() else OperandType.none;
        const o4 = if (operand4) |op| op.operandType() else OperandType.none;
        const o5 = if (operand5) |op| op.operandType() else OperandType.none;
        return ops(o1, o2, o3, o4, o5);
    }

    pub fn debugPrint(self: Signature) void {
        std.debug.warn("(", .{});
        for (self.operands) |operand| {
            if (operand == .none) {
                continue;
            }
            std.debug.warn("{},", .{@tagName(operand)});
        }
        std.debug.warn("): ", .{});
    }

    pub fn matchTemplate(template: Signature, instance: Signature) bool {
        for (template.operands) |templ, i| {
            const rhs = instance.operands[i];
            if (templ == .none and rhs == .none) {
                continue;
            } else if (!OperandType.matchTemplate(templ, rhs)) {
                return false;
            }
        }
        return true;
    }
};

/// Special opcode edge cases
/// Some opcode/instruction combinations have special legacy edge cases we need
/// to check before we can confirm a match.
pub const OpcodeEdgeCase = enum {
    None = 0x0,

    /// Prior to x86-64, the instructions:
    ///     90      XCHG EAX, EAX
    /// and
    ///     90      NOP
    /// were encoded the same way and might be treated specially by the CPU.
    /// However, on x86-64 `XCHG EAX,EAX` is no longer a NOP because it zeros
    /// the upper 32 bits of the RAX register.
    ///
    /// When AMD designed x86-64 they decide 90 should still be treated as a NOP.
    /// This means we have to choose a different encoding on x86-64.
    XCHG_EAX = 0x1,

    /// sign-extended immediate value (ie this opcode sign extends)
    Sign,

    /// mark an encoding that will only work if the immediate doesn't need a
    /// sign extension (ie this opcode zero extends)
    ///
    /// eg: `MOV r64, imm32` can be encode in the same way as `MOV r32, imm32`
    /// as long as the immediate is non-negative since all operations on 32 bit
    /// registers implicitly zero extend
    NoSign,

    /// Not encodable on 64 bit mode
    No64,

    /// Not encodable on 32/16 bit mode
    No32,

    /// Valid encoding, but undefined behaviour
    Undefined,

    pub fn isEdgeCase(
        self: OpcodeEdgeCase,
        item: InstructionItem,
        mode: Mode86,
        op1: ?*const Operand,
        op2: ?*const Operand,
        op3: ?*const Operand,
        op4: ?*const Operand,
        op5: ?*const Operand,
    ) bool {
        switch (self) {
            .XCHG_EAX => {
                return (mode == .x64 and op1.?.Reg == .EAX and op2.?.Reg == .EAX);
            },
            .NoSign, .Sign => {
                const sign = self;

                var imm_pos: u8 = undefined;
                // figure out which operand is the immediate
                if (op1 != null and op1.?.tag() == .Imm) {
                    imm_pos = 0;
                } else if (op2 != null and op2.?.tag() == .Imm) {
                    imm_pos = 1;
                } else if (op3 != null and op3.?.tag() == .Imm) {
                    imm_pos = 2;
                } else if (op4 != null and op4.?.tag() == .Imm) {
                    imm_pos = 3;
                } else if (op5 != null and op5.?.tag() == .Imm) {
                    imm_pos = 4;
                } else {
                    unreachable;
                }
                const imm = switch (imm_pos) {
                    0 => op1.?.Imm,
                    1 => op2.?.Imm,
                    2 => op3.?.Imm,
                    3 => op4.?.Imm,
                    4 => op5.?.Imm,
                    else => unreachable,
                };
                switch (sign) {
                    // Matches edgecase when it's an unsigned immediate that will get sign extended
                    .Sign => {
                        const is_unsigned = imm.sign == .Unsigned;
                        return (is_unsigned and imm.willSignExtend(item.signature.operands[imm_pos]));
                    },
                    // Matches edgecase when it's a signed immedate that needs its sign extended
                    .NoSign => {
                        const is_signed = imm.sign == .Signed;
                        return (is_signed and imm.isNegative());
                    },
                    else => unreachable,
                }
            },
            .No64 => unreachable,
            .No32 => unreachable,
            .Undefined => unreachable,

            .None => return false,
        }
    }
};

// Quick refrences:
//
// * https://en.wikichip.org/wiki/intel/cpuid
// * https://en.wikipedia.org/wiki/X86_instruction_listings
// * https://www.felixcloutier.com/x86/
// * Intel manual: Vol 3, Ch 22.13 New instructions in the pentium and later ia-32 processors
pub const CpuFeature = enum {
    pub const count = __num_cpu_features;
    pub const MaskType = u128;
    pub const all_features_mask = ~@as(CpuFeature.MaskType, 0);

    pub const Presets = struct {
        const _i386 = [_]CpuFeature{ ._8086, ._186, ._286, ._386, ._087, ._287, ._387 };
        const _i486 = [_]CpuFeature{ ._8086, ._186, ._286, ._386, ._486, ._087, ._287, ._387 };
        const x86_64 = [_]CpuFeature{
            ._8086, ._186,    ._286, ._386, ._486, .x86_64, ._087, ._287, ._387,
            .CPUID, .P6,      .FPU,  .TSC,  .MSR,  .CX8,    .SEP,  .CX16, .RSM,
            .MMX,   .SYSCALL,
        };
    };

    /// Added in 8086 / 8088
    _8086,
    /// Added in 80186 / 80188
    _186,
    /// Added in 80286
    _286,
    /// Added in 80386
    _386,
    /// Added in 80486
    _486,
    /// Added in x86-64 (CPUID.80000001H:EDX.LM[29] (Long Mode))
    x86_64,

    /// Legacy 8086 instructions not implemented on later processors
    _8086_Legacy,
    /// Legacy 80186 instructions not implemented on later processors
    _186_Legacy,
    /// Legacy 80286 instructions not implemented on later processors
    _286_Legacy,
    /// Legacy 80386 instructions not implemented on later processors
    _386_Legacy,
    /// Legacy 80486 instructions not implemented on later processors
    _486_Legacy,

    /// Added in 8087 FPU, or CPUID.01H.EDX.FPU[0] = 1
    _087,
    /// Added in 80287 FPU, or CPUID.01H.EDX.FPU[0] = 1
    _287,
    /// Added in 80387 FPU, or CPUID.01H.EDX.FPU[0] = 1
    _387,

    /// Only works on Intel CPUs
    Intel,
    /// Only works on Amd CPUs
    Amd,
    /// Only works on Cyrix CPUs
    Cyrix,

    /// Added in AMD-V
    AMD_V,
    /// Added in VT-x
    VT_X,

    ///  EFLAGS.ID[bit 21] can be set and cleared
    CPUID,

    /// CPUID.01H.EAX[11:8] = Family = 6 or 15 = 0110B or 1111B
    P6,

    /// (IA-32e mode supported) or (CPUID DisplayFamily_DisplayModel = 06H_0CH )
    RSM,

    //
    // CPUID.(EAX=1).ECX
    //
    /// CPUID.01H.ECX.SSE3[0] = 1
    SSE3,
    /// CPUID.01H.ECX.PCLMULQDQ[1] = 1
    PCLMULQDQ,
    /// CPUID.01H.ECX.MONITOR[3] = 1
    MONITOR,
    /// CPUID.01H.ECX.VMX[5] = 1
    VMX,
    /// CPUID.01H.ECX.SMX[6] = 1
    SMX,
    /// CPUID.01H.ECX.SSSE3[9] = 1 (supplemental SSE3)
    SSSE3,
    /// CPUID.01H.ECX.FMA[12] = 1 (Fused Multiply and Add)
    FMA,
    /// CPUID.01H.ECX.CX16[13] = 1
    CX16,
    /// CPUID.01H.ECX.SSE4_1[19] = 1
    SSE4_1,
    /// CPUID.01H.ECX.SSE4_2[20] = 1
    SSE4_2,
    /// CPUID.01H.ECX.MOVBE[22] = 1
    MOVBE,
    /// CPUID.01H.ECX.POPCNT[23] = 1
    POPCNT,
    /// CPUID.01H.ECX.AES[25] = 1
    AES,
    /// CPUID.01H.ECX.XSAVE[26] = 1
    XSAVE,
    /// CPUID.01H.ECX.AVX[28] = 1
    AVX,
    /// CPUID.01H.ECX.F16C[29] = 1
    F16C,
    /// CPUID.01H.ECX.RDRAND[30] = 1
    RDRAND,

    //
    // CPUID.(EAX=1).EDX
    //
    /// CPUID.01H.EDX.FPU[0] = 1
    FPU,
    /// CPUID.01H.EDX.TSC[4] = 1
    TSC,
    /// CPUID.01H.EDX.MSR[5] = 1
    MSR,
    /// CPUID.01H.EDX.CX8[8] = 1
    CX8,
    /// CPUID.01H.EDX.SEP[11] = 1 (SYSENTER and SYSEXIT)
    SEP,
    /// CPUID.01H.EDX.CMOV[15] = 1 (CMOVcc and FCMOVcc)
    CMOV,
    /// CPUID.01H.EDX.CLFSH[19] = 1 (CFLUSH)
    CLFSH,
    /// CPUID.01H.EDX.MMX[23] = 1
    MMX,
    /// CPUID.01H.EDX.FXSR[24] = 1 (FXSAVE, FXRSTOR)
    FXSR,
    /// CPUID.01H.EDX.SSE[25] = 1
    SSE,
    /// CPUID.01H.EDX.SSE2[26] = 1
    SSE2,

    //
    // CPUID.(EAX=7, ECX=0).EBX
    //
    /// CPUID.EAX.07H.EBX.FSGSBASE[0] = 1
    FSGSBASE,
    /// CPUID.EAX.07H.EBX.SGX[2] = 1 (Software Guard eXtensions)
    SGX,
    /// CPUID.EAX.07H.EBX.BMI1[3] = 1 (Bit Manipulation Instructions 1)
    BMI1,
    /// CPUID.EAX.07H.EBX.HLE[4] = 1 (Hardware Lock Elision)
    HLE,
    /// CPUID.EAX.07H.EBX.AVX2[5] = 1 (Advanced Vector eXtension 2)
    AVX2,
    /// CPUID.EAX.07H.EBX.SMEP[7] = 1 (Supervisor Mode Execution Prevention)
    SMEP,
    /// CPUID.EAX.07H.EBX.BMI2[8] = 1 (Bit Manipulation Instructions 2)
    BMI2,
    /// CPUID.EAX.07H.EBX.INVPCID[10] = 1
    INVPCID,
    /// CPUID.EAX.07H.EBX.RTM[11] = 1
    RTM,
    /// CPUID.EAX.07H.EBX.MPX[14] = 1 (Memory Protection eXtension)
    MPX,
    /// CPUID.EAX.07H.EBX.AVX512F[16] = 1
    AVX512F,
    /// CPUID.EAX.07H.EBX.AVX512DQ[17] = 1 (Doubleword and Quadword)
    AVX512DQ,
    /// CPUID.EAX.07H.EBX.RDSEED[18] = 1
    RDSEED,
    /// CPUID.EAX.07H.EBX.ADX[19] = 1
    ADX,
    /// CPUID.EAX.07H.EBX.SMAP[20] = 1 (Supervisor Mode Access Prevention)
    SMAP,
    /// CPUID.EAX.07H.EBX.AVX512_I1FMA[21] = 1 (AVX512 Integer Fused Multiply Add)
    AVX512_IFMA,
    /// CPUID.EAX.07H.EBX.PCOMMIT[22] = 1
    PCOMMIT,
    /// CPUID.EAX.07H.EBX.CLFLUSHOPT[23] = 1
    CLFLUSHOPT,
    /// CPUID.EAX.07H.EBX.CLWB[24] = 1
    CLWB,
    /// CPUID.EAX.07H.EBX.AVX512PF[26] = 1 (AVX512 Prefetch Instructions)
    AVX512PF,
    /// CPUID.EAX.07H.EBX.AVX512ER[27] = 1 (AVX512 Exponential and Reciprocal)
    AVX512ER,
    /// CPUID.EAX.07H.EBX.AVX512CD[28] = 1 (AVX512 Conflict Detection)
    AVX512CD,
    /// CPUID.EAX.07H.EBX.SHA[29] = 1
    SHA,
    /// CPUID.EAX.07H.EBX.AVX512BW[30] = 1 (AVX512 Byte and Word)
    AVX512BW,
    /// CPUID.EAX.07H.EBX.AVX512_VL[31] = 1 (AVX512 Vector length extensions)
    AVX512VL,

    //
    // CPUID.(EAX=7, ECX=0).ECX
    //
    /// CPUID.EAX.07H.ECX.PREFETCHWT1[0] = 1
    PREFETCHWT1,
    /// CPUID.EAX.07H.ECX.AVX512_VBMI[1] = 1 (AVX512 Vector Byte Manipulation Instructions)
    AVX512_VBMI,
    /// CPUID.EAX.07H.ECX.PKU[3] = 1 (Protection Key rights register for User pages)
    PKU,
    /// CPUID.EAX.07H.ECX.WAITPKG[5] = 1
    WAITPKG,
    /// CPUID.EAX.07H.ECX.AVX512_VBMI2[5] = 1 (AVX512 Vector Byte Manipulation Instructions 2)
    AVX512_VBMI2,
    /// CPUID.EAX.07H.ECX.CET_SS[7] = 1 (Control-flow Enforcement Technology - Shadow Stack)
    CET_SS,
    /// CPUID.EAX.07H.ECX.GFNI[8] = 1
    GFNI,
    /// CPUID.EAX.07H.ECX.VAES[9] = 1
    VAES,
    /// CPUID.EAX.07H.ECX.VPCLMULQDQ[10] = 1 (Carry-less multiplication )
    VPCLMULQDQ,
    /// CPUID.EAX.07H.ECX.AVX512_VNNI[11] = 1 (AVX512 Vector Neural Network Instructions)
    AVX512_VNNI,
    /// CPUID.EAX.07H.ECX.AVX512_BITALG[12] = 1 (AVX512 Bit Algorithms)
    AVX512_BITALG,
    /// CPUID.EAX.07H.ECX.AVX512_VPOPCNTDQ[14] = 1 (AVX512 Vector Population Count Dword and Qword)
    AVX512_VPOPCNTDQ,
    /// CPUID.EAX.07H.ECX.RDPID[22] = 1
    RDPID,
    /// CPUID.EAX.07H.ECX.CLDEMOTE[25] = 1
    CLDEMOTE,
    /// CPUID.EAX.07H.ECX.MOVDIRI[27] = 1
    MOVDIRI,
    /// CPUID.EAX.07H.ECX.MOVDIR64B[28] = 1
    MOVDIR64B,

    //
    // CPUID.(EAX=7, ECX=1)
    //
    /// CPUID.(EAX=7, ECX=1).EAX.AVX512_BF16 (Brain Float16)
    AVX512_BF16,

    //
    // CPUID.(EAX=7, ECX=0).EDX
    //
    /// CPUID.EAX.07H.EDX.AVX512_4VNNIW[2] = 1 (Vector Neural Network Instructions Word (4VNNIW))
    AVX512_4VNNIW,
    /// CPUID.EAX.07H.EDX.AVX512_4FMAPS[3] = 1 (Fused Multiply Accumulation Packed Single precision (4FMAPS))
    AVX512_4FMAPS,
    /// CPUID.EAX.07H.EDX.CET_IBT[20] = 1 (Control-flow Enforcement Technology - Indirect-Branch Tracking)
    CET_IBT,

    //
    // CPUID.(EAX=0DH, ECX=1).EAX
    //
    /// CPUID.(EAX=0DH, ECX=1).EAX.XSAVEOPT[0]
    XSAVEOPT,
    /// CPUID.(EAX=0DH, ECX=1).EAX.XSAVEC[1]
    XSAVEC,
    /// CPUID.(EAX=0DH, ECX=1).EAX.XSS[3]
    XSS,

    //
    // CPUID.(EAX=14H, ECX=0).EBX
    //
    /// CPUID.[EAX=14H, ECX=0).EBX.PTWRITE[4]
    PTWRITE,

    //
    // CPUID.(EAX=0x8000_0001).ECX
    //
    /// CPUID.80000001H:ECX.LAHF_SAHF[0]  LAHF/SAHF valid in 64 bit mode
    LAHF_SAHF,
    /// CPUID.80000001H:ECX.LZCNT[5] (AMD: (ABM Advanced Bit Manipulation))
    LZCNT,
    /// CPUID.80000001H:ECX.SSE4A[6]
    SSE4A,
    /// CPUID.80000001H:ECX.PREFETCHW[8] (aka 3DNowPrefetch)
    PREFETCHW,
    /// CPUID.80000001H:ECX.XOP[11]
    XOP,
    /// CPUID.80000001H:ECX.SKINIT[12] (SKINIT / STGI)
    SKINIT,
    /// CPUID.80000001H:ECX.LWP[15] (Light Weight Profiling)
    LWP,
    /// CPUID.80000001H:ECX.FMA4[16] (Fused Multiply Add 4 operands version)
    FMA4,
    /// CPUID.80000001H:ECX.TBM[21] (Trailing Bit Manipulation)
    TBM,

    //
    // CPUID.(EAX=0x8000_0001).EDX
    //
    /// CPUID.80000001H:EDX.SYSCALL[8]
    SYSCALL,
    /// CPUID.80000001H:EDX.MMXEXT[22]
    MMXEXT,
    /// CPUID.80000001H:EDX.RDTSCP[27]
    RDTSCP,
    /// CPUID.80000001H:EDX.3DNOWEXT[30] (3DNow! Extensions, 3DNow!+)
    _3DNOWEXT,
    /// CPUID.80000001H:EDX.3DNOW[31] (3DNow!)
    _3DNOW,

    /// Cyrix EMMI (Extended Multi-Media Instructions) (6x86 MX and MII)
    EMMI,

    __num_cpu_features,

    pub fn toMask(self: CpuFeature) MaskType {
        return @shlExact(@as(MaskType, 1), @enumToInt(self));
    }

    pub fn arrayToMask(feature_array: []const CpuFeature) MaskType {
        var res: MaskType = 0;
        for (feature_array) |feature| {
            res |= feature.toMask();
        }
        return res;
    }
};

pub const InstructionPrefix = enum {
    Lock,
    Rep,
    Repe,
    Repne,
    Bnd,
    /// Either XACQUIRE or XRELEASE prefix, requires lock prefix to be used
    Hle,
    /// Either XACQUIRE or XRELEASE perfix, no lock prefix required
    HleNoLock,
    /// XRELEASE prefix, no lock prefix required
    Xrelease,
};

pub const InstructionEncoding = enum {
    ZO, // no operands
    I, // immediate
    I2, // IGNORE           immediate
    II, // immediate        immediate
    MII, // ModRM:r/m        immediate        immediate
    RMII, // ModRM:reg        ModRM:r/m        immediate        immediate
    O, // opcode+reg.num
    O2, // IGNORE           opcode+reg.num
    M, // ModRM:r/m
    RM, // ModRM:reg        ModRM:r/m
    MR, // ModRM:r/m        ModRM:reg
    RMI, // ModRM:reg        ModRM:r/m       immediate
    MRI, // ModRM:r/m        ModRM:reg       immediate
    OI, // opcode+reg.num   imm8/16/32/64
    MI, // ModRM:r/m        imm8/16/32/64

    MSpec, // Special memory handling for instructions like MOVS,OUTS,XLAT, etc
    D, // encode address or offset
    FD, // AL/AX/EAX/RAX    Moffs   NA  NA
    TD, // Moffs (w)        AL/AX/EAX/RAX   NA  NA

    // AvxOpcodes encodings
    RVM, // ModRM:reg        (E)VEX:vvvv     ModRM:r/m
    MVR, // ModRM:r/m        (E)VEX:vvvv     ModRM:reg
    RMV, // ModRM:reg        ModRM:r/m       (E)VEX:vvvv
    RVMR, // ModRM:reg        (E)VEX:vvvv     ModRM:r/m       imm8[7:4]:vvvv
    RVRM, // ModRM:reg        (E)VEX:vvvv     imm8[7:4]:vvvv  ModRM:r/m
    RVMRI, // ModRM:reg        (E)VEX:vvvv     ModRM:r/m       imm8[7:4]:vvvv  imm8[3:0]
    RVRMI, // ModRM:reg        (E)VEX:vvvv     imm8[7:4]:vvvv  ModRM:r/m       imm8[3:0]
    RVMI, // ModRM:reg        (E)VEX:vvvv     ModRM:r/m       imm8
    VMI, // (E)VEX:vvvv      ModRM:r/m       imm8
    VM, // (E)VEX.vvvv      ModRM:r/m
    MV, // ModRM:r/m        (E)VEX:vvvv
    vRMI, // ModRM:reg        ModRM:r/m       imm8
    vMRI, // ModRM:r/m        ModRM:reg       imm8
    vRM, // ModRM:reg        ModRM:r/m
    vMR, // ModRM:reg        ModRM:r/m
    vM, // ModRm:r/m
    vZO, //

    pub fn getMemPos(self: InstructionEncoding) ?u8 {
        return switch (self) {
            .M, .MR, .MRI, .MI, .MVR, .MV, .vMRI, .vMR, .vM => 0,
            .RM, .RMI, .RMV, .VMI, .VM, .vRM => 1,
            .RVM, .RVMR, .RVMI => 2,
            else => null,
        };
    }
};

pub const OpcodeAnyTag = enum {
    Op,
    Avx,
};

pub const OpcodeAny = union(OpcodeAnyTag) {
    Op: Opcode,
    Avx: AvxOpcode,
};

pub const InstructionItem = struct {
    mnemonic: Mnemonic,
    signature: Signature,
    opcode: OpcodeAny,
    encoding: InstructionEncoding,
    overides: Overides,
    edge_case: OpcodeEdgeCase,
    mode_edge_case: OpcodeEdgeCase,
    disp_n: u8,
    cpu_feature_mask: CpuFeature.MaskType,

    fn create(
        mnem: Mnemonic,
        signature: Signature,
        opcode: anytype,
        encoding: InstructionEncoding,
        overides: Overides,
        extra_opts: anytype,
    ) InstructionItem {
        _ = @setEvalBranchQuota(100000);
        var edge_case = OpcodeEdgeCase.None;
        var mode_edge_case = OpcodeEdgeCase.None;
        var cpu_feature_mask: CpuFeature.MaskType = 0;
        var disp_n: u8 = 1;

        const opcode_any = switch (@TypeOf(opcode)) {
            Opcode => OpcodeAny{ .Op = opcode },
            AvxOpcode => x: {
                if (encoding.getMemPos()) |pos| {
                    const op_type = signature.operands[pos];
                    disp_n = x86.avx.calcDispMultiplier(opcode, op_type);
                } else {
                    // don't care if no memory
                }
                break :x OpcodeAny{ .Avx = opcode };
            },
            else => @compileError("opcode: Expected Opcode or AvxOpcode, got: " ++ @TypeOf(opcode)),
        };

        if (@typeInfo(@TypeOf(extra_opts)) != .Struct) {
            @compileError("extra_opts: Expected tuple or struct argument, found " ++ @typeName(@TypeOf(args)));
        }

        for (extra_opts) |opt, i| {
            switch (@TypeOf(opt)) {
                CpuFeature => cpu_feature_mask |= opt.toMask(),

                InstructionPrefix => {
                    // TODO:
                },

                OpcodeEdgeCase => {
                    switch (opt) {
                        .No32, .No64 => {
                            assert(mode_edge_case == .None);
                            mode_edge_case = opt;
                        },
                        .Undefined => {
                            // TODO:
                        },
                        else => {
                            assert(edge_case == .None);
                            edge_case = opt;
                        },
                    }
                },

                else => |bad_type| {
                    @compileError("Unsupported feature/version field type: " ++ @typeName(bad_type));
                },
            }
        }

        return InstructionItem{
            .mnemonic = mnem,
            .signature = signature,
            .opcode = opcode_any,
            .encoding = encoding,
            .overides = overides,
            .edge_case = edge_case,
            .mode_edge_case = mode_edge_case,
            .disp_n = disp_n,
            .cpu_feature_mask = cpu_feature_mask,
        };
    }
    pub fn hasEdgeCase(self: InstructionItem) callconv(.Inline) bool {
        return self.edge_case != .None;
    }
    pub fn isMachineMatch(self: InstructionItem, machine: Machine) callconv(.Inline) bool {
        if (self.cpu_feature_mask & machine.cpu_feature_mask != self.cpu_feature_mask) {
            return false;
        }

        switch (self.mode_edge_case) {
            .None => {},
            .No64 => if (machine.mode == .x64) return false,
            .No32 => if (machine.mode == .x86_32 or machine.mode == .x86_16) return false,
            else => unreachable,
        }
        return true;
    }

    pub fn matchesEdgeCase(
        self: InstructionItem,
        machine: Machine,
        op1: ?*const Operand,
        op2: ?*const Operand,
        op3: ?*const Operand,
        op4: ?*const Operand,
        op5: ?*const Operand,
    ) bool {
        return self.edge_case.isEdgeCase(self, machine.mode, op1, op2, op3, op4, op5);
    }

    /// Calculates the total length of instruction (without prefixes or rex)
    pub fn calcLengthLegacy(self: *const InstructionItem, modrm: ?x86.operand.ModRmResult) u8 {
        var result: u8 = 0;

        switch (self.opcode) {
            .Op => |op| result += op.byteCount(),
            else => unreachable,
        }
        result += self.totalImmediateSize();

        if (modrm) |rm| {
            if (rm.sib != null) {
                // modrm + sib byte
                result += 2;
            } else {
                // modrm byte only
                result += 1;
            }
            result += rm.disp_bit_size.valueBytes();
        }

        return result;
    }

    pub fn totalImmediateSize(self: InstructionItem) u8 {
        var res: u8 = 0;
        for (self.signature.operands) |ops| {
            switch (ops) {
                .imm8 => res += 1,
                .imm16 => res += 2,
                .imm32 => res += 4,
                .imm64 => res += 8,
                .none => break,
                else => continue,
            }
        }
        return res;
    }

    pub fn coerceImm(self: InstructionItem, op: ?*const Operand, pos: u8) Immediate {
        switch (self.signature.operands[pos]) {
            .imm8 => return op.?.*.Imm,
            .imm16 => return op.?.*.Imm.coerce(.Bit16),
            .imm32 => return op.?.*.Imm.coerce(.Bit32),
            .imm64 => return op.?.*.Imm.coerce(.Bit64),
            else => unreachable,
        }
    }

    pub fn encode(
        self: *const InstructionItem,
        machine: Machine,
        ctrl: ?*const EncodingControl,
        op1: ?*const Operand,
        op2: ?*const Operand,
        op3: ?*const Operand,
        op4: ?*const Operand,
        op5: ?*const Operand,
    ) AsmError!Instruction {
        return switch (self.encoding) {
            .ZO => machine.encodeRMI(self, ctrl, null, null, null, self.overides),
            .M => machine.encodeRMI(self, ctrl, null, op1, null, self.overides),
            .MI => machine.encodeRMI(self, ctrl, null, op1, self.coerceImm(op2, 1), self.overides),
            .RM => machine.encodeRMI(self, ctrl, op1, op2, null, self.overides),
            .RMI => machine.encodeRMI(self, ctrl, op1, op2, self.coerceImm(op3, 2), self.overides),
            .MRI => machine.encodeRMI(self, ctrl, op2, op1, self.coerceImm(op3, 2), self.overides),
            .MR => machine.encodeRMI(self, ctrl, op2, op1, null, self.overides),
            .I => machine.encodeRMI(self, ctrl, null, null, self.coerceImm(op1, 0), self.overides),
            .I2 => machine.encodeRMI(self, ctrl, null, null, self.coerceImm(op2, 1), self.overides),
            .II => machine.encodeRMII(self, ctrl, null, null, self.coerceImm(op1, 0), self.coerceImm(op2, 1), self.overides),
            .MII => machine.encodeRMII(self, ctrl, null, op1, self.coerceImm(op2, 1), self.coerceImm(op3, 2), self.overides),
            .RMII => machine.encodeRMII(self, ctrl, op1, op2, self.coerceImm(op3, 2), self.coerceImm(op4, 3), self.overides),
            .O => machine.encodeOI(self, ctrl, op1, null, self.overides),
            .O2 => machine.encodeOI(self, ctrl, op2, null, self.overides),
            .OI => machine.encodeOI(self, ctrl, op1, self.coerceImm(op2, 1), self.overides),
            .D => machine.encodeAddress(self, ctrl, op1, self.overides),
            .FD => machine.encodeMOffset(self, ctrl, op1, op2, self.overides),
            .TD => machine.encodeMOffset(self, ctrl, op2, op1, self.overides),
            .MSpec => machine.encodeMSpecial(self, ctrl, op1, op2, self.overides),
            .RVM => machine.encodeAvx(self, ctrl, op1, op2, op3, null, null, self.disp_n),
            .MVR => machine.encodeAvx(self, ctrl, op3, op2, op1, null, null, self.disp_n),
            .RMV => machine.encodeAvx(self, ctrl, op1, op3, op2, null, null, self.disp_n),
            .VM => machine.encodeAvx(self, ctrl, null, op1, op2, null, null, self.disp_n),
            .MV => machine.encodeAvx(self, ctrl, null, op2, op1, null, null, self.disp_n),
            .RVMI => machine.encodeAvx(self, ctrl, op1, op2, op3, null, op4, self.disp_n),
            .VMI => machine.encodeAvx(self, ctrl, null, op1, op2, null, op3, self.disp_n),
            .RVMR => machine.encodeAvx(self, ctrl, op1, op2, op3, op4, null, self.disp_n),
            .RVMRI => machine.encodeAvx(self, ctrl, op1, op2, op3, op4, op5, self.disp_n),
            .RVRM => machine.encodeAvx(self, ctrl, op1, op2, op4, op3, null, self.disp_n),
            .RVRMI => machine.encodeAvx(self, ctrl, op1, op2, op4, op3, op5, self.disp_n),
            .vRMI => machine.encodeAvx(self, ctrl, op1, null, op2, null, op3, self.disp_n),
            .vMRI => machine.encodeAvx(self, ctrl, op2, null, op1, null, op3, self.disp_n),
            .vRM => machine.encodeAvx(self, ctrl, op1, null, op2, null, null, self.disp_n),
            .vMR => machine.encodeAvx(self, ctrl, op2, null, op1, null, null, self.disp_n),
            .vM => machine.encodeAvx(self, ctrl, null, null, op1, null, null, self.disp_n),
            .vZO => machine.encodeAvx(self, ctrl, null, null, null, null, null, self.disp_n),
        };
    }
};

/// Generate a map from Mnemonic -> index in the instruction database
fn genMnemonicLookupTable() [Mnemonic.count]u16 {
    comptime {
        var result: [Mnemonic.count]u16 = undefined;
        var current_mnem = Mnemonic._mnemonic_final;

        _ = @setEvalBranchQuota(50000);

        for (result) |*val| {
            val.* = 0xffff;
        }

        for (instruction_database) |item, i| {
            if (item.mnemonic != current_mnem) {
                current_mnem = item.mnemonic;

                if (current_mnem == ._mnemonic_final) {
                    break;
                }
                if (result[@enumToInt(current_mnem)] != 0xffff) {
                    @compileError("Mnemonic mislocated in lookup table. " ++ @tagName(current_mnem));
                }
                result[@enumToInt(current_mnem)] = @intCast(u16, i);
            }
        }

        if (false) {
            // Count the number of unimplemented mnemonics
            var count: u16 = 0;
            for (result) |val, mnem_index| {
                if (val == 0xffff) {
                    @compileLog(@intToEnum(Mnemonic, mnem_index));
                    count += 1;
                }
            }
            @compileLog("Unreferenced mnemonics: ", count);
        }

        return result;
    }
}

pub fn lookupMnemonic(mnem: Mnemonic) usize {
    const result = lookup_table[@enumToInt(mnem)];
    if (result == 0xffff) {
        std.debug.panic("Instruction {} not implemented yet", .{mnem});
    }
    return result;
}

pub fn getDatabaseItem(index: usize) *const InstructionItem {
    return &instruction_database[index];
}

pub const lookup_table: [Mnemonic.count]u16 = genMnemonicLookupTable();

const Op1 = x86.Opcode.op1;
const Op2 = x86.Opcode.op2;
const Op3 = x86.Opcode.op3;

const Op1r = x86.Opcode.op1r;
const Op2r = x86.Opcode.op2r;
const Op3r = x86.Opcode.op3r;

// Opcodes with compulsory prefix that needs to precede other prefixes
const preOp1 = x86.Opcode.preOp1;
const preOp2 = x86.Opcode.preOp2;
const preOp1r = x86.Opcode.preOp1r;
const preOp2r = x86.Opcode.preOp2r;
const preOp3 = x86.Opcode.preOp3;
const preOp3r = x86.Opcode.preOp3r;

// Opcodes that are actually composed of multiple instructions
// eg: FSTENV needs prefix 0x9B before other prefixes, because 0x9B is
// actually the opcode FWAIT/WAIT
const compOp2 = x86.Opcode.compOp2;
const compOp1r = x86.Opcode.compOp1r;

const Op3DNow = x86.Opcode.op3DNow;

const ops0 = Signature.ops0;
const ops1 = Signature.ops1;
const ops2 = Signature.ops2;
const ops3 = Signature.ops3;
const ops4 = Signature.ops4;
const ops5 = Signature.ops5;

const vex = x86.avx.AvxOpcode.vex;
const vexr = x86.avx.AvxOpcode.vexr;
const evex = x86.avx.AvxOpcode.evex;
const evexr = x86.avx.AvxOpcode.evexr;
const xop = x86.avx.AvxOpcode.xop;
const xopr = x86.avx.AvxOpcode.xopr;

const instr = InstructionItem.create;

/// Create a vector instruction
fn vec(
    mnem: Mnemonic,
    signature: Signature,
    opcode: anytype,
    en: InstructionEncoding,
    extra_opts: anytype,
) InstructionItem {
    return InstructionItem.create(mnem, signature, opcode, en, .ZO, extra_opts);
}

const cpu = CpuFeature;
const edge = OpcodeEdgeCase;

const No64 = OpcodeEdgeCase.No64;
const No32 = OpcodeEdgeCase.No32;
const Sign = OpcodeEdgeCase.Sign;
const NoSign = OpcodeEdgeCase.NoSign;

const Lock = InstructionPrefix.Lock;
const Rep = InstructionPrefix.Rep;
const Repe = InstructionPrefix.Repe;
const Repne = InstructionPrefix.Repne;
const Bnd = InstructionPrefix.Bnd;
const Hle = InstructionPrefix.Hle;
const HleNoLock = InstructionPrefix.HleNoLock;
const Xrelease = InstructionPrefix.Xrelease;

const _8086_Legacy = cpu._8086_Legacy;
const _186_Legacy = cpu._186_Legacy;
const _286_Legacy = cpu._286_Legacy;
const _386_Legacy = cpu._386_Legacy;
const _486_Legacy = cpu._486_Legacy;

const _8086 = cpu._8086;
const _186 = cpu._186;
const _286 = cpu._286;
const _386 = cpu._386;
const _486 = cpu._486;
const x86_64 = cpu.x86_64;
const P6 = cpu.P6;

const _087 = cpu._087;
const _187 = cpu._187;
const _287 = cpu._287;
const _387 = cpu._387;

const MMX = cpu.MMX;
const MMXEXT = cpu.MMXEXT;
const SSE = cpu.SSE;
const SSE2 = cpu.SSE2;
const SSE3 = cpu.SSE3;
const SSSE3 = cpu.SSSE3;
const SSE4A = cpu.SSE4A;
const SSE4_1 = cpu.SSE4_1;
const SSE4_2 = cpu.SSE4_2;
const AVX = cpu.AVX;
const AVX2 = cpu.AVX2;
const AVX512F = cpu.AVX512F;
const AVX512CD = cpu.AVX512CD;
const AVX512ER = cpu.AVX512ER;
const AVX512PF = cpu.AVX512PF;
const AVX512VL = cpu.AVX512VL;
const AVX512BW = cpu.AVX512BW;
const AVX512DQ = cpu.AVX512DQ;
const AVX512_BITALG = cpu.AVX512_BITALG;
const AVX512_IFMA = cpu.AVX512_IFMA;
const AVX512_VBMI = cpu.AVX512_VBMI;
const AVX512_VBMI2 = cpu.AVX512_VBMI2;
const AVX512_VNNI = cpu.AVX512_VNNI;
const AVX512_VPOPCNTDQ = cpu.AVX512_VPOPCNTDQ;
const FMA = cpu.FMA;
const GFNI = cpu.GFNI;
const VAES = cpu.VAES;

const nomem = x86.avx.TupleType.NoMem;
const full = x86.avx.TupleType.Full;
const half = x86.avx.TupleType.Half;
const t1s = x86.avx.TupleType.Tuple1Scalar;
const t1f = x86.avx.TupleType.Tuple1Fixed;
const tup2 = x86.avx.TupleType.Tuple2;
const tup4 = x86.avx.TupleType.Tuple4;
const tup8 = x86.avx.TupleType.Tuple8;
const fmem = x86.avx.TupleType.FullMem;
const hmem = x86.avx.TupleType.HalfMem;
const qmem = x86.avx.TupleType.QuarterMem;
const emem = x86.avx.TupleType.EighthMem;
const mem128 = x86.avx.TupleType.Mem128;
const dup = x86.avx.TupleType.Movddup;

// NOTE: Entries into this table should be from most specific to most general.
// For example, if a instruction takes both a reg64 and rm64 value, an operand
// of Operand.register(.RAX) can match both, while a Operand.registerRm(.RAX)
// can only match the rm64 value.
//
// Putting the most specific opcodes first enables us to reach every possible
// encoding for an instruction.
//
// User supplied immediates without an explicit size are allowed to match
// against larger immediate sizes:
//      * imm8  <-> imm8,  imm16, imm32, imm64
//      * imm16 <-> imm16, imm32, imm64
//      * imm32 <-> imm32, imm64
// So if there are multiple operand signatures that only differ by there
// immediate size, we must place the version with the smaller immediate size
// first. This insures that the shortest encoding is chosen when the operand
// is an Immediate without a fixed size.
pub const instruction_database = [_]InstructionItem{
    //
    // 8086 / 80186
    //

    // AAA
    instr(.AAA, ops0(), Op1(0x37), .ZO, .ZO, .{ _8086, No64 }),
    // AAD
    instr(.AAD, ops0(), Op2(0xD5, 0x0A), .ZO, .ZO, .{ _8086, No64 }),
    instr(.AAD, ops1(.imm8), Op1(0xD5), .I, .ZO, .{ _8086, No64 }),
    // AAM
    instr(.AAM, ops0(), Op2(0xD4, 0x0A), .ZO, .ZO, .{ _8086, No64 }),
    instr(.AAM, ops1(.imm8), Op1(0xD4), .I, .ZO, .{ _8086, No64 }),
    // AAS
    instr(.AAS, ops0(), Op1(0x3F), .ZO, .ZO, .{ _8086, No64 }),
    // ADC
    instr(.ADC, ops2(.reg_al, .imm8), Op1(0x14), .I2, .ZO, .{_8086}),
    instr(.ADC, ops2(.rm8, .imm8), Op1r(0x80, 2), .MI, .ZO, .{ _8086, Lock, Hle }),
    instr(.ADC, ops2(.rm16, .imm8), Op1r(0x83, 2), .MI, .Op16, .{ _8086, Sign, Lock, Hle }),
    instr(.ADC, ops2(.rm32, .imm8), Op1r(0x83, 2), .MI, .Op32, .{ _386, Sign, Lock, Hle }),
    instr(.ADC, ops2(.rm64, .imm8), Op1r(0x83, 2), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.ADC, ops2(.reg_ax, .imm16), Op1(0x15), .I2, .Op16, .{_8086}),
    instr(.ADC, ops2(.reg_eax, .imm32), Op1(0x15), .I2, .Op32, .{_386}),
    instr(.ADC, ops2(.reg_rax, .imm32), Op1(0x15), .I2, .REX_W, .{ x86_64, Sign }),
    //
    instr(.ADC, ops2(.rm16, .imm16), Op1r(0x81, 2), .MI, .Op16, .{ _8086, Lock, Hle }),
    instr(.ADC, ops2(.rm32, .imm32), Op1r(0x81, 2), .MI, .Op32, .{ _386, Lock, Hle }),
    instr(.ADC, ops2(.rm64, .imm32), Op1r(0x81, 2), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.ADC, ops2(.rm8, .reg8), Op1(0x10), .MR, .ZO, .{ _8086, Lock, Hle }),
    instr(.ADC, ops2(.rm16, .reg16), Op1(0x11), .MR, .Op16, .{ _8086, Lock, Hle }),
    instr(.ADC, ops2(.rm32, .reg32), Op1(0x11), .MR, .Op32, .{ _386, Lock, Hle }),
    instr(.ADC, ops2(.rm64, .reg64), Op1(0x11), .MR, .REX_W, .{ x86_64, Lock, Hle }),
    //
    instr(.ADC, ops2(.reg8, .rm8), Op1(0x12), .RM, .ZO, .{_8086}),
    instr(.ADC, ops2(.reg16, .rm16), Op1(0x13), .RM, .Op16, .{_8086}),
    instr(.ADC, ops2(.reg32, .rm32), Op1(0x13), .RM, .Op32, .{_386}),
    instr(.ADC, ops2(.reg64, .rm64), Op1(0x13), .RM, .REX_W, .{x86_64}),
    // ADD
    instr(.ADD, ops2(.reg_al, .imm8), Op1(0x04), .I2, .ZO, .{_8086}),
    instr(.ADD, ops2(.rm8, .imm8), Op1r(0x80, 0), .MI, .ZO, .{ _8086, Lock, Hle }),
    instr(.ADD, ops2(.rm16, .imm8), Op1r(0x83, 0), .MI, .Op16, .{ _8086, Sign, Lock, Hle }),
    instr(.ADD, ops2(.rm32, .imm8), Op1r(0x83, 0), .MI, .Op32, .{ _386, Sign, Lock, Hle }),
    instr(.ADD, ops2(.rm64, .imm8), Op1r(0x83, 0), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.ADD, ops2(.reg_ax, .imm16), Op1(0x05), .I2, .Op16, .{_8086}),
    instr(.ADD, ops2(.reg_eax, .imm32), Op1(0x05), .I2, .Op32, .{_386}),
    instr(.ADD, ops2(.reg_rax, .imm32), Op1(0x05), .I2, .REX_W, .{ x86_64, Sign }),
    //
    instr(.ADD, ops2(.rm16, .imm16), Op1r(0x81, 0), .MI, .Op16, .{ _8086, Lock, Hle }),
    instr(.ADD, ops2(.rm32, .imm32), Op1r(0x81, 0), .MI, .Op32, .{ _386, Lock, Hle }),
    instr(.ADD, ops2(.rm64, .imm32), Op1r(0x81, 0), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.ADD, ops2(.rm8, .reg8), Op1(0x00), .MR, .ZO, .{ _8086, Lock, Hle }),
    instr(.ADD, ops2(.rm16, .reg16), Op1(0x01), .MR, .Op16, .{ _8086, Lock, Hle }),
    instr(.ADD, ops2(.rm32, .reg32), Op1(0x01), .MR, .Op32, .{ _386, Lock, Hle }),
    instr(.ADD, ops2(.rm64, .reg64), Op1(0x01), .MR, .REX_W, .{ x86_64, Lock, Hle }),
    //
    instr(.ADD, ops2(.reg8, .rm8), Op1(0x02), .RM, .ZO, .{_8086}),
    instr(.ADD, ops2(.reg16, .rm16), Op1(0x03), .RM, .Op16, .{_8086}),
    instr(.ADD, ops2(.reg32, .rm32), Op1(0x03), .RM, .Op32, .{_386}),
    instr(.ADD, ops2(.reg64, .rm64), Op1(0x03), .RM, .REX_W, .{x86_64}),
    // AND
    instr(.AND, ops2(.reg_al, .imm8), Op1(0x24), .I2, .ZO, .{_8086}),
    instr(.AND, ops2(.rm8, .imm8), Op1r(0x80, 4), .MI, .ZO, .{ _8086, Lock, Hle }),
    instr(.AND, ops2(.rm16, .imm8), Op1r(0x83, 4), .MI, .Op16, .{ _8086, Sign, Lock, Hle }),
    instr(.AND, ops2(.rm32, .imm8), Op1r(0x83, 4), .MI, .Op32, .{ _386, Sign, Lock, Hle }),
    instr(.AND, ops2(.rm64, .imm8), Op1r(0x83, 4), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.AND, ops2(.reg_ax, .imm16), Op1(0x25), .I2, .Op16, .{_8086}),
    instr(.AND, ops2(.reg_eax, .imm32), Op1(0x25), .I2, .Op32, .{_386}),
    instr(.AND, ops2(.reg_rax, .imm32), Op1(0x25), .I2, .REX_W, .{ x86_64, Sign }),
    //
    instr(.AND, ops2(.rm16, .imm16), Op1r(0x81, 4), .MI, .Op16, .{ _8086, Lock, Hle }),
    instr(.AND, ops2(.rm32, .imm32), Op1r(0x81, 4), .MI, .Op32, .{ _386, Lock, Hle }),
    instr(.AND, ops2(.rm64, .imm32), Op1r(0x81, 4), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.AND, ops2(.rm8, .reg8), Op1(0x20), .MR, .ZO, .{ _8086, Lock, Hle }),
    instr(.AND, ops2(.rm16, .reg16), Op1(0x21), .MR, .Op16, .{ _8086, Lock, Hle }),
    instr(.AND, ops2(.rm32, .reg32), Op1(0x21), .MR, .Op32, .{ _386, Lock, Hle }),
    instr(.AND, ops2(.rm64, .reg64), Op1(0x21), .MR, .REX_W, .{ x86_64, Lock, Hle }),
    //
    instr(.AND, ops2(.reg8, .rm8), Op1(0x22), .RM, .ZO, .{_8086}),
    instr(.AND, ops2(.reg16, .rm16), Op1(0x23), .RM, .Op16, .{_8086}),
    instr(.AND, ops2(.reg32, .rm32), Op1(0x23), .RM, .Op32, .{_386}),
    instr(.AND, ops2(.reg64, .rm64), Op1(0x23), .RM, .REX_W, .{x86_64}),
    // BOUND
    instr(.BOUND, ops2(.reg16, .rm16), Op1(0x62), .RM, .Op16, .{ _186, No64 }),
    instr(.BOUND, ops2(.reg32, .rm32), Op1(0x62), .RM, .Op32, .{ _186, No64 }),
    // CALL
    instr(.CALL, ops1(.imm16), Op1(0xE8), .I, .Op16, .{ _8086, Bnd, No64 }),
    instr(.CALL, ops1(.imm32), Op1(0xE8), .I, .Op32, .{ _386, Bnd }),
    //
    instr(.CALL, ops1(.rm16), Op1r(0xFF, 2), .M, .Op16, .{ _8086, Bnd, No64 }),
    instr(.CALL, ops1(.rm32), Op1r(0xFF, 2), .M, .Op32, .{ _386, Bnd, No64 }),
    instr(.CALL, ops1(.rm64), Op1r(0xFF, 2), .M, .ZO, .{ x86_64, Bnd, No32 }),
    //
    instr(.CALL, ops1(.ptr16_16), Op1r(0x9A, 4), .D, .Op16, .{ _8086, No64 }),
    instr(.CALL, ops1(.ptr16_32), Op1r(0x9A, 4), .D, .Op32, .{ _386, No64 }),
    //
    instr(.CALL, ops1(.m16_16), Op1r(0xFF, 3), .M, .Op16, .{_8086}),
    instr(.CALL, ops1(.m16_32), Op1r(0xFF, 3), .M, .Op32, .{_386}),
    instr(.CALL, ops1(.m16_64), Op1r(0xFF, 3), .M, .REX_W, .{x86_64}),
    // CBW
    instr(.CBW, ops0(), Op1(0x98), .ZO, .Op16, .{_8086}),
    instr(.CWDE, ops0(), Op1(0x98), .ZO, .Op32, .{_386}),
    instr(.CDQE, ops0(), Op1(0x98), .ZO, .REX_W, .{x86_64}),
    //
    instr(.CWD, ops0(), Op1(0x99), .ZO, .Op16, .{_8086}),
    instr(.CDQ, ops0(), Op1(0x99), .ZO, .Op32, .{_386}),
    instr(.CQO, ops0(), Op1(0x99), .ZO, .REX_W, .{x86_64}),
    // CLC
    instr(.CLC, ops0(), Op1(0xF8), .ZO, .ZO, .{_8086}),
    // CLD
    instr(.CLD, ops0(), Op1(0xFC), .ZO, .ZO, .{_8086}),
    // CLI
    instr(.CLI, ops0(), Op1(0xFA), .ZO, .ZO, .{_8086}),
    // CMC
    instr(.CMC, ops0(), Op1(0xF5), .ZO, .ZO, .{_8086}),
    // CMP
    instr(.CMP, ops2(.reg_al, .imm8), Op1(0x3C), .I2, .ZO, .{_8086}),
    instr(.CMP, ops2(.rm8, .imm8), Op1r(0x80, 7), .MI, .ZO, .{_8086}),
    instr(.CMP, ops2(.rm16, .imm8), Op1r(0x83, 7), .MI, .Op16, .{ _8086, Sign }),
    instr(.CMP, ops2(.rm32, .imm8), Op1r(0x83, 7), .MI, .Op32, .{ _386, Sign }),
    instr(.CMP, ops2(.rm64, .imm8), Op1r(0x83, 7), .MI, .REX_W, .{ x86_64, Sign }),
    //
    instr(.CMP, ops2(.reg_ax, .imm16), Op1(0x3D), .I2, .Op16, .{_8086}),
    instr(.CMP, ops2(.reg_eax, .imm32), Op1(0x3D), .I2, .Op32, .{_386}),
    instr(.CMP, ops2(.reg_rax, .imm32), Op1(0x3D), .I2, .REX_W, .{ x86_64, Sign }),
    //
    instr(.CMP, ops2(.rm16, .imm16), Op1r(0x81, 7), .MI, .Op16, .{_8086}),
    instr(.CMP, ops2(.rm32, .imm32), Op1r(0x81, 7), .MI, .Op32, .{_386}),
    instr(.CMP, ops2(.rm64, .imm32), Op1r(0x81, 7), .MI, .REX_W, .{ x86_64, Sign }),
    //
    instr(.CMP, ops2(.rm8, .reg8), Op1(0x38), .MR, .ZO, .{_8086}),
    instr(.CMP, ops2(.rm16, .reg16), Op1(0x39), .MR, .Op16, .{_8086}),
    instr(.CMP, ops2(.rm32, .reg32), Op1(0x39), .MR, .Op32, .{_386}),
    instr(.CMP, ops2(.rm64, .reg64), Op1(0x39), .MR, .REX_W, .{x86_64}),
    //
    instr(.CMP, ops2(.reg8, .rm8), Op1(0x3A), .RM, .ZO, .{_8086}),
    instr(.CMP, ops2(.reg16, .rm16), Op1(0x3B), .RM, .Op16, .{_8086}),
    instr(.CMP, ops2(.reg32, .rm32), Op1(0x3B), .RM, .Op32, .{_386}),
    instr(.CMP, ops2(.reg64, .rm64), Op1(0x3B), .RM, .REX_W, .{x86_64}),
    // CMPS / CMPSB / CMPSW / CMPSD / CMPSQ
    instr(.CMPS, ops2(.rm_mem8, .rm_mem8), Op1(0xA6), .MSpec, .ZO, .{ _8086, Repe, Repne }),
    instr(.CMPS, ops2(.rm_mem16, .rm_mem16), Op1(0xA7), .MSpec, .Op16, .{ _8086, Repe, Repne }),
    instr(.CMPS, ops2(.rm_mem32, .rm_mem32), Op1(0xA7), .MSpec, .Op32, .{ _386, Repe, Repne }),
    instr(.CMPS, ops2(.rm_mem64, .rm_mem64), Op1(0xA7), .MSpec, .REX_W, .{ x86_64, Repe, Repne }),
    //
    instr(.CMPSB, ops0(), Op1(0xA6), .ZO, .ZO, .{ _8086, Repe, Repne }),
    instr(.CMPSW, ops0(), Op1(0xA7), .ZO, .Op16, .{ _8086, Repe, Repne }),
    // instr(.CMPSD,   ops0(),                     Op1(0xA7),              .ZO, .Op32,    .{_386, Repe, Repne} ), // overloaded
    instr(.CMPSQ, ops0(), Op1(0xA7), .ZO, .REX_W, .{ x86_64, No32, Repe, Repne }),
    // DAA
    instr(.DAA, ops0(), Op1(0x27), .ZO, .ZO, .{ _8086, No64 }),
    // DAS
    instr(.DAS, ops0(), Op1(0x2F), .ZO, .ZO, .{ _8086, No64 }),
    // DEC
    instr(.DEC, ops1(.reg16), Op1(0x48), .O, .Op16, .{ _8086, No64 }),
    instr(.DEC, ops1(.reg32), Op1(0x48), .O, .Op32, .{ _386, No64 }),
    instr(.DEC, ops1(.rm8), Op1r(0xFE, 1), .M, .ZO, .{ _8086, Lock, Hle }),
    instr(.DEC, ops1(.rm16), Op1r(0xFF, 1), .M, .Op16, .{ _8086, Lock, Hle }),
    instr(.DEC, ops1(.rm32), Op1r(0xFF, 1), .M, .Op32, .{ _386, Lock, Hle }),
    instr(.DEC, ops1(.rm64), Op1r(0xFF, 1), .M, .REX_W, .{ x86_64, Lock, Hle }),
    // DIV
    instr(.DIV, ops1(.rm8), Op1r(0xF6, 6), .M, .ZO, .{_8086}),
    instr(.DIV, ops1(.rm16), Op1r(0xF7, 6), .M, .Op16, .{_8086}),
    instr(.DIV, ops1(.rm32), Op1r(0xF7, 6), .M, .Op32, .{_386}),
    instr(.DIV, ops1(.rm64), Op1r(0xF7, 6), .M, .REX_W, .{x86_64}),
    // ENTER
    instr(.ENTER, ops2(.imm16, .imm8), Op1(0xC8), .II, .ZO, .{_186}),
    instr(.ENTERW, ops2(.imm16, .imm8), Op1(0xC8), .II, .Op16, .{_186}),
    instr(.ENTERD, ops2(.imm16, .imm8), Op1(0xC8), .II, .Op32, .{ _386, No64 }),
    instr(.ENTERQ, ops2(.imm16, .imm8), Op1(0xC8), .II, .ZO, .{ x86_64, No32 }),
    // HLT
    instr(.HLT, ops0(), Op1(0xF4), .ZO, .ZO, .{_8086}),
    // IDIV
    instr(.IDIV, ops1(.rm8), Op1r(0xF6, 7), .M, .ZO, .{_8086}),
    instr(.IDIV, ops1(.rm16), Op1r(0xF7, 7), .M, .Op16, .{_8086}),
    instr(.IDIV, ops1(.rm32), Op1r(0xF7, 7), .M, .Op32, .{_386}),
    instr(.IDIV, ops1(.rm64), Op1r(0xF7, 7), .M, .REX_W, .{x86_64}),
    // IMUL
    instr(.IMUL, ops1(.rm8), Op1r(0xF6, 5), .M, .ZO, .{_8086}),
    instr(.IMUL, ops1(.rm16), Op1r(0xF7, 5), .M, .Op16, .{_8086}),
    instr(.IMUL, ops1(.rm32), Op1r(0xF7, 5), .M, .Op32, .{_386}),
    instr(.IMUL, ops1(.rm64), Op1r(0xF7, 5), .M, .REX_W, .{x86_64}),
    //
    instr(.IMUL, ops2(.reg16, .rm16), Op2(0x0F, 0xAF), .RM, .Op16, .{_8086}),
    instr(.IMUL, ops2(.reg32, .rm32), Op2(0x0F, 0xAF), .RM, .Op32, .{_386}),
    instr(.IMUL, ops2(.reg64, .rm64), Op2(0x0F, 0xAF), .RM, .REX_W, .{x86_64}),
    //
    instr(.IMUL, ops3(.reg16, .rm16, .imm8), Op1(0x6B), .RMI, .Op16, .{ _186, Sign }),
    instr(.IMUL, ops3(.reg32, .rm32, .imm8), Op1(0x6B), .RMI, .Op32, .{ _386, Sign }),
    instr(.IMUL, ops3(.reg64, .rm64, .imm8), Op1(0x6B), .RMI, .REX_W, .{ x86_64, Sign }),
    //
    instr(.IMUL, ops3(.reg16, .rm16, .imm16), Op1(0x69), .RMI, .Op16, .{_186}),
    instr(.IMUL, ops3(.reg32, .rm32, .imm32), Op1(0x69), .RMI, .Op32, .{_386}),
    instr(.IMUL, ops3(.reg64, .rm64, .imm32), Op1(0x69), .RMI, .REX_W, .{ x86_64, Sign }),
    // IN
    instr(.IN, ops2(.reg_al, .imm8), Op1(0xE4), .I2, .ZO, .{_8086}),
    instr(.IN, ops2(.reg_ax, .imm8), Op1(0xE5), .I2, .Op16, .{_8086}),
    instr(.IN, ops2(.reg_eax, .imm8), Op1(0xE5), .I2, .Op32, .{_386}),
    instr(.IN, ops2(.reg_al, .reg_dx), Op1(0xEC), .ZO, .ZO, .{_8086}),
    instr(.IN, ops2(.reg_ax, .reg_dx), Op1(0xED), .ZO, .Op16, .{_8086}),
    instr(.IN, ops2(.reg_eax, .reg_dx), Op1(0xED), .ZO, .Op32, .{_386}),
    // INC
    instr(.INC, ops1(.reg16), Op1(0x40), .O, .Op16, .{ _8086, No64 }),
    instr(.INC, ops1(.reg32), Op1(0x40), .O, .Op32, .{ _386, No64 }),
    instr(.INC, ops1(.rm8), Op1r(0xFE, 0), .M, .ZO, .{ _8086, Lock, Hle }),
    instr(.INC, ops1(.rm16), Op1r(0xFF, 0), .M, .Op16, .{ _8086, Lock, Hle }),
    instr(.INC, ops1(.rm32), Op1r(0xFF, 0), .M, .Op32, .{ _386, Lock, Hle }),
    instr(.INC, ops1(.rm64), Op1r(0xFF, 0), .M, .REX_W, .{ x86_64, Lock, Hle }),
    // INS / INSB / INSW / INSD
    instr(.INS, ops2(.rm_mem8, .reg_dx), Op1(0x6C), .MSpec, .ZO, .{ _186, Rep }),
    instr(.INS, ops2(.rm_mem16, .reg_dx), Op1(0x6D), .MSpec, .Op16, .{ _186, Rep }),
    instr(.INS, ops2(.rm_mem32, .reg_dx), Op1(0x6D), .MSpec, .Op32, .{ x86_64, Rep }),
    //
    instr(.INSB, ops0(), Op1(0x6C), .ZO, .ZO, .{ _186, Rep }),
    instr(.INSW, ops0(), Op1(0x6D), .ZO, .Op16, .{ _186, Rep }),
    instr(.INSD, ops0(), Op1(0x6D), .ZO, .Op32, .{ _386, Rep }),
    // INT
    instr(.INT3, ops0(), Op1(0xCC), .ZO, .ZO, .{_8086}),
    instr(.INT, ops1(.imm8), Op1(0xCD), .I, .ZO, .{_8086}),
    instr(.INTO, ops0(), Op1(0xCE), .ZO, .ZO, .{ _8086, No64 }),
    instr(.INT1, ops0(), Op1(0xF1), .ZO, .ZO, .{_386}),
    instr(.ICEBP, ops0(), Op1(0xF1), .ZO, .ZO, .{_386}),
    // IRET
    instr(.IRET, ops0(), Op1(0xCF), .ZO, .ZO, .{_8086}),
    instr(.IRETW, ops0(), Op1(0xCF), .ZO, .Op16, .{_8086}),
    instr(.IRETD, ops0(), Op1(0xCF), .ZO, .Op32, .{ _386, No64 }),
    instr(.IRETQ, ops0(), Op1(0xCF), .ZO, .ZO, .{ x86_64, No32 }),
    // Jcc
    instr(.JCXZ, ops1(.imm8), Op1(0xE3), .I, .Addr16, .{ _8086, Sign, No64 }),
    instr(.JECXZ, ops1(.imm8), Op1(0xE3), .I, .Addr32, .{ _386, Sign }),
    instr(.JRCXZ, ops1(.imm8), Op1(0xE3), .I, .Addr64, .{ x86_64, Sign, No32 }),
    //
    instr(.JA, ops1(.imm8), Op1(0x77), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JA, ops1(.imm16), Op2(0x0F, 0x87), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JA, ops1(.imm32), Op2(0x0F, 0x87), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JAE, ops1(.imm8), Op1(0x73), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JAE, ops1(.imm16), Op2(0x0F, 0x83), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JAE, ops1(.imm32), Op2(0x0F, 0x83), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JB, ops1(.imm8), Op1(0x72), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JB, ops1(.imm16), Op2(0x0F, 0x82), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JB, ops1(.imm32), Op2(0x0F, 0x82), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JBE, ops1(.imm8), Op1(0x76), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JBE, ops1(.imm16), Op2(0x0F, 0x86), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JBE, ops1(.imm32), Op2(0x0F, 0x86), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JC, ops1(.imm8), Op1(0x72), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JC, ops1(.imm16), Op2(0x0F, 0x82), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JC, ops1(.imm32), Op2(0x0F, 0x82), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JE, ops1(.imm8), Op1(0x74), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JE, ops1(.imm16), Op2(0x0F, 0x84), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JE, ops1(.imm32), Op2(0x0F, 0x84), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JG, ops1(.imm8), Op1(0x7F), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JG, ops1(.imm16), Op2(0x0F, 0x8F), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JG, ops1(.imm32), Op2(0x0F, 0x8F), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JGE, ops1(.imm8), Op1(0x7D), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JGE, ops1(.imm16), Op2(0x0F, 0x8D), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JGE, ops1(.imm32), Op2(0x0F, 0x8D), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JL, ops1(.imm8), Op1(0x7C), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JL, ops1(.imm16), Op2(0x0F, 0x8C), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JL, ops1(.imm32), Op2(0x0F, 0x8C), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JLE, ops1(.imm8), Op1(0x7E), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JLE, ops1(.imm16), Op2(0x0F, 0x8E), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JLE, ops1(.imm32), Op2(0x0F, 0x8E), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNA, ops1(.imm8), Op1(0x76), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNA, ops1(.imm16), Op2(0x0F, 0x86), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNA, ops1(.imm32), Op2(0x0F, 0x86), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNAE, ops1(.imm8), Op1(0x72), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNAE, ops1(.imm16), Op2(0x0F, 0x82), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNAE, ops1(.imm32), Op2(0x0F, 0x82), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNB, ops1(.imm8), Op1(0x73), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNB, ops1(.imm16), Op2(0x0F, 0x83), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNB, ops1(.imm32), Op2(0x0F, 0x83), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNBE, ops1(.imm8), Op1(0x77), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNBE, ops1(.imm16), Op2(0x0F, 0x87), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNBE, ops1(.imm32), Op2(0x0F, 0x87), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNC, ops1(.imm8), Op1(0x73), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNC, ops1(.imm16), Op2(0x0F, 0x83), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNC, ops1(.imm32), Op2(0x0F, 0x83), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNE, ops1(.imm8), Op1(0x75), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNE, ops1(.imm16), Op2(0x0F, 0x85), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNE, ops1(.imm32), Op2(0x0F, 0x85), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNG, ops1(.imm8), Op1(0x7E), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNG, ops1(.imm16), Op2(0x0F, 0x8E), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNG, ops1(.imm32), Op2(0x0F, 0x8E), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNGE, ops1(.imm8), Op1(0x7C), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNGE, ops1(.imm16), Op2(0x0F, 0x8C), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNGE, ops1(.imm32), Op2(0x0F, 0x8C), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNL, ops1(.imm8), Op1(0x7D), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNL, ops1(.imm16), Op2(0x0F, 0x8D), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNL, ops1(.imm32), Op2(0x0F, 0x8D), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNLE, ops1(.imm8), Op1(0x7F), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNLE, ops1(.imm16), Op2(0x0F, 0x8F), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNLE, ops1(.imm32), Op2(0x0F, 0x8F), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNO, ops1(.imm8), Op1(0x71), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNO, ops1(.imm16), Op2(0x0F, 0x81), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNO, ops1(.imm32), Op2(0x0F, 0x81), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNP, ops1(.imm8), Op1(0x7B), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNP, ops1(.imm16), Op2(0x0F, 0x8B), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNP, ops1(.imm32), Op2(0x0F, 0x8B), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNS, ops1(.imm8), Op1(0x79), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNS, ops1(.imm16), Op2(0x0F, 0x89), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNS, ops1(.imm32), Op2(0x0F, 0x89), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JNZ, ops1(.imm8), Op1(0x75), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JNZ, ops1(.imm16), Op2(0x0F, 0x85), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JNZ, ops1(.imm32), Op2(0x0F, 0x85), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JO, ops1(.imm8), Op1(0x70), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JO, ops1(.imm16), Op2(0x0F, 0x80), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JO, ops1(.imm32), Op2(0x0F, 0x80), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JP, ops1(.imm8), Op1(0x7A), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JP, ops1(.imm16), Op2(0x0F, 0x8A), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JP, ops1(.imm32), Op2(0x0F, 0x8A), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JPE, ops1(.imm8), Op1(0x7A), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JPE, ops1(.imm16), Op2(0x0F, 0x8A), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JPE, ops1(.imm32), Op2(0x0F, 0x8A), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JPO, ops1(.imm8), Op1(0x7B), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JPO, ops1(.imm16), Op2(0x0F, 0x8B), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JPO, ops1(.imm32), Op2(0x0F, 0x8B), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JS, ops1(.imm8), Op1(0x78), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JS, ops1(.imm16), Op2(0x0F, 0x88), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JS, ops1(.imm32), Op2(0x0F, 0x88), .I, .Op32, .{ _386, Sign, Bnd }),
    instr(.JZ, ops1(.imm8), Op1(0x74), .I, .ZO, .{ _8086, Sign, Bnd }),
    instr(.JZ, ops1(.imm16), Op2(0x0F, 0x84), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JZ, ops1(.imm32), Op2(0x0F, 0x84), .I, .Op32, .{ _386, Sign, Bnd }),
    // JMP
    instr(.JMP, ops1(.imm8), Op1(0xEB), .I, .ZO, .{ _8086, Sign }),
    instr(.JMP, ops1(.imm16), Op1(0xE9), .I, .Op16, .{ _8086, Sign, Bnd, No64 }),
    instr(.JMP, ops1(.imm32), Op1(0xE9), .I, .Op32, .{ _386, Sign, Bnd }),
    //
    instr(.JMP, ops1(.rm16), Op1r(0xFF, 4), .M, .Op16, .{ _8086, Bnd, No64 }),
    instr(.JMP, ops1(.rm32), Op1r(0xFF, 4), .M, .Op32, .{ _386, Bnd, No64 }),
    instr(.JMP, ops1(.rm64), Op1r(0xFF, 4), .M, .ZO, .{ x86_64, Bnd, No32 }),
    //
    instr(.JMP, ops1(.ptr16_16), Op1r(0xEA, 4), .D, .Op16, .{ _8086, No64 }),
    instr(.JMP, ops1(.ptr16_32), Op1r(0xEA, 4), .D, .Op32, .{ _386, No64 }),
    //
    instr(.JMP, ops1(.m16_16), Op1r(0xFF, 5), .M, .Op16, .{_8086}),
    instr(.JMP, ops1(.m16_32), Op1r(0xFF, 5), .M, .Op32, .{_386}),
    instr(.JMP, ops1(.m16_64), Op1r(0xFF, 5), .M, .REX_W, .{x86_64}),
    // LAHF
    instr(.LAHF, ops0(), Op1(0x9F), .ZO, .ZO, .{ _8086, No64 }),
    instr(.LAHF, ops0(), Op1(0x9F), .ZO, .ZO, .{ _8086, cpu.LAHF_SAHF, No32 }),
    // SAHF
    instr(.SAHF, ops0(), Op1(0x9E), .ZO, .ZO, .{ _8086, No64 }),
    instr(.SAHF, ops0(), Op1(0x9E), .ZO, .ZO, .{ _8086, cpu.LAHF_SAHF, No32 }),
    //  LDS / LSS / LES / LFS / LGS
    instr(.LDS, ops2(.reg16, .m16_16), Op1(0xC5), .RM, .Op16, .{ _8086, No64 }),
    instr(.LDS, ops2(.reg32, .m16_32), Op1(0xC5), .RM, .Op32, .{ _386, No64 }),
    //
    instr(.LSS, ops2(.reg16, .m16_16), Op2(0x0F, 0xB2), .RM, .Op16, .{_386}),
    instr(.LSS, ops2(.reg32, .m16_32), Op2(0x0F, 0xB2), .RM, .Op32, .{_386}),
    instr(.LSS, ops2(.reg64, .m16_64), Op2(0x0F, 0xB2), .RM, .REX_W, .{x86_64}),
    //
    instr(.LES, ops2(.reg16, .m16_16), Op1(0xC4), .RM, .Op16, .{ _8086, No64 }),
    instr(.LES, ops2(.reg32, .m16_32), Op1(0xC4), .RM, .Op32, .{ _386, No64 }),
    //
    instr(.LFS, ops2(.reg16, .m16_16), Op2(0x0F, 0xB4), .RM, .Op16, .{_386}),
    instr(.LFS, ops2(.reg32, .m16_32), Op2(0x0F, 0xB4), .RM, .Op32, .{_386}),
    instr(.LFS, ops2(.reg64, .m16_64), Op2(0x0F, 0xB4), .RM, .REX_W, .{x86_64}),
    //
    instr(.LGS, ops2(.reg16, .m16_16), Op2(0x0F, 0xB5), .RM, .Op16, .{_386}),
    instr(.LGS, ops2(.reg32, .m16_32), Op2(0x0F, 0xB5), .RM, .Op32, .{_386}),
    instr(.LGS, ops2(.reg64, .m16_64), Op2(0x0F, 0xB5), .RM, .REX_W, .{x86_64}),
    //
    // LEA
    instr(.LEA, ops2(.reg16, .rm_mem16), Op1(0x8D), .RM, .Op16, .{_8086}),
    instr(.LEA, ops2(.reg32, .rm_mem32), Op1(0x8D), .RM, .Op32, .{_386}),
    instr(.LEA, ops2(.reg64, .rm_mem64), Op1(0x8D), .RM, .REX_W, .{x86_64}),
    // LEAVE
    instr(.LEAVE, ops0(), Op1(0xC9), .ZO, .ZO, .{_186}),
    instr(.LEAVEW, ops0(), Op1(0xC9), .ZO, .Op16, .{_186}),
    instr(.LEAVED, ops0(), Op1(0xC9), .ZO, .Op32, .{ _386, No64 }),
    instr(.LEAVEQ, ops0(), Op1(0xC9), .ZO, .ZO, .{ x86_64, No32 }),
    // LOCK
    instr(.LOCK, ops0(), Op1(0xF0), .ZO, .ZO, .{_8086}),
    // LODS / LODSB / LODSW / LODSD / LODSQ
    instr(.LODS, ops2(.reg_al, .rm_mem8), Op1(0xAC), .MSpec, .ZO, .{ _8086, Rep }),
    instr(.LODS, ops2(.reg_ax, .rm_mem16), Op1(0xAD), .MSpec, .Op16, .{ _8086, Rep }),
    instr(.LODS, ops2(.reg_eax, .rm_mem32), Op1(0xAD), .MSpec, .Op32, .{ _386, Rep }),
    instr(.LODS, ops2(.reg_rax, .rm_mem64), Op1(0xAD), .MSpec, .REX_W, .{ x86_64, Rep }),
    //
    instr(.LODSB, ops0(), Op1(0xAC), .ZO, .ZO, .{ _8086, Rep }),
    instr(.LODSW, ops0(), Op1(0xAD), .ZO, .Op16, .{ _8086, Rep }),
    instr(.LODSD, ops0(), Op1(0xAD), .ZO, .Op32, .{ _386, Rep }),
    instr(.LODSQ, ops0(), Op1(0xAD), .ZO, .REX_W, .{ x86_64, No32, Rep }),
    // LOOP
    instr(.LOOP, ops1(.imm8), Op1(0xE2), .I, .ZO, .{ _8086, Sign }),
    instr(.LOOPE, ops1(.imm8), Op1(0xE1), .I, .ZO, .{ _8086, Sign }),
    instr(.LOOPNE, ops1(.imm8), Op1(0xE0), .I, .ZO, .{ _8086, Sign }),
    //
    instr(.LOOPW, ops1(.imm8), Op1(0xE2), .I, .Addr16, .{ _386, Sign, No64 }),
    instr(.LOOPEW, ops1(.imm8), Op1(0xE1), .I, .Addr16, .{ _386, Sign, No64 }),
    instr(.LOOPNEW, ops1(.imm8), Op1(0xE0), .I, .Addr16, .{ _386, Sign, No64 }),
    //
    instr(.LOOPD, ops1(.imm8), Op1(0xE2), .I, .Addr32, .{ _386, Sign }),
    instr(.LOOPED, ops1(.imm8), Op1(0xE1), .I, .Addr32, .{ _386, Sign }),
    instr(.LOOPNED, ops1(.imm8), Op1(0xE0), .I, .Addr32, .{ _386, Sign }),
    // MOV
    instr(.MOV, ops2(.rm8, .reg8), Op1(0x88), .MR, .ZO, .{ _8086, Xrelease }),
    instr(.MOV, ops2(.rm16, .reg16), Op1(0x89), .MR, .Op16, .{ _8086, Xrelease }),
    instr(.MOV, ops2(.rm32, .reg32), Op1(0x89), .MR, .Op32, .{ _386, Xrelease }),
    instr(.MOV, ops2(.rm64, .reg64), Op1(0x89), .MR, .REX_W, .{ x86_64, Xrelease }),
    //
    instr(.MOV, ops2(.reg8, .rm8), Op1(0x8A), .RM, .ZO, .{_8086}),
    instr(.MOV, ops2(.reg16, .rm16), Op1(0x8B), .RM, .Op16, .{_8086}),
    instr(.MOV, ops2(.reg32, .rm32), Op1(0x8B), .RM, .Op32, .{_386}),
    instr(.MOV, ops2(.reg64, .rm64), Op1(0x8B), .RM, .REX_W, .{x86_64}),
    //
    instr(.MOV, ops2(.rm16, .reg_seg), Op1(0x8C), .MR, .Op16, .{_8086}),
    instr(.MOV, ops2(.rm32, .reg_seg), Op1(0x8C), .MR, .Op32, .{_386}),
    instr(.MOV, ops2(.rm64, .reg_seg), Op1(0x8C), .MR, .REX_W, .{x86_64}),
    //
    instr(.MOV, ops2(.reg_seg, .rm16), Op1(0x8E), .RM, .Op16, .{_8086}),
    instr(.MOV, ops2(.reg_seg, .rm32), Op1(0x8E), .RM, .Op32, .{_386}),
    instr(.MOV, ops2(.reg_seg, .rm64), Op1(0x8E), .RM, .REX_W, .{x86_64}),
    instr(.MOV, ops2(.reg_al, .moffs8), Op1(0xA0), .FD, .ZO, .{_8086}),
    instr(.MOV, ops2(.reg_ax, .moffs16), Op1(0xA1), .FD, .Op16, .{_8086}),
    instr(.MOV, ops2(.reg_eax, .moffs32), Op1(0xA1), .FD, .Op32, .{_386}),
    instr(.MOV, ops2(.reg_rax, .moffs64), Op1(0xA1), .FD, .REX_W, .{x86_64}),
    instr(.MOV, ops2(.moffs8, .reg_al), Op1(0xA2), .TD, .ZO, .{_8086}),
    instr(.MOV, ops2(.moffs16, .reg_ax), Op1(0xA3), .TD, .Op16, .{_8086}),
    instr(.MOV, ops2(.moffs32, .reg_eax), Op1(0xA3), .TD, .Op32, .{_386}),
    instr(.MOV, ops2(.moffs64, .reg_rax), Op1(0xA3), .TD, .REX_W, .{x86_64}),
    //
    instr(.MOV, ops2(.reg8, .imm8), Op1(0xB0), .OI, .ZO, .{_8086}),
    instr(.MOV, ops2(.reg16, .imm16), Op1(0xB8), .OI, .Op16, .{_8086}),
    instr(.MOV, ops2(.reg32, .imm32), Op1(0xB8), .OI, .Op32, .{_386}),
    instr(.MOV, ops2(.reg64, .imm32), Op1(0xB8), .OI, .ZO, .{ x86_64, NoSign, No32 }),
    instr(.MOV, ops2(.reg64, .imm64), Op1(0xB8), .OI, .REX_W, .{x86_64}),
    //
    instr(.MOV, ops2(.rm8, .imm8), Op1r(0xC6, 0), .MI, .ZO, .{ _8086, Xrelease }),
    instr(.MOV, ops2(.rm16, .imm16), Op1r(0xC7, 0), .MI, .Op16, .{ _8086, Xrelease }),
    instr(.MOV, ops2(.rm32, .imm32), Op1r(0xC7, 0), .MI, .Op32, .{ _386, Xrelease }),
    instr(.MOV, ops2(.rm64, .imm32), Op1r(0xC7, 0), .MI, .REX_W, .{ x86_64, Xrelease }),
    // 386 MOV to/from Control Registers
    instr(.MOV, ops2(.reg32, .reg_cr), Op2(0x0F, 0x20), .MR, .ZO, .{ _386, No64 }),
    instr(.MOV, ops2(.reg64, .reg_cr), Op2(0x0F, 0x20), .MR, .ZO, .{ x86_64, No32 }),
    //
    instr(.MOV, ops2(.reg_cr, .reg32), Op2(0x0F, 0x22), .RM, .ZO, .{ _386, No64 }),
    instr(.MOV, ops2(.reg_cr, .reg64), Op2(0x0F, 0x22), .RM, .ZO, .{ x86_64, No32 }),
    // 386 MOV to/from Debug Registers
    instr(.MOV, ops2(.reg32, .reg_dr), Op2(0x0F, 0x21), .MR, .ZO, .{ _386, No64 }),
    instr(.MOV, ops2(.reg64, .reg_dr), Op2(0x0F, 0x21), .MR, .ZO, .{ x86_64, No32 }),
    //
    instr(.MOV, ops2(.reg_dr, .reg32), Op2(0x0F, 0x23), .RM, .ZO, .{ _386, No64 }),
    instr(.MOV, ops2(.reg_dr, .reg64), Op2(0x0F, 0x23), .RM, .ZO, .{ x86_64, No32 }),
    // MOVS / MOVSB / MOVSW / MOVSD / MOVSQ
    instr(.MOVS, ops2(.rm_mem8, .rm_mem8), Op1(0xA4), .MSpec, .ZO, .{ _8086, Rep }),
    instr(.MOVS, ops2(.rm_mem16, .rm_mem16), Op1(0xA5), .MSpec, .Op16, .{ _8086, Rep }),
    instr(.MOVS, ops2(.rm_mem32, .rm_mem32), Op1(0xA5), .MSpec, .Op32, .{ _386, Rep }),
    instr(.MOVS, ops2(.rm_mem64, .rm_mem64), Op1(0xA5), .MSpec, .REX_W, .{ x86_64, Rep }),
    //
    instr(.MOVSB, ops0(), Op1(0xA4), .ZO, .ZO, .{ _8086, Rep }),
    instr(.MOVSW, ops0(), Op1(0xA5), .ZO, .Op16, .{ _8086, Rep }),
    // instr(.MOVSD,   ops0(),                     Op1(0xA5),              .ZO, .Op32,    .{_386, Rep} ), // overloaded
    instr(.MOVSQ, ops0(), Op1(0xA5), .ZO, .REX_W, .{ x86_64, No32, Rep }),
    // MUL
    instr(.MUL, ops1(.rm8), Op1r(0xF6, 4), .M, .ZO, .{_8086}),
    instr(.MUL, ops1(.rm16), Op1r(0xF7, 4), .M, .Op16, .{_8086}),
    instr(.MUL, ops1(.rm32), Op1r(0xF7, 4), .M, .Op32, .{_386}),
    instr(.MUL, ops1(.rm64), Op1r(0xF7, 4), .M, .REX_W, .{x86_64}),
    // NEG
    instr(.NEG, ops1(.rm8), Op1r(0xF6, 3), .M, .ZO, .{ _8086, Lock, Hle }),
    instr(.NEG, ops1(.rm16), Op1r(0xF7, 3), .M, .Op16, .{ _8086, Lock, Hle }),
    instr(.NEG, ops1(.rm32), Op1r(0xF7, 3), .M, .Op32, .{ _386, Lock, Hle }),
    instr(.NEG, ops1(.rm64), Op1r(0xF7, 3), .M, .REX_W, .{ x86_64, Lock, Hle }),
    // NOP
    instr(.NOP, ops0(), Op1(0x90), .ZO, .ZO, .{_8086}),
    instr(.NOP, ops1(.rm16), Op2r(0x0F, 0x1F, 0), .M, .Op16, .{P6}),
    instr(.NOP, ops1(.rm32), Op2r(0x0F, 0x1F, 0), .M, .Op32, .{P6}),
    instr(.NOP, ops1(.rm64), Op2r(0x0F, 0x1F, 0), .M, .REX_W, .{x86_64}),
    // NOT
    instr(.NOT, ops1(.rm8), Op1r(0xF6, 2), .M, .ZO, .{ _8086, Lock, Hle }),
    instr(.NOT, ops1(.rm16), Op1r(0xF7, 2), .M, .Op16, .{ _8086, Lock, Hle }),
    instr(.NOT, ops1(.rm32), Op1r(0xF7, 2), .M, .Op32, .{ _386, Lock, Hle }),
    instr(.NOT, ops1(.rm64), Op1r(0xF7, 2), .M, .REX_W, .{ x86_64, Lock, Hle }),
    // OR
    instr(.OR, ops2(.reg_al, .imm8), Op1(0x0C), .I2, .ZO, .{_8086}),
    instr(.OR, ops2(.rm8, .imm8), Op1r(0x80, 1), .MI, .ZO, .{ _8086, Lock, Hle }),
    instr(.OR, ops2(.rm16, .imm8), Op1r(0x83, 1), .MI, .Op16, .{ _8086, Sign, Lock, Hle }),
    instr(.OR, ops2(.rm32, .imm8), Op1r(0x83, 1), .MI, .Op32, .{ _386, Sign, Lock, Hle }),
    instr(.OR, ops2(.rm64, .imm8), Op1r(0x83, 1), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.OR, ops2(.reg_ax, .imm16), Op1(0x0D), .I2, .Op16, .{_8086}),
    instr(.OR, ops2(.reg_eax, .imm32), Op1(0x0D), .I2, .Op32, .{_386}),
    instr(.OR, ops2(.reg_rax, .imm32), Op1(0x0D), .I2, .REX_W, .{ x86_64, Sign }),
    //
    instr(.OR, ops2(.rm16, .imm16), Op1r(0x81, 1), .MI, .Op16, .{ _8086, Lock, Hle }),
    instr(.OR, ops2(.rm32, .imm32), Op1r(0x81, 1), .MI, .Op32, .{ _386, Lock, Hle }),
    instr(.OR, ops2(.rm64, .imm32), Op1r(0x81, 1), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.OR, ops2(.rm8, .reg8), Op1(0x08), .MR, .ZO, .{ _8086, Lock, Hle }),
    instr(.OR, ops2(.rm16, .reg16), Op1(0x09), .MR, .Op16, .{ _8086, Lock, Hle }),
    instr(.OR, ops2(.rm32, .reg32), Op1(0x09), .MR, .Op32, .{ _386, Lock, Hle }),
    instr(.OR, ops2(.rm64, .reg64), Op1(0x09), .MR, .REX_W, .{ x86_64, Lock, Hle }),
    //
    instr(.OR, ops2(.reg8, .rm8), Op1(0x0A), .RM, .ZO, .{_8086}),
    instr(.OR, ops2(.reg16, .rm16), Op1(0x0B), .RM, .Op16, .{_8086}),
    instr(.OR, ops2(.reg32, .rm32), Op1(0x0B), .RM, .Op32, .{_386}),
    instr(.OR, ops2(.reg64, .rm64), Op1(0x0B), .RM, .REX_W, .{x86_64}),
    // OUT
    instr(.OUT, ops2(.imm8, .reg_al), Op1(0xE6), .I, .ZO, .{_8086}),
    instr(.OUT, ops2(.imm8, .reg_ax), Op1(0xE7), .I, .Op16, .{_8086}),
    instr(.OUT, ops2(.imm8, .reg_eax), Op1(0xE7), .I, .Op32, .{_386}),
    instr(.OUT, ops2(.reg_dx, .reg_al), Op1(0xEE), .ZO, .ZO, .{_8086}),
    instr(.OUT, ops2(.reg_dx, .reg_ax), Op1(0xEF), .ZO, .Op16, .{_8086}),
    instr(.OUT, ops2(.reg_dx, .reg_eax), Op1(0xEF), .ZO, .Op32, .{_386}),
    // OUTS / OUTSB / OUTSW / OUTSD
    instr(.OUTS, ops2(.reg_dx, .rm_mem8), Op1(0x6E), .MSpec, .ZO, .{ _186, Rep }),
    instr(.OUTS, ops2(.reg_dx, .rm_mem16), Op1(0x6F), .MSpec, .Op16, .{ _186, Rep }),
    instr(.OUTS, ops2(.reg_dx, .rm_mem32), Op1(0x6F), .MSpec, .Op32, .{ x86_64, Rep }),
    //
    instr(.OUTSB, ops0(), Op1(0x6E), .ZO, .ZO, .{ _186, Rep }),
    instr(.OUTSW, ops0(), Op1(0x6F), .ZO, .Op16, .{ _186, Rep }),
    instr(.OUTSD, ops0(), Op1(0x6F), .ZO, .Op32, .{ _386, Rep }),
    // POP
    instr(.POP, ops1(.reg16), Op1(0x58), .O, .Op16, .{_8086}),
    instr(.POP, ops1(.reg32), Op1(0x58), .O, .Op32, .{ _386, No64 }),
    instr(.POP, ops1(.reg64), Op1(0x58), .O, .ZO, .{ x86_64, No32 }),
    //
    instr(.POP, ops1(.rm16), Op1r(0x8F, 0), .M, .Op16, .{_8086}),
    instr(.POP, ops1(.rm32), Op1r(0x8F, 0), .M, .Op32, .{ _386, No64 }),
    instr(.POP, ops1(.rm64), Op1r(0x8F, 0), .M, .ZO, .{ x86_64, No32 }),
    //
    instr(.POP, ops1(.reg_cs), Op1(0x0F), .ZO, .ZO, .{ _8086_Legacy, No64 }),
    instr(.POP, ops1(.reg_ds), Op1(0x1F), .ZO, .ZO, .{ _8086, No64 }),
    instr(.POP, ops1(.reg_es), Op1(0x07), .ZO, .ZO, .{ _8086, No64 }),
    instr(.POP, ops1(.reg_ss), Op1(0x17), .ZO, .ZO, .{ _8086, No64 }),
    instr(.POP, ops1(.reg_fs), Op2(0x0F, 0xA1), .ZO, .ZO, .{_386}),
    instr(.POP, ops1(.reg_gs), Op2(0x0F, 0xA9), .ZO, .ZO, .{_386}),
    //
    instr(.POPW, ops1(.reg_ds), Op1(0x1F), .ZO, .Op16, .{ _8086, No64 }),
    instr(.POPW, ops1(.reg_es), Op1(0x07), .ZO, .Op16, .{ _8086, No64 }),
    instr(.POPW, ops1(.reg_ss), Op1(0x17), .ZO, .Op16, .{ _8086, No64 }),
    instr(.POPW, ops1(.reg_fs), Op2(0x0F, 0xA1), .ZO, .Op16, .{_386}),
    instr(.POPW, ops1(.reg_gs), Op2(0x0F, 0xA9), .ZO, .Op16, .{_386}),
    //
    instr(.POPD, ops1(.reg_ds), Op1(0x1F), .ZO, .Op32, .{ _8086, No64 }),
    instr(.POPD, ops1(.reg_es), Op1(0x07), .ZO, .Op32, .{ _8086, No64 }),
    instr(.POPD, ops1(.reg_ss), Op1(0x17), .ZO, .Op32, .{ _8086, No64 }),
    instr(.POPD, ops1(.reg_fs), Op2(0x0F, 0xA1), .ZO, .Op32, .{ _386, No64 }),
    instr(.POPD, ops1(.reg_gs), Op2(0x0F, 0xA9), .ZO, .Op32, .{ _386, No64 }),
    //
    instr(.POPQ, ops1(.reg_fs), Op2(0x0F, 0xA1), .ZO, .ZO, .{ _386, No32 }),
    instr(.POPQ, ops1(.reg_gs), Op2(0x0F, 0xA9), .ZO, .ZO, .{ _386, No32 }),
    // POPA
    instr(.POPA, ops0(), Op1(0x60), .ZO, .ZO, .{ _186, No64 }),
    instr(.POPAW, ops0(), Op1(0x60), .ZO, .Op16, .{ _186, No64 }),
    instr(.POPAD, ops0(), Op1(0x60), .ZO, .Op32, .{ _386, No64 }),
    // POPF / POPFD / POPFQ
    instr(.POPF, ops0(), Op1(0x9D), .ZO, .ZO, .{_8086}),
    instr(.POPFW, ops0(), Op1(0x9D), .ZO, .Op16, .{_8086}),
    instr(.POPFD, ops0(), Op1(0x9D), .ZO, .Op32, .{ _386, No64 }),
    instr(.POPFQ, ops0(), Op1(0x9D), .ZO, .ZO, .{ x86_64, No32 }),
    // PUSH
    instr(.PUSH, ops1(.imm8), Op1(0x6A), .I, .ZO, .{_186}),
    instr(.PUSH, ops1(.imm16), Op1(0x68), .I, .Op16, .{_186}),
    instr(.PUSH, ops1(.imm32), Op1(0x68), .I, .Op32, .{_386}),
    //
    instr(.PUSH, ops1(.reg16), Op1(0x50), .O, .Op16, .{_8086}),
    instr(.PUSH, ops1(.reg32), Op1(0x50), .O, .Op32, .{ _386, No64 }),
    instr(.PUSH, ops1(.reg64), Op1(0x50), .O, .ZO, .{ x86_64, No32 }),
    //
    instr(.PUSH, ops1(.rm16), Op1r(0xFF, 6), .M, .Op16, .{_8086}),
    instr(.PUSH, ops1(.rm32), Op1r(0xFF, 6), .M, .Op32, .{ _386, No64 }),
    instr(.PUSH, ops1(.rm64), Op1r(0xFF, 6), .M, .ZO, .{ x86_64, No32 }),
    //
    instr(.PUSH, ops1(.reg_cs), Op1(0x0E), .ZO, .ZO, .{ _8086, No64 }),
    instr(.PUSH, ops1(.reg_ds), Op1(0x1E), .ZO, .ZO, .{ _8086, No64 }),
    instr(.PUSH, ops1(.reg_es), Op1(0x06), .ZO, .ZO, .{ _8086, No64 }),
    instr(.PUSH, ops1(.reg_ss), Op1(0x16), .ZO, .ZO, .{ _8086, No64 }),
    instr(.PUSH, ops1(.reg_fs), Op2(0x0F, 0xA0), .ZO, .ZO, .{_386}),
    instr(.PUSH, ops1(.reg_gs), Op2(0x0F, 0xA8), .ZO, .ZO, .{_386}),
    //
    instr(.PUSHW, ops1(.reg_cs), Op1(0x0E), .ZO, .Op16, .{ _8086, No64 }),
    instr(.PUSHW, ops1(.reg_ds), Op1(0x1E), .ZO, .Op16, .{ _8086, No64 }),
    instr(.PUSHW, ops1(.reg_es), Op1(0x06), .ZO, .Op16, .{ _8086, No64 }),
    instr(.PUSHW, ops1(.reg_ss), Op1(0x16), .ZO, .Op16, .{ _8086, No64 }),
    instr(.PUSHW, ops1(.reg_fs), Op2(0x0F, 0xA0), .ZO, .Op16, .{_386}),
    instr(.PUSHW, ops1(.reg_gs), Op2(0x0F, 0xA8), .ZO, .Op16, .{_386}),
    //
    instr(.PUSHD, ops1(.reg_cs), Op1(0x0E), .ZO, .Op32, .{ _8086, No64 }),
    instr(.PUSHD, ops1(.reg_ds), Op1(0x1E), .ZO, .Op32, .{ _8086, No64 }),
    instr(.PUSHD, ops1(.reg_es), Op1(0x06), .ZO, .Op32, .{ _8086, No64 }),
    instr(.PUSHD, ops1(.reg_ss), Op1(0x16), .ZO, .Op32, .{ _8086, No64 }),
    instr(.PUSHD, ops1(.reg_fs), Op2(0x0F, 0xA0), .ZO, .Op32, .{ _386, No64 }),
    instr(.PUSHD, ops1(.reg_gs), Op2(0x0F, 0xA8), .ZO, .Op32, .{ _386, No64 }),
    //
    instr(.PUSHQ, ops1(.reg_fs), Op2(0x0F, 0xA0), .ZO, .ZO, .{ _386, No32 }),
    instr(.PUSHQ, ops1(.reg_gs), Op2(0x0F, 0xA8), .ZO, .ZO, .{ _386, No32 }),
    // PUSHA
    instr(.PUSHA, ops0(), Op1(0x60), .ZO, .ZO, .{ _186, No64 }),
    instr(.PUSHAW, ops0(), Op1(0x60), .ZO, .Op16, .{ _186, No64 }),
    instr(.PUSHAD, ops0(), Op1(0x60), .ZO, .Op32, .{ _386, No64 }),
    // PUSHF / PUSHFW / PUSHFD / PUSHFQ
    instr(.PUSHF, ops0(), Op1(0x9C), .ZO, .ZO, .{_8086}),
    instr(.PUSHFW, ops0(), Op1(0x9C), .ZO, .Op16, .{_8086}),
    instr(.PUSHFD, ops0(), Op1(0x9C), .ZO, .Op32, .{ _386, No64 }),
    instr(.PUSHFQ, ops0(), Op1(0x9C), .ZO, .ZO, .{ x86_64, No32 }),
    //  RCL / RCR / ROL / ROR
    instr(.RCL, ops2(.rm8, .imm_1), Op1r(0xD0, 2), .M, .ZO, .{_8086}),
    instr(.RCL, ops2(.rm8, .reg_cl), Op1r(0xD2, 2), .M, .ZO, .{_8086}),
    instr(.RCL, ops2(.rm8, .imm8), Op1r(0xC0, 2), .MI, .ZO, .{_186}),
    instr(.RCL, ops2(.rm16, .imm_1), Op1r(0xD1, 2), .M, .Op16, .{_8086}),
    instr(.RCL, ops2(.rm32, .imm_1), Op1r(0xD1, 2), .M, .Op32, .{_386}),
    instr(.RCL, ops2(.rm64, .imm_1), Op1r(0xD1, 2), .M, .REX_W, .{x86_64}),
    instr(.RCL, ops2(.rm16, .imm8), Op1r(0xC1, 2), .MI, .Op16, .{_186}),
    instr(.RCL, ops2(.rm32, .imm8), Op1r(0xC1, 2), .MI, .Op32, .{_386}),
    instr(.RCL, ops2(.rm64, .imm8), Op1r(0xC1, 2), .MI, .REX_W, .{x86_64}),
    instr(.RCL, ops2(.rm16, .reg_cl), Op1r(0xD3, 2), .M, .Op16, .{_8086}),
    instr(.RCL, ops2(.rm32, .reg_cl), Op1r(0xD3, 2), .M, .Op32, .{_386}),
    instr(.RCL, ops2(.rm64, .reg_cl), Op1r(0xD3, 2), .M, .REX_W, .{x86_64}),
    //
    instr(.RCR, ops2(.rm8, .imm_1), Op1r(0xD0, 3), .M, .ZO, .{_8086}),
    instr(.RCR, ops2(.rm8, .reg_cl), Op1r(0xD2, 3), .M, .ZO, .{_8086}),
    instr(.RCR, ops2(.rm8, .imm8), Op1r(0xC0, 3), .MI, .ZO, .{_186}),
    instr(.RCR, ops2(.rm16, .imm_1), Op1r(0xD1, 3), .M, .Op16, .{_8086}),
    instr(.RCR, ops2(.rm32, .imm_1), Op1r(0xD1, 3), .M, .Op32, .{_386}),
    instr(.RCR, ops2(.rm64, .imm_1), Op1r(0xD1, 3), .M, .REX_W, .{x86_64}),
    instr(.RCR, ops2(.rm16, .imm8), Op1r(0xC1, 3), .MI, .Op16, .{_186}),
    instr(.RCR, ops2(.rm32, .imm8), Op1r(0xC1, 3), .MI, .Op32, .{_386}),
    instr(.RCR, ops2(.rm64, .imm8), Op1r(0xC1, 3), .MI, .REX_W, .{x86_64}),
    instr(.RCR, ops2(.rm16, .reg_cl), Op1r(0xD3, 3), .M, .Op16, .{_8086}),
    instr(.RCR, ops2(.rm32, .reg_cl), Op1r(0xD3, 3), .M, .Op32, .{_386}),
    instr(.RCR, ops2(.rm64, .reg_cl), Op1r(0xD3, 3), .M, .REX_W, .{x86_64}),
    //
    instr(.ROL, ops2(.rm8, .imm_1), Op1r(0xD0, 0), .M, .ZO, .{_8086}),
    instr(.ROL, ops2(.rm8, .reg_cl), Op1r(0xD2, 0), .M, .ZO, .{_8086}),
    instr(.ROL, ops2(.rm8, .imm8), Op1r(0xC0, 0), .MI, .ZO, .{_186}),
    instr(.ROL, ops2(.rm16, .imm_1), Op1r(0xD1, 0), .M, .Op16, .{_8086}),
    instr(.ROL, ops2(.rm32, .imm_1), Op1r(0xD1, 0), .M, .Op32, .{_386}),
    instr(.ROL, ops2(.rm64, .imm_1), Op1r(0xD1, 0), .M, .REX_W, .{x86_64}),
    instr(.ROL, ops2(.rm16, .imm8), Op1r(0xC1, 0), .MI, .Op16, .{_186}),
    instr(.ROL, ops2(.rm32, .imm8), Op1r(0xC1, 0), .MI, .Op32, .{_386}),
    instr(.ROL, ops2(.rm64, .imm8), Op1r(0xC1, 0), .MI, .REX_W, .{x86_64}),
    instr(.ROL, ops2(.rm16, .reg_cl), Op1r(0xD3, 0), .M, .Op16, .{_8086}),
    instr(.ROL, ops2(.rm32, .reg_cl), Op1r(0xD3, 0), .M, .Op32, .{_386}),
    instr(.ROL, ops2(.rm64, .reg_cl), Op1r(0xD3, 0), .M, .REX_W, .{x86_64}),
    //
    instr(.ROR, ops2(.rm8, .imm_1), Op1r(0xD0, 1), .M, .ZO, .{_8086}),
    instr(.ROR, ops2(.rm8, .reg_cl), Op1r(0xD2, 1), .M, .ZO, .{_8086}),
    instr(.ROR, ops2(.rm8, .imm8), Op1r(0xC0, 1), .MI, .ZO, .{_186}),
    instr(.ROR, ops2(.rm16, .imm_1), Op1r(0xD1, 1), .M, .Op16, .{_8086}),
    instr(.ROR, ops2(.rm32, .imm_1), Op1r(0xD1, 1), .M, .Op32, .{_386}),
    instr(.ROR, ops2(.rm64, .imm_1), Op1r(0xD1, 1), .M, .REX_W, .{x86_64}),
    instr(.ROR, ops2(.rm16, .imm8), Op1r(0xC1, 1), .MI, .Op16, .{_186}),
    instr(.ROR, ops2(.rm32, .imm8), Op1r(0xC1, 1), .MI, .Op32, .{_386}),
    instr(.ROR, ops2(.rm64, .imm8), Op1r(0xC1, 1), .MI, .REX_W, .{x86_64}),
    instr(.ROR, ops2(.rm16, .reg_cl), Op1r(0xD3, 1), .M, .Op16, .{_8086}),
    instr(.ROR, ops2(.rm32, .reg_cl), Op1r(0xD3, 1), .M, .Op32, .{_386}),
    instr(.ROR, ops2(.rm64, .reg_cl), Op1r(0xD3, 1), .M, .REX_W, .{x86_64}),
    // REP / REPE / REPZ / REPNE / REPNZ
    instr(.REP, ops0(), Op1(0xF3), .ZO, .ZO, .{_8086}),
    instr(.REPE, ops0(), Op1(0xF3), .ZO, .ZO, .{_8086}),
    instr(.REPZ, ops0(), Op1(0xF3), .ZO, .ZO, .{_8086}),
    instr(.REPNE, ops0(), Op1(0xF2), .ZO, .ZO, .{_8086}),
    instr(.REPNZ, ops0(), Op1(0xF2), .ZO, .ZO, .{_8086}),
    //  RET
    instr(.RET, ops0(), Op1(0xC3), .ZO, .ZO, .{ _8086, Bnd }),
    instr(.RET, ops1(.imm16), Op1(0xC2), .I, .ZO, .{ _8086, Bnd }),
    instr(.RETW, ops0(), Op1(0xC3), .ZO, .Op16, .{ _8086, Bnd }),
    instr(.RETW, ops1(.imm16), Op1(0xC2), .I, .Op16, .{ _8086, Bnd }),
    instr(.RETD, ops0(), Op1(0xC3), .ZO, .Op32, .{ _386, Bnd, No64 }),
    instr(.RETD, ops1(.imm16), Op1(0xC2), .I, .Op32, .{ _386, Bnd, No64 }),
    instr(.RETQ, ops0(), Op1(0xC3), .ZO, .ZO, .{ x86_64, Bnd, No32 }),
    instr(.RETQ, ops1(.imm16), Op1(0xC2), .I, .ZO, .{ x86_64, Bnd, No32 }),
    //  RETF
    instr(.RETF, ops0(), Op1(0xCB), .ZO, .ZO, .{_8086}),
    instr(.RETF, ops1(.imm16), Op1(0xCA), .I, .ZO, .{_8086}),
    instr(.RETFW, ops0(), Op1(0xCB), .ZO, .Op16, .{_8086}),
    instr(.RETFW, ops1(.imm16), Op1(0xCA), .I, .Op16, .{_8086}),
    instr(.RETFD, ops0(), Op1(0xCB), .ZO, .Op32, .{ _386, No64 }),
    instr(.RETFD, ops1(.imm16), Op1(0xCA), .I, .Op32, .{ _386, No64 }),
    instr(.RETFQ, ops0(), Op1(0xCB), .ZO, .ZO, .{ x86_64, No32 }),
    instr(.RETFQ, ops1(.imm16), Op1(0xCA), .I, .ZO, .{ x86_64, No32 }),
    //  RETN
    instr(.RETN, ops0(), Op1(0xC3), .ZO, .ZO, .{ _8086, Bnd }),
    instr(.RETN, ops1(.imm16), Op1(0xC2), .I, .ZO, .{ _8086, Bnd }),
    instr(.RETNW, ops0(), Op1(0xC3), .ZO, .Op16, .{ _8086, Bnd }),
    instr(.RETNW, ops1(.imm16), Op1(0xC2), .I, .Op16, .{ _8086, Bnd }),
    instr(.RETND, ops0(), Op1(0xC3), .ZO, .Op32, .{ _386, Bnd, No64 }),
    instr(.RETND, ops1(.imm16), Op1(0xC2), .I, .Op32, .{ _386, Bnd, No64 }),
    instr(.RETNQ, ops0(), Op1(0xC3), .ZO, .ZO, .{ x86_64, Bnd, No32 }),
    instr(.RETNQ, ops1(.imm16), Op1(0xC2), .I, .ZO, .{ x86_64, Bnd, No32 }),
    //  SAL / SAR / SHL / SHR
    instr(.SAL, ops2(.rm8, .imm_1), Op1r(0xD0, 4), .M, .ZO, .{_8086}),
    instr(.SAL, ops2(.rm8, .reg_cl), Op1r(0xD2, 4), .M, .ZO, .{_8086}),
    instr(.SAL, ops2(.rm8, .imm8), Op1r(0xC0, 4), .MI, .ZO, .{_186}),
    instr(.SAL, ops2(.rm16, .imm_1), Op1r(0xD1, 4), .M, .Op16, .{_8086}),
    instr(.SAL, ops2(.rm32, .imm_1), Op1r(0xD1, 4), .M, .Op32, .{_386}),
    instr(.SAL, ops2(.rm64, .imm_1), Op1r(0xD1, 4), .M, .REX_W, .{x86_64}),
    instr(.SAL, ops2(.rm16, .imm8), Op1r(0xC1, 4), .MI, .Op16, .{_186}),
    instr(.SAL, ops2(.rm32, .imm8), Op1r(0xC1, 4), .MI, .Op32, .{_386}),
    instr(.SAL, ops2(.rm64, .imm8), Op1r(0xC1, 4), .MI, .REX_W, .{x86_64}),
    instr(.SAL, ops2(.rm16, .reg_cl), Op1r(0xD3, 4), .M, .Op16, .{_8086}),
    instr(.SAL, ops2(.rm32, .reg_cl), Op1r(0xD3, 4), .M, .Op32, .{_386}),
    instr(.SAL, ops2(.rm64, .reg_cl), Op1r(0xD3, 4), .M, .REX_W, .{x86_64}),
    //
    instr(.SAR, ops2(.rm8, .imm_1), Op1r(0xD0, 7), .M, .ZO, .{_8086}),
    instr(.SAR, ops2(.rm8, .reg_cl), Op1r(0xD2, 7), .M, .ZO, .{_8086}),
    instr(.SAR, ops2(.rm8, .imm8), Op1r(0xC0, 7), .MI, .ZO, .{_186}),
    instr(.SAR, ops2(.rm16, .imm_1), Op1r(0xD1, 7), .M, .Op16, .{_8086}),
    instr(.SAR, ops2(.rm32, .imm_1), Op1r(0xD1, 7), .M, .Op32, .{_386}),
    instr(.SAR, ops2(.rm64, .imm_1), Op1r(0xD1, 7), .M, .REX_W, .{x86_64}),
    instr(.SAR, ops2(.rm16, .imm8), Op1r(0xC1, 7), .MI, .Op16, .{_186}),
    instr(.SAR, ops2(.rm32, .imm8), Op1r(0xC1, 7), .MI, .Op32, .{_386}),
    instr(.SAR, ops2(.rm64, .imm8), Op1r(0xC1, 7), .MI, .REX_W, .{x86_64}),
    instr(.SAR, ops2(.rm16, .reg_cl), Op1r(0xD3, 7), .M, .Op16, .{_8086}),
    instr(.SAR, ops2(.rm32, .reg_cl), Op1r(0xD3, 7), .M, .Op32, .{_386}),
    instr(.SAR, ops2(.rm64, .reg_cl), Op1r(0xD3, 7), .M, .REX_W, .{x86_64}),
    //
    instr(.SHL, ops2(.rm8, .imm_1), Op1r(0xD0, 4), .M, .ZO, .{_8086}),
    instr(.SHL, ops2(.rm8, .reg_cl), Op1r(0xD2, 4), .M, .ZO, .{_8086}),
    instr(.SHL, ops2(.rm8, .imm8), Op1r(0xC0, 4), .MI, .ZO, .{_186}),
    instr(.SHL, ops2(.rm16, .imm_1), Op1r(0xD1, 4), .M, .Op16, .{_8086}),
    instr(.SHL, ops2(.rm32, .imm_1), Op1r(0xD1, 4), .M, .Op32, .{_386}),
    instr(.SHL, ops2(.rm64, .imm_1), Op1r(0xD1, 4), .M, .REX_W, .{x86_64}),
    instr(.SHL, ops2(.rm16, .imm8), Op1r(0xC1, 4), .MI, .Op16, .{_186}),
    instr(.SHL, ops2(.rm32, .imm8), Op1r(0xC1, 4), .MI, .Op32, .{_386}),
    instr(.SHL, ops2(.rm64, .imm8), Op1r(0xC1, 4), .MI, .REX_W, .{x86_64}),
    instr(.SHL, ops2(.rm16, .reg_cl), Op1r(0xD3, 4), .M, .Op16, .{_8086}),
    instr(.SHL, ops2(.rm32, .reg_cl), Op1r(0xD3, 4), .M, .Op32, .{_386}),
    instr(.SHL, ops2(.rm64, .reg_cl), Op1r(0xD3, 4), .M, .REX_W, .{x86_64}),
    //
    instr(.SHR, ops2(.rm8, .imm_1), Op1r(0xD0, 5), .M, .ZO, .{_8086}),
    instr(.SHR, ops2(.rm8, .reg_cl), Op1r(0xD2, 5), .M, .ZO, .{_8086}),
    instr(.SHR, ops2(.rm8, .imm8), Op1r(0xC0, 5), .MI, .ZO, .{_186}),
    instr(.SHR, ops2(.rm16, .imm_1), Op1r(0xD1, 5), .M, .Op16, .{_8086}),
    instr(.SHR, ops2(.rm32, .imm_1), Op1r(0xD1, 5), .M, .Op32, .{_386}),
    instr(.SHR, ops2(.rm64, .imm_1), Op1r(0xD1, 5), .M, .REX_W, .{x86_64}),
    instr(.SHR, ops2(.rm16, .imm8), Op1r(0xC1, 5), .MI, .Op16, .{_186}),
    instr(.SHR, ops2(.rm32, .imm8), Op1r(0xC1, 5), .MI, .Op32, .{_386}),
    instr(.SHR, ops2(.rm64, .imm8), Op1r(0xC1, 5), .MI, .REX_W, .{x86_64}),
    instr(.SHR, ops2(.rm16, .reg_cl), Op1r(0xD3, 5), .M, .Op16, .{_8086}),
    instr(.SHR, ops2(.rm32, .reg_cl), Op1r(0xD3, 5), .M, .Op32, .{_386}),
    instr(.SHR, ops2(.rm64, .reg_cl), Op1r(0xD3, 5), .M, .REX_W, .{x86_64}),
    // SBB
    instr(.SBB, ops2(.reg_al, .imm8), Op1(0x1C), .I2, .ZO, .{_8086}),
    instr(.SBB, ops2(.rm8, .imm8), Op1r(0x80, 3), .MI, .ZO, .{ _8086, Lock, Hle }),
    instr(.SBB, ops2(.rm16, .imm8), Op1r(0x83, 3), .MI, .Op16, .{ _8086, Sign, Lock, Hle }),
    instr(.SBB, ops2(.rm32, .imm8), Op1r(0x83, 3), .MI, .Op32, .{ _386, Sign, Lock, Hle }),
    instr(.SBB, ops2(.rm64, .imm8), Op1r(0x83, 3), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.SBB, ops2(.reg_ax, .imm16), Op1(0x1D), .I2, .Op16, .{_8086}),
    instr(.SBB, ops2(.reg_eax, .imm32), Op1(0x1D), .I2, .Op32, .{_386}),
    instr(.SBB, ops2(.reg_rax, .imm32), Op1(0x1D), .I2, .REX_W, .{ x86_64, Sign }),
    //
    instr(.SBB, ops2(.rm16, .imm16), Op1r(0x81, 3), .MI, .Op16, .{ _8086, Lock, Hle }),
    instr(.SBB, ops2(.rm32, .imm32), Op1r(0x81, 3), .MI, .Op32, .{ _386, Lock, Hle }),
    instr(.SBB, ops2(.rm64, .imm32), Op1r(0x81, 3), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.SBB, ops2(.rm8, .reg8), Op1(0x18), .MR, .ZO, .{ _8086, Lock, Hle }),
    instr(.SBB, ops2(.rm16, .reg16), Op1(0x19), .MR, .Op16, .{ _8086, Lock, Hle }),
    instr(.SBB, ops2(.rm32, .reg32), Op1(0x19), .MR, .Op32, .{ _386, Lock, Hle }),
    instr(.SBB, ops2(.rm64, .reg64), Op1(0x19), .MR, .REX_W, .{ x86_64, Lock, Hle }),
    //
    instr(.SBB, ops2(.reg8, .rm8), Op1(0x1A), .RM, .ZO, .{_8086}),
    instr(.SBB, ops2(.reg16, .rm16), Op1(0x1B), .RM, .Op16, .{_8086}),
    instr(.SBB, ops2(.reg32, .rm32), Op1(0x1B), .RM, .Op32, .{_386}),
    instr(.SBB, ops2(.reg64, .rm64), Op1(0x1B), .RM, .REX_W, .{x86_64}),
    // SCAS / SCASB / SCASW / SCASD / SCASQ
    instr(.SCAS, ops2(.rm_mem8, .reg_al), Op1(0xAE), .MSpec, .ZO, .{ _8086, Repe, Repne }),
    instr(.SCAS, ops2(.rm_mem16, .reg_ax), Op1(0xAF), .MSpec, .Op16, .{ _8086, Repe, Repne }),
    instr(.SCAS, ops2(.rm_mem32, .reg_eax), Op1(0xAF), .MSpec, .Op32, .{ _386, Repe, Repne }),
    instr(.SCAS, ops2(.rm_mem64, .reg_rax), Op1(0xAF), .MSpec, .REX_W, .{ x86_64, Repe, Repne }),
    //
    instr(.SCASB, ops0(), Op1(0xAE), .ZO, .ZO, .{ _8086, Repe, Repne }),
    instr(.SCASW, ops0(), Op1(0xAF), .ZO, .Op16, .{ _8086, Repe, Repne }),
    instr(.SCASD, ops0(), Op1(0xAF), .ZO, .Op32, .{ _386, Repe, Repne }),
    instr(.SCASQ, ops0(), Op1(0xAF), .ZO, .REX_W, .{ x86_64, No32, Repe, Repne }),
    // STC
    instr(.STC, ops0(), Op1(0xF9), .ZO, .ZO, .{_8086}),
    // STD
    instr(.STD, ops0(), Op1(0xFD), .ZO, .ZO, .{_8086}),
    // STI
    instr(.STI, ops0(), Op1(0xFB), .ZO, .ZO, .{_8086}),
    // STOS / STOSB / STOSW / STOSD / STOSQ
    instr(.STOS, ops2(.rm_mem8, .reg_al), Op1(0xAA), .MSpec, .ZO, .{ _8086, Rep }),
    instr(.STOS, ops2(.rm_mem16, .reg_ax), Op1(0xAB), .MSpec, .Op16, .{ _8086, Rep }),
    instr(.STOS, ops2(.rm_mem32, .reg_eax), Op1(0xAB), .MSpec, .Op32, .{ _386, Rep }),
    instr(.STOS, ops2(.rm_mem64, .reg_rax), Op1(0xAB), .MSpec, .REX_W, .{ x86_64, Rep }),
    //
    instr(.STOSB, ops0(), Op1(0xAA), .ZO, .ZO, .{ _8086, Rep }),
    instr(.STOSW, ops0(), Op1(0xAB), .ZO, .Op16, .{ _8086, Rep }),
    instr(.STOSD, ops0(), Op1(0xAB), .ZO, .Op32, .{ _386, Rep }),
    instr(.STOSQ, ops0(), Op1(0xAB), .ZO, .REX_W, .{ x86_64, Rep }),
    // SUB
    instr(.SUB, ops2(.reg_al, .imm8), Op1(0x2C), .I2, .ZO, .{_8086}),
    instr(.SUB, ops2(.rm8, .imm8), Op1r(0x80, 5), .MI, .ZO, .{ _8086, Lock, Hle }),
    instr(.SUB, ops2(.rm16, .imm8), Op1r(0x83, 5), .MI, .Op16, .{ _8086, Sign, Lock, Hle }),
    instr(.SUB, ops2(.rm32, .imm8), Op1r(0x83, 5), .MI, .Op32, .{ _386, Sign, Lock, Hle }),
    instr(.SUB, ops2(.rm64, .imm8), Op1r(0x83, 5), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.SUB, ops2(.reg_ax, .imm16), Op1(0x2D), .I2, .Op16, .{_8086}),
    instr(.SUB, ops2(.reg_eax, .imm32), Op1(0x2D), .I2, .Op32, .{_386}),
    instr(.SUB, ops2(.reg_rax, .imm32), Op1(0x2D), .I2, .REX_W, .{ x86_64, Sign }),
    //
    instr(.SUB, ops2(.rm16, .imm16), Op1r(0x81, 5), .MI, .Op16, .{ _8086, Lock, Hle }),
    instr(.SUB, ops2(.rm32, .imm32), Op1r(0x81, 5), .MI, .Op32, .{ _386, Lock, Hle }),
    instr(.SUB, ops2(.rm64, .imm32), Op1r(0x81, 5), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.SUB, ops2(.rm8, .reg8), Op1(0x28), .MR, .ZO, .{ _8086, Lock, Hle }),
    instr(.SUB, ops2(.rm16, .reg16), Op1(0x29), .MR, .Op16, .{ _8086, Lock, Hle }),
    instr(.SUB, ops2(.rm32, .reg32), Op1(0x29), .MR, .Op32, .{ _386, Lock, Hle }),
    instr(.SUB, ops2(.rm64, .reg64), Op1(0x29), .MR, .REX_W, .{ x86_64, Lock, Hle }),
    //
    instr(.SUB, ops2(.reg8, .rm8), Op1(0x2A), .RM, .ZO, .{_8086}),
    instr(.SUB, ops2(.reg16, .rm16), Op1(0x2B), .RM, .Op16, .{_8086}),
    instr(.SUB, ops2(.reg32, .rm32), Op1(0x2B), .RM, .Op32, .{_386}),
    instr(.SUB, ops2(.reg64, .rm64), Op1(0x2B), .RM, .REX_W, .{x86_64}),
    // TEST
    instr(.TEST, ops2(.reg_al, .imm8), Op1(0xA8), .I2, .ZO, .{_8086}),
    instr(.TEST, ops2(.reg_ax, .imm16), Op1(0xA9), .I2, .Op16, .{_8086}),
    instr(.TEST, ops2(.reg_eax, .imm32), Op1(0xA9), .I2, .Op32, .{_386}),
    instr(.TEST, ops2(.reg_rax, .imm32), Op1(0xA9), .I2, .REX_W, .{ x86_64, Sign }),
    //
    instr(.TEST, ops2(.rm8, .imm8), Op1r(0xF6, 0), .MI, .ZO, .{_8086}),
    instr(.TEST, ops2(.rm16, .imm16), Op1r(0xF7, 0), .MI, .Op16, .{_8086}),
    instr(.TEST, ops2(.rm32, .imm32), Op1r(0xF7, 0), .MI, .Op32, .{_386}),
    instr(.TEST, ops2(.rm64, .imm32), Op1r(0xF7, 0), .MI, .REX_W, .{x86_64}),
    //
    instr(.TEST, ops2(.rm8, .reg8), Op1(0x84), .MR, .ZO, .{_8086}),
    instr(.TEST, ops2(.rm16, .reg16), Op1(0x85), .MR, .Op16, .{_8086}),
    instr(.TEST, ops2(.rm32, .reg32), Op1(0x85), .MR, .Op32, .{_386}),
    instr(.TEST, ops2(.rm64, .reg64), Op1(0x85), .MR, .REX_W, .{x86_64}),
    // WAIT
    instr(.WAIT, ops0(), Op1(0x9B), .ZO, .ZO, .{_8086}),
    // XCHG
    instr(.XCHG, ops2(.reg_ax, .reg16), Op1(0x90), .O2, .Op16, .{_8086}),
    instr(.XCHG, ops2(.reg16, .reg_ax), Op1(0x90), .O, .Op16, .{_8086}),
    instr(.XCHG, ops2(.reg_eax, .reg32), Op1(0x90), .O2, .Op32, .{ _386, edge.XCHG_EAX }),
    instr(.XCHG, ops2(.reg32, .reg_eax), Op1(0x90), .O, .Op32, .{ _386, edge.XCHG_EAX }),
    instr(.XCHG, ops2(.reg_rax, .reg64), Op1(0x90), .O2, .REX_W, .{x86_64}),
    instr(.XCHG, ops2(.reg64, .reg_rax), Op1(0x90), .O, .REX_W, .{x86_64}),
    //
    instr(.XCHG, ops2(.rm8, .reg8), Op1(0x86), .MR, .ZO, .{ _8086, Lock, HleNoLock }),
    instr(.XCHG, ops2(.reg8, .rm8), Op1(0x86), .RM, .ZO, .{ _8086, Lock, HleNoLock }),
    instr(.XCHG, ops2(.rm16, .reg16), Op1(0x87), .MR, .Op16, .{ _8086, Lock, HleNoLock }),
    instr(.XCHG, ops2(.reg16, .rm16), Op1(0x87), .RM, .Op16, .{ _8086, Lock, HleNoLock }),
    instr(.XCHG, ops2(.rm32, .reg32), Op1(0x87), .MR, .Op32, .{ _386, Lock, HleNoLock }),
    instr(.XCHG, ops2(.reg32, .rm32), Op1(0x87), .RM, .Op32, .{ _386, Lock, HleNoLock }),
    instr(.XCHG, ops2(.rm64, .reg64), Op1(0x87), .MR, .REX_W, .{ x86_64, Lock, HleNoLock }),
    instr(.XCHG, ops2(.reg64, .rm64), Op1(0x87), .RM, .REX_W, .{ x86_64, Lock, HleNoLock }),
    // XLAT / XLATB
    instr(.XLAT, ops2(.reg_al, .rm_mem8), Op1(0xD7), .MSpec, .ZO, .{_8086}),
    //
    instr(.XLATB, ops0(), Op1(0xD7), .ZO, .ZO, .{_8086}),
    // XOR
    instr(.XOR, ops2(.reg_al, .imm8), Op1(0x34), .I2, .ZO, .{_8086}),
    instr(.XOR, ops2(.rm8, .imm8), Op1r(0x80, 6), .MI, .ZO, .{ _8086, Lock, Hle }),
    instr(.XOR, ops2(.rm16, .imm8), Op1r(0x83, 6), .MI, .Op16, .{ _8086, Sign, Lock, Hle }),
    instr(.XOR, ops2(.rm32, .imm8), Op1r(0x83, 6), .MI, .Op32, .{ _386, Sign, Lock, Hle }),
    instr(.XOR, ops2(.rm64, .imm8), Op1r(0x83, 6), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.XOR, ops2(.reg_ax, .imm16), Op1(0x35), .I2, .Op16, .{_8086}),
    instr(.XOR, ops2(.reg_eax, .imm32), Op1(0x35), .I2, .Op32, .{_386}),
    instr(.XOR, ops2(.reg_rax, .imm32), Op1(0x35), .I2, .REX_W, .{ x86_64, Sign }),
    //
    instr(.XOR, ops2(.rm16, .imm16), Op1r(0x81, 6), .MI, .Op16, .{ _8086, Lock, Hle }),
    instr(.XOR, ops2(.rm32, .imm32), Op1r(0x81, 6), .MI, .Op32, .{ _386, Lock, Hle }),
    instr(.XOR, ops2(.rm64, .imm32), Op1r(0x81, 6), .MI, .REX_W, .{ x86_64, Sign, Lock, Hle }),
    //
    instr(.XOR, ops2(.rm8, .reg8), Op1(0x30), .MR, .ZO, .{ _8086, Lock, Hle }),
    instr(.XOR, ops2(.rm16, .reg16), Op1(0x31), .MR, .Op16, .{ _8086, Lock, Hle }),
    instr(.XOR, ops2(.rm32, .reg32), Op1(0x31), .MR, .Op32, .{ _386, Lock, Hle }),
    instr(.XOR, ops2(.rm64, .reg64), Op1(0x31), .MR, .REX_W, .{ x86_64, Lock, Hle }),
    //
    instr(.XOR, ops2(.reg8, .rm8), Op1(0x32), .RM, .ZO, .{_8086}),
    instr(.XOR, ops2(.reg16, .rm16), Op1(0x33), .RM, .Op16, .{_8086}),
    instr(.XOR, ops2(.reg32, .rm32), Op1(0x33), .RM, .Op32, .{_386}),
    instr(.XOR, ops2(.reg64, .rm64), Op1(0x33), .RM, .REX_W, .{x86_64}),

    //
    // x87 -- 8087 / 80287 / 80387
    //
    // F2XM1
    instr(.F2XM1, ops0(), Op2(0xD9, 0xF0), .ZO, .ZO, .{_087}),
    // FABS
    instr(.FABS, ops0(), Op2(0xD9, 0xE1), .ZO, .ZO, .{_087}),
    // FADD / FADDP / FIADD
    instr(.FADD, ops1(.rm_mem32), Op1r(0xD8, 0), .M, .ZO, .{_087}),
    instr(.FADD, ops1(.rm_mem64), Op1r(0xDC, 0), .M, .ZO, .{_087}),
    instr(.FADD, ops1(.reg_st), Op2(0xD8, 0xC0), .O, .ZO, .{_087}),
    instr(.FADD, ops2(.reg_st, .reg_st0), Op2(0xDC, 0xC0), .O, .ZO, .{_087}),
    instr(.FADD, ops2(.reg_st0, .reg_st), Op2(0xD8, 0xC0), .O2, .ZO, .{_087}),
    //
    instr(.FADDP, ops2(.reg_st, .reg_st0), Op2(0xDE, 0xC0), .O, .ZO, .{_087}),
    instr(.FADDP, ops0(), Op2(0xDE, 0xC1), .ZO, .ZO, .{_087}),
    //
    instr(.FIADD, ops1(.rm_mem16), Op1r(0xDE, 0), .M, .ZO, .{_087}),
    instr(.FIADD, ops1(.rm_mem32), Op1r(0xDA, 0), .M, .ZO, .{_087}),
    // FBLD
    instr(.FBLD, ops1(.rm_mem80), Op1r(0xDF, 4), .M, .ZO, .{_087}),
    // FBSTP
    instr(.FBSTP, ops1(.rm_mem80), Op1r(0xDF, 6), .M, .ZO, .{_087}),
    // FCHS
    instr(.FCHS, ops0(), Op2(0xD9, 0xE0), .ZO, .ZO, .{_087}),
    instr(.FCHS, ops1(.reg_st0), Op2(0xD9, 0xE0), .ZO, .ZO, .{_087}),
    // FCLEX / FNCLEX
    instr(.FCLEX, ops0(), compOp2(.FWAIT, 0xDB, 0xE2), .ZO, .ZO, .{_087}),
    instr(.FNCLEX, ops0(), Op2(0xDB, 0xE2), .ZO, .ZO, .{_087}),
    // FCOM / FCOMP / FCOMPP
    instr(.FCOM, ops1(.rm_mem32), Op1r(0xD8, 2), .M, .ZO, .{_087}),
    instr(.FCOM, ops1(.rm_mem64), Op1r(0xDC, 2), .M, .ZO, .{_087}),
    //
    instr(.FCOM, ops2(.reg_st0, .reg_st), Op2(0xD8, 0xD0), .O2, .ZO, .{_087}),
    instr(.FCOM, ops1(.reg_st), Op2(0xD8, 0xD0), .O, .ZO, .{_087}),
    instr(.FCOM, ops0(), Op2(0xD8, 0xD1), .ZO, .ZO, .{_087}),
    //
    instr(.FCOMP, ops1(.rm_mem32), Op1r(0xD8, 3), .M, .ZO, .{_087}),
    instr(.FCOMP, ops1(.rm_mem64), Op1r(0xDC, 3), .M, .ZO, .{_087}),
    //
    instr(.FCOMP, ops2(.reg_st0, .reg_st), Op2(0xD8, 0xD8), .O2, .ZO, .{_087}),
    instr(.FCOMP, ops1(.reg_st), Op2(0xD8, 0xD8), .O, .ZO, .{_087}),
    instr(.FCOMP, ops0(), Op2(0xD8, 0xD9), .ZO, .ZO, .{_087}),
    //
    instr(.FCOMPP, ops0(), Op2(0xDE, 0xD9), .ZO, .ZO, .{_087}),
    // FDECSTP
    instr(.FDECSTP, ops0(), Op2(0xD9, 0xF6), .ZO, .ZO, .{_087}),
    // FDIV / FDIVP / FIDIV
    instr(.FDIV, ops1(.rm_mem32), Op1r(0xD8, 6), .M, .ZO, .{_087}),
    instr(.FDIV, ops1(.rm_mem64), Op1r(0xDC, 6), .M, .ZO, .{_087}),
    //
    instr(.FDIV, ops1(.reg_st), Op2(0xD8, 0xF0), .O, .ZO, .{_087}),
    instr(.FDIV, ops2(.reg_st0, .reg_st), Op2(0xD8, 0xF0), .O2, .ZO, .{_087}),
    instr(.FDIV, ops2(.reg_st, .reg_st0), Op2(0xDC, 0xF8), .O, .ZO, .{_087}),
    //
    instr(.FDIVP, ops2(.reg_st, .reg_st0), Op2(0xDE, 0xF8), .O, .ZO, .{_087}),
    instr(.FDIVP, ops0(), Op2(0xDE, 0xF9), .ZO, .ZO, .{_087}),
    //
    instr(.FIDIV, ops1(.rm_mem16), Op1r(0xDE, 6), .M, .ZO, .{_087}),
    instr(.FIDIV, ops1(.rm_mem32), Op1r(0xDA, 6), .M, .ZO, .{_087}),
    // FDIVR / FDIVRP / FIDIVR
    instr(.FDIVR, ops1(.rm_mem32), Op1r(0xD8, 7), .M, .ZO, .{_087}),
    instr(.FDIVR, ops1(.rm_mem64), Op1r(0xDC, 7), .M, .ZO, .{_087}),
    //
    instr(.FDIVR, ops1(.reg_st), Op2(0xD8, 0xF8), .O, .ZO, .{_087}),
    instr(.FDIVR, ops2(.reg_st, .reg_st0), Op2(0xDC, 0xF0), .O, .ZO, .{_087}),
    instr(.FDIVR, ops2(.reg_st0, .reg_st), Op2(0xD8, 0xF8), .O2, .ZO, .{_087}),
    //
    instr(.FDIVRP, ops2(.reg_st, .reg_st0), Op2(0xDE, 0xF0), .O, .ZO, .{_087}),
    instr(.FDIVRP, ops0(), Op2(0xDE, 0xF1), .ZO, .ZO, .{_087}),
    //
    instr(.FIDIVR, ops1(.rm_mem16), Op1r(0xDE, 7), .M, .ZO, .{_087}),
    instr(.FIDIVR, ops1(.rm_mem32), Op1r(0xDA, 7), .M, .ZO, .{_087}),
    // FFREE
    instr(.FFREE, ops1(.reg_st), Op2(0xDD, 0xC0), .O, .ZO, .{_087}),
    // FICOM / FICOMP
    instr(.FICOM, ops1(.rm_mem16), Op1r(0xDE, 2), .M, .ZO, .{_087}),
    instr(.FICOM, ops1(.rm_mem32), Op1r(0xDA, 2), .M, .ZO, .{_087}),
    //
    instr(.FICOMP, ops1(.rm_mem16), Op1r(0xDE, 3), .M, .ZO, .{_087}),
    instr(.FICOMP, ops1(.rm_mem32), Op1r(0xDA, 3), .M, .ZO, .{_087}),
    // FILD
    instr(.FILD, ops1(.rm_mem16), Op1r(0xDF, 0), .M, .ZO, .{_087}),
    instr(.FILD, ops1(.rm_mem32), Op1r(0xDB, 0), .M, .ZO, .{_087}),
    instr(.FILD, ops1(.rm_mem64), Op1r(0xDF, 5), .M, .ZO, .{_087}),
    // FINCSTP
    instr(.FINCSTP, ops0(), Op2(0xD9, 0xF7), .ZO, .ZO, .{_087}),
    // FINIT / FNINIT
    instr(.FINIT, ops0(), compOp2(.FWAIT, 0xDB, 0xE3), .ZO, .ZO, .{_087}),
    instr(.FNINIT, ops0(), Op2(0xDB, 0xE3), .ZO, .ZO, .{_087}),
    // FIST
    instr(.FIST, ops1(.rm_mem16), Op1r(0xDF, 2), .M, .ZO, .{_087}),
    instr(.FIST, ops1(.rm_mem32), Op1r(0xDB, 2), .M, .ZO, .{_087}),
    //
    instr(.FISTP, ops1(.rm_mem16), Op1r(0xDF, 3), .M, .ZO, .{_087}),
    instr(.FISTP, ops1(.rm_mem32), Op1r(0xDB, 3), .M, .ZO, .{_087}),
    instr(.FISTP, ops1(.rm_mem64), Op1r(0xDF, 7), .M, .ZO, .{_087}),
    // FLD
    instr(.FLD, ops1(.rm_mem32), Op1r(0xD9, 0), .M, .ZO, .{_087}),
    instr(.FLD, ops1(.rm_mem64), Op1r(0xDD, 0), .M, .ZO, .{_087}),
    instr(.FLD, ops1(.rm_mem80), Op1r(0xDB, 5), .M, .ZO, .{_087}),
    instr(.FLD, ops1(.reg_st), Op2(0xD9, 0xC0), .O, .ZO, .{_087}),
    instr(.FLDCW, ops1(.rm_mem16), Op1r(0xD9, 5), .M, .ZO, .{_087}),
    instr(.FLDCW, ops1(.rm_mem), Op1r(0xD9, 5), .M, .ZO, .{_087}),
    instr(.FLD1, ops0(), Op2(0xD9, 0xE8), .ZO, .ZO, .{_087}),
    instr(.FLDL2T, ops0(), Op2(0xD9, 0xE9), .ZO, .ZO, .{_087}),
    instr(.FLDL2E, ops0(), Op2(0xD9, 0xEA), .ZO, .ZO, .{_087}),
    instr(.FLDPI, ops0(), Op2(0xD9, 0xEB), .ZO, .ZO, .{_087}),
    instr(.FLDLG2, ops0(), Op2(0xD9, 0xEC), .ZO, .ZO, .{_087}),
    instr(.FLDLN2, ops0(), Op2(0xD9, 0xED), .ZO, .ZO, .{_087}),
    instr(.FLDZ, ops0(), Op2(0xD9, 0xEE), .ZO, .ZO, .{_087}),
    // FLDENV
    instr(.FLDENV, ops1(.rm_mem), Op1r(0xD9, 4), .M, .ZO, .{_087}),
    instr(.FLDENVW, ops1(.rm_mem), Op1r(0xD9, 4), .M, .Op16, .{_087}),
    instr(.FLDENVD, ops1(.rm_mem), Op1r(0xD9, 4), .M, .Op32, .{_387}),
    // FMUL / FMULP / FIMUL
    instr(.FMUL, ops1(.rm_mem32), Op1r(0xD8, 1), .M, .ZO, .{_087}),
    instr(.FMUL, ops1(.rm_mem64), Op1r(0xDC, 1), .M, .ZO, .{_087}),
    //
    instr(.FMUL, ops1(.reg_st), Op2(0xD8, 0xC8), .O, .ZO, .{_087}),
    instr(.FMUL, ops2(.reg_st, .reg_st0), Op2(0xDC, 0xC8), .O, .ZO, .{_087}),
    instr(.FMUL, ops2(.reg_st0, .reg_st), Op2(0xD8, 0xC8), .O2, .ZO, .{_087}),
    //
    instr(.FMULP, ops2(.reg_st, .reg_st0), Op2(0xDE, 0xC8), .O, .ZO, .{_087}),
    instr(.FMULP, ops0(), Op2(0xDE, 0xC9), .ZO, .ZO, .{_087}),
    //
    instr(.FIMUL, ops1(.rm_mem16), Op1r(0xDE, 1), .M, .ZO, .{_087}),
    instr(.FIMUL, ops1(.rm_mem32), Op1r(0xDA, 1), .M, .ZO, .{_087}),
    // FNOP
    instr(.FNOP, ops0(), Op2(0xD9, 0xD0), .ZO, .ZO, .{_087}),
    // FPATAN
    instr(.FPATAN, ops0(), Op2(0xD9, 0xF3), .ZO, .ZO, .{_087}),
    // FPREM
    instr(.FPREM, ops0(), Op2(0xD9, 0xF8), .ZO, .ZO, .{_087}),
    // FPTAN
    instr(.FPTAN, ops0(), Op2(0xD9, 0xF2), .ZO, .ZO, .{_087}),
    // FRNDINT
    instr(.FRNDINT, ops0(), Op2(0xD9, 0xFC), .ZO, .ZO, .{_087}),
    // FRSTOR
    instr(.FRSTOR, ops1(.rm_mem), Op1r(0xDD, 4), .M, .ZO, .{_087}),
    instr(.FRSTORW, ops1(.rm_mem), Op1r(0xDD, 4), .M, .Op16, .{_087}),
    instr(.FRSTORD, ops1(.rm_mem), Op1r(0xDD, 4), .M, .Op32, .{_387}),
    // FSAVE / FNSAVE
    instr(.FSAVE, ops1(.rm_mem), compOp1r(.FWAIT, 0xDD, 6), .M, .ZO, .{_087}),
    instr(.FSAVEW, ops1(.rm_mem), compOp1r(.FWAIT, 0xDD, 6), .M, .Op16, .{_087}),
    instr(.FSAVED, ops1(.rm_mem), compOp1r(.FWAIT, 0xDD, 6), .M, .Op32, .{_387}),
    instr(.FNSAVE, ops1(.rm_mem), Op1r(0xDD, 6), .M, .ZO, .{_087}),
    instr(.FNSAVEW, ops1(.rm_mem), Op1r(0xDD, 6), .M, .Op16, .{_087}),
    instr(.FNSAVED, ops1(.rm_mem), Op1r(0xDD, 6), .M, .Op32, .{_387}),
    // FSCALE
    instr(.FSCALE, ops0(), Op2(0xD9, 0xFD), .ZO, .ZO, .{_087}),
    // FSQRT
    instr(.FSQRT, ops0(), Op2(0xD9, 0xFA), .ZO, .ZO, .{_087}),
    // FST / FSTP
    instr(.FST, ops1(.rm_mem32), Op1r(0xD9, 2), .M, .ZO, .{_087}),
    instr(.FST, ops1(.rm_mem64), Op1r(0xDD, 2), .M, .ZO, .{_087}),
    instr(.FST, ops1(.reg_st), Op2(0xDD, 0xD0), .O, .ZO, .{_087}),
    instr(.FST, ops2(.reg_st0, .reg_st), Op2(0xDD, 0xD0), .O2, .ZO, .{_087}),
    instr(.FSTP, ops1(.rm_mem32), Op1r(0xD9, 3), .M, .ZO, .{_087}),
    instr(.FSTP, ops1(.rm_mem64), Op1r(0xDD, 3), .M, .ZO, .{_087}),
    instr(.FSTP, ops1(.rm_mem80), Op1r(0xDB, 7), .M, .ZO, .{_087}),
    instr(.FSTP, ops1(.reg_st), Op2(0xDD, 0xD8), .O, .ZO, .{_087}),
    instr(.FSTP, ops2(.reg_st0, .reg_st), Op2(0xDD, 0xD8), .O2, .ZO, .{_087}),
    // FSTCW / FNSTCW
    instr(.FSTCW, ops1(.rm_mem), compOp1r(.FWAIT, 0xD9, 7), .M, .ZO, .{_087}),
    instr(.FSTCW, ops1(.rm_mem16), compOp1r(.FWAIT, 0xD9, 7), .M, .ZO, .{_087}),
    instr(.FNSTCW, ops1(.rm_mem), Op1r(0xD9, 7), .M, .ZO, .{_087}),
    instr(.FNSTCW, ops1(.rm_mem16), Op1r(0xD9, 7), .M, .ZO, .{_087}),
    // FSTENV / FNSTENV
    instr(.FSTENV, ops1(.rm_mem), compOp1r(.FWAIT, 0xD9, 6), .M, .ZO, .{_087}),
    instr(.FSTENVW, ops1(.rm_mem), compOp1r(.FWAIT, 0xD9, 6), .M, .Op16, .{_087}),
    instr(.FSTENVD, ops1(.rm_mem), compOp1r(.FWAIT, 0xD9, 6), .M, .Op32, .{_387}),
    instr(.FNSTENV, ops1(.rm_mem), Op1r(0xD9, 6), .M, .ZO, .{_087}),
    instr(.FNSTENVW, ops1(.rm_mem), Op1r(0xD9, 6), .M, .Op16, .{_087}),
    instr(.FNSTENVD, ops1(.rm_mem), Op1r(0xD9, 6), .M, .Op32, .{_387}),
    // FSTSW / FNSTSW
    instr(.FSTSW, ops1(.rm_mem), compOp1r(.FWAIT, 0xDD, 7), .M, .ZO, .{_087}),
    instr(.FSTSW, ops1(.rm_mem16), compOp1r(.FWAIT, 0xDD, 7), .M, .ZO, .{_087}),
    instr(.FSTSW, ops1(.reg_ax), compOp2(.FWAIT, 0xDF, 0xE0), .ZO, .ZO, .{_087}),
    instr(.FNSTSW, ops1(.rm_mem), Op1r(0xDD, 7), .M, .ZO, .{_087}),
    instr(.FNSTSW, ops1(.rm_mem16), Op1r(0xDD, 7), .M, .ZO, .{_087}),
    instr(.FNSTSW, ops1(.reg_ax), Op2(0xDF, 0xE0), .ZO, .ZO, .{_087}),
    // FSUB / FSUBP / FISUB
    instr(.FSUB, ops1(.rm_mem32), Op1r(0xD8, 4), .M, .ZO, .{_087}),
    instr(.FSUB, ops1(.rm_mem64), Op1r(0xDC, 4), .M, .ZO, .{_087}),
    //
    instr(.FSUB, ops1(.reg_st), Op2(0xD8, 0xE0), .O, .ZO, .{_087}),
    instr(.FSUB, ops2(.reg_st, .reg_st0), Op2(0xDC, 0xE8), .O, .ZO, .{_087}),
    instr(.FSUB, ops2(.reg_st0, .reg_st), Op2(0xD8, 0xE0), .O2, .ZO, .{_087}),
    //
    instr(.FSUBP, ops2(.reg_st, .reg_st0), Op2(0xDE, 0xE8), .O, .ZO, .{_087}),
    instr(.FSUBP, ops0(), Op2(0xDE, 0xE9), .ZO, .ZO, .{_087}),
    //
    instr(.FISUB, ops1(.rm_mem16), Op1r(0xDE, 4), .M, .ZO, .{_087}),
    instr(.FISUB, ops1(.rm_mem32), Op1r(0xDA, 4), .M, .ZO, .{_087}),
    // FSUBR / FSUBRP / FISUBR
    instr(.FSUBR, ops1(.rm_mem32), Op1r(0xD8, 5), .M, .ZO, .{_087}),
    instr(.FSUBR, ops1(.rm_mem64), Op1r(0xDC, 5), .M, .ZO, .{_087}),
    //
    instr(.FSUBR, ops1(.reg_st), Op2(0xD8, 0xE8), .O, .ZO, .{_087}),
    instr(.FSUBR, ops2(.reg_st0, .reg_st), Op2(0xD8, 0xE8), .O2, .ZO, .{_087}),
    instr(.FSUBR, ops2(.reg_st, .reg_st0), Op2(0xDC, 0xE0), .O, .ZO, .{_087}),
    //
    instr(.FSUBRP, ops2(.reg_st, .reg_st0), Op2(0xDE, 0xE0), .O, .ZO, .{_087}),
    instr(.FSUBRP, ops0(), Op2(0xDE, 0xE1), .ZO, .ZO, .{_087}),
    //
    instr(.FISUBR, ops1(.rm_mem16), Op1r(0xDE, 5), .M, .ZO, .{_087}),
    instr(.FISUBR, ops1(.rm_mem32), Op1r(0xDA, 5), .M, .ZO, .{_087}),
    // FTST
    instr(.FTST, ops0(), Op2(0xD9, 0xE4), .ZO, .ZO, .{_087}),
    // FWAIT (alternate mnemonic for WAIT)
    instr(.FWAIT, ops0(), Op1(0x9B), .ZO, .ZO, .{_087}),
    // FXAM
    instr(.FXAM, ops0(), Op2(0xD9, 0xE5), .ZO, .ZO, .{_087}),
    // FXCH
    instr(.FXCH, ops2(.reg_st0, .reg_st), Op2(0xD9, 0xC8), .O2, .ZO, .{_087}),
    instr(.FXCH, ops1(.reg_st), Op2(0xD9, 0xC8), .O, .ZO, .{_087}),
    instr(.FXCH, ops0(), Op2(0xD9, 0xC9), .ZO, .ZO, .{_087}),
    // FXTRACT
    instr(.FXTRACT, ops0(), Op2(0xD9, 0xF4), .ZO, .ZO, .{_087}),
    // FYL2X
    instr(.FYL2X, ops0(), Op2(0xD9, 0xF1), .ZO, .ZO, .{_087}),
    // FYL2XP1
    instr(.FYL2XP1, ops0(), Op2(0xD9, 0xF9), .ZO, .ZO, .{_087}),

    //
    // 80287
    //
    // instr(.FSETPM,  ops0(),                   Op2(0xDB, 0xE4),       .ZO, .ZO,    .{cpu._287, edge.obsolete} ),

    //
    // 80387
    //
    instr(.FCOS, ops0(), Op2(0xD9, 0xFF), .ZO, .ZO, .{_387}),
    instr(.FPREM1, ops0(), Op2(0xD9, 0xF5), .ZO, .ZO, .{_387}),
    instr(.FSIN, ops0(), Op2(0xD9, 0xFE), .ZO, .ZO, .{_387}),
    instr(.FSINCOS, ops0(), Op2(0xD9, 0xFB), .ZO, .ZO, .{_387}),
    // FUCOM / FUCOMP / FUCOMPP
    instr(.FUCOM, ops2(.reg_st0, .reg_st), Op2(0xDD, 0xE0), .O2, .ZO, .{_387}),
    instr(.FUCOM, ops1(.reg_st), Op2(0xDD, 0xE0), .O, .ZO, .{_387}),
    instr(.FUCOM, ops0(), Op2(0xDD, 0xE1), .ZO, .ZO, .{_387}),
    //
    instr(.FUCOMP, ops2(.reg_st0, .reg_st), Op2(0xDD, 0xE8), .O2, .ZO, .{_387}),
    instr(.FUCOMP, ops1(.reg_st), Op2(0xDD, 0xE8), .O, .ZO, .{_387}),
    instr(.FUCOMP, ops0(), Op2(0xDD, 0xE9), .ZO, .ZO, .{_387}),
    //
    instr(.FUCOMPP, ops0(), Op2(0xDA, 0xE9), .ZO, .ZO, .{_387}),

    //
    // x87 -- Pentium Pro / P6
    //
    // FCMOVcc
    instr(.FCMOVB, ops2(.reg_st0, .reg_st), Op2(0xDA, 0xC0), .O2, .ZO, .{ cpu.CMOV, cpu.FPU }),
    instr(.FCMOVB, ops1(.reg_st), Op2(0xDA, 0xC0), .O, .ZO, .{ cpu.CMOV, cpu.FPU }),
    //
    instr(.FCMOVE, ops2(.reg_st0, .reg_st), Op2(0xDA, 0xC8), .O2, .ZO, .{ cpu.CMOV, cpu.FPU }),
    instr(.FCMOVE, ops1(.reg_st), Op2(0xDA, 0xC8), .O, .ZO, .{ cpu.CMOV, cpu.FPU }),
    //
    instr(.FCMOVBE, ops2(.reg_st0, .reg_st), Op2(0xDA, 0xD0), .O2, .ZO, .{ cpu.CMOV, cpu.FPU }),
    instr(.FCMOVBE, ops1(.reg_st), Op2(0xDA, 0xD0), .O, .ZO, .{ cpu.CMOV, cpu.FPU }),
    //
    instr(.FCMOVU, ops2(.reg_st0, .reg_st), Op2(0xDA, 0xD8), .O2, .ZO, .{ cpu.CMOV, cpu.FPU }),
    instr(.FCMOVU, ops1(.reg_st), Op2(0xDA, 0xD8), .O, .ZO, .{ cpu.CMOV, cpu.FPU }),
    //
    instr(.FCMOVNB, ops2(.reg_st0, .reg_st), Op2(0xDB, 0xC0), .O2, .ZO, .{ cpu.CMOV, cpu.FPU }),
    instr(.FCMOVNB, ops1(.reg_st), Op2(0xDB, 0xC0), .O, .ZO, .{ cpu.CMOV, cpu.FPU }),
    //
    instr(.FCMOVNE, ops2(.reg_st0, .reg_st), Op2(0xDB, 0xC8), .O2, .ZO, .{ cpu.CMOV, cpu.FPU }),
    instr(.FCMOVNE, ops1(.reg_st), Op2(0xDB, 0xC8), .O, .ZO, .{ cpu.CMOV, cpu.FPU }),
    //
    instr(.FCMOVNBE, ops2(.reg_st0, .reg_st), Op2(0xDB, 0xD0), .O2, .ZO, .{ cpu.CMOV, cpu.FPU }),
    instr(.FCMOVNBE, ops1(.reg_st), Op2(0xDB, 0xD0), .O, .ZO, .{ cpu.CMOV, cpu.FPU }),
    //
    instr(.FCMOVNU, ops2(.reg_st0, .reg_st), Op2(0xDB, 0xD8), .O2, .ZO, .{ cpu.CMOV, cpu.FPU }),
    instr(.FCMOVNU, ops1(.reg_st), Op2(0xDB, 0xD8), .O, .ZO, .{ cpu.CMOV, cpu.FPU }),
    // FCOMI
    instr(.FCOMI, ops2(.reg_st0, .reg_st), Op2(0xDB, 0xF0), .O2, .ZO, .{ cpu.CMOV, cpu.FPU }),
    instr(.FCOMI, ops1(.reg_st), Op2(0xDB, 0xF0), .O, .ZO, .{ cpu.CMOV, cpu.FPU }),
    // FCOMIP
    instr(.FCOMIP, ops2(.reg_st0, .reg_st), Op2(0xDF, 0xF0), .O2, .ZO, .{ cpu.CMOV, cpu.FPU }),
    instr(.FCOMIP, ops1(.reg_st), Op2(0xDF, 0xF0), .O, .ZO, .{ cpu.CMOV, cpu.FPU }),
    // FUCOMI
    instr(.FUCOMI, ops2(.reg_st0, .reg_st), Op2(0xDB, 0xE8), .O2, .ZO, .{ cpu.CMOV, cpu.FPU }),
    instr(.FUCOMI, ops1(.reg_st), Op2(0xDB, 0xE8), .O, .ZO, .{ cpu.CMOV, cpu.FPU }),
    // FUCOMIP
    instr(.FUCOMIP, ops2(.reg_st0, .reg_st), Op2(0xDF, 0xE8), .O2, .ZO, .{ cpu.CMOV, cpu.FPU }),
    instr(.FUCOMIP, ops1(.reg_st), Op2(0xDF, 0xE8), .O, .ZO, .{ cpu.CMOV, cpu.FPU }),

    //
    //  x87 - other
    // FISTTP - same as FSTP but won't cause a stack underflow exception
    instr(.FISTTP, ops1(.rm_mem16), Op1r(0xDF, 1), .M, .ZO, .{SSE3}),
    instr(.FISTTP, ops1(.rm_mem32), Op1r(0xDB, 1), .M, .ZO, .{SSE3}),
    instr(.FISTTP, ops1(.rm_mem64), Op1r(0xDD, 1), .M, .ZO, .{SSE3}),

    //
    // 80286
    //
    // NOTES: might want to handle operands like `r32/m16` better
    instr(.ARPL, ops2(.rm16, .reg16), Op1(0x63), .MR, .ZO, .{ No64, _286 }),
    //
    instr(.CLTS, ops0(), Op2(0x0F, 0x06), .ZO, .ZO, .{_286}),
    //
    instr(.LAR, ops2(.reg16, .rm16), Op2(0x0F, 0x02), .RM, .Op16, .{_286}),
    instr(.LAR, ops2(.reg32, .rm32), Op2(0x0F, 0x02), .RM, .Op32, .{_386}),
    instr(.LAR, ops2(.reg64, .rm64), Op2(0x0F, 0x02), .RM, .REX_W, .{x86_64}),
    //
    instr(.LGDT, ops1(.rm_mem), Op2r(0x0F, 0x01, 2), .M, .ZO, .{ No64, _286 }),
    instr(.LGDT, ops1(.rm_mem), Op2r(0x0F, 0x01, 2), .M, .ZO, .{ No32, _286 }),
    //
    instr(.LIDT, ops1(.rm_mem), Op2r(0x0F, 0x01, 3), .M, .ZO, .{ No64, _286 }),
    instr(.LIDT, ops1(.rm_mem), Op2r(0x0F, 0x01, 3), .M, .ZO, .{ No32, _286 }),
    //
    instr(.LLDT, ops1(.rm16), Op2r(0x0F, 0x00, 2), .M, .ZO, .{_286}),
    //
    instr(.LMSW, ops1(.rm16), Op2r(0x0F, 0x01, 6), .M, .ZO, .{_286}),
    //
    // instr(.LOADALL, ops1(.rm16),                Op2r(0x0F, 0x01, 6),    .M, .ZO,      .{_286, _386} ), // undocumented
    //
    instr(.LSL, ops2(.reg16, .rm16), Op2(0x0F, 0x03), .RM, .Op16, .{_286}),
    instr(.LSL, ops2(.reg32, .rm32), Op2(0x0F, 0x03), .RM, .Op32, .{_386}),
    instr(.LSL, ops2(.reg64, .rm64), Op2(0x0F, 0x03), .RM, .REX_W, .{x86_64}),
    //
    instr(.LTR, ops1(.rm16), Op2r(0x0F, 0x00, 3), .M, .ZO, .{_286}),
    //
    instr(.SGDT, ops1(.rm_mem), Op2r(0x0F, 0x01, 0), .M, .ZO, .{_286}),
    //
    instr(.SIDT, ops1(.rm_mem), Op2r(0x0F, 0x01, 1), .M, .ZO, .{_286}),
    //
    instr(.SLDT, ops1(.rm_mem16), Op2r(0x0F, 0x00, 0), .M, .ZO, .{_286}),
    instr(.SLDT, ops1(.rm_reg16), Op2r(0x0F, 0x00, 0), .M, .Op16, .{_286}),
    instr(.SLDT, ops1(.rm_reg32), Op2r(0x0F, 0x00, 0), .M, .Op32, .{_386}),
    instr(.SLDT, ops1(.rm_reg64), Op2r(0x0F, 0x00, 0), .M, .REX_W, .{x86_64}),
    //
    instr(.SMSW, ops1(.rm_mem16), Op2r(0x0F, 0x01, 4), .M, .ZO, .{_286}),
    instr(.SMSW, ops1(.rm_reg16), Op2r(0x0F, 0x01, 4), .M, .Op16, .{_286}),
    instr(.SMSW, ops1(.rm_reg32), Op2r(0x0F, 0x01, 4), .M, .Op32, .{_386}),
    instr(.SMSW, ops1(.rm_reg64), Op2r(0x0F, 0x01, 4), .M, .REX_W, .{x86_64}),
    //
    instr(.STR, ops1(.rm_mem16), Op2r(0x0F, 0x00, 1), .M, .ZO, .{_286}),
    instr(.STR, ops1(.rm_reg16), Op2r(0x0F, 0x00, 1), .M, .Op16, .{_286}),
    instr(.STR, ops1(.rm_reg32), Op2r(0x0F, 0x00, 1), .M, .Op32, .{_386}),
    instr(.STR, ops1(.rm_reg64), Op2r(0x0F, 0x00, 1), .M, .REX_W, .{x86_64}),
    //
    instr(.VERR, ops1(.rm16), Op2r(0x0F, 0x00, 4), .M, .ZO, .{_286}),
    instr(.VERW, ops1(.rm16), Op2r(0x0F, 0x00, 5), .M, .ZO, .{_286}),

    //
    // 80386
    //
    // BSF
    instr(.BSF, ops2(.reg16, .rm16), Op2(0x0F, 0xBC), .RM, .Op16, .{_386}),
    instr(.BSF, ops2(.reg32, .rm32), Op2(0x0F, 0xBC), .RM, .Op32, .{_386}),
    instr(.BSF, ops2(.reg64, .rm64), Op2(0x0F, 0xBC), .RM, .REX_W, .{x86_64}),
    // BSR
    instr(.BSR, ops2(.reg16, .rm16), Op2(0x0F, 0xBD), .RM, .Op16, .{_386}),
    instr(.BSR, ops2(.reg32, .rm32), Op2(0x0F, 0xBD), .RM, .Op32, .{_386}),
    instr(.BSR, ops2(.reg64, .rm64), Op2(0x0F, 0xBD), .RM, .REX_W, .{x86_64}),
    // BSR
    instr(.BT, ops2(.rm16, .reg16), Op2(0x0F, 0xA3), .MR, .Op16, .{_386}),
    instr(.BT, ops2(.rm32, .reg32), Op2(0x0F, 0xA3), .MR, .Op32, .{_386}),
    instr(.BT, ops2(.rm64, .reg64), Op2(0x0F, 0xA3), .MR, .REX_W, .{x86_64}),
    //
    instr(.BT, ops2(.rm16, .imm8), Op2r(0x0F, 0xBA, 4), .MI, .Op16, .{_386}),
    instr(.BT, ops2(.rm32, .imm8), Op2r(0x0F, 0xBA, 4), .MI, .Op32, .{_386}),
    instr(.BT, ops2(.rm64, .imm8), Op2r(0x0F, 0xBA, 4), .MI, .REX_W, .{x86_64}),
    // BTC
    instr(.BTC, ops2(.rm16, .reg16), Op2(0x0F, 0xBB), .MR, .Op16, .{ _386, Lock, Hle }),
    instr(.BTC, ops2(.rm32, .reg32), Op2(0x0F, 0xBB), .MR, .Op32, .{ _386, Lock, Hle }),
    instr(.BTC, ops2(.rm64, .reg64), Op2(0x0F, 0xBB), .MR, .REX_W, .{ x86_64, Lock, Hle }),
    //
    instr(.BTC, ops2(.rm16, .imm8), Op2r(0x0F, 0xBA, 7), .MI, .Op16, .{ _386, Lock, Hle }),
    instr(.BTC, ops2(.rm32, .imm8), Op2r(0x0F, 0xBA, 7), .MI, .Op32, .{ _386, Lock, Hle }),
    instr(.BTC, ops2(.rm64, .imm8), Op2r(0x0F, 0xBA, 7), .MI, .REX_W, .{ x86_64, Lock, Hle }),
    // BTR
    instr(.BTR, ops2(.rm16, .reg16), Op2(0x0F, 0xB3), .MR, .Op16, .{ _386, Lock, Hle }),
    instr(.BTR, ops2(.rm32, .reg32), Op2(0x0F, 0xB3), .MR, .Op32, .{ _386, Lock, Hle }),
    instr(.BTR, ops2(.rm64, .reg64), Op2(0x0F, 0xB3), .MR, .REX_W, .{ x86_64, Lock, Hle }),
    //
    instr(.BTR, ops2(.rm16, .imm8), Op2r(0x0F, 0xBA, 6), .MI, .Op16, .{ _386, Lock, Hle }),
    instr(.BTR, ops2(.rm32, .imm8), Op2r(0x0F, 0xBA, 6), .MI, .Op32, .{ _386, Lock, Hle }),
    instr(.BTR, ops2(.rm64, .imm8), Op2r(0x0F, 0xBA, 6), .MI, .REX_W, .{ x86_64, Lock, Hle }),
    // BTS
    instr(.BTS, ops2(.rm16, .reg16), Op2(0x0F, 0xAB), .MR, .Op16, .{ _386, Lock, Hle }),
    instr(.BTS, ops2(.rm32, .reg32), Op2(0x0F, 0xAB), .MR, .Op32, .{ _386, Lock, Hle }),
    instr(.BTS, ops2(.rm64, .reg64), Op2(0x0F, 0xAB), .MR, .REX_W, .{ x86_64, Lock, Hle }),
    //
    instr(.BTS, ops2(.rm16, .imm8), Op2r(0x0F, 0xBA, 5), .MI, .Op16, .{_386}),
    instr(.BTS, ops2(.rm32, .imm8), Op2r(0x0F, 0xBA, 5), .MI, .Op32, .{_386}),
    instr(.BTS, ops2(.rm64, .imm8), Op2r(0x0F, 0xBA, 5), .MI, .REX_W, .{x86_64}),
    // IBTS
    instr(.IBTS, ops2(.rm16, .reg16), Op2(0x0F, 0xA7), .MR, .Op16, .{ _386_Legacy, No64 }),
    instr(.IBTS, ops2(.rm32, .reg32), Op2(0x0F, 0xA7), .MR, .Op32, .{ _386_Legacy, No64 }),
    // MOVSX / MOVSXD
    instr(.MOVSX, ops2(.reg16, .rm8), Op2(0x0F, 0xBE), .RM, .Op16, .{_386}),
    instr(.MOVSX, ops2(.reg32, .rm8), Op2(0x0F, 0xBE), .RM, .Op32, .{_386}),
    instr(.MOVSX, ops2(.reg64, .rm8), Op2(0x0F, 0xBE), .RM, .REX_W, .{x86_64}),
    //
    instr(.MOVSX, ops2(.reg16, .rm16), Op2(0x0F, 0xBF), .RM, .Op16, .{_386}),
    instr(.MOVSX, ops2(.reg32, .rm16), Op2(0x0F, 0xBF), .RM, .Op32, .{_386}),
    instr(.MOVSX, ops2(.reg64, .rm16), Op2(0x0F, 0xBF), .RM, .REX_W, .{x86_64}),
    //
    instr(.MOVSXD, ops2(.reg16, .rm16), Op1(0x63), .RM, .Op16, .{_386}),
    instr(.MOVSXD, ops2(.reg16, .rm32), Op1(0x63), .RM, .Op16, .{_386}),
    instr(.MOVSXD, ops2(.reg32, .rm32), Op1(0x63), .RM, .Op32, .{_386}),
    instr(.MOVSXD, ops2(.reg64, .rm32), Op1(0x63), .RM, .REX_W, .{x86_64}),
    // MOVZX
    instr(.MOVZX, ops2(.reg16, .rm8), Op2(0x0F, 0xB6), .RM, .Op16, .{_386}),
    instr(.MOVZX, ops2(.reg32, .rm8), Op2(0x0F, 0xB6), .RM, .Op32, .{_386}),
    instr(.MOVZX, ops2(.reg64, .rm8), Op2(0x0F, 0xB6), .RM, .REX_W, .{x86_64}),
    //
    instr(.MOVZX, ops2(.reg16, .rm16), Op2(0x0F, 0xB7), .RM, .Op16, .{_386}),
    instr(.MOVZX, ops2(.reg32, .rm16), Op2(0x0F, 0xB7), .RM, .Op32, .{_386}),
    instr(.MOVZX, ops2(.reg64, .rm16), Op2(0x0F, 0xB7), .RM, .REX_W, .{x86_64}),
    // SETcc
    instr(.SETA, ops1(.rm8), Op2(0x0F, 0x97), .M, .ZO, .{_386}),
    instr(.SETAE, ops1(.rm8), Op2(0x0F, 0x93), .M, .ZO, .{_386}),
    instr(.SETB, ops1(.rm8), Op2(0x0F, 0x92), .M, .ZO, .{_386}),
    instr(.SETBE, ops1(.rm8), Op2(0x0F, 0x96), .M, .ZO, .{_386}),
    instr(.SETC, ops1(.rm8), Op2(0x0F, 0x92), .M, .ZO, .{_386}),
    instr(.SETE, ops1(.rm8), Op2(0x0F, 0x94), .M, .ZO, .{_386}),
    instr(.SETG, ops1(.rm8), Op2(0x0F, 0x9F), .M, .ZO, .{_386}),
    instr(.SETGE, ops1(.rm8), Op2(0x0F, 0x9D), .M, .ZO, .{_386}),
    instr(.SETL, ops1(.rm8), Op2(0x0F, 0x9C), .M, .ZO, .{_386}),
    instr(.SETLE, ops1(.rm8), Op2(0x0F, 0x9E), .M, .ZO, .{_386}),
    instr(.SETNA, ops1(.rm8), Op2(0x0F, 0x96), .M, .ZO, .{_386}),
    instr(.SETNAE, ops1(.rm8), Op2(0x0F, 0x92), .M, .ZO, .{_386}),
    instr(.SETNB, ops1(.rm8), Op2(0x0F, 0x93), .M, .ZO, .{_386}),
    instr(.SETNBE, ops1(.rm8), Op2(0x0F, 0x97), .M, .ZO, .{_386}),
    instr(.SETNC, ops1(.rm8), Op2(0x0F, 0x93), .M, .ZO, .{_386}),
    instr(.SETNE, ops1(.rm8), Op2(0x0F, 0x95), .M, .ZO, .{_386}),
    instr(.SETNG, ops1(.rm8), Op2(0x0F, 0x9E), .M, .ZO, .{_386}),
    instr(.SETNGE, ops1(.rm8), Op2(0x0F, 0x9C), .M, .ZO, .{_386}),
    instr(.SETNL, ops1(.rm8), Op2(0x0F, 0x9D), .M, .ZO, .{_386}),
    instr(.SETNLE, ops1(.rm8), Op2(0x0F, 0x9F), .M, .ZO, .{_386}),
    instr(.SETNO, ops1(.rm8), Op2(0x0F, 0x91), .M, .ZO, .{_386}),
    instr(.SETNP, ops1(.rm8), Op2(0x0F, 0x9B), .M, .ZO, .{_386}),
    instr(.SETNS, ops1(.rm8), Op2(0x0F, 0x99), .M, .ZO, .{_386}),
    instr(.SETNZ, ops1(.rm8), Op2(0x0F, 0x95), .M, .ZO, .{_386}),
    instr(.SETO, ops1(.rm8), Op2(0x0F, 0x90), .M, .ZO, .{_386}),
    instr(.SETP, ops1(.rm8), Op2(0x0F, 0x9A), .M, .ZO, .{_386}),
    instr(.SETPE, ops1(.rm8), Op2(0x0F, 0x9A), .M, .ZO, .{_386}),
    instr(.SETPO, ops1(.rm8), Op2(0x0F, 0x9B), .M, .ZO, .{_386}),
    instr(.SETS, ops1(.rm8), Op2(0x0F, 0x98), .M, .ZO, .{_386}),
    instr(.SETZ, ops1(.rm8), Op2(0x0F, 0x94), .M, .ZO, .{_386}),
    // SHLD
    instr(.SHLD, ops3(.rm16, .reg16, .imm8), Op2(0x0F, 0xA4), .MRI, .Op16, .{_386}),
    instr(.SHLD, ops3(.rm32, .reg32, .imm8), Op2(0x0F, 0xA4), .MRI, .Op32, .{_386}),
    instr(.SHLD, ops3(.rm64, .reg64, .imm8), Op2(0x0F, 0xA4), .MRI, .REX_W, .{x86_64}),
    //
    instr(.SHLD, ops3(.rm16, .reg16, .reg_cl), Op2(0x0F, 0xA5), .MR, .Op16, .{_386}),
    instr(.SHLD, ops3(.rm32, .reg32, .reg_cl), Op2(0x0F, 0xA5), .MR, .Op32, .{_386}),
    instr(.SHLD, ops3(.rm64, .reg64, .reg_cl), Op2(0x0F, 0xA5), .MR, .REX_W, .{x86_64}),
    // SHLD
    instr(.SHRD, ops3(.rm16, .reg16, .imm8), Op2(0x0F, 0xAC), .MRI, .Op16, .{_386}),
    instr(.SHRD, ops3(.rm32, .reg32, .imm8), Op2(0x0F, 0xAC), .MRI, .Op32, .{_386}),
    instr(.SHRD, ops3(.rm64, .reg64, .imm8), Op2(0x0F, 0xAC), .MRI, .REX_W, .{x86_64}),
    //
    instr(.SHRD, ops3(.rm16, .reg16, .reg_cl), Op2(0x0F, 0xAD), .MR, .Op16, .{_386}),
    instr(.SHRD, ops3(.rm32, .reg32, .reg_cl), Op2(0x0F, 0xAD), .MR, .Op32, .{_386}),
    instr(.SHRD, ops3(.rm64, .reg64, .reg_cl), Op2(0x0F, 0xAD), .MR, .REX_W, .{x86_64}),
    // XBTS
    instr(.XBTS, ops2(.reg16, .rm16), Op2(0x0F, 0xA6), .RM, .Op16, .{ _386_Legacy, No64 }),
    instr(.XBTS, ops2(.reg32, .rm32), Op2(0x0F, 0xA6), .RM, .Op32, .{ _386_Legacy, No64 }),

    //
    // 80486
    instr(.BSWAP, ops1(.reg16), Op2(0x0F, 0xC8), .O, .Op16, .{ _486, edge.Undefined }),
    instr(.BSWAP, ops1(.reg32), Op2(0x0F, 0xC8), .O, .Op32, .{_486}),
    instr(.BSWAP, ops1(.reg64), Op2(0x0F, 0xC8), .O, .REX_W, .{x86_64}),
    // CMPXCHG
    instr(.CMPXCHG, ops2(.rm8, .reg8), Op2(0x0F, 0xB0), .MR, .ZO, .{ _486, Lock, Hle }),
    instr(.CMPXCHG, ops2(.rm16, .reg16), Op2(0x0F, 0xB1), .MR, .Op16, .{ _486, Lock, Hle }),
    instr(.CMPXCHG, ops2(.rm32, .reg32), Op2(0x0F, 0xB1), .MR, .Op32, .{ _486, Lock, Hle }),
    instr(.CMPXCHG, ops2(.rm64, .reg64), Op2(0x0F, 0xB1), .MR, .REX_W, .{ x86_64, Lock, Hle }),
    // INVD
    instr(.INVD, ops0(), Op2(0x0F, 0x08), .ZO, .ZO, .{_486}),
    // INVLPG
    instr(.INVLPG, ops1(.rm_mem), Op2r(0x0F, 0x01, 7), .M, .ZO, .{_486}),
    // WBINVD
    instr(.WBINVD, ops0(), Op2(0x0F, 0x09), .ZO, .ZO, .{_486}),
    // XADD
    instr(.XADD, ops2(.rm8, .reg8), Op2(0x0F, 0xC0), .MR, .ZO, .{_486}),
    instr(.XADD, ops2(.rm16, .reg16), Op2(0x0F, 0xC1), .MR, .Op16, .{_486}),
    instr(.XADD, ops2(.rm32, .reg32), Op2(0x0F, 0xC1), .MR, .Op32, .{_486}),
    instr(.XADD, ops2(.rm64, .reg64), Op2(0x0F, 0xC1), .MR, .REX_W, .{x86_64}),

    //
    // Pentium
    //
    instr(.CPUID, ops0(), Op2(0x0F, 0xA2), .ZO, .ZO, .{cpu.CPUID}),
    // CMPXCHG8B / CMPXCHG16B
    instr(.CMPXCHG8B, ops1(.rm_mem64), Op2r(0x0F, 0xC7, 1), .M, .ZO, .{ cpu.CX8, Lock, Hle }),
    instr(.CMPXCHG16B, ops1(.rm_mem128), Op2r(0x0F, 0xC7, 1), .M, .REX_W, .{ cpu.CX16, Lock, Hle }),
    // RDMSR
    instr(.RDMSR, ops0(), Op2(0x0F, 0x32), .ZO, .ZO, .{cpu.MSR}),
    // RDTSC
    instr(.RDTSC, ops0(), Op2(0x0F, 0x31), .ZO, .ZO, .{cpu.TSC}),
    // WRMSR
    instr(.WRMSR, ops0(), Op2(0x0F, 0x30), .ZO, .ZO, .{cpu.MSR}),
    // RSM
    instr(.RSM, ops0(), Op2(0x0F, 0xAA), .ZO, .ZO, .{cpu.RSM}),

    //
    // Pentium MMX
    //
    // RDPMC
    instr(.RDPMC, ops0(), Op2(0x0F, 0x33), .ZO, .ZO, .{P6}),
    // EMMS
    instr(.EMMS, ops0(), preOp2(._NP, 0x0F, 0x77), .ZO, .ZO, .{cpu.MMX}),

    //
    // K6
    //
    instr(.SYSCALL, ops0(), Op2(0x0F, 0x05), .ZO, .ZO, .{ cpu.SYSCALL, cpu.Intel, No32 }),
    instr(.SYSCALL, ops0(), Op2(0x0F, 0x05), .ZO, .ZO, .{ cpu.SYSCALL, cpu.Amd }),
    instr(.SYSCALL, ops0(), Op2(0x0F, 0x05), .ZO, .ZO, .{ cpu.SYSCALL, No32 }),
    //
    instr(.SYSRET, ops0(), Op2(0x0F, 0x07), .ZO, .ZO, .{ cpu.SYSCALL, cpu.Intel, No32 }),
    instr(.SYSRET, ops0(), Op2(0x0F, 0x07), .ZO, .ZO, .{ cpu.SYSCALL, cpu.Amd }),
    instr(.SYSRET, ops0(), Op2(0x0F, 0x07), .ZO, .ZO, .{ cpu.SYSCALL, No32 }),
    instr(.SYSRETQ, ops0(), Op2(0x0F, 0x07), .ZO, .REX_W, .{x86_64}),

    //
    // Pentium Pro
    //
    // CMOVcc
    instr(.CMOVA, ops2(.reg16, .rm16), Op2(0x0F, 0x47), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVA, ops2(.reg32, .rm32), Op2(0x0F, 0x47), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVA, ops2(.reg64, .rm64), Op2(0x0F, 0x47), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVAE, ops2(.reg16, .rm16), Op2(0x0F, 0x43), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVAE, ops2(.reg32, .rm32), Op2(0x0F, 0x43), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVAE, ops2(.reg64, .rm64), Op2(0x0F, 0x43), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVB, ops2(.reg16, .rm16), Op2(0x0F, 0x42), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVB, ops2(.reg32, .rm32), Op2(0x0F, 0x42), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVB, ops2(.reg64, .rm64), Op2(0x0F, 0x42), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVBE, ops2(.reg16, .rm16), Op2(0x0F, 0x46), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVBE, ops2(.reg32, .rm32), Op2(0x0F, 0x46), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVBE, ops2(.reg64, .rm64), Op2(0x0F, 0x46), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVC, ops2(.reg16, .rm16), Op2(0x0F, 0x42), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVC, ops2(.reg32, .rm32), Op2(0x0F, 0x42), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVC, ops2(.reg64, .rm64), Op2(0x0F, 0x42), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVE, ops2(.reg16, .rm16), Op2(0x0F, 0x44), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVE, ops2(.reg32, .rm32), Op2(0x0F, 0x44), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVE, ops2(.reg64, .rm64), Op2(0x0F, 0x44), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVG, ops2(.reg16, .rm16), Op2(0x0F, 0x4F), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVG, ops2(.reg32, .rm32), Op2(0x0F, 0x4F), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVG, ops2(.reg64, .rm64), Op2(0x0F, 0x4F), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVGE, ops2(.reg16, .rm16), Op2(0x0F, 0x4D), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVGE, ops2(.reg32, .rm32), Op2(0x0F, 0x4D), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVGE, ops2(.reg64, .rm64), Op2(0x0F, 0x4D), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVL, ops2(.reg16, .rm16), Op2(0x0F, 0x4C), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVL, ops2(.reg32, .rm32), Op2(0x0F, 0x4C), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVL, ops2(.reg64, .rm64), Op2(0x0F, 0x4C), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVLE, ops2(.reg16, .rm16), Op2(0x0F, 0x4E), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVLE, ops2(.reg32, .rm32), Op2(0x0F, 0x4E), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVLE, ops2(.reg64, .rm64), Op2(0x0F, 0x4E), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNA, ops2(.reg16, .rm16), Op2(0x0F, 0x46), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNA, ops2(.reg32, .rm32), Op2(0x0F, 0x46), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNA, ops2(.reg64, .rm64), Op2(0x0F, 0x46), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNAE, ops2(.reg16, .rm16), Op2(0x0F, 0x42), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNAE, ops2(.reg32, .rm32), Op2(0x0F, 0x42), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNAE, ops2(.reg64, .rm64), Op2(0x0F, 0x42), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNB, ops2(.reg16, .rm16), Op2(0x0F, 0x43), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNB, ops2(.reg32, .rm32), Op2(0x0F, 0x43), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNB, ops2(.reg64, .rm64), Op2(0x0F, 0x43), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNBE, ops2(.reg16, .rm16), Op2(0x0F, 0x47), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNBE, ops2(.reg32, .rm32), Op2(0x0F, 0x47), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNBE, ops2(.reg64, .rm64), Op2(0x0F, 0x47), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNC, ops2(.reg16, .rm16), Op2(0x0F, 0x43), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNC, ops2(.reg32, .rm32), Op2(0x0F, 0x43), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNC, ops2(.reg64, .rm64), Op2(0x0F, 0x43), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNE, ops2(.reg16, .rm16), Op2(0x0F, 0x45), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNE, ops2(.reg32, .rm32), Op2(0x0F, 0x45), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNE, ops2(.reg64, .rm64), Op2(0x0F, 0x45), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNG, ops2(.reg16, .rm16), Op2(0x0F, 0x4E), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNG, ops2(.reg32, .rm32), Op2(0x0F, 0x4E), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNG, ops2(.reg64, .rm64), Op2(0x0F, 0x4E), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNGE, ops2(.reg16, .rm16), Op2(0x0F, 0x4C), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNGE, ops2(.reg32, .rm32), Op2(0x0F, 0x4C), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNGE, ops2(.reg64, .rm64), Op2(0x0F, 0x4C), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNL, ops2(.reg16, .rm16), Op2(0x0F, 0x4D), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNL, ops2(.reg32, .rm32), Op2(0x0F, 0x4D), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNL, ops2(.reg64, .rm64), Op2(0x0F, 0x4D), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNLE, ops2(.reg16, .rm16), Op2(0x0F, 0x4F), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNLE, ops2(.reg32, .rm32), Op2(0x0F, 0x4F), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNLE, ops2(.reg64, .rm64), Op2(0x0F, 0x4F), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNO, ops2(.reg16, .rm16), Op2(0x0F, 0x41), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNO, ops2(.reg32, .rm32), Op2(0x0F, 0x41), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNO, ops2(.reg64, .rm64), Op2(0x0F, 0x41), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNP, ops2(.reg16, .rm16), Op2(0x0F, 0x4B), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNP, ops2(.reg32, .rm32), Op2(0x0F, 0x4B), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNP, ops2(.reg64, .rm64), Op2(0x0F, 0x4B), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNS, ops2(.reg16, .rm16), Op2(0x0F, 0x49), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNS, ops2(.reg32, .rm32), Op2(0x0F, 0x49), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNS, ops2(.reg64, .rm64), Op2(0x0F, 0x49), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVNZ, ops2(.reg16, .rm16), Op2(0x0F, 0x45), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVNZ, ops2(.reg32, .rm32), Op2(0x0F, 0x45), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVNZ, ops2(.reg64, .rm64), Op2(0x0F, 0x45), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVO, ops2(.reg16, .rm16), Op2(0x0F, 0x40), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVO, ops2(.reg32, .rm32), Op2(0x0F, 0x40), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVO, ops2(.reg64, .rm64), Op2(0x0F, 0x40), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVP, ops2(.reg16, .rm16), Op2(0x0F, 0x4A), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVP, ops2(.reg32, .rm32), Op2(0x0F, 0x4A), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVP, ops2(.reg64, .rm64), Op2(0x0F, 0x4A), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVPE, ops2(.reg16, .rm16), Op2(0x0F, 0x4A), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVPE, ops2(.reg32, .rm32), Op2(0x0F, 0x4A), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVPE, ops2(.reg64, .rm64), Op2(0x0F, 0x4A), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVPO, ops2(.reg16, .rm16), Op2(0x0F, 0x4B), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVPO, ops2(.reg32, .rm32), Op2(0x0F, 0x4B), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVPO, ops2(.reg64, .rm64), Op2(0x0F, 0x4B), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVS, ops2(.reg16, .rm16), Op2(0x0F, 0x48), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVS, ops2(.reg32, .rm32), Op2(0x0F, 0x48), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVS, ops2(.reg64, .rm64), Op2(0x0F, 0x48), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    //
    instr(.CMOVZ, ops2(.reg16, .rm16), Op2(0x0F, 0x44), .RM, .Op16, .{cpu.CMOV}),
    instr(.CMOVZ, ops2(.reg32, .rm32), Op2(0x0F, 0x44), .RM, .Op32, .{cpu.CMOV}),
    instr(.CMOVZ, ops2(.reg64, .rm64), Op2(0x0F, 0x44), .RM, .REX_W, .{ cpu.CMOV, x86_64 }),
    // UD (first documented, but actually available since 80186)
    instr(.UD0, ops0(), Op2(0x0F, 0xFF), .ZO, .ZO, .{ _186_Legacy, No64 }),
    instr(.UD0, ops2(.reg16, .rm16), Op2(0x0F, 0xFF), .RM, .Op16, .{_186}),
    instr(.UD0, ops2(.reg32, .rm32), Op2(0x0F, 0xFF), .RM, .Op32, .{_186}),
    instr(.UD0, ops2(.reg64, .rm64), Op2(0x0F, 0xFF), .RM, .REX_W, .{x86_64}),
    //
    instr(.UD1, ops2(.reg16, .rm16), Op2(0x0F, 0xB9), .RM, .Op16, .{_186}),
    instr(.UD1, ops2(.reg32, .rm32), Op2(0x0F, 0xB9), .RM, .Op32, .{_186}),
    instr(.UD1, ops2(.reg64, .rm64), Op2(0x0F, 0xB9), .RM, .REX_W, .{x86_64}),
    //
    instr(.UD2, ops0(), Op2(0x0F, 0x0B), .ZO, .ZO, .{P6}),

    //
    // Pentium II
    //
    instr(.SYSENTER, ops0(), Op2(0x0F, 0x34), .ZO, .ZO, .{ cpu.SEP, cpu.Amd, No64 }),
    instr(.SYSENTER, ops0(), Op2(0x0F, 0x34), .ZO, .ZO, .{ cpu.SEP, cpu.Intel }),
    instr(.SYSENTER, ops0(), Op2(0x0F, 0x34), .ZO, .ZO, .{ cpu.SEP, No64 }),
    //
    instr(.SYSEXIT, ops0(), Op2(0x0F, 0x35), .ZO, .ZO, .{ cpu.SEP, cpu.Amd, No64 }),
    instr(.SYSEXIT, ops0(), Op2(0x0F, 0x35), .ZO, .ZO, .{ cpu.SEP, cpu.Intel }),
    instr(.SYSEXIT, ops0(), Op2(0x0F, 0x35), .ZO, .ZO, .{ cpu.SEP, No64 }),
    //
    instr(.SYSEXITQ, ops0(), Op2(0x0F, 0x35), .ZO, .REX_W, .{ cpu.SEP, x86_64, cpu.Intel, No32 }),

    //
    // x86-64
    //
    instr(.RDTSCP, ops0(), Op3(0x0F, 0x01, 0xF9), .ZO, .ZO, .{x86_64}),
    instr(.SWAPGS, ops0(), Op3(0x0F, 0x01, 0xF8), .ZO, .ZO, .{x86_64}),

    //
    // bit manipulation (ABM / BMI1 / BMI2)
    //
    // LZCNT
    instr(.LZCNT, ops2(.reg16, .rm16), preOp2(._F3, 0x0F, 0xBD), .RM, .Op16, .{cpu.LZCNT}),
    instr(.LZCNT, ops2(.reg32, .rm32), preOp2(._F3, 0x0F, 0xBD), .RM, .Op32, .{cpu.LZCNT}),
    instr(.LZCNT, ops2(.reg64, .rm64), preOp2(._F3, 0x0F, 0xBD), .RM, .REX_W, .{ cpu.LZCNT, x86_64 }),
    // LZCNT
    instr(.POPCNT, ops2(.reg16, .rm16), preOp2(._F3, 0x0F, 0xB8), .RM, .Op16, .{cpu.POPCNT}),
    instr(.POPCNT, ops2(.reg32, .rm32), preOp2(._F3, 0x0F, 0xB8), .RM, .Op32, .{cpu.POPCNT}),
    instr(.POPCNT, ops2(.reg64, .rm64), preOp2(._F3, 0x0F, 0xB8), .RM, .REX_W, .{ cpu.POPCNT, x86_64 }),
    // ANDN
    instr(.ANDN, ops3(.reg32, .reg32, .rm32), vex(.LZ, ._NP, ._0F38, .W0, 0xF2), .RVM, .ZO, .{cpu.BMI1}),
    instr(.ANDN, ops3(.reg64, .reg64, .rm64), vex(.LZ, ._NP, ._0F38, .W1, 0xF2), .RVM, .ZO, .{cpu.BMI1}),
    // BEXTR
    instr(.BEXTR, ops3(.reg32, .rm32, .reg32), vex(.LZ, ._NP, ._0F38, .W0, 0xF7), .RMV, .ZO, .{cpu.BMI1}),
    instr(.BEXTR, ops3(.reg64, .rm64, .reg64), vex(.LZ, ._NP, ._0F38, .W1, 0xF7), .RMV, .ZO, .{cpu.BMI1}),
    instr(.BEXTR, ops3(.reg32, .rm32, .imm32), xop(.LZ, ._NP, ._0Ah, .W0, 0x10), .vRMI, .ZO, .{cpu.TBM}),
    instr(.BEXTR, ops3(.reg64, .rm64, .imm32), xop(.LZ, ._NP, ._0Ah, .W1, 0x10), .vRMI, .ZO, .{cpu.TBM}),
    // BLSI
    instr(.BLSI, ops2(.reg32, .rm32), vexr(.LZ, ._NP, ._0F38, .W0, 0xF3, 3), .VM, .ZO, .{cpu.BMI1}),
    instr(.BLSI, ops2(.reg64, .rm64), vexr(.LZ, ._NP, ._0F38, .W1, 0xF3, 3), .VM, .ZO, .{cpu.BMI1}),
    // BLSMSK
    instr(.BLSMSK, ops2(.reg32, .rm32), vexr(.LZ, ._NP, ._0F38, .W0, 0xF3, 2), .VM, .ZO, .{cpu.BMI1}),
    instr(.BLSMSK, ops2(.reg64, .rm64), vexr(.LZ, ._NP, ._0F38, .W1, 0xF3, 2), .VM, .ZO, .{cpu.BMI1}),
    // BLSR
    instr(.BLSR, ops2(.reg32, .rm32), vexr(.LZ, ._NP, ._0F38, .W0, 0xF3, 1), .VM, .ZO, .{cpu.BMI1}),
    instr(.BLSR, ops2(.reg64, .rm64), vexr(.LZ, ._NP, ._0F38, .W1, 0xF3, 1), .VM, .ZO, .{cpu.BMI1}),
    // BZHI
    instr(.BZHI, ops3(.reg32, .rm32, .reg32), vex(.LZ, ._NP, ._0F38, .W0, 0xF5), .RMV, .ZO, .{cpu.BMI2}),
    instr(.BZHI, ops3(.reg64, .rm64, .reg64), vex(.LZ, ._NP, ._0F38, .W1, 0xF5), .RMV, .ZO, .{cpu.BMI2}),
    // MULX
    instr(.MULX, ops3(.reg32, .reg32, .rm32), vex(.LZ, ._F2, ._0F38, .W0, 0xF6), .RVM, .ZO, .{cpu.BMI2}),
    instr(.MULX, ops3(.reg64, .reg64, .rm64), vex(.LZ, ._F2, ._0F38, .W1, 0xF6), .RVM, .ZO, .{cpu.BMI2}),
    // PDEP
    instr(.PDEP, ops3(.reg32, .reg32, .rm32), vex(.LZ, ._F2, ._0F38, .W0, 0xF5), .RVM, .ZO, .{cpu.BMI2}),
    instr(.PDEP, ops3(.reg64, .reg64, .rm64), vex(.LZ, ._F2, ._0F38, .W1, 0xF5), .RVM, .ZO, .{cpu.BMI2}),
    // PEXT
    instr(.PEXT, ops3(.reg32, .reg32, .rm32), vex(.LZ, ._F3, ._0F38, .W0, 0xF5), .RVM, .ZO, .{cpu.BMI2}),
    instr(.PEXT, ops3(.reg64, .reg64, .rm64), vex(.LZ, ._F3, ._0F38, .W1, 0xF5), .RVM, .ZO, .{cpu.BMI2}),
    // RORX
    instr(.RORX, ops3(.reg32, .rm32, .imm8), vex(.LZ, ._F2, ._0F3A, .W0, 0xF0), .vRMI, .ZO, .{cpu.BMI2}),
    instr(.RORX, ops3(.reg64, .rm64, .imm8), vex(.LZ, ._F2, ._0F3A, .W1, 0xF0), .vRMI, .ZO, .{cpu.BMI2}),
    // SARX
    instr(.SARX, ops3(.reg32, .rm32, .reg32), vex(.LZ, ._F3, ._0F38, .W0, 0xF7), .RMV, .ZO, .{cpu.BMI2}),
    instr(.SARX, ops3(.reg64, .rm64, .reg64), vex(.LZ, ._F3, ._0F38, .W1, 0xF7), .RMV, .ZO, .{cpu.BMI2}),
    // SHLX
    instr(.SHLX, ops3(.reg32, .rm32, .reg32), vex(.LZ, ._66, ._0F38, .W0, 0xF7), .RMV, .ZO, .{cpu.BMI2}),
    instr(.SHLX, ops3(.reg64, .rm64, .reg64), vex(.LZ, ._66, ._0F38, .W1, 0xF7), .RMV, .ZO, .{cpu.BMI2}),
    // SHRX
    instr(.SHRX, ops3(.reg32, .rm32, .reg32), vex(.LZ, ._F2, ._0F38, .W0, 0xF7), .RMV, .ZO, .{cpu.BMI2}),
    instr(.SHRX, ops3(.reg64, .rm64, .reg64), vex(.LZ, ._F2, ._0F38, .W1, 0xF7), .RMV, .ZO, .{cpu.BMI2}),
    // TZCNT
    instr(.TZCNT, ops2(.reg16, .rm16), preOp2(._F3, 0x0F, 0xBC), .RM, .Op16, .{cpu.BMI1}),
    instr(.TZCNT, ops2(.reg32, .rm32), preOp2(._F3, 0x0F, 0xBC), .RM, .Op32, .{cpu.BMI1}),
    instr(.TZCNT, ops2(.reg64, .rm64), preOp2(._F3, 0x0F, 0xBC), .RM, .REX_W, .{ cpu.BMI1, x86_64 }),

    //
    // XOP opcodes
    //
    //
    // TBM
    //
    // BEXTR
    // see above .BEXTR
    // BLCFILL
    instr(.BLCFILL, ops2(.reg32, .rm32), xopr(.LZ, ._NP, ._09h, .W0, 0x01, 1), .VM, .ZO, .{cpu.TBM}),
    instr(.BLCFILL, ops2(.reg64, .rm64), xopr(.LZ, ._NP, ._09h, .W1, 0x01, 1), .VM, .ZO, .{cpu.TBM}),
    // BLCI
    instr(.BLCI, ops2(.reg32, .rm32), xopr(.LZ, ._NP, ._09h, .W0, 0x02, 6), .VM, .ZO, .{cpu.TBM}),
    instr(.BLCI, ops2(.reg64, .rm64), xopr(.LZ, ._NP, ._09h, .W1, 0x02, 6), .VM, .ZO, .{cpu.TBM}),
    // BLCIC
    instr(.BLCIC, ops2(.reg32, .rm32), xopr(.LZ, ._NP, ._09h, .W0, 0x01, 5), .VM, .ZO, .{cpu.TBM}),
    instr(.BLCIC, ops2(.reg64, .rm64), xopr(.LZ, ._NP, ._09h, .W1, 0x01, 5), .VM, .ZO, .{cpu.TBM}),
    // BLCMSK
    instr(.BLCMSK, ops2(.reg32, .rm32), xopr(.LZ, ._NP, ._09h, .W0, 0x02, 1), .VM, .ZO, .{cpu.TBM}),
    instr(.BLCMSK, ops2(.reg64, .rm64), xopr(.LZ, ._NP, ._09h, .W1, 0x02, 1), .VM, .ZO, .{cpu.TBM}),
    // BLCS
    instr(.BLCS, ops2(.reg32, .rm32), xopr(.LZ, ._NP, ._09h, .W0, 0x01, 3), .VM, .ZO, .{cpu.TBM}),
    instr(.BLCS, ops2(.reg64, .rm64), xopr(.LZ, ._NP, ._09h, .W1, 0x01, 3), .VM, .ZO, .{cpu.TBM}),
    // BLSFILL
    instr(.BLSFILL, ops2(.reg32, .rm32), xopr(.LZ, ._NP, ._09h, .W0, 0x01, 2), .VM, .ZO, .{cpu.TBM}),
    instr(.BLSFILL, ops2(.reg64, .rm64), xopr(.LZ, ._NP, ._09h, .W1, 0x01, 2), .VM, .ZO, .{cpu.TBM}),
    // BLSIC
    instr(.BLSIC, ops2(.reg32, .rm32), xopr(.LZ, ._NP, ._09h, .W0, 0x01, 6), .VM, .ZO, .{cpu.TBM}),
    instr(.BLSIC, ops2(.reg64, .rm64), xopr(.LZ, ._NP, ._09h, .W1, 0x01, 6), .VM, .ZO, .{cpu.TBM}),
    // T1MSKC
    instr(.T1MSKC, ops2(.reg32, .rm32), xopr(.LZ, ._NP, ._09h, .W0, 0x01, 7), .VM, .ZO, .{cpu.TBM}),
    instr(.T1MSKC, ops2(.reg64, .rm64), xopr(.LZ, ._NP, ._09h, .W1, 0x01, 7), .VM, .ZO, .{cpu.TBM}),
    // TZMSK
    instr(.TZMSK, ops2(.reg32, .rm32), xopr(.LZ, ._NP, ._09h, .W0, 0x01, 4), .VM, .ZO, .{cpu.TBM}),
    instr(.TZMSK, ops2(.reg64, .rm64), xopr(.LZ, ._NP, ._09h, .W1, 0x01, 4), .VM, .ZO, .{cpu.TBM}),
    //
    // LWP
    //
    // LLWPCB
    instr(.LLWPCB, ops1(.reg32), xopr(.LZ, ._NP, ._09h, .W0, 0x12, 0), .vM, .ZO, .{cpu.LWP}),
    instr(.LLWPCB, ops1(.reg64), xopr(.LZ, ._NP, ._09h, .W1, 0x12, 0), .vM, .ZO, .{cpu.LWP}),
    // LWPINS
    instr(.LWPINS, ops3(.reg32, .rm32, .imm32), xopr(.LZ, ._NP, ._0Ah, .W0, 0x12, 0), .VMI, .ZO, .{cpu.LWP}),
    instr(.LWPINS, ops3(.reg64, .rm32, .imm32), xopr(.LZ, ._NP, ._0Ah, .W1, 0x12, 0), .VMI, .ZO, .{cpu.LWP}),
    // LWPVAL
    instr(.LWPVAL, ops3(.reg32, .rm32, .imm32), xopr(.LZ, ._NP, ._0Ah, .W0, 0x12, 1), .VMI, .ZO, .{cpu.LWP}),
    instr(.LWPVAL, ops3(.reg64, .rm32, .imm32), xopr(.LZ, ._NP, ._0Ah, .W1, 0x12, 1), .VMI, .ZO, .{cpu.LWP}),
    // SLWPCB
    instr(.SLWPCB, ops1(.reg32), xopr(.LZ, ._NP, ._09h, .W0, 0x12, 1), .vM, .ZO, .{cpu.LWP}),
    instr(.SLWPCB, ops1(.reg64), xopr(.LZ, ._NP, ._09h, .W1, 0x12, 1), .vM, .ZO, .{cpu.LWP}),

    //
    // XOP vector
    //
    // VFRCZPD
    vec(.VFRCZPD, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0x81), .vRM, .{cpu.XOP}),
    vec(.VFRCZPD, ops2(.ymml, .ymml_m256), xop(.L256, ._NP, ._09h, .W0, 0x81), .vRM, .{cpu.XOP}),
    // VFRCZPS
    vec(.VFRCZPS, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0x80), .vRM, .{cpu.XOP}),
    vec(.VFRCZPS, ops2(.ymml, .ymml_m256), xop(.L256, ._NP, ._09h, .W0, 0x80), .vRM, .{cpu.XOP}),
    // VFRCZSD
    vec(.VFRCZSD, ops2(.xmml, .xmml_m64), xop(.LZ, ._NP, ._09h, .W0, 0x83), .vRM, .{cpu.XOP}),
    // VFRCZSS
    vec(.VFRCZSS, ops2(.xmml, .xmml_m32), xop(.LZ, ._NP, ._09h, .W0, 0x82), .vRM, .{cpu.XOP}),
    // VPCMOV
    vec(.VPCMOV, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0xA2), .RVMR, .{cpu.XOP}),
    vec(.VPCMOV, ops4(.ymml, .ymml, .ymml_m256, .ymml), xop(.L256, ._NP, ._08h, .W0, 0xA2), .RVMR, .{cpu.XOP}),
    vec(.VPCMOV, ops4(.xmml, .xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._08h, .W1, 0xA2), .RVRM, .{cpu.XOP}),
    vec(.VPCMOV, ops4(.ymml, .ymml, .ymml, .ymml_m256), xop(.L256, ._NP, ._08h, .W1, 0xA2), .RVRM, .{cpu.XOP}),
    // VPCOMB / VPCOMW / VPCOMD / VPCOMQ
    vec(.VPCOMB, ops4(.xmml, .xmml, .xmml_m128, .imm8), xop(.LZ, ._NP, ._08h, .W0, 0xCC), .RVMI, .{cpu.XOP}),
    vec(.VPCOMW, ops4(.xmml, .xmml, .xmml_m128, .imm8), xop(.LZ, ._NP, ._08h, .W0, 0xCD), .RVMI, .{cpu.XOP}),
    vec(.VPCOMD, ops4(.xmml, .xmml, .xmml_m128, .imm8), xop(.LZ, ._NP, ._08h, .W0, 0xCE), .RVMI, .{cpu.XOP}),
    vec(.VPCOMQ, ops4(.xmml, .xmml, .xmml_m128, .imm8), xop(.LZ, ._NP, ._08h, .W0, 0xCF), .RVMI, .{cpu.XOP}),
    // VPCOMUB / VPCOMUW / VPCOMUD / VPCOMUQ
    vec(.VPCOMUB, ops4(.xmml, .xmml, .xmml_m128, .imm8), xop(.LZ, ._NP, ._08h, .W0, 0xEC), .RVMI, .{cpu.XOP}),
    vec(.VPCOMUW, ops4(.xmml, .xmml, .xmml_m128, .imm8), xop(.LZ, ._NP, ._08h, .W0, 0xED), .RVMI, .{cpu.XOP}),
    vec(.VPCOMUD, ops4(.xmml, .xmml, .xmml_m128, .imm8), xop(.LZ, ._NP, ._08h, .W0, 0xEE), .RVMI, .{cpu.XOP}),
    vec(.VPCOMUQ, ops4(.xmml, .xmml, .xmml_m128, .imm8), xop(.LZ, ._NP, ._08h, .W0, 0xEF), .RVMI, .{cpu.XOP}),
    // VPERMIL2PD
    vec(.VPERMIL2PD, ops5(.xmml, .xmml, .xmml_m128, .xmml, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x49), .RVMRI, .{cpu.XOP}),
    vec(.VPERMIL2PD, ops5(.xmml, .xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .W1, 0x49), .RVRMI, .{cpu.XOP}),
    vec(.VPERMIL2PD, ops5(.ymml, .ymml, .ymml_m256, .ymml, .imm8), vex(.L256, ._66, ._0F3A, .W0, 0x49), .RVMRI, .{cpu.XOP}),
    vec(.VPERMIL2PD, ops5(.ymml, .ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .W1, 0x49), .RVRMI, .{cpu.XOP}),
    // VPERMIL2PS
    vec(.VPERMIL2PS, ops5(.xmml, .xmml, .xmml_m128, .xmml, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x48), .RVMRI, .{cpu.XOP}),
    vec(.VPERMIL2PS, ops5(.xmml, .xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .W1, 0x48), .RVRMI, .{cpu.XOP}),
    vec(.VPERMIL2PS, ops5(.ymml, .ymml, .ymml_m256, .ymml, .imm8), vex(.L256, ._66, ._0F3A, .W0, 0x48), .RVMRI, .{cpu.XOP}),
    vec(.VPERMIL2PS, ops5(.ymml, .ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .W1, 0x48), .RVRMI, .{cpu.XOP}),
    // VPHADDBD / VPHADDBW / VPHADDBQ
    vec(.VPHADDBW, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xC1), .vRM, .{cpu.XOP}),
    vec(.VPHADDBD, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xC2), .vRM, .{cpu.XOP}),
    vec(.VPHADDBQ, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xC3), .vRM, .{cpu.XOP}),
    // VPHADDWD / VPHADDWQ
    vec(.VPHADDWD, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xC6), .vRM, .{cpu.XOP}),
    vec(.VPHADDWQ, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xC7), .vRM, .{cpu.XOP}),
    // VPHADDDQ
    vec(.VPHADDDQ, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xCB), .vRM, .{cpu.XOP}),
    // VPHADDUBD / VPHADDUBW / VPHADDUBQ
    vec(.VPHADDUBW, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xD1), .vRM, .{cpu.XOP}),
    vec(.VPHADDUBD, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xD2), .vRM, .{cpu.XOP}),
    vec(.VPHADDUBQ, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xD3), .vRM, .{cpu.XOP}),
    // VPHADDUWD / VPHADDUWQ
    vec(.VPHADDUWD, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xD6), .vRM, .{cpu.XOP}),
    vec(.VPHADDUWQ, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xD7), .vRM, .{cpu.XOP}),
    // VPHADDUDQ
    vec(.VPHADDUDQ, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xDB), .vRM, .{cpu.XOP}),
    // VPHSUBBW
    vec(.VPHSUBBW, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xE1), .vRM, .{cpu.XOP}),
    // VPHSUBDQ
    vec(.VPHSUBDQ, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xE3), .vRM, .{cpu.XOP}),
    // VPHSUBWD
    vec(.VPHSUBWD, ops2(.xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W0, 0xE2), .vRM, .{cpu.XOP}),
    // VPMACSDD
    vec(.VPMACSDD, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0x9E), .RVMR, .{cpu.XOP}),
    // VPMACSDQH
    vec(.VPMACSDQH, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0x9F), .RVMR, .{cpu.XOP}),
    // VPMACSDQL
    vec(.VPMACSDQL, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0x97), .RVMR, .{cpu.XOP}),
    // VPMACSSDD
    vec(.VPMACSSDD, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0x8E), .RVMR, .{cpu.XOP}),
    // VPMACSSDQH
    vec(.VPMACSSDQH, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0x8F), .RVMR, .{cpu.XOP}),
    // VPMACSSDQL
    vec(.VPMACSSDQL, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0x87), .RVMR, .{cpu.XOP}),
    // VPMACSSWD
    vec(.VPMACSSWD, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0x86), .RVMR, .{cpu.XOP}),
    // VPMACSSWW
    vec(.VPMACSSWW, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0x85), .RVMR, .{cpu.XOP}),
    // VPMACSWD
    vec(.VPMACSWD, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0x96), .RVMR, .{cpu.XOP}),
    // VPMACSWW
    vec(.VPMACSWW, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0x95), .RVMR, .{cpu.XOP}),
    // VPMADCSSWD
    vec(.VPMADCSSWD, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0xA6), .RVMR, .{cpu.XOP}),
    // VPMADCSWD
    vec(.VPMADCSWD, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0xB6), .RVMR, .{cpu.XOP}),
    // VPPERM
    vec(.VPPERM, ops4(.xmml, .xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._08h, .W0, 0xA3), .RVMR, .{cpu.XOP}),
    vec(.VPPERM, ops4(.xmml, .xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._08h, .W1, 0xA3), .RVRM, .{cpu.XOP}),
    // VPROTB / VPROTW / VPROTD / VPROTQ
    // VPROTB
    vec(.VPROTB, ops3(.xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._09h, .W0, 0x90), .RMV, .{cpu.XOP}),
    vec(.VPROTB, ops3(.xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W1, 0x90), .RVM, .{cpu.XOP}),
    vec(.VPROTB, ops3(.xmml, .xmml_m128, .imm8), xop(.L128, ._NP, ._08h, .W0, 0xC0), .vRMI, .{cpu.XOP}),
    // VPROTW
    vec(.VPROTW, ops3(.xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._09h, .W0, 0x91), .RMV, .{cpu.XOP}),
    vec(.VPROTW, ops3(.xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W1, 0x91), .RVM, .{cpu.XOP}),
    vec(.VPROTW, ops3(.xmml, .xmml_m128, .imm8), xop(.L128, ._NP, ._08h, .W0, 0xC1), .vRMI, .{cpu.XOP}),
    // VPROTD
    vec(.VPROTD, ops3(.xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._09h, .W0, 0x92), .RMV, .{cpu.XOP}),
    vec(.VPROTD, ops3(.xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W1, 0x92), .RVM, .{cpu.XOP}),
    vec(.VPROTD, ops3(.xmml, .xmml_m128, .imm8), xop(.L128, ._NP, ._08h, .W0, 0xC2), .vRMI, .{cpu.XOP}),
    // VPROTQ
    vec(.VPROTQ, ops3(.xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._09h, .W0, 0x93), .RMV, .{cpu.XOP}),
    vec(.VPROTQ, ops3(.xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W1, 0x93), .RVM, .{cpu.XOP}),
    vec(.VPROTQ, ops3(.xmml, .xmml_m128, .imm8), xop(.L128, ._NP, ._08h, .W0, 0xC3), .vRMI, .{cpu.XOP}),
    // VPSHAB / VPSHAW / VPSHAD / VPSHAQ
    // VPSHAB
    vec(.VPSHAB, ops3(.xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._09h, .W0, 0x98), .RMV, .{cpu.XOP}),
    vec(.VPSHAB, ops3(.xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W1, 0x98), .RVM, .{cpu.XOP}),
    // VPSHAW
    vec(.VPSHAW, ops3(.xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._09h, .W0, 0x99), .RMV, .{cpu.XOP}),
    vec(.VPSHAW, ops3(.xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W1, 0x99), .RVM, .{cpu.XOP}),
    // VPSHAD
    vec(.VPSHAD, ops3(.xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._09h, .W0, 0x9A), .RMV, .{cpu.XOP}),
    vec(.VPSHAD, ops3(.xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W1, 0x9A), .RVM, .{cpu.XOP}),
    // VPSHAQ
    vec(.VPSHAQ, ops3(.xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._09h, .W0, 0x9B), .RMV, .{cpu.XOP}),
    vec(.VPSHAQ, ops3(.xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W1, 0x9B), .RVM, .{cpu.XOP}),
    // VPSHLB / VPSHLW / VPSHLD / VPSHLQ
    // VPSHLB
    vec(.VPSHLB, ops3(.xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._09h, .W0, 0x94), .RMV, .{cpu.XOP}),
    vec(.VPSHLB, ops3(.xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W1, 0x94), .RVM, .{cpu.XOP}),
    // VPSHLW
    vec(.VPSHLW, ops3(.xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._09h, .W0, 0x95), .RMV, .{cpu.XOP}),
    vec(.VPSHLW, ops3(.xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W1, 0x95), .RVM, .{cpu.XOP}),
    // VPSHLD
    vec(.VPSHLD, ops3(.xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._09h, .W0, 0x96), .RMV, .{cpu.XOP}),
    vec(.VPSHLD, ops3(.xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W1, 0x96), .RVM, .{cpu.XOP}),
    // VPSHLQ
    vec(.VPSHLQ, ops3(.xmml, .xmml_m128, .xmml), xop(.L128, ._NP, ._09h, .W0, 0x97), .RMV, .{cpu.XOP}),
    vec(.VPSHLQ, ops3(.xmml, .xmml, .xmml_m128), xop(.L128, ._NP, ._09h, .W1, 0x97), .RVM, .{cpu.XOP}),

    //
    // FMA4 (Fused Multiply Add 4 operands)
    //
    // VFMADDPD
    vec(.VFMADDPD, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x69), .RVMR, .{cpu.FMA4}),
    vec(.VFMADDPD, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x69), .RVMR, .{cpu.FMA4}),
    vec(.VFMADDPD, ops4(.xmml, .xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F3A, .W1, 0x69), .RVRM, .{cpu.FMA4}),
    vec(.VFMADDPD, ops4(.ymml, .ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F3A, .W1, 0x69), .RVRM, .{cpu.FMA4}),
    // VFMADDPS
    vec(.VFMADDPS, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x68), .RVMR, .{cpu.FMA4}),
    vec(.VFMADDPS, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x68), .RVMR, .{cpu.FMA4}),
    vec(.VFMADDPS, ops4(.xmml, .xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F3A, .W1, 0x68), .RVRM, .{cpu.FMA4}),
    vec(.VFMADDPS, ops4(.ymml, .ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F3A, .W1, 0x68), .RVRM, .{cpu.FMA4}),
    // VFMADDSD
    vec(.VFMADDSD, ops4(.xmml, .xmml, .xmml_m64, .xmml), vex(.LIG, ._66, ._0F3A, .W0, 0x6B), .RVMR, .{cpu.FMA4}),
    vec(.VFMADDSD, ops4(.xmml, .xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F3A, .W1, 0x6B), .RVRM, .{cpu.FMA4}),
    // VFMADDSS
    vec(.VFMADDSS, ops4(.xmml, .xmml, .xmml_m32, .xmml), vex(.LIG, ._66, ._0F3A, .W0, 0x6A), .RVMR, .{cpu.FMA4}),
    vec(.VFMADDSS, ops4(.xmml, .xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F3A, .W1, 0x6A), .RVRM, .{cpu.FMA4}),
    // VFMADDSUBPD
    vec(.VFMADDSUBPD, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x5D), .RVMR, .{cpu.FMA4}),
    vec(.VFMADDSUBPD, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x5D), .RVMR, .{cpu.FMA4}),
    vec(.VFMADDSUBPD, ops4(.xmml, .xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F3A, .W1, 0x5D), .RVRM, .{cpu.FMA4}),
    vec(.VFMADDSUBPD, ops4(.ymml, .ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F3A, .W1, 0x5D), .RVRM, .{cpu.FMA4}),
    // VFMADDSUBPS
    vec(.VFMADDSUBPS, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x5C), .RVMR, .{cpu.FMA4}),
    vec(.VFMADDSUBPS, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x5C), .RVMR, .{cpu.FMA4}),
    vec(.VFMADDSUBPS, ops4(.xmml, .xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F3A, .W1, 0x5C), .RVRM, .{cpu.FMA4}),
    vec(.VFMADDSUBPS, ops4(.ymml, .ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F3A, .W1, 0x5C), .RVRM, .{cpu.FMA4}),
    // VFMSUBADDPD
    vec(.VFMSUBADDPD, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x5F), .RVMR, .{cpu.FMA4}),
    vec(.VFMSUBADDPD, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x5F), .RVMR, .{cpu.FMA4}),
    vec(.VFMSUBADDPD, ops4(.xmml, .xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F3A, .W1, 0x5F), .RVRM, .{cpu.FMA4}),
    vec(.VFMSUBADDPD, ops4(.ymml, .ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F3A, .W1, 0x5F), .RVRM, .{cpu.FMA4}),
    // VFMSUBADDPS
    vec(.VFMSUBADDPS, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x5E), .RVMR, .{cpu.FMA4}),
    vec(.VFMSUBADDPS, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x5E), .RVMR, .{cpu.FMA4}),
    vec(.VFMSUBADDPS, ops4(.xmml, .xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F3A, .W1, 0x5E), .RVRM, .{cpu.FMA4}),
    vec(.VFMSUBADDPS, ops4(.ymml, .ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F3A, .W1, 0x5E), .RVRM, .{cpu.FMA4}),
    // VFMSUBPD
    vec(.VFMSUBPD, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x6D), .RVMR, .{cpu.FMA4}),
    vec(.VFMSUBPD, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x6D), .RVMR, .{cpu.FMA4}),
    vec(.VFMSUBPD, ops4(.xmml, .xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F3A, .W1, 0x6D), .RVRM, .{cpu.FMA4}),
    vec(.VFMSUBPD, ops4(.ymml, .ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F3A, .W1, 0x6D), .RVRM, .{cpu.FMA4}),
    // VFMSUBPS
    vec(.VFMSUBPS, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x6C), .RVMR, .{cpu.FMA4}),
    vec(.VFMSUBPS, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x6C), .RVMR, .{cpu.FMA4}),
    vec(.VFMSUBPS, ops4(.xmml, .xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F3A, .W1, 0x6C), .RVRM, .{cpu.FMA4}),
    vec(.VFMSUBPS, ops4(.ymml, .ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F3A, .W1, 0x6C), .RVRM, .{cpu.FMA4}),
    // VFMSUBSD
    vec(.VFMSUBSD, ops4(.xmml, .xmml, .xmml_m64, .xmml), vex(.LIG, ._66, ._0F3A, .W0, 0x6F), .RVMR, .{cpu.FMA4}),
    vec(.VFMSUBSD, ops4(.xmml, .xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F3A, .W1, 0x6F), .RVRM, .{cpu.FMA4}),
    // VFMSUBSS
    vec(.VFMSUBSS, ops4(.xmml, .xmml, .xmml_m32, .xmml), vex(.LIG, ._66, ._0F3A, .W0, 0x6E), .RVMR, .{cpu.FMA4}),
    vec(.VFMSUBSS, ops4(.xmml, .xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F3A, .W1, 0x6E), .RVRM, .{cpu.FMA4}),
    // VFNMADDPD
    vec(.VFNMADDPD, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x79), .RVMR, .{cpu.FMA4}),
    vec(.VFNMADDPD, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x79), .RVMR, .{cpu.FMA4}),
    vec(.VFNMADDPD, ops4(.xmml, .xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F3A, .W1, 0x79), .RVRM, .{cpu.FMA4}),
    vec(.VFNMADDPD, ops4(.ymml, .ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F3A, .W1, 0x79), .RVRM, .{cpu.FMA4}),
    // VFNMADDPS
    vec(.VFNMADDPS, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x78), .RVMR, .{cpu.FMA4}),
    vec(.VFNMADDPS, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x78), .RVMR, .{cpu.FMA4}),
    vec(.VFNMADDPS, ops4(.xmml, .xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F3A, .W1, 0x78), .RVRM, .{cpu.FMA4}),
    vec(.VFNMADDPS, ops4(.ymml, .ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F3A, .W1, 0x78), .RVRM, .{cpu.FMA4}),
    // VFNMADDSD
    vec(.VFNMADDSD, ops4(.xmml, .xmml, .xmml_m64, .xmml), vex(.LIG, ._66, ._0F3A, .W0, 0x7B), .RVMR, .{cpu.FMA4}),
    vec(.VFNMADDSD, ops4(.xmml, .xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F3A, .W1, 0x7B), .RVRM, .{cpu.FMA4}),
    // VFNMADDSS
    vec(.VFNMADDSS, ops4(.xmml, .xmml, .xmml_m32, .xmml), vex(.LIG, ._66, ._0F3A, .W0, 0x7A), .RVMR, .{cpu.FMA4}),
    vec(.VFNMADDSS, ops4(.xmml, .xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F3A, .W1, 0x7A), .RVRM, .{cpu.FMA4}),
    // VFNMSUBPD
    vec(.VFNMSUBPD, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x7D), .RVMR, .{cpu.FMA4}),
    vec(.VFNMSUBPD, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x7D), .RVMR, .{cpu.FMA4}),
    vec(.VFNMSUBPD, ops4(.xmml, .xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F3A, .W1, 0x7D), .RVRM, .{cpu.FMA4}),
    vec(.VFNMSUBPD, ops4(.ymml, .ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F3A, .W1, 0x7D), .RVRM, .{cpu.FMA4}),
    // VFNMSUBPS
    vec(.VFNMSUBPS, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x7C), .RVMR, .{cpu.FMA4}),
    vec(.VFNMSUBPS, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x7C), .RVMR, .{cpu.FMA4}),
    vec(.VFNMSUBPS, ops4(.xmml, .xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F3A, .W1, 0x7C), .RVRM, .{cpu.FMA4}),
    vec(.VFNMSUBPS, ops4(.ymml, .ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F3A, .W1, 0x7C), .RVRM, .{cpu.FMA4}),
    // VFNMSUBSD
    vec(.VFNMSUBSD, ops4(.xmml, .xmml, .xmml_m64, .xmml), vex(.LIG, ._66, ._0F3A, .W0, 0x7F), .RVMR, .{cpu.FMA4}),
    vec(.VFNMSUBSD, ops4(.xmml, .xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F3A, .W1, 0x7F), .RVRM, .{cpu.FMA4}),
    // VFNMSUBSS
    vec(.VFNMSUBSS, ops4(.xmml, .xmml, .xmml_m32, .xmml), vex(.LIG, ._66, ._0F3A, .W0, 0x7E), .RVMR, .{cpu.FMA4}),
    vec(.VFNMSUBSS, ops4(.xmml, .xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F3A, .W1, 0x7E), .RVRM, .{cpu.FMA4}),

    //
    // Misc Extensions
    //
    // ADX
    // ADCX
    instr(.ADCX, ops2(.reg32, .rm32), preOp3(._66, 0x0F, 0x38, 0xF6), .RM, .Op32, .{cpu.ADX}),
    instr(.ADCX, ops2(.reg64, .rm64), preOp3(._66, 0x0F, 0x38, 0xF6), .RM, .REX_W, .{cpu.ADX}),
    // ADOX
    instr(.ADOX, ops2(.reg32, .rm32), preOp3(._F3, 0x0F, 0x38, 0xF6), .RM, .Op32, .{cpu.ADX}),
    instr(.ADOX, ops2(.reg64, .rm64), preOp3(._F3, 0x0F, 0x38, 0xF6), .RM, .REX_W, .{cpu.ADX}),
    // CLDEMOTE
    instr(.CLDEMOTE, ops1(.rm_mem8), preOp2r(._NP, 0x0F, 0x1C, 0), .M, .ZO, .{cpu.CLDEMOTE}),
    // CLFLUSHOPT
    instr(.CLFLUSHOPT, ops1(.rm_mem8), preOp2r(._66, 0x0F, 0xAE, 7), .M, .ZO, .{cpu.CLFLUSHOPT}),
    // CET_IBT
    instr(.ENDBR32, ops0(), preOp3(._F3, 0x0F, 0x1E, 0xFB), .ZO, .ZO, .{cpu.CET_IBT}),
    instr(.ENDBR64, ops0(), preOp3(._F3, 0x0F, 0x1E, 0xFA), .ZO, .ZO, .{cpu.CET_IBT}),
    // CET_SS
    // CLRSSBSY
    instr(.CLRSSBSY, ops1(.rm_mem64), preOp2r(._F3, 0x0F, 0xAE, 6), .M, .ZO, .{cpu.CET_SS}),
    // INCSSPD / INCSSPQ
    instr(.INCSSPD, ops1(.reg32), preOp2r(._F3, 0x0F, 0xAE, 5), .M, .Op32, .{cpu.CET_SS}),
    instr(.INCSSPQ, ops1(.reg64), preOp2r(._F3, 0x0F, 0xAE, 5), .M, .REX_W, .{cpu.CET_SS}),
    // RDSSP
    instr(.RDSSPD, ops1(.reg32), preOp2r(._F3, 0x0F, 0x1E, 1), .M, .Op32, .{cpu.CET_SS}),
    instr(.RDSSPQ, ops1(.reg64), preOp2r(._F3, 0x0F, 0x1E, 1), .M, .REX_W, .{cpu.CET_SS}),
    // RSTORSSP
    instr(.RSTORSSP, ops1(.rm_mem64), preOp2r(._F3, 0x0F, 0x01, 5), .M, .ZO, .{cpu.CET_SS}),
    // SAVEPREVSSP
    instr(.SAVEPREVSSP, ops0(), preOp3(._F3, 0x0F, 0x01, 0xEA), .ZO, .ZO, .{cpu.CET_SS}),
    // SETSSBSY
    instr(.SETSSBSY, ops0(), preOp3(._F3, 0x0F, 0x01, 0xE8), .ZO, .ZO, .{cpu.CET_SS}),
    // WRSS
    instr(.WRSSD, ops2(.rm32, .reg32), Op3(0x0F, 0x38, 0xF6), .MR, .Op32, .{cpu.CET_SS}),
    instr(.WRSSQ, ops2(.rm64, .reg64), Op3(0x0F, 0x38, 0xF6), .MR, .REX_W, .{cpu.CET_SS}),
    // WRUSS
    instr(.WRUSSD, ops2(.rm32, .reg32), preOp3(._66, 0x0F, 0x38, 0xF5), .MR, .Op32, .{cpu.CET_SS}),
    instr(.WRUSSQ, ops2(.rm64, .reg64), preOp3(._66, 0x0F, 0x38, 0xF5), .MR, .REX_W, .{cpu.CET_SS}),
    // CLWB
    instr(.CLWB, ops1(.rm_mem8), preOp2r(._66, 0x0F, 0xAE, 6), .M, .ZO, .{cpu.CLWB}),
    // FSGSBASE
    // RDFSBASE
    instr(.RDFSBASE, ops1(.reg32), preOp2r(._F3, 0x0F, 0xAE, 0), .M, .Op32, .{cpu.FSGSBASE}),
    instr(.RDFSBASE, ops1(.reg64), preOp2r(._F3, 0x0F, 0xAE, 0), .M, .REX_W, .{cpu.FSGSBASE}),
    // RDGSBASE
    instr(.RDGSBASE, ops1(.reg32), preOp2r(._F3, 0x0F, 0xAE, 1), .M, .Op32, .{cpu.FSGSBASE}),
    instr(.RDGSBASE, ops1(.reg64), preOp2r(._F3, 0x0F, 0xAE, 1), .M, .REX_W, .{cpu.FSGSBASE}),
    // WRFSBASE
    instr(.WRFSBASE, ops1(.reg32), preOp2r(._F3, 0x0F, 0xAE, 2), .M, .Op32, .{cpu.FSGSBASE}),
    instr(.WRFSBASE, ops1(.reg64), preOp2r(._F3, 0x0F, 0xAE, 2), .M, .REX_W, .{cpu.FSGSBASE}),
    // WRGSBASE
    instr(.WRGSBASE, ops1(.reg32), preOp2r(._F3, 0x0F, 0xAE, 3), .M, .Op32, .{cpu.FSGSBASE}),
    instr(.WRGSBASE, ops1(.reg64), preOp2r(._F3, 0x0F, 0xAE, 3), .M, .REX_W, .{cpu.FSGSBASE}),
    // FXRSTOR
    instr(.FXRSTOR, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xAE, 1), .M, .ZO, .{cpu.FXSR}),
    instr(.FXRSTOR64, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xAE, 1), .M, .REX_W, .{ cpu.FXSR, No32 }),
    // FXSAVE
    instr(.FXSAVE, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xAE, 0), .M, .ZO, .{cpu.FXSR}),
    instr(.FXSAVE64, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xAE, 0), .M, .REX_W, .{ cpu.FXSR, No32 }),
    // SGX
    instr(.ENCLS, ops0(), preOp3(._NP, 0x0F, 0x01, 0xCF), .ZO, .ZO, .{cpu.SGX}),
    instr(.ENCLU, ops0(), preOp3(._NP, 0x0F, 0x01, 0xD7), .ZO, .ZO, .{cpu.SGX}),
    instr(.ENCLV, ops0(), preOp3(._NP, 0x0F, 0x01, 0xC0), .ZO, .ZO, .{cpu.SGX}),
    // SMX
    instr(.GETSEC, ops0(), preOp2(._NP, 0x0F, 0x37), .ZO, .ZO, .{cpu.SMX}),
    // GFNI
    instr(.GF2P8AFFINEINVQB, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0xCF), .RMI, .ZO, .{GFNI}),
    instr(.GF2P8AFFINEQB, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0xCE), .RMI, .ZO, .{GFNI}),
    instr(.GF2P8MULB, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0xCF), .RM, .ZO, .{GFNI}),
    // INVPCID
    instr(.INVPCID, ops2(.reg32, .rm_mem128), preOp3(._66, 0x0F, 0x38, 0x82), .RM, .ZO, .{ cpu.INVPCID, No64 }),
    instr(.INVPCID, ops2(.reg64, .rm_mem128), preOp3(._66, 0x0F, 0x38, 0x82), .RM, .ZO, .{ cpu.INVPCID, No32 }),
    // MOVBE
    instr(.MOVBE, ops2(.reg16, .rm_mem16), Op3(0x0F, 0x38, 0xF0), .RM, .Op16, .{cpu.MOVBE}),
    instr(.MOVBE, ops2(.reg32, .rm_mem32), Op3(0x0F, 0x38, 0xF0), .RM, .Op32, .{cpu.MOVBE}),
    instr(.MOVBE, ops2(.reg64, .rm_mem64), Op3(0x0F, 0x38, 0xF0), .RM, .REX_W, .{cpu.MOVBE}),
    //
    instr(.MOVBE, ops2(.rm_mem16, .reg16), Op3(0x0F, 0x38, 0xF1), .MR, .Op16, .{cpu.MOVBE}),
    instr(.MOVBE, ops2(.rm_mem32, .reg32), Op3(0x0F, 0x38, 0xF1), .MR, .Op32, .{cpu.MOVBE}),
    instr(.MOVBE, ops2(.rm_mem64, .reg64), Op3(0x0F, 0x38, 0xF1), .MR, .REX_W, .{cpu.MOVBE}),
    // MOVDIRI
    instr(.MOVDIRI, ops2(.rm_mem32, .reg32), preOp3(._NP, 0x0F, 0x38, 0xF9), .MR, .Op32, .{cpu.MOVDIRI}),
    instr(.MOVDIRI, ops2(.rm_mem64, .reg64), preOp3(._NP, 0x0F, 0x38, 0xF9), .MR, .REX_W, .{cpu.MOVDIRI}),
    // MOVDIR64B
    instr(.MOVDIR64B, ops2(.reg16, .rm_mem), preOp3(._66, 0x0F, 0x38, 0xF8), .RM, .Addr16, .{ cpu.MOVDIR64B, No64 }),
    instr(.MOVDIR64B, ops2(.reg32, .rm_mem), preOp3(._66, 0x0F, 0x38, 0xF8), .RM, .Addr32, .{cpu.MOVDIR64B}),
    instr(.MOVDIR64B, ops2(.reg64, .rm_mem), preOp3(._66, 0x0F, 0x38, 0xF8), .RM, .Addr64, .{ cpu.MOVDIR64B, No32 }),
    // MPX
    instr(.BNDCL, ops2(.bnd, .rm32), preOp2(._F3, 0x0F, 0x1A), .RM, .ZO, .{ cpu.MPX, No64 }),
    instr(.BNDCL, ops2(.bnd, .rm64), preOp2(._F3, 0x0F, 0x1A), .RM, .ZO, .{ cpu.MPX, No32 }),
    //
    instr(.BNDCU, ops2(.bnd, .rm32), preOp2(._F2, 0x0F, 0x1A), .RM, .ZO, .{ cpu.MPX, No64 }),
    instr(.BNDCU, ops2(.bnd, .rm64), preOp2(._F2, 0x0F, 0x1A), .RM, .ZO, .{ cpu.MPX, No32 }),
    instr(.BNDCN, ops2(.bnd, .rm32), preOp2(._F2, 0x0F, 0x1B), .RM, .ZO, .{ cpu.MPX, No64 }),
    instr(.BNDCN, ops2(.bnd, .rm64), preOp2(._F2, 0x0F, 0x1B), .RM, .ZO, .{ cpu.MPX, No32 }),
    // TODO/NOTE: special `mib` encoding actually requires SIB and is not used as normal memory
    instr(.BNDLDX, ops2(.bnd, .rm_mem), preOp2(._NP, 0x0F, 0x1A), .RM, .ZO, .{cpu.MPX}),
    //
    instr(.BNDMK, ops2(.bnd, .rm_mem32), preOp2(._F3, 0x0F, 0x1B), .RM, .ZO, .{ cpu.MPX, No64 }),
    instr(.BNDMK, ops2(.bnd, .rm_mem64), preOp2(._F3, 0x0F, 0x1B), .RM, .ZO, .{ cpu.MPX, No32 }),
    //
    instr(.BNDMOV, ops2(.bnd, .bnd_m64), preOp2(._66, 0x0F, 0x1A), .RM, .ZO, .{ cpu.MPX, No64 }),
    instr(.BNDMOV, ops2(.bnd, .bnd_m128), preOp2(._66, 0x0F, 0x1A), .RM, .ZO, .{ cpu.MPX, No32 }),
    instr(.BNDMOV, ops2(.bnd_m64, .bnd), preOp2(._66, 0x0F, 0x1B), .MR, .ZO, .{ cpu.MPX, No64 }),
    instr(.BNDMOV, ops2(.bnd_m128, .bnd), preOp2(._66, 0x0F, 0x1B), .MR, .ZO, .{ cpu.MPX, No32 }),
    // TODO/NOTE: special `mib` encoding actually requires SIB and is not used as normal memory
    instr(.BNDSTX, ops2(.rm_mem, .bnd), preOp2(._NP, 0x0F, 0x1B), .MR, .ZO, .{cpu.MPX}),
    // PCOMMIT
    instr(.PCOMMIT, ops0(), preOp3(._66, 0x0F, 0xAE, 0xF8), .ZO, .ZO, .{cpu.PCOMMIT}),
    // PKU
    instr(.RDPKRU, ops0(), preOp3(._NP, 0x0F, 0x01, 0xEE), .ZO, .ZO, .{cpu.PKU}),
    instr(.WRPKRU, ops0(), preOp3(._NP, 0x0F, 0x01, 0xEF), .ZO, .ZO, .{cpu.PKU}),
    // PREFETCHW
    instr(.PREFETCH, ops1(.rm_mem8), Op2r(0x0F, 0x0D, 0), .M, .ZO, .{cpu._3DNOW}),
    instr(.PREFETCH, ops1(.rm_mem8), Op2r(0x0F, 0x0D, 0), .M, .ZO, .{ cpu.PREFETCHW, cpu.Amd }),
    instr(.PREFETCH, ops1(.rm_mem8), Op2r(0x0F, 0x0D, 0), .M, .ZO, .{ x86_64, cpu.Amd }),
    instr(.PREFETCHW, ops1(.rm_mem8), Op2r(0x0F, 0x0D, 1), .M, .ZO, .{cpu.PREFETCHW}),
    instr(.PREFETCHW, ops1(.rm_mem8), Op2r(0x0F, 0x0D, 1), .M, .ZO, .{cpu._3DNOW}),
    instr(.PREFETCHW, ops1(.rm_mem8), Op2r(0x0F, 0x0D, 1), .M, .ZO, .{x86_64}),
    // PTWRITE
    instr(.PTWRITE, ops1(.rm32), preOp2r(._F3, 0x0F, 0xAE, 4), .M, .Op32, .{cpu.PTWRITE}),
    instr(.PTWRITE, ops1(.rm64), preOp2r(._F3, 0x0F, 0xAE, 4), .M, .REX_W, .{cpu.PTWRITE}),
    // RDPID
    instr(.RDPID, ops1(.reg32), preOp2r(._F3, 0x0F, 0xC7, 7), .M, .ZO, .{ cpu.RDPID, No64 }),
    instr(.RDPID, ops1(.reg64), preOp2r(._F3, 0x0F, 0xC7, 7), .M, .ZO, .{ cpu.RDPID, No32 }),
    // RDRAND
    instr(.RDRAND, ops1(.reg16), preOp2r(.NFx, 0x0F, 0xC7, 6), .M, .Op16, .{cpu.RDRAND}),
    instr(.RDRAND, ops1(.reg32), preOp2r(.NFx, 0x0F, 0xC7, 6), .M, .Op32, .{cpu.RDRAND}),
    instr(.RDRAND, ops1(.reg64), preOp2r(.NFx, 0x0F, 0xC7, 6), .M, .REX_W, .{cpu.RDRAND}),
    // RDSEED
    instr(.RDSEED, ops1(.reg16), preOp2r(.NFx, 0x0F, 0xC7, 7), .M, .Op16, .{cpu.RDSEED}),
    instr(.RDSEED, ops1(.reg32), preOp2r(.NFx, 0x0F, 0xC7, 7), .M, .Op32, .{cpu.RDSEED}),
    instr(.RDSEED, ops1(.reg64), preOp2r(.NFx, 0x0F, 0xC7, 7), .M, .REX_W, .{cpu.RDSEED}),
    // SMAP
    instr(.CLAC, ops0(), preOp3(._NP, 0x0F, 0x01, 0xCA), .ZO, .ZO, .{cpu.SMAP}),
    instr(.STAC, ops0(), preOp3(._NP, 0x0F, 0x01, 0xCB), .ZO, .ZO, .{cpu.SMAP}),
    // TDX (HLE / RTM)
    // HLE (NOTE: these instructions actually act as prefixes)
    instr(.XACQUIRE, ops0(), Op1(0xF2), .ZO, .ZO, .{cpu.HLE}),
    instr(.XRELEASE, ops0(), Op1(0xF3), .ZO, .ZO, .{cpu.HLE}),
    // RTM
    instr(.XABORT, ops1(.imm8), Op2(0xC6, 0xF8), .I, .ZO, .{cpu.RTM}),
    instr(.XBEGIN, ops1(.imm16), Op2(0xC7, 0xF8), .I, .Op16, .{ cpu.RTM, Sign }),
    instr(.XBEGIN, ops1(.imm32), Op2(0xC7, 0xF8), .I, .Op32, .{ cpu.RTM, Sign }),
    instr(.XEND, ops0(), preOp3(._NP, 0x0F, 0x01, 0xD5), .ZO, .ZO, .{cpu.RTM}),
    // HLE or RTM
    instr(.XTEST, ops0(), preOp3(._NP, 0x0F, 0x01, 0xD6), .ZO, .ZO, .{cpu.HLE}),
    instr(.XTEST, ops0(), preOp3(._NP, 0x0F, 0x01, 0xD6), .ZO, .ZO, .{cpu.RTM}),
    // WAITPKG
    //
    instr(.UMONITOR, ops1(.reg16), preOp2r(._F3, 0x0F, 0xAE, 6), .M, .Addr16, .{ cpu.WAITPKG, No64 }),
    instr(.UMONITOR, ops1(.reg32), preOp2r(._F3, 0x0F, 0xAE, 6), .M, .Addr32, .{cpu.WAITPKG}),
    instr(.UMONITOR, ops1(.reg64), preOp2r(._F3, 0x0F, 0xAE, 6), .M, .ZO, .{ cpu.WAITPKG, No32 }),
    //
    instr(.UMWAIT, ops3(.reg32, .reg_edx, .reg_eax), preOp2r(._F2, 0x0F, 0xAE, 6), .M, .ZO, .{cpu.WAITPKG}),
    instr(.UMWAIT, ops1(.reg32), preOp2r(._F2, 0x0F, 0xAE, 6), .M, .ZO, .{cpu.WAITPKG}),
    //
    instr(.TPAUSE, ops3(.reg32, .reg_edx, .reg_eax), preOp2r(._66, 0x0F, 0xAE, 6), .M, .ZO, .{cpu.WAITPKG}),
    instr(.TPAUSE, ops1(.reg32), preOp2r(._66, 0x0F, 0xAE, 6), .M, .ZO, .{cpu.WAITPKG}),
    // XSAVE
    // XGETBV
    instr(.XGETBV, ops0(), preOp3(._NP, 0x0F, 0x01, 0xD0), .ZO, .ZO, .{cpu.XSAVE}),
    // XSETBV
    instr(.XSETBV, ops0(), preOp3(._NP, 0x0F, 0x01, 0xD1), .ZO, .ZO, .{cpu.XSAVE}),
    // FXSAE
    instr(.XSAVE, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xAE, 4), .M, .ZO, .{cpu.XSAVE}),
    instr(.XSAVE64, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xAE, 4), .M, .REX_W, .{ cpu.XSAVE, No32 }),
    // FXRSTO
    instr(.XRSTOR, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xAE, 5), .M, .ZO, .{cpu.XSAVE}),
    instr(.XRSTOR64, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xAE, 5), .M, .REX_W, .{ cpu.XSAVE, No32 }),
    // XSAVEOPT
    instr(.XSAVEOPT, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xAE, 6), .M, .ZO, .{cpu.XSAVEOPT}),
    instr(.XSAVEOPT64, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xAE, 6), .M, .REX_W, .{ cpu.XSAVEOPT, No32 }),
    // XSAVEC
    instr(.XSAVEC, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xC7, 4), .M, .ZO, .{cpu.XSAVEC}),
    instr(.XSAVEC64, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xC7, 4), .M, .REX_W, .{ cpu.XSAVEC, No32 }),
    // XSS
    instr(.XSAVES, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xC7, 5), .M, .ZO, .{cpu.XSS}),
    instr(.XSAVES64, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xC7, 5), .M, .REX_W, .{ cpu.XSS, No32 }),
    //
    instr(.XRSTORS, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xC7, 3), .M, .ZO, .{cpu.XSS}),
    instr(.XRSTORS64, ops1(.rm_mem), preOp2r(._NP, 0x0F, 0xC7, 3), .M, .REX_W, .{ cpu.XSS, No32 }),

    //
    // AES instructions
    //
    instr(.AESDEC, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0xDE), .RM, .ZO, .{cpu.AES}),
    instr(.AESDECLAST, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0xDF), .RM, .ZO, .{cpu.AES}),
    instr(.AESENC, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0xDC), .RM, .ZO, .{cpu.AES}),
    instr(.AESENCLAST, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0xDD), .RM, .ZO, .{cpu.AES}),
    instr(.AESIMC, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0xDB), .RM, .ZO, .{cpu.AES}),
    instr(.AESKEYGENASSIST, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0xDF), .RMI, .ZO, .{cpu.AES}),

    //
    // SHA instructions
    //
    instr(.SHA1RNDS4, ops3(.xmml, .xmml_m128, .imm8), preOp3(._NP, 0x0F, 0x3A, 0xCC), .RMI, .ZO, .{cpu.SHA}),
    instr(.SHA1NEXTE, ops2(.xmml, .xmml_m128), preOp3(._NP, 0x0F, 0x38, 0xC8), .RM, .ZO, .{cpu.SHA}),
    instr(.SHA1MSG1, ops2(.xmml, .xmml_m128), preOp3(._NP, 0x0F, 0x38, 0xC9), .RM, .ZO, .{cpu.SHA}),
    instr(.SHA1MSG2, ops2(.xmml, .xmml_m128), preOp3(._NP, 0x0F, 0x38, 0xCA), .RM, .ZO, .{cpu.SHA}),
    instr(.SHA256RNDS2, ops3(.xmml, .xmml_m128, .xmm0), preOp3(._NP, 0x0F, 0x38, 0xCB), .RM, .ZO, .{cpu.SHA}),
    instr(.SHA256RNDS2, ops2(.xmml, .xmml_m128), preOp3(._NP, 0x0F, 0x38, 0xCB), .RM, .ZO, .{cpu.SHA}),
    instr(.SHA256MSG1, ops2(.xmml, .xmml_m128), preOp3(._NP, 0x0F, 0x38, 0xCC), .RM, .ZO, .{cpu.SHA}),
    instr(.SHA256MSG2, ops2(.xmml, .xmml_m128), preOp3(._NP, 0x0F, 0x38, 0xCD), .RM, .ZO, .{cpu.SHA}),

    //
    // SSE non-VEX/EVEX opcodes
    //
    // LDMXCSR
    instr(.LDMXCSR, ops1(.rm_mem32), preOp2r(._NP, 0x0F, 0xAE, 2), .M, .ZO, .{SSE}),
    // STMXCSR
    instr(.STMXCSR, ops1(.rm_mem32), preOp2r(._NP, 0x0F, 0xAE, 3), .M, .ZO, .{SSE}),
    // PREFETCH
    instr(.PREFETCHNTA, ops1(.rm_mem8), Op2r(0x0F, 0x18, 0), .M, .ZO, .{SSE}),
    instr(.PREFETCHNTA, ops1(.rm_mem8), Op2r(0x0F, 0x18, 0), .M, .ZO, .{MMXEXT}),
    instr(.PREFETCHT0, ops1(.rm_mem8), Op2r(0x0F, 0x18, 1), .M, .ZO, .{SSE}),
    instr(.PREFETCHT0, ops1(.rm_mem8), Op2r(0x0F, 0x18, 1), .M, .ZO, .{MMXEXT}),
    instr(.PREFETCHT1, ops1(.rm_mem8), Op2r(0x0F, 0x18, 2), .M, .ZO, .{SSE}),
    instr(.PREFETCHT1, ops1(.rm_mem8), Op2r(0x0F, 0x18, 2), .M, .ZO, .{MMXEXT}),
    instr(.PREFETCHT2, ops1(.rm_mem8), Op2r(0x0F, 0x18, 3), .M, .ZO, .{SSE}),
    instr(.PREFETCHT2, ops1(.rm_mem8), Op2r(0x0F, 0x18, 3), .M, .ZO, .{MMXEXT}),
    // SFENCE
    instr(.SFENCE, ops0(), preOp3(._NP, 0x0F, 0xAE, 0xF8), .ZO, .ZO, .{SSE}),
    instr(.SFENCE, ops0(), preOp3(._NP, 0x0F, 0xAE, 0xF8), .ZO, .ZO, .{MMXEXT}),
    // CLFLUSH
    instr(.CLFLUSH, ops1(.rm_mem8), preOp2r(._NP, 0x0F, 0xAE, 7), .M, .ZO, .{SSE2}),
    // LFENCE
    instr(.LFENCE, ops0(), preOp3(._NP, 0x0F, 0xAE, 0xE8), .ZO, .ZO, .{SSE2}),
    // MFENCE
    instr(.MFENCE, ops0(), preOp3(._NP, 0x0F, 0xAE, 0xF0), .ZO, .ZO, .{SSE2}),
    // MOVNTI
    instr(.MOVNTI, ops2(.rm_mem32, .reg32), preOp2(._NP, 0x0F, 0xC3), .MR, .Op32, .{SSE2}),
    instr(.MOVNTI, ops2(.rm_mem64, .reg64), preOp2(._NP, 0x0F, 0xC3), .MR, .REX_W, .{SSE2}),
    // PAUSE
    instr(.PAUSE, ops0(), preOp1(._F3, 0x90), .ZO, .ZO, .{SSE2}),
    // MONITOR
    instr(.MONITOR, ops0(), Op3(0x0F, 0x01, 0xC8), .ZO, .ZO, .{SSE3}),
    // MWAIT
    instr(.MWAIT, ops0(), Op3(0x0F, 0x01, 0xC9), .ZO, .ZO, .{SSE3}),
    // CRC32
    instr(.CRC32, ops2(.reg32, .rm8), preOp3(._F2, 0x0F, 0x38, 0xF0), .RM, .ZO, .{SSE4_2}),
    instr(.CRC32, ops2(.reg32, .rm16), preOp3(._F2, 0x0F, 0x38, 0xF1), .RM, .Op16, .{SSE4_2}),
    instr(.CRC32, ops2(.reg32, .rm32), preOp3(._F2, 0x0F, 0x38, 0xF1), .RM, .Op32, .{SSE4_2}),
    instr(.CRC32, ops2(.reg64, .rm64), preOp3(._F2, 0x0F, 0x38, 0xF1), .RM, .REX_W, .{SSE4_2}),

    //
    // AMD-V
    // CLGI
    instr(.CLGI, ops0(), Op3(0x0F, 0x01, 0xDD), .ZO, .ZO, .{cpu.AMD_V}),
    // INVLPGA
    instr(.INVLPGA, ops0(), Op3(0x0F, 0x01, 0xDF), .ZO, .ZO, .{cpu.AMD_V}),
    instr(.INVLPGA, ops2(.reg_ax, .reg_ecx), Op3(0x0F, 0x01, 0xDF), .ZO, .Addr16, .{ cpu.AMD_V, No64 }),
    instr(.INVLPGA, ops2(.reg_eax, .reg_ecx), Op3(0x0F, 0x01, 0xDF), .ZO, .Addr32, .{cpu.AMD_V}),
    instr(.INVLPGA, ops2(.reg_rax, .reg_ecx), Op3(0x0F, 0x01, 0xDF), .ZO, .Addr64, .{ cpu.AMD_V, No32 }),
    // SKINIT
    instr(.SKINIT, ops0(), Op3(0x0F, 0x01, 0xDE), .ZO, .ZO, .{ cpu.AMD_V, cpu.SKINIT }),
    instr(.SKINIT, ops1(.reg_eax), Op3(0x0F, 0x01, 0xDE), .ZO, .ZO, .{ cpu.AMD_V, cpu.SKINIT }),
    // STGI
    instr(.STGI, ops0(), Op3(0x0F, 0x01, 0xDC), .ZO, .ZO, .{ cpu.AMD_V, cpu.SKINIT }),
    // VMLOAD
    instr(.VMLOAD, ops0(), Op3(0x0F, 0x01, 0xDA), .ZO, .ZO, .{cpu.AMD_V}),
    instr(.VMLOAD, ops1(.reg_ax), Op3(0x0F, 0x01, 0xDA), .ZO, .Addr16, .{ cpu.AMD_V, No64 }),
    instr(.VMLOAD, ops1(.reg_eax), Op3(0x0F, 0x01, 0xDA), .ZO, .Addr32, .{cpu.AMD_V}),
    instr(.VMLOAD, ops1(.reg_rax), Op3(0x0F, 0x01, 0xDA), .ZO, .Addr64, .{ cpu.AMD_V, No32 }),
    // VMMCALL
    instr(.VMMCALL, ops0(), Op3(0x0F, 0x01, 0xD9), .ZO, .ZO, .{cpu.AMD_V}),
    // VMRUN
    instr(.VMRUN, ops0(), Op3(0x0F, 0x01, 0xD8), .ZO, .ZO, .{cpu.AMD_V}),
    instr(.VMRUN, ops1(.reg_ax), Op3(0x0F, 0x01, 0xD8), .ZO, .Addr16, .{ cpu.AMD_V, No64 }),
    instr(.VMRUN, ops1(.reg_eax), Op3(0x0F, 0x01, 0xD8), .ZO, .Addr32, .{cpu.AMD_V}),
    instr(.VMRUN, ops1(.reg_rax), Op3(0x0F, 0x01, 0xD8), .ZO, .Addr64, .{ cpu.AMD_V, No32 }),
    // VMSAVE
    instr(.VMSAVE, ops0(), Op3(0x0F, 0x01, 0xDB), .ZO, .ZO, .{cpu.AMD_V}),
    instr(.VMSAVE, ops1(.reg_ax), Op3(0x0F, 0x01, 0xDB), .ZO, .Addr16, .{ cpu.AMD_V, No64 }),
    instr(.VMSAVE, ops1(.reg_eax), Op3(0x0F, 0x01, 0xDB), .ZO, .Addr32, .{cpu.AMD_V}),
    instr(.VMSAVE, ops1(.reg_rax), Op3(0x0F, 0x01, 0xDB), .ZO, .Addr64, .{ cpu.AMD_V, No32 }),

    //
    // Intel VT-x
    //
    // INVEPT
    instr(.INVEPT, ops2(.reg32, .rm_mem128), preOp3(._66, 0x0F, 0x38, 0x80), .M, .ZO, .{ cpu.VT_X, No64 }),
    instr(.INVEPT, ops2(.reg64, .rm_mem128), preOp3(._66, 0x0F, 0x38, 0x80), .M, .ZO, .{ cpu.VT_X, No32 }),
    // INVVPID
    instr(.INVVPID, ops2(.reg32, .rm_mem128), preOp3(._66, 0x0F, 0x38, 0x80), .M, .ZO, .{ cpu.VT_X, No64 }),
    instr(.INVVPID, ops2(.reg64, .rm_mem128), preOp3(._66, 0x0F, 0x38, 0x80), .M, .ZO, .{ cpu.VT_X, No32 }),
    // VMCLEAR
    instr(.VMCLEAR, ops1(.rm_mem64), preOp2r(._66, 0x0F, 0xC7, 6), .M, .ZO, .{cpu.VT_X}),
    // VMFUNC
    instr(.VMFUNC, ops0(), preOp3(._NP, 0x0F, 0x01, 0xD4), .ZO, .ZO, .{cpu.VT_X}),
    // VMPTRLD
    instr(.VMPTRLD, ops1(.rm_mem64), preOp2r(._NP, 0x0F, 0xC7, 6), .M, .ZO, .{cpu.VT_X}),
    // VMPTRST
    instr(.VMPTRST, ops1(.rm_mem64), preOp2r(._NP, 0x0F, 0xC7, 7), .M, .ZO, .{cpu.VT_X}),
    // VMREAD
    instr(.VMREAD, ops2(.rm32, .reg32), preOp2(._NP, 0x0F, 0x78), .MR, .Op32, .{ cpu.VT_X, No64 }),
    instr(.VMREAD, ops2(.rm64, .reg64), preOp2(._NP, 0x0F, 0x78), .MR, .ZO, .{ cpu.VT_X, No32 }),
    // VMWRITE
    instr(.VMWRITE, ops2(.reg32, .rm32), preOp2(._NP, 0x0F, 0x79), .RM, .Op32, .{ cpu.VT_X, No64 }),
    instr(.VMWRITE, ops2(.reg64, .rm64), preOp2(._NP, 0x0F, 0x79), .RM, .ZO, .{ cpu.VT_X, No32 }),
    // VMCALL
    instr(.VMCALL, ops0(), Op3(0x0F, 0x01, 0xC1), .ZO, .ZO, .{cpu.VT_X}),
    // VMLAUNCH
    instr(.VMLAUNCH, ops0(), Op3(0x0F, 0x01, 0xC2), .ZO, .ZO, .{cpu.VT_X}),
    // VMRESUME
    instr(.VMRESUME, ops0(), Op3(0x0F, 0x01, 0xC3), .ZO, .ZO, .{cpu.VT_X}),
    // VMXOFF
    instr(.VMXOFF, ops0(), Op3(0x0F, 0x01, 0xC4), .ZO, .ZO, .{cpu.VT_X}),
    // VMXON
    instr(.VMXON, ops1(.rm_mem64), Op3r(0x0F, 0x01, 0xC7, 6), .M, .ZO, .{cpu.VT_X}),

    //
    // SIMD legacy instructions (MMX + SSE)
    //
    // ADDPD
    instr(.ADDPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x58), .RM, .ZO, .{SSE2}),
    // ADDPS
    instr(.ADDPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x58), .RM, .ZO, .{SSE}),
    // ADDSD
    instr(.ADDSD, ops2(.xmml, .xmml_m64), preOp2(._F2, 0x0F, 0x58), .RM, .ZO, .{SSE2}),
    // ADDSS
    instr(.ADDSS, ops2(.xmml, .xmml_m32), preOp2(._F3, 0x0F, 0x58), .RM, .ZO, .{SSE}),
    // ADDSUBPD
    instr(.ADDSUBPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xD0), .RM, .ZO, .{SSE3}),
    // ADDSUBPS
    instr(.ADDSUBPS, ops2(.xmml, .xmml_m128), preOp2(._F2, 0x0F, 0xD0), .RM, .ZO, .{SSE3}),
    // ANDPD
    instr(.ANDPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x54), .RM, .ZO, .{SSE2}),
    // ANDPS
    instr(.ANDPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x54), .RM, .ZO, .{SSE}),
    // ANDNPD
    instr(.ANDNPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x55), .RM, .ZO, .{SSE2}),
    // ANDNPS
    instr(.ANDNPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x55), .RM, .ZO, .{SSE}),
    // BLENDPD
    instr(.BLENDPD, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x0D), .RMI, .ZO, .{SSE4_1}),
    // BLENDPS
    instr(.BLENDPS, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x0C), .RMI, .ZO, .{SSE4_1}),
    // BLENDVPD
    instr(.BLENDVPD, ops3(.xmml, .xmml_m128, .xmm0), preOp3(._66, 0x0F, 0x38, 0x15), .RM, .ZO, .{SSE4_1}),
    instr(.BLENDVPD, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x15), .RM, .ZO, .{SSE4_1}),
    // BLENDVPS
    instr(.BLENDVPS, ops3(.xmml, .xmml_m128, .xmm0), preOp3(._66, 0x0F, 0x38, 0x14), .RM, .ZO, .{SSE4_1}),
    instr(.BLENDVPS, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x14), .RM, .ZO, .{SSE4_1}),
    // CMPPD
    instr(.CMPPD, ops3(.xmml, .xmml_m128, .imm8), preOp2(._66, 0x0F, 0xC2), .RMI, .ZO, .{SSE2}),
    // CMPPS
    instr(.CMPPS, ops3(.xmml, .xmml_m128, .imm8), preOp2(._NP, 0x0F, 0xC2), .RMI, .ZO, .{SSE}),
    // CMPSD
    instr(.CMPSD, ops0(), Op1(0xA7), .ZO, .Op32, .{ _386, Repe, Repne }), // overloaded
    instr(.CMPSD, ops3(.xmml, .xmml_m64, .imm8), preOp2(._F2, 0x0F, 0xC2), .RMI, .ZO, .{SSE2}),
    // CMPSS
    instr(.CMPSS, ops3(.xmml, .xmml_m32, .imm8), preOp2(._F3, 0x0F, 0xC2), .RMI, .ZO, .{SSE}),
    // COMISD
    instr(.COMISD, ops2(.xmml, .xmml_m64), preOp2(._66, 0x0F, 0x2F), .RM, .ZO, .{SSE2}),
    // COMISS
    instr(.COMISS, ops2(.xmml, .xmml_m32), preOp2(._NP, 0x0F, 0x2F), .RM, .ZO, .{SSE}),
    // CVTDQ2PD
    instr(.CVTDQ2PD, ops2(.xmml, .xmml_m64), preOp2(._F3, 0x0F, 0xE6), .RM, .ZO, .{SSE2}),
    // CVTDQ2PS
    instr(.CVTDQ2PS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x5B), .RM, .ZO, .{SSE2}),
    // CVTPD2DQ
    instr(.CVTPD2DQ, ops2(.xmml, .xmml_m128), preOp2(._F2, 0x0F, 0xE6), .RM, .ZO, .{SSE2}),
    // CVTPD2PI
    instr(.CVTPD2PI, ops2(.mm, .xmml_m128), preOp2(._66, 0x0F, 0x2D), .RM, .ZO, .{SSE2}),
    // CVTPD2PS
    instr(.CVTPD2PS, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x5A), .RM, .ZO, .{SSE2}),
    // CVTPI2PD
    instr(.CVTPI2PD, ops2(.xmml, .mm_m64), preOp2(._66, 0x0F, 0x2A), .RM, .ZO, .{SSE2}),
    // CVTPI2PS
    instr(.CVTPI2PS, ops2(.xmml, .mm_m64), preOp2(._NP, 0x0F, 0x2A), .RM, .ZO, .{SSE}),
    // CVTPS2DQ
    instr(.CVTPS2DQ, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x5B), .RM, .ZO, .{SSE2}),
    // CVTPS2PD
    instr(.CVTPS2PD, ops2(.xmml, .xmml_m64), preOp2(._NP, 0x0F, 0x5A), .RM, .ZO, .{SSE2}),
    // CVTPS2PI
    instr(.CVTPS2PI, ops2(.mm, .xmml_m64), preOp2(._NP, 0x0F, 0x2D), .RM, .ZO, .{SSE}),
    // CVTSD2SI
    instr(.CVTSD2SI, ops2(.reg32, .xmml_m64), preOp2(._F2, 0x0F, 0x2D), .RM, .ZO, .{SSE2}),
    instr(.CVTSD2SI, ops2(.reg64, .xmml_m64), preOp2(._F2, 0x0F, 0x2D), .RM, .REX_W, .{SSE2}),
    // CVTSD2SS
    instr(.CVTSD2SS, ops2(.xmml, .xmml_m64), preOp2(._F2, 0x0F, 0x5A), .RM, .ZO, .{SSE2}),
    // CVTSI2SD
    instr(.CVTSI2SD, ops2(.xmml, .rm32), preOp2(._F2, 0x0F, 0x2A), .RM, .ZO, .{SSE2}),
    instr(.CVTSI2SD, ops2(.xmml, .rm64), preOp2(._F2, 0x0F, 0x2A), .RM, .REX_W, .{SSE2}),
    // CVTSI2SS
    instr(.CVTSI2SS, ops2(.xmml, .rm32), preOp2(._F3, 0x0F, 0x2A), .RM, .ZO, .{SSE}),
    instr(.CVTSI2SS, ops2(.xmml, .rm64), preOp2(._F3, 0x0F, 0x2A), .RM, .REX_W, .{SSE}),
    // CVTSS2SD
    instr(.CVTSS2SD, ops2(.xmml, .xmml_m32), preOp2(._F3, 0x0F, 0x5A), .RM, .ZO, .{SSE2}),
    // CVTSS2SI
    instr(.CVTSS2SI, ops2(.reg32, .xmml_m32), preOp2(._F3, 0x0F, 0x2D), .RM, .ZO, .{SSE}),
    instr(.CVTSS2SI, ops2(.reg64, .xmml_m32), preOp2(._F3, 0x0F, 0x2D), .RM, .REX_W, .{SSE}),
    // CVTTPD2DQ
    instr(.CVTTPD2DQ, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xE6), .RM, .ZO, .{SSE2}),
    // CVTTPD2PI
    instr(.CVTTPD2PI, ops2(.mm, .xmml_m128), preOp2(._66, 0x0F, 0x2C), .RM, .ZO, .{SSE2}),
    // CVTTPS2DQ
    instr(.CVTTPS2DQ, ops2(.xmml, .xmml_m128), preOp2(._F3, 0x0F, 0x5B), .RM, .ZO, .{SSE2}),
    // CVTTPS2PI
    instr(.CVTTPS2PI, ops2(.mm, .xmml_m64), preOp2(._NP, 0x0F, 0x2C), .RM, .ZO, .{SSE}),
    // CVTTSD2SI
    instr(.CVTTSD2SI, ops2(.reg32, .xmml_m64), preOp2(._F2, 0x0F, 0x2C), .RM, .ZO, .{SSE2}),
    instr(.CVTTSD2SI, ops2(.reg64, .xmml_m64), preOp2(._F2, 0x0F, 0x2C), .RM, .REX_W, .{SSE2}),
    // CVTTSS2SI
    instr(.CVTTSS2SI, ops2(.reg32, .xmml_m32), preOp2(._F3, 0x0F, 0x2C), .RM, .ZO, .{SSE}),
    instr(.CVTTSS2SI, ops2(.reg64, .xmml_m32), preOp2(._F3, 0x0F, 0x2C), .RM, .REX_W, .{SSE}),
    // DIVPD
    instr(.DIVPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x5E), .RM, .ZO, .{SSE2}),
    // DIVPS
    instr(.DIVPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x5E), .RM, .ZO, .{SSE}),
    // DIVSD
    instr(.DIVSD, ops2(.xmml, .xmml_m64), preOp2(._F2, 0x0F, 0x5E), .RM, .ZO, .{SSE2}),
    // DIVSS
    instr(.DIVSS, ops2(.xmml, .xmml_m32), preOp2(._F3, 0x0F, 0x5E), .RM, .ZO, .{SSE}),
    // DPPD
    instr(.DPPD, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x41), .RMI, .ZO, .{SSE4_1}),
    // DPPS
    instr(.DPPS, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x40), .RMI, .ZO, .{SSE4_1}),
    // EXTRACTPS
    instr(.EXTRACTPS, ops3(.rm32, .xmml, .imm8), preOp3(._66, 0x0F, 0x3A, 0x17), .MRI, .ZO, .{SSE4_1}),
    instr(.EXTRACTPS, ops3(.reg64, .xmml, .imm8), preOp3(._66, 0x0F, 0x3A, 0x17), .MRI, .ZO, .{ SSE4_1, No32 }),
    // HADDPD
    instr(.HADDPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x7C), .RM, .ZO, .{SSE3}),
    // HADDPS
    instr(.HADDPS, ops2(.xmml, .xmml_m128), preOp2(._F2, 0x0F, 0x7C), .RM, .ZO, .{SSE3}),
    // HSUBPD
    instr(.HSUBPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x7D), .RM, .ZO, .{SSE3}),
    // HSUBPS
    instr(.HSUBPS, ops2(.xmml, .xmml_m128), preOp2(._F2, 0x0F, 0x7D), .RM, .ZO, .{SSE3}),
    // INSERTPS
    instr(.INSERTPS, ops3(.xmml, .xmml_m32, .imm8), preOp3(._66, 0x0F, 0x3A, 0x21), .RMI, .ZO, .{SSE4_1}),
    // LDDQU
    instr(.LDDQU, ops2(.xmml, .rm_mem128), preOp2(._F2, 0x0F, 0xF0), .RM, .ZO, .{SSE3}),
    // MASKMOVDQU
    instr(.MASKMOVDQU, ops2(.xmml, .xmml), preOp2(._66, 0x0F, 0xF7), .RM, .ZO, .{SSE2}),
    // MASKMOVQ
    instr(.MASKMOVQ, ops2(.mm, .mm), preOp2(._NP, 0x0F, 0xF7), .RM, .ZO, .{SSE}),
    instr(.MASKMOVQ, ops2(.mm, .mm), preOp2(._NP, 0x0F, 0xF7), .RM, .ZO, .{MMXEXT}),
    // MAXPD
    instr(.MAXPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x5F), .RM, .ZO, .{SSE2}),
    // MAXPS
    instr(.MAXPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x5F), .RM, .ZO, .{SSE}),
    // MAXSD
    instr(.MAXSD, ops2(.xmml, .xmml_m64), preOp2(._F2, 0x0F, 0x5F), .RM, .ZO, .{SSE2}),
    // MAXSS
    instr(.MAXSS, ops2(.xmml, .xmml_m32), preOp2(._F3, 0x0F, 0x5F), .RM, .ZO, .{SSE}),
    // MINPD
    instr(.MINPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x5D), .RM, .ZO, .{SSE2}),
    // MINPS
    instr(.MINPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x5D), .RM, .ZO, .{SSE}),
    // MINSD
    instr(.MINSD, ops2(.xmml, .xmml_m64), preOp2(._F2, 0x0F, 0x5D), .RM, .ZO, .{SSE2}),
    // MINSS
    instr(.MINSS, ops2(.xmml, .xmml_m32), preOp2(._F3, 0x0F, 0x5D), .RM, .ZO, .{SSE}),
    // MOVAPD
    instr(.MOVAPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x28), .RM, .ZO, .{SSE2}),
    instr(.MOVAPD, ops2(.xmml_m128, .xmml), preOp2(._66, 0x0F, 0x29), .MR, .ZO, .{SSE2}),
    // MOVAPS
    instr(.MOVAPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x28), .RM, .ZO, .{SSE}),
    instr(.MOVAPS, ops2(.xmml_m128, .xmml), preOp2(._NP, 0x0F, 0x29), .MR, .ZO, .{SSE}),
    // MOVD / MOVQ / MOVQ (2)
    instr(.MOVD, ops2(.mm, .rm32), preOp2(._NP, 0x0F, 0x6E), .RM, .ZO, .{MMX}),
    instr(.MOVD, ops2(.rm32, .mm), preOp2(._NP, 0x0F, 0x7E), .MR, .ZO, .{MMX}),
    instr(.MOVD, ops2(.mm, .rm64), preOp2(._NP, 0x0F, 0x6E), .RM, .REX_W, .{MMX}),
    instr(.MOVD, ops2(.rm64, .mm), preOp2(._NP, 0x0F, 0x7E), .MR, .REX_W, .{MMX}),
    // xmm
    instr(.MOVD, ops2(.xmml, .rm32), preOp2(._66, 0x0F, 0x6E), .RM, .ZO, .{SSE2}),
    instr(.MOVD, ops2(.rm32, .xmml), preOp2(._66, 0x0F, 0x7E), .MR, .ZO, .{SSE2}),
    instr(.MOVD, ops2(.xmml, .rm64), preOp2(._66, 0x0F, 0x6E), .RM, .REX_W, .{SSE2}),
    instr(.MOVD, ops2(.rm64, .xmml), preOp2(._66, 0x0F, 0x7E), .MR, .REX_W, .{SSE2}),
    // MOVQ
    instr(.MOVQ, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x6F), .RM, .ZO, .{MMX}),
    instr(.MOVQ, ops2(.mm_m64, .mm), preOp2(._NP, 0x0F, 0x7F), .MR, .ZO, .{MMX}),
    instr(.MOVQ, ops2(.mm, .rm64), preOp2(._NP, 0x0F, 0x6E), .RM, .REX_W, .{MMX}),
    instr(.MOVQ, ops2(.rm64, .mm), preOp2(._NP, 0x0F, 0x7E), .MR, .REX_W, .{MMX}),
    // xmm
    instr(.MOVQ, ops2(.xmml, .xmml_m64), preOp2(._F3, 0x0F, 0x7E), .RM, .ZO, .{SSE2}),
    instr(.MOVQ, ops2(.xmml_m64, .xmml), preOp2(._66, 0x0F, 0xD6), .MR, .ZO, .{SSE2}),
    instr(.MOVQ, ops2(.xmml, .rm64), preOp2(._66, 0x0F, 0x6E), .RM, .REX_W, .{SSE2}),
    instr(.MOVQ, ops2(.rm64, .xmml), preOp2(._66, 0x0F, 0x7E), .MR, .REX_W, .{SSE2}),
    // MOVDQA
    instr(.MOVDDUP, ops2(.xmml, .xmml_m64), preOp2(._F2, 0x0F, 0x12), .RM, .ZO, .{SSE3}),
    // MOVDQA
    instr(.MOVDQA, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x6F), .RM, .ZO, .{SSE2}),
    instr(.MOVDQA, ops2(.xmml_m128, .xmml), preOp2(._66, 0x0F, 0x7F), .MR, .ZO, .{SSE2}),
    // MOVDQU
    instr(.MOVDQU, ops2(.xmml, .xmml_m128), preOp2(._F3, 0x0F, 0x6F), .RM, .ZO, .{SSE2}),
    instr(.MOVDQU, ops2(.xmml_m128, .xmml), preOp2(._F3, 0x0F, 0x7F), .MR, .ZO, .{SSE2}),
    // MOVDQ2Q
    instr(.MOVDQ2Q, ops2(.mm, .xmml), preOp2(._F2, 0x0F, 0xD6), .RM, .ZO, .{SSE2}),
    // MOVHLPS
    instr(.MOVHLPS, ops2(.xmml, .xmml), preOp2(._NP, 0x0F, 0x12), .RM, .ZO, .{SSE}),
    // MOVHPD
    instr(.MOVHPD, ops2(.xmml, .rm_mem64), preOp2(._66, 0x0F, 0x16), .RM, .ZO, .{SSE2}),
    // MOVHPS
    instr(.MOVHPS, ops2(.xmml, .rm_mem64), preOp2(._NP, 0x0F, 0x16), .RM, .ZO, .{SSE}),
    // MOVLHPS
    instr(.MOVLHPS, ops2(.xmml, .xmml), preOp2(._NP, 0x0F, 0x16), .RM, .ZO, .{SSE}),
    // MOVLPD
    instr(.MOVLPD, ops2(.xmml, .rm_mem64), preOp2(._66, 0x0F, 0x12), .RM, .ZO, .{SSE2}),
    // MOVLPS
    instr(.MOVLPS, ops2(.xmml, .rm_mem64), preOp2(._NP, 0x0F, 0x12), .RM, .ZO, .{SSE}),
    // MOVMSKPD
    instr(.MOVMSKPD, ops2(.reg32, .xmml), preOp2(._66, 0x0F, 0x50), .RM, .ZO, .{SSE2}),
    instr(.MOVMSKPD, ops2(.reg64, .xmml), preOp2(._66, 0x0F, 0x50), .RM, .ZO, .{ No32, SSE2 }),
    // MOVMSKPS
    instr(.MOVMSKPS, ops2(.reg32, .xmml), preOp2(._NP, 0x0F, 0x50), .RM, .ZO, .{SSE}),
    instr(.MOVMSKPS, ops2(.reg64, .xmml), preOp2(._NP, 0x0F, 0x50), .RM, .ZO, .{ No32, SSE2 }),
    // MOVNTDQA
    instr(.MOVNTDQA, ops2(.xmml, .rm_mem128), preOp3(._66, 0x0F, 0x38, 0x2A), .RM, .ZO, .{SSE4_1}),
    // MOVNTDQ
    instr(.MOVNTDQ, ops2(.rm_mem128, .xmml), preOp2(._66, 0x0F, 0xE7), .MR, .ZO, .{SSE2}),
    // MOVNTPD
    instr(.MOVNTPD, ops2(.rm_mem128, .xmml), preOp2(._66, 0x0F, 0x2B), .MR, .ZO, .{SSE2}),
    // MOVNTPS
    instr(.MOVNTPS, ops2(.rm_mem128, .xmml), preOp2(._NP, 0x0F, 0x2B), .MR, .ZO, .{SSE}),
    // MOVNTQ
    instr(.MOVNTQ, ops2(.rm_mem64, .mm), preOp2(._NP, 0x0F, 0xE7), .MR, .ZO, .{SSE}),
    instr(.MOVNTQ, ops2(.rm_mem64, .mm), preOp2(._NP, 0x0F, 0xE7), .MR, .ZO, .{MMXEXT}),
    // MOVQ2DQ
    instr(.MOVQ2DQ, ops2(.xmml, .mm), preOp2(._F3, 0x0F, 0xD6), .RM, .ZO, .{SSE2}),
    // MOVSD
    instr(.MOVSD, ops0(), Op1(0xA5), .ZO, .Op32, .{ _386, Rep }), // overloaded
    instr(.MOVSD, ops2(.xmml, .xmml_m64), preOp2(._F2, 0x0F, 0x10), .RM, .ZO, .{SSE2}),
    instr(.MOVSD, ops2(.xmml_m64, .xmml), preOp2(._F2, 0x0F, 0x11), .MR, .ZO, .{SSE2}),
    // MOVSHDUP
    instr(.MOVSHDUP, ops2(.xmml, .xmml_m128), preOp2(._F3, 0x0F, 0x16), .RM, .ZO, .{SSE3}),
    // MOVSLDUP
    instr(.MOVSLDUP, ops2(.xmml, .xmml_m128), preOp2(._F3, 0x0F, 0x12), .RM, .ZO, .{SSE3}),
    // MOVSS
    instr(.MOVSS, ops2(.xmml, .xmml_m32), preOp2(._F3, 0x0F, 0x10), .RM, .ZO, .{SSE}),
    instr(.MOVSS, ops2(.xmml_m32, .xmml), preOp2(._F3, 0x0F, 0x11), .MR, .ZO, .{SSE}),
    // MOVUPD
    instr(.MOVUPD, ops2(.xmml, .xmml_m64), preOp2(._66, 0x0F, 0x10), .RM, .ZO, .{SSE2}),
    instr(.MOVUPD, ops2(.xmml_m64, .xmml), preOp2(._66, 0x0F, 0x11), .MR, .ZO, .{SSE2}),
    // MOVUPS
    instr(.MOVUPS, ops2(.xmml, .xmml_m32), preOp2(._NP, 0x0F, 0x10), .RM, .ZO, .{SSE}),
    instr(.MOVUPS, ops2(.xmml_m32, .xmml), preOp2(._NP, 0x0F, 0x11), .MR, .ZO, .{SSE}),
    // MPSADBW
    instr(.MPSADBW, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x42), .RMI, .ZO, .{SSE4_1}),
    // MULPD
    instr(.MULPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x59), .RM, .ZO, .{SSE2}),
    // MULPS
    instr(.MULPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x59), .RM, .ZO, .{SSE}),
    // MULSD
    instr(.MULSD, ops2(.xmml, .xmml_m64), preOp2(._F2, 0x0F, 0x59), .RM, .ZO, .{SSE2}),
    // MULSS
    instr(.MULSS, ops2(.xmml, .xmml_m32), preOp2(._F3, 0x0F, 0x59), .RM, .ZO, .{SSE}),
    // ORPD
    instr(.ORPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x56), .RM, .ZO, .{SSE2}),
    // ORPS
    instr(.ORPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x56), .RM, .ZO, .{SSE}),
    // PABSB / PABSW /PABSD
    // PABSB
    instr(.PABSB, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x1C), .RM, .ZO, .{SSSE3}),
    instr(.PABSB, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x1C), .RM, .ZO, .{SSSE3}),
    // PABSW
    instr(.PABSW, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x1D), .RM, .ZO, .{SSSE3}),
    instr(.PABSW, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x1D), .RM, .ZO, .{SSSE3}),
    // PABSD
    instr(.PABSD, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x1E), .RM, .ZO, .{SSSE3}),
    instr(.PABSD, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x1E), .RM, .ZO, .{SSSE3}),
    // PACKSSWB / PACKSSDW
    instr(.PACKSSWB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x63), .RM, .ZO, .{MMX}),
    instr(.PACKSSWB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x63), .RM, .ZO, .{SSE2}),
    //
    instr(.PACKSSDW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x6B), .RM, .ZO, .{MMX}),
    instr(.PACKSSDW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x6B), .RM, .ZO, .{SSE2}),
    // PACKUSWB
    instr(.PACKUSWB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x67), .RM, .ZO, .{MMX}),
    instr(.PACKUSWB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x67), .RM, .ZO, .{SSE2}),
    // PACKUSDW
    instr(.PACKUSDW, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x2B), .RM, .ZO, .{SSE4_1}),
    // PADDB / PADDW / PADDD / PADDQ
    instr(.PADDB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xFC), .RM, .ZO, .{MMX}),
    instr(.PADDB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xFC), .RM, .ZO, .{SSE2}),
    //
    instr(.PADDW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xFD), .RM, .ZO, .{MMX}),
    instr(.PADDW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xFD), .RM, .ZO, .{SSE2}),
    //
    instr(.PADDD, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xFE), .RM, .ZO, .{MMX}),
    instr(.PADDD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xFE), .RM, .ZO, .{SSE2}),
    //
    instr(.PADDQ, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xD4), .RM, .ZO, .{MMX}),
    instr(.PADDQ, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xD4), .RM, .ZO, .{SSE2}),
    // PADDSB / PADDSW
    instr(.PADDSB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xEC), .RM, .ZO, .{MMX}),
    instr(.PADDSB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xEC), .RM, .ZO, .{SSE2}),
    //
    instr(.PADDSW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xED), .RM, .ZO, .{MMX}),
    instr(.PADDSW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xED), .RM, .ZO, .{SSE2}),
    // PADDUSB / PADDSW
    instr(.PADDUSB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xDC), .RM, .ZO, .{MMX}),
    instr(.PADDUSB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xDC), .RM, .ZO, .{SSE2}),
    //
    instr(.PADDUSW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xDD), .RM, .ZO, .{MMX}),
    instr(.PADDUSW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xDD), .RM, .ZO, .{SSE2}),
    // PALIGNR
    instr(.PALIGNR, ops3(.mm, .mm_m64, .imm8), preOp3(._NP, 0x0F, 0x3A, 0x0F), .RMI, .ZO, .{SSSE3}),
    instr(.PALIGNR, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x0F), .RMI, .ZO, .{SSSE3}),
    // PAND
    instr(.PAND, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xDB), .RM, .ZO, .{MMX}),
    instr(.PAND, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xDB), .RM, .ZO, .{SSE2}),
    // PANDN
    instr(.PANDN, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xDF), .RM, .ZO, .{MMX}),
    instr(.PANDN, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xDF), .RM, .ZO, .{SSE2}),
    // PAVGB / PAVGW
    instr(.PAVGB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xE0), .RM, .ZO, .{SSE}),
    instr(.PAVGB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xE0), .RM, .ZO, .{MMXEXT}),
    instr(.PAVGB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xE0), .RM, .ZO, .{SSE2}),
    //
    instr(.PAVGW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xE3), .RM, .ZO, .{SSE}),
    instr(.PAVGW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xE3), .RM, .ZO, .{MMXEXT}),
    instr(.PAVGW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xE3), .RM, .ZO, .{SSE2}),
    // PBLENDVB
    instr(.PBLENDVB, ops3(.xmml, .xmml_m128, .xmm0), preOp3(._66, 0x0F, 0x38, 0x10), .RM, .ZO, .{SSE4_1}),
    instr(.PBLENDVB, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x10), .RM, .ZO, .{SSE4_1}),
    // PBLENDVW
    instr(.PBLENDW, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x0E), .RMI, .ZO, .{SSE4_1}),
    // PCLMULQDQ
    instr(.PCLMULQDQ, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x44), .RMI, .ZO, .{cpu.PCLMULQDQ}),
    // PCMPEQB / PCMPEQW / PCMPEQD
    instr(.PCMPEQB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x74), .RM, .ZO, .{MMX}),
    instr(.PCMPEQB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x74), .RM, .ZO, .{SSE2}),
    //
    instr(.PCMPEQW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x75), .RM, .ZO, .{MMX}),
    instr(.PCMPEQW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x75), .RM, .ZO, .{SSE2}),
    //
    instr(.PCMPEQD, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x76), .RM, .ZO, .{MMX}),
    instr(.PCMPEQD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x76), .RM, .ZO, .{SSE2}),
    // PCMPEQQ
    instr(.PCMPEQQ, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x29), .RM, .ZO, .{SSE2}),
    // PCMPESTRI
    instr(.PCMPESTRI, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x61), .RMI, .ZO, .{SSE4_2}),
    // PCMPESTRM
    instr(.PCMPESTRM, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x60), .RMI, .ZO, .{SSE4_2}),
    // PCMPGTB / PCMPGTW / PCMPGTD
    instr(.PCMPGTB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x64), .RM, .ZO, .{MMX}),
    instr(.PCMPGTB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x64), .RM, .ZO, .{SSE2}),
    //
    instr(.PCMPGTW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x65), .RM, .ZO, .{MMX}),
    instr(.PCMPGTW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x65), .RM, .ZO, .{SSE2}),
    //
    instr(.PCMPGTD, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x66), .RM, .ZO, .{MMX}),
    instr(.PCMPGTD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x66), .RM, .ZO, .{SSE2}),
    // PCMPISTRI
    instr(.PCMPISTRI, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x63), .RMI, .ZO, .{SSE4_2}),
    // PCMPISTRM
    instr(.PCMPISTRM, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x62), .RMI, .ZO, .{SSE4_2}),
    // PEXTRB / PEXTRD / PEXTRQ
    instr(.PEXTRB, ops3(.reg32_m8, .xmml, .imm8), preOp3(._66, 0x0F, 0x3A, 0x14), .MRI, .ZO, .{SSE4_1}),
    instr(.PEXTRB, ops3(.rm_reg64, .xmml, .imm8), preOp3(._66, 0x0F, 0x3A, 0x14), .MRI, .ZO, .{ SSE4_1, No32 }),
    instr(.PEXTRD, ops3(.rm32, .xmml, .imm8), preOp3(._66, 0x0F, 0x3A, 0x16), .MRI, .ZO, .{SSE4_1}),
    instr(.PEXTRQ, ops3(.rm64, .xmml, .imm8), preOp3(._66, 0x0F, 0x3A, 0x16), .MRI, .REX_W, .{SSE4_1}),
    // PEXTRW
    instr(.PEXTRW, ops3(.reg32, .mm, .imm8), preOp2(._NP, 0x0F, 0xC5), .RMI, .ZO, .{SSE}),
    instr(.PEXTRW, ops3(.reg32, .mm, .imm8), preOp2(._NP, 0x0F, 0xC5), .RMI, .ZO, .{MMXEXT}),
    instr(.PEXTRW, ops3(.reg64, .mm, .imm8), preOp2(._NP, 0x0F, 0xC5), .RMI, .ZO, .{ SSE, No32 }),
    instr(.PEXTRW, ops3(.reg64, .mm, .imm8), preOp2(._NP, 0x0F, 0xC5), .RMI, .ZO, .{ MMXEXT, No32 }),
    instr(.PEXTRW, ops3(.reg32, .xmml, .imm8), preOp2(._66, 0x0F, 0xC5), .RMI, .ZO, .{SSE2}),
    instr(.PEXTRW, ops3(.reg64, .xmml, .imm8), preOp2(._66, 0x0F, 0xC5), .RMI, .ZO, .{ SSE2, No32 }),
    instr(.PEXTRW, ops3(.reg32_m16, .xmml, .imm8), preOp3(._66, 0x0F, 0x3A, 0x15), .MRI, .ZO, .{SSE4_1}),
    instr(.PEXTRW, ops3(.rm_reg64, .xmml, .imm8), preOp3(._66, 0x0F, 0x3A, 0x15), .MRI, .ZO, .{ SSE4_1, No32 }),
    // PHADDW / PHADDD
    instr(.PHADDW, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x01), .RM, .ZO, .{SSSE3}),
    instr(.PHADDW, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x01), .RM, .ZO, .{SSSE3}),
    instr(.PHADDD, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x02), .RM, .ZO, .{SSSE3}),
    instr(.PHADDD, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x02), .RM, .ZO, .{SSSE3}),
    // PHADDSW
    instr(.PHADDSW, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x03), .RM, .ZO, .{SSSE3}),
    instr(.PHADDSW, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x03), .RM, .ZO, .{SSSE3}),
    // PHMINPOSUW
    instr(.PHMINPOSUW, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x41), .RM, .ZO, .{SSE4_1}),
    // PHSUBW / PHSUBD
    instr(.PHSUBW, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x05), .RM, .ZO, .{SSSE3}),
    instr(.PHSUBW, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x05), .RM, .ZO, .{SSSE3}),
    instr(.PHSUBD, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x06), .RM, .ZO, .{SSSE3}),
    instr(.PHSUBD, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x06), .RM, .ZO, .{SSSE3}),
    // PHSUBSW
    instr(.PHSUBSW, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x07), .RM, .ZO, .{SSSE3}),
    instr(.PHSUBSW, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x07), .RM, .ZO, .{SSSE3}),
    // PINSRB / PINSRD / PINSRQ
    instr(.PINSRB, ops3(.xmml, .reg32_m8, .imm8), preOp3(._66, 0x0F, 0x3A, 0x20), .RMI, .ZO, .{SSE4_1}),
    //
    instr(.PINSRD, ops3(.xmml, .rm32, .imm8), preOp3(._66, 0x0F, 0x3A, 0x22), .RMI, .ZO, .{SSE4_1}),
    //
    instr(.PINSRQ, ops3(.xmml, .rm64, .imm8), preOp3(._66, 0x0F, 0x3A, 0x22), .RMI, .REX_W, .{SSE4_1}),
    // PINSRW
    instr(.PINSRW, ops3(.mm, .reg32_m16, .imm8), preOp2(._NP, 0x0F, 0xC4), .RMI, .ZO, .{SSE}),
    instr(.PINSRW, ops3(.mm, .reg32_m16, .imm8), preOp2(._NP, 0x0F, 0xC4), .RMI, .ZO, .{MMXEXT}),
    instr(.PINSRW, ops3(.xmml, .reg32_m16, .imm8), preOp2(._66, 0x0F, 0xC4), .RMI, .ZO, .{SSE2}),
    // PMADDUBSW
    instr(.PMADDUBSW, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x04), .RM, .ZO, .{SSSE3}),
    instr(.PMADDUBSW, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x04), .RM, .ZO, .{SSSE3}),
    // PMADDWD
    instr(.PMADDWD, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xF5), .RM, .ZO, .{MMX}),
    instr(.PMADDWD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xF5), .RM, .ZO, .{SSE2}),
    // PMAXSB / PMAXSW / PMAXSD
    instr(.PMAXSW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xEE), .RM, .ZO, .{SSE}),
    instr(.PMAXSW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xEE), .RM, .ZO, .{MMXEXT}),
    instr(.PMAXSW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xEE), .RM, .ZO, .{SSE2}),
    instr(.PMAXSB, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x3C), .RM, .ZO, .{SSE4_1}),
    instr(.PMAXSD, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x3D), .RM, .ZO, .{SSE4_1}),
    // PMAXUB / PMAXUW
    instr(.PMAXUB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xDE), .RM, .ZO, .{SSE}),
    instr(.PMAXUB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xDE), .RM, .ZO, .{MMXEXT}),
    instr(.PMAXUB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xDE), .RM, .ZO, .{SSE2}),
    instr(.PMAXUW, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x3E), .RM, .ZO, .{SSE4_1}),
    // PMAXUD
    instr(.PMAXUD, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x3F), .RM, .ZO, .{SSE4_1}),
    // PMINSB / PMINSW
    instr(.PMINSW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xEA), .RM, .ZO, .{SSE}),
    instr(.PMINSW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xEA), .RM, .ZO, .{MMXEXT}),
    instr(.PMINSW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xEA), .RM, .ZO, .{SSE2}),
    instr(.PMINSB, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x38), .RM, .ZO, .{SSE4_1}),
    // PMINSD
    instr(.PMINSD, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x39), .RM, .ZO, .{SSE4_1}),
    // PMINUB / PMINUW
    instr(.PMINUB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xDA), .RM, .ZO, .{SSE}),
    instr(.PMINUB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xDA), .RM, .ZO, .{MMXEXT}),
    instr(.PMINUB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xDA), .RM, .ZO, .{SSE2}),
    instr(.PMINUW, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x3A), .RM, .ZO, .{SSE4_1}),
    // PMINUD
    instr(.PMINUD, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x3B), .RM, .ZO, .{SSE4_1}),
    // PMOVMSKB
    instr(.PMOVMSKB, ops2(.reg32, .rm_mm), preOp2(._NP, 0x0F, 0xD7), .RM, .ZO, .{SSE}),
    instr(.PMOVMSKB, ops2(.reg32, .rm_mm), preOp2(._NP, 0x0F, 0xD7), .RM, .ZO, .{MMXEXT}),
    instr(.PMOVMSKB, ops2(.reg64, .rm_mm), preOp2(._NP, 0x0F, 0xD7), .RM, .ZO, .{ SSE, No32 }),
    instr(.PMOVMSKB, ops2(.reg64, .rm_mm), preOp2(._NP, 0x0F, 0xD7), .RM, .ZO, .{ MMXEXT, No32 }),
    instr(.PMOVMSKB, ops2(.reg32, .rm_xmml), preOp2(._66, 0x0F, 0xD7), .RM, .ZO, .{SSE}),
    instr(.PMOVMSKB, ops2(.reg64, .rm_xmml), preOp2(._66, 0x0F, 0xD7), .RM, .ZO, .{ SSE, No32 }),
    // PMOVSX
    instr(.PMOVSXBW, ops2(.xmml, .xmml_m64), preOp3(._66, 0x0F, 0x38, 0x20), .RM, .ZO, .{SSE4_1}),
    instr(.PMOVSXBD, ops2(.xmml, .xmml_m32), preOp3(._66, 0x0F, 0x38, 0x21), .RM, .ZO, .{SSE4_1}),
    instr(.PMOVSXBQ, ops2(.xmml, .xmml_m16), preOp3(._66, 0x0F, 0x38, 0x22), .RM, .ZO, .{SSE4_1}),
    //
    instr(.PMOVSXWD, ops2(.xmml, .xmml_m64), preOp3(._66, 0x0F, 0x38, 0x23), .RM, .ZO, .{SSE4_1}),
    instr(.PMOVSXWQ, ops2(.xmml, .xmml_m32), preOp3(._66, 0x0F, 0x38, 0x24), .RM, .ZO, .{SSE4_1}),
    instr(.PMOVSXDQ, ops2(.xmml, .xmml_m64), preOp3(._66, 0x0F, 0x38, 0x25), .RM, .ZO, .{SSE4_1}),
    // PMOVZX
    instr(.PMOVZXBW, ops2(.xmml, .xmml_m64), preOp3(._66, 0x0F, 0x38, 0x30), .RM, .ZO, .{SSE4_1}),
    instr(.PMOVZXBD, ops2(.xmml, .xmml_m32), preOp3(._66, 0x0F, 0x38, 0x31), .RM, .ZO, .{SSE4_1}),
    instr(.PMOVZXBQ, ops2(.xmml, .xmml_m16), preOp3(._66, 0x0F, 0x38, 0x32), .RM, .ZO, .{SSE4_1}),
    //
    instr(.PMOVZXWD, ops2(.xmml, .xmml_m64), preOp3(._66, 0x0F, 0x38, 0x33), .RM, .ZO, .{SSE4_1}),
    instr(.PMOVZXWQ, ops2(.xmml, .xmml_m32), preOp3(._66, 0x0F, 0x38, 0x34), .RM, .ZO, .{SSE4_1}),
    instr(.PMOVZXDQ, ops2(.xmml, .xmml_m64), preOp3(._66, 0x0F, 0x38, 0x35), .RM, .ZO, .{SSE4_1}),
    // PMULDQ
    instr(.PMULDQ, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x28), .RM, .ZO, .{SSE4_1}),
    // PMULHRSW
    instr(.PMULHRSW, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x0B), .RM, .ZO, .{SSSE3}),
    instr(.PMULHRSW, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x0B), .RM, .ZO, .{SSSE3}),
    // PMULHUW
    instr(.PMULHUW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xE4), .RM, .ZO, .{SSE}),
    instr(.PMULHUW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xE4), .RM, .ZO, .{MMXEXT}),
    instr(.PMULHUW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xE4), .RM, .ZO, .{SSE2}),
    // PMULHW
    instr(.PMULHW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xE5), .RM, .ZO, .{MMX}),
    instr(.PMULHW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xE5), .RM, .ZO, .{SSE2}),
    // PMULLD
    instr(.PMULLD, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x40), .RM, .ZO, .{SSE4_1}),
    // PMULLW
    instr(.PMULLW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xD5), .RM, .ZO, .{MMX}),
    instr(.PMULLW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xD5), .RM, .ZO, .{SSE2}),
    // PMULUDQ
    instr(.PMULUDQ, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xF4), .RM, .ZO, .{SSE2}),
    instr(.PMULUDQ, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xF4), .RM, .ZO, .{SSE2}),
    // POR
    instr(.POR, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xEB), .RM, .ZO, .{MMX}),
    instr(.POR, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xEB), .RM, .ZO, .{SSE2}),
    // PSADBW
    instr(.PSADBW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xF6), .RM, .ZO, .{SSE}),
    instr(.PSADBW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xF6), .RM, .ZO, .{MMXEXT}),
    instr(.PSADBW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xF6), .RM, .ZO, .{SSE2}),
    // PSHUFB
    instr(.PSHUFB, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x00), .RM, .ZO, .{SSSE3}),
    instr(.PSHUFB, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x00), .RM, .ZO, .{SSSE3}),
    // PSHUFD
    instr(.PSHUFD, ops3(.xmml, .xmml_m128, .imm8), preOp2(._66, 0x0F, 0x70), .RMI, .ZO, .{SSE2}),
    // PSHUFHW
    instr(.PSHUFHW, ops3(.xmml, .xmml_m128, .imm8), preOp2(._F3, 0x0F, 0x70), .RMI, .ZO, .{SSE2}),
    // PSHUFLW
    instr(.PSHUFLW, ops3(.xmml, .xmml_m128, .imm8), preOp2(._F2, 0x0F, 0x70), .RMI, .ZO, .{SSE2}),
    // PSHUFW
    instr(.PSHUFW, ops3(.mm, .mm_m64, .imm8), preOp2(._NP, 0x0F, 0x70), .RMI, .ZO, .{SSE}),
    instr(.PSHUFW, ops3(.mm, .mm_m64, .imm8), preOp2(._NP, 0x0F, 0x70), .RMI, .ZO, .{MMXEXT}),
    // PSIGNB / PSIGNW / PSIGND
    instr(.PSIGNB, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x08), .RM, .ZO, .{SSSE3}),
    instr(.PSIGNB, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x08), .RM, .ZO, .{SSSE3}),
    //
    instr(.PSIGNW, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x09), .RM, .ZO, .{SSSE3}),
    instr(.PSIGNW, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x09), .RM, .ZO, .{SSSE3}),
    //
    instr(.PSIGND, ops2(.mm, .mm_m64), preOp3(._NP, 0x0F, 0x38, 0x0A), .RM, .ZO, .{SSSE3}),
    instr(.PSIGND, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x0A), .RM, .ZO, .{SSSE3}),
    // PSLLDQ
    instr(.PSLLDQ, ops2(.rm_xmml, .imm8), preOp2r(._66, 0x0F, 0x73, 7), .MI, .ZO, .{SSE2}),
    // PSLLW / PSLLD / PSLLQ
    // PSLLW
    instr(.PSLLW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xF1), .RM, .ZO, .{MMX}),
    instr(.PSLLW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xF1), .RM, .ZO, .{SSE2}),
    //
    instr(.PSLLW, ops2(.rm_mm, .imm8), preOp2r(._NP, 0x0F, 0x71, 6), .MI, .ZO, .{MMX}),
    instr(.PSLLW, ops2(.rm_xmml, .imm8), preOp2r(._66, 0x0F, 0x71, 6), .MI, .ZO, .{SSE2}),
    // PSLLD
    instr(.PSLLD, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xF2), .RM, .ZO, .{MMX}),
    instr(.PSLLD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xF2), .RM, .ZO, .{SSE2}),
    //
    instr(.PSLLD, ops2(.rm_mm, .imm8), preOp2r(._NP, 0x0F, 0x72, 6), .MI, .ZO, .{MMX}),
    instr(.PSLLD, ops2(.rm_xmml, .imm8), preOp2r(._66, 0x0F, 0x72, 6), .MI, .ZO, .{SSE2}),
    // PSLLQ
    instr(.PSLLQ, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xF3), .RM, .ZO, .{MMX}),
    instr(.PSLLQ, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xF3), .RM, .ZO, .{SSE2}),
    //
    instr(.PSLLQ, ops2(.rm_mm, .imm8), preOp2r(._NP, 0x0F, 0x73, 6), .MI, .ZO, .{MMX}),
    instr(.PSLLQ, ops2(.rm_xmml, .imm8), preOp2r(._66, 0x0F, 0x73, 6), .MI, .ZO, .{SSE2}),
    // PSRAW / PSRAD
    // PSRAW
    instr(.PSRAW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xE1), .RM, .ZO, .{MMX}),
    instr(.PSRAW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xE1), .RM, .ZO, .{SSE2}),
    //
    instr(.PSRAW, ops2(.mm, .imm8), preOp2r(._NP, 0x0F, 0x71, 4), .MI, .ZO, .{MMX}),
    instr(.PSRAW, ops2(.xmml, .imm8), preOp2r(._66, 0x0F, 0x71, 4), .MI, .ZO, .{SSE2}),
    // PSRAD
    instr(.PSRAD, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xE2), .RM, .ZO, .{MMX}),
    instr(.PSRAD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xE2), .RM, .ZO, .{SSE2}),
    //
    instr(.PSRAD, ops2(.mm, .imm8), preOp2r(._NP, 0x0F, 0x72, 4), .MI, .ZO, .{MMX}),
    instr(.PSRAD, ops2(.xmml, .imm8), preOp2r(._66, 0x0F, 0x72, 4), .MI, .ZO, .{SSE2}),
    // PSRLDQ
    instr(.PSRLDQ, ops2(.rm_xmml, .imm8), preOp2r(._66, 0x0F, 0x73, 3), .MI, .ZO, .{SSE2}),
    // PSRLW / PSRLD / PSRLQ
    // PSRLW
    instr(.PSRLW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xD1), .RM, .ZO, .{MMX}),
    instr(.PSRLW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xD1), .RM, .ZO, .{SSE2}),
    //
    instr(.PSRLW, ops2(.mm, .imm8), preOp2r(._NP, 0x0F, 0x71, 2), .MI, .ZO, .{MMX}),
    instr(.PSRLW, ops2(.xmml, .imm8), preOp2r(._66, 0x0F, 0x71, 2), .MI, .ZO, .{SSE2}),
    // PSRLD
    instr(.PSRLD, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xD2), .RM, .ZO, .{MMX}),
    instr(.PSRLD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xD2), .RM, .ZO, .{SSE2}),
    //
    instr(.PSRLD, ops2(.mm, .imm8), preOp2r(._NP, 0x0F, 0x72, 2), .MI, .ZO, .{MMX}),
    instr(.PSRLD, ops2(.xmml, .imm8), preOp2r(._66, 0x0F, 0x72, 2), .MI, .ZO, .{SSE2}),
    // PSRLQ
    instr(.PSRLQ, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xD3), .RM, .ZO, .{MMX}),
    instr(.PSRLQ, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xD3), .RM, .ZO, .{SSE2}),
    //
    instr(.PSRLQ, ops2(.mm, .imm8), preOp2r(._NP, 0x0F, 0x73, 2), .MI, .ZO, .{MMX}),
    instr(.PSRLQ, ops2(.xmml, .imm8), preOp2r(._66, 0x0F, 0x73, 2), .MI, .ZO, .{SSE2}),
    // PSUBB / PSUBW / PSUBD
    // PSUBB
    instr(.PSUBB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xF8), .RM, .ZO, .{MMX}),
    instr(.PSUBB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xF8), .RM, .ZO, .{SSE2}),
    // PSUBW
    instr(.PSUBW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xF9), .RM, .ZO, .{MMX}),
    instr(.PSUBW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xF9), .RM, .ZO, .{SSE2}),
    // PSUBD
    instr(.PSUBD, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xFA), .RM, .ZO, .{MMX}),
    instr(.PSUBD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xFA), .RM, .ZO, .{SSE2}),
    // PSUBQ
    instr(.PSUBQ, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xFB), .RM, .ZO, .{SSE2}),
    instr(.PSUBQ, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xFB), .RM, .ZO, .{SSE2}),
    // PSUBSB / PSUBSW
    // PSUBSB
    instr(.PSUBSB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xE8), .RM, .ZO, .{MMX}),
    instr(.PSUBSB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xE8), .RM, .ZO, .{SSE2}),
    // PSUBSW
    instr(.PSUBSW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xE9), .RM, .ZO, .{MMX}),
    instr(.PSUBSW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xE9), .RM, .ZO, .{SSE2}),
    // PSUBUSB / PSUBUSW
    // PSUBUSB
    instr(.PSUBUSB, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xD8), .RM, .ZO, .{MMX}),
    instr(.PSUBUSB, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xD8), .RM, .ZO, .{SSE2}),
    // PSUBUSW
    instr(.PSUBUSW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xD9), .RM, .ZO, .{MMX}),
    instr(.PSUBUSW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xD9), .RM, .ZO, .{SSE2}),
    // PTEST
    instr(.PTEST, ops2(.xmml, .xmml_m128), preOp3(._66, 0x0F, 0x38, 0x17), .RM, .ZO, .{SSE4_1}),
    // PUNPCKHBW / PUNPCKHWD / PUNPCKHDQ / PUNPCKHQDQ
    instr(.PUNPCKHBW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x68), .RM, .ZO, .{MMX}),
    instr(.PUNPCKHBW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x68), .RM, .ZO, .{SSE2}),
    //
    instr(.PUNPCKHWD, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x69), .RM, .ZO, .{MMX}),
    instr(.PUNPCKHWD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x69), .RM, .ZO, .{SSE2}),
    //
    instr(.PUNPCKHDQ, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x6A), .RM, .ZO, .{MMX}),
    instr(.PUNPCKHDQ, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x6A), .RM, .ZO, .{SSE2}),
    //
    instr(.PUNPCKHQDQ, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x6D), .RM, .ZO, .{SSE2}),
    // PUNPCKLBW / PUNPCKLWD / PUNPCKLDQ / PUNPCKLQDQ
    instr(.PUNPCKLBW, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x60), .RM, .ZO, .{MMX}),
    instr(.PUNPCKLBW, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x60), .RM, .ZO, .{SSE2}),
    //
    instr(.PUNPCKLWD, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x61), .RM, .ZO, .{MMX}),
    instr(.PUNPCKLWD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x61), .RM, .ZO, .{SSE2}),
    //
    instr(.PUNPCKLDQ, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0x62), .RM, .ZO, .{MMX}),
    instr(.PUNPCKLDQ, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x62), .RM, .ZO, .{SSE2}),
    //
    instr(.PUNPCKLQDQ, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x6C), .RM, .ZO, .{SSE2}),
    // PXOR
    instr(.PXOR, ops2(.mm, .mm_m64), preOp2(._NP, 0x0F, 0xEF), .RM, .ZO, .{MMX}),
    instr(.PXOR, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0xEF), .RM, .ZO, .{SSE2}),
    // RCPPS
    instr(.RCPPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x53), .RM, .ZO, .{SSE}),
    // RCPSS
    instr(.RCPSS, ops2(.xmml, .xmml_m32), preOp2(._F3, 0x0F, 0x53), .RM, .ZO, .{SSE}),
    // ROUNDPD
    instr(.ROUNDPD, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x09), .RMI, .ZO, .{SSE4_1}),
    // ROUNDPS
    instr(.ROUNDPS, ops3(.xmml, .xmml_m128, .imm8), preOp3(._66, 0x0F, 0x3A, 0x08), .RMI, .ZO, .{SSE4_1}),
    // ROUNDSD
    instr(.ROUNDSD, ops3(.xmml, .xmml_m64, .imm8), preOp3(._66, 0x0F, 0x3A, 0x0B), .RMI, .ZO, .{SSE4_1}),
    // ROUNDSS
    instr(.ROUNDSS, ops3(.xmml, .xmml_m32, .imm8), preOp3(._66, 0x0F, 0x3A, 0x0A), .RMI, .ZO, .{SSE4_1}),
    // RSQRTPS
    instr(.RSQRTPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x52), .RM, .ZO, .{SSE}),
    // RSQRTSS
    instr(.RSQRTSS, ops2(.xmml, .xmml_m32), preOp2(._F3, 0x0F, 0x52), .RM, .ZO, .{SSE}),
    // SHUFPD
    instr(.SHUFPD, ops3(.xmml, .xmml_m128, .imm8), preOp2(._66, 0x0F, 0xC6), .RMI, .ZO, .{SSE2}),
    // SHUFPS
    instr(.SHUFPS, ops3(.xmml, .xmml_m128, .imm8), preOp2(._NP, 0x0F, 0xC6), .RMI, .ZO, .{SSE}),
    // SQRTPD
    instr(.SQRTPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x51), .RM, .ZO, .{SSE2}),
    // SQRTPS
    instr(.SQRTPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x51), .RM, .ZO, .{SSE}),
    // SQRTSD
    instr(.SQRTSD, ops2(.xmml, .xmml_m64), preOp2(._F2, 0x0F, 0x51), .RM, .ZO, .{SSE2}),
    // SQRTSS
    instr(.SQRTSS, ops2(.xmml, .xmml_m32), preOp2(._F3, 0x0F, 0x51), .RM, .ZO, .{SSE}),
    // SUBPD
    instr(.SUBPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x5C), .RM, .ZO, .{SSE2}),
    // SUBPS
    instr(.SUBPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x5C), .RM, .ZO, .{SSE}),
    // SUBSD
    instr(.SUBSD, ops2(.xmml, .xmml_m64), preOp2(._F2, 0x0F, 0x5C), .RM, .ZO, .{SSE2}),
    // SUBSS
    instr(.SUBSS, ops2(.xmml, .xmml_m32), preOp2(._F3, 0x0F, 0x5C), .RM, .ZO, .{SSE}),
    // UCOMISD
    instr(.UCOMISD, ops2(.xmml, .xmml_m64), preOp2(._66, 0x0F, 0x2E), .RM, .ZO, .{SSE2}),
    // UCOMISS
    instr(.UCOMISS, ops2(.xmml, .xmml_m32), preOp2(._NP, 0x0F, 0x2E), .RM, .ZO, .{SSE}),
    // UNPCKHPD
    instr(.UNPCKHPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x15), .RM, .ZO, .{SSE2}),
    // UNPCKHPS
    instr(.UNPCKHPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x15), .RM, .ZO, .{SSE}),
    // UNPCKLPD
    instr(.UNPCKLPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x14), .RM, .ZO, .{SSE2}),
    // UNPCKLPS
    instr(.UNPCKLPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x14), .RM, .ZO, .{SSE}),
    // XORPD
    instr(.XORPD, ops2(.xmml, .xmml_m128), preOp2(._66, 0x0F, 0x57), .RM, .ZO, .{SSE2}),
    // XORPS
    instr(.XORPS, ops2(.xmml, .xmml_m128), preOp2(._NP, 0x0F, 0x57), .RM, .ZO, .{SSE}),

    //
    // 3DNow!
    //
    // FEMMS
    instr(.FEMMS, ops0(), Op2(0x0F, 0x0E), .RM, .ZO, .{cpu._3DNOW}),
    // PAVGUSB
    instr(.PAVGUSB, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0xBF), .RM, .ZO, .{cpu._3DNOW}),
    // PF2ID
    instr(.PF2ID, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x1D), .RM, .ZO, .{cpu._3DNOW}),
    // PFACC
    instr(.PFACC, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0xAE), .RM, .ZO, .{cpu._3DNOW}),
    // PFADD
    instr(.PFADD, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x9E), .RM, .ZO, .{cpu._3DNOW}),
    // PFCMPEQ
    instr(.PFCMPEQ, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0xB0), .RM, .ZO, .{cpu._3DNOW}),
    // PFCMPGE
    instr(.PFCMPGE, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x90), .RM, .ZO, .{cpu._3DNOW}),
    // PFCMPGT
    instr(.PFCMPGT, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0xA0), .RM, .ZO, .{cpu._3DNOW}),
    // PFMAX
    instr(.PFMAX, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0xA4), .RM, .ZO, .{cpu._3DNOW}),
    // PFMIN
    instr(.PFMIN, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x94), .RM, .ZO, .{cpu._3DNOW}),
    // PFMUL
    instr(.PFMUL, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0xB4), .RM, .ZO, .{cpu._3DNOW}),
    // PFRCP
    instr(.PFRCP, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x96), .RM, .ZO, .{cpu._3DNOW}),
    // PFRCPIT1
    instr(.PFRCPIT1, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0xA6), .RM, .ZO, .{cpu._3DNOW}),
    // PFRCPIT2
    instr(.PFRCPIT2, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0xB6), .RM, .ZO, .{cpu._3DNOW}),
    // PFRSQIT1
    instr(.PFRSQIT1, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0xA7), .RM, .ZO, .{cpu._3DNOW}),
    // PFRSQRT
    instr(.PFRSQRT, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x97), .RM, .ZO, .{cpu._3DNOW}),
    // PFSUB
    instr(.PFSUB, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x9A), .RM, .ZO, .{cpu._3DNOW}),
    // PFSUBR
    instr(.PFSUBR, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0xAA), .RM, .ZO, .{cpu._3DNOW}),
    // PI2FD
    instr(.PI2FD, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x0D), .RM, .ZO, .{cpu._3DNOW}),
    // PMULHRW
    instr(.PMULHRW, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x0C), .RM, .ZO, .{cpu._3DNOW}),
    instr(.PMULHRW, ops2(.mm, .mm_m64), Op2(0x0F, 0x59), .RM, .ZO, .{ cpu.EMMI, cpu.Cyrix }),
    // PREFETCH
    // see above
    // PREFETCHW
    // see above
    // PFRCPV
    instr(.PFRCPV, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x87), .RM, .ZO, .{ cpu._3DNOW, cpu.Cyrix }),
    // PFRSQRTV
    instr(.PFRSQRTV, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x86), .RM, .ZO, .{ cpu._3DNOW, cpu.Cyrix }),

    //
    // 3DNow! Extensions
    //
    // PF2IW
    instr(.PF2IW, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x1C), .RM, .ZO, .{cpu._3DNOWEXT}),
    // PFNACC
    instr(.PFNACC, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x8A), .RM, .ZO, .{cpu._3DNOWEXT}),
    // PFPNACC
    instr(.PFPNACC, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x8E), .RM, .ZO, .{cpu._3DNOWEXT}),
    // PI2FW
    instr(.PI2FW, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0x0C), .RM, .ZO, .{cpu._3DNOWEXT}),
    // PSWAPD
    instr(.PSWAPD, ops2(.mm, .mm_m64), Op3DNow(0x0F, 0x0F, 0xBB), .RM, .ZO, .{cpu._3DNOWEXT}),

    //
    // SSE4A
    //
    // EXTRQ
    instr(.EXTRQ, ops3(.rm_xmml, .imm8, .imm8), preOp2r(._66, 0x0F, 0x78, 0), .MII, .ZO, .{SSE4A}),
    instr(.EXTRQ, ops2(.xmml, .rm_xmml), preOp2(._66, 0x0F, 0x79), .RM, .ZO, .{SSE4A}),
    // INSERTQ
    instr(.INSERTQ, ops4(.xmml, .rm_xmml, .imm8, .imm8), preOp2r(._F2, 0x0F, 0x78, 0), .RMII, .ZO, .{SSE4A}),
    instr(.INSERTQ, ops2(.xmml, .rm_xmml), preOp2(._F2, 0x0F, 0x79), .RM, .ZO, .{SSE4A}),
    // MOVNTSD
    instr(.MOVNTSD, ops2(.rm_mem64, .xmml), preOp2(._F2, 0x0F, 0x2B), .MR, .ZO, .{SSE4A}),
    // MOVNTSS
    instr(.MOVNTSS, ops2(.rm_mem32, .xmml), preOp2(._F3, 0x0F, 0x2B), .MR, .ZO, .{SSE4A}),

    //
    // Cyrix EMMI (Extended Multi-Media Instructions)
    //
    // PADDSIW
    instr(.PADDSIW, ops2(.mm, .mm_m64), Op2(0x0F, 0x51), .RM, .ZO, .{ cpu.EMMI, cpu.Cyrix }),
    // PAVEB
    instr(.PAVEB, ops2(.mm, .mm_m64), Op2(0x0F, 0x50), .RM, .ZO, .{ cpu.EMMI, cpu.Cyrix }),
    // PDISTIB
    instr(.PDISTIB, ops2(.mm, .rm_mem64), Op2(0x0F, 0x54), .RM, .ZO, .{ cpu.EMMI, cpu.Cyrix }),
    // PMACHRIW
    instr(.PMACHRIW, ops2(.mm, .rm_mem64), Op2(0x0F, 0x5E), .RM, .ZO, .{ cpu.EMMI, cpu.Cyrix }),
    // PMAGW
    instr(.PMAGW, ops2(.mm, .mm_m64), Op2(0x0F, 0x52), .RM, .ZO, .{ cpu.EMMI, cpu.Cyrix }),
    // PMULHRW / PMULHRIW
    // instr(.PMULHRW,   ops2(.mm, .mm_m64),     Op2(0x0F, 0x59),   .RM, .ZO, .{cpu.EMMI, cpu.Cyrix} ), // see above
    instr(.PMULHRIW, ops2(.mm, .mm_m64), Op2(0x0F, 0x5D), .RM, .ZO, .{ cpu.EMMI, cpu.Cyrix }),
    // PMVZB / PMVNZB / PMVLZB / PMVGEZB
    instr(.PMVZB, ops2(.mm, .rm_mem64), Op2(0x0F, 0x58), .RM, .ZO, .{ cpu.EMMI, cpu.Cyrix }),
    instr(.PMVNZB, ops2(.mm, .rm_mem64), Op2(0x0F, 0x5A), .RM, .ZO, .{ cpu.EMMI, cpu.Cyrix }),
    instr(.PMVLZB, ops2(.mm, .rm_mem64), Op2(0x0F, 0x5B), .RM, .ZO, .{ cpu.EMMI, cpu.Cyrix }),
    instr(.PMVGEZB, ops2(.mm, .rm_mem64), Op2(0x0F, 0x5C), .RM, .ZO, .{ cpu.EMMI, cpu.Cyrix }),
    // PSUBSIW
    instr(.PSUBSIW, ops2(.mm, .mm_m64), Op2(0x0F, 0x55), .RM, .ZO, .{ cpu.EMMI, cpu.Cyrix }),

    //
    // SIMD vector instructions (AVX, AVX2, AVX512)
    //
    // VADDPD
    vec(.VADDPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x58), .RVM, .{AVX}),
    vec(.VADDPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x58), .RVM, .{AVX}),
    vec(.VADDPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x58, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VADDPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x58, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VADDPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F, .W1, 0x58, full), .RVM, .{AVX512F}),
    // VADDPS
    vec(.VADDPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x58), .RVM, .{AVX}),
    vec(.VADDPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x58), .RVM, .{AVX}),
    vec(.VADDPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x58, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VADDPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x58, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VADDPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst_er), evex(.L512, ._NP, ._0F, .W0, 0x58, full), .RVM, .{AVX512F}),
    // VADDSD
    vec(.VADDSD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._F2, ._0F, .WIG, 0x58), .RVM, .{AVX}),
    vec(.VADDSD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._F2, ._0F, .W1, 0x58, t1s), .RVM, .{AVX512F}),
    // VADDSS
    vec(.VADDSS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._F3, ._0F, .WIG, 0x58), .RVM, .{AVX}),
    vec(.VADDSS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._F3, ._0F, .W0, 0x58, t1s), .RVM, .{AVX512F}),
    // VADDSUBPD
    vec(.VADDSUBPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xD0), .RVM, .{AVX}),
    vec(.VADDSUBPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xD0), .RVM, .{AVX}),
    // VADDSUBPS
    vec(.VADDSUBPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._F2, ._0F, .WIG, 0xD0), .RVM, .{AVX}),
    vec(.VADDSUBPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._F2, ._0F, .WIG, 0xD0), .RVM, .{AVX}),
    // VANDPD
    vec(.VANDPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x54), .RVM, .{AVX}),
    vec(.VANDPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x54), .RVM, .{AVX}),
    vec(.VANDPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x54, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VANDPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x54, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VANDPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0x54, full), .RVM, .{AVX512DQ}),
    // VANDPS
    vec(.VANDPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x54), .RVM, .{AVX}),
    vec(.VANDPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x54), .RVM, .{AVX}),
    vec(.VANDPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x54, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VANDPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x54, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VANDPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._NP, ._0F, .W0, 0x54, full), .RVM, .{AVX512DQ}),
    // VANDNPD
    vec(.VANDNPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x55), .RVM, .{AVX}),
    vec(.VANDNPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x55), .RVM, .{AVX}),
    vec(.VANDNPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x55, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VANDNPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x55, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VANDNPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0x55, full), .RVM, .{AVX512DQ}),
    // VANDNPS
    vec(.VANDNPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x55), .RVM, .{AVX}),
    vec(.VANDNPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x55), .RVM, .{AVX}),
    vec(.VANDNPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x55, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VANDNPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x55, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VANDNPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._NP, ._0F, .W0, 0x55, full), .RVM, .{AVX512DQ}),
    // VBLENDPS
    vec(.VBLENDPD, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x0D), .RVMI, .{AVX}),
    vec(.VBLENDPD, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .WIG, 0x0D), .RVMI, .{AVX}),
    // VBLENDPS
    vec(.VBLENDPS, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x0C), .RVMI, .{AVX}),
    vec(.VBLENDPS, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .WIG, 0x0C), .RVMI, .{AVX}),
    // VBLENDVPD
    vec(.VBLENDVPD, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x4B), .RVMR, .{AVX}),
    vec(.VBLENDVPD, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x4B), .RVMR, .{AVX}),
    // VBLENDVPS
    vec(.VBLENDVPS, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x4A), .RVMR, .{AVX}),
    vec(.VBLENDVPS, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x4A), .RVMR, .{AVX}),
    // VCMPPD
    vec(.VCMPPD, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F, .WIG, 0xC2), .RVMI, .{AVX}),
    vec(.VCMPPD, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F, .WIG, 0xC2), .RVMI, .{AVX}),
    vec(.VCMPPD, ops4(.reg_k_k, .xmm, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F, .W1, 0xC2, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VCMPPD, ops4(.reg_k_k, .ymm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F, .W1, 0xC2, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VCMPPD, ops4(.reg_k_k, .zmm, .zmm_m512_m64bcst_sae, .imm8), evex(.L512, ._66, ._0F, .W1, 0xC2, full), .RVMI, .{AVX512F}),
    // VCMPPS
    vec(.VCMPPS, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._NP, ._0F, .WIG, 0xC2), .RVMI, .{AVX}),
    vec(.VCMPPS, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._NP, ._0F, .WIG, 0xC2), .RVMI, .{AVX}),
    vec(.VCMPPS, ops4(.reg_k_k, .xmm, .xmm_m128_m32bcst, .imm8), evex(.L128, ._NP, ._0F, .W0, 0xC2, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VCMPPS, ops4(.reg_k_k, .ymm, .ymm_m256_m32bcst, .imm8), evex(.L256, ._NP, ._0F, .W0, 0xC2, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VCMPPS, ops4(.reg_k_k, .zmm, .zmm_m512_m32bcst_sae, .imm8), evex(.L512, ._NP, ._0F, .W0, 0xC2, full), .RVMI, .{AVX512F}),
    // VCMPSD
    vec(.VCMPSD, ops4(.xmml, .xmml, .xmml_m64, .imm8), vex(.LIG, ._F2, ._0F, .WIG, 0xC2), .RVMI, .{AVX}),
    vec(.VCMPSD, ops4(.reg_k_k, .xmm, .xmm_m64_sae, .imm8), evex(.LIG, ._F2, ._0F, .W1, 0xC2, t1s), .RVMI, .{ AVX512VL, AVX512F }),
    // VCMPSS
    vec(.VCMPSS, ops4(.xmml, .xmml, .xmml_m32, .imm8), vex(.LIG, ._F3, ._0F, .WIG, 0xC2), .RVMI, .{AVX}),
    vec(.VCMPSS, ops4(.reg_k_k, .xmm, .xmm_m32_sae, .imm8), evex(.LIG, ._F3, ._0F, .W0, 0xC2, t1s), .RVMI, .{ AVX512VL, AVX512F }),
    // VCOMISD
    vec(.VCOMISD, ops2(.xmml, .xmml_m64), vex(.LIG, ._66, ._0F, .WIG, 0x2F), .vRM, .{AVX}),
    vec(.VCOMISD, ops2(.xmm, .xmm_m64_sae), evex(.LIG, ._66, ._0F, .W1, 0x2F, t1s), .vRM, .{AVX512F}),
    // VCOMISS
    vec(.VCOMISS, ops2(.xmml, .xmml_m32), vex(.LIG, ._NP, ._0F, .WIG, 0x2F), .vRM, .{AVX}),
    vec(.VCOMISS, ops2(.xmm, .xmm_m32_sae), evex(.LIG, ._NP, ._0F, .W0, 0x2F, t1s), .vRM, .{AVX512F}),
    // VCVTDQ2PD
    vec(.VCVTDQ2PD, ops2(.xmml, .xmml_m64), vex(.L128, ._F3, ._0F, .WIG, 0xE6), .vRM, .{AVX}),
    vec(.VCVTDQ2PD, ops2(.ymml, .xmml_m128), vex(.L256, ._F3, ._0F, .WIG, 0xE6), .vRM, .{AVX}),
    vec(.VCVTDQ2PD, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._F3, ._0F, .W0, 0xE6, half), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTDQ2PD, ops2(.ymm_kz, .xmm_m128_m32bcst), evex(.L256, ._F3, ._0F, .W0, 0xE6, half), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTDQ2PD, ops2(.zmm_kz, .ymm_m256_m32bcst), evex(.L512, ._F3, ._0F, .W0, 0xE6, half), .vRM, .{AVX512F}),
    // VCVTDQ2PS
    vec(.VCVTDQ2PS, ops2(.xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x5B), .vRM, .{AVX}),
    vec(.VCVTDQ2PS, ops2(.ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x5B), .vRM, .{AVX}),
    vec(.VCVTDQ2PS, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x5B, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTDQ2PS, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x5B, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTDQ2PS, ops2(.zmm_kz, .zmm_m512_m32bcst_er), evex(.L512, ._NP, ._0F, .W0, 0x5B, full), .vRM, .{AVX512F}),
    // VCVTPD2DQ
    vec(.VCVTPD2DQ, ops2(.xmml, .xmml_m128), vex(.L128, ._F2, ._0F, .WIG, 0xE6), .vRM, .{AVX}),
    vec(.VCVTPD2DQ, ops2(.xmml, .ymml_m256), vex(.L256, ._F2, ._0F, .WIG, 0xE6), .vRM, .{AVX}),
    vec(.VCVTPD2DQ, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._F2, ._0F, .W1, 0xE6, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPD2DQ, ops2(.xmm_kz, .ymm_m256_m64bcst), evex(.L256, ._F2, ._0F, .W1, 0xE6, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPD2DQ, ops2(.ymm_kz, .zmm_m512_m64bcst_er), evex(.L512, ._F2, ._0F, .W1, 0xE6, full), .vRM, .{AVX512F}),
    // VCVTPD2PS
    vec(.VCVTPD2PS, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x5A), .vRM, .{AVX}),
    vec(.VCVTPD2PS, ops2(.xmml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x5A), .vRM, .{AVX}),
    vec(.VCVTPD2PS, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x5A, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPD2PS, ops2(.xmm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x5A, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPD2PS, ops2(.ymm_kz, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F, .W1, 0x5A, full), .vRM, .{AVX512F}),
    // VCVTPS2DQ
    vec(.VCVTPS2DQ, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x5B), .vRM, .{AVX}),
    vec(.VCVTPS2DQ, ops2(.ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x5B), .vRM, .{AVX}),
    vec(.VCVTPS2DQ, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F, .W0, 0x5B, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPS2DQ, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F, .W0, 0x5B, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPS2DQ, ops2(.zmm_kz, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F, .W0, 0x5B, full), .vRM, .{AVX512F}),
    // VCVTPS2PD
    vec(.VCVTPS2PD, ops2(.xmml, .xmml_m64), vex(.L128, ._NP, ._0F, .WIG, 0x5A), .vRM, .{AVX}),
    vec(.VCVTPS2PD, ops2(.ymml, .xmml_m128), vex(.L256, ._NP, ._0F, .WIG, 0x5A), .vRM, .{AVX}),
    vec(.VCVTPS2PD, ops2(.xmm_kz, .xmm_m64_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x5A, half), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPS2PD, ops2(.ymm_kz, .xmm_m128_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x5A, half), .vRM, .{AVX512VL}),
    vec(.VCVTPS2PD, ops2(.zmm_kz, .ymm_m256_m32bcst_sae), evex(.L512, ._NP, ._0F, .W0, 0x5A, half), .vRM, .{AVX512F}),
    // VCVTSD2SI
    vec(.VCVTSD2SI, ops2(.reg32, .xmml_m64), vex(.LIG, ._F2, ._0F, .W0, 0x2D), .vRM, .{AVX}),
    vec(.VCVTSD2SI, ops2(.reg64, .xmml_m64), vex(.LIG, ._F2, ._0F, .W1, 0x2D), .vRM, .{AVX}),
    vec(.VCVTSD2SI, ops2(.reg32, .xmm_m64_er), evex(.LIG, ._F2, ._0F, .W0, 0x2D, t1f), .vRM, .{AVX512F}),
    vec(.VCVTSD2SI, ops2(.reg64, .xmm_m64_er), evex(.LIG, ._F2, ._0F, .W1, 0x2D, t1f), .vRM, .{AVX512F}),
    // VCVTSD2SS
    vec(.VCVTSD2SS, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._F2, ._0F, .WIG, 0x5A), .RVM, .{AVX}),
    vec(.VCVTSD2SS, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._F2, ._0F, .W1, 0x5A, t1s), .RVM, .{AVX512F}),
    // VCVTSI2SD
    vec(.VCVTSI2SD, ops3(.xmml, .xmml, .rm32), vex(.LIG, ._F2, ._0F, .W0, 0x2A), .RVM, .{AVX}),
    vec(.VCVTSI2SD, ops3(.xmml, .xmml, .rm64), vex(.LIG, ._F2, ._0F, .W1, 0x2A), .RVM, .{ AVX, No32 }),
    vec(.VCVTSI2SD, ops3(.xmm, .xmm, .rm32), evex(.LIG, ._F2, ._0F, .W0, 0x2A, t1s), .RVM, .{AVX512F}),
    vec(.VCVTSI2SD, ops3(.xmm, .xmm, .rm64_er), evex(.LIG, ._F2, ._0F, .W1, 0x2A, t1s), .RVM, .{ AVX512F, No32 }),
    // VCVTSI2SS
    vec(.VCVTSI2SS, ops3(.xmml, .xmml, .rm32), vex(.LIG, ._F3, ._0F, .W0, 0x2A), .RVM, .{AVX}),
    vec(.VCVTSI2SS, ops3(.xmml, .xmml, .rm64), vex(.LIG, ._F3, ._0F, .W1, 0x2A), .RVM, .{ AVX, No32 }),
    vec(.VCVTSI2SS, ops3(.xmm, .xmm, .rm32_er), evex(.LIG, ._F3, ._0F, .W0, 0x2A, t1s), .RVM, .{AVX512F}),
    vec(.VCVTSI2SS, ops3(.xmm, .xmm, .rm64_er), evex(.LIG, ._F3, ._0F, .W1, 0x2A, t1s), .RVM, .{ AVX512F, No32 }),
    // VCVTSS2SD
    vec(.VCVTSS2SD, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._F3, ._0F, .WIG, 0x5A), .RVM, .{AVX}),
    vec(.VCVTSS2SD, ops3(.xmm_kz, .xmm, .xmm_m32_sae), evex(.LIG, ._F3, ._0F, .W0, 0x5A, t1s), .RVM, .{AVX512F}),
    // VCVTSS2SI
    vec(.VCVTSS2SI, ops2(.reg32, .xmml_m32), vex(.LIG, ._F3, ._0F, .W0, 0x2D), .vRM, .{AVX}),
    vec(.VCVTSS2SI, ops2(.reg64, .xmml_m32), vex(.LIG, ._F3, ._0F, .W1, 0x2D), .vRM, .{ AVX, No32 }),
    vec(.VCVTSS2SI, ops2(.reg32, .xmm_m32_er), evex(.LIG, ._F3, ._0F, .W0, 0x2D, t1f), .vRM, .{AVX512F}),
    vec(.VCVTSS2SI, ops2(.reg64, .xmm_m32_er), evex(.LIG, ._F3, ._0F, .W1, 0x2D, t1f), .vRM, .{ AVX512F, No32 }),
    // VCVTTPD2DQ
    vec(.VCVTTPD2DQ, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xE6), .vRM, .{AVX}),
    vec(.VCVTTPD2DQ, ops2(.xmml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xE6), .vRM, .{AVX}),
    vec(.VCVTTPD2DQ, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0xE6, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTTPD2DQ, ops2(.xmm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0xE6, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTTPD2DQ, ops2(.ymm_kz, .zmm_m512_m64bcst_sae), evex(.L512, ._66, ._0F, .W1, 0xE6, full), .vRM, .{AVX512F}),
    // VCVTTPS2DQ
    vec(.VCVTTPS2DQ, ops2(.xmml, .xmml_m128), vex(.L128, ._F3, ._0F, .WIG, 0x5B), .vRM, .{AVX}),
    vec(.VCVTTPS2DQ, ops2(.ymml, .ymml_m256), vex(.L256, ._F3, ._0F, .WIG, 0x5B), .vRM, .{AVX}),
    vec(.VCVTTPS2DQ, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._F3, ._0F, .W0, 0x5B, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTTPS2DQ, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._F3, ._0F, .W0, 0x5B, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTTPS2DQ, ops2(.zmm_kz, .zmm_m512_m32bcst_sae), evex(.L512, ._F3, ._0F, .W0, 0x5B, full), .vRM, .{AVX512F}),
    // VCVTTSD2SI
    vec(.VCVTTSD2SI, ops2(.reg32, .xmml_m64), vex(.LIG, ._F2, ._0F, .W0, 0x2C), .vRM, .{AVX}),
    vec(.VCVTTSD2SI, ops2(.reg64, .xmml_m64), vex(.LIG, ._F2, ._0F, .W1, 0x2C), .vRM, .{ AVX, No32 }),
    vec(.VCVTTSD2SI, ops2(.reg32, .xmm_m64_sae), evex(.LIG, ._F2, ._0F, .W0, 0x2C, t1f), .vRM, .{AVX512F}),
    vec(.VCVTTSD2SI, ops2(.reg64, .xmm_m64_sae), evex(.LIG, ._F2, ._0F, .W1, 0x2C, t1f), .vRM, .{ AVX512F, No32 }),
    // VCVTTSS2SI
    vec(.VCVTTSS2SI, ops2(.reg32, .xmml_m32), vex(.LIG, ._F3, ._0F, .W0, 0x2C), .vRM, .{AVX}),
    vec(.VCVTTSS2SI, ops2(.reg64, .xmml_m32), vex(.LIG, ._F3, ._0F, .W1, 0x2C), .vRM, .{ AVX, No32 }),
    vec(.VCVTTSS2SI, ops2(.reg32, .xmm_m32_sae), evex(.LIG, ._F3, ._0F, .W0, 0x2C, t1f), .vRM, .{AVX512F}),
    vec(.VCVTTSS2SI, ops2(.reg64, .xmm_m32_sae), evex(.LIG, ._F3, ._0F, .W1, 0x2C, t1f), .vRM, .{ AVX512F, No32 }),
    // VDIVPD
    vec(.VDIVPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x5E), .RVM, .{AVX}),
    vec(.VDIVPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x5E), .RVM, .{AVX}),
    vec(.VDIVPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x5E, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VDIVPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x5E, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VDIVPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F, .W1, 0x5E, full), .RVM, .{AVX512F}),
    // VDIVPS
    vec(.VDIVPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x5E), .RVM, .{AVX}),
    vec(.VDIVPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x5E), .RVM, .{AVX}),
    vec(.VDIVPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x5E, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VDIVPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x5E, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VDIVPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst_er), evex(.L512, ._NP, ._0F, .W0, 0x5E, full), .RVM, .{AVX512F}),
    // VDIVSD
    vec(.VDIVSD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._F2, ._0F, .WIG, 0x5E), .RVM, .{AVX}),
    vec(.VDIVSD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._F2, ._0F, .W1, 0x5E, t1s), .RVM, .{AVX512F}),
    // VDIVSS
    vec(.VDIVSS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._F3, ._0F, .WIG, 0x5E), .RVM, .{AVX}),
    vec(.VDIVSS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._F3, ._0F, .W0, 0x5E, t1s), .RVM, .{AVX512F}),
    // VDPPD
    vec(.VDPPD, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x41), .RVMI, .{AVX}),
    // VDPPS
    vec(.VDPPS, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x40), .RVMI, .{AVX}),
    vec(.VDPPS, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .WIG, 0x40), .RVMI, .{AVX}),
    // VEXTRACTPS
    vec(.VEXTRACTPS, ops3(.rm32, .xmml, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x17), .vMRI, .{AVX}),
    vec(.VEXTRACTPS, ops3(.reg64, .xmml, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x17), .vMRI, .{ AVX, No32 }),
    vec(.VEXTRACTPS, ops3(.rm32, .xmm, .imm8), evex(.L128, ._66, ._0F3A, .WIG, 0x17, t1s), .vMRI, .{AVX512F}),
    vec(.VEXTRACTPS, ops3(.reg64, .xmm, .imm8), evex(.L128, ._66, ._0F3A, .WIG, 0x17, t1s), .vMRI, .{ AVX512F, No32 }),
    // VGF2P8AFFINEINVQB
    vec(.VGF2P8AFFINEINVQB, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .W1, 0xCF), .RVMI, .{ AVX, GFNI }),
    vec(.VGF2P8AFFINEINVQB, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .W1, 0xCF), .RVMI, .{ AVX, GFNI }),
    vec(.VGF2P8AFFINEINVQB, ops4(.xmm_kz, .xmm, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0xCF, full), .RVMI, .{ AVX512VL, GFNI }),
    vec(.VGF2P8AFFINEINVQB, ops4(.ymm_kz, .ymm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0xCF, full), .RVMI, .{ AVX512VL, GFNI }),
    vec(.VGF2P8AFFINEINVQB, ops4(.zmm_kz, .zmm, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0xCF, full), .RVMI, .{ AVX512F, GFNI }),
    // VGF2P8AFFINEQB
    vec(.VGF2P8AFFINEQB, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .W1, 0xCE), .RVMI, .{ AVX, GFNI }),
    vec(.VGF2P8AFFINEQB, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .W1, 0xCE), .RVMI, .{ AVX, GFNI }),
    vec(.VGF2P8AFFINEQB, ops4(.xmm_kz, .xmm, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0xCE, full), .RVMI, .{ AVX512VL, GFNI }),
    vec(.VGF2P8AFFINEQB, ops4(.ymm_kz, .ymm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0xCE, full), .RVMI, .{ AVX512VL, GFNI }),
    vec(.VGF2P8AFFINEQB, ops4(.zmm_kz, .zmm, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0xCE, full), .RVMI, .{ AVX512F, GFNI }),
    // VGF2P8MULB
    vec(.VGF2P8MULB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xCF), .RVM, .{ AVX, GFNI }),
    vec(.VGF2P8MULB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xCF), .RVM, .{ AVX, GFNI }),
    vec(.VGF2P8MULB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W0, 0xCF, fmem), .RVM, .{ AVX512VL, GFNI }),
    vec(.VGF2P8MULB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W0, 0xCF, fmem), .RVM, .{ AVX512VL, GFNI }),
    vec(.VGF2P8MULB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W0, 0xCF, fmem), .RVM, .{ AVX512F, GFNI }),
    // VHADDPD
    vec(.VHADDPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x7C), .RVM, .{AVX}),
    vec(.VHADDPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x7C), .RVM, .{AVX}),
    // VHADDPS
    vec(.VHADDPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._F2, ._0F, .WIG, 0x7C), .RVM, .{AVX}),
    vec(.VHADDPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._F2, ._0F, .WIG, 0x7C), .RVM, .{AVX}),
    // VHSUBPD
    vec(.VHSUBPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x7D), .RVM, .{AVX}),
    vec(.VHSUBPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x7D), .RVM, .{AVX}),
    // VHSUBPS
    vec(.VHSUBPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._F2, ._0F, .WIG, 0x7D), .RVM, .{AVX}),
    vec(.VHSUBPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._F2, ._0F, .WIG, 0x7D), .RVM, .{AVX}),
    // vecERTPS
    vec(.VINSERTPS, ops4(.xmml, .xmml, .xmml_m32, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x21), .RVMI, .{AVX}),
    vec(.VINSERTPS, ops4(.xmm, .xmm, .xmm_m32, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x21, t1s), .RVMI, .{AVX512F}),
    // LDDQU
    vec(.VLDDQU, ops2(.xmml, .rm_mem128), vex(.L128, ._F2, ._0F, .WIG, 0xF0), .vRM, .{AVX}),
    vec(.VLDDQU, ops2(.ymml, .rm_mem256), vex(.L256, ._F2, ._0F, .WIG, 0xF0), .vRM, .{AVX}),
    // VLDMXCSR
    vec(.VLDMXCSR, ops1(.rm_mem32), vexr(.LZ, ._NP, ._0F, .WIG, 0xAE, 2), .vM, .{AVX}),
    // VMASKMOVDQU
    vec(.VMASKMOVDQU, ops2(.xmml, .xmml), vex(.L128, ._66, ._0F, .WIG, 0xF7), .vRM, .{AVX}),
    // VMAXPD
    vec(.VMAXPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x5F), .RVM, .{AVX}),
    vec(.VMAXPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x5F), .RVM, .{AVX}),
    vec(.VMAXPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x5F, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VMAXPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x5F, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VMAXPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst_sae), evex(.L512, ._66, ._0F, .W1, 0x5F, full), .RVM, .{AVX512DQ}),
    // VMAXPS
    vec(.VMAXPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x5F), .RVM, .{AVX}),
    vec(.VMAXPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x5F), .RVM, .{AVX}),
    vec(.VMAXPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x5F, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VMAXPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x5F, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VMAXPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst_sae), evex(.L512, ._NP, ._0F, .W0, 0x5F, full), .RVM, .{AVX512DQ}),
    // VMAXSD
    vec(.VMAXSD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._F2, ._0F, .WIG, 0x5F), .RVM, .{AVX}),
    vec(.VMAXSD, ops3(.xmm_kz, .xmm, .xmm_m64_sae), evex(.LIG, ._F2, ._0F, .W1, 0x5F, t1s), .RVM, .{AVX512F}),
    // VMAXSS
    vec(.VMAXSS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._F3, ._0F, .WIG, 0x5F), .RVM, .{AVX}),
    vec(.VMAXSS, ops3(.xmm_kz, .xmm, .xmm_m32_sae), evex(.LIG, ._F3, ._0F, .W0, 0x5F, t1s), .RVM, .{AVX512F}),
    // VMINPD
    vec(.VMINPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x5D), .RVM, .{AVX}),
    vec(.VMINPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x5D), .RVM, .{AVX}),
    vec(.VMINPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x5D, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VMINPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x5D, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VMINPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst_sae), evex(.L512, ._66, ._0F, .W1, 0x5D, full), .RVM, .{AVX512DQ}),
    // VMINPS
    vec(.VMINPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x5D), .RVM, .{AVX}),
    vec(.VMINPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x5D), .RVM, .{AVX}),
    vec(.VMINPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x5D, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VMINPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x5D, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VMINPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst_sae), evex(.L512, ._NP, ._0F, .W0, 0x5D, full), .RVM, .{AVX512DQ}),
    // VMINSD
    vec(.VMINSD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._F2, ._0F, .WIG, 0x5D), .RVM, .{AVX}),
    vec(.VMINSD, ops3(.xmm_kz, .xmm, .xmm_m64_sae), evex(.LIG, ._F2, ._0F, .W1, 0x5D, t1s), .RVM, .{AVX512F}),
    // VMINSS
    vec(.VMINSS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._F3, ._0F, .WIG, 0x5D), .RVM, .{AVX}),
    vec(.VMINSS, ops3(.xmm_kz, .xmm, .xmm_m32_sae), evex(.LIG, ._F3, ._0F, .W0, 0x5D, t1s), .RVM, .{AVX512F}),
    // VMOVAPD
    vec(.VMOVAPD, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x28), .vRM, .{AVX}),
    vec(.VMOVAPD, ops2(.ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x28), .vRM, .{AVX}),
    vec(.VMOVAPD, ops2(.xmml_m128, .xmml), vex(.L128, ._66, ._0F, .WIG, 0x29), .vMR, .{AVX}),
    vec(.VMOVAPD, ops2(.ymml_m256, .ymml), vex(.L256, ._66, ._0F, .WIG, 0x29), .vMR, .{AVX}),
    //
    vec(.VMOVAPD, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F, .W1, 0x28, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVAPD, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F, .W1, 0x28, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVAPD, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F, .W1, 0x28, fmem), .vRM, .{AVX512F}),
    vec(.VMOVAPD, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._66, ._0F, .W1, 0x29, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVAPD, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._66, ._0F, .W1, 0x29, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVAPD, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._66, ._0F, .W1, 0x29, fmem), .vMR, .{AVX512F}),
    // VMOVAPS
    vec(.VMOVAPS, ops2(.xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x28), .vRM, .{AVX}),
    vec(.VMOVAPS, ops2(.ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x28), .vRM, .{AVX}),
    vec(.VMOVAPS, ops2(.xmml_m128, .xmml), vex(.L128, ._NP, ._0F, .WIG, 0x29), .vMR, .{AVX}),
    vec(.VMOVAPS, ops2(.ymml_m256, .ymml), vex(.L256, ._NP, ._0F, .WIG, 0x29), .vMR, .{AVX}),
    //
    vec(.VMOVAPS, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._NP, ._0F, .W0, 0x28, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVAPS, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._NP, ._0F, .W0, 0x28, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVAPS, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._NP, ._0F, .W0, 0x28, fmem), .vRM, .{AVX512F}),
    vec(.VMOVAPS, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._NP, ._0F, .W0, 0x29, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVAPS, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._NP, ._0F, .W0, 0x29, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVAPS, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._NP, ._0F, .W0, 0x29, fmem), .vMR, .{AVX512F}),
    // VMOVD
    // xmm[0..15]
    vec(.VMOVD, ops2(.xmml, .rm32), vex(.L128, ._66, ._0F, .W0, 0x6E), .vRM, .{AVX}),
    vec(.VMOVD, ops2(.rm32, .xmml), vex(.L128, ._66, ._0F, .W0, 0x7E), .vMR, .{AVX}),
    vec(.VMOVD, ops2(.xmml, .rm64), vex(.L128, ._66, ._0F, .W1, 0x6E), .vRM, .{ AVX, No32 }),
    vec(.VMOVD, ops2(.rm64, .xmml), vex(.L128, ._66, ._0F, .W1, 0x7E), .vMR, .{ AVX, No32 }),
    // xmm[0..31]
    vec(.VMOVD, ops2(.xmm, .rm32), evex(.L128, ._66, ._0F, .W0, 0x6E, t1s), .vRM, .{AVX512F}),
    vec(.VMOVD, ops2(.rm32, .xmm), evex(.L128, ._66, ._0F, .W0, 0x7E, t1s), .vMR, .{AVX512F}),
    vec(.VMOVD, ops2(.xmm, .rm64), evex(.L128, ._66, ._0F, .W1, 0x6E, t1s), .vRM, .{ AVX512F, No32 }),
    vec(.VMOVD, ops2(.rm64, .xmm), evex(.L128, ._66, ._0F, .W1, 0x7E, t1s), .vMR, .{ AVX512F, No32 }),
    // VMOVQ
    // xmm[0..15]
    vec(.VMOVQ, ops2(.xmml, .xmml_m64), vex(.L128, ._F3, ._0F, .WIG, 0x7E), .vRM, .{AVX}),
    vec(.VMOVQ, ops2(.xmml_m64, .xmml), vex(.L128, ._66, ._0F, .WIG, 0xD6), .vMR, .{AVX}),
    vec(.VMOVQ, ops2(.xmml, .rm64), vex(.L128, ._66, ._0F, .W1, 0x6E), .vRM, .{ AVX, No32 }),
    vec(.VMOVQ, ops2(.rm64, .xmml), vex(.L128, ._66, ._0F, .W1, 0x7E), .vMR, .{ AVX, No32 }),
    // xmm[0..31]
    vec(.VMOVQ, ops2(.xmm, .xmm_m64), evex(.L128, ._F3, ._0F, .W1, 0x7E, t1s), .vRM, .{AVX512F}),
    vec(.VMOVQ, ops2(.xmm_m64, .xmm), evex(.L128, ._66, ._0F, .W1, 0xD6, t1s), .vMR, .{AVX512F}),
    vec(.VMOVQ, ops2(.xmm, .rm64), evex(.L128, ._66, ._0F, .W1, 0x6E, t1s), .vRM, .{ AVX512F, No32 }),
    vec(.VMOVQ, ops2(.rm64, .xmm), evex(.L128, ._66, ._0F, .W1, 0x7E, t1s), .vMR, .{ AVX512F, No32 }),
    // VMOVDDUP
    vec(.VMOVDDUP, ops2(.xmml, .xmml_m64), vex(.L128, ._F2, ._0F, .WIG, 0x12), .vRM, .{AVX}),
    vec(.VMOVDDUP, ops2(.ymml, .ymml_m256), vex(.L256, ._F2, ._0F, .WIG, 0x12), .vRM, .{AVX}),
    vec(.VMOVDDUP, ops2(.xmm_kz, .xmm_m64), evex(.L128, ._F2, ._0F, .W1, 0x12, dup), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVDDUP, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._F2, ._0F, .W1, 0x12, dup), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVDDUP, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._F2, ._0F, .W1, 0x12, dup), .vRM, .{AVX512F}),
    // VMOVDQA / VMOVDQA32 / VMOVDQA64
    vec(.VMOVDQA, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x6F), .vRM, .{AVX}),
    vec(.VMOVDQA, ops2(.ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x6F), .vRM, .{AVX}),
    vec(.VMOVDQA, ops2(.xmml_m128, .xmml), vex(.L128, ._66, ._0F, .WIG, 0x7F), .vMR, .{AVX}),
    vec(.VMOVDQA, ops2(.ymml_m256, .ymml), vex(.L256, ._66, ._0F, .WIG, 0x7F), .vMR, .{AVX}),
    // VMOVDQA32
    vec(.VMOVDQA32, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F, .W0, 0x6F, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQA32, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F, .W0, 0x6F, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQA32, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F, .W0, 0x6F, fmem), .vRM, .{AVX512F}),
    vec(.VMOVDQA32, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._66, ._0F, .W0, 0x7F, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQA32, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._66, ._0F, .W0, 0x7F, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQA32, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._66, ._0F, .W0, 0x7F, fmem), .vMR, .{AVX512F}),
    // VMOVDQA64
    vec(.VMOVDQA64, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F, .W1, 0x6F, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQA64, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F, .W1, 0x6F, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQA64, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F, .W1, 0x6F, fmem), .vRM, .{AVX512F}),
    vec(.VMOVDQA64, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._66, ._0F, .W1, 0x7F, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQA64, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._66, ._0F, .W1, 0x7F, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQA64, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._66, ._0F, .W1, 0x7F, fmem), .vMR, .{AVX512F}),
    // VMOVDQU / VMOVDQU8 / VMOVDQU16 / VMOVDQU32 / VMOVDQU64
    vec(.VMOVDQU, ops2(.xmml, .xmml_m128), vex(.L128, ._F3, ._0F, .WIG, 0x6F), .vRM, .{AVX}),
    vec(.VMOVDQU, ops2(.ymml, .ymml_m256), vex(.L256, ._F3, ._0F, .WIG, 0x6F), .vRM, .{AVX}),
    vec(.VMOVDQU, ops2(.xmml_m128, .xmml), vex(.L128, ._F3, ._0F, .WIG, 0x7F), .vMR, .{AVX}),
    vec(.VMOVDQU, ops2(.ymml_m256, .ymml), vex(.L256, ._F3, ._0F, .WIG, 0x7F), .vMR, .{AVX}),
    // VMOVDQU8
    vec(.VMOVDQU8, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._F2, ._0F, .W0, 0x6F, fmem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VMOVDQU8, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._F2, ._0F, .W0, 0x6F, fmem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VMOVDQU8, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._F2, ._0F, .W0, 0x6F, fmem), .vRM, .{AVX512BW}),
    vec(.VMOVDQU8, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._F2, ._0F, .W0, 0x7F, fmem), .vMR, .{ AVX512VL, AVX512BW }),
    vec(.VMOVDQU8, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._F2, ._0F, .W0, 0x7F, fmem), .vMR, .{ AVX512VL, AVX512BW }),
    vec(.VMOVDQU8, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._F2, ._0F, .W0, 0x7F, fmem), .vMR, .{AVX512BW}),
    // VMOVDQU16
    vec(.VMOVDQU16, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._F2, ._0F, .W1, 0x6F, fmem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VMOVDQU16, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._F2, ._0F, .W1, 0x6F, fmem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VMOVDQU16, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._F2, ._0F, .W1, 0x6F, fmem), .vRM, .{AVX512BW}),
    vec(.VMOVDQU16, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._F2, ._0F, .W1, 0x7F, fmem), .vMR, .{ AVX512VL, AVX512BW }),
    vec(.VMOVDQU16, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._F2, ._0F, .W1, 0x7F, fmem), .vMR, .{ AVX512VL, AVX512BW }),
    vec(.VMOVDQU16, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._F2, ._0F, .W1, 0x7F, fmem), .vMR, .{AVX512BW}),
    // VMOVDQU32
    vec(.VMOVDQU32, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._F3, ._0F, .W0, 0x6F, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQU32, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._F3, ._0F, .W0, 0x6F, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQU32, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._F3, ._0F, .W0, 0x6F, fmem), .vRM, .{AVX512F}),
    vec(.VMOVDQU32, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._F3, ._0F, .W0, 0x7F, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQU32, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._F3, ._0F, .W0, 0x7F, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQU32, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._F3, ._0F, .W0, 0x7F, fmem), .vMR, .{AVX512F}),
    // VMOVDQU64
    vec(.VMOVDQU64, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._F3, ._0F, .W1, 0x6F, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQU64, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._F3, ._0F, .W1, 0x6F, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQU64, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._F3, ._0F, .W1, 0x6F, fmem), .vRM, .{AVX512F}),
    vec(.VMOVDQU64, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._F3, ._0F, .W1, 0x7F, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQU64, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._F3, ._0F, .W1, 0x7F, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVDQU64, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._F3, ._0F, .W1, 0x7F, fmem), .vMR, .{AVX512F}),
    // VMOVHLPS
    vec(.VMOVHLPS, ops3(.xmml, .xmml, .xmml), vex(.L128, ._NP, ._0F, .WIG, 0x12), .RVM, .{AVX}),
    vec(.VMOVHLPS, ops3(.xmm, .xmm, .xmm), evex(.L128, ._NP, ._0F, .W0, 0x12, nomem), .RVM, .{AVX512F}),
    // VMOVHPD
    vec(.VMOVHPD, ops3(.xmml, .xmml, .rm_mem64), vex(.L128, ._66, ._0F, .WIG, 0x16), .RVM, .{AVX}),
    vec(.VMOVHPD, ops2(.rm_mem64, .xmml), vex(.L128, ._66, ._0F, .WIG, 0x17), .vMR, .{AVX}),
    vec(.VMOVHPD, ops3(.xmm, .xmm, .rm_mem64), evex(.L128, ._66, ._0F, .W1, 0x16, t1s), .RVM, .{AVX512F}),
    vec(.VMOVHPD, ops2(.rm_mem64, .xmm), evex(.L128, ._66, ._0F, .W1, 0x17, t1s), .vMR, .{AVX512F}),
    // VMOVHPS
    vec(.VMOVHPS, ops3(.xmml, .xmml, .rm_mem64), vex(.L128, ._NP, ._0F, .WIG, 0x16), .RVM, .{AVX}),
    vec(.VMOVHPS, ops2(.rm_mem64, .xmml), vex(.L128, ._NP, ._0F, .WIG, 0x17), .vMR, .{AVX}),
    vec(.VMOVHPS, ops3(.xmm, .xmm, .rm_mem64), evex(.L128, ._NP, ._0F, .W0, 0x16, tup2), .RVM, .{AVX512F}),
    vec(.VMOVHPS, ops2(.rm_mem64, .xmm), evex(.L128, ._NP, ._0F, .W0, 0x17, tup2), .vMR, .{AVX512F}),
    // VMOVLHPS
    vec(.VMOVLHPS, ops3(.xmml, .xmml, .xmml), vex(.L128, ._NP, ._0F, .WIG, 0x16), .RVM, .{AVX}),
    vec(.VMOVLHPS, ops3(.xmm, .xmm, .xmm), evex(.L128, ._NP, ._0F, .W0, 0x16, nomem), .RVM, .{AVX512F}),
    // VMOVLPD
    vec(.VMOVLPD, ops3(.xmml, .xmml, .rm_mem64), vex(.L128, ._66, ._0F, .WIG, 0x12), .RVM, .{AVX}),
    vec(.VMOVLPD, ops2(.rm_mem64, .xmml), vex(.L128, ._66, ._0F, .WIG, 0x13), .vMR, .{AVX}),
    vec(.VMOVLPD, ops3(.xmm, .xmm, .rm_mem64), evex(.L128, ._66, ._0F, .W1, 0x12, t1s), .RVM, .{AVX512F}),
    vec(.VMOVLPD, ops2(.rm_mem64, .xmm), evex(.L128, ._66, ._0F, .W1, 0x13, t1s), .vMR, .{AVX512F}),
    // VMOVLPS
    vec(.VMOVLPS, ops3(.xmml, .xmml, .rm_mem64), vex(.L128, ._NP, ._0F, .WIG, 0x12), .RVM, .{AVX}),
    vec(.VMOVLPS, ops2(.rm_mem64, .xmml), vex(.L128, ._NP, ._0F, .WIG, 0x13), .vMR, .{AVX}),
    vec(.VMOVLPS, ops3(.xmm, .xmm, .rm_mem64), evex(.L128, ._NP, ._0F, .W0, 0x12, tup2), .RVM, .{AVX512F}),
    vec(.VMOVLPS, ops2(.rm_mem64, .xmm), evex(.L128, ._NP, ._0F, .W0, 0x13, tup2), .vMR, .{AVX512F}),
    // VMOVMSKPD
    vec(.VMOVMSKPD, ops2(.reg32, .xmml), vex(.L128, ._66, ._0F, .WIG, 0x50), .vRM, .{AVX}),
    vec(.VMOVMSKPD, ops2(.reg64, .xmml), vex(.L128, ._66, ._0F, .WIG, 0x50), .vRM, .{AVX}),
    vec(.VMOVMSKPD, ops2(.reg32, .ymml), vex(.L256, ._66, ._0F, .WIG, 0x50), .vRM, .{AVX}),
    vec(.VMOVMSKPD, ops2(.reg64, .ymml), vex(.L256, ._66, ._0F, .WIG, 0x50), .vRM, .{AVX}),
    // VMOVMSKPS
    vec(.VMOVMSKPS, ops2(.reg32, .xmml), vex(.L128, ._NP, ._0F, .WIG, 0x50), .vRM, .{AVX}),
    vec(.VMOVMSKPS, ops2(.reg64, .xmml), vex(.L128, ._NP, ._0F, .WIG, 0x50), .vRM, .{AVX}),
    vec(.VMOVMSKPS, ops2(.reg32, .ymml), vex(.L256, ._NP, ._0F, .WIG, 0x50), .vRM, .{AVX}),
    vec(.VMOVMSKPS, ops2(.reg64, .ymml), vex(.L256, ._NP, ._0F, .WIG, 0x50), .vRM, .{AVX}),
    // VMOVNTDQA
    vec(.VMOVNTDQA, ops2(.xmml, .rm_mem128), vex(.L128, ._66, ._0F38, .WIG, 0x2A), .vRM, .{AVX}),
    vec(.VMOVNTDQA, ops2(.ymml, .rm_mem256), vex(.L256, ._66, ._0F38, .WIG, 0x2A), .vRM, .{AVX2}),
    vec(.VMOVNTDQA, ops2(.xmm, .rm_mem128), evex(.L128, ._66, ._0F38, .W0, 0x2A, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVNTDQA, ops2(.ymm, .rm_mem256), evex(.L256, ._66, ._0F38, .W0, 0x2A, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVNTDQA, ops2(.zmm, .rm_mem512), evex(.L512, ._66, ._0F38, .W0, 0x2A, fmem), .vRM, .{AVX512F}),
    // VMOVNTDQ
    vec(.VMOVNTDQ, ops2(.rm_mem128, .xmml), vex(.L128, ._66, ._0F, .WIG, 0xE7), .vMR, .{AVX}),
    vec(.VMOVNTDQ, ops2(.rm_mem256, .ymml), vex(.L256, ._66, ._0F, .WIG, 0xE7), .vMR, .{AVX}),
    vec(.VMOVNTDQ, ops2(.rm_mem128, .xmm), evex(.L128, ._66, ._0F, .W0, 0xE7, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVNTDQ, ops2(.rm_mem256, .ymm), evex(.L256, ._66, ._0F, .W0, 0xE7, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVNTDQ, ops2(.rm_mem512, .zmm), evex(.L512, ._66, ._0F, .W0, 0xE7, fmem), .vMR, .{AVX512F}),
    // VMOVNTPD
    vec(.VMOVNTPD, ops2(.rm_mem128, .xmml), vex(.L128, ._66, ._0F, .WIG, 0x2B), .vMR, .{AVX}),
    vec(.VMOVNTPD, ops2(.rm_mem256, .ymml), vex(.L256, ._66, ._0F, .WIG, 0x2B), .vMR, .{AVX}),
    vec(.VMOVNTPD, ops2(.rm_mem128, .xmm), evex(.L128, ._66, ._0F, .W1, 0x2B, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVNTPD, ops2(.rm_mem256, .ymm), evex(.L256, ._66, ._0F, .W1, 0x2B, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVNTPD, ops2(.rm_mem512, .zmm), evex(.L512, ._66, ._0F, .W1, 0x2B, fmem), .vMR, .{AVX512F}),
    // VMOVNTPS
    vec(.VMOVNTPS, ops2(.rm_mem128, .xmml), vex(.L128, ._NP, ._0F, .WIG, 0x2B), .vMR, .{AVX}),
    vec(.VMOVNTPS, ops2(.rm_mem256, .ymml), vex(.L256, ._NP, ._0F, .WIG, 0x2B), .vMR, .{AVX}),
    vec(.VMOVNTPS, ops2(.rm_mem128, .xmm), evex(.L128, ._NP, ._0F, .W0, 0x2B, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVNTPS, ops2(.rm_mem256, .ymm), evex(.L256, ._NP, ._0F, .W0, 0x2B, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVNTPS, ops2(.rm_mem512, .zmm), evex(.L512, ._NP, ._0F, .W0, 0x2B, fmem), .vMR, .{AVX512F}),
    // VMOVSD
    vec(.VMOVSD, ops3(.xmml, .xmml, .rm_xmml), vex(.LIG, ._F2, ._0F, .WIG, 0x10), .RVM, .{AVX}),
    vec(.VMOVSD, ops2(.xmml, .rm_mem64), vex(.LIG, ._F2, ._0F, .WIG, 0x10), .vRM, .{AVX}),
    vec(.VMOVSD, ops3(.rm_xmml, .xmml, .xmml), vex(.LIG, ._F2, ._0F, .WIG, 0x11), .MVR, .{AVX}),
    vec(.VMOVSD, ops2(.rm_mem64, .xmml), vex(.LIG, ._F2, ._0F, .WIG, 0x11), .vMR, .{AVX}),
    vec(.VMOVSD, ops3(.xmm_kz, .xmm, .rm_xmm), evex(.LIG, ._F2, ._0F, .W1, 0x10, nomem), .RVM, .{AVX512F}),
    vec(.VMOVSD, ops2(.xmm_kz, .rm_mem64), evex(.LIG, ._F2, ._0F, .W1, 0x10, t1s), .vRM, .{AVX512F}),
    vec(.VMOVSD, ops3(.rm_xmm_kz, .xmm, .xmm), evex(.LIG, ._F2, ._0F, .W1, 0x11, nomem), .MVR, .{AVX512F}),
    vec(.VMOVSD, ops2(.rm_mem64_kz, .xmm), evex(.LIG, ._F2, ._0F, .W1, 0x11, t1s), .vMR, .{AVX512F}),
    // VMOVSHDUP
    vec(.VMOVSHDUP, ops2(.xmml, .xmml_m128), vex(.L128, ._F3, ._0F, .WIG, 0x16), .vRM, .{AVX}),
    vec(.VMOVSHDUP, ops2(.ymml, .ymml_m256), vex(.L256, ._F3, ._0F, .WIG, 0x16), .vRM, .{AVX}),
    vec(.VMOVSHDUP, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._F3, ._0F, .W0, 0x16, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVSHDUP, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._F3, ._0F, .W0, 0x16, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVSHDUP, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._F3, ._0F, .W0, 0x16, fmem), .vRM, .{AVX512F}),
    // VMOVSLDUP
    vec(.VMOVSLDUP, ops2(.xmml, .xmml_m128), vex(.L128, ._F3, ._0F, .WIG, 0x12), .vRM, .{AVX}),
    vec(.VMOVSLDUP, ops2(.ymml, .ymml_m256), vex(.L256, ._F3, ._0F, .WIG, 0x12), .vRM, .{AVX}),
    vec(.VMOVSLDUP, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._F3, ._0F, .W0, 0x12, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVSLDUP, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._F3, ._0F, .W0, 0x12, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVSLDUP, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._F3, ._0F, .W0, 0x12, fmem), .vRM, .{AVX512F}),
    // VMOVSS
    vec(.VMOVSS, ops3(.xmml, .xmml, .rm_xmml), vex(.LIG, ._F3, ._0F, .WIG, 0x10), .RVM, .{AVX}),
    vec(.VMOVSS, ops2(.xmml, .rm_mem64), vex(.LIG, ._F3, ._0F, .WIG, 0x10), .vRM, .{AVX}),
    vec(.VMOVSS, ops3(.rm_xmml, .xmml, .xmml), vex(.LIG, ._F3, ._0F, .WIG, 0x11), .MVR, .{AVX}),
    vec(.VMOVSS, ops2(.rm_mem64, .xmml), vex(.LIG, ._F3, ._0F, .WIG, 0x11), .vMR, .{AVX}),
    vec(.VMOVSS, ops3(.xmm_kz, .xmm, .xmm), evex(.LIG, ._F3, ._0F, .W0, 0x10, nomem), .RVM, .{AVX512F}),
    vec(.VMOVSS, ops2(.xmm_kz, .rm_mem64), evex(.LIG, ._F3, ._0F, .W0, 0x10, t1s), .vRM, .{AVX512F}),
    vec(.VMOVSS, ops3(.rm_xmm_kz, .xmm, .xmm), evex(.LIG, ._F3, ._0F, .W0, 0x11, nomem), .MVR, .{AVX512F}),
    vec(.VMOVSS, ops2(.rm_mem64_kz, .xmm), evex(.LIG, ._F3, ._0F, .W0, 0x11, t1s), .vMR, .{AVX512F}),
    // VMOVUPD
    vec(.VMOVUPD, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x10), .vRM, .{AVX}),
    vec(.VMOVUPD, ops2(.ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x10), .vRM, .{AVX}),
    vec(.VMOVUPD, ops2(.xmml_m128, .xmml), vex(.L128, ._66, ._0F, .WIG, 0x11), .vMR, .{AVX}),
    vec(.VMOVUPD, ops2(.ymml_m256, .ymml), vex(.L256, ._66, ._0F, .WIG, 0x11), .vMR, .{AVX}),
    vec(.VMOVUPD, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F, .W1, 0x10, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVUPD, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F, .W1, 0x10, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVUPD, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F, .W1, 0x10, fmem), .vRM, .{AVX512F}),
    vec(.VMOVUPD, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._66, ._0F, .W1, 0x11, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVUPD, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._66, ._0F, .W1, 0x11, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVUPD, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._66, ._0F, .W1, 0x11, fmem), .vMR, .{AVX512F}),
    // VMOVUPS
    vec(.VMOVUPS, ops2(.xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x10), .vRM, .{AVX}),
    vec(.VMOVUPS, ops2(.ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x10), .vRM, .{AVX}),
    vec(.VMOVUPS, ops2(.xmml_m128, .xmml), vex(.L128, ._NP, ._0F, .WIG, 0x11), .vMR, .{AVX}),
    vec(.VMOVUPS, ops2(.ymml_m256, .ymml), vex(.L256, ._NP, ._0F, .WIG, 0x11), .vMR, .{AVX}),
    vec(.VMOVUPS, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._NP, ._0F, .W0, 0x10, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVUPS, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._NP, ._0F, .W0, 0x10, fmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VMOVUPS, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._NP, ._0F, .W0, 0x10, fmem), .vRM, .{AVX512F}),
    vec(.VMOVUPS, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._NP, ._0F, .W0, 0x11, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVUPS, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._NP, ._0F, .W0, 0x11, fmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VMOVUPS, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._NP, ._0F, .W0, 0x11, fmem), .vMR, .{AVX512F}),
    // VMPSADBW
    vec(.VMPSADBW, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x42), .RVMI, .{AVX}),
    vec(.VMPSADBW, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .WIG, 0x42), .RVMI, .{AVX2}),
    // VMULPD
    vec(.VMULPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x59), .RVM, .{AVX}),
    vec(.VMULPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x59), .RVM, .{AVX}),
    vec(.VMULPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x59, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VMULPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x59, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VMULPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F, .W1, 0x59, full), .RVM, .{AVX512F}),
    // VMULPS
    vec(.VMULPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x59), .RVM, .{AVX}),
    vec(.VMULPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x59), .RVM, .{AVX}),
    vec(.VMULPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x59, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VMULPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x59, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VMULPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst_er), evex(.L512, ._NP, ._0F, .W0, 0x59, full), .RVM, .{AVX512F}),
    // VMULSD
    vec(.VMULSD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._F2, ._0F, .WIG, 0x59), .RVM, .{AVX}),
    vec(.VMULSD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._F2, ._0F, .W1, 0x59, t1s), .RVM, .{AVX512F}),
    // VMULSS
    vec(.VMULSS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._F3, ._0F, .WIG, 0x59), .RVM, .{AVX}),
    vec(.VMULSS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._F3, ._0F, .W0, 0x59, t1s), .RVM, .{AVX512F}),
    // VORPD
    vec(.VORPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x56), .RVM, .{AVX}),
    vec(.VORPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x56), .RVM, .{AVX}),
    vec(.VORPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x56, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VORPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x56, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VORPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0x56, full), .RVM, .{AVX512DQ}),
    // VORPS
    vec(.VORPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x56), .RVM, .{AVX}),
    vec(.VORPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x56), .RVM, .{AVX}),
    vec(.VORPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x56, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VORPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x56, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VORPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._NP, ._0F, .W0, 0x56, full), .RVM, .{AVX512DQ}),
    // VPABSB / VPABSW / VPABSD / VPABSQ
    vec(.VPABSB, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x1C), .vRM, .{AVX}),
    vec(.VPABSB, ops2(.ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x1C), .vRM, .{AVX2}),
    vec(.VPABSB, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F38, .WIG, 0x1C, fmem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPABSB, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F38, .WIG, 0x1C, fmem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPABSB, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F38, .WIG, 0x1C, fmem), .vRM, .{AVX512BW}),
    // VPABSW
    vec(.VPABSW, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x1D), .vRM, .{AVX}),
    vec(.VPABSW, ops2(.ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x1D), .vRM, .{AVX2}),
    vec(.VPABSW, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F38, .WIG, 0x1D, fmem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPABSW, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F38, .WIG, 0x1D, fmem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPABSW, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F38, .WIG, 0x1D, fmem), .vRM, .{AVX512BW}),
    // VPABSD
    vec(.VPABSD, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x1E), .vRM, .{AVX}),
    vec(.VPABSD, ops2(.ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x1E), .vRM, .{AVX2}),
    vec(.VPABSD, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x1E, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPABSD, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x1E, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPABSD, ops2(.zmm_kz, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x1E, full), .vRM, .{AVX512F}),
    // VPABSQ
    vec(.VPABSQ, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x1F, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPABSQ, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x1F, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPABSQ, ops2(.zmm_kz, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x1F, full), .vRM, .{AVX512F}),
    // VPACKSSWB / PACKSSDW
    // VPACKSSWB
    vec(.VPACKSSWB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x63), .RVM, .{AVX}),
    vec(.VPACKSSWB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x63), .RVM, .{AVX2}),
    vec(.VPACKSSWB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0x63, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPACKSSWB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0x63, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPACKSSWB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0x63, fmem), .RVM, .{AVX512BW}),
    // VPACKSSDW
    vec(.VPACKSSDW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x6B), .RVM, .{AVX}),
    vec(.VPACKSSDW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x6B), .RVM, .{AVX2}),
    vec(.VPACKSSDW, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F, .W0, 0x6B, full), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPACKSSDW, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F, .W0, 0x6B, full), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPACKSSDW, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F, .W0, 0x6B, full), .RVM, .{AVX512BW}),
    // VPACKUSWB
    vec(.VPACKUSWB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x67), .RVM, .{AVX}),
    vec(.VPACKUSWB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x67), .RVM, .{AVX2}),
    vec(.VPACKUSWB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0x67, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPACKUSWB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0x67, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPACKUSWB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0x67, fmem), .RVM, .{AVX512BW}),
    // VPACKUSDW
    vec(.VPACKUSDW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x2B), .RVM, .{AVX}),
    vec(.VPACKUSDW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x2B), .RVM, .{AVX2}),
    vec(.VPACKUSDW, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x2B, full), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPACKUSDW, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x2B, full), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPACKUSDW, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x2B, full), .RVM, .{AVX512BW}),
    // VPADDB / PADDW / PADDD / PADDQ
    // VPADDB
    vec(.VPADDB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xFC), .RVM, .{AVX}),
    vec(.VPADDB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xFC), .RVM, .{AVX2}),
    vec(.VPADDB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xFC, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPADDB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xFC, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPADDB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xFC, fmem), .RVM, .{AVX512BW}),
    // VPADDW
    vec(.VPADDW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xFD), .RVM, .{AVX}),
    vec(.VPADDW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xFD), .RVM, .{AVX2}),
    vec(.VPADDW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xFD, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPADDW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xFD, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPADDW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xFD, fmem), .RVM, .{AVX512BW}),
    // VPADDD
    vec(.VPADDD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xFE), .RVM, .{AVX}),
    vec(.VPADDD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xFE), .RVM, .{AVX2}),
    vec(.VPADDD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F, .W0, 0xFE, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPADDD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F, .W0, 0xFE, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPADDD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F, .W0, 0xFE, full), .RVM, .{AVX512F}),
    // VPADDQ
    vec(.VPADDQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xD4), .RVM, .{AVX}),
    vec(.VPADDQ, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xD4), .RVM, .{AVX2}),
    vec(.VPADDQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0xD4, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPADDQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0xD4, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPADDQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0xD4, full), .RVM, .{AVX512F}),
    // VPADDSB / PADDSW
    vec(.VPADDSB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xEC), .RVM, .{AVX}),
    vec(.VPADDSB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xEC), .RVM, .{AVX2}),
    vec(.VPADDSB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xEC, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPADDSB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xEC, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPADDSB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xEC, fmem), .RVM, .{AVX512BW}),
    //
    vec(.VPADDSW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xED), .RVM, .{AVX}),
    vec(.VPADDSW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xED), .RVM, .{AVX2}),
    vec(.VPADDSW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xED, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPADDSW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xED, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPADDSW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xED, fmem), .RVM, .{AVX512BW}),
    // VPADDUSB / PADDUSW
    vec(.VPADDUSB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xDC), .RVM, .{AVX}),
    vec(.VPADDUSB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xDC), .RVM, .{AVX2}),
    vec(.VPADDUSB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xDC, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPADDUSB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xDC, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPADDUSB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xDC, fmem), .RVM, .{AVX512BW}),
    //
    vec(.VPADDUSW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xDD), .RVM, .{AVX}),
    vec(.VPADDUSW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xDD), .RVM, .{AVX2}),
    vec(.VPADDUSW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xDD, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPADDUSW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xDD, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPADDUSW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xDD, fmem), .RVM, .{AVX512BW}),
    // VPALIGNR
    vec(.VPALIGNR, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x0F), .RVMI, .{AVX}),
    vec(.VPALIGNR, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .WIG, 0x0F), .RVMI, .{AVX2}),
    vec(.VPALIGNR, ops4(.xmm_kz, .xmm, .xmm_m128, .imm8), evex(.L128, ._66, ._0F3A, .WIG, 0x0F, fmem), .RVMI, .{ AVX512VL, AVX512BW }),
    vec(.VPALIGNR, ops4(.ymm_kz, .ymm, .ymm_m256, .imm8), evex(.L256, ._66, ._0F3A, .WIG, 0x0F, fmem), .RVMI, .{ AVX512VL, AVX512BW }),
    vec(.VPALIGNR, ops4(.zmm_kz, .zmm, .zmm_m512, .imm8), evex(.L512, ._66, ._0F3A, .WIG, 0x0F, fmem), .RVMI, .{AVX512BW}),
    // VPAND
    vec(.VPAND, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xDB), .RVM, .{AVX}),
    vec(.VPAND, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xDB), .RVM, .{AVX2}),
    vec(.VPANDD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F, .W0, 0xDB, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPANDD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F, .W0, 0xDB, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPANDD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F, .W0, 0xDB, full), .RVM, .{AVX512F}),
    vec(.VPANDQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0xDB, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPANDQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0xDB, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPANDQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0xDB, full), .RVM, .{AVX512F}),
    // VPANDN
    vec(.VPANDN, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xDF), .RVM, .{AVX}),
    vec(.VPANDN, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xDF), .RVM, .{AVX2}),
    vec(.VPANDND, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F, .W0, 0xDF, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPANDND, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F, .W0, 0xDF, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPANDND, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F, .W0, 0xDF, full), .RVM, .{AVX512F}),
    vec(.VPANDNQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0xDF, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPANDNQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0xDF, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPANDNQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0xDF, full), .RVM, .{AVX512F}),
    // VPAVGB / VPAVGW
    vec(.VPAVGB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xE0), .RVM, .{AVX}),
    vec(.VPAVGB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xE0), .RVM, .{AVX2}),
    vec(.VPAVGB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xE0, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPAVGB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xE0, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPAVGB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xE0, fmem), .RVM, .{AVX512BW}),
    //
    vec(.VPAVGW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xE3), .RVM, .{AVX}),
    vec(.VPAVGW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xE3), .RVM, .{AVX2}),
    vec(.VPAVGW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xE3, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPAVGW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xE3, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPAVGW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xE3, fmem), .RVM, .{AVX512BW}),
    // VPBLENDVB
    vec(.VPBLENDVB, ops4(.xmml, .xmml, .xmml_m128, .xmml), vex(.L128, ._66, ._0F3A, .W0, 0x4C), .RVMR, .{AVX}),
    vec(.VPBLENDVB, ops4(.ymml, .ymml, .ymml_m256, .ymml), vex(.L256, ._66, ._0F3A, .W0, 0x4C), .RVMR, .{AVX2}),
    // VPBLENDDW
    vec(.VPBLENDW, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x0E), .RVMI, .{AVX}),
    vec(.VPBLENDW, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .WIG, 0x0E), .RVMI, .{AVX2}),
    // VPCLMULQDQ
    vec(.VPCLMULQDQ, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x44), .RVMI, .{ cpu.PCLMULQDQ, AVX }),
    vec(.VPCLMULQDQ, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .WIG, 0x44), .RVMI, .{cpu.VPCLMULQDQ}),
    vec(.VPCLMULQDQ, ops4(.xmm, .xmm, .xmm_m128, .imm8), evex(.L128, ._66, ._0F3A, .WIG, 0x44, fmem), .RVMI, .{ cpu.VPCLMULQDQ, AVX512VL }),
    vec(.VPCLMULQDQ, ops4(.ymm, .ymm, .ymm_m256, .imm8), evex(.L256, ._66, ._0F3A, .WIG, 0x44, fmem), .RVMI, .{ cpu.VPCLMULQDQ, AVX512VL }),
    vec(.VPCLMULQDQ, ops4(.zmm, .zmm, .zmm_m512, .imm8), evex(.L512, ._66, ._0F3A, .WIG, 0x44, fmem), .RVMI, .{ cpu.VPCLMULQDQ, AVX512F }),
    // VPCMPEQB / VPCMPEQW / VPCMPEQD
    vec(.VPCMPEQB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x74), .RVM, .{AVX}),
    vec(.VPCMPEQB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x74), .RVM, .{AVX2}),
    vec(.VPCMPEQB, ops3(.reg_k_k, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0x74, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPEQB, ops3(.reg_k_k, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0x74, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPEQB, ops3(.reg_k_k, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0x74, fmem), .RVM, .{AVX512BW}),
    // VPCMPEQW
    vec(.VPCMPEQW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x75), .RVM, .{AVX}),
    vec(.VPCMPEQW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x75), .RVM, .{AVX2}),
    vec(.VPCMPEQW, ops3(.reg_k_k, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0x75, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPEQW, ops3(.reg_k_k, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0x75, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPEQW, ops3(.reg_k_k, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0x75, fmem), .RVM, .{AVX512BW}),
    // VPCMPEQD
    vec(.VPCMPEQD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x76), .RVM, .{AVX}),
    vec(.VPCMPEQD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x76), .RVM, .{AVX2}),
    vec(.VPCMPEQD, ops3(.reg_k_k, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F, .W0, 0x76, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPCMPEQD, ops3(.reg_k_k, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F, .W0, 0x76, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPCMPEQD, ops3(.reg_k_k, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F, .W0, 0x76, full), .RVM, .{AVX512F}),
    // VPCMPEQQ
    vec(.VPCMPEQQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x29), .RVM, .{AVX}),
    vec(.VPCMPEQQ, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x29), .RVM, .{AVX2}),
    vec(.VPCMPEQQ, ops3(.reg_k_k, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x29, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPCMPEQQ, ops3(.reg_k_k, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x29, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPCMPEQQ, ops3(.reg_k_k, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x29, full), .RVM, .{AVX512F}),
    // VPCMPESTRI
    vec(.VPCMPESTRI, ops3(.xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x61), .vRMI, .{AVX}),
    // VPCMPESTRM
    vec(.VPCMPESTRM, ops3(.xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x60), .vRMI, .{AVX}),
    // VPCMPGTB / VPCMPGTW / VPCMPGTD
    // VPCMPGTB
    vec(.VPCMPGTB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x64), .RVM, .{AVX}),
    vec(.VPCMPGTB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x64), .RVM, .{AVX2}),
    vec(.VPCMPGTB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0x64, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPGTB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0x64, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPGTB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0x64, fmem), .RVM, .{AVX512BW}),
    // VPCMPGTW
    vec(.VPCMPGTW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x65), .RVM, .{AVX}),
    vec(.VPCMPGTW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x65), .RVM, .{AVX2}),
    vec(.VPCMPGTW, ops3(.reg_k_k, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0x65, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPGTW, ops3(.reg_k_k, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0x65, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPGTW, ops3(.reg_k_k, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0x65, fmem), .RVM, .{AVX512BW}),
    // VPCMPGTD
    vec(.VPCMPGTD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x66), .RVM, .{AVX}),
    vec(.VPCMPGTD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x66), .RVM, .{AVX2}),
    vec(.VPCMPGTD, ops3(.reg_k_k, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F, .W0, 0x66, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPCMPGTD, ops3(.reg_k_k, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F, .W0, 0x66, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPCMPGTD, ops3(.reg_k_k, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F, .W0, 0x66, full), .RVM, .{AVX512F}),
    // VPCMPGTQ
    vec(.VPCMPGTQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x37), .RVM, .{AVX}),
    vec(.VPCMPGTQ, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x37), .RVM, .{AVX2}),
    vec(.VPCMPGTQ, ops3(.reg_k_k, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x37, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPCMPGTQ, ops3(.reg_k_k, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x37, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPCMPGTQ, ops3(.reg_k_k, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x37, full), .RVM, .{AVX512F}),
    // VPCMPISTRI
    vec(.VPCMPISTRI, ops3(.xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x63), .vRMI, .{AVX}),
    // VPCMPISTRM
    vec(.VPCMPISTRM, ops3(.xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x62), .vRMI, .{AVX}),
    // VPEXTRB / VPEXTRD / VPEXTRQ
    vec(.VPEXTRB, ops3(.reg32_m8, .xmml, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x14), .vMRI, .{AVX}),
    vec(.VPEXTRB, ops3(.rm_reg64, .xmml, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x14), .vMRI, .{ AVX, No32 }),
    vec(.VPEXTRB, ops3(.reg32_m8, .xmm, .imm8), evex(.L128, ._66, ._0F3A, .WIG, 0x14, t1s), .vMRI, .{AVX512BW}),
    vec(.VPEXTRB, ops3(.reg64, .xmm, .imm8), evex(.L128, ._66, ._0F3A, .WIG, 0x14, t1s), .vMRI, .{ AVX512BW, No32 }),
    //
    vec(.VPEXTRD, ops3(.rm32, .xmml, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x16), .vMRI, .{AVX}),
    vec(.VPEXTRD, ops3(.rm32, .xmm, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x16, t1s), .vMRI, .{AVX512DQ}),
    //
    vec(.VPEXTRQ, ops3(.rm64, .xmml, .imm8), vex(.L128, ._66, ._0F3A, .W1, 0x16), .vMRI, .{AVX}),
    vec(.VPEXTRQ, ops3(.rm64, .xmm, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x16, t1s), .vMRI, .{AVX512DQ}),
    // VPEXTRW
    vec(.VPEXTRW, ops3(.reg32, .xmml, .imm8), vex(.L128, ._66, ._0F, .W0, 0xC5), .vRMI, .{AVX}),
    vec(.VPEXTRW, ops3(.reg64, .xmml, .imm8), vex(.L128, ._66, ._0F, .W0, 0xC5), .vRMI, .{ AVX, No32 }),
    vec(.VPEXTRW, ops3(.reg32_m16, .xmml, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x15), .vMRI, .{AVX}),
    vec(.VPEXTRW, ops3(.rm_reg64, .xmml, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x15), .vMRI, .{ AVX, No32 }),
    vec(.VPEXTRW, ops3(.reg32, .xmm, .imm8), evex(.L128, ._66, ._0F, .WIG, 0xC5, nomem), .vRMI, .{AVX512BW}),
    vec(.VPEXTRW, ops3(.reg64, .xmm, .imm8), evex(.L128, ._66, ._0F, .WIG, 0xC5, nomem), .vRMI, .{ AVX512BW, No32 }),
    vec(.VPEXTRW, ops3(.reg32_m16, .xmm, .imm8), evex(.L128, ._66, ._0F3A, .WIG, 0x15, t1s), .vMRI, .{AVX512BW}),
    vec(.VPEXTRW, ops3(.rm_reg64, .xmm, .imm8), evex(.L128, ._66, ._0F3A, .WIG, 0x15, t1s), .vMRI, .{ AVX512BW, No32 }),
    // VPHADDW / VPHADDD
    vec(.VPHADDW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x01), .RVM, .{AVX}),
    vec(.VPHADDW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x01), .RVM, .{AVX2}),
    //
    vec(.VPHADDD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x02), .RVM, .{AVX}),
    vec(.VPHADDD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x02), .RVM, .{AVX2}),
    // VPHADDSW
    vec(.VPHADDSW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x03), .RVM, .{AVX}),
    vec(.VPHADDSW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x03), .RVM, .{AVX2}),
    // VPHMINPOSUW
    vec(.VPHMINPOSUW, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x41), .vRM, .{AVX}),
    // VPHSUBW / VPHSUBD
    vec(.VPHSUBW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x05), .RVM, .{AVX}),
    vec(.VPHSUBW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x05), .RVM, .{AVX2}),
    //
    vec(.VPHSUBD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x06), .RVM, .{AVX}),
    vec(.VPHSUBD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x06), .RVM, .{AVX2}),
    // VPHSUBSW
    vec(.VPHSUBSW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x07), .RVM, .{AVX}),
    vec(.VPHSUBSW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x07), .RVM, .{AVX2}),
    // VPINSRB / VPINSRD / VPINSRQ
    vec(.VPINSRB, ops4(.xmml, .xmml, .reg32_m8, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x20), .RVMI, .{AVX}),
    vec(.VPINSRB, ops4(.xmm, .xmm, .reg32_m8, .imm8), evex(.L128, ._66, ._0F3A, .WIG, 0x20, t1s), .RVMI, .{AVX512BW}),
    //
    vec(.VPINSRD, ops4(.xmml, .xmml, .rm32, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x22), .RVMI, .{AVX}),
    vec(.VPINSRD, ops4(.xmm, .xmm, .rm32, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x22, t1s), .RVMI, .{AVX512DQ}),
    //
    vec(.VPINSRQ, ops4(.xmml, .xmml, .rm64, .imm8), vex(.L128, ._66, ._0F3A, .W1, 0x22), .RVMI, .{AVX}),
    vec(.VPINSRQ, ops4(.xmm, .xmm, .rm64, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x22, t1s), .RVMI, .{AVX512DQ}),
    // VPINSRW
    vec(.VPINSRW, ops4(.xmml, .xmml, .reg32_m16, .imm8), vex(.L128, ._66, ._0F, .W0, 0xC4), .RVMI, .{AVX}),
    vec(.VPINSRW, ops4(.xmml, .xmml, .rm_reg64, .imm8), vex(.L128, ._66, ._0F, .W0, 0xC4), .RVMI, .{AVX}),
    vec(.VPINSRW, ops4(.xmm, .xmm, .reg32_m16, .imm8), evex(.L128, ._66, ._0F, .WIG, 0xC4, t1s), .RVMI, .{AVX512BW}),
    vec(.VPINSRW, ops4(.xmm, .xmm, .rm_reg64, .imm8), evex(.L128, ._66, ._0F, .WIG, 0xC4, t1s), .RVMI, .{AVX512BW}),
    // VPMADDUBSW
    vec(.VPMADDUBSW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x04), .RVM, .{AVX}),
    vec(.VPMADDUBSW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x04), .RVM, .{AVX2}),
    vec(.VPMADDUBSW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .WIG, 0x04, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMADDUBSW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .WIG, 0x04, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMADDUBSW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .WIG, 0x04, fmem), .RVM, .{AVX512BW}),
    // VPMADDWD
    vec(.VPMADDWD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xF5), .RVM, .{AVX}),
    vec(.VPMADDWD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xF5), .RVM, .{AVX2}),
    vec(.VPMADDWD, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xF5, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMADDWD, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xF5, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMADDWD, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xF5, fmem), .RVM, .{AVX512BW}),
    // VPMAXSB / VPMAXSW / VPMAXSD / VPMAXSQ
    // VPMAXSB
    vec(.VPMAXSB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x3C), .RVM, .{AVX}),
    vec(.VPMAXSB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x3C), .RVM, .{AVX2}),
    vec(.VPMAXSB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .WIG, 0x3C, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMAXSB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .WIG, 0x3C, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMAXSB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .WIG, 0x3C, fmem), .RVM, .{AVX512BW}),
    // VPMAXSW
    vec(.VPMAXSW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xEE), .RVM, .{AVX}),
    vec(.VPMAXSW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xEE), .RVM, .{AVX2}),
    vec(.VPMAXSW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xEE, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMAXSW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xEE, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMAXSW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xEE, fmem), .RVM, .{AVX512BW}),
    // VPMAXSD
    vec(.VPMAXSD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x3D), .RVM, .{AVX}),
    vec(.VPMAXSD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x3D), .RVM, .{AVX2}),
    vec(.VPMAXSD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x3D, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMAXSD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x3D, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMAXSD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x3D, full), .RVM, .{AVX512F}),
    // VPMAXSQ
    vec(.VPMAXSQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x3D, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMAXSQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x3D, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMAXSQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x3D, full), .RVM, .{AVX512F}),
    // VPMAXUB / VPMAXUW
    // VPMAXUB
    vec(.VPMAXUB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xDE), .RVM, .{AVX}),
    vec(.VPMAXUB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xDE), .RVM, .{AVX2}),
    vec(.VPMAXUB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xDE, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMAXUB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xDE, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMAXUB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xDE, fmem), .RVM, .{AVX512BW}),
    // VPMAXUW
    vec(.VPMAXUW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x3E), .RVM, .{AVX}),
    vec(.VPMAXUW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x3E), .RVM, .{AVX2}),
    vec(.VPMAXUW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .WIG, 0x3E, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMAXUW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .WIG, 0x3E, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMAXUW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .WIG, 0x3E, fmem), .RVM, .{AVX512BW}),
    // VPMAXUD / VPMAXUQ
    // VPMAXUD
    vec(.VPMAXUD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x3F), .RVM, .{AVX}),
    vec(.VPMAXUD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x3F), .RVM, .{AVX2}),
    vec(.VPMAXUD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x3F, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMAXUD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x3F, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMAXUD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x3F, full), .RVM, .{AVX512F}),
    // VPMAXUQ
    vec(.VPMAXUQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x3F, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMAXUQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x3F, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMAXUQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x3F, full), .RVM, .{AVX512F}),
    // VPMINSB / VPMINSW
    // VPMINSB
    vec(.VPMINSB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x38), .RVM, .{AVX}),
    vec(.VPMINSB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x38), .RVM, .{AVX2}),
    vec(.VPMINSB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .WIG, 0x38, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMINSB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .WIG, 0x38, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMINSB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .WIG, 0x38, fmem), .RVM, .{AVX512BW}),
    // VPMINSW
    vec(.VPMINSW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xEA), .RVM, .{AVX}),
    vec(.VPMINSW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xEA), .RVM, .{AVX2}),
    vec(.VPMINSW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xEA, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMINSW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xEA, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMINSW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xEA, fmem), .RVM, .{AVX512BW}),
    // VPMINSD / VPMINSQ
    // VPMINSD
    vec(.VPMINSD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x39), .RVM, .{AVX}),
    vec(.VPMINSD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x39), .RVM, .{AVX2}),
    vec(.VPMINSD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x39, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMINSD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x39, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMINSD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x39, full), .RVM, .{AVX512F}),
    // VPMINSQ
    vec(.VPMINSQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x39, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMINSQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x39, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMINSQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x39, full), .RVM, .{AVX512F}),
    // VPMINUB / VPMINUW
    // VPMINUB
    vec(.VPMINUB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xDA), .RVM, .{AVX}),
    vec(.VPMINUB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xDA), .RVM, .{AVX2}),
    vec(.VPMINUB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xDA, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMINUB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xDA, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMINUB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xDA, fmem), .RVM, .{AVX512BW}),
    // VPMINUW
    vec(.VPMINUW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x3A), .RVM, .{AVX}),
    vec(.VPMINUW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x3A), .RVM, .{AVX2}),
    vec(.VPMINUW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .WIG, 0x3A, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMINUW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .WIG, 0x3A, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMINUW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .WIG, 0x3A, fmem), .RVM, .{AVX512BW}),
    // VPMINUD / VPMINUQ
    // VPMINUD
    vec(.VPMINUD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x3B), .RVM, .{AVX}),
    vec(.VPMINUD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x3B), .RVM, .{AVX2}),
    vec(.VPMINUD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x3B, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMINUD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x3B, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMINUD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x3B, full), .RVM, .{AVX512F}),
    // VPMINUQ
    vec(.VPMINUQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x3B, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMINUQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x3B, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMINUQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x3B, full), .RVM, .{AVX512F}),
    // VPMOVMSKB
    vec(.VPMOVMSKB, ops2(.reg32, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xD7), .RVM, .{AVX}),
    vec(.VPMOVMSKB, ops2(.reg64, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xD7), .RVM, .{AVX}),
    vec(.VPMOVMSKB, ops2(.reg32, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xD7), .RVM, .{AVX2}),
    vec(.VPMOVMSKB, ops2(.reg64, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xD7), .RVM, .{AVX2}),
    // VPMOVSX
    // VPMOVSXBW
    vec(.VPMOVSXBW, ops2(.xmml, .xmml_m64), vex(.L128, ._66, ._0F38, .WIG, 0x20), .vRM, .{AVX}),
    vec(.VPMOVSXBW, ops2(.ymml, .xmml_m128), vex(.L256, ._66, ._0F38, .WIG, 0x20), .vRM, .{AVX2}),
    vec(.VPMOVSXBW, ops2(.xmm_kz, .xmm_m64), evex(.L128, ._66, ._0F38, .WIG, 0x20, hmem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVSXBW, ops2(.ymm_kz, .xmm_m128), evex(.L256, ._66, ._0F38, .WIG, 0x20, hmem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVSXBW, ops2(.zmm_kz, .ymm_m256), evex(.L512, ._66, ._0F38, .WIG, 0x20, hmem), .vRM, .{AVX512BW}),
    // VPMOVSXBD
    vec(.VPMOVSXBD, ops2(.xmml, .xmml_m32), vex(.L128, ._66, ._0F38, .WIG, 0x21), .vRM, .{AVX}),
    vec(.VPMOVSXBD, ops2(.ymml, .xmml_m64), vex(.L256, ._66, ._0F38, .WIG, 0x21), .vRM, .{AVX2}),
    vec(.VPMOVSXBD, ops2(.xmm_kz, .xmm_m32), evex(.L128, ._66, ._0F38, .WIG, 0x21, qmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSXBD, ops2(.ymm_kz, .xmm_m64), evex(.L256, ._66, ._0F38, .WIG, 0x21, qmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSXBD, ops2(.zmm_kz, .xmm_m128), evex(.L512, ._66, ._0F38, .WIG, 0x21, qmem), .vRM, .{AVX512F}),
    // VPMOVSXBQ
    vec(.VPMOVSXBQ, ops2(.xmml, .xmml_m16), vex(.L128, ._66, ._0F38, .WIG, 0x22), .vRM, .{AVX}),
    vec(.VPMOVSXBQ, ops2(.ymml, .xmml_m32), vex(.L256, ._66, ._0F38, .WIG, 0x22), .vRM, .{AVX2}),
    vec(.VPMOVSXBQ, ops2(.xmm_kz, .xmm_m16), evex(.L128, ._66, ._0F38, .WIG, 0x22, emem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSXBQ, ops2(.ymm_kz, .xmm_m32), evex(.L256, ._66, ._0F38, .WIG, 0x22, emem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSXBQ, ops2(.zmm_kz, .xmm_m64), evex(.L512, ._66, ._0F38, .WIG, 0x22, emem), .vRM, .{AVX512F}),
    // VPMOVSXWD
    vec(.VPMOVSXWD, ops2(.xmml, .xmml_m64), vex(.L128, ._66, ._0F38, .WIG, 0x23), .vRM, .{AVX}),
    vec(.VPMOVSXWD, ops2(.ymml, .xmml_m128), vex(.L256, ._66, ._0F38, .WIG, 0x23), .vRM, .{AVX2}),
    vec(.VPMOVSXWD, ops2(.xmm_kz, .xmm_m64), evex(.L128, ._66, ._0F38, .WIG, 0x23, hmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSXWD, ops2(.ymm_kz, .xmm_m128), evex(.L256, ._66, ._0F38, .WIG, 0x23, hmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSXWD, ops2(.zmm_kz, .ymm_m256), evex(.L512, ._66, ._0F38, .WIG, 0x23, hmem), .vRM, .{AVX512F}),
    // VPMOVSXWQ
    vec(.VPMOVSXWQ, ops2(.xmml, .xmml_m32), vex(.L128, ._66, ._0F38, .WIG, 0x24), .vRM, .{AVX}),
    vec(.VPMOVSXWQ, ops2(.ymml, .xmml_m64), vex(.L256, ._66, ._0F38, .WIG, 0x24), .vRM, .{AVX2}),
    vec(.VPMOVSXWQ, ops2(.xmm_kz, .xmm_m32), evex(.L128, ._66, ._0F38, .WIG, 0x24, qmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSXWQ, ops2(.ymm_kz, .xmm_m64), evex(.L256, ._66, ._0F38, .WIG, 0x24, qmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSXWQ, ops2(.zmm_kz, .xmm_m128), evex(.L512, ._66, ._0F38, .WIG, 0x24, qmem), .vRM, .{AVX512F}),
    // VPMOVSXDQ
    vec(.VPMOVSXDQ, ops2(.xmml, .xmml_m64), vex(.L128, ._66, ._0F38, .WIG, 0x25), .vRM, .{AVX}),
    vec(.VPMOVSXDQ, ops2(.ymml, .xmml_m128), vex(.L256, ._66, ._0F38, .WIG, 0x25), .vRM, .{AVX2}),
    vec(.VPMOVSXDQ, ops2(.xmm_kz, .xmm_m64), evex(.L128, ._66, ._0F38, .W0, 0x25, hmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSXDQ, ops2(.ymm_kz, .xmm_m128), evex(.L256, ._66, ._0F38, .W0, 0x25, hmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSXDQ, ops2(.zmm_kz, .ymm_m256), evex(.L512, ._66, ._0F38, .W0, 0x25, hmem), .vRM, .{AVX512F}),
    // VPMOVZX
    // VPMOVZXBW
    vec(.VPMOVZXBW, ops2(.xmml, .xmml_m64), vex(.L128, ._66, ._0F38, .WIG, 0x30), .vRM, .{AVX}),
    vec(.VPMOVZXBW, ops2(.ymml, .xmml_m128), vex(.L256, ._66, ._0F38, .WIG, 0x30), .vRM, .{AVX2}),
    vec(.VPMOVZXBW, ops2(.xmm_kz, .xmm_m64), evex(.L128, ._66, ._0F38, .WIG, 0x30, hmem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVZXBW, ops2(.ymm_kz, .xmm_m128), evex(.L256, ._66, ._0F38, .WIG, 0x30, hmem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVZXBW, ops2(.zmm_kz, .ymm_m256), evex(.L512, ._66, ._0F38, .WIG, 0x30, hmem), .vRM, .{AVX512BW}),
    // VPMOVZXBD
    vec(.VPMOVZXBD, ops2(.xmml, .xmml_m32), vex(.L128, ._66, ._0F38, .WIG, 0x31), .vRM, .{AVX}),
    vec(.VPMOVZXBD, ops2(.ymml, .xmml_m64), vex(.L256, ._66, ._0F38, .WIG, 0x31), .vRM, .{AVX2}),
    vec(.VPMOVZXBD, ops2(.xmm_kz, .xmm_m32), evex(.L128, ._66, ._0F38, .WIG, 0x31, qmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVZXBD, ops2(.ymm_kz, .xmm_m64), evex(.L256, ._66, ._0F38, .WIG, 0x31, qmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVZXBD, ops2(.zmm_kz, .xmm_m128), evex(.L512, ._66, ._0F38, .WIG, 0x31, qmem), .vRM, .{AVX512F}),
    // VPMOVZXBQ
    vec(.VPMOVZXBQ, ops2(.xmml, .xmml_m16), vex(.L128, ._66, ._0F38, .WIG, 0x32), .vRM, .{AVX}),
    vec(.VPMOVZXBQ, ops2(.ymml, .xmml_m32), vex(.L256, ._66, ._0F38, .WIG, 0x32), .vRM, .{AVX2}),
    vec(.VPMOVZXBQ, ops2(.xmm_kz, .xmm_m16), evex(.L128, ._66, ._0F38, .WIG, 0x32, emem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVZXBQ, ops2(.ymm_kz, .xmm_m32), evex(.L256, ._66, ._0F38, .WIG, 0x32, emem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVZXBQ, ops2(.zmm_kz, .xmm_m64), evex(.L512, ._66, ._0F38, .WIG, 0x32, emem), .vRM, .{AVX512F}),
    // VPMOVZXWD
    vec(.VPMOVZXWD, ops2(.xmml, .xmml_m64), vex(.L128, ._66, ._0F38, .WIG, 0x33), .vRM, .{AVX}),
    vec(.VPMOVZXWD, ops2(.ymml, .xmml_m128), vex(.L256, ._66, ._0F38, .WIG, 0x33), .vRM, .{AVX2}),
    vec(.VPMOVZXWD, ops2(.xmm_kz, .xmm_m64), evex(.L128, ._66, ._0F38, .WIG, 0x33, hmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVZXWD, ops2(.ymm_kz, .xmm_m128), evex(.L256, ._66, ._0F38, .WIG, 0x33, hmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVZXWD, ops2(.zmm_kz, .ymm_m256), evex(.L512, ._66, ._0F38, .WIG, 0x33, hmem), .vRM, .{AVX512F}),
    // VPMOVZXWQ
    vec(.VPMOVZXWQ, ops2(.xmml, .xmml_m32), vex(.L128, ._66, ._0F38, .WIG, 0x34), .vRM, .{AVX}),
    vec(.VPMOVZXWQ, ops2(.ymml, .xmml_m64), vex(.L256, ._66, ._0F38, .WIG, 0x34), .vRM, .{AVX2}),
    vec(.VPMOVZXWQ, ops2(.xmm_kz, .xmm_m32), evex(.L128, ._66, ._0F38, .WIG, 0x34, qmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVZXWQ, ops2(.ymm_kz, .xmm_m64), evex(.L256, ._66, ._0F38, .WIG, 0x34, qmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVZXWQ, ops2(.zmm_kz, .xmm_m128), evex(.L512, ._66, ._0F38, .WIG, 0x34, qmem), .vRM, .{AVX512F}),
    // VPMOVZXDQ
    vec(.VPMOVZXDQ, ops2(.xmml, .xmml_m64), vex(.L128, ._66, ._0F38, .WIG, 0x35), .vRM, .{AVX}),
    vec(.VPMOVZXDQ, ops2(.ymml, .xmml_m128), vex(.L256, ._66, ._0F38, .WIG, 0x35), .vRM, .{AVX2}),
    vec(.VPMOVZXDQ, ops2(.xmm_kz, .xmm_m64), evex(.L128, ._66, ._0F38, .W0, 0x35, hmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVZXDQ, ops2(.ymm_kz, .xmm_m128), evex(.L256, ._66, ._0F38, .W0, 0x35, hmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPMOVZXDQ, ops2(.zmm_kz, .ymm_m256), evex(.L512, ._66, ._0F38, .W0, 0x35, hmem), .vRM, .{AVX512F}),
    // VPMULDQ
    vec(.VPMULDQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x28), .RVM, .{AVX}),
    vec(.VPMULDQ, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x28), .RVM, .{AVX2}),
    vec(.VPMULDQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x28, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMULDQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x28, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMULDQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x28, full), .RVM, .{AVX512F}),
    // VPMULHRSW
    vec(.VPMULHRSW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x0B), .RVM, .{AVX}),
    vec(.VPMULHRSW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x0B), .RVM, .{AVX2}),
    vec(.VPMULHRSW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .WIG, 0x0B, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMULHRSW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .WIG, 0x0B, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMULHRSW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .WIG, 0x0B, fmem), .RVM, .{AVX512BW}),
    // VPMULHUW
    vec(.VPMULHUW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xE4), .RVM, .{AVX}),
    vec(.VPMULHUW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xE4), .RVM, .{AVX2}),
    vec(.VPMULHUW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xE4, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMULHUW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xE4, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMULHUW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xE4, fmem), .RVM, .{AVX512BW}),
    // VPMULHW
    vec(.VPMULHW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xE5), .RVM, .{AVX}),
    vec(.VPMULHW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xE5), .RVM, .{AVX2}),
    vec(.VPMULHW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xE5, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMULHW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xE5, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMULHW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xE5, fmem), .RVM, .{AVX512BW}),
    // VPMULLD / VPMULLQ
    // VPMULLD
    vec(.VPMULLD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x40), .RVM, .{AVX}),
    vec(.VPMULLD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x40), .RVM, .{AVX2}),
    vec(.VPMULLD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x40, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMULLD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x40, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMULLD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x40, full), .RVM, .{AVX512F}),
    // VPMULLQ
    vec(.VPMULLQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x40, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VPMULLQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x40, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VPMULLQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x40, full), .RVM, .{AVX512DQ}),
    // VPMULLW
    vec(.VPMULLW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xD5), .RVM, .{AVX}),
    vec(.VPMULLW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xD5), .RVM, .{AVX2}),
    vec(.VPMULLW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xD5, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMULLW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xD5, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPMULLW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xD5, fmem), .RVM, .{AVX512BW}),
    // VPMULUDQ
    vec(.VPMULUDQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xF4), .RVM, .{AVX}),
    vec(.VPMULUDQ, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xF4), .RVM, .{AVX2}),
    vec(.VPMULUDQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0xF4, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMULUDQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0xF4, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPMULUDQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0xF4, full), .RVM, .{AVX512F}),
    // VPOR
    vec(.VPOR, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xEB), .RVM, .{AVX}),
    vec(.VPOR, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xEB), .RVM, .{AVX2}),
    //
    vec(.VPORD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F, .W0, 0xEB, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPORD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F, .W0, 0xEB, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPORD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F, .W0, 0xEB, full), .RVM, .{AVX512F}),
    //
    vec(.VPORQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0xEB, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPORQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0xEB, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPORQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0xEB, full), .RVM, .{AVX512F}),
    // VPSADBW
    vec(.VPSADBW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xF6), .RVM, .{AVX}),
    vec(.VPSADBW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xF6), .RVM, .{AVX2}),
    vec(.VPSADBW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xF6, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSADBW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xF6, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSADBW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xF6, fmem), .RVM, .{AVX512BW}),
    // VPSHUFB
    vec(.VPSHUFB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x00), .RVM, .{AVX}),
    vec(.VPSHUFB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x00), .RVM, .{AVX2}),
    vec(.VPSHUFB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .WIG, 0x00, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSHUFB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .WIG, 0x00, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSHUFB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .WIG, 0x00, fmem), .RVM, .{AVX512BW}),
    // VPSHUFD
    vec(.VPSHUFD, ops3(.xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F, .WIG, 0x70), .vRMI, .{AVX}),
    vec(.VPSHUFD, ops3(.ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F, .WIG, 0x70), .vRMI, .{AVX2}),
    vec(.VPSHUFD, ops3(.xmm_kz, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F, .W0, 0x70, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VPSHUFD, ops3(.ymm_kz, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F, .W0, 0x70, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VPSHUFD, ops3(.zmm_kz, .zmm_m512_m32bcst, .imm8), evex(.L512, ._66, ._0F, .W0, 0x70, full), .vRMI, .{AVX512F}),
    // VPSHUFHW
    vec(.VPSHUFHW, ops3(.xmml, .xmml_m128, .imm8), vex(.L128, ._F3, ._0F, .WIG, 0x70), .vRMI, .{AVX}),
    vec(.VPSHUFHW, ops3(.ymml, .ymml_m256, .imm8), vex(.L256, ._F3, ._0F, .WIG, 0x70), .vRMI, .{AVX2}),
    vec(.VPSHUFHW, ops3(.xmm_kz, .xmm_m128, .imm8), evex(.L128, ._F3, ._0F, .WIG, 0x70, fmem), .vRMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSHUFHW, ops3(.ymm_kz, .ymm_m256, .imm8), evex(.L256, ._F3, ._0F, .WIG, 0x70, fmem), .vRMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSHUFHW, ops3(.zmm_kz, .zmm_m512, .imm8), evex(.L512, ._F3, ._0F, .WIG, 0x70, fmem), .vRMI, .{AVX512BW}),
    // VPSHUFLW
    vec(.VPSHUFLW, ops3(.xmml, .xmml_m128, .imm8), vex(.L128, ._F2, ._0F, .WIG, 0x70), .vRMI, .{AVX}),
    vec(.VPSHUFLW, ops3(.ymml, .ymml_m256, .imm8), vex(.L256, ._F2, ._0F, .WIG, 0x70), .vRMI, .{AVX2}),
    vec(.VPSHUFLW, ops3(.xmm_kz, .xmm_m128, .imm8), evex(.L128, ._F2, ._0F, .WIG, 0x70, fmem), .vRMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSHUFLW, ops3(.ymm_kz, .ymm_m256, .imm8), evex(.L256, ._F2, ._0F, .WIG, 0x70, fmem), .vRMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSHUFLW, ops3(.zmm_kz, .zmm_m512, .imm8), evex(.L512, ._F2, ._0F, .WIG, 0x70, fmem), .vRMI, .{AVX512BW}),
    // VPSIGNB / VPSIGNW / VPSIGND
    // VPSIGNB
    vec(.VPSIGNB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x08), .RVM, .{AVX}),
    vec(.VPSIGNB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x08), .RVM, .{AVX2}),
    // VPSIGNW
    vec(.VPSIGNW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x09), .RVM, .{AVX}),
    vec(.VPSIGNW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x09), .RVM, .{AVX2}),
    // VPSIGND
    vec(.VPSIGND, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x0A), .RVM, .{AVX}),
    vec(.VPSIGND, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x0A), .RVM, .{AVX2}),
    // VPSLLDQ
    vec(.VPSLLDQ, ops3(.xmml, .xmml_m128, .imm8), vexr(.L128, ._66, ._0F, .WIG, 0x73, 7), .VMI, .{AVX}),
    vec(.VPSLLDQ, ops3(.ymml, .ymml_m256, .imm8), vexr(.L256, ._66, ._0F, .WIG, 0x73, 7), .VMI, .{AVX2}),
    vec(.VPSLLDQ, ops3(.xmm_kz, .xmm_m128, .imm8), evexr(.L128, ._66, ._0F, .WIG, 0x73, 7, fmem), .VMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSLLDQ, ops3(.ymm_kz, .ymm_m256, .imm8), evexr(.L256, ._66, ._0F, .WIG, 0x73, 7, fmem), .VMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSLLDQ, ops3(.zmm_kz, .zmm_m512, .imm8), evexr(.L512, ._66, ._0F, .WIG, 0x73, 7, fmem), .VMI, .{AVX512BW}),
    // VPSLLW / VPSLLD / VPSLLQ
    // VPSLLW
    vec(.VPSLLW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xF1), .RVM, .{AVX}),
    vec(.VPSLLW, ops3(.xmml, .xmml_m128, .imm8), vexr(.L128, ._66, ._0F, .WIG, 0x71, 6), .VMI, .{AVX}),
    vec(.VPSLLW, ops3(.ymml, .ymml, .xmml_m128), vex(.L256, ._66, ._0F, .WIG, 0xF1), .RVM, .{AVX2}),
    vec(.VPSLLW, ops3(.ymml, .ymml_m256, .imm8), vexr(.L256, ._66, ._0F, .WIG, 0x71, 6), .VMI, .{AVX2}),
    vec(.VPSLLW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xF1, mem128), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSLLW, ops3(.ymm_kz, .ymm, .xmm_m128), evex(.L256, ._66, ._0F, .WIG, 0xF1, mem128), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSLLW, ops3(.zmm_kz, .zmm, .xmm_m128), evex(.L512, ._66, ._0F, .WIG, 0xF1, mem128), .RVM, .{AVX512BW}),
    vec(.VPSLLW, ops3(.xmm_kz, .xmm_m128, .imm8), evexr(.L128, ._66, ._0F, .WIG, 0x71, 6, fmem), .VMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSLLW, ops3(.ymm_kz, .ymm_m256, .imm8), evexr(.L256, ._66, ._0F, .WIG, 0x71, 6, fmem), .VMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSLLW, ops3(.zmm_kz, .zmm_m512, .imm8), evexr(.L512, ._66, ._0F, .WIG, 0x71, 6, fmem), .VMI, .{AVX512BW}),
    // VPSLLD
    vec(.VPSLLD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xF2), .RVM, .{AVX}),
    vec(.VPSLLD, ops3(.xmml, .xmml_m128, .imm8), vexr(.L128, ._66, ._0F, .WIG, 0x72, 6), .VMI, .{AVX}),
    vec(.VPSLLD, ops3(.ymml, .ymml, .xmml_m128), vex(.L256, ._66, ._0F, .WIG, 0xF2), .RVM, .{AVX2}),
    vec(.VPSLLD, ops3(.ymml, .ymml_m256, .imm8), vexr(.L256, ._66, ._0F, .WIG, 0x72, 6), .VMI, .{AVX2}),
    vec(.VPSLLD, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .W0, 0xF2, mem128), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSLLD, ops3(.ymm_kz, .ymm, .xmm_m128), evex(.L256, ._66, ._0F, .W0, 0xF2, mem128), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSLLD, ops3(.zmm_kz, .zmm, .xmm_m128), evex(.L512, ._66, ._0F, .W0, 0xF2, mem128), .RVM, .{AVX512F}),
    vec(.VPSLLD, ops3(.xmm_kz, .xmm_m128_m32bcst, .imm8), evexr(.L128, ._66, ._0F, .W0, 0x72, 6, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPSLLD, ops3(.ymm_kz, .ymm_m256_m32bcst, .imm8), evexr(.L256, ._66, ._0F, .W0, 0x72, 6, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPSLLD, ops3(.zmm_kz, .zmm_m512_m32bcst, .imm8), evexr(.L512, ._66, ._0F, .W0, 0x72, 6, full), .VMI, .{AVX512F}),
    // VPSLLQ
    vec(.VPSLLQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xF3), .RVM, .{AVX}),
    vec(.VPSLLQ, ops3(.xmml, .xmml_m128, .imm8), vexr(.L128, ._66, ._0F, .WIG, 0x73, 6), .VMI, .{AVX}),
    vec(.VPSLLQ, ops3(.ymml, .ymml, .xmml_m128), vex(.L256, ._66, ._0F, .WIG, 0xF3), .RVM, .{AVX2}),
    vec(.VPSLLQ, ops3(.ymml, .ymml_m256, .imm8), vexr(.L256, ._66, ._0F, .WIG, 0x73, 6), .VMI, .{AVX2}),
    vec(.VPSLLQ, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .W1, 0xF3, mem128), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSLLQ, ops3(.ymm_kz, .ymm, .xmm_m128), evex(.L256, ._66, ._0F, .W1, 0xF3, mem128), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSLLQ, ops3(.zmm_kz, .zmm, .xmm_m128), evex(.L512, ._66, ._0F, .W1, 0xF3, mem128), .RVM, .{AVX512F}),
    vec(.VPSLLQ, ops3(.xmm_kz, .xmm_m128_m64bcst, .imm8), evexr(.L128, ._66, ._0F, .W1, 0x73, 6, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPSLLQ, ops3(.ymm_kz, .ymm_m256_m64bcst, .imm8), evexr(.L256, ._66, ._0F, .W1, 0x73, 6, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPSLLQ, ops3(.zmm_kz, .zmm_m512_m64bcst, .imm8), evexr(.L512, ._66, ._0F, .W1, 0x73, 6, full), .VMI, .{AVX512F}),
    // VPSRAW / VPSRAD / VPSRAQ
    // VPSRAW
    vec(.VPSRAW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xE1), .RVM, .{AVX}),
    vec(.VPSRAW, ops3(.xmml, .xmml_m128, .imm8), vexr(.L128, ._66, ._0F, .WIG, 0x71, 4), .VMI, .{AVX}),
    vec(.VPSRAW, ops3(.ymml, .ymml, .xmml_m128), vex(.L256, ._66, ._0F, .WIG, 0xE1), .RVM, .{AVX2}),
    vec(.VPSRAW, ops3(.ymml, .ymml_m256, .imm8), vexr(.L256, ._66, ._0F, .WIG, 0x71, 4), .VMI, .{AVX2}),
    vec(.VPSRAW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xE1, mem128), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSRAW, ops3(.ymm_kz, .ymm, .xmm_m128), evex(.L256, ._66, ._0F, .WIG, 0xE1, mem128), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSRAW, ops3(.zmm_kz, .zmm, .xmm_m128), evex(.L512, ._66, ._0F, .WIG, 0xE1, mem128), .RVM, .{AVX512BW}),
    vec(.VPSRAW, ops3(.xmm_kz, .xmm_m128, .imm8), evexr(.L128, ._66, ._0F, .WIG, 0x71, 4, fmem), .VMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSRAW, ops3(.ymm_kz, .ymm_m256, .imm8), evexr(.L256, ._66, ._0F, .WIG, 0x71, 4, fmem), .VMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSRAW, ops3(.zmm_kz, .zmm_m512, .imm8), evexr(.L512, ._66, ._0F, .WIG, 0x71, 4, fmem), .VMI, .{AVX512BW}),
    // VPSRAD
    vec(.VPSRAD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xE2), .RVM, .{AVX}),
    vec(.VPSRAD, ops3(.xmml, .xmml_m128, .imm8), vexr(.L128, ._66, ._0F, .WIG, 0x72, 4), .VMI, .{AVX}),
    vec(.VPSRAD, ops3(.ymml, .ymml, .xmml_m128), vex(.L256, ._66, ._0F, .WIG, 0xE2), .RVM, .{AVX2}),
    vec(.VPSRAD, ops3(.ymml, .ymml_m256, .imm8), vexr(.L256, ._66, ._0F, .WIG, 0x72, 4), .VMI, .{AVX2}),
    vec(.VPSRAD, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .W0, 0xE2, mem128), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRAD, ops3(.ymm_kz, .ymm, .xmm_m128), evex(.L256, ._66, ._0F, .W0, 0xE2, mem128), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRAD, ops3(.zmm_kz, .zmm, .xmm_m128), evex(.L512, ._66, ._0F, .W0, 0xE2, mem128), .RVM, .{AVX512F}),
    vec(.VPSRAD, ops3(.xmm_kz, .xmm_m128_m32bcst, .imm8), evexr(.L128, ._66, ._0F, .W0, 0x72, 4, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPSRAD, ops3(.ymm_kz, .ymm_m256_m32bcst, .imm8), evexr(.L256, ._66, ._0F, .W0, 0x72, 4, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPSRAD, ops3(.zmm_kz, .zmm_m512_m32bcst, .imm8), evexr(.L512, ._66, ._0F, .W0, 0x72, 4, full), .VMI, .{AVX512F}),
    // VPSRAQ
    vec(.VPSRAQ, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .W1, 0xE2, mem128), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRAQ, ops3(.ymm_kz, .ymm, .xmm_m128), evex(.L256, ._66, ._0F, .W1, 0xE2, mem128), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRAQ, ops3(.zmm_kz, .zmm, .xmm_m128), evex(.L512, ._66, ._0F, .W1, 0xE2, mem128), .RVM, .{AVX512F}),
    vec(.VPSRAQ, ops3(.xmm_kz, .xmm_m128_m64bcst, .imm8), evexr(.L128, ._66, ._0F, .W1, 0x72, 4, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPSRAQ, ops3(.ymm_kz, .ymm_m256_m64bcst, .imm8), evexr(.L256, ._66, ._0F, .W1, 0x72, 4, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPSRAQ, ops3(.zmm_kz, .zmm_m512_m64bcst, .imm8), evexr(.L512, ._66, ._0F, .W1, 0x72, 4, full), .VMI, .{AVX512F}),
    // VPSRLDQ
    vec(.VPSRLDQ, ops3(.xmml, .xmml_m128, .imm8), vexr(.L128, ._66, ._0F, .WIG, 0x73, 3), .VMI, .{AVX}),
    vec(.VPSRLDQ, ops3(.ymml, .ymml_m256, .imm8), vexr(.L256, ._66, ._0F, .WIG, 0x73, 3), .VMI, .{AVX2}),
    vec(.VPSRLDQ, ops3(.xmm_kz, .xmm_m128, .imm8), evexr(.L128, ._66, ._0F, .WIG, 0x73, 3, fmem), .VMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSRLDQ, ops3(.ymm_kz, .ymm_m256, .imm8), evexr(.L256, ._66, ._0F, .WIG, 0x73, 3, fmem), .VMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSRLDQ, ops3(.zmm_kz, .zmm_m512, .imm8), evexr(.L512, ._66, ._0F, .WIG, 0x73, 3, fmem), .VMI, .{AVX512BW}),
    // VPSRLW / VPSRLD / VPSRLQ
    // VPSRLW
    vec(.VPSRLW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xD1), .RVM, .{AVX}),
    vec(.VPSRLW, ops3(.xmml, .xmml_m128, .imm8), vexr(.L128, ._66, ._0F, .WIG, 0x71, 2), .VMI, .{AVX}),
    vec(.VPSRLW, ops3(.ymml, .ymml, .xmml_m128), vex(.L256, ._66, ._0F, .WIG, 0xD1), .RVM, .{AVX2}),
    vec(.VPSRLW, ops3(.ymml, .ymml_m256, .imm8), vexr(.L256, ._66, ._0F, .WIG, 0x71, 2), .VMI, .{AVX2}),
    vec(.VPSRLW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xD1, mem128), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSRLW, ops3(.ymm_kz, .ymm, .xmm_m128), evex(.L256, ._66, ._0F, .WIG, 0xD1, mem128), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSRLW, ops3(.zmm_kz, .zmm, .xmm_m128), evex(.L512, ._66, ._0F, .WIG, 0xD1, mem128), .RVM, .{AVX512BW}),
    vec(.VPSRLW, ops3(.xmm_kz, .xmm_m128, .imm8), evexr(.L128, ._66, ._0F, .WIG, 0x71, 2, fmem), .VMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSRLW, ops3(.ymm_kz, .ymm_m256, .imm8), evexr(.L256, ._66, ._0F, .WIG, 0x71, 2, fmem), .VMI, .{ AVX512VL, AVX512BW }),
    vec(.VPSRLW, ops3(.zmm_kz, .zmm_m512, .imm8), evexr(.L512, ._66, ._0F, .WIG, 0x71, 2, fmem), .VMI, .{AVX512BW}),
    // VPSRLD
    vec(.VPSRLD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xD2), .RVM, .{AVX}),
    vec(.VPSRLD, ops3(.xmml, .xmml_m128, .imm8), vexr(.L128, ._66, ._0F, .WIG, 0x72, 2), .VMI, .{AVX}),
    vec(.VPSRLD, ops3(.ymml, .ymml, .xmml_m128), vex(.L256, ._66, ._0F, .WIG, 0xD2), .RVM, .{AVX2}),
    vec(.VPSRLD, ops3(.ymml, .ymml_m256, .imm8), vexr(.L256, ._66, ._0F, .WIG, 0x72, 2), .VMI, .{AVX2}),
    vec(.VPSRLD, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .W0, 0xD2, mem128), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRLD, ops3(.ymm_kz, .ymm, .xmm_m128), evex(.L256, ._66, ._0F, .W0, 0xD2, mem128), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRLD, ops3(.zmm_kz, .zmm, .xmm_m128), evex(.L512, ._66, ._0F, .W0, 0xD2, mem128), .RVM, .{AVX512F}),
    vec(.VPSRLD, ops3(.xmm_kz, .xmm_m128_m32bcst, .imm8), evexr(.L128, ._66, ._0F, .W0, 0x72, 2, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPSRLD, ops3(.ymm_kz, .ymm_m256_m32bcst, .imm8), evexr(.L256, ._66, ._0F, .W0, 0x72, 2, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPSRLD, ops3(.zmm_kz, .zmm_m512_m32bcst, .imm8), evexr(.L512, ._66, ._0F, .W0, 0x72, 2, full), .VMI, .{AVX512F}),
    // VPSRLQ
    vec(.VPSRLQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xD3), .RVM, .{AVX}),
    vec(.VPSRLQ, ops3(.xmml, .xmml_m128, .imm8), vexr(.L128, ._66, ._0F, .WIG, 0x73, 2), .VMI, .{AVX}),
    vec(.VPSRLQ, ops3(.ymml, .ymml, .xmml_m128), vex(.L256, ._66, ._0F, .WIG, 0xD3), .RVM, .{AVX2}),
    vec(.VPSRLQ, ops3(.ymml, .ymml_m256, .imm8), vexr(.L256, ._66, ._0F, .WIG, 0x73, 2), .VMI, .{AVX2}),
    vec(.VPSRLQ, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .W1, 0xD3, mem128), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRLQ, ops3(.ymm_kz, .ymm, .xmm_m128), evex(.L256, ._66, ._0F, .W1, 0xD3, mem128), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRLQ, ops3(.zmm_kz, .zmm, .xmm_m128), evex(.L512, ._66, ._0F, .W1, 0xD3, mem128), .RVM, .{AVX512F}),
    vec(.VPSRLQ, ops3(.xmm_kz, .xmm_m128_m64bcst, .imm8), evexr(.L128, ._66, ._0F, .W1, 0x73, 2, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPSRLQ, ops3(.ymm_kz, .ymm_m256_m64bcst, .imm8), evexr(.L256, ._66, ._0F, .W1, 0x73, 2, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPSRLQ, ops3(.zmm_kz, .zmm_m512_m64bcst, .imm8), evexr(.L512, ._66, ._0F, .W1, 0x73, 2, full), .VMI, .{AVX512F}),
    // VPSUBB / VPSUBW / VPSUBD
    // VPSUBB
    vec(.VPSUBB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xF8), .RVM, .{AVX}),
    vec(.VPSUBB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xF8), .RVM, .{AVX2}),
    vec(.VPSUBB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xF8, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSUBB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xF8, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSUBB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xF8, fmem), .RVM, .{AVX512BW}),
    // VPSUBW
    vec(.VPSUBW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xF9), .RVM, .{AVX}),
    vec(.VPSUBW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xF9), .RVM, .{AVX2}),
    vec(.VPSUBW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xF9, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSUBW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xF9, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSUBW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xF9, fmem), .RVM, .{AVX512BW}),
    // VPSUBD
    vec(.VPSUBD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xFA), .RVM, .{AVX}),
    vec(.VPSUBD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xFA), .RVM, .{AVX2}),
    vec(.VPSUBD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F, .W0, 0xFA, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSUBD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F, .W0, 0xFA, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSUBD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F, .W0, 0xFA, full), .RVM, .{AVX512F}),
    // VPSUBQ
    vec(.VPSUBQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xFB), .RVM, .{AVX}),
    vec(.VPSUBQ, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xFB), .RVM, .{AVX2}),
    vec(.VPSUBQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0xFB, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSUBQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0xFB, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSUBQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0xFB, full), .RVM, .{AVX512F}),
    // VPSUBSB / VPSUBSW
    vec(.VPSUBSB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xE8), .RVM, .{AVX}),
    vec(.VPSUBSB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xE8), .RVM, .{AVX2}),
    vec(.VPSUBSB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xE8, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSUBSB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xE8, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSUBSB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xE8, fmem), .RVM, .{AVX512BW}),
    //
    vec(.VPSUBSW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xE9), .RVM, .{AVX}),
    vec(.VPSUBSW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xE9), .RVM, .{AVX2}),
    vec(.VPSUBSW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xE9, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSUBSW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xE9, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSUBSW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xE9, fmem), .RVM, .{AVX512BW}),
    // VPSUBUSB / VPSUBUSW
    vec(.VPSUBUSB, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xD8), .RVM, .{AVX}),
    vec(.VPSUBUSB, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xD8), .RVM, .{AVX2}),
    vec(.VPSUBUSB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xD8, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSUBUSB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xD8, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSUBUSB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xD8, fmem), .RVM, .{AVX512BW}),
    //
    vec(.VPSUBUSW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xD9), .RVM, .{AVX}),
    vec(.VPSUBUSW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xD9), .RVM, .{AVX2}),
    vec(.VPSUBUSW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0xD9, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSUBUSW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0xD9, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSUBUSW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0xD9, fmem), .RVM, .{AVX512BW}),
    // VPTEST
    vec(.VPTEST, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .WIG, 0x17), .vRM, .{AVX}),
    vec(.VPTEST, ops2(.ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .WIG, 0x17), .vRM, .{AVX}),
    // VPUNPCKHBW / VPUNPCKHWD / VPUNPCKHDQ / VPUNPCKHQDQ
    // VPUNPCKHBW
    vec(.VPUNPCKHBW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x68), .RVM, .{AVX}),
    vec(.VPUNPCKHBW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x68), .RVM, .{AVX2}),
    vec(.VPUNPCKHBW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0x68, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPUNPCKHBW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0x68, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPUNPCKHBW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0x68, fmem), .RVM, .{AVX512BW}),
    // VPUNPCKHWD
    vec(.VPUNPCKHWD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x69), .RVM, .{AVX}),
    vec(.VPUNPCKHWD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x69), .RVM, .{AVX2}),
    vec(.VPUNPCKHWD, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0x69, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPUNPCKHWD, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0x69, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPUNPCKHWD, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0x69, fmem), .RVM, .{AVX512BW}),
    // VPUNPCKHDQ
    vec(.VPUNPCKHDQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x6A), .RVM, .{AVX}),
    vec(.VPUNPCKHDQ, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x6A), .RVM, .{AVX2}),
    vec(.VPUNPCKHDQ, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F, .W0, 0x6A, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPUNPCKHDQ, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F, .W0, 0x6A, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPUNPCKHDQ, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F, .W0, 0x6A, full), .RVM, .{AVX512F}),
    // VPUNPCKHQDQ
    vec(.VPUNPCKHQDQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x6D), .RVM, .{AVX}),
    vec(.VPUNPCKHQDQ, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x6D), .RVM, .{AVX2}),
    vec(.VPUNPCKHQDQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x6D, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPUNPCKHQDQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x6D, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPUNPCKHQDQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0x6D, full), .RVM, .{AVX512F}),
    // VPUNPCKLBW / VPUNPCKLWD / VPUNPCKLDQ / VPUNPCKLQDQ
    // VPUNPCKLBW
    vec(.VPUNPCKLBW, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x60), .RVM, .{AVX}),
    vec(.VPUNPCKLBW, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x60), .RVM, .{AVX2}),
    vec(.VPUNPCKLBW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0x60, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPUNPCKLBW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0x60, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPUNPCKLBW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0x60, fmem), .RVM, .{AVX512BW}),
    // VPUNPCKLWD
    vec(.VPUNPCKLWD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x61), .RVM, .{AVX}),
    vec(.VPUNPCKLWD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x61), .RVM, .{AVX2}),
    vec(.VPUNPCKLWD, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F, .WIG, 0x61, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPUNPCKLWD, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F, .WIG, 0x61, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPUNPCKLWD, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F, .WIG, 0x61, fmem), .RVM, .{AVX512BW}),
    // VPUNPCKLDQ
    vec(.VPUNPCKLDQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x62), .RVM, .{AVX}),
    vec(.VPUNPCKLDQ, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x62), .RVM, .{AVX2}),
    vec(.VPUNPCKLDQ, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F, .W0, 0x62, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPUNPCKLDQ, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F, .W0, 0x62, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPUNPCKLDQ, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F, .W0, 0x62, full), .RVM, .{AVX512F}),
    // VPUNPCKLQDQ
    vec(.VPUNPCKLQDQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x6C), .RVM, .{AVX}),
    vec(.VPUNPCKLQDQ, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x6C), .RVM, .{AVX2}),
    vec(.VPUNPCKLQDQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x6C, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPUNPCKLQDQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x6C, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPUNPCKLQDQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0x6C, full), .RVM, .{AVX512F}),
    // VPXOR
    vec(.VPXOR, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0xEF), .RVM, .{AVX}),
    vec(.VPXOR, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0xEF), .RVM, .{AVX2}),
    //
    vec(.VPXORD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F, .W0, 0xEF, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPXORD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F, .W0, 0xEF, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPXORD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F, .W0, 0xEF, full), .RVM, .{AVX512F}),
    //
    vec(.VPXORQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0xEF, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPXORQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0xEF, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPXORQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0xEF, full), .RVM, .{AVX512F}),
    // VRCPPS
    vec(.VRCPPS, ops2(.xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x53), .vRM, .{AVX}),
    vec(.VRCPPS, ops2(.ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x53), .vRM, .{AVX}),
    // VRCPSS
    vec(.VRCPSS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._F3, ._0F, .WIG, 0x53), .RVM, .{AVX}),
    // VROUNDPD
    vec(.VROUNDPD, ops3(.xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x09), .vRMI, .{AVX}),
    vec(.VROUNDPD, ops3(.ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .WIG, 0x09), .vRMI, .{AVX}),
    // VROUNDPS
    vec(.VROUNDPS, ops3(.xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .WIG, 0x08), .vRMI, .{AVX}),
    vec(.VROUNDPS, ops3(.ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .WIG, 0x08), .vRMI, .{AVX}),
    // VROUNDSD
    vec(.VROUNDSD, ops4(.xmml, .xmml, .xmml_m64, .imm8), vex(.LIG, ._66, ._0F3A, .WIG, 0x0B), .RVMI, .{AVX}),
    // VROUNDSS
    vec(.VROUNDSS, ops4(.xmml, .xmml, .xmml_m32, .imm8), vex(.LIG, ._66, ._0F3A, .WIG, 0x0A), .RVMI, .{AVX}),
    // VRSQRTPS
    vec(.VRSQRTPS, ops2(.xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x52), .vRM, .{AVX}),
    vec(.VRSQRTPS, ops2(.ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x52), .vRM, .{AVX}),
    // VRSQRTSS
    vec(.VRSQRTSS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._F3, ._0F, .WIG, 0x52), .RVM, .{AVX}),
    // VSHUFPD
    vec(.VSHUFPD, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F, .WIG, 0xC6), .RVMI, .{AVX}),
    vec(.VSHUFPD, ops4(.ymml, .xmml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F, .WIG, 0xC6), .RVMI, .{AVX}),
    vec(.VSHUFPD, ops4(.xmm_kz, .xmm, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F, .W1, 0xC6, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VSHUFPD, ops4(.ymm_kz, .xmm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F, .W1, 0xC6, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VSHUFPD, ops4(.zmm_kz, .xmm, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F, .W1, 0xC6, full), .RVMI, .{AVX512F}),
    // VSHUFPS
    vec(.VSHUFPS, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._NP, ._0F, .WIG, 0xC6), .RVMI, .{AVX}),
    vec(.VSHUFPS, ops4(.ymml, .xmml, .ymml_m256, .imm8), vex(.L256, ._NP, ._0F, .WIG, 0xC6), .RVMI, .{AVX}),
    vec(.VSHUFPS, ops4(.xmm_kz, .xmm, .xmm_m128_m32bcst, .imm8), evex(.L128, ._NP, ._0F, .W0, 0xC6, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VSHUFPS, ops4(.ymm_kz, .xmm, .ymm_m256_m32bcst, .imm8), evex(.L256, ._NP, ._0F, .W0, 0xC6, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VSHUFPS, ops4(.zmm_kz, .xmm, .zmm_m512_m32bcst, .imm8), evex(.L512, ._NP, ._0F, .W0, 0xC6, full), .RVMI, .{AVX512F}),
    // VSQRTPD
    vec(.VSQRTPD, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x51), .vRM, .{AVX}),
    vec(.VSQRTPD, ops2(.ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x51), .vRM, .{AVX}),
    vec(.VSQRTPD, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x51, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VSQRTPD, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x51, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VSQRTPD, ops2(.zmm_kz, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F, .W1, 0x51, full), .vRM, .{AVX512F}),
    // VSQRTPS
    vec(.VSQRTPS, ops2(.xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x51), .vRM, .{AVX}),
    vec(.VSQRTPS, ops2(.ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x51), .vRM, .{AVX}),
    vec(.VSQRTPS, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x51, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VSQRTPS, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x51, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VSQRTPS, ops2(.zmm_kz, .zmm_m512_m32bcst_er), evex(.L512, ._NP, ._0F, .W0, 0x51, full), .vRM, .{AVX512F}),
    // VSQRTSD
    vec(.VSQRTSD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._F2, ._0F, .WIG, 0x51), .RVM, .{AVX}),
    vec(.VSQRTSD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._F2, ._0F, .W1, 0x51, t1s), .RVM, .{AVX512F}),
    // VSQRTSS
    vec(.VSQRTSS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._F3, ._0F, .WIG, 0x51), .RVM, .{AVX}),
    vec(.VSQRTSS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._F3, ._0F, .W0, 0x51, t1s), .RVM, .{AVX512F}),
    // VSTMXCSR
    vec(.VSTMXCSR, ops1(.rm_mem32), vexr(.LZ, ._NP, ._0F, .WIG, 0xAE, 3), .vM, .{AVX}),
    // VSUBPD
    vec(.VSUBPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x5C), .RVM, .{AVX}),
    vec(.VSUBPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x5C), .RVM, .{AVX}),
    vec(.VSUBPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x5C, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VSUBPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x5C, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VSUBPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F, .W1, 0x5C, full), .RVM, .{AVX512F}),
    // VSUBPS
    vec(.VSUBPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x5C), .RVM, .{AVX}),
    vec(.VSUBPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x5C), .RVM, .{AVX}),
    vec(.VSUBPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x5C, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VSUBPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x5C, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VSUBPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst_er), evex(.L512, ._NP, ._0F, .W0, 0x5C, full), .RVM, .{AVX512F}),
    // VSUBSD
    vec(.VSUBSD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._F2, ._0F, .WIG, 0x5C), .RVM, .{AVX}),
    vec(.VSUBSD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._F2, ._0F, .W1, 0x5C, t1s), .RVM, .{AVX512F}),
    // VSUBSS
    vec(.VSUBSS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._F3, ._0F, .WIG, 0x5C), .RVM, .{AVX}),
    vec(.VSUBSS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._F3, ._0F, .W0, 0x5C, t1s), .RVM, .{AVX512F}),
    // VUCOMISD
    vec(.VUCOMISD, ops2(.xmml, .xmml_m64), vex(.LIG, ._66, ._0F, .WIG, 0x2E), .vRM, .{AVX}),
    vec(.VUCOMISD, ops2(.xmm_kz, .xmm_m64_sae), evex(.LIG, ._66, ._0F, .W1, 0x2E, t1s), .vRM, .{AVX512F}),
    // VUCOMISS
    vec(.VUCOMISS, ops2(.xmml, .xmml_m32), vex(.LIG, ._NP, ._0F, .WIG, 0x2E), .vRM, .{AVX}),
    vec(.VUCOMISS, ops2(.xmm_kz, .xmm_m32_sae), evex(.LIG, ._NP, ._0F, .W0, 0x2E, t1s), .vRM, .{AVX512F}),
    // VUNPCKHPD
    vec(.VUNPCKHPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x15), .RVM, .{AVX}),
    vec(.VUNPCKHPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x15), .RVM, .{AVX}),
    vec(.VUNPCKHPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x15, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VUNPCKHPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x15, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VUNPCKHPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0x15, full), .RVM, .{AVX512F}),
    // VUNPCKHPS
    vec(.VUNPCKHPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x15), .RVM, .{AVX}),
    vec(.VUNPCKHPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x15), .RVM, .{AVX}),
    vec(.VUNPCKHPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x15, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VUNPCKHPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x15, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VUNPCKHPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._NP, ._0F, .W0, 0x15, full), .RVM, .{AVX512F}),
    // VUNPCKLPD
    vec(.VUNPCKLPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x14), .RVM, .{AVX}),
    vec(.VUNPCKLPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x14), .RVM, .{AVX}),
    vec(.VUNPCKLPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x14, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VUNPCKLPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x14, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VUNPCKLPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0x14, full), .RVM, .{AVX512F}),
    // VUNPCKLPS
    vec(.VUNPCKLPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x14), .RVM, .{AVX}),
    vec(.VUNPCKLPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x14), .RVM, .{AVX}),
    vec(.VUNPCKLPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x14, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VUNPCKLPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x14, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VUNPCKLPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._NP, ._0F, .W0, 0x14, full), .RVM, .{AVX512F}),
    //
    // Instructions V-Z
    //
    // VALIGND / VALIGNQ
    // VALIGND
    vec(.VALIGND, ops4(.xmm_kz, .xmm, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x03, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VALIGND, ops4(.ymm_kz, .xmm, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x03, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VALIGND, ops4(.zmm_kz, .xmm, .zmm_m512_m32bcst, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x03, full), .RVMI, .{AVX512F}),
    // VALIGNQ
    vec(.VALIGNQ, ops4(.xmm_kz, .xmm, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x03, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VALIGNQ, ops4(.ymm_kz, .xmm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x03, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VALIGNQ, ops4(.zmm_kz, .xmm, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x03, full), .RVMI, .{AVX512F}),
    // VBLENDMPD / VBLENDMPS
    // VBLENDMPD
    vec(.VBLENDMPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x65, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VBLENDMPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x65, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VBLENDMPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x65, full), .RVM, .{AVX512F}),
    // VBLENDMPS
    vec(.VBLENDMPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x65, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VBLENDMPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x65, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VBLENDMPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x65, full), .RVM, .{AVX512F}),
    // VBROADCAST
    // VBROADCASTSS
    vec(.VBROADCASTSS, ops2(.xmml, .rm_mem32), vex(.L128, ._66, ._0F38, .W0, 0x18), .vRM, .{AVX}),
    vec(.VBROADCASTSS, ops2(.ymml, .rm_mem32), vex(.L256, ._66, ._0F38, .W0, 0x18), .vRM, .{AVX}),
    vec(.VBROADCASTSS, ops2(.xmml, .rm_xmml), vex(.L128, ._66, ._0F38, .W0, 0x18), .vRM, .{AVX2}),
    vec(.VBROADCASTSS, ops2(.ymml, .rm_xmml), vex(.L256, ._66, ._0F38, .W0, 0x18), .vRM, .{AVX2}),
    vec(.VBROADCASTSS, ops2(.xmm_kz, .xmm_m32), evex(.L128, ._66, ._0F38, .W0, 0x18, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VBROADCASTSS, ops2(.ymm_kz, .xmm_m32), evex(.L256, ._66, ._0F38, .W0, 0x18, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VBROADCASTSS, ops2(.zmm_kz, .xmm_m32), evex(.L512, ._66, ._0F38, .W0, 0x18, t1s), .vRM, .{AVX512F}),
    // VBROADCASTSD
    vec(.VBROADCASTSD, ops2(.ymml, .rm_mem64), vex(.L256, ._66, ._0F38, .W0, 0x19), .vRM, .{AVX}),
    vec(.VBROADCASTSD, ops2(.ymml, .rm_xmml), vex(.L256, ._66, ._0F38, .W0, 0x19), .vRM, .{AVX2}),
    vec(.VBROADCASTSD, ops2(.ymm_kz, .xmm_m64), evex(.L256, ._66, ._0F38, .W1, 0x19, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VBROADCASTSD, ops2(.zmm_kz, .xmm_m64), evex(.L512, ._66, ._0F38, .W1, 0x19, t1s), .vRM, .{AVX512F}),
    // VBROADCASTF128
    vec(.VBROADCASTF128, ops2(.ymml, .rm_mem128), vex(.L256, ._66, ._0F38, .W0, 0x1A), .vRM, .{AVX}),
    // VBROADCASTF32X2
    vec(.VBROADCASTF32X2, ops2(.ymm_kz, .xmm_m64), evex(.L256, ._66, ._0F38, .W0, 0x19, tup2), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VBROADCASTF32X2, ops2(.zmm_kz, .xmm_m64), evex(.L512, ._66, ._0F38, .W0, 0x19, tup2), .vRM, .{AVX512DQ}),
    // VBROADCASTF32X4
    vec(.VBROADCASTF32X4, ops2(.ymm_kz, .rm_mem128), evex(.L256, ._66, ._0F38, .W0, 0x1A, tup4), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VBROADCASTF32X4, ops2(.zmm_kz, .rm_mem128), evex(.L512, ._66, ._0F38, .W0, 0x1A, tup4), .vRM, .{AVX512F}),
    // VBROADCASTF64X2
    vec(.VBROADCASTF64X2, ops2(.ymm_kz, .rm_mem128), evex(.L256, ._66, ._0F38, .W1, 0x1A, tup2), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VBROADCASTF64X2, ops2(.zmm_kz, .rm_mem128), evex(.L512, ._66, ._0F38, .W1, 0x1A, tup2), .vRM, .{AVX512DQ}),
    // VBROADCASTF32X8
    vec(.VBROADCASTF32X8, ops2(.zmm_kz, .rm_mem256), evex(.L512, ._66, ._0F38, .W0, 0x1B, tup8), .vRM, .{AVX512DQ}),
    // VBROADCASTF64X4
    vec(.VBROADCASTF64X4, ops2(.zmm_kz, .rm_mem256), evex(.L512, ._66, ._0F38, .W1, 0x1B, tup4), .vRM, .{AVX512F}),
    // VCOMPRESSPD
    vec(.VCOMPRESSPD, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._66, ._0F38, .W1, 0x8A, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VCOMPRESSPD, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._66, ._0F38, .W1, 0x8A, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VCOMPRESSPD, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._66, ._0F38, .W1, 0x8A, t1s), .vMR, .{AVX512F}),
    // VCOMPRESSPS
    vec(.VCOMPRESSPS, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._66, ._0F38, .W0, 0x8A, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VCOMPRESSPS, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._66, ._0F38, .W0, 0x8A, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VCOMPRESSPS, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._66, ._0F38, .W0, 0x8A, t1s), .vMR, .{AVX512F}),
    // VCVTPD2QQ
    vec(.VCVTPD2QQ, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x7B, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTPD2QQ, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x7B, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTPD2QQ, ops2(.zmm_kz, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F, .W1, 0x7B, full), .vRM, .{AVX512DQ}),
    // VCVTPD2UDQ
    vec(.VCVTPD2UDQ, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._NP, ._0F, .W1, 0x79, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPD2UDQ, ops2(.xmm_kz, .ymm_m256_m64bcst), evex(.L256, ._NP, ._0F, .W1, 0x79, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPD2UDQ, ops2(.ymm_kz, .zmm_m512_m64bcst_er), evex(.L512, ._NP, ._0F, .W1, 0x79, full), .vRM, .{AVX512F}),
    // VCVTPD2UQQ
    vec(.VCVTPD2UQQ, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x79, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTPD2UQQ, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x79, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTPD2UQQ, ops2(.zmm_kz, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F, .W1, 0x79, full), .vRM, .{AVX512DQ}),
    // VCVTPH2PS
    vec(.VCVTPH2PS, ops2(.xmml, .xmml_m64), vex(.L128, ._66, ._0F38, .W0, 0x13), .vRM, .{cpu.F16C}),
    vec(.VCVTPH2PS, ops2(.ymml, .xmml_m128), vex(.L256, ._66, ._0F38, .W0, 0x13), .vRM, .{cpu.F16C}),
    vec(.VCVTPH2PS, ops2(.xmm_kz, .xmm_m64), evex(.L128, ._66, ._0F38, .W0, 0x13, hmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPH2PS, ops2(.ymm_kz, .xmm_m128), evex(.L256, ._66, ._0F38, .W0, 0x13, hmem), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPH2PS, ops2(.zmm_kz, .ymm_m256_sae), evex(.L512, ._66, ._0F38, .W0, 0x13, hmem), .vRM, .{AVX512F}),
    // VCVTPS2PH
    vec(.VCVTPS2PH, ops3(.xmml_m64, .xmml, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x1D), .vMRI, .{cpu.F16C}),
    vec(.VCVTPS2PH, ops3(.xmml_m128, .ymml, .imm8), vex(.L256, ._66, ._0F3A, .W0, 0x1D), .vMRI, .{cpu.F16C}),
    vec(.VCVTPS2PH, ops3(.xmm_m64_kz, .xmm, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x1D, hmem), .vMRI, .{ AVX512VL, AVX512F }),
    vec(.VCVTPS2PH, ops3(.xmm_m128_kz, .ymm, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x1D, hmem), .vMRI, .{ AVX512VL, AVX512F }),
    vec(.VCVTPS2PH, ops3(.ymm_m256_kz, .zmm_sae, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x1D, hmem), .vMRI, .{AVX512F}),
    // VCVTPS2QQ
    vec(.VCVTPS2QQ, ops2(.xmm_kz, .xmm_m64_m32bcst), evex(.L128, ._66, ._0F, .W0, 0x7B, half), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTPS2QQ, ops2(.ymm_kz, .xmm_m128_m32bcst), evex(.L256, ._66, ._0F, .W0, 0x7B, half), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTPS2QQ, ops2(.zmm_kz, .ymm_m256_m32bcst_er), evex(.L512, ._66, ._0F, .W0, 0x7B, half), .vRM, .{AVX512DQ}),
    // VCVTPS2UDQ
    vec(.VCVTPS2UDQ, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x79, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPS2UDQ, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x79, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTPS2UDQ, ops2(.zmm_kz, .zmm_m512_m32bcst_er), evex(.L512, ._NP, ._0F, .W0, 0x79, full), .vRM, .{AVX512F}),
    // VCVTPS2UQQ
    vec(.VCVTPS2UQQ, ops2(.xmm_kz, .xmm_m64_m32bcst), evex(.L128, ._66, ._0F, .W0, 0x79, half), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTPS2UQQ, ops2(.ymm_kz, .xmm_m128_m32bcst), evex(.L256, ._66, ._0F, .W0, 0x79, half), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTPS2UQQ, ops2(.zmm_kz, .ymm_m256_m32bcst_er), evex(.L512, ._66, ._0F, .W0, 0x79, half), .vRM, .{AVX512DQ}),
    // VCVTQQ2PD
    vec(.VCVTQQ2PD, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._F3, ._0F, .W1, 0xE6, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTQQ2PD, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._F3, ._0F, .W1, 0xE6, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTQQ2PD, ops2(.zmm_kz, .zmm_m512_m64bcst_er), evex(.L512, ._F3, ._0F, .W1, 0xE6, full), .vRM, .{AVX512DQ}),
    // VCVTQQ2PS
    vec(.VCVTQQ2PS, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._NP, ._0F, .W1, 0x5B, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTQQ2PS, ops2(.xmm_kz, .ymm_m256_m64bcst), evex(.L256, ._NP, ._0F, .W1, 0x5B, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTQQ2PS, ops2(.ymm_kz, .zmm_m512_m64bcst_er), evex(.L512, ._NP, ._0F, .W1, 0x5B, full), .vRM, .{AVX512DQ}),
    // VCVTSD2USI
    vec(.VCVTSD2USI, ops2(.reg32, .xmm_m64_er), evex(.LIG, ._F2, ._0F, .W0, 0x79, t1f), .vRM, .{AVX512F}),
    vec(.VCVTSD2USI, ops2(.reg64, .xmm_m64_er), evex(.LIG, ._F2, ._0F, .W1, 0x79, t1f), .vRM, .{ AVX512F, No32 }),
    // VCVTSS2USI
    vec(.VCVTSS2USI, ops2(.reg32, .xmm_m32_er), evex(.LIG, ._F3, ._0F, .W0, 0x79, t1f), .vRM, .{AVX512F}),
    vec(.VCVTSS2USI, ops2(.reg64, .xmm_m32_er), evex(.LIG, ._F3, ._0F, .W1, 0x79, t1f), .vRM, .{ AVX512F, No32 }),
    // VCVTTPD2QQ
    vec(.VCVTTPD2QQ, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x7A, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTTPD2QQ, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x7A, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTTPD2QQ, ops2(.zmm_kz, .zmm_m512_m64bcst_sae), evex(.L512, ._66, ._0F, .W1, 0x7A, full), .vRM, .{AVX512DQ}),
    // VCVTTPD2UDQ
    vec(.VCVTTPD2UDQ, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._NP, ._0F, .W1, 0x78, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTTPD2UDQ, ops2(.xmm_kz, .ymm_m256_m64bcst), evex(.L256, ._NP, ._0F, .W1, 0x78, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTTPD2UDQ, ops2(.ymm_kz, .zmm_m512_m64bcst_sae), evex(.L512, ._NP, ._0F, .W1, 0x78, full), .vRM, .{AVX512F}),
    // VCVTTPD2UQQ
    vec(.VCVTTPD2UQQ, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x78, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTTPD2UQQ, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x78, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTTPD2UQQ, ops2(.zmm_kz, .zmm_m512_m64bcst_sae), evex(.L512, ._66, ._0F, .W1, 0x78, full), .vRM, .{AVX512DQ}),
    // VCVTTPS2QQ
    vec(.VCVTTPS2QQ, ops2(.xmm_kz, .xmm_m64_m32bcst), evex(.L128, ._66, ._0F, .W0, 0x7A, half), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTTPS2QQ, ops2(.ymm_kz, .xmm_m128_m32bcst), evex(.L256, ._66, ._0F, .W0, 0x7A, half), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTTPS2QQ, ops2(.zmm_kz, .ymm_m256_m32bcst_sae), evex(.L512, ._66, ._0F, .W0, 0x7A, half), .vRM, .{AVX512DQ}),
    // VCVTTPS2UDQ
    vec(.VCVTTPS2UDQ, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x78, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTTPS2UDQ, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x78, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTTPS2UDQ, ops2(.zmm_kz, .zmm_m512_m32bcst_sae), evex(.L512, ._NP, ._0F, .W0, 0x78, full), .vRM, .{AVX512F}),
    // VCVTTPS2UQQ
    vec(.VCVTTPS2UQQ, ops2(.xmm_kz, .xmm_m64_m32bcst), evex(.L128, ._66, ._0F, .W0, 0x78, half), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTTPS2UQQ, ops2(.ymm_kz, .xmm_m128_m32bcst), evex(.L256, ._66, ._0F, .W0, 0x78, half), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTTPS2UQQ, ops2(.zmm_kz, .ymm_m256_m32bcst_sae), evex(.L512, ._66, ._0F, .W0, 0x78, half), .vRM, .{AVX512DQ}),
    // VCVTTSD2USI
    vec(.VCVTTSD2USI, ops2(.reg32, .xmm_m64_sae), evex(.LIG, ._F2, ._0F, .W0, 0x78, t1f), .vRM, .{AVX512F}),
    vec(.VCVTTSD2USI, ops2(.reg64, .xmm_m64_sae), evex(.LIG, ._F2, ._0F, .W1, 0x78, t1f), .vRM, .{ AVX512F, No32 }),
    // VCVTTSS2USI
    vec(.VCVTTSS2USI, ops2(.reg32, .xmm_m32_sae), evex(.LIG, ._F3, ._0F, .W0, 0x78, t1f), .vRM, .{AVX512F}),
    vec(.VCVTTSS2USI, ops2(.reg64, .xmm_m32_sae), evex(.LIG, ._F3, ._0F, .W1, 0x78, t1f), .vRM, .{ AVX512F, No32 }),
    // VCVTUDQ2PD
    vec(.VCVTUDQ2PD, ops2(.xmm_kz, .xmm_m64_m32bcst), evex(.L128, ._F3, ._0F, .W0, 0x7A, half), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTUDQ2PD, ops2(.ymm_kz, .xmm_m128_m32bcst), evex(.L256, ._F3, ._0F, .W0, 0x7A, half), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTUDQ2PD, ops2(.zmm_kz, .ymm_m256_m32bcst), evex(.L512, ._F3, ._0F, .W0, 0x7A, half), .vRM, .{AVX512F}),
    // VCVTUDQ2PS
    vec(.VCVTUDQ2PS, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._F2, ._0F, .W0, 0x7A, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTUDQ2PS, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._F2, ._0F, .W0, 0x7A, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VCVTUDQ2PS, ops2(.zmm_kz, .zmm_m512_m32bcst_er), evex(.L512, ._F2, ._0F, .W0, 0x7A, full), .vRM, .{AVX512F}),
    // VCVTUQQ2PD
    vec(.VCVTUQQ2PD, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._F3, ._0F, .W1, 0x7A, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTUQQ2PD, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._F3, ._0F, .W1, 0x7A, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTUQQ2PD, ops2(.zmm_kz, .zmm_m512_m64bcst_er), evex(.L512, ._F3, ._0F, .W1, 0x7A, full), .vRM, .{AVX512DQ}),
    // VCVTUQQ2PS
    vec(.VCVTUQQ2PS, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._F2, ._0F, .W1, 0x7A, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTUQQ2PS, ops2(.xmm_kz, .ymm_m256_m64bcst), evex(.L256, ._F2, ._0F, .W1, 0x7A, full), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VCVTUQQ2PS, ops2(.ymm_kz, .zmm_m512_m64bcst_er), evex(.L512, ._F2, ._0F, .W1, 0x7A, full), .vRM, .{AVX512DQ}),
    // VCVTUSI2SD
    vec(.VCVTUSI2SD, ops3(.xmm, .xmm, .rm32), evex(.LIG, ._F2, ._0F, .W0, 0x7B, t1s), .RVM, .{AVX512F}),
    vec(.VCVTUSI2SD, ops3(.xmm, .xmm, .rm64_er), evex(.LIG, ._F2, ._0F, .W1, 0x7B, t1s), .RVM, .{ AVX512F, No32 }),
    // VCVTUSI2SS
    vec(.VCVTUSI2SS, ops3(.xmm, .xmm, .rm32_er), evex(.LIG, ._F3, ._0F, .W0, 0x7B, t1s), .RVM, .{AVX512F}),
    vec(.VCVTUSI2SS, ops3(.xmm, .xmm, .rm64_er), evex(.LIG, ._F3, ._0F, .W1, 0x7B, t1s), .RVM, .{ AVX512F, No32 }),
    // VDBPSADBW
    vec(.VDBPSADBW, ops4(.xmm_kz, .xmm, .xmm_m128, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x42, fmem), .RVMI, .{ AVX512VL, AVX512BW }),
    vec(.VDBPSADBW, ops4(.ymm_kz, .ymm, .ymm_m256, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x42, fmem), .RVMI, .{ AVX512VL, AVX512BW }),
    vec(.VDBPSADBW, ops4(.zmm_kz, .zmm, .zmm_m512, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x42, fmem), .RVMI, .{AVX512BW}),
    // VEXPANDPD
    vec(.VEXPANDPD, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x88, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VEXPANDPD, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x88, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VEXPANDPD, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x88, t1s), .vRM, .{AVX512F}),
    // VEXPANDPS
    vec(.VEXPANDPS, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F38, .W0, 0x88, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VEXPANDPS, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F38, .W0, 0x88, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VEXPANDPS, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F38, .W0, 0x88, t1s), .vRM, .{AVX512F}),
    // VEXTRACTF (128, F32x4, 64x2, 32x8, 64x4)
    // VEXTRACTF128
    vec(.VEXTRACTF128, ops3(.xmml_m128, .ymml, .imm8), vex(.L256, ._66, ._0F3A, .W0, 0x19), .vMRI, .{AVX}),
    // VEXTRACTF32X4
    vec(.VEXTRACTF32X4, ops3(.xmm_m128_kz, .ymm, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x19, tup4), .vMRI, .{ AVX512VL, AVX512F }),
    vec(.VEXTRACTF32X4, ops3(.xmm_m128_kz, .zmm, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x19, tup4), .vMRI, .{AVX512F}),
    // VEXTRACTF64X2
    vec(.VEXTRACTF64X2, ops3(.xmm_m128_kz, .ymm, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x19, tup2), .vMRI, .{ AVX512VL, AVX512DQ }),
    vec(.VEXTRACTF64X2, ops3(.xmm_m128_kz, .zmm, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x19, tup2), .vMRI, .{AVX512DQ}),
    // VEXTRACTF32X8
    vec(.VEXTRACTF32X8, ops3(.ymm_m256_kz, .zmm, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x1B, tup8), .vMRI, .{AVX512DQ}),
    // VEXTRACTF64X4
    vec(.VEXTRACTF64X4, ops3(.ymm_m256_kz, .zmm, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x1B, tup4), .vMRI, .{AVX512F}),
    // VEXTRACTI (128, F32x4, 64x2, 32x8, 64x4)
    // VEXTRACTI128
    vec(.VEXTRACTI128, ops3(.xmml_m128, .ymml, .imm8), vex(.L256, ._66, ._0F3A, .W0, 0x39), .vMRI, .{AVX2}),
    // VEXTRACTI32X4
    vec(.VEXTRACTI32X4, ops3(.xmm_m128_kz, .ymm, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x39, tup4), .vMRI, .{ AVX512VL, AVX512F }),
    vec(.VEXTRACTI32X4, ops3(.xmm_m128_kz, .zmm, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x39, tup4), .vMRI, .{AVX512F}),
    // VEXTRACTI64X2
    vec(.VEXTRACTI64X2, ops3(.xmm_m128_kz, .ymm, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x39, tup2), .vMRI, .{ AVX512VL, AVX512DQ }),
    vec(.VEXTRACTI64X2, ops3(.xmm_m128_kz, .zmm, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x39, tup2), .vMRI, .{AVX512DQ}),
    // VEXTRACTI32X8
    vec(.VEXTRACTI32X8, ops3(.ymm_m256_kz, .zmm, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x3B, tup8), .vMRI, .{AVX512DQ}),
    // VEXTRACTI64X4
    vec(.VEXTRACTI64X4, ops3(.ymm_m256_kz, .zmm, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x3B, tup4), .vMRI, .{AVX512F}),
    // VFIXUPIMMPD
    vec(.VFIXUPIMMPD, ops4(.xmm_kz, .xmm, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x54, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VFIXUPIMMPD, ops4(.ymm_kz, .ymm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x54, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VFIXUPIMMPD, ops4(.zmm_kz, .ymm, .zmm_m512_m64bcst_sae, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x54, full), .RVMI, .{AVX512F}),
    // VFIXUPIMMPS
    vec(.VFIXUPIMMPS, ops4(.xmm_kz, .xmm, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x54, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VFIXUPIMMPS, ops4(.ymm_kz, .ymm, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x54, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VFIXUPIMMPS, ops4(.zmm_kz, .ymm, .zmm_m512_m32bcst_sae, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x54, full), .RVMI, .{AVX512F}),
    // VFIXUPIMMSD
    vec(.VFIXUPIMMSD, ops4(.xmm_kz, .xmm, .xmm_m64_sae, .imm8), evex(.LIG, ._66, ._0F3A, .W1, 0x55, t1s), .RVMI, .{ AVX512VL, AVX512F }),
    // VFIXUPIMMSS
    vec(.VFIXUPIMMSS, ops4(.xmm_kz, .xmm, .xmm_m32_sae, .imm8), evex(.LIG, ._66, ._0F3A, .W0, 0x55, t1s), .RVMI, .{ AVX512VL, AVX512F }),
    // VFMADD132PD / VFMADD213PD / VFMADD231PD
    vec(.VFMADD132PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0x98), .RVM, .{FMA}),
    vec(.VFMADD132PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0x98), .RVM, .{FMA}),
    vec(.VFMADD132PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x98, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADD132PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x98, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADD132PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0x98, full), .RVM, .{AVX512F}),
    //
    vec(.VFMADD213PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0xA8), .RVM, .{FMA}),
    vec(.VFMADD213PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0xA8), .RVM, .{FMA}),
    vec(.VFMADD213PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xA8, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADD213PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xA8, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADD213PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0xA8, full), .RVM, .{AVX512F}),
    //
    vec(.VFMADD231PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0xB8), .RVM, .{FMA}),
    vec(.VFMADD231PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0xB8), .RVM, .{FMA}),
    vec(.VFMADD231PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xB8, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADD231PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xB8, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADD231PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0xB8, full), .RVM, .{AVX512F}),
    // VFMADD132PS / VFMADD213PS / VFMADD231PS
    vec(.VFMADD132PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x98), .RVM, .{FMA}),
    vec(.VFMADD132PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x98), .RVM, .{FMA}),
    vec(.VFMADD132PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x98, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADD132PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x98, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADD132PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0x98, full), .RVM, .{AVX512F}),
    //
    vec(.VFMADD213PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xA8), .RVM, .{FMA}),
    vec(.VFMADD213PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xA8), .RVM, .{FMA}),
    vec(.VFMADD213PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xA8, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADD213PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xA8, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADD213PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0xA8, full), .RVM, .{AVX512F}),
    //
    vec(.VFMADD231PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xB8), .RVM, .{FMA}),
    vec(.VFMADD231PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xB8), .RVM, .{FMA}),
    vec(.VFMADD231PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xB8, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADD231PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xB8, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADD231PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0xB8, full), .RVM, .{AVX512F}),
    // VFMADD132SD / VFMADD213SD / VFMADD231SD
    vec(.VFMADD132SD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F38, .W1, 0x99), .RVM, .{FMA}),
    vec(.VFMADD132SD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0x99, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFMADD213SD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F38, .W1, 0xA9), .RVM, .{FMA}),
    vec(.VFMADD213SD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0xA9, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFMADD231SD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F38, .W1, 0xB9), .RVM, .{FMA}),
    vec(.VFMADD231SD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0xB9, t1s), .RVM, .{AVX512F}),
    // VFMADD132SS / VFMADD213SS / VFMADD231SS
    vec(.VFMADD132SS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F38, .W0, 0x99), .RVM, .{FMA}),
    vec(.VFMADD132SS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0x99, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFMADD213SS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F38, .W0, 0xA9), .RVM, .{FMA}),
    vec(.VFMADD213SS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0xA9, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFMADD231SS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F38, .W0, 0xB9), .RVM, .{FMA}),
    vec(.VFMADD231SS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0xB9, t1s), .RVM, .{AVX512F}),
    // VFMADDSUB132PD / VFMADDSUB213PD / VFMADDSUB231PD
    vec(.VFMADDSUB132PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0x96), .RVM, .{FMA}),
    vec(.VFMADDSUB132PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0x96), .RVM, .{FMA}),
    vec(.VFMADDSUB132PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x96, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADDSUB132PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x96, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADDSUB132PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0x96, full), .RVM, .{AVX512F}),
    //
    vec(.VFMADDSUB213PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0xA6), .RVM, .{FMA}),
    vec(.VFMADDSUB213PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0xA6), .RVM, .{FMA}),
    vec(.VFMADDSUB213PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xA6, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADDSUB213PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xA6, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADDSUB213PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0xA6, full), .RVM, .{AVX512F}),
    //
    vec(.VFMADDSUB231PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0xB6), .RVM, .{FMA}),
    vec(.VFMADDSUB231PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0xB6), .RVM, .{FMA}),
    vec(.VFMADDSUB231PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xB6, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADDSUB231PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xB6, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADDSUB231PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0xB6, full), .RVM, .{AVX512F}),
    // VFMADDSUB132PS / VFMADDSUB213PS / VFMADDSUB231PS
    vec(.VFMADDSUB132PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x96), .RVM, .{FMA}),
    vec(.VFMADDSUB132PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x96), .RVM, .{FMA}),
    vec(.VFMADDSUB132PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x96, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADDSUB132PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x96, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADDSUB132PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0x96, full), .RVM, .{AVX512F}),
    //
    vec(.VFMADDSUB213PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xA6), .RVM, .{FMA}),
    vec(.VFMADDSUB213PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xA6), .RVM, .{FMA}),
    vec(.VFMADDSUB213PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xA6, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADDSUB213PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xA6, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADDSUB213PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0xA6, full), .RVM, .{AVX512F}),
    //
    vec(.VFMADDSUB231PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xB6), .RVM, .{FMA}),
    vec(.VFMADDSUB231PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xB6), .RVM, .{FMA}),
    vec(.VFMADDSUB231PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xB6, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADDSUB231PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xB6, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMADDSUB231PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0xB6, full), .RVM, .{AVX512F}),
    // VFMSUBADD132PD / VFMSUBADD213PD / VFMSUBADD231PD
    vec(.VFMSUBADD132PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0x97), .RVM, .{FMA}),
    vec(.VFMSUBADD132PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0x97), .RVM, .{FMA}),
    vec(.VFMSUBADD132PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x97, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUBADD132PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x97, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUBADD132PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0x97, full), .RVM, .{AVX512F}),
    //
    vec(.VFMSUBADD213PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0xA7), .RVM, .{FMA}),
    vec(.VFMSUBADD213PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0xA7), .RVM, .{FMA}),
    vec(.VFMSUBADD213PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xA7, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUBADD213PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xA7, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUBADD213PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0xA7, full), .RVM, .{AVX512F}),
    //
    vec(.VFMSUBADD231PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0xB7), .RVM, .{FMA}),
    vec(.VFMSUBADD231PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0xB7), .RVM, .{FMA}),
    vec(.VFMSUBADD231PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xB7, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUBADD231PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xB7, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUBADD231PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0xB7, full), .RVM, .{AVX512F}),
    // VFMSUBADD132PS / VFMSUBADD213PS / VFMSUBADD231PS
    vec(.VFMSUBADD132PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x97), .RVM, .{FMA}),
    vec(.VFMSUBADD132PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x97), .RVM, .{FMA}),
    vec(.VFMSUBADD132PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x97, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUBADD132PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x97, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUBADD132PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0x97, full), .RVM, .{AVX512F}),
    //
    vec(.VFMSUBADD213PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xA7), .RVM, .{FMA}),
    vec(.VFMSUBADD213PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xA7), .RVM, .{FMA}),
    vec(.VFMSUBADD213PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xA7, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUBADD213PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xA7, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUBADD213PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0xA7, full), .RVM, .{AVX512F}),
    //
    vec(.VFMSUBADD231PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xB7), .RVM, .{FMA}),
    vec(.VFMSUBADD231PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xB7), .RVM, .{FMA}),
    vec(.VFMSUBADD231PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xB7, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUBADD231PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xB7, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUBADD231PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0xB7, full), .RVM, .{AVX512F}),
    // VFMSUB132PD / VFMSUB213PD / VFMSUB231PD
    vec(.VFMSUB132PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0x9A), .RVM, .{FMA}),
    vec(.VFMSUB132PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0x9A), .RVM, .{FMA}),
    vec(.VFMSUB132PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x9A, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUB132PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x9A, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUB132PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0x9A, full), .RVM, .{AVX512F}),
    //
    vec(.VFMSUB213PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0xAA), .RVM, .{FMA}),
    vec(.VFMSUB213PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0xAA), .RVM, .{FMA}),
    vec(.VFMSUB213PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xAA, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUB213PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xAA, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUB213PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0xAA, full), .RVM, .{AVX512F}),
    //
    vec(.VFMSUB231PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0xBA), .RVM, .{FMA}),
    vec(.VFMSUB231PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0xBA), .RVM, .{FMA}),
    vec(.VFMSUB231PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xBA, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUB231PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xBA, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUB231PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0xBA, full), .RVM, .{AVX512F}),
    // VFMSUB132PS / VFMSUB213PS / VFMSUB231PS
    vec(.VFMSUB132PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x9A), .RVM, .{FMA}),
    vec(.VFMSUB132PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x9A), .RVM, .{FMA}),
    vec(.VFMSUB132PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x9A, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUB132PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x9A, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUB132PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0x9A, full), .RVM, .{AVX512F}),
    //
    vec(.VFMSUB213PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xAA), .RVM, .{FMA}),
    vec(.VFMSUB213PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xAA), .RVM, .{FMA}),
    vec(.VFMSUB213PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xAA, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUB213PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xAA, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUB213PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0xAA, full), .RVM, .{AVX512F}),
    //
    vec(.VFMSUB231PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xBA), .RVM, .{FMA}),
    vec(.VFMSUB231PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xBA), .RVM, .{FMA}),
    vec(.VFMSUB231PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xBA, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUB231PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xBA, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFMSUB231PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0xBA, full), .RVM, .{AVX512F}),
    // VFMSUB132SD / VFMSUB213SD / VFMSUB231SD
    vec(.VFMSUB132SD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F38, .W1, 0x9B), .RVM, .{FMA}),
    vec(.VFMSUB132SD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0x9B, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFMSUB213SD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F38, .W1, 0xAB), .RVM, .{FMA}),
    vec(.VFMSUB213SD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0xAB, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFMSUB231SD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F38, .W1, 0xBB), .RVM, .{FMA}),
    vec(.VFMSUB231SD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0xBB, t1s), .RVM, .{AVX512F}),
    // VFMSUB132SS / VFMSUB213SS / VFMSUB231SS
    vec(.VFMSUB132SS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F38, .W0, 0x9B), .RVM, .{FMA}),
    vec(.VFMSUB132SS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0x9B, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFMSUB213SS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F38, .W0, 0xAB), .RVM, .{FMA}),
    vec(.VFMSUB213SS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0xAB, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFMSUB231SS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F38, .W0, 0xBB), .RVM, .{FMA}),
    vec(.VFMSUB231SS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0xBB, t1s), .RVM, .{AVX512F}),
    // VFNMADD132PD / VFNMADD213PD / VFNMADD231PD
    vec(.VFNMADD132PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0x9C), .RVM, .{FMA}),
    vec(.VFNMADD132PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0x9C), .RVM, .{FMA}),
    vec(.VFNMADD132PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x9C, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMADD132PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x9C, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMADD132PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0x9C, full), .RVM, .{AVX512F}),
    //
    vec(.VFNMADD213PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0xAC), .RVM, .{FMA}),
    vec(.VFNMADD213PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0xAC), .RVM, .{FMA}),
    vec(.VFNMADD213PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xAC, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMADD213PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xAC, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMADD213PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0xAC, full), .RVM, .{AVX512F}),
    //
    vec(.VFNMADD231PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0xBC), .RVM, .{FMA}),
    vec(.VFNMADD231PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0xBC), .RVM, .{FMA}),
    vec(.VFNMADD231PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xBC, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMADD231PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xBC, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMADD231PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0xBC, full), .RVM, .{AVX512F}),
    // VFNMADD132PS / VFNMADD213PS / VFNMADD231PS
    vec(.VFNMADD132PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x9C), .RVM, .{FMA}),
    vec(.VFNMADD132PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x9C), .RVM, .{FMA}),
    vec(.VFNMADD132PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x9C, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMADD132PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x9C, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMADD132PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0x9C, full), .RVM, .{AVX512F}),
    //
    vec(.VFNMADD213PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xAC), .RVM, .{FMA}),
    vec(.VFNMADD213PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xAC), .RVM, .{FMA}),
    vec(.VFNMADD213PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xAC, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMADD213PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xAC, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMADD213PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0xAC, full), .RVM, .{AVX512F}),
    //
    vec(.VFNMADD231PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xBC), .RVM, .{FMA}),
    vec(.VFNMADD231PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xBC), .RVM, .{FMA}),
    vec(.VFNMADD231PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xBC, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMADD231PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xBC, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMADD231PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0xBC, full), .RVM, .{AVX512F}),
    // VFNMADD132SD / VFNMADD213SD / VFNMADD231SD
    vec(.VFNMADD132SD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F38, .W1, 0x9D), .RVM, .{FMA}),
    vec(.VFNMADD132SD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0x9D, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFNMADD213SD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F38, .W1, 0xAD), .RVM, .{FMA}),
    vec(.VFNMADD213SD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0xAD, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFNMADD231SD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F38, .W1, 0xBD), .RVM, .{FMA}),
    vec(.VFNMADD231SD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0xBD, t1s), .RVM, .{AVX512F}),
    // VFNMADD132SS / VFNMADD213SS / VFNMADD231SS
    vec(.VFNMADD132SS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F38, .W0, 0x9D), .RVM, .{FMA}),
    vec(.VFNMADD132SS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0x9D, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFNMADD213SS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F38, .W0, 0xAD), .RVM, .{FMA}),
    vec(.VFNMADD213SS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0xAD, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFNMADD231SS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F38, .W0, 0xBD), .RVM, .{FMA}),
    vec(.VFNMADD231SS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0xBD, t1s), .RVM, .{AVX512F}),
    // VFNMSUB132PD / VFNMSUB213PD / VFNMSUB231PD
    vec(.VFNMSUB132PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0x9E), .RVM, .{FMA}),
    vec(.VFNMSUB132PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0x9E), .RVM, .{FMA}),
    vec(.VFNMSUB132PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x9E, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMSUB132PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x9E, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMSUB132PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0x9E, full), .RVM, .{AVX512F}),
    //
    vec(.VFNMSUB213PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0xAE), .RVM, .{FMA}),
    vec(.VFNMSUB213PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0xAE), .RVM, .{FMA}),
    vec(.VFNMSUB213PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xAE, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMSUB213PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xAE, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMSUB213PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0xAE, full), .RVM, .{AVX512F}),
    //
    vec(.VFNMSUB231PD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0xBE), .RVM, .{FMA}),
    vec(.VFNMSUB231PD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0xBE), .RVM, .{FMA}),
    vec(.VFNMSUB231PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xBE, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMSUB231PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xBE, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMSUB231PD, ops3(.zmm_kz, .ymm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0xBE, full), .RVM, .{AVX512F}),
    // VFNMSUB132PS / VFNMSUB213PS / VFNMSUB231PS
    vec(.VFNMSUB132PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x9E), .RVM, .{FMA}),
    vec(.VFNMSUB132PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x9E), .RVM, .{FMA}),
    vec(.VFNMSUB132PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x9E, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMSUB132PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x9E, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMSUB132PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0x9E, full), .RVM, .{AVX512F}),
    //
    vec(.VFNMSUB213PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xAE), .RVM, .{FMA}),
    vec(.VFNMSUB213PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xAE), .RVM, .{FMA}),
    vec(.VFNMSUB213PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xAE, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMSUB213PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xAE, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMSUB213PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0xAE, full), .RVM, .{AVX512F}),
    //
    vec(.VFNMSUB231PS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0xBE), .RVM, .{FMA}),
    vec(.VFNMSUB231PS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0xBE), .RVM, .{FMA}),
    vec(.VFNMSUB231PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xBE, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMSUB231PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xBE, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VFNMSUB231PS, ops3(.zmm_kz, .ymm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0xBE, full), .RVM, .{AVX512F}),
    // VFNMSUB132SD / VFNMSUB213SD / VFNMSUB231SD
    vec(.VFNMSUB132SD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F38, .W1, 0x9F), .RVM, .{FMA}),
    vec(.VFNMSUB132SD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0x9F, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFNMSUB213SD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F38, .W1, 0xAF), .RVM, .{FMA}),
    vec(.VFNMSUB213SD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0xAF, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFNMSUB231SD, ops3(.xmml, .xmml, .xmml_m64), vex(.LIG, ._66, ._0F38, .W1, 0xBF), .RVM, .{FMA}),
    vec(.VFNMSUB231SD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0xBF, t1s), .RVM, .{AVX512F}),
    // VFNMSUB132SS / VFNMSUB213SS / VFNMSUB231SS
    vec(.VFNMSUB132SS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F38, .W0, 0x9F), .RVM, .{FMA}),
    vec(.VFNMSUB132SS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0x9F, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFNMSUB213SS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F38, .W0, 0xAF), .RVM, .{FMA}),
    vec(.VFNMSUB213SS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0xAF, t1s), .RVM, .{AVX512F}),
    //
    vec(.VFNMSUB231SS, ops3(.xmml, .xmml, .xmml_m32), vex(.LIG, ._66, ._0F38, .W0, 0xBF), .RVM, .{FMA}),
    vec(.VFNMSUB231SS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0xBF, t1s), .RVM, .{AVX512F}),
    // VFPCLASSPD
    vec(.VFPCLASSPD, ops3(.reg_k_k, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x66, full), .vRMI, .{ AVX512VL, AVX512DQ }),
    vec(.VFPCLASSPD, ops3(.reg_k_k, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x66, full), .vRMI, .{ AVX512VL, AVX512DQ }),
    vec(.VFPCLASSPD, ops3(.reg_k_k, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x66, full), .vRMI, .{AVX512DQ}),
    // VFPCLASSPS
    vec(.VFPCLASSPS, ops3(.reg_k_k, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x66, full), .vRMI, .{ AVX512VL, AVX512DQ }),
    vec(.VFPCLASSPS, ops3(.reg_k_k, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x66, full), .vRMI, .{ AVX512VL, AVX512DQ }),
    vec(.VFPCLASSPS, ops3(.reg_k_k, .zmm_m512_m32bcst, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x66, full), .vRMI, .{AVX512DQ}),
    // VFPCLASSSD
    vec(.VFPCLASSSD, ops3(.reg_k_k, .xmm_m64, .imm8), evex(.LIG, ._66, ._0F3A, .W1, 0x67, t1s), .vRMI, .{AVX512DQ}),
    // VFPCLASSSS
    vec(.VFPCLASSSS, ops3(.reg_k_k, .xmm_m32, .imm8), evex(.LIG, ._66, ._0F3A, .W0, 0x67, t1s), .vRMI, .{AVX512DQ}),
    // VGATHERDPD / VGATHERQPD
    vec(.VGATHERDPD, ops3(.xmml, .vm32xl, .xmml), vex(.L128, ._66, ._0F38, .W1, 0x92), .RMV, .{AVX2}),
    vec(.VGATHERDPD, ops3(.ymml, .vm32xl, .ymml), vex(.L256, ._66, ._0F38, .W1, 0x92), .RMV, .{AVX2}),
    vec(.VGATHERDPD, ops2(.xmm_kz, .vm32x), evex(.L128, ._66, ._0F38, .W1, 0x92, t1s), .RMV, .{ AVX512VL, AVX512F }),
    vec(.VGATHERDPD, ops2(.ymm_kz, .vm32x), evex(.L256, ._66, ._0F38, .W1, 0x92, t1s), .RMV, .{ AVX512VL, AVX512F }),
    vec(.VGATHERDPD, ops2(.zmm_kz, .vm32y), evex(.L512, ._66, ._0F38, .W1, 0x92, t1s), .RMV, .{AVX512F}),
    //
    vec(.VGATHERQPD, ops3(.xmml, .vm64xl, .xmml), vex(.L128, ._66, ._0F38, .W1, 0x93), .RMV, .{AVX2}),
    vec(.VGATHERQPD, ops3(.ymml, .vm64yl, .ymml), vex(.L256, ._66, ._0F38, .W1, 0x93), .RMV, .{AVX2}),
    vec(.VGATHERQPD, ops2(.xmm_kz, .vm64x), evex(.L128, ._66, ._0F38, .W1, 0x93, t1s), .RMV, .{ AVX512VL, AVX512F }),
    vec(.VGATHERQPD, ops2(.ymm_kz, .vm64y), evex(.L256, ._66, ._0F38, .W1, 0x93, t1s), .RMV, .{ AVX512VL, AVX512F }),
    vec(.VGATHERQPD, ops2(.zmm_kz, .vm64z), evex(.L512, ._66, ._0F38, .W1, 0x93, t1s), .RMV, .{AVX512F}),
    // VGATHERDPS / VGATHERQPS
    vec(.VGATHERDPS, ops3(.xmml, .vm32xl, .xmml), vex(.L128, ._66, ._0F38, .W0, 0x92), .RMV, .{AVX2}),
    vec(.VGATHERDPS, ops3(.ymml, .vm32yl, .ymml), vex(.L256, ._66, ._0F38, .W0, 0x92), .RMV, .{AVX2}),
    vec(.VGATHERDPS, ops2(.xmm_kz, .vm32x), evex(.L128, ._66, ._0F38, .W0, 0x92, t1s), .RMV, .{ AVX512VL, AVX512F }),
    vec(.VGATHERDPS, ops2(.ymm_kz, .vm32y), evex(.L256, ._66, ._0F38, .W0, 0x92, t1s), .RMV, .{ AVX512VL, AVX512F }),
    vec(.VGATHERDPS, ops2(.zmm_kz, .vm32z), evex(.L512, ._66, ._0F38, .W0, 0x92, t1s), .RMV, .{AVX512F}),
    //
    vec(.VGATHERQPS, ops3(.xmml, .vm64xl, .xmml), vex(.L128, ._66, ._0F38, .W0, 0x93), .RMV, .{AVX2}),
    vec(.VGATHERQPS, ops3(.xmml, .vm64yl, .xmml), vex(.L256, ._66, ._0F38, .W0, 0x93), .RMV, .{AVX2}),
    vec(.VGATHERQPS, ops2(.xmm_kz, .vm64x), evex(.L128, ._66, ._0F38, .W0, 0x93, t1s), .RMV, .{ AVX512VL, AVX512F }),
    vec(.VGATHERQPS, ops2(.xmm_kz, .vm64y), evex(.L256, ._66, ._0F38, .W0, 0x93, t1s), .RMV, .{ AVX512VL, AVX512F }),
    vec(.VGATHERQPS, ops2(.ymm_kz, .vm64z), evex(.L512, ._66, ._0F38, .W0, 0x93, t1s), .RMV, .{AVX512F}),
    // VGETEXPPD
    vec(.VGETEXPPD, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x42, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VGETEXPPD, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x42, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VGETEXPPD, ops2(.zmm_kz, .zmm_m512_m64bcst_sae), evex(.L512, ._66, ._0F38, .W1, 0x42, full), .vRM, .{AVX512F}),
    // VGETEXPPS
    vec(.VGETEXPPS, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x42, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VGETEXPPS, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x42, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VGETEXPPS, ops2(.zmm_kz, .zmm_m512_m32bcst_sae), evex(.L512, ._66, ._0F38, .W0, 0x42, full), .vRM, .{AVX512F}),
    // VGETEXPSD
    vec(.VGETEXPSD, ops3(.xmm_kz, .xmm, .xmm_m64_sae), evex(.LIG, ._66, ._0F38, .W1, 0x43, t1s), .RVM, .{AVX512F}),
    // VGETEXPSS
    vec(.VGETEXPSS, ops3(.xmm_kz, .xmm, .xmm_m32_sae), evex(.LIG, ._66, ._0F38, .W0, 0x43, t1s), .RVM, .{AVX512F}),
    // VGETMANTPD
    vec(.VGETMANTPD, ops3(.xmm_kz, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x26, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VGETMANTPD, ops3(.ymm_kz, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x26, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VGETMANTPD, ops3(.zmm_kz, .zmm_m512_m64bcst_sae, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x26, full), .vRMI, .{AVX512F}),
    // VGETMANTPS
    vec(.VGETMANTPS, ops3(.xmm_kz, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x26, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VGETMANTPS, ops3(.ymm_kz, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x26, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VGETMANTPS, ops3(.zmm_kz, .zmm_m512_m32bcst_sae, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x26, full), .vRMI, .{AVX512F}),
    // VGETMANTSD
    vec(.VGETMANTSD, ops4(.xmm_kz, .xmm, .xmm_m64_sae, .imm8), evex(.LIG, ._66, ._0F3A, .W1, 0x27, t1s), .RVMI, .{AVX512F}),
    // VGETMANTSS
    vec(.VGETMANTSS, ops4(.xmm_kz, .xmm, .xmm_m32_sae, .imm8), evex(.LIG, ._66, ._0F3A, .W0, 0x27, t1s), .RVMI, .{AVX512F}),
    // vecERTF (128, F32x4, 64x2, 32x8, 64x4)
    vec(.VINSERTF128, ops4(.ymml, .ymml, .xmml_m128, .imm8), vex(.L256, ._66, ._0F3A, .W0, 0x18), .RVMI, .{AVX}),
    // vecERTF32X4
    vec(.VINSERTF32X4, ops4(.ymm_kz, .ymm, .xmm_m128, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x18, tup4), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VINSERTF32X4, ops4(.zmm_kz, .zmm, .xmm_m128, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x18, tup4), .RVMI, .{AVX512F}),
    // vecERTF64X2
    vec(.VINSERTF64X2, ops4(.ymm_kz, .ymm, .xmm_m128, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x18, tup2), .RVMI, .{ AVX512VL, AVX512DQ }),
    vec(.VINSERTF64X2, ops4(.zmm_kz, .zmm, .xmm_m128, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x18, tup2), .RVMI, .{AVX512DQ}),
    // vecERTF32X8
    vec(.VINSERTF32X8, ops4(.zmm_kz, .zmm, .ymm_m256, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x1A, tup8), .RVMI, .{AVX512DQ}),
    // vecERTF64X4
    vec(.VINSERTF64X4, ops4(.zmm_kz, .zmm, .ymm_m256, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x1A, tup4), .RVMI, .{AVX512F}),
    // vecERTI (128, F32x4, 64x2, 32x8, 64x4)
    vec(.VINSERTI128, ops4(.ymml, .ymml, .xmml_m128, .imm8), vex(.L256, ._66, ._0F3A, .W0, 0x18), .RVMI, .{AVX}),
    // vecERTI32X4
    vec(.VINSERTI32X4, ops4(.ymm_kz, .ymm, .xmm_m128, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x18, tup4), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VINSERTI32X4, ops4(.zmm_kz, .zmm, .xmm_m128, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x18, tup4), .RVMI, .{AVX512F}),
    // vecERTI64X2
    vec(.VINSERTI64X2, ops4(.ymm_kz, .ymm, .xmm_m128, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x18, tup2), .RVMI, .{ AVX512VL, AVX512DQ }),
    vec(.VINSERTI64X2, ops4(.zmm_kz, .zmm, .xmm_m128, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x18, tup2), .RVMI, .{AVX512DQ}),
    // vecERTI32X8
    vec(.VINSERTI32X8, ops4(.zmm_kz, .zmm, .ymm_m256, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x1A, tup8), .RVMI, .{AVX512DQ}),
    // vecERTI64X4
    vec(.VINSERTI64X4, ops4(.zmm_kz, .zmm, .ymm_m256, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x1A, tup4), .RVMI, .{AVX512F}),
    // VMASKMOV
    // VMASKMOVPD
    vec(.VMASKMOVPD, ops3(.xmml, .xmml, .rm_mem128), vex(.L128, ._66, ._0F38, .W0, 0x2D), .RVM, .{AVX}),
    vec(.VMASKMOVPD, ops3(.ymml, .ymml, .rm_mem256), vex(.L256, ._66, ._0F38, .W0, 0x2D), .RVM, .{AVX}),
    vec(.VMASKMOVPD, ops3(.rm_mem128, .xmml, .xmml), vex(.L128, ._66, ._0F38, .W0, 0x2F), .MVR, .{AVX}),
    vec(.VMASKMOVPD, ops3(.rm_mem256, .ymml, .ymml), vex(.L256, ._66, ._0F38, .W0, 0x2F), .MVR, .{AVX}),
    // VMASKMOVPS
    vec(.VMASKMOVPS, ops3(.xmml, .xmml, .rm_mem128), vex(.L128, ._66, ._0F38, .W0, 0x2C), .RVM, .{AVX}),
    vec(.VMASKMOVPS, ops3(.ymml, .ymml, .rm_mem256), vex(.L256, ._66, ._0F38, .W0, 0x2C), .RVM, .{AVX}),
    vec(.VMASKMOVPS, ops3(.rm_mem128, .xmml, .xmml), vex(.L128, ._66, ._0F38, .W0, 0x2E), .MVR, .{AVX}),
    vec(.VMASKMOVPS, ops3(.rm_mem256, .ymml, .ymml), vex(.L256, ._66, ._0F38, .W0, 0x2E), .MVR, .{AVX}),
    // VPBLENDD
    vec(.VPBLENDD, ops4(.xmml, .xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x02), .RVMI, .{AVX2}),
    vec(.VPBLENDD, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .W0, 0x02), .RVMI, .{AVX2}),
    // VPBLENDMB / VPBLENDMW
    // VPBLENDMB
    vec(.VPBLENDMB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W0, 0x66, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPBLENDMB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W0, 0x66, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPBLENDMB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W0, 0x66, fmem), .RVM, .{AVX512BW}),
    // VPBLENDMW
    vec(.VPBLENDMW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x66, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPBLENDMW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x66, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPBLENDMW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x66, fmem), .RVM, .{AVX512BW}),
    // VPBLENDMD / VPBLENDMQ
    // VPBLENDMD
    vec(.VPBLENDMD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x64, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPBLENDMD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x64, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPBLENDMD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x64, full), .RVM, .{AVX512F}),
    // VPBLENDMQ
    vec(.VPBLENDMQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x64, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPBLENDMQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x64, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPBLENDMQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x64, full), .RVM, .{AVX512F}),
    // VPBROADCASTB / VPBROADCASTW / VPBROADCASTD / VPBROADCASTQ
    // VPBROADCASTB
    vec(.VPBROADCASTB, ops2(.xmml, .xmml_m8), vex(.L128, ._66, ._0F38, .W0, 0x78), .vRM, .{AVX2}),
    vec(.VPBROADCASTB, ops2(.ymml, .xmml_m8), vex(.L256, ._66, ._0F38, .W0, 0x78), .vRM, .{AVX2}),
    vec(.VPBROADCASTB, ops2(.xmm_kz, .xmm_m8), evex(.L128, ._66, ._0F38, .W0, 0x78, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTB, ops2(.ymm_kz, .xmm_m8), evex(.L256, ._66, ._0F38, .W0, 0x78, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTB, ops2(.zmm_kz, .xmm_m8), evex(.L512, ._66, ._0F38, .W0, 0x78, t1s), .vRM, .{AVX512BW}),
    vec(.VPBROADCASTB, ops2(.xmm_kz, .rm_reg8), evex(.L128, ._66, ._0F38, .W0, 0x7A, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTB, ops2(.ymm_kz, .rm_reg8), evex(.L256, ._66, ._0F38, .W0, 0x7A, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTB, ops2(.zmm_kz, .rm_reg8), evex(.L512, ._66, ._0F38, .W0, 0x7A, t1s), .vRM, .{AVX512BW}),
    vec(.VPBROADCASTB, ops2(.xmm_kz, .rm_reg32), evex(.L128, ._66, ._0F38, .W0, 0x7A, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTB, ops2(.ymm_kz, .rm_reg32), evex(.L256, ._66, ._0F38, .W0, 0x7A, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTB, ops2(.zmm_kz, .rm_reg32), evex(.L512, ._66, ._0F38, .W0, 0x7A, t1s), .vRM, .{AVX512BW}),
    vec(.VPBROADCASTB, ops2(.xmm_kz, .rm_reg64), evex(.L128, ._66, ._0F38, .W0, 0x7A, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTB, ops2(.ymm_kz, .rm_reg64), evex(.L256, ._66, ._0F38, .W0, 0x7A, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTB, ops2(.zmm_kz, .rm_reg64), evex(.L512, ._66, ._0F38, .W0, 0x7A, t1s), .vRM, .{AVX512BW}),
    // VPBROADCASTW
    vec(.VPBROADCASTW, ops2(.xmml, .xmml_m16), vex(.L128, ._66, ._0F38, .W0, 0x79), .vRM, .{AVX2}),
    vec(.VPBROADCASTW, ops2(.ymml, .xmml_m16), vex(.L256, ._66, ._0F38, .W0, 0x79), .vRM, .{AVX2}),
    vec(.VPBROADCASTW, ops2(.xmm_kz, .xmm_m16), evex(.L128, ._66, ._0F38, .W0, 0x79, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTW, ops2(.ymm_kz, .xmm_m16), evex(.L256, ._66, ._0F38, .W0, 0x79, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTW, ops2(.zmm_kz, .xmm_m16), evex(.L512, ._66, ._0F38, .W0, 0x79, t1s), .vRM, .{AVX512BW}),
    vec(.VPBROADCASTW, ops2(.xmm_kz, .rm_reg16), evex(.L128, ._66, ._0F38, .W0, 0x7B, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTW, ops2(.ymm_kz, .rm_reg16), evex(.L256, ._66, ._0F38, .W0, 0x7B, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTW, ops2(.zmm_kz, .rm_reg16), evex(.L512, ._66, ._0F38, .W0, 0x7B, t1s), .vRM, .{AVX512BW}),
    vec(.VPBROADCASTW, ops2(.xmm_kz, .rm_reg32), evex(.L128, ._66, ._0F38, .W0, 0x7B, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTW, ops2(.ymm_kz, .rm_reg32), evex(.L256, ._66, ._0F38, .W0, 0x7B, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTW, ops2(.zmm_kz, .rm_reg32), evex(.L512, ._66, ._0F38, .W0, 0x7B, t1s), .vRM, .{AVX512BW}),
    vec(.VPBROADCASTW, ops2(.xmm_kz, .rm_reg64), evex(.L128, ._66, ._0F38, .W0, 0x7B, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTW, ops2(.ymm_kz, .rm_reg64), evex(.L256, ._66, ._0F38, .W0, 0x7B, t1s), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPBROADCASTW, ops2(.zmm_kz, .rm_reg64), evex(.L512, ._66, ._0F38, .W0, 0x7B, t1s), .vRM, .{AVX512BW}),
    // VPBROADCASTD
    vec(.VPBROADCASTD, ops2(.xmml, .xmml_m32), vex(.L128, ._66, ._0F38, .W0, 0x58), .vRM, .{AVX2}),
    vec(.VPBROADCASTD, ops2(.ymml, .xmml_m32), vex(.L256, ._66, ._0F38, .W0, 0x58), .vRM, .{AVX2}),
    vec(.VPBROADCASTD, ops2(.xmm_kz, .xmm_m32), evex(.L128, ._66, ._0F38, .W0, 0x58, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPBROADCASTD, ops2(.ymm_kz, .xmm_m32), evex(.L256, ._66, ._0F38, .W0, 0x58, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPBROADCASTD, ops2(.zmm_kz, .xmm_m32), evex(.L512, ._66, ._0F38, .W0, 0x58, t1s), .vRM, .{AVX512F}),
    vec(.VPBROADCASTD, ops2(.xmm_kz, .rm_reg32), evex(.L128, ._66, ._0F38, .W0, 0x7C, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPBROADCASTD, ops2(.ymm_kz, .rm_reg32), evex(.L256, ._66, ._0F38, .W0, 0x7C, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPBROADCASTD, ops2(.zmm_kz, .rm_reg32), evex(.L512, ._66, ._0F38, .W0, 0x7C, t1s), .vRM, .{AVX512F}),
    // VPBROADCASTQ
    vec(.VPBROADCASTQ, ops2(.xmml, .xmml_m64), vex(.L128, ._66, ._0F38, .W0, 0x59), .vRM, .{AVX2}),
    vec(.VPBROADCASTQ, ops2(.ymml, .xmml_m64), vex(.L256, ._66, ._0F38, .W0, 0x59), .vRM, .{AVX2}),
    vec(.VPBROADCASTQ, ops2(.xmm_kz, .xmm_m64), evex(.L128, ._66, ._0F38, .W1, 0x59, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPBROADCASTQ, ops2(.ymm_kz, .xmm_m64), evex(.L256, ._66, ._0F38, .W1, 0x59, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPBROADCASTQ, ops2(.zmm_kz, .xmm_m64), evex(.L512, ._66, ._0F38, .W1, 0x59, t1s), .vRM, .{AVX512F}),
    vec(.VPBROADCASTQ, ops2(.xmm_kz, .rm_reg64), evex(.L128, ._66, ._0F38, .W1, 0x7C, t1s), .vRM, .{ AVX512VL, AVX512F, No32 }),
    vec(.VPBROADCASTQ, ops2(.ymm_kz, .rm_reg64), evex(.L256, ._66, ._0F38, .W1, 0x7C, t1s), .vRM, .{ AVX512VL, AVX512F, No32 }),
    vec(.VPBROADCASTQ, ops2(.zmm_kz, .rm_reg64), evex(.L512, ._66, ._0F38, .W1, 0x7C, t1s), .vRM, .{ AVX512F, No32 }),
    // VPBROADCASTI32X2
    vec(.VPBROADCASTI32X2, ops2(.xmm_kz, .xmm_m64), evex(.L128, ._66, ._0F38, .W0, 0x59, tup2), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VPBROADCASTI32X2, ops2(.ymm_kz, .xmm_m64), evex(.L256, ._66, ._0F38, .W0, 0x59, tup2), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VPBROADCASTI32X2, ops2(.zmm_kz, .xmm_m64), evex(.L512, ._66, ._0F38, .W0, 0x59, tup2), .vRM, .{ AVX512VL, AVX512DQ }),
    // VPBROADCASTI128
    vec(.VPBROADCASTI128, ops2(.ymml, .rm_mem128), vex(.L256, ._66, ._0F38, .W0, 0x5A), .vRM, .{AVX2}),
    // VPBROADCASTI32X4
    vec(.VPBROADCASTI32X4, ops2(.ymm_kz, .rm_mem128), evex(.L256, ._66, ._0F38, .W0, 0x5A, tup4), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPBROADCASTI32X4, ops2(.zmm_kz, .rm_mem128), evex(.L512, ._66, ._0F38, .W0, 0x5A, tup4), .vRM, .{AVX512F}),
    // VPBROADCASTI64X2
    vec(.VPBROADCASTI64X2, ops2(.ymm_kz, .rm_mem128), evex(.L256, ._66, ._0F38, .W1, 0x5A, tup2), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VPBROADCASTI64X2, ops2(.zmm_kz, .rm_mem128), evex(.L512, ._66, ._0F38, .W1, 0x5A, tup2), .vRM, .{AVX512DQ}),
    // VPBROADCASTI32X8
    vec(.VPBROADCASTI32X8, ops2(.zmm_kz, .rm_mem256), evex(.L512, ._66, ._0F38, .W0, 0x5B, tup8), .vRM, .{AVX512DQ}),
    // VPBROADCASTI64X4
    vec(.VPBROADCASTI64X4, ops2(.zmm_kz, .rm_mem256), evex(.L512, ._66, ._0F38, .W1, 0x5B, tup4), .vRM, .{AVX512F}),
    // VPBROADCASTM
    // VPBROADCASTMB2Q
    vec(.VPBROADCASTMB2Q, ops2(.xmm_kz, .rm_k), evex(.L128, ._F3, ._0F38, .W1, 0x2A, nomem), .vRM, .{ AVX512VL, AVX512CD }),
    vec(.VPBROADCASTMB2Q, ops2(.ymm_kz, .rm_k), evex(.L256, ._F3, ._0F38, .W1, 0x2A, nomem), .vRM, .{ AVX512VL, AVX512CD }),
    vec(.VPBROADCASTMB2Q, ops2(.zmm_kz, .rm_k), evex(.L512, ._F3, ._0F38, .W1, 0x2A, nomem), .vRM, .{AVX512CD}),
    // VPBROADCASTMW2D
    vec(.VPBROADCASTMW2D, ops2(.xmm_kz, .rm_k), evex(.L128, ._F3, ._0F38, .W0, 0x3A, nomem), .vRM, .{ AVX512VL, AVX512CD }),
    vec(.VPBROADCASTMW2D, ops2(.ymm_kz, .rm_k), evex(.L256, ._F3, ._0F38, .W0, 0x3A, nomem), .vRM, .{ AVX512VL, AVX512CD }),
    vec(.VPBROADCASTMW2D, ops2(.zmm_kz, .rm_k), evex(.L512, ._F3, ._0F38, .W0, 0x3A, nomem), .vRM, .{AVX512CD}),
    // VPCMPB / VPCMPUB
    // VPCMPB
    vec(.VPCMPB, ops4(.reg_k_k, .xmm, .xmm_m128, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x3F, fmem), .RVMI, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPB, ops4(.reg_k_k, .ymm, .ymm_m256, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x3F, fmem), .RVMI, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPB, ops4(.reg_k_k, .zmm, .zmm_m512, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x3F, fmem), .RVMI, .{AVX512BW}),
    // VPCMPUB
    vec(.VPCMPUB, ops4(.reg_k_k, .xmm, .xmm_m128, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x3E, fmem), .RVMI, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPUB, ops4(.reg_k_k, .ymm, .ymm_m256, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x3E, fmem), .RVMI, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPUB, ops4(.reg_k_k, .zmm, .zmm_m512, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x3E, fmem), .RVMI, .{AVX512BW}),
    // VPCMPD / VPCMPUD
    // VPCMPD
    vec(.VPCMPD, ops4(.reg_k_k, .xmm, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x1F, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VPCMPD, ops4(.reg_k_k, .ymm, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x1F, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VPCMPD, ops4(.reg_k_k, .zmm, .zmm_m512_m32bcst, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x1F, full), .RVMI, .{AVX512F}),
    // VPCMPUD
    vec(.VPCMPUD, ops4(.reg_k_k, .xmm, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x1E, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VPCMPUD, ops4(.reg_k_k, .ymm, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x1E, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VPCMPUD, ops4(.reg_k_k, .zmm, .zmm_m512_m32bcst, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x1E, full), .RVMI, .{AVX512F}),
    // VPCMPQ / VPCMPUQ
    // VPCMPQ
    vec(.VPCMPQ, ops4(.reg_k_k, .xmm, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x1F, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VPCMPQ, ops4(.reg_k_k, .ymm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x1F, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VPCMPQ, ops4(.reg_k_k, .zmm, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x1F, full), .RVMI, .{AVX512F}),
    // VPCMPUQ
    vec(.VPCMPUQ, ops4(.reg_k_k, .xmm, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x1E, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VPCMPUQ, ops4(.reg_k_k, .ymm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x1E, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VPCMPUQ, ops4(.reg_k_k, .zmm, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x1E, full), .RVMI, .{AVX512F}),
    // VPCMPW / VPCMPUW
    // VPCMPW
    vec(.VPCMPW, ops4(.reg_k_k, .xmm, .xmm_m128, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x3F, fmem), .RVMI, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPW, ops4(.reg_k_k, .ymm, .ymm_m256, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x3F, fmem), .RVMI, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPW, ops4(.reg_k_k, .zmm, .zmm_m512, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x3F, fmem), .RVMI, .{AVX512BW}),
    // VPCMPUW
    vec(.VPCMPUW, ops4(.reg_k_k, .xmm, .xmm_m128, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x3E, fmem), .RVMI, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPUW, ops4(.reg_k_k, .ymm, .ymm_m256, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x3E, fmem), .RVMI, .{ AVX512VL, AVX512BW }),
    vec(.VPCMPUW, ops4(.reg_k_k, .zmm, .zmm_m512, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x3E, fmem), .RVMI, .{AVX512BW}),
    // VPCOMPRESSB / VPCOMPRESSW
    // VPCOMPRESSB
    vec(.VPCOMPRESSB, ops2(.rm_mem128_k, .xmm), evex(.L128, ._66, ._0F38, .W0, 0x63, t1s), .vMR, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPCOMPRESSB, ops2(.rm_xmm_kz, .xmm), evex(.L128, ._66, ._0F38, .W0, 0x63, nomem), .vMR, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPCOMPRESSB, ops2(.rm_mem256_k, .ymm), evex(.L256, ._66, ._0F38, .W0, 0x63, t1s), .vMR, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPCOMPRESSB, ops2(.rm_ymm_kz, .ymm), evex(.L256, ._66, ._0F38, .W0, 0x63, nomem), .vMR, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPCOMPRESSB, ops2(.rm_mem512_k, .zmm), evex(.L512, ._66, ._0F38, .W0, 0x63, t1s), .vMR, .{AVX512_VBMI2}),
    vec(.VPCOMPRESSB, ops2(.rm_zmm_kz, .zmm), evex(.L512, ._66, ._0F38, .W0, 0x63, nomem), .vMR, .{AVX512_VBMI2}),
    // VPCOMPRESSW
    vec(.VPCOMPRESSW, ops2(.rm_mem128_k, .xmm), evex(.L128, ._66, ._0F38, .W1, 0x63, t1s), .vMR, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPCOMPRESSW, ops2(.rm_xmm_kz, .xmm), evex(.L128, ._66, ._0F38, .W1, 0x63, nomem), .vMR, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPCOMPRESSW, ops2(.rm_mem256_k, .ymm), evex(.L256, ._66, ._0F38, .W1, 0x63, t1s), .vMR, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPCOMPRESSW, ops2(.rm_ymm_kz, .ymm), evex(.L256, ._66, ._0F38, .W1, 0x63, nomem), .vMR, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPCOMPRESSW, ops2(.rm_mem512_k, .zmm), evex(.L512, ._66, ._0F38, .W1, 0x63, t1s), .vMR, .{AVX512_VBMI2}),
    vec(.VPCOMPRESSW, ops2(.rm_zmm_kz, .zmm), evex(.L512, ._66, ._0F38, .W1, 0x63, nomem), .vMR, .{AVX512_VBMI2}),
    // VPCOMPRESSD
    vec(.VPCOMPRESSD, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._66, ._0F38, .W0, 0x8B, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPCOMPRESSD, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._66, ._0F38, .W0, 0x8B, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPCOMPRESSD, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._66, ._0F38, .W0, 0x8B, t1s), .vMR, .{AVX512F}),
    // VPCOMPRESSQ
    vec(.VPCOMPRESSQ, ops2(.xmm_m128_kz, .xmm), evex(.L128, ._66, ._0F38, .W1, 0x8B, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPCOMPRESSQ, ops2(.ymm_m256_kz, .ymm), evex(.L256, ._66, ._0F38, .W1, 0x8B, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPCOMPRESSQ, ops2(.zmm_m512_kz, .zmm), evex(.L512, ._66, ._0F38, .W1, 0x8B, t1s), .vMR, .{AVX512F}),
    // VPCONFLICTD / VPCONFLICTQ
    // VPCONFLICTD
    vec(.VPCONFLICTD, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0xC4, full), .vRM, .{ AVX512VL, AVX512CD }),
    vec(.VPCONFLICTD, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0xC4, full), .vRM, .{ AVX512VL, AVX512CD }),
    vec(.VPCONFLICTD, ops2(.zmm_kz, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0xC4, full), .vRM, .{AVX512CD}),
    // VPCONFLICTQ
    vec(.VPCONFLICTQ, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xC4, full), .vRM, .{ AVX512VL, AVX512CD }),
    vec(.VPCONFLICTQ, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xC4, full), .vRM, .{ AVX512VL, AVX512CD }),
    vec(.VPCONFLICTQ, ops2(.zmm_kz, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0xC4, full), .vRM, .{AVX512CD}),
    // VPDPBUSD
    vec(.VPDPBUSD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x50, full), .RVM, .{ AVX512VL, AVX512_VNNI }),
    vec(.VPDPBUSD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x50, full), .RVM, .{ AVX512VL, AVX512_VNNI }),
    vec(.VPDPBUSD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x50, full), .RVM, .{AVX512_VNNI}),
    // VPDPBUSDS
    vec(.VPDPBUSDS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x51, full), .RVM, .{ AVX512VL, AVX512_VNNI }),
    vec(.VPDPBUSDS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x51, full), .RVM, .{ AVX512VL, AVX512_VNNI }),
    vec(.VPDPBUSDS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x51, full), .RVM, .{AVX512_VNNI}),
    // VPDPWSSD
    vec(.VPDPWSSD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x52, full), .RVM, .{ AVX512VL, AVX512_VNNI }),
    vec(.VPDPWSSD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x52, full), .RVM, .{ AVX512VL, AVX512_VNNI }),
    vec(.VPDPWSSD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x52, full), .RVM, .{AVX512_VNNI}),
    // VPDPWSSDS
    vec(.VPDPWSSDS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x53, full), .RVM, .{ AVX512VL, AVX512_VNNI }),
    vec(.VPDPWSSDS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x53, full), .RVM, .{ AVX512VL, AVX512_VNNI }),
    vec(.VPDPWSSDS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x53, full), .RVM, .{AVX512_VNNI}),
    // VPERM2F128
    vec(.VPERM2F128, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .W0, 0x06), .RVMI, .{AVX}),
    // VPERM2I128
    vec(.VPERM2I128, ops4(.ymml, .ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .W0, 0x46), .RVMI, .{AVX2}),
    // VPERMB
    vec(.VPERMB, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W0, 0x8D, fmem), .RVM, .{ AVX512VL, AVX512_VBMI }),
    vec(.VPERMB, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W0, 0x8D, fmem), .RVM, .{ AVX512VL, AVX512_VBMI }),
    vec(.VPERMB, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W0, 0x8D, fmem), .RVM, .{AVX512_VBMI}),
    // VPERMD / VPERMW
    // VPERMD
    vec(.VPERMD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x36), .RVM, .{AVX2}),
    vec(.VPERMD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x36, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x36, full), .RVM, .{AVX512F}),
    // VPERMW
    vec(.VPERMW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x8D, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPERMW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x8D, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPERMW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x8D, fmem), .RVM, .{AVX512BW}),
    // VPERMI2B
    vec(.VPERMI2B, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W0, 0x75, fmem), .RVM, .{ AVX512VL, AVX512_VBMI }),
    vec(.VPERMI2B, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W0, 0x75, fmem), .RVM, .{ AVX512VL, AVX512_VBMI }),
    vec(.VPERMI2B, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W0, 0x75, fmem), .RVM, .{AVX512_VBMI}),
    // VPERMI2W / VPERMI2D / VPERMI2Q / VPERMI2PS / VPERMI2PD
    // VPERMI2W
    vec(.VPERMI2W, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x75, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPERMI2W, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x75, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPERMI2W, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x75, fmem), .RVM, .{AVX512BW}),
    // VPERMI2D
    vec(.VPERMI2D, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x76, full), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPERMI2D, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x76, full), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPERMI2D, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x76, full), .RVM, .{AVX512BW}),
    // VPERMI2Q
    vec(.VPERMI2Q, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x76, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMI2Q, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x76, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMI2Q, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x76, full), .RVM, .{AVX512F}),
    // VPERMI2PS
    vec(.VPERMI2PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x77, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMI2PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x77, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMI2PS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x77, full), .RVM, .{AVX512F}),
    // VPERMI2PD
    vec(.VPERMI2PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x77, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMI2PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x77, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMI2PD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x77, full), .RVM, .{AVX512F}),
    // VPERMILPD
    vec(.VPERMILPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x0D), .RVM, .{AVX}),
    vec(.VPERMILPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x0D), .RVM, .{AVX}),
    vec(.VPERMILPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x0D, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMILPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x0D, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMILPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x0D, full), .RVM, .{AVX512F}),
    vec(.VPERMILPD, ops3(.xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x05), .vRMI, .{AVX}),
    vec(.VPERMILPD, ops3(.ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .W0, 0x05), .vRMI, .{AVX}),
    vec(.VPERMILPD, ops3(.xmm_kz, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x05, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VPERMILPD, ops3(.ymm_kz, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x05, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VPERMILPD, ops3(.zmm_kz, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x05, full), .vRMI, .{AVX512F}),
    // VPERMILPS
    vec(.VPERMILPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x0C), .RVM, .{AVX}),
    vec(.VPERMILPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x0C), .RVM, .{AVX}),
    vec(.VPERMILPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x0C, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMILPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x0C, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMILPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x0C, full), .RVM, .{AVX512F}),
    vec(.VPERMILPS, ops3(.xmml, .xmml_m128, .imm8), vex(.L128, ._66, ._0F3A, .W0, 0x04), .vRMI, .{AVX}),
    vec(.VPERMILPS, ops3(.ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .W0, 0x04), .vRMI, .{AVX}),
    vec(.VPERMILPS, ops3(.xmm_kz, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x04, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VPERMILPS, ops3(.ymm_kz, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x04, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VPERMILPS, ops3(.zmm_kz, .zmm_m512_m32bcst, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x04, full), .vRMI, .{AVX512F}),
    // VPERMPD
    vec(.VPERMPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x16, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x16, full), .RVM, .{AVX512F}),
    vec(.VPERMPD, ops3(.ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .W1, 0x01), .vRMI, .{AVX2}),
    vec(.VPERMPD, ops3(.ymm_kz, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x01, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VPERMPD, ops3(.zmm_kz, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x01, full), .vRMI, .{AVX512F}),
    // VPERMPS
    vec(.VPERMPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x16), .RVM, .{AVX2}),
    vec(.VPERMPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x16, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x16, full), .RVM, .{AVX512F}),
    // VPERMQ
    vec(.VPERMQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x36, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x36, full), .RVM, .{AVX512F}),
    vec(.VPERMQ, ops3(.ymml, .ymml_m256, .imm8), vex(.L256, ._66, ._0F3A, .W1, 0x00), .vRMI, .{AVX}),
    vec(.VPERMQ, ops3(.ymm_kz, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x00, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VPERMQ, ops3(.zmm_kz, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x00, full), .vRMI, .{AVX512F}),
    // VPERMT2B
    vec(.VPERMT2B, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W0, 0x7D, fmem), .RVM, .{ AVX512VL, AVX512_VBMI }),
    vec(.VPERMT2B, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W0, 0x7D, fmem), .RVM, .{ AVX512VL, AVX512_VBMI }),
    vec(.VPERMT2B, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W0, 0x7D, fmem), .RVM, .{AVX512_VBMI}),
    // VPERMT2W / VPERMT2D / VPERMT2Q / VPERMT2PS / VPERMT2PD
    // VPERMT2W
    vec(.VPERMT2W, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x7D, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPERMT2W, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x7D, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPERMT2W, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x7D, fmem), .RVM, .{AVX512BW}),
    // VPERMT2D
    vec(.VPERMT2D, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x7E, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMT2D, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x7E, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMT2D, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x7E, full), .RVM, .{AVX512F}),
    // VPERMT2Q
    vec(.VPERMT2Q, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x7E, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMT2Q, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x7E, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMT2Q, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x7E, full), .RVM, .{AVX512F}),
    // VPERMT2PS
    vec(.VPERMT2PS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x7F, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMT2PS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x7F, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMT2PS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x7F, full), .RVM, .{AVX512F}),
    // VPERMT2PD
    vec(.VPERMT2PD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x7F, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMT2PD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x7F, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPERMT2PD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x7F, full), .RVM, .{AVX512F}),
    // VPEXPANDB / VPEXPANDW
    // VPEXPANDB
    vec(.VPEXPANDB, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F38, .W0, 0x62, t1s), .vRM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPEXPANDB, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F38, .W0, 0x62, t1s), .vRM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPEXPANDB, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F38, .W0, 0x62, t1s), .vRM, .{AVX512_VBMI2}),
    // VPEXPANDW
    vec(.VPEXPANDW, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x62, t1s), .vRM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPEXPANDW, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x62, t1s), .vRM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPEXPANDW, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x62, t1s), .vRM, .{AVX512_VBMI2}),
    // VPEXPANDD
    vec(.VPEXPANDD, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F38, .W0, 0x89, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPEXPANDD, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F38, .W0, 0x89, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPEXPANDD, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F38, .W0, 0x89, t1s), .vRM, .{AVX512F}),
    // VPEXPANDQ
    vec(.VPEXPANDQ, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x89, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPEXPANDQ, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x89, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPEXPANDQ, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x89, t1s), .vRM, .{AVX512F}),
    // VPGATHERDD / VPGATHERQD / VPGATHERDQ / VPGATHERQQ
    // VPGATHERDD
    vec(.VPGATHERDD, ops3(.xmml, .vm32xl, .xmml), vex(.L128, ._66, ._0F38, .W0, 0x90), .RMV, .{AVX2}),
    vec(.VPGATHERDD, ops3(.ymml, .vm32yl, .ymml), vex(.L256, ._66, ._0F38, .W0, 0x90), .RMV, .{AVX2}),
    vec(.VPGATHERDD, ops2(.xmm_k, .vm32x), evex(.L128, ._66, ._0F38, .W0, 0x90, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPGATHERDD, ops2(.ymm_k, .vm32y), evex(.L256, ._66, ._0F38, .W0, 0x90, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPGATHERDD, ops2(.zmm_k, .vm32z), evex(.L512, ._66, ._0F38, .W0, 0x90, t1s), .vRM, .{AVX512F}),
    // VPGATHERDQ
    vec(.VPGATHERDQ, ops3(.xmml, .vm32xl, .xmml), vex(.L128, ._66, ._0F38, .W1, 0x90), .RMV, .{AVX2}),
    vec(.VPGATHERDQ, ops3(.ymml, .vm32xl, .ymml), vex(.L256, ._66, ._0F38, .W1, 0x90), .RMV, .{AVX2}),
    vec(.VPGATHERDQ, ops2(.xmm_k, .vm32x), evex(.L128, ._66, ._0F38, .W1, 0x90, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPGATHERDQ, ops2(.ymm_k, .vm32x), evex(.L256, ._66, ._0F38, .W1, 0x90, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPGATHERDQ, ops2(.zmm_k, .vm32y), evex(.L512, ._66, ._0F38, .W1, 0x90, t1s), .vRM, .{AVX512F}),
    // VPGATHERQD
    vec(.VPGATHERQD, ops3(.xmml, .vm64xl, .xmml), vex(.L128, ._66, ._0F38, .W0, 0x91), .RMV, .{AVX2}),
    vec(.VPGATHERQD, ops3(.xmml, .vm64yl, .xmml), vex(.L256, ._66, ._0F38, .W0, 0x91), .RMV, .{AVX2}),
    vec(.VPGATHERQD, ops2(.xmm_k, .vm64x), evex(.L128, ._66, ._0F38, .W0, 0x91, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPGATHERQD, ops2(.xmm_k, .vm64y), evex(.L256, ._66, ._0F38, .W0, 0x91, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPGATHERQD, ops2(.ymm_k, .vm64z), evex(.L512, ._66, ._0F38, .W0, 0x91, t1s), .vRM, .{AVX512F}),
    // VPGATHERQQ
    vec(.VPGATHERQQ, ops3(.xmml, .vm64xl, .xmml), vex(.L128, ._66, ._0F38, .W1, 0x91), .RMV, .{AVX2}),
    vec(.VPGATHERQQ, ops3(.ymml, .vm64yl, .ymml), vex(.L256, ._66, ._0F38, .W1, 0x91), .RMV, .{AVX2}),
    vec(.VPGATHERQQ, ops2(.xmm_k, .vm64x), evex(.L128, ._66, ._0F38, .W1, 0x91, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPGATHERQQ, ops2(.ymm_k, .vm64y), evex(.L256, ._66, ._0F38, .W1, 0x91, t1s), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VPGATHERQQ, ops2(.zmm_k, .vm64z), evex(.L512, ._66, ._0F38, .W1, 0x91, t1s), .vRM, .{AVX512F}),
    // VPLZCNTD / VPLZCNTQ
    // VPLZCNTD
    vec(.VPLZCNTD, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x44, full), .vRM, .{ AVX512VL, AVX512CD }),
    vec(.VPLZCNTD, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x44, full), .vRM, .{ AVX512VL, AVX512CD }),
    vec(.VPLZCNTD, ops2(.zmm_kz, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x44, full), .vRM, .{AVX512CD}),
    // VPLZCNTQ
    vec(.VPLZCNTQ, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x44, full), .vRM, .{ AVX512VL, AVX512CD }),
    vec(.VPLZCNTQ, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x44, full), .vRM, .{ AVX512VL, AVX512CD }),
    vec(.VPLZCNTQ, ops2(.zmm_kz, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x44, full), .vRM, .{AVX512CD}),
    // VPMADD52HUQ
    vec(.VPMADD52HUQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xB5, full), .RVM, .{ AVX512VL, AVX512_IFMA }),
    vec(.VPMADD52HUQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xB5, full), .RVM, .{ AVX512VL, AVX512_IFMA }),
    vec(.VPMADD52HUQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0xB5, full), .RVM, .{AVX512_IFMA}),
    // VPMADD52LUQ
    vec(.VPMADD52LUQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0xB4, full), .RVM, .{ AVX512VL, AVX512_IFMA }),
    vec(.VPMADD52LUQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0xB4, full), .RVM, .{ AVX512VL, AVX512_IFMA }),
    vec(.VPMADD52LUQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0xB4, full), .RVM, .{AVX512_IFMA}),
    // VPMASKMOV
    // VMASKMOVD
    vec(.VMASKMOVD, ops3(.xmml, .xmml, .rm_mem128), vex(.L128, ._66, ._0F38, .W0, 0x8C), .RVM, .{AVX2}),
    vec(.VMASKMOVD, ops3(.ymml, .ymml, .rm_mem256), vex(.L256, ._66, ._0F38, .W0, 0x8C), .RVM, .{AVX2}),
    vec(.VMASKMOVD, ops3(.rm_mem128, .xmml, .xmml), vex(.L128, ._66, ._0F38, .W0, 0x8E), .MVR, .{AVX2}),
    vec(.VMASKMOVD, ops3(.rm_mem256, .ymml, .ymml), vex(.L256, ._66, ._0F38, .W0, 0x8E), .MVR, .{AVX2}),
    // VMASKMOVQ
    vec(.VMASKMOVQ, ops3(.xmml, .xmml, .rm_mem128), vex(.L128, ._66, ._0F38, .W1, 0x8C), .RVM, .{AVX2}),
    vec(.VMASKMOVQ, ops3(.ymml, .ymml, .rm_mem256), vex(.L256, ._66, ._0F38, .W1, 0x8C), .RVM, .{AVX2}),
    vec(.VMASKMOVQ, ops3(.rm_mem128, .xmml, .xmml), vex(.L128, ._66, ._0F38, .W1, 0x8E), .MVR, .{AVX2}),
    vec(.VMASKMOVQ, ops3(.rm_mem256, .ymml, .ymml), vex(.L256, ._66, ._0F38, .W1, 0x8E), .MVR, .{AVX2}),
    // VPMOVB2M / VPMOVW2M / VPMOVD2M / VPMOVQ2M
    // VPMOVB2M
    vec(.VPMOVB2M, ops2(.reg_k, .rm_xmm), evex(.L128, ._F3, ._0F38, .W0, 0x29, nomem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVB2M, ops2(.reg_k, .rm_ymm), evex(.L256, ._F3, ._0F38, .W0, 0x29, nomem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVB2M, ops2(.reg_k, .rm_zmm), evex(.L512, ._F3, ._0F38, .W0, 0x29, nomem), .vRM, .{AVX512BW}),
    // VPMOVW2M
    vec(.VPMOVW2M, ops2(.reg_k, .rm_xmm), evex(.L128, ._F3, ._0F38, .W1, 0x29, nomem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVW2M, ops2(.reg_k, .rm_ymm), evex(.L256, ._F3, ._0F38, .W1, 0x29, nomem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVW2M, ops2(.reg_k, .rm_zmm), evex(.L512, ._F3, ._0F38, .W1, 0x29, nomem), .vRM, .{AVX512BW}),
    // VPMOVD2M
    vec(.VPMOVD2M, ops2(.reg_k, .rm_xmm), evex(.L128, ._F3, ._0F38, .W0, 0x39, nomem), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VPMOVD2M, ops2(.reg_k, .rm_ymm), evex(.L256, ._F3, ._0F38, .W0, 0x39, nomem), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VPMOVD2M, ops2(.reg_k, .rm_zmm), evex(.L512, ._F3, ._0F38, .W0, 0x39, nomem), .vRM, .{AVX512DQ}),
    // VPMOVQ2M
    vec(.VPMOVQ2M, ops2(.reg_k, .rm_xmm), evex(.L128, ._F3, ._0F38, .W1, 0x39, nomem), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VPMOVQ2M, ops2(.reg_k, .rm_ymm), evex(.L256, ._F3, ._0F38, .W1, 0x39, nomem), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VPMOVQ2M, ops2(.reg_k, .rm_zmm), evex(.L512, ._F3, ._0F38, .W1, 0x39, nomem), .vRM, .{AVX512DQ}),
    // VPMOVDB / VPMOVSDB / VPMOVUSDB
    // VPMOVDB
    vec(.VPMOVDB, ops2(.xmm_m32_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x31, qmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVDB, ops2(.xmm_m64_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x31, qmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVDB, ops2(.xmm_m128_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x31, qmem), .vMR, .{AVX512F}),
    // VPMOVSDB
    vec(.VPMOVSDB, ops2(.xmm_m32_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x21, qmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSDB, ops2(.xmm_m64_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x21, qmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSDB, ops2(.xmm_m128_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x21, qmem), .vMR, .{AVX512F}),
    // VPMOVUSDB
    vec(.VPMOVUSDB, ops2(.xmm_m32_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x11, qmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVUSDB, ops2(.xmm_m64_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x11, qmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVUSDB, ops2(.xmm_m128_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x11, qmem), .vMR, .{AVX512F}),
    // VPMOVDW / VPMOVSDB / VPMOVUSDB
    // VPMOVDW
    vec(.VPMOVDW, ops2(.xmm_m64_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x33, hmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVDW, ops2(.xmm_m128_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x33, hmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVDW, ops2(.ymm_m256_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x33, hmem), .vMR, .{AVX512F}),
    // VPMOVSDB
    vec(.VPMOVSDW, ops2(.xmm_m64_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x23, hmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSDW, ops2(.xmm_m128_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x23, hmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSDW, ops2(.ymm_m256_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x23, hmem), .vMR, .{AVX512F}),
    // VPMOVUSDB
    vec(.VPMOVUSDW, ops2(.xmm_m64_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x13, hmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVUSDW, ops2(.xmm_m128_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x13, hmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVUSDW, ops2(.ymm_m256_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x13, hmem), .vMR, .{AVX512F}),
    // VPMOVM2B / VPMOVM2W / VPMOVM2D / VPMOVM2Q
    // VPMOVM2B
    vec(.VPMOVM2B, ops2(.xmm, .rm_k), evex(.L128, ._F3, ._0F38, .W0, 0x28, nomem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVM2B, ops2(.ymm, .rm_k), evex(.L256, ._F3, ._0F38, .W0, 0x28, nomem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVM2B, ops2(.zmm, .rm_k), evex(.L512, ._F3, ._0F38, .W0, 0x28, nomem), .vRM, .{AVX512BW}),
    // VPMOVM2W
    vec(.VPMOVM2W, ops2(.xmm, .rm_k), evex(.L128, ._F3, ._0F38, .W1, 0x28, nomem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVM2W, ops2(.ymm, .rm_k), evex(.L256, ._F3, ._0F38, .W1, 0x28, nomem), .vRM, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVM2W, ops2(.zmm, .rm_k), evex(.L512, ._F3, ._0F38, .W1, 0x28, nomem), .vRM, .{AVX512BW}),
    // VPMOVM2D
    vec(.VPMOVM2D, ops2(.xmm, .rm_k), evex(.L128, ._F3, ._0F38, .W0, 0x38, nomem), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VPMOVM2D, ops2(.ymm, .rm_k), evex(.L256, ._F3, ._0F38, .W0, 0x38, nomem), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VPMOVM2D, ops2(.zmm, .rm_k), evex(.L512, ._F3, ._0F38, .W0, 0x38, nomem), .vRM, .{AVX512DQ}),
    // VPMOVM2Q
    vec(.VPMOVM2Q, ops2(.xmm, .rm_k), evex(.L128, ._F3, ._0F38, .W1, 0x38, nomem), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VPMOVM2Q, ops2(.ymm, .rm_k), evex(.L256, ._F3, ._0F38, .W1, 0x38, nomem), .vRM, .{ AVX512VL, AVX512DQ }),
    vec(.VPMOVM2Q, ops2(.zmm, .rm_k), evex(.L512, ._F3, ._0F38, .W1, 0x38, nomem), .vRM, .{AVX512DQ}),
    // VPMOVQB / VPMOVSQB / VPMOVUSQB
    // VPMOVQB
    vec(.VPMOVQB, ops2(.xmm_m16_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x32, emem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVQB, ops2(.xmm_m32_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x32, emem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVQB, ops2(.xmm_m64_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x32, emem), .vMR, .{AVX512F}),
    // VPMOVSQB
    vec(.VPMOVSQB, ops2(.xmm_m16_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x22, emem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSQB, ops2(.xmm_m32_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x22, emem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSQB, ops2(.xmm_m64_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x22, emem), .vMR, .{AVX512F}),
    // VPMOVUSQB
    vec(.VPMOVUSQB, ops2(.xmm_m16_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x12, emem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVUSQB, ops2(.xmm_m32_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x12, emem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVUSQB, ops2(.xmm_m64_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x12, emem), .vMR, .{AVX512F}),
    // VPMOVQD / VPMOVSQD / VPMOVUSQD
    // VPMOVQD
    vec(.VPMOVQD, ops2(.xmm_m64_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x35, hmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVQD, ops2(.xmm_m128_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x35, hmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVQD, ops2(.ymm_m256_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x35, hmem), .vMR, .{AVX512F}),
    // VPMOVSQD
    vec(.VPMOVSQD, ops2(.xmm_m64_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x25, hmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSQD, ops2(.xmm_m128_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x25, hmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSQD, ops2(.ymm_m256_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x25, hmem), .vMR, .{AVX512F}),
    // VPMOVUSQD
    vec(.VPMOVUSQD, ops2(.xmm_m64_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x15, hmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVUSQD, ops2(.xmm_m128_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x15, hmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVUSQD, ops2(.ymm_m256_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x15, hmem), .vMR, .{AVX512F}),
    // VPMOVQW / VPMOVSQW / VPMOVUSQW
    // VPMOVQW
    vec(.VPMOVQW, ops2(.xmm_m32_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x34, qmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVQW, ops2(.xmm_m64_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x34, qmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVQW, ops2(.xmm_m128_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x34, qmem), .vMR, .{AVX512F}),
    // VPMOVSQW
    vec(.VPMOVSQW, ops2(.xmm_m32_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x24, qmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSQW, ops2(.xmm_m64_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x24, qmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVSQW, ops2(.xmm_m128_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x24, qmem), .vMR, .{AVX512F}),
    // VPMOVUSQW
    vec(.VPMOVUSQW, ops2(.xmm_m32_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x14, qmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVUSQW, ops2(.xmm_m64_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x14, qmem), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPMOVUSQW, ops2(.xmm_m128_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x14, qmem), .vMR, .{AVX512F}),
    // VPMOVWB / VPMOVSWB / VPMOVUSWB
    // VPMOVWB
    vec(.VPMOVWB, ops2(.xmm_m64_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x30, hmem), .vMR, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVWB, ops2(.xmm_m128_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x30, hmem), .vMR, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVWB, ops2(.ymm_m256_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x30, hmem), .vMR, .{AVX512BW}),
    // VPMOVSWB
    vec(.VPMOVSWB, ops2(.xmm_m64_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x20, hmem), .vMR, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVSWB, ops2(.xmm_m128_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x20, hmem), .vMR, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVSWB, ops2(.ymm_m256_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x20, hmem), .vMR, .{AVX512BW}),
    // VPMOVUSWB
    vec(.VPMOVUSWB, ops2(.xmm_m64_kz, .xmm), evex(.L128, ._F3, ._0F38, .W0, 0x10, hmem), .vMR, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVUSWB, ops2(.xmm_m128_kz, .ymm), evex(.L256, ._F3, ._0F38, .W0, 0x10, hmem), .vMR, .{ AVX512VL, AVX512BW }),
    vec(.VPMOVUSWB, ops2(.ymm_m256_kz, .zmm), evex(.L512, ._F3, ._0F38, .W0, 0x10, hmem), .vMR, .{AVX512BW}),
    // VPMULTISHIFTQB
    // VPMULTISHIFTQB
    vec(.VPMULTISHIFTQB, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x83, full), .RVM, .{ AVX512VL, AVX512_VBMI }),
    vec(.VPMULTISHIFTQB, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x83, full), .RVM, .{ AVX512VL, AVX512_VBMI }),
    vec(.VPMULTISHIFTQB, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x83, full), .RVM, .{AVX512_VBMI}),
    // VPOPCNT
    // VPOPCNTB
    vec(.VPOPCNTB, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F38, .W0, 0x54, fmem), .vRM, .{ AVX512VL, AVX512_BITALG }),
    vec(.VPOPCNTB, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F38, .W0, 0x54, fmem), .vRM, .{ AVX512VL, AVX512_BITALG }),
    vec(.VPOPCNTB, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F38, .W0, 0x54, fmem), .vRM, .{AVX512_BITALG}),
    // VPOPCNTW
    vec(.VPOPCNTW, ops2(.xmm_kz, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x54, fmem), .vRM, .{ AVX512VL, AVX512_BITALG }),
    vec(.VPOPCNTW, ops2(.ymm_kz, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x54, fmem), .vRM, .{ AVX512VL, AVX512_BITALG }),
    vec(.VPOPCNTW, ops2(.zmm_kz, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x54, fmem), .vRM, .{AVX512_BITALG}),
    // VPOPCNTD
    vec(.VPOPCNTD, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x55, full), .vRM, .{ AVX512VL, AVX512_VPOPCNTDQ }),
    vec(.VPOPCNTD, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x55, full), .vRM, .{ AVX512VL, AVX512_VPOPCNTDQ }),
    vec(.VPOPCNTD, ops2(.zmm_kz, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x55, full), .vRM, .{AVX512_VPOPCNTDQ}),
    // VPOPCNTQ
    vec(.VPOPCNTQ, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x55, full), .vRM, .{ AVX512VL, AVX512_VPOPCNTDQ }),
    vec(.VPOPCNTQ, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x55, full), .vRM, .{ AVX512VL, AVX512_VPOPCNTDQ }),
    vec(.VPOPCNTQ, ops2(.zmm_kz, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x55, full), .vRM, .{AVX512_VPOPCNTDQ}),
    // VPROLD / VPROLVD / VPROLQ / VPROLVQ
    // VPROLD
    vec(.VPROLD, ops3(.xmm_kz, .xmm_m128_m32bcst, .imm8), evexr(.L128, ._66, ._0F, .W0, 0x72, 1, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPROLD, ops3(.ymm_kz, .ymm_m256_m32bcst, .imm8), evexr(.L256, ._66, ._0F, .W0, 0x72, 1, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPROLD, ops3(.zmm_kz, .zmm_m512_m32bcst, .imm8), evexr(.L512, ._66, ._0F, .W0, 0x72, 1, full), .VMI, .{AVX512F}),
    // VPROLVD
    vec(.VPROLVD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x15, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPROLVD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x15, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPROLVD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x15, full), .RVM, .{AVX512F}),
    // VPROLQ
    vec(.VPROLQ, ops3(.xmm_kz, .xmm_m128_m64bcst, .imm8), evexr(.L128, ._66, ._0F, .W1, 0x72, 1, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPROLQ, ops3(.ymm_kz, .ymm_m256_m64bcst, .imm8), evexr(.L256, ._66, ._0F, .W1, 0x72, 1, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPROLQ, ops3(.zmm_kz, .zmm_m512_m64bcst, .imm8), evexr(.L512, ._66, ._0F, .W1, 0x72, 1, full), .VMI, .{AVX512F}),
    // VPROLVQ
    vec(.VPROLVQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x15, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPROLVQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x15, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPROLVQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x15, full), .RVM, .{AVX512F}),
    // VPRORD / VPRORVD / VPRORQ / VPRORVQ
    // VPRORD
    vec(.VPRORD, ops3(.xmm_kz, .xmm_m128_m32bcst, .imm8), evexr(.L128, ._66, ._0F, .W0, 0x72, 0, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPRORD, ops3(.ymm_kz, .ymm_m256_m32bcst, .imm8), evexr(.L256, ._66, ._0F, .W0, 0x72, 0, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPRORD, ops3(.zmm_kz, .zmm_m512_m32bcst, .imm8), evexr(.L512, ._66, ._0F, .W0, 0x72, 0, full), .VMI, .{AVX512F}),
    // VPRORVD
    vec(.VPRORVD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x14, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPRORVD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x14, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPRORVD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x14, full), .RVM, .{AVX512F}),
    // VPRORQ
    vec(.VPRORQ, ops3(.xmm_kz, .xmm_m128_m64bcst, .imm8), evexr(.L128, ._66, ._0F, .W1, 0x72, 0, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPRORQ, ops3(.ymm_kz, .ymm_m256_m64bcst, .imm8), evexr(.L256, ._66, ._0F, .W1, 0x72, 0, full), .VMI, .{ AVX512VL, AVX512F }),
    vec(.VPRORQ, ops3(.zmm_kz, .zmm_m512_m64bcst, .imm8), evexr(.L512, ._66, ._0F, .W1, 0x72, 0, full), .VMI, .{AVX512F}),
    // VPRORVQ
    vec(.VPRORVQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x14, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPRORVQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x14, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPRORVQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x14, full), .RVM, .{AVX512F}),
    // VPSCATTERDD / VPSCATTERDQ / VPSCATTERQD / VPSCATTERQQ
    // VPSCATTERDD
    vec(.VPSCATTERDD, ops2(.vm32x_k, .xmm), evex(.L128, ._66, ._0F38, .W0, 0xA0, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPSCATTERDD, ops2(.vm32y_k, .ymm), evex(.L256, ._66, ._0F38, .W0, 0xA0, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPSCATTERDD, ops2(.vm32z_k, .zmm), evex(.L512, ._66, ._0F38, .W0, 0xA0, t1s), .vMR, .{AVX512F}),
    // VPSCATTERDQ
    vec(.VPSCATTERDQ, ops2(.vm32x_k, .xmm), evex(.L128, ._66, ._0F38, .W1, 0xA0, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPSCATTERDQ, ops2(.vm32x_k, .ymm), evex(.L256, ._66, ._0F38, .W1, 0xA0, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPSCATTERDQ, ops2(.vm32y_k, .zmm), evex(.L512, ._66, ._0F38, .W1, 0xA0, t1s), .vMR, .{AVX512F}),
    // VPSCATTERQD
    vec(.VPSCATTERQD, ops2(.vm64x_k, .xmm), evex(.L128, ._66, ._0F38, .W0, 0xA1, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPSCATTERQD, ops2(.vm64y_k, .xmm), evex(.L256, ._66, ._0F38, .W0, 0xA1, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPSCATTERQD, ops2(.vm64z_k, .ymm), evex(.L512, ._66, ._0F38, .W0, 0xA1, t1s), .vMR, .{AVX512F}),
    // VPSCATTERQQ
    vec(.VPSCATTERQQ, ops2(.vm64x_k, .xmm), evex(.L128, ._66, ._0F38, .W1, 0xA1, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPSCATTERQQ, ops2(.vm64y_k, .ymm), evex(.L256, ._66, ._0F38, .W1, 0xA1, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VPSCATTERQQ, ops2(.vm64z_k, .zmm), evex(.L512, ._66, ._0F38, .W1, 0xA1, t1s), .vMR, .{AVX512F}),
    // VPSHLD
    // VPSHLDW
    vec(.VPSHLDW, ops4(.xmm_kz, .xmm, .xmm_m128, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x70, fmem), .RVMI, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHLDW, ops4(.ymm_kz, .ymm, .ymm_m256, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x70, fmem), .RVMI, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHLDW, ops4(.zmm_kz, .zmm, .zmm_m512, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x70, fmem), .RVMI, .{AVX512_VBMI2}),
    // VPSHLDD
    vec(.VPSHLDD, ops4(.xmm_kz, .xmm, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x71, full), .RVMI, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHLDD, ops4(.ymm_kz, .ymm, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x71, full), .RVMI, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHLDD, ops4(.zmm_kz, .zmm, .zmm_m512_m32bcst, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x71, full), .RVMI, .{AVX512_VBMI2}),
    // VPSHLDQ
    vec(.VPSHLDQ, ops4(.xmm_kz, .xmm, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x71, full), .RVMI, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHLDQ, ops4(.ymm_kz, .ymm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x71, full), .RVMI, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHLDQ, ops4(.zmm_kz, .zmm, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x71, full), .RVMI, .{AVX512_VBMI2}),
    // VPSHLDV
    // VPSHLDVW
    vec(.VPSHLDVW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x70, fmem), .RVM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHLDVW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x70, fmem), .RVM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHLDVW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x70, fmem), .RVM, .{AVX512_VBMI2}),
    // VPSHLDVD
    vec(.VPSHLDVD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x71, full), .RVM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHLDVD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x71, full), .RVM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHLDVD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x71, full), .RVM, .{AVX512_VBMI2}),
    // VPSHLDVQ
    vec(.VPSHLDVQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x71, full), .RVM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHLDVQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x71, full), .RVM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHLDVQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x71, full), .RVM, .{AVX512_VBMI2}),
    // VPSHRD
    // VPSHRDW
    vec(.VPSHRDW, ops4(.xmm_kz, .xmm, .xmm_m128, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x72, fmem), .RVMI, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHRDW, ops4(.ymm_kz, .ymm, .ymm_m256, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x72, fmem), .RVMI, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHRDW, ops4(.zmm_kz, .zmm, .zmm_m512, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x72, fmem), .RVMI, .{AVX512_VBMI2}),
    // VPSHRDD
    vec(.VPSHRDD, ops4(.xmm_kz, .xmm, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x73, full), .RVMI, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHRDD, ops4(.ymm_kz, .ymm, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x73, full), .RVMI, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHRDD, ops4(.zmm_kz, .zmm, .zmm_m512_m32bcst, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x73, full), .RVMI, .{AVX512_VBMI2}),
    // VPSHRDQ
    vec(.VPSHRDQ, ops4(.xmm_kz, .xmm, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x73, full), .RVMI, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHRDQ, ops4(.ymm_kz, .ymm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x73, full), .RVMI, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHRDQ, ops4(.zmm_kz, .zmm, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x73, full), .RVMI, .{AVX512_VBMI2}),
    // VPSHRDV
    // VPSHRDVW
    vec(.VPSHRDVW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x72, fmem), .RVM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHRDVW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x72, fmem), .RVM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHRDVW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x72, fmem), .RVM, .{AVX512_VBMI2}),
    // VPSHRDVD
    vec(.VPSHRDVD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x73, full), .RVM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHRDVD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x73, full), .RVM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHRDVD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x73, full), .RVM, .{AVX512_VBMI2}),
    // VPSHRDVQ
    vec(.VPSHRDVQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x73, full), .RVM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHRDVQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x73, full), .RVM, .{ AVX512VL, AVX512_VBMI2 }),
    vec(.VPSHRDVQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x73, full), .RVM, .{AVX512_VBMI2}),
    // VPSHUFBITQMB
    vec(.VPSHUFBITQMB, ops3(.reg_k_k, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W0, 0x8F, fmem), .RVM, .{ AVX512VL, AVX512_BITALG }),
    vec(.VPSHUFBITQMB, ops3(.reg_k_k, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W0, 0x8F, fmem), .RVM, .{ AVX512VL, AVX512_BITALG }),
    vec(.VPSHUFBITQMB, ops3(.reg_k_k, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W0, 0x8F, fmem), .RVM, .{AVX512_BITALG}),
    // VPSLLVW / VPSLLVD / VPSLLVQ
    // VPSLLVW
    vec(.VPSLLVW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x12, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSLLVW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x12, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSLLVW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x12, fmem), .RVM, .{AVX512BW}),
    // VPSLLVD
    vec(.VPSLLVD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x47), .RVM, .{AVX2}),
    vec(.VPSLLVD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x47), .RVM, .{AVX2}),
    vec(.VPSLLVD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x47, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSLLVD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x47, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSLLVD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x47, full), .RVM, .{AVX512F}),
    // VPSLLVQ
    vec(.VPSLLVQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0x47), .RVM, .{AVX2}),
    vec(.VPSLLVQ, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0x47), .RVM, .{AVX2}),
    vec(.VPSLLVQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x47, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSLLVQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x47, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSLLVQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x47, full), .RVM, .{AVX512F}),
    // VPSRAVW / VPSRAVD / VPSRAVQ
    // VPSRAVW
    vec(.VPSRAVW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x11, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSRAVW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x11, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSRAVW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x11, fmem), .RVM, .{AVX512BW}),
    // VPSRAVD
    vec(.VPSRAVD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x46), .RVM, .{AVX2}),
    vec(.VPSRAVD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x46), .RVM, .{AVX2}),
    vec(.VPSRAVD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x46, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRAVD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x46, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRAVD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x46, full), .RVM, .{AVX512F}),
    // VPSRAVQ
    vec(.VPSRAVQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x46, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRAVQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x46, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRAVQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x46, full), .RVM, .{AVX512F}),
    // VPSRLVW / VPSRLVD / VPSRLVQ
    // VPSRLVW
    vec(.VPSRLVW, ops3(.xmm_kz, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x10, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSRLVW, ops3(.ymm_kz, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x10, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPSRLVW, ops3(.zmm_kz, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x10, fmem), .RVM, .{AVX512BW}),
    // VPSRLVD
    vec(.VPSRLVD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x45), .RVM, .{AVX2}),
    vec(.VPSRLVD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x45), .RVM, .{AVX2}),
    vec(.VPSRLVD, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x45, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRLVD, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x45, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRLVD, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x45, full), .RVM, .{AVX512F}),
    // VPSRLVQ
    vec(.VPSRLVQ, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W1, 0x45), .RVM, .{AVX2}),
    vec(.VPSRLVQ, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W1, 0x45), .RVM, .{AVX2}),
    vec(.VPSRLVQ, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x45, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRLVQ, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x45, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPSRLVQ, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x45, full), .RVM, .{AVX512F}),
    // VPTERNLOGD / VPTERNLOGQ
    // VPTERNLOGD
    vec(.VPTERNLOGD, ops4(.xmm_kz, .xmm, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x25, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VPTERNLOGD, ops4(.ymm_kz, .ymm, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x25, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VPTERNLOGD, ops4(.zmm_kz, .zmm, .zmm_m512_m32bcst, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x25, full), .RVMI, .{AVX512F}),
    // VPTERNLOGQ
    vec(.VPTERNLOGQ, ops4(.xmm_kz, .xmm, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x25, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VPTERNLOGQ, ops4(.ymm_kz, .ymm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x25, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VPTERNLOGQ, ops4(.zmm_kz, .zmm, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x25, full), .RVMI, .{AVX512F}),
    // VPTESTMB / VPTESTMW / VPTESTMD / VPTESTMQ
    // VPTESTMB
    vec(.VPTESTMB, ops3(.reg_k_k, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W0, 0x26, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPTESTMB, ops3(.reg_k_k, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W0, 0x26, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPTESTMB, ops3(.reg_k_k, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W0, 0x26, fmem), .RVM, .{AVX512BW}),
    // VPTESTMW
    vec(.VPTESTMW, ops3(.reg_k_k, .xmm, .xmm_m128), evex(.L128, ._66, ._0F38, .W1, 0x26, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPTESTMW, ops3(.reg_k_k, .ymm, .ymm_m256), evex(.L256, ._66, ._0F38, .W1, 0x26, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPTESTMW, ops3(.reg_k_k, .zmm, .zmm_m512), evex(.L512, ._66, ._0F38, .W1, 0x26, fmem), .RVM, .{AVX512BW}),
    // VPTESTMD
    vec(.VPTESTMD, ops3(.reg_k_k, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x27, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPTESTMD, ops3(.reg_k_k, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x27, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPTESTMD, ops3(.reg_k_k, .zmm, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x27, full), .RVM, .{AVX512F}),
    // VPTESTMQ
    vec(.VPTESTMQ, ops3(.reg_k_k, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x27, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPTESTMQ, ops3(.reg_k_k, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x27, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPTESTMQ, ops3(.reg_k_k, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x27, full), .RVM, .{AVX512F}),
    // VPTESTNMB / VPTESTNMW / VPTESTNMD / VPTESTNMQ
    // VPTESTNMB
    vec(.VPTESTNMB, ops3(.reg_k_k, .xmm, .xmm_m128), evex(.L128, ._F3, ._0F38, .W0, 0x26, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPTESTNMB, ops3(.reg_k_k, .ymm, .ymm_m256), evex(.L256, ._F3, ._0F38, .W0, 0x26, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPTESTNMB, ops3(.reg_k_k, .zmm, .zmm_m512), evex(.L512, ._F3, ._0F38, .W0, 0x26, fmem), .RVM, .{AVX512BW}),
    // VPTESTNMW
    vec(.VPTESTNMW, ops3(.reg_k_k, .xmm, .xmm_m128), evex(.L128, ._F3, ._0F38, .W1, 0x26, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPTESTNMW, ops3(.reg_k_k, .ymm, .ymm_m256), evex(.L256, ._F3, ._0F38, .W1, 0x26, fmem), .RVM, .{ AVX512VL, AVX512BW }),
    vec(.VPTESTNMW, ops3(.reg_k_k, .zmm, .zmm_m512), evex(.L512, ._F3, ._0F38, .W1, 0x26, fmem), .RVM, .{AVX512BW}),
    // VPTESTNMD
    vec(.VPTESTNMD, ops3(.reg_k_k, .xmm, .xmm_m128_m32bcst), evex(.L128, ._F3, ._0F38, .W0, 0x27, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPTESTNMD, ops3(.reg_k_k, .ymm, .ymm_m256_m32bcst), evex(.L256, ._F3, ._0F38, .W0, 0x27, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPTESTNMD, ops3(.reg_k_k, .zmm, .zmm_m512_m32bcst), evex(.L512, ._F3, ._0F38, .W0, 0x27, full), .RVM, .{AVX512F}),
    // VPTESTNMQ
    vec(.VPTESTNMQ, ops3(.reg_k_k, .xmm, .xmm_m128_m64bcst), evex(.L128, ._F3, ._0F38, .W1, 0x27, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPTESTNMQ, ops3(.reg_k_k, .ymm, .ymm_m256_m64bcst), evex(.L256, ._F3, ._0F38, .W1, 0x27, full), .RVM, .{ AVX512VL, AVX512F }),
    vec(.VPTESTNMQ, ops3(.reg_k_k, .zmm, .zmm_m512_m64bcst), evex(.L512, ._F3, ._0F38, .W1, 0x27, full), .RVM, .{AVX512F}),
    // VRANGEPD / VRANGEPS / VRANGESD / VRANGESS
    // VRANGEPD
    vec(.VRANGEPD, ops4(.xmm_kz, .xmm, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x50, full), .RVMI, .{ AVX512VL, AVX512DQ }),
    vec(.VRANGEPD, ops4(.ymm_kz, .ymm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x50, full), .RVMI, .{ AVX512VL, AVX512DQ }),
    vec(.VRANGEPD, ops4(.zmm_kz, .zmm, .zmm_m512_m64bcst_sae, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x50, full), .RVMI, .{AVX512DQ}),
    // VRANGEPS
    vec(.VRANGEPS, ops4(.xmm_kz, .xmm, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x50, full), .RVMI, .{ AVX512VL, AVX512DQ }),
    vec(.VRANGEPS, ops4(.ymm_kz, .ymm, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x50, full), .RVMI, .{ AVX512VL, AVX512DQ }),
    vec(.VRANGEPS, ops4(.zmm_kz, .zmm, .zmm_m512_m32bcst_sae, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x50, full), .RVMI, .{AVX512DQ}),
    // VRANGESD
    vec(.VRANGESD, ops4(.xmm_kz, .xmm, .xmm_m64_sae, .imm8), evex(.LIG, ._66, ._0F3A, .W1, 0x51, t1s), .RVMI, .{AVX512DQ}),
    // VRANGESS
    vec(.VRANGESS, ops4(.xmm_kz, .xmm, .xmm_m32_sae, .imm8), evex(.LIG, ._66, ._0F3A, .W0, 0x51, t1s), .RVMI, .{AVX512DQ}),
    // VRCP14PD / VRCP14PS / VRCP14SD / VRCP14SS
    // VRCP14PD
    vec(.VRCP14PD, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x4C, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VRCP14PD, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x4C, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VRCP14PD, ops2(.zmm_kz, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x4C, full), .vRM, .{AVX512F}),
    // VRCP14PS
    vec(.VRCP14PS, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x4C, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VRCP14PS, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x4C, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VRCP14PS, ops2(.zmm_kz, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x4C, full), .vRM, .{AVX512F}),
    // VRCP14SD
    vec(.VRCP14SD, ops3(.xmm_kz, .xmm, .xmm_m64), evex(.LIG, ._66, ._0F38, .W1, 0x4D, t1s), .RVM, .{AVX512F}),
    // VRCP14SS
    vec(.VRCP14SS, ops3(.xmm_kz, .xmm, .xmm_m32), evex(.LIG, ._66, ._0F38, .W0, 0x4D, t1s), .RVM, .{AVX512F}),
    // VREDUCEPD / VREDUCEPS / VREDUCESD / VREDUCESS
    // VREDUCEPD
    vec(.VREDUCEPD, ops3(.xmm_kz, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x56, full), .vRMI, .{ AVX512VL, AVX512DQ }),
    vec(.VREDUCEPD, ops3(.ymm_kz, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x56, full), .vRMI, .{ AVX512VL, AVX512DQ }),
    vec(.VREDUCEPD, ops3(.zmm_kz, .zmm_m512_m64bcst_sae, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x56, full), .vRMI, .{AVX512DQ}),
    // VREDUCEPS
    vec(.VREDUCEPS, ops3(.xmm_kz, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x56, full), .vRMI, .{ AVX512VL, AVX512DQ }),
    vec(.VREDUCEPS, ops3(.ymm_kz, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x56, full), .vRMI, .{ AVX512VL, AVX512DQ }),
    vec(.VREDUCEPS, ops3(.zmm_kz, .zmm_m512_m32bcst_sae, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x56, full), .vRMI, .{AVX512DQ}),
    // VREDUCESD
    vec(.VREDUCESD, ops4(.xmm_kz, .xmm, .xmm_m64_sae, .imm8), evex(.LIG, ._66, ._0F3A, .W1, 0x57, t1s), .RVMI, .{AVX512DQ}),
    // VREDUCESS
    vec(.VREDUCESS, ops4(.xmm_kz, .xmm, .xmm_m32_sae, .imm8), evex(.LIG, ._66, ._0F3A, .W0, 0x57, t1s), .RVMI, .{AVX512DQ}),
    // VRNDSCALEPD / VRNDSCALEPS / VRNDSCALESD / VRNDSCALESS
    // VRNDSCALEPD
    vec(.VRNDSCALEPD, ops3(.xmm_kz, .xmm_m128_m64bcst, .imm8), evex(.L128, ._66, ._0F3A, .W1, 0x09, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VRNDSCALEPD, ops3(.ymm_kz, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x09, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VRNDSCALEPD, ops3(.zmm_kz, .zmm_m512_m64bcst_sae, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x09, full), .vRMI, .{AVX512F}),
    // VRNDSCALEPS
    vec(.VRNDSCALEPS, ops3(.xmm_kz, .xmm_m128_m32bcst, .imm8), evex(.L128, ._66, ._0F3A, .W0, 0x08, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VRNDSCALEPS, ops3(.ymm_kz, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x08, full), .vRMI, .{ AVX512VL, AVX512F }),
    vec(.VRNDSCALEPS, ops3(.zmm_kz, .zmm_m512_m32bcst_sae, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x08, full), .vRMI, .{AVX512F}),
    // VRNDSCALESD
    vec(.VRNDSCALESD, ops4(.xmm_kz, .xmm, .xmm_m64_sae, .imm8), evex(.LIG, ._66, ._0F3A, .W1, 0x0B, t1s), .RVMI, .{AVX512F}),
    // VRNDSCALESS
    vec(.VRNDSCALESS, ops4(.xmm_kz, .xmm, .xmm_m32_sae, .imm8), evex(.LIG, ._66, ._0F3A, .W0, 0x0A, t1s), .RVMI, .{AVX512F}),
    // VRSQRT14PD / VRSQRT14PS / VRSQRT14SD / VRSQRT14SS
    // VRSQRT14PD
    vec(.VRSQRT14PD, ops2(.xmm_kz, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x4E, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VRSQRT14PD, ops2(.ymm_kz, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x4E, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VRSQRT14PD, ops2(.zmm_kz, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F38, .W1, 0x4E, full), .vRM, .{AVX512F}),
    // VRSQRT14PS
    vec(.VRSQRT14PS, ops2(.xmm_kz, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x4E, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VRSQRT14PS, ops2(.ymm_kz, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x4E, full), .vRM, .{ AVX512VL, AVX512F }),
    vec(.VRSQRT14PS, ops2(.zmm_kz, .zmm_m512_m32bcst), evex(.L512, ._66, ._0F38, .W0, 0x4E, full), .vRM, .{AVX512F}),
    // VRSQRT14SD
    vec(.VRSQRT14SD, ops3(.xmm_kz, .xmm, .xmm_m64), evex(.LIG, ._66, ._0F38, .W1, 0x4F, t1s), .RVM, .{AVX512F}),
    // VRSQRT14SS
    vec(.VRSQRT14SS, ops3(.xmm_kz, .xmm, .xmm_m32), evex(.LIG, ._66, ._0F38, .W0, 0x4F, t1s), .RVM, .{AVX512F}),
    // VSCALEFPD / VSCALEFPS / VSCALEFSD / VSCALEFSS
    // VSCALEFPD
    vec(.VSCALEFPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F38, .W1, 0x2C, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VSCALEFPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F38, .W1, 0x2C, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VSCALEFPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst_er), evex(.L512, ._66, ._0F38, .W1, 0x2C, full), .RVMI, .{AVX512F}),
    // VSCALEFPS
    vec(.VSCALEFPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._66, ._0F38, .W0, 0x2C, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VSCALEFPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._66, ._0F38, .W0, 0x2C, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VSCALEFPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst_er), evex(.L512, ._66, ._0F38, .W0, 0x2C, full), .RVMI, .{AVX512F}),
    // VSCALEFSD
    vec(.VSCALEFSD, ops3(.xmm_kz, .xmm, .xmm_m64_er), evex(.LIG, ._66, ._0F38, .W1, 0x2D, t1s), .RVMI, .{AVX512F}),
    // VSCALEFSS
    vec(.VSCALEFSS, ops3(.xmm_kz, .xmm, .xmm_m32_er), evex(.LIG, ._66, ._0F38, .W0, 0x2D, t1s), .RVMI, .{AVX512F}),
    // VSCATTERDPS / VSCATTERDPD / VSCATTERQPS / VSCATTERQPD
    // VSCATTERDPS
    vec(.VSCATTERDPS, ops2(.vm32x_k, .xmm), evex(.L128, ._66, ._0F38, .W0, 0xA2, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VSCATTERDPS, ops2(.vm32y_k, .ymm), evex(.L256, ._66, ._0F38, .W0, 0xA2, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VSCATTERDPS, ops2(.vm32z_k, .zmm), evex(.L512, ._66, ._0F38, .W0, 0xA2, t1s), .vMR, .{AVX512F}),
    // VSCATTERDPD
    vec(.VSCATTERDPD, ops2(.vm32x_k, .xmm), evex(.L128, ._66, ._0F38, .W1, 0xA2, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VSCATTERDPD, ops2(.vm32x_k, .ymm), evex(.L256, ._66, ._0F38, .W1, 0xA2, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VSCATTERDPD, ops2(.vm32y_k, .zmm), evex(.L512, ._66, ._0F38, .W1, 0xA2, t1s), .vMR, .{AVX512F}),
    // VSCATTERQPS
    vec(.VSCATTERQPS, ops2(.vm64x_k, .xmm), evex(.L128, ._66, ._0F38, .W0, 0xA3, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VSCATTERQPS, ops2(.vm64y_k, .xmm), evex(.L256, ._66, ._0F38, .W0, 0xA3, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VSCATTERQPS, ops2(.vm64z_k, .ymm), evex(.L512, ._66, ._0F38, .W0, 0xA3, t1s), .vMR, .{AVX512F}),
    // VSCATTERQPD
    vec(.VSCATTERQPD, ops2(.vm64x_k, .xmm), evex(.L128, ._66, ._0F38, .W1, 0xA3, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VSCATTERQPD, ops2(.vm64y_k, .ymm), evex(.L256, ._66, ._0F38, .W1, 0xA3, t1s), .vMR, .{ AVX512VL, AVX512F }),
    vec(.VSCATTERQPD, ops2(.vm64z_k, .zmm), evex(.L512, ._66, ._0F38, .W1, 0xA3, t1s), .vMR, .{AVX512F}),
    // VSHUFF32X4 / VSHUFF64X2 / VSHUFI32X4 / VSHUFI64X2
    // VSHUFF32X4
    vec(.VSHUFF32X4, ops4(.ymm_kz, .ymm, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x23, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VSHUFF32X4, ops4(.zmm_kz, .zmm, .zmm_m512_m32bcst, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x23, full), .RVMI, .{AVX512F}),
    // VSHUFF64X2
    vec(.VSHUFF64X2, ops4(.ymm_kz, .ymm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x23, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VSHUFF64X2, ops4(.zmm_kz, .zmm, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x23, full), .RVMI, .{AVX512F}),
    // VSHUFI32X4
    vec(.VSHUFI32X4, ops4(.ymm_kz, .ymm, .ymm_m256_m32bcst, .imm8), evex(.L256, ._66, ._0F3A, .W0, 0x43, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VSHUFI32X4, ops4(.zmm_kz, .zmm, .zmm_m512_m32bcst, .imm8), evex(.L512, ._66, ._0F3A, .W0, 0x43, full), .RVMI, .{AVX512F}),
    // VSHUFI64X2
    vec(.VSHUFI64X2, ops4(.ymm_kz, .ymm, .ymm_m256_m64bcst, .imm8), evex(.L256, ._66, ._0F3A, .W1, 0x43, full), .RVMI, .{ AVX512VL, AVX512F }),
    vec(.VSHUFI64X2, ops4(.zmm_kz, .zmm, .zmm_m512_m64bcst, .imm8), evex(.L512, ._66, ._0F3A, .W1, 0x43, full), .RVMI, .{AVX512F}),
    // VTESTPD / VTESTPS
    // VTESTPS
    vec(.VTESTPS, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x0E), .vRM, .{AVX}),
    vec(.VTESTPS, ops2(.ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x0E), .vRM, .{AVX}),
    // VTESTPD
    vec(.VTESTPD, ops2(.xmml, .xmml_m128), vex(.L128, ._66, ._0F38, .W0, 0x0F), .vRM, .{AVX}),
    vec(.VTESTPD, ops2(.ymml, .ymml_m256), vex(.L256, ._66, ._0F38, .W0, 0x0F), .vRM, .{AVX}),
    // VXORPD
    vec(.VXORPD, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._66, ._0F, .WIG, 0x57), .RVM, .{AVX}),
    vec(.VXORPD, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._66, ._0F, .WIG, 0x57), .RVM, .{AVX}),
    vec(.VXORPD, ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128, ._66, ._0F, .W1, 0x57, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VXORPD, ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256, ._66, ._0F, .W1, 0x57, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VXORPD, ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512, ._66, ._0F, .W1, 0x57, full), .RVM, .{AVX512DQ}),
    // VXXORPS
    vec(.VXORPS, ops3(.xmml, .xmml, .xmml_m128), vex(.L128, ._NP, ._0F, .WIG, 0x57), .RVM, .{AVX}),
    vec(.VXORPS, ops3(.ymml, .ymml, .ymml_m256), vex(.L256, ._NP, ._0F, .WIG, 0x57), .RVM, .{AVX}),
    vec(.VXORPS, ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128, ._NP, ._0F, .W0, 0x57, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VXORPS, ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256, ._NP, ._0F, .W0, 0x57, full), .RVM, .{ AVX512VL, AVX512DQ }),
    vec(.VXORPS, ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512, ._NP, ._0F, .W0, 0x57, full), .RVM, .{AVX512DQ}),
    // VZEROALL
    vec(.VZEROALL, ops0(), vex(.L256, ._NP, ._0F, .WIG, 0x77), .vZO, .{AVX}),
    // VZEROUPPER
    vec(.VZEROUPPER, ops0(), vex(.L128, ._NP, ._0F, .WIG, 0x77), .vZO, .{AVX}),

    //
    // AVX512 mask register instructions
    //
    // KADDW / KADDB / KADDD / KADDQ
    vec(.KADDB, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W0, 0x4A), .RVM, .{AVX512DQ}),
    vec(.KADDW, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W0, 0x4A), .RVM, .{AVX512DQ}),
    vec(.KADDD, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W1, 0x4A), .RVM, .{AVX512BW}),
    vec(.KADDQ, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W1, 0x4A), .RVM, .{AVX512BW}),
    // KANDW / KANDB / KANDD / KANDQ
    vec(.KANDB, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W0, 0x41), .RVM, .{AVX512DQ}),
    vec(.KANDW, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W0, 0x41), .RVM, .{AVX512F}),
    vec(.KANDD, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W1, 0x41), .RVM, .{AVX512BW}),
    vec(.KANDQ, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W1, 0x41), .RVM, .{AVX512BW}),
    // KANDNW / KANDNB / KANDND / KANDNQ
    vec(.KANDNB, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W0, 0x42), .RVM, .{AVX512DQ}),
    vec(.KANDNW, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W0, 0x42), .RVM, .{AVX512F}),
    vec(.KANDND, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W1, 0x42), .RVM, .{AVX512BW}),
    vec(.KANDNQ, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W1, 0x42), .RVM, .{AVX512BW}),
    // KNOTW / KNOTB / KNOTD / KNOTQ
    vec(.KNOTB, ops2(.reg_k, .reg_k), vex(.LZ, ._66, ._0F, .W0, 0x44), .vRM, .{AVX512DQ}),
    vec(.KNOTW, ops2(.reg_k, .reg_k), vex(.LZ, ._NP, ._0F, .W0, 0x44), .vRM, .{AVX512F}),
    vec(.KNOTD, ops2(.reg_k, .reg_k), vex(.LZ, ._66, ._0F, .W1, 0x44), .vRM, .{AVX512BW}),
    vec(.KNOTQ, ops2(.reg_k, .reg_k), vex(.LZ, ._NP, ._0F, .W1, 0x44), .vRM, .{AVX512BW}),
    // KORW / KORB / KORD / KORQ
    vec(.KORB, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W0, 0x45), .RVM, .{AVX512DQ}),
    vec(.KORW, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W0, 0x45), .RVM, .{AVX512F}),
    vec(.KORD, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W1, 0x45), .RVM, .{AVX512BW}),
    vec(.KORQ, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W1, 0x45), .RVM, .{AVX512BW}),
    // KORTESTW / KORTESTB / KORTESTD / KORTESTQ
    vec(.KORTESTB, ops2(.reg_k, .reg_k), vex(.LZ, ._66, ._0F, .W0, 0x98), .vRM, .{AVX512DQ}),
    vec(.KORTESTW, ops2(.reg_k, .reg_k), vex(.LZ, ._NP, ._0F, .W0, 0x98), .vRM, .{AVX512F}),
    vec(.KORTESTD, ops2(.reg_k, .reg_k), vex(.LZ, ._66, ._0F, .W1, 0x98), .vRM, .{AVX512BW}),
    vec(.KORTESTQ, ops2(.reg_k, .reg_k), vex(.LZ, ._NP, ._0F, .W1, 0x98), .vRM, .{AVX512BW}),
    // KMOVW / KMOVB / KMOVD / KMOVQ
    vec(.KMOVB, ops2(.reg_k, .k_m8), vex(.LZ, ._66, ._0F, .W0, 0x90), .vRM, .{AVX512DQ}),
    vec(.KMOVB, ops2(.rm_mem8, .reg_k), vex(.LZ, ._66, ._0F, .W0, 0x91), .vMR, .{AVX512DQ}),
    vec(.KMOVB, ops2(.reg_k, .reg32), vex(.LZ, ._66, ._0F, .W0, 0x92), .vRM, .{AVX512DQ}),
    vec(.KMOVB, ops2(.reg32, .reg_k), vex(.LZ, ._66, ._0F, .W0, 0x93), .vRM, .{AVX512DQ}),
    //
    vec(.KMOVW, ops2(.reg_k, .k_m16), vex(.LZ, ._NP, ._0F, .W0, 0x90), .vRM, .{AVX512F}),
    vec(.KMOVW, ops2(.rm_mem16, .reg_k), vex(.LZ, ._NP, ._0F, .W0, 0x91), .vMR, .{AVX512F}),
    vec(.KMOVW, ops2(.reg_k, .reg32), vex(.LZ, ._NP, ._0F, .W0, 0x92), .vRM, .{AVX512F}),
    vec(.KMOVW, ops2(.reg32, .reg_k), vex(.LZ, ._NP, ._0F, .W0, 0x93), .vRM, .{AVX512F}),
    //
    vec(.KMOVD, ops2(.reg_k, .k_m32), vex(.LZ, ._66, ._0F, .W1, 0x90), .vRM, .{AVX512BW}),
    vec(.KMOVD, ops2(.rm_mem32, .reg_k), vex(.LZ, ._66, ._0F, .W1, 0x91), .vMR, .{AVX512BW}),
    vec(.KMOVD, ops2(.reg_k, .reg32), vex(.LZ, ._F2, ._0F, .W0, 0x92), .vRM, .{AVX512BW}),
    vec(.KMOVD, ops2(.reg32, .reg_k), vex(.LZ, ._F2, ._0F, .W0, 0x93), .vRM, .{AVX512BW}),
    //
    vec(.KMOVQ, ops2(.reg_k, .k_m64), vex(.LZ, ._NP, ._0F, .W1, 0x90), .vRM, .{AVX512BW}),
    vec(.KMOVQ, ops2(.rm_mem64, .reg_k), vex(.LZ, ._NP, ._0F, .W1, 0x91), .vMR, .{AVX512BW}),
    vec(.KMOVQ, ops2(.reg_k, .reg64), vex(.LZ, ._F2, ._0F, .W1, 0x92), .vRM, .{ AVX512BW, No32 }),
    vec(.KMOVQ, ops2(.reg64, .reg_k), vex(.LZ, ._F2, ._0F, .W1, 0x93), .vRM, .{ AVX512BW, No32 }),
    // KSHIFTLW / KSHIFTLB / KSHIFTLD / KSHIFTLQ
    vec(.KSHIFTLB, ops3(.reg_k, .reg_k, .imm8), vex(.LZ, ._66, ._0F3A, .W0, 0x32), .vRMI, .{AVX512DQ}),
    vec(.KSHIFTLW, ops3(.reg_k, .reg_k, .imm8), vex(.LZ, ._66, ._0F3A, .W1, 0x32), .vRMI, .{AVX512F}),
    vec(.KSHIFTLD, ops3(.reg_k, .reg_k, .imm8), vex(.LZ, ._66, ._0F3A, .W0, 0x33), .vRMI, .{AVX512BW}),
    vec(.KSHIFTLQ, ops3(.reg_k, .reg_k, .imm8), vex(.LZ, ._66, ._0F3A, .W1, 0x33), .vRMI, .{AVX512BW}),
    // KSHIFTRW / KSHIFTRB / KSHIFTRD / KSHIFTRQ
    vec(.KSHIFTRB, ops3(.reg_k, .reg_k, .imm8), vex(.LZ, ._66, ._0F3A, .W0, 0x30), .vRMI, .{AVX512DQ}),
    vec(.KSHIFTRW, ops3(.reg_k, .reg_k, .imm8), vex(.LZ, ._66, ._0F3A, .W1, 0x30), .vRMI, .{AVX512F}),
    vec(.KSHIFTRD, ops3(.reg_k, .reg_k, .imm8), vex(.LZ, ._66, ._0F3A, .W0, 0x31), .vRMI, .{AVX512BW}),
    vec(.KSHIFTRQ, ops3(.reg_k, .reg_k, .imm8), vex(.LZ, ._66, ._0F3A, .W1, 0x31), .vRMI, .{AVX512BW}),
    // KTESTW / KTESTB / KTESTD / KTESTQ
    vec(.KTESTB, ops2(.reg_k, .reg_k), vex(.LZ, ._66, ._0F, .W0, 0x99), .vRM, .{AVX512DQ}),
    vec(.KTESTW, ops2(.reg_k, .reg_k), vex(.LZ, ._NP, ._0F, .W0, 0x99), .vRM, .{AVX512DQ}),
    vec(.KTESTD, ops2(.reg_k, .reg_k), vex(.LZ, ._66, ._0F, .W1, 0x99), .vRM, .{AVX512BW}),
    vec(.KTESTQ, ops2(.reg_k, .reg_k), vex(.LZ, ._NP, ._0F, .W1, 0x99), .vRM, .{AVX512BW}),
    // KUNPCKBW / KUNPCKWD / KUNPCKDQ
    vec(.KUNPCKBW, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W0, 0x4B), .RVM, .{AVX512F}),
    vec(.KUNPCKWD, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W0, 0x4B), .RVM, .{AVX512BW}),
    vec(.KUNPCKDQ, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W1, 0x4B), .RVM, .{AVX512BW}),
    // KXNORW / KXNORB / KXNORD / KXNORQ
    vec(.KXNORB, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W0, 0x46), .RVM, .{AVX512DQ}),
    vec(.KXNORW, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W0, 0x46), .RVM, .{AVX512F}),
    vec(.KXNORD, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W1, 0x46), .RVM, .{AVX512BW}),
    vec(.KXNORQ, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W1, 0x46), .RVM, .{AVX512BW}),
    // KXORW / KXORB / KXORD / KXORQ
    vec(.KXORB, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W0, 0x47), .RVM, .{AVX512DQ}),
    vec(.KXORW, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W0, 0x47), .RVM, .{AVX512F}),
    vec(.KXORD, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._66, ._0F, .W1, 0x47), .RVM, .{AVX512BW}),
    vec(.KXORQ, ops3(.reg_k, .reg_k, .reg_k), vex(.L1, ._NP, ._0F, .W1, 0x47), .RVM, .{AVX512BW}),

    //
    // Xeon Phi
    //
    // PREFETCHWT1
    instr(.PREFETCHWT1, ops1(.rm_mem8), Op2r(0x0F, 0x0D, 2), .M, .ZO, .{cpu.PREFETCHWT1}),

    //
    // Undefined/Reserved Opcodes
    //
    // Unused opcodes are reserved for future instruction extensions, and most
    // encodings will generate (#UD) on earlier processors.   However, for
    // compatibility with older processors, some reserved opcodes do not generate
    // #UD but behave like other instructions or have unique behavior.
    //
    // SALC
    // - Set AL to Cary flag. IF (CF=1), AL=FF, ELSE, AL=0 (#UD in 64-bit mode)
    instr(.SALC, ops0(), Op1(0xD6), .ZO, .ZO, .{ _8086, No64 }),
    //
    // Immediate Group 1
    //
    // Same behavior as corresponding instruction with Opcode Op1r(0x80, x)
    //
    instr(.RESRV_ADD, ops2(.rm8, .imm8), Op1r(0x82, 0), .MI, .ZO, .{ _8086, No64 }),
    instr(.RESRV_OR, ops2(.rm8, .imm8), Op1r(0x82, 1), .MI, .ZO, .{ _8086, No64 }),
    instr(.RESRV_ADC, ops2(.rm8, .imm8), Op1r(0x82, 2), .MI, .ZO, .{ _8086, No64 }),
    instr(.RESRV_SBB, ops2(.rm8, .imm8), Op1r(0x82, 3), .MI, .ZO, .{ _8086, No64 }),
    instr(.RESRV_AND, ops2(.rm8, .imm8), Op1r(0x82, 4), .MI, .ZO, .{ _8086, No64 }),
    instr(.RESRV_SUB, ops2(.rm8, .imm8), Op1r(0x82, 5), .MI, .ZO, .{ _8086, No64 }),
    instr(.RESRV_XOR, ops2(.rm8, .imm8), Op1r(0x82, 6), .MI, .ZO, .{ _8086, No64 }),
    instr(.RESRV_CMP, ops2(.rm8, .imm8), Op1r(0x82, 7), .MI, .ZO, .{ _8086, No64 }),
    //
    // Shift Group 2 /6
    //
    // Same behavior as corresponding instruction with Opcode Op1r(x, 4)
    //
    instr(.RESRV_SAL, ops2(.rm8, .imm_1), Op1r(0xD0, 6), .M, .ZO, .{_8086}),
    instr(.RESRV_SAL, ops2(.rm8, .reg_cl), Op1r(0xD2, 6), .M, .ZO, .{_8086}),
    instr(.RESRV_SAL, ops2(.rm8, .imm8), Op1r(0xC0, 6), .MI, .ZO, .{_186}),
    instr(.RESRV_SAL, ops2(.rm16, .imm_1), Op1r(0xD1, 6), .M, .Op16, .{_8086}),
    instr(.RESRV_SAL, ops2(.rm32, .imm_1), Op1r(0xD1, 6), .M, .Op32, .{_386}),
    instr(.RESRV_SAL, ops2(.rm64, .imm_1), Op1r(0xD1, 6), .M, .REX_W, .{x86_64}),
    instr(.RESRV_SAL, ops2(.rm16, .imm8), Op1r(0xC1, 6), .MI, .Op16, .{_186}),
    instr(.RESRV_SAL, ops2(.rm32, .imm8), Op1r(0xC1, 6), .MI, .Op32, .{_386}),
    instr(.RESRV_SAL, ops2(.rm64, .imm8), Op1r(0xC1, 6), .MI, .REX_W, .{x86_64}),
    instr(.RESRV_SAL, ops2(.rm16, .reg_cl), Op1r(0xD3, 6), .M, .Op16, .{_8086}),
    instr(.RESRV_SAL, ops2(.rm32, .reg_cl), Op1r(0xD3, 6), .M, .Op32, .{_386}),
    instr(.RESRV_SAL, ops2(.rm64, .reg_cl), Op1r(0xD3, 6), .M, .REX_W, .{x86_64}),
    //
    instr(.RESRV_SHL, ops2(.rm8, .imm_1), Op1r(0xD0, 6), .M, .ZO, .{_8086}),
    instr(.RESRV_SHL, ops2(.rm8, .reg_cl), Op1r(0xD2, 6), .M, .ZO, .{_8086}),
    instr(.RESRV_SHL, ops2(.rm8, .imm8), Op1r(0xC0, 6), .MI, .ZO, .{_186}),
    instr(.RESRV_SHL, ops2(.rm16, .imm_1), Op1r(0xD1, 6), .M, .Op16, .{_8086}),
    instr(.RESRV_SHL, ops2(.rm32, .imm_1), Op1r(0xD1, 6), .M, .Op32, .{_386}),
    instr(.RESRV_SHL, ops2(.rm64, .imm_1), Op1r(0xD1, 6), .M, .REX_W, .{x86_64}),
    instr(.RESRV_SHL, ops2(.rm16, .imm8), Op1r(0xC1, 6), .MI, .Op16, .{_186}),
    instr(.RESRV_SHL, ops2(.rm32, .imm8), Op1r(0xC1, 6), .MI, .Op32, .{_386}),
    instr(.RESRV_SHL, ops2(.rm64, .imm8), Op1r(0xC1, 6), .MI, .REX_W, .{x86_64}),
    instr(.RESRV_SHL, ops2(.rm16, .reg_cl), Op1r(0xD3, 6), .M, .Op16, .{_8086}),
    instr(.RESRV_SHL, ops2(.rm32, .reg_cl), Op1r(0xD3, 6), .M, .Op32, .{_386}),
    instr(.RESRV_SHL, ops2(.rm64, .reg_cl), Op1r(0xD3, 6), .M, .REX_W, .{x86_64}),
    //
    // Unary Group 3 /1
    //
    instr(.RESRV_TEST, ops2(.rm8, .imm8), Op1r(0xF6, 1), .MI, .ZO, .{_8086}),
    instr(.RESRV_TEST, ops2(.rm16, .imm16), Op1r(0xF7, 1), .MI, .Op16, .{_8086}),
    instr(.RESRV_TEST, ops2(.rm32, .imm32), Op1r(0xF7, 1), .MI, .Op32, .{_386}),
    instr(.RESRV_TEST, ops2(.rm64, .imm32), Op1r(0xF7, 1), .MI, .REX_W, .{x86_64}),
    //
    // x87
    //
    // DCD0 - DCD7 (same as FCOM D8D0-D8D7)
    instr(.RESRV_FCOM, ops2(.reg_st0, .reg_st), Op2(0xDC, 0xD0), .O2, .ZO, .{_087}),
    instr(.RESRV_FCOM, ops1(.reg_st), Op2(0xDC, 0xD0), .O, .ZO, .{_087}),
    instr(.RESRV_FCOM, ops0(), Op2(0xDC, 0xD1), .ZO, .ZO, .{_087}),
    // DCD8 - DCDF (same as FCOMP D8D8-D8DF)
    instr(.RESRV_FCOMP, ops2(.reg_st0, .reg_st), Op2(0xDC, 0xD8), .O2, .ZO, .{_087}),
    instr(.RESRV_FCOMP, ops1(.reg_st), Op2(0xDC, 0xD8), .O, .ZO, .{_087}),
    instr(.RESRV_FCOMP, ops0(), Op2(0xDC, 0xD9), .ZO, .ZO, .{_087}),
    // DED0 - DED7 (same as FCOMP D8C8-D8DF)
    instr(.RESRV_FCOMP2, ops2(.reg_st0, .reg_st), Op2(0xDE, 0xD0), .O2, .ZO, .{_087}),
    instr(.RESRV_FCOMP2, ops1(.reg_st), Op2(0xDE, 0xD0), .O, .ZO, .{_087}),
    instr(.RESRV_FCOMP2, ops0(), Op2(0xDE, 0xD1), .ZO, .ZO, .{_087}),
    // D0C8 - D0CF (same as FXCH D9C8-D9CF)
    instr(.RESRV_FXCH, ops2(.reg_st0, .reg_st), Op2(0xD0, 0xC8), .O2, .ZO, .{_087}),
    instr(.RESRV_FXCH, ops1(.reg_st), Op2(0xD0, 0xC8), .O, .ZO, .{_087}),
    instr(.RESRV_FXCH, ops0(), Op2(0xD0, 0xC9), .ZO, .ZO, .{_087}),
    // DFC8 - DFCF (same as FXCH D9C8-D9CF)
    instr(.RESRV_FXCH2, ops2(.reg_st0, .reg_st), Op2(0xDF, 0xC8), .O2, .ZO, .{_087}),
    instr(.RESRV_FXCH2, ops1(.reg_st), Op2(0xDF, 0xC8), .O, .ZO, .{_087}),
    instr(.RESRV_FXCH2, ops0(), Op2(0xDF, 0xC9), .ZO, .ZO, .{_087}),
    // DFD0 - DFD7 (same as FSTP DDD8-DDDF)
    instr(.RESRV_FSTP, ops1(.reg_st), Op2(0xDF, 0xD0), .O, .ZO, .{_087}),
    instr(.RESRV_FSTP, ops2(.reg_st0, .reg_st), Op2(0xDF, 0xD0), .O2, .ZO, .{_087}),
    // DFD8 - DFDF (same as FSTP DDD8-DDDF)
    instr(.RESRV_FSTP2, ops1(.reg_st), Op2(0xDF, 0xD8), .O, .ZO, .{_087}),
    instr(.RESRV_FSTP2, ops2(.reg_st0, .reg_st), Op2(0xDF, 0xD8), .O2, .ZO, .{_087}),
    // D9D8 - D9DF (same as FFREE with addition of an x87 POP)
    instr(.FFREEP, ops1(.reg_st), Op2(0xDF, 0xC0), .O, .ZO, .{_287}),
    // DFC0 - DFC7 (same as FSTP DDD8-DDDF but won't cause a stack underflow exception)
    instr(.FSTPNOUFLOW, ops1(.reg_st), Op2(0xDD, 0xD8), .O, .ZO, .{_087}),
    instr(.FSTPNOUFLOW, ops2(.reg_st0, .reg_st), Op2(0xDD, 0xD8), .O2, .ZO, .{_087}),

    //
    // Reserved NOP
    // - Reserved instructions which have no defined impact on existing architectural state.
    // - All opcodes `0F 0D` and opcodes in range `0F 18` to `0F 1F` that are not defined above
    // NOP - 0F 0D
    // PREFETCH                                   Op2r(0x0F, 0x0D, 0)
    instr(.RESRV_NOP_0F0D_0, ops1(.rm16), Op2r(0x0F, 0x0D, 0), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F0D_0, ops1(.rm32), Op2r(0x0F, 0x0D, 0), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F0D_0, ops1(.rm64), Op2r(0x0F, 0x0D, 0), .M, .REX_W, .{x86_64}),
    // PREFETCHW                                  Op2r(0x0F, 0x0D, 1)
    instr(.RESRV_NOP_0F0D_1, ops1(.rm16), Op2r(0x0F, 0x0D, 1), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F0D_1, ops1(.rm32), Op2r(0x0F, 0x0D, 1), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F0D_1, ops1(.rm64), Op2r(0x0F, 0x0D, 1), .M, .REX_W, .{x86_64}),
    // PREFETCHWT1                                Op2r(0x0F, 0x0D, 2)
    instr(.RESRV_NOP_0F0D_2, ops1(.rm16), Op2r(0x0F, 0x0D, 2), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F0D_2, ops1(.rm32), Op2r(0x0F, 0x0D, 2), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F0D_2, ops1(.rm64), Op2r(0x0F, 0x0D, 2), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F0D_3, ops1(.rm16), Op2r(0x0F, 0x0D, 3), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F0D_3, ops1(.rm32), Op2r(0x0F, 0x0D, 3), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F0D_3, ops1(.rm64), Op2r(0x0F, 0x0D, 3), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F0D_4, ops1(.rm16), Op2r(0x0F, 0x0D, 4), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F0D_4, ops1(.rm32), Op2r(0x0F, 0x0D, 4), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F0D_4, ops1(.rm64), Op2r(0x0F, 0x0D, 4), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F0D_5, ops1(.rm16), Op2r(0x0F, 0x0D, 5), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F0D_5, ops1(.rm32), Op2r(0x0F, 0x0D, 5), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F0D_5, ops1(.rm64), Op2r(0x0F, 0x0D, 5), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F0D_6, ops1(.rm16), Op2r(0x0F, 0x0D, 6), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F0D_6, ops1(.rm32), Op2r(0x0F, 0x0D, 6), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F0D_6, ops1(.rm64), Op2r(0x0F, 0x0D, 6), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F0D_7, ops1(.rm16), Op2r(0x0F, 0x0D, 7), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F0D_7, ops1(.rm32), Op2r(0x0F, 0x0D, 7), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F0D_7, ops1(.rm64), Op2r(0x0F, 0x0D, 7), .M, .REX_W, .{x86_64}),
    // NOP - 0F 18
    // PREFETCHNTA                                Op2r(0x0F, 0x18, 0)
    instr(.RESRV_NOP_0F18_0, ops1(.rm16), Op2r(0x0F, 0x18, 0), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F18_0, ops1(.rm32), Op2r(0x0F, 0x18, 0), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F18_0, ops1(.rm64), Op2r(0x0F, 0x18, 0), .M, .REX_W, .{x86_64}),
    // PREFETCHT0                                 Op2r(0x0F, 0x18, 1)
    instr(.RESRV_NOP_0F18_1, ops1(.rm16), Op2r(0x0F, 0x18, 1), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F18_1, ops1(.rm32), Op2r(0x0F, 0x18, 1), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F18_1, ops1(.rm64), Op2r(0x0F, 0x18, 1), .M, .REX_W, .{x86_64}),
    // PREFETCHT1                                 Op2r(0x0F, 0x18, 2)
    instr(.RESRV_NOP_0F18_2, ops1(.rm16), Op2r(0x0F, 0x18, 2), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F18_2, ops1(.rm32), Op2r(0x0F, 0x18, 2), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F18_2, ops1(.rm64), Op2r(0x0F, 0x18, 2), .M, .REX_W, .{x86_64}),
    // PREFETCHT2                                 Op2r(0x0F, 0x18, 3)
    instr(.RESRV_NOP_0F18_3, ops1(.rm16), Op2r(0x0F, 0x18, 3), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F18_3, ops1(.rm32), Op2r(0x0F, 0x18, 3), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F18_3, ops1(.rm64), Op2r(0x0F, 0x18, 3), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F18_4, ops1(.rm16), Op2r(0x0F, 0x18, 4), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F18_4, ops1(.rm32), Op2r(0x0F, 0x18, 4), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F18_4, ops1(.rm64), Op2r(0x0F, 0x18, 4), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F18_5, ops1(.rm16), Op2r(0x0F, 0x18, 5), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F18_5, ops1(.rm32), Op2r(0x0F, 0x18, 5), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F18_5, ops1(.rm64), Op2r(0x0F, 0x18, 5), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F18_6, ops1(.rm16), Op2r(0x0F, 0x18, 6), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F18_6, ops1(.rm32), Op2r(0x0F, 0x18, 6), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F18_6, ops1(.rm64), Op2r(0x0F, 0x18, 6), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F18_7, ops1(.rm16), Op2r(0x0F, 0x18, 7), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F18_7, ops1(.rm32), Op2r(0x0F, 0x18, 7), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F18_7, ops1(.rm64), Op2r(0x0F, 0x18, 7), .M, .REX_W, .{x86_64}),
    // NOP - 0F 19
    instr(.RESRV_NOP_0F19_0, ops1(.rm16), Op2r(0x0F, 0x19, 0), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F19_0, ops1(.rm32), Op2r(0x0F, 0x19, 0), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F19_0, ops1(.rm64), Op2r(0x0F, 0x19, 0), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F19_1, ops1(.rm16), Op2r(0x0F, 0x19, 1), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F19_1, ops1(.rm32), Op2r(0x0F, 0x19, 1), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F19_1, ops1(.rm64), Op2r(0x0F, 0x19, 1), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F19_2, ops1(.rm16), Op2r(0x0F, 0x19, 2), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F19_2, ops1(.rm32), Op2r(0x0F, 0x19, 2), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F19_2, ops1(.rm64), Op2r(0x0F, 0x19, 2), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F19_3, ops1(.rm16), Op2r(0x0F, 0x19, 3), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F19_3, ops1(.rm32), Op2r(0x0F, 0x19, 3), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F19_3, ops1(.rm64), Op2r(0x0F, 0x19, 3), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F19_4, ops1(.rm16), Op2r(0x0F, 0x19, 4), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F19_4, ops1(.rm32), Op2r(0x0F, 0x19, 4), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F19_4, ops1(.rm64), Op2r(0x0F, 0x19, 4), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F19_5, ops1(.rm16), Op2r(0x0F, 0x19, 5), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F19_5, ops1(.rm32), Op2r(0x0F, 0x19, 5), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F19_5, ops1(.rm64), Op2r(0x0F, 0x19, 5), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F19_6, ops1(.rm16), Op2r(0x0F, 0x19, 6), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F19_6, ops1(.rm32), Op2r(0x0F, 0x19, 6), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F19_6, ops1(.rm64), Op2r(0x0F, 0x19, 6), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F19_7, ops1(.rm16), Op2r(0x0F, 0x19, 7), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F19_7, ops1(.rm32), Op2r(0x0F, 0x19, 7), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F19_7, ops1(.rm64), Op2r(0x0F, 0x19, 7), .M, .REX_W, .{x86_64}),
    // NOP - 0F 1A
    instr(.RESRV_NOP_0F1A_0, ops1(.rm16), Op2r(0x0F, 0x1A, 0), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1A_0, ops1(.rm32), Op2r(0x0F, 0x1A, 0), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1A_0, ops1(.rm64), Op2r(0x0F, 0x1A, 0), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1A_1, ops1(.rm16), Op2r(0x0F, 0x1A, 1), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1A_1, ops1(.rm32), Op2r(0x0F, 0x1A, 1), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1A_1, ops1(.rm64), Op2r(0x0F, 0x1A, 1), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1A_2, ops1(.rm16), Op2r(0x0F, 0x1A, 2), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1A_2, ops1(.rm32), Op2r(0x0F, 0x1A, 2), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1A_2, ops1(.rm64), Op2r(0x0F, 0x1A, 2), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1A_3, ops1(.rm16), Op2r(0x0F, 0x1A, 3), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1A_3, ops1(.rm32), Op2r(0x0F, 0x1A, 3), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1A_3, ops1(.rm64), Op2r(0x0F, 0x1A, 3), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1A_4, ops1(.rm16), Op2r(0x0F, 0x1A, 4), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1A_4, ops1(.rm32), Op2r(0x0F, 0x1A, 4), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1A_4, ops1(.rm64), Op2r(0x0F, 0x1A, 4), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1A_5, ops1(.rm16), Op2r(0x0F, 0x1A, 5), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1A_5, ops1(.rm32), Op2r(0x0F, 0x1A, 5), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1A_5, ops1(.rm64), Op2r(0x0F, 0x1A, 5), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1A_6, ops1(.rm16), Op2r(0x0F, 0x1A, 6), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1A_6, ops1(.rm32), Op2r(0x0F, 0x1A, 6), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1A_6, ops1(.rm64), Op2r(0x0F, 0x1A, 6), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1A_7, ops1(.rm16), Op2r(0x0F, 0x1A, 7), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1A_7, ops1(.rm32), Op2r(0x0F, 0x1A, 7), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1A_7, ops1(.rm64), Op2r(0x0F, 0x1A, 7), .M, .REX_W, .{x86_64}),
    // NOP - 0F 1B
    instr(.RESRV_NOP_0F1B_0, ops1(.rm16), Op2r(0x0F, 0x1B, 0), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1B_0, ops1(.rm32), Op2r(0x0F, 0x1B, 0), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1B_0, ops1(.rm64), Op2r(0x0F, 0x1B, 0), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1B_1, ops1(.rm16), Op2r(0x0F, 0x1B, 1), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1B_1, ops1(.rm32), Op2r(0x0F, 0x1B, 1), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1B_1, ops1(.rm64), Op2r(0x0F, 0x1B, 1), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1B_2, ops1(.rm16), Op2r(0x0F, 0x1B, 2), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1B_2, ops1(.rm32), Op2r(0x0F, 0x1B, 2), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1B_2, ops1(.rm64), Op2r(0x0F, 0x1B, 2), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1B_3, ops1(.rm16), Op2r(0x0F, 0x1B, 3), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1B_3, ops1(.rm32), Op2r(0x0F, 0x1B, 3), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1B_3, ops1(.rm64), Op2r(0x0F, 0x1B, 3), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1B_4, ops1(.rm16), Op2r(0x0F, 0x1B, 4), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1B_4, ops1(.rm32), Op2r(0x0F, 0x1B, 4), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1B_4, ops1(.rm64), Op2r(0x0F, 0x1B, 4), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1B_5, ops1(.rm16), Op2r(0x0F, 0x1B, 5), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1B_5, ops1(.rm32), Op2r(0x0F, 0x1B, 5), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1B_5, ops1(.rm64), Op2r(0x0F, 0x1B, 5), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1B_6, ops1(.rm16), Op2r(0x0F, 0x1B, 6), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1B_6, ops1(.rm32), Op2r(0x0F, 0x1B, 6), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1B_6, ops1(.rm64), Op2r(0x0F, 0x1B, 6), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1B_7, ops1(.rm16), Op2r(0x0F, 0x1B, 7), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1B_7, ops1(.rm32), Op2r(0x0F, 0x1B, 7), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1B_7, ops1(.rm64), Op2r(0x0F, 0x1B, 7), .M, .REX_W, .{x86_64}),
    // NOP - 0F 1C
    // CLDEMOTE                          preOp2r(._NP, 0x0F, 0x1C, 0)
    instr(.RESRV_NOP_0F1C_0, ops1(.rm16), Op2r(0x0F, 0x1C, 0), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1C_0, ops1(.rm32), Op2r(0x0F, 0x1C, 0), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1C_0, ops1(.rm64), Op2r(0x0F, 0x1C, 0), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1C_1, ops1(.rm16), Op2r(0x0F, 0x1C, 1), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1C_1, ops1(.rm32), Op2r(0x0F, 0x1C, 1), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1C_1, ops1(.rm64), Op2r(0x0F, 0x1C, 1), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1C_2, ops1(.rm16), Op2r(0x0F, 0x1C, 2), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1C_2, ops1(.rm32), Op2r(0x0F, 0x1C, 2), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1C_2, ops1(.rm64), Op2r(0x0F, 0x1C, 2), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1C_3, ops1(.rm16), Op2r(0x0F, 0x1C, 3), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1C_3, ops1(.rm32), Op2r(0x0F, 0x1C, 3), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1C_3, ops1(.rm64), Op2r(0x0F, 0x1C, 3), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1C_4, ops1(.rm16), Op2r(0x0F, 0x1C, 4), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1C_4, ops1(.rm32), Op2r(0x0F, 0x1C, 4), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1C_4, ops1(.rm64), Op2r(0x0F, 0x1C, 4), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1C_5, ops1(.rm16), Op2r(0x0F, 0x1C, 5), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1C_5, ops1(.rm32), Op2r(0x0F, 0x1C, 5), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1C_5, ops1(.rm64), Op2r(0x0F, 0x1C, 5), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1C_6, ops1(.rm16), Op2r(0x0F, 0x1C, 6), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1C_6, ops1(.rm32), Op2r(0x0F, 0x1C, 6), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1C_6, ops1(.rm64), Op2r(0x0F, 0x1C, 6), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1C_7, ops1(.rm16), Op2r(0x0F, 0x1C, 7), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1C_7, ops1(.rm32), Op2r(0x0F, 0x1C, 7), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1C_7, ops1(.rm64), Op2r(0x0F, 0x1C, 7), .M, .REX_W, .{x86_64}),
    // NOP - 0F 1D
    instr(.RESRV_NOP_0F1D_0, ops1(.rm16), Op2r(0x0F, 0x1D, 0), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1D_0, ops1(.rm32), Op2r(0x0F, 0x1D, 0), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1D_0, ops1(.rm64), Op2r(0x0F, 0x1D, 0), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1D_1, ops1(.rm16), Op2r(0x0F, 0x1D, 1), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1D_1, ops1(.rm32), Op2r(0x0F, 0x1D, 1), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1D_1, ops1(.rm64), Op2r(0x0F, 0x1D, 1), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1D_2, ops1(.rm16), Op2r(0x0F, 0x1D, 2), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1D_2, ops1(.rm32), Op2r(0x0F, 0x1D, 2), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1D_2, ops1(.rm64), Op2r(0x0F, 0x1D, 2), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1D_3, ops1(.rm16), Op2r(0x0F, 0x1D, 3), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1D_3, ops1(.rm32), Op2r(0x0F, 0x1D, 3), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1D_3, ops1(.rm64), Op2r(0x0F, 0x1D, 3), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1D_4, ops1(.rm16), Op2r(0x0F, 0x1D, 4), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1D_4, ops1(.rm32), Op2r(0x0F, 0x1D, 4), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1D_4, ops1(.rm64), Op2r(0x0F, 0x1D, 4), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1D_5, ops1(.rm16), Op2r(0x0F, 0x1D, 5), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1D_5, ops1(.rm32), Op2r(0x0F, 0x1D, 5), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1D_5, ops1(.rm64), Op2r(0x0F, 0x1D, 5), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1D_6, ops1(.rm16), Op2r(0x0F, 0x1D, 6), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1D_6, ops1(.rm32), Op2r(0x0F, 0x1D, 6), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1D_6, ops1(.rm64), Op2r(0x0F, 0x1D, 6), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1D_7, ops1(.rm16), Op2r(0x0F, 0x1D, 7), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1D_7, ops1(.rm32), Op2r(0x0F, 0x1D, 7), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1D_7, ops1(.rm64), Op2r(0x0F, 0x1D, 7), .M, .REX_W, .{x86_64}),
    // NOP - 0F 1E
    instr(.RESRV_NOP_0F1E_0, ops1(.rm16), Op2r(0x0F, 0x1E, 0), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1E_0, ops1(.rm32), Op2r(0x0F, 0x1E, 0), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1E_0, ops1(.rm64), Op2r(0x0F, 0x1E, 0), .M, .REX_W, .{x86_64}),
    // RDSSPD                            preOp2r(._F3, 0x0F, 0x1E, 1)
    // RDSSPQ                            preOp2r(._F3, 0x0F, 0x1E, 1)
    instr(.RESRV_NOP_0F1E_1, ops1(.rm16), Op2r(0x0F, 0x1E, 1), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1E_1, ops1(.rm32), Op2r(0x0F, 0x1E, 1), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1E_1, ops1(.rm64), Op2r(0x0F, 0x1E, 1), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1E_2, ops1(.rm16), Op2r(0x0F, 0x1E, 2), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1E_2, ops1(.rm32), Op2r(0x0F, 0x1E, 2), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1E_2, ops1(.rm64), Op2r(0x0F, 0x1E, 2), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1E_3, ops1(.rm16), Op2r(0x0F, 0x1E, 3), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1E_3, ops1(.rm32), Op2r(0x0F, 0x1E, 3), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1E_3, ops1(.rm64), Op2r(0x0F, 0x1E, 3), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1E_4, ops1(.rm16), Op2r(0x0F, 0x1E, 4), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1E_4, ops1(.rm32), Op2r(0x0F, 0x1E, 4), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1E_4, ops1(.rm64), Op2r(0x0F, 0x1E, 4), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1E_5, ops1(.rm16), Op2r(0x0F, 0x1E, 5), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1E_5, ops1(.rm32), Op2r(0x0F, 0x1E, 5), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1E_5, ops1(.rm64), Op2r(0x0F, 0x1E, 5), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1E_6, ops1(.rm16), Op2r(0x0F, 0x1E, 6), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1E_6, ops1(.rm32), Op2r(0x0F, 0x1E, 6), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1E_6, ops1(.rm64), Op2r(0x0F, 0x1E, 6), .M, .REX_W, .{x86_64}),
    // ENDBR32                            preOp3(._F3, 0x0F, 0x1E, 0xFB)
    // ENDBR64                            preOp3(._F3, 0x0F, 0x1E, 0xFA)
    instr(.RESRV_NOP_0F1E_7, ops1(.rm16), Op2r(0x0F, 0x1E, 7), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1E_7, ops1(.rm32), Op2r(0x0F, 0x1E, 7), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1E_7, ops1(.rm64), Op2r(0x0F, 0x1E, 7), .M, .REX_W, .{x86_64}),
    // NOP - 0F 1F
    instr(.RESRV_NOP_0F1F_0, ops1(.rm16), Op2r(0x0F, 0x1F, 0), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1F_0, ops1(.rm32), Op2r(0x0F, 0x1F, 0), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1F_0, ops1(.rm64), Op2r(0x0F, 0x1F, 0), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1F_1, ops1(.rm16), Op2r(0x0F, 0x1F, 1), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1F_1, ops1(.rm32), Op2r(0x0F, 0x1F, 1), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1F_1, ops1(.rm64), Op2r(0x0F, 0x1F, 1), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1F_2, ops1(.rm16), Op2r(0x0F, 0x1F, 2), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1F_2, ops1(.rm32), Op2r(0x0F, 0x1F, 2), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1F_2, ops1(.rm64), Op2r(0x0F, 0x1F, 2), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1F_3, ops1(.rm16), Op2r(0x0F, 0x1F, 3), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1F_3, ops1(.rm32), Op2r(0x0F, 0x1F, 3), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1F_3, ops1(.rm64), Op2r(0x0F, 0x1F, 3), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1F_4, ops1(.rm16), Op2r(0x0F, 0x1F, 4), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1F_4, ops1(.rm32), Op2r(0x0F, 0x1F, 4), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1F_4, ops1(.rm64), Op2r(0x0F, 0x1F, 4), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1F_5, ops1(.rm16), Op2r(0x0F, 0x1F, 5), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1F_5, ops1(.rm32), Op2r(0x0F, 0x1F, 5), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1F_5, ops1(.rm64), Op2r(0x0F, 0x1F, 5), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1F_6, ops1(.rm16), Op2r(0x0F, 0x1F, 6), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1F_6, ops1(.rm32), Op2r(0x0F, 0x1F, 6), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1F_6, ops1(.rm64), Op2r(0x0F, 0x1F, 6), .M, .REX_W, .{x86_64}),
    instr(.RESRV_NOP_0F1F_7, ops1(.rm16), Op2r(0x0F, 0x1F, 7), .M, .Op16, .{P6}),
    instr(.RESRV_NOP_0F1F_7, ops1(.rm32), Op2r(0x0F, 0x1F, 7), .M, .Op32, .{P6}),
    instr(.RESRV_NOP_0F1F_7, ops1(.rm64), Op2r(0x0F, 0x1F, 7), .M, .REX_W, .{x86_64}),

    //
    // Legacy, obsolete and undocumented Opcodes
    //
    // STOREALL
    // see: https://web.archive.org/save/http://www.vcfed.org/forum/showthread.php?70386-I-found-the-SAVEALL-opcode/page2
    instr(.STOREALL, ops0(), Op2(0x0F, 0x04), .ZO, .ZO, .{ cpu._286_Legacy, No64 }),
    // LOADALL
    instr(.LOADALL, ops0(), Op2(0x0F, 0x05), .ZO, .ZO, .{ cpu._286_Legacy, No64 }),
    instr(.LOADALL, ops0(), Op2(0x0F, 0x07), .ZO, .ZO, .{ cpu._386_Legacy, No64 }),
    instr(.LOADALLD, ops0(), Op2(0x0F, 0x07), .ZO, .ZO, .{ cpu._386_Legacy, No64 }),
    // UMOV
    instr(.UMOV, ops2(.rm8, .reg8), Op2(0x0F, 0x10), .MR, .ZO, .{ _386_Legacy, No64 }),
    instr(.UMOV, ops2(.rm16, .reg16), Op2(0x0F, 0x11), .MR, .Op16, .{ _386_Legacy, No64 }),
    instr(.UMOV, ops2(.rm32, .reg32), Op2(0x0F, 0x11), .MR, .Op32, .{ _386_Legacy, No64 }),
    //
    instr(.UMOV, ops2(.reg8, .rm8), Op2(0x0F, 0x12), .RM, .ZO, .{ _386_Legacy, No64 }),
    instr(.UMOV, ops2(.reg16, .rm16), Op2(0x0F, 0x13), .RM, .Op32, .{ _386_Legacy, No64 }),
    instr(.UMOV, ops2(.reg32, .rm32), Op2(0x0F, 0x13), .RM, .Op32, .{ _386_Legacy, No64 }),
    //
    instr(.UMOV, ops2(.rm8, .reg8), Op2(0x0F, 0x10), .MR, .ZO, .{ _486_Legacy, No64 }),
    instr(.UMOV, ops2(.rm16, .reg16), Op2(0x0F, 0x11), .MR, .Op16, .{ _486_Legacy, No64 }),
    instr(.UMOV, ops2(.rm32, .reg32), Op2(0x0F, 0x11), .MR, .Op32, .{ _486_Legacy, No64 }),
    //
    instr(.UMOV, ops2(.reg8, .rm8), Op2(0x0F, 0x12), .RM, .ZO, .{ _486_Legacy, No64 }),
    instr(.UMOV, ops2(.reg16, .rm16), Op2(0x0F, 0x13), .RM, .Op32, .{ _486_Legacy, No64 }),
    instr(.UMOV, ops2(.reg32, .rm32), Op2(0x0F, 0x13), .RM, .Op32, .{ _486_Legacy, No64 }),

    // Dummy sigil value that marks the end of the table, use this to avoid
    // extra bounds checking when scanning this table.
    instr(._mnemonic_final, ops0(), Opcode{}, .ZO, .ZO, .{}),
};
