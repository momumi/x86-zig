const x86 = @import("machine.zig");
const std = @import("std");

const assert = std.debug.assert;

usingnamespace(@import("types.zig"));

const AvxOpcode = x86.avx.AvxOpcode;

const Mnemonic = x86.Mnemonic;
const Instruction = x86.Instruction;
const Machine = x86.Machine;
const Operand = x86.operand.Operand;
const Immediate = x86.Immediate;
const OperandType = x86.operand.OperandType;

pub const Signature = struct {
    operands: [4]?OperandType,

    pub fn ops(
        o1: ?OperandType,
        o2: ?OperandType,
        o3: ?OperandType,
        o4: ?OperandType
    ) Signature {
        return Signature {
            .operands = [4]?OperandType { o1, o2, o3, o4 },
        };
    }

    pub fn ops0() Signature
    {
        return Signature {
            .operands = [4]?OperandType { null, null, null, null },
        };
    }

    pub fn ops1(o1: ?OperandType) Signature
    {
        return Signature {
            .operands = [4]?OperandType { o1, null, null, null },
        };
    }

    pub fn ops2(o1: ?OperandType, o2: ?OperandType) Signature
    {
        return Signature {
            .operands = [4]?OperandType { o1, o2, null, null },
        };
    }

    pub fn ops3(o1: ?OperandType, o2: ?OperandType, o3: ?OperandType) Signature
    {
        return Signature {
            .operands = [4]?OperandType { o1, o2, o3, null },
        };
    }

    pub fn ops4(o1: ?OperandType, o2: ?OperandType, o3: ?OperandType, o4: ?OperandType) Signature
    {
        return Signature {
            .operands = [4]?OperandType { o1, o2, o3, o4 },
        };
    }

    pub fn fromOperands(
        operand1: ?*const Operand,
        operand2: ?*const Operand,
        operand3: ?*const Operand,
        operand4: ?*const Operand
    ) Signature {
        const o1: ?OperandType = if (operand1) |op| op.operandType() else null;
        const o2: ?OperandType = if (operand2) |op| op.operandType() else null;
        const o3: ?OperandType = if (operand3) |op| op.operandType() else null;
        const o4: ?OperandType = if (operand4) |op| op.operandType() else null;
        return Signature {
            .operands = [4]?OperandType { o1, o2, o3, o4 },
        };
    }

    pub fn debugPrint(self: Signature) void {
        std.debug.warn("(", .{});
        for (self.operands) |operand| {
            if (operand) |op| {
                std.debug.warn("{},", .{@tagName(op)});
            }
        }
        std.debug.warn("): ", .{});
    }

    pub fn matchTemplate(template: Signature, instance: Signature) bool {
        for (template.operands) |templ, i| {
            const rhs = instance.operands[i];
            if (templ == null and rhs == null) {
                continue;
            } else if ((templ != null and rhs == null) or (templ == null and rhs != null)) {
                return false;
            } else if (!OperandType.matchTemplate(templ.?, rhs.?)) {
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
        op4: ?*const Operand
    ) bool {
        switch (self) {
            .XCHG_EAX => {
                return (mode == .x64 and op1.?.Reg == .EAX and op2.?.Reg == .EAX);
            },
            .NoSign, .Sign => {
                const sign = self;

                var imm_pos: u2 = undefined;
                // figure out which operand is the immediate
                if (op1 != null and op1.?.tag() == .Imm) {
                    imm_pos = 0;
                } else if (op2 != null and op2.?.tag() == .Imm) {
                    imm_pos = 1;
                } else if (op3 != null and op3.?.tag() == .Imm) {
                    imm_pos = 2;
                } else if (op4 != null and op4.?.tag() == .Imm) {
                    imm_pos = 3;
                } else {
                    unreachable;
                }
                const imm = switch (imm_pos) {
                    0 => op1.?.Imm,
                    1 => op2.?.Imm,
                    2 => op3.?.Imm,
                    3 => op4.?.Imm,
                };
                switch (sign) {
                    // Matches edgecase when it's an unsigned immediate that will get sign extended
                    .Sign => {
                        const is_unsigned = imm.sign == .Unsigned;
                        return (is_unsigned and imm.willSignExtend(item.signature.operands[imm_pos].?));
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
pub const CpuVersion = enum {
    /// Added in 8086 / 8088
    _8086,
    /// Added in 80186 / 80188
    _186,
    /// Added in 80286
    _286,
    /// Added in 80386
    _386,
    /// Added in 80486 models
    _486,
    /// Added in later 80486 models
    _486p,
    /// Added in 8087 FPU
    _087,
    /// Added in 80287 FPU
    _287,
    /// Added in 80387 FPU
    _387,
    /// Added in Pentium
    Pent,
    /// Added in Pentium MMX
    MMX,
    /// Added in AMD K6
    K6,
    /// Added in Pentium Pro
    PentPro,
    /// Added in Pentium II
    Pent2,
    /// Added in SSE
    SSE,
    /// Added in SSE2
    SSE2,
    /// Added in SSE3
    SSE3,
    /// Added in SSE4a
    SSE4_a,
    /// Added in SSE4.1
    SSE4_1,
    /// Added in SSE4.2
    SSE4_2,
    /// Added in x86-64
    x64,
    /// Added in AMD-V
    AMD_V,
    /// Added in Intel VT-x
    VT_x,
    /// Added in ABM
    ABM,
    /// Added in BMI1
    BMI1,
    /// Added in BMI2
    BMI2,
    /// Added in TBM
    TBM,
    /// CPUID.01H.EAX[11:8] = Family = 6 or 15 = 0110B or 1111B
    P6,
    /// Added in AVX
    AVX,
    /// Added in AVX2
    AVX2,
    /// Added in AVX-512 F (Foundation)
    AVX512F,
    /// Added in AVX-512 CD (Conflict Detection)
    AVX512CD,
    /// Added in AVX-512 ER (Exponential and Reciprocal)
    AVX512ER,
    /// Added in AVX-512 PF (Prefetch Instructions)
    AVX512PF,
    /// Added in AVX-512 VL (Vector length extensions)
    AVX512VL,
    /// Added in AVX-512 BW (Byte and Word)
    AVX512BW,
    /// Added in AVX-512 DQ (Doubleword and Quadword)
    AVX512DQ,
    /// Added in AVX-512 IFMA (Integer Fused Multiply Add)
    AVX512_IFMA,
    /// Added in AVX-512 VBMI (Vector Byte Manipulation Instructions)
    AVX512_VBMI,
    /// Added in AVX-512 4VNNIW (Vector Neural Network Instructions Word variable precision (4VNNIW))
    AVX512_4VNNIW,
    /// Added in AVX-512 4FMAPS (Fused Multiply Accumulation Packed Single precision (4FMAPS))
    AVX512_4FMAPS,
    /// Added in AVX-512 VPOPCNTDQ (Vector Population Count)
    AVX512_VPOPCNTDQ,
    /// Added in AVX-512 VNNI (Vector Neural Network Instructions)
    AVX512_VNNI,
    /// Added in AVX-512 VBMI2 (Vector Byte Manipulation Instructions 2)
    AVX512_VMBI2,
    /// Added in AVX-512 BITALG (Bit Algorithms)
    AVX512_BITALG,
    /// Added in AVX-512 VP2INTERSECT (Vector Pair Intersection to a Pair of Mask Registers)
    AVX512_VP2INTERSECT,
    /// Added in AVX-512 GFNI (Galois field new instructions EVEX version)
    AVX512_GFNI,
    /// Added in AVX-512 VPCLMULQDQ (Carry-less multiplication quadword EVEX version)
    AVX512_VPCLMULQDQ,
    /// Added in AVX-512 VAES (AES EVEX version)
    AVX512_VAES,

    /// LAHF valid in 64 bit mode only if CPUID.80000001H:ECX.LAHF-SAHF[bit 0]
    FeatLAHF,
};

pub const InstructionPrefix = enum {
    Lock,
    Repne,
    Rep,
    Bnd,
};

pub const InstructionEncoding = enum {
    ZO,     // no operands
    ZO16,   // no operands, 16 bit void operand
    ZO32,   // no operands, 32 bit void operand
    ZO64,   // no operands, 64 bit void operand
    ZODef,  // no operands, void operand with default size
    M,      // r/m value
    I,      // immediate
    I2,     // IGNORE           immediate
    II,     // immediate        immediate
    II16,   // immediate        immediate       void16
    O,      // opcode+reg.num
    O2,     // IGNORE           opcode+reg.num
    RM,     // ModRM:reg        ModRM:r/m
    MR,     // ModRM:r/m        ModRM:reg
    RMI,    // ModRM:reg        ModRM:r/m       immediate
    MRI,    // ModRM:r/m        ModRM:reg       immediate
    OI,     // opcode+reg.num   imm8/16/32/64
    MI,     // ModRM:r/m        imm8/16/32/64

    D,      // encode address or offset
    FD,     // AL/AX/EAX/RAX    Moffs   NA  NA
    TD,     // Moffs (w)        AL/AX/EAX/RAX   NA  NA

    // AvxOpcodes
    VVM,    // ModRM:reg        (E)VEX:vvvv     ModRM:r/m
    VVMV,   // ModRM:reg        (E)VEX:vvvv     ModRM:r/m   imm8[7:4]:vvvv
    VVMI,   // ModRM:reg        (E)VEX:vvvv     ModRM:r/m   imm8
    VMI,    // ModRM:reg        ModRM:r/m       imm8
    MVI,    // ModRM:r/m        ModRM:reg       imm8
    VM,     // ModRM:reg        ModRM:r/m
    MV,     // ModRM:reg        ModRM:r/m
};

pub const OpcodeAny = union {
    Op: Opcode,
    Avx: AvxOpcode,
};

pub const InstructionItem = struct {
    mnemonic: Mnemonic,
    signature: Signature,
    opcode: OpcodeAny,
    encoding: InstructionEncoding,
    default_size: DefaultSize,
    edge_case: OpcodeEdgeCase,
    mode_edge_case: OpcodeEdgeCase,

    fn create(
        mnem: Mnemonic,
        signature: Signature,
        opcode: var,
        en: InstructionEncoding,
        default_size: DefaultSize,
        version_and_features: var
    ) InstructionItem {
        _ = @setEvalBranchQuota(100000);
        // TODO: process version and features field
        // NOTE: If no version flags are given, can calculate version information
        // based of the signature/encoding/default_size properties as one of
        // _8086, _386, x64
        var edge_case = OpcodeEdgeCase.None;
        var mode_edge_case = OpcodeEdgeCase.None;


        if (@typeInfo(@TypeOf(version_and_features)) != .Struct) {
            @compileError("Expected tuple or struct argument, found " ++ @typeName(@TypeOf(args)));
        }

        const opcode_any = switch (@TypeOf(opcode)) {
            Opcode => OpcodeAny { .Op = opcode },
            AvxOpcode => OpcodeAny { .Avx = opcode },
            else => @compileError("Expected Opcode or AvxOpcode, got: " ++ @TypeOf(opcode)),
        };

        inline for (version_and_features) |opt, i| {
            switch (@TypeOf(opt)) {
                CpuVersion => {
                    // TODO:
                },

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

        switch (default_size) {
            .RM32Strict => switch(signature.operands[0].?) {
                .imm16 => {
                    assert(mode_edge_case == .None);
                    mode_edge_case = .No64;
                },
                else => {},
            },

            .RM64Strict => switch(signature.operands[0].?) {
                .imm16,
                .imm32 => {
                    assert(mode_edge_case == .None);
                    mode_edge_case = .No64;
                },
                else => {},
            },

            else => {},
        }

        return InstructionItem {
            .mnemonic = mnem,
            .signature = signature,
            .opcode = opcode_any,
            .encoding = en,
            .default_size = default_size,
            .edge_case = edge_case,
            .mode_edge_case = mode_edge_case,
        };
    }

    pub inline fn hasEdgeCase(self: InstructionItem) bool {
        return self.edge_case != .None;
    }

    pub inline fn isMachineMatch(self: InstructionItem, machine: Machine) bool {
        switch (self.mode_edge_case) {
            .None => {},
            .No64 => if (machine.mode == .x64) return false,
            .No32 => if (machine.mode == .x86 or machine.mode == .x86_16) return false,
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
        op4: ?*const Operand
    ) bool {
        return self.edge_case.isEdgeCase(self, machine.mode, op1, op2, op3, op4);
    }

    pub fn coerceImm(self: InstructionItem, op: ?*const Operand, pos: u8) Immediate {
        switch (self.signature.operands[pos].?) {
            .imm8 => return op.?.*.Imm,
            .imm16 => return op.?.*.Imm.coerce(.Bit16),
            .imm32 => return op.?.*.Imm.coerce(.Bit32),
            .imm64 => return op.?.*.Imm.coerce(.Bit64),
            else => unreachable,
        }
    }

    pub fn encode(
        self: InstructionItem,
        machine: Machine,
        op1: ?*const Operand,
        op2: ?*const Operand,
        op3: ?*const Operand,
        op4: ?*const Operand
    ) AsmError!Instruction {
        switch (self.encoding) {
            .ZO => return machine.encodeOpcode(self.opcode.Op, op1, self.default_size),
            .ZO16 => return machine.encodeOpcode(self.opcode.Op, &Operand.voidOperand(.WORD), self.default_size),
            .ZO32 => return machine.encodeOpcode(self.opcode.Op, &Operand.voidOperand(.DWORD), self.default_size),
            .ZO64 => return machine.encodeOpcode(self.opcode.Op, &Operand.voidOperand(.QWORD), self.default_size),
            .ZODef => return machine.encodeOpcode(self.opcode.Op, &Operand.voidOperand(machine.dataSize()), self.default_size),
            .M => return machine.encodeRm(self.opcode.Op, op1.?.*, self.default_size),
            .I => return machine.encodeImmediate(self.opcode.Op, op2, self.coerceImm(op1, 0), self.default_size),
            .I2 => return machine.encodeImmediate(self.opcode.Op, op1, self.coerceImm(op2, 1), self.default_size),
            .II => return machine.encodeImmImm(self.opcode.Op, op3, self.coerceImm(op1, 0), self.coerceImm(op2, 1), self.default_size),
            .II16 => return machine.encodeImmImm(self.opcode.Op, &Operand.voidOperand(.WORD), self.coerceImm(op1, 0), self.coerceImm(op2, 1), self.default_size),
            .O => return machine.encodeOpcodeRegNum(self.opcode.Op, op1.?.*, self.default_size),
            .O2 => return machine.encodeOpcodeRegNum(self.opcode.Op, op2.?.*, self.default_size),
            .D => return machine.encodeAddress(self.opcode.Op, op1.?.*, self.default_size),
            .OI => return machine.encodeOpcodeRegNumImmediate(self.opcode.Op, op1.?.*, self.coerceImm(op2, 1), self.default_size),
            .MI => return machine.encodeRmImmediate(self.opcode.Op, op1.?.*, self.coerceImm(op2, 1), self.default_size),
            .RM => return machine.encodeRegRm(self.opcode.Op, op1.?.*, op2.?.*, self.default_size),
            .RMI => return machine.encodeRegRmImmediate(self.opcode.Op, op1.?.*, op2.?.*, self.coerceImm(op3, 2), self.default_size),
            .MRI => return machine.encodeRegRmImmediate(self.opcode.Op, op2.?.*, op1.?.*, self.coerceImm(op3, 2), self.default_size),
            .MR => return machine.encodeRegRm(self.opcode.Op, op2.?.*, op1.?.*, self.default_size),
            .FD => return machine.encodeMOffset(self.opcode.Op, op1.?.*, op2.?.*, self.default_size),
            .TD => return machine.encodeMOffset(self.opcode.Op, op2.?.*, op1.?.*, self.default_size),
            .VVM => return machine.encodeAvx(self.opcode.Avx, op1.?, op2, op3, null, null, self.default_size),
            .VMI => return machine.encodeAvx(self.opcode.Avx, op1.?, null, op2, null, op3, self.default_size),
            .MVI => return machine.encodeAvx(self.opcode.Avx, op2.?, null, op1, null, op3, self.default_size),
            .VVMI => return machine.encodeAvx(self.opcode.Avx, op1.?, null, op2, null, op3, self.default_size),
            .VVMV => return machine.encodeAvx(self.opcode.Avx, op1.?, op2, op3, op4, null, self.default_size),
            .VM => return machine.encodeAvx(self.opcode.Avx, op1.?, null, op2, null, null, self.default_size),
            .MV => return machine.encodeAvx(self.opcode.Avx, op2.?, null, op1, null, null, self.default_size),
        }
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
// eg: FSTENV needs prefix 0x9B before other prefixes, because 0x9B is
// actually the opcode FWAIT/WAIT
const preOp1 = x86.Opcode.preOp1;
const preOp2 = x86.Opcode.preOp2;
const preOp1r = x86.Opcode.preOp1r;
const preOp2r = x86.Opcode.preOp2r;
const preOp3 = x86.Opcode.preOp3;

// Opcodes that require no prefix
const npOp1 = x86.Opcode.npOp1;
const npOp2 = x86.Opcode.npOp2;
const npOp1r = x86.Opcode.npOp1r;
const npOp2r = x86.Opcode.npOp2r;
const npOp3 = x86.Opcode.npOp3;

const ops0 = Signature.ops0;
const ops1 = Signature.ops1;
const ops2 = Signature.ops2;
const ops3 = Signature.ops3;
const ops4 = Signature.ops4;

const vex = x86.avx.AvxOpcode.vex;
const vex_r = x86.avx.AvxOpcode.vex_r;
const evex = x86.avx.AvxOpcode.evex;
const evex_r = x86.avx.AvxOpcode.evex_r;
const xop = x86.avx.AvxOpcode.xop;
const xop_r = x86.avx.AvxOpcode.xop_r;

const instr = InstructionItem.create;

const cpu = CpuVersion;
const edge = OpcodeEdgeCase;
const pre = InstructionPrefix;

const No64 = OpcodeEdgeCase.No64;
const No32 = OpcodeEdgeCase.No32;

const _186 = cpu._186;
const _286 = cpu._286;
const _386 = cpu._386;
const _486 = cpu._486;
const Pent = cpu.Pent;
const x86_64 = cpu.x64;
const _087 = cpu._087;
const _187 = cpu._187;
const _287 = cpu._287;
const _387 = cpu._387;
const MMX = cpu.AVX;
const SSE = cpu.SSE;
const SSE2 = cpu.SSE2;
const SSE3 = cpu.SSE3;
const SSE4_a = cpu.SSE4_a;
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
//
// TODO: add a comptime function to check that they have correct order.
pub const instruction_database = [_]InstructionItem {
//
// 8086 / 80186
//

// AAA
    instr(.AAA,     ops0(),                     Op1(0x37),              .ZO, .ZO32Only,   .{} ),
// AAD
    instr(.AAD,     ops0(),                     Op2(0xD5, 0x0A),        .ZO, .ZO32Only,   .{} ),
    instr(.AAD,     ops1(.imm8),                Op1(0xD5),              .I,  .ZO32Only,   .{} ),
// AAM
    instr(.AAM,     ops0(),                     Op2(0xD4, 0x0A),        .ZO, .ZO32Only,   .{} ),
    instr(.AAM,     ops1(.imm8),                Op1(0xD4),              .I,  .ZO32Only,   .{} ),
// AAS
    instr(.AAS,     ops0(),                     Op1(0x3F),              .ZO, .ZO32Only,   .{} ),
// ADD
    instr(.ADD,     ops2(.reg_al, .imm8),       Op1(0x04),              .I2, .RM8,        .{} ),
    instr(.ADD,     ops2(.rm8, .imm8),          Op1r(0x80, 0),          .MI, .RM8,        .{} ),
    instr(.ADD,     ops2(.rm16, .imm8),         Op1r(0x83, 0),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.ADD,     ops2(.rm32, .imm8),         Op1r(0x83, 0),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.ADD,     ops2(.rm64, .imm8),         Op1r(0x83, 0),          .MI, .RM32_I8,    .{edge.Sign} ),
    //
    instr(.ADD,     ops2(.reg_ax, .imm16),      Op1(0x05),              .I2, .RM32,       .{} ),
    instr(.ADD,     ops2(.reg_eax, .imm32),     Op1(0x05),              .I2, .RM32,       .{} ),
    instr(.ADD,     ops2(.reg_rax, .imm32),     Op1(0x05),              .I2, .RM32,       .{edge.Sign} ),
    //
    instr(.ADD,     ops2(.rm16, .imm16),        Op1r(0x81, 0),          .MI, .RM32,       .{} ),
    instr(.ADD,     ops2(.rm32, .imm32),        Op1r(0x81, 0),          .MI, .RM32,       .{} ),
    instr(.ADD,     ops2(.rm64, .imm32),        Op1r(0x81, 0),          .MI, .RM32,       .{edge.Sign} ),
    //
    instr(.ADD,     ops2(.rm8, .reg8),          Op1(0x00),              .MR, .RM8,        .{} ),
    instr(.ADD,     ops2(.rm16, .reg16),        Op1(0x01),              .MR, .RM32,       .{} ),
    instr(.ADD,     ops2(.rm32, .reg32),        Op1(0x01),              .MR, .RM32,       .{} ),
    instr(.ADD,     ops2(.rm64, .reg64),        Op1(0x01),              .MR, .RM32,       .{} ),
    //
    instr(.ADD,     ops2(.reg8, .rm8),          Op1(0x02),              .RM, .RM8,        .{} ),
    instr(.ADD,     ops2(.reg16, .rm16),        Op1(0x03),              .RM, .RM32,       .{} ),
    instr(.ADD,     ops2(.reg32, .rm32),        Op1(0x03),              .RM, .RM32,       .{} ),
    instr(.ADD,     ops2(.reg64, .rm64),        Op1(0x03),              .RM, .RM32,       .{} ),
// ADC
    instr(.ADC,     ops2(.reg_al, .imm8),       Op1(0x14),              .I2, .RM8,        .{} ),
    instr(.ADC,     ops2(.rm8, .imm8),          Op1r(0x80, 2),          .MI, .RM8,        .{} ),
    instr(.ADC,     ops2(.rm16, .imm8),         Op1r(0x83, 2),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.ADC,     ops2(.rm32, .imm8),         Op1r(0x83, 2),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.ADC,     ops2(.rm64, .imm8),         Op1r(0x83, 2),          .MI, .RM32_I8,    .{edge.Sign} ),
    //
    instr(.ADC,     ops2(.reg_ax, .imm16),      Op1(0x15),              .I2, .RM32,       .{} ),
    instr(.ADC,     ops2(.reg_eax, .imm32),     Op1(0x15),              .I2, .RM32,       .{} ),
    instr(.ADC,     ops2(.reg_rax, .imm32),     Op1(0x15),              .I2, .RM32,       .{edge.Sign} ),
    //
    instr(.ADC,     ops2(.rm16, .imm16),        Op1r(0x81, 2),          .MI, .RM32,       .{} ),
    instr(.ADC,     ops2(.rm32, .imm32),        Op1r(0x81, 2),          .MI, .RM32,       .{} ),
    instr(.ADC,     ops2(.rm64, .imm32),        Op1r(0x81, 2),          .MI, .RM32,       .{edge.Sign} ),
    //
    instr(.ADC,     ops2(.rm8, .reg8),          Op1(0x10),              .MR, .RM8,        .{} ),
    instr(.ADC,     ops2(.rm16, .reg16),        Op1(0x11),              .MR, .RM32,       .{} ),
    instr(.ADC,     ops2(.rm32, .reg32),        Op1(0x11),              .MR, .RM32,       .{} ),
    instr(.ADC,     ops2(.rm64, .reg64),        Op1(0x11),              .MR, .RM32,       .{} ),
    //
    instr(.ADC,     ops2(.reg8, .rm8),          Op1(0x12),              .RM, .RM8,        .{} ),
    instr(.ADC,     ops2(.reg16, .rm16),        Op1(0x13),              .RM, .RM32,       .{} ),
    instr(.ADC,     ops2(.reg32, .rm32),        Op1(0x13),              .RM, .RM32,       .{} ),
    instr(.ADC,     ops2(.reg64, .rm64),        Op1(0x13),              .RM, .RM32,       .{} ),
// AND
    instr(.AND,     ops2(.reg_al, .imm8),       Op1(0x24),              .I2, .RM8,        .{} ),
    instr(.AND,     ops2(.rm8, .imm8),          Op1r(0x80, 4),          .MI, .RM8,        .{} ),
    instr(.AND,     ops2(.rm16, .imm8),         Op1r(0x83, 4),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.AND,     ops2(.rm32, .imm8),         Op1r(0x83, 4),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.AND,     ops2(.rm64, .imm8),         Op1r(0x83, 4),          .MI, .RM32_I8,    .{edge.Sign} ),
    //
    instr(.AND,     ops2(.reg_ax, .imm16),      Op1(0x25),              .I2, .RM32,       .{} ),
    instr(.AND,     ops2(.reg_eax, .imm32),     Op1(0x25),              .I2, .RM32,       .{} ),
    instr(.AND,     ops2(.reg_rax, .imm32),     Op1(0x25),              .I2, .RM32,       .{edge.Sign} ),
    //
    instr(.AND,     ops2(.rm16, .imm16),        Op1r(0x81, 4),          .MI, .RM32,       .{} ),
    instr(.AND,     ops2(.rm32, .imm32),        Op1r(0x81, 4),          .MI, .RM32,       .{} ),
    instr(.AND,     ops2(.rm64, .imm32),        Op1r(0x81, 4),          .MI, .RM32,       .{edge.Sign} ),
    //
    instr(.AND,     ops2(.rm8, .reg8),          Op1(0x20),              .MR, .RM8,        .{} ),
    instr(.AND,     ops2(.rm16, .reg16),        Op1(0x21),              .MR, .RM32,       .{} ),
    instr(.AND,     ops2(.rm32, .reg32),        Op1(0x21),              .MR, .RM32,       .{} ),
    instr(.AND,     ops2(.rm64, .reg64),        Op1(0x21),              .MR, .RM32,       .{} ),
    //
    instr(.AND,     ops2(.reg8, .rm8),          Op1(0x22),              .RM, .RM8,        .{} ),
    instr(.AND,     ops2(.reg16, .rm16),        Op1(0x23),              .RM, .RM32,       .{} ),
    instr(.AND,     ops2(.reg32, .rm32),        Op1(0x23),              .RM, .RM32,       .{} ),
    instr(.AND,     ops2(.reg64, .rm64),        Op1(0x23),              .RM, .RM32,       .{} ),
// BOUND
    instr(.BOUND,   ops2(.reg16, .rm16),        Op1(0x62),              .RM, .RM32,       .{No64, _186} ),
    instr(.BOUND,   ops2(.reg32, .rm32),        Op1(0x62),              .RM, .RM32,       .{No64, _186} ),
// CALL
    instr(.CALL,    ops1(.imm16),               Op1(0xE8),              .I,  .RM32Strict, .{} ),
    instr(.CALL,    ops1(.imm32),               Op1(0xE8),              .I,  .RM32Strict, .{} ),
    //
    instr(.CALL,    ops1(.rm16),                Op1r(0xFF, 2),          .M,  .RM64Strict, .{} ),
    instr(.CALL,    ops1(.rm32),                Op1r(0xFF, 2),          .M,  .RM64Strict, .{} ),
    instr(.CALL,    ops1(.rm64),                Op1r(0xFF, 2),          .M,  .RM64Strict, .{} ),
    //
    instr(.CALL,    ops1(.ptr16_16),            Op1r(0x9A, 4),          .D,  .RM32Only,   .{} ),
    instr(.CALL,    ops1(.ptr16_32),            Op1r(0x9A, 4),          .D,  .RM32Only,   .{} ),
    //
    instr(.CALL,    ops1(.m16_16),              Op1r(0xFF, 3),          .M,  .RM32,       .{} ),
    instr(.CALL,    ops1(.m16_32),              Op1r(0xFF, 3),          .M,  .RM32,       .{} ),
    instr(.CALL,    ops1(.m16_64),              Op1r(0xFF, 3),          .M,  .RM32,       .{} ),
// CBW
    instr(.CBW,     ops0(),                     Op1(0x98),              .ZO16, .RM32,     .{} ),
    instr(.CWDE,    ops0(),                     Op1(0x98),              .ZO32, .RM32,     .{_386} ),
    instr(.CDQE,    ops0(),                     Op1(0x98),              .ZO64, .RM32,     .{x86_64} ),
    //
    instr(.CWD,     ops0(),                     Op1(0x99),              .ZO16, .RM32,     .{} ),
    instr(.CDQ,     ops0(),                     Op1(0x99),              .ZO32, .RM32,     .{_386} ),
    instr(.CQO,     ops0(),                     Op1(0x99),              .ZO64, .RM32,     .{x86_64} ),
// CLC
    instr(.CLC,     ops0(),                     Op1(0xF8),              .ZO, .ZO,         .{} ),
// CLD
    instr(.CLD,     ops0(),                     Op1(0xFC),              .ZO, .ZO,         .{} ),
// CLI
    instr(.CLI,     ops0(),                     Op1(0xFA),              .ZO, .ZO,         .{} ),
// CMC
    instr(.CMC,     ops0(),                     Op1(0xF5),              .ZO, .ZO,         .{} ),
// CMP
    instr(.CMP,     ops2(.reg_al, .imm8),       Op1(0x3C),              .I2, .RM8,        .{} ),
    instr(.CMP,     ops2(.rm8, .imm8),          Op1r(0x80, 7),          .MI, .RM8,        .{} ),
    instr(.CMP,     ops2(.rm16, .imm8),         Op1r(0x83, 7),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.CMP,     ops2(.rm32, .imm8),         Op1r(0x83, 7),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.CMP,     ops2(.rm64, .imm8),         Op1r(0x83, 7),          .MI, .RM32_I8,    .{edge.Sign} ),
    //
    instr(.CMP,     ops2(.reg_ax, .imm16),      Op1(0x3D),              .I2, .RM32,       .{} ),
    instr(.CMP,     ops2(.reg_eax, .imm32),     Op1(0x3D),              .I2, .RM32,       .{} ),
    instr(.CMP,     ops2(.reg_rax, .imm32),     Op1(0x3D),              .I2, .RM32,       .{edge.Sign} ),
    //
    instr(.CMP,     ops2(.rm16, .imm16),        Op1r(0x81, 7),          .MI, .RM32,       .{} ),
    instr(.CMP,     ops2(.rm32, .imm32),        Op1r(0x81, 7),          .MI, .RM32,       .{} ),
    instr(.CMP,     ops2(.rm64, .imm32),        Op1r(0x81, 7),          .MI, .RM32,       .{edge.Sign} ),
    //
    instr(.CMP,     ops2(.rm8, .reg8),          Op1(0x38),              .MR, .RM8,        .{} ),
    instr(.CMP,     ops2(.rm16, .reg16),        Op1(0x39),              .MR, .RM32,       .{} ),
    instr(.CMP,     ops2(.rm32, .reg32),        Op1(0x39),              .MR, .RM32,       .{} ),
    instr(.CMP,     ops2(.rm64, .reg64),        Op1(0x39),              .MR, .RM32,       .{} ),
    //
    instr(.CMP,     ops2(.reg8, .rm8),          Op1(0x3A),              .RM, .RM8,        .{} ),
    instr(.CMP,     ops2(.reg16, .rm16),        Op1(0x3B),              .RM, .RM32,       .{} ),
    instr(.CMP,     ops2(.reg32, .rm32),        Op1(0x3B),              .RM, .RM32,       .{} ),
    instr(.CMP,     ops2(.reg64, .rm64),        Op1(0x3B),              .RM, .RM32,       .{} ),
// CMPS / CMPSB / CMPSW / CMPSD / CMPSQ
    instr(.CMPS,    ops1(._void8),              Op1(0xA6),              .ZO, .RM8,        .{} ),
    instr(.CMPS,    ops1(._void),               Op1(0xA7),              .ZO, .RM32,       .{} ),
    //
    instr(.CMPSB,   ops0(),                     Op1(0xA6),              .ZO,   .RM8,      .{} ),
    instr(.CMPSW,   ops0(),                     Op1(0xA7),              .ZO16, .RM32,     .{} ),
    instr(.CMPSD,   ops0(),                     Op1(0xA7),              .ZO32, .RM32,     .{_386} ),
    instr(.CMPSQ,   ops0(),                     Op1(0xA7),              .ZO64, .RM32,     .{x86_64} ),
// DAA
    instr(.DAA,     ops0(),                     Op1(0x27),              .ZO, .ZO32Only,   .{} ),
// DAS
    instr(.DAS,     ops0(),                     Op1(0x2F),              .ZO, .ZO32Only,   .{} ),
// DEC
    instr(.DEC,     ops1(.reg16),               Op1(0x48),              .O,  .RM32,       .{No64} ),
    instr(.DEC,     ops1(.reg32),               Op1(0x48),              .O,  .RM32,       .{No64} ),
    instr(.DEC,     ops1(.rm8),                 Op1r(0xFE, 1),          .M,  .RM8,        .{} ),
    instr(.DEC,     ops1(.rm16),                Op1r(0xFF, 1),          .M,  .RM32,       .{} ),
    instr(.DEC,     ops1(.rm32),                Op1r(0xFF, 1),          .M,  .RM32,       .{} ),
    instr(.DEC,     ops1(.rm64),                Op1r(0xFF, 1),          .M,  .RM32,       .{} ),
// DIV
    instr(.DIV,     ops1(.rm8),                 Op1r(0xF6, 6),          .M,  .RM8,        .{} ),
    instr(.DIV,     ops1(.rm16),                Op1r(0xF7, 6),          .M,  .RM32,       .{} ),
    instr(.DIV,     ops1(.rm32),                Op1r(0xF7, 6),          .M,  .RM32,       .{} ),
    instr(.DIV,     ops1(.rm64),                Op1r(0xF7, 6),          .M,  .RM32,       .{} ),
// ENTER
    instr(.ENTER,   ops2(.imm16, .imm8),        Op1(0xC8),              .II, .RM64_16,    .{_186} ),
    instr(.ENTERW,  ops2(.imm16, .imm8),        Op1(0xC8),              .II16, .RM64_16,  .{_186} ),
// HLT
    instr(.HLT,     ops0(),                     Op1(0xF4),              .ZO, .ZO,         .{} ),
// IDIV
    instr(.IDIV,    ops1(.rm8),                 Op1r(0xF6, 7),          .M,  .RM8,        .{} ),
    instr(.IDIV,    ops1(.rm16),                Op1r(0xF7, 7),          .M,  .RM32,       .{} ),
    instr(.IDIV,    ops1(.rm32),                Op1r(0xF7, 7),          .M,  .RM32,       .{} ),
    instr(.IDIV,    ops1(.rm64),                Op1r(0xF7, 7),          .M,  .RM32,       .{} ),
// IMUL
    instr(.IMUL,    ops1(.rm8),                 Op1r(0xF6, 5),          .M,  .RM8,        .{} ),
    instr(.IMUL,    ops1(.rm16),                Op1r(0xF7, 5),          .M,  .RM32,       .{} ),
    instr(.IMUL,    ops1(.rm32),                Op1r(0xF7, 5),          .M,  .RM32,       .{} ),
    instr(.IMUL,    ops1(.rm64),                Op1r(0xF7, 5),          .M,  .RM32,       .{} ),
    //
    instr(.IMUL,    ops2(.reg16, .rm16),        Op2(0x0F, 0xAF),        .RM, .RM32,       .{} ),
    instr(.IMUL,    ops2(.reg32, .rm32),        Op2(0x0F, 0xAF),        .RM, .RM32,       .{} ),
    instr(.IMUL,    ops2(.reg64, .rm64),        Op2(0x0F, 0xAF),        .RM, .RM32,       .{} ),
    //
    instr(.IMUL,    ops3(.reg16, .rm16, .imm8), Op1(0x6B),              .RMI, .RM32_I8,   .{edge.Sign, _186} ),
    instr(.IMUL,    ops3(.reg32, .rm32, .imm8), Op1(0x6B),              .RMI, .RM32_I8,   .{edge.Sign, _386} ),
    instr(.IMUL,    ops3(.reg64, .rm64, .imm8), Op1(0x6B),              .RMI, .RM32_I8,   .{edge.Sign, x86_64} ),
    //
    instr(.IMUL,    ops3(.reg16, .rm16, .imm16),Op1(0x69),              .RMI, .RM32,      .{_186} ),
    instr(.IMUL,    ops3(.reg32, .rm32, .imm32),Op1(0x69),              .RMI, .RM32,      .{_386} ),
    instr(.IMUL,    ops3(.reg64, .rm64, .imm32),Op1(0x69),              .RMI, .RM32,      .{edge.Sign, x86_64} ),
// IN
    instr(.IN,      ops2(.reg_al, .imm8),       Op1(0xE4),              .I2, .RM8,        .{} ),
    instr(.IN,      ops2(.reg_ax, .imm8),       Op1(0xE5),              .I2, .RM32,       .{} ),
    instr(.IN,      ops2(.reg_eax, .imm8),      Op1(0xE5),              .I2, .RM32,       .{} ),
    instr(.IN,      ops2(.reg_al, .reg_dx),     Op1(0xEC),              .ZO, .RM8,        .{} ),
    instr(.IN,      ops2(.reg_ax, .reg_dx),     Op1(0xED),              .ZO16, .RM32,     .{} ),
    instr(.IN,      ops2(.reg_eax, .reg_dx),    Op1(0xED),              .ZO32, .RM32,     .{} ),
// INC
    instr(.INC,     ops1(.reg16),               Op1(0x40),              .O,  .RM32,       .{No64} ),
    instr(.INC,     ops1(.reg32),               Op1(0x40),              .O,  .RM32,       .{No64} ),
    instr(.INC,     ops1(.rm8),                 Op1r(0xFE, 0),          .M,  .RM8,        .{} ),
    instr(.INC,     ops1(.rm16),                Op1r(0xFF, 0),          .M,  .RM32,       .{} ),
    instr(.INC,     ops1(.rm32),                Op1r(0xFF, 0),          .M,  .RM32,       .{} ),
    instr(.INC,     ops1(.rm64),                Op1r(0xFF, 0),          .M,  .RM32,       .{} ),
// INS / INSB / INSW / INSD
    instr(.INS,     ops1(._void8),              Op1(0x6C),              .ZO, .RM8,        .{_186} ),
    instr(.INS,     ops1(._void),               Op1(0x6D),              .ZO, .RM32,       .{_186} ),
    //
    instr(.INSB,    ops0(),                     Op1(0x6C),              .ZO,   .RM8,      .{_186} ),
    instr(.INSW,    ops0(),                     Op1(0x6D),              .ZO16, .RM32,     .{_186} ),
    instr(.INSD,    ops0(),                     Op1(0x6D),              .ZO32, .RM32,     .{_386} ),
// INT
    instr(.INT3,    ops0(),                     Op1(0xCC),              .ZO, .ZO,         .{} ),
    instr(.INT,     ops1(.imm8),                Op1(0xCD),              .I,  .RM8,        .{} ),
    instr(.INTO,    ops0(),                     Op1(0xCE),              .ZO, .ZO32Only,   .{} ),
    instr(.INT1,    ops0(),                     Op1(0xF1),              .ZO, .ZO,         .{} ),
// IRET
    instr(.IRET,    ops1(._void),               Op1(0xCF),              .ZO,   .RM32,     .{} ),
    instr(.IRET,    ops0(),                     Op1(0xCF),              .ZO16, .RM32,     .{} ),
    instr(.IRETD,   ops0(),                     Op1(0xCF),              .ZO32, .RM32,     .{_386} ),
    instr(.IRETQ,   ops0(),                     Op1(0xCF),              .ZO64, .RM32,     .{x86_64} ),
// Jcc
    instr(.JCXZ,    ops1(.imm8),                Op1(0xE3),              .I, .RM8_Over16,  .{edge.Sign, No64} ),
    instr(.JECXZ,   ops1(.imm8),                Op1(0xE3),              .I, .RM8_Over32,  .{edge.Sign, _386} ),
    instr(.JRCXZ,   ops1(.imm8),                Op1(0xE3),              .I, .RM8,         .{edge.Sign, No32, x86_64} ),
    //
    instr(.JA,      ops1(.imm8),                Op1(0x77),              .I, .RM8,         .{edge.Sign} ),
    instr(.JA,      ops1(.imm16),               Op2(0x0F, 0x87),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JA,      ops1(.imm32),               Op2(0x0F, 0x87),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JAE,     ops1(.imm8),                Op1(0x73),              .I, .RM8,         .{edge.Sign} ),
    instr(.JAE,     ops1(.imm16),               Op2(0x0F, 0x83),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JAE,     ops1(.imm32),               Op2(0x0F, 0x83),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JB,      ops1(.imm8),                Op1(0x72),              .I, .RM8,         .{edge.Sign} ),
    instr(.JB,      ops1(.imm16),               Op2(0x0F, 0x82),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JB,      ops1(.imm32),               Op2(0x0F, 0x82),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JBE,     ops1(.imm8),                Op1(0x76),              .I, .RM8,         .{edge.Sign} ),
    instr(.JBE,     ops1(.imm16),               Op2(0x0F, 0x86),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JBE,     ops1(.imm32),               Op2(0x0F, 0x86),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JC,      ops1(.imm8),                Op1(0x72),              .I, .RM8,         .{edge.Sign} ),
    instr(.JC,      ops1(.imm16),               Op2(0x0F, 0x82),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JC,      ops1(.imm32),               Op2(0x0F, 0x82),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JE,      ops1(.imm8),                Op1(0x74),              .I, .RM8,         .{edge.Sign} ),
    instr(.JE,      ops1(.imm16),               Op2(0x0F, 0x84),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JE,      ops1(.imm32),               Op2(0x0F, 0x84),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JG,      ops1(.imm8),                Op1(0x7F),              .I, .RM8,         .{edge.Sign} ),
    instr(.JG,      ops1(.imm16),               Op2(0x0F, 0x8F),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JG,      ops1(.imm32),               Op2(0x0F, 0x8F),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JGE,     ops1(.imm8),                Op1(0x7D),              .I, .RM8,         .{edge.Sign} ),
    instr(.JGE,     ops1(.imm16),               Op2(0x0F, 0x8D),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JGE,     ops1(.imm32),               Op2(0x0F, 0x8D),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JL,      ops1(.imm8),                Op1(0x7C),              .I, .RM8,         .{edge.Sign} ),
    instr(.JL,      ops1(.imm16),               Op2(0x0F, 0x8C),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JL,      ops1(.imm32),               Op2(0x0F, 0x8C),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JLE,     ops1(.imm8),                Op1(0x7E),              .I, .RM8,         .{edge.Sign} ),
    instr(.JLE,     ops1(.imm16),               Op2(0x0F, 0x8E),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JLE,     ops1(.imm32),               Op2(0x0F, 0x8E),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNA,     ops1(.imm8),                Op1(0x76),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNA,     ops1(.imm16),               Op2(0x0F, 0x86),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNA,     ops1(.imm32),               Op2(0x0F, 0x86),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNAE,    ops1(.imm8),                Op1(0x72),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNAE,    ops1(.imm16),               Op2(0x0F, 0x82),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNAE,    ops1(.imm32),               Op2(0x0F, 0x82),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNB,     ops1(.imm8),                Op1(0x73),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNB,     ops1(.imm16),               Op2(0x0F, 0x83),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNB,     ops1(.imm32),               Op2(0x0F, 0x83),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNBE,    ops1(.imm8),                Op1(0x77),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNBE,    ops1(.imm16),               Op2(0x0F, 0x87),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNBE,    ops1(.imm32),               Op2(0x0F, 0x87),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNC,     ops1(.imm8),                Op1(0x73),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNC,     ops1(.imm16),               Op2(0x0F, 0x83),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNC,     ops1(.imm32),               Op2(0x0F, 0x83),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNE,     ops1(.imm8),                Op1(0x75),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNE,     ops1(.imm16),               Op2(0x0F, 0x85),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNE,     ops1(.imm32),               Op2(0x0F, 0x85),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNG,     ops1(.imm8),                Op1(0x7E),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNG,     ops1(.imm16),               Op2(0x0F, 0x8E),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNG,     ops1(.imm32),               Op2(0x0F, 0x8E),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNGE,    ops1(.imm8),                Op1(0x7C),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNGE,    ops1(.imm16),               Op2(0x0F, 0x8C),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNGE,    ops1(.imm32),               Op2(0x0F, 0x8C),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNL,     ops1(.imm8),                Op1(0x7D),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNL,     ops1(.imm16),               Op2(0x0F, 0x8D),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNL,     ops1(.imm32),               Op2(0x0F, 0x8D),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNLE,    ops1(.imm8),                Op1(0x7F),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNLE,    ops1(.imm16),               Op2(0x0F, 0x8F),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNLE,    ops1(.imm32),               Op2(0x0F, 0x8F),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNO,     ops1(.imm8),                Op1(0x71),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNO,     ops1(.imm16),               Op2(0x0F, 0x81),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNO,     ops1(.imm32),               Op2(0x0F, 0x81),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNP,     ops1(.imm8),                Op1(0x7B),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNP,     ops1(.imm16),               Op2(0x0F, 0x8B),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNP,     ops1(.imm32),               Op2(0x0F, 0x8B),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNS,     ops1(.imm8),                Op1(0x79),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNS,     ops1(.imm16),               Op2(0x0F, 0x89),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNS,     ops1(.imm32),               Op2(0x0F, 0x89),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNZ,     ops1(.imm8),                Op1(0x75),              .I, .RM8,         .{edge.Sign} ),
    instr(.JNZ,     ops1(.imm16),               Op2(0x0F, 0x85),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JNZ,     ops1(.imm32),               Op2(0x0F, 0x85),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JO,      ops1(.imm8),                Op1(0x70),              .I, .RM8,         .{edge.Sign} ),
    instr(.JO,      ops1(.imm16),               Op2(0x0F, 0x80),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JO,      ops1(.imm32),               Op2(0x0F, 0x80),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JP,      ops1(.imm8),                Op1(0x7A),              .I, .RM8,         .{edge.Sign} ),
    instr(.JP,      ops1(.imm16),               Op2(0x0F, 0x8A),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JP,      ops1(.imm32),               Op2(0x0F, 0x8A),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JPE,     ops1(.imm8),                Op1(0x7A),              .I, .RM8,         .{edge.Sign} ),
    instr(.JPE,     ops1(.imm16),               Op2(0x0F, 0x8A),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JPE,     ops1(.imm32),               Op2(0x0F, 0x8A),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JPO,     ops1(.imm8),                Op1(0x7B),              .I, .RM8,         .{edge.Sign} ),
    instr(.JPO,     ops1(.imm16),               Op2(0x0F, 0x8B),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JPO,     ops1(.imm32),               Op2(0x0F, 0x8B),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JS,      ops1(.imm8),                Op1(0x78),              .I, .RM8,         .{edge.Sign} ),
    instr(.JS,      ops1(.imm16),               Op2(0x0F, 0x88),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JS,      ops1(.imm32),               Op2(0x0F, 0x88),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JZ,      ops1(.imm8),                Op1(0x74),              .I, .RM8,         .{edge.Sign} ),
    instr(.JZ,      ops1(.imm16),               Op2(0x0F, 0x84),        .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JZ,      ops1(.imm32),               Op2(0x0F, 0x84),        .I, .RM32Strict,  .{edge.Sign} ),
// JMP
    instr(.JMP,     ops1(.imm8),                Op1(0xEB),              .I, .RM8,         .{edge.Sign} ),
    instr(.JMP,     ops1(.imm16),               Op1(0xE9),              .I, .RM32Strict,  .{edge.Sign} ),
    instr(.JMP,     ops1(.imm32),               Op1(0xE9),              .I, .RM32Strict,  .{edge.Sign} ),
    //
    instr(.JMP,     ops1(.rm16),                Op1r(0xFF, 4),          .M, .RM64Strict,  .{} ),
    instr(.JMP,     ops1(.rm32),                Op1r(0xFF, 4),          .M, .RM64Strict,  .{} ),
    instr(.JMP,     ops1(.rm64),                Op1r(0xFF, 4),          .M, .RM64Strict,  .{} ),
    //
    instr(.JMP,     ops1(.ptr16_16),            Op1r(0xEA, 4),          .D, .RM32Only,    .{} ),
    instr(.JMP,     ops1(.ptr16_32),            Op1r(0xEA, 4),          .D, .RM32Only,    .{} ),
    //
    instr(.JMP,     ops1(.m16_16),              Op1r(0xFF, 5),          .M, .RM32,        .{} ),
    instr(.JMP,     ops1(.m16_32),              Op1r(0xFF, 5),          .M, .RM32,        .{} ),
    instr(.JMP,     ops1(.m16_64),              Op1r(0xFF, 5),          .M, .RM32,        .{} ),
// LAHF
    instr(.LAHF,    ops0(),                     Op1(0x9F),              .ZO, .ZO,         .{cpu.FeatLAHF} ),
//  LDS / LSS / LES / LFS / LGS
    instr(.LDS,     ops2(.reg16, .m16_16),      Op1(0xC5),              .RM, .RM32Only,   .{No64} ),
    instr(.LDS,     ops2(.reg32, .m16_32),      Op1(0xC5),              .RM, .RM32Only,   .{No64} ),
    //
    instr(.LSS,     ops2(.reg16, .m16_16),      Op2(0x0F, 0xB2),        .RM, .RM32,       .{_386} ),
    instr(.LSS,     ops2(.reg32, .m16_32),      Op2(0x0F, 0xB2),        .RM, .RM32,       .{_386} ),
    instr(.LSS,     ops2(.reg64, .m16_64),      Op2(0x0F, 0xB2),        .RM, .RM32,       .{x86_64} ),
    //
    instr(.LES,     ops2(.reg16, .m16_16),      Op1(0xC4),              .RM, .RM32Only,   .{No64} ),
    instr(.LES,     ops2(.reg32, .m16_32),      Op1(0xC4),              .RM, .RM32Only,   .{No64} ),
    //
    instr(.LFS,     ops2(.reg16, .m16_16),      Op2(0x0F, 0xB4),        .RM, .RM32,       .{_386} ),
    instr(.LFS,     ops2(.reg32, .m16_32),      Op2(0x0F, 0xB4),        .RM, .RM32,       .{_386} ),
    instr(.LFS,     ops2(.reg64, .m16_64),      Op2(0x0F, 0xB4),        .RM, .RM32,       .{x86_64} ),
    //
    instr(.LGS,     ops2(.reg16, .m16_16),      Op2(0x0F, 0xB5),        .RM, .RM32,       .{_386} ),
    instr(.LGS,     ops2(.reg32, .m16_32),      Op2(0x0F, 0xB5),        .RM, .RM32,       .{_386} ),
    instr(.LGS,     ops2(.reg64, .m16_64),      Op2(0x0F, 0xB5),        .RM, .RM32,       .{x86_64} ),
    //
// LEA
    instr(.LEA,     ops2(.reg16, .rm_mem16),    Op1(0x8D),              .RM, .RM32,       .{} ),
    instr(.LEA,     ops2(.reg32, .rm_mem32),    Op1(0x8D),              .RM, .RM32,       .{} ),
    instr(.LEA,     ops2(.reg64, .rm_mem64),    Op1(0x8D),              .RM, .RM32,       .{} ),
// LEAVE
    instr(.LEAVE,   ops0(),                     Op1(0xC9),              .ZODef, .RM64_16, .{_186} ),
    instr(.LEAVEW,  ops0(),                     Op1(0xC9),              .ZO16,  .RM64_16, .{_186} ),
    instr(.LEAVED,  ops0(),                     Op1(0xC9),              .ZO32,  .RM64_16, .{No64, _186} ),
// LOCK
    instr(.LOCK,    ops0(),                     Op1(0xF0),              .ZO, .ZO,         .{} ),
// LODS / LODSB / LODSW / LODSD / LODSQ
    instr(.LODS,    ops1(._void8),              Op1(0xAC),              .ZO, .RM8,        .{} ),
    instr(.LODS,    ops1(._void),               Op1(0xAD),              .ZO, .RM32,       .{} ),
    //
    instr(.LODSB,   ops0(),                     Op1(0xAC),              .ZO,   .RM8,      .{} ),
    instr(.LODSW,   ops0(),                     Op1(0xAD),              .ZO16, .RM32,     .{} ),
    instr(.LODSD,   ops0(),                     Op1(0xAD),              .ZO32, .RM32,     .{_386} ),
    instr(.LODSQ,   ops0(),                     Op1(0xAD),              .ZO64, .RM32,     .{x86_64} ),
// LOOP
    instr(.LOOP,    ops1(.imm8),                Op1(0xE2),              .I, .RM8,         .{edge.Sign} ),
    instr(.LOOPE,   ops1(.imm8),                Op1(0xE1),              .I, .RM8,         .{edge.Sign} ),
    instr(.LOOPNE,  ops1(.imm8),                Op1(0xE0),              .I, .RM8,         .{edge.Sign} ),
    //
    instr(.LOOPW,   ops1(.imm8),                Op1(0xE2),              .I, .RM8_Over16,  .{edge.Sign, No64, _386} ),
    instr(.LOOPEW,  ops1(.imm8),                Op1(0xE1),              .I, .RM8_Over16,  .{edge.Sign, No64, _386} ),
    instr(.LOOPNEW, ops1(.imm8),                Op1(0xE0),              .I, .RM8_Over16,  .{edge.Sign, No64, _386} ),
    //
    instr(.LOOPD,   ops1(.imm8),                Op1(0xE2),              .I, .RM8_Over32,  .{edge.Sign, _386} ),
    instr(.LOOPED,  ops1(.imm8),                Op1(0xE1),              .I, .RM8_Over32,  .{edge.Sign, _386} ),
    instr(.LOOPNED, ops1(.imm8),                Op1(0xE0),              .I, .RM8_Over32,  .{edge.Sign, _386} ),
// MOV
    instr(.MOV,     ops2(.rm8,  .reg8),         Op1(0x88),              .MR, .RM8,        .{} ),
    instr(.MOV,     ops2(.rm16, .reg16),        Op1(0x89),              .MR, .RM32,       .{} ),
    instr(.MOV,     ops2(.rm32, .reg32),        Op1(0x89),              .MR, .RM32,       .{} ),
    instr(.MOV,     ops2(.rm64, .reg64),        Op1(0x89),              .MR, .RM32,       .{} ),
    //
    instr(.MOV,     ops2(.reg8,  .rm8),         Op1(0x8A),              .RM, .RM8,        .{} ),
    instr(.MOV,     ops2(.reg16, .rm16),        Op1(0x8B),              .RM, .RM32,       .{} ),
    instr(.MOV,     ops2(.reg32, .rm32),        Op1(0x8B),              .RM, .RM32,       .{} ),
    instr(.MOV,     ops2(.reg64, .rm64),        Op1(0x8B),              .RM, .RM32,       .{} ),
    //
    instr(.MOV,     ops2(.rm16, .reg_seg),      Op1(0x8C),              .MR, .RM32_RM,    .{} ),
    instr(.MOV,     ops2(.rm32, .reg_seg),      Op1(0x8C),              .MR, .RM32_RM,    .{} ),
    instr(.MOV,     ops2(.rm64, .reg_seg),      Op1(0x8C),              .MR, .RM32_RM,    .{} ),
    //
    instr(.MOV,     ops2(.reg_seg, .rm16),      Op1(0x8E),              .RM, .RM32_RM,    .{} ),
    instr(.MOV,     ops2(.reg_seg, .rm32),      Op1(0x8E),              .RM, .RM32_RM,    .{} ),
    instr(.MOV,     ops2(.reg_seg, .rm64),      Op1(0x8E),              .RM, .RM32_RM,    .{} ),
    // TODO: CHECK, not 100% sure how moffs is supposed to behave in all cases
    instr(.MOV,     ops2(.reg_al, .moffs8),     Op1(0xA0),              .FD, .RM8,        .{} ),
    instr(.MOV,     ops2(.reg_ax, .moffs16),    Op1(0xA1),              .FD, .RM32,       .{} ),
    instr(.MOV,     ops2(.reg_eax, .moffs32),   Op1(0xA1),              .FD, .RM32,       .{} ),
    instr(.MOV,     ops2(.reg_rax, .moffs64),   Op1(0xA1),              .FD, .RM32,       .{} ),
    instr(.MOV,     ops2(.moffs8, .reg_al),     Op1(0xA2),              .TD, .RM8,        .{} ),
    instr(.MOV,     ops2(.moffs16, .reg_ax),    Op1(0xA3),              .TD, .RM32,       .{} ),
    instr(.MOV,     ops2(.moffs32, .reg_eax),   Op1(0xA3),              .TD, .RM32,       .{} ),
    instr(.MOV,     ops2(.moffs64, .reg_rax),   Op1(0xA3),              .TD, .RM32,       .{} ),
    //
    instr(.MOV,     ops2(.reg8, .imm8),         Op1(0xB0),              .OI, .RM8,        .{} ),
    instr(.MOV,     ops2(.reg16, .imm16),       Op1(0xB8),              .OI, .RM32,       .{} ),
    instr(.MOV,     ops2(.reg32, .imm32),       Op1(0xB8),              .OI, .RM32,       .{} ),
    instr(.MOV,     ops2(.reg64, .imm32),       Op1(0xB8),              .OI, .RM64,       .{edge.NoSign} ),
    instr(.MOV,     ops2(.reg64, .imm64),       Op1(0xB8),              .OI, .RM32,       .{} ),
    //
    instr(.MOV,     ops2(.rm8, .imm8),          Op1r(0xC6, 0),          .MI, .RM8,        .{} ),
    instr(.MOV,     ops2(.rm16, .imm16),        Op1r(0xC7, 0),          .MI, .RM32,       .{} ),
    instr(.MOV,     ops2(.rm32, .imm32),        Op1r(0xC7, 0),          .MI, .RM32,       .{} ),
    instr(.MOV,     ops2(.rm64, .imm32),        Op1r(0xC7, 0),          .MI, .RM32,       .{} ),
    // 386 MOV to/from Control Registers
    instr(.MOV,     ops2(.reg32, .reg_cr),      Op2(0x0F, 0x20),        .MR, .RM32_RM,    .{No64, _386} ),
    instr(.MOV,     ops2(.reg64, .reg_cr),      Op2(0x0F, 0x20),        .MR, .RM64_RM,    .{No32, x86_64} ),
    //
    instr(.MOV,     ops2(.reg_cr, .reg32),      Op2(0x0F, 0x22),        .RM, .RM32_RM,    .{No64, _386} ),
    instr(.MOV,     ops2(.reg_cr, .reg64),      Op2(0x0F, 0x22),        .RM, .RM64_RM,    .{No32, x86_64} ),
    // 386 MOV to/from Debug Registers
    instr(.MOV,     ops2(.reg32, .reg_dr),      Op2(0x0F, 0x21),        .MR, .RM32_RM,    .{No64, _386} ),
    instr(.MOV,     ops2(.reg64, .reg_dr),      Op2(0x0F, 0x21),        .MR, .RM64_RM,    .{No32, x86_64} ),
    //
    instr(.MOV,     ops2(.reg_dr, .reg32),      Op2(0x0F, 0x23),        .RM, .RM32_RM,       .{No64, _386} ),
    instr(.MOV,     ops2(.reg_dr, .reg64),      Op2(0x0F, 0x23),        .RM, .RM64_RM,       .{No32, x86_64} ),
// MOVS / MOVSB / MOVSW / MOVSD / MOVSQ
    instr(.MOVS,    ops1(._void8),              Op1(0xA4),              .ZO, .RM8,        .{} ),
    instr(.MOVS,    ops1(._void),               Op1(0xA5),              .ZO, .RM32,       .{} ),
    //
    instr(.MOVSB,   ops0(),                     Op1(0xA4),              .ZO,   .RM8,      .{} ),
    instr(.MOVSW,   ops0(),                     Op1(0xA5),              .ZO16, .RM32,     .{} ),
    instr(.MOVSD,   ops0(),                     Op1(0xA5),              .ZO32, .RM32,     .{_386} ),
    instr(.MOVSQ,   ops0(),                     Op1(0xA5),              .ZO64, .RM32,     .{x86_64} ),
// MUL
    instr(.MUL,     ops1(.rm8),                 Op1r(0xF6, 4),          .M,  .RM8,        .{} ),
    instr(.MUL,     ops1(.rm16),                Op1r(0xF7, 4),          .M,  .RM32,       .{} ),
    instr(.MUL,     ops1(.rm32),                Op1r(0xF7, 4),          .M,  .RM32,       .{} ),
    instr(.MUL,     ops1(.rm64),                Op1r(0xF7, 4),          .M,  .RM32,       .{} ),
// NEG
    instr(.NEG,     ops1(.rm8),                 Op1r(0xF6, 3),          .M,  .RM8,        .{} ),
    instr(.NEG,     ops1(.rm16),                Op1r(0xF7, 3),          .M,  .RM32,       .{} ),
    instr(.NEG,     ops1(.rm32),                Op1r(0xF7, 3),          .M,  .RM32,       .{} ),
    instr(.NEG,     ops1(.rm64),                Op1r(0xF7, 3),          .M,  .RM32,       .{} ),
// NOP
    instr(.NOP,     ops0(),                     Op1(0x90),              .ZO, .ZO,         .{} ),
    instr(.NOP,     ops1(.rm16),                Op2r(0x0F, 0x1F, 0),    .M,  .RM32,       .{cpu.P6} ),
    instr(.NOP,     ops1(.rm32),                Op2r(0x0F, 0x1F, 0),    .M,  .RM32,       .{cpu.P6} ),
    instr(.NOP,     ops1(.rm64),                Op2r(0x0F, 0x1F, 0),    .M,  .RM32,       .{cpu.P6} ),
// NOT
    instr(.NOT,     ops1(.rm8),                 Op1r(0xF6, 2),          .M,  .RM8,        .{} ),
    instr(.NOT,     ops1(.rm16),                Op1r(0xF7, 2),          .M,  .RM32,       .{} ),
    instr(.NOT,     ops1(.rm32),                Op1r(0xF7, 2),          .M,  .RM32,       .{} ),
    instr(.NOT,     ops1(.rm64),                Op1r(0xF7, 2),          .M,  .RM32,       .{} ),
// OR
    instr(.OR,      ops2(.reg_al, .imm8),       Op1(0x0C),              .I2, .RM8,        .{} ),
    instr(.OR,      ops2(.rm8, .imm8),          Op1r(0x80, 1),          .MI, .RM8,        .{} ),
    instr(.OR,      ops2(.rm16, .imm8),         Op1r(0x83, 1),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.OR,      ops2(.rm32, .imm8),         Op1r(0x83, 1),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.OR,      ops2(.rm64, .imm8),         Op1r(0x83, 1),          .MI, .RM32_I8,    .{edge.Sign} ),
    //
    instr(.OR,      ops2(.reg_ax, .imm16),      Op1(0x0D),              .I2, .RM32,       .{} ),
    instr(.OR,      ops2(.reg_eax, .imm32),     Op1(0x0D),              .I2, .RM32,       .{} ),
    instr(.OR,      ops2(.reg_rax, .imm32),     Op1(0x0D),              .I2, .RM32,       .{edge.Sign} ),
    //
    instr(.OR,      ops2(.rm16, .imm16),        Op1r(0x81, 1),          .MI, .RM32,       .{} ),
    instr(.OR,      ops2(.rm32, .imm32),        Op1r(0x81, 1),          .MI, .RM32,       .{} ),
    instr(.OR,      ops2(.rm64, .imm32),        Op1r(0x81, 1),          .MI, .RM32,       .{edge.Sign} ),
    //
    instr(.OR,      ops2(.rm8, .reg8),          Op1(0x08),              .MR, .RM8,        .{} ),
    instr(.OR,      ops2(.rm16, .reg16),        Op1(0x09),              .MR, .RM32,       .{} ),
    instr(.OR,      ops2(.rm32, .reg32),        Op1(0x09),              .MR, .RM32,       .{} ),
    instr(.OR,      ops2(.rm64, .reg64),        Op1(0x09),              .MR, .RM32,       .{} ),
    //
    instr(.OR,      ops2(.reg8, .rm8),          Op1(0x0A),              .RM, .RM8,        .{} ),
    instr(.OR,      ops2(.reg16, .rm16),        Op1(0x0B),              .RM, .RM32,       .{} ),
    instr(.OR,      ops2(.reg32, .rm32),        Op1(0x0B),              .RM, .RM32,       .{} ),
    instr(.OR,      ops2(.reg64, .rm64),        Op1(0x0B),              .RM, .RM32,       .{} ),
// OUT
    instr(.OUT,     ops2(.imm8, .reg_al),       Op1(0xE6),              .I, .ZO,          .{} ),
    instr(.OUT,     ops2(.imm8, .reg_ax),       Op1(0xE7),              .I, .RM32,        .{} ),
    instr(.OUT,     ops2(.imm8, .reg_eax),      Op1(0xE7),              .I, .RM32,        .{} ),
    instr(.OUT,     ops2(.reg_dx, .reg_al),     Op1(0xEE),              .ZO, .ZO,         .{} ),
    instr(.OUT,     ops2(.reg_dx, .reg_ax),     Op1(0xEF),              .ZO16, .RM32,     .{} ),
    instr(.OUT,     ops2(.reg_dx, .reg_eax),    Op1(0xEF),              .ZO32, .RM32,     .{} ),
// OUTS / OUTSB / OUTSW / OUTSD
    instr(.OUTS,    ops1(._void8),              Op1(0x6E),              .ZO, .RM8,        .{_186} ),
    instr(.OUTS,    ops1(._void),               Op1(0x6F),              .ZO, .RM32,       .{_186} ),
    //
    instr(.OUTSB,   ops0(),                     Op1(0x6E),              .ZO,   .RM8,      .{_186} ),
    instr(.OUTSW,   ops0(),                     Op1(0x6F),              .ZO16, .RM32,     .{_186} ),
    instr(.OUTSD,   ops0(),                     Op1(0x6F),              .ZO32, .RM32,     .{_386} ),
// POP
    instr(.POP,     ops1(.reg16),               Op1(0x58),              .O,  .RM64_16,    .{} ),
    instr(.POP,     ops1(.reg32),               Op1(0x58),              .O,  .RM64_16,    .{} ),
    instr(.POP,     ops1(.reg64),               Op1(0x58),              .O,  .RM64_16,    .{} ),
    //
    instr(.POP,     ops1(.rm16),                Op1r(0x8F, 0),          .M,  .RM64_16,    .{} ),
    instr(.POP,     ops1(.rm32),                Op1r(0x8F, 0),          .M,  .RM64_16,    .{} ),
    instr(.POP,     ops1(.rm64),                Op1r(0x8F, 0),          .M,  .RM64_16,    .{} ),
    //
    instr(.POP,     ops1(.reg_ds),              Op1(0x1F),              .ZODef, .ZO32Only,.{} ),
    instr(.POP,     ops1(.reg_es),              Op1(0x07),              .ZODef, .ZO32Only,.{} ),
    instr(.POP,     ops1(.reg_ss),              Op1(0x17),              .ZODef, .ZO32Only,.{} ),
    instr(.POP,     ops1(.reg_fs),              Op2(0x0F, 0xA1),        .ZO, .ZO,         .{} ),
    instr(.POP,     ops1(.reg_gs),              Op2(0x0F, 0xA9),        .ZO, .ZO,         .{} ),
    //
    instr(.POPW,    ops1(.reg_ds),              Op1(0x1F),              .ZO16, .ZO32Only, .{} ),
    instr(.POPW,    ops1(.reg_es),              Op1(0x07),              .ZO16, .ZO32Only, .{} ),
    instr(.POPW,    ops1(.reg_ss),              Op1(0x17),              .ZO16, .ZO32Only, .{} ),
    instr(.POPW,    ops1(.reg_fs),              Op2(0x0F, 0xA1),        .ZO16, .ZO64_16,  .{} ),
    instr(.POPW,    ops1(.reg_gs),              Op2(0x0F, 0xA9),        .ZO16, .ZO64_16,  .{} ),
    //
    instr(.POPD,    ops1(.reg_ds),              Op1(0x1F),              .ZO32, .ZO32Only, .{No64} ),
    instr(.POPD,    ops1(.reg_es),              Op1(0x07),              .ZO32, .ZO32Only, .{No64} ),
    instr(.POPD,    ops1(.reg_ss),              Op1(0x17),              .ZO32, .ZO32Only, .{No64} ),
    instr(.POPD,    ops1(.reg_fs),              Op2(0x0F, 0xA1),        .ZO32, .ZO64_16,  .{No64} ),
    instr(.POPD,    ops1(.reg_gs),              Op2(0x0F, 0xA9),        .ZO32, .ZO64_16,  .{No64} ),
    //
    instr(.POPQ,    ops1(.reg_ds),              Op1(0x1F),              .ZO64, .ZO32Only, .{No32} ),
    instr(.POPQ,    ops1(.reg_es),              Op1(0x07),              .ZO64, .ZO32Only, .{No32} ),
    instr(.POPQ,    ops1(.reg_ss),              Op1(0x17),              .ZO64, .ZO32Only, .{No32} ),
    instr(.POPQ,    ops1(.reg_fs),              Op2(0x0F, 0xA1),        .ZO64, .ZO64_16,  .{No32} ),
    instr(.POPQ,    ops1(.reg_gs),              Op2(0x0F, 0xA9),        .ZO64, .ZO64_16,  .{No32} ),
// POPA
    instr(.POPA,    ops0(),                     Op1(0x60),              .ZODef, .RM32,    .{No64, _186} ),
    instr(.POPAW,   ops0(),                     Op1(0x60),              .ZO16,  .RM32,    .{No64, _186} ),
    instr(.POPAD,   ops0(),                     Op1(0x60),              .ZO32,  .RM32,    .{No64, _386} ),
// POPF / POPFD / POPFQ
    instr(.POPF,    ops1(._void),               Op1(0x9D),              .ZO, .RM64_16,    .{} ),
    //
    instr(.POPF,    ops0(),                     Op1(0x9D),              .ZODef, .RM64_16, .{} ),
    instr(.POPFW,   ops0(),                     Op1(0x9D),              .ZO16,  .RM64_16, .{} ),
    instr(.POPFD,   ops0(),                     Op1(0x9D),              .ZO32,  .RM32Only,.{_386} ),
    instr(.POPFQ,   ops0(),                     Op1(0x9D),              .ZO64,  .RM64_16, .{x86_64} ),
// PUSH
    instr(.PUSH,    ops1(.imm8),                Op1(0x6A),              .I,  .RM8 ,       .{_186} ),
    instr(.PUSH,    ops1(.imm16),               Op1(0x68),              .I,  .RM32,       .{_186} ),
    instr(.PUSH,    ops1(.imm32),               Op1(0x68),              .I,  .RM32,       .{_386} ),
    //
    instr(.PUSH,    ops1(.reg16),               Op1(0x50),              .O,  .RM64_16,    .{} ),
    instr(.PUSH,    ops1(.reg32),               Op1(0x50),              .O,  .RM64_16,    .{} ),
    instr(.PUSH,    ops1(.reg64),               Op1(0x50),              .O,  .RM64_16,    .{} ),
    //
    instr(.PUSH,    ops1(.rm16),                Op1r(0xFF, 6),          .M,  .RM64_16,    .{} ),
    instr(.PUSH,    ops1(.rm32),                Op1r(0xFF, 6),          .M,  .RM64_16,    .{} ),
    instr(.PUSH,    ops1(.rm64),                Op1r(0xFF, 6),          .M,  .RM64_16,    .{} ),
    //
    instr(.PUSH,    ops1(.reg_cs),              Op1(0x0E),              .ZODef, .ZO32Only,.{} ),
    instr(.PUSH,    ops1(.reg_ss),              Op1(0x16),              .ZODef, .ZO32Only,.{} ),
    instr(.PUSH,    ops1(.reg_ds),              Op1(0x1E),              .ZODef, .ZO32Only,.{} ),
    instr(.PUSH,    ops1(.reg_es),              Op1(0x06),              .ZODef, .ZO32Only,.{} ),
    instr(.PUSH,    ops1(.reg_fs),              Op2(0x0F, 0xA0),        .ZO, .ZO,         .{} ),
    instr(.PUSH,    ops1(.reg_gs),              Op2(0x0F, 0xA8),        .ZO, .ZO,         .{} ),
    //
    instr(.PUSHW,   ops1(.reg_cs),              Op1(0x0E),              .ZO16, .ZO32Only, .{} ),
    instr(.PUSHW,   ops1(.reg_ss),              Op1(0x16),              .ZO16, .ZO32Only, .{} ),
    instr(.PUSHW,   ops1(.reg_ds),              Op1(0x1E),              .ZO16, .ZO32Only, .{} ),
    instr(.PUSHW,   ops1(.reg_es),              Op1(0x06),              .ZO16, .ZO32Only, .{} ),
    instr(.PUSHW,   ops1(.reg_fs),              Op2(0x0F, 0xA0),        .ZO16, .ZO64_16,  .{} ),
    instr(.PUSHW,   ops1(.reg_gs),              Op2(0x0F, 0xA8),        .ZO16, .ZO64_16,  .{} ),
    //
    instr(.PUSHD,   ops1(.reg_cs),              Op1(0x0E),              .ZO32, .ZO32Only, .{No64} ),
    instr(.PUSHD,   ops1(.reg_ss),              Op1(0x16),              .ZO32, .ZO32Only, .{No64} ),
    instr(.PUSHD,   ops1(.reg_ds),              Op1(0x1E),              .ZO32, .ZO32Only, .{No64} ),
    instr(.PUSHD,   ops1(.reg_es),              Op1(0x06),              .ZO32, .ZO32Only, .{No64} ),
    instr(.PUSHD,   ops1(.reg_fs),              Op2(0x0F, 0xA0),        .ZO32, .ZO64_16,  .{No64} ),
    instr(.PUSHD,   ops1(.reg_gs),              Op2(0x0F, 0xA8),        .ZO32, .ZO64_16,  .{No64} ),
    //
    instr(.PUSHQ,   ops1(.reg_cs),              Op1(0x0E),              .ZO64, .ZO32Only, .{No32} ),
    instr(.PUSHQ,   ops1(.reg_ss),              Op1(0x16),              .ZO64, .ZO32Only, .{No32} ),
    instr(.PUSHQ,   ops1(.reg_ds),              Op1(0x1E),              .ZO64, .ZO32Only, .{No32} ),
    instr(.PUSHQ,   ops1(.reg_es),              Op1(0x06),              .ZO64, .ZO32Only, .{No32} ),
    instr(.PUSHQ,   ops1(.reg_fs),              Op2(0x0F, 0xA0),        .ZO64, .ZO64_16,  .{No32} ),
    instr(.PUSHQ,   ops1(.reg_gs),              Op2(0x0F, 0xA8),        .ZO64, .ZO64_16,  .{No32} ),
// PUSHA
    instr(.PUSHA,   ops0(),                     Op1(0x60),              .ZODef, .RM32,    .{No64, _186} ),
    instr(.PUSHAW,  ops0(),                     Op1(0x60),              .ZO16,  .RM32,    .{No64, _186} ),
    instr(.PUSHAD,  ops0(),                     Op1(0x60),              .ZO32,  .RM32,    .{No64, _386} ),
// PUSHF / PUSHFW / PUSHFD / PUSHFQ
    instr(.PUSHF,    ops1(._void),              Op1(0x9C),              .ZO, .RM64_16,    .{} ),
    //
    instr(.PUSHF,    ops0(),                    Op1(0x9C),              .ZODef, .RM64_16, .{} ),
    instr(.PUSHFW,   ops0(),                    Op1(0x9C),              .ZO16,  .RM64_16, .{} ),
    instr(.PUSHFD,   ops0(),                    Op1(0x9C),              .ZODef, .RM32Only,.{_386} ),
    instr(.PUSHFQ,   ops0(),                    Op1(0x9C),              .ZO64,  .RM64_16, .{x86_64} ),
//  RCL / RCR / ROL / ROR
    instr(.RCL,     ops2(.rm8, .imm_1),         Op1r(0xD0, 2),          .M,  .RM8,        .{} ),
    instr(.RCL,     ops2(.rm8, .reg_cl),        Op1r(0xD2, 2),          .M,  .RM8,        .{} ),
    instr(.RCL,     ops2(.rm8,  .imm8),         Op1r(0xC0, 2),          .MI, .RM8,        .{_186} ),
    instr(.RCL,     ops2(.rm16, .imm_1),        Op1r(0xD1, 2),          .M,  .RM32_I8,    .{} ),
    instr(.RCL,     ops2(.rm32, .imm_1),        Op1r(0xD1, 2),          .M,  .RM32_I8,    .{} ),
    instr(.RCL,     ops2(.rm64, .imm_1),        Op1r(0xD1, 2),          .M,  .RM32_I8,    .{} ),
    instr(.RCL,     ops2(.rm16, .imm8),         Op1r(0xC1, 2),          .MI, .RM32_I8,    .{_186} ),
    instr(.RCL,     ops2(.rm32, .imm8),         Op1r(0xC1, 2),          .MI, .RM32_I8,    .{_386} ),
    instr(.RCL,     ops2(.rm64, .imm8),         Op1r(0xC1, 2),          .MI, .RM32_I8,    .{x86_64} ),
    instr(.RCL,     ops2(.rm16, .reg_cl),       Op1r(0xD3, 2),          .M,  .RM32,       .{} ),
    instr(.RCL,     ops2(.rm32, .reg_cl),       Op1r(0xD3, 2),          .M,  .RM32,       .{} ),
    instr(.RCL,     ops2(.rm64, .reg_cl),       Op1r(0xD3, 2),          .M,  .RM32,       .{} ),
    //
    instr(.RCR,     ops2(.rm8, .imm_1),         Op1r(0xD0, 3),          .M,  .RM8,        .{} ),
    instr(.RCR,     ops2(.rm8, .reg_cl),        Op1r(0xD2, 3),          .M,  .RM8,        .{} ),
    instr(.RCR,     ops2(.rm8,  .imm8),         Op1r(0xC0, 3),          .MI, .RM8,        .{_186} ),
    instr(.RCR,     ops2(.rm16, .imm_1),        Op1r(0xD1, 3),          .M,  .RM32_I8,    .{} ),
    instr(.RCR,     ops2(.rm32, .imm_1),        Op1r(0xD1, 3),          .M,  .RM32_I8,    .{} ),
    instr(.RCR,     ops2(.rm64, .imm_1),        Op1r(0xD1, 3),          .M,  .RM32_I8,    .{} ),
    instr(.RCR,     ops2(.rm16, .imm8),         Op1r(0xC1, 3),          .MI, .RM32_I8,    .{_186} ),
    instr(.RCR,     ops2(.rm32, .imm8),         Op1r(0xC1, 3),          .MI, .RM32_I8,    .{_386} ),
    instr(.RCR,     ops2(.rm64, .imm8),         Op1r(0xC1, 3),          .MI, .RM32_I8,    .{x86_64} ),
    instr(.RCR,     ops2(.rm16, .reg_cl),       Op1r(0xD3, 3),          .M,  .RM32,       .{} ),
    instr(.RCR,     ops2(.rm32, .reg_cl),       Op1r(0xD3, 3),          .M,  .RM32,       .{} ),
    instr(.RCR,     ops2(.rm64, .reg_cl),       Op1r(0xD3, 3),          .M,  .RM32,       .{} ),
    //
    instr(.ROL,     ops2(.rm8, .imm_1),         Op1r(0xD0, 0),          .M,  .RM8,        .{} ),
    instr(.ROL,     ops2(.rm8, .reg_cl),        Op1r(0xD2, 0),          .M,  .RM8,        .{} ),
    instr(.ROL,     ops2(.rm8,  .imm8),         Op1r(0xC0, 0),          .MI, .RM8,        .{_186} ),
    instr(.ROL,     ops2(.rm16, .imm_1),        Op1r(0xD1, 0),          .M,  .RM32_I8,    .{} ),
    instr(.ROL,     ops2(.rm32, .imm_1),        Op1r(0xD1, 0),          .M,  .RM32_I8,    .{} ),
    instr(.ROL,     ops2(.rm64, .imm_1),        Op1r(0xD1, 0),          .M,  .RM32_I8,    .{} ),
    instr(.ROL,     ops2(.rm16, .imm8),         Op1r(0xC1, 0),          .MI, .RM32_I8,    .{_186} ),
    instr(.ROL,     ops2(.rm32, .imm8),         Op1r(0xC1, 0),          .MI, .RM32_I8,    .{_386} ),
    instr(.ROL,     ops2(.rm64, .imm8),         Op1r(0xC1, 0),          .MI, .RM32_I8,    .{x86_64} ),
    instr(.ROL,     ops2(.rm16, .reg_cl),       Op1r(0xD3, 0),          .M,  .RM32,       .{} ),
    instr(.ROL,     ops2(.rm32, .reg_cl),       Op1r(0xD3, 0),          .M,  .RM32,       .{} ),
    instr(.ROL,     ops2(.rm64, .reg_cl),       Op1r(0xD3, 0),          .M,  .RM32,       .{} ),
    //
    instr(.ROR,     ops2(.rm8, .imm_1),         Op1r(0xD0, 1),          .M,  .RM8,        .{} ),
    instr(.ROR,     ops2(.rm8, .reg_cl),        Op1r(0xD2, 1),          .M,  .RM8,        .{} ),
    instr(.ROR,     ops2(.rm8,  .imm8),         Op1r(0xC0, 1),          .MI, .RM8,        .{_186} ),
    instr(.ROR,     ops2(.rm16, .imm_1),        Op1r(0xD1, 1),          .M,  .RM32_I8,    .{} ),
    instr(.ROR,     ops2(.rm32, .imm_1),        Op1r(0xD1, 1),          .M,  .RM32_I8,    .{} ),
    instr(.ROR,     ops2(.rm64, .imm_1),        Op1r(0xD1, 1),          .M,  .RM32_I8,    .{} ),
    instr(.ROR,     ops2(.rm16, .imm8),         Op1r(0xC1, 1),          .MI, .RM32_I8,    .{_186} ),
    instr(.ROR,     ops2(.rm32, .imm8),         Op1r(0xC1, 1),          .MI, .RM32_I8,    .{_386} ),
    instr(.ROR,     ops2(.rm64, .imm8),         Op1r(0xC1, 1),          .MI, .RM32_I8,    .{x86_64} ),
    instr(.ROR,     ops2(.rm16, .reg_cl),       Op1r(0xD3, 1),          .M,  .RM32,       .{} ),
    instr(.ROR,     ops2(.rm32, .reg_cl),       Op1r(0xD3, 1),          .M,  .RM32,       .{} ),
    instr(.ROR,     ops2(.rm64, .reg_cl),       Op1r(0xD3, 1),          .M,  .RM32,       .{} ),
// REP / REPE / REPZ / REPNE / REPNZ
    instr(.REP,     ops0(),                     Op1(0xF3),              .ZO, .ZO,         .{} ),
    instr(.REPE,    ops0(),                     Op1(0xF3),              .ZO, .ZO,         .{} ),
    instr(.REPZ,    ops0(),                     Op1(0xF3),              .ZO, .ZO,         .{} ),
    instr(.REPNE,   ops0(),                     Op1(0xF2),              .ZO, .ZO,         .{} ),
    instr(.REPNZ,   ops0(),                     Op1(0xF2),              .ZO, .ZO,         .{} ),
//  RET
    instr(.RET,     ops0(),                     Op1(0xC3),              .ZO, .ZO,         .{} ),
    instr(.RET,     ops1(.imm16),               Op1(0xC2),              .I,  .RM16,       .{} ),
//  RETF
    instr(.RETF,    ops0(),                     Op1(0xCB),              .ZO, .ZO,         .{} ),
    instr(.RETF,    ops1(.imm16),               Op1(0xCA),              .I,  .RM16,       .{} ),
//  RETN
    instr(.RETN,    ops0(),                     Op1(0xC3),              .ZO, .ZO,         .{} ),
    instr(.RETN,    ops1(.imm16),               Op1(0xC2),              .I,  .RM16,       .{} ),
//  SAL / SAR / SHL / SHR
    instr(.SAL,     ops2(.rm8, .imm_1),         Op1r(0xD0, 4),          .M,  .RM8,        .{} ),
    instr(.SAL,     ops2(.rm8, .reg_cl),        Op1r(0xD2, 4),          .M,  .RM8,        .{} ),
    instr(.SAL,     ops2(.rm8,  .imm8),         Op1r(0xC0, 4),          .MI, .RM8,        .{_186} ),
    instr(.SAL,     ops2(.rm16, .imm_1),        Op1r(0xD1, 4),          .M,  .RM32_I8,    .{} ),
    instr(.SAL,     ops2(.rm32, .imm_1),        Op1r(0xD1, 4),          .M,  .RM32_I8,    .{} ),
    instr(.SAL,     ops2(.rm64, .imm_1),        Op1r(0xD1, 4),          .M,  .RM32_I8,    .{} ),
    instr(.SAL,     ops2(.rm16, .imm8),         Op1r(0xC1, 4),          .MI, .RM32_I8,    .{_186} ),
    instr(.SAL,     ops2(.rm32, .imm8),         Op1r(0xC1, 4),          .MI, .RM32_I8,    .{_386} ),
    instr(.SAL,     ops2(.rm64, .imm8),         Op1r(0xC1, 4),          .MI, .RM32_I8,    .{x86_64} ),
    instr(.SAL,     ops2(.rm16, .reg_cl),       Op1r(0xD3, 4),          .M,  .RM32,       .{} ),
    instr(.SAL,     ops2(.rm32, .reg_cl),       Op1r(0xD3, 4),          .M,  .RM32,       .{} ),
    instr(.SAL,     ops2(.rm64, .reg_cl),       Op1r(0xD3, 4),          .M,  .RM32,       .{} ),
    //
    instr(.SAR,     ops2(.rm8, .imm_1),         Op1r(0xD0, 7),          .M,  .RM8,        .{} ),
    instr(.SAR,     ops2(.rm8, .reg_cl),        Op1r(0xD2, 7),          .M,  .RM8,        .{} ),
    instr(.SAR,     ops2(.rm8,  .imm8),         Op1r(0xC0, 7),          .MI, .RM8,        .{_186} ),
    instr(.SAR,     ops2(.rm16, .imm_1),        Op1r(0xD1, 7),          .M,  .RM32_I8,    .{} ),
    instr(.SAR,     ops2(.rm32, .imm_1),        Op1r(0xD1, 7),          .M,  .RM32_I8,    .{} ),
    instr(.SAR,     ops2(.rm64, .imm_1),        Op1r(0xD1, 7),          .M,  .RM32_I8,    .{} ),
    instr(.SAR,     ops2(.rm16, .imm8),         Op1r(0xC1, 7),          .MI, .RM32_I8,    .{_186} ),
    instr(.SAR,     ops2(.rm32, .imm8),         Op1r(0xC1, 7),          .MI, .RM32_I8,    .{_386} ),
    instr(.SAR,     ops2(.rm64, .imm8),         Op1r(0xC1, 7),          .MI, .RM32_I8,    .{x86_64} ),
    instr(.SAR,     ops2(.rm16, .reg_cl),       Op1r(0xD3, 7),          .M,  .RM32,       .{} ),
    instr(.SAR,     ops2(.rm32, .reg_cl),       Op1r(0xD3, 7),          .M,  .RM32,       .{} ),
    instr(.SAR,     ops2(.rm64, .reg_cl),       Op1r(0xD3, 7),          .M,  .RM32,       .{} ),
    //
    instr(.SHL,     ops2(.rm8, .imm_1),         Op1r(0xD0, 4),          .M,  .RM8,        .{} ),
    instr(.SHL,     ops2(.rm8, .reg_cl),        Op1r(0xD2, 4),          .M,  .RM8,        .{} ),
    instr(.SHL,     ops2(.rm8,  .imm8),         Op1r(0xC0, 4),          .MI, .RM8,        .{_186} ),
    instr(.SHL,     ops2(.rm16, .imm_1),        Op1r(0xD1, 4),          .M,  .RM32_I8,    .{} ),
    instr(.SHL,     ops2(.rm32, .imm_1),        Op1r(0xD1, 4),          .M,  .RM32_I8,    .{} ),
    instr(.SHL,     ops2(.rm64, .imm_1),        Op1r(0xD1, 4),          .M,  .RM32_I8,    .{} ),
    instr(.SHL,     ops2(.rm16, .imm8),         Op1r(0xC1, 4),          .MI, .RM32_I8,    .{_186} ),
    instr(.SHL,     ops2(.rm32, .imm8),         Op1r(0xC1, 4),          .MI, .RM32_I8,    .{_386} ),
    instr(.SHL,     ops2(.rm64, .imm8),         Op1r(0xC1, 4),          .MI, .RM32_I8,    .{x86_64} ),
    instr(.SHL,     ops2(.rm16, .reg_cl),       Op1r(0xD3, 4),          .M,  .RM32,       .{} ),
    instr(.SHL,     ops2(.rm32, .reg_cl),       Op1r(0xD3, 4),          .M,  .RM32,       .{} ),
    instr(.SHL,     ops2(.rm64, .reg_cl),       Op1r(0xD3, 4),          .M,  .RM32,       .{} ),
    //
    instr(.SHR,     ops2(.rm8, .imm_1),         Op1r(0xD0, 5),          .M,  .RM8,        .{} ),
    instr(.SHR,     ops2(.rm8, .reg_cl),        Op1r(0xD2, 5),          .M,  .RM8,        .{} ),
    instr(.SHR,     ops2(.rm8,  .imm8),         Op1r(0xC0, 5),          .MI, .RM8,        .{_186} ),
    instr(.SHR,     ops2(.rm16, .imm_1),        Op1r(0xD1, 5),          .M,  .RM32_I8,    .{} ),
    instr(.SHR,     ops2(.rm32, .imm_1),        Op1r(0xD1, 5),          .M,  .RM32_I8,    .{} ),
    instr(.SHR,     ops2(.rm64, .imm_1),        Op1r(0xD1, 5),          .M,  .RM32_I8,    .{} ),
    instr(.SHR,     ops2(.rm16, .imm8),         Op1r(0xC1, 5),          .MI, .RM32_I8,    .{_186} ),
    instr(.SHR,     ops2(.rm32, .imm8),         Op1r(0xC1, 5),          .MI, .RM32_I8,    .{_386} ),
    instr(.SHR,     ops2(.rm64, .imm8),         Op1r(0xC1, 5),          .MI, .RM32_I8,    .{x86_64} ),
    instr(.SHR,     ops2(.rm16, .reg_cl),       Op1r(0xD3, 5),          .M,  .RM32,       .{} ),
    instr(.SHR,     ops2(.rm32, .reg_cl),       Op1r(0xD3, 5),          .M,  .RM32,       .{} ),
    instr(.SHR,     ops2(.rm64, .reg_cl),       Op1r(0xD3, 5),          .M,  .RM32,       .{} ),
// SBB
    instr(.SBB,     ops2(.reg_al, .imm8),       Op1(0x1C),              .I2, .RM8,        .{} ),
    instr(.SBB,     ops2(.rm8, .imm8),          Op1r(0x80, 3),          .MI, .RM8,        .{} ),
    instr(.SBB,     ops2(.rm16, .imm8),         Op1r(0x83, 3),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.SBB,     ops2(.rm32, .imm8),         Op1r(0x83, 3),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.SBB,     ops2(.rm64, .imm8),         Op1r(0x83, 3),          .MI, .RM32_I8,    .{edge.Sign} ),
    //
    instr(.SBB,     ops2(.reg_ax, .imm16),      Op1(0x1D),              .I2, .RM32,       .{} ),
    instr(.SBB,     ops2(.reg_eax, .imm32),     Op1(0x1D),              .I2, .RM32,       .{} ),
    instr(.SBB,     ops2(.reg_rax, .imm32),     Op1(0x1D),              .I2, .RM32,       .{edge.Sign} ),
    //
    instr(.SBB,     ops2(.rm16, .imm16),        Op1r(0x81, 3),          .MI, .RM32,       .{} ),
    instr(.SBB,     ops2(.rm32, .imm32),        Op1r(0x81, 3),          .MI, .RM32,       .{} ),
    instr(.SBB,     ops2(.rm64, .imm32),        Op1r(0x81, 3),          .MI, .RM32,       .{edge.Sign} ),
    //
    instr(.SBB,     ops2(.rm8, .reg8),          Op1(0x18),              .MR, .RM8,        .{} ),
    instr(.SBB,     ops2(.rm16, .reg16),        Op1(0x19),              .MR, .RM32,       .{} ),
    instr(.SBB,     ops2(.rm32, .reg32),        Op1(0x19),              .MR, .RM32,       .{} ),
    instr(.SBB,     ops2(.rm64, .reg64),        Op1(0x19),              .MR, .RM32,       .{} ),
    //
    instr(.SBB,     ops2(.reg8, .rm8),          Op1(0x1A),              .RM, .RM8,        .{} ),
    instr(.SBB,     ops2(.reg16, .rm16),        Op1(0x1B),              .RM, .RM32,       .{} ),
    instr(.SBB,     ops2(.reg32, .rm32),        Op1(0x1B),              .RM, .RM32,       .{} ),
    instr(.SBB,     ops2(.reg64, .rm64),        Op1(0x1B),              .RM, .RM32,       .{} ),
// SCAS / SCASB / SCASW / SCASD / SCASQ
    instr(.SCAS,    ops1(._void8),              Op1(0xAE),              .ZO, .RM8,        .{} ),
    instr(.SCAS,    ops1(._void),               Op1(0xAF),              .ZO, .RM32,       .{} ),
    //
    instr(.SCASB,   ops0(),                     Op1(0xAE),              .ZO,   .RM8,      .{} ),
    instr(.SCASW,   ops0(),                     Op1(0xAF),              .ZO16, .RM32,     .{} ),
    instr(.SCASD,   ops0(),                     Op1(0xAF),              .ZO32, .RM32,     .{_386} ),
    instr(.SCASQ,   ops0(),                     Op1(0xAF),              .ZO64, .RM32,     .{x86_64} ),
// STC
    instr(.STC,     ops0(),                     Op1(0xF9),              .ZO, .ZO,         .{} ),
// STD
    instr(.STD,     ops0(),                     Op1(0xFD),              .ZO, .ZO,         .{} ),
// STI
    instr(.STI,     ops0(),                     Op1(0xFB),              .ZO, .ZO,         .{} ),
// STOS / STOSB / STOSW / STOSD / STOSQ
    instr(.STOS,    ops1(._void8),              Op1(0xAA),              .ZO, .RM8,        .{} ),
    instr(.STOS,    ops1(._void),               Op1(0xAB),              .ZO, .RM32,       .{} ),
    //
    instr(.STOSB,   ops0(),                     Op1(0xAA),              .ZO,   .RM8,      .{} ),
    instr(.STOSW,   ops0(),                     Op1(0xAB),              .ZO16, .RM32,     .{} ),
    instr(.STOSD,   ops0(),                     Op1(0xAB),              .ZO32, .RM32,     .{_386} ),
    instr(.STOSQ,   ops0(),                     Op1(0xAB),              .ZO64, .RM32,     .{x86_64} ),
// SUB
    instr(.SUB,     ops2(.reg_al, .imm8),       Op1(0x2C),              .I2, .RM8,        .{} ),
    instr(.SUB,     ops2(.rm8, .imm8),          Op1r(0x80, 5),          .MI, .RM8,        .{} ),
    instr(.SUB,     ops2(.rm16, .imm8),         Op1r(0x83, 5),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.SUB,     ops2(.rm32, .imm8),         Op1r(0x83, 5),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.SUB,     ops2(.rm64, .imm8),         Op1r(0x83, 5),          .MI, .RM32_I8,    .{edge.Sign} ),
    //
    instr(.SUB,     ops2(.reg_ax, .imm16),      Op1(0x2D),              .I2, .RM32,       .{} ),
    instr(.SUB,     ops2(.reg_eax, .imm32),     Op1(0x2D),              .I2, .RM32,       .{} ),
    instr(.SUB,     ops2(.reg_rax, .imm32),     Op1(0x2D),              .I2, .RM32,       .{edge.Sign} ),
    //
    instr(.SUB,     ops2(.rm16, .imm16),        Op1r(0x81, 5),          .MI, .RM32,       .{} ),
    instr(.SUB,     ops2(.rm32, .imm32),        Op1r(0x81, 5),          .MI, .RM32,       .{} ),
    instr(.SUB,     ops2(.rm64, .imm32),        Op1r(0x81, 5),          .MI, .RM32,       .{edge.Sign} ),
    //
    instr(.SUB,     ops2(.rm8, .reg8),          Op1(0x28),              .MR, .RM8,        .{} ),
    instr(.SUB,     ops2(.rm16, .reg16),        Op1(0x29),              .MR, .RM32,       .{} ),
    instr(.SUB,     ops2(.rm32, .reg32),        Op1(0x29),              .MR, .RM32,       .{} ),
    instr(.SUB,     ops2(.rm64, .reg64),        Op1(0x29),              .MR, .RM32,       .{} ),
    //
    instr(.SUB,     ops2(.reg8, .rm8),          Op1(0x2A),              .RM, .RM8,        .{} ),
    instr(.SUB,     ops2(.reg16, .rm16),        Op1(0x2B),              .RM, .RM32,       .{} ),
    instr(.SUB,     ops2(.reg32, .rm32),        Op1(0x2B),              .RM, .RM32,       .{} ),
    instr(.SUB,     ops2(.reg64, .rm64),        Op1(0x2B),              .RM, .RM32,       .{} ),
// TEST
    instr(.TEST,    ops2(.reg_al, .imm8),       Op1(0xA8),              .I2, .RM8,        .{} ),
    instr(.TEST,    ops2(.reg_ax, .imm16),      Op1(0xA9),              .I2, .RM32,       .{} ),
    instr(.TEST,    ops2(.reg_eax, .imm32),     Op1(0xA9),              .I2, .RM32,       .{} ),
    instr(.TEST,    ops2(.reg_rax, .imm32),     Op1(0xA9),              .I2, .RM32,       .{edge.Sign} ),
    //
    instr(.TEST,    ops2(.rm8, .imm8),          Op1r(0xF6, 0),          .MI, .RM8,        .{} ),
    instr(.TEST,    ops2(.rm16, .imm16),        Op1r(0xF7, 0),          .MI, .RM32,       .{} ),
    instr(.TEST,    ops2(.rm32, .imm32),        Op1r(0xF7, 0),          .MI, .RM32,       .{} ),
    instr(.TEST,    ops2(.rm64, .imm32),        Op1r(0xF7, 0),          .MI, .RM32,       .{} ),
    //
    instr(.TEST,    ops2(.rm8,  .reg8),         Op1(0x84),              .MR, .RM8,        .{} ),
    instr(.TEST,    ops2(.rm16, .reg16),        Op1(0x85),              .MR, .RM32,       .{} ),
    instr(.TEST,    ops2(.rm32, .reg32),        Op1(0x85),              .MR, .RM32,       .{} ),
    instr(.TEST,    ops2(.rm64, .reg64),        Op1(0x85),              .MR, .RM32,       .{} ),
// WAIT
    instr(.WAIT,    ops0(),                     Op1(0x9B),              .ZO, .ZO,         .{} ),
// XCHG
    instr(.XCHG,    ops2(.reg_ax, .reg16),      Op1(0x90),              .O2, .RM32,       .{} ),
    instr(.XCHG,    ops2(.reg16, .reg_ax),      Op1(0x90),              .O,  .RM32,       .{} ),
    instr(.XCHG,    ops2(.reg_eax, .reg32),     Op1(0x90),              .O2, .RM32,       .{edge.XCHG_EAX} ),
    instr(.XCHG,    ops2(.reg32, .reg_eax),     Op1(0x90),              .O,  .RM32,       .{edge.XCHG_EAX} ),
    instr(.XCHG,    ops2(.reg_rax, .reg64),     Op1(0x90),              .O2, .RM32,       .{} ),
    instr(.XCHG,    ops2(.reg64, .reg_rax),     Op1(0x90),              .O,  .RM32,       .{} ),
    //
    instr(.XCHG,    ops2(.rm8, .reg8),          Op1(0x86),              .MR, .RM8,        .{pre.Lock} ),
    instr(.XCHG,    ops2(.reg8, .rm8),          Op1(0x86),              .RM, .RM8,        .{pre.Lock} ),
    instr(.XCHG,    ops2(.rm16, .reg16),        Op1(0x87),              .MR, .RM32,       .{pre.Lock} ),
    instr(.XCHG,    ops2(.reg16, .rm16),        Op1(0x87),              .RM, .RM32,       .{pre.Lock} ),
    instr(.XCHG,    ops2(.rm32, .reg32),        Op1(0x87),              .MR, .RM32,       .{pre.Lock} ),
    instr(.XCHG,    ops2(.reg32, .rm32),        Op1(0x87),              .RM, .RM32,       .{pre.Lock} ),
    instr(.XCHG,    ops2(.rm64, .reg64),        Op1(0x87),              .MR, .RM32,       .{pre.Lock} ),
    instr(.XCHG,    ops2(.reg64, .rm64),        Op1(0x87),              .RM, .RM32,       .{pre.Lock} ),
// XLAT / XLATB
    instr(.XLAT,    ops1(._void),               Op1(0xD7),              .ZO, .RM32,       .{} ),
    //
    instr(.XLAT,    ops0(),                     Op1(0xD7),              .ZO, .ZO,         .{} ),
    instr(.XLATB,   ops0(),                     Op1(0xD7),              .ZO, .ZO,         .{} ),
    // instr(.XLATB,   ops0(),                     Op1(0xD7),              .ZO64, .RM32,     .{} ),
// XOR
    instr(.XOR,     ops2(.reg_al, .imm8),       Op1(0x34),              .I2, .RM8,        .{} ),
    instr(.XOR,     ops2(.rm8, .imm8),          Op1r(0x80, 6),          .MI, .RM8,        .{} ),
    instr(.XOR,     ops2(.rm16, .imm8),         Op1r(0x83, 6),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.XOR,     ops2(.rm32, .imm8),         Op1r(0x83, 6),          .MI, .RM32_I8,    .{edge.Sign} ),
    instr(.XOR,     ops2(.rm64, .imm8),         Op1r(0x83, 6),          .MI, .RM32_I8,    .{edge.Sign} ),
    //
    instr(.XOR,     ops2(.reg_ax, .imm16),      Op1(0x35),              .I2, .RM32,       .{} ),
    instr(.XOR,     ops2(.reg_eax, .imm32),     Op1(0x35),              .I2, .RM32,       .{} ),
    instr(.XOR,     ops2(.reg_rax, .imm32),     Op1(0x35),              .I2, .RM32,       .{edge.Sign} ),
    //
    instr(.XOR,     ops2(.rm16, .imm16),        Op1r(0x81, 6),          .MI, .RM32,       .{} ),
    instr(.XOR,     ops2(.rm32, .imm32),        Op1r(0x81, 6),          .MI, .RM32,       .{} ),
    instr(.XOR,     ops2(.rm64, .imm32),        Op1r(0x81, 6),          .MI, .RM32,       .{edge.Sign} ),
    //
    instr(.XOR,     ops2(.rm8, .reg8),          Op1(0x30),              .MR, .RM8,        .{} ),
    instr(.XOR,     ops2(.rm16, .reg16),        Op1(0x31),              .MR, .RM32,       .{} ),
    instr(.XOR,     ops2(.rm32, .reg32),        Op1(0x31),              .MR, .RM32,       .{} ),
    instr(.XOR,     ops2(.rm64, .reg64),        Op1(0x31),              .MR, .RM32,       .{} ),
    //
    instr(.XOR,     ops2(.reg8, .rm8),          Op1(0x32),              .RM, .RM8,        .{} ),
    instr(.XOR,     ops2(.reg16, .rm16),        Op1(0x33),              .RM, .RM32,       .{} ),
    instr(.XOR,     ops2(.reg32, .rm32),        Op1(0x33),              .RM, .RM32,       .{} ),
    instr(.XOR,     ops2(.reg64, .rm64),        Op1(0x33),              .RM, .RM32,       .{} ),
//
// x87 -- 8087 / 80287 / 80387
//

// F2XM1
    instr(.F2XM1,   ops0(),                   Op2(0xD9, 0xF0),       .ZO, .ZO,    .{_087} ),
// FABS
    instr(.FABS,    ops0(),                   Op2(0xD9, 0xE1),       .ZO, .ZO,    .{_087} ),
// FADD / FADDP / FIADD
    instr(.FADD,    ops1(.rm_mem32),          Op1r(0xD8, 0),         .M, .ZO,     .{_087} ),
    instr(.FADD,    ops1(.rm_mem64),          Op1r(0xDC, 0),         .M, .ZO,     .{_087} ),
    instr(.FADD,    ops1(.reg_st),            Op2(0xD8, 0xC0),       .O, .ZO,     .{_087} ),
    instr(.FADD,    ops2(.reg_st, .reg_st0),  Op2(0xDC, 0xC0),       .O, .ZO,     .{_087} ),
    instr(.FADD,    ops2(.reg_st0, .reg_st),  Op2(0xD8, 0xC0),       .O2, .ZO,    .{_087} ),
    //
    instr(.FADDP,   ops2(.reg_st, .reg_st0),  Op2(0xDE, 0xC0),       .O, .ZO,     .{_087} ),
    instr(.FADDP,   ops0(),                   Op2(0xDE, 0xC1),       .ZO, .ZO,    .{_087} ),
    //
    instr(.FIADD,   ops1(.rm_mem16),          Op1r(0xDE, 0),         .M, .ZO,     .{_087} ),
    instr(.FIADD,   ops1(.rm_mem32),          Op1r(0xDA, 0),         .M, .ZO,     .{_087} ),
// FBLD
    instr(.FBLD,    ops1(.rm_mem80),          Op1r(0xDF, 4),         .M, .ZO,     .{_087} ),
// FBSTP
    instr(.FBSTP,   ops1(.rm_mem80),          Op1r(0xDF, 6),         .M, .ZO,     .{_087} ),
// FCHS
    instr(.FCHS,    ops0(),                   Op2(0xD9, 0xE0),       .ZO, .ZO,    .{_087} ),
    instr(.FCHS,    ops1(.reg_st0),           Op2(0xD9, 0xE0),       .ZO, .ZO,    .{_087} ),
// FCLEX / FNCLEX
    instr(.FCLEX,   ops0(),                preOp2(0x9B, 0xDB, 0xE2), .ZO, .ZO,    .{_087} ),
    instr(.FNCLEX,  ops0(),                   Op2(0xDB, 0xE2),       .ZO, .ZO,    .{_087} ),
// FCOM / FCOMP / FCOMPP
    instr(.FCOM,    ops1(.rm_mem32),          Op1r(0xD8, 2),         .M, .ZO,     .{_087} ),
    instr(.FCOM,    ops1(.rm_mem64),          Op1r(0xDC, 2),         .M, .ZO,     .{_087} ),
    //
    instr(.FCOM,    ops2(.reg_st0, .reg_st),  Op2(0xD8, 0xD0),       .O2, .ZO,    .{_087} ),
    instr(.FCOM,    ops1(.reg_st),            Op2(0xD8, 0xD0),       .O,  .ZO,    .{_087} ),
    instr(.FCOM,    ops0(),                   Op2(0xD8, 0xD1),       .ZO, .ZO,    .{_087} ),
    //
    instr(.FCOMP,   ops1(.rm_mem32),          Op1r(0xD8, 3),         .M, .ZO,     .{_087} ),
    instr(.FCOMP,   ops1(.rm_mem64),          Op1r(0xDC, 3),         .M, .ZO,     .{_087} ),
    //
    instr(.FCOMP,   ops2(.reg_st0, .reg_st),  Op2(0xD8, 0xD8),       .O2, .ZO,    .{_087} ),
    instr(.FCOMP,   ops1(.reg_st),            Op2(0xD8, 0xD8),       .O,  .ZO,    .{_087} ),
    instr(.FCOMP,   ops0(),                   Op2(0xD8, 0xD9),       .ZO, .ZO,    .{_087} ),
    //
    instr(.FCOMPP,  ops0(),                   Op2(0xDE, 0xD9),       .ZO, .ZO,    .{_087} ),
// FDECSTP
    instr(.FDECSTP, ops0(),                   Op2(0xD9, 0xF6),       .ZO, .ZO,    .{_087} ),
// FDIV / FDIVP / FIDIV
    instr(.FDIV,    ops1(.rm_mem32),          Op1r(0xD8, 6),         .M, .ZO,     .{_087} ),
    instr(.FDIV,    ops1(.rm_mem64),          Op1r(0xDC, 6),         .M, .ZO,     .{_087} ),
    //
    instr(.FDIV,    ops1(.reg_st),            Op2(0xD8, 0xF0),       .O,  .ZO,    .{_087} ),
    instr(.FDIV,    ops2(.reg_st0, .reg_st),  Op2(0xD8, 0xF0),       .O2, .ZO,    .{_087} ),
    instr(.FDIV,    ops2(.reg_st, .reg_st0),  Op2(0xDC, 0xF8),       .O,  .ZO,    .{_087} ),
    //
    instr(.FDIVP,   ops2(.reg_st, .reg_st0),  Op2(0xDE, 0xF8),       .O,  .ZO,    .{_087} ),
    instr(.FDIVP,   ops0(),                   Op2(0xDE, 0xF9),       .ZO, .ZO,    .{_087} ),
    //
    instr(.FIDIV,   ops1(.rm_mem16),          Op1r(0xDE, 6),         .M, .ZO,     .{_087} ),
    instr(.FIDIV,   ops1(.rm_mem32),          Op1r(0xDA, 6),         .M, .ZO,     .{_087} ),
// FDIVR / FDIVRP / FIDIVR
    instr(.FDIVR,   ops1(.rm_mem32),          Op1r(0xD8, 7),         .M, .ZO,     .{_087} ),
    instr(.FDIVR,   ops1(.rm_mem64),          Op1r(0xDC, 7),         .M, .ZO,     .{_087} ),
    //
    instr(.FDIVR,   ops1(.reg_st),            Op2(0xD8, 0xF8),       .O,  .ZO,    .{_087} ),
    instr(.FDIVR,   ops2(.reg_st, .reg_st0),  Op2(0xDC, 0xF0),       .O,  .ZO,    .{_087} ),
    instr(.FDIVR,   ops2(.reg_st0, .reg_st),  Op2(0xD8, 0xF8),       .O2, .ZO,    .{_087} ),
    //
    instr(.FDIVRP,  ops2(.reg_st, .reg_st0),  Op2(0xDE, 0xF0),       .O,  .ZO,    .{_087} ),
    instr(.FDIVRP,  ops0(),                   Op2(0xDE, 0xF1),       .ZO, .ZO,    .{_087} ),
    //
    instr(.FIDIVR,  ops1(.rm_mem16),          Op1r(0xDE, 7),         .M, .ZO,     .{_087} ),
    instr(.FIDIVR,  ops1(.rm_mem32),          Op1r(0xDA, 7),         .M, .ZO,     .{_087} ),
// FFREE
    instr(.FFREE,   ops1(.reg_st),            Op2(0xDD, 0xC0),       .O,  .ZO,    .{_087} ),
// FICOM / FICOMP
    instr(.FICOM,   ops1(.rm_mem16),          Op1r(0xDE, 2),         .M, .ZO,     .{_087} ),
    instr(.FICOM,   ops1(.rm_mem32),          Op1r(0xDA, 2),         .M, .ZO,     .{_087} ),
    //
    instr(.FICOMP,  ops1(.rm_mem16),          Op1r(0xDE, 3),         .M, .ZO,     .{_087} ),
    instr(.FICOMP,  ops1(.rm_mem32),          Op1r(0xDA, 3),         .M, .ZO,     .{_087} ),
// FILD
    instr(.FILD,    ops1(.rm_mem16),          Op1r(0xDF, 0),         .M, .ZO,     .{_087} ),
    instr(.FILD,    ops1(.rm_mem32),          Op1r(0xDB, 0),         .M, .ZO,     .{_087} ),
    instr(.FILD,    ops1(.rm_mem64),          Op1r(0xDF, 5),         .M, .ZO,     .{_087} ),
// FINCSTP
    instr(.FINCSTP, ops0(),                   Op2(0xD9, 0xF7),       .ZO, .ZO,    .{_087} ),
// FINIT / FNINIT
    instr(.FINIT,   ops0(),                preOp2(0x9B, 0xDB, 0xE3), .ZO, .ZO,    .{_087} ),
    instr(.FNINIT,  ops0(),                   Op2(0xDB, 0xE3),       .ZO, .ZO,    .{_087} ),
// FIST
    instr(.FIST,    ops1(.rm_mem16),          Op1r(0xDF, 2),         .M, .ZO,     .{_087} ),
    instr(.FIST,    ops1(.rm_mem32),          Op1r(0xDB, 2),         .M, .ZO,     .{_087} ),
    //
    instr(.FISTP,   ops1(.rm_mem16),          Op1r(0xDF, 3),         .M, .ZO,     .{_087} ),
    instr(.FISTP,   ops1(.rm_mem32),          Op1r(0xDB, 3),         .M, .ZO,     .{_087} ),
    instr(.FISTP,   ops1(.rm_mem64),          Op1r(0xDF, 7),         .M, .ZO,     .{_087} ),
// FLD
    instr(.FLD,     ops1(.rm_mem32),          Op1r(0xD9, 0),         .M, .ZO,     .{_087} ),
    instr(.FLD,     ops1(.rm_mem64),          Op1r(0xDD, 0),         .M, .ZO,     .{_087} ),
    instr(.FLD,     ops1(.rm_mem80),          Op1r(0xDB, 5),         .M, .ZO,     .{_087} ),
    instr(.FLD,     ops1(.reg_st),            Op2(0xD9, 0xC0),       .O, .ZO,     .{_087} ),
    instr(.FLD1,    ops0(),                   Op2(0xD9, 0xE8),       .ZO, .ZO,    .{_087} ),
    instr(.FLDL2T,  ops0(),                   Op2(0xD9, 0xE9),       .ZO, .ZO,    .{_087} ),
    instr(.FLDL2E,  ops0(),                   Op2(0xD9, 0xEA),       .ZO, .ZO,    .{_087} ),
    instr(.FLDPI,   ops0(),                   Op2(0xD9, 0xEB),       .ZO, .ZO,    .{_087} ),
    instr(.FLDLG2,  ops0(),                   Op2(0xD9, 0xEC),       .ZO, .ZO,    .{_087} ),
    instr(.FLDLN2,  ops0(),                   Op2(0xD9, 0xED),       .ZO, .ZO,    .{_087} ),
    instr(.FLDZ,    ops0(),                   Op2(0xD9, 0xEE),       .ZO, .ZO,    .{_087} ),
// FMUL / FMULP / FIMUL
    instr(.FMUL,    ops1(.rm_mem32),          Op1r(0xD8, 1),         .M, .ZO,     .{_087} ),
    instr(.FMUL,    ops1(.rm_mem64),          Op1r(0xDC, 1),         .M, .ZO,     .{_087} ),
    //
    instr(.FMUL,    ops1(.reg_st),            Op2(0xD8, 0xC8),       .O,  .ZO,    .{_087} ),
    instr(.FMUL,    ops2(.reg_st, .reg_st0),  Op2(0xDC, 0xC8),       .O,  .ZO,    .{_087} ),
    instr(.FMUL,    ops2(.reg_st0, .reg_st),  Op2(0xD8, 0xC8),       .O2, .ZO,    .{_087} ),
    //
    instr(.FMULP,   ops2(.reg_st, .reg_st0),  Op2(0xDE, 0xC8),       .O,  .ZO,    .{_087} ),
    instr(.FMULP,   ops0(),                   Op2(0xDE, 0xC9),       .ZO, .ZO,    .{_087} ),
    //
    instr(.FIMUL,   ops1(.rm_mem16),          Op1r(0xDE, 1),         .M, .ZO,     .{_087} ),
    instr(.FIMUL,   ops1(.rm_mem32),          Op1r(0xDA, 1),         .M, .ZO,     .{_087} ),
// FNOP
    instr(.FNOP,    ops0(),                   Op2(0xD9, 0xD0),       .ZO, .ZO,    .{_087} ),
// FPATAN
    instr(.FPATAN,  ops0(),                   Op2(0xD9, 0xF3),       .ZO, .ZO,    .{_087} ),
// FPREM
    instr(.FPREM,   ops0(),                   Op2(0xD9, 0xF8),       .ZO, .ZO,    .{_087} ),
// FPTAN
    instr(.FPTAN,   ops0(),                   Op2(0xD9, 0xF2),       .ZO, .ZO,    .{_087} ),
// FRNDINT
    instr(.FRNDINT, ops0(),                   Op2(0xD9, 0xFC),       .ZO, .ZO,    .{_087} ),
// FRSTOR
    instr(.FRSTOR,  ops1(.rm_mem),            Op1r(0xDD, 4),         .M, .ZO,     .{_087} ),
// FSAVE / FNSAVE
    instr(.FSAVE,   ops1(.rm_mem),         preOp1r(0x9B, 0xDD, 6),   .M, .ZO,     .{_087} ),
    instr(.FNSAVE,  ops1(.rm_mem),            Op1r(0xDD, 6),         .M, .ZO,     .{_087} ),
// FSCALE
    instr(.FSCALE,  ops0(),                   Op2(0xD9, 0xFD),       .ZO, .ZO,    .{_087} ),
// FSQRT
    instr(.FSQRT,   ops0(),                   Op2(0xD9, 0xFA),       .ZO, .ZO,    .{_087} ),
// FST / FSTP
    instr(.FST,     ops1(.rm_mem32),          Op1r(0xD9, 2),         .M, .ZO,     .{_087} ),
    instr(.FST,     ops1(.rm_mem64),          Op1r(0xDD, 2),         .M, .ZO,     .{_087} ),
    instr(.FST,     ops1(.reg_st),            Op2(0xDD, 0xD0),       .O, .ZO,     .{_087} ),
    instr(.FST,     ops2(.reg_st0, .reg_st),  Op2(0xDD, 0xD0),       .O2, .ZO,    .{_087} ),
    instr(.FSTP,    ops1(.rm_mem32),          Op1r(0xD9, 3),         .M, .ZO,     .{_087} ),
    instr(.FSTP,    ops1(.rm_mem64),          Op1r(0xDD, 3),         .M, .ZO,     .{_087} ),
    instr(.FSTP,    ops1(.rm_mem80),          Op1r(0xDB, 7),         .M, .ZO,     .{_087} ),
    instr(.FSTP,    ops1(.reg_st),            Op2(0xDD, 0xD8),       .O, .ZO,     .{_087} ),
    instr(.FSTP,    ops2(.reg_st0, .reg_st),  Op2(0xDD, 0xD8),       .O2, .ZO,    .{_087} ),
// FSTCW / FNSTCW
    instr(.FSTCW,   ops1(.rm_mem),         preOp1r(0x9B, 0xD9, 7),   .M, .ZO,     .{_087} ),
    instr(.FSTCW,   ops1(.rm_mem16),       preOp1r(0x9B, 0xD9, 7),   .M, .ZO,     .{_087} ),
    instr(.FNSTCW,  ops1(.rm_mem),            Op1r(0xD9, 7),         .M, .ZO,     .{_087} ),
    instr(.FNSTCW,  ops1(.rm_mem16),          Op1r(0xD9, 7),         .M, .ZO,     .{_087} ),
// FSTENV / FNSTENV
    instr(.FSTENV,  ops1(.rm_mem),         preOp1r(0x9B, 0xD9, 6),   .M, .ZO,     .{_087} ),
    instr(.FNSTENV, ops1(.rm_mem),            Op1r(0xD9, 6),         .M, .ZO,     .{_087} ),
// FSTSW / FNSTSW
    instr(.FSTSW,   ops1(.rm_mem),         preOp1r(0x9B, 0xDD, 7),   .M, .ZO,     .{_087} ),
    instr(.FSTSW,   ops1(.rm_mem16),       preOp1r(0x9B, 0xDD, 7),   .M, .ZO,     .{_087} ),
    instr(.FSTSW,   ops1(.reg_ax),         preOp2(0x9B, 0xDF, 0xE0), .ZO, .ZO,    .{_087} ),
    instr(.FNSTSW,  ops1(.rm_mem),            Op1r(0xDD, 7),         .M, .ZO,     .{_087} ),
    instr(.FNSTSW,  ops1(.rm_mem16),          Op1r(0xDD, 7),         .M, .ZO,     .{_087} ),
    instr(.FNSTSW,  ops1(.reg_ax),            Op2(0xDF, 0xE0),       .ZO, .ZO,    .{_087} ),
// FSUB / FSUBP / FISUB
    instr(.FSUB,    ops1(.rm_mem32),          Op1r(0xD8, 4),         .M, .ZO,     .{_087} ),
    instr(.FSUB,    ops1(.rm_mem64),          Op1r(0xDC, 4),         .M, .ZO,     .{_087} ),
    //
    instr(.FSUB,    ops1(.reg_st),            Op2(0xD8, 0xE0),       .O,  .ZO,    .{_087} ),
    instr(.FSUB,    ops2(.reg_st, .reg_st0),  Op2(0xDC, 0xE8),       .O,  .ZO,    .{_087} ),
    instr(.FSUB,    ops2(.reg_st0, .reg_st),  Op2(0xD8, 0xE0),       .O2, .ZO,    .{_087} ),
    //
    instr(.FSUBP,   ops2(.reg_st, .reg_st0),  Op2(0xDE, 0xE8),       .O,  .ZO,    .{_087} ),
    instr(.FSUBP,   ops0(),                   Op2(0xDE, 0xE9),       .ZO, .ZO,    .{_087} ),
    //
    instr(.FISUB,   ops1(.rm_mem16),          Op1r(0xDE, 4),         .M, .ZO,     .{_087} ),
    instr(.FISUB,   ops1(.rm_mem32),          Op1r(0xDA, 4),         .M, .ZO,     .{_087} ),
// FSUBR / FSUBRP / FISUBR
    instr(.FSUBR,   ops1(.rm_mem32),          Op1r(0xD8, 5),         .M, .ZO,     .{_087} ),
    instr(.FSUBR,   ops1(.rm_mem64),          Op1r(0xDC, 5),         .M, .ZO,     .{_087} ),
    //
    instr(.FSUBR,   ops1(.reg_st),            Op2(0xD8, 0xE8),       .O,  .ZO,    .{_087} ),
    instr(.FSUBR,   ops2(.reg_st0, .reg_st),  Op2(0xD8, 0xE8),       .O2, .ZO,    .{_087} ),
    instr(.FSUBR,   ops2(.reg_st, .reg_st0),  Op2(0xDC, 0xE0),       .O,  .ZO,    .{_087} ),
    //
    instr(.FSUBRP,  ops2(.reg_st, .reg_st0),  Op2(0xDE, 0xE0),       .O,  .ZO,    .{_087} ),
    instr(.FSUBRP,  ops0(),                   Op2(0xDE, 0xE1),       .ZO, .ZO,    .{_087} ),
    //
    instr(.FISUBR,  ops1(.rm_mem16),          Op1r(0xDE, 5),         .M, .ZO,     .{_087} ),
    instr(.FISUBR,  ops1(.rm_mem32),          Op1r(0xDA, 5),         .M, .ZO,     .{_087} ),
// FTST
    instr(.FTST,    ops0(),                   Op2(0xD9, 0xE4),       .ZO, .ZO,    .{_087} ),
// FWAIT (alternate mnemonic for WAIT)
    instr(.FWAIT,   ops0(),                   Op1(0x9B),             .ZO, .ZO,    .{_087} ),
// FXAM
    instr(.FXAM,    ops0(),                   Op2(0xD9, 0xE5),       .ZO, .ZO,    .{_087} ),
// FXCH
    instr(.FXCH,    ops2(.reg_st0, .reg_st),  Op2(0xD9, 0xC8),       .O2, .ZO,    .{_087} ),
    instr(.FXCH,    ops1(.reg_st),            Op2(0xD9, 0xC8),       .O, .ZO,     .{_087} ),
    instr(.FXCH,    ops0(),                   Op2(0xD9, 0xC9),       .ZO, .ZO,    .{_087} ),
// FXTRACT
    instr(.FXTRACT, ops0(),                   Op2(0xD9, 0xF4),       .ZO, .ZO,    .{_087} ),
// FYL2X
    instr(.FYL2X,   ops0(),                   Op2(0xD9, 0xF1),       .ZO, .ZO,    .{_087} ),
// FYL2XP1
    instr(.FYL2XP1, ops0(),                   Op2(0xD9, 0xF9),       .ZO, .ZO,    .{_087} ),

//
// 80287
//
    // instr(.FSETPM,  ops0(),                   Op2(0xDB, 0xE4),       .ZO, .ZO,    .{cpu._287, edge.obsolete} ),

//
// 80387
//
    instr(.FCOS,    ops0(),                   Op2(0xD9, 0xFF),       .ZO, .ZO,    .{_387} ),
    instr(.FPREM1,  ops0(),                   Op2(0xD9, 0xF5),       .ZO, .ZO,    .{_387} ),
    instr(.FSIN,    ops0(),                   Op2(0xD9, 0xFE),       .ZO, .ZO,    .{_387} ),
    instr(.FSINCOS, ops0(),                   Op2(0xD9, 0xFB),       .ZO, .ZO,    .{_387} ),
// FUCOM / FUCOMP / FUCOMPP
    instr(.FUCOM,   ops2(.reg_st0, .reg_st),  Op2(0xDD, 0xE0),       .O2, .ZO,    .{_387} ),
    instr(.FUCOM,   ops1(.reg_st),            Op2(0xDD, 0xE0),       .O,  .ZO,    .{_387} ),
    instr(.FUCOM,   ops0(),                   Op2(0xDD, 0xE1),       .ZO, .ZO,    .{_387} ),
    //
    instr(.FUCOMP,  ops2(.reg_st0, .reg_st),  Op2(0xDD, 0xE8),       .O2, .ZO,    .{_387} ),
    instr(.FUCOMP,  ops1(.reg_st),            Op2(0xDD, 0xE8),       .O,  .ZO,    .{_387} ),
    instr(.FUCOMP,  ops0(),                   Op2(0xDD, 0xE9),       .ZO, .ZO,    .{_387} ),
    //
    instr(.FUCOMPP, ops0(),                   Op2(0xDA, 0xE9),       .ZO, .ZO,    .{_387} ),
    //
    // TODO: need to also handle:
    // * FLDENVW
    // * FSAVEW
    // * FRSTORW
    // * FSTENVW
    // * FLDENVD
    // * FSAVED
    // * FRSTORD
    // * FSTENVD

//
// x87 -- Pentium Pro / P6
//
// FCMOVcc
    instr(.FCMOVB,   ops2(.reg_st0, .reg_st),  Op2(0xDA, 0xC0),       .O2, .ZO,    .{cpu.P6} ),
    instr(.FCMOVB,   ops1(.reg_st),            Op2(0xDA, 0xC0),       .O,  .ZO,    .{cpu.P6} ),
    //
    instr(.FCMOVE,   ops2(.reg_st0, .reg_st),  Op2(0xDA, 0xC8),       .O2, .ZO,    .{cpu.P6} ),
    instr(.FCMOVE,   ops1(.reg_st),            Op2(0xDA, 0xC8),       .O,  .ZO,    .{cpu.P6} ),
    //
    instr(.FCMOVBE,  ops2(.reg_st0, .reg_st),  Op2(0xDA, 0xD0),       .O2, .ZO,    .{cpu.P6} ),
    instr(.FCMOVBE,  ops1(.reg_st),            Op2(0xDA, 0xD0),       .O,  .ZO,    .{cpu.P6} ),
    //
    instr(.FCMOVU,   ops2(.reg_st0, .reg_st),  Op2(0xDA, 0xD8),       .O2, .ZO,    .{cpu.P6} ),
    instr(.FCMOVU,   ops1(.reg_st),            Op2(0xDA, 0xD8),       .O,  .ZO,    .{cpu.P6} ),
    //
    instr(.FCMOVNB,  ops2(.reg_st0, .reg_st),  Op2(0xDB, 0xC0),       .O2, .ZO,    .{cpu.P6} ),
    instr(.FCMOVNB,  ops1(.reg_st),            Op2(0xDB, 0xC0),       .O,  .ZO,    .{cpu.P6} ),
    //
    instr(.FCMOVNE,  ops2(.reg_st0, .reg_st),  Op2(0xDB, 0xC8),       .O2, .ZO,    .{cpu.P6} ),
    instr(.FCMOVNE,  ops1(.reg_st),            Op2(0xDB, 0xC8),       .O,  .ZO,    .{cpu.P6} ),
    //
    instr(.FCMOVNBE, ops2(.reg_st0, .reg_st),  Op2(0xDB, 0xD0),       .O2, .ZO,    .{cpu.P6} ),
    instr(.FCMOVNBE, ops1(.reg_st),            Op2(0xDB, 0xD0),       .O,  .ZO,    .{cpu.P6} ),
    //
    instr(.FCMOVNU,  ops2(.reg_st0, .reg_st),  Op2(0xDB, 0xD8),       .O2, .ZO,    .{cpu.P6} ),
    instr(.FCMOVNU,  ops1(.reg_st),            Op2(0xDB, 0xD8),       .O,  .ZO,    .{cpu.P6} ),
// FCOMI
    instr(.FCOMI,    ops2(.reg_st0, .reg_st),  Op2(0xDB, 0xF0),       .O2, .ZO,    .{cpu.P6} ),
    instr(.FCOMI,    ops1(.reg_st),            Op2(0xDB, 0xF0),       .O,  .ZO,    .{cpu.P6} ),
// FCOMIP
    instr(.FCOMIP,   ops2(.reg_st0, .reg_st),  Op2(0xDF, 0xF0),       .O2, .ZO,    .{cpu.P6} ),
    instr(.FCOMIP,   ops1(.reg_st),            Op2(0xDF, 0xF0),       .O,  .ZO,    .{cpu.P6} ),
// FUCOMI
    instr(.FUCOMI,   ops2(.reg_st0, .reg_st),  Op2(0xDB, 0xE8),       .O2, .ZO,    .{cpu.P6} ),
    instr(.FUCOMI,   ops1(.reg_st),            Op2(0xDB, 0xE8),       .O,  .ZO,    .{cpu.P6} ),
// FUCOMIP
    instr(.FUCOMIP,  ops2(.reg_st0, .reg_st),  Op2(0xDF, 0xE8),       .O2, .ZO,    .{cpu.P6} ),
    instr(.FUCOMIP,  ops1(.reg_st),            Op2(0xDF, 0xE8),       .O,  .ZO,    .{cpu.P6} ),

//
//  x87 - other
//
    instr(.FISTTP,   ops1(.rm_mem16),          Op1r(0xDF, 1),         .M, .ZO,     .{SSE3} ),
    instr(.FISTTP,   ops1(.rm_mem32),          Op1r(0xDB, 1),         .M, .ZO,     .{SSE3} ),
    instr(.FISTTP,   ops1(.rm_mem64),          Op1r(0xDD, 1),         .M, .ZO,     .{SSE3} ),

//
// 80286
//
    // NOTES: might want to handle operands like `r32/m16` better
    instr(.ARPL,    ops2(.rm16, .reg16),        Op1(0x63),              .MR, .RM16,       .{No64, _286} ),
    //
    instr(.CLTS,    ops0(),                     Op2(0x0F, 0x06),        .ZO, .ZO,         .{_286} ),
    //
    instr(.LAR,     ops2(.reg16, .rm16),        Op2(0x0F, 0x02),        .RM, .RM32,       .{_286} ),
    instr(.LAR,     ops2(.reg32, .rm32),        Op2(0x0F, 0x02),        .RM, .RM32,       .{_386} ),
    instr(.LAR,     ops2(.reg64, .rm64),        Op2(0x0F, 0x02),        .RM, .RM32,       .{x86_64} ),
    //
    instr(.LGDT,    ops1(.rm_mem),              Op2r(0x0F, 0x01, 2),    .M,  .ZO,         .{No64, _286} ),
    instr(.LGDT,    ops1(.rm_mem),              Op2r(0x0F, 0x01, 2),    .M,  .ZO,         .{No32, _286} ),
    //
    instr(.LIDT,    ops1(.rm_mem),              Op2r(0x0F, 0x01, 3),    .M,  .ZO,         .{No64, _286} ),
    instr(.LIDT,    ops1(.rm_mem),              Op2r(0x0F, 0x01, 3),    .M,  .ZO,         .{No32, _286} ),
    //
    instr(.LLDT,    ops1(.rm16),                Op2r(0x0F, 0x00, 2),    .M,  .RM16,       .{_286} ),
    //
    instr(.LMSW,    ops1(.rm16),                Op2r(0x0F, 0x01, 6),    .M,  .RM16,       .{_286} ),
    //
    // instr(.LOADALL, ops1(.rm16),                Op2r(0x0F, 0x01, 6),    .M, .RM16,        .{_286, _386} ), // undocumented
    //
    instr(.LSL,     ops2(.reg16, .rm16),        Op2(0x0F, 0x03),        .RM, .RM32,       .{_286} ),
    instr(.LSL,     ops2(.reg32, .rm32),        Op2(0x0F, 0x03),        .RM, .RM32,       .{_386} ),
    instr(.LSL,     ops2(.reg64, .rm64),        Op2(0x0F, 0x03),        .RM, .RM32,       .{x86_64} ),
    //
    instr(.LTR,     ops1(.rm16),                Op2r(0x0F, 0x00, 3),    .M,  .RM16,       .{_286} ),
    //
    instr(.SGDT,    ops1(.rm_mem),              Op2r(0x0F, 0x01, 0),    .M,  .ZO,         .{_286} ),
    //
    instr(.SIDT,    ops1(.rm_mem),              Op2r(0x0F, 0x01, 1),    .M,  .ZO,         .{_286} ),
    //
    instr(.SLDT,    ops1(.rm_mem16),            Op2r(0x0F, 0x00, 0),    .M,  .RM16,       .{_286} ),
    instr(.SLDT,    ops1(.rm_reg16),            Op2r(0x0F, 0x00, 0),    .M,  .RM32,       .{_286} ),
    instr(.SLDT,    ops1(.reg16),               Op2r(0x0F, 0x00, 0),    .M,  .RM32,       .{_286} ),
    instr(.SLDT,    ops1(.reg32),               Op2r(0x0F, 0x00, 0),    .M,  .RM32,       .{_386} ),
    instr(.SLDT,    ops1(.reg64),               Op2r(0x0F, 0x00, 0),    .M,  .RM32,       .{x86_64} ),
    //
    instr(.SMSW,    ops1(.rm_mem16),            Op2r(0x0F, 0x01, 4),    .M,  .RM16,       .{_286} ),
    instr(.SMSW,    ops1(.rm_reg16),            Op2r(0x0F, 0x01, 4),    .M,  .RM32,       .{_286} ),
    instr(.SMSW,    ops1(.reg16),               Op2r(0x0F, 0x01, 4),    .M,  .RM32,       .{_286} ),
    instr(.SMSW,    ops1(.reg32),               Op2r(0x0F, 0x01, 4),    .M,  .RM32,       .{_386} ),
    instr(.SMSW,    ops1(.reg64),               Op2r(0x0F, 0x01, 4),    .M,  .RM32,       .{x86_64} ),
    //
    instr(.STR,     ops1(.rm_mem16),            Op2r(0x0F, 0x00, 1),    .M,  .RM16,       .{_286} ),
    instr(.STR,     ops1(.rm_reg16),            Op2r(0x0F, 0x00, 1),    .M,  .RM32,       .{_286} ),
    instr(.STR,     ops1(.reg16),               Op2r(0x0F, 0x00, 1),    .M,  .RM32,       .{_286} ),
    instr(.STR,     ops1(.reg32),               Op2r(0x0F, 0x00, 1),    .M,  .RM32,       .{_386} ),
    instr(.STR,     ops1(.reg64),               Op2r(0x0F, 0x00, 1),    .M,  .RM32,       .{x86_64} ),
    //
    instr(.VERR,    ops1(.rm16),                Op2r(0x0F, 0x00, 4),    .M,  .RM16,       .{_286} ),
    instr(.VERW,    ops1(.rm16),                Op2r(0x0F, 0x00, 5),    .M,  .RM16,       .{_286} ),

//
// 80386
//
// BSF
    instr(.BSF,     ops2(.reg16, .rm16),        Op2(0x0F, 0xBC),        .RM, .RM32,       .{_386} ),
    instr(.BSF,     ops2(.reg32, .rm32),        Op2(0x0F, 0xBC),        .RM, .RM32,       .{_386} ),
    instr(.BSF,     ops2(.reg64, .rm64),        Op2(0x0F, 0xBC),        .RM, .RM32,       .{x86_64} ),
// BSR
    instr(.BSR,     ops2(.reg16, .rm16),        Op2(0x0F, 0xBD),        .RM, .RM32,       .{_386} ),
    instr(.BSR,     ops2(.reg32, .rm32),        Op2(0x0F, 0xBD),        .RM, .RM32,       .{_386} ),
    instr(.BSR,     ops2(.reg64, .rm64),        Op2(0x0F, 0xBD),        .RM, .RM32,       .{x86_64} ),
// BSR
    instr(.BT,      ops2(.rm16, .reg16),        Op2(0x0F, 0xA3),        .MR, .RM32,       .{_386} ),
    instr(.BT,      ops2(.rm32, .reg32),        Op2(0x0F, 0xA3),        .MR, .RM32,       .{_386} ),
    instr(.BT,      ops2(.rm64, .reg64),        Op2(0x0F, 0xA3),        .MR, .RM32,       .{x86_64} ),
    //
    instr(.BT,      ops2(.rm16, .imm8),         Op2r(0x0F, 0xBA, 4),    .MI, .RM32_I8,    .{_386} ),
    instr(.BT,      ops2(.rm32, .imm8),         Op2r(0x0F, 0xBA, 4),    .MI, .RM32_I8,    .{_386} ),
    instr(.BT,      ops2(.rm64, .imm8),         Op2r(0x0F, 0xBA, 4),    .MI, .RM32_I8,    .{x86_64} ),
// BTC
    instr(.BTC,     ops2(.rm16, .reg16),        Op2(0x0F, 0xBB),        .MR, .RM32,       .{_386} ),
    instr(.BTC,     ops2(.rm32, .reg32),        Op2(0x0F, 0xBB),        .MR, .RM32,       .{_386} ),
    instr(.BTC,     ops2(.rm64, .reg64),        Op2(0x0F, 0xBB),        .MR, .RM32,       .{x86_64} ),
    //
    instr(.BTC,     ops2(.rm16, .imm8),         Op2r(0x0F, 0xBA, 7),    .MI, .RM32_I8,    .{_386} ),
    instr(.BTC,     ops2(.rm32, .imm8),         Op2r(0x0F, 0xBA, 7),    .MI, .RM32_I8,    .{_386} ),
    instr(.BTC,     ops2(.rm64, .imm8),         Op2r(0x0F, 0xBA, 7),    .MI, .RM32_I8,    .{x86_64} ),
// BTR
    instr(.BTS,     ops2(.rm16, .reg16),        Op2(0x0F, 0xB3),        .MR, .RM32,       .{_386} ),
    instr(.BTS,     ops2(.rm32, .reg32),        Op2(0x0F, 0xB3),        .MR, .RM32,       .{_386} ),
    instr(.BTS,     ops2(.rm64, .reg64),        Op2(0x0F, 0xB3),        .MR, .RM32,       .{x86_64} ),
    //
    instr(.BTS,     ops2(.rm16, .imm8),         Op2r(0x0F, 0xBA, 5),    .MI, .RM32_I8,    .{_386} ),
    instr(.BTS,     ops2(.rm32, .imm8),         Op2r(0x0F, 0xBA, 5),    .MI, .RM32_I8,    .{_386} ),
    instr(.BTS,     ops2(.rm64, .imm8),         Op2r(0x0F, 0xBA, 5),    .MI, .RM32_I8,    .{x86_64} ),
// MOVSX / MOVSXD
    instr(.MOVSX,   ops2(.reg16, .rm8),         Op2(0x0F, 0xBE),        .RM, .RM32_Reg,    .{_386} ),
    instr(.MOVSX,   ops2(.reg32, .rm8),         Op2(0x0F, 0xBE),        .RM, .RM32_Reg,    .{_386} ),
    instr(.MOVSX,   ops2(.reg64, .rm8),         Op2(0x0F, 0xBE),        .RM, .RM32_Reg,    .{x86_64} ),
    //
    instr(.MOVSX,   ops2(.reg16, .rm16),        Op2(0x0F, 0xBF),        .RM, .RM32_Reg,    .{_386} ),
    instr(.MOVSX,   ops2(.reg32, .rm16),        Op2(0x0F, 0xBF),        .RM, .RM32_Reg,    .{_386} ),
    instr(.MOVSX,   ops2(.reg64, .rm16),        Op2(0x0F, 0xBF),        .RM, .RM32_Reg,    .{x86_64} ),
    //
    instr(.MOVSXD,  ops2(.reg16, .rm16),        Op1(0x63),              .RM, .RM32_Reg,    .{_386} ),
    instr(.MOVSXD,  ops2(.reg16, .rm32),        Op1(0x63),              .RM, .RM32_Reg,    .{_386} ),
    instr(.MOVSXD,  ops2(.reg32, .rm32),        Op1(0x63),              .RM, .RM32_Reg,    .{_386} ),
    instr(.MOVSXD,  ops2(.reg64, .rm32),        Op1(0x63),              .RM, .RM32_Reg,    .{x86_64} ),
// MOVZX
    instr(.MOVZX,   ops2(.reg16, .rm8),         Op2(0x0F, 0xB6),        .RM, .RM32_Reg,    .{_386} ),
    instr(.MOVZX,   ops2(.reg32, .rm8),         Op2(0x0F, 0xB6),        .RM, .RM32_Reg,    .{_386} ),
    instr(.MOVZX,   ops2(.reg64, .rm8),         Op2(0x0F, 0xB6),        .RM, .RM32_Reg,    .{x86_64} ),
    //
    instr(.MOVZX,   ops2(.reg16, .rm16),        Op2(0x0F, 0xB7),        .RM, .RM32_Reg,    .{_386} ),
    instr(.MOVZX,   ops2(.reg32, .rm16),        Op2(0x0F, 0xB7),        .RM, .RM32_Reg,    .{_386} ),
    instr(.MOVZX,   ops2(.reg64, .rm16),        Op2(0x0F, 0xB7),        .RM, .RM32_Reg,    .{x86_64} ),
// SETcc
    instr(.SETA,    ops1(.rm8),                 Op2(0x0F, 0x97),        .M,  .RM8,        .{_386} ),
    instr(.SETAE,   ops1(.rm8),                 Op2(0x0F, 0x93),        .M,  .RM8,        .{_386} ),
    instr(.SETB,    ops1(.rm8),                 Op2(0x0F, 0x92),        .M,  .RM8,        .{_386} ),
    instr(.SETBE,   ops1(.rm8),                 Op2(0x0F, 0x96),        .M,  .RM8,        .{_386} ),
    instr(.SETC,    ops1(.rm8),                 Op2(0x0F, 0x92),        .M,  .RM8,        .{_386} ),
    instr(.SETE,    ops1(.rm8),                 Op2(0x0F, 0x94),        .M,  .RM8,        .{_386} ),
    instr(.SETG,    ops1(.rm8),                 Op2(0x0F, 0x9F),        .M,  .RM8,        .{_386} ),
    instr(.SETGE,   ops1(.rm8),                 Op2(0x0F, 0x9D),        .M,  .RM8,        .{_386} ),
    instr(.SETL,    ops1(.rm8),                 Op2(0x0F, 0x9C),        .M,  .RM8,        .{_386} ),
    instr(.SETLE,   ops1(.rm8),                 Op2(0x0F, 0x9E),        .M,  .RM8,        .{_386} ),
    instr(.SETNA,   ops1(.rm8),                 Op2(0x0F, 0x96),        .M,  .RM8,        .{_386} ),
    instr(.SETNAE,  ops1(.rm8),                 Op2(0x0F, 0x92),        .M,  .RM8,        .{_386} ),
    instr(.SETNB,   ops1(.rm8),                 Op2(0x0F, 0x93),        .M,  .RM8,        .{_386} ),
    instr(.SETNBE,  ops1(.rm8),                 Op2(0x0F, 0x97),        .M,  .RM8,        .{_386} ),
    instr(.SETNC,   ops1(.rm8),                 Op2(0x0F, 0x93),        .M,  .RM8,        .{_386} ),
    instr(.SETNE,   ops1(.rm8),                 Op2(0x0F, 0x95),        .M,  .RM8,        .{_386} ),
    instr(.SETNG,   ops1(.rm8),                 Op2(0x0F, 0x9E),        .M,  .RM8,        .{_386} ),
    instr(.SETNGE,  ops1(.rm8),                 Op2(0x0F, 0x9C),        .M,  .RM8,        .{_386} ),
    instr(.SETNL,   ops1(.rm8),                 Op2(0x0F, 0x9D),        .M,  .RM8,        .{_386} ),
    instr(.SETNLE,  ops1(.rm8),                 Op2(0x0F, 0x9F),        .M,  .RM8,        .{_386} ),
    instr(.SETNO,   ops1(.rm8),                 Op2(0x0F, 0x91),        .M,  .RM8,        .{_386} ),
    instr(.SETNP,   ops1(.rm8),                 Op2(0x0F, 0x9B),        .M,  .RM8,        .{_386} ),
    instr(.SETNS,   ops1(.rm8),                 Op2(0x0F, 0x99),        .M,  .RM8,        .{_386} ),
    instr(.SETNZ,   ops1(.rm8),                 Op2(0x0F, 0x95),        .M,  .RM8,        .{_386} ),
    instr(.SETO,    ops1(.rm8),                 Op2(0x0F, 0x90),        .M,  .RM8,        .{_386} ),
    instr(.SETP,    ops1(.rm8),                 Op2(0x0F, 0x9A),        .M,  .RM8,        .{_386} ),
    instr(.SETPE,   ops1(.rm8),                 Op2(0x0F, 0x9A),        .M,  .RM8,        .{_386} ),
    instr(.SETPO,   ops1(.rm8),                 Op2(0x0F, 0x9B),        .M,  .RM8,        .{_386} ),
    instr(.SETS,    ops1(.rm8),                 Op2(0x0F, 0x98),        .M,  .RM8,        .{_386} ),
    instr(.SETZ,    ops1(.rm8),                 Op2(0x0F, 0x94),        .M,  .RM8,        .{_386} ),
// SHLD
    instr(.SHLD,    ops3(.rm16,.reg16,.imm8),   Op2(0x0F, 0xA4),        .MRI, .RM32_I8,   .{_386} ),
    instr(.SHLD,    ops3(.rm32,.reg32,.imm8),   Op2(0x0F, 0xA4),        .MRI, .RM32_I8,   .{_386} ),
    instr(.SHLD,    ops3(.rm64,.reg64,.imm8),   Op2(0x0F, 0xA4),        .MRI, .RM32_I8,   .{x86_64} ),
    //
    instr(.SHLD,    ops3(.rm16,.reg16,.reg_cl), Op2(0x0F, 0xA5),        .MR, .RM32,       .{_386} ),
    instr(.SHLD,    ops3(.rm32,.reg32,.reg_cl), Op2(0x0F, 0xA5),        .MR, .RM32,       .{_386} ),
    instr(.SHLD,    ops3(.rm64,.reg64,.reg_cl), Op2(0x0F, 0xA5),        .MR, .RM32,       .{x86_64} ),
// SHLD
    instr(.SHRD,    ops3(.rm16,.reg16,.imm8),   Op2(0x0F, 0xAC),        .MRI, .RM32_I8,   .{_386} ),
    instr(.SHRD,    ops3(.rm32,.reg32,.imm8),   Op2(0x0F, 0xAC),        .MRI, .RM32_I8,   .{_386} ),
    instr(.SHRD,    ops3(.rm64,.reg64,.imm8),   Op2(0x0F, 0xAC),        .MRI, .RM32_I8,   .{x86_64} ),
    //
    instr(.SHRD,    ops3(.rm16,.reg16,.reg_cl), Op2(0x0F, 0xAD),        .MR, .RM32,       .{_386} ),
    instr(.SHRD,    ops3(.rm32,.reg32,.reg_cl), Op2(0x0F, 0xAD),        .MR, .RM32,       .{_386} ),
    instr(.SHRD,    ops3(.rm64,.reg64,.reg_cl), Op2(0x0F, 0xAD),        .MR, .RM32,       .{x86_64} ),

//
// 80486
    instr(.BSWAP,   ops1(.reg16),               Op2(0x0F, 0xC8),        .O,  .RM32,       .{_486, edge.Undefined} ),
    instr(.BSWAP,   ops1(.reg32),               Op2(0x0F, 0xC8),        .O,  .RM32,       .{_486} ),
    instr(.BSWAP,   ops1(.reg64),               Op2(0x0F, 0xC8),        .O,  .RM32,       .{x86_64} ),
// CMPXCHG
    instr(.CMPXCHG, ops2(.rm8,  .reg8 ),        Op2(0x0F, 0xB0),        .MR, .RM8,        .{_486} ),
    instr(.CMPXCHG, ops2(.rm16, .reg16),        Op2(0x0F, 0xB1),        .MR, .RM32,       .{_486} ),
    instr(.CMPXCHG, ops2(.rm32, .reg32),        Op2(0x0F, 0xB1),        .MR, .RM32,       .{_486} ),
    instr(.CMPXCHG, ops2(.rm64, .reg64),        Op2(0x0F, 0xB1),        .MR, .RM32,       .{x86_64} ),
// INVD
    instr(.INVD,    ops0(),                     Op2(0x0F, 0x08),        .ZO, .ZO,         .{_486} ),
// INVLPG
    instr(.INVLPG,  ops1(.rm_mem),              Op2r(0x0F, 0x01, 7),    .M, .ZO,          .{_486} ),
// WBINVD
    instr(.WBINVD,  ops0(),                     Op2(0x0F, 0x09),        .ZO, .ZO,         .{_486} ),
// XADD
    instr(.XADD,    ops2(.rm8,  .reg8 ),        Op2(0x0F, 0xC0),        .MR, .RM8,        .{_486} ),
    instr(.XADD,    ops2(.rm16, .reg16),        Op2(0x0F, 0xC1),        .MR, .RM32,       .{_486} ),
    instr(.XADD,    ops2(.rm32, .reg32),        Op2(0x0F, 0xC1),        .MR, .RM32,       .{_486} ),
    instr(.XADD,    ops2(.rm64, .reg64),        Op2(0x0F, 0xC1),        .MR, .RM32,       .{x86_64} ),

//
// Pentium
//
    instr(.CPUID,      ops0(),                   Op2(0x0F, 0xA2),        .ZO, .ZO,         .{Pent} ),
// CMPXCHG8B / CMPXCHG16B
    instr(.CMPXCHG8B,  ops1(.rm_mem64),          Op2r(0x0F, 0xC7, 1),    .M, .ZO,          .{Pent} ),
    instr(.CMPXCHG16B, ops1(.rm_mem128),         Op2r(0x0F, 0xC7, 1),    .M, .REX_W,       .{Pent} ),
// RDMSR
    instr(.RDMSR,      ops0(),                   Op2(0x0F, 0x32),        .ZO, .ZO,         .{Pent} ),
// RDTSC
    instr(.RDTSC,      ops0(),                   Op2(0x0F, 0x31),        .ZO, .ZO,         .{Pent} ),
// WRMSR
    instr(.WRMSR,      ops0(),                   Op2(0x0F, 0x30),        .ZO, .ZO,         .{Pent} ),
// RSM
    instr(.RSM,        ops0(),                   Op2(0x0F, 0xAA),        .ZO, .ZO,         .{Pent} ),

//
// Pentium MMX
//
// RDPMC
    instr(.RDPMC,      ops0(),                   Op2(0x0F, 0x33),        .ZO, .ZO,         .{cpu.MMX} ),
// EMMS
    instr(.EMMS,       ops0(),                 npOp2(0x0F, 0x77),        .ZO, .ZO,         .{cpu.MMX} ),

//
// K6
//
    instr(.SYSCALL, ops0(),                   Op2(0x0F, 0x05),        .ZO, .ZO,         .{cpu.K6} ),
    instr(.SYSRET,  ops0(),                   Op2(0x0F, 0x07),        .ZO, .ZO,         .{cpu.K6} ),
    instr(.SYSRETQ, ops0(),                   Op2(0x0F, 0x07),        .ZO64, .RM32,     .{cpu.K6} ),

//
// Pentium Pro
//
// CMOVcc
    instr(.CMOVA,   ops2(.reg16, .rm16),       Op2(0x0F, 0x47),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVA,   ops2(.reg32, .rm32),       Op2(0x0F, 0x47),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVA,   ops2(.reg64, .rm64),       Op2(0x0F, 0x47),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVAE,  ops2(.reg16, .rm16),       Op2(0x0F, 0x43),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVAE,  ops2(.reg32, .rm32),       Op2(0x0F, 0x43),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVAE,  ops2(.reg64, .rm64),       Op2(0x0F, 0x43),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVB,   ops2(.reg16, .rm16),       Op2(0x0F, 0x42),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVB,   ops2(.reg32, .rm32),       Op2(0x0F, 0x42),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVB,   ops2(.reg64, .rm64),       Op2(0x0F, 0x42),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVBE,  ops2(.reg16, .rm16),       Op2(0x0F, 0x46),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVBE,  ops2(.reg32, .rm32),       Op2(0x0F, 0x46),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVBE,  ops2(.reg64, .rm64),       Op2(0x0F, 0x46),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVC,   ops2(.reg16, .rm16),       Op2(0x0F, 0x42),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVC,   ops2(.reg32, .rm32),       Op2(0x0F, 0x42),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVC,   ops2(.reg64, .rm64),       Op2(0x0F, 0x42),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVE,   ops2(.reg16, .rm16),       Op2(0x0F, 0x44),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVE,   ops2(.reg32, .rm32),       Op2(0x0F, 0x44),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVE,   ops2(.reg64, .rm64),       Op2(0x0F, 0x44),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVG,   ops2(.reg16, .rm16),       Op2(0x0F, 0x4F),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVG,   ops2(.reg32, .rm32),       Op2(0x0F, 0x4F),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVG,   ops2(.reg64, .rm64),       Op2(0x0F, 0x4F),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVGE,  ops2(.reg16, .rm16),       Op2(0x0F, 0x4D),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVGE,  ops2(.reg32, .rm32),       Op2(0x0F, 0x4D),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVGE,  ops2(.reg64, .rm64),       Op2(0x0F, 0x4D),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVL,   ops2(.reg16, .rm16),       Op2(0x0F, 0x4C),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVL,   ops2(.reg32, .rm32),       Op2(0x0F, 0x4C),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVL,   ops2(.reg64, .rm64),       Op2(0x0F, 0x4C),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVLE,  ops2(.reg16, .rm16),       Op2(0x0F, 0x4E),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVLE,  ops2(.reg32, .rm32),       Op2(0x0F, 0x4E),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVLE,  ops2(.reg64, .rm64),       Op2(0x0F, 0x4E),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNA,  ops2(.reg16, .rm16),       Op2(0x0F, 0x46),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNA,  ops2(.reg32, .rm32),       Op2(0x0F, 0x46),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNA,  ops2(.reg64, .rm64),       Op2(0x0F, 0x46),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNAE, ops2(.reg16, .rm16),       Op2(0x0F, 0x42),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNAE, ops2(.reg32, .rm32),       Op2(0x0F, 0x42),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNAE, ops2(.reg64, .rm64),       Op2(0x0F, 0x42),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNB,  ops2(.reg16, .rm16),       Op2(0x0F, 0x43),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNB,  ops2(.reg32, .rm32),       Op2(0x0F, 0x43),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNB,  ops2(.reg64, .rm64),       Op2(0x0F, 0x43),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNBE, ops2(.reg16, .rm16),       Op2(0x0F, 0x47),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNBE, ops2(.reg32, .rm32),       Op2(0x0F, 0x47),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNBE, ops2(.reg64, .rm64),       Op2(0x0F, 0x47),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNC,  ops2(.reg16, .rm16),       Op2(0x0F, 0x43),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNC,  ops2(.reg32, .rm32),       Op2(0x0F, 0x43),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNC,  ops2(.reg64, .rm64),       Op2(0x0F, 0x43),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNE,  ops2(.reg16, .rm16),       Op2(0x0F, 0x45),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNE,  ops2(.reg32, .rm32),       Op2(0x0F, 0x45),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNE,  ops2(.reg64, .rm64),       Op2(0x0F, 0x45),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNG,  ops2(.reg16, .rm16),       Op2(0x0F, 0x4E),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNG,  ops2(.reg32, .rm32),       Op2(0x0F, 0x4E),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNG,  ops2(.reg64, .rm64),       Op2(0x0F, 0x4E),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNGE, ops2(.reg16, .rm16),       Op2(0x0F, 0x4C),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNGE, ops2(.reg32, .rm32),       Op2(0x0F, 0x4C),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNGE, ops2(.reg64, .rm64),       Op2(0x0F, 0x4C),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNL,  ops2(.reg16, .rm16),       Op2(0x0F, 0x4D),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNL,  ops2(.reg32, .rm32),       Op2(0x0F, 0x4D),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNL,  ops2(.reg64, .rm64),       Op2(0x0F, 0x4D),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNLE, ops2(.reg16, .rm16),       Op2(0x0F, 0x4F),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNLE, ops2(.reg32, .rm32),       Op2(0x0F, 0x4F),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNLE, ops2(.reg64, .rm64),       Op2(0x0F, 0x4F),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNO,  ops2(.reg16, .rm16),       Op2(0x0F, 0x41),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNO,  ops2(.reg32, .rm32),       Op2(0x0F, 0x41),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNO,  ops2(.reg64, .rm64),       Op2(0x0F, 0x41),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNP,  ops2(.reg16, .rm16),       Op2(0x0F, 0x4B),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNP,  ops2(.reg32, .rm32),       Op2(0x0F, 0x4B),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNP,  ops2(.reg64, .rm64),       Op2(0x0F, 0x4B),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNS,  ops2(.reg16, .rm16),       Op2(0x0F, 0x49),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNS,  ops2(.reg32, .rm32),       Op2(0x0F, 0x49),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNS,  ops2(.reg64, .rm64),       Op2(0x0F, 0x49),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVNZ,  ops2(.reg16, .rm16),       Op2(0x0F, 0x45),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNZ,  ops2(.reg32, .rm32),       Op2(0x0F, 0x45),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVNZ,  ops2(.reg64, .rm64),       Op2(0x0F, 0x45),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVO,   ops2(.reg16, .rm16),       Op2(0x0F, 0x40),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVO,   ops2(.reg32, .rm32),       Op2(0x0F, 0x40),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVO,   ops2(.reg64, .rm64),       Op2(0x0F, 0x40),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVP,   ops2(.reg16, .rm16),       Op2(0x0F, 0x4A),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVP,   ops2(.reg32, .rm32),       Op2(0x0F, 0x4A),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVP,   ops2(.reg64, .rm64),       Op2(0x0F, 0x4A),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVPE,  ops2(.reg16, .rm16),       Op2(0x0F, 0x4A),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVPE,  ops2(.reg32, .rm32),       Op2(0x0F, 0x4A),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVPE,  ops2(.reg64, .rm64),       Op2(0x0F, 0x4A),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVPO,  ops2(.reg16, .rm16),       Op2(0x0F, 0x4B),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVPO,  ops2(.reg32, .rm32),       Op2(0x0F, 0x4B),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVPO,  ops2(.reg64, .rm64),       Op2(0x0F, 0x4B),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVS,   ops2(.reg16, .rm16),       Op2(0x0F, 0x48),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVS,   ops2(.reg32, .rm32),       Op2(0x0F, 0x48),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVS,   ops2(.reg64, .rm64),       Op2(0x0F, 0x48),        .RM, .RM32,       .{cpu.P6, x86_64} ),
    //
    instr(.CMOVZ,   ops2(.reg16, .rm16),       Op2(0x0F, 0x44),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVZ,   ops2(.reg32, .rm32),       Op2(0x0F, 0x44),        .RM, .RM32,       .{cpu.P6} ),
    instr(.CMOVZ,   ops2(.reg64, .rm64),       Op2(0x0F, 0x44),        .RM, .RM32,       .{cpu.P6, x86_64} ),
// UD
    instr(.UD0, ops2(.reg16, .rm16),          Op2(0x0F, 0xFF),        .RM, .RM32,       .{cpu.PentPro} ),
    instr(.UD0, ops2(.reg32, .rm32),          Op2(0x0F, 0xFF),        .RM, .RM32,       .{cpu.PentPro} ),
    instr(.UD0, ops2(.reg64, .rm64),          Op2(0x0F, 0xFF),        .RM, .RM32,       .{cpu.PentPro} ),
    //
    instr(.UD1, ops2(.reg16, .rm16),          Op2(0x0F, 0xB9),        .RM, .RM32,       .{cpu.PentPro} ),
    instr(.UD1, ops2(.reg32, .rm32),          Op2(0x0F, 0xB9),        .RM, .RM32,       .{cpu.PentPro} ),
    instr(.UD1, ops2(.reg64, .rm64),          Op2(0x0F, 0xB9),        .RM, .RM32,       .{cpu.PentPro} ),
    //
    instr(.UD2, ops0(),                       Op2(0x0F, 0x0B),        .ZO, .ZO,         .{cpu.PentPro} ),

//
// Pentium II
//
    instr(.SYSENTER, ops0(),                  Op2(0x0F, 0x34),        .ZO, .ZO,         .{cpu.Pent2} ),
    instr(.SYSEXIT,  ops0(),                  Op2(0x0F, 0x35),        .ZO, .ZO,         .{cpu.Pent2} ),
    instr(.SYSEXITQ, ops0(),                  Op2(0x0F, 0x35),        .ZO64, .RM32,     .{cpu.Pent2} ),

//
// x86-64
//
    instr(.RDTSCP, ops0(),                    Op3(0x0F, 0x01, 0xF9),   .ZO, .ZO,         .{x86_64} ),
    instr(.SWAPGS, ops0(),                    Op3(0x0F, 0x01, 0xF8),   .ZO, .ZO,         .{x86_64} ),

//
// bit manipulation (ABM / BMI1 / BMI2 / TBM)
//
// LZCNT
    instr(.LZCNT,   ops2(.reg16, .rm16),   preOp2(0xF3, 0x0F, 0xBD),   .RM, .RM32,       .{cpu.ABM} ),
    instr(.LZCNT,   ops2(.reg32, .rm32),   preOp2(0xF3, 0x0F, 0xBD),   .RM, .RM32,       .{cpu.ABM} ),
    instr(.LZCNT,   ops2(.reg64, .rm64),   preOp2(0xF3, 0x0F, 0xBD),   .RM, .RM32,       .{cpu.ABM, x86_64} ),
// LZCNT
    instr(.POPCNT,  ops2(.reg16, .rm16),   preOp2(0xF3, 0x0F, 0xB8),   .RM, .RM32,       .{cpu.ABM} ),
    instr(.POPCNT,  ops2(.reg32, .rm32),   preOp2(0xF3, 0x0F, 0xB8),   .RM, .RM32,       .{cpu.ABM} ),
    instr(.POPCNT,  ops2(.reg64, .rm64),   preOp2(0xF3, 0x0F, 0xB8),   .RM, .RM32,       .{cpu.ABM, x86_64} ),
// TZCNT
    instr(.TZCNT,   ops2(.reg16, .rm16),   preOp2(0xF3, 0x0F, 0xBC),   .RM, .RM32,       .{cpu.BMI1} ),
    instr(.TZCNT,   ops2(.reg32, .rm32),   preOp2(0xF3, 0x0F, 0xBC),   .RM, .RM32,       .{cpu.BMI1} ),
    instr(.TZCNT,   ops2(.reg64, .rm64),   preOp2(0xF3, 0x0F, 0xBC),   .RM, .RM32,       .{cpu.BMI1, x86_64} ),
    // TODO: VEX instructions

//
// SSE non-VEX/EVEX opcodes
//
// PREFETCH
    instr(.PREFETCHNTA, ops1(.rm_mem8),             Op2r(0x0F, 0x18, 0),          .M,  .RM8,       .{SSE} ),
    instr(.PREFETCHT0,  ops1(.rm_mem8),             Op2r(0x0F, 0x18, 1),          .M,  .RM8,       .{SSE} ),
    instr(.PREFETCHT1,  ops1(.rm_mem8),             Op2r(0x0F, 0x18, 2),          .M,  .RM8,       .{SSE} ),
    instr(.PREFETCHT2,  ops1(.rm_mem8),             Op2r(0x0F, 0x18, 3),          .M,  .RM8,       .{SSE} ),
// SFENCE
    instr(.SFENCE,      ops0(),                   npOp3(0x0F, 0xAE, 0xF8),        .ZO, .ZO,        .{SSE} ),
// CLFLUSH
    instr(.CLFLUSH,     ops1(.rm_mem8),           npOp2r(0x0F, 0xAE, 7),          .M,  .RM8,       .{SSE2} ),
// LFENCE
    instr(.LFENCE,      ops0(),                   npOp3(0x0F, 0xAE, 0xE8),        .ZO, .ZO,        .{SSE2} ),
// MFENCE
    instr(.MFENCE,      ops0(),                   npOp3(0x0F, 0xAE, 0xF0),        .ZO, .ZO,        .{SSE2} ),
// MOVNTI
    instr(.MOVNTI,      ops2(.rm_mem32, .reg32),  npOp2(0x0F, 0xC3),              .MR, .RM32,      .{SSE2} ),
    instr(.MOVNTI,      ops2(.rm_mem64, .reg64),  npOp2(0x0F, 0xC3),              .MR, .RM32,      .{SSE2} ),
// PAUSE
    instr(.PAUSE,       ops0(),                  preOp1(0xF3, 0x90),              .ZO, .ZO,        .{SSE2} ),
// MONITOR
    instr(.MONITOR,     ops0(),                     Op3(0x0F, 0x01, 0xC8),        .ZO, .ZO,        .{SSE3} ),
// MWAIT
    instr(.MWAIT,       ops0(),                     Op3(0x0F, 0x01, 0xC9),        .ZO, .ZO,        .{SSE3} ),
// CRC32
    instr(.CRC32,       ops2(.reg32, .rm8),      preOp3(0xF2, 0x0F, 0x38, 0xF0),  .RM, .RM32_Reg,  .{SSE4_2} ),
    instr(.CRC32,       ops2(.reg64, .rm8),      preOp3(0xF2, 0x0F, 0x38, 0xF0),  .RM, .RM32_Reg,  .{SSE4_2} ),
    instr(.CRC32,       ops2(.reg32, .rm16),     preOp3(0xF2, 0x0F, 0x38, 0xF1),  .RM, .RM32_RM,   .{SSE4_2} ),
    instr(.CRC32,       ops2(.reg32, .rm32),     preOp3(0xF2, 0x0F, 0x38, 0xF1),  .RM, .RM32_RM,   .{SSE4_2} ),
    instr(.CRC32,       ops2(.reg64, .rm64),     preOp3(0xF2, 0x0F, 0x38, 0xF1),  .RM, .RM32_RM,   .{SSE4_2} ),

//
// AMD-V
// CLGI
    instr(.CLGI, ops0(),                    Op3(0x0F, 0x01, 0xDD),   .ZO, .ZO,              .{cpu.AMD_V} ),
// INVLPGA
    instr(.INVLPGA, ops0(),                 Op3(0x0F, 0x01, 0xDF),   .ZO, .ZO,              .{cpu.AMD_V} ),
    instr(.INVLPGA, ops2(.reg_ax,.reg_ecx), Op3(0x0F, 0x01, 0xDF),   .ZO16, .RM8_Over16,    .{No64, cpu.AMD_V} ),
    instr(.INVLPGA, ops2(.reg_eax,.reg_ecx),Op3(0x0F, 0x01, 0xDF),   .ZO32, .RM8_Over32,    .{cpu.AMD_V} ),
    instr(.INVLPGA, ops2(.reg_rax,.reg_ecx),Op3(0x0F, 0x01, 0xDF),   .ZO64, .RM64,          .{No32, cpu.AMD_V} ),
// SKINIT
    instr(.SKINIT,  ops0(),                 Op3(0x0F, 0x01, 0xDE),   .ZO, .ZO,              .{cpu.AMD_V} ),
    instr(.SKINIT,  ops1(.reg_eax),         Op3(0x0F, 0x01, 0xDE),   .ZO, .ZO,              .{cpu.AMD_V} ),
// STGI
    instr(.STGI,    ops0(),                 Op3(0x0F, 0x01, 0xDC),   .ZO, .ZO,              .{cpu.AMD_V} ),
// VMLOAD
    instr(.VMLOAD,  ops0(),                 Op3(0x0F, 0x01, 0xDA),   .ZO, .ZO,              .{cpu.AMD_V} ),
    instr(.VMLOAD,  ops1(.reg_ax),          Op3(0x0F, 0x01, 0xDA),   .ZO16, .RM8_Over16,    .{No64, cpu.AMD_V} ),
    instr(.VMLOAD,  ops1(.reg_eax),         Op3(0x0F, 0x01, 0xDA),   .ZO32, .RM8_Over32,    .{cpu.AMD_V} ),
    instr(.VMLOAD,  ops1(.reg_rax),         Op3(0x0F, 0x01, 0xDA),   .ZO64, .RM64,          .{No32, cpu.AMD_V} ),
// VMMCALL
    instr(.VMMCALL, ops0(),                 Op3(0x0F, 0x01, 0xD9),   .ZO, .ZO,              .{cpu.AMD_V} ),
// VMRUN
    instr(.VMRUN,   ops0(),                 Op3(0x0F, 0x01, 0xD8),   .ZO, .ZO,              .{cpu.AMD_V} ),
    instr(.VMRUN,   ops1(.reg_ax),          Op3(0x0F, 0x01, 0xD8),   .ZO16, .RM8_Over16,    .{No64, cpu.AMD_V} ),
    instr(.VMRUN,   ops1(.reg_eax),         Op3(0x0F, 0x01, 0xD8),   .ZO32, .RM8_Over32,    .{cpu.AMD_V} ),
    instr(.VMRUN,   ops1(.reg_rax),         Op3(0x0F, 0x01, 0xD8),   .ZO64, .RM64,          .{No32, cpu.AMD_V} ),
// VMSAVE
    instr(.VMSAVE,  ops0(),                 Op3(0x0F, 0x01, 0xDB),   .ZO, .ZO,              .{cpu.AMD_V} ),
    instr(.VMSAVE,  ops1(.reg_ax),          Op3(0x0F, 0x01, 0xDB),   .ZO16, .RM8_Over16,    .{No64, cpu.AMD_V} ),
    instr(.VMSAVE,  ops1(.reg_eax),         Op3(0x0F, 0x01, 0xDB),   .ZO32, .RM8_Over32,    .{cpu.AMD_V} ),
    instr(.VMSAVE,  ops1(.reg_rax),         Op3(0x0F, 0x01, 0xDB),   .ZO64, .RM64,          .{No32, cpu.AMD_V} ),

//
// Intel VT-x
//
// INVEPT
    instr(.INVEPT,   ops2(.reg32, .rm_mem128), preOp3(0x66, 0x0F, 0x38, 0x80),  .M, .ZO,   .{No64, cpu.VT_x} ),
    instr(.INVEPT,   ops2(.reg64, .rm_mem128), preOp3(0x66, 0x0F, 0x38, 0x80),  .M, .ZO,   .{No32, cpu.VT_x} ),
// INVVPID
    instr(.INVVPID,  ops2(.reg32, .rm_mem128), preOp3(0x66, 0x0F, 0x38, 0x80),  .M, .ZO,   .{No64, cpu.VT_x} ),
    instr(.INVVPID,  ops2(.reg64, .rm_mem128), preOp3(0x66, 0x0F, 0x38, 0x80),  .M, .ZO,   .{No32, cpu.VT_x} ),
// VMCLEAR
    instr(.VMCLEAR,  ops1(.rm_mem64),          preOp2r(0x66, 0x0F, 0xC7, 6), .M, .RM64,   .{cpu.VT_x} ),
// VMFUNC
    instr(.VMFUNC,   ops0(),                    npOp3(0x0F, 0x01, 0xD4),     .ZO, .ZO,    .{cpu.VT_x} ),
// VMPTRLD
    instr(.VMPTRLD,  ops1(.rm_mem64),           npOp2r(0x0F, 0xC7, 6),       .M, .RM64,   .{cpu.VT_x} ),
// VMPTRST
    instr(.VMPTRST,  ops1(.rm_mem64),           npOp2r(0x0F, 0xC7, 7),       .M, .RM64,   .{cpu.VT_x} ),
// VMREAD
    instr(.VMREAD,   ops2(.rm32, .reg32),       npOp2(0x0F, 0x78),           .MR, .RM32,  .{No64, cpu.VT_x} ),
    instr(.VMREAD,   ops2(.rm64, .reg64),       npOp2(0x0F, 0x78),           .MR, .RM64,  .{No32, cpu.VT_x} ),
// VMWRITE
    instr(.VMWRITE,  ops2(.reg32, .rm32),       npOp2(0x0F, 0x79),           .RM, .RM32,  .{No64, cpu.VT_x} ),
    instr(.VMWRITE,  ops2(.reg64, .rm64),       npOp2(0x0F, 0x79),           .RM, .RM64,  .{No32, cpu.VT_x} ),
// VMCALL
    instr(.VMCALL,   ops0(),                      Op3(0x0F, 0x01, 0xC1),     .ZO, .ZO,    .{cpu.VT_x} ),
// VMLAUNCH
    instr(.VMLAUNCH, ops0(),                      Op3(0x0F, 0x01, 0xC2),     .ZO, .ZO,    .{cpu.VT_x} ),
// VMRESUME
    instr(.VMRESUME, ops0(),                      Op3(0x0F, 0x01, 0xC3),     .ZO, .ZO,    .{cpu.VT_x} ),
// VMXOFF
    instr(.VMRESUME, ops0(),                      Op3(0x0F, 0x01, 0xC4),     .ZO, .ZO,    .{cpu.VT_x} ),
// VMXON
    instr(.VMXON,    ops1(.rm_mem64),             Op3r(0x0F, 0x01, 0xC7, 6), .M, .RM64,   .{cpu.VT_x} ),

//
// SIMD legacy instructions (MMX / Legacy SSE)
//
// MOVD
    instr(.MOVD,     ops2(.mm, .rm32),          npOp2(0x0F, 0x6E),           .RM, .RM32_RM, .{MMX} ),
    instr(.MOVD,     ops2(.rm32, .mm),          npOp2(0x0F, 0x7E),           .MR, .RM32_RM, .{MMX} ),
    instr(.MOVD,     ops2(.mm, .rm64),          npOp2(0x0F, 0x6E),           .RM, .RM32_RM, .{MMX} ),
    instr(.MOVD,     ops2(.rm64, .mm),          npOp2(0x0F, 0x7E),           .MR, .RM32_RM, .{MMX} ),
    // xmm
    instr(.MOVD,     ops2(.xmml, .rm32),       preOp2(0x66, 0x0F, 0x6E),     .RM, .RM32_RM, .{SSE2} ),
    instr(.MOVD,     ops2(.rm32, .xmml),       preOp2(0x66, 0x0F, 0x7E),     .MR, .RM32_RM, .{SSE2} ),
    instr(.MOVD,     ops2(.xmml, .rm64),       preOp2(0x66, 0x0F, 0x6E),     .RM, .RM32_RM, .{SSE2} ),
    instr(.MOVD,     ops2(.rm64, .xmml),       preOp2(0x66, 0x0F, 0x7E),     .MR, .RM32_RM, .{SSE2} ),
// MOVQ
    instr(.MOVQ,     ops2(.mm, .mm_m64),        npOp2(0x0F, 0x6F),           .RM, .ZO,      .{MMX} ),
    instr(.MOVQ,     ops2(.mm_m64, .mm),        npOp2(0x0F, 0x7F),           .MR, .ZO,      .{MMX} ),
    instr(.MOVQ,     ops2(.mm, .rm64),          npOp2(0x0F, 0x6E),           .RM, .RM32_RM, .{MMX} ),
    instr(.MOVQ,     ops2(.rm64, .mm),          npOp2(0x0F, 0x7E),           .MR, .RM32_RM, .{MMX} ),
    // xmm
    instr(.MOVQ,     ops2(.xmml, .xmml_m64),   preOp2(0xF3, 0x0F, 0x7E),     .RM, .ZO,      .{SSE2} ),
    instr(.MOVQ,     ops2(.xmml_m64, .xmml),   preOp2(0x66, 0x0F, 0xD6),     .MR, .ZO,      .{SSE2} ),
    instr(.MOVQ,     ops2(.xmml, .rm64),       preOp2(0x66, 0x0F, 0x6E),     .RM, .RM32_RM, .{SSE2} ),
    instr(.MOVQ,     ops2(.rm64, .xmml),       preOp2(0x66, 0x0F, 0x7E),     .MR, .RM32_RM, .{SSE2} ),
// PACKSSWB / PACKSSDW
    instr(.PACKSSWB,  ops2(.mm, .mm_m64),            npOp2(0x0F, 0x63),           .RM, .ZO, .{MMX} ),
    instr(.PACKSSWB,  ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x63),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PACKSSDW,  ops2(.mm, .mm_m64),            npOp2(0x0F, 0x6B),           .RM, .ZO, .{MMX} ),
    instr(.PACKSSDW,  ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x6B),     .RM, .ZO, .{SSE2} ),
// PACKUSWB
    instr(.PACKUSWB,  ops2(.mm, .mm_m64),            npOp2(0x0F, 0x67),           .RM, .ZO, .{MMX} ),
    instr(.PACKUSWB,  ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x67),     .RM, .ZO, .{SSE2} ),
// PACKUSDW
    instr(.PACKUSDW,  ops2(.xmml, .xmml_m128),      preOp3(0x66, 0x0F, 0x38,0x2B),.RM, .ZO, .{SSE4_1} ),
// PADDB / PADDW / PADDD / PADDQ
    instr(.PADDB,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xFC),           .RM, .ZO, .{MMX} ),
    instr(.PADDB,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xFC),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PADDW,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xFD),           .RM, .ZO, .{MMX} ),
    instr(.PADDW,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xFD),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PADDD,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xFE),           .RM, .ZO, .{MMX} ),
    instr(.PADDD,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xFE),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PADDQ,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xD4),           .RM, .ZO, .{MMX} ),
    instr(.PADDQ,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xD4),     .RM, .ZO, .{SSE2} ),
// PADDSB / PADDSW
    instr(.PADDSB,    ops2(.mm, .mm_m64),            npOp2(0x0F, 0xEC),           .RM, .ZO, .{MMX} ),
    instr(.PADDSB,    ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xEC),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PADDSW,    ops2(.mm, .mm_m64),            npOp2(0x0F, 0xED),           .RM, .ZO, .{MMX} ),
    instr(.PADDSW,    ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xED),     .RM, .ZO, .{SSE2} ),
// PADDUSB / PADDSW
    instr(.PADDUSB,   ops2(.mm, .mm_m64),            npOp2(0x0F, 0xDC),           .RM, .ZO, .{MMX} ),
    instr(.PADDUSB,   ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xDC),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PADDUSW,   ops2(.mm, .mm_m64),            npOp2(0x0F, 0xDD),           .RM, .ZO, .{MMX} ),
    instr(.PADDUSW,   ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xDD),     .RM, .ZO, .{SSE2} ),
// PAND
    instr(.PAND,      ops2(.mm, .mm_m64),            npOp2(0x0F, 0xDB),           .RM, .ZO, .{MMX} ),
    instr(.PAND,      ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xDB),     .RM, .ZO, .{SSE2} ),
// PANDN
    instr(.PANDN,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xDF),           .RM, .ZO, .{MMX} ),
    instr(.PANDN,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xDF),     .RM, .ZO, .{SSE2} ),
// PAVGB / PAVGW
    instr(.PAVGB,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xE0),           .RM, .ZO, .{SSE} ),
    instr(.PAVGB,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xE0),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PAVGW,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xE3),           .RM, .ZO, .{SSE} ),
    instr(.PAVGW,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xE3),     .RM, .ZO, .{SSE2} ),
// PBLENDVB
    instr(.PBLENDVB,  ops3(.xmml,.xmml_m128,.xmm0), preOp3(0x66,0x0F,0x38,0x10),  .RM, .ZO, .{SSE4_1} ),
    instr(.PBLENDVB,  ops2(.xmml,.xmml_m128),       preOp3(0x66,0x0F,0x38,0x10),  .RM, .ZO, .{SSE4_1} ),
// PBLENDVW
    instr(.PBLENDW,   ops3(.xmml,.xmml_m128,.imm8), preOp3(0x66,0x0F,0x3A,0x0E),  .RMI,.ZO, .{SSE4_1} ),
// PCMPEQB / PCMPEQW / PCMPEQD
    instr(.PCMPEQB,   ops2(.mm, .mm_m64),            npOp2(0x0F, 0x74),           .RM, .ZO, .{MMX} ),
    instr(.PCMPEQB,   ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x74),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PCMPEQW,   ops2(.mm, .mm_m64),            npOp2(0x0F, 0x75),           .RM, .ZO, .{MMX} ),
    instr(.PCMPEQW,   ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x75),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PCMPEQD,   ops2(.mm, .mm_m64),            npOp2(0x0F, 0x76),           .RM, .ZO, .{MMX} ),
    instr(.PCMPEQD,   ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x76),     .RM, .ZO, .{SSE2} ),
// PCMPEQQ
    instr(.PCMPEQQ,   ops2(.xmml, .xmml_m128),      preOp3(0x66,0x0F,0x38,0x29),  .RM, .ZO, .{SSE2} ),
// PCMPESTRI
    instr(.PCMPESTRI, ops3(.xmml,.xmml_m128,.imm8), preOp3(0x66,0x0F,0x3A,0x61),  .RMI,.ZO, .{SSE4_2} ),
// PCMPESTRM
    instr(.PCMPESTRM, ops3(.xmml,.xmml_m128,.imm8), preOp3(0x66,0x0F,0x3A,0x60),  .RMI,.ZO, .{SSE4_2} ),
// PCMPGTB / PCMPGTW / PCMPGTD
    instr(.PCMPGTB,   ops2(.mm, .mm_m64),            npOp2(0x0F, 0x64),           .RM, .ZO, .{MMX} ),
    instr(.PCMPGTB,   ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x64),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PCMPGTW,   ops2(.mm, .mm_m64),            npOp2(0x0F, 0x65),           .RM, .ZO, .{MMX} ),
    instr(.PCMPGTW,   ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x65),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PCMPGTD,   ops2(.mm, .mm_m64),            npOp2(0x0F, 0x66),           .RM, .ZO, .{MMX} ),
    instr(.PCMPGTD,   ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x66),     .RM, .ZO, .{SSE2} ),
// PCMPISTRI
    instr(.PCMPISTRI, ops3(.xmml,.xmml_m128,.imm8), preOp3(0x66,0x0F,0x3A,0x63),  .RMI,.ZO, .{SSE4_2} ),
// PCMPISTRM
    instr(.PCMPISTRM, ops3(.xmml,.xmml_m128,.imm8), preOp3(0x66,0x0F,0x3A,0x62),  .RMI,.ZO, .{SSE4_2} ),
// PEXTRB / PEXTRD / PEXTRQ
    instr(.PEXTRB,    ops3(.rm_mem8, .xmml, .imm8), preOp3(0x66,0x0F,0x3A,0x14),  .MRI,.ZO, .{SSE4_1} ),
    instr(.PEXTRB,    ops3(.reg32, .xmml, .imm8),   preOp3(0x66,0x0F,0x3A,0x14),  .MRI,.ZO, .{SSE4_1} ),
    instr(.PEXTRB,    ops3(.reg64, .xmml, .imm8),   preOp3(0x66,0x0F,0x3A,0x14),  .MRI,.ZO, .{SSE4_1, No32} ),
    instr(.PEXTRD,    ops3(.rm32, .xmml, .imm8),    preOp3(0x66,0x0F,0x3A,0x16),  .MRI,.RM32_RM, .{SSE4_1} ),
    instr(.PEXTRQ,    ops3(.rm64, .xmml, .imm8),    preOp3(0x66,0x0F,0x3A,0x16),  .MRI,.RM32_RM, .{SSE4_1} ),
// PEXTRW
    instr(.PEXTRW,    ops3(.reg16, .mm, .imm8),      npOp2(0x0F,0xC5),            .MRI,.ZO, .{SSE} ),
    instr(.PEXTRW,    ops3(.reg32, .mm, .imm8),      npOp2(0x0F,0xC5),            .MRI,.ZO, .{SSE} ),
    instr(.PEXTRW,    ops3(.reg64, .mm, .imm8),      npOp2(0x0F,0xC5),            .MRI,.ZO, .{SSE, No32} ),
    instr(.PEXTRW,    ops3(.reg16, .xmml, .imm8),   preOp2(0x66,0x0F,0xC5),       .MRI,.ZO, .{SSE2} ),
    instr(.PEXTRW,    ops3(.reg32, .xmml, .imm8),   preOp2(0x66,0x0F,0xC5),       .MRI,.ZO, .{SSE2} ),
    instr(.PEXTRW,    ops3(.reg64, .xmml, .imm8),   preOp2(0x66,0x0F,0xC5),       .MRI,.ZO, .{SSE2, No32} ),
    instr(.PEXTRW,    ops3(.rm16, .xmml, .imm8),    preOp3(0x66,0x0F,0x3A,0x15),  .MRI,.ZO, .{SSE4_1} ),
    instr(.PEXTRW,    ops3(.rm_reg32, .xmml, .imm8),preOp3(0x66,0x0F,0x3A,0x15),  .MRI,.ZO, .{SSE4_1} ),
    instr(.PEXTRW,    ops3(.rm_reg64, .xmml, .imm8),preOp3(0x66,0x0F,0x3A,0x15),  .MRI,.ZO, .{SSE4_1, No32} ),
    instr(.PEXTRW,    ops3(.reg32, .xmml, .imm8),   preOp3(0x66,0x0F,0x3A,0x15),  .MRI,.ZO, .{SSE4_1} ),
    instr(.PEXTRW,    ops3(.reg64, .xmml, .imm8),   preOp3(0x66,0x0F,0x3A,0x15),  .MRI,.ZO, .{SSE4_1, No32} ),
// PMADDWD
    instr(.PMADDWD,   ops2(.mm, .mm_m64),            npOp2(0x0F, 0xF5),           .RM, .ZO, .{MMX} ),
    instr(.PMADDWD,   ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xF5),     .RM, .ZO, .{SSE2} ),
// PMULHW
    instr(.PMULHW,    ops2(.mm, .mm_m64),            npOp2(0x0F, 0xE5),           .RM, .ZO, .{MMX} ),
    instr(.PMULHW,    ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xE5),     .RM, .ZO, .{SSE2} ),
// PMULLW
    instr(.PMULLW,    ops2(.mm, .mm_m64),            npOp2(0x0F, 0xD5),           .RM, .ZO, .{MMX} ),
    instr(.PMULLW,    ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xD5),     .RM, .ZO, .{SSE2} ),
// POR
    instr(.POR,       ops2(.mm, .mm_m64),            npOp2(0x0F, 0xEB),           .RM, .ZO, .{MMX} ),
    instr(.POR,       ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xEB),     .RM, .ZO, .{SSE2} ),
// PSLLW
    instr(.PSLLW,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xF1),           .RM, .ZO, .{MMX} ),
    instr(.PSLLW,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xF1),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PSLLW,     ops2(.mm, .imm8),              npOp2r(0x0F, 0x71, 6),       .MI, .ZO, .{MMX} ),
    instr(.PSLLW,     ops2(.xmml, .imm8),           preOp2r(0x66, 0x0F, 0x71, 6), .MI, .ZO, .{SSE2} ),
// PSLLD
    instr(.PSLLD,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xF2),           .RM, .ZO, .{MMX} ),
    instr(.PSLLD,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xF2),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PSLLD,     ops2(.mm, .imm8),              npOp2r(0x0F, 0x72, 6),       .MI, .ZO, .{MMX} ),
    instr(.PSLLD,     ops2(.xmml, .imm8),           preOp2r(0x66, 0x0F, 0x72, 6), .MI, .ZO, .{SSE2} ),
// PSLLQ
    instr(.PSLLQ,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xF3),           .RM, .ZO, .{MMX} ),
    instr(.PSLLQ,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xF3),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PSLLQ,     ops2(.mm, .imm8),              npOp2r(0x0F, 0x73, 6),       .MI, .ZO, .{MMX} ),
    instr(.PSLLQ,     ops2(.xmml, .imm8),           preOp2r(0x66, 0x0F, 0x73, 6), .MI, .ZO, .{SSE2} ),
// PSRAW
    instr(.PSRAW,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xE1),           .RM, .ZO, .{MMX} ),
    instr(.PSRAW,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xE1),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PSRAW,     ops2(.mm, .imm8),              npOp2r(0x0F, 0x71, 4),       .MI, .ZO, .{MMX} ),
    instr(.PSRAW,     ops2(.xmml, .imm8),           preOp2r(0x66, 0x0F, 0x71, 4), .MI, .ZO, .{SSE2} ),
// PSRAD
    instr(.PSRAD,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xE2),           .RM, .ZO, .{MMX} ),
    instr(.PSRAD,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xE2),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PSRAD,     ops2(.mm, .imm8),              npOp2r(0x0F, 0x72, 4),       .MI, .ZO, .{MMX} ),
    instr(.PSRAD,     ops2(.xmml, .imm8),           preOp2r(0x66, 0x0F, 0x72, 4), .MI, .ZO, .{SSE2} ),
// PSRLW
    instr(.PSRLW,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xD1),           .RM, .ZO, .{MMX} ),
    instr(.PSRLW,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xD1),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PSRLW,     ops2(.mm, .imm8),              npOp2r(0x0F, 0x71, 2),       .MI, .ZO, .{MMX} ),
    instr(.PSRLW,     ops2(.xmml, .imm8),           preOp2r(0x66, 0x0F, 0x71, 2), .MI, .ZO, .{SSE2} ),
// PSRLD
    instr(.PSRLD,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xD2),           .RM, .ZO, .{MMX} ),
    instr(.PSRLD,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xD2),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PSRLD,     ops2(.mm, .imm8),              npOp2r(0x0F, 0x72, 2),       .MI, .ZO, .{MMX} ),
    instr(.PSRLD,     ops2(.xmml, .imm8),           preOp2r(0x66, 0x0F, 0x72, 2), .MI, .ZO, .{SSE2} ),
// PSRLQ
    instr(.PSRLQ,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xD3),           .RM, .ZO, .{MMX} ),
    instr(.PSRLQ,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xD3),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PSRLQ,     ops2(.mm, .imm8),              npOp2r(0x0F, 0x73, 2),       .MI, .ZO, .{MMX} ),
    instr(.PSRLQ,     ops2(.xmml, .imm8),           preOp2r(0x66, 0x0F, 0x73, 2), .MI, .ZO, .{SSE2} ),
// PSUBB / PSUBW / PSUBD
    instr(.PSUBB,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xF8),           .RM, .ZO, .{MMX} ),
    instr(.PSUBB,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xF8),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PSUBW,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xF9),           .RM, .ZO, .{MMX} ),
    instr(.PSUBW,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xF9),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PSUBD,     ops2(.mm, .mm_m64),            npOp2(0x0F, 0xFA),           .RM, .ZO, .{MMX} ),
    instr(.PSUBD,     ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xFA),     .RM, .ZO, .{SSE2} ),
// PSUBSB
    instr(.PSUBSB,    ops2(.mm, .mm_m64),            npOp2(0x0F, 0xE8),           .RM, .ZO, .{MMX} ),
    instr(.PSUBSB,    ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xE8),     .RM, .ZO, .{SSE2} ),
// PSUBSW
    instr(.PSUBSW,    ops2(.mm, .mm_m64),            npOp2(0x0F, 0xE9),           .RM, .ZO, .{MMX} ),
    instr(.PSUBSW,    ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xE9),     .RM, .ZO, .{SSE2} ),
// PSUBUSB / PSUBUSW
    instr(.PSUBUSB,   ops2(.mm, .mm_m64),            npOp2(0x0F, 0xD8),           .RM, .ZO, .{MMX} ),
    instr(.PSUBUSB,   ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xD8),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PSUBUSW,   ops2(.mm, .mm_m64),            npOp2(0x0F, 0xD9),           .RM, .ZO, .{MMX} ),
    instr(.PSUBUSW,   ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xD9),     .RM, .ZO, .{SSE2} ),
// PUNPCKHBW / PUNPCKHWD / PUNPCKHDQ
    instr(.PUNPCKHBW, ops2(.mm, .mm_m64),            npOp2(0x0F, 0x68),           .RM, .ZO, .{MMX} ),
    instr(.PUNPCKHBW, ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x68),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PUNPCKHWD, ops2(.mm, .mm_m64),            npOp2(0x0F, 0x69),           .RM, .ZO, .{MMX} ),
    instr(.PUNPCKHWD, ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x69),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PUNPCKHDQ, ops2(.mm, .mm_m64),            npOp2(0x0F, 0x6A),           .RM, .ZO, .{MMX} ),
    instr(.PUNPCKHDQ, ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x6A),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PUNPCKHQDQ,ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x6D),     .RM, .ZO, .{SSE2} ),
// PUNPCKLBW / PUNPCKLWD / PUNPCKLDQ
    instr(.PUNPCKLBW, ops2(.mm, .mm_m64),            npOp2(0x0F, 0x60),           .RM, .ZO, .{MMX} ),
    instr(.PUNPCKLBW, ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x60),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PUNPCKLWD, ops2(.mm, .mm_m64),            npOp2(0x0F, 0x61),           .RM, .ZO, .{MMX} ),
    instr(.PUNPCKLWD, ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x61),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PUNPCKLDQ, ops2(.mm, .mm_m64),            npOp2(0x0F, 0x62),           .RM, .ZO, .{MMX} ),
    instr(.PUNPCKLDQ, ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x62),     .RM, .ZO, .{SSE2} ),
    //
    instr(.PUNPCKLQDQ,ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0x6C),     .RM, .ZO, .{SSE2} ),
// PXOR
    instr(.PXOR,      ops2(.mm, .mm_m64),            npOp2(0x0F, 0xEF),           .RM, .ZO, .{MMX} ),
    instr(.PXOR,      ops2(.xmml, .xmml_m128),      preOp2(0x66, 0x0F, 0xEF),     .RM, .ZO, .{SSE2} ),

//
// SIMD vector instructions (AVX, AVX2, AVX512)
//
// MOVD
    // xmm[0..15]
    instr(.VMOVD,      ops2(.xmml, .rm32),                      vex(.L128,._66,._0F,.W0, 0x6E),    .VM, .RM32, .{AVX} ),
    instr(.VMOVD,      ops2(.rm32, .xmml),                      vex(.L128,._66,._0F,.W0, 0x7E),    .MV, .RM32, .{AVX} ),
    instr(.VMOVD,      ops2(.xmml, .rm64),                      vex(.L128,._66,._0F,.W1, 0x6E),    .VM, .RM32, .{AVX} ),
    instr(.VMOVD,      ops2(.rm64, .xmml),                      vex(.L128,._66,._0F,.W1, 0x7E),    .MV, .RM32, .{AVX} ),
    // xmm[0..31]
    instr(.VMOVD,      ops2(.xmm, .rm32),                      evex(.L128,._66,._0F,.W0, 0x6E),    .VM, .RM32, .{AVX512F} ),
    instr(.VMOVD,      ops2(.rm32, .xmm),                      evex(.L128,._66,._0F,.W0, 0x7E),    .MV, .RM32, .{AVX512F} ),
    instr(.VMOVD,      ops2(.xmm, .rm64),                      evex(.L128,._66,._0F,.W1, 0x6E),    .VM, .RM32, .{AVX512F} ),
    instr(.VMOVD,      ops2(.rm64, .xmm),                      evex(.L128,._66,._0F,.W1, 0x7E),    .MV, .RM32, .{AVX512F} ),
// MOVQ
    // xmm[0..15]
    instr(.VMOVQ,      ops2(.xmml, .xmml_m64),                  vex(.L128,._F3,._0F,.WIG,0x7E),    .VM, .ZO,   .{AVX} ),
    instr(.VMOVQ,      ops2(.xmml_m64, .xmml),                  vex(.L128,._66,._0F,.WIG,0xD6),    .MV, .ZO,   .{AVX} ),
    instr(.VMOVQ,      ops2(.xmml, .rm64),                      vex(.L128,._66,._0F,.W1, 0x6E),    .VM, .RM32, .{AVX} ),
    instr(.VMOVQ,      ops2(.rm64, .xmml),                      vex(.L128,._66,._0F,.W1, 0x7E),    .MV, .RM32, .{AVX} ),
    // xmm[0..31]
    instr(.VMOVQ,      ops2(.xmm, .xmm_m64),                   evex(.L128,._F3,._0F,.W1, 0x7E),    .VM, .ZO,   .{AVX512F} ),
    instr(.VMOVQ,      ops2(.xmm_m64, .xmm),                   evex(.L128,._66,._0F,.W1, 0xD6),    .MV, .ZO,   .{AVX512F} ),
    instr(.VMOVQ,      ops2(.xmm, .rm64),                      evex(.L128,._66,._0F,.W1, 0x6E),    .VM, .RM32, .{AVX512F} ),
    instr(.VMOVQ,      ops2(.rm64, .xmm),                      evex(.L128,._66,._0F,.W1, 0x7E),    .MV, .RM32, .{AVX512F} ),
// VPACKSSWB / PACKSSDW
    // VPACKSSWB
    instr(.VPACKSSWB,  ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG,0x63),    .VVM, .ZO,  .{AVX} ),
    instr(.VPACKSSWB,  ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG,0x63),    .VVM, .ZO,  .{AVX2} ),
    instr(.VPACKSSWB,  ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG,0x63),    .VVM, .ZO,  .{AVX512VL, AVX512BW} ),
    instr(.VPACKSSWB,  ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG,0x63),    .VVM, .ZO,  .{AVX512VL, AVX512BW} ),
    instr(.VPACKSSWB,  ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG,0x63),    .VVM, .ZO,  .{AVX512BW} ),
    // VPACKSSDW
    instr(.VPACKSSDW,  ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG,0x6B),    .VVM, .ZO,  .{AVX} ),
    instr(.VPACKSSDW,  ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG,0x6B),    .VVM, .ZO,  .{AVX2} ),
    instr(.VPACKSSDW,  ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128,._66,._0F,.W0, 0x6B),    .VVM, .ZO,  .{AVX512VL, AVX512BW} ),
    instr(.VPACKSSDW,  ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256,._66,._0F,.W0, 0x6B),    .VVM, .ZO,  .{AVX512VL, AVX512BW} ),
    instr(.VPACKSSDW,  ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512,._66,._0F,.W0, 0x6B),    .VVM, .ZO,  .{AVX512BW} ),
// VPACKUSWB
    instr(.VPACKUSWB,  ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG,0x67),    .VVM, .ZO,  .{AVX} ),
    instr(.VPACKUSWB,  ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG,0x67),    .VVM, .ZO,  .{AVX2} ),
    instr(.VPACKUSWB,  ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG,0x67),    .VVM, .ZO,  .{AVX512VL, AVX512BW} ),
    instr(.VPACKUSWB,  ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG,0x67),    .VVM, .ZO,  .{AVX512VL, AVX512BW} ),
    instr(.VPACKUSWB,  ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG,0x67),    .VVM, .ZO,  .{AVX512BW} ),
// VPACKUSDW
    instr(.VPACKUSDW,  ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F38,.WIG,0x2B),  .VVM, .ZO,  .{AVX} ),
    instr(.VPACKUSDW,  ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F38,.WIG,0x2B),  .VVM, .ZO,  .{AVX2} ),
    instr(.VPACKUSDW,  ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F38,.W0,0x2B),   .VVM, .ZO,  .{AVX512VL, AVX512BW} ),
    instr(.VPACKUSDW,  ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F38,.W0,0x2B),   .VVM, .ZO,  .{AVX512VL, AVX512BW} ),
    instr(.VPACKUSDW,  ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F38,.W0,0x2B),   .VVM, .ZO,  .{AVX512BW} ),
// VPADDB / PADDW / PADDD / PADDQ
    instr(.VPADDB,     ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0xFC),   .VVM, .ZO, .{AVX} ),
    instr(.VPADDB,     ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0xFC),   .VVM, .ZO, .{AVX2} ),
    instr(.VPADDB,     ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG, 0xFC),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPADDB,     ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG, 0xFC),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPADDB,     ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG, 0xFC),   .VVM, .ZO, .{AVX512BW} ),
    // VPADDW
    instr(.VPADDW,     ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0xFD),   .VVM, .ZO, .{AVX} ),
    instr(.VPADDW,     ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0xFD),   .VVM, .ZO, .{AVX2} ),
    instr(.VPADDW,     ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG, 0xFD),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPADDW,     ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG, 0xFD),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPADDW,     ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG, 0xFD),   .VVM, .ZO, .{AVX512BW} ),
    // VPADDD
    instr(.VPADDD,     ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0xFE),   .VVM, .ZO, .{AVX} ),
    instr(.VPADDD,     ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0xFE),   .VVM, .ZO, .{AVX2} ),
    instr(.VPADDD,     ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128,._66,._0F,.W0,  0xFE),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPADDD,     ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256,._66,._0F,.W0,  0xFE),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPADDD,     ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512,._66,._0F,.W0,  0xFE),   .VVM, .ZO, .{AVX512F} ),
    // VPADDQ
    instr(.VPADDQ,     ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0xD4),   .VVM, .ZO, .{AVX} ),
    instr(.VPADDQ,     ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0xD4),   .VVM, .ZO, .{AVX2} ),
    instr(.VPADDQ,     ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128,._66,._0F,.W1,  0xD4),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPADDQ,     ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256,._66,._0F,.W1,  0xD4),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPADDQ,     ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512,._66,._0F,.W1,  0xD4),   .VVM, .ZO, .{AVX512F} ),
// VPADDSB / PADDSW
    instr(.VPADDSB,    ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0xEC),   .VVM, .ZO, .{AVX} ),
    instr(.VPADDSB,    ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0xEC),   .VVM, .ZO, .{AVX2} ),
    instr(.VPADDSB,    ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG, 0xEC),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPADDSB,    ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG, 0xEC),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPADDSB,    ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG, 0xEC),   .VVM, .ZO, .{AVX512BW} ),
    //
    instr(.VPADDSW,    ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0xED),   .VVM, .ZO, .{AVX} ),
    instr(.VPADDSW,    ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0xED),   .VVM, .ZO, .{AVX2} ),
    instr(.VPADDSW,    ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG, 0xED),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPADDSW,    ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG, 0xED),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPADDSW,    ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG, 0xED),   .VVM, .ZO, .{AVX512BW} ),
// VPADDUSB / PADDUSW
    instr(.VPADDUSB,   ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0xDC),   .VVM, .ZO, .{AVX} ),
    instr(.VPADDUSB,   ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0xDC),   .VVM, .ZO, .{AVX2} ),
    instr(.VPADDUSB,   ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG, 0xDC),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPADDUSB,   ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG, 0xDC),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPADDUSB,   ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG, 0xDC),   .VVM, .ZO, .{AVX512BW} ),
    //
    instr(.VPADDUSW,   ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0xDD),   .VVM, .ZO, .{AVX} ),
    instr(.VPADDUSW,   ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0xDD),   .VVM, .ZO, .{AVX2} ),
    instr(.VPADDUSW,   ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG, 0xDD),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPADDUSW,   ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG, 0xDD),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPADDUSW,   ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG, 0xDD),   .VVM, .ZO, .{AVX512BW} ),
// VPAND
    instr(.VPAND,      ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0xDB),   .VVM, .ZO, .{AVX} ),
    instr(.VPAND,      ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0xDB),   .VVM, .ZO, .{AVX2} ),
    instr(.VPAND,      ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128,._66,._0F,.W0,  0xDB),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPAND,      ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256,._66,._0F,.W0,  0xDB),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPAND,      ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512,._66,._0F,.W0,  0xDB),   .VVM, .ZO, .{AVX512F} ),
    instr(.VPAND,      ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128,._66,._0F,.W1,  0xDB),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPAND,      ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256,._66,._0F,.W1,  0xDB),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPAND,      ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512,._66,._0F,.W1,  0xDB),   .VVM, .ZO, .{AVX512F} ),
// VPANDN
    instr(.VPANDN,     ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0xDF),   .VVM, .ZO, .{AVX} ),
    instr(.VPANDN,     ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0xDF),   .VVM, .ZO, .{AVX2} ),
    instr(.VPANDN,     ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128,._66,._0F,.W0,  0xDF),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPANDN,     ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256,._66,._0F,.W0,  0xDF),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPANDN,     ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512,._66,._0F,.W0,  0xDF),   .VVM, .ZO, .{AVX512F} ),
    instr(.VPANDN,     ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128,._66,._0F,.W1,  0xDF),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPANDN,     ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256,._66,._0F,.W1,  0xDF),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPANDN,     ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512,._66,._0F,.W1,  0xDF),   .VVM, .ZO, .{AVX512F} ),
// VPAVGB / VPAVGW
    instr(.VPAVGB,     ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0xE0),   .VVM, .ZO, .{AVX} ),
    instr(.VPAVGB,     ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0xE0),   .VVM, .ZO, .{AVX2} ),
    instr(.VPAVGB,     ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG, 0xE0),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPAVGB,     ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG, 0xE0),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPAVGB,     ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG, 0xE0),   .VVM, .ZO, .{AVX512BW} ),
    //
    instr(.VPAVGW,     ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0xE3),   .VVM, .ZO, .{AVX} ),
    instr(.VPAVGW,     ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0xE3),   .VVM, .ZO, .{AVX2} ),
    instr(.VPAVGW,     ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG, 0xE3),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPAVGW,     ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG, 0xE3),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPAVGW,     ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG, 0xE3),   .VVM, .ZO, .{AVX512BW} ),
// VPBLENDVB
    instr(.VPBLENDVB,  ops4(.xmml, .xmml, .xmml_m128, .xmml),   vex(.L128,._66,._0F3A,.W0,0x4C),   .VVMV,.ZO, .{AVX} ),
    instr(.VPBLENDVB,  ops4(.ymml, .ymml, .ymml_m256, .ymml),   vex(.L256,._66,._0F3A,.W0,0x4C),   .VVMV,.ZO, .{AVX2} ),
// VPBLENDDW
    instr(.VPBLENDW,   ops4(.xmml, .xmml, .xmml_m128, .imm8),   vex(.L128,._66,._0F3A,.WIG,0x0E),  .VVMI,.ZO, .{AVX} ),
    instr(.VPBLENDW,   ops4(.ymml, .ymml, .ymml_m256, .imm8),   vex(.L256,._66,._0F3A,.WIG,0x0E),  .VVMI,.ZO, .{AVX2} ),
// VPCMPEQB / VPCMPEQW / VPCMPEQD
    instr(.VPCMPEQB,   ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0x74),   .VVM, .ZO, .{AVX} ),
    instr(.VPCMPEQB,   ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0x74),   .VVM, .ZO, .{AVX2} ),
    instr(.VPCMPEQB,   ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG, 0x74),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPCMPEQB,   ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG, 0x74),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPCMPEQB,   ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG, 0x74),   .VVM, .ZO, .{AVX512BW} ),
    // VPCMPEQW
    instr(.VPCMPEQW,   ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0x75),   .VVM, .ZO, .{AVX} ),
    instr(.VPCMPEQW,   ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0x75),   .VVM, .ZO, .{AVX2} ),
    instr(.VPCMPEQW,   ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG, 0x75),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPCMPEQW,   ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG, 0x75),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPCMPEQW,   ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG, 0x75),   .VVM, .ZO, .{AVX512BW} ),
    // VPCMPEQD
    instr(.VPCMPEQD,   ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0x76),   .VVM, .ZO, .{AVX} ),
    instr(.VPCMPEQD,   ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0x76),   .VVM, .ZO, .{AVX2} ),
    instr(.VPCMPEQD,   ops3(.xmm_kz, .xmm, .xmm_m128_m32bcst), evex(.L128,._66,._0F,.W0,  0x76),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPCMPEQD,   ops3(.ymm_kz, .ymm, .ymm_m256_m32bcst), evex(.L256,._66,._0F,.W0,  0x76),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPCMPEQD,   ops3(.zmm_kz, .zmm, .zmm_m512_m32bcst), evex(.L512,._66,._0F,.W0,  0x76),   .VVM, .ZO, .{AVX512F} ),
// VPCMPEQQ
    instr(.VPCMPEQQ,   ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F38,.WIG, 0x29), .VVM, .ZO, .{AVX} ),
    instr(.VPCMPEQQ,   ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F38,.WIG, 0x29), .VVM, .ZO, .{AVX2} ),
    instr(.VPCMPEQQ,   ops3(.xmm_kz, .xmm, .xmm_m128_m64bcst), evex(.L128,._66,._0F38,.W1,  0x29), .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPCMPEQQ,   ops3(.ymm_kz, .ymm, .ymm_m256_m64bcst), evex(.L256,._66,._0F38,.W1,  0x29), .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPCMPEQQ,   ops3(.zmm_kz, .zmm, .zmm_m512_m64bcst), evex(.L512,._66,._0F38,.W1,  0x29), .VVM, .ZO, .{AVX512F} ),
// VPCMPESTRI
    instr(.VPCMPESTRI, ops3(.xmml,.xmml_m128,.imm8),            vex(.L128,._66,._0F3A,.WIG, 0x61), .VMI, .ZO, .{AVX} ),
// VPCMPESTRM
    instr(.VPCMPESTRM, ops3(.xmml,.xmml_m128,.imm8),            vex(.L128,._66,._0F3A,.WIG, 0x60), .VMI, .ZO, .{AVX} ),
// VPCMPGTB / VPCMPGTW / VPCMPGTD
    instr(.VPCMPGTB,   ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0x64),   .VVM, .ZO, .{AVX} ),
    instr(.VPCMPGTB,   ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0x64),   .VVM, .ZO, .{AVX2} ),
    instr(.VPCMPGTB,   ops3(.xmm_kz, .xmm, .xmm_m128),         evex(.L128,._66,._0F,.WIG, 0x64),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPCMPGTB,   ops3(.ymm_kz, .ymm, .ymm_m256),         evex(.L256,._66,._0F,.WIG, 0x64),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPCMPGTB,   ops3(.zmm_kz, .zmm, .zmm_m512),         evex(.L512,._66,._0F,.WIG, 0x64),   .VVM, .ZO, .{AVX512BW} ),
    // VPCMPGTW
    instr(.VPCMPGTW,   ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0x65),   .VVM, .ZO, .{AVX} ),
    instr(.VPCMPGTW,   ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0x65),   .VVM, .ZO, .{AVX2} ),
    instr(.VPCMPGTW,   ops3(.reg_k_k,.xmm,.xmm_m128),          evex(.L128,._66,._0F,.WIG, 0x65),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPCMPGTW,   ops3(.reg_k_k,.ymm,.ymm_m256),          evex(.L256,._66,._0F,.WIG, 0x65),   .VVM, .ZO, .{AVX512VL, AVX512BW} ),
    instr(.VPCMPGTW,   ops3(.reg_k_k,.zmm,.zmm_m512),          evex(.L512,._66,._0F,.WIG, 0x65),   .VVM, .ZO, .{AVX512BW} ),
    // VPCMPGTD
    instr(.VPCMPGTD,   ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F,.WIG, 0x66),   .VVM, .ZO, .{AVX} ),
    instr(.VPCMPGTD,   ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F,.WIG, 0x66),   .VVM, .ZO, .{AVX2} ),
    instr(.VPCMPGTD,   ops3(.reg_k_k,.xmm,.xmm_m128_m32bcst),  evex(.L128,._66,._0F,.W0,  0x66),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPCMPGTD,   ops3(.reg_k_k,.ymm,.ymm_m256_m32bcst),  evex(.L256,._66,._0F,.W0,  0x66),   .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPCMPGTD,   ops3(.reg_k_k,.zmm,.zmm_m512_m32bcst),  evex(.L512,._66,._0F,.W0,  0x66),   .VVM, .ZO, .{AVX512F} ),
// VPCMPGTQ
    instr(.VPCMPGTQ,   ops3(.xmml, .xmml, .xmml_m128),          vex(.L128,._66,._0F38,.WIG, 0x37), .VVM, .ZO, .{AVX} ),
    instr(.VPCMPGTQ,   ops3(.ymml, .ymml, .ymml_m256),          vex(.L256,._66,._0F38,.WIG, 0x37), .VVM, .ZO, .{AVX2} ),
    instr(.VPCMPGTQ,   ops3(.reg_k_k,.xmm,.xmm_m128_m64bcst),  evex(.L128,._66,._0F38,.W1,  0x37), .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPCMPGTQ,   ops3(.reg_k_k,.ymm,.ymm_m256_m64bcst),  evex(.L256,._66,._0F38,.W1,  0x37), .VVM, .ZO, .{AVX512VL, AVX512F} ),
    instr(.VPCMPGTQ,   ops3(.reg_k_k,.zmm,.zmm_m512_m64bcst),  evex(.L512,._66,._0F38,.W1,  0x37), .VVM, .ZO, .{AVX512F} ),
// VPCMPISTRI
    instr(.VPCMPISTRI, ops3(.xmml,.xmml_m128,.imm8),            vex(.L128,._66,._0F3A,.WIG, 0x63), .VMI, .ZO, .{AVX} ),
// VPCMPISTRM
    instr(.VPCMPISTRM, ops3(.xmml,.xmml_m128,.imm8),            vex(.L128,._66,._0F3A,.WIG, 0x62), .VMI, .ZO, .{AVX} ),
// VPEXTRB / VPEXTRD / VPEXTRQ
    instr(.VPEXTRB,    ops3(.rm8,.xmml_m128,.imm8),             vex(.L128,._66,._0F3A,.W0,  0x14), .MVI, .ZO, .{AVX} ),
    instr(.VPEXTRB,    ops3(.reg16,.xmml_m128,.imm8),           vex(.L128,._66,._0F3A,.W0,  0x14), .MVI, .ZO, .{AVX} ),
    instr(.VPEXTRB,    ops3(.reg32,.xmml_m128,.imm8),           vex(.L128,._66,._0F3A,.W0,  0x14), .MVI, .ZO, .{AVX} ),
    instr(.VPEXTRB,    ops3(.reg64,.xmml_m128,.imm8),           vex(.L128,._66,._0F3A,.W0,  0x14), .MVI, .ZO, .{AVX, No32} ),
    instr(.VPEXTRB,    ops3(.rm8,.xmm_m128,.imm8),             evex(.L128,._66,._0F3A,.WIG, 0x14), .MVI, .ZO, .{AVX512BW} ),
    instr(.VPEXTRB,    ops3(.reg16,.xmm_m128,.imm8),           evex(.L128,._66,._0F3A,.WIG, 0x14), .MVI, .ZO, .{AVX512BW} ),
    instr(.VPEXTRB,    ops3(.reg32,.xmm_m128,.imm8),           evex(.L128,._66,._0F3A,.WIG, 0x14), .MVI, .ZO, .{AVX512BW} ),
    instr(.VPEXTRB,    ops3(.reg64,.xmm_m128,.imm8),           evex(.L128,._66,._0F3A,.WIG, 0x14), .MVI, .ZO, .{AVX512BW, No32} ),
    //
    instr(.VPEXTRD,    ops3(.rm32,.xmml_m128,.imm8),            vex(.L128,._66,._0F3A,.W0,  0x16), .MVI, .ZO, .{AVX} ),
    instr(.VPEXTRD,    ops3(.rm32,.xmm_m128,.imm8),            evex(.L128,._66,._0F3A,.W0,  0x16), .MVI, .ZO, .{AVX512DQ} ),
    //
    instr(.VPEXTRQ,    ops3(.rm64,.xmml_m128,.imm8),            vex(.L128,._66,._0F3A,.W1,  0x16), .MVI, .ZO, .{AVX} ),
    instr(.VPEXTRQ,    ops3(.rm64,.xmm_m128,.imm8),            evex(.L128,._66,._0F3A,.W1,  0x16), .MVI, .ZO, .{AVX512DQ} ),
// VPEXTRW
    instr(.VPEXTRW,    ops3(.reg16,.xmml_m128,.imm8),           vex(.L128,._66,._0F,.W0, 0xC5),    .MVI, .ZO, .{AVX} ),
    instr(.VPEXTRW,    ops3(.reg32,.xmml_m128,.imm8),           vex(.L128,._66,._0F,.W0, 0xC5),    .MVI, .ZO, .{AVX} ),
    instr(.VPEXTRW,    ops3(.reg64,.xmml_m128,.imm8),           vex(.L128,._66,._0F,.W0, 0xC5),    .MVI, .ZO, .{AVX, No32} ),
    instr(.VPEXTRW,    ops3(.rm16,.xmml_m128,.imm8),            vex(.L128,._66,._0F3A,.W0, 0x15),  .MVI, .ZO, .{AVX} ),
    instr(.VPEXTRW,    ops3(.rm_reg32,.xmml_m128,.imm8),        vex(.L128,._66,._0F3A,.W0, 0x15),  .MVI, .ZO, .{AVX} ),
    instr(.VPEXTRW,    ops3(.rm_reg64,.xmml_m128,.imm8),        vex(.L128,._66,._0F3A,.W0, 0x15),  .MVI, .ZO, .{AVX, No32} ),

    // Dummy sigil value that marks the end of the table, use this to avoid
    // extra bounds checking when scanning this table.
    instr(._mnemonic_final,  ops0(), Opcode{}, .ZO, .ZO, .{} ),
};

