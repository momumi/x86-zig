const x86 = @import("machine.zig");
const std = @import("std");

const assert = std.debug.assert;

usingnamespace(@import("types.zig"));

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

    /// sign-extended immediate value
    Sign,

    /// Not encodable on 64 bit mode
    No64,

    /// Not encodable on 32/16 bit mode
    No32,

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
            .Sign => {
                var imm_pos: u2 = undefined;
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
                if (imm.sign == .Unsigned and imm.willSignExtend(item.signature.operands[imm_pos].?)) {
                    return true;
                } else {
                    return false;
                }
            },
            .No64 => {
                return mode == .x64;
            },
            .No32 => {
                return mode == .x86 or mode == .x86_16;
            },
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
    PentMMX,
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
    /// Added in AVX-512
    AVX_512,


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
    OI,     // opcode+reg.num   imm8/16/32/64
    MI,     // ModRM:r/m        imm8/16/32/64

    D,      // encode address or offset
    FD,     // AL/AX/EAX/RAX    Moffs   NA  NA
    TD,     // Moffs (w)        AL/AX/EAX/RAX   NA  NA
};

pub const InstructionItem = struct {
    mnemonic: Mnemonic,
    signature: Signature,
    opcode: Opcode,
    encoding: InstructionEncoding,
    default_size: DefaultSize,
    edge_case: OpcodeEdgeCase,
    mode_edge_case: OpcodeEdgeCase,

    fn create(
        mnem: Mnemonic,
        signature: Signature,
        opcode: Opcode,
        en: InstructionEncoding,
        default_size: DefaultSize,
        version_and_features: var
    ) InstructionItem {
        _ = @setEvalBranchQuota(5000);
        // TODO: process version and features field
        // NOTE: If no version flags are given, can calculate version information
        // based of the signature/encoding/default_size properties as one of
        // _8086, _386, x64
        var edge_case = OpcodeEdgeCase.None;
        var mode_edge_case = OpcodeEdgeCase.None;


        if (@typeInfo(@TypeOf(version_and_features)) != .Struct) {
            @compileError("Expected tuple or struct argument, found " ++ @typeName(@TypeOf(args)));
        }

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
            .opcode = opcode,
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

    pub fn encode(self: InstructionItem,
                  machine: Machine,
                  op1: ?*const Operand,
                  op2: ?*const Operand,
                  op3: ?*const Operand,
                  op4: ?*const Operand) AsmError!Instruction {
        switch (self.encoding) {
            .ZO => return machine.encodeOpcode(self.opcode, op1, self.default_size),
            .ZO16 => return machine.encodeOpcode(self.opcode, &Operand.voidOperand(.WORD), self.default_size),
            .ZO32 => return machine.encodeOpcode(self.opcode, &Operand.voidOperand(.DWORD), self.default_size),
            .ZO64 => return machine.encodeOpcode(self.opcode, &Operand.voidOperand(.QWORD), self.default_size),
            .ZODef => return machine.encodeOpcode(self.opcode, &Operand.voidOperand(machine.dataSize()), self.default_size),
            .M => return machine.encodeRm(self.opcode, op1.?.*, self.default_size),
            .I => return machine.encodeImmediate(self.opcode, op2, self.coerceImm(op1, 0), self.default_size),
            .I2 => return machine.encodeImmediate(self.opcode, op1, self.coerceImm(op2, 1), self.default_size),
            .II => return machine.encodeImmImm(self.opcode, op3, self.coerceImm(op1, 0), self.coerceImm(op2, 1), self.default_size),
            .II16 => return machine.encodeImmImm(self.opcode, &Operand.voidOperand(.WORD), self.coerceImm(op1, 0), self.coerceImm(op2, 1), self.default_size),
            .O => return machine.encodeOpcodeRegNum(self.opcode, op1.?.*, self.default_size),
            .O2 => return machine.encodeOpcodeRegNum(self.opcode, op2.?.*, self.default_size),
            .D => return machine.encodeAddress(self.opcode, op1.?.*, self.default_size),
            .OI => return machine.encodeOpcodeRegNumImmediate(self.opcode, op1.?.*, self.coerceImm(op2, 1), self.default_size),
            .MI => return machine.encodeRmImmediate(self.opcode, op1.?.*, self.coerceImm(op2, 1), self.default_size),
            .RM => return machine.encodeRegRm(self.opcode, op1.?.*, op2.?.*, self.default_size),
            .RMI => return machine.encodeRegRmImmediate(self.opcode, op1.?.*, op2.?.*, self.coerceImm(op3, 2), self.default_size),
            .MR => return machine.encodeRegRm(self.opcode, op2.?.*, op1.?.*, self.default_size),

            .FD => return machine.encodeMOffset(self.opcode, op1.?.*, op2.?.*, self.default_size),
            .TD => return machine.encodeMOffset(self.opcode, op2.?.*, op1.?.*, self.default_size),
        }
    }
};

/// Generate a map from Mnemonic -> index in the instruction database
fn genMnemonicLookupTable() [Mnemonic.count]u16 {
    comptime {
        var result: [Mnemonic.count]u16 = undefined;
        var current_mnem = Mnemonic._mnemonic_count;

        _ = @setEvalBranchQuota(5000);

        for (result) |*val| {
            val.* = 0xffff;
        }

        for (instruction_database) |item, i| {
            if (item.mnemonic != current_mnem) {
                current_mnem = item.mnemonic;
                if (result[@enumToInt(current_mnem)] != 0xffff) {
                    @compileError("Mnemonic mislocated in lookup table. " ++ @tagName(current_mnem));
                }
                result[@enumToInt(current_mnem)] = @intCast(u16, i);
            }
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

const Op1r = x86.Opcode.op1r;
const Op2r = x86.Opcode.op2r;

const ops0 = Signature.ops0;
const ops1 = Signature.ops1;
const ops2 = Signature.ops2;
const ops3 = Signature.ops3;

const instr = InstructionItem.create;

const cpu = CpuVersion;
const edge = OpcodeEdgeCase;
const pre = InstructionPrefix;

const No64 = OpcodeEdgeCase.No64;
const No32 = OpcodeEdgeCase.No32;

const _186 = cpu._186;
const _286 = cpu._286;
const _386 = cpu._386;

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
    instr(.CWDE,    ops0(),                     Op1(0x98),              .ZO32, .RM32,     .{} ),
    instr(.CDQE,    ops0(),                     Op1(0x98),              .ZO64, .RM32,     .{} ),
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
    instr(.CMPSD,   ops0(),                     Op1(0xA7),              .ZO32, .RM32,     .{} ),
    instr(.CMPSQ,   ops0(),                     Op1(0xA7),              .ZO64, .RM32,     .{} ),
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
    instr(.IMUL,    ops3(.reg64, .rm64, .imm8), Op1(0x6B),              .RMI, .RM32_I8,   .{edge.Sign, cpu.x64} ),
    //
    instr(.IMUL,    ops3(.reg16, .rm16, .imm16),Op1(0x69),              .RMI, .RM32,      .{_186} ),
    instr(.IMUL,    ops3(.reg32, .rm32, .imm32),Op1(0x69),              .RMI, .RM32,      .{_386} ),
    instr(.IMUL,    ops3(.reg64, .rm64, .imm32),Op1(0x69),              .RMI, .RM32,      .{edge.Sign, cpu.x64} ),
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
    instr(.INSD,    ops0(),                     Op1(0x6D),              .ZO32, .RM32,     .{_186} ),
// INT
    instr(.INT3,    ops0(),                     Op1(0xCC),              .ZO, .ZO,         .{} ),
    instr(.INT,     ops1(.imm8),                Op1(0xCD),              .I,  .RM8,        .{} ),
    instr(.INTO,    ops0(),                     Op1(0xCE),              .ZO, .ZO32Only,   .{} ),
    instr(.INT1,    ops0(),                     Op1(0xF1),              .ZO, .ZO,         .{} ),
// IRET
    instr(.IRET,    ops1(._void),               Op1(0xCF),              .ZO,   .RM32,     .{} ),
    instr(.IRET,    ops0(),                     Op1(0xCF),              .ZO16, .RM32,     .{} ),
    instr(.IRETD,   ops0(),                     Op1(0xCF),              .ZO32, .RM32,     .{} ),
    instr(.IRETQ,   ops0(),                     Op1(0xCF),              .ZO64, .RM32,     .{} ),
// Jcc
    instr(.JCXZ,    ops1(.imm8),                Op1(0xE3),              .I, .RM8_Over16,  .{edge.Sign, No64} ),
    instr(.JECXZ,   ops1(.imm8),                Op1(0xE3),              .I, .RM8_Over32,  .{edge.Sign, } ),
    instr(.JRCXZ,   ops1(.imm8),                Op1(0xE3),              .I, .RM8,         .{edge.Sign, No32} ),
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
    instr(.LDS,     ops2(.reg16, .m16_16),      Op1(0xC5),              .RM, .RM32Only,   .{} ),
    instr(.LDS,     ops2(.reg32, .m16_32),      Op1(0xC5),              .RM, .RM32Only,   .{} ),
    //
    instr(.LSS,     ops2(.reg16, .m16_16),      Op2(0x0F, 0xB2),        .RM, .RM32,       .{cpu._386} ),
    instr(.LSS,     ops2(.reg32, .m16_32),      Op2(0x0F, 0xB2),        .RM, .RM32,       .{cpu._386} ),
    instr(.LSS,     ops2(.reg64, .m16_64),      Op2(0x0F, 0xB2),        .RM, .RM32,       .{cpu._386} ),
    //
    instr(.LES,     ops2(.reg16, .m16_16),      Op1(0xC4),              .RM, .RM32Only,   .{} ),
    instr(.LES,     ops2(.reg32, .m16_32),      Op1(0xC4),              .RM, .RM32Only,   .{} ),
    //
    instr(.LFS,     ops2(.reg16, .m16_16),      Op2(0x0F, 0xB4),        .RM, .RM32,       .{cpu._386} ),
    instr(.LFS,     ops2(.reg32, .m16_32),      Op2(0x0F, 0xB4),        .RM, .RM32,       .{cpu._386} ),
    instr(.LFS,     ops2(.reg64, .m16_64),      Op2(0x0F, 0xB4),        .RM, .RM32,       .{cpu._386} ),
    //
    instr(.LGS,     ops2(.reg16, .m16_16),      Op2(0x0F, 0xB5),        .RM, .RM32,       .{cpu._386} ),
    instr(.LGS,     ops2(.reg32, .m16_32),      Op2(0x0F, 0xB5),        .RM, .RM32,       .{cpu._386} ),
    instr(.LGS,     ops2(.reg64, .m16_64),      Op2(0x0F, 0xB5),        .RM, .RM32,       .{cpu._386} ),
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
    instr(.LODSD,   ops0(),                     Op1(0xAD),              .ZO32, .RM32,     .{} ),
    instr(.LODSQ,   ops0(),                     Op1(0xAD),              .ZO64, .RM32,     .{} ),
// LOOP
    instr(.LOOP,    ops1(.imm8),                Op1(0xE2),              .I, .RM8,         .{} ),
    instr(.LOOPE,   ops1(.imm8),                Op1(0xE1),              .I, .RM8,         .{} ),
    instr(.LOOPNE,  ops1(.imm8),                Op1(0xE0),              .I, .RM8,         .{} ),
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
    instr(.MOV,     ops2(.rm16, .reg_seg),      Op1(0x8C),              .MR, .RM16,       .{} ),
    instr(.MOV,     ops2(.rm32, .reg_seg),      Op1(0x8C),              .MR, .RM16,       .{} ),
    instr(.MOV,     ops2(.rm64, .reg_seg),      Op1(0x8C),              .MR, .RM16,       .{} ),
    //
    instr(.MOV,     ops2(.reg_seg, .rm16),      Op1(0x8E),              .RM, .RM16,       .{} ),
    instr(.MOV,     ops2(.reg_seg, .rm32),      Op1(0x8E),              .RM, .RM16,       .{} ),
    instr(.MOV,     ops2(.reg_seg, .rm64),      Op1(0x8E),              .RM, .RM16,       .{} ),
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
    instr(.MOV,     ops2(.reg64, .imm64),       Op1(0xB8),              .OI, .RM32,       .{} ),
    //
    instr(.MOV,     ops2(.rm8, .imm8),          Op1r(0xC6, 0),          .MI, .RM8,        .{} ),
    instr(.MOV,     ops2(.rm16, .imm16),        Op1r(0xC7, 0),          .MI, .RM32,       .{} ),
    instr(.MOV,     ops2(.rm32, .imm32),        Op1r(0xC7, 0),          .MI, .RM32,       .{} ),
    instr(.MOV,     ops2(.rm64, .imm32),        Op1r(0xC7, 0),          .MI, .RM32,       .{} ),
// MOVS / MOVSB / MOVSW / MOVSD / MOVSQ
    instr(.MOVS,    ops1(._void8),              Op1(0xA4),              .ZO, .RM8,        .{} ),
    instr(.MOVS,    ops1(._void),               Op1(0xA5),              .ZO, .RM32,       .{} ),
    //
    instr(.MOVSB,   ops0(),                     Op1(0xA4),              .ZO,   .RM8,      .{} ),
    instr(.MOVSW,   ops0(),                     Op1(0xA5),              .ZO16, .RM32,     .{} ),
    instr(.MOVSD,   ops0(),                     Op1(0xA5),              .ZO32, .RM32,     .{} ),
    instr(.MOVSQ,   ops0(),                     Op1(0xA5),              .ZO64, .RM32,     .{} ),
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
    instr(.OUTSD,   ops0(),                     Op1(0x6F),              .ZO32, .RM32,     .{_186} ),
// POP
    instr(.POP,     ops1(.reg16),               Op1(0x58),              .O,  .RM64_16,    .{} ),
    instr(.POP,     ops1(.reg32),               Op1(0x58),              .O,  .RM64_16,    .{} ),
    instr(.POP,     ops1(.reg64),               Op1(0x58),              .O,  .RM64_16,    .{} ),
    //
    instr(.POP,     ops1(.rm16),                Op1r(0x8F, 0),          .M,  .RM64_16,    .{} ),
    instr(.POP,     ops1(.rm32),                Op1r(0x8F, 0),          .M,  .RM64_16,    .{} ),
    instr(.POP,     ops1(.rm64),                Op1r(0x8F, 0),          .M,  .RM64_16,    .{} ),
    //
    instr(.POP,     ops1(.reg_ds),              Op1(0x1F),              .ZO, .ZO32Only,   .{} ),
    instr(.POP,     ops1(.reg_es),              Op1(0x07),              .ZO, .ZO32Only,   .{} ),
    instr(.POP,     ops1(.reg_ss),              Op1(0x17),              .ZO, .ZO32Only,   .{} ),
    instr(.POP,     ops1(.reg_fs),              Op2(0x0F, 0xA1),        .ZO, .ZO64_16,    .{} ),
    instr(.POP,     ops1(.reg_gs),              Op2(0x0F, 0xA9),        .ZO, .ZO64_16,    .{} ),
// POPA
    instr(.POPA,    ops0(),                     Op1(0x60),              .ZODef, .RM32,    .{No64, _186} ),
    instr(.POPAW,   ops0(),                     Op1(0x60),              .ZO16,  .RM32,    .{No64, _186} ),
    instr(.POPAD,   ops0(),                     Op1(0x60),              .ZO32,  .RM32,    .{No64, _186} ),
// POPF / POPFD / POPFQ
    instr(.POPF,    ops1(._void),               Op1(0x9D),              .ZO, .RM64_16,    .{} ),
    //
    instr(.POPF,    ops0(),                     Op1(0x9D),              .ZODef, .RM64_16, .{} ),
    instr(.POPFW,   ops0(),                     Op1(0x9D),              .ZO16,  .RM64_16, .{} ),
    instr(.POPFD,   ops0(),                     Op1(0x9D),              .ZO32,  .RM32Only,.{} ),
    instr(.POPFQ,   ops0(),                     Op1(0x9D),              .ZO64,  .RM64_16, .{} ),
// PUSH
    instr(.PUSH,    ops1(.imm8),                Op1(0x6A),              .I,  .RM8 ,       .{_186} ),
    instr(.PUSH,    ops1(.imm16),               Op1(0x68),              .I,  .RM32,       .{_186} ),
    instr(.PUSH,    ops1(.imm32),               Op1(0x68),              .I,  .RM32,       .{cpu._386} ),
    //
    instr(.PUSH,    ops1(.reg16),               Op1(0x50),              .O,  .RM64_16,    .{} ),
    instr(.PUSH,    ops1(.reg32),               Op1(0x50),              .O,  .RM64_16,    .{} ),
    instr(.PUSH,    ops1(.reg64),               Op1(0x50),              .O,  .RM64_16,    .{} ),
    //
    instr(.PUSH,    ops1(.rm16),                Op1r(0xFF, 6),          .M,  .RM64_16,    .{} ),
    instr(.PUSH,    ops1(.rm32),                Op1r(0xFF, 6),          .M,  .RM64_16,    .{} ),
    instr(.PUSH,    ops1(.rm64),                Op1r(0xFF, 6),          .M,  .RM64_16,    .{} ),
    //
    instr(.PUSH,    ops1(.reg_cs),              Op1(0x0E),              .ZO, .ZO32Only,   .{} ),
    instr(.PUSH,    ops1(.reg_ss),              Op1(0x16),              .ZO, .ZO32Only,   .{} ),
    instr(.PUSH,    ops1(.reg_ds),              Op1(0x1E),              .ZO, .ZO32Only,   .{} ),
    instr(.PUSH,    ops1(.reg_es),              Op1(0x06),              .ZO, .ZO32Only,   .{} ),
    instr(.PUSH,    ops1(.reg_fs),              Op2(0x0F, 0xA0),        .ZO, .ZO64_16,    .{} ),
    instr(.PUSH,    ops1(.reg_gs),              Op2(0x0F, 0xA8),        .ZO, .ZO64_16,    .{} ),
// PUSHA
    instr(.PUSHA,   ops0(),                     Op1(0x60),              .ZODef, .RM32,    .{No64, _186} ),
    instr(.PUSHAW,  ops0(),                     Op1(0x60),              .ZO16,  .RM32,    .{No64, _186} ),
    instr(.PUSHAD,  ops0(),                     Op1(0x60),              .ZO32,  .RM32,    .{No64, _186} ),
// PUSHF / PUSHFW / PUSHFD / PUSHFQ
    instr(.PUSHF,    ops1(._void),              Op1(0x9C),              .ZO, .RM64_16,    .{} ),
    //
    instr(.PUSHF,    ops0(),                    Op1(0x9C),              .ZODef, .RM64_16, .{} ),
    instr(.PUSHFW,   ops0(),                    Op1(0x9C),              .ZO16,  .RM64_16, .{} ),
    instr(.PUSHFD,   ops0(),                    Op1(0x9C),              .ZODef, .RM32Only,.{} ),
    instr(.PUSHFQ,   ops0(),                    Op1(0x9C),              .ZO64,  .RM64_16, .{} ),
//  RCL / RCR / ROL / ROR
    instr(.RCL,     ops2(.rm8, .imm_1),         Op1r(0xD0, 2),          .M,  .RM8,        .{} ),
    instr(.RCL,     ops2(.rm8, .reg_cl),        Op1r(0xD2, 2),          .M,  .RM8,        .{} ),
    instr(.RCL,     ops2(.rm8,  .imm8),         Op1r(0xC0, 2),          .MI, .RM8,        .{_186} ),
    instr(.RCL,     ops2(.rm16, .imm_1),        Op1r(0xD1, 2),          .M,  .RM32_I8,    .{} ),
    instr(.RCL,     ops2(.rm32, .imm_1),        Op1r(0xD1, 2),          .M,  .RM32_I8,    .{} ),
    instr(.RCL,     ops2(.rm64, .imm_1),        Op1r(0xD1, 2),          .M,  .RM32_I8,    .{} ),
    instr(.RCL,     ops2(.rm16, .imm8),         Op1r(0xC1, 2),          .MI, .RM32_I8,    .{_186} ),
    instr(.RCL,     ops2(.rm32, .imm8),         Op1r(0xC1, 2),          .MI, .RM32_I8,    .{_386} ),
    instr(.RCL,     ops2(.rm64, .imm8),         Op1r(0xC1, 2),          .MI, .RM32_I8,    .{cpu.x64} ),
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
    instr(.RCR,     ops2(.rm64, .imm8),         Op1r(0xC1, 3),          .MI, .RM32_I8,    .{cpu.x64} ),
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
    instr(.ROL,     ops2(.rm64, .imm8),         Op1r(0xC1, 0),          .MI, .RM32_I8,    .{cpu.x64} ),
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
    instr(.ROR,     ops2(.rm32, .imm8),         Op1r(0xC1, 1),          .MI, .RM32_I8,    .{cpu._386} ),
    instr(.ROR,     ops2(.rm64, .imm8),         Op1r(0xC1, 1),          .MI, .RM32_I8,    .{cpu.x64} ),
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
    instr(.SAL,     ops2(.rm64, .imm8),         Op1r(0xC1, 4),          .MI, .RM32_I8,    .{cpu.x64} ),
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
    instr(.SAR,     ops2(.rm64, .imm8),         Op1r(0xC1, 7),          .MI, .RM32_I8,    .{cpu.x64} ),
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
    instr(.SHL,     ops2(.rm64, .imm8),         Op1r(0xC1, 4),          .MI, .RM32_I8,    .{cpu.x64} ),
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
    instr(.SHR,     ops2(.rm64, .imm8),         Op1r(0xC1, 5),          .MI, .RM32_I8,    .{cpu.x64} ),
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
    instr(.SCASD,   ops0(),                     Op1(0xAF),              .ZO32, .RM32,     .{} ),
    instr(.SCASQ,   ops0(),                     Op1(0xAF),              .ZO64, .RM32,     .{} ),
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
    instr(.STOSD,   ops0(),                     Op1(0xAB),              .ZO32, .RM32,     .{} ),
    instr(.STOSQ,   ops0(),                     Op1(0xAB),              .ZO64, .RM32,     .{} ),
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
    instr(.FWAIT,   ops0(),                     Op1(0x9B),              .ZO, .ZO,         .{} ),
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
// 80286
//
// NOTES: might want to handle operands like `r32/m16` better
    instr(.ARPL,    ops2(.rm16, .reg16),        Op1(0x63),              .MR, .RM16,       .{No64, _286} ),
    //
    instr(.CLTS,    ops0(),                     Op2(0x0F, 0x06),        .ZO, .ZO,         .{cpu._286} ),
    //
    instr(.LAR,     ops2(.reg16, .rm16),        Op2(0x0F, 0x02),        .RM, .RM32,       .{cpu._286} ),
    instr(.LAR,     ops2(.reg32, .rm_mem16),    Op2(0x0F, 0x02),        .RM, .RM32,       .{cpu._286} ),
    instr(.LAR,     ops2(.reg32, .rm_reg16),    Op2(0x0F, 0x02),        .RM, .RM32,       .{cpu._286} ),
    instr(.LAR,     ops2(.reg32, .rm_reg32),    Op2(0x0F, 0x02),        .RM, .RM32,       .{cpu._286} ),
    instr(.LAR,     ops2(.reg64, .rm_mem16),    Op2(0x0F, 0x02),        .RM, .RM32,       .{cpu._286} ),
    instr(.LAR,     ops2(.reg64, .rm_reg16),    Op2(0x0F, 0x02),        .RM, .RM32,       .{cpu._286} ),
    instr(.LAR,     ops2(.reg64, .rm_reg32),    Op2(0x0F, 0x02),        .RM, .RM32,       .{cpu._286} ),
    instr(.LAR,     ops2(.reg64, .rm_reg64),    Op2(0x0F, 0x02),        .RM, .RM32,       .{cpu._286} ),
    //
    instr(.LGDT,    ops1(.rm_mem),              Op2r(0x0F, 0x01, 2),    .M,  .ZO,         .{No64, _286} ),
    instr(.LGDT,    ops1(.rm_mem),              Op2r(0x0F, 0x01, 2),    .M,  .ZO,         .{No32, _286} ),
    //
    instr(.LIDT,    ops1(.rm_mem),              Op2r(0x0F, 0x01, 3),    .M,  .ZO,         .{No64, _286} ),
    instr(.LIDT,    ops1(.rm_mem),              Op2r(0x0F, 0x01, 3),    .M,  .ZO,         .{No32, _286} ),
    //
    instr(.LLDT,    ops1(.rm16),                Op2r(0x0F, 0x00, 2),    .M,  .RM16,       .{cpu._286} ),
    //
    instr(.LMSW,    ops1(.rm16),                Op2r(0x0F, 0x01, 6),    .M,  .RM16,       .{cpu._286} ),
    //
    // instr(.LOADALL, ops1(.rm16),                Op2r(0x0F, 0x01, 6),    .M, .RM16,        .{cpu._286, cpu._386} ), // undocumented
    //
    instr(.LSL,     ops2(.reg16, .rm16),        Op2(0x0F, 0x03),        .RM, .RM32,       .{cpu._286} ),
    instr(.LSL,     ops2(.reg32, .rm_mem16),    Op2(0x0F, 0x03),        .RM, .RM32,       .{cpu._286} ),
    instr(.LSL,     ops2(.reg32, .rm_reg16),    Op2(0x0F, 0x03),        .RM, .RM32,       .{cpu._286} ),
    instr(.LSL,     ops2(.reg32, .rm_reg32),    Op2(0x0F, 0x03),        .RM, .RM32,       .{cpu._286} ),
    instr(.LSL,     ops2(.reg64, .rm_mem16),    Op2(0x0F, 0x03),        .RM, .RM32,       .{cpu._286} ),
    instr(.LSL,     ops2(.reg64, .rm_reg16),    Op2(0x0F, 0x03),        .RM, .RM32,       .{cpu._286} ),
    instr(.LSL,     ops2(.reg64, .rm_reg32),    Op2(0x0F, 0x03),        .RM, .RM32,       .{cpu._286} ),
    instr(.LSL,     ops2(.reg64, .rm_reg64),    Op2(0x0F, 0x03),        .RM, .RM32,       .{cpu._286} ),
    //
    instr(.LTR,     ops1(.rm16),                Op2r(0x0F, 0x00, 3),    .M,  .RM16,       .{cpu._286} ),
    //
    instr(.SGDT,    ops1(.rm_mem),              Op2r(0x0F, 0x01, 0),    .M,  .ZO,         .{cpu._286} ),
    //
    instr(.SIDT,    ops1(.rm_mem),              Op2r(0x0F, 0x01, 1),    .M,  .ZO,         .{cpu._286} ),
    //
    instr(.SLDT,    ops1(.rm16),                Op2r(0x0F, 0x00, 0),    .M,  .ZO,         .{cpu._286} ),
    instr(.SLDT,    ops1(.rm_reg64),            Op2r(0x0F, 0x00, 0),    .M,  .ZO,         .{cpu._286} ),
    //
    instr(.SMSW,    ops1(.rm16),                Op2r(0x0F, 0x01, 4),    .M,  .RM32,       .{cpu._286} ),
    instr(.SMSW,    ops1(.rm32),                Op2r(0x0F, 0x01, 4),    .M,  .RM32,       .{cpu._286} ),
    instr(.SMSW,    ops1(.rm64),                Op2r(0x0F, 0x01, 4),    .M,  .RM32,       .{cpu._286} ),
    //
    instr(.STR,     ops1(.rm16),                Op2r(0x0F, 0x00, 1),    .M,  .RM16,       .{cpu._286} ),
    //
    instr(.VERR,    ops1(.rm16),                Op2r(0x0F, 0x00, 4),    .M,  .RM16,       .{cpu._286} ),
    instr(.VERW,    ops1(.rm16),                Op2r(0x0F, 0x00, 5),    .M,  .RM16,       .{cpu._286} ),

//
// 80386
//

//
// 80486
//

//
// x87 -- 8087 / 80287 / 80387
//

//
// Pentium
//
    instr(.CPUID,   ops0(),                     Op2(0x0F, 0xA2),        .ZO, .ZO,         .{cpu.Pent} ),
    // TODO

//
// Pentium MMX
//

//
// K6
//
    instr(.SYSCALL, ops0(),                     Op2(0x0F, 0x05),        .ZO, .ZO,         .{cpu.K6} ),
    instr(.SYSRET,  ops0(),                     Op2(0x0F, 0x07),        .ZO, .ZO,         .{cpu.K6} ),
    instr(.SYSRETQ, ops0(),                     Op2(0x0F, 0x07),        .ZO64, .RM32,     .{cpu.K6} ),

//
// Pentium Pro
//
    // TODO CMOVcc
    instr(.UD0, ops2(.reg32, .rm32),            Op2(0x0F, 0xFF),        .RM, .RM32,       .{cpu.PentPro} ),
    instr(.UD1, ops2(.reg32, .rm32),            Op2(0x0F, 0xB9),        .RM, .RM32,       .{cpu.PentPro} ),
    instr(.UD2, ops0(),                         Op2(0x0F, 0x0B),        .ZO, .ZO,         .{cpu.PentPro} ),

//
// Pentium II
//
    instr(.SYSENTER, ops0(),                    Op2(0x0F, 0x34),        .ZO, .ZO,         .{cpu.Pent2} ),
    instr(.SYSEXIT,  ops0(),                    Op2(0x0F, 0x35),        .ZO, .ZO,         .{cpu.Pent2} ),
    instr(.SYSEXITQ, ops0(),                    Op2(0x0F, 0x35),        .ZO64, .RM32,     .{cpu.Pent2} ),


};

