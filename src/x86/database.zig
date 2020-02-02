const x86 = @import("machine.zig");
const std = @import("std");

usingnamespace(@import("types.zig"));

const Mnemonic = x86.Mnemonic;
const Instruction = x86.Instruction;
const Machine = x86.Machine;
const Operand = x86.operand.Operand;
const OperandType = x86.operand.OperandType;

pub const Signature = struct {
    operands: [4]?OperandType,

    pub fn ops(o1: ?OperandType,
               o2: ?OperandType,
               o3: ?OperandType,
               o4: ?OperandType) Signature
    {
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

    pub fn fromOperands(operand1: ?*const Operand,
                        operand2: ?*const Operand,
                        operand3: ?*const Operand,
                        operand4: ?*const Operand) Signature
    {

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

    pub fn match_template(template: Signature, instance: Signature) bool {
        for (template.operands) |templ, i| {
            const rhs = instance.operands[i];
            if (templ == null and rhs == null) {
                continue;
            } else if ((templ != null and rhs == null) or (templ == null and rhs != null)) {
                return false;
            } else if (!OperandType.match_template(templ.?, rhs.?)) {
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

    pub fn testEdgeCase(
        self: OpcodeEdgeCase,
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
    AMD_K6,
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
};

pub const InstructionPrefix = enum {
    Lock,
    Repne,
    Rep,
    Bnd,
};

pub const InstructionEncoding = enum {
    ZO,     // no operands
    M,      // r/m value
    I,      // immediate
    O,      // opcode+reg.num
    O2,     // IGNORE           opcode+reg.num
    RM,     // ModRM:reg        ModRM:r/m
    MR,     // ModRM:r/m        ModRM:reg
    OI,     // opcode+reg.num   imm8/16/32/64
    MI,     // ModRM:r/m        imm8/16/32/64

    D,
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

    fn create(mnem: Mnemonic, signature: Signature, opcode: Opcode, en: InstructionEncoding,
              default_size: DefaultSize, version_and_features: var) InstructionItem {
        // TODO: process version and features field
        // NOTE: If no version flags are given, can calculate version information
        // based of the signature/encoding/default_size properties as one of
        // _8086, _386, x64
        var edge_case = OpcodeEdgeCase.None;

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
                    std.debug.assert(edge_case == .None);
                    edge_case = opt;
                },

                else => |bad_type| {
                    @compileError("Unsupported feature/version field type: " ++ @typeName(bad_type));
                },
            }
        }

        return InstructionItem {
            .mnemonic = mnem,
            .signature = signature,
            .opcode = opcode,
            .encoding = en,
            .default_size = default_size,
            .edge_case = edge_case,
        };
    }

    pub inline fn hasEdgeCase(self: InstructionItem) bool {
        return self.edge_case != .None;
    }

    pub fn matchesEdgeCase(
        self: InstructionItem,
        machine: Machine,
        op1: ?*const Operand,
        op2: ?*const Operand,
        op3: ?*const Operand,
        op4: ?*const Operand
    ) bool {
        return self.edge_case.testEdgeCase(machine.mode, op1, op2, op3, op4);
    }

    pub fn encode(self: InstructionItem,
                  machine: Machine,
                  op1: ?*const Operand,
                  op2: ?*const Operand,
                  op3: ?*const Operand,
                  op4: ?*const Operand) AsmError!Instruction {
        switch (self.encoding) {
            .ZO => return machine.encodeOpcode(self.opcode, self.default_size),
            .M => return machine.encodeRm(self.opcode, op1.?.*, self.default_size),
            .I => return machine.encodeImmediate(self.opcode, op1.?.*.Imm, self.default_size),
            .O => return machine.encodeOpcodeRegNum(self.opcode, op1.?.*, self.default_size),
            .O2 => return machine.encodeOpcodeRegNum(self.opcode, op2.?.*, self.default_size),
            .D => return machine.encodeAddress(self.opcode, op1.?.*.Addr, self.default_size),
            .OI => return machine.encodeOpcodeRegNumImmediate(self.opcode, op1.?.*, op2.?.*.Imm, self.default_size),
            .MI => return machine.encodeRmImmediate(self.opcode, op1.?.*, op2.?.*.Imm, self.default_size),
            .RM => return machine.encodeRegRm(self.opcode, op1.?.*, op2.?.*, self.default_size),
            .MR => return machine.encodeRegRm(self.opcode, op2.?.*, op1.?.*, self.default_size),

            .FD => return machine.encodeMOffset(self.opcode, op1.?.*, op2.?.*, self.default_size),
            .TD => return machine.encodeMOffset(self.opcode, op2.?.*, op1.?.*, self.default_size),
        }
    }
};


const Op1 = x86.Opcode.op1;
const Op2 = x86.Opcode.op2;

const Op1r = x86.Opcode.op1r;
const Op2r = x86.Opcode.op2r;

const ops0 = Signature.ops0;
const ops1 = Signature.ops1;
const ops2 = Signature.ops2;

const instr = InstructionItem.create;

const cpu = CpuVersion;
const edge = OpcodeEdgeCase;
const pre = InstructionPrefix;

// NOTE: Entries into this table should be from most specific to most general.
// For example, if a instruction takes both a reg64 and rm64 value, an operand
// of Operand.register(.RAX) can match both, while a Operand.registerRm(.RAX)
// can only match the rm64 value.
//
// Putting the most specific opcodes first enables us to reach every possible
// encoding for an instruction.
//
// TODO: add a comptime function to check that they have correct order.
// TODO: make function for looking up values in this table based on the mnemonic
//       and the operand signature.
pub const instruction_database = [_]InstructionItem {
// JMP
    instr(.JMP,     ops1(.imm8),                Op1(0xEB),              .I,  .RM8,        .{} ),
    instr(.JMP,     ops1(.imm16),               Op1(0xE9),              .I,  .RM32Strict, .{} ),
    instr(.JMP,     ops1(.imm32),               Op1(0xE9),              .I,  .RM32Strict, .{} ),
    //
    instr(.JMP,     ops1(.rm16),                Op1r(0xFF, 4),          .M,  .RM64Strict, .{} ),
    instr(.JMP,     ops1(.rm32),                Op1r(0xFF, 4),          .M,  .RM64Strict, .{} ),
    instr(.JMP,     ops1(.rm64),                Op1r(0xFF, 4),          .M,  .RM64Strict, .{} ),
    //
    instr(.JMP,     ops1(.ptr16_16),            Op1r(0xEA, 4),          .D,  .RM32Only,   .{} ),
    instr(.JMP,     ops1(.ptr16_32),            Op1r(0xEA, 4),          .D,  .RM32Only,   .{} ),
    //
    instr(.JMP,     ops1(.m16_16),              Op1r(0xFF, 5),          .M,  .RM32,       .{} ),
    instr(.JMP,     ops1(.m16_32),              Op1r(0xFF, 5),          .M,  .RM32,       .{} ),
    instr(.JMP,     ops1(.m16_64),              Op1r(0xFF, 5),          .M,  .RM32,       .{} ),
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
    instr(.MOV,     ops2(.reg_al, .moffs),      Op1(0xA0),              .FD, .RM8,        .{} ),
    instr(.MOV,     ops2(.reg_ax, .moffs),      Op1(0xA1),              .FD, .RM32,       .{} ),
    instr(.MOV,     ops2(.reg_eax, .moffs),     Op1(0xA1),              .FD, .RM32,       .{} ),
    instr(.MOV,     ops2(.reg_rax, .moffs),     Op1(0xA1),              .FD, .RM32,       .{} ),
    instr(.MOV,     ops2(.moffs, .reg_al),      Op1(0xA2),              .TD, .RM8,        .{} ),
    instr(.MOV,     ops2(.moffs, .reg_ax),      Op1(0xA3),              .TD, .RM32,       .{} ),
    instr(.MOV,     ops2(.moffs, .reg_eax),     Op1(0xA3),              .TD, .RM32,       .{} ),
    instr(.MOV,     ops2(.moffs, .reg_rax),     Op1(0xA3),              .TD, .RM32,       .{} ),
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
// NOP
    instr(.NOP,     ops0(),                     Op1(0x90),              .ZO, .ZO,         .{} ),
    instr(.NOP,     ops1(.rm16),                Op2r(0x0F, 0x1F, 0),    .M,  .RM32,       .{cpu.P6} ),
    instr(.NOP,     ops1(.rm32),                Op2r(0x0F, 0x1F, 0),    .M,  .RM32,       .{cpu.P6} ),
    instr(.NOP,     ops1(.rm64),                Op2r(0x0F, 0x1F, 0),    .M,  .RM32,       .{cpu.P6} ),
// PUSH
    instr(.PUSH,    ops1(.reg_cs),              Op1(0x0E),              .ZO, .ZO32Only,   .{} ),
    instr(.PUSH,    ops1(.reg_ss),              Op1(0x16),              .ZO, .ZO32Only,   .{} ),
    instr(.PUSH,    ops1(.reg_ds),              Op1(0x1E),              .ZO, .ZO32Only,   .{} ),
    instr(.PUSH,    ops1(.reg_es),              Op1(0x06),              .ZO, .ZO32Only,   .{} ),
    instr(.PUSH,    ops1(.reg_fs),              Op2(0x0F, 0xA0),        .ZO, .ZO,         .{} ),
    instr(.PUSH,    ops1(.reg_gs),              Op2(0x0F, 0xA8),        .ZO, .ZO,         .{} ),
    //
    instr(.PUSH,    ops1(.imm8),                Op1(0x6A),              .I,  .RM8 ,       .{} ),
    instr(.PUSH,    ops1(.imm16),               Op1(0x68),              .I,  .RM32,       .{} ),
    instr(.PUSH,    ops1(.imm32),               Op1(0x68),              .I,  .RM32,       .{} ),
    //
    instr(.PUSH,    ops1(.reg16),               Op1(0x50),              .O,  .RM64_16,    .{} ),
    instr(.PUSH,    ops1(.reg32),               Op1(0x50),              .O,  .RM64_16,    .{} ),
    instr(.PUSH,    ops1(.reg64),               Op1(0x50),              .O,  .RM64_16,    .{} ),
    //
    instr(.PUSH,    ops1(.rm16),                Op1r(0xFF, 6),          .M,  .RM64_16,    .{} ),
    instr(.PUSH,    ops1(.rm32),                Op1r(0xFF, 6),          .M,  .RM64_16,    .{} ),
    instr(.PUSH,    ops1(.rm64),                Op1r(0xFF, 6),          .M,  .RM64_16,    .{} ),
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
};

