const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

const imm = Operand.immediate;
const mem = Operand.memory;
const memRm = Operand.memoryRm;
const reg = Operand.register;

test "reserved opcodes" {
    const m16 = Machine.init(.x86_16);
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    const rm8 = Operand.memoryRm(.DefaultSeg, .BYTE, .EAX, 0);
    const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);

    debugPrint(false);

    {
        testOp0(m16, .SALC, "D6");
        testOp0(m32, .SALC, "D6");
        testOp0(m64, .SALC, AsmError.InvalidOperand);
    }

    // Immediate Group 1
    // Same behavior as corresponding instruction with Opcode Op1r(0x80, x)
    {
        testOp2(m32, .RESRV_ADD,     rm8, imm(0), "82 00 00");
        testOp2(m32, .RESRV_OR,      rm8, imm(0), "82 08 00");
        testOp2(m32, .RESRV_ADC,     rm8, imm(0), "82 10 00");
        testOp2(m32, .RESRV_SBB,     rm8, imm(0), "82 18 00");
        testOp2(m32, .RESRV_AND,     rm8, imm(0), "82 20 00");
        testOp2(m32, .RESRV_SUB,     rm8, imm(0), "82 28 00");
        testOp2(m32, .RESRV_XOR,     rm8, imm(0), "82 30 00");
        testOp2(m32, .RESRV_CMP,     rm8, imm(0), "82 38 00");
        //
        testOp2(m64, .RESRV_ADD,     rm8, imm(0), AsmError.InvalidOperand);
        testOp2(m64, .RESRV_OR,      rm8, imm(0), AsmError.InvalidOperand);
        testOp2(m64, .RESRV_ADC,     rm8, imm(0), AsmError.InvalidOperand);
        testOp2(m64, .RESRV_SBB,     rm8, imm(0), AsmError.InvalidOperand);
        testOp2(m64, .RESRV_AND,     rm8, imm(0), AsmError.InvalidOperand);
        testOp2(m64, .RESRV_SUB,     rm8, imm(0), AsmError.InvalidOperand);
        testOp2(m64, .RESRV_XOR,     rm8, imm(0), AsmError.InvalidOperand);
        testOp2(m64, .RESRV_CMP,     rm8, imm(0), AsmError.InvalidOperand);
    }

    // Shift Group 2 /6
    // Same behavior as corresponding instruction with Opcode Op1r(x, 4)
    {
        testOp2(m64, .RESRV_SAL,     rm8, imm(1), "67 d0 30");
        testOp2(m64, .RESRV_SAL,     rm8, reg(.CL), "67 d2 30");
        testOp2(m64, .RESRV_SAL,     rm8,  imm(0), "67 c0 30 00");
        testOp2(m64, .RESRV_SAL,     rm16, imm(1), "66 67 d1 30");
        testOp2(m64, .RESRV_SAL,     rm32, imm(1), "67 d1 30");
        testOp2(m64, .RESRV_SAL,     rm64, imm(1), "67 48 d1 30");
        testOp2(m64, .RESRV_SAL,     rm16, imm(0), "66 67 c1 30 00");
        testOp2(m64, .RESRV_SAL,     rm32, imm(0), "67 c1 30 00");
        testOp2(m64, .RESRV_SAL,     rm64, imm(0), "67 48 c1 30 00");
        testOp2(m64, .RESRV_SAL,     rm16, reg(.CL), "66 67 d3 30");
        testOp2(m64, .RESRV_SAL,     rm32, reg(.CL), "67 d3 30");
        testOp2(m64, .RESRV_SAL,     rm64, reg(.CL), "67 48 d3 30");
        //
        testOp2(m64, .RESRV_SHL,     rm8, imm(1), "67 d0 30");
        testOp2(m64, .RESRV_SHL,     rm8, reg(.CL), "67 d2 30");
        testOp2(m64, .RESRV_SHL,     rm8,  imm(0), "67 c0 30 00");
        testOp2(m64, .RESRV_SHL,     rm16, imm(1), "66 67 d1 30");
        testOp2(m64, .RESRV_SHL,     rm32, imm(1), "67 d1 30");
        testOp2(m64, .RESRV_SHL,     rm64, imm(1), "67 48 d1 30");
        testOp2(m64, .RESRV_SHL,     rm16, imm(0), "66 67 c1 30 00");
        testOp2(m64, .RESRV_SHL,     rm32, imm(0), "67 c1 30 00");
        testOp2(m64, .RESRV_SHL,     rm64, imm(0), "67 48 c1 30 00");
        testOp2(m64, .RESRV_SHL,     rm16, reg(.CL), "66 67 d3 30");
        testOp2(m64, .RESRV_SHL,     rm32, reg(.CL), "67 d3 30");
        testOp2(m64, .RESRV_SHL,     rm64, reg(.CL), "67 48 d3 30");
    }

    // Unary Group 3 /1
    {
        testOp2(m64, .RESRV_TEST,    rm8, imm(0), "67 f6 08 00");
        testOp2(m64, .RESRV_TEST,    rm16, imm(0x7FFF), "66 67 f7 08 ff 7f");
        testOp2(m64, .RESRV_TEST,    rm32, imm(0x7FFFFFFF), "67 f7 08 ff ff ff 7f");
        testOp2(m64, .RESRV_TEST,    rm64, imm(0x7FFFFFFF), "67 48 f7 08 ff ff ff 7f");
    }

    // x87
    {
        // DCD0 - DCD7 (same as FCOM D8D0-D8D7)
        testOp2(m64, .RESRV_FCOM,    reg(.ST0), reg(.ST7), "dcd7");
        testOp1(m64, .RESRV_FCOM,    reg(.ST0), "dcd0");
        testOp1(m64, .RESRV_FCOM,    reg(.ST7), "dcd7");
        testOp0(m64, .RESRV_FCOM,    "dcd1");
        // DCD8 - DCDF (same as FCOMP D8D8-D8DF)
        testOp2(m64, .RESRV_FCOMP,   reg(.ST0), reg(.ST7), "dcdf");
        testOp1(m64, .RESRV_FCOMP,   reg(.ST0), "dcd8");
        testOp1(m64, .RESRV_FCOMP,   reg(.ST7), "dcdf");
        testOp0(m64, .RESRV_FCOMP,   "dcd9");
        // DED0 - DED7 (same as FCOMP D8C8-D8DF)
        testOp2(m64, .RESRV_FCOMP2,  reg(.ST0), reg(.ST7), "ded7");
        testOp1(m64, .RESRV_FCOMP2,  reg(.ST0), "ded0");
        testOp1(m64, .RESRV_FCOMP2,  reg(.ST7), "ded7");
        testOp0(m64, .RESRV_FCOMP2,  "ded1");
        // D0C8 - D0CF (same as FXCH D9C8-D9CF)
        testOp2(m64, .RESRV_FXCH,    reg(.ST0), reg(.ST7), "d0cf");
        testOp1(m64, .RESRV_FXCH,    reg(.ST0), "d0c8");
        testOp1(m64, .RESRV_FXCH,    reg(.ST7), "d0cf");
        testOp0(m64, .RESRV_FXCH,    "d0c9");
        // DFC8 - DFCF (same as FXCH D9C8-D9CF)
        testOp1(m64, .RESRV_FXCH2,   reg(.ST0), "dfc8");
        testOp1(m64, .RESRV_FXCH2,   reg(.ST7), "dfcf");
        testOp2(m64, .RESRV_FXCH2,   reg(.ST0), reg(.ST7), "dfcf");
        testOp0(m64, .RESRV_FXCH2,   "dfc9");
        // DFD0 - DFD7 (same as FSTP DDD8-DDDF)
        testOp1(m64, .RESRV_FSTP,    reg(.ST0), "dfd0");
        testOp1(m64, .RESRV_FSTP,    reg(.ST7), "dfd7");
        testOp2(m64, .RESRV_FSTP,    reg(.ST0), reg(.ST7), "dfd7");
        // DFD8 - DFDF (same as FSTP DDD8-DDDF)
        testOp1(m64, .RESRV_FSTP2,   reg(.ST0), "dfd8");
        testOp1(m64, .RESRV_FSTP2,   reg(.ST7), "dfdf");
        testOp2(m64, .RESRV_FSTP2,   reg(.ST0), reg(.ST7), "dfdf");
        // D9D8 - D9DF (same as FFREE with addition of an x87 POP)
        testOp1(m64, .FFREEP,        reg(.ST7), "dfc7");
        // DFC0 - DFC7 (same as FSTP DDD8-DDDF but won't cause a stack underflow exception)
        testOp1(m64, .FSTPNOUFLOW,   reg(.ST7), "dddf");
        testOp2(m64, .FSTPNOUFLOW,   reg(.ST0), reg(.ST7), "dddf");
    }

    {
        // NOP - 0F 0D
        testOp1(m64, .RESRV_NOP_0F0D_0,   rm16, "66 67 0f 0d 00");
        testOp1(m64, .RESRV_NOP_0F0D_0,   rm32, "67 0f 0d 00");
        testOp1(m64, .RESRV_NOP_0F0D_1,   rm16, "66 67 0f 0d 08");
        testOp1(m64, .RESRV_NOP_0F0D_1,   rm32, "67 0f 0d 08");
        testOp1(m64, .RESRV_NOP_0F0D_1,   rm64, "67 48 0f 0d 08");
        testOp1(m64, .RESRV_NOP_0F0D_2,   rm16, "66 67 0f 0d 10");
        testOp1(m64, .RESRV_NOP_0F0D_2,   rm32, "67 0f 0d 10");
        testOp1(m64, .RESRV_NOP_0F0D_2,   rm64, "67 48 0f 0d 10");
        testOp1(m64, .RESRV_NOP_0F0D_3,   rm16, "66 67 0f 0d 18");
        testOp1(m64, .RESRV_NOP_0F0D_3,   rm32, "67 0f 0d 18");
        testOp1(m64, .RESRV_NOP_0F0D_3,   rm64, "67 48 0f 0d 18");
        testOp1(m64, .RESRV_NOP_0F0D_4,   rm16, "66 67 0f 0d 20");
        testOp1(m64, .RESRV_NOP_0F0D_4,   rm32, "67 0f 0d 20");
        testOp1(m64, .RESRV_NOP_0F0D_4,   rm64, "67 48 0f 0d 20");
        testOp1(m64, .RESRV_NOP_0F0D_5,   rm16, "66 67 0f 0d 28");
        testOp1(m64, .RESRV_NOP_0F0D_5,   rm32, "67 0f 0d 28");
        testOp1(m64, .RESRV_NOP_0F0D_5,   rm64, "67 48 0f 0d 28");
        testOp1(m64, .RESRV_NOP_0F0D_6,   rm16, "66 67 0f 0d 30");
        testOp1(m64, .RESRV_NOP_0F0D_6,   rm32, "67 0f 0d 30");
        testOp1(m64, .RESRV_NOP_0F0D_6,   rm64, "67 48 0f 0d 30");
        testOp1(m64, .RESRV_NOP_0F0D_7,   rm16, "66 67 0f 0d 38");
        testOp1(m64, .RESRV_NOP_0F0D_7,   rm32, "67 0f 0d 38");
        testOp1(m64, .RESRV_NOP_0F0D_7,   rm64, "67 48 0f 0d 38");
    }

    {
        // NOP - 0F 18
        testOp1(m64, .RESRV_NOP_0F18_0,   rm16, "66 67 0f 18 00");
        testOp1(m64, .RESRV_NOP_0F18_0,   rm32, "67 0f 18 00");
        testOp1(m64, .RESRV_NOP_0F18_0,   rm64, "67 48 0f 18 00");
        testOp1(m64, .RESRV_NOP_0F18_1,   rm16, "66 67 0f 18 08");
        testOp1(m64, .RESRV_NOP_0F18_1,   rm32, "67 0f 18 08");
        testOp1(m64, .RESRV_NOP_0F18_1,   rm64, "67 48 0f 18 08");
        testOp1(m64, .RESRV_NOP_0F18_2,   rm16, "66 67 0f 18 10");
        testOp1(m64, .RESRV_NOP_0F18_2,   rm32, "67 0f 18 10");
        testOp1(m64, .RESRV_NOP_0F18_2,   rm64, "67 48 0f 18 10");
        testOp1(m64, .RESRV_NOP_0F18_3,   rm16, "66 67 0f 18 18");
        testOp1(m64, .RESRV_NOP_0F18_3,   rm32, "67 0f 18 18");
        testOp1(m64, .RESRV_NOP_0F18_3,   rm64, "67 48 0f 18 18");
        testOp1(m64, .RESRV_NOP_0F18_4,   rm16, "66 67 0f 18 20");
        testOp1(m64, .RESRV_NOP_0F18_4,   rm32, "67 0f 18 20");
        testOp1(m64, .RESRV_NOP_0F18_4,   rm64, "67 48 0f 18 20");
        testOp1(m64, .RESRV_NOP_0F18_5,   rm16, "66 67 0f 18 28");
        testOp1(m64, .RESRV_NOP_0F18_5,   rm32, "67 0f 18 28");
        testOp1(m64, .RESRV_NOP_0F18_5,   rm64, "67 48 0f 18 28");
        testOp1(m64, .RESRV_NOP_0F18_6,   rm16, "66 67 0f 18 30");
        testOp1(m64, .RESRV_NOP_0F18_6,   rm32, "67 0f 18 30");
        testOp1(m64, .RESRV_NOP_0F18_6,   rm64, "67 48 0f 18 30");
        testOp1(m64, .RESRV_NOP_0F18_7,   rm16, "66 67 0f 18 38");
        testOp1(m64, .RESRV_NOP_0F18_7,   rm32, "67 0f 18 38");
        testOp1(m64, .RESRV_NOP_0F18_7,   rm64, "67 48 0f 18 38");
    }

    {
        // NOP - 0F 19
        testOp1(m64, .RESRV_NOP_0F19_0,   rm16, "66 67 0f 19 00");
        testOp1(m64, .RESRV_NOP_0F19_0,   rm32, "67 0f 19 00");
        testOp1(m64, .RESRV_NOP_0F19_0,   rm64, "67 48 0f 19 00");
        testOp1(m64, .RESRV_NOP_0F19_1,   rm16, "66 67 0f 19 08");
        testOp1(m64, .RESRV_NOP_0F19_1,   rm32, "67 0f 19 08");
        testOp1(m64, .RESRV_NOP_0F19_1,   rm64, "67 48 0f 19 08");
        testOp1(m64, .RESRV_NOP_0F19_2,   rm16, "66 67 0f 19 10");
        testOp1(m64, .RESRV_NOP_0F19_2,   rm32, "67 0f 19 10");
        testOp1(m64, .RESRV_NOP_0F19_2,   rm64, "67 48 0f 19 10");
        testOp1(m64, .RESRV_NOP_0F19_3,   rm16, "66 67 0f 19 18");
        testOp1(m64, .RESRV_NOP_0F19_3,   rm32, "67 0f 19 18");
        testOp1(m64, .RESRV_NOP_0F19_3,   rm64, "67 48 0f 19 18");
        testOp1(m64, .RESRV_NOP_0F19_4,   rm16, "66 67 0f 19 20");
        testOp1(m64, .RESRV_NOP_0F19_4,   rm32, "67 0f 19 20");
        testOp1(m64, .RESRV_NOP_0F19_4,   rm64, "67 48 0f 19 20");
        testOp1(m64, .RESRV_NOP_0F19_5,   rm16, "66 67 0f 19 28");
        testOp1(m64, .RESRV_NOP_0F19_5,   rm32, "67 0f 19 28");
        testOp1(m64, .RESRV_NOP_0F19_5,   rm64, "67 48 0f 19 28");
        testOp1(m64, .RESRV_NOP_0F19_6,   rm16, "66 67 0f 19 30");
        testOp1(m64, .RESRV_NOP_0F19_6,   rm32, "67 0f 19 30");
        testOp1(m64, .RESRV_NOP_0F19_6,   rm64, "67 48 0f 19 30");
        testOp1(m64, .RESRV_NOP_0F19_7,   rm16, "66 67 0f 19 38");
        testOp1(m64, .RESRV_NOP_0F19_7,   rm32, "67 0f 19 38");
        testOp1(m64, .RESRV_NOP_0F19_7,   rm64, "67 48 0f 19 38");
    }

    {
        // NOP - 0F 1A
        testOp1(m64, .RESRV_NOP_0F1A_0,   rm16, "66 67 0f 1a 00");
        testOp1(m64, .RESRV_NOP_0F1A_0,   rm32, "67 0f 1a 00");
        testOp1(m64, .RESRV_NOP_0F1A_0,   rm64, "67 48 0f 1a 00");
        testOp1(m64, .RESRV_NOP_0F1A_1,   rm16, "66 67 0f 1a 08");
        testOp1(m64, .RESRV_NOP_0F1A_1,   rm32, "67 0f 1a 08");
        testOp1(m64, .RESRV_NOP_0F1A_1,   rm64, "67 48 0f 1a 08");
        testOp1(m64, .RESRV_NOP_0F1A_2,   rm16, "66 67 0f 1a 10");
        testOp1(m64, .RESRV_NOP_0F1A_2,   rm32, "67 0f 1a 10");
        testOp1(m64, .RESRV_NOP_0F1A_2,   rm64, "67 48 0f 1a 10");
        testOp1(m64, .RESRV_NOP_0F1A_3,   rm16, "66 67 0f 1a 18");
        testOp1(m64, .RESRV_NOP_0F1A_3,   rm32, "67 0f 1a 18");
        testOp1(m64, .RESRV_NOP_0F1A_3,   rm64, "67 48 0f 1a 18");
        testOp1(m64, .RESRV_NOP_0F1A_4,   rm16, "66 67 0f 1a 20");
        testOp1(m64, .RESRV_NOP_0F1A_4,   rm32, "67 0f 1a 20");
        testOp1(m64, .RESRV_NOP_0F1A_4,   rm64, "67 48 0f 1a 20");
        testOp1(m64, .RESRV_NOP_0F1A_5,   rm16, "66 67 0f 1a 28");
        testOp1(m64, .RESRV_NOP_0F1A_5,   rm32, "67 0f 1a 28");
        testOp1(m64, .RESRV_NOP_0F1A_5,   rm64, "67 48 0f 1a 28");
        testOp1(m64, .RESRV_NOP_0F1A_6,   rm16, "66 67 0f 1a 30");
        testOp1(m64, .RESRV_NOP_0F1A_6,   rm32, "67 0f 1a 30");
        testOp1(m64, .RESRV_NOP_0F1A_6,   rm64, "67 48 0f 1a 30");
        testOp1(m64, .RESRV_NOP_0F1A_7,   rm16, "66 67 0f 1a 38");
        testOp1(m64, .RESRV_NOP_0F1A_7,   rm32, "67 0f 1a 38");
        testOp1(m64, .RESRV_NOP_0F1A_7,   rm64, "67 48 0f 1a 38");
    }

    {
        // NOP - 0F 1B
        testOp1(m64, .RESRV_NOP_0F1B_0,   rm16, "66 67 0f 1b 00");
        testOp1(m64, .RESRV_NOP_0F1B_0,   rm32, "67 0f 1b 00");
        testOp1(m64, .RESRV_NOP_0F1B_0,   rm64, "67 48 0f 1b 00");
        testOp1(m64, .RESRV_NOP_0F1B_1,   rm16, "66 67 0f 1b 08");
        testOp1(m64, .RESRV_NOP_0F1B_1,   rm32, "67 0f 1b 08");
        testOp1(m64, .RESRV_NOP_0F1B_1,   rm64, "67 48 0f 1b 08");
        testOp1(m64, .RESRV_NOP_0F1B_2,   rm16, "66 67 0f 1b 10");
        testOp1(m64, .RESRV_NOP_0F1B_2,   rm32, "67 0f 1b 10");
        testOp1(m64, .RESRV_NOP_0F1B_2,   rm64, "67 48 0f 1b 10");
        testOp1(m64, .RESRV_NOP_0F1B_3,   rm16, "66 67 0f 1b 18");
        testOp1(m64, .RESRV_NOP_0F1B_3,   rm32, "67 0f 1b 18");
        testOp1(m64, .RESRV_NOP_0F1B_3,   rm64, "67 48 0f 1b 18");
        testOp1(m64, .RESRV_NOP_0F1B_4,   rm16, "66 67 0f 1b 20");
        testOp1(m64, .RESRV_NOP_0F1B_4,   rm32, "67 0f 1b 20");
        testOp1(m64, .RESRV_NOP_0F1B_4,   rm64, "67 48 0f 1b 20");
        testOp1(m64, .RESRV_NOP_0F1B_5,   rm16, "66 67 0f 1b 28");
        testOp1(m64, .RESRV_NOP_0F1B_5,   rm32, "67 0f 1b 28");
        testOp1(m64, .RESRV_NOP_0F1B_5,   rm64, "67 48 0f 1b 28");
        testOp1(m64, .RESRV_NOP_0F1B_6,   rm16, "66 67 0f 1b 30");
        testOp1(m64, .RESRV_NOP_0F1B_6,   rm32, "67 0f 1b 30");
        testOp1(m64, .RESRV_NOP_0F1B_6,   rm64, "67 48 0f 1b 30");
        testOp1(m64, .RESRV_NOP_0F1B_7,   rm16, "66 67 0f 1b 38");
        testOp1(m64, .RESRV_NOP_0F1B_7,   rm32, "67 0f 1b 38");
        testOp1(m64, .RESRV_NOP_0F1B_7,   rm64, "67 48 0f 1b 38");
    }

    {
        // NOP - 0F 1C
        testOp1(m64, .RESRV_NOP_0F1C_0,   rm16, "66 67 0f 1c 00");
        testOp1(m64, .RESRV_NOP_0F1C_0,   rm32, "67 0f 1c 00");
        testOp1(m64, .RESRV_NOP_0F1C_0,   rm64, "67 48 0f 1c 00");
        testOp1(m64, .RESRV_NOP_0F1C_1,   rm16, "66 67 0f 1c 08");
        testOp1(m64, .RESRV_NOP_0F1C_1,   rm32, "67 0f 1c 08");
        testOp1(m64, .RESRV_NOP_0F1C_1,   rm64, "67 48 0f 1c 08");
        testOp1(m64, .RESRV_NOP_0F1C_2,   rm16, "66 67 0f 1c 10");
        testOp1(m64, .RESRV_NOP_0F1C_2,   rm32, "67 0f 1c 10");
        testOp1(m64, .RESRV_NOP_0F1C_2,   rm64, "67 48 0f 1c 10");
        testOp1(m64, .RESRV_NOP_0F1C_3,   rm16, "66 67 0f 1c 18");
        testOp1(m64, .RESRV_NOP_0F1C_3,   rm32, "67 0f 1c 18");
        testOp1(m64, .RESRV_NOP_0F1C_3,   rm64, "67 48 0f 1c 18");
        testOp1(m64, .RESRV_NOP_0F1C_4,   rm16, "66 67 0f 1c 20");
        testOp1(m64, .RESRV_NOP_0F1C_4,   rm32, "67 0f 1c 20");
        testOp1(m64, .RESRV_NOP_0F1C_4,   rm64, "67 48 0f 1c 20");
        testOp1(m64, .RESRV_NOP_0F1C_5,   rm16, "66 67 0f 1c 28");
        testOp1(m64, .RESRV_NOP_0F1C_5,   rm32, "67 0f 1c 28");
        testOp1(m64, .RESRV_NOP_0F1C_5,   rm64, "67 48 0f 1c 28");
        testOp1(m64, .RESRV_NOP_0F1C_6,   rm16, "66 67 0f 1c 30");
        testOp1(m64, .RESRV_NOP_0F1C_6,   rm32, "67 0f 1c 30");
        testOp1(m64, .RESRV_NOP_0F1C_6,   rm64, "67 48 0f 1c 30");
        testOp1(m64, .RESRV_NOP_0F1C_7,   rm16, "66 67 0f 1c 38");
        testOp1(m64, .RESRV_NOP_0F1C_7,   rm32, "67 0f 1c 38");
        testOp1(m64, .RESRV_NOP_0F1C_7,   rm64, "67 48 0f 1c 38");
    }

    {
        // NOP - 0F 1D
        testOp1(m64, .RESRV_NOP_0F1D_0,   rm16, "66 67 0f 1d 00");
        testOp1(m64, .RESRV_NOP_0F1D_0,   rm32, "67 0f 1d 00");
        testOp1(m64, .RESRV_NOP_0F1D_0,   rm64, "67 48 0f 1d 00");
        testOp1(m64, .RESRV_NOP_0F1D_1,   rm16, "66 67 0f 1d 08");
        testOp1(m64, .RESRV_NOP_0F1D_1,   rm32, "67 0f 1d 08");
        testOp1(m64, .RESRV_NOP_0F1D_1,   rm64, "67 48 0f 1d 08");
        testOp1(m64, .RESRV_NOP_0F1D_2,   rm16, "66 67 0f 1d 10");
        testOp1(m64, .RESRV_NOP_0F1D_2,   rm32, "67 0f 1d 10");
        testOp1(m64, .RESRV_NOP_0F1D_2,   rm64, "67 48 0f 1d 10");
        testOp1(m64, .RESRV_NOP_0F1D_3,   rm16, "66 67 0f 1d 18");
        testOp1(m64, .RESRV_NOP_0F1D_3,   rm32, "67 0f 1d 18");
        testOp1(m64, .RESRV_NOP_0F1D_3,   rm64, "67 48 0f 1d 18");
        testOp1(m64, .RESRV_NOP_0F1D_4,   rm16, "66 67 0f 1d 20");
        testOp1(m64, .RESRV_NOP_0F1D_4,   rm32, "67 0f 1d 20");
        testOp1(m64, .RESRV_NOP_0F1D_4,   rm64, "67 48 0f 1d 20");
        testOp1(m64, .RESRV_NOP_0F1D_5,   rm16, "66 67 0f 1d 28");
        testOp1(m64, .RESRV_NOP_0F1D_5,   rm32, "67 0f 1d 28");
        testOp1(m64, .RESRV_NOP_0F1D_5,   rm64, "67 48 0f 1d 28");
        testOp1(m64, .RESRV_NOP_0F1D_6,   rm16, "66 67 0f 1d 30");
        testOp1(m64, .RESRV_NOP_0F1D_6,   rm32, "67 0f 1d 30");
        testOp1(m64, .RESRV_NOP_0F1D_6,   rm64, "67 48 0f 1d 30");
        testOp1(m64, .RESRV_NOP_0F1D_7,   rm16, "66 67 0f 1d 38");
        testOp1(m64, .RESRV_NOP_0F1D_7,   rm32, "67 0f 1d 38");
        testOp1(m64, .RESRV_NOP_0F1D_7,   rm64, "67 48 0f 1d 38");
    }

    {
        // NOP - 0F 1E
        testOp1(m64, .RESRV_NOP_0F1E_0,   rm16, "66 67 0f 1e 00");
        testOp1(m64, .RESRV_NOP_0F1E_0,   rm32, "67 0f 1e 00");
        testOp1(m64, .RESRV_NOP_0F1E_0,   rm64, "67 48 0f 1e 00");
        testOp1(m64, .RESRV_NOP_0F1E_1,   rm16, "66 67 0f 1e 08");
        testOp1(m64, .RESRV_NOP_0F1E_1,   rm32, "67 0f 1e 08");
        testOp1(m64, .RESRV_NOP_0F1E_1,   rm64, "67 48 0f 1e 08");
        testOp1(m64, .RESRV_NOP_0F1E_2,   rm16, "66 67 0f 1e 10");
        testOp1(m64, .RESRV_NOP_0F1E_2,   rm32, "67 0f 1e 10");
        testOp1(m64, .RESRV_NOP_0F1E_2,   rm64, "67 48 0f 1e 10");
        testOp1(m64, .RESRV_NOP_0F1E_3,   rm16, "66 67 0f 1e 18");
        testOp1(m64, .RESRV_NOP_0F1E_3,   rm32, "67 0f 1e 18");
        testOp1(m64, .RESRV_NOP_0F1E_3,   rm64, "67 48 0f 1e 18");
        testOp1(m64, .RESRV_NOP_0F1E_4,   rm16, "66 67 0f 1e 20");
        testOp1(m64, .RESRV_NOP_0F1E_4,   rm32, "67 0f 1e 20");
        testOp1(m64, .RESRV_NOP_0F1E_4,   rm64, "67 48 0f 1e 20");
        testOp1(m64, .RESRV_NOP_0F1E_5,   rm16, "66 67 0f 1e 28");
        testOp1(m64, .RESRV_NOP_0F1E_5,   rm32, "67 0f 1e 28");
        testOp1(m64, .RESRV_NOP_0F1E_5,   rm64, "67 48 0f 1e 28");
        testOp1(m64, .RESRV_NOP_0F1E_6,   rm16, "66 67 0f 1e 30");
        testOp1(m64, .RESRV_NOP_0F1E_6,   rm32, "67 0f 1e 30");
        testOp1(m64, .RESRV_NOP_0F1E_6,   rm64, "67 48 0f 1e 30");
        testOp1(m64, .RESRV_NOP_0F1E_7,   rm16, "66 67 0f 1e 38");
        testOp1(m64, .RESRV_NOP_0F1E_7,   rm32, "67 0f 1e 38");
        testOp1(m64, .RESRV_NOP_0F1E_7,   rm64, "67 48 0f 1e 38");
    }

    {
        // NOP - 0F 1F
        testOp1(m64, .RESRV_NOP_0F1F_0,   rm16, "66 67 0f 1f 00");
        testOp1(m64, .RESRV_NOP_0F1F_0,   rm32, "67 0f 1f 00");
        testOp1(m64, .RESRV_NOP_0F1F_0,   rm64, "67 48 0f 1f 00");
        testOp1(m64, .RESRV_NOP_0F1F_1,   rm16, "66 67 0f 1f 08");
        testOp1(m64, .RESRV_NOP_0F1F_1,   rm32, "67 0f 1f 08");
        testOp1(m64, .RESRV_NOP_0F1F_1,   rm64, "67 48 0f 1f 08");
        testOp1(m64, .RESRV_NOP_0F1F_2,   rm16, "66 67 0f 1f 10");
        testOp1(m64, .RESRV_NOP_0F1F_2,   rm32, "67 0f 1f 10");
        testOp1(m64, .RESRV_NOP_0F1F_2,   rm64, "67 48 0f 1f 10");
        testOp1(m64, .RESRV_NOP_0F1F_3,   rm16, "66 67 0f 1f 18");
        testOp1(m64, .RESRV_NOP_0F1F_3,   rm32, "67 0f 1f 18");
        testOp1(m64, .RESRV_NOP_0F1F_3,   rm64, "67 48 0f 1f 18");
        testOp1(m64, .RESRV_NOP_0F1F_4,   rm16, "66 67 0f 1f 20");
        testOp1(m64, .RESRV_NOP_0F1F_4,   rm32, "67 0f 1f 20");
        testOp1(m64, .RESRV_NOP_0F1F_4,   rm64, "67 48 0f 1f 20");
        testOp1(m64, .RESRV_NOP_0F1F_5,   rm16, "66 67 0f 1f 28");
        testOp1(m64, .RESRV_NOP_0F1F_5,   rm32, "67 0f 1f 28");
        testOp1(m64, .RESRV_NOP_0F1F_5,   rm64, "67 48 0f 1f 28");
        testOp1(m64, .RESRV_NOP_0F1F_6,   rm16, "66 67 0f 1f 30");
        testOp1(m64, .RESRV_NOP_0F1F_6,   rm32, "67 0f 1f 30");
        testOp1(m64, .RESRV_NOP_0F1F_6,   rm64, "67 48 0f 1f 30");
        testOp1(m64, .RESRV_NOP_0F1F_7,   rm16, "66 67 0f 1f 38");
        testOp1(m64, .RESRV_NOP_0F1F_7,   rm32, "67 0f 1f 38");
        testOp1(m64, .RESRV_NOP_0F1F_7,   rm64, "67 48 0f 1f 38");
    }
}
