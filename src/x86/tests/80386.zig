const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "80386" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        const rm8 = Operand.memoryRm(.DefaultSeg, .BYTE, .EAX, 0);
        const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
        const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
        const reg16 = Operand.register(.AX);
        const reg32 = Operand.register(.EAX);
        const reg64 = Operand.register(.RAX);
        // MOVSX
        testOp2(m32, .MOVSX,  reg16, rm8,  "66 0F BE 00");
        testOp2(m32, .MOVSX,  reg32, rm8,  "0F BE 00");
        testOp2(m32, .MOVSX,  reg64, rm8,  AsmError.InvalidOperand);
        testOp2(m32, .MOVSX,  reg16, rm16, "66 0F BF 00");
        testOp2(m32, .MOVSX,  reg32, rm16, "0F BF 00");
        testOp2(m32, .MOVSX,  reg64, rm16, AsmError.InvalidOperand);
        testOp2(m64, .MOVSX,  reg16, rm8,  "66 67 0F BE 00");
        testOp2(m64, .MOVSX,  reg32, rm8,  "67 0F BE 00");
        testOp2(m64, .MOVSX,  reg64, rm8,  "67 48 0F BE 00");
        testOp2(m64, .MOVSX,  reg16, rm16, "66 67 0F BF 00");
        testOp2(m64, .MOVSX,  reg32, rm16, "67 0F BF 00");
        testOp2(m64, .MOVSX,  reg64, rm16, "67 48 0F BF 00");
        // MOVSXD
        testOp2(m32, .MOVSXD, reg16, rm16, "66 63 00");
        testOp2(m32, .MOVSXD, reg16, rm32, "66 63 00");
        testOp2(m32, .MOVSXD, reg32, rm32, "63 00");
        testOp2(m32, .MOVSXD, reg64, rm32, AsmError.InvalidOperand);
        testOp2(m64, .MOVSXD, reg16, rm16, "66 67 63 00");
        testOp2(m64, .MOVSXD, reg16, rm32, "66 67 63 00");
        testOp2(m64, .MOVSXD, reg32, rm32, "67 63 00");
        testOp2(m64, .MOVSXD, reg64, rm32, "67 48 63 00");
        // MOVZX
        testOp2(m32, .MOVZX,  reg16, rm8,  "66 0F B6 00");
        testOp2(m32, .MOVZX,  reg32, rm8,  "0F B6 00");
        testOp2(m32, .MOVZX,  reg64, rm8,  AsmError.InvalidOperand);
        testOp2(m32, .MOVZX,  reg16, rm16, "66 0F B7 00");
        testOp2(m32, .MOVZX,  reg32, rm16, "0F B7 00");
        testOp2(m32, .MOVZX,  reg64, rm16, AsmError.InvalidOperand);
        testOp2(m64, .MOVZX,  reg16, rm8,  "66 67 0F B6 00");
        testOp2(m64, .MOVZX,  reg32, rm8,  "67 0F B6 00");
        testOp2(m64, .MOVZX,  reg64, rm8,  "67 48 0F B6 00");
        testOp2(m64, .MOVZX,  reg16, rm16, "66 67 0F B7 00");
        testOp2(m64, .MOVZX,  reg32, rm16, "67 0F B7 00");
        testOp2(m64, .MOVZX,  reg64, rm16, "67 48 0F B7 00");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .BYTE, .RAX, 0);
        testOp1(m64, .SETA,   op1, "0F 97 00");
        testOp1(m64, .SETAE,  op1, "0F 93 00");
        testOp1(m64, .SETB,   op1, "0F 92 00");
        testOp1(m64, .SETBE,  op1, "0F 96 00");
        testOp1(m64, .SETC,   op1, "0F 92 00");
        testOp1(m64, .SETE,   op1, "0F 94 00");
        testOp1(m64, .SETG,   op1, "0F 9F 00");
        testOp1(m64, .SETGE,  op1, "0F 9D 00");
        testOp1(m64, .SETL,   op1, "0F 9C 00");
        testOp1(m64, .SETLE,  op1, "0F 9E 00");
        testOp1(m64, .SETNA,  op1, "0F 96 00");
        testOp1(m64, .SETNAE, op1, "0F 92 00");
        testOp1(m64, .SETNB,  op1, "0F 93 00");
        testOp1(m64, .SETNBE, op1, "0F 97 00");
        testOp1(m64, .SETNC,  op1, "0F 93 00");
        testOp1(m64, .SETNE,  op1, "0F 95 00");
        testOp1(m64, .SETNG,  op1, "0F 9E 00");
        testOp1(m64, .SETNGE, op1, "0F 9C 00");
        testOp1(m64, .SETNL,  op1, "0F 9D 00");
        testOp1(m64, .SETNLE, op1, "0F 9F 00");
        testOp1(m64, .SETNO,  op1, "0F 91 00");
        testOp1(m64, .SETNP,  op1, "0F 9B 00");
        testOp1(m64, .SETNS,  op1, "0F 99 00");
        testOp1(m64, .SETNZ,  op1, "0F 95 00");
        testOp1(m64, .SETO,   op1, "0F 90 00");
        testOp1(m64, .SETP,   op1, "0F 9A 00");
        testOp1(m64, .SETPE,  op1, "0F 9A 00");
        testOp1(m64, .SETPO,  op1, "0F 9B 00");
        testOp1(m64, .SETS,   op1, "0F 98 00");
        testOp1(m64, .SETZ,   op1, "0F 94 00");
    }

    {
        const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
        const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
        const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
        const reg16 = Operand.register(.AX);
        const reg32 = Operand.register(.EAX);
        const reg64 = Operand.register(.RAX);
        const imm8 = Operand.immediate(0xff);

        // BSF
        testOp2(m64, .BSF,  reg16, rm16, "66 67 0F BC 00");
        testOp2(m64, .BSF,  reg32, rm32, "67 0F BC 00");
        testOp2(m64, .BSF,  reg64, rm64, "67 48 0F BC 00");
        // BSR
        testOp2(m64, .BSR,  reg16, rm16, "66 67 0F BD 00");
        testOp2(m64, .BSR,  reg32, rm32, "67 0F BD 00");
        testOp2(m64, .BSR,  reg64, rm64, "67 48 0F BD 00");
        // BSR
        testOp2(m64, .BT,   rm16, reg16, "66 67 0F A3 00");
        testOp2(m64, .BT,   rm32, reg32, "67 0F A3 00");
        testOp2(m64, .BT,   rm64, reg64, "67 48 0F A3 00");
        //
        testOp2(m64, .BT,   rm16, imm8,  "66 67 0F BA 20 ff");
        testOp2(m64, .BT,   rm32, imm8,  "67 0F BA 20 ff");
        testOp2(m64, .BT,   rm64, imm8,  "67 48 0F BA 20 ff");
        // BTC
        testOp2(m64, .BTC,  rm16, reg16, "66 67 0F BB 00");
        testOp2(m64, .BTC,  rm32, reg32, "67 0F BB 00");
        testOp2(m64, .BTC,  rm64, reg64, "67 48 0F BB 00");
        //
        testOp2(m64, .BTC,  rm16, imm8,  "66 67 0F BA 38 ff");
        testOp2(m64, .BTC,  rm32, imm8,  "67 0F BA 38 ff");
        testOp2(m64, .BTC,  rm64, imm8,  "67 48 0F BA 38 ff");
        // BTR
        testOp2(m64, .BTS,  rm16, reg16, "66 67 0F B3 00");
        testOp2(m64, .BTS,  rm32, reg32, "67 0F B3 00");
        testOp2(m64, .BTS,  rm64, reg64, "67 48 0F B3 00");
        //
        testOp2(m64, .BTS,  rm16, imm8,  "66 67 0F BA 28 ff");
        testOp2(m64, .BTS,  rm32, imm8,  "67 0F BA 28 ff");
        testOp2(m64, .BTS,  rm64, imm8,  "67 48 0F BA 28 ff");
    }

    {
        const reg32 = Operand.register(.EAX);
        const reg64 = Operand.register(.RAX);
        const cr0 = Operand.registerSpecial(.CR0);
        const cr2 = Operand.registerSpecial(.CR2);
        const cr8 = Operand.registerSpecial(.CR8);
        const dr0 = Operand.registerSpecial(.DR0);
        const dr1 = Operand.registerSpecial(.DR1);
        const dr8 = Operand.registerSpecial(.DR8);
        {
            testOp2(m32, .MOV,  reg32, cr0, "0F 20 C0");
            testOp2(m32, .MOV,  reg64, cr0, AsmError.InvalidOperand);
            testOp2(m32, .MOV,  reg32, cr2, "0F 20 D0");
            testOp2(m32, .MOV,  reg64, cr2, AsmError.InvalidOperand);
            testOp2(m32, .MOV,  reg32, cr8, AsmError.InvalidMode);
            testOp2(m32, .MOV,  reg64, cr8, AsmError.InvalidOperand);
            //
            testOp2(m64, .MOV,  reg32, cr0, AsmError.InvalidOperand);
            testOp2(m64, .MOV,  reg64, cr0, "0F 20 C0");
            testOp2(m64, .MOV,  reg32, cr2, AsmError.InvalidOperand);
            testOp2(m64, .MOV,  reg64, cr2, "0F 20 D0");
            testOp2(m64, .MOV,  reg32, cr8, AsmError.InvalidOperand);
            testOp2(m64, .MOV,  reg64, cr8, "44 0F 20 C0");
            //
            testOp2(m32, .MOV,  cr0, reg32, "0F 22 C0");
            testOp2(m32, .MOV,  cr0, reg64, AsmError.InvalidOperand);
            testOp2(m32, .MOV,  cr2, reg32, "0F 22 D0");
            testOp2(m32, .MOV,  cr2, reg64, AsmError.InvalidOperand);
            testOp2(m32, .MOV,  cr8, reg32, AsmError.InvalidMode);
            testOp2(m32, .MOV,  cr8, reg64, AsmError.InvalidOperand);
            //
            testOp2(m64, .MOV,  cr0, reg32, AsmError.InvalidOperand);
            testOp2(m64, .MOV,  cr0, reg64, "0F 22 C0");
            testOp2(m64, .MOV,  cr2, reg32, AsmError.InvalidOperand);
            testOp2(m64, .MOV,  cr2, reg64, "0F 22 D0");
            testOp2(m64, .MOV,  cr8, reg32, AsmError.InvalidOperand);
            testOp2(m64, .MOV,  cr8, reg64, "44 0F 22 C0");
        }

        {
            testOp2(m32, .MOV,  reg32, dr0, "0F 21 C0");
            testOp2(m32, .MOV,  reg64, dr0, AsmError.InvalidOperand);
            testOp2(m32, .MOV,  reg32, dr1, "0F 21 C8");
            testOp2(m32, .MOV,  reg64, dr1, AsmError.InvalidOperand);
            testOp2(m32, .MOV,  reg32, dr8, AsmError.InvalidMode);
            testOp2(m32, .MOV,  reg64, dr8, AsmError.InvalidOperand);
            //
            testOp2(m64, .MOV,  reg32, dr0, AsmError.InvalidOperand);
            testOp2(m64, .MOV,  reg64, dr0, "0F 21 C0");
            testOp2(m64, .MOV,  reg32, dr1, AsmError.InvalidOperand);
            testOp2(m64, .MOV,  reg64, dr1, "0F 21 C8");
            testOp2(m64, .MOV,  reg32, dr8, AsmError.InvalidOperand);
            testOp2(m64, .MOV,  reg64, dr8, "44 0F 21 C0");
            //
            testOp2(m32, .MOV,  dr0, reg32, "0F 23 C0");
            testOp2(m32, .MOV,  dr0, reg64, AsmError.InvalidOperand);
            testOp2(m32, .MOV,  dr1, reg32, "0F 23 C8");
            testOp2(m32, .MOV,  dr1, reg64, AsmError.InvalidOperand);
            testOp2(m32, .MOV,  dr8, reg32, AsmError.InvalidMode);
            testOp2(m32, .MOV,  dr8, reg64, AsmError.InvalidOperand);
            //
            testOp2(m64, .MOV,  dr0, reg32, AsmError.InvalidOperand);
            testOp2(m64, .MOV,  dr0, reg64, "0F 23 C0");
            testOp2(m64, .MOV,  dr1, reg32, AsmError.InvalidOperand);
            testOp2(m64, .MOV,  dr1, reg64, "0F 23 C8");
            testOp2(m64, .MOV,  dr8, reg32, AsmError.InvalidOperand);
            testOp2(m64, .MOV,  dr8, reg64, "44 0F 23 C0");
        }

        // TODO: the cpu ignores the bits in the mod field, so we should support
        // setting these to arbitrary values
        // m64.mod_fill = 0b00;
        // testOp2(m64, .BSR,  reg64, cr0, "0F 20 00");

    }

    {
        const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
        const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
        const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
        const reg16 = Operand.register(.AX);
        const reg32 = Operand.register(.EAX);
        const reg64 = Operand.register(.RAX);
        const reg_cl = Operand.register(.CL);
        const imm8 = Operand.immediate(0x04);
        {
            testOp3(m32, .SHLD,  rm16, reg16, imm8, "66 0F A4 00 04");
            testOp3(m32, .SHLD,  rm32, reg32, imm8, "0F A4 00 04");
            testOp3(m32, .SHLD,  rm64, reg64, imm8, AsmError.InvalidOperand);
            //
            testOp3(m32, .SHLD,  rm16, reg16, reg_cl, "66 0F A5 00");
            testOp3(m32, .SHLD,  rm32, reg32, reg_cl, "0F A5 00");
            testOp3(m32, .SHLD,  rm64, reg64, reg_cl, AsmError.InvalidOperand);
            //
            testOp3(m64, .SHLD,  rm16, reg16, imm8, "66 67 0F A4 00 04");
            testOp3(m64, .SHLD,  rm32, reg32, imm8, "67 0F A4 00 04");
            testOp3(m64, .SHLD,  rm64, reg64, imm8, "67 48 0F A4 00 04");
            //
            testOp3(m64, .SHLD,  rm16, reg16, reg_cl, "66 67 0F A5 00");
            testOp3(m64, .SHLD,  rm32, reg32, reg_cl, "67 0F A5 00");
            testOp3(m64, .SHLD,  rm64, reg64, reg_cl, "67 48 0F A5 00");
        }

        {
            testOp3(m32, .SHRD,  rm16, reg16, imm8, "66 0F AC 00 04");
            testOp3(m32, .SHRD,  rm32, reg32, imm8, "0F AC 00 04");
            testOp3(m32, .SHRD,  rm64, reg64, imm8, AsmError.InvalidOperand);
            //
            testOp3(m32, .SHRD,  rm16, reg16, reg_cl, "66 0F AD 00");
            testOp3(m32, .SHRD,  rm32, reg32, reg_cl, "0F AD 00");
            testOp3(m32, .SHRD,  rm64, reg64, reg_cl, AsmError.InvalidOperand);
            //
            testOp3(m64, .SHRD,  rm16, reg16, imm8, "66 67 0F AC 00 04");
            testOp3(m64, .SHRD,  rm32, reg32, imm8, "67 0F AC 00 04");
            testOp3(m64, .SHRD,  rm64, reg64, imm8, "67 48 0F AC 00 04");
            //
            testOp3(m64, .SHRD,  rm16, reg16, reg_cl, "66 67 0F AD 00");
            testOp3(m64, .SHRD,  rm32, reg32, reg_cl, "67 0F AD 00");
            testOp3(m64, .SHRD,  rm64, reg64, reg_cl, "67 48 0F AD 00");
        }

    }

}
