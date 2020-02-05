const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "simple 8086 opcodes" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        testOp0(m32, .AAA, "37");
        testOp0(m32, .AAD, "D5 0A");
        testOp0(m32, .AAM, "D4 0A");
        testOp0(m32, .AAS, "3F");
        testOp0(m64, .AAA, AsmError.InvalidOperand);
        testOp0(m64, .AAD, AsmError.InvalidOperand);
        testOp0(m64, .AAM, AsmError.InvalidOperand);
        testOp0(m64, .AAS, AsmError.InvalidOperand);

        testOp0(m32, .DAA, "27");
        testOp0(m32, .DAS, "2F");

        testOp0(m32, .HLT, "F4");

        testOp0(m32, .LAHF, "9F");
        // TODO: need feature check
        // testOp0(m64, .LAHF, "9F");

        testOp0(m32, .STC, "F9");
        testOp0(m32, .STD, "FD");
        testOp0(m32, .STI, "FB");

        testOp0(m32, .CLC, "F8");
        testOp0(m32, .CLD, "FC");
        testOp0(m32, .CLI, "FA");
        testOp0(m32, .CMC, "F5");

        testOp0(m32, .WAIT, "9B");
        testOp0(m32, .FWAIT, "9B");

        testOp0(m32, .XLAT, "D7");
        testOp0(m32, .XLATB, "D7");

        testOp1(m64, .XLAT, Operand.voidOperand(.QWORD), "48 D7");

        testOp0(m64, .CBW, "66 98");
        testOp0(m64, .CWDE, "98");
        testOp0(m64, .CDQE, "48 98");

        {
            // PUSHF
            testOp0(m64, .PUSHF, "9C");
            testOp0(m64, .PUSHFW, "66 9C");
            testOp0(m64, .PUSHFD, AsmError.InvalidOperand);
            testOp0(m64, .PUSHFQ, "9C");

            testOp0(m32, .PUSHF, "9C");
            testOp0(m32, .PUSHFW, "66 9C");
            testOp0(m32, .PUSHFD, "9C");
            testOp0(m32, .PUSHFQ, AsmError.InvalidOperand);

            // POPF
            testOp0(m64, .POPF, "9D");
            testOp0(m64, .POPFW, "66 9D");
            testOp0(m64, .POPFD, AsmError.InvalidOperand);
            testOp0(m64, .POPFQ, "9D");

            testOp0(m32, .POPF, "9D");
            testOp0(m32, .POPFW, "66 9D");
            testOp0(m32, .POPFD, "9D");
            testOp0(m32, .POPFQ, AsmError.InvalidOperand);
        }

        {
            // INS
            testOp0(m64, .INSB, "6C");
            testOp0(m64, .INSW, "66 6D");
            testOp0(m64, .INSD, "6D");

            testOp0(m32, .INSB, "6C");
            testOp0(m32, .INSW, "66 6D");
            testOp0(m32, .INSD, "6D");

            // OUTS
            testOp0(m64, .OUTSB, "6E");
            testOp0(m64, .OUTSW, "66 6F");
            testOp0(m64, .OUTSD, "6F");

            testOp0(m32, .OUTSB, "6E");
            testOp0(m32, .OUTSW, "66 6F");
            testOp0(m32, .OUTSD, "6F");
        }

        {
            // MOVS
            testOp0(m64, .MOVSB, "A4");
            testOp0(m64, .MOVSW, "66 A5");
            testOp0(m64, .MOVSD, "A5");
            testOp0(m64, .MOVSQ, "48 A5");

            testOp0(m32, .MOVSB, "A4");
            testOp0(m32, .MOVSW, "66 A5");
            testOp0(m32, .MOVSD, "A5");
            testOp0(m32, .MOVSQ, AsmError.InvalidOperand);

            // CMPS
            testOp0(m64, .CMPSB, "A6");
            testOp0(m64, .CMPSW, "66 A7");
            testOp0(m64, .CMPSD, "A7");
            testOp0(m64, .CMPSQ, "48 A7");

            testOp0(m32, .CMPSB, "A6");
            testOp0(m32, .CMPSW, "66 A7");
            testOp0(m32, .CMPSD, "A7");
            testOp0(m32, .CMPSQ, AsmError.InvalidOperand);

            // STOS
            testOp0(m64, .STOSB, "AA");
            testOp0(m64, .STOSW, "66 AB");
            testOp0(m64, .STOSD, "AB");
            testOp0(m64, .STOSQ, "48 AB");

            testOp0(m32, .STOSB, "AA");
            testOp0(m32, .STOSW, "66 AB");
            testOp0(m32, .STOSD, "AB");
            testOp0(m32, .STOSQ, AsmError.InvalidOperand);

            // LODS
            testOp0(m64, .LODSB, "AC");
            testOp0(m64, .LODSW, "66 AD");
            testOp0(m64, .LODSD, "AD");
            testOp0(m64, .LODSQ, "48 AD");

            testOp0(m32, .LODSB, "AC");
            testOp0(m32, .LODSW, "66 AD");
            testOp0(m32, .LODSD, "AD");
            testOp0(m32, .LODSQ, AsmError.InvalidOperand);

            // SCAS
            testOp0(m64, .SCASB, "AE");
            testOp0(m64, .SCASW, "66 AF");
            testOp0(m64, .SCASD, "AF");
            testOp0(m64, .SCASQ, "48 AF");

            testOp0(m32, .SCASB, "AE");
            testOp0(m32, .SCASW, "66 AF");
            testOp0(m32, .SCASD, "AF");
            testOp0(m32, .SCASQ, AsmError.InvalidOperand);
        }
    }

    {
        const op1 = Operand.immediate16(0x1100);
        testOp0(m32, .RETN, "C3");
        testOp0(m32, .RETF, "CB");
        testOp1(m32, .RETN, op1, "C2 00 11");
        testOp1(m32, .RETF, op1, "CA 00 11");

        testOp0(m32, .IRET, "66 CF");
        testOp0(m32, .IRETD, "CF");
        testOp0(m32, .IRETQ, AsmError.InvalidOperand);
        testOp0(m64, .IRET, "66 CF");
        testOp0(m64, .IRETD, "CF");
        testOp0(m64, .IRETQ, "48 CF");
    }

    {
        const op1 = Operand.immediate8(0x0A);
        testOp1(m32, .AAD, op1, "D5 0A");
        testOp1(m32, .AAM, op1, "D4 0A");
        testOp1(m64, .AAD, op1, AsmError.InvalidOperand);
        testOp1(m64, .AAM, op1, AsmError.InvalidOperand);
    }

    {
        const op1 = Operand.immediate8(0x0A);
        testOp1(m32, .INT, op1, "CD 0A");
        testOp0(m32, .INT1, "F1");
        testOp0(m32, .INT3, "CC");
        testOp0(m32, .INTO, "CE");
        testOp1(m64, .INT, op1, "CD 0A");
        testOp0(m64, .INT1, "F1");
        testOp0(m64, .INT3, "CC");
        testOp0(m64, .INTO, AsmError.InvalidOperand);
    }

    {
        // IN
        const imm8 = Operand.immediate8(0x00);
        const al = Operand.register(.AL);
        const ax = Operand.register(.AX);
        const eax = Operand.register(.EAX);
        const dx = Operand.register(.DX);
        testOp2(m32, .IN, al, imm8, "E4 00");
        testOp2(m32, .IN, ax, imm8, "66 E5 00");
        testOp2(m32, .IN, eax, imm8, "E5 00");
        testOp2(m32, .IN, al, dx, "EC");
        testOp2(m32, .IN, ax, dx, "66 ED");
        testOp2(m32, .IN, eax, dx, "ED");
        // OUT
        testOp2(m32, .OUT, imm8, al,  "E6 00");
        testOp2(m32, .OUT, imm8, ax,  "66 E7 00");
        testOp2(m32, .OUT, imm8, eax, "E7 00");
        testOp2(m32, .OUT, dx, al, "EE");
        testOp2(m32, .OUT, dx, ax, "66 EF");
        testOp2(m32, .OUT, dx, eax, "EF");
    }

    // Unary
    {
        {
            const op1 = Operand.registerRm(.AL);
            testOp1(m32, .INC, op1, "FE C0");
            testOp1(m32, .DEC, op1, "FE C8");
            testOp1(m32, .NOT, op1, "F6 D0");
            testOp1(m32, .NEG, op1, "F6 D8");
        }

        {
            const op1 = Operand.registerRm(.AX);
            testOp1(m32, .INC, op1, "66 FF C0");
            testOp1(m32, .DEC, op1, "66 FF C8");
            testOp1(m32, .NOT, op1, "66 F7 D0");
            testOp1(m32, .NEG, op1, "66 F7 D8");
        }

        {
            const op1 = Operand.registerRm(.EAX);
            testOp1(m32, .INC, op1, "FF C0");
            testOp1(m32, .DEC, op1, "FF C8");
            testOp1(m32, .NOT, op1, "F7 D0");
            testOp1(m32, .NEG, op1, "F7 D8");
        }

        {
            const op1 = Operand.registerRm(.RAX);
            testOp1(m32, .INC, op1, AsmError.InvalidOperand);
            testOp1(m32, .DEC, op1, AsmError.InvalidOperand);
            testOp1(m32, .NOT, op1, AsmError.InvalidOperand);
            testOp1(m32, .NEG, op1, AsmError.InvalidOperand);
            testOp1(m64, .INC, op1, "48 FF C0");
            testOp1(m64, .DEC, op1, "48 FF C8");
            testOp1(m64, .NOT, op1, "48 F7 D0");
            testOp1(m64, .NEG, op1, "48 F7 D8");
        }

        {
            const op1 = Operand.register(.AX);
            testOp1(m32, .INC, op1, "66 40");
            testOp1(m32, .DEC, op1, "66 48");
            testOp1(m64, .INC, op1, "66 FF C0");
            testOp1(m64, .DEC, op1, "66 FF C8");
        }

        {
            const op1 = Operand.register(.EAX);
            testOp1(m32, .INC, op1, "40");
            testOp1(m32, .DEC, op1, "48");
            testOp1(m64, .INC, op1, "FF C0");
            testOp1(m64, .DEC, op1, "FF C8");
        }
    }

    // LEA
    {
        {
            const op1 = Operand.register(.EAX);
            const op2 = Operand.registerRm(.EAX);
            testOp2(m32, .LEA, op1, op2, AsmError.InvalidOperandCombination);
            testOp2(m64, .LEA, op1, op2, AsmError.InvalidOperandCombination);
        }

        {
            const op1 = Operand.register(.AX);
            const op2 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0x11);
            testOp2(m32, .LEA, op1, op2, "66 8D 40 11");
            testOp2(m64, .LEA, op1, op2, "66 67 8D 40 11");
        }

        {
            const op1 = Operand.register(.EAX);
            const op2 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0x11);
            testOp2(m32, .LEA, op1, op2, "8D 40 11");
            testOp2(m64, .LEA, op1, op2, "67 8D 40 11");
        }

        {
            const op1 = Operand.register(.RAX);
            const op2 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0x11);
            testOp2(m32, .LEA, op1, op2, AsmError.InvalidOperand);
            testOp2(m64, .LEA, op1, op2, "67 48 8D 40 11");
        }

        {
            const op1 = Operand.register(.EAX);
            const op2 = Operand.memoryRm(.DefaultSeg, .DWORD, .RAX, 0x11);
            testOp2(m32, .LEA, op1, op2, AsmError.InvalidOperand);
            testOp2(m64, .LEA, op1, op2, "8D 40 11");
        }

    }

    {
        {
            const op1 = Operand.register(.AX);
            const op2 = Operand.memoryRm(.DefaultSeg, .FAR_WORD, .EAX, 0x11);
            testOp2(m32, .LDS, op1, op2, "66 C5 40 11");
            testOp2(m64, .LDS, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .LES, op1, op2, "66 C4 40 11");
            testOp2(m64, .LES, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .LSS, op1, op2, "66 0F B2 40 11");
            testOp2(m64, .LSS, op1, op2, "66 67 0F B2 40 11");
            testOp2(m32, .LFS, op1, op2, "66 0F B4 40 11");
            testOp2(m64, .LFS, op1, op2, "66 67 0F B4 40 11");
            testOp2(m32, .LGS, op1, op2, "66 0F B5 40 11");
            testOp2(m64, .LGS, op1, op2, "66 67 0F B5 40 11");
        }

        {
            const op1 = Operand.register(.EAX);
            const op2 = Operand.memoryRm(.DefaultSeg, .FAR_DWORD, .EAX, 0x11);
            testOp2(m32, .LDS, op1, op2, "C5 40 11");
            testOp2(m64, .LDS, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .LES, op1, op2, "C4 40 11");
            testOp2(m64, .LES, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .LSS, op1, op2, "0F B2 40 11");
            testOp2(m64, .LSS, op1, op2, "67 0F B2 40 11");
            testOp2(m32, .LFS, op1, op2, "0F B4 40 11");
            testOp2(m64, .LFS, op1, op2, "67 0F B4 40 11");
            testOp2(m32, .LGS, op1, op2, "0F B5 40 11");
            testOp2(m64, .LGS, op1, op2, "67 0F B5 40 11");
        }

        {
            const op1 = Operand.register(.RAX);
            const op2 = Operand.memoryRm(.DefaultSeg, .FAR_QWORD, .EAX, 0x11);
            testOp2(m32, .LDS, op1, op2, AsmError.InvalidOperandCombination);
            testOp2(m64, .LDS, op1, op2, AsmError.InvalidOperandCombination);
            testOp2(m32, .LES, op1, op2, AsmError.InvalidOperandCombination);
            testOp2(m64, .LES, op1, op2, AsmError.InvalidOperandCombination);
            testOp2(m32, .LSS, op1, op2, AsmError.InvalidOperand);
            testOp2(m64, .LSS, op1, op2, "67 48 0F B2 40 11");
            testOp2(m32, .LFS, op1, op2, AsmError.InvalidOperand);
            testOp2(m64, .LFS, op1, op2, "67 48 0F B4 40 11");
            testOp2(m32, .LGS, op1, op2, AsmError.InvalidOperand);
            testOp2(m64, .LGS, op1, op2, "67 48 0F B5 40 11");
        }
    }

    // LOOP
    {
        {
            const op1 = Operand.immediate(0x11);
            testOp1(m32, .LOOP, op1, "E2 11");
            testOp1(m32, .LOOPE, op1, "E1 11");
            testOp1(m32, .LOOPNE, op1, "E0 11");
            testOp1(m64, .LOOP, op1, "E2 11");
            testOp1(m64, .LOOPE, op1, "E1 11");
            testOp1(m64, .LOOPNE, op1, "E0 11");
        }
    }
}
