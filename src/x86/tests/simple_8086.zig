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

        testOp0(m32, .WAIT, "9B");
        testOp0(m32, .FWAIT, "9B");

        testOp0(m32, .XLAT, "D7");
        testOp0(m32, .XLATB, "D7");

        testOp1(m64, .XLAT, Operand.voidOperand(.QWORD), "48 D7");

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

}
