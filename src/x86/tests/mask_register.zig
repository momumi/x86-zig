const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "AVX512 - mask register" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    const reg = Operand.register;
    const imm = Operand.immediate;

    const mem8 = Operand.memoryRm(.DefaultSeg, .BYTE, .EAX, 0);
    const mem16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const mem32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const mem64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);

    debugPrint(false);

    // General tests
    {
        testOp3(m32, .KADDB, reg(.K0), reg(.K0), reg(.K0), "c5 fd 4a c0");
        testOp3(m32, .KADDW, reg(.K0), reg(.K0), reg(.K0), "c5 fc 4a c0");
        testOp3(m32, .KADDD, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fd 4a c0");
        testOp3(m32, .KADDQ, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fc 4a c0");

        testOp3(m32, .KADDB, reg(.K7), reg(.K7), reg(.K7), "c5 c5 4a ff");
        testOp3(m32, .KADDW, reg(.K7), reg(.K7), reg(.K7), "c5 c4 4a ff");
        testOp3(m32, .KADDD, reg(.K7), reg(.K7), reg(.K7), "c4 e1 c5 4a ff");
        testOp3(m32, .KADDQ, reg(.K7), reg(.K7), reg(.K7), "c4 e1 c4 4a ff");

        testOp3(m32, .KADDB, reg(.K0), reg(.K7), reg(.K7), "c5 c5 4a c7");
        testOp3(m32, .KADDW, reg(.K0), reg(.K7), reg(.K7), "c5 c4 4a c7");
        testOp3(m32, .KADDD, reg(.K0), reg(.K7), reg(.K7), "c4 e1 c5 4a c7");
        testOp3(m32, .KADDQ, reg(.K0), reg(.K7), reg(.K7), "c4 e1 c4 4a c7");

        testOp3(m32, .KADDB, reg(.K7), reg(.K0), reg(.K7), "c5 fd 4a ff");
        testOp3(m32, .KADDW, reg(.K7), reg(.K0), reg(.K7), "c5 fc 4a ff");
        testOp3(m32, .KADDD, reg(.K7), reg(.K0), reg(.K7), "c4 e1 fd 4a ff");
        testOp3(m32, .KADDQ, reg(.K7), reg(.K0), reg(.K7), "c4 e1 fc 4a ff");

        testOp3(m32, .KADDB, reg(.K7), reg(.K7), reg(.K0), "c5 c5 4a f8");
        testOp3(m32, .KADDW, reg(.K7), reg(.K7), reg(.K0), "c5 c4 4a f8");
        testOp3(m32, .KADDD, reg(.K7), reg(.K7), reg(.K0), "c4 e1 c5 4a f8");
        testOp3(m32, .KADDQ, reg(.K7), reg(.K7), reg(.K0), "c4 e1 c4 4a f8");
    }

    // KMOV
    {
        testOp2(m64, .KMOVB, reg(.K0), reg(.K0), "c5 f9 90 c0   ");
        testOp2(m64, .KMOVW, reg(.K0), reg(.K0), "c5 f8 90 c0   ");
        testOp2(m64, .KMOVD, reg(.K0), reg(.K0), "c4 e1 f9 90 c0");
        testOp2(m64, .KMOVQ, reg(.K0), reg(.K0), "c4 e1 f8 90 c0");

        testOp2(m64, .KMOVB, reg(.K0), mem8 , "67 c5 f9 90 00   ");
        testOp2(m64, .KMOVW, reg(.K0), mem16, "67 c5 f8 90 00   ");
        testOp2(m64, .KMOVD, reg(.K0), mem32, "67 c4 e1 f9 90 00");
        testOp2(m64, .KMOVQ, reg(.K0), mem64, "67 c4 e1 f8 90 00");

        testOp2(m64, .KMOVB, mem8 , reg(.K0), "67 c5 f9 91 00   ");
        testOp2(m64, .KMOVW, mem16, reg(.K0), "67 c5 f8 91 00   ");
        testOp2(m64, .KMOVD, mem32, reg(.K0), "67 c4 e1 f9 91 00");
        testOp2(m64, .KMOVQ, mem64, reg(.K0), "67 c4 e1 f8 91 00");

        testOp2(m64, .KMOVB, reg(.K0), reg(.EAX), "c5 f9 92 c0   ");
        testOp2(m64, .KMOVW, reg(.K0), reg(.EAX), "c5 f8 92 c0   ");
        testOp2(m64, .KMOVD, reg(.K0), reg(.EAX), "c5 fb 92 c0   ");
        testOp2(m64, .KMOVQ, reg(.K0), reg(.RAX), "c4 e1 fb 92 c0");

        testOp2(m64, .KMOVB, reg(.EAX), reg(.K0), "c5 f9 93 c0   ");
        testOp2(m64, .KMOVW, reg(.EAX), reg(.K0), "c5 f8 93 c0   ");
        testOp2(m64, .KMOVD, reg(.EAX), reg(.K0), "c5 fb 93 c0   ");
        testOp2(m64, .KMOVQ, reg(.RAX), reg(.K0), "c4 e1 fb 93 c0");

        testOp2(m32, .KMOVB, reg(.K0), reg(.K0), "c5 f9 90 c0   ");
        testOp2(m32, .KMOVW, reg(.K0), reg(.K0), "c5 f8 90 c0   ");
        testOp2(m32, .KMOVD, reg(.K0), reg(.K0), "c4 e1 f9 90 c0");
        testOp2(m32, .KMOVQ, reg(.K0), reg(.K0), "c4 e1 f8 90 c0");

        testOp2(m32, .KMOVB, reg(.K0), mem8 , "c5 f9 90 00   ");
        testOp2(m32, .KMOVW, reg(.K0), mem16, "c5 f8 90 00   ");
        testOp2(m32, .KMOVD, reg(.K0), mem32, "c4 e1 f9 90 00");
        testOp2(m32, .KMOVQ, reg(.K0), mem64, "c4 e1 f8 90 00");

        testOp2(m32, .KMOVB, mem8 , reg(.K0), "c5 f9 91 00   ");
        testOp2(m32, .KMOVW, mem16, reg(.K0), "c5 f8 91 00   ");
        testOp2(m32, .KMOVD, mem32, reg(.K0), "c4 e1 f9 91 00");
        testOp2(m32, .KMOVQ, mem64, reg(.K0), "c4 e1 f8 91 00");

        testOp2(m32, .KMOVB, reg(.K0), reg(.EAX), "c5 f9 92 c0   ");
        testOp2(m32, .KMOVW, reg(.K0), reg(.EAX), "c5 f8 92 c0   ");
        testOp2(m32, .KMOVD, reg(.K0), reg(.EAX), "c5 fb 92 c0   ");
        testOp2(m32, .KMOVQ, reg(.K0), reg(.RAX), AsmError.InvalidOperand);

        testOp2(m32, .KMOVB, reg(.EAX), reg(.K0), "c5 f9 93 c0   ");
        testOp2(m32, .KMOVW, reg(.EAX), reg(.K0), "c5 f8 93 c0   ");
        testOp2(m32, .KMOVD, reg(.EAX), reg(.K0), "c5 fb 93 c0   ");
        testOp2(m32, .KMOVQ, reg(.RAX), reg(.K0), AsmError.InvalidOperand);
    }

    testOp3(m64, .KADDB, reg(.K0), reg(.K0), reg(.K0), "c5 fd 4a c0");
    testOp3(m64, .KADDW, reg(.K0), reg(.K0), reg(.K0), "c5 fc 4a c0");
    testOp3(m64, .KADDD, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fd 4a c0");
    testOp3(m64, .KADDQ, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fc 4a c0");

    testOp3(m64, .KANDB, reg(.K0), reg(.K0), reg(.K0), "c5 fd 41 c0");
    testOp3(m64, .KANDW, reg(.K0), reg(.K0), reg(.K0), "c5 fc 41 c0");
    testOp3(m64, .KANDD, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fd 41 c0");
    testOp3(m64, .KANDQ, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fc 41 c0");

    testOp3(m64, .KANDNB, reg(.K0), reg(.K0), reg(.K0), "c5 fd 42 c0");
    testOp3(m64, .KANDNW, reg(.K0), reg(.K0), reg(.K0), "c5 fc 42 c0");
    testOp3(m64, .KANDND, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fd 42 c0");
    testOp3(m64, .KANDNQ, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fc 42 c0");

    testOp2(m64, .KNOTB, reg(.K0), reg(.K0), "c5 f9 44 c0");
    testOp2(m64, .KNOTW, reg(.K0), reg(.K0), "c5 f8 44 c0");
    testOp2(m64, .KNOTD, reg(.K0), reg(.K0), "c4 e1 f9 44 c0");
    testOp2(m64, .KNOTQ, reg(.K0), reg(.K0), "c4 e1 f8 44 c0");

    testOp3(m64, .KORB, reg(.K0), reg(.K0), reg(.K0), "c5 fd 45 c0");
    testOp3(m64, .KORW, reg(.K0), reg(.K0), reg(.K0), "c5 fc 45 c0");
    testOp3(m64, .KORD, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fd 45 c0");
    testOp3(m64, .KORQ, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fc 45 c0");

    testOp2(m64, .KORTESTB, reg(.K0), reg(.K0), "c5 f9 98 c0");
    testOp2(m64, .KORTESTW, reg(.K0), reg(.K0), "c5 f8 98 c0");
    testOp2(m64, .KORTESTD, reg(.K0), reg(.K0), "c4 e1 f9 98 c0");
    testOp2(m64, .KORTESTQ, reg(.K0), reg(.K0), "c4 e1 f8 98 c0");

    testOp3(m64, .KSHIFTLB, reg(.K0), reg(.K0), imm(0), "c4 e3 79 32 c0 00");
    testOp3(m64, .KSHIFTLW, reg(.K0), reg(.K0), imm(0), "c4 e3 f9 32 c0 00");
    testOp3(m64, .KSHIFTLD, reg(.K0), reg(.K0), imm(0), "c4 e3 79 33 c0 00");
    testOp3(m64, .KSHIFTLQ, reg(.K0), reg(.K0), imm(0), "c4 e3 f9 33 c0 00");

    testOp3(m64, .KSHIFTRB, reg(.K0), reg(.K0), imm(0), "c4 e3 79 30 c0 00");
    testOp3(m64, .KSHIFTRW, reg(.K0), reg(.K0), imm(0), "c4 e3 f9 30 c0 00");
    testOp3(m64, .KSHIFTRD, reg(.K0), reg(.K0), imm(0), "c4 e3 79 31 c0 00");
    testOp3(m64, .KSHIFTRQ, reg(.K0), reg(.K0), imm(0), "c4 e3 f9 31 c0 00");

    testOp2(m64, .KTESTB, reg(.K0), reg(.K0), "c5 f9 99 c0");
    testOp2(m64, .KTESTW, reg(.K0), reg(.K0), "c5 f8 99 c0");
    testOp2(m64, .KTESTD, reg(.K0), reg(.K0), "c4 e1 f9 99 c0");
    testOp2(m64, .KTESTQ, reg(.K0), reg(.K0), "c4 e1 f8 99 c0");

    testOp3(m64, .KUNPCKBW, reg(.K0), reg(.K0), reg(.K0), "c5 fd 4b c0   ");
    testOp3(m64, .KUNPCKWD, reg(.K0), reg(.K0), reg(.K0), "c5 fc 4b c0   ");
    testOp3(m64, .KUNPCKDQ, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fc 4b c0");

    testOp3(m64, .KXNORB, reg(.K0), reg(.K0), reg(.K0), "c5 fd 46 c0   ");
    testOp3(m64, .KXNORW, reg(.K0), reg(.K0), reg(.K0), "c5 fc 46 c0   ");
    testOp3(m64, .KXNORD, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fd 46 c0");
    testOp3(m64, .KXNORQ, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fc 46 c0");

    testOp3(m64, .KXORB, reg(.K0), reg(.K0), reg(.K0), "c5 fd 47 c0   ");
    testOp3(m64, .KXORW, reg(.K0), reg(.K0), reg(.K0), "c5 fc 47 c0   ");
    testOp3(m64, .KXORD, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fd 47 c0");
    testOp3(m64, .KXORQ, reg(.K0), reg(.K0), reg(.K0), "c4 e1 fc 47 c0");

}

