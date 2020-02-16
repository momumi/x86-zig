const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "bit manipulation" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    const reg = Operand.register;
    const regRm = Operand.registerRm;
    const imm = Operand.immediate;

    debugPrint(false);

    const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);

    {
        const reg16 = Operand.register(.AX);
        const reg32 = Operand.register(.EAX);
        const reg64 = Operand.register(.RAX);
        // LZCNT
        testOp2(m32, .LZCNT,  reg16, rm16, "66 F3 0F BD 00");
        testOp2(m32, .LZCNT,  reg32, rm32, "F3 0F BD 00");
        testOp2(m32, .LZCNT,  reg64, rm64, AsmError.InvalidOperand);
        // POPCNT
        testOp2(m32, .POPCNT, reg16, rm16, "66 F3 0F B8 00");
        testOp2(m32, .POPCNT, reg32, rm32, "F3 0F B8 00");
        testOp2(m32, .POPCNT, reg64, rm64, AsmError.InvalidOperand);
        // TZCNT
        testOp2(m32, .TZCNT,  reg16, rm16, "66 F3 0F BC 00");
        testOp2(m32, .TZCNT,  reg32, rm32, "F3 0F BC 00");
        testOp2(m32, .TZCNT,  reg64, rm64, AsmError.InvalidOperand);

        // LZCNT
        testOp2(m64, .LZCNT,  reg16, rm16, "66 67 F3 0F BD 00");
        testOp2(m64, .LZCNT,  reg32, rm32, "67 F3 0F BD 00");
        testOp2(m64, .LZCNT,  reg64, rm64, "67 F3 48 0F BD 00");
        // POPCNT
        testOp2(m64, .POPCNT, reg16, rm16, "66 67 F3 0F B8 00");
        testOp2(m64, .POPCNT, reg32, rm32, "67 F3 0F B8 00");
        testOp2(m64, .POPCNT, reg64, rm64, "67 F3 48 0F B8 00");
        // TZCNT
        testOp2(m64, .TZCNT,  reg16, rm16, "66 67 F3 0F BC 00");
        testOp2(m64, .TZCNT,  reg32, rm32, "67 F3 0F BC 00");
        testOp2(m64, .TZCNT,  reg64, rm64, "67 F3 48 0F BC 00");
    }

    testOp3(m64, .ANDN, reg(.EAX), reg(.EAX), rm32, "67 c4 e2 78 f2 00");
    testOp3(m64, .ANDN, reg(.RAX), reg(.RAX), rm64, "67 c4 e2 f8 f2 00");

    testOp3(m64, .BEXTR, reg(.EAX), rm32, reg(.EAX), "67 c4 e2 78 f7 00");
    testOp3(m64, .BEXTR, reg(.RAX), rm64, reg(.RAX), "67 c4 e2 f8 f7 00");

    testOp2(m64, .BLSI, reg(.EAX), rm32, "67 c4 e2 78 f3 18");
    testOp2(m64, .BLSI, reg(.RAX), rm64, "67 c4 e2 f8 f3 18");

    testOp2(m64, .BLSMSK, reg(.EAX), rm32, "67 c4 e2 78 f3 10");
    testOp2(m64, .BLSMSK, reg(.RAX), rm64, "67 c4 e2 f8 f3 10");

    testOp2(m64, .BLSR, reg(.EAX), rm32, "67 c4 e2 78 f3 08");
    testOp2(m64, .BLSR, reg(.RAX), rm64, "67 c4 e2 f8 f3 08");

    testOp3(m64, .BZHI, reg(.EAX), rm32, reg(.EAX), "67 c4 e2 78 f5 00");
    testOp3(m64, .BZHI, reg(.RAX), rm64, reg(.RAX), "67 c4 e2 f8 f5 00");

    testOp3(m64, .MULX, reg(.EAX), reg(.EAX), rm32, "67 c4 e2 7b f6 00");
    testOp3(m64, .MULX, reg(.RAX), reg(.RAX), rm64, "67 c4 e2 fb f6 00");

    testOp3(m64, .PDEP, reg(.EAX), reg(.EAX), rm32, "67 c4 e2 7b f5 00");
    testOp3(m64, .PDEP, reg(.RAX), reg(.RAX), rm64, "67 c4 e2 fb f5 00");

    testOp3(m64, .PEXT, reg(.EAX), reg(.EAX), rm32, "67 c4 e2 7a f5 00");
    testOp3(m64, .PEXT, reg(.RAX), reg(.RAX), rm64, "67 c4 e2 fa f5 00");

    testOp3(m64, .RORX, reg(.EAX), rm32, imm(0), "67 c4 e3 7b f0 00 00");
    testOp3(m64, .RORX, reg(.RAX), rm64, imm(0), "67 c4 e3 fb f0 00 00");

    testOp3(m64, .SARX, reg(.EAX), rm32, reg(.EAX), "67 c4 e2 7a f7 00");
    testOp3(m64, .SARX, reg(.RAX), rm64, reg(.RAX), "67 c4 e2 fa f7 00");

    testOp3(m64, .SHLX, reg(.EAX), rm32, reg(.EAX), "67 c4 e2 79 f7 00");
    testOp3(m64, .SHLX, reg(.RAX), rm64, reg(.RAX), "67 c4 e2 f9 f7 00");

    testOp3(m64, .SHRX, reg(.EAX), rm32, reg(.EAX), "67 c4 e2 7b f7 00");
    testOp3(m64, .SHRX, reg(.RAX), rm64, reg(.RAX), "67 c4 e2 fb f7 00");

}
