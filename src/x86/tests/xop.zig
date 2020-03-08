const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

const reg = Operand.register;
const pred = Operand.registerPredicate;
const predRm = Operand.rmPredicate;
const sae = Operand.registerSae;
const regRm = Operand.registerRm;
const imm = Operand.immediate;

test "XOP" {
    const m16 = Machine.init(.x86_32);
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    const rm8 = Operand.memoryRm(.DefaultSeg, .BYTE, .EAX, 0);
    const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const mem_64 = rm64;
    const rm_mem8 = Operand.memoryRm(.DefaultSeg, .BYTE, .EAX, 0);
    const rm_mem16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const rm_mem32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm_mem64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const rm_mem128 = Operand.memoryRm(.DefaultSeg, .XMM_WORD, .EAX, 0);
    const rm_mem256 = Operand.memoryRm(.DefaultSeg, .YMM_WORD, .EAX, 0);

    {
        // BEXTR
        testOp3(m64, .BEXTR,   reg(.EAX), rm32, imm(0x44332211), "67 8f ea 78 10 00 11 22 33 44");
        testOp3(m64, .BEXTR,   reg(.RAX), rm64, imm(0x44332211), "67 8f ea f8 10 00 11 22 33 44");
        // BLCFILL
        testOp2(m64, .BLCFILL, reg(.EAX), rm32, "67 8f e9 78 01 08");
        testOp2(m64, .BLCFILL, reg(.RAX), rm64, "67 8f e9 f8 01 08");
        // BLCI
        testOp2(m64, .BLCI,    reg(.EAX), rm32, "67 8f e9 78 02 30");
        testOp2(m64, .BLCI,    reg(.RAX), rm64, "67 8f e9 f8 02 30");
        // BLCIC
        testOp2(m64, .BLCIC,   reg(.EAX), rm32, "67 8f e9 78 01 28");
        testOp2(m64, .BLCIC,   reg(.RAX), rm64, "67 8f e9 f8 01 28");
        // BLCMSK
        testOp2(m64, .BLCMSK,  reg(.EAX), rm32, "67 8f e9 78 02 08");
        testOp2(m64, .BLCMSK,  reg(.RAX), rm64, "67 8f e9 f8 02 08");
        // BLCS
        testOp2(m64, .BLCS,    reg(.EAX), rm32, "67 8f e9 78 01 18");
        testOp2(m64, .BLCS,    reg(.RAX), rm64, "67 8f e9 f8 01 18");
        // BLSFILL
        testOp2(m64, .BLSFILL, reg(.EAX), rm32, "67 8f e9 78 01 10");
        testOp2(m64, .BLSFILL, reg(.RAX), rm64, "67 8f e9 f8 01 10");
        // BLSIC
        testOp2(m64, .BLSIC,   reg(.EAX), rm32, "67 8f e9 78 01 30");
        testOp2(m64, .BLSIC,   reg(.RAX), rm64, "67 8f e9 f8 01 30");
        // T1MSKC
        testOp2(m64, .T1MSKC,  reg(.EAX), rm32, "67 8f e9 78 01 38");
        testOp2(m64, .T1MSKC,  reg(.RAX), rm64, "67 8f e9 f8 01 38");
        // TZMSK
        testOp2(m64, .TZMSK,   reg(.EAX), rm32, "67 8f e9 78 01 20");
        testOp2(m64, .TZMSK,   reg(.RAX), rm64, "67 8f e9 f8 01 20");
    }

    //
    // LWP
    //
    {
        // LLWPCB
        testOp1(m64, .LLWPCB,   reg(.ECX), "8f e9 78 12 c1");
        testOp1(m64, .LLWPCB,   reg(.RCX), "8f e9 f8 12 c1");
        // LWPINS
        testOp3(m64, .LWPINS,   reg(.ECX), rm32, imm(0x44332211), "67 8f ea 70 12 00 11 22 33 44");
        testOp3(m64, .LWPINS,   reg(.RCX), rm32, imm(0x44332211), "67 8f ea f0 12 00 11 22 33 44");
        // LWPVAL
        testOp3(m64, .LWPVAL,   reg(.ECX), rm32, imm(0x44332211), "67 8f ea 70 12 08 11 22 33 44");
        testOp3(m64, .LWPVAL,   reg(.RCX), rm32, imm(0x44332211), "67 8f ea f0 12 08 11 22 33 44");
        // SLWPCB
        testOp1(m64, .SLWPCB,   reg(.ECX), "8f e9 78 12 c9");
        testOp1(m64, .SLWPCB,   reg(.RCX), "8f e9 f8 12 c9");
    }

    {
        // VFRCZPD
        testOp2(m64, .VFRCZPD,  reg(.XMM1), regRm(.XMM0), "8f e9 78 81 c8");
        testOp2(m64, .VFRCZPD,  reg(.YMM1), regRm(.YMM0), "8f e9 7c 81 c8");
        // VFRCZPS
        testOp2(m64, .VFRCZPS,  reg(.XMM1), regRm(.XMM0), "8f e9 78 80 c8");
        testOp2(m64, .VFRCZPS,  reg(.YMM1), regRm(.YMM0), "8f e9 7c 80 c8");
        // VFRCZSD
        testOp2(m64, .VFRCZSD,  reg(.XMM1), regRm(.XMM0), "8f e9 78 83 c8");
        // VFRCZSS
        testOp2(m64, .VFRCZSS,  reg(.XMM1), regRm(.XMM0), "8f e9 78 82 c8");
    }

    {
        // VPCMOV
        testOp4(m64, .VPCMOV,   reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 a2 c8 30");
        testOp4(m64, .VPCMOV,   reg(.YMM1),reg(.YMM2),regRm(.YMM0),reg(.YMM3), "8f e8 6c a2 c8 30");
        testOp4(m64, .VPCMOV,   reg(.XMM1),reg(.XMM2),reg(.XMM3),regRm(.XMM0), "8f e8 e8 a2 c8 30");
        testOp4(m64, .VPCMOV,   reg(.YMM1),reg(.YMM2),reg(.YMM3),regRm(.YMM0), "8f e8 ec a2 c8 30");
    }

    {
        // VPCOMB / VPCOMW / VPCOMD / VPCOMQ
        testOp4(m64, .VPCOMB,   reg(.XMM1),reg(.XMM2),regRm(.XMM0),imm(0), "8f e8 68 cc c8 00");
        testOp4(m64, .VPCOMW,   reg(.XMM1),reg(.XMM2),regRm(.XMM0),imm(0), "8f e8 68 cd c8 00");
        testOp4(m64, .VPCOMD,   reg(.XMM1),reg(.XMM2),regRm(.XMM0),imm(0), "8f e8 68 ce c8 00");
        testOp4(m64, .VPCOMQ,   reg(.XMM1),reg(.XMM2),regRm(.XMM0),imm(0), "8f e8 68 cf c8 00");
        // VPCOMUB / VPCOMUW / VPCOMUD / VPCOMUQ
        testOp4(m64, .VPCOMUB,  reg(.XMM1),reg(.XMM2),regRm(.XMM0),imm(0), "8f e8 68 ec c8 00");
        testOp4(m64, .VPCOMUW,  reg(.XMM1),reg(.XMM2),regRm(.XMM0),imm(0), "8f e8 68 ed c8 00");
        testOp4(m64, .VPCOMUD,  reg(.XMM1),reg(.XMM2),regRm(.XMM0),imm(0), "8f e8 68 ee c8 00");
        testOp4(m64, .VPCOMUQ,  reg(.XMM1),reg(.XMM2),regRm(.XMM0),imm(0), "8f e8 68 ef c8 00");
    }

    {
        // VPERMIL2PD
        testOp5(m64, .VPERMIL2PD,  reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3),imm(0), "c4 e3 69 49 c8 30");
        testOp5(m64, .VPERMIL2PD,  reg(.XMM1),reg(.XMM2),reg(.XMM3),regRm(.XMM0),imm(0), "c4 e3 e9 49 c8 30");
        testOp5(m64, .VPERMIL2PD,  reg(.YMM1),reg(.YMM2),regRm(.YMM0),reg(.YMM3),imm(0), "c4 e3 6d 49 c8 30");
        testOp5(m64, .VPERMIL2PD,  reg(.YMM1),reg(.YMM2),reg(.YMM3),regRm(.YMM0),imm(0), "c4 e3 ed 49 c8 30");
        // VPERMIL2PS
        testOp5(m64, .VPERMIL2PS,  reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3),imm(0), "c4 e3 69 48 c8 30");
        testOp5(m64, .VPERMIL2PS,  reg(.XMM1),reg(.XMM2),reg(.XMM3),regRm(.XMM0),imm(0), "c4 e3 e9 48 c8 30");
        testOp5(m64, .VPERMIL2PS,  reg(.YMM1),reg(.YMM2),regRm(.YMM0),reg(.YMM3),imm(0), "c4 e3 6d 48 c8 30");
        testOp5(m64, .VPERMIL2PS,  reg(.YMM1),reg(.YMM2),reg(.YMM3),regRm(.YMM0),imm(0), "c4 e3 ed 48 c8 30");
        // imm
        testOp5(m64, .VPERMIL2PS,  reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3),imm(0x04), "c4 e3 69 48 c8 34");
        testOp5(m64, .VPERMIL2PS,  reg(.XMM1),reg(.XMM2),reg(.XMM3),regRm(.XMM0),imm(0x07), "c4 e3 e9 48 c8 37");
        testOp5(m64, .VPERMIL2PS,  reg(.YMM1),reg(.YMM2),regRm(.YMM0),reg(.YMM3),imm(0x08), "c4 e3 6d 48 c8 38");
        testOp5(m64, .VPERMIL2PS,  reg(.YMM1),reg(.YMM2),reg(.YMM3),regRm(.YMM0),imm(0x0F), "c4 e3 ed 48 c8 3F");
        testOp5(m64, .VPERMIL2PS,  reg(.YMM1),reg(.YMM2),reg(.YMM3),regRm(.YMM0),imm(0x10), AsmError.InvalidImmediate);
        testOp5(m64, .VPERMIL2PS,  reg(.YMM1),reg(.YMM2),reg(.YMM3),regRm(.YMM0),imm(0x11), AsmError.InvalidImmediate);
        testOp5(m64, .VPERMIL2PS,  reg(.YMM1),reg(.YMM2),reg(.YMM3),regRm(.YMM0),imm(0xFF), AsmError.InvalidImmediate);
    }

    {
        // VPHADDBD / VPHADDBW / VPHADDBQ
        testOp2(m64, .VPHADDBW,    reg(.XMM1), regRm(.XMM0), "8f e9 78 c1 c8");
        testOp2(m64, .VPHADDBD,    reg(.XMM1), regRm(.XMM0), "8f e9 78 c2 c8");
        testOp2(m64, .VPHADDBQ,    reg(.XMM1), regRm(.XMM0), "8f e9 78 c3 c8");
        // VPHADDWD / VPHADDWQ
        testOp2(m64, .VPHADDWD,    reg(.XMM1), regRm(.XMM0), "8f e9 78 c6 c8");
        testOp2(m64, .VPHADDWQ,    reg(.XMM1), regRm(.XMM0), "8f e9 78 c7 c8");
        // VPHADDDQ
        testOp2(m64, .VPHADDDQ,    reg(.XMM1), regRm(.XMM0), "8f e9 78 cb c8");
        // VPHADDUBD / VPHADDUBW / VPHADDUBQ
        testOp2(m64, .VPHADDUBW,   reg(.XMM1), regRm(.XMM0), "8f e9 78 d1 c8");
        testOp2(m64, .VPHADDUBD,   reg(.XMM1), regRm(.XMM0), "8f e9 78 d2 c8");
        testOp2(m64, .VPHADDUBQ,   reg(.XMM1), regRm(.XMM0), "8f e9 78 d3 c8");
        // VPHADDUWD / VPHADDUWQ
        testOp2(m64, .VPHADDUWD,   reg(.XMM1), regRm(.XMM0), "8f e9 78 d6 c8");
        testOp2(m64, .VPHADDUWQ,   reg(.XMM1), regRm(.XMM0), "8f e9 78 d7 c8");
        // VPHADDUDQ
        testOp2(m64, .VPHADDUDQ,   reg(.XMM1), regRm(.XMM0), "8f e9 78 db c8");
    }

    {
        // VPHSUBBW
        testOp2(m64, .VPHSUBBW,    reg(.XMM1), regRm(.XMM0), "8f e9 78 e1 c8");
        // VPHSUBDQ
        testOp2(m64, .VPHSUBDQ,    reg(.XMM1), regRm(.XMM0), "8f e9 78 e3 c8");
        // VPHSUBWD
        testOp2(m64, .VPHSUBWD,    reg(.XMM1), regRm(.XMM0), "8f e9 78 e2 c8");
    }

    {
        // VPMACSDD
        testOp4(m64, .VPMACSDD,    reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 9e c8 30");
        // VPMACSDQH
        testOp4(m64, .VPMACSDQH,   reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 9f c8 30");
        // VPMACSDQL
        testOp4(m64, .VPMACSDQL,   reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 97 c8 30");
        // VPMACSSDD
        testOp4(m64, .VPMACSSDD,   reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 8e c8 30");
        // VPMACSSDQH
        testOp4(m64, .VPMACSSDQH,  reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 8f c8 30");
        // VPMACSSDQL
        testOp4(m64, .VPMACSSDQL,  reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 87 c8 30");
        // VPMACSSWD
        testOp4(m64, .VPMACSSWD,   reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 86 c8 30");
        // VPMACSSWW
        testOp4(m64, .VPMACSSWW,   reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 85 c8 30");
        // VPMACSWD
        testOp4(m64, .VPMACSWD,    reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 96 c8 30");
        // VPMACSWW
        testOp4(m64, .VPMACSWW,    reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 95 c8 30");
    }

    {
        // VPMADCSSWD
        testOp4(m64, .VPMADCSSWD,  reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 a6 c8 30");
        // VPMADCSWD
        testOp4(m64, .VPMADCSWD,   reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8f e8 68 b6 c8 30");
    }

    {
        // VPPERM
        testOp4(m64, .VPPERM,      reg(.XMM1),reg(.XMM2),regRm(.XMM0),reg(.XMM3), "8fe868a3c830");
        testOp4(m64, .VPPERM,      reg(.XMM1),reg(.XMM2),reg(.XMM3),regRm(.XMM0), "8fe8e8a3c830");
    }

    {
        // VPROTB / VPROTW / VPROTD / VPROTQ
        // VPROTB
        testOp3(m64, .VPROTB,      reg(.XMM1), regRm(.XMM0), reg(.XMM2), "8f e9 68 90 c8");
        testOp3(m64, .VPROTB,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "8f e9 e8 90 c8");
        testOp3(m64, .VPROTB,      reg(.XMM1), regRm(.XMM0), imm(0), "8f e8 78 c0 c8 00");
        // VPROTW
        testOp3(m64, .VPROTW,      reg(.XMM1), regRm(.XMM0), reg(.XMM2), "8f e9 68 91 c8");
        testOp3(m64, .VPROTW,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "8f e9 e8 91 c8");
        testOp3(m64, .VPROTW,      reg(.XMM1), regRm(.XMM0), imm(0), "8f e8 78 c1 c8 00");
        // VPROTD
        testOp3(m64, .VPROTD,      reg(.XMM1), regRm(.XMM0), reg(.XMM2), "8f e9 68 92 c8");
        testOp3(m64, .VPROTD,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "8f e9 e8 92 c8");
        testOp3(m64, .VPROTD,      reg(.XMM1), regRm(.XMM0), imm(0), "8f e8 78 c2 c8 00");
        // VPROTQ
        testOp3(m64, .VPROTQ,      reg(.XMM1), regRm(.XMM0), reg(.XMM2), "8f e9 68 93 c8");
        testOp3(m64, .VPROTQ,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "8f e9 e8 93 c8");
        testOp3(m64, .VPROTQ,      reg(.XMM1), regRm(.XMM0), imm(0), "8f e8 78 c3 c8 00");
    }

    {
        // VPSHAB / VPSHAW / VPSHAD / VPSHAQ
        // VPSHAB
        testOp3(m64, .VPSHAB,      reg(.XMM1), regRm(.XMM0), reg(.XMM2), "8f e9 68 98 c8");
        testOp3(m64, .VPSHAB,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "8f e9 e8 98 c8");
        // VPSHAW
        testOp3(m64, .VPSHAW,      reg(.XMM1), regRm(.XMM0), reg(.XMM2), "8f e9 68 99 c8");
        testOp3(m64, .VPSHAW,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "8f e9 e8 99 c8");
        // VPSHAD
        testOp3(m64, .VPSHAD,      reg(.XMM1), regRm(.XMM0), reg(.XMM2), "8f e9 68 9a c8");
        testOp3(m64, .VPSHAD,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "8f e9 e8 9a c8");
        // VPSHAQ
        testOp3(m64, .VPSHAQ,      reg(.XMM1), regRm(.XMM0), reg(.XMM2), "8f e9 68 9b c8");
        testOp3(m64, .VPSHAQ,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "8f e9 e8 9b c8");
    }

    {
        // VPSHLB / VPSHLW / VPSHLD / VPSHLQ
        // VPSHLB
        testOp3(m64, .VPSHLB,      reg(.XMM1), regRm(.XMM0), reg(.XMM2), "8f e9 68 94 c8");
        testOp3(m64, .VPSHLB,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "8f e9 e8 94 c8");
        // VPSHLW
        testOp3(m64, .VPSHLW,      reg(.XMM1), regRm(.XMM0), reg(.XMM2), "8f e9 68 95 c8");
        testOp3(m64, .VPSHLW,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "8f e9 e8 95 c8");
        // VPSHLD
        testOp3(m64, .VPSHLD,      reg(.XMM1), regRm(.XMM0), reg(.XMM2), "8f e9 68 96 c8");
        testOp3(m64, .VPSHLD,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "8f e9 e8 96 c8");
        // VPSHLQ
        testOp3(m64, .VPSHLQ,      reg(.XMM1), regRm(.XMM0), reg(.XMM2), "8f e9 68 97 c8");
        testOp3(m64, .VPSHLQ,      reg(.XMM1), reg(.XMM2), regRm(.XMM0), "8f e9 e8 97 c8");
    }
}
