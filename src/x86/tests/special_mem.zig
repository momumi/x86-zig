const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

const imm = Operand.immediate;
const mem = Operand.memory;
const memRm = Operand.memoryRm;
const reg = Operand.register;

test "string and XLAT instructions" {
    const m16 = Machine.init(.x86_16);
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    // INS   BYTE ES:[(E/R)DI], DX
    // INS   WORD ES:[(E/R)DI], DX
    // INS   DWORD ES:[(E/R)DI], DX
    //
    {
        {
            testOp2(m16, .INS, memRm(.ES, .BYTE, .DI, 0), reg(.DX), "6c");
            testOp2(m32, .INS, memRm(.ES, .BYTE, .DI, 0), reg(.DX), "67 6c");
            testOp2(m64, .INS, memRm(.ES, .BYTE, .DI, 0), reg(.DX), AsmError.InvalidOperand);
            //
            testOp2(m16, .INS, memRm(.ES, .BYTE, .EDI, 0), reg(.DX), "67 6c");
            testOp2(m32, .INS, memRm(.ES, .BYTE, .EDI, 0), reg(.DX), "6c");
            testOp2(m64, .INS, memRm(.ES, .BYTE, .EDI, 0), reg(.DX), "67 6c");
            //
            testOp2(m16, .INS, memRm(.ES, .BYTE, .RDI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m32, .INS, memRm(.ES, .BYTE, .RDI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m64, .INS, memRm(.ES, .BYTE, .RDI, 0), reg(.DX), "6c");
        }

        {
            testOp2(m16, .INS, memRm(.ES, .WORD, .DI, 0), reg(.DX), "6d");
            testOp2(m32, .INS, memRm(.ES, .WORD, .DI, 0), reg(.DX), "66 67 6d");
            testOp2(m64, .INS, memRm(.ES, .WORD, .DI, 0), reg(.DX), AsmError.InvalidOperand);
            //
            testOp2(m16, .INS, memRm(.ES, .WORD, .EDI, 0), reg(.DX), "67 6d");
            testOp2(m32, .INS, memRm(.ES, .WORD, .EDI, 0), reg(.DX), "66 6d");
            testOp2(m64, .INS, memRm(.ES, .WORD, .EDI, 0), reg(.DX), "66 67 6d");
            //
            testOp2(m16, .INS, memRm(.ES, .WORD, .RDI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m32, .INS, memRm(.ES, .WORD, .RDI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m64, .INS, memRm(.ES, .WORD, .RDI, 0), reg(.DX), "66 6d");
        }

        {
            testOp2(m16, .INS, memRm(.ES, .DWORD, .DI, 0), reg(.DX), "66 6d");
            testOp2(m32, .INS, memRm(.ES, .DWORD, .DI, 0), reg(.DX), "67 6d");
            testOp2(m64, .INS, memRm(.ES, .DWORD, .DI, 0), reg(.DX), AsmError.InvalidOperand);
            //
            testOp2(m16, .INS, memRm(.ES, .DWORD, .EDI, 0), reg(.DX), "66 67 6d");
            testOp2(m32, .INS, memRm(.ES, .DWORD, .EDI, 0), reg(.DX), "6d");
            testOp2(m64, .INS, memRm(.ES, .DWORD, .EDI, 0), reg(.DX), "67 6d");
            //
            testOp2(m16, .INS, memRm(.ES, .DWORD, .RDI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m32, .INS, memRm(.ES, .DWORD, .RDI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m64, .INS, memRm(.ES, .DWORD, .RDI, 0), reg(.DX), "6d");
        }

        {
            testOp2(m16, .INS, memRm(.ES, .QWORD, .DI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m32, .INS, memRm(.ES, .QWORD, .DI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m64, .INS, memRm(.ES, .QWORD, .DI, 0), reg(.DX), AsmError.InvalidOperand);
            //
            testOp2(m16, .INS, memRm(.ES, .QWORD, .EDI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m32, .INS, memRm(.ES, .QWORD, .EDI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m64, .INS, memRm(.ES, .QWORD, .EDI, 0), reg(.DX), AsmError.InvalidOperand);
            //
            testOp2(m16, .INS, memRm(.ES, .QWORD, .RDI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m32, .INS, memRm(.ES, .QWORD, .RDI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m64, .INS, memRm(.ES, .QWORD, .RDI, 0), reg(.DX), AsmError.InvalidOperand);
        }

        {
            testOp2(m16, .INS, mem(.ES, .BYTE, 0, null, .EAX, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m32, .INS, mem(.ES, .BYTE, 0, null, .EAX, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m64, .INS, mem(.ES, .BYTE, 0, null, .EAX, 0), reg(.DX), AsmError.InvalidOperand);
            // TODO
            // testOp2(m16, .INS, mem(.ES, .BYTE, 0, .EAX, null, 0), reg(.DX), AsmError.InvalidOperand);
            // testOp2(m32, .INS, mem(.ES, .BYTE, 0, .EAX, null, 0), reg(.DX), AsmError.InvalidOperand);
            // testOp2(m64, .INS, mem(.ES, .BYTE, 0, .EAX, null, 0), reg(.DX), AsmError.InvalidOperand);
            //
            testOp2(m16, .INS, mem(.ES, .BYTE, 0, null, .EDI, 0), reg(.CX), AsmError.InvalidOperand);
            testOp2(m32, .INS, mem(.ES, .BYTE, 0, null, .EDI, 0), reg(.CX), AsmError.InvalidOperand);
            testOp2(m64, .INS, mem(.ES, .BYTE, 0, null, .EDI, 0), reg(.CX), AsmError.InvalidOperand);
            //
            testOp2(m16, .INS, mem(.ES, .XMM_WORD, 0, null, .EDI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m32, .INS, mem(.ES, .XMM_WORD, 0, null, .EDI, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m64, .INS, mem(.ES, .XMM_WORD, 0, null, .EDI, 0), reg(.DX), AsmError.InvalidOperand);
            //
            testOp2(m16, .INS, mem(.ES, .BYTE, 1, .BL, .AL, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m32, .INS, mem(.ES, .BYTE, 1, .BL, .AL, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m64, .INS, mem(.ES, .BYTE, 1, .BL, .AL, 0), reg(.DX), AsmError.InvalidOperand);
            //
            testOp2(m16, .INS, memRm(.ES, .DWORD, .EDI, 1), reg(.DX), AsmError.InvalidOperand);
            testOp2(m32, .INS, memRm(.ES, .DWORD, .EDI, 1), reg(.DX), AsmError.InvalidOperand);
            testOp2(m64, .INS, memRm(.ES, .DWORD, .EDI, 1), reg(.DX), AsmError.InvalidOperand);
            //
            testOp2(m16, .INS, mem(.ES, .DWORD, 1, .EDI, null, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m32, .INS, mem(.ES, .DWORD, 1, .EDI, null, 0), reg(.DX), AsmError.InvalidOperand);
            testOp2(m64, .INS, mem(.ES, .DWORD, 1, .EDI, null, 0), reg(.DX), AsmError.InvalidOperand);
        }
    }

    // STOS  BYTE ES:[(E/R)DI], AL
    // STOS  WORD ES:[(E/R)DI], AX
    // STOS  DWORD ES:[(E/R)DI], EAX
    // STOS  QWORD ES:[(E/R)DI], RAX
    {
        testOp2(m64, .STOS, memRm(.ES, .BYTE, .DI, 0), reg(.AL), AsmError.InvalidOperand);
        testOp2(m64, .STOS, memRm(.ES, .BYTE, .EDI, 0), reg(.AL), "67 aa");
        testOp2(m64, .STOS, memRm(.ES, .BYTE, .RDI, 0), reg(.AL), "aa");
        //
        testOp2(m64, .STOS, memRm(.ES, .WORD, .DI, 0), reg(.AX), AsmError.InvalidOperand);
        testOp2(m64, .STOS, memRm(.ES, .WORD, .EDI, 0), reg(.AX), "66 67 ab");
        testOp2(m64, .STOS, memRm(.ES, .WORD, .RDI, 0), reg(.AX), "66 ab");
        //
        testOp2(m64, .STOS, memRm(.ES, .DWORD, .DI, 0), reg(.EAX), AsmError.InvalidOperand);
        testOp2(m64, .STOS, memRm(.ES, .DWORD, .EDI, 0), reg(.EAX), "67 ab");
        testOp2(m64, .STOS, memRm(.ES, .DWORD, .RDI, 0), reg(.EAX), "ab");
        //
        testOp2(m64, .STOS, memRm(.ES, .QWORD, .DI, 0), reg(.RAX), AsmError.InvalidOperand);
        testOp2(m64, .STOS, memRm(.ES, .QWORD, .EDI, 0), reg(.RAX), "67 48 ab");
        testOp2(m64, .STOS, memRm(.ES, .QWORD, .RDI, 0), reg(.RAX), "48 ab");
    }

    // SCAS  BYTE ES:[(E/R)DI], AL
    // SCAS  WORD ES:[(E/R)DI], AX
    // SCAS  DWORD ES:[(E/R)DI], EAX
    // SCAS  QWORD ES:[(E/R)DI], RAX
    {
        testOp2(m64, .SCAS, memRm(.ES, .BYTE, .DI, 0), reg(.AL), AsmError.InvalidOperand);
        testOp2(m64, .SCAS, memRm(.ES, .BYTE, .EDI, 0), reg(.AL), "67 ae");
        testOp2(m64, .SCAS, memRm(.ES, .BYTE, .RDI, 0), reg(.AL), "ae");
        //
        testOp2(m64, .SCAS, memRm(.ES, .WORD, .DI, 0), reg(.AX), AsmError.InvalidOperand);
        testOp2(m64, .SCAS, memRm(.ES, .WORD, .EDI, 0), reg(.AX), "66 67 af");
        testOp2(m64, .SCAS, memRm(.ES, .WORD, .RDI, 0), reg(.AX), "66 af");
        //
        testOp2(m64, .SCAS, memRm(.ES, .DWORD, .DI, 0), reg(.EAX), AsmError.InvalidOperand);
        testOp2(m64, .SCAS, memRm(.ES, .DWORD, .EDI, 0), reg(.EAX), "67 af");
        testOp2(m64, .SCAS, memRm(.ES, .DWORD, .RDI, 0), reg(.EAX), "af");
        //
        testOp2(m64, .SCAS, memRm(.ES, .QWORD, .DI, 0), reg(.RAX), AsmError.InvalidOperand);
        testOp2(m64, .SCAS, memRm(.ES, .QWORD, .EDI, 0), reg(.RAX), "67 48 af");
        testOp2(m64, .SCAS, memRm(.ES, .QWORD, .RDI, 0), reg(.RAX), "48 af");
        //
        testOp2(m64, .SCAS, reg(.AL), memRm(.ES, .BYTE, .DI, 0), AsmError.InvalidOperand);
        testOp2(m64, .SCAS, reg(.AL), memRm(.ES, .BYTE, .EDI, 0), AsmError.InvalidOperand);
        testOp2(m64, .SCAS, reg(.AL), memRm(.ES, .BYTE, .RDI, 0), AsmError.InvalidOperand);
    }

    // LODS  AL, BYTE DS:[(E/R)SI]
    // LODS  AX, WORD DS:[(E/R)SI]
    // LODS  EAX, DWORD DS:[(E/R)SI]
    // LODS  RAX, QWORD DS:[(E/R)SI]
    {
        {
            testOp2(m16, .LODS, reg(.AL), memRm(.DS, .BYTE, .SI, 0), "ac");
            testOp2(m32, .LODS, reg(.AL), memRm(.DS, .BYTE, .SI, 0), "67 ac");
            testOp2(m64, .LODS, reg(.AL), memRm(.DS, .BYTE, .SI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .LODS, reg(.AL), memRm(.DS, .BYTE, .ESI, 0), "67 ac");
            testOp2(m32, .LODS, reg(.AL), memRm(.DS, .BYTE, .ESI, 0), "ac");
            testOp2(m64, .LODS, reg(.AL), memRm(.DS, .BYTE, .ESI, 0), "67 ac");
            //
            testOp2(m16, .LODS, reg(.AL), memRm(.DS, .BYTE, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m32, .LODS, reg(.AL), memRm(.DS, .BYTE, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m64, .LODS, reg(.AL), memRm(.DS, .BYTE, .RSI, 0), "ac");
        }

        {
            testOp2(m16, .LODS, reg(.AX), memRm(.DS, .WORD, .SI, 0), "ad");
            testOp2(m32, .LODS, reg(.AX), memRm(.DS, .WORD, .SI, 0), "66 67 ad");
            testOp2(m64, .LODS, reg(.AX), memRm(.DS, .WORD, .SI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .LODS, reg(.AX), memRm(.DS, .WORD, .ESI, 0), "67 ad");
            testOp2(m32, .LODS, reg(.AX), memRm(.DS, .WORD, .ESI, 0), "66 ad");
            testOp2(m64, .LODS, reg(.AX), memRm(.DS, .WORD, .ESI, 0), "66 67 ad");
            //
            testOp2(m16, .LODS, reg(.AX), memRm(.DS, .WORD, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m32, .LODS, reg(.AX), memRm(.DS, .WORD, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m64, .LODS, reg(.AX), memRm(.DS, .WORD, .RSI, 0), "66 ad");
        }

        {
            testOp2(m16, .LODS, reg(.EAX), memRm(.DS, .DWORD, .SI, 0), "66 ad");
            testOp2(m32, .LODS, reg(.EAX), memRm(.DS, .DWORD, .SI, 0), "67 ad");
            testOp2(m64, .LODS, reg(.EAX), memRm(.DS, .DWORD, .SI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .LODS, reg(.EAX), memRm(.DS, .DWORD, .ESI, 0), "66 67 ad");
            testOp2(m32, .LODS, reg(.EAX), memRm(.DS, .DWORD, .ESI, 0), "ad");
            testOp2(m64, .LODS, reg(.EAX), memRm(.DS, .DWORD, .ESI, 0), "67 ad");
            //
            testOp2(m16, .LODS, reg(.EAX), memRm(.DS, .DWORD, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m32, .LODS, reg(.EAX), memRm(.DS, .DWORD, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m64, .LODS, reg(.EAX), memRm(.DS, .DWORD, .RSI, 0), "ad");
        }

        {
            testOp2(m16, .LODS, reg(.RAX), memRm(.DS, .QWORD, .SI, 0), AsmError.InvalidOperand);
            testOp2(m32, .LODS, reg(.RAX), memRm(.DS, .QWORD, .SI, 0), AsmError.InvalidOperand);
            testOp2(m64, .LODS, reg(.RAX), memRm(.DS, .QWORD, .SI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .LODS, reg(.RAX), memRm(.DS, .QWORD, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m32, .LODS, reg(.RAX), memRm(.DS, .QWORD, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m64, .LODS, reg(.RAX), memRm(.DS, .QWORD, .ESI, 0), "67 48 ad");
            //
            testOp2(m16, .LODS, reg(.RAX), memRm(.DS, .QWORD, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m32, .LODS, reg(.RAX), memRm(.DS, .QWORD, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m64, .LODS, reg(.RAX), memRm(.DS, .QWORD, .RSI, 0), "48 ad");
        }

        {
            testOp2(m16, .LODS, reg(.EAX), memRm(.DS, .BYTE, .EAX, 0), AsmError.InvalidOperand);
            testOp2(m32, .LODS, reg(.EAX), memRm(.DS, .BYTE, .EAX, 0), AsmError.InvalidOperand);
            testOp2(m64, .LODS, reg(.EAX), memRm(.DS, .BYTE, .EAX, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .LODS, reg(.EAX), memRm(.DS, .BYTE, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m32, .LODS, reg(.EAX), memRm(.DS, .BYTE, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m64, .LODS, reg(.EAX), memRm(.DS, .BYTE, .ESI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .LODS, reg(.EAX), memRm(.DS, .XMM_WORD, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m32, .LODS, reg(.EAX), memRm(.DS, .XMM_WORD, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m64, .LODS, reg(.EAX), memRm(.DS, .XMM_WORD, .ESI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .LODS, reg(.EAX), mem(.DS, .BYTE, 1, .BL, .AL, 0), AsmError.InvalidOperand);
            testOp2(m32, .LODS, reg(.EAX), mem(.DS, .BYTE, 1, .BL, .AL, 0), AsmError.InvalidOperand);
            testOp2(m64, .LODS, reg(.EAX), mem(.DS, .BYTE, 1, .BL, .AL, 0), AsmError.InvalidOperand);
        }
    }
    // OUTS  DX, BYTE DS:[(E/R)SI]
    // OUTS  DX, WORD DS:[(E/R)SI]
    // OUTS  DX, DWORD DS:[(E/R)SI]
    {
        {
            testOp2(m64, .OUTS, reg(.DX), memRm(.DS, .BYTE, .SI, 0), AsmError.InvalidOperand);
            testOp2(m64, .OUTS, reg(.DX), memRm(.DS, .BYTE, .ESI, 0), "67 6e");
            testOp2(m64, .OUTS, reg(.DX), memRm(.DS, .BYTE, .RSI, 0), "6e");
            //
            testOp2(m64, .OUTS, reg(.DX), memRm(.DS, .WORD, .SI, 0), AsmError.InvalidOperand);
            testOp2(m64, .OUTS, reg(.DX), memRm(.DS, .WORD, .ESI, 0), "66 67 6f");
            testOp2(m64, .OUTS, reg(.DX), memRm(.DS, .WORD, .RSI, 0), "66 6f");
            //
            testOp2(m64, .OUTS, reg(.DX), memRm(.DS, .DWORD, .SI, 0), AsmError.InvalidOperand);
            testOp2(m64, .OUTS, reg(.DX), memRm(.DS, .DWORD, .ESI, 0), "67 6f");
            testOp2(m64, .OUTS, reg(.DX), memRm(.DS, .DWORD, .RSI, 0), "6f");
            //
            testOp2(m64, .OUTS, reg(.DX), memRm(.DS, .QWORD, .SI, 0), AsmError.InvalidOperand);
            testOp2(m64, .OUTS, reg(.DX), memRm(.DS, .QWORD, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m64, .OUTS, reg(.DX), memRm(.DS, .QWORD, .RSI, 0), AsmError.InvalidOperand);
        }

    }

    // CMPS  BYTE ES:[(R/E)DI], BYTE DS:[(R/E)SI]
    // CMPS  WORD ES:[(R/E)DI], WORD DS:[(R/E)SI]
    // CMPS  DWORD ES:[(R/E)DI], DWORD DS:[(R/E)SI]
    // CMPS  QWORD ES:[(R/E)DI], QWORD DS:[(R/E)SI]
    {
        {
            testOp2(m16, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .SI, 0), "a6");
            testOp2(m32, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .SI, 0), "67 a6");
            testOp2(m64, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .SI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .CMPS, memRm(.ES, .BYTE, .EDI, 0), memRm(.DS, .BYTE, .ESI, 0), "67 a6");
            testOp2(m32, .CMPS, memRm(.ES, .BYTE, .EDI, 0), memRm(.DS, .BYTE, .ESI, 0), "a6");
            testOp2(m64, .CMPS, memRm(.ES, .BYTE, .EDI, 0), memRm(.DS, .BYTE, .ESI, 0), "67 a6");
            //
            testOp2(m16, .CMPS, memRm(.ES, .BYTE, .RDI, 0), memRm(.DS, .BYTE, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .BYTE, .RDI, 0), memRm(.DS, .BYTE, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .BYTE, .RDI, 0), memRm(.DS, .BYTE, .RSI, 0), "a6");
        }

        {
            testOp2(m16, .CMPS, memRm(.ES, .WORD, .DI, 0), memRm(.DS, .WORD, .SI, 0), "a7");
            testOp2(m32, .CMPS, memRm(.ES, .WORD, .DI, 0), memRm(.DS, .WORD, .SI, 0), "66 67 a7");
            testOp2(m64, .CMPS, memRm(.ES, .WORD, .DI, 0), memRm(.DS, .WORD, .SI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .CMPS, memRm(.ES, .WORD, .EDI, 0), memRm(.DS, .WORD, .ESI, 0), "67 a7");
            testOp2(m32, .CMPS, memRm(.ES, .WORD, .EDI, 0), memRm(.DS, .WORD, .ESI, 0), "66 a7");
            testOp2(m64, .CMPS, memRm(.ES, .WORD, .EDI, 0), memRm(.DS, .WORD, .ESI, 0), "66 67 a7");
            //
            testOp2(m16, .CMPS, memRm(.ES, .WORD, .RDI, 0), memRm(.DS, .WORD, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .WORD, .RDI, 0), memRm(.DS, .WORD, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .WORD, .RDI, 0), memRm(.DS, .WORD, .RSI, 0), "66 a7");
        }

        {
            testOp2(m16, .CMPS, memRm(.ES, .DWORD, .DI, 0), memRm(.DS, .DWORD, .SI, 0), "66 a7");
            testOp2(m32, .CMPS, memRm(.ES, .DWORD, .DI, 0), memRm(.DS, .DWORD, .SI, 0), "67 a7");
            testOp2(m64, .CMPS, memRm(.ES, .DWORD, .DI, 0), memRm(.DS, .DWORD, .SI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .CMPS, memRm(.ES, .DWORD, .EDI, 0), memRm(.DS, .DWORD, .ESI, 0), "66 67 a7");
            testOp2(m32, .CMPS, memRm(.ES, .DWORD, .EDI, 0), memRm(.DS, .DWORD, .ESI, 0), "a7");
            testOp2(m64, .CMPS, memRm(.ES, .DWORD, .EDI, 0), memRm(.DS, .DWORD, .ESI, 0), "67 a7");
            //
            testOp2(m16, .CMPS, memRm(.ES, .DWORD, .RDI, 0), memRm(.DS, .DWORD, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .DWORD, .RDI, 0), memRm(.DS, .DWORD, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .DWORD, .RDI, 0), memRm(.DS, .DWORD, .RSI, 0), "a7");
        }

        {
            testOp2(m16, .CMPS, memRm(.ES, .QWORD, .DI, 0), memRm(.DS, .QWORD, .SI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .QWORD, .DI, 0), memRm(.DS, .QWORD, .SI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .QWORD, .DI, 0), memRm(.DS, .QWORD, .SI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .CMPS, memRm(.ES, .QWORD, .EDI, 0), memRm(.DS, .QWORD, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .QWORD, .EDI, 0), memRm(.DS, .QWORD, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .QWORD, .EDI, 0), memRm(.DS, .QWORD, .ESI, 0), "67 48 a7");
            //
            testOp2(m16, .CMPS, memRm(.ES, .QWORD, .RDI, 0), memRm(.DS, .QWORD, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .QWORD, .RDI, 0), memRm(.DS, .QWORD, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .QWORD, .RDI, 0), memRm(.DS, .QWORD, .RSI, 0), "48 a7");
        }

        {
            testOp2(m16, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .EAX, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .EAX, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .EAX, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .ESI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .CMPS, memRm(.ES, .BYTE, .EDI, 0), memRm(.DS, .BYTE, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .BYTE, .EDI, 0), memRm(.DS, .BYTE, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .BYTE, .EDI, 0), memRm(.DS, .BYTE, .RSI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .RSI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .RSI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .CMPS, memRm(.ES, .BYTE, .ESI, 0), memRm(.DS, .BYTE, .EDI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .BYTE, .ESI, 0), memRm(.DS, .BYTE, .EDI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .BYTE, .ESI, 0), memRm(.DS, .BYTE, .EDI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .CMPS, memRm(.ES, .WORD, .EDI, 0), memRm(.DS, .BYTE, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .WORD, .EDI, 0), memRm(.DS, .BYTE, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .WORD, .EDI, 0), memRm(.DS, .BYTE, .ESI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .CMPS, memRm(.ES, .WORD, .EDI, 0), memRm(.DS, .DWORD, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .WORD, .EDI, 0), memRm(.DS, .DWORD, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .WORD, .EDI, 0), memRm(.DS, .DWORD, .ESI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .XMM_WORD, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .XMM_WORD, .ESI, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .XMM_WORD, .ESI, 0), AsmError.InvalidOperand);
            //
            testOp2(m16, .CMPS, memRm(.ES, .BYTE, .DI, 0), mem(.DS, .BYTE, 1, .BL, .AL, 0), AsmError.InvalidOperand);
            testOp2(m32, .CMPS, memRm(.ES, .BYTE, .DI, 0), mem(.DS, .BYTE, 1, .BL, .AL, 0), AsmError.InvalidOperand);
            testOp2(m64, .CMPS, memRm(.ES, .BYTE, .DI, 0), mem(.DS, .BYTE, 1, .BL, .AL, 0), AsmError.InvalidOperand);
        }
    }

    // MOVS  BYTE ES:[(E/R)DI], BYTE DS:[(E/R)SI]
    // MOVS  WORD ES:[(E/R)DI], WORD DS:[(E/R)SI]
    // MOVS  DWORD ES:[(E/R)DI], DWORD DS:[(E/R)SI]
    // MOVS  QWORD ES:[(E/R)DI], QWORD DS:[(E/R)SI]
    {
        testOp2(m64, .MOVS, memRm(.ES, .BYTE, .DI, 0), memRm(.DS, .BYTE, .SI, 0), AsmError.InvalidOperand);
        testOp2(m64, .MOVS, memRm(.ES, .BYTE, .EDI, 0), memRm(.DS, .BYTE, .ESI, 0), "67 a4");
        testOp2(m64, .MOVS, memRm(.ES, .BYTE, .RDI, 0), memRm(.DS, .BYTE, .RSI, 0), "a4");
        //
        testOp2(m64, .MOVS, memRm(.ES, .WORD, .DI, 0), memRm(.DS, .WORD, .SI, 0), AsmError.InvalidOperand);
        testOp2(m64, .MOVS, memRm(.ES, .WORD, .EDI, 0), memRm(.DS, .WORD, .ESI, 0), "66 67 a5");
        testOp2(m64, .MOVS, memRm(.ES, .WORD, .RDI, 0), memRm(.DS, .WORD, .RSI, 0), "66 a5");
        //
        testOp2(m64, .MOVS, memRm(.ES, .DWORD, .DI, 0), memRm(.DS, .DWORD, .SI, 0), AsmError.InvalidOperand);
        testOp2(m64, .MOVS, memRm(.ES, .DWORD, .EDI, 0), memRm(.DS, .DWORD, .ESI, 0), "67 a5");
        testOp2(m64, .MOVS, memRm(.ES, .DWORD, .RDI, 0), memRm(.DS, .DWORD, .RSI, 0), "a5");
        //
        testOp2(m64, .MOVS, memRm(.ES, .QWORD, .DI, 0), memRm(.DS, .QWORD, .SI, 0), AsmError.InvalidOperand);
        testOp2(m64, .MOVS, memRm(.ES, .QWORD, .EDI, 0), memRm(.DS, .QWORD, .ESI, 0), "67 48 a5");
        testOp2(m64, .MOVS, memRm(.ES, .QWORD, .RDI, 0), memRm(.DS, .QWORD, .RSI, 0), "48 a5");
    }

    // XLAT AL, BYTE DS:[(E/R)BX + AL]
    {
        testOp0(m32, .XLATB, "D7");
        //
        testOp2(m16, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .BL, .AL, 0), AsmError.InvalidOperand);
        testOp2(m32, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .BL, .AL, 0), AsmError.InvalidOperand);
        testOp2(m64, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .BL, .AL, 0), AsmError.InvalidOperand);
        //
        testOp2(m16, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .BX, .AL, 0), "D7");
        testOp2(m32, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .BX, .AL, 0), "67 D7");
        testOp2(m64, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .BX, .AL, 0), AsmError.InvalidOperand);
        //
        testOp2(m16, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .EBX, .AL, 0), "67 D7");
        testOp2(m32, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .EBX, .AL, 0), "D7");
        testOp2(m64, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .EBX, .AL, 0), "67 D7");
        //
        testOp2(m16, .XLAT, reg(.AL), mem(.DefaultSeg, .BYTE, 1, .RBX, .AL, 0), AsmError.InvalidOperand);
        testOp2(m32, .XLAT, reg(.AL), mem(.DefaultSeg, .BYTE, 1, .RBX, .AL, 0), AsmError.InvalidOperand);
        testOp2(m64, .XLAT, reg(.AL), mem(.DefaultSeg, .BYTE, 1, .RBX, .AL, 0), "D7");
        //
        testOp2(m16, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .AL, .BL, 0), AsmError.InvalidOperand);
        testOp2(m32, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .AL, .BL, 0), AsmError.InvalidOperand);
        testOp2(m64, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .AL, .BL, 0), AsmError.InvalidOperand);
        //
        testOp2(m16, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .AL, .BX, 0), "D7");
        testOp2(m32, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .AL, .BX, 0), "67 D7");
        testOp2(m64, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .AL, .BX, 0), AsmError.InvalidOperand);
        //
        testOp2(m16, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .AL, .EBX, 0), "67 D7");
        testOp2(m32, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .AL, .EBX, 0), "D7");
        testOp2(m64, .XLAT, reg(.AL), mem(.DS, .BYTE, 1, .AL, .EBX, 0), "67 D7");
        //
        testOp2(m16, .XLAT, reg(.AL), mem(.DefaultSeg, .BYTE, 1, .AL, .RBX, 0), AsmError.InvalidOperand);
        testOp2(m32, .XLAT, reg(.AL), mem(.DefaultSeg, .BYTE, 1, .AL, .RBX, 0), AsmError.InvalidOperand);
        testOp2(m64, .XLAT, reg(.AL), mem(.DefaultSeg, .BYTE, 1, .AL, .RBX, 0), "D7");
    }

}
