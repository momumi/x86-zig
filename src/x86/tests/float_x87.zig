const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "x87 floating point instructions" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    const sreg = Operand.register;
    const memRm = Operand.memoryRmDef;

    debugPrint(false);

    {
        testOp1(m64, .FLD, sreg(.ST0), "D9 C0");
        testOp1(m64, .FLD, sreg(.ST1), "D9 C1");
        testOp1(m64, .FLD, sreg(.ST2), "D9 C2");
        testOp1(m64, .FLD, sreg(.ST3), "D9 C3");
        testOp1(m64, .FLD, sreg(.ST4), "D9 C4");
        testOp1(m64, .FLD, sreg(.ST5), "D9 C5");
        testOp1(m64, .FLD, sreg(.ST6), "D9 C6");
        testOp1(m64, .FLD, sreg(.ST7), "D9 C7");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .DWORD, .RAX, 0);
        testOp1(m64, .FLD, op1, "D9 00");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .QWORD, .RAX, 0);
        testOp1(m64, .FLD, op1, "DD 00");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .TBYTE, .RAX, 0);
        testOp1(m64, .FLD, op1, "DB 28");
    }

    {
        testOp1(m32, .FLDCW, memRm(.Void, .EAX, 0), "D9 28");
        testOp1(m64, .FLDCW, memRm(.Void, .EAX, 0), "67 D9 28");
        testOp1(m32, .FLDCW, memRm(.WORD, .EAX, 0), "D9 28");
        testOp1(m64, .FLDCW, memRm(.WORD, .EAX, 0), "67 D9 28");

        testOp1(m32, .FLDENV, memRm(.Void, .EAX, 0), "D9 20");
        testOp1(m64, .FLDENV, memRm(.Void, .EAX, 0), "67 D9 20");
    }

    {
        testOp1(m64, .FMUL, sreg(.ST0),              "D8 C8");
        testOp2(m64, .FMUL, sreg(.ST0), sreg(.ST7),  "D8 CF");
        testOp2(m64, .FMUL, sreg(.ST0), sreg(.ST0),  "DC C8");
        testOp2(m64, .FMUL, sreg(.ST7), sreg(.ST0),  "DC CF");

        testOp2(m64, .FMULP, sreg(.ST7), sreg(.ST0), "DE CF");
        testOp0(m64, .FMULP, "DE C9");

        testOp1(m64, .FIMUL, memRm( .WORD, .RAX, 0), "DE 08");
        testOp1(m64, .FIMUL, memRm(.DWORD, .RAX, 0), "DA 08");
    }

    {
        testOp1(m64, .FSAVE,  memRm(.Void, .RAX, 0), "9B DD 30");
        testOp1(m64, .FNSAVE, memRm(.Void, .RAX, 0), "DD 30");
    }


    // zero operands
    {
        testOp0(m64, .F2XM1,   "D9 F0");
        testOp0(m64, .FABS,    "D9 E1");
        testOp0(m64, .FADDP,   "DE C1");
        testOp0(m64, .FCHS,    "D9 E0");
        testOp0(m64, .FCLEX,   "9B DB E2");
        testOp0(m64, .FNCLEX,  "DB E2");
        testOp0(m64, .FCOM,    "D8 D1");
        testOp0(m64, .FCOMP,   "D8 D9");
        testOp0(m64, .FCOMPP,  "DE D9");
        testOp0(m64, .FDECSTP, "D9 F6");
        testOp0(m64, .FDIVP,   "DE F9");
        testOp0(m64, .FDIVRP,  "DE F1");
        testOp0(m64, .FINCSTP, "D9 F7");
        testOp0(m64, .FINIT,   "9B DB E3");
        testOp0(m64, .FNINIT,  "DB E3");
        testOp0(m64, .FLD1,    "D9 E8");
        testOp0(m64, .FLDL2T,  "D9 E9");
        testOp0(m64, .FLDL2E,  "D9 EA");
        testOp0(m64, .FLDPI,   "D9 EB");
        testOp0(m64, .FLDLG2,  "D9 EC");
        testOp0(m64, .FLDLN2,  "D9 ED");
        testOp0(m64, .FLDZ,    "D9 EE");
        testOp0(m64, .FMULP,   "DE C9");
        testOp0(m64, .FSUBP,   "DE E9");
        testOp0(m64, .FNOP,    "D9 D0");
        testOp0(m64, .FPATAN,  "D9 F3");
        testOp0(m64, .FPREM,   "D9 F8");
        testOp0(m64, .FPTAN,   "D9 F2");
        testOp0(m64, .FRNDINT, "D9 FC");
        testOp0(m64, .FSCALE,  "D9 FD");
        testOp0(m64, .FSQRT,   "D9 FA");
        testOp0(m64, .FSUBRP,  "DE E1");
        testOp0(m64, .FTST,    "D9 E4");
        testOp0(m64, .FWAIT,   "9B");
        testOp0(m64, .FXAM,    "D9 E5");
        testOp0(m64, .FXCH,    "D9 C9");
        testOp0(m64, .FXTRACT, "D9 F4");
        testOp0(m64, .FYL2X,   "D9 F1");
        testOp0(m64, .FYL2XP1, "D9 F9");
        testOp0(m64, .FCOS,    "D9 FF");
        testOp0(m64, .FPREM1,  "D9 F5");
        testOp0(m64, .FSIN,    "D9 FE");
        testOp0(m64, .FSINCOS, "D9 FB");
        testOp0(m64, .FUCOM,   "DD E1");
        testOp0(m64, .FUCOMP,  "DD E9");
        testOp0(m64, .FUCOMPP, "DA E9");

    }

    // one ST(i) reg operand
    {
        testOp1(m64, .FADD,     sreg(.ST1), "D8 C1");
        testOp1(m64, .FCOM,     sreg(.ST1), "D8 D1");
        testOp1(m64, .FCOMP,    sreg(.ST1), "D8 D9");
        testOp1(m64, .FDIV,     sreg(.ST1), "D8 F1");
        testOp1(m64, .FDIVR,    sreg(.ST1), "D8 F9");
        testOp1(m64, .FFREE,    sreg(.ST1), "DD C1");
        testOp1(m64, .FFREEP,   sreg(.ST1), "DF C1");
        testOp1(m64, .FLD,      sreg(.ST1), "D9 C1");
        testOp1(m64, .FMUL,     sreg(.ST1), "D8 C9");
        testOp1(m64, .FSUB,     sreg(.ST1), "D8 E1");
        testOp1(m64, .FSUBR,    sreg(.ST1), "D8 E9");
        testOp1(m64, .FST,      sreg(.ST1), "DD D1");
        testOp1(m64, .FSTP,     sreg(.ST1), "DD D9");
        testOp1(m64, .FXCH,     sreg(.ST1), "D9 C9");
        testOp1(m64, .FUCOM,    sreg(.ST1), "DD E1");
        testOp1(m64, .FUCOMP,   sreg(.ST1), "DD E9");
        testOp1(m64, .FCMOVB,   sreg(.ST1), "DA C1");
        testOp1(m64, .FCMOVE,   sreg(.ST1), "DA C9");
        testOp1(m64, .FCMOVBE,  sreg(.ST1), "DA D1");
        testOp1(m64, .FCMOVU,   sreg(.ST1), "DA D9");
        testOp1(m64, .FCMOVNB,  sreg(.ST1), "DB C1");
        testOp1(m64, .FCMOVNE,  sreg(.ST1), "DB C9");
        testOp1(m64, .FCMOVNBE, sreg(.ST1), "DB D1");
        testOp1(m64, .FCMOVNU,  sreg(.ST1), "DB D9");
        testOp1(m64, .FCOMI,    sreg(.ST1), "DB F1");
        testOp1(m64, .FCOMIP,   sreg(.ST1), "DF F1");
        testOp1(m64, .FUCOMI,   sreg(.ST1), "DB E9");
        testOp1(m64, .FUCOMIP,  sreg(.ST1), "DF E9");
        // st(0)
        testOp1(m64, .FCHS, sreg(.ST0), "D9 E0");
    }

    {
        testOp2(m64, .FADD,     sreg(.ST0), sreg(.ST1), "D8 C1");
        testOp2(m64, .FCOM,     sreg(.ST0), sreg(.ST1), "D8 D1");
        testOp2(m64, .FCOMP,    sreg(.ST0), sreg(.ST1), "D8 D9");
        testOp2(m64, .FDIV,     sreg(.ST0), sreg(.ST1), "D8 F1");
        testOp2(m64, .FDIVR,    sreg(.ST0), sreg(.ST1), "D8 F9");
        testOp2(m64, .FMUL,     sreg(.ST0), sreg(.ST1), "D8 C9");
        testOp2(m64, .FSUB,     sreg(.ST0), sreg(.ST1), "D8 E1");
        testOp2(m64, .FSUBR,    sreg(.ST0), sreg(.ST1), "D8 E9");
        testOp2(m64, .FST,      sreg(.ST0), sreg(.ST1), "DD D1");
        testOp2(m64, .FSTP,     sreg(.ST0), sreg(.ST1), "DD D9");
        testOp2(m64, .FXCH,     sreg(.ST0), sreg(.ST1), "D9 C9");
        testOp2(m64, .FUCOM,    sreg(.ST0), sreg(.ST1), "DD E1");
        testOp2(m64, .FUCOMP,   sreg(.ST0), sreg(.ST1), "DD E9");
        testOp2(m64, .FCMOVB,   sreg(.ST0), sreg(.ST1), "DA C1");
        testOp2(m64, .FCMOVE,   sreg(.ST0), sreg(.ST1), "DA C9");
        testOp2(m64, .FCMOVBE,  sreg(.ST0), sreg(.ST1), "DA D1");
        testOp2(m64, .FCMOVU,   sreg(.ST0), sreg(.ST1), "DA D9");
        testOp2(m64, .FCMOVNB,  sreg(.ST0), sreg(.ST1), "DB C1");
        testOp2(m64, .FCMOVNE,  sreg(.ST0), sreg(.ST1), "DB C9");
        testOp2(m64, .FCMOVNBE, sreg(.ST0), sreg(.ST1), "DB D1");
        testOp2(m64, .FCMOVNU,  sreg(.ST0), sreg(.ST1), "DB D9");
        testOp2(m64, .FCOMI,    sreg(.ST0), sreg(.ST1), "DB F1");
        testOp2(m64, .FCOMIP,   sreg(.ST0), sreg(.ST1), "DF F1");
        testOp2(m64, .FUCOMI,   sreg(.ST0), sreg(.ST1), "DB E9");
        testOp2(m64, .FUCOMIP,  sreg(.ST0), sreg(.ST1), "DF E9");
    }

    {
        testOp2(m64, .FADD,    sreg(.ST1), sreg(.ST0), "DC C1");
        testOp2(m64, .FADDP,   sreg(.ST1), sreg(.ST0), "DE C1");
        testOp2(m64, .FDIV,    sreg(.ST1), sreg(.ST0), "DC F9");
        testOp2(m64, .FDIVP,   sreg(.ST1), sreg(.ST0), "DE F9");
        testOp2(m64, .FDIVR,   sreg(.ST1), sreg(.ST0), "DC F1");
        testOp2(m64, .FDIVRP,  sreg(.ST1), sreg(.ST0), "DE F1");
        testOp2(m64, .FMUL,    sreg(.ST1), sreg(.ST0), "DC C9");
        testOp2(m64, .FMULP,   sreg(.ST1), sreg(.ST0), "DE C9");
        testOp2(m64, .FSUB,    sreg(.ST1), sreg(.ST0), "DC E9");
        testOp2(m64, .FSUBP,   sreg(.ST1), sreg(.ST0), "DE E9");
        testOp2(m64, .FSUBR,   sreg(.ST1), sreg(.ST0), "DC E1");
        testOp2(m64, .FSUBRP,  sreg(.ST1), sreg(.ST0), "DE E1");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .WORD, .RAX, 0);
        testOp1(m64, .FIADD,   op1, "DE 00");
        testOp1(m64, .FIDIV,   op1, "DE 30");
        testOp1(m64, .FIDIVR,  op1, "DE 38");
        testOp1(m64, .FICOM,   op1, "DE 10");
        testOp1(m64, .FICOMP,  op1, "DE 18");
        testOp1(m64, .FILD,    op1, "DF 00");
        testOp1(m64, .FIST,    op1, "DF 10");
        testOp1(m64, .FISTP,   op1, "DF 18");
        testOp1(m64, .FIMUL,   op1, "DE 08");
        testOp1(m64, .FSTCW,   op1, "9B D9 38");
        testOp1(m64, .FNSTCW,  op1, "D9 38");
        testOp1(m64, .FSTSW,   op1, "9B DD 38");
        testOp1(m64, .FNSTSW,  op1, "DD 38");
        testOp1(m64, .FISUB,   op1, "DE 20");
        testOp1(m64, .FISUBR,  op1, "DE 28");
    }

    {
        const op1 = Operand.register(.AX);
        testOp1(m64, .FSTSW,   op1, "9B DF E0");
        testOp1(m64, .FNSTSW,  op1, "DF E0");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .DWORD, .RAX, 0);
        testOp1(m64, .FADD,    op1, "D8 00");
        testOp1(m64, .FIADD,   op1, "DA 00");
        testOp1(m64, .FCOM,    op1, "D8 10");
        testOp1(m64, .FCOMP,   op1, "D8 18");
        testOp1(m64, .FDIV,    op1, "D8 30");
        testOp1(m64, .FIDIV,   op1, "DA 30");
        testOp1(m64, .FDIVR,   op1, "D8 38");
        testOp1(m64, .FIDIVR,  op1, "DA 38");
        testOp1(m64, .FICOM,   op1, "DA 10");
        testOp1(m64, .FICOMP,  op1, "DA 18");
        testOp1(m64, .FILD,    op1, "DB 00");
        testOp1(m64, .FIST,    op1, "DB 10");
        testOp1(m64, .FISTP,   op1, "DB 18");
        testOp1(m64, .FLD,     op1, "D9 00");
        testOp1(m64, .FMUL,    op1, "D8 08");
        testOp1(m64, .FIMUL,   op1, "DA 08");
        testOp1(m64, .FST,     op1, "D9 10");
        testOp1(m64, .FSTP,    op1, "D9 18");
        testOp1(m64, .FSUB,    op1, "D8 20");
        testOp1(m64, .FISUB,   op1, "DA 20");
        testOp1(m64, .FSUBR,   op1, "D8 28");
        testOp1(m64, .FISUBR,  op1, "DA 28");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .QWORD, .RAX, 0);
        testOp1(m64, .FADD,    op1, "DC 00");
        testOp1(m64, .FCOM,    op1, "DC 10");
        testOp1(m64, .FCOMP,   op1, "DC 18");
        testOp1(m64, .FDIV,    op1, "DC 30");
        testOp1(m64, .FDIVR,   op1, "DC 38");
        testOp1(m64, .FILD,    op1, "DF 28");
        testOp1(m64, .FISTP,   op1, "DF 38");
        testOp1(m64, .FLD,     op1, "DD 00");
        testOp1(m64, .FMUL,    op1, "DC 08");
        testOp1(m64, .FST,     op1, "DD 10");
        testOp1(m64, .FSTP,    op1, "DD 18");
        testOp1(m64, .FSUB,    op1, "DC 20");
        testOp1(m64, .FSUBR,   op1, "DC 28");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .Void, .RAX, 0);
        testOp1(m64, .FRSTOR,  op1, "DD 20");
        testOp1(m64, .FSAVE,   op1, "9B DD 30");
        testOp1(m64, .FNSAVE,  op1, "DD 30");
        testOp1(m64, .FSTCW,   op1, "9B D9 38");
        testOp1(m64, .FNSTCW,  op1, "D9 38");
        testOp1(m64, .FSTENV,  op1, "9B D9 30");
        testOp1(m64, .FNSTENV, op1, "D9 30");
        testOp1(m64, .FSTSW,   op1, "9B DD 38");
        testOp1(m64, .FNSTSW,  op1, "DD 38");
    }

    {
        const op1 = Operand.memoryRm(.DefaultSeg, .TBYTE, .RAX, 0);
        testOp1(m64, .FBLD,    op1, "DF 20");
        testOp1(m64, .FBSTP,   op1, "DF 30");
        testOp1(m64, .FLD,     op1, "DB 28");
        testOp1(m64, .FSTP,    op1, "DB 38");
    }
}


