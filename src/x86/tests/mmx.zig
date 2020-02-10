const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "mmx" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    const reg = Operand.register;

    debugPrint(false);

    {
        testOp0(m32, .EMMS, "0F 77");
        testOp0(m64, .EMMS, "0F 77");
    }

    {
        const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
        const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
        {
            testOp2(m32, .MOVD, reg(.MM0), rm32, "0F 6E 00");
            testOp2(m32, .MOVD, reg(.MM1), rm32, "0F 6E 08");
            testOp2(m32, .MOVD, reg(.MM2), rm32, "0F 6E 10");
            testOp2(m32, .MOVD, reg(.MM3), rm32, "0F 6E 18");
            testOp2(m32, .MOVD, reg(.MM4), rm32, "0F 6E 20");
            testOp2(m32, .MOVD, reg(.MM5), rm32, "0F 6E 28");
            testOp2(m32, .MOVD, reg(.MM6), rm32, "0F 6E 30");
            testOp2(m32, .MOVD, reg(.MM7), rm32, "0F 6E 38");
            //
            testOp2(m64, .MOVD, reg(.MM0), rm32, "67 0F 6E 00");
            testOp2(m64, .MOVD, reg(.MM1), rm32, "67 0F 6E 08");
            testOp2(m64, .MOVD, reg(.MM2), rm32, "67 0F 6E 10");
            testOp2(m64, .MOVD, reg(.MM3), rm32, "67 0F 6E 18");
            testOp2(m64, .MOVD, reg(.MM4), rm32, "67 0F 6E 20");
            testOp2(m64, .MOVD, reg(.MM5), rm32, "67 0F 6E 28");
            testOp2(m64, .MOVD, reg(.MM6), rm32, "67 0F 6E 30");
            testOp2(m64, .MOVD, reg(.MM7), rm32, "67 0F 6E 38");
        }

        {
            testOp2(m32, .MOVD, reg(.MM0), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM1), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM2), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM3), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM4), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM5), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM6), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM7), rm64, AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVD, reg(.MM0), rm64, "67 48 0F 6E 00");
            testOp2(m64, .MOVD, reg(.MM1), rm64, "67 48 0F 6E 08");
            testOp2(m64, .MOVD, reg(.MM2), rm64, "67 48 0F 6E 10");
            testOp2(m64, .MOVD, reg(.MM3), rm64, "67 48 0F 6E 18");
            testOp2(m64, .MOVD, reg(.MM4), rm64, "67 48 0F 6E 20");
            testOp2(m64, .MOVD, reg(.MM5), rm64, "67 48 0F 6E 28");
            testOp2(m64, .MOVD, reg(.MM6), rm64, "67 48 0F 6E 30");
            testOp2(m64, .MOVD, reg(.MM7), rm64, "67 48 0F 6E 38");
        }

        {
            testOp2(m32, .MOVD, reg(.MM0), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM1), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM2), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM3), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM4), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM5), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM6), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVD, reg(.MM7), rm64, AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVD, reg(.MM0), rm64, "67 48 0F 6E 00");
            testOp2(m64, .MOVD, reg(.MM1), rm64, "67 48 0F 6E 08");
            testOp2(m64, .MOVD, reg(.MM2), rm64, "67 48 0F 6E 10");
            testOp2(m64, .MOVD, reg(.MM3), rm64, "67 48 0F 6E 18");
            testOp2(m64, .MOVD, reg(.MM4), rm64, "67 48 0F 6E 20");
            testOp2(m64, .MOVD, reg(.MM5), rm64, "67 48 0F 6E 28");
            testOp2(m64, .MOVD, reg(.MM6), rm64, "67 48 0F 6E 30");
            testOp2(m64, .MOVD, reg(.MM7), rm64, "67 48 0F 6E 38");
        }

        {
            testOp2(m32, .MOVQ, reg(.MM0), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM1), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM2), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM3), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM4), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM5), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM6), rm64, AsmError.InvalidOperand);
            testOp2(m32, .MOVQ, reg(.MM7), rm64, AsmError.InvalidOperand);
            //
            testOp2(m64, .MOVQ, reg(.MM0), rm64, "67 0F 6F 00");
            testOp2(m64, .MOVQ, reg(.MM1), rm64, "67 0F 6F 08");
            testOp2(m64, .MOVQ, reg(.MM2), rm64, "67 0F 6F 10");
            testOp2(m64, .MOVQ, reg(.MM3), rm64, "67 0F 6F 18");
            testOp2(m64, .MOVQ, reg(.MM4), rm64, "67 0F 6F 20");
            testOp2(m64, .MOVQ, reg(.MM5), rm64, "67 0F 6F 28");
            testOp2(m64, .MOVQ, reg(.MM6), rm64, "67 0F 6F 30");
            testOp2(m64, .MOVQ, reg(.MM7), rm64, "67 0F 6F 38");
        }

        {
            testOp2(m32, .MOVQ, reg(.MM0), reg(.MM0), "0F 6F c0");
            testOp2(m32, .MOVQ, reg(.MM1), reg(.MM1), "0F 6F c9");
            testOp2(m32, .MOVQ, reg(.MM2), reg(.MM2), "0F 6F d2");
            testOp2(m32, .MOVQ, reg(.MM3), reg(.MM3), "0F 6F db");
            testOp2(m32, .MOVQ, reg(.MM4), reg(.MM4), "0F 6F e4");
            testOp2(m32, .MOVQ, reg(.MM5), reg(.MM5), "0F 6F ed");
            testOp2(m32, .MOVQ, reg(.MM6), reg(.MM6), "0F 6F f6");
            testOp2(m32, .MOVQ, reg(.MM7), reg(.MM7), "0F 6F ff");
            //
            testOp2(m64, .MOVQ, reg(.MM0), reg(.MM0), "0F 6F c0");
            testOp2(m64, .MOVQ, reg(.MM1), reg(.MM1), "0F 6F c9");
            testOp2(m64, .MOVQ, reg(.MM2), reg(.MM2), "0F 6F d2");
            testOp2(m64, .MOVQ, reg(.MM3), reg(.MM3), "0F 6F db");
            testOp2(m64, .MOVQ, reg(.MM4), reg(.MM4), "0F 6F e4");
            testOp2(m64, .MOVQ, reg(.MM5), reg(.MM5), "0F 6F ed");
            testOp2(m64, .MOVQ, reg(.MM6), reg(.MM6), "0F 6F f6");
            testOp2(m64, .MOVQ, reg(.MM7), reg(.MM7), "0F 6F ff");
        }
    }

}
