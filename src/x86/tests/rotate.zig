const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "rotate" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        {
            const op1 = Operand.registerRm(.AL);
            const op2 = Operand.register(.CL);
            testOp2(m32, .RCL, op1, op2, "D2 D0");
            testOp2(m32, .RCR, op1, op2, "D2 D8");
            testOp2(m32, .ROL, op1, op2, "D2 C0");
            testOp2(m32, .ROR, op1, op2, "D2 C8");
            testOp2(m64, .RCL, op1, op2, "D2 D0");
            testOp2(m64, .RCR, op1, op2, "D2 D8");
            testOp2(m64, .ROL, op1, op2, "D2 C0");
            testOp2(m64, .ROR, op1, op2, "D2 C8");
        }

        {
            const op1 = Operand.register(.AX);
            const op2 = Operand.register(.CL);
            testOp2(m32, .RCL, op1, op2, "66 D3 D0");
            testOp2(m32, .RCR, op1, op2, "66 D3 D8");
            testOp2(m32, .ROL, op1, op2, "66 D3 C0");
            testOp2(m32, .ROR, op1, op2, "66 D3 C8");
            testOp2(m64, .RCL, op1, op2, "66 D3 D0");
            testOp2(m64, .RCR, op1, op2, "66 D3 D8");
            testOp2(m64, .ROL, op1, op2, "66 D3 C0");
            testOp2(m64, .ROR, op1, op2, "66 D3 C8");
        }

        {
            const op1 = Operand.register(.EAX);
            const op2 = Operand.register(.CL);
            testOp2(m32, .RCL, op1, op2, "D3 D0");
            testOp2(m32, .RCR, op1, op2, "D3 D8");
            testOp2(m32, .ROL, op1, op2, "D3 C0");
            testOp2(m32, .ROR, op1, op2, "D3 C8");
            testOp2(m64, .RCL, op1, op2, "D3 D0");
            testOp2(m64, .RCR, op1, op2, "D3 D8");
            testOp2(m64, .ROL, op1, op2, "D3 C0");
            testOp2(m64, .ROR, op1, op2, "D3 C8");
        }

        {
            const op1 = Operand.register(.RAX);
            const op2 = Operand.register(.CL);
            testOp2(m32, .RCL, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .RCR, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .ROL, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .ROR, op1, op2, AsmError.InvalidOperand);
            testOp2(m64, .RCL, op1, op2, "48 D3 D0");
            testOp2(m64, .RCR, op1, op2, "48 D3 D8");
            testOp2(m64, .ROL, op1, op2, "48 D3 C0");
            testOp2(m64, .ROR, op1, op2, "48 D3 C8");
        }
    }

    {
        {
            const op1 = Operand.registerRm(.AL);
            const op2 = Operand.immediate(1);
            testOp2(m32, .RCL, op1, op2, "D0 D0");
            testOp2(m32, .RCR, op1, op2, "D0 D8");
            testOp2(m32, .ROL, op1, op2, "D0 C0");
            testOp2(m32, .ROR, op1, op2, "D0 C8");
            testOp2(m64, .RCL, op1, op2, "D0 D0");
            testOp2(m64, .RCR, op1, op2, "D0 D8");
            testOp2(m64, .ROL, op1, op2, "D0 C0");
            testOp2(m64, .ROR, op1, op2, "D0 C8");
        }

        {
            const op1 = Operand.register(.AX);
            const op2 = Operand.immediate(1);
            testOp2(m32, .RCL, op1, op2, "66 D1 D0");
            testOp2(m32, .RCR, op1, op2, "66 D1 D8");
            testOp2(m32, .ROL, op1, op2, "66 D1 C0");
            testOp2(m32, .ROR, op1, op2, "66 D1 C8");
            testOp2(m64, .RCL, op1, op2, "66 D1 D0");
            testOp2(m64, .RCR, op1, op2, "66 D1 D8");
            testOp2(m64, .ROL, op1, op2, "66 D1 C0");
            testOp2(m64, .ROR, op1, op2, "66 D1 C8");
        }

        {
            const op1 = Operand.register(.EAX);
            const op2 = Operand.immediate(1);
            testOp2(m32, .RCL, op1, op2, "D1 D0");
            testOp2(m32, .RCR, op1, op2, "D1 D8");
            testOp2(m32, .ROL, op1, op2, "D1 C0");
            testOp2(m32, .ROR, op1, op2, "D1 C8");
            testOp2(m64, .RCL, op1, op2, "D1 D0");
            testOp2(m64, .RCR, op1, op2, "D1 D8");
            testOp2(m64, .ROL, op1, op2, "D1 C0");
            testOp2(m64, .ROR, op1, op2, "D1 C8");
        }

        {
            const op1 = Operand.register(.RAX);
            const op2 = Operand.immediate(1);
            testOp2(m32, .RCL, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .RCR, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .ROL, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .ROR, op1, op2, AsmError.InvalidOperand);
            testOp2(m64, .RCL, op1, op2, "48 D1 D0");
            testOp2(m64, .RCR, op1, op2, "48 D1 D8");
            testOp2(m64, .ROL, op1, op2, "48 D1 C0");
            testOp2(m64, .ROR, op1, op2, "48 D1 C8");
        }
    }

    {
        {
            const op1 = Operand.registerRm(.AL);
            const op2 = Operand.immediate(4);
            testOp2(m32, .RCL, op1, op2, "C0 D0 04");
            testOp2(m32, .RCR, op1, op2, "C0 D8 04");
            testOp2(m32, .ROL, op1, op2, "C0 C0 04");
            testOp2(m32, .ROR, op1, op2, "C0 C8 04");
            testOp2(m64, .RCL, op1, op2, "C0 D0 04");
            testOp2(m64, .RCR, op1, op2, "C0 D8 04");
            testOp2(m64, .ROL, op1, op2, "C0 C0 04");
            testOp2(m64, .ROR, op1, op2, "C0 C8 04");
        }

        {
            const op1 = Operand.register(.AX);
            const op2 = Operand.immediate(4);
            testOp2(m32, .RCL, op1, op2, "66 C1 D0 04");
            testOp2(m32, .RCR, op1, op2, "66 C1 D8 04");
            testOp2(m32, .ROL, op1, op2, "66 C1 C0 04");
            testOp2(m32, .ROR, op1, op2, "66 C1 C8 04");
            testOp2(m64, .RCL, op1, op2, "66 C1 D0 04");
            testOp2(m64, .RCR, op1, op2, "66 C1 D8 04");
            testOp2(m64, .ROL, op1, op2, "66 C1 C0 04");
            testOp2(m64, .ROR, op1, op2, "66 C1 C8 04");
        }

        {
            const op1 = Operand.register(.EAX);
            const op2 = Operand.immediate(4);
            testOp2(m32, .RCL, op1, op2, "C1 D0 04");
            testOp2(m32, .RCR, op1, op2, "C1 D8 04");
            testOp2(m32, .ROL, op1, op2, "C1 C0 04");
            testOp2(m32, .ROR, op1, op2, "C1 C8 04");
            testOp2(m64, .RCL, op1, op2, "C1 D0 04");
            testOp2(m64, .RCR, op1, op2, "C1 D8 04");
            testOp2(m64, .ROL, op1, op2, "C1 C0 04");
            testOp2(m64, .ROR, op1, op2, "C1 C8 04");
        }

        {
            const op1 = Operand.register(.RAX);
            const op2 = Operand.immediate(4);
            testOp2(m32, .RCL, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .RCR, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .ROL, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .ROR, op1, op2, AsmError.InvalidOperand);
            testOp2(m64, .RCL, op1, op2, "48 C1 D0 04");
            testOp2(m64, .RCR, op1, op2, "48 C1 D8 04");
            testOp2(m64, .ROL, op1, op2, "48 C1 C0 04");
            testOp2(m64, .ROR, op1, op2, "48 C1 C8 04");
        }
    }

}

test "shift" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        {
            const op1 = Operand.registerRm(.AL);
            const op2 = Operand.register(.CL);
            testOp2(m32, .SAL, op1, op2, "D2 E0");
            testOp2(m32, .SAR, op1, op2, "D2 F8");
            testOp2(m32, .SHL, op1, op2, "D2 E0");
            testOp2(m32, .SHR, op1, op2, "D2 E8");
            testOp2(m64, .SAL, op1, op2, "D2 E0");
            testOp2(m64, .SAR, op1, op2, "D2 F8");
            testOp2(m64, .SHL, op1, op2, "D2 E0");
            testOp2(m64, .SHR, op1, op2, "D2 E8");
        }

        {
            const op1 = Operand.register(.AX);
            const op2 = Operand.register(.CL);
            testOp2(m32, .SAL, op1, op2, "66 D3 E0");
            testOp2(m32, .SAR, op1, op2, "66 D3 F8");
            testOp2(m32, .SHL, op1, op2, "66 D3 E0");
            testOp2(m32, .SHR, op1, op2, "66 D3 E8");
            testOp2(m64, .SAL, op1, op2, "66 D3 E0");
            testOp2(m64, .SAR, op1, op2, "66 D3 F8");
            testOp2(m64, .SHL, op1, op2, "66 D3 E0");
            testOp2(m64, .SHR, op1, op2, "66 D3 E8");
        }

        {
            const op1 = Operand.register(.EAX);
            const op2 = Operand.register(.CL);
            testOp2(m32, .SAL, op1, op2, "D3 E0");
            testOp2(m32, .SAR, op1, op2, "D3 F8");
            testOp2(m32, .SHL, op1, op2, "D3 E0");
            testOp2(m32, .SHR, op1, op2, "D3 E8");
            testOp2(m64, .SAL, op1, op2, "D3 E0");
            testOp2(m64, .SAR, op1, op2, "D3 F8");
            testOp2(m64, .SHL, op1, op2, "D3 E0");
            testOp2(m64, .SHR, op1, op2, "D3 E8");
        }

        {
            const op1 = Operand.register(.RAX);
            const op2 = Operand.register(.CL);
            testOp2(m32, .SAL, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .SAR, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .SHL, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .SHR, op1, op2, AsmError.InvalidOperand);
            testOp2(m64, .SAL, op1, op2, "48 D3 E0");
            testOp2(m64, .SAR, op1, op2, "48 D3 F8");
            testOp2(m64, .SHL, op1, op2, "48 D3 E0");
            testOp2(m64, .SHR, op1, op2, "48 D3 E8");
        }
    }

    {
        {
            const op1 = Operand.registerRm(.AL);
            const op2 = Operand.immediate(1);
            testOp2(m32, .SAL, op1, op2, "D0 E0");
            testOp2(m32, .SAR, op1, op2, "D0 F8");
            testOp2(m32, .SHL, op1, op2, "D0 E0");
            testOp2(m32, .SHR, op1, op2, "D0 E8");
            testOp2(m64, .SAL, op1, op2, "D0 E0");
            testOp2(m64, .SAR, op1, op2, "D0 F8");
            testOp2(m64, .SHL, op1, op2, "D0 E0");
            testOp2(m64, .SHR, op1, op2, "D0 E8");
        }

        {
            const op1 = Operand.register(.AX);
            const op2 = Operand.immediate(1);
            testOp2(m32, .SAL, op1, op2, "66 D1 E0");
            testOp2(m32, .SAR, op1, op2, "66 D1 F8");
            testOp2(m32, .SHL, op1, op2, "66 D1 E0");
            testOp2(m32, .SHR, op1, op2, "66 D1 E8");
            testOp2(m64, .SAL, op1, op2, "66 D1 E0");
            testOp2(m64, .SAR, op1, op2, "66 D1 F8");
            testOp2(m64, .SHL, op1, op2, "66 D1 E0");
            testOp2(m64, .SHR, op1, op2, "66 D1 E8");
        }

        {
            const op1 = Operand.register(.EAX);
            const op2 = Operand.immediate(1);
            testOp2(m32, .SAL, op1, op2, "D1 E0");
            testOp2(m32, .SAR, op1, op2, "D1 F8");
            testOp2(m32, .SHL, op1, op2, "D1 E0");
            testOp2(m32, .SHR, op1, op2, "D1 E8");
            testOp2(m64, .SAL, op1, op2, "D1 E0");
            testOp2(m64, .SAR, op1, op2, "D1 F8");
            testOp2(m64, .SHL, op1, op2, "D1 E0");
            testOp2(m64, .SHR, op1, op2, "D1 E8");
        }

        {
            const op1 = Operand.register(.RAX);
            const op2 = Operand.immediate(1);
            testOp2(m32, .SAL, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .SAR, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .SHL, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .SHR, op1, op2, AsmError.InvalidOperand);
            testOp2(m64, .SAL, op1, op2, "48 D1 E0");
            testOp2(m64, .SAR, op1, op2, "48 D1 F8");
            testOp2(m64, .SHL, op1, op2, "48 D1 E0");
            testOp2(m64, .SHR, op1, op2, "48 D1 E8");
        }
    }

    {
        {
            const op1 = Operand.registerRm(.AL);
            const op2 = Operand.immediate(4);
            testOp2(m32, .SAL, op1, op2, "C0 E0 04");
            testOp2(m32, .SAR, op1, op2, "C0 F8 04");
            testOp2(m32, .SHL, op1, op2, "C0 E0 04");
            testOp2(m32, .SHR, op1, op2, "C0 E8 04");
            testOp2(m64, .SAL, op1, op2, "C0 E0 04");
            testOp2(m64, .SAR, op1, op2, "C0 F8 04");
            testOp2(m64, .SHL, op1, op2, "C0 E0 04");
            testOp2(m64, .SHR, op1, op2, "C0 E8 04");
        }

        {
            const op1 = Operand.register(.AX);
            const op2 = Operand.immediate(4);
            testOp2(m32, .SAL, op1, op2, "66 C1 E0 04");
            testOp2(m32, .SAR, op1, op2, "66 C1 F8 04");
            testOp2(m32, .SHL, op1, op2, "66 C1 E0 04");
            testOp2(m32, .SHR, op1, op2, "66 C1 E8 04");
            testOp2(m64, .SAL, op1, op2, "66 C1 E0 04");
            testOp2(m64, .SAR, op1, op2, "66 C1 F8 04");
            testOp2(m64, .SHL, op1, op2, "66 C1 E0 04");
            testOp2(m64, .SHR, op1, op2, "66 C1 E8 04");
        }

        {
            const op1 = Operand.register(.EAX);
            const op2 = Operand.immediate(4);
            testOp2(m32, .SAL, op1, op2, "C1 E0 04");
            testOp2(m32, .SAR, op1, op2, "C1 F8 04");
            testOp2(m32, .SHL, op1, op2, "C1 E0 04");
            testOp2(m32, .SHR, op1, op2, "C1 E8 04");
            testOp2(m64, .SAL, op1, op2, "C1 E0 04");
            testOp2(m64, .SAR, op1, op2, "C1 F8 04");
            testOp2(m64, .SHL, op1, op2, "C1 E0 04");
            testOp2(m64, .SHR, op1, op2, "C1 E8 04");
        }

        {
            const op1 = Operand.register(.RAX);
            const op2 = Operand.immediate(4);
            testOp2(m32, .SAL, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .SAR, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .SHL, op1, op2, AsmError.InvalidOperand);
            testOp2(m32, .SHR, op1, op2, AsmError.InvalidOperand);
            testOp2(m64, .SAL, op1, op2, "48 C1 E0 04");
            testOp2(m64, .SAR, op1, op2, "48 C1 F8 04");
            testOp2(m64, .SHL, op1, op2, "48 C1 E0 04");
            testOp2(m64, .SHR, op1, op2, "48 C1 E8 04");
        }
    }
}
