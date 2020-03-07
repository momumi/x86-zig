const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

const reg = Operand.register;
const regRm = Operand.registerRm;

const imm = Operand.immediate;

test "rotate and shift" {
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        {
            testOp2(m32, .RCL, regRm(.AL), reg(.CL), "D2 D0");
            testOp2(m32, .RCR, regRm(.AL), reg(.CL), "D2 D8");
            testOp2(m32, .ROL, regRm(.AL), reg(.CL), "D2 C0");
            testOp2(m32, .ROR, regRm(.AL), reg(.CL), "D2 C8");
            //
            testOp2(m64, .RCL, regRm(.AL), reg(.CL), "D2 D0");
            testOp2(m64, .RCR, regRm(.AL), reg(.CL), "D2 D8");
            testOp2(m64, .ROL, regRm(.AL), reg(.CL), "D2 C0");
            testOp2(m64, .ROR, regRm(.AL), reg(.CL), "D2 C8");
        }

        {
            testOp2(m32, .RCL, reg(.AX), reg(.CL), "66 D3 D0");
            testOp2(m32, .RCR, reg(.AX), reg(.CL), "66 D3 D8");
            testOp2(m32, .ROL, reg(.AX), reg(.CL), "66 D3 C0");
            testOp2(m32, .ROR, reg(.AX), reg(.CL), "66 D3 C8");
            //
            testOp2(m64, .RCL, reg(.AX), reg(.CL), "66 D3 D0");
            testOp2(m64, .RCR, reg(.AX), reg(.CL), "66 D3 D8");
            testOp2(m64, .ROL, reg(.AX), reg(.CL), "66 D3 C0");
            testOp2(m64, .ROR, reg(.AX), reg(.CL), "66 D3 C8");
        }

        {
            testOp2(m32, .RCL, reg(.EAX), reg(.CL), "D3 D0");
            testOp2(m32, .RCR, reg(.EAX), reg(.CL), "D3 D8");
            testOp2(m32, .ROL, reg(.EAX), reg(.CL), "D3 C0");
            testOp2(m32, .ROR, reg(.EAX), reg(.CL), "D3 C8");
            //
            testOp2(m64, .RCL, reg(.EAX), reg(.CL), "D3 D0");
            testOp2(m64, .RCR, reg(.EAX), reg(.CL), "D3 D8");
            testOp2(m64, .ROL, reg(.EAX), reg(.CL), "D3 C0");
            testOp2(m64, .ROR, reg(.EAX), reg(.CL), "D3 C8");
        }

        {
            testOp2(m32, .RCL, reg(.RAX), reg(.CL), AsmError.InvalidOperand);
            testOp2(m32, .RCR, reg(.RAX), reg(.CL), AsmError.InvalidOperand);
            testOp2(m32, .ROL, reg(.RAX), reg(.CL), AsmError.InvalidOperand);
            testOp2(m32, .ROR, reg(.RAX), reg(.CL), AsmError.InvalidOperand);
            //
            testOp2(m64, .RCL, reg(.RAX), reg(.CL), "48 D3 D0");
            testOp2(m64, .RCR, reg(.RAX), reg(.CL), "48 D3 D8");
            testOp2(m64, .ROL, reg(.RAX), reg(.CL), "48 D3 C0");
            testOp2(m64, .ROR, reg(.RAX), reg(.CL), "48 D3 C8");
        }
    }

    {
        {
            testOp2(m32, .RCL, regRm(.AL), imm(1), "D0 D0");
            testOp2(m32, .RCR, regRm(.AL), imm(1), "D0 D8");
            testOp2(m32, .ROL, regRm(.AL), imm(1), "D0 C0");
            testOp2(m32, .ROR, regRm(.AL), imm(1), "D0 C8");
            //
            testOp2(m64, .RCL, regRm(.AL), imm(1), "D0 D0");
            testOp2(m64, .RCR, regRm(.AL), imm(1), "D0 D8");
            testOp2(m64, .ROL, regRm(.AL), imm(1), "D0 C0");
            testOp2(m64, .ROR, regRm(.AL), imm(1), "D0 C8");
        }

        {
            testOp2(m32, .RCL, reg(.AX), imm(1), "66 D1 D0");
            testOp2(m32, .RCR, reg(.AX), imm(1), "66 D1 D8");
            testOp2(m32, .ROL, reg(.AX), imm(1), "66 D1 C0");
            testOp2(m32, .ROR, reg(.AX), imm(1), "66 D1 C8");
            //
            testOp2(m64, .RCL, reg(.AX), imm(1), "66 D1 D0");
            testOp2(m64, .RCR, reg(.AX), imm(1), "66 D1 D8");
            testOp2(m64, .ROL, reg(.AX), imm(1), "66 D1 C0");
            testOp2(m64, .ROR, reg(.AX), imm(1), "66 D1 C8");
        }

        {
            testOp2(m32, .RCL, reg(.EAX), imm(1), "D1 D0");
            testOp2(m32, .RCR, reg(.EAX), imm(1), "D1 D8");
            testOp2(m32, .ROL, reg(.EAX), imm(1), "D1 C0");
            testOp2(m32, .ROR, reg(.EAX), imm(1), "D1 C8");
            //
            testOp2(m64, .RCL, reg(.EAX), imm(1), "D1 D0");
            testOp2(m64, .RCR, reg(.EAX), imm(1), "D1 D8");
            testOp2(m64, .ROL, reg(.EAX), imm(1), "D1 C0");
            testOp2(m64, .ROR, reg(.EAX), imm(1), "D1 C8");
        }

        {
            testOp2(m32, .RCL, reg(.RAX), imm(1), AsmError.InvalidOperand);
            testOp2(m32, .RCR, reg(.RAX), imm(1), AsmError.InvalidOperand);
            testOp2(m32, .ROL, reg(.RAX), imm(1), AsmError.InvalidOperand);
            testOp2(m32, .ROR, reg(.RAX), imm(1), AsmError.InvalidOperand);
            //
            testOp2(m64, .RCL, reg(.RAX), imm(1), "48 D1 D0");
            testOp2(m64, .RCR, reg(.RAX), imm(1), "48 D1 D8");
            testOp2(m64, .ROL, reg(.RAX), imm(1), "48 D1 C0");
            testOp2(m64, .ROR, reg(.RAX), imm(1), "48 D1 C8");
        }
    }

    {
        {
            testOp2(m32, .RCL, regRm(.AL), imm(4), "C0 D0 04");
            testOp2(m32, .RCR, regRm(.AL), imm(4), "C0 D8 04");
            testOp2(m32, .ROL, regRm(.AL), imm(4), "C0 C0 04");
            testOp2(m32, .ROR, regRm(.AL), imm(4), "C0 C8 04");
            //
            testOp2(m64, .RCL, regRm(.AL), imm(4), "C0 D0 04");
            testOp2(m64, .RCR, regRm(.AL), imm(4), "C0 D8 04");
            testOp2(m64, .ROL, regRm(.AL), imm(4), "C0 C0 04");
            testOp2(m64, .ROR, regRm(.AL), imm(4), "C0 C8 04");
        }

        {
            testOp2(m32, .RCL, reg(.AX), imm(4), "66 C1 D0 04");
            testOp2(m32, .RCR, reg(.AX), imm(4), "66 C1 D8 04");
            testOp2(m32, .ROL, reg(.AX), imm(4), "66 C1 C0 04");
            testOp2(m32, .ROR, reg(.AX), imm(4), "66 C1 C8 04");
            //
            testOp2(m64, .RCL, reg(.AX), imm(4), "66 C1 D0 04");
            testOp2(m64, .RCR, reg(.AX), imm(4), "66 C1 D8 04");
            testOp2(m64, .ROL, reg(.AX), imm(4), "66 C1 C0 04");
            testOp2(m64, .ROR, reg(.AX), imm(4), "66 C1 C8 04");
        }

        {
            testOp2(m32, .RCL, reg(.EAX), imm(4), "C1 D0 04");
            testOp2(m32, .RCR, reg(.EAX), imm(4), "C1 D8 04");
            testOp2(m32, .ROL, reg(.EAX), imm(4), "C1 C0 04");
            testOp2(m32, .ROR, reg(.EAX), imm(4), "C1 C8 04");
            //
            testOp2(m64, .RCL, reg(.EAX), imm(4), "C1 D0 04");
            testOp2(m64, .RCR, reg(.EAX), imm(4), "C1 D8 04");
            testOp2(m64, .ROL, reg(.EAX), imm(4), "C1 C0 04");
            testOp2(m64, .ROR, reg(.EAX), imm(4), "C1 C8 04");
        }

        {
            testOp2(m32, .RCL, reg(.RAX), imm(4), AsmError.InvalidOperand);
            testOp2(m32, .RCR, reg(.RAX), imm(4), AsmError.InvalidOperand);
            testOp2(m32, .ROL, reg(.RAX), imm(4), AsmError.InvalidOperand);
            testOp2(m32, .ROR, reg(.RAX), imm(4), AsmError.InvalidOperand);
            //
            testOp2(m64, .RCL, reg(.RAX), imm(4), "48 C1 D0 04");
            testOp2(m64, .RCR, reg(.RAX), imm(4), "48 C1 D8 04");
            testOp2(m64, .ROL, reg(.RAX), imm(4), "48 C1 C0 04");
            testOp2(m64, .ROR, reg(.RAX), imm(4), "48 C1 C8 04");
        }
    }

    {
        {
            testOp2(m32, .SAL, regRm(.AL), reg(.CL), "D2 E0");
            testOp2(m32, .SAR, regRm(.AL), reg(.CL), "D2 F8");
            testOp2(m32, .SHL, regRm(.AL), reg(.CL), "D2 E0");
            testOp2(m32, .SHR, regRm(.AL), reg(.CL), "D2 E8");
            //
            testOp2(m64, .SAL, regRm(.AL), reg(.CL), "D2 E0");
            testOp2(m64, .SAR, regRm(.AL), reg(.CL), "D2 F8");
            testOp2(m64, .SHL, regRm(.AL), reg(.CL), "D2 E0");
            testOp2(m64, .SHR, regRm(.AL), reg(.CL), "D2 E8");
        }

        {
            testOp2(m32, .SAL, reg(.AX), reg(.CL), "66 D3 E0");
            testOp2(m32, .SAR, reg(.AX), reg(.CL), "66 D3 F8");
            testOp2(m32, .SHL, reg(.AX), reg(.CL), "66 D3 E0");
            testOp2(m32, .SHR, reg(.AX), reg(.CL), "66 D3 E8");
            //
            testOp2(m64, .SAL, reg(.AX), reg(.CL), "66 D3 E0");
            testOp2(m64, .SAR, reg(.AX), reg(.CL), "66 D3 F8");
            testOp2(m64, .SHL, reg(.AX), reg(.CL), "66 D3 E0");
            testOp2(m64, .SHR, reg(.AX), reg(.CL), "66 D3 E8");
        }

        {
            testOp2(m32, .SAL, regRm(.EAX), reg(.CL), "D3 E0");
            testOp2(m32, .SAR, regRm(.EAX), reg(.CL), "D3 F8");
            testOp2(m32, .SHL, regRm(.EAX), reg(.CL), "D3 E0");
            testOp2(m32, .SHR, regRm(.EAX), reg(.CL), "D3 E8");
            //
            testOp2(m64, .SAL, regRm(.EAX), reg(.CL), "D3 E0");
            testOp2(m64, .SAR, regRm(.EAX), reg(.CL), "D3 F8");
            testOp2(m64, .SHL, regRm(.EAX), reg(.CL), "D3 E0");
            testOp2(m64, .SHR, regRm(.EAX), reg(.CL), "D3 E8");
        }

        {
            testOp2(m32, .SAL, regRm(.RAX), reg(.CL), AsmError.InvalidOperand);
            testOp2(m32, .SAR, regRm(.RAX), reg(.CL), AsmError.InvalidOperand);
            testOp2(m32, .SHL, regRm(.RAX), reg(.CL), AsmError.InvalidOperand);
            testOp2(m32, .SHR, regRm(.RAX), reg(.CL), AsmError.InvalidOperand);
            //
            testOp2(m64, .SAL, regRm(.RAX), reg(.CL), "48 D3 E0");
            testOp2(m64, .SAR, regRm(.RAX), reg(.CL), "48 D3 F8");
            testOp2(m64, .SHL, regRm(.RAX), reg(.CL), "48 D3 E0");
            testOp2(m64, .SHR, regRm(.RAX), reg(.CL), "48 D3 E8");
        }
    }

    {
        {
            testOp2(m32, .SAL, regRm(.AL), imm(1), "D0 E0");
            testOp2(m32, .SAR, regRm(.AL), imm(1), "D0 F8");
            testOp2(m32, .SHL, regRm(.AL), imm(1), "D0 E0");
            testOp2(m32, .SHR, regRm(.AL), imm(1), "D0 E8");
            //
            testOp2(m64, .SAL, regRm(.AL), imm(1), "D0 E0");
            testOp2(m64, .SAR, regRm(.AL), imm(1), "D0 F8");
            testOp2(m64, .SHL, regRm(.AL), imm(1), "D0 E0");
            testOp2(m64, .SHR, regRm(.AL), imm(1), "D0 E8");
        }

        {
            testOp2(m32, .SAL, regRm(.AX), imm(1), "66 D1 E0");
            testOp2(m32, .SAR, regRm(.AX), imm(1), "66 D1 F8");
            testOp2(m32, .SHL, regRm(.AX), imm(1), "66 D1 E0");
            testOp2(m32, .SHR, regRm(.AX), imm(1), "66 D1 E8");
            //
            testOp2(m64, .SAL, regRm(.AX), imm(1), "66 D1 E0");
            testOp2(m64, .SAR, regRm(.AX), imm(1), "66 D1 F8");
            testOp2(m64, .SHL, regRm(.AX), imm(1), "66 D1 E0");
            testOp2(m64, .SHR, regRm(.AX), imm(1), "66 D1 E8");
        }

        {
            testOp2(m32, .SAL, regRm(.EAX), imm(1), "D1 E0");
            testOp2(m32, .SAR, regRm(.EAX), imm(1), "D1 F8");
            testOp2(m32, .SHL, regRm(.EAX), imm(1), "D1 E0");
            testOp2(m32, .SHR, regRm(.EAX), imm(1), "D1 E8");
            //
            testOp2(m64, .SAL, regRm(.EAX), imm(1), "D1 E0");
            testOp2(m64, .SAR, regRm(.EAX), imm(1), "D1 F8");
            testOp2(m64, .SHL, regRm(.EAX), imm(1), "D1 E0");
            testOp2(m64, .SHR, regRm(.EAX), imm(1), "D1 E8");
        }

        {
            testOp2(m32, .SAL, regRm(.RAX), imm(1), AsmError.InvalidOperand);
            testOp2(m32, .SAR, regRm(.RAX), imm(1), AsmError.InvalidOperand);
            testOp2(m32, .SHL, regRm(.RAX), imm(1), AsmError.InvalidOperand);
            testOp2(m32, .SHR, regRm(.RAX), imm(1), AsmError.InvalidOperand);
            //
            testOp2(m64, .SAL, regRm(.RAX), imm(1), "48 D1 E0");
            testOp2(m64, .SAR, regRm(.RAX), imm(1), "48 D1 F8");
            testOp2(m64, .SHL, regRm(.RAX), imm(1), "48 D1 E0");
            testOp2(m64, .SHR, regRm(.RAX), imm(1), "48 D1 E8");
        }
    }

    {
        {
            testOp2(m32, .SAL, reg(.AL), imm(4), "C0 E0 04");
            testOp2(m32, .SAR, reg(.AL), imm(4), "C0 F8 04");
            testOp2(m32, .SHL, reg(.AL), imm(4), "C0 E0 04");
            testOp2(m32, .SHR, reg(.AL), imm(4), "C0 E8 04");
            //
            testOp2(m64, .SAL, reg(.AL), imm(4), "C0 E0 04");
            testOp2(m64, .SAR, reg(.AL), imm(4), "C0 F8 04");
            testOp2(m64, .SHL, reg(.AL), imm(4), "C0 E0 04");
            testOp2(m64, .SHR, reg(.AL), imm(4), "C0 E8 04");
        }

        {
            testOp2(m32, .SAL, reg(.AX), imm(4), "66 C1 E0 04");
            testOp2(m32, .SAR, reg(.AX), imm(4), "66 C1 F8 04");
            testOp2(m32, .SHL, reg(.AX), imm(4), "66 C1 E0 04");
            testOp2(m32, .SHR, reg(.AX), imm(4), "66 C1 E8 04");
            //
            testOp2(m64, .SAL, reg(.AX), imm(4), "66 C1 E0 04");
            testOp2(m64, .SAR, reg(.AX), imm(4), "66 C1 F8 04");
            testOp2(m64, .SHL, reg(.AX), imm(4), "66 C1 E0 04");
            testOp2(m64, .SHR, reg(.AX), imm(4), "66 C1 E8 04");
        }

        {
            testOp2(m32, .SAL, reg(.EAX), imm(4), "C1 E0 04");
            testOp2(m32, .SAR, reg(.EAX), imm(4), "C1 F8 04");
            testOp2(m32, .SHL, reg(.EAX), imm(4), "C1 E0 04");
            testOp2(m32, .SHR, reg(.EAX), imm(4), "C1 E8 04");
            //
            testOp2(m64, .SAL, reg(.EAX), imm(4), "C1 E0 04");
            testOp2(m64, .SAR, reg(.EAX), imm(4), "C1 F8 04");
            testOp2(m64, .SHL, reg(.EAX), imm(4), "C1 E0 04");
            testOp2(m64, .SHR, reg(.EAX), imm(4), "C1 E8 04");
        }

        {
            testOp2(m32, .SAL, reg(.RAX), imm(4), AsmError.InvalidOperand);
            testOp2(m32, .SAR, reg(.RAX), imm(4), AsmError.InvalidOperand);
            testOp2(m32, .SHL, reg(.RAX), imm(4), AsmError.InvalidOperand);
            testOp2(m32, .SHR, reg(.RAX), imm(4), AsmError.InvalidOperand);
            //
            testOp2(m64, .SAL, reg(.RAX), imm(4), "48 C1 E0 04");
            testOp2(m64, .SAR, reg(.RAX), imm(4), "48 C1 F8 04");
            testOp2(m64, .SHL, reg(.RAX), imm(4), "48 C1 E0 04");
            testOp2(m64, .SHR, reg(.RAX), imm(4), "48 C1 E8 04");
        }
    }
}
