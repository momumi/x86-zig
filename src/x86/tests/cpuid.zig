const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

const imm = Operand.immediate;
const mem = Operand.memory;
const memRm = Operand.memoryRm;
const reg = Operand.register;

test "cpuid features" {
    debugPrint(false);

    {
        const cpu_features = [_]CpuFeature { ._8086,  };

        const m16 = Machine.init_with_features(.x86_16, cpu_features[0..]);
        const m32 = Machine.init_with_features(.x86_32, cpu_features[0..]);
        const m64 = Machine.init_with_features(.x64, cpu_features[0..]);

        testOp2(m16, .MOV,  reg(.AL), reg(.AL), "8a c0");
        testOp2(m16, .MOV,  reg(.AX), reg(.AX), "8b c0");
        testOp2(m16, .MOV,  reg(.EAX), reg(.EAX), AsmError.InvalidOperand);
        testOp2(m16, .MOV,  reg(.RAX), reg(.RAX), AsmError.InvalidOperand);

        testOp2(m32, .MOV,  reg(.AL), reg(.AL), "8a c0");
        testOp2(m32, .MOV,  reg(.AX), reg(.AX), "66 8b c0");
        testOp2(m32, .MOV,  reg(.EAX), reg(.EAX), AsmError.InvalidOperand);
        testOp2(m32, .MOV,  reg(.RAX), reg(.RAX), AsmError.InvalidOperand);

        testOp2(m64, .MOV,  reg(.AL), reg(.AL), "8a c0");
        testOp2(m64, .MOV,  reg(.AX), reg(.AX), "66 8b c0");
        testOp2(m64, .MOV,  reg(.EAX), reg(.EAX), AsmError.InvalidOperand);
        testOp2(m64, .MOV,  reg(.RAX), reg(.RAX), AsmError.InvalidOperand);

        testOp2(m64, .FCMOVB, reg(.ST0), reg(.ST7), AsmError.InvalidOperand);

        testOp0(m64, .EMMS, AsmError.InvalidOperand);
        testOp0(m64, .VZEROALL, AsmError.InvalidOperand);
        testOp0(m64, .SFENCE, AsmError.InvalidOperand);
    }

    {
        const cpu_features = [_]CpuFeature { ._8086, ._386, .x86_64, .CMOV, .FPU };

        const m16 = Machine.init_with_features(.x86_16, cpu_features[0..]);
        const m32 = Machine.init_with_features(.x86_32, cpu_features[0..]);
        const m64 = Machine.init_with_features(.x64, cpu_features[0..]);

        testOp2(m64, .MOV,  reg(.AL), reg(.AL), "8a c0");
        testOp2(m64, .MOV,  reg(.AX), reg(.AX), "66 8b c0");
        testOp2(m64, .MOV,  reg(.EAX), reg(.EAX), "8b c0");
        testOp2(m64, .MOV,  reg(.RAX), reg(.RAX), "48 8b c0");

        testOp2(m64, .MOV,  reg(.RAX), reg(.RAX), "48 8b c0");

        testOp2(m64, .FCMOVB, reg(.ST0), reg(.ST7), "da c7");

        testOp0(m64, .EMMS, AsmError.InvalidOperand);
        testOp0(m64, .VZEROALL, AsmError.InvalidOperand);
        testOp0(m64, .SFENCE, AsmError.InvalidOperand);
    }

    {
        const cpu_features = [_]CpuFeature { .Intel, ._8086, .SYSCALL, .LAHF_SAHF };
        const m32 = Machine.init_with_features(.x86_32, cpu_features[0..]);
        const m64 = Machine.init_with_features(.x64, cpu_features[0..]);

        testOp0(m32, .SYSCALL, AsmError.InvalidOperand);
        testOp0(m32, .SYSCALL, AsmError.InvalidOperand);
        testOp0(m32, .SYSRET, AsmError.InvalidOperand);
        testOp0(m32, .SYSRET, AsmError.InvalidOperand);

        testOp0(m64, .SYSCALL, "0F 05");
        testOp0(m64, .SYSCALL, "0F 05");
        testOp0(m64, .SYSRET, "0F 07");
        testOp0(m64, .SYSRET, "0F 07");

        testOp2(m32, .FCMOVB, reg(.ST0), reg(.ST7), AsmError.InvalidOperand);
        testOp2(m64, .FCMOVB, reg(.ST0), reg(.ST7), AsmError.InvalidOperand);

        testOp0(m32, .LAHF, "9F");
        testOp0(m32, .SAHF, "9E");

        testOp0(m64, .LAHF, "9F");
        testOp0(m64, .SAHF, "9E");
    }

    {
        const cpu_features = [_]CpuFeature { .Amd, ._8086, .SYSCALL };
        const m32 = Machine.init_with_features(.x86_32, cpu_features[0..]);
        const m64 = Machine.init_with_features(.x64, cpu_features[0..]);

        testOp0(m32, .SYSCALL, "0F 05");
        testOp0(m32, .SYSCALL, "0F 05");
        testOp0(m32, .SYSRET, "0F 07");
        testOp0(m32, .SYSRET, "0F 07");

        testOp0(m64, .SYSCALL, "0F 05");
        testOp0(m64, .SYSCALL, "0F 05");
        testOp0(m64, .SYSRET, "0F 07");
        testOp0(m64, .SYSRET, "0F 07");

        testOp2(m32, .FCMOVB, reg(.ST0), reg(.ST7), AsmError.InvalidOperand);
        testOp2(m64, .FCMOVB, reg(.ST0), reg(.ST7), AsmError.InvalidOperand);

        testOp0(m32, .LAHF, "9F");
        testOp0(m32, .SAHF, "9E");

        testOp0(m64, .LAHF, AsmError.InvalidOperand);
        testOp0(m64, .SAHF, AsmError.InvalidOperand);
    }
}
