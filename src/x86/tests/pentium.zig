const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "pentium" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    const rm_mem64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const rm_mem128 = Operand.memoryRm(.DefaultSeg, .OWORD, .EAX, 0);

    debugPrint(false);

    {
        testOp0(m64, .CPUID,    "0F A2");
    }

    {
        testOp1(m32, .CMPXCHG8B,  rm_mem64,  "0F C7 08");
        testOp1(m32, .CMPXCHG16B, rm_mem128, AsmError.InvalidMode);
        testOp1(m64, .CMPXCHG8B,  rm_mem64,  "67 0F C7 08");
        testOp1(m64, .CMPXCHG16B, rm_mem128, "67 48 0F C7 08");
    }

    {
        testOp0(m32, .RDMSR, "0F 32");
        testOp0(m64, .RDMSR, "0F 32");
        //
        testOp0(m32, .RDTSC, "0F 31");
        testOp0(m64, .RDTSC, "0F 31");
        //
        testOp0(m32, .WRMSR, "0F 30");
        testOp0(m64, .WRMSR, "0F 30");
        //
        testOp0(m32, .RSM, "0F AA");
        testOp0(m64, .RSM, "0F AA");
    }

}
