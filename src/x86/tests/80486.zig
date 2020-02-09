const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "80486" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    const rm8 = Operand.memoryRm(.DefaultSeg, .BYTE, .EAX, 0);
    const rm16 = Operand.memoryRm(.DefaultSeg, .WORD, .EAX, 0);
    const rm32 = Operand.memoryRm(.DefaultSeg, .DWORD, .EAX, 0);
    const rm64 = Operand.memoryRm(.DefaultSeg, .QWORD, .EAX, 0);
    const rm_mem = Operand.memoryRm(.DefaultSeg, .Void, .EAX, 0);
    const reg8 = Operand.register(.AL);
    const reg16 = Operand.register(.AX);
    const reg32 = Operand.register(.EAX);
    const reg64 = Operand.register(.RAX);
    const cx = Operand.register(.CX);
    const ecx = Operand.register(.ECX);
    const rcx = Operand.register(.RCX);
    const imm8 = Operand.immediate(0xff);

    debugPrint(false);

    {
        testOp1(m32, .BSWAP, reg16, "66 0F C8");
        testOp1(m32, .BSWAP, reg32, "0F C8");
        testOp1(m32, .BSWAP, reg64, AsmError.InvalidOperand);
        testOp1(m32, .BSWAP, cx,    "66 0F C9");
        testOp1(m32, .BSWAP, ecx,   "0F C9");
        testOp1(m32, .BSWAP, rcx,   AsmError.InvalidOperand);
        //
        testOp1(m64, .BSWAP, reg16, "66 0F C8");
        testOp1(m64, .BSWAP, reg32, "0F C8");
        testOp1(m64, .BSWAP, reg64, "48 0F C8");
        testOp1(m64, .BSWAP, cx,    "66 0F C9");
        testOp1(m64, .BSWAP, ecx,   "0F C9");
        testOp1(m64, .BSWAP, rcx,   "48 0F C9");
    }

    {
        testOp2(m32, .CMPXCHG, rm8,  reg8,  "0F B0 00");
        testOp2(m32, .CMPXCHG, rm16, reg16, "66 0F B1 00");
        testOp2(m32, .CMPXCHG, rm32, reg32, "0F B1 00");
        testOp2(m32, .CMPXCHG, rm64, reg64, AsmError.InvalidOperand);
        //
        testOp2(m64, .CMPXCHG, rm8,  reg8,  "67 0F B0 00");
        testOp2(m64, .CMPXCHG, rm16, reg16, "66 67 0F B1 00");
        testOp2(m64, .CMPXCHG, rm32, reg32, "67 0F B1 00");
        testOp2(m64, .CMPXCHG, rm64, reg64, "67 48 0F B1 00");
    }

    {
        testOp0(m32, .INVD, "0F 08");
        testOp0(m64, .INVD, "0F 08");
        //
        testOp0(m32, .WBINVD, "0F 09");
        testOp0(m64, .WBINVD, "0F 09");
        //
        testOp1(m32, .INVLPG, rm_mem, "0F 01 38");
        testOp1(m64, .INVLPG, rm_mem, "67 0F 01 38");
    }

    {
        testOp2(m32, .XADD, rm8,  reg8,  "0F C0 00");
        testOp2(m32, .XADD, rm16, reg16, "66 0F C1 00");
        testOp2(m32, .XADD, rm32, reg32, "0F C1 00");
        testOp2(m32, .XADD, rm64, reg64, AsmError.InvalidOperand);
        //
        testOp2(m64, .XADD, rm8,  reg8,  "67 0F C0 00");
        testOp2(m64, .XADD, rm16, reg16, "66 67 0F C1 00");
        testOp2(m64, .XADD, rm32, reg32, "67 0F C1 00");
        testOp2(m64, .XADD, rm64, reg64, "67 48 0F C1 00");
    }

}
