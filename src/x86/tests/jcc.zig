const std = @import("std");
usingnamespace (@import("../machine.zig"));
usingnamespace (@import("../util.zig"));

test "jcc" {
    const m32 = Machine.init(.x86);
    const m64 = Machine.init(.x64);

    debugPrint(false);

    {
        const op1 = Operand.immediate(0x11);
        testOp1(m32, .JCXZ,   op1, "67 E3 11");
        testOp1(m32, .JECXZ,  op1, "E3 11");
        testOp1(m32, .JRCXZ,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JCXZ,   op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JECXZ,  op1, "67 E3 11");
        testOp1(m64, .JRCXZ,  op1, "E3 11");
    }

    {
        const op1 = Operand.immediate(0x11);
        testOp1(m32, .JA,   op1, "77 11");
        testOp1(m32, .JAE,  op1, "73 11");
        testOp1(m32, .JB,   op1, "72 11");
        testOp1(m32, .JBE,  op1, "76 11");
        testOp1(m32, .JC,   op1, "72 11");
        testOp1(m32, .JE,   op1, "74 11");
        testOp1(m32, .JG,   op1, "7F 11");
        testOp1(m32, .JGE,  op1, "7D 11");
        testOp1(m32, .JL,   op1, "7C 11");
        testOp1(m32, .JLE,  op1, "7E 11");
        testOp1(m32, .JNA,  op1, "76 11");
        testOp1(m32, .JNAE, op1, "72 11");
        testOp1(m32, .JNB,  op1, "73 11");
        testOp1(m32, .JNBE, op1, "77 11");
        testOp1(m32, .JNC,  op1, "73 11");
        testOp1(m32, .JNE,  op1, "75 11");
        testOp1(m32, .JNG,  op1, "7E 11");
        testOp1(m32, .JNGE, op1, "7C 11");
        testOp1(m32, .JNL,  op1, "7D 11");
        testOp1(m32, .JNLE, op1, "7F 11");
        testOp1(m32, .JNO,  op1, "71 11");
        testOp1(m32, .JNP,  op1, "7B 11");
        testOp1(m32, .JNS,  op1, "79 11");
        testOp1(m32, .JNZ,  op1, "75 11");
        testOp1(m32, .JO,   op1, "70 11");
        testOp1(m32, .JP,   op1, "7A 11");
        testOp1(m32, .JPE,  op1, "7A 11");
        testOp1(m32, .JPO,  op1, "7B 11");
        testOp1(m32, .JS,   op1, "78 11");
        testOp1(m32, .JZ,   op1, "74 11");

        testOp1(m64, .JA,   op1, "77 11");
        testOp1(m64, .JAE,  op1, "73 11");
        testOp1(m64, .JB,   op1, "72 11");
        testOp1(m64, .JBE,  op1, "76 11");
        testOp1(m64, .JC,   op1, "72 11");
        testOp1(m64, .JE,   op1, "74 11");
        testOp1(m64, .JG,   op1, "7F 11");
        testOp1(m64, .JGE,  op1, "7D 11");
        testOp1(m64, .JL,   op1, "7C 11");
        testOp1(m64, .JLE,  op1, "7E 11");
        testOp1(m64, .JNA,  op1, "76 11");
        testOp1(m64, .JNAE, op1, "72 11");
        testOp1(m64, .JNB,  op1, "73 11");
        testOp1(m64, .JNBE, op1, "77 11");
        testOp1(m64, .JNC,  op1, "73 11");
        testOp1(m64, .JNE,  op1, "75 11");
        testOp1(m64, .JNG,  op1, "7E 11");
        testOp1(m64, .JNGE, op1, "7C 11");
        testOp1(m64, .JNL,  op1, "7D 11");
        testOp1(m64, .JNLE, op1, "7F 11");
        testOp1(m64, .JNO,  op1, "71 11");
        testOp1(m64, .JNP,  op1, "7B 11");
        testOp1(m64, .JNS,  op1, "79 11");
        testOp1(m64, .JNZ,  op1, "75 11");
        testOp1(m64, .JO,   op1, "70 11");
        testOp1(m64, .JP,   op1, "7A 11");
        testOp1(m64, .JPE,  op1, "7A 11");
        testOp1(m64, .JPO,  op1, "7B 11");
        testOp1(m64, .JS,   op1, "78 11");
        testOp1(m64, .JZ,   op1, "74 11");
    }

    {
        const op1 = Operand.immediateSigned(-1);
        testOp1(m32, .JA,   op1, "77 ff");
        testOp1(m32, .JAE,  op1, "73 ff");
        testOp1(m32, .JB,   op1, "72 ff");
        testOp1(m32, .JBE,  op1, "76 ff");
        testOp1(m32, .JC,   op1, "72 ff");
        testOp1(m32, .JE,   op1, "74 ff");
        testOp1(m32, .JG,   op1, "7F ff");
        testOp1(m32, .JGE,  op1, "7D ff");
        testOp1(m32, .JL,   op1, "7C ff");
        testOp1(m32, .JLE,  op1, "7E ff");
        testOp1(m32, .JNA,  op1, "76 ff");
        testOp1(m32, .JNAE, op1, "72 ff");
        testOp1(m32, .JNB,  op1, "73 ff");
        testOp1(m32, .JNBE, op1, "77 ff");
        testOp1(m32, .JNC,  op1, "73 ff");
        testOp1(m32, .JNE,  op1, "75 ff");
        testOp1(m32, .JNG,  op1, "7E ff");
        testOp1(m32, .JNGE, op1, "7C ff");
        testOp1(m32, .JNL,  op1, "7D ff");
        testOp1(m32, .JNLE, op1, "7F ff");
        testOp1(m32, .JNO,  op1, "71 ff");
        testOp1(m32, .JNP,  op1, "7B ff");
        testOp1(m32, .JNS,  op1, "79 ff");
        testOp1(m32, .JNZ,  op1, "75 ff");
        testOp1(m32, .JO,   op1, "70 ff");
        testOp1(m32, .JP,   op1, "7A ff");
        testOp1(m32, .JPE,  op1, "7A ff");
        testOp1(m32, .JPO,  op1, "7B ff");
        testOp1(m32, .JS,   op1, "78 ff");
        testOp1(m32, .JZ,   op1, "74 ff");

        testOp1(m64, .JA,   op1, "77 ff");
        testOp1(m64, .JAE,  op1, "73 ff");
        testOp1(m64, .JB,   op1, "72 ff");
        testOp1(m64, .JBE,  op1, "76 ff");
        testOp1(m64, .JC,   op1, "72 ff");
        testOp1(m64, .JE,   op1, "74 ff");
        testOp1(m64, .JG,   op1, "7F ff");
        testOp1(m64, .JGE,  op1, "7D ff");
        testOp1(m64, .JL,   op1, "7C ff");
        testOp1(m64, .JLE,  op1, "7E ff");
        testOp1(m64, .JNA,  op1, "76 ff");
        testOp1(m64, .JNAE, op1, "72 ff");
        testOp1(m64, .JNB,  op1, "73 ff");
        testOp1(m64, .JNBE, op1, "77 ff");
        testOp1(m64, .JNC,  op1, "73 ff");
        testOp1(m64, .JNE,  op1, "75 ff");
        testOp1(m64, .JNG,  op1, "7E ff");
        testOp1(m64, .JNGE, op1, "7C ff");
        testOp1(m64, .JNL,  op1, "7D ff");
        testOp1(m64, .JNLE, op1, "7F ff");
        testOp1(m64, .JNO,  op1, "71 ff");
        testOp1(m64, .JNP,  op1, "7B ff");
        testOp1(m64, .JNS,  op1, "79 ff");
        testOp1(m64, .JNZ,  op1, "75 ff");
        testOp1(m64, .JO,   op1, "70 ff");
        testOp1(m64, .JP,   op1, "7A ff");
        testOp1(m64, .JPE,  op1, "7A ff");
        testOp1(m64, .JPO,  op1, "7B ff");
        testOp1(m64, .JS,   op1, "78 ff");
        testOp1(m64, .JZ,   op1, "74 ff");
    }

    {
        const op1 = Operand.immediate(0x80);
        testOp1(m32, .JA,   op1, "66 0F 87 80 00");
        testOp1(m32, .JAE,  op1, "66 0F 83 80 00");
        testOp1(m32, .JB,   op1, "66 0F 82 80 00");
        testOp1(m32, .JBE,  op1, "66 0F 86 80 00");
        testOp1(m32, .JC,   op1, "66 0F 82 80 00");
        testOp1(m32, .JE,   op1, "66 0F 84 80 00");
        testOp1(m32, .JG,   op1, "66 0F 8F 80 00");
        testOp1(m32, .JGE,  op1, "66 0F 8D 80 00");
        testOp1(m32, .JL,   op1, "66 0F 8C 80 00");
        testOp1(m32, .JLE,  op1, "66 0F 8E 80 00");
        testOp1(m32, .JNA,  op1, "66 0F 86 80 00");
        testOp1(m32, .JNAE, op1, "66 0F 82 80 00");
        testOp1(m32, .JNB,  op1, "66 0F 83 80 00");
        testOp1(m32, .JNBE, op1, "66 0F 87 80 00");
        testOp1(m32, .JNC,  op1, "66 0F 83 80 00");
        testOp1(m32, .JNE,  op1, "66 0F 85 80 00");
        testOp1(m32, .JNG,  op1, "66 0F 8E 80 00");
        testOp1(m32, .JNGE, op1, "66 0F 8C 80 00");
        testOp1(m32, .JNL,  op1, "66 0F 8D 80 00");
        testOp1(m32, .JNLE, op1, "66 0F 8F 80 00");
        testOp1(m32, .JNO,  op1, "66 0F 81 80 00");
        testOp1(m32, .JNP,  op1, "66 0F 8B 80 00");
        testOp1(m32, .JNS,  op1, "66 0F 89 80 00");
        testOp1(m32, .JNZ,  op1, "66 0F 85 80 00");
        testOp1(m32, .JO,   op1, "66 0F 80 80 00");
        testOp1(m32, .JP,   op1, "66 0F 8A 80 00");
        testOp1(m32, .JPE,  op1, "66 0F 8A 80 00");
        testOp1(m32, .JPO,  op1, "66 0F 8B 80 00");
        testOp1(m32, .JS,   op1, "66 0F 88 80 00");
        testOp1(m32, .JZ,   op1, "66 0F 84 80 00");

        testOp1(m64, .JA,   op1, "0F 87 80 00 00 00");
        testOp1(m64, .JAE,  op1, "0F 83 80 00 00 00");
        testOp1(m64, .JB,   op1, "0F 82 80 00 00 00");
        testOp1(m64, .JBE,  op1, "0F 86 80 00 00 00");
        testOp1(m64, .JC,   op1, "0F 82 80 00 00 00");
        testOp1(m64, .JE,   op1, "0F 84 80 00 00 00");
        testOp1(m64, .JG,   op1, "0F 8F 80 00 00 00");
        testOp1(m64, .JGE,  op1, "0F 8D 80 00 00 00");
        testOp1(m64, .JL,   op1, "0F 8C 80 00 00 00");
        testOp1(m64, .JLE,  op1, "0F 8E 80 00 00 00");
        testOp1(m64, .JNA,  op1, "0F 86 80 00 00 00");
        testOp1(m64, .JNAE, op1, "0F 82 80 00 00 00");
        testOp1(m64, .JNB,  op1, "0F 83 80 00 00 00");
        testOp1(m64, .JNBE, op1, "0F 87 80 00 00 00");
        testOp1(m64, .JNC,  op1, "0F 83 80 00 00 00");
        testOp1(m64, .JNE,  op1, "0F 85 80 00 00 00");
        testOp1(m64, .JNG,  op1, "0F 8E 80 00 00 00");
        testOp1(m64, .JNGE, op1, "0F 8C 80 00 00 00");
        testOp1(m64, .JNL,  op1, "0F 8D 80 00 00 00");
        testOp1(m64, .JNLE, op1, "0F 8F 80 00 00 00");
        testOp1(m64, .JNO,  op1, "0F 81 80 00 00 00");
        testOp1(m64, .JNP,  op1, "0F 8B 80 00 00 00");
        testOp1(m64, .JNS,  op1, "0F 89 80 00 00 00");
        testOp1(m64, .JNZ,  op1, "0F 85 80 00 00 00");
        testOp1(m64, .JO,   op1, "0F 80 80 00 00 00");
        testOp1(m64, .JP,   op1, "0F 8A 80 00 00 00");
        testOp1(m64, .JPE,  op1, "0F 8A 80 00 00 00");
        testOp1(m64, .JPO,  op1, "0F 8B 80 00 00 00");
        testOp1(m64, .JS,   op1, "0F 88 80 00 00 00");
        testOp1(m64, .JZ,   op1, "0F 84 80 00 00 00");
    }

    {
        const op1 = Operand.immediate16(0x80);
        testOp1(m32, .JA,   op1, "66 0F 87 80 00");
        testOp1(m32, .JAE,  op1, "66 0F 83 80 00");
        testOp1(m32, .JB,   op1, "66 0F 82 80 00");
        testOp1(m32, .JBE,  op1, "66 0F 86 80 00");
        testOp1(m32, .JC,   op1, "66 0F 82 80 00");
        testOp1(m32, .JE,   op1, "66 0F 84 80 00");
        testOp1(m32, .JG,   op1, "66 0F 8F 80 00");
        testOp1(m32, .JGE,  op1, "66 0F 8D 80 00");
        testOp1(m32, .JL,   op1, "66 0F 8C 80 00");
        testOp1(m32, .JLE,  op1, "66 0F 8E 80 00");
        testOp1(m32, .JNA,  op1, "66 0F 86 80 00");
        testOp1(m32, .JNAE, op1, "66 0F 82 80 00");
        testOp1(m32, .JNB,  op1, "66 0F 83 80 00");
        testOp1(m32, .JNBE, op1, "66 0F 87 80 00");
        testOp1(m32, .JNC,  op1, "66 0F 83 80 00");
        testOp1(m32, .JNE,  op1, "66 0F 85 80 00");
        testOp1(m32, .JNG,  op1, "66 0F 8E 80 00");
        testOp1(m32, .JNGE, op1, "66 0F 8C 80 00");
        testOp1(m32, .JNL,  op1, "66 0F 8D 80 00");
        testOp1(m32, .JNLE, op1, "66 0F 8F 80 00");
        testOp1(m32, .JNO,  op1, "66 0F 81 80 00");
        testOp1(m32, .JNP,  op1, "66 0F 8B 80 00");
        testOp1(m32, .JNS,  op1, "66 0F 89 80 00");
        testOp1(m32, .JNZ,  op1, "66 0F 85 80 00");
        testOp1(m32, .JO,   op1, "66 0F 80 80 00");
        testOp1(m32, .JP,   op1, "66 0F 8A 80 00");
        testOp1(m32, .JPE,  op1, "66 0F 8A 80 00");
        testOp1(m32, .JPO,  op1, "66 0F 8B 80 00");
        testOp1(m32, .JS,   op1, "66 0F 88 80 00");
        testOp1(m32, .JZ,   op1, "66 0F 84 80 00");

        testOp1(m64, .JA,   op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JAE,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JB,   op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JBE,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JC,   op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JE,   op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JG,   op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JGE,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JL,   op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JLE,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNA,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNAE, op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNB,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNBE, op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNC,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNE,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNG,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNGE, op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNL,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNLE, op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNO,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNP,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNS,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JNZ,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JO,   op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JP,   op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JPE,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JPO,  op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JS,   op1, AsmError.InvalidOperandCombination);
        testOp1(m64, .JZ,   op1, AsmError.InvalidOperandCombination);
    }

    {
        const op1 = Operand.immediateSigned32(-1);
        testOp1(m32, .JA,   op1, "0F 87 ff ff ff ff");
        testOp1(m32, .JAE,  op1, "0F 83 ff ff ff ff");
        testOp1(m32, .JB,   op1, "0F 82 ff ff ff ff");
        testOp1(m32, .JBE,  op1, "0F 86 ff ff ff ff");
        testOp1(m32, .JC,   op1, "0F 82 ff ff ff ff");
        testOp1(m32, .JE,   op1, "0F 84 ff ff ff ff");
        testOp1(m32, .JG,   op1, "0F 8F ff ff ff ff");
        testOp1(m32, .JGE,  op1, "0F 8D ff ff ff ff");
        testOp1(m32, .JL,   op1, "0F 8C ff ff ff ff");
        testOp1(m32, .JLE,  op1, "0F 8E ff ff ff ff");
        testOp1(m32, .JNA,  op1, "0F 86 ff ff ff ff");
        testOp1(m32, .JNAE, op1, "0F 82 ff ff ff ff");
        testOp1(m32, .JNB,  op1, "0F 83 ff ff ff ff");
        testOp1(m32, .JNBE, op1, "0F 87 ff ff ff ff");
        testOp1(m32, .JNC,  op1, "0F 83 ff ff ff ff");
        testOp1(m32, .JNE,  op1, "0F 85 ff ff ff ff");
        testOp1(m32, .JNG,  op1, "0F 8E ff ff ff ff");
        testOp1(m32, .JNGE, op1, "0F 8C ff ff ff ff");
        testOp1(m32, .JNL,  op1, "0F 8D ff ff ff ff");
        testOp1(m32, .JNLE, op1, "0F 8F ff ff ff ff");
        testOp1(m32, .JNO,  op1, "0F 81 ff ff ff ff");
        testOp1(m32, .JNP,  op1, "0F 8B ff ff ff ff");
        testOp1(m32, .JNS,  op1, "0F 89 ff ff ff ff");
        testOp1(m32, .JNZ,  op1, "0F 85 ff ff ff ff");
        testOp1(m32, .JO,   op1, "0F 80 ff ff ff ff");
        testOp1(m32, .JP,   op1, "0F 8A ff ff ff ff");
        testOp1(m32, .JPE,  op1, "0F 8A ff ff ff ff");
        testOp1(m32, .JPO,  op1, "0F 8B ff ff ff ff");
        testOp1(m32, .JS,   op1, "0F 88 ff ff ff ff");
        testOp1(m32, .JZ,   op1, "0F 84 ff ff ff ff");

        testOp1(m64, .JA,   op1, "0F 87 ff ff ff ff");
        testOp1(m64, .JAE,  op1, "0F 83 ff ff ff ff");
        testOp1(m64, .JB,   op1, "0F 82 ff ff ff ff");
        testOp1(m64, .JBE,  op1, "0F 86 ff ff ff ff");
        testOp1(m64, .JC,   op1, "0F 82 ff ff ff ff");
        testOp1(m64, .JE,   op1, "0F 84 ff ff ff ff");
        testOp1(m64, .JG,   op1, "0F 8F ff ff ff ff");
        testOp1(m64, .JGE,  op1, "0F 8D ff ff ff ff");
        testOp1(m64, .JL,   op1, "0F 8C ff ff ff ff");
        testOp1(m64, .JLE,  op1, "0F 8E ff ff ff ff");
        testOp1(m64, .JNA,  op1, "0F 86 ff ff ff ff");
        testOp1(m64, .JNAE, op1, "0F 82 ff ff ff ff");
        testOp1(m64, .JNB,  op1, "0F 83 ff ff ff ff");
        testOp1(m64, .JNBE, op1, "0F 87 ff ff ff ff");
        testOp1(m64, .JNC,  op1, "0F 83 ff ff ff ff");
        testOp1(m64, .JNE,  op1, "0F 85 ff ff ff ff");
        testOp1(m64, .JNG,  op1, "0F 8E ff ff ff ff");
        testOp1(m64, .JNGE, op1, "0F 8C ff ff ff ff");
        testOp1(m64, .JNL,  op1, "0F 8D ff ff ff ff");
        testOp1(m64, .JNLE, op1, "0F 8F ff ff ff ff");
        testOp1(m64, .JNO,  op1, "0F 81 ff ff ff ff");
        testOp1(m64, .JNP,  op1, "0F 8B ff ff ff ff");
        testOp1(m64, .JNS,  op1, "0F 89 ff ff ff ff");
        testOp1(m64, .JNZ,  op1, "0F 85 ff ff ff ff");
        testOp1(m64, .JO,   op1, "0F 80 ff ff ff ff");
        testOp1(m64, .JP,   op1, "0F 8A ff ff ff ff");
        testOp1(m64, .JPE,  op1, "0F 8A ff ff ff ff");
        testOp1(m64, .JPO,  op1, "0F 8B ff ff ff ff");
        testOp1(m64, .JS,   op1, "0F 88 ff ff ff ff");
        testOp1(m64, .JZ,   op1, "0F 84 ff ff ff ff");
    }

}
