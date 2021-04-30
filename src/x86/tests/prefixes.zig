const std = @import("std");
usingnamespace @import("../machine.zig");
usingnamespace @import("../util.zig");

const imm = Operand.immediate;
const mem = Operand.memory;
const memRm = Operand.memoryRm;
const reg = Operand.register;

const prefix = EncodingControl.prefix;
const prefix2 = EncodingControl.prefix2;
const hint = EncodingControl.encodingHint;

test "user prefixes" {
    debugPrint(false);

    const m16 = Machine.init(.x86_16);
    const m32 = Machine.init(.x86_32);
    const m64 = Machine.init(.x64);

    {
        testOpCtrl2(m64, prefix(.Lock), .MOV, reg(.RAX), memRm(.GS, .QWORD, .EAX, 0x11), "f0 65 67 48 8b 40 11");
        testOpCtrl2(m64, prefix2(.Repne, .Lock), .MOV, reg(.RAX), memRm(.GS, .QWORD, .EAX, 0x11), "f2 f0 65 67 48 8b 40 11");
        testOpCtrl2(m64, prefix2(.Lock, .Repne), .MOV, reg(.RAX), memRm(.GS, .QWORD, .EAX, 0x11), "f0 f2 65 67 48 8b 40 11");
        testOpCtrl0(m64, prefix(.Repne), .CMPSQ, "f2 48 a7");
    }

    {
        const ctrl = EncodingControl.init(
            .NoHint,
            .AddPrefixes,
            &[_]Prefix{ .OpSize, .AddrSize, .SegmentCS, .Repne },
        );
        testOpCtrl0(m64, ctrl, .NOP, "66 67 2E F2 90");
        testOpCtrl1(m64, ctrl, .NOP, memRm(.GS, .QWORD, .EAX, 0x11), "66 67 2e f2 65 67 48 0f 1f 40 11");
    }

    {
        const ctrl = EncodingControl.init(
            .NoHint,
            .ExactPrefixes,
            &[_]Prefix{ .OpSize, .AddrSize, .SegmentCS, .Repne },
        );
        testOpCtrl0(m64, ctrl, .NOP, "66 67 2E F2 90");
        testOpCtrl1(m64, ctrl, .NOP, memRm(.GS, .QWORD, .EAX, 0x11), AsmError.InvalidPrefixes);
    }

    {
        const ctrl = EncodingControl.init(
            .NoHint,
            .ExactPrefixes,
            &[_]Prefix{ .OpSize, .AddrSize, .SegmentGS, .Repne },
        );
        testOpCtrl0(m64, ctrl, .NOP, "66 67 65 F2 90");
        testOpCtrl1(m64, ctrl, .NOP, memRm(.GS, .QWORD, .EAX, 0x11), "66 67 65 f2 48 0f 1f 40 11");
    }

    {
        const ctrl = EncodingControl.init(
            .NoHint,
            .ExactPrefixes,
            &[_]Prefix{ .OpSize, .SegmentGS, .Repne },
        );
        testOpCtrl0(m64, ctrl, .NOP, "66 65 F2 90");
        testOpCtrl1(m64, ctrl, .NOP, memRm(.GS, .QWORD, .EAX, 0x11), AsmError.InvalidPrefixes);
    }

    {
        const cs_x11 = EncodingControl.init(.NoHint, .AddPrefixes, &([_]Prefix{.SegmentCS} ** 11));
        testOpCtrl0(m64, cs_x11, .NOP, "2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 90");
        testOpCtrl1(m64, cs_x11, .NOP, memRm(.DefaultSeg, .QWORD, .RAX, 0x00), "2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 48 0f 1f 00");
        testOpCtrl1(m64, cs_x11, .NOP, memRm(.DefaultSeg, .QWORD, .RAX, 0x11), AsmError.InstructionTooLong);
        testOpCtrl1(m64, cs_x11, .NOP, memRm(.DefaultSeg, .QWORD, .RAX, 0x44332211), AsmError.InstructionTooLong);
    }

    {
        const cs_x14 = EncodingControl.init(.NoHint, .ExactPrefixes, &([_]Prefix{.SegmentCS} ** 14));
        testOpCtrl0(m64, cs_x14, .NOP, "2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 90");
        testOpCtrl1(m64, cs_x14, .NOP, memRm(.DefaultSeg, .DWORD, .RAX, 0x00), AsmError.InstructionTooLong);
    }

    {
        const cs_x10 = EncodingControl.init(.NoHint, .ExactPrefixes, &([_]Prefix{.SegmentCS} ** 10));
        testOpCtrl1(m64, cs_x10, .NOP, memRm(.CS, .DWORD, .RAX, 0x00), "2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 0f 1f 00");
        testOpCtrl1(m64, cs_x10, .NOP, memRm(.GS, .DWORD, .RAX, 0x00), AsmError.InvalidPrefixes);
        testOpCtrl1(m64, cs_x10, .NOP, memRm(.GS, .DWORD, .RAX, 0x44332211), AsmError.InstructionTooLong);
        testOpCtrl1(m64, cs_x10, .NOP, memRm(.CS, .DWORD, .RAX, 0x44332211), AsmError.InstructionTooLong);
    }
}
