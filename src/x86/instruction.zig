const std = @import("std");
const assert = std.debug.assert;

const machine = @import("machine.zig");

usingnamespace(@import("types.zig"));

const ModRmResult = machine.operand.ModRmResult;
const Immediate = machine.operand.Immediate;
const Address = machine.operand.Address;
const MOffsetDisp = machine.operand.MOffsetDisp;
const Register = machine.Register;

// LegacyPrefixes | REX/VEX/EVEX | OPCODE(0,1,2,3) | ModRM | SIB | displacement(0,1,2,4) | immediate(0,1,2,4)
pub const prefix_max_len = 4;
pub const ext_max_len = 1;
pub const opcode_max_len = 4;
pub const modrm_max_len = 1;
pub const sib_max_len = 1;
pub const displacement_max_len = 8;
pub const immediate_max_len = 8;
pub const instruction_max_len = 15;

pub const ViewPtr = struct {
    offset: u8 = 0,
    size: u8 = 0,
};

/// Slices to parts of an instruction
pub const View = struct {
    prefix: ViewPtr = ViewPtr{},
    ext: ViewPtr = ViewPtr{},
    opcode: ViewPtr = ViewPtr{},
    modrm: ViewPtr = ViewPtr{},
    sib: ViewPtr = ViewPtr{},
    displacement: ViewPtr = ViewPtr{},
    immediate: ViewPtr = ViewPtr{},
};

pub const Instruction = struct {
    const max_length = 15;
    data: [max_length]u8 = undefined,
    len: u8 = 0,
    view: View = View{},

    pub fn asSlice(self: @This()) []const u8 {
        return self.data[0..self.len];
    }

    pub fn asMutSlice(self: *@This()) []u8 {
        return self.data[0..self.len];
    }

    fn viewSlice(self: @This(), vptr: ?ViewPtr) ?[]const u8 {
        if (vptr) |v| {
            return self.data[v.offset .. (v.offset+v.size)];
        } else {
            return null;
        }
    }

    fn viewMutSlice(self: *@This(), vptr: ?ViewPtr) ?[]u8 {
        if (vptr) |v| {
            return self.data[v.offset .. (v.offset+v.size)];
        } else {
            return null;
        }
    }

    fn debugPrint(self: @This()) void {
        const warn = if (true) std.debug.warn else util.warnDummy;
        warn("Instruction {{", .{});
        if (self.view.prefix.size != 0) {
            warn(" Pre:{x}", .{self.viewSlice(self.view.prefix)});
        }
        if (self.view.ext.size != 0) {
            warn(" Ext:{x}", .{self.viewSlice(self.view.ext)});
        }
        if (self.view.opcode.size != 0) {
            warn(" Op:{x}", .{self.viewSlice(self.view.opcode)});
        }
        if (self.view.modrm.size != 0) {
            warn(" Rm:{x}", .{self.viewSlice(self.view.modrm)});
        }
        if (self.view.sib.size != 0) {
            warn(" Sib:{x}", .{self.viewSlice(self.view.sib)});
        }
        if (self.view.displacement.size != 0) {
            warn(" Dis:{x}", .{self.viewSlice(self.view.displacement)});
        }
        if (self.view.immediate.size != 0) {
            warn(" Imm:{x}", .{self.viewSlice(self.view.immediate)});
        }
        warn(" }}\n", .{});
    }

    fn makeViewPart(self: *@This(), size: u8) ViewPtr {
        assert(self.len+size <= max_length);
        return ViewPtr {
            .offset = @intCast(u8, self.len),
            .size = size,
        };
    }

    fn addBytes(self: *@This(), bytes: []const u8) void {
        std.mem.copy(u8, self.data[self.len..], bytes[0..]);
        self.len += @intCast(u8, bytes.len);
    }

    fn addByte(self: *@This(), byte: u8) void {
        self.data[self.len] = byte;
        self.len += 1;
    }

    pub fn prefixes(self: *@This(), prefix: Prefixes) void {
        if (prefix.len == 0) {
            return;
        }
        self.view.prefix = self.makeViewPart(prefix.len);
        self.addBytes(prefix.asSlice());
    }

    pub fn sizeOveridePrefix(self: *@This(), mode: Mode86, size: BitSize) void {
        if (
            (mode == .x86_16 and size == .Bit32)
            or (mode != .x86_16 and size == .Bit16)
        ) {
            self.view.prefix = self.makeViewPart(1);
            self.addByte(0x66);
        }
    }

    // TODO: need to handle more cases, and those interacting with different addressing modes
    pub fn addRex(self: *@This(), mode: Mode86, reg: ?Register, rm: ?Register, default_size: DefaultSize) AsmError!void {
        const reg_num = if (reg == null) 0 else reg.?.number();
        const rm_num = if (rm == null) 0 else rm.?.number();
        var needs_rex = false;
        var w: u1 = 0;

        if (default_size.bitSize(mode) != .Bit64) {
            if (reg != null and reg.?.needsRex()) { needs_rex = true; }
            if (rm != null and rm.?.needsRex())   { needs_rex = true; }
            if (reg != null and reg.?.bitSize() == .Bit64) { w = 1; }
            if (rm != null and rm.?.bitSize() == .Bit64)  { w = 1; }
        }

        const r: u8 = if (reg_num < 8) 0 else 1;
        const x: u8 = 0;
        const b: u8 = if (rm_num < 8) 0 else 1;
        const rex_byte: u8 = (
            (0x40)
            | (@as(u8, w) << 3)
            | (r << 2)
            | (x << 1)
            | (b << 0)
        );

        if (rex_byte != 0x40 or needs_rex) {
            if (mode != .x64) {
                return AsmError.InvalidMode;
            }

            self.view.ext = self.makeViewPart(1);
            self.addByte(rex_byte);
        }
    }

    pub fn rexRaw(self: *@This(), mode: Mode86, rex_byte: u8) AsmError!void {
        if (rex_byte != 0x40) {
            if (mode != .x64) {
                return AsmError.InvalidMode;
            }
            self.view.ext = self.makeViewPart(1);
            self.addByte(rex_byte);
        }
    }

    pub fn rex(self: *@This(), mode: Mode86, w: u1, rm: ModRmResult) AsmError!void {
        const rex_byte = rm.rex(w);

        if (rm.needs_rex and rm.needs_no_rex) {
            return AsmError.InvalidOperandCombination;
        }

        if (rex_byte != 0x40 or rm.needs_rex) {
            if (mode != .x64) {
                return AsmError.InvalidMode;
            }
            if (rm.needs_no_rex) {
                return AsmError.InvalidOperandCombination;
            }

            self.view.ext = self.makeViewPart(1);
            self.addByte(rex_byte);
        }
    }

    pub fn opcode(self: *@This(), op: []const u8) void {
        assert(op.len <= opcode_max_len);
        self.view.opcode = self.makeViewPart(op.len);
        self.addBytes(op);
    }

    pub fn opcodeByte(self: *@This(), op: u8) void {
        self.view.opcode = self.makeViewPart(1);
        self.addByte(op);
    }

    pub fn modrm(self: *@This(), rm: ModRmResult) void {
        self.view.modrm = self.makeViewPart(1);
        self.addByte(rm.modrm());

        if (rm.sib) |sib| {
            self.view.sib = self.makeViewPart(1);
            self.addByte(sib);
        }

        switch (rm.disp) {
            .None => { },
            .Disp8 => self.addDisp8(rm.disp.Disp8),
            .Disp32 => self.addDisp32(rm.disp.Disp32),
        }
    }

    /// Add the opcode to instruction.
    pub fn addOpcode(self: *@This(), op: Opcode) void {
        self.view.opcode = self.makeViewPart(op.len);
        self.addBytes(op.asSlice());
    }

    /// Add the opcode to instruction incrementing the last byte by register number.
    pub fn addOpcodeRegNum(self: *@This(), op: Opcode, reg: Register) void {
        var modified_op = op;
        modified_op.opcode[modified_op.len-1] += reg.number() & 0x07;
        self.view.opcode = self.makeViewPart(modified_op.len);
        self.addBytes(modified_op.asSlice());
    }

    /// Add the immediate to the instruction
    pub fn addImm(self: *@This(), imm: Immediate) void {
        switch (imm.size) {
            .Imm8_any,
            .Imm8 => self.addImm8(imm.as8()),
            .Imm16_any,
            .Imm16 => self.addImm16(imm.as16()),
            .Imm32_any,
            .Imm32 => self.addImm32(imm.as32()),
            .Imm64_any,
            .Imm64 => self.addImm64(imm.as64()),
        }
    }

    pub fn addImm8(self: *@This(), imm8: u8) void {
        self.view.immediate = self.makeViewPart(1);
        self.add8(imm8);
    }

    pub fn addImm16(self: *@This(), imm16: u16) void {
        self.view.immediate = self.makeViewPart(2);
        self.add16(imm16);
    }

    pub fn addImm32(self: *@This(), imm32: u32) void {
        self.view.immediate = self.makeViewPart(4);
        self.add32(imm32);
    }

    pub fn addImm64(self: *@This(), imm64: u64) void {
        self.view.immediate = self.makeViewPart(8);
        self.add64(imm64);
    }

    pub fn addDisp8(self: *@This(), disp8: u8) void {
        self.view.displacement = self.makeViewPart(1);
        self.add8(disp8);
    }

    pub fn addDisp16(self: *@This(), disp16: u16) void {
        self.view.displacement = self.makeViewPart(2);
        self.add16(disp16);
    }

    pub fn addDisp32(self: *@This(), disp32: u32) void {
        self.view.displacement = self.makeViewPart(4);
        self.add32(disp32);
    }

    pub fn addDisp64(self: *@This(), disp64: u64) void {
        self.view.displacement = self.makeViewPart(8);
        self.add64(disp64);
    }

    pub fn add8(self: *@This(), imm8: u8) void {
        self.addByte(imm8);
    }

    pub fn add16(self: *@This(), imm16: u16) void {
        self.addByte(@intCast(u8, (imm16 >> 0) & 0xFF));
        self.addByte(@intCast(u8, (imm16 >> 8) & 0xFF));
    }

    pub fn add32(self: *@This(), imm32: u32) void {
        self.addByte(@intCast(u8, (imm32 >> 0)  & 0xFF));
        self.addByte(@intCast(u8, (imm32 >> 8)  & 0xFF));
        self.addByte(@intCast(u8, (imm32 >> 16) & 0xFF));
        self.addByte(@intCast(u8, (imm32 >> 24) & 0xFF));
    }

    pub fn add64(self: *@This(), imm64: u64) void {
        self.addByte(@intCast(u8, (imm64 >>  0) & 0xFF));
        self.addByte(@intCast(u8, (imm64 >>  8) & 0xFF));
        self.addByte(@intCast(u8, (imm64 >> 16) & 0xFF));
        self.addByte(@intCast(u8, (imm64 >> 24) & 0xFF));
        self.addByte(@intCast(u8, (imm64 >> 32) & 0xFF));
        self.addByte(@intCast(u8, (imm64 >> 40) & 0xFF));
        self.addByte(@intCast(u8, (imm64 >> 48) & 0xFF));
        self.addByte(@intCast(u8, (imm64 >> 56) & 0xFF));
    }

    pub fn addMOffsetDisp(self: *@This(), disp: MOffsetDisp) void {
        switch (disp) {
            .Disp16 => self.add16(disp.Disp16),
            .Disp32 => self.add32(disp.Disp32),
            .Disp64 => self.add64(disp.Disp64),
        }
    }

    pub fn addAddress(self: *@This(), addr: Address) void {
        const disp = addr.getDisp();

        switch (addr) {
            .FarJmp => |far| {
                const disp_size = disp.bitSize();
                assert(disp_size != .Bit64);
                self.view.displacement = self.makeViewPart(disp_size.valueBytes() + 2);
                self.addMOffsetDisp(disp);
                self.add16(far.segment);
            },
            .MOffset => |moff| {
                const disp_size = disp.bitSize();
                self.view.displacement = self.makeViewPart(disp_size.valueBytes());
                self.addMOffsetDisp(disp);
            },
        }


    }

};

