# VEX and EVEX encoding for AVX and AVX512

References:
* http://www.intel.com/products/processor/manuals/ (Volume 2: Chapter 2.3)

AVX: VEX and XOP encoding

* Can encode XMM0-15 and YMM0-15 registers
* Some SSE instructions on XMM can be encoded with both VEX or legacy opcode
* Adding these prefixes generates \#UD: 0xF0, 0x66, 0xF2, 0xF3 (group 1 and 3)
* XOP is AMD's version of VEX prefix. Uses same format, just different constant 0x8F in a 3 byte VEX prefix.
* VEX prefix is used to encode some instructions that operate on GPR with 3 operands
    * eg: ANDN, BEXTR, BLSI, BLSMSK, BLSR, BZHI, MULX, PDEP, PEXT, RORX, SARX, SHLX, SHRX


// Prefixes | VEX(2,3) | Opcode(1) | ModRM(1) | SIB(0,1) | disp(0,1,2,4) | imm8(0,1)
11 bytes maximum

2 byte VEX
```
      7   6   5   4   3   2   1   0
C5  | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 1 |
P0: | R | v | v | v | v | L | p | p |
```

3 byte VEX
```
      7   6   5   4   3   2   1   0
C4  | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
P0: | R | X | B | m | m | m | m | m |
P1: | W | v | v | v | v | L | p | p |
```

3 byte XOP is same as 3 byte vex except with 0x8F magic prefix instead of 0xC4

* Prefixes
    * REX / 0x66 / 0xF2 / 0xF3 prefixes reserved for future use
    * Allowed: Address size (0x67) / segment override
* VEX (2,3)
    * Prefix(1), determines length of the VEX/XOP
        * Two byte: 0xC5 (opcode for LDS in compat mode)
        * Three byte (VEX): 0xC4 (opcode for LES in compat mode)
        * Three byte (XOP): 0x8F (POP uses opcode `8F /0`)
        * Two byte instructions, can also be encoded as 3 byte versions
        * Two byte only be used under these conditions:
            * VEX.X == 1, VEX.B == 1, VEX.W == 0 and VEX.mm == 0b00001
            * VEX.~X == 0, VEX.~B == 0, VEX.W == 0 and VEX.mm == 0b00001
            * ie: opcode uses 0F prefix, and 3 operand `reg_num < 0b111`
    * VEX.vvvv (4 bit) (source vector)
        * Non-destructive source operand (used in 3/4 operand instructions)
        * Bit inversions of reg number: `~vvvv = ~1111 = 0000 -> XMM0 / YMM0`
    * VEX.L (1 bit) (vector length)
        * L=0 -> 128 bit vectors
        * L=1 -> 256 bit vectors
        * Docs use notation VEX.128 / VEX.256 to refer to these
    * REX R/X/B equivalents in VEX
        * VEX encodes these inverted eg: VEX.~R = REX.R
        * 2 byte VEX, only provides VEX.R
        * 3 byte VEX: provides VEX.W, VEX.~R, VEX.~X, VEX.~B
    * REX W equivalent in VEX
        * not inverted
        * VEX.W used to pick 32/64 bit general purpose registers (RAX vs EAX)
        * VEX.W has different meaning if no GPR are used in the instruction
    * VEX.pp (2 bit) prefix selector
        * Equivalent to legacy SSE instructions prefixes 0x66, 0xF2, 0xF3
        * 0b00 -> none
        * 0b01 -> 0x66
        * 0b10 -> 0xF3
        * 0b11 -> 0xF2
    * VEX.mmmmm (5 bit) opcode escape selector
        * 0b00000 -> reserved
        * 0b00001 -> 0F
        * 0b00010 -> 0F 38
        * 0b00011 -> 0F 3A
        * other values reserved
        * If 2 byte VEX is used, 0F prefix is implied
    * opcode, exactly one byte immediately following VEX prefix
    * ModRM / SIB / displacement
        * ModRM.rm
            * Encodes the operand that is a memory address
            * Otherwise it can encode either a source or destination register
        * ModRM.reg
            * Opcode extension
            * Otherwise it can encode either a source or destination register
        * SIB and displacement work the same way as in other instructions
            * VSIB
                * In AVX2, SIB can be used as part of a VSIB memory addressing
                * scale field same as SIB
                * index field: register number of a vector index register
                * base field: register number of the base register (GPR)
                * In 64bit modes, use VEX.B, VEX.X for 4th bit of register number
    * imm8[7:4]
        * The 4 bits imm8[7:4] encode the third source operand in a 4 operand instruction


## VEX in instruction summary table 

VEX.[128,256,LIG,LZ].[66,F2,F3].0F/0F3A/0F38.[W0,W1,WIG] opcode [/r] [/ib,/is4]

* VEX.128 / VEX.256 -> VEX.L
* VEX.LIG -> VEX.L is ignored
* VEX.66 / VEX.F2 / VEX.F3 -> VEX.pp
* VEX.0F / VEX.0F3A / VEX.0F38 -> VEX.mm
* VEX.W0 -> VEX.W = 0 (can possibly use 2 or 3 byte vex)
* VEX.W1 -> VEX.W = 1 (requires 3 byte vex)
* VEX.LZ -> VEX.L = 0
* VEX.WIG -> VEX.W is ignored (can use 2 or 3 byte vex)
* `/is4` imm8[7:4] contains source register, imm8[3:0] instruction specific payload


--------------------------------------------------------------------------------

# AVX-512 encoding EVEX prefix

References:
* http://www.intel.com/products/processor/manuals/ (Volume 2: Chapter 2.6)
* https://www.officedaytime.com/simd512e/simdimg/avx512memo.html

AVX-512: EVEX encoding

`Prefixes | EVEX(4) | Opcode(1) | ModRM(1) | SIB(1) | disp(1,2,4) | imm(1)`

* 0x62, P0, P1, P2
    * EVEX is 4 byte prefix (replaces 0x62 BOUND instruction)
    * 3 payload bytes P0, P1, P2

```
      7   6   5   4   3   2   1   0
62  | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 0 |
P0: | R | X | B | R'| 0 | 0 | m | m |
P1: | W | v | v | v | v | 1 | p | p |
P2: | z | L'| L | b | V'| a | a | a |
```

* EVEX.mm
    * 0b00001 -> 0F
    * 0b00010 -> 0F 38
    * 0b00011 -> 0F 3A
* EVEX.pp
    * 0b00 -> none
    * 0b01 -> 0x66
    * 0b10 -> 0xF3
    * 0b11 -> 0xF2
* EVEX.W
    * EVEX.W0, EVEX.W1 -> opcode extension
    * EVEX.W -> operand size select
* EVEX.RXB
    * Combine with reg / rm (base / index) like normal
    * EVEX.XB can extend ModRM.rm to 5 bits when SIB/VSIB absent
* EVEX.R'R
    * extends ModRM.reg to 5 bits
* EVEX.V'vvvv
* EVEX.vvvv
    * bits are inverted like VEX.vvvv
* EVEX.L'L : vector length / rounding control
    * vector length information for packed instructions
        * `0b00 -> EVEX.128`
        * `0b01 -> EVEX.256`
        * `0b10 -> EVEX.512`
        * `0b00 -> reserved`
    * ignored for instructions on vector register treated as single element
    * rounding control for floating point instructions
        * Only used this way in 512bit/scalar, floating point instructions with rounding semantic
        * EVEX.b must be set
        * `0b00 -> {rn-sae} / {rne-sae}` round to nearest integer
        * `0b01 -> {rd-sae}` round down (towards -inf)
        * `0b10 -> {ru-sae}` round up (towards +inf)
        * `0b11 -> {rz-sae}` round towards zero
    * if EVEX is used to encode scalar instructions it is generally ignored
* EVEX.aaa
    * embedded opmask register specifier {k0, k1-k7}
    * bit masks that select components from packed vector operations
    * used as `predicate operands` in EVEX instructions
        * eg: `vpaddb zmm0 {k3}, zmm1, zmm2`
        * k0 can't be used as a predicate operand
    * can be used as normal source/dest in some instructions
        * eg: `knot k1, k2`
        * k0 can be used in these instructions
    * use `EVEX.aaa = 0b000` for no masking or when it is not supported
* EVEX.z
    * For instructions that take a mask register, selects what happens to the unused bits
        * EVEX.z = 0: merging: masked elements in dest reg are unmodified (default)
        * EVEX.z = 1: zeroing: masked elements in dest reg are zeroed
    * Syntax
        * `vpaddb zmm0 {k3}, zmm1, zmm2` (merging)
        * `vpaddb zmm0 {k3} {z}, zmm1, zmm2` (zeroing)
* EVEX.b
    * broadcast / RC (rounding control) / SAE context (behaviour depends on instruction)
    * EVEX.b encodes three different things, but can only encode one at a time
        * Can only use RC/SAE when last operand is a register (RC vs SAE depends on instruction)
        * Can only use broadcast when last operand is a memory
    * broadcast a single element across the destination register
        * Written like `m32bcst`, `m64bcst` in manual
        * Only when source operand is from memory.
        * Repeats the given value in memory to create a packed vector
        * eg: m32bcst: `DWORD [RAX]{1to4}` repeats RAX 4 times to create 128 bit value
        * broadcast double:
            * `vpaddd xmm0, xmm1, [RAX]{1to4}`
            * `vpaddd ymm0, ymm1, [RAX]{1to8}`
            * `vpaddd zmm0, zmm1, [RAX]{1to16}`
            * alternative syntax:
            * `vpaddd xmm0, xmm1, dword bcst [RAX]`
            * `vpaddd ymm0, ymm1, dword bcst [RAX]`
            * `vpaddd zmm0, zmm1, dword bcst [RAX]`
        * broadcast quad:
            * `vpaddq xmm0, xmm1, [RAX]{1to2}`
            * `vpaddq ymm0, ymm1, [RAX]{1to4}`
            * `vpaddq zmm0, zmm1, [RAX]{1to8}`
            * alternative syntax:
            * `vpaddq xmm0, xmm1, qword bcst [RAX]`
            * `vpaddq ymm0, ymm1, qword bcst [RAX]`
            * `vpaddq zmm0, zmm1, qword bcst [RAX]`
    * redirect L'L field as static rounding control + SAE
        * Only register-to-register instructions (no memory operands)
        * Only instructions that are 512bit or scalar (since it reuses LL field)
        * `vcvtpd2qq zmm0, zmm1`
        * `vcvtpd2qq zmm0, zmm1, {rn-sae}`
        * `vcvtpd2qq zmm0, zmm1, {rd-sae}`
        * `vcvtpd2qq zmm0, zmm1, {ru-sae}`
        * `vcvtpd2qq zmm0, zmm1, {rz-sae}`
    * enable SAE (suppress all exceptions)
        * Only register-to-register instructions (no memory operands)
        * Only used in other floating point vector instructions without rounding semantics
            * `vminpd zmm1, zmm2, {sae}`
    * otherwise setting EVEX.b generates \#UD

Fields that can that can be "part of the opcode"

* EVEX.L'L 2 bits (depends on instruction)
* EVEX.mm 2 bits
* EVEX.pp 2 bits
* EVEX.W0, EVEX.W1 1 bit (depends on instruction)

Fields that are "part of the operands"

* EVEX.XB + ModRM.rm -> 5 bit reg number
* EVEX.R'R + ModRM.reg -> 5 bit reg number
* EVEX.V'vvvv -> 5 bit reg number
* EVEX.aaa -> 3 bit mask register number
* EVEX.z -> 1 bit selects zeroing or merging
* EVEX.b -> 1 bit SAE (suppress all exceptions on float operations)


## EVEX in instruction summary table 

EVEX.[128,256,512,LIG].[66,F2,F3].0F/0F3A/0F38.[W0,W1,WIG] opcode [/r] [ib]

* EVEX.128 / EVEX.256 / EVEX.512 -> VEX.L'L
* EVEX.LIG -> EVEX.L'L is ignored
* EVEX.66 / EVEX.F2 / EVEX.F3 -> EVEX.pp
* EVEX.0F / EVEX.0F3A / EVEX.0F38 -> EVEX.mm
* EVEX.W0 -> EVEX.W = 0
* EVEX.W1 -> EVEX.W = 1
* EVEX.WIG -> EVEX.W is ignored (can use 2 or 3 byte vex)


