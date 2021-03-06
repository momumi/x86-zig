# Segment addressing

SegReg:Address

DS:0x1234

CS:EIP

# Exceptions

* Page fault exception: `#PF(fault code)`
* General-protection exception: `#GP(0)`

# CPUID, CR and MSR Values

## CPUID input and output

```
CPUID.01H:EDX.SSE[bit 25] = 1
       ^       ^            ^---- Value or range of output
       |       |
       |       ------- Value of flag with bit position
       |
       ---- Input to CPUID instruction
```

* 01H -> is the input value to the EAX register
* EDX.SSE[bit 25] -> output register and feature flag or field name with bit possition

## Control Register Values
```
CR4.OSFXSR[bit 9] = 1
```

## Model-specific register values
```
IA32_MISC_ENABLE.ENABLEFOPCODE[bit 2] = 1
```

# Instructin format

References:

* https://www.felixcloutier.com/x86/
* https://wiki.osdev.org/X86-64_Instruction_Encoding
* http://www.intel.com/products/processor/manuals/ (Volume 2: Chapter 2)


// LegacyPrefixes | REX/VEX/EVEX | OPCODE(0,1,2,3) | ModRM | SIB | displacement(0,1,2,4) | immediate(0,1,2,4)

* Prefixes: optional prefixes, 1 byte each. Can take one prefix from up to 4 (Intel) or 5 (AMD) different groups:
    * Group 1:
        * Lock:
            * Lock: 0xF0
            * On AMD, lock is treated as it's own group
        * Repeat: (MOVS, CMPS, SCAS, LODS, STOS, INS, OUTS)
            * REPNE/REPNZ: 0xF2 (Repeat-not-Zero)
            * REP/REPE/REPZ: 0xF3
        * BND: encoded as 0xF2 if the following conditions are true
            * CPUID.(EAX=07H,ECX=0):EBX.MPX[bit 14] is set
            * BNDCFG.EN and/or IA32_BNDCFGS.EN is set
            * When the F2 prefix precedes a near {CALL,RET,JMP,Jcc} or short Jcc
    * Group 2:
        * Segment override prefixes:
            * 0x2E - CS segment override (ignored on 64 bit)
            * 0x3E - DS segment override (ignored on 64 bit)
            * 0x26 - ES segment override (ignored on 64 bit)
            * 0x36 - SS segment override (ignored on 64 bit)
            * 0x64 - FS segment override
            * 0x65 - GS segment override
        * Branch hints:
            * 0x2E - Branch not taken (used only with Jcc instructions)
            * 0x3E - Branch taken (used only with Jcc instructions)
    * Group 3: 0x66: (select between 16- and 32-bit operand sizes, selects the non-default size)
        * 0x66: Operand-size override prefix is encoding (mandatory for some instr)
    * Group 4: 0x67: (select between 16- and 32-bit addressing, selects the non-default size)
        * 0x67: Address-size override prefix
        * Some instructions use 0x67 to control the size of implicit register operand
            * eg in 32 bit mode:
                * `JCXZ  0x00 <==> 67 E3 00`
                * `JECXZ 0x00 <==> E3 00`
            * eg in 64 bit mode:
                * `JECXZ 0x00 <==> 67 E3 00`
                * `JRCXZ 0x00 <==> E3 00`
    * Can't use 0xF0, 0xF2, 0xF3, 0x66 prefixes with VEX or EVEX (Invalid Opcode #UD exception)
    * NOTE: on AMD treats prefixes in 5 groups with Lock and Repeat prefixes in separate groups
    * NOTE: can technically use as many prefixes as long as instruction length is ≤15
        * If multiple prefixes from the same group are used, only the last one has meaning
        * Can encode `0x66 0x66 0x66 0x66 0x66 0x66 0x66 0x66 0x66 0x66 0x66 0x66 0x66 0x66 0x90` (NOP + 14 0x66 prefixes)
        * Can encode `0x2E 0x36 0x3E 0x26 0x64 0x65 0x67 0xF2 0xF3 0x66 0x66 0x66 0x66 0x66 0x90` (NOP + 14 0x66 prefixes)
* REX: 1 byte prefix used for 64-bit instruction extensions
    * Encoded as REX = 0b0100WRXB
        * REX.W: 64 bit operand size
        * REX.R: extends the modrm.reg to 4 bits
        * REX.X: extends the sib.index to 4 bits
        * REX.B: extends the modrm.rm or sib.base to 4 bits
    * Not all instructions require a rex prefix in 64-bit mode
        * Not needed by near branches
        * Not needed by functions that implicity reference the RSP
    * REX byte must be placed immediately before the opcode bytes
        * If another prefix is placed between the REX byte and the opcode, then the REX byte is (ignored)/(undefined behavior)
        * Mandatory prefixes must be placed before the REX byte, otherwise the REX byte will be ignored
        * example using `mov eax, ecx` == `89 c8`
            * `48 66 89 c8` -> `mov ax, cx` REX.W=0x48 ignored
            * `66 48 89 c8` -> `mov rax, rcx` 0x66 ignored
    * If both prefix 0x66 and REX.W=0x48 are used, then operand size is 64 bit
    * If both prefix 0x66 and REX.~W=0x40 are used, then operand size is 16 bit
    * REX maybe invalid or ignored in some places
        * Multiple REX prefixes is undefined behaviour but in practice most CPUs seem to:
            * treat REX as an extra prefix that counts to opcode length
            * ignore any REX prefix that does not immediately proceed the opcode
        * Can't use REX prefix with VEX or EVEX (Invalid Opcode #UD exception)
    * Specify GPRs and SSE registers
    * Specify 64-bit operand size
    * Specify extended control registers
    * List of instructions that are 64 bit that don't require the REX prefix:
        * CALL (near)
        * JMP (near)
        * RET (near)
        * ENTER
        * Jcc
        * JRCXZ
        * LEAVE
        * LGDT
        * LIDT
        * LLDT
        * LOOP
        * LOOPcc
        * LTR
        * MOV CRn
        * MOV DRn
        * POP reg/mem
        * POP reg
        * POP FS
        * POP GS
        * POPF, POPFD, POPFQ
        * PUSH imm8
        * PUSH imm32
        * PUSH reg/mem
        * PUSH reg
        * PUSH FS
        * PUSH GS
        * PUSHF, PUSHFD, PUSHFQ
* VEX: prefix used for AVX instructions
    * 2 byte form
        * Mainly for 128-bit scalar and the most common 256-bit AVX instructions
        * First byte 0xC5
    * 3 byte form
        * A compact replacement of REX and 3-byte opcode instrucions (AVX and FMA)
        * First byte 0xC4
    * VEX and {0xF0, 0x66, 0xF2, 0xF3, REX} prefix raises `#UD` (invalid opcode exception)
* EVEX:
    * EVEX and {0xF0, 0x66, 0xF2, 0xF3, REX} prefix raises `#UD` (invalid opcode exception)
    * 4 byte prefix
        * First byte 0x62
* Opcode: 1,2 or 3 byte opcode [required]
    * 1 byte opcode
    * 2 byte opcode
        * An escape opcode byte 0x0F, plus an additional opcode byte
        * A manadatory prefix (0x66, 0xF2, 0xF3), an escape opcode byte, plus an opcode byte
        * For example: `CVTDQ2PD == F3 0F E6` F3 is not treated as a normal prefix
    * 3 byte opcode
        * An escape opcode byte 0x0F, plus two additional opcode bytes
        * A mandatory prefix (0x66, 0xF2, 0xF3), an escape code, plus two opcode bytes
        *  `0F 38 <opcode>`
        *  `0F 3A <opcode>`
        * For example: `PHADDW == 66 0F 38 01`
* ModRM: 1 byte of format `(mod << 6) | (reg << 3) | (rm << 0)` [when necessary]
    * mod: 2 bit addressing mode (affects how the registers are interpreted)
        * Combines with the r/m field to form 32 cases: 8 reg and 24 addressing modes
    * reg/opcode: 3 bit register number or opcode extension
        * Purpose of this field chosen by primary opcode information
    * r/m: 3 bit register for number
        * may encode extra opcode information for certian combinations of `r/m` and `mod`
* SIB: 1 byte of format `(scale << 6) | (index << 3) | (base << 0)` [when necessary]
    * Certain encodings of the ModR/M byte require a second addressing byte
    * scale: 2 bit scale factor
    * index: 3 bit the register number of the index register
    * base: 3 bit the register number of the base register
* displacement: 0,1,2, or 4 bytes.  Can be 8 bytes for some specific instructions
    * Used in some addressing forms of ModR/M or SIB byte
* immediate: 0,1,2, or 4 bytes.  Can be 8 bytes for some specific instructions

// REX | OPCODE(0,1,2,3) | ModRM | SIB | displacement(0,1,2,4) | immediate(0,1,2,4)


