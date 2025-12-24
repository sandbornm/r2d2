import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import SelectAllIcon from '@mui/icons-material/SelectAll';
import { alpha, Box, Button, IconButton, Popover, Stack, TextField, Tooltip, Typography, useTheme } from '@mui/material';
import { FC, useCallback, useMemo, useRef, useState } from 'react';

import type { AssemblyAnnotation } from '../types';

interface DisassemblyViewerProps {
  disassembly: string;
  arch?: string;
  annotations?: AssemblyAnnotation[];
  onAnnotate?: (address: string, note: string) => void;
  onAskAbout?: (selectedCode: string) => void;  // For asking Claude about selected code
}

// Instruction category for grouping in search
type InstructionCategory = 'data' | 'load_store' | 'branch' | 'system' | 'simd' | 'crypto' | 'atomic';

interface InstructionDoc {
  desc: string;
  category: InstructionCategory;
  syntax?: string;
  flags?: string;
  example?: string;
}

// ARM instruction documentation (Thumb/ARM32/ARM64) - Enhanced version
const ARM_DOCS_EXTENDED: Record<string, InstructionDoc> = {
  // Data processing
  'mov': { desc: 'Move: Copy value to register', category: 'data', syntax: 'MOV Rd, Op2', example: 'mov r0, #1' },
  'movs': { desc: 'Move with flags update: Copy value and update condition flags', category: 'data', flags: 'NZCV' },
  'movw': { desc: 'Move wide: Load 16-bit immediate into lower halfword', category: 'data', syntax: 'MOVW Rd, #imm16' },
  'movt': { desc: 'Move top: Load 16-bit immediate into upper halfword', category: 'data', syntax: 'MOVT Rd, #imm16' },
  'movk': { desc: 'Move keep: Move 16-bit immediate with optional shift, keeping other bits', category: 'data', syntax: 'MOVK Xd, #imm16, LSL #shift' },
  'movz': { desc: 'Move zero: Move 16-bit immediate with optional shift, zeroing other bits', category: 'data', syntax: 'MOVZ Xd, #imm16, LSL #shift' },
  'movn': { desc: 'Move inverted: Move inverted 16-bit immediate', category: 'data', syntax: 'MOVN Xd, #imm16' },
  'mvn': { desc: 'Move NOT: Copy bitwise complement to register', category: 'data' },
  'add': { desc: 'Add: Rd = Rn + Op2', category: 'data', flags: 'none (use ADDS for flags)', example: 'add x0, x1, x2' },
  'adds': { desc: 'Add with flags: Rd = Rn + Op2, update NZCV flags', category: 'data', flags: 'NZCV' },
  'adc': { desc: 'Add with carry: Rd = Rn + Op2 + Carry', category: 'data' },
  'adcs': { desc: 'Add with carry and set flags', category: 'data', flags: 'NZCV' },
  'sub': { desc: 'Subtract: Rd = Rn - Op2', category: 'data', example: 'sub sp, sp, #16' },
  'subs': { desc: 'Subtract with flags: Rd = Rn - Op2, update NZCV flags', category: 'data', flags: 'NZCV' },
  'sbc': { desc: 'Subtract with carry: Rd = Rn - Op2 - NOT(Carry)', category: 'data' },
  'sbcs': { desc: 'Subtract with carry and set flags', category: 'data', flags: 'NZCV' },
  'rsb': { desc: 'Reverse subtract: Rd = Op2 - Rn', category: 'data' },
  'mul': { desc: 'Multiply: Rd = Rm × Rs (32-bit result)', category: 'data', example: 'mul w0, w1, w2' },
  'madd': { desc: 'Multiply-add: Rd = Ra + (Rn × Rm)', category: 'data', syntax: 'MADD Xd, Xn, Xm, Xa' },
  'msub': { desc: 'Multiply-subtract: Rd = Ra - (Rn × Rm)', category: 'data', syntax: 'MSUB Xd, Xn, Xm, Xa' },
  'mla': { desc: 'Multiply-accumulate: Rd = (Rm × Rs) + Rn', category: 'data' },
  'mls': { desc: 'Multiply-subtract: Rd = Rn - (Rm × Rs)', category: 'data' },
  'umull': { desc: 'Unsigned multiply long: 64-bit = Rm × Rs', category: 'data', syntax: 'UMULL RdLo, RdHi, Rn, Rm' },
  'smull': { desc: 'Signed multiply long: 64-bit = Rm × Rs', category: 'data', syntax: 'SMULL RdLo, RdHi, Rn, Rm' },
  'umulh': { desc: 'Unsigned multiply high: Get high 64 bits of 128-bit multiply', category: 'data' },
  'smulh': { desc: 'Signed multiply high: Get high 64 bits of 128-bit multiply', category: 'data' },
  'sdiv': { desc: 'Signed divide: Rd = Rn / Rm', category: 'data', example: 'sdiv w0, w1, w2' },
  'udiv': { desc: 'Unsigned divide: Rd = Rn / Rm', category: 'data' },
  'and': { desc: 'Bitwise AND: Rd = Rn & Op2', category: 'data', example: 'and x0, x1, #0xff' },
  'ands': { desc: 'Bitwise AND with flags update', category: 'data', flags: 'NZC' },
  'orr': { desc: 'Bitwise OR: Rd = Rn | Op2', category: 'data' },
  'orn': { desc: 'Bitwise OR NOT: Rd = Rn | ~Op2', category: 'data' },
  'eor': { desc: 'Bitwise XOR: Rd = Rn ^ Op2', category: 'data' },
  'eon': { desc: 'Bitwise XOR NOT: Rd = Rn ^ ~Op2', category: 'data' },
  'bic': { desc: 'Bit clear: Rd = Rn & ~Op2', category: 'data' },
  'bics': { desc: 'Bit clear with flags', category: 'data', flags: 'NZC' },
  'lsl': { desc: 'Logical shift left: Rd = Rm << n', category: 'data', example: 'lsl x0, x1, #2' },
  'lslv': { desc: 'Logical shift left variable: Rd = Rn << Rm', category: 'data' },
  'lsr': { desc: 'Logical shift right: Rd = Rm >> n (zero fill)', category: 'data' },
  'lsrv': { desc: 'Logical shift right variable: Rd = Rn >> Rm', category: 'data' },
  'asr': { desc: 'Arithmetic shift right: Rd = Rm >> n (sign extend)', category: 'data' },
  'asrv': { desc: 'Arithmetic shift right variable', category: 'data' },
  'ror': { desc: 'Rotate right: circular shift', category: 'data' },
  'rorv': { desc: 'Rotate right variable', category: 'data' },
  'extr': { desc: 'Extract: Extract register from pair of registers', category: 'data' },
  'cmp': { desc: 'Compare: Update flags based on Rn - Op2 (alias for SUBS with ZR)', category: 'data', flags: 'NZCV' },
  'cmn': { desc: 'Compare negative: Update flags based on Rn + Op2', category: 'data', flags: 'NZCV' },
  'tst': { desc: 'Test bits: Update flags based on Rn & Op2 (alias for ANDS)', category: 'data', flags: 'NZC' },
  'teq': { desc: 'Test equivalence: Update flags based on Rn ^ Op2', category: 'data', flags: 'NZC' },
  'neg': { desc: 'Negate: Rd = 0 - Rm (alias for SUB)', category: 'data' },
  'negs': { desc: 'Negate with flags', category: 'data', flags: 'NZCV' },
  'ngc': { desc: 'Negate with carry: Rd = ~Rm + C', category: 'data' },
  'adr': { desc: 'Address: Load PC-relative address into register (±1MB)', category: 'data' },
  'adrp': { desc: 'Address page: Load PC-relative page address (±4GB)', category: 'data', syntax: 'ADRP Xd, label' },
  'cls': { desc: 'Count leading sign bits', category: 'data' },
  'clz': { desc: 'Count leading zeros', category: 'data' },
  'rbit': { desc: 'Reverse bits', category: 'data' },
  'rev': { desc: 'Reverse bytes (byte swap)', category: 'data' },
  'rev16': { desc: 'Reverse bytes in halfwords', category: 'data' },
  'rev32': { desc: 'Reverse bytes in words (ARM64)', category: 'data' },
  'rev64': { desc: 'Reverse bytes in doubleword', category: 'data' },
  'sxtb': { desc: 'Sign extend byte to 32/64 bits', category: 'data' },
  'sxth': { desc: 'Sign extend halfword to 32/64 bits', category: 'data' },
  'sxtw': { desc: 'Sign extend word to 64 bits', category: 'data' },
  'uxtb': { desc: 'Zero extend byte to 32/64 bits', category: 'data' },
  'uxth': { desc: 'Zero extend halfword to 32/64 bits', category: 'data' },
  'ubfx': { desc: 'Unsigned bitfield extract', category: 'data', syntax: 'UBFX Xd, Xn, #lsb, #width' },
  'sbfx': { desc: 'Signed bitfield extract', category: 'data' },
  'bfi': { desc: 'Bitfield insert', category: 'data', syntax: 'BFI Xd, Xn, #lsb, #width' },
  'bfxil': { desc: 'Bitfield extract and insert low', category: 'data' },
  'csel': { desc: 'Conditional select: Rd = cond ? Rn : Rm', category: 'data', syntax: 'CSEL Xd, Xn, Xm, cond' },
  'csinc': { desc: 'Conditional select increment: Rd = cond ? Rn : Rm+1', category: 'data' },
  'csinv': { desc: 'Conditional select invert: Rd = cond ? Rn : ~Rm', category: 'data' },
  'csneg': { desc: 'Conditional select negate: Rd = cond ? Rn : -Rm', category: 'data' },
  'cset': { desc: 'Conditional set: Rd = cond ? 1 : 0', category: 'data' },
  'csetm': { desc: 'Conditional set mask: Rd = cond ? -1 : 0', category: 'data' },
  'cinc': { desc: 'Conditional increment: Rd = cond ? Rn+1 : Rn', category: 'data' },
  'cinv': { desc: 'Conditional invert: Rd = cond ? ~Rn : Rn', category: 'data' },
  'cneg': { desc: 'Conditional negate: Rd = cond ? -Rn : Rn', category: 'data' },
  'ccmp': { desc: 'Conditional compare: if cond, compare Rn with Op2, else set flags to nzcv', category: 'data' },
  'ccmn': { desc: 'Conditional compare negative', category: 'data' },
  // Load/Store
  'ldr': { desc: 'Load register: Load 32/64-bit value from memory', category: 'load_store', example: 'ldr x0, [x1, #8]' },
  'ldrb': { desc: 'Load register byte: Load 8-bit value, zero-extend', category: 'load_store' },
  'ldrh': { desc: 'Load register halfword: Load 16-bit value, zero-extend', category: 'load_store' },
  'ldrsb': { desc: 'Load register signed byte: Load 8-bit value, sign-extend', category: 'load_store' },
  'ldrsh': { desc: 'Load register signed halfword: Load 16-bit value, sign-extend', category: 'load_store' },
  'ldrsw': { desc: 'Load register signed word: Load 32-bit, sign-extend to 64-bit', category: 'load_store' },
  'ldrd': { desc: 'Load register double: Load 64-bit value to register pair', category: 'load_store' },
  'ldur': { desc: 'Load register unscaled: Load with 9-bit signed offset', category: 'load_store' },
  'ldp': { desc: 'Load pair: Load two registers from consecutive memory', category: 'load_store', syntax: 'LDP Xt1, Xt2, [Xn, #imm]' },
  'ldnp': { desc: 'Load pair non-temporal: Load pair with non-temporal hint', category: 'load_store' },
  'ldar': { desc: 'Load-acquire register: Load with acquire semantics', category: 'load_store' },
  'ldaxr': { desc: 'Load-acquire exclusive: Load exclusive with acquire', category: 'load_store' },
  'ldxr': { desc: 'Load exclusive: Load value for exclusive access', category: 'load_store' },
  'ldm': { desc: 'Load multiple: Pop multiple registers from memory', category: 'load_store' },
  'ldmia': { desc: 'Load multiple increment after: Pop registers, increment base', category: 'load_store' },
  'ldmdb': { desc: 'Load multiple decrement before: Pop registers, decrement base', category: 'load_store' },
  'str': { desc: 'Store register: Store 32/64-bit value to memory', category: 'load_store', example: 'str x0, [sp, #-16]!' },
  'strb': { desc: 'Store register byte: Store 8-bit value', category: 'load_store' },
  'strh': { desc: 'Store register halfword: Store 16-bit value', category: 'load_store' },
  'strd': { desc: 'Store register double: Store 64-bit value from register pair', category: 'load_store' },
  'stur': { desc: 'Store register unscaled: Store with 9-bit signed offset', category: 'load_store' },
  'stp': { desc: 'Store pair: Store two registers to consecutive memory', category: 'load_store', syntax: 'STP Xt1, Xt2, [Xn, #imm]' },
  'stnp': { desc: 'Store pair non-temporal: Store pair with non-temporal hint', category: 'load_store' },
  'stlr': { desc: 'Store-release register: Store with release semantics', category: 'load_store' },
  'stlxr': { desc: 'Store-release exclusive: Store exclusive with release', category: 'load_store' },
  'stxr': { desc: 'Store exclusive: Store value with exclusive access', category: 'load_store' },
  'stm': { desc: 'Store multiple: Push multiple registers to memory', category: 'load_store' },
  'stmia': { desc: 'Store multiple increment after: Push registers, increment base', category: 'load_store' },
  'stmdb': { desc: 'Store multiple decrement before (PUSH): Push registers, decrement base', category: 'load_store' },
  'push': { desc: 'Push registers onto stack: SP -= 4×n, store registers', category: 'load_store' },
  'pop': { desc: 'Pop registers from stack: Load registers, SP += 4×n', category: 'load_store' },
  'prfm': { desc: 'Prefetch memory: Hint to cache controller', category: 'load_store', syntax: 'PRFM type, [Xn]' },
  // Branch
  'b': { desc: 'Branch: Unconditional jump to label (±128MB)', category: 'branch', example: 'b label' },
  'br': { desc: 'Branch to register: Jump to address in register', category: 'branch', syntax: 'BR Xn' },
  'bl': { desc: 'Branch with link: Call subroutine, save return address in LR (X30)', category: 'branch', example: 'bl printf' },
  'blr': { desc: 'Branch with link to register: Call address in register', category: 'branch', syntax: 'BLR Xn' },
  'blx': { desc: 'Branch with link and exchange: Call with possible mode switch (ARM↔Thumb)', category: 'branch' },
  'bx': { desc: 'Branch and exchange: Jump with possible mode switch', category: 'branch' },
  'ret': { desc: 'Return from subroutine: Branch to LR (X30)', category: 'branch', syntax: 'RET {Xn}' },
  'beq': { desc: 'Branch if equal: Jump if Z flag set', category: 'branch', flags: 'checks Z' },
  'bne': { desc: 'Branch if not equal: Jump if Z flag clear', category: 'branch', flags: 'checks Z' },
  'bgt': { desc: 'Branch if greater than (signed): Jump if Z=0 and N=V', category: 'branch' },
  'bge': { desc: 'Branch if greater or equal (signed): Jump if N=V', category: 'branch' },
  'blt': { desc: 'Branch if less than (signed): Jump if N≠V', category: 'branch' },
  'ble': { desc: 'Branch if less or equal (signed): Jump if Z=1 or N≠V', category: 'branch' },
  'bhi': { desc: 'Branch if higher (unsigned): Jump if C=1 and Z=0', category: 'branch' },
  'bhs': { desc: 'Branch if higher or same (unsigned): Jump if C=1', category: 'branch' },
  'blo': { desc: 'Branch if lower (unsigned): Jump if C=0', category: 'branch' },
  'bls': { desc: 'Branch if lower or same (unsigned): Jump if C=0 or Z=1', category: 'branch' },
  'bcs': { desc: 'Branch if carry set: Jump if C flag set', category: 'branch' },
  'bcc': { desc: 'Branch if carry clear: Jump if C flag clear', category: 'branch' },
  'bmi': { desc: 'Branch if minus: Jump if N flag set', category: 'branch' },
  'bpl': { desc: 'Branch if plus: Jump if N flag clear', category: 'branch' },
  'bvs': { desc: 'Branch if overflow set: Jump if V flag set', category: 'branch' },
  'bvc': { desc: 'Branch if overflow clear: Jump if V flag clear', category: 'branch' },
  'bal': { desc: 'Branch always: Unconditional branch (explicit)', category: 'branch' },
  'cbz': { desc: 'Compare and branch if zero: if Rn == 0, branch', category: 'branch', syntax: 'CBZ Xn, label' },
  'cbnz': { desc: 'Compare and branch if not zero: if Rn != 0, branch', category: 'branch', syntax: 'CBNZ Xn, label' },
  'tbz': { desc: 'Test bit and branch if zero: if bit #imm of Xn is 0, branch', category: 'branch' },
  'tbnz': { desc: 'Test bit and branch if not zero', category: 'branch' },
  'it': { desc: 'If-Then: Make following 1-4 instructions conditional', category: 'branch' },
  'ite': { desc: 'If-Then-Else: Conditional block with else clause', category: 'branch' },
  'itttt': { desc: 'If-Then-Then-Then-Then: 4 conditional instructions', category: 'branch' },
  // System
  'svc': { desc: 'Supervisor call: Trigger system call exception (syscall #imm)', category: 'system', syntax: 'SVC #imm', example: 'svc #0' },
  'swi': { desc: 'Software interrupt: Trigger system call (legacy name for SVC)', category: 'system' },
  'hvc': { desc: 'Hypervisor call: Call hypervisor from EL1', category: 'system' },
  'smc': { desc: 'Secure monitor call: Call secure monitor from EL1/EL2', category: 'system' },
  'brk': { desc: 'Breakpoint: Trigger debug exception with immediate', category: 'system', syntax: 'BRK #imm' },
  'bkpt': { desc: 'Breakpoint: Trigger debug exception', category: 'system' },
  'hlt': { desc: 'Halt: Stop execution (debug)', category: 'system' },
  'nop': { desc: 'No operation: Do nothing (often MOV r0, r0)', category: 'system' },
  'hint': { desc: 'Hint instruction: Various system hints', category: 'system' },
  'wfi': { desc: 'Wait for interrupt: Enter low-power state until interrupt', category: 'system' },
  'wfe': { desc: 'Wait for event: Enter low-power state until event', category: 'system' },
  'sev': { desc: 'Send event: Signal other cores', category: 'system' },
  'sevl': { desc: 'Send event local: Signal local event register', category: 'system' },
  'yield': { desc: 'Yield: Hint that thread can be rescheduled', category: 'system' },
  'dmb': { desc: 'Data memory barrier: Ensure memory access ordering', category: 'system', syntax: 'DMB option' },
  'dsb': { desc: 'Data synchronization barrier: Complete all memory accesses', category: 'system' },
  'isb': { desc: 'Instruction synchronization barrier: Flush pipeline', category: 'system' },
  'mrs': { desc: 'Move to register from special: Read system register', category: 'system', syntax: 'MRS Xt, sysreg' },
  'msr': { desc: 'Move to special from register: Write system register', category: 'system', syntax: 'MSR sysreg, Xt' },
  'dc': { desc: 'Data cache operation', category: 'system', syntax: 'DC op, Xt' },
  'ic': { desc: 'Instruction cache operation', category: 'system', syntax: 'IC op, Xt' },
  'tlbi': { desc: 'TLB invalidate', category: 'system' },
  'at': { desc: 'Address translate', category: 'system' },
  'sys': { desc: 'System instruction', category: 'system' },
  'sysl': { desc: 'System instruction with result', category: 'system' },
  'eret': { desc: 'Exception return: Return from exception handler', category: 'system' },
  // SIMD/VFP (NEON)
  'fmov': { desc: 'Floating-point move: Move between FP and GP registers', category: 'simd' },
  'fadd': { desc: 'Floating-point add', category: 'simd' },
  'fsub': { desc: 'Floating-point subtract', category: 'simd' },
  'fmul': { desc: 'Floating-point multiply', category: 'simd' },
  'fdiv': { desc: 'Floating-point divide', category: 'simd' },
  'fmadd': { desc: 'Floating-point fused multiply-add: Fd = Fa + (Fn × Fm)', category: 'simd' },
  'fmsub': { desc: 'Floating-point fused multiply-subtract', category: 'simd' },
  'fneg': { desc: 'Floating-point negate', category: 'simd' },
  'fabs': { desc: 'Floating-point absolute value', category: 'simd' },
  'fsqrt': { desc: 'Floating-point square root', category: 'simd' },
  'fcmp': { desc: 'Floating-point compare: Set NZCV flags', category: 'simd', flags: 'NZCV' },
  'fcmpe': { desc: 'Floating-point compare with exception on NaN', category: 'simd' },
  'fcsel': { desc: 'Floating-point conditional select', category: 'simd' },
  'fccmp': { desc: 'Floating-point conditional compare', category: 'simd' },
  'fcvt': { desc: 'Floating-point convert precision', category: 'simd' },
  'fcvtzs': { desc: 'Floating-point convert to signed integer, round toward zero', category: 'simd' },
  'fcvtzu': { desc: 'Floating-point convert to unsigned integer, round toward zero', category: 'simd' },
  'scvtf': { desc: 'Signed integer convert to floating-point', category: 'simd' },
  'ucvtf': { desc: 'Unsigned integer convert to floating-point', category: 'simd' },
  'frintz': { desc: 'Floating-point round toward zero', category: 'simd' },
  'frintp': { desc: 'Floating-point round toward +infinity', category: 'simd' },
  'frintm': { desc: 'Floating-point round toward -infinity', category: 'simd' },
  'frinta': { desc: 'Floating-point round to nearest with ties away', category: 'simd' },
  'vmov': { desc: 'Vector move: Move data between ARM and VFP/NEON registers', category: 'simd' },
  'vldr': { desc: 'Vector load: Load floating-point register from memory', category: 'simd' },
  'vstr': { desc: 'Vector store: Store floating-point register to memory', category: 'simd' },
  'vadd': { desc: 'Vector add: Floating-point addition', category: 'simd' },
  'vsub': { desc: 'Vector subtract: Floating-point subtraction', category: 'simd' },
  'vmul': { desc: 'Vector multiply: Floating-point multiplication', category: 'simd' },
  'vdiv': { desc: 'Vector divide: Floating-point division', category: 'simd' },
  'vcmp': { desc: 'Vector compare: Compare floating-point values', category: 'simd' },
  'ld1': { desc: 'Load single structure: Load 1-4 registers from memory', category: 'simd' },
  'ld2': { desc: 'Load 2-element structure with de-interleave', category: 'simd' },
  'ld3': { desc: 'Load 3-element structure with de-interleave', category: 'simd' },
  'ld4': { desc: 'Load 4-element structure with de-interleave', category: 'simd' },
  'st1': { desc: 'Store single structure: Store 1-4 registers to memory', category: 'simd' },
  'st2': { desc: 'Store 2-element structure with interleave', category: 'simd' },
  'st3': { desc: 'Store 3-element structure with interleave', category: 'simd' },
  'st4': { desc: 'Store 4-element structure with interleave', category: 'simd' },
  'dup': { desc: 'Duplicate: Broadcast element to all lanes', category: 'simd' },
  'ins': { desc: 'Insert: Copy element from GP or vector register', category: 'simd' },
  'umov': { desc: 'Unsigned move: Copy element to GP register', category: 'simd' },
  'smov': { desc: 'Signed move: Copy element with sign extension', category: 'simd' },
  // Atomic operations (ARM64)
  'ldadd': { desc: 'Atomic add: [Xn] = [Xn] + Xs, return old value', category: 'atomic' },
  'ldadda': { desc: 'Atomic add with acquire', category: 'atomic' },
  'ldaddl': { desc: 'Atomic add with release', category: 'atomic' },
  'ldaddal': { desc: 'Atomic add with acquire-release', category: 'atomic' },
  'stadd': { desc: 'Atomic store add: [Xn] = [Xn] + Xs (no return)', category: 'atomic' },
  'ldclr': { desc: 'Atomic bit clear: [Xn] = [Xn] & ~Xs', category: 'atomic' },
  'ldset': { desc: 'Atomic bit set: [Xn] = [Xn] | Xs', category: 'atomic' },
  'ldeor': { desc: 'Atomic XOR: [Xn] = [Xn] ^ Xs', category: 'atomic' },
  'ldmax': { desc: 'Atomic signed maximum', category: 'atomic' },
  'ldmin': { desc: 'Atomic signed minimum', category: 'atomic' },
  'ldumax': { desc: 'Atomic unsigned maximum', category: 'atomic' },
  'ldumin': { desc: 'Atomic unsigned minimum', category: 'atomic' },
  'swp': { desc: 'Swap: Atomically swap register with memory', category: 'atomic' },
  'swpa': { desc: 'Swap with acquire', category: 'atomic' },
  'swpl': { desc: 'Swap with release', category: 'atomic' },
  'swpal': { desc: 'Swap with acquire-release', category: 'atomic' },
  'cas': { desc: 'Compare and swap: If [Xn] == Xs, [Xn] = Xt', category: 'atomic' },
  'casa': { desc: 'Compare and swap with acquire', category: 'atomic' },
  'casl': { desc: 'Compare and swap with release', category: 'atomic' },
  'casal': { desc: 'Compare and swap with acquire-release', category: 'atomic' },
  'casp': { desc: 'Compare and swap pair', category: 'atomic' },
  // Crypto extensions
  'aese': { desc: 'AES single round encryption', category: 'crypto' },
  'aesd': { desc: 'AES single round decryption', category: 'crypto' },
  'aesmc': { desc: 'AES mix columns', category: 'crypto' },
  'aesimc': { desc: 'AES inverse mix columns', category: 'crypto' },
  'sha1c': { desc: 'SHA1 hash update (choose)', category: 'crypto' },
  'sha1m': { desc: 'SHA1 hash update (majority)', category: 'crypto' },
  'sha1p': { desc: 'SHA1 hash update (parity)', category: 'crypto' },
  'sha1h': { desc: 'SHA1 fixed rotate', category: 'crypto' },
  'sha1su0': { desc: 'SHA1 schedule update 0', category: 'crypto' },
  'sha1su1': { desc: 'SHA1 schedule update 1', category: 'crypto' },
  'sha256h': { desc: 'SHA256 hash update part 1', category: 'crypto' },
  'sha256h2': { desc: 'SHA256 hash update part 2', category: 'crypto' },
  'sha256su0': { desc: 'SHA256 schedule update 0', category: 'crypto' },
  'sha256su1': { desc: 'SHA256 schedule update 1', category: 'crypto' },
  // Thumb-2 specific
  'ldr.w': { desc: 'Load register wide: 32-bit Thumb-2 LDR encoding', category: 'load_store' },
  'str.w': { desc: 'Store register wide: 32-bit Thumb-2 STR encoding', category: 'load_store' },
  'add.w': { desc: 'Add wide: 32-bit Thumb-2 ADD encoding', category: 'data' },
};

// Simple lookup map for backward compatibility
const ARM_DOCS: Record<string, string> = Object.fromEntries(
  Object.entries(ARM_DOCS_EXTENDED).map(([k, v]) => [k, v.desc])
);

// x86/x64 instruction documentation
const X86_DOCS: Record<string, string> = {
  // Data movement
  'mov': 'Move: Copy source to destination',
  'movzx': 'Move with zero-extend: Copy and zero-extend to larger size',
  'movsx': 'Move with sign-extend: Copy and sign-extend to larger size',
  'movsxd': 'Move with sign-extend doubleword: Sign-extend 32-bit to 64-bit',
  'movabs': 'Move absolute: Load 64-bit immediate (x64)',
  'lea': 'Load effective address: Calculate address without dereferencing',
  'push': 'Push onto stack: Decrement SP, store value',
  'pop': 'Pop from stack: Load value, increment SP',
  'xchg': 'Exchange: Swap two operands atomically',
  'cmov': 'Conditional move: Move if condition is met',
  'cmove': 'Conditional move if equal: Move if ZF=1',
  'cmovne': 'Conditional move if not equal: Move if ZF=0',
  'cmovg': 'Conditional move if greater (signed)',
  'cmovl': 'Conditional move if less (signed)',
  // Arithmetic
  'add': 'Add: dest = dest + src',
  'sub': 'Subtract: dest = dest - src',
  'imul': 'Signed multiply: Signed integer multiplication',
  'mul': 'Unsigned multiply: Unsigned integer multiplication',
  'idiv': 'Signed divide: Signed integer division',
  'div': 'Unsigned divide: Unsigned integer division',
  'inc': 'Increment: dest = dest + 1',
  'dec': 'Decrement: dest = dest - 1',
  'neg': 'Negate: dest = -dest (two\'s complement)',
  'adc': 'Add with carry: dest = dest + src + CF',
  'sbb': 'Subtract with borrow: dest = dest - src - CF',
  // Logic
  'and': 'Bitwise AND: dest = dest & src',
  'or': 'Bitwise OR: dest = dest | src',
  'xor': 'Bitwise XOR: dest = dest ^ src',
  'not': 'Bitwise NOT: dest = ~dest',
  'shl': 'Shift left: dest = dest << count',
  'shr': 'Shift right logical: dest = dest >> count (zero fill)',
  'sar': 'Shift right arithmetic: dest = dest >> count (sign fill)',
  'rol': 'Rotate left: Circular shift left',
  'ror': 'Rotate right: Circular shift right',
  // Compare/Test
  'cmp': 'Compare: Set flags based on dest - src',
  'test': 'Test bits: Set flags based on dest & src',
  // Control flow
  'jmp': 'Jump: Unconditional jump to address',
  'call': 'Call: Push return address, jump to function',
  'ret': 'Return: Pop return address, jump to it',
  'je': 'Jump if equal: Jump if ZF=1',
  'jne': 'Jump if not equal: Jump if ZF=0',
  'jz': 'Jump if zero: Jump if ZF=1 (same as JE)',
  'jnz': 'Jump if not zero: Jump if ZF=0 (same as JNE)',
  'jg': 'Jump if greater (signed): ZF=0 and SF=OF',
  'jge': 'Jump if greater or equal (signed): SF=OF',
  'jl': 'Jump if less (signed): SF≠OF',
  'jle': 'Jump if less or equal (signed): ZF=1 or SF≠OF',
  'ja': 'Jump if above (unsigned): CF=0 and ZF=0',
  'jae': 'Jump if above or equal (unsigned): CF=0',
  'jb': 'Jump if below (unsigned): CF=1',
  'jbe': 'Jump if below or equal (unsigned): CF=1 or ZF=1',
  'js': 'Jump if sign (negative): SF=1',
  'jns': 'Jump if not sign (positive): SF=0',
  'jo': 'Jump if overflow: OF=1',
  'jno': 'Jump if not overflow: OF=0',
  // Stack frame
  'enter': 'Make stack frame: Push BP, BP=SP, allocate locals',
  'leave': 'Destroy stack frame: SP=BP, pop BP',
  // String ops
  'rep': 'Repeat prefix: Repeat following instruction CX times',
  'movsb': 'Move string byte: Copy byte from [SI] to [DI]',
  'stosb': 'Store string byte: Store AL at [DI]',
  'lodsb': 'Load string byte: Load [SI] into AL',
  'cmpsb': 'Compare string bytes: Compare [SI] with [DI]',
  'scasb': 'Scan string byte: Compare AL with [DI]',
  // System
  'syscall': 'System call: Invoke OS kernel (x64)',
  'int': 'Interrupt: Trigger software interrupt',
  'nop': 'No operation: Do nothing',
  'hlt': 'Halt: Stop execution until interrupt',
  'cpuid': 'CPU identification: Query processor info',
  'rdtsc': 'Read timestamp counter: Get cycle count',
  // SSE/AVX
  'movss': 'Move scalar single: Move 32-bit float',
  'movsd': 'Move scalar double: Move 64-bit float',
  'movaps': 'Move aligned packed single: Move 128-bit aligned',
  'movups': 'Move unaligned packed single: Move 128-bit unaligned',
  'addss': 'Add scalar single: Float addition',
  'subss': 'Subtract scalar single: Float subtraction',
  'mulss': 'Multiply scalar single: Float multiplication',
  'divss': 'Divide scalar single: Float division',
  'xorps': 'XOR packed single: Bitwise XOR on 128-bit',
  'pxor': 'Packed XOR: Bitwise XOR on packed integers',
  'endbr64': 'End branch 64: CET indirect branch tracking marker',
  'endbr32': 'End branch 32: CET indirect branch tracking marker',
};

// Get instruction docs based on architecture - returns extended info
const getInstructionDocsExtended = (mnemonic: string, arch: string): InstructionDoc | null => {
  const normalizedMnemonic = mnemonic.toLowerCase().replace(/\.w$/, '');

  // Check for conditional suffixes on ARM
  if (arch.includes('arm') || arch.includes('thumb') || arch.includes('aarch64')) {
    // Strip condition codes for lookup
    const armBase = normalizedMnemonic.replace(/(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|hs|lo)$/, '');
    if (ARM_DOCS_EXTENDED[normalizedMnemonic]) return ARM_DOCS_EXTENDED[normalizedMnemonic];
    if (ARM_DOCS_EXTENDED[armBase]) return ARM_DOCS_EXTENDED[armBase];
  }

  // x86 uses simple docs for now
  if (arch.includes('x86') || arch.includes('amd64') || arch.includes('i386')) {
    if (X86_DOCS[normalizedMnemonic]) {
      return { desc: X86_DOCS[normalizedMnemonic], category: 'data' };
    }
  }

  // Fallback: check ARM then x86
  if (ARM_DOCS_EXTENDED[normalizedMnemonic]) return ARM_DOCS_EXTENDED[normalizedMnemonic];
  if (X86_DOCS[normalizedMnemonic]) return { desc: X86_DOCS[normalizedMnemonic], category: 'data' };

  return null;
};

// Simple string lookup for backward compatibility
const getInstructionDocs = (mnemonic: string, arch: string): string | null => {
  const extended = getInstructionDocsExtended(mnemonic, arch);
  return extended?.desc ?? null;
};

// Category display names and colors
const CATEGORY_INFO: Record<InstructionCategory, { label: string; color: string }> = {
  data: { label: 'Data Processing', color: '#9c27b0' },
  load_store: { label: 'Load/Store', color: '#2196f3' },
  branch: { label: 'Branch', color: '#4caf50' },
  system: { label: 'System', color: '#ff9800' },
  simd: { label: 'SIMD/FPU', color: '#00bcd4' },
  crypto: { label: 'Crypto', color: '#e91e63' },
  atomic: { label: 'Atomic', color: '#673ab7' },
};

interface ParsedInstruction {
  address?: string;
  bytes?: string;
  mnemonic?: string;
  operands?: string;
  comment?: string;
  raw: string;
  isLabel?: boolean;
  isComment?: boolean;
  isEmpty?: boolean;
}

// Parse a single line of radare2 disassembly
const parseDisasmLine = (line: string): ParsedInstruction => {
  const trimmed = line.trimEnd();
  
  // Empty line
  if (!trimmed) {
    return { raw: line, isEmpty: true };
  }
  
  // Pure comment line (starts with ; after optional whitespace)
  if (/^\s*;/.test(trimmed)) {
    return { raw: line, isComment: true, comment: trimmed };
  }
  
  // Label line (ends with : and has no instruction)
  if (/^\s*\w+:$/.test(trimmed) || /^[│├└─\s]*;--\s*\w+:?/.test(trimmed)) {
    return { raw: line, isLabel: true };
  }
  
  // Try to parse standard radare2 format: 
  // │ │ 0x000003fc 4ff0000b mov.w fp, 0 ; [13] -r-x section...
  // or simpler: 0x000003fc 4ff0000b mov.w fp, 0
  
  const patterns = [
    // Full r2 format with tree chars
    /^([│├└─\s]*)\s*(0x[0-9a-f]+)\s+([0-9a-f]+)\s+(\w+(?:\.\w+)?)\s*([^;]*)?(?:;\s*(.*))?$/i,
    // Simple format
    /^\s*(0x[0-9a-f]+):\s*([0-9a-f]+)\s+(\w+(?:\.\w+)?)\s*([^;]*)?(?:;\s*(.*))?$/i,
    // Another common format
    /^\s*(0x[0-9a-f]+)\s+(\w+(?:\.\w+)?)\s*([^;]*)?(?:;\s*(.*))?$/i,
  ];
  
  for (const pattern of patterns) {
    const match = trimmed.match(pattern);
    if (match) {
      if (pattern === patterns[0]) {
        return {
          raw: line,
          address: match[2],
          bytes: match[3],
          mnemonic: match[4],
          operands: match[5]?.trim(),
          comment: match[6],
        };
      } else if (pattern === patterns[1]) {
        return {
          raw: line,
          address: match[1],
          bytes: match[2],
          mnemonic: match[3],
          operands: match[4]?.trim(),
          comment: match[5],
        };
      } else {
        return {
          raw: line,
          address: match[1],
          mnemonic: match[2],
          operands: match[3]?.trim(),
          comment: match[4],
        };
      }
    }
  }
  
  // Fallback: treat as raw line
  return { raw: line };
};

// Build ARM documentation URL - uses official ARM Developer docs
// Reference: https://developer.arm.com/documentation/dui0489/h/arm-and-thumb-instructions/instruction-summary
const getARMDocUrl = (mnemonic: string): string => {
  const cleanMnemonic = mnemonic.toLowerCase().replace(/\.w$/, '').replace(/(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|hs|lo)$/, '');
  // ARM Developer documentation - Thumb/ARM instruction reference
  // The URL pattern depends on the instruction category
  return `https://developer.arm.com/documentation/dui0489/h/arm-and-thumb-instructions/${cleanMnemonic.toUpperCase()}`;
};

// Alternative ARM doc URL for search fallback
const getARMSearchUrl = (mnemonic: string): string => {
  const cleanMnemonic = mnemonic.toLowerCase().replace(/\.w$/, '');
  return `https://developer.arm.com/search#q=${encodeURIComponent(cleanMnemonic + ' instruction')}&sort=relevancy`;
};

// Build x86 documentation URL
const getX86DocUrl = (mnemonic: string): string => {
  const cleanMnemonic = mnemonic.toLowerCase();
  // Use Felix Cloutier's x86 reference (community standard)
  return `https://www.felixcloutier.com/x86/${cleanMnemonic}`;
};

interface InstructionLineProps {
  parsed: ParsedInstruction;
  arch: string;
  annotation?: string;
}

const InstructionLine: FC<InstructionLineProps> = ({ parsed, arch, annotation }) => {
  const theme = useTheme();
  const [hovered, setHovered] = useState(false);
  
  const isDark = theme.palette.mode === 'dark';
  
  // Colors for syntax highlighting
  const colors = {
    address: isDark ? '#6a9fb5' : '#0550ae',
    bytes: isDark ? '#555' : '#999',
    mnemonic: isDark ? '#b294bb' : '#a626a4',
    register: isDark ? '#cc6666' : '#c18401',
    immediate: isDark ? '#8abeb7' : '#0184bc',
    memory: isDark ? '#f0c674' : '#50a14f',
    comment: isDark ? '#5a5a5a' : '#a0a0a0',
    label: isDark ? '#81a2be' : '#4078f2',
    tree: isDark ? '#333' : '#ddd',
  };
  
  // Get instruction documentation (extended version for rich tooltips)
  const docs = parsed.mnemonic ? getInstructionDocs(parsed.mnemonic, arch) : null;
  const extendedDocs = parsed.mnemonic ? getInstructionDocsExtended(parsed.mnemonic, arch) : null;
  
  // Highlight operands (registers, immediates, memory refs)
  const highlightOperands = useCallback((operands: string) => {
    if (!operands) return null;
    
    const parts: JSX.Element[] = [];
    let key = 0;
    
    // Split by common delimiters while preserving them
    const tokens = operands.split(/(\s+|,|\[|\]|\{|\})/);
    
    for (const token of tokens) {
      if (!token) continue;
      
      // Register patterns
      if (/^(r\d+|sp|lr|pc|fp|ip|sl|sb|[re]?[abcd]x|[re]?[sd]i|[re]?bp|[re]?sp|r\d{1,2}[dwb]?|[xy]mm\d+|zmm\d+)$/i.test(token)) {
        parts.push(<span key={key++} style={{ color: colors.register }}>{token}</span>);
      }
      // Immediate values (hex or decimal)
      else if (/^#?-?0x[0-9a-f]+$/i.test(token) || /^#?-?\d+$/.test(token)) {
        parts.push(<span key={key++} style={{ color: colors.immediate }}>{token}</span>);
      }
      // Memory brackets
      else if (token === '[' || token === ']') {
        parts.push(<span key={key++} style={{ color: colors.memory }}>{token}</span>);
      }
      // Everything else
      else {
        parts.push(<span key={key++}>{token}</span>);
      }
    }
    
    return parts;
  }, [colors]);
  
  // Handle special line types
  if (parsed.isEmpty) {
    return <Box sx={{ height: '1.4em' }} />;
  }
  
  if (parsed.isComment) {
    return (
      <Box sx={{ color: colors.comment, fontStyle: 'italic' }}>
        {parsed.raw}
      </Box>
    );
  }
  
  if (parsed.isLabel) {
    return (
      <Box sx={{ color: colors.label, fontWeight: 600 }}>
        {parsed.raw}
      </Box>
    );
  }
  
  // If we couldn't parse it, check for tree characters and try to extract
  if (!parsed.mnemonic) {
    // Still try to colorize any recognizable parts
    const treeMatch = parsed.raw.match(/^([│├└─\s]*)(.*)/);
    if (treeMatch && treeMatch[1]) {
      return (
        <Box>
          <span style={{ color: colors.tree }}>{treeMatch[1]}</span>
          <span>{treeMatch[2]}</span>
        </Box>
      );
    }
    return <Box>{parsed.raw}</Box>;
  }
  
  // Render parsed instruction with syntax highlighting
  const instructionContent = (
    <Box
      component="span"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      sx={{
        display: 'inline-flex',
        alignItems: 'baseline',
        gap: '1ch',
        cursor: docs ? 'help' : 'default',
        backgroundColor: hovered && docs ? (isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.03)') : 'transparent',
        borderRadius: 0.5,
        px: hovered && docs ? 0.5 : 0,
        mx: hovered && docs ? -0.5 : 0,
        transition: 'background-color 0.15s',
      }}
    >
      {/* Address */}
      {parsed.address && (
        <span style={{ color: colors.address, minWidth: '10ch' }}>{parsed.address}</span>
      )}
      
      {/* Bytes */}
      {parsed.bytes && (
        <span style={{ color: colors.bytes, minWidth: '8ch', fontSize: '0.9em' }}>{parsed.bytes}</span>
      )}
      
      {/* Mnemonic */}
      <span style={{ color: colors.mnemonic, fontWeight: 500, minWidth: '6ch' }}>
        {parsed.mnemonic}
      </span>
      
      {/* Operands */}
      {parsed.operands && (
        <span style={{ minWidth: '20ch' }}>
          {highlightOperands(parsed.operands)}
        </span>
      )}
      
      {/* Comment */}
      {parsed.comment && (
        <span style={{ color: colors.comment, marginLeft: '2ch' }}>
          ; {parsed.comment}
        </span>
      )}
    </Box>
  );
  
  // Build documentation URL based on architecture
  const isARM = arch.includes('arm') || arch.includes('thumb');
  const isX86 = arch.includes('x86') || arch.includes('amd64') || arch.includes('i386');
  const docUrl = parsed.mnemonic 
    ? (isARM ? getARMDocUrl(parsed.mnemonic) : isX86 ? getX86DocUrl(parsed.mnemonic) : null)
    : null;

  // Wrap with tooltip if we have docs
  if (docs && extendedDocs) {
    const categoryInfo = CATEGORY_INFO[extendedDocs.category];
    return (
      <Tooltip
        title={
          <Box sx={{ maxWidth: 420, p: 0.5 }}>
            {/* Header with mnemonic and category badge */}
            <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={1} sx={{ mb: 0.5 }}>
              <Stack direction="row" alignItems="center" spacing={1}>
                <Typography variant="subtitle2" fontWeight={700} sx={{ fontFamily: 'monospace', fontSize: '0.95rem' }}>
                  {parsed.mnemonic?.toUpperCase()}
                </Typography>
                <Box
                  sx={{
                    px: 0.75,
                    py: 0.125,
                    borderRadius: 0.5,
                    bgcolor: categoryInfo.color,
                    color: '#fff',
                    fontSize: '0.6rem',
                    fontWeight: 600,
                    textTransform: 'uppercase',
                    letterSpacing: '0.5px',
                  }}
                >
                  {categoryInfo.label}
                </Box>
              </Stack>
              {docUrl && (
                <Tooltip title="Look up in official docs">
                  <IconButton
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      window.open(docUrl, '_blank', 'noopener');
                    }}
                    sx={{ p: 0.25, color: 'primary.light' }}
                  >
                    <OpenInNewIcon sx={{ fontSize: 14 }} />
                  </IconButton>
                </Tooltip>
              )}
            </Stack>

            {/* Description */}
            <Typography variant="body2" sx={{ mb: 0.75, lineHeight: 1.4 }}>
              {docs}
            </Typography>

            {/* Syntax if available */}
            {extendedDocs.syntax && (
              <Box sx={{ mb: 0.5 }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Syntax:
                </Typography>
                <Typography
                  variant="body2"
                  sx={{
                    fontFamily: 'monospace',
                    fontSize: '0.75rem',
                    bgcolor: 'rgba(0,0,0,0.15)',
                    px: 0.75,
                    py: 0.25,
                    borderRadius: 0.5,
                    display: 'inline-block',
                    ml: 0.5,
                  }}
                >
                  {extendedDocs.syntax}
                </Typography>
              </Box>
            )}

            {/* Flags if available */}
            {extendedDocs.flags && (
              <Box sx={{ mb: 0.5 }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Flags:
                </Typography>
                <Typography
                  variant="caption"
                  sx={{
                    ml: 0.5,
                    color: 'warning.light',
                  }}
                >
                  {extendedDocs.flags}
                </Typography>
              </Box>
            )}

            {/* Example if available */}
            {extendedDocs.example && (
              <Box sx={{ mt: 0.5, pt: 0.5, borderTop: '1px solid rgba(255,255,255,0.1)' }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Example:
                </Typography>
                <Typography
                  variant="body2"
                  sx={{
                    fontFamily: 'monospace',
                    fontSize: '0.75rem',
                    color: 'success.light',
                    ml: 0.5,
                  }}
                >
                  {extendedDocs.example}
                </Typography>
              </Box>
            )}

            {isARM && (
              <Typography variant="caption" color="text.secondary" sx={{ mt: 0.75, display: 'block', fontStyle: 'italic', fontSize: '0.65rem' }}>
                Click icon for ARM reference manual
              </Typography>
            )}
          </Box>
        }
        placement="right"
        arrow
        enterDelay={150}
        leaveDelay={50}
      >
        <Box 
          component="div" 
          sx={{ 
            display: 'flex', 
            alignItems: 'center',
            gap: 1,
          }}
        >
          {instructionContent}
          {annotation && (
            <Typography 
              variant="caption" 
              sx={{ 
                color: 'warning.main', 
                fontStyle: 'italic',
                fontSize: '0.7rem',
                ml: 1,
              }}
            >
              📝 {annotation}
            </Typography>
          )}
        </Box>
      </Tooltip>
    );
  }
  
  return (
    <Box 
      sx={{ 
        display: 'flex', 
        alignItems: 'center',
        gap: 1,
      }}
    >
      {instructionContent}
      {annotation && (
        <Typography 
          variant="caption" 
          sx={{ 
            color: 'warning.main', 
            fontStyle: 'italic',
            fontSize: '0.7rem',
            ml: 1,
          }}
        >
          📝 {annotation}
        </Typography>
      )}
    </Box>
  );
};

const DisassemblyViewer: FC<DisassemblyViewerProps> = ({ 
  disassembly, 
  arch = 'unknown',
  annotations = [],
  onAnnotate,
  onAskAbout,
}) => {
  const theme = useTheme();
  const [copied, setCopied] = useState(false);
  const [selectionStart, setSelectionStart] = useState<number | null>(null);
  const [selectionEnd, setSelectionEnd] = useState<number | null>(null);
  const [isSelecting, setIsSelecting] = useState(false);
  const [selectionPopoverAnchor, setSelectionPopoverAnchor] = useState<HTMLElement | null>(null);
  const [rangeAnnotationText, setRangeAnnotationText] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);
  
  const lines = useMemo(() => {
    return disassembly.split('\n').map(parseDisasmLine);
  }, [disassembly]);

  // Build annotation lookup map
  const annotationMap = useMemo(() => {
    const map: Record<string, string> = {};
    for (const ann of annotations) {
      map[ann.address] = ann.note;
    }
    return map;
  }, [annotations]);

  // Get selected lines
  const selectedLines = useMemo(() => {
    if (selectionStart === null || selectionEnd === null) return [];
    const start = Math.min(selectionStart, selectionEnd);
    const end = Math.max(selectionStart, selectionEnd);
    return lines.slice(start, end + 1);
  }, [lines, selectionStart, selectionEnd]);

  const selectedText = useMemo(() => {
    return selectedLines.map(l => l.raw).join('\n');
  }, [selectedLines]);

  // Selection handlers
  const handleLineMouseDown = useCallback((index: number, e: React.MouseEvent) => {
    if (e.button !== 0) return; // Only left click
    setIsSelecting(true);
    setSelectionStart(index);
    setSelectionEnd(index);
    setSelectionPopoverAnchor(null);
  }, []);

  const handleLineMouseEnter = useCallback((index: number) => {
    if (isSelecting) {
      setSelectionEnd(index);
    }
  }, [isSelecting]);

  const handleMouseUp = useCallback(() => {
    if (isSelecting && selectionStart !== null && selectionEnd !== null) {
      setIsSelecting(false);
      // Show popover if we have a selection of more than one line
      if (Math.abs(selectionEnd - selectionStart) >= 0 && containerRef.current) {
        setSelectionPopoverAnchor(containerRef.current);
      }
    }
  }, [isSelecting, selectionStart, selectionEnd]);

  const handleClearSelection = useCallback(() => {
    setSelectionStart(null);
    setSelectionEnd(null);
    setSelectionPopoverAnchor(null);
    setRangeAnnotationText('');
  }, []);

  const handleCopySelection = useCallback(() => {
    navigator.clipboard.writeText(selectedText);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [selectedText]);

  const handleAskAboutSelection = useCallback(() => {
    if (onAskAbout && selectedText) {
      onAskAbout(selectedText);
    }
    handleClearSelection();
  }, [onAskAbout, selectedText, handleClearSelection]);

  const handleAnnotateRange = useCallback(() => {
    if (onAnnotate && selectedLines.length > 0 && rangeAnnotationText.trim()) {
      // Get the first address in the range
      const firstWithAddr = selectedLines.find(l => l.address);
      if (firstWithAddr?.address) {
        onAnnotate(firstWithAddr.address, rangeAnnotationText.trim());
      }
    }
    handleClearSelection();
  }, [onAnnotate, selectedLines, rangeAnnotationText, handleClearSelection]);

  const isLineSelected = useCallback((index: number) => {
    if (selectionStart === null || selectionEnd === null) return false;
    const start = Math.min(selectionStart, selectionEnd);
    const end = Math.max(selectionStart, selectionEnd);
    return index >= start && index <= end;
  }, [selectionStart, selectionEnd]);
  
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(disassembly);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [disassembly]);
  
  const isDark = theme.palette.mode === 'dark';
  const isARM = arch.includes('arm') || arch.includes('thumb');
  
  // State for user question input
  const [askQuestionText, setAskQuestionText] = useState('');
  const [showAskInput, setShowAskInput] = useState(false);

  const handleShowAskInput = useCallback(() => {
    setShowAskInput(true);
    setAskQuestionText('');
  }, []);

  const handleAskWithQuestion = useCallback(() => {
    if (onAskAbout && selectedText) {
      // If user provided a question, include it; otherwise use boilerplate
      const userQuestion = askQuestionText.trim();
      if (userQuestion) {
        // User provided their own question
        onAskAbout(`${userQuestion}\n\n\`\`\`asm\n${selectedText}\n\`\`\``);
      } else {
        // No user question - use boilerplate analysis
        onAskAbout(selectedText);
      }
    }
    handleClearSelection();
    setShowAskInput(false);
    setAskQuestionText('');
  }, [onAskAbout, selectedText, askQuestionText, handleClearSelection]);

  // Selection popover for range actions
  const selectionPopover = (
    <Popover
      open={Boolean(selectionPopoverAnchor) && selectedLines.length > 0}
      anchorEl={selectionPopoverAnchor}
      onClose={() => {
        handleClearSelection();
        setShowAskInput(false);
        setAskQuestionText('');
      }}
      anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      transformOrigin={{ vertical: 'bottom', horizontal: 'center' }}
    >
      <Box sx={{ p: 1.5, width: 360 }}>
        <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ mb: 1, display: 'block' }}>
          {selectedLines.length} line{selectedLines.length !== 1 ? 's' : ''} selected
        </Typography>
        
        {/* Main action buttons */}
        <Stack direction="row" spacing={1} sx={{ mb: 1 }}>
          <Tooltip title="Copy selection">
            <Button size="small" variant="outlined" onClick={handleCopySelection} startIcon={<ContentCopyIcon sx={{ fontSize: 14 }} />}>
              Copy
            </Button>
          </Tooltip>
          {onAskAbout && !showAskInput && (
            <Tooltip title="Ask Claude about this code">
              <Button size="small" variant="contained" onClick={handleShowAskInput}>
                Ask Claude
              </Button>
            </Tooltip>
          )}
        </Stack>

        {/* Ask Claude input area */}
        {onAskAbout && showAskInput && (
          <Box sx={{ mt: 1, pt: 1, borderTop: 1, borderColor: 'divider' }}>
            <Typography variant="caption" color="primary.main" fontWeight={600} sx={{ mb: 0.5, display: 'block' }}>
              Ask Claude about this code:
            </Typography>
            <TextField
              size="small"
              multiline
              rows={2}
              fullWidth
              autoFocus
              placeholder="What would you like to know? (leave empty for general analysis)"
              value={askQuestionText}
              onChange={(e) => setAskQuestionText(e.target.value)}
              sx={{ mb: 1 }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && e.ctrlKey) {
                  e.preventDefault();
                  handleAskWithQuestion();
                }
              }}
            />
            <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
              Press Ctrl+Enter to send, or leave empty for default analysis
            </Typography>
            <Stack direction="row" spacing={1} justifyContent="flex-end">
              <Button size="small" onClick={() => setShowAskInput(false)}>Cancel</Button>
              <Button size="small" variant="contained" onClick={handleAskWithQuestion}>
                {askQuestionText.trim() ? 'Ask' : 'Analyze'}
              </Button>
            </Stack>
          </Box>
        )}

        {/* Annotation input */}
        {onAnnotate && !showAskInput && (
          <Box sx={{ mt: 1, pt: 1, borderTop: 1, borderColor: 'divider' }}>
            <TextField
              size="small"
              multiline
              rows={2}
              fullWidth
              placeholder="Add annotation for this range..."
              value={rangeAnnotationText}
              onChange={(e) => setRangeAnnotationText(e.target.value)}
              sx={{ mb: 1 }}
            />
            <Stack direction="row" spacing={1} justifyContent="flex-end">
              <Button size="small" onClick={handleClearSelection}>Cancel</Button>
              <Button 
                size="small" 
                variant="contained" 
                onClick={handleAnnotateRange}
                disabled={!rangeAnnotationText.trim()}
              >
                Annotate
              </Button>
            </Stack>
          </Box>
        )}
      </Box>
    </Popover>
  );

  return (
    <Box>
      {selectionPopover}
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
        <Stack direction="row" spacing={1} alignItems="center">
          <Typography variant="caption" color="text.secondary" fontWeight={600}>
            Entry point disassembly
          </Typography>
          {isARM && (
            <Typography variant="caption" sx={{ 
              px: 0.75, 
              py: 0.25, 
              bgcolor: 'primary.main', 
              color: 'primary.contrastText',
              borderRadius: 0.5,
              fontSize: '0.65rem',
            }}>
              ARM
            </Typography>
          )}
          {selectionStart !== null && selectionEnd !== null && (
            <Typography variant="caption" sx={{ 
              px: 0.75, 
              py: 0.25, 
              bgcolor: alpha(theme.palette.warning.main, 0.2),
              color: 'warning.main',
              borderRadius: 0.5,
              fontSize: '0.65rem',
            }}>
              {Math.abs(selectionEnd - selectionStart) + 1} selected
            </Typography>
          )}
        </Stack>
        <Stack direction="row" spacing={0.5}>
          {selectionStart !== null && (
            <Tooltip title="Clear selection">
              <IconButton size="small" onClick={handleClearSelection}>
                <SelectAllIcon sx={{ fontSize: 14 }} />
              </IconButton>
            </Tooltip>
          )}
          <Tooltip title={copied ? 'Copied!' : 'Copy all'}>
            <IconButton size="small" onClick={handleCopy}>
              <ContentCopyIcon sx={{ fontSize: 14 }} />
            </IconButton>
          </Tooltip>
          {isARM && (
            <Tooltip title="ARM Reference Manual">
              <IconButton 
                size="small" 
                onClick={() => window.open('https://developer.arm.com/documentation/ddi0487/latest/', '_blank', 'noopener')}
              >
                <OpenInNewIcon sx={{ fontSize: 14 }} />
              </IconButton>
            </Tooltip>
          )}
        </Stack>
      </Stack>
      
      <Box
        ref={containerRef}
        onMouseUp={handleMouseUp}
        onMouseLeave={() => isSelecting && setIsSelecting(false)}
        sx={{
          fontFamily: '"JetBrains Mono", "Fira Code", "SF Mono", Consolas, monospace',
          fontSize: '0.72rem',
          lineHeight: 1.6,
          bgcolor: isDark ? '#0d1117' : '#f6f8fa',
          border: `1px solid ${isDark ? '#21262d' : '#d0d7de'}`,
          p: 1.5,
          borderRadius: 1,
          maxHeight: 450,
          overflow: 'auto',
          userSelect: 'none',
          cursor: isSelecting ? 'crosshair' : 'default',
          '&::-webkit-scrollbar': {
            width: 8,
            height: 8,
          },
          '&::-webkit-scrollbar-track': {
            bgcolor: isDark ? '#161b22' : '#f0f0f0',
          },
          '&::-webkit-scrollbar-thumb': {
            bgcolor: isDark ? '#30363d' : '#c1c1c1',
            borderRadius: 4,
          },
        }}
      >
        {lines.map((parsed, i) => (
          <Box
            key={i}
            onMouseDown={(e) => handleLineMouseDown(i, e)}
            onMouseEnter={() => handleLineMouseEnter(i)}
            sx={{
              bgcolor: isLineSelected(i) 
                ? alpha(theme.palette.warning.main, isDark ? 0.18 : 0.12)
                : 'transparent',
              mx: -1.5,
              px: 1.5,
              py: 0.125,
              borderLeft: isLineSelected(i) 
                ? `3px solid ${theme.palette.warning.main}`
                : '3px solid transparent',
              // Clean, crisp transitions
              transition: 'background-color 0.15s ease-out, border-color 0.15s ease-out',
              '&:hover': {
                bgcolor: isLineSelected(i) 
                  ? alpha(theme.palette.warning.main, isDark ? 0.25 : 0.18)
                  : alpha(theme.palette.primary.main, isDark ? 0.08 : 0.04),
                borderLeftColor: isLineSelected(i) 
                  ? theme.palette.warning.main
                  : alpha(theme.palette.primary.main, 0.5),
              },
            }}
          >
            <InstructionLine 
              parsed={parsed} 
              arch={arch}
              annotation={parsed.address ? annotationMap[parsed.address] : undefined}
            />
          </Box>
        ))}
      </Box>
      
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mt: 0.5 }}>
        <Typography variant="caption" color="text.secondary" sx={{ fontStyle: 'italic' }}>
          Drag to select • Hover for docs • Click 📝 to annotate
        </Typography>
        {annotations.length > 0 && (
          <Typography variant="caption" color="warning.main">
            {annotations.length} annotation{annotations.length !== 1 ? 's' : ''}
          </Typography>
        )}
      </Stack>
    </Box>
  );
};

export default DisassemblyViewer;

