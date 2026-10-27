#!/usr/bin/env python3
"""Generate the ARCv2 (ARC EM/HS) SLEIGH specification.

  tools/gen_arcv2.py [outdir]        (default: data/languages)
  -> ARCv2.sinc (shared by both byte orders), ARCv2.slaspec (little-endian), ARCv2_be.slaspec

Inputs (next to this script):
  ops_table.txt  the general operations of major opcodes 4-6: one line per (major, sub-opcode,
                 single/zero-operand selector, F bit) with the mnemonic, the operand formats and
                 the operand shape that GNU objdump 2.45 prints for them. It is a black-box survey
                 of objdump's output made by probe_ops2.py; nothing is taken from binutils' tables.
  auxregs.txt    auxiliary register names objdump prints for lr/sr (probe_aux.py, black box).

Semantics are written here, by mnemonic (SEM3, SEM2, ...). Operations without a semantics entry
(DSP, SIMD and extension instructions whose arithmetic is not publicly documented) become named
pcodeops taking the source operands.

Bit numbers in field definitions are those of the 32-bit instruction word (bit 31 = the most
significant bit of the first halfword). A little-endian ARCv2 core stores a 32-bit instruction
(and a long immediate) as two 16-bit halfwords, the high halfword first; the token layout below
maps the word bits accordingly.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "data", "languages")

REGS = ["r%d" % i for i in range(26)] + ["gp", "fp", "sp", "ilink", "r30", "blink"] + \
       ["r%d" % i for i in range(32, 60)] + ["lp_count", "r61", "r62", "pcl"]
PAIRS = [REGS[i] + REGS[i + 1] for i in range(0, 64, 2)]
R3 = ["r0", "r1", "r2", "r3", "r12", "r13", "r14", "r15"]
CONDS = ["", "eq", "ne", "p", "n", "c", "nc", "v", "nv", "gt", "ge", "lt", "le", "hi", "ls", "pnz"]
COND_SEM = ["1", "Z", "!Z", "!N", "N", "C", "!C", "V", "!V", "!Z && (N == V)", "N == V", "N != V",
            "Z || (N != V)", "!C && !Z", "C || Z", "!N && !Z"]
EXT_COND_NAMES = {21: "nj", 23: "nm", 24: "nt"}

out = []


def w(s=""):
    out.append(s)


# ---------------------------------------------------------------------------------------------
# Tokens. 32-bit fields are (name, hi, lo, signed) in instruction-word bit numbers.
F32 = [
    ("l_major", 31, 27, 0), ("l_b_lo", 26, 24, 0), ("l_fmt", 23, 22, 0), ("l_sub6", 21, 16, 0),
    ("l_F", 15, 15, 0), ("l_b_hi", 14, 12, 0), ("l_c", 11, 6, 0), ("l_u6", 11, 6, 0),
    ("l_a", 5, 0, 0), ("l_s6hi", 5, 0, 1), ("l_M", 5, 5, 0), ("l_cond", 4, 0, 0), ("l_R4", 4, 4, 0),
    ("l_c_hi", 11, 9, 0), ("l_c_lo", 8, 6, 0),
    # branches (majors 0 and 1)
    ("l_bit16", 16, 16, 0), ("l_bit17", 17, 17, 0), ("l_s10lo", 26, 17, 0), ("l_s9lo", 26, 18, 0),
    ("l_s10mid", 15, 6, 0), ("l_s10mid_s", 15, 6, 1), ("l_N", 5, 5, 0), ("l_bit4", 4, 4, 0),
    ("l_s4hi", 3, 0, 1), ("l_br_y", 3, 3, 0), ("l_brop", 3, 0, 0), ("l_brop3", 2, 0, 0),
    ("l_s7lo", 23, 17, 0), ("l_s8hi", 15, 15, 1),
    # loads (major 2) and stores (major 3)
    ("l_s8lo", 23, 16, 0), ("l_ld_di", 11, 11, 0), ("l_ld_aa", 10, 9, 0), ("l_ld_zz", 8, 7, 0),
    ("l_ld_x", 6, 6, 0), ("l_st_di", 5, 5, 0), ("l_st_aa", 4, 3, 0), ("l_st_zz", 2, 1, 0),
    ("l_st_r", 0, 0, 0), ("l_w6", 11, 6, 1),
    # register-register loads (major 4, sub-opcodes 0x30-0x36)
    ("l_ldr_zz", 18, 17, 0), ("l_ldr_x", 16, 16, 0), ("l_ldr_sub", 21, 19, 0),
]
# register-field copies with their own attachments
for i in range(8):
    F32.append(("l_b_lo_%d" % i, 26, 24, 0))
    F32.append(("l_bp_lo_%d" % i, 26, 24, 0))
    F32.append(("l_be_lo_%d" % i, 26, 24, 0))
    F32.append(("l_bo_lo_%d" % i, 26, 24, 0))
F32 += [("l_a_r", 5, 0, 0), ("l_a_p", 5, 0, 0), ("l_a_e", 5, 0, 0), ("l_a_o", 5, 0, 0),
        ("l_c_r", 11, 6, 0), ("l_c_p", 11, 6, 0), ("l_c_e", 11, 6, 0), ("l_c_o", 11, 6, 0),
        ("l_u6_aux", 11, 6, 0)]


def tokbits(hi, lo, le):
    if not le:
        return hi, lo
    assert (hi >= 16) == (lo >= 16), (hi, lo)
    return (hi - 16, lo - 16) if hi >= 16 else (hi + 16, lo + 16)


def token32(le):
    w("define token instr32 (32)")
    for n, hi, lo, s in F32:
        h, l = tokbits(hi, lo, le)
        w("  %-14s = (%d,%d)%s" % (n, l, h, " signed" if s else ""))
    w(";")


F16 = [
    ("s_major", 15, 11, 0), ("s_b", 10, 8, 0), ("s_c", 7, 5, 0), ("s_a", 2, 0, 0),
    ("s_b_r", 10, 8, 0), ("s_b_r2", 10, 8, 0), ("s_b_r3", 10, 8, 0), ("s_c_r", 7, 5, 0), ("s_a_r", 2, 0, 0),
    ("s_h_lo", 7, 5, 0), ("s_h_hi", 1, 0, 0), ("s_g_lo", 10, 8, 0), ("s_g_hi", 4, 3, 0),
    ("s_bit2", 2, 2, 0), ("s_bit3", 3, 3, 0), ("s_bit4", 4, 4, 0), ("s_bit5", 5, 5, 0),
    ("s_bit7", 7, 7, 0), ("s_bit10", 10, 10, 0),
    ("s_op2", 4, 3, 0), ("s_op3", 4, 2, 0), ("s_op5", 4, 0, 0), ("s_op3hi", 10, 8, 0),
    ("s_sub7_5", 7, 5, 0), ("s_sub6_5", 6, 5, 0), ("s_sub10_9", 10, 9, 0), ("s_bit8", 8, 8, 0),
    ("s_s3", 10, 8, 1), ("s_u3", 2, 0, 0), ("s_u5", 4, 0, 0), ("s_u6", 5, 0, 0), ("s_u7", 6, 0, 0),
    ("s_u8", 7, 0, 0), ("s_s9", 8, 0, 1), ("s_s10", 8, 0, 1), ("s_s7", 6, 0, 1), ("s_s11", 10, 0, 1),
    ("s_s6hi", 10, 5, 1), ("s_u6hi", 10, 5, 0),
    ("s_s13", 10, 0, 1), ("s_u10", 9, 0, 0), ("s_s6", 5, 0, 1), ("s_u2", 1, 0, 0),
    ("s_R2", 9, 8, 0), ("s_cc3", 8, 6, 0), ("s_u5a", 10, 10, 0), ("s_u5b", 4, 3, 0), ("s_u4", 3, 0, 0), ("s_bit0", 0, 0, 0),
    ("s_ent_u", 4, 1, 0), ("s_ent_fp", 8, 8, 0), ("s_ent_blink", 9, 9, 0), ("s_ent_pcl", 10, 10, 0),
    ("s_ld_u", 4, 3, 0),
]
for i in range(4):
    F16.append(("s_h_lo_%d" % i, 7, 5, 0))
    F16.append(("s_g_lo_%d" % i, 10, 8, 0))


def token16():
    w("define token instr16 (16)")
    for n, hi, lo, s in F16:
        w("  %-12s = (%d,%d)%s" % (n, lo, hi, " signed" if s else ""))
    w(";")


# ---------------------------------------------------------------------------------------------
def header():
    w("""# SLEIGH specification for the ARCv2 instruction set (Synopsys DesignWare ARC EM and HS cores),
# shared by the little-endian (ARCv2.slaspec) and big-endian (ARCv2_be.slaspec) languages.
#
# GENERATED by tools/gen_arcv2.py; edit the generator, not this file.
#
# Originally written by Roman Korkikian (sony/ARCv2_Ghidra, Apache License 2.0); rewritten for
# Ghidra-Rare as a generated specification (see CREDITS.md). Syntax follows GNU objdump 2.45
# (-m arc -M cpu=hs / cpu=em): ".f" before the condition, "0" for a discarded destination,
# objdump's condition names (p, n, c, nc, v, nv) and auxiliary register names.

define alignment=2;

define space ram type=ram_space size=4 default;
define space register type=register_space size=4;
# Auxiliary registers (lr/sr), one 32-bit word per register number at byte offset 4 * number
define space AUX_REGS_BASE type=ram_space size=4;

# 64 core registers: r26 = gp, r27 = fp, r28 = sp, r29 = ilink, r31 = blink, r58/r59 = the
# accumulator (ACCL/ACCH) on cores with the MPY/DSP options, r60 = lp_count, r61 reserved,
# r62 = long immediate indicator, r63 = pcl (the current instruction address, 32-bit aligned)
define register offset=0x00 size=4 [""")
    for i in range(0, 64, 16):
        w("    " + " ".join(REGS[i:i + 16]))
    w("];")
    w("# Even/odd register pairs (64-bit operands of ldd/std and some DSP/SIMD instructions; the")
    w("# names only serve the disassembly, the semantics address the two registers explicitly)")
    w("define register offset=0x00 size=8 [")
    for i in range(0, 32, 8):
        w("    " + " ".join(PAIRS[i:i + 8]))
    w("];")
    w("""
# STATUS32 flags: Zero, Negative, Carry, Overflow; and the llock/scond lock flag
define register offset=0x120 size=1 [ Z N C V LF ];
define register offset=0x130 size=1 [ is_in_loop ];
define register offset=0x134 size=4 [ contextreg ];

define context contextreg
  phase = (0,0)
  loopEnd = (1,1) noflow
  loopStart = (2,31) noflow   # LP_START / 2 of the loop that ends here (set by lp)
;
""")
    w("@if ENDIAN == \"big\"")
    token32(False)
    w("@else")
    w("# Little-endian: the instruction is stored as two 16-bit halfwords, high halfword first, so")
    w("# instruction bits 31..16 are token bits 15..0 and instruction bits 15..0 token bits 31..16.")
    token32(True)
    w("@endif")
    w()
    token16()
    w("""
# Long immediate: a 32-bit word stored as two halfwords, high halfword first (both byte orders)
define token limm_hi_token (16) limm_hi = (0, 15);
define token limm_lo_token (16) limm_lo = (0, 15);
""")
    # attachments
    w("attach variables [ s_a_r s_b_r s_b_r2 s_b_r3 s_c_r ] [ %s ];" % " ".join(R3))
    w("attach variables [ l_a_r l_c_r ] [ %s ];" % " ".join(REGS))
    w("attach names [ l_a_p l_c_p ] [ %s ];" % " ".join('"%s" "%s"' % (p, p) for p in PAIRS))
    ev = " ".join("%s _" % REGS[i] for i in range(0, 64, 2))
    od = " ".join("%s _" % REGS[i + 1] for i in range(0, 64, 2))
    w("attach variables [ l_a_e l_c_e ] [ %s ];" % ev)
    w("attach variables [ l_a_o l_c_o ] [ %s ];" % od)
    for i in range(8):
        regs = REGS[8 * i:8 * i + 8]
        w("attach variables [ l_b_lo_%d ] [ %s ];" % (i, " ".join(regs)))
        w("attach names [ l_bp_lo_%d ] [ %s ];" % (i, " ".join('"%s" "%s"' % (PAIRS[4 * i + k], PAIRS[4 * i + k]) for k in range(4))))
        w("attach variables [ l_be_lo_%d ] [ %s ];" % (i, " ".join("%s _" % regs[k] for k in range(0, 8, 2))))
        w("attach variables [ l_bo_lo_%d ] [ %s ];" % (i, " ".join("%s _" % regs[k + 1] for k in range(0, 8, 2))))
    for i in range(4):
        regs = REGS[8 * i:8 * i + 8]
        w("attach variables [ s_h_lo_%d s_g_lo_%d ] [ %s ];" % (i, i, " ".join(regs)))
    aux = {}
    for line in open(os.path.join(HERE, "auxregs.txt")):
        n, name = line.split()
        aux[int(n, 16)] = name
    w("attach names [ l_u6_aux ] [ %s ];" % " ".join('"%s"' % aux.get(i, hex(i)) for i in range(64)))
    w()
    return aux


def operands(aux):
    w("""# ---------------------------------------------------------------------------------------------
# Register operands. A 6-bit register field of 62 means "long immediate follows" (as a destination:
# discard the result, printed "0"); 63 reads PCL, the current instruction address with bits 1..0
# clear. The b field is split (bits 14..12 high, 26..24 low).""")
    for i in range(8):
        w("l_rb: l_b_lo_%d is l_b_hi=%d & l_b_lo_%d { export l_b_lo_%d; }" % (i, i, i, i))
    for i in range(8):
        w("l_rb_p: l_bp_lo_%d is l_b_hi=%d & l_bp_lo_%d & l_be_lo_%d & l_bo_lo_%d { local v:8 = (zext(l_bo_lo_%d) << 32) | zext(l_be_lo_%d); export v; }"
          % (i, i, i, i, i, i, i))
    for i in range(8):
        w("l_rb_e: l_be_lo_%d is l_b_hi=%d & l_be_lo_%d { export l_be_lo_%d; }" % (i, i, i, i))
        w("l_rb_o: l_bo_lo_%d is l_b_hi=%d & l_bo_lo_%d { export l_bo_lo_%d; }" % (i, i, i, i))
    for i in range(4):
        w("s_hn: s_h_lo_%d is s_h_hi=%d & %ss_h_lo_%d { export s_h_lo_%d; }" % (i, i, "s_h_lo!=6 & " if i == 3 else "", i, i))
        w("s_h: s_h_lo_%d is s_h_hi=%d & s_h_lo_%d { export s_h_lo_%d; }" % (i, i, i, i))
        w("s_g: s_g_lo_%d is s_g_hi=%d & s_g_lo_%d { export s_g_lo_%d; }" % (i, i, i, i))
    w("""
limm: v is limm_hi ; limm_lo [ v = (limm_hi << 16) | limm_lo; ] { export *[const]:4 v; }
pclv: "pcl" is epsilon { local v:4 = inst_start & 0xfffffffc; export v; }

l_b_src: limm is l_b_hi=7 & l_b_lo=6 ; limm { export limm; }
l_b_src: pclv is l_b_hi=7 & l_b_lo=7 & pclv { export pclv; }
l_b_src: l_rb is l_rb { export l_rb; }
l_b_dst: l_rb is l_rb { export l_rb; }
l_b_dst: "0" is l_b_hi=7 & l_b_lo=6 { local t:4 = 0; export t; }

l_c_src: limm is l_c=62 ; limm { export limm; }
l_c_src: pclv is l_c=63 & pclv { export pclv; }
l_c_src: l_c_r is l_c_r { export l_c_r; }

l_a_dst: l_a_r is l_a_r { export l_a_r; }
l_a_dst: "0" is l_a=62 { local t:4 = 0; export t; }

# 64-bit (register pair) operands: value = odd:even
l_a_pv: l_a_p is l_a_p & l_a_e & l_a_o { local v:8 = (zext(l_a_o) << 32) | zext(l_a_e); export v; }
l_c_pv: l_c_p is l_c_p & l_c_e & l_c_o { local v:8 = (zext(l_c_o) << 32) | zext(l_c_e); export v; }
l_c_pv: limm is l_c=62 ; limm { local v:8 = sext(limm); export v; }
l_b_pv: l_rb_p is l_rb_p { export l_rb_p; }
l_b_pv: limm is l_b_hi=7 & l_b_lo=6 ; limm { local v:8 = sext(limm); export v; }

# 16-bit h/g register operands (5 bits, h = bits 1..0:7..5); 30 means long immediate (as a
# destination: discard)
s_h_src: limm is s_h_hi=3 & s_h_lo=6 ; limm { export limm; }
s_h_src: s_h is s_h { export s_h; }
s_h_dst: s_h is s_h { export s_h; }
s_h_dst: "0" is s_h_hi=3 & s_h_lo=6 { local t:4 = 0; export t; }
s_g_dst: s_g is s_g { export s_g; }
s_g_dst: "0" is s_g_hi=3 & s_g_lo=6 { local t:4 = 0; export t; }

# General operations (majors 4-6): operands by format (bits 23..22)
#   0: a,b,c   1: a,b,u6   2: b,b,s12   3: <cc> b,b,c (bit 5 = 0) / b,b,u6 (bit 5 = 1)
op_c: l_c_src is l_fmt=0 ... & l_c_src { export l_c_src; }
op_c: l_u6 is l_fmt=1 & l_u6 { export *[const]:4 l_u6; }
op_c: s12 is l_fmt=2 & l_u6 & l_s6hi [ s12 = (l_s6hi << 6) | l_u6; ] { export *[const]:4 s12; }
op_c: l_c_src is (l_fmt=3 & l_M=0) ... & l_c_src { export l_c_src; }
op_c: l_u6 is l_fmt=3 & l_M=1 & l_u6 { export *[const]:4 l_u6; }

op_a: l_a_dst is (l_fmt=0 | l_fmt=1) & l_a_dst { export l_a_dst; }
op_a: l_b_dst is (l_fmt=2 | l_fmt=3) & l_b_dst { export l_b_dst; }

op_b: l_b_src is l_b_src { export l_b_src; }

# The odd register of a 64-bit result (a+1, or b+1 in formats 2/3); objdump prints only the
# first register of these operations (mpyd, FPU double precision)
op_ahi: o is (l_fmt=0 | l_fmt=1) & l_a [ o = (l_a + 1) << 2; ] { export *[register]:4 o; }
op_ahi: is (l_fmt=0 | l_fmt=1) & l_a=62 { local t:4 = 0; export t; }
op_ahi: o is (l_fmt=2 | l_fmt=3) & l_b_hi & l_b_lo [ o = (((l_b_hi << 3) | l_b_lo) + 1) << 2; ] { export *[register]:4 o; }
op_ahi: is (l_fmt=2 | l_fmt=3) & l_b_hi=7 & l_b_lo=6 { local t:4 = 0; export t; }
op_bhi: o is l_b_hi & l_b_lo [ o = (((l_b_hi << 3) | l_b_lo) + 1) << 2; ] { export *[register]:4 o; }
op_bhi: is l_b_hi=7 & l_b_lo=6 { local t:4 = 0; export t; }
# 64-bit sources from a register and the next one; an immediate is the high word (low word 0)
op_bd: l_rb is l_rb & op_bhi { local v:8 = (zext(op_bhi) << 32) | zext(l_rb); export v; }
op_bd: is l_b_hi=7 & l_b_lo=6 ; limm { local v:8 = zext(limm) << 32; export v; }
op_chi: o is l_c [ o = (l_c + 1) << 2; ] { export *[register]:4 o; }
op_cd: l_c_r is (l_fmt=0 | (l_fmt=3 & l_M=0)) & l_c_r & op_chi { local v:8 = (zext(op_chi) << 32) | zext(l_c_r); export v; }
op_cd: is (l_fmt=0 | (l_fmt=3 & l_M=0)) & l_c=62 ; limm { local v:8 = zext(limm) << 32; export v; }
op_cd: is (l_fmt=1 | (l_fmt=3 & l_M=1)) & l_u6 { local v:8 = zext(l_u6:4) << 32; export v; }
op_cd: s12 is l_fmt=2 & l_u6 & l_s6hi [ s12 = (l_s6hi << 6) | l_u6; ] { local v:8 = zext(s12:4) << 32; export v; }
# operations objdump decodes without any long immediate or discarded destination
op_nd: is l_fmt=0 & l_a!=62 & l_c!=62 & l_b_hi!=7 { }
op_nd: is l_fmt=0 & l_a!=62 & l_c!=62 & l_b_hi=7 & l_b_lo!=6 { }
op_nd: is l_fmt=1 & l_a!=62 & l_b_hi!=7 { }
op_nd: is l_fmt=1 & l_a!=62 & l_b_hi=7 & l_b_lo!=6 { }
op_nd: is l_fmt=2 & l_b_hi!=7 { }
op_nd: is l_fmt=2 & l_b_hi=7 & l_b_lo!=6 { }
op_nd: is l_fmt=3 & l_M=1 & l_b_hi!=7 { }
op_nd: is l_fmt=3 & l_M=1 & l_b_hi=7 & l_b_lo!=6 { }
op_nd: is l_fmt=3 & l_M=0 & l_c!=62 & l_b_hi!=7 { }
op_nd: is l_fmt=3 & l_M=0 & l_c!=62 & l_b_hi=7 & l_b_lo!=6 { }
# operations objdump does not decode as "0,limm,c" (formats 0 and 1)
op_nab: is l_fmt=2 | l_fmt=3 { }
op_nab: is (l_fmt=0 | l_fmt=1) & l_a!=62 { }
op_nab: is (l_fmt=0 | l_fmt=1) & l_a=62 & l_b_hi!=7 { }
op_nab: is (l_fmt=0 | l_fmt=1) & l_a=62 & l_b_hi=7 & l_b_lo!=6 { }

# 64-bit forms
op_cp: l_c_pv is l_fmt=0 ... & l_c_pv { export l_c_pv; }
op_cp: l_u6 is l_fmt=1 & l_u6 { local v:8 = l_u6; export v; }
op_cp: s12 is l_fmt=2 & l_u6 & l_s6hi [ s12 = (l_s6hi << 6) | l_u6; ] { local v:8 = s12; export v; }
op_cp: l_c_pv is (l_fmt=3 & l_M=0) ... & l_c_pv { export l_c_pv; }
op_cp: l_u6 is l_fmt=3 & l_M=1 & l_u6 { local v:8 = l_u6; export v; }
# the c operand printed as a single register although the operation reads a pair
op_cp1: l_c_r is l_fmt=3 & l_M=0 & l_c_r { local v:8 = zext(l_c_r); export v; }
op_cp1: limm is l_fmt=3 & l_M=0 & l_c=62 ; limm { local v:8 = sext(limm); export v; }
op_cp1: l_u6 is l_fmt=3 & l_M=1 & l_u6 { local v:8 = l_u6; export v; }

# destination register pair: a (formats 0/1) or b (formats 2/3); written as even, odd
op_ap: l_a_p is (l_fmt=0 | l_fmt=1) & l_a_p & l_a_e & l_a_o { export l_a_e; }
op_ap: "0" is (l_fmt=0 | l_fmt=1) & l_a=62 { local t:4 = 0; export t; }
op_ap: "0" is (l_fmt=2 | l_fmt=3) & l_b_hi=7 & l_b_lo=6 { local t:4 = 0; export t; }
op_ap: l_rb_p is (l_fmt=2 | l_fmt=3) & l_rb_p & l_rb_e { export l_rb_e; }
op_ap1: l_a_e is (l_fmt=0 | l_fmt=1) & l_a_e & l_a_o { export l_a_e; }
op_ap1: l_rb_e is (l_fmt=2 | l_fmt=3) & l_rb_e & l_rb_o { export l_rb_e; }
op_ao: is (l_fmt=0 | l_fmt=1) & l_a_o { export l_a_o; }
op_ao: is (l_fmt=0 | l_fmt=1) & l_a=62 { local t:4 = 0; export t; }
op_ao: is (l_fmt=2 | l_fmt=3) & l_b_hi=7 & l_b_lo=6 { local t:4 = 0; export t; }
op_ao: is (l_fmt=2 | l_fmt=3) & l_rb_o { export l_rb_o; }
op_bp: l_b_pv is l_b_pv { export l_b_pv; }
op_bp1: l_rb_e is l_rb_e & l_rb_o { local v:8 = (zext(l_rb_o) << 32) | zext(l_rb_e); export v; }
op_bp1: limm is l_b_hi=7 & l_b_lo=6 ; limm { local v:8 = sext(limm); export v; }
""")
    w("""
# Delay-slot suffix
nd: "" is l_N=0 { }
nd: ".d" is l_N=1 { }

define pcodeop ext_condition;
define pcodeop sleep;
define pcodeop swi;
define pcodeop trap_s;
define pcodeop brk;
define pcodeop unimp_s;
define pcodeop sync;
define pcodeop dsync;
define pcodeop dmb;
define pcodeop seti;
define pcodeop clri;
define pcodeop wevt;
define pcodeop wlfc;
define pcodeop rtie;
define pcodeop kflag;
define pcodeop prefetch;
define pcodeop ei;

attach variables [ s_R2 ] [ r0 r1 r2 r3 ];

macro push4(x) {
  local v:4 = x;
  sp = sp - 4;
  *:4 sp = v;
}
macro pop4(x) {
  x = *:4 sp;
  sp = sp + 4;
}
macro cmpflags(vb, vc) {
  local vr:4 = vb - vc;
  Z = vb == vc;
  N = vr s< 0;
  C = vb < vc;
  V = sborrow(vb, vc);
}
# flag: write STATUS32 (aux 0x0a); Z, N, C, V are its bits 11..8
macro set_status(v) {
  *[AUX_REGS_BASE]:4 0x28:4 = v;
  V = (v & 0x100) != 0;
  C = (v & 0x200) != 0;
  N = (v & 0x400) != 0;
  Z = (v & 0x800) != 0;
}

macro zn(v) {
  Z = v == 0;
  N = v s< 0;
}
""")
    # conditions
    w("# Conditions (true when the instruction executes). ccd: \".cc\" suffix; ccn: \"cc\" suffix")
    w("# (b, bl, j, jl, lp). Conditions 16-31 are core-specific extensions; objdump names 21, 23")
    w("# and 24 and prints nothing for the others, Ghidra prints \"e<number>\".")
    for tab, dot in (("ccd", "."), ("ccn", "")):
        for i, (n, s) in enumerate(zip(CONDS, COND_SEM)):
            if tab == "ccn" and i == 0:
                continue   # b/bl with condition 0 are separate (unconditional) constructors
            disp = (dot + n) if n else ""
            if s in ("Z", "N", "C", "V"):
                w('%s: "%s" is l_cond=%d { export %s; }' % (tab, disp, i, s))
            else:
                w('%s: "%s" is l_cond=%d { local t:1 = %s; export t; }' % (tab, disp, i, s))
        for i in range(16, 32):
            n = EXT_COND_NAMES.get(i, "e%d" % i)
            w('%s: "%s%s" is l_cond=%d { local t:1 = ext_condition(%d:1); export t; }' % (tab, dot, n, i, i))
    # bl, j and jl print the named extension conditions with a dot (bl.nj, j.nm), b does not (bnj)
    for i, (n, s) in enumerate(zip(CONDS, COND_SEM)):
        if s in ("Z", "N", "C", "V"):
            w('ccx: "%s" is l_cond=%d { export %s; }' % (n, i, s))
        else:
            w('ccx: "%s" is l_cond=%d { local t:1 = %s; export t; }' % (n, i, s))
    for i in range(16, 32):
        n = ("." + EXT_COND_NAMES[i]) if i in EXT_COND_NAMES else "e%d" % i
        w('ccx: "%s" is l_cond=%d { local t:1 = ext_condition(%d:1); export t; }' % (n, i, i))
    w()
    # 16-bit branch conditions etc. defined where used


# ---------------------------------------------------------------------------------------------
# Semantics by mnemonic. res: p-code computing vr from vb, vc (and the flags); flags: run only
# with .f (F=1), after vr. 64-bit operations use w (8 bytes).
ZN = "Z = vr == 0;\n  N = vr s< 0;"
ADD_F = "C = carry(vb, vt);\n  V = scarry(vb, vt);\n  " + ZN
SUB_F = "C = vb < vt;\n  V = sborrow(vb, vt);\n  " + ZN
SAT = """local sat:1 = (w s> 0x7fffffff) || (w s< -0x80000000);
  vr = w:4;
  if (w s<= 0x7fffffff) goto <nothigh>;
  vr = 0x7fffffff;
<nothigh>
  if (w s>= -0x80000000) goto <notlow>;
  vr = 0x80000000;
<notlow>"""
VS = "V = sat;\n  " + ZN


def sat_shift(left, right):
    return ("local sh:4 = vc;\n  local w:8;\n"
            "  if (sh s> 31) goto <big>;\n  if (sh s< -31) goto <small>;\n  if (sh s< 0) goto <neg>;\n"
            f"  w = {left.format(n='sh')};\n  goto <done>;\n"
            f"<neg>\n  w = {right.format(n='(0 - sh)')};\n  goto <done>;\n"
            f"<big>\n  w = {left.format(n='31')};\n  goto <done>;\n"
            f"<small>\n  w = {right.format(n='31')};\n<done>\n  " + SAT)


SHL = "sext(vb) << {n}"
SHR = "sext(vb s>> {n})"

SEM3 = {
    "add": ("vr = vb + vc;", "local vt:4 = vc;\n  " + ADD_F),
    "adc": ("vr = vb + vc + zext(C);",
            "local w:8 = zext(vb) + zext(vc) + zext(C);\n  C = (w >> 32) != 0;\n  V = ((vb ^ vr) & (vc ^ vr)) s< 0;\n  " + ZN),
    "sub": ("vr = vb - vc;", "local vt:4 = vc;\n  " + SUB_F),
    "sbc": ("vr = vb - vc - zext(C);",
            "local w:8 = zext(vb) - zext(vc) - zext(C);\n  C = (w >> 32) != 0;\n  V = ((vb ^ vc) & (vb ^ vr)) s< 0;\n  " + ZN),
    "and": ("vr = vb & vc;", ZN),
    "or": ("vr = vb | vc;", ZN),
    "bic": ("vr = vb & ~vc;", ZN),
    "xor": ("vr = vb ^ vc;", ZN),
    "max": ("vr = vb;\n  if (vb s>= vc) goto <keep>;\n  vr = vc;\n<keep>",
            "local d:4 = vb - vc;\n  Z = vb == vc;\n  N = d s< 0;\n  C = vc s>= vb;\n  V = sborrow(vb, vc);"),
    "min": ("vr = vb;\n  if (vb s<= vc) goto <keep>;\n  vr = vc;\n<keep>",
            "local d:4 = vb - vc;\n  Z = vb == vc;\n  N = d s< 0;\n  C = vc s<= vb;\n  V = sborrow(vb, vc);"),
    "rsub": ("vr = vc - vb;", "local vt:4 = vb;\n  vb = vc;\n  " + SUB_F),
    "bset": ("vr = vb | (1:4 << (vc & 31));", ZN),
    "bclr": ("vr = vb & ~(1:4 << (vc & 31));", ZN),
    "bxor": ("vr = vb ^ (1:4 << (vc & 31));", ZN),
    "bmsk": ("vr = vb & ((2:4 << (vc & 31)) - 1);", ZN),
    "bmskn": ("vr = vb & ~((2:4 << (vc & 31)) - 1);", ZN),
    "add1": ("vr = vb + (vc << 1);", "local vt:4 = vc << 1;\n  " + ADD_F),
    "add2": ("vr = vb + (vc << 2);", "local vt:4 = vc << 2;\n  " + ADD_F),
    "add3": ("vr = vb + (vc << 3);", "local vt:4 = vc << 3;\n  " + ADD_F),
    "sub1": ("vr = vb - (vc << 1);", "local vt:4 = vc << 1;\n  " + SUB_F),
    "sub2": ("vr = vb - (vc << 2);", "local vt:4 = vc << 2;\n  " + SUB_F),
    "sub3": ("vr = vb - (vc << 3);", "local vt:4 = vc << 3;\n  " + SUB_F),
    "mpy": ("local p:8 = sext(vb) * sext(vc);\n  vr = p:4;", ZN + "\n  V = sext(vr) != p;"),
    "mpym": ("local p:8 = sext(vb) * sext(vc);\n  vr = p(4);", ZN + "\n  V = 0;"),
    "mpymu": ("local p:8 = zext(vb) * zext(vc);\n  vr = p(4);", "Z = vr == 0;\n  N = 0;\n  V = 0;"),
    "mpyu": ("local p:8 = zext(vb) * zext(vc);\n  vr = p:4;", ZN + "\n  V = (p >> 32) != 0;"),
    "mpyw": ("vr = sext(vb:2) * sext(vc:2);", ZN + "\n  V = 0;"),
    "mpyuw": ("vr = zext(vb:2) * zext(vc:2);", ZN + "\n  V = 0;"),
    # xbfu: extract an unsigned bit field; c = (width - 1) << 5 | position
    "xbfu": ("local pos:4 = vc & 31;\n  local wid:4 = ((vc >> 5) & 31) + 1;\n  vr = (vb >> pos) & ((2:4 << (wid - 1)) - 1);", ZN),
    "seteq": ("vr = zext(vb == vc);", "local vt:4 = vc;\n  " + SUB_F.replace(ZN, "Z = vb == vc;\n  N = (vb - vc) s< 0;")),
    "setne": ("vr = zext(vb != vc);", "local vt:4 = vc;\n  " + SUB_F.replace(ZN, "Z = vb == vc;\n  N = (vb - vc) s< 0;")),
    "setlt": ("vr = zext(vb s< vc);", "local vt:4 = vc;\n  " + SUB_F.replace(ZN, "Z = vb == vc;\n  N = (vb - vc) s< 0;")),
    "setge": ("vr = zext(vb s>= vc);", "local vt:4 = vc;\n  " + SUB_F.replace(ZN, "Z = vb == vc;\n  N = (vb - vc) s< 0;")),
    "setlo": ("vr = zext(vb < vc);", "local vt:4 = vc;\n  " + SUB_F.replace(ZN, "Z = vb == vc;\n  N = (vb - vc) s< 0;")),
    "seths": ("vr = zext(vb >= vc);", "local vt:4 = vc;\n  " + SUB_F.replace(ZN, "Z = vb == vc;\n  N = (vb - vc) s< 0;")),
    "setle": ("vr = zext(vb s<= vc);", "local vt:4 = vc;\n  " + SUB_F.replace(ZN, "Z = vb == vc;\n  N = (vb - vc) s< 0;")),
    "setgt": ("vr = zext(vb s> vc);", "local vt:4 = vc;\n  " + SUB_F.replace(ZN, "Z = vb == vc;\n  N = (vb - vc) s< 0;")),
    # major 5
    "asl": ("vr = vb << (vc & 31);",
            "local s:4 = vc & 31;\n  C = (s != 0) && (((vb >> (32 - s)) & 1) != 0);\n  " + ZN),
    "lsr": ("vr = vb >> (vc & 31);",
            "local s:4 = vc & 31;\n  C = (s != 0) && (((vb >> (s - 1)) & 1) != 0);\n  " + ZN),
    "asr": ("vr = vb s>> (vc & 31);",
            "local s:4 = vc & 31;\n  C = (s != 0) && (((vb >> (s - 1)) & 1) != 0);\n  " + ZN),
    "ror": ("local s:4 = vc & 31;\n  vr = (vb >> s) | (vb << ((32 - s) & 31));",
            "C = (s != 0) && (((vb >> (s - 1)) & 1) != 0);\n  " + ZN),
    # integer division (ARCv2 DIV option): division by zero leaves the destination unchanged and
    # sets V with .f
    "div": ("vr = op_a;\n  if (vc == 0) goto <dz>;\n  vr = vb s/ vc;\n  if ((vb != 0x80000000) || (vc != -1)) goto <dz>;\n  vr = 0x80000000;\n<dz>",
            "V = vc == 0;\n  " + ZN),
    "divu": ("vr = op_a;\n  if (vc == 0) goto <dz>;\n  vr = vb / vc;\n<dz>", "V = vc == 0;\n  " + ZN),
    "rem": ("vr = op_a;\n  if (vc == 0) goto <dz>;\n  vr = 0;\n  if ((vb == 0x80000000) && (vc == -1)) goto <dz>;\n  vr = vb s% vc;\n<dz>",
            "V = vc == 0;\n  " + ZN),
    "remu": ("vr = op_a;\n  if (vc == 0) goto <dz>;\n  vr = vb % vc;\n<dz>", "V = vc == 0;\n  " + ZN),
    "adds": ("local w:8 = sext(vb) + sext(vc);\n  " + SAT, "C = 0;\n  " + VS),
    "subs": ("local w:8 = sext(vb) - sext(vc);\n  " + SAT, "C = 0;\n  " + VS),
    "adcs": ("local w:8 = sext(vb) + sext(vc) + zext(C);\n  " + SAT, "C = 0;\n  " + VS),
    "sbcs": ("local w:8 = sext(vb) - sext(vc) - zext(C);\n  " + SAT, "C = 0;\n  " + VS),
    "asls": (sat_shift(SHL, SHR), VS),
    "asrs": (sat_shift(SHR, SHL), VS),
    # FPU single precision (IEEE 754 binary32 in core registers)
    "fsmul": ("vr = vb f* vc;", ""),
    "fsadd": ("vr = vb f+ vc;", ""),
    "fssub": ("vr = vb f- vc;", ""),
    "fsdiv": ("vr = vb f/ vc;", ""),
    # fused multiply-add with the accumulator r58 (GCC loads the addend into r58: black box)
    "fsmadd": ("vr = (vb f* vc) f+ r58;", ""),
    "fsmsub": ("vr = r58 f- (vb f* vc);", ""),
}

# 64-bit results (a register pair): res computes w:8 from vb, vc (32-bit) or pb, pc (64-bit)
SEMP = {
    "mpyd": ("w = sext(vb) * sext(vc);", ZN.replace("vr", "w") + "\n  V = 0;"),
    "mpydu": ("w = zext(vb) * zext(vc);", "Z = w == 0;\n  N = 0;\n  V = 0;"),
    # FPU double precision on register pairs
    "fdmul": ("w = pb f* pc;", ""),
    "fdadd": ("w = pb f+ pc;", ""),
    "fdsub": ("w = pb f- pc;", ""),
    "fddiv": ("w = pb f/ pc;", ""),
    "fdmadd": ("local acc:8 = (zext(r59) << 32) | zext(r58);\n  w = (pb f* pc) f+ acc;", ""),
    "fdmsub": ("local acc:8 = (zext(r59) << 32) | zext(r58);\n  w = acc f- (pb f* pc);", ""),
}

# FPU compares: Z = equal, N = C = less than, V = unordered (the conditions GCC uses after them:
# black box)
FCMP = {"fscmp": 4, "fscmpf": 4, "fdcmp": 8, "fdcmpf": 8}

# FPU conversions: the u6 operand selects the conversion (GCC's codes, black box): 0 unsigned
# integer -> float, 2 signed integer -> float, 4 float -> float of the other precision, 9 float
# -> unsigned integer (truncating), 11 float -> signed integer (truncating). Other codes stay
# pcodeops. (source size, result size)
FCVT = {"fcvt32": (4, 4), "fcvt32_64": (4, 8), "fcvt64_32": (8, 4), "fcvt64": (8, 8)}


def fcvt_body(base, code):
    ss, rs = FCVT[base]
    src = "local s:%d = %s;" % (ss, "op_b" if ss == 4 else "op_bd")
    if code == 0:
        e = "local x:%d = zext(s);\n  local r:%d = int2float(x);" % (2 * ss if ss == 4 else 8, rs)
    elif code == 2:
        e = "local r:%d = int2float(s);" % rs
    elif code == 4:
        if ss == rs:
            return None
        e = "local r:%d = float2float(s);" % rs
    elif code == 9:
        e = "local x:8 = trunc(s);\n  local r:%d = x:%d;" % (rs, rs)
    elif code == 11:
        e = "local r:%d = trunc(s);" % rs
    else:
        return None
    body = src + "\n  " + e + "\n  "
    body += "op_a = r;" if rs == 4 else "op_a = r:4;\n  op_ahi = r(4);"
    return body

# two-operand: b,c (dest b) in the single-operand group (sub-opcode 0x2f)
SEM2 = {
    "asl": ("vr = vc << 1;", "C = vc s< 0;\n  V = (vc ^ vr) s< 0;\n  " + ZN),
    "asr": ("vr = vc s>> 1;", "C = (vc & 1) != 0;\n  " + ZN),
    "lsr": ("vr = vc >> 1;", "C = (vc & 1) != 0;\n  " + ZN),
    "ror": ("vr = (vc >> 1) | (vc << 31);", "C = (vc & 1) != 0;\n  " + ZN),
    "rrc": ("vr = (vc >> 1) | (zext(C) << 31);", "C = (vc & 1) != 0;\n  " + ZN),
    "rlc": ("vr = (vc << 1) | zext(C);", "C = vc s< 0;\n  " + ZN),
    "rol": ("vr = (vc << 1) | (vc >> 31);", "C = vc s< 0;\n  " + ZN),
    "sexb": ("vr = sext(vc:1);", ZN),
    "sexh": ("vr = sext(vc:2);", ZN),
    "extb": ("vr = zext(vc:1);", ZN),
    "exth": ("vr = zext(vc:2);", ZN),
    "abs": ("vr = vc;\n  if (vc s>= 0) goto <pos>;\n  vr = -vc;\n<pos>",
            "Z = vc == 0;\n  N = vc == 0x80000000;\n  C = vc s< 0;\n  V = vc == 0x80000000;"),
    "not": ("vr = ~vc;", ZN),
    "swap": ("vr = (vc << 16) | (vc >> 16);", ZN),
    "swape": ("vr = (vc << 24) | ((vc << 8) & 0xff0000) | ((vc >> 8) & 0xff00) | (vc >> 24);", ZN),
    "lsl16": ("vr = vc << 16;", ZN),
    "lsr16": ("vr = vc >> 16;", ZN),
    "asr16": ("vr = vc s>> 16;", ZN),
    "asr8": ("vr = vc s>> 8;", ZN),
    "lsr8": ("vr = vc >> 8;", ZN),
    "lsl8": ("vr = vc << 8;", ZN),
    "rol8": ("vr = (vc << 8) | (vc >> 24);", ZN),
    "ror8": ("vr = (vc >> 8) | (vc << 24);", ZN),
    # norm: number of redundant sign bits (31 for 0 and -1)
    "norm": ("local x:4 = vc ^ (vc s>> 31);\n  vr = lzcount(x) - 1;\n  if (x != 0) goto <nz>;\n  vr = 31;\n<nz>",
             "Z = vc == 0;\n  N = vc s< 0;"),
    "normh": ("local h:2 = vc:2;\n  local x:2 = h ^ (h s>> 15);\n  vr = lzcount(x) - 1;\n  if (x != 0) goto <nz>;\n  vr = 15;\n<nz>",
              "Z = h == 0;\n  N = h s< 0;"),
    # ffs/fls: position of the lowest/highest set bit (31 / 0 when none, with Z set)
    "ffs": ("vr = 31;\n  if (vc == 0) goto <z>;\n  vr = 31 - lzcount(vc & -vc);\n<z>", "Z = vc == 0;\n  N = vc s< 0;"),
    "fls": ("vr = 0;\n  if (vc == 0) goto <z>;\n  vr = 31 - lzcount(vc);\n<z>", "Z = vc == 0;\n  N = vc s< 0;"),
    "sath": ("vr = vc;\n  if (vc s<= 0x7fff) goto <h1>;\n  vr = 0x7fff;\n<h1>\n  if (vc s>= -0x8000) goto <h2>;\n  vr = 0xffff8000;\n<h2>\n  local sat:1 = vr != vc;",
             VS),
    "abss": ("vr = vc;\n  if (vc s>= 0) goto <pos>;\n  vr = -vc;\n  if (vc != 0x80000000) goto <pos>;\n  vr = 0x7fffffff;\n<pos>\n  local sat:1 = vc == 0x80000000;",
             VS),
    "negs": ("vr = -vc;\n  if (vc != 0x80000000) goto <ok>;\n  vr = 0x7fffffff;\n<ok>\n  local sat:1 = vc == 0x80000000;", VS),
    "fssqrt": ("vr = sqrt(vc);", ""),
}
SEM2P = {"fdsqrt": "w = sqrt(pc);"}

# flag-only compares: name b,c (F=1)
SEMF = {
    "tst": "local vr:4 = vb & vc;\n  " + ZN,
    "btst": "local vr:4 = vb & (1:4 << (vc & 31));\n  " + ZN,
    "cmp": "local vr:4 = vb - vc;\n  Z = vb == vc;\n  N = vr s< 0;\n  C = vb < vc;\n  V = sborrow(vb, vc);",
    "rcmp": "local vr:4 = vc - vb;\n  Z = vb == vc;\n  N = vr s< 0;\n  C = vc < vb;\n  V = sborrow(vc, vb);",
}

pcodeops = set()


def pcop(name):
    n = "op_" + re.sub(r"[^a-z0-9_]", "_", name)
    pcodeops.add(n)
    return n


def load_table():
    """ops_table.txt: 'maj sub sel F form mnemonic|shape|options[ W]' per decodable format"""
    groups = {}
    for line in open(os.path.join(HERE, "ops_table.txt")):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        head, shape, src = line.split("|")
        maj, sub, sel, F, form, mn = head.split(" ")
        key = (int(maj), int(sub, 16), sel, int(F))
        groups.setdefault(key, []).append((form, mn, shape.strip()))
    return groups


def parse_mn(mn):
    """mnemonic -> (base, .f printed, condition before .f)"""
    parts = mn.split(".")
    base = parts[0]
    rest = parts[1:]
    f = "f" in rest
    ccfirst = f and rest.index("f") > 0
    return base, (".f" if f else ""), ccfirst


def kind_of(shape):
    s = shape.replace(" ", "")
    if s in ("A,B,C", "A,B,n", "B,B,C", "B,B,n"):
        return "3"
    if s in ("AA,B,C", "AA,B,n", "BB,B,C", "BB,B,n"):
        return "p3"
    if s in ("AA,BB,CC", "AA,BB,n", "BB,BB,CC", "BB,BB,n", "BB,BB,C"):
        return "ppp"
    if s in ("B,C", "B,n"):
        return "2"
    if s in ("C", "n"):
        return "z1"
    if s == "":
        return "z0"
    return "special"


def form_pats(forms):
    zf = [f for f in forms if f.endswith("z")]
    forms = [f for f in forms if not f.endswith("z")]
    nc = [f for f in forms if f in ("0", "1", "2")]
    cc = [f for f in forms if f.startswith("3")]
    pats = ["l_fmt!=3"] if set(nc) == {"0", "1", "2"} else ["l_fmt=%s" % f for f in nc]
    pats += ["l_fmt=%s & l_a=0" % f[0] for f in zf]
    ccp = None
    if "3r" in cc and "3u" in cc:
        ccp = "l_fmt=3"
    elif "3r" in cc:
        ccp = "l_fmt=3 & l_M=0"
    elif "3u" in cc:
        ccp = "l_fmt=3 & l_M=1"
    return pats, ccp


def gen_general(groups):
    w("# ---------------------------------------------------------------------------------------------")
    w("# General operations of majors 4-7 (generated from tools/ops_table.txt)")
    special = set()
    for (maj, sub, sel, F), forms in sorted(groups.items()):
        sub_groups = {}
        for form, mn, shape in forms:
            base, fsuf, ccfirst = parse_mn(mn)
            k = kind_of(shape)
            if form.endswith("z") and k != "2":
                continue
            if sel != "-" and k == "2":
                k = "sop"
            sub_groups.setdefault((base, fsuf, ccfirst, k), []).append((form, shape))
        for (base, fsuf, ccfirst, k), fl in sorted(sub_groups.items()):
            r = dict(maj=maj, sub=sub, F=F, sel=sel, forms=[f for f, _ in fl], shapes=[s for _, s in fl])
            if k in ("3", "p3", "ppp") and sel == "-" and (maj, sub) not in SPECIAL_SUB:
                gen_alu3(r, base, fsuf, ccfirst, k)
            elif k == "2" and sel == "-" and maj >= 6:
                gen_flag2(r, base, fsuf, ccfirst)
            elif k == "sop" and sel.startswith("sop"):
                gen_sop(r, base, fsuf)
            elif k in ("z1", "z0") and sel.startswith("zop") and base != "dmb":
                gen_zop(r, base)
            else:
                special.add((maj, sub, sel, F, base, k))
    return special


# operations objdump rejects with a discarded destination (a = 62 / b = 62 in formats 2-3)
def load_limm_rejects():
    """limm_rejects.txt (probe_limm.py): format-0 long-immediate/discard combinations objdump rejects"""
    nab, nolimm = set(), set()
    for line in open(os.path.join(HERE, "limm_rejects.txt")):
        f = line.split()
        if len(f) < 4:
            continue
        key = (int(f[0]), int(f[1], 16), int(f[2]))
        if "a62" in f[3:]:
            nolimm.add(key)
        elif f[3:] == ["a62b62"]:
            nab.add(key)
    return nab, nolimm


NO_AB, NO_DISCARD = load_limm_rejects()

# sub-opcodes of major 4 written by hand in ARCv2_insn.sinc
SPECIAL_SUB = {(4, s) for s in (0x0a, 0x0b, 0x0c, 0x0d, 0x11, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                                0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36)}


def guard(r):
    return "l_major=%d & l_sub6=0x%02x & l_F=%d" % (r["maj"], r["sub"], r["F"])


def gen_alu3(r, base, fsuf, ccfirst, kind):
    g = guard(r)
    pats, ccp = form_pats(r["forms"])
    mn = base + fsuf
    mncc = (base + "^ccd" + ('^"%s"' % fsuf if fsuf else "")) if ccfirst else (mn + "^ccd")
    useF = fsuf == ".f"
    if kind == "3" and base in SEMP:
        res, flags = SEMP[base]
        body = ("local pb:8 = op_bd;\n  local pc:8 = op_cd;\n  " if "pb" in res else
                "local vb:4 = op_b;\n  local vc:4 = op_c;\n  ") + "local w:8;\n  " + res
        if useF and flags:
            body += "\n  " + flags
        body += "\n  op_a = w:4;\n  op_ahi = w(4);"
        disp = "op_a, op_b, op_c"
        cons = [("((%s & %s & op_a & op_ahi) ... & op_b & op_c & op_bd & op_cd)" % (g, p), disp, body) for p in pats]
        if ccp:
            cons.append(("((%s & %s & ccd & op_a & op_ahi) ... & op_b & op_c & op_bd & op_cd)" % (g, ccp), disp,
                         "if (!ccd) goto inst_next;\n  " + body))
    elif kind == "3":
        sem = SEM3.get(base)
        if sem:
            res, flags = sem
            body = "local vb:4 = op_b;\n  local vc:4 = op_c;\n  local vr:4;\n  " + res
            if useF and flags:
                body += "\n  " + flags
            body += "\n  op_a = vr;"
        else:
            body = "op_a = %s(op_b, op_c);" % pcop(base + fsuf)
        disp = "op_a, op_b, op_c"
        if (r["maj"], r["sub"], r["F"]) in NO_DISCARD:
            g += " & op_nd"
        if (r["maj"], r["sub"], r["F"]) in NO_AB:
            g += " & op_nab"
        cons = [("((%s & %s & op_a) ... & op_b & op_c)" % (g, p), disp, body) for p in pats]
        if ccp:
            cons.append(("((%s & %s & ccd & op_a) ... & op_b & op_c)" % (g, ccp), disp, "if (!ccd) goto inst_next;\n  " + body))
    else:
        if kind == "p3":
            src, ops, disp = "op_b & op_c", "op_b, op_c", "op_ap, op_b, op_c"
        else:
            src, ops, disp = "op_bp & op_cp", "op_bp, op_cp", "op_ap, op_bp, op_cp"
        if base in SEMP:
            res, flags = SEMP[base]
            body = ("local pb:8 = op_bp;\n  local pc:8 = op_cp;\n  " if kind == "ppp" else
                    "local vb:4 = op_b;\n  local vc:4 = op_c;\n  ") + "local w:8;\n  " + res
            if useF and flags:
                body += "\n  " + flags
            body += "\n  op_ap = w:4;\n  op_ao = w(4);"
        else:
            body = "local w:8 = %s(%s);\n  op_ap = w:4;\n  op_ao = w(4);" % (pcop(base + fsuf), ops)
        cons = [("((%s & %s & op_ap & op_ao) ... & %s)" % (g, p, src), disp, body) for p in pats]
        if ccp:
            # vadd2 format 3: c is one register (objdump accepts odd ones)
            cc_c1 = kind == "ppp" and any(s.replace(" ", "") == "BB,BB,C" for s in r["shapes"])
            c = ("((%s & %s & ccd & op_ap & op_ao) ... & %s)" % (g, ccp, src), disp, "if (!ccd) goto inst_next;\n  " + body)
            if cc_c1:
                c = tuple(x.replace("op_cp", "op_cp1") for x in c)
            cons.append(c)
    for i, (pat, disp, body) in enumerate(cons):
        m = mncc if (ccp and i == len(cons) - 1) else mn
        w(":%s %s is %s {" % (m, disp, pat))
        w("  " + body)
        w("}")
    if base in FCVT and "1" in r["forms"] and not useF:
        for code in (0, 2, 4, 9, 11):
            body = fcvt_body(base, code)
            if body:
                w(":%s op_a, op_b, \"%s\" is ((%s & l_fmt=1 & l_u6=%d & op_a & op_ahi) ... & op_b & op_bd) {"
                  % (mn, hex(code) if code else "0", g, code))
                w("  " + body)
                w("}")


def gen_flag2(r, base, fsuf, ccfirst):
    g = guard(r)
    pats, ccp = form_pats(r["forms"])
    if base in FCMP:
        if FCMP[base] == 4:
            body = "local b:4 = op_b;\n  local c:4 = op_c;"
            extra = ""
        else:
            body = "local b:8 = op_bd;\n  local c:8 = op_cd;"
            extra = " & op_bd & op_cd"
        body += "\n  V = nan(b) || nan(c);\n  Z = b f== c;\n  N = b f< c;\n  C = b f< c;"
    else:
        body = "%s(op_b, op_c);" % pcop(base)
        extra = ""
    for p in pats:
        w(":%s op_b, op_c is ((%s & %s) ... & op_b & op_c%s) {" % (base, g, p, extra))
        w("  " + body)
        w("}")
    if ccp:
        w(":%s^ccd op_b, op_c is ((%s & %s & ccd) ... & op_b & op_c%s) {" % (base, g, ccp, extra))
        w("  if (!ccd) goto inst_next;")
        w("  " + body)
        w("}")


def sop_src(forms):
    out = []
    if "0" in forms:
        out.append(("l_fmt=0", "l_c_src"))
    if "1" in forms:
        out.append(("l_fmt=1", "l_u6"))
    return out


def gen_sop(r, base, fsuf):
    g = "l_major=%d & l_sub6=0x2f & l_F=%d & l_a=0x%s" % (r["maj"], r["F"], r["sel"][3:])
    useF = fsuf == ".f"
    for fmt, src in sop_src(r["forms"]):
        cv = "l_c_src" if src == "l_c_src" else "csrc"
        pre = "" if src == "l_c_src" else ""
        if base in SEM2P:
            body = "local pc:8 = op_cd;\n  local w:8;\n  %s\n  l_b_dst = w:4;\n  op_bhi = w(4);" % SEM2P[base]
            if src == "l_c_src":
                w(":%s%s l_b_dst, l_c_src is (%s & %s & l_b_dst & op_bhi) ... & l_c_src & op_cd {" % (base, fsuf, g, fmt))
            else:
                w(":%s%s l_b_dst, l_u6 is (%s & %s & l_b_dst & l_u6 & op_bhi) ... & op_cd {" % (base, fsuf, g, fmt))
            w("  " + body)
            w("}")
            continue
        sem = SEM2.get(base)
        csrc = "l_c_src" if src == "l_c_src" else "u6v"
        if sem:
            res, flags = sem
            body = "local vc:4 = %s;\n  local vr:4;\n  %s" % (csrc, res)
            if useF and flags:
                body += "\n  " + flags
            body += "\n  l_b_dst = vr;"
        else:
            body = "l_b_dst = %s(%s);" % (pcop(base + fsuf), csrc)
        if src == "l_c_src":
            w(":%s%s l_b_dst, l_c_src is (%s & %s & l_b_dst) ... & l_c_src {" % (base, fsuf, g, fmt))
        else:
            w(":%s%s l_b_dst, l_u6 is %s & %s & l_b_dst & l_u6 {" % (base, fsuf, g, fmt))
            body = "local u6v:4 = l_u6;\n  " + body
        w("  " + body)
        w("}")


def gen_zop(r, base):
    b = int(r["sel"][3:], 16)
    g = "l_major=%d & l_sub6=0x2f & l_F=%d & l_a=0x3f & l_b_hi=%d & l_b_lo=%d" % (r["maj"], r["F"], b >> 3, b & 7)
    shapes = set(r["shapes"])
    op = pcop(base)
    for fmt, src in sop_src(r["forms"]):
        if shapes == {""}:
            w(":%s is %s & %s {" % (base, g, fmt))
            w("  %s();" % op)
        elif src == "l_c_src":
            w(":%s l_c_src is (%s & %s) ... & l_c_src {" % (base, g, fmt))
            w("  %s(l_c_src);" % op)
        else:
            w(":%s l_u6 is %s & %s & l_u6 {" % (base, g, fmt))
            w("  %s(l_u6:4);" % op)
        w("}")


# ---------------------------------------------------------------------------------------------
def aux_table(aux):
    w("# Auxiliary register operand of lr/sr/aex: [c], [limm], [u6], [s12], with objdump's names")
    w('auxop: "["^l_c_r^"]" is (l_fmt=0 | (l_fmt=3 & l_M=0)) & l_c_r { local a:4 = l_c_r << 2; export *[AUX_REGS_BASE]:4 a; }')
    for n, name in sorted(aux.items()):
        w('auxop: "[%s]" is (l_fmt=0 | (l_fmt=3 & l_M=0)) & l_c=62 ; limm_hi=0x%x ; limm_lo=0x%x { local a:4 = 0x%x; export *[AUX_REGS_BASE]:4 a; }'
          % (name, n >> 16, n & 0xffff, 4 * n))
    w('auxop: "["^limm^"]" is (l_fmt=0 | (l_fmt=3 & l_M=0)) & l_c=62 ; limm { local a:4 = limm << 2; export *[AUX_REGS_BASE]:4 a; }')
    w('auxop: "["^l_u6_aux^"]" is (l_fmt=1 | (l_fmt=3 & l_M=1)) & l_u6_aux & l_u6 { local a:4 = l_u6 << 2; export *[AUX_REGS_BASE]:4 a; }')
    for n, name in sorted(aux.items()):
        if n < 2048:
            w('auxop: "[%s]" is l_fmt=2 & l_s6hi=%d & l_u6=%d { local a:4 = 0x%x; export *[AUX_REGS_BASE]:4 a; }' % (name, n >> 6, n & 63, 4 * n))
    w('auxop: "["^s12^"]" is l_fmt=2 & l_u6 & l_s6hi [ s12 = (l_s6hi << 6) | l_u6; ] { local a:4 = s12 << 2; export *[AUX_REGS_BASE]:4 a; }')
    w()


def enter_leave():
    w("# enter_s / leave_s [r13-r(12+u),fp,blink(,pcl)] (major 0x18, bits 7..5 = 7 / 6, bit 0 = 0).")
    w("# Frame layout from high to low addresses: fp, r(12+u) ... r13, blink; enter_s then sets fp = sp.")
    for u in range(15):
        for fp in (0, 1):
            for bl in (0, 1):
                regs = []
                if u == 1:
                    regs.append("r13")
                elif u > 1:
                    regs.append("r13-%s" % REGS[12 + u])
                if fp:
                    regs.append("fp")
                if bl:
                    regs.append("blink")
                pat = "s_major=0x18 & s_bit0=0 & s_ent_u=%d & s_ent_fp=%d & s_ent_blink=%d" % (u, fp, bl)
                w(':enter_s "[%s]" is %s & s_sub7_5=7 & s_ent_pcl=0 {' % (",".join(regs), pat))
                if fp:
                    w("  push4(fp);")
                for k in range(u, 0, -1):
                    w("  push4(%s);" % REGS[12 + k])
                if bl:
                    w("  push4(blink);")
                if fp:
                    w("  fp = sp;")
                w("}")
                for pc in (0, 1):
                    w(':leave_s "[%s]" is %s & s_sub7_5=6 & s_ent_pcl=%d {' % (",".join(regs + (["pcl"] if pc else [])), pat, pc))
                    if fp:
                        w("  sp = fp;")
                    if bl:
                        w("  pop4(blink);")
                    for k in range(1, u + 1):
                        w("  pop4(%s);" % REGS[12 + k])
                    if fp:
                        w("  pop4(fp);")
                    if pc:
                        w("  return [blink];")
                    w("}")
    w()


def main():
    aux = header()
    operands(aux)
    with open(os.path.join(OUT, "ARCv2_defs.sinc"), "w") as f:
        f.write("\n".join(out) + "\n")
    out.clear()
    w("# GENERATED by tools/gen_arcv2.py from tools/ops_table.txt and tools/auxregs.txt; do not edit.")
    w("with : phase=1 {")
    aux_table(aux)
    enter_leave()
    special = gen_general(load_table())
    w("} # end of generated instructions")
    ops = "\n".join(out) + "\n"
    defs_pcodeops = "".join("define pcodeop %s;\n" % p for p in sorted(pcodeops))
    with open(os.path.join(OUT, "ARCv2_ops.sinc"), "w") as f:
        f.write(ops.replace("with : phase=1 {", defs_pcodeops + "\nwith : phase=1 {", 1))
    for name, endian in (("ARCv2.slaspec", "little"), ("ARCv2_be.slaspec", "big")):
        with open(os.path.join(OUT, name), "w") as f:
            f.write("# ARCv2 (ARC EM/HS), %s-endian. GENERATED by tools/gen_arcv2.py.\n" % endian)
            f.write("define endian=%s;\n@define ENDIAN \"%s\"\n" % (endian, endian))
            f.write('@include "ARCv2_defs.sinc"\n@include "ARCv2_ops.sinc"\n@include "ARCv2_insn.sinc"\n')
    sys.stderr.write("special (hand-written) entries: %d\n" % len(special))
    for x in sorted(special):
        sys.stderr.write("   %s\n" % (x,))


if __name__ == "__main__":
    main()
