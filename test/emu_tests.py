#!/usr/bin/env python3
"""P-code semantic tests for Ghidra's emulator (EmuCheck.java), assembled with GNU as (ARCv2).

  emu_tests.py <outdir> <bin-prefix> [--break N]
      <bin-prefix>: GNU toolchain prefix with ARCv2 support, e.g. .../bin/arc-elf32- (as, ld,
      objcopy, nm; binutils 2.45 built for arc-elf32 accepts -mcpu=hs38 and -EB)
  -> emu_<e>.bin and emu_<e>.txt for e in le, be

Each test is a short sequence at its own 0x100-aligned address followed by a "stop" label.
The .txt files have one line per test:
  <name> <start-hex> <stop-hex> <init: reg=val,...|-> <expect: reg=val,...>
Values are hex. A data area at 0x8000 (initially "D0" below) is part of the image. Every
expected value was worked out by hand from the instruction descriptions, not from Ghidra.
--break N makes the expectation of test N wrong (to show that the check can fail).
"""
import os
import re
import subprocess
import sys

out, pre = sys.argv[1], sys.argv[2]
brk = int(sys.argv[sys.argv.index("--break") + 1]) if "--break" in sys.argv else -1
M = 0xffffffff

# data area at 0x8000: 16 bytes 00 01 02 ... 0f, then 0x80 0xff 0x7f 0x00, then zeros
D0 = bytes(range(16)) + bytes([0x80, 0xff, 0x7f, 0x00]) + bytes(44)


def word(addr, e):
    b = D0[addr - 0x8000:addr - 0x8000 + 4]
    return int.from_bytes(b, "little" if e == "le" else "big")


def half(addr, e):
    b = D0[addr - 0x8000:addr - 0x8000 + 2]
    return int.from_bytes(b, "little" if e == "le" else "big")


# (name, asm, init, expect); expect may be a function of the byte order
T = [
    ("add", "add r0,r1,r2", {"r1": 5, "r2": 7}, {"r0": 12}),
    ("add.f_carry", "add.f r0,r1,r2", {"r1": M, "r2": 1}, {"r0": 0, "Z": 1, "N": 0, "C": 1, "V": 0}),
    ("add.f_overflow", "add.f r0,r1,r2", {"r1": 0x7fffffff, "r2": 1},
     {"r0": 0x80000000, "Z": 0, "N": 1, "C": 0, "V": 1}),
    ("sub.f_borrow", "sub.f r0,r1,r2", {"r1": 1, "r2": 2}, {"r0": M, "Z": 0, "N": 1, "C": 1, "V": 0}),
    ("adc_sbc", "add.f r0,r1,r2\n adc r3,r4,r5\n sub.f r6,r1,r1\n sbc r7,r4,r5",
     {"r1": M, "r2": 1, "r4": 0x10, "r5": 0x20}, {"r0": 0, "r3": 0x31, "r7": 0xfffffff0, "C": 0, "Z": 1}),
    ("logic", "and r3,r1,r2\n or r4,r1,r2\n xor r5,r1,r2\n bic r6,r1,r2\n not r7,r1",
     {"r1": 0xf0f0, "r2": 0xff00}, {"r3": 0xf000, "r4": 0xfff0, "r5": 0x0ff0, "r6": 0x00f0, "r7": 0xffff0f0f}),
    ("max_min", "max r3,r1,r2\n min r4,r1,r2", {"r1": 0xfffffffb, "r2": 3}, {"r3": 3, "r4": 0xfffffffb}),
    ("bitops", "bset r2,r1,8\n bclr r3,r1,0\n bxor r4,r1,1\n bmsk r5,r1,1\n bmskn r6,r1,1\n btst r1,4",
     {"r1": 0x0f}, {"r2": 0x10f, "r3": 0xe, "r4": 0xd, "r5": 3, "r6": 0xc, "Z": 1}),
    ("addn_subn", "add1 r3,r1,r2\n add2 r4,r1,r2\n add3 r5,r1,r2\n sub3 r6,r1,r2\n rsub r7,r1,r2",
     {"r1": 1, "r2": 2}, {"r3": 5, "r4": 9, "r5": 17, "r6": 0xfffffff1, "r7": 1}),
    ("cmp_cond", "cmp r1,r2\n mov.eq r3,1\n mov.ne r4,1\n add.lt r5,r5,1\n rcmp r1,r2\n mov.hi r6,1",
     {"r1": 5, "r2": 5}, {"r3": 1, "r4": 0, "r5": 0, "r6": 0, "Z": 1}),
    ("limm", "mov r0,0x12345678\n add r1,r0,0x11111111\n add r2,0x10,r0", {},
     {"r0": 0x12345678, "r1": 0x23456789, "r2": 0x12345688}),
    ("shifts", "asl r3,r1,4\n lsr r4,r1,5\n asr r5,r1,4\n ror r6,r1,4\n asl.f r7,r1,1",
     {"r1": 0x80000001}, {"r3": 0x10, "r4": 0x04000000, "r5": 0xf8000000, "r6": 0x18000000,
                          "r7": 2, "C": 1, "Z": 0, "N": 0}),
    ("rotate_carry", "asr.f r3,r1\n rrc r4,r2\n rlc r5,r2\n rol r6,r1\n lsl16 r7,r2",
     {"r1": 0x80000003, "r2": 0x00010002},
     {"r3": 0xc0000001, "C": 1, "r4": 0x80008001, "r5": 0x00020005, "r6": 0x00000007, "r7": 0x00020000}),
    ("multiply", "mpy r3,r1,r2\n mpym r4,r1,r2\n mpymu r5,r1,r2\n mpyu r6,r1,r2\n mpyw r7,r1,r2",
     {"r1": 0xfffffffe, "r2": 0x30000},
     {"r3": 0xfffa0000, "r4": M, "r5": 0x2ffff, "r6": 0xfffa0000, "r7": 0}),
    ("divide", "div r3,r1,r2\n divu r4,r1,r2\n rem r5,r1,r2\n remu r6,r1,r2",
     {"r1": 0xfffffff9, "r2": 2}, {"r3": 0xfffffffd, "r4": 0x7ffffffc, "r5": M, "r6": 1}),
    ("saturate", "adds.f r3,r1,r2\n subs r4,r5,r2\n abss r6,r5\n negs r7,r5",
     {"r1": 0x7fffffff, "r2": 1, "r5": 0x80000000},
     {"r3": 0x7fffffff, "V": 1, "r4": 0x80000000, "r6": 0x7fffffff, "r7": 0x7fffffff}),
    ("setcc", "seteq r3,r1,r2\n setne r4,r1,r2\n setlt r5,r1,r2\n setlo r6,r1,r2\n setgt r7,r1,r2",
     {"r1": 0xfffffffe, "r2": 3}, {"r3": 0, "r4": 1, "r5": 1, "r6": 0, "r7": 0}),
    ("extend", "sexb r2,r1\n sexh r3,r1\n extb r4,r1\n exth r5,r1\n abs r6,r7\n neg r8,r7",
     {"r1": 0x80ff, "r7": 0xfffffff9}, {"r2": M, "r3": 0xffff80ff, "r4": 0xff, "r5": 0x80ff, "r6": 7, "r8": 7}),
    ("norm_ffs_fls", "norm r3,r1\n norm r4,r2\n ffs r5,r1\n fls r6,r1\n normh r7,r8",
     {"r1": 0x00000400, "r2": 0xffffff00, "r8": 0x0001}, {"r3": 20, "r4": 23, "r5": 10, "r6": 10, "r7": 14}),
    ("swap", "swap r3,r1\n swape r4,r1\n xbfu r5,r1,0x48", {"r1": 0x12345678},
     {"r3": 0x56781234, "r4": 0x78563412, "r5": 6}),
    ("ld_st_modes", "mov r1,0x8000\n ld r3,[r1,4]\n ld.aw r4,[r1,8]\n ldh.ab r5,[r1,2]\n ld.as r6,[r1,-1]",
     {}, lambda e: {"r1": 0x800a, "r3": word(0x8004, e), "r4": word(0x8008, e), "r5": half(0x8008, e),
                    "r6": word(0x8006, e)}),
    ("ld_signed", "mov r1,0x8000\n ldb.x r3,[r1,16]\n ldb r4,[r1,18]\n ldh.x r5,[r1,16]", {},
     lambda e: {"r3": 0xffffff80, "r4": 0x7f, "r5": 0xffffff80 if e == "le" else 0xffff80ff}),
    ("ld_reg_reg", "mov r1,0x8000\n mov r2,2\n ld.as r3,[r1,r2]\n ldb r4,[r1,r2]\n ldh.as r5,[r1,r2]", {},
     lambda e: {"r3": word(0x8008, e), "r4": 2, "r5": half(0x8004, e)}),
    ("st_modes", "mov r1,0x8020\n st r2,[r1]\n stb.ab r3,[r1,1]\n sth.aw r3,[r1,3]\n st -5,[r1,4]\n"
     " ld r4,[0x8020]\n ld r5,[0x8028]", {"r2": 0x11223344, "r3": 0x5566},
     lambda e: {"r1": 0x8024, "r4": (0x11223366 if e == "le" else 0x66223344), "r5": 0xfffffffb}),
    ("ldd_std", "mov r1,0x8030\n std r2,[r1]\n ldd r4,[r1]\n ld r6,[r1,4]", {"r2": 0xaaaa, "r3": 0xbbbb},
     {"r4": 0xaaaa, "r5": 0xbbbb, "r6": 0xbbbb}),
    ("16bit_alu", "mov_s r0,5\n add_s r1,r0,3\n sub_s r2,r1,r0\n asl_s r3,r0,2\n neg_s r12,r0\n"
     " add_s r0,r0,-1\n cmp_s r0,4\n mov_s.ne r13,7\n sub_s.ne r14,r14,r14",
     {"r13": 1, "r14": 9}, {"r0": 4, "r1": 8, "r2": 3, "r3": 0x14, "r12": 0xfffffffb, "r13": 1, "r14": 9, "Z": 1}),
    ("16bit_ld_st", "mov_s r0,0x8000\n ld_s r1,[r0,4]\n ldb_s r2,[r0,3]\n ldh_s r3,[r0,2]\n"
     " mov_s r12,0x8030\n st_s r1,[r12,0]\n ld_s r13,[r12,0]", {},
     lambda e: {"r1": word(0x8004, e), "r2": 3, "r3": half(0x8002, e), "r13": word(0x8004, e)}),
    ("push_pop", "mov sp,0x8040\n push_s r1\n push_s blink\n pop_s r2\n pop_s r3",
     {"r1": 0x11, "blink": 0x22}, {"sp": 0x8040, "r2": 0x22, "r3": 0x11}),
    ("enter_leave", "mov sp,0x8040\n mov fp,0x77\n enter_s [r13-r14,fp,blink]\n mov r5,sp\n mov r6,fp\n"
     " ld r7,[sp,4]\n ld r8,[sp,12]\n ld r9,[sp,0]\n mov r13,0\n mov r14,0\n leave_s [r13-r14,fp,blink]",
     {"r13": 0x13, "r14": 0x14, "blink": 0xb1},
     {"sp": 0x8040, "fp": 0x77, "r5": 0x8030, "r6": 0x8030, "r7": 0x13, "r8": 0x77, "r9": 0xb1,
      "r13": 0x13, "r14": 0x14, "blink": 0xb1}),
    ("branch_cc", "cmp r1,r2\n blt 1f\n mov r3,1\n1: bge 2f\n mov r4,1\n2: brne r1,r2,3f\n mov r5,1\n3: bbit1 r1,0,4f\n mov r6,1\n4:",
     {"r1": 5, "r2": 7}, {"r3": 0, "r4": 1, "r5": 0, "r6": 0}),
    ("branch_16bit", "cmp_s r0,0\n beq_s 1f\n mov_s r1,1\n1: breq_s r0,0,2f\n mov_s r2,1\n2: bhi_s 3f\n mov_s r3,1\n3:",
     {"r0": 0}, {"r1": 0, "r2": 0, "r3": 1}),
    ("delay_slot", "mov r3,2f\n b.d 1f\n mov r1,5\n mov r2,6\n1: j_s.d [r3]\n add r4,r1,1\n mov r5,7\n2:",
     {}, {"r1": 5, "r2": 0, "r4": 6, "r5": 0}),
    ("call_return", "bl 1f\n mov r2,1\n b 2f\n1: mov r1,9\n j_s [blink]\n2:", {}, {"r1": 9, "r2": 1}),
    ("jl_limm", "jl 1f\n b 2f\n1: mov r1,3\n j [blink]\n2:", {}, {"r1": 3}),
    ("loop", "mov lp_count,4\n mov r1,0\n lp 1f\n add r1,r1,3\n add r2,r2,1\n1: mov r3,r1",
     {}, {"r1": 12, "r2": 4, "r3": 12, "lp_count": 0}),
    ("dbnz", "mov r1,3\n1: add r2,r2,2\n dbnz r1,1b", {}, {"r1": 0, "r2": 6}),
    ("branch_index", "mov r1,2\n bi [r1]\n b 1f\n b 2f\n b 3f\n1: mov r2,1\n2: mov r3,1\n3: mov r4,1",
     {}, {"r2": 0, "r3": 0, "r4": 1}),
    ("atomic", "mov r1,0x8030\n mov r2,0x41\n st r2,[r1]\n llock r3,[r1]\n mov r4,0x42\n scond r4,[r1]\n"
     " ld r5,[r1]\n mov r6,0x43\n ex r6,[r1]\n ld r7,[r1]", {},
     {"r3": 0x41, "r5": 0x42, "Z": 1, "r6": 0x42, "r7": 0x43}),
    ("flag_lr", "flag 0x900\n lr r1,[status32]\n mov.eq r2,1\n mov.c r3,1", {},
     {"r1": 0x900, "Z": 1, "C": 0, "V": 1, "r2": 1, "r3": 0}),
    ("fpu_single", "fsadd r3,r1,r2\n fsmul r4,r1,r2\n fssub r5,r1,r2\n fsdiv r6,r2,r1",
     {"r1": 0x40000000, "r2": 0x3f800000},   # 2.0, 1.0
     {"r3": 0x40400000, "r4": 0x40000000, "r5": 0x3f800000, "r6": 0x3f000000}),
    # double precision on even/odd register pairs (even = low word): 1.0 + 2.0, 1.0 * 2.0, sqrt(2.0)
    ("fpu_double", "fdadd r4,r6,r8\n fdmul r10,r6,r8\n fdsqrt r12,r8",
     {"r6": 0, "r7": 0x3ff00000, "r8": 0, "r9": 0x40000000},
     {"r4": 0, "r5": 0x40080000, "r10": 0, "r11": 0x40000000, "r12": 0x667f3bcd, "r13": 0x3ff6a09e}),
    ("mpyd", "mpyd r4,r1,r2\n mpydu r6,r1,r2", {"r1": 0xfffffffe, "r2": 0x40000000},
     {"r4": 0x80000000, "r5": 0xffffffff, "r6": 0x80000000, "r7": 0x3fffffff}),
]


def build(e):
    src = [" .text"]
    for i, (name, asm, _, _) in enumerate(T):
        src.append(f" .org {i * 0x100:#x}\nT{i}: {asm}\nS{i}: nop\n")
    src.append(" .org 0x8000\n .byte " + ",".join(str(b) for b in D0))
    base = f"{out}/emu_{e}"
    open(base + ".s", "w").write("\n".join(src) + "\n")
    eb = ["-EB"] if e == "be" else ["-EL"]
    subprocess.run([pre + "as", "-mcpu=hs38_linux"] + eb + [base + ".s", "-o", base + ".o"], check=True)
    subprocess.run([pre + "ld"] + eb + ["-Ttext=0", "-e", "0", base + ".o", "-o", base + ".elf"], check=True)
    subprocess.run([pre + "objcopy", "-O", "binary", base + ".elf", base + ".bin"], check=True)
    syms = {}
    for line in subprocess.run([pre + "nm", base + ".elf"], capture_output=True, text=True).stdout.split("\n"):
        m = re.match(r"([0-9a-f]+) \w (\w+)$", line)
        if m:
            syms[m.group(2)] = int(m.group(1), 16)
    with open(base + ".txt", "w") as f:
        for i, (name, _, init, exp) in enumerate(T):
            exp = exp(e) if callable(exp) else dict(exp)
            if i == brk:
                r = next(iter(exp))
                exp[r] ^= 1
            ini = ",".join(f"{r}={v & M:x}" for r, v in init.items()) or "-"
            f.write(f"{name} {syms['T%d' % i]:x} {syms['S%d' % i]:x} {ini} "
                    + ",".join(f"{r}={v & M:x}" for r, v in exp.items()) + "\n")
    for x in (".o", ".elf"):
        os.remove(base + x)


for e in ("le", "be"):
    build(e)
print(f"{len(T)} tests")
