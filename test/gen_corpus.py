#!/usr/bin/env python3
"""Decode-test corpora for the ARCv2 module, 8-byte slots (an instruction and room for a long
immediate), little-endian (32-bit instructions and long immediates are stored as two
halfwords, high halfword first).

  gen_corpus.py <outdir>
  -> half.bin   every 16-bit first halfword (65,536 slots), random fill
     w32.bin    every high halfword of a 32-bit instruction (major opcodes 0-7, 16,384 values)
                x every value of bits 5..0 of the low halfword, random bits 15..6 (1,048,576)
     fuzz.bin   50,000 random slots
The encodings are generated from the field layout alone; nothing is taken from binutils.
"""
import os
import random
import struct
import sys

out = sys.argv[1]
R = random.Random(20261027)


def rnd16():
    return R.getrandbits(16)


def save(name, slots):
    with open(os.path.join(out, name + ".bin"), "wb") as f:
        for hs in slots:
            f.write(struct.pack("<HHHH", *hs))


save("half", [(h, rnd16(), rnd16(), rnd16()) for h in range(0x10000)])
save("w32", [(hi, (R.getrandbits(10) << 6) | lo, rnd16(), rnd16()) for hi in range(0x4000) for lo in range(64)])
save("fuzz", [(rnd16(), rnd16(), rnd16(), rnd16()) for _ in range(50000)])
