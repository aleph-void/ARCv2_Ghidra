# Ghidra-Rare notes: ARCv2 (ARC EM/HS) — work in progress

This is the Ghidra-Rare fork of [sony/ARCv2_Ghidra](https://github.com/sony/ARCv2_Ghidra)
(Roman Korkikian, Sony). It is **not yet verified to the Ghidra-Rare bar**; this file records the
state of the work. Authors and changes are in [CREDITS.md](CREDITS.md).

## Testing

```
test/decode-diff.sh <workdir>            # after test/gen_corpus.py <workdir>; SLOTDIS = test/slotdis.c
test/fetch-real-samples.sh <dir>          # Bootlin arcle-hs38 uClibc libraries and programs
test/real-binaries.sh <dir> <workdir>     # import, analyse, decompile, compare with objdump
```

## Current results

Decode vs objdump 2.45 (`-m arc:ARCv2`, a slot agrees with either `-M cpu=hs` or `cpu=em`):

| Corpus | Semantic agreement (upstream) | Now |
|---|---|---|
| every 16-bit halfword (65,536 slots) | 87.6% | 91.1% |
| every 32-bit high halfword x low 6 bits (1,048,576) | 62.1% | 86.2% |
| 50,000 random slots | 88.1% | 91.4% |
| unique instructions of the Bootlin HS38 libuClibc + libgcc_s (35,564) | 81.6% | 99.4% |

Real code (Bootlin arcle-hs38 uClibc 2026.08-1, auto-detected as `ARCv2:LE:32:default`):
libuClibc 92,375 instructions (upstream: 13,464), 255 bad instructions (upstream 1,433),
98.3% semantic agreement with objdump at the same addresses, 2,179 of 2,218 functions decompile;
libgcc_s 11,058 instructions, 8 bad instructions, 99.2%; ld-uClibc, getconf, iconv, ldconfig 0 bad
instructions; all relocations applied.

## Not done yet (doesn't work)

- `llock`/`scond` (and `llockd`/`scondd`), `ldh.as`/`ld.as` with a register index (decoded as
  an immediate), 16-bit `mov_s`/`cmp_s`/`add_s` 3-bit immediates (sign), `ex`/`jl` operand
  brackets, `lp<cc>` names, and the remaining real-code differences.
- About 200 objdump mnemonics are not decoded: saturating arithmetic (`adds`, `subs`, `asls`,
  ...), `set<cc>`, the multiply/MAC/DSP families (`mac`, `mpyd`, `dmpy*`, `qmpy*`, `dmach*`, ...),
  the SIMD `v*` instructions, FPU instructions, and others; the upstream `apex_alu_dop` decodes
  encodings objdump rejects.
- No emulator tests and no every-entry test yet; no big-endian language (ARCv2 HS cores can be
  big-endian).
