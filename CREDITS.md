# Credits: ARCv2 (ARC EM/HS) module

## Upstream

| | |
|---|---|
| Source | [sony/ARCv2_Ghidra](https://github.com/sony/ARCv2_Ghidra), commit `a45097c` "Initial commit" (2023-04-26) |
| License | Apache License 2.0 (`LICENSE`) |
| Original author | Roman Korkikian (Sony; commits as "Roman Korkikian"): the ARCv2 SLEIGH specification, cspec, pspec with the auxiliary register symbols, DWARF map, ldefs, opinion, the AES example and README |
| Not used | [korkikian/ARCv2](https://github.com/korkikian/ARCv2): the same author's earlier copy, without a license; not compared, nothing taken |
| Reused from Ghidra-Rare | the ELF relocation handler and PLT extension of Ghidra-Rare's ARCompact module (aleph-void/ghidra-arcompact, Apache-2.0), adapted to EM_ARC_COMPACT2; the test harness (DumpSlots, CoverageCheck, EmuCheck, RealCheck, slotdis.c) of the same module |
| Test oracle | GNU binutils 2.45 (`objdump -m arc:ARCv2 -M cpu=hs`, `cpu=em`, `cpu=hs,dsp`, `cpu=em,dsp`; GPL-3.0), run as a black box; GCC 15.3 of Bootlin's arcle-hs38 toolchain, run as a black box (see GHIDRA-RARE.md) |

The upstream repository is the base of the fork; every Ghidra-Rare change is a separate commit.
No binutils or GCC source was read: the encodings come from objdump's output, the operation of
the instructions from the descriptions in upstream's specification and from GCC's output.

## Ghidra-Rare changes

1. **ELF opinion**: e_machine 195 (EM_ARC_COMPACT2). Upstream claimed 93, which is ARCompact
   (ARC600/ARC700) and never matched ARCv2 binaries.
2. **Generated specification** (`tools/gen_arcv2.py`): upstream's hand-written `ARCv2.slaspec`
   (5,600 lines, 62% agreement with objdump over the 32-bit encoding space) is replaced by
   - `ARCv2_defs.sinc` (generated): tokens for both byte orders, registers and register pairs,
     operand and condition tables;
   - `ARCv2_ops.sinc` (generated): the general operations of majors 4-7 from
     `tools/ops_table.txt` (a black-box survey of objdump, `tools/probe_ops2.py`), the
     auxiliary register names (`tools/auxregs.txt`, `probe_aux.py`), the long-immediate forms
     objdump rejects (`tools/limm_rejects.txt`, `probe_limm.py`), enter_s/leave_s;
   - `ARCv2_insn.sinc` (hand-written): branches, calls, compare-and-branch, loads and stores in
     every address mode, jumps, `lp`, `lr`/`sr`/`aex`, register-register loads, `ldi`, `bi`/`bih`,
     `llock`/`scond`/`ex`, `dbnz`, the 16-bit instructions.
3. **Big-endian language** `ARCv2:BE:32:default` (`ARCv2_be.slaspec`).
4. **Coverage**: every instruction objdump decodes for HS and EM, including the MPY/DSP, SIMD,
   FPU (single and double precision), FPX double-precision assist and QuarkSE extensions; upstream
   decoded about 170 mnemonics and some (`apex_alu_dop`) that objdump does not.
5. **Syntax** as objdump prints it: condition names and order (`.f.eq`, `c`/`nc`/`v`/`nv`,
   `bl.nj`), `.di`/`.aa`/`.x` order, `[pcl,...]`, register pairs (`r4r5`), `0` for a discarded
   destination, the auxiliary register names, `neg`, `nop`, `dmb`, `enter_s [r13-r16,fp,blink]`.
6. **Semantics**: flags of every base operation; saturating arithmetic; `div`/`rem`; `xbfu`,
   `bmskn`, `set<cc>`, `norm`/`ffs`/`fls`; 64-bit `mpyd`/`mpydu`, `ldd`/`std`, `llockd`/`scondd`;
   FPU single and double precision arithmetic, square root, fused multiply-add with the
   accumulator, compares and conversions; delay slots (calls return after the slot);
   zero-overhead loops; `ldi`/`jli_s`/`bi`/`bih`/`sjli` through their tables; upstream's
   `enter_s`/`leave_s` frame layout (confirmed against GCC's unwind tables).
7. **Fixes found by real code** (before the rewrite, kept): `pcl` as a source operand, `.as`
   offsets, `ldd`/`std` pairs, `sub_s.ne`, `stb_s [sp,u7]`, `lp_count`.
8. **ELF support** (Java): relocation handler and PLT markup (adapted from ARCompact).
9. **Spec files**: DWARF map with the objdump register names (r58/r59, lp_count); ldefs for both
   byte orders.
10. **Build**: stand-alone extension build; the generated `.sla` files are not tracked; release
    zips leave out `test/` and `tools/`.
11. **Tests** (`test/`): decode corpora and comparison, every-entry test, 45 emulator cases,
    real-binary analysis, fetch script, `run-tests.sh`. See [GHIDRA-RARE.md](GHIDRA-RARE.md).
