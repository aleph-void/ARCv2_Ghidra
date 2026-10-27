# Credits: ARCv2 (ARC EM/HS) module

This module is a community SLEIGH module that Ghidra-Rare imported and is testing and fixing.

## Upstream

| | |
|---|---|
| Source | [sony/ARCv2_Ghidra](https://github.com/sony/ARCv2_Ghidra), commit `a45097c` "Initial commit" (2023-04-26) |
| License | Apache License 2.0 (`LICENSE`) |
| Original author | Roman Korkikian (Sony; commits as "Roman Korkikian"): the ARCv2 SLEIGH specification, cspec, pspec with the auxiliary registers, DWARF map, ldefs, opinion, the AES example |
| Not used | [korkikian/ARCv2](https://github.com/korkikian/ARCv2): the same author's earlier copy, without a license; not compared, nothing taken |
| Reused from Ghidra-Rare | the ELF relocation handler and PLT extension of Ghidra-Rare's ARCompact module (aleph-void/ghidra-arcompact, Apache-2.0), adapted to EM_ARC_COMPACT2 |
| Test oracle | GNU binutils 2.45 (`objdump -m arc:ARCv2 -M cpu=em` / `cpu=hs`), run as a black box |

The upstream repository is the base of the fork; every Ghidra-Rare change is a separate commit.

## Ghidra-Rare changes (so far)

1. **ELF opinion**: e_machine 195 (EM_ARC_COMPACT2). Upstream claimed 93, which is ARCompact
   (ARC600/ARC700, Ghidra-Rare's ARCompact module) and never matched ARCv2 binaries.
2. **Condition codes** as objdump prints them (`.eq` after `.f`, `c`/`nc`/`v`/`nv` instead of
   `lo`/`hs`/`vs`/`vc`, no `al`) and the extension conditions 0x10-0x1f (`nj`, `nm`, `nt`,
   unnamed others) as pcodeops; branch prediction hints `.t`/`.nt` on compare-and-branch.
3. **Decoding fixes from real code**: `pcl` as a source operand (pcl-relative `ld`/`add` with a
   long immediate were rejected), `.as` offsets shown unscaled, `ldd`/`std` with all address
   modes (64-bit register pairs; the upstream pair registers were misaligned), `sub_s` vs
   `sub_s.ne`, `xbfu` destination, `lsr_s b,c`, `add_s`/`sub_s sp,sp,u7`, `extb`/`exth` operands,
   `stb_s [sp,u7]` store size, `lp_count` name.
4. **ELF support** (Java): relocation handler and PLT markup (adapted from ARCompact).
5. **Build**: stand-alone extension build; the generated `ARCv2.sla` is no longer tracked.
