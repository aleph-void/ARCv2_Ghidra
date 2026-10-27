#!/usr/bin/env python3
"""Compare Ghidra slot disassembly (DumpSlots.java) with GNU objdump slot disassembly (slotdis).

  compare.py <ghidra.txt> <objdump.txt>[,<objdump2.txt>...] [examples-per-class] [--corpus <raw.bin> <le|be>]

All files have one line per slot: "<offset-hex> <length> <text>"; length 0 means rejected. The
objdump files are the decodings of the same slots with different -M options (cpu=hs, cpu=em,
...,dsp): ARCv2 cores are configurable and some optional extensions share encodings. A slot
agrees when Ghidra matches any of them; otherwise it is compared with the first that decodes it.
objdump's "Warning: disassembly may be wrong due to guessed opcode class choice" prefix (printed
when several optional extensions share the encoding) is removed.

  exact:    same length and the same text after whitespace/number normalisation
  semantic: same instruction with an equivalent spelling (SEM below)
  explained: a known difference class (explain() below), each documented in GHIDRA-RARE.md
"""
import re
import struct
import sys
from collections import Counter, defaultdict

WARN = "Warning: disassembly may be wrong due to guessed opcode class choice. " \
       "Use -M<class[,class]> to select the correct opcode class(es)."
NUM = re.compile(r"(?<![\w.])(-?(?:0x[0-9a-f]+|\d+))(?![\w])")
_CC = r"(eq|ne|p|n|c|nc|v|nv|gt|ge|lt|le|hi|ls|pnz|nj|nm|nt|\.nj|\.nm|\.nt)?"
BRANCH = re.compile(r"^((b|bl|lp)" + _CC + r"|br(eq|ne|lt|ge|lo|hs)|bbit[01]|dbnz|b_s|beq_s|bne_s|bl_s|breq_s|brne_s"
                    r"|b(gt|ge|lt|le|hi|hs|lo|ls)_s)(\.d)?(\.n?t)?(\.d)? ")


def load(path):
    d = {}
    for line in open(path, errors="replace"):
        parts = line.rstrip("\n").split(" ", 2)
        if len(parts) < 2:
            continue
        off = int(parts[0], 16)
        txt = parts[2] if len(parts) > 2 else ""
        guessed = WARN in txt
        txt = txt.replace(WARN, "").strip()
        d[off] = (int(parts[1]), txt, guessed)
    return d


def bad(ol, ot):
    return ol == 0 or ot.startswith("(bad)") or ot.startswith(".word") or ot.startswith(".short") \
        or ot.startswith(".long") or "*unknown*" in ot


def canon_num(m):
    return hex(int(m.group(1), 0) & 0xFFFFFFFF)


def exact_norm(t):
    t = t.lower().replace("\t", " ").strip()
    if t.startswith("_"):
        t = t[1:]
    # objdump: "bl -4 ;0x1234" -> target only (relative branches, lp, dbnz)
    m = re.match(r"^(.*?)(-?\d+|-?0x[0-9a-f]+)\s*;(0x[0-9a-f]+)\s*$", t)
    if m and BRANCH.match(t):
        t = m.group(1) + m.group(3)
    # objdump's address comment on pcl-relative operands ("ld_s r0,[pcl,8] ;0x1234")
    t = re.sub(r"\s*;0x[0-9a-f]+\s*$", "", t)
    mn, _, ops = t.partition(" ")
    t = mn + " " + ops.replace(" ", "")
    return NUM.sub(canon_num, t).strip()


SEM = [
    (r"\breserved\b", "r61"),
    (r"\breservedr", "r61r"), (r"lp_countreserved", "lp_countr61"),
    # objdump prints nothing for extension conditions without a name; Ghidra prints e<n>
    (r"\.e(1[6-9]|2[02]|2[5-9]|3[01])(?=[. ]|$)", ""),
    (r"^(j|jl|b|bl|lp)e(1[6-9]|2[02]|2[5-9]|3[01])(?=[. ]|$)", r"\1"),
]


def sem_norm(t):
    t = exact_norm(t)
    for a, b in SEM:
        t = re.sub(a, b, t)
    return t


def mnem(t):
    return t.split(" ")[0].lower() if t else "-"


def explain(gt, ot, gbad, obad, w):
    """Reason for a known, explained difference class, or None."""
    gm, om = mnem(gt).split(".")[0], mnem(ot).split(".")[0]
    if gbad and not obad and "illegal use of double register pair" in ot:
        return "odd register of a 64-bit pair: objdump decodes it with a warning, Ghidra rejects it"
    if gbad and not obad and om in ("llockd", "scondd") and re.match(r"^\S+ (r\d*[13579]|ilink|blink|fp|pcl|r61|reserved),", ot):
        return "odd register of a 64-bit pair (llockd/scondd): objdump prints it without a warning, Ghidra rejects it"
    if gbad and not obad and om in ("enter_s", "leave_s") and "[0xf" in ot:
        return "enter_s/leave_s register count 15 (reserved): objdump prints the raw count"
    if not gbad and not obad and {gm, om} <= {"cmpyhnfr", "cmpychnfr"}:
        return "major 6 sub-opcodes 0x00/0x02 with F=1: objdump guesses between the DSP complex multiplies by operand form"
    if gm == om == "vadd2" and re.sub(r"\.e\d+", "", gt).rsplit(",", 1)[0] == ot.rsplit(",", 1)[0] \
            and w is not None and (w >> 22) & 3 == 3 and ((w >> 24) & 7, (w >> 12) & 7) == (6, 7):
        return "vadd2 format 3 with a long-immediate b: objdump prints c as a register pair (as one register otherwise)"
    if w == 0x2cf7ac53 and gm == "mac":
        return "Ghidra core: instruction prototype cache collision (0x2c8e1c53 mac and 0x2cf7ac53 dmacwhu.f hash alike)"
    if (gbad != obad) and "cbflyhf1r" in (om, gm):
        return "cbflyhf1r in an unusual operand form: objdump's guessed DSP class (Ghidra decodes the two documented forms)"
    if gbad and not obad and w is not None and (w >> 27) in (5, 6, 7) and 0x20 <= (w >> 16) & 63 <= 0x2e \
            and (w >> 22) & 3 == 1 and w & 63 == 62 and ((w >> 24) & 7, (w >> 12) & 7) == (6, 7):
        return "objdump bug: \"0,limm,u6\" of sub-opcodes 0x20-0x2e (whose \"0,limm,c\" form it rejects) printed with u6 as a register"
    return None
    return None


def word32(data, off, e):
    f = "<H" if e == "le" else ">H"
    hi = struct.unpack_from(f, data, off)[0]
    lo = struct.unpack_from(f, data, off + 2)[0] if off + 4 <= len(data) else 0
    return (hi << 16) | lo


def main():
    args = sys.argv[1:]
    corpus = None
    if "--corpus" in args:
        i = args.index("--corpus")
        corpus = (open(args[i + 1], "rb").read(), args[i + 2])
        del args[i:i + 3]
    g = load(args[0])
    os_ = [load(f) for f in args[1].split(",")]
    nex = int(args[2]) if len(args) > 2 else 5
    cnt = Counter()
    classes = defaultdict(list)
    for off in sorted(os_[0]):
        gl, gt, _ = g.get(off, (0, "BAD", False))
        cands = [o[off] for o in os_ if off in o and not bad(o[off][0], o[off][1])]
        ol, ot, guessed = cands[0] if cands else os_[0][off]
        for c in cands:
            if c[0] == gl and sem_norm(c[1]) == sem_norm(gt):
                ol, ot, guessed = c
                break
        gbad = gl == 0
        obad = not cands
        cnt["total"] += 1
        if gbad and obad:
            cnt["both_reject"] += 1
            continue
        w = word32(corpus[0], off, corpus[1]) if corpus else None
        agree = not gbad and not obad and gl == ol and sem_norm(gt) == sem_norm(ot)
        why = None if agree else explain(gt, ot, gbad, obad, w)
        if why:
            cnt["explained"] += 1
            classes["explained: " + why].append((off, gt, ot, ol))
            continue
        if gbad:
            cnt["ref_only"] += 1
            classes["ref only: " + mnem(ot)].append((off, gt, ot, ol))
            continue
        if obad:
            cnt["ghidra_only"] += 1
            classes["ghidra only: " + mnem(gt)].append((off, gt, ot, gl))
            continue
        cnt["both_decode"] += 1
        if gl == ol and exact_norm(gt) == exact_norm(ot):
            cnt["exact"] += 1
            cnt["semantic"] += 1
        elif agree:
            cnt["semantic"] += 1
            classes["~ " + mnem(ot)].append((off, gt, ot, gl))
        else:
            key = ("LEN " if gl != ol else "DIFF ") + mnem(ot) + " / " + mnem(gt)
            classes[key].append((off, gt, ot, "%d/%d" % (gl, ol)))
    bd = cnt["both_decode"] or 1
    unexplained = cnt["ghidra_only"] + cnt["ref_only"] + cnt["both_decode"] - cnt["semantic"]
    print("compared %d slots: both decode %d, exact %d (%.2f%%), semantic %d (%.2f%%), "
          "ghidra-only %d, ref-only %d, both reject %d, explained %d; unexplained differences %d"
          % (cnt["total"], cnt["both_decode"], cnt["exact"], 100.0 * cnt["exact"] / bd,
             cnt["semantic"], 100.0 * cnt["semantic"] / bd, cnt["ghidra_only"], cnt["ref_only"],
             cnt["both_reject"], cnt["explained"], unexplained))
    for k in sorted(classes, key=lambda k: (k.startswith("~"), k.startswith("explained"), -len(classes[k]))):
        v = classes[k]
        print("  [%d] %s" % (len(v), k))
        for off, gt, ot, ln in v[:nex]:
            print("      %08x len %s  ghidra: %-34s objdump: %s" % (off, ln, gt, ot))
    sys.exit(1 if unexplained else 0)


if __name__ == "__main__":
    main()
