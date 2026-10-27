#!/usr/bin/env bash
# Decode the corpora (gen_corpus.py) with Ghidra and with GNU libopcodes (-m arc:ARCv2 with
# -M cpu=hs, cpu=em, cpu=hs,dsp and cpu=em,dsp) in both byte orders, and compare.
#   test/decode-diff.sh <workdir>
# Environment: GHIDRA_INSTALL_DIR, SLOTDIS (slotdis binary built from test/slotdis.c)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/env.sh"
W=$(readlink -f "$1")
cd "$W"
rc=0
pids=()
for c in half w32 fuzz; do
	"$HERE/ghidra-slots.sh" ARCv2:LE:32:default $c.bin 8 g_$c.txt &
	pids+=($!)
	"$HERE/ghidra-slots.sh" ARCv2:BE:32:default ${c}_be.bin 8 g_${c}_be.txt &
	pids+=($!)
done
for c in half w32 fuzz; do
	for e in le be; do
		f=$c.bin; s=""; [[ $e == be ]] && { f=${c}_be.bin; s=_be; }
		for m in hs:cpu=hs em:cpu=em hsd:cpu=hs,dsp emd:cpu=em,dsp; do
			"$SLOTDIS" arc:ARCv2 8 $f -M ${m#*:} -e $([[ $e == be ]] && echo big || echo little) >o${m%%:*}_$c$s.txt &
			pids+=($!)
		done
	done
done
for p in "${pids[@]}"; do wait "$p" || rc=1; done
for c in half w32 fuzz; do
	for s in "" _be; do
		python3 "$HERE/compare.py" g_$c$s.txt ohs_$c$s.txt,oem_$c$s.txt,ohsd_$c$s.txt,oemd_$c$s.txt 3 \
			--corpus $c$s.bin $([[ $s == _be ]] && echo be || echo le) >cmp_$c$s.txt || rc=1
		echo "-- $c${s:- (le)}: $(head -1 cmp_$c$s.txt)"
	done
done
exit $rc
