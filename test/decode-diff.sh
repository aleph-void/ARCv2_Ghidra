#!/usr/bin/env bash
# Decode the corpora (gen_corpus.py) with Ghidra and with GNU libopcodes (-m arc, ARCv2 with
# -M cpu=em and -M cpu=hs) and compare.   test/decode-diff.sh <workdir>
# Environment: GHIDRA_INSTALL_DIR, SLOTDIS (slotdis binary built from test/slotdis.c)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/env.sh"
W=$(readlink -f "$1")
cd "$W"
rc=0
pids=()
for c in half w32 fuzz; do
	"$HERE/ghidra-slots.sh" ARCv2:LE:32:default $c.bin 8 g_$c.txt 2>/dev/null &
	pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" || rc=1; done
for c in half w32 fuzz; do
	"$SLOTDIS" arc:ARCv2 8 $c.bin -M cpu=hs >ohs_$c.txt
	"$SLOTDIS" arc:ARCv2 8 $c.bin -M cpu=em >oem_$c.txt
	python3 "$HERE/compare.py" g_$c.txt ohs_$c.txt,oem_$c.txt 3 >cmp_$c.txt || rc=1
	echo "-- $c: $(head -1 cmp_$c.txt)"
done
exit $rc
