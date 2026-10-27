#!/usr/bin/env bash
# ARCv2 module tests that need no third-party downloads beyond GNU binutils:
#   1. the generator reproduces the checked-in SLEIGH; both .slaspec files compile (and the Java
#      ELF support is compiled into lib/ for a development install)
#   2. decode corpora vs GNU objdump 2.45 (-m arc:ARCv2, cpu=hs/em, with and without dsp), both
#      byte orders: every 16-bit first halfword, every 32-bit high halfword x low 6 bits, 50,000
#      random slots
#   3. every-entry decode test (CoverageCheck.java, 2 seeds, union), both languages
#   4. p-code emulator tests (EmuCheck.java, both byte orders) and a deliberately broken
#      expectation that must fail
#   5. if REAL_SAMPLES is set (test/fetch-real-samples.sh output): test/real-binaries.sh
#
#   test/run-tests.sh [workdir]
#
# Environment:
#   GHIDRA_INSTALL_DIR  Ghidra 12.1.x/12.2 whose Ghidra/Processors/ARCv2 is (a symlink to) this
#                       module directory
#   SLOTDIS             slotdis binary (test/slotdis.c linked with libopcodes/libbfd of binutils
#                       2.45 configured --enable-targets=all), or BU_SRC + BU_LIB to build it
#   ARC_TOOLS           GNU binutils prefix with ARCv2 support for the emulator tests, e.g.
#                       .../bin/arc-elf32- (binutils 2.45 --target=arc-elf32)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
source "$HERE/env.sh"
: "${ARC_TOOLS:?set ARC_TOOLS}"
W=$(mkdir -p "${1:-arcv2-test-work}" && cd "${1:-arcv2-test-work}" && pwd)
cd "$W"
rc=0

echo "== generator and SLEIGH"
mkdir -p gen
python3 "$MOD/tools/gen_arcv2.py" "$W/gen"
for f in ARCv2_defs.sinc ARCv2_ops.sinc ARCv2.slaspec ARCv2_be.slaspec; do
	cmp -s "gen/$f" "$MOD/data/languages/$f" || { echo "FAIL: $f is not the generator's output"; rc=1; }
done
for s in "$MOD"/data/languages/*.slaspec; do
	if "$GHIDRA_INSTALL_DIR/support/sleigh" "$s" 2>&1 | grep -E "ERROR|^Error"; then rc=1; fi
done
ls -l "$MOD"/data/languages/*.sla | awk '{print "   " $5, $9}'
[[ -d "$MOD/src" ]] && "$HERE/build-jar.sh"

if [[ -z ${SLOTDIS:-} ]]; then
	: "${BU_SRC:?set SLOTDIS, or BU_SRC and BU_LIB}" "${BU_LIB:?set SLOTDIS, or BU_LIB}"
	SLOTDIS=$W/slotdis
	gcc -O2 -w -DPACKAGE=1 -DPACKAGE_VERSION=1 -o "$SLOTDIS" "$HERE/slotdis.c" -I"$BU_SRC/include" \
		-I"$BU_SRC/bfd" -I"$BU_LIB/../bfd" -I"$BU_LIB/../include" "$BU_LIB/libopcodes.a" "$BU_LIB/libbfd.a" \
		"$BU_LIB/libsframe.a" "${BU_LIBIBERTY:-$BU_LIB/libiberty.a}" -lz -lzstd
fi
export SLOTDIS

echo "== decode corpora vs GNU objdump"
python3 "$HERE/gen_corpus.py" .
"$HERE/decode-diff.sh" . || rc=1

echo "== every-entry decode test"
head -c 64 /dev/zero >zero.bin
for l in LE BE; do
	for seed in 1 2; do
		"$HERE/ghidra-script.sh" raw ARCv2:$l:32:default zero.bin CoverageCheck.java "$W/cov_${l}_$seed.txt" 64 $seed &
	done
	wait
	tot=$(grep -h '^coverage' cov_${l}_1.txt | sed 's/coverage: \([0-9]*\) constructors.*/\1/')
	un=$( (cat cov_${l}_*.txt | grep '^unreached' || true) | sort | uniq -c | awk '$1==2' | wc -l)
	echo "-- ARCv2:$l:32:default: $tot constructors, $((tot - un)) reached by at least one of 2 seeds"
	(cat cov_${l}_*.txt | grep '^unreached' || true) | sort | uniq -c | awk '$1==2 {print "   " $0}'
	[[ $un == 0 ]] || rc=1
done

echo "== p-code emulator tests"
mkdir -p emu emu_broken
python3 "$HERE/emu_tests.py" emu "$ARC_TOOLS"
python3 "$HERE/emu_tests.py" emu_broken "$ARC_TOOLS" --break 1 >/dev/null
for e in le be; do
	"$HERE/ghidra-script.sh" raw "ARCv2:${e^^}:32:default" emu/emu_$e.bin EmuCheck.java \
		"$W/emu/emu_$e.txt" "$W/emu/res_$e.txt" &
done
wait
for e in le be; do
	echo "-- $e: $(tail -1 emu/res_$e.txt)"
	if grep -v "^PASS\|^emulator" emu/res_$e.txt; then rc=1; fi
done
"$HERE/ghidra-script.sh" raw ARCv2:LE:32:default emu_broken/emu_le.bin EmuCheck.java \
	"$W/emu_broken/emu_le.txt" "$W/emu_broken/res.txt"
if grep -q '^FAIL' emu_broken/res.txt; then
	echo "-- deliberately wrong expectation detected: $(grep '^FAIL' emu_broken/res.txt)"
else
	echo "FAIL: the deliberately wrong expectation was NOT detected"; rc=1
fi

if [[ -n ${REAL_SAMPLES:-} ]]; then
	echo "== real binaries"
	"$HERE/real-binaries.sh" "$REAL_SAMPLES" "$W/real"
fi
exit $rc
