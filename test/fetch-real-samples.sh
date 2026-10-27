#!/usr/bin/env bash
# Download the Bootlin ARC HS38 uClibc toolchain (pinned URL and SHA-256) and extract its target
# libraries and programs (uClibc-ng, libgcc_s, libatomic: LGPL / GPL with the GCC runtime
# exception) as <outdir>/hs38-<name>.elf. Nothing is committed.
#   test/fetch-real-samples.sh <outdir>
set -euo pipefail
O=$(mkdir -p "$1" && cd "$1" && pwd)
cd "$O"
TB=arcle-hs38--uclibc--stable-2026.08-1
[[ -s dl.tar.xz ]] || curl -fsSL --retry 3 -o dl.tar.xz \
	https://toolchains.bootlin.com/downloads/releases/toolchains/arcle-hs38/tarballs/$TB.tar.xz
echo "ee36e61a30b7106092f5537ac14220db49cbc04bc5380d05aa80660494e2b76a  dl.tar.xz" | sha256sum -c -
P=$TB/arc-buildroot-linux-uclibc/sysroot
T=$(mktemp -d tmp.XXXXXX)
tar -C "$T" -xJf dl.tar.xz $P/lib/libuClibc-1.0.59.so $P/lib/ld-uClibc-1.0.59.so $P/lib/libgcc_s.so.1 \
	$P/lib/libatomic.so.1.2.0 $P/usr/bin/getconf $P/usr/bin/iconv $P/sbin/ldconfig
for f in "$T"/$P/lib/* "$T"/$P/usr/bin/* "$T"/$P/sbin/*; do cp "$f" "hs38-$(basename "$f").elf"; done
rm -rf "$T"
ls -l ./*.elf
