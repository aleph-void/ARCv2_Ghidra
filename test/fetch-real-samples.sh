#!/usr/bin/env bash
# Download freely licensed ARCv2 (ARC HS) Linux binaries by pinned URL and SHA-256 and extract
# their target libraries and programs (uClibc-ng: LGPL-2.1; libgcc_s, libatomic, libstdc++: GPL-3.0
# with the GCC runtime library exception) as <outdir>/<prefix>-<name>.elf. Nothing is committed.
#   bl-hs38-*   Bootlin arcle-hs38 uClibc toolchain 2026.08-1 (little-endian HS38)
#   syn-be-*    Synopsys ARC GNU 2024.12 prebuilt uClibc toolchain for big-endian ARC HS (archs)
#   test/fetch-real-samples.sh <outdir> [--keep-toolchain]
set -euo pipefail
O=$(mkdir -p "$1" && cd "$1" && pwd)
KEEP=${2:-}
cd "$O"
mkdir -p dl
get() { # url sha256 file
	if [[ ! -s dl/$3 ]]; then
		curl -fsSL --retry 3 -o "dl/$3.part" "$1"
		mv "dl/$3.part" "dl/$3"
	fi
	echo "$2  dl/$3" | sha256sum -c -
}
TB=arcle-hs38--uclibc--stable-2026.08-1
get https://toolchains.bootlin.com/downloads/releases/toolchains/arcle-hs38/tarballs/$TB.tar.xz \
	ee36e61a30b7106092f5537ac14220db49cbc04bc5380d05aa80660494e2b76a bl-hs38.tar.xz
get https://github.com/foss-for-synopsys-dwc-arc-processors/toolchain/releases/download/arc-2024.12-release/arc_gnu_2024.12_prebuilt_uclibc_be_archs_linux_install.tar.xz \
	59bccb56c6b4557153991533705048705843761f7eb8777d645f8acef156b6d2 syn-be-archs.tar.xz

extract() { # tarball sysroot-prefix out-prefix files...
	local tb=$1 pre=$2 out=$3 t
	shift 3
	t=$(mktemp -d tmp.XXXXXX)
	tar -C "$t" -xJf "dl/$tb" $(printf "$pre/%s " "$@")
	for f in "$@"; do cp "$t/$pre/$f" "$out-$(basename "$f").elf"; done
	rm -rf "$t"
}
extract bl-hs38.tar.xz $TB/arc-buildroot-linux-uclibc/sysroot bl-hs38 \
	lib/libuClibc-1.0.59.so lib/ld-uClibc-1.0.59.so lib/libgcc_s.so.1 lib/libatomic.so.1.2.0 \
	usr/bin/getconf usr/bin/iconv sbin/ldconfig
extract syn-be-archs.tar.xz arceb-archs-linux-uclibc/arceb-snps-linux-uclibc/sysroot syn-be \
	lib/libuClibc-1.0.49.so lib/ld-uClibc-1.0.49.so lib/libgcc_s.so.1 lib/libatomic.so.1.2.0 \
	lib/libstdc++.so.6.0.33 usr/bin/getconf usr/bin/iconv sbin/ldconfig
if [[ $KEEP == --keep-toolchain ]]; then
	mkdir -p toolchain
	[[ -d toolchain/$TB ]] || tar -C toolchain -xJf dl/bl-hs38.tar.xz
fi
ls -l ./*.elf
