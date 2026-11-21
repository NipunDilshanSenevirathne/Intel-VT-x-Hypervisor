#!/bin/sh
set -eu
PREFIX=${1:-$PWD/.cache/bochs}
SRC=${BOCHS_SRC:-$PWD/.cache/bochs-src}
REF=${BOCHS_REF:-master}
if [ -x "$PREFIX/bin/bochs" ]; then
	echo "bochs already installed in $PREFIX"
	exit 0
fi
if [ ! -d "$SRC/.git" ]; then
	git clone --depth 1 --branch "$REF" https://github.com/bochs-emu/Bochs "$SRC"
fi
cd "$SRC/bochs"
./configure --prefix="$PREFIX" --enable-x86-64 --enable-smp --enable-vmx=2 --enable-avx --enable-evex \
	--enable-cet --enable-protection-keys --enable-cpu-level=6 --enable-all-optimizations \
	--enable-long-phy-address --enable-pci --with-nogui --with-term=no --disable-docbook --enable-monitor-mwait
make -j"$(nproc)"
make install
echo "bochs installed in $PREFIX"
