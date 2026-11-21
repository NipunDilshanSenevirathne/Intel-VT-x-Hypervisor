#!/bin/sh
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
VER=${KERNEL_TAG:-v6.18}
DIR=${1:-$HERE/.cache/linux-${VER#v}}
if [ ! -d "$DIR" ]; then
	git clone --depth 1 --branch "$VER" https://github.com/torvalds/linux "$DIR"
fi
cd "$DIR"
if [ ! -f arch/x86/boot/bzImage ]; then
	make -s tinyconfig
	./scripts/kconfig/merge_config.sh -m .config "$HERE/tests/vm/kernel.config" >/dev/null
	make -s olddefconfig
	make -s -j"$(nproc)" bzImage modules
fi
echo "KERNEL=$DIR/arch/x86/boot/bzImage"
echo "KDIR=$DIR"
