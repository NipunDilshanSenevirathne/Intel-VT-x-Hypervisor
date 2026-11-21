#!/bin/sh
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
MODEL=${1:-corei7_haswell_4770}
NCPU=${2:-1}
KERNEL=${KERNEL:?set KERNEL to a bzImage}
KDIR=${KDIR:?set KDIR to the matching kernel build tree}
BOCHS=${BOCHS:-bochs}
BXSHARE=${BXSHARE:?set BXSHARE to the Bochs share directory}
OUT=${OUT:-$ROOT/tests/vm/out}
CYCLES=${CYCLES:-5}
VTX_PARAMS=${VTX_PARAMS:-}
TIMEOUT=${TIMEOUT:-1200}
MEGS=${MEGS:-512}
TAG=${TAG:-$MODEL-$NCPU}

mkdir -p "$OUT"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

make -s -C "$ROOT/kmod" KDIR="$KDIR" >/dev/null
make -s -C "$ROOT/tests/attack" KDIR="$KDIR" >/dev/null
make -s -C "$ROOT/tools/vtxctl" clean >/dev/null
make -s -C "$ROOT/tools/vtxctl" STATIC=-static >/dev/null
cc -static -O2 -o "$WORK/utest" "$HERE/utest.c"
cc -static -O2 -o "$WORK/bxexit" "$HERE/bxexit.c"

R=$WORK/rootfs
mkdir -p "$R/bin" "$R/proc" "$R/sys" "$R/dev" "$R/tmp" "$R/etc"
cp "$(command -v busybox)" "$R/bin/busybox"
cp "$WORK/bxexit" "$R/bin/bxexit"
cp "$ROOT/tools/vtxctl/vtxctl" "$R/bin/vtxctl"
cp "$WORK/utest" "$R/utest"
cp "$ROOT/kmod/vtxhv_root.ko" "$ROOT/kmod/vtxhv.ko" "$ROOT/tests/attack/vtxattack.ko" "$R/"
cp "$HERE/suite.sh" "$R/init"
chmod +x "$R/init"
printf 'MODEL=%s\nCYCLES=%s\nVTX_PARAMS="%s"\nBAD_MSRS_IGNORED=%s\n' "$MODEL" "$CYCLES" "$VTX_PARAMS" "${IGNORE_BAD_MSRS:-1}" > "$R/etc/suite.env"
(cd "$R" && find . | cpio -o -H newc 2>/dev/null | gzip -1 > "$WORK/initrd.gz")

ISO=$WORK/iso
mkdir -p "$ISO/isolinux"
cp /usr/lib/ISOLINUX/isolinux.bin /usr/lib/syslinux/modules/bios/ldlinux.c32 "$ISO/isolinux/"
cp "$KERNEL" "$ISO/vmlinuz"
cp "$WORK/initrd.gz" "$ISO/initrd.gz"
cat > "$ISO/isolinux/isolinux.cfg" <<EOF
DEFAULT linux
PROMPT 0
TIMEOUT 0
LABEL linux
  KERNEL /vmlinuz
  APPEND initrd=/initrd.gz console=ttyS0,115200 loglevel=5 panic=-1 tsc=reliable ${KCMDLINE:-}
EOF
genisoimage -quiet -o "$WORK/test.iso" -b isolinux/isolinux.bin -c isolinux/boot.cat \
	-no-emul-boot -boot-load-size 4 -boot-info-table -J -R "$ISO"

LOG=$OUT/$TAG.log
cat > "$WORK/bochsrc" <<EOF
megs: $MEGS
cpu: model=$MODEL, count=$NCPU, ips=200000000, reset_on_triple_fault=0, ignore_bad_msrs=${IGNORE_BAD_MSRS:-1}
romimage: file=$BXSHARE/BIOS-bochs-latest
vgaromimage: file=$BXSHARE/VGABIOS-lgpl-latest.bin
ata0-master: type=cdrom, path=$WORK/test.iso, status=inserted
boot: cdrom
com1: enabled=1, mode=file, dev=$LOG
log: $OUT/$TAG.bochs.log
panic: action=fatal
error: action=report
info: action=ignore
debug: action=ignore
display_library: nogui
clock: sync=none, time0=1
EOF
rm -f "$LOG"
START=$(date +%s)
timeout "$TIMEOUT" "$BOCHS" -q -f "$WORK/bochsrc" > "$OUT/$TAG.bochs.out" 2>&1 || true
END=$(date +%s)
FIN=$(grep -a -o "SUITE-END pass=[0-9]* fail=[0-9]*" "$LOG" | tail -1 || true)
if [ -n "$FIN" ]; then
	PASS=$(echo "$FIN" | sed 's/.*pass=\([0-9]*\).*/\1/')
	FAIL=$(echo "$FIN" | sed 's/.*fail=\([0-9]*\).*/\1/')
	DONE=1
else
	PASS=$(grep -a -c "^TEST .* PASS" "$LOG" || true)
	FAIL=$(grep -a -c "^TEST .* FAIL" "$LOG" || true)
	DONE=0
fi
printf '%-28s %3s pass  %3s fail  %s  (%ss)\n' "$TAG" "$PASS" "$FAIL" "$([ "$DONE" = 1 ] && echo complete || echo INCOMPLETE)" "$((END - START))"
[ "$FAIL" = 0 ] && [ "$DONE" = 1 ]
