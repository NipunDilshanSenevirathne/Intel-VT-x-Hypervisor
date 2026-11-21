#!/bin/sh
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$HERE/out}
mkdir -p "$OUT"
SUMMARY=$OUT/summary.txt
: > "$SUMMARY"
FAILED=0
run() {
	if "$HERE/run.sh" "$@" >> "$SUMMARY" 2>&1; then :; else FAILED=$((FAILED + 1)); fi
	tail -1 "$SUMMARY"
}
CONFIGS=${CONFIGS:-"corei7_haswell_4770:1 corei7_haswell_4770:2 corei7_sandy_bridge_2600k:1 corei7_skylake_x:2 corei7_icelake_u:4 tigerlake:2 sapphire_rapids:2"}
for c in $CONFIGS; do
	run "${c%%:*}" "${c##*:}"
done
TAG=haswell-nodtexit VTX_PARAMS="dtexit=0" run corei7_haswell_4770 2
TAG=haswell-loadguards VTX_PARAMS="guard_text=1 guard_rodata=1 guard_idt=2 pin=1023 serial_events=1" run corei7_haswell_4770 1
echo "matrix: $FAILED failing configuration(s)"
[ "$FAILED" = 0 ]
