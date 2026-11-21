#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /tmp && mount -t tmpfs tmp /tmp
. /etc/suite.env
echo 1 > /proc/sys/kernel/panic_on_oops
echo 0 > /proc/sys/kernel/kptr_restrict

: > /tmp/results
pass() { echo "TEST $1 PASS $2" | tee -a /tmp/results; }
fail() { echo "TEST $1 FAIL $2" | tee -a /tmp/results; }
check() { n=$1; shift; if "$@" >/tmp/out 2>&1; then pass "$n" "$(head -c 160 /tmp/out | tr '\n' ' ')"; else fail "$n" "$(head -c 300 /tmp/out | tr '\n' ' ')"; fi; }
atk() { echo "$*" > /dev/vtxattack; cat /dev/vtxattack; }
field() { echo "$1" | tr ' ' '\n' | grep "^$2=" | head -1 | cut -d= -f2; }
jfield() { echo "$1" | tr ',{}' '\n\n\n' | grep "\"$2\"" | head -1 | cut -d: -f2 | tr -d '"'; }
count_ev() { vtxctl --json events -c 4096 > /tmp/ev.json 2>/dev/null; cat /tmp/ev.json >> /tmp/allev.json; }
evhas() { grep -c "$1" /tmp/allev.json; }
settle() { sleep 1; }

echo "SUITE-BEGIN model=$MODEL cpus=$(grep -c ^processor /proc/cpuinfo) kernel=$(uname -r)"
grep -m1 flags /proc/cpuinfo | tr ' ' '\n' | grep -E '^(vmx|ept|vpid|pdpe1gb|la57|umip|ibt|pti|smep|smap|x2apic)$' | tr '\n' ' '; echo
: > /tmp/allev.json

if [ "$(cat /proc/cpuinfo | grep -c ' vmx')" = "0" ]; then fail boot_vmx "no vmx flag"; fi

insmod /vtxhv_root.ko && pass load_root "" || fail load_root ""
insmod /vtxhv.ko $VTX_PARAMS && pass load_driver "" || fail load_driver "$(dmesg | grep vtxhv | tail -3 | tr '\n' ' ')"
dmesg | grep -E "vtxhv" | sed 's/^/  dmesg: /'
check all_cpus_virtualized vtxctl check
vtxctl status
vtxctl caps | head -12
/utest 1500 | tee -a /tmp/results
insmod /vtxattack.ko || fail load_attack ""

PIN0=$(cat /sys/module/vtxhv/parameters/pin 2>/dev/null || echo 0)
DTEXIT=$(cat /sys/module/vtxhv/parameters/dtexit 2>/dev/null || echo Y)
pinned() { [ $((PIN0 & $1)) -ne 0 ]; }
if [ "$DTEXIT" = "Y" ]; then PINSET=all; else PINSET=cr0.wp,cr4.smep,cr4.smap,cr4.umip,msr.syscall,msr.sysenter,msr.efer; fi
echo "CONFIG pin0=$PIN0 dtexit=$DTEXIT pinset=$PINSET"

R=$(atk cr0wp)
if pinned 1; then
	[ "$(field "$R" wp_after_clear)" = "1" ] && pass loadpin_cr0wp_denied "$R" || fail loadpin_cr0wp_denied "$R"
elif [ "$(field "$R" cet)" = "1" ]; then
	[ "$(field "$R" faulted)" = "1" ] && [ "$(field "$R" wp_after_clear)" = "1" ] && pass unpinned_cr0wp_cet_gp_reflected "$R" || fail unpinned_cr0wp_cet_gp_reflected "$R"
else
	[ "$(field "$R" wp_after_clear)" = "0" ] && pass unpinned_cr0wp_allowed "$R" || fail unpinned_cr0wp_allowed "$R"
fi
R=$(atk lstar)
if pinned 16; then
	[ "$(field "$R" hijacked)" = "0" ] && pass loadpin_lstar_denied "$R" || fail loadpin_lstar_denied "$R"
else
	[ "$(field "$R" hijacked)" = "1" ] && pass unpinned_lstar_allowed "$R" || fail unpinned_lstar_allowed "$R"
fi
R=$(atk lidt)
if pinned 128; then
	[ "$(field "$R" hijacked)" = "0" ] && pass loadpin_lidt_denied "$R" || fail loadpin_lidt_denied "$R"
else
	[ "$(field "$R" hijacked)" = "1" ] && pass unpinned_lidt_allowed "$R" || fail unpinned_lidt_allowed "$R"
fi
R=$(atk ltrbuf); LPA=$(field "$R" pa)
[ "$(field "$R" busy)" = "0" ] && pass ltr_gdt_copy_prepared "$R" || fail ltr_gdt_copy_prepared "$R"
R=$(atk ltr)
if pinned 256; then
	[ "$(field "$R" lgdt_applied)" = "0" ] && [ "$(field "$R" faulted)" = "1" ] && pass loadpin_gdtr_blocks_foreign_ltr "$R" || fail loadpin_gdtr_blocks_foreign_ltr "$R"
else
	[ "$(field "$R" lgdt_applied)" = "1" ] && [ "$(field "$R" faulted)" = "0" ] && [ "$(field "$R" busy_after)" = "1" ] && pass ltr_sets_tss_busy "$R" || fail ltr_sets_tss_busy "$R"
	atk ltrbuf > /dev/null
	ID=$(vtxctl watch add --phys $LPA --len 4096 --deny w --mode enforce --name gdt-copy | awk '{print $2}')
	R=$(atk ltr)
	[ "$(field "$R" faulted)" = "0" ] && [ "$(field "$R" busy_before)" = "0" ] && [ "$(field "$R" busy_after)" = "0" ] && pass ltr_busy_write_denied_on_enforced_page "$R" || fail ltr_busy_write_denied_on_enforced_page "$R"
	vtxctl watch del $ID > /dev/null
	ID=$(vtxctl watch add --phys $LPA --len 4096 --deny w --name gdt-copy-mon | awk '{print $2}')
	atk ltrbuf > /dev/null
	R=$(atk ltr)
	[ "$(field "$R" faulted)" = "0" ] && [ "$(field "$R" busy_before)" = "0" ] && [ "$(field "$R" busy_after)" = "1" ] && pass ltr_busy_write_monitored "$R" || fail ltr_busy_write_monitored "$R"
	vtxctl watch del $ID > /dev/null
	count_ev
	if [ "$DTEXIT" = "Y" ]; then
		[ "$(grep '"type":"ept-write"' /tmp/ev.json | grep -c '"emulated":true')" -ge 2 ] && pass ltr_busy_events_via_emulator "" || fail ltr_busy_events_via_emulator "$(grep ept-write /tmp/ev.json | head -3)"
	else
		[ "$(grep -c '"type":"ept-write"' /tmp/ev.json)" -ge 2 ] && pass ltr_busy_events_via_ept "" || fail ltr_busy_events_via_ept "$(head -3 /tmp/ev.json)"
	fi
fi
R=$(atk lstar_noncanon); [ "$(field "$R" rc)" != "0" ] && [ "$(field "$R" unchanged)" = "1" ] && pass root_fault_recovery_gp_reflected "$R" || fail root_fault_recovery_gp_reflected "$R"
count_ev
[ "$(evhas '"type":"msr-write"')" -ge 2 ] && pass event_msr_logged "" || fail event_msr_logged "$(cat /tmp/ev.json | head -3)"
[ "$(evhas '"type":"cr0"')" -ge 1 ] && pass event_cr0_audited_unpinned "" || fail event_cr0_audited_unpinned ""

if [ "$DTEXIT" = "N" ]; then
	vtxctl pin idtr > /tmp/out 2>&1 && fail nodtexit_dtr_pin_refused "$(cat /tmp/out)" || { grep -q "not supported" /tmp/out && pass nodtexit_dtr_pin_refused "$(head -c 120 /tmp/out | tr '\n' ' ')" || fail nodtexit_dtr_pin_refused "$(cat /tmp/out)"; }
	S=$(vtxctl --json status)
	[ $(( $(jfield "$S" policy) & 896 )) -eq 0 ] && pass nodtexit_no_phantom_dtr_pins "policy=$(jfield "$S" policy)" || fail nodtexit_no_phantom_dtr_pins "$S"
fi
check pin_all vtxctl pin $PINSET
R=$(atk cr0wp); [ "$(field "$R" wp_after_clear)" = "1" ] && pass pinned_cr0wp_denied "$R" || fail pinned_cr0wp_denied "$R"
R=$(atk smep)
if grep -q ' smep' /proc/cpuinfo; then
	[ "$(field "$R" smep_after_clear)" = "1" ] && pass pinned_smep_denied "$R" || fail pinned_smep_denied "$R"
else
	pass pinned_smep_denied "cpu-without-smep $R"
fi
R=$(atk lstar); [ "$(field "$R" hijacked)" = "0" ] && pass pinned_lstar_denied "$R" || fail pinned_lstar_denied "$R"
if [ "$DTEXIT" = "Y" ]; then
	R=$(atk lidt); [ "$(field "$R" hijacked)" = "0" ] && pass pinned_lidt_denied "$R" || fail pinned_lidt_denied "$R"
	R=$(atk lgdt); [ "$(field "$R" hijacked)" = "0" ] && pass pinned_lgdt_denied "$R" || fail pinned_lgdt_denied "$R"
	NDEN=4
else
	R=$(atk lidt); [ "$(field "$R" hijacked)" = "1" ] && pass nodtexit_lidt_not_mediated "$R (documented: needs dtexit=1)" || fail nodtexit_lidt_not_mediated "$R"
	NDEN=2
fi
count_ev
[ "$(grep -c '"denied":true' /tmp/ev.json)" -ge $NDEN ] && pass pinned_events_denied "$(grep -c '"denied":true' /tmp/ev.json)" || fail pinned_events_denied "$(cat /tmp/ev.json | head -5)"
grep -q '"comm":"init"\|"comm":"sh"\|"comm":"cat"' /tmp/ev.json && pass event_task_attribution "" || fail event_task_attribution "$(head -2 /tmp/ev.json)"
R=$(atk badmsr)
if [ "$BAD_MSRS_IGNORED" = "1" ]; then
	[ -n "$(field "$R" rc)" ] && pass unknown_msr_forwarded "$R (cpu ignores unknown msrs)" || fail unknown_msr_forwarded "$R"
else
	[ "$(field "$R" rc)" != "0" ] && pass unknown_msr_forwarded "$R" || fail unknown_msr_forwarded "$R"
fi
R=$(atk xsetbv); [ "$(field "$R" faulted)" = "1" ] && pass bad_xsetbv_reflected_gp "$R" || fail bad_xsetbv_reflected_gp "$R"
R=$(atk vmxon); [ "$(field "$R" faulted)" = "1" ] && pass guest_vmxon_ud "$R" || fail guest_vmxon_ud "$R"
R=$(atk hc_bogus); [ "$(field "$R" rc)" = "-22" ] && pass hypercall_unknown_einval "$R" || fail hypercall_unknown_einval "$R"
R=$(atk hc_badbuf); [ "$(field "$R" rc)" = "-14" ] && pass hypercall_badbuf_efault "$R" || fail hypercall_badbuf_efault "$R"
R=$(atk kprobe vtx_handle_exit); [ "$(field "$R" rc)" != "0" ] && pass kprobe_root_refused "$R" || fail kprobe_root_refused "$R"
R=$(atk kprobe vfs_read); [ "$(field "$R" rc)" = "0" ] && pass kprobe_kernel_works "$R" || fail kprobe_kernel_works "$R"

S=$(vtxctl --json status)
APA=$(jfield "$S" arena_pa)
TPA=$(jfield "$S" root_text_pa)
R=$(atk physread $APA); [ "$(field "$R" value)" = "0x0000000000000000" ] && pass arena_hidden_from_guest "$R" || fail arena_hidden_from_guest "$R"
R=$(atk physwrite $APA 0x41); [ "$(field "$R" readback)" = "0x0" ] && pass arena_write_discarded "$R" || fail arena_write_discarded "$R"
R=$(atk physread $TPA); [ "$(field "$R" value)" != "0x0000000000000000" ] && pass root_code_readable "$R" || fail root_code_readable "$R"
B=$(field "$R" value)
R=$(atk physwrite $TPA 0xcc); R2=$(atk physread $TPA); [ "$(field "$R2" value)" = "$B" ] && pass root_code_write_discarded "$R / $R2" || fail root_code_write_discarded "$R / $R2"
count_ev
[ "$(grep -c '"type":"tamper"' /tmp/ev.json)" -ge 2 ] && pass tamper_events "$(grep -c tamper /tmp/ev.json)" || fail tamper_events ""
R=$(atk sgdt_at $TPA); R2=$(atk physread $TPA); [ "$(field "$R" unchanged)" = "1" ] && [ "$(field "$R2" value)" = "$B" ] && pass sgdt_into_root_image_discarded "$R" || fail sgdt_into_root_image_discarded "$R / $R2"
HCREF=0
for f in drain stats query wlist; do
	R=$(atk hc_out $f $TPA)
	if [ "$(field "$R" rc)" = "-14" ] && [ "$(field "$R" unchanged)" = "1" ]; then HCREF=$((HCREF + 1)); else fail "hc_${f}_into_root_image_refused" "$R"; fi
done
R2=$(atk physread $TPA)
[ "$HCREF" = "4" ] && [ "$(field "$R2" value)" = "$B" ] && pass hypercall_outputs_into_root_image_refused "refused=$HCREF" || fail hypercall_outputs_into_root_image_refused "refused=$HCREF $R2"
R=$(atk hc_out query $APA); [ "$(field "$R" rc)" = "-14" ] && pass hypercall_output_into_arena_refused "$R" || fail hypercall_output_into_arena_refused "$R"
R=$(atk buf); QPA=$(field "$R" pa)
R=$(atk hc_out query $QPA); [ "$(field "$R" rc)" = "0" ] && [ "$(field "$R" unchanged)" = "0" ] && pass hypercall_output_plain_page_ok "$R" || fail hypercall_output_plain_page_ok "$R"
count_ev
[ "$(grep '"type":"hypercall"' /tmp/ev.json | grep -c '"emulated":true')" -ge 4 ] && pass hypercall_refusal_events "$(grep -c '"type":"hypercall"' /tmp/ev.json)" || fail hypercall_refusal_events "$(grep hypercall /tmp/ev.json | head -2)"
if [ "$DTEXIT" = "Y" ]; then
	grep '"type":"tamper"' /tmp/ev.json | grep -q '"emulated":true' && pass sgdt_tamper_event_via_emulator "" || fail sgdt_tamper_event_via_emulator "$(grep tamper /tmp/ev.json | head -2)"
fi
check status_tamper_count sh -c "vtxctl --json status | grep -q '\"tamper\":[1-9]'"

R=$(atk textpad); PPA=$(field "$R" pa)
W=$(vtxctl --json guard text | tr -dc '0-9'); vtxctl watch list
R=$(atk physwrite $PPA 0xcc)
[ "$(field "$R" readback)" = "0xcc" ] && pass text_guard_monitor_allows "$R" || fail text_guard_monitor_allows "$R"
atk physwrite $PPA 0x90 > /dev/null
count_ev
grep '"type":"ept-write"' /tmp/ev.json | grep -q '"denied":false' && pass text_guard_monitor_event "" || fail text_guard_monitor_event "$(head -3 /tmp/ev.json)"
check watch_delete vtxctl watch del $W
W=$(vtxctl --json guard text enforce | tr -dc '0-9')
R=$(atk physwrite $PPA 0xcc)
[ "$(field "$R" readback)" = "0x90" ] && pass text_guard_enforce_discards "$R" || fail text_guard_enforce_discards "$R"
R=$(atk hc_out drain $PPA); [ "$(field "$R" rc)" = "-14" ] && [ "$(field "$R" unchanged)" = "1" ] && pass hypercall_output_into_guarded_text_refused "$R" || fail hypercall_output_into_guarded_text_refused "$R"
count_ev
grep '"type":"ept-write"' /tmp/ev.json | grep '"denied":true' | grep -q 'cc' && pass text_guard_enforce_event_attempted_value "" || fail text_guard_enforce_event_attempted_value "$(head -3 /tmp/ev.json)"
vtxctl watch del $W > /dev/null
check guard_rodata vtxctl guard rodata
check guard_idt vtxctl guard idt enforce

R=$(atk buf); BPA=$(field "$R" pa)
ID=$(vtxctl watch add --phys $BPA --len 4096 --deny w --mode enforce --name sgdt-enf | awk '{print $2}')
R=$(atk sgdt_at $BPA); [ "$(field "$R" unchanged)" = "1" ] && [ "$(field "$R" stored)" = "0" ] && pass sgdt_into_enforced_watch_discarded "$R" || fail sgdt_into_enforced_watch_discarded "$R"
vtxctl watch del $ID > /dev/null
ID=$(vtxctl watch add --phys $BPA --len 4096 --deny w --name sgdt-mon | awk '{print $2}')
R=$(atk sgdt_at $BPA); [ "$(field "$R" stored)" = "1" ] && pass sgdt_into_monitored_watch_stored "$R" || fail sgdt_into_monitored_watch_stored "$R"
vtxctl watch del $ID > /dev/null
count_ev
[ "$(grep '"type":"ept-write"' /tmp/ev.json | grep -c '"denied":true')" -ge 1 ] && [ "$(grep '"type":"ept-write"' /tmp/ev.json | grep -c '"denied":false')" -ge 1 ] && pass sgdt_watch_events "" || fail sgdt_watch_events "$(grep ept-write /tmp/ev.json | head -3)"
check watch_buf_rw vtxctl watch add --phys $BPA --len 4096 --deny rw --name testbuf
R=$(atk bufwrite 0x1122334455667788); [ "$(field "$R" readback)" = "0x1122334455667788" ] && pass watch_write_monitor "$R" || fail watch_write_monitor "$R"
R=$(atk bufread); [ "$(field "$R" value)" = "0x1122334455667788" ] && pass watch_read_monitor "$R" || fail watch_read_monitor "$R"
count_ev
grep '"type":"ept-write"' /tmp/ev.json | grep -q '0x1122334455667788' && pass watch_write_newval_captured "" || fail watch_write_newval_captured "$(grep ept-write /tmp/ev.json | head -2)"
grep -q '"type":"ept-read"' /tmp/ev.json && pass watch_read_event "" || fail watch_read_event ""
R=$(atk target); TGT=$(field "$R" pa)
check watch_exec vtxctl watch add --phys $TGT --len 4096 --deny x --name target-x
R=$(atk call); [ "$(field "$R" result)" = "40" ] && pass exec_monitor_allows "$R" || fail exec_monitor_allows "$R"
count_ev
grep -q '"type":"ept-exec"' /tmp/ev.json && pass exec_event "" || fail exec_event ""
R=$(atk straddle); SA=$(field "$R" pa_a); SB=$(field "$R" pa_b)
[ "$(field "$R" off)" = "0xffe" ] && [ "$SA" != "$SB" ] && pass straddle_layout "$R" || fail straddle_layout "$R"
IA=$(vtxctl watch add --phys $SA --len 4096 --deny x --name straddle-a | awk '{print $2}')
IB=$(vtxctl watch add --phys $SB --len 4096 --deny x --name straddle-b | awk '{print $2}')
count_ev
: > /tmp/straddle.json
T=0
for k in 1 2 3 4; do
	R=$(atk straddle_run 50); T=$((T + $(field "$R" sum)))
	vtxctl --json events -c 4096 >> /tmp/straddle.json
done
[ "$T" = "8400" ] && pass exec_watch_page_straddling_insn "calls=200 sum=$T" || fail exec_watch_page_straddling_insn "sum=$T"
vtxctl watch del $IA > /dev/null
vtxctl watch del $IB > /dev/null
N=$(grep '"type":"ept-exec"' /tmp/straddle.json | grep -c "\"gpa\":\"$(printf '%#x' $SB)\"")
[ "$N" -ge 200 ] && pass straddle_second_page_events "fetches_into_second_page=$N" || fail straddle_second_page_events "n=$N total=$(grep -c ept-exec /tmp/straddle.json)"
SH=$(vtxctl --json stats | tr ',' '\n' | grep step_shadows | cut -d: -f2)
[ "${SH:-0}" -ge 1 ] && pass mtf_step_interrupt_shadow "step_shadows=$SH" || fail mtf_step_interrupt_shadow "step_shadows=$SH"
check watch_virtual_symbol vtxctl watch add --sym jiffies --len 8 --deny w --name jiffies
sleep 1
count_ev
grep '"type":"ept-write"' /tmp/ev.json | grep -q 'jiffies\|do_timer\|tick' && pass watch_symbol_timer_writes "$(grep -c ept-write /tmp/ev.json)" || pass watch_symbol_timer_writes "events=$(grep -c ept-write /tmp/ev.json)"
ID=$(vtxctl watch list | awk '/jiffies/ {print $1; exit}')
vtxctl watch del $ID > /dev/null
vtxctl watch list

NCPU=$(grep -c ^processor /proc/cpuinfo)
dmesg | grep -E "BUG:|WARNING:|Oops|general protection|Call Trace" | grep -v vtxattack > /tmp/bad_pre
if [ "$NCPU" -gt 1 ] && [ -e /proc/sysrq-trigger ]; then
	echo l > /proc/sysrq-trigger
	settle
	N=$(vtxctl --json stats | tr ',' '\n' | grep nmi_reflected | cut -d: -f2)
	[ "${N:-0}" -ge 1 ] && pass nmi_reflection "reflected=$N" || fail nmi_reflection "reflected=$N"
	dmesg | grep -c "NMI backtrace" | sed 's/^/  nmi backtraces: /'
fi
dmesg -c > /dev/null
if [ "$NCPU" -gt 1 ] && [ -e /sys/devices/system/cpu/cpu1/online ]; then
	echo 0 > /sys/devices/system/cpu/cpu1/online && pass cpu_offline "" || fail cpu_offline ""
	vtxctl check
	echo 1 > /sys/devices/system/cpu/cpu1/online && pass cpu_online "" || fail cpu_online ""
	check cpu_hotplug_revirtualized vtxctl check
fi

( i=0; while [ $i -lt 40 ]; do ls -R /proc/self > /dev/null 2>&1; cat /proc/meminfo > /dev/null; dd if=/dev/zero of=/dev/null bs=64k count=64 2>/dev/null; i=$((i + 1)); done ) &
STRESS=$!
for i in 1 2 3; do
	vtxctl watch add --phys $BPA --len 4096 --deny w --name churn > /dev/null
	atk bufwrite $i > /dev/null
	ID=$(vtxctl watch list | awk '/churn/ {print $1; exit}')
	vtxctl watch del $ID > /dev/null
done
wait $STRESS
pass stress_with_watch_churn ""
vtxctl stats

rmmod vtxattack
for i in $(seq 1 $CYCLES); do
	rmmod vtxhv || { fail "reload_cycle_$i" "rmmod"; break; }
	insmod /vtxhv.ko $VTX_PARAMS || { fail "reload_cycle_$i" "insmod"; break; }
	vtxctl check > /dev/null || { fail "reload_cycle_$i" "check"; break; }
done
pass reload_cycles "cycles=$CYCLES"
insmod /vtxattack.ko

echo "DEMO-BEGIN"
if [ "$DTEXIT" = "Y" ]; then vtxctl pin cr0.wp,cr4.smep,msr.syscall,idtr > /dev/null; else vtxctl pin cr0.wp,cr4.smep,msr.syscall > /dev/null; fi
vtxctl guard idt enforce > /dev/null
S=$(vtxctl --json status)
atk cr0wp > /dev/null
atk lstar > /dev/null
atk lidt > /dev/null
atk physwrite "$(jfield "$S" arena_pa)" 0x41 > /dev/null
atk physwrite "$(jfield "$S" root_text_pa)" 0xcc > /dev/null
atk sgdt_at "$(jfield "$S" root_text_pa)" > /dev/null
atk hc_out wlist "$(jfield "$S" root_text_pa)" > /dev/null
vtxctl --no-color events -c 32
vtxctl --no-color watch list
vtxctl --no-color status
vtxctl --no-color stats
echo "DEMO-END"

R=$(atk buf); BPA=$(field "$R" pa)
vtxctl watch add --phys $BPA --len 4096 --deny w --name locked-watch > /dev/null
vtxctl pin $PINSET > /dev/null
check lock_engage vtxctl lock --yes
R=$(atk hc_devirt); [ "$(field "$R" rc)" = "-1" ] && pass locked_devirt_refused "$R" || fail locked_devirt_refused "$R"
R=$(atk hc_unpin); [ "$(field "$R" rc)" = "-1" ] && pass locked_unpin_refused "$R" || fail locked_unpin_refused "$R"
ID=$(vtxctl watch list | awk '/locked-watch/ {print $1; exit}')
R=$(atk hc_unprotect $ID); [ "$(field "$R" rc)" = "-1" ] && pass locked_unprotect_refused "$R" || fail locked_unprotect_refused "$R"
vtxctl unpin all > /dev/null 2>&1 && fail locked_cli_unpin_refused "" || pass locked_cli_unpin_refused ""
rmmod vtxhv > /dev/null 2>&1 && fail locked_unload_refused "" || pass locked_unload_refused ""
R=$(atk cr0wp); [ "$(field "$R" wp_after_clear)" = "1" ] && pass locked_pins_hold "$R" || fail locked_pins_hold "$R"
if [ "$NCPU" -gt 1 ]; then
	echo 0 > /sys/devices/system/cpu/cpu1/online 2>/dev/null && fail locked_offline_refused "" || pass locked_offline_refused ""
fi
check final_all_cpus_virtualized vtxctl check
vtxctl status
vtxctl stats

dmesg | grep -E "BUG:|WARNING:|Oops|general protection|Call Trace" | grep -v "vtxattack" >> /tmp/bad_pre
if [ -s /tmp/bad_pre ] && cp /tmp/bad_pre /tmp/bad; then
	fail kernel_log_clean "$(head -c 400 /tmp/bad | tr '\n' ' ')"
	dmesg | tail -60
else
	pass kernel_log_clean ""
fi
echo "SUITE-END pass=$(grep -c ' PASS' /tmp/results) fail=$(grep -c ' FAIL' /tmp/results)"
sleep 2
bxexit
