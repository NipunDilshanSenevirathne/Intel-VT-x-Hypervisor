# Testing

A hypervisor fails in ways ordinary software does not. A missed corner case is a VM-entry failure, a hung CPU or a silent hole in a protection. Testing is therefore layered, and each layer has its own **oracle**: a way to know the answer is right, not merely that nothing crashed.

| Layer | Command | Oracle |
|---|---|---|
| Unit, property and concurrency tests | `make test-unit` | Independent reference models written from the SDM: brute force, exhaustive enumeration, invariants |
| Coverage-guided fuzzing | `make test-fuzz` | ASan/UBSan plus semantic assertions inside the harnesses |
| Build-time isolation proof | `make check` | ELF relocation/section analysis plus full disassembly of the VMX-root image |
| Adversarial integration | `make test-vm` | An attacker module and user-space probes inside a guest booted on emulated VT-x, with every expectation written down |

The pure logic that runs in VMX root (`ept.c`, `policy.c`, `mtrr.c`, `walk.c`, `dtr.c`, `ring.c`) is plain C with no kernel dependencies. The same source files are compiled into the root image and into the userspace tests, so the code under test is the code that ships, not a copy.

---

## 1. Unit, property and concurrency tests

Built with `-fsanitize=address,undefined -fno-sanitize-recover=all`.

| Suite | Checks | What is verified |
|---|---:|---|
| `test_walk` | 786,560 | The guest page walker against an independent SDM reference across **all 786,432** combinations of P/W/U/NX per level × CPL × access type × `CR0.WP` × SMEP × SMAP × `RFLAGS.AC` × implicit-supervisor accesses. Also 2M/1G pages, 5-level paging, reserved-bit faults, bad physical addresses, A/D semantics, all-or-nothing split copies, the write-policy classification, policy-aware copies (open/monitor/enforce/self), and A/D updates that skip protected paging structures |
| `test_ept` | 467,788 | Identity-map construction with and without 1G pages, MTRR-driven splitting, pool exhaustion, permission normalisation, random split/map churn against a shadow model, the GPA-0 software-valid regression, and the sorted self-page set |
| `test_dtr` | 276,498 | The descriptor-table decoder over **276,480** VM-exit instruction-information encodings against a reference (scale, index, base, address size, segment, register/memory forms), effective-address arithmetic, GPR slot mapping, operand-size prefix detection |
| `test_mtrr` | 11,816 | Memory-type resolution (fixed ranges, variable ranges, overlap precedence UC > WT > WB, default type) against brute force, page by page |
| `test_ksyms` | 3,015 | kallsyms parsing, module symbols, `kptr_restrict` zeroed addresses, 3,000 random-garbage inputs |
| `test_fmt` | 44 | Pin and deny parsing, JSON escaping of hostile `comm` strings, event rendering including the emulator and hypercall-refusal forms |
| `test_ctl` | 15 | VMX control negotiation against allowed-0/allowed-1 masks, CR0/CR4 fixed-bit validation |
| `test_ring` | 32 | The SPSC event ring, including **2,000,000 events** pushed through a 256-slot ring by a producer thread while a consumer thread verifies order and contents |
| **Total** | **1,545,768** | **0 failures** |

**Mutation check.** Disabling the policy check for A/D updates, or for emulated stores, makes `test_ad_protected_tables` and `test_guest_copy_policy` fail immediately. The tests are sensitive to exactly the defects they were written for.

---

## 2. Fuzzing

libFuzzer (clang 18) with ASan and UBSan. Each harness also asserts semantic properties, not just "no crash".

| Harness | Executions | Semantic oracle |
|---|---:|---|
| `fuzz_walk` | 5,995,373 in 150 s | Arbitrary page tables, CR3, CPL and paging modes, plus random owned, self and watched pages. Results must be one of the four defined codes. **No byte of a page whose policy is deny or self may change**, through data writes or A/D updates. A successful copy reports exactly `len` bytes in at most two in-page chunks, all inside RAM; written chunks hold exactly the caller's data; reads never report a denial. |
| `fuzz_dtr` | 76,705,996 in 150 s | Random instruction-information words, qualifications and register files. The decoded operand and effective address must be self-consistent, and 16-bit offsets wrap as hardware wraps them. |
| `fuzz_ept` | 167,670 in 600 s | Random RAM maps, MTRR layouts, owned/self/watch tables and operation sequences (build, split, map, lookup). Every present entry carries the software-valid bit, lookups agree with the requested mappings, and the pool never overflows. |
| `fuzz_ksyms` | 2,168,524 in 90 s | Hostile `/proc/kallsyms` content. No out-of-bounds access, and lookups are monotonic. |

Numbers are from the final build, on one core, with the corpus carried over from earlier campaigns (`fuzz_walk` was restarted from an empty corpus when its oracle changed). Every campaign ended clean.

**Mutation check.** With the policy test removed from emulated stores, `fuzz_walk` aborts on its protected-page invariant within seconds.

`fuzz_ept` found the only memory-safety-adjacent defect so far: a fully-denied leaf for GPA 0 with UC type encoded as an all-zero entry, which the code read as "not present" and could later remap RWX. The fix (bit 11, software-valid, on every entry) is covered by `test_ept` and by the crashing input itself, kept in `tests/fuzz/regressions/fuzz_ept/` and replayed by `make -C tests/fuzz regress` before every campaign.

---

## 3. Isolation proof

`scripts/check_host_isolation.py` reads `vtxhv_root.ko` with pyelftools and disassembles every executable section with capstone:

1. **No undefined symbols.** The root image calls nothing outside itself: no `printk`, no `memcpy`, no thunks.
2. **No writable sections.** No mutable static state the guest could locate.
3. **No patch sites.** No `__mcount_loc`, `.altinstructions`, `.static_call_sites`, `__jump_table`, `.retpoline_sites`, `.return_sites`, `.call_sites`, `.ibt_endbr_seal` or `__patchable_function_entries`.
4. **Code relocations only point at root code or rodata.**
5. **No indirect branches** (`call/jmp reg/mem`), so retpoline, IBT and kCFI rewriting have nothing to touch.
6. **Every global function is in `.kprobes.text`**, so the kprobe blacklist forbids instrumenting it. The integration suite confirms `register_kprobe(vtx_handle_exit)` is refused.

| Kernel | Root code | Globals | Result |
|---|---:|---:|---|
| Linux 6.18 (test kernel: IBT, retpoline, return thunks, call padding) | 24,721 B | 58 | 6/6 PASS |
| Ubuntu 6.8.0-151-generic | 27,631 B | 58 | 6/6 PASS |
| Ubuntu 6.17.0-42-generic | 27,631 B | 58 | 6/6 PASS |

All three builds are warning-free, including objtool.

---

## 4. Adversarial integration suite

`tests/vm/run.sh MODEL NCPU` builds the modules, `vtxctl`, the attacker module and static probes, and packs them into an initramfs whose `/init` is `tests/vm/suite.sh`. It then boots Linux 6.18 under **Bochs with VMX and EPT emulation**. Bochs implements the SDM's VM-entry checks field by field, so a malformed VMCS fails there as it would on silicon. `tests/vm/matrix.sh` runs every configuration.

### Configurations

| Configuration | Bochs CPU model | vCPUs | Guest paging | What it exercises | Tests | Result | Wall time |
|---|---|:-:|:-:|---|--:|:-:|--:|
| `corei7_sandy_bridge_2600k-1` | Sandy Bridge | 1 | 4-level | no SMEP/SMAP, no 1G EPT pages (2M/4K only), PTI | 83 | ✅ 83/83 | 52 s |
| `corei7_haswell_4770-1` | Haswell | 1 | 4-level | baseline, SMEP, 1G EPT pages, PTI | 83 | ✅ 83/83 | 52 s |
| `corei7_haswell_4770-2` | Haswell | 2 | 4-level | SMP: NMI reflection, CPU hot-unplug/replug | 88 | ✅ 88/88 | 70 s |
| `corei7_skylake_x-2` | Skylake-X | 2 | 4-level | SMAP | 88 | ✅ 88/88 | 121 s |
| `corei7_icelake_u-4` | Ice Lake | 4 | 4-level | UMIP, four virtualized CPUs | 88 | ✅ 88/88 | 140 s |
| `tigerlake-2` | Tiger Lake | 2 | 4-level | CET: kernel IBT, the `CR0.WP`/`CET` rule | 88 | ✅ 88/88 | 152 s |
| `sapphire_rapids-2` | Sapphire Rapids | 2 | **5-level** | LA57 host and guest walks, IBT | 88 | ✅ 88/88 | 201 s |
| `haswell-nodtexit` | Haswell | 2 | 4-level | `dtexit=0`: DTR pins must be refused, stores go through EPT | 88 | ✅ 88/88 | 71 s |
| `haswell-loadguards` | Haswell | 1 | 4-level | `pin=1023 guard_text=1 guard_rodata=1 guard_idt=2 serial_events=1` | 80 | ✅ 80/80 | 133 s |
| **Total** | 7 models | 1–4 | 4 + 5-level | | **774** | **✅ 774 / 0 failed** | |

The CPU models cover Sandy Bridge (no SMEP, no 1G EPT pages), Haswell, Skylake-X, Ice Lake (UMIP), Tiger Lake (CET: kernel IBT and the `CR0.WP` rule) and Sapphire Rapids (5-level paging, LA57). Expectations adapt to what the configuration can enforce: pins loaded at `insmod` time turn the "unpinned" probes into "denied" checks, and without descriptor-table exiting the DTR pins must be *refused*.

### What the suite does

| Area | Tests |
|---|---|
| Bring-up | `load_root`, `load_driver`, `all_cpus_virtualized`, `user_cpuid_signature`, `user_cpuid_hides_vmx` |
| User-space probes | `user_vmcall_ud`, `user_vmxon_faults`, `user_desc_stores_hypervisor_emulated` (UMIP-aware), `ldt_context_switch` (1,500 rounds of LDT switching under `LLDT` emulation) |
| Unpinned behaviour is audited, not blocked | `unpinned_cr0wp_allowed` or `unpinned_cr0wp_cet_gp_reflected`, `unpinned_lstar_allowed`, `unpinned_lidt_allowed`, `event_msr_logged`, `event_cr0_audited_unpinned`, `root_fault_recovery_gp_reflected` |
| `LTR` emulation | `ltr_gdt_copy_prepared`, `ltr_sets_tss_busy`, `ltr_busy_write_denied_on_enforced_page`, `ltr_busy_write_monitored`, `ltr_busy_events_via_emulator` / `_via_ept`, `loadpin_gdtr_blocks_foreign_ltr` |
| Pins | `pin_all`, `pinned_cr0wp_denied`, `pinned_smep_denied`, `pinned_lstar_denied`, `pinned_lidt_denied`, `pinned_lgdt_denied`, `pinned_events_denied`, `loadpin_*`, `nodtexit_dtr_pin_refused`, `nodtexit_no_phantom_dtr_pins`, `nodtexit_lidt_not_mediated` |
| Architectural reflection | `unknown_msr_forwarded`, `bad_xsetbv_reflected_gp`, `guest_vmxon_ud`, `hypercall_unknown_einval`, `hypercall_badbuf_efault` |
| Self-protection | `kprobe_root_refused`, `kprobe_kernel_works`, `arena_hidden_from_guest`, `arena_write_discarded`, `root_code_readable`, `root_code_write_discarded`, `tamper_events`, `status_tamper_count` |
| Confused deputy | `sgdt_into_root_image_discarded`, `sgdt_tamper_event_via_emulator`, `hypercall_outputs_into_root_image_refused` (all four output hypercalls), `hypercall_output_into_arena_refused`, `hypercall_output_into_guarded_text_refused`, `hypercall_output_plain_page_ok`, `hypercall_refusal_events`, `sgdt_into_enforced_watch_discarded`, `sgdt_into_monitored_watch_stored`, `sgdt_watch_events` |
| Guards and watches | `text_guard_monitor_allows`, `text_guard_monitor_event`, `text_guard_enforce_discards`, `text_guard_enforce_event_attempted_value`, `guard_rodata`, `guard_idt`, `watch_buf_rw`, `watch_write_monitor`, `watch_read_monitor`, `watch_write_newval_captured`, `watch_read_event`, `watch_exec`, `exec_monitor_allows`, `exec_event`, `watch_virtual_symbol`, `watch_symbol_timer_writes`, `watch_delete` |
| MTF step engine | `straddle_layout`, `exec_watch_page_straddling_insn` (200 calls of an `ENDBR64` that spans two exec-watched pages), `straddle_second_page_events`, `mtf_step_interrupt_shadow` |
| SMP and lifecycle | `nmi_reflection` (sysrq-l NMI backtraces), `cpu_offline`, `cpu_online`, `cpu_hotplug_revirtualized`, `stress_with_watch_churn`, `reload_cycles` (5 × rmmod/insmod) |
| Lock-down | `lock_engage`, `locked_devirt_refused`, `locked_unpin_refused`, `locked_unprotect_refused` (forged hypercalls from the attacker module), `locked_cli_unpin_refused`, `locked_unload_refused`, `locked_pins_hold`, `locked_offline_refused`, `final_all_cpus_virtualized` |
| Hygiene | `kernel_log_clean`: no `BUG`, `WARNING`, `Oops`, general protection fault or call trace in the guest's log for the whole run |

**Mutation check (integration).** The integration suite was also run against a root image with the hypercall output-buffer policy removed. The run dies at `hc_out drain <root-text PA>`: `DRAIN` writes event records over the first page of the hypervisor's own code, and the next VM exit takes a host page fault inside the corrupted code. The guest's serial console shows it:

```text
vtxhv: HOST EXCEPTION cpu=0x0000000000000000 vec=0x000000000000000e err=0x0000000000000002 rip=0xffffffffc020002f ...
```

That is the attack the policy closes. With `WLIST` the bytes written are watch names, which the attacker chooses, so this primitive is code execution in VMX root, not merely a crash.

---

## 5. Defects found by testing

| Found by | Defect | Fix | Regression |
|---|---|---|---|
| `fuzz_ept` | All-zero fully-denied leaf for GPA 0 taken as not-present, remappable RWX | Software-valid bit 11 on every EPT entry | `test_ept`, `regressions/` |
| Tiger Lake (CET) | Emulated `CR0.WP = 0` while `CR4.CET = 1`, so VM entry failed | Full architectural CR0/CR4 validation before policy | `unpinned_cr0wp_cet_gp_reflected` |
| Load-time guards config | MTF step starved by interrupts while stepping a page-straddling instruction: one vCPU livelocked | One-instruction STI shadow for stepped entries; interrupt-window fallback for NMIs under STI blocking; step closure on emulated exits; 16-page step sets with per-slot scratch and recycling | `exec_watch_page_straddling_insn`, `mtf_step_interrupt_shadow` |
| No-DT-exiting config | DTR pins silently dropped while reported active | Refuse with `EOPNOTSUPP` at ioctl and at load | `nodtexit_dtr_pin_refused`, `nodtexit_no_phantom_dtr_pins` |
| Adversarial review | Host writes on the guest's behalf bypassed policy: hypercall buffers, `SGDT`/`SIDT`/`SLDT`/`STR`, A/D bits, `LTR` busy bit | `vtx_write_policy()` on every host write; byte-level locked busy-bit update after a write-intent walk | 15 integration tests, `test_walk`, `fuzz_walk` oracle |
| Adversarial review | Pinned `STAR`-family writes skipped architectural #GP; non-canonical `SYSENTER_EIP/ESP` could reach the VMCS and fail VM entry | Canonicality checks against the CPU's linear-address width; test-write-and-restore for pinned `STAR` MSRs | `root_fault_recovery_gp_reflected` under `pin=1023` |
| Review | `vtxctl stats --json` could emit invalid JSON (a leading comma) when exit reason 0 had no hits | Separator tracking | — |

---

## Reproducing

```bash
make test-unit                       # ~10 s
make test-fuzz FUZZ_TIME=300         # per harness
make check KDIR=/path/to/kernel      # isolation proof
make test-vm                         # builds Bochs and a test kernel into .cache, then runs the matrix
```

A single configuration:

```bash
KERNEL=.../bzImage KDIR=.../linux BOCHS=.../bochs BXSHARE=.../share/bochs \
VTX_PARAMS="pin=1023 guard_idt=2" tests/vm/run.sh tigerlake 2
```

Logs go to `tests/vm/out/<model>-<ncpu>.log`. That is the guest's serial console, including `vtxctl` output and, with `serial_events=1`, the hypervisor's own out-of-band event lines.
