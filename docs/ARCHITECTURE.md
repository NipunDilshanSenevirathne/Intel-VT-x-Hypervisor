# Architecture

This document walks through every mechanism in the hypervisor, in the order the code executes it. File references point at the sources that implement each part.

- [1. Two modules, two trust domains](#1-two-modules-two-trust-domains)
- [2. Probing the CPU](#2-probing-the-cpu)
- [3. The hypervisor arena](#3-the-hypervisor-arena)
- [4. A private host environment](#4-a-private-host-environment)
- [5. EPT: MTRR-aware, per-CPU identity views](#5-ept-mtrr-aware-per-cpu-identity-views)
- [6. Programming the VMCS](#6-programming-the-vmcs)
- [7. Launching: turning a running CPU into a guest](#7-launching-turning-a-running-cpu-into-a-guest)
- [8. The VM-exit path](#8-the-vm-exit-path)
- [9. Memory introspection: watches and MTF step-over](#9-memory-introspection-watches-and-mtf-step-over)
- [10. Self-protection](#10-self-protection)
- [11. Control-register, MSR and descriptor-table pinning](#11-control-register-msr-and-descriptor-table-pinning)
- [12. NMI virtualization](#12-nmi-virtualization)
- [13. Events and task attribution](#13-events-and-task-attribution)
- [14. Hypercalls and the one-way lock](#14-hypercalls-and-the-one-way-lock)
- [15. Devirtualization](#15-devirtualization)
- [16. CPU hotplug, suspend, reboot](#16-cpu-hotplug-suspend-reboot)
- [17. Build-time verification](#17-build-time-verification)

---

## 1. Two modules, two trust domains

| Module | Runs in | Contents | Built as |
|---|---|---|---|
| `vtxhv_root.ko` | **VMX root** | VM-exit stub and dispatcher, EPT engine, guest page walker, descriptor-table emulator, event rings, MTRR resolver, host IDT stubs, fault-recovering MSR/XSETBV helpers, the `VMLAUNCH` trampoline | One translation unit (`vtxhv_root.c` includes every root source plus `root_entry.inc`) |
| `vtxhv.ko` | Guest (normal kernel) | Capability probing, arena allocation, host page tables, EPT view construction, VMCS programming, CPU hotplug, PM and reboot notifiers, the `/dev/vtxhv` ioctl device | Regular composite module |

The split exists because code that runs in VMX root on a private address space has to obey rules the kernel's build system would otherwise break:

- **No calls into the kernel.** The host page tables map only RAM and the root image (section 4). One call into kernel text from VMX root is a host page fault.
- **No load-time patching.** ftrace call sites, return thunks (`__x86_return_thunk`), retpoline sites, alternatives, jump labels, call-depth padding: the kernel rewrites all of them when a module loads, often into jumps to kernel text. The root image is compiled without `-pg`, `RETPOLINE_CFLAGS`, `PADDING_CFLAGS`, the stack protector, KASAN/KCSAN/UBSAN/KCOV and auto-var-init, so it contains no patch sites at all.
- **objtool must not touch it.** With `CONFIG_X86_KERNEL_IBT`, kbuild runs objtool on whole composite modules and per-object opt-outs are ignored. A *single-object* module honours `OBJECT_FILES_NON_STANDARD`, which is why the root image is one TU.

The result is checked on every build (section 17): the root image has **zero undefined symbols**, no writable sections, no patch sites, no indirect branches, and every global function lives in `.kprobes.text`, so kprobes refuse to plant breakpoints in it.

The control plane reaches the root image only through `EXPORT_SYMBOL_GPL` entry points it calls *before* a CPU is launched (EPT construction, `vtx_apply_cr_policy`), plus addresses it writes into the VMCS (`vtx_exit_stub`, IDT stubs) and the fixup table.

## 2. Probing the CPU

`vtx_probe()` (`setup.c`) refuses to load unless every precondition holds:

1. `GenuineIntel`, `CPUID.1:ECX.VMX`.
2. `IA32_FEATURE_CONTROL` locked with *VMX outside SMX* enabled. Linux itself locks this MSR during boot and only sets the VMX bit when `CONFIG_KVM_INTEL` is enabled, so the module tells you exactly that when it fails.
3. `CR4.VMXE` clear on the probing CPU: if KVM already owns VMX, it backs off instead of colliding.
4. Call-depth tracking (`retbleed=stuff`) off: those call thunks write to `%gs`-relative per-CPU memory and would corrupt the host.
5. Capabilities: all VMX MSRs are captured (`vtx_caps`, exposed by `vtxctl caps`). Controls are computed with the *TRUE* MSRs when `IA32_VMX_BASIC[55]` is set, by `vtx_ctl_adjust()`: `(want | allowed0) & allowed1`.

Required features: EPT with 4-level walks, a WB or UC EPTP memory type, INVEPT (single or all context), MSR bitmaps, secondary controls, the monitor trap flag, and EFER load/save on entry and exit. Optional features are used when present: VPID, virtual NMIs with NMI-window exiting, unrestricted guest, descriptor-table exiting, 1 GiB and 2 MiB EPT pages, and execute-only EPT pages. Pass-through features are also enabled when present, because Linux has already patched itself to use them and would take #UD otherwise: `RDTSCP`, `INVPCID`, `XSAVES/XRSTORS` (with a zeroed XSS-exiting bitmap), `TPAUSE/UMWAIT` and `PCONFIG`.

Probing also walks `iomem_resource` to learn the RAM ranges (`System RAM`), the physical extent of `Kernel code` and `Kernel rodata` (used by the guards, so no `kallsyms` hacks are needed), and loads the full MTRR state (fixed and variable).

## 3. The hypervisor arena

Everything the host touches at run time is carved from a small number of naturally aligned 2 MiB chunks (`vtx_carve()`, falling back to smaller orders under fragmentation):

```
global state ─ EPT page pool (+ PA index) ─ sink page ─ MSR bitmap ─ host IDT
per CPU:  vcpu ─ VMXON region ─ VMCS ─ 4 scratch slots ─ host GDT ─ host TSS ─ 16 KiB stack (16 KiB aligned) ─ event ring
host page tables (carved on demand while mapping)
```

The chunk list becomes the **owned ranges**, which every EPT view redirects to the sink page (section 10). Keeping allocations in a few large chunks keeps that list short and forces few EPT splits.

The driver never reads arena memory after a CPU is launched: it sees zeros. The first test run showed this directly, when a status banner printed after launch came back as `EPT pool 7/0`. That is the self-protection working, so the driver keeps its own copies of anything it reports.

## 4. A private host environment

When a VM exit happens the CPU loads host state from the VMCS. Every piece of it belongs to the hypervisor:

| Host state | Value | Why |
|---|---|---|
| `CR3` | Private page tables (4- or 5-level, matching `CR4.LA57`) | Maps the kernel direct map for **RAM ranges only** (1 GiB/2 MiB/4 KiB leaves, NX) plus the root module's text (RX) and rodata (R, NX). Nothing else: not the kernel, not the control-plane module, not module data. Any stray access is a host #PF that is reported on the UART. |
| `GDTR` | Per-CPU private GDT | Kernel CS at 0x10, DS at 0x18, a TSS descriptor at 0x40 (same selectors as Linux, so IRET frames stay valid). |
| `TR` | Private 104-byte TSS | Never used for stack switching: every host IDT gate has IST = 0. |
| `IDTR` | Private IDT | 32 gates. #NMI goes to `vtx_nmi_stub`; everything else goes to `vtx_idt_common` → `vtx_host_exception()`. The hardware resets the IDTR limit to 0xFFFF on exit, so vectors 32–255 are non-present and fault into #NP. |
| `RSP` | `stack_base + 16 KiB − 64` | The vcpu pointer lives in the top 8 bytes. The 40 bytes below hold the IRET frame used for devirtualization. |
| `RIP` | `vtx_exit_stub` | Starts with `ENDBR64`, because a VM exit can arm the IBT tracker, like KVM's `vmx_vmexit`. |
| `GS.base` | vcpu | Informational. Host code finds its vcpu from the stack (`rsp & ~(16K-1)`), so NMIs can do the same at any point. |
| `EFER` | Current EFER | Loaded on exit (`EXIT_LOAD_EFER`). |
| `CR0`, `CR4` | Current values plus `VMXE` | SMEP and SMAP stay on in the host; all host mappings are supervisor-only. |

Host code is written to need nothing else. Copies use `rep movsb`/`rep stosb` inline asm, because the compiler is allowed to turn loops into `memcpy` calls. There are no function pointers, no stack protector, no ftrace, no static keys and no paravirt calls: every privileged operation is raw inline asm (`vtx_arch.h`).

**Fault recovery inside VMX root.** `RDMSR`, `WRMSR` and `XSETBV` executed on the guest's behalf can fault. They run through `vtx_safe_*` stubs whose faulting instruction address and recovery address are recorded in `g->fix[]`. `vtx_host_exception()` rewrites the frame's RIP and returns, and the handler then reflects #GP into the guest. The test suite exercises this by writing a non-canonical address to `IA32_LSTAR`.

## 5. EPT: MTRR-aware, per-CPU identity views

Every CPU gets **its own EPT hierarchy** (`vtx_ept_build()`, `prep.c`). All views map the same physical memory identically. They are allowed to differ only for the duration of a single-step (section 9), and that is what makes step-over safe across CPUs.

**Construction.** For each 1 GiB region the builder tries a 1 GiB leaf. If that fails it tries 2 MiB leaves, then 4 KiB. A large leaf is used only if:

- the EPT capability supports that size,
- `vtx_mtrr_type()` reports a **uniform** memory type across the whole region, and
- the region contains no "special" page: owned, self, or watched (`vtx_tables_special()`).

Memory types follow the MTRRs exactly, because with `IPAT = 0` the effective type is `combine(EPT type, guest PAT)`. Using the MTRR type as the EPT type therefore gives the same effective type the bare-metal kernel had: UC for MMIO holes, and WC framebuffers still WC through PAT. The resolver implements fixed ranges (the 88 sub-ranges below 1 MiB) and variable ranges with arbitrary masks. A variable MTRR whose mask has bits inside the probed range "partially covers" it and forces a split. At 4 KiB that can never happen, so the recursion always terminates. Overlap rules follow the SDM: any UC wins, WT plus WB gives WT, and anything else undefined becomes UC.

**Map limit.** The views cover `[0, max(RAM end, 4 GiB))` rounded to 1 GiB. Above that, GPAs (for example 64-bit PCI BARs) are mapped **on demand**: an EPT violation on an unmapped GPA gets a 2 MiB or 4 KiB identity mapping with the MTRR-derived type (`vtx_map_on_demand()`). This avoids building tables for a 64 TiB `MAXPHYADDR` space.

**Entry format.** Leaf entries carry, beyond the architectural bits:

| Bits | Meaning |
|---|---|
| 11 (`EPT_SWVALID`) | Set on every entry the hypervisor writes. Without it, a fully denied leaf for physical page 0 with UC type is all-zero apart from the tag, and was once mistaken for "not present". The libFuzzer harness found that, and it is now a regression test. |
| 52–55 (tag) | `NONE`, `WATCH`, `SINK`, `SELF`, `STEP`. The violation handler classifies a fault from the leaf alone. |

**Run-time changes.** `vtx_ept_split()` turns a 1 GiB or 2 MiB leaf into 512 children, preserving permissions, memory type and tag, then publishes the new table with a single 64-bit store. Splitting never changes translations, so no invalidation is needed. Tightening a permission is always followed by `INVEPT`: immediately on the CPU that made the change, and on the others through an EPT generation counter checked on every exit plus a broadcast `SYNC` hypercall from the driver. Table pages come from a pre-allocated pool, because the host cannot allocate memory.

## 6. Programming the VMCS

`vtx_vmcs_setup()` (`setup.c`) writes every field explicitly; `VMCLEAR` does not define field contents. Highlights:

| Area | Setting |
|---|---|
| Pin | NMI exiting + virtual NMIs (when available) |
| Primary | MSR bitmaps, secondary controls. MTF and NMI-window exiting are toggled at run time. With non-TRUE controls, CR3 load/store exiting is forced on and handled. |
| Secondary | EPT, VPID, unrestricted guest, descriptor-table exiting, plus the pass-through set from section 2 |
| Exit | 64-bit host, save/load EFER, conceal VMX from PT when available |
| Entry | IA-32e guest, load EFER, conceal VMX from PT when available |
| Exception bitmap | 0: guest exceptions never exit |
| MSR bitmap | Write-intercept for `EFER`, `STAR`, `LSTAR`, `CSTAR`, `FMASK` and `SYSENTER_CS/ESP/EIP`; everything else passes through |
| CR0 mask | Fixed bits plus `WP`. Guest reads see the read shadow. |
| CR4 mask | Fixed bits, unsupported bits, `VMXE` (hidden: the shadow reports 0), `SMEP`, `SMAP` and `UMIP` |
| VPID | `cpu + 1` |
| Link pointer | `~0` |

Guest state is a snapshot of the running CPU: control registers, `DR7`, `DEBUGCTL`, `EFER`, the `SYSENTER` MSRs, all six segment registers (access rights from `LAR`, limits from `LSL`, null selectors marked unusable), LDTR and TR (bases decoded from the 16-byte system descriptors in the live GDT), and GDTR/IDTR. The same snapshot becomes the **baseline** that the pinning policy enforces: the GDT's fixmap and writable aliases, the IDT, TR, and the `STAR`/`LSTAR`/`CSTAR`/`FMASK`/`SYSENTER`/`EFER` values.

## 7. Launching: turning a running CPU into a guest

`vtx_cpu_launch()` runs on the target CPU (it is a CPU-hotplug "online" callback) with interrupts disabled:

1. Set `CR4.VMXE` with a raw `mov` (Linux's CR4 shadow is left untouched, so Linux keeps seeing `VMXE = 0`), then `VMXON`, `INVEPT` all-context, `INVVPID` all-context, `VMCLEAR` and `VMPTRLD`.
2. `vtx_vmcs_setup()`.
3. `vtx_asm_launch()` saves callee-saved registers and `RFLAGS`, writes `GUEST_RSP` = its own stack pointer, `GUEST_RIP` = a label right after `VMLAUNCH`, and `GUEST_RFLAGS`, zeroes `RAX`, and executes `VMLAUNCH`.
4. On success the CPU "returns" from `VMLAUNCH` *as a guest* at that label, with every GPR intact and `RAX = 0`. The function pops its frame and returns 0. Linux carries on exactly where it was, now in VMX non-root.
5. `VMfailInvalid` and `VMfailValid` fall through with flags set and are decoded into an error. An *invalid guest state* failure arrives as a VM exit with bit 31 set. The host notices `launched == 0` and devirtualizes straight back to the same label with `RAX = (3 << 32) | reason`, so even that failure mode unwinds cleanly.

## 8. The VM-exit path

`vtx_exit_stub` (`root_entry.inc`) saves the 15 GPRs (`RSP` lives in the VMCS), loads the vcpu from the top of the host stack, aligns the stack and calls `vtx_handle_exit()` (`host.c`). If that returns 0, the GPRs are restored and `VMRESUME` runs; a failed `VMRESUME` falls into `vtx_resume_failed()`, which writes a full dump to the UART and halts. A non-zero return means "devirtualize", and the stub restores the GPRs and executes `IRETQ` into the frame prepared by `vtx_devirt_prepare()`.

The dispatcher first refreshes per-CPU state against global generation counters (`INVEPT` if the EPT generation moved, CR masks if the policy generation moved), then switches on the basic exit reason:

| Exit | Handling |
|---|---|
| `EXCEPTION_NMI` | NMI: queued (section 12). Anything else is re-injected unchanged. |
| `NMI_WINDOW`, `INTR_WINDOW` | Injection happens in the epilogue. The interrupt window is used only for an NMI that is pending under STI blocking (section 12). |
| `TRIPLE_FAULT`, `EPT_MISCONFIG`, unknown exits | UART dump, then halt |
| `INIT` | Logged as an event and dropped. Hotplug is handled by devirtualizing first (section 16). |
| `CPUID` | Executed natively. Leaf 1 sets the hypervisor bit and hides VMX. Leaves `0x40000000–0x400000ff` report the signature `VtxHvIntrspc`, version, features, policy, lock state and number of virtualized CPUs. |
| `GETSEC`, `XSAVES`/`XRSTORS` | #UD |
| `INVD` | Executed as `WBINVD` |
| `VMCALL` | Hypercall ABI (section 14). CPL > 0 or a bad magic number gives #UD. |
| VMX instructions | #UD plus a `vmx-insn` event. Nested hypervisors such as KVM fail gracefully through their own exception fixups. |
| `CR_ACCESS` | Architectural emulation of `MOV CR0/CR3/CR4`, `CLTS` and `LMSW` with full validity checks (section 11) |
| `MSR_READ`/`MSR_WRITE` | VMCS-backed MSRs (`EFER`, `SYSENTER_*`, `FS/GS_BASE`, `DEBUGCTL`) are read and written through the VMCS; the rest go through the fault-recovering stubs. Monitored MSRs produce events and are subject to pins. |
| `XSETBV` | Fault-recovering `XSETBV`; #GP on failure |
| `GDTR_IDTR`/`LDTR_TR` | Full emulation of `SGDT`/`SIDT`/`LGDT`/`LIDT`/`SLDT`/`STR`/`LLDT`/`LTR` (section 11) |
| `EPT_VIOLATION` | Section 9 |
| `MTF` | Completes a step-over |

The epilogue injects any pending event, opens the one-instruction interrupt shadow for a fresh step (section 9), updates `CPU_BASED_VM_EXEC_CONTROL` (MTF, NMI or interrupt window) and records per-reason exit counts and TSC cycles, which `vtxctl stats` reports. Every emulated instruction goes through `vtx_skip()`. Besides advancing RIP, it clears STI and MOV-SS blocking and, if the guest is single-stepping with `RFLAGS.TF`, sets `BS` in the pending-debug-exceptions field so the guest's #DB still fires, as on real hardware.

Events that were being delivered when an exit happened (IDT-vectoring information) are re-injected with their error code and instruction length. When an EPT violation interrupts the `IRET` that ends a guest NMI handler, virtual-NMI blocking is restored (the qualification's bit 12), so the guest never gets a nested NMI it could not have received natively.

## 9. Memory introspection: watches and MTF step-over

A **watch** is a physically contiguous GPA range with a deny mask (`r`, `w`, `x` in any combination) and a mode:

- **monitor**: log the access and let it happen.
- **enforce**: log it and refuse it. Writes are silently discarded; instruction fetches get #GP.

Ranges are rounded out to whole 4 KiB pages, the granularity of EPT, and every access to a covered page is handled. Byte-exact filtering is deliberately not attempted: without decoding every instruction's access width, a wide store that begins outside the range (`FXSAVE`, `XSAVE`, a vector store) could overlap it unseen. Watching a virtual range (`--virt` or `--sym`) is translated page by page in the driver and coalesced into physical runs that share one watch id. Permission combinations that EPT cannot express are normalized: without read permission, write is dropped too, and so is execute unless execute-only pages are supported.

An EPT violation on a page tagged `WATCH` does the following (`vtx_ept_violation()`, `host_mem.c`):

```
lock EPT ─ classify access (R/W/X) ─ bump hit counters ─ build event (gpa, gla, rip, rsp, cr3, pagewalk?, old 8 bytes)
  exec + enforce  → inject #GP, commit event
  write + enforce → copy page → a per-CPU scratch slot, map GPA → slot RWX in *this CPU's view*, arm MTF
  otherwise       → grant the missing permission in *this CPU's view*, arm MTF
unlock ─ open a one-instruction interrupt shadow ─ VMRESUME ─ guest executes exactly one instruction ─ MTF exit
  ─ capture the new 8 bytes (from the real page, or from scratch for a discarded write)
  ─ recompute the entry from policy (vtx_page_entry) ─ INVEPT own view ─ commit event
```

Why this is correct:

- **Per-CPU views.** The relaxed permission exists only in the view of the CPU running that one instruction. A second CPU cannot write through the window (monitor) or fetch modified bytes from scratch (enforce), which a single shared EPT would allow.
- **Recomputation, not restoration.** After the step, the leaf is recomputed from the *current* policy, so a watch added or removed by another CPU during the step is honoured.
- **Multi-page instructions.** Up to sixteen pages per step are tracked, with four scratch slots per CPU, so that every redirected page of one instruction has its own copy. Examples: an instruction that straddles two exec-watched pages, `MOVS` from one watched page to another, a split-lock RMW across two enforced pages, or a page-walk access plus a data access. If an instruction somehow needs more, the step set is recycled rather than aborting the host: every page is re-protected, `INVEPT` runs, and the new page starts a fresh set. Instructions that make partial progress (gathers, string iterations) still complete.
- **Interrupts cannot starve a step.** Physical interrupts are delivered straight to the guest. Without care, an interrupt that arrives on the VM entry that follows a violation is delivered *before* the stepped instruction. MTF then fires at the first handler instruction, the protections come back, the instruction is retried, faults again, and the cycle can repeat forever. The `haswell-loadguards` run hit exactly this: an `ENDBR64` straddling two exec-watched pages, plus the UART interrupts produced by `serial_events=1`, kept one vCPU spinning between the two pages. The epilogue now sets *blocking by STI* in the guest interruptibility state for the stepped entry when `RFLAGS.IF = 1`, `TF = 0`, no MOV-SS blocking, no pending debug exception and no event injection. That is precisely the one-instruction shadow an `STI` would create, and it expires when the instruction retires. `vtxctl stats` counts these shadows. NMIs still exit to the host, and an NMI that is pending during the shadow is delivered through the interrupt window (see §12).
- **Steps that end in an emulated exit.** If the stepped instruction itself causes an exit that the host emulates (`CPUID`, `WRMSR`, `SGDT`, `VMCALL`, ...), `vtx_skip()` marks the step as retired and the handler closes it immediately. Otherwise one more guest instruction would run with the relaxed permissions.
- **Old/new values.** Write events carry the 8 bytes at the faulting GPA before and after the instruction. For an enforce-mode write, "new" is the value the attacker *tried* to write, read from scratch.
- A violation whose access is already permitted (a stale TLB entry after another CPU relaxed a permission) is counted as spurious and answered with `INVEPT`.

## 10. Self-protection

Three classes of pages are marked in every view at build time:

| Class | Pages | Guest sees | Guest write | Guest fetch |
|---|---|---|---|---|
| `SINK` | Every arena chunk: VMCS, VMXON, stacks, EPT tables, rings, page tables, policy | The **sink page** (all zeros, read-only) | Discarded through scratch, `tamper` event | #GP, `tamper` event |
| `SELF` executable | Root image text | The real page, R+X | Discarded, `tamper` event | Allowed |
| `SELF` read-only | Root image rodata | The real page, R | Discarded, `tamper` event | #GP |

The host's own accesses are not subject to EPT, so it works on the real pages. Because the host never reads guest-writable memory for control decisions, all policy, watch tables, baselines and the vcpu live in the arena. A kernel-level attacker who knows the arena's physical address (`vtxctl status` prints it) can neither read nor modify any of it. The test suite proves this: it reads the arena through a fresh RW alias and gets zeros, writes `0x41` and reads back `0x0`, and writes `0xcc` over root code and reads the original byte back, with each attempt logged as `tamper`.

The page walker and introspection helpers refuse to follow guest pointers into owned memory (`vtx_phys_ok()`), so the host cannot be turned into an oracle for its own memory either.

**No confused deputy.** The host writes guest memory on the guest's behalf in five places:

- accessed/dirty updates during an emulated page walk,
- `SGDT`/`SIDT`/`SLDT`/`STR` with a memory destination,
- the TSS busy bit set by `LTR`,
- the output buffers of the `DRAIN`, `STATS`, `QUERY` and `WLIST` hypercalls.

Host writes are not subject to EPT, so each of these could turn the hypervisor into a write primitive *into its own image* or into a guarded page. An example is a `WLIST` hypercall whose buffer is the physical address of `vtx_handle_exit`, with watch names chosen as shellcode. Every such write now goes through `vtx_write_policy()`, the same classification EPT applies:

| Target page | Emulated write | Event |
|---|---|---|
| Open | performed | none |
| Watched, monitor | performed | `ept-write`, `via-emulator` |
| Watched, enforce | discarded (the instruction completes, as with scratch) | `ept-write` `DENIED`, `via-emulator` |
| Root image or arena | discarded | `tamper` `DENIED`, `via-emulator` |

Hypercall output buffers are stricter: any page that is not open fails the call with `-EFAULT` and raises a `hypercall` event naming the protected page. A/D updates into protected paging structures are skipped. The guest-copy fuzzer checks one invariant on every input: *no byte of a page whose policy is deny or self ever changes*, whether through data writes or A/D updates.

## 11. Control-register, MSR and descriptor-table pinning

**Audit vs. pin.** `CR0.WP`, `CR4.SMEP`, `CR4.SMAP` and `CR4.UMIP` are *always* in the guest/host masks, so every change to them is logged. Linux never toggles them after boot, so this costs nothing. A **pin** turns the audit into enforcement: the write still completes, but the pinned bit keeps its value in both the real register and the read shadow, and the event is marked `DENIED`.

**Architectural fidelity.** An emulated `MOV to CR0/CR4` must fault exactly where silicon would; otherwise the next VM entry fails its guest-state checks. `vtx_emul_cr0()` and `vtx_emul_cr4()` inject #GP for:

- reserved bits,
- `NW` without `CD`,
- `PG` without `PE`,
- clearing `PG` in long mode,
- **clearing `WP` while `CR4.CET = 1`**,
- clearing `PAE` or changing `LA57` in long mode,
- setting `PCIDE` with a non-zero PCID in CR3 or outside long mode,
- setting `CET` without `WP`.

The CET rule was found by the Tiger Lake run of the test matrix, where the kernel runs with IBT enabled. A TLB flush (`INVVPID`) follows any emulated change to paging-relevant CR4 bits.

**MSRs.** Writes to the system-call MSRs (`STAR`, `LSTAR`, `CSTAR`, `FMASK`), the `SYSENTER` triple and `EFER` are always logged with old and new values. When pinned, a write that would change the per-CPU baseline (or clear `NXE`, `SCE` or `LME` in `EFER`) is skipped. The classic `LSTAR` syscall hook then simply does not happen, and the test proves the machine keeps running.

Architectural faults come first here too. A non-canonical `SYSENTER_ESP`/`SYSENTER_EIP`/`FS.base`/`GS.base` raises #GP, checked against the CPU's linear-address width from `CPUID.80000008H`. Without that check, the value would reach a VMCS field that VM entry requires to be canonical, and the next entry would fail. A pinned `STAR`-family write is test-written to the real MSR and immediately restored, so a value the CPU rejects still raises #GP instead of a silent "success". The host never executes `SYSCALL`, so the transient value is never used.

**Descriptor tables.** With descriptor-table exiting enabled, all eight instructions trap and are emulated (`vtx_dtr_exit()`):

- Memory operands are decoded from the VM-exit instruction-information field and the displacement in the exit qualification, including base, index, scale, address size and segment (FS/GS bases in 64-bit mode, full segmentation in compatibility mode).
- They are translated through the guest's paging structures with a full permission model: U/S, R/W, NX, `CR0.WP`, SMEP, SMAP with `RFLAGS.AC`, accessed and dirty updates. That model is checked against an independent SDM reference across all 786,432 combinations in the unit tests.
- Multi-page stores are all-or-nothing, like hardware: both pages are translated before a byte is written.
- Faults are reflected as #PF with the correct error code and `CR2`.
- Register-destination `SLDT` and `STR` honour a `0x66` operand-size prefix, decoded from the guest instruction bytes.
- `LLDT` and `LTR` read and validate the descriptor (type, present bit). `LTR` sets the busy bit as hardware does: a write-intent, implicit-supervisor walk to byte 5 of the descriptor (so a read-only GDT mapping raises #PF *before* TR changes), then a single locked `OR` of bit 1, subject to the write policy above. The earlier version wrote the whole 8-byte descriptor through a read-intent translation, which could spill into the wrong physical page for a misaligned GDT and ignored write protection.

`LGDT`/`LIDT` to anything other than the baseline is logged, and refused when `gdtr`/`idtr` are pinned; both legitimate GDT aliases, fixmap and writable, are accepted. `LTR` to a different TSS can be pinned as well.

Without descriptor-table exiting (`dtexit=0`, or a CPU without it), the `idtr`, `gdtr` and `tr` pins cannot be enforced. They are therefore *refused*: `vtxctl pin idtr` fails with `EOPNOTSUPP` and an explanation, and `pin=` at load time makes `insmod` fail. A pin the hypervisor cannot honour is never reported as active. Earlier builds dropped such pins silently, and the `haswell-nodtexit` run exposed it.

On UMIP-capable CPUs, user-mode `SGDT`/`SIDT`/`SLDT`/`STR` raise #GP *before* the VM exit (privilege faults outrank instruction exits), and Linux's UMIP emulator answers them. The test suite checks both behaviours.

## 12. NMI virtualization

NMIs belong to the guest. Three cases are handled:

1. **NMI while the guest runs.** NMI exiting is on, so the NMI causes a VM exit and is queued (`nmi_pending`).
2. **NMI while the host runs.** It arrives through the host IDT at `vtx_nmi_stub`, which finds the vcpu from the stack, atomically increments `nmi_pending` and, if VMX is active, sets NMI-window exiting directly with `VMREAD`/`VMWRITE`. Those are single instructions, so they are safe to interleave with the interrupted handler. The epilogue writes the controls and then re-checks `nmi_pending`, which closes the lost-update window between the two.
3. **Delivery.** If the guest is not blocking (no STI, MOV-SS or virtual-NMI blocking), the NMI is injected right away. Otherwise a window exit is armed. With virtual NMIs, the processor tracks virtual blocking until the guest's `IRET`.

One subtlety: the SDM lets a processor take an NMI-window exit even while *blocking by STI* is in effect, but injecting an NMI under STI blocking may itself fail VM entry. A naive VMM can then loop forever: window exit, refuse to inject, re-arm. KVM avoids this by using the interrupt window instead, and so does `vtx_nmi_window()`. STI blocking implies `IF = 1`, so the interrupt window opens right after the next instruction, and the NMI goes in on that exit.

The SMP runs drive this with `echo l > /proc/sysrq-trigger`. Every other CPU receives an NMI backtrace IPI, and `vtxctl stats` shows the reflected count.

## 13. Events and task attribution

Events (`struct vtx_event`, 128 bytes) go into a per-CPU single-producer/single-consumer ring in the arena (`ring.c`). The head and tail sit on separate cache lines and are published with compiler barriers, which is enough on x86-TSO. A full ring drops the newest event and counts it. A global sequence number (`lock xadd`) orders events across CPUs. Optionally (`serial_events=1`) each event is also written to the UART from VMX root, an **out-of-band channel** that a compromised guest kernel cannot filter.

Every event is attributed to the guest task. The host takes the guest's kernel GS base (the VMCS field in kernel mode, `IA32_KERNEL_GS_BASE` in user mode, and the other one inside the `swapgs` window), adds the per-CPU offset of `current_task` (measured at load as `this_cpu_ptr(&current_task) − GS.base`, which works for both zero-based and non-zero-based per-CPU layouts), and reads `task->tgid` and `task->comm`. All of this goes through `vtx_kva_to_gpa()`, which handles direct-map and kernel-image addresses without walking page tables and falls back to a full guest page walk. Every read is validated against the RAM map and the owned ranges, and non-printable characters are sanitized.

## 14. Hypercalls and the one-way lock

`VMCALL` with `RAX = 0x5654480000000000 | fn` (the top three bytes spell `"VTH"`), from CPL 0 only:

| fn | Name | Arguments | Notes |
|---|---|---|---|
| 0x01 | `PING` | | Returns the signature, version and lock state |
| 0x02 | `DEVIRT` | | Refused when locked |
| 0x03 | `SYNC` | | `INVEPT` and CR-policy refresh on this CPU |
| 0x04 | `PROTECT` | `RBX` start, `RCX` end, `RDX` deny \| mode<<8, `RSI` id, `RDI` name GPA | Rejected if the range touches owned, self or sink pages |
| 0x05 | `UNPROTECT` | `RBX` id | Refused when locked |
| 0x06 | `POLICY` | `RBX` set, `RCX` clear | Clearing refused when locked |
| 0x07 | `LOCK` | | Irreversible |
| 0x08 | `DRAIN` | `RBX` buffer GPA, `RCX` max events | |
| 0x09 | `STATS` | `RBX` buffer GPA | |
| 0x0a | `QUERY` | `RBX` buffer GPA | |
| 0x0b | `WLIST` | `RBX` buffer GPA | |

Buffers are guest-physical and bounds-checked against the RAM map. Output buffers must also consist only of pages whose write policy is *open*: no arena, root image, or watched page (see §10). Unknown functions return `-EINVAL`, bad buffers `-EFAULT`. A guessed magic from user space, or from kernel code without the magic, gets #UD, and a CPL 3 caller with the right magic is also logged.

**The lock is a ratchet**: protections can still be added, but nothing can be removed, the hypervisor cannot be devirtualized, CPUs cannot go offline, and suspend is refused. The driver takes a module reference so `rmmod` fails. A forced unload panics deliberately, because freeing the module text under a live hypervisor would be worse. The suite simulates a rootkit issuing `DEVIRT`, `POLICY(clear)` and `UNPROTECT` hypercalls of its own after locking, and all three return `-EPERM`.

## 15. Devirtualization

The `DEVIRT` hypercall (also used by `rmmod`, CPU offline and suspend) has to return the CPU to native execution with every piece of architectural state the guest expects. `vtx_devirt_prepare()` reads the guest state from the VMCS, then `VMCLEAR` and `VMXOFF`, and then, carefully ordered:

1. `CR3` ← guest. The host stack and root text are mapped in every kernel page table.
2. **TR.** Clear the busy bit of Linux's TSS descriptor through the per-CPU *writable* GDT alias, `LGDT` that alias, `LTR`, then `LGDT` the read-only fixmap GDT. This is the same dance as Linux's `force_reload_TR()`, and it restores the full TSS limit (VM exit truncates it to 0x67).
3. `LLDT`, `DS`, `ES`, `FS` plus `FS.base`, the `SYSENTER` MSRs, `EFER`, `DR7`, `DEBUGCTL`, `CR0`, and `CR4` without `VMXE`.
4. `GS` plus `GS.base`, and **then** `LIDT`. An NMI between these two steps still reaches the host stub, which finds its vcpu from the stack and not through GS, so it is harmless. After `LIDT`, NMIs go to Linux with a correct GS base and TR (IST stacks).
5. Fill the IRET frame (RIP advanced past `VMCALL`, CS, RFLAGS, RSP, SS), set `RAX = 0` and return 1. The stub then restores GPRs and executes `IRETQ`, which sets RIP, CS, RFLAGS, RSP and SS together.

## 16. CPU hotplug, suspend, reboot

- Virtualization is driven by a dynamic `cpuhp` state. Its *online* callback launches the CPU; its *offline* callback devirtualizes it, and returns `-EBUSY` when locked, which makes the kernel roll back the offline. A CPU that comes back is virtualized again. The SMP test runs offline cpu1, check, online it, and expect it virtualized again.
- PM notifier: devirtualize before suspend or hibernate, relaunch on resume, and refuse suspend when locked.
- Reboot notifier: devirtualize so that `kexec` hands a clean machine to the next kernel.

## 17. Build-time verification

`scripts/check_host_isolation.py` inspects `vtxhv_root.ko` with pyelftools and Capstone and fails the build unless:

```
PASS VMX-root image has zero external symbol dependencies
PASS no mutable static state in the root image
PASS no load-time code patching sites (ftrace/alternatives/thunks/jump labels)
PASS code only references root code and read-only data
PASS no indirect branches (immune to retpoline/IBT/kCFI rewriting)
PASS every global root function is kprobe-blacklisted (.kprobes.text)
```

These properties are what make the private host address space safe. If a compiler upgrade ever introduces a `memcpy` call or a jump table, the build fails instead of the machine.
