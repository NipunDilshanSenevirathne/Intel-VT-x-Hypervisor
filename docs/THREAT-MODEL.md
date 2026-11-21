# Threat model

## What the hypervisor defends

The adversary is **code running in the guest kernel at CPL 0**, such as a rootkit loaded as a module or an exploit that has reached arbitrary kernel read/write. Once loaded (ideally from the initramfs) and **locked**, the hypervisor guarantees the following:

| Property | Mechanism |
|---|---|
| Kernel cannot read or modify hypervisor state | Every arena page is redirected to a read-only zero page in every per-CPU EPT view. Writes are discarded and logged as `tamper`. |
| Kernel cannot patch hypervisor code | Root image text is EPT read+execute only; writes are discarded and logged |
| Kernel cannot disable or unload the hypervisor | `DEVIRT`, `UNPROTECT` and pin-clearing hypercalls return `-EPERM` after the lock; `rmmod` fails; CPU offline and suspend are refused |
| Kernel cannot redirect the host | Host CR3, GDT, IDT, TSS and stack are private and hidden; the host executes only root-image code and reads no guest-writable control data |
| Kernel cannot use the hypervisor as a write primitive | Every host write made on the guest's behalf (emulated stores, A/D bits, the `LTR` busy bit, hypercall output buffers) passes the same write policy as EPT. Protected targets are refused and logged. |
| `CR0.WP`, `SMEP`, `SMAP` and `UMIP` stay on | CR guest/host masks plus pins. Every change is audited even when unpinned. |
| Syscall entry points cannot be hooked | `STAR`/`LSTAR`/`CSTAR`/`FMASK`/`SYSENTER_*`/`EFER` writes are intercepted and pinned to the per-CPU baseline |
| The IDT and GDT cannot be swapped | Descriptor-table exiting with `LIDT`/`LGDT`/`LTR` pinned to the baseline. Without descriptor-table exiting these pins are refused, never silently dropped. |
| The IDT contents cannot be rewritten | `vtxctl guard idt enforce` (an EPT write-deny watch on the IDT page) |
| Kernel text and rodata modification is visible, or prevented | `guard text\|rodata`, in monitor or enforce mode |
| Arbitrary memory regions are watched | EPT watches with per-access-type deny masks, monitor/enforce modes and old/new value capture |
| Attribution | Every event carries RIP, RSP, CR3, GPA, GLA, pid and comm |
| Out-of-band evidence | `serial_events=1` mirrors each event to the UART from VMX root, beyond the guest's reach |

## Assumptions

- **Load early, then lock.** Anything that ran in the kernel *before* the hypervisor launched could have prepared the ground, for example by pre-installing hooks the baseline then accepts. Load from the initramfs and use `lock=1` (or `vtxctl lock --yes`).
- The firmware, SMM and the CPU are trusted. SMM sits below VMX root.
- Physical memory is reached only through the CPU. **DMA is not mediated**: without VT-d/IOMMU policy, a device (or a compromised kernel programming one) can write arena memory directly. Enable the IOMMU in strict mode.
- `kexec` after locking is not supported. The next kernel would inherit an EPT that hides the arena. Reboot through firmware instead.

## Known limitations, stated plainly

- **The guest-side delivery path is trusted.** Events are drained through the `vtxhv.ko` driver, which runs in the guest. A kernel attacker can stop that path from *reporting*, but cannot stop enforcement or the UART mirror. Gaps in the sequence numbers reveal dropped events.
- **Enforce mode on kernel text is for quiescent systems.** Linux patches its own text at run time: static keys, ftrace, kprobes, `static_call`. Enforce discards those writes, and `text_poke()` then trips its `BUG_ON`. Use `monitor` (the default) on general-purpose machines, which logs every legitimate patch with old/new bytes.
- **Exec-enforce kills the offending context.** Executing from an exec-denied page injects #GP. If that happens in interrupt context, the kernel panics. That is a design choice, comparable to HVCI.
- **NMIs in flight during devirtualization** are counted but not re-raised.
- **A watch costs two exits per access.** Exec watches trap every instruction fetched from the page. Use them on narrow targets, not on hot kernel text.
- **Per-CPU event rings are bounded** (`ring_events`, default 1024). Bursts beyond that are dropped and counted, and the sequence numbers show the gap. The UART mirror is unaffected.
- **Validation was done under full-system emulation** (Bochs with VMX and EPT, seven CPU models: Sandy Bridge through Sapphire Rapids, 1–4 CPUs, 4- and 5-level paging, kernel IBT on and off). Bochs implements the SDM's VM-entry consistency checks in detail. Real silicon adds microarchitectural timing and errata that an emulator cannot reproduce, so validate on your own hardware (with a serial console) before relying on it.
- Intel VT-x only. AMD SVM is not supported.
