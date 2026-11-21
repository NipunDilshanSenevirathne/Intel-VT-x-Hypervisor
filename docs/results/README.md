# Integration run logs

Serial consoles of the final integration matrix, ANSI colour codes stripped. Each file is everything the guest printed from boot to power-off: kernel messages, `vtxctl` output, one `TEST <name> PASS|FAIL <evidence>` line per check, and a closing `SUITE-END` line.

- Guest kernel: Linux 6.18.0 (`tests/vm/kernel.config`: IBT, retpoline and return-thunk mitigations, PTI)
- Emulator: Bochs `master` at `ffefe9f` with VMX, EPT, VPID and unrestricted guest
- Driver: `tests/vm/run.sh MODEL NCPU`, five unload/reload cycles per boot

| Log | Passed | Failed |
|---|--:|--:|
| [`corei7_sandy_bridge_2600k-1.log`](corei7_sandy_bridge_2600k-1.log) | 83 | 0 |
| [`corei7_haswell_4770-1.log`](corei7_haswell_4770-1.log) | 83 | 0 |
| [`corei7_haswell_4770-2.log`](corei7_haswell_4770-2.log) | 88 | 0 |
| [`corei7_skylake_x-2.log`](corei7_skylake_x-2.log) | 88 | 0 |
| [`corei7_icelake_u-4.log`](corei7_icelake_u-4.log) | 88 | 0 |
| [`tigerlake-2.log`](tigerlake-2.log) | 88 | 0 |
| [`sapphire_rapids-2.log`](sapphire_rapids-2.log) | 88 | 0 |
| [`haswell-nodtexit.log`](haswell-nodtexit.log) | 88 | 0 |
| [`haswell-loadguards.log`](haswell-loadguards.log) | 80 | 0 |

In `haswell-loadguards.log` the hypervisor's own out-of-band event lines (`vtxhv-ev seq=...`, written from VMX root to the UART because of `serial_events=1`) are interleaved with the guest's output. That is the out-of-band channel working as intended, and it is the configuration that exposed the MTF interrupt-starvation bug described in `../TESTING.md`.
