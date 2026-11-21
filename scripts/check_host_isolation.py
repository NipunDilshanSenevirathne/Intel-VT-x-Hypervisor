#!/usr/bin/env python3
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

try:
    import capstone
except ImportError:
    capstone = None

PATCH_SECTIONS = (
    "__mcount_loc", ".return_sites", ".retpoline_sites", ".call_sites",
    ".altinstructions", ".altinstr_replacement", "__jump_table",
    ".static_call_sites", "__patchable_function_entries", ".ibt_endbr_seal",
    ".parainstructions", ".smp_locks", "__bug_table", "__ex_table",
)
ALLOWED_RELOC_TARGETS = (".kprobes.text", ".text", ".rodata")


class Report:
    def __init__(self):
        self.failures = []
        self.passes = []

    def check(self, ok, what, detail=""):
        (self.passes if ok else self.failures).append((what, detail))

    def emit(self):
        for what, _ in self.passes:
            print(f"  \033[32mPASS\033[0m {what}")
        for what, detail in self.failures:
            print(f"  \033[31mFAIL\033[0m {what}: {detail}")
        return 0 if not self.failures else 1


def section_by_index(elf, idx):
    try:
        return elf.get_section(idx)
    except Exception:
        return None


def main(path):
    rep = Report()
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        symtab = elf.get_section_by_name(".symtab")
        if not isinstance(symtab, SymbolTableSection):
            print("no symbol table")
            return 2

        undefined = sorted(
            s.name for s in symtab.iter_symbols()
            if s.name and s["st_shndx"] == "SHN_UNDEF"
        )
        rep.check(not undefined, "VMX-root image has zero external symbol dependencies",
                  ", ".join(undefined[:12]))

        writable = []
        for sec in elf.iter_sections():
            flags = sec["sh_flags"]
            if flags & 0x2 and flags & 0x1 and sec["sh_size"] and not sec.name.startswith(".gnu.linkonce.this_module"):
                if sec.name not in (".data..once",):
                    writable.append(f"{sec.name}({sec['sh_size']})")
        rep.check(not writable, "no mutable static state in the root image", ", ".join(writable))

        present = [s.name for s in elf.iter_sections() if s.name in PATCH_SECTIONS and s["sh_size"]]
        rep.check(not present, "no load-time code patching sites (ftrace/alternatives/thunks/jump labels)",
                  ", ".join(present))

        bad_relocs = []
        for sec in elf.iter_sections():
            if not isinstance(sec, RelocationSection):
                continue
            target = section_by_index(elf, sec["sh_info"])
            if target is None or not (target["sh_flags"] & 0x4):
                continue
            for rel in sec.iter_relocations():
                sym = symtab.get_symbol(rel["r_info_sym"])
                if sym["st_shndx"] == "SHN_UNDEF":
                    bad_relocs.append(f"{target.name}+{rel['r_offset']:#x}->UNDEF:{sym.name}")
                    continue
                if not isinstance(sym["st_shndx"], int):
                    continue
                dst = section_by_index(elf, sym["st_shndx"])
                if dst is None:
                    continue
                if not dst.name.startswith(ALLOWED_RELOC_TARGETS) or dst.name.startswith(".rodata") is False and dst["sh_flags"] & 0x1:
                    bad_relocs.append(f"{target.name}+{rel['r_offset']:#x}->{dst.name}:{sym.name}")
        rep.check(not bad_relocs, "code only references root code and read-only data", "; ".join(bad_relocs[:8]))

        indirect = []
        rets = 0
        if capstone is not None:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            for sec in elf.iter_sections():
                if not (sec["sh_flags"] & 0x4) or not sec["sh_size"]:
                    continue
                code = sec.data()
                off = 0
                while off < len(code):
                    progressed = False
                    for ins in md.disasm(code[off:], off):
                        progressed = True
                        off = ins.address + ins.size
                        if ins.mnemonic in ("call", "jmp") and ("[" in ins.op_str or ins.op_str.startswith("r")):
                            indirect.append(f"{sec.name}+{ins.address:#x}: {ins.mnemonic} {ins.op_str}")
                        if ins.mnemonic == "ret":
                            rets += 1
                    if not progressed:
                        off += 1
        rep.check(capstone is not None and not indirect,
                  "no indirect branches (immune to retpoline/IBT/kCFI rewriting)",
                  "; ".join(indirect[:8]) if capstone else "capstone not installed")

        exported = []
        kp = elf.get_section_by_name(".kprobes.text")
        for s in symtab.iter_symbols():
            if s["st_info"]["type"] == "STT_FUNC" and s["st_info"]["bind"] == "STB_GLOBAL":
                sec = section_by_index(elf, s["st_shndx"]) if isinstance(s["st_shndx"], int) else None
                exported.append((s.name, sec is not None and sec.name == ".kprobes.text"))
        outside = [n for n, inside in exported if not inside]
        rep.check(not outside, "every global root function is kprobe-blacklisted (.kprobes.text)",
                  ", ".join(outside[:8]))
        text_size = kp["sh_size"] if kp else 0
        print(f"  root image: {text_size} bytes of VMX-root code, {len(exported)} global functions, {rets} returns")
    return rep.emit()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: check_host_isolation.py vtxhv_root.ko")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
