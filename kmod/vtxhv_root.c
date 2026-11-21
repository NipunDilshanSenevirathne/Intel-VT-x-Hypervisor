#include <linux/export.h>
#include "vtx.h"

#include "host_util.c"
#include "host.c"
#include "host_mem.c"
#include "host_hc.c"
#include "policy.c"
#include "ept.c"
#include "walk.c"
#include "ring.c"
#include "dtr.c"
#include "mtrr.c"

asm(".pushsection .kprobes.text, \"ax\"\n\t.include \"root_entry.inc\"\n\t.popsection\n");

extern struct module __this_module;
struct module * const vtx_root_module = &__this_module;

EXPORT_SYMBOL_GPL(vtx_root_module);
EXPORT_SYMBOL_GPL(vtx_asm_launch);
EXPORT_SYMBOL_GPL(vtx_exit_stub);
EXPORT_SYMBOL_GPL(vtx_idt_stubs);
EXPORT_SYMBOL_GPL(vtx_nmi_stub);
EXPORT_SYMBOL_GPL(vtx_fault_rdmsr);
EXPORT_SYMBOL_GPL(vtx_fixup_rdmsr);
EXPORT_SYMBOL_GPL(vtx_fault_wrmsr);
EXPORT_SYMBOL_GPL(vtx_fixup_wrmsr);
EXPORT_SYMBOL_GPL(vtx_fault_xsetbv);
EXPORT_SYMBOL_GPL(vtx_fixup_xsetbv);
EXPORT_SYMBOL_GPL(vtx_apply_cr_policy);
EXPORT_SYMBOL_GPL(vtx_self_find);
EXPORT_SYMBOL_GPL(vtx_tables_special);
EXPORT_SYMBOL_GPL(vtx_page_entry);
EXPORT_SYMBOL_GPL(vtx_mtrr_type);
EXPORT_SYMBOL_GPL(vtx_ept_map);
EXPORT_SYMBOL_GPL(vtx_pool_get);

#define VTX_MODINFO(tag, val) \
	static const char __UNIQUE_ID(vtx_modinfo)[] __used __section(".modinfo") __aligned(1) = tag "=" val

VTX_MODINFO("license", "GPL");
VTX_MODINFO("author", "Nipun Dilshan Senevirathne");
VTX_MODINFO("description", "Intel VT-x hypervisor: self-contained VMX-root image");
VTX_MODINFO("version", "1.0.0");
