#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/ioport.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/irqflags.h>
#include <asm/desc.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/current.h>
#include <asm/io.h>
#include "vtx_drv.h"

struct vtx_drv vtx_d;

static struct vtx_range vtx_ram_tmp[VTX_MAX_RAM];
static u32 vtx_ram_n;
static u64 vtx_res_max;

extern unsigned int vtx_param_serial;
extern bool vtx_param_serial_events;
extern bool vtx_param_introspect;
extern unsigned int vtx_param_pin;

static void vtx_res_add_ram(u64 start, u64 end)
{
	start = ALIGN(start, PAGE_SIZE);
	end &= PAGE_MASK;
	if (end <= start)
		return;
	if (vtx_ram_n && vtx_ram_tmp[vtx_ram_n - 1].end == start) {
		vtx_ram_tmp[vtx_ram_n - 1].end = end;
		return;
	}
	if (vtx_ram_n < VTX_MAX_RAM) {
		vtx_ram_tmp[vtx_ram_n].start = start;
		vtx_ram_tmp[vtx_ram_n].end = end;
	}
	vtx_ram_n++;
}

static void vtx_res_walk(struct vtx_drv *d, struct resource *r, int depth)
{
	for (; r; r = r->sibling) {
		u64 s = r->start, e = (u64)r->end + 1;

		if (e > vtx_res_max && depth == 0 && r->child == NULL)
			vtx_res_max = e;
		if (r->name && depth == 0 && !strcmp(r->name, "System RAM"))
			vtx_res_add_ram(s, e);
		if (r->name && !strcmp(r->name, "Kernel code")) {
			d->ktext_start = s;
			d->ktext_end = e;
		}
		if (r->name && !strcmp(r->name, "Kernel rodata")) {
			d->krodata_start = s;
			d->krodata_end = e;
		}
		if (r->child && depth < 4)
			vtx_res_walk(d, r->child, depth + 1);
	}
}

static void vtx_load_mtrr(struct vtx_drv *d, u32 maxphy)
{
	struct vtx_mtrr *m = &d->mtrr;
	u64 cap = vtx_rdmsr(MSR_IA32_MTRRCAP);
	u64 def = vtx_rdmsr(MSR_IA32_MTRR_DEF_TYPE);
	u32 i;

	memset(m, 0, sizeof(*m));
	m->enabled = (def >> 11) & 1;
	m->fixed_enabled = ((def >> 10) & 1) && ((cap >> 8) & 1);
	m->def_type = def & 0xff;
	m->nvar = cap & 0xff;
	if (m->nvar > VTX_MTRR_MAX_VAR)
		m->nvar = VTX_MTRR_MAX_VAR;
	m->phys_mask = ((1ull << maxphy) - 1) & ~0xfffull;
	for (i = 0; i < m->nvar; i++) {
		m->base[i] = vtx_rdmsr(MSR_IA32_MTRR_PHYSBASE0 + 2 * i);
		m->mask[i] = vtx_rdmsr(MSR_IA32_MTRR_PHYSBASE0 + 2 * i + 1);
	}
	if ((cap >> 8) & 1) {
		vtx_mtrr_set_fixed_msr(m, 0, vtx_rdmsr(MSR_IA32_MTRR_FIX64K_00000));
		vtx_mtrr_set_fixed_msr(m, 1, vtx_rdmsr(MSR_IA32_MTRR_FIX16K_80000));
		vtx_mtrr_set_fixed_msr(m, 2, vtx_rdmsr(MSR_IA32_MTRR_FIX16K_A0000));
		for (i = 0; i < 8; i++)
			vtx_mtrr_set_fixed_msr(m, 3 + i, vtx_rdmsr(MSR_IA32_MTRR_FIX4K_C0000 + i));
	}
}

static u64 vtx_cap(struct vtx_drv *d, int idx)
{
	return d->caps[idx];
}

static int vtx_compute_controls(struct vtx_drv *d, u32 dtexit)
{
	int truec = (vtx_cap(d, VTX_CAP_BASIC) >> 55) & 1;
	u64 pinc = vtx_cap(d, truec ? VTX_CAP_TRUE_PIN : VTX_CAP_PINBASED);
	u64 procc = vtx_cap(d, truec ? VTX_CAP_TRUE_PROC : VTX_CAP_PROCBASED);
	u64 exitc = vtx_cap(d, truec ? VTX_CAP_TRUE_EXIT : VTX_CAP_EXIT);
	u64 entryc = vtx_cap(d, truec ? VTX_CAP_TRUE_ENTRY : VTX_CAP_ENTRY);
	u64 proc2c = vtx_cap(d, VTX_CAP_PROCBASED2);
	u32 want2;

	if (vtx_ctl_allowed(pinc, PIN_NMI_EXITING | PIN_VIRTUAL_NMIS) &&
	    vtx_ctl_allowed(procc, PROC_NMI_WINDOW)) {
		d->pin = vtx_ctl_adjust(pinc, PIN_NMI_EXITING | PIN_VIRTUAL_NMIS);
		d->vnmi = 1;
	} else {
		d->pin = vtx_ctl_adjust(pinc, 0);
		d->vnmi = 0;
	}
	if (d->pin & (PIN_EXT_INTR_EXITING | PIN_PREEMPT_TIMER)) {
		pr_err("vtxhv: pin-based controls force unsupported exiting (%#x)\n", d->pin);
		return -EOPNOTSUPP;
	}
	d->proc = vtx_ctl_adjust(procc, PROC_USE_MSR_BITMAPS | PROC_SECONDARY);
	if ((d->proc & (PROC_USE_MSR_BITMAPS | PROC_SECONDARY)) != (PROC_USE_MSR_BITMAPS | PROC_SECONDARY)) {
		pr_err("vtxhv: MSR bitmaps or secondary controls unsupported\n");
		return -EOPNOTSUPP;
	}
	if (d->proc & (PROC_HLT_EXITING | PROC_UNCOND_IO | PROC_MOV_DR_EXITING | PROC_INVLPG_EXITING |
		       PROC_CR8_LOAD_EXITING | PROC_CR8_STORE_EXITING | PROC_USE_IO_BITMAPS | PROC_TERTIARY)) {
		pr_err("vtxhv: processor-based controls force unsupported exiting (%#x)\n", d->proc);
		return -EOPNOTSUPP;
	}
	if (!vtx_ctl_allowed(procc, PROC_MTF) || !vtx_ctl_allowed(procc, PROC_INTR_WINDOW)) {
		pr_err("vtxhv: monitor trap flag or interrupt-window exiting unsupported\n");
		return -EOPNOTSUPP;
	}
	want2 = PROC2_EPT;
	if (vtx_ctl_allowed(proc2c, PROC2_VPID))
		want2 |= PROC2_VPID;
	if (vtx_ctl_allowed(proc2c, PROC2_RDTSCP))
		want2 |= PROC2_RDTSCP;
	if (vtx_ctl_allowed(proc2c, PROC2_INVPCID))
		want2 |= PROC2_INVPCID;
	if (vtx_ctl_allowed(proc2c, PROC2_XSAVES))
		want2 |= PROC2_XSAVES;
	if (vtx_ctl_allowed(proc2c, PROC2_WAITPKG))
		want2 |= PROC2_WAITPKG;
	if (vtx_ctl_allowed(proc2c, PROC2_PCONFIG))
		want2 |= PROC2_PCONFIG;
	if (vtx_ctl_allowed(proc2c, PROC2_UNRESTRICTED))
		want2 |= PROC2_UNRESTRICTED;
	if (dtexit && vtx_ctl_allowed(proc2c, PROC2_DESC_TABLE))
		want2 |= PROC2_DESC_TABLE;
	d->proc2 = vtx_ctl_adjust(proc2c, want2);
	if (!(d->proc2 & PROC2_EPT)) {
		pr_err("vtxhv: EPT unsupported\n");
		return -EOPNOTSUPP;
	}
	d->exitc = vtx_ctl_adjust(exitc, EXIT_HOST_LONG | EXIT_SAVE_EFER | EXIT_LOAD_EFER |
				  (vtx_ctl_allowed(exitc, EXIT_CONCEAL_PT) ? EXIT_CONCEAL_PT : 0));
	d->entryc = vtx_ctl_adjust(entryc, ENTRY_IA32E | ENTRY_LOAD_EFER |
				   (vtx_ctl_allowed(entryc, ENTRY_CONCEAL_PT) ? ENTRY_CONCEAL_PT : 0));
	if ((d->exitc & (EXIT_HOST_LONG | EXIT_SAVE_EFER | EXIT_LOAD_EFER)) != (EXIT_HOST_LONG | EXIT_SAVE_EFER | EXIT_LOAD_EFER) ||
	    (d->entryc & (ENTRY_IA32E | ENTRY_LOAD_EFER)) != (ENTRY_IA32E | ENTRY_LOAD_EFER)) {
		pr_err("vtxhv: EFER switching controls unsupported\n");
		return -EOPNOTSUPP;
	}
	if (d->exitc & (EXIT_ACK_INTR | EXIT_LOAD_PAT | EXIT_SAVE_PAT) || d->entryc & ENTRY_LOAD_PAT) {
		d->exitc &= ~(EXIT_ACK_INTR | EXIT_LOAD_PAT | EXIT_SAVE_PAT);
		d->entryc &= ~ENTRY_LOAD_PAT;
	}
	return 0;
}

int vtx_probe(struct vtx_drv *d, u32 dtexit)
{
	u32 a, b, c, dx, maxphy;
	u64 fc, basic, ept;
	int rc;

	vtx_cpuid(0, 0, &a, &b, &c, &dx);
	if (b != 0x756e6547 || dx != 0x49656e69 || c != 0x6c65746e) {
		pr_err("vtxhv: not an Intel CPU\n");
		return -ENODEV;
	}
	vtx_cpuid(1, 0, &a, &b, &c, &dx);
	if (!(c & (1u << 5))) {
		pr_err("vtxhv: CPU does not support VMX\n");
		return -ENODEV;
	}
	if (c & (1u << 31))
		pr_info("vtxhv: running under another hypervisor, relying on nested VMX\n");
	fc = vtx_rdmsr(MSR_IA32_FEATURE_CONTROL);
	if (!(fc & FEATCTL_LOCK) || !(fc & FEATCTL_VMX_OUTSIDE_SMX)) {
		pr_err("vtxhv: VMX disabled in IA32_FEATURE_CONTROL (%#llx); enable VT-x in firmware and build the kernel with KVM_INTEL\n", fc);
		return -ENODEV;
	}
	if (vtx_read_cr4() & CR4_VMXE) {
		pr_err("vtxhv: VMX already in use on this CPU (kvm_intel loaded?)\n");
		return -EBUSY;
	}
	if (boot_cpu_has(X86_FEATURE_CALL_DEPTH)) {
		pr_err("vtxhv: retbleed=stuff call-depth tracking is unsupported\n");
		return -EOPNOTSUPP;
	}
	memset(d->caps, 0, sizeof(d->caps));
	d->caps_valid = 0;
	basic = vtx_rdmsr(MSR_IA32_VMX_BASIC);
#define CAP(i, msr) do { d->caps[i] = vtx_rdmsr(msr); d->caps_valid |= 1u << (i); } while (0)
	CAP(VTX_CAP_BASIC, MSR_IA32_VMX_BASIC);
	CAP(VTX_CAP_PINBASED, MSR_IA32_VMX_PINBASED);
	CAP(VTX_CAP_PROCBASED, MSR_IA32_VMX_PROCBASED);
	CAP(VTX_CAP_EXIT, MSR_IA32_VMX_EXIT);
	CAP(VTX_CAP_ENTRY, MSR_IA32_VMX_ENTRY);
	CAP(VTX_CAP_MISC, MSR_IA32_VMX_MISC);
	CAP(VTX_CAP_CR0_FIXED0, MSR_IA32_VMX_CR0_FIXED0);
	CAP(VTX_CAP_CR0_FIXED1, MSR_IA32_VMX_CR0_FIXED1);
	CAP(VTX_CAP_CR4_FIXED0, MSR_IA32_VMX_CR4_FIXED0);
	CAP(VTX_CAP_CR4_FIXED1, MSR_IA32_VMX_CR4_FIXED1);
	CAP(VTX_CAP_VMCS_ENUM, MSR_IA32_VMX_VMCS_ENUM);
	CAP(VTX_CAP_FEATURE_CTL, MSR_IA32_FEATURE_CONTROL);
	CAP(VTX_CAP_MTRRCAP, MSR_IA32_MTRRCAP);
	CAP(VTX_CAP_MTRR_DEF, MSR_IA32_MTRR_DEF_TYPE);
	if (d->caps[VTX_CAP_PROCBASED] & (1ull << 63)) {
		CAP(VTX_CAP_PROCBASED2, MSR_IA32_VMX_PROCBASED2);
		if (d->caps[VTX_CAP_PROCBASED2] & ((u64)(PROC2_EPT | PROC2_VPID) << 32))
			CAP(VTX_CAP_EPT_VPID, MSR_IA32_VMX_EPT_VPID);
		if (d->caps[VTX_CAP_PROCBASED2] & (1ull << (32 + 13)))
			CAP(VTX_CAP_VMFUNC, MSR_IA32_VMX_VMFUNC);
	}
	if (d->caps[VTX_CAP_PROCBASED] & (1ull << (32 + 17)))
		CAP(VTX_CAP_PROCBASED3, MSR_IA32_VMX_PROCBASED3);
	if (d->caps[VTX_CAP_EXIT] & (1ull << 63))
		CAP(VTX_CAP_EXIT2, MSR_IA32_VMX_EXIT2);
	if (basic & (1ull << 55)) {
		CAP(VTX_CAP_TRUE_PIN, MSR_IA32_VMX_TRUE_PIN);
		CAP(VTX_CAP_TRUE_PROC, MSR_IA32_VMX_TRUE_PROC);
		CAP(VTX_CAP_TRUE_EXIT, MSR_IA32_VMX_TRUE_EXIT);
		CAP(VTX_CAP_TRUE_ENTRY, MSR_IA32_VMX_TRUE_ENTRY);
	}
#undef CAP
	if (((basic >> 32) & 0x1fff) > PAGE_SIZE || (basic & (1ull << 48))) {
		pr_err("vtxhv: unsupported VMX region layout (basic=%#llx)\n", basic);
		return -EOPNOTSUPP;
	}
	d->revision = (u32)(basic & 0x7fffffff);
	rc = vtx_compute_controls(d, dtexit);
	if (rc)
		return rc;
	ept = d->caps[VTX_CAP_EPT_VPID];
	if (!(ept & EPTCAP_PWL4) || !(ept & (EPTCAP_WB | EPTCAP_UC)) || !(ept & EPTCAP_INVEPT) ||
	    !(ept & (EPTCAP_INVEPT_SINGLE | EPTCAP_INVEPT_ALL))) {
		pr_err("vtxhv: EPT capabilities insufficient (%#llx)\n", ept);
		return -EOPNOTSUPP;
	}
	if ((d->proc2 & PROC2_VPID) && (!(ept & EPTCAP_INVVPID) || !(ept & (EPTCAP_INVVPID_SINGLE | EPTCAP_INVVPID_ALL))))
		d->proc2 &= ~PROC2_VPID;
	vtx_cpuid(0x80000000, 0, &a, &b, &c, &dx);
	maxphy = 36;
	if (a >= 0x80000008) {
		vtx_cpuid(0x80000008, 0, &a, &b, &c, &dx);
		maxphy = a & 0xff;
	}
	if (maxphy > 52 || maxphy < 32)
		maxphy = 36;
	d->gbpages = boot_cpu_has(X86_FEATURE_GBPAGES) ? 1 : 0;
	vtx_load_mtrr(d, maxphy);
	d->mtrr.phys_mask = ((1ull << maxphy) - 1) & ~0xfffull;
	vtx_ram_n = 0;
	vtx_res_max = 0;
	d->ktext_start = d->ktext_end = d->krodata_start = d->krodata_end = 0;
	vtx_res_walk(d, iomem_resource.child, 0);
	if (!vtx_ram_n || vtx_ram_n > VTX_MAX_RAM) {
		pr_err("vtxhv: unsupported physical memory map (%u RAM ranges)\n", vtx_ram_n);
		return -EOPNOTSUPP;
	}
	d->ram_end = vtx_ram_tmp[vtx_ram_n - 1].end;
	d->maxphy = maxphy;
	return 0;
}

static void *vtx_carve(struct vtx_drv *d, u64 bytes, u64 align, u64 *pa)
{
	for (;;) {
		int order, min_order;
		struct page *pg;

		if (d->nchunks) {
			struct vtx_chunk *c = &d->chunk[d->nchunks - 1];
			u64 off = ALIGN(c->used, align);
			u64 cap = PAGE_SIZE << c->order;

			if (off + bytes <= cap) {
				c->used = off + bytes;
				*pa = c->pa + off;
				return (u8 *)c->va + off;
			}
		}
		if (d->nchunks >= VTX_MAX_CHUNKS)
			return NULL;
		min_order = get_order(bytes > align ? bytes : align);
		order = max(min_order, 9);
		if (order > 10)
			return NULL;
		pg = NULL;
		for (; order >= min_order; order--) {
			pg = alloc_pages(GFP_KERNEL | __GFP_ZERO | __GFP_NOWARN, order);
			if (pg)
				break;
		}
		if (!pg)
			return NULL;
		d->chunk[d->nchunks].page = pg;
		d->chunk[d->nchunks].order = order;
		d->chunk[d->nchunks].va = page_address(pg);
		d->chunk[d->nchunks].pa = page_to_phys(pg);
		d->chunk[d->nchunks].used = 0;
		d->arena_bytes += PAGE_SIZE << order;
		d->nchunks++;
	}
}

static void *vtx_carve_page(struct vtx_drv *d, u64 *pa)
{
	return vtx_carve(d, PAGE_SIZE, PAGE_SIZE, pa);
}

static u64 *vtx_hpt_entry(struct vtx_drv *d, u64 va, int lvl, int la57)
{
	u64 *table = d->host_root;
	int l;

	for (l = la57 ? 5 : 4; l > lvl; l--) {
		u64 *e = &table[(va >> (12 + 9 * (l - 1))) & 511];

		if (!(*e & PTE_P)) {
			u64 pa;
			void *p = vtx_carve_page(d, &pa);

			if (!p)
				return NULL;
			d->host_pt_pages++;
			*e = pa | PTE_P | PTE_W;
		} else if (*e & PTE_PS) {
			return NULL;
		}
		table = (u64 *)__va(*e & PTE_ADDR_MASK);
	}
	return &table[(va >> (12 + 9 * (lvl - 1))) & 511];
}

static int vtx_hpt_map(struct vtx_drv *d, u64 va, u64 pa, u64 size, u64 flags, int la57)
{
	while (size) {
		int lvl = 1;
		u64 step = PAGE_SIZE;
		u64 *e;

		if (d->gbpages && !(va & (VTX_1G - 1)) && !(pa & (VTX_1G - 1)) && size >= VTX_1G) {
			lvl = 3;
			step = VTX_1G;
		} else if (!(va & (VTX_2M - 1)) && !(pa & (VTX_2M - 1)) && size >= VTX_2M) {
			lvl = 2;
			step = VTX_2M;
		}
		e = vtx_hpt_entry(d, va, lvl, la57);
		if (!e)
			return -ENOMEM;
		*e = pa | flags | PTE_P | (lvl > 1 ? PTE_PS : 0);
		va += step;
		pa += step;
		size -= step;
	}
	return 0;
}

static int vtx_hpt_map_virt(struct vtx_drv *d, u64 va, u64 size, u64 flags, int la57)
{
	u64 end = PAGE_ALIGN(va + size);

	for (va &= PAGE_MASK; va < end; va += PAGE_SIZE) {
		u64 pa = slow_virt_to_phys((void *)va);
		u64 *e = vtx_hpt_entry(d, va, 1, la57);

		if (!e)
			return -ENOMEM;
		*e = (pa & PTE_ADDR_MASK) | flags | PTE_P;
	}
	return 0;
}

extern struct module * const vtx_root_module;

static void vtx_root_layout(u64 *text, u64 *text_size, u64 *ro, u64 *ro_size)
{
	struct module *m = vtx_root_module;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	*text = (u64)m->mem[MOD_TEXT].base;
	*text_size = m->mem[MOD_TEXT].size;
	*ro = (u64)m->mem[MOD_RODATA].base;
	*ro_size = m->mem[MOD_RODATA].size;
#else
	*text = (u64)m->core_layout.base;
	*text_size = m->core_layout.text_size;
	*ro = *text + m->core_layout.text_size;
	*ro_size = m->core_layout.ro_size - m->core_layout.text_size;
#endif
	*text_size = PAGE_ALIGN(*text_size);
	*ro_size = PAGE_ALIGN(*ro_size);
}

static u64 vtx_current_task_offset(void)
{
	u64 gsb, addr;

	preempt_disable();
	gsb = vtx_rdmsr(MSR_GS_BASE);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
	addr = (u64)this_cpu_ptr(&pcpu_hot.current_task);
#else
	addr = (u64)this_cpu_ptr(&current_task);
#endif
	preempt_enable();
	return addr - gsb;
}

static void vtx_gdt_set(u64 *gdt, int idx, u64 base, u32 limit, u32 type, int s, int l, int db, int g)
{
	u64 lo = (limit & 0xffff) | ((base & 0xffffff) << 16) | ((u64)type << 40) | ((u64)s << 44) |
		 (1ull << 47) | ((u64)((limit >> 16) & 0xf) << 48) | ((u64)l << 53) | ((u64)db << 54) |
		 ((u64)g << 55) | (((base >> 24) & 0xff) << 56);

	gdt[idx] = lo;
	if (!s)
		gdt[idx + 1] = base >> 32;
}

static void vtx_idt_set(u64 *idt, int vec, u64 handler)
{
	idt[vec * 2] = (handler & 0xffff) | ((u64)0x10 << 16) | ((u64)0x8e << 40) | (((handler >> 16) & 0xffff) << 48);
	idt[vec * 2 + 1] = handler >> 32;
}

static void vtx_msr_intercept_write(u8 *bm, u32 msr)
{
	if (msr <= 0x1fff)
		bm[0x800 + msr / 8] |= 1 << (msr % 8);
	else if (msr >= 0xc0000000 && msr <= 0xc0001fff)
		bm[0xc00 + (msr - 0xc0000000) / 8] |= 1 << ((msr - 0xc0000000) % 8);
}

int vtx_alloc_all(struct vtx_drv *d, u32 pool_pages, u32 ring_events)
{
	struct vtx_global *g;
	u64 pa, ept;
	u32 i, ncpu = nr_cpu_ids;
	int cpu, rc, la57 = (vtx_read_cr4() & CR4_LA57) != 0;
	u64 nx = (vtx_rdmsr(MSR_EFER) & VEFER_NXE) ? PTE_NX : 0;
	u8 *bm;
	u64 *idt;
	u64 tbase = 0, tsize = 0, rbase = 0, rsize = 0, va;
	int maxphy = d->maxphy;

	if (ncpu > VTX_MAX_CPUS)
		return -E2BIG;
	if (!ring_events || (ring_events & (ring_events - 1)))
		ring_events = 1024;
	if (!pool_pages)
		pool_pages = 256 + 96 * ncpu;
	d->nchunks = 0;
	d->arena_bytes = 0;
	d->host_pt_pages = 0;
	g = vtx_carve(d, sizeof(*g), PAGE_SIZE, &pa);
	if (!g)
		return -ENOMEM;
	d->g = g;
	g->magic = VTX_MAGIC;
	g->ncpu = ncpu;
	g->maxphy = maxphy;
	g->dmap = PAGE_OFFSET;
	g->kimg_va = __START_KERNEL_map;
	g->kimg_pa = phys_base;
	g->kimg_end = __START_KERNEL_map + KERNEL_IMAGE_SIZE;
	g->la57 = la57;
	g->pti = boot_cpu_has(X86_FEATURE_PTI) ? 1 : 0;
	g->va57 = boot_cpu_data.extended_cpuid_level >= 0x80000008 && ((cpuid_eax(0x80000008) >> 8) & 0xff) >= 57;
	g->dtexit = (d->proc2 & PROC2_DESC_TABLE) ? 1 : 0;
	g->ept_caps = d->caps[VTX_CAP_EPT_VPID];
	g->cr0_fixed0 = d->caps[VTX_CAP_CR0_FIXED0];
	g->cr0_fixed1 = d->caps[VTX_CAP_CR0_FIXED1];
	g->cr4_fixed0 = d->caps[VTX_CAP_CR4_FIXED0];
	g->cr4_fixed1 = d->caps[VTX_CAP_CR4_FIXED1];
	g->mtrr = d->mtrr;
	g->ser_port = vtx_param_serial & 0xffff;
	g->ser_events = vtx_param_serial_events ? 1 : 0;
	g->policy = vtx_param_pin & VTX_PIN_ALL;
	if (!g->dtexit)
		g->policy &= ~(VTX_PIN_IDTR | VTX_PIN_GDTR | VTX_PIN_TR);
	g->intro = vtx_param_introspect ? 1 : 0;
	g->off_cur_task = vtx_current_task_offset();
	g->off_pid = offsetof(struct task_struct, pid);
	g->off_tgid = offsetof(struct task_struct, tgid);
	g->off_comm = offsetof(struct task_struct, comm);
	g->fix[0].ip = (u64)vtx_fault_rdmsr;
	g->fix[0].to = (u64)vtx_fixup_rdmsr;
	g->fix[1].ip = (u64)vtx_fault_wrmsr;
	g->fix[1].to = (u64)vtx_fixup_wrmsr;
	g->fix[2].ip = (u64)vtx_fault_xsetbv;
	g->fix[2].to = (u64)vtx_fixup_xsetbv;
	g->map_limit = ALIGN(max_t(u64, d->ram_end, 1ull << 32), VTX_1G);
	if (g->map_limit > (1ull << maxphy))
		g->map_limit = 1ull << maxphy;
	g->pm.dmap = g->dmap;
	g->pm.nr_ram = vtx_ram_n;
	for (i = 0; i < vtx_ram_n; i++)
		g->pm.ram[i] = vtx_ram_tmp[i];
	g->pm.tables = &g->tables;
	g->pool.total = pool_pages;
	g->pool.used = 0;
	g->pool.pa = vtx_carve(d, (u64)pool_pages * 8, 8, &pa);
	if (!g->pool.pa)
		return -ENOMEM;
	for (i = 0; i < pool_pages; i++)
		if (!vtx_carve_page(d, &g->pool.pa[i]))
			return -ENOMEM;
	if (!vtx_carve_page(d, &g->tables.sink_pa))
		return -ENOMEM;
	bm = vtx_carve_page(d, &g->msr_bitmap_pa);
	if (!bm)
		return -ENOMEM;
	vtx_msr_intercept_write(bm, MSR_EFER);
	vtx_msr_intercept_write(bm, MSR_STAR);
	vtx_msr_intercept_write(bm, MSR_LSTAR);
	vtx_msr_intercept_write(bm, MSR_CSTAR);
	vtx_msr_intercept_write(bm, MSR_SFMASK);
	vtx_msr_intercept_write(bm, MSR_IA32_SYSENTER_CS);
	vtx_msr_intercept_write(bm, MSR_IA32_SYSENTER_ESP);
	vtx_msr_intercept_write(bm, MSR_IA32_SYSENTER_EIP);
	idt = vtx_carve_page(d, &pa);
	if (!idt)
		return -ENOMEM;
	g->idt_va = (u64)idt;
	for (i = 0; i < 32; i++)
		vtx_idt_set(idt, i, i == VEC_NMI ? (u64)vtx_nmi_stub : (u64)vtx_idt_stubs + 32 * i);
	for_each_possible_cpu(cpu) {
		struct vtx_vcpu *v;
		u64 *gdt;
		void *stk;
		u64 spa;

		v = vtx_carve(d, sizeof(*v), PAGE_SIZE, &pa);
		if (!v)
			return -ENOMEM;
		v->self = v;
		v->g = g;
		v->cpu = cpu;
		v->vpid = (d->proc2 & PROC2_VPID) ? cpu + 1 : 0;
		v->pin = d->pin;
		v->proc = d->proc;
		v->proc2 = d->proc2;
		v->exitc = d->exitc;
		v->entryc = d->entryc;
		v->vmxon_va = vtx_carve_page(d, &v->vmxon_pa);
		v->vmcs_va = vtx_carve_page(d, &v->vmcs_pa);
		v->scratch_va = vtx_carve(d, VTX_SCRATCH_N * PAGE_SIZE, PAGE_SIZE, &v->scratch_pa);
		gdt = vtx_carve_page(d, &pa);
		v->gdt_va = (u64)gdt;
		v->tss_va = (u64)vtx_carve_page(d, &pa);
		stk = vtx_carve(d, VTX_STACK_SIZE, VTX_STACK_SIZE, &spa);
		v->ring = vtx_carve(d, vtx_ring_bytes(ring_events), 64, &pa);
		if (!v->vmxon_va || !v->vmcs_va || !v->scratch_va || !gdt || !v->tss_va || !stk || !v->ring)
			return -ENOMEM;
		vtx_ring_init(v->ring, ring_events);
		*(u32 *)v->vmxon_va = d->revision;
		*(u32 *)v->vmcs_va = d->revision;
		v->stack_base = (u64)stk;
		*(u64 *)(v->stack_base + VTX_STACK_SIZE - 8) = (u64)v;
		vtx_gdt_set(gdt, 1, 0, 0xfffff, 0x0b, 1, 0, 1, 1);
		vtx_gdt_set(gdt, 2, 0, 0xfffff, 0x0b, 1, 1, 0, 1);
		vtx_gdt_set(gdt, 3, 0, 0xfffff, 0x03, 1, 0, 1, 1);
		vtx_gdt_set(gdt, 8, v->tss_va, 0x67, 0x0b, 0, 0, 0, 0);
		g->vcpu[cpu] = v;
	}
	d->host_root = vtx_carve_page(d, &d->host_root_pa);
	if (!d->host_root)
		return -ENOMEM;
	d->host_pt_pages = 1;
	for (i = 0; i < vtx_ram_n; i++) {
		rc = vtx_hpt_map(d, g->dmap + vtx_ram_tmp[i].start, vtx_ram_tmp[i].start,
				 vtx_ram_tmp[i].end - vtx_ram_tmp[i].start, PTE_W | nx, la57);
		if (rc)
			return rc;
	}
	vtx_root_layout(&tbase, &tsize, &rbase, &rsize);
	if (!tbase || !tsize || (tbase & ~PAGE_MASK) || (rbase & ~PAGE_MASK))
		return -EINVAL;
	rc = vtx_hpt_map_virt(d, tbase, tsize, 0, la57);
	if (rc)
		return rc;
	if (rsize) {
		rc = vtx_hpt_map_virt(d, rbase, rsize, nx, la57);
		if (rc)
			return rc;
	}
	g->host_cr3 = d->host_root_pa;
	for (i = 0; i < d->nchunks && i < VTX_MAX_OWNED; i++) {
		g->tables.owned[i].start = d->chunk[i].pa;
		g->tables.owned[i].end = d->chunk[i].pa + (PAGE_SIZE << d->chunk[i].order);
	}
	if (d->nchunks > VTX_MAX_OWNED)
		return -E2BIG;
	g->tables.nr_owned = d->nchunks;
	g->tables.exec_only = (g->ept_caps & EPTCAP_EXEC_ONLY) ? 1 : 0;
	for (va = tbase; va < tbase + tsize; va += PAGE_SIZE) {
		if (vtx_self_insert(&g->tables, slow_virt_to_phys((void *)va), 1))
			return -E2BIG;
		if (!g->host_text_pa0)
			g->host_text_pa0 = slow_virt_to_phys((void *)va);
		g->host_text_pages++;
	}
	for (va = rbase; va < rbase + rsize; va += PAGE_SIZE) {
		if (vtx_self_insert(&g->tables, slow_virt_to_phys((void *)va), 0))
			return -E2BIG;
		g->ro_pages++;
	}
	ept = g->ept_caps;
	for_each_possible_cpu(cpu) {
		struct vtx_vcpu *v = g->vcpu[cpu];
		struct vtx_ept_build b = {
			.dmap = g->dmap,
			.pool = &g->pool,
			.mtrr = &g->mtrr,
			.tables = &g->tables,
			.limit = g->map_limit,
			.allow_1g = (ept & EPTCAP_1G) ? 1 : 0,
			.allow_2m = (ept & EPTCAP_2M) ? 1 : 0,
		};

		rc = vtx_ept_build(&b);
		if (rc) {
			pr_err("vtxhv: EPT pool exhausted building view for cpu %d (pool=%u used=%u); raise pool_pages\n",
			       cpu, g->pool.total, g->pool.used);
			return -ENOMEM;
		}
		v->ept_root = b.root_pa;
		v->eptp = vtx_eptp(b.root_pa, (ept & EPTCAP_WB) != 0);
		if (cpu == cpumask_first(cpu_possible_mask))
			pr_info("vtxhv: EPT view: %llu x 1G, %llu x 2M, %llu x 4K leaves, limit %#llx\n",
				b.leaves[3], b.leaves[2], b.leaves[1], g->map_limit);
	}
	d->ept_pages = g->pool.used;
	g->features = 0;
	if (ept & EPTCAP_1G)
		g->features |= VTX_FEAT_EPT_1G;
	if (ept & EPTCAP_2M)
		g->features |= VTX_FEAT_EPT_2M;
	if (d->proc2 & PROC2_VPID)
		g->features |= VTX_FEAT_VPID;
	if (d->vnmi)
		g->features |= VTX_FEAT_VNMI;
	if (d->proc2 & PROC2_DESC_TABLE)
		g->features |= VTX_FEAT_DTEXIT;
	if (d->proc2 & PROC2_UNRESTRICTED)
		g->features |= VTX_FEAT_UNRESTRICTED;
	if (ept & EPTCAP_EXEC_ONLY)
		g->features |= VTX_FEAT_EXEC_ONLY;
	g->features |= VTX_FEAT_MTF;
	if (d->proc2 & PROC2_INVPCID)
		g->features |= VTX_FEAT_INVPCID;
	if (d->proc2 & PROC2_XSAVES)
		g->features |= VTX_FEAT_XSAVES;
	if (d->proc2 & PROC2_RDTSCP)
		g->features |= VTX_FEAT_RDTSCP;
	if (d->proc2 & PROC2_WAITPKG)
		g->features |= VTX_FEAT_WAITPKG;
	if (la57)
		g->features |= VTX_FEAT_LA57;
	if ((d->caps[VTX_CAP_BASIC] >> 55) & 1)
		g->features |= VTX_FEAT_TRUE_CTLS;
	if (g->pti)
		g->features |= VTX_FEAT_PTI;
	if (ept & EPTCAP_WB)
		g->features |= VTX_FEAT_EPT_WB;
	if (d->proc & (PROC_CR3_LOAD_EXITING | PROC_CR3_STORE_EXITING))
		g->features |= VTX_FEAT_CR3_EXITS;
	if (g->intro)
		g->features |= VTX_FEAT_INTROSPECT;
	if (g->ser_port)
		g->features |= VTX_FEAT_SERIAL;
	d->features = g->features;
	d->pool_total = g->pool.total;
	g->arena_pa0 = d->chunk[0].pa;
	g->arena_bytes = d->arena_bytes;
	g->nchunks = d->nchunks;
	g->load_tsc = vtx_rdtsc();
	return 0;
}

void vtx_free_all(struct vtx_drv *d)
{
	u32 i;

	for (i = 0; i < d->nchunks; i++)
		__free_pages(d->chunk[i].page, d->chunk[i].order);
	d->nchunks = 0;
	d->g = NULL;
}

static u32 vtx_seg_ar(u16 sel)
{
	int ok;
	u32 ar;

	if (!(sel & ~3))
		return 0x10000;
	ar = vtx_lar(sel, &ok);
	if (!ok)
		return 0x10000;
	return (ar >> 8) & 0xf0ff;
}

static u64 vtx_sys_desc_base(u64 gdt_base, u16 sel)
{
	u64 *d = (u64 *)(gdt_base + (sel & ~7));
	u64 lo = d[0], hi = d[1];

	return ((lo >> 16) & 0xffffff) | (((lo >> 56) & 0xff) << 24) | ((hi & 0xffffffffull) << 32);
}

#define VW(f, v)	do { if (vtx_vmwrite_chk((f), (u64)(v))) { bad = (f); goto fail; } } while (0)

static int vtx_vmcs_setup(struct vtx_drv *d, struct vtx_vcpu *v)
{
	struct vtx_global *g = d->g;
	struct vtx_dtr gdtr, idtr;
	u64 cr0 = vtx_read_cr0(), cr3 = vtx_read_cr3(), cr4 = vtx_read_cr4();
	u64 efer = vtx_rdmsr(MSR_EFER);
	u16 tr = vtx_str(), ldtr = vtx_sldt();
	u16 sel[6];
	static const u32 self_f[6] = { VMCS_GUEST_ES_SEL, VMCS_GUEST_CS_SEL, VMCS_GUEST_SS_SEL,
				     VMCS_GUEST_DS_SEL, VMCS_GUEST_FS_SEL, VMCS_GUEST_GS_SEL };
	static const u32 limf[6] = { VMCS_GUEST_ES_LIMIT, VMCS_GUEST_CS_LIMIT, VMCS_GUEST_SS_LIMIT,
				     VMCS_GUEST_DS_LIMIT, VMCS_GUEST_FS_LIMIT, VMCS_GUEST_GS_LIMIT };
	static const u32 arf[6] = { VMCS_GUEST_ES_AR, VMCS_GUEST_CS_AR, VMCS_GUEST_SS_AR,
				    VMCS_GUEST_DS_AR, VMCS_GUEST_FS_AR, VMCS_GUEST_GS_AR };
	static const u32 basef[6] = { VMCS_GUEST_ES_BASE, VMCS_GUEST_CS_BASE, VMCS_GUEST_SS_BASE,
				      VMCS_GUEST_DS_BASE, VMCS_GUEST_FS_BASE, VMCS_GUEST_GS_BASE };
	u64 bad = 0;
	int i;

	vtx_sgdt(&gdtr);
	vtx_sidt(&idtr);
	sel[0] = vtx_read_es();
	sel[1] = vtx_read_cs();
	sel[2] = vtx_read_ss();
	sel[3] = vtx_read_ds();
	sel[4] = vtx_read_fs();
	sel[5] = vtx_read_gs();

	VW(VMCS_PIN_CTLS, v->pin);
	VW(VMCS_PROC_CTLS, v->proc);
	VW(VMCS_PROC_CTLS2, v->proc2);
	VW(VMCS_EXIT_CTLS, v->exitc);
	VW(VMCS_ENTRY_CTLS, v->entryc);
	VW(VMCS_EXCEPTION_BITMAP, 0);
	VW(VMCS_PF_ERR_MASK, 0);
	VW(VMCS_PF_ERR_MATCH, 0);
	VW(VMCS_CR3_TARGET_COUNT, 0);
	VW(VMCS_EXIT_MSR_STORE_COUNT, 0);
	VW(VMCS_EXIT_MSR_LOAD_COUNT, 0);
	VW(VMCS_ENTRY_MSR_LOAD_COUNT, 0);
	VW(VMCS_ENTRY_INTR_INFO, 0);
	VW(VMCS_ENTRY_EXC_ERRCODE, 0);
	VW(VMCS_ENTRY_INSTR_LEN, 0);
	VW(VMCS_TPR_THRESHOLD, 0);
	VW(VMCS_MSR_BITMAP, g->msr_bitmap_pa);
	VW(VMCS_TSC_OFFSET, 0);
	VW(VMCS_EPT_POINTER, v->eptp);
	if (v->proc2 & PROC2_VPID)
		VW(VMCS_VPID, v->vpid);
	if (v->proc2 & PROC2_XSAVES)
		VW(VMCS_XSS_EXIT_BITMAP, 0);
	VW(VMCS_LINK_POINTER, ~0ull);

	VW(VMCS_HOST_CR0, cr0);
	VW(VMCS_HOST_CR3, g->host_cr3);
	VW(VMCS_HOST_CR4, cr4);
	VW(VMCS_HOST_CS_SEL, 0x10);
	VW(VMCS_HOST_SS_SEL, 0x18);
	VW(VMCS_HOST_DS_SEL, 0);
	VW(VMCS_HOST_ES_SEL, 0);
	VW(VMCS_HOST_FS_SEL, 0);
	VW(VMCS_HOST_GS_SEL, 0);
	VW(VMCS_HOST_TR_SEL, 0x40);
	VW(VMCS_HOST_FS_BASE, 0);
	VW(VMCS_HOST_GS_BASE, (u64)v);
	VW(VMCS_HOST_TR_BASE, v->tss_va);
	VW(VMCS_HOST_GDTR_BASE, v->gdt_va);
	VW(VMCS_HOST_IDTR_BASE, g->idt_va);
	VW(VMCS_HOST_SYSENTER_CS, 0);
	VW(VMCS_HOST_SYSENTER_ESP, 0);
	VW(VMCS_HOST_SYSENTER_EIP, 0);
	VW(VMCS_HOST_EFER, efer);
	VW(VMCS_HOST_RSP, v->stack_base + VTX_HOST_RSP_OFF);
	VW(VMCS_HOST_RIP, (u64)vtx_exit_stub);

	VW(VMCS_GUEST_CR0, cr0);
	VW(VMCS_GUEST_CR3, cr3);
	VW(VMCS_GUEST_CR4, cr4);
	VW(VMCS_CR0_MASK, 0);
	VW(VMCS_CR0_SHADOW, cr0);
	VW(VMCS_CR4_MASK, CR4_VMXE);
	VW(VMCS_CR4_SHADOW, cr4 & ~CR4_VMXE);
	v->cr0_mask = 0;
	v->cr4_mask = CR4_VMXE;
	VW(VMCS_GUEST_DR7, vtx_read_dr7());
	VW(VMCS_GUEST_DEBUGCTL, vtx_rdmsr(MSR_IA32_DEBUGCTL));
	VW(VMCS_GUEST_EFER, efer);
	VW(VMCS_GUEST_SYSENTER_CS, vtx_rdmsr(MSR_IA32_SYSENTER_CS));
	VW(VMCS_GUEST_SYSENTER_ESP, vtx_rdmsr(MSR_IA32_SYSENTER_ESP));
	VW(VMCS_GUEST_SYSENTER_EIP, vtx_rdmsr(MSR_IA32_SYSENTER_EIP));
	for (i = 0; i < 6; i++) {
		u32 ar = vtx_seg_ar(sel[i]);

		VW(self_f[i], sel[i]);
		VW(arf[i], ar);
		VW(limf[i], (ar & 0x10000) ? 0 : vtx_lsl(sel[i]));
		if (i == 4)
			VW(basef[i], vtx_rdmsr(MSR_FS_BASE));
		else if (i == 5)
			VW(basef[i], vtx_rdmsr(MSR_GS_BASE));
		else
			VW(basef[i], 0);
	}
	VW(VMCS_GUEST_LDTR_SEL, ldtr);
	if (ldtr & ~3) {
		VW(VMCS_GUEST_LDTR_BASE, vtx_sys_desc_base(gdtr.base, ldtr));
		VW(VMCS_GUEST_LDTR_LIMIT, vtx_lsl(ldtr));
		VW(VMCS_GUEST_LDTR_AR, vtx_seg_ar(ldtr));
	} else {
		VW(VMCS_GUEST_LDTR_BASE, 0);
		VW(VMCS_GUEST_LDTR_LIMIT, 0);
		VW(VMCS_GUEST_LDTR_AR, 0x10000);
	}
	VW(VMCS_GUEST_TR_SEL, tr);
	VW(VMCS_GUEST_TR_BASE, vtx_sys_desc_base(gdtr.base, tr));
	VW(VMCS_GUEST_TR_LIMIT, vtx_lsl(tr));
	VW(VMCS_GUEST_TR_AR, vtx_seg_ar(tr));
	VW(VMCS_GUEST_GDTR_BASE, gdtr.base);
	VW(VMCS_GUEST_GDTR_LIMIT, gdtr.limit);
	VW(VMCS_GUEST_IDTR_BASE, idtr.base);
	VW(VMCS_GUEST_IDTR_LIMIT, idtr.limit);
	VW(VMCS_GUEST_INTERRUPTIBILITY, 0);
	VW(VMCS_GUEST_ACTIVITY, 0);
	VW(VMCS_GUEST_PENDING_DBG, 0);

	v->b_gdtr_base = gdtr.base;
	v->b_gdtr_limit = gdtr.limit;
	v->b_gdt_rw = (u64)get_current_gdt_rw();
	v->b_idtr_base = idtr.base;
	v->b_idtr_limit = idtr.limit;
	v->b_tr = tr;
	v->b_star = vtx_rdmsr(MSR_STAR);
	v->b_lstar = vtx_rdmsr(MSR_LSTAR);
	v->b_cstar = vtx_rdmsr(MSR_CSTAR);
	v->b_sfmask = vtx_rdmsr(MSR_SFMASK);
	v->b_sysenter_cs = vtx_rdmsr(MSR_IA32_SYSENTER_CS);
	v->b_sysenter_esp = vtx_rdmsr(MSR_IA32_SYSENTER_ESP);
	v->b_sysenter_eip = vtx_rdmsr(MSR_IA32_SYSENTER_EIP);
	v->b_efer = efer;
	v->policy_gen = READ_ONCE(g->policy_gen);
	v->ept_gen = READ_ONCE(g->ept_gen);
	vtx_apply_cr_policy(v);
	return 0;
fail:
	pr_err("vtxhv: cpu %u: vmwrite failed field %#llx error %llu\n", v->cpu, bad, vtx_vmread(VMCS_INSTR_ERROR));
	return -EIO;
}

const char *vtx_launch_err(u64 rc)
{
	switch (rc >> 32) {
	case 1:
		return "VMfailInvalid";
	case 2:
		return "VMfailValid";
	case 3:
		return "VM-entry failure (invalid guest state)";
	case 4:
		return "vmwrite of launch state failed";
	default:
		return "unknown";
	}
}

int vtx_cpu_launch(struct vtx_drv *d, unsigned int cpu)
{
	struct vtx_global *g = d->g;
	struct vtx_vcpu *v = g->vcpu[cpu];
	unsigned long flags;
	u64 cr0, cr4, fc, rc;
	int err = 0;

	if (!v)
		return -EINVAL;
	local_irq_save(flags);
	cr0 = vtx_read_cr0();
	cr4 = vtx_read_cr4();
	fc = vtx_rdmsr(MSR_IA32_FEATURE_CONTROL);
	if (cr4 & CR4_VMXE) {
		err = -EBUSY;
		goto out;
	}
	if (!(fc & FEATCTL_LOCK) || !(fc & FEATCTL_VMX_OUTSIDE_SMX)) {
		err = -ENODEV;
		goto out;
	}
	if (!vtx_cr_fixed_ok(cr0, g->cr0_fixed0, g->cr0_fixed1) ||
	    !vtx_cr_fixed_ok(cr4 | CR4_VMXE, g->cr4_fixed0, g->cr4_fixed1)) {
		err = -EINVAL;
		goto out;
	}
	vtx_write_cr4(cr4 | CR4_VMXE);
	if (vtx_vmxon(v->vmxon_pa)) {
		vtx_write_cr4(cr4);
		err = -EIO;
		goto out;
	}
	if (g->ept_caps & EPTCAP_INVEPT_ALL)
		vtx_invept(2, 0);
	if ((v->proc2 & PROC2_VPID) && (g->ept_caps & EPTCAP_INVVPID_ALL))
		vtx_invvpid(2, 0, 0);
	if (vtx_vmclear(v->vmcs_pa) || vtx_vmptrld(v->vmcs_pa)) {
		vtx_vmxoff();
		vtx_write_cr4(cr4);
		err = -EIO;
		goto out;
	}
	if (vtx_vmcs_setup(d, v)) {
		vtx_vmclear(v->vmcs_pa);
		vtx_vmxoff();
		vtx_write_cr4(cr4);
		err = -EIO;
		goto out;
	}
	v->nmi_pending = 0;
	v->launched = 0;
	WRITE_ONCE(v->vmx_active, (v->pin & PIN_VIRTUAL_NMIS) ? 1 : 2);
	rc = vtx_asm_launch();
	if (rc) {
		if ((rc >> 32) != 3) {
			WRITE_ONCE(v->vmx_active, 0);
			vtx_vmclear(v->vmcs_pa);
			vtx_vmxoff();
			vtx_write_cr4(cr4);
		}
		local_irq_restore(flags);
		pr_err("vtxhv: cpu %u launch failed: %s (%#llx)\n", cpu, vtx_launch_err(rc), rc);
		return -EIO;
	}
out:
	local_irq_restore(flags);
	if (err)
		pr_err("vtxhv: cpu %u: cannot enter VMX operation (%d)\n", cpu, err);
	return err;
}

u64 vtx_vmcall(u64 fn, u64 *b, u64 *c, u64 *dx, u64 *si, u64 *di)
{
	u64 a = VTX_HC_MAGIC | fn;
	u64 rb = b ? *b : 0, rc = c ? *c : 0, rd = dx ? *dx : 0, rs = si ? *si : 0, rdi = di ? *di : 0;

	asm volatile("vmcall" : "+a"(a), "+b"(rb), "+c"(rc), "+d"(rd), "+S"(rs), "+D"(rdi) : : "memory", "cc");
	if (b)
		*b = rb;
	if (c)
		*c = rc;
	if (dx)
		*dx = rd;
	if (si)
		*si = rs;
	if (di)
		*di = rdi;
	return a;
}

int vtx_cpu_devirt(struct vtx_drv *d, unsigned int cpu)
{
	unsigned long flags;
	u64 rc;

	local_irq_save(flags);
	rc = vtx_vmcall(VTX_HC_DEVIRT, NULL, NULL, NULL, NULL, NULL);
	local_irq_restore(flags);
	if (rc) {
		pr_err("vtxhv: cpu %u refused to devirtualize (%lld)\n", cpu, (s64)rc);
		return -EPERM;
	}
	return 0;
}
