#include "vtx.h"

VTX_HOSTI u32 vtx_cpl(void)
{
	return (u32)((vtx_vmread(VMCS_GUEST_SS_AR) >> 5) & 3);
}

VTX_HOST static void vtx_cpuid_exit(struct vtx_vcpu *v, struct vtx_regs *r)
{
	struct vtx_global *g = v->g;
	u32 leaf = (u32)r->rax, sub = (u32)r->rcx;
	u32 a, b, c, d;

	if (leaf >= 0x40000000 && leaf <= 0x400000ff) {
		const u32 *sig = (const u32 *)VTX_SIGNATURE;

		a = b = c = d = 0;
		if (leaf == 0x40000000) {
			a = 0x40000001;
			b = sig[0];
			c = sig[1];
			d = sig[2];
		} else if (leaf == 0x40000001) {
			a = VTX_VERSION;
			b = g->features;
			c = g->policy | (READ_ONCE(g->locked) ? 0x80000000u : 0);
			d = READ_ONCE(g->virt_count);
		}
	} else {
		vtx_cpuid(leaf, sub, &a, &b, &c, &d);
		if (leaf == 1) {
			c |= 1u << 31;
			c &= ~(1u << 5);
		}
	}
	r->rax = a;
	r->rbx = b;
	r->rcx = c;
	r->rdx = d;
	vtx_skip(v);
}

VTX_HOST static void vtx_cr_event(struct vtx_vcpu *v, u32 type, u64 oldv, u64 newv, u64 info, int denied)
{
	struct vtx_event e;

	vtx_event_begin(v, &e, type);
	e.old_val = oldv;
	e.new_val = newv;
	e.info = info;
	e.flags |= VTX_EVF_OLDVAL | VTX_EVF_NEWVAL | (denied ? VTX_EVF_DENIED : 0);
	vtx_event_commit(v, &e);
}

VTX_HOST static void vtx_emul_cr0(struct vtx_vcpu *v, u64 val)
{
	struct vtx_global *g = v->g;
	u64 old_real = vtx_vmread(VMCS_GUEST_CR0);
	u64 old_shadow = vtx_vmread(VMCS_CR0_SHADOW);
	u64 cr4 = vtx_vmread(VMCS_GUEST_CR4);
	u64 efer = vtx_vmread(VMCS_GUEST_EFER);
	u64 must1 = g->cr0_fixed0, may1 = g->cr0_fixed1;
	u64 real;
	int denied = 0;

	if (v->proc2 & PROC2_UNRESTRICTED)
		must1 &= ~(CR0_PE | CR0_PG);
	if ((val >> 32) != 0 || ((val & CR0_NW) && !(val & CR0_CD)) || ((val & CR0_PG) && !(val & CR0_PE)) ||
	    (!(val & CR0_WP) && (cr4 & CR4_CET)) || ((efer & VEFER_LMA) && !(val & CR0_PG))) {
		if ((old_shadow & CR0_WP) && !(val & CR0_WP))
			vtx_cr_event(v, VTX_EV_CR0, old_shadow, val, 1, 1);
		vtx_inject_gp(v);
		return;
	}
	if ((g->policy & VTX_PIN_CR0_WP) && (old_real & CR0_WP) && !(val & CR0_WP)) {
		denied = 1;
		val |= CR0_WP;
	}
	real = (val | must1) & may1;
	vtx_vmwrite(VMCS_GUEST_CR0, real);
	vtx_vmwrite(VMCS_CR0_SHADOW, val);
	if (denied || ((old_shadow ^ val) & CR0_WP))
		vtx_cr_event(v, VTX_EV_CR0, old_shadow, denied ? (val & ~CR0_WP) : val, 0, denied);
	vtx_skip(v);
}

VTX_HOST static void vtx_emul_cr4(struct vtx_vcpu *v, u64 val)
{
	struct vtx_global *g = v->g;
	u64 old_real = vtx_vmread(VMCS_GUEST_CR4);
	u64 old_shadow = vtx_vmread(VMCS_CR4_SHADOW);
	u64 pinned = 0, attempted = val, real;
	int denied = 0;

	{
		u64 cr0 = vtx_vmread(VMCS_GUEST_CR0);
		u64 efer = vtx_vmread(VMCS_GUEST_EFER);
		u64 cr3 = vtx_vmread(VMCS_GUEST_CR3);
		int lma = (efer & VEFER_LMA) != 0;

		if ((val & ~(g->cr4_fixed1 | CR4_VMXE)) || (val >> 32) ||
		    (lma && (!(val & CR4_PAE) || ((val ^ old_real) & CR4_LA57))) ||
		    ((val & CR4_PCIDE) && !(old_real & CR4_PCIDE) && ((cr3 & 0xfff) || !lma)) ||
		    ((val & CR4_CET) && !(cr0 & CR0_WP))) {
			if ((old_shadow & (CR4_SMEP | CR4_SMAP | CR4_UMIP)) & ~val)
				vtx_cr_event(v, VTX_EV_CR4, old_shadow, val, 5, 1);
			vtx_inject_gp(v);
			return;
		}
	}
	if (g->policy & VTX_PIN_CR4_SMEP)
		pinned |= CR4_SMEP;
	if (g->policy & VTX_PIN_CR4_SMAP)
		pinned |= CR4_SMAP;
	if (g->policy & VTX_PIN_CR4_UMIP)
		pinned |= CR4_UMIP;
	if ((old_real & pinned) & ~val) {
		denied = 1;
		val |= old_real & pinned;
	}
	real = (val | g->cr4_fixed0) & g->cr4_fixed1;
	real |= CR4_VMXE;
	vtx_vmwrite(VMCS_GUEST_CR4, real);
	vtx_vmwrite(VMCS_CR4_SHADOW, val);
	if ((old_real ^ real) & (CR4_PGE | CR4_PAE | CR4_PSE | CR4_PCIDE | CR4_SMEP | CR4_SMAP | CR4_LA57 | CR4_PKE)) {
		if (g->ept_caps & EPTCAP_INVVPID_SINGLE)
			vtx_invvpid(1, (u16)v->vpid, 0);
		else
			vtx_invvpid(2, 0, 0);
	}
	if (denied || ((old_shadow ^ val) & (CR4_SMEP | CR4_SMAP | CR4_UMIP)))
		vtx_cr_event(v, VTX_EV_CR4, old_shadow, attempted, 4, denied);
	vtx_skip(v);
}

VTX_HOST static void vtx_cr_exit(struct vtx_vcpu *v, struct vtx_regs *r)
{
	struct vtx_global *g = v->g;
	u64 q = vtx_vmread(VMCS_EXIT_QUAL);
	u32 crn = q & 15, type = (q >> 4) & 3, reg = (q >> 8) & 15;

	if (type == 0) {
		u64 val = vtx_gpr_get(v, r, reg);

		if (crn == 0) {
			vtx_emul_cr0(v, val);
		} else if (crn == 4) {
			vtx_emul_cr4(v, val);
		} else if (crn == 3) {
			u64 cr4 = vtx_vmread(VMCS_GUEST_CR4);
			int noflush = (cr4 & CR4_PCIDE) && (val >> 63);

			val &= ~(1ull << 63);
			if (val >> g->maxphy) {
				vtx_inject_gp(v);
				return;
			}
			vtx_vmwrite(VMCS_GUEST_CR3, val);
			if (!noflush) {
				if (g->ept_caps & EPTCAP_INVVPID_SINGLE_KEEPG)
					vtx_invvpid(3, (u16)v->vpid, 0);
				else if (g->ept_caps & EPTCAP_INVVPID_SINGLE)
					vtx_invvpid(1, (u16)v->vpid, 0);
				else
					vtx_invvpid(2, 0, 0);
			}
			vtx_skip(v);
		} else {
			vtx_inject_ud(v);
		}
	} else if (type == 1) {
		if (crn == 3)
			vtx_gpr_set(v, r, reg, vtx_vmread(VMCS_GUEST_CR3));
		else
			vtx_inject_ud(v);
		if (crn == 3)
			vtx_skip(v);
	} else if (type == 2) {
		vtx_emul_cr0(v, vtx_vmread(VMCS_CR0_SHADOW) & ~CR0_TS);
	} else {
		u64 sh = vtx_vmread(VMCS_CR0_SHADOW);
		u64 src = (q >> 16) & 0xffff;
		u64 nv = (sh & ~0xeull) | (src & 0xf) | (sh & CR0_PE);

		vtx_emul_cr0(v, nv);
	}
}

VTX_HOST static int vtx_msr_pinned(struct vtx_vcpu *v, u32 msr, u64 val, u64 *base)
{
	struct vtx_global *g = v->g;

	switch (msr) {
	case MSR_STAR:
		*base = v->b_star;
		return (g->policy & VTX_PIN_MSR_SYSCALL) && val != v->b_star;
	case MSR_LSTAR:
		*base = v->b_lstar;
		return (g->policy & VTX_PIN_MSR_SYSCALL) && val != v->b_lstar;
	case MSR_CSTAR:
		*base = v->b_cstar;
		return (g->policy & VTX_PIN_MSR_SYSCALL) && val != v->b_cstar;
	case MSR_SFMASK:
		*base = v->b_sfmask;
		return (g->policy & VTX_PIN_MSR_SYSCALL) && val != v->b_sfmask;
	case MSR_IA32_SYSENTER_CS:
		*base = v->b_sysenter_cs;
		return (g->policy & VTX_PIN_MSR_SYSENTER) && val != v->b_sysenter_cs;
	case MSR_IA32_SYSENTER_ESP:
		*base = v->b_sysenter_esp;
		return (g->policy & VTX_PIN_MSR_SYSENTER) && val != v->b_sysenter_esp;
	case MSR_IA32_SYSENTER_EIP:
		*base = v->b_sysenter_eip;
		return (g->policy & VTX_PIN_MSR_SYSENTER) && val != v->b_sysenter_eip;
	case MSR_EFER:
		*base = v->b_efer;
		return (g->policy & VTX_PIN_MSR_EFER) &&
		       (((v->b_efer & ~val) & (VEFER_NXE | VEFER_SCE | VEFER_LME)) != 0);
	default:
		*base = 0;
		return 0;
	}
}

VTX_HOST static void vtx_msr_write_exit(struct vtx_vcpu *v, struct vtx_regs *r)
{
	u32 msr = (u32)r->rcx;
	u64 val = ((r->rdx & 0xffffffffull) << 32) | (r->rax & 0xffffffffull);
	u64 base = 0, oldv = 0;
	int denied, monitored = 1;
	struct vtx_event e;

	denied = vtx_msr_pinned(v, msr, val, &base);
	switch (msr) {
	case MSR_IA32_SYSENTER_ESP:
	case MSR_IA32_SYSENTER_EIP:
	case MSR_FS_BASE:
	case MSR_GS_BASE:
		if (!vtx_canonical(val, v->g->va57)) {
			vtx_inject_gp(v);
			return;
		}
		break;
	default:
		break;
	}
	switch (msr) {
	case MSR_IA32_SYSENTER_CS:
		oldv = vtx_vmread(VMCS_GUEST_SYSENTER_CS);
		if (!denied)
			vtx_vmwrite(VMCS_GUEST_SYSENTER_CS, val & 0xffffffffull);
		break;
	case MSR_IA32_SYSENTER_ESP:
		oldv = vtx_vmread(VMCS_GUEST_SYSENTER_ESP);
		if (!denied)
			vtx_vmwrite(VMCS_GUEST_SYSENTER_ESP, val);
		break;
	case MSR_IA32_SYSENTER_EIP:
		oldv = vtx_vmread(VMCS_GUEST_SYSENTER_EIP);
		if (!denied)
			vtx_vmwrite(VMCS_GUEST_SYSENTER_EIP, val);
		break;
	case MSR_EFER:
		oldv = vtx_vmread(VMCS_GUEST_EFER);
		if (((oldv ^ val) & (VEFER_LME | VEFER_LMA)) || (val & ~(VEFER_SCE | VEFER_LME | VEFER_LMA | VEFER_NXE))) {
			vtx_inject_gp(v);
			return;
		}
		if (!denied)
			vtx_vmwrite(VMCS_GUEST_EFER, val);
		break;
	case MSR_FS_BASE:
		monitored = 0;
		vtx_vmwrite(VMCS_GUEST_FS_BASE, val);
		break;
	case MSR_GS_BASE:
		monitored = 0;
		vtx_vmwrite(VMCS_GUEST_GS_BASE, val);
		break;
	case MSR_IA32_DEBUGCTL:
		monitored = 0;
		vtx_vmwrite(VMCS_GUEST_DEBUGCTL, val);
		break;
	case MSR_STAR:
	case MSR_LSTAR:
	case MSR_CSTAR:
	case MSR_SFMASK: {
		int have_old = !vtx_safe_rdmsr(msr, &oldv);

		if (!have_old)
			oldv = 0;
		if (denied && !have_old)
			break;
		if (vtx_safe_wrmsr(msr, val)) {
			vtx_inject_gp(v);
			return;
		}
		if (denied)
			vtx_safe_wrmsr(msr, oldv);
		break;
	}
	default:
		monitored = 0;
		if (vtx_safe_wrmsr(msr, val)) {
			vtx_inject_gp(v);
			return;
		}
		break;
	}
	if (monitored) {
		vtx_event_begin(v, &e, VTX_EV_MSR);
		e.info = msr;
		e.old_val = oldv;
		e.new_val = val;
		e.gla = base;
		e.flags |= VTX_EVF_OLDVAL | VTX_EVF_NEWVAL | (denied ? VTX_EVF_DENIED : 0);
		vtx_event_commit(v, &e);
	}
	vtx_skip(v);
}

VTX_HOST static void vtx_msr_read_exit(struct vtx_vcpu *v, struct vtx_regs *r)
{
	u32 msr = (u32)r->rcx;
	u64 val;

	switch (msr) {
	case MSR_IA32_SYSENTER_CS:
		val = vtx_vmread(VMCS_GUEST_SYSENTER_CS);
		break;
	case MSR_IA32_SYSENTER_ESP:
		val = vtx_vmread(VMCS_GUEST_SYSENTER_ESP);
		break;
	case MSR_IA32_SYSENTER_EIP:
		val = vtx_vmread(VMCS_GUEST_SYSENTER_EIP);
		break;
	case MSR_EFER:
		val = vtx_vmread(VMCS_GUEST_EFER);
		break;
	case MSR_FS_BASE:
		val = vtx_vmread(VMCS_GUEST_FS_BASE);
		break;
	case MSR_GS_BASE:
		val = vtx_vmread(VMCS_GUEST_GS_BASE);
		break;
	case MSR_IA32_DEBUGCTL:
		val = vtx_vmread(VMCS_GUEST_DEBUGCTL);
		break;
	default:
		if (vtx_safe_rdmsr(msr, &val)) {
			vtx_inject_gp(v);
			return;
		}
		break;
	}
	r->rax = (u32)val;
	r->rdx = (u32)(val >> 32);
	vtx_skip(v);
}

VTX_HOST static void vtx_xsetbv_exit(struct vtx_vcpu *v, struct vtx_regs *r)
{
	u64 val = ((r->rdx & 0xffffffffull) << 32) | (r->rax & 0xffffffffull);

	if (vtx_cpl() != 0 || (u32)r->rcx != 0 || vtx_safe_xsetbv((u32)r->rcx, val)) {
		vtx_inject_gp(v);
		return;
	}
	vtx_skip(v);
}

VTX_HOST static void vtx_dtr_event(struct vtx_vcpu *v, u32 op, u64 oldv, u64 newv, u64 lim, int denied)
{
	struct vtx_event e;

	vtx_event_begin(v, &e, VTX_EV_DTR);
	e.info = op | (lim << 16);
	e.old_val = oldv;
	e.new_val = newv;
	e.flags |= VTX_EVF_OLDVAL | VTX_EVF_NEWVAL | (denied ? VTX_EVF_DENIED : 0);
	vtx_event_commit(v, &e);
}

VTX_HOST static void vtx_emul_event(struct vtx_vcpu *v, u64 gpa, u64 gla, int pol, int slot, const u8 *data, u32 len)
{
	struct vtx_global *g = v->g;
	struct vtx_event e;
	u64 nv = 0;
	u32 i;

	if (pol == VTX_WP_OPEN)
		return;
	for (i = 0; i < len && i < 8; i++)
		nv |= (u64)data[i] << (8 * i);
	if (pol == VTX_WP_SELF) {
		vtx_event_begin(v, &e, VTX_EV_TAMPER);
		e.watch_id = EPT_TAG_SELF;
	} else {
		vtx_event_begin(v, &e, VTX_EV_EPT_WRITE);
		if (slot >= 0 && slot < VTX_MAX_WSLOTS) {
			e.watch_id = g->tables.watch[slot].id;
			g->tables.watch[slot].hits++;
		}
	}
	e.gpa = gpa;
	e.gla = gla;
	e.info = EPTQ_WRITE;
	e.new_val = nv;
	e.flags |= VTX_EVF_GLA | VTX_EVF_EMUL | VTX_EVF_NEWVAL;
	if (pol >= VTX_WP_DENY) {
		e.flags |= VTX_EVF_DENIED;
		v->emul_denied++;
	}
	vtx_event_commit(v, &e);
}

VTX_HOST static int vtx_dtr_mem(struct vtx_vcpu *v, u64 la, void *buf, u32 len, int write)
{
	struct vtx_global *g = v->g;
	struct vtx_walk w;
	struct vtx_copy_res res;
	u32 err = 0, i, off = 0;
	u64 fva = la;
	int rc;

	vtx_walk_ctx(v, &w, 0);
	w.set_ad = 1;
	rc = vtx_guest_copy_ex(&g->pm, &w, la, buf, len, write, &err, &fva, &res);
	if (rc == VTX_WALK_PF) {
		vtx_inject_pf(v, fva, err);
		return -1;
	}
	if (rc != VTX_WALK_OK) {
		vtx_inject_gp(v);
		return -1;
	}
	if (write) {
		for (i = 0; i < res.n && i < 2; i++) {
			vtx_emul_event(v, res.gpa[i], res.gla[i], res.pol[i], res.slot[i], (const u8 *)buf + off, res.len[i]);
			off += res.len[i];
		}
	}
	return 0;
}

VTX_HOST static int vtx_ltr_busy(struct vtx_vcpu *v, u16 sel, u8 type_byte)
{
	struct vtx_global *g = v->g;
	struct vtx_walk w;
	u64 la = vtx_vmread(VMCS_GUEST_GDTR_BASE) + (sel & ~7ull) + 5;
	u64 gpa;
	u32 err = 0;
	int rc, pol, slot;
	u8 nb = type_byte | 0x02;

	vtx_walk_ctx(v, &w, 0);
	w.implicit = 1;
	w.set_ad = 1;
	rc = vtx_walk_gva(&g->pm, &w, la, VTX_ACC_WRITE, &gpa, &err);
	if (rc == VTX_WALK_PF) {
		vtx_inject_pf(v, la, err);
		return -1;
	}
	if (rc != VTX_WALK_OK || !vtx_phys_ok(&g->pm, gpa, 1)) {
		vtx_inject(v, VEC_GP, INTR_TYPE_HW_EXC, 1, sel & 0xfffc);
		return -1;
	}
	pol = vtx_write_policy(&g->tables, gpa, &slot);
	if (pol < VTX_WP_DENY)
		vtx_or8(vtx_pa2va(g->dmap, gpa), 0x02);
	vtx_emul_event(v, gpa, la, pol, slot, &nb, 1);
	return 0;
}

VTX_HOST static int vtx_read_desc(struct vtx_vcpu *v, u16 sel, u64 *lo, u64 *hi)
{
	struct vtx_global *g = v->g;
	u64 gb = vtx_vmread(VMCS_GUEST_GDTR_BASE);
	u64 gl = vtx_vmread(VMCS_GUEST_GDTR_LIMIT);
	u64 off = sel & ~7ull;
	u64 d[2];

	if ((sel & 4) || off + 15 > gl)
		return -1;
	if (vtx_read_kva(v, gb + off, d, 16)) {
		struct vtx_walk w;
		u32 err;

		vtx_walk_ctx(v, &w, 1);
		w.implicit = 1;
		if (vtx_guest_copy(&g->pm, &w, gb + off, d, 16, 0, &err, &off))
			return -1;
	}
	*lo = d[0];
	*hi = d[1];
	return 0;
}

VTX_HOSTI u64 vtx_desc_base(u64 lo, u64 hi)
{
	return ((lo >> 16) & 0xffffff) | (((lo >> 56) & 0xff) << 24) | ((hi & 0xffffffffull) << 32);
}

VTX_HOSTI u32 vtx_desc_limit(u64 lo)
{
	u32 lim = (u32)((lo & 0xffff) | (((lo >> 48) & 0xf) << 16));

	if (lo & (1ull << 55))
		lim = (lim << 12) | 0xfff;
	return lim;
}

VTX_HOSTI u32 vtx_desc_ar(u64 lo)
{
	return (u32)((lo >> 40) & 0xf0ff);
}

VTX_HOST static void vtx_dtr_exit(struct vtx_vcpu *v, struct vtx_regs *r, u32 reason)
{
	struct vtx_global *g = v->g;
	u32 info = (u32)vtx_vmread(VMCS_EXIT_INSTR_INFO);
	struct vtx_dtr_insn d;
	u64 gpr[16];
	u64 la = 0, segbase = 0;
	u32 i;
	int lm = (vtx_vmread(VMCS_GUEST_CS_AR) >> 13) & 1;

	vtx_dtr_decode(reason, info, &d);
	for (i = 0; i < 16; i++)
		gpr[i] = vtx_gpr_get(v, r, i);
	if (d.is_mem) {
		static const u32 segf[6] = { VMCS_GUEST_ES_BASE, VMCS_GUEST_CS_BASE, VMCS_GUEST_SS_BASE,
					     VMCS_GUEST_DS_BASE, VMCS_GUEST_FS_BASE, VMCS_GUEST_GS_BASE };

		if (d.seg < 6)
			segbase = vtx_vmread(segf[d.seg]);
		la = vtx_dtr_ea(&d, gpr, vtx_vmread(VMCS_EXIT_QUAL), segbase, lm);
	}
	switch (d.op) {
	case VTX_DTR_SGDT:
	case VTX_DTR_SIDT: {
		u8 buf[10];
		u64 base = vtx_vmread(d.op == VTX_DTR_SGDT ? VMCS_GUEST_GDTR_BASE : VMCS_GUEST_IDTR_BASE);
		u16 lim = (u16)vtx_vmread(d.op == VTX_DTR_SGDT ? VMCS_GUEST_GDTR_LIMIT : VMCS_GUEST_IDTR_LIMIT);
		u32 n = lm ? 10 : 6;

		buf[0] = (u8)lim;
		buf[1] = (u8)(lim >> 8);
		for (i = 0; i < 8; i++)
			buf[2 + i] = (u8)(base >> (8 * i));
		if (vtx_dtr_mem(v, la, buf, n, 1))
			return;
		break;
	}
	case VTX_DTR_LGDT:
	case VTX_DTR_LIDT: {
		u8 buf[10];
		u64 base = 0;
		u16 lim;
		int idt = d.op == VTX_DTR_LIDT;
		u64 cur;
		int denied = 0;
		u32 n = lm ? 10 : 6;

		if (vtx_cpl() != 0) {
			vtx_inject_gp(v);
			return;
		}
		if (vtx_dtr_mem(v, la, buf, n, 0))
			return;
		lim = (u16)(buf[0] | (buf[1] << 8));
		for (i = 0; i < n - 2; i++)
			base |= (u64)buf[2 + i] << (8 * i);
		if (!vtx_canonical(base, (vtx_vmread(VMCS_GUEST_CR4) & CR4_LA57) != 0)) {
			vtx_inject_gp(v);
			return;
		}
		cur = vtx_vmread(idt ? VMCS_GUEST_IDTR_BASE : VMCS_GUEST_GDTR_BASE);
		if (idt) {
			if ((g->policy & VTX_PIN_IDTR) && (base != v->b_idtr_base || lim != v->b_idtr_limit))
				denied = 1;
		} else {
			if ((g->policy & VTX_PIN_GDTR) &&
			    ((base != v->b_gdtr_base && base != v->b_gdt_rw) || lim != v->b_gdtr_limit))
				denied = 1;
		}
		if (!denied) {
			vtx_vmwrite(idt ? VMCS_GUEST_IDTR_BASE : VMCS_GUEST_GDTR_BASE, base);
			vtx_vmwrite(idt ? VMCS_GUEST_IDTR_LIMIT : VMCS_GUEST_GDTR_LIMIT, lim);
		}
		if (denied || (idt && (base != v->b_idtr_base || lim != v->b_idtr_limit)) ||
		    (!idt && base != v->b_gdtr_base && base != v->b_gdt_rw))
			vtx_dtr_event(v, d.op, cur, base, lim, denied);
		break;
	}
	case VTX_DTR_SLDT:
	case VTX_DTR_STR: {
		u16 sel = (u16)vtx_vmread(d.op == VTX_DTR_STR ? VMCS_GUEST_TR_SEL : VMCS_GUEST_LDTR_SEL);

		if (d.is_mem) {
			if (vtx_dtr_mem(v, la, &sel, 2, 1))
				return;
		} else {
			u8 code[15];
			u64 rip = vtx_vmread(VMCS_GUEST_RIP);
			u32 len = (u32)vtx_vmread(VMCS_EXIT_INSTR_LEN);
			struct vtx_walk w;
			u32 err;
			u64 fva;

			if (len > 15)
				len = 15;
			vtx_walk_ctx(v, &w, 0);
			if (vtx_guest_copy(&g->pm, &w, rip, code, len, 0, &err, &fva) == VTX_WALK_OK &&
			    vtx_insn_opsize16(code, len)) {
				u64 old = vtx_gpr_get(v, r, d.reg);

				vtx_gpr_set(v, r, d.reg, (old & ~0xffffull) | sel);
			} else {
				vtx_gpr_set(v, r, d.reg, sel);
			}
		}
		break;
	}
	case VTX_DTR_LLDT:
	case VTX_DTR_LTR: {
		u16 sel;
		u64 lo, hi;
		int ltr = d.op == VTX_DTR_LTR;

		if (vtx_cpl() != 0) {
			vtx_inject_gp(v);
			return;
		}
		if (d.is_mem) {
			if (vtx_dtr_mem(v, la, &sel, 2, 0))
				return;
		} else {
			sel = (u16)vtx_gpr_get(v, r, d.reg);
		}
		if (!ltr && (sel & ~3) == 0) {
			vtx_vmwrite(VMCS_GUEST_LDTR_SEL, sel);
			vtx_vmwrite(VMCS_GUEST_LDTR_BASE, 0);
			vtx_vmwrite(VMCS_GUEST_LDTR_LIMIT, 0);
			vtx_vmwrite(VMCS_GUEST_LDTR_AR, 0x10000);
			break;
		}
		if (vtx_read_desc(v, sel, &lo, &hi)) {
			vtx_inject(v, VEC_GP, INTR_TYPE_HW_EXC, 1, sel & 0xfffc);
			return;
		}
		if (!(lo & (1ull << 47))) {
			vtx_inject(v, VEC_NP, INTR_TYPE_HW_EXC, 1, sel & 0xfffc);
			return;
		}
		if (ltr) {
			u32 type = (u32)((lo >> 40) & 0x1f);

			if (type != 0x09) {
				vtx_inject(v, VEC_GP, INTR_TYPE_HW_EXC, 1, sel & 0xfffc);
				return;
			}
			if ((g->policy & VTX_PIN_TR) && sel != v->b_tr) {
				vtx_dtr_event(v, d.op, vtx_vmread(VMCS_GUEST_TR_SEL), sel, 0, 1);
				break;
			}
			if (vtx_ltr_busy(v, sel, (u8)(lo >> 40)))
				return;
			lo |= 1ull << 41;
			vtx_vmwrite(VMCS_GUEST_TR_SEL, sel);
			vtx_vmwrite(VMCS_GUEST_TR_BASE, vtx_desc_base(lo, hi));
			vtx_vmwrite(VMCS_GUEST_TR_LIMIT, vtx_desc_limit(lo));
			vtx_vmwrite(VMCS_GUEST_TR_AR, vtx_desc_ar(lo));
			if (sel != v->b_tr)
				vtx_dtr_event(v, d.op, v->b_tr, sel, 0, 0);
		} else {
			u32 type = (u32)((lo >> 40) & 0x1f);

			if (type != 0x02) {
				vtx_inject(v, VEC_GP, INTR_TYPE_HW_EXC, 1, sel & 0xfffc);
				return;
			}
			vtx_vmwrite(VMCS_GUEST_LDTR_SEL, sel);
			vtx_vmwrite(VMCS_GUEST_LDTR_BASE, vtx_desc_base(lo, hi));
			vtx_vmwrite(VMCS_GUEST_LDTR_LIMIT, vtx_desc_limit(lo));
			vtx_vmwrite(VMCS_GUEST_LDTR_AR, vtx_desc_ar(lo));
		}
		break;
	}
	default:
		vtx_inject_ud(v);
		return;
	}
	vtx_skip(v);
}

VTX_HOST static void vtx_reinject_idt_vectoring(struct vtx_vcpu *v)
{
	u32 info = (u32)vtx_vmread(VMCS_IDT_VEC_INFO);
	u32 type;

	if (!(info & INTR_INFO_VALID) || v->inj_valid)
		return;
	type = info & INTR_TYPE_MASK;
	v->inj_valid = 1;
	v->inj_info = info & (INTR_INFO_VALID | INTR_TYPE_MASK | INTR_INFO_ERRCODE | 0xff);
	v->inj_err = (info & INTR_INFO_ERRCODE) ? (u32)vtx_vmread(VMCS_IDT_VEC_ERRCODE) : 0;
	if (type == INTR_TYPE_SW_INT || type == INTR_TYPE_PRIV_SW_EXC || type == INTR_TYPE_SW_EXC)
		v->inj_len = (u32)vtx_vmread(VMCS_EXIT_INSTR_LEN);
	else
		v->inj_len = 0;
	if (type == INTR_TYPE_NMI)
		v->nmi_reflected++;
}

VTX_HOST static void vtx_exception_nmi_exit(struct vtx_vcpu *v)
{
	u32 info = (u32)vtx_vmread(VMCS_EXIT_INTR_INFO);

	if ((info & INTR_INFO_VALID) && (info & INTR_TYPE_MASK) == INTR_TYPE_NMI) {
		vtx_xadd64(&v->nmi_pending, 1);
		return;
	}
	if (info & INTR_INFO_VALID) {
		u32 err = (info & INTR_INFO_ERRCODE) ? (u32)vtx_vmread(VMCS_EXIT_INTR_ERRCODE) : 0;

		vtx_inject(v, info & 0xff, info & INTR_TYPE_MASK, (info & INTR_INFO_ERRCODE) != 0, err);
		v->injected--;
	}
}

VTX_HOST static void vtx_sync(struct vtx_vcpu *v)
{
	struct vtx_global *g = v->g;
	u64 eg = READ_ONCE(g->ept_gen);
	u64 pg = READ_ONCE(g->policy_gen);

	if (v->ept_gen != eg) {
		v->ept_gen = eg;
		vtx_invept_self(v);
	}
	if (v->policy_gen != pg) {
		v->policy_gen = pg;
		vtx_apply_cr_policy(v);
	}
}

VTX_HOST void vtx_apply_cr_policy(struct vtx_vcpu *v)
{
	struct vtx_global *g = v->g;
	u64 must1 = g->cr0_fixed0, must0 = ~g->cr0_fixed1;
	u64 m0, m4, real0, real4;

	if (v->proc2 & PROC2_UNRESTRICTED)
		must1 &= ~(CR0_PE | CR0_PG);
	m0 = must1 | (must0 & 0xffffffffull) | CR0_WP;
	m4 = g->cr4_fixed0 | (~g->cr4_fixed1 & 0xffffffffull) | CR4_VMXE | CR4_SMEP | CR4_SMAP | CR4_UMIP;
	real0 = vtx_vmread(VMCS_GUEST_CR0);
	real4 = vtx_vmread(VMCS_GUEST_CR4);
	if (m0 != v->cr0_mask) {
		u64 sh = vtx_vmread(VMCS_CR0_SHADOW);

		sh = (sh & v->cr0_mask) | (real0 & ~v->cr0_mask);
		vtx_vmwrite(VMCS_CR0_SHADOW, sh);
		vtx_vmwrite(VMCS_CR0_MASK, m0);
		v->cr0_mask = m0;
	}
	if (m4 != v->cr4_mask) {
		u64 sh = vtx_vmread(VMCS_CR4_SHADOW);

		sh = (sh & v->cr4_mask) | (real4 & ~v->cr4_mask);
		vtx_vmwrite(VMCS_CR4_SHADOW, sh);
		vtx_vmwrite(VMCS_CR4_MASK, m4);
		v->cr4_mask = m4;
	}
}

VTX_HOST int vtx_devirt_prepare(struct vtx_vcpu *v, struct vtx_regs *r, u64 retval)
{
	struct vtx_iret_frame *f = (struct vtx_iret_frame *)(v->stack_base + VTX_HOST_RSP_OFF);
	u64 rip = vtx_vmread(VMCS_GUEST_RIP);
	u64 rsp = vtx_vmread(VMCS_GUEST_RSP);
	u64 rfl = vtx_vmread(VMCS_GUEST_RFLAGS);
	u64 cr0 = vtx_vmread(VMCS_GUEST_CR0);
	u64 cr3 = vtx_vmread(VMCS_GUEST_CR3);
	u64 cr4 = vtx_vmread(VMCS_GUEST_CR4) & ~CR4_VMXE;
	u64 efer = vtx_vmread(VMCS_GUEST_EFER);
	u64 dbgctl = vtx_vmread(VMCS_GUEST_DEBUGCTL);
	u64 dr7 = vtx_vmread(VMCS_GUEST_DR7);
	u64 fsb = vtx_vmread(VMCS_GUEST_FS_BASE);
	u64 gsb = vtx_vmread(VMCS_GUEST_GS_BASE);
	u64 sycs = vtx_vmread(VMCS_GUEST_SYSENTER_CS);
	u64 syesp = vtx_vmread(VMCS_GUEST_SYSENTER_ESP);
	u64 syeip = vtx_vmread(VMCS_GUEST_SYSENTER_EIP);
	u16 cs = (u16)vtx_vmread(VMCS_GUEST_CS_SEL);
	u16 ss = (u16)vtx_vmread(VMCS_GUEST_SS_SEL);
	u16 ds = (u16)vtx_vmread(VMCS_GUEST_DS_SEL);
	u16 es = (u16)vtx_vmread(VMCS_GUEST_ES_SEL);
	u16 fs = (u16)vtx_vmread(VMCS_GUEST_FS_SEL);
	u16 gs = (u16)vtx_vmread(VMCS_GUEST_GS_SEL);
	u16 tr = (u16)vtx_vmread(VMCS_GUEST_TR_SEL);
	u16 ldtr = (u16)vtx_vmread(VMCS_GUEST_LDTR_SEL);
	struct vtx_dtr gdt, idt, gdtrw;
	u64 *trdesc;

	gdt.base = vtx_vmread(VMCS_GUEST_GDTR_BASE);
	gdt.limit = (u16)vtx_vmread(VMCS_GUEST_GDTR_LIMIT);
	idt.base = vtx_vmread(VMCS_GUEST_IDTR_BASE);
	idt.limit = (u16)vtx_vmread(VMCS_GUEST_IDTR_LIMIT);
	gdtrw.base = v->b_gdt_rw ? v->b_gdt_rw : gdt.base;
	gdtrw.limit = gdt.limit;
	if (retval == 0)
		rip += vtx_vmread(VMCS_EXIT_INSTR_LEN);
	if (v->proc & PROC_MTF)
		v->proc &= ~PROC_MTF;
	if (v->launched) {
		v->launched = 0;
		vtx_xadd32(&v->g->virt_count, (u32)-1);
	}
	WRITE_ONCE(v->vmx_active, 0);
	vtx_vmclear(v->vmcs_pa);
	vtx_vmxoff();
	vtx_write_cr3(cr3);
	trdesc = (u64 *)(gdtrw.base + (tr & ~7ull));
	WRITE_ONCE(*trdesc, *trdesc & ~(1ull << 41));
	vtx_lgdt(&gdtrw);
	vtx_ltr(tr);
	vtx_lgdt(&gdt);
	if (ldtr & ~3)
		vtx_lldt(ldtr);
	else
		vtx_lldt(0);
	vtx_load_ds(ds);
	vtx_load_es(es);
	vtx_load_fs(fs);
	vtx_wrmsr(MSR_FS_BASE, fsb);
	vtx_wrmsr(MSR_IA32_SYSENTER_CS, sycs);
	vtx_wrmsr(MSR_IA32_SYSENTER_ESP, syesp);
	vtx_wrmsr(MSR_IA32_SYSENTER_EIP, syeip);
	if (vtx_rdmsr(MSR_EFER) != efer)
		vtx_wrmsr(MSR_EFER, efer);
	vtx_write_dr7(dr7);
	vtx_wrmsr(MSR_IA32_DEBUGCTL, dbgctl);
	vtx_write_cr0(cr0);
	vtx_write_cr4(cr4);
	vtx_load_gs(gs);
	vtx_wrmsr(MSR_GS_BASE, gsb);
	vtx_lidt(&idt);
	f->rip = rip;
	f->cs = cs;
	f->rflags = rfl;
	f->rsp = rsp;
	f->ss = ss;
	r->rax = retval;
	return 1;
}

VTX_HOST static int vtx_vmx_insn_exit(struct vtx_vcpu *v, u32 reason)
{
	struct vtx_event e;

	vtx_event_begin(v, &e, VTX_EV_VMX);
	e.info = reason;
	e.flags |= VTX_EVF_DENIED;
	vtx_event_commit(v, &e);
	vtx_inject_ud(v);
	return 0;
}

VTX_HOSTI u32 vtx_nmi_window(u64 gi, int vnmi, int injected)
{
	if (!injected && (gi & GI_BLOCK_STI))
		return PROC_INTR_WINDOW;
	return vnmi ? PROC_NMI_WINDOW : 0;
}

VTX_HOST static u64 vtx_step_shadow(struct vtx_vcpu *v, u64 gi)
{
	u64 fl = vtx_vmread(VMCS_GUEST_RFLAGS);

	if (!(fl & RFLAGS_IF) || (fl & RFLAGS_TF) || (gi & (GI_BLOCK_STI | GI_BLOCK_MOVSS)))
		return gi;
	if (vtx_vmread(VMCS_GUEST_ACTIVITY) || vtx_vmread(VMCS_GUEST_PENDING_DBG))
		return gi;
	gi |= GI_BLOCK_STI;
	vtx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY, gi);
	v->shadows++;
	return gi;
}

VTX_HOST static void vtx_epilogue(struct vtx_vcpu *v)
{
	u64 gi = vtx_vmread(VMCS_GUEST_INTERRUPTIBILITY);
	u32 proc = v->proc;
	int vnmi = (v->pin & PIN_VIRTUAL_NMIS) != 0;
	int injected = 0;

	if (v->inj_valid) {
		vtx_vmwrite(VMCS_ENTRY_INTR_INFO, v->inj_info);
		if (v->inj_info & INTR_INFO_ERRCODE)
			vtx_vmwrite(VMCS_ENTRY_EXC_ERRCODE, v->inj_err);
		vtx_vmwrite(VMCS_ENTRY_INSTR_LEN, v->inj_len);
		v->inj_valid = 0;
		injected = 1;
	} else if (READ_ONCE(v->nmi_pending) && !(gi & (GI_BLOCK_STI | GI_BLOCK_MOVSS | GI_BLOCK_NMI))) {
		vtx_vmwrite(VMCS_ENTRY_INTR_INFO, INTR_INFO_VALID | INTR_TYPE_NMI | VEC_NMI);
		vtx_vmwrite(VMCS_ENTRY_INSTR_LEN, 0);
		vtx_xadd64(&v->nmi_pending, (u64)-1);
		v->nmi_reflected++;
		injected = 1;
	}
	if (v->step_shadow_req) {
		v->step_shadow_req = 0;
		if (!injected && (proc & PROC_MTF) && v->step_n)
			gi = vtx_step_shadow(v, gi);
	}
	if (READ_ONCE(v->nmi_pending))
		proc |= vtx_nmi_window(gi, vnmi, injected);
	vtx_vmwrite(VMCS_PROC_CTLS, proc);
	if (READ_ONCE(v->nmi_pending) && !(proc & (PROC_NMI_WINDOW | PROC_INTR_WINDOW)))
		vtx_vmwrite(VMCS_PROC_CTLS, proc | vtx_nmi_window(gi, vnmi, injected));
}

VTX_HOST int vtx_handle_exit(struct vtx_vcpu *v, struct vtx_regs *r)
{
	u64 t0 = vtx_rdtsc();
	u32 reason = (u32)vtx_vmread(VMCS_EXIT_REASON);
	u32 basic = reason & 0xffff;
	int rc = 0;

	v->cur_exit_tsc = t0;
	if (reason & EXIT_REASON_ENTRY_FAIL) {
		if (!v->launched)
			return vtx_devirt_prepare(v, r, VTX_LAUNCH_FAIL_ENTRY | reason);
		vtx_fatal(v, "vm-entry-failure", reason, vtx_vmread(VMCS_EXIT_QUAL));
	}
	if (!v->launched) {
		v->launched = 1;
		vtx_xadd32(&v->g->virt_count, 1);
	}
	vtx_sync(v);
	switch (basic) {
	case EXIT_REASON_EXCEPTION_NMI:
		vtx_exception_nmi_exit(v);
		vtx_reinject_idt_vectoring(v);
		break;
	case EXIT_REASON_NMI_WINDOW:
	case EXIT_REASON_INTR_WINDOW:
		break;
	case EXIT_REASON_TRIPLE_FAULT:
		vtx_fatal(v, "guest-triple-fault", vtx_vmread(VMCS_GUEST_RIP), vtx_vmread(VMCS_IDT_VEC_INFO));
		break;
	case EXIT_REASON_INIT: {
		struct vtx_event e;

		vtx_event_begin(v, &e, VTX_EV_INIT);
		e.flags |= VTX_EVF_DENIED;
		vtx_event_commit(v, &e);
		break;
	}
	case EXIT_REASON_CPUID:
		vtx_cpuid_exit(v, r);
		break;
	case EXIT_REASON_GETSEC:
		vtx_inject_ud(v);
		break;
	case EXIT_REASON_INVD:
		vtx_wbinvd();
		vtx_skip(v);
		break;
	case EXIT_REASON_VMCALL:
		rc = vtx_hypercall(v, r);
		break;
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
	case EXIT_REASON_INVEPT:
	case EXIT_REASON_INVVPID:
	case EXIT_REASON_VMFUNC:
		rc = vtx_vmx_insn_exit(v, basic);
		break;
	case EXIT_REASON_CR_ACCESS:
		vtx_cr_exit(v, r);
		break;
	case EXIT_REASON_MSR_READ:
		vtx_msr_read_exit(v, r);
		break;
	case EXIT_REASON_MSR_WRITE:
		vtx_msr_write_exit(v, r);
		break;
	case EXIT_REASON_MTF:
		vtx_mtf(v);
		break;
	case EXIT_REASON_GDTR_IDTR:
	case EXIT_REASON_LDTR_TR:
		vtx_dtr_exit(v, r, basic);
		break;
	case EXIT_REASON_EPT_VIOLATION:
		vtx_ept_violation(v);
		vtx_reinject_idt_vectoring(v);
		break;
	case EXIT_REASON_EPT_MISCONFIG:
		vtx_fatal(v, "ept-misconfig", vtx_vmread(VMCS_GUEST_PHYS_ADDR), 0);
		break;
	case EXIT_REASON_XSETBV:
		vtx_xsetbv_exit(v, r);
		break;
	case EXIT_REASON_XSAVES:
	case EXIT_REASON_XRSTORS:
		vtx_inject_ud(v);
		break;
	default:
		vtx_fatal(v, "unexpected-exit", reason, vtx_vmread(VMCS_EXIT_QUAL));
		break;
	}
	if (rc)
		return rc;
	if (v->step_retired) {
		v->step_retired = 0;
		if (v->step_n)
			vtx_mtf(v);
	}
	vtx_epilogue(v);
	v->total_exits++;
	if (basic < VTX_EXIT_REASONS) {
		v->exits[basic]++;
		v->cycles[basic] += vtx_rdtsc() - t0;
	}
	return 0;
}
