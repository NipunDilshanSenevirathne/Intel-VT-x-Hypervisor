#include "vtx.h"

VTX_HOSTI struct vtx_vcpu *vtx_vcpu_from_stack(void)
{
	u64 sp;

	asm volatile("movq %%rsp, %0" : "=r"(sp));
	sp &= ~((u64)VTX_STACK_SIZE - 1);
	return *(struct vtx_vcpu **)(sp + VTX_STACK_SIZE - 8);
}

VTX_HOST static void vtx_ser_putc(struct vtx_global *g, char c)
{
	u16 port = (u16)g->ser_port;
	int i;

	if (!port)
		return;
	for (i = 0; i < 200000; i++) {
		if (vtx_inb(port + 5) & 0x20)
			break;
		vtx_pause();
	}
	vtx_outb(port, (u8)c);
}

VTX_HOST void vtx_ser_puts(struct vtx_global *g, const char *s)
{
	while (*s) {
		if (*s == '\n')
			vtx_ser_putc(g, '\r');
		vtx_ser_putc(g, *s++);
	}
}

VTX_HOST void vtx_ser_hex(struct vtx_global *g, u64 v)
{
	static const char hx[] = "0123456789abcdef";
	char buf[19];
	int i;

	buf[0] = '0';
	buf[1] = 'x';
	for (i = 0; i < 16; i++)
		buf[2 + i] = hx[(v >> (60 - 4 * i)) & 15];
	buf[18] = 0;
	vtx_ser_puts(g, buf);
}

VTX_HOST static void vtx_ser_dec(struct vtx_global *g, u64 v)
{
	char buf[24];
	int i = 23;

	buf[i] = 0;
	do {
		buf[--i] = (char)('0' + v % 10);
		v /= 10;
	} while (v && i > 0);
	vtx_ser_puts(g, &buf[i]);
}

VTX_HOST void vtx_ser_kv(struct vtx_global *g, const char *k, u64 v)
{
	vtx_ser_puts(g, " ");
	vtx_ser_puts(g, k);
	vtx_ser_puts(g, "=");
	vtx_ser_hex(g, v);
}

VTX_HOST void vtx_fatal(struct vtx_vcpu *v, const char *why, u64 a, u64 b)
{
	struct vtx_global *g = v->g;

	vtx_spin_lock(&g->ser_lock);
	vtx_ser_puts(g, "\nvtxhv: FATAL cpu=");
	vtx_ser_dec(g, v->cpu);
	vtx_ser_puts(g, " ");
	vtx_ser_puts(g, why);
	vtx_ser_kv(g, "a", a);
	vtx_ser_kv(g, "b", b);
	if (v->vmx_active) {
		vtx_ser_kv(g, "reason", vtx_vmread(VMCS_EXIT_REASON));
		vtx_ser_kv(g, "qual", vtx_vmread(VMCS_EXIT_QUAL));
		vtx_ser_kv(g, "rip", vtx_vmread(VMCS_GUEST_RIP));
		vtx_ser_kv(g, "rsp", vtx_vmread(VMCS_GUEST_RSP));
		vtx_ser_kv(g, "cr0", vtx_vmread(VMCS_GUEST_CR0));
		vtx_ser_kv(g, "cr3", vtx_vmread(VMCS_GUEST_CR3));
		vtx_ser_kv(g, "cr4", vtx_vmread(VMCS_GUEST_CR4));
		vtx_ser_kv(g, "gpa", vtx_vmread(VMCS_GUEST_PHYS_ADDR));
		vtx_ser_kv(g, "idtvec", vtx_vmread(VMCS_IDT_VEC_INFO));
		vtx_ser_kv(g, "intr", vtx_vmread(VMCS_EXIT_INTR_INFO));
		vtx_ser_kv(g, "ierr", vtx_vmread(VMCS_INSTR_ERROR));
	}
	vtx_ser_puts(g, "\n");
	vtx_spin_unlock(&g->ser_lock);
	vtx_cli_hlt_forever();
	VTX_UNREACHABLE();
}

VTX_HOST void vtx_resume_failed(struct vtx_vcpu *v, u64 rflags)
{
	vtx_fatal(v, "vmresume-failed", rflags, vtx_vmread(VMCS_INSTR_ERROR));
}

VTX_HOST void vtx_host_exception(struct vtx_host_frame *f)
{
	struct vtx_vcpu *v = vtx_vcpu_from_stack();
	struct vtx_global *g = v->g;
	int i;

	for (i = 0; i < VTX_FIXUPS; i++) {
		if (g->fix[i].ip && f->rip == g->fix[i].ip) {
			f->rip = g->fix[i].to;
			v->fault_vector = (u32)f->vector;
			return;
		}
	}
	vtx_spin_lock(&g->ser_lock);
	vtx_ser_puts(g, "\nvtxhv: HOST EXCEPTION");
	vtx_ser_kv(g, "cpu", v->cpu);
	vtx_ser_kv(g, "vec", f->vector);
	vtx_ser_kv(g, "err", f->error);
	vtx_ser_kv(g, "rip", f->rip);
	vtx_ser_kv(g, "rsp", f->rsp);
	vtx_ser_kv(g, "cr2", vtx_read_cr2());
	vtx_ser_puts(g, "\n");
	vtx_spin_unlock(&g->ser_lock);
	vtx_cli_hlt_forever();
}

VTX_HOST void vtx_inject(struct vtx_vcpu *v, u32 vector, u32 type, int has_err, u32 err)
{
	v->inj_valid = 1;
	v->inj_info = INTR_INFO_VALID | type | (vector & 0xff) | (has_err ? INTR_INFO_ERRCODE : 0);
	v->inj_err = err;
	v->inj_len = 0;
	v->injected++;
}

VTX_HOST void vtx_inject_gp(struct vtx_vcpu *v)
{
	vtx_inject(v, VEC_GP, INTR_TYPE_HW_EXC, 1, 0);
}

VTX_HOST void vtx_inject_ud(struct vtx_vcpu *v)
{
	vtx_inject(v, VEC_UD, INTR_TYPE_HW_EXC, 0, 0);
}

VTX_HOST void vtx_inject_pf(struct vtx_vcpu *v, u64 cr2, u32 err)
{
	vtx_write_cr2(cr2);
	vtx_inject(v, VEC_PF, INTR_TYPE_HW_EXC, 1, err);
}

VTX_HOST void vtx_skip(struct vtx_vcpu *v)
{
	u64 rip = vtx_vmread(VMCS_GUEST_RIP) + vtx_vmread(VMCS_EXIT_INSTR_LEN);
	u64 gi = vtx_vmread(VMCS_GUEST_INTERRUPTIBILITY);
	u64 fl = vtx_vmread(VMCS_GUEST_RFLAGS);

	vtx_vmwrite(VMCS_GUEST_RIP, rip);
	if (v->step_n)
		v->step_retired = 1;
	if (gi & (GI_BLOCK_STI | GI_BLOCK_MOVSS))
		vtx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY, gi & ~(u64)(GI_BLOCK_STI | GI_BLOCK_MOVSS));
	if (fl & RFLAGS_TF) {
		u64 dbg = vtx_vmread(VMCS_GUEST_DEBUGCTL);

		if (!(dbg & 2))
			vtx_vmwrite(VMCS_GUEST_PENDING_DBG, vtx_vmread(VMCS_GUEST_PENDING_DBG) | (1ull << 14));
	}
}

VTX_HOST u64 vtx_gpr_get(struct vtx_vcpu *v, struct vtx_regs *r, u32 idx)
{
	int s = vtx_gpr_slot(idx);

	if (s == -2)
		return vtx_vmread(VMCS_GUEST_RSP);
	if (s < 0)
		return 0;
	return ((u64 *)r)[s];
}

VTX_HOST void vtx_gpr_set(struct vtx_vcpu *v, struct vtx_regs *r, u32 idx, u64 val)
{
	int s = vtx_gpr_slot(idx);

	if (s == -2) {
		vtx_vmwrite(VMCS_GUEST_RSP, val);
		return;
	}
	if (s >= 0)
		((u64 *)r)[s] = val;
}

VTX_HOST void vtx_invept_self(struct vtx_vcpu *v)
{
	struct vtx_global *g = v->g;

	if (g->ept_caps & EPTCAP_INVEPT_SINGLE)
		vtx_invept(1, v->eptp);
	else
		vtx_invept(2, 0);
}

VTX_HOST void vtx_walk_ctx(struct vtx_vcpu *v, struct vtx_walk *w, int kernel_view)
{
	struct vtx_global *g = v->g;
	u64 cr0 = vtx_vmread(VMCS_GUEST_CR0);
	u64 cr4 = vtx_vmread(VMCS_GUEST_CR4);
	u64 efer = vtx_vmread(VMCS_GUEST_EFER);
	u64 ss_ar = vtx_vmread(VMCS_GUEST_SS_AR);
	u64 cr3 = vtx_vmread(VMCS_GUEST_CR3);

	if (kernel_view && g->pti)
		cr3 &= ~(1ull << 12);
	w->cr3 = cr3;
	w->la57 = (cr4 & CR4_LA57) ? 1 : 0;
	w->nxe = (efer & VEFER_NXE) ? 1 : 0;
	w->wp = (cr0 & CR0_WP) ? 1 : 0;
	w->smep = (cr4 & CR4_SMEP) ? 1 : 0;
	w->smap = (cr4 & CR4_SMAP) ? 1 : 0;
	w->ac = (vtx_vmread(VMCS_GUEST_RFLAGS) & RFLAGS_AC) ? 1 : 0;
	w->user = kernel_view ? 0 : (((ss_ar >> 5) & 3) == 3);
	w->implicit = 0;
	w->set_ad = 0;
}

VTX_HOST int vtx_kva_to_gpa(struct vtx_vcpu *v, u64 kva, u64 *gpa)
{
	struct vtx_global *g = v->g;
	struct vtx_walk w;
	u32 err;
	u64 i;

	for (i = 0; i < g->pm.nr_ram && i < VTX_MAX_RAM; i++) {
		u64 s = g->dmap + g->pm.ram[i].start;
		u64 e = g->dmap + g->pm.ram[i].end;

		if (kva >= s && kva < e) {
			*gpa = kva - g->dmap;
			return 0;
		}
	}
	if (kva >= g->kimg_va && kva < g->kimg_end) {
		*gpa = kva - g->kimg_va + g->kimg_pa;
		return 0;
	}
	vtx_walk_ctx(v, &w, 1);
	if (vtx_walk_gva(&g->pm, &w, kva, VTX_ACC_READ, gpa, &err) != VTX_WALK_OK)
		return -1;
	return 0;
}

VTX_HOST int vtx_read_kva(struct vtx_vcpu *v, u64 kva, void *buf, u32 len)
{
	struct vtx_global *g = v->g;
	u8 *b = buf;

	while (len) {
		u64 gpa;
		u32 chunk = (u32)(VTX_PAGE_SIZE - (kva & (VTX_PAGE_SIZE - 1)));
		u8 *p;
		u32 i;

		if (chunk > len)
			chunk = len;
		if (vtx_kva_to_gpa(v, kva, &gpa))
			return -1;
		if (!vtx_phys_ok(&g->pm, gpa, chunk))
			return -1;
		p = vtx_pa2va(g->dmap, gpa);
		for (i = 0; i < chunk; i++)
			b[i] = READ_ONCE(p[i]);
		b += chunk;
		kva += chunk;
		len -= chunk;
	}
	return 0;
}

VTX_HOST void vtx_fill_task(struct vtx_vcpu *v, struct vtx_event *e)
{
	struct vtx_global *g = v->g;
	u64 gs, task = 0;
	s32 pid = 0;
	char comm[16];
	int i;

	if (!g->intro)
		return;
	if (e->flags & VTX_EVF_USER)
		gs = vtx_rdmsr(MSR_KERNEL_GS_BASE);
	else
		gs = vtx_vmread(VMCS_GUEST_GS_BASE);
	if (!(gs >> 63)) {
		u64 alt = vtx_rdmsr(MSR_KERNEL_GS_BASE);

		if (!(alt >> 63))
			return;
		gs = alt;
	}
	if (vtx_read_kva(v, gs + g->off_cur_task, &task, 8) || !(task >> 63))
		return;
	if (vtx_read_kva(v, task + g->off_tgid, &pid, 4))
		return;
	if (vtx_read_kva(v, task + g->off_comm, comm, 16))
		return;
	for (i = 0; i < 16; i++) {
		char c = comm[i];

		if (!c)
			break;
		if (c < 0x20 || c > 0x7e)
			c = '?';
		e->comm[i] = c;
	}
	for (; i < 16; i++)
		e->comm[i] = 0;
	e->comm[15] = 0;
	e->pid = pid;
	e->flags |= VTX_EVF_TASK;
}

VTX_HOST void vtx_event_begin(struct vtx_vcpu *v, struct vtx_event *e, u32 type)
{
	u64 *q = (u64 *)e;
	u64 ss_ar;
	u32 i;

	for (i = 0; i < sizeof(*e) / 8; i++)
		q[i] = 0;
	e->type = type;
	e->cpu = (u16)v->cpu;
	e->tsc = vtx_rdtsc();
	e->rip = vtx_vmread(VMCS_GUEST_RIP);
	e->rsp = vtx_vmread(VMCS_GUEST_RSP);
	e->cr3 = vtx_vmread(VMCS_GUEST_CR3);
	ss_ar = vtx_vmread(VMCS_GUEST_SS_AR);
	if (((ss_ar >> 5) & 3) == 3)
		e->flags |= VTX_EVF_USER;
}

VTX_HOST static void vtx_ser_event(struct vtx_global *g, const struct vtx_event *e)
{
	vtx_spin_lock(&g->ser_lock);
	vtx_ser_puts(g, "vtxhv-ev seq=");
	vtx_ser_dec(g, e->seq);
	vtx_ser_puts(g, " type=");
	vtx_ser_dec(g, e->type);
	vtx_ser_puts(g, " cpu=");
	vtx_ser_dec(g, e->cpu);
	vtx_ser_puts(g, (e->flags & VTX_EVF_DENIED) ? " denied" : " allowed");
	vtx_ser_kv(g, "rip", e->rip);
	vtx_ser_kv(g, "gpa", e->gpa);
	vtx_ser_kv(g, "info", e->info);
	if (e->flags & VTX_EVF_TASK) {
		vtx_ser_puts(g, " pid=");
		vtx_ser_dec(g, (u64)(u32)e->pid);
		vtx_ser_puts(g, " comm=");
		vtx_ser_puts(g, e->comm);
	}
	vtx_ser_puts(g, "\n");
	vtx_spin_unlock(&g->ser_lock);
}

VTX_HOST void vtx_event_commit(struct vtx_vcpu *v, struct vtx_event *e)
{
	struct vtx_global *g = v->g;

	vtx_fill_task(v, e);
	e->seq = vtx_xadd64(&g->seq, 1) + 1;
	if (e->type == VTX_EV_TAMPER)
		vtx_xadd64(&g->tamper, 1);
	vtx_xadd64(&g->events, 1);
	if (vtx_ring_push(v->ring, e))
		vtx_xadd64(&g->dropped, 1);
	if (g->ser_events)
		vtx_ser_event(g, e);
}
