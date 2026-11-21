#include "vtx.h"

VTX_HOSTI u32 vtx_hc_cpl(void)
{
	return (u32)((vtx_vmread(VMCS_GUEST_SS_AR) >> 5) & 3);
}

VTX_HOST static void *vtx_hc_buf(struct vtx_global *g, u64 gpa, u64 len)
{
	if (!len || len > (1ull << 20) || !vtx_phys_ok(&g->pm, gpa, len))
		return NULL;
	return vtx_pa2va(g->dmap, gpa);
}

VTX_HOST static void *vtx_hc_out(struct vtx_vcpu *v, u64 gpa, u64 len)
{
	struct vtx_global *g = v->g;
	void *p = vtx_hc_buf(g, gpa, len);
	u64 pg;

	if (!p)
		return NULL;
	for (pg = gpa & VTX_PAGE_MASK; pg < gpa + len; pg += VTX_PAGE_SIZE) {
		struct vtx_event e;

		if (vtx_write_policy(&g->tables, pg, NULL) == VTX_WP_OPEN)
			continue;
		vtx_event_begin(v, &e, VTX_EV_HYPERCALL);
		e.flags |= VTX_EVF_DENIED | VTX_EVF_EMUL;
		e.info = v->hc_fn;
		e.gpa = gpa;
		e.new_val = pg;
		vtx_event_commit(v, &e);
		v->emul_denied++;
		return NULL;
	}
	return p;
}

VTX_HOST static void vtx_zero(void *p, u64 n)
{
	vtx_memset(p, 0, n);
}

VTX_HOST static int vtx_range_forbidden(struct vtx_global *g, u64 start, u64 end)
{
	u32 i;

	for (i = 0; i < g->tables.nr_owned && i < VTX_MAX_OWNED; i++)
		if (vtx_range_overlap(start, end, g->tables.owned[i].start, g->tables.owned[i].end))
			return 1;
	for (i = 0; i < g->tables.nr_self && i < VTX_MAX_SELF; i++)
		if (g->tables.self_pa[i] >= start && g->tables.self_pa[i] < end)
			return 1;
	if (vtx_range_overlap(start, end, g->tables.sink_pa, g->tables.sink_pa + VTX_PAGE_SIZE))
		return 1;
	return 0;
}

VTX_HOST static void vtx_reapply(struct vtx_global *g, u64 start, u64 end)
{
	u64 p;

	for (p = start; p < end; p += VTX_PAGE_SIZE)
		vtx_apply_page_all(g, p);
}

VTX_HOST static s64 vtx_hc_protect(struct vtx_vcpu *v, struct vtx_regs *r)
{
	struct vtx_global *g = v->g;
	u64 start = r->rbx, end = r->rcx;
	u32 deny = (u32)(r->rdx & 7), mode = (u32)((r->rdx >> 8) & 1);
	u32 id = (u32)r->rsi;
	u64 name_gpa = r->rdi;
	struct vtx_watch *w = NULL;
	u64 p;
	u32 i;
	int rc = 0;

	if ((start | end) & (VTX_PAGE_SIZE - 1) || start >= end || (end - 1) >> g->maxphy || !deny)
		return VTX_E_INVAL;
	if (vtx_range_forbidden(g, start, end))
		return VTX_E_PERM;
	vtx_spin_lock(&g->ept_lock);
	for (i = 0; i < VTX_MAX_WSLOTS; i++) {
		if (!g->tables.watch[i].used) {
			w = &g->tables.watch[i];
			break;
		}
	}
	if (!w) {
		vtx_spin_unlock(&g->ept_lock);
		return VTX_E_NOSPC;
	}
	if (!id)
		id = ++g->next_id;
	w->id = id;
	w->deny = deny;
	w->mode = mode;
	w->start = start;
	w->end = end;
	w->hits = 0;
	vtx_zero(w->name, sizeof(w->name));
	if (name_gpa) {
		char *src = vtx_hc_buf(g, name_gpa, VTX_WNAME);

		if (src) {
			for (i = 0; i < VTX_WNAME - 1; i++) {
				char c = READ_ONCE(src[i]);

				if (!c)
					break;
				w->name[i] = (c >= 0x20 && c <= 0x7e) ? c : '?';
			}
		}
	}
	asm volatile("" : : : "memory");
	WRITE_ONCE(w->used, 1);
	for (p = start; p < end; p += VTX_PAGE_SIZE) {
		rc = vtx_apply_page_all(g, p);
		if (rc)
			break;
	}
	if (rc) {
		WRITE_ONCE(w->used, 0);
		vtx_reapply(g, start, p);
	}
	g->ept_gen++;
	v->ept_gen = g->ept_gen;
	vtx_spin_unlock(&g->ept_lock);
	vtx_invept_self(v);
	if (rc)
		return rc;
	r->rbx = id;
	return 0;
}

VTX_HOST static s64 vtx_hc_unprotect(struct vtx_vcpu *v, struct vtx_regs *r)
{
	struct vtx_global *g = v->g;
	u32 id = (u32)r->rbx, i;
	int found = 0;

	if (READ_ONCE(g->locked))
		return VTX_E_PERM;
	vtx_spin_lock(&g->ept_lock);
	for (i = 0; i < VTX_MAX_WSLOTS; i++) {
		struct vtx_watch *w = &g->tables.watch[i];

		if (w->used && w->id == id) {
			WRITE_ONCE(w->used, 0);
			vtx_reapply(g, w->start, w->end);
			found = 1;
		}
	}
	g->ept_gen++;
	v->ept_gen = g->ept_gen;
	vtx_spin_unlock(&g->ept_lock);
	vtx_invept_self(v);
	return found ? 0 : VTX_E_NOENT;
}

VTX_HOST static s64 vtx_hc_drain(struct vtx_vcpu *v, struct vtx_regs *r)
{
	struct vtx_global *g = v->g;
	u64 max = r->rcx;
	struct vtx_event *out;
	u64 n = 0;
	u32 c;

	if (!max || max > 4096)
		return VTX_E_INVAL;
	out = vtx_hc_out(v, r->rbx, max * sizeof(struct vtx_event));
	if (!out)
		return VTX_E_FAULT;
	vtx_spin_lock(&g->ring_lock);
	for (c = 0; c < g->ncpu && c < VTX_MAX_CPUS && n < max; c++) {
		struct vtx_vcpu *o = g->vcpu[c];

		if (o && o->ring)
			n += vtx_ring_pop(o->ring, out + n, (u32)(max - n));
	}
	vtx_spin_unlock(&g->ring_lock);
	return (s64)n;
}

VTX_HOST static s64 vtx_hc_stats(struct vtx_vcpu *v, struct vtx_regs *r)
{
	struct vtx_global *g = v->g;
	struct vtx_stats *s = vtx_hc_out(v, r->rbx, sizeof(*s));
	u32 c, i;

	if (!s)
		return VTX_E_FAULT;
	vtx_zero(s, sizeof(*s));
	s->nreasons = VTX_EXIT_REASONS;
	for (c = 0; c < g->ncpu && c < VTX_MAX_CPUS; c++) {
		struct vtx_vcpu *o = g->vcpu[c];

		if (!o)
			continue;
		s->ncpus++;
		for (i = 0; i < VTX_EXIT_REASONS; i++) {
			s->exits[i] += READ_ONCE(o->exits[i]);
			s->cycles[i] += READ_ONCE(o->cycles[i]);
		}
		if (c < 64)
			s->cpu_exits[c] = READ_ONCE(o->total_exits);
		s->nmi_reflected += READ_ONCE(o->nmi_reflected);
		s->steps += READ_ONCE(o->steps);
		s->spurious_ept += READ_ONCE(o->spurious);
		s->hypercalls += READ_ONCE(o->hypercalls);
		s->injected += READ_ONCE(o->injected);
		s->step_shadows += READ_ONCE(o->shadows);
		s->step_recycles += READ_ONCE(o->recycles);
		s->emul_denied += READ_ONCE(o->emul_denied);
	}
	s->events = READ_ONCE(g->events);
	s->dropped = READ_ONCE(g->dropped);
	return 0;
}

VTX_HOST static s64 vtx_hc_query(struct vtx_vcpu *v, struct vtx_regs *r)
{
	struct vtx_global *g = v->g;
	struct vtx_status *s = vtx_hc_out(v, r->rbx, sizeof(*s));
	const char *sig = VTX_SIGNATURE;
	u32 c, i, n = 0;

	if (!s)
		return VTX_E_FAULT;
	vtx_zero(s, sizeof(*s));
	s->abi = VTX_ABI_VERSION;
	s->locked = READ_ONCE(g->locked);
	s->policy = READ_ONCE(g->policy);
	s->features = g->features;
	for (c = 0; c < g->ncpu && c < VTX_MAX_CPUS; c++) {
		struct vtx_vcpu *o = g->vcpu[c];

		if (o && READ_ONCE(o->vmx_active)) {
			s->virt_mask[c / 64] |= 1ull << (c % 64);
			n++;
		}
	}
	s->virt_cpus = n;
	for (i = 0; i < VTX_MAX_WSLOTS; i++)
		if (g->tables.watch[i].used)
			s->nwatch++;
	s->pool_total = g->pool.total;
	s->pool_used = g->pool.used;
	s->nchunks = g->nchunks;
	s->events_total = READ_ONCE(g->events);
	s->events_dropped = READ_ONCE(g->dropped);
	s->tamper_count = READ_ONCE(g->tamper);
	s->arena_bytes = g->arena_bytes;
	s->arena_pa0 = g->arena_pa0;
	s->map_limit = g->map_limit;
	s->host_text_pa = g->host_text_pa0;
	s->host_text_pages = g->host_text_pages;
	s->ro_pages = g->ro_pages;
	s->maxphyaddr = g->maxphy;
	s->paging_levels = g->la57 ? 5 : 4;
	s->load_tsc = g->load_tsc;
	for (i = 0; i < 12; i++)
		s->signature[i] = sig[i];
	return 0;
}

VTX_HOST static s64 vtx_hc_wlist(struct vtx_vcpu *v, struct vtx_regs *r)
{
	struct vtx_global *g = v->g;
	struct vtx_watch_list *l = vtx_hc_out(v, r->rbx, sizeof(*l));
	u32 i, k;

	if (!l)
		return VTX_E_FAULT;
	vtx_zero(l, sizeof(*l));
	vtx_spin_lock(&g->ept_lock);
	for (i = 0; i < VTX_MAX_WSLOTS && l->count < VTX_MAX_WATCH; i++) {
		struct vtx_watch *w = &g->tables.watch[i];
		struct vtx_watch_info *o;

		if (!w->used)
			continue;
		o = &l->w[l->count++];
		o->id = w->id;
		o->deny = w->deny;
		o->mode = w->mode;
		o->pages = (u32)((w->end - w->start) >> VTX_PAGE_SHIFT);
		o->gpa_start = w->start;
		o->gpa_end = w->end;
		o->hits = w->hits;
		for (k = 0; k < VTX_NAME_LEN && k < VTX_WNAME; k++)
			o->name[k] = w->name[k];
	}
	vtx_spin_unlock(&g->ept_lock);
	return 0;
}

VTX_HOST int vtx_hypercall(struct vtx_vcpu *v, struct vtx_regs *r)
{
	struct vtx_global *g = v->g;
	u64 fn = r->rax;
	s64 ret = VTX_E_INVAL;

	if ((fn & VTX_HC_MASK) != VTX_HC_MAGIC || vtx_hc_cpl() != 0) {
		if ((fn & VTX_HC_MASK) == VTX_HC_MAGIC) {
			struct vtx_event e;

			vtx_event_begin(v, &e, VTX_EV_HYPERCALL);
			e.info = fn;
			e.flags |= VTX_EVF_DENIED;
			vtx_event_commit(v, &e);
		}
		vtx_inject_ud(v);
		return 0;
	}
	v->hypercalls++;
	v->hc_fn = fn;
	switch (fn & 0xff) {
	case VTX_HC_PING: {
		const u64 *sig = (const u64 *)VTX_SIGNATURE;

		r->rbx = sig[0];
		r->rcx = VTX_VERSION;
		r->rdx = READ_ONCE(g->locked);
		ret = 0;
		break;
	}
	case VTX_HC_DEVIRT:
		if (READ_ONCE(g->locked)) {
			ret = VTX_E_PERM;
			break;
		}
		return vtx_devirt_prepare(v, r, 0);
	case VTX_HC_SYNC:
		v->ept_gen = READ_ONCE(g->ept_gen);
		v->policy_gen = READ_ONCE(g->policy_gen);
		vtx_invept_self(v);
		vtx_apply_cr_policy(v);
		ret = 0;
		break;
	case VTX_HC_PROTECT:
		ret = vtx_hc_protect(v, r);
		break;
	case VTX_HC_UNPROTECT:
		ret = vtx_hc_unprotect(v, r);
		break;
	case VTX_HC_POLICY: {
		u32 set = (u32)r->rbx & VTX_PIN_ALL, clr = (u32)r->rcx & VTX_PIN_ALL;

		if (READ_ONCE(g->locked) && clr) {
			ret = VTX_E_PERM;
			break;
		}
		if (!g->dtexit)
			set &= ~(VTX_PIN_IDTR | VTX_PIN_GDTR | VTX_PIN_TR);
		WRITE_ONCE(g->policy, (g->policy | set) & ~clr);
		vtx_xadd64(&g->policy_gen, 1);
		v->policy_gen = READ_ONCE(g->policy_gen);
		vtx_apply_cr_policy(v);
		r->rbx = g->policy;
		ret = 0;
		break;
	}
	case VTX_HC_LOCK:
		WRITE_ONCE(g->locked, 1);
		ret = 0;
		break;
	case VTX_HC_DRAIN:
		ret = vtx_hc_drain(v, r);
		break;
	case VTX_HC_STATS:
		ret = vtx_hc_stats(v, r);
		break;
	case VTX_HC_QUERY:
		ret = vtx_hc_query(v, r);
		break;
	case VTX_HC_WLIST:
		ret = vtx_hc_wlist(v, r);
		break;
	default:
		ret = VTX_E_INVAL;
		break;
	}
	r->rax = (u64)ret;
	vtx_skip(v);
	return 0;
}
