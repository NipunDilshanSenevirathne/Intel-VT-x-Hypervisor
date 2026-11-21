#include "vtx.h"

VTX_HOST int vtx_apply_page_all(struct vtx_global *g, u64 gpa)
{
	u32 c;

	for (c = 0; c < g->ncpu && c < VTX_MAX_CPUS; c++) {
		struct vtx_vcpu *o = g->vcpu[c];
		u64 *pte;
		int rc;

		if (!o || !o->ept_root)
			continue;
		rc = vtx_ept_split(g->dmap, o->ept_root, gpa, &g->pool, &pte);
		if (rc == VTX_E_NOENT) {
			int mt = vtx_mtrr_type(&g->mtrr, gpa & VTX_PAGE_MASK, VTX_PAGE_SIZE);

			rc = vtx_ept_map(g->dmap, o->ept_root, gpa & VTX_PAGE_MASK, 1,
					 vtx_page_entry(&g->tables, gpa, (u64)(mt < 0 ? MT_UC : mt) << EPT_MT_SHIFT), &g->pool);
			if (rc)
				return rc;
			continue;
		}
		if (rc)
			return rc;
		WRITE_ONCE(*pte, vtx_page_entry(&g->tables, gpa, READ_ONCE(*pte)));
	}
	return 0;
}

VTX_HOST static u64 vtx_peek8(struct vtx_global *g, u64 pa, u64 off)
{
	u64 v = 0;
	u8 *p = vtx_pa2va(g->dmap, pa);
	int i;

	if (off > VTX_PAGE_SIZE - 8)
		off = VTX_PAGE_SIZE - 8;
	for (i = 7; i >= 0; i--)
		v = (v << 8) | READ_ONCE(p[off + i]);
	return v;
}

VTX_HOST static void vtx_flush_pending(struct vtx_vcpu *v)
{
	if (v->step_ev_valid) {
		vtx_event_commit(v, &v->step_ev);
		v->step_ev_valid = 0;
	}
}

VTX_HOST static void vtx_step_restore(struct vtx_vcpu *v)
{
	struct vtx_global *g = v->g;
	u32 i;

	for (i = 0; i < v->step_n; i++) {
		int level;
		u64 *pte = vtx_ept_lookup(g->dmap, v->ept_root, v->step[i].gpa, &level);

		if (pte && level == 1)
			WRITE_ONCE(*pte, vtx_page_entry(&g->tables, v->step[i].gpa, READ_ONCE(*pte)));
	}
	v->step_n = 0;
	v->scratch_used = 0;
}

VTX_HOST static u64 vtx_step_add(struct vtx_vcpu *v, u64 page, u64 *pte, u32 kind, u32 tag, u64 acc)
{
	struct vtx_global *g = v->g;
	struct vtx_step_ent *s;
	u64 e, attr;
	u32 i;
	int slot_needed;

	for (i = 0; i < v->step_n; i++)
		if (v->step[i].gpa == page)
			break;
	slot_needed = kind == VTX_STEP_SCRATCH && (i == v->step_n || v->step[i].kind != VTX_STEP_SCRATCH);
	if ((i == v->step_n && v->step_n >= VTX_STEP_MAX) || (slot_needed && v->scratch_used >= VTX_SCRATCH_N)) {
		vtx_step_restore(v);
		vtx_invept_self(v);
		v->recycles++;
		i = 0;
	}
	s = &v->step[i];
	if (i == v->step_n) {
		s->gpa = page;
		s->kind = VTX_STEP_ALLOW;
		s->tag = (u16)tag;
		s->slot = 0;
		v->step_n++;
	}
	if (slot_needed) {
		s->kind = VTX_STEP_SCRATCH;
		s->slot = v->scratch_used++;
	}
	e = READ_ONCE(*pte);
	attr = e & (EPT_MT_MASK | EPT_IPAT);
	v->proc |= PROC_MTF;
	v->step_shadow_req = 1;
	if (s->kind == VTX_STEP_SCRATCH) {
		u64 spa = v->scratch_pa + (u64)s->slot * VTX_PAGE_SIZE;
		u64 src = (s->tag == EPT_TAG_SINK) ? g->tables.sink_pa : page;

		if ((e & EPT_ADDR_MASK) != spa)
			vtx_memcpy(vtx_pa2va(g->dmap, spa), vtx_pa2va(g->dmap, src), VTX_PAGE_SIZE);
		WRITE_ONCE(*pte, spa | EPT_RWX | EPT_SWVALID | attr | ((u64)EPT_TAG_STEP << EPT_TAG_SHIFT));
		return spa;
	}
	{
		u64 grant = acc & EPT_RWX;

		if (grant & EPT_W)
			grant |= EPT_R;
		if ((grant & EPT_X) && !g->tables.exec_only)
			grant |= EPT_R;
		WRITE_ONCE(*pte, e | grant);
	}
	return page;
}

VTX_HOST static void vtx_map_on_demand(struct vtx_vcpu *v, u64 gpa)
{
	struct vtx_global *g = v->g;
	u64 page = gpa & VTX_PAGE_MASK;
	u64 e;

	u64 big = gpa & ~(VTX_2M - 1);
	int mt;

	if (page >> g->maxphy || page >= (1ull << 48))
		vtx_fatal(v, "ept-violation-out-of-range", gpa, g->map_limit);
	mt = vtx_mtrr_type(&g->mtrr, big, VTX_2M);
	if (mt >= 0 && !vtx_tables_special(&g->tables, big, big + VTX_2M) &&
	    !vtx_ept_map(g->dmap, v->ept_root, big, 2, big | EPT_RWX | ((u64)mt << EPT_MT_SHIFT), &g->pool))
		return;
	mt = vtx_mtrr_type(&g->mtrr, page, VTX_PAGE_SIZE);
	e = vtx_page_entry(&g->tables, page, (u64)(mt < 0 ? MT_UC : mt) << EPT_MT_SHIFT);
	if (vtx_ept_map(g->dmap, v->ept_root, page, 1, e, &g->pool))
		vtx_fatal(v, "ept-pool-exhausted", gpa, g->pool.used);
}

VTX_HOST int vtx_ept_violation(struct vtx_vcpu *v)
{
	struct vtx_global *g = v->g;
	u64 q = vtx_vmread(VMCS_EXIT_QUAL);
	u64 gpa = vtx_vmread(VMCS_GUEST_PHYS_ADDR);
	u64 page = gpa & VTX_PAGE_MASK;
	u64 acc = q & (EPTQ_READ | EPTQ_WRITE | EPTQ_EXEC);
	u64 *pte, e;
	int level;
	u32 tag;
	struct vtx_event ev;

	if ((q & EPTQ_NMI_UNBLOCK) && (v->pin & PIN_VIRTUAL_NMIS) &&
	    !(vtx_vmread(VMCS_IDT_VEC_INFO) & INTR_INFO_VALID))
		vtx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY, vtx_vmread(VMCS_GUEST_INTERRUPTIBILITY) | GI_BLOCK_NMI);
	vtx_spin_lock(&g->ept_lock);
	pte = vtx_ept_lookup(g->dmap, v->ept_root, gpa, &level);
	if (!pte) {
		vtx_map_on_demand(v, gpa);
		vtx_spin_unlock(&g->ept_lock);
		v->spurious++;
		return 0;
	}
	e = READ_ONCE(*pte);
	tag = (u32)((e >> EPT_TAG_SHIFT) & 0xf);
	if (!(acc & ~(e & EPT_RWX)) || level != 1 || tag == EPT_TAG_NONE || tag == EPT_TAG_STEP) {
		vtx_spin_unlock(&g->ept_lock);
		v->spurious++;
		vtx_invept_self(v);
		return 0;
	}
	vtx_flush_pending(v);
	vtx_event_begin(v, &ev, VTX_EV_TAMPER);
	ev.gpa = gpa;
	ev.info = q;
	if (q & EPTQ_GLA_VALID) {
		ev.gla = vtx_vmread(VMCS_GUEST_LINEAR_ADDR);
		ev.flags |= VTX_EVF_GLA;
		if (!(q & EPTQ_GLA_FINAL))
			ev.flags |= VTX_EVF_PAGEWALK;
	}
	if (tag == EPT_TAG_SINK || tag == EPT_TAG_SELF) {
		ev.flags |= VTX_EVF_DENIED;
		ev.watch_id = tag;
		if (acc & EPTQ_EXEC) {
			vtx_spin_unlock(&g->ept_lock);
			vtx_event_commit(v, &ev);
			vtx_inject_gp(v);
			return 0;
		}
		if (tag == EPT_TAG_SELF) {
			ev.old_val = vtx_peek8(g, page, gpa & 0xfff);
			ev.flags |= VTX_EVF_OLDVAL;
		}
		v->step_ev_pa = vtx_step_add(v, page, pte, VTX_STEP_SCRATCH, tag, acc);
		vtx_memcpy(&v->step_ev, &ev, sizeof(ev));
		v->step_ev_valid = 1;
		v->step_ev_off = gpa & 0xfff;
		vtx_spin_unlock(&g->ept_lock);
		return 0;
	} else {
		u32 mode = 0, i;
		int slot = -1;
		u32 deny = vtx_watch_deny(&g->tables, page, &mode, &slot);
		int enforce;

		for (i = 0; i < VTX_MAX_WSLOTS; i++) {
			struct vtx_watch *w = &g->tables.watch[i];

			if (w->used && page >= w->start && page < w->end && (w->deny & acc))
				w->hits++;
		}
		if (slot >= 0)
			ev.watch_id = g->tables.watch[slot].id;
		if (acc & EPTQ_EXEC)
			ev.type = VTX_EV_EPT_EXEC;
		else if (acc & EPTQ_WRITE)
			ev.type = VTX_EV_EPT_WRITE;
		else
			ev.type = VTX_EV_EPT_READ;
		enforce = mode && (deny & acc & (EPTQ_WRITE | EPTQ_EXEC));
		if (ev.type == VTX_EV_EPT_EXEC && enforce) {
			ev.flags |= VTX_EVF_DENIED;
			vtx_spin_unlock(&g->ept_lock);
			vtx_event_commit(v, &ev);
			vtx_inject_gp(v);
			return 0;
		}
		if (ev.type == VTX_EV_EPT_WRITE) {
			ev.old_val = vtx_peek8(g, page, gpa & 0xfff);
			ev.flags |= VTX_EVF_OLDVAL;
		}
		if (ev.type == VTX_EV_EPT_WRITE && enforce) {
			ev.flags |= VTX_EVF_DENIED;
			v->step_ev_pa = vtx_step_add(v, page, pte, VTX_STEP_SCRATCH, tag, acc);
		} else {
			v->step_ev_pa = vtx_step_add(v, page, pte, VTX_STEP_ALLOW, tag, acc);
		}
		vtx_memcpy(&v->step_ev, &ev, sizeof(ev));
		v->step_ev_valid = 1;
		v->step_ev_off = gpa & 0xfff;
		vtx_spin_unlock(&g->ept_lock);
	}
	return 0;
}

VTX_HOST int vtx_mtf(struct vtx_vcpu *v)
{
	struct vtx_global *g = v->g;
	u64 newv = 0;
	int have_new = 0;

	if (!v->step_n) {
		v->proc &= ~PROC_MTF;
		return 0;
	}
	if (v->step_ev_valid && v->step_ev.type != VTX_EV_EPT_READ && v->step_ev.type != VTX_EV_EPT_EXEC) {
		newv = vtx_peek8(g, v->step_ev_pa, v->step_ev_off);
		have_new = 1;
	}
	vtx_spin_lock(&g->ept_lock);
	vtx_step_restore(v);
	vtx_spin_unlock(&g->ept_lock);
	vtx_invept_self(v);
	v->proc &= ~PROC_MTF;
	v->steps++;
	if (v->step_ev_valid) {
		if (have_new) {
			v->step_ev.new_val = newv;
			v->step_ev.flags |= VTX_EVF_NEWVAL;
		}
		vtx_event_commit(v, &v->step_ev);
		v->step_ev_valid = 0;
	}
	return 0;
}
