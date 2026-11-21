#include "ept.h"
#include "ring.h"
#include "mtrr.h"
#include "vtx_vmcs.h"

u64 vtx_ring_bytes(u32 size)
{
	return sizeof(struct vtx_ring) + (u64)size * sizeof(struct vtx_event);
}

void vtx_ring_init(struct vtx_ring *r, u32 size)
{
	r->head = 0;
	r->tail = 0;
	r->size = size;
	r->lock = 0;
	r->dropped = 0;
	r->pushed = 0;
}

void vtx_mtrr_set_fixed_msr(struct vtx_mtrr *m, int msr_index, u64 value)
{
	int i, first;

	if (msr_index == 0)
		first = 0;
	else if (msr_index == 1)
		first = 8;
	else if (msr_index == 2)
		first = 16;
	else if (msr_index >= 3 && msr_index <= 10)
		first = 24 + (msr_index - 3) * 8;
	else
		return;
	for (i = 0; i < 8; i++)
		m->fixed[first + i] = (u8)(value >> (i * 8));
}

u64 vtx_eptp(u64 root_pa, int wb)
{
	return root_pa | ((u64)(VTX_EPT_LEVELS - 1) << 3) | (wb ? MT_WB : MT_UC);
}

int vtx_self_insert(struct vtx_tables *t, u64 pa, int exec)
{
	int i;

	pa &= VTX_PAGE_MASK;
	i = vtx_self_find(t, pa);
	if (i >= 0) {
		if (exec)
			t->self_x[i] = 1;
		return 0;
	}
	if (t->nr_self >= VTX_MAX_SELF)
		return VTX_E_NOSPC;
	i = (int)t->nr_self;
	while (i > 0 && t->self_pa[i - 1] > pa) {
		t->self_pa[i] = t->self_pa[i - 1];
		t->self_x[i] = t->self_x[i - 1];
		i--;
	}
	t->self_pa[i] = pa;
	t->self_x[i] = exec ? 1 : 0;
	t->nr_self++;
	return 0;
}

static int vtx_build_try(struct vtx_ept_build *b, u64 gpa, u64 size, int level)
{
	int mt;

	if (gpa & (size - 1) || gpa + size > b->limit)
		return 0;
	if (vtx_tables_special(b->tables, gpa, gpa + size))
		return 0;
	mt = vtx_mtrr_type(b->mtrr, gpa, size);
	if (mt < 0)
		return 0;
	if (vtx_ept_map(b->dmap, b->root_pa, gpa, level, gpa | EPT_RWX | ((u64)mt << EPT_MT_SHIFT), b->pool))
		return -1;
	b->leaves[level]++;
	return 1;
}

int vtx_ept_build(struct vtx_ept_build *b)
{
	u64 gpa = 0;

	b->root_pa = vtx_pool_get(b->pool, b->dmap);
	if (!b->root_pa)
		return VTX_E_NOMEM;
	b->leaves[0] = b->leaves[1] = b->leaves[2] = b->leaves[3] = 0;
	while (gpa < b->limit) {
		int r = 0, mt;
		u64 e;

		if (b->allow_1g) {
			r = vtx_build_try(b, gpa, VTX_1G, 3);
			if (r < 0)
				return VTX_E_NOMEM;
			if (r) {
				gpa += VTX_1G;
				continue;
			}
		}
		if (b->allow_2m) {
			r = vtx_build_try(b, gpa, VTX_2M, 2);
			if (r < 0)
				return VTX_E_NOMEM;
			if (r) {
				gpa += VTX_2M;
				continue;
			}
		}
		mt = vtx_mtrr_type(b->mtrr, gpa, VTX_PAGE_SIZE);
		if (mt < 0)
			mt = MT_UC;
		e = vtx_page_entry(b->tables, gpa, (u64)mt << EPT_MT_SHIFT);
		if (vtx_ept_map(b->dmap, b->root_pa, gpa, 1, e, b->pool))
			return VTX_E_NOMEM;
		b->leaves[1]++;
		gpa += VTX_PAGE_SIZE;
	}
	return 0;
}
