#include "ept.h"
#include "vtx_vmcs.h"

VTX_HOSTI void vtx_zero_page(void *p)
{
	u64 *q = p;
	int i;

	for (i = 0; i < 512; i++)
		WRITE_ONCE(q[i], 0);
}

VTX_HOSTI int vtx_ept_index(u64 gpa, int level)
{
	return (int)((gpa >> (12 + 9 * (level - 1))) & 511);
}

VTX_HOSTI int vtx_ept_present(u64 e)
{
	return (e & (EPT_RWX | EPT_SWVALID)) != 0 || (e & EPT_ADDR_MASK) != 0;
}

VTX_HOST u64 vtx_pool_get(struct vtx_pool *p, u64 dmap)
{
	u64 pa;

	if (p->used >= p->total)
		return 0;
	pa = p->pa[p->used++];
	vtx_zero_page(vtx_pa2va(dmap, pa));
	return pa;
}

VTX_HOST u64 *vtx_ept_lookup(u64 dmap, u64 root, u64 gpa, int *level)
{
	u64 *table = vtx_pa2va(dmap, root);
	int l;

	for (l = VTX_EPT_LEVELS; l >= 1; l--) {
		u64 *e = &table[vtx_ept_index(gpa, l)];
		u64 v = READ_ONCE(*e);

		if (!vtx_ept_present(v))
			return NULL;
		if (l == 1 || ((l == 2 || l == 3) && (v & EPT_LARGE))) {
			*level = l;
			return e;
		}
		table = vtx_pa2va(dmap, v & EPT_ADDR_MASK);
	}
	return NULL;
}

VTX_HOST int vtx_ept_map(u64 dmap, u64 root, u64 gpa, int level, u64 entry, struct vtx_pool *pool)
{
	u64 *table = vtx_pa2va(dmap, root);
	int l;

	if (level < 1 || level > 3)
		return VTX_E_INVAL;
	for (l = VTX_EPT_LEVELS; l > level; l--) {
		u64 *e = &table[vtx_ept_index(gpa, l)];
		u64 v = READ_ONCE(*e);

		if (!vtx_ept_present(v)) {
			u64 pa = vtx_pool_get(pool, dmap);

			if (!pa)
				return VTX_E_NOMEM;
			v = pa | EPT_RWX | EPT_SWVALID;
			WRITE_ONCE(*e, v);
		} else if (l <= 3 && (v & EPT_LARGE)) {
			return VTX_E_EXIST;
		}
		table = vtx_pa2va(dmap, v & EPT_ADDR_MASK);
	}
	if (level > 1)
		entry |= EPT_LARGE;
	else
		entry &= ~EPT_LARGE;
	WRITE_ONCE(table[vtx_ept_index(gpa, level)], entry | EPT_SWVALID);
	return 0;
}

VTX_HOST int vtx_ept_split(u64 dmap, u64 root, u64 gpa, struct vtx_pool *pool, u64 **pte)
{
	u64 *table = vtx_pa2va(dmap, root);
	int l;

	for (l = VTX_EPT_LEVELS; l >= 1; l--) {
		u64 *e = &table[vtx_ept_index(gpa, l)];
		u64 v = READ_ONCE(*e);

		if (!vtx_ept_present(v))
			return VTX_E_NOENT;
		if (l == 1) {
			*pte = e;
			return 0;
		}
		if ((l == 2 || l == 3) && (v & EPT_LARGE)) {
			u64 npa = vtx_pool_get(pool, dmap);
			u64 *nt, base, attr, step;
			int i;

			if (!npa)
				return VTX_E_NOMEM;
			nt = vtx_pa2va(dmap, npa);
			step = (l == 3) ? VTX_2M : VTX_PAGE_SIZE;
			base = v & EPT_ADDR_MASK & ~((step << 9) - 1);
			attr = v & ~EPT_ADDR_MASK;
			if (l == 2)
				attr &= ~EPT_LARGE;
			for (i = 0; i < 512; i++)
				WRITE_ONCE(nt[i], (base + (u64)i * step) | attr);
			asm volatile("" : : : "memory");
			WRITE_ONCE(*e, npa | EPT_RWX | EPT_SWVALID);
			v = npa | EPT_RWX | EPT_SWVALID;
		}
		table = vtx_pa2va(dmap, v & EPT_ADDR_MASK);
	}
	return VTX_E_NOENT;
}
