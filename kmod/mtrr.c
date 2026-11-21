#include "mtrr.h"
#include "vtx_vmcs.h"

VTX_HOST int vtx_mtrr_fixed_index(u64 addr)
{
	if (addr < 0x80000)
		return (int)(addr >> 16);
	if (addr < 0xc0000)
		return 8 + (int)((addr - 0x80000) >> 14);
	if (addr < VTX_MTRR_1M)
		return 24 + (int)((addr - 0xc0000) >> 12);
	return -1;
}

VTX_HOST int vtx_mtrr_combine(u32 seen)
{
	if (seen & (1u << MT_UC))
		return MT_UC;
	if ((seen & (seen - 1)) == 0) {
		int t = 0;

		while (!(seen & 1u)) {
			seen >>= 1;
			t++;
		}
		return t;
	}
	if ((seen & ~((1u << MT_WT) | (1u << MT_WB))) == 0)
		return MT_WT;
	return MT_UC;
}

VTX_HOST static int vtx_mtrr_fixed_uniform(const struct vtx_mtrr *m, u64 base, u64 size)
{
	u64 a;
	int t = -1;

	for (a = base; a < base + size; a += VTX_PAGE_SIZE) {
		int idx = vtx_mtrr_fixed_index(a);
		int ft;

		if (idx < 0)
			return -1;
		ft = m->fixed[idx];
		if (t < 0)
			t = ft;
		else if (t != ft)
			return -1;
	}
	return t;
}

VTX_HOST int vtx_mtrr_type(const struct vtx_mtrr *m, u64 base, u64 size)
{
	u32 seen = 0;
	u32 i;

	if (!size || (size & (size - 1)) || (base & (size - 1)))
		return -1;
	if (!m->enabled)
		return MT_UC;
	if (m->fixed_enabled && base < VTX_MTRR_1M) {
		if (base + size > VTX_MTRR_1M)
			return -1;
		return vtx_mtrr_fixed_uniform(m, base, size);
	}
	for (i = 0; i < m->nvar && i < VTX_MTRR_MAX_VAR; i++) {
		u64 mask, vbase, hi;

		if (!(m->mask[i] & (1ull << 11)))
			continue;
		mask = m->mask[i] & m->phys_mask;
		vbase = m->base[i] & m->phys_mask;
		hi = mask & ~(size - 1);
		if ((base & hi) != (vbase & hi))
			continue;
		if (mask & (size - 1))
			return -1;
		seen |= 1u << (m->base[i] & 0x7);
	}
	if (!seen)
		return (int)m->def_type;
	return vtx_mtrr_combine(seen);
}
