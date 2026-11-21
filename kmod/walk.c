#include "walk.h"
#include "vtx_vmcs.h"

VTX_HOST int vtx_phys_ok(const struct vtx_physmap *pm, u64 pa, u64 len)
{
	u32 i;
	u64 end = pa + len;

	if (!len || end < pa)
		return 0;
	for (i = 0; i < pm->nr_ram && i < VTX_MAX_RAM; i++) {
		if (pa >= pm->ram[i].start && end <= pm->ram[i].end)
			break;
	}
	if (i >= pm->nr_ram || i >= VTX_MAX_RAM)
		return 0;
	if (pm->tables) {
		u64 p;

		for (p = pa & VTX_PAGE_MASK; p < end; p += VTX_PAGE_SIZE)
			if (vtx_owned_find(pm->tables, p) >= 0)
				return 0;
	}
	return 1;
}

VTX_HOST int vtx_canonical(u64 va, int la57)
{
	int bits = la57 ? 57 : 48;
	s64 sv = (s64)(va << (64 - bits)) >> (64 - bits);

	return (u64)sv == va;
}

VTX_HOSTI u64 vtx_rd64(const struct vtx_physmap *pm, u64 pa)
{
	return READ_ONCE(*(u64 *)vtx_pa2va(pm->dmap, pa));
}

VTX_HOSTI void vtx_or64(const struct vtx_physmap *pm, u64 pa, u64 bits)
{
	u64 *p = vtx_pa2va(pm->dmap, pa);
	u64 v = READ_ONCE(*p);

	if ((v & bits) != bits) {
#ifdef __KERNEL__
		asm volatile("lock orq %1, %0" : "+m"(*p) : "r"(bits) : "memory", "cc");
#else
		__atomic_fetch_or(p, bits, __ATOMIC_SEQ_CST);
#endif
	}
}

VTX_HOSTI int vtx_ad_ok(const struct vtx_physmap *pm, u64 pa)
{
	return !pm->tables || vtx_write_policy(pm->tables, pa, NULL) < VTX_WP_DENY;
}

VTX_HOST int vtx_walk_gva(const struct vtx_physmap *pm, const struct vtx_walk *w, u64 gva, u32 access, u64 *gpa, u32 *pferr)
{
	u64 table = w->cr3 & PTE_ADDR_MASK;
	u64 rsvd_nx = w->nxe ? 0 : PTE_NX;
	int levels = w->la57 ? 5 : 4;
	int l;
	u32 err = 0;
	int writable = 1, user = 1, nx = 0;
	u64 entry = 0, entry_pa = 0, page_size = VTX_PAGE_SIZE, base;
	u64 apa[5];
	int an = 0;

	if (!vtx_canonical(gva, w->la57))
		return VTX_WALK_GP;
	if (access == VTX_ACC_WRITE)
		err |= VPF_W;
	if (w->user)
		err |= VPF_U;
	if (access == VTX_ACC_EXEC && (w->nxe || w->smep))
		err |= VPF_I;
	for (l = levels; l >= 1; l--) {
		int idx = (int)((gva >> (12 + 9 * (l - 1))) & 511);

		entry_pa = table + (u64)idx * 8;
		if (!vtx_phys_ok(pm, entry_pa, 8))
			return VTX_WALK_BADPHYS;
		entry = vtx_rd64(pm, entry_pa);
		if (!(entry & PTE_P)) {
			*pferr = err;
			return VTX_WALK_PF;
		}
		if (entry & rsvd_nx) {
			*pferr = err | VPF_P | VPF_RSVD;
			return VTX_WALK_PF;
		}
		if ((l == 5 || l == 4) && (entry & PTE_PS)) {
			*pferr = err | VPF_P | VPF_RSVD;
			return VTX_WALK_PF;
		}
		if (an < 5)
			apa[an++] = entry_pa;
		if (!(entry & PTE_W))
			writable = 0;
		if (!(entry & PTE_U))
			user = 0;
		if (entry & PTE_NX)
			nx = 1;
		if ((l == 3 || l == 2) && (entry & PTE_PS)) {
			page_size = (l == 3) ? VTX_1G : VTX_2M;
			break;
		}
		if (l == 1)
			break;
		table = entry & PTE_ADDR_MASK;
	}
	if (page_size == VTX_PAGE_SIZE)
		base = entry & PTE_ADDR_MASK;
	else
		base = entry & PTE_ADDR_MASK & ~(page_size - 1);
	if (w->user) {
		if (!user)
			goto prot;
		if (access == VTX_ACC_WRITE && !writable)
			goto prot;
	} else {
		if (access == VTX_ACC_WRITE && !writable && w->wp)
			goto prot;
		if (user && access != VTX_ACC_EXEC && w->smap && (w->implicit || !w->ac))
			goto prot;
		if (user && access == VTX_ACC_EXEC && w->smep)
			goto prot;
	}
	if (access == VTX_ACC_EXEC && nx && w->nxe)
		goto prot;
	*gpa = base + (gva & (page_size - 1));
	if (w->set_ad) {
		int i;

		for (i = 0; i < an; i++)
			if (vtx_ad_ok(pm, apa[i]))
				vtx_or64(pm, apa[i], PTE_A);
		if (access == VTX_ACC_WRITE && an && vtx_ad_ok(pm, apa[an - 1]))
			vtx_or64(pm, apa[an - 1], PTE_D);
	}
	return VTX_WALK_OK;
prot:
	*pferr = err | VPF_P;
	return VTX_WALK_PF;
}

VTX_HOST int vtx_guest_copy_ex(const struct vtx_physmap *pm, const struct vtx_walk *w, u64 gva, void *buf, u32 len, int write,
			      u32 *pferr, u64 *fault_va, struct vtx_copy_res *res)
{
	u8 *b = buf;
	u64 gpa[2], gla[2];
	u32 clen[2];
	int pol[2] = { VTX_WP_OPEN, VTX_WP_OPEN };
	int slot[2] = { -1, -1 };
	int n = 0, i;
	u64 va = gva;
	u32 left = len;

	if (res) {
		res->n = 0;
		res->denied = 0;
	}
	if (!len || len > VTX_PAGE_SIZE)
		return VTX_WALK_GP;
	while (left) {
		u32 chunk = (u32)(VTX_PAGE_SIZE - (va & (VTX_PAGE_SIZE - 1)));
		int r;

		if (chunk > left)
			chunk = left;
		if (n >= 2)
			return VTX_WALK_GP;
		r = vtx_walk_gva(pm, w, va, write ? VTX_ACC_WRITE : VTX_ACC_READ, &gpa[n], pferr);
		if (r) {
			*fault_va = va;
			return r;
		}
		if (!vtx_phys_ok(pm, gpa[n], chunk))
			return VTX_WALK_BADPHYS;
		if (write && pm->tables)
			pol[n] = vtx_write_policy(pm->tables, gpa[n], &slot[n]);
		gla[n] = va;
		clen[n++] = chunk;
		va += chunk;
		left -= chunk;
	}
	for (i = 0; i < n; i++) {
		u8 *p = vtx_pa2va(pm->dmap, gpa[i]);
		u32 k;

		if (!write || pol[i] < VTX_WP_DENY) {
			for (k = 0; k < clen[i]; k++) {
				if (write)
					WRITE_ONCE(p[k], b[k]);
				else
					b[k] = READ_ONCE(p[k]);
			}
		}
		b += clen[i];
	}
	if (res) {
		res->n = (u32)n;
		for (i = 0; i < n; i++) {
			res->gpa[i] = gpa[i];
			res->gla[i] = gla[i];
			res->len[i] = clen[i];
			res->pol[i] = pol[i];
			res->slot[i] = slot[i];
			if (pol[i] >= VTX_WP_DENY)
				res->denied++;
		}
	}
	return VTX_WALK_OK;
}

VTX_HOST int vtx_guest_copy(const struct vtx_physmap *pm, const struct vtx_walk *w, u64 gva, void *buf, u32 len, int write, u32 *pferr, u64 *fault_va)
{
	return vtx_guest_copy_ex(pm, w, gva, buf, len, write, pferr, fault_va, NULL);
}
