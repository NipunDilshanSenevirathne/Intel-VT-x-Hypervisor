#ifndef VTX_WALK_H
#define VTX_WALK_H

#include "vtx_types.h"
#include "policy.h"

#define VTX_ACC_READ		0
#define VTX_ACC_WRITE		1
#define VTX_ACC_EXEC		2

#define VTX_WALK_OK		0
#define VTX_WALK_PF		1
#define VTX_WALK_GP		2
#define VTX_WALK_BADPHYS	3

#define VTX_MAX_RAM		128

struct vtx_physmap {
	u64 dmap;
	u32 nr_ram;
	u32 pad;
	struct vtx_range ram[VTX_MAX_RAM];
	const struct vtx_tables *tables;
};

struct vtx_walk {
	u64 cr3;
	u32 la57;
	u32 nxe;
	u32 wp;
	u32 smep;
	u32 smap;
	u32 ac;
	u32 user;
	u32 implicit;
	u32 set_ad;
	u32 pad;
};

struct vtx_copy_res {
	u32 n;
	u32 denied;
	u64 gpa[2];
	u64 gla[2];
	u32 len[2];
	int pol[2];
	int slot[2];
};

int vtx_phys_ok(const struct vtx_physmap *pm, u64 pa, u64 len);
int vtx_canonical(u64 va, int la57);
int vtx_walk_gva(const struct vtx_physmap *pm, const struct vtx_walk *w, u64 gva, u32 access, u64 *gpa, u32 *pferr);
int vtx_guest_copy(const struct vtx_physmap *pm, const struct vtx_walk *w, u64 gva, void *buf, u32 len, int write, u32 *pferr, u64 *fault_va);
int vtx_guest_copy_ex(const struct vtx_physmap *pm, const struct vtx_walk *w, u64 gva, void *buf, u32 len, int write,
		      u32 *pferr, u64 *fault_va, struct vtx_copy_res *res);

#endif
