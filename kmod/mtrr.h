#ifndef VTX_MTRR_H
#define VTX_MTRR_H

#include "vtx_types.h"

#define VTX_MTRR_MAX_VAR	32
#define VTX_MTRR_FIXED		88
#define VTX_MTRR_1M		0x100000ull

struct vtx_mtrr {
	u32 enabled;
	u32 fixed_enabled;
	u32 def_type;
	u32 nvar;
	u64 phys_mask;
	u64 base[VTX_MTRR_MAX_VAR];
	u64 mask[VTX_MTRR_MAX_VAR];
	u8 fixed[VTX_MTRR_FIXED];
};

int vtx_mtrr_fixed_index(u64 addr);
int vtx_mtrr_combine(u32 seen_mask);
int vtx_mtrr_type(const struct vtx_mtrr *m, u64 base, u64 size);
void vtx_mtrr_set_fixed_msr(struct vtx_mtrr *m, int msr_index, u64 value);

#endif
