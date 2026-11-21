#ifndef VTX_DTR_H
#define VTX_DTR_H

#include "vtx_types.h"

struct vtx_dtr_insn {
	u32 op;
	u32 is_mem;
	u32 reg;
	u32 addr_size;
	u32 seg;
	s32 base;
	s32 index;
	u32 scale;
};

void vtx_dtr_decode(u32 reason, u32 info, struct vtx_dtr_insn *d);
u64 vtx_dtr_ea(const struct vtx_dtr_insn *d, const u64 gpr[16], u64 disp, u64 segbase, int long_mode);
int vtx_gpr_slot(u32 reg);
int vtx_insn_opsize16(const u8 *bytes, u32 len);

#endif
