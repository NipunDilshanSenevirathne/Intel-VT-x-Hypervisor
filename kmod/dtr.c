#include "dtr.h"
#include "vtx_vmcs.h"
#include "../include/uapi/vtxhv.h"

VTX_HOST void vtx_dtr_decode(u32 reason, u32 info, struct vtx_dtr_insn *d)
{
	u32 ident = (info >> 28) & 3;

	d->scale = info & 3;
	d->addr_size = (info >> 7) & 7;
	d->seg = (info >> 15) & 7;
	d->index = (info & (1u << 22)) ? -1 : (s32)((info >> 18) & 15);
	d->base = (info & (1u << 27)) ? -1 : (s32)((info >> 23) & 15);
	if (reason == EXIT_REASON_GDTR_IDTR) {
		d->op = ident;
		d->is_mem = 1;
		d->reg = 0;
	} else {
		d->op = VTX_DTR_SLDT + ident;
		d->is_mem = (info & (1u << 10)) ? 0 : 1;
		d->reg = (info >> 3) & 15;
	}
}

VTX_HOST u64 vtx_dtr_ea(const struct vtx_dtr_insn *d, const u64 gpr[16], u64 disp, u64 segbase, int long_mode)
{
	u64 ea = disp;

	if (d->base >= 0)
		ea += gpr[d->base];
	if (d->index >= 0)
		ea += gpr[d->index] << d->scale;
	if (d->addr_size == 0)
		ea &= 0xffff;
	else if (d->addr_size == 1)
		ea &= 0xffffffffull;
	if (long_mode) {
		if (d->seg == 4 || d->seg == 5)
			ea += segbase;
	} else {
		ea = (ea + segbase) & 0xffffffffull;
	}
	return ea;
}

VTX_HOST int vtx_gpr_slot(u32 reg)
{
	if (reg > 15)
		return -1;
	if (reg == 4)
		return -2;
	return reg < 4 ? (int)reg : (int)reg - 1;
}

VTX_HOST int vtx_insn_opsize16(const u8 *b, u32 len)
{
	u32 i;
	int p66 = 0, rexw = 0;

	for (i = 0; i < len; i++) {
		u8 c = b[i];

		if (c == 0x66) {
			p66 = 1;
			continue;
		}
		if (c == 0x67 || c == 0xf2 || c == 0xf3 || c == 0x2e || c == 0x36 ||
		    c == 0x3e || c == 0x26 || c == 0x64 || c == 0x65 || c == 0xf0)
			continue;
		if ((c & 0xf0) == 0x40) {
			rexw = (c & 8) != 0;
			continue;
		}
		break;
	}
	return p66 && !rexw;
}
