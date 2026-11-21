#include "ctl.h"

u32 vtx_ctl_adjust(u64 cap, u32 want)
{
	u32 must = (u32)cap;
	u32 may = (u32)(cap >> 32);

	return (want | must) & may;
}

int vtx_ctl_allowed(u64 cap, u32 bits)
{
	return (bits & (u32)(cap >> 32)) == bits;
}

u32 vtx_ctl_forced(u64 cap)
{
	return (u32)cap;
}

int vtx_cr_fixed_ok(u64 value, u64 fixed0, u64 fixed1)
{
	return (value & fixed0) == fixed0 && (value & ~fixed1) == 0;
}

u64 vtx_cr_apply_fixed(u64 value, u64 fixed0, u64 fixed1)
{
	return (value | fixed0) & fixed1;
}
