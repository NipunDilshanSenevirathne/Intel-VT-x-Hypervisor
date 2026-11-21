#ifndef VTX_CTL_H
#define VTX_CTL_H

#include "vtx_types.h"

u32 vtx_ctl_adjust(u64 cap, u32 want);
int vtx_ctl_allowed(u64 cap, u32 bits);
u32 vtx_ctl_forced(u64 cap);
int vtx_cr_fixed_ok(u64 value, u64 fixed0, u64 fixed1);
u64 vtx_cr_apply_fixed(u64 value, u64 fixed0, u64 fixed1);

#endif
