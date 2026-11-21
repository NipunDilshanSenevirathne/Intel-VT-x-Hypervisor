#ifndef VTX_POLICY_H
#define VTX_POLICY_H

#include "vtx_types.h"

#define VTX_MAX_OWNED		64
#define VTX_MAX_SELF		512
#define VTX_MAX_WSLOTS		128
#define VTX_WNAME		32

#define VTX_WP_OPEN		0
#define VTX_WP_WATCH		1
#define VTX_WP_DENY		2
#define VTX_WP_SELF		3

struct vtx_watch {
	u32 used;
	u32 id;
	u32 deny;
	u32 mode;
	u64 start;
	u64 end;
	u64 hits;
	char name[VTX_WNAME];
};

struct vtx_pool {
	u64 *pa;
	u32 total;
	u32 used;
};

struct vtx_tables {
	u64 sink_pa;
	u32 exec_only;
	u32 nr_owned;
	struct vtx_range owned[VTX_MAX_OWNED];
	u32 nr_self;
	u32 pad;
	u64 self_pa[VTX_MAX_SELF];
	u8 self_x[VTX_MAX_SELF];
	struct vtx_watch watch[VTX_MAX_WSLOTS];
};

int vtx_owned_find(const struct vtx_tables *t, u64 pa);
int vtx_self_find(const struct vtx_tables *t, u64 pa);
int vtx_tables_special(const struct vtx_tables *t, u64 start, u64 end);
u64 vtx_page_entry(const struct vtx_tables *t, u64 gpa, u64 attr);
u32 vtx_watch_deny(const struct vtx_tables *t, u64 gpa, u32 *mode, int *slot);
int vtx_write_policy(const struct vtx_tables *t, u64 gpa, int *slot);
int vtx_self_insert(struct vtx_tables *t, u64 pa, int exec);

#endif
