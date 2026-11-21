#ifndef VTX_EPT_H
#define VTX_EPT_H

#include "vtx_types.h"
#include "policy.h"
#include "mtrr.h"

#define VTX_EPT_LEVELS		4

struct vtx_ept_build {
	u64 dmap;
	struct vtx_pool *pool;
	const struct vtx_mtrr *mtrr;
	const struct vtx_tables *tables;
	u64 limit;
	u32 allow_1g;
	u32 allow_2m;
	u64 root_pa;
	u64 leaves[4];
};

u64 vtx_pool_get(struct vtx_pool *p, u64 dmap);
u64 *vtx_ept_lookup(u64 dmap, u64 root, u64 gpa, int *level);
int vtx_ept_map(u64 dmap, u64 root, u64 gpa, int level, u64 entry, struct vtx_pool *pool);
int vtx_ept_split(u64 dmap, u64 root, u64 gpa, struct vtx_pool *pool, u64 **pte);
int vtx_ept_build(struct vtx_ept_build *b);
int vtx_self_insert(struct vtx_tables *t, u64 pa, int exec);
u64 vtx_eptp(u64 root_pa, int wb);

#endif
