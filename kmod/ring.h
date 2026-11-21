#ifndef VTX_RING_H
#define VTX_RING_H

#include "vtx_types.h"
#include "../include/uapi/vtxhv.h"

struct vtx_ring {
	u64 head;
	u64 pad0[7];
	u64 tail;
	u64 pad1[7];
	u32 size;
	u32 lock;
	u64 dropped;
	u64 pushed;
	u64 pad2[5];
	struct vtx_event ev[];
};

u64 vtx_ring_bytes(u32 size);
void vtx_ring_init(struct vtx_ring *r, u32 size);
int vtx_ring_push(struct vtx_ring *r, const struct vtx_event *e);
u32 vtx_ring_pop(struct vtx_ring *r, struct vtx_event *out, u32 max);
u32 vtx_ring_count(const struct vtx_ring *r);

#endif
