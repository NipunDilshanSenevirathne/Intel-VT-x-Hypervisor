#include "ring.h"

#define vtx_barrier()	asm volatile("" : : : "memory")

VTX_HOST int vtx_ring_push(struct vtx_ring *r, const struct vtx_event *e)
{
	u64 head = r->head;
	u64 tail = READ_ONCE(r->tail);
	struct vtx_event *slot;
	const u64 *s;
	u64 *d;
	u32 i;

	if (!r->size || head - tail >= r->size) {
		r->dropped++;
		return -1;
	}
	slot = &r->ev[head & (r->size - 1)];
	s = (const u64 *)e;
	d = (u64 *)slot;
	for (i = 0; i < sizeof(*e) / 8; i++)
		WRITE_ONCE(d[i], s[i]);
	vtx_barrier();
	WRITE_ONCE(r->head, head + 1);
	r->pushed++;
	return 0;
}

VTX_HOST u32 vtx_ring_pop(struct vtx_ring *r, struct vtx_event *out, u32 max)
{
	u64 tail = r->tail;
	u64 head = READ_ONCE(r->head);
	u32 n = 0;

	vtx_barrier();
	while (tail != head && n < max) {
		const u64 *s = (const u64 *)&r->ev[tail & (r->size - 1)];
		u64 *d = (u64 *)&out[n];
		u32 i;

		for (i = 0; i < sizeof(*out) / 8; i++)
			d[i] = READ_ONCE(s[i]);
		tail++;
		n++;
	}
	vtx_barrier();
	WRITE_ONCE(r->tail, tail);
	return n;
}

VTX_HOST u32 vtx_ring_count(const struct vtx_ring *r)
{
	return (u32)(READ_ONCE(r->head) - READ_ONCE(r->tail));
}
