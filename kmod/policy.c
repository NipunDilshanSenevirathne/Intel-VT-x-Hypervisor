#include "policy.h"
#include "vtx_vmcs.h"

VTX_HOST int vtx_owned_find(const struct vtx_tables *t, u64 pa)
{
	u32 i;

	for (i = 0; i < t->nr_owned && i < VTX_MAX_OWNED; i++)
		if (pa >= t->owned[i].start && pa < t->owned[i].end)
			return (int)i;
	return -1;
}

VTX_HOST int vtx_self_find(const struct vtx_tables *t, u64 pa)
{
	int lo = 0, hi = (int)t->nr_self - 1;

	pa &= VTX_PAGE_MASK;
	if (hi >= VTX_MAX_SELF)
		hi = VTX_MAX_SELF - 1;
	while (lo <= hi) {
		int mid = lo + ((hi - lo) >> 1);

		if (t->self_pa[mid] == pa)
			return mid;
		if (t->self_pa[mid] < pa)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return -1;
}

VTX_HOST int vtx_tables_special(const struct vtx_tables *t, u64 start, u64 end)
{
	u32 i;
	int lo, hi;

	for (i = 0; i < t->nr_owned && i < VTX_MAX_OWNED; i++)
		if (vtx_range_overlap(start, end, t->owned[i].start, t->owned[i].end))
			return 1;
	lo = 0;
	hi = (int)t->nr_self - 1;
	if (hi >= VTX_MAX_SELF)
		hi = VTX_MAX_SELF - 1;
	while (lo <= hi) {
		int mid = lo + ((hi - lo) >> 1);
		u64 p = t->self_pa[mid];

		if (p >= start && p < end)
			return 1;
		if (p < start)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	for (i = 0; i < VTX_MAX_WSLOTS; i++) {
		const struct vtx_watch *w = &t->watch[i];

		if (w->used && vtx_range_overlap(start, end, w->start, w->end))
			return 1;
	}
	return 0;
}

VTX_HOST u32 vtx_watch_deny(const struct vtx_tables *t, u64 gpa, u32 *mode, int *slot)
{
	u32 deny = 0, i;
	int first = -1;

	*mode = 0;
	for (i = 0; i < VTX_MAX_WSLOTS; i++) {
		const struct vtx_watch *w = &t->watch[i];

		if (!w->used || gpa < w->start || gpa >= w->end)
			continue;
		deny |= w->deny;
		if (w->mode)
			*mode = 1;
		if (first < 0)
			first = (int)i;
	}
	if (slot)
		*slot = first;
	return deny;
}

VTX_HOST int vtx_write_policy(const struct vtx_tables *t, u64 gpa, int *slot)
{
	u32 mode, deny;
	int s = -1;

	gpa &= VTX_PAGE_MASK;
	if (slot)
		*slot = -1;
	if (vtx_owned_find(t, gpa) >= 0 || vtx_self_find(t, gpa) >= 0)
		return VTX_WP_SELF;
	deny = vtx_watch_deny(t, gpa, &mode, &s);
	if (slot)
		*slot = s;
	if (!(deny & 3))
		return VTX_WP_OPEN;
	return (mode && (deny & 2)) ? VTX_WP_DENY : VTX_WP_WATCH;
}

VTX_HOST u64 vtx_page_entry(const struct vtx_tables *t, u64 gpa, u64 attr)
{
	u64 perms = EPT_RWX, tag = EPT_TAG_NONE;
	u32 mode, deny;
	int s, slot;

	gpa &= VTX_PAGE_MASK;
	attr &= EPT_MT_MASK | EPT_IPAT;
	if (vtx_owned_find(t, gpa) >= 0)
		return t->sink_pa | EPT_R | EPT_SWVALID | attr | ((u64)EPT_TAG_SINK << EPT_TAG_SHIFT);
	s = vtx_self_find(t, gpa);
	if (s >= 0) {
		perms = EPT_R | (t->self_x[s] ? EPT_X : 0);
		return gpa | perms | EPT_SWVALID | attr | ((u64)EPT_TAG_SELF << EPT_TAG_SHIFT);
	}
	deny = vtx_watch_deny(t, gpa, &mode, &slot);
	if (slot >= 0) {
		if (deny & 1)
			perms &= ~EPT_R;
		if (deny & 2)
			perms &= ~EPT_W;
		if (deny & 4)
			perms &= ~EPT_X;
		tag = EPT_TAG_WATCH;
	}
	if (!(perms & EPT_R)) {
		perms &= ~EPT_W;
		if (!t->exec_only)
			perms &= ~EPT_X;
	}
	return gpa | perms | EPT_SWVALID | attr | (tag << EPT_TAG_SHIFT);
}
