#ifndef VTX_DRV_H
#define VTX_DRV_H

#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/mutex.h>
#include "vtx.h"
#include "ctl.h"

#define VTX_MAX_CHUNKS		64

struct vtx_chunk {
	struct page *page;
	u32 order;
	u64 pa;
	void *va;
	u64 used;
};

struct vtx_drv {
	struct vtx_global *g;
	u64 caps[VTX_CAP_COUNT];
	u32 caps_valid;
	struct vtx_mtrr mtrr;
	struct vtx_chunk chunk[VTX_MAX_CHUNKS];
	u32 nchunks;
	u64 arena_bytes;
	u32 pin;
	u32 proc;
	u32 proc2;
	u32 exitc;
	u32 entryc;
	u32 revision;
	u32 vnmi;
	u32 gbpages;
	u32 maxphy;
	u32 unloading;
	u64 ktext_start;
	u64 ktext_end;
	u64 krodata_start;
	u64 krodata_end;
	u64 ram_end;
	int hp_state;
	u32 locked;
	u32 ready;
	cpumask_t virt;
	struct mutex lock;
	u64 host_root_pa;
	u64 *host_root;
	u32 host_pt_pages;
	u32 ept_pages;
	u32 features;
	u32 pool_total;
};

extern struct vtx_drv vtx_d;

int vtx_probe(struct vtx_drv *d, u32 dtexit);
int vtx_alloc_all(struct vtx_drv *d, u32 pool_pages, u32 ring_events);
void vtx_free_all(struct vtx_drv *d);
int vtx_cpu_launch(struct vtx_drv *d, unsigned int cpu);
int vtx_cpu_devirt(struct vtx_drv *d, unsigned int cpu);
u64 vtx_vmcall(u64 fn, u64 *b, u64 *c, u64 *dx, u64 *si, u64 *di);
const char *vtx_launch_err(u64 rc);

#endif
