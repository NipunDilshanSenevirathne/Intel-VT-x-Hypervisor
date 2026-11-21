#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "../../kmod/ept.h"
#include "../../kmod/vtx_vmcs.h"

#define SIM (4u << 20)
#define LIMIT (4ull << 30)

static uint8_t *sim;
static uint64_t pool_pa[(SIM / 4096)];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct vtx_pool pool;
	struct vtx_mtrr m;
	struct vtx_tables t;
	struct vtx_ept_build b;
	uint64_t dmap;
	size_t i;
	uint32_t n;

	if (!sim && posix_memalign((void **)&sim, 4096, SIM))
		return 0;
	if (size < 8)
		return 0;
	dmap = (uint64_t)(uintptr_t)sim;
	for (n = 0; n < SIM / 4096; n++)
		pool_pa[n] = (uint64_t)(n + 1) * 4096;
	pool.pa = pool_pa;
	pool.total = 16 + data[0] % 240;
	pool.used = 0;
	memset(&m, 0, sizeof(m));
	m.enabled = data[1] & 1;
	m.fixed_enabled = (data[1] >> 1) & 1;
	m.def_type = (data[1] >> 2) & 1 ? 6 : 0;
	m.phys_mask = ((1ull << 36) - 1) & ~0xfffull;
	m.nvar = 2;
	m.base[0] = 0x6;
	m.mask[0] = (~((1ull << 31) - 1) & m.phys_mask) | (1ull << 11);
	m.base[1] = ((uint64_t)(data[2] % 16) << 28) | 0;
	m.mask[1] = (~((1ull << 28) - 1) & m.phys_mask) | (1ull << 11);
	memset(&t, 0, sizeof(t));
	t.sink_pa = 0x3ff000;
	t.exec_only = data[3] & 1;
	t.nr_owned = 1;
	t.owned[0].start = (uint64_t)(data[4] % 64) << 21;
	t.owned[0].end = t.owned[0].start + ((uint64_t)(1 + data[5] % 4) << 12);
	memset(&b, 0, sizeof(b));
	b.dmap = dmap;
	b.pool = &pool;
	b.mtrr = &m;
	b.tables = &t;
	b.limit = LIMIT;
	b.allow_1g = data[6] & 1;
	b.allow_2m = 1;
	memset(sim, 0, (pool.total + 1) * 4096ull);
	if (vtx_ept_build(&b))
		return 0;
	for (i = 8; i + 5 <= size; i += 5) {
		uint64_t gpa = ((uint64_t)data[i] | ((uint64_t)data[i + 1] << 8) | ((uint64_t)data[i + 2] << 16)) << 12;
		uint8_t op = data[i + 3], arg = data[i + 4];
		uint64_t *pte;
		int level, slot = arg % 8;

		gpa %= LIMIT;
		switch (op % 4) {
		case 0:
			if (!vtx_ept_split(dmap, b.root_pa, gpa, &pool, &pte)) {
				if ((*pte & EPT_ADDR_MASK) != gpa && (*pte >> EPT_TAG_SHIFT & 0xf) != EPT_TAG_SINK)
					abort();
				*pte = vtx_page_entry(&t, gpa, *pte);
			}
			break;
		case 1:
			pte = vtx_ept_lookup(dmap, b.root_pa, gpa, &level);
			if (!pte || level < 1 || level > 3)
				abort();
			break;
		case 2:
			t.watch[slot].used = !t.watch[slot].used;
			t.watch[slot].start = gpa;
			t.watch[slot].end = gpa + ((uint64_t)(1 + (arg >> 3)) << 12);
			t.watch[slot].deny = 1 + (arg % 7);
			t.watch[slot].mode = arg >> 7;
			break;
		default:
			vtx_tables_special(&t, gpa, gpa + ((uint64_t)arg << 12));
			break;
		}
	}
	return 0;
}
