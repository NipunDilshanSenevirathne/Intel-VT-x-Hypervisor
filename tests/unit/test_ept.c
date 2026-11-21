#include "harness.h"
#include "../../kmod/ept.h"
#include "../../kmod/vtx_vmcs.h"
#include "../../include/uapi/vtxhv.h"

#define SIM_SIZE	(96ull << 20)
#define POOL_BASE	(8ull << 20)

static uint8_t *sim;
static uint64_t dmap;
static uint64_t pool_pa[16384];
static struct vtx_pool pool;
static struct vtx_mtrr mtrr;
static struct vtx_tables tables;

static void sim_reset(uint32_t pages)
{
	uint32_t i;

	memset(sim, 0, SIM_SIZE);
	for (i = 0; i < pages; i++)
		pool_pa[i] = POOL_BASE + (uint64_t)i * 4096;
	pool.pa = pool_pa;
	pool.total = pages;
	pool.used = 0;
}

static void mtrr_layout(void)
{
	memset(&mtrr, 0, sizeof(mtrr));
	mtrr.enabled = 1;
	mtrr.fixed_enabled = 1;
	mtrr.def_type = MT_UC;
	mtrr.phys_mask = ((1ull << 39) - 1) & ~0xfffull;
	memset(mtrr.fixed, MT_WB, sizeof(mtrr.fixed));
	memset(&mtrr.fixed[16], MT_UC, 8);
	mtrr.nvar = 3;
	mtrr.base[0] = 0 | MT_WB;
	mtrr.mask[0] = (~((1ull << 31) - 1) & mtrr.phys_mask) | (1ull << 11);
	mtrr.base[1] = 0x80000000ull | MT_WB;
	mtrr.mask[1] = (~((1ull << 30) - 1) & mtrr.phys_mask) | (1ull << 11);
	mtrr.base[2] = 0x100000000ull | MT_WB;
	mtrr.mask[2] = (~((1ull << 32) - 1) & mtrr.phys_mask) | (1ull << 11);
}

static void tables_layout(int exec_only)
{
	memset(&tables, 0, sizeof(tables));
	tables.sink_pa = 0x600000;
	tables.exec_only = (uint32_t)exec_only;
	tables.nr_owned = 1;
	tables.owned[0].start = 0x200000;
	tables.owned[0].end = 0x400000;
	vtx_self_insert(&tables, 0x501000, 0);
	vtx_self_insert(&tables, 0x500000, 1);
	vtx_self_insert(&tables, 0x9000000, 1);
}

static int build(uint64_t limit, int g1, int m2, struct vtx_ept_build *b)
{
	memset(b, 0, sizeof(*b));
	b->dmap = dmap;
	b->pool = &pool;
	b->mtrr = &mtrr;
	b->tables = &tables;
	b->limit = limit;
	b->allow_1g = (uint32_t)g1;
	b->allow_2m = (uint32_t)m2;
	return vtx_ept_build(b);
}

static uint64_t translate(uint64_t root, uint64_t gpa, uint64_t *entry, int *level)
{
	uint64_t *e = vtx_ept_lookup(dmap, root, gpa, level);
	uint64_t mask;

	if (!e)
		return ~0ull;
	*entry = *e;
	mask = *level == 3 ? (1ull << 30) - 1 : (*level == 2 ? (1ull << 21) - 1 : 0xfff);
	return (*e & EPT_ADDR_MASK & ~mask) + (gpa & mask);
}

static void verify_page(uint64_t root, uint64_t gpa)
{
	uint64_t e, hpa;
	int level, mt, tag;

	hpa = translate(root, gpa, &e, &level);
	CHECK(hpa != ~0ull);
	if (hpa == ~0ull)
		return;
	tag = (int)((e >> EPT_TAG_SHIFT) & 0xf);
	mt = (int)((e >> EPT_MT_SHIFT) & 7);
	CHECK_EQ(mt, vtx_mtrr_type(&mtrr, gpa & ~0xfffull, 4096));
	if (gpa >= 0x200000 && gpa < 0x400000) {
		CHECK_EQ(level, 1);
		CHECK_EQ(hpa & ~0xfffull, 0x600000);
		CHECK_EQ(e & EPT_RWX, EPT_R);
		CHECK_EQ(tag, EPT_TAG_SINK);
	} else if ((gpa & ~0xfffull) == 0x500000 || (gpa & ~0xfffull) == 0x9000000) {
		CHECK_EQ(level, 1);
		CHECK_EQ(hpa, gpa);
		CHECK_EQ(e & EPT_RWX, EPT_R | EPT_X);
		CHECK_EQ(tag, EPT_TAG_SELF);
	} else if ((gpa & ~0xfffull) == 0x501000) {
		CHECK_EQ(e & EPT_RWX, EPT_R);
		CHECK_EQ(tag, EPT_TAG_SELF);
	} else {
		CHECK_EQ(hpa, gpa);
		CHECK_EQ(e & EPT_RWX, EPT_RWX);
		CHECK_EQ(tag, EPT_TAG_NONE);
	}
}

static void test_build_identity(void)
{
	struct vtx_ept_build b;
	uint64_t seed = 42, gpa;
	int i, level;
	uint64_t e;

	sim_reset(4096);
	mtrr_layout();
	tables_layout(0);
	CHECK_EQ(build(8ull << 30, 1, 1, &b), 0);
	for (gpa = 0; gpa < (16ull << 20); gpa += 4096)
		verify_page(b.root_pa, gpa);
	for (i = 0; i < 20000; i++)
		verify_page(b.root_pa, t_rand64(&seed) % (8ull << 30));
	CHECK(b.leaves[3] >= 4);
	translate(b.root_pa, 0x140000000ull, &e, &level);
	CHECK_EQ(level, 3);
	translate(b.root_pa, 0xc0000000ull, &e, &level);
	CHECK_EQ(level, 3);
	translate(b.root_pa, 0x3000000ull, &e, &level);
	CHECK_EQ(level, 2);
	CHECK(vtx_ept_lookup(dmap, b.root_pa, 8ull << 30, &level) == NULL);
	printf("      pool pages %u, leaves 1G=%llu 2M=%llu 4K=%llu\n", pool.used,
	       (unsigned long long)b.leaves[3], (unsigned long long)b.leaves[2], (unsigned long long)b.leaves[1]);
}

static void test_build_no_1g(void)
{
	struct vtx_ept_build b;
	uint64_t seed = 7;
	int i, level;
	uint64_t e;

	sim_reset(8192);
	mtrr_layout();
	tables_layout(0);
	CHECK_EQ(build(4ull << 30, 0, 1, &b), 0);
	CHECK_EQ(b.leaves[3], 0);
	for (i = 0; i < 20000; i++) {
		uint64_t g = t_rand64(&seed) % (4ull << 30);

		verify_page(b.root_pa, g);
		translate(b.root_pa, g, &e, &level);
		CHECK(level <= 2);
	}
}

static void test_split_preserves(void)
{
	struct vtx_ept_build b;
	uint64_t *pte, gpa, e, seed = 99;
	int level, i;

	sim_reset(4096);
	mtrr_layout();
	tables_layout(0);
	CHECK_EQ(build(8ull << 30, 1, 1, &b), 0);
	translate(b.root_pa, 0x1c0000000ull, &e, &level);
	CHECK_EQ(level, 3);
	CHECK_EQ(vtx_ept_split(dmap, b.root_pa, 0x1c0123000ull, &pool, &pte), 0);
	CHECK_EQ(*pte & EPT_ADDR_MASK, 0x1c0123000ull);
	CHECK_EQ((*pte >> EPT_MT_SHIFT) & 7, MT_WB);
	for (gpa = 0x1c0000000ull; gpa < 0x200000000ull; gpa += 1ull << 21)
		verify_page(b.root_pa, gpa);
	for (i = 0; i < 5000; i++)
		verify_page(b.root_pa, 0x1c0000000ull + t_rand64(&seed) % (1ull << 30));
	translate(b.root_pa, 0x1c0123000ull, &e, &level);
	CHECK_EQ(level, 1);
	translate(b.root_pa, 0x1c0400000ull, &e, &level);
	CHECK_EQ(level, 2);
	CHECK_EQ(vtx_ept_split(dmap, b.root_pa, 0x1c0123000ull, &pool, &pte), 0);
	CHECK_EQ(vtx_ept_split(dmap, b.root_pa, 9ull << 30, &pool, &pte), VTX_E_NOENT);
}

static void test_pool_exhaustion(void)
{
	struct vtx_ept_build b;
	uint64_t *pte;

	sim_reset(3);
	mtrr_layout();
	tables_layout(0);
	CHECK_EQ(build(8ull << 30, 1, 1, &b), VTX_E_NOMEM);
	sim_reset(64);
	CHECK_EQ(build(8ull << 30, 1, 1, &b), 0);
	pool.total = pool.used;
	CHECK_EQ(vtx_ept_split(dmap, b.root_pa, 0x1c0000000ull, &pool, &pte), VTX_E_NOMEM);
	CHECK_EQ(vtx_ept_map(dmap, b.root_pa, 9ull << 30, 1, (9ull << 30) | EPT_RWX, &pool), VTX_E_NOMEM);
	CHECK_EQ(vtx_ept_map(dmap, b.root_pa, 0x1c0000000ull, 1, 0, &pool), VTX_E_EXIST);
	CHECK_EQ(vtx_ept_map(dmap, b.root_pa, 0, 4, 0, &pool), VTX_E_INVAL);
}

static void test_page_entry_semantics(void)
{
	uint64_t e;
	int s;

	tables_layout(0);
	s = 0;
	tables.watch[s].used = 1;
	tables.watch[s].id = 1;
	tables.watch[s].start = 0x800000;
	tables.watch[s].end = 0x802000;
	tables.watch[s].deny = VTX_DENY_W;
	e = vtx_page_entry(&tables, 0x800000, (uint64_t)MT_WB << EPT_MT_SHIFT);
	CHECK_EQ(e & EPT_RWX, EPT_R | EPT_X);
	CHECK_EQ((e >> EPT_TAG_SHIFT) & 0xf, EPT_TAG_WATCH);
	CHECK_EQ((e >> EPT_MT_SHIFT) & 7, MT_WB);
	tables.watch[1] = tables.watch[0];
	tables.watch[1].id = 2;
	tables.watch[1].deny = VTX_DENY_R;
	tables.watch[1].mode = 1;
	e = vtx_page_entry(&tables, 0x801000, 0);
	CHECK_EQ(e & EPT_RWX, 0);
	tables.exec_only = 1;
	e = vtx_page_entry(&tables, 0x801000, 0);
	CHECK_EQ(e & EPT_RWX, EPT_X);
	tables.watch[1].deny = VTX_DENY_X;
	e = vtx_page_entry(&tables, 0x801000, 0);
	CHECK_EQ(e & EPT_RWX, EPT_R);
	e = vtx_page_entry(&tables, 0x802000, 0);
	CHECK_EQ(e & EPT_RWX, EPT_RWX);
	CHECK_EQ((e >> EPT_TAG_SHIFT) & 0xf, EPT_TAG_NONE);
	e = vtx_page_entry(&tables, 0x2ff000, 0);
	CHECK_EQ(e & EPT_ADDR_MASK, 0x600000);
	{
		uint32_t mode;
		int slot;

		CHECK_EQ(vtx_watch_deny(&tables, 0x801000, &mode, &slot), VTX_DENY_W | VTX_DENY_X);
		CHECK_EQ(mode, 1);
		CHECK_EQ(slot, 0);
		CHECK_EQ(vtx_watch_deny(&tables, 0x900000, &mode, &slot), 0);
		CHECK_EQ(slot, -1);
	}
	CHECK(vtx_tables_special(&tables, 0x800000, 0x801000));
	CHECK(vtx_tables_special(&tables, 0x3ff000, 0x400000));
	CHECK(!vtx_tables_special(&tables, 0x400000, 0x500000));
	CHECK(vtx_tables_special(&tables, 0x400000, 0x501000));
	CHECK_EQ(vtx_owned_find(&tables, 0x3fffff), 0);
	CHECK_EQ(vtx_owned_find(&tables, 0x400000), -1);
}

static void apply(uint64_t root, uint64_t start, uint64_t end)
{
	uint64_t p, *pte;

	for (p = start; p < end; p += 4096) {
		int rc = vtx_ept_split(dmap, root, p, &pool, &pte);

		CHECK_EQ(rc, 0);
		if (!rc)
			*pte = vtx_page_entry(&tables, p, *pte);
	}
}

static void test_random_watch_churn(void)
{
	struct vtx_ept_build b;
	uint64_t seed = 0xfeedface, gpa;
	int iter, i;

	sim_reset(8192);
	mtrr_layout();
	tables_layout((int)(seed & 1));
	CHECK_EQ(build(8ull << 30, 1, 1, &b), 0);
	for (iter = 0; iter < 300; iter++) {
		int slot = (int)(t_rand64(&seed) % 16);
		struct vtx_watch *w = &tables.watch[slot];
		uint64_t start, end;

		if (w->used) {
			start = w->start;
			end = w->end;
			w->used = 0;
			apply(b.root_pa, start, end);
		} else {
			start = (0x700000 + (t_rand64(&seed) % 0x3000) * 4096) & ~0xfffull;
			end = start + (1 + t_rand64(&seed) % 64) * 4096;
			w->start = start;
			w->end = end;
			w->deny = (uint32_t)(1 + t_rand64(&seed) % 7);
			w->mode = (uint32_t)(t_rand64(&seed) & 1);
			w->id = (uint32_t)slot + 1;
			w->used = 1;
			apply(b.root_pa, start, end);
		}
		if (iter % 30 == 0) {
			for (gpa = 0x700000; gpa < 0x3800000; gpa += 4096) {
				uint64_t e, want;
				int level;

				translate(b.root_pa, gpa, &e, &level);
				want = vtx_page_entry(&tables, gpa, (uint64_t)vtx_mtrr_type(&mtrr, gpa, 4096) << EPT_MT_SHIFT);
				if (level == 1)
					CHECK_EQ(e & ~(1ull << 7), want & ~(1ull << 7));
				else
					CHECK(!vtx_tables_special(&tables, gpa, gpa + 4096) || (e & EPT_RWX) == (want & EPT_RWX));
			}
		}
	}
	for (i = 0; i < 16; i++)
		if (tables.watch[i].used) {
			tables.watch[i].used = 0;
			apply(b.root_pa, tables.watch[i].start, tables.watch[i].end);
		}
	for (gpa = 0x700000; gpa < 0x3800000; gpa += 4096)
		verify_page(b.root_pa, gpa);
	printf("      pool pages after churn %u\n", pool.used);
}

static void test_regression_page0_noaccess(void)
{
	struct vtx_ept_build b;
	uint64_t *pte;
	int level;

	sim_reset(64);
	memset(&mtrr, 0, sizeof(mtrr));
	mtrr.phys_mask = ((1ull << 39) - 1) & ~0xfffull;
	memset(&tables, 0, sizeof(tables));
	tables.sink_pa = 0x600000;
	CHECK_EQ(build(4ull << 30, 0, 1, &b), 0);
	tables.watch[0].used = 1;
	tables.watch[0].id = 1;
	tables.watch[0].start = 0;
	tables.watch[0].end = 4096;
	tables.watch[0].deny = VTX_DENY_R;
	apply(b.root_pa, 0, 4096);
	pte = vtx_ept_lookup(dmap, b.root_pa, 0, &level);
	CHECK(pte != NULL);
	if (pte) {
		CHECK_EQ(level, 1);
		CHECK_EQ(*pte & EPT_RWX, 0);
		CHECK_EQ((*pte >> EPT_TAG_SHIFT) & 0xf, EPT_TAG_WATCH);
	}
	CHECK_EQ(vtx_ept_map(dmap, b.root_pa, 0, 1, 0, &pool), 0);
	pte = vtx_ept_lookup(dmap, b.root_pa, 0, &level);
	CHECK(pte != NULL);
}

static void test_eptp(void)
{
	CHECK_EQ(vtx_eptp(0x1234000, 1), 0x1234000ull | (3 << 3) | MT_WB);
	CHECK_EQ(vtx_eptp(0x1234000, 0), 0x1234000ull | (3 << 3) | MT_UC);
}

static void test_self_insert_sorted(void)
{
	uint64_t seed = 5;
	int i;

	memset(&tables, 0, sizeof(tables));
	for (i = 0; i < 300; i++)
		CHECK_EQ(vtx_self_insert(&tables, (t_rand64(&seed) % 100000) << 12, i & 1), 0);
	for (i = 1; i < (int)tables.nr_self; i++)
		CHECK(tables.self_pa[i - 1] < tables.self_pa[i]);
	for (i = 0; i < (int)tables.nr_self; i++)
		CHECK_EQ(vtx_self_find(&tables, tables.self_pa[i] + 123), i);
	while (tables.nr_self < VTX_MAX_SELF)
		vtx_self_insert(&tables, (uint64_t)(200000 + tables.nr_self) << 12, 0);
	CHECK_EQ(vtx_self_insert(&tables, 0xfffff000ull, 0), VTX_E_NOSPC);
}

int t_checks, t_failures;
const char *t_current;

int main(void)
{
	if (posix_memalign((void **)&sim, 4096, SIM_SIZE))
		return 1;
	dmap = (uint64_t)(uintptr_t)sim;
	printf("ept engine\n");
	T_RUN(test_build_identity);
	T_RUN(test_build_no_1g);
	T_RUN(test_split_preserves);
	T_RUN(test_pool_exhaustion);
	T_RUN(test_page_entry_semantics);
	T_RUN(test_random_watch_churn);
	T_RUN(test_regression_page0_noaccess);
	T_RUN(test_eptp);
	T_RUN(test_self_insert_sorted);
	printf("  %d checks, %d failures\n", t_checks, t_failures);
	free(sim);
	return t_failures != 0;
}
