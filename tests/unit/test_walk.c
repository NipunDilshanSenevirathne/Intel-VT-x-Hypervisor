#include "harness.h"
#include "../../kmod/walk.h"
#include "../../kmod/vtx_vmcs.h"
#include "../../include/uapi/vtxhv.h"

#define SIM_SIZE	(64ull << 20)

static uint8_t *sim;
static struct vtx_physmap pm;
static struct vtx_tables tables;
static uint64_t bump;

static uint64_t *pt(uint64_t pa)
{
	return (uint64_t *)(sim + pa);
}

static uint64_t alloc_table(void)
{
	uint64_t pa = bump;

	bump += 4096;
	memset(sim + pa, 0, 4096);
	return pa;
}

static void reset(void)
{
	memset(&pm, 0, sizeof(pm));
	memset(&tables, 0, sizeof(tables));
	pm.dmap = (uint64_t)(uintptr_t)sim;
	pm.nr_ram = 1;
	pm.ram[0].start = 0;
	pm.ram[0].end = SIM_SIZE;
	pm.tables = &tables;
	bump = 0x100000;
}

static uint64_t map(uint64_t root, int levels, uint64_t va, uint64_t pa, int leaf_level, const uint64_t *flags)
{
	uint64_t table = root;
	int l;

	for (l = levels; l > leaf_level; l--) {
		uint64_t *e = &pt(table)[(va >> (12 + 9 * (l - 1))) & 511];

		if (!(*e & PTE_P))
			*e = alloc_table() | PTE_P;
		*e = (*e & PTE_ADDR_MASK) | flags[l];
		table = *e & PTE_ADDR_MASK;
	}
	pt(table)[(va >> (12 + 9 * (leaf_level - 1))) & 511] = pa | flags[leaf_level] | (leaf_level > 1 ? PTE_PS : 0);
	return pa;
}

struct ref_ctx {
	int user_mode;
	int wp, smep, smap, ac, nxe;
};

static int ref_check(const uint64_t *flags, int levels, int leaf, int access, const struct ref_ctx *c, uint32_t *err)
{
	int l, w = 1, u = 1, nx = 0;
	uint32_t e = 0;

	if (access == VTX_ACC_WRITE)
		e |= VPF_W;
	if (c->user_mode)
		e |= VPF_U;
	if (access == VTX_ACC_EXEC && (c->nxe || c->smep))
		e |= VPF_I;
	for (l = levels; l >= leaf; l--) {
		if (!(flags[l] & PTE_P)) {
			*err = e;
			return VTX_WALK_PF;
		}
		if ((flags[l] & PTE_NX) && !c->nxe) {
			*err = e | VPF_P | VPF_RSVD;
			return VTX_WALK_PF;
		}
		w &= (flags[l] & PTE_W) != 0;
		u &= (flags[l] & PTE_U) != 0;
		nx |= (flags[l] & PTE_NX) != 0;
	}
	e |= VPF_P;
	if (c->user_mode) {
		if (!u || (access == VTX_ACC_WRITE && !w) || (access == VTX_ACC_EXEC && nx && c->nxe)) {
			*err = e;
			return VTX_WALK_PF;
		}
		return VTX_WALK_OK;
	}
	if (access == VTX_ACC_EXEC) {
		if ((u && c->smep) || (nx && c->nxe)) {
			*err = e;
			return VTX_WALK_PF;
		}
		return VTX_WALK_OK;
	}
	if (u && c->smap && !c->ac) {
		*err = e;
		return VTX_WALK_PF;
	}
	if (access == VTX_ACC_WRITE && !w && c->wp) {
		*err = e;
		return VTX_WALK_PF;
	}
	return VTX_WALK_OK;
}

static void test_permission_matrix(void)
{
	uint64_t va = 0x00007f1234567000ull;
	int combo, ctxbits, access, mismatches = 0;

	for (combo = 0; combo < (1 << 12); combo++) {
		uint64_t flags[6] = { 0 };
		uint64_t root;
		int l;

		reset();
		root = alloc_table();
		for (l = 1; l <= 4; l++) {
			int bits = (combo >> ((l - 1) * 3)) & 7;

			flags[l] = PTE_P | ((bits & 1) ? PTE_W : 0) | ((bits & 2) ? PTE_U : 0) | ((bits & 4) ? PTE_NX : 0);
		}
		map(root, 4, va, 0x2345000, 1, flags);
		for (ctxbits = 0; ctxbits < 64; ctxbits++) {
			struct ref_ctx rc = {
				.user_mode = ctxbits & 1, .wp = (ctxbits >> 1) & 1, .smep = (ctxbits >> 2) & 1,
				.smap = (ctxbits >> 3) & 1, .ac = (ctxbits >> 4) & 1, .nxe = (ctxbits >> 5) & 1,
			};
			struct vtx_walk w = {
				.cr3 = root, .la57 = 0, .nxe = (uint32_t)rc.nxe, .wp = (uint32_t)rc.wp,
				.smep = (uint32_t)rc.smep, .smap = (uint32_t)rc.smap, .ac = (uint32_t)rc.ac,
				.user = (uint32_t)rc.user_mode,
			};

			for (access = 0; access < 3; access++) {
				uint32_t e1 = 0, e2 = 0;
				uint64_t gpa = 0;
				int r1 = vtx_walk_gva(&pm, &w, va + 0x123, (uint32_t)access, &gpa, &e1);
				int r2 = ref_check(flags, 4, 1, access, &rc, &e2);

				t_checks++;
				if (r1 != r2 || (r1 == VTX_WALK_PF && e1 != e2) || (r1 == VTX_WALK_OK && gpa != 0x2345123)) {
					if (mismatches++ < 5)
						fprintf(stderr, "  mismatch combo=%#x ctx=%#x acc=%d got=%d/%#x want=%d/%#x\n",
							combo, ctxbits, access, r1, e1, r2, e2);
					t_failures++;
				}
			}
		}
	}
}

static void test_large_pages_and_la57(void)
{
	uint64_t flags[6] = { 0, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W };
	struct vtx_walk w = { .wp = 1, .nxe = 1 };
	uint64_t gpa = 0, root;
	uint32_t err = 0;

	reset();
	root = alloc_table();
	map(root, 4, 0xffff888000000000ull, 0x40000000ull, 3, flags);
	map(root, 4, 0xffff888040000000ull, 0x00200000ull, 2, flags);
	w.cr3 = root | 0x5;
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0xffff888012345678ull, VTX_ACC_READ, &gpa, &err), VTX_WALK_OK);
	CHECK_EQ(gpa, 0x52345678ull);
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0xffff8880401abcdeull, VTX_ACC_WRITE, &gpa, &err), VTX_WALK_OK);
	CHECK_EQ(gpa, 0x3abcdeull);
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0xffff888080000000ull, VTX_ACC_READ, &gpa, &err), VTX_WALK_PF);
	CHECK_EQ(err, 0);
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0x0000800000000000ull, VTX_ACC_READ, &gpa, &err), VTX_WALK_GP);
	pt(root)[0] = 0x1000 | PTE_P | PTE_PS;
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0x1000, VTX_ACC_READ, &gpa, &err), VTX_WALK_PF);
	CHECK(err & VPF_RSVD);
	reset();
	root = alloc_table();
	map(root, 5, 0xff11223344556000ull, 0x777000, 1, flags);
	w.cr3 = root;
	w.la57 = 1;
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0xff11223344556abcull, VTX_ACC_READ, &gpa, &err), VTX_WALK_OK);
	CHECK_EQ(gpa, 0x777abcull);
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0xfe11223344556abcull, VTX_ACC_READ, &gpa, &err), VTX_WALK_GP);
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0xff01223344556abcull, VTX_ACC_READ, &gpa, &err), VTX_WALK_PF);
	CHECK(vtx_canonical(0xff11223344556abcull, 1));
	CHECK(!vtx_canonical(0xff11223344556abcull, 0));
	CHECK(vtx_canonical(0x00007fffffffffffull, 0));
	CHECK(!vtx_canonical(0x0000800000000000ull, 0));
	CHECK(vtx_canonical(0xffff800000000000ull, 0));
}

static void test_bad_physical(void)
{
	uint64_t flags[6] = { 0, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W, 0 };
	struct vtx_walk w = { .wp = 1 };
	uint64_t gpa, root;
	uint32_t err;

	reset();
	root = alloc_table();
	map(root, 4, 0x400000, 0x123000, 1, flags);
	w.cr3 = root;
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0x400000, VTX_ACC_READ, &gpa, &err), VTX_WALK_OK);
	pt(root)[0] = (SIM_SIZE + 0x1000) | PTE_P | PTE_W;
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0x400000, VTX_ACC_READ, &gpa, &err), VTX_WALK_BADPHYS);
	w.cr3 = SIM_SIZE * 2;
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0x400000, VTX_ACC_READ, &gpa, &err), VTX_WALK_BADPHYS);
	reset();
	root = alloc_table();
	map(root, 4, 0x400000, 0x123000, 1, flags);
	w.cr3 = root;
	tables.nr_owned = 1;
	tables.owned[0].start = root;
	tables.owned[0].end = root + 4096;
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0x400000, VTX_ACC_READ, &gpa, &err), VTX_WALK_BADPHYS);
	CHECK(!vtx_phys_ok(&pm, root + 8, 8));
	CHECK(vtx_phys_ok(&pm, root + 4096, 8));
	CHECK(!vtx_phys_ok(&pm, SIM_SIZE - 4, 8));
	CHECK(!vtx_phys_ok(&pm, 0, 0));
	CHECK(!vtx_phys_ok(&pm, ~0ull - 3, 8));
}

static void test_ad_bits(void)
{
	uint64_t flags[6] = { 0, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W, 0 };
	struct vtx_walk w = { .wp = 1, .set_ad = 1 };
	uint64_t gpa, root, *l4, *l3, *l2, *l1;
	uint32_t err;

	reset();
	root = alloc_table();
	map(root, 4, 0x400000, 0x123000, 1, flags);
	w.cr3 = root;
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0x400000, VTX_ACC_READ, &gpa, &err), VTX_WALK_OK);
	l4 = &pt(root)[0];
	l3 = &pt(*l4 & PTE_ADDR_MASK)[0];
	l2 = &pt(*l3 & PTE_ADDR_MASK)[2];
	l1 = &pt(*l2 & PTE_ADDR_MASK)[0];
	CHECK(*l4 & PTE_A);
	CHECK(*l1 & PTE_A);
	CHECK(!(*l1 & PTE_D));
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0x400000, VTX_ACC_WRITE, &gpa, &err), VTX_WALK_OK);
	CHECK(*l1 & PTE_D);
	CHECK(!(*l2 & PTE_D));
}

static void test_guest_copy_atomicity(void)
{
	uint64_t flags[6] = { 0, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W, 0 };
	struct vtx_walk w = { .wp = 1 };
	uint8_t data[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, back[10];
	uint64_t root, fva = 0;
	uint32_t err = 0;
	int i;

	reset();
	root = alloc_table();
	map(root, 4, 0x400000, 0x200000, 1, flags);
	map(root, 4, 0x401000, 0x300000, 1, flags);
	w.cr3 = root;
	memset(sim + 0x200000, 0xee, 4096);
	CHECK_EQ(vtx_guest_copy(&pm, &w, 0x400ffb, data, 10, 1, &err, &fva), VTX_WALK_OK);
	CHECK_EQ(sim[0x200ffb], 1);
	CHECK_EQ(sim[0x200fff], 5);
	CHECK_EQ(sim[0x300000], 6);
	CHECK_EQ(sim[0x300004], 10);
	CHECK_EQ(vtx_guest_copy(&pm, &w, 0x400ffb, back, 10, 0, &err, &fva), VTX_WALK_OK);
	for (i = 0; i < 10; i++)
		CHECK_EQ(back[i], data[i]);
	memset(sim + 0x200000, 0xee, 4096);
	pt(pt(pt(pt(root)[0] & PTE_ADDR_MASK)[0] & PTE_ADDR_MASK)[2] & PTE_ADDR_MASK)[1] = 0;
	CHECK_EQ(vtx_guest_copy(&pm, &w, 0x400ffb, data, 10, 1, &err, &fva), VTX_WALK_PF);
	CHECK_EQ(fva, 0x401000);
	CHECK_EQ(err, VPF_W);
	CHECK_EQ(sim[0x200ffb], 0xee);
	CHECK_EQ(vtx_guest_copy(&pm, &w, 0x400000, data, 0, 0, &err, &fva), VTX_WALK_GP);
}

static void add_watch(int slot, uint64_t start, uint64_t end, uint32_t deny, uint32_t mode)
{
	struct vtx_watch *wt = &tables.watch[slot];

	wt->used = 1;
	wt->id = 100 + (uint32_t)slot;
	wt->deny = deny;
	wt->mode = mode;
	wt->start = start;
	wt->end = end;
}

static void test_write_policy(void)
{
	int slot = 42;

	reset();
	tables.nr_owned = 1;
	tables.owned[0].start = 0x800000;
	tables.owned[0].end = 0x802000;
	tables.self_pa[0] = 0x600000;
	tables.self_pa[1] = 0x601000;
	tables.self_x[0] = 1;
	tables.nr_self = 2;
	add_watch(3, 0x700000, 0x702000, VTX_DENY_W, VTX_MODE_MONITOR);
	add_watch(7, 0x701000, 0x703000, VTX_DENY_W, VTX_MODE_ENFORCE);
	add_watch(9, 0x710000, 0x711000, VTX_DENY_X, VTX_MODE_ENFORCE);
	add_watch(11, 0x720000, 0x721000, VTX_DENY_R, VTX_MODE_ENFORCE);
	CHECK_EQ(vtx_write_policy(&tables, 0x123456, &slot), VTX_WP_OPEN);
	CHECK_EQ(slot, -1);
	CHECK_EQ(vtx_write_policy(&tables, 0x800fff, &slot), VTX_WP_SELF);
	CHECK_EQ(vtx_write_policy(&tables, 0x801000, &slot), VTX_WP_SELF);
	CHECK_EQ(vtx_write_policy(&tables, 0x802000, &slot), VTX_WP_OPEN);
	CHECK_EQ(vtx_write_policy(&tables, 0x600000, &slot), VTX_WP_SELF);
	CHECK_EQ(vtx_write_policy(&tables, 0x601abc, &slot), VTX_WP_SELF);
	CHECK_EQ(vtx_write_policy(&tables, 0x602000, &slot), VTX_WP_OPEN);
	CHECK_EQ(vtx_write_policy(&tables, 0x700008, &slot), VTX_WP_WATCH);
	CHECK_EQ(slot, 3);
	CHECK_EQ(vtx_write_policy(&tables, 0x701ff8, &slot), VTX_WP_DENY);
	CHECK_EQ(slot, 3);
	CHECK_EQ(vtx_write_policy(&tables, 0x702000, &slot), VTX_WP_DENY);
	CHECK_EQ(slot, 7);
	CHECK_EQ(vtx_write_policy(&tables, 0x703000, NULL), VTX_WP_OPEN);
	CHECK_EQ(vtx_write_policy(&tables, 0x710000, &slot), VTX_WP_OPEN);
	CHECK_EQ(slot, 9);
	CHECK_EQ(vtx_write_policy(&tables, 0x720000, &slot), VTX_WP_WATCH);
	CHECK_EQ(slot, 11);
}

static void test_guest_copy_policy(void)
{
	uint64_t flags[6] = { 0, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W, 0 };
	struct vtx_walk w = { .wp = 1 };
	struct vtx_copy_res res;
	uint8_t data[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, back[4];
	uint64_t root, fva = 0;
	uint32_t err = 0;

	reset();
	tables.self_pa[0] = 0x600000;
	tables.nr_self = 1;
	add_watch(0, 0x700000, 0x701000, VTX_DENY_W, VTX_MODE_MONITOR);
	add_watch(1, 0x710000, 0x711000, VTX_DENY_W, VTX_MODE_ENFORCE);
	root = alloc_table();
	map(root, 4, 0x400000, 0x200000, 1, flags);
	map(root, 4, 0x401000, 0x600000, 1, flags);
	map(root, 4, 0x402000, 0x700000, 1, flags);
	map(root, 4, 0x403000, 0x710000, 1, flags);
	w.cr3 = root;
	memset(sim + 0x200000, 0xee, 4096);
	memset(sim + 0x600000, 0xcc, 4096);
	memset(sim + 0x700000, 0xaa, 4096);
	memset(sim + 0x710000, 0xbb, 4096);
	CHECK_EQ(vtx_guest_copy_ex(&pm, &w, 0x400ffb, data, 10, 1, &err, &fva, &res), VTX_WALK_OK);
	CHECK_EQ(res.n, 2);
	CHECK_EQ(res.denied, 1);
	CHECK_EQ(res.pol[0], VTX_WP_OPEN);
	CHECK_EQ(res.pol[1], VTX_WP_SELF);
	CHECK_EQ(res.gpa[0], 0x200ffb);
	CHECK_EQ(res.gpa[1], 0x600000);
	CHECK_EQ(res.gla[0], 0x400ffb);
	CHECK_EQ(res.gla[1], 0x401000);
	CHECK_EQ(res.len[0], 5);
	CHECK_EQ(res.len[1], 5);
	CHECK_EQ(sim[0x200ffb], 1);
	CHECK_EQ(sim[0x200fff], 5);
	CHECK_EQ(sim[0x600000], 0xcc);
	CHECK_EQ(sim[0x600004], 0xcc);
	CHECK_EQ(vtx_guest_copy_ex(&pm, &w, 0x402010, data, 10, 1, &err, &fva, &res), VTX_WALK_OK);
	CHECK_EQ(res.n, 1);
	CHECK_EQ(res.denied, 0);
	CHECK_EQ(res.pol[0], VTX_WP_WATCH);
	CHECK_EQ(res.slot[0], 0);
	CHECK_EQ(sim[0x700010], 1);
	CHECK_EQ(sim[0x700019], 10);
	CHECK_EQ(vtx_guest_copy_ex(&pm, &w, 0x403010, data, 10, 1, &err, &fva, &res), VTX_WALK_OK);
	CHECK_EQ(res.pol[0], VTX_WP_DENY);
	CHECK_EQ(res.slot[0], 1);
	CHECK_EQ(res.denied, 1);
	CHECK_EQ(sim[0x710010], 0xbb);
	CHECK_EQ(sim[0x710019], 0xbb);
	CHECK_EQ(vtx_guest_copy_ex(&pm, &w, 0x401ffe, back, 4, 0, &err, &fva, &res), VTX_WALK_OK);
	CHECK_EQ(res.n, 2);
	CHECK_EQ(res.denied, 0);
	CHECK_EQ(back[1], 0xcc);
	CHECK_EQ(back[2], 0xaa);
	CHECK_EQ(vtx_guest_copy_ex(&pm, &w, 0x401000, back, 4, 0, &err, &fva, &res), VTX_WALK_OK);
	CHECK_EQ(back[0], 0xcc);
	CHECK_EQ(res.pol[0], VTX_WP_OPEN);
	CHECK_EQ(res.denied, 0);
	CHECK_EQ(vtx_guest_copy_ex(&pm, &w, 0x403ffc, data, 10, 1, &err, &fva, &res), VTX_WALK_PF);
	CHECK_EQ(fva, 0x404000);
	CHECK_EQ(res.n, 0);
	pm.tables = NULL;
	CHECK_EQ(vtx_guest_copy_ex(&pm, &w, 0x403010, data, 10, 1, &err, &fva, &res), VTX_WALK_OK);
	CHECK_EQ(res.pol[0], VTX_WP_OPEN);
	CHECK_EQ(sim[0x710010], 1);
}

static void test_ad_protected_tables(void)
{
	uint64_t flags[6] = { 0, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W, PTE_P | PTE_W, 0 };
	struct vtx_walk w = { .wp = 1, .set_ad = 1 };
	uint64_t gpa, root, l1pa, *l1;
	uint32_t err;

	reset();
	root = alloc_table();
	map(root, 4, 0x400000, 0x123000, 1, flags);
	l1pa = pt(pt(pt(root)[0] & PTE_ADDR_MASK)[0] & PTE_ADDR_MASK)[2] & PTE_ADDR_MASK;
	l1 = &pt(l1pa)[0];
	tables.self_pa[0] = l1pa;
	tables.nr_self = 1;
	w.cr3 = root;
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0x400000, VTX_ACC_WRITE, &gpa, &err), VTX_WALK_OK);
	CHECK_EQ(gpa, 0x123000);
	CHECK(pt(root)[0] & PTE_A);
	CHECK(!(*l1 & PTE_A));
	CHECK(!(*l1 & PTE_D));
	tables.nr_self = 0;
	add_watch(0, l1pa, l1pa + 4096, VTX_DENY_W, VTX_MODE_ENFORCE);
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0x400000, VTX_ACC_WRITE, &gpa, &err), VTX_WALK_OK);
	CHECK(!(*l1 & PTE_A));
	CHECK(!(*l1 & PTE_D));
	tables.watch[0].mode = VTX_MODE_MONITOR;
	CHECK_EQ(vtx_walk_gva(&pm, &w, 0x400000, VTX_ACC_WRITE, &gpa, &err), VTX_WALK_OK);
	CHECK(*l1 & PTE_A);
	CHECK(*l1 & PTE_D);
}

int t_checks, t_failures;
const char *t_current;

int main(void)
{
	if (posix_memalign((void **)&sim, 4096, SIM_SIZE))
		return 1;
	printf("guest page walker\n");
	T_RUN(test_permission_matrix);
	T_RUN(test_large_pages_and_la57);
	T_RUN(test_bad_physical);
	T_RUN(test_ad_bits);
	T_RUN(test_guest_copy_atomicity);
	T_RUN(test_write_policy);
	T_RUN(test_guest_copy_policy);
	T_RUN(test_ad_protected_tables);
	printf("  %d checks, %d failures\n", t_checks, t_failures);
	free(sim);
	return t_failures != 0;
}
