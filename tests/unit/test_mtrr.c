#include "harness.h"
#include "../../kmod/mtrr.h"
#include "../../kmod/vtx_vmcs.h"

static int ref_type_4k(const struct vtx_mtrr *m, uint64_t a)
{
	uint32_t seen = 0, i;

	if (!m->enabled)
		return MT_UC;
	if (m->fixed_enabled && a < 0x100000)
		return m->fixed[vtx_mtrr_fixed_index(a)];
	for (i = 0; i < m->nvar; i++) {
		uint64_t mask = m->mask[i] & m->phys_mask;

		if (!(m->mask[i] & (1ull << 11)))
			continue;
		if ((a & mask) == (m->base[i] & mask))
			seen |= 1u << (m->base[i] & 7);
	}
	if (!seen)
		return (int)m->def_type;
	if (seen & (1u << MT_UC))
		return MT_UC;
	if (seen == (1u << MT_WT) || seen == (1u << MT_WB) || seen == ((1u << MT_WT) | (1u << MT_WB)))
		return seen == (1u << MT_WB) ? MT_WB : MT_WT;
	if ((seen & (seen - 1)) == 0)
		return __builtin_ctz(seen);
	return MT_UC;
}

static void base_mtrr(struct vtx_mtrr *m)
{
	memset(m, 0, sizeof(*m));
	m->enabled = 1;
	m->fixed_enabled = 1;
	m->def_type = MT_UC;
	m->phys_mask = ((1ull << 39) - 1) & ~0xfffull;
	memset(m->fixed, MT_WB, sizeof(m->fixed));
}

static void add_var(struct vtx_mtrr *m, uint64_t base, uint64_t size, int type)
{
	uint32_t i = m->nvar++;

	m->base[i] = base | (uint64_t)type;
	m->mask[i] = ((~(size - 1)) & m->phys_mask) | (1ull << 11);
}

static void test_fixed_index(void)
{
	CHECK_EQ(vtx_mtrr_fixed_index(0), 0);
	CHECK_EQ(vtx_mtrr_fixed_index(0x7ffff), 7);
	CHECK_EQ(vtx_mtrr_fixed_index(0x80000), 8);
	CHECK_EQ(vtx_mtrr_fixed_index(0x9ffff), 15);
	CHECK_EQ(vtx_mtrr_fixed_index(0xa0000), 16);
	CHECK_EQ(vtx_mtrr_fixed_index(0xbffff), 23);
	CHECK_EQ(vtx_mtrr_fixed_index(0xc0000), 24);
	CHECK_EQ(vtx_mtrr_fixed_index(0xfffff), 87);
	CHECK(vtx_mtrr_fixed_index(0x100000) < 0);
}

static void test_fixed_msr_unpack(void)
{
	struct vtx_mtrr m;
	int i;

	base_mtrr(&m);
	vtx_mtrr_set_fixed_msr(&m, 0, 0x0706050403020100ull);
	vtx_mtrr_set_fixed_msr(&m, 10, 0x0606060606060600ull);
	for (i = 0; i < 8; i++)
		CHECK_EQ(m.fixed[i], i);
	CHECK_EQ(m.fixed[80], 0);
	CHECK_EQ(m.fixed[81], 6);
	CHECK_EQ(m.fixed[87], 6);
	vtx_mtrr_set_fixed_msr(&m, 11, 0x0101010101010101ull);
	CHECK_EQ(m.fixed[87], 6);
}

static void test_combine(void)
{
	CHECK_EQ(vtx_mtrr_combine(1u << MT_UC | 1u << MT_WB), MT_UC);
	CHECK_EQ(vtx_mtrr_combine(1u << MT_WT | 1u << MT_WB), MT_WT);
	CHECK_EQ(vtx_mtrr_combine(1u << MT_WB), MT_WB);
	CHECK_EQ(vtx_mtrr_combine(1u << MT_WC), MT_WC);
	CHECK_EQ(vtx_mtrr_combine(1u << MT_WC | 1u << MT_WB), MT_UC);
	CHECK_EQ(vtx_mtrr_combine(1u << MT_WP | 1u << MT_WT), MT_UC);
}

static void test_basic_layout(void)
{
	struct vtx_mtrr m;

	base_mtrr(&m);
	add_var(&m, 0, 1ull << 31, MT_WB);
	add_var(&m, 1ull << 31, 1ull << 30, MT_WB);
	add_var(&m, 0xc0000000, 1ull << 30, MT_UC);
	add_var(&m, 0x100000000ull, 1ull << 32, MT_WB);
	add_var(&m, 0xd0000000, 1ull << 28, MT_WC);
	CHECK_EQ(vtx_mtrr_type(&m, 0x40000000, 1ull << 30), MT_WB);
	CHECK_EQ(vtx_mtrr_type(&m, 0x80000000, 1ull << 30), MT_WB);
	CHECK_EQ(vtx_mtrr_type(&m, 0xc0000000, 1ull << 30), -1);
	CHECK_EQ(vtx_mtrr_type(&m, 0xc0000000, 1ull << 21), MT_UC);
	CHECK_EQ(vtx_mtrr_type(&m, 0xd0000000, 1ull << 21), MT_UC);
	CHECK_EQ(vtx_mtrr_type(&m, 0x100000000ull, 1ull << 30), MT_WB);
	CHECK_EQ(vtx_mtrr_type(&m, 0x200000000ull, 1ull << 30), MT_UC);
	CHECK_EQ(vtx_mtrr_type(&m, 0, 1ull << 21), -1);
	CHECK_EQ(vtx_mtrr_type(&m, 0, 4096), MT_WB);
	CHECK_EQ(vtx_mtrr_type(&m, 0x1000, 8192), -1);
	CHECK_EQ(vtx_mtrr_type(&m, 0x1000, 0x3000), -1);
	m.enabled = 0;
	CHECK_EQ(vtx_mtrr_type(&m, 0x40000000, 1ull << 30), MT_UC);
}

static void test_fixed_region(void)
{
	struct vtx_mtrr m;

	base_mtrr(&m);
	add_var(&m, 0, 1ull << 30, MT_WB);
	memset(&m.fixed[16], MT_UC, 8);
	CHECK_EQ(vtx_mtrr_type(&m, 0xa0000, 0x4000), MT_UC);
	CHECK_EQ(vtx_mtrr_type(&m, 0x80000, 0x20000), MT_WB);
	CHECK_EQ(vtx_mtrr_type(&m, 0x80000, 0x80000), -1);
	CHECK_EQ(vtx_mtrr_type(&m, 0, 0x100000), -1);
	m.fixed_enabled = 0;
	CHECK_EQ(vtx_mtrr_type(&m, 0, 0x100000), MT_WB);
	CHECK_EQ(vtx_mtrr_type(&m, 0, 1ull << 21), MT_WB);
}

static void test_property_random(void)
{
	uint64_t seed = 0x9e3779b97f4a7c15ull;
	int iter;

	for (iter = 0; iter < 400; iter++) {
		struct vtx_mtrr m;
		uint32_t n = (uint32_t)(t_rand64(&seed) % 10), i;
		static const int types[] = { MT_UC, MT_WC, MT_WT, MT_WP, MT_WB };
		int probe;

		base_mtrr(&m);
		m.def_type = types[t_rand64(&seed) % 5];
		m.fixed_enabled = (uint32_t)(t_rand64(&seed) & 1);
		for (i = 0; i < 88; i++)
			m.fixed[i] = (uint8_t)(t_rand64(&seed) % 3 ? MT_WB : types[t_rand64(&seed) % 5]);
		for (i = 0; i < n; i++) {
			int shift = 21 + (int)(t_rand64(&seed) % 13);
			uint64_t size = 1ull << shift;
			uint64_t base = (t_rand64(&seed) % (1ull << 34)) & ~(size - 1);

			if (t_rand64(&seed) % 7 == 0)
				size = 1ull << (12 + t_rand64(&seed) % 9);
			base &= ~(size - 1);
			add_var(&m, base, size, types[t_rand64(&seed) % 5]);
		}
		for (probe = 0; probe < 24; probe++) {
			int shift = (probe % 3 == 0) ? 30 : (probe % 3 == 1 ? 21 : 12);
			uint64_t size = 1ull << shift;
			uint64_t base = (t_rand64(&seed) % (1ull << 34)) & ~(size - 1);
			int got, want = -2;
			uint64_t a;
			int uniform = 1;

			if (probe % 5 == 0)
				base = (base & ((1ull << 22) - 1)) & ~(size - 1);
			got = vtx_mtrr_type(&m, base, size);
			for (a = base; a < base + size; a += 4096) {
				int t = ref_type_4k(&m, a);

				if (want == -2)
					want = t;
				else if (t != want)
					uniform = 0;
				if (!uniform)
					break;
			}
			if (got >= 0)
				CHECK(uniform && got == want);
			if (shift == 12)
				CHECK(got == want);
		}
	}
}

int t_checks, t_failures;
const char *t_current;

int main(void)
{
	printf("mtrr resolver\n");
	T_RUN(test_fixed_index);
	T_RUN(test_fixed_msr_unpack);
	T_RUN(test_combine);
	T_RUN(test_basic_layout);
	T_RUN(test_fixed_region);
	T_RUN(test_property_random);
	printf("  %d checks, %d failures\n", t_checks, t_failures);
	return t_failures != 0;
}
