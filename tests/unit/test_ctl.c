#include "harness.h"
#include "../../kmod/ctl.h"

static void test_adjust(void)
{
	uint64_t cap = ((uint64_t)0xfff9fffe << 32) | 0x0401e172;

	CHECK_EQ(vtx_ctl_adjust(cap, 0), 0x0401e172);
	CHECK_EQ(vtx_ctl_adjust(cap, 1u << 31), 0x8401e172);
	CHECK_EQ(vtx_ctl_adjust(cap, 1u << 0), 0x0401e172);
	CHECK_EQ(vtx_ctl_adjust(cap, 1u << 17), 0x0401e172);
	CHECK(vtx_ctl_allowed(cap, 1u << 28));
	CHECK(!vtx_ctl_allowed(cap, 1u << 17));
	CHECK(!vtx_ctl_allowed(cap, (1u << 28) | 1u));
	CHECK_EQ(vtx_ctl_forced(cap), 0x0401e172);
}

static void test_fixed(void)
{
	uint64_t f0 = 0x80000021, f1 = 0xffffffff;

	CHECK(vtx_cr_fixed_ok(0x80050033, f0, f1));
	CHECK(!vtx_cr_fixed_ok(0x80050013, f0, f1));
	CHECK(!vtx_cr_fixed_ok(0x180050033ull, f0, f1));
	CHECK_EQ(vtx_cr_apply_fixed(0x00050012, f0, f1), 0x80050033);
	CHECK_EQ(vtx_cr_apply_fixed(0x100000000ull, f0, f1), 0x80000021);
	CHECK(vtx_cr_fixed_ok(0x3726f0 | 0x2000, 0x2000, 0x3727ff));
	CHECK(!vtx_cr_fixed_ok(0x3706f0, 0x2000, 0x3727ff));
}

int t_checks, t_failures;
const char *t_current;

int main(void)
{
	printf("vmx control logic\n");
	T_RUN(test_adjust);
	T_RUN(test_fixed);
	printf("  %d checks, %d failures\n", t_checks, t_failures);
	return t_failures != 0;
}
