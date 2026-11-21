#include "harness.h"
#include "../../kmod/dtr.h"
#include "../../kmod/vtx_vmcs.h"
#include "../../include/uapi/vtxhv.h"

static uint32_t enc(uint32_t scale, uint32_t reg1, uint32_t asz, uint32_t isreg, uint32_t seg, uint32_t idx,
		    uint32_t idx_inv, uint32_t base, uint32_t base_inv, uint32_t ident)
{
	return scale | (reg1 << 3) | (asz << 7) | (isreg << 10) | (seg << 15) | (idx << 18) | (idx_inv << 22) |
	       (base << 23) | (base_inv << 27) | (ident << 28);
}

static void test_decode_exhaustive(void)
{
	uint32_t ident, scale, asz, seg, idx, base, inv;

	for (ident = 0; ident < 4; ident++)
		for (scale = 0; scale < 4; scale++)
			for (asz = 0; asz < 3; asz++)
				for (seg = 0; seg < 6; seg++)
					for (idx = 0; idx < 16; idx += 3)
						for (base = 0; base < 16; base += 5)
							for (inv = 0; inv < 4; inv++) {
								struct vtx_dtr_insn d;
								uint32_t info = enc(scale, 0, asz, 0, seg, idx, inv & 1, base, inv >> 1, ident);

								vtx_dtr_decode(EXIT_REASON_GDTR_IDTR, info, &d);
								CHECK_EQ(d.op, ident);
								CHECK_EQ(d.is_mem, 1);
								CHECK_EQ(d.scale, scale);
								CHECK_EQ(d.addr_size, asz);
								CHECK_EQ(d.seg, seg);
								CHECK_EQ(d.index, (inv & 1) ? -1 : (int)idx);
								CHECK_EQ(d.base, (inv >> 1) ? -1 : (int)base);
								info = enc(scale, base, asz, inv & 1, seg, idx, 0, base, 0, ident);
								vtx_dtr_decode(EXIT_REASON_LDTR_TR, info, &d);
								CHECK_EQ(d.op, VTX_DTR_SLDT + ident);
								CHECK_EQ(d.is_mem, !(inv & 1));
								CHECK_EQ(d.reg, base);
							}
}

static void test_effective_address(void)
{
	uint64_t gpr[16];
	struct vtx_dtr_insn d;
	int i;

	for (i = 0; i < 16; i++)
		gpr[i] = 0x1000ull * (uint64_t)(i + 1);
	vtx_dtr_decode(EXIT_REASON_GDTR_IDTR, enc(3, 0, 2, 0, 3, 6, 0, 3, 0, 0), &d);
	CHECK_EQ(vtx_dtr_ea(&d, gpr, 0x10, 0xdead0000, 1), gpr[3] + (gpr[6] << 3) + 0x10);
	vtx_dtr_decode(EXIT_REASON_GDTR_IDTR, enc(0, 0, 2, 0, 5, 0, 1, 7, 0, 1), &d);
	CHECK_EQ(vtx_dtr_ea(&d, gpr, (uint64_t)-8, 0x7000000000ull, 1), 0x7000000000ull + gpr[7] - 8);
	vtx_dtr_decode(EXIT_REASON_GDTR_IDTR, enc(0, 0, 1, 0, 3, 0, 1, 0, 1, 2), &d);
	CHECK_EQ(vtx_dtr_ea(&d, gpr, 0xfffffffffffffff0ull, 0, 1), 0xfffffff0ull);
	vtx_dtr_decode(EXIT_REASON_GDTR_IDTR, enc(1, 0, 0, 0, 3, 2, 0, 1, 0, 3), &d);
	CHECK_EQ(vtx_dtr_ea(&d, gpr, 0x1, 0, 1), (gpr[1] + (gpr[2] << 1) + 1) & 0xffff);
	vtx_dtr_decode(EXIT_REASON_GDTR_IDTR, enc(0, 0, 1, 0, 3, 0, 1, 3, 0, 0), &d);
	CHECK_EQ(vtx_dtr_ea(&d, gpr, 0x4, 0x100, 0), (gpr[3] + 0x4 + 0x100) & 0xffffffffull);
}

static void test_gpr_slots(void)
{
	CHECK_EQ(vtx_gpr_slot(0), 0);
	CHECK_EQ(vtx_gpr_slot(3), 3);
	CHECK_EQ(vtx_gpr_slot(4), -2);
	CHECK_EQ(vtx_gpr_slot(5), 4);
	CHECK_EQ(vtx_gpr_slot(15), 14);
	CHECK_EQ(vtx_gpr_slot(16), -1);
}

static void test_opsize(void)
{
	static const uint8_t str16[] = { 0x66, 0x0f, 0x00, 0xc8 };
	static const uint8_t str32[] = { 0x0f, 0x00, 0xc8 };
	static const uint8_t str64[] = { 0x48, 0x0f, 0x00, 0xc8 };
	static const uint8_t str66w[] = { 0x66, 0x48, 0x0f, 0x00, 0xc8 };
	static const uint8_t seg66[] = { 0x2e, 0x66, 0x0f, 0x00, 0xc8 };
	static const uint8_t rex_only[] = { 0x41, 0x0f, 0x00, 0xc8 };

	CHECK(vtx_insn_opsize16(str16, sizeof(str16)));
	CHECK(!vtx_insn_opsize16(str32, sizeof(str32)));
	CHECK(!vtx_insn_opsize16(str64, sizeof(str64)));
	CHECK(!vtx_insn_opsize16(str66w, sizeof(str66w)));
	CHECK(vtx_insn_opsize16(seg66, sizeof(seg66)));
	CHECK(!vtx_insn_opsize16(rex_only, sizeof(rex_only)));
	CHECK(!vtx_insn_opsize16(str16, 0));
}

int t_checks, t_failures;
const char *t_current;

int main(void)
{
	printf("descriptor-table instruction decoder\n");
	T_RUN(test_decode_exhaustive);
	T_RUN(test_effective_address);
	T_RUN(test_gpr_slots);
	T_RUN(test_opsize);
	printf("  %d checks, %d failures\n", t_checks, t_failures);
	return t_failures != 0;
}
