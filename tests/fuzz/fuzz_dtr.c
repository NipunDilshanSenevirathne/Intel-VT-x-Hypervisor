#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "../../kmod/dtr.h"
#include "../../kmod/vtx_vmcs.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct vtx_dtr_insn d;
	uint64_t gpr[16], disp, seg, ea;
	uint32_t info;

	if (size < 4 + 8 + 8 + 128)
		return 0;
	memcpy(&info, data, 4);
	memcpy(&disp, data + 4, 8);
	memcpy(&seg, data + 12, 8);
	memcpy(gpr, data + 20, 128);
	vtx_dtr_decode((info & 0x80000000u) ? 47 : 46, info, &d);
	if (d.op > 7 || d.scale > 3 || d.seg > 7 || d.base > 15 || d.index > 15 || d.base < -1 || d.index < -1 || d.reg > 15)
		abort();
	ea = vtx_dtr_ea(&d, gpr, disp, seg, (int)(info & 1));
	if (d.addr_size == 0 && !(info & 1) && ((ea - seg) & 0xffffffffull) > 0xffff)
		abort();
	if (!(info & 1) && (ea >> 32))
		abort();
	vtx_gpr_slot(info & 31);
	vtx_insn_opsize16(data + 20, (uint32_t)(size - 20 > 15 ? 15 : size - 20));
	return 0;
}
