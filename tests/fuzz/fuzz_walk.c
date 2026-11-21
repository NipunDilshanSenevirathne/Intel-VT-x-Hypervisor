#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "../../kmod/walk.h"
#include "../../kmod/vtx_vmcs.h"

#define MEM_PAGES 16

static uint8_t mem[MEM_PAGES * 4096] __attribute__((aligned(4096)));
static uint8_t before[MEM_PAGES * 4096];

struct ctl {
	uint64_t cr3;
	uint64_t gva;
	uint32_t flags;
	uint32_t access;
	uint32_t len;
	uint32_t owned_page;
	uint32_t self_page;
	uint32_t watch_page;
};

static int overlap(uint64_t a, uint64_t al, uint64_t b, uint64_t bl)
{
	return a < b + bl && b < a + al;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct vtx_physmap pm;
	struct vtx_tables t;
	struct vtx_walk w;
	struct vtx_copy_res res;
	struct ctl c;
	uint64_t gpa = 0, fva = 0;
	uint32_t err = 0, n, i, denied = 0, total = 0;
	uint8_t buf[64];
	size_t body;
	int rc, write, p;

	if (size < sizeof(c))
		return 0;
	memcpy(&c, data, sizeof(c));
	body = size - sizeof(c);
	if (body > sizeof(mem))
		body = sizeof(mem);
	memset(mem, 0, sizeof(mem));
	memcpy(mem, data + sizeof(c), body);
	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (uint8_t)(0xa5 ^ i ^ (c.len >> 8));
	memset(&t, 0, sizeof(t));
	memset(&pm, 0, sizeof(pm));
	pm.dmap = (uint64_t)(uintptr_t)mem;
	pm.nr_ram = 2;
	pm.ram[0].start = 0;
	pm.ram[0].end = 7 * 4096;
	pm.ram[1].start = 8 * 4096;
	pm.ram[1].end = sizeof(mem);
	pm.tables = &t;
	if (c.owned_page & 0x10) {
		t.nr_owned = 1;
		t.owned[0].start = (uint64_t)(c.owned_page & 15) * 4096;
		t.owned[0].end = t.owned[0].start + 4096;
	}
	if (c.self_page & 0x10) {
		t.self_pa[0] = (uint64_t)(c.self_page & 15) * 4096;
		t.nr_self = 1;
	}
	if (c.watch_page & 0x10) {
		t.watch[0].used = 1;
		t.watch[0].id = 1;
		t.watch[0].deny = (c.watch_page >> 5) & 7;
		t.watch[0].mode = (c.watch_page >> 8) & 1;
		t.watch[0].start = (uint64_t)(c.watch_page & 15) * 4096;
		t.watch[0].end = t.watch[0].start + 4096 * (1 + ((c.watch_page >> 9) & 1));
	}
	memset(&w, 0, sizeof(w));
	w.cr3 = c.cr3;
	w.la57 = c.flags & 1;
	w.nxe = (c.flags >> 1) & 1;
	w.wp = (c.flags >> 2) & 1;
	w.smep = (c.flags >> 3) & 1;
	w.smap = (c.flags >> 4) & 1;
	w.ac = (c.flags >> 5) & 1;
	w.user = (c.flags >> 6) & 1;
	w.implicit = (c.flags >> 7) & 1;
	w.set_ad = (c.flags >> 8) & 1;
	write = (c.flags >> 9) & 1;
	n = 1 + c.len % sizeof(buf);
	memcpy(before, mem, sizeof(mem));
	switch (vtx_walk_gva(&pm, &w, c.gva, c.access % 3, &gpa, &err)) {
	case VTX_WALK_OK:
	case VTX_WALK_PF:
	case VTX_WALK_GP:
	case VTX_WALK_BADPHYS:
		break;
	default:
		abort();
	}
	rc = vtx_guest_copy_ex(&pm, &w, c.gva, buf, n, write, &err, &fva, &res);
	for (p = 0; p < MEM_PAGES; p++)
		if (vtx_write_policy(&t, (uint64_t)p * 4096, NULL) >= VTX_WP_DENY &&
		    memcmp(mem + p * 4096, before + p * 4096, 4096))
			abort();
	if (rc != VTX_WALK_OK) {
		if (res.n || res.denied)
			abort();
		return 0;
	}
	if (res.n < 1 || res.n > 2)
		abort();
	for (i = 0; i < res.n; i++) {
		if (!vtx_phys_ok(&pm, res.gpa[i], res.len[i]))
			abort();
		if ((res.gpa[i] & 4095) + res.len[i] > 4096)
			abort();
		if (res.pol[i] >= VTX_WP_DENY)
			denied++;
		if (!write && res.pol[i] != VTX_WP_OPEN)
			abort();
		total += res.len[i];
	}
	if (total != n || denied != res.denied)
		abort();
	if (!write)
		return 0;
	i = res.n - 1;
	if (res.pol[i] < VTX_WP_DENY && memcmp(mem + res.gpa[i], buf + (n - res.len[i]), res.len[i]))
		abort();
	if (res.n == 2 && res.pol[0] < VTX_WP_DENY &&
	    !overlap(res.gpa[0], res.len[0], res.gpa[1], res.len[1]) &&
	    memcmp(mem + res.gpa[0], buf, res.len[0]))
		abort();
	return 0;
}
