#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "../../tools/vtxctl/ksyms.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ksyms k;
	uint64_t probe = 0, off;
	size_t i;

	if (ksyms_parse(&k, (const char *)data, size))
		return 0;
	for (i = 1; i < k.n; i++)
		if (k.v[i - 1].addr > k.v[i].addr)
			abort();
	memcpy(&probe, data, size < 8 ? size : 8);
	ksyms_lookup(&k, probe, &off);
	ksyms_lookup(&k, ~probe, &off);
	if (k.n)
		ksyms_find(&k, k.v[k.n / 2].name);
	ksyms_free(&k);
	return 0;
}
