#ifndef VTXCTL_KSYMS_H
#define VTXCTL_KSYMS_H

#include <stddef.h>
#include <stdint.h>

struct ksym {
	uint64_t addr;
	char *name;
	char *mod;
	char type;
};

struct ksyms {
	struct ksym *v;
	size_t n;
	size_t cap;
	int usable;
};

int ksyms_parse(struct ksyms *k, const char *buf, size_t len);
int ksyms_load(struct ksyms *k, const char *path);
const struct ksym *ksyms_lookup(const struct ksyms *k, uint64_t addr, uint64_t *off);
const struct ksym *ksyms_find(const struct ksyms *k, const char *name);
void ksyms_free(struct ksyms *k);

#endif
