#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "ksyms.h"

static int ksym_cmp(const void *a, const void *b)
{
	const struct ksym *x = a, *y = b;

	if (x->addr != y->addr)
		return x->addr < y->addr ? -1 : 1;
	return strcmp(x->name, y->name);
}

static int ksyms_push(struct ksyms *k, uint64_t addr, char type, const char *name, size_t nlen,
		      const char *mod, size_t mlen)
{
	struct ksym *s;

	if (k->n == k->cap) {
		size_t nc = k->cap ? k->cap * 2 : 4096;
		struct ksym *nv = realloc(k->v, nc * sizeof(*nv));

		if (!nv)
			return -1;
		k->v = nv;
		k->cap = nc;
	}
	s = &k->v[k->n];
	s->addr = addr;
	s->type = type;
	s->name = strndup(name, nlen);
	s->mod = mlen ? strndup(mod, mlen) : NULL;
	if (!s->name || (mlen && !s->mod)) {
		free(s->name);
		free(s->mod);
		return -1;
	}
	k->n++;
	return 0;
}

int ksyms_parse(struct ksyms *k, const char *buf, size_t len)
{
	size_t i = 0;

	memset(k, 0, sizeof(*k));
	while (i < len) {
		size_t ls = i, le;
		uint64_t addr = 0;
		int digits = 0;
		char type;
		const char *name, *mod = NULL;
		size_t nlen, mlen = 0, p;

		while (i < len && buf[i] != '\n')
			i++;
		le = i;
		if (i < len)
			i++;
		p = ls;
		while (p < le && isxdigit((unsigned char)buf[p]) && digits < 16) {
			char c = buf[p];

			addr = (addr << 4) | (uint64_t)(isdigit((unsigned char)c) ? c - '0' : (tolower((unsigned char)c) - 'a' + 10));
			p++;
			digits++;
		}
		if (!digits || p >= le || buf[p] != ' ')
			continue;
		p++;
		if (p >= le)
			continue;
		type = buf[p++];
		if (p >= le || buf[p] != ' ')
			continue;
		p++;
		name = &buf[p];
		while (p < le && buf[p] != ' ' && buf[p] != '\t')
			p++;
		nlen = (size_t)(&buf[p] - name);
		if (!nlen)
			continue;
		while (p < le && (buf[p] == ' ' || buf[p] == '\t'))
			p++;
		if (p < le && buf[p] == '[') {
			size_t q = p + 1;

			while (q < le && buf[q] != ']')
				q++;
			if (q < le) {
				mod = &buf[p + 1];
				mlen = q - p - 1;
			}
		}
		if (addr)
			k->usable = 1;
		if (ksyms_push(k, addr, type, name, nlen, mod, mlen)) {
			ksyms_free(k);
			return -1;
		}
	}
	if (k->n)
		qsort(k->v, k->n, sizeof(*k->v), ksym_cmp);
	return 0;
}

int ksyms_load(struct ksyms *k, const char *path)
{
	FILE *f = fopen(path, "r");
	char *buf = NULL;
	size_t len = 0, cap = 0;
	int rc;

	memset(k, 0, sizeof(*k));
	if (!f)
		return -1;
	for (;;) {
		size_t r;

		if (cap - len < 65536) {
			char *nb = realloc(buf, cap + (1 << 20));

			if (!nb) {
				free(buf);
				fclose(f);
				return -1;
			}
			buf = nb;
			cap += 1 << 20;
		}
		r = fread(buf + len, 1, cap - len, f);
		if (!r)
			break;
		len += r;
	}
	fclose(f);
	rc = ksyms_parse(k, buf, len);
	free(buf);
	return rc;
}

static int ksym_is_text(char t)
{
	return t == 't' || t == 'T' || t == 'w' || t == 'W';
}

const struct ksym *ksyms_lookup(const struct ksyms *k, uint64_t addr, uint64_t *off)
{
	size_t lo = 0, hi = k->n;
	const struct ksym *best = NULL;

	if (!k->usable || !k->n)
		return NULL;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (k->v[mid].addr <= addr)
			lo = mid + 1;
		else
			hi = mid;
	}
	while (lo > 0) {
		const struct ksym *s = &k->v[lo - 1];

		if (ksym_is_text(s->type) || s->type == 'd' || s->type == 'D' || s->type == 'r' || s->type == 'R' ||
		    s->type == 'b' || s->type == 'B') {
			best = s;
			break;
		}
		lo--;
	}
	if (!best)
		return NULL;
	if (addr - best->addr > (1u << 20))
		return NULL;
	if (off)
		*off = addr - best->addr;
	return best;
}

const struct ksym *ksyms_find(const struct ksyms *k, const char *name)
{
	size_t i;

	for (i = 0; i < k->n; i++)
		if (!strcmp(k->v[i].name, name))
			return &k->v[i];
	return NULL;
}

void ksyms_free(struct ksyms *k)
{
	size_t i;

	for (i = 0; i < k->n; i++) {
		free(k->v[i].name);
		free(k->v[i].mod);
	}
	free(k->v);
	memset(k, 0, sizeof(*k));
}
