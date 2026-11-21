#ifndef VTX_TEST_HARNESS_H
#define VTX_TEST_HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

extern int t_checks;
extern int t_failures;
extern const char *t_current;

#define CHECK(cond) do {								\
	t_checks++;									\
	if (!(cond)) {									\
		t_failures++;								\
		fprintf(stderr, "  FAIL %s:%d [%s] %s\n", __FILE__, __LINE__, t_current, #cond); \
	}										\
} while (0)

#define CHECK_EQ(a, b) do {								\
	unsigned long long _a = (unsigned long long)(a), _b = (unsigned long long)(b);	\
	t_checks++;									\
	if (_a != _b) {									\
		t_failures++;								\
		fprintf(stderr, "  FAIL %s:%d [%s] %s == %s (%#llx != %#llx)\n", __FILE__, __LINE__, \
			t_current, #a, #b, _a, _b);					\
	}										\
} while (0)

typedef void (*t_fn)(void);

struct t_case {
	const char *name;
	t_fn fn;
};

#define T_RUN(fn) do {									\
	int _f = t_failures, _c = t_checks;						\
	t_current = #fn;								\
	fn();										\
	printf("  %s %-44s %6d checks\n", t_failures == _f ? "\033[32mok\033[0m  " : "\033[31mFAIL\033[0m", #fn, \
	       t_checks - _c);								\
} while (0)

static inline uint64_t t_rand64(uint64_t *s)
{
	uint64_t x = *s;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	*s = x;
	return x;
}

#endif
