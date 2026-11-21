#include "harness.h"
#include "../../tools/vtxctl/ksyms.h"

static const char sample[] =
	"ffffffff81000000 T _text\n"
	"ffffffff81000000 T startup_64\n"
	"ffffffff81001000 t helper_one\n"
	"ffffffff81002000 T do_sys_open\n"
	"ffffffff82000000 D jiffies\n"
	"ffffffffc0200000 t vtx_handle_exit\t[vtxhv_root]\n"
	"ffffffffc0201000 T vtx_ioctl\t[vtxhv]\n"
	"garbage line without fields\n"
	"zzzzzzzzzzzzzzzz T bad_addr\n"
	"ffffffff83000000 X\n"
	"\n"
	"ffffffff81003000 W weak_fn";

static void test_parse_lookup(void)
{
	struct ksyms k;
	const struct ksym *s;
	uint64_t off = 0;

	CHECK_EQ(ksyms_parse(&k, sample, sizeof(sample) - 1), 0);
	CHECK(k.usable);
	CHECK_EQ(k.n, 8);
	s = ksyms_lookup(&k, 0xffffffff81001234ull, &off);
	CHECK(s && !strcmp(s->name, "helper_one"));
	CHECK_EQ(off, 0x234);
	s = ksyms_lookup(&k, 0xffffffffc0200010ull, &off);
	CHECK(s && !strcmp(s->name, "vtx_handle_exit") && s->mod && !strcmp(s->mod, "vtxhv_root"));
	s = ksyms_lookup(&k, 0xffffffff81003010ull, &off);
	CHECK(s && !strcmp(s->name, "weak_fn"));
	CHECK(ksyms_lookup(&k, 0x1000, &off) == NULL);
	CHECK(ksyms_lookup(&k, 0xffffffffd0000000ull, &off) == NULL);
	s = ksyms_find(&k, "jiffies");
	CHECK(s && s->addr == 0xffffffff82000000ull && s->type == 'D');
	CHECK(ksyms_find(&k, "nope") == NULL);
	ksyms_free(&k);
	CHECK_EQ(k.n, 0);
}

static void test_restricted(void)
{
	static const char hidden[] = "0000000000000000 T _text\n0000000000000000 T foo\n";
	struct ksyms k;

	CHECK_EQ(ksyms_parse(&k, hidden, sizeof(hidden) - 1), 0);
	CHECK(!k.usable);
	CHECK(ksyms_lookup(&k, 0x1234, NULL) == NULL);
	ksyms_free(&k);
}

static void test_random_garbage(void)
{
	uint64_t seed = 77;
	char buf[4096];
	int iter;

	for (iter = 0; iter < 3000; iter++) {
		struct ksyms k;
		size_t n = (size_t)(t_rand64(&seed) % sizeof(buf)), i;

		for (i = 0; i < n; i++) {
			uint64_t r = t_rand64(&seed) % 100;

			buf[i] = r < 30 ? "0123456789abcdef"[r % 16] : r < 40 ? ' ' : r < 45 ? '\n' : r < 50 ? '[' : r < 55 ? ']' : (char)(t_rand64(&seed) & 0xff);
		}
		CHECK_EQ(ksyms_parse(&k, buf, n), 0);
		ksyms_lookup(&k, t_rand64(&seed), NULL);
		ksyms_free(&k);
	}
}

int t_checks, t_failures;
const char *t_current;

int main(void)
{
	printf("kallsyms symbolizer\n");
	T_RUN(test_parse_lookup);
	T_RUN(test_restricted);
	T_RUN(test_random_garbage);
	printf("  %d checks, %d failures\n", t_checks, t_failures);
	return t_failures != 0;
}
