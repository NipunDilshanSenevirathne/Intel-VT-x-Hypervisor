#include <pthread.h>
#include <sched.h>
#include "harness.h"
#include "../../kmod/ring.h"

void vtx_ring_init(struct vtx_ring *r, u32 size);
u64 vtx_ring_bytes(u32 size);

static struct vtx_ring *mk(uint32_t size)
{
	struct vtx_ring *r = aligned_alloc(64, (vtx_ring_bytes(size) + 63) & ~63ull);

	memset(r, 0xa5, vtx_ring_bytes(size));
	vtx_ring_init(r, size);
	return r;
}

static void test_basic(void)
{
	struct vtx_ring *r = mk(8);
	struct vtx_event e, out[16];
	uint32_t i, n;

	memset(&e, 0, sizeof(e));
	CHECK_EQ(sizeof(struct vtx_event), 128);
	CHECK_EQ(vtx_ring_count(r), 0);
	CHECK_EQ(vtx_ring_pop(r, out, 16), 0);
	for (i = 0; i < 8; i++) {
		e.seq = i;
		CHECK_EQ(vtx_ring_push(r, &e), 0);
	}
	e.seq = 99;
	CHECK_EQ(vtx_ring_push(r, &e), -1);
	CHECK_EQ(r->dropped, 1);
	CHECK_EQ(vtx_ring_count(r), 8);
	n = vtx_ring_pop(r, out, 3);
	CHECK_EQ(n, 3);
	CHECK_EQ(out[0].seq, 0);
	CHECK_EQ(out[2].seq, 2);
	for (i = 0; i < 3; i++) {
		e.seq = 100 + i;
		CHECK_EQ(vtx_ring_push(r, &e), 0);
	}
	n = vtx_ring_pop(r, out, 16);
	CHECK_EQ(n, 8);
	CHECK_EQ(out[0].seq, 3);
	CHECK_EQ(out[4].seq, 7);
	CHECK_EQ(out[5].seq, 100);
	CHECK_EQ(out[7].seq, 102);
	CHECK_EQ(vtx_ring_count(r), 0);
	r->size = 0;
	CHECK_EQ(vtx_ring_push(r, &e), -1);
	free(r);
}

#define SPSC_N 2000000ull

struct spsc {
	struct vtx_ring *r;
	uint64_t pushed;
	uint64_t popped;
	uint64_t errors;
	volatile int done;
};

static void *producer(void *arg)
{
	struct spsc *s = arg;
	struct vtx_event e;
	uint64_t i;

	memset(&e, 0, sizeof(e));
	for (i = 0; i < SPSC_N; i++) {
		e.seq = i;
		e.rip = i * 7;
		e.gpa = ~i;
		while (vtx_ring_push(s->r, &e))
			sched_yield();
		s->pushed++;
	}
	__atomic_store_n(&s->done, 1, __ATOMIC_RELEASE);
	return NULL;
}

static void *consumer(void *arg)
{
	struct spsc *s = arg;
	struct vtx_event out[64];
	uint64_t last = 0;
	int first = 1;

	for (;;) {
		int fin = __atomic_load_n(&s->done, __ATOMIC_ACQUIRE);
		uint32_t n = vtx_ring_pop(s->r, out, 64), i;

		for (i = 0; i < n; i++) {
			if ((!first && out[i].seq <= last) || out[i].rip != out[i].seq * 7 || out[i].gpa != ~out[i].seq)
				s->errors++;
			last = out[i].seq;
			first = 0;
		}
		s->popped += n;
		if (fin && !n && !vtx_ring_count(s->r))
			break;
	}
	return NULL;
}

static void test_spsc_threads(void)
{
	struct spsc s;
	pthread_t p, c;

	memset(&s, 0, sizeof(s));
	s.r = mk(256);
	pthread_create(&c, NULL, consumer, &s);
	pthread_create(&p, NULL, producer, &s);
	pthread_join(p, NULL);
	pthread_join(c, NULL);
	CHECK_EQ(s.errors, 0);
	CHECK_EQ(s.pushed, s.popped);
	CHECK_EQ(s.pushed, SPSC_N);
	CHECK_EQ(s.popped, SPSC_N);
	CHECK_EQ(s.r->pushed, s.pushed);
	printf("      %llu events through a 256-slot ring, %llu full-ring retries\n",
	       (unsigned long long)s.popped, (unsigned long long)s.r->dropped);
	free(s.r);
}

int t_checks, t_failures;
const char *t_current;

int main(void)
{
	printf("event ring\n");
	T_RUN(test_basic);
	T_RUN(test_spsc_threads);
	printf("  %d checks, %d failures\n", t_checks, t_failures);
	return t_failures != 0;
}
