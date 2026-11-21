#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <sched.h>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <asm/ldt.h>

static sigjmp_buf jb;
static volatile int last_sig;

static void on_sig(int s)
{
	last_sig = s;
	siglongjmp(jb, 1);
}

static void report(const char *name, int ok, const char *detail)
{
	printf("TEST %s %s %s\n", name, ok ? "PASS" : "FAIL", detail ? detail : "");
	fflush(stdout);
}

static int test_vmcall_user(void)
{
	char d[64];

	last_sig = 0;
	signal(SIGILL, on_sig);
	signal(SIGSEGV, on_sig);
	if (!sigsetjmp(jb, 1)) {
		uint64_t a = 0x5654480000000001ull;

		asm volatile("vmcall" : "+a"(a) : : "rbx", "rcx", "rdx", "memory");
	}
	snprintf(d, sizeof(d), "signal=%d", last_sig);
	report("user_vmcall_ud", last_sig == SIGILL, d);
	return 0;
}

static int test_vmx_user(void)
{
	char d[64];
	uint64_t pa = 0;

	last_sig = 0;
	signal(SIGILL, on_sig);
	signal(SIGSEGV, on_sig);
	if (!sigsetjmp(jb, 1))
		asm volatile("vmxon %0" : : "m"(pa) : "cc", "memory");
	snprintf(d, sizeof(d), "signal=%d", last_sig);
	report("user_vmxon_faults", last_sig == SIGILL || last_sig == SIGSEGV, d);
	return 0;
}

static int cpu_has_flag(const char *flag)
{
	char line[8192], pat[64];
	FILE *f = fopen("/proc/cpuinfo", "r");
	int found = 0;

	if (!f)
		return 0;
	snprintf(pat, sizeof(pat), " %s", flag);
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "flags", 5)) {
			char *p = strstr(line, pat);

			found = p && (p[strlen(pat)] == ' ' || p[strlen(pat)] == '\n');
			break;
		}
	}
	fclose(f);
	return found;
}

static int test_desc_stores(void)
{
	struct __attribute__((packed)) { uint16_t lim; uint64_t base; } g = { 0 }, i = { 0 };
	uint16_t tr = 0xffff, ldt = 0xffff;
	char d[160];

	last_sig = 0;
	signal(SIGSEGV, on_sig);
	signal(SIGILL, on_sig);
	if (!sigsetjmp(jb, 1)) {
		asm volatile("sgdt %0" : "=m"(g));
		asm volatile("sidt %0" : "=m"(i));
		asm volatile("str %0" : "=r"(tr));
		asm volatile("sldt %0" : "=r"(ldt));
	}
	snprintf(d, sizeof(d), "sig=%d gdt=%#llx/%#x idt=%#llx/%#x tr=%#x ldt=%#x", last_sig,
		 (unsigned long long)g.base, g.lim, (unsigned long long)i.base, i.lim, tr, ldt);
	if (cpu_has_flag("umip"))
		report("user_desc_stores_umip_guest_emulated", last_sig == SIGSEGV ||
		       (!last_sig && g.base == 0xfffffffffffe0000ull && g.lim == 0 && i.base == 0xffffffffffff0000ull), d);
	else
		report("user_desc_stores_hypervisor_emulated", !last_sig && g.lim != 0 && i.lim != 0 && tr != 0xffff &&
		       (g.base >> 47) == 0x1ffff && (i.base >> 47) == 0x1ffff, d);
	return 0;
}

static int set_ldt_entry(int idx, uint32_t base, uint32_t limit)
{
	struct user_desc u;

	memset(&u, 0, sizeof(u));
	u.entry_number = idx;
	u.base_addr = base;
	u.limit = limit;
	u.seg_32bit = 1;
	u.contents = 0;
	u.read_exec_only = 0;
	u.limit_in_pages = 0;
	u.seg_not_present = 0;
	u.useable = 1;
	return (int)syscall(SYS_modify_ldt, 1, &u, sizeof(u));
}

static int ldt_limit(int idx, uint32_t *lim)
{
	uint32_t l = 0;
	uint8_t ok = 0;
	uint32_t sel = (uint32_t)(idx << 3) | 4 | 3;

	asm volatile("lsl %2, %0\n\tsetz %1" : "=r"(l), "=q"(ok) : "r"(sel) : "cc");
	*lim = l;
	return ok;
}

static int test_ldt(int rounds)
{
	int i, bad = 0, pid;
	char d[96];

	if (set_ldt_entry(3, 0x1000, 0x1234)) {
		report("ldt_context_switch", 0, "modify_ldt failed");
		return 0;
	}
	pid = fork();
	if (pid == 0) {
		for (i = 0; i < rounds; i++)
			sched_yield();
		_exit(0);
	}
	for (i = 0; i < rounds; i++) {
		uint32_t l;

		sched_yield();
		if (!ldt_limit(3, &l) || l != 0x1234)
			bad++;
		if (i % 64 == 0 && set_ldt_entry(3, 0x1000, 0x1234))
			bad++;
	}
	waitpid(pid, NULL, 0);
	snprintf(d, sizeof(d), "rounds=%d mismatches=%d", rounds, bad);
	report("ldt_context_switch", bad == 0, d);
	return 0;
}

static int test_cpuid(void)
{
	unsigned a, b, c, d;
	char sig[13];

	asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0x40000000), "c"(0));
	memcpy(sig, &b, 4);
	memcpy(sig + 4, &c, 4);
	memcpy(sig + 8, &d, 4);
	sig[12] = 0;
	report("user_cpuid_signature", !strcmp(sig, "VtxHvIntrspc") && a >= 0x40000001, sig);
	asm volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
	report("user_cpuid_hides_vmx", !((c >> 5) & 1) && ((c >> 31) & 1), NULL);
	return 0;
}

int main(int argc, char **argv)
{
	int rounds = argc > 1 ? atoi(argv[1]) : 2000;

	test_cpuid();
	test_vmcall_user();
	test_vmx_user();
	test_desc_stores();
	test_ldt(rounds);
	return 0;
}
