#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <inttypes.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <cpuid.h>
#include "fmt.h"
#include "ksyms.h"

#define VTXCTL_VERSION "1.0.0"

static int opt_json;
static volatile sig_atomic_t stop;

static void on_sig(int s)
{
	(void)s;
	stop = 1;
}

static int dev_open(int flags)
{
	int fd = open(VTX_DEVICE_PATH, flags | O_CLOEXEC);

	if (fd < 0) {
		fprintf(stderr, "%svtxctl:%s cannot open %s: %s%s\n", c_red(), c_off(), VTX_DEVICE_PATH, strerror(errno),
			errno == ENOENT ? " (is vtxhv loaded?)" : "");
		exit(2);
	}
	return fd;
}

static int xioctl(int fd, unsigned long req, void *arg, const char *what)
{
	if (ioctl(fd, req, arg) < 0) {
		fprintf(stderr, "%svtxctl:%s %s failed: %s\n", c_red(), c_off(), what, strerror(errno));
		return -1;
	}
	return 0;
}

static uint64_t parse_u64(const char *s)
{
	char *end;
	uint64_t v;

	errno = 0;
	v = strtoull(s, &end, 0);
	if (errno || end == s) {
		fprintf(stderr, "vtxctl: invalid number '%s'\n", s);
		exit(2);
	}
	if (*end == 'k' || *end == 'K')
		v <<= 10;
	else if (*end == 'm' || *end == 'M')
		v <<= 20;
	else if (*end == 'g' || *end == 'G')
		v <<= 30;
	return v;
}

static void kv(const char *k, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void kv(const char *k, const char *fmt, ...)
{
	va_list ap;

	printf("  %s%-18s%s ", c_bold(), k, c_off());
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

static int cmd_status(void)
{
	int fd = dev_open(O_RDONLY);
	struct vtx_status s;
	char feat[512], pins[256], sig[17];
	unsigned i;

	memset(&s, 0, sizeof(s));
	if (xioctl(fd, VTX_IOC_STATUS, &s, "status"))
		return 1;
	close(fd);
	memcpy(sig, s.signature, 16);
	sig[16] = 0;
	feature_format(s.features, feat, sizeof(feat));
	pin_format(s.policy, pins, sizeof(pins));
	if (opt_json) {
		printf("{\"signature\":");
		json_str(stdout, sig);
		printf(",\"abi\":%u,\"online_cpus\":%u,\"virtualized_cpus\":%u,\"locked\":%s,\"policy\":%u,\"pins\":",
		       s.abi, s.online_cpus, s.virt_cpus, s.locked ? "true" : "false", s.policy);
		json_str(stdout, pins);
		printf(",\"features\":");
		json_str(stdout, feat);
		printf(",\"watches\":%u,\"ept_pool_total\":%u,\"ept_pool_used\":%u,\"events\":%llu"
		       ",\"dropped\":%llu,\"tamper\":%llu,\"arena_bytes\":%llu,\"arena_chunks\":%u"
		       ",\"map_limit\":\"%#llx\",\"root_text_pages\":%u,\"root_ro_pages\":%u,\"maxphyaddr\":%u"
		       ",\"paging_levels\":%u,\"arena_pa\":\"%#llx\",\"root_text_pa\":\"%#llx\"}\n",
		       s.nwatch, s.pool_total, s.pool_used, s.events_total, s.events_dropped, s.tamper_count,
		       s.arena_bytes, s.nchunks, s.map_limit, s.host_text_pages, s.ro_pages, s.maxphyaddr, s.paging_levels,
		       s.arena_pa0, s.host_text_pa);
		return 0;
	}
	printf("%s%s Intel VT-x Hypervisor %s %s(%s, ABI %u)%s\n", c_bold(), c_blu(), c_off(), c_dim(), sig, s.abi, c_off());
	kv("state", "%s%s%s on %u/%u CPUs", s.virt_cpus ? c_grn() : c_red(), s.virt_cpus ? "ACTIVE" : "INACTIVE", c_off(),
	   s.virt_cpus, s.online_cpus);
	printf("  %s%-18s%s ", c_bold(), "virtualized", c_off());
	for (i = 0; i < VTX_MAX_CPUS; i++)
		if (s.virt_mask[i / 64] & (1ull << (i % 64)))
			printf("cpu%u ", i);
	printf("\n");
	kv("policy lock", "%s%s%s", s.locked ? c_red() : c_grn(), s.locked ? "ENGAGED (one-way)" : "open", c_off());
	kv("pins", "%s", pins);
	kv("watches", "%u active slot%s", s.nwatch, s.nwatch == 1 ? "" : "s");
	kv("events", "%llu total, %llu dropped, %s%llu tamper attempts%s", s.events_total,
	   s.events_dropped, s.tamper_count ? c_red() : "", s.tamper_count, c_off());
	kv("EPT pool", "%u/%u pages (%.1f%%)", s.pool_used, s.pool_total,
	   s.pool_total ? 100.0 * s.pool_used / s.pool_total : 0.0);
	kv("hypervisor arena", "%llu KiB in %u chunk%s @%#llx (hidden from guest)", s.arena_bytes >> 10,
	   s.nchunks, s.nchunks == 1 ? "" : "s", s.arena_pa0);
	kv("root image", "%u code page%s, %u rodata page%s (write-protected)", s.host_text_pages,
	   s.host_text_pages == 1 ? "" : "s", s.ro_pages, s.ro_pages == 1 ? "" : "s");
	kv("identity map", "0 .. %#llx (on-demand above), MAXPHYADDR %u, host paging %u-level", s.map_limit,
	   s.maxphyaddr, s.paging_levels);
	kv("features", "%s", feat);
	return 0;
}

static int cmd_caps(void)
{
	int fd = dev_open(O_RDONLY);
	struct vtx_caps c;

	memset(&c, 0, sizeof(c));
	if (xioctl(fd, VTX_IOC_CAPS, &c, "caps"))
		return 1;
	close(fd);
	caps_print(stdout, &c, opt_json);
	return 0;
}

static int cmd_check(void)
{
	long n = sysconf(_SC_NPROCESSORS_ONLN), cpu, ok = 0;

	if (opt_json)
		printf("{\"cpus\":[");
	for (cpu = 0; cpu < n; cpu++) {
		cpu_set_t set;
		unsigned a, b, c, d;
		char sig[13];
		int good;

		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		if (sched_setaffinity(0, sizeof(set), &set))
			continue;
		__cpuid(0x40000000, a, b, c, d);
		memcpy(sig, &b, 4);
		memcpy(sig + 4, &c, 4);
		memcpy(sig + 8, &d, 4);
		sig[12] = 0;
		good = !strcmp(sig, VTX_SIGNATURE);
		ok += good;
		if (opt_json) {
			printf("%s{\"cpu\":%ld,\"virtualized\":%s,\"max_leaf\":\"%#x\"}", cpu ? "," : "", cpu,
			       good ? "true" : "false", a);
		} else {
			__cpuid(0x40000001, a, b, c, d);
			printf("  cpu%-3ld %s%-12s%s %s\n", cpu, good ? c_grn() : c_red(), good ? "virtualized" : "native", c_off(),
			       good ? "" : "");
		}
	}
	if (opt_json)
		printf("],\"virtualized\":%ld,\"online\":%ld}\n", ok, n);
	else
		printf("%s%ld/%ld%s CPUs report the %s hypervisor via CPUID 0x40000000\n", ok == n ? c_grn() : c_red(), ok, n,
		       c_off(), VTX_SIGNATURE);
	return ok == n ? 0 : 1;
}

static int cmd_watch(int argc, char **argv)
{
	int fd;

	if (argc < 2) {
		fprintf(stderr, "usage: vtxctl watch add|del|list ...\n");
		return 2;
	}
	if (!strcmp(argv[1], "list")) {
		struct vtx_watch_list l;
		unsigned i;

		fd = dev_open(O_RDONLY);
		memset(&l, 0, sizeof(l));
		if (xioctl(fd, VTX_IOC_WATCH_LIST, &l, "watch list"))
			return 1;
		close(fd);
		if (opt_json)
			printf("[");
		else
			printf("%s%-5s %-6s %-8s %-20s %-20s %-7s %-10s %s%s\n", c_bold(), "ID", "DENY", "MODE", "GPA START",
			       "GPA END", "PAGES", "HITS", "NAME", c_off());
		for (i = 0; i < l.count && i < VTX_MAX_WATCH; i++) {
			struct vtx_watch_info *w = &l.w[i];
			char d[4], name[VTX_NAME_LEN + 1];

			deny_format(w->deny, d);
			memcpy(name, w->name, VTX_NAME_LEN);
			name[VTX_NAME_LEN] = 0;
			if (opt_json) {
				printf("%s{\"id\":%u,\"deny\":\"%s\",\"mode\":\"%s\",\"gpa_start\":\"%#llx\",\"gpa_end\":\"%#llx"
				       "\",\"pages\":%u,\"hits\":%llu,\"name\":", i ? "," : "", w->id, d,
				       w->mode ? "enforce" : "monitor", w->gpa_start, w->gpa_end, w->pages, w->hits);
				json_str(stdout, name);
				printf("}");
			} else {
				printf("%-5u %s%-6s%s %s%-8s%s %#-20llx %#-20llx %-7u %-10llu %s\n", w->id,
				       c_yel(), d, c_off(), w->mode ? c_red() : c_grn(), w->mode ? "enforce" : "monitor", c_off(),
				       w->gpa_start, w->gpa_end, w->pages, w->hits, name);
			}
		}
		if (opt_json)
			printf("]\n");
		return 0;
	}
	if (!strcmp(argv[1], "del")) {
		uint32_t id;

		if (argc < 3) {
			fprintf(stderr, "usage: vtxctl watch del ID\n");
			return 2;
		}
		id = (uint32_t)parse_u64(argv[2]);
		fd = dev_open(O_RDWR);
		if (xioctl(fd, VTX_IOC_WATCH_DEL, &id, "watch del"))
			return 1;
		close(fd);
		printf("watch %u removed\n", id);
		return 0;
	}
	if (!strcmp(argv[1], "add")) {
		static const struct option lo[] = {
			{ "phys", required_argument, 0, 'p' }, { "virt", required_argument, 0, 'v' },
			{ "sym", required_argument, 0, 's' }, { "len", required_argument, 0, 'l' },
			{ "deny", required_argument, 0, 'd' }, { "mode", required_argument, 0, 'm' },
			{ "name", required_argument, 0, 'n' }, { 0, 0, 0, 0 },
		};
		struct vtx_watch_req r;
		const char *sym = NULL;
		int c, have = 0;

		memset(&r, 0, sizeof(r));
		r.deny = VTX_DENY_W;
		r.len = 4096;
		optind = 1;
		while ((c = getopt_long(argc - 1, argv + 1, "p:v:s:l:d:m:n:", lo, NULL)) != -1) {
			switch (c) {
			case 'p':
				r.addr = parse_u64(optarg);
				have = 1;
				break;
			case 'v':
				r.addr = parse_u64(optarg);
				r.flags |= VTX_WF_VIRT;
				have = 1;
				break;
			case 's':
				sym = optarg;
				r.flags |= VTX_WF_VIRT;
				have = 1;
				break;
			case 'l':
				r.len = parse_u64(optarg);
				break;
			case 'd':
				if (deny_parse(optarg, &r.deny)) {
					fprintf(stderr, "vtxctl: --deny takes a combination of r, w, x\n");
					return 2;
				}
				break;
			case 'm':
				if (!strcasecmp(optarg, "enforce"))
					r.mode = VTX_MODE_ENFORCE;
				else if (!strcasecmp(optarg, "monitor"))
					r.mode = VTX_MODE_MONITOR;
				else {
					fprintf(stderr, "vtxctl: --mode is monitor or enforce\n");
					return 2;
				}
				break;
			case 'n':
				snprintf(r.name, sizeof(r.name), "%s", optarg);
				break;
			default:
				return 2;
			}
		}
		if (!have) {
			fprintf(stderr, "usage: vtxctl watch add (--phys A|--virt A|--sym NAME) [--len N] [--deny rwx] [--mode monitor|enforce] [--name N]\n");
			return 2;
		}
		if (sym) {
			struct ksyms k;
			const struct ksym *s;

			if (ksyms_load(&k, "/proc/kallsyms") || !k.usable) {
				fprintf(stderr, "vtxctl: /proc/kallsyms unreadable or addresses hidden (kptr_restrict)\n");
				return 1;
			}
			s = ksyms_find(&k, sym);
			if (!s) {
				fprintf(stderr, "vtxctl: symbol '%s' not found\n", sym);
				ksyms_free(&k);
				return 1;
			}
			r.addr = s->addr;
			if (!r.name[0])
				snprintf(r.name, sizeof(r.name), "%s", sym);
			ksyms_free(&k);
		}
		fd = dev_open(O_RDWR);
		if (xioctl(fd, VTX_IOC_WATCH_ADD, &r, "watch add"))
			return 1;
		close(fd);
		if (opt_json)
			printf("{\"id\":%u}\n", r.id);
		else
			printf("watch %s%u%s armed on %s %#llx +%llu (%s)\n", c_grn(), r.id, c_off(),
			       (r.flags & VTX_WF_VIRT) ? "virtual" : "physical", r.addr, r.len,
			       r.mode ? "enforce" : "monitor");
		return 0;
	}
	fprintf(stderr, "vtxctl: unknown watch subcommand '%s'\n", argv[1]);
	return 2;
}

static int cmd_guard(int argc, char **argv)
{
	struct vtx_guard_req g;
	int fd;

	memset(&g, 0, sizeof(g));
	if (argc < 2) {
		fprintf(stderr, "usage: vtxctl guard text|rodata|idt [monitor|enforce]\n");
		return 2;
	}
	if (!strcmp(argv[1], "text"))
		g.which = VTX_GUARD_KTEXT;
	else if (!strcmp(argv[1], "rodata"))
		g.which = VTX_GUARD_KRODATA;
	else if (!strcmp(argv[1], "idt"))
		g.which = VTX_GUARD_IDT;
	else {
		fprintf(stderr, "vtxctl: unknown guard '%s'\n", argv[1]);
		return 2;
	}
	if (argc > 2 && !strcasecmp(argv[2], "enforce"))
		g.mode = VTX_MODE_ENFORCE;
	fd = dev_open(O_RDWR);
	if (xioctl(fd, VTX_IOC_GUARD, &g, "guard"))
		return 1;
	close(fd);
	printf("guard %s armed as watch %s%u%s (%s)\n", argv[1], c_grn(), g.id, c_off(), g.mode ? "enforce" : "monitor");
	return 0;
}

static int cmd_pin(int argc, char **argv, int clear)
{
	struct vtx_policy p;
	uint32_t mask;
	char buf[256];
	int fd;

	if (argc < 2 || pin_parse(argv[1], &mask)) {
		fprintf(stderr, "usage: vtxctl %s cr0.wp,cr4.smep,cr4.smap,cr4.umip,msr.syscall,msr.sysenter,msr.efer,idtr,gdtr,tr|cr|msr|dtr|all\n",
			clear ? "unpin" : "pin");
		return 2;
	}
	memset(&p, 0, sizeof(p));
	if (clear)
		p.clear = mask;
	else
		p.set = mask;
	fd = dev_open(O_RDWR);
	if (ioctl(fd, VTX_IOC_POLICY, &p) < 0) {
		int e = errno;

		fprintf(stderr, "%svtxctl:%s %s failed: %s\n", c_red(), c_off(), clear ? "unpin" : "pin", strerror(e));
		if (e == EOPNOTSUPP)
			fprintf(stderr, "        idtr/gdtr/tr pins need descriptor-table exiting; load vtxhv with dtexit=1 on a CPU that supports it\n");
		else if (e == EPERM)
			fprintf(stderr, "        the policy is locked; pins can be added but never removed until reboot\n");
		return 1;
	}
	close(fd);
	pin_format(p.result, buf, sizeof(buf));
	printf("active pins: %s%s%s\n", c_grn(), buf, c_off());
	return 0;
}

static int cmd_lock(int argc, char **argv)
{
	int fd;

	if (argc < 2 || strcmp(argv[1], "--yes")) {
		fprintf(stderr, "vtxctl lock is irreversible until reboot: the hypervisor can no longer be unloaded,\n"
				"pins/watches cannot be removed and CPUs cannot be taken offline. Re-run with --yes.\n");
		return 2;
	}
	fd = dev_open(O_RDWR);
	if (xioctl(fd, VTX_IOC_LOCK, NULL, "lock"))
		return 1;
	close(fd);
	printf("%spolicy lock engaged%s\n", c_red(), c_off());
	return 0;
}

static int cmd_events(int argc, char **argv)
{
	static const struct option lo[] = {
		{ "follow", no_argument, 0, 'f' }, { "count", required_argument, 0, 'c' },
		{ "no-sym", no_argument, 0, 'S' }, { 0, 0, 0, 0 },
	};
	struct vtx_event ev[256];
	struct ksyms k;
	int follow = 0, sym = 1, c, fd;
	long max = -1, seen = 0;

	optind = 1;
	while ((c = getopt_long(argc, argv, "fc:S", lo, NULL)) != -1) {
		switch (c) {
		case 'f':
			follow = 1;
			break;
		case 'c':
			max = (long)parse_u64(optarg);
			break;
		case 'S':
			sym = 0;
			break;
		default:
			return 2;
		}
	}
	memset(&k, 0, sizeof(k));
	if (sym)
		ksyms_load(&k, "/proc/kallsyms");
	fd = dev_open(O_RDONLY | (follow ? 0 : O_NONBLOCK));
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);
	if (!opt_json && !follow)
		printf("%s%-7s %-5s %-10s %-7s %-22s %-34s %s%s\n", c_bold(), "SEQ", "CPU", "TYPE", "ACTION", "TASK", "RIP",
		       "DETAIL", c_off());
	while (!stop && (max < 0 || seen < max)) {
		ssize_t n = read(fd, ev, sizeof(ev));
		ssize_t i;

		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				break;
			fprintf(stderr, "vtxctl: read: %s\n", strerror(errno));
			break;
		}
		for (i = 0; i < n / (ssize_t)sizeof(ev[0]) && (max < 0 || seen < max); i++, seen++) {
			if (opt_json)
				ev_print_json(stdout, &ev[i], &k);
			else
				ev_print_text(stdout, &ev[i], &k, 0);
		}
		fflush(stdout);
	}
	close(fd);
	ksyms_free(&k);
	return 0;
}

static int cmd_stats(void)
{
	struct vtx_stats s;
	unsigned long long total = 0;
	unsigned i;
	int fd = dev_open(O_RDONLY);

	memset(&s, 0, sizeof(s));
	if (xioctl(fd, VTX_IOC_STATS, &s, "stats"))
		return 1;
	close(fd);
	for (i = 0; i < VTX_EXIT_REASONS; i++)
		total += s.exits[i];
	if (opt_json) {
		const char *sep = "";

		printf("{\"total_exits\":%llu,\"reasons\":{", total);
		for (i = 0; i < VTX_EXIT_REASONS; i++) {
			if (!s.exits[i])
				continue;
			printf("%s\"%s\":{\"count\":%llu,\"avg_cycles\":%llu}", sep, exit_reason_name(i), s.exits[i],
			       s.cycles[i] / s.exits[i]);
			sep = ",";
		}
		printf("},\"nmi_reflected\":%llu,\"mtf_steps\":%llu,\"spurious_ept\":%llu"
		       ",\"hypercalls\":%llu,\"injected\":%llu,\"events\":%llu,\"dropped\":%llu"
		       ",\"step_shadows\":%llu,\"step_recycles\":%llu,\"emulator_denied\":%llu}\n",
		       s.nmi_reflected, s.steps, s.spurious_ept, s.hypercalls, s.injected, s.events, s.dropped,
		       s.step_shadows, s.step_recycles, s.emul_denied);
		return 0;
	}
	printf("%s%-26s %12s %8s %14s%s\n", c_bold(), "VM-EXIT REASON", "COUNT", "SHARE", "AVG CYCLES", c_off());
	for (i = 0; i < VTX_EXIT_REASONS; i++) {
		double share;
		int bar, j;

		if (!s.exits[i])
			continue;
		share = total ? 100.0 * s.exits[i] / total : 0;
		printf("%-26s %12llu %7.2f%% %14llu  %s", exit_reason_name(i), s.exits[i], share,
		       s.cycles[i] / s.exits[i], c_cyn());
		bar = (int)(share / 4);
		for (j = 0; j < bar; j++)
			printf("█");
		printf("%s\n", c_off());
	}
	printf("%s%-26s %12llu%s\n", c_bold(), "TOTAL", total, c_off());
	printf("\nper-CPU exits:");
	for (i = 0; i < 64 && i < s.ncpus; i++)
		printf(" cpu%u=%llu", i, s.cpu_exits[i]);
	printf("\nNMIs reflected %llu, MTF steps %llu (interrupt-shadowed %llu, recycled %llu), spurious EPT %llu"
	       ", hypercalls %llu, injected %llu, emulator writes denied %llu, events %llu (dropped %llu)\n",
	       s.nmi_reflected, s.steps, s.step_shadows, s.step_recycles, s.spurious_ept, s.hypercalls, s.injected,
	       s.emul_denied, s.events, s.dropped);
	return 0;
}

static void usage(void)
{
	printf("%sIntel VT-x Hypervisor control%s  vtxctl " VTXCTL_VERSION "\n\n"
	       "usage: vtxctl [--json] [--color|--no-color] <command> [args]\n\n"
	       "  status                         hypervisor state, policy, memory, features\n"
	       "  check                          verify every CPU runs under the hypervisor (CPUID)\n"
	       "  caps                           decode the CPU's VMX capability MSRs\n"
	       "  watch add --phys|--virt|--sym ADDR [--len N] [--deny rwx] [--mode monitor|enforce] [--name N]\n"
	       "  watch del ID | watch list      manage EPT watches\n"
	       "  guard text|rodata|idt [enforce]  write-protect kernel text/rodata or the IDT\n"
	       "  pin LIST | unpin LIST          cr0.wp cr4.smep cr4.smap cr4.umip msr.syscall msr.sysenter msr.efer idtr gdtr tr\n"
	       "  lock --yes                     engage the one-way policy lock\n"
	       "  events [-f] [-c N] [--no-sym]  stream introspection events\n"
	       "  stats                          VM-exit profile\n"
	       "  version\n", c_bold(), c_off());
}

int main(int argc, char **argv)
{
	int i = 1;

	fmt_color = isatty(1);
	for (; i < argc && argv[i][0] == '-' && argv[i][1] == '-'; i++) {
		if (!strcmp(argv[i], "--json"))
			opt_json = 1;
		else if (!strcmp(argv[i], "--color"))
			fmt_color = 1;
		else if (!strcmp(argv[i], "--no-color"))
			fmt_color = 0;
		else if (!strcmp(argv[i], "--help")) {
			usage();
			return 0;
		} else
			break;
	}
	if (opt_json)
		fmt_color = 0;
	if (i >= argc) {
		usage();
		return 2;
	}
	argc -= i;
	argv += i;
	if (!strcmp(argv[0], "status"))
		return cmd_status();
	if (!strcmp(argv[0], "caps"))
		return cmd_caps();
	if (!strcmp(argv[0], "check"))
		return cmd_check();
	if (!strcmp(argv[0], "watch"))
		return cmd_watch(argc, argv);
	if (!strcmp(argv[0], "guard"))
		return cmd_guard(argc, argv);
	if (!strcmp(argv[0], "pin"))
		return cmd_pin(argc, argv, 0);
	if (!strcmp(argv[0], "unpin"))
		return cmd_pin(argc, argv, 1);
	if (!strcmp(argv[0], "lock"))
		return cmd_lock(argc, argv);
	if (!strcmp(argv[0], "events"))
		return cmd_events(argc, argv);
	if (!strcmp(argv[0], "stats"))
		return cmd_stats();
	if (!strcmp(argv[0], "version")) {
		printf("vtxctl " VTXCTL_VERSION " (ABI %d)\n", VTX_ABI_VERSION);
		return 0;
	}
	if (!strcmp(argv[0], "help")) {
		usage();
		return 0;
	}
	fprintf(stderr, "vtxctl: unknown command '%s'\n", argv[0]);
	usage();
	return 2;
}
