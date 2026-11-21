#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <ctype.h>
#include "fmt.h"

int fmt_color;

const char *c_red(void) { return fmt_color ? "\033[1;31m" : ""; }
const char *c_grn(void) { return fmt_color ? "\033[1;32m" : ""; }
const char *c_yel(void) { return fmt_color ? "\033[1;33m" : ""; }
const char *c_blu(void) { return fmt_color ? "\033[1;34m" : ""; }
const char *c_mag(void) { return fmt_color ? "\033[1;35m" : ""; }
const char *c_cyn(void) { return fmt_color ? "\033[1;36m" : ""; }
const char *c_dim(void) { return fmt_color ? "\033[2m" : ""; }
const char *c_bold(void) { return fmt_color ? "\033[1m" : ""; }
const char *c_off(void) { return fmt_color ? "\033[0m" : ""; }

static const char *const ev_names[VTX_EV_MAX] = {
	[VTX_EV_NONE] = "none",
	[VTX_EV_EPT_READ] = "ept-read",
	[VTX_EV_EPT_WRITE] = "ept-write",
	[VTX_EV_EPT_EXEC] = "ept-exec",
	[VTX_EV_TAMPER] = "tamper",
	[VTX_EV_CR0] = "cr0",
	[VTX_EV_CR4] = "cr4",
	[VTX_EV_MSR] = "msr-write",
	[VTX_EV_DTR] = "dtr",
	[VTX_EV_VMX] = "vmx-insn",
	[VTX_EV_HYPERCALL] = "hypercall",
	[VTX_EV_INIT] = "init-signal",
};

const char *ev_type_name(uint32_t t)
{
	return t < VTX_EV_MAX && ev_names[t] ? ev_names[t] : "unknown";
}

static const char *const exit_names[] = {
	"EXCEPTION_NMI", "EXTERNAL_INTERRUPT", "TRIPLE_FAULT", "INIT", "SIPI", "IO_SMI", "OTHER_SMI",
	"INTERRUPT_WINDOW", "NMI_WINDOW", "TASK_SWITCH", "CPUID", "GETSEC", "HLT", "INVD", "INVLPG",
	"RDPMC", "RDTSC", "RSM", "VMCALL", "VMCLEAR", "VMLAUNCH", "VMPTRLD", "VMPTRST", "VMREAD",
	"VMRESUME", "VMWRITE", "VMXOFF", "VMXON", "CR_ACCESS", "DR_ACCESS", "IO_INSTRUCTION",
	"MSR_READ", "MSR_WRITE", "INVALID_GUEST_STATE", "MSR_LOAD_FAIL", "RESERVED_35", "MWAIT",
	"MONITOR_TRAP_FLAG", "RESERVED_38", "MONITOR", "PAUSE", "MCE_DURING_ENTRY", "RESERVED_42",
	"TPR_BELOW_THRESHOLD", "APIC_ACCESS", "VIRTUALIZED_EOI", "GDTR_IDTR", "LDTR_TR",
	"EPT_VIOLATION", "EPT_MISCONFIG", "INVEPT", "RDTSCP", "PREEMPTION_TIMER", "INVVPID",
	"WBINVD", "XSETBV", "APIC_WRITE", "RDRAND", "INVPCID", "VMFUNC", "ENCLS", "RDSEED",
	"PML_FULL", "XSAVES", "XRSTORS", "PCONFIG", "SPP", "UMWAIT", "TPAUSE", "LOADIWKEY",
	"ENCLV", "RESERVED_71", "ENQCMD_PASID", "ENQCMDS_PASID", "BUS_LOCK", "NOTIFY", "SEAMCALL",
	"TDCALL", "RDMSRLIST", "WRMSRLIST",
};

const char *exit_reason_name(unsigned r)
{
	return r < sizeof(exit_names) / sizeof(exit_names[0]) ? exit_names[r] : "UNKNOWN";
}

const char *msr_name(uint32_t msr)
{
	switch (msr) {
	case 0x174: return "IA32_SYSENTER_CS";
	case 0x175: return "IA32_SYSENTER_ESP";
	case 0x176: return "IA32_SYSENTER_EIP";
	case 0x1d9: return "IA32_DEBUGCTL";
	case 0xc0000080: return "IA32_EFER";
	case 0xc0000081: return "IA32_STAR";
	case 0xc0000082: return "IA32_LSTAR";
	case 0xc0000083: return "IA32_CSTAR";
	case 0xc0000084: return "IA32_FMASK";
	case 0xc0000100: return "IA32_FS_BASE";
	case 0xc0000101: return "IA32_GS_BASE";
	case 0xc0000102: return "IA32_KERNEL_GS_BASE";
	default: return "MSR";
	}
}

const char *dtr_op_name(unsigned op)
{
	static const char *const n[] = { "SGDT", "SIDT", "LGDT", "LIDT", "SLDT", "STR", "LLDT", "LTR" };

	return op < 8 ? n[op] : "?";
}

static const struct { uint32_t bit; const char *name; } pins[] = {
	{ VTX_PIN_CR0_WP, "cr0.wp" },
	{ VTX_PIN_CR4_SMEP, "cr4.smep" },
	{ VTX_PIN_CR4_SMAP, "cr4.smap" },
	{ VTX_PIN_CR4_UMIP, "cr4.umip" },
	{ VTX_PIN_MSR_SYSCALL, "msr.syscall" },
	{ VTX_PIN_MSR_SYSENTER, "msr.sysenter" },
	{ VTX_PIN_MSR_EFER, "msr.efer" },
	{ VTX_PIN_IDTR, "idtr" },
	{ VTX_PIN_GDTR, "gdtr" },
	{ VTX_PIN_TR, "tr" },
};

const char *pin_name(unsigned bit)
{
	size_t i;

	for (i = 0; i < sizeof(pins) / sizeof(pins[0]); i++)
		if (pins[i].bit == bit)
			return pins[i].name;
	return "?";
}

int pin_parse(const char *list, uint32_t *mask)
{
	char buf[512], *tok, *save = NULL;
	size_t i;

	*mask = 0;
	if (!list || strlen(list) >= sizeof(buf))
		return -1;
	strcpy(buf, list);
	for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		int found = 0;

		while (*tok == ' ')
			tok++;
		if (!strcasecmp(tok, "all")) {
			*mask |= VTX_PIN_ALL;
			continue;
		}
		if (!strcasecmp(tok, "cr")) {
			*mask |= VTX_PIN_CR0_WP | VTX_PIN_CR4_SMEP | VTX_PIN_CR4_SMAP;
			continue;
		}
		if (!strcasecmp(tok, "msr")) {
			*mask |= VTX_PIN_MSR_SYSCALL | VTX_PIN_MSR_SYSENTER | VTX_PIN_MSR_EFER;
			continue;
		}
		if (!strcasecmp(tok, "dtr")) {
			*mask |= VTX_PIN_IDTR | VTX_PIN_GDTR | VTX_PIN_TR;
			continue;
		}
		for (i = 0; i < sizeof(pins) / sizeof(pins[0]); i++) {
			if (!strcasecmp(tok, pins[i].name)) {
				*mask |= pins[i].bit;
				found = 1;
			}
		}
		if (!found)
			return -1;
	}
	return *mask ? 0 : -1;
}

void pin_format(uint32_t mask, char *buf, size_t len)
{
	size_t i, n = 0;

	buf[0] = 0;
	for (i = 0; i < sizeof(pins) / sizeof(pins[0]); i++) {
		if (!(mask & pins[i].bit))
			continue;
		n += (size_t)snprintf(buf + n, n < len ? len - n : 0, "%s%s", n ? "," : "", pins[i].name);
	}
	if (!n)
		snprintf(buf, len, "none");
}

int deny_parse(const char *s, uint32_t *deny)
{
	*deny = 0;
	if (!s || !*s)
		return -1;
	for (; *s; s++) {
		switch (tolower((unsigned char)*s)) {
		case 'r':
			*deny |= VTX_DENY_R;
			break;
		case 'w':
			*deny |= VTX_DENY_W;
			break;
		case 'x':
			*deny |= VTX_DENY_X;
			break;
		default:
			return -1;
		}
	}
	return 0;
}

void deny_format(uint32_t deny, char *buf)
{
	buf[0] = (deny & VTX_DENY_R) ? 'r' : '-';
	buf[1] = (deny & VTX_DENY_W) ? 'w' : '-';
	buf[2] = (deny & VTX_DENY_X) ? 'x' : '-';
	buf[3] = 0;
}

void feature_format(uint32_t f, char *buf, size_t len)
{
	static const struct { uint32_t bit; const char *name; } feats[] = {
		{ VTX_FEAT_EPT_1G, "ept-1g" }, { VTX_FEAT_EPT_2M, "ept-2m" }, { VTX_FEAT_VPID, "vpid" },
		{ VTX_FEAT_VNMI, "virtual-nmi" }, { VTX_FEAT_DTEXIT, "dt-exiting" },
		{ VTX_FEAT_UNRESTRICTED, "unrestricted" }, { VTX_FEAT_EXEC_ONLY, "exec-only" },
		{ VTX_FEAT_MTF, "mtf" }, { VTX_FEAT_INVPCID, "invpcid" }, { VTX_FEAT_XSAVES, "xsaves" },
		{ VTX_FEAT_RDTSCP, "rdtscp" }, { VTX_FEAT_WAITPKG, "waitpkg" }, { VTX_FEAT_LA57, "la57" },
		{ VTX_FEAT_TRUE_CTLS, "true-ctls" }, { VTX_FEAT_PTI, "pti" }, { VTX_FEAT_EPT_WB, "ept-wb" },
		{ VTX_FEAT_CR3_EXITS, "cr3-exits" }, { VTX_FEAT_INTROSPECT, "introspection" },
		{ VTX_FEAT_SERIAL, "uart" },
	};
	size_t i, n = 0;

	buf[0] = 0;
	for (i = 0; i < sizeof(feats) / sizeof(feats[0]); i++)
		if (f & feats[i].bit)
			n += (size_t)snprintf(buf + n, n < len ? len - n : 0, "%s%s", n ? " " : "", feats[i].name);
}

void ev_access(const struct vtx_event *e, char *buf)
{
	uint64_t q = e->info;

	buf[0] = (q & 1) ? 'r' : '-';
	buf[1] = (q & 2) ? 'w' : '-';
	buf[2] = (q & 4) ? 'x' : '-';
	buf[3] = 0;
}

void ev_symbol(const struct ksyms *k, uint64_t addr, char *buf, size_t len)
{
	uint64_t off = 0;
	const struct ksym *s = k ? ksyms_lookup(k, addr, &off) : NULL;

	if (!s) {
		snprintf(buf, len, "%#llx", (unsigned long long)addr);
		return;
	}
	if (s->mod)
		snprintf(buf, len, "%s+%#llx [%s]", s->name, (unsigned long long)off, s->mod);
	else
		snprintf(buf, len, "%s+%#llx", s->name, (unsigned long long)off);
}

static const char *ev_emul(const struct vtx_event *e)
{
	return (e->flags & VTX_EVF_EMUL) ? " via-emulator" : "";
}

static void ev_detail(const struct vtx_event *e, char *buf, size_t len)
{
	char acc[4];

	switch (e->type) {
	case VTX_EV_EPT_READ:
	case VTX_EV_EPT_WRITE:
	case VTX_EV_EPT_EXEC:
		ev_access(e, acc);
		if (e->type == VTX_EV_EPT_WRITE && (e->flags & VTX_EVF_NEWVAL))
			snprintf(buf, len, "watch=%u gpa=%#llx gla=%#llx acc=%s old=%#018llx new=%#018llx%s%s",
				 e->watch_id, e->gpa, e->gla, acc, e->old_val, e->new_val,
				 (e->flags & VTX_EVF_PAGEWALK) ? " pagewalk" : "", ev_emul(e));
		else
			snprintf(buf, len, "watch=%u gpa=%#llx gla=%#llx acc=%s%s%s",
				 e->watch_id, e->gpa, e->gla, acc, (e->flags & VTX_EVF_PAGEWALK) ? " pagewalk" : "",
				 ev_emul(e));
		break;
	case VTX_EV_TAMPER:
		ev_access(e, acc);
		snprintf(buf, len, "target=%s gpa=%#llx gla=%#llx acc=%s attempted=%#018llx%s",
			 e->watch_id == 2 ? "hypervisor-memory" : "hypervisor-image", e->gpa, e->gla, acc, e->new_val,
			 ev_emul(e));
		break;
	case VTX_EV_CR0:
		snprintf(buf, len, "cr0 %#llx -> %#llx (WP %u->%u)", e->old_val, e->new_val,
			 (unsigned)((e->old_val >> 16) & 1), (unsigned)((e->new_val >> 16) & 1));
		break;
	case VTX_EV_CR4:
		snprintf(buf, len, "cr4 %#llx -> %#llx (SMEP %u->%u SMAP %u->%u)", e->old_val, e->new_val,
			 (unsigned)((e->old_val >> 20) & 1), (unsigned)((e->new_val >> 20) & 1),
			 (unsigned)((e->old_val >> 21) & 1), (unsigned)((e->new_val >> 21) & 1));
		break;
	case VTX_EV_MSR:
		snprintf(buf, len, "%s(%#llx) %#llx -> %#llx", msr_name((uint32_t)e->info), e->info,
			 e->old_val, e->new_val);
		break;
	case VTX_EV_DTR:
		snprintf(buf, len, "%s %#llx -> %#llx limit=%#llx", dtr_op_name(e->info & 0xff),
			 e->old_val, e->new_val, e->info >> 16);
		break;
	case VTX_EV_VMX:
		snprintf(buf, len, "%s executed by guest", exit_reason_name((unsigned)e->info));
		break;
	case VTX_EV_HYPERCALL:
		if (e->flags & VTX_EVF_EMUL)
			snprintf(buf, len, "hypercall %#llx refused: output buffer %#llx overlaps protected page %#llx",
				 e->info, e->gpa, e->new_val);
		else
			snprintf(buf, len, "unprivileged hypercall %#llx", e->info);
		break;
	default:
		snprintf(buf, len, "info=%#llx", e->info);
		break;
	}
}

void ev_print_text(FILE *o, const struct vtx_event *e, const struct ksyms *k, uint64_t tsc0)
{
	char sym[256], det[320], task[48];
	int denied = (e->flags & VTX_EVF_DENIED) != 0;
	const char *col = denied ? c_red() : (e->type == VTX_EV_TAMPER ? c_mag() : c_yel());

	ev_symbol(k, e->rip, sym, sizeof(sym));
	ev_detail(e, det, sizeof(det));
	if (e->flags & VTX_EVF_TASK)
		snprintf(task, sizeof(task), "%d/%.15s", e->pid, e->comm);
	else
		snprintf(task, sizeof(task), "-");
	fprintf(o, "%s#%-6llu%s cpu%-2u %s%-10s%s %s%-7s%s %-22s %s%s%s  %s\n",
		c_dim(), e->seq, c_off(), e->cpu, col, ev_type_name(e->type), c_off(),
		denied ? c_red() : c_grn(), denied ? "DENIED" : "allowed", c_off(), task,
		c_cyn(), sym, c_off(), det);
	(void)tsc0;
}

void json_str(FILE *o, const char *s)
{
	fputc('"', o);
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\')
			fprintf(o, "\\%c", c);
		else if (c < 0x20)
			fprintf(o, "\\u%04x", c);
		else
			fputc(c, o);
	}
	fputc('"', o);
}

void ev_print_json(FILE *o, const struct vtx_event *e, const struct ksyms *k)
{
	char sym[256], comm[17];

	ev_symbol(k, e->rip, sym, sizeof(sym));
	memcpy(comm, e->comm, 16);
	comm[16] = 0;
	fprintf(o, "{\"seq\":%llu,\"tsc\":%llu,\"cpu\":%u,\"type\":\"%s\",\"denied\":%s,"
		"\"rip\":\"%#llx\",\"symbol\":",
		e->seq, e->tsc, e->cpu, ev_type_name(e->type), (e->flags & VTX_EVF_DENIED) ? "true" : "false", e->rip);
	json_str(o, sym);
	fprintf(o, ",\"rsp\":\"%#llx\",\"cr3\":\"%#llx\",\"gpa\":\"%#llx\",\"gla\":\"%#llx\","
		"\"old\":\"%#llx\",\"new\":\"%#llx\",\"info\":\"%#llx\",\"watch\":%u,\"user\":%s",
		e->rsp, e->cr3, e->gpa, e->gla, e->old_val, e->new_val, e->info, e->watch_id,
		(e->flags & VTX_EVF_USER) ? "true" : "false");
	if (e->flags & VTX_EVF_TASK) {
		fprintf(o, ",\"pid\":%d,\"comm\":", e->pid);
		json_str(o, comm);
	}
	if (e->flags & VTX_EVF_EMUL)
		fprintf(o, ",\"emulated\":true");
	fprintf(o, "}\n");
}

const struct bitname pin_ctl_bits[] = {
	{ 0, "External-interrupt exiting" }, { 3, "NMI exiting" }, { 5, "Virtual NMIs" },
	{ 6, "VMX-preemption timer" }, { 7, "Posted interrupts" }, { 99, NULL },
};

const struct bitname proc_ctl_bits[] = {
	{ 2, "Interrupt-window exiting" }, { 3, "Use TSC offsetting" }, { 7, "HLT exiting" },
	{ 9, "INVLPG exiting" }, { 10, "MWAIT exiting" }, { 11, "RDPMC exiting" }, { 12, "RDTSC exiting" },
	{ 15, "CR3-load exiting" }, { 16, "CR3-store exiting" }, { 17, "Activate tertiary controls" },
	{ 19, "CR8-load exiting" }, { 20, "CR8-store exiting" }, { 21, "Use TPR shadow" },
	{ 22, "NMI-window exiting" }, { 23, "MOV-DR exiting" }, { 24, "Unconditional I/O exiting" },
	{ 25, "Use I/O bitmaps" }, { 27, "Monitor trap flag" }, { 28, "Use MSR bitmaps" },
	{ 29, "MONITOR exiting" }, { 30, "PAUSE exiting" }, { 31, "Activate secondary controls" },
	{ 99, NULL },
};

const struct bitname proc2_ctl_bits[] = {
	{ 0, "Virtualize APIC accesses" }, { 1, "Enable EPT" }, { 2, "Descriptor-table exiting" },
	{ 3, "Enable RDTSCP" }, { 4, "Virtualize x2APIC mode" }, { 5, "Enable VPID" },
	{ 6, "WBINVD exiting" }, { 7, "Unrestricted guest" }, { 8, "APIC-register virtualization" },
	{ 9, "Virtual-interrupt delivery" }, { 10, "PAUSE-loop exiting" }, { 11, "RDRAND exiting" },
	{ 12, "Enable INVPCID" }, { 13, "Enable VM functions" }, { 14, "VMCS shadowing" },
	{ 15, "Enable ENCLS exiting" }, { 16, "RDSEED exiting" }, { 17, "Enable PML" },
	{ 18, "EPT-violation #VE" }, { 19, "Conceal VMX from PT" }, { 20, "Enable XSAVES/XRSTORS" },
	{ 21, "PASID translation" }, { 22, "Mode-based execute control" }, { 23, "Sub-page write permissions" },
	{ 24, "PT uses guest-physical addresses" }, { 25, "Use TSC scaling" }, { 26, "Enable user wait and pause" },
	{ 27, "Enable PCONFIG" }, { 28, "Enable ENCLV exiting" }, { 30, "VMM bus-lock detection" },
	{ 31, "Instruction timeout" }, { 99, NULL },
};

const struct bitname exit_ctl_bits[] = {
	{ 2, "Save debug controls" }, { 9, "Host address-space size" }, { 12, "Load IA32_PERF_GLOBAL_CTRL" },
	{ 15, "Acknowledge interrupt on exit" }, { 18, "Save IA32_PAT" }, { 19, "Load IA32_PAT" },
	{ 20, "Save IA32_EFER" }, { 21, "Load IA32_EFER" }, { 22, "Save VMX-preemption timer value" },
	{ 23, "Clear IA32_BNDCFGS" }, { 24, "Conceal VMX from PT" }, { 25, "Clear IA32_RTIT_CTL" },
	{ 26, "Clear IA32_LBR_CTL" }, { 28, "Load CET state" }, { 29, "Load PKRS" },
	{ 31, "Activate secondary controls" }, { 99, NULL },
};

const struct bitname entry_ctl_bits[] = {
	{ 2, "Load debug controls" }, { 9, "IA-32e mode guest" }, { 10, "Entry to SMM" },
	{ 11, "Deactivate dual-monitor treatment" }, { 13, "Load IA32_PERF_GLOBAL_CTRL" },
	{ 14, "Load IA32_PAT" }, { 15, "Load IA32_EFER" }, { 16, "Load IA32_BNDCFGS" },
	{ 17, "Conceal VMX from PT" }, { 18, "Load IA32_RTIT_CTL" }, { 20, "Load CET state" },
	{ 21, "Load guest IA32_LBR_CTL" }, { 22, "Load PKRS" }, { 99, NULL },
};

const struct bitname ept_cap_bits[] = {
	{ 0, "Execute-only pages" }, { 6, "Page-walk length 4" }, { 7, "Page-walk length 5" },
	{ 8, "EPTP memory type UC" }, { 14, "EPTP memory type WB" }, { 16, "2MB EPT pages" },
	{ 17, "1GB EPT pages" }, { 20, "INVEPT" }, { 21, "EPT accessed/dirty flags" },
	{ 22, "Advanced EPT violation info" }, { 23, "Supervisor shadow-stack control" },
	{ 25, "INVEPT single-context" }, { 26, "INVEPT all-context" }, { 32, "INVVPID" },
	{ 40, "INVVPID individual-address" }, { 41, "INVVPID single-context" },
	{ 42, "INVVPID all-context" }, { 43, "INVVPID single-context-retaining-globals" },
	{ 99, NULL },
};

static void caps_ctl(FILE *o, const char *title, unsigned long long cap, uint32_t used, const struct bitname *b, int json, int *first)
{
	uint32_t must = (uint32_t)cap, may = (uint32_t)(cap >> 32);

	if (json) {
		fprintf(o, "%s\"%s\":{\"allowed0\":\"%#x\",\"allowed1\":\"%#x\",\"used\":\"%#x\",\"bits\":[", *first ? "" : ",",
			title, must, may, used);
		*first = 0;
		for (; b->name; b++) {
			fprintf(o, "{\"bit\":%u,\"name\":", b->bit);
			json_str(o, b->name);
			fprintf(o, ",\"supported\":%s,\"forced\":%s,\"used\":%s}%s",
				(may >> b->bit) & 1 ? "true" : "false", (must >> b->bit) & 1 ? "true" : "false",
				(used >> b->bit) & 1 ? "true" : "false", b[1].name ? "," : "");
		}
		fprintf(o, "]}");
		return;
	}
	fprintf(o, "\n%s%s%s  %s(allowed-0 %#010x  allowed-1 %#010x)%s\n", c_bold(), title, c_off(), c_dim(), must, may, c_off());
	for (; b->name; b++) {
		int sup = (may >> b->bit) & 1, forced = (must >> b->bit) & 1, on = (used >> b->bit) & 1;
		const char *st = forced ? "forced" : (sup ? "yes" : "no");
		const char *col = forced ? c_yel() : (sup ? c_grn() : c_red());

		fprintf(o, "  [%2u] %-40s %s%-6s%s %s\n", b->bit, b->name, col, st, c_off(), on ? "● in use" : "");
	}
}

void caps_print(FILE *o, const struct vtx_caps *c, int json)
{
	int truec = (c->msr[VTX_CAP_BASIC] >> 55) & 1;
	unsigned long long basic = c->msr[VTX_CAP_BASIC], misc = c->msr[VTX_CAP_MISC], ept = c->msr[VTX_CAP_EPT_VPID];
	int first = 1;
	const struct bitname *b;

	if (json) {
		fprintf(o, "{\"basic\":{\"revision\":%llu,\"region_size\":%llu,\"memtype\":%llu"
			",\"true_controls\":%s,\"ins_outs_info\":%s},",
			basic & 0x7fffffff, (basic >> 32) & 0x1fff, (basic >> 50) & 0xf, truec ? "true" : "false",
			(basic >> 54) & 1 ? "true" : "false");
		fprintf(o, "\"maxphyaddr\":%u,\"controls\":{", c->maxphyaddr);
		caps_ctl(o, "pin", c->msr[truec ? VTX_CAP_TRUE_PIN : VTX_CAP_PINBASED], c->pin_used, pin_ctl_bits, 1, &first);
		caps_ctl(o, "primary", c->msr[truec ? VTX_CAP_TRUE_PROC : VTX_CAP_PROCBASED], c->proc_used, proc_ctl_bits, 1, &first);
		caps_ctl(o, "secondary", c->msr[VTX_CAP_PROCBASED2], c->proc2_used, proc2_ctl_bits, 1, &first);
		caps_ctl(o, "exit", c->msr[truec ? VTX_CAP_TRUE_EXIT : VTX_CAP_EXIT], c->exit_used, exit_ctl_bits, 1, &first);
		caps_ctl(o, "entry", c->msr[truec ? VTX_CAP_TRUE_ENTRY : VTX_CAP_ENTRY], c->entry_used, entry_ctl_bits, 1, &first);
		fprintf(o, "},\"ept_vpid\":[");
		for (b = ept_cap_bits; b->name; b++) {
			fprintf(o, "{\"bit\":%u,\"name\":", b->bit);
			json_str(o, b->name);
			fprintf(o, ",\"supported\":%s}%s", (ept >> b->bit) & 1 ? "true" : "false", b[1].name ? "," : "");
		}
		fprintf(o, "],\"cr0_fixed0\":\"%#llx\",\"cr0_fixed1\":\"%#llx\",\"cr4_fixed0\":\"%#llx"
			"\",\"cr4_fixed1\":\"%#llx\",\"feature_control\":\"%#llx\"}\n",
			c->msr[VTX_CAP_CR0_FIXED0], c->msr[VTX_CAP_CR0_FIXED1], c->msr[VTX_CAP_CR4_FIXED0],
			c->msr[VTX_CAP_CR4_FIXED1], c->msr[VTX_CAP_FEATURE_CTL]);
		return;
	}
	fprintf(o, "%sIA32_VMX_BASIC%s %#018llx\n", c_bold(), c_off(), basic);
	fprintf(o, "  VMCS revision %llu, region %llu bytes, memory type %s, TRUE controls %s, INS/OUTS info %s\n",
		basic & 0x7fffffff, (basic >> 32) & 0x1fff, ((basic >> 50) & 0xf) == 6 ? "WB" : "UC",
		truec ? "yes" : "no", (basic >> 54) & 1 ? "yes" : "no");
	fprintf(o, "%sIA32_VMX_MISC%s %#018llx\n", c_bold(), c_off(), misc);
	fprintf(o, "  preemption-timer rate 2^%llu, CR3 targets %llu, max MSR list %llu"
		", activity states %s%s%s, VMWRITE to exit fields %s\n",
		misc & 0x1f, (misc >> 16) & 0x1ff, 512 * (((misc >> 25) & 7) + 1),
		(misc >> 6) & 1 ? "HLT " : "", (misc >> 7) & 1 ? "shutdown " : "", (misc >> 8) & 1 ? "wait-for-SIPI" : "",
		(misc >> 29) & 1 ? "yes" : "no");
	fprintf(o, "%sMAXPHYADDR%s %u bits   %sFEATURE_CONTROL%s %#llx (lock %u, VMX outside SMX %u)\n",
		c_bold(), c_off(), c->maxphyaddr, c_bold(), c_off(), c->msr[VTX_CAP_FEATURE_CTL],
		(unsigned)(c->msr[VTX_CAP_FEATURE_CTL] & 1), (unsigned)((c->msr[VTX_CAP_FEATURE_CTL] >> 2) & 1));
	fprintf(o, "%sCR0 fixed%s 0=%#llx 1=%#llx   %sCR4 fixed%s 0=%#llx 1=%#llx\n",
		c_bold(), c_off(), c->msr[VTX_CAP_CR0_FIXED0], c->msr[VTX_CAP_CR0_FIXED1],
		c_bold(), c_off(), c->msr[VTX_CAP_CR4_FIXED0], c->msr[VTX_CAP_CR4_FIXED1]);
	caps_ctl(o, "Pin-based VM-execution controls", c->msr[truec ? VTX_CAP_TRUE_PIN : VTX_CAP_PINBASED], c->pin_used, pin_ctl_bits, 0, &first);
	caps_ctl(o, "Primary processor-based VM-execution controls", c->msr[truec ? VTX_CAP_TRUE_PROC : VTX_CAP_PROCBASED], c->proc_used, proc_ctl_bits, 0, &first);
	caps_ctl(o, "Secondary processor-based VM-execution controls", c->msr[VTX_CAP_PROCBASED2], c->proc2_used, proc2_ctl_bits, 0, &first);
	caps_ctl(o, "VM-exit controls", c->msr[truec ? VTX_CAP_TRUE_EXIT : VTX_CAP_EXIT], c->exit_used, exit_ctl_bits, 0, &first);
	caps_ctl(o, "VM-entry controls", c->msr[truec ? VTX_CAP_TRUE_ENTRY : VTX_CAP_ENTRY], c->entry_used, entry_ctl_bits, 0, &first);
	fprintf(o, "\n%sEPT/VPID capabilities%s  %s(%#018llx)%s\n", c_bold(), c_off(), c_dim(), ept, c_off());
	for (b = ept_cap_bits; b->name; b++) {
		int s = (ept >> b->bit) & 1;

		fprintf(o, "  [%2u] %-40s %s%s%s\n", b->bit, b->name, s ? c_grn() : c_red(), s ? "yes" : "no", c_off());
	}
}
