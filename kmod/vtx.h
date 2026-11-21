#ifndef VTX_H
#define VTX_H

#include "vtx_types.h"
#include "vtx_arch.h"
#include "vtx_vmcs.h"
#include "policy.h"
#include "mtrr.h"
#include "ept.h"
#include "walk.h"
#include "ring.h"
#include "dtr.h"
#include "../include/uapi/vtxhv.h"

#define VTX_MAGIC		0x5654584856495352ull
#define VTX_VERSION		0x00010000u
#define VTX_HC_MAGIC		0x5654480000000000ull
#define VTX_HC_MASK		0xffffff0000000000ull

#define VTX_STACK_SIZE		(16 * 1024)
#define VTX_HOST_RSP_OFF	(VTX_STACK_SIZE - 64)
#define VTX_STEP_MAX		16
#define VTX_SCRATCH_N		4
#define VTX_FIXUPS		3

#define VCPU_OFF_NMI_PENDING	8
#define VCPU_OFF_VMX_ACTIVE	16

#define VTX_HC_PING		0x01
#define VTX_HC_DEVIRT		0x02
#define VTX_HC_SYNC		0x03
#define VTX_HC_PROTECT		0x04
#define VTX_HC_UNPROTECT	0x05
#define VTX_HC_POLICY		0x06
#define VTX_HC_LOCK		0x07
#define VTX_HC_DRAIN		0x08
#define VTX_HC_STATS		0x09
#define VTX_HC_QUERY		0x0a
#define VTX_HC_WLIST		0x0b

#define VTX_LAUNCH_FAIL_INVALID	(1ull << 32)
#define VTX_LAUNCH_FAIL_VALID	(2ull << 32)
#define VTX_LAUNCH_FAIL_ENTRY	(3ull << 32)

#define VTX_STEP_ALLOW		0
#define VTX_STEP_SCRATCH	1

struct vtx_regs {
	u64 rax;
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

struct vtx_host_frame {
	struct vtx_regs regs;
	u64 vector;
	u64 error;
	u64 rip;
	u64 cs;
	u64 rflags;
	u64 rsp;
	u64 ss;
};

struct vtx_iret_frame {
	u64 rip;
	u64 cs;
	u64 rflags;
	u64 rsp;
	u64 ss;
};

struct vtx_step_ent {
	u64 gpa;
	u16 kind;
	u16 tag;
	u32 slot;
};

struct vtx_global;

struct vtx_vcpu {
	struct vtx_vcpu *self;
	u64 nmi_pending;
	u32 vmx_active;
	u32 cpu;
	struct vtx_global *g;
	u64 stack_base;
	u64 vmxon_pa;
	u64 vmcs_pa;
	void *vmxon_va;
	void *vmcs_va;
	u64 gdt_va;
	u64 tss_va;
	u64 ept_root;
	u64 eptp;
	u64 scratch_pa;
	void *scratch_va;
	struct vtx_ring *ring;
	u32 vpid;
	u32 launched;
	u32 pin;
	u32 proc;
	u32 proc2;
	u32 exitc;
	u32 entryc;
	u32 pad0;
	u64 cr0_mask;
	u64 cr4_mask;
	u64 policy_gen;
	u64 ept_gen;
	u32 inj_valid;
	u32 inj_info;
	u32 inj_err;
	u32 inj_len;
	u64 b_gdtr_base;
	u64 b_gdt_rw;
	u64 b_idtr_base;
	u16 b_gdtr_limit;
	u16 b_idtr_limit;
	u16 b_tr;
	u16 pad1;
	u64 b_star;
	u64 b_lstar;
	u64 b_cstar;
	u64 b_sfmask;
	u64 b_sysenter_cs;
	u64 b_sysenter_esp;
	u64 b_sysenter_eip;
	u64 b_efer;
	u32 step_n;
	u32 step_ev_valid;
	struct vtx_step_ent step[VTX_STEP_MAX];
	struct vtx_event step_ev;
	u64 step_ev_off;
	u64 step_ev_pa;
	u32 fault_vector;
	u32 scratch_used;
	u32 step_shadow_req;
	u32 step_retired;
	u64 hc_fn;
	u64 exits[VTX_EXIT_REASONS];
	u64 cycles[VTX_EXIT_REASONS];
	u64 total_exits;
	u64 nmi_reflected;
	u64 steps;
	u64 spurious;
	u64 hypercalls;
	u64 injected;
	u64 shadows;
	u64 recycles;
	u64 emul_denied;
	u64 cur_exit_tsc;
};

struct vtx_fixup {
	u64 ip;
	u64 to;
};

struct vtx_global {
	u64 magic;
	u64 dmap;
	u64 kimg_va;
	u64 kimg_pa;
	u64 kimg_end;
	u32 ncpu;
	u32 features;
	u32 maxphy;
	u32 la57;
	u32 pti;
	u32 va57;
	u32 dtexit;
	u64 ept_caps;
	u64 cr0_fixed0;
	u64 cr0_fixed1;
	u64 cr4_fixed0;
	u64 cr4_fixed1;
	u64 map_limit;
	u32 ept_lock;
	u32 ring_lock;
	u64 ept_gen;
	u64 policy_gen;
	u32 policy;
	u32 locked;
	u64 seq;
	u64 events;
	u64 dropped;
	u64 tamper;
	u32 ser_port;
	u32 ser_events;
	u32 ser_lock;
	u32 intro;
	u64 off_cur_task;
	u64 off_pid;
	u64 off_tgid;
	u64 off_comm;
	u32 next_id;
	u32 nwatch_ids;
	u64 msr_bitmap_pa;
	u64 host_cr3;
	u64 idt_va;
	u64 load_tsc;
	u64 arena_pa0;
	u64 arena_bytes;
	u32 nchunks;
	u32 host_text_pages;
	u64 host_text_pa0;
	u32 ro_pages;
	u32 virt_count;
	struct vtx_fixup fix[VTX_FIXUPS];
	struct vtx_mtrr mtrr;
	struct vtx_pool pool;
	struct vtx_physmap pm;
	struct vtx_tables tables;
	struct vtx_vcpu *vcpu[VTX_MAX_CPUS];
};

extern char vtx_exit_stub[];
extern char vtx_idt_stubs[];
extern char vtx_nmi_stub[];
extern char vtx_fault_rdmsr[];
extern char vtx_fixup_rdmsr[];
extern char vtx_fault_wrmsr[];
extern char vtx_fixup_wrmsr[];
extern char vtx_fault_xsetbv[];
extern char vtx_fixup_xsetbv[];

u64 vtx_asm_launch(void);
int vtx_safe_rdmsr(u32 msr, u64 *val);
int vtx_safe_wrmsr(u32 msr, u64 val);
int vtx_safe_xsetbv(u32 idx, u64 val);

int vtx_handle_exit(struct vtx_vcpu *v, struct vtx_regs *r);
void vtx_resume_failed(struct vtx_vcpu *v, u64 rflags);
void vtx_host_exception(struct vtx_host_frame *f);

void vtx_ser_puts(struct vtx_global *g, const char *s);
void vtx_ser_hex(struct vtx_global *g, u64 v);
void vtx_ser_kv(struct vtx_global *g, const char *k, u64 v);
void vtx_fatal(struct vtx_vcpu *v, const char *why, u64 a, u64 b) __attribute__((noreturn));
void vtx_inject(struct vtx_vcpu *v, u32 vector, u32 type, int has_err, u32 err);
void vtx_inject_gp(struct vtx_vcpu *v);
void vtx_inject_ud(struct vtx_vcpu *v);
void vtx_inject_pf(struct vtx_vcpu *v, u64 cr2, u32 err);
void vtx_skip(struct vtx_vcpu *v);
void vtx_event_begin(struct vtx_vcpu *v, struct vtx_event *e, u32 type);
void vtx_event_commit(struct vtx_vcpu *v, struct vtx_event *e);
void vtx_fill_task(struct vtx_vcpu *v, struct vtx_event *e);
void vtx_walk_ctx(struct vtx_vcpu *v, struct vtx_walk *w, int kernel_view);
int vtx_kva_to_gpa(struct vtx_vcpu *v, u64 kva, u64 *gpa);
int vtx_read_kva(struct vtx_vcpu *v, u64 kva, void *buf, u32 len);

int vtx_ept_violation(struct vtx_vcpu *v);
int vtx_mtf(struct vtx_vcpu *v);
int vtx_hypercall(struct vtx_vcpu *v, struct vtx_regs *r);
void vtx_apply_cr_policy(struct vtx_vcpu *v);
int vtx_apply_page_all(struct vtx_global *g, u64 gpa);
void vtx_invept_self(struct vtx_vcpu *v);
u64 vtx_gpr_get(struct vtx_vcpu *v, struct vtx_regs *r, u32 idx);
void vtx_gpr_set(struct vtx_vcpu *v, struct vtx_regs *r, u32 idx, u64 val);
int vtx_devirt_prepare(struct vtx_vcpu *v, struct vtx_regs *r, u64 retval);

#endif
