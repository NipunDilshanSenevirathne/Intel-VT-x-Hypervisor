#ifndef VTXHV_UAPI_H
#define VTXHV_UAPI_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define VTX_DEVICE_NAME		"vtxhv"
#define VTX_DEVICE_PATH		"/dev/vtxhv"
#define VTX_ABI_VERSION		1
#define VTX_SIGNATURE		"VtxHvIntrspc"
#define VTX_MAX_WATCH		64
#define VTX_MAX_CPUS		256
#define VTX_EXIT_REASONS	80
#define VTX_NAME_LEN		32

enum vtx_event_type {
	VTX_EV_NONE = 0,
	VTX_EV_EPT_READ = 1,
	VTX_EV_EPT_WRITE = 2,
	VTX_EV_EPT_EXEC = 3,
	VTX_EV_TAMPER = 4,
	VTX_EV_CR0 = 5,
	VTX_EV_CR4 = 6,
	VTX_EV_MSR = 7,
	VTX_EV_DTR = 8,
	VTX_EV_VMX = 9,
	VTX_EV_HYPERCALL = 10,
	VTX_EV_INIT = 11,
	VTX_EV_MAX
};

#define VTX_EVF_DENIED		0x0001
#define VTX_EVF_GLA		0x0002
#define VTX_EVF_USER		0x0004
#define VTX_EVF_NEWVAL		0x0008
#define VTX_EVF_PAGEWALK	0x0010
#define VTX_EVF_TASK		0x0020
#define VTX_EVF_OLDVAL		0x0040
#define VTX_EVF_EMUL		0x0080

#define VTX_DTR_SGDT		0
#define VTX_DTR_SIDT		1
#define VTX_DTR_LGDT		2
#define VTX_DTR_LIDT		3
#define VTX_DTR_SLDT		4
#define VTX_DTR_STR		5
#define VTX_DTR_LLDT		6
#define VTX_DTR_LTR		7

struct vtx_event {
	__u64 seq;
	__u64 tsc;
	__u32 type;
	__u16 cpu;
	__u16 flags;
	__s32 pid;
	__u32 watch_id;
	__u64 rip;
	__u64 rsp;
	__u64 cr3;
	__u64 gpa;
	__u64 gla;
	__u64 old_val;
	__u64 new_val;
	__u64 info;
	char comm[16];
	__u64 reserved[2];
};

#define VTX_DENY_R		0x1
#define VTX_DENY_W		0x2
#define VTX_DENY_X		0x4
#define VTX_DENY_ALL		0x7

#define VTX_MODE_MONITOR	0
#define VTX_MODE_ENFORCE	1

#define VTX_WF_VIRT		0x1

struct vtx_watch_req {
	__u64 addr;
	__u64 len;
	__u32 deny;
	__u32 mode;
	__u32 flags;
	__u32 id;
	char name[VTX_NAME_LEN];
};

struct vtx_watch_info {
	__u32 id;
	__u32 deny;
	__u32 mode;
	__u32 pages;
	__u64 gpa_start;
	__u64 gpa_end;
	__u64 hits;
	char name[VTX_NAME_LEN];
};

struct vtx_watch_list {
	__u32 count;
	__u32 reserved;
	struct vtx_watch_info w[VTX_MAX_WATCH];
};

#define VTX_PIN_CR0_WP		(1u << 0)
#define VTX_PIN_CR4_SMEP	(1u << 1)
#define VTX_PIN_CR4_SMAP	(1u << 2)
#define VTX_PIN_CR4_UMIP	(1u << 3)
#define VTX_PIN_MSR_SYSCALL	(1u << 4)
#define VTX_PIN_MSR_SYSENTER	(1u << 5)
#define VTX_PIN_MSR_EFER	(1u << 6)
#define VTX_PIN_IDTR		(1u << 7)
#define VTX_PIN_GDTR		(1u << 8)
#define VTX_PIN_TR		(1u << 9)
#define VTX_PIN_ALL		0x3ffu
#define VTX_PIN_DTR		(VTX_PIN_IDTR | VTX_PIN_GDTR | VTX_PIN_TR)

struct vtx_policy {
	__u32 set;
	__u32 clear;
	__u32 result;
	__u32 reserved;
};

#define VTX_GUARD_KTEXT		1
#define VTX_GUARD_KRODATA	2
#define VTX_GUARD_IDT		3

struct vtx_guard_req {
	__u32 which;
	__u32 mode;
	__u32 id;
	__u32 reserved;
};

#define VTX_FEAT_EPT_1G		(1u << 0)
#define VTX_FEAT_EPT_2M		(1u << 1)
#define VTX_FEAT_VPID		(1u << 2)
#define VTX_FEAT_VNMI		(1u << 3)
#define VTX_FEAT_DTEXIT		(1u << 4)
#define VTX_FEAT_UNRESTRICTED	(1u << 5)
#define VTX_FEAT_EXEC_ONLY	(1u << 6)
#define VTX_FEAT_MTF		(1u << 7)
#define VTX_FEAT_INVPCID	(1u << 8)
#define VTX_FEAT_XSAVES		(1u << 9)
#define VTX_FEAT_RDTSCP		(1u << 10)
#define VTX_FEAT_WAITPKG	(1u << 11)
#define VTX_FEAT_LA57		(1u << 12)
#define VTX_FEAT_TRUE_CTLS	(1u << 13)
#define VTX_FEAT_PTI		(1u << 14)
#define VTX_FEAT_EPT_WB		(1u << 15)
#define VTX_FEAT_CR3_EXITS	(1u << 16)
#define VTX_FEAT_INTROSPECT	(1u << 17)
#define VTX_FEAT_SERIAL		(1u << 18)

struct vtx_status {
	__u32 abi;
	__u32 online_cpus;
	__u32 virt_cpus;
	__u32 locked;
	__u64 virt_mask[VTX_MAX_CPUS / 64];
	__u32 policy;
	__u32 features;
	__u32 nwatch;
	__u32 pool_total;
	__u32 pool_used;
	__u32 nchunks;
	__u64 events_total;
	__u64 events_dropped;
	__u64 tamper_count;
	__u64 arena_bytes;
	__u64 arena_pa0;
	__u64 map_limit;
	__u64 host_text_pa;
	__u32 host_text_pages;
	__u32 ro_pages;
	__u32 maxphyaddr;
	__u32 paging_levels;
	__u64 load_tsc;
	char signature[16];
};

#define VTX_CAP_BASIC		0
#define VTX_CAP_PINBASED	1
#define VTX_CAP_PROCBASED	2
#define VTX_CAP_EXIT		3
#define VTX_CAP_ENTRY		4
#define VTX_CAP_MISC		5
#define VTX_CAP_CR0_FIXED0	6
#define VTX_CAP_CR0_FIXED1	7
#define VTX_CAP_CR4_FIXED0	8
#define VTX_CAP_CR4_FIXED1	9
#define VTX_CAP_VMCS_ENUM	10
#define VTX_CAP_PROCBASED2	11
#define VTX_CAP_EPT_VPID	12
#define VTX_CAP_TRUE_PIN	13
#define VTX_CAP_TRUE_PROC	14
#define VTX_CAP_TRUE_EXIT	15
#define VTX_CAP_TRUE_ENTRY	16
#define VTX_CAP_VMFUNC		17
#define VTX_CAP_PROCBASED3	18
#define VTX_CAP_EXIT2		19
#define VTX_CAP_FEATURE_CTL	20
#define VTX_CAP_MTRRCAP		21
#define VTX_CAP_MTRR_DEF	22
#define VTX_CAP_COUNT		23

struct vtx_caps {
	__u64 msr[VTX_CAP_COUNT];
	__u32 valid;
	__u32 maxphyaddr;
	__u32 pin_used;
	__u32 proc_used;
	__u32 proc2_used;
	__u32 exit_used;
	__u32 entry_used;
	__u32 reserved;
};

struct vtx_stats {
	__u32 ncpus;
	__u32 nreasons;
	__u64 exits[VTX_EXIT_REASONS];
	__u64 cycles[VTX_EXIT_REASONS];
	__u64 cpu_exits[64];
	__u64 nmi_reflected;
	__u64 steps;
	__u64 spurious_ept;
	__u64 hypercalls;
	__u64 injected;
	__u64 events;
	__u64 dropped;
	__u64 step_shadows;
	__u64 step_recycles;
	__u64 emul_denied;
	__u64 reserved[5];
};

#define VTX_IOC_MAGIC		0xB7
#define VTX_IOC_STATUS		_IOR(VTX_IOC_MAGIC, 0x01, struct vtx_status)
#define VTX_IOC_CAPS		_IOR(VTX_IOC_MAGIC, 0x02, struct vtx_caps)
#define VTX_IOC_WATCH_ADD	_IOWR(VTX_IOC_MAGIC, 0x03, struct vtx_watch_req)
#define VTX_IOC_WATCH_DEL	_IOW(VTX_IOC_MAGIC, 0x04, __u32)
#define VTX_IOC_WATCH_LIST	_IOR(VTX_IOC_MAGIC, 0x05, struct vtx_watch_list)
#define VTX_IOC_POLICY		_IOWR(VTX_IOC_MAGIC, 0x06, struct vtx_policy)
#define VTX_IOC_LOCK		_IO(VTX_IOC_MAGIC, 0x07)
#define VTX_IOC_STATS		_IOR(VTX_IOC_MAGIC, 0x08, struct vtx_stats)
#define VTX_IOC_GUARD		_IOWR(VTX_IOC_MAGIC, 0x09, struct vtx_guard_req)

#endif
