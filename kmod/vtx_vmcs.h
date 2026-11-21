#ifndef VTX_VMCS_H
#define VTX_VMCS_H

#define VMCS_VPID			0x0000
#define VMCS_GUEST_ES_SEL		0x0800
#define VMCS_GUEST_CS_SEL		0x0802
#define VMCS_GUEST_SS_SEL		0x0804
#define VMCS_GUEST_DS_SEL		0x0806
#define VMCS_GUEST_FS_SEL		0x0808
#define VMCS_GUEST_GS_SEL		0x080a
#define VMCS_GUEST_LDTR_SEL		0x080c
#define VMCS_GUEST_TR_SEL		0x080e
#define VMCS_HOST_ES_SEL		0x0c00
#define VMCS_HOST_CS_SEL		0x0c02
#define VMCS_HOST_SS_SEL		0x0c04
#define VMCS_HOST_DS_SEL		0x0c06
#define VMCS_HOST_FS_SEL		0x0c08
#define VMCS_HOST_GS_SEL		0x0c0a
#define VMCS_HOST_TR_SEL		0x0c0c

#define VMCS_IO_BITMAP_A		0x2000
#define VMCS_IO_BITMAP_B		0x2002
#define VMCS_MSR_BITMAP			0x2004
#define VMCS_EXIT_MSR_STORE_ADDR	0x2006
#define VMCS_EXIT_MSR_LOAD_ADDR		0x2008
#define VMCS_ENTRY_MSR_LOAD_ADDR	0x200a
#define VMCS_TSC_OFFSET			0x2010
#define VMCS_EPT_POINTER		0x201a
#define VMCS_XSS_EXIT_BITMAP		0x202c
#define VMCS_GUEST_PHYS_ADDR		0x2400
#define VMCS_LINK_POINTER		0x2800
#define VMCS_GUEST_DEBUGCTL		0x2802
#define VMCS_GUEST_PAT			0x2804
#define VMCS_GUEST_EFER			0x2806
#define VMCS_HOST_PAT			0x2c00
#define VMCS_HOST_EFER			0x2c02

#define VMCS_PIN_CTLS			0x4000
#define VMCS_PROC_CTLS			0x4002
#define VMCS_EXCEPTION_BITMAP		0x4004
#define VMCS_PF_ERR_MASK		0x4006
#define VMCS_PF_ERR_MATCH		0x4008
#define VMCS_CR3_TARGET_COUNT		0x400a
#define VMCS_EXIT_CTLS			0x400c
#define VMCS_EXIT_MSR_STORE_COUNT	0x400e
#define VMCS_EXIT_MSR_LOAD_COUNT	0x4010
#define VMCS_ENTRY_CTLS			0x4012
#define VMCS_ENTRY_MSR_LOAD_COUNT	0x4014
#define VMCS_ENTRY_INTR_INFO		0x4016
#define VMCS_ENTRY_EXC_ERRCODE		0x4018
#define VMCS_ENTRY_INSTR_LEN		0x401a
#define VMCS_TPR_THRESHOLD		0x401c
#define VMCS_PROC_CTLS2			0x401e

#define VMCS_INSTR_ERROR		0x4400
#define VMCS_EXIT_REASON		0x4402
#define VMCS_EXIT_INTR_INFO		0x4404
#define VMCS_EXIT_INTR_ERRCODE		0x4406
#define VMCS_IDT_VEC_INFO		0x4408
#define VMCS_IDT_VEC_ERRCODE		0x440a
#define VMCS_EXIT_INSTR_LEN		0x440c
#define VMCS_EXIT_INSTR_INFO		0x440e

#define VMCS_GUEST_ES_LIMIT		0x4800
#define VMCS_GUEST_CS_LIMIT		0x4802
#define VMCS_GUEST_SS_LIMIT		0x4804
#define VMCS_GUEST_DS_LIMIT		0x4806
#define VMCS_GUEST_FS_LIMIT		0x4808
#define VMCS_GUEST_GS_LIMIT		0x480a
#define VMCS_GUEST_LDTR_LIMIT		0x480c
#define VMCS_GUEST_TR_LIMIT		0x480e
#define VMCS_GUEST_GDTR_LIMIT		0x4810
#define VMCS_GUEST_IDTR_LIMIT		0x4812
#define VMCS_GUEST_ES_AR		0x4814
#define VMCS_GUEST_CS_AR		0x4816
#define VMCS_GUEST_SS_AR		0x4818
#define VMCS_GUEST_DS_AR		0x481a
#define VMCS_GUEST_FS_AR		0x481c
#define VMCS_GUEST_GS_AR		0x481e
#define VMCS_GUEST_LDTR_AR		0x4820
#define VMCS_GUEST_TR_AR		0x4822
#define VMCS_GUEST_INTERRUPTIBILITY	0x4824
#define VMCS_GUEST_ACTIVITY		0x4826
#define VMCS_GUEST_SYSENTER_CS		0x482a
#define VMCS_HOST_SYSENTER_CS		0x4c00

#define VMCS_CR0_MASK			0x6000
#define VMCS_CR4_MASK			0x6002
#define VMCS_CR0_SHADOW			0x6004
#define VMCS_CR4_SHADOW			0x6006
#define VMCS_EXIT_QUAL			0x6400
#define VMCS_GUEST_LINEAR_ADDR		0x640a

#define VMCS_GUEST_CR0			0x6800
#define VMCS_GUEST_CR3			0x6802
#define VMCS_GUEST_CR4			0x6804
#define VMCS_GUEST_ES_BASE		0x6806
#define VMCS_GUEST_CS_BASE		0x6808
#define VMCS_GUEST_SS_BASE		0x680a
#define VMCS_GUEST_DS_BASE		0x680c
#define VMCS_GUEST_FS_BASE		0x680e
#define VMCS_GUEST_GS_BASE		0x6810
#define VMCS_GUEST_LDTR_BASE		0x6812
#define VMCS_GUEST_TR_BASE		0x6814
#define VMCS_GUEST_GDTR_BASE		0x6816
#define VMCS_GUEST_IDTR_BASE		0x6818
#define VMCS_GUEST_DR7			0x681a
#define VMCS_GUEST_RSP			0x681c
#define VMCS_GUEST_RIP			0x681e
#define VMCS_GUEST_RFLAGS		0x6820
#define VMCS_GUEST_PENDING_DBG		0x6822
#define VMCS_GUEST_SYSENTER_ESP		0x6824
#define VMCS_GUEST_SYSENTER_EIP		0x6826

#define VMCS_HOST_CR0			0x6c00
#define VMCS_HOST_CR3			0x6c02
#define VMCS_HOST_CR4			0x6c04
#define VMCS_HOST_FS_BASE		0x6c06
#define VMCS_HOST_GS_BASE		0x6c08
#define VMCS_HOST_TR_BASE		0x6c0a
#define VMCS_HOST_GDTR_BASE		0x6c0c
#define VMCS_HOST_IDTR_BASE		0x6c0e
#define VMCS_HOST_SYSENTER_ESP		0x6c10
#define VMCS_HOST_SYSENTER_EIP		0x6c12
#define VMCS_HOST_RSP			0x6c14
#define VMCS_HOST_RIP			0x6c16

#define PIN_EXT_INTR_EXITING		(1u << 0)
#define PIN_NMI_EXITING			(1u << 3)
#define PIN_VIRTUAL_NMIS		(1u << 5)
#define PIN_PREEMPT_TIMER		(1u << 6)

#define PROC_INTR_WINDOW		(1u << 2)
#define PROC_HLT_EXITING		(1u << 7)
#define PROC_INVLPG_EXITING		(1u << 9)
#define PROC_CR3_LOAD_EXITING		(1u << 15)
#define PROC_CR3_STORE_EXITING		(1u << 16)
#define PROC_TERTIARY			(1u << 17)
#define PROC_CR8_LOAD_EXITING		(1u << 19)
#define PROC_CR8_STORE_EXITING		(1u << 20)
#define PROC_NMI_WINDOW			(1u << 22)
#define PROC_MOV_DR_EXITING		(1u << 23)
#define PROC_UNCOND_IO			(1u << 24)
#define PROC_USE_IO_BITMAPS		(1u << 25)
#define PROC_MTF			(1u << 27)
#define PROC_USE_MSR_BITMAPS		(1u << 28)
#define PROC_SECONDARY			(1u << 31)

#define PROC2_VIRT_APIC			(1u << 0)
#define PROC2_EPT			(1u << 1)
#define PROC2_DESC_TABLE		(1u << 2)
#define PROC2_RDTSCP			(1u << 3)
#define PROC2_VPID			(1u << 5)
#define PROC2_UNRESTRICTED		(1u << 7)
#define PROC2_INVPCID			(1u << 12)
#define PROC2_XSAVES			(1u << 20)
#define PROC2_WAITPKG			(1u << 26)
#define PROC2_PCONFIG			(1u << 27)

#define EXIT_SAVE_DEBUG			(1u << 2)
#define EXIT_HOST_LONG			(1u << 9)
#define EXIT_ACK_INTR			(1u << 15)
#define EXIT_SAVE_PAT			(1u << 18)
#define EXIT_LOAD_PAT			(1u << 19)
#define EXIT_SAVE_EFER			(1u << 20)
#define EXIT_LOAD_EFER			(1u << 21)
#define EXIT_CONCEAL_PT			(1u << 24)

#define ENTRY_LOAD_DEBUG		(1u << 2)
#define ENTRY_IA32E			(1u << 9)
#define ENTRY_LOAD_PAT			(1u << 14)
#define ENTRY_LOAD_EFER			(1u << 15)
#define ENTRY_CONCEAL_PT		(1u << 17)

#define INTR_INFO_VALID			(1u << 31)
#define INTR_INFO_ERRCODE		(1u << 11)
#define INTR_INFO_NMI_UNBLOCK		(1u << 12)
#define INTR_TYPE_EXT			(0u << 8)
#define INTR_TYPE_NMI			(2u << 8)
#define INTR_TYPE_HW_EXC		(3u << 8)
#define INTR_TYPE_SW_INT		(4u << 8)
#define INTR_TYPE_PRIV_SW_EXC		(5u << 8)
#define INTR_TYPE_SW_EXC		(6u << 8)
#define INTR_TYPE_MASK			(7u << 8)

#define GI_BLOCK_STI			(1u << 0)
#define GI_BLOCK_MOVSS			(1u << 1)
#define GI_BLOCK_SMI			(1u << 2)
#define GI_BLOCK_NMI			(1u << 3)

#define EXIT_REASON_EXCEPTION_NMI	0
#define EXIT_REASON_EXT_INTR		1
#define EXIT_REASON_TRIPLE_FAULT	2
#define EXIT_REASON_INIT		3
#define EXIT_REASON_SIPI		4
#define EXIT_REASON_INTR_WINDOW		7
#define EXIT_REASON_NMI_WINDOW		8
#define EXIT_REASON_TASK_SWITCH		9
#define EXIT_REASON_CPUID		10
#define EXIT_REASON_GETSEC		11
#define EXIT_REASON_HLT			12
#define EXIT_REASON_INVD		13
#define EXIT_REASON_INVLPG		14
#define EXIT_REASON_RDPMC		15
#define EXIT_REASON_RDTSC		16
#define EXIT_REASON_RSM			17
#define EXIT_REASON_VMCALL		18
#define EXIT_REASON_VMCLEAR		19
#define EXIT_REASON_VMLAUNCH		20
#define EXIT_REASON_VMPTRLD		21
#define EXIT_REASON_VMPTRST		22
#define EXIT_REASON_VMREAD		23
#define EXIT_REASON_VMRESUME		24
#define EXIT_REASON_VMWRITE		25
#define EXIT_REASON_VMXOFF		26
#define EXIT_REASON_VMXON		27
#define EXIT_REASON_CR_ACCESS		28
#define EXIT_REASON_DR_ACCESS		29
#define EXIT_REASON_IO			30
#define EXIT_REASON_MSR_READ		31
#define EXIT_REASON_MSR_WRITE		32
#define EXIT_REASON_BAD_GUEST		33
#define EXIT_REASON_MSR_LOAD_FAIL	34
#define EXIT_REASON_MWAIT		36
#define EXIT_REASON_MTF			37
#define EXIT_REASON_MONITOR		39
#define EXIT_REASON_PAUSE		40
#define EXIT_REASON_MCE_ENTRY		41
#define EXIT_REASON_TPR_BELOW		43
#define EXIT_REASON_APIC_ACCESS		44
#define EXIT_REASON_EOI			45
#define EXIT_REASON_GDTR_IDTR		46
#define EXIT_REASON_LDTR_TR		47
#define EXIT_REASON_EPT_VIOLATION	48
#define EXIT_REASON_EPT_MISCONFIG	49
#define EXIT_REASON_INVEPT		50
#define EXIT_REASON_RDTSCP		51
#define EXIT_REASON_PREEMPT_TIMER	52
#define EXIT_REASON_INVVPID		53
#define EXIT_REASON_WBINVD		54
#define EXIT_REASON_XSETBV		55
#define EXIT_REASON_APIC_WRITE		56
#define EXIT_REASON_RDRAND		57
#define EXIT_REASON_INVPCID		58
#define EXIT_REASON_VMFUNC		59
#define EXIT_REASON_ENCLS		60
#define EXIT_REASON_RDSEED		61
#define EXIT_REASON_PML_FULL		62
#define EXIT_REASON_XSAVES		63
#define EXIT_REASON_XRSTORS		64
#define EXIT_REASON_UMWAIT		67
#define EXIT_REASON_TPAUSE		68
#define EXIT_REASON_ENTRY_FAIL		(1u << 31)

#define EPTQ_READ			(1ull << 0)
#define EPTQ_WRITE			(1ull << 1)
#define EPTQ_EXEC			(1ull << 2)
#define EPTQ_GLA_VALID			(1ull << 7)
#define EPTQ_GLA_FINAL			(1ull << 8)
#define EPTQ_NMI_UNBLOCK		(1ull << 12)

#define MSR_IA32_FEATURE_CONTROL	0x0000003a
#define MSR_IA32_SYSENTER_CS		0x00000174
#define MSR_IA32_SYSENTER_ESP		0x00000175
#define MSR_IA32_SYSENTER_EIP		0x00000176
#define MSR_IA32_DEBUGCTL		0x000001d9
#define MSR_IA32_PAT			0x00000277
#define MSR_IA32_MTRRCAP		0x000000fe
#define MSR_IA32_MTRR_DEF_TYPE		0x000002ff
#define MSR_IA32_MTRR_PHYSBASE0		0x00000200
#define MSR_IA32_MTRR_FIX64K_00000	0x00000250
#define MSR_IA32_MTRR_FIX16K_80000	0x00000258
#define MSR_IA32_MTRR_FIX16K_A0000	0x00000259
#define MSR_IA32_MTRR_FIX4K_C0000	0x00000268
#define MSR_IA32_VMX_BASIC		0x00000480
#define MSR_IA32_VMX_PINBASED		0x00000481
#define MSR_IA32_VMX_PROCBASED		0x00000482
#define MSR_IA32_VMX_EXIT		0x00000483
#define MSR_IA32_VMX_ENTRY		0x00000484
#define MSR_IA32_VMX_MISC		0x00000485
#define MSR_IA32_VMX_CR0_FIXED0		0x00000486
#define MSR_IA32_VMX_CR0_FIXED1		0x00000487
#define MSR_IA32_VMX_CR4_FIXED0		0x00000488
#define MSR_IA32_VMX_CR4_FIXED1		0x00000489
#define MSR_IA32_VMX_VMCS_ENUM		0x0000048a
#define MSR_IA32_VMX_PROCBASED2		0x0000048b
#define MSR_IA32_VMX_EPT_VPID		0x0000048c
#define MSR_IA32_VMX_TRUE_PIN		0x0000048d
#define MSR_IA32_VMX_TRUE_PROC		0x0000048e
#define MSR_IA32_VMX_TRUE_EXIT		0x0000048f
#define MSR_IA32_VMX_TRUE_ENTRY		0x00000490
#define MSR_IA32_VMX_VMFUNC		0x00000491
#define MSR_IA32_VMX_PROCBASED3		0x00000492
#define MSR_IA32_VMX_EXIT2		0x00000493
#define MSR_EFER			0xc0000080
#define MSR_STAR			0xc0000081
#define MSR_LSTAR			0xc0000082
#define MSR_CSTAR			0xc0000083
#define MSR_SFMASK			0xc0000084
#define MSR_FS_BASE			0xc0000100
#define MSR_GS_BASE			0xc0000101
#define MSR_KERNEL_GS_BASE		0xc0000102

#define FEATCTL_LOCK			(1ull << 0)
#define FEATCTL_VMX_OUTSIDE_SMX		(1ull << 2)

#define CR0_PE				(1ull << 0)
#define CR0_MP				(1ull << 1)
#define CR0_EM				(1ull << 2)
#define CR0_TS				(1ull << 3)
#define CR0_NE				(1ull << 5)
#define CR0_WP				(1ull << 16)
#define CR0_NW				(1ull << 29)
#define CR0_CD				(1ull << 30)
#define CR0_PG				(1ull << 31)
#define CR4_PSE				(1ull << 4)
#define CR4_PAE				(1ull << 5)
#define CR4_PGE				(1ull << 7)
#define CR4_UMIP			(1ull << 11)
#define CR4_LA57			(1ull << 12)
#define CR4_VMXE			(1ull << 13)
#define CR4_SMXE			(1ull << 14)
#define CR4_PCIDE			(1ull << 17)
#define CR4_OSXSAVE			(1ull << 18)
#define CR4_SMEP			(1ull << 20)
#define CR4_SMAP			(1ull << 21)
#define CR4_PKE				(1ull << 22)
#define CR4_CET				(1ull << 23)
#define VEFER_SCE			(1ull << 0)
#define VEFER_LME			(1ull << 8)
#define VEFER_LMA			(1ull << 10)
#define VEFER_NXE			(1ull << 11)
#define RFLAGS_TF			(1ull << 8)
#define RFLAGS_IF			(1ull << 9)
#define RFLAGS_AC			(1ull << 18)
#define RFLAGS_VM			(1ull << 17)

#define EPT_R				(1ull << 0)
#define EPT_W				(1ull << 1)
#define EPT_X				(1ull << 2)
#define EPT_RWX				(EPT_R | EPT_W | EPT_X)
#define EPT_MT_SHIFT			3
#define EPT_MT_MASK			(7ull << EPT_MT_SHIFT)
#define EPT_IPAT			(1ull << 6)
#define EPT_LARGE			(1ull << 7)
#define EPT_SWVALID			(1ull << 11)
#define EPT_TAG_SHIFT			52
#define EPT_TAG_MASK			(0xfull << EPT_TAG_SHIFT)
#define EPT_ADDR_MASK			0x000ffffffffff000ull

#define EPT_TAG_NONE			0
#define EPT_TAG_WATCH			1
#define EPT_TAG_SINK			2
#define EPT_TAG_SELF			3
#define EPT_TAG_STEP			4

#define EPTCAP_EXEC_ONLY		(1ull << 0)
#define EPTCAP_PWL4			(1ull << 6)
#define EPTCAP_UC			(1ull << 8)
#define EPTCAP_WB			(1ull << 14)
#define EPTCAP_2M			(1ull << 16)
#define EPTCAP_1G			(1ull << 17)
#define EPTCAP_INVEPT			(1ull << 20)
#define EPTCAP_INVEPT_SINGLE		(1ull << 25)
#define EPTCAP_INVEPT_ALL		(1ull << 26)
#define EPTCAP_INVVPID			(1ull << 32)
#define EPTCAP_INVVPID_ADDR		(1ull << 40)
#define EPTCAP_INVVPID_SINGLE		(1ull << 41)
#define EPTCAP_INVVPID_ALL		(1ull << 42)
#define EPTCAP_INVVPID_SINGLE_KEEPG	(1ull << 43)

#define MT_UC				0
#define MT_WC				1
#define MT_WT				4
#define MT_WP				5
#define MT_WB				6

#define PTE_P				(1ull << 0)
#define PTE_W				(1ull << 1)
#define PTE_U				(1ull << 2)
#define PTE_PWT				(1ull << 3)
#define PTE_PCD				(1ull << 4)
#define PTE_A				(1ull << 5)
#define PTE_D				(1ull << 6)
#define PTE_PS				(1ull << 7)
#define PTE_G				(1ull << 8)
#define PTE_NX				(1ull << 63)
#define PTE_ADDR_MASK			0x000ffffffffff000ull

#define VPF_P				(1u << 0)
#define VPF_W				(1u << 1)
#define VPF_U				(1u << 2)
#define VPF_RSVD				(1u << 3)
#define VPF_I				(1u << 4)

#define VEC_DE				0
#define VEC_DB				1
#define VEC_NMI				2
#define VEC_BP				3
#define VEC_UD				6
#define VEC_DF				8
#define VEC_TS				10
#define VEC_NP				11
#define VEC_SS				12
#define VEC_GP				13
#define VEC_PF				14
#define VEC_MC				18

#endif
