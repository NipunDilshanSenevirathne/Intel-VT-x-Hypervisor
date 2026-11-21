	.equ VTX_STACK_SIZE, 16384
	.equ VCPU_OFF_NMI_PENDING, 8
	.equ VCPU_OFF_VMX_ACTIVE, 16
	.equ VMCS_PROC_CTLS, 0x4002
	.equ PROC_NMI_WINDOW, 0x400000

	.macro SAVE_GPRS
	pushq %r15
	pushq %r14
	pushq %r13
	pushq %r12
	pushq %r11
	pushq %r10
	pushq %r9
	pushq %r8
	pushq %rdi
	pushq %rsi
	pushq %rbp
	pushq %rbx
	pushq %rdx
	pushq %rcx
	pushq %rax
	.endm

	.macro LOAD_GPRS
	popq %rax
	popq %rcx
	popq %rdx
	popq %rbx
	popq %rbp
	popq %rsi
	popq %rdi
	popq %r8
	popq %r9
	popq %r10
	popq %r11
	popq %r12
	popq %r13
	popq %r14
	popq %r15
	.endm

	.balign 64
	.globl vtx_exit_stub
	.type vtx_exit_stub, @function
vtx_exit_stub:
	endbr64
	SAVE_GPRS
	movq %rsp, %rsi
	movq 176(%rsp), %rdi
	subq $8, %rsp
	call vtx_handle_exit
	addq $8, %rsp
	testl %eax, %eax
	jnz 2f
	LOAD_GPRS
	vmresume
	pushfq
	popq %rsi
	movq 56(%rsp), %rdi
	call vtx_resume_failed
	ud2
2:
	LOAD_GPRS
	iretq
	int3
	.size vtx_exit_stub, . - vtx_exit_stub

	.macro IDT_STUB vec
	.balign 32
	endbr64
	.if (\vec - 8) * (\vec - 10) * (\vec - 11) * (\vec - 12) * (\vec - 13) * (\vec - 14) * (\vec - 17) * (\vec - 21) * (\vec - 29) * (\vec - 30)
	pushq $0
	.endif
	pushq $\vec
	jmp vtx_idt_common
	.endm

	.balign 32
	.globl vtx_idt_stubs
vtx_idt_stubs:
	.irp v, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	IDT_STUB \v
	.endr

	.balign 32
vtx_idt_common:
	SAVE_GPRS
	movq %rsp, %rdi
	call vtx_host_exception
	LOAD_GPRS
	addq $16, %rsp
	iretq
	int3

	.balign 32
	.globl vtx_nmi_stub
	.type vtx_nmi_stub, @function
vtx_nmi_stub:
	endbr64
	pushq %rax
	pushq %rcx
	pushq %rdx
	movq %rsp, %rax
	andq $-VTX_STACK_SIZE, %rax
	movq VTX_STACK_SIZE-8(%rax), %rax
	lock incq VCPU_OFF_NMI_PENDING(%rax)
	cmpl $1, VCPU_OFF_VMX_ACTIVE(%rax)
	jne 1f
	movq $VMCS_PROC_CTLS, %rcx
	vmread %rcx, %rdx
	orq $PROC_NMI_WINDOW, %rdx
	vmwrite %rdx, %rcx
1:
	popq %rdx
	popq %rcx
	popq %rax
	iretq
	int3
	.size vtx_nmi_stub, . - vtx_nmi_stub

	.balign 16
	.globl vtx_safe_rdmsr
	.type vtx_safe_rdmsr, @function
vtx_safe_rdmsr:
	endbr64
	movl %edi, %ecx
	.globl vtx_fault_rdmsr
vtx_fault_rdmsr:
	rdmsr
	shlq $32, %rdx
	orq %rdx, %rax
	movq %rax, (%rsi)
	xorl %eax, %eax
	ret
	int3
	.globl vtx_fixup_rdmsr
vtx_fixup_rdmsr:
	movl $1, %eax
	ret
	int3
	.size vtx_safe_rdmsr, . - vtx_safe_rdmsr

	.balign 16
	.globl vtx_safe_wrmsr
	.type vtx_safe_wrmsr, @function
vtx_safe_wrmsr:
	endbr64
	movl %edi, %ecx
	movl %esi, %eax
	movq %rsi, %rdx
	shrq $32, %rdx
	.globl vtx_fault_wrmsr
vtx_fault_wrmsr:
	wrmsr
	xorl %eax, %eax
	ret
	int3
	.globl vtx_fixup_wrmsr
vtx_fixup_wrmsr:
	movl $1, %eax
	ret
	int3
	.size vtx_safe_wrmsr, . - vtx_safe_wrmsr

	.balign 16
	.globl vtx_safe_xsetbv
	.type vtx_safe_xsetbv, @function
vtx_safe_xsetbv:
	endbr64
	movl %edi, %ecx
	movl %esi, %eax
	movq %rsi, %rdx
	shrq $32, %rdx
	.globl vtx_fault_xsetbv
vtx_fault_xsetbv:
	xsetbv
	xorl %eax, %eax
	ret
	int3
	.globl vtx_fixup_xsetbv
vtx_fixup_xsetbv:
	movl $1, %eax
	ret
	int3
	.size vtx_safe_xsetbv, . - vtx_safe_xsetbv

	.balign 16
	.globl vtx_asm_launch
	.type vtx_asm_launch, @function
vtx_asm_launch:
	endbr64
	pushq %rbp
	pushq %rbx
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	pushfq
	movq $0x681c, %rdx
	vmwrite %rsp, %rdx
	jna 3f
	leaq 4f(%rip), %rax
	movq $0x681e, %rdx
	vmwrite %rax, %rdx
	jna 3f
	pushfq
	popq %rax
	movq $0x6820, %rdx
	vmwrite %rax, %rdx
	jna 3f
	xorl %eax, %eax
	vmlaunch
	jc 1f
	jz 2f
1:
	movabsq $0x100000000, %rax
	jmp 5f
2:
	movq $0x4400, %rdx
	vmread %rdx, %rax
	movabsq $0x200000000, %rdx
	orq %rdx, %rax
	jmp 5f
3:
	movabsq $0x400000000, %rax
	jmp 5f
4:
	endbr64
5:
	popfq
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbx
	popq %rbp
	ret
	int3
	.size vtx_asm_launch, . - vtx_asm_launch
