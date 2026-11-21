#ifndef VTX_ARCH_H
#define VTX_ARCH_H

#include "vtx_types.h"

struct vtx_dtr {
	u16 limit;
	u64 base;
} __attribute__((packed));

VTX_HOSTI u64 vtx_rdmsr(u32 msr)
{
	u32 lo, hi;

	asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
	return ((u64)hi << 32) | lo;
}

VTX_HOSTI void vtx_wrmsr(u32 msr, u64 val)
{
	asm volatile("wrmsr" : : "c"(msr), "a"((u32)val), "d"((u32)(val >> 32)) : "memory");
}

VTX_HOSTI u64 vtx_rdtsc(void)
{
	u32 lo, hi;

	asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((u64)hi << 32) | lo;
}

VTX_HOSTI void vtx_cpuid(u32 leaf, u32 sub, u32 *a, u32 *b, u32 *c, u32 *d)
{
	asm volatile("cpuid" : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d) : "a"(leaf), "c"(sub));
}

VTX_HOSTI u64 vtx_read_cr0(void)
{
	u64 v;

	asm volatile("mov %%cr0, %0" : "=r"(v));
	return v;
}

VTX_HOSTI u64 vtx_read_cr2(void)
{
	u64 v;

	asm volatile("mov %%cr2, %0" : "=r"(v));
	return v;
}

VTX_HOSTI u64 vtx_read_cr3(void)
{
	u64 v;

	asm volatile("mov %%cr3, %0" : "=r"(v));
	return v;
}

VTX_HOSTI u64 vtx_read_cr4(void)
{
	u64 v;

	asm volatile("mov %%cr4, %0" : "=r"(v));
	return v;
}

VTX_HOSTI void vtx_write_cr0(u64 v)
{
	asm volatile("mov %0, %%cr0" : : "r"(v) : "memory");
}

VTX_HOSTI void vtx_write_cr2(u64 v)
{
	asm volatile("mov %0, %%cr2" : : "r"(v) : "memory");
}

VTX_HOSTI void vtx_write_cr3(u64 v)
{
	asm volatile("mov %0, %%cr3" : : "r"(v) : "memory");
}

VTX_HOSTI void vtx_write_cr4(u64 v)
{
	asm volatile("mov %0, %%cr4" : : "r"(v) : "memory");
}

VTX_HOSTI u64 vtx_read_dr7(void)
{
	u64 v;

	asm volatile("mov %%dr7, %0" : "=r"(v));
	return v;
}

VTX_HOSTI void vtx_write_dr7(u64 v)
{
	asm volatile("mov %0, %%dr7" : : "r"(v));
}

VTX_HOSTI u64 vtx_read_rflags(void)
{
	u64 v;

	asm volatile("pushfq; popq %0" : "=r"(v));
	return v;
}

VTX_HOSTI void vtx_sgdt(struct vtx_dtr *d)
{
	asm volatile("sgdt %0" : "=m"(*d));
}

VTX_HOSTI void vtx_sidt(struct vtx_dtr *d)
{
	asm volatile("sidt %0" : "=m"(*d));
}

VTX_HOSTI void vtx_lgdt(const struct vtx_dtr *d)
{
	asm volatile("lgdt %0" : : "m"(*d) : "memory");
}

VTX_HOSTI void vtx_lidt(const struct vtx_dtr *d)
{
	asm volatile("lidt %0" : : "m"(*d) : "memory");
}

VTX_HOSTI u16 vtx_str(void)
{
	u16 v;

	asm volatile("str %0" : "=r"(v));
	return v;
}

VTX_HOSTI u16 vtx_sldt(void)
{
	u16 v;

	asm volatile("sldt %0" : "=r"(v));
	return v;
}

VTX_HOSTI void vtx_ltr(u16 sel)
{
	asm volatile("ltr %0" : : "r"(sel) : "memory");
}

VTX_HOSTI void vtx_lldt(u16 sel)
{
	asm volatile("lldt %0" : : "r"(sel) : "memory");
}

#define VTX_READ_SEG(name)						\
VTX_HOSTI u16 vtx_read_##name(void)					\
{									\
	u16 v;								\
	asm volatile("mov %%" #name ", %0" : "=r"(v));			\
	return v;							\
}

VTX_READ_SEG(cs)
VTX_READ_SEG(ss)
VTX_READ_SEG(ds)
VTX_READ_SEG(es)
VTX_READ_SEG(fs)
VTX_READ_SEG(gs)

VTX_HOSTI void vtx_load_ds(u16 v)
{
	asm volatile("mov %0, %%ds" : : "r"(v));
}

VTX_HOSTI void vtx_load_es(u16 v)
{
	asm volatile("mov %0, %%es" : : "r"(v));
}

VTX_HOSTI void vtx_load_fs(u16 v)
{
	asm volatile("mov %0, %%fs" : : "r"(v));
}

VTX_HOSTI void vtx_load_gs(u16 v)
{
	asm volatile("mov %0, %%gs" : : "r"(v));
}

VTX_HOSTI u32 vtx_lar(u16 sel, int *ok)
{
	u32 ar = 0;
	u8 z;

	asm volatile("lar %k2, %k0\n\tsetz %1" : "=r"(ar), "=q"(z) : "r"((u32)sel), "0"(0) : "cc");
	*ok = z;
	return ar;
}

VTX_HOSTI u32 vtx_lsl(u16 sel)
{
	u32 lim = 0;

	asm volatile("lsl %k1, %k0" : "=r"(lim) : "r"((u32)sel), "0"(0) : "cc");
	return lim;
}

VTX_HOSTI void vtx_pause(void)
{
	asm volatile("pause" : : : "memory");
}

VTX_HOSTI void vtx_wbinvd(void)
{
	asm volatile("wbinvd" : : : "memory");
}

VTX_HOSTI void vtx_outb(u16 port, u8 v)
{
	asm volatile("outb %0, %1" : : "a"(v), "Nd"(port));
}

VTX_HOSTI u8 vtx_inb(u16 port)
{
	u8 v;

	asm volatile("inb %1, %0" : "=a"(v) : "Nd"(port));
	return v;
}

VTX_HOSTI void vtx_memcpy(void *dst, const void *src, u64 n)
{
	asm volatile("rep movsb" : "+D"(dst), "+S"(src), "+c"(n) : : "memory");
}

VTX_HOSTI void vtx_memset(void *dst, u8 v, u64 n)
{
	asm volatile("rep stosb" : "+D"(dst), "+c"(n) : "a"(v) : "memory");
}

VTX_HOSTI u64 vtx_xchg64(u64 *p, u64 v)
{
	asm volatile("xchgq %0, %1" : "+r"(v), "+m"(*p) : : "memory");
	return v;
}

VTX_HOSTI u64 vtx_xadd64(u64 *p, u64 v)
{
	asm volatile("lock xaddq %0, %1" : "+r"(v), "+m"(*p) : : "memory", "cc");
	return v;
}

VTX_HOSTI void vtx_or8(u8 *p, u8 v)
{
	asm volatile("lock orb %1, %0" : "+m"(*p) : "iq"(v) : "memory", "cc");
}

VTX_HOSTI u32 vtx_xadd32(u32 *p, u32 v)
{
	asm volatile("lock xaddl %0, %1" : "+r"(v), "+m"(*p) : : "memory", "cc");
	return v;
}

VTX_HOSTI u32 vtx_cmpxchg32(u32 *p, u32 old, u32 new)
{
	u32 prev;

	asm volatile("lock cmpxchgl %2, %1" : "=a"(prev), "+m"(*p) : "r"(new), "0"(old) : "memory", "cc");
	return prev;
}

VTX_HOSTI void vtx_spin_lock(u32 *l)
{
	while (vtx_cmpxchg32(l, 0, 1) != 0) {
		while (READ_ONCE(*l))
			vtx_pause();
	}
}

VTX_HOSTI void vtx_spin_unlock(u32 *l)
{
	asm volatile("" : : : "memory");
	WRITE_ONCE(*l, 0);
}

VTX_HOSTI u64 vtx_vmread(u64 field)
{
	u64 v;

	asm volatile("vmread %1, %0" : "=r"(v) : "r"(field) : "cc");
	return v;
}

VTX_HOSTI void vtx_vmwrite(u64 field, u64 val)
{
	asm volatile("vmwrite %1, %0" : : "r"(field), "rm"(val) : "cc", "memory");
}

VTX_HOSTI int vtx_vmwrite_chk(u64 field, u64 val)
{
	u8 bad;

	asm volatile("vmwrite %2, %1\n\tsetna %0" : "=q"(bad) : "r"(field), "rm"(val) : "cc", "memory");
	return bad ? -1 : 0;
}

VTX_HOSTI int vtx_vmxon(u64 pa)
{
	u8 bad;

	asm volatile("vmxon %1\n\tsetna %0" : "=q"(bad) : "m"(pa) : "cc", "memory");
	return bad ? -1 : 0;
}

VTX_HOSTI void vtx_vmxoff(void)
{
	asm volatile("vmxoff" : : : "cc", "memory");
}

VTX_HOSTI int vtx_vmclear(u64 pa)
{
	u8 bad;

	asm volatile("vmclear %1\n\tsetna %0" : "=q"(bad) : "m"(pa) : "cc", "memory");
	return bad ? -1 : 0;
}

VTX_HOSTI int vtx_vmptrld(u64 pa)
{
	u8 bad;

	asm volatile("vmptrld %1\n\tsetna %0" : "=q"(bad) : "m"(pa) : "cc", "memory");
	return bad ? -1 : 0;
}

VTX_HOSTI int vtx_invept(u64 type, u64 eptp)
{
	struct {
		u64 eptp;
		u64 rsvd;
	} d = { eptp, 0 };
	u8 bad;

	asm volatile("invept %1, %2\n\tsetna %0" : "=q"(bad) : "m"(d), "r"(type) : "cc", "memory");
	return bad ? -1 : 0;
}

VTX_HOSTI int vtx_invvpid(u64 type, u16 vpid, u64 gva)
{
	struct {
		u64 vpid;
		u64 gva;
	} d = { vpid, gva };
	u8 bad;

	asm volatile("invvpid %1, %2\n\tsetna %0" : "=q"(bad) : "m"(d), "r"(type) : "cc", "memory");
	return bad ? -1 : 0;
}

VTX_HOSTI void vtx_cli_hlt_forever(void)
{
	for (;;)
		asm volatile("cli; hlt" : : : "memory");
}

#endif
