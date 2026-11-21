#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/irqflags.h>
#include <asm/desc.h>
#include <asm/msr.h>
#include <asm/asm.h>
#include <asm/io.h>
#include <asm/tlbflush.h>
#include <asm/linkage.h>
#include <linux/smp.h>

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)
#define rdmsrq(m, v)		rdmsrl(m, v)
#define wrmsrq(m, v)		wrmsrl(m, v)
#define rdmsrq_safe(m, p)	rdmsrl_safe(m, p)
#define wrmsrq_safe(m, v)	wrmsrl_safe(m, v)
#endif

#define HC_MAGIC 0x5654480000000000ull

static char result[512];
static void *buf_page;
static void *ltr_gdt;

int vtxattack_straddle(void);

asm(".pushsection .text.vtxattack_straddle, \"ax\"\n\t"
    ".balign 4096\n\t"
    ".skip 4094, 0xcc\n\t"
    ".globl vtxattack_straddle\n\t"
    ".type vtxattack_straddle, @function\n"
    "vtxattack_straddle:\n\t"
    ".byte 0xf3, 0x0f, 0x1e, 0xfa\n\t"
    "movl $0x2a, %eax\n\t"
    ASM_RET
    ".size vtxattack_straddle, .-vtxattack_straddle\n\t"
    ".popsection\n");

struct ltr_ctx {
	int prep;
	u16 tr;
	int applied;
	int faulted;
	int busy_before;
	int busy_after;
};
static DEFINE_MUTEX(attack_lock);

static noinline __aligned(4096) int vtxattack_target(int x)
{
	return x * 3 + 1;
}

static u64 raw_cr0(void)
{
	u64 v;

	asm volatile("mov %%cr0, %0" : "=r"(v));
	return v;
}

static void raw_set_cr0(u64 v)
{
	asm volatile("mov %0, %%cr0" : : "r"(v) : "memory");
}

static u64 raw_cr4(void)
{
	u64 v;

	asm volatile("mov %%cr4, %0" : "=r"(v));
	return v;
}

static void raw_set_cr4(u64 v)
{
	asm volatile("mov %0, %%cr4" : : "r"(v) : "memory");
}

static u64 hypercall(u64 fn, u64 b, u64 c)
{
	u64 a = HC_MAGIC | fn;

	asm volatile("vmcall" : "+a"(a), "+b"(b), "+c"(c) : : "rdx", "rsi", "rdi", "memory", "cc");
	return a;
}

static int map_phys(u64 pa, void **alias, struct page **pg)
{
	*pg = pfn_to_page(pa >> PAGE_SHIFT);
	*alias = vmap(pg, 1, VM_MAP, PAGE_KERNEL);
	return *alias ? 0 : -ENOMEM;
}

static int do_physwrite(u64 pa, u8 val, u8 *before, u8 *after)
{
	struct page *pg;
	void *a;
	unsigned long flags;

	if (map_phys(pa & PAGE_MASK, &a, &pg))
		return -ENOMEM;
	local_irq_save(flags);
	*before = READ_ONCE(*((u8 *)a + (pa & ~PAGE_MASK)));
	WRITE_ONCE(*((u8 *)a + (pa & ~PAGE_MASK)), val);
	*after = READ_ONCE(*((u8 *)a + (pa & ~PAGE_MASK)));
	local_irq_restore(flags);
	vunmap(a);
	return 0;
}

static int do_physread(u64 pa, u64 *val)
{
	struct page *pg;
	void *a;

	if (map_phys(pa & PAGE_MASK, &a, &pg))
		return -ENOMEM;
	*val = READ_ONCE(*(u64 *)((u8 *)a + (pa & ~PAGE_MASK & ~7ull)));
	vunmap(a);
	return 0;
}

static void ltr_on_cpu(void *arg)
{
	struct ltr_ctx *c = arg;
	struct desc_ptr orig, fake, now;
	u16 tr;
	u8 *type;

	native_store_gdt(&orig);
	asm volatile("str %0" : "=r"(tr));
	c->tr = tr;
	type = (u8 *)ltr_gdt + (tr & ~7) + 5;
	if (c->prep) {
		memset(ltr_gdt, 0, PAGE_SIZE);
		memcpy(ltr_gdt, (void *)orig.address, min_t(u32, orig.size + 1, PAGE_SIZE));
		*type &= ~0x02;
		c->busy_after = (READ_ONCE(*type) & 0x02) != 0;
		return;
	}
	c->busy_before = (READ_ONCE(*type) & 0x02) != 0;
	fake.address = (unsigned long)ltr_gdt;
	fake.size = orig.size;
	native_load_gdt(&fake);
	native_store_gdt(&now);
	c->applied = now.address == fake.address;
	asm goto("1: ltr %0\n\t"
		 _ASM_EXTABLE(1b, %l[ltrfault])
		 : : "r"(tr) : "memory" : ltrfault);
	goto ltrdone;
ltrfault:
	c->faulted = 1;
ltrdone:
	c->busy_after = (READ_ONCE(*type) & 0x02) != 0;
	native_load_gdt(&orig);
}

static void run(char *cmd)
{
	unsigned long flags;
	char *arg = strchr(cmd, ' ');

	if (arg)
		*arg++ = 0;
	result[0] = 0;
	if (!strcmp(cmd, "cr0wp")) {
		u64 before, mid;
		int faulted = 0;

		local_irq_save(flags);
		before = raw_cr0();
		asm goto("1: mov %0, %%cr0\n\t"
			 _ASM_EXTABLE(1b, %l[cr0fault])
			 : : "r"(before & ~X86_CR0_WP) : "memory" : cr0fault);
		goto cr0done;
cr0fault:
		faulted = 1;
cr0done:
		mid = raw_cr0();
		raw_set_cr0(before);
		local_irq_restore(flags);
		snprintf(result, sizeof(result), "cr0wp wp_before=%llu wp_after_clear=%llu faulted=%d cet=%llu",
			 (before >> 16) & 1, (mid >> 16) & 1, faulted, (raw_cr4() >> 23) & 1);
	} else if (!strcmp(cmd, "smep")) {
		u64 before, mid;

		local_irq_save(flags);
		before = raw_cr4();
		raw_set_cr4(before & ~X86_CR4_SMEP);
		mid = raw_cr4();
		raw_set_cr4(before);
		local_irq_restore(flags);
		snprintf(result, sizeof(result), "smep smep_before=%llu smep_after_clear=%llu", (before >> 20) & 1, (mid >> 20) & 1);
	} else if (!strcmp(cmd, "lstar")) {
		u64 before, mid;

		local_irq_save(flags);
		rdmsrq(MSR_LSTAR, before);
		wrmsrq(MSR_LSTAR, 0xffffffffdeadbeefull);
		rdmsrq(MSR_LSTAR, mid);
		wrmsrq(MSR_LSTAR, before);
		local_irq_restore(flags);
		snprintf(result, sizeof(result), "lstar hijacked=%d before=%#llx after=%#llx", mid != before, before, mid);
	} else if (!strcmp(cmd, "lstar_noncanon")) {
		u64 before, after;
		int rc;

		local_irq_save(flags);
		rdmsrq(MSR_LSTAR, before);
		rc = wrmsrq_safe(MSR_LSTAR, 0x8000000000000000ull);
		rdmsrq(MSR_LSTAR, after);
		if (after != before)
			wrmsrq(MSR_LSTAR, before);
		local_irq_restore(flags);
		snprintf(result, sizeof(result), "lstar_noncanon rc=%d unchanged=%d", rc, after == before);
	} else if (!strcmp(cmd, "lidt") || !strcmp(cmd, "lgdt")) {
		struct desc_ptr orig, fake, now;
		void *buf = (void *)__get_free_page(GFP_KERNEL);
		int idt = !strcmp(cmd, "lidt");

		if (!buf) {
			snprintf(result, sizeof(result), "%s nomem", cmd);
			return;
		}
		local_irq_save(flags);
		if (idt)
			store_idt(&orig);
		else
			native_store_gdt(&orig);
		memcpy(buf, (void *)orig.address, min_t(u32, orig.size + 1, PAGE_SIZE));
		fake.address = (unsigned long)buf;
		fake.size = orig.size;
		if (idt) {
			load_idt(&fake);
			store_idt(&now);
			load_idt(&orig);
		} else {
			native_load_gdt(&fake);
			native_store_gdt(&now);
			native_load_gdt(&orig);
		}
		local_irq_restore(flags);
		snprintf(result, sizeof(result), "%s hijacked=%d orig=%#lx after=%#lx", cmd, now.address == fake.address,
			 orig.address, now.address);
		free_page((unsigned long)buf);
	} else if (!strcmp(cmd, "sgdt")) {
		struct desc_ptr g, i;

		native_store_gdt(&g);
		store_idt(&i);
		snprintf(result, sizeof(result), "sgdt gdt=%#lx/%#x idt=%#lx/%#x tr=%#lx", g.address, g.size, i.address, i.size,
			 native_store_tr());
	} else if (!strcmp(cmd, "physwrite") && arg) {
		u64 pa;
		unsigned int v = 0xcc;
		u8 b = 0, a = 0;
		char *sp = strchr(arg, ' ');

		if (sp) {
			*sp++ = 0;
			if (kstrtouint(sp, 0, &v))
				v = 0xcc;
		}
		if (kstrtoull(arg, 0, &pa)) {
			snprintf(result, sizeof(result), "physwrite badarg");
			return;
		}
		if (do_physwrite(pa, (u8)v, &b, &a))
			snprintf(result, sizeof(result), "physwrite failed");
		else
			snprintf(result, sizeof(result), "physwrite pa=%#llx before=%#x wrote=%#x readback=%#x", pa, b, v & 0xff, a);
	} else if (!strcmp(cmd, "physread") && arg) {
		u64 pa, val = 0;

		if (kstrtoull(arg, 0, &pa) || do_physread(pa, &val))
			snprintf(result, sizeof(result), "physread failed");
		else
			snprintf(result, sizeof(result), "physread pa=%#llx value=%#018llx", pa, val);
	} else if (!strcmp(cmd, "textpad")) {
		snprintf(result, sizeof(result), "textpad pa=%#llx", slow_virt_to_phys((void *)((unsigned long)_printk - 8)));
	} else if (!strcmp(cmd, "buf")) {
		snprintf(result, sizeof(result), "buf va=%#lx pa=%#llx", (unsigned long)buf_page, virt_to_phys(buf_page));
	} else if (!strcmp(cmd, "bufread")) {
		snprintf(result, sizeof(result), "bufread value=%#llx", READ_ONCE(*(u64 *)buf_page));
	} else if (!strcmp(cmd, "bufwrite") && arg) {
		u64 v = 0;

		if (kstrtoull(arg, 0, &v))
			v = 0x4141414141414141ull;
		WRITE_ONCE(*(u64 *)buf_page, v);
		snprintf(result, sizeof(result), "bufwrite readback=%#llx", READ_ONCE(*(u64 *)buf_page));
	} else if (!strcmp(cmd, "target")) {
		snprintf(result, sizeof(result), "target va=%#lx pa=%#llx", (unsigned long)vtxattack_target,
			 slow_virt_to_phys((void *)vtxattack_target));
	} else if (!strcmp(cmd, "call")) {
		int (*volatile fn)(int) = vtxattack_target;

		snprintf(result, sizeof(result), "call result=%d", fn(13));
	} else if (!strcmp(cmd, "vmxon")) {
		u64 pa = 0;
		int faulted = 0;

		asm goto("1: vmxon %0\n\t"
			 _ASM_EXTABLE(1b, %l[fault])
			 : : "m"(pa) : "cc", "memory" : fault);
		goto out_vmx;
fault:
		faulted = 1;
out_vmx:
		snprintf(result, sizeof(result), "vmxon faulted=%d", faulted);
	} else if (!strcmp(cmd, "badmsr")) {
		u64 v = 0;
		int rc = rdmsrq_safe(0x12345678, &v);

		snprintf(result, sizeof(result), "badmsr rc=%d", rc);
	} else if (!strcmp(cmd, "xsetbv")) {
		int faulted = 0;

		asm goto("1: xsetbv\n\t"
			 _ASM_EXTABLE(1b, %l[xfault])
			 : : "c"(0), "a"(0), "d"(0) : "memory" : xfault);
		goto out_x;
xfault:
		faulted = 1;
out_x:
		snprintf(result, sizeof(result), "xsetbv faulted=%d", faulted);
	} else if (!strcmp(cmd, "kprobe") && arg) {
		struct kprobe kp = { .symbol_name = arg };
		int rc = register_kprobe(&kp);

		if (!rc)
			unregister_kprobe(&kp);
		snprintf(result, sizeof(result), "kprobe %s rc=%d", arg, rc);
	} else if (!strcmp(cmd, "hc_unprotect") && arg) {
		unsigned int id = 0;
		s64 rc;

		if (kstrtouint(arg, 0, &id))
			id = 1;
		rc = (s64)hypercall(0x05, id, 0);
		snprintf(result, sizeof(result), "hc_unprotect id=%u rc=%lld", id, rc);
	} else if (!strcmp(cmd, "hc_devirt")) {
		s64 rc;

		local_irq_save(flags);
		rc = (s64)hypercall(0x02, 0, 0);
		local_irq_restore(flags);
		snprintf(result, sizeof(result), "hc_devirt rc=%lld", rc);
	} else if (!strcmp(cmd, "hc_unpin")) {
		s64 rc = (s64)hypercall(0x06, 0, 0x3ff);

		snprintf(result, sizeof(result), "hc_unpin rc=%lld", rc);
	} else if (!strcmp(cmd, "hc_bogus")) {
		s64 rc = (s64)hypercall(0x7f, 0, 0);

		snprintf(result, sizeof(result), "hc_bogus rc=%lld", rc);
	} else if (!strcmp(cmd, "hc_badbuf")) {
		s64 rc = (s64)hypercall(0x09, 0x10, 0);

		snprintf(result, sizeof(result), "hc_badbuf rc=%lld", rc);
	} else if (!strcmp(cmd, "hc_out") && arg) {
		static const struct { const char *n; u64 fn; u64 c; } t[] = {
			{ "drain", 0x08, 1 }, { "stats", 0x09, 0 }, { "query", 0x0a, 0 }, { "wlist", 0x0b, 0 },
		};
		char *pa_s = strchr(arg, ' ');
		u64 pa, b0, b1, a0, a1;
		struct page *pg;
		void *al;
		s64 rc;
		int i;

		if (!pa_s) {
			snprintf(result, sizeof(result), "hc_out badarg");
			goto out;
		}
		*pa_s++ = 0;
		for (i = 0; i < ARRAY_SIZE(t); i++)
			if (!strcmp(arg, t[i].n))
				break;
		if (i == ARRAY_SIZE(t) || kstrtoull(pa_s, 0, &pa) || map_phys(pa & PAGE_MASK, &al, &pg)) {
			snprintf(result, sizeof(result), "hc_out badarg");
			goto out;
		}
		b0 = READ_ONCE(*(u64 *)((u8 *)al + (pa & ~PAGE_MASK & ~7ull)));
		b1 = READ_ONCE(*(u64 *)((u8 *)al + ((pa + 8) & ~PAGE_MASK & ~7ull)));
		rc = (s64)hypercall(t[i].fn, pa, t[i].c);
		a0 = READ_ONCE(*(u64 *)((u8 *)al + (pa & ~PAGE_MASK & ~7ull)));
		a1 = READ_ONCE(*(u64 *)((u8 *)al + ((pa + 8) & ~PAGE_MASK & ~7ull)));
		vunmap(al);
		snprintf(result, sizeof(result), "hc_out fn=%s pa=%#llx rc=%lld unchanged=%d", t[i].n, pa, rc,
			 a0 == b0 && a1 == b1);
	} else if (!strcmp(cmd, "sgdt_at") && arg) {
		struct desc_ptr expect;
		u8 before[10], after[10];
		struct page *pg;
		void *al;
		u8 *dst;
		u64 pa;

		if (kstrtoull(arg, 0, &pa) || map_phys(pa & PAGE_MASK, &al, &pg)) {
			snprintf(result, sizeof(result), "sgdt_at badarg");
			goto out;
		}
		dst = (u8 *)al + 0x200;
		local_irq_save(flags);
		memcpy(before, dst, 10);
		native_store_gdt(&expect);
		asm volatile("sgdt %0" : "=m"(*(struct desc_ptr *)dst) : : "memory");
		memcpy(after, dst, 10);
		local_irq_restore(flags);
		vunmap(al);
		snprintf(result, sizeof(result), "sgdt_at pa=%#llx unchanged=%d stored=%d", pa,
			 !memcmp(before, after, 10), !memcmp(after, &expect, 10));
	} else if (!strcmp(cmd, "ltrbuf")) {
		struct ltr_ctx c = { .prep = 1 };

		smp_call_function_single(0, ltr_on_cpu, &c, 1);
		snprintf(result, sizeof(result), "ltrbuf pa=%#llx tr=%#x busy=%d", (u64)virt_to_phys(ltr_gdt), c.tr,
			 c.busy_after);
	} else if (!strcmp(cmd, "ltr")) {
		struct ltr_ctx c = { .prep = 0 };

		smp_call_function_single(0, ltr_on_cpu, &c, 1);
		snprintf(result, sizeof(result), "ltr tr=%#x lgdt_applied=%d faulted=%d busy_before=%d busy_after=%d",
			 c.tr, c.applied, c.faulted, c.busy_before, c.busy_after);
	} else if (!strcmp(cmd, "straddle")) {
		unsigned long va = (unsigned long)vtxattack_straddle;

		snprintf(result, sizeof(result), "straddle va=%#lx off=%#lx pa_a=%#llx pa_b=%#llx", va, va & ~PAGE_MASK,
			 (u64)slow_virt_to_phys((void *)va) & PAGE_MASK,
			 (u64)slow_virt_to_phys((void *)(va + 2)) & PAGE_MASK);
	} else if (!strcmp(cmd, "straddle_run")) {
		unsigned int n = 100, i;
		u64 sum = 0;

		if (arg && kstrtouint(arg, 0, &n))
			n = 100;
		for (i = 0; i < n; i++) {
			sum += vtxattack_straddle();
			if (!(i & 63))
				cond_resched();
		}
		snprintf(result, sizeof(result), "straddle_run calls=%u sum=%llu", n, sum);
	} else {
		snprintf(result, sizeof(result), "unknown command");
	}
out:
	pr_info("vtxattack: %s\n", result);
}

static ssize_t attack_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
	char cmd[128];

	if (len >= sizeof(cmd))
		return -EINVAL;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = 0;
	strim(cmd);
	mutex_lock(&attack_lock);
	run(cmd);
	mutex_unlock(&attack_lock);
	return len;
}

static ssize_t attack_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
	ssize_t r;

	mutex_lock(&attack_lock);
	r = simple_read_from_buffer(buf, len, off, result, strlen(result));
	mutex_unlock(&attack_lock);
	return r;
}

static const struct file_operations attack_fops = {
	.owner = THIS_MODULE,
	.write = attack_write,
	.read = attack_read,
};

static struct miscdevice attack_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vtxattack",
	.fops = &attack_fops,
	.mode = 0600,
};

static int __init attack_init(void)
{
	int rc;

	buf_page = (void *)get_zeroed_page(GFP_KERNEL);
	ltr_gdt = (void *)get_zeroed_page(GFP_KERNEL);
	if (!buf_page || !ltr_gdt) {
		free_page((unsigned long)buf_page);
		free_page((unsigned long)ltr_gdt);
		return -ENOMEM;
	}
	rc = misc_register(&attack_misc);
	if (rc) {
		free_page((unsigned long)buf_page);
		free_page((unsigned long)ltr_gdt);
	}
	return rc;
}

static void __exit attack_exit(void)
{
	misc_deregister(&attack_misc);
	free_page((unsigned long)buf_page);
	free_page((unsigned long)ltr_gdt);
}

module_init(attack_init);
module_exit(attack_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Adversarial test driver for the Intel VT-x hypervisor test-suite");
