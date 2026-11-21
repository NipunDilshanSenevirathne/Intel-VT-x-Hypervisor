#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>
#include <linux/suspend.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/sched/signal.h>
#include <linux/capability.h>
#include <asm/desc.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include "vtx_drv.h"

unsigned int vtx_param_serial = 0x3f8;
module_param_named(serial, vtx_param_serial, uint, 0444);
MODULE_PARM_DESC(serial, "I/O port of the UART used for fatal diagnostics and event mirroring (0 disables)");

bool vtx_param_serial_events;
module_param_named(serial_events, vtx_param_serial_events, bool, 0444);
MODULE_PARM_DESC(serial_events, "Mirror every event to the UART out of band");

bool vtx_param_introspect = true;
module_param_named(introspect, vtx_param_introspect, bool, 0444);
MODULE_PARM_DESC(introspect, "Attribute events to the guest task (pid/comm)");

unsigned int vtx_param_pin;
module_param_named(pin, vtx_param_pin, uint, 0444);
MODULE_PARM_DESC(pin, "Initial pin mask (VTX_PIN_* bits)");

static bool vtx_param_dtexit = true;
module_param_named(dtexit, vtx_param_dtexit, bool, 0444);
MODULE_PARM_DESC(dtexit, "Intercept descriptor-table instructions (LGDT/LIDT/LLDT/LTR and stores)");

static unsigned int vtx_param_pool;
module_param_named(pool_pages, vtx_param_pool, uint, 0444);
MODULE_PARM_DESC(pool_pages, "EPT page-table pool size in pages (0 = automatic)");

static unsigned int vtx_param_ring = 1024;
module_param_named(ring_events, vtx_param_ring, uint, 0444);
MODULE_PARM_DESC(ring_events, "Per-CPU event ring capacity (power of two)");

static unsigned int vtx_param_guard_text;
module_param_named(guard_text, vtx_param_guard_text, uint, 0444);
MODULE_PARM_DESC(guard_text, "Kernel text write guard at load: 0 off, 1 monitor, 2 enforce");

static unsigned int vtx_param_guard_rodata;
module_param_named(guard_rodata, vtx_param_guard_rodata, uint, 0444);
MODULE_PARM_DESC(guard_rodata, "Kernel rodata write guard at load: 0 off, 1 monitor, 2 enforce");

static unsigned int vtx_param_guard_idt;
module_param_named(guard_idt, vtx_param_guard_idt, uint, 0444);
MODULE_PARM_DESC(guard_idt, "IDT page write guard at load: 0 off, 1 monitor, 2 enforce");

static bool vtx_param_lock;
module_param_named(lock, vtx_param_lock, bool, 0444);
MODULE_PARM_DESC(lock, "Engage the one-way policy lock right after loading");

static DEFINE_MUTEX(vtx_drain_lock);

static long vtx_hc(u64 fn, u64 *b, u64 *c, u64 *dx, u64 *si, u64 *di)
{
	int cpu = get_cpu();
	long rc;

	if (!cpumask_test_cpu(cpu, &vtx_d.virt)) {
		put_cpu();
		return -ENODEV;
	}
	rc = (long)vtx_vmcall(fn, b, c, dx, si, di);
	put_cpu();
	return rc;
}

static void vtx_sync_one(void *unused)
{
	if (cpumask_test_cpu(smp_processor_id(), &vtx_d.virt))
		vtx_vmcall(VTX_HC_SYNC, NULL, NULL, NULL, NULL, NULL);
}

static void vtx_broadcast_sync(void)
{
	cpus_read_lock();
	on_each_cpu(vtx_sync_one, NULL, 1);
	cpus_read_unlock();
}

static long vtx_protect_phys(u64 start, u64 end, u32 deny, u32 mode, u32 *id, const char *name)
{
	u64 b = start, c = end, dx = (deny & 7) | ((u64)(mode & 1) << 8), si = *id, di = 0;
	char *nb = NULL;
	long rc;

	if (name && name[0]) {
		nb = kzalloc(VTX_NAME_LEN, GFP_KERNEL);
		if (!nb)
			return -ENOMEM;
		strscpy(nb, name, VTX_NAME_LEN);
		di = virt_to_phys(nb);
	}
	rc = vtx_hc(VTX_HC_PROTECT, &b, &c, &dx, &si, &di);
	kfree(nb);
	if (!rc)
		*id = (u32)b;
	return rc;
}

static long vtx_unprotect(u32 id)
{
	u64 b = id;

	return vtx_hc(VTX_HC_UNPROTECT, &b, NULL, NULL, NULL, NULL);
}

static int vtx_kva_phys(u64 va, u64 *pa)
{
	unsigned int level;
	pte_t *pte;

	if (va < PAGE_OFFSET && va < __START_KERNEL_map)
		return -EFAULT;
	pte = lookup_address(va, &level);
	if (!pte || !pte_present(*pte))
		return -EFAULT;
	*pa = slow_virt_to_phys((void *)va);
	return 0;
}

static long vtx_watch_add(struct vtx_watch_req *req)
{
	u64 start, end, va, run_pa = 0, run_len = 0;
	u32 id = 0;
	long rc = 0;

	if (!req->len || req->len > (1ull << 30) || !(req->deny & VTX_DENY_ALL) || req->mode > 1)
		return -EINVAL;
	req->name[VTX_NAME_LEN - 1] = 0;
	start = req->addr & PAGE_MASK;
	end = PAGE_ALIGN(req->addr + req->len);
	if (end <= start)
		return -EINVAL;
	if (!(req->flags & VTX_WF_VIRT)) {
		rc = vtx_protect_phys(start, end, req->deny, req->mode, &id, req->name);
		if (!rc) {
			req->id = id;
			vtx_broadcast_sync();
		}
		return rc;
	}
	for (va = start; va < end; va += PAGE_SIZE) {
		u64 pa;

		rc = vtx_kva_phys(va, &pa);
		if (rc)
			break;
		if (run_len && pa == run_pa + run_len) {
			run_len += PAGE_SIZE;
			continue;
		}
		if (run_len) {
			rc = vtx_protect_phys(run_pa, run_pa + run_len, req->deny, req->mode, &id, req->name);
			if (rc)
				break;
		}
		run_pa = pa;
		run_len = PAGE_SIZE;
	}
	if (!rc && run_len)
		rc = vtx_protect_phys(run_pa, run_pa + run_len, req->deny, req->mode, &id, req->name);
	if (rc && id)
		vtx_unprotect(id);
	if (!rc)
		req->id = id;
	vtx_broadcast_sync();
	return rc;
}

static long vtx_guard(struct vtx_guard_req *g)
{
	u64 start = 0, end = 0;
	const char *name;
	u32 id = 0;
	long rc;

	if (g->mode > 1)
		return -EINVAL;
	switch (g->which) {
	case VTX_GUARD_KTEXT:
		start = vtx_d.ktext_start;
		end = vtx_d.ktext_end;
		name = "kernel-text";
		break;
	case VTX_GUARD_KRODATA:
		start = vtx_d.krodata_start;
		end = vtx_d.krodata_end;
		name = "kernel-rodata";
		break;
	case VTX_GUARD_IDT: {
		struct desc_ptr dp;

		store_idt(&dp);
		if (vtx_kva_phys(dp.address, &start))
			return -EFAULT;
		end = start + dp.size + 1;
		name = "idt";
		break;
	}
	default:
		return -EINVAL;
	}
	if (!start || end <= start)
		return -ENOENT;
	start &= PAGE_MASK;
	end = PAGE_ALIGN(end);
	rc = vtx_protect_phys(start, end, VTX_DENY_W, g->mode, &id, name);
	if (!rc) {
		g->id = id;
		vtx_broadcast_sync();
	}
	return rc;
}

static long vtx_lock(void)
{
	long rc = vtx_hc(VTX_HC_LOCK, NULL, NULL, NULL, NULL, NULL);

	if (rc)
		return rc;
	mutex_lock(&vtx_d.lock);
	if (!vtx_d.locked) {
		vtx_d.locked = 1;
		__module_get(THIS_MODULE);
	}
	mutex_unlock(&vtx_d.lock);
	pr_info("vtxhv: policy lock engaged; the hypervisor can no longer be unloaded or weakened\n");
	return 0;
}

static long vtx_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	void __user *up = (void __user *)arg;
	long rc;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	switch (cmd) {
	case VTX_IOC_STATUS: {
		struct vtx_status *s = kzalloc(sizeof(*s), GFP_KERNEL);
		u64 b;

		if (!s)
			return -ENOMEM;
		b = virt_to_phys(s);
		rc = vtx_hc(VTX_HC_QUERY, &b, NULL, NULL, NULL, NULL);
		s->online_cpus = num_online_cpus();
		if (!rc && copy_to_user(up, s, sizeof(*s)))
			rc = -EFAULT;
		kfree(s);
		return rc;
	}
	case VTX_IOC_CAPS: {
		struct vtx_caps c;

		memset(&c, 0, sizeof(c));
		memcpy(c.msr, vtx_d.caps, sizeof(c.msr));
		c.valid = vtx_d.caps_valid;
		c.maxphyaddr = vtx_d.maxphy;
		c.pin_used = vtx_d.pin;
		c.proc_used = vtx_d.proc;
		c.proc2_used = vtx_d.proc2;
		c.exit_used = vtx_d.exitc;
		c.entry_used = vtx_d.entryc;
		return copy_to_user(up, &c, sizeof(c)) ? -EFAULT : 0;
	}
	case VTX_IOC_WATCH_ADD: {
		struct vtx_watch_req req;

		if (copy_from_user(&req, up, sizeof(req)))
			return -EFAULT;
		rc = vtx_watch_add(&req);
		if (!rc && copy_to_user(up, &req, sizeof(req)))
			rc = -EFAULT;
		return rc;
	}
	case VTX_IOC_WATCH_DEL: {
		u32 id;

		if (copy_from_user(&id, up, sizeof(id)))
			return -EFAULT;
		rc = vtx_unprotect(id);
		vtx_broadcast_sync();
		return rc;
	}
	case VTX_IOC_WATCH_LIST: {
		struct vtx_watch_list *l = kzalloc(sizeof(*l), GFP_KERNEL);
		u64 b;

		if (!l)
			return -ENOMEM;
		b = virt_to_phys(l);
		rc = vtx_hc(VTX_HC_WLIST, &b, NULL, NULL, NULL, NULL);
		if (!rc && copy_to_user(up, l, sizeof(*l)))
			rc = -EFAULT;
		kfree(l);
		return rc;
	}
	case VTX_IOC_POLICY: {
		struct vtx_policy p;
		u64 b, c;

		if (copy_from_user(&p, up, sizeof(p)))
			return -EFAULT;
		if ((p.set | p.clear) & ~VTX_PIN_ALL)
			return -EINVAL;
		if ((p.set & VTX_PIN_DTR) && !(vtx_d.proc2 & PROC2_DESC_TABLE))
			return -EOPNOTSUPP;
		b = p.set;
		c = p.clear;
		rc = vtx_hc(VTX_HC_POLICY, &b, &c, NULL, NULL, NULL);
		if (rc)
			return rc;
		p.result = (u32)b;
		vtx_broadcast_sync();
		return copy_to_user(up, &p, sizeof(p)) ? -EFAULT : 0;
	}
	case VTX_IOC_LOCK:
		return vtx_lock();
	case VTX_IOC_STATS: {
		struct vtx_stats *s = kzalloc(sizeof(*s), GFP_KERNEL);
		u64 b;

		if (!s)
			return -ENOMEM;
		b = virt_to_phys(s);
		rc = vtx_hc(VTX_HC_STATS, &b, NULL, NULL, NULL, NULL);
		if (!rc && copy_to_user(up, s, sizeof(*s)))
			rc = -EFAULT;
		kfree(s);
		return rc;
	}
	case VTX_IOC_GUARD: {
		struct vtx_guard_req g;

		if (copy_from_user(&g, up, sizeof(g)))
			return -EFAULT;
		rc = vtx_guard(&g);
		if (!rc && copy_to_user(up, &g, sizeof(g)))
			rc = -EFAULT;
		return rc;
	}
	default:
		return -ENOTTY;
	}
}

static ssize_t vtx_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
	u32 max = len / sizeof(struct vtx_event);
	struct vtx_event *kb;
	ssize_t ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!max)
		return -EINVAL;
	if (max > 256)
		max = 256;
	kb = kmalloc_array(max, sizeof(*kb), GFP_KERNEL);
	if (!kb)
		return -ENOMEM;
	for (;;) {
		u64 b = virt_to_phys(kb), c = max;
		long n;

		mutex_lock(&vtx_drain_lock);
		n = vtx_hc(VTX_HC_DRAIN, &b, &c, NULL, NULL, NULL);
		mutex_unlock(&vtx_drain_lock);
		if (n < 0) {
			ret = n;
			break;
		}
		if (n > 0) {
			ret = copy_to_user(buf, kb, n * sizeof(*kb)) ? -EFAULT : (ssize_t)(n * sizeof(*kb));
			break;
		}
		if (f->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
		if (msleep_interruptible(25) || signal_pending(current)) {
			ret = -EINTR;
			break;
		}
	}
	kfree(kb);
	return ret;
}

static const struct file_operations vtx_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = vtx_ioctl,
	.compat_ioctl = vtx_ioctl,
	.read = vtx_read,
	.llseek = noop_llseek,
};

static struct miscdevice vtx_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = VTX_DEVICE_NAME,
	.fops = &vtx_fops,
	.mode = 0600,
};

static int vtx_cpu_online(unsigned int cpu)
{
	int rc;

	if (!vtx_d.ready)
		return 0;
	rc = vtx_cpu_launch(&vtx_d, cpu);
	if (!rc)
		cpumask_set_cpu(cpu, &vtx_d.virt);
	return rc;
}

static int vtx_cpu_offline(unsigned int cpu)
{
	int rc;

	if (!cpumask_test_cpu(cpu, &vtx_d.virt))
		return 0;
	if (vtx_d.locked && !vtx_d.unloading)
		return -EBUSY;
	rc = vtx_cpu_devirt(&vtx_d, cpu);
	if (!rc)
		cpumask_clear_cpu(cpu, &vtx_d.virt);
	return rc;
}

static void vtx_devirt_one(void *unused)
{
	unsigned int cpu = smp_processor_id();

	if (cpumask_test_cpu(cpu, &vtx_d.virt) && !vtx_cpu_devirt(&vtx_d, cpu))
		cpumask_clear_cpu(cpu, &vtx_d.virt);
}

static void vtx_launch_one(void *unused)
{
	unsigned int cpu = smp_processor_id();

	if (!cpumask_test_cpu(cpu, &vtx_d.virt) && !vtx_cpu_launch(&vtx_d, cpu))
		cpumask_set_cpu(cpu, &vtx_d.virt);
}

static int vtx_pm_notify(struct notifier_block *nb, unsigned long action, void *data)
{
	switch (action) {
	case PM_HIBERNATION_PREPARE:
	case PM_SUSPEND_PREPARE:
		if (vtx_d.locked)
			return notifier_from_errno(-EBUSY);
		on_each_cpu(vtx_devirt_one, NULL, 1);
		break;
	case PM_POST_HIBERNATION:
	case PM_POST_SUSPEND:
	case PM_POST_RESTORE:
		if (!vtx_d.locked)
			on_each_cpu(vtx_launch_one, NULL, 1);
		break;
	}
	return NOTIFY_OK;
}

static int vtx_reboot_notify(struct notifier_block *nb, unsigned long action, void *data)
{
	if (!vtx_d.locked)
		on_each_cpu(vtx_devirt_one, NULL, 1);
	return NOTIFY_DONE;
}

static struct notifier_block vtx_pm_nb = { .notifier_call = vtx_pm_notify };
static struct notifier_block vtx_reboot_nb = { .notifier_call = vtx_reboot_notify, .priority = INT_MAX };

static void vtx_apply_load_guards(void)
{
	static const u32 which[3] = { VTX_GUARD_KTEXT, VTX_GUARD_KRODATA, VTX_GUARD_IDT };
	unsigned int modes[3] = { vtx_param_guard_text, vtx_param_guard_rodata, vtx_param_guard_idt };
	int i;

	for (i = 0; i < 3; i++) {
		struct vtx_guard_req g = { .which = which[i] };
		long rc;

		if (!modes[i])
			continue;
		g.mode = modes[i] >= 2 ? VTX_MODE_ENFORCE : VTX_MODE_MONITOR;
		rc = vtx_guard(&g);
		if (rc)
			pr_warn("vtxhv: guard %u failed (%ld)\n", which[i], rc);
	}
}

static int __init vtx_init(void)
{
	int rc;

	mutex_init(&vtx_d.lock);
	cpumask_clear(&vtx_d.virt);
	rc = vtx_probe(&vtx_d, vtx_param_dtexit);
	if (rc)
		return rc;
	if ((vtx_param_pin & ~VTX_PIN_ALL) ||
	    ((vtx_param_pin & VTX_PIN_DTR) && !(vtx_d.proc2 & PROC2_DESC_TABLE))) {
		pr_err("vtxhv: pin=%#x cannot be enforced: IDTR/GDTR/TR pins need descriptor-table exiting (dtexit=%d, cpu support %s)\n",
		       vtx_param_pin, vtx_param_dtexit, vtx_ctl_allowed(vtx_d.caps[VTX_CAP_PROCBASED2], PROC2_DESC_TABLE) ? "yes" : "no");
		return -EOPNOTSUPP;
	}
	rc = vtx_alloc_all(&vtx_d, vtx_param_pool, vtx_param_ring);
	if (rc) {
		pr_err("vtxhv: allocation failed (%d)\n", rc);
		vtx_free_all(&vtx_d);
		return rc;
	}
	rc = misc_register(&vtx_misc);
	if (rc) {
		vtx_free_all(&vtx_d);
		return rc;
	}
	vtx_d.ready = 1;
	rc = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "vtxhv:online", vtx_cpu_online, vtx_cpu_offline);
	if (rc < 0) {
		pr_err("vtxhv: virtualization failed (%d)\n", rc);
		vtx_d.ready = 0;
		misc_deregister(&vtx_misc);
		if (cpumask_empty(&vtx_d.virt))
			vtx_free_all(&vtx_d);
		return rc;
	}
	vtx_d.hp_state = rc;
	register_pm_notifier(&vtx_pm_nb);
	register_reboot_notifier(&vtx_reboot_nb);
	vtx_apply_load_guards();
	pr_info("vtxhv: Intel VT-x hypervisor active on %u/%u CPUs; arena %llu KiB in %u chunks; EPT pool %u/%u pages; features %#x\n",
		cpumask_weight(&vtx_d.virt), num_online_cpus(), vtx_d.arena_bytes >> 10, vtx_d.nchunks,
		vtx_d.ept_pages, vtx_d.pool_total, vtx_d.features);
	if (vtx_param_lock)
		vtx_lock();
	return 0;
}

static void __exit vtx_exit(void)
{
	if (vtx_d.locked)
		panic("vtxhv: forced unload of a locked hypervisor");
	unregister_reboot_notifier(&vtx_reboot_nb);
	unregister_pm_notifier(&vtx_pm_nb);
	vtx_d.unloading = 1;
	cpuhp_remove_state(vtx_d.hp_state);
	vtx_d.ready = 0;
	misc_deregister(&vtx_misc);
	if (!cpumask_empty(&vtx_d.virt)) {
		pr_crit("vtxhv: %u CPUs still virtualized; leaking hypervisor memory\n", cpumask_weight(&vtx_d.virt));
		return;
	}
	vtx_free_all(&vtx_d);
	pr_info("vtxhv: unloaded, all CPUs returned to native execution\n");
}

module_init(vtx_init);
module_exit(vtx_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nipun Dilshan Senevirathne");
MODULE_DESCRIPTION("Intel VT-x hypervisor for live memory introspection");
MODULE_VERSION("1.0.0");
