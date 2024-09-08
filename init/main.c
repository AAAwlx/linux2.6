/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  GK 2/5/95  -  Changed to support mounting root fs via NFS
 *  Added initrd & change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Moan early if gcc is old, avoiding bogus kernels - Paul Gortmaker, May '96
 *  Simplified starting of init:  Michael A. Griffith <grif@acm.org> 
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/stackprotector.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/smp_lock.h>
#include <linux/initrd.h>
#include <linux/bootmem.h>
#include <linux/acpi.h>
#include <linux/tty.h>
#include <linux/percpu.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/kernel_stat.h>
#include <linux/start_kernel.h>
#include <linux/security.h>
#include <linux/smp.h>
#include <linux/workqueue.h>
#include <linux/profile.h>
#include <linux/rcupdate.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/cgroup.h>
#include <linux/efi.h>
#include <linux/tick.h>
#include <linux/interrupt.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/unistd.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>
#include <linux/buffer_head.h>
#include <linux/page_cgroup.h>
#include <linux/debug_locks.h>
#include <linux/debugobjects.h>
#include <linux/lockdep.h>
#include <linux/kmemleak.h>
#include <linux/pid_namespace.h>
#include <linux/device.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/idr.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <linux/kmemcheck.h>
#include <linux/kmemtrace.h>
#include <linux/sfi.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <trace/boot.h>

#include <asm/io.h>
#include <asm/bugs.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>

#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/smp.h>
#endif

static int kernel_init(void *);

extern void init_IRQ(void);
extern void fork_init(unsigned long);
extern void mca_init(void);
extern void sbus_init(void);
extern void prio_tree_init(void);
extern void radix_tree_init(void);
extern void free_initmem(void);
#ifndef CONFIG_DEBUG_RODATA
static inline void mark_rodata_ro(void) { }
#endif

#ifdef CONFIG_TC
extern void tc_init(void);
#endif

enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/* Default late time init is NULL. archs can override this later. */
void (*__initdata late_time_init)(void);
extern void softirq_init(void);

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];
/* Untouched saved command line (eg. for /proc) */
char *saved_command_line;
/* Command line for parameter parsing */
static char *static_command_line;

static char *execute_command;
static char *ramdisk_execute_command;

#ifdef CONFIG_SMP
/* Setup configured maximum number of CPUs to activate */
unsigned int __initdata setup_max_cpus = NR_CPUS;

/*
 * Setup routine for controlling SMP activation
 *
 * Command-line option of "nosmp" or "maxcpus=0" will disable SMP
 * activation entirely (the MPS table probe still happens, though).
 *
 * Command-line option of "maxcpus=<NUM>", where <NUM> is an integer
 * greater than 0, limits the maximum number of CPUs activated in
 * SMP mode to <NUM>.
 */

void __weak arch_disable_smp_support(void) { }

static int __init nosmp(char *str)
{
	setup_max_cpus = 0;
	arch_disable_smp_support();

	return 0;
}

early_param("nosmp", nosmp);

/* this is hard limit */
static int __init nrcpus(char *str)
{
	int nr_cpus;

	get_option(&str, &nr_cpus);
	if (nr_cpus > 0 && nr_cpus < nr_cpu_ids)
		nr_cpu_ids = nr_cpus;

	return 0;
}

early_param("nr_cpus", nrcpus);

static int __init maxcpus(char *str)
{
	get_option(&str, &setup_max_cpus);
	if (setup_max_cpus == 0)
		arch_disable_smp_support();

	return 0;
}

early_param("maxcpus", maxcpus);
#else
static const unsigned int setup_max_cpus = NR_CPUS;
#endif

/*
 * If set, this is an indication to the drivers that reset the underlying
 * device before going ahead with the initialization otherwise driver might
 * rely on the BIOS and skip the reset operation.
 *
 * This is useful if kernel is booting in an unreliable environment.
 * For ex. kdump situaiton where previous kernel has crashed, BIOS has been
 * skipped and devices will be in unknown state.
 */
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static int __init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

__setup("reset_devices", set_reset_devices);

static char * argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
char * envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

extern struct obs_kernel_param __setup_start[], __setup_end[];

static int __init obsolete_checksetup(char *line)
{
	struct obs_kernel_param *p;
	int had_early_param = 0;

	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (!strncmp(line, p->str, n)) {
			if (p->early) {
				/* Already done in parse_early_param?
				 * (Needs exact match on param part).
				 * Keep iterating, as we can have early
				 * params and __setups of same names 8( */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = 1;
			} else if (!p->setup_func) {
				printk(KERN_WARNING "Parameter %s is obsolete,"
				       " ignored\n", p->str);
				return 1;
			} else if (p->setup_func(line + n))
				return 1;
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}

/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);

EXPORT_SYMBOL(loops_per_jiffy);

static int __init debug_kernel(char *str)
{
	console_loglevel = 10;
	return 0;
}

static int __init quiet_kernel(char *str)
{
	console_loglevel = 4;
	return 0;
}

early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);

static int __init loglevel(char *str)
{
	get_option(&str, &console_loglevel);
	return 0;
}

early_param("loglevel", loglevel);

/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
static int __init unknown_bootoption(char *param, char *val)
{
	/* Change NUL term back to "=", to make "param" the whole string. */
	if (val) {
		/* param=val or param="val"? */
		if (val == param+strlen(param)+1)
			val[-1] = '=';
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
			val--;
		} else
			BUG();
	}

	/* Handle obsolete-style parameters */
	if (obsolete_checksetup(param))
		return 0;

	/* Unused module parameter. */
	if (strchr(param, '.') && (!val || strchr(param, '.') < val))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "Too many boot env vars at `%s'";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], val - param))
				break;
		}
		envp_init[i] = param;
	} else {
		/* Command line option */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "Too many boot init vars at `%s'";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

#ifdef CONFIG_DEBUG_PAGEALLOC
int __read_mostly debug_pagealloc_enabled = 0;
#endif

static int __init init_setup(char *str)
{
	unsigned int i;

	execute_command = str;
	/*
	 * In case LILO is going to boot us with default command line,
	 * it prepends "auto" before the whole cmdline which makes
	 * the shell think it should execute a script with such name.
	 * So we ignore all arguments entered _before_ init=... [MJ]
	 */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
	unsigned int i;

	ramdisk_execute_command = str;
	/* See "auto" comment in init_setup */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("rdinit=", rdinit_setup);

#ifndef CONFIG_SMP

#ifdef CONFIG_X86_LOCAL_APIC
static void __init smp_init(void)
{
	APIC_init_uniprocessor();
}
#else
#define smp_init()	do { } while (0)
#endif

static inline void setup_nr_cpu_ids(void) { }
static inline void smp_prepare_cpus(unsigned int maxcpus) { }

#else

/* Setup number of possible processor ids */
int nr_cpu_ids __read_mostly = NR_CPUS;
EXPORT_SYMBOL(nr_cpu_ids);

/* An arch may set nr_cpu_ids earlier if needed, so this would be redundant */
static void __init setup_nr_cpu_ids(void)
{
	nr_cpu_ids = find_last_bit(cpumask_bits(cpu_possible_mask),NR_CPUS) + 1;
}

/* Called by boot processor to activate the rest. */
static void __init smp_init(void)
{
	unsigned int cpu;

	/* FIXME: This should be done in userspace --RR */
	for_each_present_cpu(cpu) {
		if (num_online_cpus() >= setup_max_cpus)
			break;
		if (!cpu_online(cpu))
			cpu_up(cpu);
	}

	/* Any cleanup work */
	printk(KERN_INFO "Brought up %ld CPUs\n", (long)num_online_cpus());
	smp_cpus_done(setup_max_cpus);
}

#endif

/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 */
static void __init setup_command_line(char *command_line)
{
	saved_command_line = alloc_bootmem(strlen (boot_command_line)+1);
	static_command_line = alloc_bootmem(strlen (command_line)+1);
	strcpy (saved_command_line, boot_command_line);
	strcpy (static_command_line, command_line);
}

/*
 * rest_init - 系统启动后的初始化函数
 *
 * 这个函数是系统启动后的初始化函数，在内核初始化的最后阶段调用。
 * 在释放内核锁后，它启动了两个内核线程：kernel_init 和 kthreadd。
 * 然后设置了默认的 NUMA 策略，并根据新线程的 PID 获取了对应的任务结构。
 * 最后初始化了引导空闲线程，并调用 schedule() 开始系统的调度。
 *
 * 注意事项：
 *   - 这个函数在释放内核锁后运行，并且声明为 noinline，确保不会被内联优化。
 *   - 在调用 schedule() 之前，需要禁用抢占，并在调用 cpu_idle() 之前再次启用。
 */
static noinline void __init_refok rest_init(void)
	__releases(kernel_lock)
{
	int pid;

	rcu_scheduler_starting();  // RCU调度器启动

	kernel_thread(kernel_init, NULL, CLONE_FS | CLONE_SIGHAND);  // 创建内核线程 kernel_init
	numa_default_policy();  // 设置默认的NUMA策略

	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);  // 创建内核线程 kthreadd
	rcu_read_lock();  // 获取RCU读锁

	// 根据线程的PID获取对应的任务结构
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);

	rcu_read_unlock();  // 释放RCU读锁
	unlock_kernel();  // 释放内核锁

	/*
	 * 引导空闲线程必须至少执行一次 schedule() 来启动系统：
	 */
	init_idle_bootup_task(current);

	preempt_enable_no_resched();  // 启用抢占，不重新调度
	schedule();  // 调度器启动

	preempt_disable();  // 禁用抢占

	/* 在禁用抢占的情况下调用 cpu_idle() */
	cpu_idle();  // 进入CPU空闲状态
}

/* Check for early params. */
static int __init do_early_param(char *param, char *val)
{
	struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if ((p->early && strcmp(param, p->str) == 0) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				printk(KERN_WARNING
				       "Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}

void __init parse_early_options(char *cmdline)
{
	parse_args("early options", cmdline, NULL, 0, do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void)
{
	static __initdata int done = 0;
	static __initdata char tmp_cmdline[COMMAND_LINE_SIZE];

	if (done)
		return;

	/* All fall through to do_early_param. */
	strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	done = 1;
}

/*
 *	Activate the first processor.
 */

static void __init boot_cpu_init(void)
{
	int cpu = smp_processor_id();
	/* Mark the boot cpu "present", "online" etc for SMP and UP case */
	set_cpu_online(cpu, true);
	set_cpu_active(cpu, true);
	set_cpu_present(cpu, true);
	set_cpu_possible(cpu, true);
}

void __init __weak smp_setup_processor_id(void)
{
}

void __init __weak thread_info_cache_init(void)
{
}

/*
 * Set up kernel memory allocators
 */
static void __init mm_init(void)
{
	/*
	 * page_cgroup requires countinous pages as memmap
	 * and it's bigger than MAX_ORDER unless SPARSEMEM.
	 */
	page_cgroup_init_flatmem();
	mem_init();
	kmem_cache_init();
	pgtable_cache_init();
	vmalloc_init();
}

asmlinkage void __init start_kernel(void)
{
	char * command_line;
	extern struct kernel_param __start___param[], __stop___param[];

	smp_setup_processor_id();

	/*
	 * Need to run as early as possible, to initialize the
	 * lockdep hash:
	 */
	lockdep_init();
	debug_objects_early_init();

	/*
	 * Set up the the initial canary ASAP:
	 */
	boot_init_stack_canary();

	cgroup_init_early();

	local_irq_disable();
	early_boot_irqs_off();
	early_init_irq_lock_class();

/*
 * Interrupts are still disabled. Do necessary setups, then
 * enable them
 */
	lock_kernel();
	tick_init();
	boot_cpu_init();
	page_address_init();//该函数初始化高端内存（High Memory）线性地址空间中永久映射相关的全局变量
	printk(KERN_NOTICE "%s", linux_banner);
	setup_arch(&command_line);
	mm_init_owner(&init_mm, &init_task);//初始化0号线程的mm_struct结构
	setup_command_line(command_line);
	setup_nr_cpu_ids();
	setup_per_cpu_areas();
	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */

	build_all_zonelists();
	page_alloc_init();

	printk(KERN_NOTICE "Kernel command line: %s\n", boot_command_line);
	parse_early_param();
	parse_args("Booting kernel", static_command_line, __start___param,
		   __stop___param - __start___param,
		   &unknown_bootoption);
	/*
	 * 它们使用较大的 bootmem 分配，并且必须先于 kmem_cache_init()
	 */
	pidhash_init();
	vfs_caches_init_early();//初始化vfs数据结构的缓存
	sort_main_extable();
	trap_init();		// 初始化异常处理
	mm_init();
	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 */
	sched_init();
	/*
	 * Disable preemption - early bootup scheduling is extremely
	 * fragile until we cpu_idle() for the first time.
	 */
	preempt_disable();
	if (!irqs_disabled()) {
		printk(KERN_WARNING "start_kernel(): bug: interrupts were "
				"enabled *very* early, fixing it\n");
		local_irq_disable();
	}
	rcu_init();
	radix_tree_init();
	/* init some links before init_ISA_irqs() */
	early_irq_init();
	init_IRQ();		// 初始化外部中断
	prio_tree_init();
	init_timers();		// 初始化定时器模块，同时，会注册定时器的软中断处理函数
	hrtimers_init();
	softirq_init();		// 初始化软中断
	timekeeping_init();
	time_init();
	profile_init();
	if (!irqs_disabled())
		printk(KERN_CRIT "start_kernel(): bug: interrupts were "
				 "enabled early\n");
	early_boot_irqs_on();
	local_irq_enable();

	/* Interrupts are enabled now so all GFP allocations are safe. */
	gfp_allowed_mask = __GFP_BITS_MASK;

	kmem_cache_init_late();

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();
	if (panic_later)
		panic(panic_later, panic_param);

	lockdep_info();

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	locking_selftest();

#ifdef CONFIG_BLK_DEV_INITRD
// 如果初始RAM盘（initrd_start）存在并且初始RAM盘不能低于某个起始地址（initrd_below_start_ok为假），
// 并且初始RAM盘的物理页框号小于最小的低地址页框号（min_low_pfn），则执行以下操作。
if (initrd_start && !initrd_below_start_ok &&
    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
    
    // 打印一个严重的内核消息，表示初始RAM盘被覆盖，并禁用它。
    printk(KERN_CRIT "initrd overwritten (0x%08lx < 0x%08lx) - "
        "disabling it.\n",
        page_to_pfn(virt_to_page((void *)initrd_start)),
        min_low_pfn);
    
    // 将initrd_start设置为0，表示禁用初始RAM盘。
    initrd_start = 0;
}
#endif
	page_cgroup_init();
	enable_debug_pagealloc();
	kmemtrace_init();
	kmemleak_init();
	debug_objects_mem_init();
	idr_init_cache();
	setup_per_cpu_pageset();
	numa_policy_init();
	if (late_time_init)
		late_time_init();
	sched_clock_init();
	calibrate_delay();
	pidmap_init();
	anon_vma_init();
#ifdef CONFIG_X86
	if (efi_enabled)
		efi_enter_virtual_mode();
#endif
	thread_info_cache_init();
	cred_init();
	fork_init(totalram_pages);
	proc_caches_init();
	buffer_init();
	key_init();
	security_init();
	vfs_caches_init(totalram_pages);//初始化vfs，构建 /
	signals_init();
	/* rootfs populating might need page-writeback */
	page_writeback_init();
#ifdef CONFIG_PROC_FS
	proc_root_init();
#endif
	cgroup_init();
	cpuset_init();
	taskstats_init_early();
	delayacct_init();

	check_bugs();

	acpi_early_init(); /* before LAPIC and SMP init */
	sfi_init_late();

	ftrace_init();

	/* Do the rest non-__init'ed, we're now alive */
	rest_init();//系统启动后的初始化函数
}

/* Call all constructor functions linked into the kernel. */
static void __init do_ctors(void)
{
#ifdef CONFIG_CONSTRUCTORS
	ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

	for (; fn < (ctor_fn_t *) __ctors_end; fn++)
		(*fn)();
#endif
}

int initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

static char msgbuf[64];
static struct boot_trace_call call;
static struct boot_trace_ret ret;

/**
 * @brief 执行一个初始化调用
 * @param fn 初始化调用函数指针
 * @return 初始化调用函数的返回结果
 */
int do_one_initcall(initcall_t fn)
{
    // 保存当前抢占计数
    int count = preempt_count();
    ktime_t calltime, delta, rettime;

    // 如果启用了初始化调用调试
    if (initcall_debug) {
        call.caller = task_pid_nr(current);
        printk("调用 %pF @ %i\n", fn, call.caller);
        calltime = ktime_get();  // 获取当前时间
        trace_boot_call(&call, fn);
        enable_boot_trace();
    }

    // 调用初始化函数并保存结果
    ret.result = fn();

    // 如果启用了初始化调用调试
    if (initcall_debug) {
        disable_boot_trace();
        rettime = ktime_get();  // 获取返回时间
        delta = ktime_sub(rettime, calltime);  // 计算调用持续时间
        ret.duration = (unsigned long long) ktime_to_ns(delta) >> 10;  // 转换为微秒
        trace_boot_ret(&ret, fn);
        printk("初始化调用 %pF 返回 %d，耗时 %Ld 微秒\n", fn, ret.result, ret.duration);
    }

    msgbuf[0] = 0;  // 清空消息缓冲区

    // 如果返回结果为错误码且启用了初始化调用调试
    if (ret.result && ret.result != -ENODEV && initcall_debug)
        sprintf(msgbuf, "错误码 %d ", ret.result);

    // 检查抢占计数是否匹配
    if (preempt_count() != count) {
        strlcat(msgbuf, "抢占不平衡 ", sizeof(msgbuf));
        preempt_count() = count;
    }
    // 检查中断是否被禁用
    if (irqs_disabled()) {
        strlcat(msgbuf, "中断已禁用 ", sizeof(msgbuf));
        local_irq_enable();
    }
    // 如果消息缓冲区有内容，打印消息
    if (msgbuf[0]) {
        printk("初始化调用 %pF 返回 %s\n", fn, msgbuf);
    }

    return ret.result;  // 返回初始化函数的结果
}

extern initcall_t __initcall_start[], __initcall_end[], __early_initcall_end[];

static void __init do_initcalls(void)
{
	initcall_t *fn;

	for (fn = __early_initcall_end; fn < __initcall_end; fn++)
		do_one_initcall(*fn);

	/* Make sure there is no pending stuff from the initcall sequence */
	flush_scheduled_work();
}

/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 */
static void __init do_basic_setup(void)
{
	init_workqueues();
	cpuset_init_smp();
	usermodehelper_init();
	init_tmpfs();
	driver_init();//初始化设备
	init_irq_proc();
	do_ctors();
	do_initcalls();//执行初始化的initcall
}

static void __init do_pre_smp_initcalls(void)
{
	initcall_t *fn;

	for (fn = __initcall_start; fn < __early_initcall_end; fn++)
		do_one_initcall(*fn);
}

static void run_init_process(char *init_filename)
{
	argv_init[0] = init_filename;
	kernel_execve(init_filename, argv_init, envp_init);
}

/* This is a non __init function. Force it to be noinline otherwise gcc
 * makes it inline to init() and it becomes part of init.text section
 */
static noinline int init_post(void)
	__releases(kernel_lock)
{
	/* need to finish all async __init code before freeing the memory */
	async_synchronize_full();
	free_initmem();
	unlock_kernel();
	mark_rodata_ro();
	system_state = SYSTEM_RUNNING;
	numa_default_policy();


	current->signal->flags |= SIGNAL_UNKILLABLE;

	if (ramdisk_execute_command) {
		run_init_process(ramdisk_execute_command);
		printk(KERN_WARNING "Failed to execute %s\n",
				ramdisk_execute_command);
	}

	/*
	 * We try each of these until one succeeds.
	 *
	 * The Bourne shell can be used instead of init if we are
	 * trying to recover a really broken machine.
	 */
	if (execute_command) {
		run_init_process(execute_command);
		printk(KERN_WARNING "Failed to execute %s.  Attempting "
					"defaults...\n", execute_command);
	}
	run_init_process("/sbin/init");
	run_init_process("/etc/init");
	run_init_process("/bin/init");
	run_init_process("/bin/sh");

	panic("No init found.  Try passing init= option to kernel. "
	      "See Linux Documentation/init.txt for guidance.");
}

/*
 * kernel_init - 内核初始化函数
 *
 * 这个函数是Linux内核的初始化入口，负责在系统引导时完成各种核心的初始化工作。
 * 它被设计为在内核锁的保护下执行，确保在启动过程中的关键步骤中不会被中断。
 *
 * 注意事项：
 *   - 在初始化过程中，通过设置内存和CPU允许的节点和CPU掩码来确保init进程能够在任何节点和CPU上运行。
 *   - 设置了当前进程为PID命名空间的child_reaper，用于处理孤儿进程。
 *   - 执行了多个SMP初始化函数来准备对称多处理系统。
 *   - 最后通过prepare_namespace()函数准备根文件系统，然后清理init内存段并启动用户模式进程。
 */
static int __init kernel_init(void * unused)
{
	lock_kernel();  // 加锁内核，防止在关键初始化阶段被中断

	/*
	 * init可以在任何节点上分配页面
	 */
	set_mems_allowed(node_states[N_HIGH_MEMORY]);

	/*
	 * init可以在任何CPU上运行
	 */
	set_cpus_allowed_ptr(current, cpu_all_mask);

	/*
	 * 告诉系统，我们将成为无辜孤儿进程的处理者。
	 *
	 * 我们不希望人们对这个任务数组中的位置有错误的假设。
	 */
	init_pid_ns.child_reaper = current;

	cad_pid = task_pid(current);  // 获取当前进程的PID

	smp_prepare_cpus(setup_max_cpus);  // 准备多处理器系统

	do_pre_smp_initcalls();  // 执行早期的SMP初始化调用

	start_boot_trace();  // 启动引导跟踪

	smp_init();  // 初始化SMP

	sched_init_smp();  // 初始化调度器的SMP部分

	do_basic_setup();  // 执行基本的系统设置

	/* 打开根文件系统上的/dev/console，这一步不应失败 */
	if (sys_open((const char __user *) "/dev/console", O_RDWR, 0) < 0)
		printk(KERN_WARNING "Warning: unable to open an initial console.\n");

	(void) sys_dup(0);  // 复制标准输入
	(void) sys_dup(0);  // 复制标准输入

	/*
	 * 检查是否存在早期用户空间初始化程序。如果存在，则让它完成所有工作。
	 */
	if (!ramdisk_execute_command)
		ramdisk_execute_command = "/init";

	if (sys_access((const char __user *) ramdisk_execute_command, 0) != 0) {//检查文件的存在性，与当前进程是否具有权限
		ramdisk_execute_command = NULL;
		prepare_namespace();  // 准备根文件系统命名空间
	}

	/*
	 * 初始化完成，系统基本运行起来了。清理初始化内存段并启动用户模式进程。
	 */
	init_post();

	return 0;
}
