/*
 * linux/kernel/workqueue.c
 *
 * Generic mechanism for defining kernel helper threads for running
 * arbitrary tasks in process context.
 *
 * Started by Ingo Molnar, Copyright (C) 2002
 *
 * Derived from the taskqueue/keventd code by:
 *
 *   David Woodhouse <dwmw2@infradead.org>
 *   Andrew Morton
 *   Kai Petzke <wpp@marie.physik.tu-berlin.de>
 *   Theodore Ts'o <tytso@mit.edu>
 *
 * Made to use alloc_percpu by Christoph Lameter.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/signal.h>
#include <linux/completion.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/kthread.h>
#include <linux/hardirq.h>
#include <linux/mempolicy.h>
#include <linux/freezer.h>
#include <linux/kallsyms.h>
#include <linux/debug_locks.h>
#include <linux/lockdep.h>
#define CREATE_TRACE_POINTS
#include <trace/events/workqueue.h>

// 工作者线程执行worker_thread函数，在worker_thread中死循环

// 每一个工作者线程由一个cpu_workqueue_struct结构体表示。而workqueue_struct结构体则表示给定类型的所有工作者线程。

/*
 * The per-CPU workqueue (if single thread, we always use the first
 * possible cpu).
 */
// 每一个工作者线程都有一个这样的结构体。假如只有一种工作者线程的话那么该结构有16个，因为cpu有16个，每一种工作线程在每个cpu上都需要有实例
struct cpu_workqueue_struct {

	spinlock_t lock;		// 锁，保护这种结构

	struct list_head worklist;		// 工作列表
	wait_queue_head_t more_work;
	struct work_struct *current_work;		// 指向当前工作

	struct workqueue_struct *wq;		// 关联工作队列结构（即所属的工作者线程的类型）
	struct task_struct *thread;			// 关联线程
} ____cacheline_aligned;

/*
 * The externally visible workqueue abstraction is an array of
 * per-CPU workqueues:
 */

// 每种工作者线程有一个这样的结构体。
// 一种工作者线程有一个这样的结构体，然后在这个结构体内部有一个cpu_workqueue_struct组成的数组，数组的每一个元素代表该种工作者线程在每一个cpu上的实例

// 每个工作者线程类型关联一个自己的workqueue_struct。该结构体里面，给每个线程分配一个cpu_workqueue_struct，
// 因而也就是给每个处理器分配一个，因为每个处理器都有一个该类型的工作者线程

// 外部可见的工作队列抽象是由每个CPU的工作队列组成的数组
struct workqueue_struct {
	// 由cpu_workqueue_struct结构组成的数组，数组每一项对应系统中一个处理器，
	// 系统每一个CPU对应一个工作者线程，所以对于给定计算机来说，就是每个处理器，
	// 每个工作者线程对应一个这样的cpu_workqueue_struct结构体。
	struct cpu_workqueue_struct *cpu_wq;		// 一个数组，总数为cpu数，代表者该种工作者线程在每一个cpu上的实体
	struct list_head list;
	const char *name;
	int singlethread;
	int freezeable;		/* Freeze threads during suspend */
	int rt;
#ifdef CONFIG_LOCKDEP
	struct lockdep_map lockdep_map;
#endif
};

#ifdef CONFIG_DEBUG_OBJECTS_WORK

static struct debug_obj_descr work_debug_descr;

/*
 * fixup_init is called when:
 * - an active object is initialized
 */
static int work_fixup_init(void *addr, enum debug_obj_state state)
{
	struct work_struct *work = addr;

	switch (state) {
	case ODEBUG_STATE_ACTIVE:
		cancel_work_sync(work);
		debug_object_init(work, &work_debug_descr);
		return 1;
	default:
		return 0;
	}
}

/*
 * fixup_activate is called when:
 * - an active object is activated
 * - an unknown object is activated (might be a statically initialized object)
 */
static int work_fixup_activate(void *addr, enum debug_obj_state state)
{
	struct work_struct *work = addr;

	switch (state) {

	case ODEBUG_STATE_NOTAVAILABLE:
		/*
		 * This is not really a fixup. The work struct was
		 * statically initialized. We just make sure that it
		 * is tracked in the object tracker.
		 */
		if (test_bit(WORK_STRUCT_STATIC, work_data_bits(work))) {
			debug_object_init(work, &work_debug_descr);
			debug_object_activate(work, &work_debug_descr);
			return 0;
		}
		WARN_ON_ONCE(1);
		return 0;

	case ODEBUG_STATE_ACTIVE:
		WARN_ON(1);

	default:
		return 0;
	}
}

/*
 * fixup_free is called when:
 * - an active object is freed
 */
static int work_fixup_free(void *addr, enum debug_obj_state state)
{
	struct work_struct *work = addr;

	switch (state) {
	case ODEBUG_STATE_ACTIVE:
		cancel_work_sync(work);
		debug_object_free(work, &work_debug_descr);
		return 1;
	default:
		return 0;
	}
}

static struct debug_obj_descr work_debug_descr = {
	.name		= "work_struct",
	.fixup_init	= work_fixup_init,
	.fixup_activate	= work_fixup_activate,
	.fixup_free	= work_fixup_free,
};

static inline void debug_work_activate(struct work_struct *work)
{
	debug_object_activate(work, &work_debug_descr);
}

static inline void debug_work_deactivate(struct work_struct *work)
{
	debug_object_deactivate(work, &work_debug_descr);
}

void __init_work(struct work_struct *work, int onstack)
{
	if (onstack)
		debug_object_init_on_stack(work, &work_debug_descr);
	else
		debug_object_init(work, &work_debug_descr);
}
EXPORT_SYMBOL_GPL(__init_work);

void destroy_work_on_stack(struct work_struct *work)
{
	debug_object_free(work, &work_debug_descr);
}
EXPORT_SYMBOL_GPL(destroy_work_on_stack);

#else
static inline void debug_work_activate(struct work_struct *work) { }
static inline void debug_work_deactivate(struct work_struct *work) { }
#endif

/* Serializes the accesses to the list of workqueues. */
static DEFINE_SPINLOCK(workqueue_lock);
static LIST_HEAD(workqueues);

static int singlethread_cpu __read_mostly;
static const struct cpumask *cpu_singlethread_map __read_mostly;
/*
 * _cpu_down() first removes CPU from cpu_online_map, then CPU_DEAD
 * flushes cwq->worklist. This means that flush_workqueue/wait_on_work
 * which comes in between can't use for_each_online_cpu(). We could
 * use cpu_possible_map, the cpumask below is more a documentation
 * than optimization.
 */
static cpumask_var_t cpu_populated_map __read_mostly;

/* If it's single threaded, it isn't in the list of workqueues. */
static inline int is_wq_single_threaded(struct workqueue_struct *wq)
{
	return wq->singlethread;
}

static const struct cpumask *wq_cpu_map(struct workqueue_struct *wq)
{
	return is_wq_single_threaded(wq)
		? cpu_singlethread_map : cpu_populated_map;
}

static
struct cpu_workqueue_struct *wq_per_cpu(struct workqueue_struct *wq, int cpu)
{
	if (unlikely(is_wq_single_threaded(wq)))
		cpu = singlethread_cpu;
	return per_cpu_ptr(wq->cpu_wq, cpu);
}

/*
 * Set the workqueue on which a work item is to be run
 * - Must *only* be called if the pending flag is set
 */
static inline void set_wq_data(struct work_struct *work,
				struct cpu_workqueue_struct *cwq)
{
	unsigned long new;

	BUG_ON(!work_pending(work));

	new = (unsigned long) cwq | (1UL << WORK_STRUCT_PENDING);
	new |= WORK_STRUCT_FLAG_MASK & *work_data_bits(work);
	atomic_long_set(&work->data, new);
}

static inline
struct cpu_workqueue_struct *get_wq_data(struct work_struct *work)
{
	return (void *) (atomic_long_read(&work->data) & WORK_STRUCT_WQ_DATA_MASK);
}

static void insert_work(struct cpu_workqueue_struct *cwq,
			struct work_struct *work, struct list_head *head)
{
	trace_workqueue_insertion(cwq->thread, work);

	set_wq_data(work, cwq);
	/*
	 * Ensure that we get the right work->data if we see the
	 * result of list_add() below, see try_to_grab_pending().
	 */
	smp_wmb();
	list_add_tail(&work->entry, head);
	wake_up(&cwq->more_work);
}

static void __queue_work(struct cpu_workqueue_struct *cwq,
			 struct work_struct *work)
{
	unsigned long flags;

	debug_work_activate(work);
	spin_lock_irqsave(&cwq->lock, flags);
	insert_work(cwq, work, &cwq->worklist);
	spin_unlock_irqrestore(&cwq->lock, flags);
}

/**
 * queue_work - queue work on a workqueue
 * @wq: workqueue to use
 * @work: work to queue
 *
 * Returns 0 if @work was already on a queue, non-zero otherwise.
 *
 * We queue the work to the CPU on which it was submitted, but if the CPU dies
 * it can be processed by another CPU.
 */
// 对指定工作线程进行调度，和schedule_work函数作用雷同，不过变成了指定工作线程(wq)
int queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	int ret;

	ret = queue_work_on(get_cpu(), wq, work);
	put_cpu();

	return ret;
}
EXPORT_SYMBOL_GPL(queue_work);

/**
 * queue_work_on - queue work on specific cpu
 * @cpu: CPU number to execute work on
 * @wq: workqueue to use
 * @work: work to queue
 *
 * Returns 0 if @work was already on a queue, non-zero otherwise.
 *
 * We queue the work to a specific CPU, the caller must ensure it
 * can't go away.
 */
int
queue_work_on(int cpu, struct workqueue_struct *wq, struct work_struct *work)
{
	int ret = 0;

	if (!test_and_set_bit(WORK_STRUCT_PENDING, work_data_bits(work))) {
		BUG_ON(!list_empty(&work->entry));
		__queue_work(wq_per_cpu(wq, cpu), work);
		ret = 1;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(queue_work_on);

static void delayed_work_timer_fn(unsigned long __data)
{
	struct delayed_work *dwork = (struct delayed_work *)__data;
	struct cpu_workqueue_struct *cwq = get_wq_data(&dwork->work);
	struct workqueue_struct *wq = cwq->wq;

	__queue_work(wq_per_cpu(wq, smp_processor_id()), &dwork->work);
}

/**
 * queue_delayed_work - queue work on a workqueue after delay
 * @wq: workqueue to use
 * @dwork: delayable work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * Returns 0 if @work was already on a queue, non-zero otherwise.
 */
// 对指定工作线程进行延时调度
int queue_delayed_work(struct workqueue_struct *wq,
			struct delayed_work *dwork, unsigned long delay)
{
	if (delay == 0)
		return queue_work(wq, &dwork->work);

	return queue_delayed_work_on(-1, wq, dwork, delay);
}
EXPORT_SYMBOL_GPL(queue_delayed_work);

/**
 * queue_delayed_work_on - queue work on specific CPU after delay
 * @cpu: CPU number to execute work on
 * @wq: workqueue to use
 * @dwork: work to queue
 * @delay: number of jiffies to wait before queueing
 *
 * Returns 0 if @work was already on a queue, non-zero otherwise.
 */
int queue_delayed_work_on(int cpu, struct workqueue_struct *wq,
			struct delayed_work *dwork, unsigned long delay)
{
	int ret = 0;
	struct timer_list *timer = &dwork->timer;
	struct work_struct *work = &dwork->work;

	if (!test_and_set_bit(WORK_STRUCT_PENDING, work_data_bits(work))) {
		BUG_ON(timer_pending(timer));
		BUG_ON(!list_empty(&work->entry));

		timer_stats_timer_set_start_info(&dwork->timer);

		/* This stores cwq for the moment, for the timer_fn */
		set_wq_data(work, wq_per_cpu(wq, raw_smp_processor_id()));
		timer->expires = jiffies + delay;
		timer->data = (unsigned long)dwork;
		timer->function = delayed_work_timer_fn;

		if (unlikely(cpu >= 0))
			add_timer_on(timer, cpu);
		else
			add_timer(timer);
		ret = 1;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(queue_delayed_work_on);

static void run_workqueue(struct cpu_workqueue_struct *cwq)
{
	spin_lock_irq(&cwq->lock);
	// 当链表不为空，选取下一个节点对象。
	while (!list_empty(&cwq->worklist)) {
		struct work_struct *work = list_entry(cwq->worklist.next,
						struct work_struct, entry);
		work_func_t f = work->func;
#ifdef CONFIG_LOCKDEP
		/*
		 * It is permissible to free the struct work_struct
		 * from inside the function that is called from it,
		 * this we need to take into account for lockdep too.
		 * To avoid bogus "held lock freed" warnings as well
		 * as problems when looking into work->lockdep_map,
		 * make a copy and use that here.
		 */
		struct lockdep_map lockdep_map = work->lockdep_map;
#endif
		trace_workqueue_execution(cwq->thread, work);
		debug_work_deactivate(work);
		cwq->current_work = work;
		// 把该节点从链表上解下来
		list_del_init(cwq->worklist.next);
		spin_unlock_irq(&cwq->lock);

		BUG_ON(get_wq_data(work) != cwq);
		// 将待处理标志位pending清零
		work_clear_pending(work);
		lock_map_acquire(&cwq->wq->lockdep_map);
		lock_map_acquire(&lockdep_map);
		// 调用函数
		f(work);
		lock_map_release(&lockdep_map);
		lock_map_release(&cwq->wq->lockdep_map);

		if (unlikely(in_atomic() || lockdep_depth(current) > 0)) {
			printk(KERN_ERR "BUG: workqueue leaked lock or atomic: "
					"%s/0x%08x/%d\n",
					current->comm, preempt_count(),
				       	task_pid_nr(current));
			printk(KERN_ERR "    last function: ");
			print_symbol("%s\n", (unsigned long)f);
			debug_show_held_locks(current);
			dump_stack();
		}

		spin_lock_irq(&cwq->lock);
		cwq->current_work = NULL;
	}
	spin_unlock_irq(&cwq->lock);
}

// 工作者线程执行的函数
static int worker_thread(void *__cwq)
{
	struct cpu_workqueue_struct *cwq = __cwq;
	DEFINE_WAIT(wait);		// 定义一个等待队列，名字是wait，func是autoremove_wake_function

	if (cwq->wq->freezeable)
		set_freezable();

	// 死循环，当有操作被插入到队列时，线程被唤醒。当没有操作时，它又会睡眠
	for (;;) {
		// 线程将自己设置为休眠状态（TASK_INTERRUPTIBLE）
		prepare_to_wait(&cwq->more_work, &wait, TASK_INTERRUPTIBLE);
		if (!freezing(current) &&
		    !kthread_should_stop() &&
		    list_empty(&cwq->worklist))
				//如果工作链表是空，线程调用schedule进入休眠 
			schedule();
		// 如果链表中由对象，线程不会睡眠。相反，它将自己状态设置为TASK_RUNNING，脱离等待队列
		finish_wait(&cwq->more_work, &wait);

		try_to_freeze();

		if (kthread_should_stop())
			break;

		// 如果链表非空，调用run_workqueue()函数执行被推后的工作
		run_workqueue(cwq);
	}

	return 0;
}

struct wq_barrier {
	struct work_struct	work;
	struct completion	done;
};

static void wq_barrier_func(struct work_struct *work)
{
	struct wq_barrier *barr = container_of(work, struct wq_barrier, work);
	complete(&barr->done);
}

static void insert_wq_barrier(struct cpu_workqueue_struct *cwq,
			struct wq_barrier *barr, struct list_head *head)
{
	/*
	 * debugobject calls are safe here even with cwq->lock locked
	 * as we know for sure that this will not trigger any of the
	 * checks and call back into the fixup functions where we
	 * might deadlock.
	 */
	INIT_WORK_ON_STACK(&barr->work, wq_barrier_func);
	__set_bit(WORK_STRUCT_PENDING, work_data_bits(&barr->work));

	init_completion(&barr->done);

	debug_work_activate(&barr->work);
	insert_work(cwq, &barr->work, head);
}

static int flush_cpu_workqueue(struct cpu_workqueue_struct *cwq)
{
	int active = 0;
	struct wq_barrier barr;

	WARN_ON(cwq->thread == current);

	spin_lock_irq(&cwq->lock);
	if (!list_empty(&cwq->worklist) || cwq->current_work != NULL) {
		insert_wq_barrier(cwq, &barr, &cwq->worklist);
		active = 1;
	}
	spin_unlock_irq(&cwq->lock);

	if (active) {
		wait_for_completion(&barr.done);
		destroy_work_on_stack(&barr.work);
	}

	return active;
}

/**
 * flush_workqueue - ensure that any scheduled work has run to completion.
 * @wq: workqueue to flush
 *
 * Forces execution of the workqueue and blocks until its completion.
 * This is typically used in driver shutdown handlers.
 *
 * We sleep until all works which were queued on entry have been handled,
 * but we are not livelocked by new incoming ones.
 *
 * This function used to run the workqueues itself.  Now we just wait for the
 * helper threads to do it.
 */
// 刷新指定的工作队列，函数会一直等待，直到队列中所有对象都被执行以后才返回，只能在进程上下文使用，因为在等待所有待处理工作执行的时候，该函数会进入休眠状态。
void flush_workqueue(struct workqueue_struct *wq)
{
	const struct cpumask *cpu_map = wq_cpu_map(wq);
	int cpu;

	might_sleep();
	lock_map_acquire(&wq->lockdep_map);
	lock_map_release(&wq->lockdep_map);
	for_each_cpu(cpu, cpu_map)
		flush_cpu_workqueue(per_cpu_ptr(wq->cpu_wq, cpu));
}
EXPORT_SYMBOL_GPL(flush_workqueue);

/**
 * flush_work - block until a work_struct's callback has terminated
 * @work: the work which is to be flushed
 *
 * Returns false if @work has already terminated.
 *
 * It is expected that, prior to calling flush_work(), the caller has
 * arranged for the work to not be requeued, otherwise it doesn't make
 * sense to use this function.
 */
int flush_work(struct work_struct *work)
{
	struct cpu_workqueue_struct *cwq;
	struct list_head *prev;
	struct wq_barrier barr;

	might_sleep();
	cwq = get_wq_data(work);
	if (!cwq)
		return 0;

	lock_map_acquire(&cwq->wq->lockdep_map);
	lock_map_release(&cwq->wq->lockdep_map);

	prev = NULL;
	spin_lock_irq(&cwq->lock);
	if (!list_empty(&work->entry)) {
		/*
		 * See the comment near try_to_grab_pending()->smp_rmb().
		 * If it was re-queued under us we are not going to wait.
		 */
		smp_rmb();
		if (unlikely(cwq != get_wq_data(work)))
			goto out;
		prev = &work->entry;
	} else {
		if (cwq->current_work != work)
			goto out;
		prev = &cwq->worklist;
	}
	insert_wq_barrier(cwq, &barr, prev->next);
out:
	spin_unlock_irq(&cwq->lock);
	if (!prev)
		return 0;

	wait_for_completion(&barr.done);
	destroy_work_on_stack(&barr.work);
	return 1;
}
EXPORT_SYMBOL_GPL(flush_work);

/*
 * Upon a successful return (>= 0), the caller "owns" WORK_STRUCT_PENDING bit,
 * so this work can't be re-armed in any way.
 */
static int try_to_grab_pending(struct work_struct *work)
{
	struct cpu_workqueue_struct *cwq;
	int ret = -1;

	if (!test_and_set_bit(WORK_STRUCT_PENDING, work_data_bits(work)))
		return 0;

	/*
	 * The queueing is in progress, or it is already queued. Try to
	 * steal it from ->worklist without clearing WORK_STRUCT_PENDING.
	 */

	cwq = get_wq_data(work);
	if (!cwq)
		return ret;

	spin_lock_irq(&cwq->lock);
	if (!list_empty(&work->entry)) {
		/*
		 * This work is queued, but perhaps we locked the wrong cwq.
		 * In that case we must see the new value after rmb(), see
		 * insert_work()->wmb().
		 */
		smp_rmb();
		if (cwq == get_wq_data(work)) {
			debug_work_deactivate(work);
			list_del_init(&work->entry);
			ret = 1;
		}
	}
	spin_unlock_irq(&cwq->lock);

	return ret;
}

static void wait_on_cpu_work(struct cpu_workqueue_struct *cwq,
				struct work_struct *work)
{
	struct wq_barrier barr;
	int running = 0;

	spin_lock_irq(&cwq->lock);
	if (unlikely(cwq->current_work == work)) {
		insert_wq_barrier(cwq, &barr, cwq->worklist.next);
		running = 1;
	}
	spin_unlock_irq(&cwq->lock);

	if (unlikely(running)) {
		wait_for_completion(&barr.done);
		destroy_work_on_stack(&barr.work);
	}
}

static void wait_on_work(struct work_struct *work)
{
	struct cpu_workqueue_struct *cwq;
	struct workqueue_struct *wq;
	const struct cpumask *cpu_map;
	int cpu;

	might_sleep();

	lock_map_acquire(&work->lockdep_map);
	lock_map_release(&work->lockdep_map);

	cwq = get_wq_data(work);
	if (!cwq)
		return;

	wq = cwq->wq;
	cpu_map = wq_cpu_map(wq);

	for_each_cpu(cpu, cpu_map)
		wait_on_cpu_work(per_cpu_ptr(wq->cpu_wq, cpu), work);
}

static int __cancel_work_timer(struct work_struct *work,
				struct timer_list* timer)
{
	int ret;

	do {
		ret = (timer && likely(del_timer(timer)));
		if (!ret)
			ret = try_to_grab_pending(work);
		wait_on_work(work);
	} while (unlikely(ret < 0));

	work_clear_pending(work);
	return ret;
}

/**
 * cancel_work_sync - block until a work_struct's callback has terminated
 * @work: the work which is to be flushed
 *
 * Returns true if @work was pending.
 *
 * cancel_work_sync() will cancel the work if it is queued. If the work's
 * callback appears to be running, cancel_work_sync() will block until it
 * has completed.
 *
 * It is possible to use this function if the work re-queues itself. It can
 * cancel the work even if it migrates to another workqueue, however in that
 * case it only guarantees that work->func() has completed on the last queued
 * workqueue.
 *
 * cancel_work_sync(&delayed_work->work) should be used only if ->timer is not
 * pending, otherwise it goes into a busy-wait loop until the timer expires.
 *
 * The caller must ensure that workqueue_struct on which this work was last
 * queued can't be destroyed before this function returns.
 */
int cancel_work_sync(struct work_struct *work)
{
	return __cancel_work_timer(work, NULL);
}
EXPORT_SYMBOL_GPL(cancel_work_sync);

/**
 * cancel_delayed_work_sync - reliably kill off a delayed work.
 * @dwork: the delayed work struct
 *
 * Returns true if @dwork was pending.
 *
 * It is possible to use this function if @dwork rearms itself via queue_work()
 * or queue_delayed_work(). See also the comment for cancel_work_sync().
 */
int cancel_delayed_work_sync(struct delayed_work *dwork)
{
	return __cancel_work_timer(&dwork->work, &dwork->timer);
}
EXPORT_SYMBOL(cancel_delayed_work_sync);

static struct workqueue_struct *keventd_wq __read_mostly;

/**
 * schedule_work - put work task in global workqueue
 * @work: job to be done
 *
 * Returns zero if @work was already on the kernel-global workqueue and
 * non-zero otherwise.
 *
 * This puts a job in the kernel-global workqueue if it was not already
 * queued and leaves it in the same position on the kernel-global
 * workqueue otherwise.
 */
// 对工作线程进行调度(调度events线程)，工作线程直接会执行
int schedule_work(struct work_struct *work)
{
	return queue_work(keventd_wq, work);
}
EXPORT_SYMBOL(schedule_work);

/*
 * schedule_work_on - put work task on a specific cpu
 * @cpu: cpu to put the work task on
 * @work: job to be done
 *
 * This puts a job on a specific cpu
 */
int schedule_work_on(int cpu, struct work_struct *work)
{
	return queue_work_on(cpu, keventd_wq, work);
}
EXPORT_SYMBOL(schedule_work_on);

/**
 * schedule_delayed_work - put work task in global workqueue after delay
 * @dwork: job to be done
 * @delay: number of jiffies to wait or 0 for immediate execution
 *
 * After waiting for a given time this puts a job in the kernel-global
 * workqueue.
 */
// 对工作线程进行调度（调度events线程），延迟delay后工作线程才开始执行
int schedule_delayed_work(struct delayed_work *dwork,
					unsigned long delay)
{
	return queue_delayed_work(keventd_wq, dwork, delay);
}
EXPORT_SYMBOL(schedule_delayed_work);

/**
 * flush_delayed_work - block until a dwork_struct's callback has terminated
 * @dwork: the delayed work which is to be flushed
 *
 * Any timeout is cancelled, and any pending work is run immediately.
 */
void flush_delayed_work(struct delayed_work *dwork)
{
	if (del_timer_sync(&dwork->timer)) {
		struct cpu_workqueue_struct *cwq;
		cwq = wq_per_cpu(get_wq_data(&dwork->work)->wq, get_cpu());
		__queue_work(cwq, &dwork->work);
		put_cpu();
	}
	flush_work(&dwork->work);
}
EXPORT_SYMBOL(flush_delayed_work);

/**
 * schedule_delayed_work_on - queue work in global workqueue on CPU after delay
 * @cpu: cpu to use
 * @dwork: job to be done
 * @delay: number of jiffies to wait
 *
 * After waiting for a given time this puts a job in the kernel-global
 * workqueue on the specified CPU.
 */
int schedule_delayed_work_on(int cpu,
			struct delayed_work *dwork, unsigned long delay)
{
	return queue_delayed_work_on(cpu, keventd_wq, dwork, delay);
}
EXPORT_SYMBOL(schedule_delayed_work_on);

/**
 * schedule_on_each_cpu - call a function on each online CPU from keventd
 * @func: the function to call
 *
 * Returns zero on success.
 * Returns -ve errno on failure.
 *
 * schedule_on_each_cpu() is very slow.
 */
int schedule_on_each_cpu(work_func_t func)
{
	int cpu;
	int orig = -1;
	struct work_struct *works;

	works = alloc_percpu(struct work_struct);
	if (!works)
		return -ENOMEM;

	get_online_cpus();

	/*
	 * When running in keventd don't schedule a work item on
	 * itself.  Can just call directly because the work queue is
	 * already bound.  This also is faster.
	 */
	if (current_is_keventd())
		orig = raw_smp_processor_id();

	for_each_online_cpu(cpu) {
		struct work_struct *work = per_cpu_ptr(works, cpu);

		INIT_WORK(work, func);
		if (cpu != orig)
			schedule_work_on(cpu, work);
	}
	if (orig >= 0)
		func(per_cpu_ptr(works, orig));

	for_each_online_cpu(cpu)
		flush_work(per_cpu_ptr(works, cpu));

	put_online_cpus();
	free_percpu(works);
	return 0;
}

// 刷新events工作队列，函数会一直等待，直到队列中所有对象都被执行以后才返回，只能在进程上下文使用，因为在等待所有待处理工作执行的时候，该函数会进入休眠状态。
// 该函数并不取消任何延迟执行的工作，就是说任何通过schedule_delayed_work调度的工作，如果其延迟时间未结束，并不会因为调用flush_scheduled_work()而被刷新掉
void flush_scheduled_work(void)
{
	flush_workqueue(keventd_wq);
}
EXPORT_SYMBOL(flush_scheduled_work);

/**
 * execute_in_process_context - reliably execute the routine with user context
 * @fn:		the function to execute
 * @ew:		guaranteed storage for the execute work structure (must
 *		be available when the work executes)
 *
 * Executes the function immediately if process context is available,
 * otherwise schedules the function for delayed execution.
 *
 * Returns:	0 - function was executed
 *		1 - function was scheduled for execution
 */
int execute_in_process_context(work_func_t fn, struct execute_work *ew)
{
	if (!in_interrupt()) {
		fn(&ew->work);
		return 0;
	}

	INIT_WORK(&ew->work, fn);
	schedule_work(&ew->work);

	return 1;
}
EXPORT_SYMBOL_GPL(execute_in_process_context);

int keventd_up(void)
{
	return keventd_wq != NULL;
}

int current_is_keventd(void)
{
	struct cpu_workqueue_struct *cwq;
	int cpu = raw_smp_processor_id(); /* preempt-safe: keventd is per-cpu */
	int ret = 0;

	BUG_ON(!keventd_wq);

	cwq = per_cpu_ptr(keventd_wq->cpu_wq, cpu);
	if (current == cwq->thread)
		ret = 1;

	return ret;

}

static struct cpu_workqueue_struct *
init_cpu_workqueue(struct workqueue_struct *wq, int cpu)
{
	struct cpu_workqueue_struct *cwq = per_cpu_ptr(wq->cpu_wq, cpu);

	cwq->wq = wq;
	spin_lock_init(&cwq->lock);
	INIT_LIST_HEAD(&cwq->worklist);
	init_waitqueue_head(&cwq->more_work);

	return cwq;
}

static int create_workqueue_thread(struct cpu_workqueue_struct *cwq, int cpu)
{
	struct sched_param param = { .sched_priority = MAX_RT_PRIO-1 };
	struct workqueue_struct *wq = cwq->wq;
	const char *fmt = is_wq_single_threaded(wq) ? "%s" : "%s/%d";
	struct task_struct *p;

	p = kthread_create(worker_thread, cwq, fmt, wq->name, cpu);
	/*
	 * Nobody can add the work_struct to this cwq,
	 *	if (caller is __create_workqueue)
	 *		nobody should see this wq
	 *	else // caller is CPU_UP_PREPARE
	 *		cpu is not on cpu_online_map
	 * so we can abort safely.
	 */
	if (IS_ERR(p))
		return PTR_ERR(p);
	if (cwq->wq->rt)
		sched_setscheduler_nocheck(p, SCHED_FIFO, &param);
	cwq->thread = p;

	trace_workqueue_creation(cwq->thread, cpu);

	return 0;
}

static void start_workqueue_thread(struct cpu_workqueue_struct *cwq, int cpu)
{
	struct task_struct *p = cwq->thread;

	if (p != NULL) {
		if (cpu >= 0)
			kthread_bind(p, cpu);
		wake_up_process(p);
	}
}

struct workqueue_struct *__create_workqueue_key(const char *name,
						int singlethread,
						int freezeable,
						int rt,
						struct lock_class_key *key,
						const char *lock_name)
{
	struct workqueue_struct *wq;
	struct cpu_workqueue_struct *cwq;
	int err = 0, cpu;

	wq = kzalloc(sizeof(*wq), GFP_KERNEL);
	if (!wq)
		return NULL;

	wq->cpu_wq = alloc_percpu(struct cpu_workqueue_struct);
	if (!wq->cpu_wq) {
		kfree(wq);
		return NULL;
	}

	wq->name = name;
	lockdep_init_map(&wq->lockdep_map, lock_name, key, 0);
	wq->singlethread = singlethread;
	wq->freezeable = freezeable;
	wq->rt = rt;
	INIT_LIST_HEAD(&wq->list);

	if (singlethread) {
		cwq = init_cpu_workqueue(wq, singlethread_cpu);
		err = create_workqueue_thread(cwq, singlethread_cpu);
		start_workqueue_thread(cwq, -1);
	} else {
		cpu_maps_update_begin();
		/*
		 * We must place this wq on list even if the code below fails.
		 * cpu_down(cpu) can remove cpu from cpu_populated_map before
		 * destroy_workqueue() takes the lock, in that case we leak
		 * cwq[cpu]->thread.
		 */
		spin_lock(&workqueue_lock);
		list_add(&wq->list, &workqueues);
		spin_unlock(&workqueue_lock);
		/*
		 * We must initialize cwqs for each possible cpu even if we
		 * are going to call destroy_workqueue() finally. Otherwise
		 * cpu_up() can hit the uninitialized cwq once we drop the
		 * lock.
		 */
		for_each_possible_cpu(cpu) {
			cwq = init_cpu_workqueue(wq, cpu);
			if (err || !cpu_online(cpu))
				continue;
			err = create_workqueue_thread(cwq, cpu);
			start_workqueue_thread(cwq, cpu);
		}
		cpu_maps_update_done();
	}

	if (err) {
		destroy_workqueue(wq);
		wq = NULL;
	}
	return wq;
}
EXPORT_SYMBOL_GPL(__create_workqueue_key);

static void cleanup_workqueue_thread(struct cpu_workqueue_struct *cwq)
{
	/*
	 * Our caller is either destroy_workqueue() or CPU_POST_DEAD,
	 * cpu_add_remove_lock protects cwq->thread.
	 */
	if (cwq->thread == NULL)
		return;

	lock_map_acquire(&cwq->wq->lockdep_map);
	lock_map_release(&cwq->wq->lockdep_map);

	flush_cpu_workqueue(cwq);
	/*
	 * If the caller is CPU_POST_DEAD and cwq->worklist was not empty,
	 * a concurrent flush_workqueue() can insert a barrier after us.
	 * However, in that case run_workqueue() won't return and check
	 * kthread_should_stop() until it flushes all work_struct's.
	 * When ->worklist becomes empty it is safe to exit because no
	 * more work_structs can be queued on this cwq: flush_workqueue
	 * checks list_empty(), and a "normal" queue_work() can't use
	 * a dead CPU.
	 */
	trace_workqueue_destruction(cwq->thread);
	kthread_stop(cwq->thread);
	cwq->thread = NULL;
}

/**
 * destroy_workqueue - safely terminate a workqueue
 * @wq: target workqueue
 *
 * Safely destroy a workqueue. All work currently pending will be done first.
 */
void destroy_workqueue(struct workqueue_struct *wq)
{
	const struct cpumask *cpu_map = wq_cpu_map(wq);
	int cpu;

	cpu_maps_update_begin();
	spin_lock(&workqueue_lock);
	list_del(&wq->list);
	spin_unlock(&workqueue_lock);

	for_each_cpu(cpu, cpu_map)
		cleanup_workqueue_thread(per_cpu_ptr(wq->cpu_wq, cpu));
 	cpu_maps_update_done();

	free_percpu(wq->cpu_wq);
	kfree(wq);
}
EXPORT_SYMBOL_GPL(destroy_workqueue);

static int __devinit workqueue_cpu_callback(struct notifier_block *nfb,
						unsigned long action,
						void *hcpu)
{
	unsigned int cpu = (unsigned long)hcpu;
	struct cpu_workqueue_struct *cwq;
	struct workqueue_struct *wq;
	int ret = NOTIFY_OK;

	action &= ~CPU_TASKS_FROZEN;

	switch (action) {
	case CPU_UP_PREPARE:
		cpumask_set_cpu(cpu, cpu_populated_map);
	}
undo:
	list_for_each_entry(wq, &workqueues, list) {
		cwq = per_cpu_ptr(wq->cpu_wq, cpu);

		switch (action) {
		case CPU_UP_PREPARE:
			if (!create_workqueue_thread(cwq, cpu))
				break;
			printk(KERN_ERR "workqueue [%s] for %i failed\n",
				wq->name, cpu);
			action = CPU_UP_CANCELED;
			ret = NOTIFY_BAD;
			goto undo;

		case CPU_ONLINE:
			start_workqueue_thread(cwq, cpu);
			break;

		case CPU_UP_CANCELED:
			start_workqueue_thread(cwq, -1);
		case CPU_POST_DEAD:
			cleanup_workqueue_thread(cwq);
			break;
		}
	}

	switch (action) {
	case CPU_UP_CANCELED:
	case CPU_POST_DEAD:
		cpumask_clear_cpu(cpu, cpu_populated_map);
	}

	return ret;
}

#ifdef CONFIG_SMP

struct work_for_cpu {
	struct completion completion;
	long (*fn)(void *);
	void *arg;
	long ret;
};

static int do_work_for_cpu(void *_wfc)
{
	struct work_for_cpu *wfc = _wfc;
	wfc->ret = wfc->fn(wfc->arg);
	complete(&wfc->completion);
	return 0;
}

/**
 * work_on_cpu - run a function in user context on a particular cpu
 * @cpu: the cpu to run on
 * @fn: the function to run
 * @arg: the function arg
 *
 * This will return the value @fn returns.
 * It is up to the caller to ensure that the cpu doesn't go offline.
 * The caller must not hold any locks which would prevent @fn from completing.
 */
long work_on_cpu(unsigned int cpu, long (*fn)(void *), void *arg)
{
	struct task_struct *sub_thread;
	struct work_for_cpu wfc = {
		.completion = COMPLETION_INITIALIZER_ONSTACK(wfc.completion),
		.fn = fn,
		.arg = arg,
	};

	sub_thread = kthread_create(do_work_for_cpu, &wfc, "work_for_cpu");
	if (IS_ERR(sub_thread))
		return PTR_ERR(sub_thread);
	kthread_bind(sub_thread, cpu);
	wake_up_process(sub_thread);
	wait_for_completion(&wfc.completion);
	return wfc.ret;
}
EXPORT_SYMBOL_GPL(work_on_cpu);
#endif /* CONFIG_SMP */

void __init init_workqueues(void)
{
	alloc_cpumask_var(&cpu_populated_map, GFP_KERNEL);

	cpumask_copy(cpu_populated_map, cpu_online_mask);
	singlethread_cpu = cpumask_first(cpu_possible_mask);
	cpu_singlethread_map = cpumask_of(singlethread_cpu);
	hotcpu_notifier(workqueue_cpu_callback, 0);
	keventd_wq = create_workqueue("events");
	BUG_ON(!keventd_wq);
}
