/*
 * Generic waiting primitives.
 *
 * (C) 2004 William Irwin, Oracle
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/wait.h>
#include <linux/hash.h>

void __init_waitqueue_head(wait_queue_head_t *q, struct lock_class_key *key)
{
	spin_lock_init(&q->lock);
	lockdep_set_class(&q->lock, key);
	INIT_LIST_HEAD(&q->task_list);
}

EXPORT_SYMBOL(__init_waitqueue_head);

// 向等待队列中添加元素
void add_wait_queue(wait_queue_head_t *q, wait_queue_t *wait)
{
	unsigned long flags;

	wait->flags &= ~WQ_FLAG_EXCLUSIVE;
	spin_lock_irqsave(&q->lock, flags);
	__add_wait_queue(q, wait);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(add_wait_queue);

void add_wait_queue_exclusive(wait_queue_head_t *q, wait_queue_t *wait)
{
	unsigned long flags;

	wait->flags |= WQ_FLAG_EXCLUSIVE;
	spin_lock_irqsave(&q->lock, flags);
	__add_wait_queue_tail(q, wait);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(add_wait_queue_exclusive);

void remove_wait_queue(wait_queue_head_t *q, wait_queue_t *wait)
{
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	__remove_wait_queue(q, wait);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(remove_wait_queue);


/*
 * Note: we use "set_current_state()" _after_ the wait-queue add,
 * because we need a memory barrier there on SMP, so that any
 * wake-function that tests for the wait-queue being active
 * will be guaranteed to see waitqueue addition _or_ subsequent
 * tests in this thread will see the wakeup having taken place.
 *
 * The spin_unlock() itself is semi-permeable and only protects
 * one way (it only protects stuff inside the critical region and
 * stops them from bleeding out - it would still allow subsequent
 * loads to move into the critical region).
 */
// 修改进程状态，可以修改为TASK_INTERRUPTIBLE或TASK_UNINTERRUPTIBLE
void
prepare_to_wait(wait_queue_head_t *q, wait_queue_t *wait, int state)
{
	unsigned long flags;

	wait->flags &= ~WQ_FLAG_EXCLUSIVE;
	spin_lock_irqsave(&q->lock, flags);
	if (list_empty(&wait->task_list))
		__add_wait_queue(q, wait);
	set_current_state(state);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(prepare_to_wait);

void
prepare_to_wait_exclusive(wait_queue_head_t *q, wait_queue_t *wait, int state)
{
	unsigned long flags;

	wait->flags |= WQ_FLAG_EXCLUSIVE;
	spin_lock_irqsave(&q->lock, flags);
	if (list_empty(&wait->task_list))
		__add_wait_queue_tail(q, wait);
	set_current_state(state);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(prepare_to_wait_exclusive);

/*
 * finish_wait - clean up after waiting in a queue
 * @q: waitqueue waited on
 * @wait: wait descriptor
 *
 * Sets current thread back to running state and removes
 * the wait descriptor from the given waitqueue if still
 * queued.
 */
void finish_wait(wait_queue_head_t *q, wait_queue_t *wait)
{
	unsigned long flags;

	__set_current_state(TASK_RUNNING);
	/*
	 * We can check for list emptiness outside the lock
	 * IFF:
	 *  - we use the "careful" check that verifies both
	 *    the next and prev pointers, so that there cannot
	 *    be any half-pending updates in progress on other
	 *    CPU's that we haven't seen yet (and that might
	 *    still change the stack area.
	 * and
	 *  - all other users take the lock (ie we can only
	 *    have _one_ other CPU that looks at or modifies
	 *    the list).
	 */
	if (!list_empty_careful(&wait->task_list)) {
		spin_lock_irqsave(&q->lock, flags);
		list_del_init(&wait->task_list);
		spin_unlock_irqrestore(&q->lock, flags);
	}
}
EXPORT_SYMBOL(finish_wait);

/*
 * abort_exclusive_wait - abort exclusive waiting in a queue
 * @q: waitqueue waited on
 * @wait: wait descriptor
 * @state: runstate of the waiter to be woken
 * @key: key to identify a wait bit queue or %NULL
 *
 * Sets current thread back to running state and removes
 * the wait descriptor from the given waitqueue if still
 * queued.
 *
 * Wakes up the next waiter if the caller is concurrently
 * woken up through the queue.
 *
 * This prevents waiter starvation where an exclusive waiter
 * aborts and is woken up concurrently and noone wakes up
 * the next waiter.
 */
void abort_exclusive_wait(wait_queue_head_t *q, wait_queue_t *wait,
			unsigned int mode, void *key)
{
	unsigned long flags;

	__set_current_state(TASK_RUNNING);
	spin_lock_irqsave(&q->lock, flags);
	if (!list_empty(&wait->task_list))
		list_del_init(&wait->task_list);
	else if (waitqueue_active(q))
		__wake_up_locked_key(q, mode, key);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL(abort_exclusive_wait);

// 等待队列的autoremove_wake_function函数，使用DEFINE_WAIT定义等待队列，默认使用这个函数，DEFINE_WAIT在wait.h中
int autoremove_wake_function(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	int ret = default_wake_function(wait, mode, sync, key);		// 在sched中定义的唤醒函数

	if (ret)
		list_del_init(&wait->task_list);
	return ret;
}
EXPORT_SYMBOL(autoremove_wake_function);

int wake_bit_function(wait_queue_t *wait, unsigned mode, int sync, void *arg)
{
	struct wait_bit_key *key = arg;
	struct wait_bit_queue *wait_bit
		= container_of(wait, struct wait_bit_queue, wait);

	if (wait_bit->key.flags != key->flags ||
			wait_bit->key.bit_nr != key->bit_nr ||
			test_bit(key->bit_nr, key->flags))
		return 0;
	else
		return autoremove_wake_function(wait, mode, sync, key);
}
EXPORT_SYMBOL(wake_bit_function);

/*
 * To allow interruptible waiting and asynchronous (i.e. nonblocking)
 * waiting, the actions of __wait_on_bit() and __wait_on_bit_lock() are
 * permitted return codes. Nonzero return codes halt waiting and return.
 */
int __sched
__wait_on_bit(wait_queue_head_t *wq, struct wait_bit_queue *q,
			int (*action)(void *), unsigned mode)
{
	int ret = 0;

	do {
		prepare_to_wait(wq, &q->wait, mode);
		if (test_bit(q->key.bit_nr, q->key.flags))
			ret = (*action)(q->key.flags);
	} while (test_bit(q->key.bit_nr, q->key.flags) && !ret);
	finish_wait(wq, &q->wait);
	return ret;
}
EXPORT_SYMBOL(__wait_on_bit);

int __sched out_of_line_wait_on_bit(void *word, int bit,
					int (*action)(void *), unsigned mode)
{
	wait_queue_head_t *wq = bit_waitqueue(word, bit);
	DEFINE_WAIT_BIT(wait, word, bit);

	return __wait_on_bit(wq, &wait, action, mode);
}
EXPORT_SYMBOL(out_of_line_wait_on_bit);

int __sched
__wait_on_bit_lock(wait_queue_head_t *wq, struct wait_bit_queue *q,
			int (*action)(void *), unsigned mode)
{
	do {
		int ret;

		prepare_to_wait_exclusive(wq, &q->wait, mode);
		if (!test_bit(q->key.bit_nr, q->key.flags))
			continue;
		ret = action(q->key.flags);
		if (!ret)
			continue;
		abort_exclusive_wait(wq, &q->wait, mode, &q->key);
		return ret;
	} while (test_and_set_bit(q->key.bit_nr, q->key.flags));
	finish_wait(wq, &q->wait);
	return 0;
}
EXPORT_SYMBOL(__wait_on_bit_lock);

int __sched out_of_line_wait_on_bit_lock(void *word, int bit,
					int (*action)(void *), unsigned mode)
{
	wait_queue_head_t *wq = bit_waitqueue(word, bit);
	DEFINE_WAIT_BIT(wait, word, bit);

	return __wait_on_bit_lock(wq, &wait, action, mode);
}
EXPORT_SYMBOL(out_of_line_wait_on_bit_lock);

void __wake_up_bit(wait_queue_head_t *wq, void *word, int bit)
{
	struct wait_bit_key key = __WAIT_BIT_KEY_INITIALIZER(word, bit);
	if (waitqueue_active(wq))
		__wake_up(wq, TASK_NORMAL, 1, &key);
}
EXPORT_SYMBOL(__wake_up_bit);

/**
 * wake_up_bit - wake up a waiter on a bit
 * @word: the word being waited on, a kernel virtual address
 * @bit: the bit of the word being waited on
 *
 * There is a standard hashed waitqueue table for generic use. This
 * is the part of the hashtable's accessor API that wakes up waiters
 * on a bit. For instance, if one were to have waiters on a bitflag,
 * one would call wake_up_bit() after clearing the bit.
 *
 * In order for this to function properly, as it uses waitqueue_active()
 * internally, some kind of memory barrier must be done prior to calling
 * this. Typically, this will be smp_mb__after_clear_bit(), but in some
 * cases where bitflags are manipulated non-atomically under a lock, one
 * may need to use a less regular barrier, such fs/inode.c's smp_mb(),
 * because spin_unlock() does not guarantee a memory barrier.
 */
/**
 * wake_up_bit - 唤醒位上等待的进程
 * @word: 正在等待的word,一个内核虚拟地址
 * @bit: word上正在等待的位
 *
 * 这里有一个标准的散列等待队列表用于普遍用途。这是哈希表访问器API的一部分,唤醒位上等待的进程。
 * 例如,如果有进程等待一个位标志,在清除该位后就可以调用wake_up_bit()。
 *
 * 为了使这个函数正常工作,它在内部使用waitqueue_active(),因此在调用之前必须进行某种内存屏障。
 * 通常这将是smp_mb__after_clear_bit(),但在某些情况下,当位标志在锁保护下非原子性地操作时,
 * 可能需要使用更不规则的屏障,如fs/inode.c中的smp_mb(),因为spin_unlock()不能保证内存屏障。
 */
void wake_up_bit(void *word, int bit)
{
	__wake_up_bit(bit_waitqueue(word, bit), word, bit);
}
EXPORT_SYMBOL(wake_up_bit);

wait_queue_head_t *bit_waitqueue(void *word, int bit)
{
	// 确定一个指向等待队列表的指针
	// 根据系统位宽(32位或64位),决定偏移量
	const int shift = BITS_PER_LONG == 32 ? 5 : 6;
	// 获取word所在页面的zone
	const struct zone *zone = page_zone(virt_to_page(word));
	// 将word和bit组合成一个值,作为哈希表的索引
	unsigned long val = (unsigned long)word << shift | bit;

	// 返回等待队列表的地址
	return &zone->wait_table[hash_long(val, zone->wait_table_bits)];
}
EXPORT_SYMBOL(bit_waitqueue);
