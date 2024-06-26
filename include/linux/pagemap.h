#ifndef _LINUX_PAGEMAP_H
#define _LINUX_PAGEMAP_H

/*
 * Copyright 1995 Linus Torvalds
 */
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/highmem.h>
#include <linux/compiler.h>
#include <asm/uaccess.h>
#include <linux/gfp.h>
#include <linux/bitops.h>
#include <linux/hardirq.h> /* for in_interrupt() */

/*
 * Bits in mapping->flags.  The lower __GFP_BITS_SHIFT bits are the page
 * allocation mode flags.
 */
enum mapping_flags {
	AS_EIO		= __GFP_BITS_SHIFT + 0,	/* IO error on async write */
	AS_ENOSPC	= __GFP_BITS_SHIFT + 1,	/* ENOSPC on async write */
	AS_MM_ALL_LOCKS	= __GFP_BITS_SHIFT + 2,	/* under mm_take_all_locks() */
	AS_UNEVICTABLE	= __GFP_BITS_SHIFT + 3,	/* e.g., ramdisk, SHM_LOCK */
};

static inline void mapping_set_error(struct address_space *mapping, int error)
{
	if (unlikely(error)) {
		if (error == -ENOSPC)
			set_bit(AS_ENOSPC, &mapping->flags);
		else
			set_bit(AS_EIO, &mapping->flags);
	}
}

static inline void mapping_set_unevictable(struct address_space *mapping)
{
	set_bit(AS_UNEVICTABLE, &mapping->flags);
}

static inline void mapping_clear_unevictable(struct address_space *mapping)
{
	clear_bit(AS_UNEVICTABLE, &mapping->flags);
}

static inline int mapping_unevictable(struct address_space *mapping)
{
	if (likely(mapping))
		return test_bit(AS_UNEVICTABLE, &mapping->flags);
	return !!mapping;
}

static inline gfp_t mapping_gfp_mask(struct address_space * mapping)
{
	return (__force gfp_t)mapping->flags & __GFP_BITS_MASK;
}

/*
 * This is non-atomic.  Only to be used before the mapping is activated.
 * Probably needs a barrier...
 */
static inline void mapping_set_gfp_mask(struct address_space *m, gfp_t mask)
{
	m->flags = (m->flags & ~(__force unsigned long)__GFP_BITS_MASK) |
				(__force unsigned long)mask;
}

/*
 * The page cache can done in larger chunks than
 * one page, because it allows for more efficient
 * throughput (it can then be mapped into user
 * space in smaller chunks for same flexibility).
 *
 * Or rather, it _will_ be done in larger chunks.
 */
#define PAGE_CACHE_SHIFT	PAGE_SHIFT
#define PAGE_CACHE_SIZE		PAGE_SIZE
#define PAGE_CACHE_MASK		PAGE_MASK
#define PAGE_CACHE_ALIGN(addr)	(((addr)+PAGE_CACHE_SIZE-1)&PAGE_CACHE_MASK)

#define page_cache_get(page)		get_page(page)
#define page_cache_release(page)	put_page(page)
void release_pages(struct page **pages, int nr, int cold);

/*
 * speculatively take a reference to a page.
 * If the page is free (_count == 0), then _count is untouched, and 0
 * is returned. Otherwise, _count is incremented by 1 and 1 is returned.
 *
 * This function must be called inside the same rcu_read_lock() section as has
 * been used to lookup the page in the pagecache radix-tree (or page table):
 * this allows allocators to use a synchronize_rcu() to stabilize _count.
 *
 * Unless an RCU grace period has passed, the count of all pages coming out
 * of the allocator must be considered unstable. page_count may return higher
 * than expected, and put_page must be able to do the right thing when the
 * page has been finished with, no matter what it is subsequently allocated
 * for (because put_page is what is used here to drop an invalid speculative
 * reference).
 *
 * This is the interesting part of the lockless pagecache (and lockless
 * get_user_pages) locking protocol, where the lookup-side (eg. find_get_page)
 * has the following pattern:
 * 1. find page in radix tree
 * 2. conditionally increment refcount
 * 3. check the page is still in pagecache (if no, goto 1)
 *
 * Remove-side that cares about stability of _count (eg. reclaim) has the
 * following (with tree_lock held for write):
 * A. atomically check refcount is correct and set it to 0 (atomic_cmpxchg)
 * B. remove page from pagecache
 * C. free the page
 *
 * There are 2 critical interleavings that matter:
 * - 2 runs before A: in this case, A sees elevated refcount and bails out
 * - A runs before 2: in this case, 2 sees zero refcount and retries;
 *   subsequently, B will complete and 1 will find no page, causing the
 *   lookup to return NULL.
 *
 * It is possible that between 1 and 2, the page is removed then the exact same
 * page is inserted into the same position in pagecache. That's OK: the
 * old find_get_page using tree_lock could equally have run before or after
 * such a re-insertion, depending on order that locks are granted.
 *
 * Lookups racing against pagecache insertion isn't a big problem: either 1
 * will find the page or it will not. Likewise, the old find_get_page could run
 * either before the insertion or afterwards, depending on timing.
 */
static inline int page_cache_get_speculative(struct page *page)
{
	VM_BUG_ON(in_interrupt());

#if !defined(CONFIG_SMP) && defined(CONFIG_TREE_RCU)
# ifdef CONFIG_PREEMPT
	VM_BUG_ON(!in_atomic());
# endif
	/*
	 * Preempt must be disabled here - we rely on rcu_read_lock doing
	 * this for us.
	 *
	 * Pagecache won't be truncated from interrupt context, so if we have
	 * found a page in the radix tree here, we have pinned its refcount by
	 * disabling preempt, and hence no need for the "speculative get" that
	 * SMP requires.
	 */
	VM_BUG_ON(page_count(page) == 0);
	atomic_inc(&page->_count);

#else
	if (unlikely(!get_page_unless_zero(page))) {
		/*
		 * Either the page has been freed, or will be freed.
		 * In either case, retry here and the caller should
		 * do the right thing (see comments above).
		 */
		return 0;
	}
#endif
	VM_BUG_ON(PageTail(page));

	return 1;
}

/*
 * Same as above, but add instead of inc (could just be merged)
 */
static inline int page_cache_add_speculative(struct page *page, int count)
{
	VM_BUG_ON(in_interrupt());

#if !defined(CONFIG_SMP) && defined(CONFIG_TREE_RCU)
# ifdef CONFIG_PREEMPT
	VM_BUG_ON(!in_atomic());
# endif
	VM_BUG_ON(page_count(page) == 0);
	atomic_add(count, &page->_count);

#else
	if (unlikely(!atomic_add_unless(&page->_count, count, 0)))
		return 0;
#endif
	VM_BUG_ON(PageCompound(page) && page != compound_head(page));

	return 1;
}

static inline int page_freeze_refs(struct page *page, int count)
{
	return likely(atomic_cmpxchg(&page->_count, count, 0) == count);
}

static inline void page_unfreeze_refs(struct page *page, int count)
{
	VM_BUG_ON(page_count(page) != 0);
	VM_BUG_ON(count == 0);

	atomic_set(&page->_count, count);
}

#ifdef CONFIG_NUMA
extern struct page *__page_cache_alloc(gfp_t gfp);
#else
// 如果不是NUMA系统，定义一个内联函数__page_cache_alloc来分配页面。
static inline struct page *__page_cache_alloc(gfp_t gfp)
{
	// 调用alloc_pages函数，请求分配一个零阶（0-order，即单个页面）的页面。
	return alloc_pages(gfp, 0);
}
#endif

// 分配一个页并。
static inline struct page *page_cache_alloc(struct address_space *x)
{
	// 通过__page_cache_alloc函数分配页面，其GFP掩码由mapping_gfp_mask(x)提供。
	return __page_cache_alloc(mapping_gfp_mask(x));
}

// 此函数用来分配一个新页面，然后调用add_to_page_cache_lru将其加入到页面调整缓存。
static inline struct page *page_cache_alloc_cold(struct address_space *x)
{
	// 调用__page_cache_alloc函数分配一个新页面，参数是地址空间x的GFP掩码与GFP_COLD标志的组合
	// mapping_gfp_mask(x) 获取地址空间的分配掩码，这通常是基于文件系统类型和其他因素的GFP标志
	// __GFP_COLD 表示请求分配“冷”页面，即倾向于不在CPU缓存中的页面
	return __page_cache_alloc(mapping_gfp_mask(x)|__GFP_COLD);
}

typedef int filler_t(void *, struct page *);

/**
 * find_get_page - 查找并获取一个页面引用
 * @mapping: 要搜索的地址空间
 * @offset: 页面索引
 *
 * 在给定的 (mapping, offset) 元组中是否存在一个页面缓存的 struct page？
 * 如果存在，增加其引用计数并返回它；如果不存在，返回 NULL。
 */
// mapping是指定地址空间，offset是文件中的指定位置，以页面为单位
extern struct page * find_get_page(struct address_space *mapping,
				pgoff_t index);
// find_lock_page 函数，和 find_get_page 类似，但返回的页面会被锁定。
extern struct page * find_lock_page(struct address_space *mapping,
				pgoff_t index);
// find_or_create_page 函数，寻找或创建一个页面。如果页面不存在，则根据 gfp_mask 参数的规定分配新的页面。
extern struct page * find_or_create_page(struct address_space *mapping,
				pgoff_t index, gfp_t gfp_mask);
// find_get_pages 函数，获取一系列连续页面，返回找到的页面数。
unsigned find_get_pages(struct address_space *mapping, pgoff_t start,
			unsigned int nr_pages, struct page **pages);
// find_get_pages_contig 函数，功能与 find_get_pages 类似，但它保证返回的页面在物理内存中也是连续的。
unsigned find_get_pages_contig(struct address_space *mapping, pgoff_t start,
			       unsigned int nr_pages, struct page **pages);
// find_get_pages_tag 函数，根据特定的标记来查找页面，返回找到的页面数。
unsigned find_get_pages_tag(struct address_space *mapping, pgoff_t *index,
			int tag, unsigned int nr_pages, struct page **pages);

// grab_cache_page_write_begin 函数，获取并锁定用于写入的缓存页面。
struct page *grab_cache_page_write_begin(struct address_space *mapping,
			pgoff_t index, unsigned flags);

/*
 * Returns locked page at given index in given cache, creating it if needed.
 */
/*
 * Returns locked page at given index in given cache, creating it if needed.
 * 返回指定缓存中给定索引的锁定页面，如有必要会创建它。
 */
// grab_cache_page 函数，尝试获取并锁定一个页面，如果页面不存在则创建它。
static inline struct page *grab_cache_page(struct address_space *mapping,
								pgoff_t index)
{
	// 使用地址空间的 GFP 掩码调用 find_or_create_page，尝试获取或创建页面。
	return find_or_create_page(mapping, index, mapping_gfp_mask(mapping));
}

extern struct page * grab_cache_page_nowait(struct address_space *mapping,
				pgoff_t index);
extern struct page * read_cache_page_async(struct address_space *mapping,
				pgoff_t index, filler_t *filler,
				void *data);
extern struct page * read_cache_page(struct address_space *mapping,
				pgoff_t index, filler_t *filler,
				void *data);
extern struct page * read_cache_page_gfp(struct address_space *mapping,
				pgoff_t index, gfp_t gfp_mask);
extern int read_cache_pages(struct address_space *mapping,
		struct list_head *pages, filler_t *filler, void *data);

static inline struct page *read_mapping_page_async(
						struct address_space *mapping,
						     pgoff_t index, void *data)
{
	filler_t *filler = (filler_t *)mapping->a_ops->readpage;
	return read_cache_page_async(mapping, index, filler, data);
}

static inline struct page *read_mapping_page(struct address_space *mapping,
					     pgoff_t index, void *data)
{
	filler_t *filler = (filler_t *)mapping->a_ops->readpage;
	return read_cache_page(mapping, index, filler, data);
}

/*
 * Return byte-offset into filesystem object for page.
 */
static inline loff_t page_offset(struct page *page)
{
	return ((loff_t)page->index) << PAGE_CACHE_SHIFT;
}

static inline pgoff_t linear_page_index(struct vm_area_struct *vma,
					unsigned long address)
{
	pgoff_t pgoff = (address - vma->vm_start) >> PAGE_SHIFT;
	pgoff += vma->vm_pgoff;
	return pgoff >> (PAGE_CACHE_SHIFT - PAGE_SHIFT);
}

extern void __lock_page(struct page *page);
extern int __lock_page_killable(struct page *page);
extern void __lock_page_nosync(struct page *page);
extern void unlock_page(struct page *page);

static inline void __set_page_locked(struct page *page)
{
	__set_bit(PG_locked, &page->flags);
}

static inline void __clear_page_locked(struct page *page)
{
	__clear_bit(PG_locked, &page->flags);
}

static inline int trylock_page(struct page *page)
{
	return (likely(!test_and_set_bit_lock(PG_locked, &page->flags)));
}

/*
 * lock_page may only be called if we have the page's inode pinned.
 */
static inline void lock_page(struct page *page)
{
	might_sleep();
	if (!trylock_page(page))
		__lock_page(page);
}

/*
 * lock_page_killable is like lock_page but can be interrupted by fatal
 * signals.  It returns 0 if it locked the page and -EINTR if it was
 * killed while waiting.
 */
static inline int lock_page_killable(struct page *page)
{
	might_sleep();
	if (!trylock_page(page))
		return __lock_page_killable(page);
	return 0;
}

/*
 * lock_page_nosync should only be used if we can't pin the page's inode.
 * Doesn't play quite so well with block device plugging.
 */
static inline void lock_page_nosync(struct page *page)
{
	might_sleep();
	if (!trylock_page(page))
		__lock_page_nosync(page);
}
	
/*
 * This is exported only for wait_on_page_locked/wait_on_page_writeback.
 * Never use this directly!
 */
/*
 * 此函数仅导出用于 wait_on_page_locked/wait_on_page_writeback。
 * 切勿直接使用此函数！
 */
extern void wait_on_page_bit(struct page *page, int bit_nr);

/* 
 * Wait for a page to be unlocked.
 *
 * This must be called with the caller "holding" the page,
 * ie with increased "page->count" so that the page won't
 * go away during the wait..
 */
/*
 * 等待一个页面解锁。
 *
 * 调用此函数时，调用者必须“持有”该页面，
 * 即增加了“page->count”，以便在等待期间页面不会消失。
 */
static inline void wait_on_page_locked(struct page *page)
{
	// 如果页面当前被锁定
	if (PageLocked(page))
		// 等待指定的页面位变为未设置状态
		wait_on_page_bit(page, PG_locked);
}

/* 
 * Wait for a page to complete writeback
 */
/* 
 * 等待页面完成回写
 */
static inline void wait_on_page_writeback(struct page *page)
{
	// 如果页面处于回写状态
	if (PageWriteback(page))
		// 等待页面的回写位变为未设置状态
		wait_on_page_bit(page, PG_writeback);
}

// 通知系统页面回写已完成
extern void end_page_writeback(struct page *page);

/*
 * Add an arbitrary waiter to a page's wait queue
 */
/*
 * 向页面的等待队列添加一个任意的等待者
 */
extern void add_page_wait_queue(struct page *page, wait_queue_t *waiter);

/*
 * Fault a userspace page into pagetables.  Return non-zero on a fault.
 *
 * This assumes that two userspace pages are always sufficient.  That's
 * not true if PAGE_CACHE_SIZE > PAGE_SIZE.
 */
/*
 * 将用户空间的页面故障进页表。如果发生故障，返回非零值。
 *
 * 这假设两个用户空间页面总是足够的。如果 PAGE_CACHE_SIZE > PAGE_SIZE，
 * 这个假设就不成立。
 */
static inline int fault_in_pages_writeable(char __user *uaddr, int size)
{
	int ret;

	// 如果大小为零，直接返回0，无需处理。
	if (unlikely(size == 0))
		return 0;

	/*
	 * Writing zeroes into userspace here is OK, because we know that if
	 * the zero gets there, we'll be overwriting it.
	 */
	/*
	 * 这里写入用户空间的零是可以的，因为我们知道如果零写入成功，
	 * 我们会覆盖它。
	 */
	// 尝试写一个零到用户地址，检查是否可写。
	ret = __put_user(0, uaddr);
	if (ret == 0) {
		char __user *end = uaddr + size - 1;

		/*
		 * If the page was already mapped, this will get a cache miss
		 * for sure, so try to avoid doing it.
		 */
		/*
		 * 如果页面已经映射，这将确保得到一个缓存未命中，
		 * 所以尽量避免这样做。
		 */
		// 检查是否跨页，如果跨页，则对结束地址进行写入尝试。
		if (((unsigned long)uaddr & PAGE_MASK) !=
				((unsigned long)end & PAGE_MASK))
		 	ret = __put_user(0, end);
	}
	return ret;
}

static inline int fault_in_pages_readable(const char __user *uaddr, int size)
{
	volatile char c;
	int ret;

	// 如果大小为零，直接返回0，无需处理。
	if (unlikely(size == 0))
		return 0;

	// 尝试从用户地址读取一个字节，检查是否可读。
	ret = __get_user(c, uaddr);
	if (ret == 0) {
		const char __user *end = uaddr + size - 1;

		// 检查是否跨页，如果跨页，则对结束地址进行读取尝试。
		if (((unsigned long)uaddr & PAGE_MASK) !=
				((unsigned long)end & PAGE_MASK))
		 	ret = __get_user(c, end);
	}
	return ret;
}

// 定义函数 add_to_page_cache_locked，其将页面添加到页面缓存中，并锁定该页面。
int add_to_page_cache_locked(struct page *page, struct address_space *mapping,
				pgoff_t index, gfp_t gfp_mask);
// 通过page_cache_alloc_cold函数分配一个新页面，然后调用add_to_page_cache_lru将其加入到页面调整缓存。
int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
				pgoff_t index, gfp_t gfp_mask);
// 声明函数 remove_from_page_cache，其从页面缓存中移除指定页面。
extern void remove_from_page_cache(struct page *page);
// 声明函数 __remove_from_page_cache，其直接从页面缓存中移除指定页面。
extern void __remove_from_page_cache(struct page *page);

/*
 * Like add_to_page_cache_locked, but used to add newly allocated pages:
 * the page is new, so we can just run __set_page_locked() against it.
 */
/*
 * 类似于 add_to_page_cache_locked，但用于添加新分配的页面：
 * 页面是新的，因此我们可以直接对其执行 __set_page_locked() 操作。
 */
// 定义内联函数 add_to_page_cache，用于将新分配的页面添加到页面缓存中。
static inline int add_to_page_cache(struct page *page,
		struct address_space *mapping, pgoff_t offset, gfp_t gfp_mask)
{
	int error;

	// 锁定页面，防止其他操作影响此页面。
	__set_page_locked(page);
	// 尝试将页面添加到页面缓存，并锁定它。
	error = add_to_page_cache_locked(page, mapping, offset, gfp_mask);
	// 检查添加页面是否出现错误。
	if (unlikely(error))
		// 如果添加失败，则解锁页面。
		__clear_page_locked(page);
	return error;	// 返回操作结果，如果成功则为0，否则为错误代码。
}

#endif /* _LINUX_PAGEMAP_H */
