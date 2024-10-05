/*
 * linux/mm/slab.c
 * Written by Mark Hemment, 1996/97.
 * (markhe@nextd.demon.co.uk)
 *
 * kmem_cache_destroy() + some cleanup - 1999 Andrea Arcangeli
 *
 * Major cleanup, different bufctl logic, per-cpu arrays
 *	(c) 2000 Manfred Spraul
 *
 * Cleanup, make the head arrays unconditional, preparation for NUMA
 * 	(c) 2002 Manfred Spraul
 *
 * An implementation of the Slab Allocator as described in outline in;
 *	UNIX Internals: The New Frontiers by Uresh Vahalia
 *	Pub: Prentice Hall	ISBN 0-13-101908-2
 * or with a little more detail in;
 *	The Slab Allocator: An Object-Caching Kernel Memory Allocator
 *	Jeff Bonwick (Sun Microsystems).
 *	Presented at: USENIX Summer 1994 Technical Conference
 *
 * The memory is organized in caches, one cache for each object type.
 * (e.g. inode_cache, dentry_cache, buffer_head, vm_area_struct)
 * Each cache consists out of many slabs (they are small (usually one
 * page long) and always contiguous), and each slab contains multiple
 * initialized objects.
 *
 * This means, that your constructor is used only for newly allocated
 * slabs and you must pass objects with the same initializations to
 * kmem_cache_free.
 *
 * Each cache can only support one memory type (GFP_DMA, GFP_HIGHMEM,
 * normal). If you need a special memory type, then must create a new
 * cache for that memory type.
 *
 * In order to reduce fragmentation, the slabs are sorted in 3 groups:
 *   full slabs with 0 free objects
 *   partial slabs
 *   empty slabs with no allocated objects
 *
 * If partial slabs exist, then new allocations come from these slabs,
 * otherwise from empty slabs or new slabs are allocated.
 *
 * kmem_cache_destroy() CAN CRASH if you try to allocate from the cache
 * during kmem_cache_destroy(). The caller must prevent concurrent allocs.
 *
 * Each cache has a short per-cpu head array, most allocs
 * and frees go into that array, and if that array overflows, then 1/2
 * of the entries in the array are given back into the global cache.
 * The head array is strictly LIFO and should improve the cache hit rates.
 * On SMP, it additionally reduces the spinlock operations.
 *
 * The c_cpuarray may not be read with enabled local interrupts -
 * it's changed with a smp_call_function().
 *
 * SMP synchronization:
 *  constructors and destructors are called without any locking.
 *  Several members in struct kmem_cache and struct slab never change, they
 *	are accessed without any locking.
 *  The per-cpu arrays are never accessed from the wrong cpu, no locking,
 *  	and local interrupts are disabled so slab code is preempt-safe.
 *  The non-constant members are protected with a per-cache irq spinlock.
 *
 * Many thanks to Mark Hemment, who wrote another per-cpu slab patch
 * in 2000 - many ideas in the current implementation are derived from
 * his patch.
 *
 * Further notes from the original documentation:
 *
 * 11 April '97.  Started multi-threading - markhe
 *	The global cache-chain is protected by the mutex 'cache_chain_mutex'.
 *	The sem is only needed when accessing/extending the cache-chain, which
 *	can never happen inside an interrupt (kmem_cache_create(),
 *	kmem_cache_shrink() and kmem_cache_reap()).
 *
 *	At present, each engine can be growing a cache.  This should be blocked.
 *
 * 15 March 2005. NUMA slab allocator.
 *	Shai Fultheim <shai@scalex86.org>.
 *	Shobhit Dayal <shobhit@calsoftinc.com>
 *	Alok N Kataria <alokk@calsoftinc.com>
 *	Christoph Lameter <christoph@lameter.com>
 *
 *	Modified the slab allocator to be node aware on NUMA systems.
 *	Each node has its own list of partial, free and full slabs.
 *	All object allocations for a node occur from node specific slab lists.
 */

#include	<linux/slab.h>
#include	<linux/mm.h>
#include	<linux/poison.h>
#include	<linux/swap.h>
#include	<linux/cache.h>
#include	<linux/interrupt.h>
#include	<linux/init.h>
#include	<linux/compiler.h>
#include	<linux/cpuset.h>
#include	<linux/proc_fs.h>
#include	<linux/seq_file.h>
#include	<linux/notifier.h>
#include	<linux/kallsyms.h>
#include	<linux/cpu.h>
#include	<linux/sysctl.h>
#include	<linux/module.h>
#include	<linux/kmemtrace.h>
#include	<linux/rcupdate.h>
#include	<linux/string.h>
#include	<linux/uaccess.h>
#include	<linux/nodemask.h>
#include	<linux/kmemleak.h>
#include	<linux/mempolicy.h>
#include	<linux/mutex.h>
#include	<linux/fault-inject.h>
#include	<linux/rtmutex.h>
#include	<linux/reciprocal_div.h>
#include	<linux/debugobjects.h>
#include	<linux/kmemcheck.h>

#include	<asm/cacheflush.h>
#include	<asm/tlbflush.h>
#include	<asm/page.h>

/*
 * DEBUG	- 1 for kmem_cache_create() to honour; SLAB_RED_ZONE & SLAB_POISON.
 *		  0 for faster, smaller code (especially in the critical paths).
 *
 * STATS	- 1 to collect stats for /proc/slabinfo.
 *		  0 for faster, smaller code (especially in the critical paths).
 *
 * FORCED_DEBUG	- 1 enables SLAB_RED_ZONE and SLAB_POISON (if possible)
 */

#ifdef CONFIG_DEBUG_SLAB
#define	DEBUG		1
#define	STATS		1
#define	FORCED_DEBUG	1
#else
#define	DEBUG		0
#define	STATS		0
#define	FORCED_DEBUG	0
#endif

/* Shouldn't this be in a header file somewhere? */
#define	BYTES_PER_WORD		sizeof(void *)
#define	REDZONE_ALIGN		max(BYTES_PER_WORD, __alignof__(unsigned long long))

#ifndef ARCH_KMALLOC_MINALIGN
/*
 * Enforce a minimum alignment for the kmalloc caches.
 * Usually, the kmalloc caches are cache_line_size() aligned, except when
 * DEBUG and FORCED_DEBUG are enabled, then they are BYTES_PER_WORD aligned.
 * Some archs want to perform DMA into kmalloc caches and need a guaranteed
 * alignment larger than the alignment of a 64-bit integer.
 * ARCH_KMALLOC_MINALIGN allows that.
 * Note that increasing this value may disable some debug features.
 */
#define ARCH_KMALLOC_MINALIGN __alignof__(unsigned long long)
#endif

#ifndef ARCH_SLAB_MINALIGN
/*
 * Enforce a minimum alignment for all caches.
 * Intended for archs that get misalignment faults even for BYTES_PER_WORD
 * aligned buffers. Includes ARCH_KMALLOC_MINALIGN.
 * If possible: Do not enable this flag for CONFIG_DEBUG_SLAB, it disables
 * some debug features.
 */
#define ARCH_SLAB_MINALIGN 0
#endif

#ifndef ARCH_KMALLOC_FLAGS
#define ARCH_KMALLOC_FLAGS SLAB_HWCACHE_ALIGN
#endif

/* Legal flag mask for kmem_cache_create(). */
#if DEBUG
# define CREATE_MASK	(SLAB_RED_ZONE | \
			 SLAB_POISON | SLAB_HWCACHE_ALIGN | \
			 SLAB_CACHE_DMA | \
			 SLAB_STORE_USER | \
			 SLAB_RECLAIM_ACCOUNT | SLAB_PANIC | \
			 SLAB_DESTROY_BY_RCU | SLAB_MEM_SPREAD | \
			 SLAB_DEBUG_OBJECTS | SLAB_NOLEAKTRACE | SLAB_NOTRACK)
#else
# define CREATE_MASK	(SLAB_HWCACHE_ALIGN | \
			 SLAB_CACHE_DMA | \
			 SLAB_RECLAIM_ACCOUNT | SLAB_PANIC | \
			 SLAB_DESTROY_BY_RCU | SLAB_MEM_SPREAD | \
			 SLAB_DEBUG_OBJECTS | SLAB_NOLEAKTRACE | SLAB_NOTRACK)
#endif

/*
 * kmem_bufctl_t:
 *
 * Bufctl's are used for linking objs within a slab
 * linked offsets.
 *
 * This implementation relies on "struct page" for locating the cache &
 * slab an object belongs to.
 * This allows the bufctl structure to be small (one int), but limits
 * the number of objects a slab (not a cache) can contain when off-slab
 * bufctls are used. The limit is the size of the largest general cache
 * that does not use off-slab slabs.
 * For 32bit archs with 4 kB pages, is this 56.
 * This is not serious, as it is only for large objects, when it is unwise
 * to have too many per slab.
 * Note: This limit can be raised by introducing a general cache whose size
 * is less than 512 (PAGE_SIZE<<3), but greater than 256.
 */

typedef unsigned int kmem_bufctl_t;
#define BUFCTL_END	(((kmem_bufctl_t)(~0U))-0)
#define BUFCTL_FREE	(((kmem_bufctl_t)(~0U))-1)
#define	BUFCTL_ACTIVE	(((kmem_bufctl_t)(~0U))-2)
#define	SLAB_LIMIT	(((kmem_bufctl_t)(~0U))-3)

/*
 * struct slab
 *
 * Manages the objs in a slab. Placed either at the beginning of mem allocated
 * for a slab, or allocated from an general cache.
 * Slabs are chained into three list: fully used, partial, fully free slabs.
 */
/* 
 * struct slab
 *
 * 管理 slab 中的对象。放置在为 slab 分配的内存的开始处，
 * 或者从通用缓存中分配。
 * Slabs 被链入三个列表：完全使用的、部分使用的、完全空闲的 slabs。
 */
// slab层把不同对象划分为高速缓存组，每个高速缓存组都存放不同类型的对象。每种对象对应一个高速缓存。
// 一个高速缓存有多个slab，然后每个slab内又有多个该对象。
// slab描述符要么在自身开始的地方，要么另行分配。
struct slab {
	struct list_head list;		// 满、部分满或空链表
	unsigned long colouroff;	// slab着色的偏移量
	// 在slab中的第一个对象
	void *s_mem;		/* including colour offset */		/* 包括颜色偏移的内存指针，指向 slab 的第一个对象 */
	// slab中已分配的对象数
	unsigned int inuse;	/* num of objs active in slab */
	// 第一个空闲对象（如果有的话）
	kmem_bufctl_t free;
	unsigned short nodeid;	/* 所属 NUMA 节点的 ID */
};

/*
 * struct slab_rcu
 *
 * slab_destroy on a SLAB_DESTROY_BY_RCU cache uses this structure to
 * arrange for kmem_freepages to be called via RCU.  This is useful if
 * we need to approach a kernel structure obliquely, from its address
 * obtained without the usual locking.  We can lock the structure to
 * stabilize it and check it's still at the given address, only if we
 * can be sure that the memory has not been meanwhile reused for some
 * other kind of object (which our subsystem's lock might corrupt).
 *
 * rcu_read_lock before reading the address, then rcu_read_unlock after
 * taking the spinlock within the structure expected at that address.
 *
 * We assume struct slab_rcu can overlay struct slab when destroying.
 */
struct slab_rcu {
	struct rcu_head head;
	struct kmem_cache *cachep;
	void *addr;
};

/*
 * struct array_cache
 *
 * Purpose:
 * - LIFO ordering, to hand out cache-warm objects from _alloc
 * - reduce the number of linked list operations
 * - reduce spinlock operations
 *
 * The limit is stored in the per-cpu structure to reduce the data cache
 * footprint.
 *
 */
struct array_cache {
	unsigned int avail;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int touched;
	spinlock_t lock;
	void *entry[];	/*
			 * Must have this definition in here for the proper
			 * alignment of array_cache. Also simplifies accessing
			 * the entries.
			 */
};

/*
 * bootstrap: The caches do not work without cpuarrays anymore, but the
 * cpuarrays are allocated from the generic caches...
 */
#define BOOT_CPUCACHE_ENTRIES	1
struct arraycache_init {
	struct array_cache cache;
	void *entries[BOOT_CPUCACHE_ENTRIES];
};

/*
 * The slab lists for all objects.
 */
// 包含三个slab链表，slabs_full，slabs_partial和slabs_empty
struct kmem_list3 {
    struct list_head slabs_partial;  /* 部分填充的 slab 列表，放在第一个位置有助于生成更好的汇编代码 */
    struct list_head slabs_full;     /* 完全填充的 slab 列表 */
    struct list_head slabs_free;     /* 空闲 slab 列表 */
    unsigned long free_objects;      /* 当前缓存中可用的空闲对象数量 */
    unsigned int free_limit;         /* 用于触发 slab 缓存回收的对象数量阈值 */
    unsigned int colour_next;        /* 每个节点的缓存着色索引，避免缓存同行冲突 */
    spinlock_t list_lock;            /* 用于保护部分 slab 列表的锁，保证并发访问安全 */
    struct array_cache *shared;      /* 节点的共享缓存，用于减少内存分配中的争用 */
    struct array_cache **alien;      /* 指向其他节点的缓存指针，用于跨节点内存分配 */
    unsigned long next_reap;         /* 下一次 slab 回收的时间戳，更新时无需加锁 */
    int free_touched;                /* 标志位，指示缓存是否自上次回收以来被修改，无需加锁 */
};

/*
 * Need this for bootstrapping a per node allocator.
 */
#define NUM_INIT_LISTS (3 * MAX_NUMNODES)
setup_cpu_cache
#define	CACHE_CACHE 0
#define	SIZE_AC MAX_NUMNODES
#define	SIZE_L3 (2 * MAX_NUMNODES)

static int drain_freelist(struct kmem_cache *cache,
			struct kmem_list3 *l3, int tofree);
static void free_block(struct kmem_cache *cachep, void **objpp, int len,
			int node);
static int enable_cpucache(struct kmem_cache *cachep, gfp_t gfp);
static void cache_reap(struct work_struct *unused);

/*
 * This function must be completely optimized away if a constant is passed to
 * it.  Mostly the same as what is in linux/slab.h except it returns an index.
 */
static __always_inline int index_of(const size_t size)
{
	extern void __bad_size(void);

	if (__builtin_constant_p(size)) {
		int i = 0;

#define CACHE(x) \
	if (size <=x) \
		return i; \
	else \
		i++;
#include <linux/kmalloc_sizes.h>
#undef CACHE
		__bad_size();
	} else
		__bad_size();
	return 0;
}

static int slab_early_init = 1;

#define INDEX_AC index_of(sizeof(struct arraycache_init))
#define INDEX_L3 index_of(sizeof(struct kmem_list3))

static void kmem_list3_init(struct kmem_list3 *parent)
{
	INIT_LIST_HEAD(&parent->slabs_full);
	INIT_LIST_HEAD(&parent->slabs_partial);
	INIT_LIST_HEAD(&parent->slabs_free);
	parent->shared = NULL;
	parent->alien = NULL;
	parent->colour_next = 0;
	spin_lock_init(&parent->list_lock);
	parent->free_objects = 0;
	parent->free_touched = 0;
}

#define MAKE_LIST(cachep, listp, slab, nodeid)				\
	do {								\
		INIT_LIST_HEAD(listp);					\
		list_splice(&(cachep->nodelists[nodeid]->slab), listp);	\
	} while (0)

#define	MAKE_ALL_LISTS(cachep, ptr, nodeid)				\
	do {								\
	MAKE_LIST((cachep), (&(ptr)->slabs_full), slabs_full, nodeid);	\
	MAKE_LIST((cachep), (&(ptr)->slabs_partial), slabs_partial, nodeid); \
	MAKE_LIST((cachep), (&(ptr)->slabs_free), slabs_free, nodeid);	\
	} while (0)

#define CFLGS_OFF_SLAB		(0x80000000UL)
#define	OFF_SLAB(x)	((x)->flags & CFLGS_OFF_SLAB)

#define BATCHREFILL_LIMIT	16
/*
 * Optimization question: fewer reaps means less probability for unnessary
 * cpucache drain/refill cycles.
 *
 * OTOH the cpuarrays can contain lots of objects,
 * which could lock up otherwise freeable slabs.
 */
#define REAPTIMEOUT_CPUC	(2*HZ)
#define REAPTIMEOUT_LIST3	(4*HZ)

#if STATS
#define	STATS_INC_ACTIVE(x)	((x)->num_active++)
#define	STATS_DEC_ACTIVE(x)	((x)->num_active--)
#define	STATS_INC_ALLOCED(x)	((x)->num_allocations++)
#define	STATS_INC_GROWN(x)	((x)->grown++)
#define	STATS_ADD_REAPED(x,y)	((x)->reaped += (y))
#define	STATS_SET_HIGH(x)						\
	do {								\
		if ((x)->num_active > (x)->high_mark)			\
			(x)->high_mark = (x)->num_active;		\
	} while (0)
#define	STATS_INC_ERR(x)	((x)->errors++)
#define	STATS_INC_NODEALLOCS(x)	((x)->node_allocs++)
#define	STATS_INC_NODEFREES(x)	((x)->node_frees++)
#define STATS_INC_ACOVERFLOW(x)   ((x)->node_overflow++)
#define	STATS_SET_FREEABLE(x, i)					\
	do {								\
		if ((x)->max_freeable < i)				\
			(x)->max_freeable = i;				\
	} while (0)
#define STATS_INC_ALLOCHIT(x)	atomic_inc(&(x)->allochit)
#define STATS_INC_ALLOCMISS(x)	atomic_inc(&(x)->allocmiss)
#define STATS_INC_FREEHIT(x)	atomic_inc(&(x)->freehit)
#define STATS_INC_FREEMISS(x)	atomic_inc(&(x)->freemiss)
#else
#define	STATS_INC_ACTIVE(x)	do { } while (0)
#define	STATS_DEC_ACTIVE(x)	do { } while (0)
#define	STATS_INC_ALLOCED(x)	do { } while (0)
#define	STATS_INC_GROWN(x)	do { } while (0)
#define	STATS_ADD_REAPED(x,y)	do { } while (0)
#define	STATS_SET_HIGH(x)	do { } while (0)
#define	STATS_INC_ERR(x)	do { } while (0)
#define	STATS_INC_NODEALLOCS(x)	do { } while (0)
#define	STATS_INC_NODEFREES(x)	do { } while (0)
#define STATS_INC_ACOVERFLOW(x)   do { } while (0)
#define	STATS_SET_FREEABLE(x, i) do { } while (0)
#define STATS_INC_ALLOCHIT(x)	do { } while (0)
#define STATS_INC_ALLOCMISS(x)	do { } while (0)
#define STATS_INC_FREEHIT(x)	do { } while (0)
#define STATS_INC_FREEMISS(x)	do { } while (0)
#endif

#if DEBUG

/*
 * memory layout of objects:
 * 0		: objp
 * 0 .. cachep->obj_offset - BYTES_PER_WORD - 1: padding. This ensures that
 * 		the end of an object is aligned with the end of the real
 * 		allocation. Catches writes behind the end of the allocation.
 * cachep->obj_offset - BYTES_PER_WORD .. cachep->obj_offset - 1:
 * 		redzone word.
 * cachep->obj_offset: The real object.
 * cachep->buffer_size - 2* BYTES_PER_WORD: redzone word [BYTES_PER_WORD long]
 * cachep->buffer_size - 1* BYTES_PER_WORD: last caller address
 *					[BYTES_PER_WORD long]
 */
static int obj_offset(struct kmem_cache *cachep)
{
	return cachep->obj_offset;
}

static int obj_size(struct kmem_cache *cachep)
{
	return cachep->obj_size;
}

static unsigned long long *dbg_redzone1(struct kmem_cache *cachep, void *objp)
{
	BUG_ON(!(cachep->flags & SLAB_RED_ZONE));
	return (unsigned long long*) (objp + obj_offset(cachep) -
				      sizeof(unsigned long long));
}

static unsigned long long *dbg_redzone2(struct kmem_cache *cachep, void *objp)
{
	BUG_ON(!(cachep->flags & SLAB_RED_ZONE));
	if (cachep->flags & SLAB_STORE_USER)
		return (unsigned long long *)(objp + cachep->buffer_size -
					      sizeof(unsigned long long) -
					      REDZONE_ALIGN);
	return (unsigned long long *) (objp + cachep->buffer_size -
				       sizeof(unsigned long long));
}

static void **dbg_userword(struct kmem_cache *cachep, void *objp)
{
	BUG_ON(!(cachep->flags & SLAB_STORE_USER));
	return (void **)(objp + cachep->buffer_size - BYTES_PER_WORD);
}

#else

#define obj_offset(x)			0
#define obj_size(cachep)		(cachep->buffer_size)
#define dbg_redzone1(cachep, objp)	({BUG(); (unsigned long long *)NULL;})
#define dbg_redzone2(cachep, objp)	({BUG(); (unsigned long long *)NULL;})
#define dbg_userword(cachep, objp)	({BUG(); (void **)NULL;})

#endif

#ifdef CONFIG_TRACING
size_t slab_buffer_size(struct kmem_cache *cachep)
{
	return cachep->buffer_size;
}
EXPORT_SYMBOL(slab_buffer_size);
#endif

/*
 * Do not go above this order unless 0 objects fit into the slab.
 */
#define	BREAK_GFP_ORDER_HI	1
#define	BREAK_GFP_ORDER_LO	0
static int slab_break_gfp_order = BREAK_GFP_ORDER_LO;

/*
 * Functions for storing/retrieving the cachep and or slab from the page
 * allocator.  These are used to find the slab an obj belongs to.  With kfree(),
 * these are used to find the cache which an obj belongs to.
 */
static inline void page_set_cache(struct page *page, struct kmem_cache *cache)
{
	page->lru.next = (struct list_head *)cache;
}

static inline struct kmem_cache *page_get_cache(struct page *page)
{
	page = compound_head(page);
	BUG_ON(!PageSlab(page));
	return (struct kmem_cache *)page->lru.next;
}

static inline void page_set_slab(struct page *page, struct slab *slab)
{
	page->lru.prev = (struct list_head *)slab;
}

static inline struct slab *page_get_slab(struct page *page)
{
	BUG_ON(!PageSlab(page));
	return (struct slab *)page->lru.prev;
}

static inline struct kmem_cache *virt_to_cache(const void *obj)
{
	struct page *page = virt_to_head_page(obj);
	return page_get_cache(page);
}

static inline struct slab *virt_to_slab(const void *obj)
{
	struct page *page = virt_to_head_page(obj);
	return page_get_slab(page);
}

/**
 * index_to_obj - 将 slab 中的索引转换为对象的指针
 * @cache: 指向 kmem_cache 结构体的指针，包含 slab 缓存的配置信息
 * @slab: 指向 slab 结构体的指针，表示当前的 slab
 * @idx: 对象的索引，表示在 slab 中的位置
 *
 * 该函数根据对象的索引计算出其在 slab 中的实际内存地址，并返回该对象的指针。
 */
static inline void *index_to_obj(struct kmem_cache *cache, struct slab *slab, unsigned int idx)
{
    // 计算并返回对象的指针地址：
    // slab->s_mem 是 slab 数据区的起始地址，
    // cache->buffer_size 是每个对象的大小，
    // 通过将起始地址偏移 (buffer_size * idx) 得到对象的地址。
    return slab->s_mem + cache->buffer_size * idx;
}


/*
 * We want to avoid an expensive divide : (offset / cache->buffer_size)
 *   Using the fact that buffer_size is a constant for a particular cache,
 *   we can replace (offset / cache->buffer_size) by
 *   reciprocal_divide(offset, cache->reciprocal_buffer_size)
 */
static inline unsigned int obj_to_index(const struct kmem_cache *cache,
					const struct slab *slab, void *obj)
{
	u32 offset = (obj - slab->s_mem);
	return reciprocal_divide(offset, cache->reciprocal_buffer_size);
}

/*
 * These are the default caches for kmalloc. Custom caches can have other sizes.
 */
struct cache_sizes malloc_sizes[] = {
#define CACHE(x) { .cs_size = (x) },
#include <linux/kmalloc_sizes.h>
	CACHE(ULONG_MAX)
#undef CACHE
};
EXPORT_SYMBOL(malloc_sizes);

/* Must match cache_sizes above. Out of line to keep cache footprint low. */
struct cache_names {
	char *name;
	char *name_dma;
};

static struct cache_names __initdata cache_names[] = {
#define CACHE(x) { .name = "size-" #x, .name_dma = "size-" #x "(DMA)" },
#include <linux/kmalloc_sizes.h>
	{NULL,}
#undef CACHE
};

static struct arraycache_init initarray_cache __initdata =
    { {0, BOOT_CPUCACHE_ENTRIES, 1, 0} };
static struct arraycache_init initarray_generic =
    { {0, BOOT_CPUCACHE_ENTRIES, 1, 0} };

/* internal cache of cache description objs */
static struct kmem_cache cache_cache = {
	.batchcount = 1,
	.limit = BOOT_CPUCACHE_ENTRIES,
	.shared = 1,
	.buffer_size = sizeof(struct kmem_cache),
	.name = "kmem_cache",
};

#define BAD_ALIEN_MAGIC 0x01020304ul

/*
 * chicken and egg problem: delay the per-cpu array allocation
 * until the general caches are up.
 */
static enum {
	NONE,///尚未初始化，CPU 缓存系统没有启用。
	PARTIAL_AC,//处理器的 array 缓存已初始化，但更高级的缓存（如 kmem_list3）尚未设置。
	PARTIAL_L3,//部分初始化，kmem_list3 缓存已分配并初始化。
	EARLY,//早期初始化阶段，通常用于指代部分 CPU 缓存或数据结构已经准备好，但尚未完全启用。
	FULL
} g_cpucache_up;

/*
 * used by boot code to determine if it can use slab based allocator
 */
int slab_is_available(void)
{
	return g_cpucache_up >= EARLY;
}

#ifdef CONFIG_LOCKDEP

/*
 * Slab sometimes uses the kmalloc slabs to store the slab headers
 * for other slabs "off slab".
 * The locking for this is tricky in that it nests within the locks
 * of all other slabs in a few places; to deal with this special
 * locking we put on-slab caches into a separate lock-class.
 *
 * We set lock class for alien array caches which are up during init.
 * The lock annotation will be lost if all cpus of a node goes down and
 * then comes back up during hotplug
 */
static struct lock_class_key on_slab_l3_key;
static struct lock_class_key on_slab_alc_key;

static void init_node_lock_keys(int q)
{
	struct cache_sizes *s = malloc_sizes;

	if (g_cpucache_up != FULL)
		return;

	for (s = malloc_sizes; s->cs_size != ULONG_MAX; s++) {
		struct array_cache **alc;
		struct kmem_list3 *l3;
		int r;

		l3 = s->cs_cachep->nodelists[q];
		if (!l3 || OFF_SLAB(s->cs_cachep))
			continue;
		lockdep_set_class(&l3->list_lock, &on_slab_l3_key);
		alc = l3->alien;
		/*
		 * FIXME: This check for BAD_ALIEN_MAGIC
		 * should go away when common slab code is taught to
		 * work even without alien caches.
		 * Currently, non NUMA code returns BAD_ALIEN_MAGIC
		 * for alloc_alien_cache,
		 */
		if (!alc || (unsigned long)alc == BAD_ALIEN_MAGIC)
			continue;
		for_each_node(r) {
			if (alc[r])
				lockdep_set_class(&alc[r]->lock,
					&on_slab_alc_key);
		}
	}
}

static inline void init_lock_keys(void)
{
	int node;

	for_each_node(node)
		init_node_lock_keys(node);
}
#else
static void init_node_lock_keys(int q)
{
}

static inline void init_lock_keys(void)
{
}
#endif

/*
 * Guard access to the cache-chain.
 */
static DEFINE_MUTEX(cache_chain_mutex);
static struct list_head cache_chain;//用来维护所有 kmem_cache 实例（缓存池）的链表

static DEFINE_PER_CPU(struct delayed_work, slab_reap_work);

static inline struct array_cache *cpu_cache_get(struct kmem_cache *cachep)
{
	return cachep->array[smp_processor_id()];
}

static inline struct kmem_cache *__find_general_cachep(size_t size,
							gfp_t gfpflags)
{
	struct cache_sizes *csizep = malloc_sizes;

#if DEBUG
	/* This happens if someone tries to call
	 * kmem_cache_create(), or __kmalloc(), before
	 * the generic caches are initialized.
	 */
	BUG_ON(malloc_sizes[INDEX_AC].cs_cachep == NULL);
#endif
	if (!size)
		return ZERO_SIZE_PTR;

	while (size > csizep->cs_size)
		csizep++;

	/*
	 * Really subtle: The last entry with cs->cs_size==ULONG_MAX
	 * has cs_{dma,}cachep==NULL. Thus no special case
	 * for large kmalloc calls required.
	 */
#ifdef CONFIG_ZONE_DMA
	if (unlikely(gfpflags & GFP_DMA))
		return csizep->cs_dmacachep;
#endif
	return csizep->cs_cachep;
}

static struct kmem_cache *kmem_find_general_cachep(size_t size, gfp_t gfpflags)
{
	return __find_general_cachep(size, gfpflags);
}

static size_t slab_mgmt_size(size_t nr_objs, size_t align)
{
	return ALIGN(sizeof(struct slab)+nr_objs*sizeof(kmem_bufctl_t), align);
}

/*
 * Calculate the number of objects and left-over bytes for a given buffer size.
 */
static void cache_estimate(unsigned long gfporder, size_t buffer_size,
			   size_t align, int flags, size_t *left_over,
			   unsigned int *num)
{
	int nr_objs;                 // 该 slab 可以容纳的对象数
	size_t mgmt_size;            // slab 管理结构所需的大小
	size_t slab_size = PAGE_SIZE << gfporder;  // slab 的总大小，基于 gfporder 确定

	/*
	 * slab 管理结构可以位于 slab 内部或外部。如果位于 slab 内部，
	 * 则分配的内存用于以下用途：
	 *
	 * - struct slab：用于 slab 管理
	 * - 每个对象一个 kmem_bufctl_t
	 * - 根据 @align 对齐填充
	 * - @buffer_size 为每个对象的大小
	 *
	 * 如果 slab 管理结构位于 slab 之外（off-slab），
	 * 则对齐会在计算对象大小时处理好。由于 slab 总是页对齐的，
	 * 所以对象在分配时也会被正确对齐。
	 */
	if (flags & CFLGS_OFF_SLAB) {
		// 当 slab 管理结构位于 slab 之外时，不计算管理结构大小
		mgmt_size = 0;
		nr_objs = slab_size / buffer_size;  // 计算该 slab 可以容纳的对象数

		// 限制对象数不要超过 SLAB_LIMIT
		if (nr_objs > SLAB_LIMIT)
			nr_objs = SLAB_LIMIT;
	} else {
		/*
		 * 首次估算时忽略对齐填充。对齐填充至多占用 @align-1 字节，
		 * 而 @buffer_size 至少为 @align。在最坏情况下，该估算值
		 * 会比实际可以容纳的对象数多一个。
		 */
		nr_objs = (slab_size - sizeof(struct slab)) /
			  (buffer_size + sizeof(kmem_bufctl_t));

		/*
		 * 如果计算的对象数大于实际可以容纳的对象数，减少 1 个对象。
		 */
		if (slab_mgmt_size(nr_objs, align) + nr_objs*buffer_size
		       > slab_size)
			nr_objs--;

		// 限制对象数不要超过 SLAB_LIMIT
		if (nr_objs > SLAB_LIMIT)
			nr_objs = SLAB_LIMIT;

		// 计算 slab 管理结构所需的大小
		mgmt_size = slab_mgmt_size(nr_objs, align);
	}

	// 设置输出参数
	*num = nr_objs;  // slab 中可容纳的对象数量
	*left_over = slab_size - nr_objs * buffer_size - mgmt_size;  // 剩余的碎片空间大小
}


#define slab_error(cachep, msg) __slab_error(__func__, cachep, msg)

static void __slab_error(const char *function, struct kmem_cache *cachep,
			char *msg)
{
	printk(KERN_ERR "slab error in %s(): cache `%s': %s\n",
	       function, cachep->name, msg);
	dump_stack();
}

/*
 * By default on NUMA we use alien caches to stage the freeing of
 * objects allocated from other nodes. This causes massive memory
 * inefficiencies when using fake NUMA setup to split memory into a
 * large number of small nodes, so it can be disabled on the command
 * line
  */

static int use_alien_caches __read_mostly = 1;
static int __init noaliencache_setup(char *s)
{
	use_alien_caches = 0;
	return 1;
}
__setup("noaliencache", noaliencache_setup);

#ifdef CONFIG_NUMA
/*
 * Special reaping functions for NUMA systems called from cache_reap().
 * These take care of doing round robin flushing of alien caches (containing
 * objects freed on different nodes from which they were allocated) and the
 * flushing of remote pcps by calling drain_node_pages.
 */
static DEFINE_PER_CPU(unsigned long, slab_reap_node);

static void init_reap_node(int cpu)
{
	int node;

	node = next_node(cpu_to_node(cpu), node_online_map);
	if (node == MAX_NUMNODES)
		node = first_node(node_online_map);

	per_cpu(slab_reap_node, cpu) = node;
}

static void next_reap_node(void)
{
	int node = __get_cpu_var(slab_reap_node);

	node = next_node(node, node_online_map);
	if (unlikely(node >= MAX_NUMNODES))
		node = first_node(node_online_map);
	__get_cpu_var(slab_reap_node) = node;
}

#else
#define init_reap_node(cpu) do { } while (0)
#define next_reap_node(void) do { } while (0)
#endif

/*
 * Initiate the reap timer running on the target CPU.  We run at around 1 to 2Hz
 * via the workqueue/eventd.
 * Add the CPU number into the expiration time to minimize the possibility of
 * the CPUs getting into lockstep and contending for the global cache chain
 * lock.
 */
static void __cpuinit start_cpu_timer(int cpu)
{
	struct delayed_work *reap_work = &per_cpu(slab_reap_work, cpu);

	/*
	 * When this gets called from do_initcalls via cpucache_init(),
	 * init_workqueues() has already run, so keventd will be setup
	 * at that time.
	 */
	if (keventd_up() && reap_work->work.func == NULL) {
		init_reap_node(cpu);
		INIT_DELAYED_WORK(reap_work, cache_reap);
		schedule_delayed_work_on(cpu, reap_work,
					__round_jiffies_relative(HZ, cpu));
	}
}

static struct array_cache *alloc_arraycache(int node, int entries,
					    int batchcount, gfp_t gfp)
{
	int memsize = sizeof(void *) * entries + sizeof(struct array_cache);
	struct array_cache *nc = NULL;

	nc = kmalloc_node(memsize, gfp, node);
	/*
	 * The array_cache structures contain pointers to free object.
	 * However, when such objects are allocated or transfered to another
	 * cache the pointers are not cleared and they could be counted as
	 * valid references during a kmemleak scan. Therefore, kmemleak must
	 * not scan such objects.
	 */
	kmemleak_no_scan(nc);
	if (nc) {
		nc->avail = 0;
		nc->limit = entries;
		nc->batchcount = batchcount;
		nc->touched = 0;
		spin_lock_init(&nc->lock);
	}
	return nc;
}

/*
 * Transfer objects in one arraycache to another.
 * Locking must be handled by the caller.
 *
 * Return the number of entries transferred.
 */
static int transfer_objects(struct array_cache *to,
		struct array_cache *from, unsigned int max)
{
	/* Figure out how many entries to transfer */
	int nr = min(min(from->avail, max), to->limit - to->avail);

	if (!nr)
		return 0;

	memcpy(to->entry + to->avail, from->entry + from->avail -nr,
			sizeof(void *) *nr);

	from->avail -= nr;
	to->avail += nr;
	return nr;
}

#ifndef CONFIG_NUMA

#define drain_alien_cache(cachep, alien) do { } while (0)
#define reap_alien(cachep, l3) do { } while (0)

static inline struct array_cache **alloc_alien_cache(int node, int limit, gfp_t gfp)
{
	return (struct array_cache **)BAD_ALIEN_MAGIC;
}

static inline void free_alien_cache(struct array_cache **ac_ptr)
{
}

static inline int cache_free_alien(struct kmem_cache *cachep, void *objp)
{
	return 0;
}

static inline void *alternate_node_alloc(struct kmem_cache *cachep,
		gfp_t flags)
{
	return NULL;
}

static inline void *____cache_alloc_node(struct kmem_cache *cachep,
		 gfp_t flags, int nodeid)
{
	return NULL;
}

#else	/* CONFIG_NUMA */

static void *____cache_alloc_node(struct kmem_cache *, gfp_t, int);
static void *alternate_node_alloc(struct kmem_cache *, gfp_t);

static struct array_cache **alloc_alien_cache(int node, int limit, gfp_t gfp)
{
	struct array_cache **ac_ptr;
	int memsize = sizeof(void *) * nr_node_ids;
	int i;

	if (limit > 1)
		limit = 12;
	ac_ptr = kzalloc_node(memsize, gfp, node);
	if (ac_ptr) {
		for_each_node(i) {
			if (i == node || !node_online(i))
				continue;
			ac_ptr[i] = alloc_arraycache(node, limit, 0xbaadf00d, gfp);
			if (!ac_ptr[i]) {
				for (i--; i >= 0; i--)
					kfree(ac_ptr[i]);
				kfree(ac_ptr);
				return NULL;
			}
		}
	}
	return ac_ptr;
}

static void free_alien_cache(struct array_cache **ac_ptr)
{
	int i;

	if (!ac_ptr)
		return;
	for_each_node(i)
	    kfree(ac_ptr[i]);
	kfree(ac_ptr);
}

static void __drain_alien_cache(struct kmem_cache *cachep,
				struct array_cache *ac, int node)
{
	struct kmem_list3 *rl3 = cachep->nodelists[node];

	if (ac->avail) {
		spin_lock(&rl3->list_lock);
		/*
		 * Stuff objects into the remote nodes shared array first.
		 * That way we could avoid the overhead of putting the objects
		 * into the free lists and getting them back later.
		 */
		if (rl3->shared)
			transfer_objects(rl3->shared, ac, ac->limit);

		free_block(cachep, ac->entry, ac->avail, node);
		ac->avail = 0;
		spin_unlock(&rl3->list_lock);
	}
}

/*
 * Called from cache_reap() to regularly drain alien caches round robin.
 */
static void reap_alien(struct kmem_cache *cachep, struct kmem_list3 *l3)
{
	int node = __get_cpu_var(slab_reap_node);

	if (l3->alien) {
		struct array_cache *ac = l3->alien[node];

		if (ac && ac->avail && spin_trylock_irq(&ac->lock)) {
			__drain_alien_cache(cachep, ac, node);
			spin_unlock_irq(&ac->lock);
		}
	}
}

static void drain_alien_cache(struct kmem_cache *cachep,
				struct array_cache **alien)
{
	int i = 0;
	struct array_cache *ac;
	unsigned long flags;

	for_each_online_node(i) {
		ac = alien[i];
		if (ac) {
			spin_lock_irqsave(&ac->lock, flags);
			__drain_alien_cache(cachep, ac, i);
			spin_unlock_irqrestore(&ac->lock, flags);
		}
	}
}

static inline int cache_free_alien(struct kmem_cache *cachep, void *objp)
{
	struct slab *slabp = virt_to_slab(objp);
	int nodeid = slabp->nodeid;
	struct kmem_list3 *l3;
	struct array_cache *alien = NULL;
	int node;

	node = numa_node_id();

	/*
	 * Make sure we are not freeing a object from another node to the array
	 * cache on this cpu.
	 */
	if (likely(slabp->nodeid == node))
		return 0;

	l3 = cachep->nodelists[node];
	STATS_INC_NODEFREES(cachep);
	if (l3->alien && l3->alien[nodeid]) {
		alien = l3->alien[nodeid];
		spin_lock(&alien->lock);
		if (unlikely(alien->avail == alien->limit)) {
			STATS_INC_ACOVERFLOW(cachep);
			__drain_alien_cache(cachep, alien, nodeid);
		}
		alien->entry[alien->avail++] = objp;
		spin_unlock(&alien->lock);
	} else {
		spin_lock(&(cachep->nodelists[nodeid])->list_lock);
		free_block(cachep, &objp, 1, nodeid);
		spin_unlock(&(cachep->nodelists[nodeid])->list_lock);
	}
	return 1;
}
#endif

static void __cpuinit cpuup_canceled(long cpu)
{
	struct kmem_cache *cachep;
	struct kmem_list3 *l3 = NULL;
	int node = cpu_to_node(cpu);
	const struct cpumask *mask = cpumask_of_node(node);

	list_for_each_entry(cachep, &cache_chain, next) {
		struct array_cache *nc;
		struct array_cache *shared;
		struct array_cache **alien;

		/* cpu is dead; no one can alloc from it. */
		nc = cachep->array[cpu];
		cachep->array[cpu] = NULL;
		l3 = cachep->nodelists[node];

		if (!l3)
			goto free_array_cache;

		spin_lock_irq(&l3->list_lock);

		/* Free limit for this kmem_list3 */
		l3->free_limit -= cachep->batchcount;
		if (nc)
			free_block(cachep, nc->entry, nc->avail, node);

		if (!cpumask_empty(mask)) {
			spin_unlock_irq(&l3->list_lock);
			goto free_array_cache;
		}

		shared = l3->shared;
		if (shared) {
			free_block(cachep, shared->entry,
				   shared->avail, node);
			l3->shared = NULL;
		}

		alien = l3->alien;
		l3->alien = NULL;

		spin_unlock_irq(&l3->list_lock);

		kfree(shared);
		if (alien) {
			drain_alien_cache(cachep, alien);
			free_alien_cache(alien);
		}
free_array_cache:
		kfree(nc);
	}
	/*
	 * In the previous loop, all the objects were freed to
	 * the respective cache's slabs,  now we can go ahead and
	 * shrink each nodelist to its limit.
	 */
	list_for_each_entry(cachep, &cache_chain, next) {
		l3 = cachep->nodelists[node];
		if (!l3)
			continue;
		drain_freelist(cachep, l3, l3->free_objects);
	}
}

static int __cpuinit cpuup_prepare(long cpu)
{
	struct kmem_cache *cachep;
	struct kmem_list3 *l3 = NULL;
	int node = cpu_to_node(cpu);
	const int memsize = sizeof(struct kmem_list3);

	/*
	 * We need to do this right in the beginning since
	 * alloc_arraycache's are going to use this list.
	 * kmalloc_node allows us to add the slab to the right
	 * kmem_list3 and not this cpu's kmem_list3
	 */

	list_for_each_entry(cachep, &cache_chain, next) {
		/*
		 * Set up the size64 kmemlist for cpu before we can
		 * begin anything. Make sure some other cpu on this
		 * node has not already allocated this
		 */
		if (!cachep->nodelists[node]) {
			l3 = kmalloc_node(memsize, GFP_KERNEL, node);
			if (!l3)
				goto bad;
			kmem_list3_init(l3);
			l3->next_reap = jiffies + REAPTIMEOUT_LIST3 +
			    ((unsigned long)cachep) % REAPTIMEOUT_LIST3;

			/*
			 * The l3s don't come and go as CPUs come and
			 * go.  cache_chain_mutex is sufficient
			 * protection here.
			 */
			cachep->nodelists[node] = l3;
		}

		spin_lock_irq(&cachep->nodelists[node]->list_lock);
		cachep->nodelists[node]->free_limit =
			(1 + nr_cpus_node(node)) *
			cachep->batchcount + cachep->num;
		spin_unlock_irq(&cachep->nodelists[node]->list_lock);
	}

	/*
	 * Now we can go ahead with allocating the shared arrays and
	 * array caches
	 */
	list_for_each_entry(cachep, &cache_chain, next) {
		struct array_cache *nc;
		struct array_cache *shared = NULL;
		struct array_cache **alien = NULL;

		nc = alloc_arraycache(node, cachep->limit,
					cachep->batchcount, GFP_KERNEL);
		if (!nc)
			goto bad;
		if (cachep->shared) {
			shared = alloc_arraycache(node,
				cachep->shared * cachep->batchcount,
				0xbaadf00d, GFP_KERNEL);
			if (!shared) {
				kfree(nc);
				goto bad;
			}
		}
		if (use_alien_caches) {
			alien = alloc_alien_cache(node, cachep->limit, GFP_KERNEL);
			if (!alien) {
				kfree(shared);
				kfree(nc);
				goto bad;
			}
		}
		cachep->array[cpu] = nc;
		l3 = cachep->nodelists[node];
		BUG_ON(!l3);

		spin_lock_irq(&l3->list_lock);
		if (!l3->shared) {
			/*
			 * We are serialised from CPU_DEAD or
			 * CPU_UP_CANCELLED by the cpucontrol lock
			 */
			l3->shared = shared;
			shared = NULL;
		}
#ifdef CONFIG_NUMA
		if (!l3->alien) {
			l3->alien = alien;
			alien = NULL;
		}
#endif
		spin_unlock_irq(&l3->list_lock);
		kfree(shared);
		free_alien_cache(alien);
	}
	init_node_lock_keys(node);

	return 0;
bad:
	cpuup_canceled(cpu);
	return -ENOMEM;
}

static int __cpuinit cpuup_callback(struct notifier_block *nfb,
				    unsigned long action, void *hcpu)
{
	long cpu = (long)hcpu;
	int err = 0;

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		mutex_lock(&cache_chain_mutex);
		err = cpuup_prepare(cpu);
		mutex_unlock(&cache_chain_mutex);
		break;
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		start_cpu_timer(cpu);
		break;
#ifdef CONFIG_HOTPLUG_CPU
  	case CPU_DOWN_PREPARE:
  	case CPU_DOWN_PREPARE_FROZEN:
		/*
		 * Shutdown cache reaper. Note that the cache_chain_mutex is
		 * held so that if cache_reap() is invoked it cannot do
		 * anything expensive but will only modify reap_work
		 * and reschedule the timer.
		*/
		cancel_rearming_delayed_work(&per_cpu(slab_reap_work, cpu));
		/* Now the cache_reaper is guaranteed to be not running. */
		per_cpu(slab_reap_work, cpu).work.func = NULL;
  		break;
  	case CPU_DOWN_FAILED:
  	case CPU_DOWN_FAILED_FROZEN:
		start_cpu_timer(cpu);
  		break;
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		/*
		 * Even if all the cpus of a node are down, we don't free the
		 * kmem_list3 of any cache. This to avoid a race between
		 * cpu_down, and a kmalloc allocation from another cpu for
		 * memory from the node of the cpu going down.  The list3
		 * structure is usually allocated from kmem_cache_create() and
		 * gets destroyed at kmem_cache_destroy().
		 */
		/* fall through */
#endif
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
		mutex_lock(&cache_chain_mutex);
		cpuup_canceled(cpu);
		mutex_unlock(&cache_chain_mutex);
		break;
	}
	return err ? NOTIFY_BAD : NOTIFY_OK;
}

static struct notifier_block __cpuinitdata cpucache_notifier = {
	&cpuup_callback, NULL, 0
};

/*
 * swap the static kmem_list3 with kmalloced memory
 */
static void init_list(struct kmem_cache *cachep, struct kmem_list3 *list,
			int nodeid)
{
	struct kmem_list3 *ptr;

	ptr = kmalloc_node(sizeof(struct kmem_list3), GFP_NOWAIT, nodeid);
	BUG_ON(!ptr);

	memcpy(ptr, list, sizeof(struct kmem_list3));
	/*
	 * Do not assume that spinlocks can be initialized via memcpy:
	 */
	spin_lock_init(&ptr->list_lock);

	MAKE_ALL_LISTS(cachep, ptr, nodeid);
	cachep->nodelists[nodeid] = ptr;
}

/*
 * 为那些 buffer_size 与 kmem_list3 大小相同的缓存设置所有 kmem_list3 结构。
 * 这个函数会为指定的缓存（cachep）的每个在线节点设置相应的 kmem_list3 结构。
 */
static void __init set_up_list3s(struct kmem_cache *cachep, int index)
{
	int node;

	/* 遍历所有在线的 NUMA 节点，确保每个节点都有对应的 kmem_list3 */
	for_each_online_node(node) {
		/* 
		 * 将 cachep 对应节点的 nodelists 指向初始化的 kmem_list3 数组中
		 * 根据 index 和节点编号计算的相应元素。
		 */
		cachep->nodelists[node] = &initkmem_list3[index + node];

		/* 
		 * 设置 next_reap 字段，以决定下次 slab 回收的时间。
		 * jiffies：当前时间，用来计算 slab 回收的超时时间。
		 * REAPTIMEOUT_LIST3：表示回收超时的常量。
		 * ((unsigned long)cachep) % REAPTIMEOUT_LIST3：通过缓存指针做取模运算，
		 * 随机化回收时间，避免所有节点的回收操作同步发生，减少性能抖动。
		 */
		cachep->nodelists[node]->next_reap = jiffies +
		    REAPTIMEOUT_LIST3 +                    /* 回收超时常量 */
		    ((unsigned long)cachep) % REAPTIMEOUT_LIST3; /* 随机化偏移量以避免同步 */
	}
}


/*
 * Initialisation.  Called after the page allocator have been initialised and
 * before smp_init().
 */
void __init kmem_cache_init(void)
{
	// 初始化过程中使用的一些变量
	size_t left_over;
	struct cache_sizes *sizes;
	struct cache_names *names;
	int i;
	int order;
	int node;

	// 如果系统中只有一个节点，不使用外来缓存
	if (num_possible_nodes() == 1)
		use_alien_caches = 0;

	// 初始化初始的 slab 列表
	for (i = 0; i < NUM_INIT_LISTS; i++) {
		kmem_list3_init(&initkmem_list3[i]);
		if (i < MAX_NUMNODES)
			cache_cache.nodelists[i] = NULL;
	}
	set_up_list3s(&cache_cache, CACHE_CACHE);

	// 如果总的内存超过32MB，设置slab分配器使用的页数更大，以减少碎片化
	if (totalram_pages > (32 << 20) >> PAGE_SHIFT)
		slab_break_gfp_order = BREAK_GFP_ORDER_HI;

	// 第一步: 创建缓存，用于管理 kmem_cache 结构
	node = numa_node_id();  // 获取当前 NUMA 节点的 ID

	// 初始化 cache_cache，管理所有缓存描述符
	INIT_LIST_HEAD(&cache_chain);  // 初始化 cache_chain 列表
	list_add(&cache_cache.next, &cache_chain);  // 将 cache_cache 加入链表
	cache_cache.colour_off = cache_line_size();  // 设置 cache 的颜色偏移量
	cache_cache.array[smp_processor_id()] = &initarray_cache.cache;  // 设置 per-CPU 缓存
	cache_cache.nodelists[node] = &initkmem_list3[CACHE_CACHE + node];  // 设置节点列表

	// 设置 cache_cache 的大小，确保它对齐缓存行
	cache_cache.buffer_size = offsetof(struct kmem_cache, nodelists) +
				 nr_node_ids * sizeof(struct kmem_list3 *);
	cache_cache.buffer_size = ALIGN(cache_cache.buffer_size,
					cache_line_size());
	cache_cache.reciprocal_buffer_size =
		reciprocal_value(cache_cache.buffer_size);

	// 估算缓存大小，确保有足够的空间来存放对象
	for (order = 0; order < MAX_ORDER; order++) {
		cache_estimate(order, cache_cache.buffer_size,
			cache_line_size(), 0, &left_over, &cache_cache.num);
		if (cache_cache.num)
			break;
	}
	BUG_ON(!cache_cache.num);  // 如果计算失败，触发 BUG
	cache_cache.gfporder = order;  // 设置缓存使用的页面顺序
	cache_cache.colour = left_over / cache_cache.colour_off;  // 设置缓存颜色
	cache_cache.slab_size = ALIGN(cache_cache.num * sizeof(kmem_bufctl_t) +
				      sizeof(struct slab), cache_line_size());  // 设置 slab 大小

	// 第二步: 创建 kmalloc 缓存，用于分配内存对象
	sizes = malloc_sizes;
	names = cache_names;

	// 创建内存池，确保能够正确分配 array cache 和 kmem_list3 结构
	sizes[INDEX_AC].cs_cachep = kmem_cache_create(names[INDEX_AC].name,
					sizes[INDEX_AC].cs_size,
					ARCH_KMALLOC_MINALIGN,
					ARCH_KMALLOC_FLAGS|SLAB_PANIC,
					NULL);

	// 如果 INDEX_AC 与 INDEX_L3 不同，也创建 L3 缓存
	if (INDEX_AC != INDEX_L3) {
		sizes[INDEX_L3].cs_cachep =
			kmem_cache_create(names[INDEX_L3].name,
				sizes[INDEX_L3].cs_size,
				ARCH_KMALLOC_MINALIGN,
				ARCH_KMALLOC_FLAGS|SLAB_PANIC,
				NULL);
	}

	slab_early_init = 0;  // slab 初始化标志

	// 为每种大小的 slab 缓存创建内存池
	while (sizes->cs_size != ULONG_MAX) {
		if (!sizes->cs_cachep) {
			sizes->cs_cachep = kmem_cache_create(names->name,
					sizes->cs_size,
					ARCH_KMALLOC_MINALIGN,
					ARCH_KMALLOC_FLAGS|SLAB_PANIC,
					NULL);
		}
#ifdef CONFIG_ZONE_DMA
		// 如果有 DMA 区域，为其创建单独的缓存
		sizes->cs_dmacachep = kmem_cache_create(
					names->name_dma,
					sizes->cs_size,
					ARCH_KMALLOC_MINALIGN,
					ARCH_KMALLOC_FLAGS|SLAB_CACHE_DMA|
						SLAB_PANIC,
					NULL);
#endif
		sizes++;
		names++;
	}

	// 第四步: 替换缓存的初始化数组
	{
		struct array_cache *ptr;

		ptr = kmalloc(sizeof(struct arraycache_init), GFP_NOWAIT);
		BUG_ON(cpu_cache_get(&cache_cache) != &initarray_cache.cache);
		memcpy(ptr, cpu_cache_get(&cache_cache),
		       sizeof(struct arraycache_init));
		spin_lock_init(&ptr->lock);
		cache_cache.array[smp_processor_id()] = ptr;

		ptr = kmalloc(sizeof(struct arraycache_init), GFP_NOWAIT);
		BUG_ON(cpu_cache_get(malloc_sizes[INDEX_AC].cs_cachep)
		       != &initarray_generic.cache);
		memcpy(ptr, cpu_cache_get(malloc_sizes[INDEX_AC].cs_cachep),
		       sizeof(struct arraycache_init));
		spin_lock_init(&ptr->lock);
		malloc_sizes[INDEX_AC].cs_cachep->array[smp_processor_id()] = ptr;
	}

	// 第五步: 替换 kmem_list3 的初始化数据
	{
		int nid;

		for_each_online_node(nid) {
			init_list(&cache_cache, &initkmem_list3[CACHE_CACHE + nid], nid);
			init_list(malloc_sizes[INDEX_AC].cs_cachep,
				  &initkmem_list3[SIZE_AC + nid], nid);

			if (INDEX_AC != INDEX_L3) {
				init_list(malloc_sizes[INDEX_L3].cs_cachep,
					  &initkmem_list3[SIZE_L3 + nid], nid);
			}
		}
	}

	// 标志 CPU 缓存已初始化
	g_cpucache_up = EARLY;
}

void __init kmem_cache_init_late(void)
{
	struct kmem_cache *cachep;

	/* 
	 * 6) 将所有 kmem_cache 的 CPU 本地缓存（head arrays）调整为最终大小。 
	 * 在早期初始化过程中，CPU缓存还未完全设置好。现在进行最终调整。
	 */
	mutex_lock(&cache_chain_mutex);  // 加锁以保护 cache 链表
	list_for_each_entry(cachep, &cache_chain, next) // 遍历所有缓存
		if (enable_cpucache(cachep, GFP_NOWAIT)) // 启用 CPU 缓存
			BUG();  // 如果启用失败，触发内核错误
	mutex_unlock(&cache_chain_mutex);  // 解锁

	/* 所有缓存的 CPU 本地缓存已经启用，标记全局状态 */
	g_cpucache_up = FULL;

	/* 
	 * 初始化 lockdep 锁定依赖检测系统的锁，以便跟踪 malloc 缓存中使用的锁。 
	 * 这是为了调试锁依赖关系，防止死锁问题。
	 */
	init_lock_keys();

	/*
	 * 注册 CPU 启动通知回调函数。当有新的 CPU 加入系统时，
	 * 这个回调函数会初始化该 CPU 的本地缓存。
	 */
	register_cpu_notifier(&cpucache_notifier);

	/*
	 * 内存回收定时器稍后会在模块初始化时启动，因为该部分内核功能尚未完全启用。
	 * 这个定时器负责定期回收不再使用的 slab 缓存。
	 */
}


static int __init cpucache_init(void)
{
	int cpu;

	/*
	 * Register the timers that return unneeded pages to the page allocator
	 */
	for_each_online_cpu(cpu)
		start_cpu_timer(cpu);
	return 0;
}
__initcall(cpucache_init);

/*
 * Interface to system's page allocator. No need to hold the cache-lock.
 * 系统页面分配器的接口。无需持有缓存锁。
 * 
 * If we requested dmaable memory, we will get it. Even if we
 * did not request dmaable memory, we might get it, but that
 * would be relatively rare and ignorable.
 * 如果我们请求了可DMA的内存，我们将得到它。
 * 即使我们没有请求DMA内存，我们也可能得到它，但这是相对罕见且可以忽略的。
 */
// 用于创建新的slab对象，一个高速缓存有多个slab，当高速缓存中slab对象用完了就需要创建新的slab对象
// 第一个参数指向需要很多页的特定高速缓存。第二个参数是内存分配标志。
// 当nodeid非负时，分配器尝试从相同的内存节点给发出的请求进行分配。
static void *kmem_getpages(struct kmem_cache *cachep, gfp_t flags, int nodeid)
{
	struct page *page;
	int nr_pages;
	int i;

#ifndef CONFIG_MMU
	/*
	 * Nommu uses slab's for process anonymous memory allocations, and thus
	 * requires __GFP_COMP to properly refcount higher order allocations
	 */
	/*
	 * Nommu 使用slab来进行进程匿名内存分配，因此需要 __GFP_COMP 来正确地引用计算更高阶的分配。
	 */
	flags |= __GFP_COMP;
#endif

	flags |= cachep->gfpflags;	// 设置标志位
	if (cachep->flags & SLAB_RECLAIM_ACCOUNT)
		flags |= __GFP_RECLAIMABLE;		// 如果标志位指示需要回收，则设置相应标志

	// 分配内存，大小为2的幂次方，存放在cachep->gfporder
	page = alloc_pages_exact_node(nodeid, flags | __GFP_NOTRACK, cachep->gfporder);
	if (!page)
		return NULL;

	nr_pages = (1 << cachep->gfporder);	// 计算页面数量
	if (cachep->flags & SLAB_RECLAIM_ACCOUNT)
		add_zone_page_state(page_zone(page),
			NR_SLAB_RECLAIMABLE, nr_pages);		// 更新页面状态
	else
		add_zone_page_state(page_zone(page),
			NR_SLAB_UNRECLAIMABLE, nr_pages);	// 更新页面状态
	for (i = 0; i < nr_pages; i++)
		__SetPageSlab(page + i);		// 设置页面为 slab

	if (kmemcheck_enabled && !(cachep->flags & SLAB_NOTRACK)) {
		kmemcheck_alloc_shadow(page, cachep->gfporder, flags, nodeid);

		if (cachep->ctor)
			kmemcheck_mark_uninitialized_pages(page, nr_pages);	// 标记未初始化的页面
		else
			kmemcheck_mark_unallocated_pages(page, nr_pages);	// 标记未分配的页面
	}

	return page_address(page);	// 返回页面地址
}

/*
 * Interface to system's page release.
 */
/*
 * 系统页面释放的接口。
 */
// 释放内存
static void kmem_freepages(struct kmem_cache *cachep, void *addr)
{
	unsigned long i = (1 << cachep->gfporder);	// 页面数量
	struct page *page = virt_to_page(addr);	// 获取页面结构指针
	const unsigned long nr_freed = i;		// 释放的页面数量

	kmemcheck_free_shadow(page, cachep->gfporder);

	if (cachep->flags & SLAB_RECLAIM_ACCOUNT)
		sub_zone_page_state(page_zone(page),
				NR_SLAB_RECLAIMABLE, nr_freed);	// 更新页面状态
	else
		sub_zone_page_state(page_zone(page),
				NR_SLAB_UNRECLAIMABLE, nr_freed);	// 更新页面状态
	while (i--) {
		BUG_ON(!PageSlab(page));	// 断言页面为 slab
		__ClearPageSlab(page);		// 清除页面的 slab 标志
		page++;	// 移动到下一个页面
	}
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += nr_freed;	// 更新当前进程的回收状态
	free_pages((unsigned long)addr, cachep->gfporder);	// 释放页面
}

static void kmem_rcu_free(struct rcu_head *head)
{
	struct slab_rcu *slab_rcu = (struct slab_rcu *)head;	// RCU slab 结构指针
	struct kmem_cache *cachep = slab_rcu->cachep;				// kmem 缓存指针

	kmem_freepages(cachep, slab_rcu->addr);		// 调用页面释放函数释放页面
	if (OFF_SLAB(cachep))
		kmem_cache_free(cachep->slabp_cache, slab_rcu);	// 如果为 OFF_SLAB，则释放缓存
}

#if DEBUG

#ifdef CONFIG_DEBUG_PAGEALLOC
static void store_stackinfo(struct kmem_cache *cachep, unsigned long *addr,
			    unsigned long caller)
{
	int size = obj_size(cachep);

	addr = (unsigned long *)&((char *)addr)[obj_offset(cachep)];

	if (size < 5 * sizeof(unsigned long))
		return;

	*addr++ = 0x12345678;
	*addr++ = caller;
	*addr++ = smp_processor_id();
	size -= 3 * sizeof(unsigned long);
	{
		unsigned long *sptr = &caller;
		unsigned long svalue;

		while (!kstack_end(sptr)) {
			svalue = *sptr++;
			if (kernel_text_address(svalue)) {
				*addr++ = svalue;
				size -= sizeof(unsigned long);
				if (size <= sizeof(unsigned long))
					break;
			}
		}

	}
	*addr++ = 0x87654321;
}
#endif

static void poison_obj(struct kmem_cache *cachep, void *addr, unsigned char val)
{
	int size = obj_size(cachep);
	addr = &((char *)addr)[obj_offset(cachep)];

	memset(addr, val, size);
	*(unsigned char *)(addr + size - 1) = POISON_END;
}

static void dump_line(char *data, int offset, int limit)
{
	int i;
	unsigned char error = 0;
	int bad_count = 0;

	printk(KERN_ERR "%03x:", offset);
	for (i = 0; i < limit; i++) {
		if (data[offset + i] != POISON_FREE) {
			error = data[offset + i];
			bad_count++;
		}
		printk(" %02x", (unsigned char)data[offset + i]);
	}
	printk("\n");

	if (bad_count == 1) {
		error ^= POISON_FREE;
		if (!(error & (error - 1))) {
			printk(KERN_ERR "Single bit error detected. Probably "
					"bad RAM.\n");
#ifdef CONFIG_X86
			printk(KERN_ERR "Run memtest86+ or a similar memory "
					"test tool.\n");
#else
			printk(KERN_ERR "Run a memory test tool.\n");
#endif
		}
	}
}
#endif

#if DEBUG

static void print_objinfo(struct kmem_cache *cachep, void *objp, int lines)
{
	int i, size;
	char *realobj;

	if (cachep->flags & SLAB_RED_ZONE) {
		printk(KERN_ERR "Redzone: 0x%llx/0x%llx.\n",
			*dbg_redzone1(cachep, objp),
			*dbg_redzone2(cachep, objp));
	}

	if (cachep->flags & SLAB_STORE_USER) {
		printk(KERN_ERR "Last user: [<%p>]",
			*dbg_userword(cachep, objp));
		print_symbol("(%s)",
				(unsigned long)*dbg_userword(cachep, objp));
		printk("\n");
	}
	realobj = (char *)objp + obj_offset(cachep);
	size = obj_size(cachep);
	for (i = 0; i < size && lines; i += 16, lines--) {
		int limit;
		limit = 16;
		if (i + limit > size)
			limit = size - i;
		dump_line(realobj, i, limit);
	}
}

static void check_poison_obj(struct kmem_cache *cachep, void *objp)
{
	char *realobj;
	int size, i;
	int lines = 0;

	realobj = (char *)objp + obj_offset(cachep);
	size = obj_size(cachep);

	for (i = 0; i < size; i++) {
		char exp = POISON_FREE;
		if (i == size - 1)
			exp = POISON_END;
		if (realobj[i] != exp) {
			int limit;
			/* Mismatch ! */
			/* Print header */
			if (lines == 0) {
				printk(KERN_ERR
					"Slab corruption: %s start=%p, len=%d\n",
					cachep->name, realobj, size);
				print_objinfo(cachep, objp, 0);
			}
			/* Hexdump the affected line */
			i = (i / 16) * 16;
			limit = 16;
			if (i + limit > size)
				limit = size - i;
			dump_line(realobj, i, limit);
			i += 16;
			lines++;
			/* Limit to 5 lines */
			if (lines > 5)
				break;
		}
	}
	if (lines != 0) {
		/* Print some data about the neighboring objects, if they
		 * exist:
		 */
		struct slab *slabp = virt_to_slab(objp);
		unsigned int objnr;

		objnr = obj_to_index(cachep, slabp, objp);
		if (objnr) {
			objp = index_to_obj(cachep, slabp, objnr - 1);
			realobj = (char *)objp + obj_offset(cachep);
			printk(KERN_ERR "Prev obj: start=%p, len=%d\n",
			       realobj, size);
			print_objinfo(cachep, objp, 2);
		}
		if (objnr + 1 < cachep->num) {
			objp = index_to_obj(cachep, slabp, objnr + 1);
			realobj = (char *)objp + obj_offset(cachep);
			printk(KERN_ERR "Next obj: start=%p, len=%d\n",
			       realobj, size);
			print_objinfo(cachep, objp, 2);
		}
	}
}
#endif

#if DEBUG
static void slab_destroy_debugcheck(struct kmem_cache *cachep, struct slab *slabp)
{
	int i;
	for (i = 0; i < cachep->num; i++) {
		void *objp = index_to_obj(cachep, slabp, i);

		if (cachep->flags & SLAB_POISON) {
#ifdef CONFIG_DEBUG_PAGEALLOC
			if (cachep->buffer_size % PAGE_SIZE == 0 &&
					OFF_SLAB(cachep))
				kernel_map_pages(virt_to_page(objp),
					cachep->buffer_size / PAGE_SIZE, 1);
			else
				check_poison_obj(cachep, objp);
#else
			check_poison_obj(cachep, objp);
#endif
		}
		if (cachep->flags & SLAB_RED_ZONE) {
			if (*dbg_redzone1(cachep, objp) != RED_INACTIVE)
				slab_error(cachep, "start of a freed object "
					   "was overwritten");
			if (*dbg_redzone2(cachep, objp) != RED_INACTIVE)
				slab_error(cachep, "end of a freed object "
					   "was overwritten");
		}
	}
}
#else
static void slab_destroy_debugcheck(struct kmem_cache *cachep, struct slab *slabp)
{
}
#endif

/**
 * slab_destroy - destroy and release all objects in a slab
 * @cachep: cache pointer being destroyed
 * @slabp: slab pointer being destroyed
 *
 * Destroy all the objs in a slab, and release the mem back to the system.
 * Before calling the slab must have been unlinked from the cache.  The
 * cache-lock is not held/needed.
 */
static void slab_destroy(struct kmem_cache *cachep, struct slab *slabp)
{
	void *addr = slabp->s_mem - slabp->colouroff;

	slab_destroy_debugcheck(cachep, slabp);
	if (unlikely(cachep->flags & SLAB_DESTROY_BY_RCU)) {
		struct slab_rcu *slab_rcu;

		slab_rcu = (struct slab_rcu *)slabp;
		slab_rcu->cachep = cachep;
		slab_rcu->addr = addr;
		call_rcu(&slab_rcu->head, kmem_rcu_free);
	} else {
		kmem_freepages(cachep, addr);
		if (OFF_SLAB(cachep))
			kmem_cache_free(cachep->slabp_cache, slabp);
	}
}

static void __kmem_cache_destroy(struct kmem_cache *cachep)
{
	int i;
	struct kmem_list3 *l3;

	for_each_online_cpu(i)
	    kfree(cachep->array[i]);

	/* NUMA: free the list3 structures */
	for_each_online_node(i) {
		l3 = cachep->nodelists[i];
		if (l3) {
			kfree(l3->shared);
			free_alien_cache(l3->alien);
			kfree(l3);
		}
	}
	kmem_cache_free(&cache_cache, cachep);
}


/**
 * calculate_slab_order - calculate size (page order) of slabs
 * @cachep: pointer to the cache that is being created
 * @size: size of objects to be created in this cache.
 * @align: required alignment for the objects.
 * @flags: slab allocation flags
 *
 * Also calculates the number of objects per slab.
 *
 * This could be made much more intelligent.  For now, try to avoid using
 * high order pages for slabs.  When the gfp() functions are more friendly
 * towards high-order requests, this should be changed.
 */
static size_t calculate_slab_order(struct kmem_cache *cachep,
			size_t size, size_t align, unsigned long flags)
{
	unsigned long offslab_limit;  // 用于确定 off-slab 缓存的限制
	size_t left_over = 0;         // 剩余的碎片大小
	int gfporder;                 // 用于 slab 分配的页数的阶数

	// 循环遍历不同阶数的页分配，直到找到合适的 slab 配置
	for (gfporder = 0; gfporder <= KMALLOC_MAX_ORDER; gfporder++) {
		unsigned int num;   // 当前阶数下可分配的对象数量
		size_t remainder;   // 当前阶数下的剩余碎片空间

		// 估算当前阶数下 slab 中的对象数和剩余碎片
		cache_estimate(gfporder, size, align, flags, &remainder, &num);
		
		// 如果没有可分配的对象，继续尝试下一个阶数
		if (!num)
			continue;

		// 如果使用 off-slab 缓存方式，计算最大允许的对象数
		if (flags & CFLGS_OFF_SLAB) {
			/*
			 * 使用 off-slab slab 的缓存对象数上限。
			 * 避免在 cache_grow() 中出现无限循环的情况。
			 */
			offslab_limit = size - sizeof(struct slab);
			offslab_limit /= sizeof(kmem_bufctl_t);

			// 如果对象数超出 off-slab 限制，跳出循环
			if (num > offslab_limit)
				break;
		}

		// 找到符合要求的配置，记录可分配对象数和阶数
		cachep->num = num;
		cachep->gfporder = gfporder;
		left_over = remainder;  // 记录当前阶数下的剩余碎片

		/*
		 * 对于 VFS 可回收的 slab，大多数分配是使用 GFP_NOFS，
		 * 我们不希望在无法缩小 dcache 时分配更高阶的页。
		 */
		if (flags & SLAB_RECLAIM_ACCOUNT)
			break;

		/*
		 * 虽然对象数越多越好，但非常大的 slab 对 gfp() 调用
		 * 会带来不利影响，因此我们限制 gfporder。
		 */
		if (gfporder >= slab_break_gfp_order)
			break;

		/*
		 * 判断内部碎片是否可以接受。如果剩余碎片占的比例较小，
		 * 则认为该配置是合适的，终止循环。
		 */
		if (left_over * 8 <= (PAGE_SIZE << gfporder))
			break;
	}
	
	// 返回最后的剩余碎片大小
	return left_over;
}

static int __init_refok setup_cpu_cache(struct kmem_cache *cachep, gfp_t gfp)
{
	// 如果 CPU 缓存系统已经完全启用，直接启用指定缓存的 CPU 缓存功能
	if (g_cpucache_up == FULL)
		return enable_cpucache(cachep, gfp);

	// 如果 CPU 缓存系统尚未启用，进行初始化
	if (g_cpucache_up == NONE) {
		/*
		 * 注意：第一个 kmem_cache_create 必须创建 kmalloc(24) 使用的缓存，
		 * 否则创建其他缓存时会触发 BUG。
		 */
		cachep->array[smp_processor_id()] = &initarray_generic.cache;

		/*
		 * 如果第一个被创建的缓存用于 kmalloc(sizeof(kmem_list3))，
		 * 则需要初始化它的所有 kmem_list3 结构，否则会触发 BUG。
		 */
		set_up_list3s(cachep, SIZE_AC);  // 设置大小为 SIZE_AC 的 kmem_list3

		// 根据缓存设置不同的状态
		if (INDEX_AC == INDEX_L3)
			g_cpucache_up = PARTIAL_L3;
		else
			g_cpucache_up = PARTIAL_AC;
	} else {
		// 如果不是首次创建，则为当前处理器分配 array 缓存
		cachep->array[smp_processor_id()] =
			kmalloc(sizeof(struct arraycache_init), gfp);

		// 如果缓存状态为 PARTIAL_AC，继续设置 list3s，并更新状态
		if (g_cpucache_up == PARTIAL_AC) {
			set_up_list3s(cachep, SIZE_L3);  // 设置大小为 SIZE_L3 的 kmem_list3
			g_cpucache_up = PARTIAL_L3;
		} else {
			// 如果 CPU 缓存系统处于部分启用状态，为每个在线的 NUMA 节点分配 kmem_list3
			int node;
			for_each_online_node(node) {
				// 为每个 NUMA 节点分配 kmem_list3 结构，并进行初始化
				cachep->nodelists[node] =
				    kmalloc_node(sizeof(struct kmem_list3),
						gfp, node);
				BUG_ON(!cachep->nodelists[node]);  // 如果分配失败，则触发 BUG
				kmem_list3_init(cachep->nodelists[node]);  // 初始化 kmem_list3 结构
			}
		}
	}

	// 设置当前 NUMA 节点上 kmem_list3 结构的再收割时间
	cachep->nodelists[numa_node_id()]->next_reap =
			jiffies + REAPTIMEOUT_LIST3 +
			((unsigned long)cachep) % REAPTIMEOUT_LIST3;

	// 初始化 CPU 缓存的可用对象、限制和批处理计数等参数
	cpu_cache_get(cachep)->avail = 0;  // 设置 CPU 缓存的可用对象为 0
	cpu_cache_get(cachep)->limit = BOOT_CPUCACHE_ENTRIES;  // 设置可分配的最大条目数
	cpu_cache_get(cachep)->batchcount = 1;  // 设置批处理的数量
	cpu_cache_get(cachep)->touched = 0;  // 初始化 touched 标记
	cachep->batchcount = 1;  // 设置缓存批处理数量
	cachep->limit = BOOT_CPUCACHE_ENTRIES;  // 设置缓存的最大条目数
	return 0;
}

/**
 * kmem_cache_create - Create a cache.
 * @name: A string which is used in /proc/slabinfo to identify this cache.
 * @size: The size of objects to be created in this cache.
 * @align: The required alignment for the objects.
 * @flags: SLAB flags
 * @ctor: A constructor for the objects.
 *
 * Returns a ptr to the cache on success, NULL on failure.
 * Cannot be called within a int, but can be interrupted.
 * The @ctor is run when new pages are allocated by the cache.
 *
 * @name must be valid until the cache is destroyed. This implies that
 * the module calling this has to destroy the cache before getting unloaded.
 * Note that kmem_cache_name() is not guaranteed to return the same pointer,
 * therefore applications must manage it themselves.
 *
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialised memory.
 *
 * %SLAB_RED_ZONE - Insert `Red' zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline.  This can be beneficial if you're counting cycles as closely
 * as davem.
 */
/**
 * kmem_cache_create - 创建一个缓存。
 * @name: 在 /proc/slabinfo 中用来识别此缓存的字符串。
 * @size: 将在此缓存中创建的对象的大小。
 * @align: 对象所需的对齐。
 * @flags: SLAB标志。
 * @ctor: 对象的构造器。
 *
 * 成功时返回指向缓存的指针，失败时返回NULL。
 * 不能在中断内调用，但可以被中断。
 * @ctor 在缓存分配新页面时运行。
 *
 * @name 必须在缓存被销毁之前有效。这意味着调用此函数的模块必须在卸载前销毁缓存。
 * 注意 kmem_cache_name() 不保证返回相同的指针，因此应用程序必须自行管理它。
 *
 * 标志有：
 *
 * %SLAB_POISON - 用已知测试模式(a5a5a5a5)填充slab，以捕获对未初始化内存的引用。
 *
 * %SLAB_RED_ZONE - 在分配的内存周围插入`红区`来检查缓冲区溢出。
 *
 * %SLAB_HWCACHE_ALIGN - 将此缓存中的对象对齐到硬件缓存行。如果你像davem那样仔细计算周期，这可能有益。
 */
// 函数用于创建一个新的slab缓存。第一个参数是字符串，存放高速缓存的名字，第二个参数是高速缓存中每个元素的大小，
// 第三个参数是slab内第一个对象的偏移，用来确保在页内进行特定的对齐。通常0就可以满足，也就是标准对齐。
// flags参数是可选的设置项，用来控制高速缓存的行为。可以为0,表示没有特殊行为，或者与以下标志进行或运算，在slab.h中存在定义
// SLAB_HWCACHE_ALIGN
// SLAB_POISON
// SLAB_RED_ZONE
// SLAB_PANIC
// SLAB_CACHE_DMA
// 最后一个参数ctor是高速缓存的构造函数。只有在新的页主加到高速缓存，构造函数才被调用。实际上Linux内核的高速缓存不适用构造函数，赋值为NULL即可。
// 函数成功时返回一个指向所创建的高速缓存的指针，否则返回NULL。该函数可能睡眠，不应在中断上下文调用。
struct kmem_cache *kmem_cache_create (const char *name, size_t size, size_t align,
    unsigned long flags, void (*ctor)(void *)) {
    size_t left_over, slab_size, ralign;  // 定义临时变量以存储对齐方式、剩余大小和slab大小
    struct kmem_cache *cachep = NULL, *pc;  // 定义kmem_cache结构指针用于管理缓存
    gfp_t gfp;  // 用于分配内存的标志位

    /*
     * 健全性检查，确保传入参数有效并且满足要求。如果不满足，记录错误并触发BUG
     */
    if (!name || in_interrupt() || (size < BYTES_PER_WORD) ||
        size > KMALLOC_MAX_SIZE) {
        printk(KERN_ERR "%s: Early error in slab %s\n", __func__, name);
        BUG();  // 触发内核BUG，停止执行
    }

    /*
     * 使用 cache_chain_mutex 来确保对 CPU在线掩码(cpu_online_mask)的一致访问
     */
    if (slab_is_available()) {
        get_online_cpus();  // 获取当前在线的CPU
        mutex_lock(&cache_chain_mutex);  // 锁定缓存链表的互斥锁
    }

    /*
     * 遍历 cache_chain 链表，检查是否已存在同名的缓存。如果是，打印错误并输出调用堆栈
     */
    list_for_each_entry(pc, &cache_chain, next) {
        char tmp;
        int res;

        // 检查内核地址中的缓存名是否有效
        res = probe_kernel_address(pc->name, tmp);
        if (res) {
            printk(KERN_ERR "SLAB: cache with size %d has lost its name\n",
                   pc->buffer_size);
            continue;  // 如果无效，继续遍历
        }

        // 如果找到同名缓存，打印错误并显示调用堆栈
        if (!strcmp(pc->name, name)) {
            printk(KERN_ERR "kmem_cache_create: duplicate cache %s\n", name);
            dump_stack();
            goto oops;  // 错误跳转
        }
    }

#if DEBUG
    // 警告缓存名中存在空格
    WARN_ON(strchr(name, ' '));
#endif

    /*
     * 检查并确保传入的flags是合法的
     */
    BUG_ON(flags & ~CREATE_MASK);

    /*
     * 对齐缓存对象的大小，以确保避免未对齐的内存访问
     */
    if (size & (BYTES_PER_WORD - 1)) {
        size += (BYTES_PER_WORD - 1);  // 增加至下一个字对齐边界
        size &= ~(BYTES_PER_WORD - 1);  // 清除非对齐部分
    }

    /* 
     * 计算最终的对齐方式，根据体系结构建议或用户指定的方式来调整
     */
    if (flags & SLAB_HWCACHE_ALIGN) {
        ralign = cache_line_size();  // 获取硬件缓存行的大小
        while (size <= ralign / 2)  // 确保缓存行中不浪费空间
            ralign /= 2;
    } else {
        ralign = BYTES_PER_WORD;  // 使用最小的字对齐
    }

    /* 
     * 如果启用调试选项，强制字对齐
     */
    if (flags & SLAB_STORE_USER)
        ralign = BYTES_PER_WORD;

    if (flags & SLAB_RED_ZONE) {
        ralign = REDZONE_ALIGN;  // 如果启用Redzone调试，强制使用Redzone对齐
        size += REDZONE_ALIGN - 1;
        size &= ~(REDZONE_ALIGN - 1);
    }

    // 保证对齐值不小于架构要求的最小对齐
    if (ralign < ARCH_SLAB_MINALIGN)
        ralign = ARCH_SLAB_MINALIGN;
    
    // 保证对齐值不小于用户指定的对齐
    if (ralign < align)
        ralign = align;

    // 如果对齐方式过大，禁用调试选项
    if (ralign > __alignof__(unsigned long long))
        flags &= ~(SLAB_RED_ZONE | SLAB_STORE_USER);

    align = ralign;  // 保存最终的对齐值

    /*
     * 根据slab是否可用来选择合适的内存分配标志
     */
    if (slab_is_available())
        gfp = GFP_KERNEL;
    else
        gfp = GFP_NOWAIT;

    /*
     * 分配缓存管理结构 kmem_cache
     */
    cachep = kmem_cache_zalloc(&cache_cache, gfp);
    if (!cachep)
        goto oops;  // 如果分配失败，跳转到错误处理

#if DEBUG
    // 设置缓存对象的大小
    cachep->obj_size = size;
#endif

    /*
     * 根据对象的大小和slab的初始化状态，确定slab管理是在slab上还是slab外
     */
    if ((size >= (PAGE_SIZE >> 3)) && !slab_early_init &&
        !(flags & SLAB_NOLEAKTRACE))
        flags |= CFLGS_OFF_SLAB;  // 如果对象较大，使用slab外管理

    size = ALIGN(size, align);  // 确保缓存对象对齐

    /*
     * 计算 slab order（页框数量），并根据对象大小调整slab管理
     */
    left_over = calculate_slab_order(cachep, size, align, flags);

    if (!cachep->num) {
        printk(KERN_ERR "kmem_cache_create: couldn't create cache %s.\n", name);
        kmem_cache_free(&cache_cache, cachep);
        cachep = NULL;
        goto oops;
    }

    slab_size = ALIGN(cachep->num * sizeof(kmem_bufctl_t) + sizeof(struct slab), align);

    /*
     * 检查slab是否可以移动到slab上管理（以提高空间利用率）
     */
    if (flags & CFLGS_OFF_SLAB && left_over >= slab_size) {
        flags &= ~CFLGS_OFF_SLAB;  // 取消slab外管理
        left_over -= slab_size;  // 调整剩余空间
    }

    /*
     * 如果启用了slab外管理，确保其空间和结构大小合适
     */
    if (flags & CFLGS_OFF_SLAB) {
        slab_size = cachep->num * sizeof(kmem_bufctl_t) + sizeof(struct slab);
    }

    cachep->colour_off = cache_line_size();  // 计算缓存的颜色偏移量
    if (cachep->colour_off < align)
        cachep->colour_off = align;

    cachep->colour = left_over / cachep->colour_off;  // 计算可用的颜色数量
    cachep->slab_size = slab_size;  // 设置slab大小
    cachep->flags = flags;  // 设置缓存的标志
    cachep->buffer_size = size;  // 设置缓存的缓冲区大小

    /*
     * 如果缓存使用slab外管理，寻找通用的slab缓存
     */
    if (flags & CFLGS_OFF_SLAB) {
        cachep->slabp_cache = kmem_find_general_cachep(slab_size, 0u);
        BUG_ON(ZERO_OR_NULL_PTR(cachep->slabp_cache));  // 确保缓存有效
    }

    cachep->ctor = ctor;  // 设置构造函数
    cachep->name = name;  // 设置缓存名称

    /*
     * 初始化每个 CPU 的缓存
     */
    if (setup_cpu_cache(cachep, gfp)) {
        __kmem_cache_destroy(cachep);  // 销毁缓存
        cachep = NULL;
        goto oops;
    }

    /*
     * 将缓存添加到链表中
     */
    list_add(&cachep->next, &cache_chain);
oops:
    /*
     * 如果缓存创建失败且设置了 SLAB_PANIC 标志，触发 panic
     */
    if (!cachep && (flags & SLAB_PANIC))
        panic("kmem_cache_create(): failed to create slab `%s'\n", name);

    /*
     * 解锁缓存链表并释放在线CPU的引用
     */
    if (slab_is_available()) {
        mutex_unlock(&cache_chain_mutex);
        put_online_cpus();
    }

    return cachep;  // 返回创建的缓存
}

EXPORT_SYMBOL(kmem_cache_create);

#if DEBUG
static void check_irq_off(void)
{
	BUG_ON(!irqs_disabled());
}

static void check_irq_on(void)
{
	BUG_ON(irqs_disabled());
}

static void check_spinlock_acquired(struct kmem_cache *cachep)
{
#ifdef CONFIG_SMP
	check_irq_off();
	assert_spin_locked(&cachep->nodelists[numa_node_id()]->list_lock);
#endif
}

static void check_spinlock_acquired_node(struct kmem_cache *cachep, int node)
{
#ifdef CONFIG_SMP
	check_irq_off();
	assert_spin_locked(&cachep->nodelists[node]->list_lock);
#endif
}

#else
#define check_irq_off()	do { } while(0)
#define check_irq_on()	do { } while(0)
#define check_spinlock_acquired(x) do { } while(0)
#define check_spinlock_acquired_node(x, y) do { } while(0)
#endif

static void drain_array(struct kmem_cache *cachep, struct kmem_list3 *l3,
			struct array_cache *ac,
			int force, int node);

static void do_drain(void *arg)
{
	struct kmem_cache *cachep = arg;
	struct array_cache *ac;
	int node = numa_node_id();

	check_irq_off();
	ac = cpu_cache_get(cachep);
	spin_lock(&cachep->nodelists[node]->list_lock);
	free_block(cachep, ac->entry, ac->avail, node);
	spin_unlock(&cachep->nodelists[node]->list_lock);
	ac->avail = 0;
}

static void drain_cpu_caches(struct kmem_cache *cachep)
{
	struct kmem_list3 *l3;
	int node;

	on_each_cpu(do_drain, cachep, 1);
	check_irq_on();
	for_each_online_node(node) {
		l3 = cachep->nodelists[node];
		if (l3 && l3->alien)
			drain_alien_cache(cachep, l3->alien);
	}

	for_each_online_node(node) {
		l3 = cachep->nodelists[node];
		if (l3)
			drain_array(cachep, l3, l3->shared, 1, node);
	}
}

/*
 * Remove slabs from the list of free slabs.
 * Specify the number of slabs to drain in tofree.
 *
 * Returns the actual number of slabs released.
 */
static int drain_freelist(struct kmem_cache *cache,
			struct kmem_list3 *l3, int tofree)
{
	struct list_head *p;
	int nr_freed;
	struct slab *slabp;

	nr_freed = 0;
	while (nr_freed < tofree && !list_empty(&l3->slabs_free)) {

		spin_lock_irq(&l3->list_lock);
		p = l3->slabs_free.prev;
		if (p == &l3->slabs_free) {
			spin_unlock_irq(&l3->list_lock);
			goto out;
		}

		slabp = list_entry(p, struct slab, list);
#if DEBUG
		BUG_ON(slabp->inuse);
#endif
		list_del(&slabp->list);
		/*
		 * Safe to drop the lock. The slab is no longer linked
		 * to the cache.
		 */
		l3->free_objects -= cache->num;
		spin_unlock_irq(&l3->list_lock);
		slab_destroy(cache, slabp);
		nr_freed++;
	}
out:
	return nr_freed;
}

/* Called with cache_chain_mutex held to protect against cpu hotplug */
static int __cache_shrink(struct kmem_cache *cachep)
{
	int ret = 0, i = 0;
	struct kmem_list3 *l3;

	drain_cpu_caches(cachep);

	check_irq_on();
	for_each_online_node(i) {
		l3 = cachep->nodelists[i];
		if (!l3)
			continue;

		drain_freelist(cachep, l3, l3->free_objects);

		ret += !list_empty(&l3->slabs_full) ||
			!list_empty(&l3->slabs_partial);
	}
	return (ret ? 1 : 0);
}

/**
 * kmem_cache_shrink - Shrink a cache.
 * @cachep: The cache to shrink.
 *
 * Releases as many slabs as possible for a cache.
 * To help debugging, a zero exit status indicates all slabs were released.
 */
int kmem_cache_shrink(struct kmem_cache *cachep)
{
	int ret;
	BUG_ON(!cachep || in_interrupt());

	get_online_cpus();
	mutex_lock(&cache_chain_mutex);
	ret = __cache_shrink(cachep);
	mutex_unlock(&cache_chain_mutex);
	put_online_cpus();
	return ret;
}
EXPORT_SYMBOL(kmem_cache_shrink);

/**
 * kmem_cache_destroy - delete a cache
 * @cachep: the cache to destroy
 *
 * Remove a &struct kmem_cache object from the slab cache.
 *
 * It is expected this function will be called by a module when it is
 * unloaded.  This will remove the cache completely, and avoid a duplicate
 * cache being allocated each time a module is loaded and unloaded, if the
 * module doesn't have persistent in-kernel storage across loads and unloads.
 *
 * The cache must be empty before calling this function.
 *
 * The caller must guarantee that noone will allocate memory from the cache
 * during the kmem_cache_destroy().
 */
// 撤销一个给定高速缓存。该函数不能在中断中调用，因为可能睡眠。该函数调用需要两个条件：
// 1.高速缓存中所有slab都为空。
// 2.在调用kmem_cache_destroy()过程中（后）不再访问这个高速缓存。
// 成功返回0,否则返回非0。
void kmem_cache_destroy(struct kmem_cache *cachep)
{
	BUG_ON(!cachep || in_interrupt());

	/* Find the cache in the chain of caches. */
	get_online_cpus();
	mutex_lock(&cache_chain_mutex);
	/*
	 * the chain is never empty, cache_cache is never destroyed
	 */
	list_del(&cachep->next);
	if (__cache_shrink(cachep)) {
		slab_error(cachep, "Can't free all objects");
		list_add(&cachep->next, &cache_chain);
		mutex_unlock(&cache_chain_mutex);
		put_online_cpus();
		return;
	}

	if (unlikely(cachep->flags & SLAB_DESTROY_BY_RCU))
		rcu_barrier();

	__kmem_cache_destroy(cachep);
	mutex_unlock(&cache_chain_mutex);
	put_online_cpus();
}
EXPORT_SYMBOL(kmem_cache_destroy);

/*
 * Get the memory for a slab management obj.
 * For a slab cache when the slab descriptor is off-slab, slab descriptors
 * always come from malloc_sizes caches.  The slab descriptor cannot
 * come from the same cache which is getting created because,
 * when we are searching for an appropriate cache for these
 * descriptors in kmem_cache_create, we search through the malloc_sizes array.
 * If we are creating a malloc_sizes cache here it would not be visible to
 * kmem_find_general_cachep till the initialization is complete.
 * Hence we cannot have slabp_cache same as the original cache.
 */
static struct slab *alloc_slabmgmt(struct kmem_cache *cachep, void *objp,
				   int colour_off, gfp_t local_flags,
				   int nodeid)
{
	struct slab *slabp;  // slab 管理结构指针

	// 判断 slab 管理结构是否是在 slab 之外分配（off-slab）
	if (OFF_SLAB(cachep)) {
		/* Slab management obj is off-slab. */
		// 如果 slab 管理结构是 off-slab，则从 slabp_cache 中分配管理对象
		slabp = kmem_cache_alloc_node(cachep->slabp_cache,
					      local_flags, nodeid);
		/*
		 * 如果 slab 的第一个对象泄漏（分配了但没有引用），我们需要确保
		 * kmemleak 不会将 ->s_mem 指针视为该对象的引用，否则泄漏不会被报告。
		 * 因此，使用 kmemleak_scan_area 对 slab 的管理结构进行扫描。
		 */
		kmemleak_scan_area(&slabp->list, sizeof(struct list_head),
				   local_flags);

		// 如果 slab 管理结构分配失败，返回 NULL
		if (!slabp)
			return NULL;
	} else {
		// slab 管理结构在 slab 内部分配（on-slab）
		// 在 slab 中，管理结构位于 objp 起始位置之后的 colour_off 偏移处
		slabp = objp + colour_off;

		// 计算新的 colour_off，将 slab 大小加到偏移量上
		colour_off += cachep->slab_size;
	}

	// 初始化 slab 管理结构的字段
	slabp->inuse = 0;  // 初始化 inuse 表示 slab 中当前没有使用的对象
	slabp->colouroff = colour_off;  // 设置 slab 的颜色偏移量
	slabp->s_mem = objp + colour_off;  // s_mem 指向 slab 中第一个对象的起始地址
	slabp->nodeid = nodeid;  // 记录 slab 所属的 NUMA 节点
	slabp->free = 0;  // 初始化 free 字段为 0，表示所有对象都是空闲的

	// 返回初始化后的 slab 管理结构
	return slabp;
}

static inline kmem_bufctl_t *slab_bufctl(struct slab *slabp)
{
	return (kmem_bufctl_t *) (slabp + 1);
}

static void cache_init_objs(struct kmem_cache *cachep,
			    struct slab *slabp)
{
	int i;

	for (i = 0; i < cachep->num; i++) {
		void *objp = index_to_obj(cachep, slabp, i);
#if DEBUG
		/* need to poison the objs? */
		if (cachep->flags & SLAB_POISON)
			poison_obj(cachep, objp, POISON_FREE);
		if (cachep->flags & SLAB_STORE_USER)
			*dbg_userword(cachep, objp) = NULL;

		if (cachep->flags & SLAB_RED_ZONE) {
			*dbg_redzone1(cachep, objp) = RED_INACTIVE;
			*dbg_redzone2(cachep, objp) = RED_INACTIVE;
		}
		/*
		 * Constructors are not allowed to allocate memory from the same
		 * cache which they are a constructor for.  Otherwise, deadlock.
		 * They must also be threaded.
		 */
		if (cachep->ctor && !(cachep->flags & SLAB_POISON))
			cachep->ctor(objp + obj_offset(cachep));

		if (cachep->flags & SLAB_RED_ZONE) {
			if (*dbg_redzone2(cachep, objp) != RED_INACTIVE)
				slab_error(cachep, "constructor overwrote the"
					   " end of an object");
			if (*dbg_redzone1(cachep, objp) != RED_INACTIVE)
				slab_error(cachep, "constructor overwrote the"
					   " start of an object");
		}
		if ((cachep->buffer_size % PAGE_SIZE) == 0 &&
			    OFF_SLAB(cachep) && cachep->flags & SLAB_POISON)
			kernel_map_pages(virt_to_page(objp),
					 cachep->buffer_size / PAGE_SIZE, 0);
#else
		if (cachep->ctor)
			cachep->ctor(objp);
#endif
		slab_bufctl(slabp)[i] = i + 1;
	}
	slab_bufctl(slabp)[i - 1] = BUFCTL_END;
}

static void kmem_flagcheck(struct kmem_cache *cachep, gfp_t flags)
{
	if (CONFIG_ZONE_DMA_FLAG) {
		if (flags & GFP_DMA)
			BUG_ON(!(cachep->gfpflags & GFP_DMA));
		else
			BUG_ON(cachep->gfpflags & GFP_DMA);
	}
}

/**
 * slab_get_obj - 从 slab 中获取一个对象
 * @cachep: 指向 kmem_cache 结构体的指针，表示 slab 缓存的信息
 * @slabp: 指向 slab 结构体的指针，表示当前的 slab
 * @nodeid: NUMA 节点 ID，用于验证 slab 所属的节点
 *
 * 该函数从给定的 slab 中分配一个对象，并更新 slab 的状态以反映分配的变化。
 */
static void *slab_get_obj(struct kmem_cache *cachep, struct slab *slabp, int nodeid)
{
    // 从 slab 的 free 链表中获取一个空闲对象的指针
    void *objp = index_to_obj(cachep, slabp, slabp->free);
    kmem_bufctl_t next;

    // 增加 slab 中正在使用的对象计数
    slabp->inuse++;

    // 获取下一个空闲对象的索引
    next = slab_bufctl(slabp)[slabp->free];

#if DEBUG
    // 在调试模式下，将当前对象标记为已分配，并检查节点 ID 是否匹配
    slab_bufctl(slabp)[slabp->free] = BUFCTL_FREE;
    WARN_ON(slabp->nodeid != nodeid);  // 如果 slab 的 nodeid 不匹配则发出警告
#endif

    // 更新 slab 的 free 指针，指向下一个空闲对象
    slabp->free = next;

    // 返回分配的对象指针
    return objp;
}

static void slab_put_obj(struct kmem_cache *cachep, struct slab *slabp,
				void *objp, int nodeid)
{
	unsigned int objnr = obj_to_index(cachep, slabp, objp);

#if DEBUG
	/* Verify that the slab belongs to the intended node */
	WARN_ON(slabp->nodeid != nodeid);

	if (slab_bufctl(slabp)[objnr] + 1 <= SLAB_LIMIT + 1) {
		printk(KERN_ERR "slab: double free detected in cache "
				"'%s', objp %p\n", cachep->name, objp);
		BUG();
	}
#endif
	slab_bufctl(slabp)[objnr] = slabp->free;
	slabp->free = objnr;
	slabp->inuse--;
}

/*
 * Map pages beginning at addr to the given cache and slab. This is required
 * for the slab allocator to be able to lookup the cache and slab of a
 * virtual address for kfree, ksize, kmem_ptr_validate, and slab debugging.
 */
static void slab_map_pages(struct kmem_cache *cache, struct slab *slab,
			   void *addr)
{
	int nr_pages;
	struct page *page;

	page = virt_to_page(addr);

	nr_pages = 1;
	if (likely(!PageCompound(page)))
		nr_pages <<= cache->gfporder;

	do {
		page_set_cache(page, cache);
		page_set_slab(page, slab);
		page++;
	} while (--nr_pages);
}

/*
 * Grow (by 1) the number of slabs within a cache.  This is called by
 * kmem_cache_alloc() when there are no active objs left in a cache.
 */
static int cache_grow(struct kmem_cache *cachep,
		gfp_t flags, int nodeid, void *objp)
{
	struct slab *slabp;  // slab 结构指针，用于管理分配的 slab
	size_t offset;  // slab 颜色的偏移量
	gfp_t local_flags;  // 分配标志，局部变量
	struct kmem_list3 *l3;  // 指向 kmem_list3 结构的指针，该结构管理 slab 列表

	/*
	 * 检查传递的 flags 是否包含非法的 GFP 标志。
	 * 这个检查只在这里进行，避免在 kmem_cache_alloc() 的关键路径中影响性能。
	 */
	BUG_ON(flags & GFP_SLAB_BUG_MASK);

	// 从传递的 flags 中提取约束和回收标志
	local_flags = flags & (GFP_CONSTRAINT_MASK | GFP_RECLAIM_MASK);

	/* 
	 * 获取对应节点的 l3（slab 管理器）列表锁以修改该节点的颜色索引。
	 * 颜色用于减少 CPU 缓存冲突，通过 offset 实现不同的 slab 颜色。
	 */
	check_irq_off();
	l3 = cachep->nodelists[nodeid];
	spin_lock(&l3->list_lock);

	// 获取下一个 slab 的颜色偏移值
	offset = l3->colour_next;
	l3->colour_next++;

	// 如果颜色索引达到上限，则循环重置为 0
	if (l3->colour_next >= cachep->colour)
		l3->colour_next = 0;

	// 释放 l3 列表锁
	spin_unlock(&l3->list_lock);

	// 计算 slab 的颜色偏移
	offset *= cachep->colour_off;

	// 如果可以等待分配（__GFP_WAIT 设置），重新启用本地中断
	if (local_flags & __GFP_WAIT)
		local_irq_enable();

	/*
	 * 检查分配标志是否有效。这个检查在此进行而不是 kmem_cache_alloc() 中，
	 * 这样可以减少关键路径的长度。如果调用者标志无效，会在此捕获。
	 */
	kmem_flagcheck(cachep, flags);

	/*
	 * 分配用于存放对象的内存页，尝试从指定的 nodeid 分配物理页。
	 * 如果没有传递 objp（外部指定的内存），则调用 kmem_getpages() 从内存中获取。
	 */
	if (!objp)
		objp = kmem_getpages(cachep, local_flags, nodeid);
	
	// 如果获取内存页失败，则跳转到 failed 处理
	if (!objp)
		goto failed;

	/* 分配 slab 管理结构，初始化 slab 管理结构的信息 */
        slabp = alloc_slabmgmt(cachep, objp, offset,
                               local_flags & ~GFP_CONSTRAINT_MASK, nodeid);

        // 如果 slab 管理结构分配失败，跳转到 opps1 处理
	if (!slabp)
		goto opps1;

	// 将 slab 中的页面映射为可用对象
	slab_map_pages(cachep, slabp, objp);

	// 初始化 slab 中的对象
	cache_init_objs(cachep, slabp);

	// 如果 __GFP_WAIT 设置，禁用本地中断
	if (local_flags & __GFP_WAIT)
		local_irq_disable();

	check_irq_off();  // 确认中断已禁用
	spin_lock(&l3->list_lock);  // 获取 l3 列表锁以修改 slab 列表

	/* 将 slab 加入空闲 slab 列表 */
	list_add_tail(&slabp->list, &(l3->slabs_free));

	// 增加增长统计计数
	STATS_INC_GROWN(cachep);

	// 更新节点中的空闲对象计数
	l3->free_objects += cachep->num;

	// 释放 l3 列表锁
	spin_unlock(&l3->list_lock);

	// slab 成功分配，返回 1 表示成功
	return 1;

opps1:
	// 如果分配 slab 管理结构失败，释放之前分配的内存页
	kmem_freepages(cachep, objp);

failed:
	// 如果分配失败并且设置了 __GFP_WAIT，则禁用中断
	if (local_flags & __GFP_WAIT)
		local_irq_disable();

	// 返回 0 表示分配失败
	return 0;
}

#if DEBUG

/*
 * Perform extra freeing checks:
 * - detect bad pointers.
 * - POISON/RED_ZONE checking
 */
static void kfree_debugcheck(const void *objp)
{
	if (!virt_addr_valid(objp)) {
		printk(KERN_ERR "kfree_debugcheck: out of range ptr %lxh.\n",
		       (unsigned long)objp);
		BUG();
	}
}

static inline void verify_redzone_free(struct kmem_cache *cache, void *obj)
{
	unsigned long long redzone1, redzone2;

	redzone1 = *dbg_redzone1(cache, obj);
	redzone2 = *dbg_redzone2(cache, obj);

	/*
	 * Redzone is ok.
	 */
	if (redzone1 == RED_ACTIVE && redzone2 == RED_ACTIVE)
		return;

	if (redzone1 == RED_INACTIVE && redzone2 == RED_INACTIVE)
		slab_error(cache, "double free detected");
	else
		slab_error(cache, "memory outside object was overwritten");

	printk(KERN_ERR "%p: redzone 1:0x%llx, redzone 2:0x%llx.\n",
			obj, redzone1, redzone2);
}

static void *cache_free_debugcheck(struct kmem_cache *cachep, void *objp,
				   void *caller)
{
	struct page *page;
	unsigned int objnr;
	struct slab *slabp;

	BUG_ON(virt_to_cache(objp) != cachep);

	objp -= obj_offset(cachep);
	kfree_debugcheck(objp);
	page = virt_to_head_page(objp);

	slabp = page_get_slab(page);

	if (cachep->flags & SLAB_RED_ZONE) {
		verify_redzone_free(cachep, objp);
		*dbg_redzone1(cachep, objp) = RED_INACTIVE;
		*dbg_redzone2(cachep, objp) = RED_INACTIVE;
	}
	if (cachep->flags & SLAB_STORE_USER)
		*dbg_userword(cachep, objp) = caller;

	objnr = obj_to_index(cachep, slabp, objp);

	BUG_ON(objnr >= cachep->num);
	BUG_ON(objp != index_to_obj(cachep, slabp, objnr));

#ifdef CONFIG_DEBUG_SLAB_LEAK
	slab_bufctl(slabp)[objnr] = BUFCTL_FREE;
#endif
	if (cachep->flags & SLAB_POISON) {
#ifdef CONFIG_DEBUG_PAGEALLOC
		if ((cachep->buffer_size % PAGE_SIZE)==0 && OFF_SLAB(cachep)) {
			store_stackinfo(cachep, objp, (unsigned long)caller);
			kernel_map_pages(virt_to_page(objp),
					 cachep->buffer_size / PAGE_SIZE, 0);
		} else {
			poison_obj(cachep, objp, POISON_FREE);
		}
#else
		poison_obj(cachep, objp, POISON_FREE);
#endif
	}
	return objp;
}

static void check_slabp(struct kmem_cache *cachep, struct slab *slabp)
{
	kmem_bufctl_t i;
	int entries = 0;

	/* Check slab's freelist to see if this obj is there. */
	for (i = slabp->free; i != BUFCTL_END; i = slab_bufctl(slabp)[i]) {
		entries++;
		if (entries > cachep->num || i >= cachep->num)
			goto bad;
	}
	if (entries != cachep->num - slabp->inuse) {
bad:
		printk(KERN_ERR "slab: Internal list corruption detected in "
				"cache '%s'(%d), slabp %p(%d). Hexdump:\n",
			cachep->name, cachep->num, slabp, slabp->inuse);
		for (i = 0;
		     i < sizeof(*slabp) + cachep->num * sizeof(kmem_bufctl_t);
		     i++) {
			if (i % 16 == 0)
				printk("\n%03x:", i);
			printk(" %02x", ((unsigned char *)slabp)[i]);
		}
		printk("\n");
		BUG();
	}
}
#else
#define kfree_debugcheck(x) do { } while(0)
#define cache_free_debugcheck(x,objp,z) (objp)
#define check_slabp(x,y) do { } while(0)
#endif

static void *cache_alloc_refill(struct kmem_cache *cachep, gfp_t flags)
{
    int batchcount;  // 需要填充的对象批次数量
    struct kmem_list3 *l3;  // 管理 slab 列表的结构
    struct array_cache *ac;  // 当前 CPU 的 per-CPU 缓存
    int node;  // 当前 NUMA 节点

retry:
    // 确保当前环境下中断是被禁用的
    check_irq_off();
    
    // 获取当前的 NUMA 节点 ID
    node = numa_node_id();
    
    // 获取当前 CPU 的 per-CPU 缓存
    ac = cpu_cache_get(cachep);
    
    // 获取缓存中批量分配对象的数量
    batchcount = ac->batchcount;
    
    // 如果最近缓存未被访问且批次数大于限制，则减少填充批次
    if (!ac->touched && batchcount > BATCHREFILL_LIMIT) {
        batchcount = BATCHREFILL_LIMIT;
    }
    
    // 获取对应节点的 kmem_list3 结构
    l3 = cachep->nodelists[node];
    
    // 确保当前 CPU 缓存为空且 l3 不为空
    BUG_ON(ac->avail > 0 || !l3);
    
    // 获取 slab 管理的自旋锁，避免并发操作
    spin_lock(&l3->list_lock);

    // 尝试从共享缓存填充对象
    if (l3->shared && transfer_objects(ac, l3->shared, batchcount)) {
        l3->shared->touched = 1;  // 标记共享缓存已被访问
        goto alloc_done;
    }

    // 如果共享缓存无法提供对象，则从 slab 列表中分配对象
    while (batchcount > 0) {
        struct list_head *entry;
        struct slab *slabp;

        // 从部分使用的 slab 列表中获取下一个 slab
        entry = l3->slabs_partial.next;
        if (entry == &l3->slabs_partial) {
            l3->free_touched = 1;  // 标记 free slab 列表已被访问
            entry = l3->slabs_free.next;
            
            // 如果 free slab 列表也为空，则需要创建新的 slab
            if (entry == &l3->slabs_free)
                goto must_grow;
        }

        // 获取 slab 结构
        slabp = list_entry(entry, struct slab, list);
        check_slabp(cachep, slabp);
        check_spinlock_acquired(cachep);

        // 检查 slab 中是否有可分配的对象
        BUG_ON(slabp->inuse >= cachep->num);

        // 从 slab 中分配对象并添加到 CPU 缓存中
        while (slabp->inuse < cachep->num && batchcount--) {
            STATS_INC_ALLOCED(cachep);  // 增加已分配对象的统计计数
            STATS_INC_ACTIVE(cachep);   // 增加活跃对象的统计计数
            STATS_SET_HIGH(cachep);     // 更新高水位线

            // 将分配的对象放入 CPU 缓存的 entry 数组中
            ac->entry[ac->avail++] = slab_get_obj(cachep, slabp, node);
        }
        check_slabp(cachep, slabp);

        // 将 slab 移动到相应的列表中：部分使用或已满
        list_del(&slabp->list);
        if (slabp->free == BUFCTL_END)
            list_add(&slabp->list, &l3->slabs_full);  // 移动到已满列表
        else
            list_add(&slabp->list, &l3->slabs_partial);  // 仍有空闲对象，移动到部分使用列表
    }

must_grow:
    // 更新 l3 中的 free_objects 数量
    l3->free_objects -= ac->avail;

alloc_done:
    // 释放自旋锁
    spin_unlock(&l3->list_lock);

    // 如果 CPU 缓存中仍没有对象，尝试通过创建新的 slab 来分配
    if (unlikely(!ac->avail)) {
        int x;

        // 尝试创建新的 slab，并进行对象分配
        x = cache_grow(cachep, flags | GFP_THISNODE, node, NULL);

        // `cache_grow` 可能重新启用中断，此时 CPU 缓存可能已发生变化
        ac = cpu_cache_get(cachep);
        
        // 如果分配失败且 CPU 缓存仍为空，返回 NULL
        if (!x && ac->avail == 0)
            return NULL;

        // 如果对象已被中断处理程序分配，再次检查并重新尝试
        if (!ac->avail)
            goto retry;
    }

    // 标记 CPU 缓存已被访问
    ac->touched = 1;

    // 返回分配的对象
    return ac->entry[--ac->avail];
}

static inline void cache_alloc_debugcheck_before(struct kmem_cache *cachep,
						gfp_t flags)
{
	might_sleep_if(flags & __GFP_WAIT);
#if DEBUG
	kmem_flagcheck(cachep, flags);
#endif
}

#if DEBUG
static void *cache_alloc_debugcheck_after(struct kmem_cache *cachep,
				gfp_t flags, void *objp, void *caller)
{
	if (!objp)
		return objp;
	if (cachep->flags & SLAB_POISON) {
#ifdef CONFIG_DEBUG_PAGEALLOC
		if ((cachep->buffer_size % PAGE_SIZE) == 0 && OFF_SLAB(cachep))
			kernel_map_pages(virt_to_page(objp),
					 cachep->buffer_size / PAGE_SIZE, 1);
		else
			check_poison_obj(cachep, objp);
#else
		check_poison_obj(cachep, objp);
#endif
		poison_obj(cachep, objp, POISON_INUSE);
	}
	if (cachep->flags & SLAB_STORE_USER)
		*dbg_userword(cachep, objp) = caller;

	if (cachep->flags & SLAB_RED_ZONE) {
		if (*dbg_redzone1(cachep, objp) != RED_INACTIVE ||
				*dbg_redzone2(cachep, objp) != RED_INACTIVE) {
			slab_error(cachep, "double free, or memory outside"
						" object was overwritten");
			printk(KERN_ERR
				"%p: redzone 1:0x%llx, redzone 2:0x%llx\n",
				objp, *dbg_redzone1(cachep, objp),
				*dbg_redzone2(cachep, objp));
		}
		*dbg_redzone1(cachep, objp) = RED_ACTIVE;
		*dbg_redzone2(cachep, objp) = RED_ACTIVE;
	}
#ifdef CONFIG_DEBUG_SLAB_LEAK
	{
		struct slab *slabp;
		unsigned objnr;

		slabp = page_get_slab(virt_to_head_page(objp));
		objnr = (unsigned)(objp - slabp->s_mem) / cachep->buffer_size;
		slab_bufctl(slabp)[objnr] = BUFCTL_ACTIVE;
	}
#endif
	objp += obj_offset(cachep);
	if (cachep->ctor && cachep->flags & SLAB_POISON)
		cachep->ctor(objp);
#if ARCH_SLAB_MINALIGN
	if ((u32)objp & (ARCH_SLAB_MINALIGN-1)) {
		printk(KERN_ERR "0x%p: not aligned to ARCH_SLAB_MINALIGN=%d\n",
		       objp, ARCH_SLAB_MINALIGN);
	}
#endif
	return objp;
}
#else
#define cache_alloc_debugcheck_after(a,b,objp,d) (objp)
#endif

static bool slab_should_failslab(struct kmem_cache *cachep, gfp_t flags)
{
	if (cachep == &cache_cache)
		return false;

	return should_failslab(obj_size(cachep), flags, cachep->flags);
}

static inline void *____cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
    void *objp;  // 用于存储分配得到的对象指针
    struct array_cache *ac;  // 指向 CPU 上的 per-CPU 缓存

    // 检查中断是否被禁用，确保分配过程是原子的
    check_irq_off();

    // 获取当前 CPU 的缓存（per-CPU 缓存中的 array_cache 结构体）
    ac = cpu_cache_get(cachep);

    // 如果缓存中有可用对象
    if (likely(ac->avail)) {
        // 增加分配命中计数，表示在缓存中找到了可用对象
        STATS_INC_ALLOCHIT(cachep);
        
        // 标记缓存已被访问（触发器用于优化缓存管理）
        ac->touched = 1;
        
        // 从缓存中取出一个对象，并减少缓存的可用对象计数
        objp = ac->entry[--ac->avail];
    } else {
        // 增加分配未命中计数，表示缓存没有可用对象
        STATS_INC_ALLOCMISS(cachep);
        
        // 调用 `cache_alloc_refill` 重新填充缓存并分配一个对象
        objp = cache_alloc_refill(cachep, flags);
        
        /*
         * `cache_alloc_refill` 可能更新了 `ac` 指针，
         * 因此需要重新获取 per-CPU 缓存的正确值以保证后续操作。
         */
        ac = cpu_cache_get(cachep);
    }

    /*
     * 为了避免出现误报，如果 per-CPU 缓存中的对象被泄漏，我们需要确保
     * `kmemleak` 不会将 per-CPU 缓存中的指针视为对该对象的引用。
     * 通过调用 `kmemleak_erase` 清除对缓存中对象的引用。
     */
    if (objp)
        kmemleak_erase(&ac->entry[ac->avail]);
    
    // 返回分配得到的对象指针，如果分配失败则返回 NULL
    return objp;
}

#ifdef CONFIG_NUMA
/*
 * Try allocating on another node if PF_SPREAD_SLAB|PF_MEMPOLICY.
 *
 * If we are in_interrupt, then process context, including cpusets and
 * mempolicy, may not apply and should not be used for allocation policy.
 */
static void *alternate_node_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	int nid_alloc, nid_here;

	if (in_interrupt() || (flags & __GFP_THISNODE))
		return NULL;
	nid_alloc = nid_here = numa_node_id();
	if (cpuset_do_slab_mem_spread() && (cachep->flags & SLAB_MEM_SPREAD))
		nid_alloc = cpuset_mem_spread_node();
	else if (current->mempolicy)
		nid_alloc = slab_node(current->mempolicy);
	if (nid_alloc != nid_here)
		return ____cache_alloc_node(cachep, flags, nid_alloc);
	return NULL;
}

/*
 * Fallback function if there was no memory available and no objects on a
 * certain node and fall back is permitted. First we scan all the
 * available nodelists for available objects. If that fails then we
 * perform an allocation without specifying a node. This allows the page
 * allocator to do its reclaim / fallback magic. We then insert the
 * slab into the proper nodelist and then allocate from it.
 */
static void *fallback_alloc(struct kmem_cache *cache, gfp_t flags)
{
	struct zonelist *zonelist;
	gfp_t local_flags;
	struct zoneref *z;
	struct zone *zone;
	enum zone_type high_zoneidx = gfp_zone(flags);
	void *obj = NULL;
	int nid;

	if (flags & __GFP_THISNODE)
		return NULL;

	zonelist = node_zonelist(slab_node(current->mempolicy), flags);
	local_flags = flags & (GFP_CONSTRAINT_MASK|GFP_RECLAIM_MASK);

retry:
	/*
	 * Look through allowed nodes for objects available
	 * from existing per node queues.
	 */
	for_each_zone_zonelist(zone, z, zonelist, high_zoneidx) {
		nid = zone_to_nid(zone);

		if (cpuset_zone_allowed_hardwall(zone, flags) &&
			cache->nodelists[nid] &&
			cache->nodelists[nid]->free_objects) {
				obj = ____cache_alloc_node(cache,
					flags | GFP_THISNODE, nid);
				if (obj)
					break;
		}
	}

	if (!obj) {
		/*
		 * This allocation will be performed within the constraints
		 * of the current cpuset / memory policy requirements.
		 * We may trigger various forms of reclaim on the allowed
		 * set and go into memory reserves if necessary.
		 */
		if (local_flags & __GFP_WAIT)
			local_irq_enable();
		kmem_flagcheck(cache, flags);
		obj = kmem_getpages(cache, local_flags, numa_node_id());
		if (local_flags & __GFP_WAIT)
			local_irq_disable();
		if (obj) {
			/*
			 * Insert into the appropriate per node queues
			 */
			nid = page_to_nid(virt_to_page(obj));
			if (cache_grow(cache, flags, nid, obj)) {
				obj = ____cache_alloc_node(cache,
					flags | GFP_THISNODE, nid);
				if (!obj)
					/*
					 * Another processor may allocate the
					 * objects in the slab since we are
					 * not holding any locks.
					 */
					goto retry;
			} else {
				/* cache_grow already freed obj */
				obj = NULL;
			}
		}
	}
	return obj;
}

/*
 * A interface to enable slab creation on nodeid
 */
static void *____cache_alloc_node(struct kmem_cache *cachep, gfp_t flags,
				int nodeid)
{
	struct list_head *entry;
	struct slab *slabp;
	struct kmem_list3 *l3;
	void *obj;
	int x;

	l3 = cachep->nodelists[nodeid];
	BUG_ON(!l3);

retry:
	check_irq_off();
	spin_lock(&l3->list_lock);
	entry = l3->slabs_partial.next;
	if (entry == &l3->slabs_partial) {
		l3->free_touched = 1;
		entry = l3->slabs_free.next;
		if (entry == &l3->slabs_free)
			goto must_grow;
	}

	slabp = list_entry(entry, struct slab, list);
	check_spinlock_acquired_node(cachep, nodeid);
	check_slabp(cachep, slabp);

	STATS_INC_NODEALLOCS(cachep);
	STATS_INC_ACTIVE(cachep);
	STATS_SET_HIGH(cachep);

	BUG_ON(slabp->inuse == cachep->num);

	obj = slab_get_obj(cachep, slabp, nodeid);
	check_slabp(cachep, slabp);
	l3->free_objects--;
	/* move slabp to correct slabp list: */
	list_del(&slabp->list);

	if (slabp->free == BUFCTL_END)
		list_add(&slabp->list, &l3->slabs_full);
	else
		list_add(&slabp->list, &l3->slabs_partial);

	spin_unlock(&l3->list_lock);
	goto done;

must_grow:
	spin_unlock(&l3->list_lock);
	x = cache_grow(cachep, flags | GFP_THISNODE, nodeid, NULL);
	if (x)
		goto retry;

	return fallback_alloc(cachep, flags);

done:
	return obj;
}

/**
 * kmem_cache_alloc_node - Allocate an object on the specified node
 * @cachep: The cache to allocate from.
 * @flags: See kmalloc().
 * @nodeid: node number of the target node.
 * @caller: return address of caller, used for debug information
 *
 * Identical to kmem_cache_alloc but it will allocate memory on the given
 * node, which can improve the performance for cpu bound structures.
 *
 * Fallback to other node is possible if __GFP_THISNODE is not set.
 */
static __always_inline void *
__cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid,
		   void *caller)
{
	unsigned long save_flags;
	void *ptr;

	flags &= gfp_allowed_mask;

	lockdep_trace_alloc(flags);

	if (slab_should_failslab(cachep, flags))
		return NULL;

	cache_alloc_debugcheck_before(cachep, flags);
	local_irq_save(save_flags);

	if (nodeid == -1)
		nodeid = numa_node_id();

	if (unlikely(!cachep->nodelists[nodeid])) {
		/* Node not bootstrapped yet */
		ptr = fallback_alloc(cachep, flags);
		goto out;
	}

	if (nodeid == numa_node_id()) {
		/*
		 * Use the locally cached objects if possible.
		 * However ____cache_alloc does not allow fallback
		 * to other nodes. It may fail while we still have
		 * objects on other nodes available.
		 */
		ptr = ____cache_alloc(cachep, flags);
		if (ptr)
			goto out;
	}
	/* ___cache_alloc_node can fall back to other nodes */
	ptr = ____cache_alloc_node(cachep, flags, nodeid);
  out:
	local_irq_restore(save_flags);
	ptr = cache_alloc_debugcheck_after(cachep, flags, ptr, caller);
	kmemleak_alloc_recursive(ptr, obj_size(cachep), 1, cachep->flags,
				 flags);

	if (likely(ptr))
		kmemcheck_slab_alloc(cachep, flags, ptr, obj_size(cachep));

	if (unlikely((flags & __GFP_ZERO) && ptr))
		memset(ptr, 0, obj_size(cachep));

	return ptr;
}

static __always_inline void *
__do_cache_alloc(struct kmem_cache *cache, gfp_t flags)
{
	void *objp;

	if (unlikely(current->flags & (PF_SPREAD_SLAB | PF_MEMPOLICY))) {
		objp = alternate_node_alloc(cache, flags);
		if (objp)
			goto out;
	}
	objp = ____cache_alloc(cache, flags);

	/*
	 * We may just have run out of memory on the local node.
	 * ____cache_alloc_node() knows how to locate memory on other nodes
	 */
 	if (!objp)
 		objp = ____cache_alloc_node(cache, flags, numa_node_id());

  out:
	return objp;
}
#else

static __always_inline void *
__do_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	return ____cache_alloc(cachep, flags);
}

#endif /* CONFIG_NUMA */

static __always_inline void *
__cache_alloc(struct kmem_cache *cachep, gfp_t flags, void *caller)
{
    unsigned long save_flags;  // 保存中断状态的标志位
    void *objp;  // 用于存储分配的内存对象指针

    // 对分配标志进行过滤，仅保留允许的 GFP 标志
    flags &= gfp_allowed_mask;

    // 跟踪锁依赖性以调试分配中的潜在死锁问题
    lockdep_trace_alloc(flags);

    // 通过 slab_should_failslab 函数检查是否故意模拟 slab 分配失败
    if (slab_should_failslab(cachep, flags))
        return NULL;  // 如果模拟失败，则返回 NULL

    // 分配前进行调试检查，确保 cache 和标志的正确性
    cache_alloc_debugcheck_before(cachep, flags);

    // 禁用本地中断，保证分配过程中不被打断
    local_irq_save(save_flags);

    // 实际执行内存分配的核心函数
    objp = __do_cache_alloc(cachep, flags);

    // 恢复中断状态
    local_irq_restore(save_flags);

    // 分配后进行调试检查，检测是否有不一致的行为
    objp = cache_alloc_debugcheck_after(cachep, flags, objp, caller);

    // 进行内存泄漏检测，记录分配的对象
    kmemleak_alloc_recursive(objp, obj_size(cachep), 1, cachep->flags, flags);

    // 预取分配对象的缓存行，优化后续写操作的性能
    prefetchw(objp);

    // 如果分配成功且 objp 有效，则进行 kmemcheck 监测
    if (likely(objp))
        kmemcheck_slab_alloc(cachep, flags, objp, obj_size(cachep));

    // 如果分配标志中包含 __GFP_ZERO 且分配成功，则将分配的内存清零
    if (unlikely((flags & __GFP_ZERO) && objp))
        memset(objp, 0, obj_size(cachep));

    // 返回分配的内存对象指针
    return objp;
}


/*
 * Caller needs to acquire correct kmem_list's list_lock
 */
static void free_block(struct kmem_cache *cachep, void **objpp, int nr_objects,
		       int node)
{
	int i;
	struct kmem_list3 *l3;

	for (i = 0; i < nr_objects; i++) {
		void *objp = objpp[i];
		struct slab *slabp;

		slabp = virt_to_slab(objp);
		l3 = cachep->nodelists[node];
		list_del(&slabp->list);
		check_spinlock_acquired_node(cachep, node);
		check_slabp(cachep, slabp);
		slab_put_obj(cachep, slabp, objp, node);
		STATS_DEC_ACTIVE(cachep);
		l3->free_objects++;
		check_slabp(cachep, slabp);

		/* fixup slab chains */
		if (slabp->inuse == 0) {
			if (l3->free_objects > l3->free_limit) {
				l3->free_objects -= cachep->num;
				/* No need to drop any previously held
				 * lock here, even if we have a off-slab slab
				 * descriptor it is guaranteed to come from
				 * a different cache, refer to comments before
				 * alloc_slabmgmt.
				 */
				slab_destroy(cachep, slabp);
			} else {
				list_add(&slabp->list, &l3->slabs_free);
			}
		} else {
			/* Unconditionally move a slab to the end of the
			 * partial list on free - maximum time for the
			 * other objects to be freed, too.
			 */
			list_add_tail(&slabp->list, &l3->slabs_partial);
		}
	}
}

static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
{
	int batchcount;
	struct kmem_list3 *l3;
	int node = numa_node_id();

	batchcount = ac->batchcount;
#if DEBUG
	BUG_ON(!batchcount || batchcount > ac->avail);
#endif
	check_irq_off();
	l3 = cachep->nodelists[node];
	spin_lock(&l3->list_lock);
	if (l3->shared) {
		struct array_cache *shared_array = l3->shared;
		int max = shared_array->limit - shared_array->avail;
		if (max) {
			if (batchcount > max)
				batchcount = max;
			memcpy(&(shared_array->entry[shared_array->avail]),
			       ac->entry, sizeof(void *) * batchcount);
			shared_array->avail += batchcount;
			goto free_done;
		}
	}

	free_block(cachep, ac->entry, batchcount, node);
free_done:
#if STATS
	{
		int i = 0;
		struct list_head *p;

		p = l3->slabs_free.next;
		while (p != &(l3->slabs_free)) {
			struct slab *slabp;

			slabp = list_entry(p, struct slab, list);
			BUG_ON(slabp->inuse);

			i++;
			p = p->next;
		}
		STATS_SET_FREEABLE(cachep, i);
	}
#endif
	spin_unlock(&l3->list_lock);
	ac->avail -= batchcount;
	memmove(ac->entry, &(ac->entry[batchcount]), sizeof(void *)*ac->avail);
}

/*
 * Release an obj back to its cache. If the obj has a constructed state, it must
 * be in this state _before_ it is released.  Called with disabled ints.
 */
static inline void __cache_free(struct kmem_cache *cachep, void *objp)
{
	struct array_cache *ac = cpu_cache_get(cachep);

	check_irq_off();
	kmemleak_free_recursive(objp, cachep->flags);
	objp = cache_free_debugcheck(cachep, objp, __builtin_return_address(0));

	kmemcheck_slab_free(cachep, objp, obj_size(cachep));

	/*
	 * Skip calling cache_free_alien() when the platform is not numa.
	 * This will avoid cache misses that happen while accessing slabp (which
	 * is per page memory  reference) to get nodeid. Instead use a global
	 * variable to skip the call, which is mostly likely to be present in
	 * the cache.
	 */
	if (nr_online_nodes > 1 && cache_free_alien(cachep, objp))
		return;

	if (likely(ac->avail < ac->limit)) {
		STATS_INC_FREEHIT(cachep);
		ac->entry[ac->avail++] = objp;
		return;
	} else {
		STATS_INC_FREEMISS(cachep);
		cache_flusharray(cachep, ac);
		ac->entry[ac->avail++] = objp;
	}
}

/**
 * kmem_cache_alloc - Allocate an object
 * @cachep: The cache to allocate from.
 * @flags: See kmalloc().
 *
 * Allocate an object from this cache.  The flags are only relevant
 * if the cache has no available objects.
 */
// 创建高速缓存之后，通过如下函数获取对象。该函数从给定的高速缓存中返回一个指向对象的指针。如果高速缓存的所有slab中
// 都没有空闲对象，那么slab层必须通过kmem_getpages()获取新的页，gfp_t类型的参数传递给页面分配函数。应该是GFP_KERNEL或GFP_ATOMIC。
void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
	void *ret = __cache_alloc(cachep, flags, __builtin_return_address(0));

	trace_kmem_cache_alloc(_RET_IP_, ret,
			       obj_size(cachep), cachep->buffer_size, flags);

	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc);

#ifdef CONFIG_TRACING
void *kmem_cache_alloc_notrace(struct kmem_cache *cachep, gfp_t flags)
{
	return __cache_alloc(cachep, flags, __builtin_return_address(0));
}
EXPORT_SYMBOL(kmem_cache_alloc_notrace);
#endif

/**
 * kmem_ptr_validate - check if an untrusted pointer might be a slab entry.
 * @cachep: the cache we're checking against
 * @ptr: pointer to validate
 *
 * This verifies that the untrusted pointer looks sane;
 * it is _not_ a guarantee that the pointer is actually
 * part of the slab cache in question, but it at least
 * validates that the pointer can be dereferenced and
 * looks half-way sane.
 *
 * Currently only used for dentry validation.
 */
int kmem_ptr_validate(struct kmem_cache *cachep, const void *ptr)
{
	unsigned long size = cachep->buffer_size;
	struct page *page;

	if (unlikely(!kern_ptr_validate(ptr, size)))
		goto out;
	page = virt_to_page(ptr);
	if (unlikely(!PageSlab(page)))
		goto out;
	if (unlikely(page_get_cache(page) != cachep))
		goto out;
	return 1;
out:
	return 0;
}

#ifdef CONFIG_NUMA
void *kmem_cache_alloc_node(struct kmem_cache *cachep, gfp_t flags, int nodeid)
{
	void *ret = __cache_alloc_node(cachep, flags, nodeid,
				       __builtin_return_address(0));

	trace_kmem_cache_alloc_node(_RET_IP_, ret,
				    obj_size(cachep), cachep->buffer_size,
				    flags, nodeid);

	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_node);

#ifdef CONFIG_TRACING
void *kmem_cache_alloc_node_notrace(struct kmem_cache *cachep,
				    gfp_t flags,
				    int nodeid)
{
	return __cache_alloc_node(cachep, flags, nodeid,
				  __builtin_return_address(0));
}
EXPORT_SYMBOL(kmem_cache_alloc_node_notrace);
#endif

static __always_inline void *
__do_kmalloc_node(size_t size, gfp_t flags, int node, void *caller)
{
	struct kmem_cache *cachep;
	void *ret;

	cachep = kmem_find_general_cachep(size, flags);
	if (unlikely(ZERO_OR_NULL_PTR(cachep)))
		return cachep;
	ret = kmem_cache_alloc_node_notrace(cachep, flags, node);

	trace_kmalloc_node((unsigned long) caller, ret,
			   size, cachep->buffer_size, flags, node);

	return ret;
}

#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_TRACING)
void *__kmalloc_node(size_t size, gfp_t flags, int node)
{
	return __do_kmalloc_node(size, flags, node,
			__builtin_return_address(0));
}
EXPORT_SYMBOL(__kmalloc_node);

void *__kmalloc_node_track_caller(size_t size, gfp_t flags,
		int node, unsigned long caller)
{
	return __do_kmalloc_node(size, flags, node, (void *)caller);
}
EXPORT_SYMBOL(__kmalloc_node_track_caller);
#else
void *__kmalloc_node(size_t size, gfp_t flags, int node)
{
	return __do_kmalloc_node(size, flags, node, NULL);
}
EXPORT_SYMBOL(__kmalloc_node);
#endif /* CONFIG_DEBUG_SLAB || CONFIG_TRACING */
#endif /* CONFIG_NUMA */

/**
 * __do_kmalloc - allocate memory
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate (see kmalloc).
 * @caller: function caller for debug tracking of the caller
 */
static __always_inline void *__do_kmalloc(size_t size, gfp_t flags,
					  void *caller)
{
	struct kmem_cache *cachep;
	void *ret;

	/* If you want to save a few bytes .text space: replace
	 * __ with kmem_.
	 * Then kmalloc uses the uninlined functions instead of the inline
	 * functions.
	 */
	cachep = __find_general_cachep(size, flags);
	if (unlikely(ZERO_OR_NULL_PTR(cachep)))
		return cachep;
	ret = __cache_alloc(cachep, flags, caller);

	trace_kmalloc((unsigned long) caller, ret,
		      size, cachep->buffer_size, flags);

	return ret;
}


#if defined(CONFIG_DEBUG_SLAB) || defined(CONFIG_TRACING)
void *__kmalloc(size_t size, gfp_t flags)
{
	return __do_kmalloc(size, flags, __builtin_return_address(0));
}
EXPORT_SYMBOL(__kmalloc);

void *__kmalloc_track_caller(size_t size, gfp_t flags, unsigned long caller)
{
	return __do_kmalloc(size, flags, (void *)caller);
}
EXPORT_SYMBOL(__kmalloc_track_caller);

#else
void *__kmalloc(size_t size, gfp_t flags)
{
	return __do_kmalloc(size, flags, NULL);
}
EXPORT_SYMBOL(__kmalloc);
#endif

/**
 * kmem_cache_free - Deallocate an object
 * @cachep: The cache the allocation was from.
 * @objp: The previously allocated object.
 *
 * Free an object which was previously allocated from this
 * cache.
 */
// 释放一个对象，并把它返回给原先的slab，这样就能把cachep中的对象objp标记为空闲
void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
	unsigned long flags;

	local_irq_save(flags);
	debug_check_no_locks_freed(objp, obj_size(cachep));
	if (!(cachep->flags & SLAB_DEBUG_OBJECTS))
		debug_check_no_obj_freed(objp, obj_size(cachep));
	__cache_free(cachep, objp);
	local_irq_restore(flags);

	trace_kmem_cache_free(_RET_IP_, objp);
}
EXPORT_SYMBOL(kmem_cache_free);

/**
 * kfree - free previously allocated memory
 * @objp: pointer returned by kmalloc.
 *
 * If @objp is NULL, no operation is performed.
 *
 * Don't free memory not originally allocated by kmalloc()
 * or you will run into trouble.
 */
void kfree(const void *objp)
{
	struct kmem_cache *c;
	unsigned long flags;

	trace_kfree(_RET_IP_, objp);

	if (unlikely(ZERO_OR_NULL_PTR(objp)))
		return;
	local_irq_save(flags);
	kfree_debugcheck(objp);
	c = virt_to_cache(objp);
	debug_check_no_locks_freed(objp, obj_size(c));
	debug_check_no_obj_freed(objp, obj_size(c));
	__cache_free(c, (void *)objp);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(kfree);

unsigned int kmem_cache_size(struct kmem_cache *cachep)
{
	return obj_size(cachep);
}
EXPORT_SYMBOL(kmem_cache_size);

const char *kmem_cache_name(struct kmem_cache *cachep)
{
	return cachep->name;
}
EXPORT_SYMBOL_GPL(kmem_cache_name);

/*
 * This initializes kmem_list3 or resizes various caches for all nodes.
 */
/*
 * 为每个 NUMA 节点分配 kmem_list3 结构并设置共享缓存和外来缓存
 */
static int alloc_kmemlist(struct kmem_cache *cachep, gfp_t gfp)
{
	int node;
	struct kmem_list3 *l3;
	struct array_cache *new_shared;
	struct array_cache **new_alien = NULL;

	/* 遍历所有在线节点 */
	for_each_online_node(node) {

		/* 如果使用外来缓存 (alien cache)，为外来缓存分配内存 */
		if (use_alien_caches) {
			new_alien = alloc_alien_cache(node, cachep->limit, gfp);
			if (!new_alien)
				goto fail;  /* 分配失败则跳转到错误处理 */
		}

		/* 如果 cachep 允许共享缓存，则为共享缓存分配内存 */
		new_shared = NULL;
		if (cachep->shared) {
			new_shared = alloc_arraycache(node,
				cachep->shared * cachep->batchcount, 
				0xbaadf00d, gfp);  /* 分配共享缓存 */
			if (!new_shared) {
				/* 如果共享缓存分配失败，释放外来缓存并跳转到错误处理 */
				free_alien_cache(new_alien);
				goto fail;
			}
		}

		/* 获取当前节点的 kmem_list3 结构 */
		l3 = cachep->nodelists[node];
		if (l3) {
			struct array_cache *shared = l3->shared;

			/* 加锁以确保对 list 的安全访问 */
			spin_lock_irq(&l3->list_lock);

			/* 如果旧的共享缓存存在，则释放其内容 */
			if (shared)
				free_block(cachep, shared->entry,
						shared->avail, node);

			/* 更新新的共享缓存和外来缓存 */
			l3->shared = new_shared;
			if (!l3->alien) {
				l3->alien = new_alien;
				new_alien = NULL;
			}

			/* 根据节点上的 CPU 数量设置空闲对象的限制 */
			l3->free_limit = (1 + nr_cpus_node(node)) *
					cachep->batchcount + cachep->num;
			spin_unlock_irq(&l3->list_lock);

			/* 释放旧的共享缓存 */
			kfree(shared);
			/* 释放未使用的外来缓存 */
			free_alien_cache(new_alien);
			continue;
		}

		/* 如果当前节点没有 kmem_list3 结构，则为其分配新的结构 */
		l3 = kmalloc_node(sizeof(struct kmem_list3), gfp, node);
		if (!l3) {
			/* 分配失败则释放共享缓存和外来缓存，跳转到错误处理 */
			free_alien_cache(new_alien);
			kfree(new_shared);
			goto fail;
		}

		/* 初始化 kmem_list3 结构 */
		kmem_list3_init(l3);

		/* 设置回收时间以避免同步冲突 */
		l3->next_reap = jiffies + REAPTIMEOUT_LIST3 +
				((unsigned long)cachep) % REAPTIMEOUT_LIST3;

		/* 赋值新的共享缓存和外来缓存 */
		l3->shared = new_shared;
		l3->alien = new_alien;

		/* 根据节点上的 CPU 数量设置空闲对象的限制 */
		l3->free_limit = (1 + nr_cpus_node(node)) *
					cachep->batchcount + cachep->num;

		/* 将 kmem_list3 结构保存到 cachep 的节点列表中 */
		cachep->nodelists[node] = l3;
	}
	return 0;

fail:
	/* 如果缓存尚未激活，则回滚已分配的内容 */
	if (!cachep->next.next) {
		node--;
		while (node >= 0) {
			if (cachep->nodelists[node]) {
				l3 = cachep->nodelists[node];

				/* 释放共享缓存和外来缓存，并释放 kmem_list3 结构 */
				kfree(l3->shared);
				free_alien_cache(l3->alien);
				kfree(l3);
				cachep->nodelists[node] = NULL;
			}
			node--;
		}
	}
	return -ENOMEM;  /* 返回内存不足错误 */
}


struct ccupdate_struct {
	struct kmem_cache *cachep;
	struct array_cache *new[NR_CPUS];
};

static void do_ccupdate_local(void *info)
{
	struct ccupdate_struct *new = info;
	struct array_cache *old;

	check_irq_off();
	old = cpu_cache_get(new->cachep);

	new->cachep->array[smp_processor_id()] = new->new[smp_processor_id()];
	new->new[smp_processor_id()] = old;
}

/* Always called with the cache_chain_mutex held */
/* 
 * 总是持有 cache_chain_mutex 时调用此函数，用于调整 CPU 缓存参数 
 */
static int do_tune_cpucache(struct kmem_cache *cachep, int limit,
				int batchcount, int shared, gfp_t gfp)
{
	struct ccupdate_struct *new;
	int i;

	/* 分配一个 ccupdate_struct 结构，用于更新 CPU 缓存 */
	new = kzalloc(sizeof(*new), gfp);
	if (!new)
		return -ENOMEM;

	/* 遍历所有在线的 CPU */
	for_each_online_cpu(i) {
		/* 为每个 CPU 分配一个 array_cache 结构 */
		new->new[i] = alloc_arraycache(cpu_to_node(i), limit,
						batchcount, gfp);
		if (!new->new[i]) {
			/* 如果分配失败，回收已分配的资源并返回内存不足错误 */
			for (i--; i >= 0; i--)
				kfree(new->new[i]);
			kfree(new);
			return -ENOMEM;
		}
	}
	/* 将 cachep 赋值给 ccupdate_struct 结构的 cachep 字段 */
	new->cachep = cachep;

	/* 在每个 CPU 上执行 do_ccupdate_local 函数，更新本地的缓存 */
	on_each_cpu(do_ccupdate_local, (void *)new, 1);

	/* 确认中断处于开启状态 */
	check_irq_on();
	/* 设置 cachep 的 batchcount、limit 和 shared 值 */
	cachep->batchcount = batchcount;
	cachep->limit = limit;
	cachep->shared = shared;

	/* 释放旧的 array_cache 结构中的缓存块 */
	for_each_online_cpu(i) {
		struct array_cache *ccold = new->new[i];
		if (!ccold)
			continue;
		/* 加锁，确保并发访问的安全性 */
		spin_lock_irq(&cachep->nodelists[cpu_to_node(i)]->list_lock);
		/* 释放旧缓存中的空闲块 */
		free_block(cachep, ccold->entry, ccold->avail, cpu_to_node(i));
		spin_unlock_irq(&cachep->nodelists[cpu_to_node(i)]->list_lock);
		/* 释放旧的 array_cache 结构 */
		kfree(ccold);
	}
	/* 释放临时的 ccupdate_struct 结构 */
	kfree(new);
	/* 分配新的 kmem_list3 结构 */
	return alloc_kmemlist(cachep, gfp);
}


/* Called with cache_chain_mutex held always */
static int enable_cpucache(struct kmem_cache *cachep, gfp_t gfp)
{
	int err;
	int limit, shared;

	/*
	 * 头部 array 缓存有三个目的：
	 * - 创建一个 LIFO 顺序（后进先出），即返回那些缓存中仍然存有数据的对象，提高缓存命中率。
	 * - 减少对自旋锁的操作次数，降低并发锁开销。
	 * - 减少 slab 和 bufctl 链表上的操作：array 的操作更便宜。
	 * 
	 * limit 的值是根据对象的大小进行估算的，具体的值可以根据 Bonwick 所描述的自动调优算法进行优化。
	 * Bonwick 是一种 slab 缓存调优技术的提出者，可以自动调节缓存参数以提高性能。
	 */
	if (cachep->buffer_size > 131072)
		limit = 1;          // 对象非常大时，限制缓存的大小为 1。
	else if (cachep->buffer_size > PAGE_SIZE)
		limit = 8;          // 如果对象大小超过页面大小，限制为 8。
	else if (cachep->buffer_size > 1024)
		limit = 24;         // 对象大小在 1KB 到页面大小之间时，限制为 24。
	else if (cachep->buffer_size > 256)
		limit = 54;         // 对象大小在 256B 到 1KB 之间时，限制为 54。
	else
		limit = 120;        // 对象较小时，限制为 120。

	/*
	 * CPU 负载高的任务（例如网络路由）会表现出 CPU 绑定的分配行为：
	 * 大多数分配在一个 CPU 上进行，而大多数释放操作在另一个 CPU 上完成。
	 * 对于这种情况，需要在 CPU 之间有效传递对象。这是通过共享 array 实现的。
	 * 该 array 替代了 Bonwick 的 "magazine" 层。
	 * 
	 * 在单处理器系统上，它的功能等同于更大的 limit，然而效率较低。因此，默认情况下在单处理器上禁用。
	 */
	shared = 0;
	if (cachep->buffer_size <= PAGE_SIZE && num_possible_cpus() > 1)
		shared = 8;         // 如果对象小于等于页面大小且有多个 CPU，则启用共享缓存，大小为 8。

#if DEBUG
	/*
	 * 启用调试时，大的批处理计数会导致禁用本地中断的时间过长，因此限制批处理计数的大小。
	 */
	if (limit > 32)
		limit = 32;
#endif
	err = do_tune_cpucache(cachep, limit, (limit + 1) / 2, shared, gfp);
	if (err)
		printk(KERN_ERR "enable_cpucache failed for %s, error %d.\n",
		       cachep->name, -err);
	return err;
}


/*
 * Drain an array if it contains any elements taking the l3 lock only if
 * necessary. Note that the l3 listlock also protects the array_cache
 * if drain_array() is used on the shared array.
 */
void drain_array(struct kmem_cache *cachep, struct kmem_list3 *l3,
			 struct array_cache *ac, int force, int node)
{
	int tofree;

	if (!ac || !ac->avail)
		return;
	if (ac->touched && !force) {
		ac->touched = 0;
	} else {
		spin_lock_irq(&l3->list_lock);
		if (ac->avail) {
			tofree = force ? ac->avail : (ac->limit + 4) / 5;
			if (tofree > ac->avail)
				tofree = (ac->avail + 1) / 2;
			free_block(cachep, ac->entry, tofree, node);
			ac->avail -= tofree;
			memmove(ac->entry, &(ac->entry[tofree]),
				sizeof(void *) * ac->avail);
		}
		spin_unlock_irq(&l3->list_lock);
	}
}

/**
 * cache_reap - Reclaim memory from caches.
 * @w: work descriptor
 *
 * Called from workqueue/eventd every few seconds.
 * Purpose:
 * - clear the per-cpu caches for this CPU.
 * - return freeable pages to the main free memory pool.
 *
 * If we cannot acquire the cache chain mutex then just give up - we'll try
 * again on the next iteration.
 */
static void cache_reap(struct work_struct *w)
{
	struct kmem_cache *searchp;
	struct kmem_list3 *l3;
	int node = numa_node_id();
	struct delayed_work *work = to_delayed_work(w);

	if (!mutex_trylock(&cache_chain_mutex))
		/* Give up. Setup the next iteration. */
		goto out;

	list_for_each_entry(searchp, &cache_chain, next) {
		check_irq_on();

		/*
		 * We only take the l3 lock if absolutely necessary and we
		 * have established with reasonable certainty that
		 * we can do some work if the lock was obtained.
		 */
		l3 = searchp->nodelists[node];

		reap_alien(searchp, l3);

		drain_array(searchp, l3, cpu_cache_get(searchp), 0, node);

		/*
		 * These are racy checks but it does not matter
		 * if we skip one check or scan twice.
		 */
		if (time_after(l3->next_reap, jiffies))
			goto next;

		l3->next_reap = jiffies + REAPTIMEOUT_LIST3;

		drain_array(searchp, l3, l3->shared, 0, node);

		if (l3->free_touched)
			l3->free_touched = 0;
		else {
			int freed;

			freed = drain_freelist(searchp, l3, (l3->free_limit +
				5 * searchp->num - 1) / (5 * searchp->num));
			STATS_ADD_REAPED(searchp, freed);
		}
next:
		cond_resched();
	}
	check_irq_on();
	mutex_unlock(&cache_chain_mutex);
	next_reap_node();
out:
	/* Set up the next iteration */
	schedule_delayed_work(work, round_jiffies_relative(REAPTIMEOUT_CPUC));
}

#ifdef CONFIG_SLABINFO

static void print_slabinfo_header(struct seq_file *m)
{
	/*
	 * Output format version, so at least we can change it
	 * without _too_ many complaints.
	 */
#if STATS
	seq_puts(m, "slabinfo - version: 2.1 (statistics)\n");
#else
	seq_puts(m, "slabinfo - version: 2.1\n");
#endif
	seq_puts(m, "# name            <active_objs> <num_objs> <objsize> "
		 "<objperslab> <pagesperslab>");
	seq_puts(m, " : tunables <limit> <batchcount> <sharedfactor>");
	seq_puts(m, " : slabdata <active_slabs> <num_slabs> <sharedavail>");
#if STATS
	seq_puts(m, " : globalstat <listallocs> <maxobjs> <grown> <reaped> "
		 "<error> <maxfreeable> <nodeallocs> <remotefrees> <alienoverflow>");
	seq_puts(m, " : cpustat <allochit> <allocmiss> <freehit> <freemiss>");
#endif
	seq_putc(m, '\n');
}

static void *s_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	mutex_lock(&cache_chain_mutex);
	if (!n)
		print_slabinfo_header(m);

	return seq_list_start(&cache_chain, *pos);
}

static void *s_next(struct seq_file *m, void *p, loff_t *pos)
{
	return seq_list_next(p, &cache_chain, pos);
}

static void s_stop(struct seq_file *m, void *p)
{
	mutex_unlock(&cache_chain_mutex);
}

static int s_show(struct seq_file *m, void *p)
{
	struct kmem_cache *cachep = list_entry(p, struct kmem_cache, next);
	struct slab *slabp;
	unsigned long active_objs;
	unsigned long num_objs;
	unsigned long active_slabs = 0;
	unsigned long num_slabs, free_objects = 0, shared_avail = 0;
	const char *name;
	char *error = NULL;
	int node;
	struct kmem_list3 *l3;

	active_objs = 0;
	num_slabs = 0;
	for_each_online_node(node) {
		l3 = cachep->nodelists[node];
		if (!l3)
			continue;

		check_irq_on();
		spin_lock_irq(&l3->list_lock);

		list_for_each_entry(slabp, &l3->slabs_full, list) {
			if (slabp->inuse != cachep->num && !error)
				error = "slabs_full accounting error";
			active_objs += cachep->num;
			active_slabs++;
		}
		list_for_each_entry(slabp, &l3->slabs_partial, list) {
			if (slabp->inuse == cachep->num && !error)
				error = "slabs_partial inuse accounting error";
			if (!slabp->inuse && !error)
				error = "slabs_partial/inuse accounting error";
			active_objs += slabp->inuse;
			active_slabs++;
		}
		list_for_each_entry(slabp, &l3->slabs_free, list) {
			if (slabp->inuse && !error)
				error = "slabs_free/inuse accounting error";
			num_slabs++;
		}
		free_objects += l3->free_objects;
		if (l3->shared)
			shared_avail += l3->shared->avail;

		spin_unlock_irq(&l3->list_lock);
	}
	num_slabs += active_slabs;
	num_objs = num_slabs * cachep->num;
	if (num_objs - active_objs != free_objects && !error)
		error = "free_objects accounting error";

	name = cachep->name;
	if (error)
		printk(KERN_ERR "slab: cache %s error: %s\n", name, error);

	seq_printf(m, "%-17s %6lu %6lu %6u %4u %4d",
		   name, active_objs, num_objs, cachep->buffer_size,
		   cachep->num, (1 << cachep->gfporder));
	seq_printf(m, " : tunables %4u %4u %4u",
		   cachep->limit, cachep->batchcount, cachep->shared);
	seq_printf(m, " : slabdata %6lu %6lu %6lu",
		   active_slabs, num_slabs, shared_avail);
#if STATS
	{			/* list3 stats */
		unsigned long high = cachep->high_mark;
		unsigned long allocs = cachep->num_allocations;
		unsigned long grown = cachep->grown;
		unsigned long reaped = cachep->reaped;
		unsigned long errors = cachep->errors;
		unsigned long max_freeable = cachep->max_freeable;
		unsigned long node_allocs = cachep->node_allocs;
		unsigned long node_frees = cachep->node_frees;
		unsigned long overflows = cachep->node_overflow;

		seq_printf(m, " : globalstat %7lu %6lu %5lu %4lu \
				%4lu %4lu %4lu %4lu %4lu", allocs, high, grown,
				reaped, errors, max_freeable, node_allocs,
				node_frees, overflows);
	}
	/* cpu stats */
	{
		unsigned long allochit = atomic_read(&cachep->allochit);
		unsigned long allocmiss = atomic_read(&cachep->allocmiss);
		unsigned long freehit = atomic_read(&cachep->freehit);
		unsigned long freemiss = atomic_read(&cachep->freemiss);

		seq_printf(m, " : cpustat %6lu %6lu %6lu %6lu",
			   allochit, allocmiss, freehit, freemiss);
	}
#endif
	seq_putc(m, '\n');
	return 0;
}

/*
 * slabinfo_op - iterator that generates /proc/slabinfo
 *
 * Output layout:
 * cache-name
 * num-active-objs
 * total-objs
 * object size
 * num-active-slabs
 * total-slabs
 * num-pages-per-slab
 * + further values on SMP and with statistics enabled
 */

static const struct seq_operations slabinfo_op = {
	.start = s_start,
	.next = s_next,
	.stop = s_stop,
	.show = s_show,
};

#define MAX_SLABINFO_WRITE 128
/**
 * slabinfo_write - Tuning for the slab allocator
 * @file: unused
 * @buffer: user buffer
 * @count: data length
 * @ppos: unused
 */
ssize_t slabinfo_write(struct file *file, const char __user * buffer,
		       size_t count, loff_t *ppos)
{
	char kbuf[MAX_SLABINFO_WRITE + 1], *tmp;
	int limit, batchcount, shared, res;
	struct kmem_cache *cachep;

	if (count > MAX_SLABINFO_WRITE)
		return -EINVAL;
	if (copy_from_user(&kbuf, buffer, count))
		return -EFAULT;
	kbuf[MAX_SLABINFO_WRITE] = '\0';

	tmp = strchr(kbuf, ' ');
	if (!tmp)
		return -EINVAL;
	*tmp = '\0';
	tmp++;
	if (sscanf(tmp, " %d %d %d", &limit, &batchcount, &shared) != 3)
		return -EINVAL;

	/* Find the cache in the chain of caches. */
	mutex_lock(&cache_chain_mutex);
	res = -EINVAL;
	list_for_each_entry(cachep, &cache_chain, next) {
		if (!strcmp(cachep->name, kbuf)) {
			if (limit < 1 || batchcount < 1 ||
					batchcount > limit || shared < 0) {
				res = 0;
			} else {
				res = do_tune_cpucache(cachep, limit,
						       batchcount, shared,
						       GFP_KERNEL);
			}
			break;
		}
	}
	mutex_unlock(&cache_chain_mutex);
	if (res >= 0)
		res = count;
	return res;
}

static int slabinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &slabinfo_op);
}

static const struct file_operations proc_slabinfo_operations = {
	.open		= slabinfo_open,
	.read		= seq_read,
	.write		= slabinfo_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

#ifdef CONFIG_DEBUG_SLAB_LEAK

static void *leaks_start(struct seq_file *m, loff_t *pos)
{
	mutex_lock(&cache_chain_mutex);
	return seq_list_start(&cache_chain, *pos);
}

static inline int add_caller(unsigned long *n, unsigned long v)
{
	unsigned long *p;
	int l;
	if (!v)
		return 1;
	l = n[1];
	p = n + 2;
	while (l) {
		int i = l/2;
		unsigned long *q = p + 2 * i;
		if (*q == v) {
			q[1]++;
			return 1;
		}
		if (*q > v) {
			l = i;
		} else {
			p = q + 2;
			l -= i + 1;
		}
	}
	if (++n[1] == n[0])
		return 0;
	memmove(p + 2, p, n[1] * 2 * sizeof(unsigned long) - ((void *)p - (void *)n));
	p[0] = v;
	p[1] = 1;
	return 1;
}

static void handle_slab(unsigned long *n, struct kmem_cache *c, struct slab *s)
{
	void *p;
	int i;
	if (n[0] == n[1])
		return;
	for (i = 0, p = s->s_mem; i < c->num; i++, p += c->buffer_size) {
		if (slab_bufctl(s)[i] != BUFCTL_ACTIVE)
			continue;
		if (!add_caller(n, (unsigned long)*dbg_userword(c, p)))
			return;
	}
}

static void show_symbol(struct seq_file *m, unsigned long address)
{
#ifdef CONFIG_KALLSYMS
	unsigned long offset, size;
	char modname[MODULE_NAME_LEN], name[KSYM_NAME_LEN];

	if (lookup_symbol_attrs(address, &size, &offset, modname, name) == 0) {
		seq_printf(m, "%s+%#lx/%#lx", name, offset, size);
		if (modname[0])
			seq_printf(m, " [%s]", modname);
		return;
	}
#endif
	seq_printf(m, "%p", (void *)address);
}

static int leaks_show(struct seq_file *m, void *p)
{
	struct kmem_cache *cachep = list_entry(p, struct kmem_cache, next);
	struct slab *slabp;
	struct kmem_list3 *l3;
	const char *name;
	unsigned long *n = m->private;
	int node;
	int i;

	if (!(cachep->flags & SLAB_STORE_USER))
		return 0;
	if (!(cachep->flags & SLAB_RED_ZONE))
		return 0;

	/* OK, we can do it */

	n[1] = 0;

	for_each_online_node(node) {
		l3 = cachep->nodelists[node];
		if (!l3)
			continue;

		check_irq_on();
		spin_lock_irq(&l3->list_lock);

		list_for_each_entry(slabp, &l3->slabs_full, list)
			handle_slab(n, cachep, slabp);
		list_for_each_entry(slabp, &l3->slabs_partial, list)
			handle_slab(n, cachep, slabp);
		spin_unlock_irq(&l3->list_lock);
	}
	name = cachep->name;
	if (n[0] == n[1]) {
		/* Increase the buffer size */
		mutex_unlock(&cache_chain_mutex);
		m->private = kzalloc(n[0] * 4 * sizeof(unsigned long), GFP_KERNEL);
		if (!m->private) {
			/* Too bad, we are really out */
			m->private = n;
			mutex_lock(&cache_chain_mutex);
			return -ENOMEM;
		}
		*(unsigned long *)m->private = n[0] * 2;
		kfree(n);
		mutex_lock(&cache_chain_mutex);
		/* Now make sure this entry will be retried */
		m->count = m->size;
		return 0;
	}
	for (i = 0; i < n[1]; i++) {
		seq_printf(m, "%s: %lu ", name, n[2*i+3]);
		show_symbol(m, n[2*i+2]);
		seq_putc(m, '\n');
	}

	return 0;
}

static const struct seq_operations slabstats_op = {
	.start = leaks_start,
	.next = s_next,
	.stop = s_stop,
	.show = leaks_show,
};

static int slabstats_open(struct inode *inode, struct file *file)
{
	unsigned long *n = kzalloc(PAGE_SIZE, GFP_KERNEL);
	int ret = -ENOMEM;
	if (n) {
		ret = seq_open(file, &slabstats_op);
		if (!ret) {
			struct seq_file *m = file->private_data;
			*n = PAGE_SIZE / (2 * sizeof(unsigned long));
			m->private = n;
			n = NULL;
		}
		kfree(n);
	}
	return ret;
}

static const struct file_operations proc_slabstats_operations = {
	.open		= slabstats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};
#endif

static int __init slab_proc_init(void)
{
	proc_create("slabinfo",S_IWUSR|S_IRUGO,NULL,&proc_slabinfo_operations);
#ifdef CONFIG_DEBUG_SLAB_LEAK
	proc_create("slab_allocators", 0, NULL, &proc_slabstats_operations);
#endif
	return 0;
}
module_init(slab_proc_init);
#endif

/**
 * ksize - get the actual amount of memory allocated for a given object
 * @objp: Pointer to the object
 *
 * kmalloc may internally round up allocations and return more memory
 * than requested. ksize() can be used to determine the actual amount of
 * memory allocated. The caller may use this additional memory, even though
 * a smaller amount of memory was initially specified with the kmalloc call.
 * The caller must guarantee that objp points to a valid object previously
 * allocated with either kmalloc() or kmem_cache_alloc(). The object
 * must not be freed during the duration of the call.
 */
size_t ksize(const void *objp)
{
	BUG_ON(!objp);
	if (unlikely(objp == ZERO_SIZE_PTR))
		return 0;

	return obj_size(virt_to_cache(objp));
}
EXPORT_SYMBOL(ksize);
