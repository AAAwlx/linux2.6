/*
 * include/linux/idr.h
 * 
 * 2002-10-18  written by Jim Houston jim.houston@ccur.com
 *	Copyright (C) 2002 by Concurrent Computer Corporation
 *	Distributed under the GNU GPL license version 2.
 *
 * Small id to pointer translation service avoiding fixed sized
 * tables.
 */

#ifndef __IDR_H__
#define __IDR_H__

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/rcupdate.h>

#if BITS_PER_LONG == 32
# define IDR_BITS 5
# define IDR_FULL 0xfffffffful
/* We can only use two of the bits in the top level because there is
   only one possible bit in the top level (5 bits * 7 levels = 35
   bits, but you only use 31 bits in the id). */
# define TOP_LEVEL_FULL (IDR_FULL >> 30)
#elif BITS_PER_LONG == 64
# define IDR_BITS 6
# define IDR_FULL 0xfffffffffffffffful
/* We can only use two of the bits in the top level because there is
   only one possible bit in the top level (6 bits * 6 levels = 36
   bits, but you only use 31 bits in the id). */
# define TOP_LEVEL_FULL (IDR_FULL >> 62)
#else
# error "BITS_PER_LONG is not 32 or 64"
#endif

#define IDR_SIZE (1 << IDR_BITS)
#define IDR_MASK ((1 << IDR_BITS)-1)

#define MAX_ID_SHIFT (sizeof(int)*8 - 1)
#define MAX_ID_BIT (1U << MAX_ID_SHIFT)
#define MAX_ID_MASK (MAX_ID_BIT - 1)

/* Leave the possibility of an incomplete final layer */
#define MAX_LEVEL (MAX_ID_SHIFT + IDR_BITS - 1) / IDR_BITS

/* Number of id_layer structs to leave in free list */
#define IDR_FREE_MAX MAX_LEVEL + MAX_LEVEL

struct idr_layer {
    unsigned long bitmap;             /* 位图，0 位表示该位置有空闲空间 */
    struct idr_layer *ary[1<<IDR_BITS]; /* 指向下层 idr_layer 的指针数组，大小为 2^IDR_BITS */
    int count;                        /* 计数，当为 0 时，可以释放该层 */
    int layer;                        /* 离叶子节点的距离（层数） */
    struct rcu_head rcu_head;         /* 用于 RCU（Read-Copy Update）的头部结构 */
};

// 用于映射用户空间的uid
struct idr {
	struct idr_layer *top;
	struct idr_layer *id_free;
	int		  layers; /* only valid without concurrent changes */
	int		  id_free_cnt;
	spinlock_t	  lock;
};

#define IDR_INIT(name)						\
{								\
	.top		= NULL,					\
	.id_free	= NULL,					\
	.layers 	= 0,					\
	.id_free_cnt	= 0,					\
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),	\
}
#define DEFINE_IDR(name)	struct idr name = IDR_INIT(name)

/* Actions to be taken after a call to _idr_sub_alloc */
#define IDR_NEED_TO_GROW -2
#define IDR_NOMORE_SPACE -3

#define _idr_rc_to_errno(rc) ((rc) == -1 ? -EAGAIN : -ENOSPC)

/**
 * idr synchronization (stolen from radix-tree.h)
 *
 * idr_find() is able to be called locklessly, using RCU. The caller must
 * ensure calls to this function are made within rcu_read_lock() regions.
 * Other readers (lock-free or otherwise) and modifications may be running
 * concurrently.
 *
 * It is still required that the caller manage the synchronization and
 * lifetimes of the items. So if RCU lock-free lookups are used, typically
 * this would mean that the items have their own locks, or are amenable to
 * lock-free access; and that the items are freed by RCU (or only freed after
 * having been deleted from the idr tree *and* a synchronize_rcu() grace
 * period).
 */

/*
 * This is what we export.
 */

// 根据id查找指针，成功返回id关联的指针，失败返回空指针。如果idr_get_new或idr_get_new_above将空指针映射给UID，那么该函数成功也返回NULL。
void *idr_find(struct idr *idp, int id);
// 调整后备树的大小，该函数将在需要时进行UID的分配工作，调整由idp指向的idr的大小。如果真需要调整大小，则内存分配例程使用gfp标识。该函数成功返回1,失败返回0
int idr_pre_get(struct idr *idp, gfp_t gfp_mask);
// 获取新的UID,并且将其加到idr的方法是idr_get_new。使用idp所指向的idr去分配一个新的UID，
// 并且将其关联到指针ptr上。成功返回0,并将新的UID存于id。错误是返回非0的错误玛，错误码时-EAGIN。
// 说明还需要再次调用idr_pre_get()，如果idr已满，错误码时-ENOSPC。
int idr_get_new(struct idr *idp, void *ptr, int *id);
// 该函数使得调用者可以指定一个最小的UID返回值，和idr_get_new()作用相同，确保新的UID大于等于starting_id。使用这个变种方法允许idr的使用者确保UID不会被重用。
int idr_get_new_above(struct idr *idp, void *ptr, int starting_id, int *id);
int idr_for_each(struct idr *idp,
		 int (*fn)(int id, void *p, void *data), void *data);
void *idr_get_next(struct idr *idp, int *nextid);
void *idr_replace(struct idr *idp, void *ptr, int id);
// 从idr中删除UID
void idr_remove(struct idr *idp, int id);
// 删除所有的UID，先调用idr_remove_all，再调用idr_destroy就能释放idr占用的所有内存
void idr_remove_all(struct idr *idp);
// 撤销idr，如果成功，则只释放idr中未使用的内存，并不释放当前分配给UID使用的任何内存。通过，内核不会撤销idr，除非关闭或卸载，而且只有在没有其他用户时才能删除
void idr_destroy(struct idr *idp);
// 初始化一个idr
void idr_init(struct idr *idp);


/*
 * IDA - IDR based id allocator, use when translation from id to
 * pointer isn't necessary.
 */
#define IDA_CHUNK_SIZE		128	/* 128 bytes per chunk */
#define IDA_BITMAP_LONGS	(128 / sizeof(long) - 1)
#define IDA_BITMAP_BITS		(IDA_BITMAP_LONGS * sizeof(long) * 8)

struct ida_bitmap {
	long			nr_busy;
	unsigned long		bitmap[IDA_BITMAP_LONGS];
};

struct ida {
	struct idr		idr;
	struct ida_bitmap	*free_bitmap;
};

#define IDA_INIT(name)		{ .idr = IDR_INIT(name), .free_bitmap = NULL, }
#define DEFINE_IDA(name)	struct ida name = IDA_INIT(name)

int ida_pre_get(struct ida *ida, gfp_t gfp_mask);
int ida_get_new_above(struct ida *ida, int starting_id, int *p_id);
int ida_get_new(struct ida *ida, int *p_id);
void ida_remove(struct ida *ida, int id);
void ida_destroy(struct ida *ida);
void ida_init(struct ida *ida);

void __init idr_init_cache(void);

#endif /* __IDR_H__ */
