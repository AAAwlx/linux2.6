/*
 *  fs/ext4/mballoc.h
 *
 *  Written by: Alex Tomas <alex@clusterfs.com>
 *  mballoc多块分配器
 */
#ifndef _EXT4_MBALLOC_H
#define _EXT4_MBALLOC_H

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/proc_fs.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <linux/blkdev.h>
#include <linux/mutex.h>
#include "ext4_jbd2.h"
#include "ext4.h"

/*
 * with AGGRESSIVE_CHECK allocator runs consistency checks over
 * structures. these checks slow things down a lot
 */
#define AGGRESSIVE_CHECK__

/*
 * with DOUBLE_CHECK defined mballoc creates persistent in-core
 * bitmaps, maintains and uses them to check for double allocations
 */
#define DOUBLE_CHECK__

/*
 */
#ifdef CONFIG_EXT4_DEBUG
extern u8 mb_enable_debug;

#define mb_debug(n, fmt, a...)	                                        \
	do {								\
		if ((n) <= mb_enable_debug) {		        	\
			printk(KERN_DEBUG "(%s, %d): %s: ",		\
			       __FILE__, __LINE__, __func__);		\
			printk(fmt, ## a);				\
		}							\
	} while (0)
#else
#define mb_debug(n, fmt, a...)
#endif

#define EXT4_MB_HISTORY_ALLOC		1	/* 分配块的历史记录标志 */
#define EXT4_MB_HISTORY_PREALLOC	2	/* 使用预分配块的历史记录标志 */

/*
 * mballoc 在寻找最佳扩展块（连续块）时，可以扫描的最大范围（已找到的扩展块数量）
 */
#define MB_DEFAULT_MAX_TO_SCAN		200

/*
 * mballoc 在寻找最佳扩展块时，必须至少扫描的范围
 */
#define MB_DEFAULT_MIN_TO_SCAN		10

/*
 * mballoc 在寻找最佳块时，将扫描的块组数量上限
 */
#define MB_DEFAULT_MAX_GROUPS_TO_SCAN	5

/*
 * 如果启用了 'ext4_mb_stats'，分配器将在卸载时收集统计信息。
 * 但这会增加一定的开销！
 */
#define MB_DEFAULT_STATS		0

/*
 * 小于 MB_DEFAULT_STREAM_THRESHOLD 的文件将由流分配器处理。
 * 流分配器的目的是将请求尽可能紧密地打包在一起，以产生平滑的 I/O 流量。
 * 对于流请求，我们使用局部性组的预分配空间。
 * 可以通过 /proc/fs/ext4/<partition>/stream_req 调整此阈值。
 */
#define MB_DEFAULT_STREAM_THRESHOLD	16	/* 64K */

/*
 * 使用 2^N 搜索伙伴系统的请求数量
 */
#define MB_DEFAULT_ORDER2_REQS		2

/*
 * 默认情况下，组预分配的块数为 512 个块
 */
#define MB_DEFAULT_GROUP_PREALLOC	512


// 描述一个空闲块数据结构，用于跟踪分配组中的空闲块信息
struct ext4_free_data {
    struct rb_node node;        // 将空闲块信息链接到 group_info 的红黑树节点
    struct list_head list;      // 将空闲块信息链接到 ext4_sb_info 的链表节点
    ext4_group_t group;         // 空闲块所属的块组
    ext4_grpblk_t start_blk;    // 空闲块的起始块
    ext4_grpblk_t count;        // 空闲块的数量
    tid_t t_tid;                // 释放该块区的事务 ID
};

// 预分配空间结构，描述一个文件或组的预分配块
struct ext4_prealloc_space {
    struct list_head pa_inode_list;  // 链接到 inode 的预分配列表
    struct list_head pa_group_list;  // 链接到块组的预分配列表
    union {
        struct list_head pa_tmp_list;  // 临时链表
        struct rcu_head pa_rcu;        // 用于 RCU 的回调机制
    } u;
    spinlock_t pa_lock;                // 锁定预分配空间的自旋锁
    atomic_t pa_count;                 // 预分配空间引用计数
    unsigned pa_deleted;               // 是否已删除标志
    ext4_fsblk_t pa_pstart;            // 预分配空间的物理起始块
    ext4_lblk_t pa_lstart;             // 预分配空间的逻辑起始块
    ext4_grpblk_t pa_len;              // 预分配块的长度
    ext4_grpblk_t pa_free;             // 剩余未使用的预分配块数
    unsigned short pa_type;            // 预分配类型（inode 或 group）
    spinlock_t *pa_obj_lock;           // 对象锁
    struct inode *pa_inode;            // 仅用于历史记录的 inode 指针
};

// 定义预分配类型
enum {
    MB_INODE_PA = 0,   // inode 级别的预分配
    MB_GROUP_PA = 1    // 块组级别的预分配
};

// 描述一个自由块区的结构
struct ext4_free_extent {
    ext4_lblk_t fe_logical;   // 空闲块的逻辑起始块
    ext4_grpblk_t fe_start;   // 空闲块的物理起始块
    ext4_group_t fe_group;    // 空闲块所在的组
    ext4_grpblk_t fe_len;     // 空闲块的长度
};

// 描述本地性组（Locality Group），用于将相关的更改分组在一起
struct ext4_locality_group {
    struct mutex lg_mutex;                        // 保护预分配的互斥锁
    struct list_head lg_prealloc_list[PREALLOC_TB_SIZE];  // 预分配列表数组，用于流分配
    spinlock_t lg_prealloc_lock;                  // 自旋锁，用于同步访问预分配列表
};

// 定义了分配上下文，跟踪分配过程中的状态和结果
struct ext4_allocation_context {
    struct inode *ac_inode;           // 关联的 inode 指针
    struct super_block *ac_sb;        // 超级块指针

    struct ext4_free_extent ac_o_ex;  // 原始请求的自由块区
    struct ext4_free_extent ac_g_ex;  // 标准化后的目标自由块区
    struct ext4_free_extent ac_b_ex;  // 最佳找到的自由块区
    struct ext4_free_extent ac_f_ex;  // 预分配前找到的最佳自由块区的副本

    unsigned long ac_ex_scanned;      // 已扫描的块数
    __u16 ac_groups_scanned;          // 已扫描的块组数
    __u16 ac_found;                   // 找到的自由块数
    __u16 ac_tail;                    // 用于跟踪末尾块的字段
    __u16 ac_buddy;                   // 用于伙伴系统的字段
    __u16 ac_flags;                   // 分配提示标志
    __u8 ac_status;                   // 分配状态
    __u8 ac_criteria;                 // 分配标准
    __u8 ac_repeats;                  // 重复计数
    __u8 ac_2order;                   // 如果请求分配 2^N 个块，且 N > 0，此字段存储 N，否则为 0
    __u8 ac_op;                       // 操作类型，仅用于历史记录

    struct page *ac_bitmap_page;      // 位图页面指针
    struct page *ac_buddy_page;       // 伙伴页面指针
    struct rw_semaphore *alloc_semp;  // 成功分配后持有的信号量指针
    struct ext4_prealloc_space *ac_pa;  // 预分配空间指针
    struct ext4_locality_group *ac_lg;  // 本地性组指针
};

// 分配状态
#define AC_STATUS_CONTINUE  1  // 继续分配
#define AC_STATUS_FOUND     2  // 找到目标块
#define AC_STATUS_BREAK     3  // 终止分配

// ext4 伙伴系统结构，管理块组中的位图和伙伴系统信息
struct ext4_buddy {
    struct page *bd_buddy_page;      // 伙伴页面指针
    void *bd_buddy;                  // 伙伴数据指针
    struct page *bd_bitmap_page;     // 位图页面指针
    void *bd_bitmap;                 // 位图数据指针
    struct ext4_group_info *bd_info; // 块组信息指针
    struct super_block *bd_sb;       // 超级块指针
    __u16 bd_blkbits;                // 块大小的位数
    ext4_group_t bd_group;           // 块组号
    struct rw_semaphore *alloc_semp; // 分配信号量指针
};
#define EXT4_MB_BITMAP(e4b)	((e4b)->bd_bitmap)
#define EXT4_MB_BUDDY(e4b)	((e4b)->bd_buddy)

static inline ext4_fsblk_t ext4_grp_offs_to_block(struct super_block *sb,
					struct ext4_free_extent *fex)
{
	return ext4_group_first_block_no(sb, fex->fe_group) + fex->fe_start;
}
#endif
