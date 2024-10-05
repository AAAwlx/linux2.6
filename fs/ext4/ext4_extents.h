/*
 * Copyright (c) 2003-2006, Cluster File Systems, Inc, info@clusterfs.com
 * Written by Alex Tomas <alex@clusterfs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-
 */

#ifndef _EXT4_EXTENTS
#define _EXT4_EXTENTS

#include "ext4.h"

/*
 * With AGGRESSIVE_TEST defined, the capacity of index/leaf blocks
 * becomes very small, so index split, in-depth growing and
 * other hard changes happen much more often.
 * This is for debug purposes only.
 */
#define AGGRESSIVE_TEST_

/*
 * With EXTENTS_STATS defined, the number of blocks and extents
 * are collected in the truncate path. They'll be shown at
 * umount time.
 */
#define EXTENTS_STATS__

/*
 * If CHECK_BINSEARCH is defined, then the results of the binary search
 * will also be checked by linear search.
 */
#define CHECK_BINSEARCH__

/*
 * Turn on EXT_DEBUG to get lots of info about extents operations.
 */
#define EXT_DEBUG__
#ifdef EXT_DEBUG
#define ext_debug(a...)		printk(a)
#else
#define ext_debug(a...)
#endif

/*
 * If EXT_STATS is defined then stats numbers are collected.
 * These number will be displayed at umount time.
 */
#define EXT_STATS_


/*
 * ext4_inode 结构体中的 i_block 数组总共占用 60 字节。
 * 前 12 字节存储 ext4_extent_header 结构体；
 * 剩余部分存储 ext4_extent 数组。
 */

/*
 * 这是磁盘上的 Ext4 文件系统的 extent 结构。
 * 它用于树结构的底层（即叶子节点）。
 */
struct ext4_extent {
	__le32	ee_block;	/* 该 extent 覆盖的第一个逻辑块 */
	__le16	ee_len;		/* 该 extent 覆盖的块数量 */
	__le16	ee_start_hi;	/* 物理块地址的高 16 位 */
	__le32	ee_start_lo;	/* 物理块地址的低 32 位 */
};


/*
 * This is index on-disk structure.
 * It's used at all the levels except the bottom.
 */
/*
 * 这是索引节点的磁盘结构。
 * 它用于所有层级，除了最底层。
 */
struct ext4_extent_idx {
	__le32	ei_block;	/* 表示该ext4_extent_idx指向开始的逻辑块号 */
	__le32	ei_leaf_lo;	/* 指向下一层的物理块的指针，可以是叶子节点或下一个索引 */
	__le16	ei_leaf_hi;	/* 物理块地址的高 16 位 */
	__u16	ei_unused;	/* 保留字段，未使用 */
};
/*
 * Each block (leaves and indexes), even inode-stored has header.
 */
struct ext4_extent_header {
	__le16	eh_magic;	/* probably will support different formats */
	__le16	eh_entries;	/* number of valid entries */
	__le16	eh_max;		/* capacity of store in entries */
	__le16	eh_depth;	/* has tree real underlying blocks? */
	__le32	eh_generation;	/* generation of the tree */
};

#define EXT4_EXT_MAGIC		cpu_to_le16(0xf30a)

/*
 * Array of ext4_ext_path contains path to some extent.
 * Creation/lookup routines use it for traversal/splitting/etc.
 * Truncate uses it to simulate recursive walking.
 */
struct ext4_ext_path {
	ext4_fsblk_t			p_block;
	__u16				p_depth;
	struct ext4_extent		*p_ext;
	struct ext4_extent_idx		*p_idx;
	struct ext4_extent_header	*p_hdr;
	struct buffer_head		*p_bh;
};

/*
 * structure for external API
 */

#define EXT4_EXT_CACHE_NO	0
#define EXT4_EXT_CACHE_GAP	1
#define EXT4_EXT_CACHE_EXTENT	2

/*
 * to be called by ext4_ext_walk_space()
 * negative retcode - error
 * positive retcode - signal for ext4_ext_walk_space(), see below
 * callback must return valid extent (passed or newly created)
 */
typedef int (*ext_prepare_callback)(struct inode *, struct ext4_ext_path *,
					struct ext4_ext_cache *,
					struct ext4_extent *, void *);

#define EXT_CONTINUE   0
#define EXT_BREAK      1
#define EXT_REPEAT     2

/* Maximum logical block in a file; ext4_extent's ee_block is __le32 */
#define EXT_MAX_BLOCK	0xffffffff

/*
 * EXT_INIT_MAX_LEN is the maximum number of blocks we can have in an
 * initialized extent. This is 2^15 and not (2^16 - 1), since we use the
 * MSB of ee_len field in the extent datastructure to signify if this
 * particular extent is an initialized extent or an uninitialized (i.e.
 * preallocated).
 * EXT_UNINIT_MAX_LEN is the maximum number of blocks we can have in an
 * uninitialized extent.
 * If ee_len is <= 0x8000, it is an initialized extent. Otherwise, it is an
 * uninitialized one. In other words, if MSB of ee_len is set, it is an
 * uninitialized extent with only one special scenario when ee_len = 0x8000.
 * In this case we can not have an uninitialized extent of zero length and
 * thus we make it as a special case of initialized extent with 0x8000 length.
 * This way we get better extent-to-group alignment for initialized extents.
 * Hence, the maximum number of blocks we can have in an *initialized*
 * extent is 2^15 (32768) and in an *uninitialized* extent is 2^15-1 (32767).
 */
#define EXT_INIT_MAX_LEN	(1UL << 15)
#define EXT_UNINIT_MAX_LEN	(EXT_INIT_MAX_LEN - 1)


#define EXT_FIRST_EXTENT(__hdr__) \
	((struct ext4_extent *) (((char *) (__hdr__)) +		\
				 sizeof(struct ext4_extent_header)))
#define EXT_FIRST_INDEX(__hdr__) \
	((struct ext4_extent_idx *) (((char *) (__hdr__)) +	\
				     sizeof(struct ext4_extent_header)))
#define EXT_HAS_FREE_INDEX(__path__) \
	(le16_to_cpu((__path__)->p_hdr->eh_entries) \
				     < le16_to_cpu((__path__)->p_hdr->eh_max))
#define EXT_LAST_EXTENT(__hdr__) \
	(EXT_FIRST_EXTENT((__hdr__)) + le16_to_cpu((__hdr__)->eh_entries) - 1)
#define EXT_LAST_INDEX(__hdr__) \
	(EXT_FIRST_INDEX((__hdr__)) + le16_to_cpu((__hdr__)->eh_entries) - 1)
#define EXT_MAX_EXTENT(__hdr__) \
	(EXT_FIRST_EXTENT((__hdr__)) + le16_to_cpu((__hdr__)->eh_max) - 1)
#define EXT_MAX_INDEX(__hdr__) \
	(EXT_FIRST_INDEX((__hdr__)) + le16_to_cpu((__hdr__)->eh_max) - 1)

static inline struct ext4_extent_header *ext_inode_hdr(struct inode *inode)
{
	return (struct ext4_extent_header *) EXT4_I(inode)->i_data;
}

static inline struct ext4_extent_header *ext_block_hdr(struct buffer_head *bh)
{
	return (struct ext4_extent_header *) bh->b_data;
}

static inline unsigned short ext_depth(struct inode *inode)
{
	return le16_to_cpu(ext_inode_hdr(inode)->eh_depth);
}

static inline void
ext4_ext_invalidate_cache(struct inode *inode)
{
	EXT4_I(inode)->i_cached_extent.ec_type = EXT4_EXT_CACHE_NO;
}

static inline void ext4_ext_mark_uninitialized(struct ext4_extent *ext)
{
	/* We can not have an uninitialized extent of zero length! */
	BUG_ON((le16_to_cpu(ext->ee_len) & ~EXT_INIT_MAX_LEN) == 0);
	ext->ee_len |= cpu_to_le16(EXT_INIT_MAX_LEN);
}

static inline int ext4_ext_is_uninitialized(struct ext4_extent *ext)
{
	/* Extent with ee_len of 0x8000 is treated as an initialized extent */
	return (le16_to_cpu(ext->ee_len) > EXT_INIT_MAX_LEN);
}

/**
 * ext4_ext_get_actual_len - 获取实际的区间长度。
 * @ext: 指向要检索长度的区间结构的指针。
 *
 * 此函数根据存储的长度值计算区间的实际长度。长度以一种方式存储，
 * 用于区分已初始化和未初始化的长度。如果长度小于或等于 EXT_INIT_MAX_LEN，
 * 则直接返回该长度。否则，通过从存储的长度中减去 EXT_INIT_MAX_LEN 
 * 来计算实际长度。
 *
 * 返回: 区间的实际长度。
 */
static inline int ext4_ext_get_actual_len(struct ext4_extent *ext)
{
    // 检查区间的长度是否小于或等于最大初始化长度
	return (le16_to_cpu(ext->ee_len) <= EXT_INIT_MAX_LEN ?
		// 如果是，则直接返回该长度
		le16_to_cpu(ext->ee_len) :
		// 否则，通过减去初始化最大长度来计算实际长度
		(le16_to_cpu(ext->ee_len) - EXT_INIT_MAX_LEN));
}
static inline void ext4_ext_mark_initialized(struct ext4_extent *ext)
{
	ext->ee_len = cpu_to_le16(ext4_ext_get_actual_len(ext));
}

/*
 * 根据 inode 和逻辑块数量，计算分配新扩展所需的元数据数量。
 */
extern int ext4_ext_calc_metadata_amount(struct inode *inode, sector_t lblocks);

/*
 * 从给定的 extent 结构中获取物理块号。
 */
extern ext4_fsblk_t ext_pblock(struct ext4_extent *ex);

/*
 * 从 extent 索引节点中获取物理块号。
 */
extern ext4_fsblk_t idx_pblock(struct ext4_extent_idx *idx);

/*
 * 将物理块号存储到给定的 extent 结构中。
 */
extern void ext4_ext_store_pblock(struct ext4_extent *ex, ext4_fsblk_t block);

/*
 * 初始化给定 inode 的 extent 树结构。
 */
extern int ext4_extent_tree_init(handle_t *handle, struct inode *inode);

/*
 * 计算给定路径上单个扩展的所需操作信用数。
 */
extern int ext4_ext_calc_credits_for_single_extent(struct inode *inode, int num, struct ext4_ext_path *path);

/*
 * 检查两个 extent 是否可以合并。
 */
extern int ext4_can_extents_be_merged(struct inode *inode, struct ext4_extent *ex1, struct ext4_extent *ex2);

/*
 * 尝试合并给定路径上的两个 extent。
 */
extern int ext4_ext_try_to_merge(struct inode *inode, struct ext4_ext_path *path, struct ext4_extent *ex);

/*
 * 检查给定的 extent 是否与现有的 extent 重叠。
 */
extern unsigned int ext4_ext_check_overlap(struct inode *inode, struct ext4_extent *ex, struct ext4_ext_path *path);

/*
 * 插入一个新的 extent 到给定路径的 extent 树中。
 */
extern int ext4_ext_insert_extent(handle_t *handle, struct inode *inode, struct ext4_ext_path *path, struct ext4_extent *ex, int flags);

/*
 * 遍历 inode 的空间区域，执行用户提供的回调函数。
 */
extern int ext4_ext_walk_space(struct inode *inode, ext4_lblk_t start, ext4_lblk_t end, ext_prepare_callback callback, void *data);

/*
 * 查找给定逻辑块号对应的 extent。
 */
extern struct ext4_ext_path *ext4_ext_find_extent(struct inode *inode, ext4_lblk_t lblk, struct ext4_ext_path *path);

/*
 * 在 extent 树中向左搜索，查找最近的 extent。
 */
extern int ext4_ext_search_left(struct inode *inode, struct ext4_ext_path *path, ext4_lblk_t *lblk, ext4_fsblk_t *pblk);

/*
 * 在 extent 树中向右搜索，查找最近的 extent。
 */
extern int ext4_ext_search_right(struct inode *inode, struct ext4_ext_path *path, ext4_lblk_t *lblk, ext4_fsblk_t *pblk);

/*
 * 释放给定路径上的所有引用。
 */
extern void ext4_ext_drop_refs(struct ext4_ext_path *path);

/*
 * 检查 inode 是否具有有效的 extent 结构。
 */
extern int ext4_ext_check_inode(struct inode *inode);
#endif /* _EXT4_EXTENTS */

