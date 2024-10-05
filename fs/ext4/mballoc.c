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


/*
 * mballoc.c contains the multiblocks allocation routines
 */

#include "mballoc.h"
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <trace/events/ext4.h>

/*
 * MUSTDO:
 *   - test ext4_ext_search_left() and ext4_ext_search_right()
 *   - search for metadata in few groups
 *
 * TODO v4:
 *   - normalization should take into account whether file is still open
 *   - discard preallocations if no free space left (policy?)
 *   - don't normalize tails
 *   - quota
 *   - reservation for superuser
 *
 * TODO v3:
 *   - bitmap read-ahead (proposed by Oleg Drokin aka green)
 *   - track min/max extents in each group for better group selection
 *   - mb_mark_used() may allocate chunk right after splitting buddy
 *   - tree of groups sorted by number of free blocks
 *   - error handling
 */

/*
 * The allocation request involve request for multiple number of blocks
 * near to the goal(block) value specified.
 *
 * During initialization phase of the allocator we decide to use the
 * group preallocation or inode preallocation depending on the size of
 * the file. The size of the file could be the resulting file size we
 * would have after allocation, or the current file size, which ever
 * is larger. If the size is less than sbi->s_mb_stream_request we
 * select to use the group preallocation. The default value of
 * s_mb_stream_request is 16 blocks. This can also be tuned via
 * /sys/fs/ext4/<partition>/mb_stream_req. The value is represented in
 * terms of number of blocks.
 *
 * The main motivation for having small file use group preallocation is to
 * ensure that we have small files closer together on the disk.
 *
 * First stage the allocator looks at the inode prealloc list,
 * ext4_inode_info->i_prealloc_list, which contains list of prealloc
 * spaces for this particular inode. The inode prealloc space is
 * represented as:
 *
 * pa_lstart -> the logical start block for this prealloc space
 * pa_pstart -> the physical start block for this prealloc space
 * pa_len    -> length for this prealloc space
 * pa_free   ->  free space available in this prealloc space
 *
 * The inode preallocation space is used looking at the _logical_ start
 * block. If only the logical file block falls within the range of prealloc
 * space we will consume the particular prealloc space. This make sure that
 * that the we have contiguous physical blocks representing the file blocks
 *
 * The important thing to be noted in case of inode prealloc space is that
 * we don't modify the values associated to inode prealloc space except
 * pa_free.
 *
 * If we are not able to find blocks in the inode prealloc space and if we
 * have the group allocation flag set then we look at the locality group
 * prealloc space. These are per CPU prealloc list repreasented as
 *
 * ext4_sb_info.s_locality_groups[smp_processor_id()]
 *
 * The reason for having a per cpu locality group is to reduce the contention
 * between CPUs. It is possible to get scheduled at this point.
 *
 * The locality group prealloc space is used looking at whether we have
 * enough free space (pa_free) withing the prealloc space.
 *
 * If we can't allocate blocks via inode prealloc or/and locality group
 * prealloc then we look at the buddy cache. The buddy cache is represented
 * by ext4_sb_info.s_buddy_cache (struct inode) whose file offset gets
 * mapped to the buddy and bitmap information regarding different
 * groups. The buddy information is attached to buddy cache inode so that
 * we can access them through the page cache. The information regarding
 * each group is loaded via ext4_mb_load_buddy.  The information involve
 * block bitmap and buddy information. The information are stored in the
 * inode as:
 *
 *  {                        page                        }
 *  [ group 0 bitmap][ group 0 buddy] [group 1][ group 1]...
 *
 *
 * one block each for bitmap and buddy information.  So for each group we
 * take up 2 blocks. A page can contain blocks_per_page (PAGE_CACHE_SIZE /
 * blocksize) blocks.  So it can have information regarding groups_per_page
 * which is blocks_per_page/2
 *
 * The buddy cache inode is not stored on disk. The inode is thrown
 * away when the filesystem is unmounted.
 *
 * We look for count number of blocks in the buddy cache. If we were able
 * to locate that many free blocks we return with additional information
 * regarding rest of the contiguous physical block available
 *
 * Before allocating blocks via buddy cache we normalize the request
 * blocks. This ensure we ask for more blocks that we needed. The extra
 * blocks that we get after allocation is added to the respective prealloc
 * list. In case of inode preallocation we follow a list of heuristics
 * based on file size. This can be found in ext4_mb_normalize_request. If
 * we are doing a group prealloc we try to normalize the request to
 * sbi->s_mb_group_prealloc. Default value of s_mb_group_prealloc is
 * 512 blocks. This can be tuned via
 * /sys/fs/ext4/<partition/mb_group_prealloc. The value is represented in
 * terms of number of blocks. If we have mounted the file system with -O
 * stripe=<value> option the group prealloc request is normalized to the
 * stripe value (sbi->s_stripe)
 *
 * The regular allocator(using the buddy cache) supports few tunables.
 *
 * /sys/fs/ext4/<partition>/mb_min_to_scan
 * /sys/fs/ext4/<partition>/mb_max_to_scan
 * /sys/fs/ext4/<partition>/mb_order2_req
 *
 * The regular allocator uses buddy scan only if the request len is power of
 * 2 blocks and the order of allocation is >= sbi->s_mb_order2_reqs. The
 * value of s_mb_order2_reqs can be tuned via
 * /sys/fs/ext4/<partition>/mb_order2_req.  If the request len is equal to
 * stripe size (sbi->s_stripe), we try to search for contiguous block in
 * stripe size. This should result in better allocation on RAID setups. If
 * not, we search in the specific group using bitmap for best extents. The
 * tunable min_to_scan and max_to_scan control the behaviour here.
 * min_to_scan indicate how long the mballoc __must__ look for a best
 * extent and max_to_scan indicates how long the mballoc __can__ look for a
 * best extent in the found extents. Searching for the blocks starts with
 * the group specified as the goal value in allocation context via
 * ac_g_ex. Each group is first checked based on the criteria whether it
 * can used for allocation. ext4_mb_good_group explains how the groups are
 * checked.
 *
 * Both the prealloc space are getting populated as above. So for the first
 * request we will hit the buddy cache which will result in this prealloc
 * space getting filled. The prealloc space is then later used for the
 * subsequent request.
 */

/*
 * mballoc operates on the following data:
 *  - on-disk bitmap
 *  - in-core buddy (actually includes buddy and bitmap)
 *  - preallocation descriptors (PAs)
 *
 * there are two types of preallocations:
 *  - inode
 *    assiged to specific inode and can be used for this inode only.
 *    it describes part of inode's space preallocated to specific
 *    physical blocks. any block from that preallocated can be used
 *    independent. the descriptor just tracks number of blocks left
 *    unused. so, before taking some block from descriptor, one must
 *    make sure corresponded logical block isn't allocated yet. this
 *    also means that freeing any block within descriptor's range
 *    must discard all preallocated blocks.
 *  - locality group
 *    assigned to specific locality group which does not translate to
 *    permanent set of inodes: inode can join and leave group. space
 *    from this type of preallocation can be used for any inode. thus
 *    it's consumed from the beginning to the end.
 *
 * relation between them can be expressed as:
 *    in-core buddy = on-disk bitmap + preallocation descriptors
 *
 * this mean blocks mballoc considers used are:
 *  - allocated blocks (persistent)
 *  - preallocated blocks (non-persistent)
 *
 * consistency in mballoc world means that at any time a block is either
 * free or used in ALL structures. notice: "any time" should not be read
 * literally -- time is discrete and delimited by locks.
 *
 *  to keep it simple, we don't use block numbers, instead we count number of
 *  blocks: how many blocks marked used/free in on-disk bitmap, buddy and PA.
 *
 * all operations can be expressed as:
 *  - init buddy:			buddy = on-disk + PAs
 *  - new PA:				buddy += N; PA = N
 *  - use inode PA:			on-disk += N; PA -= N
 *  - discard inode PA			buddy -= on-disk - PA; PA = 0
 *  - use locality group PA		on-disk += N; PA -= N
 *  - discard locality group PA		buddy -= PA; PA = 0
 *  note: 'buddy -= on-disk - PA' is used to show that on-disk bitmap
 *        is used in real operation because we can't know actual used
 *        bits from PA, only from on-disk bitmap
 *
 * if we follow this strict logic, then all operations above should be atomic.
 * given some of them can block, we'd have to use something like semaphores
 * killing performance on high-end SMP hardware. let's try to relax it using
 * the following knowledge:
 *  1) if buddy is referenced, it's already initialized
 *  2) while block is used in buddy and the buddy is referenced,
 *     nobody can re-allocate that block
 *  3) we work on bitmaps and '+' actually means 'set bits'. if on-disk has
 *     bit set and PA claims same block, it's OK. IOW, one can set bit in
 *     on-disk bitmap if buddy has same bit set or/and PA covers corresponded
 *     block
 *
 * so, now we're building a concurrency table:
 *  - init buddy vs.
 *    - new PA
 *      blocks for PA are allocated in the buddy, buddy must be referenced
 *      until PA is linked to allocation group to avoid concurrent buddy init
 *    - use inode PA
 *      we need to make sure that either on-disk bitmap or PA has uptodate data
 *      given (3) we care that PA-=N operation doesn't interfere with init
 *    - discard inode PA
 *      the simplest way would be to have buddy initialized by the discard
 *    - use locality group PA
 *      again PA-=N must be serialized with init
 *    - discard locality group PA
 *      the simplest way would be to have buddy initialized by the discard
 *  - new PA vs.
 *    - use inode PA
 *      i_data_sem serializes them
 *    - discard inode PA
 *      discard process must wait until PA isn't used by another process
 *    - use locality group PA
 *      some mutex should serialize them
 *    - discard locality group PA
 *      discard process must wait until PA isn't used by another process
 *  - use inode PA
 *    - use inode PA
 *      i_data_sem or another mutex should serializes them
 *    - discard inode PA
 *      discard process must wait until PA isn't used by another process
 *    - use locality group PA
 *      nothing wrong here -- they're different PAs covering different blocks
 *    - discard locality group PA
 *      discard process must wait until PA isn't used by another process
 *
 * now we're ready to make few consequences:
 *  - PA is referenced and while it is no discard is possible
 *  - PA is referenced until block isn't marked in on-disk bitmap
 *  - PA changes only after on-disk bitmap
 *  - discard must not compete with init. either init is done before
 *    any discard or they're serialized somehow
 *  - buddy init as sum of on-disk bitmap and PAs is done atomically
 *
 * a special case when we've used PA to emptiness. no need to modify buddy
 * in this case, but we should care about concurrent init
 *
 */

 /*
 * Logic in few words:
 *
 *  - allocation:
 *    load group
 *    find blocks
 *    mark bits in on-disk bitmap
 *    release group
 *
 *  - use preallocation:
 *    find proper PA (per-inode or group)
 *    load group
 *    mark bits in on-disk bitmap
 *    release group
 *    release PA
 *
 *  - free:
 *    load group
 *    mark bits in on-disk bitmap
 *    release group
 *
 *  - discard preallocations in group:
 *    mark PAs deleted
 *    move them onto local list
 *    load on-disk bitmap
 *    load group
 *    remove PA from object (inode or locality group)
 *    mark free blocks in-core
 *
 *  - discard inode's preallocations:
 */

/*
 * Locking rules
 *
 * Locks:
 *  - bitlock on a group	(group)
 *  - object (inode/locality)	(object)
 *  - per-pa lock		(pa)
 *
 * Paths:
 *  - new pa
 *    object
 *    group
 *
 *  - find and use pa:
 *    pa
 *
 *  - release consumed pa:
 *    pa
 *    group
 *    object
 *
 *  - generate in-core bitmap:
 *    group
 *        pa
 *
 *  - discard all for given object (inode, locality group):
 *    object
 *        pa
 *    group
 *
 *  - discard all for given group:
 *    group
 *        pa
 *    group
 *        object
 *
 */
static struct kmem_cache *ext4_pspace_cachep;
static struct kmem_cache *ext4_ac_cachep;
static struct kmem_cache *ext4_free_ext_cachep;
static void ext4_mb_generate_from_pa(struct super_block *sb, void *bitmap,
					ext4_group_t group);
static void ext4_mb_generate_from_freelist(struct super_block *sb, void *bitmap,
						ext4_group_t group);
static void release_blocks_on_commit(journal_t *journal, transaction_t *txn);

static inline void *mb_correct_addr_and_bit(int *bit, void *addr)
{
#if BITS_PER_LONG == 64
	*bit += ((unsigned long) addr & 7UL) << 3;
	addr = (void *) ((unsigned long) addr & ~7UL);
#elif BITS_PER_LONG == 32
	*bit += ((unsigned long) addr & 3UL) << 3;
	addr = (void *) ((unsigned long) addr & ~3UL);
#else
#error "how many bits you are?!"
#endif
	return addr;
}

static inline int mb_test_bit(int bit, void *addr)
{
	/*
	 * ext4_test_bit on architecture like powerpc
	 * needs unsigned long aligned address
	 */
	addr = mb_correct_addr_and_bit(&bit, addr);
	return ext4_test_bit(bit, addr);
}

static inline void mb_set_bit(int bit, void *addr)
{
	addr = mb_correct_addr_and_bit(&bit, addr);
	ext4_set_bit(bit, addr);
}

static inline void mb_clear_bit(int bit, void *addr)
{
	addr = mb_correct_addr_and_bit(&bit, addr);
	ext4_clear_bit(bit, addr);
}

static inline int mb_find_next_zero_bit(void *addr, int max, int start)
{
	int fix = 0, ret, tmpmax;
	addr = mb_correct_addr_and_bit(&fix, addr);
	tmpmax = max + fix;
	start += fix;

	ret = ext4_find_next_zero_bit(addr, tmpmax, start) - fix;
	if (ret > max)
		return max;
	return ret;
}

static inline int mb_find_next_bit(void *addr, int max, int start)
{
	int fix = 0, ret, tmpmax;
	addr = mb_correct_addr_and_bit(&fix, addr);
	tmpmax = max + fix;
	start += fix;

	ret = ext4_find_next_bit(addr, tmpmax, start) - fix;
	if (ret > max)
		return max;
	return ret;
}

static void *mb_find_buddy(struct ext4_buddy *e4b, int order, int *max)
{
	char *bb;

	BUG_ON(EXT4_MB_BITMAP(e4b) == EXT4_MB_BUDDY(e4b));
	BUG_ON(max == NULL);

	if (order > e4b->bd_blkbits + 1) {
		*max = 0;
		return NULL;
	}

	/* at order 0 we see each particular block */
	*max = 1 << (e4b->bd_blkbits + 3);
	if (order == 0)
		return EXT4_MB_BITMAP(e4b);

	bb = EXT4_MB_BUDDY(e4b) + EXT4_SB(e4b->bd_sb)->s_mb_offsets[order];
	*max = EXT4_SB(e4b->bd_sb)->s_mb_maxs[order];

	return bb;
}

#ifdef DOUBLE_CHECK
static void mb_free_blocks_double(struct inode *inode, struct ext4_buddy *e4b,
			   int first, int count)
{
	int i;
	struct super_block *sb = e4b->bd_sb;

	if (unlikely(e4b->bd_info->bb_bitmap == NULL))
		return;
	assert_spin_locked(ext4_group_lock_ptr(sb, e4b->bd_group));
	for (i = 0; i < count; i++) {
		if (!mb_test_bit(first + i, e4b->bd_info->bb_bitmap)) {
			ext4_fsblk_t blocknr;

			blocknr = ext4_group_first_block_no(sb, e4b->bd_group);
			blocknr += first + i;
			ext4_grp_locked_error(sb, e4b->bd_group,
				   __func__, "double-free of inode"
				   " %lu's block %llu(bit %u in group %u)",
				   inode ? inode->i_ino : 0, blocknr,
				   first + i, e4b->bd_group);
		}
		mb_clear_bit(first + i, e4b->bd_info->bb_bitmap);
	}
}

static void mb_mark_used_double(struct ext4_buddy *e4b, int first, int count)
{
	int i;

	if (unlikely(e4b->bd_info->bb_bitmap == NULL))
		return;
	assert_spin_locked(ext4_group_lock_ptr(e4b->bd_sb, e4b->bd_group));
	for (i = 0; i < count; i++) {
		BUG_ON(mb_test_bit(first + i, e4b->bd_info->bb_bitmap));
		mb_set_bit(first + i, e4b->bd_info->bb_bitmap);
	}
}

static void mb_cmp_bitmaps(struct ext4_buddy *e4b, void *bitmap)
{
	if (memcmp(e4b->bd_info->bb_bitmap, bitmap, e4b->bd_sb->s_blocksize)) {
		unsigned char *b1, *b2;
		int i;
		b1 = (unsigned char *) e4b->bd_info->bb_bitmap;
		b2 = (unsigned char *) bitmap;
		for (i = 0; i < e4b->bd_sb->s_blocksize; i++) {
			if (b1[i] != b2[i]) {
				printk(KERN_ERR "corruption in group %u "
				       "at byte %u(%u): %x in copy != %x "
				       "on disk/prealloc\n",
				       e4b->bd_group, i, i * 8, b1[i], b2[i]);
				BUG();
			}
		}
	}
}

#else
static inline void mb_free_blocks_double(struct inode *inode,
				struct ext4_buddy *e4b, int first, int count)
{
	return;
}
static inline void mb_mark_used_double(struct ext4_buddy *e4b,
						int first, int count)
{
	return;
}
static inline void mb_cmp_bitmaps(struct ext4_buddy *e4b, void *bitmap)
{
	return;
}
#endif

#ifdef AGGRESSIVE_CHECK

#define MB_CHECK_ASSERT(assert)						\
do {									\
	if (!(assert)) {						\
		printk(KERN_EMERG					\
			"Assertion failure in %s() at %s:%d: \"%s\"\n",	\
			function, file, line, # assert);		\
		BUG();							\
	}								\
} while (0)

static int __mb_check_buddy(struct ext4_buddy *e4b, char *file,
				const char *function, int line)
{
	struct super_block *sb = e4b->bd_sb;
	int order = e4b->bd_blkbits + 1;
	int max;
	int max2;
	int i;
	int j;
	int k;
	int count;
	struct ext4_group_info *grp;
	int fragments = 0;
	int fstart;
	struct list_head *cur;
	void *buddy;
	void *buddy2;

	{
		static int mb_check_counter;
		if (mb_check_counter++ % 100 != 0)
			return 0;
	}

	while (order > 1) {
		buddy = mb_find_buddy(e4b, order, &max);
		MB_CHECK_ASSERT(buddy);
		buddy2 = mb_find_buddy(e4b, order - 1, &max2);
		MB_CHECK_ASSERT(buddy2);
		MB_CHECK_ASSERT(buddy != buddy2);
		MB_CHECK_ASSERT(max * 2 == max2);

		count = 0;
		for (i = 0; i < max; i++) {

			if (mb_test_bit(i, buddy)) {
				/* only single bit in buddy2 may be 1 */
				if (!mb_test_bit(i << 1, buddy2)) {
					MB_CHECK_ASSERT(
						mb_test_bit((i<<1)+1, buddy2));
				} else if (!mb_test_bit((i << 1) + 1, buddy2)) {
					MB_CHECK_ASSERT(
						mb_test_bit(i << 1, buddy2));
				}
				continue;
			}

			/* both bits in buddy2 must be 0 */
			MB_CHECK_ASSERT(mb_test_bit(i << 1, buddy2));
			MB_CHECK_ASSERT(mb_test_bit((i << 1) + 1, buddy2));

			for (j = 0; j < (1 << order); j++) {
				k = (i * (1 << order)) + j;
				MB_CHECK_ASSERT(
					!mb_test_bit(k, EXT4_MB_BITMAP(e4b)));
			}
			count++;
		}
		MB_CHECK_ASSERT(e4b->bd_info->bb_counters[order] == count);
		order--;
	}

	fstart = -1;
	buddy = mb_find_buddy(e4b, 0, &max);
	for (i = 0; i < max; i++) {
		if (!mb_test_bit(i, buddy)) {
			MB_CHECK_ASSERT(i >= e4b->bd_info->bb_first_free);
			if (fstart == -1) {
				fragments++;
				fstart = i;
			}
			continue;
		}
		fstart = -1;
		/* check used bits only */
		for (j = 0; j < e4b->bd_blkbits + 1; j++) {
			buddy2 = mb_find_buddy(e4b, j, &max2);
			k = i >> j;
			MB_CHECK_ASSERT(k < max2);
			MB_CHECK_ASSERT(mb_test_bit(k, buddy2));
		}
	}
	MB_CHECK_ASSERT(!EXT4_MB_GRP_NEED_INIT(e4b->bd_info));
	MB_CHECK_ASSERT(e4b->bd_info->bb_fragments == fragments);

	grp = ext4_get_group_info(sb, e4b->bd_group);
	buddy = mb_find_buddy(e4b, 0, &max);
	list_for_each(cur, &grp->bb_prealloc_list) {
		ext4_group_t groupnr;
		struct ext4_prealloc_space *pa;
		pa = list_entry(cur, struct ext4_prealloc_space, pa_group_list);
		ext4_get_group_no_and_offset(sb, pa->pa_pstart, &groupnr, &k);
		MB_CHECK_ASSERT(groupnr == e4b->bd_group);
		for (i = 0; i < pa->pa_len; i++)
			MB_CHECK_ASSERT(mb_test_bit(k + i, buddy));
	}
	return 0;
}
#undef MB_CHECK_ASSERT
#define mb_check_buddy(e4b) __mb_check_buddy(e4b,	\
					__FILE__, __func__, __LINE__)
#else
#define mb_check_buddy(e4b)
#endif

/* FIXME!! need more doc */
static void ext4_mb_mark_free_simple(struct super_block *sb,
                                      void *buddy, ext4_grpblk_t first, ext4_grpblk_t len,
                                      struct ext4_group_info *grp)
{
    struct ext4_sb_info *sbi = EXT4_SB(sb); // 获取超级块信息
    ext4_grpblk_t min; // 需要标记的最小块数
    ext4_grpblk_t max; // 可覆盖的最大块数
    ext4_grpblk_t chunk; // 当前标记的块数
    unsigned short border; // 边界标识

    // 确保标记的块数不超过块组的最大块数
    BUG_ON(len > EXT4_BLOCKS_PER_GROUP(sb));

    border = 2 << sb->s_blocksize_bits; // 设置边界，边界是块大小的 4 倍

    while (len > 0) {
        // 找出当前块位置可以覆盖的最大块数
        max = ffs(first | border) - 1;

        // 找出需要标记的块数的对数（以 2 为底）
        min = fls(len) - 1;

        // 如果可覆盖的最大块数小于需要标记的块数，则取最大值
        if (max < min)
            min = max;

        chunk = 1 << min; // 计算当前要标记的块数

        // 仅标记多块的块数
        grp->bb_counters[min]++; // 更新块计数器
        if (min > 0)
            mb_clear_bit(first >> min,
                         buddy + sbi->s_mb_offsets[min]); // 清除位图中的相应位

        len -= chunk; // 减少剩余需要标记的块数
        first += chunk; // 更新当前标记的起始块
    }
}

static noinline_for_stack
void ext4_mb_generate_buddy(struct super_block *sb,
                             void *buddy, void *bitmap, ext4_group_t group)
{
    struct ext4_group_info *grp = ext4_get_group_info(sb, group);
    ext4_grpblk_t max = EXT4_BLOCKS_PER_GROUP(sb); // 每个块组的最大块数
    ext4_grpblk_t i = 0;  // 当前块索引
    ext4_grpblk_t first;  // 连续空闲块的起始索引
    ext4_grpblk_t len;    // 连续空闲块的长度
    unsigned free = 0;    // 统计空闲块的总数
    unsigned fragments = 0; // 统计空闲块的片段数
    unsigned long long period = get_cycles(); // 获取当前周期数

    // 从位图中查找下一个空闲块
    i = mb_find_next_zero_bit(bitmap, max, 0);
    grp->bb_first_free = i; // 设置块组中的第一个空闲块
    while (i < max) {
        fragments++; // 增加片段计数
        first = i;  // 记录当前连续空闲块的起始位置
        i = mb_find_next_bit(bitmap, max, i); // 查找下一个已用块
        len = i - first; // 计算当前连续空闲块的长度
        free += len; // 更新空闲块总数

        // 如果有多个连续空闲块，标记为简单空闲块
        if (len > 1)
            ext4_mb_mark_free_simple(sb, buddy, first, len, grp);
        else
            grp->bb_counters[0]++; // 否则增加单个空闲块计数

        // 查找下一个空闲块
        if (i < max)
            i = mb_find_next_zero_bit(bitmap, max, i);
    }
    grp->bb_fragments = fragments; // 更新片段计数

    // 检查空闲块数是否与组描述符中的值一致
    if (free != grp->bb_free) {
        ext4_grp_locked_error(sb, group, __func__,
            "EXT4-fs: group %u: %u blocks in bitmap, %u in gd",
            group, free, grp->bb_free);
        /*
         * 如果继续处理，认为组描述符损坏，
         * 使用位图中的值更新 bb_free
         */
        grp->bb_free = free;
    }

    // 清除需要初始化的标志
    clear_bit(EXT4_GROUP_INFO_NEED_INIT_BIT, &(grp->bb_state));

    // 计算并更新生成 buddy 的周期时间
    period = get_cycles() - period;
    spin_lock(&EXT4_SB(sb)->s_bal_lock); // 加锁以更新全局统计信息
    EXT4_SB(sb)->s_mb_buddies_generated++; // 增加生成计数
    EXT4_SB(sb)->s_mb_generation_time += period; // 累加时间
    spin_unlock(&EXT4_SB(sb)->s_bal_lock); // 解锁
}


/* The buddy information is attached the buddy cache inode
 * for convenience. The information regarding each group
 * is loaded via ext4_mb_load_buddy. The information involve
 * block bitmap and buddy information. The information are
 * stored in the inode as
 *
 * {                        page                        }
 * [ group 0 bitmap][ group 0 buddy] [group 1][ group 1]...
 *
 *
 * one block each for bitmap and buddy information.
 * So for each group we take up 2 blocks. A page can
 * contain blocks_per_page (PAGE_CACHE_SIZE / blocksize)  blocks.
 * So it can have information regarding groups_per_page which
 * is blocks_per_page/2
 */

static int ext4_mb_init_cache(struct page *page, char *incore)
{
    // 定义变量
	ext4_group_t ngroups;           // 文件系统中的块组数量
	int blocksize;                  // 块大小
	int blocks_per_page;            // 每页包含的块数量
	int groups_per_page;            // 每页可缓存的块组数量
	int err = 0;                    // 错误代码
	int i;                          // 循环变量
	ext4_group_t first_group;       // 页中缓存的第一个块组
	int first_block;                // 页中缓存的第一个块号
	struct super_block *sb;         // 超级块结构指针
	struct buffer_head *bhs;        // 用于单个组的缓存块指针
	struct buffer_head **bh;        // 用于多个组的缓存块指针数组
	struct inode *inode;            // 索引节点指针
	char *data;                     // 用于临时存储块组信息的指针
	char *bitmap;                   // 块组位图指针

	// 调试信息：输出当前页面的索引
	mb_debug(1, "init page %lu\n", page->index);

	// 获取页面所属的 inode 和超级块信息
	inode = page->mapping->host;
	sb = inode->i_sb;

	// 获取文件系统中的块组数量和块大小
	ngroups = ext4_get_groups_count(sb);
	blocksize = 1 << inode->i_blkbits;

	// 计算每页的块数和每页可缓存的块组数量
	blocks_per_page = PAGE_CACHE_SIZE / blocksize;
	groups_per_page = blocks_per_page >> 1;  // 每组占用两个块
	if (groups_per_page == 0)
		groups_per_page = 1;  // 确保至少有一个块组

	// 为每个块组分配 buffer_heads
	if (groups_per_page > 1) {
		err = -ENOMEM;
		i = sizeof(struct buffer_head *) * groups_per_page;
		bh = kzalloc(i, GFP_NOFS);  // 分配内存
		if (bh == NULL)
			goto out;  // 如果分配失败，跳转到清理阶段
	} else
		bh = &bhs;  // 单个组的情况使用 bhs

	// 计算页中第一个块组的编号
	first_group = page->index * blocks_per_page / 2;

	// 读取该页面覆盖的所有块组到缓存中
	for (i = 0; i < groups_per_page; i++) {
		struct ext4_group_desc *desc;

		// 如果块组编号超出文件系统范围，退出循环
		if (first_group + i >= ngroups)
			break;

		// 获取块组描述符
		err = -EIO;
		desc = ext4_get_group_desc(sb, first_group + i, NULL);
		if (desc == NULL)
			goto out;

		// 获取块组位图的 buffer_head
		err = -ENOMEM;
		bh[i] = sb_getblk(sb, ext4_block_bitmap(sb, desc));
		if (bh[i] == NULL)
			goto out;

		// 如果位图已更新，跳过后续处理
		if (bitmap_uptodate(bh[i]))
			continue;

		// 加锁 buffer，并检查是否需要更新
		lock_buffer(bh[i]);
		if (bitmap_uptodate(bh[i])) {
			unlock_buffer(bh[i]);
			continue;
		}

		// 加锁块组，处理未初始化的块组
		ext4_lock_group(sb, first_group + i);
		if (desc->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
			// 初始化块组位图
			ext4_init_block_bitmap(sb, bh[i], first_group + i, desc);
			set_bitmap_uptodate(bh[i]);
			set_buffer_uptodate(bh[i]);
			ext4_unlock_group(sb, first_group + i);
			unlock_buffer(bh[i]);
			continue;
		}

		ext4_unlock_group(sb, first_group + i);

		// 如果 buffer 已更新，标记位图已更新
		if (buffer_uptodate(bh[i])) {
			set_bitmap_uptodate(bh[i]);
			unlock_buffer(bh[i]);
			continue;
		}

		// 提交 buffer 进行读取
		get_bh(bh[i]);
		set_bitmap_uptodate(bh[i]);
		bh[i]->b_end_io = end_buffer_read_sync;
		submit_bh(READ, bh[i]);
		mb_debug(1, "read bitmap for group %u\n", first_group + i);
	}

	// 等待 I/O 完成
	for (i = 0; i < groups_per_page && bh[i]; i++)
		wait_on_buffer(bh[i]);

	// 检查 I/O 是否成功
	err = -EIO;
	for (i = 0; i < groups_per_page && bh[i]; i++)
		if (!buffer_uptodate(bh[i]))
			goto out;

	err = 0;

	// 初始化页面内容，将整个页面设置为 0xff
	first_block = page->index * blocks_per_page;
	memset(page_address(page), 0xff, PAGE_CACHE_SIZE);

	// 遍历页面中的每个块并初始化
	for (i = 0; i < blocks_per_page; i++) {
		int group;
		struct ext4_group_info *grinfo;

		// 计算块所属的块组
		group = (first_block + i) >> 1;
		if (group >= ngroups)
			break;

		// 计算页面中的数据位置和位图指针
		data = page_address(page) + (i * blocksize);
		bitmap = bh[group - first_group]->b_data;

		// 处理 buddy 块
		if ((first_block + i) & 1) {
			BUG_ON(incore == NULL);
			mb_debug(1, "put buddy for group %u in page %lu/%x\n",
				group, page->index, i * blocksize);
			grinfo = ext4_get_group_info(sb, group);
			grinfo->bb_fragments = 0;
			memset(grinfo->bb_counters, 0,
			       sizeof(*grinfo->bb_counters) *
				(sb->s_blocksize_bits+2));
			ext4_lock_group(sb, group);
			ext4_mb_generate_buddy(sb, data, incore, group);
			ext4_unlock_group(sb, group);
			incore = NULL;
		} else {
			// 处理位图块
			BUG_ON(incore != NULL);
			mb_debug(1, "put bitmap for group %u in page %lu/%x\n",
				group, page->index, i * blocksize);

			ext4_lock_group(sb, group);
			memcpy(data, bitmap, blocksize);
			ext4_mb_generate_from_pa(sb, data, group);
			ext4_mb_generate_from_freelist(sb, data, group);
			ext4_unlock_group(sb, group);

			// 设置 incore，供后续 buddy 块生成
			incore = data;
		}
	}

	// 标记页面已更新
	SetPageUptodate(page);

out:
	// 释放 buffer_head
	if (bh) {
		for (i = 0; i < groups_per_page && bh[i]; i++)
			brelse(bh[i]);
		if (bh != &bhs)
			kfree(bh);
	}

	return err;
}

static noinline_for_stack
int ext4_mb_init_group(struct super_block *sb, ext4_group_t group)
{
    int ret = 0; // 返回值初始化为0
    void *bitmap; // 位图指针
    int blocks_per_page; // 每页块数
    int block, pnum, poff; // 块号、页号、偏移
    int num_grp_locked = 0; // 锁定的组数
    struct ext4_group_info *this_grp; // 当前组信息
    struct ext4_sb_info *sbi = EXT4_SB(sb); // 超级块信息
    struct inode *inode = sbi->s_buddy_cache; // 伙伴缓存的inode
    struct page *page = NULL, *bitmap_page = NULL; // 页指针

    mb_debug(1, "初始化组 %u\n", group); // 调试信息
    blocks_per_page = PAGE_CACHE_SIZE / sb->s_blocksize; // 计算每页的块数
    this_grp = ext4_get_group_info(sb, group); // 获取当前组的信息
    
    // 确保不会重新初始化已经锁定的组
    num_grp_locked = ext4_mb_get_buddy_cache_lock(sb, group);
    if (!EXT4_MB_GRP_NEED_INIT(this_grp)) {
        // 如果组已初始化，直接返回
        ret = 0;
        goto err;
    }
    
    // 计算当前组需要的块
    block = group * 2;
    pnum = block / blocks_per_page; // 页号
    poff = block % blocks_per_page; // 偏移量
    page = find_or_create_page(inode->i_mapping, pnum, GFP_NOFS); // 查找或创建页面
    if (page) {
        BUG_ON(page->mapping != inode->i_mapping); // 检查页面映射
        ret = ext4_mb_init_cache(page, NULL); // 初始化缓存
        if (ret) {
            unlock_page(page); // 解锁页面
            goto err;
        }
        unlock_page(page); // 解锁页面
    }
    if (page == NULL || !PageUptodate(page)) {
        ret = -EIO; // 处理错误
        goto err;
    }
    mark_page_accessed(page); // 标记页面已访问
    bitmap_page = page; // 设置位图页面
    bitmap = page_address(page) + (poff * sb->s_blocksize); // 获取位图地址

    // 初始化伙伴缓存
    block++;
    pnum = block / blocks_per_page; // 更新页号
    poff = block % blocks_per_page; // 更新偏移量
    page = find_or_create_page(inode->i_mapping, pnum, GFP_NOFS); // 查找或创建页面
    if (page == bitmap_page) {
        // 如果位图和伙伴在同一页面
        unlock_page(page); // 解锁页面
    } else if (page) {
        BUG_ON(page->mapping != inode->i_mapping); // 检查页面映射
        ret = ext4_mb_init_cache(page, bitmap); // 读取磁盘，并且初始化block bitmap
        if (ret) {
            unlock_page(page); // 解锁页面
            goto err;
        }
        unlock_page(page); // 解锁页面
    }
    if (page == NULL || !PageUptodate(page)) {
        ret = -EIO; // 处理错误
        goto err;
    }
    mark_page_accessed(page); // 标记页面已访问
err:
    ext4_mb_put_buddy_cache_lock(sb, group, num_grp_locked); // 释放锁
    if (bitmap_page)
        page_cache_release(bitmap_page); // 释放位图页面
    if (page)
        page_cache_release(page); // 释放页面
    return ret; // 返回结果
}


/**
 * ext4_mb_load_buddy - 加载指定组的 buddy 缓存
 * @sb: 超级块指针
 * @group: 要加载的块组编号
 * @e4b: ext4_buddy 结构体指针，用于存储加载后的 buddy 缓存
 *
 * 该函数用于加载指定组的 buddy 缓存以及位图缓存到内存中，供块分配器使用。
 * 
 * 主要步骤：
 * 1. 确定 buddy 缓存的页面号与偏移。
 * 2. 如果需要初始化组信息，则初始化块组。
 * 3. 查找或创建页，将 buddy 和位图数据加载到内存中。
 * 4. 成功加载后，将页地址和位图、buddy 信息存储在 e4b 结构中。
 *
 * 返回值：
 * 成功返回 0，失败返回负数错误码。
 */
static noinline_for_stack int
ext4_mb_load_buddy(struct super_block *sb, ext4_group_t group,
                   struct ext4_buddy *e4b)
{
    int blocks_per_page;
    int block;
    int pnum;
    int poff;
    struct page *page;
    int ret;
    struct ext4_group_info *grp;
    struct ext4_sb_info *sbi = EXT4_SB(sb);
    struct inode *inode = sbi->s_buddy_cache;

    mb_debug(1, "load group %u\n", group);

    // 计算每页能容纳的块数
    blocks_per_page = PAGE_CACHE_SIZE / sb->s_blocksize;
    grp = ext4_get_group_info(sb, group);

    // 初始化 ext4_buddy 结构体
    e4b->bd_blkbits = sb->s_blocksize_bits;
    e4b->bd_info = ext4_get_group_info(sb, group);
    e4b->bd_sb = sb;
    e4b->bd_group = group;
    e4b->bd_buddy_page = NULL;
    e4b->bd_bitmap_page = NULL;
    e4b->alloc_semp = &grp->alloc_sem;

repeat_load_buddy:
    down_read(e4b->alloc_semp);

    // 如果需要初始化块组，调用 ext4_mb_init_group 进行初始化
    if (unlikely(EXT4_MB_GRP_NEED_INIT(grp))) {
        up_read(e4b->alloc_semp);
        ret = ext4_mb_init_group(sb, group);
        if (ret)
            return ret;
        goto repeat_load_buddy;
    }

    // 计算存储 buddy 缓存的起始块号
    block = group * 2;
    pnum = block / blocks_per_page;
    poff = block % blocks_per_page;

    // 查找或创建 buddy 页
    page = find_get_page(inode->i_mapping, pnum);
    if (page == NULL || !PageUptodate(page)) {
        if (page)
            page_cache_release(page);
        page = find_or_create_page(inode->i_mapping, pnum, GFP_NOFS);
        if (page) {
            BUG_ON(page->mapping != inode->i_mapping);
            if (!PageUptodate(page)) {
                ret = ext4_mb_init_cache(page, NULL);
                if (ret) {
                    unlock_page(page);
                    goto err;
                }
                mb_cmp_bitmaps(e4b, page_address(page) +
                               (poff * sb->s_blocksize));
            }
            unlock_page(page);
        }
    }
    if (page == NULL || !PageUptodate(page)) {
        ret = -EIO;
        goto err;
    }
    e4b->bd_bitmap_page = page;
    e4b->bd_bitmap = page_address(page) + (poff * sb->s_blocksize);
    mark_page_accessed(page);

    // 处理 buddy 页
    block++;
    pnum = block / blocks_per_page;
    poff = block % blocks_per_page;

    page = find_get_page(inode->i_mapping, pnum);
    if (page == NULL || !PageUptodate(page)) {
        if (page)
            page_cache_release(page);
        page = find_or_create_page(inode->i_mapping, pnum, GFP_NOFS);
        if (page) {
            BUG_ON(page->mapping != inode->i_mapping);
            if (!PageUptodate(page)) {
                ret = ext4_mb_init_cache(page, e4b->bd_bitmap);
                if (ret) {
                    unlock_page(page);
                    goto err;
                }
            }
            unlock_page(page);
        }
    }
    if (page == NULL || !PageUptodate(page)) {
        ret = -EIO;
        goto err;
    }
    e4b->bd_buddy_page = page;
    e4b->bd_buddy = page_address(page) + (poff * sb->s_blocksize);
    mark_page_accessed(page);

    // 确保 buddy 和位图页已正确加载
    BUG_ON(e4b->bd_bitmap_page == NULL);
    BUG_ON(e4b->bd_buddy_page == NULL);

    return 0;

err:
    if (e4b->bd_bitmap_page)
        page_cache_release(e4b->bd_bitmap_page);
    if (e4b->bd_buddy_page)
        page_cache_release(e4b->bd_buddy_page);
    e4b->bd_buddy = NULL;
    e4b->bd_bitmap = NULL;

    // 解锁组分配信号量
    up_read(e4b->alloc_semp);
    return ret;
}

static void ext4_mb_release_desc(struct ext4_buddy *e4b)
{
	if (e4b->bd_bitmap_page)
		page_cache_release(e4b->bd_bitmap_page);
	if (e4b->bd_buddy_page)
		page_cache_release(e4b->bd_buddy_page);
	/* Done with the buddy cache */
	if (e4b->alloc_semp)
		up_read(e4b->alloc_semp);
}


static int mb_find_order_for_block(struct ext4_buddy *e4b, int block)
{
	int order = 1;
	void *bb;

	BUG_ON(EXT4_MB_BITMAP(e4b) == EXT4_MB_BUDDY(e4b));
	BUG_ON(block >= (1 << (e4b->bd_blkbits + 3)));

	bb = EXT4_MB_BUDDY(e4b);
	while (order <= e4b->bd_blkbits + 1) {
		block = block >> 1;
		if (!mb_test_bit(block, bb)) {
			/* this block is part of buddy of order 'order' */
			return order;
		}
		bb += 1 << (e4b->bd_blkbits - order);
		order++;
	}
	return 0;
}

static void mb_clear_bits(void *bm, int cur, int len)
{
	__u32 *addr;

	len = cur + len;
	while (cur < len) {
		if ((cur & 31) == 0 && (len - cur) >= 32) {
			/* fast path: clear whole word at once */
			addr = bm + (cur >> 3);
			*addr = 0;
			cur += 32;
			continue;
		}
		mb_clear_bit(cur, bm);
		cur++;
	}
}

static void mb_set_bits(void *bm, int cur, int len)
{
	__u32 *addr;

	len = cur + len;
	while (cur < len) {
		if ((cur & 31) == 0 && (len - cur) >= 32) {
			/* fast path: set whole word at once */
			addr = bm + (cur >> 3);
			*addr = 0xffffffff;
			cur += 32;
			continue;
		}
		mb_set_bit(cur, bm);
		cur++;
	}
}

static void mb_free_blocks(struct inode *inode, struct ext4_buddy *e4b,
			  int first, int count)
{
	int block = 0;
	int max = 0;
	int order;
	void *buddy;
	void *buddy2;
	struct super_block *sb = e4b->bd_sb;

	BUG_ON(first + count > (sb->s_blocksize << 3));
	assert_spin_locked(ext4_group_lock_ptr(sb, e4b->bd_group));
	mb_check_buddy(e4b);
	mb_free_blocks_double(inode, e4b, first, count);

	e4b->bd_info->bb_free += count;
	if (first < e4b->bd_info->bb_first_free)
		e4b->bd_info->bb_first_free = first;

	/* let's maintain fragments counter */
	if (first != 0)
		block = !mb_test_bit(first - 1, EXT4_MB_BITMAP(e4b));
	if (first + count < EXT4_SB(sb)->s_mb_maxs[0])
		max = !mb_test_bit(first + count, EXT4_MB_BITMAP(e4b));
	if (block && max)
		e4b->bd_info->bb_fragments--;
	else if (!block && !max)
		e4b->bd_info->bb_fragments++;

	/* let's maintain buddy itself */
	while (count-- > 0) {
		block = first++;
		order = 0;

		if (!mb_test_bit(block, EXT4_MB_BITMAP(e4b))) {
			ext4_fsblk_t blocknr;

			blocknr = ext4_group_first_block_no(sb, e4b->bd_group);
			blocknr += block;
			ext4_grp_locked_error(sb, e4b->bd_group,
				   __func__, "double-free of inode"
				   " %lu's block %llu(bit %u in group %u)",
				   inode ? inode->i_ino : 0, blocknr, block,
				   e4b->bd_group);
		}
		mb_clear_bit(block, EXT4_MB_BITMAP(e4b));
		e4b->bd_info->bb_counters[order]++;

		/* start of the buddy */
		buddy = mb_find_buddy(e4b, order, &max);

		do {
			block &= ~1UL;
			if (mb_test_bit(block, buddy) ||
					mb_test_bit(block + 1, buddy))
				break;

			/* both the buddies are free, try to coalesce them */
			buddy2 = mb_find_buddy(e4b, order + 1, &max);

			if (!buddy2)
				break;

			if (order > 0) {
				/* for special purposes, we don't set
				 * free bits in bitmap */
				mb_set_bit(block, buddy);
				mb_set_bit(block + 1, buddy);
			}
			e4b->bd_info->bb_counters[order]--;
			e4b->bd_info->bb_counters[order]--;

			block = block >> 1;
			order++;
			e4b->bd_info->bb_counters[order]++;

			mb_clear_bit(block, buddy2);
			buddy = buddy2;
		} while (1);
	}
	mb_check_buddy(e4b);
}

static int mb_find_extent(struct ext4_buddy *e4b, int order, int block,
				int needed, struct ext4_free_extent *ex)
{
	int next = block;    // 当前正在处理的块号
	int max;             // 当前 buddy 系统中的最大块号
	int ord;             // 当前块的阶数（表示块的大小，阶数越高，块越大）
	void *buddy;         // 指向 buddy 位图的指针

	assert_spin_locked(ext4_group_lock_ptr(e4b->bd_sb, e4b->bd_group)); // 确保当前已锁定组的自旋锁
	BUG_ON(ex == NULL); // 确保传入的结构体指针不为空

	buddy = mb_find_buddy(e4b, order, &max); // 根据阶数找到 buddy 位图和其最大块数
	BUG_ON(buddy == NULL); // 确保 buddy 不为空
	BUG_ON(block >= max);  // 确保块号在 buddy 系统的范围内
	if (mb_test_bit(block, buddy)) { // 检查块是否已经被占用
		// 如果块已被占用，设置空闲区间长度为 0 并返回
		ex->fe_len = 0;
		ex->fe_start = 0;
		ex->fe_group = 0;
		return 0;
	}

	/* FIXME: 是否完全舍弃 order? */
	if (likely(order == 0)) {
		/* 如果 order 为 0，则重新查找块对应的实际阶数 */
		order = mb_find_order_for_block(e4b, block);
		block = block >> order; // 将块号缩小为相应阶数的大小
	}

	// 设置初始空闲区间信息
	ex->fe_len = 1 << order;          // 根据阶数设置区间长度
	ex->fe_start = block << order;    // 根据阶数设置起始块号
	ex->fe_group = e4b->bd_group;     // 设置区间所属的块组

	// 计算起始块到给定块之间的差值
	next = next - ex->fe_start;       // 计算需要跳过的块数
	ex->fe_len -= next;               // 减去跳过的块
	ex->fe_start += next;             // 更新区间起始块号

	// 循环查找连续的空闲块，直到满足所需长度或找不到更多空闲块
	while (needed > ex->fe_len &&
	       (buddy = mb_find_buddy(e4b, order, &max))) {

		if (block + 1 >= max)  // 如果块号超出范围，结束查找
			break;

		next = (block + 1) * (1 << order);  // 计算下一个块号
		if (mb_test_bit(next, EXT4_MB_BITMAP(e4b)))  // 如果下一个块已被占用，结束查找
			break;

		ord = mb_find_order_for_block(e4b, next); // 查找下一个块的阶数

		order = ord;
		block = next >> order; // 更新当前块号为下一个块号
		ex->fe_len += 1 << order; // 增加找到的空闲区间长度
	}

	// 确保区间的起始和长度在合法范围内
	BUG_ON(ex->fe_start + ex->fe_len > (1 << (e4b->bd_blkbits + 3)));
	return ex->fe_len; // 返回找到的空闲区间长度
}


static int mb_mark_used(struct ext4_buddy *e4b, struct ext4_free_extent *ex)
{
	int ord;
	int mlen = 0;
	int max = 0;
	int cur;
	int start = ex->fe_start;
	int len = ex->fe_len;
	unsigned ret = 0;
	int len0 = len;
	void *buddy;

	BUG_ON(start + len > (e4b->bd_sb->s_blocksize << 3));
	BUG_ON(e4b->bd_group != ex->fe_group);
	assert_spin_locked(ext4_group_lock_ptr(e4b->bd_sb, e4b->bd_group));
	mb_check_buddy(e4b);
	mb_mark_used_double(e4b, start, len);

	e4b->bd_info->bb_free -= len;
	if (e4b->bd_info->bb_first_free == start)
		e4b->bd_info->bb_first_free += len;

	/* let's maintain fragments counter */
	if (start != 0)
		mlen = !mb_test_bit(start - 1, EXT4_MB_BITMAP(e4b));
	if (start + len < EXT4_SB(e4b->bd_sb)->s_mb_maxs[0])
		max = !mb_test_bit(start + len, EXT4_MB_BITMAP(e4b));
	if (mlen && max)
		e4b->bd_info->bb_fragments++;
	else if (!mlen && !max)
		e4b->bd_info->bb_fragments--;

	/* let's maintain buddy itself */
	while (len) {
		ord = mb_find_order_for_block(e4b, start);

		if (((start >> ord) << ord) == start && len >= (1 << ord)) {
			/* the whole chunk may be allocated at once! */
			mlen = 1 << ord;
			buddy = mb_find_buddy(e4b, ord, &max);
			BUG_ON((start >> ord) >= max);
			mb_set_bit(start >> ord, buddy);
			e4b->bd_info->bb_counters[ord]--;
			start += mlen;
			len -= mlen;
			BUG_ON(len < 0);
			continue;
		}

		/* store for history */
		if (ret == 0)
			ret = len | (ord << 16);

		/* we have to split large buddy */
		BUG_ON(ord <= 0);
		buddy = mb_find_buddy(e4b, ord, &max);
		mb_set_bit(start >> ord, buddy);
		e4b->bd_info->bb_counters[ord]--;

		ord--;
		cur = (start >> ord) & ~1U;
		buddy = mb_find_buddy(e4b, ord, &max);
		mb_clear_bit(cur, buddy);
		mb_clear_bit(cur + 1, buddy);
		e4b->bd_info->bb_counters[ord]++;
		e4b->bd_info->bb_counters[ord]++;
	}

	mb_set_bits(EXT4_MB_BITMAP(e4b), ex->fe_start, len0);
	mb_check_buddy(e4b);

	return ret;
}

/*
 * Must be called under group lock!
 */
static void ext4_mb_use_best_found(struct ext4_allocation_context *ac,
					struct ext4_buddy *e4b)
{
	struct ext4_sb_info *sbi = EXT4_SB(ac->ac_sb);
	int ret;

	BUG_ON(ac->ac_b_ex.fe_group != e4b->bd_group);
	BUG_ON(ac->ac_status == AC_STATUS_FOUND);

	ac->ac_b_ex.fe_len = min(ac->ac_b_ex.fe_len, ac->ac_g_ex.fe_len);
	ac->ac_b_ex.fe_logical = ac->ac_g_ex.fe_logical;
	ret = mb_mark_used(e4b, &ac->ac_b_ex);

	/* preallocation can change ac_b_ex, thus we store actually
	 * allocated blocks for history */
	ac->ac_f_ex = ac->ac_b_ex;

	ac->ac_status = AC_STATUS_FOUND;
	ac->ac_tail = ret & 0xffff;
	ac->ac_buddy = ret >> 16;

	/*
	 * take the page reference. We want the page to be pinned
	 * so that we don't get a ext4_mb_init_cache_call for this
	 * group until we update the bitmap. That would mean we
	 * double allocate blocks. The reference is dropped
	 * in ext4_mb_release_context
	 */
	ac->ac_bitmap_page = e4b->bd_bitmap_page;
	get_page(ac->ac_bitmap_page);
	ac->ac_buddy_page = e4b->bd_buddy_page;
	get_page(ac->ac_buddy_page);
	/* on allocation we use ac to track the held semaphore */
	ac->alloc_semp =  e4b->alloc_semp;
	e4b->alloc_semp = NULL;
	/* store last allocated for subsequent stream allocation */
	if (ac->ac_flags & EXT4_MB_STREAM_ALLOC) {
		spin_lock(&sbi->s_md_lock);
		sbi->s_mb_last_group = ac->ac_f_ex.fe_group;
		sbi->s_mb_last_start = ac->ac_f_ex.fe_start;
		spin_unlock(&sbi->s_md_lock);
	}
}

/*
 * regular allocator, for general purposes allocation
 */

static void ext4_mb_check_limits(struct ext4_allocation_context *ac,
					struct ext4_buddy *e4b,
					int finish_group)
{
	struct ext4_sb_info *sbi = EXT4_SB(ac->ac_sb);
	struct ext4_free_extent *bex = &ac->ac_b_ex;
	struct ext4_free_extent *gex = &ac->ac_g_ex;
	struct ext4_free_extent ex;
	int max;

	if (ac->ac_status == AC_STATUS_FOUND)
		return;
	/*
	 * We don't want to scan for a whole year
	 */
	if (ac->ac_found > sbi->s_mb_max_to_scan &&
			!(ac->ac_flags & EXT4_MB_HINT_FIRST)) {
		ac->ac_status = AC_STATUS_BREAK;
		return;
	}

	/*
	 * Haven't found good chunk so far, let's continue
	 */
	if (bex->fe_len < gex->fe_len)
		return;

	if ((finish_group || ac->ac_found > sbi->s_mb_min_to_scan)
			&& bex->fe_group == e4b->bd_group) {
		/* recheck chunk's availability - we don't know
		 * when it was found (within this lock-unlock
		 * period or not) */
		max = mb_find_extent(e4b, 0, bex->fe_start, gex->fe_len, &ex);
		if (max >= gex->fe_len) {
			ext4_mb_use_best_found(ac, e4b);
			return;
		}
	}
}

/*
 * The routine checks whether found extent is good enough. If it is,
 * then the extent gets marked used and flag is set to the context
 * to stop scanning. Otherwise, the extent is compared with the
 * previous found extent and if new one is better, then it's stored
 * in the context. Later, the best found extent will be used, if
 * mballoc can't find good enough extent.
 *
 * FIXME: real allocation policy is to be designed yet!
 */
static void ext4_mb_measure_extent(struct ext4_allocation_context *ac,
					struct ext4_free_extent *ex,
					struct ext4_buddy *e4b)
{
	struct ext4_free_extent *bex = &ac->ac_b_ex;
	struct ext4_free_extent *gex = &ac->ac_g_ex;

	BUG_ON(ex->fe_len <= 0);
	BUG_ON(ex->fe_len > EXT4_BLOCKS_PER_GROUP(ac->ac_sb));
	BUG_ON(ex->fe_start >= EXT4_BLOCKS_PER_GROUP(ac->ac_sb));
	BUG_ON(ac->ac_status != AC_STATUS_CONTINUE);

	ac->ac_found++;

	/*
	 * The special case - take what you catch first
	 */
	if (unlikely(ac->ac_flags & EXT4_MB_HINT_FIRST)) {
		*bex = *ex;
		ext4_mb_use_best_found(ac, e4b);
		return;
	}

	/*
	 * Let's check whether the chuck is good enough
	 */
	if (ex->fe_len == gex->fe_len) {
		*bex = *ex;
		ext4_mb_use_best_found(ac, e4b);
		return;
	}

	/*
	 * If this is first found extent, just store it in the context
	 */
	if (bex->fe_len == 0) {
		*bex = *ex;
		return;
	}

	/*
	 * If new found extent is better, store it in the context
	 */
	if (bex->fe_len < gex->fe_len) {
		/* if the request isn't satisfied, any found extent
		 * larger than previous best one is better */
		if (ex->fe_len > bex->fe_len)
			*bex = *ex;
	} else if (ex->fe_len > gex->fe_len) {
		/* if the request is satisfied, then we try to find
		 * an extent that still satisfy the request, but is
		 * smaller than previous one */
		if (ex->fe_len < bex->fe_len)
			*bex = *ex;
	}

	ext4_mb_check_limits(ac, e4b, 0);
}

static noinline_for_stack
int ext4_mb_try_best_found(struct ext4_allocation_context *ac,
					struct ext4_buddy *e4b)
{
	struct ext4_free_extent ex = ac->ac_b_ex;
	ext4_group_t group = ex.fe_group;
	int max;
	int err;

	BUG_ON(ex.fe_len <= 0);
	err = ext4_mb_load_buddy(ac->ac_sb, group, e4b);
	if (err)
		return err;

	ext4_lock_group(ac->ac_sb, group);
	max = mb_find_extent(e4b, 0, ex.fe_start, ex.fe_len, &ex);

	if (max > 0) {
		ac->ac_b_ex = ex;
		ext4_mb_use_best_found(ac, e4b);
	}

	ext4_unlock_group(ac->ac_sb, group);
	ext4_mb_release_desc(e4b);

	return 0;
}

/*
 * ext4_mb_find_by_goal - 根据目标块组和目标块范围查找空闲块
 * @ac: 分配上下文，包含当前分配的参数和状态
 * @e4b: buddy 分配系统的上下文结构，用于描述当前块组的 buddy 信息
 *
 * 该函数尝试在目标块组中找到满足目标块范围的空闲块，并进行分配。如果找到满足条件的块，
 * 会将这些块返回给分配上下文，更新分配状态，并且调用函数完成分配操作。
 *
 * 返回 0 表示成功查找，返回错误码表示查找失败。
 */
static noinline_for_stack
int ext4_mb_find_by_goal(struct ext4_allocation_context *ac,
				struct ext4_buddy *e4b)
{
	ext4_group_t group = ac->ac_g_ex.fe_group;  // 获取目标块组
	int max;  // 记录找到的最大空闲块的数量
	int err;
	struct ext4_sb_info *sbi = EXT4_SB(ac->ac_sb);  // 获取超级块信息
	struct ext4_free_extent ex;  // 用于存储找到的空闲块信息

	// 如果没有设置 EXT4_MB_HINT_TRY_GOAL 标志，则不进行查找
	if (!(ac->ac_flags & EXT4_MB_HINT_TRY_GOAL))
		return 0;

	// 加载目标块组的 buddy 信息
	err = ext4_mb_load_buddy(ac->ac_sb, group, e4b);
	if (err)
		return err;  // 加载失败则返回错误码

	// 锁定目标块组，防止并发修改
	ext4_lock_group(ac->ac_sb, group);

	// 查找目标块范围内的空闲块，结果存储在 ex 中
	max = mb_find_extent(e4b, 0, ac->ac_g_ex.fe_start,
			     ac->ac_g_ex.fe_len, &ex);

	// 如果找到的空闲块数量大于或等于需要分配的块数，并且符合条带化要求
	if (max >= ac->ac_g_ex.fe_len && ac->ac_g_ex.fe_len == sbi->s_stripe) {
		ext4_fsblk_t start;

		// 计算块组的第一个块的物理块号，并检查是否符合条带化要求
		start = ext4_group_first_block_no(ac->ac_sb, e4b->bd_group) +
			ex.fe_start;
		/* 使用 do_div 进行 64 位除法，计算块号对条带大小的余数 */
		if (do_div(start, sbi->s_stripe) == 0) {
			ac->ac_found++;  // 记录已找到的块
			ac->ac_b_ex = ex;  // 将找到的块信息存储到分配上下文
			ext4_mb_use_best_found(ac, e4b);  // 使用找到的最佳块进行分配
		}
	}
	// 如果找到的块数量大于或等于需要分配的块数
	else if (max >= ac->ac_g_ex.fe_len) {
		// 确保找到的块长度和范围有效
		BUG_ON(ex.fe_len <= 0);
		BUG_ON(ex.fe_group != ac->ac_g_ex.fe_group);
		BUG_ON(ex.fe_start != ac->ac_g_ex.fe_start);
		ac->ac_found++;  // 记录已找到的块
		ac->ac_b_ex = ex;  // 将找到的块信息存储到分配上下文
		ext4_mb_use_best_found(ac, e4b);  // 使用找到的最佳块进行分配
	}
	// 如果找到的块数量大于 0 且设置了合并标志
	else if (max > 0 && (ac->ac_flags & EXT4_MB_HINT_MERGE)) {
		// 确保找到的块长度和范围有效
		BUG_ON(ex.fe_len <= 0);
		BUG_ON(ex.fe_group != ac->ac_g_ex.fe_group);
		BUG_ON(ex.fe_start != ac->ac_g_ex.fe_start);
		ac->ac_found++;  // 记录已找到的块
		ac->ac_b_ex = ex;  // 将找到的块信息存储到分配上下文
		ext4_mb_use_best_found(ac, e4b);  // 使用找到的最佳块进行分配
	}

	// 解锁目标块组
	ext4_unlock_group(ac->ac_sb, group);
	// 释放 buddy 信息
	ext4_mb_release_desc(e4b);

	return 0;  // 返回 0 表示成功查找
}

/*
 * The routine scans buddy structures (not bitmap!) from given order
 * to max order and tries to find big enough chunk to satisfy the req
 */
static noinline_for_stack
void ext4_mb_simple_scan_group(struct ext4_allocation_context *ac,
					struct ext4_buddy *e4b)
{
	struct super_block *sb = ac->ac_sb;
	struct ext4_group_info *grp = e4b->bd_info;
	void *buddy;
	int i;
	int k;
	int max;

	BUG_ON(ac->ac_2order <= 0);
	for (i = ac->ac_2order; i <= sb->s_blocksize_bits + 1; i++) {
		if (grp->bb_counters[i] == 0)
			continue;

		buddy = mb_find_buddy(e4b, i, &max);
		BUG_ON(buddy == NULL);

		k = mb_find_next_zero_bit(buddy, max, 0);
		BUG_ON(k >= max);

		ac->ac_found++;

		ac->ac_b_ex.fe_len = 1 << i;
		ac->ac_b_ex.fe_start = k << i;
		ac->ac_b_ex.fe_group = e4b->bd_group;

		ext4_mb_use_best_found(ac, e4b);

		BUG_ON(ac->ac_b_ex.fe_len != ac->ac_g_ex.fe_len);

		if (EXT4_SB(sb)->s_mb_stats)
			atomic_inc(&EXT4_SB(sb)->s_bal_2orders);

		break;
	}
}

/*
 * The routine scans the group and measures all found extents.
 * In order to optimize scanning, caller must pass number of
 * free blocks in the group, so the routine can know upper limit.
 */
static noinline_for_stack
void ext4_mb_complex_scan_group(struct ext4_allocation_context *ac,
					struct ext4_buddy *e4b)
{
	struct super_block *sb = ac->ac_sb;
	void *bitmap = EXT4_MB_BITMAP(e4b);
	struct ext4_free_extent ex;
	int i;
	int free;

	free = e4b->bd_info->bb_free;
	BUG_ON(free <= 0);

	i = e4b->bd_info->bb_first_free;

	while (free && ac->ac_status == AC_STATUS_CONTINUE) {
		i = mb_find_next_zero_bit(bitmap,
						EXT4_BLOCKS_PER_GROUP(sb), i);
		if (i >= EXT4_BLOCKS_PER_GROUP(sb)) {
			/*
			 * IF we have corrupt bitmap, we won't find any
			 * free blocks even though group info says we
			 * we have free blocks
			 */
			ext4_grp_locked_error(sb, e4b->bd_group,
					__func__, "%d free blocks as per "
					"group info. But bitmap says 0",
					free);
			break;
		}

		mb_find_extent(e4b, 0, i, ac->ac_g_ex.fe_len, &ex);
		BUG_ON(ex.fe_len <= 0);
		if (free < ex.fe_len) {
			ext4_grp_locked_error(sb, e4b->bd_group,
					__func__, "%d free blocks as per "
					"group info. But got %d blocks",
					free, ex.fe_len);
			/*
			 * The number of free blocks differs. This mostly
			 * indicate that the bitmap is corrupt. So exit
			 * without claiming the space.
			 */
			break;
		}

		ext4_mb_measure_extent(ac, &ex, e4b);

		i += ex.fe_len;
		free -= ex.fe_len;
	}

	ext4_mb_check_limits(ac, e4b, 1);
}

/*
 * This is a special case for storages like raid5
 * we try to find stripe-aligned chunks for stripe-size requests
 * XXX should do so at least for multiples of stripe size as well
 */
static noinline_for_stack
void ext4_mb_scan_aligned(struct ext4_allocation_context *ac,
				 struct ext4_buddy *e4b)
{
	struct super_block *sb = ac->ac_sb;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	void *bitmap = EXT4_MB_BITMAP(e4b);
	struct ext4_free_extent ex;
	ext4_fsblk_t first_group_block;
	ext4_fsblk_t a;
	ext4_grpblk_t i;
	int max;

	BUG_ON(sbi->s_stripe == 0);

	/* find first stripe-aligned block in group */
	first_group_block = ext4_group_first_block_no(sb, e4b->bd_group);

	a = first_group_block + sbi->s_stripe - 1;
	do_div(a, sbi->s_stripe);
	i = (a * sbi->s_stripe) - first_group_block;

	while (i < EXT4_BLOCKS_PER_GROUP(sb)) {
		if (!mb_test_bit(i, bitmap)) {
			max = mb_find_extent(e4b, 0, i, sbi->s_stripe, &ex);
			if (max >= sbi->s_stripe) {
				ac->ac_found++;
				ac->ac_b_ex = ex;
				ext4_mb_use_best_found(ac, e4b);
				break;
			}
		}
		i += sbi->s_stripe;
	}
}

static int ext4_mb_good_group(struct ext4_allocation_context *ac,
				ext4_group_t group, int cr)
{
	unsigned free, fragments;
	unsigned i, bits;
	int flex_size = ext4_flex_bg_size(EXT4_SB(ac->ac_sb));
	struct ext4_group_info *grp = ext4_get_group_info(ac->ac_sb, group);

	BUG_ON(cr < 0 || cr >= 4);
	BUG_ON(EXT4_MB_GRP_NEED_INIT(grp));

	free = grp->bb_free;
	fragments = grp->bb_fragments;
	if (free == 0)
		return 0;
	if (fragments == 0)
		return 0;

	switch (cr) {
	case 0:
		BUG_ON(ac->ac_2order == 0);

		/* Avoid using the first bg of a flexgroup for data files */
		if ((ac->ac_flags & EXT4_MB_HINT_DATA) &&
		    (flex_size >= EXT4_FLEX_SIZE_DIR_ALLOC_SCHEME) &&
		    ((group % flex_size) == 0))
			return 0;

		bits = ac->ac_sb->s_blocksize_bits + 1;
		for (i = ac->ac_2order; i <= bits; i++)
			if (grp->bb_counters[i] > 0)
				return 1;
		break;
	case 1:
		if ((free / fragments) >= ac->ac_g_ex.fe_len)
			return 1;
		break;
	case 2:
		if (free >= ac->ac_g_ex.fe_len)
			return 1;
		break;
	case 3:
		return 1;
	default:
		BUG();
	}

	return 0;
}

/*
 * lock the group_info alloc_sem of all the groups
 * belonging to the same buddy cache page. This
 * make sure other parallel operation on the buddy
 * cache doesn't happen  whild holding the buddy cache
 * lock
 */
int ext4_mb_get_buddy_cache_lock(struct super_block *sb, ext4_group_t group)
{
	int i;
	int block, pnum;
	int blocks_per_page;
	int groups_per_page;
	ext4_group_t ngroups = ext4_get_groups_count(sb);
	ext4_group_t first_group;
	struct ext4_group_info *grp;

	blocks_per_page = PAGE_CACHE_SIZE / sb->s_blocksize;
	/*
	 * the buddy cache inode stores the block bitmap
	 * and buddy information in consecutive blocks.
	 * So for each group we need two blocks.
	 */
	block = group * 2;
	pnum = block / blocks_per_page;
	first_group = pnum * blocks_per_page / 2;

	groups_per_page = blocks_per_page >> 1;
	if (groups_per_page == 0)
		groups_per_page = 1;
	/* read all groups the page covers into the cache */
	for (i = 0; i < groups_per_page; i++) {

		if ((first_group + i) >= ngroups)
			break;
		grp = ext4_get_group_info(sb, first_group + i);
		/* take all groups write allocation
		 * semaphore. This make sure there is
		 * no block allocation going on in any
		 * of that groups
		 */
		down_write_nested(&grp->alloc_sem, i);
	}
	return i;
}

void ext4_mb_put_buddy_cache_lock(struct super_block *sb,
					ext4_group_t group, int locked_group)
{
	int i;
	int block, pnum;
	int blocks_per_page;
	ext4_group_t first_group;
	struct ext4_group_info *grp;

	blocks_per_page = PAGE_CACHE_SIZE / sb->s_blocksize;
	/*
	 * the buddy cache inode stores the block bitmap
	 * and buddy information in consecutive blocks.
	 * So for each group we need two blocks.
	 */
	block = group * 2;
	pnum = block / blocks_per_page;
	first_group = pnum * blocks_per_page / 2;
	/* release locks on all the groups */
	for (i = 0; i < locked_group; i++) {

		grp = ext4_get_group_info(sb, first_group + i);
		/* take all groups write allocation
		 * semaphore. This make sure there is
		 * no block allocation going on in any
		 * of that groups
		 */
		up_write(&grp->alloc_sem);
	}

}

static noinline_for_stack int
ext4_mb_regular_allocator(struct ext4_allocation_context *ac)
{
	ext4_group_t ngroups, group, i;
	int cr;
	int err = 0;
	int bsbits;
	struct ext4_sb_info *sbi;
	struct super_block *sb;
	struct ext4_buddy e4b;

	sb = ac->ac_sb;  // 获取超级块
	sbi = EXT4_SB(sb);  // 获取 EXT4 超级块信息
	ngroups = ext4_get_groups_count(sb);  // 获取文件系统块组数量

	/* 如果文件没有使用 extent，则限制在较低的块组范围内 */
	if (!(EXT4_I(ac->ac_inode)->i_flags & EXT4_EXTENTS_FL))
		ngroups = sbi->s_blockfile_groups;

	/* 确保当前状态不是 AC_STATUS_FOUND，如果是则终止执行（用于调试） */
	BUG_ON(ac->ac_status == AC_STATUS_FOUND);

	/* 首先尝试通过目标块进行分配 */
	err = ext4_mb_find_by_goal(ac, &e4b);
	if (err || ac->ac_status == AC_STATUS_FOUND)
		goto out;  // 如果找到目标块，跳转到结束处理

	/* 如果只允许使用目标块，则退出 */
	if (unlikely(ac->ac_flags & EXT4_MB_HINT_GOAL_ONLY))
		goto out;

	/* 
	 * 如果要分配的块数量是 2 的幂次方，则设置 ac->ac2_order 
	 * 如果设置了 ac2_order，则分配时尝试使用 buddy 系统进行精确分配
	 */
	i = fls(ac->ac_g_ex.fe_len);  // 计算 fe_len 的最高有效位
	ac->ac_2order = 0;

	/* 只有当请求的块数大于等于 sbi->s_mb_order2_reqs 时，才使用 buddy 系统 */
	if (i >= sbi->s_mb_order2_reqs) {
		/* 检查 fe_len 是否正好是 2 的幂次方 */
		if ((ac->ac_g_ex.fe_len & (~(1 << (i - 1)))) == 0)
			ac->ac_2order = i - 1;  // 设置 ac2_order 表示块数为 2 的幂次方
	}

	bsbits = ac->ac_sb->s_blocksize_bits;  // 获取块大小的位数

	/* 如果启用了流分配，则使用全局目标块 */
	if (ac->ac_flags & EXT4_MB_STREAM_ALLOC) {
		spin_lock(&sbi->s_md_lock);  // 锁定元数据
		ac->ac_g_ex.fe_group = sbi->s_mb_last_group;  // 获取上次分配的块组
		ac->ac_g_ex.fe_start = sbi->s_mb_last_start;  // 获取上次分配的起始块
		spin_unlock(&sbi->s_md_lock);  // 解锁元数据
	}

	/* 开始扫描块组以找到大致合适的块 */
	cr = ac->ac_2order ? 0 : 1;  // 如果块数是 2 的幂次方，从 0 开始，否则从 1 开始
	/*
	 * cr == 0 表示尝试精确分配，
	 * cr == 3 表示尝试任何可用的块
	 */
repeat:
	for (; cr < 4 && ac->ac_status == AC_STATUS_CONTINUE; cr++) {
		ac->ac_criteria = cr;  // 设置当前的分配条件

		/* 从目标块组开始搜索合适的块组 */
		group = ac->ac_g_ex.fe_group;

		for (i = 0; i < ngroups; group++, i++) {
			struct ext4_group_info *grp;
			struct ext4_group_desc *desc;

			if (group == ngroups)
				group = 0;  // 如果超出块组范围，从头开始

			/* 快速检查跳过空的块组 */
			grp = ext4_get_group_info(sb, group);
			if (grp->bb_free == 0)
				continue;  // 跳过没有空闲块的块组

			/* 加载 buddy 系统，用于后续的分配操作 */
			err = ext4_mb_load_buddy(sb, group, &e4b);
			if (err)
				goto out;  // 如果加载 buddy 失败，跳转到结束处理

			ext4_lock_group(sb, group);  // 锁定块组，防止并发修改
			if (!ext4_mb_good_group(ac, group, cr)) {
				/* 如果块组不适合分配，解锁并释放资源 */
				ext4_unlock_group(sb, group);
				ext4_mb_release_desc(&e4b);
				continue;
			}

			ac->ac_groups_scanned++;  // 记录已扫描的块组数量
			desc = ext4_get_group_desc(sb, group, NULL);  // 获取块组描述符

			/* 根据不同条件选择分配方式 */
			if (cr == 0)
				ext4_mb_simple_scan_group(ac, &e4b);  // 简单扫描
			else if (cr == 1 &&
					ac->ac_g_ex.fe_len == sbi->s_stripe)
				ext4_mb_scan_aligned(ac, &e4b);  // 按照条带化分配
			else
				ext4_mb_complex_scan_group(ac, &e4b);  // 复杂扫描

			ext4_unlock_group(sb, group);  // 解锁块组
			ext4_mb_release_desc(&e4b);  // 释放 buddy 资源

			if (ac->ac_status != AC_STATUS_CONTINUE)
				break;  // 如果分配成功，跳出循环
		}
	}

	/* 如果找到的块长度大于 0 且状态不是已找到，则尝试分配最佳找到的块 */
	if (ac->ac_b_ex.fe_len > 0 && ac->ac_status != AC_STATUS_FOUND &&
	    !(ac->ac_flags & EXT4_MB_HINT_FIRST)) {

		/* 尝试分配找到的最佳块 */
		ext4_mb_try_best_found(ac, &e4b);
		if (ac->ac_status != AC_STATUS_FOUND) {
			/*
			 * 如果被其他进程抢先分配了，我们只能分配第一个找到的块
			 * 并且标记状态为 CONTINUE，继续分配过程
			 */
			ac->ac_b_ex.fe_group = 0;
			ac->ac_b_ex.fe_start = 0;
			ac->ac_b_ex.fe_len = 0;
			ac->ac_status = AC_STATUS_CONTINUE;
			ac->ac_flags |= EXT4_MB_HINT_FIRST;  // 标记已进行第一次分配
			cr = 3;  // 将分配条件设置为 3，表示接受任何分配
			atomic_inc(&sbi->s_mb_lost_chunks);  // 记录丢失的块数
			goto repeat;  // 重新开始分配
		}
	}
out:
	return err;  // 返回错误代码
}


static void *ext4_mb_seq_groups_start(struct seq_file *seq, loff_t *pos)
{
	struct super_block *sb = seq->private;
	ext4_group_t group;

	if (*pos < 0 || *pos >= ext4_get_groups_count(sb))
		return NULL;
	group = *pos + 1;
	return (void *) ((unsigned long) group);
}

static void *ext4_mb_seq_groups_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct super_block *sb = seq->private;
	ext4_group_t group;

	++*pos;
	if (*pos < 0 || *pos >= ext4_get_groups_count(sb))
		return NULL;
	group = *pos + 1;
	return (void *) ((unsigned long) group);
}

static int ext4_mb_seq_groups_show(struct seq_file *seq, void *v)
{
	struct super_block *sb = seq->private;
	ext4_group_t group = (ext4_group_t) ((unsigned long) v);
	int i;
	int err;
	struct ext4_buddy e4b;
	struct sg {
		struct ext4_group_info info;
		ext4_grpblk_t counters[16];
	} sg;

	group--;
	if (group == 0)
		seq_printf(seq, "#%-5s: %-5s %-5s %-5s "
				"[ %-5s %-5s %-5s %-5s %-5s %-5s %-5s "
				  "%-5s %-5s %-5s %-5s %-5s %-5s %-5s ]\n",
			   "group", "free", "frags", "first",
			   "2^0", "2^1", "2^2", "2^3", "2^4", "2^5", "2^6",
			   "2^7", "2^8", "2^9", "2^10", "2^11", "2^12", "2^13");

	i = (sb->s_blocksize_bits + 2) * sizeof(sg.info.bb_counters[0]) +
		sizeof(struct ext4_group_info);
	err = ext4_mb_load_buddy(sb, group, &e4b);
	if (err) {
		seq_printf(seq, "#%-5u: I/O error\n", group);
		return 0;
	}
	ext4_lock_group(sb, group);
	memcpy(&sg, ext4_get_group_info(sb, group), i);
	ext4_unlock_group(sb, group);
	ext4_mb_release_desc(&e4b);

	seq_printf(seq, "#%-5u: %-5u %-5u %-5u [", group, sg.info.bb_free,
			sg.info.bb_fragments, sg.info.bb_first_free);
	for (i = 0; i <= 13; i++)
		seq_printf(seq, " %-5u", i <= sb->s_blocksize_bits + 1 ?
				sg.info.bb_counters[i] : 0);
	seq_printf(seq, " ]\n");

	return 0;
}

static void ext4_mb_seq_groups_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations ext4_mb_seq_groups_ops = {
	.start  = ext4_mb_seq_groups_start,
	.next   = ext4_mb_seq_groups_next,
	.stop   = ext4_mb_seq_groups_stop,
	.show   = ext4_mb_seq_groups_show,
};

static int ext4_mb_seq_groups_open(struct inode *inode, struct file *file)
{
	struct super_block *sb = PDE(inode)->data;
	int rc;

	rc = seq_open(file, &ext4_mb_seq_groups_ops);
	if (rc == 0) {
		struct seq_file *m = (struct seq_file *)file->private_data;
		m->private = sb;
	}
	return rc;

}

static const struct file_operations ext4_mb_seq_groups_fops = {
	.owner		= THIS_MODULE,
	.open		= ext4_mb_seq_groups_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};


/* 
 * 创建并初始化给定组的 ext4_group_info 数据结构。
 * 该函数负责为每个组分配和初始化元数据，主要用于管理组中的空闲块信息。
 */
int ext4_mb_add_groupinfo(struct super_block *sb, ext4_group_t group,
			  struct ext4_group_desc *desc)
{
	int i, len; // i: 索引变量, len: 需要分配的内存长度
	int metalen = 0; // 用于元组组信息表的内存大小
	struct ext4_sb_info *sbi = EXT4_SB(sb); // 获取超级块信息
	struct ext4_group_info **meta_group_info; // 元组组信息指针

	/*
	 * 首先检查该组是否为保留块的第一个组。
	 * 如果是，则需要为 ext4_group_info 结构体分配一个新的指针表。
	 */
	if (group % EXT4_DESC_PER_BLOCK(sb) == 0) {
		// 计算为指针表分配的内存大小，EXT4_DESC_PER_BLOCK_BITS(sb) 是每块描述符的位数
		metalen = sizeof(*meta_group_info) <<
			EXT4_DESC_PER_BLOCK_BITS(sb);
		meta_group_info = kmalloc(metalen, GFP_KERNEL); // 分配内存
		if (meta_group_info == NULL) { // 检查内存分配是否成功
			printk(KERN_ERR "EXT4-fs: can't allocate mem for a "
			       "buddy group\n");
			goto exit_meta_group_info; // 分配失败，跳转到错误处理
		}
		// 将新分配的指针表保存到超级块的信息中
		sbi->s_group_info[group >> EXT4_DESC_PER_BLOCK_BITS(sb)] =
			meta_group_info;
	}

	/*
	 * 计算需要分配的内存大小。如果更改 bb_counters 大小，
	 * 需要确保 ext4_mb_generate_buddy() 函数中也进行相应修改。
	 */
	len = offsetof(typeof(**meta_group_info),
		       bb_counters[sb->s_blocksize_bits + 2]); // 计算偏移量大小

	// 获取当前组的 meta_group_info 表
	meta_group_info =
		sbi->s_group_info[group >> EXT4_DESC_PER_BLOCK_BITS(sb)];
	i = group & (EXT4_DESC_PER_BLOCK(sb) - 1); // 计算组在表中的索引

	// 为当前组分配并初始化 ext4_group_info 结构体
	meta_group_info[i] = kzalloc(len, GFP_KERNEL); // 分配内存并初始化为零
	if (meta_group_info[i] == NULL) { // 检查分配是否成功
		printk(KERN_ERR "EXT4-fs: can't allocate buddy mem\n");
		goto exit_group_info; // 分配失败，跳转到错误处理
	}

	// 设置组状态位，表示该组需要初始化
	set_bit(EXT4_GROUP_INFO_NEED_INIT_BIT,
		&(meta_group_info[i]->bb_state));

	/*
	 * 初始化 bb_free 以便能够跳过空组而无需初始化。
	 * 如果块组的 bg_flags 标志包含 EXT4_BG_BLOCK_UNINIT（表示未初始化），
	 * 则使用 ext4_free_blocks_after_init() 计算该组中的空闲块数；
	 * 否则，直接从组描述符中读取空闲块数。
	 */
	if (desc->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
		meta_group_info[i]->bb_free =
			ext4_free_blocks_after_init(sb, group, desc);
	} else {
		meta_group_info[i]->bb_free =
			ext4_free_blks_count(sb, desc);
	}

	// 初始化组的预分配列表、分配信号量和红黑树根节点
	INIT_LIST_HEAD(&meta_group_info[i]->bb_prealloc_list);
	init_rwsem(&meta_group_info[i]->alloc_sem);
	meta_group_info[i]->bb_free_root = RB_ROOT;

#ifdef DOUBLE_CHECK
	{
		// DEBUG 模式下，检查位图是否正确
		struct buffer_head *bh;
		meta_group_info[i]->bb_bitmap =
			kmalloc(sb->s_blocksize, GFP_KERNEL); // 分配位图内存
		BUG_ON(meta_group_info[i]->bb_bitmap == NULL); // 检查分配是否成功
		bh = ext4_read_block_bitmap(sb, group); // 读取块组位图
		BUG_ON(bh == NULL); // 确保读取成功
		memcpy(meta_group_info[i]->bb_bitmap, bh->b_data,
			sb->s_blocksize); // 复制位图数据
		put_bh(bh); // 释放 buffer_head
	}
#endif

	return 0; // 成功返回

exit_group_info:
	/* 如果已经分配了 meta_group_info 表，则释放它 */
	if (group % EXT4_DESC_PER_BLOCK(sb) == 0)
		kfree(sbi->s_group_info[group >> EXT4_DESC_PER_BLOCK_BITS(sb)]);

exit_meta_group_info:
	return -ENOMEM; // 返回内存不足错误
}


static int ext4_mb_init_backend(struct super_block *sb)
{
	ext4_group_t ngroups = ext4_get_groups_count(sb); // 获取文件系统中的组数量
	ext4_group_t i;
	struct ext4_sb_info *sbi = EXT4_SB(sb); // 获取超级块信息
	struct ext4_super_block *es = sbi->s_es; // 获取扩展4超级块
	int num_meta_group_infos; // 元组组信息数量
	int num_meta_group_infos_max; // 最大元组组信息数量
	int array_size; // 数组大小
	struct ext4_group_desc *desc; // 组描述符

	/* 计算用于 GDT 的块数量 */
	num_meta_group_infos = (ngroups + EXT4_DESC_PER_BLOCK(sb) -
				1) >> EXT4_DESC_PER_BLOCK_BITS(sb);

	/*
	 * 计算 GDT 使用的总块数，包括 GDT 的保留块数。
	 * s_group_info 数组根据此值分配，以便在不复杂操作指针的情况下进行干净的在线调整。
	 * 缺点是在没有调整发生时会浪费内存，但这在页面级别上是非常低的
	 * （见下面的注释）
	 * 当允许 META_BG 调整时需要正确处理这个问题。
	 */
	num_meta_group_infos_max = num_meta_group_infos +
				le16_to_cpu(es->s_reserved_gdt_blocks);

	/*
	 * array_size 是 s_group_info 数组的大小。我们将其向上取整到下一个 2 的幂，
	 * 因为 kmalloc 内部进行这个近似，因此我们可以在这里多分配一些内存
	 * （例如，可能用于 META_BG 调整）。
	 */
	array_size = 1;
	while (array_size < sizeof(*sbi->s_group_info) *
	       num_meta_group_infos_max)
		array_size = array_size << 1;

	/* 
	 * 一个 8TB 文件系统需要 4096 字节的 kmalloc 内存，
	 * 一个 128KB 的分配应足以满足 256TB 文件系统的需求。
	 * 因此，目前只需使用两级方案。
	 */
	sbi->s_group_info = kmalloc(array_size, GFP_KERNEL); // 分配 s_group_info 数组
	if (sbi->s_group_info == NULL) { // 检查分配是否成功
		printk(KERN_ERR "EXT4-fs: can't allocate buddy meta group\n");
		return -ENOMEM; // 分配失败，返回内存不足错误
	}

	sbi->s_buddy_cache = new_inode(sb); // 创建新的 inode 用于缓存
	if (sbi->s_buddy_cache == NULL) { // 检查创建是否成功
		printk(KERN_ERR "EXT4-fs: can't get new inode\n");
		goto err_freesgi; // 创建失败，释放 s_group_info
	}
	EXT4_I(sbi->s_buddy_cache)->i_disksize = 0; // 初始化磁盘大小为 0

	// 遍历所有组，添加组信息
	for (i = 0; i < ngroups; i++) {
		desc = ext4_get_group_desc(sb, i, NULL); // 获取组描述符
		if (desc == NULL) { // 检查获取是否成功
			printk(KERN_ERR "EXT4-fs: can't read descriptor %u\n", i);
			goto err_freebuddy; // 读取失败，释放 buddy 缓存
		}
		if (ext4_mb_add_groupinfo(sb, i, desc) != 0) // 添加组信息
			goto err_freebuddy; // 添加失败，释放 buddy 缓存
	}

	return 0; // 成功初始化

// 错误处理：释放 buddy 缓存
err_freebuddy:
	while (i-- > 0)
		kfree(ext4_get_group_info(sb, i)); // 释放之前添加的组信息

	i = num_meta_group_infos; // 释放 s_group_info 数组
	while (i-- > 0)
		kfree(sbi->s_group_info[i]);
	iput(sbi->s_buddy_cache); // 释放 buddy 缓存 inode

err_freesgi:
	kfree(sbi->s_group_info); // 释放 s_group_info 数组
	return -ENOMEM; // 返回内存不足错误
}


int ext4_mb_init(struct super_block *sb, int needs_recovery)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb); // 获取扩展4超级块信息
	unsigned i, j; // 索引变量
	unsigned offset; // 偏移量
	unsigned max; // 最大值
	int ret; // 返回值

	// 计算 s_mb_offsets 数组的大小
	i = (sb->s_blocksize_bits + 2) * sizeof(*sbi->s_mb_offsets);
	sbi->s_mb_offsets = kmalloc(i, GFP_KERNEL); // 分配内存
	if (sbi->s_mb_offsets == NULL) { // 检查分配是否成功
		return -ENOMEM; // 分配失败，返回内存不足错误
	}

	// 计算 s_mb_maxs 数组的大小
	i = (sb->s_blocksize_bits + 2) * sizeof(*sbi->s_mb_maxs);
	sbi->s_mb_maxs = kmalloc(i, GFP_KERNEL); // 分配内存
	if (sbi->s_mb_maxs == NULL) { // 检查分配是否成功
		kfree(sbi->s_mb_offsets); // 释放之前分配的内存
		return -ENOMEM; // 分配失败，返回内存不足错误
	}

	/* order 0 is regular bitmap */
	sbi->s_mb_maxs[0] = sb->s_blocksize << 3; // 初始化第一个最大值
	sbi->s_mb_offsets[0] = 0; // 初始化第一个偏移量

	i = 1; // 从 1 开始
	offset = 0; // 初始化偏移量为 0
	max = sb->s_blocksize << 2; // 初始化最大值为块大小的四倍
	do {
		sbi->s_mb_offsets[i] = offset; // 设置偏移量
		sbi->s_mb_maxs[i] = max; // 设置最大值
		offset += 1 << (sb->s_blocksize_bits - i); // 计算下一个偏移量
		max = max >> 1; // 减小最大值
		i++;
	} while (i <= sb->s_blocksize_bits + 1); // 循环直到填满

	// 初始化 buddy 数据
	ret = ext4_mb_init_backend(sb); // 调用初始化后端函数
	if (ret != 0) { // 检查返回值
		kfree(sbi->s_mb_offsets); // 释放已分配的内存
		kfree(sbi->s_mb_maxs);
		return ret; // 返回错误
	}

	spin_lock_init(&sbi->s_md_lock); // 初始化元数据锁
	spin_lock_init(&sbi->s_bal_lock); // 初始化平衡锁

	// 初始化一些默认值
	sbi->s_mb_max_to_scan = MB_DEFAULT_MAX_TO_SCAN; // 最大扫描量
	sbi->s_mb_min_to_scan = MB_DEFAULT_MIN_TO_SCAN; // 最小扫描量
	sbi->s_mb_stats = MB_DEFAULT_STATS; // 初始化统计信息
	sbi->s_mb_stream_request = MB_DEFAULT_STREAM_THRESHOLD; // 流请求阈值
	sbi->s_mb_order2_reqs = MB_DEFAULT_ORDER2_REQS; // order2 请求
	sbi->s_mb_group_prealloc = MB_DEFAULT_GROUP_PREALLOC; // 组预分配

	// 为局部性组分配每 CPU 的结构
	sbi->s_locality_groups = alloc_percpu(struct ext4_locality_group);
	if (sbi->s_locality_groups == NULL) { // 检查分配是否成功
		kfree(sbi->s_mb_offsets); // 释放已分配的内存
		kfree(sbi->s_mb_maxs);
		return -ENOMEM; // 返回内存不足错误
	}
	
	// 初始化每个 CPU 的局部性组
	for_each_possible_cpu(i) {
		struct ext4_locality_group *lg;
		lg = per_cpu_ptr(sbi->s_locality_groups, i); // 获取当前 CPU 的局部性组
		mutex_init(&lg->lg_mutex); // 初始化互斥锁
		for (j = 0; j < PREALLOC_TB_SIZE; j++) // 初始化预分配列表
			INIT_LIST_HEAD(&lg->lg_prealloc_list[j]);
		spin_lock_init(&lg->lg_prealloc_lock); // 初始化预分配锁
	}

	// 如果有进程文件系统，则创建 mb_groups 的 proc 文件
	if (sbi->s_proc)
		proc_create_data("mb_groups", S_IRUGO, sbi->s_proc,
				 &ext4_mb_seq_groups_fops, sb);

	// 如果启用了日志，则设置提交回调函数
	if (sbi->s_journal)
		sbi->s_journal->j_commit_callback = release_blocks_on_commit;

	return 0; // 成功初始化
}


/* need to called with the ext4 group lock held */
static void ext4_mb_cleanup_pa(struct ext4_group_info *grp)
{
	struct ext4_prealloc_space *pa;
	struct list_head *cur, *tmp;
	int count = 0;

	list_for_each_safe(cur, tmp, &grp->bb_prealloc_list) {
		pa = list_entry(cur, struct ext4_prealloc_space, pa_group_list);
		list_del(&pa->pa_group_list);
		count++;
		kmem_cache_free(ext4_pspace_cachep, pa);
	}
	if (count)
		mb_debug(1, "mballoc: %u PAs left\n", count);

}

int ext4_mb_release(struct super_block *sb)
{
	ext4_group_t ngroups = ext4_get_groups_count(sb);
	ext4_group_t i;
	int num_meta_group_infos;
	struct ext4_group_info *grinfo;
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (sbi->s_group_info) {
		for (i = 0; i < ngroups; i++) {
			grinfo = ext4_get_group_info(sb, i);
#ifdef DOUBLE_CHECK
			kfree(grinfo->bb_bitmap);
#endif
			ext4_lock_group(sb, i);
			ext4_mb_cleanup_pa(grinfo);
			ext4_unlock_group(sb, i);
			kfree(grinfo);
		}
		num_meta_group_infos = (ngroups +
				EXT4_DESC_PER_BLOCK(sb) - 1) >>
			EXT4_DESC_PER_BLOCK_BITS(sb);
		for (i = 0; i < num_meta_group_infos; i++)
			kfree(sbi->s_group_info[i]);
		kfree(sbi->s_group_info);
	}
	kfree(sbi->s_mb_offsets);
	kfree(sbi->s_mb_maxs);
	if (sbi->s_buddy_cache)
		iput(sbi->s_buddy_cache);
	if (sbi->s_mb_stats) {
		printk(KERN_INFO
		       "EXT4-fs: mballoc: %u blocks %u reqs (%u success)\n",
				atomic_read(&sbi->s_bal_allocated),
				atomic_read(&sbi->s_bal_reqs),
				atomic_read(&sbi->s_bal_success));
		printk(KERN_INFO
		      "EXT4-fs: mballoc: %u extents scanned, %u goal hits, "
				"%u 2^N hits, %u breaks, %u lost\n",
				atomic_read(&sbi->s_bal_ex_scanned),
				atomic_read(&sbi->s_bal_goals),
				atomic_read(&sbi->s_bal_2orders),
				atomic_read(&sbi->s_bal_breaks),
				atomic_read(&sbi->s_mb_lost_chunks));
		printk(KERN_INFO
		       "EXT4-fs: mballoc: %lu generated and it took %Lu\n",
				sbi->s_mb_buddies_generated++,
				sbi->s_mb_generation_time);
		printk(KERN_INFO
		       "EXT4-fs: mballoc: %u preallocated, %u discarded\n",
				atomic_read(&sbi->s_mb_preallocated),
				atomic_read(&sbi->s_mb_discarded));
	}

	free_percpu(sbi->s_locality_groups);
	if (sbi->s_proc)
		remove_proc_entry("mb_groups", sbi->s_proc);

	return 0;
}

/*
 * This function is called by the jbd2 layer once the commit has finished,
 * so we know we can free the blocks that were released with that commit.
 */
static void release_blocks_on_commit(journal_t *journal, transaction_t *txn)
{
	struct super_block *sb = journal->j_private;
	struct ext4_buddy e4b;
	struct ext4_group_info *db;
	int err, count = 0, count2 = 0;
	struct ext4_free_data *entry;
	struct list_head *l, *ltmp;

	list_for_each_safe(l, ltmp, &txn->t_private_list) {
		entry = list_entry(l, struct ext4_free_data, list);

		mb_debug(1, "gonna free %u blocks in group %u (0x%p):",
			 entry->count, entry->group, entry);

		if (test_opt(sb, DISCARD)) {
			ext4_fsblk_t discard_block;

			discard_block = entry->start_blk +
				ext4_group_first_block_no(sb, entry->group);
			trace_ext4_discard_blocks(sb,
					(unsigned long long)discard_block,
					entry->count);
			sb_issue_discard(sb, discard_block, entry->count);
		}

		err = ext4_mb_load_buddy(sb, entry->group, &e4b);
		/* we expect to find existing buddy because it's pinned */
		BUG_ON(err != 0);

		db = e4b.bd_info;
		/* there are blocks to put in buddy to make them really free */
		count += entry->count;
		count2++;
		ext4_lock_group(sb, entry->group);
		/* Take it out of per group rb tree */
		rb_erase(&entry->node, &(db->bb_free_root));
		mb_free_blocks(NULL, &e4b, entry->start_blk, entry->count);

		if (!db->bb_free_root.rb_node) {
			/* No more items in the per group rb tree
			 * balance refcounts from ext4_mb_free_metadata()
			 */
			page_cache_release(e4b.bd_buddy_page);
			page_cache_release(e4b.bd_bitmap_page);
		}
		ext4_unlock_group(sb, entry->group);
		kmem_cache_free(ext4_free_ext_cachep, entry);
		ext4_mb_release_desc(&e4b);
	}

	mb_debug(1, "freed %u blocks in %u structures\n", count, count2);
}

#ifdef CONFIG_EXT4_DEBUG
u8 mb_enable_debug __read_mostly;

static struct dentry *debugfs_dir;
static struct dentry *debugfs_debug;

static void __init ext4_create_debugfs_entry(void)
{
	debugfs_dir = debugfs_create_dir("ext4", NULL);
	if (debugfs_dir)
		debugfs_debug = debugfs_create_u8("mballoc-debug",
						  S_IRUGO | S_IWUSR,
						  debugfs_dir,
						  &mb_enable_debug);
}

static void ext4_remove_debugfs_entry(void)
{
	debugfs_remove(debugfs_debug);
	debugfs_remove(debugfs_dir);
}

#else

static void __init ext4_create_debugfs_entry(void)
{
}

static void ext4_remove_debugfs_entry(void)
{
}

#endif
//初始化块分配需要的缓存
int __init init_ext4_mballoc(void)
{
	ext4_pspace_cachep =
		kmem_cache_create("ext4_prealloc_space",
				     sizeof(struct ext4_prealloc_space),
				     0, SLAB_RECLAIM_ACCOUNT, NULL);
	if (ext4_pspace_cachep == NULL)
		return -ENOMEM;

	ext4_ac_cachep =
		kmem_cache_create("ext4_alloc_context",
				     sizeof(struct ext4_allocation_context),
				     0, SLAB_RECLAIM_ACCOUNT, NULL);
	if (ext4_ac_cachep == NULL) {
		kmem_cache_destroy(ext4_pspace_cachep);
		return -ENOMEM;
	}

	ext4_free_ext_cachep =
		kmem_cache_create("ext4_free_block_extents",
				     sizeof(struct ext4_free_data),
				     0, SLAB_RECLAIM_ACCOUNT, NULL);
	if (ext4_free_ext_cachep == NULL) {
		kmem_cache_destroy(ext4_pspace_cachep);
		kmem_cache_destroy(ext4_ac_cachep);
		return -ENOMEM;
	}
	ext4_create_debugfs_entry();
	return 0;
}

void exit_ext4_mballoc(void)
{
	/* 
	 * Wait for completion of call_rcu()'s on ext4_pspace_cachep
	 * before destroying the slab cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(ext4_pspace_cachep);
	kmem_cache_destroy(ext4_ac_cachep);
	kmem_cache_destroy(ext4_free_ext_cachep);
	ext4_remove_debugfs_entry();
}


/*
 * Check quota and mark choosed space (ac->ac_b_ex) non-free in bitmaps
 * Returns 0 if success or error code
 */
static noinline_for_stack int
ext4_mb_mark_diskspace_used(struct ext4_allocation_context *ac,
				handle_t *handle, unsigned int reserv_blks)
{
	struct buffer_head *bitmap_bh = NULL;
	struct ext4_super_block *es;
	struct ext4_group_desc *gdp;
	struct buffer_head *gdp_bh;
	struct ext4_sb_info *sbi;
	struct super_block *sb;
	ext4_fsblk_t block;
	int err, len;

	BUG_ON(ac->ac_status != AC_STATUS_FOUND);
	BUG_ON(ac->ac_b_ex.fe_len <= 0);

	sb = ac->ac_sb;
	sbi = EXT4_SB(sb);
	es = sbi->s_es;


	err = -EIO;
	bitmap_bh = ext4_read_block_bitmap(sb, ac->ac_b_ex.fe_group);
	if (!bitmap_bh)
		goto out_err;

	err = ext4_journal_get_write_access(handle, bitmap_bh);
	if (err)
		goto out_err;

	err = -EIO;
	gdp = ext4_get_group_desc(sb, ac->ac_b_ex.fe_group, &gdp_bh);
	if (!gdp)
		goto out_err;

	ext4_debug("using block group %u(%d)\n", ac->ac_b_ex.fe_group,
			ext4_free_blks_count(sb, gdp));

	err = ext4_journal_get_write_access(handle, gdp_bh);
	if (err)
		goto out_err;

	block = ext4_grp_offs_to_block(sb, &ac->ac_b_ex);

	len = ac->ac_b_ex.fe_len;
	if (!ext4_data_block_valid(sbi, block, len)) {
		ext4_error(sb, "Allocating blocks %llu-%llu which overlap "
			   "fs metadata\n", block, block+len);
		/* File system mounted not to panic on error
		 * Fix the bitmap and repeat the block allocation
		 * We leak some of the blocks here.
		 */
		ext4_lock_group(sb, ac->ac_b_ex.fe_group);
		mb_set_bits(bitmap_bh->b_data, ac->ac_b_ex.fe_start,
			    ac->ac_b_ex.fe_len);
		ext4_unlock_group(sb, ac->ac_b_ex.fe_group);
		err = ext4_handle_dirty_metadata(handle, NULL, bitmap_bh);
		if (!err)
			err = -EAGAIN;
		goto out_err;
	}

	ext4_lock_group(sb, ac->ac_b_ex.fe_group);
#ifdef AGGRESSIVE_CHECK
	{
		int i;
		for (i = 0; i < ac->ac_b_ex.fe_len; i++) {
			BUG_ON(mb_test_bit(ac->ac_b_ex.fe_start + i,
						bitmap_bh->b_data));
		}
	}
#endif
	mb_set_bits(bitmap_bh->b_data, ac->ac_b_ex.fe_start,ac->ac_b_ex.fe_len);
	if (gdp->bg_flags & cpu_to_le16(EXT4_BG_BLOCK_UNINIT)) {
		gdp->bg_flags &= cpu_to_le16(~EXT4_BG_BLOCK_UNINIT);
		ext4_free_blks_set(sb, gdp,
					ext4_free_blocks_after_init(sb,
					ac->ac_b_ex.fe_group, gdp));
	}
	len = ext4_free_blks_count(sb, gdp) - ac->ac_b_ex.fe_len;
	ext4_free_blks_set(sb, gdp, len);
	gdp->bg_checksum = ext4_group_desc_csum(sbi, ac->ac_b_ex.fe_group, gdp);

	ext4_unlock_group(sb, ac->ac_b_ex.fe_group);
	percpu_counter_sub(&sbi->s_freeblocks_counter, ac->ac_b_ex.fe_len);
	/*
	 * Now reduce the dirty block count also. Should not go negative
	 */
	if (!(ac->ac_flags & EXT4_MB_DELALLOC_RESERVED))
		/* release all the reserved blocks if non delalloc */
		percpu_counter_sub(&sbi->s_dirtyblocks_counter, reserv_blks);

	if (sbi->s_log_groups_per_flex) {
		ext4_group_t flex_group = ext4_flex_group(sbi,
							  ac->ac_b_ex.fe_group);
		atomic_sub(ac->ac_b_ex.fe_len,
			   &sbi->s_flex_groups[flex_group].free_blocks);
	}

	err = ext4_handle_dirty_metadata(handle, NULL, bitmap_bh);
	if (err)
		goto out_err;
	err = ext4_handle_dirty_metadata(handle, NULL, gdp_bh);

out_err:
	sb->s_dirt = 1;
	brelse(bitmap_bh);
	return err;
}

/*
 * here we normalize request for locality group
 * Group request are normalized to s_strip size if we set the same via mount
 * option. If not we set it to s_mb_group_prealloc which can be configured via
 * /sys/fs/ext4/<partition>/mb_group_prealloc
 *
 * XXX: should we try to preallocate more than the group has now?
 */
static void ext4_mb_normalize_group_request(struct ext4_allocation_context *ac)
{
	struct super_block *sb = ac->ac_sb;
	struct ext4_locality_group *lg = ac->ac_lg;

	BUG_ON(lg == NULL);
	if (EXT4_SB(sb)->s_stripe)
		ac->ac_g_ex.fe_len = EXT4_SB(sb)->s_stripe;
	else
		ac->ac_g_ex.fe_len = EXT4_SB(sb)->s_mb_group_prealloc;
	mb_debug(1, "#%u: goal %u blocks for locality group\n",
		current->pid, ac->ac_g_ex.fe_len);
}

/*
 * Normalization means making request better in terms of
 * size and alignment
 */
static noinline_for_stack void
ext4_mb_normalize_request(struct ext4_allocation_context *ac,
				struct ext4_allocation_request *ar)
{
	int bsbits, max;
	ext4_lblk_t end;
	loff_t size, orig_size, start_off;
	ext4_lblk_t start, orig_start;
	struct ext4_inode_info *ei = EXT4_I(ac->ac_inode);
	struct ext4_prealloc_space *pa;

	/* do normalize only data requests, metadata requests
	   do not need preallocation */
	if (!(ac->ac_flags & EXT4_MB_HINT_DATA))
		return;

	/* sometime caller may want exact blocks */
	if (unlikely(ac->ac_flags & EXT4_MB_HINT_GOAL_ONLY))
		return;

	/* caller may indicate that preallocation isn't
	 * required (it's a tail, for example) */
	if (ac->ac_flags & EXT4_MB_HINT_NOPREALLOC)
		return;

	if (ac->ac_flags & EXT4_MB_HINT_GROUP_ALLOC) {
		ext4_mb_normalize_group_request(ac);
		return ;
	}

	bsbits = ac->ac_sb->s_blocksize_bits;

	/* first, let's learn actual file size
	 * given current request is allocated */
	size = ac->ac_o_ex.fe_logical + ac->ac_o_ex.fe_len;
	size = size << bsbits;
	if (size < i_size_read(ac->ac_inode))
		size = i_size_read(ac->ac_inode);

	/* max size of free chunks */
	max = 2 << bsbits;

#define NRL_CHECK_SIZE(req, size, max, chunk_size)	\
		(req <= (size) || max <= (chunk_size))

	/* first, try to predict filesize */
	/* XXX: should this table be tunable? */
	start_off = 0;
	if (size <= 16 * 1024) {
		size = 16 * 1024;
	} else if (size <= 32 * 1024) {
		size = 32 * 1024;
	} else if (size <= 64 * 1024) {
		size = 64 * 1024;
	} else if (size <= 128 * 1024) {
		size = 128 * 1024;
	} else if (size <= 256 * 1024) {
		size = 256 * 1024;
	} else if (size <= 512 * 1024) {
		size = 512 * 1024;
	} else if (size <= 1024 * 1024) {
		size = 1024 * 1024;
	} else if (NRL_CHECK_SIZE(size, 4 * 1024 * 1024, max, 2 * 1024)) {
		start_off = ((loff_t)ac->ac_o_ex.fe_logical >>
						(21 - bsbits)) << 21;
		size = 2 * 1024 * 1024;
	} else if (NRL_CHECK_SIZE(size, 8 * 1024 * 1024, max, 4 * 1024)) {
		start_off = ((loff_t)ac->ac_o_ex.fe_logical >>
							(22 - bsbits)) << 22;
		size = 4 * 1024 * 1024;
	} else if (NRL_CHECK_SIZE(ac->ac_o_ex.fe_len,
					(8<<20)>>bsbits, max, 8 * 1024)) {
		start_off = ((loff_t)ac->ac_o_ex.fe_logical >>
							(23 - bsbits)) << 23;
		size = 8 * 1024 * 1024;
	} else {
		start_off = (loff_t)ac->ac_o_ex.fe_logical << bsbits;
		size	  = ac->ac_o_ex.fe_len << bsbits;
	}
	orig_size = size = size >> bsbits;
	orig_start = start = start_off >> bsbits;

	/* don't cover already allocated blocks in selected range */
	if (ar->pleft && start <= ar->lleft) {
		size -= ar->lleft + 1 - start;
		start = ar->lleft + 1;
	}
	if (ar->pright && start + size - 1 >= ar->lright)
		size -= start + size - ar->lright;

	end = start + size;

	/* check we don't cross already preallocated blocks */
	rcu_read_lock();
	list_for_each_entry_rcu(pa, &ei->i_prealloc_list, pa_inode_list) {
		ext4_lblk_t pa_end;

		if (pa->pa_deleted)
			continue;
		spin_lock(&pa->pa_lock);
		if (pa->pa_deleted) {
			spin_unlock(&pa->pa_lock);
			continue;
		}

		pa_end = pa->pa_lstart + pa->pa_len;

		/* PA must not overlap original request */
		BUG_ON(!(ac->ac_o_ex.fe_logical >= pa_end ||
			ac->ac_o_ex.fe_logical < pa->pa_lstart));

		/* skip PAs this normalized request doesn't overlap with */
		if (pa->pa_lstart >= end || pa_end <= start) {
			spin_unlock(&pa->pa_lock);
			continue;
		}
		BUG_ON(pa->pa_lstart <= start && pa_end >= end);

		/* adjust start or end to be adjacent to this pa */
		if (pa_end <= ac->ac_o_ex.fe_logical) {
			BUG_ON(pa_end < start);
			start = pa_end;
		} else if (pa->pa_lstart > ac->ac_o_ex.fe_logical) {
			BUG_ON(pa->pa_lstart > end);
			end = pa->pa_lstart;
		}
		spin_unlock(&pa->pa_lock);
	}
	rcu_read_unlock();
	size = end - start;

	/* XXX: extra loop to check we really don't overlap preallocations */
	rcu_read_lock();
	list_for_each_entry_rcu(pa, &ei->i_prealloc_list, pa_inode_list) {
		ext4_lblk_t pa_end;
		spin_lock(&pa->pa_lock);
		if (pa->pa_deleted == 0) {
			pa_end = pa->pa_lstart + pa->pa_len;
			BUG_ON(!(start >= pa_end || end <= pa->pa_lstart));
		}
		spin_unlock(&pa->pa_lock);
	}
	rcu_read_unlock();

	if (start + size <= ac->ac_o_ex.fe_logical &&
			start > ac->ac_o_ex.fe_logical) {
		printk(KERN_ERR "start %lu, size %lu, fe_logical %lu\n",
			(unsigned long) start, (unsigned long) size,
			(unsigned long) ac->ac_o_ex.fe_logical);
	}
	BUG_ON(start + size <= ac->ac_o_ex.fe_logical &&
			start > ac->ac_o_ex.fe_logical);
	BUG_ON(size <= 0 || size > EXT4_BLOCKS_PER_GROUP(ac->ac_sb));

	/* now prepare goal request */

	/* XXX: is it better to align blocks WRT to logical
	 * placement or satisfy big request as is */
	ac->ac_g_ex.fe_logical = start;
	ac->ac_g_ex.fe_len = size;

	/* define goal start in order to merge */
	if (ar->pright && (ar->lright == (start + size))) {
		/* merge to the right */
		ext4_get_group_no_and_offset(ac->ac_sb, ar->pright - size,
						&ac->ac_f_ex.fe_group,
						&ac->ac_f_ex.fe_start);
		ac->ac_flags |= EXT4_MB_HINT_TRY_GOAL;
	}
	if (ar->pleft && (ar->lleft + 1 == start)) {
		/* merge to the left */
		ext4_get_group_no_and_offset(ac->ac_sb, ar->pleft + 1,
						&ac->ac_f_ex.fe_group,
						&ac->ac_f_ex.fe_start);
		ac->ac_flags |= EXT4_MB_HINT_TRY_GOAL;
	}

	mb_debug(1, "goal: %u(was %u) blocks at %u\n", (unsigned) size,
		(unsigned) orig_size, (unsigned) start);
}

static void ext4_mb_collect_stats(struct ext4_allocation_context *ac)
{
	struct ext4_sb_info *sbi = EXT4_SB(ac->ac_sb);

	if (sbi->s_mb_stats && ac->ac_g_ex.fe_len > 1) {
		atomic_inc(&sbi->s_bal_reqs);
		atomic_add(ac->ac_b_ex.fe_len, &sbi->s_bal_allocated);
		if (ac->ac_o_ex.fe_len >= ac->ac_g_ex.fe_len)
			atomic_inc(&sbi->s_bal_success);
		atomic_add(ac->ac_found, &sbi->s_bal_ex_scanned);
		if (ac->ac_g_ex.fe_start == ac->ac_b_ex.fe_start &&
				ac->ac_g_ex.fe_group == ac->ac_b_ex.fe_group)
			atomic_inc(&sbi->s_bal_goals);
		if (ac->ac_found > sbi->s_mb_max_to_scan)
			atomic_inc(&sbi->s_bal_breaks);
	}

	if (ac->ac_op == EXT4_MB_HISTORY_ALLOC)
		trace_ext4_mballoc_alloc(ac);
	else
		trace_ext4_mballoc_prealloc(ac);
}

/*
 * Called on failure; free up any blocks from the inode PA for this
 * context.  We don't need this for MB_GROUP_PA because we only change
 * pa_free in ext4_mb_release_context(), but on failure, we've already
 * zeroed out ac->ac_b_ex.fe_len, so group_pa->pa_free is not changed.
 */
static void ext4_discard_allocated_blocks(struct ext4_allocation_context *ac)
{
	struct ext4_prealloc_space *pa = ac->ac_pa;
	int len;

	if (pa && pa->pa_type == MB_INODE_PA) {
		len = ac->ac_b_ex.fe_len;
		pa->pa_free += len;
	}

}

/*
 * use blocks preallocated to inode
 */
static void ext4_mb_use_inode_pa(struct ext4_allocation_context *ac,
				struct ext4_prealloc_space *pa)
{
	ext4_fsblk_t start;
	ext4_fsblk_t end;
	int len;

	/* found preallocated blocks, use them */
	start = pa->pa_pstart + (ac->ac_o_ex.fe_logical - pa->pa_lstart);
	end = min(pa->pa_pstart + pa->pa_len, start + ac->ac_o_ex.fe_len);
	len = end - start;
	ext4_get_group_no_and_offset(ac->ac_sb, start, &ac->ac_b_ex.fe_group,
					&ac->ac_b_ex.fe_start);
	ac->ac_b_ex.fe_len = len;
	ac->ac_status = AC_STATUS_FOUND;
	ac->ac_pa = pa;

	BUG_ON(start < pa->pa_pstart);
	BUG_ON(start + len > pa->pa_pstart + pa->pa_len);
	BUG_ON(pa->pa_free < len);
	pa->pa_free -= len;

	mb_debug(1, "use %llu/%u from inode pa %p\n", start, len, pa);
}

/*
 * use blocks preallocated to locality group
 */
static void ext4_mb_use_group_pa(struct ext4_allocation_context *ac,
				struct ext4_prealloc_space *pa)
{
	unsigned int len = ac->ac_o_ex.fe_len;

	ext4_get_group_no_and_offset(ac->ac_sb, pa->pa_pstart,
					&ac->ac_b_ex.fe_group,
					&ac->ac_b_ex.fe_start);
	ac->ac_b_ex.fe_len = len;
	ac->ac_status = AC_STATUS_FOUND;
	ac->ac_pa = pa;

	/* we don't correct pa_pstart or pa_plen here to avoid
	 * possible race when the group is being loaded concurrently
	 * instead we correct pa later, after blocks are marked
	 * in on-disk bitmap -- see ext4_mb_release_context()
	 * Other CPUs are prevented from allocating from this pa by lg_mutex
	 */
	mb_debug(1, "use %u/%u from group pa %p\n", pa->pa_lstart-len, len, pa);
}

/*
 * Return the prealloc space that have minimal distance
 * from the goal block. @cpa is the prealloc
 * space that is having currently known minimal distance
 * from the goal block.
 */
static struct ext4_prealloc_space *
ext4_mb_check_group_pa(ext4_fsblk_t goal_block,
			struct ext4_prealloc_space *pa,
			struct ext4_prealloc_space *cpa)
{
	ext4_fsblk_t cur_distance, new_distance;

	if (cpa == NULL) {
		atomic_inc(&pa->pa_count);
		return pa;
	}
	cur_distance = abs(goal_block - cpa->pa_pstart);
	new_distance = abs(goal_block - pa->pa_pstart);

	if (cur_distance < new_distance)
		return cpa;

	/* drop the previous reference */
	atomic_dec(&cpa->pa_count);
	atomic_inc(&pa->pa_count);
	return pa;
}

/*
 * search goal blocks in preallocated space
 */
static noinline_for_stack int
ext4_mb_use_preallocated(struct ext4_allocation_context *ac)
{
	int order, i;
	struct ext4_inode_info *ei = EXT4_I(ac->ac_inode);
	struct ext4_locality_group *lg;
	struct ext4_prealloc_space *pa, *cpa = NULL;
	ext4_fsblk_t goal_block;

	/* only data can be preallocated */
	if (!(ac->ac_flags & EXT4_MB_HINT_DATA))
		return 0;

	/* first, try per-file preallocation */
	rcu_read_lock();
	list_for_each_entry_rcu(pa, &ei->i_prealloc_list, pa_inode_list) {

		/* all fields in this condition don't change,
		 * so we can skip locking for them */
		if (ac->ac_o_ex.fe_logical < pa->pa_lstart ||
			ac->ac_o_ex.fe_logical >= pa->pa_lstart + pa->pa_len)
			continue;

		/* non-extent files can't have physical blocks past 2^32 */
		if (!(EXT4_I(ac->ac_inode)->i_flags & EXT4_EXTENTS_FL) &&
			pa->pa_pstart + pa->pa_len > EXT4_MAX_BLOCK_FILE_PHYS)
			continue;

		/* found preallocated blocks, use them */
		spin_lock(&pa->pa_lock);
		if (pa->pa_deleted == 0 && pa->pa_free) {
			atomic_inc(&pa->pa_count);
			ext4_mb_use_inode_pa(ac, pa);
			spin_unlock(&pa->pa_lock);
			ac->ac_criteria = 10;
			rcu_read_unlock();
			return 1;
		}
		spin_unlock(&pa->pa_lock);
	}
	rcu_read_unlock();

	/* can we use group allocation? */
	if (!(ac->ac_flags & EXT4_MB_HINT_GROUP_ALLOC))
		return 0;

	/* inode may have no locality group for some reason */
	lg = ac->ac_lg;
	if (lg == NULL)
		return 0;
	order  = fls(ac->ac_o_ex.fe_len) - 1;
	if (order > PREALLOC_TB_SIZE - 1)
		/* The max size of hash table is PREALLOC_TB_SIZE */
		order = PREALLOC_TB_SIZE - 1;

	goal_block = ext4_grp_offs_to_block(ac->ac_sb, &ac->ac_g_ex);
	/*
	 * search for the prealloc space that is having
	 * minimal distance from the goal block.
	 */
	for (i = order; i < PREALLOC_TB_SIZE; i++) {
		rcu_read_lock();
		list_for_each_entry_rcu(pa, &lg->lg_prealloc_list[i],
					pa_inode_list) {
			spin_lock(&pa->pa_lock);
			if (pa->pa_deleted == 0 &&
					pa->pa_free >= ac->ac_o_ex.fe_len) {

				cpa = ext4_mb_check_group_pa(goal_block,
								pa, cpa);
			}
			spin_unlock(&pa->pa_lock);
		}
		rcu_read_unlock();
	}
	if (cpa) {
		ext4_mb_use_group_pa(ac, cpa);
		ac->ac_criteria = 20;
		return 1;
	}
	return 0;
}

/*
 * the function goes through all block freed in the group
 * but not yet committed and marks them used in in-core bitmap.
 * buddy must be generated from this bitmap
 * Need to be called with the ext4 group lock held
 */
static void ext4_mb_generate_from_freelist(struct super_block *sb, void *bitmap,
						ext4_group_t group)
{
	struct rb_node *n;
	struct ext4_group_info *grp;
	struct ext4_free_data *entry;

	grp = ext4_get_group_info(sb, group);
	n = rb_first(&(grp->bb_free_root));

	while (n) {
		entry = rb_entry(n, struct ext4_free_data, node);
		mb_set_bits(bitmap, entry->start_blk, entry->count);
		n = rb_next(n);
	}
	return;
}

/*
 * the function goes through all preallocation in this group and marks them
 * used in in-core bitmap. buddy must be generated from this bitmap
 * Need to be called with ext4 group lock held
 */
static noinline_for_stack
void ext4_mb_generate_from_pa(struct super_block *sb, void *bitmap,
					ext4_group_t group)
{
	struct ext4_group_info *grp = ext4_get_group_info(sb, group);
	struct ext4_prealloc_space *pa;
	struct list_head *cur;
	ext4_group_t groupnr;
	ext4_grpblk_t start;
	int preallocated = 0;
	int count = 0;
	int len;

	/* all form of preallocation discards first load group,
	 * so the only competing code is preallocation use.
	 * we don't need any locking here
	 * notice we do NOT ignore preallocations with pa_deleted
	 * otherwise we could leave used blocks available for
	 * allocation in buddy when concurrent ext4_mb_put_pa()
	 * is dropping preallocation
	 */
	list_for_each(cur, &grp->bb_prealloc_list) {
		pa = list_entry(cur, struct ext4_prealloc_space, pa_group_list);
		spin_lock(&pa->pa_lock);
		ext4_get_group_no_and_offset(sb, pa->pa_pstart,
					     &groupnr, &start);
		len = pa->pa_len;
		spin_unlock(&pa->pa_lock);
		if (unlikely(len == 0))
			continue;
		BUG_ON(groupnr != group);
		mb_set_bits(bitmap, start, len);
		preallocated += len;
		count++;
	}
	mb_debug(1, "prellocated %u for group %u\n", preallocated, group);
}

static void ext4_mb_pa_callback(struct rcu_head *head)
{
	struct ext4_prealloc_space *pa;
	pa = container_of(head, struct ext4_prealloc_space, u.pa_rcu);
	kmem_cache_free(ext4_pspace_cachep, pa);
}

/*
 * drops a reference to preallocated space descriptor
 * if this was the last reference and the space is consumed
 */
static void ext4_mb_put_pa(struct ext4_allocation_context *ac,
			struct super_block *sb, struct ext4_prealloc_space *pa)
{
	ext4_group_t grp;
	ext4_fsblk_t grp_blk;

	if (!atomic_dec_and_test(&pa->pa_count) || pa->pa_free != 0)
		return;

	/* in this short window concurrent discard can set pa_deleted */
	spin_lock(&pa->pa_lock);
	if (pa->pa_deleted == 1) {
		spin_unlock(&pa->pa_lock);
		return;
	}

	pa->pa_deleted = 1;
	spin_unlock(&pa->pa_lock);

	grp_blk = pa->pa_pstart;
	/* 
	 * If doing group-based preallocation, pa_pstart may be in the
	 * next group when pa is used up
	 */
	if (pa->pa_type == MB_GROUP_PA)
		grp_blk--;

	ext4_get_group_no_and_offset(sb, grp_blk, &grp, NULL);

	/*
	 * possible race:
	 *
	 *  P1 (buddy init)			P2 (regular allocation)
	 *					find block B in PA
	 *  copy on-disk bitmap to buddy
	 *  					mark B in on-disk bitmap
	 *					drop PA from group
	 *  mark all PAs in buddy
	 *
	 * thus, P1 initializes buddy with B available. to prevent this
	 * we make "copy" and "mark all PAs" atomic and serialize "drop PA"
	 * against that pair
	 */
	ext4_lock_group(sb, grp);
	list_del(&pa->pa_group_list);
	ext4_unlock_group(sb, grp);

	spin_lock(pa->pa_obj_lock);
	list_del_rcu(&pa->pa_inode_list);
	spin_unlock(pa->pa_obj_lock);

	call_rcu(&(pa)->u.pa_rcu, ext4_mb_pa_callback);
}

/*
 * creates new preallocated space for given inode
 */
static noinline_for_stack int
ext4_mb_new_inode_pa(struct ext4_allocation_context *ac)
{
	struct super_block *sb = ac->ac_sb;
	struct ext4_prealloc_space *pa;
	struct ext4_group_info *grp;
	struct ext4_inode_info *ei;

	/* preallocate only when found space is larger then requested */
	BUG_ON(ac->ac_o_ex.fe_len >= ac->ac_b_ex.fe_len);
	BUG_ON(ac->ac_status != AC_STATUS_FOUND);
	BUG_ON(!S_ISREG(ac->ac_inode->i_mode));

	pa = kmem_cache_alloc(ext4_pspace_cachep, GFP_NOFS);
	if (pa == NULL)
		return -ENOMEM;

	if (ac->ac_b_ex.fe_len < ac->ac_g_ex.fe_len) {
		int winl;
		int wins;
		int win;
		int offs;

		/* we can't allocate as much as normalizer wants.
		 * so, found space must get proper lstart
		 * to cover original request */
		BUG_ON(ac->ac_g_ex.fe_logical > ac->ac_o_ex.fe_logical);
		BUG_ON(ac->ac_g_ex.fe_len < ac->ac_o_ex.fe_len);

		/* we're limited by original request in that
		 * logical block must be covered any way
		 * winl is window we can move our chunk within */
		winl = ac->ac_o_ex.fe_logical - ac->ac_g_ex.fe_logical;

		/* also, we should cover whole original request */
		wins = ac->ac_b_ex.fe_len - ac->ac_o_ex.fe_len;

		/* the smallest one defines real window */
		win = min(winl, wins);

		offs = ac->ac_o_ex.fe_logical % ac->ac_b_ex.fe_len;
		if (offs && offs < win)
			win = offs;

		ac->ac_b_ex.fe_logical = ac->ac_o_ex.fe_logical - win;
		BUG_ON(ac->ac_o_ex.fe_logical < ac->ac_b_ex.fe_logical);
		BUG_ON(ac->ac_o_ex.fe_len > ac->ac_b_ex.fe_len);
	}

	/* preallocation can change ac_b_ex, thus we store actually
	 * allocated blocks for history */
	ac->ac_f_ex = ac->ac_b_ex;

	pa->pa_lstart = ac->ac_b_ex.fe_logical;
	pa->pa_pstart = ext4_grp_offs_to_block(sb, &ac->ac_b_ex);
	pa->pa_len = ac->ac_b_ex.fe_len;
	pa->pa_free = pa->pa_len;
	atomic_set(&pa->pa_count, 1);
	spin_lock_init(&pa->pa_lock);
	INIT_LIST_HEAD(&pa->pa_inode_list);
	INIT_LIST_HEAD(&pa->pa_group_list);
	pa->pa_deleted = 0;
	pa->pa_type = MB_INODE_PA;

	mb_debug(1, "new inode pa %p: %llu/%u for %u\n", pa,
			pa->pa_pstart, pa->pa_len, pa->pa_lstart);
	trace_ext4_mb_new_inode_pa(ac, pa);

	ext4_mb_use_inode_pa(ac, pa);
	atomic_add(pa->pa_free, &EXT4_SB(sb)->s_mb_preallocated);

	ei = EXT4_I(ac->ac_inode);
	grp = ext4_get_group_info(sb, ac->ac_b_ex.fe_group);

	pa->pa_obj_lock = &ei->i_prealloc_lock;
	pa->pa_inode = ac->ac_inode;

	ext4_lock_group(sb, ac->ac_b_ex.fe_group);
	list_add(&pa->pa_group_list, &grp->bb_prealloc_list);
	ext4_unlock_group(sb, ac->ac_b_ex.fe_group);

	spin_lock(pa->pa_obj_lock);
	list_add_rcu(&pa->pa_inode_list, &ei->i_prealloc_list);
	spin_unlock(pa->pa_obj_lock);

	return 0;
}

/*
 * creates new preallocated space for locality group inodes belongs to
 */
static noinline_for_stack int
ext4_mb_new_group_pa(struct ext4_allocation_context *ac)
{
	struct super_block *sb = ac->ac_sb;
	struct ext4_locality_group *lg;
	struct ext4_prealloc_space *pa;
	struct ext4_group_info *grp;

	/* preallocate only when found space is larger then requested */
	BUG_ON(ac->ac_o_ex.fe_len >= ac->ac_b_ex.fe_len);
	BUG_ON(ac->ac_status != AC_STATUS_FOUND);
	BUG_ON(!S_ISREG(ac->ac_inode->i_mode));

	BUG_ON(ext4_pspace_cachep == NULL);
	pa = kmem_cache_alloc(ext4_pspace_cachep, GFP_NOFS);
	if (pa == NULL)
		return -ENOMEM;

	/* preallocation can change ac_b_ex, thus we store actually
	 * allocated blocks for history */
	ac->ac_f_ex = ac->ac_b_ex;

	pa->pa_pstart = ext4_grp_offs_to_block(sb, &ac->ac_b_ex);
	pa->pa_lstart = pa->pa_pstart;
	pa->pa_len = ac->ac_b_ex.fe_len;
	pa->pa_free = pa->pa_len;
	atomic_set(&pa->pa_count, 1);
	spin_lock_init(&pa->pa_lock);
	INIT_LIST_HEAD(&pa->pa_inode_list);
	INIT_LIST_HEAD(&pa->pa_group_list);
	pa->pa_deleted = 0;
	pa->pa_type = MB_GROUP_PA;

	mb_debug(1, "new group pa %p: %llu/%u for %u\n", pa,
			pa->pa_pstart, pa->pa_len, pa->pa_lstart);
	trace_ext4_mb_new_group_pa(ac, pa);

	ext4_mb_use_group_pa(ac, pa);
	atomic_add(pa->pa_free, &EXT4_SB(sb)->s_mb_preallocated);

	grp = ext4_get_group_info(sb, ac->ac_b_ex.fe_group);
	lg = ac->ac_lg;
	BUG_ON(lg == NULL);

	pa->pa_obj_lock = &lg->lg_prealloc_lock;
	pa->pa_inode = NULL;

	ext4_lock_group(sb, ac->ac_b_ex.fe_group);
	list_add(&pa->pa_group_list, &grp->bb_prealloc_list);
	ext4_unlock_group(sb, ac->ac_b_ex.fe_group);

	/*
	 * We will later add the new pa to the right bucket
	 * after updating the pa_free in ext4_mb_release_context
	 */
	return 0;
}

static int ext4_mb_new_preallocation(struct ext4_allocation_context *ac)
{
	int err;

	if (ac->ac_flags & EXT4_MB_HINT_GROUP_ALLOC)
		err = ext4_mb_new_group_pa(ac);
	else
		err = ext4_mb_new_inode_pa(ac);
	return err;
}

/*
 * finds all unused blocks in on-disk bitmap, frees them in
 * in-core bitmap and buddy.
 * @pa must be unlinked from inode and group lists, so that
 * nobody else can find/use it.
 * the caller MUST hold group/inode locks.
 * TODO: optimize the case when there are no in-core structures yet
 */
static noinline_for_stack int
ext4_mb_release_inode_pa(struct ext4_buddy *e4b, struct buffer_head *bitmap_bh,
			struct ext4_prealloc_space *pa,
			struct ext4_allocation_context *ac)
{
	struct super_block *sb = e4b->bd_sb;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	unsigned int end;
	unsigned int next;
	ext4_group_t group;
	ext4_grpblk_t bit;
	unsigned long long grp_blk_start;
	sector_t start;
	int err = 0;
	int free = 0;

	BUG_ON(pa->pa_deleted == 0);
	ext4_get_group_no_and_offset(sb, pa->pa_pstart, &group, &bit);
	grp_blk_start = pa->pa_pstart - bit;
	BUG_ON(group != e4b->bd_group && pa->pa_len != 0);
	end = bit + pa->pa_len;

	if (ac) {
		ac->ac_sb = sb;
		ac->ac_inode = pa->pa_inode;
	}

	while (bit < end) {
		bit = mb_find_next_zero_bit(bitmap_bh->b_data, end, bit);
		if (bit >= end)
			break;
		next = mb_find_next_bit(bitmap_bh->b_data, end, bit);
		start = ext4_group_first_block_no(sb, group) + bit;
		mb_debug(1, "    free preallocated %u/%u in group %u\n",
				(unsigned) start, (unsigned) next - bit,
				(unsigned) group);
		free += next - bit;

		if (ac) {
			ac->ac_b_ex.fe_group = group;
			ac->ac_b_ex.fe_start = bit;
			ac->ac_b_ex.fe_len = next - bit;
			ac->ac_b_ex.fe_logical = 0;
			trace_ext4_mballoc_discard(ac);
		}

		trace_ext4_mb_release_inode_pa(ac, pa, grp_blk_start + bit,
					       next - bit);
		mb_free_blocks(pa->pa_inode, e4b, bit, next - bit);
		bit = next + 1;
	}
	if (free != pa->pa_free) {
		printk(KERN_CRIT "pa %p: logic %lu, phys. %lu, len %lu\n",
			pa, (unsigned long) pa->pa_lstart,
			(unsigned long) pa->pa_pstart,
			(unsigned long) pa->pa_len);
		ext4_grp_locked_error(sb, group,
					__func__, "free %u, pa_free %u",
					free, pa->pa_free);
		/*
		 * pa is already deleted so we use the value obtained
		 * from the bitmap and continue.
		 */
	}
	atomic_add(free, &sbi->s_mb_discarded);

	return err;
}

static noinline_for_stack int
ext4_mb_release_group_pa(struct ext4_buddy *e4b,
				struct ext4_prealloc_space *pa,
				struct ext4_allocation_context *ac)
{
	struct super_block *sb = e4b->bd_sb;
	ext4_group_t group;
	ext4_grpblk_t bit;

	trace_ext4_mb_release_group_pa(ac, pa);
	BUG_ON(pa->pa_deleted == 0);
	ext4_get_group_no_and_offset(sb, pa->pa_pstart, &group, &bit);
	BUG_ON(group != e4b->bd_group && pa->pa_len != 0);
	mb_free_blocks(pa->pa_inode, e4b, bit, pa->pa_len);
	atomic_add(pa->pa_len, &EXT4_SB(sb)->s_mb_discarded);

	if (ac) {
		ac->ac_sb = sb;
		ac->ac_inode = NULL;
		ac->ac_b_ex.fe_group = group;
		ac->ac_b_ex.fe_start = bit;
		ac->ac_b_ex.fe_len = pa->pa_len;
		ac->ac_b_ex.fe_logical = 0;
		trace_ext4_mballoc_discard(ac);
	}

	return 0;
}

/*
 * releases all preallocations in given group
 *
 * first, we need to decide discard policy:
 * - when do we discard
 *   1) ENOSPC
 * - how many do we discard
 *   1) how many requested
 */
static noinline_for_stack int
ext4_mb_discard_group_preallocations(struct super_block *sb,
					ext4_group_t group, int needed)
{
	struct ext4_group_info *grp = ext4_get_group_info(sb, group);
	struct buffer_head *bitmap_bh = NULL;
	struct ext4_prealloc_space *pa, *tmp;
	struct ext4_allocation_context *ac;
	struct list_head list;
	struct ext4_buddy e4b;
	int err;
	int busy = 0;
	int free = 0;

	mb_debug(1, "discard preallocation for group %u\n", group);

	if (list_empty(&grp->bb_prealloc_list))
		return 0;

	bitmap_bh = ext4_read_block_bitmap(sb, group);
	if (bitmap_bh == NULL) {
		ext4_error(sb, "Error reading block bitmap for %u", group);
		return 0;
	}

	err = ext4_mb_load_buddy(sb, group, &e4b);
	if (err) {
		ext4_error(sb, "Error loading buddy information for %u", group);
		put_bh(bitmap_bh);
		return 0;
	}

	if (needed == 0)
		needed = EXT4_BLOCKS_PER_GROUP(sb) + 1;

	INIT_LIST_HEAD(&list);
	ac = kmem_cache_alloc(ext4_ac_cachep, GFP_NOFS);
	if (ac)
		ac->ac_sb = sb;
repeat:
	ext4_lock_group(sb, group);
	list_for_each_entry_safe(pa, tmp,
				&grp->bb_prealloc_list, pa_group_list) {
		spin_lock(&pa->pa_lock);
		if (atomic_read(&pa->pa_count)) {
			spin_unlock(&pa->pa_lock);
			busy = 1;
			continue;
		}
		if (pa->pa_deleted) {
			spin_unlock(&pa->pa_lock);
			continue;
		}

		/* seems this one can be freed ... */
		pa->pa_deleted = 1;

		/* we can trust pa_free ... */
		free += pa->pa_free;

		spin_unlock(&pa->pa_lock);

		list_del(&pa->pa_group_list);
		list_add(&pa->u.pa_tmp_list, &list);
	}

	/* if we still need more blocks and some PAs were used, try again */
	if (free < needed && busy) {
		busy = 0;
		ext4_unlock_group(sb, group);
		/*
		 * Yield the CPU here so that we don't get soft lockup
		 * in non preempt case.
		 */
		yield();
		goto repeat;
	}

	/* found anything to free? */
	if (list_empty(&list)) {
		BUG_ON(free != 0);
		goto out;
	}

	/* now free all selected PAs */
	list_for_each_entry_safe(pa, tmp, &list, u.pa_tmp_list) {

		/* remove from object (inode or locality group) */
		spin_lock(pa->pa_obj_lock);
		list_del_rcu(&pa->pa_inode_list);
		spin_unlock(pa->pa_obj_lock);

		if (pa->pa_type == MB_GROUP_PA)
			ext4_mb_release_group_pa(&e4b, pa, ac);
		else
			ext4_mb_release_inode_pa(&e4b, bitmap_bh, pa, ac);

		list_del(&pa->u.pa_tmp_list);
		call_rcu(&(pa)->u.pa_rcu, ext4_mb_pa_callback);
	}

out:
	ext4_unlock_group(sb, group);
	if (ac)
		kmem_cache_free(ext4_ac_cachep, ac);
	ext4_mb_release_desc(&e4b);
	put_bh(bitmap_bh);
	return free;
}

/*
 * releases all non-used preallocated blocks for given inode
 *
 * It's important to discard preallocations under i_data_sem
 * We don't want another block to be served from the prealloc
 * space when we are discarding the inode prealloc space.
 *
 * FIXME!! Make sure it is valid at all the call sites
 */
void ext4_discard_preallocations(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct super_block *sb = inode->i_sb;
	struct buffer_head *bitmap_bh = NULL;
	struct ext4_prealloc_space *pa, *tmp;
	struct ext4_allocation_context *ac;
	ext4_group_t group = 0;
	struct list_head list;
	struct ext4_buddy e4b;
	int err;

	if (!S_ISREG(inode->i_mode)) {
		/*BUG_ON(!list_empty(&ei->i_prealloc_list));*/
		return;
	}

	mb_debug(1, "discard preallocation for inode %lu\n", inode->i_ino);
	trace_ext4_discard_preallocations(inode);

	INIT_LIST_HEAD(&list);

	ac = kmem_cache_alloc(ext4_ac_cachep, GFP_NOFS);
	if (ac) {
		ac->ac_sb = sb;
		ac->ac_inode = inode;
	}
repeat:
	/* first, collect all pa's in the inode */
	spin_lock(&ei->i_prealloc_lock);
	while (!list_empty(&ei->i_prealloc_list)) {
		pa = list_entry(ei->i_prealloc_list.next,
				struct ext4_prealloc_space, pa_inode_list);
		BUG_ON(pa->pa_obj_lock != &ei->i_prealloc_lock);
		spin_lock(&pa->pa_lock);
		if (atomic_read(&pa->pa_count)) {
			/* this shouldn't happen often - nobody should
			 * use preallocation while we're discarding it */
			spin_unlock(&pa->pa_lock);
			spin_unlock(&ei->i_prealloc_lock);
			printk(KERN_ERR "uh-oh! used pa while discarding\n");
			WARN_ON(1);
			schedule_timeout_uninterruptible(HZ);
			goto repeat;

		}
		if (pa->pa_deleted == 0) {
			pa->pa_deleted = 1;
			spin_unlock(&pa->pa_lock);
			list_del_rcu(&pa->pa_inode_list);
			list_add(&pa->u.pa_tmp_list, &list);
			continue;
		}

		/* someone is deleting pa right now */
		spin_unlock(&pa->pa_lock);
		spin_unlock(&ei->i_prealloc_lock);

		/* we have to wait here because pa_deleted
		 * doesn't mean pa is already unlinked from
		 * the list. as we might be called from
		 * ->clear_inode() the inode will get freed
		 * and concurrent thread which is unlinking
		 * pa from inode's list may access already
		 * freed memory, bad-bad-bad */

		/* XXX: if this happens too often, we can
		 * add a flag to force wait only in case
		 * of ->clear_inode(), but not in case of
		 * regular truncate */
		schedule_timeout_uninterruptible(HZ);
		goto repeat;
	}
	spin_unlock(&ei->i_prealloc_lock);

	list_for_each_entry_safe(pa, tmp, &list, u.pa_tmp_list) {
		BUG_ON(pa->pa_type != MB_INODE_PA);
		ext4_get_group_no_and_offset(sb, pa->pa_pstart, &group, NULL);

		err = ext4_mb_load_buddy(sb, group, &e4b);
		if (err) {
			ext4_error(sb, "Error loading buddy information for %u",
					group);
			continue;
		}

		bitmap_bh = ext4_read_block_bitmap(sb, group);
		if (bitmap_bh == NULL) {
			ext4_error(sb, "Error reading block bitmap for %u",
					group);
			ext4_mb_release_desc(&e4b);
			continue;
		}

		ext4_lock_group(sb, group);
		list_del(&pa->pa_group_list);
		ext4_mb_release_inode_pa(&e4b, bitmap_bh, pa, ac);
		ext4_unlock_group(sb, group);

		ext4_mb_release_desc(&e4b);
		put_bh(bitmap_bh);

		list_del(&pa->u.pa_tmp_list);
		call_rcu(&(pa)->u.pa_rcu, ext4_mb_pa_callback);
	}
	if (ac)
		kmem_cache_free(ext4_ac_cachep, ac);
}

/*
 * finds all preallocated spaces and return blocks being freed to them
 * if preallocated space becomes full (no block is used from the space)
 * then the function frees space in buddy
 * XXX: at the moment, truncate (which is the only way to free blocks)
 * discards all preallocations
 */
static void ext4_mb_return_to_preallocation(struct inode *inode,
					struct ext4_buddy *e4b,
					sector_t block, int count)
{
	BUG_ON(!list_empty(&EXT4_I(inode)->i_prealloc_list));
}
#ifdef CONFIG_EXT4_DEBUG
static void ext4_mb_show_ac(struct ext4_allocation_context *ac)
{
	struct super_block *sb = ac->ac_sb;
	ext4_group_t ngroups, i;

	printk(KERN_ERR "EXT4-fs: Can't allocate:"
			" Allocation context details:\n");
	printk(KERN_ERR "EXT4-fs: status %d flags %d\n",
			ac->ac_status, ac->ac_flags);
	printk(KERN_ERR "EXT4-fs: orig %lu/%lu/%lu@%lu, goal %lu/%lu/%lu@%lu, "
			"best %lu/%lu/%lu@%lu cr %d\n",
			(unsigned long)ac->ac_o_ex.fe_group,
			(unsigned long)ac->ac_o_ex.fe_start,
			(unsigned long)ac->ac_o_ex.fe_len,
			(unsigned long)ac->ac_o_ex.fe_logical,
			(unsigned long)ac->ac_g_ex.fe_group,
			(unsigned long)ac->ac_g_ex.fe_start,
			(unsigned long)ac->ac_g_ex.fe_len,
			(unsigned long)ac->ac_g_ex.fe_logical,
			(unsigned long)ac->ac_b_ex.fe_group,
			(unsigned long)ac->ac_b_ex.fe_start,
			(unsigned long)ac->ac_b_ex.fe_len,
			(unsigned long)ac->ac_b_ex.fe_logical,
			(int)ac->ac_criteria);
	printk(KERN_ERR "EXT4-fs: %lu scanned, %d found\n", ac->ac_ex_scanned,
		ac->ac_found);
	printk(KERN_ERR "EXT4-fs: groups: \n");
	ngroups = ext4_get_groups_count(sb);
	for (i = 0; i < ngroups; i++) {
		struct ext4_group_info *grp = ext4_get_group_info(sb, i);
		struct ext4_prealloc_space *pa;
		ext4_grpblk_t start;
		struct list_head *cur;
		ext4_lock_group(sb, i);
		list_for_each(cur, &grp->bb_prealloc_list) {
			pa = list_entry(cur, struct ext4_prealloc_space,
					pa_group_list);
			spin_lock(&pa->pa_lock);
			ext4_get_group_no_and_offset(sb, pa->pa_pstart,
						     NULL, &start);
			spin_unlock(&pa->pa_lock);
			printk(KERN_ERR "PA:%u:%d:%u \n", i,
			       start, pa->pa_len);
		}
		ext4_unlock_group(sb, i);

		if (grp->bb_free == 0)
			continue;
		printk(KERN_ERR "%u: %d/%d \n",
		       i, grp->bb_free, grp->bb_fragments);
	}
	printk(KERN_ERR "\n");
}
#else
static inline void ext4_mb_show_ac(struct ext4_allocation_context *ac)
{
	return;
}
#endif

/*
 * We use locality group preallocation for small size file. The size of the
 * file is determined by the current size or the resulting size after
 * allocation which ever is larger
 *
 * One can tune this size via /sys/fs/ext4/<partition>/mb_stream_req
 */
static void ext4_mb_group_or_file(struct ext4_allocation_context *ac)
{
	struct ext4_sb_info *sbi = EXT4_SB(ac->ac_sb);  // 获取超级块信息
	int bsbits = ac->ac_sb->s_blocksize_bits;  // 块大小的位数
	loff_t size, isize;

	// 如果不是数据分配请求，直接返回
	if (!(ac->ac_flags & EXT4_MB_HINT_DATA))
		return;

	// 如果只使用目标分配，不需要进一步处理，直接返回
	if (unlikely(ac->ac_flags & EXT4_MB_HINT_GOAL_ONLY))
		return;

	// 计算当前分配后的文件大小
	size = ac->ac_o_ex.fe_logical + ac->ac_o_ex.fe_len;
	// 计算当前inode的大小，以块大小对齐
	isize = (i_size_read(ac->ac_inode) + ac->ac_sb->s_blocksize - 1)
		>> bsbits;

	// 如果分配后的文件大小等于当前文件大小，并且文件系统不忙，
	// 并且当前inode没有活跃的写入操作，则禁用预分配
	if ((size == isize) &&
	    !ext4_fs_is_busy(sbi) &&
	    (atomic_read(&ac->ac_inode->i_writecount) == 0)) {
		ac->ac_flags |= EXT4_MB_HINT_NOPREALLOC;  // 设置禁用预分配标志
		return;
	}

	// 对于大文件，不使用组分配
	size = max(size, isize);  // 使用更大的值作为分配的文件大小
	if (size > sbi->s_mb_stream_request) {
		ac->ac_flags |= EXT4_MB_STREAM_ALLOC;  // 设置流式分配标志
		return;
	}

	// 确保局部分配组指针为空
	BUG_ON(ac->ac_lg != NULL);
	/*
	 * 局部组预分配空间是基于每个CPU的。使用每个CPU单独的局部组
	 * 的原因是减少来自多个CPU的块请求之间的争用。
	 */
	ac->ac_lg = __this_cpu_ptr(sbi->s_locality_groups);  // 获取当前CPU的局部组

	// 将使用组分配，设置相关标志
	ac->ac_flags |= EXT4_MB_HINT_GROUP_ALLOC;

	// 为了序列化组中的所有分配操作，获取局部组的互斥锁
	mutex_lock(&ac->ac_lg->lg_mutex);
}

static noinline_for_stack int
ext4_mb_initialize_context(struct ext4_allocation_context *ac,
				struct ext4_allocation_request *ar)
{
	struct super_block *sb = ar->inode->i_sb;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct ext4_super_block *es = sbi->s_es;
	ext4_group_t group;
	unsigned int len;
	ext4_fsblk_t goal;
	ext4_grpblk_t block;

	/* 不能分配超过组大小的块 */
	len = ar->len;

	/* 通过这个小技巧过滤掉过大的请求 */
	if (len >= EXT4_BLOCKS_PER_GROUP(sb) - 10)
		len = EXT4_BLOCKS_PER_GROUP(sb) - 10;

	/* 从目标块号开始搜索 */
	goal = ar->goal;
	if (goal < le32_to_cpu(es->s_first_data_block) ||
			goal >= ext4_blocks_count(es))
		goal = le32_to_cpu(es->s_first_data_block);
	ext4_get_group_no_and_offset(sb, goal, &group, &block);

	/* 设置分配目标 */
	memset(ac, 0, sizeof(struct ext4_allocation_context));  // 初始化分配上下文结构体为0
	ac->ac_b_ex.fe_logical = ar->logical;  // 设置逻辑块号
	ac->ac_status = AC_STATUS_CONTINUE;  // 设置分配状态为继续
	ac->ac_sb = sb;  // 关联超级块
	ac->ac_inode = ar->inode;  // 关联inode
	ac->ac_o_ex.fe_logical = ar->logical;  // 设置原始分配请求的逻辑块号
	ac->ac_o_ex.fe_group = group;  // 设置目标组号
	ac->ac_o_ex.fe_start = block;  // 设置组内偏移量
	ac->ac_o_ex.fe_len = len;  // 设置分配长度
	ac->ac_g_ex.fe_logical = ar->logical;  // 设置分配目标的逻辑块号
	ac->ac_g_ex.fe_group = group;  // 设置分配目标的组号
	ac->ac_g_ex.fe_start = block;  // 设置组内偏移量
	ac->ac_g_ex.fe_len = len;  // 设置分配长度
	ac->ac_flags = ar->flags;  // 设置分配标志

	/* 定义分配策略：是针对文件分配还是局部分配组分配
	 * 实际上这是一个策略判断，用于判断当前分配是面向文件还是局部分配组
	 */
	ext4_mb_group_or_file(ac);

	/* 调试信息输出：打印初始化分配上下文的详细信息 */
	mb_debug(1, "init ac: %u blocks @ %u, goal %u, flags %x, 2^%d, "
			"left: %u/%u, right %u/%u to %swritable\n",
			(unsigned) ar->len, (unsigned) ar->logical,
			(unsigned) ar->goal, ac->ac_flags, ac->ac_2order,
			(unsigned) ar->lleft, (unsigned) ar->pleft,
			(unsigned) ar->lright, (unsigned) ar->pright,
			atomic_read(&ar->inode->i_writecount) ? "" : "non-");
	return 0;  // 返回成功
}

static noinline_for_stack void
ext4_mb_discard_lg_preallocations(struct super_block *sb,
					struct ext4_locality_group *lg,
					int order, int total_entries)
{
	ext4_group_t group = 0;
	struct ext4_buddy e4b;
	struct list_head discard_list;
	struct ext4_prealloc_space *pa, *tmp;
	struct ext4_allocation_context *ac;

	mb_debug(1, "discard locality group preallocation\n");

	INIT_LIST_HEAD(&discard_list);
	ac = kmem_cache_alloc(ext4_ac_cachep, GFP_NOFS);
	if (ac)
		ac->ac_sb = sb;

	spin_lock(&lg->lg_prealloc_lock);
	list_for_each_entry_rcu(pa, &lg->lg_prealloc_list[order],
						pa_inode_list) {
		spin_lock(&pa->pa_lock);
		if (atomic_read(&pa->pa_count)) {
			/*
			 * This is the pa that we just used
			 * for block allocation. So don't
			 * free that
			 */
			spin_unlock(&pa->pa_lock);
			continue;
		}
		if (pa->pa_deleted) {
			spin_unlock(&pa->pa_lock);
			continue;
		}
		/* only lg prealloc space */
		BUG_ON(pa->pa_type != MB_GROUP_PA);

		/* seems this one can be freed ... */
		pa->pa_deleted = 1;
		spin_unlock(&pa->pa_lock);

		list_del_rcu(&pa->pa_inode_list);
		list_add(&pa->u.pa_tmp_list, &discard_list);

		total_entries--;
		if (total_entries <= 5) {
			/*
			 * we want to keep only 5 entries
			 * allowing it to grow to 8. This
			 * mak sure we don't call discard
			 * soon for this list.
			 */
			break;
		}
	}
	spin_unlock(&lg->lg_prealloc_lock);

	list_for_each_entry_safe(pa, tmp, &discard_list, u.pa_tmp_list) {

		ext4_get_group_no_and_offset(sb, pa->pa_pstart, &group, NULL);
		if (ext4_mb_load_buddy(sb, group, &e4b)) {
			ext4_error(sb, "Error loading buddy information for %u",
					group);
			continue;
		}
		ext4_lock_group(sb, group);
		list_del(&pa->pa_group_list);
		ext4_mb_release_group_pa(&e4b, pa, ac);
		ext4_unlock_group(sb, group);

		ext4_mb_release_desc(&e4b);
		list_del(&pa->u.pa_tmp_list);
		call_rcu(&(pa)->u.pa_rcu, ext4_mb_pa_callback);
	}
	if (ac)
		kmem_cache_free(ext4_ac_cachep, ac);
}

/*
 * We have incremented pa_count. So it cannot be freed at this
 * point. Also we hold lg_mutex. So no parallel allocation is
 * possible from this lg. That means pa_free cannot be updated.
 *
 * A parallel ext4_mb_discard_group_preallocations is possible.
 * which can cause the lg_prealloc_list to be updated.
 */

static void ext4_mb_add_n_trim(struct ext4_allocation_context *ac)
{
	int order, added = 0, lg_prealloc_count = 1;
	struct super_block *sb = ac->ac_sb;
	struct ext4_locality_group *lg = ac->ac_lg;
	struct ext4_prealloc_space *tmp_pa, *pa = ac->ac_pa;

	order = fls(pa->pa_free) - 1;
	if (order > PREALLOC_TB_SIZE - 1)
		/* The max size of hash table is PREALLOC_TB_SIZE */
		order = PREALLOC_TB_SIZE - 1;
	/* Add the prealloc space to lg */
	rcu_read_lock();
	list_for_each_entry_rcu(tmp_pa, &lg->lg_prealloc_list[order],
						pa_inode_list) {
		spin_lock(&tmp_pa->pa_lock);
		if (tmp_pa->pa_deleted) {
			spin_unlock(&tmp_pa->pa_lock);
			continue;
		}
		if (!added && pa->pa_free < tmp_pa->pa_free) {
			/* Add to the tail of the previous entry */
			list_add_tail_rcu(&pa->pa_inode_list,
						&tmp_pa->pa_inode_list);
			added = 1;
			/*
			 * we want to count the total
			 * number of entries in the list
			 */
		}
		spin_unlock(&tmp_pa->pa_lock);
		lg_prealloc_count++;
	}
	if (!added)
		list_add_tail_rcu(&pa->pa_inode_list,
					&lg->lg_prealloc_list[order]);
	rcu_read_unlock();

	/* Now trim the list to be not more than 8 elements */
	if (lg_prealloc_count > 8) {
		ext4_mb_discard_lg_preallocations(sb, lg,
						order, lg_prealloc_count);
		return;
	}
	return ;
}

/*
 * release all resource we used in allocation
 */
static int ext4_mb_release_context(struct ext4_allocation_context *ac)
{
	struct ext4_prealloc_space *pa = ac->ac_pa;
	if (pa) {
		if (pa->pa_type == MB_GROUP_PA) {
			/* see comment in ext4_mb_use_group_pa() */
			spin_lock(&pa->pa_lock);
			pa->pa_pstart += ac->ac_b_ex.fe_len;
			pa->pa_lstart += ac->ac_b_ex.fe_len;
			pa->pa_free -= ac->ac_b_ex.fe_len;
			pa->pa_len -= ac->ac_b_ex.fe_len;
			spin_unlock(&pa->pa_lock);
		}
	}
	if (ac->alloc_semp)
		up_read(ac->alloc_semp);
	if (pa) {
		/*
		 * We want to add the pa to the right bucket.
		 * Remove it from the list and while adding
		 * make sure the list to which we are adding
		 * doesn't grow big.  We need to release
		 * alloc_semp before calling ext4_mb_add_n_trim()
		 */
		if ((pa->pa_type == MB_GROUP_PA) && likely(pa->pa_free)) {
			spin_lock(pa->pa_obj_lock);
			list_del_rcu(&pa->pa_inode_list);
			spin_unlock(pa->pa_obj_lock);
			ext4_mb_add_n_trim(ac);
		}
		ext4_mb_put_pa(ac, ac->ac_sb, pa);
	}
	if (ac->ac_bitmap_page)
		page_cache_release(ac->ac_bitmap_page);
	if (ac->ac_buddy_page)
		page_cache_release(ac->ac_buddy_page);
	if (ac->ac_flags & EXT4_MB_HINT_GROUP_ALLOC)
		mutex_unlock(&ac->ac_lg->lg_mutex);
	ext4_mb_collect_stats(ac);
	return 0;
}

static int ext4_mb_discard_preallocations(struct super_block *sb, int needed)
{
	ext4_group_t i, ngroups = ext4_get_groups_count(sb);
	int ret;
	int freed = 0;

	trace_ext4_mb_discard_preallocations(sb, needed);
	for (i = 0; i < ngroups && needed > 0; i++) {
		ret = ext4_mb_discard_group_preallocations(sb, i, needed);
		freed += ret;
		needed -= ret;
	}

	return freed;
}

/*
 * Main entry point into mballoc to allocate blocks
 * it tries to use preallocation first, then falls back
 * to usual allocation
 */
ext4_fsblk_t ext4_mb_new_blocks(handle_t *handle,
				 struct ext4_allocation_request *ar, int *errp)
{
	int freed;
	struct ext4_allocation_context *ac = NULL;
	struct ext4_sb_info *sbi;
	struct super_block *sb;
	ext4_fsblk_t block = 0;
	unsigned int inquota = 0;
	unsigned int reserv_blks = 0;

	sb = ar->inode->i_sb;
	sbi = EXT4_SB(sb);

	trace_ext4_request_blocks(ar);  // 记录块分配请求的跟踪信息，用于调试

	/*
	 * 对于延迟分配，跳过ENOSPC（无空间）和
	 * EDQUOT（配额超限）检查，因为在将数据复制到
	 * pagecache 时已经预留了块和配额。
	 */
	if (EXT4_I(ar->inode)->i_delalloc_reserved_flag)
		ar->flags |= EXT4_MB_DELALLOC_RESERVED;
	else {
		/* 在没有延迟分配的情况下，我们需要验证是否有足够的
		 * 空闲块进行分配，并确保分配不会超出配额限制。
		 */
		while (ar->len && ext4_claim_free_blocks(sbi, ar->len)) {
			/* 让出处理器以允许其他线程释放空间 */
			yield();
			ar->len = ar->len >> 1;  // 将请求长度减半
		}
		if (!ar->len) {
			*errp = -ENOSPC;  // 无空间
			return 0;
		}
		reserv_blks = ar->len;
		while (ar->len && dquot_alloc_block(ar->inode, ar->len)) {
			ar->flags |= EXT4_MB_HINT_NOPREALLOC;  // 提示避免预分配
			ar->len--;
		}
		inquota = ar->len;
		if (ar->len == 0) {
			*errp = -EDQUOT;  // 配额超限
			goto out3;
		}
	}

	/* 为分配上下文分配内存 */
	ac = kmem_cache_alloc(ext4_ac_cachep, GFP_NOFS);
	if (!ac) {
		ar->len = 0;
		*errp = -ENOMEM;  // 内存不足
		goto out1;
	}

	/* 初始化分配上下文 */
	*errp = ext4_mb_initialize_context(ac, ar);
	if (*errp) {
		ar->len = 0;
		goto out2;
	}

	/* 检查是否可以使用预分配的块 */
	ac->ac_op = EXT4_MB_HISTORY_PREALLOC;
	if (!ext4_mb_use_preallocated(ac)) {
		ac->ac_op = EXT4_MB_HISTORY_ALLOC;
		ext4_mb_normalize_request(ac, ar);  // 标准化分配请求
repeat:
		/* 正常分配块 */
		ext4_mb_regular_allocator(ac);

		/* 如果分配的空间超过了用户最初请求的空间，
		 * 将多余的空间存储在一个特殊的描述符中。
		 */
		if (ac->ac_status == AC_STATUS_FOUND &&
				ac->ac_o_ex.fe_len < ac->ac_b_ex.fe_len)
			ext4_mb_new_preallocation(ac);  // 创建新的预分配块
	}
	if (likely(ac->ac_status == AC_STATUS_FOUND)) {
		*errp = ext4_mb_mark_diskspace_used(ac, handle, reserv_blks);  // 标记使用的磁盘空间
		if (*errp ==  -EAGAIN) {
			/*
			 * 如果分配失败，释放引用并重试
			 */
			ext4_mb_release_context(ac);
			ac->ac_b_ex.fe_group = 0;
			ac->ac_b_ex.fe_start = 0;
			ac->ac_b_ex.fe_len = 0;
			ac->ac_status = AC_STATUS_CONTINUE;
			goto repeat;  // 重试分配
		} else if (*errp) {
			ext4_discard_allocated_blocks(ac);  // 丢弃已分配的块
			ac->ac_b_ex.fe_len = 0;
			ar->len = 0;
			ext4_mb_show_ac(ac);  // 显示分配上下文的调试信息
		} else {
			block = ext4_grp_offs_to_block(sb, &ac->ac_b_ex);  // 获取分配的块号
			ar->len = ac->ac_b_ex.fe_len;
		}
	} else {
		freed  = ext4_mb_discard_preallocations(sb, ac->ac_o_ex.fe_len);  // 丢弃预分配的块
		if (freed)
			goto repeat;  // 如果释放了预分配块，重试分配
		*errp = -ENOSPC;  // 无空间
		ac->ac_b_ex.fe_len = 0;
		ar->len = 0;
		ext4_mb_show_ac(ac);  // 显示分配上下文的调试信息
	}

	ext4_mb_release_context(ac);  // 释放分配上下文

out2:
	kmem_cache_free(ext4_ac_cachep, ac);  // 释放上下文内存
out1:
	/* 如果实际分配的块数少于预期，则释放多余的配额 */
	if (inquota && ar->len < inquota)
		dquot_free_block(ar->inode, inquota - ar->len);
out3:
	if (!ar->len) {
		if (!EXT4_I(ar->inode)->i_delalloc_reserved_flag)
			/* 如果没有延迟分配，则释放所有预留的块 */
			percpu_counter_sub(&sbi->s_dirtyblocks_counter,
						reserv_blks);
	}

	trace_ext4_allocate_blocks(ar, (unsigned long long)block);  // 跟踪块分配

	return block;  // 返回分配的块号
}

/*
 * We can merge two free data extents only if the physical blocks
 * are contiguous, AND the extents were freed by the same transaction,
 * AND the blocks are associated with the same group.
 */
static int can_merge(struct ext4_free_data *entry1,
			struct ext4_free_data *entry2)
{
	if ((entry1->t_tid == entry2->t_tid) &&
	    (entry1->group == entry2->group) &&
	    ((entry1->start_blk + entry1->count) == entry2->start_blk))
		return 1;
	return 0;
}

static noinline_for_stack int
ext4_mb_free_metadata(handle_t *handle, struct ext4_buddy *e4b,
		      struct ext4_free_data *new_entry)
{
	ext4_grpblk_t block;
	struct ext4_free_data *entry;
	struct ext4_group_info *db = e4b->bd_info;
	struct super_block *sb = e4b->bd_sb;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct rb_node **n = &db->bb_free_root.rb_node, *node;
	struct rb_node *parent = NULL, *new_node;

	BUG_ON(!ext4_handle_valid(handle));
	BUG_ON(e4b->bd_bitmap_page == NULL);
	BUG_ON(e4b->bd_buddy_page == NULL);

	new_node = &new_entry->node;
	block = new_entry->start_blk;

	if (!*n) {
		/* first free block exent. We need to
		   protect buddy cache from being freed,
		 * otherwise we'll refresh it from
		 * on-disk bitmap and lose not-yet-available
		 * blocks */
		page_cache_get(e4b->bd_buddy_page);
		page_cache_get(e4b->bd_bitmap_page);
	}
	while (*n) {
		parent = *n;
		entry = rb_entry(parent, struct ext4_free_data, node);
		if (block < entry->start_blk)
			n = &(*n)->rb_left;
		else if (block >= (entry->start_blk + entry->count))
			n = &(*n)->rb_right;
		else {
			ext4_grp_locked_error(sb, e4b->bd_group, __func__,
					"Double free of blocks %d (%d %d)",
					block, entry->start_blk, entry->count);
			return 0;
		}
	}

	rb_link_node(new_node, parent, n);
	rb_insert_color(new_node, &db->bb_free_root);

	/* Now try to see the extent can be merged to left and right */
	node = rb_prev(new_node);
	if (node) {
		entry = rb_entry(node, struct ext4_free_data, node);
		if (can_merge(entry, new_entry)) {
			new_entry->start_blk = entry->start_blk;
			new_entry->count += entry->count;
			rb_erase(node, &(db->bb_free_root));
			spin_lock(&sbi->s_md_lock);
			list_del(&entry->list);
			spin_unlock(&sbi->s_md_lock);
			kmem_cache_free(ext4_free_ext_cachep, entry);
		}
	}

	node = rb_next(new_node);
	if (node) {
		entry = rb_entry(node, struct ext4_free_data, node);
		if (can_merge(new_entry, entry)) {
			new_entry->count += entry->count;
			rb_erase(node, &(db->bb_free_root));
			spin_lock(&sbi->s_md_lock);
			list_del(&entry->list);
			spin_unlock(&sbi->s_md_lock);
			kmem_cache_free(ext4_free_ext_cachep, entry);
		}
	}
	/* Add the extent to transaction's private list */
	spin_lock(&sbi->s_md_lock);
	list_add(&new_entry->list, &handle->h_transaction->t_private_list);
	spin_unlock(&sbi->s_md_lock);
	return 0;
}

/**
 * ext4_free_blocks() -- Free given blocks and update quota
 * @handle:		handle for this transaction
 * @inode:		inode
 * @block:		start physical block to free
 * @count:		number of blocks to count
 * @metadata: 		Are these metadata blocks
 */
void ext4_free_blocks(handle_t *handle, struct inode *inode,
		      struct buffer_head *bh, ext4_fsblk_t block,
		      unsigned long count, int flags)
{
	struct buffer_head *bitmap_bh = NULL;
	struct super_block *sb = inode->i_sb;
	struct ext4_allocation_context *ac = NULL;
	struct ext4_group_desc *gdp;
	struct ext4_super_block *es;
	unsigned long freed = 0;
	unsigned int overflow;
	ext4_grpblk_t bit;
	struct buffer_head *gd_bh;
	ext4_group_t block_group;
	struct ext4_sb_info *sbi;
	struct ext4_buddy e4b;
	int err = 0;
	int ret;

	if (bh) {
		if (block)
			BUG_ON(block != bh->b_blocknr);
		else
			block = bh->b_blocknr;
	}

	sbi = EXT4_SB(sb);
	es = EXT4_SB(sb)->s_es;
	if (!(flags & EXT4_FREE_BLOCKS_VALIDATED) &&
	    !ext4_data_block_valid(sbi, block, count)) {
		ext4_error(sb, "Freeing blocks not in datazone - "
			   "block = %llu, count = %lu", block, count);
		goto error_return;
	}

	ext4_debug("freeing block %llu\n", block);
	trace_ext4_free_blocks(inode, block, count, flags);

	if (flags & EXT4_FREE_BLOCKS_FORGET) {
		struct buffer_head *tbh = bh;
		int i;

		BUG_ON(bh && (count > 1));

		for (i = 0; i < count; i++) {
			if (!bh)
				tbh = sb_find_get_block(inode->i_sb,
							block + i);
			ext4_forget(handle, flags & EXT4_FREE_BLOCKS_METADATA, 
				    inode, tbh, block + i);// 调用 ext4_forget 函数来处理撤销逻辑，传入标志、inode、缓冲区和块号
		}
	}

	/* 
	 * We need to make sure we don't reuse the freed block until
	 * after the transaction is committed, which we can do by
	 * treating the block as metadata, below.  We make an
	 * exception if the inode is to be written in writeback mode
	 * since writeback mode has weak data consistency guarantees.
	 */
	if (!ext4_should_writeback_data(inode))
		flags |= EXT4_FREE_BLOCKS_METADATA;

	ac = kmem_cache_alloc(ext4_ac_cachep, GFP_NOFS);
	if (ac) {
		ac->ac_inode = inode;
		ac->ac_sb = sb;
	}

do_more:
	overflow = 0;
	ext4_get_group_no_and_offset(sb, block, &block_group, &bit);

	/*
	 * Check to see if we are freeing blocks across a group
	 * boundary.
	 */
	if (bit + count > EXT4_BLOCKS_PER_GROUP(sb)) {
		overflow = bit + count - EXT4_BLOCKS_PER_GROUP(sb);
		count -= overflow;
	}
	bitmap_bh = ext4_read_block_bitmap(sb, block_group);
	if (!bitmap_bh) {
		err = -EIO;
		goto error_return;
	}
	gdp = ext4_get_group_desc(sb, block_group, &gd_bh);
	if (!gdp) {
		err = -EIO;
		goto error_return;
	}

	if (in_range(ext4_block_bitmap(sb, gdp), block, count) ||
	    in_range(ext4_inode_bitmap(sb, gdp), block, count) ||
	    in_range(block, ext4_inode_table(sb, gdp),
		      EXT4_SB(sb)->s_itb_per_group) ||
	    in_range(block + count - 1, ext4_inode_table(sb, gdp),
		      EXT4_SB(sb)->s_itb_per_group)) {

		ext4_error(sb, "Freeing blocks in system zone - "
			   "Block = %llu, count = %lu", block, count);
		/* err = 0. ext4_std_error should be a no op */
		goto error_return;
	}

	BUFFER_TRACE(bitmap_bh, "getting write access");
	err = ext4_journal_get_write_access(handle, bitmap_bh);
	if (err)
		goto error_return;

	/*
	 * We are about to modify some metadata.  Call the journal APIs
	 * to unshare ->b_data if a currently-committing transaction is
	 * using it
	 */
	BUFFER_TRACE(gd_bh, "get_write_access");
	err = ext4_journal_get_write_access(handle, gd_bh);
	if (err)
		goto error_return;
#ifdef AGGRESSIVE_CHECK
	{
		int i;
		for (i = 0; i < count; i++)
			BUG_ON(!mb_test_bit(bit + i, bitmap_bh->b_data));
	}
#endif
	if (ac) {
		ac->ac_b_ex.fe_group = block_group;
		ac->ac_b_ex.fe_start = bit;
		ac->ac_b_ex.fe_len = count;
		trace_ext4_mballoc_free(ac);
	}

	err = ext4_mb_load_buddy(sb, block_group, &e4b);
	if (err)
		goto error_return;

	if ((flags & EXT4_FREE_BLOCKS_METADATA) && ext4_handle_valid(handle)) {
		struct ext4_free_data *new_entry;
		/*
		 * blocks being freed are metadata. these blocks shouldn't
		 * be used until this transaction is committed
		 */
		new_entry  = kmem_cache_alloc(ext4_free_ext_cachep, GFP_NOFS);
		new_entry->start_blk = bit;
		new_entry->group  = block_group;
		new_entry->count = count;
		new_entry->t_tid = handle->h_transaction->t_tid;

		ext4_lock_group(sb, block_group);
		mb_clear_bits(bitmap_bh->b_data, bit, count);
		ext4_mb_free_metadata(handle, &e4b, new_entry);
	} else {
		/* need to update group_info->bb_free and bitmap
		 * with group lock held. generate_buddy look at
		 * them with group lock_held
		 */
		ext4_lock_group(sb, block_group);
		mb_clear_bits(bitmap_bh->b_data, bit, count);
		mb_free_blocks(inode, &e4b, bit, count);
		ext4_mb_return_to_preallocation(inode, &e4b, block, count);
	}

	ret = ext4_free_blks_count(sb, gdp) + count;
	ext4_free_blks_set(sb, gdp, ret);
	gdp->bg_checksum = ext4_group_desc_csum(sbi, block_group, gdp);
	ext4_unlock_group(sb, block_group);
	percpu_counter_add(&sbi->s_freeblocks_counter, count);

	if (sbi->s_log_groups_per_flex) {
		ext4_group_t flex_group = ext4_flex_group(sbi, block_group);
		atomic_add(count, &sbi->s_flex_groups[flex_group].free_blocks);
	}

	ext4_mb_release_desc(&e4b);

	freed += count;

	/* We dirtied the bitmap block */
	BUFFER_TRACE(bitmap_bh, "dirtied bitmap block");
	err = ext4_handle_dirty_metadata(handle, NULL, bitmap_bh);

	/* And the group descriptor block */
	BUFFER_TRACE(gd_bh, "dirtied group descriptor block");
	ret = ext4_handle_dirty_metadata(handle, NULL, gd_bh);
	if (!err)
		err = ret;

	if (overflow && !err) {
		block += count;
		count = overflow;
		put_bh(bitmap_bh);
		goto do_more;
	}
	sb->s_dirt = 1;
error_return:
	if (freed)
		dquot_free_block(inode, freed);
	brelse(bitmap_bh);
	ext4_std_error(sb, err);
	if (ac)
		kmem_cache_free(ext4_ac_cachep, ac);
	return;
}
