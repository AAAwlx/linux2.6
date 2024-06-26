#ifndef _FAT_H
#define _FAT_H

#include <linux/buffer_head.h>
#include <linux/string.h>
#include <linux/nls.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/msdos_fs.h>

/*
 * vfat shortname flags
 */
#define VFAT_SFN_DISPLAY_LOWER	0x0001 /* convert to lowercase for display */
#define VFAT_SFN_DISPLAY_WIN95	0x0002 /* emulate win95 rule for display */
#define VFAT_SFN_DISPLAY_WINNT	0x0004 /* emulate winnt rule for display */
#define VFAT_SFN_CREATE_WIN95	0x0100 /* emulate win95 rule for create */
#define VFAT_SFN_CREATE_WINNT	0x0200 /* emulate winnt rule for create */

#define FAT_ERRORS_CONT		1      /* ignore error and continue */
#define FAT_ERRORS_PANIC	2      /* panic on error */
#define FAT_ERRORS_RO		3      /* remount r/o on error */

struct fat_mount_options {
	uid_t fs_uid; // 文件系统的用户ID
	gid_t fs_gid; // 文件系统的组ID
	unsigned short fs_fmask; // 文件的权限掩码
	unsigned short fs_dmask; // 目录的权限掩码
	unsigned short codepage;  /* 短文件名转换时使用的代码页 */
	char *iocharset;          /* 文件名输入/显示时使用的字符集 */
	unsigned short shortname; /* 短文件名显示/创建规则的标志 */
	unsigned char name_check; /* 文件名检查方式: r = relaxed, n = normal, s = strict */
	unsigned char errors;     /* 发生错误时的处理方式: continue, panic, remount-ro */
	unsigned short allow_utime;/* 设置访问时间和修改时间的权限 */

	// 以下是位字段标志（布尔值），用来控制各种挂载选项
	unsigned quiet:1,         /* 是否静默处理chmod和chown操作 */
			 showexec:1,      /* 是否只为com/exe/bat文件设置执行位 */
			 sys_immutable:1, /* 系统文件是否不可变 */
			 dotsOK:1,        /* 隐藏和系统文件是否以'.filename'命名 */
			 isvfat:1,        /* 是否支持VFAT长文件名 */
			 utf8:1,          /* 是否使用UTF-8字符集（默认） */
			 unicode_xlate:1, /* 为未处理的Unicode创建转义序列 */
			 numtail:1,       /* 第一个别名是否有数字'~1'类型的尾部 */
			 flush:1,         /* 是否快速写入 */
			 nocase:1,        /* 是否需要大小写转换？0=需要大小写转换 */
			 usefree:1,       /* FAT32是否使用free_clusters */
			 tz_utc:1,        /* 文件系统时间戳是否为UTC */
			 rodir:1,         /* 是否允许目录设置只读属性 */
			 discard:1;       /* 删除时是否发送discard请求 */
};


#define FAT_HASH_BITS	8
#define FAT_HASH_SIZE	(1UL << FAT_HASH_BITS)//512bety

/*
 * MS-DOS file system in-core superblock data
 */
/*
 * MS-DOS 文件系统内存中的超级块数据
 */
struct msdos_sb_info {
    unsigned short sec_per_clus; /* 每簇的扇区数 */
    unsigned short cluster_bits; /* 簇大小的对数值（log2(cluster_size)） */
    unsigned int cluster_size;   /* 簇大小 */
    unsigned char fats, fat_bits; /* FAT 表的数量和 FAT 表的位数（12 或 16 位） */
    unsigned short fat_start;    /* FAT 表的起始扇区 */
    unsigned long fat_length;    /* FAT 表的长度（扇区数） */
    unsigned long dir_start;     /* 根目录的起始扇区 */
    unsigned short dir_entries;  /* 根目录中的条目数 */
    unsigned long data_start;    /* 数据区的起始扇区 */
    unsigned long max_cluster;   /* 最大簇号 */
    unsigned long root_cluster;  /* 根目录的第一个簇号（用于 FAT32） */
    unsigned long fsinfo_sector; /* FAT32 文件系统信息扇区号 */
    struct mutex fat_lock;       /* 用于保护 FAT 表的互斥锁 */
    unsigned int prev_free;      /* 上一个已分配的簇号 */
    unsigned int free_clusters;  /* 空闲簇的数量，-1 表示未定义 */
    unsigned int free_clus_valid; /* free_clusters 是否有效 */
    struct fat_mount_options options; /* FAT 文件系统挂载选项 */
    struct nls_table *nls_disk;  /* 磁盘上使用的代码页 */
    struct nls_table *nls_io;    /* 用于输入和显示的字符集 */
    const void *dir_ops;         /* 不透明；默认的目录操作 */
    int dir_per_block;           /* 每块中的目录条目数 */
    int dir_per_block_bits;      /* log2(dir_per_block) */

    int fatent_shift;            /* FAT 表条目移位值 */
    struct fatent_operations *fatent_ops; /* FAT 表条目操作 */
    struct inode *fat_inode;     /* FAT 表的 inode */

    spinlock_t inode_hash_lock;  /* inode 哈希表的自旋锁 */
    struct hlist_head inode_hashtable[FAT_HASH_SIZE]; /* inode 哈希表 */
};


#define FAT_CACHE_VALID	0	/* special case for valid cache 保证缓存有效*/

/*
 * MS-DOS file system inode data in memory
 */
struct msdos_inode_info {
	spinlock_t cache_lru_lock;  // 自旋锁，用于保护缓存 LRU（Least Recently Used）链表
	struct list_head cache_lru;  // 缓存 LRU 链表头，用于管理缓存项
	int nr_caches;  // 缓存项的数量
	/* 用于避免 fat_free() 和 fat_get_cluster() 之间的竞争 */
	unsigned int cache_valid_id;  // 缓存有效 ID，用于同步缓存操作

	/* 注意：mmu_private 是 64 位的，因此访问时必须持有 ->i_mutex 锁 */
	loff_t mmu_private;  // 实际分配的大小（以字节为单位）

	int i_start;  // 起始簇号，0 表示没有起始簇
	int i_logstart;  // 逻辑起始簇号
	int i_attrs;  // 未使用的属性位
	loff_t i_pos;  // 目录项在磁盘上的位置，0 表示没有位置
	struct hlist_node i_fat_hash;  // 根据 i_location 进行哈希的链表节点
	struct inode vfs_inode;  // 通用 VFS（虚拟文件系统） inode 结构
};

struct fat_slot_info {
	loff_t i_pos;		/* on-disk position of directory entry */
	loff_t slot_off;	/* offset for slot or de start */
	int nr_slots;		/* number of slots + 1(de) in filename */
	struct msdos_dir_entry *de;
	struct buffer_head *bh;
};

static inline struct msdos_sb_info *MSDOS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct msdos_inode_info *MSDOS_I(struct inode *inode)
{
	return container_of(inode, struct msdos_inode_info, vfs_inode);
}

/*
 * If ->i_mode can't hold S_IWUGO (i.e. ATTR_RO), we use ->i_attrs to
 * save ATTR_RO instead of ->i_mode.
 *
 * If it's directory and !sbi->options.rodir, ATTR_RO isn't read-only
 * bit, it's just used as flag for app.
 */
static inline int fat_mode_can_hold_ro(struct inode *inode)
{
	struct msdos_sb_info *sbi = MSDOS_SB(inode->i_sb);
	mode_t mask;

	if (S_ISDIR(inode->i_mode)) {
		if (!sbi->options.rodir)
			return 0;
		mask = ~sbi->options.fs_dmask;
	} else
		mask = ~sbi->options.fs_fmask;

	if (!(mask & S_IWUGO))
		return 0;
	return 1;
}

/* Convert attribute bits and a mask to the UNIX mode. */
static inline mode_t fat_make_mode(struct msdos_sb_info *sbi,
				   u8 attrs, mode_t mode)
{
	if (attrs & ATTR_RO && !((attrs & ATTR_DIR) && !sbi->options.rodir))
		mode &= ~S_IWUGO;

	if (attrs & ATTR_DIR)
		return (mode & ~sbi->options.fs_dmask) | S_IFDIR;
	else
		return (mode & ~sbi->options.fs_fmask) | S_IFREG;
}

/* Return the FAT attribute byte for this inode */
static inline u8 fat_make_attrs(struct inode *inode)
{
	u8 attrs = MSDOS_I(inode)->i_attrs;
	if (S_ISDIR(inode->i_mode))
		attrs |= ATTR_DIR;
	if (fat_mode_can_hold_ro(inode) && !(inode->i_mode & S_IWUGO))
		attrs |= ATTR_RO;
	return attrs;
}

static inline void fat_save_attrs(struct inode *inode, u8 attrs)
{
	if (fat_mode_can_hold_ro(inode))
		MSDOS_I(inode)->i_attrs = attrs & ATTR_UNUSED;
	else
		MSDOS_I(inode)->i_attrs = attrs & (ATTR_UNUSED | ATTR_RO);
}

static inline unsigned char fat_checksum(const __u8 *name)
{
	unsigned char s = name[0];
	s = (s<<7) + (s>>1) + name[1];	s = (s<<7) + (s>>1) + name[2];
	s = (s<<7) + (s>>1) + name[3];	s = (s<<7) + (s>>1) + name[4];
	s = (s<<7) + (s>>1) + name[5];	s = (s<<7) + (s>>1) + name[6];
	s = (s<<7) + (s>>1) + name[7];	s = (s<<7) + (s>>1) + name[8];
	s = (s<<7) + (s>>1) + name[9];	s = (s<<7) + (s>>1) + name[10];
	return s;
}

static inline sector_t fat_clus_to_blknr(struct msdos_sb_info *sbi, int clus)
{
	return ((sector_t)clus - FAT_START_ENT) * sbi->sec_per_clus
		+ sbi->data_start;
}

static inline void fat16_towchar(wchar_t *dst, const __u8 *src, size_t len)
{
#ifdef __BIG_ENDIAN
	while (len--) {
		*dst++ = src[0] | (src[1] << 8);
		src += 2;
	}
#else
	memcpy(dst, src, len * 2);
#endif
}

static inline void fatwchar_to16(__u8 *dst, const wchar_t *src, size_t len)
{
#ifdef __BIG_ENDIAN
	while (len--) {
		dst[0] = *src & 0x00FF;
		dst[1] = (*src & 0xFF00) >> 8;
		dst += 2;
		src++;
	}
#else
	memcpy(dst, src, len * 2);
#endif
}

/* fat/cache.c */
extern void fat_cache_inval_inode(struct inode *inode);
extern int fat_get_cluster(struct inode *inode, int cluster,
			   int *fclus, int *dclus);
extern int fat_bmap(struct inode *inode, sector_t sector, sector_t *phys,
		    unsigned long *mapped_blocks, int create);

/* fat/dir.c */
extern const struct file_operations fat_dir_operations;
extern int fat_search_long(struct inode *inode, const unsigned char *name,
			   int name_len, struct fat_slot_info *sinfo);
extern int fat_dir_empty(struct inode *dir);
extern int fat_subdirs(struct inode *dir);
extern int fat_scan(struct inode *dir, const unsigned char *name,
		    struct fat_slot_info *sinfo);
extern int fat_get_dotdot_entry(struct inode *dir, struct buffer_head **bh,
				struct msdos_dir_entry **de, loff_t *i_pos);
extern int fat_alloc_new_dir(struct inode *dir, struct timespec *ts);
extern int fat_add_entries(struct inode *dir, void *slots, int nr_slots,
			   struct fat_slot_info *sinfo);
extern int fat_remove_entries(struct inode *dir, struct fat_slot_info *sinfo);

/* fat/fatent.c */
struct fat_entry {
	int entry;
	union {
		u8 *ent12_p[2];
		__le16 *ent16_p;
		__le32 *ent32_p;
	} u;
	int nr_bhs;
	struct buffer_head *bhs[2];
	struct inode *fat_inode;
};

static inline void fatent_init(struct fat_entry *fatent)
{
	fatent->nr_bhs = 0;
	fatent->entry = 0;
	fatent->u.ent32_p = NULL;
	fatent->bhs[0] = fatent->bhs[1] = NULL;
	fatent->fat_inode = NULL;
}

static inline void fatent_set_entry(struct fat_entry *fatent, int entry)
{
	fatent->entry = entry;
	fatent->u.ent32_p = NULL;
}

static inline void fatent_brelse(struct fat_entry *fatent)
{
	int i;
	fatent->u.ent32_p = NULL;
	for (i = 0; i < fatent->nr_bhs; i++)
		brelse(fatent->bhs[i]);
	fatent->nr_bhs = 0;
	fatent->bhs[0] = fatent->bhs[1] = NULL;
	fatent->fat_inode = NULL;
}

extern void fat_ent_access_init(struct super_block *sb);
extern int fat_ent_read(struct inode *inode, struct fat_entry *fatent,
			int entry);
extern int fat_ent_write(struct inode *inode, struct fat_entry *fatent,
			 int new, int wait);
extern int fat_alloc_clusters(struct inode *inode, int *cluster,
			      int nr_cluster);
extern int fat_free_clusters(struct inode *inode, int cluster);
extern int fat_count_free_clusters(struct super_block *sb);

/* fat/file.c */
extern int fat_generic_ioctl(struct inode *inode, struct file *filp,
			     unsigned int cmd, unsigned long arg);
extern const struct file_operations fat_file_operations;
extern const struct inode_operations fat_file_inode_operations;
extern int fat_setattr(struct dentry * dentry, struct iattr * attr);
extern void fat_truncate(struct inode *inode);
extern int fat_getattr(struct vfsmount *mnt, struct dentry *dentry,
		       struct kstat *stat);
extern int fat_file_fsync(struct file *file, struct dentry *dentry,
			  int datasync);

/* fat/inode.c */
extern void fat_attach(struct inode *inode, loff_t i_pos);
extern void fat_detach(struct inode *inode);
extern struct inode *fat_iget(struct super_block *sb, loff_t i_pos);
extern struct inode *fat_build_inode(struct super_block *sb,
			struct msdos_dir_entry *de, loff_t i_pos);
extern int fat_sync_inode(struct inode *inode);
extern int fat_fill_super(struct super_block *sb, void *data, int silent,
			const struct inode_operations *fs_dir_inode_ops, int isvfat);

extern int fat_flush_inodes(struct super_block *sb, struct inode *i1,
		            struct inode *i2);
/* fat/misc.c */
extern void fat_fs_error(struct super_block *s, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3))) __cold;
extern int fat_clusters_flush(struct super_block *sb);
extern int fat_chain_add(struct inode *inode, int new_dclus, int nr_cluster);
extern void fat_time_fat2unix(struct msdos_sb_info *sbi, struct timespec *ts,
			      __le16 __time, __le16 __date, u8 time_cs);
extern void fat_time_unix2fat(struct msdos_sb_info *sbi, struct timespec *ts,
			      __le16 *time, __le16 *date, u8 *time_cs);
extern int fat_sync_bhs(struct buffer_head **bhs, int nr_bhs);

int fat_cache_init(void);
void fat_cache_destroy(void);

/* helper for printk */
typedef unsigned long long	llu;

#endif /* !_FAT_H */
