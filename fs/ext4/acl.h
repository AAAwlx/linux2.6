/**
 * 文件：fs/ext4/acl.h
 * POSIX ACL（Access Control List）是一种文件系统级别的访问控制机制，它可以为每个文件或目录指定不同的访问权限
  (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

#include <linux/posix_acl_xattr.h>  /* 包含 POSIX ACL 扩展属性的定义 */

/* 定义 EXT4 ACL 版本 */
#define EXT4_ACL_VERSION 0x0001

/* 定义 ACL 条目结构体 */
typedef struct {
	__le16		e_tag;  /* ACL 条目的标签 */
	__le16		e_perm; /* ACL 条目的权限 */
	__le32		e_id;   /* ACL 条目的 ID（用户或组） */
} ext4_acl_entry;

/* 定义 ACL 条目（简短）结构体 */
typedef struct {
	__le16		e_tag;  /* ACL 条目的标签 */
	__le16		e_perm; /* ACL 条目的权限 */
} ext4_acl_entry_short;

/* 定义 ACL 头部结构体 */
typedef struct {
	__le32		a_version;  /* ACL 版本 */
} ext4_acl_header;

/* 计算 ACL 大小的内联函数 */
static inline size_t ext4_acl_size(int count)
{
	if (count <= 4) {
		/* 如果条目数小于或等于 4，使用简短的条目结构 */
		return sizeof(ext4_acl_header) +
		       count * sizeof(ext4_acl_entry_short);
	} else {
		/* 否则，前 4 个条目使用简短结构，剩余条目使用完整结构 */
		return sizeof(ext4_acl_header) +
		       4 * sizeof(ext4_acl_entry_short) +
		       (count - 4) * sizeof(ext4_acl_entry);
	}
}

/* 计算 ACL 条目数的内联函数 */
static inline int ext4_acl_count(size_t size)
{
	ssize_t s;
	size -= sizeof(ext4_acl_header);  /* 减去 ACL 头部的大小 */
	s = size - 4 * sizeof(ext4_acl_entry_short);  /* 计算剩余空间 */
	if (s < 0) {
		/* 如果剩余空间小于 0，则全是简短条目 */
		if (size % sizeof(ext4_acl_entry_short))
			return -1;  /* 大小不对齐，返回错误 */
		return size / sizeof(ext4_acl_entry_short);  /* 返回条目数 */
	} else {
		/* 否则，剩余空间中包含完整条目 */
		if (s % sizeof(ext4_acl_entry))
			return -1;  /* 大小不对齐，返回错误 */
		return s / sizeof(ext4_acl_entry) + 4;  /* 返回条目数 */
	}
}

#ifdef CONFIG_EXT4_FS_POSIX_ACL

/* 在 POSIX ACL 配置下，声明相关函数 */
extern int ext4_check_acl(struct inode *, int);
extern int ext4_acl_chmod(struct inode *);
extern int ext4_init_acl(handle_t *, struct inode *, struct inode *);

#else  /* CONFIG_EXT4_FS_POSIX_ACL */

#include <linux/sched.h>  /* 包含调度相关头文件 */
#define ext4_check_acl NULL  /* 在没有 POSIX ACL 支持时，定义为 NULL */

static inline int
ext4_acl_chmod(struct inode *inode)
{
	return 0;  /* 在没有 POSIX ACL 支持时，权限修改函数返回 0 */
}

static inline int
ext4_init_acl(handle_t *handle, struct inode *inode, struct inode *dir)
{
	return 0;  /* 在没有 POSIX ACL 支持时，ACL 初始化函数返回 0 */
}
#endif  /* CONFIG_EXT4_FS_POSIX_ACL */
