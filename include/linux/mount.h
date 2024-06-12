/*
 *
 * Definitions for mount interface. This describes the in the kernel build 
 * linkedlist with mounted filesystems.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/nodemask.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

struct super_block;
struct vfsmount;
struct dentry;
struct mnt_namespace;

#define MNT_NOSUID	0x01
#define MNT_NODEV	0x02
#define MNT_NOEXEC	0x04
#define MNT_NOATIME	0x08
#define MNT_NODIRATIME	0x10
#define MNT_RELATIME	0x20
#define MNT_READONLY	0x40	/* does the user want this to be r/o? */
#define MNT_STRICTATIME 0x80

#define MNT_SHRINKABLE	0x100
#define MNT_WRITE_HOLD	0x200

#define MNT_SHARED	0x1000	/* if the vfsmount is a shared mount */
#define MNT_UNBINDABLE	0x2000	/* if the vfsmount is a unbindable mount */
/*
 * MNT_SHARED_MASK is the set of flags that should be cleared when a
 * mount becomes shared.  Currently, this is only the flag that says a
 * mount cannot be bind mounted, since this is how we create a mount
 * that shares events with another mount.  If you add a new MNT_*
 * flag, consider how it interacts with shared mounts.
 */
#define MNT_SHARED_MASK	(MNT_UNBINDABLE)
#define MNT_PROPAGATION_MASK	(MNT_SHARED | MNT_UNBINDABLE)


#define MNT_INTERNAL	0x4000

struct vfsmount {
	struct list_head mnt_hash;        // 挂载点的哈希链表，用于查找
	struct vfsmount *mnt_parent;      // 父文件系统，我们挂载在其上
	struct dentry *mnt_mountpoint;    // 挂载点的目录项
	struct dentry *mnt_root;          // 挂载文件系统的根目录
	struct super_block *mnt_sb;       // 指向超级块的指针
	struct list_head mnt_mounts;      // 子挂载点列表，挂载点以此为锚
	struct list_head mnt_child;       // 子挂载点列表中的挂载点
	int mnt_flags;                    // 挂载标志
	// 64位架构上的4字节空洞
	const char *mnt_devname;          // 设备名称，例如 /dev/dsk/hda1
	struct list_head mnt_list;        // 挂载点列表
	struct list_head mnt_expire;      // 文件系统特定的过期链表链接
	struct list_head mnt_share;       // 共享挂载点的循环链表
	struct list_head mnt_slave_list;  // 从属挂载点列表
	struct list_head mnt_slave;       // 从属挂载点列表中的挂载点
	struct vfsmount *mnt_master;      // 从属挂载点的主挂载点
	struct mnt_namespace *mnt_ns;     // 包含该挂载点的命名空间
	int mnt_id;                       // 挂载点标识符
	int mnt_group_id;                 // 对等组标识符
	/*
	 * 我们将 mnt_count 和 mnt_expiry_mark 放在 vfsmount 结构体的末尾，
	 * 以便将这些频繁修改的字段放在一个单独的缓存行中
	 * （这样在 SMP 机器上读取 mnt_flags 时不会发生 ping-pong 效应）
	 */
	atomic_t mnt_count;               // 挂载点的引用计数
	int mnt_expiry_mark;              // 标记是否已标记为过期
	int mnt_pinned;                   // 挂载点是否被固定（不能卸载）
	int mnt_ghosts;                   // 挂载点是否为幽灵状态
#ifdef CONFIG_SMP
	int __percpu *mnt_writers;        // 挂载点的写入者数量（SMP 配置）
#else
	int mnt_writers;                  // 挂载点的写入者数量（非 SMP 配置）
#endif
};
static inline int *get_mnt_writers_ptr(struct vfsmount *mnt)
{
#ifdef CONFIG_SMP
	return mnt->mnt_writers;
#else
	return &mnt->mnt_writers;
#endif
}

static inline struct vfsmount *mntget(struct vfsmount *mnt)
{
	if (mnt)
		atomic_inc(&mnt->mnt_count);
	return mnt;
}

struct file; /* forward dec */

extern int mnt_want_write(struct vfsmount *mnt);
extern int mnt_want_write_file(struct file *file);
extern int mnt_clone_write(struct vfsmount *mnt);
extern void mnt_drop_write(struct vfsmount *mnt);
extern void mntput_no_expire(struct vfsmount *mnt);
extern void mnt_pin(struct vfsmount *mnt);
extern void mnt_unpin(struct vfsmount *mnt);
extern int __mnt_is_readonly(struct vfsmount *mnt);

static inline void mntput(struct vfsmount *mnt)
{
	if (mnt) {
		mnt->mnt_expiry_mark = 0;
		mntput_no_expire(mnt);
	}
}

extern struct vfsmount *do_kern_mount(const char *fstype, int flags,
				      const char *name, void *data);

struct file_system_type;
extern struct vfsmount *vfs_kern_mount(struct file_system_type *type,
				      int flags, const char *name,
				      void *data);

struct nameidata;

struct path;
extern int do_add_mount(struct vfsmount *newmnt, struct path *path,
			int mnt_flags, struct list_head *fslist);

extern void mark_mounts_for_expiry(struct list_head *mounts);

extern dev_t name_to_dev_t(char *name);

#endif /* _LINUX_MOUNT_H */
