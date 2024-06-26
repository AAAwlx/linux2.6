/*
 * Resizable simple ram filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 *
 * Usage limits added by David Gibson, Linuxcare Australia.
 * This file is released under the GPL.
 */

/*
 * NOTE! This filesystem is probably most useful
 * not as a real filesystem, but as an example of
 * how virtual filesystems can be written.
 *
 * It doesn't get much simpler than this. Consider
 * that this file implements the full semantics of
 * a POSIX-compliant read-write filesystem.
 *
 * Note in particular how the filesystem does not
 * need to implement any data structures of its own
 * to keep track of the virtual data: using the VFS
 * caches is sufficient.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/ramfs.h>
#include <linux/sched.h>
#include <linux/parser.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include "internal.h"

#define RAMFS_DEFAULT_MODE	0755

static const struct super_operations ramfs_ops;
static const struct inode_operations ramfs_dir_inode_operations;
/*填写文件系统后备设备的信息*/
static struct backing_dev_info ramfs_backing_dev_info = {
	.name		= "ramfs",
	.ra_pages	= 0,	/* No readahead */
	.capabilities	= BDI_CAP_NO_ACCT_AND_WRITEBACK |
			  BDI_CAP_MAP_DIRECT | BDI_CAP_MAP_COPY |
			  BDI_CAP_READ_MAP | BDI_CAP_WRITE_MAP | BDI_CAP_EXEC_MAP,
};

struct inode *ramfs_get_inode(struct super_block *sb, int mode, dev_t dev)
{
	struct inode * inode = new_inode(sb);//这个inode最后在内存中

	if (inode) {
		inode->i_mode = mode;
		inode->i_uid = current_fsuid();
		inode->i_gid = current_fsgid();
		inode->i_mapping->a_ops = &ramfs_aops;
		inode->i_mapping->backing_dev_info = &ramfs_backing_dev_info;
		这些操作设置了 inode 的映射信息
		mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
		mapping_set_unevictable(inode->i_mapping);
		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		//根据文件属性设置inode的操作函数
		switch (mode & S_IFMT) {
		default:
			init_special_inode(inode, mode, dev);
			break;
		case S_IFREG://普通文件
			inode->i_op = &ramfs_file_inode_operations;
			inode->i_fop = &ramfs_file_operations;
			break;
		case S_IFDIR://目录
			inode->i_op = &ramfs_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;

			/* directory inodes start off with i_nlink == 2 (for "." entry) */
			inc_nlink(inode);
			break;
		case S_IFLNK://链接文件
			inode->i_op = &page_symlink_inode_operations;
			break;
		}
	}
	return inode;
}

/*
 * File creation. Allocate an inode, and we're done..
 */
/* SMP-safe */
static int
ramfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	struct inode * inode = ramfs_get_inode(dir->i_sb, mode, dev);//分配一个inode
	int error = -ENOSPC;

	if (inode) {
		if (dir->i_mode & S_ISGID) {
			inode->i_gid = dir->i_gid;
			if (S_ISDIR(mode))
				inode->i_mode |= S_ISGID;
		}
		d_instantiate(dentry, inode);//将inode与direnty建立联系
		dget(dentry);	/* 增加目录项的引用计数 */
		error = 0;
		dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	}
	return error;
}

static int ramfs_mkdir(struct inode * dir, struct dentry * dentry, int mode)
{
	int retval = ramfs_mknod(dir, dentry, mode | S_IFDIR, 0);
	if (!retval)
		inc_nlink(dir);
	return retval;
}

static int ramfs_create(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd)
{
	return ramfs_mknod(dir, dentry, mode | S_IFREG, 0);
}

static int ramfs_symlink(struct inode * dir, struct dentry *dentry, const char * symname)
{
	struct inode *inode;
	int error = -ENOSPC;

	inode = ramfs_get_inode(dir->i_sb, S_IFLNK|S_IRWXUGO, 0);
	if (inode) {
		int l = strlen(symname)+1;
		error = page_symlink(inode, symname, l);
		if (!error) {
			if (dir->i_mode & S_ISGID)
				inode->i_gid = dir->i_gid;
			d_instantiate(dentry, inode);
			dget(dentry);
			dir->i_mtime = dir->i_ctime = CURRENT_TIME;
		} else
			iput(inode);
	}
	return error;
}

static const struct inode_operations ramfs_dir_inode_operations = {
	.create		= ramfs_create,
	.lookup		= simple_lookup,
	.link		= simple_link,
	.unlink		= simple_unlink,
	.symlink	= ramfs_symlink,
	.mkdir		= ramfs_mkdir,
	.rmdir		= simple_rmdir,
	.mknod		= ramfs_mknod,
	.rename		= simple_rename,
};

static const struct super_operations ramfs_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.show_options	= generic_show_options,
};

struct ramfs_mount_opts {
	umode_t mode;
};

enum {
	Opt_mode,
	Opt_err
};

static const match_table_t tokens = {
	{Opt_mode, "mode=%o"},
	{Opt_err, NULL}
};

struct ramfs_fs_info {
	struct ramfs_mount_opts mount_opts;
};

static int ramfs_parse_options(char *data, struct ramfs_mount_opts *opts)
{
	substring_t args[MAX_OPT_ARGS];
	int option;
	int token;
	char *p;

	opts->mode = RAMFS_DEFAULT_MODE;

	while ((p = strsep(&data, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_mode:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			opts->mode = option & S_IALLUGO;
			break;
		/*
		 * We might like to report bad mount options here;
		 * but traditionally ramfs has ignored all mount options,
		 * and as it is used as a !CONFIG_SHMEM simple substitute
		 * for tmpfs, better continue to ignore other mount options.
		 */
		}
	}

	return 0;
}
static int ramfs_fill_super(struct super_block * sb, void * data, int silent)
{
    struct ramfs_fs_info *fsi;          // 定义文件系统信息结构指针
    struct inode *inode = NULL;         // 定义 inode 指针并初始化为 NULL
    struct dentry *root;                // 定义目录项指针
    int err;                            // 定义错误码变量

    // 保存挂载选项
    save_mount_options(sb, data);

    // 分配并初始化 ramfs_fs_info 结构
    fsi = kzalloc(sizeof(struct ramfs_fs_info), GFP_KERNEL);
    sb->s_fs_info = fsi;
    if (!fsi) {                         // 检查内存分配是否成功
        err = -ENOMEM;                  // 设置错误码为内存不足
        goto fail;                      // 跳转到错误处理
    }

    // 解析挂载选项
    err = ramfs_parse_options(data, &fsi->mount_opts);
    if (err)
        goto fail;                      // 如果解析选项失败，跳转到错误处理

    // 设置超级块的各项参数
    sb->s_maxbytes       = MAX_LFS_FILESIZE; // 最大文件大小
    sb->s_blocksize      = PAGE_CACHE_SIZE;  // 块大小
    sb->s_blocksize_bits = PAGE_CACHE_SHIFT; // 块大小位移
    sb->s_magic          = RAMFS_MAGIC;      // 文件系统魔数
    sb->s_op             = &ramfs_ops;       // 操作集合
    sb->s_time_gran      = 1;                // 时间粒度

    // 获取根目录的 inode
    inode = ramfs_get_inode(sb, S_IFDIR | fsi->mount_opts.mode, 0);
    if (!inode) {                        // 检查是否成功获取 inode
        err = -ENOMEM;                   // 设置错误码为内存不足
        goto fail;                       // 跳转到错误处理
    }

    // 分配根目录项
    root = d_alloc_root(inode);
    sb->s_root = root;
    if (!root) {                         // 检查是否成功分配根目录项
        err = -ENOMEM;                   // 设置错误码为内存不足
        goto fail;                       // 跳转到错误处理
    }

    return 0;                            // 成功返回 0

fail:
    kfree(fsi);                          // 释放分配的文件系统信息结构
    sb->s_fs_info = NULL;                // 将超级块的文件系统信息指针置空
    iput(inode);                         // 释放 inode
    return err;                          // 返回错误码
}

int ramfs_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_nodev(fs_type, flags, data, ramfs_fill_super, mnt);//设置超级块，ramfs_fill_super做回调函数
}

static int rootfs_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_nodev(fs_type, flags|MS_NOUSER, data, ramfs_fill_super,
			    mnt);
}

static void ramfs_kill_sb(struct super_block *sb)
{
	kfree(sb->s_fs_info);
	kill_litter_super(sb);
}

static struct file_system_type ramfs_fs_type = {
	.name		= "ramfs",
	.get_sb		= ramfs_get_sb,
	.kill_sb	= ramfs_kill_sb,
};
static struct file_system_type rootfs_fs_type = {
	.name		= "rootfs",
	.get_sb		= rootfs_get_sb,
	.kill_sb	= kill_litter_super,
};

static int __init init_ramfs_fs(void)
{
	return register_filesystem(&ramfs_fs_type);
}

static void __exit exit_ramfs_fs(void)
{
	unregister_filesystem(&ramfs_fs_type);
}

module_init(init_ramfs_fs)//注册模块
module_exit(exit_ramfs_fs)

int __init init_rootfs(void)//初始化根文件系统
{
	int err;

	err = bdi_init(&ramfs_backing_dev_info);//初始化设备信息
	if (err)
		return err;

	err = register_filesystem(&rootfs_fs_type);//注册文件系统
	if (err)//错误处理回收资源
		bdi_destroy(&ramfs_backing_dev_info);

	return err;
}

MODULE_LICENSE("GPL");
