/*
 * linux/fs/ext4/ioctl.c
 *
 * Copyright (C) 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/capability.h>
#include <linux/time.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include "ext4_jbd2.h"
#include "ext4.h"

long ext4_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    // 获取文件对应的inode结构
    struct inode *inode = filp->f_dentry->d_inode;
    // 获取ext4文件系统特定的inode信息
    struct ext4_inode_info *ei = EXT4_I(inode);
    unsigned int flags;

    // 打印调试信息
    ext4_debug("cmd = %u, arg = %lu\n", cmd, arg);

    // 根据命令cmd的不同执行不同的操作
    switch (cmd) {
    case EXT4_IOC_GETFLAGS:
        // 获取inode的标志
        ext4_get_inode_flags(ei);
        flags = ei->i_flags & EXT4_FL_USER_VISIBLE;
        // 将flags值复制到用户空间
        return put_user(flags, (int __user *) arg);
    case EXT4_IOC_SETFLAGS: {
        handle_t *handle = NULL;
        int err, migrate = 0;
        struct ext4_iloc iloc;
        unsigned int oldflags;
        unsigned int jflag;

        // 检查是否有权限修改标志
        if (!is_owner_or_cap(inode))
            return -EACCES;

        // 从用户空间获取新的标志值
        if (get_user(flags, (int __user *) arg))
            return -EFAULT;

        // 请求写权限
        err = mnt_want_write(filp->f_path.mnt);
        if (err)
            return err;

        // 屏蔽无效的标志位
        flags = ext4_mask_flags(inode->i_mode, flags);

        err = -EPERM;
        mutex_lock(&inode->i_mutex);
        // 检查是否为配额文件，禁止修改
        if (IS_NOQUOTA(inode))
            goto flags_out;

        oldflags = ei->i_flags;

        // JOURNAL_DATA标志只能由root修改
        jflag = flags & EXT4_JOURNAL_DATA_FL;

        // IMMUTABLE和APPEND_ONLY标志只能由具有相关权限的用户修改
        if ((flags ^ oldflags) & (EXT4_APPEND_FL | EXT4_IMMUTABLE_FL)) {
            if (!capable(CAP_LINUX_IMMUTABLE))
                goto flags_out;
        }

        // JOURNAL_DATA标志只能由具有相关权限的用户修改
        if ((jflag ^ oldflags) & (EXT4_JOURNAL_DATA_FL)) {
            if (!capable(CAP_SYS_RESOURCE))
                goto flags_out;
        }

        // 检查并处理EXTENTS标志的变化
        if (oldflags & EXT4_EXTENTS_FL) {
            if (!(flags & EXT4_EXTENTS_FL)) {
                err = -EOPNOTSUPP;
                goto flags_out;
            }
        } else if (flags & EXT4_EXTENTS_FL) {
            migrate = 1;
            flags &= ~EXT4_EXTENTS_FL;
        }

        // 检查并处理EOFBLOCKS标志的变化
        if (flags & EXT4_EOFBLOCKS_FL) {
            if (!(oldflags & EXT4_EOFBLOCKS_FL)) {
                err = -EOPNOTSUPP;
                goto flags_out;
            }
        } else if (oldflags & EXT4_EOFBLOCKS_FL)
            ext4_truncate(inode);

        // 开始一个新的journal事务
        handle = ext4_journal_start(inode, 1);
        if (IS_ERR(handle)) {
            err = PTR_ERR(handle);
            goto flags_out;
        }
        if (IS_SYNC(inode))
            ext4_handle_sync(handle);
        // 预留inode写入操作
        err = ext4_reserve_inode_write(handle, inode, &iloc);
        if (err)
            goto flags_err;

        // 更新flags
        flags = flags & EXT4_FL_USER_MODIFIABLE;
        flags |= oldflags & ~EXT4_FL_USER_MODIFIABLE;
        ei->i_flags = flags;

        // 设置inode标志
        ext4_set_inode_flags(inode);
        inode->i_ctime = ext4_current_time(inode);

        // 将修改标记为脏
        err = ext4_mark_iloc_dirty(handle, inode, &iloc);
flags_err:
        // 停止journal事务
        ext4_journal_stop(handle);
        if (err)
            goto flags_out;

        // 处理JOURNAL_DATA标志的变化
        if ((jflag ^ oldflags) & (EXT4_JOURNAL_DATA_FL))
            err = ext4_change_inode_journal_flag(inode, jflag);
        if (err)
            goto flags_out;
        // 如果需要迁移，执行迁移操作
        if (migrate)
            err = ext4_ext_migrate(inode);
flags_out:
        mutex_unlock(&inode->i_mutex);
        mnt_drop_write(filp->f_path.mnt);
        return err;
    }
    case EXT4_IOC_GETVERSION:
    case EXT4_IOC_GETVERSION_OLD:
        // 获取inode的版本号并复制到用户空间
        return put_user(inode->i_generation, (int __user *) arg);
    case EXT4_IOC_SETVERSION:
    case EXT4_IOC_SETVERSION_OLD: {
        handle_t *handle;
        struct ext4_iloc iloc;
        __u32 generation;
        int err;

        // 检查是否有权限设置版本号
        if (!is_owner_or_cap(inode))
            return -EPERM;

        // 请求写权限
        err = mnt_want_write(filp->f_path.mnt);
        if (err)
            return err;
        // 从用户空间获取新的版本号
        if (get_user(generation, (int __user *) arg)) {
            err = -EFAULT;
            goto setversion_out;
        }

        // 开始一个新的journal事务
        handle = ext4_journal_start(inode, 1);
        if (IS_ERR(handle)) {
            err = PTR_ERR(handle);
            goto setversion_out;
        }
        // 预留inode写入操作
        err = ext4_reserve_inode_write(handle, inode, &iloc);
        if (err == 0) {
            inode->i_ctime = ext4_current_time(inode);
            inode->i_generation = generation;
            // 将修改标记为脏
            err = ext4_mark_iloc_dirty(handle, inode, &iloc);
        }
        ext4_journal_stop(handle);
setversion_out:
        mnt_drop_write(filp->f_path.mnt);
        return err;
    }
#ifdef CONFIG_JBD2_DEBUG
    case EXT4_IOC_WAIT_FOR_READONLY:
        {
            struct super_block *sb = inode->i_sb;
            DECLARE_WAITQUEUE(wait, current);
            int ret = 0;

            set_current_state(TASK_INTERRUPTIBLE);
            add_wait_queue(&EXT4_SB(sb)->ro_wait_queue, &wait);
            if (timer_pending(&EXT4_SB(sb)->turn_ro_timer)) {
                schedule();
                ret = 1;
            }
            remove_wait_queue(&EXT4_SB(sb)->ro_wait_queue, &wait);
            return ret;
        }
#endif
    case EXT4_IOC_GROUP_EXTEND: {
        ext4_fsblk_t n_blocks_count;
        struct super_block *sb = inode->i_sb;
        int err, err2 = 0;

        // 检查是否有权限扩展组
        if (!capable(CAP_SYS_RESOURCE))
            return -EPERM;

        // 从用户空间获取新的块数
        if (get_user(n_blocks_count, (__u32 __user *)arg))
            return -EFAULT;

        // 请求写权限
        err = mnt_want_write(filp->f_path.mnt);
        if (err)
            return err;

        // 扩展组
        err = ext4_group_extend(sb, EXT4_SB(sb)->s_es, n_blocks_count);
        if (EXT4_SB(sb)->s_journal) {
            jbd2_journal_lock_updates(EXT4_SB(sb)->s_journal);
            err2 = jbd2_journal_flush(EXT4_SB(sb)->s_journal);
            jbd2_journal_unlock_updates(EXT4_SB(sb)->s_journal);
        }
        if (err == 0)
            err = err2;
        mnt_drop_write(filp->f_path.mnt);

        return err;
    }

    case EXT4_IOC_MOVE_EXT: {
        struct move_extent me;
        struct file *donor_filp;
        int err;

        // 检查文件的读写模式
        if (!(filp->f_mode & FMODE_READ) ||
            !(filp->f_mode & FMODE_WRITE))
            return -EBADF;

        // 从用户空间复制move_extent结构体
        if (copy_from_user(&me, (struct move_extent __user *)arg, sizeof(me)))
            return -EFAULT;
        me.moved_len = 0;

        // 获取供体文件的file结构体
        donor_filp = fget(me.donor_fd);
        if (!donor_filp)
            return -EBADF;

        // 检查供体文件的写模式
        if (!(donor_filp->f_mode & FMODE_WRITE)) {
            err = -EBADF;
            goto mext_out;
        }

        // 请求写权限
        err = mnt_want_write(filp->f_path.mnt);
        if (err)
            goto mext_out;

        // 移动扩展
        err = ext4_move_extents(filp, donor_filp, me.orig_start,
                                me.donor_start, me.len, &me.moved_len);
        mnt_drop_write(filp->f_path.mnt);
        if (me.moved_len > 0)
            file_remove_suid(donor_filp);

        // 将结果复制回用户空间
        if (copy_to_user((struct move_extent __user *)arg, 
                         &me, sizeof(me)))
            err = -EFAULT;
mext_out:
        fput(donor_filp);
        return err;
    }

    case EXT4_IOC_GROUP_ADD: {
        struct ext4_new_group_data input;
        struct super_block *sb = inode->i_sb;
        int err, err2 = 0;

        // 检查是否有权限添加组
        if (!capable(CAP_SYS_RESOURCE))
            return -EPERM;

        // 从用户空间复制ext4_new_group_data结构体
        if (copy_from_user(&input, (struct ext4_new_group_input __user *)arg,
                           sizeof(input)))
            return -EFAULT;

        // 请求写权限
        err = mnt_want_write(filp->f_path.mnt);
        if (err)
            return err;

        // 添加组
        err = ext4_group_add(sb, &input);
        if (EXT4_SB(sb)->s_journal) {
            jbd2_journal_lock_updates(EXT4_SB(sb)->s_journal);
            err2 = jbd2_journal_flush(EXT4_SB(sb)->s_journal);
            jbd2_journal_unlock_updates(EXT4_SB(sb)->s_journal);
        }
        if (err == 0)
            err = err2;
        mnt_drop_write(filp->f_path.mnt);

        return err;
    }

    case EXT4_IOC_MIGRATE:
    {
        int err;
        // 检查是否有权限迁移inode
        if (!is_owner_or_cap(inode))
            return -EACCES;

        // 请求写权限
        err = mnt_want_write(filp->f_path.mnt);
        if (err)
            return err;
        // 锁定inode防止写和截断操作
        mutex_lock(&(inode->i_mutex));
        err = ext4_ext_migrate(inode);
        mutex_unlock(&(inode->i_mutex));
        mnt_drop_write(filp->f_path.mnt);
        return err;
    }

    case EXT4_IOC_ALLOC_DA_BLKS:
    {
        int err;
        // 检查是否有权限分配延迟分配块
        if (!is_owner_or_cap(inode))
            return -EACCES;

        // 请求写权限
        err = mnt_want_write(filp->f_path.mnt);
        if (err)
            return err;
        err = ext4_alloc_da_blocks(inode);
        mnt_drop_write(filp->f_path.mnt);
        return err;
    }

    default:
        // 未知命令
        return -ENOTTY;
    }
}


#ifdef CONFIG_COMPAT
long ext4_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/* These are just misnamed, they actually get/put from/to user an int */
	switch (cmd) {
	case EXT4_IOC32_GETFLAGS:
		cmd = EXT4_IOC_GETFLAGS;
		break;
	case EXT4_IOC32_SETFLAGS:
		cmd = EXT4_IOC_SETFLAGS;
		break;
	case EXT4_IOC32_GETVERSION:
		cmd = EXT4_IOC_GETVERSION;
		break;
	case EXT4_IOC32_SETVERSION:
		cmd = EXT4_IOC_SETVERSION;
		break;
	case EXT4_IOC32_GROUP_EXTEND:
		cmd = EXT4_IOC_GROUP_EXTEND;
		break;
	case EXT4_IOC32_GETVERSION_OLD:
		cmd = EXT4_IOC_GETVERSION_OLD;
		break;
	case EXT4_IOC32_SETVERSION_OLD:
		cmd = EXT4_IOC_SETVERSION_OLD;
		break;
#ifdef CONFIG_JBD2_DEBUG
	case EXT4_IOC32_WAIT_FOR_READONLY:
		cmd = EXT4_IOC_WAIT_FOR_READONLY;
		break;
#endif
	case EXT4_IOC32_GETRSVSZ:
		cmd = EXT4_IOC_GETRSVSZ;
		break;
	case EXT4_IOC32_SETRSVSZ:
		cmd = EXT4_IOC_SETRSVSZ;
		break;
	case EXT4_IOC_GROUP_ADD:
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return ext4_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif
