/*
 *  Copyright (C) 2008 Red Hat, Inc., Eric Paris <eparis@redhat.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/srcu.h>

#include <linux/fsnotify_backend.h>
#include "fsnotify.h"

/*
 * Clear all of the marks on an inode when it is being evicted from core
 */
void __fsnotify_inode_delete(struct inode *inode)
{
	fsnotify_clear_marks_by_inode(inode);
}
EXPORT_SYMBOL_GPL(__fsnotify_inode_delete);

/*
 * Given an inode, first check if we care what happens to our children.  Inotify
 * and dnotify both tell their parents about events.  If we care about any event
 * on a child we run all of our children and set a dentry flag saying that the
 * parent cares.  Thus when an event happens on a child it can quickly tell if
 * if there is a need to find a parent and send the event to the parent.
 */
void __fsnotify_update_child_dentry_flags(struct inode *inode)
{
	struct dentry *alias;
	int watched;

	if (!S_ISDIR(inode->i_mode))
		return;

	/* determine if the children should tell inode about their events */
	watched = fsnotify_inode_watches_children(inode);

	spin_lock(&dcache_lock);
	/* run all of the dentries associated with this inode.  Since this is a
	 * directory, there damn well better only be one item on this list */
	list_for_each_entry(alias, &inode->i_dentry, d_alias) {
		struct dentry *child;

		/* run all of the children of the original inode and fix their
		 * d_flags to indicate parental interest (their parent is the
		 * original inode) */
		list_for_each_entry(child, &alias->d_subdirs, d_u.d_child) {
			if (!child->d_inode)
				continue;

			spin_lock(&child->d_lock);
			if (watched)
				child->d_flags |= DCACHE_FSNOTIFY_PARENT_WATCHED;
			else
				child->d_flags &= ~DCACHE_FSNOTIFY_PARENT_WATCHED;
			spin_unlock(&child->d_lock);
		}
	}
	spin_unlock(&dcache_lock);
}

/* Notify this dentry's parent about a child's events. */
void __fsnotify_parent(struct dentry *dentry, __u32 mask)
{
	struct dentry *parent;
	struct inode *p_inode;
	bool send = false;
	bool should_update_children = false;

	if (!(dentry->d_flags & DCACHE_FSNOTIFY_PARENT_WATCHED))
		return;

	spin_lock(&dentry->d_lock);
	parent = dentry->d_parent;
	p_inode = parent->d_inode;

	if (fsnotify_inode_watches_children(p_inode)) {
		if (p_inode->i_fsnotify_mask & mask) {
			dget(parent);
			send = true;
		}
	} else {
		/*
		 * The parent doesn't care about events on it's children but
		 * at least one child thought it did.  We need to run all the
		 * children and update their d_flags to let them know p_inode
		 * doesn't care about them any more.
		 */
		dget(parent);
		should_update_children = true;
	}

	spin_unlock(&dentry->d_lock);

	if (send) {
		/* we are notifying a parent so come up with the new mask which
		 * specifies these are events which came from a child. */
		mask |= FS_EVENT_ON_CHILD;

		fsnotify(p_inode, mask, dentry->d_inode, FSNOTIFY_EVENT_INODE,
			 dentry->d_name.name, 0);
		dput(parent);
	}

	if (unlikely(should_update_children)) {
		__fsnotify_update_child_dentry_flags(p_inode);
		dput(parent);
	}
}
EXPORT_SYMBOL_GPL(__fsnotify_parent);

/*
 * This is the main call to fsnotify.  The VFS calls into hook specific functions
 * in linux/fsnotify.h.  Those functions then in turn call here.  Here will call
 * out to all of the registered fsnotify_group.  Those groups can then use the
 * notification event in whatever means they feel necessary.
 */
void fsnotify(struct inode *to_tell, __u32 mask, void *data, int data_is, const char *file_name, u32 cookie)
{
	struct fsnotify_group *group;
	struct fsnotify_event *event = NULL;
	int idx;

	// 1. 计算测试掩码，去掉 FS_EVENT_ON_CHILD 标志，因为全局测试通常只关心特定事件，而不是子事件
	__u32 test_mask = (mask & ~FS_EVENT_ON_CHILD);

	// 2. 如果没有 fsnotify 组，或掩码不匹配全局掩码，则返回
	if (list_empty(&fsnotify_groups))
		return;

	if (!(test_mask & fsnotify_mask))
		return;

	if (!(test_mask & to_tell->i_fsnotify_mask))
		return;

	// 3. 获取 SRCU 锁以遍历 fsnotify 组
	idx = srcu_read_lock(&fsnotify_grp_srcu);
	list_for_each_entry_rcu(group, &fsnotify_groups, group_list) {
		// 4. 如果掩码匹配，检查组是否应该处理该事件
		if (test_mask & group->mask) {
			if (!group->ops->should_send_event(group, to_tell, mask))
				continue;

			// 5. 如果没有事件对象，则创建一个新的事件对象
			if (!event) {
				event = fsnotify_create_event(to_tell, mask, data,
							      data_is, file_name, cookie,
							      GFP_KERNEL);
				// 6. 如果内存不足而事件对象未创建，则退出循环
				if (!event)
					break;
			}

			// 7. 处理事件
			group->ops->handle_event(group, event);
		}
	}
	// 8. 释放 SRCU 锁
	srcu_read_unlock(&fsnotify_grp_srcu, idx);

	// 9. 事件创建函数 fsnotify_create_event() 已经对事件对象进行了引用计数，
	//     在处理事件后需要释放这个事件对象的引用
	if (event)
		fsnotify_put_event(event);
}

EXPORT_SYMBOL_GPL(fsnotify);

static __init int fsnotify_init(void)
{
	return init_srcu_struct(&fsnotify_grp_srcu);
}
subsys_initcall(fsnotify_init);
