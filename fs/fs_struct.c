#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>

/*
 * Replace the fs->{rootmnt,root} with {mnt,dentry}. Put the old values.
 * It can block.
 * 此函数用于更新文件系统结构的根挂载点和目录项，必要时会阻塞以确保操作的一致性。
 */
void set_fs_root(struct fs_struct *fs, struct path *path)
{
	struct path old_root;

	write_lock(&fs->lock);  // 获取fs->lock的写锁
	old_root = fs->root;    // 将当前根文件系统路径保存在old_root中
	fs->root = *path;       // 将fs->root设置为新路径提供的路径
	path_get(path);         // 增加新路径的引用计数，确保其有效
	write_unlock(&fs->lock); // 释放fs->lock的写锁

	if (old_root.dentry)    // 如果old_root.dentry存在（旧根不为空）
		path_put(&old_root); // 释放对旧根路径的引用，释放相关资源
}

/*
 * Replace the fs->{pwdmnt,pwd} with {mnt,dentry}. Put the old values.
 * It can block.
 */
void set_fs_pwd(struct fs_struct *fs, struct path *path)
{
	struct path old_pwd;

	write_lock(&fs->lock);
	old_pwd = fs->pwd;
	fs->pwd = *path;
	path_get(path);
	write_unlock(&fs->lock);

	if (old_pwd.dentry)
		path_put(&old_pwd);
}

void chroot_fs_refs(struct path *old_root, struct path *new_root)
{
	struct task_struct *g, *p;
	struct fs_struct *fs;
	int count = 0;

	read_lock(&tasklist_lock);
	do_each_thread(g, p) {
		task_lock(p);
		fs = p->fs;
		if (fs) {
			write_lock(&fs->lock);
			if (fs->root.dentry == old_root->dentry
			    && fs->root.mnt == old_root->mnt) {
				path_get(new_root);
				fs->root = *new_root;
				count++;
			}
			if (fs->pwd.dentry == old_root->dentry
			    && fs->pwd.mnt == old_root->mnt) {
				path_get(new_root);
				fs->pwd = *new_root;
				count++;
			}
			write_unlock(&fs->lock);
		}
		task_unlock(p);
	} while_each_thread(g, p);
	read_unlock(&tasklist_lock);
	while (count--)
		path_put(old_root);
}

void free_fs_struct(struct fs_struct *fs)
{
	path_put(&fs->root);
	path_put(&fs->pwd);
	kmem_cache_free(fs_cachep, fs);
}
/*用于任务退出时清理其文件系统的环境*/
void exit_fs(struct task_struct *tsk)
{
	struct fs_struct *fs = tsk->fs;

	if (fs) {
		int kill;
		task_lock(tsk);
		write_lock(&fs->lock);
		tsk->fs = NULL;
		kill = !--fs->users;
		write_unlock(&fs->lock);
		task_unlock(tsk);
		if (kill)
			free_fs_struct(fs);
	}
}
/*用于fork时资源的复制*/
struct fs_struct *copy_fs_struct(struct fs_struct *old)
{
	struct fs_struct *fs = kmem_cache_alloc(fs_cachep, GFP_KERNEL);
	/* We don't need to lock fs - think why ;-) */
	if (fs) {
		fs->users = 1;
		fs->in_exec = 0;
		rwlock_init(&fs->lock);
		fs->umask = old->umask;
		read_lock(&old->lock);
		fs->root = old->root;
		path_get(&old->root);
		fs->pwd = old->pwd;
		path_get(&old->pwd);
		read_unlock(&old->lock);
	}
	return fs;
}

int unshare_fs_struct(void)
{
	struct fs_struct *fs = current->fs;
	struct fs_struct *new_fs = copy_fs_struct(fs);
	int kill;

	if (!new_fs)
		return -ENOMEM;

	task_lock(current);
	write_lock(&fs->lock);
	kill = !--fs->users;
	current->fs = new_fs;
	write_unlock(&fs->lock);
	task_unlock(current);

	if (kill)
		free_fs_struct(fs);

	return 0;
}
EXPORT_SYMBOL_GPL(unshare_fs_struct);

int current_umask(void)
{
	return current->fs->umask;
}
EXPORT_SYMBOL(current_umask);

/* to be mentioned only in INIT_TASK */
struct fs_struct init_fs = {
	.users		= 1,
	.lock		= __RW_LOCK_UNLOCKED(init_fs.lock),
	.umask		= 0022,
};

void daemonize_fs_struct(void)
{
	struct fs_struct *fs = current->fs;

	if (fs) {
		int kill;

		task_lock(current);

		write_lock(&init_fs.lock);
		init_fs.users++;
		write_unlock(&init_fs.lock);

		write_lock(&fs->lock);
		current->fs = &init_fs;
		kill = !--fs->users;
		write_unlock(&fs->lock);

		task_unlock(current);
		if (kill)
			free_fs_struct(fs);
	}
}
