#ifndef _LINUX_NSPROXY_H
#define _LINUX_NSPROXY_H

#include <linux/spinlock.h>
#include <linux/sched.h>

struct mnt_namespace;
struct uts_namespace;
struct ipc_namespace;
struct pid_namespace;
struct fs_struct;

/*
 * A structure to contain pointers to all per-process
 * namespaces - fs (mount), uts, network, sysvipc, etc.
 *
 * 'count' is the number of tasks holding a reference.
 * The count for each namespace, then, will be the number
 * of nsproxies pointing to it, not the number of tasks.
 *
 * The nsproxy is shared by tasks which share all namespaces.
 * As soon as a single namespace is cloned or unshared, the
 * nsproxy is copied.
 */
struct nsproxy {
	atomic_t count;//原子计数器，用于管理结构的引用计数
	struct uts_namespace *uts_ns;//指向 UTS 命名空间的指针，存储系统标识符信息。
	struct ipc_namespace *ipc_ns;//指向 IPC 命名空间的指针，管理进程间通信资源。
	struct mnt_namespace *mnt_ns;//指向挂载命名空间的指针，管理文件系统的挂载点。
	struct pid_namespace *pid_ns;//指向 PID 命名空间的指针，管理进程 ID 的命名空间。
	struct net 	     *net_ns;//指向网络命名空间的指针，管理网络资源和设置。
};
extern struct nsproxy init_nsproxy;

/*
 * the namespaces access rules are:
 *
 *  1. only current task is allowed to change tsk->nsproxy pointer or
 *     any pointer on the nsproxy itself
 *
 *  2. when accessing (i.e. reading) current task's namespaces - no
 *     precautions should be taken - just dereference the pointers
 *
 *  3. the access to other task namespaces is performed like this
 *     rcu_read_lock();
 *     nsproxy = task_nsproxy(tsk);
 *     if (nsproxy != NULL) {
 *             / *
 *               * work with the namespaces here
 *               * e.g. get the reference on one of them
 *               * /
 *     } / *
 *         * NULL task_nsproxy() means that this task is
 *         * almost dead (zombie)
 *         * /
 *     rcu_read_unlock();
 *
 */

static inline struct nsproxy *task_nsproxy(struct task_struct *tsk)
{
	return rcu_dereference(tsk->nsproxy);
}

int copy_namespaces(unsigned long flags, struct task_struct *tsk);
void exit_task_namespaces(struct task_struct *tsk);
void switch_task_namespaces(struct task_struct *tsk, struct nsproxy *new);
void free_nsproxy(struct nsproxy *ns);
int unshare_nsproxy_namespaces(unsigned long, struct nsproxy **,
	struct fs_struct *);

static inline void put_nsproxy(struct nsproxy *ns)
{
	if (atomic_dec_and_test(&ns->count)) {
		free_nsproxy(ns);
	}
}

static inline void get_nsproxy(struct nsproxy *ns)
{
	atomic_inc(&ns->count);
}

#ifdef CONFIG_CGROUP_NS
int ns_cgroup_clone(struct task_struct *tsk, struct pid *pid);
#else
static inline int ns_cgroup_clone(struct task_struct *tsk, struct pid *pid)
{
	return 0;
}
#endif

#endif
