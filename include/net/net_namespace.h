/*
 * Operations on the network namespace
 */
#ifndef __NET_NET_NAMESPACE_H
#define __NET_NET_NAMESPACE_H

#include <asm/atomic.h>
#include <linux/workqueue.h>
#include <linux/list.h>

#include <net/netns/core.h>
#include <net/netns/mib.h>
#include <net/netns/unix.h>
#include <net/netns/packet.h>
#include <net/netns/ipv4.h>
#include <net/netns/ipv6.h>
#include <net/netns/dccp.h>
#include <net/netns/x_tables.h>
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#include <net/netns/conntrack.h>
#endif
#include <net/netns/xfrm.h>

struct proc_dir_entry;
struct net_device;
struct sock;
struct ctl_table_header;
struct net_generic;
struct sock;


#define NETDEV_HASHBITS    8
#define NETDEV_HASHENTRIES (1 << NETDEV_HASHBITS)

struct net {
	atomic_t count;                       // 原子计数器，管理命名空间引用计数
#ifdef NETNS_REFCNT_DEBUG
	atomic_t use_count;                   // 调试模式下，跟踪销毁引用
#endif
	struct list_head list;                // 网络命名空间链表
	struct list_head cleanup_list;        // 即将释放的命名空间
	struct list_head exit_list;           // 仅在 net_mutex 下使用的链表

	struct proc_dir_entry *proc_net;      // proc 目录入口
	struct proc_dir_entry *proc_net_stat; // proc 统计信息入口

#ifdef CONFIG_SYSCTL
	struct ctl_table_set sysctls;         // sysctl 表设置
#endif

	struct net_device *loopback_dev;      // 环回设备

	struct list_head dev_base_head;       // 设备基础链表
	struct hlist_head *dev_name_head;     // 设备名称哈希链表
	struct hlist_head *dev_index_head;    // 设备索引哈希链表

	// 核心 FIB 规则
	struct list_head rules_ops;            // FIB 规则操作链表
	spinlock_t rules_mod_lock;            // FIB 规则修改锁

	struct sock *rtnl;                    // rtnetlink 套接字
	struct sock *genl_sock;               // 通用 netlink 套接字

	struct netns_core core;               // 网络命名空间核心信息
	struct netns_mib mib;                 // 网络命名空间管理信息库
	struct netns_packet packet;            // 数据包信息
	struct netns_unix unx;                // UNIX 域网络信息
	struct netns_ipv4 ipv4;               // IPv4 网络信息
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct netns_ipv6 ipv6;               // IPv6 网络信息
#endif
#if defined(CONFIG_IP_DCCP) || defined(CONFIG_IP_DCCP_MODULE)
	struct netns_dccp dccp;               // DCCP 网络信息
#endif
#ifdef CONFIG_NETFILTER
	struct netns_xt xt;                   // netfilter 扩展信息
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	struct netns_ct ct;                   // 连接跟踪信息
#endif
	struct sock *nfnl;                   // netfilter netlink 套接字
	struct sock *nfnl_stash;             // netfilter netlink 套接字的临时存储
#endif
#ifdef CONFIG_XFRM
	struct netns_xfrm xfrm;               // 变换网络信息
#endif
#ifdef CONFIG_WEXT_CORE
	struct sk_buff_head wext_nlevents;    // 无线扩展网络事件缓冲区
#endif
	struct net_generic *gen;              // 通用网络数据
};


#include <linux/seq_file_net.h>

/* Init's network namespace */
extern struct net init_net;

#ifdef CONFIG_NET
extern struct net *copy_net_ns(unsigned long flags, struct net *net_ns);

#else /* CONFIG_NET */
static inline struct net *copy_net_ns(unsigned long flags, struct net *net_ns)
{
	/* There is nothing to copy so this is a noop */
	return net_ns;
}
#endif /* CONFIG_NET */


extern struct list_head net_namespace_list;

extern struct net *get_net_ns_by_pid(pid_t pid);

#ifdef CONFIG_NET_NS
extern void __put_net(struct net *net);

static inline struct net *get_net(struct net *net)
{
	atomic_inc(&net->count);
	return net;
}

static inline struct net *maybe_get_net(struct net *net)
{
	/* Used when we know struct net exists but we
	 * aren't guaranteed a previous reference count
	 * exists.  If the reference count is zero this
	 * function fails and returns NULL.
	 */
	if (!atomic_inc_not_zero(&net->count))
		net = NULL;
	return net;
}

static inline void put_net(struct net *net)
{
	if (atomic_dec_and_test(&net->count))
		__put_net(net);
}

static inline
int net_eq(const struct net *net1, const struct net *net2)
{
	return net1 == net2;
}
#else

static inline struct net *get_net(struct net *net)
{
	return net;
}

static inline void put_net(struct net *net)
{
}

static inline struct net *maybe_get_net(struct net *net)
{
	return net;
}

static inline
int net_eq(const struct net *net1, const struct net *net2)
{
	return 1;
}
#endif


#ifdef NETNS_REFCNT_DEBUG
static inline struct net *hold_net(struct net *net)
{
	if (net)
		atomic_inc(&net->use_count);
	return net;
}

static inline void release_net(struct net *net)
{
	if (net)
		atomic_dec(&net->use_count);
}
#else
static inline struct net *hold_net(struct net *net)
{
	return net;
}

static inline void release_net(struct net *net)
{
}
#endif

#ifdef CONFIG_NET_NS

static inline void write_pnet(struct net **pnet, struct net *net)
{
	*pnet = net;
}

static inline struct net *read_pnet(struct net * const *pnet)
{
	return *pnet;
}

#else

#define write_pnet(pnet, net)	do { (void)(net);} while (0)
#define read_pnet(pnet)		(&init_net)

#endif

#define for_each_net(VAR)				\
	list_for_each_entry(VAR, &net_namespace_list, list)

#define for_each_net_rcu(VAR)				\
	list_for_each_entry_rcu(VAR, &net_namespace_list, list)

#ifdef CONFIG_NET_NS
#define __net_init
#define __net_exit
#define __net_initdata
#else
#define __net_init	__init
#define __net_exit	__exit_refok
#define __net_initdata	__initdata
#endif

struct pernet_operations {
	struct list_head list;
	int (*init)(struct net *net);
	void (*exit)(struct net *net);
	void (*exit_batch)(struct list_head *net_exit_list);
	int *id;
	size_t size;
};

/*
 * Use these carefully.  If you implement a network device and it
 * needs per network namespace operations use device pernet operations,
 * otherwise use pernet subsys operations.
 *
 * Network interfaces need to be removed from a dying netns _before_
 * subsys notifiers can be called, as most of the network code cleanup
 * (which is done from subsys notifiers) runs with the assumption that
 * dev_remove_pack has been called so no new packets will arrive during
 * and after the cleanup functions have been called.  dev_remove_pack
 * is not per namespace so instead the guarantee of no more packets
 * arriving in a network namespace is provided by ensuring that all
 * network devices and all sockets have left the network namespace
 * before the cleanup methods are called.
 *
 * For the longest time the ipv4 icmp code was registered as a pernet
 * device which caused kernel oops, and panics during network
 * namespace cleanup.   So please don't get this wrong.
 */
extern int register_pernet_subsys(struct pernet_operations *);
extern void unregister_pernet_subsys(struct pernet_operations *);
extern int register_pernet_device(struct pernet_operations *);
extern void unregister_pernet_device(struct pernet_operations *);

struct ctl_path;
struct ctl_table;
struct ctl_table_header;

extern struct ctl_table_header *register_net_sysctl_table(struct net *net,
	const struct ctl_path *path, struct ctl_table *table);
extern struct ctl_table_header *register_net_sysctl_rotable(
	const struct ctl_path *path, struct ctl_table *table);
extern void unregister_net_sysctl_table(struct ctl_table_header *header);

#endif /* __NET_NET_NAMESPACE_H */
