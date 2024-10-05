/*
 *  linux/fs/char_dev.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/major.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/seq_file.h>

#include <linux/kobject.h>
#include <linux/kobj_map.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/backing-dev.h>

#include "internal.h"

/*
 * capabilities for /dev/mem, /dev/kmem and similar directly mappable character
 * devices
 * - permits shared-mmap for read, write and/or exec
 * - does not permit private mmap in NOMMU mode (can't do COW)
 * - no readahead or I/O queue unplugging required
 */
struct backing_dev_info directly_mappable_cdev_bdi = {
	.name = "char",
	.capabilities	= (
#ifdef CONFIG_MMU
		/* permit private copies of the data to be taken */
		BDI_CAP_MAP_COPY |
#endif
		/* permit direct mmap, for read, write or exec */
		BDI_CAP_MAP_DIRECT |
		BDI_CAP_READ_MAP | BDI_CAP_WRITE_MAP | BDI_CAP_EXEC_MAP),
};

static struct kobj_map *cdev_map;

static DEFINE_MUTEX(chrdevs_lock);

static struct char_device_struct {
	struct char_device_struct *next;
	unsigned int major;
	unsigned int baseminor;
	int minorct;
	char name[64];
	struct cdev *cdev;		/* will die */
} *chrdevs[CHRDEV_MAJOR_HASH_SIZE];

/* index in the above */
static inline int major_to_index(int major)
{
	return major % CHRDEV_MAJOR_HASH_SIZE;
}

#ifdef CONFIG_PROC_FS

void chrdev_show(struct seq_file *f, off_t offset)
{
	struct char_device_struct *cd;

	if (offset < CHRDEV_MAJOR_HASH_SIZE) {
		mutex_lock(&chrdevs_lock);
		for (cd = chrdevs[offset]; cd; cd = cd->next)
			seq_printf(f, "%3d %s\n", cd->major, cd->name);
		mutex_unlock(&chrdevs_lock);
	}
}

#endif /* CONFIG_PROC_FS */

/**
 * __register_chrdev_region() - 注册一个字符设备号区域
 * @major: 主要设备号。如果为 0，系统将动态分配一个未使用的主设备号。
 * @baseminor: 设备的起始次设备号。
 * @minorct: 要注册的连续次设备号的数量。
 * @name: 设备的名称。
 *
 * 该函数用于为字符设备分配并注册一个主设备号和次设备号范围。
 * 如果成功，函数返回一个指向 `char_device_struct` 结构的指针；
 * 否则返回错误指针（如 -ENOMEM 或 -EBUSY）。
 *
 * 返回值:
 * - 成功时返回 `char_device_struct` 结构指针。
 * - 错误时返回错误指针，可能为 -ENOMEM（内存分配失败）或 -EBUSY（设备号冲突）。
 */
static struct char_device_struct *
__register_chrdev_region(unsigned int major, unsigned int baseminor,
			   int minorct, const char *name)
{
	struct char_device_struct *cd, **cp;
	int ret = 0;
	int i;

	// 为字符设备结构分配内存，并初始化为 0
	cd = kzalloc(sizeof(struct char_device_struct), GFP_KERNEL);
	if (cd == NULL)
		return ERR_PTR(-ENOMEM); // 内存分配失败，返回错误指针

	mutex_lock(&chrdevs_lock); // 获取字符设备全局表的锁

	/* 如果主设备号为 0，表示需要动态分配一个未使用的主设备号 */
	if (major == 0) {
		for (i = ARRAY_SIZE(chrdevs) - 1; i > 0; i--) {
			if (chrdevs[i] == NULL) // 找到未使用的主设备号
				break;
		}

		// 如果没有可用的主设备号，返回错误
		if (i == 0) {
			ret = -EBUSY;
			goto out;
		}
		major = i; // 使用找到的主设备号
		ret = major; // 返回分配的主设备号
	}

	// 设置字符设备的属性
	cd->major = major;
	cd->baseminor = baseminor;
	cd->minorct = minorct;
	strlcpy(cd->name, name, sizeof(cd->name)); // 拷贝设备名称

	i = major_to_index(major); // 计算哈希索引

	// 遍历字符设备表，找到适合的位置插入新的字符设备
	for (cp = &chrdevs[i]; *cp; cp = &(*cp)->next)
		if ((*cp)->major > major ||
		    ((*cp)->major == major &&
		     (((*cp)->baseminor >= baseminor) ||
		      ((*cp)->baseminor + (*cp)->minorct > baseminor))))
			break;

	/* 检查次设备号范围是否重叠 */
	if (*cp && (*cp)->major == major) {
		int old_min = (*cp)->baseminor;
		int old_max = (*cp)->baseminor + (*cp)->minorct - 1;
		int new_min = baseminor;
		int new_max = baseminor + minorct - 1;

		// 新设备与已存在设备从左边重叠
		if (new_max >= old_min && new_max <= old_max) {
			ret = -EBUSY;
			goto out;
		}

		// 新设备与已存在设备从右边重叠
		if (new_min <= old_max && new_min >= old_min) {
			ret = -EBUSY;
			goto out;
		}
	}

	// 将新设备插入字符设备链表
	cd->next = *cp;
	*cp = cd;
	mutex_unlock(&chrdevs_lock); // 解锁
	return cd; // 返回注册成功的字符设备结构指针

out:
	mutex_unlock(&chrdevs_lock); // 解锁
	kfree(cd); // 释放已分配的内存
	return ERR_PTR(ret); // 返回错误指针
}

static struct char_device_struct *
__unregister_chrdev_region(unsigned major, unsigned baseminor, int minorct)
{
	struct char_device_struct *cd = NULL, **cp;
	int i = major_to_index(major);

	mutex_lock(&chrdevs_lock);
	for (cp = &chrdevs[i]; *cp; cp = &(*cp)->next)
		if ((*cp)->major == major &&
		    (*cp)->baseminor == baseminor &&
		    (*cp)->minorct == minorct)
			break;
	if (*cp) {
		cd = *cp;
		*cp = cd->next;
	}
	mutex_unlock(&chrdevs_lock);
	return cd;
}

/**
 * register_chrdev_region() - register a range of device numbers
 * @from: the first in the desired range of device numbers; must include
 *        the major number.
 * @count: the number of consecutive device numbers required
 * @name: the name of the device or driver.
 *
 * Return value is zero on success, a negative error code on failure.
 */
int register_chrdev_region(dev_t from, unsigned count, const char *name)
{
	struct char_device_struct *cd;
	dev_t to = from + count;
	dev_t n, next;

	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		if (next > to)
			next = to;
		cd = __register_chrdev_region(MAJOR(n), MINOR(n),
			       next - n, name);
		if (IS_ERR(cd))
			goto fail;
	}
	return 0;
fail:
	to = n;
	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		kfree(__unregister_chrdev_region(MAJOR(n), MINOR(n), next - n));
	}
	return PTR_ERR(cd);
}

/**
 * alloc_chrdev_region() - register a range of char device numbers
 * @dev: output parameter for first assigned number
 * @baseminor: first of the requested range of minor numbers
 * @count: the number of minor numbers required
 * @name: the name of the associated device or driver
 *
 * Allocates a range of char device numbers.  The major number will be
 * chosen dynamically, and returned (along with the first minor number)
 * in @dev.  Returns zero or a negative error code.
 */
int alloc_chrdev_region(dev_t *dev, unsigned baseminor, unsigned count,
			const char *name)
{
	struct char_device_struct *cd;
	cd = __register_chrdev_region(0, baseminor, count, name);
	if (IS_ERR(cd))
		return PTR_ERR(cd);
	*dev = MKDEV(cd->major, cd->baseminor);
	return 0;
}

/**
 * __register_chrdev() - 创建并注册一个字符设备，管理一系列次设备号
 * @major: 主设备号，或为 0 以动态分配
 * @baseminor: 请求的次设备号范围的起始次设备号
 * @count: 所需的次设备号数量
 * @name: 设备名称，用于标识这个设备范围
 * @fops: 关联的文件操作结构体
 *
 * 如果 @major == 0，该函数将动态分配一个主设备号并返回该主设备号。
 *
 * 如果 @major > 0，该函数将尝试保留具有指定主设备号的设备，
 * 成功时返回 0。
 *
 * 失败时返回负的错误码。
 *
 * 该设备的名称与 /dev 中的设备名称无关。它仅帮助跟踪设备的不同拥有者。
 * 如果你的模块只有一种设备类型，可以在这里使用模块名称作为设备名称。
 */
int __register_chrdev(unsigned int major, unsigned int baseminor,
		      unsigned int count, const char *name,
		      const struct file_operations *fops)
{
	struct char_device_struct *cd;
	struct cdev *cdev;
	int err = -ENOMEM;

	// 注册字符设备区域，分配设备号
	cd = __register_chrdev_region(major, baseminor, count, name);
	if (IS_ERR(cd))
		return PTR_ERR(cd);
	
	// 分配 cdev 结构体
	cdev = cdev_alloc();
	if (!cdev)
		goto out2;

	cdev->owner = fops->owner;  // 设置设备的拥有者
	cdev->ops = fops;          // 设置设备的文件操作
	kobject_set_name(&cdev->kobj, "%s", name);  // 设置设备名称
	
	// 将 cdev 添加到系统中
	err = cdev_add(cdev, MKDEV(cd->major, baseminor), count);
	if (err)
		goto out;

	cd->cdev = cdev;

	// 如果请求主设备号为 0，返回分配的主设备号
	return major ? 0 : cd->major;

out:
	kobject_put(&cdev->kobj);  // 释放 cdev 的 kobject
out2:
	kfree(__unregister_chrdev_region(cd->major, baseminor, count));  // 释放字符设备区域
	return err;
}

/**
 * unregister_chrdev_region() - return a range of device numbers
 * @from: the first in the range of numbers to unregister
 * @count: the number of device numbers to unregister
 *
 * This function will unregister a range of @count device numbers,
 * starting with @from.  The caller should normally be the one who
 * allocated those numbers in the first place...
 */
void unregister_chrdev_region(dev_t from, unsigned count)
{
	dev_t to = from + count;
	dev_t n, next;

	for (n = from; n < to; n = next) {
		next = MKDEV(MAJOR(n)+1, 0);
		if (next > to)
			next = to;
		kfree(__unregister_chrdev_region(MAJOR(n), MINOR(n), next - n));
	}
}

/**
 * __unregister_chrdev - unregister and destroy a cdev
 * @major: major device number
 * @baseminor: first of the range of minor numbers
 * @count: the number of minor numbers this cdev is occupying
 * @name: name of this range of devices
 *
 * Unregister and destroy the cdev occupying the region described by
 * @major, @baseminor and @count.  This function undoes what
 * __register_chrdev() did.
 */
void __unregister_chrdev(unsigned int major, unsigned int baseminor,
			 unsigned int count, const char *name)
{
	struct char_device_struct *cd;

	cd = __unregister_chrdev_region(major, baseminor, count);
	if (cd && cd->cdev)
		cdev_del(cd->cdev);
	kfree(cd);
}

static DEFINE_SPINLOCK(cdev_lock);

static struct kobject *cdev_get(struct cdev *p)
{
	struct module *owner = p->owner;
	struct kobject *kobj;

	if (owner && !try_module_get(owner))
		return NULL;
	kobj = kobject_get(&p->kobj);
	if (!kobj)
		module_put(owner);
	return kobj;
}

void cdev_put(struct cdev *p)
{
	if (p) {
		struct module *owner = p->owner;
		kobject_put(&p->kobj);
		module_put(owner);
	}
}

/*
 * Called every time a character special file is opened
 */
static int chrdev_open(struct inode *inode, struct file *filp)
{
	struct cdev *p;
	struct cdev *new = NULL;
	int ret = 0;

	// 1. 获取 cdev 锁
	spin_lock(&cdev_lock);
	p = inode->i_cdev;

	// 2. 如果 inode 还没有关联的 cdev
	if (!p) {
		struct kobject *kobj;
		int idx;

		// 3. 解锁 cdev 锁，查找对应的 cdev 对象
		spin_unlock(&cdev_lock);
		kobj = kobj_lookup(cdev_map, inode->i_rdev, &idx);
		if (!kobj)
			return -ENXIO;  // 设备未找到

		// 4. 从 kobject 中获取 cdev 对象
		new = container_of(kobj, struct cdev, kobj);
		spin_lock(&cdev_lock);

		// 5. 再次检查 inode 的 i_cdev，确保在我们重新加锁期间没有其他线程修改
		p = inode->i_cdev;
		if (!p) {
			inode->i_cdev = p = new;
			list_add(&inode->i_devices, &p->list);  // 将 cdev 添加到设备列表
			new = NULL;
		} else if (!cdev_get(p))  // 增加 cdev 的引用计数
			ret = -ENXIO;  // 设备未找到
	} else if (!cdev_get(p))  // 增加 cdev 的引用计数
		ret = -ENXIO;  // 设备未找到

	// 6. 释放 cdev 锁
	spin_unlock(&cdev_lock);
	cdev_put(new);  // 释放对 new 的引用

	// 7. 检查是否出错
	if (ret)
		return ret;

	// 8. 获取文件操作结构体 f_op
	ret = -ENXIO;
	filp->f_op = fops_get(p->ops);
	if (!filp->f_op)
		goto out_cdev_put;

	// 9. 如果文件操作结构体有 open 函数，则调用它
	if (filp->f_op->open) {
		ret = filp->f_op->open(inode, filp);
		if (ret)
			goto out_cdev_put;
	}

	return 0;

 out_cdev_put:
	cdev_put(p);  // 释放对 cdev 的引用
	return ret;
}

int cdev_index(struct inode *inode)
{
	int idx;
	struct kobject *kobj;

	kobj = kobj_lookup(cdev_map, inode->i_rdev, &idx);
	if (!kobj)
		return -1;
	kobject_put(kobj);
	return idx;
}

void cd_forget(struct inode *inode)
{
	spin_lock(&cdev_lock);
	list_del_init(&inode->i_devices);
	inode->i_cdev = NULL;
	spin_unlock(&cdev_lock);
}

static void cdev_purge(struct cdev *cdev)
{
	spin_lock(&cdev_lock);
	while (!list_empty(&cdev->list)) {
		struct inode *inode;
		inode = container_of(cdev->list.next, struct inode, i_devices);
		list_del_init(&inode->i_devices);
		inode->i_cdev = NULL;
	}
	spin_unlock(&cdev_lock);
}

/*
 * Dummy default file-operations: the only thing this does
 * is contain the open that then fills in the correct operations
 * depending on the special file...
 */
const struct file_operations def_chr_fops = {
	.open = chrdev_open,
};

static struct kobject *exact_match(dev_t dev, int *part, void *data)
{
	struct cdev *p = data;
	return &p->kobj;
}

static int exact_lock(dev_t dev, void *data)
{
	struct cdev *p = data;
	return cdev_get(p) ? 0 : -1;
}

/**
 * cdev_add() - add a char device to the system
 * @p: the cdev structure for the device
 * @dev: the first device number for which this device is responsible
 * @count: the number of consecutive minor numbers corresponding to this
 *         device
 *
 * cdev_add() adds the device represented by @p to the system, making it
 * live immediately.  A negative error code is returned on failure.
 */
/**
 * cdev_add() - 向系统中添加字符设备
 * @p: 该设备的 cdev 结构指针
 * @dev: 该设备负责的第一个设备号（主设备号和次设备号组合）
 * @count: 与该设备对应的连续次设备号数量
 *
 * cdev_add() 将由 @p 所表示的字符设备添加到系统中，使该设备立即生效并
 * 可供用户空间访问。该函数在成功时返回 0，若失败则返回负的错误代码。
 * 
 * 主要作用是将字符设备注册到内核中，完成从内核视角的字符设备配置，
 * 使其能够通过设备号（主设备号+次设备号）进行操作。
 */

int cdev_add(struct cdev *p, dev_t dev, unsigned count)
{
	p->dev = dev;
	p->count = count;
	return kobj_map(cdev_map, dev, count, NULL, exact_match, exact_lock, p);
}

static void cdev_unmap(dev_t dev, unsigned count)
{
	kobj_unmap(cdev_map, dev, count);
}

/**
 * cdev_del() - remove a cdev from the system
 * @p: the cdev structure to be removed
 *
 * cdev_del() removes @p from the system, possibly freeing the structure
 * itself.
 */
void cdev_del(struct cdev *p)
{
	cdev_unmap(p->dev, p->count);
	kobject_put(&p->kobj);
}


static void cdev_default_release(struct kobject *kobj)
{
	struct cdev *p = container_of(kobj, struct cdev, kobj);
	cdev_purge(p);
}

static void cdev_dynamic_release(struct kobject *kobj)
{
	struct cdev *p = container_of(kobj, struct cdev, kobj);
	cdev_purge(p);
	kfree(p);
}

static struct kobj_type ktype_cdev_default = {
	.release	= cdev_default_release,
};

static struct kobj_type ktype_cdev_dynamic = {
	.release	= cdev_dynamic_release,
};

/**
 * cdev_alloc() - allocate a cdev structure
 *
 * Allocates and returns a cdev structure, or NULL on failure.
 */
struct cdev *cdev_alloc(void)
{
	struct cdev *p = kzalloc(sizeof(struct cdev), GFP_KERNEL);
	if (p) {
		INIT_LIST_HEAD(&p->list);
		kobject_init(&p->kobj, &ktype_cdev_dynamic);
	}
	return p;
}

/**
 * cdev_init() - initialize a cdev structure
 * @cdev: the structure to initialize
 * @fops: the file_operations for this device
 *
 * Initializes @cdev, remembering @fops, making it ready to add to the
 * system with cdev_add().
 */
void cdev_init(struct cdev *cdev, const struct file_operations *fops)
{
	memset(cdev, 0, sizeof *cdev);
	INIT_LIST_HEAD(&cdev->list);
	kobject_init(&cdev->kobj, &ktype_cdev_default);
	cdev->ops = fops;
}

static struct kobject *base_probe(dev_t dev, int *part, void *data)
{
	if (request_module("char-major-%d-%d", MAJOR(dev), MINOR(dev)) > 0)
		/* Make old-style 2.4 aliases work */
		request_module("char-major-%d", MAJOR(dev));
	return NULL;
}

void __init chrdev_init(void)
{
	cdev_map = kobj_map_init(base_probe, &chrdevs_lock);
	bdi_init(&directly_mappable_cdev_bdi);
}


/* Let modules do char dev stuff */
EXPORT_SYMBOL(register_chrdev_region);
EXPORT_SYMBOL(unregister_chrdev_region);
EXPORT_SYMBOL(alloc_chrdev_region);
EXPORT_SYMBOL(cdev_init);
EXPORT_SYMBOL(cdev_alloc);
EXPORT_SYMBOL(cdev_del);
EXPORT_SYMBOL(cdev_add);
EXPORT_SYMBOL(cdev_index);
EXPORT_SYMBOL(__register_chrdev);
EXPORT_SYMBOL(__unregister_chrdev);
EXPORT_SYMBOL(directly_mappable_cdev_bdi);
