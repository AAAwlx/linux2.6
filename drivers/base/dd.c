/*
 * drivers/base/dd.c - The core device/driver interactions.
 *
 * This file contains the (sometimes tricky) code that controls the
 * interactions between devices and drivers, which primarily includes
 * driver binding and unbinding.
 *
 * All of this code used to exist in drivers/base/bus.c, but was
 * relocated to here in the name of compartmentalization (since it wasn't
 * strictly code just for the 'struct bus_type'.
 *
 * Copyright (c) 2002-5 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 * Copyright (c) 2007-2009 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2007-2009 Novell Inc.
 *
 * This file is released under the GPLv2
 */

#include <linux/device.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/async.h>
#include <linux/pm_runtime.h>

#include "base.h"
#include "power/power.h"


static void driver_bound(struct device *dev)
{
	if (klist_node_attached(&dev->p->knode_driver)) {
		printk(KERN_WARNING "%s: device %s already bound\n",
			__func__, kobject_name(&dev->kobj));
		return;
	}

	pr_debug("driver: '%s': %s: bound to device '%s'\n", dev_name(dev),
		 __func__, dev->driver->name);

	if (dev->bus)
		blocking_notifier_call_chain(&dev->bus->p->bus_notifier,
					     BUS_NOTIFY_BOUND_DRIVER, dev);

	klist_add_tail(&dev->p->knode_driver, &dev->driver->p->klist_devices);
}

static int driver_sysfs_add(struct device *dev)
{
	int ret;

	ret = sysfs_create_link(&dev->driver->p->kobj, &dev->kobj,
			  kobject_name(&dev->kobj));
	if (ret == 0) {
		ret = sysfs_create_link(&dev->kobj, &dev->driver->p->kobj,
					"driver");
		if (ret)
			sysfs_remove_link(&dev->driver->p->kobj,
					kobject_name(&dev->kobj));
	}
	return ret;
}

static void driver_sysfs_remove(struct device *dev)
{
	struct device_driver *drv = dev->driver;

	if (drv) {
		sysfs_remove_link(&drv->p->kobj, kobject_name(&dev->kobj));
		sysfs_remove_link(&dev->kobj, "driver");
	}
}

/**
 * device_bind_driver - bind a driver to one device.
 * @dev: device.
 *
 * Allow manual attachment of a driver to a device.
 * Caller must have already set @dev->driver.
 *
 * Note that this does not modify the bus reference count
 * nor take the bus's rwsem. Please verify those are accounted
 * for before calling this. (It is ok to call with no other effort
 * from a driver's probe() method.)
 *
 * This function must be called with the device lock held.
 */
int device_bind_driver(struct device *dev)
{
	int ret;

	ret = driver_sysfs_add(dev);
	if (!ret)
		driver_bound(dev);
	return ret;
}
EXPORT_SYMBOL_GPL(device_bind_driver);

static atomic_t probe_count = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(probe_waitqueue);

/**
 * really_probe - 真正的驱动程序探测函数
 * @dev: 要探测的设备
 * @drv: 要探测的驱动程序
 *
 * 此函数尝试将指定的驱动程序与设备进行匹配和绑定。
 * 如果匹配成功并且探测成功，则将驱动程序绑定到设备。
 * 如果探测失败或者驱动程序与设备不匹配，则会进行清理工作并返回适当的错误码。
 *
 * 返回值:
 *  - 1: 成功将驱动程序绑定到设备
 *  - 0: 驱动程序与设备不匹配或者探测失败
 */
static int really_probe(struct device *dev, struct device_driver *drv)
{
    int ret = 0;

    atomic_inc(&probe_count);  // 原子操作，增加探测计数器

    pr_debug("bus: '%s': %s: probing driver %s with device %s\n",
             drv->bus->name, __func__, drv->name, dev_name(dev));  // 打印调试信息，记录探测驱动程序和设备的过程
    WARN_ON(!list_empty(&dev->devres_head));  // 如果设备资源列表不为空，则发出警告

    dev->driver = drv;  // 将设备的驱动程序指针指向传入的驱动程序结构体
    if (driver_sysfs_add(dev)) {  // 将驱动程序添加到设备的sysfs节点
        printk(KERN_ERR "%s: driver_sysfs_add(%s) failed\n",
               __func__, dev_name(dev));
        goto probe_failed;  // 如果添加失败，则跳转到探测失败处理步骤
    }

    if (dev->bus->probe) {  // 如果设备总线定义了probe函数
        ret = dev->bus->probe(dev);  // 调用总线的probe函数，尝试探测设备
        if (ret)
            goto probe_failed;  // 如果探测失败，则跳转到探测失败处理步骤
    } else if (drv->probe) {  // 如果设备总线没有定义probe函数，但驱动程序定义了probe函数
        ret = drv->probe(dev);  // 调用驱动程序的probe函数，尝试探测设备
        if (ret)
            goto probe_failed;  // 如果探测失败，则跳转到探测失败处理步骤
    }

    driver_bound(dev);  // 将驱动程序绑定到设备
    ret = 1;  // 设置返回值为1，表示成功将驱动程序绑定到设备
    pr_debug("bus: '%s': %s: bound device %s to driver %s\n",
             drv->bus->name, __func__, dev_name(dev), drv->name);  // 打印调试信息，记录驱动程序绑定到设备的过程
    goto done;  // 跳转到完成处理步骤

probe_failed:
    devres_release_all(dev);  // 释放设备的所有资源
    driver_sysfs_remove(dev);  // 从设备的sysfs节点移除驱动程序
    dev->driver = NULL;  // 将设备的驱动程序指针置为NULL

    if (ret != -ENODEV && ret != -ENXIO) {
        /* 驱动程序匹配但探测失败 */
        printk(KERN_WARNING
               "%s: probe of %s failed with error %d\n",
               drv->name, dev_name(dev), ret);
    }
    /*
     * 忽略由于 ->probe 返回的错误，以便下一个驱动程序可以尝试运行。
     */
    ret = 0;  // 设置返回值为0，表示驱动程序与设备不匹配或者探测失败

done:
    atomic_dec(&probe_count);  // 原子操作，减少探测计数器
    wake_up(&probe_waitqueue);  // 唤醒等待队列中等待探测完成的进程

    return ret;  // 返回探测结果，1表示成功绑定驱动程序，0表示失败或者驱动程序与设备不匹配
}

/**
 * driver_probe_done
 * Determine if the probe sequence is finished or not.
 *
 * Should somehow figure out how to use a semaphore, not an atomic variable...
 */
int driver_probe_done(void)
{
	pr_debug("%s: probe_count = %d\n", __func__,
		 atomic_read(&probe_count));
	if (atomic_read(&probe_count))
		return -EBUSY;
	return 0;
}

/**
 * wait_for_device_probe - 等待设备探测完成
 *
 * 此函数等待所有已知设备完成其探测过程。
 * 它使用等待队列来暂停执行，直到条件 (probe_count == 0) 满足，
 * 确保没有更多设备正在探测。一旦条件满足，
 * 它会同步任何异步操作以确保完全初始化。
 */
void wait_for_device_probe(void)
{
	/* 等待已知设备完成其探测 */
	wait_event(probe_waitqueue, atomic_read(&probe_count) == 0);

	/* 同步任何异步操作以确保完全初始化 */
	async_synchronize_full();
}
EXPORT_SYMBOL_GPL(wait_for_device_probe);


/**
 * driver_probe_device - 尝试将设备与驱动程序绑定
 * @drv: 要绑定到设备的驱动程序
 * @dev: 要尝试绑定到驱动程序的设备
 *
 * 如果设备未注册，则此函数返回 -ENODEV；
 * 如果设备成功绑定，则返回 1；
 * 否则返回 0。
 *
 * 调用此函数时必须持有 @dev 的锁。对于 USB 接口，还必须持有 @dev->parent 的锁。
 */
int driver_probe_device(struct device_driver *drv, struct device *dev)
{
	int ret = 0;

	// 如果设备未注册，则返回 -ENODEV
	if (!device_is_registered(dev))
		return -ENODEV;

	// 打印调试信息，显示设备与驱动的匹配情况
	pr_debug("bus: '%s': %s: matched device %s with driver %s\n",
		 drv->bus->name, __func__, dev_name(dev), drv->name);

	// 增加设备的运行时引用计数，不唤醒设备
	pm_runtime_get_noresume(dev);
	// 等待设备的运行时操作完成
	pm_runtime_barrier(dev);
	// 真正尝试将设备与驱动程序绑定
	ret = really_probe(dev, drv);
	// 同步释放设备的运行时引用计数
	pm_runtime_put_sync(dev);

	return ret;
}


static int __device_attach(struct device_driver *drv, void *data)
{
	struct device *dev = data;

	if (!driver_match_device(drv, dev))
		return 0;

	return driver_probe_device(drv, dev);
}

/**
 * device_attach - 尝试将设备绑定到其驱动程序
 * @dev: 要绑定的设备结构体指针
 *
 * 此函数尝试将指定的设备绑定到其驱动程序。如果设备已经有驱动程序，则直接尝试绑定。
 * 如果绑定失败，则将设备的驱动程序指针置为NULL，然后返回0。
 * 如果设备没有驱动程序，则遍历设备所在总线上的所有驱动程序，尝试将每个驱动程序绑定到设备。
 * 返回成功绑定的驱动程序数量，如果没有成功绑定任何驱动程序，则返回0。
 */
int device_attach(struct device *dev)
{
    int ret = 0;  // 返回值，默认为0

    device_lock(dev);  // 锁定设备，确保同一时刻只有一个线程访问设备

    if (dev->driver) {  // 如果设备已经有驱动程序
        ret = device_bind_driver(dev);  // 尝试将设备绑定到其驱动程序
        if (ret == 0)
            ret = 1;  // 绑定成功，返回1
        else {
            dev->driver = NULL;  // 绑定失败，将设备的驱动程序指针置为NULL
            ret = 0;  // 返回0表示绑定失败
        }
    } else {  // 如果设备没有驱动程序
        pm_runtime_get_noresume(dev);  // 增加设备的运行时引用计数，但不唤醒设备
        ret = bus_for_each_drv(dev->bus, NULL, dev, __device_attach);  // 遍历设备所在总线上的所有驱动程序，尝试将每个驱动程序绑定到设备
        pm_runtime_put_sync(dev);  // 同步设备的运行时状态，并且等待操作完成
    }

    device_unlock(dev);  // 解锁设备，允许其他线程访问设备

    return ret;  // 返回成功绑定的驱动程序数量，如果没有成功绑定任何驱动程序，则返回0
}

EXPORT_SYMBOL_GPL(device_attach);

static int __driver_attach(struct device *dev, void *data)
{
	struct device_driver *drv = data;

	/*
	 * Lock device and try to bind to it. We drop the error
	 * here and always return 0, because we need to keep trying
	 * to bind to devices and some drivers will return an error
	 * simply if it didn't support the device.
	 *
	 * driver_probe_device() will spit a warning if there
	 * is an error.
	 */

	if (!driver_match_device(drv, dev))
		return 0;

	if (dev->parent)	/* Needed for USB */
		device_lock(dev->parent);
	device_lock(dev);
	if (!dev->driver)
		driver_probe_device(drv, dev);
	device_unlock(dev);
	if (dev->parent)
		device_unlock(dev->parent);

	return 0;
}

/**
 * driver_attach - try to bind driver to devices.
 * @drv: driver.
 *
 * Walk the list of devices that the bus has on it and try to
 * match the driver with each one.  If driver_probe_device()
 * returns 0 and the @dev->driver is set, we've found a
 * compatible pair.
 */
int driver_attach(struct device_driver *drv)
{
	return bus_for_each_dev(drv->bus, NULL, drv, __driver_attach);
}
EXPORT_SYMBOL_GPL(driver_attach);

/*
 * __device_release_driver() must be called with @dev lock held.
 * When called for a USB interface, @dev->parent lock must be held as well.
 */
static void __device_release_driver(struct device *dev)
{
	struct device_driver *drv;

	drv = dev->driver;
	if (drv) {
		pm_runtime_get_noresume(dev);
		pm_runtime_barrier(dev);

		driver_sysfs_remove(dev);

		if (dev->bus)
			blocking_notifier_call_chain(&dev->bus->p->bus_notifier,
						     BUS_NOTIFY_UNBIND_DRIVER,
						     dev);

		if (dev->bus && dev->bus->remove)
			dev->bus->remove(dev);
		else if (drv->remove)
			drv->remove(dev);
		devres_release_all(dev);
		dev->driver = NULL;
		klist_remove(&dev->p->knode_driver);
		if (dev->bus)
			blocking_notifier_call_chain(&dev->bus->p->bus_notifier,
						     BUS_NOTIFY_UNBOUND_DRIVER,
						     dev);

		pm_runtime_put_sync(dev);
	}
}

/**
 * device_release_driver - manually detach device from driver.
 * @dev: device.
 *
 * Manually detach device from driver.
 * When called for a USB interface, @dev->parent lock must be held.
 */
void device_release_driver(struct device *dev)
{
	/*
	 * If anyone calls device_release_driver() recursively from
	 * within their ->remove callback for the same device, they
	 * will deadlock right here.
	 */
	device_lock(dev);
	__device_release_driver(dev);
	device_unlock(dev);
}
EXPORT_SYMBOL_GPL(device_release_driver);

/**
 * driver_detach - detach driver from all devices it controls.
 * @drv: driver.
 */
void driver_detach(struct device_driver *drv)
{
	struct device_private *dev_prv;
	struct device *dev;

	// 循环处理驱动程序关联的设备列表
	for (;;) {
		// 获取设备列表锁
		spin_lock(&drv->p->klist_devices.k_lock);
		// 如果设备列表为空，则释放锁并跳出循环
		if (list_empty(&drv->p->klist_devices.k_list)) {
			spin_unlock(&drv->p->klist_devices.k_lock);
			break;
		}
		// 获取设备私有数据结构，该数据结构包含在设备驱动的设备列表中
		dev_prv = list_entry(drv->p->klist_devices.k_list.prev,
				     struct device_private,
				     knode_driver.n_node);
		// 获取设备指针
		dev = dev_prv->device;
		// 增加设备的引用计数，确保设备不会在操作过程中被释放
		get_device(dev);
		// 释放设备列表锁
		spin_unlock(&drv->p->klist_devices.k_lock);

		// 如果设备有父设备（例如USB设备），则需要获取父设备的锁
		if (dev->parent)
			device_lock(dev->parent);
		// 获取设备自身的锁
		device_lock(dev);
		// 如果设备当前的驱动程序是 drv，则释放设备的驱动绑定
		if (dev->driver == drv)
			__device_release_driver(dev);
		// 释放设备自身的锁
		device_unlock(dev);
		// 如果设备有父设备，则释放父设备的锁
		if (dev->parent)
			device_unlock(dev->parent);
		// 减少设备的引用计数，可能会导致设备的释放
		put_device(dev);
	}
}


/*
 * These exports can't be _GPL due to .h files using this within them, and it
 * might break something that was previously working...
 */
/*
 * 这些导出函数不能使用 _GPL，因为有些 .h 文件中使用了这些函数，
 * 如果改变它们的导出方式，可能会破坏之前能正常工作的代码...
 */
// 从设备结构中获取存储的私有数据
void *dev_get_drvdata(const struct device *dev)
{
	// 确保设备结构及其私有数据指针存在
	if (dev && dev->p)
		// 返回私有数据
		return dev->p->driver_data;
	return NULL;	// 如果设备结构不存在或无私有数据指针，则返回 NULL
}
EXPORT_SYMBOL(dev_get_drvdata);

// 设置设备结构中的私有数据
void dev_set_drvdata(struct device *dev, void *data)
{
	int error;	// 用于捕捉错误码

	if (!dev)	// 如果设备结构不存在，则直接返回
		return;
	// 如果设备结构中没有私有数据结构
	if (!dev->p) {
		// 初始化设备的私有数据结构
		error = device_private_init(dev);
		if (error)	// 如果初始化失败
			return;	// 直接返回
	}
	// 将传入的数据设置为设备的私有数据
	dev->p->driver_data = data;
}
EXPORT_SYMBOL(dev_set_drvdata);
