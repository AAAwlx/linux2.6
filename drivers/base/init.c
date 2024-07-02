/*
 * Copyright (c) 2002-3 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 *
 * This file is released under the GPLv2
 */

#include <linux/device.h>
#include <linux/init.h>
#include <linux/memory.h>

#include "base.h"

/**
 * driver_init - 驱动程序初始化函数
 *
 * 在系统启动过程中调用，用于初始化驱动程序和设备相关的核心组件。
 * 初始化顺序按照依赖关系来安排，确保各个组件能够正常工作。
 */
void __init driver_init(void)
{
    /* 这些是核心组件 */
    devtmpfs_init();        // 初始化设备临时文件系统
    devices_init();         // 初始化设备
    buses_init();           // 初始化总线
    classes_init();         // 初始化设备类别
    firmware_init();        // sys/firmware 设备树放在这里
    hypervisor_init();      // 初始化虚拟化管理器

    /* 这些也是核心组件，但必须在上述核心组件初始化之后再进行初始化 */
    platform_bus_init();    // 初始化平台总线
    system_bus_init();      // 初始化系统总线
    cpu_dev_init();         // 初始化CPU设备
    memory_dev_init();      // 初始化内存设备
}
