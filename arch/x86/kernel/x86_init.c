/*
 * Copyright (C) 2009 Thomas Gleixner <tglx@linutronix.de>
 *
 *  For licencing details see kernel-base/COPYING
 */
#include <linux/init.h>
#include <linux/ioport.h>

#include <asm/bios_ebda.h>
#include <asm/paravirt.h>
#include <asm/pci_x86.h>
#include <asm/mpspec.h>
#include <asm/setup.h>
#include <asm/apic.h>
#include <asm/e820.h>
#include <asm/time.h>
#include <asm/irq.h>
#include <asm/pat.h>
#include <asm/tsc.h>
#include <asm/iommu.h>

void __cpuinit x86_init_noop(void) { }
void __init x86_init_uint_noop(unsigned int unused) { }
void __init x86_init_pgd_noop(pgd_t *unused) { }
int __init iommu_init_noop(void) { return 0; }
void iommu_shutdown_noop(void) { }

/*
 * The platform setup functions are preset with the default functions
 * for standard PC hardware.
 */
struct x86_init_ops x86_init __initdata = {

	.resources = {
		.probe_roms		= x86_init_noop,  // 处理 ROM 的探测操作，这里指定为一个无操作的函数
		.reserve_resources	= reserve_standard_io_resources,  // 保留标准 I/O 资源
		.memory_setup		= default_machine_specific_memory_setup,  // 设置特定于机器的内存配置
	},

	.mpparse = {
		.mpc_record		= x86_init_uint_noop,  // MPC 记录解析，这里指定为一个无操作的函数
		.setup_ioapic_ids	= x86_init_noop,  // 设置 IOAPIC IDs，这里指定为一个无操作的函数
		.mpc_apic_id		= default_mpc_apic_id,  // 获取 MPC APIC ID
		.smp_read_mpc_oem	= default_smp_read_mpc_oem,  // 读取 SMP 的 MPC OEM 信息
		.mpc_oem_bus_info	= default_mpc_oem_bus_info,  // 获取 MPC OEM 总线信息
		.find_smp_config	= default_find_smp_config,  // 查找 SMP 配置
		.get_smp_config		= default_get_smp_config,  // 获取 SMP 配置
	},

	.irqs = {
		.pre_vector_init	= init_ISA_irqs,  // 初始化 ISA 中断向量
		.intr_init		= native_init_IRQ,  // 初始化本地中断
		.trap_init		= x86_init_noop,  // 初始化陷阱处理，这里指定为一个无操作的函数
	},

	.oem = {
		.arch_setup		= x86_init_noop,  // 架构特定的初始化设置，这里指定为一个无操作的函数
		.banner			= default_banner,  // 打印启动横幅
	},

	.paging = {
		.pagetable_setup_start	= native_pagetable_setup_start,  // 设置页表的开始阶段
		.pagetable_setup_done	= native_pagetable_setup_done,  // 设置页表的完成阶段
	},

	.timers = {
		.setup_percpu_clockev	= setup_boot_APIC_clock,  // 设置每个 CPU 的 APIC 时钟
		.tsc_pre_init		= x86_init_noop,  // 处理 TSC（时间戳计数器）的预初始化，这里指定为一个无操作的函数
		.timer_init		= hpet_time_init,  // 初始化 HPET（高精度事件定时器）
	},

	.iommu = {
		.iommu_init		= iommu_init_noop,  // IOMMU 的初始化，这里指定为一个无操作的函数
	},

	.pci = {
		.init			= x86_default_pci_init,  // PCI 总线的默认初始化
		.init_irq		= x86_default_pci_init_irq,  // PCI 中断的默认初始化
		.fixup_irqs		= x86_default_pci_fixup_irqs,  // 修复 PCI 中断问题的默认函数
	},
};


struct x86_cpuinit_ops x86_cpuinit __cpuinitdata = {
	.setup_percpu_clockev		= setup_secondary_APIC_clock,
};

static void default_nmi_init(void) { };

struct x86_platform_ops x86_platform = {
	.calibrate_tsc			= native_calibrate_tsc,
	.get_wallclock			= mach_get_cmos_time,
	.set_wallclock			= mach_set_rtc_mmss,
	.iommu_shutdown			= iommu_shutdown_noop,
	.is_untracked_pat_range		= is_ISA_range,
	.nmi_init			= default_nmi_init
};
