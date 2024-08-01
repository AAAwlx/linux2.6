/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 *   This file is part of the Linux kernel, and is made available under
 *   the terms of the GNU General Public License version 2.
 *
 * ----------------------------------------------------------------------- */

/*
 * Prepare the machine for transition to protected mode.
 */

#include "boot.h"
#include <asm/segment.h>

/*
 * Invoke the realmode switch hook if present; otherwise
 * disable all interrupts.
 */
static void realmode_switch_hook(void)
{
	if (boot_params.hdr.realmode_swtch) {
		asm volatile("lcallw *%0"
			     : : "m" (boot_params.hdr.realmode_swtch)
			     : "eax", "ebx", "ecx", "edx");
	} else {
		asm volatile("cli");
		outb(0x80, 0x70); /* Disable NMI */
		io_delay();
	}
}

/*
 * Disable all interrupts at the legacy PIC.
 */
static void mask_all_interrupts(void)
{
	outb(0xff, 0xa1);	/* Mask all interrupts on the secondary PIC */
	io_delay();
	outb(0xfb, 0x21);	/* Mask all but cascade on the primary PIC */
	io_delay();
}

/*
 * Reset IGNNE# if asserted in the FPU.
 */
static void reset_coprocessor(void)
{
	outb(0, 0xf0);
	io_delay();
	outb(0, 0xf1);
	io_delay();
}

/*
 * Set up the GDT
 */

struct gdt_ptr {
	u16 len;
	u32 ptr;
} __attribute__((packed));

static void setup_gdt(void)
{
	/* There are machines which are known to not boot with the GDT
	   being 8-byte unaligned.  Intel recommends 16 byte alignment. */
	static const u64 boot_gdt[] __attribute__((aligned(16))) = {
		/* CS: code, read/execute, 4 GB, base 0 */
		[GDT_ENTRY_BOOT_CS] = GDT_ENTRY(0xc09b, 0, 0xfffff),
		/* DS: data, read/write, 4 GB, base 0 */
		[GDT_ENTRY_BOOT_DS] = GDT_ENTRY(0xc093, 0, 0xfffff),
		/* TSS: 32-bit tss, 104 bytes, base 4096 */
		/* We only have a TSS here to keep Intel VT happy;
		   we don't actually use it for anything. */
		[GDT_ENTRY_BOOT_TSS] = GDT_ENTRY(0x0089, 4096, 103),
	};
	/* Xen HVM incorrectly stores a pointer to the gdt_ptr, instead
	   of the gdt_ptr contents.  Thus, make it static so it will
	   stay in memory, at least long enough that we switch to the
	   proper kernel GDT. */
	static struct gdt_ptr gdt;

	gdt.len = sizeof(boot_gdt)-1;
	gdt.ptr = (u32)&boot_gdt + (ds() << 4);

	asm volatile("lgdtl %0" : : "m" (gdt));
}

/*
 * Set up the IDT
 */
static void setup_idt(void)
{
	static const struct gdt_ptr null_idt = {0, 0};
	asm volatile("lidtl %0" : : "m" (null_idt));
}

/*
 * Actual invocation sequence
 */
void go_to_protected_mode(void)
{
	/* Hook before leaving real mode, also disables interrupts */
	realmode_switch_hook();
	// 在离开实模式之前执行的钩子函数，同时禁用中断。该函数可能用于进行一些必要的清理或准备工作。

	/* Enable the A20 gate */
	if (enable_a20()) {
		puts("A20 gate not responding, unable to boot...\n");
		die();
	}
	// 启用 A20 门。A20 门用于允许访问 1MB 以上的内存地址。如果启用失败，输出错误信息并终止启动过程。

	/* Reset coprocessor (IGNNE#) */
	reset_coprocessor();
	// 重置协处理器（如 FPU）。协处理器可能会在进入保护模式之前需要重置，以确保没有残留状态影响操作。

	/* Mask all interrupts in the PIC */
	mask_all_interrupts();
	// 遮蔽所有中断请求。在进入保护模式之前，禁用所有中断请求，以防在模式转换过程中出现中断问题。

	/* Actual transition to protected mode... */
	setup_idt();
	// 设置中断描述符表（IDT）。IDT 用于定义中断处理程序的地址，在保护模式下，系统需要正确设置 IDT 以处理中断。

	setup_gdt();
	// 设置全局描述符表（GDT）。GDT 用于定义内存段的基地址、大小和属性，是进入保护模式的关键步骤。

	protected_mode_jump(boot_params.hdr.code32_start,
			    (u32)&boot_params + (ds() << 4));
	// 执行实际的模式转换跳转到保护模式。`protected_mode_jump` 函数会跳转到保护模式的入口点，并传递必要的参数，如启动代码的地址和启动参数的位置。
}
