/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *   Copyright 2009 Intel Corporation; author H. Peter Anvin
 *
 *   This file is part of the Linux kernel, and is made available under
 *   the terms of the GNU General Public License version 2.
 *
 * ----------------------------------------------------------------------- */

/*
 * Main module for the real-mode kernel code
 */

#include "boot.h"

struct boot_params boot_params __attribute__((aligned(16)));

char *HEAP = _end;
char *heap_end = _end;		/* Default end of heap = no heap */

/*
 * Copy the header into the boot parameter block.  Since this
 * screws up the old-style command line protocol, adjust by
 * filling in the new-style command line pointer instead.
 */

static void copy_boot_params(void)
{
	struct old_cmdline {
		u16 cl_magic;
		u16 cl_offset;
	};
	const struct old_cmdline * const oldcmd =
		(const struct old_cmdline *)OLD_CL_ADDRESS;

	BUILD_BUG_ON(sizeof boot_params != 4096);
	memcpy(&boot_params.hdr, &hdr, sizeof hdr);

	if (!boot_params.hdr.cmd_line_ptr &&
	    oldcmd->cl_magic == OLD_CL_MAGIC) {
		/* Old-style command line protocol. */
		u16 cmdline_seg;

		/* Figure out if the command line falls in the region
		   of memory that an old kernel would have copied up
		   to 0x90000... */
		if (oldcmd->cl_offset < boot_params.hdr.setup_move_size)
			cmdline_seg = ds();
		else
			cmdline_seg = 0x9000;

		boot_params.hdr.cmd_line_ptr =
			(cmdline_seg << 4) + oldcmd->cl_offset;
	}
}

/*
 * Set the keyboard repeat rate to maximum.  Unclear why this
 * is done here; this might be possible to kill off as stale code.
 */
static void keyboard_set_repeat(void)
{
	struct biosregs ireg;
	initregs(&ireg);
	ireg.ax = 0x0305;
	intcall(0x16, &ireg, NULL);
}

/*
 * Get Intel SpeedStep (IST) information.
 */
static void query_ist(void)
{
	struct biosregs ireg, oreg;

	/* Some older BIOSes apparently crash on this call, so filter
	   it from machines too old to have SpeedStep at all. */
	if (cpu.level < 6)
		return;

	initregs(&ireg);
	ireg.ax  = 0xe980;	 /* IST Support */
	ireg.edx = 0x47534943;	 /* Request value */
	intcall(0x15, &ireg, &oreg);

	boot_params.ist_info.signature  = oreg.eax;
	boot_params.ist_info.command    = oreg.ebx;
	boot_params.ist_info.event      = oreg.ecx;
	boot_params.ist_info.perf_level = oreg.edx;
}

/*
 * Tell the BIOS what CPU mode we intend to run in.
 */
static void set_bios_mode(void)
{
#ifdef CONFIG_X86_64
	struct biosregs ireg;

	initregs(&ireg);
	ireg.ax = 0xec00;
	ireg.bx = 2;
	intcall(0x15, &ireg, NULL);
#endif
}

static void init_heap(void)
{
	char *stack_end;

	if (boot_params.hdr.loadflags & CAN_USE_HEAP) {
		asm("leal %P1(%%esp),%0"
		    : "=r" (stack_end) : "i" (-STACK_SIZE));

		heap_end = (char *)
			((size_t)boot_params.hdr.heap_end_ptr + 0x200);
		if (heap_end > stack_end)
			heap_end = stack_end;
	} else {
		/* Boot protocol 2.00 only, no heap available */
		puts("WARNING: Ancient bootloader, some functionality "
		     "may be limited!\n");
	}
}

void main(void)
{
	/* First, copy the boot header into the "zeropage" 复制引导头到“zeropage”，以准备启动参数和内存布局信息*/
	copy_boot_params();

	/* End of heap check 初始化堆内存，确保有足够的堆空间用于运行时数据分配。*/
	init_heap();

	/* 验证 CPU 是否符合当前内核要求。如果不符合，显示错误信息并终止启动过程 */
	if (validate_cpu()) {
		puts("Unable to boot - please use a kernel appropriate "
		     "for your CPU.\n");
		die();
	}

	/* Tell the BIOS what CPU mode we intend to run in. 设置 BIOS，以告知系统将要使用的 CPU 模式（如保护模式)*/
	set_bios_mode();

	/* Detect memory layout 检测系统的内存布局，获取内存的详细信息，如总内存大小、内存块等*/
	detect_memory();

	/* Set keyboard repeat rate (why?)设置键盘重复速率，可能是为了在后续的操作中确保键盘输入的正确性。 */
	keyboard_set_repeat();

	/* Query MCA information */
	query_mca();
	// 查询 MCA（Machine Check Architecture）信息，用于检测和报告硬件错误。

	/* Query Intel SpeedStep (IST) information */
	query_ist();
	// 查询 Intel SpeedStep 信息，用于处理 CPU 频率和电源管理。

	/* Query APM information */
#if defined(CONFIG_APM) || defined(CONFIG_APM_MODULE)
	query_apm_bios();
#endif
	// 如果配置了 APM（Advanced Power Management），查询 APM BIOS 信息。

	/* Query EDD information */
#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)
	query_edd();
#endif
	// 如果配置了 EDD（Enhanced Disk Drive），查询 EDD 信息。

	/* Set the video mode */
	set_video();
	// 设置视频模式，以确保显示器正确显示信息。

	/* Parse command line for 'quiet' and pass it to decompressor. */
	if (cmdline_find_option_bool("quiet"))
		boot_params.hdr.loadflags |= QUIET_FLAG;
	// 解析命令行参数，检查是否有“quiet”选项。如果有，将“quiet”标志设置到启动参数中，禁用启动时的详细信息显示。

	/* Do the last things and invoke protected mode */
	go_to_protected_mode();
	// 完成最后的初始化操作，并切换到保护模式，开始执行操作系统的核心代码。
}

