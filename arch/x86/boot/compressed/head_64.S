/*
 *  linux/boot/head.S
 *
 *  Copyright (C) 1991, 1992, 1993  Linus Torvalds
 */

/*
 *  head.S contains the 32-bit startup code.
 *
 * NOTE!!! Startup happens at absolute address 0x00001000, which is also where
 * the page directory will exist. The startup code will be overwritten by
 * the page directory. [According to comments etc elsewhere on a compressed
 * kernel it will end up at 0x1000 + 1Mb I hope so as I assume this. - AC]
 *
 * Page 0 is deliberately kept safe, since System Management Mode code in 
 * laptops may need to access the BIOS data stored there.  This is also
 * useful for future device drivers that either access the BIOS via VM86 
 * mode.
 */

/*
 * High loaded stuff by Hans Lermen & Werner Almesberger, Feb. 1996
 */
	.code32
	.text

#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/pgtable_types.h>
#include <asm/page_types.h>
#include <asm/boot.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>

	__HEAD
	.code32
ENTRY(startup_32)
	cld
	/*
	 * 比较 KEEP_SEGMENTS flag to see if the bootloader is asking
	 * us to not reload segments
	 */
	testb $(1<<6), BP_loadflags(%esi)	# 检查 BP_loadflags 结构体中的第 6 位是否被设置
	jnz 1f								# 如果第 6 位被设置（即标志位不为零），跳转到标签 1

	cli
	movl	$(__KERNEL_DS), %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
1:

/*
 * Calculate the delta between where we were compiled to run
 * at and where we were actually loaded at.  This can only be done
 * with a short local call on x86.  Nothing  else will tell us what
 * address we are running at.  The reserved chunk of the real-mode
 * data at 0x1e4 (defined as a scratch field) are used as the stack
 * for this calculation. Only 4 bytes are needed.
 */
	leal	(BP_scratch+4)(%esi), %esp
	call	1f
1:	popl	%ebp
	subl	$1b, %ebp

/* setup a stack and make sure cpu supports long mode. */
	movl	$boot_stack_end, %eax
	addl	%ebp, %eax
	movl	%eax, %esp

	call	verify_cpu
	testl	%eax, %eax
	jnz	no_longmode

/*
 * Compute the delta between where we were compiled to run at
 * and where the code will actually run at.
 *
 * %ebp contains the address we are loaded at by the boot loader and %ebx
 * contains the address where we should move the kernel image temporarily
 * for safe in-place decompression.
 */

#ifdef CONFIG_RELOCATABLE
	movl	%ebp, %ebx
	movl	BP_kernel_alignment(%esi), %eax
	decl	%eax
	addl	%eax, %ebx
	notl	%eax
	andl	%eax, %ebx
#else
	movl	$LOAD_PHYSICAL_ADDR, %ebx
#endif

	/* Target address to relocate to for decompression */
	addl	$z_extract_offset, %ebx

/*
 * Prepare for entering 64 bit mode
 */

	/* Load new GDT with the 64bit segments using 32bit descriptor */
	leal	gdt(%ebp), %eax
	movl	%eax, gdt+2(%ebp)
	lgdt	gdt(%ebp)

	/* PAE 位使能，启用物理地址扩展模式*/
	movl	$(X86_CR4_PAE), %eax
	movl	%eax, %cr4

 /*
  * Build early 4G boot pagetable构建4GB的的页表
  */
	/* Initialize Page tables to 0 */
	leal	pgtable(%ebx), %edi
	xorl	%eax, %eax
	movl	$((4096*6)/4), %ecx
	rep	stosl

	/* Build Level 4 */
	leal	pgtable + 0(%ebx), %edi
	leal	0x1007 (%edi), %eax
	movl	%eax, 0(%edi)

	/* Build Level 3 */
	leal	pgtable + 0x1000(%ebx), %edi
	leal	0x1007(%edi), %eax
	movl	$4, %ecx
1:	movl	%eax, 0x00(%edi)
	addl	$0x00001000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b

	/* Build Level 2 */
	leal	pgtable + 0x2000(%ebx), %edi
	movl	$0x00000183, %eax
	movl	$2048, %ecx
1:	movl	%eax, 0(%edi)
	addl	$0x00200000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b

	/* Enable the boot page tables */
	leal	pgtable(%ebx), %eax
	movl	%eax, %cr3

	/* Enable Long mode in EFER (Extended Feature Enable Register) */
	movl	$MSR_EFER, %ecx
	rdmsr
	btsl	$_EFER_LME, %eax
	wrmsr

	/*
	 * 跳转到 64 位模式前的设置
	 * When the jump is performend we will be in long mode but
	 * 在 32 位兼容模式下 EFER.LME = 1, CS.L = 0, CS.D = 1
	 * (and in turn EFER.LMA = 1).	要跳转到 64 位模式，我们使用
	 * 新的idt/gdt that has __KERNEL_CS with CS.L = 1.
	 * 我们将所有值放在迷你堆栈上，以便 lret 可以用于执行那个远跳
	 */
	pushl	$__KERNEL_CS 				#将内核代码段选择子(__KERNEL_CS)压入栈中
	leal	startup_64(%ebp), %eax 		#将标号 startup_64 的地址加载到 %eax 寄存器
	pushl	%eax 						#将 %eax 寄存器的值（即 startup_64 的地址）压入栈中

	/* 进入分页保护模式，激活长模式 */
	movl	$(X86_CR0_PG | X86_CR0_PE), %eax /* # 将 CR0 寄存器的值设置为启用分页 (PG) 和保护模式 (PE) */
	movl	%eax, %cr0

	/* 从 32 位兼容模式跳转到 64 位模式 */
	lret
ENDPROC(startup_32)

no_longmode:#错误处理函数
	/* This isn't an x86-64 CPU so hang */
1:
	hlt
	jmp     1b

#include "../../kernel/verify_cpu_64.S"

	/*
	 * Be careful here startup_64 needs to be at a predictable
	 * address so I can export it in an ELF header.  Bootloaders
	 * should look at the ELF header to find this address, as
	 * it may change in the future.
	 */
	.code64
	.org 0x200
ENTRY(startup_64)
	/*
	 * We come here either from startup_32 or directly from a
	 * 64bit bootloader.  If we come here from a bootloader we depend on
	 * an identity mapped page table being provied that maps our
	 * entire text+data+bss and hopefully all of memory.
	 */

	/* Setup data segments. */
	xorl	%eax, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %fs
	movl	%eax, %gs
	lldt	%ax
	movl    $0x20, %eax
	ltr	%ax

	/*
	 * Compute the decompressed kernel start address.  It is where
	 * we were loaded at aligned to a 2M boundary. %rbp contains the
	 * decompressed kernel start address.
	 *
	 * If it is a relocatable kernel then decompress and run the kernel
	 * from load address aligned to 2MB addr, otherwise decompress and
	 * run the kernel from LOAD_PHYSICAL_ADDR
	 *
	 * We cannot rely on the calculation done in 32-bit mode, since we
	 * may have been invoked via the 64-bit entry point.
	 */

	/* Start with the delta to where the kernel will run at. */
#ifdef CONFIG_RELOCATABLE
	leaq	startup_32(%rip) /* - $startup_32 */, %rbp
	movl	BP_kernel_alignment(%rsi), %eax
	decl	%eax
	addq	%rax, %rbp
	notq	%rax
	andq	%rax, %rbp
#else
	movq	$LOAD_PHYSICAL_ADDR, %rbp
#endif

	/* Target address to relocate to for decompression */
	leaq	z_extract_offset(%rbp), %rbx

	/* Set up the stack */
	leaq	boot_stack_end(%rbx), %rsp

	/* Zero EFLAGS */
	pushq	$0
	popfq

/*
 * Copy the compressed kernel to the end of our buffer
 * where decompression in place becomes safe.
 */
	pushq	%rsi
	leaq	(_bss-8)(%rip), %rsi
	leaq	(_bss-8)(%rbx), %rdi
	movq	$_bss /* - $startup_32 */, %rcx
	shrq	$3, %rcx
	std
	rep	movsq
	cld
	popq	%rsi

/*
 * Jump to the relocated address.
 */
	leaq	relocated(%rbx), %rax
	jmp	*%rax

	.text
relocated:

/*
 * Clear BSS (stack is currently empty)
 */
	xorl	%eax, %eax
	leaq    _bss(%rip), %rdi
	leaq    _ebss(%rip), %rcx
	subq	%rdi, %rcx
	shrq	$3, %rcx
	rep	stosq

/*
 * Do the decompression, and jump to the new kernel..
 * 解压内核映像,并跳转到内核执行
 */
	pushq	%rsi			/* Save the real mode argument */
	movq	%rsi, %rdi		/* real mode address */
	leaq	boot_heap(%rip), %rsi	/* malloc area for uncompression */
	leaq	input_data(%rip), %rdx  /* input_data */
	movl	$z_input_len, %ecx	/* input_len */
	movq	%rbp, %r8		/* output target address */
	call	decompress_kernel
	popq	%rsi

/*
 * Jump to the decompressed kernel.
 */
	jmp	*%rbp

	.data
gdt:
	.word	gdt_end - gdt
	.long	gdt
	.word	0
	.quad	0x0000000000000000	/* NULL descriptor */
	.quad	0x00af9a000000ffff	/* __KERNEL_CS */
	.quad	0x00cf92000000ffff	/* __KERNEL_DS */
	.quad	0x0080890000000000	/* TS descriptor */
	.quad   0x0000000000000000	/* TS continued */
gdt_end:

/*
 * Stack and heap for uncompression
 */
	.bss
	.balign 4
boot_heap:
	.fill BOOT_HEAP_SIZE, 1, 0
boot_stack:
	.fill BOOT_STACK_SIZE, 1, 0
boot_stack_end:

/*
 * Space for page tables (not in .bss so not zeroed)
 */
	.section ".pgtable","a",@nobits
	.balign 4096
pgtable:
	.fill 6*4096, 1, 0
