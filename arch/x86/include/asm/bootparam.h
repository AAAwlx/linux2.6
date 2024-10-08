#ifndef _ASM_X86_BOOTPARAM_H
#define _ASM_X86_BOOTPARAM_H

#include <linux/types.h>
#include <linux/screen_info.h>
#include <linux/apm_bios.h>
#include <linux/edd.h>
#include <asm/e820.h>
#include <asm/ist.h>
#include <video/edid.h>

/* setup data types */
#define SETUP_NONE			0
#define SETUP_E820_EXT			1

/* extensible setup data list node */
struct setup_data {
    __u64 next;   // 下一个 setup_data 结构的物理地址
    __u32 type;   // 数据类型，标识 data 字段中的数据类型
    __u32 len;    // 数据的长度，单位为字节
    __u8  data[0];// 数据本身的开始位置（柔性数组成员）
};


struct setup_header {
	__u8	setup_sects;
	__u16	root_flags;
	__u32	syssize;
	__u16	ram_size;
#define RAMDISK_IMAGE_START_MASK	0x07FF
#define RAMDISK_PROMPT_FLAG		0x8000
#define RAMDISK_LOAD_FLAG		0x4000
	__u16	vid_mode;
	__u16	root_dev;
	__u16	boot_flag;
	__u16	jump;
	__u32	header;
	__u16	version;
	__u32	realmode_swtch;
	__u16	start_sys;
	__u16	kernel_version;
	__u8	type_of_loader;
	__u8	loadflags;
#define LOADED_HIGH	(1<<0)
#define QUIET_FLAG	(1<<5)
#define KEEP_SEGMENTS	(1<<6)
#define CAN_USE_HEAP	(1<<7)
	__u16	setup_move_size;
	__u32	code32_start;
	__u32	ramdisk_image;
	__u32	ramdisk_size;
	__u32	bootsect_kludge;
	__u16	heap_end_ptr;
	__u8	ext_loader_ver;
	__u8	ext_loader_type;
	__u32	cmd_line_ptr;
	__u32	initrd_addr_max;
	__u32	kernel_alignment;
	__u8	relocatable_kernel;
	__u8	_pad2[3];
	__u32	cmdline_size;
	__u32	hardware_subarch;
	__u64	hardware_subarch_data;
	__u32	payload_offset;
	__u32	payload_length;
	__u64	setup_data;
} __attribute__((packed));

struct sys_desc_table {
	__u16 length;
	__u8  table[14];
};

struct efi_info {
	__u32 efi_loader_signature;
	__u32 efi_systab;
	__u32 efi_memdesc_size;
	__u32 efi_memdesc_version;
	__u32 efi_memmap;
	__u32 efi_memmap_size;
	__u32 efi_systab_hi;
	__u32 efi_memmap_hi;
};

/* The so-called "zeropage" */
/*该结构体用于保存启动时传递给内核的参数信息*/
struct boot_params {
	struct screen_info screen_info;			/* 0x000 */
	// 屏幕信息结构体，包含显示模式和分辨率等信息。

	struct apm_bios_info apm_bios_info;		/* 0x040 */
	// APM (Advanced Power Management) BIOS 信息结构体，用于电源管理。

	__u8  _pad2[4];					/* 0x054 */
	// 填充字节，用于对齐结构体字段，确保后续字段按适当的对齐方式排列。

	__u64  tboot_addr;				/* 0x058 */
	// 传递给内核的 tboot 地址，通常用于多引导系统的启动参数。

	struct ist_info ist_info;			/* 0x060 */
	// IST (Interrupt Stack Table) 信息结构体，涉及中断栈的配置。

	__u8  _pad3[16];				/* 0x070 */
	// 填充字节，用于对齐结构体字段。

	__u8  hd0_info[16];	/* obsolete! */		/* 0x080 */
	// 过时的硬盘0信息，现已不再使用。

	__u8  hd1_info[16];	/* obsolete! */		/* 0x090 */
	// 过时的硬盘1信息，现已不再使用。

	struct sys_desc_table sys_desc_table;		/* 0x0a0 */
	// 系统描述符表结构体，包含系统硬件描述信息。

	__u8  _pad4[144];				/* 0x0b0 */
	// 填充字节，用于对齐结构体字段。

	struct edid_info edid_info;			/* 0x140 */
	// EDID (Extended Display Identification Data) 信息结构体，包含显示设备的相关信息。

	struct efi_info efi_info;			/* 0x1c0 */
	// EFI (Extensible Firmware Interface) 信息结构体，包含 EFI 相关的信息。

	__u32 alt_mem_k;				/* 0x1e0 */
	// 备用内存信息，以KB为单位。

	__u32 scratch;		/* Scratch field! */	/* 0x1e4 */
	// 临时字段，可用于传递其他信息或调试用途。

	__u8  e820_entries;				/* 0x1e8 */
	// e820 内存映射条目的数量，描述了系统内存的布局。

	__u8  eddbuf_entries;				/* 0x1e9 */
	// EDD (Enhanced Disk Drive) 缓冲区条目的数量，用于描述磁盘驱动器信息。

	__u8  edd_mbr_sig_buf_entries;			/* 0x1ea */
	// EDD MBR (Master Boot Record) 签名缓冲区条目的数量。

	__u8  _pad6[6];					/* 0x1eb */
	// 填充字节，用于对齐结构体字段。

	struct setup_header hdr;    /* setup header */	/* 0x1f1 */
	// 设置头部结构体，包含启动过程的基本配置信息。

	__u8  _pad7[0x290-0x1f1-sizeof(struct setup_header)];
	// 填充字节，用于对齐结构体字段。

	__u32 edd_mbr_sig_buffer[EDD_MBR_SIG_MAX];	/* 0x290 */
	// EDD MBR 签名缓冲区，用于存储 MBR 的签名信息。

	struct e820entry e820_map[E820MAX];		/* 0x2d0 */
	// e820 内存映射表，用于描述系统内存的布局和类型。

	__u8  _pad8[48];				/* 0xcd0 */
	// 填充字节，用于对齐结构体字段。

	struct edd_info eddbuf[EDDMAXNR];		/* 0xd00 */
	// EDD 缓冲区，用于存储磁盘驱动器信息。

	__u8  _pad9[276];				/* 0xeec */
	// 填充字节，用于对齐结构体字段。
} __attribute__((packed));


enum {
	X86_SUBARCH_PC = 0,
	X86_SUBARCH_LGUEST,
	X86_SUBARCH_XEN,
	X86_SUBARCH_MRST,
	X86_NR_SUBARCHS,
};



#endif /* _ASM_X86_BOOTPARAM_H */
