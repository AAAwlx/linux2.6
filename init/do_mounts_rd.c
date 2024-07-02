
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/minix_fs.h>
#include <linux/ext2_fs.h>
#include <linux/romfs_fs.h>
#include <linux/cramfs_fs.h>
#include <linux/initrd.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "do_mounts.h"
#include "../fs/squashfs/squashfs_fs.h"

#include <linux/decompress/generic.h>


int __initdata rd_prompt = 1;/* 1 = prompt for RAM disk, 0 = don't prompt */

static int __init prompt_ramdisk(char *str)
{
	rd_prompt = simple_strtol(str,NULL,0) & 1;
	return 1;
}
__setup("prompt_ramdisk=", prompt_ramdisk);

int __initdata rd_image_start;		/* starting block # of image */

static int __init ramdisk_start_setup(char *str)
{
	rd_image_start = simple_strtol(str,NULL,0);
	return 1;
}
__setup("ramdisk_start=", ramdisk_start_setup);

static int __init crd_load(int in_fd, int out_fd, decompress_fn deco);

/*
 * This routine tries to find a RAM disk image to load, and returns the
 * number of blocks to read for a non-compressed image, 0 if the image
 * is a compressed image, and -1 if an image with the right magic
 * numbers could not be found.
 *
 * We currently check for the following magic numbers:
 *	minix
 *	ext2
 *	romfs
 *	cramfs
 *	squashfs
 *	gzip
 */
/**
 * identify_ramdisk_image - 识别 RAM 磁盘镜像的文件系统类型和相关信息
 * @fd: 文件描述符，指向 RAM 磁盘镜像的文件
 * @start_block: RAM 磁盘镜像在文件中的起始块号
 * @decompressor: 输出参数，指向解压缩函数的指针，根据需要更新为发现的解压缩函数
 *
 * 从指定文件的给定块开始读取数据，尝试识别 RAM 磁盘镜像的文件系统类型。
 * 支持的文件系统类型包括 gzip、romfs、cramfs、squashfs、minix 和 ext2。
 * 如果识别成功，打印相应的信息并返回 RAM 磁盘的块数。
 * 如果未找到有效的 RAM 磁盘镜像，打印相应的错误信息并返回 -1。
 *
 * 返回值:
 *  - 如果识别成功，返回 RAM 磁盘的块数；
 *  - 如果未找到有效的 RAM 磁盘镜像，返回 -1。
 */
static int __init
identify_ramdisk_image(int fd, int start_block, decompress_fn *decompressor)
{
	const int size = 512;
	struct minix_super_block *minixsb;
	struct ext2_super_block *ext2sb;
	struct romfs_super_block *romfsb;
	struct cramfs_super *cramfsb;
	struct squashfs_super_block *squashfsb;
	int nblocks = -1;
	unsigned char *buf;
	const char *compress_name;

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -1;

	// 将不同类型的文件系统结构体指针指向同一个缓冲区
	minixsb = (struct minix_super_block *) buf;
	ext2sb = (struct ext2_super_block *) buf;
	romfsb = (struct romfs_super_block *) buf;
	cramfsb = (struct cramfs_super *) buf;
	squashfsb = (struct squashfs_super_block *) buf;

	// 初始化缓冲区，填充为特定的值
	memset(buf, 0xe5, size);

	/*
	 * 读取块 0，用于测试是否为压缩内核
	 */
	sys_lseek(fd, start_block * BLOCK_SIZE, 0);
	sys_read(fd, buf, size);

	// 尝试根据读取的数据判断是否为压缩格式，并获取解压缩函数指针
	*decompressor = decompress_method(buf, size, &compress_name);
	if (compress_name) {
		printk(KERN_NOTICE "RAMDISK: %s image found at block %d\n",
		       compress_name, start_block);
		if (!*decompressor)
			printk(KERN_EMERG
			       "RAMDISK: %s decompressor not configured!\n",
			       compress_name);
		nblocks = 0;
		goto done;
	}

	// 判断是否为 romfs 文件系统
	if (romfsb->word0 == ROMSB_WORD0 &&
	    romfsb->word1 == ROMSB_WORD1) {
		printk(KERN_NOTICE
		       "RAMDISK: romfs filesystem found at block %d\n",
		       start_block);
		nblocks = (ntohl(romfsb->size)+BLOCK_SIZE-1)>>BLOCK_SIZE_BITS;
		goto done;
	}

	// 判断是否为 cramfs 文件系统
	if (cramfsb->magic == CRAMFS_MAGIC) {
		printk(KERN_NOTICE
		       "RAMDISK: cramfs filesystem found at block %d\n",
		       start_block);
		nblocks = (cramfsb->size + BLOCK_SIZE - 1) >> BLOCK_SIZE_BITS;
		goto done;
	}

	// 判断是否为 squashfs 文件系统
	if (le32_to_cpu(squashfsb->s_magic) == SQUASHFS_MAGIC) {
		printk(KERN_NOTICE
		       "RAMDISK: squashfs filesystem found at block %d\n",
		       start_block);
		nblocks = (le64_to_cpu(squashfsb->bytes_used) + BLOCK_SIZE - 1)
			 >> BLOCK_SIZE_BITS;
		goto done;
	}

	/*
	 * 读取块 1，尝试判断是否为 minix 或 ext2 超级块
	 */
	sys_lseek(fd, (start_block+1) * BLOCK_SIZE, 0);
	sys_read(fd, buf, size);

	// 尝试判断是否为 minix 文件系统
	if (minixsb->s_magic == MINIX_SUPER_MAGIC ||
	    minixsb->s_magic == MINIX_SUPER_MAGIC2) {
		printk(KERN_NOTICE
		       "RAMDISK: Minix filesystem found at block %d\n",
		       start_block);
		nblocks = minixsb->s_nzones << minixsb->s_log_zone_size;
		goto done;
	}

	// 尝试判断是否为 ext2 文件系统
	if (ext2sb->s_magic == cpu_to_le16(EXT2_SUPER_MAGIC)) {
		printk(KERN_NOTICE
		       "RAMDISK: ext2 filesystem found at block %d\n",
		       start_block);
		nblocks = le32_to_cpu(ext2sb->s_blocks_count) <<
			le32_to_cpu(ext2sb->s_log_block_size);
		goto done;
	}

	// 如果未找到有效的 RAM 磁盘镜像，打印相应的错误信息
	printk(KERN_NOTICE
	       "RAMDISK: Couldn't find valid RAM disk image starting at %d.\n",
	       start_block);

done:
	// 重新设置文件指针，释放缓冲区内存，返回识别结果
	sys_lseek(fd, start_block * BLOCK_SIZE, 0);
	kfree(buf);
	return nblocks;
}

/**
 * rd_load_image - 加载初始化RAM磁盘（initrd）映像到RAM磁盘设备
 * @from: 要加载的initrd映像文件路径
 *
 * 尝试从指定路径加载initrd映像到/dev/ram设备。
 * 如果成功加载，将数据复制到RAM磁盘设备中，并根据需要更改软盘（如果是多个磁盘加载）。
 *
 * 返回值:
 *  - 1: 成功加载并复制了initrd映像
 *  - 0: 加载或复制失败
 */
int __init rd_load_image(char *from)
{
    int res = 0;
    int in_fd, out_fd;
    unsigned long rd_blocks, devblocks;
    int nblocks, i, disk;
    char *buf = NULL;
    unsigned short rotate = 0;
    decompress_fn decompressor = NULL;
#if !defined(CONFIG_S390) && !defined(CONFIG_PPC_ISERIES)
    char rotator[4] = { '|' , '/' , '-' , '\\' };
#endif

    out_fd = sys_open("/dev/ram", O_RDWR, 0);  // 打开/dev/ram设备，准备写入操作
    if (out_fd < 0)
        goto out;  // 打开失败，跳转到out标签处理

    in_fd = sys_open(from, O_RDONLY, 0);  // 打开initrd映像文件，准备读取操作
    if (in_fd < 0)
        goto noclose_input;  // 打开失败，跳转到noclose_input标签处理未关闭输入文件描述符

    nblocks = identify_ramdisk_image(in_fd, rd_image_start, &decompressor);  // 识别RAM磁盘映像的块数或大小
    if (nblocks < 0)
        goto done;  // 识别失败，跳转到done标签处理

    if (nblocks == 0) {
        if (crd_load(in_fd, out_fd, decompressor) == 0)  // 如果nblocks为0，则尝试使用crd_load加载数据
            goto successful_load;
        goto done;  // 加载失败，跳转到done标签处理
    }

    /*
     * 注意: nblocks 实际上不是块数，而是要加载到ramdisk的数据量（以KiB为单位）。
     * 因此，任何块大小是1KiB的RAM磁盘块大小应该可以正常工作，
     * 当命令行上指定适当的ramdisk_blocksize时。
     *
     * 默认的ramdisk_blocksize是1KiB，通常使用其他块大小是愚蠢的，
     * 因此请确保在生成ext2fs ramdisk-images时使用1KiB块大小。
     */
    if (sys_ioctl(out_fd, BLKGETSIZE, (unsigned long)&rd_blocks) < 0)
        rd_blocks = 0;
    else
        rd_blocks >>= 1;

    if (nblocks > rd_blocks) {
        printk("RAMDISK: image too big! (%dKiB/%ldKiB)\n",
               nblocks, rd_blocks);
        goto done;  // 映像过大，跳转到done标签处理
    }

    /*
     * 开始复制数据
     */
    if (sys_ioctl(in_fd, BLKGETSIZE, (unsigned long)&devblocks) < 0)
        devblocks = 0;
    else
        devblocks >>= 1;

    if (strcmp(from, "/initrd.image") == 0)
        devblocks = nblocks;

    if (devblocks == 0) {
        printk(KERN_ERR "RAMDISK: could not determine device size\n");
        goto done;  // 无法确定设备大小，跳转到done标签处理
    }

    buf = kmalloc(BLOCK_SIZE, GFP_KERNEL);  // 分配内存缓冲区
    if (!buf) {
        printk(KERN_ERR "RAMDISK: could not allocate buffer\n");
        goto done;  // 分配内存失败，跳转到done标签处理
    }

    printk(KERN_NOTICE "RAMDISK: Loading %dKiB [%ld disk%s] into ram disk... ",
           nblocks, ((nblocks-1)/devblocks)+1, nblocks>devblocks ? "s" : "");
    for (i = 0, disk = 1; i < nblocks; i++) {
        if (i && (i % devblocks == 0)) {
            printk("done disk #%d.\n", disk++);
            rotate = 0;
            if (sys_close(in_fd)) {
                printk("Error closing the disk.\n");
                goto noclose_input;
            }
            change_floppy("disk #%d", disk);  // 更改软盘设备
            in_fd = sys_open(from, O_RDONLY, 0);  // 重新打开软盘设备
            if (in_fd < 0)  {
                printk("Error opening disk.\n");
                goto noclose_input;
            }
            printk("Loading disk #%d... ", disk);
        }
        sys_read(in_fd, buf, BLOCK_SIZE);  // 从输入文件读取数据
        sys_write(out_fd, buf, BLOCK_SIZE);  // 将数据写入输出设备
#if !defined(CONFIG_S390) && !defined(CONFIG_PPC_ISERIES)
        if (!(i % 16)) {
            printk("%c\b", rotator[rotate & 0x3]);  // 打印加载进度
            rotate++;
        }
#endif
    }
    printk("done.\n");

successful_load:
    res = 1;  // 设置成功加载标志
done:
    sys_close(in_fd);  // 关闭输入文件描述符
noclose_input:
    sys_close(out_fd);  // 关闭输出文件描述符
out:
    kfree(buf);  // 释放内存缓冲区
    sys_unlink("/dev/ram");  // 删除/dev/ram设备节点
    return res;  // 返回加载结果标志
}


int __init rd_load_disk(int n)
{
	if (rd_prompt)
		change_floppy("root floppy disk to be loaded into RAM disk");
	create_dev("/dev/root", ROOT_DEV);
	create_dev("/dev/ram", MKDEV(RAMDISK_MAJOR, n));
	return rd_load_image("/dev/root");
}

static int exit_code;
static int decompress_error;
static int crd_infd, crd_outfd;

static int __init compr_fill(void *buf, unsigned int len)
{
	int r = sys_read(crd_infd, buf, len);
	if (r < 0)
		printk(KERN_ERR "RAMDISK: error while reading compressed data");
	else if (r == 0)
		printk(KERN_ERR "RAMDISK: EOF while reading compressed data");
	return r;
}

static int __init compr_flush(void *window, unsigned int outcnt)
{
	int written = sys_write(crd_outfd, window, outcnt);
	if (written != outcnt) {
		if (decompress_error == 0)
			printk(KERN_ERR
			       "RAMDISK: incomplete write (%d != %d)\n",
			       written, outcnt);
		decompress_error = 1;
		return -1;
	}
	return outcnt;
}

static void __init error(char *x)
{
	printk(KERN_ERR "%s\n", x);
	exit_code = 1;
	decompress_error = 1;
}

static int __init crd_load(int in_fd, int out_fd, decompress_fn deco)
{
	int result;
	crd_infd = in_fd;
	crd_outfd = out_fd;
	result = deco(NULL, 0, compr_fill, compr_flush, NULL, NULL, error);
	if (decompress_error)
		result = 1;
	return result;
}
