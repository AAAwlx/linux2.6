#include <linux/module.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#include <linux/fd.h>
#include <linux/tty.h>
#include <linux/suspend.h>
#include <linux/root_dev.h>
#include <linux/security.h>
#include <linux/delay.h>
#include <linux/genhd.h>
#include <linux/mount.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/initrd.h>
#include <linux/async.h>
#include <linux/fs_struct.h>
#include <linux/slab.h>

#include <linux/nfs_fs.h>
#include <linux/nfs_fs_sb.h>
#include <linux/nfs_mount.h>

#include "do_mounts.h"

int __initdata rd_doload;	/* 1 = load RAM disk, 0 = don't load */

int root_mountflags = MS_RDONLY | MS_SILENT;
static char * __initdata root_device_name;
static char __initdata saved_root_name[64];
static int __initdata root_wait;

dev_t ROOT_DEV;

static int __init load_ramdisk(char *str)
{
	rd_doload = simple_strtol(str,NULL,0) & 3;
	return 1;
}
__setup("load_ramdisk=", load_ramdisk);

static int __init readonly(char *str)
{
	if (*str)
		return 0;
	root_mountflags |= MS_RDONLY;
	return 1;
}

static int __init readwrite(char *str)
{
	if (*str)
		return 0;
	root_mountflags &= ~MS_RDONLY;
	return 1;
}

__setup("ro", readonly);
__setup("rw", readwrite);

/*
 *	Convert a name into device number.  We accept the following variants:
 *
 *	1) device number in hexadecimal	represents itself
 *	2) /dev/nfs represents Root_NFS (0xff)
 *	3) /dev/<disk_name> represents the device number of disk
 *	4) /dev/<disk_name><decimal> represents the device number
 *         of partition - device number of disk plus the partition number
 *	5) /dev/<disk_name>p<decimal> - same as the above, that form is
 *	   used when disk name of partitioned disk ends on a digit.
 *
 *	If name doesn't have fall into the categories above, we return (0,0).
 *	block_class is used to check if something is a disk name. If the disk
 *	name contains slashes, the device name has them replaced with
 *	bangs.
 */

dev_t name_to_dev_t(char *name)
{
    char s[32];       // 用于存储设备名称的缓冲区
    char *p;          // 用于解析字符串的指针
    dev_t res = 0;    // 最终的设备号
    int part;         // 分区号

    // 检查名称是否以 "/dev/" 开头
    if (strncmp(name, "/dev/", 5) != 0) {
        unsigned maj, min;

        // 尝试将名称解析为主设备号和次设备号
        if (sscanf(name, "%u:%u", &maj, &min) == 2) {
            res = MKDEV(maj, min);
            // 验证解析后的设备号是否有效
            if (maj != MAJOR(res) || min != MINOR(res))
                goto fail;
        } else {
            // 将名称解析为一个设备号
            res = new_decode_dev(simple_strtoul(name, &p, 16));
            // 检查解析后是否有剩余的字符
            if (*p)
                goto fail;
        }
        goto done;
    }

    // 跳过 "/dev/" 部分
    name += 5;
    res = Root_NFS;
    // 检查是否是 NFS 根文件系统
    if (strcmp(name, "nfs") == 0)
        goto done;
    res = Root_RAM0;
    // 检查是否是 RAM 根文件系统
    if (strcmp(name, "ram") == 0)
        goto done;

    // 检查名称长度是否超过 31 个字符
    if (strlen(name) > 31)
        goto fail;
    // 复制名称到缓冲区
    strcpy(s, name);
    // 将 '/' 替换为 '!'
    for (p = s; *p; p++)
        if (*p == '/')
            *p = '!';
    // 查找设备号
    res = blk_lookup_devt(s, 0);
    if (res)
        goto done;

    /*
     * 尝试查找不存在但有效的分区，
     * 这些分区可能在重新验证磁盘后才存在，比如分区的 md 设备
     */
    while (p > s && isdigit(p[-1]))
        p--;
    if (p == s || !*p || *p == '0')
        goto fail;

    // 尝试没有分区号的磁盘名称
    part = simple_strtoul(p, NULL, 10);
    *p = '\0';
    res = blk_lookup_devt(s, part);
    if (res)
        goto done;

    // 尝试没有 p<分区号> 的磁盘名称
    if (p < s + 2 || !isdigit(p[-2]) || p[-1] != 'p')
        goto fail;
    p[-1] = '\0';
    res = blk_lookup_devt(s, part);
    if (res)
        goto done;

fail:
    return 0;
done:
    return res;
}


static int __init root_dev_setup(char *line)
{
	strlcpy(saved_root_name, line, sizeof(saved_root_name));
	return 1;
}

__setup("root=", root_dev_setup);

static int __init rootwait_setup(char *str)
{
	if (*str)
		return 0;
	root_wait = 1;
	return 1;
}

__setup("rootwait", rootwait_setup);

static char * __initdata root_mount_data;
static int __init root_data_setup(char *str)
{
	root_mount_data = str;
	return 1;
}

static char * __initdata root_fs_names;
static int __init fs_names_setup(char *str)
{
	root_fs_names = str;
	return 1;
}

static unsigned int __initdata root_delay;
static int __init root_delay_setup(char *str)
{
	root_delay = simple_strtoul(str, NULL, 0);
	return 1;
}

__setup("rootflags=", root_data_setup);
__setup("rootfstype=", fs_names_setup);
__setup("rootdelay=", root_delay_setup);

static void __init get_fs_names(char *page)
{
	char *s = page;

	if (root_fs_names) {
		strcpy(page, root_fs_names);
		while (*s++) {
			if (s[-1] == ',')
				s[-1] = '\0';
		}
	} else {
		int len = get_filesystem_list(page);
		char *p, *next;

		page[len] = '\0';
		for (p = page-1; p; p = next) {
			next = strchr(++p, '\n');
			if (*p++ != '\t')
				continue;
			while ((*s++ = *p++) != '\n')
				;
			s[-1] = '\0';
		}
	}
	*s = '\0';
}

static int __init do_mount_root(char *name, char *fs, int flags, void *data)
{
	int err = sys_mount(name, "/root", fs, flags, data);
	if (err)
		return err;

	sys_chdir("/root");
	ROOT_DEV = current->fs->pwd.mnt->mnt_sb->s_dev;
	printk("VFS: Mounted root (%s filesystem)%s on device %u:%u.\n",
	       current->fs->pwd.mnt->mnt_sb->s_type->name,
	       current->fs->pwd.mnt->mnt_sb->s_flags & MS_RDONLY ?
	       " readonly" : "", MAJOR(ROOT_DEV), MINOR(ROOT_DEV));
	return 0;
}

void __init mount_block_root(char *name, int flags)
{
    char *fs_names = __getname_gfp(GFP_KERNEL | __GFP_NOTRACK_FALSE_POSITIVE); // 获取文件系统名称列表的缓冲区
    char *p;
#ifdef CONFIG_BLOCK
    char b[BDEVNAME_SIZE]; // 块设备名称缓冲区
#else
    const char *b = name;
#endif

    get_fs_names(fs_names); // 获取所有文件系统名称
retry:
    for (p = fs_names; *p; p += strlen(p)+1) {
        int err = do_mount_root(name, p, flags, root_mount_data); // 尝试挂载根文件系统
        switch (err) {
            case 0:
                goto out; // 挂载成功，退出
            case -EACCES:
                flags |= MS_RDONLY; // 如果权限不足，则以只读模式重新尝试
                goto retry;
            case -EINVAL:
                continue; // 无效参数，尝试下一个文件系统
        }
        /*
         * 允许用户区分根设备上的 sys_open 失败和超级块错误
         * 并向他们提供可用设备的列表
         */
#ifdef CONFIG_BLOCK
        __bdevname(ROOT_DEV, b); // 获取块设备名称
#endif
        printk("VFS: Cannot open root device \"%s\" or %s\n",
               root_device_name, b);
        printk("Please append a correct \"root=\" boot option; here are the available partitions:\n");

        printk_all_partitions(); // 打印所有分区信息
#ifdef CONFIG_DEBUG_BLOCK_EXT_DEVT
        printk("DEBUG_BLOCK_EXT_DEVT is enabled, you need to specify "
               "explicit textual name for \"root=\" boot option.\n");
#endif
        panic("VFS: Unable to mount root fs on %s", b); // 挂载失败，触发内核恐慌
    }

    printk("List of all partitions:\n");
    printk_all_partitions(); // 打印所有分区信息
    printk("No filesystem could mount root, tried: ");
    for (p = fs_names; *p; p += strlen(p)+1)
        printk(" %s", p);
    printk("\n");
#ifdef CONFIG_BLOCK
    __bdevname(ROOT_DEV, b); // 获取块设备名称
#endif
    panic("VFS: Unable to mount root fs on %s", b); // 挂载失败，触发内核恐慌
out:
    putname(fs_names); // 释放文件系统名称列表缓冲区
}
 
#ifdef CONFIG_ROOT_NFS
static int __init mount_nfs_root(void)
{
	void *data = nfs_root_data();

	create_dev("/dev/root", ROOT_DEV);
	if (data &&
	    do_mount_root("/dev/root", "nfs", root_mountflags, data) == 0)
		return 1;
	return 0;
}
#endif

#if defined(CONFIG_BLK_DEV_RAM) || defined(CONFIG_BLK_DEV_FD)
void __init change_floppy(char *fmt, ...)
{
	struct termios termios;
	char buf[80];
	char c;
	int fd;
	va_list args;
	va_start(args, fmt);
	vsprintf(buf, fmt, args);
	va_end(args);
	fd = sys_open("/dev/root", O_RDWR | O_NDELAY, 0);
	if (fd >= 0) {
		sys_ioctl(fd, FDEJECT, 0);
		sys_close(fd);
	}
	printk(KERN_NOTICE "VFS: Insert %s and press ENTER\n", buf);
	fd = sys_open("/dev/console", O_RDWR, 0);
	if (fd >= 0) {
		sys_ioctl(fd, TCGETS, (long)&termios);
		termios.c_lflag &= ~ICANON;
		sys_ioctl(fd, TCSETSF, (long)&termios);
		sys_read(fd, &c, 1);
		termios.c_lflag |= ICANON;
		sys_ioctl(fd, TCSETSF, (long)&termios);
		sys_close(fd);
	}
}
#endif

void __init mount_root(void)
{
#ifdef CONFIG_ROOT_NFS
    if (MAJOR(ROOT_DEV) == UNNAMED_MAJOR) {
        if (mount_nfs_root())  // 尝试通过NFS挂载根文件系统
            return;

        printk(KERN_ERR "VFS: Unable to mount root fs via NFS, trying floppy.\n");
        ROOT_DEV = Root_FD0;  // 如果NFS挂载失败，则尝试使用软盘作为根文件系统
    }
#endif

#ifdef CONFIG_BLK_DEV_FD
    if (MAJOR(ROOT_DEV) == FLOPPY_MAJOR) {
        /* rd_doload is 2 for a dual initrd/ramload setup */
        if (rd_doload == 2) {
            if (rd_load_disk(1)) {  // 如果rd_doload为2，则尝试加载软盘上的初始化RAM磁盘
                ROOT_DEV = Root_RAM1;  // 如果加载成功，则将ROOT_DEV设置为RAM1
                root_device_name = NULL;  // 清空根设备名称
            }
        } else {
            change_floppy("root floppy");  // 如果rd_doload不为2，则更改软盘设备
        }
    }
#endif

#ifdef CONFIG_BLOCK
    create_dev("/dev/root", ROOT_DEV);  // 在/dev下创建根设备节点"/dev/root"
    mount_block_root("/dev/root", root_mountflags);  // 挂载块设备根文件系统到指定挂载点，使用root_mountflags指定的挂载标志
#endif
}


/*
 * Prepare the namespace - decide what/where to mount, load ramdisks, etc.
 * 准备命名空间 - 决定何时/何地挂载，加载ramdisk等。
 */
void __init prepare_namespace(void)
{
	int is_floppy;

	// 如果设置了延迟挂载根设备，则等待指定的秒数
	if (root_delay) {
		printk(KERN_INFO "Waiting %dsec before mounting root device...\n",
		       root_delay);
		ssleep(root_delay);
	}

	/*
	 * 等待已知设备完成它们的探测
	 *
	 * 注意：这里是潜在的引起长时间启动延迟的地方。
	 * 例如，等待触摸板初始化可能需要5秒。
	 */
	wait_for_device_probe();

	// 运行多设备（md）的设置
	md_run_setup();

	// 如果保存的根设备名称存在，则使用它进行挂载
	if (saved_root_name[0]) {
		root_device_name = saved_root_name;
		if (!strncmp(root_device_name, "mtd", 3) ||
		    !strncmp(root_device_name, "ubi", 3)) {
			mount_block_root(root_device_name, root_mountflags);
			goto out;
		}
		ROOT_DEV = name_to_dev_t(root_device_name);
		if (strncmp(root_device_name, "/dev/", 5) == 0)
			root_device_name += 5;
	}

	// 加载initrd ramdisk
	if (initrd_load())
		goto out;

	// 如果根设备仍然为0且设置了根设备等待，则等待根设备就绪
	if ((ROOT_DEV == 0) && root_wait) {
		printk(KERN_INFO "Waiting for root device %s...\n",
			saved_root_name);
		while (driver_probe_done() != 0 ||
			(ROOT_DEV = name_to_dev_t(saved_root_name)) == 0)
			msleep(100);
		async_synchronize_full();
	}

	// 检测根设备是否为软盘
	is_floppy = MAJOR(ROOT_DEV) == FLOPPY_MAJOR;

	// 如果是软盘并且需要加载ramdisk，则加载ramdisk
	if (is_floppy && rd_doload && rd_load_disk(0))
		ROOT_DEV = Root_RAM0;

	// 进行挂载根文件系统
	mount_root();

out:
	// 挂载devtmpfs文件系统到"/dev"目录
	devtmpfs_mount("dev");

	// 移动当前进程的根目录到根文件系统的根目录
	sys_mount(".", "/", NULL, MS_MOVE, NULL);

	// 改变当前进程的根目录为"/"
	sys_chroot(".");
}

