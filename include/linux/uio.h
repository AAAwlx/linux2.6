#ifndef __LINUX_UIO_H
#define __LINUX_UIO_H

#include <linux/compiler.h>
#include <linux/types.h>

/*
 *	Berkeley style UIO structures	-	Alan Cox 1994.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

struct iovec
{
	/* BSD 使用 caddr_t (1003.1g 要求使用 void *) */
	// 指向数据缓冲区的起始地址的指针。注释说明 BSD 系统使用 caddr_t 类型，但 POSIX.1g 标准要求使用 void * 类型以提高通用性和兼容性。
	void __user *iov_base;	/* BSD uses caddr_t (1003.1g requires void *) */
	/* 必须是 size_t (1003.1g) */
	// 表示缓冲区的长度，类型为 __kernel_size_t，它基于系统标准定义应当是 size_t 类型。size_t 类型确保了长度值的兼容性和足够的数据容量，以便支持各种大小的数据。
	__kernel_size_t iov_len; /* Must be size_t (1003.1g) */
};

/*
 *	UIO_MAXIOV shall be at least 16 1003.1g (5.4.1.1)
 */
 
#define UIO_FASTIOV	8
#define UIO_MAXIOV	1024

#ifdef __KERNEL__

struct kvec {
	void *iov_base; /* and that should *never* hold a userland pointer */
	size_t iov_len;
};

/*
 * Total number of bytes covered by an iovec.
 *
 * NOTE that it is not safe to use this function until all the iovec's
 * segment lengths have been validated.  Because the individual lengths can
 * overflow a size_t when added together.
 */
static inline size_t iov_length(const struct iovec *iov, unsigned long nr_segs)
{
	unsigned long seg;
	size_t ret = 0;

	for (seg = 0; seg < nr_segs; seg++)
		ret += iov[seg].iov_len;
	return ret;
}

unsigned long iov_shorten(struct iovec *iov, unsigned long nr_segs, size_t to);
#endif

#endif
