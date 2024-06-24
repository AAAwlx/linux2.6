/*
 * Macros for manipulating and testing flags related to a
 * pageblock_nr_pages number of pages.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation version 2 of the License
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Original author, Mel Gorman
 * Major cleanups and reduction of bit operations, Andy Whitcroft
 */
#ifndef PAGEBLOCK_FLAGS_H
#define PAGEBLOCK_FLAGS_H

#include <linux/types.h>

/* Bit indices that affect a whole block of pages */
// 定义一个枚举类型 pageblock_bits
enum pageblock_bits {
    PB_migrate,                          // PB_migrate 表示迁移类型的起始值
    PB_migrate_end = PB_migrate + 3 - 1, // PB_migrate_end 表示迁移类型的结束值，这里使用 3 位来表示不同的迁移类型
                                          // 计算方式是从 PB_migrate 开始，加上 3 (表示 3 位)减去 1，得到结束值
                                          // PB_migrate 到 PB_migrate_end 共占用 3 位
    NR_PAGEBLOCK_BITS                    // NR_PAGEBLOCK_BITS 表示 pageblock_bits 枚举类型中的总位数
};

#ifdef CONFIG_HUGETLB_PAGE

#ifdef CONFIG_HUGETLB_PAGE_SIZE_VARIABLE

/* Huge page sizes are variable */
extern int pageblock_order;

#else /* CONFIG_HUGETLB_PAGE_SIZE_VARIABLE */

/* Huge pages are a constant size */
#define pageblock_order		HUGETLB_PAGE_ORDER

#endif /* CONFIG_HUGETLB_PAGE_SIZE_VARIABLE */

#else /* CONFIG_HUGETLB_PAGE */

/* If huge pages are not used, group by MAX_ORDER_NR_PAGES */
#define pageblock_order		(MAX_ORDER-1)

#endif /* CONFIG_HUGETLB_PAGE */

#define pageblock_nr_pages	(1UL << pageblock_order)

/* Forward declaration */
struct page;

/* Declarations for getting and setting flags. See mm/page_alloc.c */
unsigned long get_pageblock_flags_group(struct page *page,
					int start_bitidx, int end_bitidx);
void set_pageblock_flags_group(struct page *page, unsigned long flags,
					int start_bitidx, int end_bitidx);

#define get_pageblock_flags(page) \
			get_pageblock_flags_group(page, 0, NR_PAGEBLOCK_BITS-1)
#define set_pageblock_flags(page) \
			set_pageblock_flags_group(page, 0, NR_PAGEBLOCK_BITS-1)

#endif	/* PAGEBLOCK_FLAGS_H */
