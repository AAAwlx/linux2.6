/*
 *	linux/mm/mlock.c
 *
 *  (C) Copyright 1995 Linus Torvalds
 *  (C) Copyright 2002 Christoph Hellwig
 */

#include <linux/capability.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/mempolicy.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/rmap.h>
#include <linux/mmzone.h>
#include <linux/hugetlb.h>

#include "internal.h"

int can_do_mlock(void)
{
	if (capable(CAP_IPC_LOCK))
		return 1;
	if (rlimit(RLIMIT_MEMLOCK) != 0)
		return 1;
	return 0;
}
EXPORT_SYMBOL(can_do_mlock);

/*
 * Mlocked pages are marked with PageMlocked() flag for efficient testing
 * in vmscan and, possibly, the fault path; and to support semi-accurate
 * statistics.
 *
 * An mlocked page [PageMlocked(page)] is unevictable.  As such, it will
 * be placed on the LRU "unevictable" list, rather than the [in]active lists.
 * The unevictable list is an LRU sibling list to the [in]active lists.
 * PageUnevictable is set to indicate the unevictable state.
 *
 * When lazy mlocking via vmscan, it is important to ensure that the
 * vma's VM_LOCKED status is not concurrently being modified, otherwise we
 * may have mlocked a page that is being munlocked. So lazy mlock must take
 * the mmap_sem for read, and verify that the vma really is locked
 * (see mm/rmap.c).
 */

/*
 *  LRU accounting for clear_page_mlock()
 */
void __clear_page_mlock(struct page *page)
{
	VM_BUG_ON(!PageLocked(page));

	if (!page->mapping) {	/* truncated ? */
		return;
	}

	dec_zone_page_state(page, NR_MLOCK);
	count_vm_event(UNEVICTABLE_PGCLEARED);
	if (!isolate_lru_page(page)) {
		putback_lru_page(page);
	} else {
		/*
		 * We lost the race. the page already moved to evictable list.
		 */
		if (PageUnevictable(page))
			count_vm_event(UNEVICTABLE_PGSTRANDED);
	}
}

/*
 * Mark page as mlocked if not already.
 * If page on LRU, isolate and putback to move to unevictable list.
 */
void mlock_vma_page(struct page *page)
{
	BUG_ON(!PageLocked(page));

	if (!TestSetPageMlocked(page)) {
		inc_zone_page_state(page, NR_MLOCK);
		count_vm_event(UNEVICTABLE_PGMLOCKED);
		if (!isolate_lru_page(page))
			putback_lru_page(page);
	}
}

/**
 * munlock_vma_page - munlock a vma page
 * @page - page to be unlocked
 *
 * called from munlock()/munmap() path with page supposedly on the LRU.
 * When we munlock a page, because the vma where we found the page is being
 * munlock()ed or munmap()ed, we want to check whether other vmas hold the
 * page locked so that we can leave it on the unevictable lru list and not
 * bother vmscan with it.  However, to walk the page's rmap list in
 * try_to_munlock() we must isolate the page from the LRU.  If some other
 * task has removed the page from the LRU, we won't be able to do that.
 * So we clear the PageMlocked as we might not get another chance.  If we
 * can't isolate the page, we leave it for putback_lru_page() and vmscan
 * [page_referenced()/try_to_unmap()] to deal with.
 */
void munlock_vma_page(struct page *page)
{
	BUG_ON(!PageLocked(page));

	if (TestClearPageMlocked(page)) {
		dec_zone_page_state(page, NR_MLOCK);
		if (!isolate_lru_page(page)) {
			int ret = try_to_munlock(page);
			/*
			 * did try_to_unlock() succeed or punt?
			 */
			if (ret != SWAP_MLOCK)
				count_vm_event(UNEVICTABLE_PGMUNLOCKED);

			putback_lru_page(page);
		} else {
			/*
			 * Some other task has removed the page from the LRU.
			 * putback_lru_page() will take care of removing the
			 * page from the unevictable list, if necessary.
			 * vmscan [page_referenced()] will move the page back
			 * to the unevictable list if some other vma has it
			 * mlocked.
			 */
			if (PageUnevictable(page))
				count_vm_event(UNEVICTABLE_PGSTRANDED);
			else
				count_vm_event(UNEVICTABLE_PGMUNLOCKED);
		}
	}
}

/**
 * __mlock_vma_pages_range() -  mlock a range of pages in the vma.
 * @vma:   target vma
 * @start: start address
 * @end:   end address
 *
 * This takes care of making the pages present too.
 *
 * return 0 on success, negative error code on error.
 *
 * vma->vm_mm->mmap_sem must be held for at least read.
 */
static long __mlock_vma_pages_range(struct vm_area_struct *vma,
				    unsigned long start, unsigned long end)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long addr = start;
	struct page *pages[16]; /* 16 gives a reasonable batch */
	int nr_pages = (end - start) / PAGE_SIZE;
	int ret = 0;
	int gup_flags;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(end   & ~PAGE_MASK);
	VM_BUG_ON(start < vma->vm_start);
	VM_BUG_ON(end   > vma->vm_end);
	VM_BUG_ON(!rwsem_is_locked(&mm->mmap_sem));

	gup_flags = FOLL_TOUCH | FOLL_GET;
	if (vma->vm_flags & VM_WRITE)
		gup_flags |= FOLL_WRITE;

	while (nr_pages > 0) {
		int i;

		cond_resched();

		/*
		 * get_user_pages makes pages present if we are
		 * setting mlock. and this extra reference count will
		 * disable migration of this page.  However, page may
		 * still be truncated out from under us.
		 */
		ret = __get_user_pages(current, mm, addr,
				min_t(int, nr_pages, ARRAY_SIZE(pages)),
				gup_flags, pages, NULL);
		/*
		 * This can happen for, e.g., VM_NONLINEAR regions before
		 * a page has been allocated and mapped at a given offset,
		 * or for addresses that map beyond end of a file.
		 * We'll mlock the pages if/when they get faulted in.
		 */
		if (ret < 0)
			break;

		lru_add_drain();	/* push cached pages to LRU */

		for (i = 0; i < ret; i++) {
			struct page *page = pages[i];

			if (page->mapping) {
				/*
				 * That preliminary check is mainly to avoid
				 * the pointless overhead of lock_page on the
				 * ZERO_PAGE: which might bounce very badly if
				 * there is contention.  However, we're still
				 * dirtying its cacheline with get/put_page:
				 * we'll add another __get_user_pages flag to
				 * avoid it if that case turns out to matter.
				 */
				lock_page(page);
				/*
				 * Because we lock page here and migration is
				 * blocked by the elevated reference, we need
				 * only check for file-cache page truncation.
				 */
				if (page->mapping)
					mlock_vma_page(page);
				unlock_page(page);
			}
			put_page(page);	/* ref from get_user_pages() */
		}

		addr += ret * PAGE_SIZE;
		nr_pages -= ret;
		ret = 0;
	}

	return ret;	/* 0 or negative error code */
}

/*
 * convert get_user_pages() return value to posix mlock() error
 */
static int __mlock_posix_error_return(long retval)
{
	if (retval == -EFAULT)
		retval = -ENOMEM;
	else if (retval == -ENOMEM)
		retval = -EAGAIN;
	return retval;
}

/**
 * mlock_vma_pages_range() - mlock pages in specified vma range.
 * @vma - the vma containing the specfied address range
 * @start - starting address in @vma to mlock
 * @end   - end address [+1] in @vma to mlock
 *
 * For mmap()/mremap()/expansion of mlocked vma.
 *
 * return 0 on success for "normal" vmas.
 *
 * return number of pages [> 0] to be removed from locked_vm on success
 * of "special" vmas.
 */
long mlock_vma_pages_range(struct vm_area_struct *vma,
			unsigned long start, unsigned long end)
{
	int nr_pages = (end - start) / PAGE_SIZE;
	BUG_ON(!(vma->vm_flags & VM_LOCKED));

	/*
	 * filter unlockable vmas
	 */
	if (vma->vm_flags & (VM_IO | VM_PFNMAP))
		goto no_mlock;

	if (!((vma->vm_flags & (VM_DONTEXPAND | VM_RESERVED)) ||
			is_vm_hugetlb_page(vma) ||
			vma == get_gate_vma(current))) {

		__mlock_vma_pages_range(vma, start, end);

		/* Hide errors from mmap() and other callers */
		return 0;
	}

	/*
	 * User mapped kernel pages or huge pages:
	 * make these pages present to populate the ptes, but
	 * fall thru' to reset VM_LOCKED--no need to unlock, and
	 * return nr_pages so these don't get counted against task's
	 * locked limit.  huge pages are already counted against
	 * locked vm limit.
	 */
	make_pages_present(start, end);

no_mlock:
	vma->vm_flags &= ~VM_LOCKED;	/* and don't come back! */
	return nr_pages;		/* error or pages NOT mlocked */
}

/*
 * munlock_vma_pages_range() - munlock all pages in the vma range.'
 * @vma - vma containing range to be munlock()ed.
 * @start - start address in @vma of the range
 * @end - end of range in @vma.
 *
 *  For mremap(), munmap() and exit().
 *
 * Called with @vma VM_LOCKED.
 *
 * Returns with VM_LOCKED cleared.  Callers must be prepared to
 * deal with this.
 *
 * We don't save and restore VM_LOCKED here because pages are
 * still on lru.  In unmap path, pages might be scanned by reclaim
 * and re-mlocked by try_to_{munlock|unmap} before we unmap and
 * free them.  This will result in freeing mlocked pages.
 */
/*
 * munlock_vma_pages_range() - 解锁 VMA 范围内的所有页面。
 * @vma - 包含要解锁的范围的虚拟内存区域。
 * @start - 在 @vma 中范围的起始地址
 * @end - 在 @vma 中范围的结束地址。
 *
 * 用于 mremap()、munmap() 和退出过程。
 *
 * 调用时 @vma 应为 VM_LOCKED。
 *
 * 返回时 VM_LOCKED 被清除。调用者必须准备处理这一点。
 *
 * 我们在这里不保存和恢复 VM_LOCKED，因为页面仍在 LRU 列表上。在取消映射路径中，
 * 页面可能被回收扫描并在我们取消映射和释放它们之前被 try_to_{munlock|unmap} 重新锁定。
 * 这可能导致释放已锁定的页面。
 */
void munlock_vma_pages_range(struct vm_area_struct *vma,
			     unsigned long start, unsigned long end)
{
	unsigned long addr;

	// 确保本地 CPU 的 LRU 列表被刷新
	lru_add_drain();
	// 清除 VMA 的 VM_LOCKED 标志
	vma->vm_flags &= ~VM_LOCKED;

	// 遍历指定范围内的每一页
	for (addr = start; addr < end; addr += PAGE_SIZE) {
		struct page *page;
		/*
		 * Although FOLL_DUMP is intended for get_dump_page(),
		 * it just so happens that its special treatment of the
		 * ZERO_PAGE (returning an error instead of doing get_page)
		 * suits munlock very well (and if somehow an abnormal page
		 * has sneaked into the range, we won't oops here: great).
		 */
		/*
		 * 虽然 FOLL_DUMP 本意是为 get_dump_page() 设计，
		 * 但恰巧它对 ZERO_PAGE（返回错误而不是执行 get_page）的特殊处理
		 * 很适合 munlock 使用（而且如果某些异常页面偷偷进入范围，我们也不会触发异常：很好）。
		 */
		page = follow_page(vma, addr, FOLL_GET | FOLL_DUMP);	// 尝试获取页
		if (page && !IS_ERR(page)) {	// 如果页面有效且没有错误
			lock_page(page);	// 锁定页面
			/*
			 * Like in __mlock_vma_pages_range(),
			 * because we lock page here and migration is
			 * blocked by the elevated reference, we need
			 * only check for file-cache page truncation.
			 */
			/*
			 * 如同 __mlock_vma_pages_range() 中，
			 * 因为我们在这里锁定了页面，并且由于增加的引用计数阻止了迁移，
			 * 我们只需检查文件缓存页面是否被截断。
			 */
			if (page->mapping)
				munlock_vma_page(page);	// 解锁页面
			unlock_page(page);	// 解锁页面
			put_page(page);	// 释放页面引用
		}
		cond_resched();	// 提供一个让出 CPU 的机会
	}
}

/*
 * mlock_fixup  - handle mlock[all]/munlock[all] requests.
 *
 * Filters out "special" vmas -- VM_LOCKED never gets set for these, and
 * munlock is a no-op.  However, for some special vmas, we go ahead and
 * populate the ptes via make_pages_present().
 *
 * For vmas that pass the filters, merge/split as appropriate.
 */
static int mlock_fixup(struct vm_area_struct *vma, struct vm_area_struct **prev,
	unsigned long start, unsigned long end, unsigned int newflags)
{
	struct mm_struct *mm = vma->vm_mm;
	pgoff_t pgoff;
	int nr_pages;
	int ret = 0;
	int lock = newflags & VM_LOCKED;

	if (newflags == vma->vm_flags ||
			(vma->vm_flags & (VM_IO | VM_PFNMAP)))
		goto out;	/* don't set VM_LOCKED,  don't count */

	if ((vma->vm_flags & (VM_DONTEXPAND | VM_RESERVED)) ||
			is_vm_hugetlb_page(vma) ||
			vma == get_gate_vma(current)) {
		if (lock)
			make_pages_present(start, end);
		goto out;	/* don't set VM_LOCKED,  don't count */
	}

	pgoff = vma->vm_pgoff + ((start - vma->vm_start) >> PAGE_SHIFT);
	*prev = vma_merge(mm, *prev, start, end, newflags, vma->anon_vma,
			  vma->vm_file, pgoff, vma_policy(vma));
	if (*prev) {
		vma = *prev;
		goto success;
	}

	if (start != vma->vm_start) {
		ret = split_vma(mm, vma, start, 1);
		if (ret)
			goto out;
	}

	if (end != vma->vm_end) {
		ret = split_vma(mm, vma, end, 0);
		if (ret)
			goto out;
	}

success:
	/*
	 * Keep track of amount of locked VM.
	 */
	nr_pages = (end - start) >> PAGE_SHIFT;
	if (!lock)
		nr_pages = -nr_pages;
	mm->locked_vm += nr_pages;

	/*
	 * vm_flags is protected by the mmap_sem held in write mode.
	 * It's okay if try_to_unmap_one unmaps a page just after we
	 * set VM_LOCKED, __mlock_vma_pages_range will bring it back.
	 */

	if (lock) {
		vma->vm_flags = newflags;
		ret = __mlock_vma_pages_range(vma, start, end);
		if (ret < 0)
			ret = __mlock_posix_error_return(ret);
	} else {
		munlock_vma_pages_range(vma, start, end);
	}

out:
	*prev = vma;
	return ret;
}

static int do_mlock(unsigned long start, size_t len, int on)
{
	unsigned long nstart, end, tmp;
	struct vm_area_struct * vma, * prev;
	int error;

	len = PAGE_ALIGN(len);
	end = start + len;
	if (end < start)
		return -EINVAL;
	if (end == start)
		return 0;
	vma = find_vma_prev(current->mm, start, &prev);
	if (!vma || vma->vm_start > start)
		return -ENOMEM;

	if (start > vma->vm_start)
		prev = vma;

	for (nstart = start ; ; ) {
		unsigned int newflags;

		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */

		newflags = vma->vm_flags | VM_LOCKED;
		if (!on)
			newflags &= ~VM_LOCKED;

		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;
		error = mlock_fixup(vma, &prev, nstart, tmp, newflags);
		if (error)
			break;
		nstart = tmp;
		if (nstart < prev->vm_end)
			nstart = prev->vm_end;
		if (nstart >= end)
			break;

		vma = prev->vm_next;
		if (!vma || vma->vm_start != nstart) {
			error = -ENOMEM;
			break;
		}
	}
	return error;
}

SYSCALL_DEFINE2(mlock, unsigned long, start, size_t, len)
{
	unsigned long locked;
	unsigned long lock_limit;
	int error = -ENOMEM;

	if (!can_do_mlock())
		return -EPERM;

	lru_add_drain_all();	/* flush pagevec */

	down_write(&current->mm->mmap_sem);
	len = PAGE_ALIGN(len + (start & ~PAGE_MASK));
	start &= PAGE_MASK;

	locked = len >> PAGE_SHIFT;
	locked += current->mm->locked_vm;

	lock_limit = rlimit(RLIMIT_MEMLOCK);
	lock_limit >>= PAGE_SHIFT;

	/* check against resource limits */
	if ((locked <= lock_limit) || capable(CAP_IPC_LOCK))
		error = do_mlock(start, len, 1);
	up_write(&current->mm->mmap_sem);
	return error;
}

SYSCALL_DEFINE2(munlock, unsigned long, start, size_t, len)
{
	int ret;

	down_write(&current->mm->mmap_sem);
	len = PAGE_ALIGN(len + (start & ~PAGE_MASK));
	start &= PAGE_MASK;
	ret = do_mlock(start, len, 0);
	up_write(&current->mm->mmap_sem);
	return ret;
}

static int do_mlockall(int flags)
{
	struct vm_area_struct * vma, * prev = NULL;
	unsigned int def_flags = 0;

	if (flags & MCL_FUTURE)
		def_flags = VM_LOCKED;
	current->mm->def_flags = def_flags;
	if (flags == MCL_FUTURE)
		goto out;

	for (vma = current->mm->mmap; vma ; vma = prev->vm_next) {
		unsigned int newflags;

		newflags = vma->vm_flags | VM_LOCKED;
		if (!(flags & MCL_CURRENT))
			newflags &= ~VM_LOCKED;

		/* Ignore errors */
		mlock_fixup(vma, &prev, vma->vm_start, vma->vm_end, newflags);
	}
out:
	return 0;
}

SYSCALL_DEFINE1(mlockall, int, flags)
{
	unsigned long lock_limit;
	int ret = -EINVAL;

	if (!flags || (flags & ~(MCL_CURRENT | MCL_FUTURE)))
		goto out;

	ret = -EPERM;
	if (!can_do_mlock())
		goto out;

	lru_add_drain_all();	/* flush pagevec */

	down_write(&current->mm->mmap_sem);

	lock_limit = rlimit(RLIMIT_MEMLOCK);
	lock_limit >>= PAGE_SHIFT;

	ret = -ENOMEM;
	if (!(flags & MCL_CURRENT) || (current->mm->total_vm <= lock_limit) ||
	    capable(CAP_IPC_LOCK))
		ret = do_mlockall(flags);
	up_write(&current->mm->mmap_sem);
out:
	return ret;
}

SYSCALL_DEFINE0(munlockall)
{
	int ret;

	down_write(&current->mm->mmap_sem);
	ret = do_mlockall(0);
	up_write(&current->mm->mmap_sem);
	return ret;
}

/*
 * Objects with different lifetime than processes (SHM_LOCK and SHM_HUGETLB
 * shm segments) get accounted against the user_struct instead.
 */
static DEFINE_SPINLOCK(shmlock_user_lock);

int user_shm_lock(size_t size, struct user_struct *user)
{
	unsigned long lock_limit, locked;
	int allowed = 0;

	locked = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	lock_limit = rlimit(RLIMIT_MEMLOCK);
	if (lock_limit == RLIM_INFINITY)
		allowed = 1;
	lock_limit >>= PAGE_SHIFT;
	spin_lock(&shmlock_user_lock);
	if (!allowed &&
	    locked + user->locked_shm > lock_limit && !capable(CAP_IPC_LOCK))
		goto out;
	get_uid(user);
	user->locked_shm += locked;
	allowed = 1;
out:
	spin_unlock(&shmlock_user_lock);
	return allowed;
}

void user_shm_unlock(size_t size, struct user_struct *user)
{
	spin_lock(&shmlock_user_lock);
	user->locked_shm -= (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	spin_unlock(&shmlock_user_lock);
	free_uid(user);
}

int account_locked_memory(struct mm_struct *mm, struct rlimit *rlim,
			  size_t size)
{
	unsigned long lim, vm, pgsz;
	int error = -ENOMEM;

	pgsz = PAGE_ALIGN(size) >> PAGE_SHIFT;

	down_write(&mm->mmap_sem);

	lim = ACCESS_ONCE(rlim[RLIMIT_AS].rlim_cur) >> PAGE_SHIFT;
	vm   = mm->total_vm + pgsz;
	if (lim < vm)
		goto out;

	lim = ACCESS_ONCE(rlim[RLIMIT_MEMLOCK].rlim_cur) >> PAGE_SHIFT;
	vm   = mm->locked_vm + pgsz;
	if (lim < vm)
		goto out;

	mm->total_vm  += pgsz;
	mm->locked_vm += pgsz;

	error = 0;
 out:
	up_write(&mm->mmap_sem);
	return error;
}

void refund_locked_memory(struct mm_struct *mm, size_t size)
{
	unsigned long pgsz = PAGE_ALIGN(size) >> PAGE_SHIFT;

	down_write(&mm->mmap_sem);

	mm->total_vm  -= pgsz;
	mm->locked_vm -= pgsz;

	up_write(&mm->mmap_sem);
}
