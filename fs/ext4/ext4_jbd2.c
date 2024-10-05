/*
 * Interface between ext4 and JBD
 */

#include "ext4_jbd2.h"

#include <trace/events/ext4.h>

int __ext4_journal_get_undo_access(const char *where, handle_t *handle,
				struct buffer_head *bh)
{
	int err = 0;

	// 检查事务句柄是否有效，只有有效的 handle 才执行操作
	if (ext4_handle_valid(handle)) {
		// 尝试获取撤销日志的访问权限
		err = jbd2_journal_get_undo_access(handle, bh);
		// 如果出错，记录错误并中止事务
		if (err)
			ext4_journal_abort_handle(where, __func__, bh,
						  handle, err);
	}
	return err;
}

int __ext4_journal_get_write_access(const char *where, handle_t *handle,
				struct buffer_head *bh)
{
	int err = 0;

	// 检查事务句柄是否有效，只有有效的 handle 才执行操作
	if (ext4_handle_valid(handle)) {
		// 尝试获取写访问权限
		err = jbd2_journal_get_write_access(handle, bh);
		// 如果获取写访问权限失败，记录错误并中止事务
		if (err)
			ext4_journal_abort_handle(where, __func__, bh,
						  handle, err);
	}
	return err;
}
/*
 * __ext4_forget - 在文件系统中撤销（移除）指定的缓冲区
 * @where: 调用该函数的位置（用于日志记录）
 * @handle: 事务句柄，表示文件系统操作的上下文
 * @is_metadata: 指示是否为元数据块（1表示是元数据）
 * @inode: 与缓冲区关联的 inode
 * @bh: 缓冲区头指针，表示需要遗忘的缓冲区
 * @blocknr: 需要遗忘的块号
 *
 * 该函数用于处理 ext4 文件系统中对指定块的“遗忘”操作。它通过对数据块的
 * 操作来确保在文件系统的事务过程中，数据块被安全地丢弃或撤销。这种操作
 * 主要在块不再被使用时执行，以确保文件系统的一致性。
 *
 * 返回值:
 *  0 表示成功，否则返回错误码。
 */
int __ext4_forget(const char *where, handle_t *handle, int is_metadata,
		  struct inode *inode, struct buffer_head *bh,
		  ext4_fsblk_t blocknr)
{
	int err;

	// 检查是否允许当前线程进入休眠状态
	might_sleep();

	// 记录遗忘操作的跟踪信息
	trace_ext4_forget(inode, is_metadata, blocknr);
	BUFFER_TRACE(bh, "enter");

	// 打印调试信息，记录该缓冲区的相关信息
	jbd_debug(4, "forgetting bh %p: is_metadata = %d, mode %o, "
		  "data mode %x\n",
		  bh, is_metadata, inode->i_mode,
		  test_opt(inode->i_sb, DATA_FLAGS));

	// 如果没有启用事务日志（无效 handle），直接丢弃缓冲区并返回
	if (!ext4_handle_valid(handle)) {
		bforget(bh);
		return 0;
	}

	/*
	 * 在进行完整数据日志记录（journal_data）时，无需执行撤销操作（revoke），
	 * 或者在处理非元数据且不需要日志记录的数据块时跳过撤销。
	 */
	if (test_opt(inode->i_sb, DATA_FLAGS) == EXT4_MOUNT_JOURNAL_DATA ||
	    (!is_metadata && !ext4_should_journal_data(inode))) {
		if (bh) {
			BUFFER_TRACE(bh, "call jbd2_journal_forget");
			err = jbd2_journal_forget(handle, bh);
			if (err)
				ext4_journal_abort_handle(where, __func__, bh,
							  handle, err);
			return err;
		}
		return 0;
	}

	/*
	 * 当不进行完整数据日志记录且（是元数据或需要日志记录的数据）时，
	 * 需要调用 revoke 操作来撤销该数据块的日志记录。
	 */
	BUFFER_TRACE(bh, "call jbd2_journal_revoke");
	err = jbd2_journal_revoke(handle, blocknr, bh);
	if (err) {
		ext4_journal_abort_handle(where, __func__, bh, handle, err);
		ext4_abort(inode->i_sb, __func__,
			   "error %d when attempting revoke", err);
	}
	BUFFER_TRACE(bh, "exit");
	return err;
}

int __ext4_journal_get_create_access(const char *where,
				handle_t *handle, struct buffer_head *bh)
{
	int err = 0;

	// 检查 handle 是否有效，表示是否启用了事务日志
	if (ext4_handle_valid(handle)) {
		// 调用 jbd2 提供的函数来获取创建访问权限
		err = jbd2_journal_get_create_access(handle, bh);
		// 如果获取创建访问权限失败，记录并中止该事务
		if (err)
			ext4_journal_abort_handle(where, __func__, bh,
						  handle, err);
	}
	// 返回操作结果
	return err;
}

/**
 * __ext4_handle_dirty_metadata - 处理元数据的脏页写入
 * @where: 调用该函数的位置，用于日志记录
 * @handle: 文件系统事务的句柄
 * @inode: 关联的 inode，可能为 NULL
 * @bh: 缓冲区头指针，表示需要处理的元数据块
 *
 * 该函数用于处理 ext4 文件系统中的元数据修改，并根据是否启用了日志来选择不同的
 * 写入处理方式。如果启用了日志，将调用 `jbd2_journal_dirty_metadata` 来记录元数据
 * 的脏页写入；如果没有启用日志，将直接标记缓冲区为脏，并在必要时同步到磁盘。
 *
 * 返回值:
 *  0 表示成功，否则返回错误码。
 */
int __ext4_handle_dirty_metadata(const char *where, handle_t *handle,
				 struct inode *inode, struct buffer_head *bh)
{
	int err = 0;

	// 如果启用了日志系统，调用 jbd2 提供的脏页写入接口
	if (ext4_handle_valid(handle)) {
		err = jbd2_journal_dirty_metadata(handle, bh);
		// 如果发生错误，中止该事务并记录错误信息
		if (err)
			ext4_journal_abort_handle(where, __func__, bh,
						  handle, err);
	} else {
		// 否则，直接标记缓冲区为脏页，准备写入磁盘
		if (inode)
			mark_buffer_dirty_inode(bh, inode);  // 关联 inode
		else
			mark_buffer_dirty(bh);  // 不关联 inode，直接标记为脏页

		// 如果 inode 需要同步，执行同步操作
		if (inode && inode_needs_sync(inode)) {
			sync_dirty_buffer(bh);  // 同步缓冲区到磁盘
			// 检查同步过程中是否有错误，并处理未更新成功的缓冲区
			if (buffer_req(bh) && !buffer_uptodate(bh)) {
				ext4_error(inode->i_sb,
					   "IO error syncing inode, "
					   "inode=%lu, block=%llu",
					   inode->i_ino,
					   (unsigned long long) bh->b_blocknr);
				err = -EIO;  // 返回 I/O 错误
			}
		}
	}
	return err;
}
