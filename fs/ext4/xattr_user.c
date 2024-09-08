/*
 * linux/fs/ext4/xattr_user.c
 * Handler for extended user attributes.
 *
 * Copyright (C) 2001 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include "ext4_jbd2.h"
#include "ext4.h"
#include "xattr.h"

/*
 * 函数用于生成包含用户扩展属性名称的列表项。
 */
static size_t
ext4_xattr_user_list(struct dentry *dentry, char *list, size_t list_size,
		     const char *name, size_t name_len, int type)
{
	const size_t prefix_len = XATTR_USER_PREFIX_LEN;  /* 用户扩展属性前缀长度 */
	const size_t total_len = prefix_len + name_len + 1;  /* 计算总长度 */

	/* 如果文件系统未启用用户扩展属性，则返回 0 */
	if (!test_opt(dentry->d_sb, XATTR_USER))
		return 0;

	/* 如果提供了列表缓冲区且总长度不超过缓冲区大小 */
	if (list && total_len <= list_size) {
		memcpy(list, XATTR_USER_PREFIX, prefix_len);  /* 复制前缀到列表中 */
		memcpy(list + prefix_len, name, name_len);  /* 复制属性名称到列表中 */
		list[prefix_len + name_len] = '\0';  /* 添加字符串结束符 */
	}
	return total_len;  /* 返回总长度 */
}

/*
 * 函数用于获取用户扩展属性的值。
 */
static int
ext4_xattr_user_get(struct dentry *dentry, const char *name,
		    void *buffer, size_t size, int type)
{
	/* 如果名称为空，则返回无效参数错误 */
	if (strcmp(name, "") == 0)
		return -EINVAL;
	/* 如果文件系统未启用用户扩展属性，则返回不支持错误 */
	if (!test_opt(dentry->d_sb, XATTR_USER))
		return -EOPNOTSUPP;
	/* 调用 ext4_xattr_get 函数获取扩展属性的值 */
	return ext4_xattr_get(dentry->d_inode, EXT4_XATTR_INDEX_USER,
			      name, buffer, size);
}

/*
 * 函数用于设置用户扩展属性的值。
 */
static int
ext4_xattr_user_set(struct dentry *dentry, const char *name,
		    const void *value, size_t size, int flags, int type)
{
	/* 如果名称为空，则返回无效参数错误 */
	if (strcmp(name, "") == 0)
		return -EINVAL;
	/* 如果文件系统未启用用户扩展属性，则返回不支持错误 */
	if (!test_opt(dentry->d_sb, XATTR_USER))
		return -EOPNOTSUPP;
	/* 调用 ext4_xattr_set 函数设置扩展属性的值 */
	return ext4_xattr_set(dentry->d_inode, EXT4_XATTR_INDEX_USER,
			      name, value, size, flags);
}

/*
 * 用户扩展属性处理程序。
 */
struct xattr_handler ext4_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,  /* 扩展属性前缀 */
	.list	= ext4_xattr_user_list,  /* 列出扩展属性的函数 */
	.get	= ext4_xattr_user_get,  /* 获取扩展属性值的函数 */
	.set	= ext4_xattr_user_set,  /* 设置扩展属性值的函数 */
};
