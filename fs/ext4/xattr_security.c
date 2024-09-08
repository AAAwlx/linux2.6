/*
 * linux/fs/ext4/xattr_security.c
 * Handler for storing security labels as extended attributes.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/slab.h>
#include "ext4_jbd2.h"
#include "ext4.h"
#include "xattr.h"

/*
 * 函数用于生成包含安全扩展属性名称的列表项。
 */
static size_t
ext4_xattr_security_list(struct dentry *dentry, char *list, size_t list_size,
		const char *name, size_t name_len, int type)
{
	const size_t prefix_len = sizeof(XATTR_SECURITY_PREFIX)-1;  /* 安全扩展属性前缀长度 */
	const size_t total_len = prefix_len + name_len + 1;  /* 计算总长度 */

	/* 如果提供了列表缓冲区且总长度不超过缓冲区大小 */
	if (list && total_len <= list_size) {
		memcpy(list, XATTR_SECURITY_PREFIX, prefix_len);  /* 复制前缀到列表中 */
		memcpy(list+prefix_len, name, name_len);  /* 复制属性名称到列表中 */
		list[prefix_len + name_len] = '\0';  /* 添加字符串结束符 */
	}
	return total_len;  /* 返回总长度 */
}

/*
 * 函数用于获取安全扩展属性的值。
 */
static int
ext4_xattr_security_get(struct dentry *dentry, const char *name,
		       void *buffer, size_t size, int type)
{
	/* 如果名称为空，则返回无效参数错误 */
	if (strcmp(name, "") == 0)
		return -EINVAL;
	/* 调用 ext4_xattr_get 函数获取扩展属性的值 */
	return ext4_xattr_get(dentry->d_inode, EXT4_XATTR_INDEX_SECURITY,
			      name, buffer, size);
}

/*
 * 函数用于设置安全扩展属性的值。
 */
static int
ext4_xattr_security_set(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags, int type)
{
	/* 如果名称为空，则返回无效参数错误 */
	if (strcmp(name, "") == 0)
		return -EINVAL;
	/* 调用 ext4_xattr_set 函数设置扩展属性的值 */
	return ext4_xattr_set(dentry->d_inode, EXT4_XATTR_INDEX_SECURITY,
			      name, value, size, flags);
}

/*
 * 函数用于初始化安全扩展属性。
 */
int
ext4_init_security(handle_t *handle, struct inode *inode, struct inode *dir)
{
	int err;
	size_t len;
	void *value;
	char *name;

	/* 调用 security_inode_init_security 获取安全扩展属性名称和值 */
	err = security_inode_init_security(inode, dir, &name, &value, &len);
	if (err) {
		if (err == -EOPNOTSUPP)  /* 如果不支持安全扩展属性，返回 0 */
			return 0;
		return err;  /* 返回错误码 */
	}
	/* 使用指定的句柄设置安全扩展属性 */
	err = ext4_xattr_set_handle(handle, inode, EXT4_XATTR_INDEX_SECURITY,
				    name, value, len, 0);
	kfree(name);  /* 释放名称内存 */
	kfree(value);  /* 释放值内存 */
	return err;  /* 返回结果 */
}

/*
 * 安全扩展属性处理程序。
 */
struct xattr_handler ext4_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,  /* 扩展属性前缀 */
	.list	= ext4_xattr_security_list,  /* 列出扩展属性的函数 */
	.get	= ext4_xattr_security_get,  /* 获取扩展属性值的函数 */
	.set	= ext4_xattr_security_set,  /* 设置扩展属性值的函数 */
};
