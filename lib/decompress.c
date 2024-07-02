/*
 * decompress.c
 *
 * Detect the decompression method based on magic number
 */

#include <linux/decompress/generic.h>

#include <linux/decompress/bunzip2.h>
#include <linux/decompress/unlzma.h>
#include <linux/decompress/inflate.h>
#include <linux/decompress/unlzo.h>

#include <linux/types.h>
#include <linux/string.h>

#ifndef CONFIG_DECOMPRESS_GZIP
# define gunzip NULL
#endif
#ifndef CONFIG_DECOMPRESS_BZIP2
# define bunzip2 NULL
#endif
#ifndef CONFIG_DECOMPRESS_LZMA
# define unlzma NULL
#endif
#ifndef CONFIG_DECOMPRESS_LZO
# define unlzo NULL
#endif

/**
 * compressed_formats - 预定义的压缩格式数组
 *
 * 这个数组包含了多种压缩格式的定义，每一项包括压缩格式的魔数、名称和解压缩函数指针。
 * 当解压缩函数需要根据输入数据的前缀判断压缩格式时，会使用这个数组进行匹配。
 */
static const struct compress_format {
	unsigned char magic[2];     // 压缩格式的魔数（前两个字节）
	const char *name;           // 压缩格式的名称
	decompress_fn decompressor; // 解压缩函数指针
} compressed_formats[] = {
	{ {037, 0213}, "gzip", gunzip },   // gzip 格式，对应的解压缩函数为 gunzip
	{ {037, 0236}, "gzip", gunzip },   // gzip 格式，对应的解压缩函数为 gunzip
	{ {0x42, 0x5a}, "bzip2", bunzip2 },// bzip2 格式，对应的解压缩函数为 bunzip2
	{ {0x5d, 0x00}, "lzma", unlzma },  // lzma 格式，对应的解压缩函数为 unlzma
	{ {0x89, 0x4c}, "lzo", unlzo },    // lzo 格式，对应的解压缩函数为 unlzo
	{ {0, 0}, NULL, NULL }             // 数组结束标志，magic 为 {0, 0} 表示结尾
};

/**
 * decompress_method - 根据输入数据选择解压缩函数
 * @inbuf: 指向输入数据缓冲区的指针
 * @len: 输入数据缓冲区的长度
 * @name: 输出参数，指向匹配的压缩格式名称的指针
 *
 * 根据输入缓冲区中的数据，查找匹配的压缩格式，并返回对应的解压缩函数。
 *
 * 返回值:
 *  - 如果找到匹配的压缩格式，返回该压缩格式的解压缩函数；
 *  - 如果未找到匹配的压缩格式或输入数据长度不足2字节，返回NULL。
 */
decompress_fn decompress_method(const unsigned char *inbuf, int len,
				const char **name)
{
	const struct compress_format *cf;

	if (len < 2)
		return NULL;	// 需要至少2字节的数据长度才能进行判断

	// 遍历已定义的压缩格式列表，查找匹配的压缩格式
	for (cf = compressed_formats; cf->name; cf++) {
		if (!memcmp(inbuf, cf->magic, 2))
			break;  // 找到匹配的压缩格式，跳出循环
	}

	if (name)
		*name = cf->name;  // 将匹配的压缩格式名称赋值给name指针

	return cf->decompressor;  // 返回匹配的压缩格式的解压缩函数指针
}
