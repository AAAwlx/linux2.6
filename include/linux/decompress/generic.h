#ifndef DECOMPRESS_GENERIC_H
#define DECOMPRESS_GENERIC_H

typedef int (*decompress_fn) (unsigned char *inbuf, int len,
			      int(*fill)(void*, unsigned int),
			      int(*flush)(void*, unsigned int),
			      unsigned char *outbuf,
			      int *posp,
			      void(*error)(char *x));

/* inbuf - 输入缓冲区
 *len - inbuf 中预读数据的 len
 *fill - 空时填充 inbuf 的函数
 *flush - 写出 outbuf 的函数
 *outbuf - 输出缓冲区
 *posp - 如果非空，输入位置（读取的字节数）将为
 * 返回这里
 *
 *如果len != 0，inbuf应该包含所有必要的输入数据，并填充
 *应该为NULL
 *如果len = 0，inbuf可以为NULL，在这种情况下解压缩器将分配
 *输入缓冲区。  如果 inbuf != NULL 它必须至少为 XXX_IOBUF_SIZE 字节。
 *fill 将被调用（重复...）来读取数据，最多 XXX_IOBUF_SIZE
 *每次调用应读取字节数。  用适当的解压器替换 XXX
 *名称，即 LZMA_IOBUF_SIZE。
 *
 *如果flush = NULL，outbuf必须足够大以缓冲所有预期的
 *输出。  如果flush！= NULL，输出缓冲区将由
 *decompressor (outbuf = NULL)，并且会调用flush函数
 *在适当的时间刷新输出缓冲区（解压缩器和流
 *取决于）
 */


/* Utility routine to detect the decompression method */
decompress_fn decompress_method(const unsigned char *inbuf, int len,
				const char **name);

#endif
