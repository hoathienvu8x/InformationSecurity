#pragma once

#include <stdint.h>
#include <stdio.h>

typedef struct MD5_CV
{
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
} CV;

typedef struct Message_Block
{
    uint32_t x[16];
} MB;

#define F(b, c, d) ((b & c) | (~b & d))
#define G(b, c, d) ((b & d) | (c & ~d))
#define H(b, c, d) (b ^ c ^ d)
#define I(b, c, d) (c ^ (b | ~d))
#define CLS(x, s) ((x >> (32 - s)) | (x << s))

/**
* @brief MD5 哈希函数
* @param message 需要进行哈希的字符串
* @param message_len 需要进行哈希的字符串的长度
* @param message_bytes_len 信息的字节数
* @param message_block_bits_len 哈希函数所用信息块的比特数
*/
void MD5(char *message, uint64_t message_len, uint8_t *result);

/**
* @brief HMD5 函数
* @param cv HMD5 的CV输入
* @param mb message block
* @return 返回哈希后的CV结果
*/
CV HMD5(CV cv, MB mb);

/**
* @brief 把长度为16 bytes的缓冲区以16进制形式顺序打印出来
* @param result MD5 哈希后的结果
*/
void print_result(uint8_t * result);