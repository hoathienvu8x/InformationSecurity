#pragma once
#include <stdint.h>
#include <malloc.h>
#include <memory.h>

/**
* @brief HMAC 函数
* @param H 用于 HMAC 的哈希函数
* @param message 需要进行 HMAC 消息认证的信息
* @param message_bytes_len 信息的字节数
* @param message_block_bits_len 哈希函数所用信息块的比特数
* @param key 共享密钥字符串
* @param key_len 共享密钥长度
* @param result HMAC 的结果，如果使用 MD5 算法则需要一个16bytes的缓冲区
*/
void HMAC(void (*H)(char *, uint64_t, uint8_t *), char * message, uint64_t message_bytes_len, uint64_t message_block_bits_len, uint8_t * key, uint64_t key_len, uint8_t * result);
