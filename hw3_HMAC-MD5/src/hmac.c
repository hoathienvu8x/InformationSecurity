#include "hmac.h"

static const uint8_t ipad = 0x36;
static const uint8_t opad = 0x5c;

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
void HMAC(void (*H)(char *, uint64_t, uint8_t *), char * message, uint64_t message_bytes_len, uint64_t message_block_bits_len, uint8_t * key, uint64_t key_len, uint8_t * result) {
    uint64_t message_block_bytes_len = message_block_bits_len / 8;
    // 生成K+
    uint8_t * k_plus = malloc(message_block_bytes_len);
    memset(k_plus + key_len, 0, message_block_bytes_len - key_len);
    memcpy(k_plus, key, key_len);
    // 生成Si和So
    uint8_t * si = malloc(message_block_bytes_len);
    uint8_t * so = malloc(message_block_bytes_len);
    for (int i = 0; i < message_block_bytes_len; ++i) {
        si[i] = k_plus[i] ^ ipad;
        so[i] = k_plus[i] ^ opad;
    }
    // 将Si和message拼接起来
    uint8_t * si_m = malloc(message_block_bytes_len + message_bytes_len);
    memcpy(si_m, si, message_block_bytes_len);
    memcpy(si_m + message_block_bytes_len, message, message_bytes_len);
    // 对拼接起来的 Si || message 进行第一次哈希
    (*H)(si_m, message_block_bytes_len + message_bytes_len, result);
    // 将 So 和第一次哈希结果拼起来
    uint8_t * so_h = malloc(message_block_bytes_len + 16);
    memcpy(so_h, so, message_block_bytes_len);
    memcpy(so_h + message_block_bytes_len, result, 16);
    // 对 So 和第一次哈希拼接结果进行第二次哈希
    (*H)(so_h, message_block_bytes_len + 16, result);
    free(k_plus);
    free(si);
    free(so);
    free(si_m);
    free(so_h);
}
