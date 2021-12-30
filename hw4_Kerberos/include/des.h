#pragma once
#include "bits_operation.h"
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include <time.h>

#define DES_ENCRYPT 0
#define DES_DECRYPT 1

typedef struct
{
    // 执行permutation前的比特数
    int from_bits;
    // 执行permutation后的比特数
    int to_bits;
    int permutation_table[64];
} permutation_t;

/**
 * @brief 根据置换表 permutation_table，将 chunk 进行置换
 * @param perm 置换表，表中每个元素 perm[i] 为 e 表示对应位置 result[i] = chunk[e]
 * @param chunk 将被置换的数组
 * @return 置换后的数组
 */
uint64_t do_permutation(const permutation_t *perm, const uint64_t chunk);

/**
 * @brief 做 DES 的16次迭代和迭代后置换LR
 * @param key DES 的密钥
 * @param chunk 要做迭代的块
 * @param state 判断是加密还是解密，DES_ENCRYPT是加密，DES_ENCRYPT是解密
 * @return 执行完迭代置换的结果
 */
uint64_t do_iter_and_switch(uint64_t key, const uint64_t chunk, int state);

/**
 * @brief 做 DES 的 S-Box 选择
 * @note S-Box 选择函数是 6 位转 4 位的变换。
 * 假设 Si=(abcdef)2，那么 n=(af)2 确定行号，m=(bcde)2 确定列号
 * @param chunk 二进制位数为 6 的 Feistel 轮函数分组
 * @return 二进制位数为 4 的选择后的分组
 */
uint64_t do_sbox(const int boxs, const uint64_t chunk);

/**
 * @brief DES的feistel函数
 * @param old_right 对应于Ri-1
 * @param key 子密钥Ki
 * @return feistel函数的结果
 */
uint64_t feistel(const uint64_t old_right, const uint64_t key);

/**
 * @brief 生成一组子密钥
 * @param key DES 的密钥
 * @param subkey 子密钥数组的指针
 * @return 不返回值，结果会存储在subkey数组里
 */
void gernerate_subkey(uint64_t key, uint64_t subkey[]);

/**
 * @brief 执行 DES 的IP置换，循环迭代，IP逆置换过程
 * @param input 以 uint64_t 输入的一个64位块
 * @param key DES 的密钥
 * @param state 判断是加密还是解密，DES_ENCRYPT是加密，DES_ENCRYPT是解密
 * @return 加密或者解密的块
 */
uint64_t _des_process(uint64_t input, uint64_t key, int state);

/**
 * @brief DES 的加密函数
 * @param input 需要加密的明文字符流头指针
 * @param len 明文长度
 * @param output 加密后的密文的头指针
 * @param key 以 uint8_t[8] 为格式的密钥，uint8_t[0]最左边的二进制数对应于 uint64_t 二进制形式的最右一位
 * @return 返回加密后的密文长度
 */
int des_encrypt(uint8_t * input, int len, uint8_t * output, uint8_t key[8]);

/**
 * @brief DES 的解密函数
 * @param input 需要解密的密文字符流头指针
 * @param len 密文长度
 * @param output 解密后的明文的头指针
 * @param key 以 uint8_t[8] 为格式的密钥，uint8_t[0]最左边的二进制数对应于 uint64_t 二进制形式的最右一位
 * @return 解密后的明文长度
 */
int des_decrypt(uint8_t * input, int len, uint8_t * output, uint8_t key[8]);

/**
 * @brief 随机生成一个密钥
 * @param key 储存生成密钥的缓冲区
 */
void generate_key(uint8_t key[8]);

/**
 * @brief 纠正一个密钥
 * @param key 储存生成密钥的缓冲区
 */
void correct_key(uint8_t key[8]);

/**
* @brief 把长度为8 bytes的缓冲区以16进制形式顺序打印出来
* @param result key
*/
void print_key(uint8_t * key);

extern const permutation_t PERM_IP;
extern const permutation_t PERM_IPINV;
extern const permutation_t PERM_E_EXTENSION;
extern const int S_BOX[8][4][16];
extern const permutation_t PERM_P;
extern const permutation_t PERM_PC1;
extern const permutation_t PERM_PC2;