#pragma once
#include <gmp.h>

/**
* @brief 生成一对公私钥
* @param k 钥匙的位数
* @param n 密钥中 n 的引用
* @param e 公钥中 e 的引用
* @param d 私钥中 e 的引用
*/
void generate_key(int k, mpz_t n, mpz_t e, mpz_t d);

/**
* @brief 对字符串 M(message) 加密
* @param key_n 公钥的 n
* @param public_key_e 公钥的 e
* @param key_len 密钥长度
* @param M 字符串缓冲区的地址，注意，如果缓冲区为 buffer[], 那应该传入&buffer，而且缓冲区必须用 malloc 分配，加密后该函数会释放原来的缓冲区并新分配一个缓冲区到M
*/
void rsa_encrypt(mpz_t key_n, mpz_t public_key_e, int key_len, char ** M);

/**
* @brief 对字符串 C(cipertext) 解密
* @param key_n 公钥的 n
* @param public_key_d 私钥的 d
* @param key_len 密钥长度
* @param C 字符串缓冲区的地址，注意，如果缓冲区为 buffer[], 那应该传入&buffer，而且缓冲区必须用 malloc 分配，加密后该函数会释放原来的缓冲区并新分配一个缓冲区到C
*/
void rsa_decrype(mpz_t key_n, mpz_t private_key_d, int key_len, char ** C);

/**
* @brief 将字符串转成一个大数
* @param str 要转换的字符串
* @param len 密钥长度
* @param result 转化后的大数结果的引用
*/
void os2ip(char * str, int len, mpz_t result);

/**
* @brief 将大数转成一个字符串
* @param x 要转换的大数
* @param len 密钥长度
* @param result 转化后的字符串
*/
void i2osp(mpz_t x, int len, char * result);

/**
* @brief RSA 中对大数加解密算法
* @param key_n 公私钥的 n
* @param e 公钥中 e 或私钥中 d 的引用
* @param message 需要加解密的大数
* @param result 加解密后的结果
*/
void rsa_adp_aep(mpz_t key_n, mpz_t e, mpz_t m, mpz_t result);