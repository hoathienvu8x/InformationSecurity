#include "rsa.h"
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>

/**
* @brief 生成一对公私钥
* @param k 钥匙的位数
* @param n 密钥中 n 的引用
* @param e 公钥中 e 的引用
* @param d 私钥中 e 的引用
*/
void generate_key(int k, mpz_t n, mpz_t e, mpz_t d) {
    gmp_randstate_t grt;
    gmp_randinit_default(grt);
    gmp_randseed_ui(grt, time(NULL)); 
    mpz_t p_lb, q_lb, n_lb, p_hb, q_hb, p, q, f, temp;
    mpz_init(p_lb);
    mpz_init(q_lb);    
    mpz_init(p_hb);
    mpz_init(q_hb);
    mpz_init(n_lb);
    mpz_init(p);
    mpz_init(q);
    mpz_init(f);
    mpz_init(temp);
    mpz_ui_pow_ui(p_lb, 2, (k + 1) / 2 - 1);
    mpz_ui_pow_ui(q_lb, 2, k - (k + 1) / 2 - 1);
    mpz_ui_pow_ui(n_lb, 2, k - 1);
    mpz_ui_pow_ui(p_hb, 2, (k + 1) / 2);
    mpz_ui_pow_ui(q_hb, 2, k - (k + 1) / 2);
    // step 1 是参数
    // strp 7
    mpz_set_ui(e, 65537);
    // step 3
    while (1) {
        mpz_urandomb(q, grt, (k - 1) / 2);
        if (mpz_cmp(q_lb, q) > 0) {
            mpz_add(q, q, q_lb);
        }  
        mpz_nextprime(q, q);
        if (mpz_cmp(q, q_hb) >= 0) {
            continue;
        }
        break;
    }
    
    while (1) {
        // step 2
        mpz_urandomb(p, grt, (k + 1) / 2);
        if (mpz_cmp(p_lb, p) > 0) {
            mpz_add(p, p, p_lb);
        }
        mpz_nextprime(p, p);
        if (mpz_cmp(p, p_hb) >= 0) {
            continue;
        }

        // step 4
        if (mpz_cmp(p, q) >= 0) {
            mpz_sub(temp, p, q);
        } 
        else {
            mpz_sub(temp, q, p);
        }
        if (mpz_sizeinbase(temp, 2) <= ((k/2 - 100 < k / 3) ? k/2 - 100 : k / 3)) {
            continue;
        }

        // step 5
        mpz_mul(n, p, q);
        if (mpz_cmp(n, n_lb) < 0) {
            continue;
        }

        // step 8
        mpz_sub_ui(p, p, 1);
        mpz_sub_ui(q, q, 1);
        mpz_mul(f, p, q);
        mpz_invert(d, e, f);
        if (mpz_sizeinbase(d, 2) <= k / 2) {
            continue;
        }
        break;
    }
    mpz_clear(p_lb);
    mpz_clear(q_lb);    
    mpz_clear(p_hb);
    mpz_clear(q_hb);
    mpz_clear(n_lb);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(f);
    mpz_clear(temp);
}

/**
* @brief 对字符串 M(message) 加密
* @param key_n 公钥的 n
* @param public_key_e 公钥的 e
* @param key_len 密钥长度
* @param M 字符串缓冲区的地址，注意，如果缓冲区为 buffer[], 那应该传入&buffer，而且缓冲区必须用 malloc 分配，加密后该函数会释放原来的缓冲区并新分配一个缓冲区到M
*/
void rsa_encrypt(mpz_t key_n, mpz_t public_key_e, int key_len, char ** M) {
    int m_len = strlen(*M);
    if (m_len > key_len - 11) {
        fprintf(stderr, "message too long\n");
        exit(1);
    }

    // 进行编码，填充字符串至 key_len 长度
    char * EM = malloc(key_len + 1);
    EM[0] = 0x00;
    EM[1] = 0x02;
    srand((unsigned)time(NULL));
    for (int i = 0; i < key_len - m_len - 3; ++i) {
        EM[2 + i] = rand() % 255 + 1;
    }
    EM[key_len - m_len - 1] = 0x00;
    strcpy(EM + key_len - m_len, *M);

    mpz_t m;
    mpz_t c;
    mpz_init(m);
    mpz_init(c);

    // 将字符串转换为大数
    os2ip(EM, key_len, m);
    // 执行 RSA 核心，将大数加密
    rsa_adp_aep(key_n, public_key_e, m, c);
    // 将加密后的大数转换为字符串
    i2osp(c, key_len, EM);
    // 将原来的缓冲区换成新的缓冲区
    free(*M);
    *M = EM;
    mpz_clear(m);
    mpz_clear(c);
}

/**
* @brief 对字符串 C(cipertext) 解密
* @param key_n 公钥的 n
* @param public_key_d 私钥的 d
* @param key_len 密钥长度
* @param C 字符串缓冲区的地址，注意，如果缓冲区为 buffer[], 那应该传入&buffer，而且缓冲区必须用 malloc 分配，加密后该函数会释放原来的缓冲区并新分配一个缓冲区到C
*/
void rsa_decrype(mpz_t key_n, mpz_t private_key_d, int key_len, char ** C) {
    if (key_len < 11) {
        fprintf(stderr, "decryption error\n");
        exit(1);
    }

    mpz_t m;
    mpz_t c;
    mpz_init(m);
    mpz_init(c);
    // 将字符串转换为大数
    os2ip(*C, key_len, c);
    // 执行 RSA 核心，将大数加密
    rsa_adp_aep(key_n, private_key_d, c, m);
    // 将加密后的大数转换为字符串
    i2osp(m, key_len, *C);
    mpz_clear(m);
    mpz_clear(c);
    // 检查解密的格式是否符合标准
    if ((*C)[0] != 0x00 || (*C)[1] != 0x02) {
        fprintf(stderr, "decryption error\n");
        exit(1);
    }

    int i = 2, ps_len = 0;
    for (; (*C)[i] != 0x00 && i < key_len; ++i, ++ps_len);
    ++i;
    if (ps_len < 8 || i >= key_len) {
        fprintf(stderr, "decryption error\n");
        exit(1);
    }

    char * message = malloc(key_len - i + 1);
    message[key_len - i] = 0;
    strncpy(message, *C + i, key_len - i);
    // 将原来的缓冲区换成新的缓冲区
    free(*C);
    *C = message;
}

/**
* @brief 将字符串转成一个大数
* @param str 要转换的字符串
* @param len 密钥长度
* @param result 转化后的大数结果的引用
*/
void os2ip(char * str, int len, mpz_t result) {
    mpz_t pow;
    mpz_init(pow);

    for (int i = 0; i < len; ++i) {
        mpz_set_ui(pow, 0);
        mpz_ui_pow_ui(pow, 256, len - i - 1);
        mpz_mul_ui(pow, pow, (uint8_t)str[i]);
        mpz_add(result, result, pow);
    }
    mpz_clear(pow);
}

/**
* @brief 将大数转成一个字符串
* @param x 要转换的大数
* @param len 密钥长度
* @param result 转化后的字符串
*/
void i2osp(mpz_t x, int len, char * result) {
    mpz_t temp;
    mpz_init_set_ui(temp, 256);
    mpz_pow_ui(temp, temp, len);
    if (!(mpz_cmp(x, temp) < 0)) {
        fprintf(stderr, "integer too large\n");
        exit(1);
    }
    result[len] = 0;
    for (int i = len - 1; i >= 0; --i) {
        result[i] = 0;
        result[i] |= mpz_fdiv_q_ui(x, x, 256);
    }
}

/**
* @brief RSA 中对大数加解密算法
* @param key_n 公私钥的 n
* @param e 公钥中 e 或私钥中 d 的引用
* @param message 需要加解密的大数
* @param result 加解密后的结果
*/
void rsa_adp_aep(mpz_t key_n, mpz_t e, mpz_t message, mpz_t result) {
    if (mpz_cmp_ui(message, 0) < 0 || mpz_cmp(message, key_n) >= 0) {
        fprintf(stderr, "message representative out of range\n");
        exit(1);
    }

    mpz_powm(result, message, e, key_n);
}