#include "md5.h"

static const CV IV = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};

static const uint32_t T[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint32_t S[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

/**
* @brief MD5 哈希函数
* @param message 需要进行哈希的字符串
* @param message_len 需要进行哈希的字符串的长度
* @param message_bytes_len 信息的字节数
* @param message_block_bits_len 哈希函数所用信息块的比特数
*/
void MD5(char message[], uint64_t message_len, uint8_t *result) {
    // 先处理不需要填充的块
    uint64_t non_flled_block_num = message_len / 64;
    CV cv = IV;
    for (int i = 0; i < non_flled_block_num; ++i) {
        MB mb;
        for (int j = 0; j < 16; ++j) {
            mb.x[j] = 0;
            for (int k = 3; k >= 0; --k) {
                mb.x[j] = mb.x[j] << 8;
                mb.x[j] |= (uint8_t)message[64 * i + 4 * j + k];
            }
        }
        cv = HMD5(cv, mb);
    }
    // 再处理需要填充的块
    MB mb;
    uint64_t message_bits = message_len * 8;
    uint64_t message_remain = message_len % 64;

    if (message_remain) {
        // 可以填满一整个x
        int i = 0;
        for (; i < message_remain / 4; ++i) {
            mb.x[i] = 0;
            for (int j = 3; j >= 0; --j) {
                mb.x[i] = mb.x[i] << 8;
                mb.x[i] |= (uint8_t)message[64 * non_flled_block_num + 4 * i + j];
            }
        }

        // 填不满一整个x，则补1000..。能填满则直接填1000....
        int bytes_remain = message_remain % 4;
        mb.x[i] = 0;
        for (int j = 3; j >= 0; --j) {
            mb.x[i] = mb.x[i] << 8;
            if (j > bytes_remain) {
                continue;
            }
            else if (j == bytes_remain) {
                mb.x[i] |= 0x00000080;
            }
            else {
                mb.x[i] |= (uint8_t)message[64 * non_flled_block_num + 4 * i + j];
            }
        }
        ++i;
        // 判断该块是否还有位置填充信息长度
        // 如果有
        if (i <= 14) {
            for (; i < 14; ++i) {
                mb.x[i] = 0;
            }
            mb.x[15] = message_bits >> 32;
            mb.x[14] = message_bits & (uint32_t)0xffffffff;
            cv = HMD5(cv, mb);
        }
        // 如果没有则需要新增一个块
        else {
            for (; i < 16; ++i) {
                mb.x[i] = 0;
            }
            cv = HMD5(cv, mb);
            for (int i = 0; i < 14; ++i) {
                mb.x[i] = 0;
            }
            mb.x[14] = message_bits & (uint32_t)0xffffffff;
            mb.x[15] = message_bits >> 32;
            cv = HMD5(cv, mb);
        }
    }
    else {
        mb.x[0] = 0x00000080;
        for (int i = 1; i < 14; ++i) {
            mb.x[i] = 0;
        }
        mb.x[14] = message_bits & (uint32_t)0xffffffff;
        mb.x[15] = message_bits >> 32;
        cv = HMD5(cv, mb);
    }

    for (int i = 0; i < 4; ++i) {
        result[i] = 0;
        result[i] = (cv.a >> (8 * i)) & 0xff;
    }
    for (int i = 0; i < 4; ++i) {
        result[4 + i] = 0;
        result[4 + i] = (cv.b >> (8 * i)) & 0xff;
    }    
    for (int i = 0; i < 4; ++i) {
        result[8 + i] = 0;
        result[8 + i] = (cv.c >> (8 * i)) & 0xff;
    }    
    for (int i = 0; i < 4; ++i) {
        result[12 + i] = 0;
        result[12 + i] = (cv.d >> (8 * i)) & 0xff;
    }
}

/**
* @brief HMD5 函数
* @param cv HMD5 的CV输入
* @param mb message block
* @return 返回哈希后的CV结果
*/
CV HMD5(CV cv, MB mb) {
    CV origin_cv = cv;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 16; ++j) {
            switch (i)
            {
            case 0:
                cv.a = cv.b + CLS((cv.a + F(cv.b, cv.c, cv.d) + mb.x[j] + T[i * 16 + j]), S[i * 16 + j]);
                break;
            case 1:
                cv.a = cv.b + CLS((cv.a + G(cv.b, cv.c, cv.d) + mb.x[(1 + 5 * j) % 16] + T[i * 16 + j]), S[i * 16 + j]);
                break;
            case 2:
                cv.a = cv.b + CLS((cv.a + H(cv.b, cv.c, cv.d) + mb.x[(5 + 3 * j) % 16] + T[i * 16 + j]), S[i * 16 + j]);
                break;
            case 3:
                cv.a = cv.b + CLS((cv.a + I(cv.b, cv.c, cv.d) + mb.x[(7 * j) % 16] + T[i * 16 + j]), S[i * 16 + j]);
                break;
            default:
                break;
            }
            uint32_t temp = cv.d;
            cv.d = cv.c;
            cv.c = cv.b;
            cv.b = cv.a;
            cv.a = temp;
        }
    }
    cv.a += origin_cv.a;
    cv.b += origin_cv.b;
    cv.c += origin_cv.c;
    cv.d += origin_cv.d;
    return cv;
}

/**
* @brief 把长度为16 bytes的缓冲区以16进制形式顺序打印出来
* @param result MD5 哈希后的结果
*/
void print_result(uint8_t * result) {
    for (int i = 0; i < 16; ++i) {
        printf("%02x", result[i]);
    }
    printf("\n");
}