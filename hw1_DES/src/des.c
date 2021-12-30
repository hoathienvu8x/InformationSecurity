#include "des.h"

/**
 * @brief 根据置换表 permutation_table，将 chunk 进行置换
 * @param perm 置换表，表中每个元素 perm[i] 为 e 表示对应位置 result[i] = chunk[e]
 * @param chunk 将被置换的数组
 * @return 置换后的数组
 */
uint64_t do_permutation(const permutation_t *perm, const uint64_t chunk) {
    uint64_t result = 0;
    for (int i = 0; i < perm->to_bits; ++i) {
        set_bit(&result, i, get_bit(chunk, perm->permutation_table[i]));
    }
    return result;
}

/**
 * @brief 做 DES 的16次迭代和迭代后置换LR
 * @param key DES 的密钥
 * @param chunk 要做迭代的块
 * @param state 判断是加密还是解密，DES_ENCRYPT是加密，DES_ENCRYPT是解密
 * @return 执行完迭代置换的结果
 */
uint64_t do_iter_and_switch(uint64_t key, const uint64_t chunk, int state) {
    uint32_t old_left, old_right, left, right;
    old_left = chunk;
    old_right = chunk >> 32;

    uint64_t subkey[16], inv_subkey[16];
    gernerate_subkey(key, subkey);
    for (int i = 0; i < 16; ++i) {
        inv_subkey[i] = subkey[15 - i];
    }

    for (int i = 0; i < 16; ++i) {
        left = old_right;
        if (state) {
            right = old_left ^ feistel(old_right, inv_subkey[i]);
        }
        else {
            right = old_left ^ feistel(old_right, subkey[i]);
        }

        old_left = left;
        old_right = right;
    }

    uint64_t result = right;
    result |= (uint64_t)left << 32;
    return result;
}

/**
 * @brief 做 DES 的 S-Box 选择
 * @note S-Box 选择函数是 6 位转 4 位的变换。
 * 假设 Si=(abcdef)2，那么 n=(af)2 确定行号，m=(bcde)2 确定列号
 * @param chunk 二进制位数为 6 的 Feistel 轮函数分组
 * @return 二进制位数为 4 的选择后的分组
 */
uint64_t do_sbox(const int boxs, const uint64_t chunk) {
    uint64_t col = 0;
    for (int i = 0; i < 4; ++i) {
        set_bit(&col, i, get_bit(chunk, 4 - i));
    }
    uint64_t inv = S_BOX[boxs][((chunk & 1) << 1) | ((chunk >> 5) & 1)][col];
    uint64_t result = 0;
    for (int i = 0; i < 4; ++i) {
        set_bit(&result, i, get_bit(inv, 3 - i));
    }
    return result;
}

/**
 * @brief DES的feistel函数
 * @param old_right 对应于Ri-1
 * @param key 子密钥Ki
 * @return feistel函数的结果
 */
uint64_t feistel(const uint64_t old_right, const uint64_t key) {
    uint64_t right = do_permutation(&PERM_E_EXTENSION, old_right);
    right ^= key;
    uint64_t result = 0;
    for (int i = 7; i >= 0; --i) {
        result = result << 4;
        result |= do_sbox(i, (right >> (6 * i)) & 0x3F);
    }
    return do_permutation(&PERM_P, result);
}

/**
 * @brief 生成一组子密钥
 * @param key DES 的密钥
 * @param subkey 子密钥数组的指针
 * @return 不返回值，结果会存储在subkey数组里
 */
void gernerate_subkey(uint64_t key, uint64_t subkey[]) {
    key = do_permutation(&PERM_PC1, key);
    uint64_t C, D;
    C = key & 0xFFFFFFF;
    D = key >> 28;
    for (int i = 1; i <= 16; ++i) {
        C = loop_right_shift(C, 28);
        D = loop_right_shift(D, 28);
        if (i != 1 && i != 2 && i != 9 && i != 16) {
            C = loop_right_shift(C, 28);
            D = loop_right_shift(D, 28);
        }
        uint64_t temp = (D << 28) | C;
        subkey[i - 1] = do_permutation(&PERM_PC2, temp);
    }

}

/**
 * @brief 执行 DES 的IP置换，循环迭代，IP逆置换过程
 * @param input 以 uint64_t 输入的一个64位块
 * @param key DES 的密钥
 * @param state 判断是加密还是解密，DES_ENCRYPT是加密，DES_ENCRYPT是解密
 * @return 加密或者解密的块
 */
uint64_t _des_process(uint64_t input, uint64_t key, int state) {
    uint64_t result = do_permutation(&PERM_IP, input);
    result = do_iter_and_switch(key, result, state);
    return do_permutation(&PERM_IPINV, result);
}

/**
 * @brief DES 的加密函数
 * @param input 需要加密的明文字符流头指针
 * @param output 加密后的密文的头指针
 * @param key 以 char[8] 为格式的密钥，char[0]最左边的二进制数对应于 uint64_t 二进制形式的最右一位
 * @return 没有返回，结果在 output 中
 */
void des_encrypt(char * input, char * output, char key[8]) {
    int remain = 8 - strlen(input) % 8;
    int origin_len = strlen(input);
    int after_encrypt_byte_num = (strlen(input) / 8 + 1) * 8;
    char * str = malloc(after_encrypt_byte_num + 1);
    str[after_encrypt_byte_num] = 0;
    strcpy(str, input);
    for (int i = 0; i < remain; ++i) {
        str[origin_len + i] = remain;
    }

    for (int i = 0; i < after_encrypt_byte_num / 8; ++i) {
        uint64_t temp =  _des_process(char_str_to_uint64(str + 8 * i), char_str_to_uint64(key), DES_ENCRYPT);
        uint64_to_char_str(temp, output + 8 * i);
    }
    output[after_encrypt_byte_num] = 0;
    free(str);
}

/**
 * @brief DES 的解密函数
 * @param input 需要加密的密文字符流头指针
 * @param output 解密后的明文的头指针
 * @param key 以 char[8] 为格式的密钥，char[0]最左边的二进制数对应于 uint64_t 二进制形式的最右一位
 * @return 没有返回，结果在 output 中
 */
void des_decrypt(char * input, char * output, char key[8]) {
    int len = strlen(input);
    char * str = malloc(len);
    for (int i = 0; i < len / 8; ++i) {
        uint64_t temp =  _des_process(char_str_to_uint64(input + 8 * i), char_str_to_uint64(key), DES_DECRYPT);
        uint64_to_char_str(temp, str + 8 * i);
    }
    int remain = str[len - 1];
    str[len - remain] = 0;
    strcpy(output, str);
    free(str);
}

/**
 * @brief 随机生成一个密钥
 * @param key 储存生成密钥的缓冲区
 */
void generate_key(char key[8]) {
    srand((unsigned)time(NULL));
    uint64_t r = rand();
    r = r << 32;
    r |= (uint64_t)rand();
    r = loop_right_shift(r, 64);
    for (int i = 0; i < 8; ++i) {
        int ones_count = 0;
        for (int j = 0; j < 8; ++j) {
            if (get_bit(r, 8 * i + j)) {
                ones_count++;
            }
            if (ones_count % 2 == 0) {
                set_bit(&r, i * 8 + 7, 1);
            }
        }
    }
    uint64_to_char_str(r, key);

}

const permutation_t PERM_IP = {
    64, 64,
    {
        57, 49, 41, 33, 25, 17,  9,  1,
        59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5,
        63, 55, 47, 39, 31, 23, 15,  7,
        56, 48, 40, 32, 24, 16,  8,  0,
        58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4,
        62, 54, 46, 38, 30, 22, 14,  6
    }
};

const permutation_t PERM_IPINV = {
    64, 64,
    {
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25,
        32,  0, 40,  8, 48, 16, 56, 24
    }
};

const permutation_t PERM_E_EXTENSION = {
    32, 48,
    {
        31,  0,  1,  2,  3,  4,
         3,  4,  5,  6,  7,  8,
         7,  8,  9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31,  0
    }
};

const int S_BOX[8][4][16] = {
    {
        { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7 },
        {  0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
        {  4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
        { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 },
    },
    {
        { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10 },
        {  3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
        {  0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
        { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 },
    },
    {
        { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8 },
        { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
        { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
        {  1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 },
    },
    {
        {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
        { 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
        { 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
        {  3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 },
    },
    {
        {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9 },
        { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
        {  4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
        { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 },
    },
    {
        { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11 },
        { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 },
        {  9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 },
        {  4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 },
    },
    {
        {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1 },
        { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
        {  1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
        {  6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 },
    },
    {
        { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
        {  1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
        {  7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
        {  2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 },
    },
};

const permutation_t PERM_P = {
    32, 32,
    {
        15,  6, 19, 20,
        28, 11, 27, 16,
         0, 14, 22, 25,
         4, 17, 30,  9,
         1,  7, 23, 13,
        31, 26,  2,  8,
        18, 12, 29,  5,
        21, 10,  3, 24
    }
};

const permutation_t PERM_PC1 = {
    64, 56,
    {
        56, 48, 40, 32, 24, 16,  8,
         0, 57, 49, 41, 33, 25, 17,
         9,  1, 58, 50, 42, 34, 26,
        18, 10,  2, 59, 51, 43, 35,
        62, 54, 46, 38, 30, 22, 14,
         6, 61, 53, 45, 37, 29, 21,
        13,  5, 60, 52, 44, 36, 28,
        20, 12,  4, 27, 19, 11,  3
    }
};

const permutation_t PERM_PC2 = {
    56, 48,
    {
        13, 16, 10, 23,  0,  4,
         2, 27, 14,  5, 20,  9,
        22, 18, 11,  3, 25,  7,
        15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    }
};