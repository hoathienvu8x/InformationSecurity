#include "bits_operation.h"

/**
 * @brief 获得 uint64_t 的某一个位，最右边的低位的 pos 为0
 * @param chunk 以 uint64_t 为形式的块
 * @param pos 获得第 pos 位
 * @return 返回 uint64_t 从右边数起的第 pos 位，只包含0和1
 */
uint64_t get_bit(const uint64_t chunk, const int pos) {
    uint64_t result = chunk >> pos & (uint64_t)1;
    return result;
}

/**
 * @brief 设置 uint64_t 的某一个位，最右边的低位的 pos 为0
 * @param chunk 以 uint64_t 为形式的块指针
 * @param pos 要设置的第 pos 位
 * @param state 要设置成0或者1
 */
void set_bit(uint64_t *chunk, const int pos, const uint64_t state) {
    if (state) {
        *chunk = *chunk | (state << pos);
    }
    else {
        *chunk = *chunk & (~((uint64_t)1 << pos));
    }
}

/**
 * @brief 将一个最大长度为64位块
 * @param data 以 uint64_t 为形式的块
 * @param len 该块的长度
 * @return len长的块的循环右移一位的结果
 */
uint64_t loop_right_shift(uint64_t data, int len) {
    uint64_t temp = data & 1;
    data = data >> 1;
    data |= temp << (len - 1);
    return data;
}

/**
 * @brief 将以 uint64_t 存储的块转化为 char[8]，其中char[0]的最高位相当于 uint64_t 的最低位
 * @param input 要转换的 uint64_t 块
 * @param str 转换后字符流存储的缓冲区
 */
void uint64_to_char_str(uint64_t input, char str[8]) {
    for (int i = 0; i < 8; ++i) {
        str[i] &= 0;
    }
    for (int i = 0; i < 64; ++i) {
        int state = get_bit(input, i);
        str[i / 8] |= state << (7 - (i % 8));
    }
}

/**
 * @brief 将以 char[8] 存储的块转化为 uint64_t ，其中char[0]的最高位相当于 uint64_t 的最低位
 * @param input 要转换的 char[8] 块
 * @return 转换后的 uint64_t 块
 */
uint64_t char_str_to_uint64(char str[8]) {
    uint64_t result = 0;
    for (int i = 0; i < 64; ++i) {
        uint64_t ch = str[i / 8];
        uint64_t state = (ch >> (7 - (i % 8))) & 1;
        set_bit(&result, i, state);
    }
    return result;
}
