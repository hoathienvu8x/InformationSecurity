#pragma once
#include <stdint.h>

/**
 * @brief 获得 uint64_t 的某一个位，最右边的低位的 pos 为0
 * @param chunk 以 uint64_t 为形式的块
 * @param pos 获得第 pos 位
 * @return 返回 uint64_t 从右边数起的第 pos 位，只包含0和1
 */
uint64_t get_bit(const uint64_t chunk, const int pos);

/**
 * @brief 设置 uint64_t 的某一个位，最右边的低位的 pos 为0
 * @param chunk 以 uint64_t 为形式的块指针
 * @param pos 要设置的第 pos 位
 * @param state 要设置成0或者1
 */
void set_bit(uint64_t *chunk, const int pos, const uint64_t state);

/**
 * @brief 将一个最大长度为64位块
 * @param data 以 uint64_t 为形式的块
 * @param len 该块的长度
 * @return len长的块的循环右移一位的结果
 */
uint64_t loop_right_shift(uint64_t data, int len);

/**
 * @brief 将以 uint64_t 存储的块转化为 uint8_t[8]，其中uint8_t[0]的最高位相当于 uint64_t 的最低位
 * @param input 要转换的 uint64_t 块
 * @param str 转换后字符流存储的缓冲区
 */
void uint64_to_char_str(uint64_t input, uint8_t str[8]);

/**
 * @brief 将以 uint8_t[8] 存储的块转化为 uint64_t ，其中uint8_t[0]的最高位相当于 uint64_t 的最低位
 * @param input 要转换的 uint8_t[8] 块
 * @return 转换后的 uint64_t 块
 */
uint64_t char_str_to_uint64(uint8_t str[8]);