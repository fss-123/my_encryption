#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// 宏定义：方便位操作 (DES专用)
// 获取64位数据的第 i 位 (i从1开始，1是最高位/最左边位)
#define GET_BIT_64(data, i) (((data) >> (64 - (i))) & 0x01)
// 设置64位数据的第 i 位为 val (i从1开始)
#define SET_BIT_64(data, i, val) \
    do { \
        if (val) (data) |= (1ULL << (64 - (i))); \
        else (data) &= ~(1ULL << (64 - (i))); \
    } while (0)

// 定义数据类型，使用标准C库中的固定宽度整数
typedef uint64_t uint64;
typedef int64_t int64;
typedef uint32_t uint32;
typedef uint8_t uint8;

// --- C 语言链接开始 ---
#ifdef __cplusplus
extern "C" {
#endif


// --- 核心数学函数声明 (用于RSA, Elgamal等) ---

// 1. 快速幂/模幂运算 (Modular Exponentiation)
uint64 power(uint64 base, uint64 exponent, uint64 modulus);

// 2. 扩展欧几里得算法 (Extended Euclidean Algorithm)
uint64 extended_gcd(uint64 a, uint64 b, int64* x, int64* y);

// 3. 模逆元 (Modular Inverse)
uint64 mod_inverse(uint64 a, uint64 m);

// --- 核心位操作函数声明 (用于DES, AES) ---

/**
 * 执行通用置换操作
 * @param input: 输入数据块
 * @param table: 置换表 (包含位索引，索引从1开始)
 * @param input_bits: 输入数据的总位数 (如 64, 56)
 * @param output_bits: 输出数据的总位数
 * @return 置换后的数据块
 */
uint64 general_permute(uint64 input, const uint8* table, int output_bits);

// --- 核心 AES 辅助函数声明 (针对 32 位字和小端序) ---

/**
 * AES 字加载：将 4 字节数组加载为一个 uint32 字。
 * 强制按小端序加载 (AES 标准)。
 */
void aes_load_word(uint32* dst, const uint8* src);

/**
 * AES 字存储：将一个 uint32 字存储为 4 字节数组。
 * 强制按小端序存储 (AES 标准)。
 */
void aes_store_word(uint8* dst, uint32 src);

void print_hex(const char* label, const uint8* data, size_t len);





#ifdef __cplusplus
}
#endif

#endif // UTILS_H#pragma once
