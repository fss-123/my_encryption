#include "utils.h"
#include <stdio.h>

// 1. 快速幂/模幂运算
uint64 power(uint64 base, uint64 exponent, uint64 modulus) {
    uint64 result = 1;
    base %= modulus;
    while (exponent > 0) {
        if (exponent & 1) {
            result = (result * base) % modulus;
        }
        exponent >>= 1;
        base = (base * base) % modulus;
    }
    return result;
}

// 2. 扩展欧几里得算法
uint64 extended_gcd(uint64 a, uint64 b, int64* x, int64* y) {
    if (a == 0) { *x = 0; *y = 1; return b; }
    int64 x1, y1;
    uint64 gcd = extended_gcd(b % a, a, &x1, &y1);
    // [关键修复] 必须强制转换为 int64！
    // 否则 (b/a) 是 uint64，与 int64 相乘会导致 x1 被错误地转为无符号数。
    *x = y1 - (int64)(b / a) * x1;

    *y = x1;
    return gcd;
}

// 3. 模逆元
uint64 mod_inverse(uint64 a, uint64 m) {
    int64 x, y;
    uint64 g = extended_gcd(a, m, &x, &y);
    if (g != 1) { return 0; }
    // [修复2 - 关键！] 
    // 问题：x 是 int64 (可能是负数), m 是 uint64。
    // 如果直接 x % m，x 会被转为无符号大数，导致结果错误。
    // 解决：将 m 强转为 int64，在有符号域内计算，确保处理负数正确。
    int64 m_signed = (int64)m;
    return (uint64)((x % m_signed + m_signed) % m_signed);
}

// --- 核心位操作函数实现 (用于DES, AES) ---
uint64 general_permute(uint64 input, const uint8* table, int output_bits) {
    uint64 output = 0;

    for (int i = 0; i < output_bits; i++) {
        // table[i] 是输入块中的位索引 (从1开始)
        int input_bit_pos = table[i];

        // 1. 提取输入块的对应位
        // 提取第 input_bit_pos 位的操作：
        // 实际位索引：64 - input_bit_pos
        uint64 bit = (input >> (64 - input_bit_pos)) & 1ULL;

        // 2. 将提取的位设置到输出块的当前位 i
        // 输出块的第 i 个位置 (从左到右，i从0开始) 对应实际位索引：63 - i
        if (bit) {
            output |= (1ULL << (63 - i));
        }
    }
    return output;
}

// --- 工具函数：打印 Hex ---
// 只要 utils.h 声明了它，就在这里实现。
// 确保 所有测试函数中没有这个函数的定义，否则会报 LNK2005。
void print_hex(const char* label, const uint8* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

// =======================================================
// --- AES 核心修复：强制使用大端序 (Big Endian) ---
// =======================================================

/**
 * AES 字加载：将 4 字节数组加载为一个 uint32 字。
 * 必须使用大端序 (MSB 在前)，以匹配 aes.cpp 中的移位逻辑。
 * src[0] -> MSB (最高位)
 * src[3] -> LSB (最低位)
 */
void aes_load_word(uint32* dst, const uint8* src) {
    *dst = ((uint32)src[0] << 24) |
        ((uint32)src[1] << 16) |
        ((uint32)src[2] << 8) |
        ((uint32)src[3]);
}

/**
 * AES 字存储：将一个 uint32 字存储为 4 字节数组。
 * 必须使用大端序 (MSB 在前)。
 */
void aes_store_word(uint8* dst, uint32 src) {
    dst[0] = (uint8)((src >> 24) & 0xFF); // MSB
    dst[1] = (uint8)((src >> 16) & 0xFF);
    dst[2] = (uint8)((src >> 8) & 0xFF);
    dst[3] = (uint8)(src & 0xFF);         // LSB
}
