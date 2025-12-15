#ifndef AES_H
#define AES_H

#include "utils.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// --- AES 核心常量 ---

// AES 块大小 (State 矩阵为 4x4 字节)
#define AES_BLOCK_SIZE 16

// 密钥长度 (Nk: 密钥字数, Key Size in bytes)
#define AES_KEY_128 16 // 128 bit = 4 words
#define AES_KEY_192 24 // 192 bit = 6 words
#define AES_KEY_256 32 // 256 bit = 8 words

// 轮数 (Nr)
#define AES_ROUNDS_128 10
#define AES_ROUNDS_192 12
#define AES_ROUNDS_256 14
#define AES_MAX_ROUNDS AES_ROUNDS_256 // 最大轮数

// 密钥扩展后的总字数: (Nr + 1) * 4 words
#define AES_EXPANDED_WORDS (AES_MAX_ROUNDS + 1) * 4

// --- 数据结构 ---

// AES 密钥调度结构体
// 存储扩展后的轮密钥 (W)
typedef struct {
    uint32 W[AES_EXPANDED_WORDS]; // 扩展密钥数组，按 word 存储
    int rounds;                   // 实际使用的轮数 (10, 12, 或 14)
} AES_Schedule;

// --- C 语言链接开始 ---
#ifdef __cplusplus
extern "C" {
#endif

    // --- 核心函数声明 ---

    /**
     * 1. 密钥扩展 (Key Expansion)
     * 根据原始密钥生成所有轮所需的轮密钥。
     *
     * @param raw_key_bytes: 原始密钥字节数组 (16, 24 或 32 字节)
     * @param key_size: 密钥长度 (AES_KEY_128/192/256)
     * @param schedule: 存储扩展密钥的结构体
     * @return true 成功，false 失败
     */
    bool aes_key_expansion(const uint8* raw_key_bytes, size_t key_size, AES_Schedule* schedule);

    /**
     * 2. AES 加密 (ECB 模式的单块操作)
     *
     * @param input_block: 16 字节明文
     * @param output_block: 16 字节密文
     * @param schedule: 扩展密钥
     */
    void aes_encrypt(const uint8* input_block, uint8* output_block, const AES_Schedule* schedule);

    /**
     * 3. AES 解密 (ECB 模式的单块操作)
     * @param input_block: 16 字节密文
     * @param output_block: 16 字节明文
     * @param schedule: 扩展密钥
     */
    void aes_decrypt(const uint8* input_block, uint8* output_block, const AES_Schedule* schedule);


    // --- C 语言链接结束 ---
#ifdef __cplusplus
}
#endif

#endif // AES_H
