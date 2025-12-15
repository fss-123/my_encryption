#ifndef DES_H
#define DES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h> // 包含 size_t
#include "utils.h"  // <<< 关键修复：引入 utils.h 获得 uint32/uint64/uint8 类型

// DES 块大小和密钥大小（字节）
#define DES_BLOCK_SIZE 8
#define DES_KEY_SIZE 8
#define DES_ROUNDS 16

// 定义数据类型：使用 utils.h 中的 typedef
typedef uint64 DES_Block;
typedef uint64 DES_Key;

// DES 密钥调度结构体
typedef struct {
    uint64 K[DES_ROUNDS]; // 存储16个48位的子密钥
} DES_Subkeys;

// --- C 语言链接开始 (确保与源文件链接成功) ---
#ifdef __cplusplus
extern "C" {
#endif
// --- 核心函数声明 ---

// 1. 密钥调度 (Key Schedule)
// 输入：64位原始密钥
// 输出：16个48位子密钥
void des_key_schedule(DES_Key raw_key, DES_Subkeys* subkeys);

// 2. DES 加密
// block: 64位明文块
// subkeys: 16个子密钥
// 返回：64位密文块
DES_Block des_encrypt_block(DES_Block block, const DES_Subkeys* subkeys);

// 3. DES 解密
// block: 64位密文块
// subkeys: 16个子密钥
// 返回：64位明文块
DES_Block des_decrypt_block(DES_Block block, const DES_Subkeys* subkeys);

// 4. DES 高级模式加密 (例如：ECB模式)
// in_data: 输入数据
// out_data: 输出数据
// length: 数据长度（字节）
// key: 8字节密钥
// is_encrypt: true为加密，false为解密
bool des_ecb_process(const uint8_t* in_data, uint8_t* out_data, size_t length, const uint8_t* key, bool is_encrypt);



#ifdef __cplusplus
}
#endif
#endif // DES_H#pragma once
