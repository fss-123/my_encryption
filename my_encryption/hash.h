#ifndef HASH_H
#define HASH_H

#include "utils.h"
#include <stdint.h>
#include <stddef.h>

// SHA-256 输出大小：256位 = 32字节
#define SHA256_BLOCK_SIZE 32

// 上下文结构体：保存哈希计算的中间状态
typedef struct {
    uint8 data[64];     // 当前处理的数据块缓冲区 (512位)
    uint32 datalen;     // 缓冲区当前已填入的数据长度
    uint64 bitlen;      // 处理过的总比特数 (用于最后的长度填充)
    uint32 state[8];    // 8个 32位 内部状态寄存器 (A..H)
} SHA256_CTX;

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * 1. 初始化哈希上下文
     * 设置初始哈希值 (H0 ~ H7)
     */
    void sha256_init(SHA256_CTX* ctx);

    /**
     * 2. 更新哈希状态
     * 传入数据，如果缓冲区满了就进行一次变换 (Transform)
     * @param data: 输入数据
     * @param len: 数据长度
     */
    void sha256_update(SHA256_CTX* ctx, const uint8* data, size_t len);

    /**
     * 3. 结束哈希计算
     * 进行填充 (Padding)，追加长度信息，计算最终哈希值
     * @param hash: 输出的 32 字节摘要
     */
    void sha256_final(SHA256_CTX* ctx, uint8 hash[SHA256_BLOCK_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // HASH_H#pragma once
