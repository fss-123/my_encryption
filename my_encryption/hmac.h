#ifndef HMAC_H
#define HMAC_H

#include "utils.h"
#include "hash.h" // 依赖 SHA-256
#include <stdint.h>
#include <stddef.h>

// HMAC-SHA256 的输出长度等于 SHA256 的摘要长度 (32字节)
#define HMAC_OUTPUT_SIZE SHA256_BLOCK_SIZE

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * 计算 HMAC-SHA256
     * @param key: 密钥
     * @param key_len: 密钥长度
     * @param msg: 消息数据
     * @param msg_len: 消息长度
     * @param output: 输出缓冲区 (至少 32 字节)
     */
    void hmac_sha256(const uint8* key, size_t key_len,
        const uint8* msg, size_t msg_len,
        uint8* output);

#ifdef __cplusplus
}
#endif

#endif // HMAC_H#pragma once
