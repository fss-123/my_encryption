#include "hmac.h"
#include <string.h>
#include <stdlib.h>

// SHA-256 的内部处理块大小是 512 位 = 64 字节
#define SHA256_INPUT_BLOCK_SIZE 64

void hmac_sha256(const uint8* key, size_t key_len,
    const uint8* msg, size_t msg_len,
    uint8* output) {

    SHA256_CTX ctx;
    uint8 k_prime[SHA256_INPUT_BLOCK_SIZE]; // 处理后的密钥 K'
    uint8 k_ipad[SHA256_INPUT_BLOCK_SIZE];  // K' XOR ipad
    uint8 k_opad[SHA256_INPUT_BLOCK_SIZE];  // K' XOR opad
    uint8 inner_hash[SHA256_BLOCK_SIZE];    // 第一步 Hash 结果

    // 1. 处理密钥 Key
    // 如果密钥长度 > 64，先做一次 Hash 变成 32 字节
    if (key_len > SHA256_INPUT_BLOCK_SIZE) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, k_prime);
        // 剩余部分补 0
        memset(k_prime + SHA256_BLOCK_SIZE, 0, SHA256_INPUT_BLOCK_SIZE - SHA256_BLOCK_SIZE);
    }
    else {
        // 如果密钥长度 <= 64，直接拷贝，剩余部分补 0
        memcpy(k_prime, key, key_len);
        memset(k_prime + key_len, 0, SHA256_INPUT_BLOCK_SIZE - key_len);
    }

    // 2. 准备 Inner Pad (ipad) 和 Outer Pad (opad)
    // ipad = 0x36, opad = 0x5c
    for (int i = 0; i < SHA256_INPUT_BLOCK_SIZE; i++) {
        k_ipad[i] = k_prime[i] ^ 0x36;
        k_opad[i] = k_prime[i] ^ 0x5c;
    }

    // 3. 计算 Inner Hash
    // Hash(k_ipad || message)
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, SHA256_INPUT_BLOCK_SIZE);
    sha256_update(&ctx, msg, msg_len);
    sha256_final(&ctx, inner_hash);

    // 4. 计算 Outer Hash (最终结果)
    // Hash(k_opad || inner_hash)
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, SHA256_INPUT_BLOCK_SIZE);
    sha256_update(&ctx, inner_hash, SHA256_BLOCK_SIZE);
    sha256_final(&ctx, output);
}