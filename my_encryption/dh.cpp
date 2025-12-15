#include "dh.h"
#include <stdio.h>

// 1. 生成公钥
// pub = g^priv mod p
uint64 dh_generate_public_key(const DH_Context* ctx, uint64 priv_key) {
    // 检查私钥范围 (1 <= priv < p-1)
    if (priv_key == 0 || priv_key >= ctx->p - 1) {
        printf("Warning: Private key is out of recommended range.\n");
    }

    // 使用快速模幂计算
    return power(ctx->g, priv_key, ctx->p);
}

// 2. 计算共享秘密
// secret = remote_pub ^ local_priv mod p
uint64 dh_compute_shared_secret(const DH_Context* ctx, uint64 local_priv, uint64 remote_pub) {
    // 简单的安全性检查
    if (remote_pub == 0 || remote_pub >= ctx->p) {
        printf("Error: Invalid remote public key.\n");
        return 0;
    }

    // 核心计算
    return power(remote_pub, local_priv, ctx->p);
}