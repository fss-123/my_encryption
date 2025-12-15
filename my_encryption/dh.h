#ifndef DH_H
#define DH_H

#include "utils.h"
#include <stdint.h>

// DH 公共参数结构体 (Public Parameters)
// 在实际协议中，这通常是预先协商好的固定值 (如 RFC 3526)
typedef struct {
    uint64 p; // 大素数
    uint64 g; // 生成元
} DH_Context;

#ifdef __cplusplus
extern "C" {
#endif

    // --- 核心功能 ---

    /**
     * 1. 生成公钥 (Generate Public Key)
     * 计算公式: pub_key = g ^ priv_key mod p
     * @param ctx: 公共参数 (p, g)
     * @param priv_key: 本地生成的私钥 (随机数)
     * @return 本地公钥
     */
    uint64 dh_generate_public_key(const DH_Context* ctx, uint64 priv_key);

    /**
     * 2. 计算共享秘密 (Compute Shared Secret)
     * 计算公式: secret = (remote_pub) ^ local_priv mod p
     * @param ctx: 公共参数 (p, g)
     * @param local_priv: 自己的私钥
     * @param remote_pub: 对方发来的公钥
     * @return 协商出的共享秘密
     */
    uint64 dh_compute_shared_secret(const DH_Context* ctx, uint64 local_priv, uint64 remote_pub);

#ifdef __cplusplus
}
#endif

#endif // DH_H