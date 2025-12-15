#ifndef DSA_H
#define DSA_H

#include "utils.h"
#include <stdint.h>

// DSA 公共参数结构体 (Public Domain Parameters)
typedef struct {
    uint64 p; // 大素数 L bits
    uint64 q; // p-1 的素因子 N bits
    uint64 g; // 生成元，阶为 q
} DSA_Params;

// DSA 公钥结构体
typedef struct {
    DSA_Params params;
    uint64 y; // y = g^x mod p
} DSA_PublicKey;

// DSA 私钥结构体
typedef struct {
    DSA_Params params;
    uint64 x; // 随机私钥 0 < x < q
} DSA_PrivateKey;

// DSA 签名结构体 (r, s)
typedef struct {
    uint64 r;
    uint64 s;
} DSA_Signature;

#ifdef __cplusplus
extern "C" {
#endif

    // --- 1. 密钥管理 ---
    /**
     * 生成 DSA 密钥对
     * @param p, q, g: 预设的公共参数
     * @param x: 手动指定的私钥 (实际应随机生成，0 < x < q)
     * @param pub: 输出公钥
     * @param priv: 输出私钥
     */
    bool dsa_generate_keys(uint64 p, uint64 q, uint64 g, uint64 x, DSA_PublicKey* pub, DSA_PrivateKey* priv);

    // --- 2. 签名 ---
    /**
     * DSA 签名
     * @param digest: 消息的哈希摘要 (整数形式)
     * @param k: 临时随机数 (0 < k < q)
     * @param priv: 私钥
     * @return 签名结构体 (r, s)
     */
    DSA_Signature dsa_sign(uint64 digest, uint64 k, const DSA_PrivateKey* priv);

    // --- 3. 验签 ---
    /**
     * DSA 验签
     * @param digest: 消息的哈希摘要
     * @param sig: 签名结构体
     * @param pub: 公钥
     * @return true 验证通过, false 验证失败
     */
    bool dsa_verify(uint64 digest, DSA_Signature sig, const DSA_PublicKey* pub);

#ifdef __cplusplus
}
#endif

#endif // DSA_H#pragma once
