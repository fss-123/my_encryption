#ifndef ELGAMAL_H
#define ELGAMAL_H

#include "utils.h"
#include <stdint.h>

// ElGamal 公钥结构体
typedef struct {
    uint64 p; // 大素数 (Prime modulus)
    uint64 g; // 生成元 (Generator)
    uint64 y; // 公钥值 y = g^x mod p
} ElGamal_PublicKey;

// ElGamal 私钥结构体
typedef struct {
    uint64 p; // 大素数 (需要用于解密运算)
    uint64 x; // 私钥值 (Private exponent)
} ElGamal_PrivateKey;

// ElGamal 密文结构体 (密文由两部分组成)
typedef struct {
    uint64 c1; // 临时公钥 g^k
    uint64 c2; // 掩码后的消息 M * y^k
} ElGamal_Ciphertext;

// ElGamal 签名结构体 (签名由两部分组成)
typedef struct {
    uint64 r; // 也有人称为 s1
    uint64 s; // 也有人称为 s2
} ElGamal_Signature;

#ifdef __cplusplus
extern "C" {
#endif

    // --- 1. 密钥管理 ---
    /**
     * 生成 ElGamal 密钥对
     * @param p: 大素数
     * @param g: 生成元
     * @param x: 私钥 (随机选取的整数，必须 1 < x < p-1)
     * @param pub: 输出公钥
     * @param priv: 输出私钥
     */
    void elgamal_generate_keys(uint64 p, uint64 g, uint64 x, ElGamal_PublicKey* pub, ElGamal_PrivateKey* priv);

    // --- 2. 加密/解密 ---
    /**
     * ElGamal 加密
     * @param message: 明文整数 (必须 < p)
     * @param k: 临时随机数 (必须与 p-1 互质) - 实际应用中应由函数内部随机生成，这里为了测试可控，作为参数传入
     * @param pub: 公钥
     * @return 密文结构体 (c1, c2)
     */
    ElGamal_Ciphertext elgamal_encrypt(uint64 message, uint64 k, const ElGamal_PublicKey* pub);

    /**
     * ElGamal 解密
     * @param ciphertext: 密文结构体
     * @param priv: 私钥
     * @return 明文整数
     */
    uint64 elgamal_decrypt(ElGamal_Ciphertext ciphertext, const ElGamal_PrivateKey* priv);

    // --- 3. 签名/验签 ---
    /**
     * ElGamal 签名
     * @param message: 消息摘要
     * @param k: 临时随机数 (必须与 p-1 互质)
     * @param priv: 私钥
     * @return 签名结构体 (r, s)
     */
    ElGamal_Signature elgamal_sign(uint64 message, uint64 k, const ElGamal_PrivateKey* priv);

    /**
     * ElGamal 验签
     * @param message: 消息摘要
     * @param sig: 签名结构体
     * @param pub: 公钥
     * @return true 验证成功, false 验证失败
     */
    bool elgamal_verify(uint64 message, ElGamal_Signature sig, const ElGamal_PublicKey* pub);

#ifdef __cplusplus
}
#endif

#endif // ELGAMAL_H#pragma once
