#ifndef ECC_H
#define ECC_H

#include "utils.h"
#include <stdint.h>
#include <stdbool.h>

// 定义椭圆曲线参数: y^2 = x^3 + ax + b (mod p)
typedef struct {
    uint64 p; // 模数 (大素数)
    uint64 a; // 曲线参数 a
    uint64 b; // 曲线参数 b
    uint64 n; // 基点 G 的阶 (Order)，用于签名
} ECC_Curve;

// 定义曲线上的点 (x, y)
typedef struct {
    uint64 x;
    uint64 y;
    bool is_infinity; // 是否为无穷远点 (零元)
} ECC_Point;

// ECC 公钥 (就是一个点 Q)
typedef struct {
    ECC_Curve curve;
    ECC_Point Q; // Q = d * G
    ECC_Point G; // 生成元 G (Base Point)
} ECC_PublicKey;

// ECC 私钥 (就是一个整数 d)
typedef struct {
    ECC_Curve curve;
    uint64 d;    // 私钥 scalar
    ECC_Point G; // 生成元 G
} ECC_PrivateKey;

// 签名结构体 (r, s)
typedef struct {
    uint64 r;
    uint64 s;
} ECC_Signature;

// 密文结构体 (用于 ElGamal-ECC)
// 包含两个点: C1 = kG, C2 = M + kQ
typedef struct {
    ECC_Point C1;
    ECC_Point C2;
} ECC_Ciphertext;

#ifdef __cplusplus
extern "C" {
#endif

    // --- 1. 基础运算 (对外暴露以便测试) ---
    // 检查点是否在曲线上
    bool ecc_is_on_curve(ECC_Point P, ECC_Curve curve);
    // 点加法: R = P + Q
    ECC_Point ecc_point_add(ECC_Point P, ECC_Point Q, ECC_Curve curve);
    // 标量乘法: R = k * P
    ECC_Point ecc_scalar_mult(uint64 k, ECC_Point P, ECC_Curve curve);

    // --- 2. 密钥管理 ---
    // 生成密钥对
    bool ecc_generate_keys(ECC_Curve curve, ECC_Point G, uint64 d, ECC_PublicKey* pub, ECC_PrivateKey* priv);

    // --- 3. ECDSA 签名/验签 ---
    // 签名: hash 是消息摘要的整数表示，k 是临时随机数
    ECC_Signature ecdsa_sign(uint64 hash, uint64 k, const ECC_PrivateKey* priv);
    // 验签
    bool ecdsa_verify(uint64 hash, ECC_Signature sig, const ECC_PublicKey* pub);

    // --- 4. ECC-ElGamal 加密/解密 ---
    // 注意: 这里的 message 必须是曲线上的一个点 M。
    // 将普通数据映射到曲线上是很复杂的过程，教学中我们假设消息已经是点 M。
    ECC_Ciphertext ecc_encrypt(ECC_Point message, uint64 k, const ECC_PublicKey* pub);
    ECC_Point ecc_decrypt(ECC_Ciphertext ct, const ECC_PrivateKey* priv);

#ifdef __cplusplus
}
#endif

#endif // ECC_H#pragma once
