#include "ecc.h"
#include <stdio.h>

bool test_ecc_full() {
    printf("===========================================\n");
    printf("       ECC 椭圆曲线算法测试 (ECDSA & ElGamal)\n");
    printf("===========================================\n");

    // 1. 定义曲线参数 (Toy Curve)
    // y^2 = x^3 + 2x + 2 (mod 17)
    ECC_Curve curve;
    curve.p = 17;
    curve.a = 2;
    curve.b = 2;
    curve.n = 19; // G点 (5,1) 的阶

    // 生成元 G
    ECC_Point G;
    G.x = 5; G.y = 1; G.is_infinity = false;

    printf("[1] 曲线参数:\n");
    printf("    y^2 = x^3 + %llux + %llu (mod %llu)\n", curve.a, curve.b, curve.p);
    printf("    生成元 G = (%llu, %llu)\n", G.x, G.y);

    // 2. 生成密钥
    uint64 d = 7; // 私钥 (1 < d < n)
    ECC_PublicKey pub;
    ECC_PrivateKey priv;

    if (!ecc_generate_keys(curve, G, d, &pub, &priv)) {
        printf("? 密钥生成失败。\n");
        return false;
    }
    printf("    -> 私钥 d: %llu\n", priv.d);
    printf("    -> 公钥 Q: (%llu, %llu)\n\n", pub.Q.x, pub.Q.y);
    // 预期 Q = 7 * (5,1) 在该曲线上应该是一个有效点

    // --- 场景 A: ECDSA 签名/验签 ---
    printf("[场景 A] ECDSA 签名测试:\n");
    uint64 hash = 10; // 消息摘要
    uint64 k = 10;    // 随机数

    // 签名
    ECC_Signature sig = ecdsa_sign(hash, k, &priv);
    printf("    消息摘要: %llu\n", hash);
    printf("    签名结果 (r, s): (%llu, %llu)\n", sig.r, sig.s);

    // 验签
    bool valid = ecdsa_verify(hash, sig, &pub);
    if (valid) {
        printf("    ? 验签成功！\n");
    }
    else {
        printf("    ? 验签失败！\n");
        return false;
    }

    // --- 场景 B: ECC-ElGamal 加密通信 ---
    printf("\n[场景 B] ECC-ElGamal 加密测试:\n");
    // 明文必须是曲线上的一个点。我们随便找一个点，比如 (5,1) 也就是 G 自己，或者 (0,6)
    // 验证 (0,6): 6^2=36=2, 0+0+2=2. (0,6) 在曲线上。
    ECC_Point msg;
    msg.x = 0; msg.y = 6; msg.is_infinity = false;

    printf("    原始消息点 M: (%llu, %llu)\n", msg.x, msg.y);

    // 加密
    uint64 k_enc = 3;
    ECC_Ciphertext ct = ecc_encrypt(msg, k_enc, &pub);
    printf("    密文 C1: (%llu, %llu)\n", ct.C1.x, ct.C1.y);
    printf("    密文 C2: (%llu, %llu)\n", ct.C2.x, ct.C2.y);

    // 解密
    ECC_Point decrypted = ecc_decrypt(ct, &priv);
    printf("    解密后消息: (%llu, %llu)\n", decrypted.x, decrypted.y);

    if (decrypted.x == msg.x && decrypted.y == msg.y) {
        printf("    ? 加密/解密 成功！\n");
    }
    else {
        printf("    ? 加密/解密 失败！\n");
        return false;
    }

    return true;
}

extern "C" int test_ecc_main() {
    if (test_ecc_full()) return 0;
    return 1;
}