#include "elgamal.h"
#include <stdio.h>

// 打印公钥信息
void print_elgamal_key(const char* label, uint64 p, uint64 g, uint64 y) {
    printf("%s: (p=%llu, g=%llu, y=%llu)\n", label, p, g, y);
}

bool test_elgamal_full() {
    printf("==================================================\n");
    printf("       ElGamal 综合测试 (加密/解密 & 签名/验签)\n");
    printf("==================================================\n");

    // 1. 设定参数 (Toy Example)
    // 选取一个大素数 p (例如 467)
    uint64 p = 467;
    // 选取生成元 g (例如 2)
    uint64 g = 2;
    // 选取私钥 x (1 < x < p-1)
    uint64 x = 127;

    ElGamal_PublicKey pub;
    ElGamal_PrivateKey priv;

    printf("[1] 生成密钥对...\n");
    elgamal_generate_keys(p, g, x, &pub, &priv);

    print_elgamal_key("    -> 公钥", pub.p, pub.g, pub.y);
    printf("    -> 私钥: x=%llu\n\n", priv.x);

    // 验证公钥 y = 2^127 mod 467
    // 预期 y = 132 (如果你的 power 函数正确)

    // --- 场景 A: 加密通信 ---
    printf("[场景 A] 加密通信测试:\n");
    uint64 message = 100; // 原始消息 (必须 < p)
    printf("    原始消息: %llu\n", message);

    // 随机数 k (用于加密，必须与 p-1 互质，这里手动指定)
    uint64 k_enc = 213;

    // 加密
    ElGamal_Ciphertext ct = elgamal_encrypt(message, k_enc, &pub);
    printf("    加密结果 (c1, c2): (%llu, %llu)\n", ct.c1, ct.c2);

    // 解密
    uint64 decrypted = elgamal_decrypt(ct, &priv);
    printf("    解密结果: %llu\n", decrypted);

    if (decrypted == message) {
        printf("    ? 加密/解密 成功！\n");
    }
    else {
        printf("    ? 加密/解密 失败！\n");
        return false;
    }

    // --- 场景 B: 数字签名 ---
    printf("\n[场景 B] 数字签名测试:\n");
    // 随机数 k (用于签名，必须与 p-1=466 互质)
    // gcd(213, 466) = 1 (213 = 3*71, 466 = 2*233) -> 互质，可以使用
    uint64 k_sign = 213;

    // 签名
    ElGamal_Signature sig = elgamal_sign(message, k_sign, &priv);
    printf("    签名结果 (r, s): (%llu, %llu)\n", sig.r, sig.s);

    // 验签
    bool verify_result = elgamal_verify(message, sig, &pub);
    if (verify_result) {
        printf("    ? 签名验证 通过！\n");
    }
    else {
        printf("    ? 签名验证 失败！\n");
        return false;
    }

    // --- 场景 C: 篡改测试 ---
    printf("\n[场景 C] 篡改测试:\n");
    uint64 fake_msg = 101; // 篡改消息
    printf("    篡改消息为: %llu\n", fake_msg);
    if (!elgamal_verify(fake_msg, sig, &pub)) {
        printf("    ? 系统成功检测到篡改！\n");
    }
    else {
        printf("    ? 失败：篡改的消息通过了验证！\n");
        return false;
    }

    return true;
}

// 主入口
extern "C" int test_elgamal_main() {
    if (test_elgamal_full()) {
        return 0;
    }
    return 1;
}