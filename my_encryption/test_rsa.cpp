#include "rsa.h"
#include <stdio.h>

// 辅助打印函数
void print_rsa_key(const char* label, uint64 n, uint64 exp) {
    printf("%s: (n=%llu, exp=%llu)\n", label, n, exp);
}

bool test_rsa_full() {
    printf("===========================================\n");
    printf("       RSA 综合测试 (加密/解密 & 签名/验签)\n");
    printf("===========================================\n");

    // 1. 密钥生成
    // 选取两个素数 p, q (为了演示，选小一点的素数)
    uint64 p = 61;
    uint64 q = 53;
    uint64 e = 17; // 公钥指数

    RSA_PublicKey pub;
    RSA_PrivateKey priv;

    printf("[1] 生成密钥对 (p=%llu, q=%llu, e=%llu)...\n", p, q, e);
    if (!rsa_generate_keys(p, q, e, &pub, &priv)) {
        printf("? 密钥生成失败。\n");
        return false;
    }
    print_rsa_key("    -> 公钥 (Public)", pub.n, pub.e);
    print_rsa_key("    -> 私钥 (Private)", priv.n, priv.d);
    printf("\n");

    // 定义一个测试消息 (必须小于 n = 3233)
    uint64 message = 1234;
    printf("-------------------------------------------\n");
    printf("测试消息 (Message): %llu\n", message);
    printf("-------------------------------------------\n");

    // --- 场景 A: 保密通信 (公钥加密 -> 私钥解密) ---
    printf("\n[场景 A] 保密通信测试 (Alice 发给 Bob):\n");

    // A.1 加密
    uint64 ciphertext = rsa_encrypt(message, &pub);
    printf("    1. 公钥加密结果: %llu\n", ciphertext);

    // A.2 解密
    uint64 decrypted = rsa_decrypt(ciphertext, &priv);
    printf("    2. 私钥解密结果: %llu\n", decrypted);

    // A.3 验证
    if (decrypted == message) {
        printf("    ? 加密/解密 成功！\n");
    }
    else {
        printf("    ? 加密/解密 失败！\n");
        return false;
    }

    // --- 场景 B: 数字签名 (私钥签名 -> 公钥验签) ---
    printf("\n[场景 B] 数字签名测试 (Bob 验证 Alice):\n");

    // B.1 签名 (使用私钥)
    uint64 signature = rsa_sign(message, &priv);
    printf("    1. 私钥签名结果 (Signature): %llu\n", signature);

    // B.2 验签 (使用公钥)
    // 验签过程是计算 S^e mod n，得到的结果应该等于原消息
    uint64 verified_message = rsa_verify(signature, &pub);
    printf("    2. 公钥验签还原: %llu\n", verified_message);

    // B.3 验证
    if (verified_message == message) {
        printf("    ? 签名/验签 成功！(消息来源真实且未被篡改)\n");
    }
    else {
        printf("    ? 签名/验签 失败！\n");
        return false;
    }

    // --- 场景 C: 篡改攻击测试 ---
    printf("\n[场景 C] 篡改攻击测试:\n");
    uint64 fake_signature = signature + 1; // 攻击者修改了签名
    printf("    攻击者伪造签名: %llu\n", fake_signature);
    uint64 fake_verify = rsa_verify(fake_signature, &pub);
    printf("    验签结果: %llu (期望不等于 %llu)\n", fake_verify, message);

    if (fake_verify != message) {
        printf("    ? 系统成功检测到篡改！\n");
    }
    else {
        printf("    ? 失败：伪造的签名竟然通过了验证！\n");
        return false;
    }

    return true;
}

// 主入口
extern "C" int test_rsa_main() {
    if (test_rsa_full()) {
        return 0;
    }
    return 1;
}