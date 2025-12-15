#include "dsa.h"
#include <stdio.h>

bool test_dsa_full() {
    printf("===========================================\n");
    printf("          DSA 数字签名算法测试\n");
    printf("===========================================\n");

    // 1. 设置公共参数 (Toy Parameters)
    // 满足条件: p 是素数, q 是素数且整除 p-1, g 的阶为 q mod p
    // 选 p=283, q=47 (282 = 6 * 47)
    // 选 g: 令 h=2, g = h^((p-1)/q) mod p = 2^6 mod 283 = 64
    uint64 p = 283;
    uint64 q = 47;
    uint64 g = 64;

    // 验证 g 的阶是否正确 (g^q mod p 应该等于 1)
    if (power(g, q, p) != 1) {
        printf("?? 警告: 参数 g 的阶不是 q，测试可能会失败。\n");
    }

    // 2. 生成密钥
    uint64 x = 15; // 私钥 (1 < x < 47)

    DSA_PublicKey pub;
    DSA_PrivateKey priv;

    printf("[1] 生成密钥对 (p=%llu, q=%llu, g=%llu)...\n", p, q, g);
    if (!dsa_generate_keys(p, q, g, x, &pub, &priv)) {
        printf("? 密钥生成失败。\n");
        return false;
    }
    printf("    -> 私钥 x: %llu\n", priv.x);
    printf("    -> 公钥 y: %llu\n\n", pub.y);

    // 3. 签名流程
    printf("[2] 签名测试:\n");
    uint64 message_hash = 100; // 假设这是消息 "Hello" 的哈希值 (整数表示)
    uint64 k = 19;             // 随机数 k (1 < k < 47)

    printf("    消息摘要: %llu\n", message_hash);
    printf("    随机数 k: %llu\n", k);

    DSA_Signature sig = dsa_sign(message_hash, k, &priv);
    printf("    生成的签名 (r, s): (%llu, %llu)\n\n", sig.r, sig.s);

    // 4. 验签流程
    printf("[3] 验签测试:\n");
    bool valid = dsa_verify(message_hash, sig, &pub);
    if (valid) {
        printf("    ? 验签成功！(Signature Valid)\n");
    }
    else {
        printf("    ? 验签失败！(Signature Invalid)\n");
        return false;
    }

    // 5. 篡改测试
    printf("\n[4] 篡改攻击测试:\n");
    uint64 fake_hash = 101; // 篡改消息哈希
    printf("    篡改后的摘要: %llu\n", fake_hash);
    if (!dsa_verify(fake_hash, sig, &pub)) {
        printf("    ? 篡改检测成功！(Reject Valid)\n");
    }
    else {
        printf("    ? 失败：篡改的消息通过了验证！\n");
        return false;
    }

    return true;
}

// 主入口
extern "C" int test_dsa_main() {
    if (test_dsa_full()) {
        return 0;
    }
    return 1;
}