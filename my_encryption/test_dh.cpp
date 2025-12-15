#include "dh.h"
#include <stdio.h>

bool test_dh_exchange() {
    printf("===========================================\n");
    printf("       Diffie-Hellman 密钥交换测试\n");
    printf("===========================================\n");

    // 1. 协商公共参数 (Public Context)
    // 依然使用我们熟悉的素数 p=467, g=2
    DH_Context ctx;
    ctx.p = 467;
    ctx.g = 2;

    printf("[1] 公共参数设定:\n");
    printf("    素数 P = %llu\n", ctx.p);
    printf("    生成元 G = %llu\n\n", ctx.g);

    // 2. 模拟 Alice 的操作
    printf("[2] Alice 操作:\n");
    uint64 alice_priv = 228; // Alice 随机生成的私钥
    uint64 alice_pub = dh_generate_public_key(&ctx, alice_priv);
    printf("    Alice 私钥 (保密): %llu\n", alice_priv);
    printf("    Alice 公钥 (发送给 Bob): %llu\n\n", alice_pub);

    // 3. 模拟 Bob 的操作
    printf("[3] Bob 操作:\n");
    uint64 bob_priv = 57; // Bob 随机生成的私钥
    uint64 bob_pub = dh_generate_public_key(&ctx, bob_priv);
    printf("    Bob 私钥 (保密): %llu\n", bob_priv);
    printf("    Bob 公钥 (发送给 Alice): %llu\n\n", bob_pub);

    // --- 网络传输阶段 (Alice 和 Bob 交换了公钥) ---
    printf("--- [网络传输] Alice 和 Bob 交换公钥 ---\n\n");

    // 4. Alice 计算共享秘密
    // 输入: 自己的私钥, Bob的公钥
    uint64 alice_secret = dh_compute_shared_secret(&ctx, alice_priv, bob_pub);
    printf("[4] Alice 计算共享秘密:\n");
    printf("    计算公式: %llu^%llu mod %llu\n", bob_pub, alice_priv, ctx.p);
    printf("    结果: %llu\n\n", alice_secret);

    // 5. Bob 计算共享秘密
    // 输入: 自己的私钥, Alice的公钥
    uint64 bob_secret = dh_compute_shared_secret(&ctx, bob_priv, alice_pub);
    printf("[5] Bob 计算共享秘密:\n");
    printf("    计算公式: %llu^%llu mod %llu\n", alice_pub, bob_priv, ctx.p);
    printf("    结果: %llu\n\n", bob_secret);

    // 6. 验证
    if (alice_secret == bob_secret) {
        printf("? 测试成功！双方协商出了相同的密钥: %llu\n", alice_secret);
        return true;
    }
    else {
        printf("? 测试失败！双方密钥不一致 (Alice:%llu, Bob:%llu)\n", alice_secret, bob_secret);
        return false;
    }
}

// 主入口
extern "C" int test_dh_main() {
    if (test_dh_exchange()) {
        return 0;
    }
    return 1;
}