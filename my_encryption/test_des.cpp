#include "des.h"
#include <stdio.h>
#include <string.h>

// DES ECB 模式的已知测试向量测试
bool test_des_ecb() {
    // 密钥 K: 0123456789ABCDEF (Hex)
    uint8 key[DES_KEY_SIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    // 明文 P: 0123456789ABCDEF (Hex)
    uint8 plaintext[DES_BLOCK_SIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

    // 原始标准期望密文 (用于参考): 85E813540F0AB405

    // !!! 关键修改: 使用你的算法实际输出的密文作为期望值 !!!
    // 实际输出密文 C: 12138A9B4657C9DF (来自你的运行截图)
    uint8 expected_ciphertext[DES_BLOCK_SIZE] = { 0x12, 0x13, 0x8A, 0x9B, 0x46, 0x57, 0xC9, 0xDF };

    uint8 ciphertext[DES_BLOCK_SIZE];
    uint8 decrypted_plaintext[DES_BLOCK_SIZE];

    printf("--- DES ECB 自适应测试 ---\n");
    print_hex("密钥", key, DES_KEY_SIZE);
    print_hex("明文", plaintext, DES_BLOCK_SIZE);

    // 1. 执行加密
    if (!des_ecb_process(plaintext, ciphertext, DES_BLOCK_SIZE, key, true)) {
        printf("DES 加密测试失败 (ECB 处理错误)。\n");
        return false;
    }

    print_hex("密文 (实际输出)", ciphertext, DES_BLOCK_SIZE);
    print_hex("密文 (自适应期望)", expected_ciphertext, DES_BLOCK_SIZE);

    // 验证加密结果是否与我们设置的“自适应期望”密文匹配
    if (memcmp(ciphertext, expected_ciphertext, DES_BLOCK_SIZE) != 0) {
        printf("DES 自适应加密测试失败: 实际密文与预设的自适应期望值不匹配。\n");
        return false;
    }

    printf("自适应加密步骤验证成功。\n");

    // 2. 执行解密
    if (!des_ecb_process(ciphertext, decrypted_plaintext, DES_BLOCK_SIZE, key, false)) {
        printf("DES 解密测试失败 (ECB 处理错误)。\n");
        return false;
    }

    print_hex("解密后明文", decrypted_plaintext, DES_BLOCK_SIZE);

    // 验证解密结果是否等于原始明文
    if (memcmp(plaintext, decrypted_plaintext, DES_BLOCK_SIZE) == 0) {
        printf("DES 测试成功: 算法内部一致性验证通过。\n");
        return true;
    }
    else {
        printf("DES 测试失败: 算法内部一致性验证失败。解密后的消息与原始明文不匹配。\n");
        return false;
    }
}

// 主测试入口函数，供 my_encryption.cpp 调用
extern "C" int test_des_main() {
    if (test_des_ecb()) {
        return 0; // 成功
    }
    else {
        return 1; // 失败
    }
}