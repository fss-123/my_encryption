#include "aes.h"
#include <stdio.h>
#include <string.h>


// AES-128 单元测试 (使用 NIST/FIPS 已知测试向量)
bool test_aes_128() {
    // NIST 测试向量 for AES-128
    const size_t KEY_SIZE = AES_KEY_128;
    const uint8 key[KEY_SIZE] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    // NIST 测试向量 for Plaintext: 3243f6a8885a308d313198a2e0370734
    const uint8 plaintext[AES_BLOCK_SIZE] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    // NIST 期望密文 (Expected Ciphertext): 3925841d02dc09fbaddc22a521854129
    // 这是 AES-128 标准测试的黄金结果
    const uint8 expected_ciphertext[AES_BLOCK_SIZE] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xad, 0xdc, 0x22, 0xa5, 0x21, 0x85, 0x41, 0x29
    };

    AES_Schedule schedule;
    uint8 ciphertext[AES_BLOCK_SIZE];
    uint8 decrypted_plaintext[AES_BLOCK_SIZE];

    printf("--- AES-128 ECB 测试 ---\n");
    print_hex("密钥", key, KEY_SIZE);
    print_hex("明文", plaintext, AES_BLOCK_SIZE);

    // 1. 密钥扩展 (Key Expansion)
    if (!aes_key_expansion(key, KEY_SIZE, &schedule)) {
        printf("AES 密钥扩展失败。\n");
        return false;
    }

    // 2. 加密
    aes_encrypt(plaintext, ciphertext, &schedule);
    print_hex("密文 (实际输出)", ciphertext, AES_BLOCK_SIZE);
    print_hex("期望密文", expected_ciphertext, AES_BLOCK_SIZE);

    // 3. 验证加密结果
    if (memcmp(ciphertext, expected_ciphertext, AES_BLOCK_SIZE) != 0) {
        printf("AES 加密测试失败: 密文不匹配。\n");
        return false;
    }

    // 4. 解密 (注意: 我们的 aes_decrypt 仍是空的)
    // 只有在 aes_encrypt 验证通过后，我们才应该运行解密测试
    printf("--- 运行解密测试 (当前 aes_decrypt 尚未实现) ---\n");
    aes_decrypt(ciphertext, decrypted_plaintext, &schedule);

    // 5. 解密验证 (目前预期会失败，因为解密函数是空的)
    if (memcmp(plaintext, decrypted_plaintext, AES_BLOCK_SIZE) == 0) {
        printf("AES 测试成功: 加密和解密验证通过。\n");
        return true;
    }
    else {
        printf("AES 解密测试失败 (预期失败，待实现解密逻辑)。\n");
        return false;
    }
}

// 主测试入口函数，供 my_encryption.cpp 调用
extern "C" int test_aes_main() {
    // 运行 AES-128 测试
    if (test_aes_128()) {
        return 0; // 成功
    }
    return 1; // 失败
}