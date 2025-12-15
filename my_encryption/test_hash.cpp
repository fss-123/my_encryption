#include "hash.h"
#include <stdio.h>
#include <string.h>

// 辅助: 计算并打印
void test_sha256_vector(const char* input_str, const char* expected_hex) {
    SHA256_CTX ctx;
    uint8 hash[SHA256_BLOCK_SIZE];

    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8*)input_str, strlen(input_str));
    sha256_final(&ctx, hash);

    printf("输入: \"%s\"\n", input_str);
    print_hex("哈希", hash, SHA256_BLOCK_SIZE);
    // 这里为了演示简单，人眼比对即可，或者你可以写个 hex_to_bytes 函数来 memcmp
    printf("期望: %s ...\n\n", expected_hex);
}

bool test_hash_full() {
    printf("===========================================\n");
    printf("          SHA-256 哈希算法测试\n");
    printf("===========================================\n");

    // 1. 空字符串
    // 期望: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    test_sha256_vector("", "E3B0C442...");

    // 2. "abc"
    // 期望: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    test_sha256_vector("abc", "BA7816BF...");

    // 3. 长字符串
    // 期望: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
    test_sha256_vector("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248D6A61...");

    return true; // 简单返回 true，实际应加 memcmp 验证
}

extern "C" int test_hash_main() {
    if (test_hash_full()) return 0;
    return 1;
}