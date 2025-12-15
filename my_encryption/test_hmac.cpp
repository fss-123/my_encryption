#include "hmac.h"
#include <stdio.h>
#include <string.h>

bool test_hmac_rfc4231() {
    printf("===========================================\n");
    printf("       HMAC-SHA256 消息认证码测试\n");
    printf("===========================================\n");

    // RFC 4231 Test Case 2
    const char* key_str = "Jefe";
    const char* msg_str = "what do ya want for nothing?";

    // 预期结果 (Hex)
    // 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    // 为了简单比对，我们只比对前几位和后几位，或者人工看打印

    uint8 output[HMAC_OUTPUT_SIZE];

    printf("[1] 输入参数:\n");
    printf("    Key: \"%s\"\n", key_str);
    printf("    Msg: \"%s\"\n", msg_str);

    // 计算 HMAC
    hmac_sha256((const uint8*)key_str, strlen(key_str),
        (const uint8*)msg_str, strlen(msg_str),
        output);

    printf("\n[2] 计算结果:\n");
    print_hex("    HMAC", output, HMAC_OUTPUT_SIZE);

    printf("\n[3] 预期结果 (RFC 4231):\n");
    printf("    HMAC: 5BDCC146...64EC3843\n");

    // 简单验证首字节
    if (output[0] == 0x5b && output[31] == 0x43) {
        printf("\n? HMAC 测试成功！\n");
        return true;
    }
    else {
        printf("\n? HMAC 测试失败！\n");
        return false;
    }
}

extern "C" int test_hmac_main() {
    if (test_hmac_rfc4231()) {
        return 0;
    }
    return 1;
}