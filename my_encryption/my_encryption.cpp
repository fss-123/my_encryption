#include <iostream>
#include <stdio.h> // for printf
#include <stdlib.h> // for exit()

// --- 声明所有算法的测试入口函数 ---
extern "C" int test_des_main();
// 声明其他所有未实现的测试函数
extern "C" int test_aes_main();
extern "C" int test_rsa_main();
extern "C" int test_elgamal_main();
extern "C" int test_dh_main();
extern "C" int test_dsa_main();
extern "C" int test_ecc_main();
extern "C" int test_hash_main();
extern "C" int test_hmac_main();

int main()
{
    printf("--- 我的加密库主程序 (My Encryption Library Main Program) ---\n\n");

    int choice;

    while (1) {
        printf("\n请选择要运行的算法模块测试：\n");
        printf("---------------------------------------\n");

        // --- 可测试的 9 个算法选项 ---
        printf("1. DES (对称加密)\n");
        printf("2. AES (对称加密)\n");
        printf("3. RSA (非对称加密/签名)\n");
        printf("4. Elgamal (非对称加密)\n");
        printf("5. DH (密钥交换)\n");
        printf("6. DSA (数字签名)\n");
        printf("7. ECC (椭圆曲线)\n");
        printf("8. HASH (散列函数)\n");
        printf("9. HMAC (消息认证)\n");
        // -------------------------------

        printf("0. 退出程序\n");
        printf("---------------------------------------\n");
        printf("请输入选项编号 (0-9): ");

        // 获取用户输入
        if (!(std::cin >> choice)) {
            printf("\n错误：无效的输入。请重新启动程序。\n");
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        if (choice == 0) {
            printf("\n程序退出。再见！\n");
            break;
        }

        switch (choice) {
        case 1: // DES: 运行已实现的测试
            printf("\n>>> 正在运行 DES (对称加密) 测试...\n");
            if (test_des_main() == 0) {
                printf("DES 测试结果：✅ 成功 (Passed)\n");
            }
            else {
                printf("DES 测试结果：❌ 失败 (Failed)\n");
            }
            break;

        case 2: // <<< AES: 运行测试
            printf("\n>>> 正在运行 AES (对称加密) 测试...\n");
            // 调用 test_aes_main，它将执行密钥扩展和加密验证。
            // 预期：解密部分会失败，但我们现在验证加密步骤。
            if (test_aes_main() == 0) {
                printf("AES 测试结果：✅ 成功 (Passed)\n");
            }
            else {
                printf("AES 测试结果：❌ 失败 (Failed)\n");
            }
            break;
        case 3: // RSA
            printf("\n>>> 正在运行 RSA (非对称加密) 测试...\n");
            // 调用 test_rsa_main
            if (test_rsa_main() == 0) {
                printf("RSA 测试结果：✅ 成功 (Passed)\n");
            }
            else {
                printf("RSA 测试结果：❌ 失败 (Failed)\n");
            }
            break; // RSA
        case 4: // Elgamal
            printf("\n>>> 正在运行 ElGamal 测试...\n");
            if (test_elgamal_main() == 0) {
                printf("ElGamal 测试结果：✅ 成功\n");
            }
            else {
                printf("ElGamal 测试结果：❌ 失败\n");
            }
            break;
            // switch 中
        case 5: // DH
            printf("\n>>> 正在运行 DH (密钥交换) 测试...\n");
            if (test_dh_main() == 0) {
                printf("DH 测试结果：✅ 成功\n");
            }
            else {
                printf("DH 测试结果：❌ 失败\n");
            }
            break;
            // ... switch 语句 ...
        case 6: // DSA
            printf("\n>>> 正在运行 DSA (数字签名) 测试...\n");
            if (test_dsa_main() == 0) {
                printf("DSA 测试结果：✅ 成功\n");
            }
            else {
                printf("DSA 测试结果：❌ 失败\n");
            }
            break;
        case 7: // ECC
            printf("\n>>> 正在运行 ECC (椭圆曲线) 测试...\n");
            if (test_ecc_main() == 0) {
                printf("ECC 测试结果：✅ 成功\n");
            }
            else {
                printf("ECC 测试结果：❌ 失败\n");
            }
            break;
        case 8: // HASH
            printf("\n>>> 正在运行 HASH (SHA-256) 测试...\n");
            if (test_hash_main() == 0) {
                printf("HASH 测试完成\n");
            }
            break;
        case 9: // HMAC
            printf("\n>>> 正在运行 HMAC (SHA-256) 测试...\n");
            if (test_hmac_main() == 0) {
                printf("HMAC 测试结果：✅ 成功\n");
            }
            else {
                printf("HMAC 测试结果：❌ 失败\n");
            }
            break;
        default:
            printf("\n警告：输入的选项 %d 无效，请重新选择 (0-9)。\n", choice);
            break;
        }
    }

    return 0;
}
