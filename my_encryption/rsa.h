#ifndef RSA_H
#define RSA_H

#include "utils.h"
#include <stdint.h>

// RSA 公钥结构体
typedef struct {
    uint64 e; // 公钥指数
    uint64 n; // 模数
} RSA_PublicKey;

// RSA 私钥结构体
typedef struct {
    uint64 d; // 私钥指数
    uint64 n; // 模数
} RSA_PrivateKey;

#ifdef __cplusplus
extern "C" {
#endif

    // --- 密钥管理 ---
    bool rsa_generate_keys(uint64 p, uint64 q, uint64 e, RSA_PublicKey* pub, RSA_PrivateKey* priv);

    // --- 加密/解密 (保密通信) ---
    uint64 rsa_encrypt(uint64 message, const RSA_PublicKey* pub);
    uint64 rsa_decrypt(uint64 ciphertext, const RSA_PrivateKey* priv);

    // --- 签名/验签 (身份认证) ---

    /**
     * 4. RSA 签名 (Sign)
     * 使用【私钥】对消息进行计算，生成签名。
     * 公式: S = M^d mod n
     */
    uint64 rsa_sign(uint64 message, const RSA_PrivateKey* priv);

    /**
     * 5. RSA 验签 (Verify)
     * 使用【公钥】对签名进行反算，验证是否还原为原消息。
     * 公式: M' = S^e mod n
     */
    uint64 rsa_verify(uint64 signature, const RSA_PublicKey* pub);

#ifdef __cplusplus
}
#endif

#endif // RSA_H