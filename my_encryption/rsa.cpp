#include "rsa.h"
#include <stdio.h>


// 1. RSA 密钥生成 (代码保持不变，参考上一条回复)
bool rsa_generate_keys(uint64 p, uint64 q, uint64 e, RSA_PublicKey* pub, RSA_PrivateKey* priv) {
    // 计算模数 n = p * q
    uint64 n = p * q;

    // 计算欧拉函数 phi(n) = (p-1) * (q-1)
    uint64 phi = (p - 1) * (q - 1);

    // 检查 e 的有效性 (必须 1 < e < phi)
    if (e <= 1 || e >= phi) {
        printf("错误: 公钥指数 e 无效。\n");
        return false;
    }

    // 计算私钥指数 d
    // d 是 e 在模 phi 下的逆元： (d * e) % phi == 1
    // 使用我们在 utils.cpp 中实现的 mod_inverse
    uint64 d = mod_inverse(e, phi);

    if (d == 0) {
        printf("错误: 无法计算私钥 d (e 和 phi 可能不互质)。\n");
        return false;
    }

    // 填充密钥结构体
    pub->n = n;
    pub->e = e;

    priv->n = n;
    priv->d = d;

    return true;
}

// 2. RSA 加密 (公钥)
uint64 rsa_encrypt(uint64 message, const RSA_PublicKey* pub) {
    return power(message, pub->e, pub->n);
}

// 3. RSA 解密 (私钥)
uint64 rsa_decrypt(uint64 ciphertext, const RSA_PrivateKey* priv) {
    return power(ciphertext, priv->d, priv->n);
}

// ==========================================
// --- 新增：签名与验签实现 ---
// ==========================================

// 4. RSA 签名 (私钥)
// 注意：在真实世界中，我们通常是对消息的 Hash 值进行签名，而不是消息本身。
// 但因为这是 Toy RSA，我们直接对 uint64 消息签名。
uint64 rsa_sign(uint64 message, const RSA_PrivateKey* priv) {
    if (message >= priv->n) {
        printf("警告: 待签名消息大于模数 n，签名将无效！\n");
    }
    // 核心：使用私钥指数 d 进行模幂运算
    // S = M^d mod n
    return power(message, priv->d, priv->n);
}

// 5. RSA 验签 (公钥)
uint64 rsa_verify(uint64 signature, const RSA_PublicKey* pub) {
    // 核心：使用公钥指数 e 进行模幂运算
    // M' = S^e mod n
    return power(signature, pub->e, pub->n);
}