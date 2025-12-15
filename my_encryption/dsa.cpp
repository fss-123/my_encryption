#include "dsa.h"
#include <stdio.h>

// 1. 密钥生成
// y = g^x mod p
bool dsa_generate_keys(uint64 p, uint64 q, uint64 g, uint64 x, DSA_PublicKey* pub, DSA_PrivateKey* priv) {
    // 基本参数检查
    if (x == 0 || x >= q) {
        printf("Error: Private key x must be in range [1, q-1].\n");
        return false;
    }

    // 验证 q 是否整除 p-1 (简单的参数校验)
    if ((p - 1) % q != 0) {
        printf("Warning: q does not divide p-1. This is not a valid DSA parameter set.\n");
        // 虽有警告，但为了测试灵活性，暂不强制返回 false，除非你希望严格控制
    }

    // 填充私钥
    priv->params.p = p;
    priv->params.q = q;
    priv->params.g = g;
    priv->x = x;

    // 计算公钥 y = g^x mod p
    uint64 y = power(g, x, p);

    // 填充公钥
    pub->params = priv->params; // 复制参数
    pub->y = y;

    return true;
}

// 2. DSA 签名
// r = (g^k mod p) mod q
// s = k^(-1) * (H(m) + x*r) mod q
DSA_Signature dsa_sign(uint64 digest, uint64 k, const DSA_PrivateKey* priv) {
    DSA_Signature sig = { 0, 0 };
    uint64 p = priv->params.p;
    uint64 q = priv->params.q;
    uint64 g = priv->params.g;
    uint64 x = priv->x;

    // 检查 k 的有效性
    if (k == 0 || k >= q) {
        printf("Error: k must be in range [1, q-1].\n");
        return sig;
    }

    // 1. 计算 r = (g^k mod p) mod q
    uint64 gk = power(g, k, p);
    sig.r = gk % q;

    if (sig.r == 0) {
        printf("Error: r became 0. Need a new k.\n");
        return sig;
    }

    // 2. 计算 s = k^(-1) * (digest + x*r) mod q

    // a. 计算 k 的模逆元 k_inv (mod q)
    uint64 k_inv = mod_inverse(k, q);
    if (k_inv == 0) {
        printf("Error: k has no inverse mod q.\n");
        return sig;
    }

    // b. 计算 (digest + x*r) mod q
    // 为了防止 uint64 溢出，我们分步取模
    // 核心公式: (A + B) % M = ((A % M) + (B % M)) % M
    uint64 xr = (x * sig.r) % q;       // (x * r) mod q
    uint64 h = digest % q;             // H(m) mod q
    uint64 sum = (h + xr) % q;         // (H(m) + x*r) mod q

    // c. 最终计算 s
    sig.s = (k_inv * sum) % q;

    if (sig.s == 0) {
        printf("Error: s became 0. Need a new k.\n");
    }

    return sig;
}

// 3. DSA 验签
// w = s^(-1) mod q
// u1 = (H(m) * w) mod q
// u2 = (r * w) mod q
// v = ((g^u1 * y^u2) mod p) mod q
// 验证 v == r
bool dsa_verify(uint64 digest, DSA_Signature sig, const DSA_PublicKey* pub) {
    uint64 p = pub->params.p;
    uint64 q = pub->params.q;
    uint64 g = pub->params.g;
    uint64 y = pub->y;

    // 1. 范围检查
    if (sig.r <= 0 || sig.r >= q || sig.s <= 0 || sig.s >= q) {
        return false;
    }

    // 2. 计算 w = s^(-1) mod q
    uint64 w = mod_inverse(sig.s, q);
    if (w == 0) return false;

    // 3. 计算 u1 = (digest * w) mod q
    uint64 h = digest % q;
    uint64 u1 = (h * w) % q;

    // 4. 计算 u2 = (r * w) mod q
    uint64 u2 = (sig.r * w) % q;

    // 5. 计算 v = ((g^u1 * y^u2) mod p) mod q
    // 这里需要两次模幂和一次模乘
    uint64 term1 = power(g, u1, p); // g^u1 mod p
    uint64 term2 = power(y, u2, p); // y^u2 mod p

    // term1 * term2 mod p
    // 同样，为了防止 uint64 乘法溢出，我们在相乘前已经保证 term1, term2 < p。
    // 但如果 p 接近 2^32，乘积可能接近 2^64。只要 p < 2^32 (42亿)，这里就是安全的。
    // 如果 p 是 64 位大数，这里需要 __int128 或者模乘函数。
    // 鉴于我们的教学场景，这里直接乘。
    uint64 v_temp = (term1 * term2) % p;

    uint64 v = v_temp % q;

    // 6. 验证
    return (v == sig.r);
}