#include "ecc.h"
#include <stdio.h>

// 辅助: 比较两个点是否相等
static bool points_equal(ECC_Point P, ECC_Point Q) {
    if (P.is_infinity && Q.is_infinity) return true;
    if (P.is_infinity || Q.is_infinity) return false;
    return (P.x == Q.x) && (P.y == Q.y);
}

// 1. 检查点是否在曲线上
// y^2 = x^3 + ax + b (mod p)
bool ecc_is_on_curve(ECC_Point P, ECC_Curve curve) {
    if (P.is_infinity) return true;

    // LHS = y^2
    uint64 lhs = power(P.y, 2, curve.p);

    // RHS = x^3 + ax + b
    uint64 rhs = power(P.x, 3, curve.p);
    uint64 ax = (curve.a * P.x) % curve.p;
    rhs = (rhs + ax + curve.b) % curve.p;

    return lhs == rhs;
}

// 2. 点加法 P + Q
ECC_Point ecc_point_add(ECC_Point P, ECC_Point Q, ECC_Curve curve) {
    ECC_Point R;
    R.is_infinity = false;

    // 情况1: 无穷远点处理 (Identity)
    if (P.is_infinity) return Q;
    if (Q.is_infinity) return P;

    // 情况2: P 和 Q x 坐标相同
    if (P.x == Q.x) {
        // P = -Q (垂直线)，结果是无穷远点
        // 判断方法: y1 = -y2 mod p => (y1 + y2) % p == 0
        if ((P.y + Q.y) % curve.p == 0) {
            R.is_infinity = true;
            return R;
        }
        // P = Q (同一点)，执行点倍积
        if (P.y == Q.y) {
            // 斜率 lambda = (3x^2 + a) * (2y)^(-1) mod p
            uint64 num = (3 * power(P.x, 2, curve.p) + curve.a) % curve.p;
            uint64 den = (2 * P.y) % curve.p;
            uint64 den_inv = mod_inverse(den, curve.p);

            if (den_inv == 0) { // 垂直切线
                R.is_infinity = true; return R;
            }

            uint64 lambda = (num * den_inv) % curve.p;

            // rx = lambda^2 - 2x
            // rx = (lambda^2 - 2x) mod p
            // 负数处理: (A - B) mod p -> (A + p - (B%p)) % p
            uint64 l2 = power(lambda, 2, curve.p);
            uint64 two_x = (2 * P.x) % curve.p;
            R.x = (l2 >= two_x) ? (l2 - two_x) : (l2 + curve.p - two_x);

            // ry = lambda(x - rx) - y
            uint64 x_diff = (P.x >= R.x) ? (P.x - R.x) : (P.x + curve.p - R.x);
            uint64 term = (lambda * x_diff) % curve.p;
            R.y = (term >= P.y) ? (term - P.y) : (term + curve.p - P.y);

            return R;
        }
    }

    // 情况3: P != Q (普通加法)
    // 斜率 lambda = (y2 - y1) * (x2 - x1)^(-1) mod p
    uint64 num, den;
    if (Q.y >= P.y) num = Q.y - P.y;
    else num = Q.y + curve.p - P.y;

    if (Q.x >= P.x) den = Q.x - P.x;
    else den = Q.x + curve.p - P.x;

    uint64 den_inv = mod_inverse(den, curve.p);
    uint64 lambda = (num * den_inv) % curve.p;

    // rx = lambda^2 - x1 - x2
    uint64 l2 = power(lambda, 2, curve.p);
    uint64 x_sum = (P.x + Q.x) % curve.p;
    R.x = (l2 >= x_sum) ? (l2 - x_sum) : (l2 + curve.p - x_sum);

    // ry = lambda(x1 - rx) - y1
    uint64 x_diff = (P.x >= R.x) ? (P.x - R.x) : (P.x + curve.p - R.x);
    uint64 term = (lambda * x_diff) % curve.p;
    R.y = (term >= P.y) ? (term - P.y) : (term + curve.p - P.y);

    return R;
}

// 3. 标量乘法 R = k * P (Double-and-Add 算法)
ECC_Point ecc_scalar_mult(uint64 k, ECC_Point P, ECC_Curve curve) {
    ECC_Point R;
    R.is_infinity = true; // R = 0 (Infinity)
    ECC_Point Temp = P;

    while (k > 0) {
        if (k & 1) {
            R = ecc_point_add(R, Temp, curve);
        }
        Temp = ecc_point_add(Temp, Temp, curve); // Double
        k >>= 1;
    }
    return R;
}

// 4. 密钥生成
// Q = d * G
bool ecc_generate_keys(ECC_Curve curve, ECC_Point G, uint64 d, ECC_PublicKey* pub, ECC_PrivateKey* priv) {
    if (!ecc_is_on_curve(G, curve)) {
        printf("Error: Generator point is not on the curve.\n");
        return false;
    }

    // 计算公钥 Q = d * G
    ECC_Point Q = ecc_scalar_mult(d, G, curve);

    pub->curve = curve;
    pub->G = G;
    pub->Q = Q;

    priv->curve = curve;
    priv->G = G;
    priv->d = d;

    return true;
}

// 5. ECDSA 签名
// r = (kG).x mod n
// s = k^(-1) * (hash + r*d) mod n
ECC_Signature ecdsa_sign(uint64 hash, uint64 k, const ECC_PrivateKey* priv) {
    ECC_Signature sig = { 0, 0 };
    uint64 n = priv->curve.n;

    // 计算 R = k * G
    ECC_Point R = ecc_scalar_mult(k, priv->G, priv->curve);

    // r = R.x mod n
    sig.r = R.x % n;
    if (sig.r == 0) {
        printf("Error: r = 0, choose different k.\n");
        return sig;
    }

    // s = k^(-1) * (hash + r*d) mod n
    uint64 k_inv = mod_inverse(k, n);
    uint64 rd = (sig.r * priv->d) % n;
    uint64 sum = (hash + rd) % n;
    sig.s = (k_inv * sum) % n;

    if (sig.s == 0) printf("Error: s = 0, choose different k.\n");

    return sig;
}

// 6. ECDSA 验签
// w = s^(-1) mod n
// u1 = hash * w mod n
// u2 = r * w mod n
// P = u1*G + u2*Q
// check P.x == r
bool ecdsa_verify(uint64 hash, ECC_Signature sig, const ECC_PublicKey* pub) {
    if (sig.r == 0 || sig.s == 0) return false;
    uint64 n = pub->curve.n;

    uint64 w = mod_inverse(sig.s, n);
    uint64 u1 = (hash * w) % n;
    uint64 u2 = (sig.r * w) % n;

    // P = u1*G + u2*Q
    ECC_Point P1 = ecc_scalar_mult(u1, pub->G, pub->curve);
    ECC_Point P2 = ecc_scalar_mult(u2, pub->Q, pub->curve);
    ECC_Point P = ecc_point_add(P1, P2, pub->curve);

    if (P.is_infinity) return false;

    return (P.x % n) == sig.r;
}

// 7. ECC-ElGamal 加密
// C1 = kG
// C2 = M + kQ (点加法)
ECC_Ciphertext ecc_encrypt(ECC_Point message, uint64 k, const ECC_PublicKey* pub) {
    ECC_Ciphertext ct;
    // C1 = k * G
    ct.C1 = ecc_scalar_mult(k, pub->G, pub->curve);

    // S = k * Q (Shared Secret)
    ECC_Point S = ecc_scalar_mult(k, pub->Q, pub->curve);

    // C2 = M + S
    ct.C2 = ecc_point_add(message, S, pub->curve);

    return ct;
}

// 8. ECC-ElGamal 解密
// M = C2 - d*C1 = C2 + d*(-C1) = C2 - S
// 这里我们简化：计算 S = d*C1，然后在点加法中我们要实现 "点减法"
// 点减法 P - Q = P + (-Q). 
// -Q 的坐标是 (x, -y mod p)
ECC_Point ecc_decrypt(ECC_Ciphertext ct, const ECC_PrivateKey* priv) {
    // S = d * C1
    ECC_Point S = ecc_scalar_mult(priv->d, ct.C1, priv->curve);

    // 计算 -S (Inverse Point)
    // S(x, y) -> -S(x, p-y)
    ECC_Point NegS = S;
    NegS.y = priv->curve.p - S.y;

    // M = C2 + (-S)
    return ecc_point_add(ct.C2, NegS, priv->curve);
}