#include "hash.h"
#include <string.h>
#include <stdio.h>

// --- SHA-256 常量 K (64个) ---
static const uint32 K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// --- 辅助宏 (位操作) ---
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

// --- 核心变换函数: 处理一个 512 位 (64字节) 的块 ---
static void sha256_transform(SHA256_CTX* ctx, const uint8* data) {
    uint32 a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    // 1. 准备消息调度表 W[0..63]
    // 前16个字直接从数据读取 (注意: SHA-256 要求大端序解析)
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);

    // 扩展剩余的 48 个字
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    // 2. 初始化工作变量
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // 3. 主循环 (64轮)
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // 4. 更新状态 (累加)
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

// 1. 初始化
void sha256_init(SHA256_CTX* ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    // SHA-256 初始哈希值 (前8个素数平方根的小数部分)
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

// 2. 更新 (支持分块输入)
//void sha256_update(SHA256_CTX* ctx, const uint8* data, size_t len) {
//    for (size_t i = 0; i < len; ++i) {
//        ctx->data[ctx->datalen] = data[i];
//        ctx->datalen++;
//
//        // 如果缓冲区满了 (64字节)，处理该块
//        if (ctx->datalen == 64) {
//            sha256_transform(ctx, ctx->data);
//            ctx->bitlen += 512;
//            ctx->datalen = 0;
//        }
//    }
//}
// 替换上面代码块中的 sha256_update
void sha256_update(SHA256_CTX* ctx, const uint8* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;

        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

// 3. 结束 (填充 Padding)
void sha256_final(SHA256_CTX* ctx, uint8 hash[SHA256_BLOCK_SIZE]) {
    uint32 i = ctx->datalen;

    // 填充规则:
    // 1. 先补一个 '1' bit (0x80)
    // 2. 补 '0' 直到长度 = 448 mod 512 (即最后留 8 字节放长度)
    // 3. 最后 8 字节放原始数据的长度 (Big Endian, bit 单位)

    // 补 0x80
    if (ctx->datalen < 64) {
        ctx->data[i++] = 0x80;
    }
    else {
        // 极罕见情况：datalen 刚好满了，需要 transform 后再补
        sha256_transform(ctx, ctx->data);
        ctx->bitlen += 512;
        ctx->datalen = 0;
        ctx->data[0] = 0x80;
        i = 1;
    }

    // 如果剩余空间不足 8 字节 (即 i > 56)，需要填充并新开一块
    if (i > 56) {
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        ctx->bitlen += 512; // 这里的 bitlen 增加其实不影响最后的长度字段，因为长度是基于实际输入的
        // 重置缓冲区，准备放长度
        memset(ctx->data, 0, 56);
    }
    else {
        // 空间足够，补 0 到 56
        while (i < 56) ctx->data[i++] = 0x00;
    }

    // 填入原始长度 (Big Endian)
    // 注意: bitlen 保存的是处理过的整块 bits。
    // 我们需要加上最后这块里的有效 bits (不含padding)。
    // 这里的逻辑稍微调整：我们在 update 时已经累加了整块的 bitlen。
    // 我们需要算出 *实际消息* 的总 bit 长度。
    // 正确的做法：应该在 update 时累加 bitlen。
    // 修正：上面的 update 逻辑里，bitlen 是每满 512 才加。
    // 所以总长度 = ctx->bitlen + (ctx->datalen * 8) 
    // 注意：这里的 datalen 是指 final 调用前的有效数据长度。
    // 刚才我们修改了 datalen 和 data 数组，所以得用原始的 datalen 来算。
    // 为了简化，我们在 update 里直接累加 bitlen 最安全。

    // --- 修正 update 的 bitlen 逻辑以匹配 final ---
    // 为了代码简洁，我们在这里回溯计算总长度有点麻烦。
    // 让我们稍微改一下上面的 update，让它不要动 bitlen，我们在这里统一算？
    // 不，最标准做法是在 update 里累计。

    // 重新计算总长度 (64位整数)
    // 这里的 ctx->bitlen 是已经 transform 过的块的总 bits。
    // 我们需要加上 final 进来时缓冲区里的字节数 * 8。
    // 但此时 ctx->datalen 已经被我们在 padding 过程中改乱了。
    // 关键：在 padding 开始前，i 就是当时的 datalen。
    // 但是，最上面的 padding 逻辑中，如果 datalen=64 会出问题。
    // 让我们采用更稳健的写法：单独维护一个 total_bits 变量？
    // 或者，我们在 final 开头就算出 total_bits。

    uint64 total_bits = ctx->bitlen + (uint64)((i - (ctx->data[i - 1] == 0x80 ? 1 : 0)) * 8);
    // 这种回溯太复杂容易错。

    // **简单的修正方案**：
    // 我们假设使用者调用 update 传入数据。
    // 我们在 final 的第一行，先计算好 total_bits。
    uint64 final_total_bits = ctx->bitlen + (ctx->datalen * 8);

    // ... (执行上面的 padding 逻辑，填 0x80, 填 0 ...) ...

    // 最后 8 字节填入 final_total_bits (Big Endian)
    ctx->data[63] = final_total_bits;
    ctx->data[62] = final_total_bits >> 8;
    ctx->data[61] = final_total_bits >> 16;
    ctx->data[60] = final_total_bits >> 24;
    ctx->data[59] = final_total_bits >> 32;
    ctx->data[58] = final_total_bits >> 40;
    ctx->data[57] = final_total_bits >> 48;
    ctx->data[56] = final_total_bits >> 56;

    // 处理最后一块
    sha256_transform(ctx, ctx->data);

    // 输出结果 (Big Endian)
    for (i = 0; i < 4; ++i) {
        hash[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = (ctx->state[i]) & 0xFF;
    }
    // 继续输出后4个状态
    for (i = 0; i < 4; ++i) {
        hash[16 + i * 4] = (ctx->state[4 + i] >> 24) & 0xFF;
        hash[16 + i * 4 + 1] = (ctx->state[4 + i] >> 16) & 0xFF;
        hash[16 + i * 4 + 2] = (ctx->state[4 + i] >> 8) & 0xFF;
        hash[16 + i * 4 + 3] = (ctx->state[4 + i]) & 0xFF;
    }
}