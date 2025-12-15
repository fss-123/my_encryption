#include "aes.h"
#include "utils.h"
#include <string.h>
#include <stdio.h>

// ============================================================================
// --- 1. AES 固定查找表 (Look-up Tables) ---
// ============================================================================

// S-Box (Substitution Box, 字节代换表)
// 作用：提供非线性变换。AES 的安全性主要依赖于此。
// 原理：S-Box 是基于有限域 GF(2^8) 上的乘法逆元构造的。
// 使用方法：输入字节 b，输出 S_BOX[b]。
static const uint8 S_BOX[256] = {
    // ... (这里是你提供的完整 256 字节数据，为了节省篇幅省略，请保持原样)
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// 逆 S-Box (Inverse S-Box)
// 作用：用于解密时撤销 SubBytes 操作。
static const uint8 INV_S_BOX[256] = {
    // ... (这里是你提供的完整 256 字节数据，为了节省篇幅省略，请保持原样)
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// 轮常量表 (Rcon)
// 作用：用于密钥扩展。Rcon[i] 代表 x^(i-1) 在 GF(2^8) 中的值。
// 引入不对称性，防止每一轮的密钥生成方式过于相似。
static const uint32 RCON[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

// AES 状态矩阵类型 (4x4 字节)
// State 矩阵按“列主序”存储，即 state[r][c] 对应 input[r + 4*c]
typedef uint8 State[4][4];


// ============================================================================
// --- 2. 有限域 GF(2^8) 基础运算 ---
// ============================================================================

// 伽罗瓦域乘法 (乘以 x，即乘以 0x02)
// 原理：在 GF(2^8) 中，加法是 XOR，乘法是多项式乘法模 m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)。
// 如果左移导致最高位溢出 (b & 0x80)，则需要异或 0x1B 来进行模运算。
static uint8 gmul_x(uint8 b) {
    uint8 result = (b << 1);
    if (b & 0x80) {
        result ^= 0x1b; // 0x1b 是不可约多项式的低8位
    }
    return result;
}

// 辅助函数：乘以 0x03
// 原理：0x03 * b = (0x02 + 0x01) * b = (0x02 * b) XOR (0x01 * b)
static uint8 gmul_3(uint8 b) {
    return gmul_x(b) ^ b;
}


// ============================================================================
// --- 3. 密钥扩展辅助函数 (Key Expansion Helpers) ---
// ============================================================================

// RotWord: 字循环左移
// 作用：增加密钥扩展的扩散性。
// 输入 Word (32位): [B0, B1, B2, B3] (假设大端序 MSB在左)
// 输出: [B1, B2, B3, B0]
static uint32 rot_word(uint32 w) {
    // 技巧：(w << 8) 把 B1,B2,B3 左移，B0 丢弃；(w >> 24) 把 B0 移到最右。
    // OR 运算将它们合并。
    return (w << 8) | (w >> 24);
}

// SubWord: 字代换
// 作用：对 Word 中的每个字节独立进行 S-Box 代换。增加非线性。
// 这里的实现非常关键：必须确保字节序的一致性。
// 我们这里假设 w 是大端序 (MSB 在高位)，所以依次提取高位到低位的字节。
static uint32 sub_word(uint32 w) {
    return
        ((uint32)S_BOX[(w >> 24) & 0xFF] << 24) | // 替换最高位字节 (MSB)
        ((uint32)S_BOX[(w >> 16) & 0xFF] << 16) | // 替换次高位
        ((uint32)S_BOX[(w >> 8) & 0xFF] << 8) |   // 替换次低位
        ((uint32)S_BOX[(w) & 0xFF]);              // 替换最低位 (LSB)
}


// ============================================================================
// --- 4. AES 核心变换 (Transformations) ---
// ============================================================================

// SubBytes (字节代换)
// 作用：对 State 矩阵中的每个字节进行 S-Box 替换。
// 这是 AES 唯一的非线性变换，用于抵抗差分分析。
static void sub_bytes(State state) {
    for (int i = 0; i < 4; i++) { // 行
        for (int j = 0; j < 4; j++) { // 列
            state[i][j] = S_BOX[state[i][j]];
        }
    }
}

// ShiftRows (行位移)
// 作用：对 State 矩阵的每一行进行循环左移。
// 第0行不移，第1行左移1，第2行左移2，第3行左移3。
// 目的：让每一列的数据扩散到其他列。
static void shift_rows(State state) {
    uint8 temp;
    // Row 1: 左移 1
    temp = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = temp;
    // Row 2: 左移 2
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    // Row 3: 左移 3 (相当于右移 1)
    temp = state[3][0]; state[3][0] = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = temp;
}

// MixColumns (列混淆)
// 作用：对 State 矩阵的每一列进行线性变换。
// 原理：将每一列视为 GF(2^8) 上的多项式，乘以一个固定的多项式 a(x) (模 x^4 + 1)。
// 矩阵形式：
// [02 03 01 01]
// [01 02 03 01]
// [01 01 02 03]
// [03 01 01 02]
// 目的：提供极高的扩散性，结合 ShiftRows，只需几轮就能让改变一位明文影响整个状态。
static void mix_columns(State state) {
    uint8 temp[4];
    for (int j = 0; j < 4; j++) { // 遍历每一列
        uint8 s0 = state[0][j], s1 = state[1][j], s2 = state[2][j], s3 = state[3][j];
        // 矩阵乘法展开：
        temp[0] = gmul_x(s0) ^ gmul_3(s1) ^ s2 ^ s3;
        temp[1] = s0 ^ gmul_x(s1) ^ gmul_3(s2) ^ s3;
        temp[2] = s0 ^ s1 ^ gmul_x(s2) ^ gmul_3(s3);
        temp[3] = gmul_3(s0) ^ s1 ^ s2 ^ gmul_x(s3);

        state[0][j] = temp[0]; state[1][j] = temp[1]; state[2][j] = temp[2]; state[3][j] = temp[3];
    }
}

// AddRoundKey (轮密钥加)
// 作用：将 State 矩阵与轮密钥进行 XOR。
// 原理：异或运算简单且可逆。这是将密钥注入算法的唯一步骤。
static void add_round_key(State state, const uint32* round_key) {
    for (int c = 0; c < 4; c++) {
        uint32 w = round_key[c]; // 获取该列对应的轮密钥字 (大端序)

        // 将 32位 整数 w 拆分回 4 个字节，并与 State 的一列 XOR
        state[0][c] ^= (w >> 24) & 0xFF; // MSB 对应第 0 行
        state[1][c] ^= (w >> 16) & 0xFF; // 对应第 1 行
        state[2][c] ^= (w >> 8) & 0xFF;  // 对应第 2 行
        state[3][c] ^= w & 0xFF;         // LSB 对应第 3 行
    }
}


// ============================================================================
// --- 5. 公共接口实现 ---
// ============================================================================

// 密钥扩展 (Key Expansion)
// 目标：从初始密钥生成 4 * (Nr + 1) 个 32位字。
bool aes_key_expansion(const uint8* raw_key_bytes, size_t key_size, AES_Schedule* schedule) {
    int Nk, Nr;
    // 根据密钥长度设定参数
    if (key_size == AES_KEY_128) { Nk = 4; Nr = AES_ROUNDS_128; }
    else if (key_size == AES_KEY_192) { Nk = 6; Nr = AES_ROUNDS_192; }
    else if (key_size == AES_KEY_256) { Nk = 8; Nr = AES_ROUNDS_256; }
    else return false;

    schedule->rounds = Nr;

    // 1. 前 Nk 个字直接就是原始密钥
    // 注意：这里我们使用 aes_load_word，但为了匹配上面的逻辑，
    // 请确保 aes_load_word 是按 "大端序" 加载的（即 byte[0] 在高位）。
    // 在之前的 utils.cpp 修正中，我们已经强制改为大端序加载。
    for (int i = 0; i < Nk; i++) {
        aes_load_word(&schedule->W[i], raw_key_bytes + i * 4);
    }

    // 2. 生成剩余的轮密钥
    for (int i = Nk; i < 4 * (Nr + 1); i++) {
        uint32 temp = schedule->W[i - 1];

        // 每 Nk 个字，执行一次复杂变换
        if (i % Nk == 0) {
            // RotWord -> SubWord -> XOR Rcon
            temp = sub_word(rot_word(temp)) ^ RCON[i / Nk - 1];
        }
        // 对于 AES-256 (Nk=8)，中间还有一次额外的 SubWord
        else if (Nk > 6 && i % Nk == 4) {
            temp = sub_word(temp);
        }

        // W[i] = W[i-Nk] XOR temp
        schedule->W[i] = schedule->W[i - Nk] ^ temp;
    }
    return true;
}

// AES 加密 (Encryption)
void aes_encrypt(const uint8* input_block, uint8* output_block, const AES_Schedule* schedule) {
    State state;

    // 1. 输入: 将 16字节数组 映射到 4x4 State 矩阵
    // 关键点：AES 规定是 "列主序" (Column-Major Order)
    // 即：前 4 个字节填满第一列，然后第二列...
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] = input_block[r + c * 4];
        }
    }

    // 2. 初始轮：AddRoundKey
    add_round_key(state, schedule->W + 0);

    // 3. 主循环 (1 到 Nr-1 轮)
    for (int round = 1; round < schedule->rounds; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state); // 每一轮都有列混淆
        add_round_key(state, schedule->W + round * 4);
    }

    // 4. 最终轮 (第 Nr 轮)
    // 注意：最终轮没有 MixColumns！这是为了让解密过程对称。
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, schedule->W + schedule->rounds * 4);

    // 5. 输出: 将 State 矩阵 映射回 16字节数组
    // 同样是 "列主序" 提取
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            output_block[r + c * 4] = state[r][c];
        }
    }
}

// AES 解密 (Decryption)
void aes_decrypt(const uint8* input_block, uint8* output_block, const AES_Schedule* schedule) {
    // 解密逻辑尚未实现，后续将添加：
    // 1. 逆序执行轮次
    // 2. 使用 InvShiftRows, InvSubBytes, InvMixColumns
    // 3. AddRoundKey 还是 AddRoundKey (因为 XOR 是自逆的)
    (void)input_block; (void)output_block; (void)schedule;
}