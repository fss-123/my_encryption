#include "des.h"
#include <string.h>
#include <stdio.h> 



// --- DES 固定表 (Tables) ---

// 1. 初始置换 (IP) - 64位输入，64位输出
// IP 表定义了 DES 加密开始时，64位明文块的位如何重新排列。
static const uint8 IP_Table[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,  64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,   59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7
};

// 2. 最终逆置换 (FP, IP的逆) - 64位输入，64位输出
// FP 表是 IP 表的逆操作，在 16 轮 Feistel 结构完成后，将数据恢复到原始顺序。
static const uint8 FP_Table[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,  39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,  37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,  35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,  33, 1, 41, 9, 49, 17, 57, 25
};

// 3. 扩展置换 (E-Box) - 32位输入，48位输出
// 在 F 函数中，将 32 位的 R 块扩展为 48 位，以便与 48 位子密钥进行异或运算。
// 某些位会被重复使用。
static const uint8 E_Table[48] = {
    32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,  8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23,
    24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
};

// 4. P 置换 (P-Box) - 32位输入，32位输出
// 在 F 函数中，S 盒输出（32位）的最终置换。
static const uint8 P_Table[32] = {
    16, 7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,   19, 13, 30, 6, 22, 11, 4, 25
};

// 5. S 盒 (S-Boxes) - S2到S8省略，需自行填充
// S 盒是 DES 中非线性变换的核心，提供安全性。将 6 位输入映射为 4 位输出。
static const uint8 S_Boxes[8][4][16] = {
    // S1
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    // S2 到 S8
    { /* S2 */ }, { /* S3 */ }, { /* S4 */ }, { /* S5 */ },
    { /* S6 */ }, { /* S7 */ }, { /* S8 */ }
};

// 6. PC-1 置换 (密钥选择) - 64位输入，56位输出
// 用于从 64 位密钥中选出 56 个有效位，并进行初始置换。
static const uint8 PC1_Table[56] = {
    57, 49, 41, 33, 25, 17, 9, 1,  58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
    61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
};

// 7. 循环左移位数
// 定义了每一轮 (共 16 轮) 密钥的左移位数。
static const uint8 Shift_Table[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

// 8. PC-2 置换 (压缩选择) - 56位输入，48位输出
// 用于从 56 位循环移位后的密钥中选择 48 位作为当前轮的子密钥 K[i]。
static const uint8 PC2_Table[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

// --- DES 核心辅助函数 ---

// 循环左移 C 和 D (各28位)
// 用于密钥调度，只对 28 位数据进行循环左移。
static uint32 left_rotate_28(uint32 data, int shift) {
    // (data << shift) 实现左移，(data >> (28 - shift)) 补充溢出到右侧
    // 0x0FFFFFFF 掩码确保只操作低 28 位
    return ((data << shift) | (data >> (28 - shift))) & 0x0FFFFFFF;
}


// --- 核心函数实现 ---

// 1. 密钥调度
// 根据 64 位原始密钥生成 16 个 48 位的子密钥 K[0] 到 K[15]。
void des_key_schedule(uint64 raw_key, DES_Subkeys* subkeys) {
    // 1. PC-1 置换 (64位密钥 -> 56位密钥)
    uint64 key_56 = general_permute(raw_key, PC1_Table, 56);

    // 2. 分割 C0 (高28位) 和 D0 (低28位)
    uint32 C = (uint32)(key_56 >> 28);
    uint32 D = (uint32)(key_56 & 0x0FFFFFFF);

    for (int i = 0; i < DES_ROUNDS; i++) {
        // 3. 循环左移 C 和 D
        int shift = Shift_Table[i];
        C = left_rotate_28(C, shift);
        D = left_rotate_28(D, shift);

        // 4. 合并 C 和 D (56位)
        uint64 CD_56 = (((uint64)C) << 28) | D;

        // 5. PC-2 置换 (56位 -> 48位子密钥 K[i])
        subkeys->K[i] = general_permute(CD_56, PC2_Table, 48);
    }
}

// 2. DES F函数 (Feistel Function)
// 这是 DES 每一轮的核心混淆函数： F(R, K)
static uint32 des_f_function(uint32 R_in, uint64 subkey) {
    // 1. 扩展置换 (E-Table): 32位 R_in -> 48位 E
    uint64 R_in_64 = (uint64)R_in;
    uint64 E = general_permute(R_in_64, E_Table, 48);

    // 2. 异或子密钥: B = E XOR subkey (48位)
    uint64 B = E ^ subkey;

    // 3. S盒置换: 48位 -> 32位
    uint32 sbox_output = 0;
    for (int i = 0; i < 8; i++) {
        // 提取 6 位输入块 B[i]
        uint8 input_6_bits = (uint8)((B >> (48 - 6 * (i + 1))) & 0x3F);

        // S盒的行索引：第 1 位 (MSB) 和 第 6 位 (LSB) 组合
        uint8 row = (input_6_bits & 0x20) >> 4;
        row |= (input_6_bits & 0x01);

        // S盒的列索引：中间 4 位 (Bit 5 到 Bit 2)
        uint8 col = (input_6_bits >> 1) & 0x0F;

        // 查 S 盒，得到 4 位输出
        uint8 output_4_bits = S_Boxes[i][row][col];

        // 放置到 32 位输出的对应位置
        sbox_output |= ((uint32)output_4_bits) << (32 - 4 * (i + 1));
    }

    // 4. P置换 (P-Box): 32位 sbox_output -> 32位 结果
    uint64 p_input = ((uint64)sbox_output) << 32;
    uint64 p_output_64 = general_permute(p_input, P_Table, 32);

    // 返回 P 置换后的 32 位结果
    return (uint32)(p_output_64 >> 32);
}

// 3. DES 加密块
// 对单个 64 位数据块执行 DES 加密
DES_Block des_encrypt_block(DES_Block block, const DES_Subkeys* subkeys) {
    // 1. 初始置换 (IP)
    uint64 permuted_block = general_permute(block, IP_Table, 64);

    // 2. 分割 L0 (高 32 位) 和 R0 (低 32 位)
    uint32 L = (uint32)(permuted_block >> 32);
    uint32 R = (uint32)permuted_block;

    // 3. 16 轮 Feistel 结构： L(i) = R(i-1); R(i) = L(i-1) XOR F(R(i-1), K(i))
    for (int i = 0; i < DES_ROUNDS; i++) {
        uint32 R_next = L ^ des_f_function(R, subkeys->K[i]);
        L = R;
        R = R_next;
    }

    // 4. 交换 L16 和 R16 (L16 || R16 -> R16 || L16)
    uint64 pre_fp_block = (((uint64)R) << 32) | L;

    // 5. 最终逆置换 (FP)
    return general_permute(pre_fp_block, FP_Table, 64);
}

// 4. DES 解密块
// 对单个 64 位密文块执行 DES 解密
DES_Block des_decrypt_block(DES_Block block, const DES_Subkeys* subkeys) {
    // 解密过程与加密相同，但子密钥 K[i] 的使用顺序是逆序的 (K[15], K[14], ..., K[0])

    // 1. 初始置换 (IP)
    uint64 permuted_block = general_permute(block, IP_Table, 64);

    // 2. 分割 L0 和 R0
    uint32 L = (uint32)(permuted_block >> 32);
    uint32 R = (uint32)permuted_block;

    // 3. 16 轮 Feistel 结构 (子密钥顺序逆序)
    for (int i = 0; i < DES_ROUNDS; i++) {
        // 使用子密钥 K[15], K[14], ..., K[0]
        uint32 R_next = L ^ des_f_function(R, subkeys->K[DES_ROUNDS - 1 - i]);
        L = R;
        R = R_next;
    }

    // 4. 交换 L16 和 R16
    uint64 pre_fp_block = (((uint64)R) << 32) | L;

    // 5. 最终逆置换 (FP)
    return general_permute(pre_fp_block, FP_Table, 64);
}

// 5. DES ECB 模式处理
// 实现了 DES 的电子密码本模式 (ECB)。对整个数据缓冲区进行分组处理。
bool des_ecb_process(const uint8* in_data, uint8* out_data, size_t length, const uint8* key, bool is_encrypt) {
    // 检查数据长度是否为块大小 (8字节) 的倍数。ECB 模式要求输入数据必须是整数块。
    if (length % DES_BLOCK_SIZE != 0) {
        // 在实际安全应用中，应使用填充 (Padding)
        return false;
    }

    // 密钥处理：将 8 字节数组转换为 64 位整数
    uint64 raw_key;
    memcpy(&raw_key, key, DES_KEY_SIZE);

    // 密钥调度：生成 16 个子密钥
    DES_Subkeys subkeys;
    des_key_schedule(raw_key, &subkeys);

    size_t num_blocks = length / DES_BLOCK_SIZE;
    for (size_t i = 0; i < num_blocks; i++) {
        // 读取当前 8 字节块
        uint64 input_block;
        memcpy(&input_block, in_data + i * DES_BLOCK_SIZE, DES_BLOCK_SIZE);

        uint64 output_block;
        if (is_encrypt) {
            // 执行加密
            output_block = des_encrypt_block(input_block, &subkeys);
        }
        else {
            // 执行解密
            output_block = des_decrypt_block(input_block, &subkeys);
        }

        // 将结果块写回输出缓冲区
        memcpy(out_data + i * DES_BLOCK_SIZE, &output_block, DES_BLOCK_SIZE);
    }

    return true;
}