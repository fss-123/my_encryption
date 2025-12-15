MyCryptoLib 是一个从零开始构建的、基于原生 C/C++ 实现的轻量级密码学算法库。本项目旨在通过零外部依赖 (Zero-dependency) 的方式，完整复现现代密码学的核心算法体系，是深入理解密码学底层原理和工程实现的绝佳范本。

注意: 本项目主要用于教育、学习和研究目的。虽然逻辑严密，但在生产环境中建议使用经过广泛审计的工业级库（如 OpenSSL）。

项目特色 (Features)
零依赖: 仅使用 C/C++ 标准库，无需安装 OpenSSL 或其他第三方库。

模块化设计: 严格遵循接口与实现分离原则 (.h / .cpp)。

全栈覆盖: 涵盖对称加密、非对称加密、密钥交换、数字签名、哈希函数及消息认证。

底层实现: 亲自实现了模幂运算、扩展欧几里得算法、有限域运算及位级置换。

跨平台: 代码标准，可在 Windows (Visual Studio) 和 Linux (GCC/Clang) 环境下编译。

🛠️ 支持的算法 (Algorithms)
1. 对称加密 (Symmetric Encryption)
DES: 经典 Feistel 结构，包含完整的初始置换 (IP)、轮函数及逆置换。

AES-128 (ECB): 实现 SP 网络，包含 SubBytes, ShiftRows, MixColumns, AddRoundKey。特别处理了 x86 架构下的大端序 (Big-Endian) 兼容性问题。

2. 非对称加密 (Asymmetric Encryption)
RSA: 基于大整数分解困难问题。实现了密钥生成、加解密、签名及验签。

ElGamal: 基于离散对数问题 (DLP)。支持随机化加密（密文对结构）及签名。

ECC: 椭圆曲线密码学。实现了点加、点倍积、标量乘法，支持 ECDSA 签名及 ECC-ElGamal 加密。

3. 密钥交换与签名 (Key Exchange & Signatures)
Diffie-Hellman (DH): 实现公开通道下的安全密钥协商。

DSA: NIST 标准数字签名算法。

4. 哈希与认证 (Hash & MAC)

SHA-256: 实现了标准的 Init-Update-Final 流式处理架构。

HMAC-SHA256: 实现了基于哈希的消息认证码，保障消息完整性与真实性。

MyCryptoLib/
├── include/          # 头文件 (接口声明)
│   ├── aes.h
│   ├── des.h
│   ├── rsa.h
│   ├── ecc.h
│   ├── utils.h       # 核心数学库与辅助函数声明
│   └── ...
├── src/              # 源文件 (算法实现)
│   ├── aes.cpp
│   ├── des.cpp
│   ├── rsa.cpp
│   ├── utils.cpp     # 模幂、GCD、位操作的具体实现
│   └── ...
├── test/             # 单元测试 (Unit Tests)
│   ├── test_aes.cpp
│   ├── test_rsa.cpp
│   └── ...
├── my_encryption.cpp # 主程序入口 (交互式菜单)
└── README.md         # 项目文档
