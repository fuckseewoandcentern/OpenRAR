# OpenRAR — 开源的RAR 5.0 压缩与归档工具 (Clean-Room Implementation)

## 免责声明及法律参考

* **AI生成与责任赦免**：该项目100%由**Gemini 4 Argon**独立开发，不保证其功能完成度以及是否存在设计缺陷，对您造成的财产损失比如功能异常或者电脑爆炸该项目所有者一概不负责
* **使用目的**：该文件夹及其子目录下的所有资源仅供学习和研究使用。其旨在为学术和研究人员提供参考和资料，任何其他目的均不适用。
* **非商业与非法用途**：严禁将此文件夹及其内容用于任何商业或非法用途。对于因违反此规定而产生的任何法律后果，用户需自行承担全部责任。
* **来源与版权**：该文件夹目录下的所有资源信息均来源于公开的格式规范与开源社区参考。如有关于版权的争议或问题，请联系原作者或权利人。本声明者与版权问题无关且不承担任何相关责任。
* **下载后的处理**：请注意，您在下载任何资源后，必须在 24 小时内从您的电脑或存储设备中彻底删除上述资源，无论这些资源是软件、文档还是其他形式的数据。
* **支持正版**：如果您觉得rar对您有帮助或您喜欢它，请到RARLAB购买正版WinRAR/RAR-CLI。购买和注册正版软件可以获取官方的支持和更新。
* **法律参考**：根据《计算机软件保护条例》（2002 年 1 月 1 日实施）的第十七条规定：为了学习和研究软件内含的设计思想和原理，通过安装、显示、传输或者存储软件的方式使用软件，可以不经软件著作权人许可，不向其支付报酬。鉴于此，我们强烈建议用户在使用该文件夹及其内容时，遵循上述法规，并确保其行为目的仅限于学习和研究软件内部的设计思想和原理。
* **最终解释权**：本免责声明的最终解释权归声明者所有。
* **解释权说明**：本声明中的“最终解释权”条款并非意在单方面施加权利或霸王条款，而是为了在可能出现的模糊或争议情况下提供清晰的指导和解释。其目的是确保本声明的内容和意图得到恰当和公正的实施，同时为用户提供更明确的方向和帮助。

在使用该文件夹及其内容前，请确保已仔细阅读并完全理解上述声明和法律参考。您的使用行为将被视为对上述内容的完全接受。

---

## 项目简介

**OpenRAR** 是一个采用净室设计（Clean-Room Design）、以 **GNU GENERAL PUBLIC LICENSE Version 3 or later(GPL v3.0-or-later)** 许可协议授权的 RAR 5.0 压缩器与解压器。

* **零专有代码**：本项目**不直接基于来自 RARLAB 的任何代码**（不包含 `unrar` 源码或任何商业组件），所有压缩、解压、加密、哈希及容器读写逻辑均依据公开的 [RAR 5.0 Archive Format Specification](https://www.rarlab.com/technote.htm) 与开源项目 [`unrar-free`](https://gitlab.com/bgermann/unrar-free) 的设计思想独立实现。
* ~~**无任何商业激活机制**：彻底移除了官方 CLI 中的注册密钥检查（`rarreg.key`）、评估版提示及 `已注册给 ...` 等激活相关机制。~~ 后续版本将增加该功能（并不会影响任何功能使用）
* **双向 100% 兼容**：
  * 由本工具 `rar.exe` 创建的 RAR 5.0 压缩包（含存储 `-m0`、LZSS+Huffman 压缩 `-m1`..`-m5`、固实模式 `-s`、AES-256 加密 `-p`/`-hp`、BLAKE2sp 校验 `-htb`、注释 `-z`、自解压 `-sfx`、分卷 `-v`、恢复记录 `-rr`）可直接被官方 WinRAR (`Rar.exe`) 校验与解压。
  * 由官方 WinRAR (`Rar.exe`) 创建的 RAR 5.0 压缩包可直接被本工具列表（`l`/`v`/`lt`/`lb`）、测试（`t`）、解压（`x`/`e`/`p`）与修改（`c`/`cw`/`rn`/`d`/`k`/`r`）。
* **双 CLI 兼容模式**：同时支持官方 `Rar.exe` 的全部命令/开关体系（含完整简体中文 CLI 输出），以及 `unrar-free` 的 GNU 长选项（`--extract`、`--list`、`--extract-no-paths`、`--force`、`--password`）。

---

## 核心架构与源码结构

```text
rar/
├── include/
│   ├── rar_defs.h       # RAR 5.0 规范常量、变长整数 (vint) 编解码、头部与额外记录定义
│   ├── rar_crypto.h     # CRC32、BLAKE2sp (8 路并行树哈希)、SHA-256、PBKDF2、AES-256-CBC 接口
│   ├── rar_codec.h      # RAR 5.0 LZSS 滑动窗口 + 范式哈夫曼压缩器与解压器 (含 4 类滤波器)
│   ├── rar_archive.h    # RAR 5.0 容器解析、序列化、固实归档、分卷、SFX 自解压与修复引擎
│   └── rar_cli.h        # CLI 参数解析器与命令执行器接口
├── src/
│   ├── rar_crypto.cpp   # 密码学与校验和算法的独立净室实现
│   ├── rar_codec.cpp    # RAR 5.0 比特流压缩 (Rar5Compressor) 与解压 (Rar5Decompressor)
│   ├── rar_archive.cpp  # 归档容器读写、多卷自动拼接、QOpen 快速打开与恢复记录实现
│   ├── rar_cli.cpp      # 复刻官方 Rar.exe 与 unrar-free 的命令行交互实现
│   └── main.cpp         # Windows Unicode 命令行入口与 SFX 自解压检测
├── tests/
│   └── test_compat.py   # 与官方 WinRAR CLI 的双向端到端兼容性自动化测试套件
├── CMakeLists.txt       # 跨平台 CMake 构建脚本
├── build.bat            # Windows MSVC 一键编译脚本
└── LICENSE              # GNU General Public License v3.0 (GPL-3.0-or-later)
```

---

## RAR 5.0 压缩与格式原理分析

### 1. 容器结构与变长整数 (`vint`)
* **魔数签名**：RAR 5.0 固定以 8 字节签名 `52 61 72 21 1A 07 01 00`（`Rar!\x1a\x07\x01\x00`）起始。在 `rar_defs.h` 中，该常量采用 `0xA1` 异或掩码存储于静态区，防止将 `rar.exe` 作为自解压（SFX）存根时在 `.rdata` 段误匹配出伪签名。
* **`vint` 编码**：所有头部字段采用小端 Base-128 变长无符号整数，每字节低 7 位存放数据，最高位（`0x80`）为延续标志位。
* **块头部布局**：`HeaderCRC32 (uint32) | HeaderSize (vint) | HeaderType (vint) | HeaderFlags (vint) | [ExtraAreaSize (vint)] | [DataSize (vint)] | TypeSpecificFields | [ExtraArea] | [DataArea]`。

### 2. LZSS 滑动窗口与范式哈夫曼编码 (`Rar5Compressor` / `Rar5Decompressor`)
* **数据块格式**：每个压缩块由字节对齐的块头起始，包含 `BlockFlags`（指示表是否更新、是否为最后一个块及末字节有效比特数）、`BlockBitSize`、`BlockByteSize` 以及块头校验和（`0x5A ^ BlockFlags ^ ...`）。
* **四棵范式哈夫曼树**：
  1. **主字母表 (`MAIN_HUFF_SIZE = 306`)**：`0..255` 为字面量字节，`256` 为滤波器指令，`257` 为重复上一次匹配（距离与长度均不变），`258..261` 为引用 4 槽位距离缓存 `dist_cache_[0..3]` 并从 RD 树读取长度，`262..305` 为显式距离匹配（内嵌匹配长度槽位）。
  2. **距离偏移表 (`DIST_HUFF_SIZE = 64`)**：编码匹配距离的高位槽位，低位由固定额外比特与低 4 位对齐树（`LD`）共同组成。
  3. **低位距离表 (`LOW_DIST_HUFF_SIZE = 16`)**：编码距离的低 4 位（或 `0xFF` 重复上一次低 4 位）。
  4. **重复长度表 (`REP_LEN_HUFF_SIZE = 44`)**：编码 `258..261` 距离缓存命中的匹配长度。
* **远距离隐式长度补偿**：对于显式距离匹配（符号 `262..305`），当 `distance > 0x100` 时基础匹配长度隐式 `+1`；`> 0x2000` 时再 `+1`；`> 0x40000` 时再 `+1`。

### 3. 密钥派生与校验和混淆 (`rar_crypto.cpp`)
* **PBKDF2-HMAC-SHA256**：使用 16 字节随机盐执行单链 PBKDF2：
  * 在 `1 << KdfCount` 次迭代处派生 256 位 AES-CBC 加密密钥 `aes_key`；
  * 继续迭代 `+16` 次派生校验和混淆密钥 `hash_key`；
  * 继续迭代 `+32` 次派生密码验证值 `psw_check_val`（折叠异或为 8 字节并附带 4 字节 SHA-256 校验前缀）。
* **Tweaked Checksum (`CFL5_TWEAKED`)**：文件加密时，头部中的 CRC32 或 BLAKE2sp 会与 `HMAC-SHA256(hash_key, raw_checksum)` 进行混淆，避免通过明文哈希泄露被加密文件的身份。

---

## 编译与测试

### 1. 编译构建
在 Windows 环境下（需安装 Visual Studio C++ 工具链）：
```bat
build.bat
```
或使用 CMake：
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```
构建完成后将在项目根目录生成 `rar.exe` 与 `unrar-free.exe`。

### 2. 运行双向兼容性测试
```bash
python tests/test_compat.py
```

---

## 常用命令行示例

```bash
# 创建 RAR 5.0 压缩包（默认 -m3 标准压缩，递归子目录）
rar a -r archive.rar src_dir

# 创建固实 (-s)、最大压缩 (-m5)、使用 BLAKE2sp 校验 (-htb) 的压缩包
rar a -r -s -m5 -htb solid_archive.rar src_dir

# 创建加密文件与加密文件头 (-hp) 的压缩包
rar a -r -hpMySecretPassword secure.rar src_dir

# 创建自解压可执行压缩包 (-sfx)
rar a -r -sfx installer.exe src_dir

# 列出压缩包内容（简略 / 详细 / 技术详情 / 纯文件名）
rar l archive.rar
rar v archive.rar
rar lt archive.rar
rar lb archive.rar

# 测试压缩包完整性
rar t archive.rar

# 解压压缩包到指定目录
rar x -y archive.rar output_dir\

# unrar-free 兼容长选项模式
unrar-free --list archive.rar
unrar-free --extract --force archive.rar output_dir\
```
