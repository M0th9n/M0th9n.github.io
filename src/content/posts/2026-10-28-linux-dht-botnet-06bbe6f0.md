---
title: "恶意样本分析：Linux DHT-P2P botnet (B1txor20/Pink/Fodcha 谱系候选)（ELF · elf · 06bbe6f0）"
published: 2026-10-28
draft: false
description: "恶意（置信度低）：Linux DHT-P2P botnet (B1txor20/Pink/Fodcha 谱系候选) · botnet/backdoor · 难度 medium · emulation"
tags: ["botnet", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Linux DHT-P2P botnet (B1txor20/Pink/Fodcha 谱系候选)**（存疑） · 置信度 **低**
> 
> 别名：B1txor20、Pink、Fodcha、DHT botnet
> 
> 静态还原出自解压后的 PPC 主程序：含 BitTorrent DHT(KRPC) 报文构造、Ed25519 签名校验、ChaCha20 加密常量、/bin/sh -c 命令执行与会话单实例 IPC；动态侧在加固隔离实例内实际执行到载荷代码（创建 AF_UNIX 抽象套接字 six_sayven-<port>、创建 TCP 套接字并 connect 127.0.0[.]1:<port>，网络被拒后 exit_group(1)）。恶意性由静态可判定能力 + 动态真实执行共同支撑。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Linux DHT-P2P botnet (B1txor20/Pink/Fodcha 谱系候选)** · 别名 B1txor20、Pink、Fodcha、DHT botnet · _存疑_ |
| 置信度 | **低** |
| 行为类 | botnet · backdoor |
| 难度 | medium |
| 首次出现 | 2026-10-28 13:58:35 |
| 分析方法 | emulation |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/06bbe6f0d5549fc7e781c5cc0d411285d963aae4b1747c87b05a686cfe1fe8ff/) |

## 攻击链

<svg viewBox="0 0 720 226" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="150" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="38" fill="currentColor" font-weight="600" font-size="14">配置解密</text>
<text x="250" y="38" fill="currentColor" fill-opacity="0.65" font-size="12.5">AES 解密内置配置</text>
<text x="250" y="56" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="92" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="96" fill="currentColor" font-weight="600" font-size="14">连接 C2</text>
<text x="250" y="96" fill="currentColor" fill-opacity="0.65" font-size="12.5">原始 TCP 到硬编码 C2</text>
<text x="250" y="114" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="96" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="150" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="154" fill="currentColor" font-weight="600" font-size="14">远控 / 窃密</text>
<text x="250" y="154" fill="currentColor" fill-opacity="0.65" font-size="12.5">shell / 键盘 / 截屏 / 摄像头</text>
<text x="250" y="172" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1059</text>
<text x="613" y="154" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `06bbe6f0d5549fc7e781c5cc0d411285d963aae4b1747c87b05a686cfe1fe8ff` |
| MD5 | _未记录_ |
| 大小 | 124,688 字节（121.8 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **8** 条行为，每条都挂了证据；其中 **6** 条静态可得、**2** 条经动态分析取得。

### 1. 自解压 LZMA 主载荷

`T1027.002` · 置信度 **高** · 静态

入口 0x1009d228 起为 UPX-LZMA 解压存根（0x400 项概率表初始化、由首字节推导 lc/lp/pb），运行时解出约 33 万字节 PPC 主程序；加壳文件整体熵 7.994，静态字符串全为密文。

> **证据**：文件偏移 0x98/0x1e6e3 有 'UPX!' 标记, method=0x0e(LZMA); 0x1009d228 stwu/mflr + 0x400 概率表填充
> 
> **来源**：`ref:92f0dbaf1c` · `ref:3708f7b05f` · `ref:d23c115519`

### 2. 解析自身文件路径

`T1083` · 置信度 **中** · 静态

还原后的代码引用 '/proc/self/exe' 及 '%s/%s'、'..'、'.' 等路径拼接串，用于定位并复用自身可执行文件路径（自我复制/重启）。

> **证据**：还原块 2 偏移 0x77 '/proc/self/exe'（虚拟地址 0x100d00ff 附近），及 0x4d15c '%s-%u'、0x4d17c '%s/%s'
> 
> **来源**：`ref:6604bda969` · `ref:5d3d80dbfa`

### 3. 绑定单实例抽象套接字

`T1559` · 置信度 **高** · 动态

以 '%s-%u' 生成名称 'six_sayven-<端口>' 并 bind 到 AF_UNIX 抽象地址，作为本机单实例/进程间协调标记。

> **证据**：动态事件 bind(0, {sa_family=AF_UNIX, sun_path=@"six_sayven-63464"}) = 0；字符串 six_sayven 位于还原镜像 0x4d164
> 
> **来源**：`ref:f9cc3e7b77` · `ref:6604bda969` · `ref:f8f55147ca`

### 4. 探测回环网络后退出

`T1016` · 置信度 **高** · 动态

关闭 0/1/2 后创建 TCP 套接字、设置 SO_SNDTIMEO，connect 到 127.0.0[.]1:<同一端口>；在无网隔离环境返回 ENETUNREACH 后调用 exit_group(1)，说明其以本机连通性作为后续流程的前置条件。

> **证据**：trace: close(0/1/2) → socket(AF_INET) → setsockopt(SO_SNDTIMEO) → connect(..., htons(63464), 127.0.0[.]1) = -1 ENETUNREACH → exit_group(1)
> 
> **来源**：`ref:f9cc3e7b77` · `ref:f8f55147ca`

### 5. 接入 BitTorrent DHT 网络

`T1071` · 置信度 **高** · 静态

载荷内含完整 KRPC 报文模板，可向 DHT 发起 get/put/ping/get_peers 并处理 nodes/token/info_hash/target 字段，即通过 BitTorrent DHT 覆盖网收发指令，无固定 C2 地址。

> **证据**：还原镜像 0x4d343 '*d1:ad2:id20:'、0x4d3bc 'e1:q9:get_peers1:t2:'、0x4d384 'e1:q3:put1:t2:'、0x4d3ac '9:info_hash20:'、0x4d400 'id'/'sig'/'seq'/'token'
> 
> **来源**：`ref:6604bda969` · `ref:5d3d80dbfa`

### 6. 校验 Ed25519 签名指令

`T1553.002` · 置信度 **高** · 静态

内置 Ed25519 实现与域分隔串 'SigEd25519 no Ed25519 collisions'，配合 sig64/seq/v 字段对 DHT 中的下发指令做签名与序号校验，防止指令被伪造或重放。

> **证据**：还原镜像 0x4d460 'SigEd25519 no Ed25519 collisions'、0x4d35c '3:seqi%llde3:sig64:'
> 
> **来源**：`ref:6604bda969` · `ref:5d3d80dbfa`

### 7. ChaCha20 加密与编码

`T1573` · 置信度 **高** · 静态

存在 ChaCha20 常量 'expand 32-byte k' 与 z-base-32 字母表 'ybndrfg8ejkmcpqxot1uwisza345h769'，用于对 DHT 载荷加解密与紧凑编码。

> **证据**：还原镜像 0x4e5cc 'expand 32-byte k'、0x4d43c z-base-32 表
> 
> **来源**：`ref:6604bda969` · `ref:5d3d80dbfa`

### 8. 调用 shell 执行指令

`T1059.004` · 置信度 **高** · 静态

载荷含 '/bin/sh'、'sh'、'-c' 组合，具备把远端下发字符串交给系统 shell 执行的能力（僵尸网络指令执行面）。

> **证据**：还原镜像 0x4d220 '/bin/sh'、0x4d226 'sh'、0x4d22c '-c'
> 
> **来源**：`ref:6604bda969` · `ref:5d3d80dbfa`


## IOC（已去武器化）

### 网络

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| other | `BitTorrent DHT 覆盖网 (KRPC: get/put/get_peers/ping, 报文以 Ed25519 签名, z-base-32/ChaCha20 编码)` | - | c2 | 静态 | ⏳ 未观测 |
| dns | `2001:4860:4860[::]8888` | 53 | c2 | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `AF_UNIX 抽象套接字 six_sayven-<随机端口>（单实例标记）`

**落地路径**

- `/proc/self/exe`
- `/bin/sh`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_transport` | `BitTorrent DHT (KRPC over UDP)` | 是 | 静态 |
| `dht_queries` | `get / put / get_peers / ping, 字段 id/info_hash/token/nodes/target/sig/seq` | 是 | 静态 |
| `dht_command_auth` | `Ed25519 (sig64 + seq + v)` | 是 | 静态 |
| `encryption_algo` | `ChaCha20 ('expand 32-byte k') + z-base-32 编码` | 是 | 静态 |
| `dns_resolver` | `2001:4860:4860::8888` | 否 | 静态 |
| `command_shell` | `/bin/sh -c` | 是 | 静态 |
| `singleton_id` | `six_sayven-%u` | 是 | 静态 |
| `build_stamp` | `Jan 5 2022 14:22:37` | 否 | 静态 |
| `target_arch` | `ppc (32-bit big-endian)` | 是 | 静态 |
| `c2_hosts` | `未恢复：无固定 IP/域名，指令经 DHT 覆盖网按 info_hash 分发` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 样本没有可读的固定 IP/域名 C2，不能按传统 HTTP/DNS 面板 C2 描述；其指令通道是 BitTorrent DHT 覆盖网。
- 未发现勒索、擦除、浏览器凭据窃取等代码或行为证据，不得归类为 ransomware/wiper/stealer。
- 未观测到任何真实外联：唯一的 connect 目标是 127.0.0[.]1 且被隔离网络以 ENETUNREACH 拒绝，不能据此声称已定位或复现 C2 服务器。
- 运行日志中出现的 'wow i guess im finna bridge now' 不是样本输出（样本在关闭 0/1/2 后没有任何 write 调用），不能当作样本特征串。
- 未观测到 DDoS 流量或攻击指令被执行的证据，不能声称具备可直接利用的 DDoS 打击效果。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | emulation |
| 脱壳 | 是（stage2 `e95b76c2d7058fb6302c9b3ed0f38e55629bb0c5fa522161e7da3cea2f0f358f`） |

**局限与待验证**

1. 加壳导致全部静态字符串为密文，字符串与逻辑均来自自解压还原（LZMA 块边界由流解码逐步确定），还原镜像约 13.7KB 未覆盖。
2. 隔离环境无网，样本在 connect 127.0.0[.]1 返回 ENETUNREACH 后立即 exit(1)，DHT 阶段与指令执行未进入真实网络，故 C2/info_hash 标为静态恢复且待动态验证。
3. 家族归属仅基于能力指纹组合（DHT+Ed25519+ChaCha20+z-base-32），缺少厂商引擎或 YARA 独立确认，按候选处理。
4. 未取得 DHT 公钥/20 字节 info_hash 的确定位置，无法给出可复现的节点定位信息。
5. 本样本为 PPC 架构，无法在 x86 环境本机执行，动态观测仅来自跨架构用户态仿真与系统调用追踪。

## 证据索引

<details>
<summary>展开 17 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:aea59b70e6` | ELF 结构解析 | 加壳 ELF 结构：PPC32 大端 EXEC，无 interp/符号/导入，3 个段（RW 0x10000000 filesz 0x1000 memsz 0x751d8；RX 0x10080000 filesz 0x1e600） |
| `ref:165ba42849` | elf.sections | 段表：RW-/R-X/GNU_STACK，无节表（已被加壳移除） |
| `ref:3708f7b05f` | scan.entropy | 整文件熵 7.994，符合加密/压缩壳 |
| `ref:e95607e7a5` | 字符串提取 | 加壳态仅 539 条无意义 ASCII 串，无任何可读配置或 C2 |
| `ref:92f0dbaf1c` | disasm.function | 入口 0x1009d228 反汇编：栈探测 + 位运算，为解压存根而非业务代码 |
| `ref:f8f55147ca` | emu.qemu | 跨架构仿真执行 exit=0 记录，arch=ppc，隔离无网（unshare -n） |
| `ref:4e04f06eab` | bash | 取回仿真产物：detonate.json/stdout.txt/stderr.txt/trace.log |
| `ref:f9cc3e7b77` | bash | 系统调用追踪：guest 关闭 0/1/2、bind AF_UNIX @six_sayven-63464、connect 127.0.0[.]1:63464=ENETUNREACH、exit_group(1) |
| `ref:d23c115519` | bash | 自行实现 LZMA 块定位与解压（lc3/lp0/pb2），还原镜像 0x5160d 字节并构造可解析 ELF |
| `ref:5d3d80dbfa` | bash | 哈希：原样本 sha256 与还原镜像 sha256 e95b76c2…f358f |
| `ref:af3adea1e3` | ELF 结构解析 | 还原后 ELF 解析成功：单 R-X 段 0x10080000，size 333325，entry 0x10080000 |
| `ref:da6ec3d99a` | decompile.symbols | 还原后识别 3356 个函数（静态 libc + 主程序），确认载荷为可执行 PPC 程序 |
| `ref:b4d42e2211` | decompile.function | 反编译 0x10080024：__libc_csu_init 风格 init 数组遍历，印证标准静态 uClibc 程序结构 |
| `ref:59e1300f47` | decompile.function | 反编译 0x100800e0：libc 启动辅助例程，返回 .data 基址 |
| `ref:6604bda969` | 字符串提取 | 还原后字符串：DHT KRPC 模板、Ed25519 域分隔串、z-base-32 表、expand 32-byte k、/bin/sh、six_sayven、2001:4860:4860::8888、ppc、Jan 5 2022 14:22:37 |
| `ref:5bc6fef3da` | bash | capstone 扫描 56973 条指令，未发现直接 lis 0x100c/0x100d 取串（经 TOC/数据表间接寻址） |
| `ref:7k8suqzo4` | bash | 尝试定位品牌/家族串（pink/aisuru/fodcha/mirai 等）均未命中，佐证家族判定需依赖能力指纹 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
