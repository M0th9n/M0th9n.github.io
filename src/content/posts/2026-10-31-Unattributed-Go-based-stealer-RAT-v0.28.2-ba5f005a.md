---
title: "恶意样本分析：Unattributed Go-based stealer/RAT (v0.28.2)（PE · exe · ba5f005a）"
published: 2026-10-31
draft: false
description: "恶意（置信度低）：Unattributed Go-based stealer/RAT (v0.28.2) · stealer/rat/backdoor · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["stealer", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unattributed Go-based stealer/RAT (v0.28.2)**（存疑） · 置信度 **低**
> 
> 样本为 UPX 加壳的 32 位 Go 程序，在隔离 Windows 环境中真实运行并持续外联（TCP/443、UDP/443），内存取像恢复了完整载荷；载荷字符串包含浏览器登录凭据/Cookie 的 SQL 查询、加密钱包与 Telegram/Discord/Steam 数据采集、剪贴板/屏幕/摄像头采集、远程 Shell/端口转发、计划任务持久化以及 QUIC/WebSocket 与 DoH 通信代码，功能上构成窃密木马兼远程控制后门。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unattributed Go-based stealer/RAT (v0.28.2)** · _存疑_ |
| 置信度 | **低** |
| 行为类 | stealer · rat · backdoor |
| 难度 | medium |
| 首次出现 | 2026-10-29 00:45:20 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ba5f005a7d4c9969ef3152be044ea3875d598e0838fa4f905e5491f129cc4cc5/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX自解压装载载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">窃取浏览器登录凭据</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">导出Cookie与自动填充</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">收割加密钱包与TON</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555, T1005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">QUIC与DoH隐蔽回连</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001, T1573</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ba5f005a7d4c9969ef3152be044ea3875d598e0838fa4f905e5491f129cc4cc5` |
| MD5 | _未记录_ |
| 大小 | 3,592,878 字节（3.4 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **12** 条行为，每条都挂了证据；其中 **11** 条静态可得、**1** 条经动态分析取得。

### 1. UPX自解压装载载荷

`T1027.002` · 置信度 **高** · 静态

文件为三节 UPX 自解压结构（UPX0/UPX1/UPX2），入口位于高熵可写可执行节 UPX1，运行时在内存中还原出约 12.9 MB 的 Go 载荷。

> **证据**：UPX1 熵 8.0；导入仅 4 个 (LoadLibraryA/GetProcAddress/VirtualProtect/ExitProcess)；内存载荷入口 rva 0xC54020。
> 
> **来源**：`ev-000008` · `ev-000005` · `ref:6143f4c3f4` · `ref:327dc29626`

### 2. 窃取浏览器登录凭据

`T1555.003` · 置信度 **高** · 静态

遍历主流浏览器配置目录，用 SQLite 查询读取保存的用户名/密码并解密浏览器主密钥。

> **证据**：字符串 'SELECT origin_url, action_url, username_value, password_value, date_created FROM logins'、Firefox 'SELECT item1,item2 FROM metaData WHERE id = password'、'key4.db'、'logins.json'、'Local State'。
> 
> **来源**：`ref:8e3e4ea0f1` · `ev-000039`

### 3. 导出Cookie与自动填充

`T1539` · 置信度 **高** · 静态

读取浏览器 Cookie 与自动填充数据库，导出 host/path/过期时间及加密值。

> **证据**：字符串 'SELECT name,encrypted_value,host_key,path,expires_utc FROM cookies WHERE length(encrypted_value) > 0'、'SELECT name, value, host, path, expiry FROM moz_cookies'、'Autofills'、'cookies.sqlite'。
> 
> **来源**：`ref:8e3e4ea0f1`

### 4. 收割加密钱包与TON

`T1555, T1005` · 置信度 **高** · 静态

扫描浏览器钱包扩展与本地钱包目录，读取钱包密钥/地址，并集成 TON 区块链库处理 TON 钱包。

> **证据**：钱包名列表 Metamask/Phantom/Keplr/TronLink/Exodus/Electrum 等；'Crypto\Roaming'、'Electrum\wallets'、'XMR.PT'；依赖 github[.]com/xssnick/tonutils-go@v1.16.0。
> 
> **来源**：`ref:8e3e4ea0f1` · `ref:22e1ccc08c`

### 5. 窃取Discord与Telegram与Steam会话

`T1528, T1555` · 置信度 **高** · 静态

提取 Discord 令牌、Telegram tdata 会话与 Steam 登录信息。

> **证据**：字符串 'Clients\DiscordTokens.txt'、'$appdata\discord'、'tdata'、'loginusers.vdf'、'SteamPath'、'found tg process'。
> 
> **来源**：`ref:8e3e4ea0f1` · `ref:22e1ccc08c`

### 6. 监控剪贴板与屏幕

`T1115, T1113` · 置信度 **高** · 静态

读取剪贴板内容（含钱包地址/口令）并调用截图库抓取屏幕。

> **证据**：API 字符串 GetClipboardData/SetClipboardData/OpenClipboard；'Clipboard:'、'PrintScreen'；符号 salat/screenshot.CaptureRect。
> 
> **来源**：`ref:8e3e4ea0f1` · `ref:22e1ccc08c`

### 7. 采集摄像头与麦克风

`T1125` · 置信度 **高** · 静态

通过 ffmpeg 风格采集管道获取摄像头画面与麦克风音频，供远程端查看。

> **证据**：符号 ffwcam/ffwmic/DesktopFF；字符串 'aformat=sample_fmts=s32:channel_layouts=mono:sample_rates=32000'、'audio= video='。
> 
> **来源**：`ref:22e1ccc08c`

### 8. 开放远程Shell与端口转发

`T1059, T1090` · 置信度 **高** · 静态

内置远程 Shell、端口转发与分块文件传输能力，通过 WebSocket 收发指令与数据。

> **证据**：符号 startShell/stopShell/shellProc/portFwd/recvWss/wsMessage/chunkSize；字符串 'cmd.Run failed with %s'、'taskkill /F /PID'。
> 
> **来源**：`ref:22e1ccc08c`

### 9. 注册计划任务持久化

`T1053.005` · 置信度 **高** · 静态

通过 Task Scheduler COM 接口注册/删除计划任务，配置仅在联网时启动以维持存活。

> **证据**：接口/属性字符串 ITaskService、RegisterTaskDefinition、StartBoundary、RunOnlyIfNetworkAvailable、error registering task；依赖 capnspacehook/taskmaster。
> 
> **来源**：`ref:22e1ccc08c` · `ref:881f995d64`

### 10. 滥用令牌提升权限

`T1134` · 置信度 **中** · 静态

调整进程特权并复制/滥用访问令牌，以便读取受保护进程与浏览器数据。

> **证据**：字符串 RtlAdjustPrivilege、OpenProcessToken、DuplicateTokenEx、CopySid、'OpenProcess failed: %v'、'lsass.exe'。
> 
> **来源**：`ref:8e3e4ea0f1`

### 11. QUIC与DoH隐蔽回连

`T1071.001, T1573` · 置信度 **高** · 动态

使用 QUIC/HTTP3 与 WebSocket 作为命令通道，并通过 DoH 解析 C2 域名以规避 DNS 监控。

> **证据**：依赖 quic-go@v0.38.1；字符串 1.1.1[.]1/dns-query、cloudflare-dns[.]com/dns-query、dns.google/resolve、bestConnMethod、http3 DISABLED；动态观测到进程 1768 向 UDP 1.1.1[.]1:443 与 TCP 假网地址:443 反复连接（TCP 443 共 128 次）。
> 
> **来源**：`ref:21fbc7a749` · `ref:881f995d64` · `ref:9188bc1dfc`

### 12. 内嵌WASM模块加载

`T1027.009` · 置信度 **中** · 静态

载荷内嵌两个 WebAssembly 模块，运行时由 wazero 解释执行，用于隐藏部分逻辑。

> **证据**：内存镜像偏移 0x69C6A0 与 0xB56B38 处均为 '00 61 73 6D 01 00 00 00' 魔数；依赖 tetratelabs/wazero@v1.8.2。
> 
> **来源**：`ref:22e1ccc08c` · `ref:881f995d64`


## IOC（已去武器化）

### 网络

:::note
**已动态观测到连接**：样本实际向该目标发起 TCP 连接（短时间内多次重试）。
:::

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| other | `hxxps://1[.]1[.]1[.]1/dns-query` | 443 | c2 | 动态 | 已观测 |
| other | `hxxps://cloudflare-dns[.]com/dns-query` | 443 | c2 | 静态 | ⏳ 未观测 |
| other | `hxxps://dns[.]google/resolve` | 443 | c2 | 静态 | ⏳ 未观测 |
| other | `C2 host hidden behind DoH (not recovered)` | 443 | c2 | 动态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%LOCALAPPDATA%\<browser>\User Data\Local State`
- `%LOCALAPPDATA%\<browser>\User Data\Default\Login Data`
- `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\key4.db`
- `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\logins.json`
- `%APPDATA%\discord\Local Storage\leveldb`
- `%APPDATA%\<wallet>\Crypto\Roaming`
- `%TEMP%\chunk`
- `%APPDATA%\<app>\Clients\DiscordTokens.txt`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `version` | `0.28.2 (x86)` | 否 | 静态 |
| `c2_transport` | `QUIC/HTTP3 + WebSocket (gorilla/websocket)` | 是 | 静态 |
| `dns_resolvers` | `1.1.1[.]1 / cloudflare-dns[.]com / dns.google (DoH)` | 是 | 静态 |
| `c2_host` | `unresolved (DoH-resolved at runtime; not recovered)` | 是 | 动态 |
| `c2_port` | `443` | 否 | 动态 |
| `persistence` | `Windows Task Scheduler COM (RegisterTaskDefinition)` | 否 | 静态 |
| `encryption_algo` | `AES-CBC (browser master key), X25519, DPAPI` | 否 | 静态 |
| `browser_targets` | `Chrome/Chromium 系、Firefox、Edge、Brave、Opera 等 30+ 浏览器` | 否 | 静态 |
| `wallet_targets` | `MetaMask/Phantom/Keplr/TronLink/Exodus/Electrum/TON 钱包等` | 否 | 静态 |
| `capabilities` | `credential/cookie/wallet/Discord/Telegram/Steam/clipboard/screen/webcam/mic/shell/port-forward/file-transfer` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能判定为勒索软件：未见用户文件批量加密、勒索信、卷影删除或备份破坏逻辑；AES/CBC 常量用于浏览器主密钥解密而非文件加密。
- 不能判定为挖矿程序：未见矿池地址、Stratum 协议或 xmrig 相关字符串，动态期间亦未观察到矿池连接。
- 不能断言存在蠕虫式横向移动：未观测到 SMB/PsExec/远程服务创建等横向行为。
- 不能断言属于某个已命名商业家族：缺少厂商签名、YARA 命中或可读配置，家族归属存疑。
- UPX 解压存根中的 rdtsc/int 2Dh/cpuid 命中属加壳器运行时特征，不能据此认定样本主动实施反调试。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `086db9c7dc770690474e48b74e1be1a0c23934d94d812ab8dae7954e32d8c9fd`） |

**局限与待验证**

1. 实际 C2 域名未取回：样本优先使用 DoH（1.1.1[.]1 / cloudflare-dns[.]com / dns.google）解析，假网 DNS 无法记录明文查询。
2. 动态观测中的 192.0.2[.]123:443 是隔离环境的假网应答地址，并非真实 C2，不应作为外部 IOC 使用。
3. 恢复的载荷来自进程内存取像（已按内存对齐重建），与磁盘原始未加壳文件可能存在节区布局差异；其哈希仅标识该内存映像。
4. 未观察到计划任务、注册表写入等持久化动作的具体落地记录，持久化能力依据代码/字符串推断，动态未闭环。
5. 未获取到可命名家族的签名或配置，家族字段仅为能力描述，置信度低。
6. UPX 解压存根触发的反调试启发式命中未被动态验证为样本自身行为。

## 证据索引

<details>
<summary>展开 17 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | SHA256/MD5/SHA1 与文件大小 3,592,878 字节 |
| `ev-000008` | 样本分诊 | 加壳可能性 85%，UPX 段名、W^X、导入仅 4 个 |
| `ref:6143f4c3f4` | 导入表解析 | 原始导入仅 KERNEL32: LoadLibraryA/ExitProcess/GetProcAddress/VirtualProtect |
| `ref:327dc29626` | unpack.detect | 识别为 UPX，置信度 0.9 |
| `ref:cafc67b8d0` | unpack.antidebug | UPX1 段内 rdtsc/int 2Dh/cpuid 命中（加壳器存根） |
| `ref:9188bc1dfc` | 动态分析平台 | 真实引爆成功，PID 1768 存活并产生 16 个内存转储文件 |
| `ref:f7e6706ca5` | sandbox.timeline | 时间线：1 个候选进程，hollows 扫描 2 个可疑对象 |
| `ref:97090bbd97` | 内存转储 | 转储报告：PID 1768 为 32 位非托管进程，主模块 0xC55000 字节 |
| `ref:9a5b32b80a` | 动态产物收集 | 假网日志与转储导入线索；样本发起大量 443 连接 |
| `ref:33aa545e67` | PE 结构解析 | 内存载荷 PE 结构：I386、3 节、入口 rva 0xC54020 |
| `ev-000039` | 字符串提取 | 内存载荷字符串：Go build ID、QUIC 帧、钱包/浏览器相关串 |
| `ref:881f995d64` | strings | Go 构建信息、模块依赖、DoH 端点与 QUIC 库 |
| `ref:8e3e4ea0f1` | strings | 浏览器 SQL 查询、钱包列表、Discord/Telegram/Steam 路径、任务计划与令牌 API |
| `ref:21fbc7a749` | strings | 配置/域名提取与假网事件统计：1768 向 443 发起 128 次 TCP 及 UDP 连接 |
| `ref:22e1ccc08c` | strings | 远程控制能力符号（shell/portFwd/ffwcam/ffwmic）与两处 WASM 魔数 |
| `ref:dda6b8e31f` | strings | 排除勒索/挖矿关键字，未发现命名家族标识 |
| `c2_evidence:ba5f005a` | 连接证据提取 | 动态网络监控记录到 130 次到 1.1.1[.]1:443, sa1atik[.]cn:443, ton[.]access[.]orbs[.]network:443, tonapi[.]io:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
