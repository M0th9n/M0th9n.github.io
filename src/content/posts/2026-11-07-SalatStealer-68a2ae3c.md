---
title: "恶意样本分析：SalatStealer（PE · exe · 68a2ae3c）"
published: 2026-11-07
draft: false
description: "恶意（置信度高）：SalatStealer · stealer/rat/backdoor · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Salat", "stealer", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **SalatStealer** · 置信度 **高**
> 
> 别名：Salat、Salat RAT、salat/2.0
> 
> 动态沙箱中样本进程真实运行并周期性外连两个 .cn 域名，向 /qqkb/ 路径 POST 数据；结合内置浏览器凭据窃取、键盘记录、屏幕/摄像头采集、令牌窃取与远程命令模块，判定为窃密与远控混合恶意软件。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **SalatStealer** · 别名 Salat、Salat RAT、salat/2.0 |
| 置信度 | **高** |
| 行为类 | stealer · rat · backdoor |
| 难度 | hard |
| 首次出现 | 2026-11-04 14:42:18 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/68a2ae3c48e8da2c291354023c92330193589430024477765cb1acf26717f61d/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">DoH解析C2域名</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.004</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">向双域名回传数据</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1041</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">窃取浏览器凭据</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">收集会话与钱包</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">记录键盘与截屏</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001, T1113</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `68a2ae3c48e8da2c291354023c92330193589430024477765cb1acf26717f61d` |
| MD5 | _未记录_ |
| 大小 | 6,495,232 字节（6.2 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **11** 条行为，每条都挂了证据；其中 **9** 条静态可得、**2** 条经动态分析取得。

### 1. DoH解析C2域名

`T1071.004` · 置信度 **高** · 动态

通过 1.1.1[.]1、8.8.8[.]8、dns.google 的 DoH 接口查询并获取 C2 域名地址，绕过本地 DNS 监控。

> **证据**：动态：进程 7308 连接 1.1.1[.]1:443/8.8.8[.]8:443，请求 /dns-query?name=morkovka[.]cn 与 /resolve?name=sa1atik[.]cn；静态字符串 0x4B01EB、0x4CFFD8。
> 
> **来源**：`ref:8a13a267b8` · `ref:b0fdf2ab16`

### 2. 向双域名回传数据

`T1041` · 置信度 **高** · 动态

解析成功后向两个域名的 /qqkb/ 路径发送 HTTP POST，携带主机与窃取数据，并周期性重连。

> **证据**：动态：启动后约 30 秒起 POST /qqkb/，Host 分别为 morkovka[.]cn、sa1atik[.]cn；后续每约 20 秒重连，UA 为 salat/2.0。
> 
> **来源**：`ref:8a13a267b8` · `ref:b0fdf2ab16`

### 3. 窃取浏览器凭据

`T1555.003` · 置信度 **高** · 静态

枚举 Chromium/Gecko 用户配置，提取 cookies、登录凭据、autofill 与扩展数据，使用 CryptUnprotectData 及 Local State 主密钥解密。

> **证据**：字符串 0x4A6278 src/makelog/invdump/chrome.rs、0x4A6296 gecko.rs、0x4AD16F Local State/app_bound_encrypted_key、0x4A3287 Browsers/Logins_；导入 CryptUnprotectData。
> 
> **来源**：`ref:b0fdf2ab16` · `ref:3b4d64aae0`

### 4. 收集会话与钱包

`T1539` · 置信度 **高** · 静态

收集 Telegram tdata、Discord/Steam/Roblox 令牌与本地加密钱包，并通过公链 RPC 查询余额。

> **证据**：字符串 0x4A2FD7 telegram candidates、0x4A2FEE DiscordTokens.txt、0x4A304D SteamTokens.txt、0x4A30A6 zipping wallets；动态 DNS 查询 toncenter[.]com、tonapi[.]io、eth[.]drpc[.]org 等。
> 
> **来源**：`ref:b0fdf2ab16` · `ref:8a13a267b8`

### 5. 记录键盘与截屏

`T1056.001, T1113` · 置信度 **高** · 静态

安装全局键盘钩子并轮询按键状态，使用 GDI 抓取屏幕像素，形成键盘记录与屏幕截图。

> **证据**：字符串 0x4D1DBC keytest-quit-helper、0x4D1E38 SetWindowsHookExW returned NULL；导入 GetAsyncKeyState、SetWindowsHookExW、BitBlt、GetDIBits。
> 
> **来源**：`ref:b0fdf2ab16` · `ref:3b4d64aae0`

### 6. 开启摄像头与录音

`T1125` · 置信度 **高** · 静态

通过 Media Foundation 枚举视频设备并采集摄像头帧，同时使用音频库采集麦克风数据。

> **证据**：字符串 0x4A7400 src/camera.rs、0x4A6B08 src/sound.rs；导入 MFEnumDeviceSources、MFTEnumEx、D3D11CreateDevice 及 cpal 相关符号。
> 
> **来源**：`ref:b0fdf2ab16` · `ref:3b4d64aae0`

### 7. 执行远程命令

`T1059` · 置信度 **高** · 静态

内置 shell、文件管理、任务管理、进程挂起/恢复与上传下载模块，可接受控制端指令执行命令并回传输出。

> **证据**：字符串 0x4A297B src/shell.rs、0x4A7458 src/execute.rs、0x4A789A src/filemanager.rs、0x4A7990 src/taskmanager.rs；导入 CreateProcessW、CreatePipe、NtSuspendProcess/NtResumeProcess。
> 
> **来源**：`ref:b0fdf2ab16` · `ref:3b4d64aae0`

### 8. 跨会话窃取令牌

`T1134.001` · 置信度 **高** · 静态

枚举会话与进程令牌，复制/模拟 SYSTEM 或已登录用户令牌，切换到活动会话后以该令牌创建进程。

> **证据**：字符串 0x4D2480 OpenProcessToken、0x4D24D0 SetTokenInformation(TokenSessionId=)、0x4D16A8 CreateProcessWithTokenW、0x4D1F9A migrate_session；导入 WTSQueryUserToken、DuplicateTokenEx、CreateProcessAsUserW。
> 
> **来源**：`ref:b0fdf2ab16` · `ref:3b4d64aae0`

### 9. 注册服务与自启动

`T1547.001, T1543.003` · 置信度 **中** · 静态

写入当前用户 Run 键，并具备创建/启动 Windows 服务的能力，用于开机自启与权限维持。

> **证据**：字符串 0x4D1A11 SOFTWARE\Microsoft\Windows\CurrentVersion\Run、0x4ABF60 OpusUpdateOpusSvc；导入 RegSetValueExW、CreateServiceW、StartServiceW。
> 
> **来源**：`ref:b0fdf2ab16` · `ref:3b4d64aae0`

### 10. 添加Defender排除

`T1562.001` · 置信度 **高** · 静态

内置 base64 编码的 PowerShell 脚本，调用 Add-MpPreference 将 Program Files、AppData、LocalAppData 加入 Defender 排除路径。

> **证据**：偏移 0x4AE838 的 base64 解码为 PowerShell：Add-MpPreference -ExclusionPath（ProgramFiles、ProgramFilesX86、ApplicationData、LocalApplicationData）。
> 
> **来源**：`ref:b0fdf2ab16`

### 11. RDP隧道与内网代理

`T1572, T1021.001` · 置信度 **中** · 静态

包含 RDP 子会话、WebSocket/QUIC/HTTP3 隧道与代理模块，可在受控端建立远程桌面与内网转发通道。

> **证据**：字符串 rdp_child/src/rdp/*、0x4A6F71 connect p2_server tunnel、0x4A6998 src/proxy.rs、0x4A6B48 tokio-tungstenite、0x4A6690 h3/quinn；导入 WTSEnableChildSessions、WTSQueryUserToken。
> 
> **来源**：`ref:b0fdf2ab16` · `ref:3b4d64aae0`


## IOC（已去武器化）

### 网络

:::note
**已动态观测到连接**：样本实际向该目标发起 TCP 连接（短时间内多次重试）。
:::

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控仿真服务完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://morkovka[.]cn/qqkb/` | 443 | c2 | 动态 | 已观测 |
| http | `hxxps://sa1atik[.]cn/qqkb/` | 443 | c2 | 动态 | 已观测 |

### 主机

**互斥体**

- `Global\WEBR_FL0APC6K5F44`

**落地路径**

- `%APPDATA%\Local\<browser profile data>`
- `%LOCALAPPDATA%\<browser profile data>`
- `%ProgramFiles%\<install_dir>\opus-installscript`
- `%ProgramFiles(x86)%\<install_dir>\opus-installscript`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

**服务**

- `OpusUpdate`
- `OpusSvc`

**计划任务**

- `OpusElvMigrate`
- `OpusElvScreen`
- `OpusElvChild`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `morkovka[.]cn, sa1atik[.]cn` | 是 | 动态 |
| `c2_path` | `/qqkb/` | 是 | 动态 |
| `user_agent` | `salat/2.0` | 是 | 静态 |
| `dns_over_https` | `1.1.1[.]1, 8.8.8[.]8, dns.google` | 否 | 动态 |
| `mutex` | `Global\WEBR_FL0APC6K5F44` | 否 | 静态 |
| `persistence_run_key` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | 否 | 静态 |
| `service_names` | `OpusUpdate, OpusSvc` | 否 | 静态 |
| `install_marker` | `opus-installscript, opus-runscript, opus-child-stdin` | 否 | 静态 |
| `encryption_algo` | `AES-GCM/ChaCha20-Poly1305; TLS 1.3 (rustls) for C2 transport` | 否 | 静态 |
| `defender_exclusion_script` | `base64 PowerShell Add-MpPreference exclusion paths` | 否 | 静态 |
| `browser_targets` | `Chromium/Gecko cookies, logins, tokens, autofill` | 是 | 静态 |
| `wallet_and_session_targets` | `Telegram tdata, Discord/Steam/Roblox tokens, crypto wallets, Ethereum/TON RPC` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 未见文件加密、卷影删除或勒索信，不能归为 ransomware/wiper。
- 内置完整窃密与远控模块，并非仅下载后续载荷的 downloader/loader。
- 未捕获真实 C2 IP；域名通过 DoH 解析，1.1.1[.]1/8.8.8[.]8 是解析通道，不是 C2 服务器。
- 动态运行中未直接观察到提权成功、服务实际注册或安装目录落地，相关能力主要来自代码字符串与 API 面。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 静态未提取到明文配置；C2 域名来自动态 DoH 解析与 POST 请求观测。
2. 安装目录、服务注册与计划任务的最终名称未在动态窗口内直接确认，IOC 依据内置字符串推断。
3. RDP 子会话、摄像头/音频采集等能力由模块路径与 API 面证明，沙箱内未实际触发。
4. C2 真实 IP 未解析（网络被安全重定向），仅保留域名级 IOC。
5. 家族命名依据内置 salat/2.0 标识与回连域名，未获得厂商引擎或 YARA 规则交叉确认。

## 证据索引

<details>
<summary>展开 9 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 |
| `ref:260dbdc87a` | 样本分诊 | 6 段、熵 6.37/6.44、无壳、40 DLL/415 导入 |
| `ref:ccc8eeb9ea` | PE 结构解析 | PE64 GUI、入口 RVA 0x3885A0、无异常 |
| `ref:3b4d64aae0` | 导入表解析 | CryptUnprotectData、SetWindowsHookExW、WTSQueryUserToken、CreateServiceW 等 |
| `ev-000009` | 字符串提取 | Rust 工程路径、浏览器/钱包/Telegram 目标与 C2 相关字符串 |
| `ev-000013` | 密码学常量识别 | AES S-box、SHA-256、CRC32、base64 常量 |
| `ref:379b82c521` | unpack.detect | 未检测到加壳 |
| `ref:8a13a267b8` | 动态分析平台 | 真实运行 PID 7308；DoH 解析 morkovka[.]cn/sa1atik[.]cn，POST /qqkb/，UA salat/2.0 |
| `c2_evidence:68a2ae3c` | 连接证据提取 | 动态网络监控记录到 123 次到 1.1.1[.]1:443, 1[.]1[.]1[.]1:443, 1rpc[.]io:443, 8.8.8[.]8:443, base-mainnet[.]public[.]blastapi[.]io:443, base[.]api[.]pocket[.]network:443, base[.]gateway[.]tenderly[.]co:443, dns[.]google:443, gateway[.]tenderly[.]co:443, mainnet[.]base[.]org:443, morkovka[.]cn:443, rpc[.]baseazul[.]dev:443, sa1atik[.]cn:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
