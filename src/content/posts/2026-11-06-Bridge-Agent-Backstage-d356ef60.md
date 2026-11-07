---
title: "恶意样本分析：Bridge Agent / Backstage（PE · exe · d356ef60）"
published: 2026-11-06
draft: false
description: "恶意（置信度中）：Bridge Agent / Backstage · stealer/rat · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Bridge Agent", "stealer", "rat", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Bridge Agent / Backstage**（存疑） · 置信度 **中**
> 
> 别名：BridgeAgent、Backstage、rxclient、rxinj
> 
> 在隔离动态环境中，样本自行运行并向硬编码 IP 176.65.144[.]46:443 以 multipart 方式上传 21,640,997 字节的 forensics.zip；运行期内存与临时目录显示其并行采集浏览器凭据、钱包、即时通讯、SSH、云与 Wi-Fi 配置，并生成 54,542,958 字节的 LSASS 内存转储。数据采集、凭据窃取与固定地址外传均已直接观测。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Bridge Agent / Backstage** · 别名 BridgeAgent、Backstage、rxclient、rxinj · _存疑_ |
| 置信度 | **中** |
| 行为类 | stealer · rat |
| 难度 | hard |
| 首次出现 | 2026-11-03 14:36:10 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/d356ef60fbcb9b6903823a87ae6f146fc879f84813076a9ebd343b1ac3e35ea2/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">收集浏览器凭据</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">注入浏览器窃密钥</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">转储 LSASS 凭据</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1003.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">窃取钱包与聊天数据</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">收集 WiFi 与系统凭据</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `d356ef60fbcb9b6903823a87ae6f146fc879f84813076a9ebd343b1ac3e35ea2` |
| MD5 | _未记录_ |
| 大小 | 10,748,438 字节（10.3 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **10** 条行为，每条都挂了证据；其中 **3** 条静态可得、**7** 条经动态分析取得。

### 1. 收集浏览器凭据

`T1555.003` · 置信度 **高** · 动态

枚举 Chrome、Edge、Brave、Opera、Vivaldi、Firefox、Yandex 的用户配置目录，提取 Cookies、Passwords、Cards、IBANs、Tokens、Local Extension Settings，并把整个 profile 复制到输出目录。

> **证据**：RVA 0x26a6a1（文件偏移 0x2690a1）附近字符串 'Google\Chrome\User Data … Cookies … PASSWORDS … CARDS … IBANS … TOKENS'；动态内存出现 output\Browsers\installed_browsers.txt 与 [CHROMIUM]/[FIREFOX]/[WALLETS] collected 日志。
> 
> **来源**：`ref:60d4ce909d` · `ref:a83af8f3c6` · `ref:544e0b5ea9`

### 2. 注入浏览器窃密钥

`T1055` · 置信度 **高** · 动态

释放内置 helper.exe 到 %TEMP%\rxinj_<时间戳>\，通过命名管道读取 App-Bound Encryption Key / Copilot App-Bound Encryption Key 及 Cookies、Passwords、Cards、IBANs、Tokens；加载器日志显示以直接系统调用在目标进程分配内存、写入数据并创建远程线程。

> **证据**：文件偏移 0x108fc2 起为内嵌 helper.exe（1,423,360 字节）；其字符串含 'App-Bound Encryption Key'、'__DLL_PIPE_COMPLETION_SIGNAL__'、'Allocating memory in target process via syscall...'、'Creating remote thread via syscall...'；动态内存出现路径 ...\Temp\rxinj_1793917890002939300\helper.exe。
> 
> **来源**：`ref:60d4ce909d` · `ref:a83af8f3c6`

### 3. 转储 LSASS 凭据

`T1003.001` · 置信度 **高** · 动态

释放 lss.exe 到 %TEMP%\rxlss_<时间戳>\，对 lsass.exe 生成内存转储，输出到 output\mimikatz-credentials\lss.dmp；运行日志记录 'dump 54542958 bytes'。

> **证据**：文件偏移 0x264aa0 起为内嵌 lss.exe（16,896 字节，无导入表、纯系统调用）；文件偏移 0x268cac 处含 '[LSASS] running lss.exe...'、'lss.dmp'、'mimikatz-credentials'；动态内存含 '[INFO] [LSASS] dump 54542958 bytes' 与 output\mimikatz-credentials\lss.dmp。
> 
> **来源**：`ref:d3fb77fedb` · `ref:6060cd3615` · `ref:f296979c36`

### 4. 窃取钱包与聊天数据

`T1555` · 置信度 **高** · 动态

复制 Exodus、Ledger Live、Trezor Suite、Electrum、Sparrow、Atomic、Guarda、Monero GUI、Bitcoin Core 等钱包数据，以及 Telegram、Discord、Slack、Signal、Outlook、Steam、笔记和远程工具配置。

> **证据**：字符串 'bitcoin-qt.exe'、'monero-wallet-gui.exe'、'Ledger Live.exe'、'Trezor Suite.exe' 及 '[TELEGRAM] collected'、'[CHAT] collected'、'[STEAM] collected'、'[REMOTE_ACCESS] collected'。
> 
> **来源**：`ref:60d4ce909d` · `ref:a83af8f3c6`

### 5. 收集 WiFi 与系统凭据

`T1555` · 置信度 **高** · 静态

执行 netsh wlan show profiles 导出 Wi-Fi 配置，读取 Windows Vault、RDP 连接记录（Default.rdp）、whoami /groups、环境变量与已安装软件清单。

> **证据**：字符串 'powershell-Command netsh wlan show profiles'、'wifi_networks.txt'、'WindowsVault'、'Default.rdp'、'privileges.txt'、'system_env.txt'、'installed_software.txt'。
> 
> **来源**：`ref:60d4ce909d`

### 6. 双重ZIP打包数据

`T1560.001` · 置信度 **高** · 静态

35 个采集线程并行执行；T+90 秒生成 FAST ZIP，T+300 秒生成 COMPLETE ZIP，代码注释强调不跳过任何数据。

> **证据**：字符串 '[MAIN] DUAL TRANSMISSION STRATEGY'、'Fast ZIP at 90s + Complete ZIP at 5min (NEVER SKIPS DATA)'、'[PARALLEL] waiting for all 35 collectors to complete'。
> 
> **来源**：`ref:60d4ce909d`

### 7. 上传取证包至固定IP

`T1041` · 置信度 **高** · 动态

以 multipart/form-data 向 hxxps://176[.]65[.]144[.]46/api/forensics 上传 ZIP，携带 x-device-id、x-signature、x-country、x-public-ip 请求头及 protocol、message_id、type、device_id、sequence、sent_at、country、public_ip、size_bytes、zip_file 字段；实测单次上传 21,640,997 字节。

> **证据**：动态：PID 7256 发起 TCP 176.65.144[.]46:443；HTTP 请求为 POST /api/forensics，content-length 21642465，type=forensics.zip，size_bytes=21640997；静态字符串位于文件偏移 0x2694ba/0x2694d8/0x269521。
> 
> **来源**：`ref:544e0b5ea9` · `ref:b35981618a` · `ref:debd9c13f6`

### 8. 查询地理位置规避

`T1614` · 置信度 **高** · 动态

访问 hxxp://ip-api[.]com/json/?fields=countryCode 获取出口国家，设备 ID 采用 XX_<公网IP> 形式；配置显示 GEO_BLOCKING_ENABLED=false。

> **证据**：动态 GET /json/?fields=countryCode，Host: ip-api[.]com；字符串 '[GEO] Geo-blocking disabled (GEO_BLOCKING_ENABLED=false)' 与 'countryCode'。
> 
> **来源**：`ref:544e0b5ea9` · `ref:60d4ce909d`

### 9. 临时目录暂存组件

`T1074.001` · 置信度 **高** · 动态

在 %LOCALAPPDATA%\Temp 下创建 rxclient_<时间戳>、rxinj_<时间戳>、rxlss_<时间戳> 目录，分别存放采集结果、helper.exe 与 lss.exe；任务结束后清理 rxclient 目录。

> **证据**：动态内存路径 'C:\Users\<user>\AppData\Local\Temp\rxclient_1793917877417917500\output'、'...\rxinj_1793917890002939300\helper.exe'、'...\rxlss_1793917890231685800\lss.exe'。
> 
> **来源**：`ref:a83af8f3c6` · `ref:f296979c36`

### 10. 附加远控组件

`T1219` · 置信度 **中** · 静态

主程序在最后一个节的数据之后附加 7,533,734 字节的完整 PE（bridge.exe）；其字符串表明为具备 Backstage 工作区、私有 CA WebSocket、ConPTY 命令行、剪贴板与输入注入、浏览器配置迁移能力的远控代理，并设置 HKCU Run 自启动；本次观测窗口内未看到该组件执行。

> **证据**：文件偏移 0x30F600 起附加 PE；字符串 'bridge-agent-v5.1.4-chrome-launch-fidelity'、'Local\BridgeAgent-'、'HKCU\Software\Microsoft\Windows\CurrentVersion\RunBridgeAgent'、'X-Bridge-Server-Time'。
> 
> **来源**：`ref:bd70bd6229` · `ref:d47603756a`


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
| http | `hxxps://176[.]65[.]144[.]46/api/forensics` | 443 | exfil | 动态 | 已观测 |
| http | `hxxps://176[.]65[.]144[.]46/api/agent/connect` | 443 | c2 | 动态 | 已观测 |

### 主机

**互斥体**

- `Local\BridgeAgent-<session id>`

**落地路径**

- `%LOCALAPPDATA%\Temp\rxclient_<timestamp>\output`
- `%LOCALAPPDATA%\Temp\rxclient_<timestamp>\output\octo-fingerprint.json`
- `%LOCALAPPDATA%\Temp\rxclient_<timestamp>\output\mimikatz-credentials\lss.dmp`
- `%LOCALAPPDATA%\Temp\rxinj_<timestamp>\helper.exe`
- `%LOCALAPPDATA%\Temp\rxlss_<timestamp>\lss.exe`
- `%ProgramData%\BridgeAgent`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BridgeAgent`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `176.65.144[.]46:443` | 是 | 静态 |
| `exfil_endpoint` | `/api/forensics` | 是 | 动态 |
| `connect_endpoint` | `/api/agent/connect` | 是 | 静态 |
| `upload_type` | `forensics.zip` | 是 | 动态 |
| `request_headers` | `X-Device-ID; X-Signature; X-Country; X-Public-IP` | 是 | 动态 |
| `device_id_format` | `XX_<public_ip>` | 是 | 动态 |
| `geo_lookup` | `hxxp://ip-api[.]com/json/?fields=countryCode` | 否 | 动态 |
| `geo_blocking_enabled` | `false` | 否 | 静态 |
| `zip_schedule` | `fast=90s; complete=300s` | 是 | 静态 |
| `encryption_algo` | `none (plain ZIP in multipart/form-data)` | 否 | 动态 |
| `mutex` | `Local\BridgeAgent-<session id>` | 否 | 静态 |
| `install_path` | `%ProgramData%\BridgeAgent` | 否 | 静态 |
| `persistence` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BridgeAgent` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不是勒索软件：未发现文件加密、扩展名篡改或赎金说明，行为集中在窃取与外传。
- 不是挖矿程序：未发现矿池地址、挖矿库或算力相关组件。
- 未观察到蠕虫式传播或横向移动执行：'[LATERAL] collected' 仅表示收集远程访问配置，不等于横向移动。
- 附加的 bridge.exe 本次未被观察到执行，不能断言其已完成安装或持久化。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 按隔离要求未进行真实外网连接，C2 域名、服务器归属与 TLS 证书信息未能获取，仅确认硬编码 IP 与端口。
2. 附加的 bridge.exe 远控组件在本次观测窗口内未执行，其持久化与远程控制能力来自静态字符串推断。
3. 未定位到明文配置块；配置项由静态字符串与动态请求字段恢复，若存在额外加密配置未能确认。
4. LSASS 转储文件已生成但未进一步解析，无法列出其中的具体账号口令。
5. 家族命名缺少公开引擎或规则交叉印证，'Bridge Agent / Backstage' 为基于内置标识的候选归属。

## 证据索引

<details>
<summary>展开 14 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:1614b1909c` | 样本分诊 | 哈希、分节熵、加壳评分 0、导入面统计 |
| `ref:4b4e2baba2` | PE 结构解析 | AMD64 GUI PE，5 节，入口 RVA 0x101f80，镜像大小 0x312000 |
| `ref:6cd264693f` | 导入表解析 | 17 个 DLL/182 个导入，含 ws2_32、crypt32、secur32、ntdll 文件与管道 API |
| `ref:60d4ce909d` | 字符串提取 | 收集器、钱包、浏览器、LSASS、C2 与双 ZIP 策略字符串 |
| `ref:bd70bd6229` | PE 结构解析 | 尾部附加 PE：6 节、镜像 0x736000、GUI 子系统 |
| `ref:d47603756a` | 导入表解析 | 附加 PE 导入 USER32/CRYPT32/CreatePseudoConsole 等远控相关 API |
| `ref:d3fb77fedb` | PE 结构解析 | 内嵌 lss.exe：4 节、无导入、控制台子系统 |
| `ref:6060cd3615` | 导入表解析 | lss.exe 导入表为空（纯系统调用） |
| `ref:544e0b5ea9` | 动态分析平台 | 样本真实引爆：进程 7256 持续运行，捕获内存转储与网络重定向日志 |
| `ref:b35981618a` | script | 从网络监控日志提取 POST /api/forensics 请求头、multipart 字段与 21,640,997 字节大小 |
| `ref:debd9c13f6` | script | 从网络监控日志确认 TCP 176.65.144[.]46:443 与 ip-api[.]com 查询 |
| `ref:a83af8f3c6` | script | 从内存转储提取 rxclient/rxinj/rxlss 路径、octo-fingerprint.json 与 C2 字符串 |
| `ref:f296979c36` | script | 从运行期内存提取 '[INFO] [LSASS] dump 54542958 bytes' 与 mimikatz-credentials\lss.dmp 路径 |
| `c2_evidence:d356ef60` | 连接证据提取 | 动态网络监控记录到 5 次到 176.65.144[.]46:443, ip-api[.]com:80 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
