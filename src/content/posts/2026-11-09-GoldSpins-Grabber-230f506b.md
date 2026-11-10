---
title: "恶意样本分析：GoldSpins Grabber（PE · exe · 230f506b）"
published: 2026-11-09
draft: false
description: "恶意（置信度低）：GoldSpins Grabber · stealer/injector · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["GoldSpins Grabber", "stealer", "injector", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **GoldSpins Grabber**（存疑） · 置信度 **低**
> 
> 静态反编译确认其为一次性内存窃密器：枚举 Chromium/Firefox 凭据与 Cookie、加密钱包、Discord/Telegram/Steam/Roblox 令牌、密码管理器、FTP/VPN 配置并截屏，然后将 ZIP 上传到 hxxps://goldspins[.]club/gate。真实动态环境进一步观测到其释放内置 DLL、启动无头 msedge、DNS 查询 goldspins.club / ip-api[.]com，以及带有 X-Build-ID=582501ca、X-HWID、X-Token 的 97,756 字节 ZIP POST（内含 Screenshot.jpg、FileGrabber/TextFiles、DetectedDomains.txt），因此判定为恶意且证据为运行期自证。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **GoldSpins Grabber** · _存疑_ |
| 置信度 | **低** |
| 行为类 | stealer · injector |
| 难度 | medium |
| 首次出现 | 2026-11-06 07:01:23 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/230f506bb813f4950bba612d0804ce34a1fee8bf24e8d068ac9a34979f0a835b/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">反沙箱与反调试</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">释放内置载荷DLL</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">启动无头浏览器</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">注入浏览器窃密</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">解密浏览器数据</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `230f506bb813f4950bba612d0804ce34a1fee8bf24e8d068ac9a34979f0a835b` |
| MD5 | _未记录_ |
| 大小 | 1,482,240 字节（1.4 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **10** 条行为，每条都挂了证据；其中 **6** 条静态可得、**4** 条经动态分析取得。

### 1. 反沙箱与反调试

`T1497.001` · 置信度 **高** · 静态

启动阶段串联四项检查：自身可执行文件名中连续十六进制/数字长度、当前进程名、系统进程列表、HKLM 注册表键名；命中 sandboxie/cuckoo/procmon/wireshark/fiddler/x64dbg/ollydbg/windbg/IDA/processhacker/vmware/VirtualBox/QEMU/Xen/Parallels 等关键词即退出。关键词表以 XOR 0x5A 混淆，运行时解码。

> **证据**：FUN_140007fb0 依次调用 FUN_140007df0/FUN_140007690/FUN_140007890/FUN_140007b60；RegOpenKeyExA(HKLM)、Process32First/Next、GetModuleFileNameA；仿真可见 RegOpenKeyExA 传入 XOR 后字符串。
> 
> **来源**：`ev-000036` · `ev-000038` · `ev-000039` · `ev-000040` · `ev-000025` · `ref:f9c2607a4b`

### 2. 释放内置载荷DLL

`T1027` · 置信度 **高** · 动态

从 .data 内嵌的 MZ 映像（rva 0xf8820，0x4a00 字节）提取 payload_v3.dll 到 %TEMP%\<8位十六进制>.dll。本次动态运行观测到 C:\Users\analyst\AppData\Local\Temp\0043820B.dll 被创建。

> **证据**：FUN_140008500 检查 MZ 头后 CreateFileA/WriteFile 写入 %TEMP%\%08X.dll；动态文件创建事件 TargetFilename=C:\Users\analyst\AppData\Local\Temp\0043820B.dll。
> 
> **来源**：`ev-000032` · `ref:f19ab4471d`

### 3. 启动无头浏览器

`T1106` · 置信度 **高** · 动态

定位 Chrome/Edge/Brave 安装路径，使用 CreateProcessA 启动 "<browser>" --headless --disable-gpu --no-sandbox --disable-software-rasterizer，为后续注入与 App-Bound Encryption 密钥解密准备宿主进程。动态观测到 msedge.exe 以上述命令行启动。

> **证据**：FUN_140009f70 拼接无头参数并调用 CreateProcessA；动态进程创建事件 Image=msedge.exe，CommandLine 含 --headless --disable-gpu --no-sandbox --disable-software-rasterizer。
> 
> **来源**：`ev-000034` · `ev-000035` · `ref:f19ab4471d`

### 4. 注入浏览器窃密

`T1055` · 置信度 **高** · 静态

以 VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryA) 将 payload_v3.dll 注入无头浏览器。该 DLL 读取浏览器 Local State 的 app_bound_encrypted_key，通过 IElevator COM 解出 32 字节 App-Bound Encryption 密钥并写入 C:\Windows\Temp\payload_log.txt；主程序轮询日志提取 Key 并缓存至内存。

> **证据**：FUN_14000a320 注入链；FUN_140009700 轮询 payload_log.txt 并按十六进制解析 32 字节 key；payload_v3.dll 导出 elevator_init/elevator_decrypt_key 并使用 CoCreateInstance/CoSetProxyBlanket。
> 
> **来源**：`ev-000033` · `ev-000026` · `ref:3cadef3374` · `ref:f19ab4471d`

### 5. 解密浏览器数据

`T1555.003` · 置信度 **高** · 静态

使用内嵌 SQLite 读取 Chrome/Edge/Brave 的 cookies、Login Data、Web Data，调用 CryptUnprotectData 处理 DPAPI，并用 BCrypt AES-GCM 解密 v10/v20 Cookie；同时读取 Firefox cookies.sqlite 与 logins.json，尝试 PK11SDR_Decrypt。

> **证据**：FUN_1400f26a0 主收集函数；字符串 "SELECT host_key, name, encrypted_value..."、"CryptUnprotectData"、"BCryptDecrypt"、"%s\\Local State"、"SELECT host, name, value..."。
> 
> **来源**：`ev-000027` · `ev-000029` · `ev-000024` · `ref:4636600a8b`

### 6. 收集钱包与令牌

`T1555` · 置信度 **高** · 静态

遍历 40 余种浏览器钱包扩展与桌面钱包（MetaMask、Phantom、TrustWallet、Exodus、Electrum、Ledger Live、Monero、Bitcoin Core 等），并收集 Discord Tokens、Telegram tdata、Steam JWT、Roblox Cookies、Google Refresh Tokens、密码管理器（Bitwarden/1Password/KeePass/Dashlane/NordPass）、FileZilla、OpenVPN/WireGuard/CyberGhost 配置。

> **证据**：字符串表 Wallets/Extensions/%s_%s、Wallets/Desktop/%s、Discord/Tokens.txt、Telegram/tdata、Gaming/Steam/MemoryTokens.txt、Browsers/Google Accounts/RefreshTokens.txt、PasswordManagers/*、FTP/FileZilla/recentservers.xml、VPN/*。
> 
> **来源**：`ev-000024` · `ev-000027`

### 7. 截屏并打包外传

`T1041` · 置信度 **高** · 动态

用 GDI BitBlt + GDI+ 生成 Screenshot.jpg，将截图、FileGrabber/TextFiles 文档与 DetectedDomains.txt 打包为 ZIP，通过 WinHTTP POST 上传至 hxxps://goldspins[.]club/gate。动态抓包显示 Content-Length=97756，请求头包含 X-Build-ID: 582501ca、X-HWID: 6431AF93-E7480E04、X-Token: hSgOlyXfIkv1ED5zLWqKn9p4HAZu0wJY。

> **证据**：FUN_14000c670 WinHttpOpen/Connect/OpenRequest(POST)/SendRequest，UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"；动态 POST /gate 的 ZIP 内含 Screenshot.jpg、FileGrabber/TextFiles/*.txt、DetectedDomains.txt。
> 
> **来源**：`ev-000028` · `ev-000027` · `ref:f19ab4471d`

### 8. 查询出口IP归属

`T1016` · 置信度 **高** · 动态

上传前先请求 ip-api[.]com 的 /line/?fields=countryCode,query，获取出口 IP 与国家代码，推测用于地域判断或数据标注。该域名为公开 IP 地理位置服务，不是攻击者基础设施。

> **证据**：动态 DNS 查询 ip-api[.]com 与 GET /line/?fields=countryCode,query（Host: ip-api[.]com，User-Agent: Mozilla/5.0）。
> 
> **来源**：`ref:f19ab4471d`

### 9. 上报Clipper状态

`T1071.001` · 置信度 **中** · 静态

存在向 hxxps://goldspins[.]club/clipper 发送状态上报的代码路径，X-Clipper-Status 取值为 installed/already_installed/failed/not_embedded；本次运行未观测到该请求，也未观测到实际的剪贴板监控或地址替换行为。

> **证据**：FUN_14000d1b0 拼接 "%s/clipper" 并 POST，构造 Content-Type: text/plain、X-Build-ID、X-HWID、X-Clipper-Status、可选 X-Token 头。
> 
> **来源**：`ev-000030`

### 10. 混淆字符串与API

`T1027` · 置信度 **高** · 静态

大量敏感字符串以 XOR 0x5A 加密存储（反沙箱名单、钱包/浏览器关键字等）；WinHTTP、advapi32、crypt32、bcrypt、iphlpapi 等 API 通过哈希常量在运行时解析，规避静态导入特征。

> **证据**：FUN_140007160 以 FUN_140008250(hash1, hash2) 填充 API 指针表；FUN_140007b60/FUN_140007690/FUN_140007890 对字符串原地 XOR 0x5A 后再比较。
> 
> **来源**：`ev-000037` · `ev-000024` · `ev-000025`


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
| http | `hxxps://goldspins[.]club/gate` | 443 | c2 | 动态 | 已观测 |
| http | `hxxps://goldspins[.]club/clipper` | 443 | download | 动态 | 已观测 |

### 主机

**落地路径**

- `%TEMP%\<8位十六进制>.dll`
- `C:\Windows\Temp\payload_log.txt`
- `%LOCALAPPDATA%\Temp\grabber_pipe.txt`
- `\\.\pipe\grabber_<pid>_<tid>`
- `Local\grabber_shm_<pid>_<tid>`
- `\\.\pipe\grabber_dummy`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `goldspins[.]club` | 是 | 动态 |
| `c2_url` | `hxxps://goldspins[.]club/gate` | 是 | 动态 |
| `c2_port` | `443` | 是 | 动态 |
| `build_id` | `582501ca` | 是 | 动态 |
| `auth_token` | `hSgOlyXfIkv1ED5zLWqKn9p4HAZu0wJY` | 是 | 动态 |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` | 是 | 动态 |
| `clipper_endpoint` | `hxxps://goldspins[.]club/clipper` | 否 | 静态 |
| `clipper_status_values` | `installed\|already_installed\|failed\|not_embedded` | 否 | 静态 |
| `ip_check_url` | `hxxp://ip-api[.]com/line/?fields=countryCode,query` | 否 | 动态 |
| `hwid` | `运行时生成；本次观测值 6431AF93-E7480E04` | 否 | 动态 |
| `encryption_algo` | `Chromium 数据：DPAPI + AES-GCM (BCryptDecrypt)；Chrome App-Bound Encryption：IElevator COM` | 否 | 静态 |
| `embedded_payload` | `payload_v3.dll, 18944 bytes, sha256 5f7d95ef0a18e315d572ae57ad94ef08d8ff892785e7e034d4ad113c417464fb` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能称为 ransomware/wiper：没有加密或删除用户文件、没有勒索信；BCrypt/DPAPI 仅用于解密浏览器 Cookie/密钥。
- 不能称为持久化后门或 RAT：未创建 Run 键、服务、计划任务，动态运行中也没有命令循环或长期驻留。
- 不能称为通用下载器/投放器：内置 payload_v3.dll 只是 Chrome App-Bound Encryption 辅助模块，未观测到下载或执行任意第二阶段。
- 不能把 ip-api[.]com 当作攻击者 C2：它是公开的 IP 地理位置查询服务，仅用于出口 IP/国家判断。
- 不能声称存在剪贴板劫持：代码含 /clipper 状态上报路径，但本次未观测到剪贴板监控或钱包地址替换。
- 不能声称写注册表持久化：注册表仅被读取用于反虚拟机检测和已安装软件枚举。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次动态运行未触发 /clipper 上报，也未观测到实际剪贴板劫持；该路径仅由静态代码确认。
2. 未对 msedge 进程做定向内存取证，因此 DLL 是否成功加载到浏览器进程未被直接观测；注入结论基于注入代码、Temp DLL 落地与无头 msedge 进程创建。
3. 反沙箱字符串经 XOR 0x5A 解码后存在拼写变体（如 sandfox/vmwaro/procmonroxo），部分关键字匹配可能失效；不影响整体窃密结论。
4. HWID 的生成算法未完整还原，仅记录运行时观测值 6431AF93-E7480E04。
5. 未观测到持久化、自删除或剪贴板劫持；未获取 C2 返回的业务响应内容。
6. 样本内嵌 SQLite 静态库并保留调试节，静态阅读容易；但部分字符串解码存在变体，阅读时需以实际解密结果为准。

## 证据索引

<details>
<summary>展开 22 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与 imphash |
| `ev-000003` | scan.entropy | .text 熵 6.263，未见高熵加壳段 |
| `ev-000024` | 字符串提取 | 浏览器/钱包/令牌/截图/上传等字符串与路径 |
| `ev-000002` | 导入表解析 | 9 个 DLL/211 个符号，含 GDI+、WinHTTP 间接调用相关的 Crypt32、CreateRemoteThread 等 |
| `ev-000036` | decompile.ghidra | FUN_140007fb0 反虚拟机总开关 |
| `ev-000038` | decompile.ghidra | FUN_140007df0 枚举 HKLM 注册表键名做反虚拟机检查 |
| `ev-000039` | decompile.ghidra | FUN_140007690 枚举进程名做反分析检查 |
| `ev-000040` | decompile.ghidra | FUN_140007890 检查自身文件名/关键字 |
| `ev-000032` | decompile.ghidra | FUN_140008500 提取内嵌 MZ 到 %TEMP% |
| `ev-000034` | decompile.ghidra | FUN_140009f70 以无头参数 CreateProcessA 启动浏览器 |
| `ev-000033` | decompile.ghidra | FUN_14000a320 VirtualAllocEx/WriteProcessMemory/CreateRemoteThread 注入 |
| `ev-000026` | decompile.ghidra | FUN_140009700 注入后轮询 payload_log.txt 提取 32 字节 key |
| `ev-000027` | decompile.ghidra | FUN_1400f26a0 主收集流程（浏览器/钱包/截图等） |
| `ev-000028` | decompile.ghidra | FUN_14000c670 WinHTTP POST 上传实现 |
| `ev-000030` | decompile.ghidra | FUN_14000d1b0 /clipper 状态上报 |
| `ev-000037` | decompile.ghidra | FUN_140007160 哈希常量解析 API |
| `ref:3cadef3374` | pe.exports | payload_v3.dll 导出 elevator_init/decrypt_key 等 |
| `ref:f9c2607a4b` | dyn.run | 仿真观测到 API 哈希解析、HKLM 反虚拟机查询与 Grabber 横幅 |
| `ref:f19ab4471d` | 动态分析平台 | 真实动态：释放 Temp DLL、启动无头 msedge、DNS 查询 goldspins.club/ip-api[.]com、POST /gate 上传 ZIP |
| `c2_evidence:230f506b` | 连接证据提取 | 动态网络监控记录到 1 次到 goldspins[.]club:443 的连接尝试；未捕获完整会话 |
| `telemetry:230f506b` | 动态遥测 | 动态遥测记录到：监控组件 注册表事件 1 条；监控组件 进程/文件事件 116 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 26 条 |
| `etw:230f506b:5800` | 进程事件监控 | 短命进程事件：230f506bb813f4950bba612d0804ce34a1fee8bf24e8d068ac9a34979f0a835b.exe（pid 5800；MD5=043AEA82EA3D8CF809FFF5A7801814AD,SHA256=230F506BB813F4950BBA612D0804CE34A1FEE8BF24E8D068AC9A34979F0A835B,IMPHASH=3F8E2AB76B7440ED45BE9591BF586EBE） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
