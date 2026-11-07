---
title: "恶意样本分析：HVNC_SOCKS5 (SanaHeiSayonara)（PE · exe · 6d68d0a9）"
published: 2026-11-01
draft: false
description: "恶意（置信度中）：HVNC_SOCKS5 (SanaHeiSayonara) · stealer/rat/backdoor · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["stealer", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **HVNC_SOCKS5 (SanaHeiSayonara)**（存疑） · 置信度 **中**
> 
> 别名：SanaHeiSayonara HVNC、Krutyak HVNC loader
> 
> 64 位 C++ 远控/窃密程序：静态确认 UAC 绕过自提升、Defender 排除、Steam 资料页死信箱取址、Chromium 凭据解密、钱包收集与键盘钩子；动态沙箱内真实启动（同名进程二次启动）并观测到对 steamcommunity[.]com/id/l5jgtd78uhn43987f89w 的请求及对 mitmatmet[.]com:1010 的持续加密 TCP 回连。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **HVNC_SOCKS5 (SanaHeiSayonara)** · 别名 SanaHeiSayonara HVNC、Krutyak HVNC loader · _存疑_ |
| 置信度 | **中** |
| 行为类 | stealer · rat · backdoor |
| 难度 | medium |
| 首次出现 | 2026-11-01 11:49:02 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/6d68d0a96c8bc726cbe3bf6f6253fb0ccae50627e966b8606f3582ef65eacec7/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">绕 UAC 自提权重启</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1548.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">添加杀软排除项</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Steam 死信箱取址</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">加密回连 C2</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1573</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">解密浏览器凭据</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `6d68d0a96c8bc726cbe3bf6f6253fb0ccae50627e966b8606f3582ef65eacec7` |
| MD5 | _未记录_ |
| 大小 | 1,747,456 字节（1.7 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **6** 条静态可得、**3** 条经动态分析取得。

### 1. 绕 UAC 自提权重启

`T1548.002` · 置信度 **高**

检测当前令牌是否已提升；未提升时以 ComputerDefaults.exe 为宿主，通过 ICMLuaUtil CLSID 201ef99a-7fa0-444c-9399-19ba84f12a1a 与 ncalrpc 调试/复制令牌方式绕过 UAC，并用原命令行重启自身。

> **证据**：FUN_1400019f0 @0x1400019f0 调 ComputerDefaults.exe、DbgUiSetThreadDebugObject、NtDuplicateObject；FUN_140003af0 检查 TokenElevation；FUN_140002560 用 GetCommandLineW 重启
> 
> **来源**：`ev-000016` · `ev-000022` · `ev-000031` · `ref:89b6288ca3`

### 2. 添加杀软排除项

`T1562.001` · 置信度 **高** · 静态

启动 powershell.exe，通过管道写入 Get-ScheduledJob 与 Add-MpPreference -ExclusionPath/-ExclusionProcess，将自身与所在目录加入 Defender 排除。

> **证据**：FUN_140001510 @0x140001510 CreateProcessW + CreatePipe + WriteFile；字符串 0x14018d410 起为 Add-MpPreference 脚本
> 
> **来源**：`ev-000015` · `ev-000033`

### 3. Steam 死信箱取址

`T1102` · 置信度 **高** · 动态

向 steamcommunity[.]com/id/l5jgtd78uhn43987f89w 发起 HTTPS 请求，用正则提取 og:title 作为主机名；失败时回退到内置域名 mitmatmet[.]com。

> **证据**：FUN_140013770 @0x140013770 调 FUN_140013f50("steamcommunity[.]com", 路径, 443) 并匹配 <meta property="og:title">；FUN_140001190 传入 id/l5jgtd78uhn43987f89w 与 mitmatmet[.]com
> 
> **来源**：`ev-000020` · `ev-000021` · `ev-000018` · `ev-000033` · `ev-000034`

### 4. 加密回连 C2

`T1573` · 置信度 **高** · 动态

以固定周期解析并连接 mitmatmet[.]com:1010，收发不可读二进制块（观测到 20/48 字节、16 字节分组特征），构成加密信标/任务通道。

> **证据**：动态网络监控：03:27:36 起解析 mitmatmet[.]com，样本同名进程对 192.0.2[.]123:1010 建立 79 次连接；静态 FUN_140013900 @0x140013900 每 240s 重取地址；字符串含 "expand 32-byte k" 与 BCrypt GCM
> 
> **来源**：`ev-000023` · `ev-000021` · `ev-000018` · `ev-000034` · `ref:89b6288ca3`

### 5. 解密浏览器凭据

`T1555.003` · 置信度 **高** · 静态

定位 Chrome/Edge/Brave/Opera 的 Local State，提取 encrypted_key 与 app_bound_encrypted_key，先 DPAPI 解密再以 Google Chromekey1/BCrypt AES-GCM 解出 v20 密钥，用于解密 cookies、logins、credit_cards 查询结果。

> **证据**：FUN_140003ea0 @0x140003ea0：CryptUnprotectData、BCryptOpenAlgorithmProvider/BCryptDecrypt、字符串 "Google Chromekey1"、"app_bound_encrypted_key"、SQLite SELECT ... FROM logins/cookies/credit_cards
> 
> **来源**：`ev-000017` · `ev-000033`

### 6. 收集钱包数据

`T1005` · 置信度 **高** · 静态

遍历 Exodus、Atomic、Guarda、Armory、Komodo、Wasabi、Electrum、Coinomi 等钱包目录/文件并打包外传。

> **证据**：字符串 0x19bd20 起：%APPDATA%\Exodus\exodus.wallet、%APPDATA%\atomic\Local Storage\leveldb、%APPDATA%\Guarda、%APPDATA%\Armory、%APPDATA%\WalletWasabi\Client\Wallets、%APPDATA%\Electrum\wallets、%LOCALAPPDATA%\Coinomi\Coinomi\wallets
> 
> **来源**：`ev-000033`

### 7. 键盘钩子记录

`T1056.001` · 置信度 **高** · 静态

安装 WH_KEYBOARD_LL 全局键盘钩子并把击键写入 keylog.txt，另一线程周期性读取该文件并发送至控制端。

> **证据**：FUN_140019650 @0x140019650 调 SetWindowsHookExW(0xd, FUN_140018920) 并进入消息循环；FUN_1400198f0/FUN_1400192e0 循环读取文件并调用 FUN_1400106d0；字符串 keylog.txt @0x14018fa28
> 
> **来源**：`ev-000024` · `ev-000030` · `ev-000033`

### 8. 创建隐藏桌面

`T1219` · 置信度 **高** · 静态

以自定义名创建或打开隐藏桌面（WinSta0\Default 及派生桌面名），配合桌面切换与 PrintWindow/StretchBlt 抓屏，实现 HVNC 远程操作。

> **证据**：FUN_140014360 @0x140014360：OpenDesktopW/CreateDesktopW、SetThreadDesktop；导入 PrintWindow、StretchBlt、OpenInputDesktop；字符串 WinSta0\Default @0x14018d530
> 
> **来源**：`ev-000028` · `ev-000033`

### 9. 解压载荷装驱动

`T1105` · 置信度 **高** · 静态

通过 powershell Expand-Archive 将 C:\ProgramData\Krutyak.zip 解到 C:\ProgramData，并调用 deviceinstaller 安装 usbmmIdd.inf（usbmmidd 虚拟显示驱动）后执行 enableidd 1。

> **证据**：字符串 @0x14018d2b0：$archpath = "C:\ProgramData\Krutyak.zip"; ... Expand-Archive；@0x14019cdb0：%ws\%ws install %ws\usbmmIdd.inf usbmmidd；@0x14019ce18：enableidd 1
> 
> **来源**：`ev-000033`


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
| http | `hxxps://steamcommunity[.]com/id/l5jgtd78uhn43987f89w` | 443 | c2 | 动态 | 已观测 |
| tcp | `mitmatmet[.]com` | 1010 | c2 | 动态 | — |

### 主机

**互斥体**

- `SanaHeiSayonarac`
- `SanaHeiSayonarad`
- `SanaHeiSayonarae`
- `SanaHeiSayonaraf`
- `SanaHeiSayonarag`
- `%s_SanaHeiSayonarah`
- `%s_SanaHeiSayonarai`

**落地路径**

- `%LOCALAPPDATA%\SanaHeiSayonaraa`
- `%LOCALAPPDATA%\SanaHeiSayonaraG`
- `C:\ProgramData\Krutyak.zip`
- `C:\ProgramData\usbmmidd_v2`
- `keylog.txt`

**服务**

- `usbmmidd`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `mitmatmet[.]com:1010 (fallback); steamcommunity[.]com/id/l5jgtd78uhn43987f89w (dead-drop)` | 是 | 动态 |
| `dead_drop_url` | `hxxps://steamcommunity[.]com/id/l5jgtd78uhn43987f89w` | 是 | 动态 |
| `campaign_id` | `l5jgtd78uhn43987f89w` | 是 | 静态 |
| `mutex` | `SanaHeiSayonara{c..g} / %s_SanaHeiSayonara{h,i}` | 是 | 静态 |
| `install_archive` | `C:\ProgramData\Krutyak.zip` | 否 | 静态 |
| `driver_package` | `C:\ProgramData\usbmmidd_v2 (usbmmIdd.inf, deviceinstaller64.exe, enableidd 1)` | 否 | 静态 |
| `encryption_algo` | `ChaCha20 ("expand 32-byte k") 与 AES-GCM (BCrypt) 用于通信/配置；另有 BCrypt 哈希` | 否 | 静态 |
| `keylog_file` | `keylog.txt` | 否 | 静态 |
| `browser_targets` | `Chrome / Edge / Brave / Opera / Firefox：cookies、logins、credit_cards、扩展与 Local State` | 否 | 静态 |
| `wallet_targets` | `Exodus、Atomic、Guarda、Armory、Komodo、Wasabi、Electrum、Coinomi` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要将其判定为勒索软件：样本未实现文件加密或勒索文本，AES-GCM/ChaCha20 仅用于通信、配置与浏览器密钥解密。
- 不要称其使用了内核提权漏洞：UAC 绕过只是把自身提升到管理员，未利用内核漏洞。
- 不要把对 steamcommunity[.]com 的请求当作正常浏览行为：该 URL 是硬编码的死信箱解析路径，用于获取备用 C2 主机。
- 不要断言 SOCKS5 代理或 HVNC 会话已在本环境实际启用：仅由导出名、导入与代码路径证明具备能力，动态仅观测到信标。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 沙箱为无真实外网环境，mitmatmet[.]com:1010 的响应与后续任务未获取；1010 仅见加密字节，无法还原明文协议。
2. Steam 资料页响应被本地网络拦截，未能取得真实 og:title，因此死信箱是否替换了备用域名无法确认。
3. 未观察到 C:\ProgramData\Krutyak.zip 下载/解压与 usbmmidd 驱动安装，相关行为来自代码与字符串，属于能力而非已发生事实。
4. SOCKS5 代理、HVNC 远程会话、钱包实际打包外传未在本次动态窗口内触发，均为静态推导。
5. 家族名 HVNC_SOCKS5/SanaHeiSayonara 来自构建名与互斥体前缀，缺少第三方引擎或公开报告交叉验证，归属存疑。

## 证据索引

<details>
<summary>展开 21 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | hash_scan | sha256=6d68...acec7, md5=1ccc4246..., imphash=ee100517e971d046ed1372570e0e5361 |
| `ev-000002` | import_hash | imphash ee100517e971d046ed1372570e0e5361 |
| `ev-000014` | string_scan | ASCII 7847 条 / UTF-16LE 827 条（flag 命中为字符集噪声，非凭据） |
| `ev-000015` | static_decompile | FUN_140001510 通过 powershell 写入 Defender 排除脚本 |
| `ev-000016` | static_decompile | FUN_1400019f0 利用 ComputerDefaults/ICMLuaUtil 与调试令牌绕过 UAC |
| `ev-000017` | static_decompile | FUN_140003ea0 解密 Chromium encrypted_key 与 app_bound_encrypted_key（BCrypt GCM） |
| `ev-000018` | static_decompile | FUN_140013f50 WinHTTP 请求/下载封装 |
| `ev-000019` | static_decompile | FUN_1400014c0 创建 SanaHeiSayonarad 互斥体，已存在则退出 |
| `ev-000020` | static_decompile | FUN_140013770 请求 Steam 资料页并解析 og:title 作为主机名 |
| `ev-000021` | static_decompile | FUN_140001190 主流程：互斥体、Defender 排除、Steam 取址、mitmatmet[.]com 回退、线程创建 |
| `ev-000022` | static_decompile | FUN_140002560 未提权时以原命令行调用 UAC 绕过 |
| `ev-000023` | static_decompile | FUN_140013900 每 240 秒刷新 C2 地址 |
| `ev-000024` | static_decompile | FUN_140019650 安装 WH_KEYBOARD_LL 并进入消息循环 |
| `ev-000028` | static_decompile | FUN_140014360 OpenDesktopW/CreateDesktopW 创建隐藏桌面 |
| `ev-000030` | static_decompile | FUN_1400192e0 读取 keylog 文件并发送 |
| `ev-000031` | static_decompile | FUN_140003af0 读取 TokenElevation |
| `ev-000032` | static_decompile | FUN_140019cc0 创建 SanaHeiSayonarac 互斥体 |
| `ev-000033` | string_extraction | 自写脚本按偏移提取互斥体、C2、死信箱路径、Krutyak/usbmmidd、钱包与 keylog 字符串 |
| `ev-000034` | dynamic_log_analysis | 自写脚本解析沙箱网络监控：Steam GET、mitmatmet[.]com DNS 与 1010 端口 79 次加密 TCP、同名二次进程 |
| `ref:89b6288ca3` | dynamic_sandbox | 真实沙箱引爆：进程 7736 启动并产生内存转储，随后同名进程 1756 出现并联网；无 hollowing 命中 |
| `c2_evidence:6d68d0a9` | 连接证据提取 | 动态网络监控记录到 3 次到 maps[.]windows[.]com:443, steamcommunity[.]com:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
