---
title: "恶意样本分析：Santa Grabber（PE · exe · edc59856）"
published: 2026-11-14
draft: false
description: "恶意（置信度高）：Santa Grabber · stealer/downloader · 难度 hard · 静态反编译（动态执行未取得运行时行为）"
tags: ["Santa Grabber", "stealer", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Santa Grabber** · 置信度 **高**
> 
> 别名：Santa、Santagrabber、Santa Stealer
> 
> 该文件是 pkg 打包的 Node.js 应用程序，伪装成 GoXLR Utility（package.json name=goxlr-utility, version=1.2.5），覆盖层内解出的 index.js 经解混淆后包含完整的窃密逻辑：读取 Discord 令牌、Chromium/Firefox 浏览器 Cookie/登录数据/自动填充、Exodus 与浏览器钱包扩展、键盘记录与屏幕截图，并通过 Discord webhook、cafebabe[.]cc 双通道 webhook、catbox[.]moe/GoFile 上传外传；同时写入 HKCU Run、Startup 目录与计划任务实现持久化，并具备反虚拟机与投放 cheatsan[.]club 可执行文件的行为。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Santa Grabber** · 别名 Santa、Santagrabber、Santa Stealer |
| 置信度 | **高** |
| 行为类 | stealer · downloader |
| 难度 | hard |
| 首次出现 | 2026-11-11 02:17:23 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/edc59856abfb63319dc82ad03960595f62945ba34149fb2a4829252dae743e3d/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解包还原混淆载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">冒充 GoXLR 工具</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">双通道回传数据</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1041</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">压缩包云端外传</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1567.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">窃取 Discord 令牌</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `edc59856abfb63319dc82ad03960595f62945ba34149fb2a4829252dae743e3d` |
| MD5 | _未记录_ |
| 大小 | 58,588,291 字节（55.9 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **12** 条行为，每条都挂了证据，且全部静态可得。

### 1. 解包还原混淆载荷

`T1027` · 置信度 **高** · 静态

PE 覆盖层是 pkg 虚拟文件系统；逐条 gunzip 后得到 538805 字节的 obfuscator[.]io 混淆 index.js，静态复现其自定义 base64 字符串表（5808 项）与数组轮转即可还原明文字符串与常量。

> **证据**：覆盖层文件偏移 0x23D5800；index.js 解压后 538805 字节；字符串表 5808 项，轮转值 143
> 
> **来源**：`ev-000108`

### 2. 冒充 GoXLR 工具

`T1036.005` · 置信度 **高** · 静态

package.json 自称 goxlr-utility 1.2.5（官方 GoXLR 控制工具），内嵌运行时导出名为 node.exe，构建路径却位于 santa-WEEK 项目下，属于典型名称伪装。

> **证据**：package.json: name=goxlr-utility, version=1.2.5；构建路径 C:\snapshot\chas\Bot\temp_builds\santa-WEEK-9F6AE8BFA27C
> 
> **来源**：`ev-000108` · `ref:ee5c040477`

### 3. 双通道回传数据

`T1041` · 置信度 **高** · 静态

同时向 canary[.]discord[.]com 的 Discord webhook 与 cafebabe[.]cc 的兼容 webhook 发送消息/压缩包，代码中以 postToBoth、sendZipToWebhook 实现；后者作为备用/面板通道。

> **证据**：const webhook="hxxps://canary[.]discord[.]com/api/webhooks/1568032154561019976/..."; dualhook="hxxps://cafebabe[.]cc/api/webhooks/179231388932405535/..."; postToBoth/sendZipToWebhook
> 
> **来源**：`ev-000108`

### 4. 压缩包云端外传

`T1567.002` · 置信度 **高** · 静态

将收集结果打包为 ZIP 后优先尝试 GoFile，失败再调用 catbox[.]moe 的 user/api.php 上传，返回的 URL 再写入回传消息。

> **证据**：uploadToGoFile(...) / uploadToCatbox(...); 请求 hxxps://catbox[.]moe/user/api.php；日志 "uploadToCatbox: starting"
> 
> **来源**：`ev-000108`

### 5. 窃取 Discord 令牌

`T1539` · 置信度 **高** · 静态

遍历 %APPDATA%\discord、discordcanary、discordptb、discorddevelopment 的 Local Storage leveldb，用 BROWSER_TOKEN_REGEX 提取令牌，对 dQw4w9WgXcQ 前缀的加密值调用 DPAPI 解密，并进一步调用 Discord API 获取账号资料、账单/关系等信息。

> **证据**：discordPaths 四个路径；BROWSER_TOKEN_REGEX=/mfa\.[\w-]{84}|[\w-]{24}\.[\w-]{6}\.[\w-]{27}/g；DISCORD_ENC_PREFIX="dQw4w9WgXcQ:"；Dpapi.unprotectData；discord[.]com/api/v9/users/@me
> 
> **来源**：`ev-000109`

### 6. 读取浏览器凭据

`T1555.003` · 置信度 **高** · 静态

针对 Chrome、Edge、Brave、Vivaldi、Opera/Opera GX、Yandex、Chromium、Epic、Amigo 读取 Cookies、Login Data、Web Data，并用 sql.js 查询；Firefox/Waterfox 读取 cookies.sqlite 与 logins.json，通过 nss3.dll 调用 PK11SDR_Decrypt 解密。

> **证据**：getTargets: Local\Google\Chrome、Local\BraveSoftware\Brave-Browser、Roaming\Opera Software\Opera GX 等；cookies.sqlite/logins.json；nss3.dll + PK11SDR_Decrypt；sql.js Database.exec
> 
> **来源**：`ev-000109`

### 7. 打包钱包与扩展

`T1555` · 置信度 **高** · 静态

收集 Exodus 的 exodus.wallet（chacha20poly1305 解密）及 Metamask、Phantom、Coinbase、Rabby、Keplr、Ronin、Trust、Math、Zerion 等浏览器扩展数据，打包到 %TEMP%\<用户名>_WalletBackup 后外传。

> **证据**：collectAllWallets/getExodusWallet("exodus.wallet")；copyWalletExtensions 扩展 ID 表；tempDir=path.join(os.tmpdir, username+"_WalletBackup")
> 
> **来源**：`ev-000109`

### 8. 键盘记录与截屏

`T1056.001` · 置信度 **高** · 静态

通过 ffi 加载 GetAsyncKeyState 采集按键；用 wmic logicaldisk 枚举卷名并生成 screenshots/monitor_N.png 屏幕截图，均纳入外传内容。

> **证据**：ffi.Library(..., {GetAsyncKeyState: ["int16", ["int"]]})；captureScreens；wmic logicaldisk get volumename；screenshots/monitor_
> 
> **来源**：`ev-000109`

### 9. 写入开机自启

`T1547.001` · 置信度 **高** · 静态

installStartup 将自身复制到当前用户 Startup 目录，并执行 reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsSecurityHealthService"，同时尝试 schtasks /create /sc onlogon 创建登录计划任务。

> **证据**：installStartup；reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsSecurityHealthService；schtasks /create /tn ... /sc onlogon；Start Menu\Programs\Startup
> 
> **来源**：`ev-000108`

### 10. 投放作弊程序

`T1105` · 置信度 **高** · 静态

shouldDropCheat/dropAndRunCheatExe 从 cheatsan[.]club 下载 xyzallahuakbar1337.exe 到本地并启动，同时以 __CHEAT_LAUNCHED_KEY 环境变量避免重复执行，兼具下载器与诱饵分发作用。

> **证据**：CHEAT_EXE_URL="hxxps://cheatsan[.]club/xyzallahuakbar1337.exe"；shouldDropCheat；dropAndRunCheatExe；__CHEAT_LAUNCHED_KEY
> 
> **来源**：`ev-000108`

### 11. 规避虚拟机分析

`T1497.001` · 置信度 **高** · 静态

advancedVMCheck 检查 虚拟化平台/VirtualBox/QEMU 的 MAC 前缀、vboxservice/vmtoolsd/qemu 进程与 VBoxMouse.sys 等驱动文件，命中即调用 process.exit 终止，避免在分析环境继续运行。

> **证据**：advancedVMCheck 位于解密器之后并紧跟 if(advancedVMCheck)process.exit；MAC 前缀 00:0C:29、00:50:56、08:00:27、00:16:3E；VBoxMouse.sys；vboxservice/vmtoolsd
> 
> **来源**：`ev-000109`

### 12. 收集主机与RDP情报

`T1082` · 置信度 **高** · 静态

getRdpInfo 用 quser 与 reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" 判断 RDP 会话、提取客户端 IP/会话名；GetIp 通过 myexternalip[.]com 与 ipapi[.]co 获取公网 IP、地理信息，用于受害者画像。

> **证据**：getRdpInfo: execSync("quser")、reg query HKCU\Software\Microsoft\Terminal Server Client\Default；GetIp: hxxps://www[.]myexternalip[.]com/raw、hxxps://ipapi[.]co/；RDP_SERVER_IP=85.11.167[.]82
> 
> **来源**：`ev-000109`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://canary[.]discord[.]com/api/webhooks/1568032154561019976/flfNZhu2wPZaNUWUspPKVQQEtcCw_qkMMOQT9loJv_K5Z8ewqiOWz4GjFP9bfdUVIYF1` | 443 | exfil | 静态 | ⏳ 未观测 |
| http | `hxxps://cafebabe[.]cc/api/webhooks/179231388932405535/3R0dD_a0xzlad-RpQcZZWbc9xiYURRqh7hUXItbDRM94j9PcMoyzaTIK1EnV3a0CLE4P` | 443 | panel | 静态 | ⏳ 未观测 |
| http | `hxxps://cheatsan[.]club/xyzallahuakbar1337[.]exe` | 443 | download | 静态 | ⏳ 未观测 |
| http | `hxxps://catbox[.]moe/user/api.php` | 443 | exfil | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%APPDATA%\discord\Local Storage\leveldb`
- `%APPDATA%\discordcanary\Local Storage\leveldb`
- `%APPDATA%\discordptb\Local Storage\leveldb`
- `%APPDATA%\discorddevelopment\Local Storage\leveldb`
- `%LOCALAPPDATA%\Google\Chrome\User Data`
- `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data`
- `%APPDATA%\Opera Software\Opera GX`
- `%APPDATA%\Mozilla\Firefox\Profiles`
- `%TEMP%\<用户名>_WalletBackup`
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<名称>.exe`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

**计划任务**

- `<名称> - schtasks /create /sc onlogon`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `canary[.]discord[.]com; cafebabe[.]cc` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `c2_uri` | `/api/webhooks/1568032154561019976/flfNZhu2wPZaNUWUspPKVQQEtcCw_qkMMOQT9loJv_K5Z8ewqiOWz4GjFP9bfdUVIYF1; /api/webhooks/179231388932405535/3R0dD_a0xzlad-RpQcZZWbc9xiYURRqh7hUXItbDRM94j9PcMoyzaTIK1EnV3a0CLE4P` | 是 | 静态 |
| `download_url` | `hxxps://cheatsan[.]club/xyzallahuakbar1337[.]exe` | 否 | 静态 |
| `upload_endpoints` | `hxxps://catbox[.]moe/user/api.php; GoFile 上传（代码中作为 catbox 失败后的回退）` | 否 | 静态 |
| `persistence_run_value` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSecurityHealthService` | 是 | 静态 |
| `campaign_id` | `santa-WEEK-9F6AE8BFA27C` | 否 | 静态 |
| `rdp_fallback_ip` | `85[.]11[.]167[.]82` | 否 | 静态 |
| `credential_decryption` | `Windows DPAPI + Firefox NSS PK11SDR + chacha20poly1305 (Exodus)` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不应因为代码使用 DPAPI、chacha20poly1305 或 AES 就判定为 ransomware/加密器：这些算法仅用于解密被窃取的浏览器/钱包数据，未观察到对用户文件加密或索要赎金的行为。
- 不应判定为 wiper 或破坏型样本：未发现批量删除/覆盖用户文件的逻辑，代码中的 unlink/rmSync 仅用于清理临时压缩包与临时目录。
- 不应把 85.11.167[.]82 当作已连接的 C2 服务器：它在 getRdpInfo 中仅作为 RDP 客户端 IP 取不到时的回退展示值，未发现对其发起网络连接。
- 不应认为它与官方 GoXLR Utility 同源：package.json 的 goxlr-utility 名称是伪装，实际载荷为独立构建的窃密程序。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 否 |

**局限与待验证**

1. 本次未在动态沙箱中真实投放样本，所有 C2、外传端点与持久化命令均来自静态解包/解混淆，recoverability 统一标为 static 且 pending_dynamic_verify=true。
2. 样本内置 虚拟化平台/VirtualBox/QEMU 检测（MAC 前缀、驱动文件、服务/进程），在常见虚拟化分析环境中可能直接 process.exit，真实动态观测需要能规避该检测的宿主或先打补丁。
3. GoFile 上传的具体 API 端点未在明文中形成完整 URL，代码中仅见 uploadToGoFile 字段与回退逻辑，未将其列为独立 IOC。
4. index.js 使用 obfuscator[.]io 字符串表与控制流混淆，已还原字符串与主要函数语义，但个别动态拼接的注册表值名/计划任务名需运行时才能确定。
5. 家族名来自样本自身页脚与构建路径（Santa | @Santagrabber、santa-WEEK），公开威胁情报中对该命名的对应关系未在本环境内核验。

## 证据索引

<details>
<summary>展开 10 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | md5=cf0aa9136423836bd92fc7c7164aa13c, sha1=9ff3874a5602a9519c6a5522f13288ee4eab4f11, sha256=edc59856abfb63319dc82ad03960595f62945ba34149fb2a4829252dae743e3d, size=58588291 |
| `ev-000002` | scan.imphash | imphash=5aa213c13ebbefe9c0a30df030df0286 |
| `ev-000003` | scan.rich | Rich header 18 条工具链记录，richhash=b5fb0d62897893e03122aedc628c638c |
| `ref:2c74089bf0` | PE 结构解析 | AMD64 PE, 7 sections, image base 0x140000000, entry RVA 0x125DDB8, subsystem WINDOWS_CUI, export_count=28122 |
| `ref:8828d25ce7` | 导入表解析 | 11 个 DLL / 384 个导入符号，含 WS2_32、ADVAPI32、CRYPT32、dbghelp、PSAPI 等 |
| `ref:ee5c040477` | pe.exports | 导出名 node.exe，28122 个导出，典型 V8/Node.js 运行时符号（v8::internal 等） |
| `ref:d7a8f2a199` | unpack.detect | packed=false, packer=null, 无非典型壳信号 |
| `ref:db6b0b6fa6` | 字符串提取 | 命中 pkg/prelude、PKG_DUMMY_ENTRYPOINT、node_modules、OpenSSL CRYPTOGAMS 等字符串，指向 pkg 打包的 Node.js 应用 |
| `ev-000108` | evidence.record (script) | 解包 pkg 覆盖层并提取 index.js（538805 字节），静态复现 obfuscator[.]io base64 字符串表与轮转，还原 webhook/dualhook/下载 URL/catbox/RDP IP/持久化命令 |
| `ev-000109` | evidence.record (script) | 清点窃密能力：Discord 令牌、浏览器 Cookie/登录/自动填充、钱包与扩展、键盘记录、截屏、RDP/主机信息、反虚拟机检测 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
