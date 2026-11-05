---
title: "恶意样本分析：Aokigahara（PE · exe · ad9a979e）"
published: 2026-11-05
draft: false
description: "恶意（置信度中）：Aokigahara · stealer/loader · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Aokigahara", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Aokigahara**（存疑） · 置信度 **中**
> 
> 在真实 Windows 动态沙箱中引爆后，样本进程（pid 1824）自身内存里出现一个未登记于模块列表的 64 位 PE 影像（基址 0x140000000，RWX 私有内存），该影像内部含 'AOKIGAHARA DEBUG LOG' 调试横幅与成套浏览器/钱包/通讯软件凭据采集路径；随后样本进程向 farenaw[.]cc:443 发起 X25519 握手请求并分片上传 sysinfo、screenshot、filegraber 三类数据，最后发送 COMPLETE 收尾。隔离网络仅记录到样本侧请求，未收到服务器响应，故 C2 会话标记为待动态验证。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Aokigahara** · _存疑_ |
| 置信度 | **中** |
| 行为类 | stealer · loader |
| 难度 | hard |
| 首次出现 | 2026-11-02 23:08:57 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ad9a979e68a411ca15f5d003c37ada725d02c34d6c1b7f34c4dbbbed39a8dd4f/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">内存映射二号载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">解密内置配置</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">检测虚拟机环境</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">导出浏览器密码</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">窃取会话Cookie</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ad9a979e68a411ca15f5d003c37ada725d02c34d6c1b7f34c4dbbbed39a8dd4f` |
| MD5 | _未记录_ |
| 大小 | 10,383,768 字节（9.9 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **12** 条行为，每条都挂了证据；其中 **6** 条静态可得、**6** 条经动态分析取得。

### 1. 内存映射二号载荷

`T1620` · 置信度 **高** · 动态

Go 加载器在自身进程内以 MEM_PRIVATE、RWX(0x40) 属性映射一个未登记的 64 位 PE 影像（基址 0x140000000，0x35000 字节，sha256 d64f88ab…），并在其中解密配置、启动窃密模块；内存取证同时记录该影像具备完整 PE 头、10 个节、非系统模块。

> **证据**：内存取证报告: module=140000000, is_listed_module=0, has_pe=1, protection=0x40, 10 sections；样本导入 VirtualAlloc/VirtualFree/CreateThread/GetProcAddress
> 
> **来源**：`ref:36b2726a32` · `ref:e2147ac215` · `ev-000020`

### 2. 解密内置配置

`T1027` · 置信度 **高** · 静态

第二阶段从 .stgcfg 节（4096 字节、熵 7.19）解密运行配置，成功打印 'CONFIG: decrypted'，失败则 'CONFIG: failed, using defaults' 回退默认值；配置中保存 C2 与采集开关。

> **证据**：stage2 节表 .stgcfg @VA 0x21000；字符串 0x22163 'CONFIG: decrypted'、0x22175 'CONFIG: failed, using defaults'
> 
> **来源**：`ev-000020`

### 3. 检测虚拟机环境

`T1497.001` · 置信度 **高** · 动态

启动时查询 vmware Tools、VirtualBox Guest Additions、VBoxGuest/vmci 服务与 WDAGUtilityAccount 等痕迹，命中即输出 'ANTI_VM: detected, exiting' 并退出；运行期还在 advapi32 的 GetUserNameA 附近留下 3 处代码补丁，疑似伪造用户名/规避分析。

> **证据**：stage2 字符串 SOFTWARE\vmware, Inc.\vmware Tools / SOFTWARE\Oracle\VirtualBox Guest Additions / SYSTEM\...\Services\VBoxGuest / WDAGUtilityAccount（0x2282a-0x228eb）；内存取证 advapi32 补丁记录 4a8f0/4a8f6/4a8fd
> 
> **来源**：`ev-000020` · `ev-000022` · `ref:36b2726a32`

### 4. 导出浏览器密码

`T1555.003` · 置信度 **高** · 静态

读取 Chromium 系（Chrome/Edge/Brave/Opera/Vivaldi/Yandex/360/QQ/Cent/Arc 等）与 Firefox 系（Firefox/Waterfox/Pale Moon/Floorp 等）的 Login Data、Web Data、logins.json、key4.db，调用 PK11SDR_Decrypt 解密后汇总为 Browser/Passwords.txt、CreditCards.txt、Autofill.txt、History.txt。

> **证据**：字符串 '%s\Login Data'、'Browser/Passwords.txt'、'Browser/CreditCards.txt'、'PK11SDR_Decrypt'（0x24054）、'%s\Web Data'
> 
> **来源**：`ev-000020`

### 5. 窃取会话Cookie

`T1539` · 置信度 **高** · 静态

复制各浏览器 Cookies 数据库与 Local State，针对新版 Chrome 的 App-Bound 加密处理 app_bound_encrypted_key/local_stored_cvc，并含 'STATUS:NO_ABE' 分支；输出 Browser/Cookies/*_Cookies.txt。

> **证据**：字符串 '%s\Network\Cookies'、'app_bound_encrypted_key'、'local_stored_cvc'、'STATUS:NO_ABE'、'Browser/Cookies/%s_Cookies.txt'
> 
> **来源**：`ev-000020` · `ref:fa2696b2ad`

### 6. 抓取钱包与FTP凭据

`T1555.003` · 置信度 **高** · 静态

遍历桌面/浏览器扩展钱包（Exodus、Electrum、Atomic、Coinomi、WalletWasabi、Monero、TokenPocket、MetaMask 等）与 FTP 客户端（FileZilla、WinSCP、CoreFTP、FlashFXP、SmartFTP）配置，输出到 Wallets/ 与 FTP/ 目录。

> **证据**：字符串 'Exodus\exodus.wallet'、'Wallets/Extensions/%s'、'FTP/WinSCP/Sessions.txt'、'Software\Martin Prikryl\WinSCP 2\Sessions'
> 
> **来源**：`ev-000020`

### 7. 收割通讯与游戏会话

`T1539` · 置信度 **高** · 静态

打包 Telegram（含 Kotatogram/64Gram/AyuGram/Unigram 等分支）tdata、Discord 令牌与 Web 会话 leveldb、Steam loginusers/config 刷新令牌，以及 Roblox .ROBLOSECURITY、Battle.net/Epic/Riot/Minecraft 等游戏凭据。

> **证据**：字符串 'Messengers/Telegram/tdata'、'dQw4w9WgXcQ'（Discord 令牌前缀）、'Games/Steam/Tokens.txt'、'Games/Roblox/cookies.txt'、'.ROBLOSECURITY'
> 
> **来源**：`ev-000020`

### 8. 读取AI工具令牌

`T1552.001` · 置信度 **高** · 静态

收集 Claude Code、Codex、Copilot、Gemini、Cursor、Windsurf、AWS、Kiro 等 AI/云工具的本地令牌与配置（AISessions/*），包括 .aws\credentials、state.vscdb、config.json、.env。

> **证据**：字符串 'AISessions/ClaudeCode/credentials.json'、'AISessions/AWS/credentials'、'cursorAuth/accessToken'、'AISessions/Windsurf/Tokens.txt'
> 
> **来源**：`ev-000020`

### 9. 截屏并采集剪贴板

`T1113` · 置信度 **高** · 动态

生成屏幕截图（Screenshot.jpg）与剪贴板文本（Clipboard.txt），并由 filegraber 模块抓取桌面/文档/下载目录文件；隔离网络请求日志中观测到 screenshot 与 filegraber 两个分片的 POST 请求体。

> **证据**：隔离网络 HTTP 请求日志: POST /gate/chunk 头 X-Chunk: screenshot（index 1, 20874 B）、X-Chunk: filegraber（index 2, 557 B）；字符串 'Screenshot.jpg'、'Clipboard.txt'
> 
> **来源**：`ev-000021` · `ev-000020` · `ref:36b2726a32`

### 10. X25519握手连C2

`T1573.002` · 置信度 **高** · 动态

样本进程向 farenaw[.]cc:443 发起 POST /gate/handshake，正文为 32 字节 X25519 公钥，携带 X-Build-ID/X-HWID/X-Gate-Token/X-Session 头，建立加密会话后再传输数据。

> **证据**：隔离网络 HTTP 请求日志: POST /gate/handshake Host: farenaw[.]cc, Content-Length: 32, X-KEX: x25519, X-Build-ID: 86b8b3da, X-HWID: E9F2B627
> 
> **来源**：`ref:36b2726a32` · `ev-000021`

### 11. 分片加密回传

`T1041` · 置信度 **高** · 动态

将采集结果按 X-Total=20 分片，使用 X-Chunk（sysinfo/screenshot/filegraber）与 X-Chunk-Index 依次 POST /gate/chunk，完成后 POST /gate/complete（正文 'COMPLETE'）结束会话。

> **证据**：隔离网络 HTTP 请求日志: 三次 POST /gate/chunk（X-Chunk: sysinfo/screenshot/filegraber，X-Chunk-Index 0/1/2，X-Total: 20）+ 一次 POST /gate/complete，body=COMPLETE，均发往 farenaw[.]cc:443
> 
> **来源**：`ref:36b2726a32` · `ev-000021`

### 12. 查询出口IP与归属

`T1614` · 置信度 **高** · 动态

以 User-Agent 'Mozilla/5.0' 请求 hxxp://ip-api[.]com/json/?fields=query,countryCode,city,isp，获取出口 IP、国家/城市与运营商，用于受害者画像或环境判定。

> **证据**：隔离网络 HTTP 请求日志: GET /json/?fields=query,countryCode,city,isp Host: ip-api[.]com，来源进程 pid 1824
> 
> **来源**：`ev-000021` · `ref:36b2726a32`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://farenaw[.]cc/gate/handshake` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://farenaw[.]cc/gate/chunk` | 443 | exfil | 静态 | ⏳ 未观测 |
| http | `hxxps://farenaw[.]cc/gate/complete` | 443 | exfil | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%TEMP%\akg_debug.txt`
- `%TEMP%\akg_%08lx.tmp`
- `%TEMP%\akg_%lx_%lx.tmp`
- `%TEMP%\akg_ff_%lx.tmp`
- `\\.\pipe\akg_%lx_%lx`

**注册表**

- `HKCU\Software\Valve\Steam（读取 Steam 安装路径与账号配置）`
- `HKCU\Software\Valve\Steam\Users（读取 Steam 账号/令牌）`
- `HKLM\SOFTWARE\vmware, Inc.\vmware Tools（虚拟机探测）`
- `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions（虚拟机探测）`
- `HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest（虚拟机探测）`
- `HKLM\SYSTEM\CurrentControlSet\Services\vmci（虚拟机探测）`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `farenaw[.]cc` | 是 | 静态 |
| `c2_base_path` | `/gate（POST /gate/handshake、/gate/chunk、/gate/complete）` | 是 | 静态 |
| `key_exchange` | `x25519（握手体为 32 字节公钥，头字段 X-KEX: x25519）` | 是 | 静态 |
| `upload_headers` | `X-Build-ID / X-Session / X-HWID / X-Gate-Token / X-Chunk / X-Chunk-Index / X-Total` | 是 | 静态 |
| `build_id` | `86b8b3da` | 否 | 动态 |
| `session_id` | `84402f62bfcec6a9f992f5d8b2fb87fe` | 否 | 动态 |
| `hwid` | `E9F2B627` | 否 | 动态 |
| `geoip_lookup` | `hxxp://ip-api[.]com/json/?fields=query,countryCode,city,isp` | 否 | 动态 |
| `config_blob` | `第二阶段 .stgcfg 节（4096 字节，熵 7.19）加密配置，运行时打印 'CONFIG: decrypted'，失败回退默认值` | 是 | 静态 |
| `chunk_total` | `20（X-Total 声明），实际观测到 sysinfo/screenshot/filegraber 三个分片` | 否 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能称其为勒索软件或文件加密器：虽内置 AES 实现并遍历大量文件路径，但未观察到文件加密、扩展名改写或勒索说明。
- 不能声称向其他进程注入或远程控制：二号载荷位于样本自身进程（pid 1824）的私有内存 0x140000000，未见 OpenProcess/CreateRemoteThread/跨进程写入证据。
- 不能声称具备持久化：未观察到 Run 键、服务、计划任务或启动目录写入。
- 不能把 ip-api[.]com 当作 C2 基础设施：它是公开的地理定位服务，仅用于出口 IP/地区探测。
- 不能给出外传内容明文：上传体经会话密钥加密，只能确认分片类型名与长度，不能还原具体凭据。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `d64f88ab888e1eb68465c44cb11197099c03b3eeacc97cfe78b87988a65721a3`） |

**局限与待验证**

1. 第二阶段 .stgcfg 配置为高熵加密块，未能静态解密；C2 主机与协议字段来自动态观测。
2. X-Total 声明 20 个分片，实际仅观测到 sysinfo/screenshot/filegraber 三个即结束，其余采集类别未被真实触发。
3. mutex 名称由运行时按机器信息拼接（仅见到 'MUTEX: already running' 逻辑），未取得具体名称。
4. Go 加载器的字符串字面量被加密混淆，静态无法还原其内部决策逻辑，加载器侧的判定主要依赖内存取证与导入面。
5. 内存转储的二号载荷在分析主机上被安全策略阻止写回磁盘，对其解析在内存中完成（节表/导入表/字符串）。
6. 尚未观察到键盘记录、横向移动或持久化，故未将其列入行为结论。

## 证据索引

<details>
<summary>展开 6 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 10383768 |
| `ev-000003` | scan.entropy | .text 熵 6.001（未加壳） |
| `ev-000017` | 密码学常量识别 | AES 正/逆 S-box 与 SHA-256 轮常量，偏移 0x992ba0/0x992ca0 |
| `ev-000020` | evidence.record | 内存中解析二号载荷：AOKIGAHARA 窃密器、.stgcfg 加密配置、采集路径与 C2 协议字符串 |
| `ev-000021` | evidence.record | 网络监控日志解析：farenaw[.]cc 的 handshake/chunk/complete 交互与 ip-api[.]com 查询 |
| `ev-000022` | evidence.record | Go 1.24.5 + garble 混淆、自签名证书、内嵌高熵载荷块、advapi32 运行时补丁 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
