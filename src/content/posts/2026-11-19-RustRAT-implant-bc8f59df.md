---
title: "恶意样本分析：RustRAT-implant（PE · exe · bc8f59df）"
published: 2026-11-19
draft: false
description: "恶意（置信度中）：RustRAT-implant · rat/backdoor/stealer · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["RustRAT", "rat", "backdoor", "stealer", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **RustRAT-implant**（存疑） · 置信度 **中**
> 
> 别名：Rust implant RAT、WindowsHelper RAT
> 
> 该样本是用 Rust 编写的远程控制木马（源码路径 implant\src\*.rs）。静态可见完整的远控命令分发（shell、keylog、dump cookies、screenshot、download/upload、persist、elevate、sleep、exit）与对应实现依赖（GetAsyncKeyState、BitBlt/GetDIBits、CryptUnprotectData、rusqlite 读取浏览器 Login Data/Cookies、WSASocket/connect）。动态沙箱中样本运行后把自身复制到用户启动目录 Startup\WindowsHelper.exe（文件创建事件），并以 5 秒周期反复 TCP 回连 144.172.111[.]127:20222，每次发送 4 字节长度前缀加 AES 加密载荷，属于典型的加密信道 RAT 回连。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **RustRAT-implant** · 别名 Rust implant RAT、WindowsHelper RAT · _存疑_ |
| 置信度 | **中** |
| 行为类 | rat · backdoor · stealer |
| 难度 | medium |
| 首次出现 | 2026-11-17 00:42:01 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/bc8f59df0718ef65a5f5a828161572d17b447ebbb5760cd3a977da0a196ca77f/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">自复制到启动目录</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.001</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">加密回连C2</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1573.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">内置远控命令集</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">窃取浏览器凭据</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">键盘记录</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `bc8f59df0718ef65a5f5a828161572d17b447ebbb5760cd3a977da0a196ca77f` |
| MD5 | _未记录_ |
| 大小 | 1,740,288 字节（1.7 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **11** 条行为，每条都挂了证据；其中 **9** 条静态可得、**2** 条经动态分析取得。

### 1. 自复制到启动目录

`T1547.001` · 置信度 **高** · 动态

进程启动后约 3 秒把自身副本写入当前用户的 Startup 目录，文件名为 WindowsHelper.exe（主机遥测文件创建事件，来源 PID 1516），获得登录自启能力。

> **证据**：动态事件：File created TargetFilename=C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsHelper.exe, ProcessId=1516, RuleName=T1023
> 
> **来源**：`ref:9a21e3cfa3` · `ref:43676d5143`

### 2. 加密回连C2

`T1573.001` · 置信度 **高** · 动态

以裸 TCP 连接 144.172.111[.]127:20222，连接被拒/无响应后每约 5 秒重试；每帧以 4 字节大端长度 0x69 开头，后接 AES 加密载荷。

> **证据**：网络监控：bc8f59...exe (1516) requested TCP 144.172.111[.]127:20222 共 5 次；RawTCP 会话每次长度前缀 00 00 00 69
> 
> **来源**：`ref:b55628f4a0` · `ref:9bc1f14731`

### 3. 内置远控命令集

`T1105` · 置信度 **高** · 静态

二进制内含完整服务端指令集合：Shell、Keylog(Start/Stop/Dump)、Screenshot、Download、Upload、Sleep、Mouse、SysInfo、Procs、ListDir、Urls、Persist、Elevate、Exit，并有对应 ServerMessage 变体与命令串 sysinfo/procs/ls/urls/programs/exts/pw/cookies/shot/persist/keylog/ctl。

> **证据**：字符串簇 0x152170 与 0x151568：'sysinfoprocslsurlsprogramsextspwcookies'、'struct variant ServerMessage::Download/Upload/Sleep'
> 
> **来源**：`ref:d2198238b5`

### 4. 窃取浏览器凭据

`T1555.003` · 置信度 **高** · 静态

用 rusqlite 打开 Chrome/Edge 的 Login Data 与 Cookies 数据库，执行 SELECT origin_url, username_value, password_value FROM logins 与 SELECT host_key, name, encrypted_value FROM cookies，并用 CryptUnprotectData 解密经 DPAPI 保护的密码/Cookie 值。

> **证据**：字符串 0x153455 'SELECT host_key, name, encrypted_value FROM cookies'；0x1524xx 'GoogleUser DataLogin DataSELECT origin_url, username_value, password_value FROM logins'；导入 crypt32!CryptUnprotectData
> 
> **来源**：`ref:d2198238b5` · `ref:cbb590aa19`

### 5. 键盘记录

`T1056.001` · 置信度 **高** · 静态

轮询 GetAsyncKeyState 并结合 VK 映射表记录按键，支持 keylog start/stop/dump 指令把记录回传；键位表包含 ')!@#$%^&*(' 等 shift 符号。

> **证据**：导入 user32!GetAsyncKeyState；字符串 0x15217e 'keylogger iniciado ... keylog ctl keylogger parado keylog(vazio)'；0x1536e7 ')!@#$%^&*(' 与 implant\src\keylogger.rs
> 
> **来源**：`ref:cbb590aa19` · `ref:d2198238b5`

### 6. 屏幕截取

`T1113` · 置信度 **高** · 静态

通过 GetDC/BitBlt/CreateCompatibleBitmap/GetDIBits 抓取桌面位图，并用 png crate 编码后按 Screenshot/ScreenshotStream 消息回传。

> **证据**：导入 gdi32!BitBlt/GetDIBits、user32!GetDC；字符串 0x152fba 'falha ao capturar tela implant\src\screenshot.rs'、'ScreenshotStream'
> 
> **来源**：`ref:cbb590aa19` · `ref:d2198238b5`

### 7. 远程命令执行

`T1059.003` · 置信度 **高** · 静态

使用 cmd.exe /e:ON /v:OFF /d /c 执行服务端下发的命令（Shell 消息），并把 stdout/stderr 回传；实现 CreateProcessW + 命名管道/异步 IO 读取输出。

> **证据**：字符串 'cmd.exe /e:ON /v:OFF /d /c' 与 '\\cmd.exe\\'；导入 CreateProcessW、NtCreateNamedPipeFile、NtReadFile/NtWriteFile；'struct variant ServerMessage::Shell'
> 
> **来源**：`ref:d2198238b5` · `ref:cbb590aa19`

### 8. 伪装微软组件

`T1036.005` · 置信度 **高** · 静态

资源版本信息伪装为 Microsoft Corporation 的 'Assistente do Windows'，OriginalFilename 为 WindowsHelper.exe，落盘名同样使用 WindowsHelper.exe，以降低用户与人工排查的怀疑。

> **证据**：版本资源 0x1a4736：CompanyName=Microsoft Corporation、FileDescription=Assistente do Windows、OriginalFilename=WindowsHelper.exe；动态进程属性一致
> 
> **来源**：`ref:d2198238b5` · `ref:9a21e3cfa3`

### 9. 模仿UAC提权流程

`T1548.002` · 置信度 **中** · 静态

内置 Elevate 指令与葡语提示 'prompt UAC enviado a vitima, aguarde aceitar'，可向受害者弹出 UAC 提示申请管理员权限，成功后继续以高权限运行。

> **证据**：字符串 0x153c11 'persistencia instalada (Run key)'、0x153c1f 'falha ao pedir elevacao'、0x153c31 'elevate'、'prompt UAC enviado a vitima, aguarde aceitar'
> 
> **来源**：`ref:d2198238b5`

### 10. 加密内嵌数据

`T1027` · 置信度 **中** · 静态

文件末尾存在 2048 字节全字节分布的高熵 overlay，且 .text 中反复用 VirtualProtect 把 .fptable 段在只读/可写之间切换以解密查表，说明存在运行期解密的自定义数据结构，配置不以明文出现。

> **证据**：overlay 0x1a8600-0x1a8e00（2048 字节，256 种字节值）；rva 0x145210: VirtualProtect(0x1a9000, 0x100, PAGE_READONLY)
> 
> **来源**：`ref:f038d6102d` · `ref:9bc1f14731`

### 11. 收集主机与进程信息

`T1082` · 置信度 **高** · 静态

响应 SysInfo/Procs 指令，采集主机名、用户名、管理员标志、OS 版本、CPU 核数/架构、内存、磁盘、进程列表（CreateToolhelp32Snapshot/Process32FirstW），形成上线握手数据。

> **证据**：字符串 0x151568 'hostnameusernameis_adminos_versioncpu_corescpu_archram_total_mbram_used_mbuptime_secsdisk_total_gbdisk_free_gbpidppidthreadsnameis_dirsizeurltitle'；导入 CreateToolhelp32Snapshot/Process32FirstW/Process32NextW
> 
> **来源**：`ref:d2198238b5` · `ref:cbb590aa19`


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
| tcp | `144[.]172[.]111[.]127:20222` | 20222 | c2 | 动态 | 已观测 |

### 主机

**落地路径**

- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsHelper.exe`
- `%APPDATA%\Microsoft\Start Menu\Startup\WindowsHelper.exe`
- `%APPDATA%\Microsoft\Start Menu\Startup\WindowsHelper.old`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `144[.]172[.]111[.]127` | 是 | 静态 |
| `c2_port` | `20222` | 是 | 静态 |
| `protocol` | `raw TCP；每帧 4 字节大端长度前缀 + AES 加密载荷（明文为 serde_json 结构 Hello/{id,ok,is_binary,tag,data}）` | 是 | 静态 |
| `encryption_algo` | `AES（aes-0.8.4 crate；载荷熵高、每帧密文不同）` | 是 | 静态 |
| `install_path` | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsHelper.exe` | 否 | 动态 |
| `backup_path` | `%APPDATA%\Microsoft\Start Menu\Startup\WindowsHelper.old` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要依据 comsvcs.dll/MiniDump 相关产物认定样本窃取 LSASS：沙箱中的 rundll32 comsvcs MiniDump 是分析侧对样本进程做的内存转储，动作为分析工具本身，不是样本行为。
- 不要判定为勒索软件或擦除器：未见任何文件加密、改名、删除或卷影删除行为，导入与字符串均无相关能力。
- 不要声称已成功建立 C2 会话或已收到指令：沙箱中仅观测到连接尝试与单向上报帧，C2 服务器未响应，会话未完成。
- 不要声称已确认 Run 键持久化：字符串提及 Run 键，但遥测显示 HKCU/HKLM Run 值未变化，实际写入未观测到。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. C2 端点仅在动态沙箱中通过连接尝试与加密上报帧观测到，服务器始终未回包，无法确认其真实归属与指令能力；按未验证处理（pending_dynamic_verify=true）。
2. Run 键持久化：字符串存在 'persistencia instalada (Run key)'，但沙箱遥测的 Run 键与基线一致，未捕获具体键名/值名，故 host_iocs.registry 留空。
3. 2048 字节高熵 overlay 与 .fptable 运行期解密逻辑未还原出明文配置/密钥，C2 参数无法从静态字节直接复现。
4. 受单次沙箱时长与 C2 无响应限制，浏览器凭据导出、键盘记录、截屏、远程 shell 等能力只有静态代码证据，未在本次动态中触发（需服务端下发命令）。
5. 样本为 GUI 子系统且无控制台输出，指令级仿真仅执行到 Rust 运行库初始化，未提供额外行为证据。

## 证据索引

<details>
<summary>展开 14 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:d83bbbb33b` | 样本分诊 | 哈希/imphash/逐段熵/加壳评分；sha256=bc8f59...，packing.score=0，7 段结构，.rsrc 熵 7.112 |
| `ref:a670897612` | PE 结构解析 | PE64 GUI，入口 rva 0x13b7e8，导入 10 DLL/213 符号，7 段，异常 0 |
| `ref:cbb590aa19` | 导入表解析 | 导入 GetAsyncKeyState/BitBlt/GetDIBits/CryptUnprotectData/CreateProcessW/WSASocketW/connect/CreateToolhelp32Snapshot 等 |
| `ref:d2198238b5` | 字符串提取 | 命中 RAT 命令串、浏览器 SQL、implant 源路径与伪装版本资源 |
| `ref:f12460618d` | 指令级仿真 | 指令级仿真仅执行 Rust 运行库初始化（36 次 API），无网络行为 |
| `ref:9bc1f14731` | 动态沙箱 | 真实沙箱引爆：样本 PID 1516 运行，产出时间线、内存转储与网络监控日志，收口后回滚 |
| `ref:b55628f4a0` | 动态沙箱/网络监控 | 5 次 TCP 144.172.111[.]127:20222 连接尝试，RawTCP 记录长度前缀 00 00 00 69 的加密帧 |
| `ref:9a21e3cfa3` | 动态沙箱/主机遥测 | 主机遥测文件创建与进程事件：样本创建 Startup\WindowsHelper.exe；Run 键与基线一致 |
| `ref:f038d6102d` | script | 文件末尾 0x1a8600-0x1a8e00 为 2048 字节高熵 overlay，256 种字节值 |
| `ref:65d8b4537d` | disasm.function | rva 0xc900 起为 serde 反序列化与网络处理函数，含 getaddrinfo 调用 |
| `ref:19170f44be` | script | 解析 UTF-16 字符串与版本资源（Assistente do Windows / WindowsHelper.exe） |
| `c2_evidence:bc8f59df` | 连接证据提取 | 动态网络监控记录到 5 次到 144.172.111[.]127:20222 的连接尝试；未捕获完整会话 |
| `telemetry:bc8f59df` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 113 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 27 条 |
| `etw:bc8f59df:1516` | 进程事件监控 | 短命进程事件：bc8f59df0718ef65a5f5a828161572d17b447ebbb5760cd3a977da0a196ca77f.exe（pid 1516；MD5=0639DFA49F3D977D587D7AF370F7F0AD,SHA256=BC8F59DF0718EF65A5F5A828161572D17B447EBBB5760CD3A977DA0A196CA77F,IMPHASH=9F55D5D034347970B96EDD3AE7DF91A4） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
