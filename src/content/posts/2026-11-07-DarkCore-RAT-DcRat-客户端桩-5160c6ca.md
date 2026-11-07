---
title: "恶意样本分析：DarkCore RAT (DcRat 客户端桩)（PE · exe · 5160c6ca）"
published: 2026-11-07
draft: false
description: "恶意（置信度中）：DarkCore RAT (DcRat 客户端桩) · rat/backdoor/injector · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["DarkCore", "rat", "backdoor", "injector", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **DarkCore RAT (DcRat 客户端桩)**（存疑） · 置信度 **中**
> 
> 别名：DcRat、DarkCore、DCRat candidate
> 
> 64 位原生客户端桩，导出 DcInjEntry/DcCloakProcess/DcHjAct/DcHjSet，内置 AES-256-GCM 配置解密、远程配置拉取、自定义二进制协议上线、进程注入与反虚拟机/反调试；在隔离 Windows 沙箱中真实运行并持续向 2.27.4[.]184:49812 发起 TCP 连接，内存中可见解密后的主机/端口与 getaddrinfo 成功日志，构成可直接复核的恶意远控上线行为。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **DarkCore RAT (DcRat 客户端桩)** · 别名 DcRat、DarkCore、DCRat candidate · _存疑_ |
| 置信度 | **中** |
| 行为类 | rat · backdoor · injector |
| 难度 | hard |
| 首次出现 | 2026-11-06 06:59:16 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/5160c6ca466626650a1bd5cb2918d756ed101a721bb31c4d7611c62e9427597f/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置配置</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">拉取远程配置</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">直连C2端口上线</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">发送HELLO注册包</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">注入宿主进程</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `5160c6ca466626650a1bd5cb2918d756ed101a721bb31c4d7611c62e9427597f` |
| MD5 | _未记录_ |
| 大小 | 608,256 字节（594.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **12** 条行为，每条都挂了证据；其中 **11** 条静态可得、**1** 条经动态分析取得。

### 1. 解密内置配置

`T1027` · 置信度 **高** · 静态

启动后使用 CNG 的 AES-256-GCM（密钥 32 字节、nonce 12 字节、tag 16 字节）解密 .data2 中的配置块，失败则走降级路径；模块加载器另有 PVM\x02 容器解密与滚动 XOR 解码。

> **证据**：FUN_14004bc98（BCryptOpenAlgorithmProvider("AES") + ChainingModeGCM + BCryptDecrypt）；FUN_14004dfa4 校验 PVM\x02 头并调用解密；FUN_14002870c 为 SHA-256 KDF
> 
> **来源**：`ref:75dc2a0d6d` · `ref:9caf81bdef` · `ref:cdd12e527e`

### 2. 拉取远程配置

`T1105` · 置信度 **高** · 静态

从配置中的 URL 用 WinHTTP 发起 GET（UA 固定 Mozilla/5.0），支持把 pastebin[.]com/raw/<id> 重写为下载地址；取回文本的第一条非注释行按 host:port 解析，写入全局 C2 主机与端口字段，60 秒内不重复拉取。

> **证据**：FUN_14000be0c：字符串 "hxxps://"/"hxxp://"/"pastebin[.]com"/"/raw/"，调用 WinHttpQueryDataAvailable/WinHttpReadData，结果写入 DAT_14008f3c0 与 DAT_14009900a
> 
> **来源**：`ref:25910a007a` · `ref:9ba17d3133`

### 3. 直连C2端口上线

`T1571` · 置信度 **高** · 动态

独立运行时解析配置主机并以裸 TCP 反复连接 2.27.4[.]184:49812，间隔约 10–20 秒重试，持续数分钟不退出。

> **证据**：沙箱时间线 pid 8040；网络监控记录 02:46:27–02:49:51 共 13 次 TCP 2.27.4[.]184:49812 连接尝试；进程内存堆区可见 "49812"、"2.27.4[.]184"、"getaddrinfo ret=0"
> 
> **来源**：`ref:0c27c1d45e` · `ref:19055b45e0` · `ref:f4928adee5`

### 4. 发送HELLO注册包

`T1095` · 置信度 **高** · 静态

连接建立后使用自定义二进制协议 OpMap_v2 发送 HELLO 上线包，客户端标识形如 INJ-<pid>-<tid>，日志显示 "HS OK sending HELLO"、"HELLO SENT OK - ONLINE"。

> **证据**：FUN_140010fe0 握手流程；字符串 0x76230 "native KDF ok"、0x76240 "HS OK sending HELLO"、0x76260 "INJ-%08lX-%08lX"、0x76288 "HELLO SENT OK - ONLINE"
> 
> **来源**：`ref:4ff94afb05` · `ref:9ba17d3133`

### 5. 注入宿主进程

`T1055` · 置信度 **高** · 静态

导出 DcInjEntry 作为注入入口：读取自身模块基址与 SizeOfImage 做标记，清理 %TEMP%\wctk.dat / wcti.dat，创建并等待 WctSync_<pid> 事件，初始化内部状态后进入主循环；配套 DcHjAct/DcHjSet 控制劫持开关。

> **证据**：0x14002e478 DcInjEntry（VirtualQuery 校验 MZ/PE、DeleteFileA wctk.dat/wcti.dat、OpenEventA WctSync_%lu）；0x14004aa68 DcHjAct / 0x14004aa78 DcHjSet
> 
> **来源**：`ref:3cb407c9ef` · `ref:ee0ea0bf4c` · `ref:f301bf0db6`

### 6. 伪装svchost进程

`T1036.005` · 置信度 **高** · 静态

导出 DcCloakProcess 在未指定目标名时默认把自身伪装为 C:\Windows\System32\svchost.exe，并调用 CFG 合法调用目标设置与进程信息改造例程隐匿注入痕迹。

> **证据**：0x14002e448 DcCloakProcess 默认参数 L"C:\\Windows\\System32\\svchost.exe"；随后调用 FUN_14004422c / FUN_140046974 / FUN_140045620；字符串 SetProcessValidCallTargets
> 
> **来源**：`ref:7cb584cdc2` · `ref:9ba17d3133`

### 7. 检测虚拟机环境

`T1497.001` · 置信度 **高** · 静态

遍历进程与系统信息，命中 vboxservice.exe、vgauthservice.exe、vmusrvc.exe、qemu-ga.exe、vboxtray.exe、vmtoolsd.exe、vmwaretray.exe、vmwareuser.exe 等名称，或检测 WDAGUtilityAccount、DESKTOP- 前缀、USBSTOR 记录时直接退出，日志标记 ANTI_VM HIT / ANTI_SANDBOX HIT。

> **证据**：字符串表 0x771e8 起的 VM 进程名列表；0x76500 "ANTI_VM HIT exit"、0x76530 "ANTI_SANDBOX HIT exit"、0x76560 FLAGS ad/vm/sb/etw/amsi/uh/dump/masq；创建进程快照与 QueryFullProcessImageNameW 导入
> 
> **来源**：`ref:bc4c5209fd` · `ref:9ba17d3133`

### 8. 反调试自检

`T1622` · 置信度 **高** · 静态

通过 SEH、IsDebuggerPresent、调试标志位与异常分发路径进行反调试自检，命中后记录 ANTI_DEBUG HIT 并退出；同时在注入模式下可跳过部分环境退出逻辑。

> **证据**：字符串 0x764b0 "ANTI_DEBUG SEH 0x%08lX"、0x764d0 "ANTI_DEBUG HIT exit"、0x764e8 "ANTI_DEBUG CHECK ok"；导入 IsDebuggerPresent/SetUnhandledExceptionFilter/RtlCaptureContext
> 
> **来源**：`ref:9ba17d3133` · `ref:bc4c5209fd`

### 9. 加载远程插件

`T1105` · 置信度 **高** · 静态

接收服务端下发的 PVM\x02 模块块，按 id 分发并在内存中加载，模块可带注入标志；日志含 modpush id/blob/inj 与 ModDisp、RegEx exports 等模块调度信息。

> **证据**：FUN_14004dfa4 解析 PVM\x02（magic+长度+AES-GCM 密文）；字符串 0x75e10 "modpush id=0x%02X blob=%u inj=%d"、0x77bd0 "RegEx exports init/initex/disp/shut"、0x77c20 "ModDisp enter 0x%02X"
> 
> **来源**：`ref:9caf81bdef` · `ref:9ba17d3133`

### 10. 内置PowerShell远控

`T1059.001` · 置信度 **高** · 静态

内置完整 PowerShell 交互会话实现：启动 powershell.exe/pwsh.exe，用 ::__DCPS_META__::/::__DCPS_END__:: 分帧回传 stdout/stderr，支持 #B64# 脚本、:cmd/:psreset/:pskill 等控制命令，形成无文件远程命令执行通道。

> **证据**：字符串 0x74b90–0x75bc8 的 PowerShell runspace/管道脚本与 DCPS 协议标记；0x75770 ::dcscript:: / 0x75780 ::dcps::；CreateProcessA + CreatePipe + PeekNamedPipe
> 
> **来源**：`ref:9ba17d3133` · `ref:bc4c5209fd`

### 11. 清理临时载荷

`T1070.004` · 置信度 **高** · 静态

注入入口首先删除 %TEMP%\wctk.dat 与 %TEMP%\wcti.dat，并在运行过程中使用 wcts.log/wctt.log 记录自身事件，减少可取证落地物。

> **证据**：0x14002e478：GetTempPathA 后 wsprintfA("%swctk.dat"/"%swcti.dat") 紧跟 DeleteFileA；日志文件名 wcts.log / wctt.log
> 
> **来源**：`ref:3cb407c9ef` · `ref:9ba17d3133`

### 12. 读取注册表hive

`T1012` · 置信度 **中** · 静态

拼接 %s\Windows\System32\config\SOFTWARE 路径读取离线注册表配置单元，并具备 RegEnumValue/RegDeleteValue/RegSetValueEx 等注册表读写能力，用于主机/系统信息收集与配置篡改。

> **证据**：字符串 0x76640 "%s\\Windows\\System32\\config\\SOFTWARE"；导入 RegEnumValueW/RegQueryValueExW/RegSetValueExW/RegDeleteTreeW；内存中可见 Software\Microsoft\Windows\CurrentVersion 路径
> 
> **来源**：`ref:9ba17d3133` · `ref:bc4c5209fd` · `ref:cdcbe41f93`


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
| tcp | `2.27.4[.]184` | 49812 | c2 | 动态 | 已观测 |
| https | `2.27.4[.]184` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://pastebin[.]com/raw/<id>` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `Local\DCSI%s`
- `Local\DCSS%s`
- `Local\WDINJ%s`
- `Local\WD%08X`
- `Local\W%02X%02X%02X%02X%02X%02X%02X%02X`
- `Local\DCWDFLAG`
- `WctSync_<pid>（事件对象名）`

**落地路径**

- `%TEMP%\wctk.dat`
- `%TEMP%\wcti.dat`
- `%TEMP%\wcts.log`
- `%TEMP%\wctt.log`
- `%TEMP%\dc%08lx%04x.dll`
- `%TEMP%\%08X%08X.exe`
- `%USERPROFILE%\Desktop\dc_hrdp_debug.log`
- `C:\Users\Public\Desktop\<dropped_name>`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run（运行时内存可见该路径，具体值名未恢复）`
- `SYSTEM\CurrentControlSet\Services\WinSxAutoInstallService`

**服务**

- `WinSxAutoInstallService`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `2.27.4[.]184` | 是 | 动态 |
| `c2_port` | `49812` | 是 | 动态 |
| `c2_transport` | `裸 TCP（内置 WinHTTP 封装，亦支持 http/https 与 443 默认端口）` | 是 | 静态 |
| `config_loader` | `支持从 pastebin[.]com/raw/<id> 或任意 http(s) URL 拉取首行 host:port 覆盖配置` | 否 | 静态 |
| `user_agent` | `Mozilla/5.0` | 否 | 静态 |
| `encryption_algo` | `AES-256-GCM（32 字节密钥、12 字节 nonce、16 字节 tag）+ SHA-256 KDF；模块解密后还有一层滚动 XOR` | 是 | 静态 |
| `campaign_id` | `DARKCORE01` | 否 | 静态 |
| `protocol` | `自定义二进制协议 OpMap_v2，HELLO 上线包携带 INJ-<pid>-<tid> 标识` | 是 | 静态 |
| `plugins` | `ph-media-key-v1 / ph-media-n-c-v1；RD_SetCaptureMode、HVNC_SetTorMode、HVNC_SetWssMode 等导出插件能力` | 否 | 静态 |
| `install_path` | `%TEMP%（wctk.dat / wcti.dat / dc<hex>.dll）` | 否 | 静态 |
| `mutex_family` | `Local\DC* / Local\W* / Local\WDINJ*` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要仅凭 CryptUnprotectData、bcrypt/AES 等通用导入就判定为浏览器密码窃取器或勒索软件——这些是配置/模块加密与 DPAPI 通用能力。
- 不要把 2.27.4[.]184:49812 说成唯一或永久 C2；配置可运行时从远程 URL 更新，且内置 https/443 与 pastebin 下载路径。
- 不要声称已观测到完整远控指令执行：本次仅见上线连接尝试与内存中的配置，未收到服务端任务。
- 不要把该文件当作可独立运行的后门 EXE；它是导出注入入口的客户端桩，通常由加载器/宿主进程投放。
- 不要根据导入 WinHTTP 就断言全部通信走 HTTP：实测为裸 TCP。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 无服务端监听，未观测到 HELLO 之后的指令下发、插件下载与持久化写操作；C2 主机/端口仅由网络行为与进程内存字符串确认。
2. 配置文件为 AES-256-GCM 密文，静态未还原完整明文字段（如配置下发 URL 的 ID、持久化注册表值名、互斥量完整拼串）；以运行时内存与网络证据为准。
3. 持久化线索来自字符串与内存中的 CurrentVersion 路径，未观察到实际注册表写入；服务名 WinSxAutoInstallService 同样未观测到创建服务动作。
4. 进程内存镜像包含大量系统模块字符串，个别注册表路径可能来自系统 DLL，因此相关条目置信度标为中等。
5. 家族命名依据样本自标识字符串（DARKCORE01/[DarkCore]/Dc* 导出/DCPS），公开命名称谓可能不同，保持 uncertain。
6. 本次动态观测窗口内样本未派生子进程、未产生可捕获的落地文件；模块化能力仅由代码与字符串证实。

## 证据索引

<details>
<summary>展开 17 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=5160c6ca466626650a1bd5cb2918d756ed101a721bb31c4d7611c62e9427597f，大小 608256 |
| `ev-000002` | scan.imphash | imphash=513cd6674933d27c38b7beb90a5ff371 |
| `ref:33e97eefee` | PE 结构解析 | PE32+ AMD64 GUI，9 个节，导出 4 个，节名含 .pvmut/.fptable，无结构异常 |
| `ref:bc4c5209fd` | 导入表解析 | 289 个导入：WS2_32/WinHTTP/bcrypt/CryptUnprotectData/注册表/进程与线程枚举/ReadProcessMemory/CreateProcess |
| `ref:196a87c547` | pe.exports | client_stub.exe 导出 DcCloakProcess(0x2e448)、DcHjAct(0x4aa68)、DcHjSet(0x4aa78)、DcInjEntry(0x2e478) |
| `ref:9ba17d3133` | 字符串提取 | 抽取 1896 条 ASCII/207 条 UTF-16 字符串：DarkCore、DCPS、PVM 模块、反虚拟机列表、wctk.dat、pastebin 等 |
| `ref:25910a007a` | decompile | FUN_14000be0c 实现 http(s)/pastebin 配置拉取与 host:port 解析（WinHTTP） |
| `ref:4ff94afb05` | decompile | FUN_140010fe0 实现 C2 连接、SHA-256 KDF、HELLO 握手与机器指纹 |
| `ref:75dc2a0d6d` | decompile | FUN_14004bc98 为 AES-256-GCM 解密例程（ChainingModeGCM） |
| `ref:9caf81bdef` | decompile | FUN_14004dfa4 解析 PVM\x02 模块容器并解密分发 |
| `ref:3cb407c9ef` | decompile | DcInjEntry 注入入口：VirtualQuery 自校验、删除 wctk.dat/wcti.dat、WctSync 事件同步 |
| `ref:7cb584cdc2` | decompile | DcCloakProcess 默认伪装为 C:\Windows\System32\svchost.exe |
| `ref:0c27c1d45e` | 动态分析平台 | 隔离环境真实引爆：pid 8040 运行 4 分钟，进程时间线与 6 个内存转储采集成功，环境已回滚 |
| `ref:19055b45e0` | network.observe | 样本进程 13 次 TCP 连接 2.27.4[.]184:49812（02:46–02:49），无子进程/落地文件 |
| `ref:f4928adee5` | memory.forensics | 进程内存堆区可见 49812、2.27.4[.]184、getaddrinfo ret=0，确认运行时配置已解密 |
| `ref:5ba7ccb1b0` | memory.forensics | 内存镜像确认 DARKCORE01、%swctk.dat、native KDF、HELLO、OpMap_v2、client_stub 导出名等同源代码资产 |
| `c2_evidence:5160c6ca` | 连接证据提取 | 动态网络监控记录到 14 次到 2.27.4[.]184:49812, config[.]edge[.]skype[.]com:80, maps[.]windows[.]com:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
