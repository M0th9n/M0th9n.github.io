---
title: "恶意样本分析：Agent Tesla（other · vbe · fdbdf977）"
published: 2026-11-15
draft: false
description: "恶意（置信度高）：Agent Tesla · stealer/injector/loader · 难度 medium · 纯静态分析"
tags: ["Agent Tesla", "stealer", "injector", "loader"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Agent Tesla** · 置信度 **高**
> 
> 别名：AgentTesla、OriginLogger
> 
> 样本是伪 .vbe 扩展名的明文 VBScript 投放器：先释放并启动内嵌的 PowerShell 脚本，脚本用 AES-256-CBC 解密第二层 PowerShell，再以 Base64+重复密钥 XOR 还原 .NET 注入器与最终 PE；注入器把最终 PE 镂空注入 aspnet_compiler.exe。最终载荷具备浏览器/邮件/FTP 凭据窃取、键盘记录、剪贴板采集、截屏和 SMTP/Telegram 外传能力，属于典型 Agent Tesla 家族窃密木马。上述链条均由静态解密、字符串和 PE/CLI 元数据直接证实，未见任何正常业务功能。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Agent Tesla** · 别名 AgentTesla、OriginLogger |
| 置信度 | **高** |
| 行为类 | stealer · injector · loader |
| 难度 | medium |
| 首次出现 | 2026-11-13 13:39:05 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/fdbdf9779f45ab3732628f78bd7c4c4f3862285edae7dd3e0d2908e48f192336/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">释放执行PowerShell</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">双层解密内嵌载荷</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">反射加载.NET注入器</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">镂空注入合法宿主</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">键盘记录窃取输入</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `fdbdf9779f45ab3732628f78bd7c4c4f3862285edae7dd3e0d2908e48f192336` |
| MD5 | _未记录_ |
| 大小 | 706,317 字节（689.8 KB） |
| 类型 | other · `vbe` |

## 行为分析

共 **11** 条行为，每条都挂了证据，且全部静态可得。

### 1. 释放执行PowerShell

`T1059.001` · 置信度 **高** · 静态

VBScript 将内嵌 Base64 解码为 .ps1 写入 C:\Temp\，随后用 powershell.exe -nop -ep bypass -file 执行，执行后删除脚本。

> **证据**：vbe off 0x139 g_payloadB64；PhaseWriteScript 写入 C:\Temp\<随机>.ps1；PhaseExecute 调用 g_shell.Run，参数 -nop -ep bypass
> 
> **来源**：`ref:7c4137b89c` · `ev-000004`

### 2. 双层解密内嵌载荷

`T1140` · 置信度 **高** · 静态

第一层 PowerShell 用硬编码 AES-256-CBC 密钥/IV 解密大块 Base64；第二层用重复密钥 XOR 还原 Base64，再解码为 .NET 程序集。

> **证据**：stage1.ps1 $encryptedPayload；AES key f8fb6c0d...；stage2.ps1 ConvertFrom-MaskedBlob，XOR key ZZaDazKA6@@^^
> 
> **来源**：`ev-000004`

### 3. 反射加载.NET注入器

`T1620` · 置信度 **高** · 静态

第二层脚本通过 [Reflection.Assembly]::Load 在内存中加载 64000 字节程序集，并反射调用类型 DEVV.WHORE 的静态方法 LAUNCHER。

> **证据**：stage2.ps1 Invoke-InMemoryAssembly: [Reflection.Assembly]::Load；type DEVV.WHORE，method LAUNCHER；stage3 PE/CLI 头确认为 .NET DLL
> 
> **来源**：`ev-000004` · `ev-000001` · `ref:0a2e59969d`

### 4. 镂空注入合法宿主

`T1055.012` · 置信度 **高** · 静态

注入器以 aspnet_compiler.exe 为目标创建挂起进程，取消映射其映像、分配内存、写入 PE 头与节区、改写线程上下文并恢复执行，完成进程镂空。

> **证据**：stage3 UTF-16 off 0xc2d8 CreateProcessA、0xc246 VirtualAllocEx、0xc264 WriteProcessMemory、0xc2ae ZwUnmapViewOfSection、0xc1aa SetThreadContext、0xc190 ResumeThread、0xc0de 'Failed to update PEB'；stage2 传入 hostExe 与内嵌 PE
> 
> **来源**：`ev-000001` · `ref:0a2e59969d` · `ev-000004`

### 5. 键盘记录窃取输入

`T1056.001` · 置信度 **高** · 静态

载荷安装全局键盘钩子并记录前台窗口与按键，形成键盘日志。

> **证据**：stage4 off 0xe688 SetWindowsHookExA；0x10451 StartKeylogger；#Strings KeyLogger/KeyboardProc/GetForegroundWindow
> 
> **来源**：`ev-000002` · `ev-000006`

### 6. 窃取浏览器保存凭据

`T1555.003` · 置信度 **高** · 静态

遍历 Chrome/Edge/Brave/Firefox 等数十种浏览器配置，读取 Login Data/logins.json，并用 DPAPI 或 NSS 解密保存的用户名与密码。

> **证据**：stage4 UTF-16 off 0x12d5e 'Login Data' 等路径；0xeaa8 CryptUnprotectData；#Strings NSS_Init/PK11SDR_Decrypt/password_value
> 
> **来源**：`ev-000002` · `ev-000006`

### 7. 读取邮件与FTP凭据

`T1555` · 置信度 **高** · 静态

读取 Outlook 配置与注册表、Foxmail 安装路径、Thunderbird/SeaMonkey 配置以及 FileZilla recentservers.xml，提取账号与密码。

> **证据**：stage4 off 0x12ace Foxmail.url.mailto；Outlook Profiles 注册表键；FileZilla recentservers.xml；POP3/IMAP/SMTP/HTTP Password 字段
> 
> **来源**：`ev-000002` · `ev-000006`

### 8. 截屏与剪贴板采集

`T1113, T1115` · 置信度 **高** · 静态

按定时器截取屏幕并读取剪贴板内容，作为独立日志类别回传。

> **证据**：stage4 off 0x10de0 TakeScreenshot；0xea69 GetClipboardData；#Strings ClipboardVault/ScreenshotVault/OpenClipboard
> 
> **来源**：`ev-000002` · `ev-000006`

### 9. 邮件与Telegram外传

`T1048` · 置信度 **高** · 静态

将窃取的凭据、键盘日志、截屏与主机信息打包，经 SMTP(587) 邮件或 Telegram Bot sendDocument 接口外传。

> **证据**：stage4 UTF-16 off 0x11a89 mail[.]merchantinvestnetwork[.]com；0x11a27/0x11ac7 两个账号；0x11ee7 api[.]telegram[.]org/bot 与 0x11f21 /sendDocument?chat_id=；#SMTPEnabled/#TGEnabled 开关
> 
> **来源**：`ev-000006` · `ev-000002`

### 10. 禁用安全与系统工具

`T1562.001` · 置信度 **中** · 静态

载荷包含禁用 Windows Defender、任务管理器、注册表编辑器与命令行的代码路径，用于降低受害者排查能力。

> **证据**：stage4 off 0xe6e1 DisableWD；0x1047a Taskmgr_Disabler；0x1048b Registeries_Disabler；#Strings CMD_Disabler/EmptyBlocker
> 
> **来源**：`ev-000002` · `ev-000006`

### 11. 探测IP与地理位置

`T1016` · 置信度 **高** · 静态

通过外部 IP 回显与地理定位服务获取受害者公网 IP、国家与时间信息，并附在回传邮件中。

> **证据**：stage4 US 'hxxp://checkip[.]dyndns[.]org/' 与 'hxxps://reallyfreegeoip[.]org/xml/'；INFO_SystemIP/INFO_Country/INFO_Date_Time 字段
> 
> **来源**：`ev-000002` · `ev-000006`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| smtp | `mail[.]merchantinvestnetwork[.]com` | 587 | exfil | 静态 | ⏳ 未观测 |
| telegram | `hxxps://api[.]telegram[.]org/bot<TOKEN>/sendDocument?chat_id=<ID>` | 443 | exfil | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\Temp\<8位随机大写字母>.ps1`
- `C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe`
- `%APPDATA%\UserData.txt`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `mail[.]merchantinvestnetwork[.]com; api[.]telegram[.]org` | 是 | 静态 |
| `c2_port` | `587 (SMTP); 443 (Telegram)` | 是 | 静态 |
| `c2_uri` | `hxxps://api[.]telegram[.]org/bot<TOKEN>/sendDocument?chat_id=<ID>` | 否 | 静态 |
| `smtp_accounts` | `rocky@merchantinvestnetwork[.]com; rocee@merchantinvestnetwork[.]com` | 是 | 静态 |
| `smtp_password` | `69)}!t9lT9om:b!&` | 是 | 静态 |
| `encryption_algo` | `AES-256-CBC (第一层); Base64+重复密钥 XOR (第二层); AES-GCM/TripleDES/DPAPI (载荷内部)` | 是 | 静态 |
| `aes_key` | `f8fb6c0d59cc8079de52d6a91ecc283bd63253b9ce8676c476056f8d3d00dafa` | 是 | 静态 |
| `aes_iv` | `42df37eb27d3b70287401a7048f9b10c` | 是 | 静态 |
| `xor_key` | `ZZaDazKA6@@^^` | 是 | 静态 |
| `injector_host` | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe` | 是 | 静态 |
| `log_path` | `%APPDATA%\UserData.txt` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要判定为勒索软件：样本虽使用 AES/TripleDES，但未见文件遍历加密、扩展名改写或勒索提示，其密码学仅用于配置/凭据保护与外传。
- 不要判定为下载器：各阶段载荷均内嵌并逐层解密，未观察到运行时从 HTTP/FTP 下载下一阶段的逻辑。
- 不要断言已建立持久化：静态未见 Run 键、服务或计划任务写入，不能仅凭窃密木马常见行为推断其已驻留。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 是（stage2 `fe0c88cdf01e3ba06f1bae487812f96b7b314671972b2cf87507d08a4266c955`） |

**局限与待验证**

1. 本环境仅做静态分析，未在隔离的 Windows 环境中引爆，因此 SMTP 与 Telegram 外传通道、进程镂空结果均未动态验证，C2 统一标记为 static 且 pending_dynamic_verify=true。
2. Telegram Bot token、chat_id 与 FTP 主机/口令未在明文中恢复，可能由构建时加密配置或运行时生成；目前只能确认 Telegram Bot API 调用模板与 #FTPEnabled 开关。
3. 未观察到持久化代码，不能排除由外部邮件附件、压缩包或宏文档负责再次投递/驻留。
4. stage3 注入器经过名称混淆，注入实现依据其 UTF-16 API 名称、失败提示与调用参数判定，未做动态内存取证。
5. 浏览器/邮件客户端凭据读取依赖受害主机实际安装的软件与用户配置，静态阶段无法确认实际窃取到的数据量。

## 证据索引

<details>
<summary>展开 8 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000004` | 脚本化取证 | 从 .vbe 提取 Base64、解码第一层 PS1、用内嵌 AES-256-CBC 密钥/IV 解密第二层 PS1、XOR/Base64 还原 stage3/stage4，并记录各级 SHA-256 与注入宿主。 |
| `ev-000006` | evidence.record(manual) | 从 stage4 字符串偏移提取 SMTP 服务器/账号/口令、Telegram API 模板、IP 探测地址及窃密/反分析能力字符串。 |
| `ev-000001` | 字符串提取 | stage3 注入器字符串：CreateProcessA/ZwUnmapViewOfSection/VirtualAllocEx/WriteProcessMemory/SetThreadContext/ResumeThread，以及 'Failed to update PEB' 等镂空注入失败提示。 |
| `ev-000002` | 字符串提取 | stage4 载荷字符串：浏览器 Login Data 路径、Outlook/Foxmail/FileZilla 凭据、SetWindowsHookExA、剪贴板/截屏、SMTP/Telegram 外传与反分析类名。 |
| `ev-000005` | 密码学常量识别 | stage3 中识别到 MD5 T-table 常量（off 0xf200），说明注入器内部使用 MD5。 |
| `ref:0a2e59969d` | PE 结构解析 | stage3 为 32 位 .NET DLL（仅 mscoree 导入，无异常节表），与反射加载器描述一致。 |
| `ref:7a0ebd471f` | PE 结构解析 | stage4 为 32 位 .NET GUI PE（仅 mscoree 导入，3 节），是最终窃密载荷。 |
| `ref:7c4137b89c` | 字符串提取 | 原始 .vbe 字符串证据：WORK_DIR=C:\Temp\、PS_LAUNCH=powershell.exe -nop -ep bypass -file、g_payloadB64 起始 Base64。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
