---
title: "恶意样本分析：Agent Tesla（PE · exe · 30eed7cc）"
published: 2026-11-23
draft: false
description: "恶意（置信度中）：Agent Tesla · stealer/loader · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Agent Tesla", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Agent Tesla**（存疑） · 置信度 **中**
> 
> 别名：AgentTesla、OriginLogger、Negasteal
> 
> 样本是伪装成 Birch Desktop Utility / peridot.dll v3.7.2.6 的 .NET NativeAOT 程序。动态沙箱中它存活约 3 分钟，期间出现一个无参数启动的 csc.exe 进程；内存取证显示该进程的原 PE 头被替换、工作集内存在 MEM_MAPPED 的注入 .NET 程序集，且 amsi.dll、clr.dll、ntdll.dll 被内存补丁。注入程序集运行后解密出完整的凭据窃取串表（浏览器登录库、Windows Vault、邮件/FTP/VNC/VPN 客户端、键盘记录、截屏、Tor 与邮件/FTP/Web 面板外传模板），属于明确的窃密恶意软件。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Agent Tesla** · 别名 AgentTesla、OriginLogger、Negasteal · _存疑_ |
| 置信度 | **中** |
| 行为类 | stealer · loader |
| 难度 | hard |
| 首次出现 | 2026-11-23 07:32:35 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/30eed7cc22eca8d8e9bdbc77413b05a1a3b5f18426c153f084981fde111bd4cc/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装桌面工具品牌</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">注入编译器进程执行</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">内存修补 AMSI 绕过</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">解密内置窃密串表</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">窃取浏览器与系统凭据</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `30eed7cc22eca8d8e9bdbc77413b05a1a3b5f18426c153f084981fde111bd4cc` |
| MD5 | _未记录_ |
| 大小 | 1,780,286 字节（1.7 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **10** 条行为，每条都挂了证据；其中 **7** 条静态可得、**3** 条经动态分析取得。

### 1. 伪装桌面工具品牌

`T1036.005` · 置信度 **高** · 静态

PE 资源版本信息伪装为 CompanyName=Birch、ProductName=Birch Desktop Utility、InternalName/OriginalFilename=peridot.dll、FileVersion 3.7.2[.]6，清单名为 Birch.DesktopUtility；二进制为无数字签名的 NativeAOT .NET 单文件，用于降低用户与终端防护的怀疑。

> **证据**：文件偏移 0x139194 起 VS_VERSION_INFO（Birch Desktop Utility / peridot.dll）；0x13943c 清单 assemblyIdentity name="Birch.DesktopUtility"；字符串 "Fatal error. .NET runtime failed to initialize." 与 CoreCLR 运行时串表明为 NativeAOT .NET
> 
> **来源**：`ref:9c68760627` · `ref:8accf5bb75` · `ref:f80506a6e0`

### 2. 注入编译器进程执行

`T1055.012` · 置信度 **高** · 动态

分析窗口内 C:\Windows\Microsoft[.]NET\Framework\v4.0.30319\csc.exe（PID 2420）以无参数方式启动并持续存活；内存取证显示其主模块 PE 头被替换（DOS/文件/NT 头与入口点均被修改）、工作集中存在 MEM_MAPPED 的可移植执行体植入（基数 0x260000），符合进程空壳/程序集内存注入。

> **证据**：内存取证报告: main_image_path=csc.exe, is_managed=1, headers_scan is_pe_replaced=1/ep_modified=1/nt_hdr_modified=1; workingset_scan has_pe=1 @0x260000 size 0x1cc000; 系统遥测 17:27:51 创建 csc.exe（命令行仅镜像路径）, 17:30:57 该进程仍被扫描
> 
> **来源**：`ref:ab478739dd` · `ref:456b1985f9` · `ref:fa5fe72aea`

### 3. 内存修补 AMSI 绕过

`T1562.001` · 置信度 **高** · 动态

在被注入的 csc.exe 中发现 amsi.dll 1 处代码补丁、clr.dll 12 处补丁、ntdll.dll 2 处补丁，属于运行时禁用 AMSI 扫描并对 CLR/系统调用路径做篡改，以便加载并执行加密的 .NET 窃密模块。

> **证据**：内存取证 code_scan: amsi.dll patches=1, clr.dll patches=12, ntdll.dll patches=2; clr.dll 补丁偏移 0x100e4-0x10cd8（标签 patch_0..patch_11）
> 
> **来源**：`ref:ab478739dd`

### 4. 解密内置窃密串表

`T1027` · 置信度 **高** · 动态

注入进程内存中出现静态文件中不存在的完整明文串表：安装/持久化模板（%insname%、%insfolder%、%insregname%、%startupfolder%）、Tor 配置模板（%tordir%、%hash%、%torpass%）、外传模板（%ftphost%、%ftpuser%、%ftppassword%、%urlkey%、%PostURL%）以及浏览器/凭据客户端路径清单，说明载荷在内存中解密字符串后执行。

> **证据**：注入进程内存偏移 0x9b3d8a 起出现 "%startupfolder%\\%insfolder%\\%insname%"、"Software\\Microsoft\\Windows\\CurrentVersion\\Run"、"%tordir%\\Data\\Tor"；0x9b64b0 起出现 "hxxp://127.0.0[.]1:"、"POST"、"%PostURL%"；0x9b6712 起出现 Tor 下载地址
> 
> **来源**：`ref:77ef06292d` · `ref:eba426a687`

### 5. 窃取浏览器与系统凭据

`T1555.003` · 置信度 **高** · 静态

载荷内置对 Chromium 分支浏览器（Chrome/Edge/Opera/Yandex/Brave/Vivaldi/360/QQ/UC/CocCoc/Torch/7Star/Citrio 等）的 "Login Data"/"Local State" 与 Firefox logins.json、signons.sqlite、key3.db/key4.db、cookies.sqlite 的解析，并枚举 Windows Vault GUID（Windows Web Password Credential、Windows Credentials、Web Credentials 等）读取系统保存的口令，另含 RDP Credential Manager 提取逻辑。

> **证据**：注入进程内存 0x9b4c7e 起: "\\Default\\Login Data"、"logins"、"cookies.sqlite"、"key4.db"、"Windows Web Password Credential"、"Windows Credential Picker Protector"、"RDP"、"credentialpolicy"、"blob"；载荷 .NET 元数据含 vaultcli.dll/VaultEnumerateVaults/VaultGetItem 引用
> 
> **来源**：`ref:77ef06292d` · `ref:59d3b9b646`

### 6. 键盘记录与剪贴板截获

`T1056.001` · 置信度 **高** · 静态

载荷引用 SetWindowsHookEx、CallNextHookEx、GetKeyboardState、ToUnicodeEx、MapVirtualKey、GetKeyboardLayout、GetForegroundWindow/GetWindowText 并挂接剪贴板查看链（SetClipboardViewer/ChangeClipboardChain），生成带 HTML 颜色标记的键盘记录（KL_*.html）与剪贴板文本记录（"Copied Text:"）。

> **证据**：载荷 .NET 元数据: SetWindowsHookEx, ToUnicodeEx, GetKeyboardState, ChangeClipboardChain, get_Clipboard; 注入进程内存含 "KL_"、"Copied Text: "、"{ALT+TAB}"/"{CAPSLOCK}" 键名模板与颜色 #00ba66
> 
> **来源**：`ref:59d3b9b646` · `ref:77ef06292d`

### 7. 截屏并收集主机信息

`T1113` · 置信度 **高** · 静态

载荷通过 Graphics.CopyFromScreen + Bitmap/ImageFormat.Jpeg 生成屏幕截图（SC_*.jpeg），并用 WMI 查询 Win32_Processor、Win32_NetworkAdapterConfiguration、Win32_BaseBoard 及 SystemInformation 收集主机名、用户名、操作系统版本、CPU、内存、IP/MAC 与主板序列号，形成受害者画像。

> **证据**：注入进程内存含 "SELECT * FROM Win32_Processor"、"Win32_NetworkAdapterConfiguration"、"IPEnabled"、"MacAddress"、"Win32_BaseBoard"、"SerialNumber"、"SC_.jpeg"、"Screenshot"、"image/jpeg"；载荷元数据含 get_Screen/CopyFromScreen/ManagementObjectSearcher
> 
> **来源**：`ref:77ef06292d` · `ref:59d3b9b646`

### 8. 部署 Tor 隐蔽通道

`T1090.003` · 置信度 **高** · 静态

载荷内置 torrc 模板（DataDirectory %tordir%\Data\Tor、ControlPort 9051、CookieAuthentication 1、hashedcontrolpassword %hash%、AvoidDiskWrites 1）并规划从 hxxps://www.theonionrouter[.]com/.../tor-win32-0.4.3[.]6.zip 下载 Tor 9.5.3，随后启动 tor.exe、等待 "Bootstrapped 100%" 并通过 9051 控制端口发起 SIGNAL NEWNYM，用于把回连/外传藏进 Tor 网络。

> **证据**：注入进程内存 0x9b6522-0x9b6712: "AUTHENTICATE \"%torpass%\""、"SIGNAL NEWNYM"、"ControlPort 9051"、"hashedcontrolpassword %hash%"、"Bootstrapped 100%"、tor-win32-0.4.3[.]6.zip 下载地址
> 
> **来源**：`ref:eba426a687` · `ref:77ef06292d`

### 9. 多通道外传窃密日志

`T1048.003` · 置信度 **高** · 静态

载荷实现 SMTP 附件发送（MailMessage/SmtpClient，含账号配置模型）、FTP 上传（FtpWebRequest，%ftphost%/%ftpuser%/%ftppassword%）、Web 面板 HTTP POST（webpanel/PostURL/%urlkey%）以及 multipart/form-data 的 chat_id/document 上传，把键盘记录、截屏、Cookie、凭据打包为 CO_*.zip、SC_*.jpeg、KL_*.html 外传。

> **证据**：注入进程内存: "webpanel"、"PostURL"、"multipart/form-data; boundary="、"chat_id"、"sendDocument"、"CO_"、"SC_"、"KL_"、"application/zip"、"%ftphost%/%ftpuser%%ftppassword%"
> 
> **来源**：`ref:77ef06292d` · `ref:eba426a687`

### 10. 写入启动项实现自启

`T1547.001` · 置信度 **中** · 静态

载荷内置持久化模板：复制自身到 %startupfolder%\%insfolder%\%insname%，写 HKCU\Software\Microsoft\Windows\CurrentVersion\Run（值名 %insregname%）与 HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows 的 Load 值，并处理 StartupApproved\Run 以规避启动项被禁用；本次分析窗口内未观测到实际注册表写入或文件落盘。

> **证据**：注入进程内存 0x9b3e84: "%startupfolder%\\%insfolder%\\%insname%"、"Software\\Microsoft\\Windows\\CurrentVersion\\Run"、"%insregname%"、"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\R"、"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"、"Load"
> 
> **来源**：`ref:eba426a687` · `ref:77ef06292d`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\%insfolder%\%insname%`
- `%TEMP%\ (运行期临时文件模板：CO_*.zip / SC_*.jpeg / KL_*.html / log.tmp)`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run (值名 %insregname%)`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`
- `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows (值 Load)`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `payload_injection_host` | `C:\Windows\Microsoft[.]NET\Framework\v4.0.30319\csc.exe` | 是 | 动态 |
| `exfil_channels` | `SMTP(MailClient/SmtpClient 附件) + FTP(FtpWebRequest) + Web 面板 HTTP POST(%urlkey%/%PostURL%) + 可选 Telegram 风格 multipart 上传` | 是 | 静态 |
| `tor_channel` | `内置 torrc 模板：DataDirectory %tordir%\Data\Tor / ControlPort 9051 / CookieAuthentication 1 / hashedcontrolpassword %hash%` | 否 | 静态 |
| `tor_install_source` | `hxxps://www.theonionrouter[.]com/dist[.]torproject[.]org/torbrowser/9.5.3/tor-win32-0.4.3[.]6.zip` | 否 | 静态 |
| `persistence_templates` | `%startupfolder%\%insfolder%\%insname%；HKCU\...\CurrentVersion\Run:%insregname%；HKCU\...\Windows NT\CurrentVersion\Windows:Load；StartupApproved 记录` | 是 | 静态 |
| `credential_targets` | `Chromium/Firefox 全系浏览器登录与 Cookie；Windows Vault；Windows RDP；FileZilla/WinSCP/SmartFTP/FlashFXP/CoreFTP/WS_FTP/FTPGetter；The Bat!/Outlook/Foxmail/Becky!/eM Client/Mailbird/PocoMail/IncrediMail/Eudora/Claws Mail；Pidgin/Trillian；UltraVNC/TightVNC；DynDNS/No-IP/Psi+/OpenVPN/NordVPN/PIA/IDM/MySQL Workbench` | 是 | 静态 |
| `campaign_id` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能声称样本已完成数据外传：分析窗口内网络监控未记录到样本进程或其注入进程的任何外联，SMTP/FTP/Web 面板/Tor 仅是载荷内置能力与模板。
- 不能归类为勒索软件或擦除器：未发现文件加密、删除或勒索信相关行为与字符串。
- 不能声称持久化已经生效：Run 键、Startup 目录与 Windows Load 值仅见于解密后的模板字符串，遥测中没有对应的注册表写入或文件创建事件。
- 不能声称发生了横向移动：未观测到 SMB/远程服务创建或远程主机连接，注入目标仅为本机 csc.exe。
- 不能把注入进程的创建父进程直接认定为样本：系统遥测未记录父进程字段，父子关系由时间线与唯一恶意主体推断。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 未恢复外部 C2 地址、密钥、互斥量与活动 ID：载荷配置为运行时解密，静态文件与两次内存转储中均未出现明文 C2 或 .onion 地址。
2. 网络监控未记录到样本进程或其注入进程的任何连接，因此 C2 列表为空，外传行为只能按内置能力判定，不能按已发生外传判定。
3. 注入进程 csc.exe 的父进程字段未出现在系统遥测中；“样本创建该进程”由时间线（样本启动 44 秒后出现无参数 csc.exe、窗口内无其他恶意主体）推断，非直接父子证据。
4. 载荷 .NET 程序集被混淆（类型/方法名重命名为单双字母、用户字符串加密），可读信息来自内存明文串表与元数据引用，因此家族归属为特征匹配而非厂商命名。
5. 遥测中 Defender 与 AMSI 事件为空，无法确认终端防护是否告警或拦截过该样本。
6. 沙箱客体在分析后已回滚，未保留运行期落盘文件；持久化与驻留路径均为模板推断。

## 证据索引

<details>
<summary>展开 18 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:9696b2a8be` | 样本分诊 | M1 分诊：前后缀哈希、6 个节、熵、导入面与加壳评分 0 |
| `ref:f80506a6e0` | PE 结构解析 | PE 结构：AMD64、GUI 子系统、6 节（.text/.rdata/.data/.pdata/.fptable/.rsrc）、无签名数据目录 |
| `ref:0a59e3baa0` | 导入表解析 | 5 个 DLL / 146 个导入，含 bcrypt、ole32、KERNEL32 与 KERNELBASE（NativeAOT 运行时形态） |
| `ref:8accf5bb75` | 字符串提取 | 字符串中出现 "Fatal error. .NET runtime failed to initialize."、CoreCLR/.NET Runtime 标识，确认 NativeAOT .NET |
| `ref:9c68760627` | 字符串提取 | 资源段字符串：Birch Desktop Utility / peridot.dll / v3.7.2.6 / 清单 Birch.DesktopUtility |
| `ref:387a4ecebf` | 密码学常量识别 | 命中 TEA/XTEA 黄金比常量 0x9E3779B9（混淆字符串解密常量） |
| `ref:0c3c268324` | dyn.run | 仿真仅执行到 .NET 运行时初始化（FlsAlloc/VirtualProtect），未进入业务逻辑 |
| `ref:957e51302c` | unpack.detect | 静态判断未加壳（packed=false） |
| `ref:18024335f5` | 动态分析平台 | 真实动态：样本 PID 4032 运行，抓取 6 份内存转储，窗口内无新子进程被记录 |
| `ref:fa5fe72aea` | watch.timeline | 时间线：样本 4032 生成、t0/t3 两轮转储、无 hollows 命中 |
| `ref:456b1985f9` | telemetry.sysmon | 系统遥测进程创建：样本 4032、无参数 csc.exe 2420（17:27:51）、注入工具扫描记录 |
| `ref:ab478739dd` | memory.forensics | csc.exe 2420 内存取证：主模块 PE 头替换、0x260000 处 MEM_MAPPED 注入 PE、amsi/clr/ntdll 代码补丁 |
| `ref:59d3b9b646` | metadata.parse | 注入程序集元数据：SetWindowsHookEx/ToUnicodeEx/VaultGetItem/WebClient/SmtpClient/BCrypt 等引用 |
| `ref:77ef06292d` | memory.strings | 注入进程内存解密串表：浏览器/邮件/FTP/VNC/VPN 凭据目标、外传模板、Tor 模板、键盘记录模板 |
| `ref:eba426a687` | memory.strings | 内存中外传与 Tor 细节：webpanel/PostURL/%urlkey%/ControlPort 9051/hashedcontrolpassword/下载地址 |
| `ref:3aa704b08e` | hash.artifacts | 恢复产物哈希：asm_big.bin / asm_small.bin / 260000.csc.exe |
| `telemetry:30eed7cc` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 120 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 22 条 |
| `etw:30eed7cc:4032` | 进程事件监控 | 短命进程事件：30eed7cc22eca8d8e9bdbc77413b05a1a3b5f18426c153f084981fde111bd4cc.exe（pid 4032；MD5=5010B8399509839408562B25414645BC,SHA256=30EED7CC22ECA8D8E9BDBC77413B05A1A3B5F18426C153F084981FDE111BD4CC,IMPHASH=34C1613AD57F5792B6BB9A7A4B724D84） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
