---
title: "恶意样本分析：Agent Tesla（other · vbe · f5dcf0ba）"
published: 2026-11-18
draft: false
description: "恶意（置信度高）：Agent Tesla · stealer/loader/spyware · 难度 hard · 纯静态分析"
tags: ["Agent Tesla", "stealer", "loader", "spyware"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Agent Tesla** · 置信度 **高**
> 
> 别名：AgentTesla、Agent-Tesla
> 
> 样本是一个明文 VBScript 包装器（.vbe），先落地并运行 PowerShell，再经 Base64 + GZip + AES-256-CBC/PKCS7 解出第二层 PowerShell，随后用固定 XOR 密钥还原 .NET 加载器，并通过反射调用 DEVVV.WHORE.LAUNCHER 加载 CloudServices 程序集。该 CloudServices 程序集包含 SMTP、FTP、Telegram 外传通道，以及浏览器/邮件客户端凭据窃取、键盘记录、剪贴板窃取、截屏和禁用安全工具等功能，具备完整的信息窃取器能力。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Agent Tesla** · 别名 AgentTesla、Agent-Tesla |
| 置信度 | **高** |
| 行为类 | stealer · loader · spyware |
| 难度 | hard |
| 首次出现 | 2026-11-16 16:00:02 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/f5dcf0baa347c29202f8c4cf7ca69f5e3e2d1a627fba29e9a20209f45489313d/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">落地并执行PowerShell</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.005; T1059.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">解密内嵌PowerShell</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027; T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">XOR还原.NET载荷</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027; T1140</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">反射加载载荷程序集</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">轮询哨兵后延迟触发</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `f5dcf0baa347c29202f8c4cf7ca69f5e3e2d1a627fba29e9a20209f45489313d` |
| MD5 | _未记录_ |
| 大小 | 692,060 字节（675.8 KB） |
| 类型 | other · `vbe` |

## 行为分析

共 **12** 条行为，每条都挂了证据，且全部静态可得。

### 1. 落地并执行PowerShell

`T1059.005; T1059.001` · 置信度 **高** · 静态

VBE 包装器在 C:\Temp\ 生成 8 位随机大写字母命名的 .ps1，并用 powershell.exe -nop -ep bypass -file 静默运行，随后删除临时脚本。

> **证据**：原始 .vbe off 0x00b4 常量 TEMP_DIR=C:\Temp\，off 0x00ef PS_LAUNCH_CMD=powershell.exe -nop -ep bypass -file；StepDecodeAndWrite/StepInvoke/StepRemoveArtifacts
> 
> **来源**：`ref:3bbbb40ff4` · `ev-000003`

### 2. 解密内嵌PowerShell

`T1027; T1140` · 置信度 **高** · 静态

第一层 PowerShell 校验内嵌 GZip 密文的 SHA-256 后解压，再用硬编码 AES-256 密钥和 IV 以 CBC/PKCS7 解密出第二层脚本。

> **证据**：stage1.ps1 内 $B64_Key=UeYqzFDWifEEtogvXiIzCbr/B4b3Nq1iP+IHTzWzNL8=、$B64_IV=5YrDgjSfmp7p7goaohQbIQ==、Expand-GZipBytes/Invoke-AesDecrypt
> 
> **来源**：`ev-000003`

### 3. XOR还原.NET载荷

`T1027; T1140` · 置信度 **高** · 静态

第二层脚本将 Base64 文本先解码，再用固定 13 字节密钥 ZZaDazKA6@@^^ 做重复密钥 XOR，得到 Base64 形式的 .NET 程序集并再次解码。

> **证据**：stage2.ps1 function ConvertFrom-MaskedBlob；$xorKey=ZZaDazKA6@@^^；$encodedFragment 长度 0x1A000
> 
> **来源**：`ev-000003`

### 4. 反射加载载荷程序集

`T1620` · 置信度 **高** · 静态

脚本调用 [Reflection.Assembly]::Load 加载还原后的 .NET DLL，并按类型 DEVVV.WHORE、方法 LAUNCHER 反射执行，把 aspnet_compiler.exe 路径和第二个 PE 字节数组作为参数传入。

> **证据**：stage2.ps1 Invoke-InMemoryAssembly；TypeName 'DEVVV.WHORE'；MethodName 'LAUNCHER'；$hostExe=C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe
> 
> **来源**：`ev-000003`

### 5. 轮询哨兵后延迟触发

`T1497` · 置信度 **高** · 静态

加载器以 aspnet_compiler 为哨兵进程，每 5 秒检查一次；只有在哨兵进程不存在时才继续执行载荷，形成延时/环境规避。

> **证据**：stage2.ps1 Start-WatchLoop：$Sentinel="aspnet_compiler"、$IntervalSeconds=5、Test-ProcessAbsent
> 
> **来源**：`ev-000003`

### 6. 禁用任务管理器与注册表

`T1562.001` · 置信度 **中** · 静态

载荷包含 Taskmgr_Disabler、Registeries_Disabler 和 DisableWD 相关方法/字符串，用于关闭任务管理器、注册表编辑器和安全防护相关功能。

> **证据**：extraData.pe #Strings off 0x1047a 'Taskmgr_Disabler'、off 0x1048b 'Registeries_Disabler'、off 0x0e6e1 'DisableWD'
> 
> **来源**：`ev-000004` · `ref:488c53a4b7`

### 7. 窃取浏览器保存口令

`T1555.003` · 置信度 **高** · 静态

遍历 Chrome、Edge、Firefox、Opera、Brave、Vivaldi、QQ、360、UC 等浏览器配置目录，读取 Login Data/logins.json，并使用 DPAPI、BCrypt AES-GCM、TripleDES 等解密保存的账号密码。

> **证据**：extraData.pe off 0x13527 UTF-16 '\Google\Chrome\User Data\Default\Login Data'；类/方法 CredentialModel、SQLiteHandler、FFDecryptor、MozilSpeed、AesGcm、BCrypt、CryptUnprotectData
> 
> **来源**：`ev-000004` · `ref:488c53a4b7`

### 8. 键盘记录与剪贴板窃取

`T1056.001; T1115` · 置信度 **高** · 静态

通过 SetWindowsHookExA/GetKeyboardState 安装键盘钩子并启动 KeyLogger，同时读取和替换剪贴板内容用于窃取复制数据。

> **证据**：extraData.pe off 0x0e688 'SetWindowsHookExA'、off 0x10451 'StartKeylogger'、off 0x10260 'ClipboardReplacer'、off 0x0f5d1 'GetKeyboardState'
> 
> **来源**：`ev-000004` · `ref:488c53a4b7`

### 9. 截屏并打包外传

`T1113` · 置信度 **高** · 静态

调用截屏功能生成 .png 文件，并通过 FTP STOR 上传到 / SCREENSHOT / 目录，或作为邮件/Telegram 附件外传。

> **证据**：extraData.pe off 0x10de0 'TakeScreenshot'；方法名 'ScreenshotSender'；#US 字符串 ' / SCREENSHOT / '、'.png'、'STOR'
> 
> **来源**：`ev-000004`

### 10. 经SMTP回传窃密数据

`T1048` · 置信度 **高** · 静态

使用 System.Net.Mail.SmtpClient 连接 mail[.]merchantinvestnetwork[.]com:587，以 bossy@merchantinvestnetwork[.]com 认证，将 UserData.txt、截图等作为 multipart 附件发送到 bosskkk@merchantinvestnetwork[.]com。

> **证据**：extraData.pe off 0x11a27 / RVA 0x13827 '#SMTPEnabled' 及 SMTP 主机、账号、口令、收件人；off 0x11a89 mail[.]merchantinvestnetwork[.]com；SmtpClient/MailMessage/multipart/form-data
> 
> **来源**：`ev-000004` · `ref:942b62e991`

### 11. 收集邮件客户端凭据

`T1555` · 置信度 **高** · 静态

读取 Outlook 配置注册表键并解密 IMAP/POP3/HTTP/SMTP 密码，同时解析 Foxmail 的 Account.rec0 获取邮箱账号和口令。

> **证据**：extraData.pe #US 'GetOutlookPasswords'/'decryptOutlookPassword'；Outlook Profiles 键；'Foxmail'、'\\Accounts\\Account.rec0'、'POP3Password'
> 
> **来源**：`ev-000004`

### 12. 探测IP并支持多通道外传

`T1016; T1102; T1048` · 置信度 **高** · 静态

通过 checkip[.]dyndns[.]org 和 reallyfreegeoip[.]org 获取受害者公网 IP 与国家，并保留 FTP、Telegram sendDocument 等备用外传路径。

> **证据**：extraData.pe off 0x11d2f 'checkip[.]dyndns[.]org'、off 0x11e21 'reallyfreegeoip[.]org'、off 0x11eeb / RVA 0x13CEB 'hxxps://api[.]telegram[.]org/bot'；'#FTPEnabled'、'#TGEnabled'、'/sendDocument?chat_id='
> 
> **来源**：`ev-000004` · `ref:474acee977`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| smtp | `mail[.]merchantinvestnetwork[.]com` | 587 | exfil | 静态 | ⏳ 未观测 |
| telegram | `hxxps://api[.]telegram[.]org/bot` | 443 | exfil | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\Temp\<8 uppercase letters>.ps1`
- `%APPDATA%\Google\Chrome\User Data\Default\Login Data`
- `%APPDATA%\Microsoft\Edge\User Data\Default\Login Data`
- `%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json`
- `%APPDATA%\FileZilla\recentservers.xml`
- `%APPDATA%\Thunderbird\Profiles\*`

**注册表**

- `HKCU\Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676`
- `HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676`
- `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676`
- `HKCU\Software\Classes\Foxmail.url.mailto\Shell\open\command`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `mail[.]merchantinvestnetwork[.]com; api[.]telegram[.]org` | 是 | 静态 |
| `c2_port` | `587` | 是 | 静态 |
| `smtp_user` | `bossy@merchantinvestnetwork[.]com` | 是 | 静态 |
| `smtp_password` | `2)D?sbbRb+m_{l8%` | 是 | 静态 |
| `smtp_recipient` | `bosskkk@merchantinvestnetwork[.]com` | 是 | 静态 |
| `telegram_api_base` | `hxxps://api[.]telegram[.]org/bot` | 否 | 静态 |
| `ip_check_url` | `hxxp://checkip[.]dyndns[.]org/` | 否 | 静态 |
| `geo_ip_url` | `hxxps://reallyfreegeoip[.]org/xml/` | 否 | 静态 |
| `encryption_algo` | `loader: Base64 -> GZip -> AES-256-CBC/PKCS7; stage2: Base64 + repeating-key XOR; stealer secrets: DPAPI/BCrypt AES-GCM/TripleDES` | 是 | 静态 |
| `install_path` | `未恢复（样本未显式携带安装路径）` | 否 | 静态 |
| `mutex` | `未发现` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能因为载荷使用 AES-GCM/BCrypt/TripleDES 就判定为勒索软件；这些算法用于解密浏览器/邮件客户端凭据和加载器数据。
- 不能因为代码中存在 FTP 和 Telegram 外传路径就断言样本实际使用了它们；静态分析只确认存在能力，完整恢复并启用的是 SMTP 通道。
- 不能把 checkip[.]dyndns[.]org 和 reallyfreegeoip[.]org 当作 C2；它们是公网 IP 与地理定位查询服务。
- 不能声称已观测到注册表写入、计划任务或自启动持久化；本次未执行样本，相关持久化字段未恢复。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 是（stage2 `ffb8cc4aa981225f783cd5f7a22db6f33afa8f2a1162bfb5a2623700815353a7`） |

**局限与待验证**

1. 本次为纯静态分析，未在动态沙箱中引爆，reproduced=false；所有 C2 与配置均为静态解密结果，pending_dynamic_verify=true。
2. Telegram bot token、FTP 凭据和 campaign_id 未在样本中恢复；Telegram/FTP 只能确认代码路径存在。
3. DEVVV.WHORE.LAUNCHER 经 .NET 混淆（不可见 Unicode 类型名、控制流平坦化），其向 aspnet_compiler.exe 注入/加载的精确方式未动态确认。
4. 未发现 mutex、安装路径或计划任务/服务等持久化字段；不能排除运行时生成。

## 证据索引

<details>
<summary>展开 9 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:3bbbb40ff4` | 字符串提取 | 原始 .vbe 明文脚本字符串：C:\Temp\、powershell.exe -nop -ep bypass -file、StepDecodeAndWrite/StepInvoke/StepRemoveArtifacts |
| `ev-000003` | evidence.record | 四层载荷链脚本复现：stage1/stage2/payload_assembly.dll/extraData.pe 的哈希、AES 密钥/IV、XOR 密钥 |
| `ev-000004` | evidence.record | extraData.pe 配置与能力提取：SMTP 账号口令收件人、Telegram API、IP/地理查询、浏览器/邮件/键盘/剪贴板/截屏/禁用安全工具能力 |
| `ev-000002` | 字符串提取 | extraData.pe 字符串扫描：.NET 资源、#Strings/#US 中的配置与能力标识 |
| `ref:22c6109667` | PE 结构解析 | extraData.pe PE 结构：I386、.NET、3 个节、入口 RVA 0x17FCE、仅 mscoree.dll 导入 |
| `ref:52eacba3e2` | PE 结构解析 | payload_assembly.dll PE 结构：I386 DLL、3 个节、入口 RVA 0x100AE |
| `ref:942b62e991` | addr.translate | extraData.pe off 0x11A27 → RVA 0x13827 / VA 0x413827（SMTP 配置区） |
| `ref:474acee977` | addr.translate | extraData.pe off 0x11EEB → RVA 0x13CEB / VA 0x413CEB（Telegram API 字符串） |
| `ref:f692fb9682` | 导入表解析 | extraData.pe 唯一导入 mscoree.dll!_CorExeMain，确认托管程序集 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
