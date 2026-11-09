---
title: "恶意样本分析：ScreenConnect（other · msi · 2ec27605）"
published: 2026-11-08
draft: false
description: "恶意（置信度高）：ScreenConnect · rat/backdoor · 难度 medium · 纯静态分析"
tags: ["ScreenConnect", "rat", "backdoor", "MSI"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ScreenConnect** · 置信度 **高**
> 
> 别名：ConnectWise Control、ConnectWise ScreenConnect、ScreenConnect Client
> 
> 安装包是一个未签名的 ScreenConnect 25.2.4.9229 定制客户端，MSI 数据库与 system.config 均固定指向外部中继 pridaworldcity[.]shop:8041，并以 Access/Guest 角色接入；同时注册自动启动服务、安全模式持久化、LSA 认证包、登录凭据提供程序和 URL 协议处理器。嵌入 PE 带有 ConnectWise 签名但证书已被吊销。没有执行样本，恶意性基于安装包配置与持久化注册的直接静态证据。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ScreenConnect** · 别名 ConnectWise Control、ConnectWise ScreenConnect、ScreenConnect Client |
| 置信度 | **高** |
| 行为类 | rat · backdoor |
| 难度 | medium |
| 首次出现 | 2026-11-08 10:54:27 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/2ec27605d8a42fea6ef86e6f8b7fd416c2ef598f5e912333c5c4c0ec14a47314/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">安装自启动远程控制服务</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">写入安全模式持久化键</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1112</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">注册LSA认证包</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">注册登录凭据提供程序</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1556</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">外联攻击者中继服务器</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `2ec27605d8a42fea6ef86e6f8b7fd416c2ef598f5e912333c5c4c0ec14a47314` |
| MD5 | _未记录_ |
| 大小 | 14,385,152 字节（13.7 MB） |
| 类型 | other · `msi` |

## 行为分析

共 **9** 条行为，每条都挂了证据，且全部静态可得。

### 1. 安装自启动远程控制服务

`T1543.003` · 置信度 **高** · 静态

MSI 的 ServiceInstall 表创建名为 ScreenConnect Client (5776edccd59d9568) 的 Win32 自有进程服务，StartType=2（自动启动），Arguments 直接传入 SERVICE_CLIENT_LAUNCH_PARAMETERS；ServiceControl 启动该服务，ServiceConfig 将第一/第二次失败动作设为 restart。

> **证据**：ServiceInstall 行 ServiceType=16, StartType=2, Arguments=[SERVICE_CLIENT_LAUNCH_PARAMETERS]；ServiceControl Event=163；ServiceConfig First/SecondFailureActionType=restart
> 
> **来源**：`ev-000023`

### 2. 写入安全模式持久化键

`T1112` · 置信度 **高** · 静态

Registry 表在 HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (5776edccd59d9568) 写入值 'Service'，使该服务在安全模式（带网络）下仍会被加载。

> **证据**：Registry 表 reg3831C0C36D9CE44BC3E6FAE6F161BEA8：Root=2(HKLM), Key=SYSTEM\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME], Value=Service
> 
> **来源**：`ev-000023`

### 3. 注册LSA认证包

`T1547.002` · 置信度 **高** · 静态

Registry 表向 HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages 追加 ScreenConnect.WindowsAuthenticationPackage.dll，注册自定义 LSA 认证包。

> **证据**：Registry 表 regB33BA5DF8D6A3B0A5B5032B6CB3E561B：Root=2, Key=SYSTEM\CurrentControlSet\Control\Lsa, Name=Authentication Packages, Value=[~][#ScreenConnect.WindowsAuthenticationPackage.dll]
> 
> **来源**：`ev-000023` · `ev-000002`

### 4. 注册登录凭据提供程序

`T1556` · 置信度 **高** · 静态

Registry 表注册 CLSID {6FF59A85-BC37-4CD4-1515-049683AF130A}\InprocServer32 指向 ScreenConnect.WindowsCredentialProvider.dll，并加入 Credential Providers 列表，使客户端可介入 Windows 登录界面。

> **证据**：Registry 表 reg86A6324C.../regA0D3A6DD.../regCC376884...；CREDENTIAL_PROVIDER_CLASS_ID={6FF59A85-BC37-4CD4-1515-049683AF130A}
> 
> **来源**：`ev-000023`

### 5. 外联攻击者中继服务器

`T1071` · 置信度 **高** · 静态

system.config 的 ClientLaunchParametersConstraint 与 MSI 启动参数均固定 h=pridaworldcity[.]shop、p=8041、k=<RSA-2048 公钥>；客户端启动后连接该中继建立会话通道。

> **证据**：system.config 偏移 410 的 ClientLaunchParametersConstraint；MSI Property SERVICE_CLIENT_LAUNCH_PARAMETERS；k 解码为 PUBLICKEYBLOB / RSA-2048
> 
> **来源**：`ev-000001` · `ev-000023`

### 6. 配置访客免认证接入

`T1219` · 置信度 **中** · 静态

同一启动参数含 e=Access&y=Guest，客户端以 Access/Guest 角色接入中继；结合中继端的来宾策略，操作者可在不持有目标本地凭据的情况下建立远程控制会话。

> **证据**：SERVICE_CLIENT_LAUNCH_PARAMETERS = ?e=Access&y=Guest&h=pridaworldcity[.]shop&p=8041&k=...
> 
> **来源**：`ev-000023` · `ev-000001`

### 7. 投放远程Shell组件

`T1105` · 置信度 **高** · 静态

安装包部署 ScreenConnect.WindowsBackstageShell.exe 与 ScreenConnect.WindowsFileManager.exe；ClientService 字符串包含 TryRunCommandMessageCommand、FileMessage、TransferFilesMessage、ClipboardBlobMessage、TrySendSas 等远程命令/文件/剪贴板处理链。

> **证据**：MSI File 表/字符串中的 ScreenConnect.WindowsBackstageShell.exe、ScreenConnect.WindowsFileManager.exe；ClientService 字符串 TryRunCommandMessageCommand、FileMessage、TransferFilesMessage、ClipboardBlobMessage、TrySendSas
> 
> **来源**：`ev-000022` · `ev-000002`

### 8. 注册URL协议拉起客户端

`T1112` · 置信度 **高** · 静态

Registry 表注册 URL 协议 sc-5776edccd59d9568，open 命令为 "[INSTALLLOCATION]ScreenConnect.WindowsClient.exe" "%1"，可通过特制链接拉起客户端。

> **证据**：Registry 表 regED314AE69CE5D835D523FB365C82C36B：Key=[URL_SCHEME]\shell\open\command, Value="[INSTALLLOCATION]ScreenConnect.WindowsClient.exe" "%1"
> 
> **来源**：`ev-000023`

### 9. 隐藏托盘图标与通知

`T1564` · 置信度 **高** · 静态

app.config 将 AccessShowSystemTrayIcon、ShowSystemTrayIcon、ShowBalloonOnConnect、ShowBalloonOnHide 等设置为 false，运行时尽量不显示托盘图标和连接/隐藏提示。

> **证据**：app.config 偏移 1474-1805：Support/Access/ShowSystemTrayIcon=false；ShowBalloonOnConnect/OnHide=false
> 
> **来源**：`ev-000025`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `pridaworldcity[.]shop` | 8041 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)`
- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)\ScreenConnect.ClientService.exe`
- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)\ScreenConnect.WindowsClient.exe`
- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)\ScreenConnect.WindowsBackstageShell.exe`
- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)\ScreenConnect.WindowsFileManager.exe`
- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)\ScreenConnect.WindowsCredentialProvider.dll`
- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)\ScreenConnect.WindowsAuthenticationPackage.dll`

**注册表**

- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (5776edccd59d9568)`
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6FF59A85-BC37-4CD4-1515-049683AF130A}\InprocServer32`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-1515-049683AF130A}`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Classes\sc-5776edccd59d9568\shell\open\command`

**服务**

- `ScreenConnect Client (5776edccd59d9568)`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `pridaworldcity[.]shop` | 是 | 静态 |
| `c2_port` | `8041` | 是 | 静态 |
| `relay_public_key` | `BgIAAACkAABSU0ExAAgAAAEAAQCZH6bqCBgUL5EZDH0N/2gP0+i5KpkjnYNAVpO6XLmjkQnKtg4qcM4qmC7bSuMBbm6Pr8zSf2Vq0SDOHQHhZawgbF1CEmSufaEnE6xpGwemG6F0HgzCNTtdzjUXtJGTDWZej1aWcWaNV2XFFdwmJE0z2jk6g7pmcEyycRaVdI8O0eFPQpqxsQS7LJeTnxfLZtlSdq9C/61Z8xRYH53S+RqlhcFllbiApB0sdWN8ZmZBPr/4EM2pvkM9En20Apqw4gN4csI+ssfoDsKWj2sWt5q5Kd7cB/Ho8wP6HdraGyKZfGgMp3EjpJwnSqWps+6RDDqXu3iOcrf9djtNP7tOO8+/` | 是 | 静态 |
| `relay_key_type` | `RSA-2048` | 否 | 静态 |
| `encryption_algo` | `RSA-2048` | 否 | 静态 |
| `instance_id` | `5776edccd59d9568` | 是 | 静态 |
| `access_mode` | `Access / Guest` | 是 | 静态 |
| `service_name` | `ScreenConnect Client (5776edccd59d9568)` | 是 | 静态 |
| `install_path` | `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)` | 是 | 静态 |
| `product_version` | `25.2.4.9229` | 否 | 静态 |
| `url_scheme` | `sc-5776edccd59d9568` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要把 BackstageShell/FileManager 的存在当作已经发生远程命令执行或文件窃取：静态分析只看到组件与消息处理代码，未观测到实际会话。
- 不要把它归为 ransomware/wiper：未发现加密、删除、勒索或破坏性代码；这是被滥用的 RMM 客户端。
- 不要声称已观测到与 pridaworldcity[.]shop 的 C2 会话或成功连接：样本未执行，C2 仅来自静态配置。
- 不要断言嵌入的 ScreenConnect 二进制被攻击者篡改：它们带有 ConnectWise 签名（证书已被颁发者吊销），主要恶意性来自定制配置、未签名 MSI 和持久化注册。
- 不要仅凭域名归因到某个勒索软件组织或攻击活动；缺少基础设施关联和战役证据。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 纯静态分析：未执行、未仿真、未在沙箱中引爆样本，无法确认真实网络连接、会话建立、命令执行或凭据读取。
2. 安装包结构异常：MSI 的 Default.cab 流之后还附加了多份递增文件数的 CAB（14→20 个文件），部分资源在提取时被截断（Client.Override.resources 标称 323648 字节，实际只取到 32767 字节）；不影响主配置与 PE 组件判断，但完整性存疑。
3. 嵌入 PE 的 Authenticode 证书状态为 'A certificate was explicitly revoked by its issuer'；MSI 本身未签名。无法据此确认二进制来源或完整性。
4. C2/中继配置为静态提取，标记 recoverability=static 且 pending_dynamic_verify=true；未获取真实会话或假网日志。
5. 未联网解析 pridaworldcity[.]shop，无法确认域名当前归属、解析记录或是否仍活跃。
6. 无法归因到具体攻击者/勒索软件组织；ScreenConnect 是合法 RMM 产品，若由合法管理员部署则可能属于正常运维。
7. MSI 的 CustomAction FixupServiceArguments 等未逐条反编译，服务参数可能在安装时被进一步修正；但 Property 与 system.config 中的中继配置已足以定位 C2。

## 证据索引

<details>
<summary>展开 10 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000023` | evidence.record (MSI database parsing) | Property/ServiceInstall/ServiceControl/ServiceConfig/Registry/Directory 表：relay、service、safe mode、LSA、credential provider、URL scheme |
| `ev-000024` | evidence.record (Authenticode) | MSI 未签名；ServiceExe/WindowsClient 签名者为 ConnectWise，证书被吊销 |
| `ev-000001` | 字符串提取 | system.config 中的 ClientLaunchParametersConstraint: h=pridaworldcity[.]shop&p=8041&k=... |
| `ev-000002` | 字符串提取 | ScreenConnect.ClientService.dll 中的命令/文件/剪贴板/凭据处理字符串 |
| `ev-000022` | 字符串提取 | MSI 中的组件名、ProductCode、Credential Provider GUID 等字符串 |
| `ev-000025` | 字符串提取 | app.config 中的托盘图标/通知隐藏设置 |
| `ref:f1d2c11080` | PE 结构解析 | ServiceExeWithService 导入 CreateServiceW/StartServiceW/RegSetValueExW 等服务与注册表 API |
| `ref:1bcf719020` | 哈希与指纹 | ServiceExeWithService SHA256=f048400c23add8c75abe189393d33c873c02c74eeaf43d47b950c8d643763b35；imphash=48809c7ee5e417210ac66dca4db818df |
| `ref:366e8cc684` | CAB extraction | Default.cab 解出 17 个文件（PE/配置/资源） |
| `ref:0477e3830c` | hash calculation | 提取组件的 SHA256 列表 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
