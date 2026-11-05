---
title: "恶意样本分析：ScreenConnect（PE · exe · 079fe697）"
published: 2026-11-05
draft: false
description: "恶意（置信度高）：ScreenConnect · rat/backdoor · 难度 easy · 动态沙箱 + 静态反编译"
tags: ["ScreenConnect", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ScreenConnect** · 置信度 **高**
> 
> 别名：ConnectWise Control、ConnectWise ScreenConnect、ScreenConnect Client
> 
> 样本为带有有效 ConnectWise 数字签名的 ScreenConnect(ConnectWise Control)客户端安装包，但内嵌 MSI 的会话参数被固定指向外部运营者实例 instance-kiscll，并安装以 LocalSystem 运行的自动启动服务、注册凭据提供程序与 LSA 认证包，构成面向未知第三方的全功能远程控制植入。签名只证明构建来源，不证明实例归属和使用授权。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ScreenConnect** · 别名 ConnectWise Control、ConnectWise ScreenConnect、ScreenConnect Client |
| 置信度 | **高** |
| 行为类 | rat · backdoor |
| 难度 | easy |
| 首次出现 | 2026-11-02 16:07:06 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/079fe697069f4fa94a73754d356e3084053427fed92cea0f2c7e2ea4298c10d8/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">内置中转地址配置</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">安装自启系统服务</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">注册登录界面远控</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1556</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">挂接LSA认证包</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">释放多组件远控程序</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `079fe697069f4fa94a73754d356e3084053427fed92cea0f2c7e2ea4298c10d8` |
| MD5 | _未记录_ |
| 大小 | 12,842,552 字节（12.2 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 内置中转地址配置

`T1071.001` · 置信度 **高** · 静态

内嵌 MSI 的 SERVICE_CLIENT_LAUNCH_PARAMETERS 属性写死 e=Access&y=Guest 会话参数、中转主机 h=instance-kiscll-relay[.]screenconnect[.]com、端口 p=443 与服务器 RSA 公钥 k，安装后由服务原样使用该参数回连。

> **证据**：MSI Property 表 SERVICE_CLIENT_LAUNCH_PARAMETERS；SC_PAYLOAD 偏移 2574456 的 #10 资源
> 
> **来源**：`ev-000060`

### 2. 安装自启系统服务

`T1543.003` · 置信度 **高** · 静态

MSI ServiceInstall 表创建名为 "ScreenConnect Client (10dfa41e812005bd)" 的服务，ServiceType=16(own process)、StartType=2(auto)、DisplayName="Remote Control"，命令行参数为上述中转站参数，从而以服务身份长期驻留。

> **证据**：msilib ServiceInstall 行: StartType=2, ServiceType=16, Arguments=[SERVICE_CLIENT_LAUNCH_PARAMETERS]
> 
> **来源**：`ev-000060`

### 3. 注册登录界面远控

`T1556` · 置信度 **高** · 静态

MSI Registry 表把 CLSID {6FF59A85-BC37-4CD4-4997-70E0A190F289} 的 InprocServer32 指到 ScreenConnect.WindowsCredentialProvider.dll，并注册到 Credential Providers 列表，使远控组件可在 Windows 登录界面被加载，覆盖锁屏/登录场景。

> **证据**：Registry 表 reg484EC307914B152DDA21A85E972FFE8A: CLSID\...\InprocServer32 -> WindowCredentialProvider.dll
> 
> **来源**：`ev-000060` · `ev-000045`

### 4. 挂接LSA认证包

`T1547.005` · 置信度 **高** · 静态

MSI Registry 表向 HKLM\SYSTEM\CurrentControlSet\Control\Lsa 的 Authentication Packages 值追加 ScreenConnect.WindowsAuthenticationPackage.dll，将自定义认证包注入登录认证流程。

> **证据**：Registry 表 reg27BFB9E3BAD4AA096A74DD0F76D17ED5: SYSTEM\CurrentControlSet\Control\Lsa Authentication Packages
> 
> **来源**：`ev-000060` · `ev-000044`

### 5. 释放多组件远控程序

`T1219` · 置信度 **高** · 静态

MSI File 表将 ClientService、WindowsClient、BackstageShell、FileManager、Core/Client/Windows 托管库及凭据提供程序、认证包等 18 个组件释放到安装目录，构成完整的远程桌面、后台 Shell、文件管理与登录态控制能力。

> **证据**：MSI File 表 18 行；字符串 ScreenConnect.WindowsBackstageShell.exe / ScreenConnect.WindowsFileManager.exe / ScreenConnect.ClientService.exe
> 
> **来源**：`ev-000060` · `ref:1dda566b1c`

### 6. 注册URL协议唤起

`T1546` · 置信度 **高** · 静态

MSI Registry 表创建 HKCR\sc-10dfa41e812005bd 及 shell\open\command 指向 ScreenConnect.WindowsClient.exe "%1"，使外部链接可直接拉起客户端并传入会话参数。

> **证据**：Registry 表 regED314AE69CE5D835D523FB365C82C36B: [URL_SCHEME]\shell\open\command
> 
> **来源**：`ev-000060`

### 7. 安全模式保持驻留

`T1112` · 置信度 **高** · 静态

MSI Registry 表在 HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME] 写入 "Service"，使该服务在安全模式（网络）下仍被加载，增加清除难度。

> **证据**：Registry 表 reg3831C0C36D9CE44BC3E6FAE6F161BEA8: SafeBoot\Network\[SERVICE_NAME] = Service
> 
> **来源**：`ev-000060`

### 8. 回连443中转站

`T1071.001` · 置信度 **中** · 静态

安装后的服务按配置向 instance-kiscll-relay[.]screenconnect[.]com:443 建立出站会话（ScreenConnect 以 HTTP(S) 承载中继流量），等待运营者接入并下发控制指令。

> **证据**：配置 h=...&p=443；本次动态运行未观测到该连接（安装未完成）
> 
> **来源**：`ev-000060`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://instance-kiscll-relay[.]screenconnect[.]com` | 443 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)\ScreenConnect.ClientService.exe`
- `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)\ScreenConnect.WindowsClient.exe`
- `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)\ScreenConnect.WindowsBackstageShell.exe`
- `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)\ScreenConnect.WindowsFileManager.exe`
- `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)\ScreenConnect.WindowsCredentialProvider.dll`
- `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)\ScreenConnect.WindowsAuthenticationPackage.dll`

**注册表**

- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa (Authentication Packages 追加 ScreenConnect.WindowsAuthenticationPackage.dll)`
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (10dfa41e812005bd)`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-4997-70E0A190F289}`
- `HKCR\CLSID\{6FF59A85-BC37-4CD4-4997-70E0A190F289}\InprocServer32`
- `HKCR\sc-10dfa41e812005bd\shell\open\command`

**服务**

- `ScreenConnect Client (10dfa41e812005bd)`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `instance-kiscll-relay[.]screenconnect[.]com` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `instance_name` | `kiscll` | 是 | 静态 |
| `instance_id` | `10dfa41e812005bd` | 是 | 静态 |
| `service_launch_parameters` | `?e=Access&y=Guest&h=instance-kiscll-relay[.]screenconnect[.]com&p=443&k=BgIAAACkAABSU0ExAAgAAAEAAQABkytvcpYvQRJ%2b3DTPa0GCVP%2fQzmrHhAs%2blgU3UTQC1n3umKCmw%2f1omAeRte8Jhiman0dSse1p6tJrYzgcY7bvHOXisKjGACElGZD02daWxt%2bkeiietMYVLtLlL%2fp69oN%2fUnkyY3PQhCF%2f6F5xeC91C%2b5WMCrkxzZUIiRIjgdoq8gRJ%2f%2bHIaBJ9GI7kGZPwrbh%2bzIHb5sEwNHWmI%2b26BJCUGT3z244vGsxVdNnaom3UC4EXssITfPcMhicRNZvHsDJnXKElEM%2f%2bzAY1%2fJPqpPt%2fIXYOxjUxWkbJL%2fJe0PZlJGhIk%2b9gpOM1hq1xjfeHlJygMy%2bVTYO61QmFE8NG7XL` | 是 | 静态 |
| `encryption_algo` | `RSA-2048 (CAPI PUBLICKEYBLOB "RSA1", aiKeyAlg=CALG_RSA_KEYX) 用于中转站身份校验` | 否 | 静态 |
| `service_name` | `ScreenConnect Client (10dfa41e812005bd)` | 是 | 静态 |
| `install_path` | `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)` | 是 | 静态 |
| `url_scheme` | `sc-10dfa41e812005bd` | 否 | 静态 |
| `product_version` | `26.7.6.9783` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要将其判定为勒索软件或擦除器：样本与内嵌 MSI 中未发现文件加密、卷影删除或磁盘破坏逻辑。
- 不要声称其具备自主横向传播能力：样本自身只是安装并运行远控客户端，横向移动需由远端运营者手动作业，不能归因于二进制。
- 不要把有效的 ConnectWise 数字签名当作安全或无害的依据：签名仅证明由厂商构建，实例归属与使用目的无法由签名证明。
- 不要在缺少流量证据时断言已成功上线 C2：本次动态运行未安装完成，未观测到对中转站的网络请求。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `ac0c4b51f6d244e1dc70890c9490dabea4973597a89bf7269ca8d4e32e584ad4`） |

**局限与待验证**

1. 本次真实动态运行只观察到外层安装器进程常驻，未完成 MSI 安装，因此服务创建、文件落地、注册表写入与回连行为均由静态 MSI 表与配置推导（recoverability=static），C2 连接标记 pending_dynamic_verify。
2. 中转站域名属于 ConnectWise 云托管的中继基础设施，实例 kiscll 的运营者身份无法通过样本本身确认；需结合该域名的被动 DNS/证书与网络日志进一步归属。
3. 未取得安装后的 ScreenConnect.ClientService.exe 运行样本，无法核对运行时配置是否与 MSI 内嵌参数一致。
4. 样本使用 ScreenConnect 正常安装机制，若在具备提权与交互条件的环境中安装，行为可能比本次观测更完整。

## 证据索引

<details>
<summary>展开 8 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 12842552 字节 |
| `ev-000002` | scan.imphash | imphash=cd305a01d034d1a4ac62cbed1ae36be7，导入仅 mscoree/KERNEL32/OLEAUT32（.NET 宿主） |
| `ev-000007` | scan.entropy | .rsrc 熵 7.808（12.7MB），对应内嵌打包资源 |
| `ev-000039` | 字符串提取 | 命中 WiX/安装器字符串 ScreenConnect 组件清单与 GUID |
| `ev-000044` | 字符串提取 | 命中 AuthenticationPackageFilesX86_64 与 WindowsAuthenticationPackage.dll |
| `ev-000045` | 字符串提取 | 命中 CredentialProviderFilesX86_64 与 WindowsCredentialProvider.dll |
| `ev-000052` | 字符串提取 | 命中 MSI config GUID 与 URL_SCHEME/服务参数上下文 |
| `ev-000060` | 脚本化取证 | 解析 SC_PAYLOAD 与内嵌 MSI 全部关键表，提取中转站、服务、注册表与组件清单；核验外层 Authenticode 签名有效 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
