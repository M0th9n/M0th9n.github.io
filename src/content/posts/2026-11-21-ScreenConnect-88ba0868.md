---
title: "恶意样本分析：ScreenConnect（PE · exe · 88ba0868）"
published: 2026-11-21
draft: false
description: "恶意（置信度高）：ScreenConnect · rat/implant · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["ScreenConnect", "rat", "implant", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ScreenConnect** · 置信度 **高**
> 
> 别名：ConnectWise Control、ScreenConnect Client、ScreenConnect RAT
> 
> 该文件是带有 ConnectWise 有效签名的 ScreenConnect(ConnectWise Control)客户端安装器，本身为正规远程控制软件；但其内嵌 MSI 的启动参数硬编码了未知自托管中继 instance-lwmknd-relay[.]screenconnect[.]com:443，并以 Guest/Access 模式预置会话。安装包会注册自启动服务、URL 协议处理器、登录凭据提供程序并挂接 LSA 认证包，具备完整的交互式远程控制与持久化能力，符合攻击者投递 ScreenConnect 作为远程访问木马的典型形态，故判定为恶意。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ScreenConnect** · 别名 ConnectWise Control、ScreenConnect Client、ScreenConnect RAT |
| 置信度 | **高** |
| 行为类 | rat · implant |
| 难度 | medium |
| 首次出现 | 2026-11-19 01:07:08 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">内嵌加密载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">校验并释放MSI</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">安装系统服务</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">注册URL协议</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1546</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">沙箱内加载CLR</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2` |
| MD5 | _未记录_ |
| 大小 | 12,842,552 字节（12.2 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **10** 条行为，每条都挂了证据；其中 **8** 条静态可得、**2** 条经动态分析取得。

### 1. 内嵌加密载荷

`T1027.009` · 置信度 **高** · 静态

.rsrc 资源区携带 12,758,552 字节的高熵数据，其中 FILES 资源为五个 PE/托管程序集(EntryPoint、Resolver、ScreenConnect.Core、ScreenConnect.Windows、ScreenConnect.WindowsInstaller)，类型 10 资源 SC_PAYLOAD 为 10,256,668 字节的自定义容器，前 284 字节为 RSA1 密钥/签名头，0x11C 起为完整 OLE 复合文档(MSI)。

> **证据**：.rsrc 资源表：SC_PAYLOAD rva 0x278878 size 10256668；偏移 0x11C 处字节 d0cf11e0a1b11ae1
> 
> **来源**：`ev-000007` · `ev-000060`

### 2. 校验并释放MSI

`T1140` · 置信度 **中** · 静态

引导器为 requireAdministrator 的混合模式程序，导入 mscoree!CorBindToRuntimeEx 及 FindResourceW/LoadResource/SizeofResource/WriteFile；EntryPoint 程序集含 PayloadStuffingTechnique、GetOriginalPayload、ReadSizePrefixedBytes、SignedMsiFileContents 等方法，先按长度前缀读出载荷、验证 RSA1 签名，再交给 WindowsInstaller 组件修改并落盘安装。

> **证据**：import mscoree!CorBindToRuntimeEx；资源 FILES/_EntryPoint 字符串 PayloadStuffingTechnique、ReadSizePrefixedBytes、SignedMsiFileContents
> 
> **来源**：`ev-000060` · `ev-000059`

### 3. 安装系统服务

`T1543.003` · 置信度 **高** · 静态

内嵌 MSI 的 ServiceInstall 表以 ServiceType=16、StartType=2(auto)、ErrorControl=1 安装名为 "ScreenConnect Client (260a7850ff837e46)" 的服务，映像为 Program Files 下的 ScreenConnect.ClientService.exe，启动参数携带 relay 接入串，实现开机自启动的常驻控制通道。

> **证据**：MSI ServiceInstall: Name=[SERVICE_NAME], StartType=2, ServiceType=16, Arguments=[SERVICE_CLIENT_LAUNCH_PARAMETERS]
> 
> **来源**：`ev-000060`

### 4. 注册URL协议

`T1546` · 置信度 **高** · 静态

写入 HKCR\sc-260a7850ff837e46 作为 URL Protocol，并将 shell\open\command 指向 "...\ScreenConnect.WindowsClient.exe" "%1"，使外部链接可直接拉起远程会话客户端。

> **证据**：MSI Registry 表：Root=0( HKCR )，Key=[URL_SCHEME]，Value=shell\open\command
> 
> **来源**：`ev-000060`

### 5. 劫持登录凭据接口

`T1556` · 置信度 **高** · 静态

注册 CLSID {6FF59A85-BC37-4CD4-8385-DCD77FB81F24}\InprocServer32 指向 ScreenConnect.WindowsCredentialProvider.dll，并在 Credential Providers 键下登记，使控制端可在 Windows 登录/凭据界面发起远程会话。

> **证据**：MSI Registry 表：CLSID\[CREDENTIAL_PROVIDER_CLASS_ID]\InprocServer32、Authentication\Credential Providers\[CREDENTIAL_PROVIDER_CLASS_ID]
> 
> **来源**：`ev-000060`

### 6. 挂接LSA认证包

`T1556` · 置信度 **高** · 静态

向 HKLM\SYSTEM\CurrentControlSet\Control\Lsa 的 Authentication Packages 多字符串追加 ScreenConnect.WindowsAuthenticationPackage.dll，把远程控制组件挂入本机认证流程。

> **证据**：MSI Registry 表：Root=2(HKLM)，Key=SYSTEM\CurrentControlSet\Control\Lsa，Name=Authentication Packages
> 
> **来源**：`ev-000060`

### 7. 登记安全模式启动

`T1543.003` · 置信度 **中** · 静态

在 HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network 下创建与服务同名的键，使该远程控制服务在安全模式(带网络)下仍随系统加载。

> **证据**：MSI Registry 表：System\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME]，Component=Service
> 
> **来源**：`ev-000060`

### 8. 配置自托管中继

`T1219` · 置信度 **高** · 静态

MSI 属性 SERVICE_CLIENT_LAUNCH_PARAMETERS 预置 "?e=Access&y=Guest&h=instance-lwmknd-relay[.]screenconnect[.]com&p=443&k=<RSA1 来宾校验公钥>"，客户端安装后即以 Guest/Access 身份向该 443/TCP 中继发起出站连接，控制端为未知自托管实例 lwmknd。

> **证据**：MSI Property 表 SERVICE_CLIENT_LAUNCH_PARAMETERS 中的 h= 与 p= 字段
> 
> **来源**：`ev-000060`

### 9. 沙箱内加载CLR

`T1204.002` · 置信度 **中** · 动态

在隔离 Windows 客体中运行时，安装器进程 pid 3540 于启动后驻留，内存取证两次转储该进程并取出 8.7 MB 的 CLR 运行时模块 6dcd0000.clr.dll，证明引导器在运行时加载并执行了内嵌的托管程序集。

> **证据**：动态观测时间线：pid 3540 born，t0/t3 两次内存转储；模块 6dcd0000.clr.dll 被抽取
> 
> **来源**：`ev-000061`

### 10. 未推进安装与外联

`T1219` · 置信度 **中** · 动态

动态观察窗口内未出现 msiexec 子进程，MSI 安装日志与落盘清单为空；网络监控日志中亦无来自该样本进程的 DNS/TCP 记录，relay 会话未建立，说明安装流程在无交互客体中未走完，C2 通道未获运行时验证。

> **证据**：网络监控日志仅含系统进程流量；msi_files.json 为空；timeline 22:20:01–22:22:00 无新进程
> 
> **来源**：`ev-000061`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `instance-lwmknd-relay[.]screenconnect[.]com` | 443 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%ProgramFiles%\ScreenConnect Client (260a7850ff837e46)\ScreenConnect.ClientService.exe`
- `%ProgramFiles%\ScreenConnect Client (260a7850ff837e46)\ScreenConnect.WindowsClient.exe`
- `%ProgramFiles%\ScreenConnect Client (260a7850ff837e46)\ScreenConnect.WindowsCredentialProvider.dll`
- `%ProgramFiles%\ScreenConnect Client (260a7850ff837e46)\ScreenConnect.WindowsAuthenticationPackage.dll`
- `%ProgramFiles%\ScreenConnect Client (260a7850ff837e46)\system.config`

**注册表**

- `HKLM\SYSTEM\CurrentControlSet\Services\ScreenConnect Client (260a7850ff837e46)`
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (260a7850ff837e46)`
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages (追加 ScreenConnect.WindowsAuthenticationPackage.dll)`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-8385-DCD77FB81F24}`
- `HKCR\CLSID\{6FF59A85-BC37-4CD4-8385-DCD77FB81F24}\InprocServer32 = ...\ScreenConnect.WindowsCredentialProvider.dll`
- `HKCR\sc-260a7850ff837e46 (URL Protocol)`
- `HKCR\sc-260a7850ff837e46\shell\open\command = "...\ScreenConnect.WindowsClient.exe" "%1"`

**服务**

- `ScreenConnect Client (260a7850ff837e46) — StartType=2(auto)，ServiceType=16(own process)，命令行含 relay 启动参数`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `instance-lwmknd-relay[.]screenconnect[.]com` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `c2_uri` | `?e=Access&y=Guest&h=instance-lwmknd-relay[.]screenconnect[.]com&p=443` | 是 | 静态 |
| `campaign_id` | `instance lwmknd（Client 实例标识 260a7850ff837e46）` | 否 | 静态 |
| `install_path` | `%ProgramFiles%\ScreenConnect Client (260a7850ff837e46)` | 是 | 静态 |
| `service_name` | `ScreenConnect Client (260a7850ff837e46)` | 是 | 静态 |
| `url_scheme` | `sc-260a7850ff837e46` | 否 | 静态 |
| `product_code` | `{CAA6CA9E-5E51-E6BD-1D18-B9F00ABF33A7}` | 否 | 静态 |
| `credential_provider_clsid` | `{6FF59A85-BC37-4CD4-8385-DCD77FB81F24}` | 否 | 静态 |
| `encryption_algo` | `RSA-2048(RSA1) 签名/密钥封装，载荷为大小前缀封装 + 内嵌 MSI` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能因原始 EXE 与内嵌 MSI 均带 ConnectWise 有效签名就判为良性：签名只证明厂商来源，不能证明本安装包配置的自托管中继未经攻击者控制。
- 不能断言样本已窃取凭据或已记录键盘：凭据提供程序与 LSA 认证包的安装仅代表能力与持久化面，动态窗口内未观测到任何凭据外传。
- 不能把本样本归类为勒索软件或蠕虫：未发现文件加密、卷影删除或自我传播代码，其行为面是远程访问与持久化。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `5e1ff08fb7d66e02acacd97b46cd6bde531b95ca049ccd0e008cfa1c5c35ea29`） |

**局限与待验证**

1. 动态通道：样本在无交互客体中驻留但未派生子进程、未写安装日志、未发起外联；产物收集阶段超时，大体积内存转储未能回传，客体已回滚。
2. C2 仅有静态证据：relay 域名与端口从内嵌 MSI 属性中提取，网络监控/网络监控未捕获该域的 DNS 或 TLS 会话，因此 c2 标为 static 且 pending_dynamic_verify=true。
3. 未验证实际安装后的注册表/服务状态：样本未完成安装，未取得运行后 HKLM 服务项、LSA 认证包变更的运行时差分。
4. EntryPoint 的载荷校验/释放细节来自托管程序集方法名与导入 API 推断，未逐条反编译 IL。

## 证据索引

<details>
<summary>展开 7 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2, size=12842552 |
| `ev-000002` | scan.imphash | imphash=cd305a01d034d1a4ac62cbed1ae36be7 |
| `ev-000003` | scan.rich | Rich header 12 条工具链记录，richhash=a498773e40e07b36d0f4a2dab1633f09 |
| `ev-000007` | scan.entropy | .rsrc 熵 7.808，大小 12,759,040，提示资源内嵌压缩/加密载荷 |
| `ev-000059` | 字符串提取 | 提取 65,469 条 ASCII 与 4,954 条 UTF-16LE 字符串，含 ScreenConnect 资源标识 |
| `ev-000060` | evidence.record | 自写解析：提取 SC_PAYLOAD 内嵌 MSI，读出 relay/服务/注册表/CLSID 配置并验证 ConnectWise 签名 |
| `ev-000061` | evidence.record | 动态观测整理：pid 3540 启动并加载 CLR，未推进安装、未外联 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
