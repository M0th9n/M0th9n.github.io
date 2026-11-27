---
title: "恶意样本分析：ScreenConnect（other · msi · a39c509e）"
published: 2026-11-26
draft: false
description: "恶意（置信度高）：ScreenConnect · rat/backdoor · 难度 medium · 纯静态分析"
tags: ["ScreenConnect", "rat", "backdoor", "MSI"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ScreenConnect** · 置信度 **高**
> 
> 别名：ConnectWise Control、ScreenConnect RAT、ScreenConnect Client
> 
> 该文件是经 ConnectWise, LLC 有效签名的 ScreenConnect 客户端安装包（未被篡改），但被预置为以 LocalSystem 自动启动服务、以 Guest 身份连接固定中继 instance-yu0lau-relay[.]screenconnect[.]com:443，并同时注册 LSA 认证包、凭据提供程序、带网络安全模式持久化键及 Backstage Shell/File Manager 组件。合法签名远控组件加固定中继与高权限驻留的组合，是典型的 RMM 滥用型远控投递，具备持久化远程控制、凭据交互与文件传输能力。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ScreenConnect** · 别名 ConnectWise Control、ScreenConnect RAT、ScreenConnect Client |
| 置信度 | **高** |
| 行为类 | rat · backdoor |
| 难度 | medium |
| 首次出现 | 2026-11-24 00:44:43 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/a39c509eef5c8de1438b7cbe0933e17113cca572a6f64c6bf8384986353173b3/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">安装自启动服务</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">连接指定中继节点</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">挂接LSA认证包</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1556</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">注册凭据提供程序</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1556</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">写入安全模式持久化</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1112</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `a39c509eef5c8de1438b7cbe0933e17113cca572a6f64c6bf8384986353173b3` |
| MD5 | _未记录_ |
| 大小 | 10,260,480 字节（9.8 MB） |
| 类型 | other · `msi` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 安装自启动服务

`T1543.003` · 置信度 **高** · 静态

以 LocalSystem 身份安装名为 ScreenConnect Client (f03edb1838cd757d) 的自动启动服务（ServiceType=16、StartType=2、ErrorControl=1，StartName 为空即 LocalSystem），服务启动参数直接使用预置的远端连接 URI。

> **证据**：MSI ServiceInstall 表 Name=[SERVICE_NAME], StartType=2, StartName 空; ServiceControl Event=163; Arguments="[SERVICE_CLIENT_LAUNCH_PARAMETERS]"
> 
> **来源**：`ev-000066` · `ev-000065`

### 2. 连接指定中继节点

`T1219` · 置信度 **高** · 静态

服务以访客身份（?e=Access&y=Guest）连接 instance-yu0lau-relay[.]screenconnect[.]com:443 的 ScreenConnect 中继，并携带固定 2048 位 RSA 公钥建立会话，使操作者无需目标端确认即可发起远控连接。

> **证据**：MSI Property SERVICE_CLIENT_LAUNCH_PARAMETERS @off≈3596288; 内嵌 system.config 的 ClientLaunchParametersConstraint @off=410
> 
> **来源**：`ev-000050` · `ev-000065`

### 3. 挂接LSA认证包

`T1556` · 置信度 **高** · 静态

把 ScreenConnect.WindowsAuthenticationPackage.dll 追加到 HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages，使该认证包随 LSA 加载，可在登录/解锁流程中介入凭据交互。

> **证据**：Registry 表 reg27BFB9E3...: Root=2(HKLM), Key=SYSTEM\CurrentControlSet\Control\Lsa, Name=Authentication Packages, Value=[~][#ScreenConnect.WindowsAuthenticationPackage.dll]
> 
> **来源**：`ev-000066` · `ev-000065`

### 4. 注册凭据提供程序

`T1556` · 置信度 **高** · 静态

注册 COM CLSID {6FF59A85-BC37-4CD4-410E-264908C38164}，InprocServer32 指向 ScreenConnect.WindowsCredentialProvider.dll，并写入 Credential Providers 键（x64 与 ARM64 两套），为远程会话提供自定义登录与凭据交互界面。

> **证据**：Registry reg484EC3... InprocServer32=[#ScreenConnect.WindowsCredentialProvider.dll]; reg20D6DF... Credential Providers\{CLSID}; 内嵌 DLL 字符串含 ProcessCredentialProviderMessage/EnsureStoredCredentialsState
> 
> **来源**：`ev-000066` · `ev-000065` · `ev-000023`

### 5. 写入安全模式持久化

`T1112` · 置信度 **高** · 静态

在 HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network 下创建以服务名为名的键并设值为 Service，使该服务在带网络的安全模式下仍会启动，提升持久化强度。

> **证据**：Registry 表 reg3831C0C3...: Key=System\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME], Value=Service
> 
> **来源**：`ev-000066` · `ev-000065`

### 6. 部署远程Shell组件

`T1059` · 置信度 **中** · 静态

安装 ScreenConnect.WindowsBackstageShell.exe（Backstage 后台 Shell），该官方组件为远端操作者提供交互式命令执行通道。

> **证据**：File/Component 表 BackstageShellFiles -> ScreenConnect.WindowsBackstageShell.exe (73272 字节, sha256 853ad96a...); MSI 字符串含 BackstageShellFiles 组件名
> 
> **来源**：`ev-000065` · `ev-000067`

### 7. 部署文件管理器

`T1105` · 置信度 **中** · 静态

安装 ScreenConnect.WindowsFileManager.exe，为远端操作者提供文件浏览、上传/下载与远程执行入口。

> **证据**：File/Component 表 FileManagerFiles -> ScreenConnect.WindowsFileManager.exe (93752 字节, sha256 022f9645...); MSI 字符串含 FileManagerFiles 组件名
> 
> **来源**：`ev-000065` · `ev-000067`

### 8. 服务失败自动重启

`T1543.003` · 置信度 **高** · 静态

通过 ServiceConfig 把服务失败恢复动作配置为 restart/restart/none，服务进程被终止后由系统自动拉起，维持驻留。

> **证据**：ServiceConfig 表: FirstFailureActionType=restart, SecondFailureActionType=restart, ThirdFailureActionType=none
> 
> **来源**：`ev-000066` · `ev-000065`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `instance-yu0lau-relay[.]screenconnect[.]com` | 443 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%ProgramFiles%\ScreenConnect Client (f03edb1838cd757d)\`
- `%ProgramFiles%\ScreenConnect Client (f03edb1838cd757d)\ScreenConnect.ClientService.exe`
- `%ProgramFiles%\ScreenConnect Client (f03edb1838cd757d)\ScreenConnect.WindowsClient.exe`
- `%ProgramFiles%\ScreenConnect Client (f03edb1838cd757d)\ScreenConnect.WindowsCredentialProvider.dll`
- `%ProgramFiles%\ScreenConnect Client (f03edb1838cd757d)\ScreenConnect.WindowsAuthenticationPackage.dll`

**注册表**

- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa (Authentication Packages += ScreenConnect.WindowsAuthenticationPackage.dll)`
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (f03edb1838cd757d)`
- `HKCR\CLSID\{6FF59A85-BC37-4CD4-410E-264908C38164}\InprocServer32`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-410E-264908C38164}`
- `HKCR\sc-f03edb1838cd757d`

**服务**

- `ScreenConnect Client (f03edb1838cd757d)`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `instance-yu0lau-relay[.]screenconnect[.]com` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `c2_uri` | `?e=Access&y=Guest&h=instance-yu0lau-relay[.]screenconnect[.]com&p=443&k=<RSA-2048 public key>&t=WA` | 是 | 静态 |
| `service_name` | `ScreenConnect Client (f03edb1838cd757d)` | 是 | 静态 |
| `install_path` | `%ProgramFiles%\ScreenConnect Client (f03edb1838cd757d)` | 是 | 静态 |
| `service_account` | `LocalSystem` | 否 | 静态 |
| `service_start_type` | `auto` | 是 | 静态 |
| `encryption_algo` | `RSA-2048 (CALG_RSA_SIGN; client public key carried in launch URI)` | 否 | 静态 |
| `instance_id` | `instance-yu0lau` | 否 | 静态 |
| `client_tag` | `f03edb1838cd757d` | 否 | 静态 |
| `product_version` | `26.7.9.9792` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭内嵌 RSA 公钥或 k= 参数就断言样本使用自定义加密/窃密模块；该公钥是 ScreenConnect 客户端连接中继用的标准会话公钥。
- 不能因为 MSI 与内嵌 PE 具有 ConnectWise 有效签名就判为完全良性；风险来自合法签名的远控组件被配置为连接指定中继并高权限驻留。
- 不能声称已在真实主机引爆或观测到外联/会话建立；本次为纯静态分析，C2 可达性未验证。
- 不能把 BackstageShell.exe / FileManager.exe 当作独立恶意载荷；它们是 ScreenConnect 官方功能组件。
- 不能断言 instance-yu0lau 中继一定归攻击者所有；其归属需网络侧或租户侧情报确认。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次为纯静态分析（该格式无隔离动态通道），未执行安装，也未验证到中继的连通性或会话建立；C2 条目标记为 static 且 pending_dynamic_verify=true。
2. 服务创建、注册表写入、LSA 认证包加载、安全模式持久化等均来自 MSI 表声明的安装逻辑，未在真实主机上观测到落地效果。
3. instance-yu0lau 中继的归属与用途无法静态确认，需网络侧/租户侧情报佐证。
4. CAB 中 1 个 LZX 压缩文件夹（ServiceExeWithService / ServiceExeWithoutService，各 95288 字节）未能完整解出；同类组件 ScreenConnect.ClientService.dll 已提取并通过签名与字符串分析。
5. MSI 复合文档中共 2504 个 4096 字节扇区，仅 914 个被流引用；偏移 3600384 与 5816320 各有一份未被引用的旧 Default.cab 副本，_StringData 中也残留旧 ProductCode，属构建残留，未作为恶意功能依据。
6. 未取得 C2 会话、注册表/服务落地、进程注入等运行时行为；动态通道未启用（reproduced=false）。

## 证据索引

<details>
<summary>展开 7 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000050` | 字符串提取 | 内嵌 system.config 中提取到 ClientLaunchParametersConstraint，含 instance-yu0lau-relay[.]screenconnect[.]com:443 与 RSA 公钥参数（off=410） |
| `ev-000065` | 字符串提取 | MSI 长字符串抽取，命中完整 Property/Registry/ServiceInstall/File 数据块，含 SERVICE_CLIENT_LAUNCH_PARAMETERS、Lsa\Authentication Packages、SafeBoot\Network、Credential Providers、服务名与 18 个内嵌文件名（off≈3596288） |
| `ev-000066` | evidence.record | 只读解析 MSI 数据库表：Property/CustomAction/ServiceInstall/ServiceControl/ServiceConfig/Registry/Media/File/Component/Feature/InstallExecuteSequence/LaunchCondition/Upgrade 的完整行值 |
| `ev-000067` | evidence.record | 提取内嵌 Default.cab 并解出 18 个文件、计算 sha256；校验 MSI 与主要 PE 的 Authenticode 签名（CN=ConnectWise, LLC, Valid）；解析 RSA-2048 公钥；统计 CFB 扇区占用与未引用 cab 副本 |
| `ev-000023` | 字符串提取 | ScreenConnect.ClientService.dll 字符串：ProcessCredentialProviderMessage、EnsureStoredCredentialsState、MaintainEphemeralUsers、TryStart/CreateProcessAsUser 等方法名，支撑凭据提供程序与服务端进程管理能力 |
| `ev-000049` | 字符串提取 | ScreenConnect.WindowsClient.exe 字符串：屏幕采集/DXGI、剪贴板、远程会话与控制面板相关方法名，支撑远控客户端性质 |
| `ev-000045` | 字符串提取 | MSI 摘要字符串统计（ascii 780 / utf16le 350），并显示 WiX Toolset 3.11 构建标识与 ScreenConnect.InstallerActions 自定义动作名 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
