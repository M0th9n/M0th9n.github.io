---
title: "恶意样本分析：ScreenConnect（other · msi · ded99954）"
published: 2026-11-22
draft: false
description: "恶意（置信度高）：ScreenConnect · rat/backdoor · 难度 medium · 纯静态分析"
tags: ["ScreenConnect", "rat", "backdoor", "MSI"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ScreenConnect** · 置信度 **高**
> 
> 别名：ConnectWise Control、ConnectWise ScreenConnect、ScreenConnect Client、ScreenConnect RAT
> 
> 该 MSI 由 ScreenConnect 官方工具链构建并使用 ConnectWise 签名的组件，但其服务启动参数被定制为 ?h=188.253.28[.]5&p=8041，且 app.config 关闭托盘图标、连接通知与受控提示；安装过程同时注册开机自启服务、LSA 认证包、凭据提供程序、SafeBoot 网络项与自定义 URL 协议。该组合符合将合法远程控制工具武器化为隐蔽后门的用法，故判为恶意远控/后门。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ScreenConnect** · 别名 ConnectWise Control、ConnectWise ScreenConnect、ScreenConnect Client、ScreenConnect RAT |
| 置信度 | **高** |
| 行为类 | rat · backdoor |
| 难度 | medium |
| 首次出现 | 2026-11-20 01:57:28 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ded99954032a139212f19cc66fd170ea5266e5301b95abf4a4139a57f51a88ba/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">注册自启远控服务</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">外联指定中继主机</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">关闭托盘与连接通知</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.008</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">注册LSA认证包</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">注册凭据提供程序</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1556</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ded99954032a139212f19cc66fd170ea5266e5301b95abf4a4139a57f51a88ba` |
| MD5 | _未记录_ |
| 大小 | 13,471,744 字节（12.8 MB） |
| 类型 | other · `msi` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 注册自启远控服务

`T1543.003` · 置信度 **高** · 静态

安装时创建名为 'ScreenConnect Client (9101ab61b8839c58)'、显示名 'Remote Control' 的 Windows 服务，启动参数为 ?h=188.253.28[.]5&p=8041，并配置失败自动重启，实现开机自启与常驻。

> **证据**：MSI ServiceInstall/ServiceControl/ServiceConfig 表；ServiceExeWithService -> ScreenConnect.ClientService.exe
> 
> **来源**：`ev-000037` · `ev-000029`

### 2. 外联指定中继主机

`T1071.001` · 置信度 **高** · 静态

服务按 '?h=188.253.28[.]5&p=8041' 参数主动连接 188.253.28[.]5:8041，并按 k 参数中的 RSA1 会话 envelope 协商远程控制通道。

> **证据**：system.config ClientLaunchParametersConstraint；MSI Property SERVICE_CLIENT_LAUNCH_PARAMETERS
> 
> **来源**：`ev-000039` · `ev-000037`

### 3. 关闭托盘与连接通知

`T1564.008` · 置信度 **高** · 静态

app.config 将 ShowSystemTrayIcon、ShowConnectedNotification、SupportShowUnderControlBanner、AccessShowUnderControlBanner 全部设为 false，隐藏远控会话的可见提示。

> **证据**：extracted/app.config 中 ScreenConnect.SystemSettings 各 setting value=false
> 
> **来源**：`ev-000039`

### 4. 注册LSA认证包

`T1547.002` · 置信度 **高** · 静态

向 HKLM\SYSTEM\CurrentControlSet\Control\Lsa 的 Authentication Packages 追加 ScreenConnect.WindowsAuthenticationPackage.dll，扩展系统登录认证流程。

> **证据**：Registry 表 regB33BA5DF... Root=2(HKLM) Key='SYSTEM\CurrentControlSet\Control\Lsa' Name='Authentication Packages'
> 
> **来源**：`ev-000037` · `ev-000038`

### 5. 注册凭据提供程序

`T1556` · 置信度 **高** · 静态

在 HKLM 的 Credential Providers 与 HKCR\CLSID 下注册 {6FF59A85-BC37-4CD4-D1CE-1A3BA4B0092C}，InprocServer32 指向 ScreenConnect.WindowsCredentialProvider.dll，使其可参与 Windows 登录凭据处理。

> **证据**：Registry 表 regCC376884...(Credential Providers) / regA0D3A6DD...(CLSID InprocServer32)
> 
> **来源**：`ev-000037`

### 6. 注册自定义URL协议

`T1112` · 置信度 **高** · 静态

注册 HKCR\sc-9101ab61b8839c58 协议，shell\open\command 指向 ScreenConnect.WindowsClient.exe "%1"，可经链接或参数拉起客户端。

> **证据**：Registry 表 reg239C9CCD/regED314AE6，Root=0(HKCR)，Key='[URL_SCHEME]\shell\open\command'
> 
> **来源**：`ev-000037`

### 7. 写入SafeBoot网络项

`T1112` · 置信度 **高** · 静态

写入 HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\<服务名> = 'Service'，使远控服务在带网络的安全模式下仍可启动。

> **证据**：Registry 表 reg3831C0C3... Root=2(HKLM) Key='System\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME]'
> 
> **来源**：`ev-000037`

### 8. 投放远控组件套件

`T1219` · 置信度 **高** · 静态

从内嵌 CAB 解出并安装 20 个 ScreenConnect 组件（WindowsClient、ClientService、BackstageShell、FileManager、CredentialProvider、AuthenticationPackage 等），提供交互式桌面控制、后台命令执行与文件传输能力。

> **证据**：MSI File 表 20 项；Default.cab 解包得到同名文件；WindowsClient.exe sha256=da7697...；ServiceExeWithService sha256=8c7e1f...
> 
> **来源**：`ev-000038` · `ev-000023` · `ev-000029`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `188.253.28[.]5` | 8041 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)\ScreenConnect.ClientService.exe`
- `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)\ScreenConnect.WindowsClient.exe`
- `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)\ScreenConnect.WindowsBackstageShell.exe`
- `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)\ScreenConnect.WindowsFileManager.exe`
- `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)\ScreenConnect.WindowsCredentialProvider.dll`
- `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)\ScreenConnect.WindowsAuthenticationPackage.dll`

**注册表**

- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (9101ab61b8839c58) = Service`
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages += ScreenConnect.WindowsAuthenticationPackage.dll`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-D1CE-1A3BA4B0092C}`
- `HKCR\CLSID\{6FF59A85-BC37-4CD4-D1CE-1A3BA4B0092C}\InprocServer32 = ScreenConnect.WindowsCredentialProvider.dll`
- `HKCR\sc-9101ab61b8839c58\shell\open\command = "ScreenConnect.WindowsClient.exe" "%1"`

**服务**

- `ScreenConnect Client (9101ab61b8839c58)`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `188.253.28[.]5` | 是 | 静态 |
| `c2_port` | `8041` | 是 | 静态 |
| `service_name` | `ScreenConnect Client (9101ab61b8839c58)` | 是 | 静态 |
| `service_display_name` | `Remote Control` | 否 | 静态 |
| `install_path` | `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)` | 是 | 静态 |
| `url_scheme` | `sc-9101ab61b8839c58` | 否 | 静态 |
| `credential_provider_clsid` | `{6FF59A85-BC37-4CD4-D1CE-1A3BA4B0092C}` | 否 | 静态 |
| `product_version` | `25.3.4.9288` | 否 | 静态 |
| `c2_session_envelope` | `k=BgIAAACkAABSU0Ex...（276 字节 RSA1 会话 envelope，服务端 RSA 公钥封装）` | 否 | 静态 |
| `encryption_algo` | `RSA session envelope (tag 'RSA1')` | 否 | 静态 |
| `stealth_ui` | `ShowSystemTrayIcon=false; ShowConnectedNotification=false; SupportShowUnderControlBanner=false` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能因组件由 ConnectWise 合法签名就判为干净：签名只说明组件来源合法，安装包已被重新配置为连接 188.253.28[.]5:8041 的隐蔽远控。
- 未发现勒索加密、批量窃取浏览器凭据或蠕虫式横向传播的证据，不应归类为 ransomware、stealer 或 botnet。
- 该 MSI 是完整安装包而非投递器：内嵌 CustomActionLibrary/WixCA 为 ScreenConnect/WiX 安装器自定义动作 DLL，不是独立的下一阶段母体，不应按 dropper 投放链描述。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 是 |

**局限与待验证**

1. 纯静态分析：未执行 MSI 或任何组件，C2 与行为均来自安装表、配置文件与签名/哈希证据，recoverability=static，pending_dynamic_verify=true。
2. k 参数为服务端 RSA 公钥封装的 276 字节会话 envelope（tag 'RSA1'），无私钥无法解出中继侧会话标识或活动会话；仅能从明文 h/p 得到中继地址与端口。
3. 该格式未启用隔离动态通道，未实际观测外联、屏幕控制、凭据捕获、服务启动或 LSA/凭据提供程序生效。
4. 离线 Authenticode 校验中部分签名链因缺少在线吊销/时间戳信息返回未知状态；托管 DLL 未签名属该发行版常态，不等同于文件被篡改。
5. 无法确认 188.253.28[.]5:8041 所有者的真实意图，仅依据本安装包的配置将其作为远控中继列出。

## 证据索引

<details>
<summary>展开 7 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000022` | 字符串提取 | MSI 字符串抽取，命中 ScreenConnect.* 组件文件名与安装标识 |
| `ev-000023` | 样本分诊 | ScreenConnect.WindowsClient.exe 哈希/分段/加壳评分 |
| `ev-000029` | 样本分诊 | ServiceExeWithService 哈希/导入/Rich header |
| `ev-000037` | evidence.record | MSI 数据库表格导出：C2 启动参数、服务、注册表、安装路径、产品信息 |
| `ev-000038` | evidence.record | MSI 内嵌 CAB 解包与 20 个组件哈希、Authenticode 签名状态 |
| `ev-000039` | evidence.record | system.config/app.config 连接参数与隐蔽性开关、k 会话 envelope 结构 |
| `ev-000040` | evidence.record | 内嵌自定义动作 DLL 版本资源：ScreenConnect.InstallerActions 与 WiXCA |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
