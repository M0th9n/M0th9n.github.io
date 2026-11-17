---
title: "恶意样本分析：ScreenConnect（PE · exe · 1fe8c02f）"
published: 2026-11-17
draft: false
description: "恶意（置信度高）：ScreenConnect · rat/backdoor · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["ScreenConnect", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ScreenConnect** · 置信度 **高**
> 
> 别名：ConnectWise Control、ScreenConnect Client、ScreenConnect RAT
> 
> 样本是经过厂商签名的 ScreenConnect 客户端安装器，但内嵌配置把中继指向 192.166.82[.]26:8041，并关闭托盘图标、连接气泡与受控横幅；真实动态中它创建了 LocalSystem 自启动服务、注册登录凭据提供程序和安全模式持久化项，安装后的客户端进程持续向该中继发起连接。这是把合法远程控制软件改配为未授权远控通道的典型用法，判定为恶意。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ScreenConnect** · 别名 ConnectWise Control、ScreenConnect Client、ScreenConnect RAT |
| 置信度 | **高** |
| 行为类 | rat · backdoor |
| 难度 | medium |
| 首次出现 | 2026-11-16 15:41:22 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/1fe8c02fd04ac95a923527f34466bd815fc6cb8ac100120f688b1893574b0296/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">释放并安装远控客户端</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">创建自启动系统服务</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">连接受控中继服务器</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">注册登录凭据提供程序</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1556</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">写入安全模式持久化</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1112</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `1fe8c02fd04ac95a923527f34466bd815fc6cb8ac100120f688b1893574b0296` |
| MD5 | _未记录_ |
| 大小 | 5,642,768 字节（5.4 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **2** 条静态可得、**7** 条经动态分析取得。

### 1. 释放并安装远控客户端

`T1219` · 置信度 **高** · 动态

样本是 WiX Burn 引导器，内嵌 5 个 .NET 组件与 ScreenConnect 安装包，释放后调用 msiexec /i 将 ScreenConnect 客户端 25.2.4.9229 安装到 Program Files (x86)。

> **证据**：资源 FILES/SCREENCONNECT.CORE、SCREENCONNECT.WINDOWS、SCREENCONNECT.WINDOWSINSTALLER；msiexec /i %TEMP%\ScreenConnect\25.2.4.9229\8622b665acfa39f0\ScreenConnect.msi；msiexec 创建安装目录文件
> 
> **来源**：`ev-000051` · `ev-000052` · `ref:5862c80c3d`

### 2. 创建自启动系统服务

`T1543.003` · 置信度 **高** · 动态

安装程序通过 services.exe 注册名为 ScreenConnect Client (8622b665acfa39f0) 的服务，以 LocalSystem 运行且启动类型为自动(Start=2)，ImagePath 直接携带中继参数。

> **证据**：HKLM\System\CurrentControlSet\Services\ScreenConnect Client (8622b665acfa39f0)\Start = DWORD 0x2；服务安装事件 7045；进程 pid 6616
> 
> **来源**：`ev-000052` · `ref:a8259de3a7`

### 3. 连接受控中继服务器

`T1219` · 置信度 **高** · 动态

安装后的 ScreenConnect.ClientService.exe 以 Guest 访问模式反复向 192.166.82[.]26:8041 发起 TCP 连接，携带实例标识与预置会话 ID，等待控制端接入。

> **证据**：网络监控日志：ScreenConnect.ClientService.exe (pid 6616) requested TCP 192.166.82[.]26:8041（多次）；命令行 ?e=Access&y=Guest&h=192.166.82[.]26&p=8041&s=50698413-e915-42dd-a257-fcd7670e0944
> 
> **来源**：`ev-000051` · `ev-000052`

### 4. 注册登录凭据提供程序

`T1556` · 置信度 **高** · 动态

msiexec 注册 Credential Provider CLSID {6FF59A85-BC37-4CD4-2F83-3B812406AD99}，其 InprocServer32 指向 ScreenConnect.WindowsCredentialProvider.dll，使远控组件可在登录界面加载。

> **证据**：HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-2F83-3B812406AD99} = ScreenConnect Client (8622b665acfa39f0) Credential Provider；HKCR\CLSID\{6FF59A85-...}\InprocServer32 = ...\ScreenConnect.WindowsCredentialProvider.dll
> 
> **来源**：`ev-000052`

### 5. 写入安全模式持久化

`T1112` · 置信度 **高** · 动态

安装程序在 HKLM\System\CurrentControlSet\Control\SafeBoot\Network 下写入同名服务项，使服务在带网络的安全模式启动时仍可加载。

> **证据**：SafeBoot\Network\ScreenConnect Client (8622b665acfa39f0)\(Default) = Service
> 
> **来源**：`ev-000052`

### 6. 注册sc协议快速上线

`T1112` · 置信度 **高** · 动态

创建 HKCR\sc-8622b665acfa39f0 协议处理器，shell\open\command 指向 ScreenConnect.WindowsClient.exe，使 sc-<实例> 链接可一键拉起客户端接入。

> **证据**：HKCR\sc-8622b665acfa39f0\shell\open\command\(Default) = "...\ScreenConnect.WindowsClient.exe"
> 
> **来源**：`ev-000052`

### 7. 隐藏托盘与提示横幅

`T1564` · 置信度 **高** · 静态

内嵌 app.config 将 ShowSystemTrayIcon、ShowBalloonOnConnect、Support/Access/ShouldShowUnderControlBanner 全部设为 false，并关闭无用户进程时的自动同意提示，使用户难以察觉远程控制。

> **证据**：文件偏移 0x54D3D4 的 app.config：ShowSystemTrayIcon=false；ShowBalloonOnConnect=false；ShouldShowUnderControlBanner=false；AutoConsentIfUserProcessNotRunning=false
> 
> **来源**：`ev-000051`

### 8. 部署后台与文件管理组件

`T1219` · 置信度 **高** · 动态

安装包同时落盘 WindowsBackstageShell.exe、WindowsFileManager.exe 与 WindowsAuthenticationPackage.dll，为远程后台命令、文件传输和凭据包注册提供能力。

> **证据**：msiexec 文件创建：Program Files (x86)\ScreenConnect Client (8622b665acfa39f0)\ScreenConnect.WindowsBackstageShell.exe / WindowsFileManager.exe / WindowsAuthenticationPackage.dll
> 
> **来源**：`ev-000052`

### 9. 滥用厂商代码签名

`T1553.002` · 置信度 **高** · 静态

安装包带有 ConnectWise, LLC 的有效 Authenticode 代码签名（DigiCert 签发），可借厂商信誉绕过基于签名的拦截；签名仅证明二进制来源，不代表配置的中继属于合法运维。

> **证据**：Authenticode 证书主体 CN=Connectwise, LLC，序列号 0xb9360051bccf66642998998d5ba97ce，有效期 2022-08-17 至 2025-08-15
> 
> **来源**：`ev-000051` · `ref:51c2f521d7`


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
| tcp | `192[.]166[.]82[.]26:8041` | 8041 | c2 | 动态 | 已观测 |

### 主机

**落地路径**

- `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)\`
- `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)\ScreenConnect.ClientService.exe`
- `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)\ScreenConnect.WindowsClient.exe`
- `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)\ScreenConnect.WindowsCredentialProvider.dll`
- `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)\ScreenConnect.WindowsBackstageShell.exe`
- `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)\ScreenConnect.WindowsFileManager.exe`
- `%TEMP%\ScreenConnect\25.2.4.9229\8622b665acfa39f0\`

**注册表**

- `HKLM\System\CurrentControlSet\Services\ScreenConnect Client (8622b665acfa39f0)`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-2F83-3B812406AD99}`
- `HKCR\CLSID\{6FF59A85-BC37-4CD4-2F83-3B812406AD99}\InprocServer32`
- `HKLM\System\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (8622b665acfa39f0)`
- `HKCR\sc-8622b665acfa39f0\shell\open\command`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{9A597075-529B-9FA0-6F02-0510504CA30D}`

**服务**

- `ScreenConnect Client (8622b665acfa39f0)`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `192[.]166[.]82[.]26` | 是 | 静态 |
| `c2_port` | `8041` | 是 | 静态 |
| `c2_uri` | `?e=Access&y=Guest` | 是 | 静态 |
| `instance_id` | `8622b665acfa39f0` | 是 | 静态 |
| `session_id` | `50698413-e915-42dd-a257-fcd7670e0944` | 否 | 静态 |
| `campaign_id` | `JDOOODD` | 否 | 静态 |
| `install_path` | `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)` | 是 | 静态 |
| `service_name` | `ScreenConnect Client (8622b665acfa39f0)` | 是 | 静态 |
| `service_account` | `LocalSystem` | 是 | 静态 |
| `ui_stealth` | `ShowSystemTrayIcon=false; ShowBalloonOnConnect=false; SupportShowUnderControlBanner=false; AccessShowUnderControlBanner=false; ShouldShowUnderControlBanner=false; AutoConsentIfUserProcessNotRunning=false` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能判定为勒索或窃密木马：未观察到文件加密、浏览器凭据导出或数据回传内容，动态阶段仅捕获到中继连接尝试。
- 不能因为二进制带有有效厂商签名就认定其良性：签名只证明安装包由 ConnectWise 签发，中继地址与隐藏界面配置指向第三方控制端。
- 不能声称已成功建立远程控制会话：沙箱内只记录到 TCP 连接尝试，没有捕获到中继认证或会话流量。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 中继仅在沙箱内记录到 TCP 连接尝试，未取得完整认证/会话流量，C2 按静态恢复标记并保留待动态确认。
2. 未从磁盘提取到安装后的客户端配置文件明文；中继、实例与会话参数来自 Burn 内嵌配置、服务 ImagePath 和进程命令行。
3. 未观测到键盘鼠标控制、文件传输或后台 shell 等实际远程操作，因为中继端未响应。
4. 未发现计划任务或 Run 键持久化，也未观察到 Defender 排除项写入。
5. 签名证书有效期截至 2025-08-15，离线环境未校验证书链撤销状态。

## 证据索引

<details>
<summary>展开 12 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:3f47b0361f` | 样本分诊 | PE 分诊：5 段、.rsrc 熵 7.45、导入 3 个 DLL、无加壳信号 |
| `ref:5862c80c3d` | PE 结构解析 | PE32 GUI，入口 RVA 0x14AD，资源目录 5.47MB，签名表 95KB |
| `ref:f74413c1a4` | 导入表解析 | 导入 mscoree CorBindToRuntimeEx、KERNEL32 资源/文件 API、OLEAUT32 |
| `ref:d4c7fd0b2e` | 字符串提取 | 字符串 20857 条，命中 WiX/ScreenConnect 安装组件名 |
| `ref:a8259de3a7` | 动态产物收集 | 真实动态产物包：遥测、网络监控、内存转储 |
| `ev-000051` | evidence.record | 静态提取：内嵌 Burn 配置、app.config 隐藏项、签名主体 |
| `ev-000052` | evidence.record | 动态遥测：服务、凭据提供程序、安全模式、协议处理器、中继连接 |
| `ref:36284d613d` | 内存转储 | ClientService.exe 内存转储 |
| `ref:681a976c1d` | 内存转储 | WindowsClient.exe 内存转储 |
| `c2_evidence:1fe8c02f` | 连接证据提取 | 动态网络监控记录到 4 次到 192.166.82[.]26:8041 的连接尝试；未捕获完整会话 |
| `telemetry:1fe8c02f` | 动态遥测 | 动态遥测记录到：新增服务 1 个（ScreenConnect Client (8622b665acfa39f0)）；监控组件 注册表事件 16 条；监控组件 进程/文件事件 116 条；ETW 短命进程事件 1 条；系统服务事件 5 条；已过滤工具/系统噪声 43 条 |
| `etw:1fe8c02f:7192` | 进程事件监控 | 短命进程事件：1fe8c02fd04ac95a923527f34466bd815fc6cb8ac100120f688b1893574b0296.exe（pid 7192；MD5=D442BCBCE7DBAB15930408261452A21D,SHA256=1FE8C02FD04AC95A923527F34466BD815FC6CB8AC100120F688B1893574B0296,IMPHASH=9771EE6344923FA220489AB01239BDFD） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
