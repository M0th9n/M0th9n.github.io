---
title: "恶意样本分析：Action1 Agent（other · msi · c5f41fff）"
published: 2026-11-19
draft: false
description: "灰色/PUA（置信度高）：Action1 Agent · implant · 难度 medium · 纯静态分析"
tags: ["Action1 Agent", "implant", "MSI"]
category: "恶意样本日报"
lang: "zh"
---

> [!CAUTION]
> **判定：灰色/PUA** · 家族 **Action1 Agent** · 置信度 **高**
> 
> 别名：Action1、Action1 RMM、A1Agent
> 
> 样本是 Action1 Corporation 官方签发、数字签名有效的远程管理(RMM)Agent 安装包:MSI 产品信息、内嵌 action1_agent.exe 版本信息与签名主体一致,未发现篡改、窃密、勒索或破坏代码。它安装为 LocalSystem 自启动服务并回连厂商云,具备远程命令执行、远程桌面、软件分发与重启关机能力,属于可被滥用的双用途远程管理工具,按风险软件/PUA 归类。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Action1 Agent** · 别名 Action1、Action1 RMM、A1Agent |
| 置信度 | **高** |
| 行为类 | implant |
| 难度 | medium |
| 首次出现 | 2026-11-17 20:00:06 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/c5f41fff34f1e18dad19bff448bdb7952d7886908c292fe570b5695c5e91850b/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">安装自启动系统服务</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">写入租户密钥配置</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1112</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">开启崩溃转储收集</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1112</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">HTTPS 回连管理云</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">嵌入证书双向认证</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1573.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `c5f41fff34f1e18dad19bff448bdb7952d7886908c292fe570b5695c5e91850b` |
| MD5 | _未记录_ |
| 大小 | 7,139,328 字节（6.8 MB） |
| 类型 | other · `msi` |

## 行为分析

共 **10** 条行为，每条都挂了证据，且全部静态可得。

### 1. 安装自启动系统服务

`T1543.003` · 置信度 **高** · 静态

MSI 以 LocalSystem 账户创建自启动服务 A1Agent,指向 action1_agent.exe,并在安装后启动该服务。

> **证据**：ServiceInstall: A1Agent/action1_agent.exe/LocalSystem/启动类型 16(auto); ServiceControl 启动服务; IAT CreateServiceW(7303440)、StartServiceCtrlDispatcherW(7303448)
> 
> **来源**：`ev-000018`

### 2. 写入租户密钥配置

`T1112` · 置信度 **高** · 静态

安装时向 HKLM\Software\Action1\Agent 写入 RSA 私钥、X.509 客户端证书、客户 ID、安装目录与 MSI 产品码。

> **证据**：Registry 表: HKLM\Software\Action1\Agent 下 PrivateKey|Certificate|CustomerId|MSI|INSTALLDIR; Property A1_PRIVATEKEY/A1_CERTIFICATE/A1_CUSTOMERID
> 
> **来源**：`ev-000018` · `ev-000020`

### 3. 开启崩溃转储收集

`T1112` · 置信度 **高** · 静态

为 action1_agent.exe、action1_update.exe、action1_remote.exe 配置 Windows 错误报告本地转储目录、转储类型与数量。

> **证据**：Registry 表: HKLM\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\<exe> 下 DumpFolder=[INSTALLDIR]CrashDumps、DumpType=2、DumpCount=2
> 
> **来源**：`ev-000018`

### 4. HTTPS 回连管理云

`T1071.001` · 置信度 **高** · 静态

通过 WinHTTP 以 HTTPS 连接厂商管理端 server[.]action1[.]com 与中继 relay[.]action1[.]com,并按内置 URI 模板上传/下载文件。

> **证据**：IAT WinHttpOpen(7304844)、WinHttpConnect(7304840)、WinHttpOpenRequest(7304832)、WinHttpSendRequest(7304848); 字符串 server[.]action1[.]com@0x79ebc8、relay[.]action1[.]com@0x7d5eec
> 
> **来源**：`ref:ed84731c01` · `ev-000020`

### 5. 嵌入证书双向认证

`T1573.002` · 置信度 **高** · 静态

使用安装包内嵌的 X.509 证书与 RSA 私钥对管理端做客户端证书认证,并结合系统证书库 API 建立加密通道。

> **证据**：MSI Property A1_CERTIFICATE(CN=ca[.]app[.]action1[.]com)+A1_PRIVATEKEY; IAT CertOpenStore(7303464)、CertFindCertificateInStore(7303476); 密码学常量命中 AES/SHA-256
> 
> **来源**：`ev-000018` · `ev-000019` · `ev-000010`

### 6. 远程下发命令执行

`T1059.001` · 置信度 **中** · 静态

内置 RunPowershell/runaction 命令通道,服务端可下发命令,以目标会话用户或 LocalSystem 权限创建进程执行。

> **证据**：UTF-16 字符串 RunPowershell、runaction、command、powershell.exe; IAT CreateProcessAsUserW(7303368)、WTSQueryUserToken(7305080)、LogonUserW(7303356)、CreateProcessW(7304012)
> 
> **来源**：`ev-000020` · `ref:ed84731c01`

### 7. 下载并更新载荷

`T1105` · 置信度 **高** · 静态

按服务端下发的 URI 从内置下载路径或 S3 包仓库获取文件,并通过 MSI 事务接口执行安装/升级。

> **证据**：字符串 hxxps://{}/builtin/{}_builtin/file.dat{}、/customers/custom/{}/{}/file.dat{}、a1-backend-packages[.]s3[.]amazonaws[.]com; IAT CreateTransaction(7305160)、CommitTransaction(7305156); 附带 7z.dll 解包
> 
> **来源**：`ev-000020` · `ref:ed84731c01`

### 8. 开启远程桌面控制

`T1219` · 置信度 **高** · 静态

随包投放 TightVNC 派生的 action1_remote.exe,可截取屏幕、注入键鼠输入、访问剪贴板并以用户令牌创建进程。

> **证据**：action1_remote.exe 版本信息 FileDescription=Remote Server; 字符串 TightVNC@0xcee21; IAT BitBlt(819344)、GetDIBits(819380)、SendInput(820236)、SetWindowsHookExW(820300)、CreateProcessAsUserW(819232)
> 
> **来源**：`ref:aa817ab1a6` · `ev-000020`

### 9. 枚举主机与会话

`T1082;T1057;T1018` · 置信度 **高** · 静态

枚举进程、登录会话、网络共享与计算机名,并采集 agent.guid、system.id、disk.serial 等设备指纹上报。

> **证据**：IAT Process32FirstW(7303716)、WTSEnumerateSessionsW(7305084)、NetShareGetInfo(7304460)、GetComputerNameExW(7303548); 配置键 agent.guid/system.id/disk.serial
> 
> **来源**：`ref:ed84731c01` · `ev-000020`

### 10. 远程重启或关机

`T1529` · 置信度 **高** · 静态

提供远程重启/关机与取消重启指令,调用系统关机接口并维护重启倒计时状态。

> **证据**：IAT InitiateSystemShutdownExW(7303296)、AbortSystemShutdownW(7303300); 字符串 reboot、shutdown、cancelreboot、reboot_countdown
> 
> **来源**：`ref:ed84731c01` · `ev-000020`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://server[.]action1[.]com/` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://relay[.]action1[.]com/` | 443 | relay | 静态 | ⏳ 未观测 |
| http | `hxxps://a1-backend-packages[.]s3[.]amazonaws[.]com/` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `Global\Action1_AgentConnectedToServerEvent`
- `Action1_InstalledSoftwareMutex`

**落地路径**

- `%WINDIR%\Action1\action1_agent.exe`
- `%WINDIR%\Action1\action1_remote.exe`
- `%WINDIR%\Action1\7z.dll`
- `%WINDIR%\Action1\CrashDumps`

**注册表**

- `HKLM\Software\Action1\Agent\PrivateKey`
- `HKLM\Software\Action1\Agent\Certificate`
- `HKLM\Software\Action1\Agent\CustomerId`
- `HKLM\Software\Action1\Agent\MSI`
- `HKLM\Software\Action1\Agent\INSTALLDIR`
- `HKLM\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\action1_agent.exe`

**服务**

- `A1Agent (Action1 Agent)`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `server[.]action1[.]com, relay[.]action1[.]com` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `c2_uri` | `/builtin/{}/builtin/file.dat{}, /customers/custom/{}/{}/file.dat{}` | 是 | 静态 |
| `customer_id` | `f314fe20-d754-11f1-aa9a-777ddf71d172` | 是 | 静态 |
| `install_path` | `%WINDIR%\Action1` | 是 | 静态 |
| `service_name` | `A1Agent` | 是 | 静态 |
| `encryption_algo` | `TLS/OpenSSL; AES/SHA-256/RC4 primitives present` | 否 | 静态 |
| `client_certificate` | `embedded X.509, CN=ca[.]app[.]action1[.]com` | 是 | 静态 |
| `private_key` | `embedded RSA private key (MSI Property A1_PRIVATEKEY)` | 是 | 静态 |
| `mutex` | `Global\Action1_AgentConnectedToServerEvent` | 否 | 静态 |
| `proxy_config` | `agent.proxy.hostname/port/username/password; agent.use.proxy` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭远程命令/远程桌面能力就断言其为恶意后门或 RAT:样本由 Action1 Corporation 有效签名,安装包自签名后未被篡改,且未发现窃密、勒索或破坏代码。
- 不能把 server[.]action1[.]com / relay[.]action1[.]com / a1-backend-packages[.]s3[.]amazonaws[.]com 当作攻击者 C2,这些是 Action1 官方管理云与包仓库。
- 本次没有实际安装或运行 MSI,不能声称已观测到服务创建、注册表写入、文件落盘或真实网络外联;这些均来自安装包与二进制的静态声明。
- 不能因为 MSI 携带 RSA 私钥与客户证书就认定其为窃密木马,该材料用于 Agent 向所属租户管理端做客户端认证。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次为纯静态档位,未安装 MSI、未运行 Agent;服务创建、注册表写入、文件落盘与网络外联均为安装包声明或代码能力,未经动态确认。
2. C2 域名、端口与 URI 来自 MSI/二进制字符串,标为静态恢复并挂起动态验证;端口 443 由 HTTPS 使用推断。
3. 内置客户 ID 与证书可能对应特定租户,离线环境无法核验其归属及是否属于滥用活动。
4. Agent 为大型静态链接 C++ 程序(含 OpenSSL/curl/boost/libtorrent),未对全部代码路径逐函数反编译,远程命令与下载执行的具体协议细节仍需动态验证。

## 证据索引

<details>
<summary>展开 9 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000018` | evidence.record | 只读解析 MSI 表:产品/服务/注册表/自定义动作/租户密钥与客户 ID |
| `ev-000019` | evidence.record | Authenticode 签名校验:MSI 与主载荷签名有效,签名者 CN=Action1 Corporation |
| `ev-000020` | evidence.record | CAB 解包后载荷字符串/版本信息:厂商域名、配置键、命名对象与远程控制能力 |
| `ev-000001` | 字符串提取 | action1_agent.exe 字符串抽取(28,331 ASCII / 2,223 UTF-16) |
| `ev-000010` | 密码学常量识别 | action1_agent.exe 密码学常量:AES/SHA-256/CRC32/base64 |
| `ref:28957d6555` | PE 结构解析 | action1_agent.exe PE 画像:32 位,5 段,无异常,24 个导入 DLL |
| `ref:ed84731c01` | 导入表解析 | action1_agent.exe 导入表:服务控制/WinHTTP/WS2_32/证书/进程与关机 API |
| `ref:217ca3ec2a` | PE 结构解析 | action1_remote.exe PE 画像:32 位 GUI 子系统,5 段,无异常 |
| `ref:aa817ab1a6` | 导入表解析 | action1_remote.exe 导入表:屏幕捕获/键鼠注入/剪贴板/令牌与命名管道 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
