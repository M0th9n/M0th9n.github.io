---
title: "恶意样本分析：ValleyRAT / Winos（候选）（PE · exe · ab6dc65b）"
published: 2026-11-14
draft: false
description: "恶意（置信度低）：ValleyRAT / Winos（候选） · loader/rat/injector · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["ValleyRAT", "loader", "rat", "injector", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ValleyRAT / Winos（候选）**（存疑） · 置信度 **低**
> 
> 别名：ValleyRAT、Winos 4.0、SilverFox 相关加载链
> 
> 真实动态沙箱中完整观测到多阶段投递链：7z 自解压体把带 iMyFone 签名的 Engine-Infra.exe 释放到 %TEMP% 并启动，后者把自身与 Qt5Core/MSVC 运行库暂存到 C:\ProgramData\mgr_agent_v2 并重启，随后释放并执行 C:\ProgramData\PoExplorer.exe，创建计划任务 ConfigDebug_amd64_debug，PoExplorer 反复解析 new-label[.]club 并 TCP 连接 :3333；内存取证还显示该进程主镜像头被替换、存在 529 处补丁的未映射模块，并留有 cp/dp/sid/tag/buildId/av/monitors 配置。该链条符合加载器加远程控制后门，且明确规避正常安装路径与签名校验。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ValleyRAT / Winos（候选）** · 别名 ValleyRAT、Winos 4.0、SilverFox 相关加载链 · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · rat · injector |
| 难度 | hard |
| 首次出现 | 2026-11-12 00:23:06 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ab6dc65bff1fcf2082974b906384d9ed9cc902deec33c0589d11d7a31df51e6c/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">自解压投递上线组件</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">侧载签名 iMyFone 组件</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">暂存目录后重启</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">释放并执行 PoExplorer</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">镂空注入 PoExplorer</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ab6dc65bff1fcf2082974b906384d9ed9cc902deec33c0589d11d7a31df51e6c` |
| MD5 | _未记录_ |
| 大小 | 7,496,236 字节（7.1 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **12** 条行为，每条都挂了证据；其中 **2** 条静态可得、**10** 条经动态分析取得。

### 1. 自解压投递上线组件

`T1204.002` · 置信度 **高** · 动态

7z 自解压模块将内置文件解到 %TEMP%，并按配置 RunProgram 启动 Engine-Infra.exe。

> **证据**：SFX 配置位于文件偏移 0x2DF45：InstallPath="%TEMP%"、RunProgram="%T%\Engine-Infra.exe"；动态进程链 4060→2480 于 %TEMP%\Engine-Infra.exe。
> 
> **来源**：`ev-000027` · `ev-000007` · `ev-000028`

### 2. 侧载签名 iMyFone 组件

`T1574.002` · 置信度 **高** · 动态

启动带 DigiCert EV 签名的 iMyFone Engine-Infra.exe，并从同目录加载 Qt5Core.dll 等依赖，借助合法签名降低告警。

> **证据**：Engine-Infra.exe 证书字段含 Shenzhen iMyFone Technology/DigiCert；运行中从 %TEMP% 加载 Qt5Core.dll、msvcp120.dll、msvcr120.dll。
> 
> **来源**：`ev-000016` · `ev-000008` · `ev-000028`

### 3. 暂存目录后重启

`T1036.005` · 置信度 **高** · 动态

将自身与 Qt5Core/MSVC 运行库复制到 C:\ProgramData\mgr_agent_v2，并从该目录重新启动。

> **证据**：主机遥测 04:01:45 连续创建 mgr_agent_v2\Engine-Infra.exe、Qt5Core.dll、msvcp120.dll、msvcp_win.dll、msvcr120.dll、ucrtbase.dll；04:01:46 PID 5632 从该路径启动。
> 
> **来源**：`ev-000028`

### 4. 释放并执行 PoExplorer

`T1105` · 置信度 **高** · 动态

从暂存目录写出 C:\ProgramData\PoExplorer.exe 并立即启动该进程。

> **证据**：主机遥测 04:02:35 由 PID 5632 创建 C:\ProgramData\PoExplorer.exe，同一秒创建 PID 1824 执行该文件。
> 
> **来源**：`ev-000028`

### 5. 镂空注入 PoExplorer

`T1055.012` · 置信度 **高** · 动态

PoExplorer 主镜像的 DOS/PE 头、入口点和节表被替换，内存中还存在 529 处补丁的未映射模块，符合进程镂空或代码注入。

> **证据**：内存取证报告：is_pe_replaced=1、ep_modified=1、sec_hdr_modified=1；0x8d0000 未映射模块 529 处补丁，ntdll 3 处补丁。
> 
> **来源**：`ev-000028`

### 6. 创建计划任务持久化

`T1053.005` · 置信度 **高** · 动态

通过任务计划程序创建名为 ConfigDebug_amd64_debug 的计划任务，并写入 Windows\Tasks 的 .job 文件。

> **证据**：主机遥测 04:02:51：PID 5632 创建 C:\Windows\Tasks\ConfigDebug_amd64_debug.job，svchost 同时创建 C:\Windows\System32\Tasks\ConfigDebug_amd64_debug。
> 
> **来源**：`ev-000028`

### 7. 解析 C2 域名

`T1071.004` · 置信度 **高** · 动态

PoExplorer.exe 反复解析 new-label[.]club，网络监控返回假网地址。

> **证据**：主机遥测 DNS 事件 QueryName=new-label[.]club，时间 04:02:53、04:03:40、04:04:25，结果 192.0.2[.]123。
> 
> **来源**：`ev-000028`

### 8. TCP 3333 回连

`T1095` · 置信度 **高** · 动态

PoExplorer.exe 多次向 192.0.2[.]123:3333 发起 TCP 连接，符合控制端口回连。

> **证据**：网络监控日志 04:02:53/04:03:35/04:03:40/04:04:20/04:04:25：PoExplorer.exe (1824) requested TCP 192.0.2[.]123:3333。
> 
> **来源**：`ev-000028`

### 9. 采集主机与屏幕信息

`T1082` · 置信度 **高** · 动态

内存配置 JSON 收集计算机名、用户名、内存、UAC、CPU、显示器分辨率与刷新率、版本与构建标识，用于主机画像和远控会话。

> **证据**：内存转储 0x6052B7 处明文 JSON：computer/user/ram/uac/cpu/ver/iver/ts/cp/dp/sid/tag/buildId/av/monitors。
> 
> **来源**：`ev-000028`

### 10. 识别杀软状态

`T1518.001` · 置信度 **高** · 动态

配置中上报 av 字段为 Windows Defender(OFF)，说明会探测安全软件状态后再上线。

> **证据**：JSON 字段 av="VwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgAoAE8ARgBGACkA"（Base64 解码为 Windows Defender(OFF)）。
> 
> **来源**：`ev-000028`

### 11. 内置加密资源文件

`T1027.009` · 置信度 **中** · 静态

投放 sampleragent.bin（5.6MB，前 0x404E 为类英文文本，后接 687 个 IDAT 的 PNG chunk 容器）与 watcherserver.dat（126KB）作为后续载荷或配置资源。

> **证据**：7z 归档目录含 sampleragent.bin/watcherserver.dat；sampleragent.bin 0x404E 起为大端长度 0x2000 的 IDAT chunk，末尾 IEND 加 CRC。
> 
> **来源**：`ev-000027`

### 12. 滥用合法代码签名

`T1553.002` · 置信度 **中** · 静态

以 iMyFone 的 DigiCert EV 签名二进制作为白名单宿主，掩盖后续侧载与载荷投放。

> **证据**：Engine-Infra.exe 内证书字段：Shenzhen iMyFone Technology Co., Ltd、DigiCert EV Code Signing、ocsp/crl[.]digicert[.]com。
> 
> **来源**：`ev-000016` · `ev-000008`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| dns | `new-label[.]club` | 53 | c2 | 静态 | ⏳ 未观测 |
| tcp | `new-label[.]club` | 3333 | c2 | 静态 | ⏳ 未观测 |
| tcp | `new-label[.]club` | 3334 | exfil | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%TEMP%\Engine-Infra.exe`
- `%TEMP%\Qt5Core.dll`
- `%TEMP%\sampleragent.bin`
- `%TEMP%\watcherserver.dat`
- `%ProgramData%\mgr_agent_v2\Engine-Infra.exe`
- `%ProgramData%\mgr_agent_v2\Qt5Core.dll`
- `%ProgramData%\mgr_agent_v2\msvcp120.dll`
- `%ProgramData%\mgr_agent_v2\msvcp_win.dll`
- `%ProgramData%\mgr_agent_v2\msvcr120.dll`
- `%ProgramData%\mgr_agent_v2\ucrtbase.dll`
- `%ProgramData%\PoExplorer.exe`
- `%ALLUSERSPROFILE%\PoExplorer.exe`

**计划任务**

- `ConfigDebug_amd64_debug`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `['new-label[.]club']` | 是 | 静态 |
| `c2_port` | `3333` | 是 | 静态 |
| `data_port` | `3334` | 否 | 静态 |
| `install_path` | `C:\ProgramData\mgr_agent_v2` | 否 | 动态 |
| `payload_path` | `C:\ProgramData\PoExplorer.exe` | 否 | 动态 |
| `task_name` | `ConfigDebug_amd64_debug` | 否 | 动态 |
| `build_id` | `main` | 否 | 静态 |
| `campaign_tag` | `new` | 否 | 静态 |
| `bot_sid` | `VUSURWIV` | 否 | 静态 |
| `version` | `0.1.32` | 否 | 静态 |
| `av_status` | `Windows Defender(OFF)` | 否 | 静态 |
| `encryption_algo` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能声称 C2 会话已建立或数据外传成功：仅观测到 DNS 解析与 TCP connect 尝试，没有应用层请求/响应、上线包或回传内容。
- 不能声称这是 iMyFone 官方安装包，或 iMyFone 公司开发了该恶意软件：签名组件是被侧载/滥用的宿主，SFX 解压到 %TEMP% 并直接运行服务组件的流程不符合正常安装逻辑。
- 不能声称存在服务持久化或注册表 Run 键：MFLocalService/MFResident 仅是字符串，实际未创建服务，Run 键无变化。
- 不能声称已窃取凭据、浏览器数据或文件：未观测到相关文件访问或外传；配置仅体现主机与显示器信息采集。
- 不能把家族定为某一确定家族：缺少 YARA、厂商引擎或公开报告交叉验证，ValleyRAT/Winos 仅是行为与配置形态相似的候选。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是 |

**局限与待验证**

1. C2 仅观测到 DNS 解析和 TCP 3333 连接尝试，未取得应用层会话或响应；因此 c2 条目按 static 加 pending_dynamic_verify 记录。
2. 家族归属没有 YARA、厂商引擎或公开报告交叉验证；ValleyRAT/Winos 为候选，家族字段标记 uncertain。
3. sampleragent.bin 的 0x404E 前缀为类英文随机文本，其后 687 个 IDAT 数据无法解压为有效 PNG，未完成解密，具体载荷作用为推断。
4. 未对 Engine-Infra.exe 的 Authenticode 做密码学验签，仅依据证书字段和安全目录存在性判断其签名来源。
5. 未采集到磁盘上的 PoExplorer.exe 原文件，只有内存镜像；其落盘哈希未知，内存镜像显示头部被替换。
6. 遥测中部分事件的 UtcTime 与事件时间不一致（10-12 对 11-14），可能是客体时钟或时间设置异常，未据此推断时间篡改行为。
7. 沙箱基线本身存在 MicrosoftEdgeUpdate、Windows Update 等外联，C2 归因只取 new-label[.]club:3333 与 PoExplorer.exe 相关事件。
8. 192.0.2[.]123 为网络监控使用的保留测试地址，不是真实 C2 IP；3334 端口仅来自配置，未观测到实际连接。

## 证据索引

<details>
<summary>展开 16 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | 外层 SFX sha256/md5/sha1 |
| `ev-000007` | 字符串提取 | 外层 7z SFX 模块字符串（7-Zip SFX 1.4.0 beta / 9.15 beta） |
| `ev-000008` | 哈希与指纹 | Engine-Infra.exe sha256 与 Rich header |
| `ev-000016` | 字符串提取 | Engine-Infra 字符串：MFLocalService、Maifeng/iMyFone、MFResident.exe、QtService |
| `ev-000017` | decompile.function | QtService 命令行与服务安装分支反编译 |
| `ev-000018` | decompile.function | 服务启动与 HandlerThread 反编译 |
| `ev-000019` | 哈希与指纹 | Qt5Core.dll sha256 |
| `ev-000022` | scan.entropy | Qt5Core .text 熵 6.501（非加壳） |
| `ev-000027` | evidence.record | 7z 静态解包、SFX 配置、四个阶段文件哈希、sampleragent PNG chunk 结构 |
| `ev-000028` | evidence.record | 沙箱进程链、文件创建、计划任务、DNS/TCP、内存取证、配置 JSON |
| `ref:667f30b308` | disasm.function | Qt5Core 0x2130 处将 sampleragent.bin 指针转 UTF-16 的代码 |
| `ref:f9b7a86634` | PE 结构解析 | Qt5Core 7089 导出、正常 5 节结构 |
| `telemetry:ab6dc65b` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 147 条；ETW 短命进程事件 3 条；已过滤工具/系统噪声 28 条 |
| `etw:ab6dc65b:4060` | 进程事件监控 | 短命进程事件：ab6dc65bff1fcf2082974b906384d9ed9cc902deec33c0589d11d7a31df51e6c.exe（pid 4060；MD5=BF4DFFC81084F6453CD050CADA628844,SHA256=AB6DC65BFF1FCF2082974B906384D9ED9CC902DEEC33C0589D11D7A31DF51E6C,IMPHASH=B5A014D7EEB4C2042897567E1288A095） |
| `etw:ab6dc65b:2480` | 进程事件监控 | 短命进程事件：Engine-Infra.exe（pid 2480；MD5=CF01F8E53800DC303F0066DBED915078,SHA256=FDB9FEC2A2809B72C4897955EAA4B960BBC46C183EE15ED706F66DB4E3D46484,IMPHASH=A4AD602AAB365EFF6CA7FB2CD8E12944） |
| `etw:ab6dc65b:5632` | 进程事件监控 | 短命进程事件：Engine-Infra.exe（pid 5632；MD5=CF01F8E53800DC303F0066DBED915078,SHA256=FDB9FEC2A2809B72C4897955EAA4B960BBC46C183EE15ED706F66DB4E3D46484,IMPHASH=A4AD602AAB365EFF6CA7FB2CD8E12944） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
