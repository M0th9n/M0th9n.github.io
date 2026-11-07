---
title: "恶意样本分析：twitmerklend-loader (unattributed)（PE · exe · a459cc80）"
published: 2026-10-31
draft: false
description: "恶意（置信度低）：twitmerklend-loader (unattributed) · loader/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **twitmerklend-loader (unattributed)**（存疑） · 置信度 **低**
> 
> 隔离 Windows 10 客体中真实引爆：样本进程在启动后先解析其从未在文件中明文的域名 twitmerklend[.]com，随后自身发起 443 出站连接；其进程内存中可直接读到完整的 HTTPS C2 URL（hxxps://twitmerklend[.]com/<uuid>/<uuid>）。静态代码同时具备 WMI 杀软枚举、cmd/PowerShell 命令执行、文件时间戳篡改与哈希式动态 API 解析能力，组合符合远程控制型加载器特征。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **twitmerklend-loader (unattributed)** · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | medium |
| 首次出现 | 2026-10-30 14:34:32 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/a459cc80f8ad88b4e68b4ba073d2a4d7b34ca1072c1201551a09ae8ccd8dd8f6/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">HTTPS 回连 C2</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">枚举杀毒软件</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1518.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">解析远程配置</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">执行 cmd 命令</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">PowerShell 免策略执行</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `a459cc80f8ad88b4e68b4ba073d2a4d7b34ca1072c1201551a09ae8ccd8dd8f6` |
| MD5 | _未记录_ |
| 大小 | 259,072 字节（253.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **8** 条行为，每条都挂了证据；其中 **7** 条静态可得、**1** 条经动态分析取得。

### 1. HTTPS 回连 C2

`T1071.001` · 置信度 **高** · 动态

启动后向 twitmerklend[.]com:443 发起出站连接，并在内存中构造 hxxps://twitmerklend[.]com/<uuid>/<uuid> 形式的任务请求 URL。

> **证据**：沙箱网络日志： 'Received A request for domain twitmerklend[.]com' + pid 4936 requested TCP 192.0.2[.]123:443；内存偏移 0x20838f 处完整 URL
> 
> **来源**：`ref:19d61a85c2` · `ev-000024` · `ref:2fb9df9f74`

### 2. 枚举杀毒软件

`T1518.001` · 置信度 **高** · 静态

通过 COM/WMI 连接 root\SecurityCenter2 并执行 SELECT * FROM AntivirusProduct，读取 displayName 收集已安装杀软列表。

> **证据**：0x40b4d0：CoCreateInstance→ConnectServer(root\SecurityCenter2)→ExecQuery(XOR 还原的 WQL 查询)→Get(displayName)；字符串 0x430400/0x43042e
> 
> **来源**：`ev-000020` · `ev-000012`

### 3. 解析远程配置

`T1105` · 置信度 **中** · 静态

对 C2 响应体先 zlib 解压再按 JSON/字段表解析（settings/run/status 等），据返回值决定后续动作。

> **证据**：0x405fe0：WinINet 风格请求→FUN_0040add0 读响应→FUN_004031e0 inflate→FUN_00408ac0 解析→按解密后的字段名取值
> 
> **来源**：`ev-000023` · `ev-000019`

### 4. 执行 cmd 命令

`T1059.003` · 置信度 **高** · 静态

以 ShellExecuteEx 的 open/runas 谓词运行 cmd.exe /c "<命令>"，可按配置决定是否请求管理员权限。

> **证据**：0x40f720：verb 取 'open' 或 'runas'，命令行由 cmd.exe + "/c \"%s\"" 拼装；字符串 0x430510/0x43047c/0x430634/0x430470
> 
> **来源**：`ev-000021` · `ev-000022` · `ev-000012`

### 5. PowerShell 免策略执行

`T1059.001` · 置信度 **高** · 静态

用 -ExecutionPolicy Bypass -NoProfile 配合 -EncodedCommand / -Command / -File 启动 PowerShell 执行下发内容。

> **证据**：字符串 0x430520 / 0x430590 / 0x430650；0x40f720 中由 cmd/PowerShell 模板拼装命令行
> 
> **来源**：`ev-000012` · `ev-000022`

### 6. 篡改文件时间戳

`T1070.006` · 置信度 **中** · 静态

导入 LocalFileTimeToFileTime/SystemTimeToFileTime/SetFileTime，具备将落地文件时间伪装为系统文件时间的能力。

> **证据**：导入表 KERNEL32: SetFileTime / LocalFileTimeToFileTime / SystemTimeToFileTime
> 
> **来源**：`ref:90c5c899f3`

### 7. 哈希动态解析 API

`T1027` · 置信度 **中** · 静态

不依赖导入表，按模块序号 + 32 位哈希在运行时解析 API 后间接调用（如 ShellExecuteEx、WMI/网络相关函数）。

> **证据**：0x4189b0(module_idx, hash) 反复调用后再 (*func)；如 0x83e9e133（ShellExecuteEx 路径）
> 
> **来源**：`ev-000018` · `ev-000021`

### 8. XOR 混淆字符串

`T1027` · 置信度 **高** · 静态

敏感宽字符串以 4 字节循环密钥逐字节 XOR 存放，运行时解密后才使用（如 WQL 查询）。

> **证据**：0x40b4d0 中 local_7e 与 0x4303fc 处 4 字节密钥循环异或，还原出 'SELECT * FROM AntivirusProduct'
> 
> **来源**：`ev-000020`


## IOC（已去武器化）

### 网络

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://twitmerklend[.]com/31aa8434-bc4d-511f-910d-adbab2766b4f/22d0642c-c560-5532-a5ee-70fb76dc49ef` | 443 | c2 | 动态 | — |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `twitmerklend[.]com` | 是 | 动态 |
| `c2_url` | `hxxps://twitmerklend[.]com/31aa8434-bc4d-511f-910d-adbab2766b4f/22d0642c-c560-5532-a5ee-70fb76dc49ef` | 是 | 动态 |
| `http_client` | `WinHTTP (HTTP/1.1, GET/POST)` | 否 | 静态 |
| `av_discovery_query` | `WMI root\SecurityCenter2 : SELECT * FROM AntivirusProduct (field displayName)` | 否 | 静态 |
| `cmd_exec_template` | `cmd.exe /c "%s" ; ShellExecuteEx verb open\|runas` | 否 | 静态 |
| `ps_exec_template` | `powershell -ExecutionPolicy Bypass -NoProfile -EncodedCommand\|-Command\|-File "%s"` | 否 | 静态 |
| `payload_encoding` | `zlib inflate (inflate 1.1.3) + CRC32` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能断言样本已下载或执行二阶段载荷：观测窗口内仅见 DNS 解析与 443 连接，未见落地文件、子进程或服务创建。
- 不能断言其为某个具体家族（如 BumbleBee/HijackLoader 等）：无 YARA、厂商命名或家族专属字符串佐证，family 字段为候选且 uncertain。
- 不能断言具备窃密/勒索/挖矿能力：代码与行为中均未发现浏览器凭据、钱包、加密文件等路径。
- 不能把 'runas'、'--headless' 模板当作已执行行为：当前仅静态可见模板，未观测到对应进程创建。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. C2 域名与完整 URL 未在静态文件中以明文/简单 XOR 形式出现，只能在运行时进程内存中恢复；静态无法直接给出该 IOC。
2. 观测窗口内未见 TLS 应用层请求/响应内容（网络侧仅记录到域名解析与 TCP 443 建连），因此二阶段载荷、任务指令、持久化方式均未确认。
3. 未观测到文件写入、注册表修改、计划任务或服务创建；相关能力仅来自导入表与代码路径，属静态推断。
4. PowerShell 与 --headless 浏览器启动模板、runas 提权分支均未在本次运行中被触发，实际使用场景未知。
5. 家族归属缺少 YARA/多引擎/公开报告佐证，仅按代码与配置特征给出候选名，置信度低。

## 证据索引

<details>
<summary>展开 13 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与样本大小 259072 |
| `ev-000003` | scan.rich | Rich header 13 条记录，MSVC 工具链 |
| `ev-000012` | 字符串提取 | 字符串抽取：HTTP/1.1、root\SecurityCenter2、cmd.exe、PowerShell -EncodedCommand、--headless 等 |
| `ref:90c5c899f3` | 导入表解析 | 导入表 82 项：CreateFileW/WriteFile/SetFileTime、CoCreateInstance、IsDebuggerPresent 等 |
| `ev-000019` | decompile.ghidra | 0x40a880：WinINet/WinHTTP 请求构造（GET + HTTP/1.1） |
| `ev-000020` | decompile.ghidra | 0x40b4d0：WMI root\SecurityCenter2 枚举 AntivirusProduct/displayName，并 XOR 还原 WQL |
| `ev-000021` | decompile.ghidra | 0x40f720：ShellExecuteEx verb open/runas + cmd.exe /c + PowerShell 模板 |
| `ev-000022` | decompile.ghidra | 0x40f720 完整伪代码（含 EncodedCommand/--headless 分支） |
| `ev-000023` | decompile.ghidra | 0x405fe0：C2 响应读取→inflate→配置字段解析 |
| `ref:2fb9df9f74` | 动态分析平台 | 真实动态引爆：pid 4936 运行，内存转储与时间线 |
| `ref:19d61a85c2` | bash (log parse) | 沙箱网络日志：twitmerklend[.]com 解析 + 样本 pid 4936 TCP 443 |
| `ev-000024` | evidence.record | 内存转储中恢复完整 C2 URL 及加载模块 |
| `c2_evidence:a459cc80` | 连接证据提取 | 动态网络监控记录到 1 次到 ctldl[.]windowsupdate[.]com:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
