---
title: "恶意样本分析：WSF PowerShell Downloader（other · wsf · df00d262）"
published: 2026-10-29
draft: false
description: "恶意（置信度低）：WSF PowerShell Downloader · downloader/dropper/loader · 难度 easy · 纯静态分析"
tags: ["downloader", "dropper", "loader", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **WSF PowerShell Downloader**（存疑） · 置信度 **低**
> 
> 别名：PowerShell stager、WSF dropper
> 
> 脚本为明文 JScript（WSF 容器），执行链完整可读：用 MSXML2.XMLHTTP 同步 GET 下载远程 PowerShell 脚本，写入 C:\Temp\ 下随机命名的 .ps1，再以 powershell.exe -nop -ep bypass -file 隐藏窗口执行；无任何用户交互或合法性业务逻辑。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **WSF PowerShell Downloader** · 别名 PowerShell stager、WSF dropper · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · dropper · loader |
| 难度 | easy |
| 首次出现 | 2026-10-29 09:01:39 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/df00d2622fb6f50f3030fbe5a873e96c3e5810c412c0c3fd71e8bafb35f3ba20/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">经脚本宿主执行 JScript</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.007</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">下载远程 PowerShell</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">创建落盘目录</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">随机名落盘脚本</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口执行载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `df00d2622fb6f50f3030fbe5a873e96c3e5810c412c0c3fd71e8bafb35f3ba20` |
| MD5 | _未记录_ |
| 大小 | 5,933 字节（5.8 KB） |
| 类型 | other · `wsf` |

## 行为分析

共 **7** 条行为，每条都挂了证据，且全部静态可得。

### 1. 经脚本宿主执行 JScript

`T1059.007` · 置信度 **高** · 静态

文件为 .wsf 作业文件，内含 <script language="JScript"> 与 CDATA 代码块，由 Windows Script Host 解析执行；加载即调用 IIFE 并执行 engine.run，无需用户交互。

> **证据**：off 0x1E '<script language="JScript">'；off 0x1555 'engine.run;'
> 
> **来源**：`ev-000001` · `ev-000002`

### 2. 下载远程 PowerShell

`T1105` · 置信度 **高** · 静态

通过 ActiveXObject('MSXML2.XMLHTTP') 以同步 GET 请求下载 hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK.PS1，状态码为 200 时取响应正文作为下一阶段载荷。

> **证据**：off 0x13A 地址常量；off 0x2D0 'var xhr = new ActiveXObject('MSXML2.XMLHTTP')'；off 0x5B6 'xhr.open('GET', url, false)'
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 创建落盘目录

`T1105` · 置信度 **高** · 静态

执行前先用 FileSystemObject.FolderExists/CreateFolder 检查并创建 C:\Temp\，失败则整条流水线短路退出，属于典型的载荷暂存目录准备。

> **证据**：off 0x3AB 'Env.ensureFolder(state.directory)'；off 0x417 'fso.CreateFolder(path)'
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 随机名落盘脚本

`T1105` · 置信度 **高** · 静态

以 Math.random.toString(36) 截取 8 位并转大写，拼成 .ps1 文件名，再用 CreateTextFile 将下载内容整体写入 C:\Temp\；文件名每次运行不同，增加静态特征匹配难度。

> **证据**：off 0x79C 'function randomScriptName'；off 0x81F "return seed.toUpperCase + '.ps1'"；off 0xC55 'Env.writeText(targetPath, state.payload)'
> 
> **来源**：`ev-000001` · `ev-000002`

### 5. 隐藏窗口执行载荷

`T1564` · 置信度 **高** · 静态

调用 WScript.Shell.Run 并传入窗口样式 0（隐藏）与 waitOnReturn=true，启动 powershell.exe -nop -ep bypass -file "<随机名>.ps1"，用户界面上不可见。

> **证据**：off 0xD67 'Env.spawnHidden('；off 0xD6F "powershell.exe -nop -ep bypass -file"；off 0x691 'shell.Run(commandLine, 0, true)'
> 
> **来源**：`ev-000001` · `ev-000002`

### 6. 绕过执行策略限制

`T1562.001` · 置信度 **高** · 静态

PowerShell 启动参数使用 -nop（不加载 profile）与 -ep bypass（忽略执行策略），刻意规避脚本执行限制，为后续下载/执行模块清障。

> **证据**：off 0xD6F 命令行字符串 '-nop -ep bypass -file'
> 
> **来源**：`ev-000001` · `ev-000002`

### 7. 失败重试下载

`T1105` · 置信度 **中** · 静态

下载包在 try/catch 与 do/while 中，最多尝试 3 次（maxAttempts=2，循环条件 triesLeft>=0），以容忍临时网络故障或单次请求被拦截。

> **证据**：off 0x9C5 'var triesLeft = state.maxAttempts'；off 0xB4B 'while (triesLeft >= 0)'
> 
> **来源**：`ev-000001` · `ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK[.]PS1` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\Temp\`
- `C:\Temp\<8位大写随机字符>.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK[.]PS1` | 是 | 静态 |
| `download_dir` | `C:\Temp\` | 是 | 静态 |
| `install_path` | `C:\Temp\<8位大写随机字符>.ps1` | 是 | 静态 |
| `exec_commandline` | `powershell.exe -nop -ep bypass -file "C:\Temp\<RAND>.ps1"` | 是 | 静态 |
| `retry_count` | `maxAttempts=2（do/while 判定为 triesLeft>=0，实际最多 3 次尝试）` | 否 | 静态 |
| `encryption_algo` | `-` | 否 | 静态 |
| `campaign_id` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能声称存在持久化：脚本内无注册表写入、无服务安装、无计划任务、无启动目录投放。
- 不能声称是窃密/勒索/挖矿家族：本样本不含凭据收集、文件加密或挖矿相关代码，最终载荷 KMK.PS1 未取得，其功能未知。
- 不能仅凭域名判定攻击者归属：denizcerceve[.]com 很可能是被入侵的合法站点，路径 /images/... 具有正常站点目录伪装特征。
- 不能声称使用了加密或混淆：脚本为完全明文，无解码/解密例程，扫描未发现密码学常量。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 纯静态档位：该格式无隔离动态通道，未执行样本，联网下载与 PowerShell 落地/执行均为代码推断，未经运行时确认。
2. 远程载荷 KMK.PS1 未获取（分析环境无外联），其真实功能、是否有二次下载、C2 心跳与持久化均未知。
3. 域名 denizcerceve[.]com 的所有权与是否被入侵无法在离线环境核实，域名可能已被关停或内容变更。
4. 未使用任何厂商引擎或 YARA 规则比对，家族归因缺乏外部情报佐证，只能给出行为描述性名称。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 抽取 ASCII 字符串 159 条（UTF-16 0 条），命中 C2 URL、C:\Temp\、COM 对象名与 powershell 命令行；flag 命中 0。 |
| `ev-000002` | evidence.record | 逐行阅读脚本并结合字符串偏移确认完整执行链（下载→落盘→隐藏执行），确认无持久化/无加密；自述证据，置信度上限 0.7。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
