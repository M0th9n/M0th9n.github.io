---
title: "恶意样本分析：HTA PowerShell Downloader (secured_stub)（other · hta · 9c9b1343）"
published: 2026-11-17
draft: false
description: "恶意（置信度中）：HTA PowerShell Downloader (secured_stub) · downloader/loader · 难度 easy · 纯静态分析"
tags: ["HTA", "downloader", "loader", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **HTA PowerShell Downloader (secured_stub)**（存疑） · 置信度 **中**
> 
> 别名：SecuredStub HTA dropper
> 
> 样本是伪装成 System Uptime 的 HTA 文件。其内置 RC4 + 自定义字母表 Base64 字符串解密逻辑，代码级还原后可见完整下载执行链：从 hxxp://45.136.5[.]82/23/secured_stub.ps1?JPG 同步下载 PowerShell 脚本，写入 %TEMP% 下随机命名的 .ps1，并以 -ExecutionPolicy Bypass -WindowStyle Hidden 隐藏窗口执行，随后删除落地文件。该行为本身即为典型的恶意下载器/加载器，无需依赖外部引擎结论。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **HTA PowerShell Downloader (secured_stub)** · 别名 SecuredStub HTA dropper · _存疑_ |
| 置信度 | **中** |
| 行为类 | downloader · loader |
| 难度 | easy |
| 首次出现 | 2026-11-16 15:44:05 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/9c9b13435910c1db025ca3f062ebe7375901f9736276972437bdf322d6be20e5/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装系统运行时间</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">RC4解密字符串表</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">随机化落地文件名</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">下载远程PS1脚本</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">写入临时目录</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `9c9b13435910c1db025ca3f062ebe7375901f9736276972437bdf322d6be20e5` |
| MD5 | _未记录_ |
| 大小 | 20,322 字节（19.8 KB） |
| 类型 | other · `hta` |

## 行为分析

共 **9** 条行为，每条都挂了证据，且全部静态可得。

### 1. 伪装系统运行时间

`T1036.005` · 置信度 **高** · 静态

HTA:APPLICATION 将应用名设为 System Uptime，窗口最小化且不显示在任务栏，用以伪装成系统运行时间组件。

> **证据**：文件偏移 0-189：APPLICATIONNAME="System Uptime"、SHOWINTASKBAR="no"、WINDOWSTATE="minimize"
> 
> **来源**：`ev-000001`

### 2. RC4解密字符串表

`T1140` · 置信度 **高** · 静态

内置 RC4 与自定义字母表 Base64 解密函数，运行时还原配置键、API 名称与命令字符串，静态不可直接读出全部明文。

> **证据**：偏移 12730 起 _0x5694/_0x20df/_0x1113 字符串解密；解密脚本还原 90 条主字符串与 36 条配置字符串
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 随机化落地文件名

`T1036` · 置信度 **高** · 静态

在 %TEMP% 下用 12 位随机大写字母加 .ps1 生成落地文件名，避免基于固定文件名的检测与清理。

> **证据**：偏移 2272 函数 _0x5aeae0：nameLength=12、alphabet=ABCDEFGHIJKLMNOPQRSTUVWXYZ、后缀 .ps1
> 
> **来源**：`ev-000002`

### 4. 下载远程PS1脚本

`T1105` · 置信度 **高** · 静态

通过 MSXML2.XMLHTTP 以同步 GET 从 hxxp://45.136.5[.]82/23/secured_stub.ps1?JPG 拉取远程 PowerShell 脚本。

> **证据**：偏移 3155 函数 _0x279773 使用 MSXML2.XMLHTTP.open('GET', url, false)；偏移 800 配置 url 赋值
> 
> **来源**：`ev-000001` · `ev-000002`

### 5. 写入临时目录

`T1105` · 置信度 **高** · 静态

HTTP 状态码为 200 时，用 Scripting.FileSystemObject.CreateTextFile 将响应体写入 %TEMP% 下的随机 .ps1 文件并关闭句柄。

> **证据**：偏移 3453 函数 _0x1b64e7：CreateTextFile(path,true)/Write/Close；主流程判断状态 0xc8
> 
> **来源**：`ev-000002`

### 6. 隐藏窗口执行脚本

`T1059.001` · 置信度 **高** · 静态

用 WScript.Shell.Run 以 powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File 启动落地脚本，窗口样式 0 且不等待进程结束。

> **证据**：偏移 5313 函数 _0x1ca3f9 调用 WScript.Shell.Run；偏移 5828 命令串 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "'
> 
> **来源**：`ev-000001` · `ev-000002`

### 7. 绕过执行策略

`T1562.001` · 置信度 **高** · 静态

PowerShell 命令行显式附带 -ExecutionPolicy Bypass，绕过本机脚本执行策略限制。

> **证据**：偏移 5828 命令串包含 -ExecutionPolicy Bypass
> 
> **来源**：`ev-000001` · `ev-000002`

### 8. 删除落地脚本

`T1070.004` · 置信度 **高** · 静态

执行 3000 ms 后检查落地文件是否存在并调用 DeleteFile 删除，清除磁盘痕迹。

> **证据**：偏移 4459 函数 _0x2a874e FileExists/DeleteFile；配置 cleanupDelay=0xbb8 (3000 ms)
> 
> **来源**：`ev-000002`

### 9. 执行后关闭窗口

`T1564.003` · 置信度 **高** · 静态

删除完成后调用 window.close 结束 HTA 窗口；下载失败分支同样直接关闭窗口以缩短暴露时间。

> **证据**：偏移 6030 函数 _0x3a1899 调用 window.close；主流程 else 分支 window.close
> 
> **来源**：`ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://45[.]136[.]5[.]82/23/secured_stub[.]ps1?JPG` | 80 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%TEMP%\<12位随机大写字母>.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `45.136.5[.]82` | 是 | 静态 |
| `c2_port` | `80` | 是 | 静态 |
| `c2_uri` | `/23/secured_stub.ps1?JPG` | 是 | 静态 |
| `download_method` | `GET` | 否 | 静态 |
| `http_client` | `MSXML2.XMLHTTP` | 否 | 静态 |
| `temp_dir` | `%TEMP%` | 是 | 静态 |
| `filename_length` | `12` | 否 | 静态 |
| `filename_alphabet` | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` | 否 | 静态 |
| `file_extension` | `.ps1` | 是 | 静态 |
| `cleanup_delay_ms` | `3000` | 否 | 静态 |
| `launch_command` | `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "<path>"` | 是 | 静态 |
| `encryption_algo` | `RC4 + custom-alphabet Base64 (string obfuscation)` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能将该样本认定为勒索软件、窃密木马或 RAT：静态分析仅确认其下载并执行 PowerShell 脚本，最终脚本内容未被获取，后续能力未知。
- 没有证据表明样本写入注册表、创建计划任务或服务、或实现持久化，不应声称其具备驻留能力。
- 不应仅凭唯一 IP/URL 或字符串特征将其归因到某一具体商业命名家族；本报告的家族名仅为投递链行为描述。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次仅做静态分析，未在真实隔离环境中引爆，也未抓取 secured_stub.ps1 的内容；远程服务的可用性、实际下发载荷及后续行为均未验证。
2. 远程脚本内容未知，因此无法判定最终载荷类型（如窃密、远控、挖矿等），相关字段一律留空或标注待动态验证。
3. 样本不是 PE/ELF，常规可执行文件结构、导入表与节区分析不适用；哈希与格式由本地字节读取脚本计算。
4. C2 及配置均来自代码级解密与常量读取，标注为 static 且 pending_dynamic_verify=true，未经网络会话确认。

## 证据索引

<details>
<summary>展开 3 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 静态字符串提取：397 条 ASCII 字符串，明文包含 HTA 伪装头、配置赋值行、MSXML2.XMLHTTP/WScript.Shell/Scripting.FileSystemObject 以及 PowerShell 命令行片段。 |
| `ev-000002` | evidence.record | 自写解密脚本复现 RC4 + 自定义字母表 Base64，还原完整配置与执行链，并与样本 _0x1113 配置数组索引交叉验证。 |
| `ev-000003` | evidence.record | 本地字节读取：20322 字节、ASCII/CRLF HTA；sha256=9c9b13435910c1db025ca3f062ebe7375901f9736276972437bdf322d6be20e5、md5=c0518ff04706c91792aca3d76adcc8ee。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
