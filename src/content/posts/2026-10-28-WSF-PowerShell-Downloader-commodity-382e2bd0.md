---
title: "恶意样本分析：WSF PowerShell Downloader (commodity)（other · wsf · 382e2bd0）"
published: 2026-10-28
draft: false
description: "恶意（置信度低）：WSF PowerShell Downloader (commodity) · downloader/loader/dropper · 难度 easy · 纯静态分析"
tags: ["恶意样本分析", "WSF PowerShell Downloader (commodity)", "downloader", "loader", "dropper", "other"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **WSF PowerShell Downloader (commodity)**（存疑） · 置信度 **低**
> 
> 别名：JScript.WSF.Downloader、WSF.PS1.Loader
> 
> 样本为明文可读的 WSF/JScript 脚本(4295 字节),完整展示一条「访问固定 HTTPS 地址→读取响应体→写入 C:\Temp\<随机8位大写>.ps1→以 powershell.exe -nop -ep bypass -file 隐藏窗口执行」的下载-执行链;入口处 Api.run 无条件触发,无任何用户交互或合法性校验。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **WSF PowerShell Downloader (commodity)** · 别名 JScript.WSF.Downloader、WSF.PS1.Loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · loader · dropper |
| 难度 | easy |
| 首次出现 | 2026-10-28 13:51:16 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/382e2bd0a1b1bf18cdf94438ec898450b05b12577e6f2f3579019518d0bb2f5a/) |

## 攻击链

<svg viewBox="0 0 720 226" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="150" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="38" fill="currentColor" font-weight="600" font-size="14">反分析</text>
<text x="250" y="38" fill="currentColor" fill-opacity="0.65" font-size="12.5">反虚拟机 / 反调试 / 关杀软</text>
<text x="250" y="56" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1497</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="92" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="96" fill="currentColor" font-weight="600" font-size="14">伪装落地</text>
<text x="250" y="96" fill="currentColor" fill-opacity="0.65" font-size="12.5">复制到 %LocalAppData%</text>
<text x="250" y="114" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="96" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="150" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="154" fill="currentColor" font-weight="600" font-size="14">远控 / 窃密</text>
<text x="250" y="154" fill="currentColor" fill-opacity="0.65" font-size="12.5">shell / 键盘 / 截屏 / 摄像头</text>
<text x="250" y="172" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1059</text>
<text x="613" y="154" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `382e2bd0a1b1bf18cdf94438ec898450b05b12577e6f2f3579019518d0bb2f5a` |
| MD5 | _未记录_ |
| 大小 | 4,295 字节（4.2 KB） |
| 类型 | other · `wsf` |

## 行为分析

共 **6** 条行为，每条都挂了证据，且全部静态可得。

### 1. 固定URL拉取PS1载荷

`T1105` · 置信度 **高** · 静态

通过 MSXML2.XMLHTTP 对固定地址发起同步 GET 请求,校验 status==200 后把 responseText 作为待执行脚本内容。

> **证据**：offset 0x00B9(185) 字符串 hxxps://hotelsalamander[.]pl/.../KMK.PS1;offset 0x04E1(1249) this.http.open('GET', url, false); offset 0x0571(1393) responseText
> 
> **来源**：`ev-000001` · `ev-000002`

### 2. 创建C:\Temp暂存目录

`T1074` · 置信度 **高** · 静态

通过 FileSystemObject.FolderExists/CreateFolder 确保 C:\Temp\ 存在,作为二次载荷的落地暂存目录。

> **证据**：offset 0x0124(292) this.directory = 'C:\\Temp\\'; offset 0x02E4(740) this.fs.CreateFolder(dirPath)
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 随机名写入脚本文件

`T1036` · 置信度 **高** · 静态

以 Math.random.toString(36).substring(2,10) 生成 8 位随机串并转大写,拼接 .ps1 后缀,用 CreateTextFile 覆盖写入下载内容,规避固定文件名检测。

> **证据**：offset 0x07B6(1974) Math.random.toString(36).substring(2, 10); offset 0x07FB(2043) return randPart.toUpperCase + '.ps1'; offset 0x03C7(967) CreateTextFile
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 隐藏窗口拉起PowerShell

`T1059.001` · 置信度 **高** · 静态

用 WScript.Shell.Run(cmd, 0, true) 以窗口样式 0(隐藏)启动 powershell.exe -nop -ep bypass -file "C:\Temp\<RANDOM>.ps1",并同步等待其结束。

> **证据**：offset 0x06BF(1727) this.sh.Run(cmd, 0, true); offset 0x0917(2327) 'powershell.exe -nop -ep bypass -file "' + path + '"'
> 
> **来源**：`ev-000001` · `ev-000002`

### 5. 绕过执行策略与配置

`T1562.001` · 置信度 **高** · 静态

启动参数固定使用 -nop(不加载 profile)与 -ep bypass(绕过 PowerShell 执行策略),削弱脚本执行限制。

> **证据**：offset 0x0917(2327) 命令行含 -nop -ep bypass
> 
> **来源**：`ev-000001` · `ev-000002`

### 6. WSF宿主自动执行入口

`T1059.007` · 置信度 **高** · 静态

脚本以 <script language="JScript"> 嵌入 .wsf,末尾直接调用 Api.run 触发完整下载-执行流水线,无需用户交互;后续可通过全局 ScriptAPI.config 改写 URL/目录。

> **证据**：offset 0x001E(30) <script language="JScript">; offset 0x1057(4183) Api.run; offset 0x1061(4225) this.ScriptAPI = Api;
> 
> **来源**：`ev-000001` · `ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://hotelsalamander[.]pl/wp-includes/rest-api/lfszonm/vtsdyif/gtwmhfx/KMK.PS1` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\Temp\`
- `C:\Temp\<8位随机大写字母>.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `hotelsalamander[.]pl` | 是 | 静态 |
| `download_url` | `hxxps://hotelsalamander[.]pl/wp-includes/rest-api/lfszonm/vtsdyif/gtwmhfx/KMK.PS1` | 是 | 静态 |
| `install_path` | `C:\Temp\<RANDOM8>.ps1` | 是 | 静态 |
| `launch_command` | `powershell.exe -nop -ep bypass -file "<path>"` | 是 | 静态 |
| `retry_max_attempts` | `2` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得判定为勒索软件或窃密木马:样本内无文件加密、凭据读取、浏览器数据收集或批量外传代码,唯一网络行为是单次 GET 下载。
- 不得判定存在持久化:未发现注册表 Run 键、计划任务、服务安装或启动目录写入。
- 不得声称已确认最终载荷家族或完整 C2 基础设施:KMK.PS1 本体未获取,其二阶段行为与后续 C2 均未观测。
- 不得描述为具备横向移动或蠕虫传播能力:无 SMB/RDP/远程执行相关代码。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 该格式无隔离动态通道,所有结论均来自明文源码与字符串静态审阅,未真实执行样本。
2. 下载地址 hxxps://hotelsalamander[.]pl/... 为疑似被入侵 WordPress 站点路径,分析时未发起真实请求,当前是否仍存活/返回何种载荷未知。
3. 二阶段 KMK.PS1 内容、其持久化方式、最终家族归属与真实 C2 均未获取,相关字段留空并标记待动态验证。
4. 文件哈希由本地只读校验得出(自述证据),未与外部情报库比对,首次出现时间未知。
5. 未发现互斥体、注册表、服务或计划任务等主机持久化痕迹,但这仅代表一阶段脚本不包含,不代表二阶段不存在。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 抽取 123 条 ASCII 字符串(0 条 UTF-16LE),给出 URL、C:\Temp、CreateTextFile、MSXML2.XMLHTTP、powershell 命令行等关键串的字节偏移。 |
| `ev-000002` | evidence.record | 本地只读校验:sha256/md5/大小,并逐字节复核唯一 URL、落地目录、随机文件名、启动参数、重试次数,确认无持久化与加密代码。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
