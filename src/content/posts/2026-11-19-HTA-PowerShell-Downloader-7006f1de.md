---
title: "恶意样本分析：HTA PowerShell Downloader（other · hta · 7006f1de）"
published: 2026-11-19
draft: false
description: "恶意（置信度低）：HTA PowerShell Downloader · downloader/dropper · 难度 easy · 纯静态分析"
tags: ["HTA", "downloader", "dropper", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **HTA PowerShell Downloader**（存疑） · 置信度 **低**
> 
> 别名：HTA/PSDownloader、System Uptime HTA stager、secured_stub loader
> 
> 样本为 7664 字节明文 HTA(无编码、无加密、无隐藏附加数据),脚本在窗口加载时立即执行完整投递链:用 MSXML2.XMLHTTP 同步 GET 从 hxxp://104[.]168[.]70[.]178/187/secured_stub[.]ps1?IMAGE[.]PNG 下载 PowerShell 脚本,经 Scripting.FileSystemObject 写入 %TEMP% 下 12 位随机大写字母命名的 .ps1,再用 WScript.Shell.Run 以 powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File 隐藏执行,3 秒后删除落盘脚本并关闭窗口。下载并静默执行远程脚本是明确的恶意投递行为,且界面被伪装成“System Uptime”以规避用户察觉。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **HTA PowerShell Downloader** · 别名 HTA/PSDownloader、System Uptime HTA stager、secured_stub loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · dropper |
| 难度 | easy |
| 首次出现 | 2026-11-18 10:18:04 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/7006f1de4a2c355cd4255e58df89accb487c2ea8fa61c894ae7f42057da06e51/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装系统运行时间</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">拼装随机临时文件</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">同步下载远程脚本</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">写入临时PowerShell</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">绕过执行策略启动</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `7006f1de4a2c355cd4255e58df89accb487c2ea8fa61c894ae7f42057da06e51` |
| MD5 | _未记录_ |
| 大小 | 7,664 字节（7.5 KB） |
| 类型 | other · `hta` |

## 行为分析

共 **7** 条行为，每条都挂了证据，且全部静态可得。

### 1. 伪装系统运行时间

`T1036` · 置信度 **高** · 静态

HTA 应用声明 APPLICATIONNAME="System Uptime"、标题同名,CAPTION="no"、BORDER="none"、SHOWINTASKBAR="no"、WINDOWSTATE="minimize",使窗口最小化且不在任务栏出现,把投递行为伪装成系统工具。

> **证据**：HTA:APPLICATION 块,字符串偏移 42(APPLICATIONNAME) / 116(SHOWINTASKBAR) / 140(WINDOWSTATE) / 205(title)
> 
> **来源**：`ev-000001`

### 2. 拼装随机临时文件

`T1074` · 置信度 **高** · 静态

通过 WScript.Shell.ExpandEnvironmentStrings 展开 %TEMP%,再拼接 12 位 A-Z 随机字母与 .ps1 后缀,生成难以预测的落盘路径。

> **证据**：FileService.tempDir(off=2307)、randomName(off=2440)、nameLength=12(off=918)、alphabet(off=972)
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 同步下载远程脚本

`T1105` · 置信度 **高** · 静态

创建 ActiveXObject("MSXML2.XMLHTTP"),以 open("GET", url, false) 同步请求 hxxp://104[.]168[.]70[.]178/187/secured_stub[.]ps1?IMAGE[.]PNG,并检查返回状态是否为 200,否则终止流程。

> **证据**：Settings.url(off=820)、NetworkService.fetch(off=3622: open/send)、status!==200 判断(off=6207)
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 写入临时PowerShell

`T1074.001` · 置信度 **高** · 静态

把 HTTP 响应的 responseText 通过 Scripting.FileSystemObject.CreateTextFile 覆盖写入上一步生成的 %TEMP% 随机 .ps1 文件。

> **证据**：FileService.write(off=2753: CreateTextFile(path,true) / file.Write)、persist 阶段(off=6344)
> 
> **来源**：`ev-000001` · `ev-000002`

### 5. 绕过执行策略启动

`T1059.001` · 置信度 **高** · 静态

以 WScript.Shell.Run 启动 powershell.exe,参数固定为 -ExecutionPolicy Bypass -WindowStyle Hidden -File "<落盘脚本>",即绕过 PowerShell 执行策略并直接执行下载脚本。

> **证据**：powershellArgs(off=1049)、ProcessService.runHidden(off=4265: command 拼接 / Com.shell.Run(off=4448))
> 
> **来源**：`ev-000001` · `ev-000002`

### 6. 隐藏窗口无感运行

`T1564.003` · 置信度 **高** · 静态

Run 的窗口样式参数为 0 且不等待返回,配合 -WindowStyle Hidden,使子进程无可见窗口、HTA 主窗口本身也最小化隐藏。

> **证据**：Com.shell.Run(command, 0, false)(off=4448);WINDOWSTATE="minimize"(off=140)
> 
> **来源**：`ev-000001`

### 7. 延时删除落地脚本

`T1070.004` · 置信度 **高** · 静态

启动子进程后设置 3000ms 定时器,到期删除 %TEMP% 下的 .ps1 并 window.close;任一阶段抛异常时同样删除已落盘文件并关闭窗口,减少磁盘残留。

> **证据**：cleanupDelay=3000(off=943)、schedule-cleanup 阶段(off=6564: setTimeout/DeleteFile/window.close)、失败清理(off=7403)
> 
> **来源**：`ev-000001` · `ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://104[.]168[.]70[.]178/187/secured_stub[.]ps1?IMAGE[.]PNG` | 80 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%TEMP%\<12 位随机大写字母>.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `104.168.70[.]178` | 是 | 静态 |
| `c2_port` | `80` | 是 | 静态 |
| `c2_uri` | `/187/secured_stub.ps1?IMAGE[.]PNG` | 是 | 静态 |
| `download_path` | `%TEMP%\<12 位 A-Z 随机字母>.ps1` | 是 | 静态 |
| `powershell_command` | `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "<script_path>"` | 是 | 静态 |
| `cleanup_delay_ms` | `3000` | 否 | 静态 |
| `encryption_algo` | `none` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得称为勒索软件或信息窃取器:本文件内没有任何文件加密、浏览器凭据、键盘记录或数据回传逻辑,其本体只是下载并执行远程 PowerShell。
- 不得断言第二阶段 secured_stub.ps1 的内容、家族或最终目的:本次未取得该响应体,payload 相关结论无证据支撑。
- 不得声称已建立持久化:样本没有写入 Run 键、服务、计划任务或启动目录,setTimeout 只是本进程内的 3 秒延时清理。
- 不得声称网络请求已被真实发出或被服务器接收:样本未在真实环境引爆,URL 可达性、返回内容与 C2 存活状态均未验证。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次为纯静态分析:该格式在当前环境没有隔离动态通道,样本未被执行,所有行为结论来自对其明文脚本的逐段解读。
2. 第二阶段 hxxp://104[.]168[.]70[.]178/187/secured_stub[.]ps1?IMAGE[.]PNG 未下载,最终载荷类型、后续 C2 与外联行为均未知,相关字段留空并标记待动态确认。
3. C2 的 recoverability 记为 static 且 pending_dynamic_verify=true:仅在脚本中读出该地址,没有任何真实请求/响应会话可佐证其存活。
4. 没有可用的厂商命名、数字签名或家族特征串,家族判定仅为行为族级描述,置信度低。
5. 未对 IP 104.168.70[.]178 做归属与信誉核查(无外网),其托管属性未知。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 抽取 ASCII 151 条字符串并给出偏移:HTA 应用声明、Settings.url(off=820)、powershellArgs(off=1049)、三个 ActiveXObject、各阶段与清理逻辑;无 flag 命中、无 UTF-16 字符串。 |
| `ev-000002` | evidence.record | 自写脚本核对文件完整性(7664 字节、0 个 NUL、无 base64 大块、仅 1 个 URL/1 个 IP、末尾止于 </html>)并还原五阶段投递流水线,同时复算 sha256 与 md5。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
