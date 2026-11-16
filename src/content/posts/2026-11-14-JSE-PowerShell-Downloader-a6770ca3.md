---
title: "恶意样本分析：JSE PowerShell Downloader（other · jse · a6770ca3）"
published: 2026-11-14
draft: false
description: "恶意（置信度低）：JSE PowerShell Downloader · downloader/loader · 难度 easy · 纯静态分析"
tags: ["JSE", "downloader", "loader"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **JSE PowerShell Downloader**（存疑） · 置信度 **低**
> 
> 别名：JScript downloader、PowerShell 载荷投递器
> 
> 样本为未混淆的明文 JScript 下载器。源码直接显示完整攻击链：创建 C:\Temp 暂存目录，通过 MSXML2.XMLHTTP 以 HTTPS 同步 GET 下载 hxxps://www[.]studio-cf[.]com/5f8bwp/C1KMK.ps1，将响应体写成 8 位随机大写文件名的 .ps1，再用 WScript.Shell.Run 以隐藏窗口启动 powershell.exe -nop -ep bypass -file 执行。下载并执行远程脚本的行为在源码中完整可见，无需依赖外部引擎判定。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **JSE PowerShell Downloader** · 别名 JScript downloader、PowerShell 载荷投递器 · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · loader |
| 难度 | easy |
| 首次出现 | 2026-11-12 07:42:12 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/a6770ca3b3072d5033614da556532f2dfb0c227caedbc3ccf2a7dc073fe790b3/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">创建暂存目录</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">经HTTPS拉取载荷</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">下载远程脚本</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">随机名落盘脚本</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口执行</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `a6770ca3b3072d5033614da556532f2dfb0c227caedbc3ccf2a7dc073fe790b3` |
| MD5 | _未记录_ |
| 大小 | 4,836 字节（4.7 KB） |
| 类型 | other · `jse` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 创建暂存目录

`T1074.001` · 置信度 **高** · 静态

通过 Scripting.FileSystemObject 检查并创建 C:\Temp\ 目录，作为后续载荷落盘位置。

> **证据**：偏移 1060 附近 f.CreateFolder(dirPath)，目录常量 'C:\\Temp\\'（偏移 223）
> 
> **来源**：`ev-000001`

### 2. 经HTTPS拉取载荷

`T1071.001` · 置信度 **高** · 静态

使用 MSXML2.XMLHTTP 以同步 GET 请求访问 hxxps://www.studio-cf[.]com/5f8bwp/C1KMK.ps1，状态码 200 时取 responseText 作为下一阶段内容。

> **证据**：偏移 2083 xhr.open('GET', url, false)；偏移 2133 xhr.send；URL 常量偏移 155
> 
> **来源**：`ev-000001`

### 3. 下载远程脚本

`T1105` · 置信度 **高** · 静态

从远程站点下载 PowerShell 脚本内容，构成入站工具传输；下载失败时最多重试 2 次。

> **证据**：偏移 2017 while (attempt <= attempts)，attempts 默认 2；stageDownload 调用 net.fetch
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 随机名落盘脚本

`T1105` · 置信度 **高** · 静态

将下载内容通过 CreateTextFile 写入 C:\Temp\ 下 8 位随机大写字母数字命名的 .ps1 文件，增加文件识别难度。

> **证据**：偏移 1384 Math.random.toString(36).substring(2, 10)；偏移 1562 CreateTextFile(filePath, true)；偏移 1625 handle.Write(content)
> 
> **来源**：`ev-000001`

### 5. 隐藏窗口执行

`T1564.003` · 置信度 **高** · 静态

调用 WScript.Shell.Run 启动 powershell.exe，窗口样式参数为 0（隐藏）并等待执行完成，使用户不可见载荷运行。

> **证据**：偏移 2960 shell.Run(command, 0, true)
> 
> **来源**：`ev-000001`

### 6. 绕过执行策略

`T1562.001` · 置信度 **高** · 静态

命令行使用 -nop -ep bypass 关闭 PowerShell 配置文件加载并绕过执行策略，直接执行下载脚本。

> **证据**：偏移 2868 命令字符串 'powershell.exe -nop -ep bypass -file "' + scriptPath
> 
> **来源**：`ev-000001` · `ev-000002`

### 7. 以JScript运行

`T1059.007` · 置信度 **高** · 静态

脚本以 Windows Script Host 的 JScript 形式运行，通过 ActiveXObject 实例化 FileSystemObject、WScript.Shell 与 MSXML2.XMLHTTP 并缓存复用。

> **证据**：偏移 513 new ActiveXObject(progId)；偏移 648/713/768 分别创建 FileSystemObject、WScript.Shell、MSXML2.XMLHTTP
> 
> **来源**：`ev-000001`

### 8. 重置远程配置

`T1105` · 置信度 **中** · 静态

暴露 config/reset 接口，可改写或恢复远程地址、暂存目录与重试次数，便于二次投递时更换载荷 URL。

> **证据**：偏移 4097 config(key, value) 修改 runtime.settings；偏移 4340 reset 恢复默认 URL
> 
> **来源**：`ev-000001`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://www.studio-cf[.]com/5f8bwp/C1KMK.ps1` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\Temp\`
- `C:\Temp\%RANDOM%.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `www.studio-cf[.]com` | 是 | 静态 |
| `c2_url` | `hxxps://www.studio-cf[.]com/5f8bwp/C1KMK.ps1` | 是 | 静态 |
| `staging_dir` | `C:\Temp\` | 是 | 静态 |
| `payload_filename_pattern` | `%RANDOM_8_UPPER%.ps1` | 是 | 静态 |
| `retry_count` | `2` | 否 | 静态 |
| `launch_command` | `powershell.exe -nop -ep bypass -file "C:\Temp\<RANDOM>.ps1"` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得仅因 PowerShell 下载与执行就判定为勒索软件、窃密软件或挖矿程序：脚本中没有文件加密、凭据收集或矿池通信代码，下载的 PowerShell 载荷内容未获取。
- 不得声称样本已建立 C2 会话或成功回连：仅从源码确认存在 HTTPS GET 下载地址，未在真实网络环境中观测到请求/响应。
- 不得声称存在持久化（注册表 Run 键、计划任务、服务）：源码中未见任何持久化 API 或命令。
- 不得把 studio-cf[.]com 直接认定为攻击者自有基础设施：该域名可能为被入侵的合法站点，需结合托管内容进一步确认。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次为纯静态分析，未运行样本，也未访问远程 URL，因此无法确认 hxxps://www.studio-cf[.]com/5f8bwp/C1KMK.ps1 当前是否仍可访问及其实际内容。
2. 第二阶段 PowerShell 脚本未取得，其最终行为（如信息窃取、持久化、横向移动）无法判定；behavior_class 仅反映第一阶段的下载/加载能力。
3. 无网络会话或沙箱行为遥测，C2 条目按静态提取标注，待动态验证。
4. 脚本无家族专属特征，family 字段为行为类型命名，归因存在不确定性。
5. 样本路径显示为 .jse，但内容实际是未编码的明文 JScript（非 Microsoft JScript Encoded 编码），可能经过二次保存或改写。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | ASCII 字符串 133 条、UTF-16LE 0 条、flag 命中 0；完整还原脚本源码，含远程 URL、C:\Temp\ 路径、ActiveXObject/XMLHTTP/CreateTextFile/WScript.Shell.Run 及 powershell.exe -nop -ep bypass -file 命令。 |
| `ev-000002` | evidence.record | 静态读取明文 JScript 并计算哈希（sha256 与题面一致，md5 be7ad4a1b9b4db1a524e44136519acd0，sha1 85e27450f6da593fa4f2a23b70130b42710d7916）；整理下载-落盘-隐藏执行的调用链，确认未执行样本。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
