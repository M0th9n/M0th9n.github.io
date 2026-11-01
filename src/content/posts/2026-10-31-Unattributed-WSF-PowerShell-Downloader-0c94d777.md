---
title: "恶意样本分析：Unattributed WSF/PowerShell Downloader（other · wsf · 0c94d777）"
published: 2026-10-31
draft: false
description: "恶意（置信度低）：Unattributed WSF/PowerShell Downloader · downloader/loader · 难度 easy · 纯静态分析"
tags: ["downloader", "loader", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unattributed WSF/PowerShell Downloader**（存疑） · 置信度 **低**
> 
> 别名：JScript WSF downloader、KMK.PS1 loader、WSF PowerShell dropper
> 
> 样本为未混淆的 Windows Script File(JScript),完整源码可直接阅读:执行即创建 C:\Temp\,以 MSXML2.XMLHTTP 同步 GET 硬编码的 hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK[.]PS1,将返回文本写入 C:\Temp\<8 位随机名>.ps1,再以 powershell.exe -nop -ep bypass -file 隐藏窗口启动。该链条无任何合法用途,属典型的下载-落地-执行(downloader/loader)行为;第二阶段 PS1 未获取、未动态执行,故不采用最高证据级别,也未将任何运行期结论视为已观测。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unattributed WSF/PowerShell Downloader** · 别名 JScript WSF downloader、KMK.PS1 loader、WSF PowerShell dropper · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · loader |
| 难度 | easy |
| 首次出现 | 2026-10-30 11:54:05 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/0c94d77776c08b660932586745e3e5c65c6754217c992e62a0a7e8a90f9b7fd9/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解析WSF执行JScript</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.007</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">创建临时暂存目录</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">HTTPS同步GET下载</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">接收远程PS1载荷</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">失败重试两次</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `0c94d77776c08b660932586745e3e5c65c6754217c992e62a0a7e8a90f9b7fd9` |
| MD5 | _未记录_ |
| 大小 | 3,591 字节（3.5 KB） |
| 类型 | other · `wsf` |

## 行为分析

共 **9** 条行为，每条都挂了证据，且全部静态可得。

### 1. 解析WSF执行JScript

`T1059.007` · 置信度 **高** · 静态

文件为 <job><script language="JScript"> 结构,脚本体置于 CDATA 中;加载后立即执行 Api.run,无用户交互,宿主通常为 wscript.exe/cscript.exe。

> **证据**：off 0x1E '<script language="JScript">';off 0xDB1 'Api.run;';off 0xDC5 'this.ScriptAPI = Api;'
> 
> **来源**：`ev-000001`

### 2. 创建临时暂存目录

`T1074.001` · 置信度 **高** · 静态

通过 Scripting.FileSystemObject 检查 C:\Temp\ 是否存在,不存在则 CreateFolder 创建,为落盘做准备;失败即整体退出。

> **证据**：off 0x404 fs.FolderExists(State.dir);off 0x434 fs.CreateFolder(State.dir)
> 
> **来源**：`ev-000001`

### 3. HTTPS同步GET下载

`T1071.001` · 置信度 **高** · 静态

以 MSXML2.XMLHTTP 对硬编码 URL 发起同步 GET(http.open('GET', url, false); http.send),仅当 status===200 时取 responseText 作为载荷。

> **证据**：off 0x5AF http.open('GET', State.url, false);off 0x5E4 http.send;off 0x602 http.status === 200
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 接收远程PS1载荷

`T1105` · 置信度 **高** · 静态

把 HTTP 响应体当作 PowerShell 脚本内容接收,大小与内容不做任何校验,失败时回退为 null 并进入重试分支。

> **证据**：off 0x62E result = http.responseText;突发异常时 off 0x68D result = null
> 
> **来源**：`ev-000001`

### 5. 失败重试两次

`T1105` · 置信度 **高** · 静态

do/while 循环最多重试 2 次(State.retries=2),直到拿到非空内容为止,提升在临时网络故障下的投递成功率。

> **证据**：off 0x153 retries: 2;off 0x6FB while (result === null && triesLeft-- > 0)
> 
> **来源**：`ev-000001` · `ev-000002`

### 6. 随机名脚本落盘

`T1105` · 置信度 **高** · 静态

从 A-Z0-9 池生成 8 位随机文件名,用 CreateTextFile/Write/Close 把下载内容写成 C:\Temp\<随机名>.ps1,落地文件名不可预知。

> **证据**：off 0x831 pool='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';off 0x936 CreateTextFile(target, true);off 0x971 handle.Write(script)
> 
> **来源**：`ev-000001`

### 7. 调用PowerShell执行

`T1059.001` · 置信度 **高** · 静态

通过 WScript.Shell.Run 启动 powershell.exe -nop -ep bypass -file "<落地脚本>",把执行权交给第二阶段脚本。

> **证据**：off 0x9B3 sh.Run('powershell.exe -nop -ep bypass -file "' + target + '"', 0, true)
> 
> **来源**：`ev-000001` · `ev-000002`

### 8. 关闭执行策略限制

`T1562.001` · 置信度 **高** · 静态

命令行固定携带 -nop(NoProfile)与 -ep bypass(ExecutionPolicy Bypass),削弱 PowerShell 默认脚本执行与配置约束。

> **证据**：off 0x9B3 命令行中的 '-nop -ep bypass' 参数
> 
> **来源**：`ev-000001`

### 9. 隐藏窗口静默运行

`T1564.003` · 置信度 **高** · 静态

Run(cmd, 0, true) 以窗口样式 0 启动且同步等待返回,用户在屏幕上不会看到控制台窗口。

> **证据**：off 0x9E9 Run 的 intWindowStyle 参数为 0、bWaitOnReturn 为 true
> 
> **来源**：`ev-000001`


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
- `C:\Temp\<8 位 A-Z0-9 随机名>.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `denizcerceve[.]com (hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK[.]PS1)` | 是 | 静态 |
| `payload_url` | `hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK[.]PS1` | 是 | 静态 |
| `stage2_filename` | `KMK.PS1` | 是 | 静态 |
| `install_path` | `C:\Temp\<8 位 A-Z0-9 随机名>.ps1` | 是 | 静态 |
| `staging_dir` | `C:\Temp\` | 是 | 静态 |
| `launch_cmdline` | `powershell.exe -nop -ep bypass -file "<staged .ps1>"` | 是 | 静态 |
| `retry_count` | `2` | 否 | 静态 |
| `encryption_algo` | `none (明文 HTTP 响应直接写盘,无编码/加密)` | 否 | 静态 |
| `control_interface` | `this.ScriptAPI.config(key, value) 可在宿主内改写 URL/目录/重试次数` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 未见任何持久化机制(无注册表 Run 键、无服务、无计划任务、无启动目录写入),不应称其为持久化后门。
- 样本中不存在凭据读取、浏览器数据收集或文件加密代码,不应归为 stealer / ransomware;它只是投递链的第一跳。
- 第二阶段 KMK.PS1 未获取、未执行,其最终载荷类型(RAT/挖矿/勒索等)未知,不应凭本文件断言最终家族或能力。
- 无法确认 denizcerceve[.]com 是攻击者注册的专用基础设施还是被滥用的合法站点(其图片目录路径形似被入侵的 CMS),不应直接将其定性为专用 C2 面板。
- 脚本为明文可读、无编码或加密层,不应归类为加壳或混淆样本。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 未执行样本,所有运行期结论(实际请求、写盘、进程创建)均为源码直读推断,未经实际观测确认。
2. 第二阶段 hxxps://denizcerceve[.]com/.../KMK[.]PS1 未下载,载荷内容、最终行为与家族归属未知;c2 条目为投递地址而非交互式 C2,标记待动态验证。
3. 域名 denizcerceve[.]com 的当前状态与归属未核实(未做外网/DNS 查询),PATH 形似被入侵站点的图片目录,但无法证实。
4. 无网络情报与厂商命名可交叉验证,family 字段为候选占位,uncertain=true。
5. 旁路文件 *.zip 为加密压缩包(非样本本体),未参与本次分析。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 字符串抽取:ASCII 105 条 / UTF-16LE 0 条,完整还原脚本语义所需的关键串与偏移(URL、C:\Temp\、三个 COM 对象、sh.Run 命令行、重试次数)。 |
| `ev-000002` | evidence.record | 自写脚本核对哈希与结构化配置:sha256 与文件名一致,md5=8eccc460cc282502e90d97970d570b9c,3591 字节,CRLF;抽取 URL/COM 对象/暂存目录/启动命令行/重试次数,确认全文无编码混淆。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
