---
title: "恶意样本分析：AutoIt IExpress Loader（PE · exe · 33655b25）"
published: 2026-11-22
draft: false
description: "恶意（置信度低）：AutoIt IExpress Loader · loader/dropper · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["AutoIt IExpress", "loader", "dropper", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **AutoIt IExpress Loader**（存疑） · 置信度 **低**
> 
> 别名：ColorSync Dynamics loader、IExpress + AutoIt reflective loader
> 
> 该文件是改造自微软 Win32 Cabinet Self-Extractor(wextract)的 IExpress 自解压包，资源中内嵌 1.5MB CAB，解包后释放正版 AutoIt3 解释器与被编译/加密的 Bond.au3 脚本，并通过 cmd /c explorer.exe Hampton.lnk 建立指向 AutoIt3.exe Bond.au3 的快捷方式完成二次启动。静态还原出的 AutoIt 脚本实现手写 PE 反射映射、AMSI 绕过、分析环境检测、计划任务持久化与 %APPDATA% 下伪装目录落盘；动态沙箱中完整观测到“自解压→AutoIt→explorer→AutoIt 脚本”的进程链。综合为恶意的投放/加载器（loader/dropper）。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **AutoIt IExpress Loader** · 别名 ColorSync Dynamics loader、IExpress + AutoIt reflective loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · dropper |
| 难度 | medium |
| 首次出现 | 2026-11-20 17:10:54 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/33655b25377b44ca1fc1ee24c36a5e31e01926c217ee54113a3eb0213768ab39/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解包自解压载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">快捷方式拉起脚本</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">反射式映射PE</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">绕过AMSI扫描</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">探测分析环境</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `33655b25377b44ca1fc1ee24c36a5e31e01926c217ee54113a3eb0213768ab39` |
| MD5 | _未记录_ |
| 大小 | 1,806,336 字节（1.7 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **8** 条行为，每条都挂了证据；其中 **6** 条静态可得、**2** 条经动态分析取得。

### 1. 解包自解压载荷

`T1027.009` · 置信度 **高** · 动态

作为 IExpress 自解压包，将内嵌 CAB 中的 AutoIt3.exe 与 Bond.au3 释放到 %TEMP%\IXP000.TMP 后启动；资源区 SED 指令为 cmd /c explorer.exe Hampton.lnk & timeout /t 8 /nobreak。

> **证据**：动态进程/文件事件：PID 4000 于 23:42:23 创建 %TEMP%\IXP000.TMP\AutoIt3.exe；静态偏移 0x1B62E8 处 SED 命令串；.rsrc 含 MSCF CAB。
> 
> **来源**：`ref:357abbfdd8` · `ref:6a93ced2cf` · `ref:712c25af9b` · `ref:39066d348c`

### 2. 快捷方式拉起脚本

`T1204.002` · 置信度 **高** · 动态

解包后由 AutoIt3.exe /AutoIt3ExecuteLine 调用 FileCreateShortcut 生成 Hampton.lnk（目标 AutoIt3.exe，参数 Bond.au3），再以 explorer.exe Hampton.lnk 打开，经 explorer 拉起 C:\Users\<user>\AppData\Local\Temp\IXP000.TMP\AutoIt3.exe Bond.au3。

> **证据**：动态进程链（同一时间线）：cmd.exe /c explorer.exe Hampton.lnk -> explorer.exe Hampton.lnk -> AutoIt3.exe Bond.au3（父进程 explorer.exe，PID 4140）。
> 
> **来源**：`ref:6a93ced2cf` · `ref:357abbfdd8`

### 3. 反射式映射PE

`T1620` · 置信度 **高** · 静态

AutoIt 脚本内实现手写 PE 加载器：解析 IMAGE_DOS_HEADER/IMAGE_NT_HEADERS、分配可执行内存、按节复制、解析导入并修正重定位，最终用 DllCallAddress 调用入口点，无需落地 PE 文件即可执行内嵌载荷。

> **证据**：脚本明文字符串含 word Magic;byte MajorLinkerVersion;...;dword NumberOfRvaAndSizes 及 IMAGE_DOS_HEADER 结构；函数体内 DllCall(kernel32!VirtualAlloc/GetProcAddress) 与 DllCallAddress(入口)。
> 
> **来源**：`ref:39066d348c` · `ref:ed82ddd346`

### 4. 绕过AMSI扫描

`T1562.001` · 置信度 **中** · 静态

脚本解出 amsi.dll 与 AmsiScanBuffer 字符串，并在加载流程中定位/改写 AMSI 扫描函数，以规避内存/脚本内容检测（AMSI bypass）。

> **证据**：解码字符串命中 'amsi.dll'、'AmsiScanBuffer'；脚本调用 ntdll/kernel32 解析导出并修改内存。
> 
> **来源**：`ref:39066d348c`

### 5. 探测分析环境

`T1497.001` · 置信度 **中** · 静态

脚本内置虚拟化/沙箱/杀软进程名单（vmtoolsd.exe、VBoxTray.exe、SandboxieRpcSs.exe、avastui.exe、bdagent.exe），命中后提前退出，避免在分析环境中展开后续载荷。

> **证据**：解码字符串含 vmware/vbox/sandboxie/avast/bitdefender 进程名；动态中 AutoIt 脚本进程在启动约 2 秒内退出且无后续行为。
> 
> **来源**：`ref:39066d348c` · `ref:6a93ced2cf`

### 6. 计划任务持久化

`T1053.005` · 置信度 **中** · 静态

脚本携带完整计划任务 XML（URI \SpectraFox，LogonType InteractiveToken，RunLevel HighestAvailable，ExecutionTimeLimit PT0S），并具备调用 schtasks 创建任务的能力，用于开机/登录后重新拉起加载器。

> **证据**：解码字符串：<RegistrationInfo><URI>\SpectraFox</URI>、<RunLevel>HighestAvailable</RunLevel>、<LogonType>InteractiveToken</LogonType>、hxxp://schemas[.]microsoft[.]com/windows/2004/02/mit/task。
> 
> **来源**：`ref:39066d348c`

### 7. 伪装目录落盘

`T1036.005` · 置信度 **中** · 静态

以仿冒厂商目录 %APPDATA%\ColorSync Dynamics\ 存放 H.au3、AutoIt3.exe、notfound.dat 与 SpectraFox.lnk，文件名与目录名具有伪装/规避特征。

> **证据**：解码路径：\ColorSync Dynamics\H.au3、\ColorSync Dynamics\AutoIt3.exe、\ColorSync Dynamics\notfound.dat、\ColorSync Dynamics\SpectraFox.lnk。
> 
> **来源**：`ref:39066d348c`

### 8. 内嵌加密大载荷

`T1027.013` · 置信度 **高** · 静态

脚本以 215 段十六进制字符串拼出 392926 字节载荷，并用运行时密钥/自解密 stub 处理后交给反射映射器；该载荷是最终执行体，静态下无法还原为 PE。

> **证据**：$DUVISMREQ 由 215 个 3638 字符十六进制片段拼接（总 785852 hex 字符）；载荷熵约 7.997，长度 392926 ≡ 14 (mod 16)；出现 16 字节重复密钥材料 D3B105F5B61A538037ECE4099F40FB06。
> 
> **来源**：`ref:39066d348c` · `ref:ed82ddd346`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `%TEMP%\IXP000.TMP\AutoIt3.exe`
- `%TEMP%\IXP000.TMP\Bond.au3`
- `%TEMP%\IXP000.TMP\Hampton.lnk`
- `%APPDATA%\ColorSync Dynamics\H.au3`
- `%APPDATA%\ColorSync Dynamics\AutoIt3.exe`
- `%APPDATA%\ColorSync Dynamics\notfound.dat`
- `%APPDATA%\ColorSync Dynamics\SpectraFox.lnk`

**计划任务**

- `\SpectraFox`
- `\Integrating`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `install_path` | `%APPDATA%\ColorSync Dynamics\` | 是 | 静态 |
| `dropped_files` | `H.au3;AutoIt3.exe;notfound.dat;SpectraFox.lnk` | 是 | 静态 |
| `scheduled_task_name` | `\SpectraFox` | 否 | 静态 |
| `embedded_payload_size` | `392926` | 是 | 静态 |
| `payload_protection` | `十六进制内嵌 + 运行时解密/自解密 stub + 反射式 PE 映射` | 是 | 静态 |
| `loader_technique` | `AutoIt 手写 PE 映射器（解析 IMAGE_DOS_HEADER/IMAGE_NT_HEADERS，VirtualAlloc，DllCallAddress 调用入口）` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得因样本带微软 wextract 版本信息/签名外观就判为良性或“合法自解压工具”：.rsrc 内嵌的 CAB 与 AutoIt 加载器才是实际行为。
- 未观测到任何 C2 会话（网络监控仅有系统自身流量），不得编造 C2 地址/端口，也不得据此断定其为远控/窃密家族。
- 不得声称已实际观察到计划任务/注册表被创建：目前只有脚本内的任务 XML 与命令字符串证据，动态遥测未见相应创建事件。
- 反射映射发生在 AutoIt 进程内，并未观测到跨进程注入或进程镂空，不要报成 injector/process hollowing。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `956ff12aac9252d44069817a7733a233f504ea9632aff082819b56603dd56501`） |

**局限与待验证**

1. 内嵌 392926 字节载荷未能在静态下解密（XOR/16 字节重复密钥/AES 尝试均失败），最终 C2、家族归属与载荷功能无法确证；需真机内存取证（在解密/映射完成后抓取 AutoIt 进程内存）。
2. 动态沙箱中 AutoIt 脚本进程启动后数秒内退出，未产生网络连接、持久化写入或子进程；结合脚本内的虚拟化/沙箱进程名单，推断为环境检测导致的主动退出，但这属于推断而非直接观测。
3. 未取得 .au3 加载器执行后的内存转储（进程存活时间过短），因此反射映射/AMSI 绕过仅有静态脚本证据，未获运行时内存佐证。
4. 本次未观察到主机持久化（计划任务/注册表 Run 键）实际落地，相关能力来自脚本内明文字符串与任务 XML。
5. AutoIt3.exe 为签名正版解释器，不代表其行为合法；该二进制本身不含恶意逻辑。

## 证据索引

<details>
<summary>展开 10 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1/imphash/rich 头 |
| `ev-000004` | scan.entropy | 逐段熵：.rsrc 熵 7.976（内嵌压缩 CAB） |
| `ev-000011` | 字符串提取 | 字符串抽取；短串阶段已见 wextract/IExpress 特征 |
| `ev-000015` | 字符串提取 | 长串阶段命中 SED 命令：cmd /c explorer.exe Hampton.lnk 与 AutoIt3.exe /AutoIt3ExecuteLine FileCreateShortcut(...) |
| `ev-000016` | evidence.record | 静态拆包/脚本还原/字符串解码（CAB、Bond.au3、AutoIt3.exe、1819 条明文、计划任务与路径 IOC） |
| `ev-000017` | evidence.record | 内嵌 391KB 载荷的静态解密尝试与失败结论 |
| `telemetry:33655b25` | 动态遥测 | 动态遥测记录到：监控组件 注册表事件 2 条；监控组件 进程/文件事件 127 条；ETW 短命进程事件 3 条；已过滤工具/系统噪声 26 条 |
| `etw:33655b25:4000` | 进程事件监控 | 短命进程事件：33655b25377b44ca1fc1ee24c36a5e31e01926c217ee54113a3eb0213768ab39.exe（pid 4000；MD5=A75F7EB5D62E36C994DF43B2D26A87A4,SHA256=33655B25377B44CA1FC1EE24C36A5E31E01926C217EE54113A3EB0213768AB39,IMPHASH=89A4228E8581F783C2AB1992D9178F8E） |
| `etw:33655b25:4952` | 进程事件监控 | 短命进程事件：AutoIt3.exe（pid 4952；MD5=80CDD5F19D704A001589976BAE277BAB,SHA256=5D69A932A077FEE044B193C28E84564143F5C7E51079AB48E88FEF74AB0B77B7,IMPHASH=3614AFAB8D930EE31934510EDB015CDC） |
| `etw:33655b25:4140` | 进程事件监控 | 短命进程事件：AutoIt3.exe（pid 4140；MD5=80CDD5F19D704A001589976BAE277BAB,SHA256=5D69A932A077FEE044B193C28E84564143F5C7E51079AB48E88FEF74AB0B77B7,IMPHASH=3614AFAB8D930EE31934510EDB015CDC） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
