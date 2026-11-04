---
title: "恶意样本分析：Unattributed MSI reflective loader（other · msi · 9666fe7e）"
published: 2026-11-03
draft: false
description: "恶意（置信度低）：Unattributed MSI reflective loader · loader/dropper · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["loader", "dropper", "MSI"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unattributed MSI reflective loader**（存疑） · 置信度 **低**
> 
> MSI 数据库内仅有的自定义动作 Type=4166 为 64 位 VBScript，挂载在 InstallExecuteSequence 序号 1534（NOT REMOVE），安装过程中会从 Binary 表取出 PowerShell 脚本写入 %TEMP% 并以隐藏窗口 PowerShell 执行；该 PowerShell 再反射读取第二个 Binary 流、按自定义转置算法还原出一个 1.43 MB 的 PE32+ x64 载荷并手工映射执行。整条链可由包内字节与脚本还原，属于典型的无文件/反射加载安装包。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unattributed MSI reflective loader** · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · dropper |
| 难度 | medium |
| 首次出现 | 2026-11-01 17:17:42 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/9666fe7e1ff1f42bc8e9035cb54358dfeab009970ed005d3e2c9ecd1b54a40dc/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">安装即触发隐藏 VBScript</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">从安装包读取脚本</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口拉起 PowerShell</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">解码第二层加载器</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">转置还原内嵌 PE</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `9666fe7e1ff1f42bc8e9035cb54358dfeab009970ed005d3e2c9ecd1b54a40dc` |
| MD5 | _未记录_ |
| 大小 | 3,032,064 字节（2.9 MB） |
| 类型 | other · `msi` |

## 行为分析

共 **9** 条行为，每条都挂了证据，且全部静态可得。

### 1. 安装即触发隐藏 VBScript

`T1059.005` · 置信度 **高** · 静态

MSI 自定义动作 PQKh1GUxbiud 为 Type=4166（VBScript、64 位脚本、失败继续），排在 InstallExecuteSequence 第 1534 步、条件 NOT REMOVE，在 InstallInitialize(1500) 之后立即执行，无需用户交互。

> **证据**：CustomAction 表: Type=4166, Source=pTSPSnJ00twr, Target=C2wYrqeGRUN; InstallExecuteSequence: PQKh1GUxbiud=1534
> 
> **来源**：`ev-000096`

### 2. 从安装包读取脚本

`T1140` · 置信度 **高** · 静态

VBScript 通过 Session.Database.OpenView 执行 SELECT `Data` FROM `Binary` WHERE `Name`='orAiO4EgE7'，把包内 PowerShell 脚本用 ADODB.Stream 以 windows-1252 写入 %TEMP%\<随机数>.ps1。

> **证据**：VBScript: ivygsiq="SELECT `Data` FROM `Binary` WHERE `Name`='orAiO4EgE7'"; ADODB.Stream.SaveToFile dyhca,2
> 
> **来源**：`ev-000097`

### 3. 隐藏窗口拉起 PowerShell

`T1059.001` · 置信度 **高** · 静态

以 %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File <临时 ps1> <MSI 路径> 方式运行并等待返回，随后删除临时脚本。

> **证据**：ckcj="""" & ybpsnhhz & """ -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & dyhca ...; sefltemlri.Run ckcj,0,True
> 
> **来源**：`ev-000097`

### 4. 解码第二层加载器

`T1027` · 置信度 **高** · 静态

PowerShell 从内嵌十进制点对字符串（'a.b' -> b*16+a）还原出 10090 字节反射加载器，再用 [powershell]::Create.AddScript 在同一进程内执行，不落盘。

> **证据**：$vJ7g1y3E9GZup.Add([byte]([int]$G5xvZ0n[1]*16+[int]$G5xvZ0n[0])); $YVcf5k9cWXTj.AddScript($mFfXYu7EuB8p)
> 
> **来源**：`ev-000097`

### 5. 转置还原内嵌 PE

`T1140` · 置信度 **高** · 静态

反射加载器用 Reflection.Emit 声明 msi.dll 的 MsiOpenDatabase/MsiDatabaseOpenView/MsiViewExecute/MsiViewFetch/MsiRecordReadStream，读取 Binary 流 SfILm5Js，按 4 字节头（步长 2、偏移 0、反转标志 0）做转置，还原出 PE32+ x64 文件（sha256 1fa8d8fe...，1430016 字节）。

> **证据**：$Vj9izBm3YRlsH='SfILm5Js'; $o1675[$r5219]=$KeZy0hIuw4mWuD[4+($r5219*$w8159)+$f9811]; e_lfanew check + machine 0x20B
> 
> **来源**：`ev-000097`

### 6. 手工映射并执行载荷

`T1620` · 置信度 **高** · 静态

若 CLR 目录为 0，则使用 VirtualAlloc/VirtualProtect 按 PE 头布局把载荷映射到内存并调用入口点；CLR 目录非 0 时改用 Assembly.Load 执行，属于反射式代码加载。

> **证据**：$d7PeWRDT0v::VirtualAlloc(...12288,4); VirtualProtect; [Reflection.Assembly]::Load($KeZy0hIuw4mWuD); EntryPoint.Invoke
> 
> **来源**：`ev-000097` · `ref:78892cdf68`

### 7. 伪装成均衡器应用

`T1036.005` · 置信度 **中** · 静态

载荷带伪造版本信息（Media Code Core / Equalizer Renderer Desktop / equalizer_renderer）与 25 张位图资源、GUI 窗口导入（CreateWindowExA/RegisterClassA/ShowWindow），用于伪装成正常桌面程序；代码段另有大量无意义指令与随机常量填充。

> **证据**：VS_VERSION_INFO: CompanyName=Media Code Core, FileDescription=Equalizer Management and Refactor Service; .rsrc 含 25 个 BITMAP; imports USER32 CreateWindowExA/RegisterClassA/ShowWindow
> 
> **来源**：`ref:850390c96b` · `ref:78892cdf68` · `ref:cf94d56592`

### 8. 释放低熵标记文件

`T1036` · 置信度 **高** · 静态

File/Component/Directory 表把 cab1.cab 中 36 字节文件释放为 %LOCALAPPDATA%\L4PjdK9K3\lAJ3abdB.ini，内容为两个随机令牌加 16 位十六进制串，可作感染/活动标记。

> **证据**：File: dljO6DyTNmT1K -> lAJ3abdB.ini, 36 bytes, Component FLlml5rFIbrOu, Directory JM1crRaqKS3(LocalAppDataFolder); cab 内容 TLvrxBmv FxwJ3gkF6 fa5371cd64b61a55
> 
> **来源**：`ev-000096`

### 9. 加密第二阶段数据段

`T1027` · 置信度 **高** · 静态

还原出的 PE 中 .rdata 约 551 KB、熵 7.998，前 0x8D000 区间几乎全随机；.text 仅 46 KB 且充满无效指令，说明最终功能载荷仍被加密/混淆，静态无法取出。

> **证据**：.rdata rva=53248 size=551424 entropy=7.998; .text entropy=6.028; 0x1000 起 entry 为 jmp 0x140001000
> 
> **来源**：`ref:bea450dde0` · `ref:850390c96b` · `ref:985b898bed`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `%LOCALAPPDATA%\L4PjdK9K3\lAJ3abdB.ini`
- `%TEMP%\<随机数>.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `custom_action` | `PQKh1GUxbiud / Type=4166 / Source=pTSPSnJ00twr / Target=C2wYrqeGRUN / Sequence=1534 / Condition=NOT REMOVE` | 是 | 静态 |
| `binary_ps1_stream` | `orAiO4EgE7 (84305 bytes, PowerShell 解码壳)` | 是 | 静态 |
| `binary_payload_stream` | `SfILm5Js (2860036 bytes, 转置打包的 PE32+ x64)` | 是 | 静态 |
| `payload_decode_params` | `header[0]=2 (stride), header[1]=0 (offset), header[2]=0 (reverse), 数据从第 4 字节起取 byte[4+i*stride+offset]` | 是 | 静态 |
| `install_path` | `%LOCALAPPDATA%\L4PjdK9K3\lAJ3abdB.ini` | 是 | 静态 |
| `marker_content` | `TLvrxBmv FxwJ3gkF6 fa5371cd64b61a55` | 否 | 静态 |
| `product_code` | `{7EF695EE-EE0C-4231-B342-0043193AB92A}` | 是 | 静态 |
| `upgrade_code` | `{000D8C9B-FC91-4BE1-8A76-4614ADD918A6}` | 否 | 静态 |
| `install_scope` | `per-user (MSIINSTALLPERUSER=1)` | 否 | 静态 |
| `env_var` | `VjOAY8awfi5zo (承载 MSI 原始路径, 传给 PowerShell)` | 否 | 静态 |
| `stage2_sha256` | `1fa8d8fe397706f55fe93ace8a4e19ae06d52d5affa078e7d9d9b56ac205a38a` | 否 | 静态 |
| `encryption_algo` | `自定义转置(外壳) + 未知算法加密的第二阶段 .rdata(约 512 KB, 熵 7.998)，未解出` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得称为勒索软件或窃密木马：未观测到文件加密、凭据/浏览器数据访问等行为。
- 不得声称存在 C2 外联或下载行为：静态未发现 URL/IP，仿真未产生网络事件，c2 为空。
- 不得断言具备服务、计划任务等持久化：MSI 表与代码中均未发现相应项。
- 不得把 .rdata 高熵区直接认定为最终 RAT 载荷或具体家族：该区尚未解密。
- 不得把 MSI 的卸载注册表项当作恶意持久化证据：那是 Windows Installer 的标准登记。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 是（stage2 `1fa8d8fe397706f55fe93ace8a4e19ae06d52d5affa078e7d9d9b56ac205a38a`） |

**局限与待验证**

1. 本次为纯静态分析，未执行 MSI 安装流程，也未在真实主机运行还原出的 PE；所有行为来自脚本/数据库/PE 结构证据，reproduced=false。
2. 第二阶段 PE（1.43 MB）的 .rdata 约 512 KB 为高熵加密数据，未解出密钥/算法，因此其最终 C2、窃密或远控功能无法确认，c2 为空。
3. 对还原 PE 的用户态指令仿真仅执行到 2 个 API（InitializeCriticalSection、__acrt_iob_func）即停止，未产生文件/网络/注册表事件，不能据此排除运行期行为。
4. 未获得厂商引擎或 YARA 佐证，家族归属不确定（uncertain=true），仅按技术链归类为 MSI 反射加载器。
5. MSI 安装会在 %LOCALAPPDATA% 下创建目录并写入 .ini，实际落地路径中的用户目录因环境不同而不同。

## 证据索引

<details>
<summary>展开 10 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000096` | evidence.record | 只读解析 MSI 数据库：CustomAction Type=4166/VBScript/seq1534、三条 Binary 流、File/Component/Directory 释放路径与标记内容、ProductCode/UpgradeCode |
| `ev-000097` | evidence.record | 还原执行链：VBScript 取 Binary orAiO4EgE7 写 %TEMP% ps1 并隐藏运行 PowerShell；PowerShell 十进制解码 10090 字节反射加载器；读取 SfILm5Js 转置还原 PE 并手工映射/Assembly.Load |
| `ref:850390c96b` | PE 结构解析 | 还原载荷结构：PE32+ x64 GUI，7 节，入口 RVA 36934，CLR 目录为 0，.rsrc 806824 字节 |
| `ref:78892cdf68` | 导入表解析 | 还原载荷导入表：KERNEL32(VirtualAlloc/VirtualProtect/VirtualQuery/线程池)、USER32 窗口 API、MSVC CRT；imphash 241b6302ab625ed2e79213b6b4dfdeb2 |
| `ref:bea450dde0` | scan.entropy | 还原载荷段熵：.rdata 7.998（加密/压缩）、.text 6.028、整体 4.741 |
| `ref:cf94d56592` | 字符串提取 | 还原载荷字符串：版本信息/导入名/大量代码字节；未见 URL 或 C2 |
| `ref:5a8eaf0bcc` | 字符串提取 | MSI 原始字符串扫描：ASCII 3183 条、UTF-16 292 条；可见 ProductCode、ComponentId 等安装数据库串 |
| `ref:03766d62e6` | dyn.run | 还原载荷用户态仿真：仅执行 InitializeCriticalSection 与 __acrt_iob_func，无文件/网络/注册表事件 |
| `ref:985b898bed` | disasm.function | 入口点反汇编：0x140001000 先设置全局状态并调用 0x140001020；含 PEB 访问与 CRT 初始化 |
| `ref:d5336f7ac0` | disasm.function | TLS 回调反汇编：0x14000b340 为标准 CRT TLS 初始化循环，非反调试 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
