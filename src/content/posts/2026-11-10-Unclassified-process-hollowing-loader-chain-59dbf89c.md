---
title: "恶意样本分析：Unclassified process-hollowing loader chain（other · vbe · 59dbf89c）"
published: 2026-11-10
draft: false
description: "恶意（置信度低）：Unclassified process-hollowing loader chain · dropper/loader · 难度 medium · 纯静态分析"
tags: ["dropper", "loader"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unclassified process-hollowing loader chain**（存疑） · 置信度 **低**
> 
> 多层静态解密与 .NET IL 反编译自证完整攻击链：伪装 .vbe 的脚本内嵌 2 MB Base64 的 PowerShell 脚本，该脚本以 AES-256-CBC 解出第二阶段 PowerShell，再以 Base64+XOR 解出并反射加载 .NET 程序集；该程序集解析 kernel32/ntdll 的 VirtualAllocEx/WriteProcessMemory/ReadProcessMemory/ZwUnmapViewOfSection/CreateProcessA/SetThreadContext/ResumeThread，定义对应委托与 PROCESS_INFORMATION/STARTUPINFO 结构，配合 PowerShell 传入的目标路径 aspnet_compiler.exe 与 284672 字节高熵 PE，构成典型进程镂空注入加载器。未进行真实引爆，C2 未恢复。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unclassified process-hollowing loader chain** · _存疑_ |
| 置信度 | **低** |
| 行为类 | dropper · loader |
| 难度 | medium |
| 首次出现 | 2026-11-08 16:24:18 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/59dbf89c137441569e22add76ff1208a846c6b5cd1e695d2960bace52df7765e/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装VBE投递脚本</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">释放随机名PS1</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口执行PS1</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">AES解密下一阶段</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">反射加载.NET注入器</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `59dbf89c137441569e22add76ff1208a846c6b5cd1e695d2960bace52df7765e` |
| MD5 | _未记录_ |
| 大小 | 2,059,104 字节（2.0 MB） |
| 类型 | other · `vbe` |

## 行为分析

共 **9** 条行为，每条都挂了证据，且全部静态可得。

### 1. 伪装VBE投递脚本

`T1036` · 置信度 **高** · 静态

文件以 .vbe 扩展名分发，实际 payload 首字节为可读文本 "Option Explicit"，并非 VBE 编码格式，属扩展名伪装以规避按文件类型拦截。

> **证据**：文件偏移 0x0 起为明文 VBScript；文件内 m_b64Payload 单行长 2,056,024 字符（第 13 行）
> 
> **来源**：`ev-000011`

### 2. 释放随机名PS1

`T1059.001` · 置信度 **高** · 静态

脚本检查并创建 C:\Temp\ 目录，以 8 位随机大写字母命名生成 .ps1，内容由内嵌 Base64 经 MSXML2.DOMDocument 解码后写入。

> **证据**：Const WORK_ROOT="C:\Temp\"; Const TMP_SUFFIX=".ps1"; RandomTag 取 A-Z 8 次; m_fs.CreateTextFile(m_stagePath, True)
> 
> **来源**：`ev-000011`

### 3. 隐藏窗口执行PS1

`T1564.003` · 置信度 **高** · 静态

以 WScript.Shell.Run 调用 "powershell.exe -nop -ep bypass -file <脚本>"，窗口参数 0（隐藏）且等待返回，随后删除落地脚本。

> **证据**：Const PS_INVOKE="powershell.exe -nop -ep bypass -file """; m_wsh.Run m_launchCmd, 0, True; CleanupArtifacts -> DeleteFile
> 
> **来源**：`ev-000011`

### 4. AES解密下一阶段

`T1140` · 置信度 **高** · 静态

第一阶段 PowerShell 用 AES-256-CBC/PKCS7 解密 1,123,568 字节内置密文，密钥与 IV 同以 Base64 硬编码，解密结果交由 Invoke-Expression 执行。

> **证据**：New-Object System.Security.Cryptography.AesManaged; $aes.Mode=CBC; $aes.Padding=PKCS7; Invoke-Expression $decryptedScript
> 
> **来源**：`ev-000011`

### 5. 反射加载.NET注入器

`T1620` · 置信度 **高** · 静态

第二阶段 PowerShell 以 Base64+XOR（密钥 SKaDazKA6@@^^）还原后再 Base64 解码出 .NET 程序集，通过 [Reflection.Assembly]::Load 在内存加载并反射调用 FILED.WHORE::LAUNCHER。

> **证据**：$xorKey="SKaDazKA6@@^^"; [Reflection.Assembly]::Load($Image); GetType('FILED.WHORE').GetMethod('LAUNCHER')
> 
> **来源**：`ev-000011` · `ev-000002`

### 6. 镂空注入系统进程

`T1055.012` · 置信度 **中** · 静态

.NET 程序集在静态构造中从 kernel32/ntdll 解析 CreateProcessA、ZwUnmapViewOfSection、VirtualAllocEx、WriteProcessMemory、ReadProcessMemory、Get/SetThreadContext、ResumeThread，并定义对应委托及进程/线程结构；配合调用方传入的 aspnet_compiler.exe 路径与 PE 字节，实现创建挂起进程、卸载映像、写入载荷、改线程上下文、恢复线程的进程镂空链。

> **证据**：FILED.WHORE::.cctor 中 ldstr 'VirtualAllocEx'/'WriteProcessMemory'/'ZwUnmapViewOfSection'/'CreateProcessA' 后 GetProcAddress 并存入 _virtualAllocEx/_writeProcessMemory/_zwUnmapViewOfSection/_createProcessA；类型表含 PROCESS_INFORMATION、STARTUPINFO、ResumeThreadDelegate 等
> 
> **来源**：`ev-000010` · `ev-000011`

### 7. 轮询哨兵进程再注入

`T1057` · 置信度 **高** · 静态

注入前循环使用 Get-Process 检查 aspnet_compiler 是否已在运行，存在则每 5 秒重试，不存在才执行注入，以避免重复注入并等待目标进程退出。

> **证据**：function Test-ProcessAbsent { Get-Process -Name $ProcessName }; Start-BeaconLoop 参数 SentinelName="aspnet_compiler", IntervalSeconds=5
> 
> **来源**：`ev-000011`

### 8. 内存加载高熵PE

`T1027.002` · 置信度 **高** · 静态

注入体为 284,672 字节 PE32，仅一个 .text 节且熵 7.99、导入表为空，入口处为自解密/自跳转 stub，注入后不落盘，属内存态加壳载荷。

> **证据**：注入 PE：e_lfanew=0xB8、1 个节 .text 熵 7.994、导入/导出目录全空、入口 RVA 0x2760 起始为 push ebp/mov ebp,esp/sub esp,0x658 解包代码；文件头前 32 字节为 4D 5A 45 52 E8 00 00 00 00 58 83 E8 09... 的 PE 跳转 stub
> 
> **来源**：`ev-000001` · `ev-000011`

### 9. 清除落地脚本痕迹

`T1070.004` · 置信度 **高** · 静态

PowerShell 返回后立即删除 C:\Temp 下生成的随机名 .ps1，减少磁盘取证痕迹。

> **证据**：Sub CleanupArtifacts: If m_fs.FileExists(m_stagePath) Then m_fs.DeleteFile m_stagePath, True
> 
> **来源**：`ev-000011`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `C:\Temp\<8 位大写字母>.ps1`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `runtime_root` | `C:\Temp\` | 否 | 静态 |
| `stage_path_pattern` | `C:\Temp\<8 位大写字母 A-Z>.ps1` | 是 | 静态 |
| `launch_command` | `powershell.exe -nop -ep bypass -file "C:\Temp\<RANDOM>.ps1"` | 是 | 静态 |
| `encryption_algo` | `AES-256-CBC/PKCS7 (stage1->stage2); Base64+XOR (stage2->.NET assembly)` | 是 | 静态 |
| `aes_key_b64` | `eNAQTmnt6oRTrGYQruVoPeTZ1dlZ/F4hfA+d1HTyy/s=` | 是 | 静态 |
| `aes_iv_b64` | `hzN0jIJpWlFDwY7mLQBsFA==` | 是 | 静态 |
| `xor_key` | `SKaDazKA6@@^^` | 是 | 静态 |
| `dotnet_entrypoint` | `FILED.WHORE::LAUNCHER` | 是 | 静态 |
| `hollow_target` | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe` | 是 | 静态 |
| `sentinel_process` | `aspnet_compiler` | 是 | 静态 |
| `poll_interval_seconds` | `5` | 否 | 静态 |
| `c2_hosts` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要因 .NET 程序集引用 RijndaelManaged/AesCryptoServiceProvider/MD5CryptoServiceProvider 就判定为勒索软件或窃密器：静态未见文件加密、浏览器凭证或键盘记录逻辑。
- 不要声称存在外联 C2、下载或数据回传：全部载荷内嵌，静态未出现任何 URL、域名、IP 或 socket 调用。
- 不要声称已安装 Service1 服务或写入注册表/计划任务：ServiceBase 派生类仅为模板残留，未见服务安装或注册表写入代码。
- 不要将注入载荷归入具体家族（如 Remcos/Agent Tesla 等）：未提取到配置、家族标识或 C2，家族无法确定。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 是（stage2 `6f5e5b62d1048251c1141402fdb3e941d21c51b3b91584495d002ced29f6259a`） |

**局限与待验证**

1. 该格式无隔离动态通道，未真实引爆，reproduced=false；所有行为结论均来自静态解码与反编译，注入是否成功、最终载荷运行效果未动态观测。
2. .NET 程序集采用压缩/加密混淆（元数据方法体仅余 stub，随机命名资源 1628 字节高熵，常见 deflate/lzma 解压均失败），LAUNCHER 的实际注入实现未能静态还原，进程镂空结论基于其导入面、委托签名、结构定义与调用参数。
3. 注入的 PE32 为单节高熵加壳载荷，入口 stub 在纯 CPU 仿真中进入循环未完成解密，最终模块、配置与 C2 未能恢复。
4. 静态未发现任何 URL/IP/域名，c2 为空；若后续动态分析出现网络行为，应作为新增 IOC 补充。
5. 同目录存在同名 zip（AES 加密压缩包），未纳入本次分析；家族无法确定，family.uncertain=true。

## 证据索引

<details>
<summary>展开 11 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 注入 PE 字符串抽取：454 条 ASCII，无 URL/命令/家族标识 |
| `ev-000002` | 哈希与指纹 | 反射加载的 .NET 程序集 sha256=6f5e5b62d1048251c1141402fdb3e941d21c51b3b91584495d002ced29f6259a |
| `ev-000003` | scan.imphash | .NET 程序集 imphash=dae02f32a21e03ce65412f6e56942daa |
| `ev-000004` | scan.entropy | .NET 程序集 .text 节熵 5.939 |
| `ev-000005` | scan.entropy | .NET 程序集 .sdata 节熵 6.638 |
| `ev-000006` | scan.entropy | .NET 程序集 .rsrc 节熵 2.733 |
| `ev-000007` | scan.entropy | .NET 程序集 .reloc 节熵 0.082 |
| `ev-000008` | 样本分诊 | .NET 程序集加壳可能性 25%（导入符号极少） |
| `ev-000009` | 密码学常量识别 | .NET 程序集命中 MD5 T-table 常量 |
| `ev-000010` | 字符串提取 | .NET 程序集元数据字符串：FILED.dll、Service1、ResumeThreadDelegate、SetThreadContextDelegate 等 |
| `ev-000011` | evidence.record | 本地静态解码链：VBE->PS1(Base64)->PS2(AES-256-CBC)->.NET(Base64+XOR)->注入 PE；IL 反编译确认进程镂空 API 绑定与 FILED.WHORE::LAUNCHER 入口 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
