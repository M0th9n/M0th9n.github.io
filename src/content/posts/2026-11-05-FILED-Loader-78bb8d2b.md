---
title: "恶意样本分析：FILED Loader（other · vbe · 78bb8d2b）"
published: 2026-11-05
draft: false
description: "恶意（置信度中）：FILED Loader · loader/injector · 难度 hard · 纯静态分析"
tags: ["FILED", "loader", "injector"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **FILED Loader**（存疑） · 置信度 **中**
> 
> 别名：FILED.WHORE、MZER/aspnet_compiler loader
> 
> 通过静态多层解码与 IL 反编译，直接还原出隐藏窗口启动 PowerShell、AES-256/XOR 解码、内存反射加载 .NET 程序集、并以挂起方式把 PE 注入合法 aspnet_compiler.exe 的完整攻击链；全部结论均可回溯到文件字节、字符串与反汇编/反编译结果。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **FILED Loader** · 别名 FILED.WHORE、MZER/aspnet_compiler loader · _存疑_ |
| 置信度 | **中** |
| 行为类 | loader · injector |
| 难度 | hard |
| 首次出现 | 2026-11-04 15:57:49 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/78bb8d2beb60bf28a7b6138dce4eca11bb5eabbe5ffa9015c302f510e642ed89/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Base64 解码载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">落盘临时脚本</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">隐藏窗口启动PS</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">AES 解密下一阶段</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">XOR还原.NET载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `78bb8d2beb60bf28a7b6138dce4eca11bb5eabbe5ffa9015c302f510e642ed89` |
| MD5 | _未记录_ |
| 大小 | 2,000,848 字节（1.9 MB） |
| 类型 | other · `vbe` |

## 行为分析

共 **10** 条行为，每条都挂了证据，且全部静态可得。

### 1. Base64 解码载荷

`T1140` · 置信度 **高** · 静态

VBScript 将 m_b64Payload 交给 MSXML2.DOMDocument(bin.base64) 解码，经 ADODB.Stream 以 UTF-8 读出，得到完整的 PowerShell 脚本文本。

> **证据**：VBE 中 m_b64Payload 赋值；StepMaterializeScript 内 MSXML2.DOMDocument 与 ADODB.Stream 调用
> 
> **来源**：`ref:10f9e4e06d` · `ref:2b650aa7db`

### 2. 落盘临时脚本

`T1074.001` · 置信度 **高** · 静态

在 C:\Temp\ 下创建 8 位大写字母随机名的 .ps1 文件并写入解码后的脚本内容。

> **证据**：Const WORK_ROOT="C:\Temp\"；RandomTag 生成 [A-Z]{8}；m_fs.CreateTextFile(m_stagePath, True)
> 
> **来源**：`ref:10f9e4e06d`

### 3. 隐藏窗口启动PS

`T1059.001` · 置信度 **高** · 静态

通过 WScript.Shell.Run 执行 powershell.exe -nop -ep bypass -file <ps1>，窗口参数为 0（隐藏），并同步等待其结束。

> **证据**：Const PS_INVOKE="powershell.exe -nop -ep bypass -file """；m_wsh.Run m_launchCmd, 0, True
> 
> **来源**：`ref:10f9e4e06d`

### 4. AES 解密下一阶段

`T1140` · 置信度 **高** · 静态

第二阶段脚本用内嵌 AES-256 密钥与 IV，以 CBC/PKCS7 解密 $encryptedPayload，恢复下一层 PowerShell 脚本。

> **证据**：Invoke-AESDecryption: Aes.Create / CipherMode.CBC / PaddingMode.PKCS7；key=b64 FIPAHE6eSqLMU4rJ5xWP/lFJesQFi3USEdP+ecpMHe0=，iv=b64 /jtW/qodA8KR5ArS0fbWUg==
> 
> **来源**：`ref:cb40333703` · `ref:2b650aa7db`

### 5. XOR还原.NET载荷

`T1027` · 置信度 **高** · 静态

第三阶段脚本对 $encBlob 先 Base64 解码，再按 UTF-8 密钥 SKaDazKA6@@^^ 循环 XOR，得到 Base64 文本并二次解码为 .NET 程序集。

> **证据**：Expand-ObfuscatedPayload: $plain[$idx] = $enc[$idx] -bxor $key[$idx % $klen]；$xormaterial = "SKaDazKA6@@^^"
> 
> **来源**：`ref:705f4ec640` · `ref:2b650aa7db`

### 6. 反射加载程序集

`T1620` · 置信度 **高** · 静态

通过 [Reflection.Assembly]::Load 在内存中加载 .NET 程序集，按 ClassPath 'FILED.WHORE'、Method 'LAUNCHER' 反射调用。

> **证据**：[Reflection.Assembly]::Load($Image)；GetType('FILED.WHORE').GetMethod('LAUNCHER').Invoke($null,$invokeParams)
> 
> **来源**：`ref:705f4ec640` · `ref:2b650aa7db`

### 7. 探测宿主进程

`T1057` · 置信度 **高** · 静态

循环调用 Get-Process -Name aspnet_compiler 检查宿主是否已在运行，仅在进程缺席时执行注入，避免重复感染。

> **证据**：Test-ProcessAbsent: Get-Process -Name $SentinelName；Start-BeaconLoop 默认 SentinelName="aspnet_compiler"
> 
> **来源**：`ref:705f4ec640`

### 8. 注入合法系统进程

`T1055` · 置信度 **高** · 静态

LAUNCHER 以 CREATE_SUSPENDED(0x8000004) 创建 C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe，用 VirtualAllocEx(0x3000, PAGE_EXECUTE_READWRITE) 分配内存、WriteProcessMemory 写入 PE 节、CreateRemoteThread 从映像入口执行，最后 ResumeThread。

> **证据**：FILED.WHORE::LAUNCHER IL：createFlags=0x8000004；VirtualAllocEx(SizeOfImage,0x3000,0x40)；WriteProcessMemory；CreateRemoteThread；ResumeThread
> 
> **来源**：`ref:8f6f0f1ef5` · `ref:2b650aa7db`

### 9. 注入MZER封装载荷

`T1027.002` · 置信度 **高** · 静态

注入载荷为 284672 字节、以 'MZER' 开头的自定位 PE 映像；stub 用 call/pop 取得基址，读取 e_lfanew=0xB8，再取 AddressOfEntryPoint 后跳转。原生映像仅一个 .text 段、无导入表。

> **证据**：stage5 偏移 0 为 4D 5A 45 52（MZER）；e_lfanew=0xB8；entry rva=0x2760；.text 熵 7.994；导入 0
> 
> **来源**：`ref:a43473f3a9` · `ref:931ebd9b8f` · `ref:f2ac1a2cd9` · `ref:2b650aa7db`

### 10. 删除暂存脚本

`T1070.004` · 置信度 **高** · 静态

PowerShell 启动后调用 CleanupArtifacts 删除 C:\Temp 下的 .ps1，减少落地痕迹。

> **证据**：CleanupArtifacts: If m_fs.FileExists(m_stagePath) Then m_fs.DeleteFile m_stagePath, True
> 
> **来源**：`ref:10f9e4e06d`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `C:\Temp\`
- `C:\Temp\[A-Z]{8}.ps1`
- `%WINDIR%\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `-` | 否 | 静态 |
| `launch_command` | `powershell.exe -nop -ep bypass -file <C:\Temp\[A-Z]{8}.ps1>` | 是 | 静态 |
| `staging_path` | `C:\Temp\[A-Z]{8}.ps1` | 是 | 静态 |
| `encryption_algo` | `AES-256-CBC/PKCS7（第二阶段）；Base64+XOR（第三阶段）` | 是 | 静态 |
| `aes_key_b64` | `FIPAHE6eSqLMU4rJ5xWP/lFJesQFi3USEdP+ecpMHe0=` | 是 | 静态 |
| `aes_iv_b64` | `/jtW/qodA8KR5ArS0fbWUg==` | 是 | 静态 |
| `xor_key` | `SKaDazKA6@@^^` | 是 | 静态 |
| `injection_target` | `%WINDIR%\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe` | 是 | 静态 |
| `assembly_class` | `FILED.WHORE` | 是 | 静态 |
| `assembly_method` | `LAUNCHER` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要判定为 ransomware/wiper：样本中没有文件加密、卷影删除或覆盖写入逻辑，现有证据只支持加载与注入链。
- 不要把 aspnet_compiler.exe 当作恶意文件或 IOC 主项：它是被注入的合法微软系统组件，仅作为宿主进程。
- 不要声称已确认 C2 域名或 IP：静态多层解码未发现网络配置，最终载荷主体为高熵数据，需动态或进一步解密确认。
- 不要依据 .vbe 扩展名认定它是 VBE 编码文件：内容实为明文 VBScript，仅由 Windows Script Host 执行。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 是（stage2 `5f1eb3f4e57fbad168b6af1ee572784f6c3481f44c0bebb48aa32e0c11bb8102`） |

**局限与待验证**

1. 仅做静态分析，未执行或仿真样本；最终 MZER 载荷主体为高熵（7.994）数据且无导入表，未解密，无法确认其最终功能与 C2。
2. 未观察到持久化（服务/注册表/计划任务），不排除后续载荷在内存中建立持久化。
3. 家族名称为基于内嵌程序集命名（FILED.dll、FILED.WHORE::LAUNCHER）的候选，尚无外部引擎或公开报告交叉印证。
4. 注入依赖目标机存在 .NET Framework 4.x 与 aspnet_compiler.exe；实际注入成功率与后续行为未经动态验证。
5. 文件名扩展名为 .vbe，实际为明文 VBScript，需 Windows Script Host 解析执行。

## 证据索引

<details>
<summary>展开 9 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:10f9e4e06d` | 字符串提取 | 原始 .vbe 字符串：Const WORK_ROOT="C:\Temp\"、Const PS_INVOKE="powershell.exe -nop -ep bypass -file """、m_b64Payload |
| `ref:cb40333703` | 字符串提取 | stage2 字符串：“PS Secure Loader - Advanced Decryption Engine”、$encryptedPayload 及 AES 密文块 |
| `ref:705f4ec640` | 字符串提取 | stage3 字符串：Expand-ObfuscatedPayload、Reflective Assembly Runner、Test-ProcessAbsent、Get-Process |
| `ref:8f6f0f1ef5` | 样本分诊 | stage4 .NET 程序集 sha256=41753c17…，.text 熵 5.75，.sdata/.rsrc/.reloc 结构正常 |
| `ref:931ebd9b8f` | 样本分诊 | stage5 .text 熵 7.994（高）、导入 0、sha256=5f1eb3f4… |
| `ref:f2ac1a2cd9` | 导入表解析 | stage5 导入表为空（0 个 DLL / 0 个符号） |
| `ref:a43473f3a9` | disasm.function | stage5 rva 0x2760 函数体：栈上常量初始化并多次 call 0x401090 |
| `ref:7922eb8ea0` | 字符串提取 | stage5 仅 454 条 ASCII 短串，无可读 C2/配置字符串 |
| `ref:2b650aa7db` | evidence.record | 静态解码链与 IL 反编译：四层哈希、AES/XOR 密钥、CreateProcess/VirtualAllocEx/WriteProcessMemory/CreateRemoteThread 调用序列 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
