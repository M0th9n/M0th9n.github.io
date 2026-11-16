---
title: "恶意样本分析：Delphi PoolParty 注入加载器（PE · exe · e0cb3810）"
published: 2026-11-15
draft: false
description: "恶意（置信度低）：Delphi PoolParty 注入加载器 · loader/injector/pua_bundler · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Delphi PoolParty", "loader", "injector", "pua", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Delphi PoolParty 注入加载器**（存疑） · 置信度 **低**
> 
> 别名：TestPrivilegeAndHandle.dll、framework_PoolInjectLib、PoolPartyBof
> 
> 样本为 64 位 Windows 程序，主体被改为控制流平坦化并以哈希立即数分发，静态还原困难；其 .data 段以单字节 0xDF 异或隐藏一份完整的 64 位 Delphi 注入模块。动态运行中，样本在自身进程内手工映射该模块（基址 0x1BCFE400000，0x1AB000 字节，MEM_PRIVATE、RWX 且不在已加载模块列表），随后拉起同路径子进程。载荷模块具备 SeDebugPrivilege 提权、ntdll 用户态钩子摘除、服务/进程枚举、线程池（PoolParty）注入与自删除能力，并伪造版本信息；文件还捆绑了一个 MD5 改号工具。综合判定为恶意加载器/注入器。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Delphi PoolParty 注入加载器** · 别名 TestPrivilegeAndHandle.dll、framework_PoolInjectLib、PoolPartyBof · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · injector · pua_bundler |
| 难度 | hard |
| 首次出现 | 2026-11-14 16:27:57 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/e0cb38109715476c5db9be2fc7fb4611b93e037467b0b3c56872537b623d5ccf/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">控制流平坦化混淆</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">异或藏匿64位载荷</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">反射加载内嵌DLL</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">线程池注入框架</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">启用调试权限提权</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1134</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `e0cb38109715476c5db9be2fc7fb4611b93e037467b0b3c56872537b623d5ccf` |
| MD5 | _未记录_ |
| 大小 | 3,111,360 字节（3.0 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **11** 条行为，每条都挂了证据；其中 **9** 条静态可得、**2** 条经动态分析取得。

### 1. 控制流平坦化混淆

`T1027` · 置信度 **高** · 静态

入口及主逻辑被改写为控制流平坦化：以状态变量和哈希立即数（如 0x8B430A26、0xD25ABD30、0x9D7EEADA）经跳转表分发，反编译结果呈状态机循环，属编译期混淆。

> **证据**：0x14000F950 起 mov dword ptr [rdi],0x8B430A26；0x14000FB60 处 cmp/jg + jmp 表分发；反编译呈状态机
> 
> **来源**：`call:call_75f282465dfd47d790215267` · `ev-000014`

### 2. 异或藏匿64位载荷

`T1027.002` · 置信度 **高** · 静态

.data 段（RVA 0x2A000，1,758,208 字节）整体按单字节 0xDF 异或，可还原出一份完整 64 位 PE（10 个节），该 PE 的节尺寸与运行期内存中出现的注入模块一致，文本含 TestPrivilegeAndHandle 与 MyTimerUnit。

> **证据**：RVA 0x2A000 起始字节 92 85 9A 8D 37…，异或 0xDF 后为 MZER 开头、e_lfanew=0x100 的 PE
> 
> **来源**：`ev-000019` · `ev-000003` · `call:call_be6542bb63a24dc8b40d35bd`

### 3. 反射加载内嵌DLL

`T1620` · 置信度 **高** · 动态

运行时在自身进程内手工映射解密得到的 64 位 Delphi DLL：内存模块基址 0x1BCFE400000、大小 0x1AB000、MEM_PRIVATE、PAGE_EXECUTE_READWRITE，且不在已加载模块列表，内存取证将其判定为植入型 PE。

> **证据**：进程内存扫描：模块 1bcfe400000，module_size=1ab000，mapping_type=MEM_PRIVATE，protection=40，is_listed_module=0，implanted_pe=1
> 
> **来源**：`call:call_6a1de654b66f42d3b49daa46` · `call:call_be6542bb63a24dc8b40d35bd`

### 4. 线程池注入框架

`T1055` · 置信度 **中** · 静态

载荷 DLL 内保留 framework_PoolInjectLib 与 PoolPartyBof 字符串，并实现进程写入类注入原语（WriteProcessMemory、VirtualAllocEx、NtWriteVirtualMemory、NtOpenProcess 等），具备 PoolParty 线程池注入能力；本次运行未观察到对其它进程的实际注入。

> **证据**：载荷 RVA 0x149F79 处 framework_PoolInjectLib、0x149F91 处 PoolPartyBof；导入表含 WriteProcessMemory/VirtualAllocEx/NtWriteVirtualMemory
> 
> **来源**：`call:call_be6542bb63a24dc8b40d35bd` · `call:call_f72b7c794dc94316b585cd42` · `ev-000019`

### 5. 启用调试权限提权

`T1134` · 置信度 **中** · 静态

载荷 DLL 实现 EnableDebugPrivilege、GetAdmin、RunAsAdmin，通过 OpenProcessToken、LookupPrivilegeValue、AdjustTokenPrivileges 打开 SeDebugPrivilege，并准备以管理员身份重启自身。

> **证据**：RTTI 方法 EnableDebugPrivilege@0x13E282、RunAsAdmin@0x13E21F；导入 AdjustTokenPrivileges/LookupPrivilegeValue/OpenProcessToken
> 
> **来源**：`call:call_be6542bb63a24dc8b40d35bd` · `call:call_f72b7c794dc94316b585cd42`

### 6. 摘除ntdll用户态钩子

`T1562.001` · 置信度 **中** · 静态

载荷 DLL 提供 UnHookNTdll 方法，并引用 Winapi.Windows.PkgHelper，用于还原被安全产品挂钩的 ntdll 函数以规避监控。

> **证据**：RTTI 方法 UnHookNTdll@0x13E0BD；单元 Winapi.Windows.PkgHelper@0x14A017
> 
> **来源**：`call:call_be6542bb63a24dc8b40d35bd` · `ev-000019`

### 7. 枚举服务与进程

`T1057` · 置信度 **中** · 静态

载荷 DLL 实现 ServiceToPID、GetProcessID、getPid，并导入 OpenSCManager/StartService、Process32First/Process32Next、NtQuerySystemInformation，用于枚举服务、进程并挑选操作目标。

> **证据**：RTTI ServiceToPID@0x13E12A；导入 OpenSCManager/StartService/Process32FirstW/NtQuerySystemInformation
> 
> **来源**：`call:call_f72b7c794dc94316b585cd42` · `call:call_be6542bb63a24dc8b40d35bd`

### 8. 拉起自身副本

`T1548.002` · 置信度 **中** · 动态

主进程（PID 8076）在完成注入后创建指向同一文件的子进程（PID 7200），命令行与父进程一致；结合载荷中的 RunAsAdmin 逻辑，判断为提权重启路径，子进程随后崩溃并触发系统错误报告。

> **证据**：ETW 进程事件：PID 7200，Image 同路径，ParentPID 8076；随后出现 WerFault 进程
> 
> **来源**：`call:call_6a1de654b66f42d3b49daa46`

### 9. 伪装版本信息

`T1036.005` · 置信度 **高** · 静态

版本资源被伪造成随机产品名 KeTTwXaSBnJ、公司 OHUuoKlBet、版本 5.7.4344.928；运行时进程属性中的 FileVersion/Description/Company/OriginalFilename 与该伪造值一致，与文件实际组件不符。

> **证据**：0x2F5F12 处 VS_VERSION_INFO：KeTTwXaSBnJ / 5.7.4344.928 / OHUuoKlBet；动态进程属性同值
> 
> **来源**：`ev-000020` · `call:call_6a1de654b66f42d3b49daa46` · `ev-000018`

### 10. 捆绑哈希改号工具

`T1027` · 置信度 **高** · 静态

在 .rsrc 中以资源类型 EXE、资源名 MD5EDITTOOLS 捆绑完整 32 位 GUI 程序“MD5 Edit Tools 3.0.2[.]11”（作者 MagicDevil.Zhang@qq[.]com），内含 doschangmd5.bat 与推广页面 URL，属哈希篡改/推广类 PUP；本次运行未观察到其落地执行。

> **证据**：资源 EXE/MD5EDITTOOLS 数据 RVA 0x1DF10C、大小 0x11C000，即文件偏移 0x1D9F0C 的 32 位 PE；版本串 MD5 Edit Tools 3.0.2[.]11
> 
> **来源**：`ev-000020` · `call:call_8afc542b978a429a8b821e40` · `ev-000015`

### 11. 自删除模块

`T1070.004` · 置信度 **中** · 静态

载荷 DLL 实现 DeleteSelf 方法，并导入 DeleteFile/MoveFile，具备运行后删除自身文件的能力；本次运行未观察到删除动作。

> **证据**：RTTI 方法 DeleteSelf@0x13E0F4；导入 DeleteFile/MoveFile
> 
> **来源**：`call:call_be6542bb63a24dc8b40d35bd` · `call:call_f72b7c794dc94316b585cd42`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://dn-magicdevil[.]qbox[.]me/md530211[.]html` | 80 | download | 静态 | ⏳ 未观测 |
| http | `hxxp://dn-magicdevil[.]qbox[.]me/Ad[.]html` | 80 | download | 静态 | ⏳ 未观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `embedded_payload` | `TestPrivilegeAndHandle.dll（64 位 Delphi PE，内存映射后 0x1AB000 字节）` | 是 | 静态 |
| `payload_xor_byte` | `0xDF（.data 整体异或，可稳定还原出完整 PE）` | 是 | 静态 |
| `injection_framework` | `framework_PoolInjectLib / PoolPartyBof（线程池工作工厂注入）` | 否 | 静态 |
| `bundled_tool` | `MD5 Edit Tools 3.0.2[.]11（资源类型 EXE、名称 MD5EDITTOOLS，32 位 Delphi GUI）` | 否 | 静态 |
| `fake_version_info` | `ProductName/OriginalFilename=KeTTwXaSBnJ，CompanyName=OHUuoKlBet，FileVersion=5.7.4344.928` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得把捆绑的 32 位 MD5 Edit Tools 当作加载器本体，也不得声称它已在本机执行或落地。
- 本次分析未取得任何 C2 请求/响应或外联会话，不得声称样本已与外部服务器通信或回传数据。
- 未观察到文件加密、凭据读取、注册表 Run 键写入、服务创建或计划任务写入，不得据此判定为勒索、窃密或已持久化。
- 载荷中的 PoolParty/注入导入表只证明能力，未观察到对其它进程的实际注入，不得声称已完成跨进程注入。
- 家族归属缺少 YARA、多引擎或配置标识佐证，不得直接断言为某个已知 APT/恶意软件家族。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `6dea8fa5bb340e838c5e91fea8a806ace9a889e6889b5e9ad6df4502749f4088`） |

**局限与待验证**

1. 未取得 C2 地址或完整配置：静态与运行期内存均未发现硬编码主机，配置可能依赖后续指令或外部参数。
2. 未观察到对其它进程的实际注入或横向行为；PoolParty/注入能力来自载荷字符串与导入表，属能力判断而非行为观测。
3. 子进程启动后很快崩溃（触发系统错误报告），提权重启是否走 UAC 路径未能完全确认。
4. 静态解密载荷与运行期内存转储存在约 8% 字节差异（基址重定位、运行期补丁），无法逐字节比对。
5. 捆绑的 MD5 Edit Tools 在本次运行中未被释放或执行，其网络 URL 仅为静态字符串，未验证连通性。
6. 未观察到注册表、服务、证书或防御规避相关的实际写入；相关能力判断均来自载荷导入表与 RTTI 方法名。

## 证据索引

<details>
<summary>展开 23 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=e0cb38109715476c5db9be2fc7fb4611b93e037467b0b3c56872537b623d5ccf |
| `call:call_96c8cae628674032b35e97ac` | PE 结构解析 | 外层 64 位 PE：8 节，.data 1.76MB，入口 RVA 0x10B00，时间戳 0 |
| `call:call_b0af55f409de492e82fa5791` | 导入表解析 | 外层仅导入 KERNEL32 74 个 CRT/基础 API（无网络 API），需动态解析 |
| `ev-000003` | scan.entropy | .data 熵 5.768（1,758,208 字节），提示大体积嵌入数据 |
| `ev-000014` | decompile.ghidra | FUN_14000F950 反编译呈状态机分发，确认控制流平坦化与逐字节变换循环 |
| `call:call_75f282465dfd47d790215267` | disasm.function | RVA 0xF950 起指令级证据：哈希立即数 0x8B430A26 与 jmp 表分发 |
| `ev-000019` | evidence.record | 脚本：.data 异或 0xDF 还原完整 64 位 PE（sha256=6dea8fa5…），与内存转储一致率约 92% |
| `ev-000020` | evidence.record | 脚本：0x1D9F0C 处 32 位 MD5 Edit Tools 及 0x2F5F12 处伪造版本信息 |
| `call:call_6a1de654b66f42d3b49daa46` | 动态分析平台 | 动态引爆：PID 8076 注入模块 1bcfe400000 被转储；拉起同路径子进程 PID 7200；无网络外联 |
| `call:call_be6542bb63a24dc8b40d35bd` | PE 结构解析 | 注入模块：11 节，入口 RVA 0x1408B0，导出表存在，内存转储 PE |
| `call:call_6ccfc09ba3aa472aba4a30df` | pe.exports | DLL 名 TestPrivilegeAndHandle.dll；导出 dbkFCallWrapperAddr / __dbk_fcall_wrapper |
| `call:call_f72b7c794dc94316b585cd42` | pe.imports(dump) | 导入 WriteProcessMemory/VirtualAllocEx/NtWriteVirtualMemory/AdjustTokenPrivileges/OpenSCManager 等 |
| `call:call_8afc542b978a429a8b821e40` | PE 结构解析 | 捆绑 32 位 PE：4 节，入口 RVA 0x8F37B，GUI 子系统 |
| `ev-000015` | 字符串提取 | 捆绑工具字符串：doschangmd5.bat、AutoAdd/Open/Net、C:..I: 等 |
| `ev-000018` | 字符串提取 | 外层长字符串：PDB 路径 C:\Users\Administrator\source\repos\ConsoleApplication3\x64\Release\ConsoleApplication3.pdb |
| `call:call_8493be7fc0ec48f4b416b243` | unpack.detect | 无已知壳特征（packed=false），混淆为编译期控制流平坦化 |
| `ev-000018` | 字符串提取 | 长字符串/编码字符串检查：可读串集中于 CRT 与伪造版本信息，关键逻辑字符串由异或载荷承载 |
| `telemetry:e0cb3810` | 动态遥测 | 动态遥测记录到：监控组件 注册表事件 1 条；监控组件 进程/文件事件 145 条；ETW 短命进程事件 6 条；已过滤工具/系统噪声 29 条 |
| `etw:e0cb3810:8076` | 进程事件监控 | 短命进程事件：e0cb38109715476c5db9be2fc7fb4611b93e037467b0b3c56872537b623d5ccf.exe（pid 8076；MD5=C1A4A7448BC3F868E624311621535CE1,SHA256=E0CB38109715476C5DB9BE2FC7FB4611B93E037467B0B3C56872537B623D5CCF,IMPHASH=C7F4A7C59999F7A98CFB176DEBD524C8） |
| `etw:e0cb3810:7200` | 进程事件监控 | 短命进程事件：e0cb38109715476c5db9be2fc7fb4611b93e037467b0b3c56872537b623d5ccf.exe（pid 7200；MD5=C1A4A7448BC3F868E624311621535CE1,SHA256=E0CB38109715476C5DB9BE2FC7FB4611B93E037467B0B3C56872537B623D5CCF,IMPHASH=C7F4A7C59999F7A98CFB176DEBD524C8） |
| `etw:e0cb3810:7636` | 进程事件监控 | 短命进程事件：ngentask.exe（pid 7636；MD5=3142937610966B092CA8886C76A3B113,SHA256=FF70C1B71440E34931EB8EF97236F3CB2BB2668C72E7A3338660CED5C0753AF8,IMPHASH=00000000000000000000000000000000） |
| `etw:e0cb3810:5100` | 进程事件监控 | 短命进程事件：ngen.exe（pid 5100；MD5=B6C3FE33B436E5006514403824F17C66,SHA256=A446D35F5E60BDAE1A7117B71D90ABB0FEA424EE416B0E0ECD2C485DC5939A68,IMPHASH=4AD0B1CAB8B0F51517768C87B067BA8A） |
| `etw:e0cb3810:800` | 进程事件监控 | 短命进程事件：ngen.exe（pid 800；MD5=B6C3FE33B436E5006514403824F17C66,SHA256=A446D35F5E60BDAE1A7117B71D90ABB0FEA424EE416B0E0ECD2C485DC5939A68,IMPHASH=4AD0B1CAB8B0F51517768C87B067BA8A） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
