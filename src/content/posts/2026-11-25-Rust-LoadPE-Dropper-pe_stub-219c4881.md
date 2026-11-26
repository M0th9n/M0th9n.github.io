---
title: "恶意样本分析：Rust LoadPE Dropper (pe_stub)（PE · exe · 219c4881）"
published: 2026-11-25
draft: false
description: "恶意（置信度低）：Rust LoadPE Dropper (pe_stub) · loader/dropper/injector · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["LoadPE", "loader", "dropper", "injector", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Rust LoadPE Dropper (pe_stub)**（存疑） · 置信度 **低**
> 
> 别名：loadpe、pe_stub、bundle_deploy
> 
> 样本是 Rust 编写、带 9.4MB 文本填充的 PE 加载器：导入面同时具备资源释放、进程镂空(VirtualAllocEx/WriteProcessMemory/GetThreadContext/SetThreadContext/ResumeThread)与 ShellExecuteExW 启动能力；.rdata 中保留 src\main.rs、src\loadpe_child.rs、src\bundle_deploy.rs 等源码路径与“loadpe (self-hollow, no drop)”“drop written ->”“packed self removed after child ok”“excl: phase begin (UAC may appear)”等运行日志模板；反编译确认其通过 bcrypt.dll 的 AES-256-GCM 解密内置 PE 并校验 MZ。版本资源伪装为 sihost.exe/Desktop Window Manager。综合为恶意投放型加载器（loader/dropper）。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Rust LoadPE Dropper (pe_stub)** · 别名 loadpe、pe_stub、bundle_deploy · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · dropper · injector |
| 难度 | medium |
| 首次出现 | 2026-11-23 16:33:43 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/219c48815fd9fb9091255d4f97d8070cffcd74900ebfd6648c00512a5731cda1/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">自镂空映射 PE</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">落盘并启动子进程</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">清理落地痕迹</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1070.004</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">运行未衍生子进程</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `219c48815fd9fb9091255d4f97d8070cffcd74900ebfd6648c00512a5731cda1` |
| MD5 | _未记录_ |
| 大小 | 11,237,648 字节（10.7 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **10** 条行为，每条都挂了证据；其中 **8** 条静态可得、**2** 条经动态分析取得。

### 1. 解密内置载荷

`T1140` · 置信度 **高** · 静态

通过 LoadLibraryA("bcrypt.dll")+GetProcAddress 动态解析 BCrypt* 接口，以 BCryptOpenAlgorithmProvider("AES")、ChainingModeGCM 建立 AES-256-GCM，密钥 32 字节、nonce 12 字节、tag 16 字节，从载荷尾部 EXPL 结构取出参数解密，并检查结果前两字节是否为 MZ。

> **证据**：0x140002714 反编译：BCryptGenerateSymmetricKey(...,0x20) + pbNonce/cbNonce=0xc + cbAuthData=0x10；0x140002d8c 校验尾部 0x4C505845("EXPL") 与版本 1/2/3
> 
> **来源**：`ev-000017` · `ev-000018`

### 2. 自镂空映射 PE

`T1620` · 置信度 **高** · 静态

加载器保留“loadpe (self-hollow, no drop)”路径：解析 NtQueryInformationProcess/NtUnmapViewOfSection 后在本进程内解除映像再映射解密后的 PE，并尝试用 RtlAddFunctionTable/SetProcessValidCallTargets 处理 CFG 校验，避免调用 LoadLibrary。

> **证据**：0x1400061ba/0x1400061e3 引用 NtQueryInformationProcess、NtUnmapViewOfSection；字符串“loadpe (self-hollow, no drop)”“loadpe ok (child survived alive window)”；kernel32!SetProcessValidCallTargets 字符串
> 
> **来源**：`ev-000011` · `ev-000013`

### 3. 落盘并启动子进程

`T1106` · 置信度 **高** · 静态

自映射失败时回退到磁盘投放：把解密后的 PE 写入 %LOCALAPPDATA%\LocalApp_<随机后缀>\Application.exe（并尝试 ProgramData\dll|sys 等目录），再用 CreateProcessW 或 ShellExecuteExW 启动，日志记录“drop written -> …”“child launched, drop kept @ …”。

> **证据**：导入表 CreateProcessW @iat 0x34040、ShellExecuteExW @iat 0x34080；字符串“disk drop -> ”“spawn: staged ”“Application.exe”“LOCALAPPDATA”“LocalApp_”
> 
> **来源**：`ref:1067b91fbe` · `ev-000011`

### 4. 清理落地痕迹

`T1070.004` · 置信度 **高** · 静态

启动前用 DeleteFileW 清理旧的落地文件，子进程启动成功后删除自身 packed 文件（“packed self removed after child ok”），并按 PE_STUB_KEEP_MOTW 决定是否处理 Zone.Identifier（Mark-of-the-Web）。

> **证据**：0x140005223 反编译中的 DeleteFileW(local_d0) 调用；字符串“packed self removed after child ok”“:Zone.Identifier”“PE_STUB_KEEP_MOTW”
> 
> **来源**：`ev-000013` · `ev-000011`

### 5. 伪装系统组件

`T1036.005` · 置信度 **高** · 静态

版本资源伪装为 Windows 组件：CompanyName=MS Windows Platform，ProductName=Desktop Window Manager，InternalName=sihost，OriginalFilename=sihost.exe，FileDescription=Windows Runtime Library；另有构建器默认的“Local Application (4f6595c8)”字符串表。

> **证据**：RT_VERSION 资源 StringTable：OriginalFilename=sihost.exe / ProductName=Desktop Window Manager；GUI 子系统、无窗口逻辑
> 
> **来源**：`ref:b40a1fd8c9` · `ev-000011`

### 6. 探测目标运行时

`T1082` · 置信度 **高** · 静态

在选路前探测宿主环境：字符串覆盖 mscoree.dll/clr.dll/hostfxr.dll（.NET）、Qt5/Qt6/qwindows.dll、Microsoft.UI.Xaml/WindowsAppRuntime/WinUI、libssl、AyuGram，以及 RUNTIMES\WIN-X64\NATIVE 等目录名，用于决定 in-proc 映射还是落盘启动（“skip inproc -> disk (GUI/TLS/WinUI)”）。

> **证据**：0x35ed0 起字符串表 mscoree.dll clr.dll hostfxr.dll … Qt5 Qt6 qwindows.dll libssl AyuGram；0x349c8 WindowsAppRuntime/MddBootstrap
> 
> **来源**：`ev-000011` · `ev-000016`

### 7. UAC 提权尝试

`T1548.002` · 置信度 **中** · 静态

落地阶段记录“excl: phase begin (UAC may appear)”“excl: UAC/prime begin”，并通过 ShellExecuteExW（runas 语义）尝试以提升权限启动落地文件，失败则重试其他目录。

> **证据**：字符串“excl: phase begin (UAC may appear)”“excl: UAC/prime begin/end”“excl launch dir ->”；ShellExecuteExW 导入 @iat 0x34080
> 
> **来源**：`ev-000011`

### 8. 运行时解析敏感 API

`T1027` · 置信度 **高** · 静态

除导入表外，关键能力（BCrypt 加解密、NtQueryInformationProcess/NtUnmapViewOfSection）通过 LoadLibraryA/GetProcAddress 在运行时解析，降低导入面可读性。

> **证据**：0x140002744 LoadLibraryA("bcrypt.dll") + GetProcAddress 链；0x1400061e3 引用 NtUnmapViewOfSection 字符串
> 
> **来源**：`ev-000017` · `ref:1067b91fbe`

### 9. 运行未衍生子进程

`T1106` · 置信度 **高** · 动态

在隔离 Windows 环境投放执行 150 秒，仅观测到样本自身进程（单一候选 PID），其后代进程、落地文件与子进程链均未出现；内存扫描亦未发现注入、映像替换或 PE 头修改，说明本次运行中自映射/落盘执行链路未完成。

> **证据**：动态时间线：candidate_count=1、dumped_pids 为空、hollows count=0；内存扫描 Total suspicious=0；ETW 仅记录样本自身创建
> 
> **来源**：`ref:95a75ad258` · `ref:bbd81fe68a` · `ref:a0222a8462`

### 10. 运行期无外联与持久化

`T1071` · 置信度 **高** · 动态

网络监控在观测窗口内未记录样本进程的任何 DNS/HTTP 会话（只有系统进程的更新与证书流量），遥测比对显示 Run 启动项、服务、Defender 排除项均无变化；未观测到 C2 通信或持久化写入。

> **证据**：网络监控日志仅含 svchost/监控组件/EdgeUpdate 等系统进程；遥测 Run 键与服务前后一致；样本 PID 无连接记录
> 
> **来源**：`ref:f0512169a5` · `ref:991d0702de` · `ref:b578fad4ba`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `%LOCALAPPDATA%\LocalApp_<随机后缀>\Application.exe`
- `%TEMP%\pe_stub_spawn.log`
- `%TEMP%\pe_stub_fail.log`
- `%PROGRAMDATA%\dll`
- `%PROGRAMDATA%\sys`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `encryption_algo` | `AES-256-GCM (BCryptOpenAlgorithmProvider("AES")+ChainingModeGCM，32 字节密钥、12 字节 nonce、16 字节 tag)` | 是 | 静态 |
| `payload_container_format` | `尾部 EXPL footer：version 1/2/3 对应 0x4c/0x70/0x78 字节定长结构，含 key/nonce/authdata/明文长度` | 是 | 静态 |
| `env_flag` | `PE_STUB_KEEP_MOTW（环境变量开关，控制落地文件是否保留 Zone.Identifier）` | 否 | 静态 |
| `drop_filename` | `Application.exe` | 否 | 静态 |
| `log_files` | `pe_stub_spawn.log / pe_stub_fail.log（PE_STUB_SPAWN_LOG）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能断言该样本已成功植入或已经落地执行载荷：动态窗口内无子进程、无落地文件、内存扫描无注入痕迹。
- 不能因为出现 AES-GCM 解密与“encrypt/entropy_codec”字样就判定为勒索软件：没有任何遍历或加密用户文件的行为证据。
- 不能把内置载荷归属到具体恶意家族（如 Amadey、StealC 等）：未取得载荷，也没有 YARA/多引擎/配置字符串支持。
- 不能把字符串扫描命中的“_falsetrue{”片段当作 flag 或配置：该片段位于 Rust demangle 字符串表中，属于编译器/运行时噪声。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 内置载荷未能解密：资源 #6258 为 524288 字节高熵密文加约 1MB 重复 manifest 文本填充，尾部不存在 EXPL footer，因而无法取得 AES 密钥/nonce，未提取出 stage2。
2. 动态观测窗口内样本未落地、未注入、未外联，未取得 API 级调用序列；仅 Speakeasy 仿真到 CRT 初始化即中止，无法据此判断解密是否执行过。
3. 未发现任何 C2 地址、URL 或配置串，c2 字段为空；不排除载荷内含网络能力但未解密。
4. 家族归属仅为行为学命名（pe_stub/loadpe），缺少厂商命名与多引擎数据，confidence 为 low 且 uncertain=true。
5. host_iocs 中的路径来自字符串模板与目录词表（LocalApp_、Application.exe、pe_stub_*.log、ProgramData\dll|sys），未在本次运行中观测到实际创建。

## 证据索引

<details>
<summary>展开 17 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 11237648 |
| `ev-000002` | scan.imphash | imphash=ed8e3ce678659cdefbf4193bc755be3f |
| `ev-000003` | scan.rich | Rich header 10 条 MSVC 工具链记录 |
| `ev-000004` | scan.entropy | .text 熵 6.374（未加壳） |
| `ev-000011` | 字符串提取 | 字符串抽取 360728 条 ASCII，含 loadpe/bundle_deploy/EXPL 相关模板与 flag 噪声命中 |
| `ev-000012` | 密码学常量识别 | 标准 base64 字母表常量 @0x340e6 |
| `ev-000013` | decompile.ghidra | main(FUN_140005223) 反编译：日志、DeleteFileW 清理与载荷处理调用 |
| `ev-000017` | decompile.ghidra | FUN_140002714：BCrypt AES-GCM 解密封装（32 字节密钥、12 字节 nonce、16 字节 tag） |
| `ev-000018` | decompile.ghidra | FUN_140002d8c：解析尾部 EXPL 版本 1/2/3 结构并校验 MZ |
| `ref:1067b91fbe` | 导入表解析 | 导入面：资源释放、进程镂空、CreateProcessW/ShellExecuteExW、注册表与文件操作 |
| `ref:b40a1fd8c9` | pe.resources | 资源枚举与版本信息（sihost.exe 伪装、Local Application） |
| `ref:95a75ad258` | 动态分析平台 | 隔离环境真实引爆时间线：1 个候选进程，无子进程 |
| `ref:bbd81fe68a` | 动态分析平台 | 内存扫描摘要：Total suspicious=0，hollows 0 |
| `ref:f0512169a5` | 动态分析平台 | 网络监控日志：无样本进程会话 |
| `ref:991d0702de` | 动态分析平台 | 遥测前后比对：Run 键/服务/Defender 排除项无变化 |
| `telemetry:219c4881` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 109 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 22 条 |
| `etw:219c4881:3920` | 进程事件监控 | 短命进程事件：219c48815fd9fb9091255d4f97d8070cffcd74900ebfd6648c00512a5731cda1.exe（pid 3920；MD5=0B71302466DD23D7F1F9E7458A5D9A82,SHA256=219C48815FD9FB9091255D4F97D8070CFFCD74900EBFD6648C00512A5731CDA1,IMPHASH=ED8E3CE678659CDEFBF4193BC755BE3F） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
