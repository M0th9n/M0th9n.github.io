---
title: "恶意样本分析：PineBorough Loader（PE · exe · 2075bc1b）"
published: 2026-11-19
draft: false
description: "恶意（置信度低）：PineBorough Loader · loader/injector · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["PineBorough", "loader", "injector", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **PineBorough Loader**（存疑） · 置信度 **低**
> 
> 别名：StartMenuPin、Start Menu Pin loader、Document Manager decoy
> 
> 样本以 256 词词表索引异或后接 AES-256-CTR 的方式在 .rdata 中隐藏一个完整 PE，运行时经 BCrypt 解密并借助 NtCreateUserProcess/NtUnmapViewOfSection/NtAllocateVirtualMemory/NtWriteVirtualMemory/NtGetContextThread/NtSetContextThread/NtResumeThread 完成进程镂空式注入；同时具备 NtQueryInformationProcess 反调试、延时与内存/CPU 环境校验、API 名异或隐藏等规避技术，并伪装成合法桌面组件。动态沙箱中已观测到 bcrypt 加载和明文 PE 出现在进程内存。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **PineBorough Loader** · 别名 StartMenuPin、Start Menu Pin loader、Document Manager decoy · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · injector |
| 难度 | medium |
| 首次出现 | 2026-11-17 18:33:15 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/2075bc1baa8fb95e5cdc559de8a7f1d400f74fe0a517b71833d5ad0eb506a39a/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">词表编码隐藏载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">AES-CTR解密载荷</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">动态解析API</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">反调试探测</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">内存中现出载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `2075bc1baa8fb95e5cdc559de8a7f1d400f74fe0a517b71833d5ad0eb506a39a` |
| MD5 | _未记录_ |
| 大小 | 2,418,616 字节（2.3 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **11** 条行为，每条都挂了证据；其中 **10** 条静态可得、**1** 条经动态分析取得。

### 1. 词表编码隐藏载荷

`T1027` · 置信度 **高** · 静态

.rdata 中约 2.1 MB 的英文词文本并非普通字符串，而是 410640 个 token 的词表编码；运行时把每个 token 映射为 0-255 下标，作为载荷密文字节。

> **证据**：0x140001000 词表哈希表构建与 token 匹配循环; PTR_DAT_1400086c0 256 词表; .rdata RVA 0xADF0 起的文本块
> 
> **来源**：`ev-000013` · `ev-000018`

### 2. AES-CTR解密载荷

`T1140` · 置信度 **高** · 静态

解码后的密文再经 BCrypt 的 AES-256 计数器模式解密：以 32 字节派生密钥(每字节 (i*7+0x59) XOR 内置表)、12 字节 nonce 和小端计数器生成密钥流后异或，得到 410640 字节可执行映像。

> **证据**：0x140001aa0 调用 BCryptOpenAlgorithmProvider/SetProperty(ChainingModeECB)/GenerateSymmetricKey/BCryptEncrypt 后异或
> 
> **来源**：`ev-000015` · `ev-000018`

### 3. 动态解析API

`T1027` · 置信度 **高** · 静态

所有敏感 API 名称以 0x85 异或混淆存放在 .rdata，启动时逐条解密后调用 GetProcAddress 解析，不在导入表中暴露 ntdll/bcrypt 敏感函数。

> **证据**：0x140001940 按长度 64 字节块与末段 0x85 异或后 GetProcAddress; 解析 VirtualAlloc/NtCreateUserProcess/BCrypt* 等
> 
> **来源**：`ev-000014` · `ev-000013` · `b97dd4db39`

### 4. 反调试探测

`T1622` · 置信度 **高** · 静态

通过 NtQueryInformationProcess 分别查询 ProcessDebugPort(7) 与 ProcessDebugFlags(0x1e)，命中调试器即调用 ExitProcess 静默退出。

> **证据**：0x140001000 中 (*NtQueryInformationProcess)(handle,7,&buf,8) 与 (...,0x1e,&flags)
> 
> **来源**：`ev-000013`

### 5. 延时反沙箱

`T1497.003` · 置信度 **高** · 静态

记录 GetTickCount64，调用 Sleep(2551ms) 后再次取时间，若实际间隔小于 2051ms 则判定时间被加速/钩住并退出。

> **证据**：0x140001000 GetTickCount64 -> Sleep(0x9f7) -> GetTickCount64, 差值 < 0x803 则退出
> 
> **来源**：`ev-000013`

### 6. 校验内存与CPU

`T1497.001` · 置信度 **高** · 静态

用 GlobalMemoryStatusEx 检查物理内存是否大于 1.5 GB、用 GetSystemInfo 检查处理器数量，并调用 GetUserNameA/RegOpenKeyExA/GDI/GetSystemMetrics 等收集环境特征参与条件判断。

> **证据**：0x140001000 GlobalMemoryStatusEx + GetSystemInfo(dwNumberOfProcessors); 0x1400035d0 采集用户名/注册表/显示环境
> 
> **来源**：`ev-000013` · `ev-000027`

### 7. 进程镂空注入

`T1055.012` · 置信度 **高** · 静态

解析 System32 下存在的 svchost.exe/dllhost.exe/rundll32.exe/notepad.exe 之一，NtCreateUserProcess 创建挂起进程后卸载其映像、分配内存、写入解密映像、修复重定位、改写 RCX/RIP 为入口并 NtResumeThread 执行。

> **证据**：0x140002120 依次调用 NtUnmapViewOfSection/NtAllocateVirtualMemory/NtWriteVirtualMemory/NtGetContextThread/NtSetContextThread/NtResumeThread; 0x140001e10 解密并拼接 \svchost.exe 等路径
> 
> **来源**：`ev-000016` · `ev-000031` · `7adb02f4be`

### 8. 伪装合法程序

`T1036.005` · 置信度 **高** · 静态

版本资源伪造公司 PineBorough Park Utilities Ltd.、产品 Start Menu Pin、描述 Background desktop service component、原始文件名 StartMenuPin.exe，并使用大段办公软件风格的假字符串与假日志消息掩护。

> **证据**：资源段 RVA 0x2511EC 附近 UTF-16 版本信息; 0x14000A7xx 起的 Document Manager 假消息表
> 
> **来源**：`4ad5b2fc75` · `194f498424` · `ev-000017`

### 9. 垃圾代码填充

`T1027` · 置信度 **高** · 静态

大量看似有业务含义的函数实际只对假配置字符串做长度/CRC/base64 等无副作用运算，用于抬高静态分析成本、稀释真实控制流。

> **证据**：0x140003230/0x140003470/0x140003790/0x140003080 仅对 Document Manager 假配置串做哈希与长度运算
> 
> **来源**：`ev-000026` · `ev-000028` · `ev-000029`

### 10. 内存中现出载荷

`T1140` · 置信度 **高** · 动态

动态沙箱中样本加载 bcrypt.dll，启动约 3 秒后的进程内存转储偏移 0x33613F 处出现解密后的完整 PE 头，证明内置载荷已在内存中被还原。

> **证据**：early.t0.dmp 偏移 0x33613F 命中 stage2 PE 头 (sha256 6e6acaa1...)；监控组件 模块清单含 bcrypt.dll
> 
> **来源**：`7a79f120e5` · `2bf2d789d1`

### 11. 投递纯GUI诱饵

`T1027` · 置信度 **中** · 静态

解密得到的第二阶段是 PE32+ x64 GUI 程序(1215 个函数)，导入仅限 kernel32 字符串/堆/线程、USER32、GDI32、SHELL32，未导入任何网络、文件、注册表或进程操作 API，自身未表现恶意能力。

> **证据**：stage2 entry 0x140004290; 导入表仅 4 个 DLL/76 个符号; 无 socket/WinHttp/CreateFile/RegSetValue 导入
> 
> **来源**：`ev-000030` · `1e1b2b5484` · `ev-000019`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `%SystemRoot%\System32\svchost.exe`
- `%SystemRoot%\System32\dllhost.exe`
- `%SystemRoot%\System32\rundll32.exe`
- `%SystemRoot%\System32\notepad.exe`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `-` | 否 | 静态 |
| `encryption_algo` | `AES-256-CTR (BCrypt: AES/ECB 加密计数器块后异或), 32 字节密钥, 12 字节 nonce` | 是 | 静态 |
| `payload_encoding` | `256 词词表: 每个 token 的词表下标作为单字节, 再与 81 A7 53 FB 循环异或` | 是 | 静态 |
| `payload_size` | `410640` | 是 | 静态 |
| `hollow_targets` | `\svchost.exe;\dllhost.exe;\rundll32.exe;\notepad.exe (System32 下存在的第一个)` | 是 | 静态 |
| `install_path` | `-` | 否 | 静态 |
| `mutex` | `-` | 否 | 静态 |
| `campaign_id` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不可称其为勒索软件或文件加密器：未发现文件遍历/加密/删除或勒索信逻辑，AES 仅用于保护内置载荷。
- 不可称其为窃密木马：无浏览器凭据、钱包、键盘记录相关代码，也未导入文件/网络数据外传 API。
- 不可称其存在 C2 或外联：无网络 API，动态沙箱网络日志中没有与该样本相关的请求或会话。
- 不可称其已实现持久化：未观测到注册表 Run 项、服务或计划任务写入。
- 不可仅凭第二阶段是 GUI 程序就判定样本为良性：装载器本身的隐藏、反调试与进程镂空行为已构成恶意能力。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `6e6acaa1fcb21bd405d8a3befc09601d4107dfb51e8b96a3e3041f0c2c1bdab8`） |

**局限与待验证**

1. 动态沙箱时间线中仅出现样本自身进程，未出现 svchost.exe/dllhost.exe 等子进程，进程镂空在本次环境中未被观测到（可能创建失败或被环境差异影响），因此注入是否落地未能动态证实。
2. 第二阶段为只有 USER32/GDI32/SHELL32 与字符串/堆/线程导入的 GUI 程序，静态与动态均未见网络、文件、注册表或凭据访问，无法确认其真实用途，可能只是诱饵或占位载荷。
3. 无可提取的 C2 配置或域名/IP；无网络 API，网络监控未捕获与该样本相关的请求。
4. 内存转储中确认了明文 PE，但未直接捕获到写入目标进程的映像，注入链的证据以静态调用链为主。
5. 反调试与时序/环境校验可能在不同硬件或加速环境中导致提前退出，不同沙箱上行为可能不一致。

## 证据索引

<details>
<summary>展开 13 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | 父样本 sha256/md5/sha1 |
| `ev-000002` | scan.imphash | imphash 416e71941f92841b6e99d0f352f195e6 |
| `ev-000011` | 字符串提取 | 父样本字符串(含 Word 词表、伪装版本信息) |
| `ev-000013` | decompile.ghidra | 0x140001000: 反调试/时序/环境校验 + 词表解码 + AES-CTR |
| `ev-000014` | decompile.ghidra | 0x140001940: 异或解密导出名后 GetProcAddress |
| `ev-000015` | decompile.ghidra | 0x140001aa0: BCrypt AES-256-CTR 解密 |
| `ev-000016` | decompile.ghidra | 0x140002120: NtCreateUserProcess 进程镂空注入 |
| `ev-000018` | evidence.record | 脚本完整还原第二阶段 PE 并给出 sha256 |
| `ev-000019` | 字符串提取 | 第二阶段字符串(仅 UI 词表) |
| `ev-000030` | decompile.ghidra | 第二阶段入口 0x140004290 |
| `ev-000031` | decompile.ghidra | 0x140001e10: 解密并拼接 \svchost.exe 等目标路径 |
| `telemetry:2075bc1b` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 97 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 27 条 |
| `etw:2075bc1b:1144` | 进程事件监控 | 短命进程事件：2075bc1baa8fb95e5cdc559de8a7f1d400f74fe0a517b71833d5ad0eb506a39a.exe（pid 1144；MD5=BAF7E87CCBF9F1085805C96793F24E90,SHA256=2075BC1BAA8FB95E5CDC559DE8A7F1D400F74FE0A517B71833D5AD0EB506A39A,IMPHASH=416E71941F92841B6E99D0F352F195E6） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
