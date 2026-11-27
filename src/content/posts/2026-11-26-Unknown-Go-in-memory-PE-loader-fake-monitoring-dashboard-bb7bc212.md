---
title: "恶意样本分析：Unknown Go in-memory PE loader (fake monitoring dashboard)（PE · exe · bb7bc212）"
published: 2026-11-26
draft: false
description: "恶意（置信度低）：Unknown Go in-memory PE loader (fake monitoring dashboard) · loader · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unknown Go in-memory PE loader (fake monitoring dashboard)**（存疑） · 置信度 **低**
> 
> 该程序是 Go 1.25.4 编译的控制台程序，表面上循环打印一份虚构的“网络基础设施监控面板”（8 个节点、在线/降级/离线统计、虚构带宽与可靠性评分），但静态与运行时证据都指向隐蔽载荷：其 .rdata 中存在约 1.1MB 近随机高熵数据块；动态分析期间，在该样本自身进程的 MEM_PRIVATE、RWX（保护属性 0x40）内存中发现一个未登记于模块链表的完整 64 位 PE 镜像（基址 0x220000000，0x25a000 字节，4 个节），其重建导入表包含 ntdll 原生内存/线程/进程 API 与 bcrypt 加解密 API。整个过程无子进程、无文件落地、无外联，符合“伪装界面 + 内存加载/执行载荷”的隐蔽执行模式，判定为恶意。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unknown Go in-memory PE loader (fake monitoring dashboard)** · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader |
| 难度 | hard |
| 首次出现 | 2026-11-25 11:04:51 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/bb7bc21269b543e669840e8771b6729ee254ccfe989115c0c8c6216175e7a0c1/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">映射内嵌PE到内存</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">载荷导入原生API</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">伪造监控面板掩护</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">运行期动态解析API</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">内嵌高熵载荷数据</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `bb7bc21269b543e669840e8771b6729ee254ccfe989115c0c8c6216175e7a0c1` |
| MD5 | _未记录_ |
| 大小 | 3,313,152 字节（3.2 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **5** 条行为，每条都挂了证据；其中 **3** 条静态可得、**2** 条经动态分析取得。

### 1. 映射内嵌PE到内存

`T1620` · 置信度 **高** · 动态

运行期间，样本进程内出现一个未登记于已加载模块链表的完整 PE 镜像：位于 MEM_PRIVATE 内存、保护属性为 RWX（0x40），大小 0x25a000，含 4 个节（.text 约 1.1MB、.data 约 1.3MB），PE 头被内存取证工具识别并成功按镜像布局转储。除样本自身外无其它进程运行，说明该镜像由样本进程自行创建。

> **证据**：内存取证报告：scanned.modified.implanted_pe=1、implanted_shc=0；module=220000000、mapping_type=MEM_PRIVATE、protection=40、is_listed_module=0、sections_count=4；对应转储文件 220000000.exe（2,468,642 字节）
> 
> **来源**：`ref:3e56e28918` · `ref:8c7ec44593`

### 2. 载荷导入原生API

`T1106` · 置信度 **高** · 动态

被映射的 PE 模块重建出的导入表指向系统原生接口：ntdll 的 NtAllocateVirtualMemory / NtFreeVirtualMemory / NtProtectVirtualMemory / NtWriteVirtualMemory / NtReadVirtualMemory / NtCreateThreadEx / NtOpenProcess / NtTerminateProcess / NtQueryInformationProcess / NtSetInformationThread / NtQuerySystemInformation / NtCreateFile / NtQueryDirectoryFile / NtCreateMutant / NtCreateSemaphore 等，以及 bcrypt 的 BCryptOpenAlgorithmProvider / BCryptGenerateSymmetricKey / BCryptEncrypt / BCryptDecrypt / BCryptGenRandom。导入集中在少数几个 IAT 区块，导入项一 DLL 一项，符合手动装载/内存重建导入的特征。

> **证据**：内存转储重建导入：bcrypt 8 项、kernel32/user32 9 项、ntdll 27 项（NtCreateThreadEx @ 0x233188、NtWriteVirtualMemory @ 0x2331c0、BCryptEncrypt @ 0x11b0b0 等）
> 
> **来源**：`ref:869b04e902` · `ref:8c7ec44593`

### 3. 伪造监控面板掩护

`T1036` · 置信度 **高** · 静态

主程序以固定 8 个节点的伪数据循环输出“NETWORK INFRASTRUCTURE MONITORING DASHBOARD / NETWORK HEALTH STATUS / DETAILED NODE REPORT”，统计 online/degraded/offline 节点数并打印虚构的带宽、丢包、可靠性评分、告警等文本，使进程外观类似运维监控工具；这是对恶意载荷的界面伪装与注意力掩护。

> **证据**：main.Cccntqygoqiewrjahjbr @0x1400e4300 连续调用 runtime.printstring 打印上述标题、节点表与百分比；字符串 "Network Size: "、"Online Nodes: "、"Degraded Nodes: "、"Offline Nodes: "、"Network Health: " 位于 0x140123a02 附近常量区
> 
> **来源**：`ref:381a2e761e` · `ref:01f4c5adc0`

### 4. 运行期动态解析API

`T1106` · 置信度 **中** · 静态

静态导入表仅含 kernel32，但 main.xcwal 中通过 syscall.(*LazyProc).Find 解析一个运行时惰性 API 并立即以 syscall.SyscallN 调用一次（出错则 gopanic）；main.etmrhfknxqoan 中再经 syscall.(*LazyProc).Call 调用该惰性过程。该调用路径不出现在导入表中，属于运行时 API 解析，常用于规避静态导入特征。

> **证据**：main.xcwal +0x40: call 0x14007b880 (syscall.(*LazyProc).Find)；+0x8f: call 0x14006c000 (syscall.SyscallN)；main.etmrhfknxqoan +0x431: call 0x14007ba60 (syscall.(*LazyProc).Call)
> 
> **来源**：`ref:b83ccc5a04` · `ref:18c26ab11f` · `ref:89a767b436`

### 5. 内嵌高熵载荷数据

`T1027.009` · 置信度 **中** · 静态

程序 .rdata 段整体熵 7.162，其中文件偏移 0x160000–0x274000（约 1.1MB）为熵 7.996–7.998 的近随机数据块，明显区别于 Go 代码与符号区；而该程序并未链接任何加密或压缩库，运行时内存里却出现完整的 PE 镜像，说明高熵块是随程序分发的加密/压缩载荷容器。

> **证据**：分块熵：0x170000–0x260000 各 64KB 块熵 7.996–7.998；.rdata 段熵 7.162（evidence ev-000004）；链接包清单仅 bufio/io/os/sort/strings/syscall/time 等标准库，无 crypto/*、compress/*
> 
> **来源**：`ref:df1d768ab1` · `ref:47e7d910e0` · `ref:082e23804c`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `payload_in_memory_base` | `0x220000000` | 是 | 动态 |
| `payload_in_memory_size` | `0x25a000` | 是 | 动态 |
| `payload_entry_rva` | `0xEA080` | 否 | 动态 |
| `payload_sections` | `.text/.rdata/.data/.reloc (4)` | 否 | 动态 |
| `c2_hosts` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得仅凭字符串表中出现 NetUserAdd / LogonUserW / CreateProcessAsUserW / CertOpenStore 等 API 名称就断言其执行了账户创建、令牌窃取或证书操作——未发现对应调用链，且这些多为 Go 标准库惰性 API 名称常量。
- 不得声称存在 C2 通信或数据外传：动态窗口内未见该样本发起任何网络连接，网络监控仅记录到系统组件的更新/证书校验请求。
- 不得声称已实现持久化：未观察到文件写入、注册表修改、服务或计划任务创建。
- 不得把伪造的“网络监控面板”当作真实运维工具行为或据此判为良性。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `ab62b4878f36565e83934044a5baf22dab6c694d604a0badf6185a7ee66612f1`） |

**局限与待验证**

1. 未取得 C2 地址、URI 或加密配置：动态窗口内无任何来自样本的网络会话，故 c2 为空。
2. 被映射 PE 的入口逻辑未还原：其字符串区仅 269 条短 ASCII 串且缺乏语义（代码型），导入表为内存重建结果，无法确认其具体功能（是否窃密/远控/横向）。
3. Go 侧函数名与字符串标识符被随机化，且 .rdata 高熵块与内存 PE 的对应关系未做解密复现，静态侧无法给出载荷生成算法。
4. 未观察到持久化、文件写入、注册表或服务操作，但不能据此排除其在特定条件下执行这些动作。
5. 缺少厂商命名/YARA 佐证，家族归属标记为不确定。
6. 动态观测约 3 分钟，长周期行为（定时任务、延迟执行）可能未被覆盖。

## 证据索引

<details>
<summary>展开 20 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:47e7d910e0` | 样本分诊 | 哈希/imphash/逐段熵/异常/加壳评分：8 节、导入仅 1 个 DLL 46 项、.rdata 熵 7.162、无异常、packing=0 |
| `ref:db13754f4a` | 导入表解析 | 导入表：仅 kernel32，46 个函数（WriteFile/WriteConsoleW/VirtualAlloc/CreateThread/GetProcAddress 等），imphash=d42595b695fc008ef2c56aabd8efd68e |
| `ref:01f4c5adc0` | 字符串提取 | 主样本 6358 条 ASCII 串，含 Go build ID 与监控面板文案；无 flag 命中 |
| `ref:1131823e71` | script(buildinfo) | Go 构建信息：path=YKMhhXyLySmb、(devel)、-trimpath、CGO_ENABLED=0、GOARCH=amd64、go1.25.4 |
| `ref:61720d5ff6` | script(pclntab) | 解析 Go pclntab：1796 个函数，main 包 22 个，入口 0x90300–0xe7ac0，函数名均为随机标识符 |
| `ref:082e23804c` | script(pclntab pkgs) | 链接包清单仅标准库：bufio/bytes/errors/io/math/os/slices/sort/strconv/strings/sync/syscall/time/unicode，无 net/crypto/compress |
| `ref:381a2e761e` | decompile.function | main.Cccntqygoqiewrjahjbr @0x1400e4300：连续 printstring 输出伪造监控面板标题、8 节点状态统计与百分比 |
| `ref:f59b5da56d` | decompile.function | main.main @0x1400e7ac0：栈帧约 1.17MB 的巨型函数，仅识别入口，伪代码为空 |
| `ref:b83ccc5a04` | script(callsite) | 调用点定位：main.xcwal→LazyProc.Find(0xc6d00)/SyscallN(0xc6d4f)，main.etmrhfknxqoan→LazyProc.Call(0xe28b1) |
| `ref:18c26ab11f` | disasm.function | main.xcwal 0xc6c40 起：mov rax,[rip+0x239675] 取惰性过程指针后 call syscall.(*LazyProc).Find，test/jne 处理错误 |
| `ref:89a767b436` | disasm.function | main.etmrhfknxqoan 0xe2820 起：构造参数后 call syscall.(*LazyProc).Call @0x14007ba60 |
| `ref:df1d768ab1` | script(entropy) | 分块熵扫描：0x160000–0x274000 区间 64KB 块熵 7.996–7.998，构成约 1.1MB 高熵块；仅样本自身为有效 PE 头 |
| `ref:f607e16343` | 动态分析平台 | 动态投放：pid 6952 被识别并转储（16 个文件），无新子进程（candidates=0），无勒索便签，收口后回滚 |
| `ref:3e56e28918` | sandbox(内存取证报告) | scan_report/dump_report：implanted_pe=1，module=220000000，size=0x25a000，MEM_PRIVATE，protection=40，is_listed_module=0，4 节，dump_mode=REALIGNED |
| `ref:8c7ec44593` | sandbox(产物解包) | 取出内存镜像 220000000.exe（2,468,642 字节）与重建导入表、ETW 事件（进程镜像、命令行、哈希、dump 动作） |
| `ref:869b04e902` | pe.imports(payload) | 内存载荷导入：40 个 DLL 各 1 项，含 ntdll 27 个 Nt* 原生 API、bcrypt 8 个 BCrypt*、user32.GetSystemMetrics/wvsprintfA 等 |
| `ref:048e08b4d3` | pe.parse(payload) | 载荷结构：PE32+ AMD64、4 节（.text 1.1MB/.rdata 28KB/.data 1.3MB/.reloc）、GUI 子系统、未签名、入口 RVA 0xEA080 |
| `ref:7ee0967282` | sandbox(时间线/网络日志) | 时间线：进程 00:34 启动后被两次转储，观测至 00:37；网络监控日志仅有系统组件的 Windows Update/OCSP 请求，无样本流量 |
| `telemetry:bb7bc212` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 122 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 22 条 |
| `etw:bb7bc212:6952` | 进程事件监控 | 短命进程事件：bb7bc21269b543e669840e8771b6729ee254ccfe989115c0c8c6216175e7a0c1.exe（pid 6952；MD5=FBDAE5E7BFA0B44A6FFA2E2D0DB8089D,SHA256=BB7BC21269B543E669840E8771B6729EE254CCFE989115C0C8C6216175E7A0C1,IMPHASH=D42595B695FC008EF2C56AABD8EFD68E） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
