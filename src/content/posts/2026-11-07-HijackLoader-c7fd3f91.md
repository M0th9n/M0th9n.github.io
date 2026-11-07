---
title: "恶意样本分析：HijackLoader（PE · exe · c7fd3f91）"
published: 2026-11-07
draft: false
description: "恶意（置信度低）：HijackLoader · loader · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Hijack", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **HijackLoader**（存疑） · 置信度 **低**
> 
> 别名：IDAT Loader、loader.dll JLI 侧加载器
> 
> 64 位 DLL(内部名 loader.dll)导出完整 JLI_* 接口,与 Java 启动器 jli.dll 的导入面一一对应,具备 DLL 侧加载劫持面;.rdata/.data 存放 209 条、合计 544211 字节的多层编码数据(base64url 跳位 + XOR/LCG + 自定义 LZ),配套控制流平坦化与反调试探测;未见任何合法 Java 启动器应有的 JVM 调用路径。上述结论由反编译、结构解析与本机行为仿真直接支撑。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **HijackLoader** · 别名 IDAT Loader、loader.dll JLI 侧加载器 · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader |
| 难度 | hard |
| 首次出现 | 2026-11-03 23:35:57 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/c7fd3f91a48fddc1ba61b91c6b059299c809215bff45fd01dbb601ca95242221/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装 Java 启动器导出</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">TLS 回调写入标记</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">检测调试器与虚拟机</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">解密内嵌字符串表</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">独立启动即静默退出</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `c7fd3f91a48fddc1ba61b91c6b059299c809215bff45fd01dbb601ca95242221` |
| MD5 | _未记录_ |
| 大小 | 732,672 字节（715.5 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **8** 条静态可得、**1** 条经动态分析取得。

### 1. 伪装 Java 启动器导出

`T1574.002` · 置信度 **高** · 静态

模块内部名为 loader.dll,导出 JLI_Launch、JLI_InitArgProcessing、JLI_GetStdArgs、JLI_GetStdArgc、JLI_MemAlloc、JLI_MemFree、JLI_CmdToArgs 及 7 个同名序数别名,导出面与 Java 启动器 jli.dll 完全对应,可被 java.exe 按 DLL 搜索顺序侧加载。

> **证据**：导出表 RVA 0x6A9A8 dll_name=loader.dll;JLI_Launch RVA 0x16A4;序数 8-14 复用序数 1-7 的 RVA
> 
> **来源**：`ref:ae35feeedb` · `ref:a07a460aa6`

### 2. TLS 回调写入标记

`T1027` · 置信度 **高** · 静态

PE 头注册 TLS 回调(RVA 0xA510),在 DLL/线程 attach 时把 0xae0882db4e12d9c3、0xd68d6341、0xd9d3bb9f 等常量与标志字节写入 TLS 块,后续代码以 TLS+0x50/+0x60 处的值判定是否继续执行。

> **证据**：TLS 目录 RVA 0x66550 -> 回调 RVA 0xA510 -> FUN_1800015b0(RVA 0x15B0)
> 
> **来源**：`ref:a2b75125bb` · `ref:f1b94cd82d`

### 3. 检测调试器与虚拟机

`T1622` · 置信度 **高** · 静态

导入 IsDebuggerPresent 并在代码中出现 rdtsc 时间差与 cpuid 探测(RVA 0x9CF9、0xC452),属于典型的反调试/反虚拟机检查。

> **证据**：IAT 438456 IsDebuggerPresent;rdtsc @ RVA 0x9CF9;cpuid @ RVA 0xC452
> 
> **来源**：`ref:f85af4e0b2` · `ref:898f18cd3e`

### 4. 解密内嵌字符串表

`T1140` · 置信度 **高** · 静态

把 209 条加密字符串(合计 544211 字节)以 64 字符块为界、每块丢弃 1 位后做 base64url 解码,再用 LCG/xorshift 生成密钥流异或,最后经自定义 LZ 解压;解码器位于 FUN_1800088cf,异或循环位于 RVA 0x3C4E 附近。

> **证据**：表 @0xB0C18 共 209 项;FUN_1800088cf(RVA 0x88CF)内含 64 项反查表与 LZ 回溯拷贝;0x3C4E imul 0x54eeddff96585e01
> 
> **来源**：`ref:b7b9057a0a` · `ref:2fac977dee` · `ref:dd36158d1b`

### 5. 控制流平坦化混淆

`T1027` · 置信度 **高** · 静态

入口分发与后续逻辑通过跳转表与计算 goto 展开(FUN_180002196、FUN_180009347、FUN_18000A593 等),反编译器无法恢复直接调用关系,静态阅读成本被显著抬高。

> **证据**：FUN_180002196 末尾 (*(code*)(&LAB_1800057D3+*(int*)(&DAT_1800624BC+0x294/0x4B0)));FUN_180009347 同样以 0x38/0x7C/0x88/0xCC 偏移分派
> 
> **来源**：`ref:f702470691` · `ref:0b0efe2e23`

### 6. 运行时解析敏感 API

`T1027` · 置信度 **高** · 静态

静态导入仅 89 个 kernel32/user32/同步原语 API,不含网络、进程注入、加密库接口;LoadLibraryA/LoadLibraryExW + GetProcAddress 用于运行时解析(仿真中已观测到 LoadLibraryExW("api-ms-win-core-fibers-l1-1-2") 与 GetProcAddress("FlsGetValue2") 的真实调用链)。

> **证据**：IAT RVA 0x6AF80 起 736 字节;仿真事件 pc=0x18000E357 LoadLibraryExW、pc=0x18000E488 GetProcAddress
> 
> **来源**：`ref:898f18cd3e` · `ref:38711e055d`

### 7. 校验宿主与命令行

`T1497.001` · 置信度 **中** · 静态

导入 GetCommandLineA/GetCommandLineW、GetStartupInfoW、GetModuleFileNameW、GetEnvironmentStringsW、GetCurrentDirectoryW、GetFullPathNameW,具备依据宿主进程名/命令行/环境决定是否执行载荷的条件判断面。

> **证据**：IAT 438160/438168 GetCommandLineA/W;438272 GetModuleFileNameW;438328 GetStartupInfoW;438224 GetEnvironmentStringsW
> 
> **来源**：`ref:898f18cd3e`

### 8. 具备落盘与遍历能力

`T1083` · 置信度 **中** · 静态

导入 CreateFileW、SetFilePointerEx、WriteFile、FlushFileBuffers、FindFirstFileExW/FindNextFileW/FindClose、GetTempPathW、GetWindowsDirectoryW、GetSystemDirectoryW,具备写文件与目录遍历能力;本次动态观测中未出现实际文件操作事件。

> **证据**：IAT 438024 CreateFileW;438072 FindFirstFileExW;438080 FindNextFileW;438648 WriteFile;438376 GetTempPathW
> 
> **来源**：`ref:898f18cd3e`

### 9. 独立启动即静默退出

`T1497.001` · 置信度 **高** · 动态

以普通可执行形态在隔离环境启动后,进程在数秒内自行退出,未创建子进程、未产生文件/注册表/网络事件,内存转储中原始编码表保持未解密状态,说明载荷执行依赖特定宿主上下文而非独立运行。

> **证据**：动态时间线:2 个同名进程先后启动并在转储前消失;内存镜像中 'zOa5ZYoXzI3P3vs' 仍为密文且仅出现 1 次
> 
> **来源**：`ref:02f18f9c76` · `ref:348b83898b` · `ref:99aae65d0a`


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
| `internal_dll_name` | `loader.dll` | 是 | 静态 |
| `pdb_path` | `LLD PDB.efork.pdb` | 否 | 静态 |
| `export_surface` | `JLI_Launch/JLI_InitArgProcessing/JLI_GetStdArgs/JLI_GetStdArgc/JLI_MemAlloc/JLI_MemFree/JLI_CmdToArgs (+7 个序数别名)` | 是 | 静态 |
| `encryption_algo` | `base64url(每 64 字符丢弃 1 位) -> XOR(LCG 0x54eeddff96585e01/0xa00cdb6684d853f5 + xorshift) -> 自定义 LZ 解压` | 是 | 静态 |
| `string_table_items` | `209` | 是 | 静态 |
| `string_table_bytes` | `544211` | 是 | 静态 |
| `c2_hosts` | `-` | 是 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 未观测到任何网络事件,不得断言其具备下载/回连能力,也不得给出具体 C2 域名或 IP
- 未见进程注入、进程镂空、加密勒索或凭据窃取的调用链,不得定性为 injector/ransomware/stealer
- 导出 JLI_* 是伪装而非合法 Java 组件,不得把它当作正常 JDK 文件或误判为 benign
- 本次未能解密配置,不得声称已提取 C2、互斥体、安装路径或持久化项
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 样本为 DLL 且导出面针对 Java 启动器宿主,隔离环境中无该宿主,直接引爆只得到进程启动-退出,未能观测到解密后的载荷行为
2. 209 条字符串表的异或种子来自运行时上下文(非文件内常量),静态无法还原,因此 c2/config/host_iocs 未能取得,相关项标记为 dynamic 且未清除待验证状态
3. 仅静态导入面可见基础 API,载荷阶段所需的网络/注入能力若存在,应通过运行时动态解析获得,本次未取得证据
4. 家族归属为候选(HijackLoader/IDAT Loader),依据为导出伪装与混淆实现特征,缺少配置或 C2 佐证

## 证据索引

<details>
<summary>展开 18 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:5a42436a09` | 样本分诊 | 哈希/imphash/节表熵/加壳评分 0/异常 0 |
| `ref:75a88e53e0` | PE 结构解析 | PE64 DLL,image_base 0x180000000,6 节,TLS/导出/调试目录 |
| `ref:ae35feeedb` | pe.exports | dll_name=loader.dll,14 个导出(JLI_*) |
| `ref:898f18cd3e` | 导入表解析 | 3 个 DLL / 89 个导入,无网络/注入/加密 API |
| `ref:f85af4e0b2` | unpack.antidebug | IsDebuggerPresent + rdtsc + cpuid 三处反分析技术 |
| `ref:7c9fcd6cb8` | unpack.detect | 未识别到已知壳 |
| `ref:a2b75125bb` | decompile.function | TLS 回调 RVA 0xA510 |
| `ref:f1b94cd82d` | decompile.function | TLS 回调写入常量/标志到 TLS 块 |
| `ref:b7b9057a0a` | decompile.function | FUN_1800088cf:64 项反查表 + XOR + LZ 解码器 |
| `ref:f702470691` | decompile.function | FUN_180002196 计算 goto 分发器 |
| `ref:0b0efe2e23` | decompile.function | FUN_180009347 计算 goto 分发器 |
| `ref:2fac977dee` | script | 解析 0xB0C18 表:209 项,合计 544211 字节;定位 XOR 循环 |
| `ref:a07a460aa6` | script | 字符串区提取到 'LLD PDB.efork.pdb'、'loader.dll' 与 JLI_* 导出名 |
| `ref:38711e055d` | dyn.run | 仿真观测 LoadLibraryExW+GetProcAddress 调用链,无文件/网络行为 |
| `ref:02f18f9c76` | 动态分析平台 | 原始样本引爆:无新进程/无转储/无网络 |
| `ref:348b83898b` | 动态分析平台 | 宿主调用桩引爆:2 个进程启动后退出,6 份内存转储 |
| `ref:99aae65d0a` | script | 内存转储中编码表仍为密文,无 C2/URL 明文 |
| `c2_evidence:c7fd3f91` | 连接证据提取 | 动态网络监控记录到 2 次到 maps[.]windows[.]com:443, ocsp[.]digicert[.]com:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
