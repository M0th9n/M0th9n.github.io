---
title: "恶意样本分析：JLI DLL Loader (unattributed)（PE · exe · 05bc075d）"
published: 2026-11-10
draft: false
description: "恶意（置信度低）：JLI DLL Loader (unattributed) · loader · 难度 medium · 静态反编译（动态执行未取得运行时行为）"
tags: ["JLI", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **JLI DLL Loader (unattributed)**（存疑） · 置信度 **低**
> 
> 别名：loader.dll JLI loader、jli.dll 伪装加载器
> 
> 该文件是可执行 DLL,却以 Java 启动库 jli.dll 的完整导出/导入面伪装自己(导出名 loader.dll + 14 个 JLI_* 项),经 UPX 加壳,脱壳后在 .rdata/.data 中携带合计 473,362 字符的 base64url 文本,解码后为 355,021 字节、熵 7.99 的无文件头数据,并由 RVA 0x9ADB0 的 210 条分块索引表与运行期乱序 base64 字母表(SplitMix64 洗牌)配合还原。这是典型的 DLL 侧加载/内嵌二阶段载荷的加载器构造,未发现任何正常 jli.dll 应具有的 Java 启动逻辑。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **JLI DLL Loader (unattributed)** · 别名 loader.dll JLI loader、jli.dll 伪装加载器 · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader |
| 难度 | medium |
| 首次出现 | 2026-11-08 17:42:49 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/05bc075d609943ef13d07e9fe5033ca89a031221e92fb6e6df305bbdff751c3b/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX 加壳隐藏代码</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">冒用 jli.dll 导出面</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">侧加载入口欺骗</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">内置加密二阶段载荷</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.013</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">分块索引重组载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `05bc075d609943ef13d07e9fe5033ca89a031221e92fb6e6df305bbdff751c3b` |
| MD5 | _未记录_ |
| 大小 | 440,320 字节（430.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据，且全部静态可得。

### 1. UPX 加壳隐藏代码

`T1027.002` · 置信度 **高** · 静态

样本以 UPX 段(UPX0/UPX1/UPX2)交付,入口位于可写可执行的自解密段 UPX1,熵 7.999;脱壳后恢复为 6 个常规 PE 段。

> **证据**：pe.sections: UPX0/UPX1/UPX2, UPX1 entropy 7.999; unpack.detect: packer=upx, confidence 0.9
> 
> **来源**：`ev-000008` · `ref:81717b94c6`

### 2. 冒用 jli.dll 导出面

`T1036.005` · 置信度 **高** · 静态

导出表声明 DLL 名 loader.dll,导出 JLI_Launch/JLI_MemAlloc/JLI_CmdToArgs 等 14 个 JLI_* 项,导入面与正版 jli.dll 完全相同,但镜像体积与内容均不同于正版 jli.dll,属于合法系统组件名称伪装。

> **证据**：pe.exports: loader.dll / 14 exports; pe.imports: KERNEL32.DLL(84)+api-ms-win-core-synch-l1-2-0.dll(2); 正版 jli.dll 87,152B vs 脱壳镜像 642,560B
> 
> **来源**：`ref:af2ad2834d` · `ref:a0544a3d09` · `ev-000016`

### 3. 侧加载入口欺骗

`T1574.002` · 置信度 **中** · 静态

以 JLI_Launch(0x180002866)等合法导出名作为调用入口,导出桩经 0x180002E59 进入内部初始化链;该构造用于被宿主程序按 jli.dll 名称加载后执行自身代码。

> **证据**：0x180002866 JLI_Launch: call 0x180002E59; entry 0xC1A0 → 0xC060; 导出名与 jli.dll 逐一对应
> 
> **来源**：`ref:af2ad2834d` · `ref:39c87f97b1` · `ref:4d09a2a672`

### 4. 内置加密二阶段载荷

`T1027.013` · 置信度 **高** · 静态

.rdata 与 .data 起始各有一段纯 base64url 文本(233,154 + 240,208 字符),解码后为 355,021 字节、熵 7.99、256 种字节值齐全且无 MZ/PK/ELF 头,属于加密/压缩后的下一阶段数据。

> **证据**：.rdata RVA 0x1B000 起 233,154 字符; .data RVA 0x60000 起 240,208 字符; 解码 355,021 字节 entropy 7.99
> 
> **来源**：`ev-000017` · `ref:b7eec4e578`

### 5. 分块索引重组载荷

`T1140` · 置信度 **中** · 静态

RVA 0x9ADB0 处存在 210 条 {VA,length} 分块索引,条目指向上述两段文本并按块首尾相接,用于运行期按索引拼接还原完整编码串。

> **证据**：RVA 0x9ADB0: 210 条 {VA,length}; 例 0x1800600A5/0xC2B、0x18001B0E0/0x512、0x18001B5F2/0xD39
> 
> **来源**：`ev-000017`

### 6. 运行期洗牌 base64

`T1140` · 置信度 **高** · 静态

RVA 0x1B83 的函数载入 SplitMix64 常量,对 .rdata 0x54E38 处的 64 字节 base64 字母表执行 Fisher-Yates 洗牌(就地交换栈上字母表字节),再用洗牌后的字母表解码载荷,使标准 base64 识别失效。

> **证据**：0x1B83: movabs 0x9E3779B97F4A7C15 / 0xBF58476D1CE4E5B9 / 0x94D049BB133111EB; .rdata 0x54E38 字母表; 交换 [rsp+rbx+0x1F]/[rsp+rdx+0x20]
> 
> **来源**：`ref:c82d5cf8af` · `ref:365b3b313a` · `ev-000017`

### 7. 动态解析系统 API

`T1129` · 置信度 **中** · 静态

导入表仅保留少量 KERNEL32 函数(LoadLibraryA/GetProcAddress/VirtualProtect 等),其余能力需在运行期通过 GetProcAddress 解析,并以 .data 中的函数指针间接调用。

> **证据**：pe.imports: LoadLibraryA/GetProcAddress/VirtualProtect; 0x1C31 call qword ptr [.data] 间接调用
> 
> **来源**：`ref:a0544a3d09` · `ref:c82d5cf8af`


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
| `payload_encoding` | `base64url 文本 + 运行期用 SplitMix64 洗牌生成的乱序字母表` | 是 | 静态 |
| `payload_size` | `473362 字符编码,解码后 355021 字节(两段:RVA 0x1B000 起 233154 字符、RVA 0x60000 起 240208 字符)` | 是 | 静态 |
| `chunk_index_table` | `RVA 0x9ADB0,210 条 {VA,length} 分块索引(如 0x1800600A5/0xC2B、0x18001B0E0/0x512)` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不应称其为勒索软件或窃密程序:未发现文件加密、凭据读取或浏览器数据收集相关代码。
- 不应声称已确认 C2 或下载地址:静态未提取到可用的 URL/IP/域名,沙箱中也未观测到任何外联会话。
- 不应声称样本可独立运行:该文件是 DLL,直接以可执行方式投放不会产生新进程,动态中未出现样本相关子进程。
- 不应声称已观测到进程注入或持久化:没有相应 API 调用链、注册表、服务或计划任务证据。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 是（stage2 `6c3dc4eea58cf0babc559652126f230d2b8cffd5de1a0040195dfbd7bf2372b6`） |

**局限与待验证**

1. 仅在隔离沙箱中直接投放该 DLL,未观测到新进程、网络请求或内存转储,故无运行期恶意行为证据。
2. 内嵌 355,021 字节载荷仅完成解码与结构定位,未能解密出可识别的下一阶段 PE/脚本,其功能(下载、注入或窃密)无法确认。
3. 家族归因缺少厂商引擎/YARA/公开报告佐证,仅为基于导出面冒用与内嵌加密载荷的候选判断。
4. 加壳段内命中的 rdtsc/int 2Dh/cpuid 等反调试特征位于压缩数据中,存在误报可能,未作为结论使用。

## 证据索引

<details>
<summary>展开 11 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=05bc075d...; md5=35fa8e6578f4eae5ece1c045b35940b2; size=440320 |
| `ev-000008` | 样本分诊 | 加壳可能性 85%:导入极少(4)、W^X 段、UPX0 段名 |
| `ref:39c87f97b1` | PE 结构解析 | PE64 DLL,3 段 UPX0/UPX1/UPX2,image_base=0x180000000,entry RVA 0xA32B0 |
| `ref:af2ad2834d` | pe.exports | DLL 名 loader.dll,14 个导出(JLI_* 7 名 + 7 个无名别名) |
| `ref:a0544a3d09` | 导入表解析 | 脱壳镜像导入:KERNEL32.DLL 84 项 + api-ms-win-core-synch-l1-2-0.dll 2 项 |
| `ref:c82d5cf8af` | disasm.function | 0x1B83 处 SplitMix64 常量与字母表洗牌/交换指令 |
| `ref:365b3b313a` | 密码学常量识别 | base64 url-safe 字母表 @0x53638;0x9E3779B9 常量(NIST/SplitMix 混合) |
| `ref:c84ce61f56` | 动态分析平台 | 沙箱投放 120s:候选进程 0、转储 0、hollows 扫描 0,已回滚 |
| `ev-000016` | evidence.record | 静态解包(642,560B)与正版 jli.dll(87,152B)导出/导入面比对 |
| `ev-000017` | evidence.record | 两段 base64url 载荷解码为 355,021 字节(熵 7.99)、210 条分块索引、运行期洗牌字母表 |
| `telemetry:05bc075d` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 91 条；已过滤工具/系统噪声 27 条 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
