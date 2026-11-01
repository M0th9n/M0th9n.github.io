---
title: "恶意样本分析：Unattributed .NET steganographic loader (PureCrypter-like)（PE · exe · e702881e）"
published: 2026-10-31
draft: false
description: "恶意（置信度低）：Unattributed .NET steganographic loader (PureCrypter-like) · loader/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unattributed .NET steganographic loader (PureCrypter-like)**（存疑） · 置信度 **低**
> 
> 别名：HillGather loader、HWMonitor stage-2 loader
> 
> 样本为 .NET WinForms 程序，尾部逻辑从内嵌位图资源解码出一个 48640 字节的 .NET 程序集并在内存中通过 AppDomain.Load 加载、再以反射调用其入口；该二级程序集又从宿主程序集取另一个位图资源准备继续装载。加载体、隐写容器与反射调用均由反汇编/反编译直接确认。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unattributed .NET steganographic loader (PureCrypter-like)** · 别名 HillGather loader、HWMonitor stage-2 loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | medium |
| 首次出现 | 2026-10-29 06:43:20 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/e702881e545e69338b7b9c7934b8a950d5aea71dec005e4a359bce0dd1422452/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装牧场模拟界面</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">位图隐写藏二级载荷</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">内存加载隐藏程序集</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">反射调用二级入口</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">二级再取宿主资源</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `e702881e545e69338b7b9c7934b8a950d5aea71dec005e4a359bce0dd1422452` |
| MD5 | _未记录_ |
| 大小 | 560,128 字节（547.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据，且全部静态可得。

### 1. 伪装牧场模拟界面

`T1036.005` · 置信度 **高** · 静态

以功能完整的牧场/羊群行程模拟 WinForms 界面启动（HillForm/TeamForm/FlockForm/GatherForm/ReportForm），真实加载逻辑藏在 HillForm.InitializeComponent 尾部，需要用户打开主窗体才触发。

> **证据**：HillForm.InitializeComponent IL 0x072e–0x07ac（控件添加到 pnlControlBar 之后立即执行加载）
> 
> **来源**：`ref:ff69c0f8ec` · `ref:35732d46e7` · `ref:9127f0d9dd`

### 2. 位图隐写藏二级载荷

`T1027.003` · 置信度 **高** · 静态

从 .resources 的 dzh 位图（128x127、32bpp）按列优先顺序读取像素 R/G/B，还原出 48640 字节数据，Movie 头部为 'MZ'，即一个完整 .NET 程序集。

> **证据**：HillForm.Run 0x4624 / ReadPixelBytes 0x4658；资源 dzh 文件偏移 0x17e32；还原结果 sha256=b9ef8fef5b455817a626806044ae6567cb1f7bafaa7d17a7724a02a25f90d2d2
> 
> **来源**：`ref:9127f0d9dd`

### 3. 内存加载隐藏程序集

`T1620` · 置信度 **高** · 静态

调用 AppDomain.CurrentDomain.Load(byte[]) 把上一步得到的字节数组直接加载为内存程序集，磁盘上不产生二级文件。

> **证据**：IL 0x0738 call Run；0x0744 MethodSpec（AppDomain.Load(byte[])）；0x0749 callvirt System.AppDomain::Load
> 
> **来源**：`ref:ff69c0f8ec` · `ref:9127f0d9dd`

### 4. 反射调用二级入口

`T1620` · 置信度 **高** · 静态

取加载程序集的第 2 个类型（GetTypes[1]），取第一个方法（GetMethods[0]），再经 Microsoft.VisualBasic LateBinding.LateCall 以 "Invoke" 方式传入 3 个字符串参数调用，静态分析无法直接看到调用目标。

> **证据**：IL 0x0750 GetTypes → 0x0785 Type::GetMethods → 0x0791 ldstr 'Invoke' → 0x07ac LateBinding::LateCall
> 
> **来源**：`ref:ff69c0f8ec` · `ref:9127f0d9dd`

### 5. 二级再取宿主资源

`T1027.003` · 置信度 **中** · 静态

被加载的 HWMonitor.dll 引用 Assembly.GetEntryAssembly、ResourceManager.GetObject、Image.GetPixel/SetPixel 与 RestoreOriginalBitmap，说明它从宿主（HillGather）程序集继续取用另一个位图资源（ulHS，PNG 457x505）并可能回写/覆盖原图，构成多级装载链。

> **证据**：stage-2 元数据 MethodRef: Assembly::GetEntryAssembly、ResourceManager::GetObject、Bitmap::GetPixel/SetPixel、方法 RestoreOriginalBitmap(0x28cc)
> 
> **来源**：`ref:5f540ef524` · `ref:fa77c8ac76` · `ref:9127f0d9dd`

### 6. 字符串加密规避检测

`T1027` · 置信度 **高** · 静态

第一阶段 .cctor 用 "413 43B 430 43C 443 440 20" 形式的十六进制码点串（解码为西里尔字母 "Гламур "）拼接静态字段，运行时再按该分隔符 Regex.Split 取值；二级程序集的用户字符串同样以数字/字母编码存放，需运行时还原。

> **证据**：HillForm..cctor 0x6fbf: ldstr '413 43B ...' → stsfld dv；InitializeComponent 0x075d Regex::Split
> 
> **来源**：`ref:ff69c0f8ec` · `ref:fa77c8ac76`

### 7. 覆盖式面板隐藏交互

`T1564.003` · 置信度 **中** · 静态

二级程序集以 Panel 子类 GamePanel + Form1 + Timer 构建覆盖层，配合 ProcessCmdKey、GetPixel/SetPixel 与 RestoreOriginalBitmap 做屏幕级绘制/还原，未发现独立可见窗体或控制台输出。

> **证据**：stage-2 类型 GamePanel/Form1，MethodRef TextRenderer::DrawText、Bitmap::SetPixel、方法 RestoreOriginalBitmap
> 
> **来源**：`ref:5f540ef524` · `ref:fa77c8ac76`


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
| `stage2_container` | `内嵌资源 dzh（Bitmap，BMP 128x127x32bpp，文件偏移 0x17e32）` | 是 | 静态 |
| `stage2_decode` | `逐像素读取：H=127，i∈[0,48640)，x=(i/3)/H，y=(i/3)%H，字节依次取 R/G/B` | 是 | 静态 |
| `stage2_exec` | `AppDomain.CurrentDomain.Load(byte[]) → GetTypes[1] → GetMethods[0] → LateBinding.LateCall(..., "Invoke", {0,{s1,s2,"HillGather"}})` | 是 | 静态 |
| `stage3_container` | `入口程序集资源 ulHS（Bitmap，PNG 457x505 RGBA），由二级程序集读取` | 否 | 静态 |
| `string_encoding` | `第一阶段 .cctor 用码点串拼接：Гламур + 十六进制串（'413 43B 430 43C 443 440 20' 为分隔符）` | 是 | 静态 |
| `c2_hosts` | `未取回` | 否 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得声称已观测到 C2 或任何外联行为：样本静态仅导入 mscoree!CorExeMain，一、二级元数据均未引用 System.Net/WebClient/Socket，动态引爆也未取回网络日志。
- 不得把字符串 hxxp://hillfarmgather[.]org/schema/gather.xsd 当作 C2 或下载地址：它是 XML 导出的命名空间常量，且程序无网络调用面。
- 不得断言具体家族名称或最终目的（窃密/勒索/远控）：三级载荷尚未还原，二级字符串为运行时解码，缺少可佐证的家族标识。
- 不得声称存在持久化（服务/计划任务/注册表自启动）：未发现相应 API 引用或落地配置。
- 不得把 HillGatherRecord.xml / HillGatherSchema.xsd 当作恶意落地文件：它们是界面导出/校验功能使用的文件名。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `b9ef8fef5b455817a626806044ae6567cb1f7bafaa7d17a7724a02a25f90d2d2`） |

**局限与待验证**

1. 真实动态引爆未取得结果（沙箱启动/投放监控过程未返回可用产物），因此没有运行期网络、内存或文件落地证据，reproduced=false。
2. 二级程序集被混淆（方法名 1AAA1/3AAA1/…、字符串运行时解码），三级载荷（ulHS，PNG 457x505）的提取算法与最终功能尚未还原。
3. 一、二级元数据均无 System.Net/WebClient/Socket 引用；若存在网络能力，只能位于尚未还原的三级载荷或经反射间接调用。
4. 样本由 .NET 反射/隐写构建，静态结论对混淆部分可能存在偏差；家族归属为候选而非定论。

## 证据索引

<details>
<summary>展开 8 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:05105c9f20` | 样本分诊 | sha256=e702881e…，.text 熵 7.58、仅 1 个导入符号，加壳可能性 0.6 |
| `ref:ff69c0f8ec` | PE 结构解析 | I386 PE，3 节，入口 0x89d32，导入目录仅 79 字节，CLI/COM 目录存在 |
| `ref:f75392f457` | 导入表解析 | 唯一导入 mscoree.dll!_CorExeMain（.NET 程序） |
| `ref:35732d46e7` | 字符串提取 | 抽取字符串并命中资源/命名空间字符串（HillGather、dzh、ulHS 等） |
| `ref:5f540ef524` | PE 结构解析 | 还原出的二级载荷为 I386 DLL，.NET，3 节，模块大小 48640 |
| `ref:fa77c8ac76` | 字符串提取 | 二级载荷字符串：GetTypes/GetMethods/Invoke/LateBinding/GetEntryAssembly/GetPixel/SetPixel 等 |
| `ref:9127f0d9dd` | 脚本化取证 | 按样本自身算法解码位图资源 dzh，得到以 MZ 开头的 48640 字节 .NET 程序集 HWMonitor.dll |
| `ref:d37b1c0e9b` | 动态分析平台 | 动态环境已启动但未运行投放样本，无样本进程/网络产物 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
