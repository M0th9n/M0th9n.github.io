---
title: "恶意样本分析：HWMonitor Stego Loader（PE · exe · 3fb04465）"
published: 2026-11-03
draft: false
description: "恶意（置信度低）：HWMonitor Stego Loader · loader/dropper · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["HWMonitor Stego", "loader", "dropper", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **HWMonitor Stego Loader**（存疑） · 置信度 **低**
> 
> 别名：HWMonitor Pro 伪装加载器、PureCrypter-like .NET stego loader
> 
> 反编译主程序验证其为 .NET 隐写加载器: 资源位图 TW1 的 RGB 像素被逐点读成 92160 字节并还原出完整 PE32 .NET 程序集(HWMonitor.dll), 随后通过运行期拼接的 'L'+'oad' 经 VB LateBinding 调用 AppDomain.Load 反射加载, 再以 Activator.CreateInstance 实例化并挂入窗体。完整加载链在本环境静态复现, 且外层以完整 WinForms 业务界面作伪装。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **HWMonitor Stego Loader** · 别名 HWMonitor Pro 伪装加载器、PureCrypter-like .NET stego loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · dropper |
| 难度 | hard |
| 首次出现 | 2026-11-03 06:43:43 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/3fb044653334e89c68176d670bedbec83c2e09a2a609b4814eee1575fda6da2d/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">图像隐写藏 PE</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">反射加载内存程序集</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">十六进制串拆配置</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">运行期拼接 API 名</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">伪装山舍管理程序</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `3fb044653334e89c68176d670bedbec83c2e09a2a609b4814eee1575fda6da2d` |
| MD5 | _未记录_ |
| 大小 | 2,665,984 字节（2.5 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据，且全部静态可得。

### 1. 图像隐写藏 PE

`T1027.003` · 置信度 **高** · 静态

资源位图 TW1(177x176, 32bpp) 被按列优先逐像素读取 R/G/B 通道, 累积到 92160 字节后得到以 MZ 开头的完整 PE32 .NET 程序集, 用于把第二段藏进普通图片资源。

> **证据**：RadioTelescopeDecoder.Produce @0x10c34; 像素采集回调 <...Produce>b__0 @0x111d4 调 GetPixel 并 Append R/G/B; HutForm.InitializeComponent @0x4be0 传入 sampleBudget=92160
> 
> **来源**：`ev-000008` · `ev-000005`

### 2. 反射加载内存程序集

`T1620` · 置信度 **高** · 静态

运行期把 'L' 与 'oad' 拼接成 'Load', 交 VB LateBinding 在 AppDomain.CurrentDomain 上调用, 以解码得到的字节数组加载程序集, 不向磁盘写文件。

> **证据**：0x4a83-0x4aa9: get_CurrentDomain / Concat('L','oad') / LateBinding::LateGet; 0x4ab5 Assembly::GetExportedTypes
> 
> **来源**：`ev-000008` · `ev-000005`

### 3. 十六进制串拆配置

`T1140` · 置信度 **高** · 静态

静态字段 intConn 的值由 '4F 49 4C' 分隔的十六进制片段组成, Split 后取 [1]、[3] 得到 '4342677A'(即资源名 CBgz) 与空串, 与 'MountainHut' 组成 3 个构造参数, 再用 Activator.CreateInstance 实例化载荷导出的类型。

> **证据**：HutForm::.cctor @0x6a0e; 0x4abd-0x4af3: Split / newarr String / Activator::CreateInstance
> 
> **来源**：`ev-000008`

### 4. 运行期拼接 API 名

`T1027` · 置信度 **高** · 静态

敏感方法名 'Load' 被拆成两个常量在栈上拼接, 使静态字符串扫描看不到完整的反射加载调用。

> **证据**：HutForm.InitializeComponent @0x4be0, 0x4a89/0x4a8e ldstr 'L'/'oad' + 0x4a93 String::Concat
> 
> **来源**：`ev-000005` · `ev-000008`

### 5. 伪装山舍管理程序

`T1036` · 置信度 **高** · 静态

外层是功能完整的 WinForms 'Mountain Hut' 旅舍补给模拟程序, 含 HutForm/HutSetupForm/SupplyForm/SeasonForm/ReportForm、DataSet 与大量界面资源, 以正常业务外观掩盖启动期的载荷加载。

> **证据**：程序集 oqNZ, 版本信息 ProductName/FileDescription='Mountain Hut', CompanyName='Alpine Supply Systems'; 类型/资源见 scan.strings 与元数据
> 
> **来源**：`ev-000005` · `ev-000002`

### 6. 高熵单段隐藏载荷

`T1027.002` · 置信度 **高** · 静态

PE 仅有 .text(熵 7.91, 约 2.66MB) 与 .rsrc 两个段, 导入表/导出表为空, 图片资源与 IL 混在 .text 内, 使基于导入面/段名的常规静态判据失效。

> **证据**：.text rva 0x2000 entropy 7.91; import_dll_count=0; section 数=2; entry_point.rva=0 (纯托管入口由 CLR 解析)
> 
> **来源**：`ev-000002` · `ev-000004` · `ev-000001`

### 7. 内嵌监控程序伪装

`T1036` · 置信度 **中** · 静态

第二段自报为 HWMonitor 2.8(HWMonitor.dll), 元数据含 'HWMonitor Pro'、'CPUID SARL 2026' 与硬件监控描述, 同时带 MD5/AES/RSA 常量和 Reflection.Emit/GetManifestResourceStream 等保护运行库特征; 其真实性未验证。

> **证据**：payload Assembly=HWMonitor 2.8, Module=HWMonitor.dll; strings 'HWMonitor Pro'/'CPUID SARL'/'Professional-grade hardware monitoring...'; MD5 T-table @0x15dbe
> 
> **来源**：`ev-000006` · `ev-000007` · `ev-000008`


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
| `embedded_payload_resource` | `TW1 (177x176 Bitmap, 解码上限 92160 字节)` | 是 | 静态 |
| `decode_budget_bytes` | `92160` | 是 | 静态 |
| `payload_assembly` | `HWMonitor 2.8 / HWMonitor.dll` | 是 | 静态 |
| `payload_sha256` | `be02d40783e5f695449a8d700f27a11cee7443bc3bb75fe554314a0ba15ad576` | 是 | 静态 |
| `loader_member` | `AppDomain.Load(byte[]) via Microsoft.VisualBasic LateBinding` | 是 | 静态 |
| `activation_args` | `4342677A\|''\|MountainHut (由 intConn 按 '4F 49 4C' 分割得到)` | 是 | 静态 |
| `activation_resource` | `CBgz (929x977 Bitmap, '4342677A' 的 ASCII 即 CBgz)` | 否 | 静态 |
| `decoy_application` | `Mountain Hut / oqNZ.exe (WinForms 旅舍补给模拟, Alpine Supply Systems)` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得断言存在 C2 或外联行为: 主程序与载荷均未发现 URL/域名/公网 IP, 载荷仅引用本地 .NET 库, 动态沙箱也未取得可用的网络时间线。
- 不得断言窃密/勒索/挖矿能力: 未观察到浏览器数据、钱包、文件加密或矿池相关操作, 这些能力没有证据支撑。
- 不得仅凭 .text 高熵就判为传统加壳: 该段同时存放 .NET 元数据/IL 与图片资源, 属于托管程序与隐写载荷的组合, 不是 UPX 类原生壳。
- 不得把 'HWMonitor Pro' 名称直接当作已知恶意家族签名: 无厂商引擎或 YARA 佐证, 且载荷内同时存在游戏/关卡字符串, 与正版产品特征不一致, 真实性待核实。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `be02d40783e5f695449a8d700f27a11cee7443bc3bb75fe554314a0ba15ad576`） |

**局限与待验证**

1. 隔离动态沙箱的观测请求在超时内未返回, 未取得进程/内存/网络时间线, 因此 reproduced=false; 所有结论均为静态反编译与载荷提取所得。
2. 未发现任何 C2、URL、域名或公网 IP, 无法给出网络 IOC; 不排除载荷在特定条件下才启用网络能力。
3. 第二段程序集带有明显的 .NET 混淆/保护特征(随机资源名、Reflection.Emit、AES/RSA/MD5 常量), 其内部行为未逐方法还原, 真实用途与正版 HWMonitor Pro 的关系未验证。
4. 外层 PE 的 entry_point.rva=0 且导入表为空, 属纯托管入口形态; 无法排除部分资源或元数据被刻意构造以干扰分析。
5. 动态档位虽已调用隔离沙箱原语, 但因超时未获得可用产物, 不应据此认为样本无恶意行为。

## 证据索引

<details>
<summary>展开 8 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=3fb044653334e89c68176d670bedbec83c2e09a2a609b4814eee1575fda6da2d, size=2665984 |
| `ev-000002` | scan.entropy | .text 段熵 7.91(高), 覆盖 off 512..2664448 |
| `ev-000003` | scan.entropy | .rsrc 段熵 4.149 |
| `ev-000004` | 样本分诊 | 加壳可能性 0.60: 可执行段高熵 7.91, 导入符号 0 |
| `ev-000005` | 字符串提取 | 主程序字符串: MountainHut 窗体/DataSet/资源键 TW1、CBgz、Screenshot_2026_04_11_230907 等 |
| `ev-000006` | 字符串提取 | 第二段字符串: HWMonitor.dll / HWMonitor Pro / CPUID SARL / 加密与反射 API 名 |
| `ev-000007` | 密码学常量识别 | 第二段命中 MD5 T-table @0x15dbe |
| `ev-000008` | evidence.record | 脚本复现解码: TW1 位图 -> 92160 字节 -> MZ/PE 程序集 sha256 be02d407..., 并提取激活参数 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
