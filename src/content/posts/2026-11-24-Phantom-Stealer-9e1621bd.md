---
title: "恶意样本分析：Phantom Stealer（PE · exe · 9e1621bd）"
published: 2026-11-24
draft: false
description: "恶意（置信度高）：Phantom Stealer · stealer/spyware · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Phantom", "stealer", "spyware", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Phantom Stealer** · 置信度 **高**
> 
> 别名：PhantomStealer、Phantom
> 
> 外层是伪装成渔业模拟游戏的 .NET 程序，启动时从其内嵌位图资源中按像素 RGB 通道还原出一个 .NET DLL，再通过反射 Load/Activator 激活。真实动态沙箱中该进程向 api[.]telegram[.]org 的固定 Bot 上传桌面截图、浏览器口令报告、Cookie 报告与信用卡报告，并在报告标题中自报 Phantom Stealer v4.0.0，属于完整的数据窃取与回传行为。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Phantom Stealer** · 别名 PhantomStealer、Phantom |
| 置信度 | **高** |
| 行为类 | stealer · spyware |
| 难度 | medium |
| 首次出现 | 2026-11-23 08:10:50 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/9e1621bde6fe02497bd1dfb21036111e38ca10efde31e3af2cf0eecbc77e54a4/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">位图隐写藏 DLL</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">反射加载内嵌 DLL</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">伪装渔业模拟程序</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">窃取浏览器凭据</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">抓取桌面截图外发</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1113</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `9e1621bde6fe02497bd1dfb21036111e38ca10efde31e3af2cf0eecbc77e54a4` |
| MD5 | _未记录_ |
| 大小 | 2,562,560 字节（2.4 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **4** 条静态可得、**5** 条经动态分析取得。

### 1. 位图隐写藏 DLL

`T1027.003` · 置信度 **高** · 静态

内嵌资源 'Credit' 是一张 153x152 32bpp 位图，其像素 R/G/B 通道按列优先顺序拼接后前 69632 字节恰为 PE 文件头 MZ，构成一个 32 位 .NET DLL。

> **证据**：资源流偏移 0x157E0，BMP 位于 0x159D0；解码产物 sha256=073eaa…31dd；pe_parse 显示 machine=I386、导入 mscoree!_CorDllMain
> 
> **来源**：`ref:32b2a7f7a9` · `ref:d07e86589b`

### 2. 反射加载内嵌 DLL

`T1620` · 置信度 **高** · 静态

BayForm.InitializeComponent 用 LateBinding.LateGet(...,"Load", [解码字节]) 取得 Assembly，取 GetExportedTypes[1]，再用拆分的字符串参数调用 Activator.CreateInstance 激活载荷。

> **证据**：IL_48C3–IL_4933：Thread.GetDomain → LateGet("Load") → GetExportedTypes → Regex.Split(intConn,"72D71DAD9") → Activator.CreateInstance
> 
> **来源**：`ref:32b2a7f7a9`

### 3. 伪装渔业模拟程序

`T1036.005` · 置信度 **高** · 静态

外层程序包含完整的 Baduk/渔业季节点菜、XSD 校验与 XML 报告功能及大量韩语罗马字 UI 字符串，用作窃密载荷的掩护界面。

> **证据**：#US 流含 'Cornish Pilchard Seine'、'XSD Geomjeung' 等 UI 文本；Program.Main 仅 new BayForm 后 Application.Run
> 
> **来源**：`ref:0151deea7b` · `ref:32b2a7f7a9`

### 4. 窃取浏览器凭据

`T1555.003` · 置信度 **高** · 动态

运行后生成浏览器口令报告 HTML、Cookie 报告 JSON 与信用卡报告 HTML，并在无浏览器数据时返回 'No recovery data found' / 统计为 0 的结构化报告。

> **证据**：网络监控 捕获 PW_*.html、CO_*.json（含 ChromiumBrowsers/GeckoBrowsers 统计字段）、CC_*.html（'Credit Card Recovery Results'）
> 
> **来源**：`ref:68ae1e8b0c`

### 5. 抓取桌面截图外发

`T1113` · 置信度 **高** · 动态

向 Telegram 上传 1371x727 的 PNG 桌面截图，文件名形如 SC_<用户>_<主机>_<时间>.png，并附带系统信息 caption。

> **证据**：网络监控 POST multipart filename=SC_analyst_DESKTOP-7QK4M2P_20261125_022117.png，正文以 PNG 魔数开始
> 
> **来源**：`ref:68ae1e8b0c`

### 6. Telegram Bot 回传

`T1567` · 置信度 **高** · 动态

通过 hxxps://api[.]telegram[.]org/bot<token>/sendDocument 向 chat_id=8318921728 分四次上传截图、口令、Cookie、信用卡报告。

> **证据**：4 次 POST /bot8434269883:AAGOIsbCStlszeizPd-pZb54sSuJR0Vc0qY/sendDocument，multipart 字段 chat_id=8318921728
> 
> **来源**：`ref:68ae1e8b0c`

### 7. 查询公网 IP

`T1016` · 置信度 **高** · 动态

启动后先解析并 GET hxxp://icanhazip[.]com/ 以获取受害者公网地址，再随报告回传内网、网关与外部 IP。

> **证据**：网络监控：DNS 'icanhazip[.]com' → GET / Host: icanhazip[.]com；caption 含 Gateway IP/Internal IP/External IP
> 
> **来源**：`ref:68ae1e8b0c`

### 8. 回传主机与杀软信息

`T1082` · 置信度 **高** · 动态

报告 caption 收集用户名、计算机名、系统版本、语言、杀软名称与网络位置并随附件发送。

> **证据**：caption 行：Username: analyst / CompName: DESKTOP-7QK4M2P / Antivirus: Windows Defender / System: Windows 10
> 
> **来源**：`ref:68ae1e8b0c`

### 9. 字符串加密与混淆

`T1027` · 置信度 **高** · 静态

载荷程序集使用格鲁吉亚字母类型/方法名、SuppressIldasm、运行时解密字符串并通过反射调用方法，明显为 .NET 混淆器产物。

> **证据**：类型名 ႤႨ/ႳႤ，方法 ႠႤ/ႭႷ；MemberRef 含 SuppressIldasmAttribute、Type.GetMethods、MethodBase.Invoke
> 
> **来源**：`ref:f7dfed3514` · `ref:504f6a8a38`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| telegram | `hxxps://api[.]telegram[.]org/bot8434269883:AAGOIsbCStlszeizPd-pZb54sSuJR0Vc0qY` | 443 | exfil | 静态 | ⏳ 未观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `api[.]telegram[.]org` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `c2_uri` | `/bot8434269883:AAGOIsbCStlszeizPd-pZb54sSuJR0Vc0qY/sendDocument` | 是 | 静态 |
| `bot_token` | `8434269883:AAGOIsbCStlszeizPd-pZb54sSuJR0Vc0qY` | 是 | 动态 |
| `chat_id` | `8318921728` | 是 | 动态 |
| `ip_check_url` | `hxxp://icanhazip[.]com/` | 否 | 动态 |
| `exfil_types` | `screenshot(PNG), passwords(HTML), cookies(JSON), credit cards(HTML)` | 是 | 动态 |
| `embedded_payload_sha256` | `073eaa28846bed6b2702b3cc9ce3d4c63669293d16714b8e07f5da0a59aa31dd` | 是 | 静态 |
| `assembly_name` | `ISLC Edited` | 否 | 静态 |
| `activation_args` | `646A6B44,726467,CornishPilchardSeine` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不是勒索软件：未观察到文件加密/勒索信息，核心行为是窃取与外传。
- 外层渔业模拟界面不是无害游戏本体：其真实用途是加载隐藏窃密 DLL。
- 未观察到键盘记录、注册表持久化或服务创建，不应声称具备这些能力。
- 本次沙箱内浏览器无凭据数据，回传内容为 0 条，不能据此声称已实际窃得真实用户口令。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `073eaa28846bed6b2702b3cc9ce3d4c63669293d16714b8e07f5da0a59aa31dd`） |

**局限与待验证**

1. 动态沙箱投放阶段出现过基础设施繁忙，最终仅有单次成功运行窗口可引用；其余失败与样本无关。
2. 沙箱客体未安装浏览器，口令/Cookie/信用卡报告内容为空，无法验证其对真实浏览器数据库的解析细节。
3. 载荷字符串经 .NET 混淆加密，未完整枚举全部功能（如钱包/即时通讯软件窃取）不能排除。
4. Telegram 与 icanhazip 请求由沙箱假网接住，外部 IP 等返回值为伪造，仅证明请求形态与目标。
5. 未观察到持久化、提权或横向移动行为。

## 证据索引

<details>
<summary>展开 7 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:fbad56068c` | 样本分诊 | 外层 PE 分诊：.text 熵 7.951、0 导入、加壳评分 0.6 |
| `ref:32b2a7f7a9` | PE 结构解析 | AMD64 .NET 程序，EP=0，仅 .text/.rsrc，COR20 元数据 + 资源目录 |
| `ref:0151deea7b` | 字符串提取 | 外层含 'Cornish Pilchard Seine' 等 UI 字符串，无 URL/进程/网络 API 字符串 |
| `ref:d07e86589b` | PE 结构解析 | 解码出的 stage1 为 PE32 DLL，I386，导入 mscoree!_CorDllMain |
| `ref:504f6a8a38` | 导入表解析 | stage1 仅导入 mscoree.dll!_CorDllMain（.NET DLL） |
| `ref:f7dfed3514` | 字符串提取 | stage1 程序集名 'ISLC Edited'，类型 GamePanel/Form1，格鲁吉亚文混淆标识 |
| `ref:68ae1e8b0c` | 动态分析平台 | win10 动态客体运行态；本次运行的 网络监控 日志见 dynamic-runs 对应样本目录 live/fakenet_divert.log，抓取 Telegram 外传会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
