---
title: "恶意样本分析：Softonic Bundler（PE · exe · d1ea1ce5）"
published: 2026-10-30
draft: false
description: "灰色/PUA（置信度高）：Softonic Bundler · pua_bundler/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Softonic Bundler", "pua", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!CAUTION]
> **判定：灰色/PUA** · 家族 **Softonic Bundler** · 置信度 **高**
> 
> 别名：Softonic_2、Softonic Downloader、PUA.Softonic
> 
> 运行时内存转储还原出完整的付费推广投放逻辑（检测 Chrome/Slack/.NET、从 CloudFront 拉取产品配置、下载并执行捆绑安装包、回传 JSON 遥测），并带有 Softonic_2 活动标识；文件由 Softonic EV 证书签名。未发现加密、窃密或持久化后门，定性为捆绑推广型 PUA。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Softonic Bundler** · 别名 Softonic_2、Softonic Downloader、PUA.Softonic |
| 置信度 | **高** |
| 行为类 | pua_bundler · downloader |
| 难度 | medium |
| 首次出现 | 2026-10-28 00:24:29 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/d1ea1ce5d9ba4b6456afd412abbb86d5ae540f4db0c2ee1719fe7ce6ebc9e970/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Inno 自解压加载</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">查询已装浏览器应用</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1012</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">采集主机指纹</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">HTTPS 获取投放配置</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">下载捆绑安装包</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `d1ea1ce5d9ba4b6456afd412abbb86d5ae540f4db0c2ee1719fe7ce6ebc9e970` |
| MD5 | _未记录_ |
| 大小 | 2,132,400 字节（2.0 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. Inno 自解压加载

`T1204.002` · 置信度 **高** · 静态

文件为 Inno Setup 6.7.0 安装器，导出 SetupLdr.e32/__dbk_fcall_wrapper；运行时以 /SL5="$C00BC,848247,840704,<exe>" 从自身 0xCF177/0xCD400 处读取安装数据。

> **证据**：pe.exports dll_name=SetupLdr.e32; 内存字符串 /SL5="$C00BC,848247,840704,..."; 数据头 'Inno Setup Setup Data (6.7.0)' @0xCF177
> 
> **来源**：`ref:ca9ae6d764` · `ev-000099`

### 2. 查询已装浏览器应用

`T1012` · 置信度 **高** · 静态

读取 SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe、Software\Google\Chrome\BLBeacon\version、{commonpf}\Google\Chrome\Application\chrome.exe、SOFTWARE\Slack 及 Uninstall 项、.NET NDP v4\Full，用于决定投放哪些产品。

> **证据**：内存 UTF-16 常量 @0x4b2d88/0x4b2e5f/0x4b3002/0x4abdf6/0x4b6a1f
> 
> **来源**：`ev-000099`

### 3. 采集主机指纹

`T1082` · 置信度 **高** · 静态

读取 MachineGuid、Windows NT CurrentVersion UBR、CPU 型号/主频、内存与磁盘空间、OS 位数，用于条件投放与遥测。

> **证据**：内存常量 MachineGuid @0x4a3a4f、SOFTWARE\Microsoft\Cryptography @0x4a3a79、HARDWARE\DESCRIPTION\System\CentralProcessor\0 @0x4b63ba
> 
> **来源**：`ev-000099`

### 4. HTTPS 获取投放配置

`T1071.001` · 置信度 **高** · 静态

通过 WinHttp.WinHttpRequest.5.1 对 hxxps://dviqfidnuw7nn[.]cloudfront[.]net/o 发起 GET，解析返回的 JSON 产品/规则清单（prv/plv/l/a/i/s/u/o 字段）。

> **证据**：内存常量 hxxps://dviqfidnuw7nn[.]cloudfront[.]net/o @0x4aae01，'GET' @0x4aa0f7，WinHttp.WinHttpRequest.5.1 @0x4aa067
> 
> **来源**：`ev-000099`

### 5. 下载捆绑安装包

`T1105` · 置信度 **高** · 静态

从 hxxps://dviqfidnuw7nn[.]cloudfront[.]net/f/ 下载产品安装包到 {tmp}\component，按 .exe/.msi/.zip 处理；zip 解压后取其中的可执行文件。

> **证据**：内存常量 hxxps://dviqfidnuw7nn[.]cloudfront[.]net/f/ @0x4bc408/0x4bc71e，'{tmp}\component' @0x4bd833，'no executable in zip' @0x4bde90
> 
> **来源**：`ev-000099`

### 6. 静默执行安装包

`T1204.002` · 置信度 **高** · 静态

对下载的 .exe/.msi 以 shell 'open' 方式执行，记录 execution failed/finish: Success/FAILED.png 等状态，安装完成页可勾选运行产品。

> **证据**：内存常量 'open' @0x4be901/0x4becba/0x4bfc26，'execution failed' @0x4be6f1，'finish: Success' @0x4bef3d
> 
> **来源**：`ev-000099`

### 7. 回传转化遥测

`T1041` · 置信度 **高** · 静态

向 hxxps://dviqfidnuw7nn[.]cloudfront[.]net/zbd 发送 POST application/json，内容含 makedate/scheme/subdomain/slack/insights 及 MachineGuid 等，Authorization 头使用 Signature= 形式。

> **证据**：内存常量 'POST' @0x4ad25a、'Authorization'/'Signature=' @0x4ad45e/0x4ad48c、'"insights":' @0x4acba8
> 
> **来源**：`ev-000099`

### 8. 有效签名掩护投递

`T1553.002` · 置信度 **高** · 静态

安装器带有效 Authenticode 签名（SOFTONIC INTERNATIONAL SA，Sectigo EV），可降低下载来源与执行时的信誉拦截概率。

> **证据**：Get-AuthenticodeSignature: Status=Valid, Subject=CN=SOFTONIC INTERNATIONAL SA
> 
> **来源**：`ref:bc595b1712`


## IOC（已去武器化）

### 网络

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://dviqfidnuw7nn[.]cloudfront[.]net/o` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://dviqfidnuw7nn[.]cloudfront[.]net/zbd` | 443 | exfil | 静态 | ⏳ 未观测 |
| http | `hxxps://dviqfidnuw7nn[.]cloudfront[.]net/f/` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%TEMP%\is-<random>.tmp\<sha256>.tmp`
- `%TEMP%\component`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `dviqfidnuw7nn[.]cloudfront[.]net` | 是 | 静态 |
| `config_url` | `hxxps://dviqfidnuw7nn[.]cloudfront[.]net/o` | 是 | 静态 |
| `telemetry_url` | `hxxps://dviqfidnuw7nn[.]cloudfront[.]net/zbd` | 是 | 静态 |
| `download_base` | `hxxps://dviqfidnuw7nn[.]cloudfront[.]net/f/` | 是 | 静态 |
| `campaign_id` | `Softonic_2` | 否 | 静态 |
| `analytics_namespace` | `zb_analytics` | 否 | 静态 |
| `framework_version` | `4.6.6` | 否 | 静态 |
| `transport` | `WinHttp.WinHttpRequest.5.1 (GET/POST application/json, Authorization: Signature=)` | 是 | 静态 |
| `targeting_checks` | `Chrome/Firefox/Slack/.NET 版本与安装状态；MachineGuid、CPU、RAM、磁盘、OS 版本` | 否 | 静态 |
| `publisher` | `SOFTONIC INTERNATIONAL SA（EV 代码签名，证书有效期 2026-01-28 至 2027-01-29）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不是勒索软件：未发现文件加密、勒索说明或影子副本删除行为。
- 不是窃密木马：脚本只读取浏览器/Slack 安装状态与 MachineGuid 等环境信息，未触及浏览器凭据、Cookie、钱包或键盘记录。
- 不能声称已观测到真实 C2 通信或下载：自动化引爆时网络监控未记录到 cloudfront 请求，C2/下载地址来自运行时内存中的脚本常量。
- 不能因具有效 Softonic EV 签名就判为良性：签名只证明发布者身份，不排除其安装器捆绑推广第三方软件。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. Inno Setup 6.7.0 的安装数据块格式较新，现有解包器无法解析，未能提取内嵌的 setup 数据/产品清单文件。
2. 沙箱内仅完成启动与向导阶段，无用户点击，故未真实触发 /o 配置拉取、/f/ 下载与捆绑安装，也未观测到任何到 cloudfront 的流量。
3. C2 与下载地址为脚本常量（静态），recoverability 标为 static 且 pending_dynamic_verify=true；未用模拟网络证实其当前可用性。
4. Download 的具体产品列表、下载文件哈希与最终落地名称取决于远端 /o 返回内容，本次未能获取。
5. 样本为 32 位 GUI 安装器，需交互；内存取证只能覆盖已加载的安装引擎与脚本逻辑，未覆盖远端下发阶段。

## 证据索引

<details>
<summary>展开 6 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:de56f3edae` | PE 结构解析 | PE32 GUI，11 节，入口 RVA 0xADE60，SECURITY 目录存在（RVA 0x205D40，大小 11376），无结构异常。 |
| `ref:ca9ae6d764` | pe.exports | 导出 dll_name=SetupLdr.e32，符号 dbkFCallWrapperAddr/__dbk_fcall_wrapper，确认 Inno Setup 加载器。 |
| `ref:e9e4603f7e` | 导入表解析 | 5 个 DLL/150 符号，含 FindResourceW/LoadResource/LockResource/SizeofResource（安装数据资源加载）等。 |
| `ref:91e2500d96` | 动态沙箱 | 真实引爆：pid 4888 启动，120s 内无新建进程、无进程空心化/注入；网络监控无 cloudfront/DNS 请求。 |
| `ev-000099` | evidence.record | 从进程内存转储提取的脚本常量：CloudFront /o、/zbd、/f/，Softonic_2、zb_analytics，浏览器/Slack/.NET 检测，下载执行与遥测逻辑。 |
| `ref:bc595b1712` | bash | 版本信息与签名：ProductName=Softonic--International (SA)，FileVersion=4.0.2[.]0；Authenticode 有效，签署者 CN=SOFTONIC INTERNATIONAL SA（Sectigo EV）。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
