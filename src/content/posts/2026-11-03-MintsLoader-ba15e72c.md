---
title: "恶意样本分析：MintsLoader（PE · exe · ba15e72c）"
published: 2026-11-03
draft: false
description: "恶意（置信度低）：MintsLoader · downloader/loader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Mints", "downloader", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **MintsLoader**（存疑） · 置信度 **低**
> 
> 别名：MintLoader
> 
> 样本为 NSIS 安装器，运行后由同一进程持续向 hxxp://109.248.151[.]106/VzDeNIilOBcrr195.bin 发起周期性 HTTP GET（约每 10 秒一次，Firefox UA），请求在真实动态沙箱网络监控中被完整观测；同时其 Authenticode 签名摘要与文件内容不符，版本信息为随机词伪造，安装包内塞入数 MB 常量填充文件与随机命名诱饵文件。综合为下载/加载器类恶意软件。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **MintsLoader** · 别名 MintLoader · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · loader |
| 难度 | medium |
| 首次出现 | 2026-11-03 06:44:32 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ba15e72ccec9f88b88d0a0c5c141ff66d21ad050f277427182fbb7061854b780/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">移植失效代码签名</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">伪造安装器版本信息</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">塞入数兆填充文件</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">铺设随机名诱饵目录</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">以 NSIS 安装器执行</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ba15e72ccec9f88b88d0a0c5c141ff66d21ad050f277427182fbb7061854b780` |
| MD5 | _未记录_ |
| 大小 | 648,168 字节（633.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **8** 条行为，每条都挂了证据；其中 **4** 条静态可得、**4** 条经动态分析取得。

### 1. 移植失效代码签名

`T1553.002` · 置信度 **高** · 静态

PE 带 Authenticode 签名与 RFC3161 时间戳，签名者 CN=Fileside（Certum 签发），但内嵌 SHA-256 摘要与按规范重算的文件摘要不一致，属于签名移植或签名后篡改，不能作为可信依据。

> **证据**：SECURITY 目录 RVA/偏移 0x9D178、大小 4720；内嵌摘要 1768f394… vs 计算值 deaed425…
> 
> **来源**：`ev-000012` · `ref:828deee609`

### 2. 伪造安装器版本信息

`T1036.005` · 置信度 **高** · 静态

VERSIONINFO 使用无意义随机词：OriginalFilename/InternalName=pygmean ageing.exe、CompanyName=isobutene moity、ProductName=beylic fedtlderstvlens classable、Comments=unsole、LegalCopyright=choir huldskab，且文件名与被安装内容无关。

> **证据**：资源段 VERSIONINFO 字符串（UTF-16，文件偏移约 0x1E6xx-0x1E9xx）
> 
> **来源**：`ev-000011` · `ref:3480ae8653`

### 3. 塞入数兆填充文件

`T1027` · 置信度 **高** · 静态

NSIS 数据区携带两个数 MB 的常量填充文件（0xA8 重复 2,926,106 字节；'6' 重复 4,454,307 字节）以及 137KB/160KB 高熵无语义数据块，用于撑大安装包、绕过体积与内容检测，本身不被执行。

> **证据**：calphurnia.fem 0xA8×2926106（熵 0.16）；fusiformis.opm 0x36×4454307（熵 0.16）；Pragmatism 熵 7.77
> 
> **来源**：`ev-000011`

### 4. 铺设随机名诱饵目录

`T1036` · 置信度 **中** · 动态

安装器把 Mimoses\Hovedindgange 树（真实 JPEG 照片 + 随机词命名的 ini/txt）释放到用户目录下的随机名路径；进程内存中可见输出目录字符串，磁盘文件清单未捕获。

> **证据**：内存字符串 C:\Users\analyst\Larikin203\Mimoses\Hovedindgange\；归档条目 Mimoses\Hovedindgange\*.jpg/*.ini
> 
> **来源**：`ev-000013` · `ev-000011`

### 5. 以 NSIS 安装器执行

`T1204.002` · 置信度 **高** · 静态

文件为 32 位 NSIS 3 Unicode 安装器（$PLUGINSDIR\System.dll），以 GUI 子系统启动；样本依赖用户运行安装器触发后续下载逻辑，PE 本体不含恶意代码。

> **证据**：pe_parse entry RVA 0x358D / subsystem GUI；overlay@0x1EE00 为 NSIS 包，含 System.dll 插件
> 
> **来源**：`ref:828deee609` · `ev-000011`

### 6. HTTP 回连拉取载荷

`T1071.001` · 置信度 **高** · 动态

样本进程向 109.248.151[.]106:80 发送 GET /VzDeNIilOBcrr195.bin，Host 头为裸 IP，UA 伪装 Firefox 157，无 Cookie/Referer，响应本应为下一阶段二进制（沙箱仅回放仿真响应）。

> **证据**：网络事件 19:29:32 GET /VzDeNIilOBcrr195.bin Host: 109.248.151[.]106；内存中同串 URL 与 winhttp/urlmon 加载痕迹
> 
> **来源**：`ref:849a787224` · `ev-000013`

### 7. 下载可执行二阶段

`T1105` · 置信度 **中** · 动态

请求路径为随机串 .bin，符合下载并加载下一阶段 PE 的加载器模式；本次未取得服务器真实响应，二阶段内容与执行链未能确认。

> **证据**：GET /VzDeNIilOBcrr195.bin 周期性出现；进程已加载 winhttp.dll/urlmon.dll/wininet.dll
> 
> **来源**：`ref:849a787224` · `ev-000013`

### 8. 十秒周期重试下载

`T1105` · 置信度 **高** · 动态

同一下载请求约每 10 秒重复一次并持续至观测结束（19:29:32 至 19:31:53 共 13 次），说明下载失败后进入固定间隔轮询，而非一次性请求。

> **证据**：网络时间线 19:29:32 / 19:29:42 / … / 19:31:53 每 10s 一次 GET 同路径
> 
> **来源**：`ref:849a787224`


## IOC（已去武器化）

### 网络

:::note
**已动态观测到连接**：样本实际向该目标发起 TCP 连接（短时间内多次重试）。
:::

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控仿真服务完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://109[.]248[.]151[.]106/VzDeNIilOBcrr195[.]bin` | 80 | c2 | 动态 | 已观测 |

### 主机

**落地路径**

- `%USERPROFILE%\Larikin203\Mimoses\Hovedindgange\`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `109.248.151[.]106` | 是 | 动态 |
| `c2_url` | `hxxp://109[.]248[.]151[.]106/VzDeNIilOBcrr195[.]bin` | 是 | 动态 |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0` | 否 | 动态 |
| `beacon_interval_sec` | `10` | 否 | 动态 |
| `install_path` | `%USERPROFILE%\Larikin203\Mimoses\Hovedindgange\` | 否 | 静态 |
| `signature_subject` | `C=DE, L=Berlin, O=Fileside, CN=Fileside (Certum Code Signing 2021 CA; digest mismatch)` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能称其为勒索软件或擦除器：未观测到文件加密、批量删除或勒索信。
- 不能称其为信息窃取器：未观测到浏览器凭据、钱包、剪贴板或文档收集行为。
- 不能认定其建立了持久化：未观测到 Run 键、服务、计划任务或启动目录写入。
- 不能因签名 CN=Fileside 就认定这是 Fileside 官方软件：签名摘要与文件内容不匹配，属移植/失效签名。
- 不能把安装包内的 JPEG、随机 ini/txt 与数 MB 填充文件当作恶意载荷：它们未被观测到执行。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 二阶段载荷未取得：沙箱网络为仿真回放，服务器真实响应未知，后续窃密/远控/挖矿等能力无法确认，stage2 为空。
2. 未采集文件系统写入清单：诱饵目录只在进程内存字符串中出现，无法证明文件已落盘及具体清单。
3. 家族归属为候选（MintsLoader-like）：缺少厂商命名/YARA 或配置解密串的直接对应，置信度低。
4. NSIS 脚本头解析在 7z 中报 BadCmd=13，未能还原完整安装脚本；安装/下载逻辑由动态行为与内存字符串推断。
5. 未观察到权限提升、UAC 绕过或注入行为；若二阶段包含此类能力，本次观测不到。

## 证据索引

<details>
<summary>展开 13 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=ba15e72c…, md5=f1f1f53f…, size=648168 |
| `ev-000002` | scan.imphash | imphash=573bb7b41bc641bd95c0f5eec13c233b |
| `ref:828deee609` | PE 结构解析 | PE32 i386, entry RVA 0x358D, subsystem GUI, 5 节, SECURITY 目录 0x9D178/4720, 无异常 |
| `ref:3480ae8653` | 字符串提取 | ASCII 1206 / UTF-16 50 条，含 NSIS 错误串与伪造 VERSIONINFO |
| `ref:4cbb998e7d` | 导入表解析 | 7 DLL / 163 符号；注册表、ShellExecute、文件复制等 NSIS 运行库导入 |
| `ref:849a787224` | 动态分析平台 | 真实动态：PID 1348 每 10s 请求 109.248.151[.]106:80 GET /VzDeNIilOBcrr195.bin；进程表/内存转储/网络日志已打包 |
| `ref:cbe5604e9b` | dyn.run | 仿真仅完成 NSIS 加载器初始化（55 次 API），无文件/网络行为 |
| `ref:6a819f2189` | unpack.detect | 未检测到加壳（packed=false） |
| `ref:48ec8bf950` | unpack.antidebug | 未识别到反调试/反分析技术 |
| `ev-000011` | 脚本化取证 | NSIS 解包清单：诱饵照片/随机 ini/数 MB 填充文件 + System.dll |
| `ev-000012` | 脚本化取证 | Authenticode 摘要不匹配，签名者 Fileside/Certum，签名时间 2025-03-04 |
| `ev-000013` | 脚本化取证 | 进程内存含 C2 URL 与 %USERPROFILE%\Larikin203\Mimoses\Hovedindgange\ 路径 |
| `c2_evidence:ba15e72c` | 连接证据提取 | 动态网络监控记录到 20 次到 109.248.151[.]106:80, 109[.]248[.]151[.]106:80 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
