---
title: "恶意样本分析：Astronexx Installer（PE · exe · 1453f354）"
published: 2026-11-22
draft: false
description: "灰色/PUA（置信度中）：Astronexx Installer · pua_bundler/loader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Astronexx Installer", "pua", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!CAUTION]
> **判定：灰色/PUA** · 家族 **Astronexx Installer**（存疑） · 置信度 **中**
> 
> 别名：BitComet Installer 假冒包、Astronexx 签名加密安装器
> 
> 样本是 Inno Setup 6.7 制作的自解压安装器，版本资源自称 BitComet Installer 2.23.11[.]2，但签名主体为 Astronexx，产品厂商与签名厂商不一致；安装数据在明文版本头之后整体高熵（约 8.0）且程序内置口令与 ChaCha20 加密支持，属于规避静态检测的可疑打包方式。动态运行仅观察到其把安装引擎释放到 %TEMP% 并常驻等待，未在无口令条件下落盘或联网。综合判定为潜在不需要/捆绑安装器，具体载荷因加密未能取证。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Astronexx Installer** · 别名 BitComet Installer 假冒包、Astronexx 签名加密安装器 · _存疑_ |
| 置信度 | **中** |
| 行为类 | pua_bundler · loader |
| 难度 | medium |
| 首次出现 | 2026-11-21 00:30:21 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/1453f3543d436969a05a641894d511a128a11030d79b9af16b8b430d42faedaf/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装 BitComet 安装器</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">使用有效代码签名</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">加密安装数据</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">释放安装引擎到临时目录</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">常驻等待安装口令</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `1453f3543d436969a05a641894d511a128a11030d79b9af16b8b430d42faedaf` |
| MD5 | _未记录_ |
| 大小 | 3,028,296 字节（2.9 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **6** 条行为，每条都挂了证据；其中 **3** 条静态可得、**3** 条经动态分析取得。

### 1. 伪装 BitComet 安装器

`T1036` · 置信度 **高** · 静态

PE 版本资源声明 FileDescription=BitComet Installer、ProductName=BitComet、FileVersion 与 ProductVersion=2.23.11[.]2，CompanyName 为空；而文件实际签名主体为 Astronexx，构成产品厂商身份不一致的伪装。

> **证据**：版本资源 StringFileInfo：BitComet Installer / BitComet / 2.23.11[.]2；证书 Subject=CN=Astronexx, O=Astronexx, C=IL
> 
> **来源**：`call_795df3fa82fe47d5a224aee8` · `call_e70e896488ec48e4a575c20b`

### 2. 使用有效代码签名

`T1553.002` · 置信度 **高** · 静态

文件携带有效的 Authenticode 签名，签名主体为 Astronexx，签发链为 Sectigo Public Code Signing CA R36，带 DigiCert 时间戳（2026-02-11），可使基于“未签名/签名无效”的安全策略放行。

> **证据**：Get-AuthenticodeSignature：Status=Valid，Signer CN=Astronexx；证书有效期 2024-11-14 至 2026-11-15
> 
> **来源**：`call_e70e896488ec48e4a575c20b` · `call_a80bbe1588654bad80704b67`

### 3. 加密安装数据

`T1027` · 置信度 **高** · 静态

在文件偏移 0x19E7AD 处为明文头 “Inno Setup Setup Data (6.7.0)”，其后 1,319,291 字节熵为 8.0，无法读出安装清单与文件名；程序包含 TSetupEncryptionKey/TSetupEncryptionNonce 与 ChaCha20 实现，并提示使用 /PASSWORD= 口令，表明安装数据经口令加密。

> **证据**：0x19E7AD “Inno Setup Setup Data (6.7.0)”；其后数据熵 8.0；字符串 TSetupEncryptionKey、TSetupEncryptionNonce、ChaCha20.pas、Please specify the password using the /PASSWORD= command line parameter
> 
> **来源**：`call_15ccacd4f6c74b96bf9eb14c` · `call_8e05d519aa844dd8bcbdbd98` · `ev-000017`

### 4. 释放安装引擎到临时目录

`T1036.005` · 置信度 **高** · 动态

运行时父进程将 Inno Setup 安装引擎释放至 %TEMP%\is-UXFOYWE0NV.tmp\<安装包文件名>.tmp，并以 /SL5="$40112,1697709,940544,..." 参数启动；其中 1697709（0x19E7AD）正是加密安装数据的偏移。

> **证据**：动态事件：PID 5000 → PID 6864，命令行含 /SL5="$40112,1697709,940544,C:\dyn\samples\<sha256>.exe"；镜像路径 %TEMP%\is-UXFOYWE0NV.tmp\<sha256>.tmp
> 
> **来源**：`call_c03dc7b5b2f84658b502bbf1` · `call_791882527a8c42eca742d5d5` · `call_34fd32155a7740a2a8dbbdc5`

### 5. 常驻等待安装口令

`T1204.002` · 置信度 **中** · 动态

临时目录中的引擎进程以 Setup/Uninstall 版本信息运行，在观测窗口内持续存活（约两分钟）且未再创建安装子流程，符合口令保护安装器在等待用户输入口令的状态；需用户交互才会继续。

> **证据**：内存取证在样本启动约 2 分钟后仍能扫描到 PID 6864；时间线内该进程无后续子进程、无文件落地
> 
> **来源**：`call_69026298c7384a7a91fc7d0a` · `call_791882527a8c42eca742d5d5`

### 6. 创建临时安装子进程

`T1106` · 置信度 **高** · 动态

父进程通过 CreateProcessW 启动临时目录中的安装引擎，构成本样本在分析窗口内唯一可见的进程链；导入面同时包含 VirtualAlloc/VirtualProtect/VirtualQuery 等 API，但未观察到注入行为。

> **证据**：导入表 CreateProcessW（IAT RVA 783164）、VirtualProtect（783096）、VirtualAlloc（783312）；动态进程创建事件 PID 5000 → PID 6864
> 
> **来源**：`call_e3344d6bed30403ca6bea057` · `call_34fd32155a7740a2a8dbbdc5`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `%TEMP%\is-<随机>.tmp\<安装包文件名>.tmp`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `encryption_algo` | `ChaCha20（Inno Setup 6.7 加密安装数据）` | 是 | 静态 |
| `password_required` | `true（安装器要求 /PASSWORD= 口令）` | 是 | 静态 |
| `setup_data_offset` | `0x19E7AD（1,697,709）` | 否 | 静态 |
| `setup_data_entropy` | `8.0（1,319,291 字节，无可读文件清单）` | 否 | 静态 |
| `payload_recovered` | `false（未取得口令，加密负载未解出）` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得声称样本已安装 BitComet 或已投放任何具体恶意载荷：安装数据在无口令条件下未被解出，运行期也未观察到安装目录、落地文件或载荷执行。
- 不得仅凭签名有效就认定其为 BitComet 官方发布：签名主体为 Astronexx，与版本资源中的 BitComet 不一致。
- 不得把导入表中的 VirtualAlloc/VirtualProtect/VirtualQuery 等 API 的存在当作注入或内存马证据：调用链未证实，动态观测仅见子进程创建。
- 不得把分析环境自身的网络拦截服务或系统证书流量写成样本的 C2/外联行为；分析窗口内未记录到样本进程发起的网络请求。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 安装数据使用口令加密（ChaCha20），未取得口令，无法提取文件清单、安装脚本、最终落地组件和任何后续载荷。
2. 动态运行未输入口令，仅观察到引擎释放与常驻等待阶段；未观测到 C2、持久化、服务或计划任务，不能据此排除后续恶意行为。
3. 网络监控仅记录到系统自身的证书/更新流量，未见样本进程的 DNS/HTTP/TCP 请求，因此 C2 列表为空。
4. 运行前后状态对比未发现可归因于样本的文件、注册表自启动项、服务或计划任务改动；新增的网络拦截服务属于分析环境组件。
5. 未使用多引擎或公开沙箱结果，家族归属基于签名与打包特征，存在不确定性。

## 证据索引

<details>
<summary>展开 16 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `call_07c8b16ab39e4fbfb68431fd` | 静态分诊 | 哈希、段熵、导入导出面与结构异常分诊 |
| `call_91361dea97c34b81a8ab7346` | 静态结构解析 | PE 头/数据目录/节表：SECURITY 目录 11,296 字节、节布局与入口点 |
| `call_e3344d6bed30403ca6bea057` | 导入表解析 | 150 个导入符号，含 CreateProcessW、VirtualAlloc、VirtualProtect、VirtualQuery |
| `call_b8840142616246be8f98c1b8` | 导出表解析 | 导出 SetupLdr.e32、dbkFCallWrapperAddr、__dbk_fcall_wrapper，确认 Inno Setup 加载器 |
| `call_078bffcb814d4837a7edf88e` | 字符串扫描 | ASCII/UTF-16 字符串及 Inno Setup、加密/口令相关字符串 |
| `call_a80bbe1588654bad80704b67` | 签名与覆盖层脚本 | 定位 0x19E7AD 安装数据、解析签名证书链与签名者 Astronexx |
| `call_e70e896488ec48e4a575c20b` | 签名校验 | Authenticode Status=Valid，签名者 CN=Astronexx，时间戳 2026-02-11 |
| `call_15ccacd4f6c74b96bf9eb14c` | 覆盖层熵分析 | 安装数据区 1,319,291 字节熵 8.0，无可读文件清单 |
| `ev-000017` | 自述脚本核验 | 综合脚本结论：加密安装数据、有效签名、版本资源与内存检索结果 |
| `call_c03dc7b5b2f84658b502bbf1` | 动态沙箱观测 | 回滚→投放→轮询→内存取证的时间线与转储清单 |
| `call_791882527a8c42eca742d5d5` | 内存取证 | PID 5000 为样本本体、PID 6864 为 %TEMP% 下释放的 Setup/Uninstall 引擎 |
| `call_34fd32155a7740a2a8dbbdc5` | 系统事件日志 | 进程创建/注册表/服务事件对比：样本进程链与无自启动项改动 |
| `call_1783bf1c5ab34e41a0bb0a99` | 网络监控日志 | 分析窗口内仅系统证书/更新流量，无样本进程网络请求 |
| `telemetry:1453f354` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 116 条；ETW 短命进程事件 2 条；已过滤工具/系统噪声 22 条 |
| `etw:1453f354:5000` | 进程事件监控 | 短命进程事件：1453f3543d436969a05a641894d511a128a11030d79b9af16b8b430d42faedaf.exe（pid 5000；MD5=6DAA57A6DE2089247B285729EF63E985,SHA256=1453F3543D436969A05A641894D511A128A11030D79B9AF16B8B430D42FAEDAF,IMPHASH=88016FCDEF7F227C62171D0AFAD9AAE4） |
| `etw:1453f354:6864` | 进程事件监控 | 短命进程事件：1453f3543d436969a05a641894d511a128a11030d79b9af16b8b430d42faedaf.tmp（pid 6864；MD5=FFF07A0E94AE80F0F88A1DF40BEEE103,SHA256=DF9F982BDF4DE66D23BC423B5992E1590A72417E65F5C87397702F386D7E05AD,IMPHASH=4F3A70412C909E6E8F69020F0BEE4F39） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
