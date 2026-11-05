---
title: "恶意样本分析：EzzVPN 主题安装器（NetGuard_S / BootPack 构建）（PE · exe · 0e4d87b4）"
published: 2026-11-05
draft: false
description: "恶意（置信度低）：EzzVPN 主题安装器（NetGuard_S / BootPack 构建） · dropper/pua_bundler · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["EzzVPN 主题安装器", "dropper", "pua", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **EzzVPN 主题安装器（NetGuard_S / BootPack 构建）**（存疑） · 置信度 **低**
> 
> 别名：EzzVPN Premium Client Setup、NetGuard_S installer、BootPack.e32 loader
> 
> 样本是一个以商业 VPN 客户端为外壳、经自建私有 CA 伪造厂商签名的安装/投放器：签名链根与中间 CA 均为自签（根证书 issuer==subject，叶证书与 CA 在签名前约 1 秒内签发），并用公共时间戳服务加盖以延长“签名有效期”；stub 在启动早期探测 Wine 兼容层；安装数据块签名被改为 'NetGuard_S Setup Data (6.7.0)'、内部单元名为 BootPackAndSetup.*、导出名 BootPack.e32，刻意隐藏安装器身份；section 之外附加 7.57MB 高熵（逐 256KB 熵≈7.999）加密/压缩载荷。真实沙箱中样本执行并自解压到 %TEMP% 下 32 位副本，但安装向导未完成，最终载荷功能未直接观测。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **EzzVPN 主题安装器（NetGuard_S / BootPack 构建）** · 别名 EzzVPN Premium Client Setup、NetGuard_S installer、BootPack.e32 loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | dropper · pua_bundler |
| 难度 | hard |
| 首次出现 | 2026-11-04 14:54:07 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/0e4d87b44ccd91af41c14719d39bd3362091a93aaea573c0038432abd70c266d/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪造代码签名证书</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">检测Wine仿真环境</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">改名安装引擎</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">内置加密载荷</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">自解压到临时目录</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `0e4d87b44ccd91af41c14719d39bd3362091a93aaea573c0038432abd70c266d` |
| MD5 | _未记录_ |
| 大小 | 8,593,424 字节（8.2 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **6** 条行为，每条都挂了证据；其中 **5** 条静态可得、**1** 条经动态分析取得。

### 1. 伪造代码签名证书

`T1553.002` · 置信度 **高** · 静态

PE 内嵌 Authenticode 签名，但签名链为自建：根证书 'Software Trust Root 557E06' 自签，其下签发 'Code Signing CA 557E06'，再签发叶证书 CN=ClearPath Networking Ltd.（OU=Engineering, L=San Jose, ST=California, C=US）。根、CA、叶三张证书的签发时间集中在签名前约 1 秒内，且由公共时间戳服务加盖时间戳；该链无法连接到公共受信根，Windows 显示为未知发布者。

> **证据**：证书表 file off=0x82FE68 size=10408；叶证书 serial=6aa86f66842652b9e4be548fa05c0df396819881，有效期 2026-11-04 13:40:04Z→2028-11-03；根 cert issuer==subject
> 
> **来源**：`ref:c41e7b6124` · `ref:20e017086a`

### 2. 检测Wine仿真环境

`T1497.001` · 置信度 **高** · 静态

启动早期先 GetModuleHandleW("ntdll.dll") 取模块基址，再以 GetProcAddress 查询导出 "wine_get_version" 判断是否运行于 Wine 兼容层；随后 VerSetConditionMask/VerifyVersionInfoW 校验系统版本。该探测出现在安装界面之前，属反分析/环境识别。

> **证据**：仿真 API 轨迹 pc=0x40E109 GetProcAddress(ret=0xFEEE0000, 'wine_get_version')，pc=0x4056FF VerifyVersionInfoW；字符串 wine_get_version 位于 .text file off 0x00D510
> 
> **来源**：`ref:e40f13771a` · `ref:dce356513a`

### 3. 改名安装引擎

`T1027` · 置信度 **高** · 静态

安装数据块签名被改为 'NetGuard_S Setup Data (6.7.0)'（标准 Inno Setup 为 'Inno Setup Setup Data (x.y.z)'），加载器内保存同一常量用于校验；内部 Delphi 单元名为 BootPackAndSetup.InstFunc / BootPackAndSetup.Messages / Compression.LZMA1SmallDecompressor，导出表 DLL 名为 BootPack.e32。改名与自研单元用于隐藏真实安装器来源、规避基于签名的检测。

> **证据**：数据块签名 off=0x6FC27D；加载器常量 off=0xB530C；导出 'BootPack.e32'/'__dbk_fcall_wrapper'/'dbkFCallWrapperAddr'；单元名表 off≈0xAFB52
> 
> **来源**：`ref:20e017086a` · `ref:b2f9374ce8` · `ref:ded64dd285`

### 4. 内置加密载荷

`T1027.002` · 置信度 **高** · 静态

在所有 section 结束（0x0F6800）之后附加 7,573,352 字节高熵数据（逐 256KB 熵约 7.999，起始 magic 7A6C621A），其后紧跟 10,408 字节 Authenticode 证书；该区域不对应任何 section，只能由运行中的安装器用其 LZMA1/加解密组件展开，静态无法读取文件清单与载荷。

> **证据**：PE 解析：section 原始数据结束 off=0x0F6800，security directory 指向 off=0x82FE68；熵扫描 29 个 256KB 窗口均≈7.999；magic 7A6C621A 位于 0x0F6800
> 
> **来源**：`ref:5b03866a6b` · `ref:02b646215e` · `ref:1fc5415ced`

### 5. 自解压到临时目录

`T1036.005` · 置信度 **高** · 动态

真实动态中样本以自身身份启动（pid 3924），随后在 %TEMP%\is-<随机>.tmp\ 下生成同名 .tmp 副本并以 32 位 WOW64 进程（pid 440）执行，该副本加载 winhttp.dll、ws2_32.dll、mpr.dll、comdlg32.dll、wtsapi32.dll 等组件；扫描时该进程内存未见注入、IAT 钩子或替换的映像。

> **证据**：动态时间线 pid 3924 → %TEMP%\is-F239MFSCLY.tmp\<sha256>.tmp (pid 440)；进程模块列表含 winhttp.dll/ws2_32.dll；内存转储中出现该临时路径字符串
> 
> **来源**：`ref:711ea6866c` · `ref:6de561a3a6` · `ref:728354e3d6`

### 6. 采集系统磁盘信息

`T1497.001` · 置信度 **中** · 静态

通过 VerifyVersionInfoW/GetVersionExW/GetSystemInfo/GetVolumeInformationW/GetDriveTypeW/GetTempPathW 采集系统版本、卷信息、磁盘类型与临时目录。上述调用与常规安装器的环境适配一致，单独不构成恶意判据，但与 Wine 探测组合后体现运行环境识别意图。

> **证据**：IAT rva：GetSystemInfo=783320，GetVolumeInformationW=783204，GetDriveTypeW=783212，VerifyVersionInfoW=783344，GetTempPathW=783324，GetVersionExW=783340
> 
> **来源**：`ref:349f9fc5e4` · `ref:e40f13771a`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `%TEMP%\is-<10字符随机>.tmp\<原文件名>.tmp`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `installer_engine` | `NetGuard_S Setup Data (6.7.0) / BootPackAndSetup (export DLL name BootPack.e32)` | 是 | 静态 |
| `product_name` | `EzzVPN Premium` | 是 | 静态 |
| `product_version` | `ProductVersion 1.1.43 / FileVersion 1.1.43[.]125` | 否 | 静态 |
| `company_name` | `EzzVPN Soft` | 否 | 静态 |
| `builder_comment` | `This installation was built with DataPack...` | 否 | 静态 |
| `signature_issuer` | `CN=ClearPath Networking Ltd. (self-signed root 'Software Trust Root 557E06')` | 是 | 静态 |
| `payload_blob` | `file offset 0x0F6800, size 7573352 bytes, entropy 7.999/256KB, magic 7A6C621A` | 是 | 静态 |
| `c2_hosts` | `-` | 否 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能断言已投放某个具体恶意家族或后门：安装向导未完成，未取得解包后的载荷，family 仅为品牌与构建器层面的候选，uncertain=true。
- 不能断言存在 C2 或持久化：真实动态窗口内未观测到样本自身发起的网络请求，也未观测到服务、计划任务或 Run 键写入。
- 不能仅凭导入表出现 VirtualAlloc/VirtualProtect/CreateProcessW/AdjustTokenPrivileges 就认定进程注入或提权——这些调用与常规安装器的内存解压、子进程启动、关闭占用文件的流程一致，且未观测到跨进程写入。
- 不能因高熵尾随数据就报 ransomware/stealer：高熵块是安装器的加密/压缩资源，未见文件加密、凭据读取或数据回传行为。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 安装向导需要人工交互，动态窗口内未完成安装，未观测到落地文件、服务、计划任务或网络回连，因此载荷性质与家族未证实。
2. 7,573,352 字节尾随数据经 LZMA1 与多种参数尝试均无法静态展开，判断其另有加密层或非标准封装，文件清单与落地路径不可静态获取。
3. Wine 探测（GetProcAddress("wine_get_version")）由指令级仿真直接观测，真实沙箱仅取得进程/内存快照，未取得 API 级调用日志，故该行为在真实环境中的触发时序未复核。
4. 未对签名 CMS 的摘要做二次校验，只能确认证书链为自建且不可信，不能据此断言文件在签名后被篡改。
5. 安装器进程的内部单元名与版权信息可被构建者任意设置，不能作为唯一归因依据。

## 证据索引

<details>
<summary>展开 14 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=0e4d87b44ccd91af41c14719d39bd3362091a93aaea573c0038432abd70c266d，size=8593424 |
| `ev-000002` | scan.imphash | imphash=88016fcdef7f227c62171d0afad9aae4 |
| `ref:02b646215e` | PE 结构解析 | PE32 Delphi/C++Builder 布局，11 sections，section 结束 off=0x0F6800，security directory off=0x82FE68 size=10408 |
| `ref:349f9fc5e4` | 导入表解析 | 5 DLL/150 符号：kernel32/user32/advapi32/oleaut32/comctl32，含 CreateProcessW/OpenProcessToken/AdjustTokenPrivileges/RegOpenKeyExW/RegQueryValueExW/VerifyVersionInfoW |
| `ref:b2f9374ce8` | pe.exports | 导出 DLL 名 BootPack.e32，导出 dbkFCallWrapperAddr 与 __dbk_fcall_wrapper |
| `ref:75fe6d3b7a` | resource strings | 版本信息：EzzVPN Premium Client Setup 1.1.43[.]125 / EzzVPN Soft / 'This installation was built with DataPack...' |
| `ref:20e017086a` | string scan | 数据块签名 'NetGuard_S Setup Data (6.7.0)'（off 0x6FC27D）与加载器常量（off 0xB530C）；证书内 ClearPath/DigiCert 字符串 |
| `ref:c41e7b6124` | certificate parse | 自签根 'Software Trust Root 557E06' → 'Code Signing CA 557E06' → 叶 CN=ClearPath Networking Ltd.，签发时间集中在 2026-11-04 13:40:02–13:40:04Z |
| `ref:5b03866a6b` | overlay analysis | 0x0F6800 起 29 个 256KB 窗口熵均≈7.999，magic 7A6C621A |
| `ref:ded64dd285` | string scan | 内部单元 BootPackAndSetup.InstFunc/Messages、Compression.LZMA1SmallDecompressor、Shared.SetupEntFunc |
| `ref:e40f13771a` | emulation | API 轨迹：GetModuleHandleW(ntdll.dll)→GetProcAddress('wine_get_version')、VerSetConditionMask/VerifyVersionInfoW |
| `ref:711ea6866c` | sandbox watch | pid 3924 启动，pid 440 运行 %TEMP%\is-F239MFSCLY.tmp\<sha256>.tmp，无子进程/C2，结束时回滚 |
| `ref:6de561a3a6` | memory scan | 样本与临时副本进程扫描：Total suspicious=0，无注入/IAT 钩子；临时副本加载 winhttp/ws2_32 等 |
| `ref:728354e3d6` | memory dump strings | 内存转储含 '\REGISTRY\USER\...\is-F239MFSCLY.tmp\<sha>.tmp' 与 EzzVPN 版本信息，无落地文件/注册表写入痕迹 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
