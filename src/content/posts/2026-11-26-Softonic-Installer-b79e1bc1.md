---
title: "恶意样本分析：Softonic Installer（PE · exe · b79e1bc1）"
published: 2026-11-26
draft: false
description: "灰色/PUA（置信度中）：Softonic Installer · pua_bundler · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Softonic Installer", "pua", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!CAUTION]
> **判定：灰色/PUA** · 家族 **Softonic Installer**（存疑） · 置信度 **中**
> 
> 别名：Softonic Downloader、Softonic Bundler
> 
> 样本是用 Inno Setup 6.7.0 构建的 Windows 安装器，版本资源与 Authenticode 签名一致指向 SOFTONIC INTERNATIONAL SA（签名有效、文件未被篡改）。偏移 0xCF177 起的 50112 字节安装数据段与随后 1.22MB 文件数据段整体为高熵（7.996/8.000），属于 Inno Setup 6.5+ 的数据加密，静态无法枚举安装清单；动态沙箱内样本仅完成自解包并启动安装向导，等待用户交互，未观察到网络外联、持久化或落地文件。结合其 Softonic 下载门户安装器身份与载荷被加密隐藏的事实，按潜在不受欢迎的捆绑安装器（PUA）定性，而非明确恶意载荷。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Softonic Installer** · 别名 Softonic Downloader、Softonic Bundler · _存疑_ |
| 置信度 | **中** |
| 行为类 | pua_bundler |
| 难度 | medium |
| 首次出现 | 2026-11-24 00:59:20 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/b79e1bc1e64eee64ad28259d78e944330f3ff7419e2ff4a40d879221796f2e6b/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">临时目录自解包重启</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">安装向导等待交互</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">安装数据全量加密</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">以 EV 签名降低告警</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">产品标识统一为品牌名</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `b79e1bc1e64eee64ad28259d78e944330f3ff7419e2ff4a40d879221796f2e6b` |
| MD5 | _未记录_ |
| 大小 | 2,132,432 字节（2.0 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **6** 条行为，每条都挂了证据；其中 **4** 条静态可得、**2** 条经动态分析取得。

### 1. 临时目录自解包重启

`T1140` · 置信度 **高** · 动态

样本作为 Inno Setup 引导器运行后，把内嵌的 Setup 组件写入 %TEMP%\is-D58ML0UQO0.tmp\<样本名>.tmp，并以 /SL5="$50112,848247,840704,<原样本路径>" 参数启动该副本；进程创建监控记录了 1612 → 6384 的父子关系与完整命令行。

> **证据**：ETW 进程创建事件：pid 6384 image=C:\Users\analyst\AppData\Local\Temp\is-D58ML0UQO0.tmp\b79e...tmp，parent_pid=1612，command_line 含 /SL5="$50112,848247,840704,..."
> 
> **来源**：`call:call_6df460ce762644a1ade3c2b3` · `call:call_972a23975cf4420eb48b9664`

### 2. 安装向导等待交互

`T1204.002` · 置信度 **高** · 动态

解包后的 Setup 进程（pid 6384）加载 winhttp.dll、ws2_32.dll、shell32.dll 等组件，但在观测窗口内始终停留在交互式安装向导阶段：未创建业务子进程，未产生任何落地文件或注册表/服务改动。

> **证据**：监控组件 报告 Total suspicious: 0（pid 1612 与 6384）；遥测前后差分仅新增分析环境自身条目（网络监控 根证书、WinDivert/监控组件 服务、Edge 更新事件）；网络监控 主机列表全部为系统组件域名
> 
> **来源**：`call:call_1546eec2a0` · `call:call_7255018828ea473b94aa1ea5` · `call:call_3941405e44e04500b9ab319d`

### 3. 安装数据全量加密

`T1027` · 置信度 **高** · 静态

偏移 0xCF177 的 Inno Setup 数据段只有 64 字节明文签名 'Inno Setup Setup Data (6.7.0)'，其后的数据与 0xDB537 之后的文件数据块熵分别为 7.996 与 8.000，属于 Inno Setup 6.5+ 的 ChaCha20 数据加密，静态无法枚举将被安装的文件、注册表项与 [Run] 项。

> **证据**：setup data 熵 7.996；文件数据段（898359–2121056）熵 8.000；段内无任何 UTF-16 文件路径字符串
> 
> **来源**：`call:call_9a8a314703744677a96d81ca` · `call:call_8803968b93854502b6e6f1fb`

### 4. 以 EV 签名降低告警

`T1553.002` · 置信度 **高** · 静态

PE 带有完整的 Authenticode 签名，签名主体为 SOFTONIC INTERNATIONAL SA 的 EV 代码签名证书，签名为 Valid 且覆盖全部内嵌加密数据，时间戳由 DigiCert 2026 时间戳服务签发；运行时不触发签名告警。

> **证据**：Get-AuthenticodeSignature → Status=Valid, Signer CN=SOFTONIC INTERNATIONAL SA (OID.2.5.4[.]15=Private Organization, SERIALNUMBER=A62134341), Timestamper=DigiCert SHA256 RSA4096 Timestamp 受控仿真服务 2026 1
> 
> **来源**：`call:call_1fc0d1b10f474131a6f80ae4` · `call:call_aa2eb22b27c04a79b7af799a`

### 5. 产品标识统一为品牌名

`T1036` · 置信度 **中** · 静态

版本资源未声明具体产品：FileDescription、ProductName 与 CompanyName 同为 'Softonic--International (SA)'，OriginalFileName 为空，仅保留 4.0.2[.]0 版本号；资源区只有通用图标与内置消息表，没有可供识别的产品文档或帮助链接。

> **证据**：RT_VERSION 字符串表（size=1412, rva=0xDA5A8）：FileDescription='Softonic--International (SA)'，OriginalFileName 空；RT_ICON 100 为 128x128 PNG
> 
> **来源**：`call:call_df732c3f43124729be028938` · `call:call_7f6dd28610cd4218bd4b80cc`

### 6. 安装器框架特征齐全

`T1587.001` · 置信度 **高** · 静态

PE 导出表 DLL 名为 SetupLdr.e32 并导出 __dbk_fcall_wrapper，节名 .itext/.didata/.edata/.reloc 与导入面（kernel32 105 个 API 含 FindResourceW/LoadResource/LockResource/SizeofResource、advapi32 的令牌与注册表 API、user32 的窗口/消息循环）完全符合 Delphi 编写的 Inno Setup 引导器；.rsrc 内 RT_RCDATA 11111 保存 'rDlPtS' 引导偏移表。

> **证据**：pe.exports dll_name=SetupLdr.e32；RT_RCDATA 11111 头 72 44 6c 50 74 53 ('rDlPtS')，与 file offset 0xCC554 同构
> 
> **来源**：`call:call_283012560dea4f948641e382` · `call:call_bb8ea93a13d04efe900127f5` · `call:call_15485681a33e49129d399906`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `%TEMP%\is-<随机串>.tmp\<样本名>.tmp`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `installer_framework` | `Inno Setup 6.7.0 (Embarcadero Delphi Win32 编译器 36.0)` | 是 | 静态 |
| `payload_encryption` | `Inno Setup setup-data/file 加密；安装数据段熵 7.996、文件数据段熵 8.000，无口令无法解密` | 是 | 静态 |
| `setup_data_offset` | `file offset 0xCF177 (848247)，长 50112 字节；其后 898359 至 2121056 为压缩/加密文件数据` | 否 | 静态 |
| `product_version` | `4.0.2[.]0 / ©2026 Softonic--International (SA)` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要断言样本盗用或伪造 Softonic 证书：签名链校验有效，签名主体与版本资源中的公司信息一致，文件未被第三方篡改。
- 不要断言存在 C2、持久化、注入或信息窃取：动态窗口内无样本外联、无注册表/服务/计划任务改动、监控组件 未发现注入或可疑内存区域。
- 不要把它归为勒索、挖矿或后门：代码与行为中没有任何相应特征，仅为一个加密载荷的交互式安装器。
- 不要把动态观测到的 'comsvcs' 转储件当成凭据窃取证据：它是分析环境自身的进程快照产物，样本未调用 MiniDump 相关接口。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 安装数据（50112 字节）与文件数据（约 1.22MB）均为 Inno Setup 6.5+ 加密，熵约 8.0，无口令无法枚举安装清单或提取捆绑组件，因此未能确认具体捆绑软件、安装路径与 [Run] 项。
2. 动态窗口内安装向导停留在交互页面，没有点击继续，未观测到落地文件、注册表写入或网络请求；c2 为空仅代表未观测到，而非证明其不存在。
3. 沙箱客体为罗马尼亚语区域设置，网络监控 与系统事件中混有 Edge 更新、证书 CRL 检查等系统流量，已在分析中排除；遥测差分新增项均为分析设施自身（网络监控 根证书、WinDivert/监控组件 服务）。
4. 未取得第三方检测引擎或 YARA 命中结果，家族归类基于签名主体、版本资源与打包框架，属于中等置信度推断。

## 证据索引

<details>
<summary>展开 18 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `call:call_15485681a33e49129d399906` | 样本分诊 | PE 哈希/节表/导入面/加壳评分 0，无结构异常 |
| `call:call_bb8ea93a13d04efe900127f5` | PE 结构解析 | 11 节、I386 GUI、入口 0x0B1E20、安全目录 11376 字节、资源目录 0xD7060 |
| `call:call_283012560dea4f948641e382` | pe.exports | 导出 DLL 名 SetupLdr.e32，导出 __dbk_fcall_wrapper |
| `call:call_df732c3f43124729be028938` | python/pefile 资源枚举 | RT_VERSION 指向 Softonic 4.0.2[.]0；RT_RCDATA 11111 为 rDlPtS 引导偏移表；签名 11376 字节 |
| `call:call_1fc0d1b10f474131a6f80ae4` | PowerShell Get-AuthenticodeSignature | 签名 Valid，签署者 CN=SOFTONIC INTERNATIONAL SA，时间戳 DigiCert 2026 |
| `call:call_aa2eb22b27c04a79b7af799a` | openssl pkcs7 | 证书链：Sectigo EV R36 → Root R46 → AAA；时间戳链 DigiCert G4 |
| `call:call_8803968b93854502b6e6f1fb` | python 手动解析 overlay | 0xCF177 处 'Inno Setup Setup Data (6.7.0)'，50112 字节安装数据段内容为随机字节，无可读文件表 |
| `call:call_9a8a314703744677a96d81ca` | python 熵计算 | 安装数据段熵 7.996、其后文件数据段熵 8.000 |
| `call:call_972a23975cf4420eb48b9664` | 动态分析平台 | 回滚→投放→轮询 33 次，唯一候选 pid 1612，t0/t3 各生成进程与模块内存转储，hollows 全扫 0 命中，收口后已回滚 |
| `call:call_6df460ce762644a1ade3c2b3` | ETW/进程时间线解析 | pid 1612 创建 pid 6384（%TEMP%\is-D58ML0UQO0.tmp\*.tmp /SL5="$50112,848247,840704,..."），并记录两者 SHA256/imphash |
| `call:call_1546eec2a0` | 监控组件 报告解析 | pid 1612 Total suspicious 0 / 6384 Total suspicious 0，无 Hooked/IAT Hooks/Implanted |
| `call:call_3941405e44e04500b9ab319d` | 网络监控 日志解析 | 样本 pid 1612/6384 无任何 DNS/TCP 请求；主机列表均为 Edge/Windows Update/证书 CRL |
| `call:call_7255018828ea473b94aa1ea5` | 遥测差分 | services +2（WinDivert/监控组件）、certificates +4（fakenet.flare、DigiCert EV Root，均属分析设施），defender/events/run_keys 无变化 |
| `call:call_fbddd6b36c5a4e918b12ce36` | strings | 版本/签名区含 'SOFTONIC INTERNATIONAL SA' |
| `call:call_7f6dd28610cd4218bd4b80cc` | 字符串提取 | Delphi RTTI（TSetupHeader/TSetupEncryptionKey/TSetupEncryptionNonce）、'Inno Setup Setup Data (6.7.0)'、'.itext/.didata/.edata' |
| `telemetry:b79e1bc1` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 114 条；ETW 短命进程事件 2 条；已过滤工具/系统噪声 22 条 |
| `etw:b79e1bc1:1612` | 进程事件监控 | 短命进程事件：b79e1bc1e64eee64ad28259d78e944330f3ff7419e2ff4a40d879221796f2e6b.exe（pid 1612；MD5=48CA02BDF2D4F348B6404556C85748D8,SHA256=B79E1BC1E64EEE64AD28259D78E944330F3FF7419E2FF4A40D879221796F2E6B,IMPHASH=88016FCDEF7F227C62171D0AFAD9AAE4） |
| `etw:b79e1bc1:6384` | 进程事件监控 | 短命进程事件：b79e1bc1e64eee64ad28259d78e944330f3ff7419e2ff4a40d879221796f2e6b.tmp（pid 6384；MD5=FA1C977A4003CC0793201A6F1711BB6D,SHA256=3A62AE0D102CFF66FBA0A1F0B9BCDF116AD369C3C4F0212EB21A53C766C75A7D,IMPHASH=4F3A70412C909E6E8F69020F0BEE4F39） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
