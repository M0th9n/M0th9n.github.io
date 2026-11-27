---
title: "恶意样本分析：NSIS_Downloader（PE · exe · 74a5ddeb）"
published: 2026-11-26
draft: false
description: "恶意（置信度低）：NSIS_Downloader · downloader/dropper · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["downloader", "dropper", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **NSIS_Downloader**（存疑） · 置信度 **低**
> 
> 别名：NSIS dropper、Discord CDN loader
> 
> 样本是一个 Nullsoft Install System v3.02.1 打包的安装器：解包内容不是正常软件，而是 4 个纯填充文件（合计约 25.6MB、熵≈0.16）加 3 张图片和 5 个丹麦语 lorem-ipsum 文本等诱饵；程序运行后会以自身镜像路径反复派生同名子进程，其中子进程通过 HTTPS 向 cdn[.]discordapp[.]com 上固定的 Discord 附件地址请求 JUfHv82.bin，并把 User-Agent 伪造成 Firefox/160.0，失败后约每 10 秒重试一次，观测窗口内共 17 次。该下载地址不是任何合法软件的分发渠道，且下载内容不落任何签名/校验流程，属于典型的第一阶段下载器行为，整体判定为恶意。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **NSIS_Downloader** · 别名 NSIS dropper、Discord CDN loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | downloader · dropper |
| 难度 | medium |
| 首次出现 | 2026-11-26 14:00:08 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解包诱饵文件至用户目录</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">同路径重启自身</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">伪装成普通安装器</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">从Discord下载载荷</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">动态加载WinINet</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917` |
| MD5 | _未记录_ |
| 大小 | 1,201,664 字节（1.1 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **3** 条静态可得、**4** 条经动态分析取得。

### 1. 解包诱饵文件至用户目录

`T1027` · 置信度 **高** · 动态

以安装器 UI 形式把 16 个条目解包到 %USERPROFILE%\Sopsaisana58：4 个单字节填充大文件、3 张真实 JPEG、5 个丹麦语 lorem-ipsum 文本/ini、2 个未知 blob（skotjet 150310 字节、Gadeteatret 25341 字节）以及 System.dll 插件。内存中可见 NSIS 的 “Output folder:”“Extract: skotjet... 100%” 进度串和 \??\C:\Users\analyst\Sopsaisana58\skotjet 这类对象管理器路径，说明解包动作真实发生。

> **证据**：进程内存 0x10057e 'Output folder: C:\Users\analyst\Sopsaisana58'、0x14966e 'Extract: skotjet... 100%'、0x125f9e '\??\C:\Users\analyst\Sopsaisana58\skotjet'；附加数据解包清单 16 项（overlay 偏移 162304）
> 
> **来源**：`ev-000012` · `ev-000013` · `ev-000014` · `ev-000015`

### 2. 同路径重启自身

`T1036` · 置信度 **高** · 动态

运行期间以自身镜像路径派生多个同名子进程：引爆进程（pid 6804）先后启动 pid 5436 与 pid 3848，pid 3848 又启动 pid 4680；四者 Image 路径均为样本身份、哈希一致，用于切换执行分支并把下载行为分散到新进程上。

> **证据**：进程创建事件：6804→5436、6804→3848、3848→4680，Image=C:\dyn\samples\<sha256>.exe，命令行为 '"<路径>.exe" '，哈希与样本一致
> 
> **来源**：`ev-000015`

### 3. 伪装成普通安装器

`T1036.005` · 置信度 **高** · 静态

PE 版本信息为随机英文词拼凑：OriginalFilename=discoursing coracoprocoracoid.exe、FileVersion/ProductVersion 1.1.0[.]0、Comments=pontificator unbarbarized stereophony、LegalTrademarks=stemmelben slingrefises；界面使用标准 NSIS“Setup”安装向导，产品名由随机词构成，用于冒充正常软件安装包。

> **证据**：版本资源 OriginalFilename=discoursing coracoprocoracoid.exe；脚本字符串表 'Nullsoft Install System v3.02.1' + ' Setup'；附加数据 SubType=NSIS-3 Unicode
> 
> **来源**：`ev-000012` · `ev-000013`

### 4. 从Discord下载载荷

`T1071.001` · 置信度 **高** · 动态

子进程通过 HTTPS 向 cdn[.]discordapp[.]com 的固定 Discord 附件路径请求 JUfHv82.bin，请求携带伪造的 Firefox/160.0 User-Agent 与 Cache-Control: no-cache；在下载未获得正常应答的情况下约每 10 秒重试，观测窗口内共 17 次 GET。

> **证据**：网络监控日志：pid 3848 requested TCP <sinkhole>:443 ×17，随后 HTTP GET /attachments/1574386543248801863/1575464094113472542/JUfHv82.bin?... HTTP/1.1（UA: Mozilla/5.0 ... Firefox/160.0）；进程内存 0x6babaa6 出现完整 URL
> 
> **来源**：`ev-000014` · `ev-000015`

### 5. 动态加载WinINet

`T1106` · 置信度 **中** · 动态

静态导入表只有 kernel32/user32/gdi32/shell32/advapi32/comctl32/ole32，没有 wininet/winhttp；运行进程内存中出现 C:\Windows\SYSTEM32\WININET.DLL、urlmon.dll、%SystemRoot%\system32\mswsock.dll 以及完整请求行/请求头，说明下载能力是经安装器插件（System.dll 的 Alloc/Call）在运行时解析并调用 WinINet 实现的。

> **证据**：内存 0x6b93e83 附近 'C:\Windows\SYSTEM32\WININET.DLL'、'...\urlmon.dll'、'%SystemRoot%\system32\ms wsock.dll' 与 'GET /attachments/... HTTP/1.1'；脚本字符串表含 '\System.dll'、'Alloc'、'Call'；导入表无 wininet
> 
> **来源**：`ev-000014` · `ev-000013`

### 6. 内置诱饵注册表与随机路径

`T1112` · 置信度 **中** · 静态

脚本字符串表内置一批随机键名与随机目录/文件名，如 Software\Microsoft\Windows\CurrentVersion\Soony、...\krestiane、...\Aaretagenes、Software\Access\Disabled，以及 \baadevrfts\Imperforata.exe、Tuberizations\yapness.exe、\Dysanalyte\blockholer.ini 等；这些名字与安装器真实功能无关，用于制造噪声、干扰基于字符串/行为的判定。本次分析未在系统遥测中观测到样本真的写入这些注册表键或创建这些文件。

> **证据**：脚本字符串表（头部块偏移 162336，解压 10866 字节）内的 'Software\Microsoft\Windows\CurrentVersion\Soony\'、'Tuberizations\yapness.exe'、'C:\Windows\system32\Tuberizations\yapness.exe'；遥测中无对应注册表写入事件
> 
> **来源**：`ev-000013`

### 7. 填充文件膨胀样本体积

`T1027` · 置信度 **高** · 静态

4 个解包文件 brevforsendelser.flu（9.18MB）、degauss.ski（6.62MB）、oprrerene.she（5.15MB）、shirtband.mic（4.65MB）合计约 25.6MB，熵约 0.16，超过 99% 的字节是同一种重复值，不承载任何可执行逻辑，仅用于把安装包撑大、稀释真实逻辑并干扰特征提取。

> **证据**：解包后逐文件统计：熵 0.16，uniq=256，最高频字节占比 99.0%（brevforsendelser.flu 中 0x04 占 9,093,450/9,184,071 字节）
> 
> **来源**：`ev-000012`


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
| http | `hxxps://cdn[.]discordapp[.]com/attachments/1574386543248801863/1575464094113472542/JUfHv82[.]bin?ex=6b0960c6&is=6b080f46&hm=f48fc4b0e1d411c4315568f29f5b9338fa8423b78627eca5c6cbffbc1eea9512` | 443 | download | 动态 | 已观测 |

### 主机

**落地路径**

- `%USERPROFILE%\Sopsaisana58`
- `%USERPROFILE%\Sopsaisana58\skotjet`
- `C:\Windows\system32\Tuberizations\yapness.exe`
- `%USERPROFILE%\Sopsaisana58\baadevrfts\Imperforata.exe`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Soony`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\krestiane`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Aaretagenes`
- `HKCU\Software\Access\Disabled`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `cdn[.]discordapp[.]com` | 是 | 静态 |
| `c2_url` | `hxxps://cdn[.]discordapp[.]com/attachments/1574386543248801863/1575464094113472542/JUfHv82[.]bin?ex=6b0960c6&is=6b080f46&hm=f48fc4b0e1d411c4315568f29f5b9338fa8423b78627eca5c6cbffbc1eea9512` | 是 | 静态 |
| `install_path` | `%USERPROFILE%\Sopsaisana58` | 是 | 静态 |
| `http_user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0` | 否 | 静态 |
| `retry_interval_sec` | `10` | 否 | 静态 |
| `encryption_algo` | `unknown（下载 URL 未以明文出现在脚本字符串表，推断为运行时解密/拼接，未能确认算法）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要声称已取得或执行第二阶段载荷：下载请求全部被隔离网络的假服务接管，分析窗口内没有拿到真实的 JUfHv82.bin 内容，也没有观察到载荷执行。
- 不要声称样本建立了持久化：系统遥测中没有任何样本进程写入 Run 键、注册服务或创建计划任务，也没有启动项/服务被创建的证据。
- 不要把这批诱饵注册表键/随机路径当成已实现的功能：它们只出现在安装脚本的字符串表中，本次分析未观测到实际写入或创建。
- 不要判定为窃密/勒索/挖矿或进程注入类家族：内存扫描未发现注入痕迹（被扫描进程的可疑模块数为 0），也没有文件遍历、凭据读取或加密行为证据。
- 不要把 Discord 附件 URL 当作已确认可用的 C2 信道：仅观测到出站 GET，没有真实服务端应答，URL 中的签名参数（ex/is/hm）表明其为临时下载链接。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 第二阶段（JUfHv82.bin）未能取回：所有下载请求由隔离网络的假服务应答/接管，未获得真实内容，故后续行为、加密方式与最终家族均无法确认。
2. C2 会话只有出站请求、没有真实服务端响应，因此 c2 条目标记为静态恢复并保持待动态确认；下载 URL 本身来源于运行进程内存，而非脚本明文。
3. 未取得被分析系统的文件系统快照：诱饵文件落地仅由进程内存中的 'Output folder:'/'Extract:' 进度串与 \??\ 对象管理器路径推断，未逐文件核对。
4. 注册表键名来自安装脚本文本，系统遥测中没有观察到样本进程写入这些键，相关条目属于意图而非既成事实。
5. 内存扫描未发现注入或模块镂空（可疑模块计数为 0），但这不能排除后续阶段具备注入能力。
6. 样本的下载 URL 未出现在脚本明文串中，推测由加密配置或运行期拼接产生，具体算法未定位。

## 证据索引

<details>
<summary>展开 12 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917，md5=df603e63f979d42b422b356191822b74，imphash=b34f154ec913d2d2c435cbd644e91687，大小 1201664 字节 |
| `ev-000011` | 字符串提取 | 字符串抽取：ascii 1810 条 / utf16le 40 条；可见 NSIS 安装器串（verifying installer、NSIS Error）、SeShutdownPrivilege、[Rename]、%s%S.dll 等 |
| `ev-000012` | 脚本化取证 | 静态解包 NSIS 附加数据：overlay 偏移 162304，SubType=NSIS-3 Unicode，16 个条目；4 个单字节填充文件合计约 25.6MB（熵 0.16），3 张 JPEG、5 个丹麦语文本、2 个未知 blob、System.dll 插件 |
| `ev-000013` | 脚本化取证 | raw-deflate 解压偏移 162336 处 10866 字节头部块，得到 NSIS 字符串表：安装目录 \Sopsaisana58、Nullsoft Install System v3.02.1、System.dll/Alloc/Call、随机注册表键与随机 .exe/ini 路径；表中无任何 http/discord 明文 |
| `ev-000014` | 脚本化取证 | 对动态沙箱取回的样本子进程全内存镜像做字符串扫描：完整 Discord 附件 URL、GET 请求行、伪造 Firefox/160.0 UA、Host/Cache-Control 头、WININET.DLL/urlmon.dll/mswsock.dll 路径、安装目录 C:\Users\analyst\Sopsaisana58 |
| `ev-000015` | 脚本化取证 | 动态沙箱汇总：6804→5436/3848→4680 的同路径自派生进程链；网络监控 侧对 cdn[.]discordapp[.]com 同一附件 URL 的 17 次 GET（约 10s 间隔）；遥测中无 Run 键/服务/计划任务写入；被扫描进程可疑模块计数 0 |
| `c2_evidence:74a5ddeb` | 连接证据提取 | 动态网络监控记录到 17 次到 cdn[.]discordapp[.]com:443 的连接尝试；未捕获完整会话 |
| `telemetry:74a5ddeb` | 动态遥测 | 动态遥测记录到：监控组件 注册表事件 1 条；监控组件 进程/文件事件 139 条；ETW 短命进程事件 4 条；已过滤工具/系统噪声 25 条 |
| `etw:74a5ddeb:6804` | 进程事件监控 | 短命进程事件：74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917.exe（pid 6804；MD5=DF603E63F979D42B422B356191822B74,SHA256=74A5DDEB4BA368A82963256B59F255E04F2ABB2B5A19D440C2326345C2A8E917,IMPHASH=B34F154EC913D2D2C435CBD644E91687） |
| `etw:74a5ddeb:5436` | 进程事件监控 | 短命进程事件：74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917.exe（pid 5436；MD5=DF603E63F979D42B422B356191822B74,SHA256=74A5DDEB4BA368A82963256B59F255E04F2ABB2B5A19D440C2326345C2A8E917,IMPHASH=B34F154EC913D2D2C435CBD644E91687） |
| `etw:74a5ddeb:3848` | 进程事件监控 | 短命进程事件：74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917.exe（pid 3848；MD5=DF603E63F979D42B422B356191822B74,SHA256=74A5DDEB4BA368A82963256B59F255E04F2ABB2B5A19D440C2326345C2A8E917,IMPHASH=B34F154EC913D2D2C435CBD644E91687） |
| `etw:74a5ddeb:4680` | 进程事件监控 | 短命进程事件：74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917.exe（pid 4680；MD5=DF603E63F979D42B422B356191822B74,SHA256=74A5DDEB4BA368A82963256B59F255E04F2ABB2B5A19D440C2326345C2A8E917,IMPHASH=B34F154EC913D2D2C435CBD644E91687） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
