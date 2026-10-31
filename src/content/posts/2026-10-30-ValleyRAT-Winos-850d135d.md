---
title: "恶意样本分析：ValleyRAT (Winos)（PE · exe · 850d135d）"
published: 2026-10-30
draft: false
description: "恶意（置信度中）：ValleyRAT (Winos) · dropper/rat/backdoor · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["ValleyRAT", "dropper", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ValleyRAT (Winos)**（存疑） · 置信度 **中**
> 
> 别名：ValleyRAT、Winos、Winos 4.0
> 
> 样本是一个伪装为 Data Run Guide 的 Inno Setup 安装器。动态沙箱中它释放并运行了 %APPDATA%\hrjhh\hrjhh.exe 与同目录 log.dll，hrjhh.exe 实为合法 NBMSClient/BarClientView 客户端重命名并静态导入 log.dll，恶意 log.dll 侧载后在进程内植入 2 个 VMProtect 保护的 PE；随后 hrjhh.exe 持续解析并连接 rfjp93sina[.]top:443（DoH 模板 hxxps://%s/dns-query?dns=%s），同时运行 Quark 浏览器安装器。安装器 + 侧载 + 进程注入 + 隐蔽 C2 心跳构成完整的恶意投递链。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ValleyRAT (Winos)** · 别名 ValleyRAT、Winos、Winos 4.0 · _存疑_ |
| 置信度 | **中** |
| 行为类 | dropper · rat · backdoor |
| 难度 | medium |
| 首次出现 | 2026-10-27 23:46:21 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/850d135d3ff871f88c96e5a6b889b1f454944ffdd35b2fce5e3fa1d049d8bf70/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装安装包释放载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">侧载合法客户端</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">注入VMProtect后门</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.002</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">DoH隧道解析C2</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">周期回连C2心跳</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `850d135d3ff871f88c96e5a6b889b1f454944ffdd35b2fce5e3fa1d049d8bf70` |
| MD5 | _未记录_ |
| 大小 | 5,430,309 字节（5.2 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **12** 条行为，每条都挂了证据；其中 **6** 条静态可得、**6** 条经动态分析取得。

### 1. 伪装安装包释放载荷

`T1204.002` · 置信度 **高** · 动态

Inno Setup 6.9.3 安装器以 AppName『Data Run Guide』和伪造的 Microsoft 版权信息伪装，执行后向 %APPDATA%\hrjhh 释放 hrjhh.exe 与 log.dll，并从 %TEMP% 启动 htfgqdowfk.exe。

> **证据**：PE 导出 SetupLdr.e32；安装数据签名『Inno Setup Setup Data (6.9.3)』@0x43ce5e；动态沙箱时间线：PID 1628=%APPDATA%\hrjhh\hrjhh.exe、PID 5860=%TEMP%\htfgqdowfk.exe
> 
> **来源**：`ref:f3587a48ce` · `ref:2cd8ba2c8e` · `ref:d55f56cc4f` · `ref:5e799c57a7` · `ev-000028`

### 2. 侧载合法客户端

`T1574.002` · 置信度 **高** · 动态

释放的 hrjhh.exe 实际是合法 NBMSClient/BarClientView 客户端（PDB D:\slave\workspace\AppBcClient\startbc\startbc.cpp）重命名而来；其导入表静态导入 log.dll，恶意 log.dll 放在同目录后被加载，形成 DLL 侧载。

> **证据**：hrjhh.exe 内存镜像导入描述符第 4 项 name=log.dll @RVA 0x31570；模块列表 0x6f3c0000 log.dll；字符串 D:\slave\workspace\AppBcClient\startbc\startbc.cpp、NBMSClient\BarClientView.exe
> 
> **来源**：`ref:242c110b48` · `ref:c00bb9d598` · `ref:20a9b83342` · `ref:5e799c57a7` · `ev-000028`

### 3. 注入VMProtect后门

`T1055.002` · 置信度 **高** · 动态

恶意 log.dll 为高熵自解密壳，加载后在 hrjhh.exe 进程内植入 2 个可执行 PE 模块（0x27a0000 与 0x28b0000，含 .vmp0 段、导出名 Fuck），形成内存中的后门核心。

> **证据**：内存扫描 implanted PE=2；28b0000.dll .vmp0 熵 7.91、unpack_detect=vmprotect(0.9)；27a0000 区域在 +0x1973 处含 PE 与 shellcode；导出 Fuck
> 
> **来源**：`ref:5e799c57a7` · `ref:6e0604e26e` · `ref:3d404386b3` · `ref:0e33f3cae8` · `ref:be3585b187` · `ref:dfc239c619`

### 4. DoH隧道解析C2

`T1071.001` · 置信度 **高** · 动态

后门使用 WinHttp.WinhttpRequest.5.1 向 hxxps://rfjp93sina[.]top/dns-query?dns=... 发送 DNS-over-HTTPS 查询，把 C2 通信封装在 HTTPS/DoH 中。

> **证据**：内存字符串 WinHttp.WinhttpRequest.5.1 与 hxxps://%s/dns-query?dns=%s；网络监控中 rfjp93sina[.]top 被解析 25 次，hrjhh.exe 持续 TCP 443
> 
> **来源**：`ev-000028` · `ref:5e799c57a7`

### 5. 周期回连C2心跳

`T1071.001` · 置信度 **高** · 动态

hrjhh.exe 以约 5 秒间隔持续连接 rfjp93sina[.]top:443，2 分钟内观测到 25 次域名解析与连续 TCP 443 连接，属于稳定的 C2 心跳。

> **证据**：网络监控 09:16:25–09:18:32：hrjhh.exe(1628) 每次解析 rfjp93sina[.]top 后请求 TCP 192.0.2[.]123:443
> 
> **来源**：`ref:5e799c57a7` · `ev-000028`

### 6. 写入Run键自启

`T1547.001` · 置信度 **中** · 静态

后门配置包含 HKCU\Software\Microsoft\Windows\CurrentVersion\Run\RacMan，用于把 hrjhh.exe 注册为当前用户登录自启动项。

> **证据**：内存字符串 HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\RacMan（0x1d9469）与 HKCU\...\Run\RacMan 配置记录
> 
> **来源**：`ev-000028` · `ref:242c110b48`

### 7. 注册RacMan服务

`T1543.003` · 置信度 **中** · 静态

后门具备创建/删除系统服务的能力，配置中引用 HKLM\SYSTEM\CurrentControlSet\Services\RacMan 的 ImagePath/Group/wow64，用于以服务方式持久化。

> **证据**：28b0000.dll 导入 CreateServiceA/OpenSCManagerA/OpenServiceA/DeleteService；字符串 HKLM\...\Services\RacMan\ImagePath
> 
> **来源**：`ref:1e9c7021f9` · `ev-000028`

### 8. 键盘与窗口记录

`T1056.001` · 置信度 **高** · 静态

后门导入键盘钩子与前台窗口读取 API，可安装全局键盘钩子并采集前台窗口标题/类名，具备键盘记录能力。

> **证据**：28b0000.dll 导入 SetWindowsHookExA、CallNextHookEx、GetKeyState、GetForegroundWindow、GetWindowTextA、GetClassNameA
> 
> **来源**：`ref:1e9c7021f9`

### 9. 截屏与摄像头采集

`T1113` · 置信度 **中** · 静态

后门导入屏幕/光标/字体相关 GDI API，并在进程中加载 avicap32/winmm/msvfw32，配合 Scrnshot.dll 插件具备截屏与摄像头采集能力。

> **证据**：28b0000.dll 导入 GetDC/GetCursorPos/CreateFontA/GetDeviceCaps；hrjhh 进程加载 avicap32.dll、winmm.dll、msvfw32.dll；字符串 %s\Scrnshot.dll
> 
> **来源**：`ref:1e9c7021f9` · `ref:5e799c57a7` · `ev-000028`

### 10. 命令管道远程执行

`T1059.003` · 置信度 **中** · 静态

后门导入 CreateProcessA 与 CreateNamedPipeA，并使用命名管道 \\.\Pipe\1351827 / \\.\Pipe\%d，用于执行远程命令并回传输出。

> **证据**：28b0000.dll 导入 CreateProcessA、CreateNamedPipeA；内存字符串 \\.\Pipe\1351827 与 \\.\Pipe\%d
> 
> **来源**：`ref:1e9c7021f9` · `ev-000028`

### 11. 进程枚举与Token窃取

`T1134.002` · 置信度 **高** · 静态

后门枚举进程、打开进程并具备跨会话注入能力：VirtualAllocEx/WriteProcessMemory/GetThreadContext/SetThreadContext，配合 WTSQueryUserToken/DuplicateTokenEx/CreateProcessAsUserA 窃取用户令牌。

> **证据**：28b0000.dll 导入 CreateToolhelp32Snapshot、Process32First/Next、OpenProcess、VirtualAllocEx、WriteProcessMemory、WTSQueryUserToken、DuplicateTokenEx、CreateProcessAsUserA
> 
> **来源**：`ref:1e9c7021f9`

### 12. 捆绑安装Quark浏览器

`T1105` · 置信度 **高** · 动态

安装器同时投放并运行 Quark 浏览器迷你安装器，后者向 track[.]lc[.]quark[.]cn 与 px[.]effirst[.]com 上报安装/使用统计，用正常软件为后门作掩护。

> **证据**：网络监控：htfgqdowfk.exe(5860) 请求 track[.]lc[.]quark[.]cn/collect 与 px[.]effirst[.]com/api/v1/jstrace/upload；文件位于 %TEMP%\htfgqdowfk.exe
> 
> **来源**：`ref:5e799c57a7` · `ev-000028`


## IOC（已去武器化）

### 网络

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://rfjp93sina[.]top/dns-query` | 443 | c2 | 动态 | — |

### 主机

**落地路径**

- `%APPDATA%\hrjhh\hrjhh.exe`
- `%APPDATA%\hrjhh\log.dll`
- `%APPDATA%\hrjhh\dsp_bridge.dll`
- `%APPDATA%\hrjhh\Scrnshot.dll`
- `%APPDATA%\hrjhh\Language.dll`
- `%APPDATA%\hrjhh\Box.ini`
- `%APPDATA%\hrjhh\Update.xml`
- `%APPDATA%\hrjhh\Update.log`
- `%TEMP%\htfgqdowfk.exe`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\RacMan`
- `HKLM\SYSTEM\CurrentControlSet\Services\RacMan`

**服务**

- `RacMan`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `rfjp93sina[.]top` | 是 | 动态 |
| `c2_port` | `443` | 是 | 动态 |
| `c2_protocol` | `DNS-over-HTTPS via WinHttp.WinhttpRequest.5.1，模板 hxxps://%s/dns-query?dns=%s` | 是 | 静态 |
| `install_path` | `%APPDATA%\hrjhh` | 是 | 动态 |
| `service_name` | `RacMan` | 否 | 静态 |
| `run_key` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\RacMan` | 否 | 静态 |
| `group_name` | `Default` | 否 | 静态 |
| `plugin_modules` | `dsp_bridge.dll;Scrnshot.dll;Language.dll;Box.ini;Update.xml;Update.log` | 否 | 静态 |
| `encryption_algo` | `CryptoAPI RSA 导入/解密（CryptAcquireContextW + CryptImportKey + CryptDecrypt）` | 否 | 静态 |
| `pipe_name` | `\\.\Pipe\1351827` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要把捆绑的 Quark 浏览器安装器（htfgqdowfk.exe）当作最终恶意载荷；它是推广/正常软件，真正的后门是 hrjhh.exe 侧载 log.dll 后注入的 VMProtect 模块。
- 不要因为 hrjhh.exe 内含 cmd.exe、CreatePipe 等字符串就认定该文件本身是恶意主体；它是被重命名并侧载利用的合法 NBMSClient/BarClientView 客户端。
- 不要声称已获取 C2 的真实 IP 或服务器响应；沙箱为假网环境，只观测到域名解析与 443 连接。
- 不要声称样本具有勒索/文件加密或浏览器凭据窃取能力；现有证据只支持 RAT/后门与信息采集。
- 不要仅凭字符串『Telegram』断言存在 Telegram C2；未观测到 api[.]telegram[.]org 等相关域名或流量。
- 不要断言家族归属已由厂商引擎或 YARA 确认；ValleyRAT/Winos 是基于 TTP 与组件命名的候选。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 沙箱为假网环境，仅观测到 rfjp93sina[.]top 的域名解析与 TCP 443 连接，未取得 C2 真实 IP、证书或服务器响应，DoH 隧道载荷内容未知。
2. HKCU Run 键与 HKLM RacMan 服务来自内存字符串与 API 导入能力，未直接读取客体注册表确认实际写入，故按 static 记录。
3. hrjhh.exe 的磁盘文件未取回，仅从进程内存镜像恢复；其数字签名、原始文件哈希与磁盘属性未能核验。
4. VMProtect 后门未脱壳，键盘记录、截屏、远程命令、Token 窃取等能力由导入表与内存字符串推断，未逐项在运行时触发验证。
5. log.dll 为自解密壳且导出名混入 ADSI/LDAP/OpenGL 等系统函数名，未完整脱壳，无法确认其内部模块边界。
6. 家族归属（ValleyRAT/Winos）基于 TTP 与组件命名推测，未经厂商引擎或 YARA 直接确认。

## 证据索引

<details>
<summary>展开 16 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希计算 | sha256=850d135d3ff871f88c96e5a6b889b1f454944ffdd35b2fce5e3fa1d049d8bf70，大小 5430309 |
| `ref:f3587a48ce` | PE 结构解析 | PE32 GUI，入口 RVA 0xAD054，11 段，导出 2 个 |
| `ref:2cd8ba2c8e` | 导出表解析 | DLL 名 SetupLdr.e32，导出 dbkFCallWrapperAddr 与 __dbk_fcall_wrapper，确认 Inno Setup 加载器 |
| `ref:f08493d0e3` | 导入表解析 | 5 个 DLL/150 个导入，含 CreateProcessW、VirtualAlloc、FindResourceW、CreateThread |
| `ref:d55f56cc4f` | 字符串扫描 | Inno Setup 6.9.3/6.5.0 字符串、SetupLdr、TInstItem 等安装器特征 |
| `ref:5e799c57a7` | 动态沙箱时间线 | 引爆后进程 1628=hrjhh.exe、5860=htfgqdowfk.exe；内存扫描发现 2 个植入 PE；产物含网络监控日志与内存转储 |
| `ref:20a9b83342` | PE 结构解析 | log.dll：11 段、W^X 段、113 个导出、TLS |
| `ref:dfc239c619` | 壳检测 | log.dll 判定为自解密壳，.text/.jfiS/.YAaj 高熵且入口段可写 |
| `ref:6e0604e26e` | PE 结构解析 | 28b0000.dll：6 段含 .vmp0（827392 字节），导出 1 个 |
| `ref:0e33f3cae8` | 壳检测 | 28b0000.dll 判定为 VMProtect，置信度 0.9 |
| `ref:be3585b187` | 导出表解析 | 28b0000.dll 唯一导出名 Fuck @RVA 0x1756C |
| `ref:1e9c7021f9` | 导入表解析 | 28b0000.dll 导入 15 个 DLL/243 个符号，含进程枚举、注入、服务、注册表、键盘、截屏、WinINet/WinHTTP、CryptoAPI、Token |
| `ref:242c110b48` | 字符串扫描 | hrjhh.exe 内存镜像字符串含 NBMSClient/BarClientView PDB 与 D:\slave\workspace\AppBcClient 路径 |
| `ref:c00bb9d598` | PE 结构解析 | hrjhh.exe 内存镜像为 PE32 GUI，6 段，image base 0x160000，导入描述符指向 log.dll |
| `ev-000028` | 脚本分析 | 解析网络监控与 minidump：C2 rfjp93sina[.]top:443、DoH 模板、RacMan 持久化、插件路径、Quark 统计上报、hrjhh.exe 静态导入 log.dll |
| `c2_evidence:850d135d` | 连接证据提取 | 动态网络监控记录到 1 次到 g[.]live[.]com:80 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
