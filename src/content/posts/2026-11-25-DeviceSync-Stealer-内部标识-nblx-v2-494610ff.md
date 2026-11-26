---
title: "恶意样本分析：DeviceSync Stealer（内部标识 nblx-v2）（PE · exe · 494610ff）"
published: 2026-11-25
draft: false
description: "恶意（置信度低）：DeviceSync Stealer（内部标识 nblx-v2） · stealer/loader · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["DeviceSync", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **DeviceSync Stealer（内部标识 nblx-v2）**（存疑） · 置信度 **低**
> 
> 别名：Device Sync、DeviceSync.dll、DSYNC、nblx-v2
> 
> 静态还原出完整的信息窃取实现：以 .NET 程序伪装成“Device Sync”同步组件，内置 Chrome/Edge/Brave/Opera 与 Firefox 的 Cookie、密码、自动填充、信用卡、历史记录采集，配合 IElevator COM 提升解密 App-Bound 加密数据；同时具备剪贴板/屏幕/钱包/注册表配置单元收集、Defender 排除与 AMSI/ETW 补丁、HKCU Run 持久化、HTTPS 回传（固定 RSA 公钥）与 DGA 兜底、以及从服务端取放后续载荷。动态沙箱中该 .NET 载荷实际加载并常驻，进程内存中可见 HarvestBrowserAsync/GuardPolicy 等窃取与自检符号；因运行环境被识别为虚拟化，收集与外联在观察窗口内未发生。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **DeviceSync Stealer（内部标识 nblx-v2）** · 别名 Device Sync、DeviceSync.dll、DSYNC、nblx-v2 · _存疑_ |
| 置信度 | **低** |
| 行为类 | stealer · loader |
| 难度 | hard |
| 首次出现 | 2026-11-24 23:27:58 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/494610ff80608b4f0ca922fb27a8e1a2cd9d896ee4ae03384cf405faf4a6e3fc/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装设备同步组件</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Harvest浏览器凭据</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">绕过应用绑定加密</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1548</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">收集钱包与桌面数据</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">环境自检后延迟驻留</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `494610ff80608b4f0ca922fb27a8e1a2cd9d896ee4ae03384cf405faf4a6e3fc` |
| MD5 | _未记录_ |
| 大小 | 598,016 字节（584.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **11** 条行为，每条都挂了证据；其中 **9** 条静态可得、**2** 条经动态分析取得。

### 1. 伪装设备同步组件

`T1036.005` · 置信度 **高** · 静态

以伪造的版本资源（Device Sync / DeviceSync.dll / 4.3.73[.]0）与三节随机名（fgFmU、tFXPS、NtWES）伪装为普通同步软件，实际为 .NET 信息窃取程序。

> **证据**：资源节内 VS_VERSION_INFO：CompanyName=Device Sync、OriginalFilename=DeviceSync.dll；PE 头无导入表、入口 RVA=0、节名随机
> 
> **来源**：`ref:2909583825` · `ref:57bf27c1c3` · `ev-000006`

### 2. Harvest浏览器凭据

`T1555.003` · 置信度 **高** · 静态

按 Chrome/Edge/Brave/Opera/Chromium 的 User Data 与 Firefox 配置目录逐项采集 Cookie、Login Data、Web Data、History、Local State，并通过无头浏览器 DevTools 与 SQLite 直读两条路径导出。

> **证据**：UTF-16 字面量 '\Network\Cookies'、'\Login Data'、'\Web Data'、'Local State'、'chrome://settings/passwords'；方法名 HarvestBrowserAsync/ReadCookiesAsync/ReadLoginsAsync；SQLite 查询 'SELECT url, title, visit_count, last_visit_time FROM urls ... LIMIT 2000'
> 
> **来源**：`ev-000006` · `ref:2909583825`

### 3. 绕过应用绑定加密

`T1548` · 置信度 **高** · 静态

枚举 IElevatorChrome/IElevatorEdge/IElevatorBrave 及其 V2 接口，通过 --elevated-caller 提升助手进程以 COM 调用解密 Chrome v20 的 App-Bound 加密 Cookie 与密码；失败时回落数据库解析。

> **证据**：字面量 IElevatorChrome2/IElevatorEdge2/IElevatorBrave2、CoCreateInstance/CoSetProxyBlanket、'--elevated-caller <clsid> <request> <result>'、'[abe] elevated decrypt failed'、'ERR:blanket'
> 
> **来源**：`ev-000006` · `ref:2909583825`

### 4. 收集钱包与桌面数据

`T1555` · 置信度 **高** · 静态

检索桌面钱包文件、浏览器扩展钱包、剪贴板文本、屏幕截图、注册表配置单元（SAM/SYSTEM/SECURITY/SOFTWARE）与会话/域信息，并打包为带时间戳的压缩包。

> **证据**：字面量 wallet-seed.txt/wallet.dat/keystore.json、clipboard.txt、screen.bmp、hives、'[host] hive '、'[*] harvest packed: '；方法 HarvestDesktop/HarvestHives/HarvestExtensionsAsync
> 
> **来源**：`ev-000006` · `ref:2909583825`

### 5. 削弱杀软与遥测

`T1562.001` · 置信度 **高** · 静态

定位 amsi.dll 的 AmsiScanBuffer 与 ntdll 的 EtwEventWrite，改内存保护后打补丁，并用 PowerShell Add-MpPreference 添加针对 winhst.exe 与 powershell.exe 的排除项。

> **证据**：字面量 amsi.dll/AmsiScanBuffer/ntdll.dll/EtwEventWrite/VirtualProtect、'Add-MpPreference -ExclusionPath'、'Add-MpPreference -ExclusionProcess'、winhst.exe、powershell.exe
> 
> **来源**：`ev-000006` · `ref:d576f8eae2`

### 6. 写入启动项持久化

`T1547.001` · 置信度 **高** · 静态

将自身复制到安装目录并以 dsync 为值名写入当前用户 Run 键，命令行附带 --persist=auto --boot；在 Linux 侧还会写入 XDG 自启动 .desktop 项。

> **证据**：字面量 'Software\Microsoft\Windows\CurrentVersion\Run'、'[persist] kept ('、'--persist=auto --boot'、'[Desktop Entry]'、'X-GNOME-Autostart-enabled=true'
> 
> **来源**：`ev-000006` · `ref:2909583825`

### 7. 固定公钥回传数据

`T1071.001` · 置信度 **高** · 静态

通过 HTTPS 向配置主机（默认 196[.]251[.]102[.]202）的 /account 与 /dashboard 提交采集包，连接前用内置 RSA-3072 公钥校验服务端，校验失败则尝试 DGA 生成域名，仍失败则离线暂存。

> **证据**：UTF-16 字面量 ' hxxps://'、'/account'、'/dashboard'、'BEGIN PUBLIC KEY'、'[!] server closed the link without proving the pinned key'、'[dga] '、'[!] pin failure '，紧随 IP 的 Base64 公钥 'MIIBojANBgkqhkiG9w0BAQEFAAOCAY8A...'
> 
> **来源**：`ev-000006` · `ref:2909583825`

### 8. 服务端取放后续载荷

`T1105` · 置信度 **高** · 静态

从服务端拉取 drop 载荷（可选 SHA-256 校验），写入临时 payload_<时间戳> 后启动，并记录 drop.log、回执与失败重试。

> **证据**：字面量 '--drop'、'--drop-sha256'、'--drop-anyway'、'payload_'、'[drop] running pid '、'[*] acked '、'[!] no ack for '、'spool:keep '
> 
> **来源**：`ev-000006` · `ref:2909583825`

### 9. 自删除与投放诱饵

`T1070.004` · 置信度 **高** · 静态

退出时用 cmd.exe 执行 ping 延时后 del 自身；采集目录中投放 cookies.txt/passwords.txt/wallet-seed.txt 等诱饵记录干扰人工排查。

> **证据**：字面量 '/c ping -n 3 127.0.0[.]1 >nul & del /f /q "'、'junk:start'、'[junk] decoy records written'
> 
> **来源**：`ev-000006`

### 10. 环境自检后延迟驻留

`T1497.001` · 置信度 **高** · 动态

启动后执行虚拟化/分析环境打分与 dwell 等待（含休眠跳过检测），评分命中即中止收集；本次运行中进程加载 .NET 载荷后静默驻留约 3 分钟，未产生子进程与外联。

> **证据**：动态时间线：pid 4256 于 02:34:07 启动，02:34:14 与 02:34:25 两次内存转储时仍存活并延续到观察结束；进程创建事件仅一条、无子进程；内存字符串 GuardPolicy/GuardProbe/'[guard] analysis environment, aborting'；'[guard] dwell ok (+'
> 
> **来源**：`ref:f80473fa52` · `ev-000006`

### 11. 内存装载窃取模块

`T1497.003` · 置信度 **中** · 动态

运行时进程内实际加载并编译了采集相关方法（HarvestBrowserAsync、HarvestProfileAsync、HarvestHives、SendGuardedAsync 等），窃取逻辑随主程序集进入就绪状态，但窗口内未进入执行收集阶段。

> **证据**：进程内存转储字符串包含 HarvestBrowserAsync/HarvestProfileAsync/HarvestExtensionsAsync/HarvestHives/SendGuardedAsync/DSYNC_SERVER/DSYNC_PIN/nblx-v2；3 分钟内无收集产物或外联，符合先驻留后作业的时序
> 
> **来源**：`ref:f80473fa52`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://196[.]251[.]102[.]202/account` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://196[.]251[.]102[.]202/dashboard` | 443 | panel | 静态 | ⏳ 未观测 |
| dns | `DGA（种子 89c7e1a14d62660f9665696997d1921d7e93a99573067392，失败时回落固定主机）` | - | c2 | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `Global\mtx-<随机后缀>（单实例互斥量）`

**落地路径**

- `%TEMP%\payload_<yyyyMMddHHmmss>`
- `%TEMP%\dsync_launch_*.log`
- `<安装目录>\installed.marker`
- `<安装目录>\.shadow`
- `%LOCALAPPDATA%\...\spool`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run（值名 dsync，命令行带 --persist=auto --boot）`
- `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths（读取与修复）`
- `HKLM\SOFTWARE\Microsoft\Windows Defender\Features（读取 TamperProtection）`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `196[.]251[.]102[.]202` | 是 | 静态 |
| `c2_uri_account` | `/account` | 否 | 静态 |
| `c2_uri_dashboard` | `/dashboard` | 否 | 静态 |
| `c2_port` | `443（TLS；端口未以常量出现，按 https 前缀推断）` | 否 | 静态 |
| `tls_pin_public_key` | `RSA-3072 SubjectPublicKeyInfo，Base64 前缀 MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAv/QI9rrFckC+...AgMBAAE=` | 是 | 静态 |
| `dga_seed` | `89c7e1a14d62660f9665696997d1921d7e93a99573067392` | 否 | 静态 |
| `protocol_tag` | `nblx-v2` | 否 | 静态 |
| `install_marker` | `installed.marker` | 否 | 静态 |
| `mutex_prefix` | `Global\mtx-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要判定为勒索软件或擦除器：样本没有文件加密、卷影删除或磁盘破坏逻辑。
- 不要声称已成功外传凭据：本次动态窗口未见任何样本发起的网络请求或回传会话。
- 不要声称已在宿主写入 Defender 排除或启动项：仅有相应代码路径与命令字符串，运行期遥测未显示注册表/服务变更。
- 不要把它简单归类为下载器：其主体能力是本地浏览器与钱包数据窃取，取放载荷只是附属流程。
- 不要把伪造的“Device Sync”产品信息当作真实厂商归属。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 未取得 C2 会话：动态窗口内样本零外联，C2 主机/路径/公钥均为静态恢复，需后续在更真实环境中复核。
2. 运行期仅见进程加载与驻留，未观测到浏览器采集、Defender 排除、启动项写入等动作；相关结论基于代码与字面量，属静态判定。
3. 安装目录根路径、互斥量随机后缀、DGA 域名后缀未静态或动态取得。
4. 尾部高熵数据节（NtWES，2333 字节）未被任何数据目录引用，可能为加密配置/密钥材料/附加载荷，未解密。
5. 家族命名无厂商引擎或公开规则佐证，仅依据样本内部标识（Device Sync、nblx-v2、DSYNC_*）。

## 证据索引

<details>
<summary>展开 7 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:2909583825` | 样本分诊 | 哈希/节熵/导入面/加壳信号分诊 |
| `ref:57bf27c1c3` | PE 结构解析 | PE 结构：3 个随机名节、入口 RVA 0、无导入表、COM Descriptor 指向 .NET 元数据 |
| `ev-000006` | 字符串提取 | ASCII 1957 条 / UTF-16LE 757 条字符串抽取，含浏览器路径、Defender 排除、DGA/固定公钥等 |
| `ref:d576f8eae2` | unpack.antidebug | 静态反调试/反分析技术识别（2 项，低置信） |
| `ref:f80473fa52` | 动态分析平台 | 真实动态：pid 4256 启动、两次内存转储、无子进程、网络监控无样本请求、遥测前后对比、回滚 |
| `telemetry:494610ff` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 118 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 26 条 |
| `etw:494610ff:4256` | 进程事件监控 | 短命进程事件：494610ff80608b4f0ca922fb27a8e1a2cd9d896ee4ae03384cf405faf4a6e3fc.exe（pid 4256；MD5=3DAA8D07D773074BBEFFC31447ADB4EF,SHA256=494610FF80608B4F0CA922FB27A8E1A2CD9D896EE4AE03384CF405FAF4A6E3FC,IMPHASH=00000000000000000000000000000000） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
