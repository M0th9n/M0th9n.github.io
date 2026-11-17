---
title: "恶意样本分析：SolidMetricCollective（PE · exe · 7c500ab9）"
published: 2026-11-17
draft: false
description: "恶意（置信度低）：SolidMetricCollective · loader/rat · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["SolidMetricCollective", "loader", "rat", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **SolidMetricCollective**（存疑） · 置信度 **低**
> 
> 别名：Solid Metric Collective signed Go loader
> 
> 样本为 UPX 加壳的 Go 程序，脱壳后确认使用 garble 混淆并以自签名代码签名证书伪装合法软件；在真实动态沙箱中解析并回连 blapt[.]tattoo:443，先上报 tag/exp/hwid 指纹，再以 multipart 上传加密数据；同一进程内存中被检测到一个未登记模块（MEM_PRIVATE，基址 0x140000000），该模块具备屏幕/活动桌面采集与 LZMA 解压能力，并内嵌同一 campaign tag。上述行为由网络监控、内存取证与静态反编译共同证实。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **SolidMetricCollective** · 别名 Solid Metric Collective signed Go loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · rat |
| 难度 | hard |
| 首次出现 | 2026-11-13 20:33:44 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/7c500ab902c6ed54912c6fceac3cf133caf710106750a14bbd04e1e2580eaacf/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX 脱壳载入主模块</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">伪造代码签名证书</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">进程内注入原生模块</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.002</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">采集屏幕与活动桌面</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1113</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">回连 C2 域名上线</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `7c500ab902c6ed54912c6fceac3cf133caf710106750a14bbd04e1e2580eaacf` |
| MD5 | _未记录_ |
| 大小 | 1,209,792 字节（1.2 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **4** 条静态可得、**5** 条经动态分析取得。

### 1. UPX 脱壳载入主模块

`T1027.002` · 置信度 **高** · 静态

外层为 UPX 加壳的 64 位 PE（UPX0/UPX1/UPX2，UPX1 熵 8.0，仅 4 个导入），脱壳后得到 5.9 MB 的 Go 1.21.1 主模块（sha256 f0282a85…）。

> **证据**：section 名 UPX0/UPX1/UPX2；UPX1 entropy 8.0；upx -d 还原为 5901760 字节
> 
> **来源**：`ref:d8fb592173` · `ref:4e6132755a` · `ref:d72365535b`

### 2. 伪造代码签名证书

`T1553.002` · 置信度 **高** · 静态

文件尾部携带 PKCS#7 代码签名，证书为自签名（subject=issuer=Solid Metric Collective，有效期 2026-11-06 至 2027-11-13），并非可信 CA 签发，用于伪装合法软件。

> **证据**：WIN_CERTIFICATE @0x59EE00，长度 0x1FC0；openssl 解析 subject=issuer=Solid Metric Collective
> 
> **来源**：`ref:9e794babac` · `ref:67119a44eb`

### 3. 进程内注入原生模块

`T1055.002` · 置信度 **高** · 动态

主程序自身进程内存在一个未登记的可执行模块（基址 0x140000000，MEM_PRIVATE，非模块列表项），监控组件 判定 implanted_pe；主程序导入 VirtualAlloc/VirtualProtect/CreateThread/GetThreadContext/SetThreadContext 等支持进程内映射与执行。

> **证据**：监控组件: module 140000000 / MEM_PRIVATE / is_listed_module=0 / implanted_pe=1；Go 导入 VirtualAlloc、VirtualProtect、CreateThread
> 
> **来源**：`ref:0b9911592d` · `ref:6b195c2543` · `ref:a52aa20709`

### 4. 采集屏幕与活动桌面

`T1113` · 置信度 **高** · 动态

注入的 252 KB 模块导入 GetDC/GetWindowDC/BitBlt/CreateCompatibleDC/CreateCompatibleBitmap/GetDIBits 以及 OpenDesktopW/GetForegroundWindow/GetKeyboardLayout，具备截取屏幕与活动桌面内容的能力。

> **证据**：140000000.exe 导入表：BitBlt、GetDIBits、GetDC、OpenDesktopW、GetForegroundWindow
> 
> **来源**：`ref:3606b693a4` · `ref:a52aa20709`

### 5. 回连 C2 域名上线

`T1071.001` · 置信度 **高** · 动态

样本解析 blapt[.]tattoo 并通过明文 HTTP 连接 443 端口，请求携带固定 Chrome/117 UA 与 Host: blapt[.]tattoo，属于 HTTP 协议回连。

> **证据**：网络监控日志：6004 requested TCP 192.0.2[.]123:443；POST / HTTP/1.1，Host: blapt[.]tattoo
> 
> **来源**：`ref:0b9911592d` · `ref:03f1c49013`

### 6. 上报主机指纹与标签

`T1082` · 置信度 **高** · 动态

上线请求正文为 tag=bf5eea7eb9dd0adade73f83a0970f1eb&exp=1794540729&hwid=9e9004d73381f66733c6bd6fcb6e2b9b，向 C2 提交 campaign 标签、到期时间与设备指纹。

> **证据**：POST 正文 tag=…&exp=…&hwid=…；注入模块内嵌同一 tag 字符串
> 
> **来源**：`ref:03f1c49013` · `ref:a7c8d10118`

### 7. 加密数据外传

`T1041` · 置信度 **中** · 动态

随后以 multipart/form-data 向同一 C2 上传 1243 字节二进制数据（字段 access_token、type=0、file=data），再发送 6 字节二进制 POST，内容为加密/打包格式，未在流量中暴露明文。

> **证据**：multipart 正文含 access_token/type/file；file 段为高熵二进制；末尾 6 字节 application/octet-stream POST
> 
> **来源**：`ref:03f1c49013`

### 8. LZMA 解压内置载荷

`T1140` · 置信度 **中** · 静态

注入模块包含 LZMA 解码实现（0x4020 字典、乘法哈希匹配表），用于在内存中解压内嵌的下阶段数据。

> **证据**：FUN_140002bb0 反编译：0x4020 字典、0x61C8864F 乘法哈希、match length 编码
> 
> **来源**：`ref:9e72fbe5d3`

### 9. 混淆符号与字符串

`T1027` · 置信度 **高** · 静态

Go 主模块使用 garble 类混淆：main 包函数名被替换为随机标识符（如 main.aul1Z8i5kw），字符串字面量按需解密，静态文件内几乎无业务明文，且构建时使用 -trimpath。

> **证据**：COFF 符号 main.aul1Z8i5kw / main.h7Ylgg180；build info 含 -trimpath=true；静态无 blapt[.]tattoo 明文
> 
> **来源**：`ref:7c8d2372cc` · `ref:a7c8d10118` · `ref:af5e0024a9`


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
| http | `hxxp://blapt[.]tattoo:443/` | 443 | c2 | 动态 | 已观测 |
| http | `hxxp://blapt[.]tattoo:443/` | 443 | exfil | 动态 | 已观测 |

### 主机

**落地路径**

- `%WINDIR%\System32\<64位十六进制随机名>`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `blapt[.]tattoo` | 是 | 动态 |
| `c2_port` | `443` | 是 | 动态 |
| `c2_uri` | `/` | 是 | 动态 |
| `campaign_tag` | `bf5eea7eb9dd0adade73f83a0970f1eb` | 是 | 动态 |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0[.]0 Safari/537.36` | 是 | 动态 |
| `checkin_params` | `tag, exp, hwid` | 是 | 动态 |
| `upload_part_names` | `access_token, type, file` | 否 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 前后系统快照对比未发现 HKCU/HKLM Run 键、服务或计划任务新增，不能声称该样本具备持久化能力。
- 未观察到子进程创建、凭据读取或浏览器数据访问，不能定性为窃密木马。
- 上传的 1243 字节为加密二进制，不能断言其内容为屏幕截图或账号凭据。
- 自签名证书与采集类 API 只能证明伪装与能力，不能据此认定某一厂商家族。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `f0282a857abfaa212681fe3945dc4b559ef270b443720be73d5f717ec808573b`） |

**局限与待验证**

1. C2 的 HTTP 响应由沙箱网络服务模拟，未获得真实指令或后续载荷，无法确认 C2 下发的任务。
2. Go 字符串经混淆并按需解密，静态文件内除少量运行期字符串外无业务明文，完整配置主要依赖内存取证恢复。
3. 系统快照对比未见 Run 键、服务、计划任务或 Defender 排除项新增，持久化能力未获证实。
4. 未观察到子进程创建、凭据文件读取或浏览器数据访问。
5. %WINDIR%\System32\<64位十六进制名> 仅出现在运行期内存字符串中，未能确认实际写盘。
6. 注入模块为内存重建产物，导入表可能不完整；其内部功能仅通过反编译与导入面判定，未观测到实际截屏调用。

## 证据索引

<details>
<summary>展开 19 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:d8fb592173` | 样本分诊 | 原始样本：UPX 段名、UPX1 熵 8.0、4 个导入，加壳可能性 85% |
| `ref:4e6132755a` | unpack.detect | 判定 UPX 加壳，策略 upx_unpack |
| `ref:624c10072a` | PE 结构解析 | 原始 PE 结构：AMD64、3 段、入口 0x6006E0、W^X 异常 |
| `ref:943dba855b` | 导入表解析 | 原始样本仅导入 KERNEL32 的 4 个函数 |
| `ref:7c8d2372cc` | 样本分诊 | 脱壳后正常 PE，8 段，45 个导入，无加壳信号 |
| `ref:6b195c2543` | 导入表解析 | 脱壳后导入 VirtualAlloc/VirtualProtect/CreateThread/SetThreadContext 等 |
| `ref:e56a1b67aa` | disasm.function | main.main 反汇编，控制流平坦化、字符串按需解密 |
| `ref:a7c8d10118` | decompile.symbols | 316 个函数与字符串表，含 campaign tag；main 函数名被随机化 |
| `ref:67119a44eb` | openssl (bash) | 解析 PKCS#7 签名：自签名 Solid Metric Collective 证书与 DigiCert 时间戳链 |
| `ref:9e794babac` | evidence.record | 证书字段与自签名结论（脚本登记） |
| `ref:0b9911592d` | 动态分析平台 | 真实动态沙箱引爆：进程 6004、监控组件 定点转储、时间线与网络日志 |
| `ref:a52aa20709` | PE 结构解析 | 注入模块 140000000.exe 结构：AMD64、4 段、35 个 DLL 导入 |
| `ref:3606b693a4` | 导入表解析 | 注入模块导入 BitBlt/GetDC/GetDIBits/OpenDesktopW 等 |
| `ref:9e72fbe5d3` | decompile.function | FUN_140002bb0 为 LZMA 解码实现 |
| `ref:03f1c49013` | evidence.record | 网络日志解析：blapt[.]tattoo 上线、multipart 上传、6 字节 POST |
| `ref:af5e0024a9` | evidence.record | 内存转储字符串与注入模块 tag 比对 |
| `c2_evidence:7c500ab9` | 连接证据提取 | 动态网络监控记录到 2 次到 blapt[.]tattoo:443 的连接尝试；未捕获完整会话 |
| `telemetry:7c500ab9` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 135 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 27 条 |
| `etw:7c500ab9:6004` | 进程事件监控 | 短命进程事件：7c500ab902c6ed54912c6fceac3cf133caf710106750a14bbd04e1e2580eaacf.exe（pid 6004；MD5=6C671644D6FD5CD57310ED3A7B7C52E3,SHA256=7C500AB902C6ED54912C6FCEAC3CF133CAF710106750A14BBD04E1E2580EAACF,IMPHASH=00000000000000000000000000000000） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
