---
title: "恶意样本分析：Bellwick（PE · exe · 0ef77eac）"
published: 2026-11-17
draft: false
description: "恶意（置信度低）：Bellwick · loader/downloader · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Bellwick", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Bellwick**（存疑） · 置信度 **低**
> 
> 别名：Bellwick DoH loader
> 
> 样本使用伪装成 Realtek 音频服务的资源与版本信息，导入表为空、入口经混淆分派器解密后运行；在隔离沙箱中真实引爆后，样本主动以 DNS-over-HTTPS 向公共解析器查询 bucket[.]bellwick[.]cc 与 telegra[.]ph，并在内存中解出该 C2 域名、HTTP 头字段与主机指纹相关配置。上述行为组合不具备正常音频服务的合理性，判定为恶意加载器/下载器。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Bellwick** · 别名 Bellwick DoH loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | hard |
| 首次出现 | 2026-11-16 15:25:40 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/0ef77eac80b0f0addda266a68d4fa754c73e53bc453a4595ca13173e04434166/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装Realtek音频服务</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">入口混淆分派</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">运行期解析API</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">DoH解析C2域名</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.004</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">连接公共DoH解析器</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1573</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `0ef77eac80b0f0addda266a68d4fa754c73e53bc453a4595ca13173e04434166` |
| MD5 | _未记录_ |
| 大小 | 720,896 字节（704.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **5** 条静态可得、**2** 条经动态分析取得。

### 1. 伪装Realtek音频服务

`T1036.005` · 置信度 **高** · 静态

资源中写入 Realtek HD Audio 的清单与版本信息，声称公司为 Realtek Semiconductor Corp.、文件描述为 Realtek HD Audio Manager，并将样本命名为 RtkAudioService.exe，以此伪装合法音频服务。

> **证据**：资源 .rsrc (rva 0xd3000) 清单 name="Realtek.Audio.RtkAudioService"；版本串 FileDescription=Realtek HD Audio Manager；进程创建记录同样显示该伪装描述
> 
> **来源**：`ref:5520ccbd36` · `ref:792822e31a`

### 2. 入口混淆分派

`T1027` · 置信度 **高** · 静态

入口 0x401000 仅执行 call 0x4192f4 后 ret，真实逻辑位于 0x4192f4；运行中大量使用常量哈希计算与 retf 远返回构成分派器，0x41c481 内以 0x1337/0xbaad/0xbeef/0xdead 等魔数分支决定后续跳转，属于明显的代码混淆。

> **证据**：0x401000 call 0x4192f4; ret；0x4192f4 处为真实主逻辑；0x41c481 比较 ax,0x1337 / 0xbaad / 0xbeef / 0xc0de / 0xdead 并跳转
> 
> **来源**：`ref:372107d846` · `ref:fdc185685f` · `ref:8225af3184`

### 3. 运行期解析API

`T1027` · 置信度 **高** · 静态

PE 导入表与导出表均为空，样本在运行期自行定位并加载 sspicli、schannel、ncrypt、bcrypt 等模块，通过内存分派调用系统 API，规避静态导入分析。

> **证据**：导入表 dll_count=0 / symbol_count=0；内存模块列表含 sspicli.dll、schannel.dll、ncrypt.dll、bcrypt.dll、rpcrt4.dll
> 
> **来源**：`ref:f45f975287` · `ref:9e5170f4eb` · `ref:792822e31a`

### 4. DoH解析C2域名

`T1071.004` · 置信度 **高** · 动态

样本通过 HTTPS POST /dns-query（Host: dns[.]google 或 cloudflare-dns[.]com）向公共解析器查询 A 记录：先查询 bucket[.]bellwick[.]cc，随后查询 telegra[.]ph，以 DNS-over-HTTPS 隐藏域名解析过程。

> **证据**：网络监控: POST /dns-query; Host: dns[.]google; 报文体 'bucketbellwickcc...'；随后 Host: cloudflare-dns[.]com，报文体 'telegraph...'
> 
> **来源**：`ref:792822e31a`

### 5. 连接公共DoH解析器

`T1573` · 置信度 **高** · 动态

在约 25 秒内多次向 8.8.8[.]8、8.8.4[.]4、1.1.1[.]1、1.0.0[.]1 的 443 端口发起 TCP 连接，并在连接上完成 TLS 与 DoH 请求。

> **证据**：网络监控时间线: 进程 7744 requested TCP 8.8.8[.]8:443 / 8.8.4[.]4:443 / 1.1.1[.]1:443 / 1.0.0[.]1:443（04:29:38–04:30:03）
> 
> **来源**：`ref:792822e31a`

### 6. 采集主机指纹

`T1082` · 置信度 **中** · 静态

样本读取注册表 MachineGuid，并读取 COMPUTERNAME、USERDOMAIN、环境变量等信息用于生成受害机标识；内存中可见完整环境块与 DESKTOP-7QK4M2P 等取值。

> **证据**：内存明文: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid、FallbackGUID、COMPUTERNAME=DESKTOP-7QK4M2P、USERDOMAIN=DESKTOP-7QK4M2P、完整环境变量块
> 
> **来源**：`ref:792822e31a`

### 7. 内存解密C2配置

`T1140` · 置信度 **中** · 静态

配置文件在磁盘上以未知算法加密，运行后在内存堆区出现明文配置：C2 域名 bucket[.]bellwick[.]cc、HTTP 头字段 Host/Accept/Content-Type/Content-Length、32 位十六进制标识 a995a64757a751ca7b61c118f8aa3dc9 与全零 GUID。

> **证据**：内存取证: 0x211b82/0x211ba2/0x211d12 处 'bucket[.]bellwick[.]cc'；0x211bc2 起 Accept/Content-Type/Content-Length/Host；0x211ce2 处 32 位十六进制标识；样本文件中不存在这些明文（单字节 XOR/ADD 也不命中）
> 
> **来源**：`ref:792822e31a`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://bucket[.]bellwick[.]cc/` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://telegra[.]ph/` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `bucket[.]bellwick[.]cc` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `c2_uri` | `/` | 否 | 静态 |
| `doh_resolvers` | `8.8.8[.]8 / 8.8.4[.]4 (SNI dns[.]google), 1.1.1[.]1 / 1.0.0[.]1 (SNI cloudflare-dns[.]com), POST /dns-query` | 是 | 静态 |
| `dead_drop_host` | `telegra[.]ph` | 否 | 静态 |
| `campaign_id` | `a995a64757a751ca7b61c118f8aa3dc9` | 否 | 静态 |
| `bot_id_sources` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid; COMPUTERNAME; USERDOMAIN; 环境变量块` | 是 | 静态 |
| `config_encryption` | `unknown（文件中为密文，仅运行时于内存出现明文；单字节 XOR/ADD 均不命中）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能断言已成功下载或执行第二阶段载荷：仅观测到 DoH 域名解析与连接尝试，未捕获到对 bucket[.]bellwick[.]cc 或 telegra[.]ph 的完整请求/响应会话，也未发现落地文件或子进程。
- 不能据此判定为窃密或勒索软件：未观测到文件枚举、凭据读取、浏览器数据访问或加密破坏行为。
- 不能把 telegra[.]ph 直接当作恶意基础设施：公开的 Telegraph 域名可能仅被用作 dead-drop 解析载体，需结合具体页面路径才能定性。
- 不能声称存在持久化：未观测到注册表自启动、服务安装或计划任务创建。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 配置在文件中以未知算法加密，静态分析未能还原；C2 与配置项来自沙箱内存明文，尚缺对 bucket[.]bellwick[.]cc 的完整请求/响应会话，故 c2/config 统一标记 recoverability=static 且 pending_dynamic_verify=true。
2. DoH 请求侧已被完整捕获，但解析器未返回上游真实应答，无法确认域名解析结果以及后续 C2 交互内容。
3. 样本在约 25 秒后自行退出，未观测到持久化、文件落地或子进程；不排除其行为因网络/虚拟环境而提前终止。
4. 家族命名仅依据 C2 域名归簇，缺少厂商命名、签名或 YARA 佐证，family 标记 uncertain=true。

## 证据索引

<details>
<summary>展开 14 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | hash/entropy/triage | sha256/分段熵/加壳可能性(25%, 仅因 0 导入) |
| `ref:5520ccbd36` | PE 结构解析 | I386 GUI、入口 0x1000、5 个节、.rsrc 与 .reloc、导入/导出目录均为 0 |
| `ref:f45f975287` | 导入表解析 | dll_count=0, symbol_count=0, imphash 为空 |
| `ref:9e5170f4eb` | 壳检测 | packed=false，唯一信号为导入符号极少 |
| `ref:c4a3e15950` | 字符串扫描 | 1429 条 ASCII/29 条 UTF-16 串，无 flag 命中；大量音频领域诱饵串 |
| `ref:372107d846` | 入口反汇编 | 0x401000: call 0x4192f4; ret |
| `ref:fdc185685f` | 主逻辑反汇编 | 0x4192f4 使用常量与哈希调用构造分派 |
| `ref:8225af3184` | 分派器反汇编 | 0x41c481 内比较 0x1337/0xbaad/0xbeef/0xc0de/0xdead 等魔数 |
| `ref:cf51bc3001` | CPU 仿真 | 执行 18 条指令后因无效内存访问停止，说明依赖真实运行时环境 |
| `ref:d40e80364a` | 函数识别 | 未能识别出函数表，进一步佐证强混淆 |
| `ref:0a51e6c932` | 行为仿真 | 仿真环境未产生 API/网络事件 |
| `ref:792822e31a` | 动态沙箱 | 真实引爆：进程 7744 运行约 25 秒，捕获 DoH 查询 bucket[.]bellwick[.]cc / telegra[.]ph、4 个公共解析器 443 连接、内存明文配置与模块列表 |
| `telemetry:0ef77eac` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 94 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 27 条 |
| `etw:0ef77eac:7744` | 进程事件监控 | 短命进程事件：0ef77eac80b0f0addda266a68d4fa754c73e53bc453a4595ca13173e04434166.exe（pid 7744；MD5=8AC9D410BB716F766C0857821FE2781E,SHA256=0EF77EAC80B0F0ADDDA266A68D4FA754C73E53BC453A4595CA13173E04434166,IMPHASH=00000000000000000000000000000000） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
