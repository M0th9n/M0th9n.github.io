---
title: "恶意样本分析：SteamProfile-gated obfuscated implant (未命名变体)（PE · exe · 216f8ae1）"
published: 2026-11-23
draft: false
description: "恶意（置信度低）：SteamProfile-gated obfuscated implant (未命名变体) · backdoor · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **SteamProfile-gated obfuscated implant (未命名变体)**（存疑） · 置信度 **低**
> 
> 别名：Steam Community dead-drop client、obfuscated x64 loader/RAT (string-encrypted)
> 
> 样本为高度混淆的 64 位 Windows 植入体：静态文件中业务字符串全部加密、导入表被裁剪到仅 20 个基础 API，入口处用混淆的常量算术动态解析并加载模块；动态沙箱中真实运行后，样本进程自身将启动项写入当前用户 Run 键（值名 light-theme，数据为自身路径），并以约 30 秒为周期持续向 steamcommunity[.]com 的固定用户主页发起 HTTP 请求。持久化 + 周期性回连 + 全量隐藏字符串的组合，可直接判定为恶意植入体。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **SteamProfile-gated obfuscated implant (未命名变体)** · 别名 Steam Community dead-drop client、obfuscated x64 loader/RAT (string-encrypted) · _存疑_ |
| 置信度 | **低** |
| 行为类 | backdoor |
| 难度 | medium |
| 首次出现 | 2026-11-22 16:58:57 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/216f8ae18eca087ef83446686514577e03c68bb8a3ce1381661d3d34821b6aaf/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">写入 Run 键自启动</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.001</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">30 秒周期回连主页</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">运行时解密字符串表</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">动态解析并加载模块</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">加载截屏与采集依赖</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1113</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `216f8ae18eca087ef83446686514577e03c68bb8a3ce1381661d3d34821b6aaf` |
| MD5 | _未记录_ |
| 大小 | 2,253,312 字节（2.1 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **3** 条静态可得、**4** 条经动态分析取得。

### 1. 写入 Run 键自启动

`T1547.001` · 置信度 **高** · 动态

运行后约 6 秒，样本进程自身在 HKU\S-1-5-21-...-1000\SOFTWARE\Microsoft\Windows\CurrentVersion\Run 下创建值 light-theme，数据为样本自身绝对路径，实现登录自启动。

> **证据**：系统事件遥测 01:01:11 注册表值设置事件：ProcessId 6200 = 样本，TargetObject=...\Run\light-theme，Details=C:\dyn\samples\216f8ae1...exe；同名值 light-theme 亦出现在样本解密后的字符串表中
> 
> **来源**：`ev-000011` · `ev-000010`

### 2. 30 秒周期回连主页

`T1102` · 置信度 **高** · 动态

启动后约 16 秒开始，样本以约 30 秒固定周期重复向 steamcommunity[.]com 的固定用户主页发起 HTTP 请求（GET /id/765611991592232669/，UA Mozilla/5.0，Cache-Control: no-cache），运行窗口内共观测到 6 次，构成心跳式回连。

> **证据**：DNS 查询 steamcommunity[.]com 由 pid 6200 发起；网络监控在 01:01:22 / 01:01:52 / 01:02:23 / 01:02:53 / 01:03:23 / 01:03:53 六次捕获同一样本进程的 GET /id/765611991592232669/ 与 Host: steamcommunity[.]com
> 
> **来源**：`ev-000011` · `ev-000010`

### 3. 运行时解密字符串表

`T1027` · 置信度 **高** · 静态

文件内 .rdata/.data 熵分别为 7.538/7.996 且不含任何明文业务字符串（仅剩导入名），样本在运行期才把字符串表解密到堆中，解密后可见互斥量后缀、主题名、Steam 主页 URL、HELLO 协议格式等；说明静态特征被系统性隐藏。

> **证据**：.rdata 熵 7.538(off 0x209000)、.data 熵 7.996(off 0x214200)；全文件字符串抽取 0 条业务明文；内存转储 0x9da52d 处出现解密后的字符串表
> 
> **来源**：`ev-000005` · `ev-000006` · `ev-000009` · `ev-000010`

### 4. 动态解析并加载模块

`T1129` · 置信度 **高** · 动态

入口处不通过静态导入表使用 API，而以常量异或/指针算术混淆计算函数地址并逐个 LoadLibraryA 加载 advapi32、shell32、ole32、iphlpapi、wininet、ws2_32、psapi、combase、sechost、d3d11、dxgi、rpcrt4 等模块，规避导入表检测并具备注册表、网络、进程与图形功能面。

> **证据**：入口 0x1400F5430 处 sub rsp,0x28 后 movabs 常量运算后 call r8；行为仿真中 pc 0x1400334ca-0x140033372d 连续 LoadLibraryA(advapi32/shell32/ole32/iphlpapi/wininet/ws2_32/psapi/combase/sechost/d3d11/dxgi/rpcrt4)
> 
> **来源**：`ref:a01aaeadd1` · `ref:6e53d506fc` · `ev-000003`

### 5. 加载截屏与采集依赖

`T1113` · 置信度 **中** · 动态

样本主动加载 d3d11.dll 与 dxgi.dll（桌面复制/截屏常用依赖）以及 psapi.dll、iphlpapi.dll、GetForegroundWindow/IsWindowVisible/GetFocus 等窗口与主机信息采集面，具备屏幕抓取与进程/环境枚举能力；本次运行窗口内未捕获实际画面文件。

> **证据**：行为仿真 pc 0x1400336bb LoadLibraryA(d3d11.dll)、0x1400336f6 LoadLibraryA(dxgi.dll) 与 psapi/iphlpapi 加载；静态导入 USER32.GetForegroundWindow/IsWindowVisible/GetFocus/GetProcessWindowStation、GDI32.GetStockObject
> 
> **来源**：`ref:6e53d506fc` · `ref:d8e55c004f`

### 6. 单实例互斥量命名

`T1480` · 置信度 **低** · 静态

解密后字符串表显示两枚全局互斥量名 Global\{{081F2F64-1503-2D62-555E-C9FD8082EAC0}}_Admin 与 ..._User，用于按管理员/普通用户区分单实例运行；本次运行窗口未直接捕获互斥量创建的系统事件。

> **证据**：内存转储 0x144c9 与 0x9da52d 处明文互斥量 Global\{{081F2F64-1503-2D62-555E-C9FD8082EAC0}}_Admin / _User
> 
> **来源**：`ev-000010`

### 7. HELLO 面板握手协议

`T1071.001` · 置信度 **中** · 静态

内置协议格式串 HELLO|%s|%s|%s|%s|%s|v3.3F|%s|%s|%s（自报版本 v3.3F，九个字段承载标识/环境信息），配套 %s@%s 与 hxxps://%s:%hu/ 的地址拼接格式，表明存在向远端面板上报的握手/心跳通道。

> **证据**：内存转储 0x9da59d-0x9da5a9 处解密出 %s@%s 与 HELLO|%s|%s|%s|%s|%s|v3.3F|%s|%s|%s；另见 hxxps://%s:%hu/ 与 hxxps://%s/%s/%s
> 
> **来源**：`ev-000010`


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
| http | `hxxps://steamcommunity[.]com/id/765611991592232669/` | 443 | panel | 动态 | 已观测 |

### 主机

**互斥体**

- `Global\{{081F2F64-1503-2D62-555E-C9FD8082EAC0}}_Admin`
- `Global\{{081F2F64-1503-2D62-555E-C9FD8082EAC0}}_User`

**注册表**

- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\light-theme`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `steamcommunity[.]com` | 是 | 动态 |
| `c2_uri` | `/id/765611991592232669/` | 是 | 动态 |
| `c2_port` | `443` | 是 | 动态 |
| `user_agent` | `Mozilla/5.0` | 是 | 动态 |
| `beacon_period_sec` | `30` | 否 | 动态 |
| `registry_run_value` | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\light-theme` | 是 | 动态 |
| `mutex` | `Global\{{081F2F64-1503-2D62-555E-C9FD8082EAC0}}_Admin / _User` | 否 | 静态 |
| `protocol_hello` | `HELLO\|%s\|%s\|%s\|%s\|%s\|v3.3F\|%s\|%s\|%s` | 否 | 静态 |
| `build_version` | `v3.3F` | 否 | 静态 |
| `campaign_flags` | `nocrp_on; light-theme; --elevated` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得声称样本已窃取账号口令、浏览器数据或 Steam 会话：运行窗口内未观测到对浏览器/Steam 目录的读取，也没有携带数据的外发请求。
- 不得声称样本执行了进程注入/进程镂空：内存扫描对该进程判定 0 处可疑植入，且运行期未派生子进程。
- 不得把 steamcommunity[.]com 当作攻击者私有 C2 域名处置：它是合法公开站点，样本仅访问其中一条固定用户主页，可能用于授权/死信箱校验，真实面板主机未在本次窗口现身。
- 不得把该样本归类为勒索或擦除类：未见文件加密、删除或卷影破坏行为。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 样本 .rdata/.data 全部加密、字符串按需解密，静态无法还原完整配置与代码语义；控制流经混淆，入口处为常量异或算术 + 间接调用，未做全量反混淆。
2. 仅捕获到对 steamcommunity[.]com 固定主页的 HTTP 请求，未取得 HELLO 协议对应的真实面板会话，故真实 C2 主机、端口与加密方式均未确认（HELLO 协议项标记为静态推断）。
3. 截屏（d3d11/dxgi）、进程枚举（psapi）、互斥量单实例等能力来自模块加载与解密字符串，运行窗口内未直接观测到截屏产物、进程遍历结果或互斥量创建事件，相关结论置信度按中/低处理。
4. 未取得文件系统层的完整操作记录，样本是否读取浏览器/Steam 数据无法从本次产物判定。
5. 家族命名缺少厂商命名、YARA 或公开沙箱报告的交叉印证，仅以候选形式登记并标注不确定。

## 证据索引

<details>
<summary>展开 18 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=216f8ae1...；md5=3b61a16fce9eff5f4b20a384aceef89b；大小 2253312 字节 |
| `ev-000002` | scan.imphash | imphash=bc051e8081fce700a2904976020c7b00 |
| `ev-000003` | scan.rich | Rich 头存在，6 条 MSVC 工具链记录，richhash=227e4c8928441e706fb7a3f687e67bf5 |
| `ev-000004` | scan.entropy | .text 熵 6.654 |
| `ev-000005` | scan.entropy | .rdata 熵 7.538（高） |
| `ev-000006` | scan.entropy | .data 熵 7.996（高） |
| `ev-000009` | 字符串提取 | 字符串抽取：ASCII 792 条，全部为代码字节样式，无业务明文、无 flag 命中 |
| `ev-000010` | 脚本化取证 | 从内存转储提取运行时解密字符串表（_Admin/_User/light-theme/Steam 主页 URL/nocrp_on/HELLO 协议等） |
| `ev-000011` | 脚本化取证 | 解析动态沙箱遥测与网络监控：Run 键 light-theme 写入、steamcommunity[.]com DNS 与 6 次 HTTP 请求、无子进程、内存扫描 0 可疑 |
| `ref:ce26b78dd2` | PE 结构解析 | AMD64 GUI 可执行，5 节，入口 RVA 0xF5430，无导出/无资源/TLS/LoadConfig，无结构异常 |
| `ref:d8e55c004f` | 导入表解析 | 5 个 DLL / 20 个导入符号（KERNEL32、WS2_32 序数 8/14/111、USER32、GDI32、ole32），无 CRT/无 LoadLibrary/GetProcAddress 静态导入 |
| `ref:a01aaeadd1` | disasm.function | 入口 0x1400F5430 起为混淆桩：movabs 常量 + 指针算术 + 间接 call/jmp，动态解析 API |
| `ref:8ad6c8afb6` | unpack.detect | 静态壳检测：未命中已知壳（packed=false, confidence=0） |
| `ref:6e53d506fc` | dyn.run | 行为仿真：LoadLibraryA advapi32/shell32/ole32/iphlpapi/wininet/ws2_32/psapi/combase/sechost/d3d11/dxgi/rpcrt4 |
| `ref:5bf347a4bd` | 动态分析平台 | 真实动态引爆：样本进程启动并持续运行，产出内存转储、网络监控与遥测；观察窗口内无新子进程 |
| `c2_evidence:216f8ae1` | 连接证据提取 | 动态网络监控记录到 8 次到 steamcommunity[.]com:443 的连接尝试；未捕获完整会话 |
| `telemetry:216f8ae1` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 113 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 23 条 |
| `etw:216f8ae1:6200` | 进程事件监控 | 短命进程事件：216f8ae18eca087ef83446686514577e03c68bb8a3ce1381661d3d34821b6aaf.exe（pid 6200；MD5=3B61A16FCE9EFF5F4B20A384ACEEF89B,SHA256=216F8AE18ECA087EF83446686514577E03C68BB8A3CE1381661D3D34821B6AAF,IMPHASH=2EDDB0DD356374D338CC10CE8C8B6680） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
