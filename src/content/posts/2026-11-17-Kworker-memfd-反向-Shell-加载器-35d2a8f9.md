---
title: "恶意样本分析：Kworker memfd 反向 Shell 加载器（ELF · elf · 35d2a8f9）"
published: 2026-11-17
draft: false
description: "恶意（置信度低）：Kworker memfd 反向 Shell 加载器 · backdoor/downloader/loader · 难度 easy · 动态沙箱 + 静态反编译"
tags: ["Kworker memfd", "backdoor", "downloader", "loader", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Kworker memfd 反向 Shell 加载器**（存疑） · 置信度 **低**
> 
> 别名：linux_amd64_tcp 模板反向 shell、memfd/fexecve 无文件 stager
> 
> 反编译 main 显示完整反向 shell/无文件加载链：先用 access("/tmp/log_de.log") 做单实例检查，随后循环 connect 硬编码的 149.30.247[.]60:8080，成功后发送 "l64 "+端口+32 字节主机标识，把收到的数据逐字节 XOR 0x99 解密并写入 memfd_create 创建的内存文件，最后 fexecve 以 "[kworker/0:2]" 为 argv[0] 执行该内存载荷。隔离环境真跑观测到进程反复向 149.30.247[.]60:8080 发起 TCP 连接（ENETUNREACH，每 10 秒重试），与静态逻辑一致。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Kworker memfd 反向 Shell 加载器** · 别名 linux_amd64_tcp 模板反向 shell、memfd/fexecve 无文件 stager · _存疑_ |
| 置信度 | **低** |
| 行为类 | backdoor · downloader · loader |
| 难度 | easy |
| 首次出现 | 2026-11-16 00:11:57 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">检查运行标记</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">循环连接硬编码 C2</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">发送协议握手</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">创建匿名内存文件</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">XOR 解密并写入载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `35d2a8f92ffde391195c38d7c7dbdd6b5eda71ba55fcbecfb4bf56e84312da8d` |
| MD5 | _未记录_ |
| 大小 | 9,800 字节（9.6 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **7** 条行为，每条都挂了证据，且全部静态可得。

### 1. 检查运行标记

`T1480` · 置信度 **高** · 静态

main 入口先调用 access("/tmp/log_de.log", F_OK)，若该文件存在则直接 exit(0)，否则继续执行，用于限制重复运行/规避重复分析。

> **证据**：main @0x400950；0x400967 call access，参数 "/tmp/log_de.log" @0x400cd4；0x400977 分支调用 exit
> 
> **来源**：`ev-000001` · `ev-000002` · `ev-000008`

### 2. 循环连接硬编码 C2

`T1095` · 置信度 **高** · 静态

解析内置地址 149.30.247[.]60 后填充 sockaddr_in（端口 8080），设置 TCP SYN 重传次数为 10，循环 connect，失败则 sleep(10) 无限重试。

> **证据**：0x400a1b call connect；0x400a29 call sleep；套接字选项 (6,7)=10；真跑 strace: connect(3,{AF_INET,htons(8080),149.30.247[.]60})=-1 ENETUNREACH
> 
> **来源**：`ev-000001` · `ev-000014` · `ev-000016`

### 3. 发送协议握手

`T1095` · 置信度 **高** · 静态

连接建立后依次发送 6 字节 "l64 "、2 字节端口（0x1f90 即 8080）和 32 字节主机标识（0x400d00 处 IP 字符串的 32 字节拷贝），用于向服务端标识受害端。

> **证据**：0x400a3e send(...,"l64 ",6,0)；0x400a62 send 端口 0x901f；0x400a75 send 32 字节主机缓冲
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 创建匿名内存文件

`T1620` · 置信度 **高** · 静态

通过 syscall 319（memfd_create）创建名称为 "a" 的匿名可执行内存文件，作为远端载荷的接收载体，不在磁盘生成文件。

> **证据**：0x400a88 mov edi,0x13f；0x400a8f call syscall；名称 "a" @0x400ceb
> 
> **来源**：`ev-000001` · `ev-000002`

### 5. XOR 解密并写入载荷

`T1140` · 置信度 **高** · 静态

对每次 recv 收到的数据块逐字节 XOR 0x99 后 write 到 memfd，实现简单的流式混淆传输，直到对端关闭连接。

> **证据**：0x400aac call recv；0x400abd xor byte ptr [rax],0x99；0x400ad4 call write(memfd)
> 
> **来源**：`ev-000001` · `ev-000002`

### 6. 伪装进程名执行载荷

`T1036.005` · 置信度 **高** · 静态

连接结束后 close 套接字，realpath(argv[0]) 写入环境变量 CWD，随后 fexecve 执行 memfd，argv[0] 设为 "[kworker/0:2]" 伪装成内核工作线程。

> **证据**：0x400af9 call realpath；0x400b0f call setenv("CWD")；0x400b37 call fexecve，argv 首项 "[kworker/0:2]" @0x400cf1
> 
> **来源**：`ev-000001` · `ev-000002`

### 7. 以根目录地址兜底解析

`T1095` · 置信度 **高** · 静态

对内置地址先调用 gethostbyname，返回空时回退 inet_addr，保证即使域名解析不可用也能得到连接地址。

> **证据**：0x4009ab call gethostbyname；0x4009b6 call inet_addr；结果按字节写入 sockaddr_in
> 
> **来源**：`ev-000001`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `149[.]30[.]247[.]60:8080` | 8080 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/tmp/log_de.log`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `149[.]30[.]247[.]60` | 是 | 静态 |
| `c2_port` | `8080` | 是 | 静态 |
| `c2_protocol_handshake` | `原始 TCP；首包为 "l64 "(6 字节) + 2 字节大端端口 + 32 字节主机标识` | 是 | 静态 |
| `payload_transport_encoding` | `逐字节 XOR 0x99` | 是 | 静态 |
| `exec_method` | `memfd_create("a") 接收载荷后 fexecve 执行，不落盘` | 是 | 静态 |
| `argv0_masquerade` | `[kworker/0:2]` | 是 | 静态 |
| `single_instance_marker` | `/tmp/log_de.log（仅检查是否存在，不存在才继续执行；未见创建逻辑）` | 是 | 静态 |
| `campaign_id` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要称其为勒索软件或挖矿程序：样本不含文件加密、密钥管理或矿池/挖矿相关逻辑，唯一编码操作是 0x99 单字节 XOR。
- 不要声称 149.30.247[.]60 已确认是可用的在线 C2：隔离网络中只观测到 ENETUNREACH 连接尝试，没有任何成功会话或下发内容。
- 不要声称样本创建了 /tmp/log_de.log：反编译显示只检查该文件是否存在，不存在时才继续执行。
- 不要声称样本具备持久化能力：未见 systemd、cron、rc.local 或 shell profile 写入逻辑。
- 不要把 "[kworker/0:2]" 当成真实内核线程：它是 fexecve 时伪造的 argv[0]。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 隔离网络不可达，仅观测到 connect 尝试（ENETUNREACH）与每 10 秒重试，未获得服务端握手响应或第二阶段载荷；因此 c2 按静态可恢复处理并标记待动态确认。
2. 发送内容与解密后的载荷未能从真实流量中捕获：协议字段（"l64 "、端口、32 字节主机标识、XOR 0x99）来自反编译，而非成功会话。
3. 家族归属缺少厂商引擎、签名或 YARA 佐证，当前名称为基于行为特征的候选，存在不确定性。
4. 仅在 x86-64 原生环境验证执行；memfd + fexecve 能否成功依赖目标内核允许匿名内存文件可执行，未在其他内核/架构上验证。

## 证据索引

<details>
<summary>展开 4 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | decompile.function | 反编译 main @0x400950，还原 access 检查、connect/send 握手、syscall(0x13f) memfd_create、XOR 0x99 写入与 fexecve("[kworker/0:2]") 全链 |
| `ev-000002` | 字符串提取 | 抽取 135 条 ASCII 字符串，命中 /tmp/log_de.log、"l64 "、CWD、[kworker/0:2]、149.30.247[.]60、linux_amd64_tcp.c |
| `ev-000014` | dyn.trace.strace | 加固实例 strace：socket(AF_INET,SOCK_STREAM) 后 connect 149.30.247[.]60:8080 返回 ENETUNREACH，重试循环 |
| `ev-000016` | dyn.exec | 加固 WSL 真跑：进程无 stdout，持续重试连接 C2，超时被终止（exit=124） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
