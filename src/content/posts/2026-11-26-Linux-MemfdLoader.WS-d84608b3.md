---
title: "恶意样本分析：Linux/MemfdLoader.WS（ELF · elf · d84608b3）"
published: 2026-11-26
draft: false
description: "恶意（置信度低）：Linux/MemfdLoader.WS · loader/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["loader", "downloader", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Linux/MemfdLoader.WS**（存疑） · 置信度 **低**
> 
> 别名：linux_i386_ws loader、ws_/l32 HTTP 信标内存加载器
> 
> 该文件是一个 32 位 x86 Linux ELF 内存加载器/下载器：启动后检查 /tmp/log_de.log 单实例标记，向硬编码地址 47.107.122[.]241:40002 反复建立 TCP 连接并发送伪装成 Firefox 的 HTTP 信标，随后读取 HTTP 响应、把响应体逐字节 XOR 0x99 解密后写入 memfd，再通过 fexecve 以 [kworker/0:2] 进程名无文件执行第二阶段。反编译与反汇编完整还原了该执行链，加固实例内的真实运行也观测到标记文件探测与对 47.107.122[.]241:40002 的重复连接尝试。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Linux/MemfdLoader.WS** · 别名 linux_i386_ws loader、ws_/l32 HTTP 信标内存加载器 · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | medium |
| 首次出现 | 2026-11-24 01:05:32 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/d84608b3e154142cdb626876c3ea8948225786ebe2c7791509a2253d7009cf0c/) |

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
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">回连硬编码 C2</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">发送伪浏览器信标</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">读取响应头分界</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">XOR 0x99 解密载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `d84608b3e154142cdb626876c3ea8948225786ebe2c7791509a2253d7009cf0c` |
| MD5 | _未记录_ |
| 大小 | 7,262 字节（7.1 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **5** 条静态可得、**2** 条经动态分析取得。

### 1. 检查单实例标记

`T1480` · 置信度 **高** · 动态

调用 access("/tmp/log_de.log", F_OK)，若该路径已存在则直接 exit(0)，用于避免同一主机重复运行。

> **证据**：0x08048707 call access，路径 0x08048ae0="/tmp/log_de.log"；动态观测 access("/tmp/log_de.log", F_OK) 返回 ENOENT。
> 
> **来源**：`ev-000002` · `ev-000010` · `ref:a81b35b734`

### 2. 回连硬编码 C2

`T1071.001` · 置信度 **高** · 动态

创建 AF_INET/SOCK_STREAM 套接字并设置 TCP_SYNCNT=10，随后 connect 到 47.107.122[.]241:40002；连接失败时 sleep(10) 无限重试。

> **证据**：0x0804873d 写入端口 0x429c(40002)，0x08048746 gethostbyname，0x08048784 socket，0x080487b1 setsockopt，0x080487be connect；动态观测 connect(3, {sin_port=htons(40002), sin_addr=47.107.122[.]241}) 连续返回 ENETUNREACH 并进入 10 秒休眠。
> 
> **来源**：`ev-000002` · `ev-000015` · `ev-000016` · `ev-000017` · `ref:c7bbb8697d`

### 3. 发送伪浏览器信标

`T1071.001` · 置信度 **高** · 静态

连接成功后用 sprintf 拼出 "GET /?a=l32&h=47.107.122[.]241&t=ws_&p=40002 HTTP/1.1"，附带 Host 与 Firefox/48.0 User-Agent，并 send 0x400 字节上报主机标识与端口。

> **证据**：0x08048808 call sprintf，格式串 0x08048b19，实参 0x08048b15="l32"、0x08048af0="47.107.122[.]241"、0x08048b11="ws_"；0x0804881b call send。
> 
> **来源**：`ev-000002` · `ev-000001` · `ref:c7bbb8697d`

### 4. 读取响应头分界

`T1071.001` · 置信度 **高** · 静态

逐字节 recv 直到识别 \r\n\r\n 头部终止序列，从而把 HTTP 响应头与随后的二进制载荷体分开。

> **证据**：0x0804883a call recv，0x0804888a 起比较 0x0a/0x0d 四字节序列判断报文头结束。
> 
> **来源**：`ev-000002` · `ref:c7bbb8697d`

### 5. XOR 0x99 解密载荷

`T1140` · 置信度 **高** · 静态

对 recv 收到的每个数据块逐字节执行 XOR 0x99 后再写出，为第二阶段载荷的轻量混淆层。

> **证据**：0x080488c2 指令 80 34 0a 99（xor byte ptr [edx+ecx], 0x99），循环长度为本次 recv 返回值。
> 
> **来源**：`ev-000002` · `ref:a81b35b734`

### 6. memfd 无文件执行

`T1620` · 置信度 **高** · 静态

以 syscall 356（i386 memfd_create）创建名为 "a"、带 MFD_CLOEXEC 的内存文件，把解密后的载荷写入该 fd，最后 fexecve 从内存直接执行，避免落盘。

> **证据**：0x0804887a push 0x164、0x0804887d push "a"(0x08048b9c)、0x08048887 call syscall；0x080488d5 write；0x08048944 call fexecve。
> 
> **来源**：`ev-000002` · `ref:a81b35b734`

### 7. 伪装内核线程名

`T1036.005` · 置信度 **高** · 静态

执行前把 argv[0] 设为 "[kworker/0:2]"，并 setenv("CWD", realpath(argv[0]), 1)，使第二阶段在进程列表中伪装为内核工作线程。

> **证据**：0x08048930 写入 argv[0]=0x08048ba2="[kworker/0:2]"，0x080488fa realpath，0x0804891a setenv("CWD",...)（键 0x08048b9e）。
> 
> **来源**：`ev-000002` · `ref:a81b35b734`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://47[.]107[.]122[.]241:40002/` | 40002 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/tmp/log_de.log`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `47.107.122[.]241` | 是 | 静态 |
| `c2_port` | `40002` | 是 | 静态 |
| `c2_uri` | `GET /?a=l32&h=<host>&t=ws_&p=<port> HTTP/1.1` | 是 | 静态 |
| `user_agent` | `Mozilla/5.0 (Windows NT 6.1; rv:48.0) Gecko/20100101 Firefox/48.0` | 是 | 静态 |
| `marker_path` | `/tmp/log_de.log` | 是 | 静态 |
| `payload_xor_key` | `0x99` | 是 | 静态 |
| `memfd_name` | `a` | 是 | 静态 |
| `exec_argv0` | `[kworker/0:2]` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要断言最终载荷是勒索软件、挖矿或 DDoS：本次未取得第二阶段，只能确认加载器会下载并内存执行任意载荷。
- 不要声称已建立 C2 会话或收到远程指令：分析窗口内只有 connect 尝试且被网络隔离拒绝，没有请求/响应会话。
- 不要声称样本使用 AES/RSA 等强加密：载荷仅做单字节 XOR 0x99。
- 不要声称存在 Windows 注册表、服务或计划任务持久化：样本是 Linux ELF，未实现该类行为。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 分析环境无外网，C2 连接均被拒绝，未取得 HTTP 响应与第二阶段样本；XOR 解密、memfd 写入与 fexecve 执行路径由反编译/反汇编静态确认，未经端到端动态验证。
2. C2 字段虽有真实 connect 事件，但无成功会话，因此按静态恢复处理并标记待动态确认。
3. 样本为 32 位 i386 ELF，依赖 /lib/ld-linux.so.2；其他架构主机上的行为未验证。
4. 运行环境中 /etc/resolv.conf 缺失，gethostbyname 解析失败并回退 inet_addr，因此只确认了 IP 形式 C2，无法排除同源域名。
5. 单实例标记 /tmp/log_de.log 仅被检查存在性，样本本身未创建该文件，推测由第二阶段或投递链创建。

## 证据索引

<details>
<summary>展开 8 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 抽取 122 条 ASCII 字符串，定位 C2 IP、HTTP 信标格式、User-Agent、标记路径、memfd 名称与伪装进程名。 |
| `ev-000002` | decompile.ghidra | 反编译 main（0x080486e0），完整还原单实例检查、C2 连接、信标、XOR 解密与 memfd/fexecve 执行链。 |
| `ev-000010` | dyn.trace.strace | 动态观测 access("/tmp/log_de.log", F_OK) 返回 ENOENT。 |
| `ev-000015` | dyn.trace.strace | 动态观测 socket(AF_INET, SOCK_STREAM, IPPROTO_IP) 创建成功。 |
| `ev-000016` | dyn.trace.strace | 动态观测 connect 到 47.107.122[.]241:40002 返回 ENETUNREACH，随后 10 秒休眠重试。 |
| `ev-000017` | dyn.trace.strace | 动态观测第二次 connect 到 47.107.122[.]241:40002 仍返回 ENETUNREACH。 |
| `ref:c7bbb8697d` | disasm.function | main 反汇编：access/gethostbyname/socket/setsockopt/connect/sprintf/send/recv 调用点与常量 0x429c。 |
| `ref:a81b35b734` | disasm.function | main 后半段反汇编：syscall 0x164(memfd_create)、XOR 0x99 循环、write、realpath/setenv、argv[0]=[kworker/0:2]、fexecve。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
