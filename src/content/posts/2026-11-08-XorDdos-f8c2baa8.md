---
title: "恶意样本分析：XorDdos（ELF · elf · f8c2baa8）"
published: 2026-11-08
draft: false
description: "恶意（置信度中）：XorDdos · downloader/loader/backdoor · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["XorDdos", "downloader", "loader", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **XorDdos**（存疑） · 置信度 **中**
> 
> 别名：XOR.DDoS、Linux.XorDdos、ELF/XorDdos
> 
> 反编译与反汇编显示该程序是只做 TCP 上线、接收 XOR(0x99) 加密载荷、写入内存文件并 fexecve 直接执行的下载器/加载器；在隔离环境中真实运行观测到其反复连接 124.222.69[.]132:8085（网络不可达时每 10 秒重试），属已实现并可复现的恶意 C2 通信与远程代码执行准备行为。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **XorDdos** · 别名 XOR.DDoS、Linux.XorDdos、ELF/XorDdos · _存疑_ |
| 置信度 | **中** |
| 行为类 | downloader · loader · backdoor |
| 难度 | medium |
| 首次出现 | 2026-11-07 01:40:21 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">探测标记文件</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">连接C2并重试</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">发送l64指纹</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">异或解密载荷</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">内存文件执行</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `f8c2baa82c618ced9c42990f9379df137e9577b93933384463cb8ad7c4693feb` |
| MD5 | _未记录_ |
| 大小 | 9,800 字节（9.6 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **6** 条行为，每条都挂了证据；其中 **4** 条静态可得、**2** 条经动态分析取得。

### 1. 探测标记文件

`T1480` · 置信度 **高** · 动态

启动时调用 access("/tmp/log_de.log", F_OK)；文件存在则 exit(0)，不存在才继续执行后续上线逻辑。

> **证据**：0x400967 call access("/tmp/log_de.log",0)；0x40096e 条件跳转后 0x400972 call exit(0)；动态追踪见 access 返回 ENOENT
> 
> **来源**：`ev-000015` · `ev-000007`

### 2. 连接C2并重试

`T1095` · 置信度 **高** · 动态

解析/填入 124.222.69[.]132，socket(AF_INET,SOCK_STREAM,0) 后设置 TCP_SYNCNT=10，连接 8085 端口；connect 失败则 sleep(10) 无限重试。

> **证据**：0x400a1b call connect；0x400a29 call sleep(10)；动态事件 connect(sin_port=htons(8085), sin_addr=124.222.69[.]132)=-1 ENETUNREACH，随后 clock_nanosleep 10s 再重试
> 
> **来源**：`ev-000013` · `ev-000015`

### 3. 发送l64指纹

`T1095` · 置信度 **高** · 静态

连接成功后依次发送 6 字节 "l64 "、2 字节网络序端口(0x1f 0x95，即 8085)、32 字节含 C2 IP 字符串的缓冲区，作为上线握手/标识。

> **证据**：0x400a3e call send(fd,"l64 ",6)；0x400a62 发送端口两字节；0x400a75 发送 0x20 字节缓冲区
> 
> **来源**：`ev-000015` · `ev-000001`

### 4. 异或解密载荷

`T1140` · 置信度 **高** · 静态

循环 recv 最多 0x1000 字节，对收到的每个字节执行 XOR 0x99 得到明文载荷。

> **证据**：0x400abd xor byte ptr [rax],0x99 的逐字节循环；反编译可见 *pbVar7 = *pbVar7 ^ 0x99
> 
> **来源**：`ev-000015`

### 5. 内存文件执行

`T1620` · 置信度 **高** · 静态

syscall(319, "a", 0) 创建 memfd，将解密后的载荷 write 入该匿名文件，最后 fexecve 直接在内存中执行，不落地磁盘。

> **证据**：0x400a88 mov edi,0x13f; call syscall => memfd_create("a",0)；0x400ad4 call write(memfd, buf, len)；0x400b37 call fexecve
> 
> **来源**：`ev-000015`

### 6. 伪装内核线程

`T1036.005` · 置信度 **高** · 静态

执行载荷前用 realpath(argv[0]) 取得自身路径并 setenv("CWD", 路径, 1)，同时把 argv[0] 设为 "[kworker/0:2]"，伪装成内核工作线程。

> **证据**：0x400af9 call realpath；0x400b0f call setenv("CWD",...)；0x400b25 载入 0x400cf1 处的 "[kworker/0:2]" 作为 argv[0]
> 
> **来源**：`ev-000015` · `ev-000001`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `124.222.69[.]132` | 8085 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/tmp/log_de.log`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `124.222.69[.]132` | 是 | 静态 |
| `c2_port` | `8085` | 是 | 静态 |
| `transport` | `raw TCP (AF_INET/SOCK_STREAM), setsockopt IPPROTO_TCP/TCP_SYNCNT=10, 10s reconnect interval` | 是 | 静态 |
| `handshake` | `6-byte banner 'l64 ' + 2-byte network-order port + 32-byte buffer containing the C2 IP string` | 是 | 静态 |
| `encryption_algo` | `single-byte XOR 0x99 applied to received payload` | 是 | 静态 |
| `memfd_name` | `a` | 是 | 静态 |
| `argv0_masquerade` | `[kworker/0:2]` | 是 | 静态 |
| `env_var` | `CWD=<realpath of the sample>` | 否 | 静态 |
| `marker_path` | `/tmp/log_de.log` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要断言样本已成功连接 C2 或已下载二阶段载荷：隔离环境仅观测到 connect 尝试与 ENETUNREACH，没有请求/响应会话。
- 不要断言存在持久化机制：未观察到 systemd、cron、rc 脚本、服务或计划任务写入。
- 不要将其归类为 ransomware、wiper 或 miner：代码中没有文件加密、删除或挖矿相关逻辑与常量。
- 不要把 /tmp/log_de.log 描述为样本写入的日志或配置：样本只做存在性检查，存在时直接退出。
- 不要把 argv[0] "[kworker/0:2]" 当成真实内核线程或真实进程名。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 动态运行处于网络隔离环境，connect 均返回 ENETUNREACH，未建立 C2 会话，协议细节与二阶段载荷只能静态恢复，故 C2 标记为 static 且 pending_dynamic_verify。
2. 未取得被投递的二阶段 ELF，无法确认其最终能力（DDoS、后门或其他）。
3. 家族归属依据代码特征（XOR 0x99、memfd+fexecve、[kworker/0:2] 伪装、l64 握手）与公开 XorDdos 特征一致，但缺少 YARA/多引擎签名佐证，属候选结论。
4. 运行约 20 秒后因超时被终止，未观察到长期行为；未观察到 /tmp/log_de.log 被创建或持久化写入。
5. 静态分析基于单个 main 函数与 CRT 桩代码，未发现其他业务函数或额外的隐藏配置。

## 证据索引

<details>
<summary>展开 6 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | static.strings | 抽取到 "/tmp/log_de.log"、"l64 "、"CWD"、"[kworker/0:2]"、"124.222.69[.]132" 等关键字符串 |
| `ev-000007` | dynamic.syscall_trace | access("/tmp/log_de.log", F_OK) 返回 -1 ENOENT |
| `ev-000012` | dynamic.syscall_trace | socket(AF_INET, SOCK_STREAM, IPPROTO_IP) 返回 3 |
| `ev-000013` | dynamic.syscall_trace | connect 到 124.222.69[.]132:8085 返回 ENETUNREACH |
| `ev-000014` | dynamic.syscall_trace | 10 秒后再次 connect 同一 C2，仍返回 ENETUNREACH |
| `ev-000015` | static.decompile | main 反编译：标记检查 -> 解析/连接 C2 -> 重试 -> 发送 l64 握手 -> recv 并 XOR 0x99 -> memfd -> fexecve("[kworker/0:2]") |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
