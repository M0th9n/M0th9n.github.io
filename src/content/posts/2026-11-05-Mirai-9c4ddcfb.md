---
title: "恶意样本分析：Mirai（ELF · elf · 9c4ddcfb）"
published: 2026-11-05
draft: false
description: "恶意（置信度高）：Mirai · botnet/backdoor · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Mirai", "botnet", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Mirai** · 置信度 **高**
> 
> 别名：Mirai DDoS botnet、Mirai (SOCKS5 proxy variant)、2.0.4_socks5 build
> 
> 反编译确认 Mirai 系 DDoS/SOCKS5 后门逻辑：内置加密配置解密出动态域名 C2，主循环做注册与指令接收，守护化后启动 0.0.0[.]0:26721 的 SOCKS5 代理并执行 iptables 放行，另注册 15 种 TCP/UDP/GRE 洪泛向量；受控环境真实执行中观测到反调试立即退出、启动 SOCKS5 子进程（实参 0.0.0[.]0:26721/lucy_user/password_meow）以及经 shell 执行 iptables。网络隔离下未建立真实 C2 会话。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Mirai** · 别名 Mirai DDoS botnet、Mirai (SOCKS5 proxy variant)、2.0.4_socks5 build |
| 置信度 | **高** |
| 行为类 | botnet · backdoor |
| 难度 | medium |
| 首次出现 | 2026-11-02 01:20:19 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/9c4ddcfb0606a3f9ac5a67b53cf30276a61db873f346c1c2caf5da9c3eb272ad/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">检测调试即退出</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">识别虚拟机环境</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">解密内置配置</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">伪装进程并守护化</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">解析域名连接C2</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1568</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `9c4ddcfb0606a3f9ac5a67b53cf30276a61db873f346c1c2caf5da9c3eb272ad` |
| MD5 | _未记录_ |
| 大小 | 221,204 字节（216.0 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **11** 条行为，每条都挂了证据；其中 **10** 条静态可得、**1** 条经动态分析取得。

### 1. 检测调试即退出

`T1622` · 置信度 **高** · 动态

启动时先 ptrace(PTRACE_TRACEME) 自检，再读取 /proc/self/status 的 TracerPid；任一发现被调试立即 exit(0)，不产生任何网络行为。

> **证据**：_check_tracer@0x4021b0 ptrace(PTRACE_TRACEME)；_is_debugger_present@0x4027e0 解析 TracerPid；动态执行中 ptrace 返回 EPERM 后 exit(0)
> 
> **来源**：`ev-000010` · `ev-000059` · `ev-000013`

### 2. 识别虚拟机环境

`T1497.001` · 置信度 **高** · 静态

读取 /proc/cpuinfo、/proc/sys/kernel/osrelease 并调用 uname，匹配 vmware、vbox、qemu、kvm 等特征，命中即退出，规避分析环境。

> **证据**：_is_vm@0x4028e0 内联比较 "vmware"/"vbox"/"qemu"/"kvm"，数据位于 .rodata 0x41b380-0x41b3bd
> 
> **来源**：`ev-000007`

### 3. 解密内置配置

`T1027` · 置信度 **高** · 静态

运行时用 ChaCha20 逐项解密 18 个内置字符串，还原 C2 域名、SOCKS5 用户名/口令、进程名与 /proc 路径；密钥与 nonce 硬编码在 .data。

> **证据**：xor_init@0x404bf0 → xor_add@0x404b60 → chacha20_xor@0x404db0；密文表 0x1b57e、密钥 0x1e280、nonce 0x1e2a0
> 
> **来源**：`ev-000006` · `ev-000008` · `ev-000063`

### 4. 伪装进程并守护化

`T1036.005` · 置信度 **高** · 静态

改写 argv[0] 与 prctl(PR_SET_NAME) 为 "2.0.4_socks5"，随后 fork、setsid、关闭 0/1/2 并 chdir("/")，转入后台常驻。

> **证据**：main@0x400300：_strcpy(*argv, enc[2])、prctl(0xf, enc[2])、fork/setsid/close(0..2)/chdir；动态观测到两次 fork 后进入 SOCKS5 子进程
> 
> **来源**：`ev-000003` · `ev-000060`

### 5. 解析域名连接C2

`T1568` · 置信度 **高** · 静态

通过内置解析器查 bass1231488c2[.]hopto[.]org，取回 A 记录后连接 TCP/35342，使用 2 字节大端长度前缀的指令协议。

> **证据**：main@0x400300 lookup_domain(enc[3]) 与 srv_addr.sin_port 常量 0x0E8A（网络序 35342，指令 0x400ca4 写入 0x52d682）；动态观测到连续向 53/UDP 的解析尝试
> 
> **来源**：`ev-000003` · `ev-000018` · `ev-000063` · `ref:1a96c3b6c0`

### 6. 加密上报主机信息

`T1082` · 置信度 **高** · 静态

注册包以 0x00000004 开头，依次发送 "x86"、"2.0.4_socks5"，再用 ChaCha20 加密 CPU 核数、内存大小与主机标识 "aterna" 后发送。

> **证据**：main@0x400300 依次 send(4 字节魔数)、"x86"、进程名、chacha20_xor 后的 sysconf(_SC_NPROCESSORS_ONLN)/sysinfo 结果与 "aterna"；动态抓到对应 sendto 序列
> 
> **来源**：`ev-000003` · `ev-000019`

### 7. 开启SOCKS5后门

`T1090` · 置信度 **高** · 静态

另起子进程在 0.0.0[.]0:26721 监听 SOCKS5，使用固定用户名/口令认证，认证通过后对目标做 CONNECT 并双向转发流量，把受害主机变为代理出口。

> **证据**：socks5_server@0x403ba0 实参 0.0.0[.]0/0x6861/lucy_user/password_meow（动态断点读到 0.0.0[.]0:26721）；clientthread@0x403e00 实现用户名口令认证与 poll 转发
> 
> **来源**：`ev-000005` · `ev-000060` · `ev-000062`

### 8. 篡改防火墙放行

`T1562.004` · 置信度 **高** · 静态

以 system 连续执行 5 条 iptables 变体命令，向 INPUT 链追加 tcp/26721 ACCEPT，为代理端口开路。

> **证据**：socks5_server@0x403ba0 调用 system("iptables -A INPUT -p tcp --dport 26721 -j ACCEPT") 等 5 条；动态观测到随后 vfork/exec /usr/bin/dash
> 
> **来源**：`ev-000005` · `ev-000060`

### 9. 清除端口占用进程

`T1057, T1489` · 置信度 **高** · 静态

解析 /proc/net/tcp 找到监听 26721 的 socket inode，遍历 /proc/<pid>/exe 与 /proc/<pid>/fd/* 匹配该 inode，kill 掉占用端口的其他进程（保留父进程），以确保自己独占端口。

> **证据**：kill_port@0x4046b0 读 /proc/net/tcp 与 /proc/<pid>/fd，main 以 0x6168 调用（字节交换为 6861=26721）
> 
> **来源**：`ev-000004` · `ev-000003`

### 10. 发动多向量洪泛

`T1498` · 置信度 **高** · 静态

floods_init 注册 15 种攻击向量（udp_plain/udp_raw/udp_bypass/udp_openvpn/udp_raknet、tcp_ack/tcp_syn_data/tcp_stomp/tcp_handshake/tcp_bypass/tcp_wra/tcp_socket/tcp_sockethold、gre_ip 等），收到 C2 指令后 fork 洪泛进程并按指令持续攻击目标。

> **证据**：floods_init@0x403220 注册表；flood_parse@0x402c50 解析目标/端口/选项；flood_start@0x402eb0 fork 执行 flood_*（flood_udpraw@0x408e90、flood_greip@0x409220 等）
> 
> **来源**：`ev-000012` · `ev-000009` · `ev-000011`

### 11. 向代理面板报到

`T1071` · 置信度 **高** · 静态

代理服务启动后回连 212[.]118[.]43[.]167:2222，发送固定文本 "hi im here, i think" 做上线/可用性通报。

> **证据**：proxy_report@0x403b00：sockaddr 端口常量 0xAE08（2222）、地址常量 0xA72B76D4（212.118.43[.]167），strcpy "hi im here, i think" 后 send
> 
> **来源**：`ev-000061` · `ref:80c7e21c0e`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `bass1231488c2[.]hopto[.]org` | 35342 | c2 | 静态 | ⏳ 未观测 |
| tcp | `212[.]118[.]43[.]167` | 2222 | panel | 静态 | ⏳ 未观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `bass1231488c2[.]hopto[.]org` | 是 | 静态 |
| `c2_port` | `35342` | 是 | 静态 |
| `socks5_listen` | `0.0.0[.]0:26721` | 是 | 静态 |
| `socks5_user` | `lucy_user` | 是 | 静态 |
| `socks5_pass` | `password_meow` | 是 | 静态 |
| `proxy_report_endpoint` | `212[.]118[.]43[.]167:2222` | 是 | 静态 |
| `encryption_algo` | `ChaCha20（20 轮，32 字节密钥 + 12 字节 nonce，计数器从 1 开始；用于内置字符串与注册字段）` | 是 | 静态 |
| `bot_source_id` | `aterna` | 是 | 静态 |
| `process_name` | `2.0.4_socks5` | 是 | 静态 |
| `campaign_id` | `aterna/2.0.4_socks5` | 否 | 静态 |
| `dns_resolvers` | `8.8.8[.]8, 51.254.162[.]59, 51.77.149[.]139, 194.36.144[.]87, 195.10.195[.]195, 94.16.114[.]254（内置解析服务器列表，均为公共 DNS，非攻击者独有）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不可判定为勒索/擦除类：未发现文件加密、勒索信或磁盘破坏代码；ChaCha20 仅用于字符串与注册字段加密。
- 不可判定为窃密木马：未发现浏览器凭据、文件收集或批量外传逻辑。
- 不可声称存在注册表/服务/计划任务持久化：样本为 Linux ELF，无相关 API 与路径。
- 不可声称已观测到与真实 C2 的完整会话：分析网络被隔离，仅观测到域名解析尝试与注册包构造/发送失败。
- 不可判定为下载器/投放器：未发现下载或执行二阶段载荷的代码路径。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. C2 域名/端口与代理面板地址均由内置 ChaCha20 配置与硬编码常量静态恢复，未能在真实网络中完成回连验证（pending_dynamic_verify）。
2. 守护路径的动态观测需要跳过 ptrace 反调试检查；SOCKS5 监听与 iptables 规则在隔离环境中的实际生效情况未验证。
3. 15 种洪泛向量只做了代码级确认，未对任何真实目标发起攻击。
4. 家族谱系可确认为 Mirai 系，但精确变体命名缺少厂商命名佐证。
5. 样本参数解析使用自实现的字符串比较（相等返回 1），导致 --debug 分支实际不可用；仅能通过传入其他参数进入调试分支，这是本样本的行为特征而非分析缺陷。

## 证据索引

<details>
<summary>展开 20 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000003` | 静态反编译 | main@0x400300：反调试/反虚拟机、配置解密、C2 注册与指令循环、守护化与 SOCKS5 子进程 |
| `ev-000004` | 静态反编译 | kill_port@0x4046b0：/proc/net/tcp 定位 26721 监听进程并 kill |
| `ev-000005` | 静态反编译 | socks5_server@0x403ba0：iptables 放行 26721、固定账号口令、线程化代理服务 |
| `ev-000006` | 静态反编译 | xor_init@0x404bf0：18 项内置加密字符串的索引与长度表 |
| `ev-000007` | 静态反编译 | _is_vm@0x4028e0：/proc/cpuinfo、osrelease、uname 的虚拟机特征匹配 |
| `ev-000008` | 静态反编译 | xor_add@0x404b60：ChaCha20 解密单个字符串 |
| `ev-000009` | 静态反编译 | flood_parse@0x402c50：C2 攻击指令字段解析 |
| `ev-000010` | 静态反编译 | _check_tracer@0x4021b0：ptrace(PTRACE_TRACEME) 反调试 |
| `ev-000011` | 静态反编译 | flood_start@0x402eb0：按向量 fork 攻击进程并下发 20 余项参数 |
| `ev-000012` | 静态反编译 | floods_init@0x403220：注册 15 种 DDoS 洪泛向量 |
| `ev-000013` | 动态执行观测 | 真实执行：ptrace(PTRACE_TRACEME) 返回 EPERM 后 exit(0)，反调试生效 |
| `ev-000018` | 动态执行观测 | 真实执行：输出 fortnite，连续向多个 DNS 服务器 53/UDP 发起解析请求 |
| `ev-000019` | 系统调用监控 | 真实执行：execve ./prog x，随后 socket/connect(DNS)/write(fortnite) 等 |
| `ev-000059` | 静态反编译 | _is_debugger_present@0x4027e0：读取 /proc/self/status 的 TracerPid |
| `ev-000060` | 调试器观测 | 跳过反调试后观测 SOCKS5 实参 0.0.0[.]0:26721/lucy_user/password_meow，随后 vfork 执行 /usr/bin/dash |
| `ev-000061` | 静态反编译 | proxy_report@0x403b00：回连 212.118.43[.]167:2222 发送 "hi im here, i think" |
| `ev-000062` | 静态反编译 | clientthread@0x403e00：SOCKS5 认证、CONNECT 与双向转发 |
| `ev-000063` | 脚本还原 | ChaCha20 解密内置字符串表：C2 域名、SOCKS5 账号口令、进程名与 /proc 路径 |
| `ref:cd428945ec` | 符号表解析 | 1448 个符号、933 个函数，暴露 Mirai 源文件与攻击函数名 |
| `ref:bee2691cad` | 哈希计算 | md5 abe3e6ae7d1bb3519448d07cc04036bc；sha1 d066876b10b9160c70b6fb9ced4e491f23a42632；sha256 与题面一致 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
