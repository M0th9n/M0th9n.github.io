---
title: "恶意样本分析：EasyShell（ELF · elf · 2c5acece）"
published: 2026-11-23
draft: false
description: "恶意（置信度高）：EasyShell · rat/backdoor/implant · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["EasyShell", "rat", "backdoor", "implant", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **EasyShell** · 置信度 **高**
> 
> 别名：easyshell-http-beacon-implant、ESCH
> 
> 样本是可执行的 Linux/aarch64 Rust HTTP beacon：内置明文 C2 地址与 32 字节密钥，具备远程 Shell、SOCKS 隧道、文件传输、截屏、内存加载 ELF 插件与反虚拟机能力；在加固隔离实例中真实运行后观测到对 C2 的 HTTPS 连接尝试、/etc/passwd 读取和进程名伪装，恶意意图明确。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **EasyShell** · 别名 easyshell-http-beacon-implant、ESCH |
| 置信度 | **高** |
| 行为类 | rat · backdoor · implant |
| 难度 | medium |
| 首次出现 | 2026-11-23 07:37:09 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/2c5acecebf16c6f00435c6bbd08afcc04936c5cd6291a8ed2987c5e05e667409/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">回连HTTPS C2</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">伪装内核线程名</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">枚举本地账户</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1087.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">探测网络配置</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1016</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">反虚拟机检查</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `2c5acecebf16c6f00435c6bbd08afcc04936c5cd6291a8ed2987c5e05e667409` |
| MD5 | _未记录_ |
| 大小 | 3,755,152 字节（3.6 MB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **12** 条行为，每条都挂了证据；其中 **8** 条静态可得、**4** 条经动态分析取得。

### 1. 回连HTTPS C2

`T1071.001` · 置信度 **高** · 动态

启动后创建 IPv4 TCP socket，并向 192[.]3[.]31[.]148 的 8443 端口发起 HTTPS 回连，使用 /api/v2/sync 通道收发指令；网络隔离环境下该连接返回 ENETUNREACH。

> **证据**：strace connect(fd, {sin_port=htons(8443), sin_addr=inet_addr("192.3.31[.]148")}) = -1 ENETUNREACH；文件偏移 0x2036e2 的 URL 常量；0x41352c 处代码加载该地址
> 
> **来源**：`ref:0bd4c01627` · `ref:90c5406615` · `ref:6ec6eec48e`

### 2. 伪装内核线程名

`T1036.005` · 置信度 **高** · 动态

通过 prctl(PR_SET_NAME) 把运行线程名改为 [watchdog/0] 一类内核线程样式，并内置 [kworker/0:0]、[rcu_sched]、[migration/0] 等伪装名模板，降低在进程列表中的辨识度。

> **证据**：strace prctl(PR_SET_NAME, "[watchdog/0]") = 0；字符串区含 [kworker/0:0]、[rcu_sched]、[watchdog/1] 等伪装名
> 
> **来源**：`ref:0bd4c01627` · `ref:76901a8fcf`

### 3. 枚举本地账户

`T1087.001` · 置信度 **高** · 动态

打开 /etc/passwd 并连续读取，用于收集本地账户名、UID、家目录与登录 Shell 等身份信息。

> **证据**：strace openat("/etc/passwd") = 4；read(...) 返回 1024/507 字节，内容为 passwd 行
> 
> **来源**：`ref:0bd4c01627`

### 4. 探测网络配置

`T1016` · 置信度 **高** · 动态

两次打开 NETLINK_ROUTE 原始套接字，读取网卡、地址与路由信息（rtm_family/ifi_family/rtm_type 等 netlink 属性），用于内网定位与后续横向。

> **证据**：strace socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) 两次；.rodata 含 rtm_family/ifa_family/rtm_type 等 neli 属性名
> 
> **来源**：`ref:0bd4c01627` · `ref:a5aabbf0e3`

### 5. 反虚拟机检查

`T1497.001` · 置信度 **高** · 静态

读取 /sys/class/dmi/id/{product_name,sys_vendor,board_vendor}、/proc/xen 与 systemd 虚拟化标记，并匹配 vmware/virtualbox/qemu/kvm/xen/hyper-v/parallels/bhyve/proxmox 等厂商串；同时检查 cgroup CPU 配额和 CPU 型号，用于识别分析环境。

> **证据**：文件偏移 0x2038xx 起含 /sys/class/dmi/id/product_name 等路径与 vmware/virtualbox/qemu/kvm/xen/hyper-v 常量；字符串 "SYSTEMD_VIRTUALIZATION"、"hypervisor"、"cpu.cfs_quota_us"
> 
> **来源**：`ref:c4f3f083ba` · `ref:76901a8fcf`

### 6. 远程执行Shell

`T1059.004` · 置信度 **高** · 静态

内置交互式与非交互式 Shell：用 /bin/bash --rcfile 启动并清理 HISTFILE/HISTSIZE，支持 PTY、批量命令与执行超时，接收服务端下发的命令并回传输出。

> **证据**：字符串 /bin/bash、--rcfile、export HISTFILE=/dev/null HISTSIZE=500、ES_SHELL_BATCH_MS、interactive-1..4、ConPTY 提示；crates/impl-core/src/plugin_exec/unix.rs
> 
> **来源**：`ref:76901a8fcf` · `ref:a5aabbf0e3`

### 7. 架设SOCKS隧道

`T1090` · 置信度 **高** · 静态

实现 SOCKS5 代理、端口转发、反向监听与多路复用隧道（es-socks-/es-pump-tcp/es-mux-agg/es-dns/es-idle-reaper），可把受害主机变为进入内网的跳板。

> **证据**：crates/impl-core/src/socks_tunnel/{mod,backward_listen,mux,codec,hop_relay}.rs；字符串 es-socks-、es-pump-tcp、LISTEN/FORWARD/BIND、backward-listen-1
> 
> **来源**：`ref:a5aabbf0e3` · `ref:76901a8fcf`

### 8. 文件上传下载

`T1105` · 置信度 **高** · 静态

提供 upload/download 工作线程与断点续传/暂停/恢复能力，并支持 cp/mv/mkdir/rm 等文件操作，结果经 C2 通道回传。

> **证据**：crates/impl-core/src/download_xfer.rs、upload_worker.rs；字符串 [+] Downloading、download resume offset beyond file size、cp:/mv: bad args、Mkdir failed
> 
> **来源**：`ref:a5aabbf0e3` · `ref:76901a8fcf`

### 9. 截屏与鼠标控制

`T1113` · 置信度 **高** · 静态

采集屏幕画面并读取 /dev/input/mice 与 DISPLAY/WAYLAND_DISPLAY，支持鼠标控制、屏幕参数上报（screenW/screenH）。

> **证据**：XOR 0x5A 解码得 screen capture/screenshot/screen control；字符串 /dev/input/mice、{"screenW":1,"screenH":1}、mouseMs/mousePx
> 
> **来源**：`ref:c26c8969f0` · `ref:76901a8fcf`

### 10. 内存加载ELF插件

`T1620` · 置信度 **中** · 静态

将服务端下发的原生 ELF 载荷放入隔离子进程执行，并读取 /proc/self/maps 与 /proc/sys/vm/mmap_min_addr 为内存映射做准备；非原生可执行载荷会被拒绝。

> **证据**：XOR 0x5A 解码得 "payload is not a native executable"、"spawning native binary in isolated child"；动态读取 /proc/self/maps、/proc/sys/vm/mmap_min_addr
> 
> **来源**：`ref:c26c8969f0` · `ref:0bd4c01627`

### 11. 自删除与字符串混淆

`T1070.004` · 置信度 **中** · 静态

支持 delete-self 动作删除自身文件，并对通信字段做 XOR 0x5A 与替换表（!ES/7/SBOX/）混淆，增加静态取证难度。

> **证据**：字符串 delete-self-1；XOR 0x5A 可把 )9(??4z954.(56 解为 screen control；.rodata 含 !ES/7/SBOX/ 标签
> 
> **来源**：`ref:76901a8fcf` · `ref:c26c8969f0`

### 12. AES加密通信

`T1573.001` · 置信度 **中** · 静态

使用 AES crate 与 32 字节 base64 密钥/标准 base64 对 C2 载荷加解密，并以 HTTPS 承载，降低流量可读性。

> **证据**：aes-0.8.4 源码路径、SHA-256 与 base64 常量；文件偏移 0x203762 的 44 字符 base64 密钥可解码为 32 字节
> 
> **来源**：`ref:0b33798ecf` · `ref:168df48565` · `ref:0c5fc7be6a`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://192[.]3[.]31[.]148:8443/api/v2/sync` | 8443 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/tmp/.<random>.lk`
- `/dev/input/mice`
- `/sys/class/dmi/id/product_name`
- `/sys/class/dmi/id/sys_vendor`
- `/sys/class/dmi/id/board_vendor`
- `/proc/self/maps`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `192[.]3[.]31[.]148` | 是 | 静态 |
| `c2_port` | `8443` | 是 | 静态 |
| `c2_uri` | `/api/v2/sync` | 是 | 静态 |
| `encryption_key` | `LY6nDGIwrDlZZrvHtRseg+IWBrJuvbT6LFHEUM7I3lo=` | 是 | 静态 |
| `encryption_algo` | `AES（aes 0.8.4 crate；base64 解码后为 32 字节密钥，具体分组模式未由运行流量确认）` | 是 | 静态 |
| `client_id` | `es-beacon-drain` | 是 | 静态 |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0[.]0 Safari/537.36` | 否 | 静态 |
| `http_header_keys` | `client-id / Client-Id / X-Client-Id；Content-Type 可为 application/octet-stream 或 application/json` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能断言已成功建立 C2 会话或回传数据：动态执行时网络被隔离，connect 返回 ENETUNREACH，未观测到任何请求/响应或上传事件。
- 不能断言存在持久化：未见 systemd、cron、rc.local 或自启动写入的证据，动态仅观察到 /tmp 下的临时锁文件。
- 不能把它归类为勒索、挖矿或纯窃密软件：未发现文件加密、矿池协议或浏览器凭据读取行为，其核心是远程控制。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 动态通道网络隔离，C2 仅观测到 connect 尝试（ENETUNREACH）；配置与 C2 均按静态恢复处理并标记待动态验证。
2. 未取得服务端下发的 sleep/jitter 数值与具体指令；相关能力由字符串、源码路径与代码引用推断。
3. 反虚拟机判定的实际返回值及其后续分支未动态确认。
4. 跨架构用户态执行与原生机器的系统调用时序可能存在差异。
5. 未观测到内存插件加载、截屏、SOCKS 隧道等需要服务端指令才会触发的行为。
6. 未发现持久化机制，不能排除由外部加载器负责驻留的可能。

## 证据索引

<details>
<summary>展开 15 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:c921f466ea` | ELF 结构解析 | ELF 结构：aarch64、静态链接、已剥离、入口 RVA 0xA278 |
| `ref:dd77520dfa` | 字符串提取 | 字符串与 flag 正则扫描 |
| `ref:320b788f71` | strings/grep | 命中 crates/easyshell-http-beacon-implant 源码路径与 C2 常量 |
| `ref:90c5406615` | script | 定位 /api/v2/sync、C2 URL、密钥、client_id 的文件偏移 |
| `ref:0c5fc7be6a` | script | 转储配置区固定长度字段 |
| `ref:cfd776e658` | script | 扫描 ARM64 adrp/add，定位 0x41352c 等配置引用点 |
| `ref:6ec6eec48e` | disasm.function | 0x41352c 处加载 C2 URL/密钥/路径常量 |
| `ref:3d0009fc78` | disasm.function | 0x40ea00 处从 0x603691 拷贝 15 字节 es-beacon-drain |
| `ref:76901a8fcf` | script | 转储动作/协议字符串区（delete-self、interactive shell、socks、upload/download） |
| `ref:c4f3f083ba` | strings/grep | 反虚拟机路径与厂商串 |
| `ref:c26c8969f0` | script | XOR 0x5A 解出 screenshot/screen control/native executable 等明文 |
| `ref:0b33798ecf` | 密码学常量识别 | SHA-256 与标准 base64 常量 |
| `ref:168df48565` | script | base64 密钥解码为 32 字节 |
| `ref:2cc820e886` | dyn.exec | 隔离实例真实运行，25 秒超时，多线程/定时器活动 |
| `ref:0bd4c01627` | dyn.trace | 系统调用追踪：connect 192.3.31[.]148:8443 ENETUNREACH、/etc/passwd、NETLINK_ROUTE、prctl 改名 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
