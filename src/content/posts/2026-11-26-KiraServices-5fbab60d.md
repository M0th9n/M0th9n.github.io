---
title: "恶意样本分析：KiraServices（ELF · elf · 5fbab60d）"
published: 2026-11-26
draft: false
description: "恶意（置信度中）：KiraServices · botnet/backdoor · 难度 hard · 静态反编译（动态执行未取得运行时行为）"
tags: ["KiraServices", "botnet", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **KiraServices**（存疑） · 置信度 **中**
> 
> 别名：Self Rep botnet、NeTiS botnet
> 
> 静态反编译与指令级分析显示该 ARM64 静态 ELF 具备完整的远控/僵尸网络能力：systemd、cron、init.d、rc.local 四重持久化，进程名伪装与反调试，ChaCha20 加密的自定义 TCP 任务通道，Discord 网关 WebSocket 指令通道，以及过滤私网后对公网地址发起连接的自动扩散逻辑。隔离执行时程序因非 root 身份立即静默退出，未捕获真实外联，但代码路径与字符串证据相互印证。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **KiraServices** · 别名 Self Rep botnet、NeTiS botnet · _存疑_ |
| 置信度 | **中** |
| 行为类 | botnet · backdoor |
| 难度 | hard |
| 首次出现 | 2026-11-24 12:40:53 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/5fbab60d9b176dbed720219cd4ea5f0ee65978c03114e62250f5de1186ddc2a8/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置字符串表</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">检测调试与注入环境</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">伪装为常见守护进程</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">安装 systemd 服务持久化</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">写入 cron 开机任务</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `5fbab60d9b176dbed720219cd4ea5f0ee65978c03114e62250f5de1186ddc2a8` |
| MD5 | _未记录_ |
| 大小 | 731,504 字节（714.4 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **11** 条行为，每条都挂了证据，且全部静态可得。

### 1. 解密内置字符串表

`T1027` · 置信度 **高** · 静态

内置按索引寻址的字符串表，逐字节与 4 字节密钥异或解密，解出 KIRASERVICES/SHOP/INSIDE/FEMBOY 等伪装用词；主流程在运行早期即调用该解密例程。

> **证据**：FUN_0040ddc0 @0x40ddc0 异或解密循环；字符串表 0x4c2568，密钥表 0x4c08f0；密文 0x47a580 以密钥 0x1a 解出 KIRASERVICES
> 
> **来源**：`ref:cc2b0b2c55`

### 2. 检测调试与注入环境

`T1622` · 置信度 **高** · 静态

读取 /proc/self/status 的 TracerPid 并调用 ptrace(PTRACE_TRACEME) 自检，同时检查 LD_PRELOAD、LD_AUDIT、GDB、STRACE 环境变量，命中则改变执行路径。

> **证据**：0x40dc4c 引用 /proc/self/status 并比较 TracerPid；0x40dd58/0x40dd80/0x40dd90/0x40dda0 引用 LD_PRELOAD/LD_AUDIT/GDB/STRACE；0x42e820 调 ptrace
> 
> **来源**：`ref:62c85bd54c` · `ref:4e6108fb92`

### 3. 伪装为常见守护进程

`T1036.005` · 置信度 **高** · 静态

内置 httpd/nginx/apache/lighttpd/sshd/telnetd/uhttpd/mini_httpd/dropbear/systemd/kthreadd/kswapd/kworker 等名称列表，并结合 /proc/<pid>/cmdline 扫描，用于进程名伪装或压制同类进程。

> **证据**：0x47a3e0~0x47a4a0 进程名列表；0x499624 /proc/%d/cmdline；0x47a310 字符集用于生成随机名
> 
> **来源**：`ref:62c85bd54c` · `ref:4e6108fb92`

### 4. 安装 systemd 服务持久化

`T1543.002` · 置信度 **高** · 静态

向 /etc/systemd/system/%s.service 写入 [Unit]/[Service] 模板（ExecStart=自身路径、Restart=always、WantedBy=multi-user.target），随后执行 systemctl enable %s.service。

> **证据**：0x47a090 /etc/systemd/system；0x47a0a8 /etc/systemd/system/%s.service；0x40c5e0~0x40c7a0 拼装与写入；0x47a158 systemctl enable
> 
> **来源**：`ref:4e6108fb92` · `ref:62c85bd54c`

### 5. 写入 cron 开机任务

`T1053.003` · 置信度 **高** · 静态

执行 crontab -l 读取现有任务后，追加 '@reboot <自身路径> &' 并写回，实现重启后自启动。

> **证据**：0x47a1e0 crontab -l 2>/dev/null；0x47a1f8 (crontab -l 2>/dev/null; echo '@reboot %s &') | crontab -；0x40c870~0x40c8d0
> 
> **来源**：`ref:4e6108fb92` · `ref:62c85bd54c`

### 6. 布置 init.d 与 rc.local

`T1037.004` · 置信度 **高** · 静态

生成 /etc/init.d/%s 启停脚本（含 BEGIN INIT INFO 头）并向 /etc/rc.local 追加自启动命令，覆盖无 systemd 的环境。

> **证据**：0x47a238 /etc/init.d、0x47a248 /etc/init.d/%s、0x47a350 /etc/rc.local；0x40c8e0~0x40caa0
> 
> **来源**：`ref:4e6108fb92` · `ref:62c85bd54c`

### 7. 枚举公网地址自助传播

`T1595.001` · 置信度 **中** · 静态

从内置地址表随机取址，过滤 127/8、10/8、172.16/12、192.168/16、100.64/10、169.254/16 等私网与保留段，仅对公网地址建立 TCP 连接并发送 16 字节握手包，具备蠕虫式扩散特征。

> **证据**：FUN_0040b9d0 @0x40b9d0 选址；FUN_0040b860 @0x40b860 私网/保留段判定；0x40af00 socket、0x40af38 connect、0x40af54 send；端口常量 0xDD19
> 
> **来源**：`ref:067e854d5d`

### 8. 加密任务通道

`T1573.001` · 置信度 **高** · 静态

在 TCP 会话中使用 ChaCha20（'expand 32-byte k' 常量、20 轮、ror 16/12/8/7）加解密任务负载；接收端先校验 4 字节魔数 0xD12C8F4A，再按 2 字节长度读取密文并解密分发。

> **证据**：0x481290 'expand 32-byte k'；FUN_0040b020 @0x40b020 初始化；FUN_0040b0b0 @0x40b0b0 流加密；主循环比较 0xD12C8F4A
> 
> **来源**：`ref:8bc013f2e4` · `ev-000005`

### 9. Discord 网关指令通道

`T1102.002` · 置信度 **中** · 静态

内置完整 Discord Gateway WebSocket 握手模板（GET /?v=9&encoding=json、Host: gateway[.]discord[.]gg、Upgrade: websocket、Sec-WebSocket-Key/Version）及浏览器 User-Agent 池，表明以第三方即时通讯服务承载指令通道。

> **证据**：0x4793e8 GET /?v=9&encoding=json HTTP/1.1；0x47940a Host: gateway[.]discord[.]gg；0x4796a8 Sec-WebSocket-Key；0x479360~0x479420 UA 池
> 
> **来源**：`ref:62c85bd54c`

### 10. 采集主机指纹

`T1082` · 置信度 **高** · 静态

读取 /proc/cpuinfo 解析 'cpu cores'、读取 /proc/mounts 与 /proc/<pid>/cmdline、取主机名，并把结果随握手包上报，用于受害者画像与目标筛选。

> **证据**：0x47a590 /proc/cpuinfo、0x499680 cpu cores、0x47a5a0 /proc/mounts、0x499624 /proc/%d/cmdline；主函数在握手后读取并上报
> 
> **来源**：`ref:62c85bd54c` · `ev-000005`

### 11. 强制 root 身份运行

`T1078.003` · 置信度 **中** · 静态

启动时要求 getuid==0，非 root 环境下初始化失败即静默返回，体现其面向嵌入式设备/服务器 root 权限的部署前提。

> **证据**：FUN_004005f0 @0x4005f0 起始调用 FUN_0042b0a0（getuid 类）并要求返回 0；隔离执行以 uid 1000 运行时 exit=0 且无输出
> 
> **来源**：`ev-000005` · `ev-000006`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `runtime-selected public IPv4 from encrypted bootstrap list (private/loopback ranges filtered)` | 6621 | c2 | 静态 | ⏳ 未观测 |
| http | `gateway[.]discord[.]gg` | 80 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/etc/systemd/system/%s.service`
- `/etc/init.d/%s`
- `/etc/rc.local`
- `/dev/shm/`
- `/var/tmp/`
- `/var/run/`
- `/usr/local/bin/`

**服务**

- `<name>.service (systemd, ExecStart=<self>, Restart=always, WantedBy=multi-user.target)`

**计划任务**

- `@reboot <self> & (crontab)`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `encrypted IPv4 bootstrap list, decrypted at runtime; only public addresses selected` | 是 | 静态 |
| `c2_port` | `6621 (0x19DD)` | 是 | 静态 |
| `protocol` | `TCP: 16-byte handshake, 4-byte magic 0xD12C8F4A, 2-byte length, ChaCha20-encrypted payload` | 是 | 静态 |
| `encryption_algo` | `ChaCha20 (20 rounds, 'expand 32-byte k')` | 是 | 静态 |
| `discord_gateway` | `gateway[.]discord[.]gg` | 否 | 静态 |
| `persistence_mechanisms` | `systemd service, crontab @reboot, /etc/init.d script, /etc/rc.local` | 是 | 静态 |
| `masquerade_names` | `httpd,nginx,apache,lighttpd,sshd,telnetd,uhttpd,mini_httpd,dropbear,systemd,kthreadd,ksoftirqd,kswapd,kworker` | 否 | 静态 |
| `campaign_id` | `KIRASERVICES` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要判定为勒索软件：ChaCha20 仅用于字符串与 C2 通道加密，未发现文件加密、扩展名改写或赎金说明。
- 不要断言已实际发生外联或 DDoS：受限环境无网络且非 root，程序启动即静默退出，未捕获连接、会话或攻击流量。
- 不要直接套用某一确定家族名：KiraServices 为由内嵌 campaign 串推导的候选命名，尚缺多引擎或 YARA 佐证。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 否 |

**局限与待验证**

1. 隔离执行以非 root 用户运行，程序在完成 root 检查后直接退出（无输出、无网络事件），因此未取得运行时行为证据，全部结论基于静态反编译与指令级分析。
2. C2 地址来自运行时解密的 IPv4 列表，未能还原具体地址；端口 6621 由 sockaddr 写入指令推导，存在字节序解释误差的可能。
3. Discord 网关仅为静态字符串证据，未见 bot token 或频道 ID 明文，无法确证该通道在本次样本中实际启用。
4. 未取得厂商引擎或 YARA 命中，家族命名按内嵌 campaign 串暂定，需外部情报复核。

## 证据索引

<details>
<summary>展开 9 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000004` | 字符串提取 | 抽取 1419 条 ASCII 字符串，命中 Discord 网关握手模板、HTTP 客户端模板、systemd/cron/init.d/rc.local 持久化模板、进程名列表与反调试关键字 |
| `ev-000005` | decompile.ghidra | 反编译主函数 FUN_004005f0：root 检查、socket/select 主循环、ChaCha20 解密与命令分发 |
| `ev-000006` | emu.qemu | ARM64 隔离仿真执行，exit=0、无 stdout/stderr，印证非 root 静默退出 |
| `ref:015d4e8403` | ELF 结构解析 | AARCH64 EXEC、静态链接、entry=0x401100、无 interp/DT_NEEDED |
| `ref:ce9e2566b8` | elf.sections | .text 495KB 熵 6.53，.rodata 116KB 熵 4.57，无加壳特征 |
| `ref:4e6108fb92` | disasm.refs | 指令级引用映射：持久化模板、/proc/self/status、LD_PRELOAD/LD_AUDIT/GDB/STRACE 引用地址 |
| `ref:8bc013f2e4` | scan.rodata | 0x481290 处 'expand 32-byte k' 与 0x481560 的 32 字节密钥，确认 ChaCha20 |
| `ref:067e854d5d` | disasm.range | 0x40b860 私网/保留段过滤与 0x40af00 起 socket/connect/send 扩散逻辑 |
| `ref:cc2b0b2c55` | script.xor | 对 0x47a580 密文做单字节异或求解，密钥 0x1a 解出 KIRASERVICES/SHOP/INSIDE/FEMBOY 等词 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
