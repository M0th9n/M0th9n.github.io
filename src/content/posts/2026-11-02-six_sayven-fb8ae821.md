---
title: "恶意样本分析：six_sayven（ELF · elf · fb8ae821）"
published: 2026-11-02
draft: false
description: "恶意（置信度低）：six_sayven · botnet/backdoor · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["six_sayven", "botnet", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **six_sayven**（存疑） · 置信度 **低**
> 
> 别名：Hajime-like DHT/DoH P2P botnet
> 
> 静态结构为静态链接、已剥离符号的 32 位大端 MIPS ELF，内含 DoH/DHT/Ed25519/Salsa20 与 /bin/sh、看门狗设备、原始套接字等能力；在隔离的加固实例中经 qemu-user 真机执行，直接观测到 prctl 改名、访问 /dev/watchdog、请求 RAW 套接字、连接 8.8.8[.]8:53、创建抽象 UNIX 套接字 six_sayven-63464 并连接 127.0.0[.]1:63464 等行为，属于可在 IoT 设备上驻留的 P2P 僵尸网络程序。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **six_sayven** · 别名 Hajime-like DHT/DoH P2P botnet · _存疑_ |
| 置信度 | **低** |
| 行为类 | botnet · backdoor |
| 难度 | hard |
| 首次出现 | 2026-11-02 08:45:33 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/fb8ae821d6e1fe9fb1d34ccc505937a528b7ce2e9392745f89cc6d9c94d4351f/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">DoH引导寻址</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.004</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">DHT签名寻址</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">随机进程名伪装</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">关闭看门狗</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">创建原始套接字</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `fb8ae821d6e1fe9fb1d34ccc505937a528b7ce2e9392745f89cc6d9c94d4351f` |
| MD5 | _未记录_ |
| 大小 | 560,956 字节（547.8 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **11** 条行为，每条都挂了证据；其中 **5** 条静态可得、**6** 条经动态分析取得。

### 1. DoH引导寻址

`T1071.004` · 置信度 **中** · 静态

通过 HTTPS 向 cloudflare-dns[.]com / dns[.]google 发送 POST /dns-query（Accept: application/dns-message）的 DNS-over-HTTPS 请求，用于引导节点发现，绕过本地 DNS 监控。

> **证据**：.rodata 0x47de90 'cloudflare-dns[.]com'; 0x47dea4 'dns.google'; 0x47deb8 'POST /dns-query HTTP/1.1'
> 
> **来源**：`ev-000001` · `ref:ef87b3bba7`

### 2. DHT签名寻址

`T1571` · 置信度 **中** · 静态

使用 BitTorrent DHT（BEP5）报文 get_peers/put/ping 与 bencode 模板进行节点发现和指令分发，报文携带 64 字节 Ed25519 签名与 z-base32 编码的 info_hash。

> **证据**：.rodata 0x47e010 'd1:ad2:id20:'; 0x47e030 '3:seqi%llde3:sig64:'; 0x47e120 z-base32 字母表; 0x47e148 'SigEd25519 no Ed25519 collisions'
> 
> **来源**：`ev-000001` · `ev-000005`

### 3. 随机进程名伪装

`T1036` · 置信度 **高** · 动态

启动后调用 prctl(PR_SET_NAME) 将进程名改为随机串（本次观测为 venj38），规避基于进程名的查杀与人工排查。

> **证据**：动态事件 prctl(PR_SET_NAME, "venj38")
> 
> **来源**：`ref:e46213bbbc` · `ev-000010`

### 4. 关闭看门狗

`T1562.001` · 置信度 **高** · 动态

探测并尝试以读写方式打开 /dev/watchdog 与 /dev/misc/watchdog，阻止看门狗复位导致设备重启，维持长期驻留。

> **证据**：strace access("/dev/watchdog"); openat("/dev/watchdog", O_RDWR); access("/dev/misc/watchdog")
> 
> **来源**：`ev-000026` · `ev-000027` · `ev-000028` · `ev-000029`

### 5. 创建原始套接字

`T1095` · 置信度 **高** · 动态

请求 AF_INET/SOCK_RAW（IPPROTO_UDP 与 IPPROTO_TCP）原始套接字，具备伪造源地址实施 UDP/SYN 洪泛的能力；本次因降权运行被内核以 EPERM 拒绝。

> **证据**：strace socket(AF_INET, SOCK_RAW, IPPROTO_UDP) = -1 EPERM; socket(AF_INET, SOCK_RAW, IPPROTO_TCP) = -1 EPERM
> 
> **来源**：`ev-000024` · `ev-000025`

### 6. 探测本地网络

`T1016` · 置信度 **高** · 动态

向 8.8.8[.]8:53 建立 UDP 连接后 getsockname 获取出口地址，并通过 ioctl 0x8912/0x8921 枚举网卡 MAC/IP，用于选择扫描源地址。

> **证据**：FUN_00401508 @0x401508: socket/connect/getsockname + ioctl 0x8912; strace connect(3, 8.8.8[.]8:53)
> 
> **来源**：`ev-000009` · `ev-000031`

### 7. 本地桥接通道

`T1090` · 置信度 **高** · 动态

创建名为 six_sayven-63464 的抽象 UNIX 套接字并连接 127.0.0[.]1:63464，成功后向控制台打印横幅并进入本地桥接/转发角色。

> **证据**：strace bind(AF_UNIX, sun_path=@"six_sayven-63464"); connect(127.0.0[.]1:63464); write(1, "wow i guess im finna bridge now")
> 
> **来源**：`ev-000010` · `ref:e46213bbbc`

### 8. 调用系统Shell

`T1059.004` · 置信度 **中** · 静态

内置 /bin/sh、"sh"、"-c" 字符串，具备执行下发 shell 命令的能力，可被用于下发 DDoS 指令或二次载荷。

> **证据**：.rodata 0x47dd24 '/bin/sh'; 0x47dd28 'sh'; 0x47dd30 '-c'
> 
> **来源**：`ev-000001` · `ev-000011`

### 9. 校验加密载荷

`T1140` · 置信度 **中** · 静态

内置 SHA-256/SHA-1/MD5 摘要与 Salsa20（expand 32-byte k）/Ed25519 代码，用于 P2P 报文完整性校验与加解密。

> **证据**：crypto 常量 off 0x7f300/0x7f320; .rodata 0x47f2b0 'expand 32-byte k'
> 
> **来源**：`ev-000004` · `ev-000005` · `ev-000006` · `ev-000007`

### 10. 写入OOM权重

`T1562.001` · 置信度 **低** · 静态

使用 /proc/%d/oom_score_adj 与 /proc/%d/oom_adj 路径模板调整进程 OOM 评分，降低被内核内存回收机制杀死的概率。

> **证据**：.rodata 0x47dbdc 'oom_score_adj'; 0x47dbec 'oom_adj'; 0x47dd00 '/proc/%d/%s'
> 
> **来源**：`ev-000001`

### 11. 后台化并切换根

`T1564` · 置信度 **中** · 动态

调用 chdir("/") 切换工作目录，并以守护化方式在设备上常驻运行（存在 fork/waitpid 相关系统调用序列）。

> **证据**：strace chdir("/")；main @0x4016ec 中 fork/waitpid 调用序列
> 
> **来源**：`ref:e46213bbbc` · `ev-000008`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| other | `BitTorrent DHT (BEP5) P2P swarm (get_peers/put/ping, Ed25519-signed)` | 6881 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://cloudflare-dns[.]com/dns-query` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://dns[.]google/dns-query` | 443 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/dev/watchdog`
- `/dev/misc/watchdog`
- `/bin/sh`
- `/dev/urandom`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `BitTorrent DHT (BEP5) 对等网络；节点发现与指令分发经 DHT 完成，未发现硬编码 C2 域名/IP` | 是 | 静态 |
| `bootstrap_dns` | `cloudflare-dns[.]com, dns[.]google（DoH POST /dns-query, application/dns-message）` | 是 | 静态 |
| `bot_tag` | `six_sayven` | 否 | 静态 |
| `local_bridge` | `AF_UNIX 抽象套接字 six_sayven-63464 + TCP 127.0.0[.]1:63464` | 否 | 动态 |
| `signature_scheme` | `Ed25519（3:sig64: 字段，64 字节签名）` | 是 | 静态 |
| `encryption_algo` | `Salsa20/ChaCha20（expand 32-byte k）、SHA-256、SHA-1、MD5` | 否 | 静态 |
| `process_name` | `运行期由 prctl(PR_SET_NAME) 设为随机串（观测到 venj38）` | 否 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得断言样本已经发动 DDoS：本次仅观测到原始套接字申请被拒，没有任何实际攻击流量或受害人。
- 不得断言硬编码 C2 域名/IP：寻址依赖 DHT 对等网络与 DoH 引导，静态与动态均未得到可直接外联的 C2 地址。
- 不得将其归类为勒索软件或窃密程序：未见文件加密、凭据收集或浏览器数据访问行为。
- 不得因出现 six_sayven 字符串就断言这是已公开命名的成熟家族：该名称仅为本样本自带标签，未获厂商/YARA 交叉印证。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 运行实例使用 unshare -n 完全断网，DHT 对等发现、DoH 解析与桥接后的指令通道均未能真实触发，C2 端点只能静态推断并标注待动态验证。
2. RAW 套接字请求因降权被 EPERM 拒绝，无法观测实际 DDoS 报文构造与发送。
3. 家族归属仅有样本自带标签与协议特征支撑，缺少厂商引擎或 YARA 规则的交叉印证，置信度低。
4. 部分关键字符串（例如运行期横幅）在文件中为加密/编码状态，未能在静态阶段完整还原其解密配置。

## 证据索引

<details>
<summary>展开 17 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | ASCII+UTF16LE 字符串抽取，命中 DoH/DHT/Ed25519/Salsa20/看门狗/oom 等关键字符串 |
| `ev-000003` | 字符串提取 | 字符串抽取汇总（566 条 ASCII / 3 条 UTF-16LE） |
| `ev-000004` | 密码学常量识别 | SHA-256 初始常量 @0x7f300 |
| `ev-000005` | 密码学常量识别 | SHA-256 轮常量 @0x7f320 |
| `ev-000006` | 密码学常量识别 | SHA-1 初始常量 @0x7e100 |
| `ev-000007` | 密码学常量识别 | MD5 初始常量 @0x7e100 |
| `ev-000008` | decompile.ghidra | 入口函数反编译：经 __libc_start_main 进入 0x4016ec |
| `ev-000009` | decompile.ghidra | FUN_00401508 反编译：connect 8.8.8[.]8:53 + getsockname + ioctl 0x8912/0x8921 获取出口地址/MAC |
| `ev-000010` | dyn.exec | 加固实例真机执行：MIPS BE 经 qemu-user 运行，退出码 0，输出横幅 |
| `ev-000024` | dyn.trace.strace | socket(AF_INET, SOCK_RAW, IPPROTO_UDP) 被 EPERM 拒绝 |
| `ev-000025` | dyn.trace.strace | socket(AF_INET, SOCK_RAW, IPPROTO_TCP) 被 EPERM 拒绝 |
| `ev-000026` | dyn.trace.strace | access("/dev/watchdog") |
| `ev-000027` | dyn.trace.strace | openat("/dev/watchdog", O_RDWR) |
| `ev-000028` | dyn.trace.strace | access("/dev/misc/watchdog") |
| `ev-000029` | dyn.trace.strace | openat("/dev/misc/watchdog", O_RDWR) |
| `ev-000031` | dyn.trace.strace | connect(3, 8.8.8[.]8:53) 用于本地地址探测 |
| `ref:e46213bbbc` | dyn.trace.strace | 完整 strace：prctl 改名、chdir("/")、抽象 UNIX 套接字 six_sayven-63464、127.0.0[.]1:63464 连接、横幅输出 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
