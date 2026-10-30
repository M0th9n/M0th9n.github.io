---
title: "恶意样本分析：Linux/ARM DoH-Tunnel Backdoor (unattributed)（ELF · elf · ffa6a217）"
published: 2026-10-29
draft: false
description: "恶意（置信度低）：Linux/ARM DoH-Tunnel Backdoor (unattributed) · backdoor/implant · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["backdoor", "implant", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Linux/ARM DoH-Tunnel Backdoor (unattributed)**（存疑） · 置信度 **低**
> 
> 在加固 Linux 分析实例中真实执行该 32 位 ARM 样本，直接观测到双重派生守护进程、进程名伪装为 libssl.so、绑定抽象 UNIX 套接字 @fdrunkkkk@@@@5、写入 /proc/self/oom_score_adj=-1000，以及向 8.8.8[.]8/1.1.1[.]1/9.9.9[.]9 等公共 DNS-over-HTTPS 解析器 443 端口的 TLS 连接尝试；结合静态反编译确认其用 POST /dns-query 与自定义编码的 DNS 隧道收发改令数据。分析环境无外网，连接均被拒绝，故未观测到成功回连或指令执行。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Linux/ARM DoH-Tunnel Backdoor (unattributed)** · _存疑_ |
| 置信度 | **低** |
| 行为类 | backdoor · implant |
| 难度 | medium |
| 首次出现 | 2026-10-29 06:33:35 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ffa6a2173ab38292e4f095e608bd8a744eb2a4bb0591acd9eb9ebfe544e8ea6a/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">双重派生守护进程</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">伪装成libssl.so</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">占用抽象控制套接字</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1559</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">抬高OOM免疫值</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">经公共DoH回连</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.004</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ffa6a2173ab38292e4f095e608bd8a744eb2a4bb0591acd9eb9ebfe544e8ea6a` |
| MD5 | _未记录_ |
| 大小 | 481,920 字节（470.6 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **3** 条静态可得、**6** 条经动态分析取得。

### 1. 双重派生守护进程

`T1564` · 置信度 **高** · 动态

二次 fork + setsid 脱离会话, 将 stdin/stdout/stderr 重定向到 /dev/null, 在后台常驻。

> **证据**：动态事件: clone(90)->setsid->clone(92)->dup2(4,0/1/2); 入口 0x8190, main 0xd484
> 
> **来源**：`ref:ef353ffb33` · `ref:4c59457e66` · `ref:3ef991b956`

### 2. 伪装成libssl.so

`T1036.005` · 置信度 **高** · 动态

启动后调用 prctl(PR_SET_NAME, "libssl.so") 修改进程显示名, 冒充系统 TLS 库相关进程。

> **证据**：动态事件 prctl(PR_SET_NAME, "libssl.so"); 静态有大量 wolfSSL/TLS 字符串佐证其伪装合理性
> 
> **来源**：`ref:ef353ffb33` · `ref:202f89ddb9`

### 3. 占用抽象控制套接字

`T1559` · 置信度 **高** · 动态

绑定并监听抽象 UNIX 套接字 @fdrunkkkk@@@@5(backlog=1), 用作单实例锁与本地指令通道。

> **证据**：动态事件 bind(AF_UNIX, sun_path=@"fdrunkkkk@@@@5") + listen(1); 字符串位于文件偏移 0x669a8
> 
> **来源**：`ref:ef353ffb33` · `ref:202f89ddb9`

### 4. 抬高OOM免疫值

`T1562.001` · 置信度 **高** · 动态

向 /proc/self/oom_score_adj 写入 -1000, 试图降低被系统 OOM killer 终止的概率。

> **证据**：动态事件 openat("/proc/self/oom_score_adj", O_WRONLY) + write("-1000") 返回 EACCES
> 
> **来源**：`ref:ef353ffb33`

### 5. 经公共DoH回连

`T1071.004` · 置信度 **高** · 动态

向 8.8.8[.]8/1.1.1[.]1/9.9.9[.]9 等公共解析器的 443 端口发起 TLS 连接, 以 dns.google 等域名作 Host/SNI, 发送 POST /dns-query 请求, 把 C2 流量混入正常 DoH 解析。

> **证据**：0xe478 构造 DoH 请求(0x66a40 处 "POST /dns-query HTTP/1.1"); 动态事件 connect :443 到 8.8.8[.]8、4.4.8[.]8、1.1.1[.]1、1.0.0[.]1、9.9.9[.]9 等
> 
> **来源**：`ref:0ec1694b0b` · `ref:ef353ffb33` · `ref:202f89ddb9`

### 6. 构造DNS隧道查询

`T1001` · 置信度 **高** · 静态

用自定义 base64 字母表把数据编码进 DNS 查询名, 自行拼接 2 字节事务 ID、查询类型与 CLASS=1, 走 TCP 443 DoH 发出。

> **证据**：0xe478 内嵌字母表字符串位于 0x66a00; 构建 0x0100 标志与 QDCOUNT=1 的 DNS 报文
> 
> **来源**：`ref:0ec1694b0b` · `ref:202f89ddb9`

### 7. 解码TXT隐藏IP

`T1001` · 置信度 **高** · 静态

解析 DNS TXT(type=0x10) 应答, 按 '|' 拆分条目, 对十六进制 nibble 做 XOR(0x6b/0x9e/0x3f/0x2a) 还原出点分 IPv4 列表。

> **证据**：0xfdf8 解码函数; 0xebac/0xf408 按 TXT 记录类型筛选并按 '|' 分割
> 
> **来源**：`ref:5dcd44b8a5` · `ref:a01fc398b3` · `ref:ebc5205315`

### 8. 清空进程参数

`T1070` · 置信度 **中** · 静态

启动后对 argv/环境区执行 memset, 擦除命令行与参数痕迹, 增加事后取证难度。

> **证据**：0xd310 计算 argv 区末端并 memset(ptr,0,len); 由 main 0xd484 在 daemon 化前调用
> 
> **来源**：`ref:a814d82e72` · `ref:3ef991b956`

### 9. 检测父进程存活

`T1622` · 置信度 **中** · 动态

向标准输出打印 "father?" 并配合 fork/UNIX 套接字进行父/子进程与单实例校验, 影响启动路径与调试行为。

> **证据**：动态事件 write(1,"father?") 后紧接 clone/setsid; 该串在静态字符串表中无明文, 运行时生成
> 
> **来源**：`ref:ef353ffb33` · `ref:3ef991b956`


## IOC（已去武器化）

### 网络

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://dns[.]google/dns-query (直连 8[.]8[.]8[.]8:443, SNI/Host=dns[.]google)` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://cloudflare-dns[.]com/dns-query (直连 1[.]1[.]1[.]1 / 1[.]0[.]0[.]1:443)` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://dns[.]quad9[.]net/dns-query (直连 9[.]9[.]9[.]9:443; 备用地址常量按主机序存储, 实际 connect 112[.]112[.]112[.]149)` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://dns[.]adguard-dns[.]com/dns-query (备用地址常量按主机序存储, 实际 connect 14[.]14[.]140[.]94 / 15[.]15[.]140[.]94)` | 443 | c2 | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `抽象 UNIX 套接字 @fdrunkkkk@@@@5`

**落地路径**

- `/dev/null`
- `/proc/self/exe`
- `/dev/urandom`
- `/etc/resolv.conf`
- `/etc/hosts`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `dns[.]google, cloudflare-dns[.]com, dns[.]quad9[.]net, dns[.]adguard-dns[.]com (作为 DoH Host/SNI)` | 是 | 静态 |
| `c2_ips` | `8[.]8[.]8[.]8, 4[.]4[.]8[.]8, 1[.]1[.]1[.]1, 1[.]0[.]0[.]1, 9[.]9[.]9[.]9, 112[.]112[.]112[.]149, 14[.]14[.]140[.]94, 15[.]15[.]140[.]94` | 是 | 动态 |
| `transport` | `HTTPS POST /dns-query, Content-Type: application/dns-message, TLS 1.3 (静态链接 wolfSSL)` | 是 | 静态 |
| `dns_tunnel_encoding` | `查询名使用自定义 base64 字母表编码; TXT 记录体按 '\|' 分割, 用 XOR 0x6b/0x9e/0x3f/0x2a 还原 IPv4` | 否 | 静态 |
| `mutex` | `@fdrunkkkk@@@@5` | 是 | 动态 |
| `process_name` | `libssl.so` | 是 | 动态 |
| `launch_argument` | `argv[1] 作为隧道标签/域名基址; 缺少参数直接退出` | 是 | 静态 |
| `encryption_algo` | `TLS13-AES256-GCM-SHA384` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能判定为勒索软件或窃密木马:未发现文件加密、凭据/浏览器数据或密钥环采集代码。
- 不能判定已成功连接 C2 或收到指令:分析环境无外网, 所有 443/53 连接均返回 ENETUNREACH。
- 不能判定具备扫描、自传播或 DDoS 能力:未见扫描器、漏洞利用或攻击指令表。
- 不能仅凭内嵌 /bin/sh 与 system 断定其可执行任意命令:该字符串属于静态链接的 C 运行库, 未取得恶意侧调用链证据。
- 不能据此样本认定具体家族:无外部情报、YARA 或多引擎结果支撑, 家族字段仅为未归属候选。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 分析环境无外网, DoH 会话与 DNS 隧道应用层协议只能在静态层面还原, 未观测到真实指令、文件落地或横向行为。
2. 进程名伪装、抽象套接字、OOM 免疫与 DoH 回连均为真实执行观测; C2 成功回连与后续载荷仍待联网环境验证。
3. 家族归属缺少外部情报/多引擎佐证, 仅以行为特征给出未归属候选。
4. 反编译存在类型推导噪声, 个别栈上常量结构(如握手 0x50 字节缓冲区)语义未完全确认。
5. 未观察到 cron/systemd/rc 等持久化写入, 不能据此认为不具备持久化能力。

## 证据索引

<details>
<summary>展开 12 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:f9c7ee691f` | ELF 结构解析 | ELF32 ARM little-endian, EXEC, 静态链接, entry VA 0x8190, 3 个 PT_LOAD, 无 NEEDED |
| `ref:57eb6d0cad` | elf.sections | .text 419988 字节熵 6.07, .rodata 41392 字节熵 6.60, 无高熵加密段 |
| `ref:202f89ddb9` | 字符串提取 | 命中 DoH 请求模板、四个 DoH 域名、自定义 base64 字母表、@fdrunkkkk@@@@5、libssl/TLS 相关字符串 |
| `ref:8232b44f6f` | 密码学常量识别 | AES/SHA-1/SHA-256/MD5 常量(AES 逆 S-box、SHA-256 初始值等), 对应静态链接的密码库 |
| `ref:4c59457e66` | decompile.function | entry 0x8190 标准 glibc 启动路径, 解出 main=0xd484 |
| `ref:3ef991b956` | decompile.function | main 0xd484: 要求 argv[1], 建立 AF_UNIX 监听、守护化、DoH 连接与指令循环 |
| `ref:0ec1694b0b` | decompile.function | 0xe478: 构造 DNS 查询、TLS 连接并发送 POST /dns-query, 校验响应头部 |
| `ref:ebc5205315` | decompile.function | 0xf408: 走 UDP/53 直连 8.8.8[.]8 拉取 A/TXT 记录并解析条目 |
| `ref:a01fc398b3` | decompile.function | 0xebac: 解析 DNS TXT(type 0x10) 应答, 按 '\|' 分割后逐条解码 |
| `ref:5dcd44b8a5` | decompile.function | 0xfdf8: 以 XOR 0x6b/0x9e/0x3f/0x2a 将编码串还原为 IPv4 |
| `ref:a814d82e72` | decompile.function | 0xd310: 计算 argv 区末端并 memset 清零命令行 |
| `ref:ef353ffb33` | dyn.trace | 真实执行系统调用序列: 守护化、PR_SET_NAME=libssl.so、bind @fdrunkkkk@@@@5、oom_score_adj 写入、向 8.8.8[.]8/1.1.1[.]1/9.9.9[.]9 等 443 与 53 连接(均 ENETUNREACH) |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
