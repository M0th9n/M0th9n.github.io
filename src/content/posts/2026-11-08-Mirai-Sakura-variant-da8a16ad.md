---
title: "恶意样本分析：Mirai (Sakura variant)（ELF · elf · da8a16ad）"
published: 2026-11-08
draft: false
description: "恶意（置信度中）：Mirai (Sakura variant) · botnet · 难度 medium · 静态反编译（动态执行未取得运行时行为）"
tags: ["Mirai", "botnet", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Mirai (Sakura variant)** · 置信度 **中**
> 
> 别名：Sakura_Bot、Sakura botnet、Mirai.Sakura
> 
> 反编译确认该程序为 Linux/PowerPC 的 Mirai 系 DDoS 僵尸网络客户端：硬编码 C2 92.119.165[.]164:12345，连接后上报本机 IP/端口/架构，接收以 '!' 开头的远程指令并派生 TCP/UDP/VSE/DNS/CLDAP/LDAP/DISCORD 等攻击线程，使用原始套接字与伪造源地址。源码文件名 Sakura_Bot.c 与 Mirai 标准函数集（initConnection/processCmd/ftcp/atcp/dnsattack/getRandomIP/makeIPPacket 等）一致。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Mirai (Sakura variant)** · 别名 Sakura_Bot、Sakura botnet、Mirai.Sakura |
| 置信度 | **中** |
| 行为类 | botnet |
| 难度 | medium |
| 首次出现 | 2026-11-07 08:27:31 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/da8a16ad477f6f8cce793c18b2c9dcbea9e8ff745e973bdef164de398fdd2a60/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">双重派生脱离终端</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">硬编码C2断线重连</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">上线报到泄露身份</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">探测本机网络身份</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1016</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">识别可用服务端口</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `da8a16ad477f6f8cce793c18b2c9dcbea9e8ff745e973bdef164de398fdd2a60` |
| MD5 | _未记录_ |
| 大小 | 101,468 字节（99.1 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **11** 条行为，每条都挂了证据，且全部静态可得。

### 1. 双重派生脱离终端

`T1564` · 置信度 **高** · 静态

main 连续两次 fork，父进程退出；子进程调用 setsid、chdir("/")，并将 SIGHUP(0xd) 设为忽略，转入后台常驻运行。

> **证据**：main @ 0x100083b0：fork; waitpid/exit; fork; exit; setsid; chdir("/"); signal(0xd, 1)
> 
> **来源**：`ev-000005`

### 2. 硬编码C2断线重连

`T1095` · 置信度 **高** · 静态

initConnection 读取 commServer[0] 的 "92.119.165[.]164:12345"，按冒号拆出端口，建立 TCP 连接（30 秒超时）；连接失败或断开后主循环 sleep(5) 反复重连。

> **证据**：initConnection @ 0x10008210：socket(2,1,0)+connectTimeout(...,0x1e)；commServer 符号 @ 0x10023370 → 0x10010b10 "92.119.165[.]164:12345"
> 
> **来源**：`ev-000006` · `call:call_8634c51fc2c4465ea34515bd` · `call:call_df4db7dd57a94a838b0b0d27`

### 3. 上线报到泄露身份

`T1082` · 置信度 **高** · 静态

连接成功后用 sockprintf 发送 "[1;95mDevice Connected: %s | Port: %s | Arch: %s"，内容为本机 IP、被判定为可入侵的端口（22 或 Unknown Port）以及架构名 "Ppc"。

> **证据**：main @ 0x100083b0 调用 sockprintf(@0x100114c4 格式串)；getArch @ 0x10005ff8 返回 0x100113f8 "Ppc"；getPortz @ 0x10006020 返回 "22"/"Unknown Port"
> 
> **来源**：`ev-000005` · `ev-000011` · `ev-000012`

### 4. 探测本机网络身份

`T1016` · 置信度 **高** · 静态

getOurIP 通过 UDP connect 8.8.8[.]8:53 后 getsockname 取得出口 IP，读取 /proc/net/route 找默认路由接口，再以 ioctl(SIOCGIFHWADDR, 0x8927) 取得 MAC 地址。

> **证据**：getOurIP @ 0x100005d0：inet_addr("8.8.8[.]8")、htons(0x35)、open("/proc/net/route")、ioctl(fd,0x8927,...)
> 
> **来源**：`ev-000008`

### 5. 识别可用服务端口

`T1082` · 置信度 **高** · 静态

getPortz 通过 access 依次检查 /usr/bin/python、/usr/bin/python3、/usr/bin/perl、/usr/sbin/telnetd，存在任一即上报端口 22，否则上报 Unknown Port，用于向 C2 说明该主机的可利用服务。

> **证据**：getPortz @ 0x10006020：access("/usr/bin/python")、"/usr/bin/python3"、"/usr/bin/perl"、"/usr/sbin/telnetd" → "22"/"Unknown Port"（字符串 @0x10011404/0x10010f28）
> 
> **来源**：`ev-000011` · `ev-000004`

### 6. 解析感叹号指令

`T1095` · 置信度 **高** · 静态

主循环用 recvLine 读取 C2 数据；仅当首字符为 '!' 时，按空格切分第一个 token 作为攻击方法名，将其转大写，后续 token 作为参数传入 processCmd 分发。

> **证据**：main @ 0x100083b0：acStack_1058[0]=='!'、toupper、strtok(" ")、processCmd(local_10b0, local_1080)
> 
> **来源**：`ev-000005` · `ev-000007`

### 7. 派生TCP/UDP洪水

`T1498.001` · 置信度 **高** · 静态

processCmd 对 TCP/UDP 指令做参数校验后调用 listFork 派生攻击子进程，执行 ftcp/SendUDP，使用原始套接字与随机源地址/随机源端口持续发送报文，支持逗号分隔的多目标。

> **证据**：processCmd @ 0x10006120：strcmp("TCP")→ftcp @ 0x100025ac；strcmp("UDP")→SendUDP @ 0x10002130；每次 listFork+_exit(0)
> 
> **来源**：`ev-000007`

### 8. 反射放大三协议

`T1498.002` · 置信度 **高** · 静态

内置 DNS、CLDAP、LDAP 反射放大攻击：构造查询负载，循环用 getRandomIP 伪造源地址、makeIPPacket 组包并 sendto 到目标，实现反射/放大流量。

> **证据**：dnsattack @ 0x100052b0：build_dns_query + getRandomIP + makeIPPacket + sendto；cldapattack @ 0x10005654；ldapattack @ 0x10005a30；build_ldap_search @ 0x10005dd4；build_dns_query @ 0x10004fb4
> 
> **来源**：`ev-000010` · `call:call_a2ced84f066c4731b0184084`

### 9. VSE协议放大攻击

`T1498.002` · 置信度 **高** · 静态

内置 VSE 攻击（Valve Source Engine 查询放大）：使用 "TSource Engine Query" 负载构造 UDP 报文，结合随机源地址向目标游戏/查询端口发送。

> **证据**：vseattack @ 0x10002f38 + makevsepacket @ 0x10002eec；vse_payload @ 0x10010ebc = "TSource Engine Query rfdknjms"
> 
> **来源**：`call:call_df4db7dd57a94a838b0b0d27` · `call:call_a2ced84f066c4731b0184084`

### 10. 伪造源地址发包

`T1498.001` · 置信度 **高** · 静态

所有洪泛/反射函数共用 getRandomIP 生成（可按掩码限定的）随机源 IP，makeIPPacket/csum/tcpcsum 自行组装 IP/UDP/TCP 报文与校验和，体现源地址伪造能力。

> **证据**：getRandomIP @ 0x10000478；makeIPPacket @ 0x10002044；csum @ 0x10001e00；tcpcsum @ 0x10001f40；discordattack 中 getRandomIP(...)+makeIPPacket(...)+csum(...)
> 
> **来源**：`ev-000009` · `call:call_a2ced84f066c4731b0184084`

### 11. DISCORD语音洪水

`T1498.001` · 置信度 **高** · 静态

discordattack 默认目的端口 443（0x1bb），使用原始 UDP 套接字、随机源 IP、8 字节固定负载 "discord_payload" 加随机填充，持续向目标发送伪造源地址报文。

> **证据**：discordattack @ 0x10005c4c：param_2==0 → 0x1bb；memcpy(buf+0x1c, &discord_payload_6464, 8)；getRandomIP + sendto 循环
> 
> **来源**：`ev-000009`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `92.119.165[.]164` | 12345 | c2 | 静态 | ⏳ 未观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `92.119.165[.]164` | 是 | 静态 |
| `c2_port` | `12345` | 是 | 静态 |
| `transport` | `raw TCP (SOCK_STREAM), 30 秒连接超时，断线后 5 秒重连` | 是 | 静态 |
| `c2_protocol` | `明文行协议；仅处理以 '!' 开头的指令，参数以空格分隔并仅做大小写归一化` | 是 | 静态 |
| `attack_methods` | `TCP,UDP,VSE,STDHEX,STD,NFODROP,OVHKILL,XMAS,CRUSH,STOMP,STOP,PPS,DNS,CLDAP,LDAP,DISCORD` | 否 | 静态 |
| `campaign_marker` | `dayzddos.co` | 否 | 静态 |
| `embedded_user_agents` | `Chrome 44/46/60/63/69 共 7 条 Mozilla/5.0 字符串（Windows NT 10.0/6.1/5.1、X11 Linux）` | 否 | 静态 |
| `encryption_algo` | `null (未发现 AES/SHA/MD5/TEA/CRC/Base64 等密码学常量)` | 否 | 静态 |
| `install_path` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要将其归类为窃密、勒索或挖矿样本：反编译中没有任何凭据读取、文件加密、钱包/矿池或数据回传逻辑，核心能力是远程控制的 DDoS 攻击。
- 不要声称存在持久化机制：程序只做 fork/setsid/chdir 守护化，未发现自启动写入、cron、rc.local、服务注册或自我复制代码；持久化若存在只可能来自外部投放链，样本本身未实现。
- 不要声称已确认 C2 上线或真实网络会话：C2 配置来自静态字符串/指针，跨架构仿真未获得成功连接或任何响应，C2 的 recoverability 必须保持 static。
- 不要把它当作通用远程控制后门：指令集仅限内置的洪泛/反射方法，没有 shell 执行、文件上传/下载或任意命令执行实现。
- 不要套用 Windows 主机 IOC 模板：该样本为 32 位大端 PowerPC Linux ELF，未创建注册表项、Windows 服务、计划任务或互斥体。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 否 |

**局限与待验证**

1. 样本架构为 PowerPC 32 位大端，无法在 x86 加固执行环境中原生运行；跨架构仿真启动后在超时前未产生可观测输出，未获得真实 C2 连接、指令交互或攻击流量。
2. C2 92.119.165[.]164:12345 仅由静态字符串与 commServer 指针确认，未经动态会话验证，标记为 static 且 pending_dynamic_verify=true。
3. processCmd 的后半段反编译输出被截断，DNS/CLDAP/LDAP/DISCORD/PPS/STOMP 等指令的具体分发代码未逐条展开；其绑定关系由命令字符串、函数符号及 dnsattack/discordattack 实现交叉确认。
4. 未观测到持久化、下载/更新模块；不排除投放该 ELF 的扫描器或加载脚本在外部提供驻留能力。
5. 未进行任何真实外联，所有网络指标均为静态恢复；嵌入的 Mozilla User-Agent 字符串仅作为伪装常量存在，未发现对应的 HTTP 客户端逻辑。

## 证据索引

<details>
<summary>展开 12 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 字符串抽取命中（含字母表常量），确认非加密资源 |
| `ev-000004` | 字符串提取 | ASCII 1045 条/UTF16LE 2 条；含 C2、User-Agent、攻击方法名、telnetd 路径等 |
| `ev-000005` | decompile.function | 反编译 main @ 0x100083b0：守护化、连接 C2、上报 banner、'!' 指令循环 |
| `ev-000006` | decompile.function | 反编译 initConnection @ 0x10008210：commServer 选点、冒号拆端口、socket+connectTimeout(30s) |
| `ev-000007` | decompile.function | 反编译 processCmd @ 0x10006120：TCP/UDP/VSE/STDHEX/STD/NFODROP/OVHKILL/XMAS/CRUSH 等指令分支与 listFork |
| `ev-000008` | decompile.function | 反编译 getOurIP @ 0x100005d0：8.8.8[.]8 UDP 探测、/proc/net/route、ioctl 取 MAC |
| `ev-000009` | decompile.function | 反编译 discordattack @ 0x10005c4c：默认 443、伪造源 IP、原始 UDP 发送循环 |
| `ev-000010` | decompile.function | 反编译 dnsattack @ 0x100052b0：build_dns_query+getRandomIP+makeIPPacket 反射放大 |
| `ev-000011` | decompile.function | 反编译 getPortz @ 0x10006020：python/python3/perl/telnetd 存在性探测，上报 22 |
| `ev-000012` | decompile.function | 反编译 getArch @ 0x10005ff8：返回 "Ppc" |
| `call:call_a2ced84f066c4731b0184084` | decompile.symbols | 228 个函数与字符串清单：确认 Mirai 函数集、攻击函数入口与攻击方法常量 |
| `call:call_8634c51fc2c4465ea34515bd` | script | 解析 .symtab/.sdata：commServer@0x10023370 仅 1 项，指向 0x10010b10 "92.119.165[.]164:12345"；currentServer@0x10023374 初值 -1；无 execve/system/unlink 等符号 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
