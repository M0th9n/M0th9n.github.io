---
title: "恶意样本分析：CatStorm（ELF · elf · 9e0eca4e）"
published: 2026-11-23
draft: false
description: "恶意（置信度中）：CatStorm · botnet/miner · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["CatStorm", "botnet", "miner", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **CatStorm**（存疑） · 置信度 **中**
> 
> 别名：CatStorm Go DDoS bot、catstorm/Bot
> 
> 该文件为 Go 1.25.0 编译的 MIPS 大端 ELF，内置完整的 DDoS 僵尸网络源码树（catstorm/Bot/Methods/l4、l7、process）与门罗币挖矿模块；main.main 将硬编码地址 45.61.182[.]32 与端口 9111 拼接后调用 net.Dial（tcp）建立控制通道，并在收到命令后分派至 ack/dns/syn/udp/tcp/http 等十余种攻击方法。隔离实例内实际执行时观察到以 0755 权限尝试写入自启动文件（被非 root 权限拒绝）以及创建外联 TCP 套接字，恶意意图与能力由静态符号、字符串和运行期事件共同证实。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **CatStorm** · 别名 CatStorm Go DDoS bot、catstorm/Bot · _存疑_ |
| 置信度 | **中** |
| 行为类 | botnet · miner |
| 难度 | hard |
| 首次出现 | 2026-11-21 18:07:12 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/9e0eca4e0acbd39ecfe98ac9fedf1cf5ae0354a9cf92910a96daea5a6d293790/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">直连C2端口9111</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">尝试写入自启动文件</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002, T1053.003</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">发起TCP外联套接字</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">解析C2指令发动DDoS</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1498.001, T1059.004</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">滥用DNS与协议放大</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1498.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `9e0eca4e0acbd39ecfe98ac9fedf1cf5ae0354a9cf92910a96daea5a6d293790` |
| MD5 | _未记录_ |
| 大小 | 6,619,351 字节（6.3 MB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **10** 条行为，每条都挂了证据；其中 **8** 条静态可得、**2** 条经动态分析取得。

### 1. 直连C2端口9111

`T1095` · 置信度 **高** · 静态

从只读数据段取出全局字符串 45.61.182[.]32 与 9111，用单字节冒号拼接为 45.61.182[.]32:9111，随后以 tcp 为网络类型调用 net.Dial 建立控制通道。

> **证据**：main.main 0x2f72d0 载入 0x64b478(45.61.182[.]32)、0x2f7490 载入 0x64b480(9111)；0x2f74b0-0x2f74cc 以冒号(0x47d6d0) 调 runtime.concatstring3；0x2f7560 jal net.Dial，network=tcp@0x3ff270
> 
> **来源**：`ref:240e5980c7` · `ref:94457dd902` · `ref:0f43eeb107` · `ref:6372a6d1d7`

### 2. 尝试写入自启动文件

`T1543.002, T1053.003` · 置信度 **高** · 动态

运行期以 0755 权限打开并截断目标文件用于落地持久化副本，因以普通用户身份运行返回 EACCES；静态对应 process.Persist 到 installSystemd 将自身复制到 /lib/systemd/systemd-update 并写入 /etc/systemd/system/bot-update.service。

> **证据**：strace openat(AT_FDCWD, <path>, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0755) = -1 EACCES；process.Persist @0x2f50a0、installSystemd @0x2f5a40、installCron @0x2f565c、installInitd @0x2f5c48
> 
> **来源**：`ref:f30404a690` · `ref:0113621c00` · `ref:719961b497` · `ref:bc6b4cbe26`

### 3. 发起TCP外联套接字

`T1095` · 置信度 **高** · 动态

运行期创建 AF_INET 的 TCP 套接字并做 IPv6/IPv4 绑定探测，网络命名空间隔离下未完成到 C2 的 connect 会话；静态链路指向 45.61.182[.]32:9111。

> **证据**：strace socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_TCP)=6，随后 bind(AF_INET6) 探测并 close；无成功 connect 记录
> 
> **来源**：`ref:0eacbcdf2c` · `ref:f30404a690` · `ref:5e15e08a75`

### 4. 解析C2指令发动DDoS

`T1498.001, T1059.004` · 置信度 **高** · 静态

对 C2 连接使用 bufio.Scanner 按行读取文本命令，经 strings.Fields 切分后由 main.startAttack 分派到 16 种攻击向量（ack、dns、syn、udp、tcp、tcp-stomp、tcp-bypass、udp-bypass、http、http-bypass、discord、fortnite、minecraft、ssh、pps、udp-pps）。

> **证据**：main.main 内 bufio.NewScanner/(*Scanner).Scan/Text、strings.Fields 后 16 次调用 main.startAttack(0x2fe184)；方法串 @0x4005f9(tcp-stomp)、0x400d7c(tcp-bypass/udp-bypass)、0x40145f(http-bypass)
> 
> **来源**：`ref:59f4eeedbb` · `ref:fe348e2fae` · `ref:f473e500be` · `ref:80645b0e11`

### 5. 滥用DNS与协议放大

`T1498.002` · 置信度 **高** · 静态

内置 DNS 查询池（1.1.1[.]1/1.0.0[.]1/8.8.8[.]8/8.8.4[.]4/9.9.9[.]9:53）构造 DNS 洪水报文；另含 Fortnite、Minecraft、Discord、SSH 协议洪水及伪造 Referer 的 HTTP 层洪水，形成反射/放大式拒绝服务。

> **证据**：l4.initDnsPool@0x2e75b8、l4.buildDnsPacket@0x2e6e8c、l4.Dnsflood@0x2e771c；解析器列表 @0x3ffcd7；l7.Httpflood@0x2edd2c 与引用搜索引擎 Referer 字串
> 
> **来源**：`ref:80645b0e11` · `ref:e0995d6202` · `ref:d281b5f1bc`

### 6. 多路径开机持久化

`T1543.002, T1053.003, T1037.004` · 置信度 **高** · 静态

通过 systemd 服务单元（Description=System Update Service、Restart=always、WantedBy=multi-user.target）、/etc/cron.d 与 @reboot 计划任务、/etc/init.d 脚本、/etc/rc.local 以及 /etc/profile.d 脚本五条路径实现重启与登录后自启动，并在 init 脚本 stop 分支执行 killall systemd-update。

> **证据**：installSystemd@0x2f5a40/installCron@0x2f565c/installCronDir@0x2f590c/installInitd@0x2f5c48/installRcLocal@0x2f5e50/installProfile@0x2f6010；单元模板 @0x41757a；路径 @0x4071c2、0x40dac5、0x40a2d5；@reboot root system-update @0x402038
> 
> **来源**：`ref:80645b0e11` · `ref:f2cff81ca2` · `ref:bc6b4cbe26` · `ref:8adf084f3e` · `ref:719961b497`

### 7. 伪装系统进程名

`T1036.005` · 置信度 **中** · 静态

运行时改写 /proc/self/comm 一类进程标识，使用 kworker/0:0 与 amazon、github、gitlab、docker、python、systemd 等系统/服务名混淆；同时提供 Protect 例程维持存活并终止旧实例。

> **证据**：process.Hide@0x2f4c58（引用 /proc/self/comm）、process.Protect@0x2f6128；伪装名池 @0x3ff94a、0x401f00；killall systemd-update 2>/dev/null @0x417f2c
> 
> **来源**：`ref:80645b0e11` · `ref:4bec64fe11` · `ref:bc6b4cbe26`

### 8. 内置XMRig挖矿

`T1496` · 置信度 **高** · 静态

编译进 MoneroMiner 模块，引用 xmrig-mips、stratum+tcp:// 与 --donate-level 等矿机参数，可在 C2 指令下启动门罗币挖矿消耗受害主机算力。

> **证据**：catstorm/Bot/Methods.MoneroMiner@0x2e4bd0（源码 monero.go）；字符串 xmrig-mips/stratum+tcp:///--donate-level @0x3f0d9a、0x3ff94a
> 
> **来源**：`ref:80645b0e11` · `ref:d281b5f1bc` · `ref:df341679cc`

### 9. 上报主机资源指纹

`T1082, T1016` · 置信度 **高** · 静态

采集内存总量、磁盘总量、CPU 数量与运行时统计，经 strconv 格式化后与 REGISTER linux mips 横幅一并上报 C2，用于攻击调度与收益评估。

> **证据**：main.main 调 process.GetTotalRAM@0x2f47f4、GetTotalDisk@0x2f4a94、runtime.NumCPU、strconv.FormatFloat；REGISTER linux mips @0x404ed0；/proc/meminfo 中 MemTotal @0x400614
> 
> **来源**：`ref:59f4eeedbb` · `ref:fe348e2fae` · `ref:df341679cc`

### 10. 下载更新自身

`T1105` · 置信度 **中** · 静态

内置 curl/wget/tftp/axel/sftp 等下载器路径池与 /tmp/.upd 暂存路径，配合 UPDATE_OK/UPDATE_FAIL 应答实现远程更新或替换载荷。

> **证据**：/tmp/.upd @0x40060b；下载器路径池 @0x401fad、0x402c18；UPDATE_OK/UPDATE_FAIL @0x3f0d90、0x3f19d9
> 
> **来源**：`ref:719961b497` · `ref:df341679cc` · `ref:d281b5f1bc`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `45[.]61[.]182[.]32:9111` | 9111 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/tmp/.google`
- `/tmp/.upd`
- `/tmp/.cron`
- `/lib/systemd/systemd-update`
- `/usr/lib/systemd/systemd-update`
- `/etc/systemd/system/bot-update.service`
- `/etc/cron.d/system-update`
- `/etc/init.d/system-update`
- `/etc/profile.d/system-update.sh`
- `/etc/rc.local`

**服务**

- `bot-update.service（Description=System Update Service）`

**计划任务**

- `crontab 条目：@reboot root system-update`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `45[.]61[.]182[.]32` | 是 | 静态 |
| `c2_port` | `9111` | 是 | 静态 |
| `protocol_banner` | `REGISTER linux mips` | 是 | 静态 |
| `install_path` | `/tmp/.google` | 是 | 静态 |
| `persist_systemd_binary` | `/lib/systemd/systemd-update` | 是 | 静态 |
| `persist_systemd_unit` | `/etc/systemd/system/bot-update.service` | 是 | 静态 |
| `persist_cron` | `/etc/cron.d/system-update` | 是 | 静态 |
| `persist_initd` | `/etc/init.d/system-update` | 是 | 静态 |
| `persist_profile` | `/etc/profile.d/system-update.sh` | 是 | 静态 |
| `update_staging` | `/tmp/.upd` | 否 | 静态 |
| `miner_binary` | `xmrig-mips` | 否 | 静态 |
| `dns_flood_resolvers` | `1.1.1[.]1:53,1.0.0[.]1:53,8.8.8[.]8:53,8.8.4[.]4:53,9.9.9[.]9:53` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能称其为勒索软件或擦除器：未发现文件加密、卷影删除或磁盘擦写逻辑。
- 不能称其具备蠕虫式自动扫描与弱口令爆破传播能力：样本内未包含端口扫描、Telnet/SSH 爆破模块。
- 不能声称已取得 C2 会话或成功回传数据：隔离网络内仅观察到套接字创建，无成功 connect 与会话。
- 不能声称持久化文件已成功落地：运行环境为非 root，写自启动文件被 EACCES 拒绝，只能证实尝试行为。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 隔离网络 fail-closed，未与 45.61.182[.]32:9111 建立会话，C2 协议与回传内容仅由静态字符串与调用链还原，C2 条目标记为 static 且待动态复核。
2. 执行实例为非 root，写自启动文件被拒（EACCES），无法验证持久化落地后的实际自启动效果。
3. 样本为 MIPS 架构，经 qemu 用户态运行，指令级时序、反调试与完整命令处理循环未完全覆盖。
4. 反编译器未恢复 Go 符号（函数识别为 FUN_xxxx），函数语义主要依据内置 pclntab 符号表、字符串常量与调用点交叉印证。
5. 运行期未观察到完成的 connect、DNS 查询或 HTTP 请求，攻击方法仅由代码与常量证实，未在本次分析中实际触发。

## 证据索引

<details>
<summary>展开 21 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:1427c4337a` | ELF 结构解析 | ELF32 大端 MIPS，ET_EXEC，含 .gopclntab/.go.buildinfo 等 Go 段，无动态依赖 |
| `ref:2372118766` | 哈希与指纹 | md5=56c13363e44c382b329a64295879b68b，sha256=9e0eca4e...3790 |
| `ref:7d81fddf03` | scan.entropy | 整体熵 5.565，.text 5.105，无高熵加壳特征 |
| `ref:e3259118d1` | 字符串提取 | 抽取 15055 条 ASCII 字符串，含 Go 标准库与明文常量 |
| `ref:708f52c736` | 字符串提取 | Go 源码路径表：catstorm/Bot/Methods/l4/*.go、l7/http.go、process/linux.go、monero.go |
| `ref:80645b0e11` | 字符串提取 | 具名函数表：Ackflood/Dnsflood/Synflood/Tcpbypassflood/Httpflood、Persist/installSystemd/installCron、MoneroMiner |
| `ref:a9a356fe4a` | script | 解析 Go pclntab 得 6139 个函数及地址：main.main=0x2f7178、process.Persist=0x2f50a0、MoneroMiner=0x2e4bd0 等 |
| `ref:240e5980c7` | script | main.main 内 0x2f72d0/0x2f7308/0x2f7490 分别加载全局串头 0x64b478/0x64b480/0x64b488 |
| `ref:94457dd902` | script | 解码 0x2f7400-0x2f7560：concatstring3(45.61.182[.]32, 冒号, 9111) 后 jal net.Dial，network=tcp |
| `ref:0f43eeb107` | script | 全 .text 扫描 jal 目标：main.main 0x2f7560 调用 net.Dial |
| `ref:59f4eeedbb` | script | main.main 调用清单：bufio.Scanner、strings.Fields、16 次 startAttack、GetTotalRAM/Disk、SetKeepAlive |
| `ref:fe348e2fae` | script | main.main 引用字面量：REGISTER linux mips、tcp-stomp、tcp-bypass、http-bypass、/tmp/.google、攻击方法名 |
| `ref:df341679cc` | script | REGISTER linux mips 横幅、xmrig-mips/stratum+tcp://、UPDATE_OK/UPDATE_FAIL、priv-flood 等常量定位 |
| `ref:719961b497` | script | 持久化路径常量：/etc/cron.d/system-update、/etc/init.d/system-update、/etc/systemd/system/bot-update.service、/etc/profile.d/system-update.sh、/lib/systemd/systemd-update |
| `ref:f2cff81ca2` | script | systemd 单元模板：[Unit] Description=System Update Service、Restart=always、WantedBy=multi-user.target |
| `ref:8adf084f3e` | script | crontab 条目 @reboot root system-update 与 /etc/rc.local 引用 |
| `ref:bc6b4cbe26` | script | killall systemd-update 2>/dev/null 脚本片段与 @reboot 常量 |
| `ref:784dac248f` | dyn.exec | 隔离实例 qemu-mips 执行，exit=1，network_isolated=true，无标准输出 |
| `ref:5e15e08a75` | dyn.trace | strace 2819 次系统调用：写自启动文件 EACCES、TCP 套接字创建、IPv6 绑定探测 |
| `ref:f30404a690` | dyn.trace | 完整 trace 尾部：openat(...O_WRONLY\|O_CREAT\|O_TRUNC,0755)=-1 EACCES；socket(AF_INET,SOCK_STREAM)=6；exit_group(1) |
| `ref:0eacbcdf2c` | dyn.trace | 网络相关调用过滤：socket/setsockopt/bind，未出现 connect 成功记录 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
