---
title: "恶意样本分析：libbase XMRig coinminer（ELF · elf · 7620e6a9）"
published: 2026-11-05
draft: false
description: "恶意（置信度中）：libbase XMRig coinminer · miner/backdoor · 难度 medium · 纯静态分析"
tags: ["libbase XMRig", "miner", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **libbase XMRig coinminer**（存疑） · 置信度 **中**
> 
> 别名：XMRig-based Linux coinminer、system-helper miner、snapd/snap masquerading miner、ssh-session-gate backdoor
> 
> 样本内置完整的 XMRig/RandomX 门罗币挖矿引擎（donate-level=0），并实现 libbase/system-helper/ssh-session-gate 等多重持久化与后门组件，具备明确的资源滥用和长期驻留意图；未见勒索、文件加密或凭据窃取逻辑。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **libbase XMRig coinminer** · 别名 XMRig-based Linux coinminer、system-helper miner、snapd/snap masquerading miner、ssh-session-gate backdoor · _存疑_ |
| 置信度 | **中** |
| 行为类 | miner · backdoor |
| 难度 | medium |
| 首次出现 | 2026-11-01 17:20:24 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/7620e6a995b46fef7f2de8b214deceb27ef1a6cdd56ec05b763f0fcb30c4514b/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">内置XMRig矿机</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1496</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">每分钟拉起守护</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">伪装systemd服务</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">劫持登录Shell</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1546.004</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">预加载恶意共享库</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.006</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `7620e6a995b46fef7f2de8b214deceb27ef1a6cdd56ec05b763f0fcb30c4514b` |
| MD5 | _未记录_ |
| 大小 | 2,588,672 字节（2.5 MB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **12** 条行为，每条都挂了证据，且全部静态可得。

### 1. 内置XMRig矿机

`T1496` · 置信度 **高** · 静态

静态链接完整的 XMRig/RandomX 门罗币挖矿引擎，配置模板将 donate-level 置 0，并内置 7 个 supportxmr 默认矿池，运行时按配置连接矿池提交算力。

> **证据**：配置模板 off 1336428-1336663（algo rx/0、pass 16）；矿池串 off 1389735 起；RandomX/Argon2/MSR 字符串与 /dev/cpu/{}/msr 引用 0x44807D
> 
> **来源**：`ref:e67796d665` · `ref:756fa2f42e`

### 2. 每分钟拉起守护

`T1053.003` · 置信度 **高** · 静态

写入 /etc/cron.d/system-helper 及用户 crontab 的 @reboot 与每分钟任务，反复执行 /var/tmp/snap、/var/tmp/snapd、$HOME/.X0-lock，实现重启与周期性自启动。

> **证据**：cron 行 off 1375299-1375672；/etc/cron.d/system-helper 引用 0x42C850
> 
> **来源**：`ref:e67796d665` · `ref:5cfe41c619`

### 3. 伪装systemd服务

`T1543.002` · 置信度 **高** · 静态

安装 system-helper.service（Type=oneshot，执行 /usr/local/bin/system-helper-run）与 system-helper.timer（OnBootSec=0，OnCalendar=*:0/1），以系统助手名义实现开机与每分钟驻留。

> **证据**：unit 文本 off 1376659-1377182；/etc/systemd/system/system-helper.service 引用 0x42C3B0
> 
> **来源**：`ref:e67796d665` · `ref:5cfe41c619`

### 4. 劫持登录Shell

`T1546.004` · 置信度 **高** · 静态

将 libbase.sh 安装到 /usr/local/libexec 与 /etc/profile.d，并写入 ~/.bashrc、~/.zshrc；用 --libbase-run 包装交互式 Shell，备份并替换 /bin/sh（/bin/sh.bak），在用户登录时接管会话。

> **证据**：libbase.sh 路径 off 1380866-1381101；/bin/sh.bak 引用 0x431361；main 在 0x4027EE 检查 argv[1]==--libbase-run 并跳转 0x43148B
> 
> **来源**：`ref:e67796d665` · `ref:5d344ce76f` · `ref:5cfe41c619`

### 5. 预加载恶意共享库

`T1574.006` · 置信度 **高** · 静态

向 /usr/local/lib 写入 libcommon.so 并保留 .bak，通过 LD_PRELOAD 与 /etc/ld.so.preload 强制加载，具备用户态劫持/隐藏能力。

> **证据**：LD_PRELOAD= 引用 0x42A5B7；/etc/ld.so.preload 引用 0x42AE32；libcommon.so/.bak 字符串 off 1375782-1375828
> 
> **来源**：`ref:5cfe41c619` · `ref:e67796d665`

### 6. 篡改系统监控命令

`T1014` · 置信度 **高** · 静态

在 Shell 环境覆盖 top、crontab、kill 等命令，过滤名称含 16、libbase.sh 的进程与计划任务，使用户难以发现挖矿进程和持久化条目。

> **证据**：top 过滤 /16/d、/libbase.sh/d 于 off 1377320；crontab/kill 包装于 off 1377881 与 1378592
> 
> **来源**：`ref:e67796d665`

### 7. 清除历史与日志

`T1070.003` · 置信度 **高** · 静态

删除 $HOME/.bash_history 与 /var/tmp/apt.log、/var/tmp/yum.log，并结束名称含 b0s、yum.log、apt.log 的进程，降低被取证与追溯的概率。

> **证据**：pkill -9 -f '.b0s' 等命令 off 1379387，引用 0x4303C5
> 
> **来源**：`ref:e67796d665` · `ref:5cfe41c619`

### 8. 杀掉竞争挖矿进程

`T1489` · 置信度 **高** · 静态

按 comm=16 或 pgrep -x 16 查找同名进程并保留 CPU 占用最高者、杀死其余实例；同时终止 nvidia-smi 中 ./init 等竞争挖矿进程，独占受害主机算力。

> **证据**：ps/pgrep/kill 逻辑 off 1379295-1380271；pkill '.b0s' 引用 0x4303C5
> 
> **来源**：`ref:e67796d665` · `ref:5cfe41c619`

### 9. 篡改sshd会话门

`T1556` · 置信度 **高** · 静态

修改 /etc/ssh/sshd_config，写入 ForceCommand 调用 /usr/local/sbin/ssh-session-gate，并禁用 X11/Agent 转发；会话门读取 SSH_ORIGINAL_COMMAND，包装 scp/rsync/sftp-server，可劫持或记录 SSH 会话命令。

> **证据**：sshd_config 引用 0x44A099 与 0x4329D2；main 在 0x402925 检查 ssh-session-gate 路径、0x402939 读取 SSH_ORIGINAL_COMMAND/SSH_TTY
> 
> **来源**：`ref:5cfe41c619` · `ref:5d344ce76f` · `ref:e67796d665`

### 10. 布置防火墙自保

`T1562.004` · 置信度 **高** · 静态

安装 iptables 与 fail2ban，写入 jail.local（maxretry=3、bantime=-1、banaction=iptables-multiport、ignorecommand=/bin/false），以永久封禁方式压制扫描与竞争访问。

> **证据**：fail2ban/iptables 命令串 off 1380271
> 
> **来源**：`ref:e67796d665`

### 11. 内置加密二阶段

`T1027.009` · 置信度 **中** · 静态

文件偏移 0x1634B8 处嵌入第二个 ELF64 头（ET_EXEC、x86-64、entry 0xC1F400、phnum=3、无节头），其后 1,133,384 字节块熵为 8.00，疑为加密或压缩的二阶段载荷，当前未解密。

> **证据**：内置 ELF 头 off 0x1634B8；块熵 8.00；整体熵 7.424
> 
> **来源**：`ref:5cfe41c619`

### 12. 回连80端口探活

`T1071.001` · 置信度 **中** · 静态

构造 HTTP 请求访问 runtime 主机的 80 端口路径 /f/m/.X0-lock_，并伴随 server::alive 探活逻辑；目标主机在静态数据中不可见，推断由运行期配置或外部解析获得。

> **证据**：lea rdx,[rip+0x11d8e6] @0x433C3E 指向 /f/m/.X0-lock_；server::alive 引用 0x4342BE；hxxp://、:80 紧随同一字符串区
> 
> **来源**：`ref:5cfe41c619` · `ref:e67796d665`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `pool-fr[.]supportxmr[.]com` | 5555 | c2 | 静态 | — |
| tcp | `pool-phx[.]supportxmr[.]com` | 5555 | c2 | 静态 | — |
| tcp | `pool-nyc[.]supportxmr[.]com` | 5555 | c2 | 静态 | — |
| tcp | `pool-hk[.]supportxmr[.]com` | 5555 | c2 | 静态 | — |
| tcp | `pool-sg[.]supportxmr[.]com` | 5555 | c2 | 静态 | — |
| tcp | `pool-aus[.]supportxmr[.]com` | 5555 | c2 | 静态 | — |
| tcp | `pool-ca[.]supportxmr[.]com` | 5555 | c2 | 静态 | — |
| http | `hxxp://[runtime-host]:80/f/m/.X0-lock_` | 80 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/var/tmp/snap`
- `/var/tmp/snapd`
- `$HOME/.X0-lock`
- `/usr/local/libexec/libbase.sh`
- `/etc/profile.d/libbase.sh`
- `/etc/profile.d/libcommon.csh`
- `/usr/local/lib/libcommon.so`
- `/usr/local/lib/libcommon.so.bak`
- `/usr/local/sbin/ssh-session-gate`
- `/usr/local/bin/system-helper-run`
- `/etc/systemd/system/system-helper.service`
- `/etc/systemd/system/system-helper.timer`
- `/etc/cron.d/system-helper`
- `/etc/ld.so.preload`
- `/etc/fail2ban/jail.local`
- `/bin/sh.bak`
- `/etc/ssh/sshd_config`

**服务**

- `system-helper.service`
- `system-helper.timer`

**计划任务**

- `@reboot [ -f /var/tmp/snap ] && chmod +x /var/tmp/snap && /var/tmp/snap`
- `@reboot [ -f /var/tmp/snapd ] && chmod +x /var/tmp/snapd && /var/tmp/snapd`
- `@reboot [ -f $HOME/.X0-lock ] && chmod +x $HOME/.X0-lock && $HOME/.X0-lock`
- `* * * * * [ -f /var/tmp/snap ] && chmod +x /var/tmp/snap && /var/tmp/snap`
- `* * * * * [ -f /var/tmp/snapd ] && chmod +x /var/tmp/snapd && /var/tmp/snapd`
- `* * * * * [ -f $HOME/.X0-lock ] && chmod +x $HOME/.X0-lock && $HOME/.X0-lock`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `pool-fr[.]supportxmr[.]com:5555, pool-phx[.]supportxmr[.]com:5555, pool-nyc[.]supportxmr[.]com:5555, pool-hk[.]supportxmr[.]com:5555, pool-sg[.]supportxmr[.]com:5555, pool-aus[.]supportxmr[.]com:5555, pool-ca[.]supportxmr[.]com:5555` | 是 | 静态 |
| `mining_algo` | `rx/0 (RandomX, Monero/XMR)` | 是 | 静态 |
| `donate_level` | `0` | 否 | 静态 |
| `pool_password` | `16` | 否 | 静态 |
| `beacon_path` | `/f/m/.X0-lock_` | 是 | 静态 |
| `persistence_entry` | `/usr/local/libexec/libbase.sh (via /etc/profile.d/libbase.sh, ~/.bashrc, ~/.zshrc, /bin/sh wrapper)` | 是 | 静态 |
| `preload_library` | `/usr/local/lib/libcommon.so via /etc/ld.so.preload` | 否 | 静态 |
| `mining_wallet` | `-` | 是 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不应报告为勒索软件：未发现文件加密、扩展名改写或赎金提示代码，行为集中在 CPU 挖矿与持久化。
- 不应报告为凭据窃取器：未观察到读取浏览器密码库、钱包文件、SSH 私钥或系统凭据的逻辑。
- 不应据此断言具备 SSH 爆破/横向蠕虫能力：静态数据中未见密码字典、known_hosts 扫描或批量认证代码。
- 默认 supportxmr 矿池不等于实际收款地址：矿池列表是内置配置模板，真实矿池/钱包可能被运行期配置覆盖且未在样本中明文出现。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次为纯静态分析，未在隔离主机引爆样本，未观测到实际进程、网络连接或文件落地行为；相关结论均来自结构、字符串与指令级证据。
2. 未能静态确定真实矿池账户与收款钱包；内置 supportxmr 列表可能只是 XMRig 默认模板。
3. HTTP 探活路径的主机部分由运行期配置/解析决定，静态数据中无明文 C2 域名或 IP。
4. 文件偏移 0x1634B8 处的第二阶段 ELF 主体为高熵加密/压缩数据，未脱壳或解密，其功能未知。
5. 未获得厂商引擎、YARA 规则或多引擎命名佐证，家族名称为候选且存在不确定性。
6. 部分脚本字符串在样本中以拼接或转义形式存在，报告按可读语义还原，个别路径/参数可能存在运行期变量替换。

## 证据索引

<details>
<summary>展开 8 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:98eb859d23` | ELF 结构解析 | ELF64 x86-64 EXEC，静态链接，entry 0x4070D7，两个 LOAD 段、GNU_STACK RWX，无节头/符号/导入，异常 shdr_oob。 |
| `ref:a9b8e93f9c` | elf.sections | 段表确认 R-X 与 RW- LOAD、TLS、GNU_RELRO、RWX GNU_STACK；无节表。 |
| `ref:756fa2f42e` | 字符串提取 | 首轮字符串抽取（3119 条 ASCII），命中 hugepages/随机化字母表等字符串。 |
| `ref:e67796d665` | 字符串提取 | 长字符串抽取：XMRig 配置模板、7 个 supportxmr 矿池、cron/systemd/libbase/sshd/LD_PRELOAD/反取证等持久化字符串及偏移。 |
| `ref:5d344ce76f` | decompile.function | main @0x4027EE 反编译：分发 --libbase-run、检测 /usr/local/sbin/ssh-session-gate、读取 SSH_ORIGINAL_COMMAND/SSH_TTY、包装 sftp/rsync/scp。 |
| `ref:cf57a551da` | disasm.function | main 入口指令流，确认参数检查与 ssh-session-gate 字符串引用。 |
| `ref:b30fde2b2b` | decompile.symbols | 静态 ELF 中识别 3044 个函数，主体为 C++（libuv/XMRig 风格），无可读符号。 |
| `ref:5cfe41c619` | evidence.record | 指令级交叉引用定位安装/持久化/探活/sshd 函数地址；定位并测量内置加密 ELF 二阶段（0x1634B8，1,133,384 字节，块熵 8.00）。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
