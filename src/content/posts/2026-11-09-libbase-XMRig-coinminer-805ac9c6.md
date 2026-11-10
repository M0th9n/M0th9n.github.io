---
title: "恶意样本分析：libbase XMRig coinminer（ELF · elf · 805ac9c6）"
published: 2026-11-09
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
> 样本内置完整 XMRig/RandomX 门罗币挖矿引擎，并携带 system-helper 服务、cron 每分钟自启、libbase.sh 登录 Shell 劫持、/etc/ld.so.preload 预加载、sshd ForceCommand 会话门、fail2ban 永久封禁自保、竞争矿工清理与日志清除等代码与脚本；另有 XOR 0x5A 混淆的 C2 配置（两个 IP 与 project0[.]cc）及嵌入的加密 ELF 二阶段。挖矿牟利与长期驻留意图明确。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **libbase XMRig coinminer** · 别名 XMRig-based Linux coinminer、system-helper miner、snapd/snap masquerading miner、ssh-session-gate backdoor · _存疑_ |
| 置信度 | **中** |
| 行为类 | miner · backdoor |
| 难度 | medium |
| 首次出现 | 2026-11-07 15:02:26 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/805ac9c67e7b44520283963ac357d6f2b9a84291a0086ac4e02caf56aeaeed23/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">内置门罗币挖矿引擎</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1496</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">劫持登录Shell会话</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1546.004</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">每分钟拉起守护进程</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">伪装systemd助手服务</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">预加载恶意共享库</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.006</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `805ac9c67e7b44520283963ac357d6f2b9a84291a0086ac4e02caf56aeaeed23` |
| MD5 | _未记录_ |
| 大小 | 1,703,936 字节（1.6 MB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **12** 条行为，每条都挂了证据，且全部静态可得。

### 1. 内置门罗币挖矿引擎

`T1496` · 置信度 **高** · 静态

静态链接完整 XMRig/RandomX 挖矿引擎，含 rx/0 算法、MSR/huge pages 优化、7 个 supportxmr 矿池与 donate-level=0 的内置配置模板。

> **证据**：0x552280 'RandomX'，0x551773 'no valid configuration found, try hxxps://xmrig[.]com/wizard'，0x54fc43 起 cron 与 0x552xxx 配置模板
> 
> **来源**：`ref:1230379508` · `ref:3a1200a943`

### 2. 劫持登录Shell会话

`T1546.004` · 置信度 **高** · 静态

main 识别 --libbase-run 参数并进入 libbase.sh 包装逻辑，向 /usr/local/libexec/libbase.sh、/etc/profile.d、~/.bashrc、~/.zshrc 写入启动钩子，备份并替换 /bin/sh（/bin/sh.bak），交互式 Shell 启动时被接管。

> **证据**：0x402812 lea rsi,'--libbase-run'；0x40284f lea rsi,'libbase.sh'；0x402976 lea r13,'/bin/sh'
> 
> **来源**：`ref:3a1200a943` · `ref:1230379508`

### 3. 每分钟拉起守护进程

`T1053.003` · 置信度 **高** · 静态

向用户 crontab 写入 @reboot 与 * * * * * 任务，周期执行 /var/tmp/snap、/var/tmp/snapd、$HOME/.X0-lock，实现重启与每分钟自愈。

> **证据**：0x54fc43 / 0x54fcd6 起六条 cron 行；0x5503d5 '/etc/cron.d/system-helper'
> 
> **来源**：`ref:1230379508`

### 4. 伪装systemd助手服务

`T1543.002` · 置信度 **高** · 静态

写入 system-helper.service（Type=oneshot，ExecStart=/usr/local/bin/system-helper-run）与 system-helper.timer（OnBootSec=0、每分钟），伪装为系统助手实现开机与周期驻留。

> **证据**：0x55018c unit 文本；0x550227 timer 文本；0x5502b2/0x5502dc unit 路径
> 
> **来源**：`ref:1230379508`

### 5. 预加载恶意共享库

`T1574.006` · 置信度 **高** · 静态

写入 /usr/local/lib/libcommon.so 并保留 .bak，通过 LD_PRELOAD 与 /etc/ld.so.preload 强制加载，具备用户态劫持与隐藏能力。

> **证据**：0x550017 '/etc/ld.so.preload'；0x54fe35 'libcommon.so'；0x54fe2x 'LD_PRELOAD='
> 
> **来源**：`ref:1230379508`

### 6. 隐藏任务与监控进程

`T1014` · 置信度 **高** · 静态

在登录 Shell 中覆盖 top、crontab、kill 命令：top 过滤含 16 与 libbase.sh 的行，crontab 读写时隐藏 snap/snapd/.X0-lock 条目，kill -9 被改写为不发送 SIGKILL，使用户难以发现驻留与挖矿进程。

> **证据**：0x550428 top 包装；0x550659 crontab 包装；0x5509d4 kill 包装
> 
> **来源**：`ref:1230379508`

### 7. 清除历史与系统日志

`T1070.003` · 置信度 **高** · 静态

执行 pkill 清理 b0s/yum.log/apt.log 相关进程，并删除 $HOME/.bash_history、/var/tmp/apt.log、/var/tmp/yum.log，降低取证与追溯概率。

> **证据**：0x550c3b 'pkill -9 -f .b0s; ... rm -f $HOME/.bash_history /var/tmp/apt.log /var/tmp/yum.log'
> 
> **来源**：`ref:1230379508`

### 8. 清除竞争挖矿进程

`T1489` · 置信度 **高** · 静态

通过 ps/pgrep 查找 comm 为 16 的同名进程，保留 CPU 占用最高者并杀掉其余实例；同时清理 nvidia-smi 中 ./init 等竞争挖矿进程，独占受害主机算力。

> **证据**：0x403426 ps 命令；0x550bdf nvidia-smi 清理；0x550d64 pgrep -x 16
> 
> **来源**：`ref:3a1200a943` · `ref:1230379508`

### 9. 篡改sshd会话门

`T1556` · 置信度 **高** · 静态

在 main 中检查 /usr/local/sbin/ssh-session-gate 并读取 SSH_ORIGINAL_COMMAND/SSH_TTY，包装 sftp-server、rsync、scp 调用；样本内另有 sshd_config 与 ForceCommand 字符串，显示对 SSH 会话的门控与劫持能力。

> **证据**：0x402916 lea rsi,'/usr/local/sbin/ssh-session-gate'；0x40292d 'SSH_ORIGINAL_COMMAND'；0x402939 'SSH_TTY'；0x55270e 'sshd_config'
> 
> **来源**：`ref:3a1200a943` · `ref:1230379508`

### 10. 防火墙与封禁自保

`T1562.004` · 置信度 **高** · 静态

安装 iptables 与 fail2ban，写入 jail.local（maxretry=3、bantime=-1、banaction=iptables-multiport、ignorecommand=/bin/false），以永久封禁方式压制扫描与竞争访问。

> **证据**：0x550faf 起 fail2ban/iptables 命令串；0x551199 '/etc/fail2ban/jail.local'
> 
> **来源**：`ref:1230379508`

### 11. 回连C2探活与取载

`T1071.001` · 置信度 **中** · 静态

内置 XOR 0x5A 混淆的配置字段（两个 IPv4：169.58.248[.]162、5.189.149[.]171，域名 project0[.]cc，96 字符令牌），并以 :80/f/m/.X0-lock_ 路径与 server::alive 状态字构造 HTTP 探活/取载请求。

> **证据**：0x1520C8/0x1520D8/0x1520E8/0x153940 XOR 0x5A 解出 IP/域名/令牌；0x55152b ':80/f/m/.X0-lock_'；0x55153d 'server::alive'
> 
> **来源**：`ref:bf524934c6` · `ref:1230379508`

### 12. 内置加密二阶段载荷

`T1027.009` · 置信度 **中** · 静态

在 0x1634B8 处嵌入第二个 ELF64 头（ET_EXEC、x86-64、entry 0xC1F400、phnum=3、无节头），其后区块熵约 8.0，疑为加密/压缩的二阶段载荷；本样本中该嵌入体亦被截断。

> **证据**：0x1634b8 嵌入 ELF 头；0x16xxxx-0x19xxxx 熵 7.8-8.0；现存二阶段 248,648 字节
> 
> **来源**：`ref:bf524934c6` · `ref:32cc11dc7d`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://169.58.248[.]162/f/m/.X0-lock_` | 80 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxp://5.189.149[.]171/f/m/.X0-lock_` | 80 | c2 | 静态 | ⏳ 未观测 |
| dns | `project0[.]cc` | - | c2 | 静态 | ⏳ 未观测 |
| tcp | `pool-fr[.]supportxmr[.]com` | 5555 | c2 | 静态 | ⏳ 未观测 |
| tcp | `pool-phx[.]supportxmr[.]com` | 5555 | c2 | 静态 | ⏳ 未观测 |
| tcp | `pool-nyc[.]supportxmr[.]com` | 5555 | c2 | 静态 | ⏳ 未观测 |
| tcp | `pool-hk[.]supportxmr[.]com` | 5555 | c2 | 静态 | ⏳ 未观测 |
| tcp | `pool-sg[.]supportxmr[.]com` | 5555 | c2 | 静态 | ⏳ 未观测 |
| tcp | `pool-aus[.]supportxmr[.]com` | 5555 | c2 | 静态 | ⏳ 未观测 |
| tcp | `pool-ca[.]supportxmr[.]com` | 5555 | c2 | 静态 | ⏳ 未观测 |

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
| `c2_hosts` | `169.58.248[.]162, 5.189.149[.]171, project0[.]cc` | 是 | 静态 |
| `beacon_path` | `/f/m/.X0-lock_` | 是 | 静态 |
| `c2_port` | `80` | 否 | 静态 |
| `mining_algo` | `rx/0 (RandomX/Monero)` | 是 | 静态 |
| `mining_pools` | `pool-fr/phx/nyc/hk/sg/aus/ca[.]supportxmr[.]com:5555` | 否 | 静态 |
| `donate_level` | `0` | 否 | 静态 |
| `string_obfuscation` | `单字节 XOR 0x5A` | 是 | 静态 |
| `bot_token` | `89PNDJssF3RbL6m7aSydYB4tLrvjZ28Cr8n4LucmFHat8botWkWr6oDPEaSHfeZn4wfA3dC5QsE7nZV1P6tE81sK2i9heamZ` | 否 | 静态 |
| `install_path` | `/usr/local/libexec/libbase.sh` | 是 | 静态 |
| `preload_library` | `/usr/local/lib/libcommon.so` | 否 | 静态 |
| `mining_wallet` | `-` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不应报告为勒索软件：未见文件加密、扩展名改写或赎金提示逻辑，行为集中在挖矿与持久化。
- 不应报告为凭据窃取器：未见浏览器密码库、钱包文件、SSH 私钥读取逻辑。
- 不应据此断言具备 SSH 爆破/蠕虫式横向传播能力：静态数据中未见字典、known_hosts 扫描或批量认证代码。
- 不应把内置 supportxmr 矿池列表当作实际收款矿池或钱包：该列表是 XMRig 默认配置模板，真实钱包未在样本中明文出现。
- 不应断言 C2 当前存活或已建立会话：仅静态恢复出 IP/域名与探活路径，未进行任何真实网络交互。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 样本被截断（文件大小仅为 ELF 首段声明的一半左右），RW 数据段、后半代码与大部分嵌入二阶段缺失，无法运行或仿真验证，相关结论仅限现存字节。
2. 本次未进行真实动态引爆，未观察到进程、文件落地或网络会话；C2 与配置均标记为静态恢复、待动态验证。
3. 96 字符配置令牌使用同一 XOR 密钥保护的自定义 base64 字母表编码，尚未解出其明文，无法确认它是钱包、机器人 ID 还是加密配置。
4. 未在样本中找到明文门罗钱包地址；内置 supportxmr 矿池可能被运行期参数覆盖。
5. 家族名称来自字符串组合与既有社区命名，缺少厂商引擎/YARA 命名佐证，存在不确定性。
6. 引用 C2/探活路径的代码位于被截断的后半段，未能给出该配置的调用点指令级证据。

## 证据索引

<details>
<summary>展开 8 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:dd9a6af2bc` | ELF 结构解析 | ELF64 x86-64 EXEC，静态链接，entry 0x407017，两个 LOAD 段、TLS、GNU_RELRO、RWX GNU_STACK，无节头/符号/导入，shdr 越界异常。 |
| `ref:65131aaf08` | elf.sections | 段表确认 R-X 与 RW- LOAD、TLS、GNU_RELRO、RWX GNU_STACK，无节表。 |
| `ref:1230379508` | 字符串提取 | 抽取 3955 条 ASCII 字符串，含 XMRig 配置模板、supportxmr 矿池、cron/systemd/libbase/sshd/LD_PRELOAD/fail2ban/反取证脚本与路径。 |
| `ref:32cc11dc7d` | scan.entropy | 整体熵 6.859；嵌入二阶段区块熵约 8.0。 |
| `ref:f345abc908` | 密码学常量识别 | 识别标准与 URL-safe base64 字母表常量，与自定义编码表位置一致。 |
| `ref:b99c135240` | disasm.function | 入口 0x407017 指令流：__libc_start_main(main=0x4027EE)。 |
| `ref:3a1200a943` | disasm.function | main 0x4027EE 反汇编：--libbase-run 分发、libbase.sh 安装、ssh-session-gate、SSH_ORIGINAL_COMMAND/SSH_TTY、sftp/rsync/scp 包装、IP 探测与 '16' 进程清理。 |
| `ref:bf524934c6` | evidence.record | 自写脚本：确认样本截断（1,703,936 vs 3,325,013）、嵌入 ELF 二阶段（0x1634B8，entry 0xC1F400）、XOR 0x5A 解出两个 C2 IP、project0[.]cc 与 96 字符令牌。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
