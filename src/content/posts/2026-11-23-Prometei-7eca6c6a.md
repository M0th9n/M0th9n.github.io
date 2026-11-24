---
title: "恶意样本分析：Prometei（ELF · elf · 7eca6c6a）"
published: 2026-11-23
draft: false
description: "恶意（置信度高）：Prometei · botnet/miner/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Prometei", "botnet", "miner", "downloader", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Prometei** · 置信度 **高**
> 
> 别名：Prometei botnet、PROMETEI、Prometei miner
> 
> 样本为 UPX 加壳的 Linux x86-64 程序，脱壳后包含完整的 P2P/CGI C2 客户端、crontab 与 systemd 持久化代码、模块下载接口和挖矿控制命令；硬编码 prometei.cgi 的 Tor/I2P/CGI 端点，并在隔离动态环境中实际启动、尝试写入 crontab、修改 /etc/hosts 和监听 TCP/89。静态与动态证据相互印证，判定为恶意。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Prometei** · 别名 Prometei botnet、PROMETEI、Prometei miner |
| 置信度 | **高** |
| 行为类 | botnet · miner · downloader |
| 难度 | medium |
| 首次出现 | 2026-11-22 22:29:53 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/7eca6c6addbaa2a42e035427ad71a131c994acf3d07cebe7a381657630403d8f/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">自解压 UPX 载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">读取节点配置</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">回连 CGI C2</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">解析 CMDv2 指令</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">监听 89 端口</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `7eca6c6addbaa2a42e035427ad71a131c994acf3d07cebe7a381657630403d8f` |
| MD5 | _未记录_ |
| 大小 | 449,079 字节（438.6 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **12** 条行为，每条都挂了证据；其中 **7** 条静态可得、**5** 条经动态分析取得。

### 1. 自解压 UPX 载荷

`T1027` · 置信度 **高** · 动态

样本以 UPX 4.2.4 加壳；启动后从 /proc/self/exe 读取自身并由入口 stub 解压约 1.29MB 的静态 ELF 主体，再将代码段 mprotect 为可执行。

> **证据**：packed entry 0x15EB650；动态 trace: mmap(0x401000,1049681) + mprotect(PROT_READ|PROT_EXEC)
> 
> **来源**：`ev-000017` · `ev-000011`

### 2. 读取节点配置

`T1027` · 置信度 **高** · 静态

解析附加 JSON 配置（config/id/enckey/ParentId/ip/ParentIp/ParentHostname），并通过 /proc/<pid>/exe、/usr/sbin/uplugplay、/etc/uplugplay 定位自身与配置。

> **证据**：FUN_00425fcb @0x425fcb 中 '/proc/%d/exe'；JSON 位于文件偏移 0x6d8f0
> 
> **来源**：`ev-000059` · `ev-000012`

### 3. 回连 CGI C2

`T1071.001` · 置信度 **高** · 静态

向 C2 发送 HTTP GET /cgi-bin/p.cgi?r=0&auth=hash&i=<id>&enckey=<blob>，使用 SHA-256 计算的 auth 令牌和 base64 enckey 完成节点认证。

> **证据**：FUN_0041a8b4 @0x41a8b4；字符串 0x502aa0
> 
> **来源**：`ev-000013` · `ev-000059` · `ev-000008`

### 4. 解析 CMDv2 指令

`T1071.001` · 置信度 **高** · 静态

P2P 会话读取以 '_CMDv2_;<len>:' 开头的命令帧并分发（配置更新、模块下发、启停挖矿），同时用 HTTP/1.1 info 头交换节点信息。

> **证据**：FUN_0042076d @0x42076d；字符串 0x502f69 '_CMDv2_;%d:'
> 
> **来源**：`ev-000014` · `ev-000062`

### 5. 监听 89 端口

`T1571` · 置信度 **高** · 动态

启动后创建 TCP 套接字并尝试 bind 0.0.0[.]0:89、listen(4096)，作为 P2P 节点接收对端命令；非特权运行下 bind 返回 EACCES。

> **证据**：动态 trace: bind(sin_port=htons(89), 0.0.0[.]0) = -EACCES; listen(22,4096)
> 
> **来源**：`ev-000017` · `ev-000058`

### 6. 写入 cron 自启动

`T1053.003` · 置信度 **高** · 动态

执行 crontab -l，构造 '@reboot <self> -cron'（task.cron）并回写 crontab -，尝试在重启后自动运行；动态环境因 /var/spool/cron 权限被拒。

> **证据**：FUN_00423701 @0x423701；动态 stderr: crontabs/analyst/: fopen: Permission denied
> 
> **来源**：`ev-000015` · `ev-000017`

### 7. 安装 systemd 服务

`T1543.002` · 置信度 **高** · 静态

生成 /lib/systemd/system/uplugplay.service（Description=UPlug, Type=forking, ExecStart=/usr/sbin/uplugplay），并调用 systemctl daemon-reload/enable/start/stop 管理服务。

> **证据**：字符串 0x424095 '[Unit]'、0x4241a5 '/lib/systemd/system/uplugplay.service'、systemctl 命令串
> 
> **来源**：`ev-000005`

### 8. 篡改 hosts 文件

`T1565.001` · 置信度 **高** · 动态

运行期间以 O_WRONLY|O_CREAT|O_APPEND 打开 /etc/hosts，意图写入域名映射；动态环境因非特权返回 EACCES。

> **证据**：动态 trace: openat('/etc/hosts', O_WRONLY|O_CREAT|O_APPEND) = -EACCES
> 
> **来源**：`ev-000017` · `ev-000062`

### 9. 下载并投放模块

`T1105` · 置信度 **中** · 静态

内置 HTTP 客户端/服务端支持 Content-disposition 附件下发、fgetnormal 与 sha256hash 校验，可从 C2 拉取并投放 Prometei 模块。

> **证据**：字符串 0x502d38 'Content-disposition: attachment; filename=%s'、0x502ccf 'fgetnormal'、0x502db8 'sha256hash: %s'
> 
> **来源**：`ev-000062` · `ev-000013`

### 10. 控制挖矿任务

`T1496` · 置信度 **中** · 静态

实现 start_mining/stop_mining 命令，并读取 /proc/stat、CPU/内存信息；代码内构造 HashPowerProject 相关哈希常量，用于挖矿子模块控制。

> **证据**：字符串 0x502f5b 'start_mining'、0x503199 'stop_mining'；FUN_00410a6b @0x410a6b
> 
> **来源**：`ev-000062` · `ev-000066`

### 11. 收集主机指纹

`T1082` · 置信度 **高** · 静态

读取 /etc/os-release、/etc/redhat-release、/etc/debian_version、/proc/cpuinfo、/proc/meminfo、/etc/resolv.conf，并调用 hostnamectl/dmidecode 收集硬件与虚拟化信息，随 info 头回传。

> **证据**：字符串 0x502xxx；FUN_0042076d 的 'info: %s,%s\\%s,...' 头
> 
> **来源**：`ev-000062` · `ev-000014`

### 12. 伪装合法进程名

`T1036.005` · 置信度 **高** · 动态

启动时检查 /usr/sbin/msdtc、msdtc2、msdtc3，并使用 uplugplay/upnpsetup/walker/updatecheckerd/pdefenderd/crashdump 等名称伪装或兼容；动态观测到对 /usr/sbin/msdtc* 的 openat。

> **证据**：动态 trace: openat('/usr/sbin/msdtc')/msdtc2/msdtc3 = ENOENT；服务名列表 0x42478c
> 
> **来源**：`ev-000017` · `ev-000005`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://45[.]55[.]121[.]171/cgi-bin/p.cgi` | 80 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxp://103[.]176[.]111[.]176/cgi-bin/p.cgi` | 80 | c2 | 静态 | ⏳ 未观测 |
| other | `hxxps://gb7ni5rgeexdcncj[.]onion/cgi-bin/prometei.cgi` | 443 | c2 | 静态 | ⏳ 未观测 |
| other | `hxxp://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq[.]b32[.]i2p/cgi-bin/prometei.cgi` | 80 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/usr/sbin/uplugplay`
- `/etc/uplugplay`
- `/etc/CommId`
- `/lib/systemd/system/uplugplay.service`
- `/etc/hosts`
- `/tmp/debug.txt`
- `/etc/pcc0`
- `/etc/pcc1`
- `.ssh/pcc0`

**服务**

- `uplugplay.service`
- `进程伪装名: uplugplay, upnpsetup, walker, netwalker, updatecheckerd, pdefenderd, crashdump, msdtc, msdtc2, msdtc3, smcard, smcard2, zsvc, nvsync`

**计划任务**

- `crontab: @reboot <self> -cron (task.cron)`
- `systemd: uplugplay.service (Type=forking, ExecStart=/usr/sbin/uplugplay)`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `45[.]55[.]121[.]171; 103[.]176[.]111[.]176; gb7ni5rgeexdcncj[.]onion; mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq[.]b32[.]i2p` | 是 | 静态 |
| `c2_port` | `80 (HTTP); 443 (onion); 本地 P2P 监听 89` | 否 | 静态 |
| `c2_uri` | `/cgi-bin/p.cgi; /cgi-bin/prometei.cgi` | 是 | 静态 |
| `node_id` | `IBQulJI4geplOAxw` | 是 | 静态 |
| `parent_id` | `3NM4VHR5SU73YP72HV` | 是 | 静态 |
| `parent_host` | `192[.]168[.]2[.]8 (W19-DC01)` | 否 | 静态 |
| `enckey` | `base64 blob（128/129 字节），用于 auth=hash&enckey= 握手` | 是 | 静态 |
| `encryption_algo` | `SHA-256 (auth=hash) + base64 编码 enckey` | 否 | 静态 |
| `version` | `v4.42V_Unix64` | 否 | 静态 |
| `install_paths` | `/usr/sbin/uplugplay; /etc/uplugplay; /lib/systemd/system/uplugplay.service` | 否 | 静态 |
| `persistence` | `crontab @reboot <self> -cron; systemd uplugplay.service` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭硬编码的 prometei.cgi 与 p.cgi 就断言已与真实 C2 建立会话；本次仅观察到监听与连接逻辑，未取得完整 HTTP 请求/响应。
- 不能把 192.168.2[.]8 / W19-DC01 当作公网 C2；它是配置中的父节点/内网主机信息。
- 不能声称已成功写入 crontab 或创建 systemd 服务；动态运行以非特权用户执行，相关写入被系统拒绝。
- 不能把 HashPowerProject 当作已确认的矿池域名或钱包；未提取到 stratum 地址或钱包地址。
- 不要将其误判为单纯 UPX 壳或通用下载器；脱壳后主体含完整 P2P/C2、持久化与挖矿控制逻辑。
- 不要把动态中的 bind EACCES 当作无网络行为；网络命名空间被隔离，未见成功外联。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 是（stage2 `7d544e1c6d2e27906d3164c506d6778f901ea959d4d8b7e8a0f6b3cf6cef7c7a`） |

**局限与待验证**

1. 动态运行以非特权 analyst 身份执行，crontab/systemd 写入被拒，未能验证重启持久化的完整成功路径。
2. 网络处于隔离命名空间，仅观察到 socket/bind 与连接逻辑，未获得 connect 成功或 HTTP 会话；所有 C2 均标记为 static 且 pending_dynamic_verify。
3. 配置中的 enckey 为 base64 blob（约 128 字节），其具体解密/签名用途尚未完全还原。
4. 未取得矿池地址、钱包地址或独立的挖矿子模块；start_mining/stop_mining 仅证明命令能力。
5. 样本删除了 section 头并在 UPX 流后附加 JSON overlay，标准 UPX 工具需截断 overlay 后才能脱壳；脱壳产物仅用于静态分析。
6. 未观察到成功 C2 会话，因此不能确认当前 C2 基础设施仍在线。

## 证据索引

<details>
<summary>展开 19 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000059` | 字符串提取 | 原始样本末尾提取到附加 JSON 配置（id/enckey/ParentId/ip/ParentIp/ParentHostname） |
| `ev-000060` | 字符串提取 | 原始样本字符串总览，含 UPX 4.24 标识与配置 JSON |
| `ev-000001` | 字符串提取 | 原始样本 ASCII 字符串与 flag 正则抽样 |
| `ev-000017` | dyn.exec | 隔离动态运行：stdout Starting.../Usermode install...Fail；stderr crontab 权限拒绝；trace 显示 bind 0.0.0[.]0:89 |
| `ev-000058` | dyn.exec | 隔离动态运行复现，确认 crontab 持久化尝试与 TCP/89 监听循环 |
| `b4723d4005` | dyn.trace | strace 追踪：读取自身 ELF、检查 /usr/sbin/msdtc*、写 /etc/hosts 被拒、读取 /etc/CommId、寻找 uplugplay 路径 |
| `ev-000012` | decompile.ghidra | 反编译主函数 0x425fcb：配置/路径解析、cron/systemd 安装、命令分发、挖矿控制 |
| `ev-000013` | decompile.ghidra | 反编译 0x41a8b4：auth=hash 的 CGI C2 握手与 enckey 使用 |
| `ev-000014` | decompile.ghidra | 反编译 0x42076d：P2P 连接、info 头、_CMDv2_ 命令帧解析 |
| `ev-000015` | decompile.ghidra | 反编译 0x423701：crontab -l / @reboot ... -cron / crontab - 持久化 |
| `ev-000062` | 字符串提取 | 脱壳主体字符串：C2 URI 模板、start_mining/stop_mining、systemd/cron、指纹采集 |
| `ev-000066` | decompile.ghidra | 反编译 0x410a6b：HashPowerProject 相关哈希常量构造 |
| `ev-000011` | decompile.ghidra | 入口 _start 与 __libc_start_main 调用 |
| `ev-000005` | 字符串提取 | 脱壳主体字符串总览：systemd unit、服务名列表、伪装/持久化路径 |
| `ev-000008` | 密码学常量识别 | SHA-256 常量命中，支持 auth=hash 与 sha256hash 校验 |
| `ev-000010` | 密码学常量识别 | base64 字母表命中，支持 enckey 编码 |
| `0769cd66e8` | unpack/upx script | 截断 UPX trailer 后附加 JSON overlay 并成功脱壳，得到 1,288,624 字节主体 |
| `ffc7d39167` | 哈希与指纹 | 原始样本 sha256/md5/sha1 与大小 |
| `afc547daf7` | ELF 结构解析 | 原始样本 ELF 结构：x86-64 EXEC、UPX 双 LOAD、无 section 头 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
