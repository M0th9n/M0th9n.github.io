---
title: "恶意样本分析：Unclassified Go-based Linux tunnel/backdoor (custom bridge implant)（ELF · elf · 17485b17）"
published: 2026-11-01
draft: false
description: "恶意（置信度低）：Unclassified Go-based Linux tunnel/backdoor (custom bridge implant) · backdoor/implant · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["backdoor", "implant", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unclassified Go-based Linux tunnel/backdoor (custom bridge implant)**（存疑） · 置信度 **低**
> 
> 别名：Go bridge implant、smux-based Linux backdoor
> 
> 隔离 Linux 动态分析中观察到样本启动后立即向硬编码 154.36.183[.]100:18089 发起 TCP 连接并持续重连；静态同时可见 systemd/upstart/init.d/OpenRC 服务持久化模板、busybox 调用、历史清理与 LD_PRELOAD 线索，符合远程控制/隧道后门特征。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unclassified Go-based Linux tunnel/backdoor (custom bridge implant)** · 别名 Go bridge implant、smux-based Linux backdoor · _存疑_ |
| 置信度 | **低** |
| 行为类 | backdoor · implant |
| 难度 | medium |
| 首次出现 | 2026-10-30 00:06:09 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/17485b175a4ca46adbce11efa571f875fb530922b9cc7d5ad60078846ce0f603/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">外联硬编码C2</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">五秒重连保活</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1008</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">安装系统服务自启</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">写入inittab持久化</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1037.004</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">部署busybox工具</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.004</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `17485b175a4ca46adbce11efa571f875fb530922b9cc7d5ad60078846ce0f603` |
| MD5 | _未记录_ |
| 大小 | 7,864,320 字节（7.5 MB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **12** 条行为，每条都挂了证据；其中 **10** 条静态可得、**2** 条经动态分析取得。

### 1. 外联硬编码C2

`T1095` · 置信度 **高** · 动态

启动后向 154.36.183[.]100:18089 发起 TCP 连接；连接失败仍持续尝试。

> **证据**：系统调用追踪 connect(6, {sa_family=AF_INET, sin_port=htons(18089), sin_addr=inet_addr("154.36.183[.]100")}) 多次出现
> 
> **来源**：`ev-000023` · `ev-000027` · `ev-000030` · `ev-000036`

### 2. 五秒重连保活

`T1008` · 置信度 **中** · 动态

连接失败或服务端数据异常后按约 5 秒间隔重连，维持 C2 通道。

> **证据**：字符串 "Error data from server, and will be reconnected in five seconds"@0x4bccaa 与 "The connection server failed and will be reconnected in five seconds, error"@0x4be4c8；动态多次 connect
> 
> **来源**：`ev-000045` · `ev-000023` · `ev-000027`

### 3. 安装系统服务自启

`T1543.002` · 置信度 **高** · 静态

内嵌 systemd/upstart/init.d/OpenRC 服务模板，可将自身注册为系统服务实现开机自启。

> **证据**：服务模板 ExecStart={{.Path|cmdEscape}}@0x4c0651、#!/sbin/openrc-run@0x4bfff7、### BEGIN INIT INFO@0x4c0a25；/etc/init.d/@0x4a5b2b
> 
> **来源**：`ev-000044` · `ev-000043`

### 4. 写入inittab持久化

`T1037.004` · 置信度 **中** · 静态

引用 /etc/inittab 与 /etc/init.d/，具备通过传统 init 脚本/inittab 实现持久化的能力。

> **证据**：/etc/inittab@0x4a5b3a；/etc/init.d/@0x4a5b2b
> 
> **来源**：`ev-000043`

### 5. 部署busybox工具

`T1059.004` · 置信度 **中** · 静态

使用 /bin/busybox 与 /tmp/busybox 路径，落地或调用 busybox 执行系统命令。

> **证据**：/bin/busybox@0x4a5b18；/tmp/busybox@0x4a5b6c
> 
> **来源**：`ev-000043`

### 6. 清理命令历史

`T1070.003` · 置信度 **中** · 静态

设置 HISTFILE=/tmp/.del，将 shell 历史重定向到临时文件以隐藏操作痕迹。

> **证据**：HISTFILE=/tmp/.del@0x4a880d
> 
> **来源**：`ev-000043`

### 7. LD_PRELOAD注入

`T1574.006` · 置信度 **中** · 静态

包含 LD_PRELOAD=%s 与 LD_PARAMS=%s，可能通过动态链接器预加载劫持目标进程。

> **证据**：LD_PRELOAD=%s@0x4a6341；LD_PARAMS=%s@0x4a5cab
> 
> **来源**：`ev-000043`

### 8. 本地SOCKS代理

`T1090` · 置信度 **中** · 静态

包含 socks5、socks bind/connects 与 127.0.0[.]1:6103、127.0.0[.]1:53，具备提供本地代理/转发能力。

> **证据**：socks5@0x4a3b42；127.0.0[.]1:6103@0x4a4e31；127.0.0[.]1:53@0x4a5b8b；socks connects@0x4a6710
> 
> **来源**：`ev-000043` · `ev-000045`

### 9. smux加密隧道

`T1573` · 置信度 **中** · 静态

使用 smux 多路复用承载自定义加密数据，含 nonce 方向与密文长度校验。

> **证据**：mux:packer: newpack content is nil@0x4b2aac；received invalid encrypted data size %d@0x4b577a；write data to remote wrong nonce direction@0x4aae33
> 
> **来源**：`ev-000045`

### 10. 探测主机与进程

`T1082` · 置信度 **中** · 静态

读取 /proc/1/comm、/proc/%d/stat、/etc/passwd、/etc/group、/etc/hosts、/etc/resolv.conf、/run/user/%s 等主机与进程信息。

> **证据**：/proc/1/comm@0x4a5b50；/run/user/%s@0x4a5b5c；/etc/passwd、/etc/group、/etc/hosts、/etc/resolv.conf 字符串
> 
> **来源**：`ev-000043`

### 11. 云存储通道

`T1567.002` · 置信度 **中** · 静态

内嵌阿里云 OSS SDK，具备通过对象存储上传/下载文件的能力。

> **证据**：aliyun_v4_request@0x4a80a0；x-oss-* 常量；uploadSpeed/downloadSpeed 与 "The file is larger than 30M..."@0x4ba64f
> 
> **来源**：`ev-000044`

### 12. 创建web_user账户

`T1136.001` · 置信度 **低** · 静态

包含 "the web_user may have been occupied!"，可能在主机或管理面板中创建/占用 web_user 账户。

> **证据**：the web_user may have been occupied!@0x4b3f63；/etc/passwd 字符串
> 
> **来源**：`ev-000045` · `ev-000043`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `154[.]36[.]183[.]100:18089` | 18089 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/home/vbccsb`
- `/tmp/busybox`
- `/bin/busybox`
- `/tmp/log_de.log`
- `/tmp/log_de-0.log`
- `/tmp/.del`
- `/etc/init.d/<service>`
- `/etc/inittab`

**服务**

- `systemd/upstart/init.d/OpenRC 服务（名称由安装路径/二进制名派生）`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `154[.]36[.]183[.]100` | 是 | 动态 |
| `c2_port` | `18089` | 是 | 动态 |
| `persistence` | `systemd/upstart/init.d/OpenRC service; /etc/inittab; busybox` | 是 | 静态 |
| `install_path` | `/home/vbccsb` | 否 | 静态 |
| `log_paths` | `/tmp/log_de.log,/tmp/log_de-0.log (TMPDIR 可覆盖)` | 否 | 静态 |
| `local_proxy_listeners` | `127[.]0[.]0[.]1:6103,127[.]0[.]0[.]1:53` | 否 | 静态 |
| `encryption_algo` | `custom stream/block cipher with nonce direction (unconfirmed)` | 否 | 静态 |
| `cloud_storage_sdk` | `Aliyun OSS (aliyun_v4_request / x-oss-*)` | 否 | 静态 |
| `campaign_id` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭 AES S-box 判定为勒索软件或文件加密器；AES 常量来自 Go 标准库 crypto/aes，未观察到文件加密或勒索行为。
- 不能判定为挖矿木马；未发现 stratum/xmrig/钱包/矿池字符串，也未观察到挖矿行为。
- 不能在未成功建立 C2 会话的情况下宣称已回传数据或已接收指令；本次动态仅观察到 TCP connect 尝试，出站网络被隔离。
- 不能确认家族归属为 nps、frp、Stowaway 等已知工具；缺少对应专有字符串与配置键。
- 不能确认 LD_PRELOAD 注入已实际执行；目前仅为静态字符串线索。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 出站网络被隔离，仅捕获到对 154.36.183[.]100:18089 的 connect 尝试（ENETUNREACH），未建立 C2 会话，无法获取指令、协议明文或回传数据。
2. 未以 root 运行，服务/inittab 持久化写入未实际落地，仅由内嵌模板与路径字符串证明能力。
3. 家族归属不确定：Go 符号被混淆，未匹配到已知家族的专有字符串；仅能描述为自定义 Go 隧道/后门。
4. 加密算法未完全确认：AES S-box 属 Go 标准库，协议中的 nonce/密文长度提示自定义加密，但密钥与算法模式未知。
5. 阿里云 OSS 的具体用途（配置下发、文件上传/外泄或更新）未在动态中观察到。
6. 127.0.0[.]1:6103 与 127.0.0[.]1:53 仅为静态字符串，未观察到监听或代理会话。

## 证据索引

<details>
<summary>展开 12 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000018` | dyn.exec | 隔离 Linux 动态运行，样本持续运行并超时；无 stdout/stderr。 |
| `ev-000019` | dyn.trace | execve("./prog") 成功，确认样本实际启动。 |
| `ev-000020` | dyn.trace | 读取 /sys/kernel/mm/transparent_hugepage/hpage_pmd_size（Go 运行时行为）。 |
| `ev-000022` | dyn.trace | AF_NETLINK NETLINK_ROUTE 套接字，枚举网络接口。 |
| `ev-000023` | dyn.trace | connect 154.36.183[.]100:18089，返回 ENETUNREACH。 |
| `ev-000027` | dyn.trace | 第二次 connect 154.36.183[.]100:18089，确认重连行为。 |
| `ev-000030` | dyn.trace | 第三次 connect 154.36.183[.]100:18089。 |
| `ev-000036` | dyn.trace | 第四次 connect 154.36.183[.]100:18089。 |
| `ev-000042` | decompile.function | 反编译 FUN_007de2a0：读取 TMPDIR、拼接 log_de.log/log_de-0.log、操作 /home/vbccsb。 |
| `ev-000043` | evidence.record | 自定义持久化/主机字符串与 pclntab 解析（自述证据）。 |
| `ev-000044` | evidence.record | 系统服务模板与阿里云 OSS SDK 字符串（自述证据）。 |
| `ev-000045` | evidence.record | 自定义 C2/协议消息字符串（自述证据）。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
