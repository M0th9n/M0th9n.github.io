---
title: "恶意样本分析：Chisel（ELF · elf · cca9accd）"
published: 2026-11-15
draft: false
description: "灰色/PUA（置信度高）：Chisel · backdoor · 难度 easy · 静态反编译（动态执行未取得运行时行为）"
tags: ["Chisel", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!CAUTION]
> **判定：灰色/PUA** · 家族 **Chisel** · 置信度 **高**
> 
> 别名：chisel、Hacktool.Chisel、Tunnel/Chisel、Backdoor.Linux.Chisel（厂商命名）
> 
> 样本是未加壳、未混淆的 Go 静态编译程序，构建信息明示源码路径为 github[.]com/jpillora/chisel（vcs.modified=false），反编译可见 main.client / main.server / main.generatePidFile 与上游命令行接口完全一致。其功能是通用 TCP/UDP 隧道与 SOCKS5 代理（chisel），可被用于反向端口转发、内网穿透与建立交互式通道，属于典型的双用途黑客工具/风险软件；二进制内未发现任何硬编码服务器、密钥、持久化或窃密逻辑，因此按“潜在不受欢迎应用（黑客工具）”定性，而不是已配置的攻击载荷。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Chisel** · 别名 chisel、Hacktool.Chisel、Tunnel/Chisel、Backdoor.Linux.Chisel（厂商命名） |
| 置信度 | **高** |
| 行为类 | backdoor |
| 难度 | easy |
| 首次出现 | 2026-11-14 07:01:26 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/cca9accd3c1554703ab11eb9c10b146d9d8a84ea165450003200de1ebbc2ac4c/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">按子命令分流运行</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">建立反向端口隧道</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1572</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">内置 SOCKS5 代理</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1090</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">HTTP 通道加密传输</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">口令与密钥认证</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1573.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `cca9accd3c1554703ab11eb9c10b146d9d8a84ea165450003200de1ebbc2ac4c` |
| MD5 | _未记录_ |
| 大小 | 8,654,848 字节（8.3 MB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **7** 条行为，每条都挂了证据，且全部静态可得。

### 1. 按子命令分流运行

`T1059` · 置信度 **高** · 静态

main.main 读取命令行首个参数，若等于 "client" 进入客户端模式、等于 "server" 进入服务端模式；无参数或未知子命令只打印帮助并退出，没有隐藏的自动执行分支。

> **证据**：main.main @ VA 0x7EA5A0（RVA 0x3EA5A0）比较 0x65696C63/0x746E 与 0x76726573/0x7265 后调用 main.client/main.server；否则 fmt.Fprint 帮助并 os.Exit(0)
> 
> **来源**：`ref:2c7b47c6c4`

### 2. 建立反向端口隧道

`T1572` · 置信度 **高** · 静态

客户端解析 <server> 与一个或多个 remote 描述，支持 R:<本地接口>:<端口>:<目标主机>:<目标端口>/<协议> 的反向端口转发，把客户端可达的服务暴露到服务端一侧。

> **证据**：main.client @ VA 0x7EB9A0 将 args[0] 写入 Config.Server、其余写入 Config.Remotes；帮助文本含 "which does reverse port forwarding" 与示例 R:2222:localhost:22
> 
> **来源**：`ref:40c373b9dd` · `ref:37b83a2ad3`

### 3. 内置 SOCKS5 代理

`T1090` · 置信度 **高** · 静态

服务端在 --socks5 下启用 SOCKS5 代理，客户端 remote 可写 socks / R:socks，形成可被攻击者用于内网代理的通道（默认 127.0.0[.]1:1080）。

> **证据**：main.server @ VA 0x7EA8E0 初始化 chserver.Config.Socks5；帮助文本 "When the chisel server has --socks5 enabled" 与示例 "5000:socks"、"R:socks"
> 
> **来源**：`ref:3f1f9acb23` · `ref:37b83a2ad3`

### 4. HTTP 通道加密传输

`T1071.001` · 置信度 **高** · 静态

隧道以 HTTP/WebSocket 协议承载，可在其内运行加密的 SSH 风格会话；服务端可用自带证书或 ACME（--tls-domain）申请证书，客户端支持指纹校验与自定义 Host 头。

> **证据**：字符串 "chisel.http2:"、"LetsEncrypt cache directory %s"、"acme-v02[.]api[.]letsencrypt[.]org/directory"；main.client 设置 TLS.ServerName 与 Header["Host"]；main.server 暴露 TLS.Cert/TLS.Key/TLS.CA
> 
> **来源**：`ref:7f7ff0961a` · `ref:40c373b9dd` · `ref:3f1f9acb23`

### 5. 口令与密钥认证

`T1573.002` · 置信度 **高** · 静态

客户端从 --auth 或 AUTH 环境变量取口令；服务端通过 --key/--keyfile 生成或加载 ECDSA 私钥，并以公钥指纹校验对端，形成带认证的隐蔽通道。

> **证据**：main.client 中 os.Getenv("AUTH") 写入 Config.Auth；main.server 中 CHISEL_KEY / CHISEL_KEY_FILE 与 ccrypto.GenerateKeyFile；符号表含 ccrypto.FingerprintKey、verifyLegacyFingerprint
> 
> **来源**：`ref:40c373b9dd` · `ref:3f1f9acb23` · `ref:2411078e7d`

### 6. stdio 打通 shell

`T1059.004` · 置信度 **高** · 静态

remote 支持 stdio:<主机>:<端口> 形式，把本地标准输入输出接至远端，可承载交互式 shell 或任意字节流（帮助明确给出 stdio:example[.]com:22）。

> **证据**：帮助文本 "stdio:example[.]com:22" 与错误串 "stdio cannot be reversed"；main.client 将 remote 原样交给 client.NewClient 解析
> 
> **来源**：`ref:37b83a2ad3` · `ref:40c373b9dd`

### 7. 监听端口等待接入

`T1571` · 置信度 **高** · 静态

服务端默认绑定 0.0.0[.]0:8080（可用 --host/--port 或 HOST/PORT 环境变量覆盖），等待客户端注册并建立隧道，是部署为持久入口时的监听面。

> **证据**：main.server 读取 HOST 后默认回退到 7 字节常量 0x8BAF22（"0.0.0[.]0"），端口默认回退到 4 字节常量 0x8BA63F（"8080"）
> 
> **来源**：`ref:3f1f9acb23`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `chisel.pid（当前工作目录；仅在 --pid 参数下创建，权限 0644）`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `无内置地址；服务端地址由客户端命令行 <server> 参数（http/ws/wss 形式）在运行时提供` | 是 | 静态 |
| `c2_port` | `服务端默认监听端口 8080（PORT 环境变量或 --port 可覆盖）` | 否 | 静态 |
| `transport` | `HTTP/WebSocket 承载的 SSH 风格会话；支持 --tls-cert/--tls-key/--tls-domain(ACME) 的 TLS 变体` | 否 | 静态 |
| `auth_env` | `客户端 AUTH 环境变量（或 --auth）；服务端 CHISEL_KEY / CHISEL_KEY_FILE（或 --key/--keyfile）` | 否 | 静态 |
| `encryption_algo` | `会话层使用 SSH 风格密钥交换（ECDSA/Ed25519）与 AES-GCM/ChaCha20-Poly1305 等对称算法；可选 TLS 1.2/1.3` | 否 | 静态 |
| `proxy_mode` | `SOCKS5 代理模式（服务端 --socks5，远端 'socks'/'R:socks'，默认本地 127.0.0[.]1:1080）` | 否 | 静态 |
| `pid_file` | `chisel.pid（--pid 时写入当前进程号）` | 否 | 静态 |
| `campaign_id` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得称样本内置 C2 或已指向攻击者服务器：可执行文件中没有硬编码的 IP、域名、端口或密钥；帮助文本里的 my-server[.]com、192.168.0[.]5、example[.]com 均为上游文档示例。
- 不得称样本具备持久化、提权或凭据窃取能力：未发现 systemd/服务/计划任务/自启动写入，也未发现读取 /etc/shadow、SSH 私钥或浏览器数据的代码路径。
- 不得把样本中的 AES/SHA-256/base64 常量当作勒索或窃密加密的证据：这些常量来自 Go 标准库以及 TLS/SSH 协议实现（含正向与逆 S-box、SHA-256 轮常量、URL-safe base64 字母表）。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 否 |

**局限与待验证**

1. 动态沙箱通道本次未取得有效观测：加固实例执行接口返回 guest_rc=0 但无 stdout/stderr、无事件产物，无法据此确认任何运行时网络行为；因此所有结论均建立在静态反编译与结构解析上。
2. 二进制不含内置配置，服务端地址、端口、认证口令与转发规则都必须由命令行参数或环境变量提供，静态分析无法确定本次投递实际使用的 C2 与端口。
3. ELF 节头表位于文件偏移 0x190（紧随程序头），不同于常见 Go 构建把节头放在文件末尾的布局；节内容与 buildinfo 自洽且未发现附加载荷，但该布局提示文件可能经过重打包处理。
4. 字符串表中出现形如 chisel-v30.0.0-src 的版本串，与上游公开发布 tag 风格不一致，可能是构建时注入的版本标签；未发现该差异影响功能。
5. 样本已剥离符号表，函数名依赖 .gopclntab 恢复；虽然 vcs.modified=false，仍不能百分之百排除同版本源码级微小补丁。

## 证据索引

<details>
<summary>展开 18 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:4b496bf5e9` | ELF 结构解析 | ELF64 EXEC / x86-64，入口 VA 0x46D340，3 个 LOAD 段，无 INTERP，needed 为空 |
| `ref:45c7d80e65` | elf.sections | .text 4,113,876B(熵 6.145)、.rodata 1,648,410B、.gopclntab 2,487,192B，符合 Go 静态二进制 |
| `ref:14ade7f14c` | elf.imports | 无动态依赖、无导入符号（CGO_ENABLED=0 静态链接） |
| `ref:44b50d109d` | script (buildinfo parse) | Go buildinfo：path=github[.]com/jpillora/chisel、go1.21.0、GOOS=linux、GOARCH=amd64、vcs.revision=4eb9e6a…、vcs.modified=false |
| `ref:721b8f49b3` | script (pclntab scan) | main 包函数表：main.main / main.client / main.server / main.generatePidFile / headerFlags / multiFlag |
| `ref:ffa11e5fda` | script (string scan) | chisel 包路径 github[.]com/jpillora/chisel/{client,server,share/ccrypto} 与版本串 chisel-v30.0.0-src |
| `ref:2c7b47c6c4` | decompile.function | main.main @ VA 0x7EA5A0：按 argv[1] 的 client/server 比较分流，否则打印帮助退出 |
| `ref:40c373b9dd` | decompile.function | main.client @ VA 0x7EB9A0：Config.Server/Remotes、AUTH 环境变量、指纹/认证/代理/头/TLS、NewClient 与可选 pid 文件 |
| `ref:3f1f9acb23` | decompile.function | main.server @ VA 0x7EA8E0：Key/KeyFile/Auth/AuthFile/KeepAlive/Proxy/Socks5/Reverse/TLS，HOST 默认 0.0.0[.]0、PORT 默认 8080 |
| `ref:0edb169b3a` | decompile.function | main.generatePidFile @ VA 0x7EA820：os.WriteFile("chisel.pid", pid, 0644) |
| `ref:b2a1ac8600` | script (VA to offset) | VA 0x8BC0FC 处 10 字节为 "chisel.pid"，对应 generatePidFile 的写入路径 |
| `ref:37b83a2ad3` | script (help text) | 上游 CLI 帮助：R: 反向端口转发、socks、stdio:example[.]com:22、UDP 转发示例 |
| `ref:7f7ff0961a` | script (URL scan) | 字符串含 chisel 文档示例 hxxp://admin:password@my-server[.]com:8081、ACME 目录与项目地址；无硬编码 C2 |
| `ref:4bd764c096` | 密码学常量识别 | AES 正/逆 S-box（0x7EAAC0/0x7EABC0）、SHA-256 轮常量（0x5792F0）、CRC32、标准与 URL-safe base64 字母表 |
| `ref:a456cfc32c` | 哈希与指纹 | md5 ed8b9d38fe272f2692b47292e74a0352 / sha1 a1f2a3f401ad3d18a14030353a2975afaf8dac4d / sha256 与文件名一致 |
| `ref:3fd6fded36` | script (ELF header) | e_shoff=0x190（400）、14 个节头、文件尾部 2448 字节零填充；节头位置不同于常规 Go 布局 |
| `ref:2411078e7d` | decompile.symbols | 共 9,948 个函数，含 chisel/client、chisel/server、ccrypto.NewClient/GenerateKeyFile/FingerprintKey 等 |
| `ref:acd6b7a6a9` | 字符串提取 | 提取 23,922 条 ASCII / 133 条 UTF-16 字符串；未发现真实 C2 或 flag，命中项为 Go 字符串表拼接误报 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
