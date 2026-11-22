---
title: "恶意样本分析：Go RPC Backdoor (rpc/cmd/client)（PE · exe · bb0e4bb5）"
published: 2026-11-21
draft: false
description: "恶意（置信度中）：Go RPC Backdoor (rpc/cmd/client) · backdoor/rat · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["RPC", "backdoor", "rat", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Go RPC Backdoor (rpc/cmd/client)**（存疑） · 置信度 **中**
> 
> 别名：AdobeARMservice masquerader、未命名定制 Go 远控
> 
> 该文件是 Go 1.27.1 编译的 64 位 Windows GUI 后门。静态反编译确认其具备自安装到用户目录、伪装 Adobe 更新服务、通过 HTTPS(/v2/monitor)回连、HMAC 签名会话、远程命令执行、文件上传/下载、SOCKS5 代理等能力；动态沙箱中样本确实完成用户目录自安装路径驻留并三次向 127.0.0[.]1:443 发起连接尝试，符合后门/远控行为。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Go RPC Backdoor (rpc/cmd/client)** · 别名 AdobeARMservice masquerader、未命名定制 Go 远控 · _存疑_ |
| 置信度 | **中** |
| 行为类 | backdoor · rat |
| 难度 | hard |
| 首次出现 | 2026-11-20 14:06:36 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/bb0e4bb5a6f691438a6e60480c700b4fe7195ec4b13b1d6aaa952e3e651db570/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">自安装并伪装Adobe服务</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">连接本机443端口重试</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">轮询HTTPS监控端点</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">远程执行系统命令</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">内置侦察与文件命令</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `bb0e4bb5a6f691438a6e60480c700b4fe7195ec4b13b1d6aaa952e3e651db570` |
| MD5 | _未记录_ |
| 大小 | 13,441,536 字节（12.8 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **11** 条行为，每条都挂了证据；其中 **9** 条静态可得、**2** 条经动态分析取得。

### 1. 自安装并伪装Adobe服务

`T1036.005` · 置信度 **高** · 动态

调用 os.Executable / os.Rename 将自身移动到 %LOCALAPPDATA%\Programs\AdobeARMservice\AdobeARMservice_x86.exe（父目录不存在则创建），资源版本信息伪装为 Adobe Acrobat Update Service / AdobeARMservice_x86.exe 1.182.0[.]1。

> **证据**：rpc/internal/client.AutoInstall rva 0x3ae0c0；动态内存取证显示 PID 5516 主模块路径为 C:\Users\analyst\AppData\Local\Programs\AdobeARMservice\AdobeARMservice_x86.exe
> 
> **来源**：`ev-000030` · `ev-000056` · `ref:d317d590fb`

### 2. 连接本机443端口重试

`T1071.001` · 置信度 **高** · 动态

样本运行约 75 秒后连续三次发起 TCP 127.0.0[.]1:443 连接，均被本机分流拦截失败，未产生外部域名解析或外部连接。

> **证据**：网络监控日志: pid 5516 于 12:02:43/44/45 三次 requested TCP 127.0.0[.]1:443，随后 loopback 发送失败
> 
> **来源**：`ref:d317d590fb` · `ev-000056` · `ev-000031`

### 3. 轮询HTTPS监控端点

`T1071.001` · 置信度 **高** · 静态

构造 GET {base}/v2/monitor 请求，附带 Cookie: connect.sid=<HMAC 令牌> 与 X-Metadata 头，响应按 JSON 解析为命令帧（cmd/args/cwd/exit_code/data/chunk）。

> **证据**：rpc/internal/client.(*Client).Sync rva 0x3b4f80: fmt.Sprintf("%s/v2/monitor")、net/http.NewRequestWithContext("GET")、Cookie/X-Metadata、encoding/json Decode
> 
> **来源**：`ev-000046` · `ev-000057`

### 4. 远程执行系统命令

`T1059.003` · 置信度 **高** · 静态

对非内置命令使用 os/exec 的 CombinedOutput 在受控工作目录中执行，30 秒上下文超时，输出截断至 0x80000 字节并回传。

> **证据**：rpc/internal/client.(*Client).builder rva 0x3b7cc0: context.WithTimeout(30s) + os/exec.(*Cmd).CombinedOutput；分派字符串 "exec" 于 (*Client).Run
> 
> **来源**：`ev-000054` · `ev-000038`

### 5. 内置侦察与文件命令

`T1082` · 置信度 **高** · 静态

实现 ls/cat/env/pwd/whoami/localip/cd/tree 等内置命令：枚举目录时间与大小、读取任意文件（上限 0x80000）、导出环境变量、返回当前用户与网卡地址。

> **证据**：(*Client).status rva 0x3b6fc0 比较 "ls"/"cat"/"env"/"pwd"/"whoami"/"localip"；(*Client).gender rva 0x3b6200 处理 "cd"/"tree"
> 
> **来源**：`ev-000053` · `ev-000051`

### 6. 上传任意文件落盘

`T1105` · 置信度 **高** · 静态

收到 push 命令后将文件内容写入攻击者指定路径：相对路径拼接到当前工作目录，MkdirAll 创建父目录，os.WriteFile 使用 0644 权限，覆盖已有文件。

> **证据**：(*Client).invite rva 0x3aee80: filepath.IsAbs/path.Join、os.MkdirAll(0755)、os.WriteFile(mode 0x1a4=0644)
> 
> **来源**：`ev-000052` · `ev-000038`

### 7. 下载导出本地文件

`T1005` · 置信度 **中** · 静态

download 命令对应文件读取并分块回传（含 filename/orig_size/chunk/is_dir 字段），可把主机文件外带。

> **证据**：(*Client).Run 分派 "download" 到 (*Client).summary；proto.FileUploadMeta/Frame 含 filename、orig_size、chunk、is_dir
> 
> **来源**：`ev-000038` · `ev-000046`

### 8. 开放SOCKS5内网代理

`T1090.003` · 置信度 **高** · 静态

收到 socks5 命令后调用 OpenTunnel/OpenTunnelPoll，把受害主机变为 SOCKS5 代理/隧道节点，供攻击者横向访问内网。

> **证据**：(*Client).Run rva 0x3aa920 中 6 字节分派 "socks5" → (*Client).OpenTunnel / OpenTunnelPoll；Go 类型 OpenTunnelPoll、fragmentGroups
> 
> **来源**：`ev-000038`

### 9. HMAC签名伪装会话Cookie

`T1573` · 置信度 **高** · 静态

以 32 位十六进制内置密钥对十进制时间戳做 HMAC-SHA256 并十六进制编码，作为 Express 风格 connect.sid Cookie 与 X-Metadata 头的值，伪装成普通 Web 会话流量。

> **证据**：rpc/internal/auth.Compute rva 0x2ca9a0: crypto/hmac + SHA-256、fmt "%d" 时间戳、hex 编码；(*Client).Sync 中 "connect.sid=%s"
> 
> **来源**：`ev-000055` · `ev-000046` · `ev-000057`

### 10. 伪造浏览器TLS指纹

`T1573` · 置信度 **高** · 静态

使用 refraction-networking/utls 构造自定义 TLS ClientHello（含 GREASE、ECH、PSK 扩展等），使回连流量更接近浏览器而非 Go 默认指纹。

> **证据**：rpc/internal/client.NewTransport rva 0x3b87c0 使用 utls；Go build info dep github[.]com/refraction-networking/utls v1.8.2；字符串 BuildHandshakeState/ClientHelloID
> 
> **来源**：`ev-000039` · `ev-000028`

### 11. 远程关机与退出

`T1529` · 置信度 **高** · 静态

分派 shutdown 命令后调用 Shutdown 结束会话并退出；另有 sleep 命令调整休眠节奏。

> **证据**：(*Client).Run rva 0x3aa920: 8 字节 "shutdown" → rpc_internal_client.Shutdown；5 字节 "sleep" 分支
> 
> **来源**：`ev-000038`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://localhost` | 443 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%LOCALAPPDATA%\Programs\AdobeARMservice\AdobeARMservice_x86.exe`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxps://localhost` | 是 | 静态 |
| `c2_uri` | `/v2/monitor` | 是 | 静态 |
| `c2_method` | `GET` | 是 | 静态 |
| `hmac_key` | `1564fea2dea4c8806348a2ae01afafe7` | 是 | 静态 |
| `auth_scheme` | `HMAC-SHA256(十进制时间戳) 十六进制串；Cookie: connect.sid=<token>；X-Metadata: <token>` | 是 | 静态 |
| `install_path` | `%LOCALAPPDATA%\Programs\AdobeARMservice\AdobeARMservice_x86.exe` | 是 | 动态 |
| `user_agent` | `uTLS 自定义 ClientHello/浏览器指纹` | 否 | 静态 |
| `sleep_min_sec` | `10` | 否 | 静态 |
| `sleep_max_sec` | `30` | 否 | 静态 |
| `command_set` | `exec,push,download,socks5,sleep,shutdown,nop` | 是 | 静态 |
| `window_class` | `DDE Server Window` | 否 | 静态 |
| `env_override` | `NRLAGNT (候选)` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭二进制里存在 AES S-box 就断言 C2 或文件使用 AES 加密——Go 标准库 crypto/aes 会无条件带入该常量表，本次未取得加密流量的明文/密文对照。
- 不能把默认配置中的 localhost/127.0.0[.]1 当作真实外部 C2 并据此认定已回连成功；本次仅看到失败的 loopback 连接尝试。
- 不能声称样本已建立注册表/服务/计划任务持久化：动态窗口未观测到此类写入，静态代码也只体现为用户目录文件自安装。
- 不能因内置 SOCKS5 和文件上传就将其归类为通用代理工具或下载器；其核心是带命令分派的远控后门。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 动态窗口内仅观测到 3 次 127.0.0[.]1:443 连接尝试，均因 loopback 分流失败，未获得任何 C2 请求/响应；C2 与 config 中相关项按静态处理并标记 pending_dynamic_verify。
2. 默认基址 hxxps://localhost 可能被环境变量或部署参数覆盖（发现 7 字符候选名 NRLAGNT），真实外部 C2 未在本环境出现，无法确认实际后端。
3. 未见注册表、服务、计划任务写入；持久化结论仅限文件自安装，重启后是否自启未验证。
4. Go 函数名、文件名被随机英文词替换（防分析），无法与公开家族情报做符号级比对，家族归属不确定。
5. 静态反调试命中（GetThreadContext、rdtsc、cpuid、int 2Dh）多来自 Go 运行时/加密例程，未在调用链上证实刻意反调试。
6. HMAC 密钥、请求头格式与命令分派均来自静态反编译，未能在真实流量中复核；远程 shell/文件上传/SOCKS5 未被实际触发。

## 证据索引

<details>
<summary>展开 17 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/imphash 与样本标识核对 |
| `ev-000028` | 字符串提取 | Go build ID 与字符串统计 |
| `ev-000029` | decompile.function | main.main: AutoInstall → DefaultConfig → post → Client.Run |
| `ev-000030` | decompile.function | AutoInstall: LOCALAPPDATA\Programs 自安装与后缀剥离 |
| `ev-000031` | decompile.function | DefaultConfig: 默认基址/休眠/VERBOSE 处理 |
| `ev-000038` | decompile.function | (*Client).Run: exec/push/download/socks5/sleep/shutdown/nop 分派 |
| `ev-000039` | decompile.function | NewTransport: utls 传输层与超时 |
| `ev-000042` | decompile.function | 隐藏窗口 DDE Server Window 与消息循环 |
| `ev-000046` | decompile.function | Sync: GET /v2/monitor + Cookie/X-Metadata + JSON 解码 |
| `ev-000052` | decompile.function | invite: 路径拼接/MkdirAll/WriteFile 上传落盘 |
| `ev-000054` | decompile.function | builder: os/exec CombinedOutput 远程命令执行 |
| `ev-000055` | decompile.function | auth.Compute: HMAC-SHA256 时间戳令牌 |
| `ev-000057` | evidence.record | 静态提取 .data 字符串头: 默认基址/HMAC 密钥/安装名/NRLAGNT |
| `ev-000056` | evidence.record | 动态产物解析: 自安装路径、127.0.0[.]1:443 尝试、无子进程 |
| `ref:d317d590fb` | 动态分析平台 | 隔离环境 真实引爆与时间线/内存转储/网络日志 |
| `telemetry:bb0e4bb5` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 107 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 18 条 |
| `etw:bb0e4bb5:5516` | 进程事件监控 | 短命进程事件：bb0e4bb5a6f691438a6e60480c700b4fe7195ec4b13b1d6aaa952e3e651db570.exe（pid 5516；MD5=B372D12CB536D14F60FEB0BDCD7AFEF4,SHA256=BB0E4BB5A6F691438A6E60480C700B4FE7195EC4B13B1D6AAA952E3E651DB570,IMPHASH=ED8B780A3CE7CA4ABA78A21F6BC3D4E0） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
