---
title: "恶意样本分析：ValleyRAT/Winos 4.0 系加载器（候选）（PE · exe · 201f298a）"
published: 2026-11-17
draft: false
description: "恶意（置信度中）：ValleyRAT/Winos 4.0 系加载器（候选） · loader/downloader · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["ValleyRAT", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ValleyRAT/Winos 4.0 系加载器（候选）**（存疑） · 置信度 **中**
> 
> 别名：Silver Fox 银狐、Winos 4.0、ValleyRAT loader
> 
> 样本在隔离 Windows 沙箱中真实运行后 1 分钟内向阿里云 OSS 地址 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com 发起 TCP/443 并发出完整 HTTP 请求（GET /tad，User-Agent: 3M），该域名与请求路径在磁盘文件中并不存在、只出现在运行后的进程内存中，说明配置为运行时解密/构造；同时其版本资源与代码签名均冒用“腾讯会议 3.37.1[.]426 / Tencent Technology”，而签名完整性校验为哈希不匹配，属伪造/盗用签名。结合落地目录 C:\Users\Public\pinIhy\ 与 VUXkpL.exe 等内存配置，判定为恶意加载/下载器而非正常装机包。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ValleyRAT/Winos 4.0 系加载器（候选）** · 别名 Silver Fox 银狐、Winos 4.0、ValleyRAT loader · _存疑_ |
| 置信度 | **中** |
| 行为类 | loader · downloader |
| 难度 | hard |
| 首次出现 | 2026-11-14 18:07:15 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/201f298ad9e5940aff96ac3a165c4a4800b50cc070b945e68d98dc9b28e5831e/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">冒用腾讯会议签名</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">40MB 填充撑大文件</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">运行时解出下载配置</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">向 OSS 请求载荷</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">自建协议指向备用C2</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `201f298ad9e5940aff96ac3a165c4a4800b50cc070b945e68d98dc9b28e5831e` |
| MD5 | _未记录_ |
| 大小 | 40,893,088 字节（39.0 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **6** 条行为，每条都挂了证据；其中 **3** 条静态可得、**3** 条经动态分析取得。

### 1. 冒用腾讯会议签名

`T1036.001` · 置信度 **高** · 静态

版本资源声明 FileDescription/ProductName 为“腾讯会议”、版本 3.37.1[.]426、版权归 Tencent Corporation；证书表内的代码签名者为 Tencent Technology (Shenzhen) Company Limited（DigiCert 签发、2025-08-25 时间戳），但完整性校验返回哈希不匹配，即文件内容与签名时所签哈希不一致，签名被复用/伪造。

> **证据**：版本资源 /16/1/2052 @RVA 0x2702548 含"腾讯会议 3.37.1[.]426"；证书表 @RVA 0x26FB0E0；签名校验结果 HashMismatch
> 
> **来源**：`ref:e20b790a5b` · `ref:b4f488552d` · `ref:82d622c69f`

### 2. 40MB 填充撑大文件

`T1027` · 置信度 **高** · 静态

.data 段原始大小 40,552,448 字节（占整个文件约 99%），熵仅 2.027，内部是大段零填充与来自多个无关程序的字符串/结构碎片（RPCS3、shadPS4、Terraform Provider、腾讯会议、Wondershare 等），且同一批字符串在多个偏移重复出现，缺乏被本程序代码引用的证据，符合“用无关数据填充使体积超阈值、规避扫描”的做法。

> **证据**：.data RVA 0x2F000 起始，raw 40,552,448 字节，熵 2.027；0x1909B87 起 6.8MB 混合内容；rsx_debugger 在 0xBA15B/0x19AF91B/0x1BE0CEB/0x26AE1BB 四处重复
> 
> **来源**：`ref:f97acae034` · `ref:09dc82270f` · `ref:72bdd8bb2f` · `ref:1db6cfcb34`

### 3. 运行时解出下载配置

`T1140` · 置信度 **高** · 动态

进程运行后内存中出现明文配置 hxxps://3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com/tad、C:\Users\Public\pinIhy\ 与 C:\Users\Public\pinIhy\VUXkpL.exe；这些完整字符串在磁盘文件中检索不到（仅文件 .text 起始处保留片段 "3spp0a"），说明配置由运行时解密/拼接得到。

> **证据**：静态文件中 3byy0j/aliyuncs//tad/VUXkpL 命中数为 0；内存镜像偏移 0x3E59C 起为 hxxps://3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com/tad，0x41674 为 C:\Users\Public\pinIhy\VUXkpL.exe
> 
> **来源**：`ref:918d2c95b6` · `ref:fdc4042949` · `ref:eeb058802f`

### 4. 向 OSS 请求载荷

`T1105` · 置信度 **高** · 动态

真实运行约 1 分钟后，样本进程发起 TCP 192.0.2[.]123:443 连接，并发出完整明文 HTTP 请求：GET /tad HTTP/1.1、Host: 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com、User-Agent: 3M、Cache-Control: no-cache；即以 HTTP（而非 TLS）访问 443 端口向第三方对象存储索取下一阶段内容。

> **证据**：网络日志 01:37:03 样本进程(2244) requested TCP :443；01:37:05 HTTPListener443 记录 GET /tad，Host=3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com，UA=3M
> 
> **来源**：`ref:efd8a77229` · `ref:bebdb83e9d`

### 5. 自建协议指向备用C2

`T1071` · 置信度 **中** · 静态

内存配置中存在自定义协议形式的地址 ykkgj://3spp0a[.]fjj-te-svzazex[.]rczpletj[.]tfd/（随机二级域 + 非常规 TLD .tfd），与 OSS 下载地址并列存放，作为独立于 HTTP 下载通道的备用控制/回连入口；磁盘静态文件中只保留其片段 "3spp0a"。

> **证据**：内存 0x3E8CC 处 "ykkgj://"，0x3EBDC 处 "ykkgj://3spp0a[.]fjj-te-svzazex[.]rczpletj[.]tfd/"；静态文件偏移 0x42B 处片段 "3spp0a"
> 
> **来源**：`ref:fdc4042949` · `ref:37f21e67b3`

### 6. 公共目录暂存载荷

`T1074` · 置信度 **高** · 动态

配置固定使用 %PUBLIC%\pinIhy\ 作为暂存目录，并给出落盘文件名 VUXkpL.exe；该目录位于所有用户可写的 Public 路径，便于无特权写入并由后续进程加载，属下载后落地执行的典型准备动作（本次分析窗口内未捕获到实际文件写入事件）。

> **证据**：内存偏移 0x3E40C / 0x3E6AC / 0x3F7FC 均为 C:\Users\Public\pinIhy\；0x41674 为 ...\VUXkpL.exe
> 
> **来源**：`ref:fdc4042949`


## IOC（已去武器化）

### 网络

:::note
**已动态观测到连接**：样本实际向该目标发起 TCP 连接（短时间内多次重试）。
:::

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控仿真服务完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com/tad` | 443 | download | 动态 | 已观测 |
| other | `ykkgj://3spp0a[.]fjj-te-svzazex[.]rczpletj[.]tfd/` | - | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `C:\Users\Public\pinIhy\`
- `C:\Users\Public\pinIhy\VUXkpL.exe`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `payload_url` | `hxxps://3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com/tad` | 是 | 动态 |
| `user_agent` | `3M` | 是 | 动态 |
| `staging_dir` | `%PUBLIC%\pinIhy\` | 是 | 动态 |
| `dropped_payload_path` | `%PUBLIC%\pinIhy\VUXkpL.exe` | 否 | 动态 |
| `c2_hosts` | `3spp0a[.]fjj-te-svzazex[.]rczpletj[.]tfd（协议前缀 ykkgj://）` | 否 | 静态 |
| `protocol_scheme` | `ykkgj://` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得因文件中出现 RPCS3、shadPS4、Terraform Provider、腾讯会议等字符串就认定样本捆绑了这些软件或具备模拟器/云迁移功能——这些内容位于不可达的 40MB 填充区，未见本程序代码引用。
- 不得声称已观测到持久化行为（计划任务、Run 键、服务安装）：动态窗口内无注册表/服务/任务事件，内存中的 CurrentVersion\Run 字符串来自系统模块而非样本自身。
- 不得声称已完成二阶段载荷的下载与执行：只捕获到一次 HTTP GET 请求与内存中的落地路径字符串，未见响应体、文件写入或新进程。
- 不得把 ykkgj:// 描述为已验证可用的 C2 通道：它仅来自内存配置字符串，未观测到任何收发交互。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 动态观察窗口内未捕获响应体与落盘文件，无法确认第二阶段载荷类型与实际执行结果。
2. .data 中 40.5MB 内容多为互不相关的程序字符串碎片，静态引用链未能定位到解密/使用它的代码；.text 主体为 MSVC 运行库，入口处存在非正常跳转，完整解密算法未还原。
3. 文件 Authenticode 校验为哈希不匹配，无法据此确认签名环节究竟发生在打包前还是打包后被篡改。
4. 自定义协议地址 ykkgj://3spp0a[.]fjj-te-svzazex[.]rczpletj[.]tfd/ 仅来自内存字符串，未做可用性验证，也未观察到实际回连。
5. 沙箱未采集文件系统与注册表遥测，落地目录与持久化只能依据内存字符串推断，不能视为已发生。

## 证据索引

<details>
<summary>展开 20 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:09dc82270f` | 样本分诊 | 哈希/imphash/段熵/异常/加壳评分一站式分诊；40MB .data、熵 2.027、packing.score=0、anomaly=0 |
| `ref:f97acae034` | PE 结构解析 | PE64 GUI、入口 RVA 0x98C0、7 个段、.data 原始 40,552,448 字节、characteristics 含 RELOCS_STRIPPED 但存在 .reloc |
| `ref:09ff19ec7c` | 导入表解析 | 4 个导入 DLL / 88 个符号，含 ShellExecuteW、CoCreateInstance、VirtualAlloc、CreateFileW、FindFirstFileExW、IsDebuggerPresent |
| `ref:37f21e67b3` | 字符串提取 | ASCII 33330 条 / UTF16 569 条；文件偏移 0x42B 处出现片段 3spp0a |
| `ref:05364e4e0e` | 密码学常量识别 | 命中 AES S-box/逆 S-box、SHA-256、MD5、CRC32、base64 常量（均位于填充区） |
| `ref:e20b790a5b` | script | 解析版本资源 /16/1/2052：腾讯会议 3.37.1[.]426 / © Tencent Corporation |
| `ref:b4f488552d` | script | 证书表字符串：DigiCert 链 + Tencent Technology (Shenzhen) Company Limited + 2025-08-25 时间戳 |
| `ref:82d622c69f` | script | 系统签名校验：Status=HashMismatch，签名者证书主题为 Tencent Technology (Shenzhen) |
| `ref:72bdd8bb2f` | script | 填充区内命中 rpcs3_app/rsx_debugger/shadPS4/sceAudioOutOpen 等无关程序字符串 |
| `ref:1db6cfcb34` | script | 填充区内命中 terraform-provider-vcd、vmware/go-vcloud-director 等 Go 模块路径 |
| `ref:bebdb83e9d` | 动态分析平台 | 沙箱引爆：候选进程 1 个、无 hollows、无定点转储，收口后回滚；时间线记录样本 PID 与内存转储 |
| `ref:efd8a77229` | script | 网络监控日志：样本进程请求 TCP :443 后出现 GET /tad，Host=3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com，UA=3M |
| `ref:eeb058802f` | script | 进程内存镜像检索：3byy0j/aliyuncs 各 21-22 处命中，/tad 5 处命中（磁盘文件 0 命中） |
| `ref:fdc4042949` | script | 内存配置区还原：hxxps://3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com/tad、C:\Users\Public\pinIhy\、VUXkpL.exe、ykkgj://3spp0a[.]fjj-te-svzazex[.]rczpletj[.]tfd/ |
| `ref:918d2c95b6` | script | 静态文件检索 3byy0j/aliyuncs/oss-cn-beijing 均为 0 命中，证明配置为运行时生成 |
| `ref:6a20b14125` | unpack.detect | 静态壳检测未命中（packed=false），与“自填充而非加密壳”的结构一致 |
| `ref:15bb76986d` | disasm.function | 入口 RVA 0x98C0：调用 __security_init_cookie 后跳转 RVA 0x11EC，非标准 CRT 入口路径 |
| `c2_evidence:201f298a` | 连接证据提取 | 动态网络监控记录到 1 次到 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com:443 的连接尝试；未捕获完整会话 |
| `telemetry:201f298a` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 108 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 27 条 |
| `etw:201f298a:2244` | 进程事件监控 | 短命进程事件：201f298ad9e5940aff96ac3a165c4a4800b50cc070b945e68d98dc9b28e5831e.exe（pid 2244；MD5=401E4A3730E1932E6A77D52249850EFB,SHA256=201F298AD9E5940AFF96AC3A165C4A4800B50CC070B945E68D98DC9B28E5831E,IMPHASH=20ABBE0F6AB059EA4A375BCB6B8A717B） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
