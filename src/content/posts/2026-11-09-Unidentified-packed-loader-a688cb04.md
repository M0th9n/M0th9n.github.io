---
title: "恶意样本分析：Unidentified packed loader（PE · exe · a688cb04）"
published: 2026-11-09
draft: false
description: "恶意（置信度低）：Unidentified packed loader · loader/injector/backdoor · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["loader", "injector", "backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unidentified packed loader**（存疑） · 置信度 **低**
> 
> 别名：NGENUITY.exe loader (fake HyperX)、furtifivik loader
> 
> 样本是 64 位 GUI 加载器：伪造 HyperX NGENUITY 4.3.11[.]0 版本资源但无厂商签名；.didat 段携带 5.77MB 自定义魔数加密载荷；通过 PEB 遍历与导出表哈希隐藏 API 解析；运行时用 ntdll 的 XPRESS-HUFF 解压接口在内存还原第二级 PE，并在运行中的浏览器进程内替换模块映像头；真实动态中进程反复向两个域名 443 端口回连（HTTP POST，X-Campaign-ID: main）。多项独立证据相互印证，判定为恶意加载器/后门投放体。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unidentified packed loader** · 别名 NGENUITY.exe loader (fake HyperX)、furtifivik loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · injector · backdoor |
| 难度 | hard |
| 首次出现 | 2026-11-06 09:02:31 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/a688cb046e2c5b7be525fc0970b290262f9edd7e2815cf64e7cf1f990bd78e72/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装厂商版本信息</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">填充无关导入掩饰</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">哈希解析隐藏 API</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.007</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">内置加密压缩载荷</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.013</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">内存植入七段 PE</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `a688cb046e2c5b7be525fc0970b290262f9edd7e2815cf64e7cf1f990bd78e72` |
| MD5 | _未记录_ |
| 大小 | 5,946,368 字节（5.7 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **10** 条行为，每条都挂了证据；其中 **6** 条静态可得、**4** 条经动态分析取得。

### 1. 伪装厂商版本信息

`T1036.005` · 置信度 **高** · 静态

PE 版本资源伪造为 HyperX NGENUITY 4.3.11[.]0（CompanyName=HyperX，OriginalFilename=NGENUITY.exe），但安全目录为空、无任何厂商数字签名，导入面也与真实外设管理软件不符。

> **证据**：资源节版本串 HyperX NGENUITY / NGENUITY.exe；SECURITY 数据目录 rva=0,size=0
> 
> **来源**：`ref:c56baa27f7` · `ref:b05e6615f4`

### 2. 填充无关导入掩饰

`T1027` · 置信度 **中** · 静态

导入表 110 个符号中，USER32/GDI32/ADVAPI32/OLE32/SHLWAPI/VERSION 的 33 个 API 在可执行段没有任何 call/mov 引用，仅用于把程序伪装成普通 GUI 软件。

> **证据**：对 IAT 区间 0x1C000-0x1C3C8 的 RIP 相对引用全扫描，仅 KERNEL32 的 CRT 函数被调用
> 
> **来源**：`ref:9c885e6594` · `ref:372bb099b4`

### 3. 哈希解析隐藏 API

`T1027.007` · 置信度 **高** · 静态

遍历 PEB 加载链表按模块名哈希定位 kernel32/kernelbase/ntdll，再手工解析导出表按哈希取函数地址（djb2 变体，末步异或 0xF8121CB6）。

> **证据**：0x140001000 PEB 遍历；0x140001280 导出表解析；0x140001490 名称哈希
> 
> **来源**：`ref:fd27a86f36` · `ref:362bbe8f18`

### 4. 内置加密压缩载荷

`T1027.013` · 置信度 **高** · 静态

.didat 段携带 5,771,888 字节载荷，起始魔数 0x3E8F4A71C62B9D05，随后为 0x50 字节头（含 0x38/0x3C/0x40 处长度字段）与密文，整段约 55% 为零字节。

> **证据**：.didat RVA 0x2F000，首 8 字节 ed ac a8 64 09 22 96 ee；0x1400024E0 按该魔数定位段
> 
> **来源**：`ref:362bbe8f18` · `ev-000009`

### 5. 解压第二级载荷

`T1140` · 置信度 **高** · 静态

用哈希解析到的 RtlGetCompressionWorkSpaceSize / RtlDecompressBufferEx（格式 4，XPRESS-HUFF）在内存解出第二级数据，并校验解出缓冲区头部的自定义魔数。

> **证据**：0x140003E90 解析 ntdll 导出哈希 0x39264741/0xB055D003 并调用解压例程
> 
> **来源**：`ref:ddc572537f` · `ref:fd27a86f36`

### 6. 内存植入七段 PE

`T1620` · 置信度 **高** · 动态

沙箱进程私有内存 0x140000000 出现 2.87MB、7 个节（.text/.rdata/.data/.pdata/.init/.rsrc/.reloc）的 PE，入口位于 .init，且不是磁盘文件映射。

> **证据**：内存扫描 implanted_pe=1，module_size=0x2BD000，mapping_type=MEM_PRIVATE
> 
> **来源**：`ref:d5acbea132` · `ref:c4723712b7`

### 7. 替换浏览器映像头

`T1055.012` · 置信度 **高** · 动态

运行中的 msedge.exe 进程模块头被改写（DOS 头/NT 头/节表/入口点全部修改），其 5.98MB 映像的节布局与投放样本完全一致（含 .didat），属映像替换式注入。

> **证据**：内存扫描 is_pe_replaced=1，节表 .data/.textbss/.gfids/.debug/.reloc/.edata/.didat/.rsrc
> 
> **来源**：`ref:c1e9f22260` · `ref:d5acbea132`

### 8. 定时回连双域名

`T1071.001` · 置信度 **高** · 动态

样本进程在约 2.5 分钟内 14 次向 443 端口发起连接，HTTP 请求 Host 依次为 furtifivik[.]net 与 futifivikbaackip[.]net，携带请求头 X-Campaign-ID: main，正文长度 133 字节。

> **证据**：网络监控：sample.exe (pid 1680) requested TCP 192.0.2[.]123:443；POST Host=furtifivik[.]net, Content-Length: 133
> 
> **来源**：`ref:d239be030d` · `ref:d5acbea132`

### 9. 载入网络加密组件

`T1071` · 置信度 **高** · 动态

运行期加载 winhttp/ws2_32/dnsapi/mswsock/schannel/crypt32/ncrypt/mskeyprotect/webio 等模块，说明网络与 TLS 通信在内存中完成，未出现在静态导入表。

> **证据**：内存扫描模块列表含 winhttp.dll、ws2_32.dll、dnsapi.dll、ncrypt.dll、schannel.dll、webio.dll
> 
> **来源**：`ref:d5acbea132` · `ref:372bb099b4`

### 10. 采集主机指纹播种

`T1082` · 置信度 **高** · 静态

读取系统时间、性能计数器、本地时间、处理器架构、ACP、临时目录、LCID 与键盘类型，与常量 0x26BFDC68 混合迭代生成种子，供载荷密钥/校验使用。

> **证据**：0x140005E70 调用 GetSystemInfo/GetLocalTime/GetACP/GetKeyboardType/GetUserDefaultLCID/GetTempPathW
> 
> **来源**：`ref:1372433372` · `ref:22ff621437`


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
| http | `hxxp://furtifivik[.]net/` | 443 | c2 | 动态 | 已观测 |
| http | `hxxp://futifivikbaackip[.]net/` | 443 | c2 | 动态 | 已观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `furtifivik[.]net; futifivikbaackip[.]net` | 是 | 动态 |
| `c2_port` | `443` | 是 | 动态 |
| `campaign_id` | `main` | 否 | 动态 |
| `campaign_header` | `X-Campaign-ID` | 否 | 动态 |
| `beacon_body_size` | `133` | 否 | 动态 |
| `payload_container` | `custom header magic 0x3E8F4A71C62B9D05 + stream cipher + XPRESS-HUFF compression` | 是 | 静态 |
| `api_hash_seed` | `djb2 variant, final XOR 0xF8121CB6` | 否 | 静态 |
| `payload_seed` | `0x26BFDC68` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能因为版本资源写着 HyperX NGENUITY 就认定它是厂商官方或良性文件：它没有厂商签名，实际行为是载荷解密加载与进程注入。
- 未观察到文件加密、删除或勒索提示，不能归类为 ransomware 或 wiper。
- 未观察到凭据、浏览器数据读取或外传内容（仅截获 133 字节信标），不能断言其为 stealer。
- 未取得 POST 正文与真实 C2 IP，不能编造具体 IP、URI 路径或指令协议。
- 未取得注册表/服务/计划任务遥测证据，不能声称样本已建立持久化。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `e59cbf27a4849ccc0f4bd575810ff642cd56ca99151a9793e64d95f3938652e6`） |

**局限与待验证**

1. 第二级载荷只从进程内存按映像布局整体取出，未还原其完整可执行文件与内部配置；其 .rdata 仅见 C++/CRT 字符串，C2 与命令处理逻辑在内存中被进一步处理。
2. C2 的 HTTP 正文未留存，仅有长度 133 字节与 Host/自定义头，因此无法判断指令协议与回传内容。
3. 未取得注册表、服务、计划任务、证书库或 Defender 排除项的遥测证据，持久化能力未验证。
4. 被替换映像的 msedge.exe 为环境中已存在的浏览器进程，注入的具体系统调用序列未逐帧记录，方法由内存扫描结果推断。
5. 家族无法确认：缺少 YARA 命中、多引擎判定或公开报告，family 字段按不确定处理。
6. 本次真实动态仅在受控网络环境中观察；拦截到的 192.0.2[.]123 为网络模拟地址，不代表真实 C2 IP。

## 证据索引

<details>
<summary>展开 21 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1/imphash 计算 |
| `ev-000002` | scan.imphash | imphash=e2d31538a87edde17ea0bef61047ecdf |
| `ev-000009` | scan.entropy | .didat 段 5,771,888 字节，熵 4.575 |
| `ref:b05e6615f4` | PE 结构解析 | 8 段、ImageBase 0x140000000、无 SECURITY 目录、入口 0x6388 |
| `ref:372bb099b4` | 导入表解析 | 7 个 DLL、110 个符号的导入表 |
| `ref:c9ac968992` | 字符串提取 | ASCII/UTF-16 字符串抽取（含 .textbss 内的混淆串） |
| `ref:c56baa27f7` | manual-parse | 资源节 VS_VERSION_INFO：HyperX NGENUITY 4.3.11[.]0 / NGENUITY.exe |
| `ref:362bbe8f18` | decompile.ghidra | 0x1400024E0 按 0x3E8F4A71C62B9D05 定位 .didat 段 |
| `ref:22ff621437` | decompile.ghidra | 0x140002A30 主流程：定位段、解压、执行 stage-2 |
| `ref:ddc572537f` | decompile.ghidra | 0x140003E90 用 ntdll 哈希导出解压 stage-2 |
| `ref:6f0ca2f8d0` | decompile.ghidra | 0x140001F70 指令长度解码/校验逻辑 |
| `ref:1372433372` | decompile.ghidra | 0x140005E70 采集主机信息生成种子 |
| `ref:fd27a86f36` | manual-script | 模块/API 哈希反算：kernel32=0xC61224C3, kernelbase=0xF29A0B57, ntdll=0x1108B1E7 |
| `ref:9c885e6594` | manual-script | IAT 交叉引用扫描：USER32/GDI32/ADVAPI32 等导入无引用 |
| `ref:d5acbea132` | 动态分析平台 | 真实引爆：pid 1680，6 份进程转储，内存扫描 1 处植入 PE |
| `ref:d239be030d` | manual-script | 网络日志：furtifivik[.]net / futifivikbaackip[.]net，POST 133 字节，X-Campaign-ID: main |
| `ref:c1e9f22260` | manual-script | msedge.exe 进程模块头被替换，5.98MB 映像节布局与样本一致 |
| `ref:c4723712b7` | manual-script | 从内存转储提取 2.87MB 七段 stage-2 PE，sha256=e59cbf27... |
| `c2_evidence:a688cb04` | 连接证据提取 | 动态网络监控记录到 30 次到 furtifivik[.]net:443, futifivikbaackip[.]net:443 的连接尝试；未捕获完整会话 |
| `telemetry:a688cb04` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 123 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 27 条 |
| `etw:a688cb04:1680` | 进程事件监控 | 短命进程事件：a688cb046e2c5b7be525fc0970b290262f9edd7e2815cf64e7cf1f990bd78e72.exe（pid 1680；MD5=A6524A72039FAD96888F3982AD018ADD,SHA256=A688CB046E2C5B7BE525FC0970B290262F9EDD7E2815CF64E7CF1F990BD78E72,IMPHASH=E2D31538A87EDDE17EA0BEF61047ECDF） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
