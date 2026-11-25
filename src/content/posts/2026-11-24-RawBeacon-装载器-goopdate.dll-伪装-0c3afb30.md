---
title: "恶意样本分析：RawBeacon 装载器(goopdate.dll 伪装)（PE · dll · 0c3afb30）"
published: 2026-11-24
draft: false
description: "恶意（置信度低）：RawBeacon 装载器(goopdate.dll 伪装) · loader/dropper · 难度 hard · 静态反编译（动态执行未取得运行时行为）"
tags: ["RawBeacon 装载器", "loader", "dropper", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **RawBeacon 装载器(goopdate.dll 伪装)**（存疑） · 置信度 **低**
> 
> 别名：rawbeacon.dll loader、goopdate.dll sideload loader
> 
> 反编译证据自证:该 DLL 伪装为 Google 更新组件 goopdate.dll,导出名为 DllEntry 的函数在内部把 %TEMP% 下的诱饵文件 cam_numbers_825e2c.pdf 打开,同时用 VirtualAlloc(0x3000,0x40) 手工映射一段内嵌 PE(rawbeacon.dll,SizeOfImage 0x6f000),修复重定位、手工解析导入表、调用其入口并按其导出表定位并执行 RunPayload;RunPayload 再以 RWX 方式执行内嵌 PIC 装载器,该装载器通过 PEB 遍历和自定义哈希隐藏解析 22 个系统 API(含 RtlDecompressBuffer),并用 base64 + 逐字节 XOR + LZNT1 的双层方式藏匿约 300KB 最终载荷。上述行为均为反射式内存装载与载荷藏匿,无合法软件用途。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **RawBeacon 装载器(goopdate.dll 伪装)** · 别名 rawbeacon.dll loader、goopdate.dll sideload loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · dropper |
| 难度 | hard |
| 首次出现 | 2026-11-24 12:12:51 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/0c3afb30eca4de018a7a3aa42ab43acc4a3c998595ba1802da876feffb419bcc/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装成谷歌更新组件</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">投放 PDF 诱饵并打开</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">手工映射内嵌 DLL</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">按导出名执行 RunPayload</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">RWX 执行内嵌 shellcode</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `0c3afb30eca4de018a7a3aa42ab43acc4a3c998595ba1802da876feffb419bcc` |
| MD5 | _未记录_ |
| 大小 | 447,960 字节（437.5 KB） |
| 类型 | PE · `dll` |

## 行为分析

共 **9** 条行为，每条都挂了证据，且全部静态可得。

### 1. 伪装成谷歌更新组件

`T1036.005` · 置信度 **高** · 静态

DLL 自身导出表 DLL 名为 goopdate.dll、仅导出一个名为 DllEntry 的函数,用于冒充 Google Update 组件并以侧加载方式被宿主调用。

> **证据**：pe.exports: dll_name=goopdate.dll, symbols=[DllEntry @ rva 0x1610]
> 
> **来源**：`ref:6d995fcc0a`

### 2. 投放 PDF 诱饵并打开

`T1204.002` · 置信度 **高** · 静态

取 %TEMP% 路径,把同目录下的 win.dll 复制为 cam_numbers_825e2c.pdf,再用 ShellExecuteExW(fMask=0x400, nShow=1) 打开该“文档”以制造正常阅读 PDF 的假象。

> **证据**：FUN_693414e0 @ 0x693414e0: GetTempPathW -> wsprintfW(L"%s%s", tmp, L"cam_numbers_825e2c.pdf") -> GetModuleFileNameW/wcsrchr -> CopyFileW -> ShellExecuteExW
> 
> **来源**：`ref:71f0bb7ef8` · `ref:827290c4ca`

### 3. 手工映射内嵌 DLL

`T1620` · 置信度 **高** · 静态

DllEntry 先用 VirtualAlloc 申请 0x6f000 字节可读写执行内存(优先基址 0x6a180000),按内嵌镜像的节表逐节 memcpy,遍历 .reloc 修复重定位,再按导入表项 LoadLibraryA/GetProcAddress 填充 IAT。

> **证据**：DllEntry @ 0x69341610: VirtualAlloc(0x6a180000,0x6f000,0x3000,0x40); memcpy 循环; \*puVar3 = \*puVar3 + delta; LoadLibraryA/GetProcAddress 填充
> 
> **来源**：`ev-000016` · `ref:36903b2a81`

### 4. 按导出名执行 RunPayload

`T1620` · 置信度 **高** · 静态

映射完成后调用内嵌镜像入口,再手工解析其导出表,用 lstrcmpA 匹配字符串 "RunPayload" 并以函数指针方式直接调用该导出。

> **证据**：DllEntry @ 0x69341610 尾部: lstrcmpA(export_name, "RunPayload") == 0 -> call [puVar7 + 导出地址]
> 
> **来源**：`ev-000016`

### 5. RWX 执行内嵌 shellcode

`T1620` · 置信度 **高** · 静态

内嵌 rawbeacon.dll 的 RunPayload 导出申请 0x63a2e 字节 RWX 内存,把自身 rva 0x4044 处的 408110 字节 shellcode 拷入,FlushInstructionCache 后直接调用,形成无文件落地的位置无关装载链。

> **证据**：RunPayload @ rawbeacon rva 0x14f0: VirtualAlloc(0,0x63a2e,0x3000,0x40) -> memcpy(&DAT_6a184044,0x63a2e) -> GetCurrentProcess/FlushInstructionCache -> (*_Dst)
> 
> **来源**：`ev-000025` · `ref:e26d924ebf`

### 6. 哈希隐藏解析系统 API

`T1027` · 置信度 **高** · 静态

PIC 装载器遍历 PEB 模块链表,用自定义哈希(seed 0xf4283c27 的 ROR13)匹配模块与函数名,解析出 LoadLibraryA/GetProcAddress/VirtualAlloc/VirtualProtect/VirtualQuery/MapViewOfFile/CreateFileMappingA/RtlDecompressBuffer 等 22 个 API,导入表上不留这些名字。

> **证据**：FUN_00402624 @ 0x402624 哈希循环(uVar4=0xf4283c27; ror13; c>0x60 时 -0x20)+ FUN_0040299e PEB 模块遍历;FUN_004026f0 的 22 个常量已全部映射到 kernel32/ntdll 导出名
> 
> **来源**：`ev-000032` · `ev-000031` · `ref:743642c1a9`

### 7. 解密解压内置载荷

`T1140` · 置信度 **高** · 静态

装载器按容器条目类型分派解码:类型 1 为逐字节重复密钥 XOR,类型 4 调用 RtlDecompressBuffer(格式 2 = LZNT1)解压,然后按 PE 节表把结果映射进内存并跳转入口。

> **证据**：FUN_00402bc3 @ 0x402bc3: dst[i] ^= key[i % keylen];entry @ 0x401000 中 (*pcStack_80c)(2, this, size, src, len, &out) 对应 RtlDecompressBuffer(LZNT1)
> 
> **来源**：`ev-000033` · `ev-000028`

### 8. base64 藏匿加密载荷

`T1027` · 置信度 **高** · 静态

shellcode 数据区携带 399660 字符纯 base64 文本(占整个 408110 字节载荷的 98%),解码后为 299744 字节、熵 7.987 的高熵数据,使静态字符串与 YARA 特征难以命中。

> **证据**：文件偏移 0x5a26 起 399660 字符 base64;解码长度 299744、熵 7.987;头部 01000000c00000001092040010920400
> 
> **来源**：`ref:7ebccaae7c`

### 9. 滥用有效代码签名

`T1553.002` · 置信度 **中** · 静态

外层 DLL 附带 14808 字节 Authenticode 签名,签发链为 Microsoft ID Verified CS AOC CA 03,签名主体为个人 ISABEL ALEJANDRA FLORES,时间戳 2026-11-24,使文件在文件属性上显示为“已验证发布者”。

> **证据**：SECURITY 目录 rva 433152 size 14808(文件偏移 0x69C00);openssl 解析 PKCS#7:subject=ISABEL ALEJANDRA FLORES, issuer=Microsoft ID Verified CS AOC CA 03
> 
> **来源**：`ref:859742b4b3` · `ref:7ebccaae7c`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `%TEMP%\cam_numbers_825e2c.pdf`
- `<DLL所在目录>\win.dll`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `api_resolution` | `PEB 遍历 + 自定义 ROR13(seed=0xf4283c27,大写化累加) 哈希,模块哈希 kernel32.dll=0xb0af8c96 / ntdll.dll=0xef561b93,共 22 个 API 常量` | 是 | 静态 |
| `payload_encoding` | `内嵌 399660 字符 base64 文本 -> 299744 字节高熵数据(熵 7.987),容器头 01000000 c0000000 10920400 10920400` | 是 | 静态 |
| `encryption_algo` | `逐字节重复密钥 XOR(FUN_00402bc3)+ RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1=2) 解压,按容器条目类型 1/2/3/4 分派` | 是 | 静态 |
| `decoy_document` | `%TEMP%\cam_numbers_825e2c.pdf(实为 win.dll 的副本,ShellExecuteExW 打开)` | 是 | 静态 |
| `c2_hosts` | `-` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能断言其为勒索软件或窃密程序:最终 ~300KB 载荷未解密,未观测到文件加密、凭据读取或浏览器数据访问行为。
- 不能给出任何 C2 地址/端口:装载器层无 ws2_32/wininet/WinHTTP 导入,加密载荷未解开,沙箱也未产生网络会话。
- 不能声称已在真实主机上成功执行:样本是 DLL,需宿主 EXE 调用导出 DllEntry;沙箱投放未产生新进程。
- 不能把 goopdate.dll 当作 Google 官方组件,也不能仅凭签名主体判定来源归属(签名可能为滥用/转售证书)。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 否 |

**局限与待验证**

1. 最终载荷(299744 字节高熵数据)未解密:容器条目布局与密钥均在 PIC 装载器内部动态构造,静态只到解码算法层,因此 C2、上线 URI、加密套件与家族归属无法确认。
2. 动态沙箱通道本次未取得行为:样本为 DLL,客体内无宿主调用 DllEntry,观察窗口内无新进程、无内存转储、无网络会话,网络监控 无可解析连接。
3. 仿真(用户态 API 仿真)仅推进到 CRT 初始化阶段(InitializeCriticalSection/_initterm/GetModuleHandleA/DisableThreadLibraryCalls 共 8 次调用),未进入 DllEntry 装载逻辑,不能作为行为依据。
4. Authenticode 仅解析了证书主体与签发链,未做吊销/时间戳有效性校验,也未确认证书是否被吊销或转售。
5. 内嵌镜像由 MinGW-w64(GCC 9.3/10)编译,PE 特征为手工构建/剥离符号,无法从编译信息反推作者环境。

## 证据索引

<details>
<summary>展开 16 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:5ba04f1191` | 样本分诊 | sha256/md5/imphash aacb2e69d0124c38c8150f18be1a9539,10 节,无异常,packing.score=0 |
| `ref:859742b4b3` | PE 结构解析 | PE32 i386 DLL,ImageBase 0x69340000,entry rva 0x13b0,SECURITY 目录 14808 字节 |
| `ref:6d995fcc0a` | pe.exports | 导出 DLL 名 goopdate.dll,唯一导出 DllEntry @ rva 0x1610 |
| `ref:7892c94bb4` | 导入表解析 | 仅 KERNEL32/msvcrt/SHELL32/USER32 共 36 个符号,含 CopyFileW/GetTempPathW/GetModuleFileNameW/ShellExecuteExW/VirtualAlloc |
| `ref:827290c4ca` | 字符串提取 | 命中 cam_numbers_825e2c.pdf、win.dll、RunPayload、kernel32.dll 等字符串(偏移 0x1e60/0x1e78/0x1ed1) |
| `ref:36903b2a81` | PE 结构解析 | 内嵌 stage1 PE:ImageBase 0x6a180000,SizeOfImage 0x6f000,导出 rawbeacon.dll!RunPayload |
| `ev-000016` | decompile.function | DllEntry 手工映射内嵌 PE、修复重定位、解析导入、调用入口并按名字调用 RunPayload |
| `ev-000037` | decompile.function | FUN_693414e0 把同目录 win.dll 复制为 %TEMP%\cam_numbers_825e2c.pdf 并 ShellExecuteExW 打开 |
| `ev-000025` | decompile.function | RunPayload 申请 0x63a2e RWX 内存,memcpy 内嵌 shellcode,FlushInstructionCache 后调用 |
| `ev-000028` | decompile.function | PIC 装载器入口:解析 PE 节、按类型 1/2/3/4 分派 XOR/LZNT1 解码并映射执行 |
| `ev-000032` | decompile.function | 自定义哈希函数: seed 0xf4283c27, ROR13 + 大写化累加,用于隐藏解析 API |
| `ref:743642c1a9` | evidence.record | 22 个 API 哈希常量全部映射到 kernel32/ntdll 导出名(脚本自算) |
| `ref:7ebccaae7c` | evidence.record | base64 载荷几何(399660 字符->299744 字节,熵 7.987)与 Authenticode 签名主体(脚本自算) |
| `ref:6be75a1a90` | 动态分析平台 | 回滚-启动-投放观测:candidates=0、empty=true、无进程/无转储/无网络事件 |
| `ref:0d43e8ed00` | dyn.run | 用户态仿真仅到 CRT 初始化(8 次 API),未进入 DllEntry 主逻辑 |
| `telemetry:0c3afb30` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 91 条；已过滤工具/系统噪声 22 条 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
