---
title: "恶意样本分析：VRM Stealer（私有/定制 crypter 投递的凭据窃取器）（PE · exe · 9a9646a9）"
published: 2026-11-15
draft: false
description: "恶意（置信度中）：VRM Stealer（私有/定制 crypter 投递的凭据窃取器） · stealer · 难度 hard · 静态反编译（动态执行未取得运行时行为）"
tags: ["VRM", "stealer", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **VRM Stealer（私有/定制 crypter 投递的凭据窃取器）**（存疑） · 置信度 **中**
> 
> 该文件是一个自解密的载荷加载器：main(0x140002a30) 从镜像自身的随机命名节 'zdvylx'（RVA 0x2F000）中定位容器头（magic 0x9f8a3bb43f221fc7），按 240 字节数据 / 240 字节空洞去交织，用容器内嵌的 32 字节密钥与 16 字节 IV（经 xorshift32 流还原）做 AES-256-CBC 解密，再调用 RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF) 解出 2,806,223 字节内层镜像，校验 magic 0x3e8f4a71c62b9d05 后按自定义节表在内存中映射并转入执行。本报告全流程复现了该解密/解压链，解出的内层代码是一套凭据窃取器：内嵌完整 SQLite3 引擎用于读取 Chromium 系浏览器库，包含 Chrome / Edge / Brave / Opera / Opera GX、'\Local State'、'-wal'/'-shm'、Telegram 'tdata\'/'user_data'/'media_cache'/'stickers'、钱包 'PRIVATE_KEY|0x'/'keyRingType'/'keyRingName'/'mnemonic/'、'steamid:'，以及 winhttp 网络栈占位串和上行 JSON 的 '"build_id":' / '"hwid":' 字段。外层版本资源伪装成 Blue Microphones 的 Blue Sherpa 2.2.0[.]0，属于典型诱饵伪装。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **VRM Stealer（私有/定制 crypter 投递的凭据窃取器）** · _存疑_ |
| 置信度 | **中** |
| 行为类 | stealer |
| 难度 | hard |
| 首次出现 | 2026-11-13 12:11:59 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/9a9646a99eca2179c1e92a44ce11ca437b55a41fdf4c140bf3554bf30dfcb736/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置加密载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">去交织取出压缩体</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">解压还原内层镜像</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">哈希解析隐藏API</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">内存映射后执行</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `9a9646a99eca2179c1e92a44ce11ca437b55a41fdf4c140bf3554bf30dfcb736` |
| MD5 | _未记录_ |
| 大小 | 5,357,568 字节（5.1 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **11** 条行为，每条都挂了证据，且全部静态可得。

### 1. 解密内置加密载荷

`T1140` · 置信度 **高** · 静态

main 从自身 'zdvylx' 节取出 32 字节密钥材料与 16 字节 IV 材料，用 xorshift32(seed=0xfcdc579a) 生成密钥流异或还原，再经 BCryptOpenAlgorithmProvider("AES") + ChainingModeCBC 做 AES-256-CBC 解密（密文 2,591,616 字节）。

> **证据**：0x140003cd0 / 0x140003bd0 密钥流还原；0x140003830 内 bcrypt.dll 字符串、"AES"、"ChainingModeCBC" 与 BCryptDecrypt 调用；段 'zdvylx' RVA 0x2F000
> 
> **来源**：`ev-000024` · `ev-000021` · `ev-000022` · `ev-000023`

### 2. 去交织取出压缩体

`T1027` · 置信度 **高** · 静态

解密前先按容器头 0x38/0x3C/0x40/0x44/0x48 字段做块拷贝：每 240 字节有效数据后跳过 240 字节空洞，把 5,183,488 字节节内容重排为 2,591,616 字节连续密文。

> **证据**：0x140002a30 调用 FUN_14001a7b0 的循环，头字段 [+0x40]=0x278b80、[+0x44]=0x600、[+0x48]=0x00f000f0
> 
> **来源**：`ev-000017`

### 3. 解压还原内层镜像

`T1027` · 置信度 **高** · 静态

解密结果送入 RtlDecompressBufferEx（格式 4 = XPRESS Huffman）解压为 2,806,223 字节内层镜像，并校验其首 8 字节等于 0x3e8f4a71c62b9d05、读取 7 条 28 字节节表后在内存中重建映像。

> **证据**：0x140003e90 中 FUN_140001280(0xe345ccb3)/FUN_140001280(0x6a365bf1) 调用 (4, dst, size, src, size, &out, ws)；校验常量 0x3e8f4a71c62b9d05 @ 0x140003ffb 附近
> 
> **来源**：`ev-000020` · `ev-000019`

### 4. 哈希解析隐藏API

`T1027` · 置信度 **高** · 静态

通过遍历模块导出表并按 h = (c|0x20) ^ (h*0x21), h^=0x22719744 的自定义哈希解析 API，避免在导入表中暴露 VirtualAlloc / CreateThread / RtlDecompressBufferEx / BCrypt* 等敏感函数名。

> **证据**：0x1400014c0 哈希函数；0x140001000 按哈希遍历导出表；0x140003e90 内以 0xe345ccb3 / 0x6a365bf1 取压缩相关 API
> 
> **来源**：`ev-000018` · `ev-000020`

### 5. 内存映射后执行

`T1620` · 置信度 **高** · 静态

解出的内层镜像不落盘：按节表分配内存、拷贝 .text/.rdata/.data/.pdata/.init/.rsrc/.reloc 各节并处理重定位，随后把控制权交给内层入口（0x140003e90 组装结构后由 main 继续调用）。

> **证据**：0x140003e90 中按 28 字节节表循环拷贝（piVar17 递增 7 个 dword）+ FUN_140004820/FUN_140003520 写映像
> 
> **来源**：`ev-000020` · `ev-000017`

### 6. 伪装音频软件发行商

`T1036.005` · 置信度 **高** · 静态

版本资源伪造为 Blue Microphones LLC 的 Blue Sherpa 2.2.0[.]0（OriginalFilename BlueSherpa.exe，LegalCopyright 2025），与真实功能无关，用于降低用户与终端防护的警觉。

> **证据**：.rsrc 版本信息：CompanyName 'Blue Microphones LLC'、FileDescription 'Blue Sherpa'、OriginalFilename 'BlueSherpa.exe'
> 
> **来源**：`ev-000010` · `ev-000013`

### 7. 窃取浏览器凭据

`T1555.003` · 置信度 **高** · 静态

内层代码内嵌完整 SQLite3 引擎（含 'SQLite format 3'、sqlite_master 查询、json_* 函数、-wal/-shm 处理），并硬编码 Chrome / Edge / Brave / Opera / Opera GX 与 '\Local State'、'ReadCookie'/'SetCookie' 等符号，用于读取 Cookie、登录数据与自动填充库。

> **证据**：解出镜像 .rdata 偏移 0x2E1xx 起：'Chrome','Edge','Brave','Opera','Opera GX','/Local State','-wal','-shm','_meta.json'；SQLite 引擎字符串（'SQLite format 3'、'sqlite_master'）
> 
> **来源**：`ev-000020`

### 8. 窃取Telegram会话

`T1555` · 置信度 **高** · 静态

硬编码 Telegram Desktop 数据目录结构 'tdata\\'、'user_data'、'media_cache'、'mediaCache'、'stickers'、'emoji_cache'，用于打包会话数据（tdata 可直接接管账号）。

> **证据**：解出镜像 .rdata 偏移 0x1F8xx 附近：'tdata\'、'user_data'、'mediaCache'、'media_cache'、'stickers'、'emoji_cache'、'dumps'
> 
> **来源**：`ev-000020`

### 9. 收割钱包私钥助记词

`T1552.001` · 置信度 **中** · 静态

包含钱包/密钥库特征串 'PRIVATE_KEY|0x'、'keyRingType'、'keyRingName'、'keyhex'、'mnemonic/'、'steamid:'，表明会枚举本机加密钱包与 Steam 会话文件并提取私钥/助记词。

> **证据**：解出镜像 .rdata 偏移 0x20Bxx-0x22Cxx：'PRIVATE_KEY|0x','keyRingType','keyRingName','keyhex','mnemonic/','steamid:'
> 
> **来源**：`ev-000020`

### 10. 回传主机指纹

`T1041` · 置信度 **高** · 静态

内层模块用 winhttp 封装 HTTP 会话（占位串 'winhttpopen='、'connect='、'openreq='、'send='、'recv='、' body='、'http='），并以包含 '"build_id":'、'"hwid":'、'"data":' 的 JSON 向服务端上报主机指纹与窃取结果；上行数据用 AES-GCM 处理（'[AES-GCM failed]'、'[no AES key]'、ECDH_P256/HASH）。

> **证据**：解出镜像 .rdata 偏移 0x1E4xx（build_id/hwid）、0x1F9xx（winhttp 占位串）、0x1FE4x（[AES-GCM failed]）；导入串表含 winhttp/BCrypt 系列
> 
> **来源**：`ev-000020`

### 11. 检测调试器

`T1622` · 置信度 **中** · 静态

内层模块导入/使用 NtQueryInformationProcess（常与 ProcessDebugPort/ProcessDebugFlags 检测配套），外层亦导入 IsDebuggerPresent，用于在调试环境下收敛行为。

> **证据**：解出镜像导入串表含 'NtQueryInformationProcess'（.rdata 0x1E3xx）；外层导入 IsDebuggerPresent（iat_rva 0x1C190）
> 
> **来源**：`ev-000020` · `ev-000003`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `crypter_encryption_algo` | `AES-256-CBC (BCrypt, 密钥/IV 由容器头经 xorshift32 流还原)` | 是 | 静态 |
| `payload_container_magic` | `0x9f8a3bb43f221fc7 (定位节) / 0x3e8f4a71c62b9d05 (内层镜像)` | 是 | 静态 |
| `payload_compression` | `RtlDecompressBufferEx, COMPRESSION_FORMAT_XPRESS_HUFF (4)` | 是 | 静态 |
| `payload_storage_layout` | `240 字节数据块 + 240 字节空洞交替存放` | 是 | 静态 |
| `build_pdb_path` | `C:\Users\Administrator\Desktop\Desktop\vrm new\out\release\app.pdb` | 否 | 静态 |
| `c2_hosts` | `unknown（未从静态数据中恢复明文域名/URL）` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得报为 ransomware / wiper：未发现文件加密循环、扩展名改写或勒索信字符串，内层行为面是凭据收集。
- 不得声称已在沙箱中观测到真实外联或 C2 会话：本次沙箱投放未取回成功会话，C2 数量为零，网络行为仅为静态能力推断。
- 不得断言样本已写入注册表、创建服务或计划任务：未获得相应动态遥测，host_iocs 的注册表/服务/任务三项为空。
- 不得把 'Blue Microphones / Blue Sherpa' 当作真实发行商签署的合法软件：该版本资源与自解密加载链矛盾，属伪装。
- 不得确认具体商业家族名（如 Lumma / Vidar / RedLine）：仅凭构建路径 'vrm new' 只能给出候选与 uncertain 标记。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 是（stage2 `303b3b6b00c61ec77fef4cb4c8f7440c4c2af3e9c1d44b6d93c5d06a7f5e9ab8`） |

**局限与待验证**

1. 沙箱投放（回滚->启动->投放->轮询->产物收集）两次均在接口层超时，样本在观测窗口内未被确认执行，故 reproduced=false、C2 为空、无网络/注册表/文件动态证据。
2. 明文 C2 域名、URI、端口未恢复：内层配置疑似在运行时派生（字符串区存在大量非明文可打印序列）且上行使用 ECDH_P256 + AES-GCM，静态阶段未解出端点。
3. 内层影像是去掉 MZ 头的自定义容器，无法直接作为独立 PE 运行，尚未在仿真器中单步到网络初始化点。
4. 家族归属仅有构建路径 'vrm new' 与日志名 'VRM-%04d%02d%02d' 佐证，缺少厂商命名或 YARA 规则交叉验证。
5. ‘NtQueryInformationProcess’ 只出现在导入字符串表中，未在反汇编层面确认具体检测逻辑，置信度标为中。

## 证据索引

<details>
<summary>展开 14 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000003` | 样本分诊 | 8 个节，'zdvylx' 占 5,183,456 字节（熵 4.981），无壳信号；导入 108 个符号 |
| `ev-000010` | scan.entropy | .rsrc 熵 2.872，仅含 1 KB 版本资源 |
| `ev-000013` | 字符串提取 | 外层的 ASCII/UTF-16 字符串概览，未见明文 URL |
| `ev-000015` | decompile.ghidra | __scrt_common_main_seh：标准 MSVC 启动流程，调用 main(0x140002a30) |
| `ev-000017` | decompile.ghidra | main(0x140002a30)：定位容器 -> 去交织块拷贝 -> 解密 -> 解压 -> 映射 |
| `ev-000018` | decompile.ghidra | 0x1400014c0 API 哈希函数（0x1505/0x21/0x22719744） |
| `ev-000019` | decompile.ghidra | 0x1400024e0 按节首 8 字节 0x9f8a3bb43f221fc7 定位容器，返回节基址与 +0x50 数据区 |
| `ev-000020` | decompile.ghidra | 0x140003e90：RtlGetCompressionWorkSpaceSize/RtlDecompressBufferEx(4)，校验 0x3e8f4a71c62b9d05 并重建 7 段节表 |
| `ev-000021` | decompile.ghidra | 0x140003cd0：用 xorshift32 流异或 32 字节密钥材料 |
| `ev-000022` | decompile.ghidra | 0x140003bd0：预热 9 轮后异或 16 字节 IV 材料 |
| `ev-000023` | decompile.ghidra | 0x140004310：xorshift32 (<<13, >>17, <<5) |
| `ev-000024` | decompile.ghidra | 0x140003830：bcrypt.dll / AES / ChainingModeCBC / BCryptGenerateSymmetricKey / BCryptDecrypt |
| `ev-000025` | decompile.ghidra | 0x140001f70：自定义字节流解码器（备用 0x20 标志分支） |
| `telemetry:9a9646a9` | 动态遥测 | 动态遥测记录到：监控组件 注册表事件 4 条；监控组件 进程/文件事件 85 条；系统服务事件 4 条；已过滤工具/系统噪声 27 条 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
