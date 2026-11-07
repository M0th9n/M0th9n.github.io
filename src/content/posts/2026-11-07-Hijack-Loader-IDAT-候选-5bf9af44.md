---
title: "恶意样本分析：Hijack Loader (IDAT) 候选（PE · exe · 5bf9af44）"
published: 2026-11-07
draft: false
description: "恶意（置信度低）：Hijack Loader (IDAT) 候选 · loader/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Hijack", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Hijack Loader (IDAT) 候选**（存疑） · 置信度 **低**
> 
> 别名：IDAT Loader、signed-binary loader、签名滥用型下载器
> 
> 样本运行后从公共云盘下载加密载荷，并在内存中解密、手工映射执行；隔离沙箱中真实观测到与内置字符串完全一致的 HTTP 下载请求；其 360 代码签名校验为 HashMismatch（内容被篡改），属签名滥用 + 下载器/加载器链路。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Hijack Loader (IDAT) 候选** · 别名 IDAT Loader、signed-binary loader、签名滥用型下载器 · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | medium |
| 首次出现 | 2026-11-06 00:40:23 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/5bf9af4450ec63c2b592f054ba876cb40b96678363d8bdc49455e9a7dd3bfcd9/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">篡改360签名</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">资源藏二级载荷</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">解密资源到RWX内存</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">HTTP下载载荷</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">AES解密下载内容</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `5bf9af4450ec63c2b592f054ba876cb40b96678363d8bdc49455e9a7dd3bfcd9` |
| MD5 | _未记录_ |
| 大小 | 1,152,272 字节（1.1 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **8** 条行为，每条都挂了证据；其中 **7** 条静态可得、**1** 条经动态分析取得。

### 1. 篡改360签名

`T1553.002` · 置信度 **高** · 静态

文件携带 QIHU 360 SOFTWARE CO. LIMITED 的 VeriSign 代码签名，但 Authenticode 校验结果为 HashMismatch，说明签名后内容被修改，属签名滥用以降低告警。

> **证据**：Authenticode 校验: Status=HashMismatch, Signer=CN=QIHU 360 SOFTWARE CO. LIMITED (Symantec Class 3 SHA256 Code Signing CA)
> 
> **来源**：`ev-000024`

### 2. 资源藏二级载荷

`T1027.009` · 置信度 **高** · 静态

Delphi 宿主在自定义资源类型 rtirtwerqq / 名称 tjertier6 中存放 203,508 字节高熵数据（首 4 字节为载荷长度 202,240），不依赖外部文件即可携带下一阶段。

> **证据**：资源 RVA 0xE3C7C, size 0x31AF4; 首字段 0x31600; 0x4C9852 处 push 'tjertier6'/'rtirtwerqq' 后调用资源流创建
> 
> **来源**：`ev-000022` · `ev-000011` · `ev-000010`

### 3. 解密资源到RWX内存

`T1620` · 置信度 **高** · 静态

入口 FormCreate 通过 GetProcAddress(GetModuleHandleA('kernel32'),'VirtualAlloc') 申请 PAGE_EXECUTE_READWRITE 内存，按 322→320 字节行去填充重排后做位置相关 XOR 解码，最后以 push/ret 跳入刚解密的可执行缓冲区。

> **证据**：0x4C9877 GetModuleHandleA('kernel32'); 0x4C987D GetProcAddress('VirtualAlloc'); 0x4C98A1/0x4C98C1 VirtualAlloc(size+0x140, MEM_COMMIT=0x1000, PAGE_EXECUTE_READWRITE=0x40); 0x4C99CB ret 跳转
> 
> **来源**：`ev-000019` · `ev-000022`

### 4. HTTP下载载荷

`T1105` · 置信度 **高** · 动态

第二级 PE 构造 InternetOpenA/InternetConnectA/HttpOpenRequestA/HttpSendRequestA 请求，从 drive[.]usercontent[.]google[.]com 下载以 Google Drive id 标识的文件；沙箱网络日志中观测到与内置字符串完全一致的 GET 请求。

> **证据**：0x401975 含 InternetOpenA/InternetConnectA(port 0x50)/HttpOpenRequestA/HttpSendRequestA；0x42A1A8 URL 常量；网络日志 03:04:47 GET /download?id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY...
> 
> **来源**：`ev-000015` · `ev-000023` · `ev-000012`

### 5. AES解密下载内容

`T1140` · 置信度 **高** · 静态

使用 CryptoAPI（Microsoft Enhanced RSA and AES Cryptographic Provider）以 SHA-256 哈希派生 AES-128 密钥，对下载数据按 160 字节分块 CryptDecrypt，得到可执行的下一阶段。

> **证据**：0x402F8D: CryptAcquireContextW → CryptCreateHash(0x800C) → CryptHashData → CryptDeriveKey(0x660E) → CryptDecrypt 循环，块长 0xA0
> 
> **来源**：`ev-000018` · `ev-000012`

### 6. 手工映射PE并调用导出

`T1129` · 置信度 **高** · 静态

对解密后的缓冲区做手工 PE 映射（校验 DOS/NT 头、节对齐、分配并改写页保护），随后按序号/名称解析导出并调用 updateSW，使载荷无需落地即可执行。

> **证据**：含 'DOS header is not valid!'/'Signature != IMAGE_NT_SIGNATURE!'/'alignedImageSize != AlignValueUp!' 等映射错误串；0x4041A9 中解析 'updateSW' 后 (*pcVar11) 循环调用
> 
> **来源**：`ev-000017` · `ev-000016` · `ev-000012`

### 7. 写注册表持久化

`T1547.001` · 置信度 **中** · 静态

通过 RegCreateKeyExA/RegSetValueExA 在 HKEY_CURRENT_USER 下创建子键并写入 REG_SZ 值；键名/值名在运行时由内置口令解密得到。

> **证据**：0x40467A RegCreateKeyExA(hKey=0x80000001=HKEY_CURRENT_USER, ...); 0x4046BE RegSetValueExA(type=REG_SZ)
> 
> **来源**：`ev-000017` · `ev-000012`

### 8. 随机延时规避沙箱

`T1497.003` · 置信度 **高** · 静态

启动后随机 Sleep(1000~5000ms)，下载/装载循环中再以 Sleep(2000~3000ms) 轮询重试，拖延沙箱观测窗口，降低自动化分析成功率。

> **证据**：0x4041A9: Sleep(随机 1000~4000); 循环内 Sleep(3000)；0x404800: Sleep(随机 1000~5000)；0x40457F 循环内 Sleep(2000)
> 
> **来源**：`ev-000016` · `ev-000017`


## IOC（已去武器化）

### 网络

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://drive[.]usercontent[.]google[.]com/download?id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY&export=download&authuser=0&confirm=t` | 80 | download | 动态 | — |

### 主机

**落地路径**

- `%TEMP%\<运行时解密目录>\service（由 GetTempPathA 结果拼接 '/service'）`

**注册表**

- `HKCU\<运行时解密子键>（RegCreateKeyExA/RegSetValueExA 写入 REG_SZ）`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `drive[.]usercontent[.]google[.]com` | 是 | 动态 |
| `download_url` | `hxxp://drive[.]usercontent[.]google[.]com/download?id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY&export=download&authuser=0&confirm=t` | 是 | 动态 |
| `http_headers` | `Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1 ; Accept-Language: ru-RU,ru;q=0.9,en;q=0.8 ; Accept-Charset: iso-8859-1, utf-8, utf-16, *;q=0.1 ; Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0` | 否 | 静态 |
| `encryption_algo` | `AES-128 (CALG_AES_128, CryptoAPI)，密钥由 SHA-256(CALG_SHA_256) 对内置口令字符串派生；静态可见口令常量 A1B2C3D4E5F6G7H8` | 是 | 静态 |
| `export_name` | `updateSW` | 是 | 静态 |
| `persistence` | `HKEY_CURRENT_USER 下 RegCreateKeyExA + RegSetValueExA(REG_SZ)` | 否 | 静态 |
| `campaign_markers` | `mixeleven / mixtwelve / mixthirt / mixsix / uniqjjtwo / /service` | 否 | 静态 |
| `stage2_sha256` | `551600eccf6cd51db03d465b96218e286acba1056eab90c01e4d17b336c57cc1` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能断言该文件是 360 官方正常程序：其数字签名校验为 HashMismatch，内容在签名后被修改。
- 不能断言已确认最终载荷家族与用途：下载内容被隔离网络拦截，未取得真实下一阶段样本。
- 不能断言存在勒索/文件加密行为：本次未观察到文件加密、勒索信或卷影删除。
- 不能断言公共云盘地址本身是传统 C2 服务器：它是载荷托管/下载点，未观察到命令控制信道。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `551600eccf6cd51db03d465b96218e286acba1056eab90c01e4d17b336c57cc1`） |

**局限与待验证**

1. 第二级的注册表子键、写入值名、落地目录名、互斥体等字符串为运行时加密，静态未能还原具体文本。
2. 下载的最终载荷未取得（网络被隔离重定向，返回非真实内容），因此无法给出下一阶段家族与 C2。
3. 内存取证在启动后约 34 秒采集，可能早于随机延时结束，未捕获到映射后的载荷镜像；内存扫描未报告注入/镂空模块。
4. 沙箱轮询未发现新子进程，载荷以导出函数方式在原进程内执行，属预期行为而非样本未运行。
5. 家族命名为候选（低置信度），仅基于作案手法组合，缺少公开指纹或配置字段佐证。

## 证据索引

<details>
<summary>展开 13 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | 样本 sha256/md5/imphash |
| `ev-000002` | scan.imphash | imphash=3427ca46131c1a1a2c4ea2922a963ba0 |
| `ev-000010` | scan.entropy | .rsrc 熵 7.249（高） |
| `ev-000011` | 字符串提取 | 宿主字符串与 Delphi 资源字符串 |
| `ev-000012` | 字符串提取 | stage2 字符串：Google Drive URL、updateSW、/service、AES 口令等 |
| `ev-000015` | decompile.ghidra | stage2 HTTP 下载函数 FUN_00401975 |
| `ev-000016` | decompile.ghidra | stage2 下载→AES 解密→映射→调用 updateSW 的主流程 |
| `ev-000017` | decompile.ghidra | stage2 安装/注册表/延时与路径逻辑 FUN_00404800 |
| `ev-000018` | decompile.ghidra | stage2 CryptoAPI AES-128 解密函数 FUN_00402F8D |
| `ev-000022` | evidence.record | 资源解密还原出 stage2 PE（sha256 5516...） |
| `ev-000023` | evidence.record | 沙箱网络日志观测到云盘下载请求（含 stage2 特征请求头） |
| `ev-000024` | evidence.record | Authenticode 校验 HashMismatch，签名者为 360 |
| `c2_evidence:5bf9af44` | 连接证据提取 | 动态网络监控记录到 1 次到 maps[.]windows[.]com:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
