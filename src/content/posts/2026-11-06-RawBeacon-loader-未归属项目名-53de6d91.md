---
title: "恶意样本分析：RawBeacon loader (未归属项目名)（PE · dll · 53de6d91）"
published: 2026-11-06
draft: false
description: "恶意（置信度中）：RawBeacon loader (未归属项目名) · loader · 难度 hard · 静态反编译（DLL 未被宿主加载，动态未生效）"
tags: ["RawBeacon", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **RawBeacon loader (未归属项目名)**（存疑） · 置信度 **中**
> 
> 别名：rawbeacon.dll、goopdate.dll 伪装组件、RunPayload 加载器
> 
> 反编译外层导出 DllEntry 可见完整的手工映射器：以 VirtualAlloc(0x6a180000,0x6f000) 申请镜像空间、逐节复制内嵌 PE、修正重定位、按导入表 LoadLibraryA/GetProcAddress 解析后调用内层入口，并以 lstrcmpA 查找导出名 RunPayload 后直接调用；内层 RunPayload 再以 VirtualAlloc(RWX,0x63a2e)+memcpy+FlushInstructionCache 执行位置无关载荷。该链路属典型的反射式加载器（隐蔽执行内嵌代码），与正常更新组件行为不符。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **RawBeacon loader (未归属项目名)** · 别名 rawbeacon.dll、goopdate.dll 伪装组件、RunPayload 加载器 · _存疑_ |
| 置信度 | **中** |
| 行为类 | loader |
| 难度 | hard |
| 首次出现 | 2026-11-05 10:21:15 |
| 分析方法 | 静态反编译（DLL 未被宿主加载，动态未生效） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/53de6d9138476ce0d55fa6a1449d16189478f81f7cd2983580af0e8c8b247a1a/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">冒充谷歌更新组件</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">手工映射内嵌DLL</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">按导出名调用载荷</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">执行无文件载荷</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">内嵌位置无关加载器</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `53de6d9138476ce0d55fa6a1449d16189478f81f7cd2983580af0e8c8b247a1a` |
| MD5 | _未记录_ |
| 大小 | 447,960 字节（437.5 KB） |
| 类型 | PE · `dll` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 冒充谷歌更新组件

`T1036.005` · 置信度 **高** · 静态

外层 DLL 的导出表 DLL 名为 goopdate.dll，且仅导出一个 DllEntry，伪装成 Google Update 的组件名以规避基于名称的检测。

> **证据**：PE 导出表 dll_name=goopdate.dll, export DllEntry RVA 0x1610
> 
> **来源**：`ref:61d32f12b6`

### 2. 手工映射内嵌DLL

`T1620` · 置信度 **高** · 静态

DllEntry 在固定地址 0x6a180000 申请 0x6f000 字节空间，复制内嵌镜像首 0x400 字节与各节数据，按 IMAGE_REL_BASED_HIGHLOW 修正重定位，遍历导入表调用 LoadLibraryA/GetProcAddress 填充 IAT，再调用内层镜像入口。

> **证据**：0x650c1610 VirtualAlloc(0x6a180000,0x6f000,0x3000,0x40) + 逐节 memcpy + 重定位/导入解析
> 
> **来源**：`ref:7a2aba74bf`

### 3. 按导出名调用载荷

`T1620` · 置信度 **高** · 静态

映射完成后以 lstrcmpA 在导出名表中匹配 "RunPayload"，命中即调用对应函数地址，实现按名称链式激活内嵌组件。

> **证据**：0x650c1610 lstrcmpA(..., "RunPayload") 后 call [导出地址表]
> 
> **来源**：`ref:7a2aba74bf` · `ref:5a89550279`

### 4. 执行无文件载荷

`T1055` · 置信度 **高** · 静态

内层导出 RunPayload 以 VirtualAlloc(0,0x63a2e,PAGE_EXECUTE_READWRITE) 申请可读写执行内存，从镜像 .rdata(RVA 0x4044) 复制 408,110 字节，FlushInstructionCache 后直接 call 该缓冲区，载荷不以文件形式落盘。

> **证据**：0x6a1814f0 VirtualAlloc(0,0x63a2e,0x3000,0x40); memcpy(dst,0x6a184044,0x63a2e); FlushInstructionCache; call dst
> 
> **来源**：`ref:76e6328e85`

### 5. 内嵌位置无关加载器

`T1027` · 置信度 **中** · 静态

.rdata RVA 0x4044 起为一段位置无关的编译代码：入口为 0x8C4 字节栈帧的函数，内部自行调用 memset/memcpy、读取 PE 头字段（e_lfanew/节表）、申请页内存并按 0x1000/0x10000 对齐参数构造映射，另含以常量比较分派 API 的哈希解析函数，用于在内存中装载后续载荷。

> **证据**：inner RVA 0x4044: 55 8B EC 83 E4 F8 81 EC C4 08 00 00；0x5EE0 处为 cmp edx,imm32 的哈希分派序列
> 
> **来源**：`ref:d352a70532`

### 6. 藏匿加密载荷容器

`T1140` · 置信度 **中** · 静态

内层 .rdata RVA 0x6146 起存放 399,660 字符 base64 文本，解码后为 299,744 字节容器（version=1、0xC0 字节密钥/签名块、长度 0x49210），主体 299,536 字节熵 7.98，属加密或压缩的后续载荷，静态无法直接还原。

> **证据**：base64 @文件偏移 0x5A26(内层 RVA 0x6146)，解码头 01000000C00000001092040010920400
> 
> **来源**：`ev-000019`

### 7. 携带个体签名证书

`T1553.002` · 置信度 **高** · 静态

外层 DLL 带有效格式的 Authenticode 签名：根为 Microsoft Identity Verification Root Certificate Authority 2020，叶证书主体为个人 ISABEL ALEJANDRA FLORES，用于提升执行时的信任度并干扰基于签名信誉的判定。

> **证据**：安全目录 file offset 0x69C00 size 0x39D8，PKCS#7 叶证书 CN=ISABEL ALEJANDRA FLORES
> 
> **来源**：`ev-000020`

### 8. 备用诱导文件路径

`T1204.002` · 置信度 **低** · 静态

外层 .rdata 同时存放 UTF-16 字符串 cam_numbers_39d9b1.pdf、win.dll 与格式串 "%s%s"，并导入 GetTempPathW/CopyFileW/ShellExecuteExW/wsprintfW，具备拼接临时目录路径、写出伪装文档并启动的能力组合。

> **证据**：outer .rdata off 0x1e60-0x1ed6 含 cam_numbers_39d9b1.pdf / win.dll / %s%s；导入 GetTempPathW、CopyFileW、ShellExecuteExW
> 
> **来源**：`ref:6251094f9a` · `ref:54aca43490`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `%TEMP%\win.dll`
- `%TEMP%\cam_numbers_39d9b1.pdf`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `embedded_payload_container` | `内层 .rdata RVA 0x6146 起 399,660 字符 base64 → 299,744 字节容器：version=1、0xC0 字节密钥/签名块、两处 0x00049210 长度字段，0xD0 起 299,536 字节主体（熵 7.98，加密/压缩）` | 是 | 静态 |
| `install_path` | `%TEMP%\win.dll` | 否 | 静态 |
| `decoy_document` | `%TEMP%\cam_numbers_39d9b1.pdf` | 否 | 静态 |
| `signer_subject` | `C=US, ST=in, L=East Chicago, O=ISABEL ALEJANDRA FLORES, CN=ISABEL ALEJANDRA FLORES (issuer: Microsoft ID Verified CS AOC CA 04)` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 未观测到任何真实外联，不能宣称存在已确认的 C2 域名/IP 或通信协议。
- 不能宣称样本会实际写出 cam_numbers_*.pdf 诱饵并调用 ShellExecuteExW——仅见字符串与相关导入，未取得调用链或运行证据。
- 不能把 goopdate.dll/Google Update 名称当作正版组件，也不能据此认定其与 Google 相关。
- 内嵌 292KB 载荷未解密，不能宣称其最终功能为窃密、RAT、勒索或挖矿。
- 未校验证书吊销与时间戳状态，不能宣称签名有效或已被吊销。
- 未观察到动态落地文件，不能宣称存在持久化（服务/计划任务/注册表）。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（DLL 未被宿主加载，动态未生效） |
| 脱壳 | 否 |

**局限与待验证**

1. 样本为 DLL 且导出为非标准入口（DllEntry），投放后未被宿主加载，动态沙箱未产生新进程、未捕获样本侧 DNS/TCP 记录，故无动态行为证据；reproduced=false。
2. 内嵌 299,536 字节载荷为高熵加密/压缩数据，解密算法与密钥位于 .rdata 的位置无关代码中，未完成还原，后续能力（C2、持久化、窃密等）均未知。
3. cam_numbers_39d9b1.pdf 与 win.dll 仅为字符串及导入组合，未定位到调用点，释放/诱饵行为待动态验证。
4. 证书仅按结构解析出主体与链，未做吊销、有效期与签名完整性的密码学校验。
5. 动态档位虽启用，但无真实引爆结果，因此所有 c2/config 动态字段均保持 pending_dynamic_verify。

## 证据索引

<details>
<summary>展开 8 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小确认 |
| `ev-000002` | scan.imphash | imphash=aacb2e69d0124c38c8150f18be1a9539 |
| `ev-000014` | decompile.ghidra | DllEntry @0x650c1610：手工映射内嵌 PE、解析导入、按 RunPayload 名称调用 |
| `ev-000016` | decompile.ghidra | RunPayload @0x6a1814f0：RWX 分配 + memcpy .rdata + FlushInstructionCache + call |
| `ev-000016` | disasm.function | RunPayload 指令级确认 VirtualAlloc 0x63a2e / memcpy 0x6a184044 |
| `ev-000019` | 脚本化取证 | base64 容器解码：299,744 字节，头部 version=1/0xC0/0x49210，主体熵 7.98 |
| `ev-000020` | 脚本化取证 | Authenticode PKCS#7 解析：微软签名链，叶主体 ISABEL ALEJANDRA FLORES |
| `c2_evidence:53de6d91` | 连接证据提取 | 动态网络监控记录到 2 次到 maps[.]windows[.]com:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
