---
title: "恶意样本分析：Unidentified stage2 loader (stage2.dll/RunStage2)（PE · exe · 5761156e）"
published: 2026-10-30
draft: false
description: "恶意（置信度低）：Unidentified stage2 loader (stage2.dll/RunStage2) · loader/dropper/injector · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["loader", "dropper", "injector", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unidentified stage2 loader (stage2.dll/RunStage2)**（存疑） · 置信度 **低**
> 
> 静态解密出内置俄文诱饵文档并通过 explorer 代启；尾部 overlay 去重排后解密出带进程注入能力的 stage2 PE；真实动态沙箱中该样本进程（pid 676）反复向 151.244.30[.]118:80 发起 HTTP GET 回连。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unidentified stage2 loader (stage2.dll/RunStage2)** · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · dropper · injector |
| 难度 | medium |
| 首次出现 | 2026-10-29 06:28:26 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/5761156e111a1a20364b9c6f91afa524533a24bbd73217bbb0add2d492cd89cf/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">读取自身尾部载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">解密内置诱饵容器</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">释放俄文诱饵PDF</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">经explorer代启PDF</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">HTTP GUID路径回连</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `5761156e111a1a20364b9c6f91afa524533a24bbd73217bbb0add2d492cd89cf` |
| MD5 | _未记录_ |
| 大小 | 523,476 字节（511.2 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **8** 条行为，每条都挂了证据；其中 **7** 条静态可得、**1** 条经动态分析取得。

### 1. 读取自身尾部载荷

`T1027` · 置信度 **高** · 静态

以 GetModuleFileNameW 取得自身路径后 CreateFileW/ReadFile 打开自身，按最后一个 section 的 RVA+VirtualSize 页对齐计算 overlay 起点，将全部追加数据读入堆内存。

> **证据**：0x140004197: GetModuleFileNameW/CreateFileW/GetFileSize/SetFilePointerEx/ReadFile；0x1400042da 解析 PE 段表计算对齐长度
> 
> **来源**：`ev-000018`

### 2. 解密内置诱饵容器

`T1140` · 置信度 **高** · 静态

对 .text 内 rva 0x4710、长度 0x1cf23 的数据用自定义 xorshift 流密码（seed 0x7afffe80）解密，得到 [count][nameLen][dataLen][name][data] 容器，count=1。

> **证据**：0x140003ce2 流密码实现（xorshift/mul 0x9e3779b1/add 0xfef3133e/rol26）；0x140003999 解析容器；seed@rva 0x21634=0x7afffe80，长度@0x4708=0x1cf23
> 
> **来源**：`ev-000019` · `ev-000016` · `ev-000033`

### 3. 释放俄文诱饵PDF

`T1027.009` · 置信度 **高** · 静态

把容器内唯一文件 Запрос.pdf（118,535 字节，%PDF-1.7）写入 %LOCALAPPDATA%\Temp\ 或（回退）%TEMP%\，随后关闭句柄。

> **证据**：0x140003999: CreateFileA(GENERIC_WRITE/CREATE_ALWAYS)+WriteFile；动态仿真中 file_access create/write 118535 字节到 C:\Windows\temp\\Запрос.pdf
> 
> **来源**：`ev-000016` · `ev-000033` · `ref:0fd46fad6e`

### 4. 经explorer代启PDF

`T1204.002` · 置信度 **高** · 静态

ShellExecuteA(NULL, "open", "explorer.exe", <诱饵路径>, NULL, SW_SHOW) 由 explorer 代为打开文档，避免直接 CreateProcess 落痕。

> **证据**：0x140003999 尾部: ShellExecuteA(hwnd=0, "open", "explorer.exe", path, 0, 5)；动态仿真 pc=0x140003c91
> 
> **来源**：`ev-000016` · `ref:0fd46fad6e`

### 5. 去重排解密二阶段

`T1140` · 置信度 **高** · 静态

对 overlay（0x58ad4 字节）执行 32 段伪随机去间隙重排，再以 seed 0x7fbb2404 解密前 0x24c00 字节，得到 AMD64 PE（stage2.dll，导出 RunStage2，EntryPoint 0x31a0）。

> **证据**：0x140004423 去重排（参数 0x58ad4/0x3aa00/seed 0xefbf3105/5/58/0/3，段长表@0x21660）；0x140001603 调用 0x140003ce2 解密；0x140001d2d 串联调用
> 
> **来源**：`ev-000022` · `ev-000026` · `ev-000029` · `ev-000033`

### 6. 注入执行二阶段模块

`T1055.012` · 置信度 **中** · 静态

stage2 具备 VirtualAllocEx/WriteProcessMemory/VirtualProtectEx/GetThreadContext/SetThreadContext/ResumeThread/NtUnmapViewOfSection/NtCreateSection/NtMapViewOfSection/CreateProcessInternalW 等导入与动态解析字符串，构成远程进程注入/空洞化执行链；主样本通过函数指针把该模块与数据缓冲区交给加载器。

> **证据**：stage2 字符串表 0x1dd1c-0x1de0b: ZwQueryVirtualMemory/NtUnmapViewOfSection/NtMapViewOfSection/NtCreateSection/CreateProcessInternalW；0x1400032f6 通过 DAT_140027780+ctx[0] 间接调用
> 
> **来源**：`ev-000033` · `ev-000031`

### 7. HTTP GUID路径回连

`T1071.001` · 置信度 **高** · 动态

样本进程（pid 676）向 151.244.30[.]118:80 反复发起 GET /66ccc916-eeea-4c41-a612-445cf6ef5a1c，User-Agent 为 Mozilla/5.0，约 0.5 秒重试一次，持续到沙箱收口。

> **证据**：网络监控日志: 'Diverter 5761156e...exe (676) requested TCP 151.244.30[.]118:80'，随后 'GET /66ccc916-eeea-4c41-a612-445cf6ef5a1c HTTP/1.1'（8 秒内约 110 次）
> 
> **来源**：`ref:1f73be6e83` · `ref:e1a9987fae`

### 8. 伪造厂商版本信息

`T1036.005` · 置信度 **高** · 静态

资源版本信息伪装为 CompanyName=Jacobson Logistics、FileDescription=Shell Plugin Broker、OriginalFilename=shellpluginhost.exe、FileVersion=9.52.8111.397，且无数字签名。

> **证据**：VS_VERSION_INFO 字符串表（decompile.symbols 提取）: Jacobson Logistics / Shell Plugin Broker / shellpluginhost.exe
> 
> **来源**：`ref:76c099623b`


## IOC（已去武器化）

### 网络

:::note
**已动态观测到连接**：样本实际向该目标发起 TCP 连接（短时间内多次重试）。
:::

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://151.244[.]30[.]118/66ccc916-eeea-4c41-a612-445cf6ef5a1c` | 80 | c2 | 动态 | 已观测 |

### 主机

**落地路径**

- `%TEMP%\Запрос.pdf`
- `%LOCALAPPDATA%\Temp\Запрос.pdf`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `decoy_document` | `Запрос.pdf` | 是 | 静态 |
| `drop_path` | `%TEMP%\Запрос.pdf（优先 %LOCALAPPDATA%\Temp\Запрос.pdf）` | 否 | 静态 |
| `encryption_algo` | `自定义流密码：xorshift32 生成状态，key=(state*0x9e3779b1+0xfef3133e)，逐字节异或；反馈 state=rol26(cipher_dword^state)；诱饵容器 seed=0x7afffe80，stage2 seed=0x7fbb2404` | 是 | 静态 |
| `payload_transform` | `32 段伪随机去间隙重排（seed=0xefbf3105，参数 5/58/0/3，段长表 22-24）后解密前 0x24c00 字节` | 是 | 静态 |
| `stage2_module` | `stage2.dll（导出 RunStage2，AMD64，ImageBase 0x180000000，EntryPoint 0x31a0）` | 是 | 静态 |
| `c2_endpoint` | `hxxp://151.244[.]30[.]118/66ccc916-eeea-4c41-a612-445cf6ef5a1c` | 是 | 动态 |
| `user_agent` | `Mozilla/5.0` | 否 | 动态 |
| `beacon_behavior` | `约 0.5 秒间隔连续 GET 同一 GUID 路径（8 秒内约 110 次）` | 否 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要判定为勒索/擦除器：未观察到任何用户文件加密、删除或勒索信息。
- 不要把诱饵 PDF 说成漏洞利用文档：该 PDF 不含 /JS、/JavaScript、/OpenAction、/Launch、/EmbeddedFile、/AA 或 /URI 动作。
- 不要声称已确认持久化：本次未观察到注册表 Run 键、服务或计划任务写入。
- 不要判定为信息窃取器：未观察到浏览器凭据、键盘记录、剪贴板或钱包相关行为。
- 不要断言家族归属：除构建产物与回连特征外，未取得家族专属标识。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `a8f9df819ff42e8d50423075989162d48fef10c51b47bd2c4b0a5a00b88a0959`） |

**局限与待验证**

1. C2 地址与 GUID 路径只来自动态观测，静态载荷中未找到明文 IP（推测运行时解密），因此 c2 标记为 dynamic。
2. stage2 的完整配置、后续下发内容与注入目标进程未能观测：内存取证采样时（运行早期）尚未捕获到注入区。
3. 沙箱运行窗口有限，未观察到持久化、提权或数据回传报文；C2 应答未获取。
4. 诱饵 PDF 本身无脚本动作，其作用是社工诱饵；无法据此确认攻击链最终载荷类型。
5. 样本含较多不可达的混淆代码与自定义加密器，静态函数边界由反编译近似恢复，个别常量语义以运行时行为为准。
6. 回连 URL 中的 GUID 可能是受害机/会话标识，不是固定的 C2 路径。

## 证据索引

<details>
<summary>展开 17 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 样本分诊 | sha256/md5/sha1/imphash 与整体分诊 |
| `ev-000008` | 样本分诊 | 加壳可能性 35%，.text 熵 7.879 |
| `ev-000016` | decompile.function | 0x140003999 容器解析+释放文件+ShellExecuteA |
| `ev-000018` | decompile.function | 0x140004197 自读文件尾部 overlay |
| `ev-000019` | decompile.function | 0x140003ce2 自定义流密码 |
| `ev-000022` | decompile.function | 0x140004423 32 段去间隙重排 |
| `ev-000026` | decompile.function | 0x140001603 解密 stage2 缓冲区 |
| `ev-000029` | decompile.function | 0x140001d2d 串联去重排与解密 |
| `ev-000031` | decompile.function | 0x1400032f6 通过函数指针调用加载器 |
| `ev-000032` | evidence.record | 脚本复现解密/去重排（含更正前占位哈希，已被 ev-000033 取代） |
| `ev-000033` | evidence.record | 诱饵 PDF 与 stage2 PE 的尺寸/哈希/导出/导入 |
| `ev-000034` | evidence.record | 诱饵 PDF 无脚本/动作关键字 |
| `ref:1f73be6e83` | 动态分析平台 | 真实沙箱引爆、时间线与产出包（含网络监控日志） |
| `ref:0fd46fad6e` | dyn.run | 仿真观测写文件与 ShellExecuteA |
| `ref:76c099623b` | decompile.symbols | 版本信息与导入/字符串表 |
| `ref:e1a9987fae` | network log | pid 676 请求 151.244.30[.]118:80 与 GET 路径原文 |
| `c2_evidence:5761156e` | 连接证据提取 | 动态网络监控记录到 29 次到 151.244.30[.]118:80, 151[.]244[.]30[.]118:80, 224.0.0[.]251:5353, 239.255.255[.]250:1900, arc[.]msn[.]com:443, config[.]edge[.]skype[.]com:443, edge[.]microsoft[.]com:443, ntp[.]msn[.]cn:443, www[.]bing[.]com:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
