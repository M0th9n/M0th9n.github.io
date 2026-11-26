---
title: "恶意样本分析：Phantom-Labs VRM Stealer（PE · exe · 9238bb50）"
published: 2026-11-25
draft: false
description: "恶意（置信度中）：Phantom-Labs VRM Stealer · stealer/loader · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["Phantom-Labs VRM", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Phantom-Labs VRM Stealer**（存疑） · 置信度 **中**
> 
> 别名：VRM Stealer、phantom-labs.vault stealer
> 
> 该文件伪装为音频设备配套软件 Blue Sherpa 2.2.0[.]0（Blue Microphones LLC），实为一个自解密的投递器：运行时把内嵌容器解密成 2.88MB 的 64 位 PE 并在私有可执行内存中以原基址 0x140000000 执行；内存中的载荷使用 WinHTTP 以 HTTPS POST /sync 回连 heysunlab[.]fun:443，携带固定鉴权头 X-Auth-Token 与 ECDH 临时公钥，并读取 Steam 登录态（loginusers、steamid、web_secure、CEF cookies）后加密外传。文件无数字签名，节名被打乱、无 Rich 头、调试目录为伪造内容。上述行为均在真实运行中被直接观测（内存取证检出植入 PE、网络监控捕获完整请求头与请求体）。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Phantom-Labs VRM Stealer** · 别名 VRM Stealer、phantom-labs.vault stealer · _存疑_ |
| 置信度 | **中** |
| 行为类 | stealer · loader |
| 难度 | hard |
| 首次出现 | 2026-11-25 09:44:59 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/9238bb50f85bd34f3c8127ef7860e6df0ceb631f3c1d0be546716e36ef35aa0f/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">内存解密释放PE载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">解析内嵌加密容器</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">伪装厂商版本信息</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">哈希解析系统API</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.007</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">窃取Steam会话令牌</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `9238bb50f85bd34f3c8127ef7860e6df0ceb631f3c1d0be546716e36ef35aa0f` |
| MD5 | _未记录_ |
| 大小 | 5,802,496 字节（5.5 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **10** 条行为，每条都挂了证据；其中 **5** 条静态可得、**5** 条经动态分析取得。

### 1. 内存解密释放PE载荷

`T1027.009` · 置信度 **高** · 动态

进程在 MEM_PRIVATE + PAGE_EXECUTE_READWRITE 的私有内存中以基址 0x140000000 映射出一份 2.88MB 的 64 位 PE（7 个节，.text 约 2.39MB），该内存区不是已加载模块，属于运行时植入的独立映像。

> **证据**：内存扫描报告 implanted_pe=1、module 140000000 size 0x2bd000、protection 0x40、mapping MEM_PRIVATE；转储文件 140000000.exe sha256 6b295a1bca1d887e253d958cf1d8edf31935ba85198aa48a81849d087dda7888
> 
> **来源**：`ref:310897aeb1` · `ref:1af92d4316`

### 2. 解析内嵌加密容器

`T1027.009` · 置信度 **高** · 静态

main 先按 PE 节表遍历，命中节首 8 字节为 0x9E3779B97F4A7C15 的容器节（RVA 0x2F000，大小 0x55E200），随后按 192 字节数据块/固定跨距的稀疏记录把容器重组为连续缓冲，并校验子块魔数 0x3e8f4a71c62b9d05 后按 0x1c 字节表项解析。

> **证据**：FUN_1400024e0 比对 0x9E3779B97F4A7C15；FUN_140003e90 校验 0x3e8f4a71c62b9d05 并以 0x1c 步长遍历；节 RVA 0x2F000 容量 5,628,416 字节
> 
> **来源**：`ref:a9e6e0427b` · `ref:b371c7f942` · `ref:4227a0d254`

### 3. 伪装厂商版本信息

`T1036.005` · 置信度 **高** · 静态

资源段写入 Blue Microphones LLC / Blue Sherpa 2.2.0[.]0 / BlueSherpa.exe 的完整版本信息，但文件无 Authenticode 签名；同时 PE 节表被改写成 .sxdata/.textbss/.idata/.tls/.edata 等错位且重名的名称，Rich 头缺失，调试目录为伪造内容（类型 13，指向 COFF 符号名区）。

> **证据**：pe.parse: 8 个节出现重复 .sxdata/.edata、rich=false、SECURITY 目录为 0；UTF-16 版本串 Blue Sherpa / 2.2.0[.]0；.rsrc 中 VS_VERSION_INFO
> 
> **来源**：`ref:4227a0d254` · `ref:36525b2e30` · `ref:d6d4f57db2`

### 4. 哈希解析系统API

`T1027.007` · 置信度 **中** · 静态

外层程序不通过常规导入表调用关键例程，而是以常量哈希查找模块句柄与导出函数（如 0xd5a13ff 取模块、0x2574e559/0xac07721b 取函数），容器解析阶段再用函数指针回调完成解密与校验。

> **证据**：FUN_140001000(0xd5a13ff) 后接 FUN_140001280(handle,0x2574e559)/0xac07721b，返回函数指针并在 FUN_140003e90 中调用
> 
> **来源**：`ref:b371c7f942` · `ref:adb3774aa3`

### 5. 窃取Steam会话令牌

`T1555` · 置信度 **高** · 动态

载荷在内存中解密出 Steam 凭据采集逻辑：解析 loginusers 记录，输出 account/steamid/token/web_secure 字段，并统计 cookies（含 CEF 存储）与 pairs；对无法解密令牌的账号记录诊断信息而非跳过。

> **证据**：内存明文串 loginusers、steamid: 、web_secure: 、-> cookies= 、# diag: cef 、account: (web-session) 、# diag: loginusers 未读取 等
> 
> **来源**：`ref:7309bcedf5` · `ref:661eedc6ad`

### 6. ECDH加密上传数据

`T1573.001` · 置信度 **高** · 动态

载荷导入并调用 BCryptGenerateKeyPair/BCryptExportKey/BCryptSecretAgreement/BCryptDeriveKey 完成临时 ECDH 协商，再以 AES-GCM 封装上传内容；HTTP 体为包含 encrypted/salt/nonce/iterations/digest/kdf 的 JSON 信封，并在请求尾部附加 EK:04… 形式的临时公钥。

> **证据**：载荷导入表 bcrypt.BCryptSecretAgreement/BCryptDeriveKey/BCryptEncrypt；内存中 {"encrypted":…,"salt":…,"nonce":…,"iterations":…,"digest":…,"kdf"} 与种子串 .phantom-labs.vault.seed.；POST 体尾部 EK:04760963e0cd3def…
> 
> **来源**：`ref:5f66805ca2` · `ref:661eedc6ad` · `ref:e0a325db6c`

### 7. HTTPS回连C2外传

`T1041` · 置信度 **高** · 动态

载荷以 WinHTTP 对 heysunlab[.]fun:443 发起 HTTPS POST /sync，携带固定鉴权头 X-Auth-Token、Content-Type: text/plain 与轮换的浏览器 UA，首次请求后每 3–5 秒重试一次，连续约 90 秒。

> **证据**：网络监控记录：DNS 查询 heysunlab[.]fun；9238bb50….exe (2112) requested TCP 192.0.2[.]123:443；HTTPListener443 收 POST /sync、X-Auth-Token: VRM-x9k4p2Q8rTmL5Ws1
> 
> **来源**：`ref:8c4c7b0c96` · `ref:e0a325db6c`

### 8. 监听剪贴板内容

`T1115` · 置信度 **中** · 静态

载荷注册无窗口消息循环（RegisterClassExW/CreateWindowExW/DispatchMessageW）并调用 AddClipboardFormatListener 持续接收剪贴板变更消息，配合采集逻辑读取剪贴板文本。

> **证据**：载荷重建导入表含 user32.AddClipboardFormatListener/RemoveClipboardFormatListener/RegisterClassExW/DispatchMessageW
> 
> **来源**：`ref:5f66805ca2`

### 9. 擦除内存取证痕迹

`T1070` · 置信度 **高** · 动态

容器使用完毕后，外层程序把容器节由 RW 改回只读前先整段清零，随后对自身 PE 头所在页申请写权限并立即退出，使内存镜像中既没有容器明文也没有完整头部。

> **证据**：VirtualProtect(0x14002f000,0x55e200,4) → 清零 → VirtualProtect(...,1)；随后 VirtualProtect(0x140000000,0x400,4) 并 ExitProcess(0)（仿真调用序列 pc 0x140005ca4/0x140005cc2/0x140005bbe/0x140005b43）
> 
> **来源**：`ref:f109d64216` · `ref:3b701413c3`

### 10. 采集主机指纹信息

`T1082` · 置信度 **中** · 静态

载荷导入并调用卷序列号、磁盘剩余空间、逻辑处理器拓扑、内存状态、时区、区域设置等接口，用于生成主机指纹并随外传数据一并上报。

> **证据**：载荷导入表 kernel32.GetVolumeInformationW/GetDiskFreeSpaceW/GetLogicalProcessorInformation/GlobalMemoryStatusEx/GetTimeZoneInformation/GetLocaleInfoEx；外层 FUN_140005e70 亦混入 GetComputerNameW/GetSystemMetrics/GetTickCount 派生种子
> 
> **来源**：`ref:5f66805ca2` · `ref:1c8c4180e8`


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
| http | `hxxps://heysunlab[.]fun/sync` | 443 | exfil | 动态 | 已观测 |

### 主机

- **未恢复任何主机 IOC。**

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `heysunlab[.]fun` | 是 | 动态 |
| `c2_uri` | `/sync` | 是 | 动态 |
| `auth_token` | `VRM-x9k4p2Q8rTmL5Ws1 (请求头 X-Auth-Token)` | 是 | 动态 |
| `encryption_algo` | `ECDH（BCryptGenerateKeyPair/BCryptSecretAgreement/BCryptDeriveKey）+ AES-GCM，信封含 encrypted/salt/nonce/iterations/digest/kdf 字段` | 是 | 静态 |
| `campaign_id` | `phantom-labs / VRM（PBKDF2 种子串 .phantom-labs.vault.seed.，令牌前缀 VRM-）` | 否 | 静态 |
| `user_agent` | `每次请求轮换浏览器 UA（Firefox/137.0、Edge/136、Edge/135 等）` | 否 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要判定为勒索软件：BCrypt 的对称加密仅用于 C2 外传封装，未观察到批量文件加密、影子副本删除或勒索说明文件（沙箱内勒索说明计数为 0）。
- 不要把版本信息当作可信来源：Blue Sherpa/Blue Microphones LLC 字样是可伪造的资源，该文件无数字签名，且节表/调试目录明显被改写。
- 不要声称已确认持久化：内存与沙箱产物中均未出现 Run 键、计划任务、服务安装或启动目录写入的证据。
- 不要把它当作纯下载器：第二阶段载荷由内嵌容器在内存中释放并就地执行，未观察到落地可执行文件。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是（stage2 `6b295a1bca1d887e253d958cf1d8edf31935ba85198aa48a81849d087dda7888`） |

**局限与待验证**

1. 载荷字符串在运行时解密，静态 .rdata 中无明文配置，C2 与令牌均来自内存取证与网络监控。
2. 沙箱网络为模拟环境，客户端 TLS 校验未通过，导致同一请求每 3–5 秒重试约 90 秒；因此观测到的是完整请求（方法、路径、鉴权头、请求体尾部）而非服务器侧成功响应，服务端返回内容与后续指令未能获取。
3. 未观察到持久化、进程注入到其他进程、以及二次下载行为，相关能力不能据此断言。
4. 外层容器解密所用的部分例程依赖机器指纹（计算机名/CPU/时区等）派生，离线复现解密结果与真实主机环境相关。

## 证据索引

<details>
<summary>展开 19 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:36525b2e30` | 哈希与指纹 | sha256=9238bb50…aa0f, imphash=7825189a0024596d121cb759a21f3300, 无 Rich 头 |
| `ref:4227a0d254` | PE 结构解析 | AMD64 GUI，8 节，节名错位/重名，SECURITY 目录为空，入口 RVA 0x63C0 |
| `ref:adb3774aa3` | 导入表解析 | 7 个导入 DLL/108 个符号，无网络与进程注入 API，符合外层投递器特征 |
| `ref:a05cbec966` | decompile.function | main(FUN_140002a30) 解析容器并调用 FUN_140003e90 |
| `ref:a9e6e0427b` | decompile.function | FUN_1400024e0 以 0x9E3779B97F4A7C15 定位容器节 |
| `ref:b371c7f942` | decompile.function | FUN_140003e90 校验 0x3e8f4a71c62b9d05 并按 0x1c 表项解析 |
| `ref:3b701413c3` | decompile.function | FUN_140005be0 清零容器节并切换页保护 |
| `ref:f109d64216` | dyn.run | 仿真调用序列显示对 0x2F000/0x55E200 的 VirtualProtect 与对自身 PE 头的写保护变更后 ExitProcess |
| `ref:1af92d4316` | 动态分析平台 | 真实运行：pid 2112 被转储，11 个内存产物，含植入 PE 转储 |
| `ref:310897aeb1` | memory-scan-report | implanted_pe=1，MEM_PRIVATE 基址 140000000、大小 0x2bd000、保护 0x40 |
| `ref:5f66805ca2` | imports-of-dump | 载荷导入 bcrypt ECDH/AES、winhttp、剪贴板监听、SHGetKnownFolderPath、系统指纹类 API |
| `ref:7309bcedf5` | memory-strings | 内存明文：hxxps://heysunlab[.]fun/sync、X-Auth-Token、loginusers/steamid/web_secure、sqlite 语句 |
| `ref:661eedc6ad` | memory-strings | JSON 信封 {"encrypted","salt","nonce","iterations","digest","kdf"} 与 .phantom-labs.vault.seed.、构建路径 …\vrm new\out\release\app.pdb |
| `ref:8c4c7b0c96` | network-log | DNS 查询 heysunlab[.]fun 与进程 2112 对 192.0.2[.]123:443 的连接 |
| `ref:e0a325db6c` | network-log | POST /sync，X-Auth-Token: VRM-x9k4p2Q8rTmL5Ws1，UA 轮换，请求体尾部 EK:04… |
| `ref:be8bbc87df` | memory-strings | 内存中 UA 轮换串与 EK: 公钥字段的上下文 |
| `c2_evidence:9238bb50` | 连接证据提取 | 动态网络监控记录到 18 次到 heysunlab[.]fun:443 的连接尝试；未捕获完整会话 |
| `telemetry:9238bb50` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 139 条；ETW 短命进程事件 1 条；已过滤工具/系统噪声 22 条 |
| `etw:9238bb50:2112` | 进程事件监控 | 短命进程事件：9238bb50f85bd34f3c8127ef7860e6df0ceb631f3c1d0be546716e36ef35aa0f.exe（pid 2112；MD5=6CDE024FB9FA6304258FAB37534FC045,SHA256=9238BB50F85BD34F3C8127EF7860E6DF0CEB631F3C1D0BE546716E36EF35AA0F,IMPHASH=7825189A0024596D121CB759A21F3300） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
