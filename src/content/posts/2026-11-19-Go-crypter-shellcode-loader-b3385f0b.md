---
title: "恶意样本分析：Go crypter shellcode loader（PE · exe · b3385f0b）"
published: 2026-11-19
draft: false
description: "恶意（置信度低）：Go crypter shellcode loader · loader/backdoor · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["crypter", "loader", "backdoor", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Go crypter shellcode loader**（存疑） · 置信度 **低**
> 
> 别名：crypter_persist、Go OneDrive loader
> 
> 该样本是 Go 语言编译的 shellcode 加载器（crypter）：静态可见 main.runStage1/2/3 与 main.DecryptAES，内嵌三段 AES-CBC 密文；运行时会以 C:\ProgramData\OneDrive.exe 名义自我复制、通过 schtasks 创建登录触发的计划任务、尝试为 C:\ProgramData 添加 Defender 排除，并把解密后的 shellcode 写入 RWX 内存后建线程执行。动态沙箱中样本派生出的 OneDrive.exe 进程每约 5 秒解析域名 nxbase[.]im 并尝试连接 TCP 7777，呈现典型的远控回连行为。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Go crypter shellcode loader** · 别名 crypter_persist、Go OneDrive loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · backdoor |
| 难度 | medium |
| 首次出现 | 2026-11-16 15:00:13 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/b3385f0b6c15c5abe66c6f62af3fa1306f5ee3e7ea58731300b1fa0585808f27/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置Shellcode</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">RWX内存执行Shellcode</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">假冒OneDrive落地</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">注册登录计划任务</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">周期回连C2</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `b3385f0b6c15c5abe66c6f62af3fa1306f5ee3e7ea58731300b1fa0585808f27` |
| MD5 | _未记录_ |
| 大小 | 2,396,672 字节（2.3 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **6** 条静态可得、**1** 条经动态分析取得。

### 1. 解密内置Shellcode

`T1140` · 置信度 **高** · 静态

把 .rdata 中的三段 AES-CBC 密文（0x1D560、0x11D60、0x19400 字节）复制到堆缓冲区，调用 main.DecryptAES（内部经 main.DeriveKey 派生密钥）解密；长度非 16 倍数时报“payload is not a multiple of the block size”，失败时报“decryption failed: %w”。

> **证据**：main.DecryptAES @rva 0xea310 → 0xe9fb0；密文 rva 0x12a2d0 / 0xff170 / 0x110ed0；字符串“payload is not a multiple of the block size”@0x4f9521、“decryption failed: %w”@0x4f2f61
> 
> **来源**：`ev-000013` · `ref:db14d4cf66` · `ref:117c5443b7`

### 2. RWX内存执行Shellcode

`T1620` · 置信度 **高** · 静态

用 VirtualAlloc(0x3000=PAGE_EXECUTE_READWRITE, MEM_COMMIT) 申请可执行内存，把解密后的载荷拷入，再调用 CreateThread 启动 shellcode，并按阶段打印“[1]/[2]/[3] Shellcode thread started”。

> **证据**：rva 0xea43a 起：mov [eax+8],0x3000; mov [eax+0xc],4; call [0x63a4c4](VirtualAlloc)；随后 call [0x63a4d0](CreateThread)；字符串“Shellcode thread started”
> 
> **来源**：`ref:98556fceb8` · `ref:078b774f91`

### 3. 假冒OneDrive落地

`T1036.005` · 置信度 **高** · 静态

将自身复制到 C:\ProgramData\OneDrive.exe 并以此名称运行，沙箱中对应进程为 OneDrive.exe（PID 4208）。

> **证据**：字符串“C:\ProgramData\OneDrive.exe”@VA 0x4f50c3；日志“install dir ready: %s”“self-copied (%d bytes) -> %s”；动态进程 OneDrive.exe (4208)
> 
> **来源**：`ref:078b774f91` · `ref:cd9c889a87`

### 4. 注册登录计划任务

`T1053.005` · 置信度 **高** · 静态

通过隐藏窗口的 cmd.exe 执行 schtasks /Create，注册计划任务“\Microsoft\Windows\Scheduled\Maintenance_314F38”，触发条件为登录（ONLOGON），成功后打印“Persistence status: OK (scheduled task wired for next logon)”。

> **证据**：main.installPersistence 内字符串“schtasks /Create: cErr=%v cOut=%s”@0x4f6ed2、“\Microsoft\Windows\Scheduled\Maintenance_314F38”@VA 0x4fa0f8、“ONLOGON”；disasm rva 0xec11d 附近构造 schtasks 参数
> 
> **来源**：`ref:161bb4e60a` · `ref:078b774f91`

### 5. 添加Defender排除

`T1562.001` · 置信度 **高** · 静态

优先调用 Windows Defender 的 MpCmdRun.exe 执行“-AddExclusion -ExclusionPath C:\ProgramData”，失败时回退 PowerShell 的“Add-MpPreference -ExclusionPath”，以规避对该目录的扫描。

> **证据**：字符串“defender: running: \"%s\" -AddExclusion -Path %q”“Add-MpPreference -ExclusionPath \"%s\"”“defender: MpCmdRun = %s”“C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe”；main.applyDefenderExclusion
> 
> **来源**：`ref:078b774f91`

### 6. 隐藏窗口调用命令

`T1059.003` · 置信度 **中** · 静态

通过 C:\Windows\System32\cmd.exe 以隐藏窗口方式执行 schtasks、PowerShell 等命令，避免弹出控制台窗口。

> **证据**：字符串“C:\Windows\System32\cmd.exe”“powershell -NoProfile”“hiddenCmd”；disasm rva 0xec0e0 附近调用 hiddenCmd（0x4ea7b0）
> 
> **来源**：`ref:161bb4e60a` · `ref:078b774f91`

### 7. 周期回连C2

`T1095` · 置信度 **高** · 动态

载荷进程 OneDrive.exe 每约 5 秒解析一次域名 nxbase[.]im 并尝试向 TCP 7777 发起连接，持续约 2 分钟直至沙箱收口，符合 beacon 轮询特征。

> **证据**：动态网络日志：DNS A 请求 nxbase[.]im；OneDrive.exe (4208) requested TCP 192.0.2[.]123:7777（每约 5 秒重复），首次 00:43:51
> 
> **来源**：`ref:cd9c889a87` · `ref:4d35384391`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `nxbase[.]im` | 7777 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%ProgramData%\OneDrive.exe`
- `%SystemDrive%\crypter_persist.log`

**计划任务**

- `\Microsoft\Windows\Scheduled\Maintenance_314F38`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `nxbase[.]im` | 是 | 静态 |
| `c2_port` | `7777` | 是 | 静态 |
| `install_path` | `%ProgramData%\OneDrive.exe` | 是 | 静态 |
| `persistence_task` | `\Microsoft\Windows\Scheduled\Maintenance_314F38` | 是 | 静态 |
| `encryption_algo` | `AES-128-CBC（三个阶段各自内嵌 16 字节 key/IV，运行时经 DeriveKey 派生）` | 是 | 静态 |
| `defender_exclusion_path` | `C:\ProgramData` | 否 | 静态 |
| `log_path` | `%SystemDrive%\crypter_persist.log` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能判定为勒索软件或文件加密器：AES 仅用于解密内置 shellcode，沙箱中未观察到任何文件加密、扩展名修改或勒索信。
- 不能声称 C2 会话已建立或已收到指令：仅观察到 DNS 解析与周期性 TCP 连接尝试，没有完整请求/响应。
- 不能声称已窃取凭据或横向移动：样本会调用 comsvcs.dll 相关导出仅出现在分析侧的进程转储流程中，样本自身未观察到该行为。
- 不能声称已写入注册表或创建服务：Defender 排除与持久化均通过命令行工具实现，未读取到注册表/服务写入的遥测证据。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 三段内嵌密文虽已定位到 rva 与内嵌 key/IV，但运行时密钥经 main.DeriveKey 二次派生，静态直接 AES-CBC 解密未得到可识别明文，未还原明文 shellcode/最终配置。
2. C2 仅有 DNS 解析与 TCP 连接尝试（每约 5 秒），无完整请求/响应，故 c2 与 config 中的 c2_hosts/c2_port 按 static + pending_dynamic_verify 记录，不能断言成功回连或已下发指令。
3. 沙箱时间线只记录到样本自身进程（PID 1060）与后续 OneDrive.exe（PID 4208），未捕获计划任务、Defender 排除、注册表或服务的运行时遥测，这些结论基于代码路径与字符串证据。
4. 最终载荷的通信协议与指令格式未知，无法确认其是 RAT、下载器还是内存注入器；behavior_class 的 backdoor 为基于周期性回连的功能推断。
5. 样本家族无公开命名可对齐，family 置信度为 low 且 uncertain=true。

## 证据索引

<details>
<summary>展开 15 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 2396672 |
| `ev-000002` | scan.imphash | imphash=5f77bccf23632019202250229664e21b |
| `ev-000003` | scan.entropy | .text 熵 6.186，无高熵壳特征 |
| `ev-000011` | 密码学常量识别 | AES 正/逆 S-box @off 0x2305e0 / 0x2306e0 |
| `ev-000013` | evidence.record | 脚本定位三段 AES-CBC 密文 rva 与内嵌 key/IV |
| `ref:e5414e42f0` | PE 结构解析 | PE32 I386 GUI，6 节，入口 rva 0x88650，镜像基址 0x400000，无异常 |
| `ref:17f833c032` | 导入表解析 | 仅 kernel32.dll 46 个导入，符合 Go 运行时特征 |
| `ref:078b774f91` | 字符串提取 | 命中 OneDrive.exe 路径、计划任务名、Defender 排除、阶段/Shellcode 日志等关键字符串 |
| `ref:bd5a893200` | disasm.function | runStage1 复制 0x1d560 字节密文并携带 key/IV 调用解密 |
| `ref:db14d4cf66` | disasm.function | DecryptAES 内校验长度并报 payload/decryption 错误 |
| `ref:98556fceb8` | disasm.function | VirtualAlloc(PAGE_EXECUTE_READWRITE)+CreateThread 执行载荷 |
| `ref:161bb4e60a` | disasm.function | installPersistence 构造 schtasks /Create 与状态日志 |
| `ref:4d35384391` | 动态分析平台 | 回滚→引爆→轮询 27 次，样本进程 PID 1060，收口后回滚 |
| `ref:c5de758b2e` | sandbox.timeline | 时间线仅样本自身进程，5 个内存转储，hollows 全扫 1 项 |
| `ref:cd9c889a87` | sandbox.fakenet | OneDrive.exe(4208) 周期解析 nxbase[.]im 并连接 TCP 7777（每约 5s） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
