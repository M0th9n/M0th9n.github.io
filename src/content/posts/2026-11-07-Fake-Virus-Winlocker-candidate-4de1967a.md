---
title: "恶意样本分析：Fake-Virus Winlocker (candidate)（PE · exe · 4de1967a）"
published: 2026-11-07
draft: false
description: "恶意（置信度低）：Fake-Virus Winlocker (candidate) · ransomware · 难度 hard · 动态沙箱 + 静态反编译"
tags: ["ransomware", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Fake-Virus Winlocker (candidate)**（存疑） · 置信度 **低**
> 
> 别名：Winlocker、Fake VIRUS locker、Ransom.Win32.Winlocker (candidate)
> 
> 64 位 GUI PE，导入表/资源表均为空，入口与大量函数被不透明谓词混淆；在隔离沙箱中真实运行后，进程私有内存里还原出成对的锁屏/勒索文案（'This is a VIRUS!!!! Do you want to run the file?' 与 'To remove the window, you must CRYPT FILE!'，标题 'Warning'），配合 rdtsc/cpuid 反分析、PEB 手工解析 API 与运行时字符串解密，属于典型的 Winlocker/勒索类恶意程序。但沙箱时间窗内未观测到文件加密、持久化或外联。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Fake-Virus Winlocker (candidate)** · 别名 Winlocker、Fake VIRUS locker、Ransom.Win32.Winlocker (candidate) · _存疑_ |
| 置信度 | **低** |
| 行为类 | ransomware |
| 难度 | hard |
| 首次出现 | 2026-11-06 14:57:55 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/4de1967a36849e08f2396f983363692c6fb288dc7382c20b7c0320741177dceb/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">剥离导入表</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">遍历PEB查找模块</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">运行时解密字符串</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">弹出伪装病毒确认框</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">显示锁屏勒索提示</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1486</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `4de1967a36849e08f2396f983363692c6fb288dc7382c20b7c0320741177dceb` |
| MD5 | _未记录_ |
| 大小 | 1,384,960 字节（1.3 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **8** 条行为，每条都挂了证据；其中 **5** 条静态可得、**3** 条经动态分析取得。

### 1. 剥离导入表

`T1027` · 置信度 **高** · 静态

PE 导入目录为空（IMPORT RVA=0、size=0），导出表与资源目录同样为空，程序没有任何静态导入符号，所有系统 API 必须在运行时自行解析。

> **证据**：pe.parse: data_directories[1] IMPORT rva=0 size=0; scan.triage: import_dll_count=0 / import_symbol_count=0
> 
> **来源**：`ref:f9a68b1201` · `ref:8807d06e90`

### 2. 遍历PEB查找模块

`T1027` · 置信度 **高** · 静态

通过 gs:[0x60] 取得 PEB，沿 InInitializationOrderLinks（+0x20）遍历已加载模块链表，读取 FullDllName（+0x48 长度 / +0x50 缓冲区）并逐字节复制模块路径，随后调用自写哈希与解析例程完成 API 绑定。

> **证据**：RVA 0x14538: mov rax, qword ptr gs:[0x60]；后续遍历 [r14+0x20] 链表、读 [r14+0x48]/[r14+0x50]，call 0x3900B4AE8（哈希）与 0x390024A60（解析）
> 
> **来源**：`ref:53b2c65f07` · `ref:44f8a0e4d7`

### 3. 运行时解密字符串

`T1027` · 置信度 **高** · 动态

文件内没有可读的功能字符串（静态仅 426 条 ASCII 且均为代码碎片），而进程私有内存中成片出现明文环境块与功能文案，说明字符串在运行时解密后写入堆内存。

> **证据**：scan.strings: ascii_count=426、flag_hits=0；内存取证: 0x20FD38ABE40 起出现成套明文提示串
> 
> **来源**：`ref:45202b7198` · `ref:91f4da466b`

### 4. 弹出伪装病毒确认框

`T1204` · 置信度 **中** · 动态

解密后的内存中存在文案 'This is a VIRUS!!!! Do you want to run the file?' 与标题 'Warning'，属于以“病毒警告”诱导用户确认/执行的社会工程弹窗。

> **证据**：内存 0x20FD38ABE40 = 'This is a VIRUS!!!! Do you want to run the file?'；0x20FD38B35A0 = 'Warning'
> 
> **来源**：`ref:45202b7198`

### 5. 显示锁屏勒索提示

`T1486` · 置信度 **中** · 动态

解密后的内存中存在 'To remove the window, you must CRYPT FILE!'，属于屏幕锁定/勒索提示文案；沙箱时间窗内未见文件被加密或勒索信落盘，整理逻辑未触发或未执行到加密阶段。

> **证据**：内存 0x20FD38ABE72 = 'To remove the window, you must CRYPT FILE!'
> 
> **来源**：`ref:45202b7198`

### 6. rdtsc时序反调试

`T1497.003` · 置信度 **高** · 静态

RVA 0x19EE 处以 rdtsc 读取时间戳，取差值后对 0x47 取模并加 10 作为延迟/随机化参数，属于基于时间差的反调试与环境探测。

> **证据**：RVA 0x19EE: rdtsc; shl rdx,0x20; or rax,rdx; div rcx (0x47); add eax,0xa; call 0x390002578
> 
> **来源**：`ref:a96bc655fb` · `ref:44f8a0e4d7`

### 7. cpuid探测运行环境

`T1497.001` · 置信度 **中** · 静态

代码中含 cpuid 序列，用于读取 CPU/虚拟化特征，与 rdtsc 检查配合判断是否处于虚拟机或调试环境。

> **证据**：unpack.antidebug 报告 cpuid(VM/调试探测) @ RVA 187967（0x2DE3F）
> 
> **来源**：`ref:44f8a0e4d7`

### 8. 常量哈希混淆符号

`T1027` · 置信度 **高** · 静态

RVA 0x30F0F 附近以 0x9E3779B9 为增量做滚动哈希（h = (h ^ (b<<8)) + 0x9E3779B9，再做移位/乘法混合），用于隐藏 API/字符串名称；该常量出现在哈希循环中，不是 TEA 加密轮。

> **证据**：RVA 0x30F0E add eax,0x9E3779B9；其后 shr/shl/imul 混合；scan.crypto 将同一常量误报为 TEA/XTEA delta
> 
> **来源**：`ref:4926bc2fcc` · `ref:fa93f2042e`


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
| `messagebox_text_run_prompt` | `This is a VIRUS!!!! Do you want to run the file?` | 是 | 动态 |
| `winlocker_message` | `To remove the window, you must CRYPT FILE!` | 是 | 动态 |
| `window_title` | `Warning` | 否 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能仅凭 0x9E3779B9 常量判定样本使用 TEA/XTEA 文件加密——反汇编显示该常量位于滚动哈希循环中，不存在 TEA 加密轮。
- 未观测到文件被加密、勒索信落盘或桌面/输入被锁定，不能断言样本已完成加密或存在可用解密器。
- 网络监视未记录到样本自身的外联，不能给出 C2 域名或 IP。
- 未观测到子进程、进程注入、服务/计划任务持久化，不能将其判为注入器、下载器或 loader。
- 家族名仅为候选：两条提示文案不足以与已知家族一一对应，不应对外断言具体家族。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 样本运行后等待用户交互，沙箱观测窗口内未触发后续逻辑，加密/持久化/外联路径均未观测到。
2. 导入表为空且字符串全部运行时解密，静态无法还原完整配置；未取得 C2、互斥体、安装路径、加密算法等字段。
3. 内存中恢复的文案证明其已被解密并驻留，但未直接截获窗口显示事件或用户交互结果。
4. 家族指纹不足：无 YARA 命中、无配置提取、无可对照的多引擎标签。
5. .text 段混淆严重，未完成全量控制流还原，函数级语义仅覆盖入口、PEB 解析、哈希与反调试片段。

## 证据索引

<details>
<summary>展开 13 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=4de1967a36849e08f2396f983363692c6fb288dc7382c20b7c0320741177dceb, md5=cb201373d521bfed5555838bf099c366, size=1384960 |
| `ev-000002` | pe.parse / scan.rich | PE64 GUI，4 个节，IMPORT/EXPORT/RESOURCE 目录均为 0，Rich header 5 条 MSVC 工具链记录 |
| `ev-000008` | 字符串提取 | 静态仅 426 条 ASCII 字符串、无 UTF-16 串、无功能提示串 |
| `ev-000009` | 密码学常量识别 | 0x9E3779B9 常量命中（后经反汇编确认为滚动哈希的一部分，非 TEA） |
| `ev-000012` | decompile.entry | 入口函数为大量常量运算/不透明谓词与 switch 分发，典型控制流混淆 |
| `ref:53b2c65f07` | disasm.function | gs:[0x60] 取 PEB，遍历模块链表并读取 FullDllName，调用哈希/解析例程 |
| `ref:a96bc655fb` | disasm.function | RVA 0x19EE rdtsc 时间差计算，对 0x47 取模后加 0x0A |
| `ref:44f8a0e4d7` | unpack.antidebug | 静态识别 rdtsc 时间差、PEB 访问 (gs:[0x60])、cpuid(VM/调试探测) |
| `ref:3a5ce3ff22` | 动态分析平台 | 沙箱引爆并回滚；pid 8076 常驻，两次定点内存转储与全扫均完成；无新增子进程 |
| `ref:7a4c780d09` | network-log | 网络监视日志中无样本进程的外联，域名均为系统更新/证书类流量 |
| `ref:45202b7198` | memory-forensics | 进程私有内存 0x20FD38ABE40/0x20FD38ABE72/0x20FD38B35A0 处还原出病毒提示、锁屏勒索文案与 Warning 标题 |
| `ref:4926bc2fcc` | disasm.function | 0x9E3779B9 参与的滚动哈希/混合循环，确认非 TEA 加密 |
| `c2_evidence:4de1967a` | 连接证据提取 | 动态网络监控记录到 2 次到 maps[.]windows[.]com:443 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
