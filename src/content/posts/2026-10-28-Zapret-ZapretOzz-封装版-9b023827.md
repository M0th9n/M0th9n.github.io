---
title: "恶意样本分析：Zapret (ZapretOzz 封装版)（PE · exe · 9b023827）"
published: 2026-10-28
draft: false
description: "灰色/PUA（置信度高）：Zapret (ZapretOzz 封装版) · pua_bundler · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["恶意样本分析", "Zapret (ZapretOzz 封装版)", "pua_bundler", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!CAUTION]
> **判定：灰色/PUA** · 家族 **Zapret (ZapretOzz 封装版)** · 置信度 **高**
> 
> 别名：ZapretOzz、winws.exe、Bat To Exe Converter 自解压封装
> 
> 动态内存取证还原出完整批处理脚本：程序自解压到 %TEMP% 后由命令解释器执行，按 files/config.txt 拼接参数并启动 files/winws.exe（Zapret 网络审查绕过工具）。全程未见 C2 外联、持久化、凭据窃取或代码注入，判定为被打包分发的 HackTool / 潜在 unwanted 程序，而非恶意木马。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Zapret (ZapretOzz 封装版)** · 别名 ZapretOzz、winws.exe、Bat To Exe Converter 自解压封装 |
| 置信度 | **高** |
| 行为类 | pua_bundler |
| 难度 | medium |
| 首次出现 | 2026-10-28 11:26:19 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/9b023827a3ac225c5672cce1871a2ac1ddd58cbd37dc9c3933d13f8f0a61356a/) |

## 攻击链

<svg viewBox="0 0 720 168" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="92" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="38" fill="currentColor" font-weight="600" font-size="14">配置解密</text>
<text x="250" y="38" fill="currentColor" fill-opacity="0.65" font-size="12.5">AES 解密内置配置</text>
<text x="250" y="56" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="92" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="92" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="96" fill="currentColor" font-weight="600" font-size="14">远控 / 窃密</text>
<text x="250" y="96" fill="currentColor" fill-opacity="0.65" font-size="12.5">shell / 键盘 / 截屏 / 摄像头</text>
<text x="250" y="114" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1059</text>
<rect x="586" y="81" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="96" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `9b023827a3ac225c5672cce1871a2ac1ddd58cbd37dc9c3933d13f8f0a61356a` |
| MD5 | _未记录_ |
| 大小 | 1,204,736 字节（1.1 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **5** 条行为，每条都挂了证据；其中 **1** 条静态可得、**4** 条经动态分析取得。

### 1. 自解压释放临时文件

`T1027` · 置信度 **高** · 动态

运行时枚举自身资源，经 RC4 解密后写入 %TEMP% 下的随机命名 .tmp 目录，落地批处理与 files 子目录。

> **证据**：0x140003592 FindResourceW(type=10)→LoadResource→RC4→CreateFileW；内存可见 %TEMP%5FC.tmp5FD.tmp5FE.bat
> 
> **来源**：`ref:26908989c5` · `ref:c422feb7c4` · `ref:64a0d616a7`

### 2. RC4 解密内嵌脚本

`T1140` · 置信度 **高** · 静态

内置 RC4 实现（S 盒初始化 + KSA + PRGA 异或）解密内嵌 RCDATA 资源，解密结果即批处理文本。

> **证据**：0x140001284 S 盒 0..255 初始化与 PRGA 逐字节异或；调用点 0x1400037d0 / 0x140003876
> 
> **来源**：`ref:25fcab0408` · `ref:26908989c5`

### 3. 命令行执行批处理

`T1059.003` · 置信度 **高** · 动态

通过命令解释器执行释放出的 .bat，并取得短路径以便 ShellExecute 调用。

> **证据**：导入 GetShortPathNameW / ShellExecuteExW；0x140003cc9 GetShortPathNameW 后转入执行链
> 
> **来源**：`ref:bd0b51eb90` · `ref:c422feb7c4`

### 4. 读取配置拼接参数

`T1005` · 置信度 **高** · 动态

批处理逐行读取 files\config.txt，替换 {ignore}/{quicgoogle}/{stun} 三个占位符后拼成单一参数字符串。

> **证据**：内存脚本：for /f "usebackq delims=" %%A in ("%~dp0files\config.txt") do ( set "line=!line:{stun}=%stun%!" ... set "args=!args! !line!" )
> 
> **来源**：`ref:c75ec58036`

### 5. 启动 winws 绕过工具

`T1106` · 置信度 **高** · 动态

以窗口标题 ZapretOzz 启动 files\winws.exe 并传入上一步拼接的参数，用于网络流量的分片/伪造处理。

> **证据**：内存脚本末尾：start "ZapretOzz" "files\winws.exe" !args!
> 
> **来源**：`ref:c75ec58036` · `ref:64a0d616a7`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `%TEMP%\<随机名>.tmp\<随机名>.tmp\<随机名>.bat`
- `%TEMP%\<随机名>.tmpiles\winws.exe`
- `%TEMP%\<随机名>.tmpiles\config.txt`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `bundled_payload` | `files\winws.exe (Zapret DPI 绕过工具) 与 files\config.txt / ignore.txt / stun.bin / quic_initial_www_google_com.bin` | 是 | 动态 |
| `launch_command` | `start "ZapretOzz" "files\winws.exe" !args!` | 是 | 动态 |
| `argument_source` | `%~dp0files\config.txt 逐行读取，替换 {ignore}/{quicgoogle}/{stun} 后拼接为命令行参数` | 是 | 动态 |
| `wrapper` | `Bat To Exe Converter (b2eincfilepath)` | 否 | 动态 |
| `encryption_algo` | `RC4（内嵌资源解密）+ zlib inflate 1.2.11` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得称为窃密木马/键盘记录器：未发现凭据收集、屏幕捕获或浏览器数据读取相关代码与行为。
- 不得称为下载器或 C2 植入体：网络监控中样本进程自身无任何外联，未观察到回连或远端下载。
- 不得称为注入/进程镂空：内存扫描显示 0 处植入 PE、0 处 API 挂钩、0 处节区头篡改。
- 不得称为勒索软件：无文件加密行为，勒索信计数为 0。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 是 |

**局限与待验证**

1. 子进程（推测为命令解释器与 winws.exe）在观测窗口内出现后很快退出，未采集到其完整命令行与驱动/服务加载证据，因此绕过功能的实际效果未验证。
2. 样本自身无网络行为，网络监控仅记录到系统组件的更新与证书流量，不能据此判断工具运行时是否改写流量。
3. winws.exe 本体未从沙箱取回，无法核对其哈希与驱动释放行为。
4. 封装器判定依据为内存中的 b2eincfilepath 变量与自解压目录结构，属强特征但未做官方签名比对。

## 证据索引

<details>
<summary>展开 11 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:8b9270e6f1` | 样本分诊 | sha256/imphash/节区与熵，无壳迹象，0 结构异常 |
| `ref:0ecc612b72` | PE 结构解析 | PE64 GUI，资源目录 1.08MB，入口 RVA 0x1000 |
| `ref:c422feb7c4` | 导入表解析 | GetTempFileNameW/CreateDirectoryW/FindResourceW/LoadResource/GetShortPathNameW/ShellExecuteExW 等 128 个导入 |
| `ref:25fcab0408` | decompile.function | 0x140001284 = RC4（S 盒初始化+KSA+PRGA） |
| `ref:26908989c5` | decompile.function | 0x140003592 资源枚举→RC4→写文件 |
| `ref:bd0b51eb90` | decompile.function | 0x140003cc9 GetShortPathNameW 生成短路径供执行 |
| `ref:c75ec58036` | sandbox memory strings | 进程内存还原的批处理正文与 start 命令 |
| `ref:64a0d616a7` | sandbox memory strings | b2eincfilepath、%TEMP% 解包路径等字符串 |
| `ref:6ec25fdd9c` | 动态分析平台 | 真实引爆：pid 7056 存活，时间线/转储/全扫完成并回滚 |
| `ref:2767631de6` | sandbox memory scan | 进程内存扫描：植入 0、挂钩 0、可疑 0 |
| `ref:033b3c789a` | sandbox network log | 样本进程无外联，仅系统组件更新/证书流量 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
