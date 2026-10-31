---
title: "恶意样本分析：EtherHiding-style Python loader (sltnnt[.]ru)（PE · exe · 0b349a5b）"
published: 2026-10-30
draft: false
description: "恶意（置信度低）：EtherHiding-style Python loader (sltnnt[.]ru) · loader/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["EtherHiding", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **EtherHiding-style Python loader (sltnnt[.]ru)**（存疑） · 置信度 **低**
> 
> 别名：EtherHiding loader、Python RAT installer、NtProfileIndex loader
> 
> 反编译可见完整投递链:16 字节 XOR 混淆的全部字符串在入口函数内现场解密,解出 8 个 Polygon JSON-RPC 端点与 eth_call 合约死信箱(合约 0x9c0a507300fd902787bb193d80fca5ce6e1bff9a、选择子 0xce6d41de)、下载站 sltnnt[.]ru 及其 /cdn/ 路径、%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex 安装目录,以及下载 python-3.12.7 嵌入式解释器 + get-pip + requirements.txt 后以 python.exe main.py --host --env 拉起 app.pyd 的完整逻辑;入口处另有 CPU 型号、系统盘容量、开机时长等反沙箱门禁。沙箱内真实执行并观测到样本自重启为两个进程,内存镜像中可见解密后的 CPU 型号常量。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **EtherHiding-style Python loader (sltnnt[.]ru)** · 别名 EtherHiding loader、Python RAT installer、NtProfileIndex loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | medium |
| 首次出现 | 2026-10-28 19:49:54 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/0b349a5b1a1d1d40b3fbaf1a794c94f569770ce5a9a4bdf8cbeb198627a9da12/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">现场解密字符串表</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">比对QEMU处理器名</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">按容量与开机时长退场</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">合约死信箱取配置</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">自复制二次启动</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `0b349a5b1a1d1d40b3fbaf1a794c94f569770ce5a9a4bdf8cbeb198627a9da12` |
| MD5 | _未记录_ |
| 大小 | 1,139,712 字节（1.1 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **10** 条行为，每条都挂了证据；其中 **9** 条静态可得、**1** 条经动态分析取得。

### 1. 现场解密字符串表

`T1027` · 置信度 **高** · 静态

入口函数 0x401011 起用 16 字节密钥逐字符异或解密 40 余条内置字符串 (out[i]=key[i&0xf]^data[i]),全部 URL、路径、合约地址、命令行参数在文件中均以密文存在,常规静态字符串扫描看不到。

> **证据**：0x401076 xor r8b,[rax+rcx]; 数据块 rva 0x9eba8 / 0x7796c / 0x77c88,密钥紧随其后 16 字节
> 
> **来源**：`ev-000014` · `ev-000012`

### 2. 比对QEMU处理器名

`T1497.001` · 置信度 **高** · 静态

读取 HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0 的 ProcessorNameString,与硬编码的 "Intel Core Processor (Broadwell)"(QEMU 默认 CPU 型号)比对,命中后进入容量门禁分支。

> **证据**：RegOpenKeyExA@0x401191 / RegQueryValueExA@0x40233c; 字符串 rva 0x9eba8 / 0x9ebe6 / 0x9ec09
> 
> **来源**：`ev-000015` · `ev-000014` · `ev-000012`

### 3. 按容量与开机时长退场

`T1497.001` · 置信度 **高** · 静态

GetDiskFreeSpaceExW("C:\\") 取系统盘总容量、GetTickCount64 取开机时长:总容量小于约 105GB、或落在约 200-240GB 区间、或开机不足约 41 分钟、或低内存(<6.5GB)叠加特定 CPU 架构时,执行 ud2 非法指令使进程崩溃,不做任何业务动作。

> **证据**：GetDiskFreeSpaceExW@0x4011b6 / 0x40126b / 0x4023b4, GetTickCount64@0x4011d5, GlobalMemoryStatusEx@0x40120c, 崩溃点 0x4023e1 invalidInstructionException
> 
> **来源**：`ev-000015` · `ev-000012`

### 4. 合约死信箱取配置

`T1102` · 置信度 **高** · 静态

拼接 {"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x9c0a507300fd902787bb193d80fca5ce6e1bff9a","data":"0xce6d41de"},"latest"],"id":1},依次向 8 个 Polygon JSON-RPC 公共端点查询,把返回值当作配置/下一跳来源,可在域名被封时继续工作。

> **证据**：JSON 模板 rva 0x779f4 / 0x77a3a / 0x77a54,合约 0x779a0,选择子 0x779da,端点 0x77a78-0x77bcf
> 
> **来源**：`ev-000014` · `ev-000012`

### 5. 回源sltnnt下载载荷

`T1071.001` · 置信度 **高** · 静态

以 Chrome/120 的 User-Agent 与自定义头 x-cdn-origin-verify: trusted-upstream 访问 hxxps://sltnnt[.]ru 的 /cdn/5ef451455923、/cdn/e/42a522313d92、/cdn/e/36f2c0035ef9,分别取回 requirements.txt、main.py、app.pyd。

> **证据**：sltnnt[.]ru rva 0x9d9f8(引用点 0x4022d0); /cdn 路径引用点 0x40280b / 0x402b0d / 0x402ba4; UA rva 0x77e61
> 
> **来源**：`ev-000014` · `ev-000012`

### 6. 装Python运行时环境

`T1105` · 置信度 **高** · 静态

把 python-3.12.7-embed-amd64.zip 下载为 python.zip 并解压到安装目录,改写 python312._pth(在 #import site 与 import site 间切换),下载 get-pip.py 引导 pip,再执行 Scripts\pip.exe 安装 requirements.txt 依赖。

> **证据**：python[.]org 包 URL rva 0x77cd4, python.zip 0x77d2a, python312._pth 0x77d5e, get-pip.py 0x77db3, Scripts\pip.exe 0x77e01; 引用点 0x402553-0x4027c0
> 
> **来源**：`ev-000014` · `ev-000012`

### 7. 拉起Python后门进程

`T1059.006` · 置信度 **高** · 静态

用 CreateProcessW 启动安装目录内的 python.exe,命令行含 main.py、app.pyd、--host、--env,并区分 install / AppHost 两种运行模式,随后 WaitForSingleObject 与 GetExitCodeProcess 等待其退出。

> **证据**：CreateProcessW@0x4075ac(main 内)与 0x405e2d; 命令行拼接助手 0x407400-0x4075e6; 参数串 0x77fc7 / 0x78001 / 0x78018 / 0x7802e / 0x77f76 / 0x77f8d
> 
> **来源**：`ev-000015` · `ev-000014`

### 8. 取件后用AES解密

`T1140` · 置信度 **中** · 静态

FUN_00407a78 组装 "-k -s -X PUT -H ... -o <本地文件> <URL>" 形式的外部下载器命令行并 CreateProcessW 执行,再用 NtCreateFile 读回文件,以 base64 的 32 字节内置密钥与内置 AES S 盒/T 表解密后使用。

> **证据**：0x407a78 参数 "-k"(0x6b2d)/"-s"/"-X"/"PUT"/"-H"/"-o"; NtCreateFile 0x407879; AES 表 0x508180 与 0x4d0240; 密钥 rva 0xd01ac
> 
> **来源**：`ev-000013` · `ev-000015`

### 9. 原生API读写文件

`T1106` · 置信度 **中** · 静态

落地文件读写走 NtCreateFile / NtSetInformationFile / ReadFile / WriteFile 而非 Win32 高层封装,并用 GetFileAttributesW 探测目标路径,便于控制落地文件的存在性与时间戳。

> **证据**：NtCreateFile@0x407879 / 0x415051, NtSetInformationFile@0x404362 / 0x4078a6, WriteFile@0x415696, GetFileAttributesW@0x40733b
> 
> **来源**：`ev-000015`

### 10. 自复制二次启动

`T1497.001` · 置信度 **中** · 动态

动态沙箱内首进程(pid 4436)启动约 1 秒后出现同路径第二实例(pid 4876),两个实例都在未发起任何网络请求前退出,与入口处的自重启 + 反沙箱门禁分支一致。

> **证据**：动态时间线: pid 4436 born 23:56:11.9, pid 4876 born 23:56:12.9, 同一路径 ...\samples\<sha256>.exe; 内存镜像含解密后的 "Intel Core Processor" 常量
> 
> **来源**：`ref:a169437c6a`


## IOC（已去武器化）

### 网络

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://sltnnt[.]ru` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://sltnnt[.]ru/cdn/5ef451455923` | 443 | download | 静态 | ⏳ 未观测 |
| http | `hxxps://sltnnt[.]ru/cdn/e/42a522313d92` | 443 | download | 静态 | ⏳ 未观测 |
| http | `hxxps://sltnnt[.]ru/cdn/e/36f2c0035ef9` | 443 | download | 静态 | ⏳ 未观测 |
| http | `hxxps://polygon-rpc[.]com` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://rpc-mainnet[.]matic[.]quiknode[.]pro` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://polygon-public[.]nodies[.]app` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://1rpc[.]io/matic` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://polygon-bor-rpc[.]publicnode[.]com` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://api[.]zan[.]top/polygon-mainnet` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://polygon[.]rpc[.]subquery[.]network/public` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://endpoints[.]omniatech[.]io/v1/matic/mainnet/public` | 443 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\python.zip`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\python.exe`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\python312._pth`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\get-pip.py`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\Scripts\pip.exe`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\requirements.txt`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\main.py`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\app.pyd`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `sltnnt[.]ru` | 是 | 静态 |
| `c2_paths` | `/cdn/5ef451455923 (requirements.txt); /cdn/e/42a522313d92 (main.py); /cdn/e/36f2c0035ef9 (app.pyd)` | 是 | 静态 |
| `blockchain_rpc_endpoints` | `8 个 Polygon JSON-RPC 端点: polygon-rpc[.]com / rpc-mainnet.matic.quiknode.pro / polygon-public.nodies.app / 1rpc[.]io/matic / polygon-bor-rpc[.]publicnode[.]com / api[.]zan[.]top / polygon.rpc.subquery.network / endpoints[.]omniatech[.]io` | 是 | 静态 |
| `smart_contract` | `0x9c0a507300fd902787bb193d80fca5ce6e1bff9a (eth_call selector 0xce6d41de, 配置死信箱)` | 是 | 静态 |
| `install_path` | `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex` | 是 | 静态 |
| `payload_argv` | `python.exe main.py --host <c2> --env <env> (mode: install / AppHost)` | 是 | 静态 |
| `encryption_algo` | `AES(内置 32 字节密钥, base64 "dK9mT3nR7xQ2pL8wF4jH6yB1cN5gA0sZ12345678abc=") + 16 字节 XOR 字符串混淆 + ChaCha20-Poly1305(TLS 会话)` | 是 | 静态 |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0[.]0 Safari/537.36` | 否 | 静态 |
| `http_header` | `x-cdn-origin-verify: trusted-upstream` | 否 | 静态 |
| `campaign_id` | `3003170a-66f7-4989-943f-b16099549156` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能判定为勒索软件或数据擦除器:未见文件加密循环、卷影副本删除、扩展名改写或勒索信,沙箱内也未生成勒索说明文件。
- 不能判定为窃密木马(stealer):未观测到浏览器凭据库、加密货币钱包、聊天软件数据的读取;真正执行窃密的 app.pyd 未取回,能力未知。
- 不能声称已建立注册表 Run 键、服务或计划任务持久化:导入表只有 RegOpenKeyExA/RegQueryValueExA 读取(读 CPU 名),没有任何注册表写入 API,持久化方式未获证据。
- 不能把 python[.]org 与 bootstrap[.]pypa[.]io 当作恶意基础设施:它们是官方分发站点,仅被用来获取合法的 Python 运行时与 pip。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 载荷阶段未触发:沙箱为新建虚拟机,系统盘容量与开机时长落在样本的排除区间内,样本在下载前以 ud2 主动崩溃,因此 sltnnt[.]ru 与 Polygon RPC 的实际请求未被网络监控观测到,C2 与配置全部为静态解密所得(pending_dynamic_verify=true)。
2. app.pyd / main.py / requirements.txt 均未取回,下游 Python 载荷的具体功能(远控、窃密或其他)无法确认,行为分类只覆盖加载器本身。
3. 与 32 字节密钥同段存放的 AES 密文配置未能离线解开:解密后的配置内容取决于从 C2 或合约取回的数据,静态不可得。
4. 持久化机制未获证据:入口逻辑中未见注册表写入、服务或计划任务创建,持久化可能由 Python 阶段完成,无法验证。
5. 动态仅观测到两次进程创建与退出,未捕获子进程、文件写入或注入行为;内存扫描未发现挂钩或模块替换。

## 证据索引

<details>
<summary>展开 14 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 1139712 |
| `ev-000002` | scan.imphash | imphash=73f461c771aef77ec43d53a0c54f0c8d |
| `ev-000003` | scan.entropy | .text 熵 6.369,无高熵段 |
| `ev-000010` | 字符串提取 | 静态字符串扫描:1392 条 ASCII,无明文 URL/路径(均被混淆) |
| `ev-000011` | decompile.function | entry@0x401000 仅调用 0x401011 后 RtlExitUserProcess |
| `ev-000012` | decompile.function | main@0x401011: 字符串解密 + 反沙箱门禁 + 配置解析 + 下载安装链 |
| `ev-000013` | decompile.function | FUN_00407a78@0x407a78: 外部下载器命令行组装 + 读回 + AES 解密 |
| `ev-000014` | 脚本化取证 | 复现 XOR 字符串解密,输出 44 条明文配置项 |
| `ev-000015` | 脚本化取证 | 导入桩回溯得到 48 个 API 的实际调用点 |
| `ref:b0ed339b24` | PE 结构解析 | PE 结构:AMD64/7 段/无资源/无 Rich/48 导入 |
| `ref:726d7c905c` | 导入表解析 | 导入面:ntdll/kernel32/advapi32/crypt32/ws2_32 |
| `ref:4ccabd3fb2` | unpack.detect | 未加壳(packed=false) |
| `ref:a169437c6a` | 动态分析平台 | 动态引爆:2 个候选进程、时间线与内存镜像打包,无网络/文件行为 |
| `ref:5a0de6c0e2` | cfg.function | main 的 177 个基本块与调用目标 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
