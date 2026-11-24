---
title: "恶意样本分析：EtherHiding（other · msi · ffd3f75d）"
published: 2026-11-22
draft: false
description: "恶意（置信度中）：EtherHiding · loader/backdoor/implant · 难度 medium · 纯静态分析"
tags: ["EtherHiding", "loader", "backdoor", "implant", "MSI"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **EtherHiding**（存疑） · 置信度 **中**
> 
> 别名：Node.js EtherHiding loader、Node.js blockchain dead-drop implant
> 
> MSI 安装包内含两条自定义动作，分别以 cmd.exe 运行批处理、以 wscript.exe 隐藏运行 VBScript；批处理从 nodejs[.]org 下载 Node 运行时并把 node.exe 重命名为 SetupHost[.]exe，VBScript 隐藏启动该宿主执行伪装成 .xml 的 JavaScript。脚本被自定义字节码虚拟机混淆，解码后可见 Ethereum 智能合约死投解析 C2 地址、循环访问面板 /api/ 路径拉取任务并以 new Function 动态执行返回代码，属于远程控制植入体。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **EtherHiding** · 别名 Node.js EtherHiding loader、Node.js blockchain dead-drop implant · _存疑_ |
| 置信度 | **中** |
| 行为类 | loader · backdoor · implant |
| 难度 | medium |
| 首次出现 | 2026-11-22 10:58:43 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ffd3f75dc955f02cd4a2a75952669fe6627c79f1b1f2533f2fc3bbb345daf2da/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">自定义动作触发载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1218.007</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">下载Node作宿主</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">伪装xml执行JS</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.008</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">区块链解析C2地址</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">轮询面板拉取任务</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ffd3f75dc955f02cd4a2a75952669fe6627c79f1b1f2533f2fc3bbb345daf2da` |
| MD5 | _未记录_ |
| 大小 | 39,424 字节（38.5 KB） |
| 类型 | other · `msi` |

## 行为分析

共 **9** 条行为，每条都挂了证据，且全部静态可得。

### 1. 自定义动作触发载荷

`T1218.007` · 置信度 **高** · 静态

MSI 的 CustomAction 以 [SystemFolder]cmd.exe /c "[目录]ConfigureProduct.cmd" 与 wscript.exe //B //Nologo "[目录]4glrodx5s.vbs" … 两条命令在安装过程中执行释放出的脚本。

> **证据**：MSI CustomAction 字符串于 30012–30600 区间；wscript.exe 参数含 4glrodx5s.vbs、EmbeddedHost\SetupHost[.]exe、NCPaZsSrJXdD.xml
> 
> **来源**：`ev-000009` · `ev-000010`

### 2. 下载Node作宿主

`T1105` · 置信度 **高** · 静态

批处理用 PowerShell 解码内置 base64 得到 hxxps://nodejs[.]org/dist/v18.19.0/node-v18.19.0-win-x64.zip，以 System32\curl.exe 下载到 %TEMP%，再用 tar.exe 解压并把 node.exe 重命名为 EmbeddedHost\SetupHost[.]exe。

> **证据**：ConfigureProduct.cmd 中 PACKAGE_SRC_B64=aHR0cHM6Ly9ub2RlanMub3JnL2Rpc3QvdjE4LjE5LjAvbm9kZS12MTguMTkuMC13aW4teDY0LnppcA== 及 curl/tar/ren 调用
> 
> **来源**：`ev-000010`

### 3. 伪装xml执行JS

`T1036.008` · 置信度 **高** · 静态

MSI File 表把随机 CAB 成员 9zcwfbdl.xml 安装为 NCPaZsSrJXdD.xml，VBScript 以 WScript.Shell.Run 隐藏调用 SetupHost[.]exe（即 node.exe）并把该 .xml 当脚本执行，实现文件类型伪装。

> **证据**：File 表映射 9zcwfbdl.xml|NCPaZsSrJXdD.xml；iNsMUqg28zax 内容为 CreateObject("WScript.Shell").Run ... CLng(0), False
> 
> **来源**：`ev-000009` · `ev-000010`

### 4. 区块链解析C2地址

`T1102.001` · 置信度 **高** · 静态

植入体向 7 个 Ethereum JSON-RPC 端点并发 eth_call（to=0xdf64c4d1…、data=0x7d434425+0x977928…），按 ABI 解析返回字符串，投票选出 C2 URL，失败则使用内置面板地址。

> **证据**：反混淆字符串 'hxxps://rpc[.]flashbots[.]net/fast' 等、'eth_call'、'0x7d434425'、合约 0xdf64c4d1fa017fc565e6564b117bd6ba8437953f
> 
> **来源**：`ev-000010`

### 5. 轮询面板拉取任务

`T1071.001` · 置信度 **高** · 静态

循环向 {C2}/api/{随机4hex}/{UUID}/{随机4hex}.{png|jpg|gif|css|ico|webp}?{id|token|key|b|q|s|v}={build} 发起 GET，单次超时约 120 秒；成功轮次间隔约 0.5 秒，连接错误后随机切换地址并等待约 5 秒，每约 300 秒重新解析一次区块链地址。

> **证据**：_aq 中 fetch(_cm, {signal}); URL 由 '/api/'、'.png/.jpg/.gif/.css/.ico/.webp' 拼接；日志 'Polling: '、'Poll failed: '
> 
> **来源**：`ev-000010`

### 6. 动态执行远程代码

`T1059.007` · 置信度 **高** · 静态

把面板响应体（长度 > 10 字节）拼入 new Function("require","process","Buffer","console","__dirname","__filename","log","return (async=>{"+task+"})") 并 await 执行，等于任意 Node.js 远程代码执行。

> **证据**：JS 中 new Function 字符串拼接 + 'Task executed' / 'Task error: ' 日志
> 
> **来源**：`ev-000010`

### 7. 生成随机安装位置

`T1074.001` · 置信度 **高** · 静态

以 COMPUTERNAME 与 USERNAME 的 md5 派生目录名，在 %LOCALAPPDATA% 的 Microsoft/Windows/Programs/Packages/Google 之一及 Services/Components/Assemblies/Extensions/Modules 之下创建随机多级目录，写入 base64(JSON) 配置（含 randomUUID 生成的客户端标识）与 sha1 命名的日志文件。

> **证据**：_e 中 LOCALAPPDATA/USERPROFILE/AppData/Local 与两组词表；mkdirSync(recursive)、writeFileSync(base64)、appendFileSync 日志
> 
> **来源**：`ev-000010`

### 8. 规避EDR环境

`T1518.001` · 置信度 **中** · 静态

MSI 的 RegLocator/属性中出现 SENTINELONE_DIR 与条件字符串 NOT SENTINELONE_DIR，用于在检测到 SentinelOne 安装目录时跳过相应动作。

> **证据**：MSI 字符串 'SENTINELONE_DIR … NOT SENTINELONE_DIR'（约 28989–29650 区间）
> 
> **来源**：`ev-000001` · `ev-000009`

### 9. 隐藏窗口与清理痕迹

`T1564.003` · 置信度 **高** · 静态

以 start "" /MIN 后台启动自身、VBScript 用窗口模式 0 隐藏运行、wscript //B 无提示执行；下载包用后 del /q 删除，并配置 RemoveFile 清理临时文件。

> **证据**：ConfigureProduct.cmd 的 start /MIN、wscript //B //Nologo、del /q；MSI RemoveFile/RemoveTempFiles 条目
> 
> **来源**：`ev-000009` · `ev-000010`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://fortic[.]eastus[.]cloudapp[.]azure[.]com` | 443 | c2 | 静态 | ⏳ 未观测 |
| other | `Ethereum eth_call selector 0x7d434425 -> 合约 0xdf64c4d1fa017fc565e6564b117bd6ba8437953f（参数 0x977928898a80c7228d8c2e80dfa42ff75f746f56），返回 C2 URL` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://rpc[.]flashbots[.]net/fast 等 7 个 Ethereum JSON-RPC 端点（tenderly/mevblocker/blastapi/publicnode/drpc/merkle）` | 443 | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%LOCALAPPDATA%\<Microsoft|Windows|Programs|Packages|Google>\<Services|Components|Assemblies|Extensions|Modules>\<4hex>\（随机安装目录，md5(COMPUTERNAME+USERNAME) 派生）`
- `%LOCALAPPDATA%\...\<4hex>\<md5(安装目录)前 8 字符>（base64(JSON) 客户端标识/配置）`
- `%LOCALAPPDATA%\...\<4hex>\<sha1(安装目录+"l")前 8 字符>（运行日志）`
- `%TEMP%\MbZidXdN_GKnCJe6CuQ_PostApply.log`
- `%TEMP%\MbZidXdN_GKnCJe6CuQ_<随机数>.zip（Node 运行时下载包，用后删除）`
- `%<系统分区>\Program Files\SentinelOne（仅作为 EDR 存在性检测目标）`

**注册表**

- `HKCU\Software\MbZidXdN\GKnCJe6CuQ（根键由 MSI Registry 表推断，未动态确认）`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxps://fortic[.]eastus[.]cloudapp[.]azure[.]com` | 是 | 静态 |
| `c2_contract` | `0xdf64c4d1fa017fc565e6564b117bd6ba8437953f` | 是 | 静态 |
| `c2_selector` | `0x7d434425` | 是 | 静态 |
| `c2_contract_arg` | `0x977928898a80c7228d8c2e80dfa42ff75f746f56` | 是 | 静态 |
| `rpc_fallbacks` | `hxxps://mainnet[.]gateway[.]tenderly[.]co; hxxps://rpc[.]flashbots[.]net/fast; hxxps://rpc[.]mevblocker[.]io; hxxps://eth-mainnet[.]public[.]blastapi[.]io; hxxps://ethereum-rpc[.]publicnode[.]com; hxxps://eth[.]drpc[.]org; hxxps://eth[.]merkle[.]io` | 否 | 静态 |
| `build_id` | `0ea3559d-1abc-4bd2-b595-58b778d21cd9` | 是 | 静态 |
| `task_uri_pattern` | `{c2}/api/{rand4hex}/{uuid}/{rand4hex}.{png\|jpg\|gif\|css\|ico\|webp}?{id\|token\|key\|b\|q\|s\|v}={build}` | 是 | 静态 |
| `install_path_pattern` | `%LOCALAPPDATA%\<wordA>\<wordB>\<4hex>（wordA/wordB 由 md5(COMPUTERNAME+USERNAME) 前 4 个十六进制字符选词）` | 是 | 静态 |
| `encryption_algo` | `none（仅使用 md5/sha1 生成文件名，未加密通信或文件）` | 否 | 静态 |
| `runtime_host` | `node.exe（下载自 nodejs[.]org 后被重命名为 SetupHost[.]exe）` | 是 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得称为勒索软件或加密器：反混淆代码只用 md5/sha1 派生文件名与日志名，没有任何文件加密或赎金逻辑。
- 不得称为传统 PE 进程注入：全部逻辑运行在 Node.js 用户态脚本中，未发现 VirtualAllocEx/CreateRemoteThread 等注入行为。
- 不得把 nodejs[.]org 下载地址当作 C2：该 URL 仅用于获取官方 Node 运行时作为合法宿主，真正的控制端是 fortic[.]eastus[.]cloudapp[.]azure[.]com 与以太坊合约解析结果。
- 不得声称已观测到凭据/浏览器数据窃取：本次静态分析未见相关文件访问逻辑，不能据此归为窃密类。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次为纯静态分析，未启用可用的动态通道，安装期行为均由 MSI 表与内嵌脚本推断，未取得运行时网络/进程观测。
2. C2 地址与配置由静态反混淆获得，recoverability 标为 static 且 pending_dynamic_verify=true；未与面板发生任何真实会话。
3. MSI 表流名称被字符级改写，未逐表解析 Registry 表 Root 列，HKCU\Software\MbZidXdN\GKnCJe6CuQ 的根键为推断值。
4. 未真实创建或观测计划任务、服务；植入体自身不包含这些持久化手段，持久化主要依赖 MSI 安装与随机目录内的文件。
5. 反混淆依赖复现的字节码 VM 解释器（9 种操作码），已对 145 条字符串逐一解码；若存在运行时二次解密则不在此覆盖范围。
6. 样本格式非 PE/ELF，常规结构类工具不适用，结论建立在复合文档结构、CAB 内容与脚本语义之上。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000009` | 字符串提取 | MSI 字符串抽取：ProductName/Manufacturer/CustomAction/File 表名、SENTINELONE_DIR 条件等（ascii 58 条、utf16le 13 条，含地址 28989–30600 区间的表字符串） |
| `ev-000010` | evidence.record | 脚本解析符合文档、提取 CAB 与 3 个载荷、复现字节码 VM 解码 145 条字符串并还原 Node.js 植入体逻辑与 C2 配置 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
