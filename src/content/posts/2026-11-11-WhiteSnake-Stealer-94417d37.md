---
title: "恶意样本分析：WhiteSnake Stealer（PE · exe · 94417d37）"
published: 2026-11-11
draft: false
description: "恶意（置信度高）：WhiteSnake Stealer · stealer · 难度 medium · 静态反编译（动态执行未取得运行时行为）"
tags: ["WhiteSnake", "stealer", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **WhiteSnake Stealer** · 置信度 **高**
> 
> 别名：WhiteSnake、WhiteSnake Grabber、WSR Stealer
> 
> 静态反编译与内置字符串解密完整还原出一条 .NET 信息窃取链：样本解密内置配置后取得 Telegram 机器人令牌与聊天 ID，遍历浏览器、通讯软件、钱包与 Steam/FileZilla 等敏感数据，截取屏幕并汇总主机信息，使用 GZip+RC4+RSA 封装为 WSR 报告，再通过 Telegram Bot API 上传。另有 WMI 虚拟机检测与单实例互斥体。所有关键字符串、API 调用与算法均由样本自身字节还原，动态沙箱因 PE 结构异常未能建立执行会话。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **WhiteSnake Stealer** · 别名 WhiteSnake、WhiteSnake Grabber、WSR Stealer |
| 置信度 | **高** |
| 行为类 | stealer |
| 难度 | medium |
| 首次出现 | 2026-11-10 12:12:24 |
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/94417d37bc60731b37a8c8c713bb2c132f90eef3551bc9c331d42c8203bce35f/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解密内置配置</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">建立单实例互斥体</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">检测虚拟机并退出</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">收集浏览器数据</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">抓取钱包与聊天数据</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1657</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `94417d37bc60731b37a8c8c713bb2c132f90eef3551bc9c331d42c8203bce35f` |
| MD5 | _未记录_ |
| 大小 | 57,344 字节（56.0 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **10** 条行为，每条都挂了证据，且全部静态可得。

### 1. 解密内置配置

`T1027` · 置信度 **高** · 静态

在类型静态构造器中依次调用字符串 XOR 解密例程，还原 Telegram 令牌、聊天 ID、RSA 公钥、标签与抓取指令 XML，并写入静态字段。

> **证据**：0x224c 为 out[i]=(char)(data[i]^key[i%key.Length]) 循环；0x322c 连续对 Field#22-#27 执行 stsfld
> 
> **来源**：`ev-000008`

### 2. 建立单实例互斥体

`T1480` · 置信度 **高** · 静态

以名称 bckvtsynto 创建带初始所有权的 Mutex，未获得所有权时调用 Environment.Exit(5) 退出，防止重复运行。

> **证据**：0x2218 new Mutex(true,name,out createdNew) + Exit(5)；0x37b8 Main 首先调用该例程
> 
> **来源**：`ev-000008` · `ev-000007`

### 3. 检测虚拟机并退出

`T1497.001` · 置信度 **高** · 静态

通过 WMI 查询 SELECT * FROM Win32_ComputerSystem，将 Manufacturer/Model 转小写后匹配 virtual、vmware、vbox、kvm、qemu 等 12 个关键字，命中则退出进程。

> **证据**：0x3598 构造 12 元素关键字数组并调用 ManagementObjectSearcher；0x37b8 命中后 Environment.Exit(5)
> 
> **来源**：`ev-000008`

### 4. 收集浏览器数据

`T1555.003` · 置信度 **高** · 静态

按内置指令遍历 Chrome、Edge、Brave、Chromium、Firefox、Thunderbird 等配置目录，读取 Login Data、Cookies、logins.json、key4.db、Web Data、Local State 等文件，并用 DPAPI 解出浏览器主密钥。

> **证据**：指令 XML 中 command name=1/2 指向各浏览器；0x2374 ProcessCommand 读取文件并正则匹配 encrypted_key；MR58 ProtectedData.Unprotect
> 
> **来源**：`ev-000008`

### 5. 抓取钱包与聊天数据

`T1657` · 置信度 **高** · 静态

收集 Discord/Telegram 本地数据、FileZilla 站点配置、Steam 凭据、Pidgin 账户及 Atomic、Guarda、Coinomi、Bitcoin、Electrum、Exodus 钱包文件，打包到 Grabber/Wallets 等相对路径。

> **证据**：指令 XML 中 19 条 command 含 Discord leveldb、tdata、sitemanager.xml、ssfn*、*.wallet、exodus.wallet/*.seco
> 
> **来源**：`ev-000008` · `ev-000007`

### 6. 截取当前屏幕

`T1113` · 置信度 **高** · 静态

调用屏幕边界与 CopyFromScreen 抓取全屏，并以 JPEG 编码后 Base64 写入报告 Screenshot 字段。

> **证据**：0x34a8 Screen.GetBounds + Graphics.CopyFromScreen + ImageFormat.Jpeg；0x2f48 调用 MakeScreenshot 后 ToBase64String
> 
> **来源**：`ev-000008`

### 7. 收集主机指纹

`T1082` · 置信度 **高** · 静态

读取用户名、计算机名、操作系统版本，并登记执行时间戳与标签，作为报告 Information 字段。

> **证据**：0x2f48 生成 Username/Compname/OS/Execution timestamp；MR132 Environment.UserName、MR133 MachineName
> 
> **来源**：`ev-000008`

### 8. 查询公网 IP

`T1016` · 置信度 **高** · 静态

通过 WebClient 下载 hxxp://ip-api[.]com/line?fields=query 获取出口 IP，失败时填入固定回退字符串。

> **证据**：0x3428 WebClient.DownloadString + Trim 换行，异常分支返回预置文本
> 
> **来源**：`ev-000008`

### 9. 压缩加密窃取数据

`T1560.001` · 置信度 **高** · 静态

将报告对象序列化为 XML，GZip 压缩后用 32 字节随机 RC4 密钥加密，再用内置 RSA-2048 公钥以 OAEP 加密该密钥，按 WSR$ + 密文 + 加密密钥拼接为最终容器。

> **证据**：0x2f48 XmlSerializer/Compress/RNG 32 字节/RC4(0x2c28)/RSACryptoServiceProvider.Encrypt(true)/ASCII WSR$
> 
> **来源**：`ev-000008`

### 10. 经 Telegram 外传

`T1567` · 置信度 **高** · 静态

设置 TLS 1.2 后以 multipart/form-data POST 到 api[.]telegram[.]org 的 sendDocument 接口，文件名形如 用户@主机_report.wsr，并检查响应是否包含 {"ok":true。

> **证据**：0x2d5c 拼装 hxxps://api[.]telegram[.]org/bot + token + /sendDocument?chat_id= + id，WebHeaderCollection 添加 POST/Content-Type，WebClient.UploadData
> 
> **来源**：`ev-000008` · `ev-000007`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| telegram | `hxxps://api[.]telegram[.]org/bot5690489105:AAEQZjYHEOdNHOLcf-ksLf347CR9V3wq4ss/sendDocument?chat_id=6195973924` | 443 | exfil | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `bckvtsynto`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `api[.]telegram[.]org` | 是 | 静态 |
| `telegram_bot_token` | `5690489105:AAEQZjYHEOdNHOLcf-ksLf347CR9V3wq4ss` | 是 | 静态 |
| `telegram_chat_id` | `6195973924` | 是 | 静态 |
| `mutex` | `bckvtsynto` | 是 | 静态 |
| `campaign_id` | `invoice` | 否 | 静态 |
| `encryption_algo` | `GZip 压缩 + RC4(32 字节随机密钥) + RSA-2048/OAEP 封装密钥；输出以 WSR$ 开头` | 是 | 静态 |
| `rsa_public_key` | `<RSAKeyValue><Modulus>tuZn8b6ZXNFzbfB7CnOwtcASlIFNuTQSpgx7crefNOdUsDhLHViQPJroWGlSvGbbT5yskoG0S8p1elKnYJglYKpBl1tJWL9K0nQmACLDXGnyItTogvgYIUQEgubKQ42AFYvyThqd76xtiqej/Qo+F8wqsZkU/9hkkny17sM4LjJ6ylDcw6zNRl49UXwcq2FL7UIYNgtyEj4omivkFFj/3azDn5+Dw4W4nkrUFxQw6XaROVRBl0ka50xspE1iCneFIJGqWeGeHq9UP2B9qkB1uherMX5hkuewJBXhPfZ54aItxQEccBtQ3bnrwdE7vHeSSDLBulG/JnYmGM5UoAeijw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>` | 是 | 静态 |
| `report_name_template` | `{username}@{computername}_report.wsr` | 否 | 静态 |
| `ip_lookup_url` | `hxxp://ip-api[.]com/line?fields=query` | 否 | 静态 |
| `anti_vm_keywords` | `virtual;vmbox;vmware;thinapp;VMXh;innotek gmbh;tpvcgateway;tpautoconnsvc;vbox;kvm;red hat;qemu` | 否 | 静态 |
| `grab_targets` | `Chrome/Edge/Brave/Chromium/Firefox/Thunderbird/Discord/FileZilla/Snowflake SSH/Steam/Pidgin/Telegram；钱包 Atomic/Guarda/Coinomi/Bitcoin/Electrum/Exodus` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要判定为勒索软件：RC4/RSA 仅用于封装上传报告，未发现对用户文件加密或索要赎金的代码路径。
- 不要判定为持久化后门/RAT：未发现注册表 Run、服务、计划任务或远程命令通道；内置 command XML 是本地抓取清单而非 C2 指令集。
- 不要断言样本已在目标环境成功执行或成功外联：动态沙箱未创建样本进程，也未观察到任何 DNS/TCP 会话。
- 不要断言存在下载器或二级载荷：没有发现从网络下载并执行代码的路径。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 静态反编译（动态执行未取得运行时行为） |
| 脱壳 | 否 |

**局限与待验证**

1. 动态沙箱投放后轮询 673 次、0 个新候选进程，网络监控无任何样本相关 DNS/TCP 会话，未取得真实运行行为；静态结构显示声明的 .text 原始偏移 0x200 指向零填充区，实际内容按 RVA 对齐，标准加载器无法映射 CLR 头，这解释了执行失败。
2. C2 与全部配置来自静态解密，未观测到与 api[.]telegram[.]org 的成功请求/响应，因此按静态处理并保留 pending_dynamic_verify。
3. 未验证 Telegram 机器人令牌与聊天 ID 当前是否仍然有效。
4. 未获得可支撑注册表、服务、证书或杀毒软件行为的遥测数据；相关项均为空。
5. 未从内存或资源段提取到二级载荷；WSR 报告结构由代码还原，未取得真实上传样本。
6. 导入表解析异常（工具解析出 385 个空 DLL 条目），imphash 不宜用于家族关联或相似度检索。

## 证据索引

<details>
<summary>展开 12 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件规模 |
| `ev-000002` | scan.imphash | imphash=f39bd897d8a5059590f3ba7e7a7d7b89 |
| `ev-000006` | PE 结构解析 | Machine=I386 与 Optional Magic=0x20b 不一致 |
| `ev-000007` | 字符串提取 | ASCII 364 条/UTF-16LE 210 条，含 .NET 元数据与 WhiteSnake.Properties.Resources 等残留名 |
| `ev-000008` | 脚本化取证 | 自写 .NET 元数据解析+CIL 反汇编+字符串 XOR 解密，还原全部配置、外传链与反虚拟机清单 |
| `ev-000009` | evidence.record(manual) | PE 节表/镜像布局错位的静态推断，用于解释动态未执行 |
| `ref:89a734ac95` | PE 结构解析 | PE 头部完整画像（入口 0x871e、导入目录 0x86d0、SizeOfImage 0xe000） |
| `ref:a690bc5023` | 节表解析 | 三节 .text/.rsrc/.reloc 的 RVA 与原始偏移 |
| `ref:2b340a4f12` | 导入表解析 | 导入表解析异常，385 个空 DLL 条目（导入目录落在元数据尾部） |
| `ref:b4cdb193e5` | unpack.detect | 无已知壳签名，packed=false |
| `ref:1794a67c25` | 动态分析平台 | 动态投放后 candidate_count=0、无进程转储、无相关网络会话，已回滚 |
| `telemetry:94417d37` | 动态遥测 | 动态遥测记录到：监控组件 进程/文件事件 97 条；已过滤工具/系统噪声 27 条 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
