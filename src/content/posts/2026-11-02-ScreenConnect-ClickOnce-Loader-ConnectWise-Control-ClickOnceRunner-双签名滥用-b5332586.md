---
title: "恶意样本分析：ScreenConnect ClickOnce Loader（ConnectWise Control ClickOnceRunner 双签名滥用）（PE · exe · b5332586）"
published: 2026-11-02
draft: false
description: "恶意（置信度中）：ScreenConnect ClickOnce Loader（ConnectWise Control ClickOnceRunner 双签名滥用） · loader/downloader/rat · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["ScreenConnect ClickOnce", "loader", "downloader", "rat", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ScreenConnect ClickOnce Loader（ConnectWise Control ClickOnceRunner 双签名滥用）**（存疑） · 置信度 **中**
> 
> 别名：ClickOnceRunner abuse、ScreenConnect click-once stager、dfshim ClickOnce loader
> 
> 程序主体逻辑经反编译完整还原：打开当前用户 TrustedPublisher 证书存储，把自身 Authenticode 签名里的证书写入该存储；再从签名认证属性 OID 1.3.6[.]1.4.1[.]311[.]4.1.1 中取出 UTF-16 的 ClickOnce 部署清单地址，通过 dfshim!ShOpenVerbApplicationW 拉起，随后睡眠 40 秒并删除刚写入的证书。该清单指向 hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect[.]Client[.]application，即攻击者控制的 ScreenConnect(ConnectWise Control) 远程控制客户端。样本文件尾部的签名同时带有一个自签证书签名和一份嵌套的 ConnectWise 代码签名，属于签名注入/双签名伪装。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ScreenConnect ClickOnce Loader（ConnectWise Control ClickOnceRunner 双签名滥用）** · 别名 ClickOnceRunner abuse、ScreenConnect click-once stager、dfshim ClickOnce loader · _存疑_ |
| 置信度 | **中** |
| 行为类 | loader · downloader · rat |
| 难度 | medium |
| 首次出现 | 2026-10-31 08:12:46 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/b5332586088042aaef4fe1cb73931c9a125dc0f0ab8135912fd446818a019417/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪造证书入信任库</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.004</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">从签名属性取载点</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">ClickOnce 拉起远端</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">落地远程控制工具</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">冒用正规厂商签名</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `b5332586088042aaef4fe1cb73931c9a125dc0f0ab8135912fd446818a019417` |
| MD5 | _未记录_ |
| 大小 | 313,912 字节（306.6 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据，且全部静态可得。

### 1. 伪造证书入信任库

`T1553.004` · 置信度 **高** · 静态

打开当前用户 TrustedPublisher 证书存储，并把自身签名消息中的证书以 CERT_STORE_ADD_ALWAYS 方式写入，使随后经 ClickOnce 安装的载荷被视为“可信发布者”而跳过发布者提示。

> **证据**：0x401052 call CertOpenSystemStoreA(0,"TrustedPublisher"); 0x401102 call CertAddCertificateContextToStore(store,ctx,1,..)
> 
> **来源**：`ref:2e21dbdcc8` · `ref:8ce631e474` · `ref:065d412192`

### 2. 从签名属性取载点

`T1027` · 置信度 **高** · 静态

把自身文件路径交给 CryptQueryObject 提取 PKCS#7 签名，读取签名者认证属性 OID 1.3.6[.]1.4.1[.]311[.]4.1.1，跳过 DER 头后得到 UTF-16LE 的 ClickOnce 清单 URL；URL 不在代码或资源中，只存在于签名属性里。

> **证据**：0x401076 call CryptQueryObject(1,self,0x400,2,..); 0x40118f call CertFindAttribute("1.3.6[.]1.4.1[.]311[.]4.1.1",...); 字符串 0x446484
> 
> **来源**：`ref:2e21dbdcc8` · `ref:8ce631e474` · `ref:756f6cf38f` · `ref:c2ed1de018`

### 3. ClickOnce 拉起远端

`T1105` · 置信度 **高** · 静态

动态加载 dfshim.dll 并解析 ShOpenVerbApplicationW，将上一步取得的 URL（pbData+4 指向的 Unicode 串）作为应用地址调用，由 ClickOnce 运行时下载并启动部署清单。

> **证据**：0x4011e2 LoadLibraryA("dfshim"); 0x4011f4 GetProcAddress(ShOpenVerbApplicationW); 0x4011f7 call eax（参数为属性值+4）
> 
> **来源**：`ref:2e21dbdcc8` · `ref:8ce631e474` · `ref:756f6cf38f`

### 4. 落地远程控制工具

`T1219` · 置信度 **高** · 静态

内嵌清单地址为 hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect[.]Client[.]application?...&p=8041&k=…，即攻击者中继上的 ScreenConnect 客户端部署清单；客户端一旦安装即建立可交互的远程控制通道。

> **证据**：签名属性内 UTF-16 字符串（文件偏移 0x49C58 起）；h=31.56.209[.]123&p=8041&k=BgIAAACkAABSU0Ex…
> 
> **来源**：`ref:756f6cf38f` · `ref:0a0482cc2c`

### 5. 冒用正规厂商签名

`T1553.002` · 置信度 **高** · 静态

PE 安全目录中的 PKCS#7 含未认证属性 OID 1.3.6[.]1.4.1[.]311[.]2.4.1（嵌套签名），内层签名者为 Connectwise, LLC（DigiCert 代码签名 CA），外层为自签的 paperlesinvite 证书；Windows 签名接口将 ConnectWise 证书作为显示签名者，形成“正规厂商已签名”的假象。

> **证据**：安全目录 RVA 0x497C0/大小 0x3238；asn1: 1.3.6[.]1.4.1[.]311[.]2.4.1 嵌套签名，内层 subject=CN=Connectwise, LLC；Get-AuthenticodeSignature Signer=Connectwise, LLC
> 
> **来源**：`ref:38d9e8442e` · `ref:b6f6f1a345` · `ref:3b208eb51d` · `ref:a3e4e3abfa`

### 6. 40 秒后清除证书

`T1070` · 置信度 **高** · 静态

调用 Sleep(40000) 后遍历先前返回的证书上下文并逐个 CertDeleteCertificateFromStore，再关闭存储，使被信任的伪造证书只在短暂窗口内存在，降低被取证发现的概率。

> **证据**：0x4011f9 push 0x9c40; call [Sleep]; 清理循环内 call CertDeleteCertificateFromStore / CertCloseStore
> 
> **来源**：`ref:2e21dbdcc8` · `ref:8ce631e474`

### 7. 代码本体未改动

`T1553.002` · 置信度 **高** · 静态

按 PE Authenticode 规则计算的映像摘要为 6386A686AD2206DCC31EA1D75BF87E54CAA396019D310B0B71219B5D9FBCF71E，与签名内嵌的摘要一致，说明代码段未被修改；威胁来自追加的签名（签名注入），而非代码补丁。

> **证据**：自实现 Authenticode 摘要计算与 SPC_INDIRECT_DATA 中 sha256 摘要逐字节相同；PDB 路径指向 cwcontrol\Product\ClickOnceRunner
> 
> **来源**：`ref:71f432f4f0` · `ref:c2ed1de018` · `ref:0af020d952`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect[.]Client[.]application?h=31[.]56[.]209[.]123&p=8041&k=BgIAAACkAABSU0ExAAgAAAEAAQAVCr...（清单内含 Base64 客户端密钥，已截断）` | 443 | download | 静态 | ⏳ 未观测 |
| tcp | `31[.]56[.]209[.]123:8041` | 8041 | c2 | 静态 | ⏳ 未观测 |

### 主机

**注册表**

- `HKCU\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates\4D78D1933270944FB476EFF1BB6D0E8FFA3EE5C2`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `clickonce_manifest_url` | `hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect[.]Client[.]application?h=31[.]56[.]209[.]123&p=8041&k=BgIAAACkAABSU0ExAAgAAAEAAQAVCr...（截断）` | 是 | 静态 |
| `relay_host` | `31[.]56[.]209[.]123` | 是 | 静态 |
| `relay_port` | `8041` | 是 | 静态 |
| `trust_store` | `TrustedPublisher（当前用户，CertOpenSystemStoreA 传入 NULL 提供程序）` | 是 | 静态 |
| `signing_attr_oid` | `1.3.6[.]1.4.1[.]311[.]4.1.1（认证属性，值为 DER OCTET STRING 包裹的 UTF-16LE 清单地址）` | 是 | 静态 |
| `injected_cert_subject` | `CN=CN=paperlesinvite.sbs` | 是 | 静态 |
| `injected_cert_issuer` | `CN=CN=paperlesinvite.sbs Root（自签根，未随签名下发）` | 否 | 静态 |
| `injected_cert_sha1` | `4D78D1933270944FB476EFF1BB6D0E8FFA3EE5C2` | 是 | 静态 |
| `nested_signer_subject` | `CN=Connectwise, LLC, O=Connectwise, LLC, L=Tampa, S=Florida, C=US（序列号 0B9360051BCCF66642998998D5BA97CE）` | 否 | 静态 |
| `build_pdb_path` | `C:\builds\cc\cwcontrol\Product\ClickOnceRunner\Release\ClickOnceRunner.pdb` | 否 | 静态 |
| `cert_cleanup_delay_seconds` | `40` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要把它当作自带远控能力的独立后门/木马本体：其代码与正版 ConnectWise Control ClickOnceRunner 一致，远程控制能力来自其经 ClickOnce 拉取的 ScreenConnect 客户端。
- 不要因为签名中内嵌 DigiCert 与 ConnectWise 证书就认定该文件由 ConnectWise 合法签发且可信：该证书已被颁发者吊销，且外层自签签名携带攻击者载点，签名状态并非有效。
- 不要在报告中声称已在沙箱观测到实际外联或二阶段落地：观测窗口内未出现到 31.56.209[.]123 的连接或 dfsvc 子进程，该结论仅为静态还原。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 二阶段未落地：沙箱执行期间未观察到 dfshim/dfsvc 子进程或到 31.56.209[.]123 的出站连接，ClickOnce 清单内容与最终安装的 ScreenConnect 客户端未取得，C2 配置均标记为静态恢复、待动态确认。
2. 沙箱未提供注册表/证书存储的直接快照，TrustedPublisher 写入与 40 秒后的删除仅由反编译调用链确认，未做动态比对。
3. 签名外层自签证书的根证书未随签名下发（签名消息仅含叶子证书），因此该伪造链的完整信任路径只能推断。
4. 家族命名基于组件指纹、签名结构与载荷地址，未取得厂商命名或 YARA 佐证，故标记 uncertain。
5. ScreenConnect 清单 URL 中的 k 参数为较长的 Base64 客户端密钥，报告与 JSON 中做了截断，完整值可在样本偏移 0x49C58 处读取。

## 证据索引

<details>
<summary>展开 10 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=b5332586088042aaef4fe1cb73931c9a125dc0f0ab8135912fd446818a019417, imphash=c2fe6927e1db8cf00400dbef9e5d35be |
| `ev-000013` | decompile.ghidra | FUN_00401000 反编译：TrustedPublisher 证书写入 + 签名属性取 URL + dfshim!ShOpenVerbApplicationW + Sleep(40000) + 删除证书 |
| `ref:8ce631e474` | disasm.function | 0x401000 起 190 条指令的调用点：CertOpenSystemStoreA@0x401052、CryptQueryObject@0x401076、CertAddCertificateContextToStore@0x401102、CertFindAttribute@0x40118f、LoadLibraryA(dfshim)@0x4011e2、GetProcAddress@0x4011f4、间接调用@0x4011f7 |
| `ref:756f6cf38f` | script | 从签名认证属性 OID 1.3.6[.]1.4.1[.]311[.]4.1.1 提取 UTF-16LE ClickOnce 清单 URL（偏移 0x49C58） |
| `ref:38d9e8442e` | script | ASN.1 结构解析：外层自签签名 + 嵌套签名 OID 1.3.6[.]1.4.1[.]311[.]2.4.1 + Connectwise, LLC 证书链与时间戳 |
| `ref:9342ec2b1b` | script | 伪造证书指纹 SHA1=4D78D1933270944FB476EFF1BB6D0E8FFA3EE5C2，subject=CN=CN=paperlesinvite.sbs，issuer=CN=CN=paperlesinvite.sbs Root，EKU=时间戳 |
| `ref:71f432f4f0` | script | Authenticode 摘要 6386A686… 与签名内 SPC_INDIRECT_DATA 摘要一致（算法在已签名 VM 程序上校验通过） |
| `ref:0af020d952` | script | 调试目录 PDB 路径 C:\builds\cc\cwcontrol\Product\ClickOnceRunner\Release\ClickOnceRunner.pdb |
| `ref:3b208eb51d` | script | 系统签名接口：Signer=CN=Connectwise, LLC（DigiCert CA），状态异常，证书已被颁发者吊销 |
| `ref:d4c9fdbb20` | 动态分析平台 | 沙箱真实投放并执行，样本进程持续运行并被内存转储；无新子进程，网络侧无到 31.56.209[.]123 的连接 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
