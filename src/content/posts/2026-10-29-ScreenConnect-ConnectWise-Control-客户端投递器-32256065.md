---
title: "恶意样本分析：ScreenConnect (ConnectWise Control) 客户端投递器（PE · exe · 32256065）"
published: 2026-10-29
draft: false
description: "恶意（置信度中）：ScreenConnect (ConnectWise Control) 客户端投递器 · loader/downloader/rat · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["ScreenConnect", "loader", "downloader", "rat", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **ScreenConnect (ConnectWise Control) 客户端投递器**（存疑） · 置信度 **中**
> 
> 别名：ConnectWise ScreenConnect、ScreenConnect RAT、ConnectWise Control、ScreenConnect.Client.application loader
> 
> 样本是一个 32 位 GUI 子系统的 ClickOnce 引导器:它把自身数字签名中的证书写入当前用户的『受信任发布者』库,再从签名属性 OID 1.3.6[.]1.4.1[.]311[.]4.1.1 中取出部署地址 hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect.Client.application?h=31[.]56[.]209[.]123&p=8041,经 dfshim!ShOpenVerbApplicationW 启动 ClickOnce 部署安装 ConnectWise ScreenConnect 客户端,从而获得指向外部单一 IP 的远程控制通道。反编译(0x401000)与动态沙箱内存取证(dfshim.dll→dfdll.dll→urlmon.dll 加载链)相互印证。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **ScreenConnect (ConnectWise Control) 客户端投递器** · 别名 ConnectWise ScreenConnect、ScreenConnect RAT、ConnectWise Control、ScreenConnect.Client.application loader · _存疑_ |
| 置信度 | **中** |
| 行为类 | loader · downloader · rat |
| 难度 | medium |
| 首次出现 | 2026-10-29 09:05:34 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/32256065004e7e816afd12baa39caaacdcc185fa5f3202055b8c65e81727402f/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">解析自身数字签名</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">写入受信发布者证书库</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.004</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">从签名属性取部署地址</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">借 dfshim 启动 ClickOnce</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1218</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">远程拉取远控客户端</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `32256065004e7e816afd12baa39caaacdcc185fa5f3202055b8c65e81727402f` |
| MD5 | _未记录_ |
| 大小 | 312,528 字节（305.2 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **7** 条行为，每条都挂了证据；其中 **6** 条静态可得、**1** 条经动态分析取得。

### 1. 解析自身数字签名

`T1553.002` · 置信度 **高** · 静态

以自身可执行文件路径调用 CryptQueryObject(CERT_QUERY_OBJECT_FILE) 解析内嵌 PKCS#7,取证书数量与全部证书实体。

> **证据**：0x401000 FUN_00401000:GetModuleFileNameW → CryptQueryObject(1,lpFilename,0x400,2,...) → CryptMsgGetParam(11/12)
> 
> **来源**：`ev-000013`

### 2. 写入受信发布者证书库

`T1553.004` · 置信度 **高** · 静态

打开当前用户证书库 TrustedPublisher,把签名里的每张证书 CertAddCertificateContextToStore 写入,使本文件发布者在系统中表现为可信发布者。

> **证据**：0x401000:CertOpenSystemStoreA(0,"TrustedPublisher") → CertAddCertificateContextToStore(...)
> 
> **来源**：`ev-000013`

### 3. 从签名属性取部署地址

`T1027` · 置信度 **高** · 静态

在签名已认证属性中查找 OID 1.3.6[.]1.4.1[.]311[.]4.1.1,取出其中的 UTF-16 部署地址;该地址不出现在 .rdata/.data 或代码常量里,静态字符串扫描几乎不可见。

> **证据**：0x401000:CertFindAttribute("1.3.6[.]1.4.1[.]311[.]4.1.1",...);地址位于签名区文件偏移 0x4C12C
> 
> **来源**：`ev-000013` · `ev-000017`

### 4. 借 dfshim 启动 ClickOnce

`T1218` · 置信度 **高** · 动态

LoadLibraryA("dfshim") 后取 ShOpenVerbApplicationW 并把上一步的 URL 交给它,由系统 ClickOnce 组件发起部署;动态快照中该进程随后加载 dfshim.dll、dfdll.dll、urlmon.dll、mscoree.dll。

> **证据**：0x401000:LoadLibraryA("dfshim")/GetProcAddress("ShOpenVerbApplicationW") → 间接调用;动态 PID 1048 的模块链 dfshim.dll → dfdll.dll → urlmon.dll
> 
> **来源**：`ev-000013` · `ev-000016`

### 5. 远程拉取远控客户端

`T1105` · 置信度 **中** · 静态

ClickOnce 部署地址指向外部单 IP 的 ScreenConnect 实例,运行时会下载并安装对应的 .application 清单与客户端程序;本次动态运行未观察到实际出网,该阶段未取得。

> **证据**：签名属性 URL:hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect.Client.application?h=31[.]56[.]209[.]123&p=8041
> 
> **来源**：`ev-000017` · `ev-000016`

### 6. 回连8041端口建远控

`T1219` · 置信度 **中** · 静态

安装后的 ScreenConnect 客户端按 h=31[.]56[.]209[.]123&p=8041 的参数回连中继服务器,形成可交互的远程桌面/命令通道;该连接在本样本进程内不发生,由下载的子程序完成。

> **证据**：部署 URL 的 h/p 参数(31[.]56[.]209[.]123,8041);样本自身导入表无网络 API,仅 KERNEL32+CRYPT32 共 97 个符号
> 
> **来源**：`ev-000017` · `ev-000002`

### 7. 40秒后抹掉信任证书

`T1070` · 置信度 **高** · 静态

Sleep(40000) 后遍历先前加入的证书句柄逐个 CertDeleteCertificateFromStore 删除并关闭证书库,减少受信发布者库中的残留痕迹。

> **证据**：0x401000:Sleep(40000) → CertDeleteCertificateFromStore 循环 → CertCloseStore
> 
> **来源**：`ev-000013`


## IOC（已去武器化）

### 网络

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控 受控仿真服务 完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect.Client.application?h=31[.]56[.]209[.]123&p=8041&k=<base64 RSA1 公钥>` | 443 | download | 静态 | ⏳ 未观测 |
| tcp | `31[.]56[.]209[.]123` | 8041 | c2 | 静态 | ⏳ 未观测 |

### 主机

**注册表**

- `HKCU\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `clickonce_url` | `hxxps://31[.]56[.]209[.]123/Bin/ScreenConnect.Client.application?h=31[.]56[.]209[.]123&p=8041&k=<base64>` | 是 | 静态 |
| `c2_hosts` | `31[.]56[.]209[.]123` | 是 | 静态 |
| `c2_port` | `8041` | 是 | 静态 |
| `deployment_key` | `k 参数 base64 解码为 276 字节、含 RSA1 魔数的 CAPI 公钥 blob(ScreenConnect 客户端部署密钥)` | 是 | 静态 |
| `config_location` | `配置不在代码/资源中,而是存放在 Authenticode 签名属性 OID 1.3.6[.]1.4.1[.]311[.]4.1.1 的值里(文件偏移 0x1F12C,UTF-16LE)` | 是 | 静态 |
| `signer_certificate` | `CN=Connectwise, LLC, O=Connectwise, LLC, L=Tampa, ST=Florida, C=US; serial=0xb9360051bccf66642998998d5ba97ce; 签发者 DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能因为二进制自身没有网络 API 就判定它无 C2:下载与回连由 dfshim/ClickOnce 与随后安装的 ScreenConnect 客户端完成,样本只是引导器。
- 不能把它当作自研加密协议的窃密或勒索程序:样本中没有文件遍历/加密、凭据读取或自定义 C2 协议实现,动态中也未见文件写入。
- 不能仅凭『签名有效、主体为 ConnectWise』判定为合法软件:签名覆盖的部署地址指向外部单一 IP 的非企业托管实例。
- 不能把 TrustedPublisher 写入当作持久化:代码在约 40 秒后主动删除这些证书并退出。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 远程 .application 清单与 ScreenConnect 客户端未取得:动态网络监控 未记录到 31[.]56[.]209[.]123:443/8041 的任何连接,样本进程在 40 秒等待后退出,故 stage2 为空、C2 参数仅来自静态提取。
2. 代码把签名属性 blob 加 4 字节偏移后传给 ShOpenVerbApplicationW;动态中 ClickOnce 部署库确已加载但未见下载请求,无法排除偏移导致 URL 被截断、部署在解析阶段即失败。
3. 受信发布者证书库的写入/删除只有反编译证据,动态档位没有注册表或证书库监控,未能直接取证该写入。
4. 家族命名基于 ScreenConnect 部署特征与签名主体,缺少厂商命名或 YARA 佐证,故标记 uncertain。

## 证据索引

<details>
<summary>展开 10 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与文件大小 312528 |
| `ev-000002` | scan.imphash | imphash=c2fe6927e1db8cf00400dbef9e5d35be |
| `ev-000003` | scan.rich | Rich header 11 条工具链记录,richhash=02ef09fc7c85d790ac1d32f483d193df |
| `ev-000004` | scan.entropy | .text 熵 6.608(未达加壳阈值) |
| `ev-000009` | 字符串提取 | 字符串扫描:ascii 1144 / utf16 464 条,无明文 C2;命中的字母表为运行库数据 |
| `ev-000013` | decompile.function | 0x401000 主函数:证书库写入 + 签名属性取 URL + dfshim ClickOnce + Sleep(40000) 清理 |
| `ev-000014` | decompile.function | find_pe_section 为 MSVC 运行库函数(非恶意逻辑) |
| `ev-000015` | 脚本化取证 | 重算 Authenticode 摘要并与签名内摘要比对一致;签名主体 CN=Connectwise, LLC |
| `ev-000016` | 脚本化取证 | 动态沙箱:进程 1048 加载 dfshim.dll→dfdll.dll→urlmon.dll,无对外连接 |
| `ev-000017` | 脚本化取证 | 从签名属性 OID 1.3.6[.]1.4.1[.]311[.]4.1.1 提取 ScreenConnect ClickOnce 部署 URL 与 RSA1 部署密钥 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
