---
title: "恶意样本分析：NSIS-based loader (unattributed)（PE · exe · ec2ea177）"
published: 2026-11-02
draft: false
description: "恶意（置信度低）：NSIS-based loader (unattributed) · loader/downloader · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **NSIS-based loader (unattributed)**（存疑） · 置信度 **低**
> 
> 别名：NSIS dropper、NSIS fake installer loader、NSIS 静默安装器加载器
> 
> 动态沙箱中安装器进程真实向 185[.]29[.]10[.]102:80 发起 HTTP 下载请求，进程内存中可见完整请求报文；静态解析同时显示静默安装、释放 14 个数据/诱饵文件并加载 System.dll 插件、注册远程 DLL 以及自签名证书伪装。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **NSIS-based loader (unattributed)** · 别名 NSIS dropper、NSIS fake installer loader、NSIS 静默安装器加载器 · _存疑_ |
| 置信度 | **低** |
| 行为类 | loader · downloader |
| 难度 | medium |
| 首次出现 | 2026-11-02 08:03:12 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/ec2ea17710d05c629c3c4a399dfdb301eb3498dab02b71c975197be782455dce/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">静默安装伪装组件</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">填充大文件作诱饵</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">调用 System.dll 插件</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">注册远程 DLL</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">循环下载远程载荷</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `ec2ea17710d05c629c3c4a399dfdb301eb3498dab02b71c975197be782455dce` |
| MD5 | _未记录_ |
| 大小 | 665,808 字节（650.2 KB） |
| 类型 | PE · `exe` |

## 行为分析

共 **9** 条行为，每条都挂了证据；其中 **7** 条静态可得、**2** 条经动态分析取得。

### 1. 静默安装伪装组件

`T1036.005` · 置信度 **高** · 静态

以 NSIS 静默模式运行，把 14 个数据/诱饵文件（含 4 个单字节填充诱饵）释放到 %PROGRAMFILES%\Vaar220\counterembargo\Colorability224，并把 System.dll 插件释放到 $PLUGINSDIR，伪装成正常应用安装程序。

> **证据**：NSIS firstheader flags=0x306A（含 silent 位）；解压头部后 EXTRACTFILE 指令 130-143（14 个数据文件）与 102（System.dll）；安装目录字符串 $PROGRAMFILES\Vaar220\counterembargo\Colorability224
> 
> **来源**：`ev-000014` · `ev-000010` · `ref:a083ca3d38`

### 2. 填充大文件作诱饵

`T1027` · 置信度 **高** · 静态

释放 4 个 278KB-904KB 的单字节填充文件以及 JPG/INI/TXT 文本，制造正常安装包体积并干扰静态判定。

> **证据**：falsifiability.pre/Bulningen.pur/heteroalbumose.ube/undualises.odd 分别 95%-99% 由 0xF1/0xC9/0x8A/0x07 填充；Torturofret 的 MZ 处 e_lfanew 越界
> 
> **来源**：`ev-000013` · `ev-000010`

### 3. 调用 System.dll 插件

`T1106` · 置信度 **高** · 静态

释放 NSIS System.dll 到 $PLUGINSDIR，并通过 REGISTERDLL 调用其 Call 导出，为后续原生 API 调用做准备。

> **证据**：NSIS 指令 105：REGISTERDLL $PLUGINSDIR\System.dll "Call"；数据块首个流解出 12,288 字节 MZ 文件
> 
> **来源**：`ev-000010` · `ref:0ffa31b392`

### 4. 注册远程 DLL

`T1129` · 置信度 **中** · 静态

对 $INSTDIR\verdensherredmmernes.dll 调用 DllRegisterServer；该 DLL 不在 15 个嵌入文件中，需由远程下载获得，形成下载后加载链路。

> **证据**：NSIS 指令 122：REGISTERDLL $INSTDIR\verdensherredmmernes.dll "DllRegisterServer"；字符串表含 DllRegisterServer
> 
> **来源**：`ev-000010` · `ref:ec3a3d96d6`

### 5. 循环下载远程载荷

`T1105` · 置信度 **高** · 动态

安装器进程以 Firefox UA 向 185[.]29[.]10[.]102:80 请求 /zRVZRgnIWQzkRMbTfrq107[.]bin，约每 10 秒重试一次，形成下载循环。

> **证据**：网络监控：ec2ea...exe (PID 4896) 自 21:49:25 起反复请求 TCP 185[.]29[.]10[.]102:80，GET /zRVZRgnIWQzkRMbTfrq107[.]bin；进程内存含同一请求
> 
> **来源**：`ref:8a5a73c745` · `ev-000011`

### 6. HTTP 伪装浏览器流量

`T1071.001` · 置信度 **高** · 动态

使用 Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0 作为 User-Agent，并附加 Cache-Control: no-cache，把下载流量伪装成浏览器请求。

> **证据**：网络日志中的 User-Agent 与进程内存 0x565F158 处完整请求头一致
> 
> **来源**：`ref:8a5a73c745` · `ev-000011`

### 7. 写入伪注册表键

`T1112` · 置信度 **中** · 静态

通过 RegCreateKeyExW/RegSetValueExW 在 HKCU\Software\Microsoft\Windows\CurrentVersion 下的 stool、fastlaasningerne、reargument 以及 HKLM\SOFTWARE\whitecapping\lapfuls\Begyndelsestider156 写入或删除值。

> **证据**：NSIS 指令 64/155/164/165 携带上述键名；导入表含 RegCreateKeyExW/RegSetValueExW/RegDeleteValueW/RegDeleteKeyW
> 
> **来源**：`ev-000015` · `ref:0ffa31b392`

### 8. 自签名证书伪装

`T1553.002` · 置信度 **高** · 静态

使用自签名 Authenticode 证书（C=FR, O=Ganglioneuroma, OU=Hvlvene Udbetal Smittebrerne, CN=Ganglioneuroma）给安装包签名，制造“已签名软件”假象。

> **证据**：PE 安全目录偏移 0xA1620，WIN_CERTIFICATE 长度 4784，subject 与 issuer 相同
> 
> **来源**：`ev-000012`

### 9. 运行时还原 C2 配置

`T1027.013` · 置信度 **高** · 静态

C2 URL 与 User-Agent 在磁盘镜像的 ASCII/UTF-16 搜索中均为 0 命中，仅出现在进程内存，说明配置在运行时生成或解密，以规避静态字符串检测。

> **证据**：整份 PE 搜索 185[.]29[.]10[.]102 / zRVZRgn... / Mozilla / Firefox 均 0 命中；内存 0x90351351 出现 ANSI URL，0x564197C 出现 UTF-16 路径
> 
> **来源**：`ev-000011`


## IOC（已去武器化）

### 网络

:::note
**已动态观测到连接**：样本实际向该目标发起 TCP 连接（短时间内多次重试）。
:::

:::caution
**真实服务器侧仍未验证**：上述连接/握手是与本地受控仿真服务完成的，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://185[.]29[.]10[.]102/zRVZRgnIWQzkRMbTfrq107[.]bin` | 80 | download | 动态 | 已观测 |

### 主机

**落地路径**

- `%PROGRAMFILES%\Vaar220\counterembargo\Colorability224\`
- `%PROGRAMFILES%\Vaar220\counterembargo\Colorability224\verdensherredmmernes.dll`

**注册表**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\stool`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\fastlaasningerne\`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\reargument`
- `HKLM\SOFTWARE\whitecapping\lapfuls\Begyndelsestider156`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `185[.]29[.]10[.]102` | 是 | 动态 |
| `download_url` | `hxxp://185[.]29[.]10[.]102/zRVZRgnIWQzkRMbTfrq107[.]bin` | 是 | 动态 |
| `http_user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0` | 是 | 动态 |
| `install_path` | `%PROGRAMFILES%\Vaar220\counterembargo\Colorability224` | 是 | 静态 |
| `registered_dll` | `%INSTDIR%\verdensherredmmernes.dll` | 否 | 静态 |
| `retry_interval_seconds` | `10` | 否 | 动态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得判定为勒索软件或窃密程序：未取得第二阶段载荷，未观察到文件加密、浏览器凭据/剪贴板窃取或横向移动行为。
- 不得声称样本创建了服务或计划任务：静态与动态均未见到对应 API 调用、服务名或计划任务字符串。
- 不得把 15 个嵌入文件当作功能组件：其中 4 个大文件为单字节填充，3 个为 JPG，其余多为随机词文本或无可执行结构的高熵数据；未见其中包含有效 PE。
- 不得断言样本使用 regsvr32.exe：注册动作由安装器进程内调用 DllRegisterServer 完成，未观察到 regsvr32 子进程。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 第二阶段下载未取得有效载荷（请求反复重试直至观测结束），家族归属与最终能力无法确认。
2. C2 URL 与 User-Agent 在磁盘镜像中不可见，仅从进程内存恢复；静态不可直接提取。
3. 注册表写入来自 NSIS 脚本指令与导入 API，未做实时注册表差异确认。
4. 未观察到子进程、服务、计划任务或进程注入；不排除后续阶段具备这些能力。
5. 样本为 32 位，运行环境为 64 位 Windows 10；其他系统上行为可能不同。
6. 签名证书为自签名，不能作为可信发布者依据。

## 证据索引

<details>
<summary>展开 15 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256/md5/sha1 与大小 |
| `ev-000002` | scan.imphash | imphash=f4639a0b3116c2cfc71144b88a929cfd |
| `ev-000009` | 字符串提取 | ASCII/UTF-16 字符串抽取（无 flag 命中） |
| `ref:a083ca3d38` | 样本分诊 | M1 分诊：0 异常、packing.score=0、5 个节 |
| `ref:0ffa31b392` | 导入表解析 | 7 个 DLL/163 个符号，含 RegCreateKeyExW/RegSetValueExW/GetProcAddress |
| `ref:63f93971eb` | PE 结构解析 | PE32/i386，入口 RVA 0x3552，覆盖层起点 323584 |
| `ev-000010` | static unpack + NSIS header decode | 15 个嵌入文件、安装目录、System.dll 插件、DllRegisterServer 指令 |
| `ev-000011` | memory dump analysis | 内存中的完整 HTTP 请求与 URL/UA 偏移 |
| `ev-000012` | certificate parse | 自签名证书 CN=Ganglioneuroma |
| `ev-000013` | embedded file byte statistics | 4 个单字节填充大文件；Torturofret 非有效 PE |
| `ev-000014` | NSIS firstheader parse | flags=0x306A（silent + force CRC） |
| `ev-000015` | NSIS instruction decode | 注册表键与写入/删除指令 |
| `ref:8a5a73c745` | dynamic sandbox | 真实引爆时间线与网络请求观测 |
| `ref:3ddc379c91` | anti-debug static scan | 未发现反调试技术 |
| `c2_evidence:ec2ea177` | 连接证据提取 | 动态网络监控记录到 22 次到 185.29.10[.]102:80, 185[.]29[.]10[.]102:80, displaycatalog[.]mp[.]microsoft[.]com:80 的连接尝试；未捕获完整会话 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
