---
title: "恶意样本分析：DarkStealer（PE · exe · 75f88ea2）"
published: 2026-11-06
draft: false
description: "恶意（置信度中）：DarkStealer · stealer/loader/injector · 难度 medium · 动态沙箱 + 静态反编译"
tags: ["Dark", "stealer", "loader", "injector", "PE"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **DarkStealer**（存疑） · 置信度 **中**
> 
> 别名：Dark-Stealer、Dark Stealer、@DarkStealer404 build
> 
> 样本为 PyInstaller 打包的 Python 信息窃取器。动态沙箱中真实执行后，先后解析并访问 api[.]ipify[.]org/httpbin[.]org/api[.]myip[.]com（公网 IP 探测），随后持续解析 api[.]telegram[.]org 并以 Bot API 上传文件，失败后转向 catbox.moe、upload[.]gofile[.]io、0x0.st 备用图床；静态脚本内含 Chrome/Firefox 凭据与 Cookie 解密、App-Bound Encryption 绕过、Discord 令牌与 Telegram 会话目录窃取、钱包扩展数据收集、PowerShell 截图与隐藏 VBS+Run 键持久化、加密货币地址剪贴板替换。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **DarkStealer** · 别名 Dark-Stealer、Dark Stealer、@DarkStealer404 build · _存疑_ |
| 置信度 | **中** |
| 行为类 | stealer · loader · injector |
| 难度 | medium |
| 首次出现 | 2026-11-03 15:03:59 |
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/75f88ea2bc7f6b9c258d2254d68bdf62b7ce2bc2c1fd49c466f3af213f59422c/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">检测虚拟机与分析工具</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">探测公网IP做画像</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1016</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">动态观测</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">解密Chrome账密</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">绕过App-Bound加密</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1134.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">远程调试窃取Cookie</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `75f88ea2bc7f6b9c258d2254d68bdf62b7ce2bc2c1fd49c466f3af213f59422c` |
| MD5 | _未记录_ |
| 大小 | 34,027,016 字节（32.5 MB） |
| 类型 | PE · `exe` |

## 行为分析

共 **13** 条行为，每条都挂了证据；其中 **11** 条静态可得、**2** 条经动态分析取得。

### 1. 检测虚拟机与分析工具

`T1497.001` · 置信度 **高** · 静态

进程启动即比对主机名/用户名/GPU/操作系统/进程/IP 黑名单（含 vmtoolsd.exe、vboxservice.exe、wireshark.exe、x64dbg.exe、ida64.exe、processhacker.exe、pestudio.exe、joeboxcontrol.exe，GPU 'vmware SVGA 3D'、'virtualbox Graphics Adapter'，用户名 WDAGUtilityAccount/runneradmin 等），命中则退出。

> **证据**：入口脚本中 blackListedIPS/blackListedHostname/blackListedGPU/blackListedProcesses 列表及 check_* 函数；PE 导入 CreateToolhelp32Snapshot/Process32FirstW（rva 209232/209240）
> 
> **来源**：`ref:8a81869bf1` · `ref:80fe281c4a`

### 2. 探测公网IP做画像

`T1016` · 置信度 **高** · 动态

依次请求 api[.]ipify[.]org、httpbin[.]org/ip、api[.]myip[.]com 获取出口 IP，parse 失败则标记 'Unknown IP'，用于受害者画像与黑名单判断。

> **证据**：get_ip(service_url) 与 ip_services 列表；动态沙箱 07:07:21-07:07:33 连续三次解析上述三个域名
> 
> **来源**：`ref:87dad7b966` · `ref:5c13982afb`

### 3. 解密Chrome账密

`T1555.003` · 置信度 **高** · 静态

复制 Login Data/Ya Passman Data 到临时库，按 v10(DPAPI+AES-GCM)/v20 分支解出密码，逐条写入 Passwords.txt；无密钥时输出 '[No decryption keys]'。

> **证据**：get_passwords：SELECT origin_url, username_value, password_value FROM logins；CryptUnprotectData、MODE_GCM、decrypt_password
> 
> **来源**：`ref:5c13982afb` · `ref:418a6c8e26`

### 4. 绕过App-Bound加密

`T1134.002` · 置信度 **高** · 静态

对 Chrome 127+ 的 v20 应用绑定密钥，先经 COM 提权服务/DPAPI 解包，再用硬编码 XOR key 与 ChaCha20-Poly1305 解密 AES key；必要时启用 SeDebugPrivilege 复制 lsass.exe 令牌做模拟以读取系统级密钥。

> **证据**：get_app_bound_key/decrypt_with_cng/derive_v20_master_key；NCryptOpenStorageProvider/NCryptDecrypt；常量 '@B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787'
> 
> **来源**：`ref:418a6c8e26` · `ref:8a81869bf1`

### 5. 远程调试窃取Cookie

`T1539` · 置信度 **高** · 静态

Cookies 库直读失败时，以 --remote-debugging-port=9876 --headless=new --user-data-dir 启动受害浏览器，访问 hxxp://localhost:9876/json 取 webSocketDebuggerUrl，连 WebSocket 后发 Network.enable/Network.getAllCookies 批量取回 Cookie。

> **证据**：get_cookie 内 '--remote-debugging-port=9876'、'Network.getAllCookies'、'webSocketDebuggerUrl'、requests+websocket 调用链
> 
> **来源**：`ref:418a6c8e26`

### 6. 导出Firefox账密Cookie

`T1555.003` · 置信度 **高** · 静态

复制 key4.db/logins.json/cookies.sqlite，按 NSS 格式用 3DES 或 AES-CBC 解出 master key，再解 encryptedUsername/encryptedPassword 与 moz_cookies。

> **证据**：getKey: SELECT item1,item2 FROM metaData；SELECT a11,a102 FROM nssPrivate；decrypt3DES/decrypt_aes/PKCS7unpad
> 
> **来源**：`ref:418a6c8e26`

### 7. 收集信用卡与自动填充

`T1555.004` · 置信度 **高** · 静态

从 Chromium 'Web Data' 库读取 credit_cards 表的卡号/CVV/有效期/持卡人，并从 autofill 表导出历史填充项，分别落盘 Credit Cards.txt、Autofills.txt。

> **证据**：get_credit_cards：SELECT ... FROM credit_cards；get_autofill：SELECT * FROM autofill
> 
> **来源**：`ref:418a6c8e26`

### 8. 窃取Discord与TG会话

`T1528` · 置信度 **高** · 静态

遍历 %APPDATA%\discord 的 leveldb，提取并 DPAPI 解密 Discord 令牌；同时 taskkill /IM Telegram.exe /FT 后拷贝 %APPDATA%\Telegram Desktop\tdata 会话目录。

> **证据**：discord_folder/leveldb_paths/decrypted_token、'taskkill /IM Telegram.exe /FT'、'Telegram Desktop'/'tdata'
> 
> **来源**：`ref:8a81869bf1` · `ref:966ab3244f`

### 9. 翻找钱包与助记词

`T1005` · 置信度 **高** · 静态

按关键词（wallet/mnemonic/seed/passphrase/metamask/exodus/paypal 等）与扩展名在 Desktop/Documents/Downloads 搜文件，并枚举 MetaMask、Trust、Phantom、OKX 等 30+ 钱包扩展 ID 的 LevelDB 目录，打包到 Wallets。

> **证据**：search_sensitive_files 的 search_keywords/folders_to_search/MAX_TOTAL_SIZE；get_extensions_wallet 的钱包扩展 ID 列表（nkbihfbeogaeaoehlefnkodbefgpgknn 等）
> 
> **来源**：`ref:966ab3244f` · `ref:8a81869bf1`

### 10. 截图并打包上传

`T1113` · 置信度 **高** · 静态

用 PowerShell（Add-Type System.Windows.Forms.Drawing + CopyFromScreen）生成 Screenshot.png，与全部窃取文本一起 zip 后按 Telegram→catbox→gofile→0x0.st 顺序回传。

> **证据**：take_screenshot 的 PS 脚本；create_zip_archive_catbox/upload_to_catbox/upload_to_gofile/upload_to_0x0/send_telegram_document
> 
> **来源**：`ref:8a81869bf1`

### 11. Telegram机器人回传

`T1567.002` · 置信度 **高** · 动态

以 Bot API sendDocument 上传 zip（caption 带 catbox/gofile/0x0 镜像链接），失败则用 sendMessage 发送链接；动态沙箱中 07:07:37 起反复解析 api[.]telegram[.]org，07:09 起转向 catbox.moe/gofile[.]io/0x0.st。

> **证据**：TOKEN_BOT/CHAT_ID 与 'hxxps://api[.]telegram[.]org/bot' + '/sendDocument'；动态 DNS 记录 ipify→telegram→catbox→gofile→0x0.st
> 
> **来源**：`ref:87dad7b966` · `ref:8a81869bf1` · `ref:6e61490618`

### 12. 写入Run键持久化

`T1547.001` · 置信度 **中** · 静态

把经 base64+XOR 混淆的 PowerShell 载荷与剪贴板劫持脚本落到隐藏目录，生成 .vbs 启动器并 attrib +h +s，注册 HKCU\...\Run\<随机名>=wscript.exe <vbs>，实现用户级开机自启。

> **证据**：run_clipper/install_dir/vbs_content/reg_cmds；'attrib +h +s'、'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'、'wscript.exe'
> 
> **来源**：`ref:8a81869bf1`

### 13. 剪贴板替换钱包地址

`T1115` · 置信度 **高** · 静态

PowerShell 死循环每 500ms 读取剪贴板，按正则识别 BTC/ETH/LTC/USDT/SOL/XRP/TON/DOGE/ADA/XLM/BCH 地址并替换为攻击者地址，同时以隐藏窗口、高优先级/后台线程方式维持运行。

> **证据**：内嵌 PowerShell 中 $addy 地址表与 while($true){[System.Windows.Forms.Clipboard]::GetText} 替换循环；$beacon 通过 [scriptblock]::Create 执行
> 
> **来源**：`ref:8a81869bf1`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| telegram | `hxxps://api[.]telegram[.]org/bot8896670610:AAEk0SFei5wIZex0ZYUs4f5-pfzcAmvfpw/sendDocument` | 443 | exfil | 静态 | ⏳ 未观测 |
| telegram | `hxxps://api[.]telegram[.]org/bot<token>/sendMessage（聊天 ID 8593010908）` | 443 | panel | 静态 | — |
| http | `hxxps://catbox[.]moe/user/api[.]php` | 443 | exfil | 静态 | ⏳ 未观测 |
| http | `hxxps://upload[.]gofile[.]io/uploadFile（含 api[.]gofile[.]io/servers 选址）` | 443 | exfil | 静态 | ⏳ 未观测 |
| http | `hxxps://0x0[.]st` | 443 | exfil | 静态 | ⏳ 未观测 |
| http | `hxxps://api[.]ipify[.]org?format=json / hxxps://httpbin[.]org/ip / hxxps://api[.]myip[.]com` | 443 | other | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `%LOCALAPPDATA%\Bunny\<MM-DD-YY_HH-MM-SS>\ （窃取数据暂存目录，含 Zip、NameFile.zip）`
- `%LOCALAPPDATA%\Bunny\<timestamp>\Screenshot.png（PowerShell CopyFromScreen 截屏）`
- `%LOCALAPPDATA%\Bunny\<timestamp>\Passwords.txt / Cookies.txt / Autofills.txt / Credit Cards.txt / History.txt / Wallets.txt（明文窃取结果）`
- `%LOCALAPPDATA%\Bunny\<timestamp>\<随机名>.vbs（隐藏属性的持久化启动器，attrib +h +s）`
- `%LOCALAPPDATA%\Bunny\<timestamp>\<随机名>.ps1（PowerShell 载荷/剪贴板劫持脚本）`
- `%APPDATA%\discord\Local Storage\leveldb\（Discord 令牌来源）`
- `%APPDATA%\Telegram Desktop\tdata\（Telegram 会话数据来源）`

**注册表**

- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\<随机名> = wscript.exe "%LOCALAPPDATA%\Bunny\<...>\<随机名>.vbs"`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `api[.]telegram[.]org（Bot API），备用图床 catbox.moe / gofile[.]io / 0x0.st` | 是 | 静态 |
| `telegram_bot_token` | `8896670610:AAEk0SFei5wIZex0ZYUs4f5-pfzcAmvfpw` | 是 | 静态 |
| `telegram_chat_id` | `8593010908` | 是 | 静态 |
| `install_path` | `%LOCALAPPDATA%\Bunny\<timestamp>\` | 否 | 静态 |
| `persistence` | `HKCU\...\CurrentVersion\Run 指向隐藏 .vbs（wscript.exe 拉起 powershell -w hidden -ExecutionPolicy Bypass -File <ps1>）` | 否 | 静态 |
| `encryption_algo` | `DPAPI(CryptUnprotectData) + AES-256-GCM(Chrome v10) + ChaCha20-Poly1305(App-Bound v20) + 3DES/AES-CBC(NSS key4.db)` | 否 | 静态 |
| `campaign_id` | `Telegram:Dark-Stealer @DarkStealer404 / t.me/DarkStealer404 \| @Bo2o444` | 否 | 静态 |
| `clipper_addresses` | `BTC bc1qfpt6ljm7j2edsjn6f8aqst9qu6x55dgyfz30hw; ETH/BNB/SHIB/PEPE 0x8e977c00EfeF0e3C9a044C0641e2648F7731425d; LTC ltc1qfcrpmxw742lcef435526lwdqynt8ersmt4yha7; USDT/TRX TUCra7c48byL4xHfZWnXgmJDuPw9upTPz2; SOL 5EWvLKWj66rsVwdoUjTygujjSfusEXfTRbhvS5TBi1My` | 否 | 静态 |
| `ip_check_services` | `api[.]ipify[.]org, httpbin[.]org/ip, api[.]myip[.]com` | 否 | 静态 |
| `work_time` | `WorkTime / WorkName 运行时段与主机名画像字段` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不要把 181.214.153[.]11 当作 C2：它与 'AppOnFly-VPS'、'vboxuser'、'BEE7370C-8C0C-4...' 等处同处反沙箱黑名单数据段，属被检测的托管环境特征，而非回连目标。
- 不要报 ransomware/wiper：样本对用户文件只读+复制，未见加密、删除或破坏性写入；pycryptodome 的 AES/ChaCha20 仅用于解密浏览器与 NSS 密钥库。
- 不要报 RAT/backdoor：未见键盘记录、屏幕远控、任意命令下发或交互式反向 shell；PowerShell 载荷为本地剪贴板劫持与自启动，非远控通道。
- 不要报 worm/横向移动：未见 USB 传播、SMB/PsExec/WMI 横向或域内探测代码。
- 不要报 miner：无矿池地址、Stratum 协议或挖矿库痕迹。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析 + 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 动态阶段只观测到 DNS 解析与上传请求被假网接收，未取得 Telegram 服务端返回内容，也没有在内存转储中提取到明文凭据；故未见凭据密文本身。
2. 持久化（隐藏 VBS + HKCU Run 键）与剪贴板劫持子载荷为静态还原，动态窗口内未捕获对应注册表写入与 PowerShell 进程事件，需在更长观测窗或专门监控下复核。
3. 沙箱客体启用了隐蔽化配置，样本的反虚拟机判定未触发退出，但这不代表其在普通 vmware/virtualbox 环境中同样会执行。
4. 家族名为样本自述品牌（输出文件版权串），未与厂商引擎/YARA 规则交叉验证，别名可能存在出入。
5. 未联网核对 Telegram Bot token / 聊天 ID 的有效性与归属，相关值仅按样本内嵌字符串如实呈现。

## 证据索引

<details>
<summary>展开 13 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 哈希与指纹 | sha256=75f88ea2…9422c，md5=dd5d790644ef62d0ce238067fedbac55，size=34027016 |
| `ev-000002` | scan.imphash | imphash=e3e80a143805ea18936c8f612e25d363 |
| `ev-000003` | scan.rich | Rich header 11 条工具链记录，richhash=a5ab84cd6b0f32306530937074b2749c |
| `ev-000004` | scan.entropy | .text 熵 6.486（低熵，未加壳） |
| `ev-000018` | 字符串提取 | ascii 9394 条 / utf16 113 条；无真实 flag 命中 |
| `ref:177b341c3e` | PE 结构解析 | PE32+ AMD64 GUI，7 段，entry rva 59248，image 708608，无异常 |
| `ref:80fe281c4a` | 导入表解析 | 5 个 DLL /150 符号：CreateToolhelp32Snapshot/Process32FirstW、CreateProcessW、GetTokenInformation、VirtualProtect、GetProcAddress |
| `ref:ea346b8ffc` | script(extract) | 定位 PyInstaller cookie（距文件尾 88 字节，pyver=311，pylib=python311.dll），解出 CArchive 83 个条目及入口脚本 sys_core_a24e56c0(28296462B) |
| `ref:8a81869bf1` | script(strings) | 入口脚本可读常量：Telegram bot token/chat id、catbox/gofile/0x0.st、App-Bound 解密常量、黑名单列表、钱包扩展 ID 表、内嵌 PowerShell 剪贴板劫持脚本 |
| `ref:418a6c8e26` | script(strings) | get_passwords/get_app_bound_key/get_cookie/getKey/get_credit_cards 等函数名与 SQL、DPAPI/NCrypt/ChaCha20-Poly1305 调用串 |
| `ref:6e61490618` | 动态分析平台 | 真实引爆：pid 7456 启动并产生 6 份内存转储，时间线记录候选进程与回滚状态 |
| `ref:87dad7b966` | sandbox.watch(log) | 网络监控：07:07:21-33 解析 api[.]ipify[.]org/httpbin[.]org/api[.]myip[.]com；07:07:37 起反复 api[.]telegram[.]org；07:09:11-24 catbox.moe/upload[.]gofile[.]io/api[.]gofile[.]io/0x0.st |
| `ref:57180ad96d` | 字符串提取 | 原始 PE 字符串层：仅暴露引导器与资源，无 C2 明文（C2 全在压缩归档内） |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
