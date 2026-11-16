---
title: "恶意样本分析：Go 语言 SSH/PAM 挖矿僵尸网络（systemd-worker）（ELF · elf · 11707e39）"
published: 2026-11-15
draft: false
description: "恶意（置信度中）：Go 语言 SSH/PAM 挖矿僵尸网络（systemd-worker） · botnet/miner/backdoor · 难度 hard · 纯静态分析"
tags: ["语言 SSH", "botnet", "miner", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Go 语言 SSH/PAM 挖矿僵尸网络（systemd-worker）**（存疑） · 置信度 **中**
> 
> 别名：systemd-worker miner bot、Go P2P miner bot
> 
> 样本是一个用 Go 编写、链接 libpam 的 x86-64 ELF。二进制中可直接取证到：Discord webhook 外传地址与 {"content":...} 负载格式、systemd 服务自安装（/bin/systemd-worker、/lib/systemd/system/systemd-worker.service、systemctl enable systemd-worker.service）、0.0.0[.]0:22 的 SSH/PAM 远程登录服务、XMRig/NBMiner 矿池预设字段、attackqueue 凭据队列、P2P 指令 sharepeer/sharerigconfig/shareupdateinfo，以及虚拟化环境检测和公网出口 IP 探测。这些能力组合在一起没有正当用途。C2 对端与矿池地址属运行期下发，未获得成功仿真，因此动态行为未观测，结论全部来自静态反编译与字节级取证。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Go 语言 SSH/PAM 挖矿僵尸网络（systemd-worker）** · 别名 systemd-worker miner bot、Go P2P miner bot · _存疑_ |
| 置信度 | **中** |
| 行为类 | botnet · miner · backdoor |
| 难度 | hard |
| 首次出现 | 2026-11-12 16:54:03 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/11707e3902992c8e20e19de09cbc78381e43234c4560a706a031fe01ce7e96fb/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">安装为系统服务</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">开放 SSH 后门</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1133</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">收集 SSH 凭据</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1078</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">横向爆破 SSH</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1110.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">共享对等配置</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `11707e3902992c8e20e19de09cbc78381e43234c4560a706a031fe01ce7e96fb` |
| MD5 | _未记录_ |
| 大小 | 3,637,248 字节（3.5 MB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **11** 条行为，每条都挂了证据，且全部静态可得。

### 1. 安装为系统服务

`T1543.002` · 置信度 **高** · 静态

把自身落地为 /bin/systemd-worker，写入 /lib/systemd/system/systemd-worker.service（ExecStart=/bin/systemd-worker，WantedBy=multi-user.target），并执行 systemctl enable systemd-worker.service 实现开机自启与进程常驻。

> **证据**：文件偏移 0x349473 字面量 /bin/systemd-worker；0x35410a 字面量 /lib/systemd/system/systemd-worker.service；0x34e26e 含 ExecStart=/bin/systemd-worker；0x35219d 含 [Install] WantedBy=multi-user.target；0x359590 含 service systemd-worker enable || systemctl enable systemd-worker.service
> 
> **来源**：`ref:fb062e220c` · `ref:e500dc17ff`

### 2. 开放 SSH 后门

`T1133` · 置信度 **高** · 静态

以 0.0.0[.]0:22 监听 SSH，读取 /etc/ssh/ssh_host_rsa_key、ssh_host_ecdsa_key、ssh_host_ed25519_key 作为主机密钥，调用 libpam 的 pam_authenticate 做系统口令认证，并支持 PTY 与 SFTP 会话，等于在受害主机上长期保留一个可登录的远程入口。

> **证据**：0x345fb5 字面量 0.0.0[.]0:22（VA 0x745fb5）；导入表 0x1439 libpam.so.0 与 0x1ce3 _cgo_eba3282b571c_Cfunc_pam_authenticate；0x34c215/0x34d0f1/0x34e225 SSH 主机密钥路径；类型表 0x2c6135 *pam.Style 与 RequestPty
> 
> **来源**：`ref:0339085ba8` · `ref:3abe169092` · `ev-000003`

### 3. 收集 SSH 凭据

`T1078` · 置信度 **高** · 静态

定义 credential 结构与 attackqueue 队列，字段为 ip、username、password、privatekey，把登录成功或抓取到的 SSH 主机、账号、口令、私钥集中排队，供后续横向复用。

> **证据**：0x2d7473 类型元数据 '*struct { F uintptr; attackqueue *[]main.credential }'；0x2ed41f 闭包结构 '{ privatekey string; username string; ip string; password string }'；0x2cd369 '*main._rig_config'
> 
> **来源**：`ref:82600ab013` · `ref:fb062e220c` · `ref:28a2c2a72c`

### 4. 横向爆破 SSH

`T1110.001` · 置信度 **中** · 静态

内置 admin/root/passwd/qwerty/123456/a123456/ubuntu/centos 等用户名与弱口令候选，配合 SSH 客户端、known_hosts 与 id_rsa 处理逻辑，对可达 SSH 服务逐一尝试登录，成功凭据回填 attackqueue。

> **证据**：0x3444a0-0x344604 短字符串区含 admin、passwd、qwerty、root、id_rsa、known_hosts、a123456、ubuntu、centos 等；0x3533e3 'username/password authentication failed'；0x2c6d4d privatekey 字段名
> 
> **来源**：`ref:fb062e220c` · `ref:64820a9cf0` · `ref:e500dc17ff`

### 5. 共享对等配置

`T1071` · 置信度 **高** · 静态

用 ^(sharepeer)(\s)(.*)$、^(sharerigconfig)(\s)([A-Za-z0-9+=\/]+)$、^(shareupdateinfo)(\s)([A-Za-z0-9+=\/]+)$ 三条正则解析控制指令，在对等节点间共享对端信息、矿机配置与更新信息，形成去中心化控制面。

> **证据**：0x35357f 正则 ^(sharerigconfig)...；0x353c14 正则 ^(shareupdateinfo)...；0x34a491 正则 ^(sharepeer)(\s)(.*)$
> 
> **来源**：`ref:47ce4eadd7` · `ref:fb062e220c`

### 6. 下发矿工挖矿

`T1496` · 置信度 **高** · 静态

配置结构包含 xmrig/nbminer 的 enabled、nicehash、algo、poolAddr、poolUser、poolPass 以及 downloadURL、checksum，用于下载并启动矿工程序、连接矿池消耗受害主机 CPU 算力。

> **证据**：0x2d5825 json 标签 Xmrig_nicehash/Xmrig_poolAddr/Xmrig_poolPass/Xmrig_poolUser；0x2d6099 Nbminer_poolAddr/Nbminer_poolPass；0x2d474f DownloadURL json:"downloadURL"、Checksum json:"checksum"；0x2d43b5 current_preset_xmrig_poolAddr
> 
> **来源**：`ref:99381340aa` · `ref:47ce4eadd7`

### 7. Discord 外传数据

`T1567.002` · 置信度 **高** · 静态

内置 Discord webhook URL，并用 '{"content": "..."}' 形式构造 HTTP 请求体，把受害主机信息与外传内容提交到 discord[.]com/api/webhooks/<id>/<token>。

> **证据**：0x35a713 字面量 hxxps://discord[.]com/api/webhooks/960954050583613549/YAk...（VA 0x75a713）；0x35134c 负载格式 '{\n"content": "'
> 
> **来源**：`ref:df4258af15` · `ref:99381340aa`

### 8. 探测公网出口 IP

`T1016` · 置信度 **高** · 静态

依次请求 hxxp://ipgrab[.]io/、hxxps://ident[.]me/、hxxp://ipinfo[.]io/ip、hxxps://api[.]ipify[.]org、hxxp://inet-ip[.]info/ip、hxxps://checkip[.]amazonaws[.]com、hxxps://ip[.]seeip[.]org/ 等外部回显服务获取出口 IP，用于上报、去重与节点发现。

> **证据**：0x348a51 hxxp://ipgrab[.]io/ 与 hxxps://ident[.]me/；0x349837 hxxp://ipinfo[.]io/ip；0x34a66c hxxps://ip[.]seeip[.]org/；0x34ada3 hxxp://inet-ip[.]info/ip 与 hxxps://api[.]ipify[.]org；0x34ed73 hxxps://checkip[.]amazonaws[.]com
> 
> **来源**：`ref:23e0fbad7d` · `ref:fb062e220c`

### 9. 检测虚拟化环境

`T1497.001` · 置信度 **中** · 静态

内置 vmware、vboxdrv、vboxguest、qemu、xen、kvm、openvz、docker、lxc、virtio-pci、/proc/self/status 等检测线索，判断是否运行在虚拟机或容器中，以便改变行为或规避分析环境。

> **证据**：0x344ed8 附近字面量 vmware/virtualbox；0x345379 vboxdrv/vboxguest；0x345932 /dev/ptmx、/dev/pts/0；0x346433 virtio-pci；0xac0f8 /etc/loc…（locale 路径片段）
> 
> **来源**：`ref:fb062e220c` · `ref:64820a9cf0`

### 10. 终止竞争挖矿进程

`T1489` · 置信度 **中** · 静态

构造 kill -9 $(lsof -t -i:<port>) 一类 shell 命令，借助 os/exec 终止占用目标端口或资源的竞争进程，为自身矿工与后门让路。

> **证据**：0x34a6f4 字面量 kill -9 $(lsof -t -i:；0x2c34ec os/exec 包名；0x3467f3 chmod +x ./；0x345192 nohup ./p
> 
> **来源**：`ref:fb062e220c` · `ref:64820a9cf0`

### 11. 隐藏临时目录暂存

`T1074.001` · 置信度 **高** · 静态

使用点号开头的 /tmp/.jpec 作为临时工作目录暂存组件与中间文件，降低在 /tmp 中被人工发现概率。

> **证据**：0x34a3e1 字面量 /tmp/.jpec（位于 0x34a3e7 起）；同一字符串区含 chmod +x ./ 与 nohup ./p
> 
> **来源**：`ref:e500dc17ff` · `ref:fb062e220c`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://discord[.]com/api/webhooks/960954050583613549/YAkGomn5eYtrPChuOPz87pIkS7WK2XpB5Y3ozZQXaAho2VCBN99g7k9oqSAPJ9Ji7bTr` | 443 | exfil | 静态 | ⏳ 未观测 |
| other | `P2P 对等控制通道（sharepeer / sharerigconfig / shareupdateinfo 指令，节点地址运行期下发，样本内无固定端点）` | - | c2 | 静态 | ⏳ 未观测 |

### 主机

**落地路径**

- `/bin/systemd-worker`
- `/lib/systemd/system/systemd-worker.service`
- `/tmp/.jpec`
- `/etc/ssh/ssh_host_rsa_key`
- `/etc/ssh/ssh_host_ecdsa_key`
- `/etc/ssh/ssh_host_ed25519_key`

**服务**

- `systemd-worker`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `exfil_webhook` | `hxxps://discord[.]com/api/webhooks/960954050583613549/YAkGomn5eYtrPChuOPz87pIkS7WK2XpB5Y3ozZQXaAho2VCBN99g7k9oqSAPJ9Ji7bTr` | 是 | 静态 |
| `exfil_payload_format` | `{"content": "..."}（Discord webhook 文本负载，见字面量 '{\n"content": "'）` | 是 | 静态 |
| `c2_hosts` | `P2P 对等节点；通过 sharepeer/sharerigconfig/shareupdateinfo 指令交换对端、矿机配置与更新信息，地址运行期下发` | 是 | 静态 |
| `remote_access_listen` | `0.0.0[.]0:22` | 是 | 静态 |
| `install_path` | `/bin/systemd-worker` | 是 | 静态 |
| `service_unit_path` | `/lib/systemd/system/systemd-worker.service` | 是 | 静态 |
| `service_name` | `systemd-worker` | 是 | 静态 |
| `work_dir` | `/tmp/.jpec` | 否 | 静态 |
| `miner_presets` | `xmrig_{enabled,nicehash,algo,poolAddr,poolUser,poolPass} 与 nbminer_{enabled,algo,poolAddr,poolUser,poolPass}` | 是 | 静态 |
| `update` | `downloadURL + checksum（更新载荷下载地址与校验值运行期下发）` | 否 | 静态 |
| `credential_queue` | `attackqueue: {ip, username, password, privatekey}` | 是 | 静态 |
| `encryption_algo` | `无自定义加密；仅标准 base64/base36 编码与 SSH 内建加密（未见自定义 AES 常量或勒索加密逻辑）` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不能因 crypto/aes 包与 base64 常量就判定样本对文件或配置做加密勒索：样本仅使用标准库的 SSH 加密与 base64/base36 编码，未见勒索文件操作或自定义 AES 实现。
- 不能把内置 Discord webhook 当作唯一命令通道：它承担外传/上报，命令面是运行期 P2P 配置（sharepeer/sharerigconfig/shareupdateinfo），样本内没有固定 C2 主机。
- 不能仅凭 /bin/systemd-worker 与 0.0.0[.]0:22 断言受害主机上已创建服务或已监听端口：静态只证明代码具备该能力，本次未获得任何运行期行为。
- 不能把文件头附近的 88 字符 base64 串（TegskTGfBzL5...）当作硬编码密钥：解码结果为 Go build ID（.note.go.buildid）。
- 不能断言样本已实际挖矿或已与矿池通信：矿池地址、downloadURL 与 checksum 均为运行期下发，样本内无明文矿池端点。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 文件截断导致能力面不完全：e_shoff=0x1ce6018 越界，节头数为 35 但节表缺失；只读段声明 27 MB、实际仅约 0.75 MB 可读，写段与 DYNAMIC 缺失，符号表为空，无法恢复完整导入表与函数边界。
2. 无真实动态证据：按分析规范未在真机执行该 ELF；仿真执行尝试返回空结果，未观测到任何运行期行为，因此 c2/config 全部标记为 recoverability=static 且 pending_dynamic_verify=true。
3. 家族归因不确定：缺少多引擎、YARA 或公开报告交叉印证，族名是按能力与内部命名给出的候选（uncertain=true），不代表已有厂商命名。
4. 矿工二进制、矿池地址、downloadURL/checksum 的具体值不可得：只见到配置字段与下发逻辑，实际载荷未随样本提供。
5. 字符串扫描命中的 'shusvz{}|0|1}' 与 'uint64unuseduptimevmwarewaitid{hash}' 是 Go 短字符串拼接产物，不是真实 flag 或凭据。
6. 主机痕迹字段中的 mutex/registry/tasks 为空，是因为这是 Linux ELF 且未执行，不能据此排除运行期存在互斥量或 cron 行为。
7. 字符串 'Please type "I am human" to prove that you are human:' 的用途无法静态确认，未计入行为结论。

## 证据索引

<details>
<summary>展开 20 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | flag 形态命中 shusvz{}\|0\|1} @0x3443d8，经核对为 Go 短字符串拼接产物 |
| `ev-000002` | 字符串提取 | flag 形态命中 uint64unuseduptimevmwarewaitid{hash} @0x344f86，为 Go 字符串表拼接产物 |
| `ev-000003` | 字符串提取 | 抽取 9624 条 ASCII 字符串；确认 libpam/libpthread/libc 导入与 PAM、pthread 相关符号 |
| `ev-000004` | 密码学常量识别 | CRC32 IEEE 常量 @0x1e82d4 |
| `ev-000005` | 密码学常量识别 | 标准 base64 字母表 @0x358b7a |
| `ev-000006` | 密码学常量识别 | URL-safe base64 字母表 @0x358bba；未发现 AES/SHA 自定义实现常量 |
| `ref:4d83efb0e8` | ELF 结构解析 | ELF64 x86-64 EXEC，入口 RVA 13424/VA 4207728，链接 libpam.so.0 与 libc.so.6，12 个程序头，节表越界 |
| `ref:3abe169092` | decompile.symbols | 符号被裁剪，仅恢复 909 个匿名函数（FUN_*），可见 libpam/PAM 相关 cgo 符号 |
| `ref:97128bc087` | 自定义字符串提取 | Go 依赖路径：github[.]com/msteinert/pam、github[.]com/pkg/sftp、github[.]com/shirou/gopsutil/{cpu,net,process}、golang[.]org/x/crypto/ssh、golang[.]org/x/term |
| `ref:28a2c2a72c` | 自定义字符串提取 | 主包类型名 main._rig_config、main._update、main.credential |
| `ref:82600ab013` | 自定义字符串提取 | 类型元数据 attackqueue *[]main.credential，以及闭包字段 privatekey/username/ip/password |
| `ref:64820a9cf0` | 自定义字符串提取 | 导入符号串（libpam、pam_*、os/exec、ssh、password、sftp）与关键字上下文 |
| `ref:fb062e220c` | 自定义字符串提取 | 0x2e0000 之后字面量：/bin/systemd-worker、systemd unit、/tmp/.jpec、kill -9 $(lsof -t -i:、vmware/vbox、弱口令字典、chmod +x/nohup |
| `ref:23e0fbad7d` | 自定义字符串提取 | URL 与域名：ipgrab[.]io、ident[.]me、ipinfo[.]io、ipify[.]org、inet-ip[.]info、seeip[.]org、checkip[.]amazonaws[.]com |
| `ref:99381340aa` | 自定义字符串提取 | 46 个 JSON 标签（xmrig_*/nbminer_*/downloadURL/checksum 等）与 Discord webhook 字面量 |
| `ref:47ce4eadd7` | 自定义字符串提取 | sharepeer/sharerigconfig/shareupdateinfo 正则与 attack 队列/rig 配置上下文 |
| `ref:e500dc17ff` | 自定义字符串提取 | 0.0.0[.]0:22、SSH 主机密钥路径、systemd unit 结尾、/tmp/.jpec、短口令字典与 'I am human' 提示串 |
| `ref:df4258af15` | addr.translate | Discord webhook 字面量 off 0x35a713 → RVA 0x35a713 / VA 0x75a713 |
| `ref:0339085ba8` | addr.translate | 0.0.0[.]0:22 字面量 off 0x345fb5 → RVA 0x345fb5 / VA 0x745fb5 |
| `ref:957e447114` | 自定义头部解析 | .note.go.buildid 内 88 字符 base64 解码为 Go build ID；e_shnum=35、e_shoff 越界证实文件截断 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
