---
title: "恶意样本分析：VoidLink（ELF · elf · 6dcfe9f6）"
published: 2026-10-31
draft: false
description: "恶意（置信度中）：VoidLink · backdoor/stealer/rat · 难度 hard · 纯静态分析"
tags: ["VoidLink", "backdoor", "stealer", "rat", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **VoidLink**（存疑） · 置信度 **中**
> 
> 别名：VoidLink Implant v3.0、vl、VoidLink C2 beacon
> 
> 只读静态证据显示该 ELF 具备 C2 心跳、内存 ELF 插件加载、内核模块级网络/进程隐藏、凭证窃取与痕迹清理能力，并自标识为 VoidLink Implant Core v3.0；样本未执行，判定基于嵌入配置字符串、内嵌内核模块源码与程序头结构。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **VoidLink** · 别名 VoidLink Implant v3.0、vl、VoidLink C2 beacon · _存疑_ |
| 置信度 | **中** |
| 行为类 | backdoor · stealer · rat |
| 难度 | hard |
| 首次出现 | 2026-10-30 12:34:43 |
| 分析方法 | 纯静态分析 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/6dcfe9f66d3aef1efd7007c588a59f69e5cd61b7a8eca1fb89a84b8ccef13a2b/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">伪装静态资源外联</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">内存加载ELF插件</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">植入内核模块隐藏</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1014</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">eBPF隐藏监听端口</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1014</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">窃取SSH与云凭证</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1552.001, T1552.005</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `6dcfe9f66d3aef1efd7007c588a59f69e5cd61b7a8eca1fb89a84b8ccef13a2b` |
| MD5 | _未记录_ |
| 大小 | 1,048,576 字节（1.0 MB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **12** 条行为，每条都挂了证据，且全部静态可得。

### 1. 伪装静态资源外联

`T1071.001` · 置信度 **高** · 静态

以 HTTP POST /api/v2/sync、/api/v2/heartbeat 与 /api/v1/sessions/{uuid} 作为心跳/任务通道，并借用 /static/js/app.{hash}.js、_ga Cookie 等前端资源样式伪装业务流量。

> **证据**：0x226a2 "POST /api/v2/sync HTTP/1.1"; 0xf4397 "/api/v1/sessions/{uuid}"; 0xdfc28 "/static/js/app."; 0xdfb2e "[BEACON] Encrypting request..."
> 
> **来源**：`ev-000011` · `ev-000003`

### 2. 内存加载ELF插件

`T1129` · 置信度 **高** · 静态

从 C2 任务接收 base64 编码的 ELF 插件，自实现 ELF 头/节表/重定位解析与 mmap 链接后直接调用入口，扩展命令执行、持久化、逃逸等能力。

> **证据**：0xec590 "[PLUGIN_EXEC] ERROR: Invalid ELF magic"; 0xed218 "[ELF_LINKER] load: data.len="; 0xf0a25 "[RELOC] Total relocations"; 0xeb885 "Plugin loaded successfully"
> 
> **来源**：`ev-000011` · `ev-000003`

### 3. 植入内核模块隐藏

`T1014` · 置信度 **高** · 静态

内嵌可编译的 LKM 源码 vl_stealth.ko，注册 tcp4_seq_show/udp4_seq_show/sock_diag 的 kretprobe，按端口/进程/文件名前缀隐藏网络连接、进程与文件。

> **证据**：0xfb610 "// 3.x Full Stealth Module - C2 Integration Version"; 0xfbe40 "static struct kretprobe tcp4_krp..."; 0xff371 "strnstr(line_start, tcp4_seq_show"; 0xf5a6a "vl_stealth.ko"; 0xf8c04 hide_port/hide_pid/hide_file
> 
> **来源**：`ev-000011` · `ev-000003`

### 4. eBPF隐藏监听端口

`T1014` · 置信度 **中** · 静态

内嵌 eBPF 工具源码与 Makefile（sd_ss.bpf.c / sd_loader.c），在目标机编译加载后枚举并隐藏本机监听端口，端口列表落入 /tmp/.vl_ss_ports。

> **证据**：0xe6190 "detect://Makefile/ebpf/ebpf/sd_ss.bpf.c/ebpf/sd_loader.c"; 0xf50aa "/tmp/.vl_ss_ports"; 0xf823a "eBPF ss_loader failed"
> 
> **来源**：`ev-000011`

### 5. 窃取SSH与云凭证

`T1552.001, T1552.005` · 置信度 **高** · 静态

遍历 /root/.ssh 私钥、/.kube/config、/.aws/、/.git-credentials 及 shell 历史，并访问 169.254.169[.]254、metadata.google.internal、metadata[.]tencentyun[.]com、100.100.100[.]200 等云元数据接口获取临时凭证。

> **证据**：0xf8d00 "/root/.ssh/id_rsa"; 0xec590 "/.kube/config/.aws/"; 0xf8e41 "AWS_SECRET"; 0xfab08 "169.254.169[.]254"; 0xf630c "metadata.google.internal"; 0xf5fe9 "metadata[.]tencentyun[.]com"
> 
> **来源**：`ev-000011` · `ev-000003`

### 6. 导出TLS会话密钥

`T1552` · 置信度 **中** · 静态

读取进程/环境中的 CLIENT_RANDOM、CLIENT_TRAFFIC_SECRET、SERVER_TRAFFIC_SECRET、握手流量密钥等 TLS 会话材料，用于解密被监控主机的 TLS 通信。

> **证据**：0xf8e4c "CLIENT_TRAFFIC_SECRET"; 0xf8e62 "SERVER_TRAFFIC_SECRET"; 0xf8e78 "CLIENT_HANDSHAKE_TRAFFIC_SECRET"; 0xf8f76 "CLIENT_RANDOM"; 0xf5c19 "/proc/self/environ"
> 
> **来源**：`ev-000011`

### 7. 清理日志与历史

`T1070.003, T1070.004` · 置信度 **高** · 静态

清除 /var/log/secure、auth.log、messages、wtmp/lastlog 等日志，删除各 shell 历史文件，并设置 HISTFILE=/dev/null、HISTSIZE=0 抑制后续命令记录。

> **证据**：0xf6dc6 "/var/log/secure"; 0xf6626 "/var/log/auth.log"; 0xf9078 "export HISTFILE=/dev/null"; 0xf46ea "/root/.zsh_history"; 0xf471d "/root/.bash_history"
> 
> **来源**：`ev-000011` · `ev-000003`

### 8. 插件化持久化与逃逸

`T1543.002, T1574.006, T1611` · 置信度 **中** · 静态

通过 plugin_load 下发 cron_persist_v3、systemd_persist_v3、ld_preload_v3 建立持久化，或以 docker_escape_v3、k8s_privesc_v3 尝试容器逃逸；插件名称由 C2 任务指定。

> **证据**：0xfb14e "persist plugin (cron_persist_v3/systemd_persist_v3/ld_preload_v3)"; 0xfb1ae "escape plugin (docker_escape_v3/k8s_privesc_v3)"; 0xf6025 "/etc/systemd/system"; 0xf8b26 "/etc/cron.d"
> 
> **来源**：`ev-000011`

### 9. 反调试与完整性校验

`T1622, T1027` · 置信度 **中** · 静态

初始化 debugger_detector、integrity_checker、secure_allocator 与 smc_engine 等模块，进行调试器探测、内存完整性与自修改代码保护。

> **证据**：0xf54f1 "debugger_detector"; 0xf7c2c "integrity_checker initialized"; 0xf7d1a "smc_engine initialized"; 0xf5503 "secure_allocator"
> 
> **来源**：`ev-000011`

### 10. 伪装k8s容器资源

`T1036` · 置信度 **中** · 静态

检测 /.dockerenv、/proc/1/cgroup 与 k8s serviceaccount，启用 k8s_masquerade 并设置 cpu_limit、memory_limit_mb、network_limit_bps，将自身伪装为集群工作负载。

> **证据**：0xf4ae3 "/.dockerenv"; 0xf5941 "/proc/1/cgroup"; 0xe9a08 "k8s_masquerade"; 0xec520 "cpu_limit/memory_limit_mb/network_limit_bps"
> 
> **来源**：`ev-000011` · `ev-000003`

### 11. 远程Shell与文件操控

`T1059.004` · 置信度 **高** · 静态

通过 beacon_pty_start/beacon_pty_read/beacon_pty_write 建立交互式 PTY，配合 beacon_exec、beacon_file_read/write/append 与 beacon_chdir 实现远程命令执行和文件管理。

> **证据**：0xf4c4f "beacon_pty_start"; 0xf8a96 "beacon_pty_read"; 0xf8bce "beacon_exec"; 0xf6b3a "beacon_file_write"; 0xf64e7 "/bin/bash"
> 
> **来源**：`ev-000011`

### 12. 原始套接字隐蔽触发

`T1095` · 置信度 **中** · 静态

内置 Python 片段创建 SOCK_RAW/ICMP 套接字，使用固定 magic 0xC0DE 与 key 0x42 封装 cmd 与十六进制数据，构成独立于 HTTP 的隐蔽控制/触发通道。

> **证据**：0xfb1fe "s=socket.socket(socket.AF_INET,socket.SOCK_RAW,1); magic=0xC0DE; key=0x42; payload=struct.pack(>HBB,magic,cmd,key)+data"
> 
> **来源**：`ev-000011`


## IOC（已去武器化）

### 网络

:::note
**未恢复任何 C2 / 网络 IOC**（原因见文末「分析方法与局限」）。
:::

### 主机

**落地路径**

- `/tmp/.vl_config`
- `/tmp/.vl_cmd.sh`
- `/tmp/.vl_ss_ports`
- `/tmp/.vl_ss_loader`
- `/tmp/.vl_k3.ko`
- `/tmp/.vl_k4.ko`
- `/tmp/.vl_k5.ko`
- `/tmp/.vl_k6.ko`
- `/tmp/.vl_build`
- `/tmp/implant_debug.log`
- `/var/tmp/.vl_creds`
- `/dev/shm/.vl_creds`
- `/var/tmp/.vl_data`
- `/var/tmp/.vl_*`
- `/dev/shm/.vl_*`

**计划任务**

- `crontab 条目（由 cron_persist_v3 插件创建）`
- `systemd 服务（由 systemd_persist_v3 插件创建）`
- `/etc/rc.local 自启动项（持久化模块使用路径）`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_host` | `运行时下发，未内嵌；仅见 example[.]com / api[.]example[.]com 占位` | 是 | 动态 |
| `agent_id` | `运行时生成并由 C2 下发（JSON 字段 agent_id）` | 是 | 动态 |
| `public_key` | `32 字节 base64 公钥，由 C2 下发（"public key must be 32 bytes"）` | 是 | 动态 |
| `encryption_algo` | `AES-256-GCM；另有 ChaCha20/Salsa20 "expand 32-byte k" 常量与 TLS 1.3 客户端实现` | 是 | 静态 |
| `beacon_sleep_ms` | `心跳间隔（毫秒），可被 C2 调整` | 是 | 静态 |
| `min_delay_ms` | `抖动下限` | 否 | 静态 |
| `max_delay_ms` | `抖动上限` | 否 | 静态 |
| `heartbeat_mode` | `aggressive / human_like / low_activity` | 否 | 静态 |
| `working_hours` | `工作时段限制（enable_grease、work_start_hour、work_end_hour、timezone_offset）` | 否 | 静态 |
| `max_ops_per_hour` | `每小时操作上限` | 否 | 静态 |
| `camouflage` | `http_camouflage / http_full_camouflage / tls_camouflage / k8s_masquerade` | 是 | 静态 |
| `persistence_plugins` | `cron_persist_v3 / systemd_persist_v3 / ld_preload_v3` | 否 | 静态 |
| `container_plugins` | `docker_escape_v3 / k8s_privesc_v3 / timestomp_v3` | 否 | 静态 |
| `config_path` | `/tmp/.vl_config` | 否 | 静态 |
| `lkm_module` | `vl_stealth.ko / stealth_netstat.ko` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 样本内出现 AES/SHA/MD5/CRC32/base64 常量，属于 TLS、哈希与编码的通用实现，不能据此判定为勒索软件或加密器。
- 样本未内嵌可用的 C2 地址，只有 example[.]com/api[.]example[.]com 占位；不能把任何具体 IP 或域名认定为该样本的 C2。
- 插件名称 cron_persist_v3、ld_preload_v3、docker_escape_v3 等仅说明能力入口存在，不等于样本已在本机完成持久化或容器逃逸。
- 文件的可执行段与入口地址均位于文件尾之外，缺少机器码；不能依据静态结果断言具体注入、提权或反调试实现细节。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 纯静态分析 |
| 脱壳 | 否 |

**局限与待验证**

1. 样本在 0x100000 处被截断：含代码的 PT_LOAD（文件偏移 1225824，大小 745230）与入口点 1229920 均超出文件尾，无法反汇编或仿真执行，功能结论来自嵌入字符串/源码与结构。
2. 未获得任何明文 C2 主机、端口或 agent_id；配置由运行时 /tmp/.vl_config 或 C2 下发，无法在静态阶段恢复。
3. 家族名来自样本自标识字符串 VoidLink Implant Core v3.0，缺少外部引擎/公开报告的交叉印证，故标记为不确定候选。
4. LKM 与 eBPF 相关结论来自内嵌源码文本，未在实际内核上编译或加载验证。
5. 样本未真实引爆，reproduced=false；所有行为均为静态可判定能力，不代表已在宿主执行。

## 证据索引

<details>
<summary>展开 13 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000003` | 字符串提取 | 抽取 3364 条 ASCII 字符串，命中 C2 端点、beacon_* API、插件与凭证路径 |
| `ev-000004` | 密码学常量识别 | AES S-box @0xeabc0 |
| `ev-000005` | 密码学常量识别 | SHA-256 初始常量 @0xdf8e0 |
| `ev-000006` | 密码学常量识别 | SHA-1 初始常量 @0xeab60 |
| `ev-000007` | 密码学常量识别 | MD5 初始常量 @0xeab60 |
| `ev-000008` | 密码学常量识别 | CRC32 多项式 @0xe5ce0 |
| `ev-000009` | 密码学常量识别 | CRC32 查表项 @0xe5ae4 |
| `ev-000010` | 密码学常量识别 | 标准 base64 字母表 @0x4e7c |
| `ref:4043c06c82` | ELF 结构解析 | ELF64 x86-64 EXEC，入口 1229920，无节表/符号/导入，shdr 越界 |
| `ref:cb886c8897` | scan.entropy | 整体熵 7.307，存在高熵嵌入数据 |
| `ref:d0fd262e6f` | elf.sections | 仅程序头，sections 为空 |
| `ev-000011` | evidence.record | 只读字符串偏移映射：VoidLink 自标识、C2 端点、插件 ABI、LKM/eBPF 源码、凭证与 TLS 密钥 |
| `ev-000012` | evidence.record | 布局核对：代码段与入口均在 EOF 之外，样本被截断 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
