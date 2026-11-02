---
title: "恶意样本分析：Meterpreter（ELF · elf · 726cae68）"
published: 2026-11-01
draft: false
description: "恶意（置信度中）：Meterpreter · backdoor/loader/downloader · 难度 easy · 动态沙箱 + 静态反编译"
tags: ["Meterpreter", "backdoor", "loader", "downloader", "ELF"]
category: "恶意样本日报"
lang: "zh"
---

> [!WARNING]
> **判定：恶意** · 家族 **Meterpreter**（存疑） · 置信度 **中**
> 
> 别名：Metasploit linux/x86 stager、linux/x86/meterpreter/reverse_tcp stager、linux_i386_tcp stager
> 
> 反编译主函数完整还原出『单实例锁文件 → 硬编码地址的 TCP 反向连接 → 发送 l32 握手 → 接收并逐字节 XOR 0x99 解密阶段二 → memfd_create 匿名落地 → fexecve 以伪装进程名执行』的完整链路，并已被反汇编逐条地址核对。程序对本地用户没有任何可见功能输出，全部逻辑服务于远程载荷投递与执行，属远程控制载荷投递器/后门。

## 速览

| 项目 | 内容 |
|:--|:--|
| 家族 | **Meterpreter** · 别名 Metasploit linux/x86 stager、linux/x86/meterpreter/reverse_tcp stager、linux_i386_tcp stager · _存疑_ |
| 置信度 | **中** |
| 行为类 | backdoor · loader · downloader |
| 难度 | easy |
| 首次出现 | 2026-10-30 00:14:15 |
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 来源 | [MalwareBazaar](https://bazaar.abuse.ch/sample/726cae684af35571a565bbac17e09cd79beaa07afc036721635372b79b934b87/) |

## 攻击链

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="攻击链概览" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">锁文件防重复运行</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">硬编码 C2 与端口</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">失败每十秒重连</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">发送 l32 握手包</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">接收并异或解密</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">静态</text>
</svg>

## 样本标识

| 项目 | 值 |
|:--|:--|
| SHA-256 | `726cae684af35571a565bbac17e09cd79beaa07afc036721635372b79b934b87` |
| MD5 | _未记录_ |
| 大小 | 6,968 字节（6.8 KB） |
| 类型 | ELF · `elf` |

## 行为分析

共 **8** 条行为，每条都挂了证据，且全部静态可得。

### 1. 锁文件防重复运行

`T1480` · 置信度 **高** · 静态

程序启动即调用 access("/tmp/log_de.log",0)；若该文件已存在则立即 exit(0)，用固定路径锁实现单实例/防重复感染。

> **证据**：0x080486d7 call access@plt(0x8048630)，参数 0x08048a60="/tmp/log_de.log"；返回 0 时 0x080486e5 call exit@plt(0x80485c0)
> 
> **来源**：`ev-000002` · `ev-000001` · `ref:5ca1f4d12b`

### 2. 硬编码 C2 与端口

`T1095` · 置信度 **高** · 静态

内置远端地址 172.245.80[.]41 与端口 80：先用 rep movsb 把 0x08048a8c 处字符串拷到栈缓冲，gethostbyname 失败则回退 inet_addr；sockaddr_in 以 0x5000(网络序) 填入端口。

> **证据**：0x080486fa mov esi,0x08048a8c; 0x08048720 mov word [ebp-0x144a],0x5000(端口80); 0x08048763 socket(2,1,0); gethostbyname@0x8048650 / inet_addr@0x8048660
> 
> **来源**：`ev-000002` · `ev-000001` · `ref:ce4b30f8fc`

### 3. 失败每十秒重连

`T1095` · 置信度 **高** · 静态

connect 返回 -1 时无条件 sleep(10) 后重试，形成常驻重连；socket 另设 SO_KEEPALIVE(level 6/opt 7/10s)。

> **证据**：0x0804879d call connect@plt(0x8048670); 0x080487ad push 0xa; call sleep@plt(0x80485a0); setsockopt@0x08048790
> 
> **来源**：`ev-000002` · `ref:5ca1f4d12b`

### 4. 发送 l32 握手包

`T1095` · 置信度 **高** · 静态

连接建立后依次发送 6 字节 "l32 " 标识、2 字节端口、32 字节主机字符串，作为阶段一(下载器)向控制端的登记握手。

> **证据**：0x080487bb push 0x08048a70("l32 ")/push 6/call send@0x80486a0；0x080487e1 send 2 字节端口；0x080487f1 push 0x20 发送 32 字节主机串
> 
> **来源**：`ev-000002` · `ev-000001` · `ref:55b5536162`

### 5. 接收并异或解密

`T1140` · 置信度 **高** · 静态

循环 recv(0x1000) 收取阶段二数据块，对每个字节执行 XOR 0x99 解密后写入匿名文件描述符，直至对端关闭。

> **证据**：0x08048832 call recv@plt(0x8048680)；0x08048846 xor byte ptr [edx+ecx],0x99；0x08048859 call write@plt(0x8048610)
> 
> **来源**：`ev-000002` · `ref:55b5536162`

### 6. memfd 内存落地

`T1620` · 置信度 **高** · 静态

通过 syscall 0x164(i386 memfd_create) 以名称 "a" 创建匿名内存文件，作为阶段二的落地载体，磁盘上不留文件。

> **证据**：0x08048801 push 0x164; 0x08048806 push 0x08048a77("a"); call syscall@plt(0x8048620)
> 
> **来源**：`ev-000002` · `ref:ce4b30f8fc`

### 7. fexecve 执行载荷

`T1620` · 置信度 **高** · 静态

接收结束后清零 4KB 缓冲区、close(socket)，再以 argv=["[kworker/0:2]"] 和 environ 调用 fexecve，直接从 memfd 执行阶段二，原始文件名与入口不留痕。

> **证据**：0x080488c8 call fexecve@plt(0x80485e0)；0x080488b4 mov dword [ebp-0x1454],0x08048a7d("[kworker/0:2]")；0x0804888e call realpath
> 
> **来源**：`ev-000002` · `ev-000001` · `ref:55b5536162`

### 8. 伪装内核线程名

`T1036.005` · 置信度 **高** · 静态

执行载荷时把 argv[0] 设为 "[kworker/0:2]"，并用 realpath(argv[0]) 填充 CWD 环境变量后 setenv，使进程在进程列表中呈现为内核工作线程。

> **证据**：0x08048884 push [eax](argv[0]) 后 0x0804888e call realpath；0x0804889e push "CWD"(0x08048a79)/push 1/call setenv@0x80485f0
> 
> **来源**：`ev-000002` · `ev-000001` · `ref:55b5536162`


## IOC（已去武器化）

### 网络

:::caution
**待动态验证**：上述地址为静态分析所得，分析环境网络隔离下未观察到成功的连接或会话，真实 C2 的响应与下发内容仍未知。
:::

| 类型 | 值 | 端口 | 角色 | 证据来源 | 动态观测 |
|:--|:--|--:|:--|:--|:--|
| tcp | `172[.]245[.]80[.]41` | 80 | c2 | 静态 | ⏳ 未观测 |

### 主机

**互斥体**

- `/tmp/log_de.log（单实例锁文件，存在即退出）`

**落地路径**

- `/tmp/log_de.log`
- `memfd 名称 "a"（仅存在于进程内存，无磁盘路径）`

### 配置

| 键 | 值 | 必需 | 证据来源 |
|:--|:--|:--|:--|
| `c2_hosts` | `172[.]245[.]80[.]41` | 是 | 静态 |
| `c2_port` | `80` | 是 | 静态 |
| `stager_banner` | `"l32 "（6 字节，连接后首发）` | 是 | 静态 |
| `stage_transport` | `原始 TCP；握手 = l32 魔数 + 2 字节端口 + 32 字节主机串，之后为下行阶段二数据流` | 是 | 静态 |
| `encryption_algo` | `XOR 0x99（单字节循环异或，仅传输混淆，非强加密）` | 是 | 静态 |
| `install_path` | `无磁盘安装；阶段二驻留于 memfd 匿名文件（名称 "a"）` | 否 | 静态 |
| `instance_lock_file` | `/tmp/log_de.log` | 是 | 静态 |
| `memfd_name` | `a` | 是 | 静态 |
| `process_masquerade` | `[kworker/0:2]` | 否 | 静态 |
| `reconnect_interval_sec` | `10` | 否 | 静态 |

## 不应误判

:::important
以下结论**容易被误判**，引用本报告时请注意。

- 不得因样本含异或解密、下载与内存执行就判定为勒索软件或信息窃取程序：代码中没有文件加密、凭据/浏览器数据读取或勒索提示逻辑。
- 第二阶段载荷未被取得，不能断言其具体能力（是否提供交互式 shell、是否加载内核/用户态隐藏模块），只能确认存在『下载—解密—内存执行』的投递链路。
- 未发现 cron、systemd 单元、rc.local 或 shell 配置文件写入，不能断言具备持久化能力。
- 样本回连目标为裸 TCP 80 端口，不能仅凭端口号断言其为 HTTP 通信；实际协议是自定义握手加原始数据流。
:::

## 分析方法与局限

| 项目 | 内容 |
|:--|:--|
| 分析方法 | 动态沙箱分析（Linux 样本）+ 静态反编译 |
| 脱壳 | 否 |

**局限与待验证**

1. 两次运行尝试均在加载器阶段失败（缺少 /lib/ld-linux.so.2），未进入 main，未产生任何网络/文件行为可观测记录，因此 c2 仍为静态恢复且待动态复核。
2. 第二阶段载荷未知，其哈希、协议与后续能力无法给出。
3. 家族归属基于握手魔数 "l32 "、memfd+fexecve 装载形态与源文件名推断，为中等置信度候选，不排除被其他家族复用 stager 的可能。
4. 网络出口在分析环境内被隔离，无法验证回连目标当前是否存活。

## 证据索引

<details>
<summary>展开 9 条工具证据</summary>

| 证据 ID | 工具 | 摘要 |
|:--|:--|:--|
| `ev-000001` | 字符串提取 | 字符串抽取：/tmp/log_de.log、l32 、CWD、[kworker/0:2]、172.245.80[.]41（off 2656/2672/2681/2685/2700） |
| `ev-000002` | decompile.function | main@0x080486b0 反编译：锁文件、C2 连接、l32 握手、recv+XOR 0x99、memfd_create、fexecve 全链路 |
| `ref:5ca1f4d12b` | disasm.function | main 前段反汇编：access/exit、C2 字符串拷贝、端口 0x5000、socket/setsockopt/connect/sleep |
| `ref:55b5536162` | disasm.function | main 后段反汇编：send 握手、syscall 0x164、xor 0x99、realpath/setenv、fexecve |
| `ref:ce4b30f8fc` | static.bytes | rodata 原始字节核对：0x08048a60=/tmp/log_de.log、0x08048a70=l32 、0x08048a77=a、0x08048a79=CWD、0x08048a7d=[kworker/0:2]、0x08048a8c=172.245.80[.]41 |
| `ref:1287bc8ab5` | ELF 结构解析 | ELF32 i386 EXEC，入口 0x08048960，导入 socket/connect/send/recv/gethostbyname/inet_addr/fexecve/realpath/setenv/syscall/access/sleep |
| `ref:523c01432d` | 哈希与指纹 | sha256 与题面一致（6968 字节），md5 f1b1df04e7b4259431bc3735ba79745a |
| `ev-000004` | dyn.exec | 隔离实例执行失败：strace exec ./prog 返回 ENOENT（缺 32 位加载器），未进入程序 |
| `ev-000005` | emu.qemu | 用户态模拟同样因缺少 /lib/ld-linux.so.2 拒绝加载，exit=255 |

</details>

---

_本报告样本不公开，IOC 已去武器化，仅供安全研究。_
