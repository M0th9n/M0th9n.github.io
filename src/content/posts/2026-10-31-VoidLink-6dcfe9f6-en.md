---
title: "Malware Analysis: VoidLink (ELF · elf · 6dcfe9f6)"
published: 2026-10-31
draft: false
description: "Malicious (medium confidence): VoidLink · backdoor/stealer/rat · difficulty hard · pure static analysis"
tags: ["VoidLink", "backdoor", "stealer", "rat", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-31-VoidLink-6dcfe9f6"
---

> [!WARNING]
> **Verdict: malicious** · Family **VoidLink** (uncertain) · Confidence **medium**
> 
> Aliases: VoidLink Implant v3.0, vl, VoidLink C2 beacon
> 
> Read-only static evidence shows that this ELF has C2 heartbeat, in-memory ELF plugin loading, kernel-module-level network/process hiding, credential theft and anti-forensic cleanup capabilities, and self-identifies as VoidLink Implant Core v3.0; the sample was not executed, and the verdict is based on embedded configuration strings, embedded kernel module source and program header structure.

## Overview

| Item | Content |
|:--|:--|
| Family | **VoidLink** · aliases VoidLink Implant v3.0, vl, VoidLink C2 beacon · _uncertain_ |
| Confidence | **medium** |
| Behaviour class | backdoor · stealer · rat |
| Difficulty | hard |
| First seen | 2026-10-30 12:34:43 |
| Analysis method | pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/6dcfe9f66d3aef1efd7007c588a59f69e5cd61b7a8eca1fb89a84b8ccef13a2b/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">C2 over fake static assets</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Load ELF plugins in memory</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Kernel module hiding</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1014</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">eBPF hides listening ports</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1014</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Steal SSH and cloud creds</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1552.001, T1552.005</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `6dcfe9f66d3aef1efd7007c588a59f69e5cd61b7a8eca1fb89a84b8ccef13a2b` |
| MD5 | _not recorded_ |
| Size | 1,048,576 bytes (1.0 MB) |
| Type | ELF · `elf` |

## Behaviour analysis

**12** behaviours were recovered, each with supporting evidence, and all of them are static.

### 1. C2 over fake static assets

`T1071.001` · confidence **high** · static

Uses HTTP POST /api/v2/sync, /api/v2/heartbeat and /api/v1/sessions/{uuid} as the heartbeat/task channel, and borrows front-end resource styling such as /static/js/app.{hash}.js and the _ga Cookie to camouflage the traffic as business traffic.

> **Evidence**: 0x226a2 "POST /api/v2/sync HTTP/1.1"; 0xf4397 "/api/v1/sessions/{uuid}"; 0xdfc28 "/static/js/app."; 0xdfb2e "[BEACON] Encrypting request..."
> 
> **Source**: `ev-000011` · `ev-000003`

### 2. Load ELF plugins in memory

`T1129` · confidence **high** · static

Receives base64-encoded ELF plugins from C2 tasks, implements its own ELF header/section-table/relocation parsing and mmap-based linking, and then calls the entry point directly, extending capabilities such as command execution, persistence and escape.

> **Evidence**: 0xec590 "[PLUGIN_EXEC] ERROR: Invalid ELF magic"; 0xed218 "[ELF_LINKER] load: data.len="; 0xf0a25 "[RELOC] Total relocations"; 0xeb885 "Plugin loaded successfully"
> 
> **Source**: `ev-000011` · `ev-000003`

### 3. Kernel module hiding

`T1014` · confidence **high** · static

Embeds compilable LKM source vl_stealth.ko that registers kretprobes on tcp4_seq_show/udp4_seq_show/sock_diag and hides network connections, processes and files by port/process/filename prefix.

> **Evidence**: 0xfb610 "// 3.x Full Stealth Module - C2 Integration Version"; 0xfbe40 "static struct kretprobe tcp4_krp..."; 0xff371 "strnstr(line_start, tcp4_seq_show"; 0xf5a6a "vl_stealth.ko"; 0xf8c04 hide_port/hide_pid/hide_file
> 
> **Source**: `ev-000011` · `ev-000003`

### 4. eBPF hides listening ports

`T1014` · confidence **medium** · static

Embeds eBPF tool source and a Makefile (sd_ss.bpf.c / sd_loader.c); once compiled and loaded on the target host it enumerates and hides the local listening ports, with the port list stored in /tmp/.vl_ss_ports.

> **Evidence**: 0xe6190 "detect://Makefile/ebpf/ebpf/sd_ss.bpf.c/ebpf/sd_loader.c"; 0xf50aa "/tmp/.vl_ss_ports"; 0xf823a "eBPF ss_loader failed"
> 
> **Source**: `ev-000011`

### 5. Steal SSH and cloud credentials

`T1552.001, T1552.005` · confidence **high** · static

Walks /root/.ssh private keys, /.kube/config, /.aws/, /.git-credentials and shell history, and accesses cloud metadata endpoints such as 169.254.169[.]254, metadata.google.internal, metadata[.]tencentyun[.]com and 100.100.100[.]200 to obtain temporary credentials.

> **Evidence**: 0xf8d00 "/root/.ssh/id_rsa"; 0xec590 "/.kube/config/.aws/"; 0xf8e41 "AWS_SECRET"; 0xfab08 "169.254.169[.]254"; 0xf630c "metadata.google.internal"; 0xf5fe9 "metadata[.]tencentyun[.]com"
> 
> **Source**: `ev-000011` · `ev-000003`

### 6. Export TLS session keys

`T1552` · confidence **medium** · static

Reads TLS session material such as CLIENT_RANDOM, CLIENT_TRAFFIC_SECRET, SERVER_TRAFFIC_SECRET and handshake traffic keys from processes/environment variables, to decrypt the TLS communications of monitored hosts.

> **Evidence**: 0xf8e4c "CLIENT_TRAFFIC_SECRET"; 0xf8e62 "SERVER_TRAFFIC_SECRET"; 0xf8e78 "CLIENT_HANDSHAKE_TRAFFIC_SECRET"; 0xf8f76 "CLIENT_RANDOM"; 0xf5c19 "/proc/self/environ"
> 
> **Source**: `ev-000011`

### 7. Clean logs and history

`T1070.003, T1070.004` · confidence **high** · static

Clears logs such as /var/log/secure, auth.log, messages, wtmp/lastlog, deletes the shell history files, and sets HISTFILE=/dev/null and HISTSIZE=0 to suppress subsequent command logging.

> **Evidence**: 0xf6dc6 "/var/log/secure"; 0xf6626 "/var/log/auth.log"; 0xf9078 "export HISTFILE=/dev/null"; 0xf46ea "/root/.zsh_history"; 0xf471d "/root/.bash_history"
> 
> **Source**: `ev-000011` · `ev-000003`

### 8. Plugin-based persistence and escape

`T1543.002, T1574.006, T1611` · confidence **medium** · static

Delivers cron_persist_v3, systemd_persist_v3 and ld_preload_v3 through plugin_load to establish persistence, or attempts container escape with docker_escape_v3 and k8s_privesc_v3; the plugin names are specified by C2 tasks.

> **Evidence**: 0xfb14e "persist plugin (cron_persist_v3/systemd_persist_v3/ld_preload_v3)"; 0xfb1ae "escape plugin (docker_escape_v3/k8s_privesc_v3)"; 0xf6025 "/etc/systemd/system"; 0xf8b26 "/etc/cron.d"
> 
> **Source**: `ev-000011`

### 9. Anti-debugging and integrity checks

`T1622, T1027` · confidence **medium** · static

Initialises modules such as debugger_detector, integrity_checker, secure_allocator and smc_engine, performing debugger detection, memory integrity checks and self-modifying-code protection.

> **Evidence**: 0xf54f1 "debugger_detector"; 0xf7c2c "integrity_checker initialized"; 0xf7d1a "smc_engine initialized"; 0xf5503 "secure_allocator"
> 
> **Source**: `ev-000011`

### 10. Masquerade as a k8s container resource

`T1036` · confidence **medium** · static

Detects /.dockerenv, /proc/1/cgroup and the k8s serviceaccount, enables k8s_masquerade and sets cpu_limit, memory_limit_mb and network_limit_bps to disguise itself as a cluster workload.

> **Evidence**: 0xf4ae3 "/.dockerenv"; 0xf5941 "/proc/1/cgroup"; 0xe9a08 "k8s_masquerade"; 0xec520 "cpu_limit/memory_limit_mb/network_limit_bps"
> 
> **Source**: `ev-000011` · `ev-000003`

### 11. Remote shell and file manipulation

`T1059.004` · confidence **high** · static

Establishes an interactive PTY through beacon_pty_start/beacon_pty_read/beacon_pty_write, and together with beacon_exec, beacon_file_read/write/append and beacon_chdir provides remote command execution and file management.

> **Evidence**: 0xf4c4f "beacon_pty_start"; 0xf8a96 "beacon_pty_read"; 0xf8bce "beacon_exec"; 0xf6b3a "beacon_file_write"; 0xf64e7 "/bin/bash"
> 
> **Source**: `ev-000011`

### 12. Covert trigger over raw sockets

`T1095` · confidence **medium** · static

Contains an embedded Python snippet that creates a SOCK_RAW/ICMP socket and encapsulates cmd and hex data using the fixed magic 0xC0DE and key 0x42, forming a covert control/trigger channel independent of HTTP.

> **Evidence**: 0xfb1fe "s=socket.socket(socket.AF_INET,socket.SOCK_RAW,1); magic=0xC0DE; key=0x42; payload=struct.pack(>HBB,magic,cmd,key)+data"
> 
> **Source**: `ev-000011`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis method and limitations" at the end of this report).
:::

### Host

**Drop paths**

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

**Scheduled tasks**

- `crontab entries (created by the cron_persist_v3 plugin)`
- `systemd services (created by the systemd_persist_v3 plugin)`
- `/etc/rc.local autostart entry (path used by the persistence module)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_host` | `delivered at runtime, not embedded; only example[.]com / api[.]example[.]com placeholders seen` | yes | dynamic |
| `agent_id` | `generated at runtime and delivered by the C2 (JSON field agent_id)` | yes | dynamic |
| `public_key` | `32-byte base64 public key, delivered by the C2 ("public key must be 32 bytes")` | yes | dynamic |
| `encryption_algo` | `AES-256-GCM; plus ChaCha20/Salsa20 "expand 32-byte k" constants and a TLS 1.3 client implementation` | yes | static |
| `beacon_sleep_ms` | `heartbeat interval (milliseconds), adjustable by the C2` | yes | static |
| `min_delay_ms` | `jitter lower bound` | no | static |
| `max_delay_ms` | `jitter upper bound` | no | static |
| `heartbeat_mode` | `aggressive / human_like / low_activity` | no | static |
| `working_hours` | `working-hours restriction (enable_grease, work_start_hour, work_end_hour, timezone_offset)` | no | static |
| `max_ops_per_hour` | `maximum operations per hour` | no | static |
| `camouflage` | `http_camouflage / http_full_camouflage / tls_camouflage / k8s_masquerade` | yes | static |
| `persistence_plugins` | `cron_persist_v3 / systemd_persist_v3 / ld_preload_v3` | no | static |
| `container_plugins` | `docker_escape_v3 / k8s_privesc_v3 / timestomp_v3` | no | static |
| `config_path` | `/tmp/.vl_config` | no | static |
| `lkm_module` | `vl_stealth.ko / stealth_netstat.ko` | no | static |

## Don't misread this

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- The presence of AES/SHA/MD5/CRC32/base64 constants in the sample is part of generic TLS, hashing and encoding implementations and cannot be used to judge it as ransomware or an encryptor.
- The sample embeds no usable C2 address, only the example[.]com/api[.]example[.]com placeholders; no specific IP or domain can be identified as this sample's C2.
- Plugin names such as cron_persist_v3, ld_preload_v3 and docker_escape_v3 only show that the capability entry points exist; they do not mean the sample has already achieved persistence or container escape on this host.
- Both the executable segment and the entry address lie beyond the end of the file, and machine code is missing; static results cannot be used to assert specific injection, privilege-escalation or anti-debugging implementation details.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | pure static analysis |
| Unpacked | no |

**Limitations and open questions**

1. The sample is truncated at 0x100000: the code-bearing PT_LOAD (file offset 1225824, size 745230) and the entry point 1229920 both lie beyond the end of the file, so it cannot be disassembled or emulated; the functional conclusions come from embedded strings/source and structure.
2. No plaintext C2 host, port or agent_id was obtained; the configuration is delivered at runtime via /tmp/.vl_config or by the C2 and cannot be recovered at the static stage.
3. The family name comes from the sample's self-identifying string VoidLink Implant Core v3.0, with no cross-confirmation from external engines or public reports, so it is marked as an uncertain candidate.
4. Conclusions about the LKM and eBPF come from embedded source text and were not verified by compiling or loading them on a real kernel.
5. The sample was not actually detonated, reproduced=false; all behaviours are statically determinable capabilities and do not mean they have been executed on a host.

## Evidence index

<details>
<summary>Show 13 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000003` | string extraction | Extracted 3,364 ASCII strings, hitting C2 endpoints, beacon_* APIs, plugin and credential paths |
| `ev-000004` | Cryptographic constant identification | AES S-box @0xeabc0 |
| `ev-000005` | Cryptographic constant identification | SHA-256 initial constants @0xdf8e0 |
| `ev-000006` | Cryptographic constant identification | SHA-1 initial constants @0xeab60 |
| `ev-000007` | Cryptographic constant identification | MD5 initial constants @0xeab60 |
| `ev-000008` | Cryptographic constant identification | CRC32 polynomial @0xe5ce0 |
| `ev-000009` | Cryptographic constant identification | CRC32 table entries @0xe5ae4 |
| `ev-000010` | Cryptographic constant identification | standard base64 alphabet @0x4e7c |
| `ref:4043c06c82` | ELF structure parse | ELF64 x86-64 EXEC, entry 1229920, no section table/symbols/imports, shdr out of bounds |
| `ref:cb886c8897` | scan.entropy | Overall entropy 7.307, high-entropy embedded data present |
| `ref:d0fd262e6f` | elf.sections | Program headers only, sections empty |
| `ev-000011` | evidence.record | Read-only string offset mapping: VoidLink self-identification, C2 endpoints, plugin ABI, LKM/eBPF source, credential and TLS keys |
| `ev-000012` | evidence.record | Layout check: the code segment and the entry point both lie beyond EOF; the sample is truncated |

</details>

---

_This sample is not shared; IOCs are defanged. For security research only._
