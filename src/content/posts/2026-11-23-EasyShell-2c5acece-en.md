---
title: "Malware Sample Analysis: EasyShell (ELF · elf · 2c5acece)"
published: 2026-11-23
draft: false
description: "Malicious (high confidence): EasyShell · rat/backdoor/implant · difficulty medium · dynamic sandbox + static decompilation"
tags: ["EasyShell", "rat", "backdoor", "implant", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-23-EasyShell-2c5acece"
---

> [!WARNING]
> **Verdict: Malicious** · Family **EasyShell** · Confidence **High**
> 
> Aliases: easyshell-http-beacon-implant, ESCH
> 
> The sample is an executable Linux/aarch64 Rust HTTP beacon: it embeds a plaintext C2 address and a 32-byte key, and provides remote shell, SOCKS tunneling, file transfer, screenshot, in-memory ELF plugin loading and anti-VM capabilities; after actually running in a hardened isolated instance, HTTPS connection attempts to the C2, /etc/passwd reads and process-name masquerading were observed, confirming clear malicious intent.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **EasyShell** · aliases easyshell-http-beacon-implant, ESCH |
| Confidence | **High** |
| Behavior class | rat · backdoor · implant |
| Difficulty | medium |
| First seen | 2026-11-23 07:37:09 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/2c5acecebf16c6f00435c6bbd08afcc04936c5cd6291a8ed2987c5e05e667409/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Beacon to HTTPS C2</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Kernel thread name masquerade</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Enumerate local accounts</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1087.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Probe network config</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1016</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Anti-VM checks</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `2c5acecebf16c6f00435c6bbd08afcc04936c5cd6291a8ed2987c5e05e667409` |
| MD5 | _Not recorded_ |
| Size | 3,755,152 bytes (3.6 MB) |
| Type | ELF · `elf` |

## Behavior Analysis

**12** behaviors in total, each backed by evidence; **8** are statically available and **4** were obtained through dynamic analysis.

### 1. Beacon to HTTPS C2

`T1071.001` · Confidence **High** · Dynamic

After startup it creates an IPv4 TCP socket and initiates an HTTPS callback to 192[.]3[.]31[.]148 on port 8443, using the /api/v2/sync channel to send and receive commands; in the network-isolated environment this connection returned ENETUNREACH.

> **Evidence**: strace connect(fd, {sin_port=htons(8443), sin_addr=inet_addr("192.3.31[.]148")}) = -1 ENETUNREACH; URL constant at file offset 0x2036e2; code at 0x41352c loads this address
> 
> **Source**: `ref:0bd4c01627` · `ref:90c5406615` · `ref:6ec6eec48e`

### 2. Kernel Thread Name Masquerade

`T1036.005` · Confidence **High** · Dynamic

Uses prctl(PR_SET_NAME) to change the running thread name to a kernel-thread style such as [watchdog/0], and embeds masquerade-name templates including [kworker/0:0], [rcu_sched] and [migration/0] to reduce visibility in process listings.

> **Evidence**: strace prctl(PR_SET_NAME, "[watchdog/0]") = 0; the string area contains masquerade names such as [kworker/0:0], [rcu_sched], [watchdog/1]
> 
> **Source**: `ref:0bd4c01627` · `ref:76901a8fcf`

### 3. Enumerate Local Accounts

`T1087.001` · Confidence **High** · Dynamic

Opens /etc/passwd and reads it continuously to collect local account names, UIDs, home directories, login shells and other identity information.

> **Evidence**: strace openat("/etc/passwd") = 4; read(...) returned 1024/507 bytes containing passwd lines
> 
> **Source**: `ref:0bd4c01627`

### 4. Probe Network Configuration

`T1016` · Confidence **High** · Dynamic

Opens NETLINK_ROUTE raw sockets twice and reads network interface, address and routing information (netlink attributes such as rtm_family/ifi_family/rtm_type) for internal-network positioning and later lateral movement.

> **Evidence**: strace socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) twice; .rodata contains neli attribute names such as rtm_family/ifa_family/rtm_type
> 
> **Source**: `ref:0bd4c01627` · `ref:a5aabbf0e3`

### 5. Anti-VM Checks

`T1497.001` · Confidence **High** · Static

Reads /sys/class/dmi/id/{product_name,sys_vendor,board_vendor}, /proc/xen and systemd virtualization markers, and matches vendor strings such as vmware/virtualbox/qemu/kvm/xen/hyper-v/parallels/bhyve/proxmox; it also checks the cgroup CPU quota and CPU model to identify analysis environments.

> **Evidence**: file offset 0x2038xx onward contains paths such as /sys/class/dmi/id/product_name and vmware/virtualbox/qemu/kvm/xen/hyper-v constants; strings "SYSTEMD_VIRTUALIZATION", "hypervisor", "cpu.cfs_quota_us"
> 
> **Source**: `ref:c4f3f083ba` · `ref:76901a8fcf`

### 6. Remote Shell Execution

`T1059.004` · Confidence **High** · Static

Embeds interactive and non-interactive shells: starts /bin/bash --rcfile and clears HISTFILE/HISTSIZE, supports PTY, batch commands and execution timeouts, receives server-issued commands and returns their output.

> **Evidence**: strings /bin/bash, --rcfile, export HISTFILE=/dev/null HISTSIZE=500, ES_SHELL_BATCH_MS, interactive-1..4, ConPTY hints; crates/impl-core/src/plugin_exec/unix.rs
> 
> **Source**: `ref:76901a8fcf` · `ref:a5aabbf0e3`

### 7. SOCKS Tunnel Setup

`T1090` · Confidence **High** · Static

Implements SOCKS5 proxying, port forwarding, reverse listening and multiplexed tunnels (es-socks-/es-pump-tcp/es-mux-agg/es-dns/es-idle-reaper), turning the victim host into a pivot into the internal network.

> **Evidence**: crates/impl-core/src/socks_tunnel/{mod,backward_listen,mux,codec,hop_relay}.rs; strings es-socks-, es-pump-tcp, LISTEN/FORWARD/BIND, backward-listen-1
> 
> **Source**: `ref:a5aabbf0e3` · `ref:76901a8fcf`

### 8. File Upload and Download

`T1105` · Confidence **High** · Static

Provides upload/download worker threads with resumable transfer, pause and resume capabilities, and supports file operations such as cp/mv/mkdir/rm, with results returned through the C2 channel.

> **Evidence**: crates/impl-core/src/download_xfer.rs, upload_worker.rs; strings [+] Downloading, download resume offset beyond file size, cp:/mv: bad args, Mkdir failed
> 
> **Source**: `ref:a5aabbf0e3` · `ref:76901a8fcf`

### 9. Screenshot and Mouse Control

`T1113` · Confidence **High** · Static

Captures the screen and reads /dev/input/mice and DISPLAY/WAYLAND_DISPLAY, supporting mouse control and screen parameter reporting (screenW/screenH).

> **Evidence**: XOR 0x5A decodes to screen capture/screenshot/screen control; strings /dev/input/mice, {"screenW":1,"screenH":1}, mouseMs/mousePx
> 
> **Source**: `ref:c26c8969f0` · `ref:76901a8fcf`

### 10. In-Memory ELF Plugin Loading

`T1620` · Confidence **Medium** · Static

Runs server-delivered native ELF payloads in an isolated child process, and reads /proc/self/maps and /proc/sys/vm/mmap_min_addr to prepare memory mapping; non-native executable payloads are rejected.

> **Evidence**: XOR 0x5A decodes to "payload is not a native executable", "spawning native binary in isolated child"; dynamically reads /proc/self/maps, /proc/sys/vm/mmap_min_addr
> 
> **Source**: `ref:c26c8969f0` · `ref:0bd4c01627`

### 11. Self-Deletion and String Obfuscation

`T1070.004` · Confidence **Medium** · Static

Supports a delete-self action to delete its own file, and obfuscates communication fields with XOR 0x5A and a substitution table (!ES/7/SBOX/), increasing the difficulty of static forensics.

> **Evidence**: string delete-self-1; XOR 0x5A decodes )9(??4z954.(56 to screen control; .rodata contains the !ES/7/SBOX/ label
> 
> **Source**: `ref:76901a8fcf` · `ref:c26c8969f0`

### 12. AES-Encrypted Communications

`T1573.001` · Confidence **Medium** · Static

Uses the AES crate with a 32-byte base64 key/standard base64 to encrypt and decrypt C2 payloads, carried over HTTPS to reduce traffic readability.

> **Evidence**: aes-0.8.4 source path, SHA-256 and base64 constants; the 44-character base64 key at file offset 0x203762 decodes to 32 bytes
> 
> **Source**: `ref:0b33798ecf` · `ref:168df48565` · `ref:0c5fc7be6a`


## IOCs (Defanged)

### Network

:::caution
**Pending dynamic verification**: the address above comes from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://192[.]3[.]31[.]148:8443/api/v2/sync` | 8443 | c2 | Static | ⏳ Not observed |

### Host

**Dropped paths**

- `/tmp/.<random>.lk`
- `/dev/input/mice`
- `/sys/class/dmi/id/product_name`
- `/sys/class/dmi/id/sys_vendor`
- `/sys/class/dmi/id/board_vendor`
- `/proc/self/maps`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `192[.]3[.]31[.]148` | Yes | Static |
| `c2_port` | `8443` | Yes | Static |
| `c2_uri` | `/api/v2/sync` | Yes | Static |
| `encryption_key` | `LY6nDGIwrDlZZrvHtRseg+IWBrJuvbT6LFHEUM7I3lo=` | Yes | Static |
| `encryption_algo` | `AES (aes 0.8.4 crate; a 32-byte key after base64 decoding; the exact block mode was not confirmed by runtime traffic)` | Yes | Static |
| `client_id` | `es-beacon-drain` | Yes | Static |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0[.]0 Safari/537.36` | No | Static |
| `http_header_keys` | `client-id / Client-Id / X-Client-Id; Content-Type may be application/octet-stream or application/json` | No | Static |

## What Not to Misjudge

:::important
The following conclusions are **easy to misjudge**; please note this when citing this report.

- It cannot be asserted that a C2 session was successfully established or data exfiltrated: the network was isolated during dynamic execution, connect returned ENETUNREACH, and no request/response or upload events were observed.
- It cannot be asserted that persistence exists: no evidence of systemd, cron, rc.local or autostart writes was found; dynamically, only a temporary lock file under /tmp was observed.
- It cannot be classified as ransomware, a miner or pure stealer: no file encryption, mining-pool protocol or browser-credential reading behavior was found; its core is remote control.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | No |

**Limitations and Pending Verification**

1. The dynamic channel was network-isolated, and only a connect attempt to the C2 (ENETUNREACH) was observed; configuration and C2 were handled as statically recovered and flagged for pending dynamic verification.
2. The server-delivered sleep/jitter values and specific commands were not obtained; the related capabilities are inferred from strings, source paths and code references.
3. The actual return value of the anti-VM determination and its subsequent branches were not dynamically confirmed.
4. Cross-architecture user-mode execution may differ from a native machine in system-call timing.
5. Behaviors that require server commands to trigger, such as in-memory plugin loading, screenshots and SOCKS tunneling, were not observed.
6. No persistence mechanism was found; the possibility that an external loader is responsible for residency cannot be excluded.

## Evidence Index

<details>
<summary>Expand 15 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:c921f466ea` | ELF structure parsing | ELF structure: aarch64, statically linked, stripped, entry RVA 0xA278 |
| `ref:dd77520dfa` | String extraction | String and flag regex scan |
| `ref:320b788f71` | strings/grep | Hits crates/easyshell-http-beacon-implant source path and C2 constants |
| `ref:90c5406615` | script | Locates file offsets of /api/v2/sync, C2 URL, key, client_id |
| `ref:0c5fc7be6a` | script | Dumps fixed-length fields of the configuration area |
| `ref:cfd776e658` | script | Scans ARM64 adrp/add, locating configuration reference points such as 0x41352c |
| `ref:6ec6eec48e` | disasm.function | Loads C2 URL/key/path constants at 0x41352c |
| `ref:3d0009fc78` | disasm.function | Copies 15 bytes es-beacon-drain from 0x603691 at 0x40ea00 |
| `ref:76901a8fcf` | script | Dumps action/protocol string area (delete-self, interactive shell, socks, upload/download) |
| `ref:c4f3f083ba` | strings/grep | Anti-VM paths and vendor strings |
| `ref:c26c8969f0` | script | XOR 0x5A reveals plaintext such as screenshot/screen control/native executable |
| `ref:0b33798ecf` | Cryptographic constant identification | SHA-256 and standard base64 constants |
| `ref:168df48565` | script | Base64 key decodes to 32 bytes |
| `ref:2cc820e886` | dyn.exec | Actually run in an isolated instance, 25-second timeout, multi-thread/timer activity |
| `ref:0bd4c01627` | dyn.trace | System-call tracing: connect 192.3.31[.]148:8443 ENETUNREACH, /etc/passwd, NETLINK_ROUTE, prctl rename |

</details>

---

_The sample in this report is not public; IOCs have been defanged and are provided for security research only._
