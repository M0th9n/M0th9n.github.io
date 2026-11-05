---
title: "Malware Analysis: Mirai (ELF · elf · 9c4ddcfb)"
published: 2026-11-05
draft: false
description: "Malicious (high confidence): Mirai · botnet/backdoor · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Mirai", "botnet", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-05-Mirai-9c4ddcfb"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Mirai** · Confidence **high**
> 
> Aliases: Mirai DDoS botnet, Mirai (SOCKS5 proxy variant), 2.0.4_socks5 build
> 
> Decompilation confirms Mirai-family DDoS/SOCKS5 backdoor logic: an embedded encrypted configuration decrypts to a dynamic domain C2, the main loop registers and receives commands, and after daemonizing it starts a SOCKS5 proxy on 0.0.0[.]0:26721 and executes iptables rules to open the port, and it registers 15 TCP/UDP/GRE flood vectors; real execution in the controlled environment showed the anti-debug check exiting immediately, a SOCKS5 child process being started (arguments 0.0.0[.]0:26721/lucy_user/password_meow), and iptables being run through a shell. No real C2 session was established under network isolation.

## Overview

| Item | Content |
|:--|:--|
| Family | **Mirai** · aliases Mirai DDoS botnet, Mirai (SOCKS5 proxy variant), 2.0.4_socks5 build |
| Confidence | **high** |
| Behavior class | botnet · backdoor |
| Difficulty | medium |
| First seen | 2026-11-02 01:20:19 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/9c4ddcfb0606a3f9ac5a67b53cf30276a61db873f346c1c2caf5da9c3eb272ad/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Exit on debugger</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">observed</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Detect VM environment</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded config</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Masquerade and daemonize</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Resolve domain, connect C2</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1568</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `9c4ddcfb0606a3f9ac5a67b53cf30276a61db873f346c1c2caf5da9c3eb272ad` |
| MD5 | _not recorded_ |
| Size | 221,204 bytes (216.0 KB) |
| Type | ELF · `elf` |

## Behavior analysis

**11** behaviors in total, each backed by evidence; **10** are statically recoverable and **1** was obtained through dynamic analysis.

### 1. Exit on debugger detection

`T1622` · Confidence **high** · dynamic

At startup it first self-checks with ptrace(PTRACE_TRACEME), then reads TracerPid from /proc/self/status; if either indicates a debugger it exits immediately with exit(0) and produces no network activity.

> **Evidence**: _check_tracer@0x4021b0 ptrace(PTRACE_TRACEME); _is_debugger_present@0x4027e0 parses TracerPid; during dynamic execution ptrace returned EPERM and the process called exit(0)
> 
> **Source**: `ev-000010` · `ev-000059` · `ev-000013`

### 2. Detect VM environment

`T1497.001` · Confidence **high** · static

Reads /proc/cpuinfo and /proc/sys/kernel/osrelease and calls uname, matching vmware, vbox, qemu and kvm signatures; on a match it exits, evading the analysis environment.

> **Evidence**: _is_vm@0x4028e0 compares inline "vmware"/"vbox"/"qemu"/"kvm"; data at .rodata 0x41b380-0x41b3bd
> 
> **Source**: `ev-000007`

### 3. Decrypt embedded config

`T1027` · Confidence **high** · static

At runtime it decrypts 18 embedded strings one by one with ChaCha20, recovering the C2 domain, the SOCKS5 username/password, the process name and the /proc paths; the key and nonce are hardcoded in .data.

> **Evidence**: xor_init@0x404bf0 → xor_add@0x404b60 → chacha20_xor@0x404db0; ciphertext table 0x1b57e, key 0x1e280, nonce 0x1e2a0
> 
> **Source**: `ev-000006` · `ev-000008` · `ev-000063`

### 4. Masquerade and daemonize

`T1036.005` · Confidence **high** · static

Overwrites argv[0] and prctl(PR_SET_NAME) with "2.0.4_socks5", then forks, calls setsid, closes 0/1/2 and chdir("/") to run resident in the background.

> **Evidence**: main@0x400300: _strcpy(*argv, enc[2]), prctl(0xf, enc[2]), fork/setsid/close(0..2)/chdir; dynamic observation showed two forks before it entered the SOCKS5 child process
> 
> **Source**: `ev-000003` · `ev-000060`

### 5. Resolve domain, connect C2

`T1568` · Confidence **high** · static

It looks up bass1231488c2[.]hopto[.]org with its built-in resolver, takes the A record and connects to TCP/35342, using a command protocol with a 2-byte big-endian length prefix.

> **Evidence**: main@0x400300 lookup_domain(enc[3]) and srv_addr.sin_port constant 0x0E8A (network order 35342, written by instruction 0x400ca4 into 0x52d682); dynamic observation showed repeated UDP/53 resolution attempts
> 
> **Source**: `ev-000003` · `ev-000018` · `ev-000063` · `ref:1a96c3b6c0`

### 6. Encrypted host information report

`T1082` · Confidence **high** · static

The registration packet begins with 0x00000004 and sends "x86" and "2.0.4_socks5" in sequence, then sends the CPU core count, memory size and the host identifier "aterna" encrypted with ChaCha20.

> **Evidence**: main@0x400300 sends the 4-byte magic, "x86", the process name, then the chacha20_xor'd results of sysconf(_SC_NPROCESSORS_ONLN)/sysinfo and "aterna"; the matching sendto sequence was captured dynamically
> 
> **Source**: `ev-000003` · `ev-000019`

### 7. Open SOCKS5 backdoor

`T1090` · Confidence **high** · static

It starts a separate child process listening for SOCKS5 on 0.0.0[.]0:26721 with fixed username/password authentication; once authenticated it performs CONNECT to the target and forwards traffic in both directions, turning the victim host into a proxy exit.

> **Evidence**: socks5_server@0x403ba0 arguments 0.0.0[.]0/0x6861/lucy_user/password_meow (a dynamic breakpoint read 0.0.0[.]0:26721); clientthread@0x403e00 implements username/password authentication and poll-based forwarding
> 
> **Source**: `ev-000005` · `ev-000060` · `ev-000062`

### 8. Tamper with firewall to allow traffic

`T1562.004` · Confidence **high** · static

It runs five iptables variant commands in a row through system, appending tcp/26721 ACCEPT to the INPUT chain to open the proxy port.

> **Evidence**: socks5_server@0x403ba0 calls system("iptables -A INPUT -p tcp --dport 26721 -j ACCEPT") and four more; dynamic observation showed a subsequent vfork/exec of /usr/bin/dash
> 
> **Source**: `ev-000005` · `ev-000060`

### 9. Kill processes holding the port

`T1057, T1489` · Confidence **high** · static

It parses /proc/net/tcp to find the socket inode listening on 26721, walks /proc/<pid>/exe and /proc/<pid>/fd/* matching that inode, and kills other processes holding the port (keeping its parent), ensuring exclusive use of the port.

> **Evidence**: kill_port@0x4046b0 reads /proc/net/tcp and /proc/<pid>/fd; main calls it with 0x6168 (byte-swapped 6861=26721)
> 
> **Source**: `ev-000004` · `ev-000003`

### 10. Launch multi-vector floods

`T1498` · Confidence **high** · static

floods_init registers 15 attack vectors (udp_plain/udp_raw/udp_bypass/udp_openvpn/udp_raknet, tcp_ack/tcp_syn_data/tcp_stomp/tcp_handshake/tcp_bypass/tcp_wra/tcp_socket/tcp_sockethold, gre_ip and others); on a C2 command it forks flood processes and keeps attacking the target as instructed.

> **Evidence**: floods_init@0x403220 registry; flood_parse@0x402c50 parses target/port/options; flood_start@0x402eb0 forks flood_* (flood_udpraw@0x408e90, flood_greip@0x409220 and others)
> 
> **Source**: `ev-000012` · `ev-000009` · `ev-000011`

### 11. Check in with proxy panel

`T1071` · Confidence **high** · static

After the proxy service starts it connects back to 212[.]118[.]43[.]167:2222 and sends the fixed text "hi im here, i think" as an online/availability notification.

> **Evidence**: proxy_report@0x403b00: sockaddr port constant 0xAE08 (2222), address constant 0xA72B76D4 (212.118.43[.]167), strcpy "hi im here, i think" then send
> 
> **Source**: `ev-000061` · `ref:80c7e21c0e`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the isolated analysis network, so the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `bass1231488c2[.]hopto[.]org` | 35342 | c2 | static | ⏳ not observed |
| tcp | `212[.]118[.]43[.]167` | 2222 | panel | static | ⏳ not observed |

### Host

- **No host IOCs were recovered.**

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `bass1231488c2[.]hopto[.]org` | yes | static |
| `c2_port` | `35342` | yes | static |
| `socks5_listen` | `0.0.0[.]0:26721` | yes | static |
| `socks5_user` | `lucy_user` | yes | static |
| `socks5_pass` | `password_meow` | yes | static |
| `proxy_report_endpoint` | `212[.]118[.]43[.]167:2222` | yes | static |
| `encryption_algo` | `ChaCha20 (20 rounds, 32-byte key + 12-byte nonce, counter starts at 1; used for embedded strings and registration fields)` | yes | static |
| `bot_source_id` | `aterna` | yes | static |
| `process_name` | `2.0.4_socks5` | yes | static |
| `campaign_id` | `aterna/2.0.4_socks5` | no | static |
| `dns_resolvers` | `8.8.8[.]8, 51.254.162[.]59, 51.77.149[.]139, 194.36.144[.]87, 195.10.195[.]195, 94.16.114[.]254 (built-in resolver list, all public DNS, not attacker-specific)` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not classify it as ransomware/wiper: no file encryption, ransom note or disk-destruction code was found; ChaCha20 is used only for string and registration-field encryption.
- Do not classify it as an infostealer: no browser credential, file collection or bulk exfiltration logic was found.
- Do not claim registry/service/scheduled-task persistence: the sample is a Linux ELF and has no such APIs or paths.
- Do not claim a complete session with the real C2 was observed: the analysis network was isolated, and only domain resolution attempts and registration packet construction/failed sends were observed.
- Do not classify it as a downloader/dropper: no code path downloads or executes a second-stage payload.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The C2 domain/port and the proxy panel address were statically recovered from the embedded ChaCha20 configuration and hardcoded constants, and no callback could be verified on the real network (pending_dynamic_verify).
2. Dynamic observation of the daemon path requires bypassing the ptrace anti-debug check; whether the SOCKS5 listener and iptables rules actually take effect in the isolated environment was not verified.
3. The 15 flood vectors were confirmed only at code level; no attack was launched against any real target.
4. The lineage can be confirmed as Mirai-family, but the exact variant naming lacks vendor naming evidence.
5. The sample parses its own arguments with a self-implemented string comparison (returns 1 on equality), which makes the --debug branch effectively unusable; the debug branch can only be reached by passing other arguments. This is a behavior of the sample, not an analysis defect.

## Evidence index

<details>
<summary>Expand 20 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000003` | static decompilation | main@0x400300: anti-debug/anti-VM, config decryption, C2 registration and command loop, daemonization and the SOCKS5 child process |
| `ev-000004` | static decompilation | kill_port@0x4046b0: locate the process listening on 26721 via /proc/net/tcp and kill it |
| `ev-000005` | static decompilation | socks5_server@0x403ba0: iptables rule to allow 26721, fixed credentials, threaded proxy service |
| `ev-000006` | static decompilation | xor_init@0x404bf0: index and length table of 18 embedded encrypted strings |
| `ev-000007` | static decompilation | _is_vm@0x4028e0: VM signature matching on /proc/cpuinfo, osrelease and uname |
| `ev-000008` | static decompilation | xor_add@0x404b60: ChaCha20 decryption of a single string |
| `ev-000009` | static decompilation | flood_parse@0x402c50: parsing of C2 attack command fields |
| `ev-000010` | static decompilation | _check_tracer@0x4021b0: ptrace(PTRACE_TRACEME) anti-debug |
| `ev-000011` | static decompilation | flood_start@0x402eb0: fork attack processes per vector and pass 20+ parameters |
| `ev-000012` | static decompilation | floods_init@0x403220: register 15 DDoS flood vectors |
| `ev-000013` | dynamic execution observation | real execution: ptrace(PTRACE_TRACEME) returned EPERM and the process exited with exit(0), so the anti-debug check worked |
| `ev-000018` | dynamic execution observation | real execution: printed fortnite and sent repeated resolution requests to several DNS servers on UDP/53 |
| `ev-000019` | syscall monitoring | real execution: execve ./prog x, followed by socket/connect(DNS)/write(fortnite) |
| `ev-000059` | static decompilation | _is_debugger_present@0x4027e0: read TracerPid from /proc/self/status |
| `ev-000060` | debugger observation | after bypassing the anti-debug check, observed SOCKS5 arguments 0.0.0[.]0:26721/lucy_user/password_meow, followed by vfork of /usr/bin/dash |
| `ev-000061` | static decompilation | proxy_report@0x403b00: connect back to 212.118.43[.]167:2222 and send "hi im here, i think" |
| `ev-000062` | static decompilation | clientthread@0x403e00: SOCKS5 authentication, CONNECT and bidirectional forwarding |
| `ev-000063` | script recovery | ChaCha20 decryption of the embedded string table: C2 domain, SOCKS5 credentials, process name and /proc paths |
| `ref:cd428945ec` | symbol table parsing | 1,448 symbols and 933 functions, exposing Mirai source-file and attack-function names |
| `ref:bee2691cad` | hash computation | md5 abe3e6ae7d1bb3519448d07cc04036bc; sha1 d066876b10b9160c70b6fb9ced4e491f23a42632; sha256 matches the submission |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
