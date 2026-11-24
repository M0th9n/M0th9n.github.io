---
title: "Malware Analysis: LimboC2 (ELF · elf · 841bdbfe)"
published: 2026-11-22
draft: false
description: "Malicious (medium confidence): LimboC2 · botnet/implant · medium difficulty · static decompilation (dynamic execution produced no runtime behavior)"
tags: ["LimboC2", "botnet", "implant", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-22-LimboC2-841bdbfe"
---

> [!WARNING]
> **Verdict: Malicious** · Family **LimboC2** (uncertain) · Confidence **Medium**
> 
> Aliases: Mirai, Limbo
> 
> Static decompilation confirms that this ELF is an ARM32 statically linked IoT DDoS botnet client: it has a configurable C2 address and a custom encrypted binary protocol with HMAC-SHA256 verification, 27 attack command handlers, HTTP/HTTP2 flooding and SSDP/mDNS/SNMP/LDAP/DNS reflection-amplification payloads, along with anti-forensics logic that enumerates and kills competing processes via /proc, masquerades as httpd, forks a daemon, and self-deletes via /proc/self/exe. The conclusions come from decompiling the real bytes and parsing data tables in this environment; the sample was not executed.

## Overview

| Item | Content |
|:--|:--|
| Family | **LimboC2** · aliases Mirai, Limbo · _uncertain_ |
| Confidence | **Medium** |
| Behavior classes | botnet · implant |
| Difficulty | medium |
| First seen | 2026-11-21 07:02:00 |
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/841bdbfe6611bd8b42d60f9ff73b9d849ed1dce96d19517d2ec4376842d4621d/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Connect encrypted C2 channel</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Verify C2 packet integrity</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1573</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">XOR-obfuscated strings</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Masquerade as httpd</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Forked daemon kills rivals</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1489</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `841bdbfe6611bd8b42d60f9ff73b9d849ed1dce96d19517d2ec4376842d4621d` |
| MD5 | _Not recorded_ |
| Size | 94,496 bytes (92.3 KB) |
| Type | ELF · `elf` |

## Behavior Analysis

**10** behaviors in total, each backed by evidence, and all are static.

### 1. Connect Encrypted C2 Channel

`T1071` · Confidence **High** · Static

After startup it forks into the background, creates a TCP socket and connects to the C2: it first resolves the built-in host string with its own DNS client and connects to port 1995 on success; if resolution fails it uses the hardcoded address 115[.]11[.]111[.]11:22.

> **Evidence**: main 0x2a624: socket(2,1,0) → FUN_0x2b298 rewrites sockaddr_in(sin_addr=resolution result, sin_port=htons(0x7cb=1995)) → connect 0x2c2c0(syscall 283); default constant 0x730b6f0b bswapped into sin_addr, port 0x16
> 
> **Source**: `ev-000006` · `ev-000013` · `ev-000015` · `ev-000007` · `ev-000008`

### 2. Verify C2 Packet Integrity

`T1573` · Confidence **High** · Static

C2 packets are parsed as a 6-byte header (2-byte big-endian length, 4-byte big-endian sequence) + payload + 8-byte tag; the tag is an HMAC-SHA256 over the sequence and payload, truncated; the session key rotates with the sequence, and only after verification does it enter command dispatch.

> **Evidence**: FUN_000298ac 0x298ac bswaps the sequence and feeds it with the payload into FUN_00029414; the latter is HMAC-SHA256 (0x6a09e667…IV, ipad 0x36/opad 0x5c); in main 0x2a624, FUN_00029918 compares the 8-byte tag
> 
> **Source**: `ev-000032` · `ev-000027` · `ev-000006`

### 3. XOR-Obfuscated Built-in Strings

`T1027` · Confidence **High** · Static

Configuration and attack-payload strings are stored in .rodata encrypted with a four-step XOR (0xC2/0xD2/0x53/0x6D, equivalent to 0x2E) and decrypted by length into heap memory at startup before use.

> **Evidence**: FUN_0002a2bc 0x2a2bc copies three ciphertext blocks 0x195c/0x196b/0x1029; FUN_0002a35c 0x2a35c decrypts byte by byte with the four eor steps; decrypted results include 18.220.36[.]224., done., TSource Engine Query
> 
> **Source**: `ev-000009` · `ev-000016` · `ev-000034`

### 4. Masquerade as httpd

`T1036.005` · Confidence **High** · Static

Overwrites argv[0] with httpd and sets the task name to httpd via prctl(PR_SET_NAME); it also ignores SIGCHLD and installs multiple signal handlers to reduce the chance of identification/termination.

> **Evidence**: main 0x2a624 calls FUN_0002a4a0(*argv,"httpd"); FUN_0002c19c 0x2c19c has movw r7,#0xac(172=prctl) + svc with arguments (0xf,"httpd")
> 
> **Source**: `ev-000006` · `ev-000029`

### 5. Forked Daemon Kills Rivals

`T1489` · Confidence **High** · Static

Forks another child process into an infinite loop that periodically enumerates /proc/*/exe and /proc/*/maps and executes kill(pid,9) on processes matching the kill list (busybox, sshd, telnetd, httpd, dropbear, watchdog, other-architecture main_*, /tmp, /var and other paths).

> **Evidence**: FUN_0002b300 0x2b300 reads /proc/%d/exe; FUN_0002b570 0x2b570 reads /proc/%d/maps; FUN_0002b83c 0x2b83c forks + loops calling both; kill wrapper 0x2cfb0(pid,9); log string "(limboc2/exe) Killed process"
> 
> **Source**: `ev-000021` · `ev-000022` · `ev-000028`

### 6. Self-Delete Dropped File

`T1070.004` · Confidence **High** · Static

After reading /proc/self/exe to obtain its own path, opens that path with O_WRONLY|O_CREAT|O_TRUNC(0x241) and truncates the executable on disk to erase drop traces.

> **Evidence**: FUN_0002a5c8 0x2a5c8 readlink("/proc/self/exe") → FUN_0002c0d8 0x2c0d8; the latter calls syscall 5(open) with flags 0x241|0x20000, mode 0x1ff
> 
> **Source**: `ev-000026` · `ev-000030`

### 7. Dispatch 27 Attack Command Types

`T1498` · Confidence **High** · Static

At initialization it registers 27 C2 command handlers (command numbers 0–26); when the second packet byte matches, the corresponding function is called; handlers cover UDP/TCP raw-packet flooding, HTTP/HTTP2 flooding and reflection-amplification variants.

> **Evidence**: FUN_000224a8 0x224a8 writes FUN_00025408/0x2788c/…/0x2879c into table DAT_00047e64 one by one; FUN_00023228 0x23228 matches *(byte*)(handler+1) against param_2 and then calls it
> 
> **Source**: `ev-000023` · `ev-000020`

### 8. Launch HTTP Traffic Flood

`T1498.001` · Confidence **High** · Static

Selects from 5 browser UAs and 12 random paths and repeatedly sends GET/POST requests to the target (with random Cookie/X-* headers), keeping connections alive to form an HTTP flood.

> **Evidence**: FUN_0002342c 0x2342c takes PTR_0x112e4[u%5] and PTR_0x11320[u%12]; templates 0x11189/0x1126e(GET), 0x10abe(POST), 0x111b5(X-%s); sendto 0x2c930
> 
> **Source**: `ev-000025` · `ev-000003` · `ev-000034`

### 9. Launch HTTP2 Flood

`T1498.001` · Confidence **High** · Static

Sends bulk HTTP/2 connection prefaces "PRI * HTTP/2.0" and subsequent frame data to the target, forming an HTTP/2 protocol-layer flood.

> **Evidence**: Command 18 → FUN_00023c08 0x23c08; template address 0x112f8 (PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n), sent by FUN_0002c930
> 
> **Source**: `ev-000023` · `ev-000003`

### 10. Use Reflection-Amplification Payloads

`T1498.002` · Confidence **Medium** · Static

Built-in request templates for SSDP/UPnP M-SEARCH, mDNS (_services._dns-sd._udp.local), SNMP/LDAP (objectClass), DNS (www[.]google[.]com) and others, sent in bulk with raw sockets for reflection-amplification attacks.

> **Evidence**: Pointer table 0x1152c–0x1158c points to 0x111c0/0x1178a M-SEARCH, 0x11704 mDNS, 0x1160d ASN.1(SNMP), 0x11674/0x11813 objectClass(LDAP), 0x115f0 www[.]google[.]com; commands 21–23/26 build packets with FUN_000285c0
> 
> **Source**: `ev-000003` · `ev-000023` · `ev-000034`


## IOC (Defanged)

### Network

:::caution
**Pending dynamic verification**: The addresses above were obtained statically; no successful connection or session was observed under the isolated analysis network, so the real C2 responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| dns | `18[.]220[.]36[.]224[.]` | 1995 | c2 | static | ⏳ Not observed |
| tcp | `115[.]11[.]111[.]11` | 22 | c2 | static | ⏳ Not observed |

### Host

**Drop paths**

- `/proc/self/exe`
- `/proc/%d/exe`
- `/proc/%d/maps`
- `/proc/`
- `/dev/null`
- `/tmp`
- `/var`
- `/mnt`
- `/boot`
- `/home`
- `/dev`
- `/root`
- `/opt/`
- `/usr/lib/systemd/systemd`
- `/usr/libexec/openssh/sftp-server`
- `/bin/busybox`
- `/usr/compress/bin/`
- `/compress/bin`
- `/compress/usr/`
- `/root/dvr_app/`
- `/root/dvr_gui/`
- `/anko-app/`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `18[.]220[.]36[.]224[.] (resolved via its own DNS resolver) / 115[.]11[.]111[.]11 (hardcoded fallback)` | Yes | static |
| `c2_port` | `1995 (after successful resolution) / 22 (hardcoded default)` | Yes | static |
| `dns_resolver` | `8[.]8[.]8[.]8:53 (its own DNS client, used to resolve the host string)` | No | static |
| `c2_protocol` | `Custom binary: 2-byte big-endian length + 4-byte big-endian sequence + <=1024-byte payload + 8-byte verification tag; the first packet negotiates/rotates the 32-byte session key` | Yes | static |
| `packet_auth` | `HMAC-SHA256 (ipad 0x36 / opad 0x5c), output truncated to 8 bytes` | Yes | static |
| `string_obfuscation` | `Four-step XOR 0xC2^0xD2^0x53^0x6D (equivalent 0x2E)` | Yes | static |
| `command_count` | `27` | No | static |
| `http_flood_paths` | `/, /index.php, /wp-login.php, /admin, /login, /api/v1/status, /search?q=, /.env, /actuator/health, /assets/app.js, /?s=, /xmlrpc.php` | No | static |
| `user_agents` | `5 entries: Chrome 120 (Win), Chrome 119 (Linux), Safari 17.1 (macOS), iPhone iOS 17_1, curl/8.4.0` | No | static |
| `self_delete` | `open("/proc/self/exe", O_WRONLY\|O_CREAT\|O_TRUNC, 0777)` | No | static |

## Common Misinterpretations

:::important
The following conclusions are **easy to misinterpret**; keep them in mind when citing this report.

- Do not assert that the sample has worm-like self-propagation: no Telnet/SSH brute force, exploit or download-drop code was found; strings such as telnet/busybox/sshd appear only in the competing-process kill list.
- Do not assert that the C2 is actually online or that the addresses were dynamically confirmed: both C2 endpoints are static extractions, and the sample was not executed in this environment; all are marked pending_dynamic_verify.
- Do not assert persistence exists: no systemd/rc.local/cron writes or service-installation code were found; only the fork daemon and self-deletion are present.
- Do not assert that it encrypts/ransoms user files: SHA-256 is used only for C2 packet HMAC verification, and no file encryption or ransom prompt was found.
- Do not treat built-in paths such as /.env and /wp-login.php as vulnerability-scanning evidence: they belong to the random request-path table for HTTP flooding.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Unpacked | No |

**Limitations and pending verification**

1. The sample is an ARM32 statically linked ELF and was not actually executed in the isolated guest this time (to avoid real outbound connections to the public C2 address), so the dynamic channel obtained no behavioral evidence; C2 and configuration are recorded as static and marked pending_dynamic_verify.
2. The main C2 host string decodes to "18.220.36[.]224." with a trailing dot, while the sample's own IPv4 parser requires a NUL immediately after the fourth octet, so the trailing dot takes the DNS-resolution branch; on failure it falls back to the hardcoded 115[.]11[.]111[.]11:22. The actual final connection target could not be dynamically confirmed.
3. The specific attack names of the 27 command handlers (UDP/TCP/HTTP/HTTP2/reflection etc.) are inferred from handler code and built-in payload templates; no real C2 command samples were obtained.
4. The family name LimboC2 comes from the sample's own "(limboc2/...)" log markers and Mirai-family commonalities, without vendor naming or multi-engine cross-validation, so it is marked uncertain.
5. Some attack handlers use raw sockets/custom packets, and whether source addresses are spoofed was not dynamically verified one by one.

## Evidence Index

<details>
<summary>Expand 25 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000003` | string_scan | ASCII strings and addresses: attack templates, kill list, httpd/telnet/sshd, /proc paths, limboc2 log strings |
| `ev-000004` | crypto_scan | Hits SHA-256 round constant K (off 0x185c) |
| `ev-000006` | static_decompile | main 0x2a624: C2 connection loop, sockaddr constants, packet header parsing, HMAC verification and command dispatch |
| `ev-000007` | static_decompile | 0x2c414 bswap32: handles the hardcoded IP constant |
| `ev-000008` | static_decompile | 0x2c41c htons: converts port 0x16/0x7cb |
| `ev-000009` | static_decompile | 0x2a2bc: copies three XOR ciphertext blocks to the heap and records lengths |
| `ev-000013` | static_decompile | 0x2b298: rewrites sin_addr after DNS resolution and sets sin_port=htons(1995) |
| `ev-000015` | static_decompile | 0x29cd0: its own DNS client (8.8.8[.]8:53, A-record resolution) |
| `ev-000016` | static_decompile | 0x2a35c: four-step XOR string decryption (equivalent 0x2E) |
| `ev-000018` | static_decompile | 0x2c5f8: strict IPv4 text parsing, must be NUL after the fourth octet |
| `ev-000020` | static_decompile | 0x23228: dispatch attack handlers by command byte lookup |
| `ev-000021` | static_decompile | 0x2b300: enumerate /proc/*/exe and kill(pid,9) by list |
| `ev-000022` | static_decompile | 0x2b570: enumerate /proc/*/maps and kill(pid,9) by list |
| `ev-000023` | static_decompile | 0x224a8: register 27 C2 command handlers |
| `ev-000024` | static_decompile | 0x29bec: xorshift PRNG random-string generation with a 32-character alphabet |
| `ev-000025` | static_decompile | 0x2342c: HTTP flood (random UA/path, GET/POST, random X-* headers) |
| `ev-000026` | static_decompile | 0x2a5c8: read /proc/self/exe and open itself for write/truncate |
| `ev-000027` | static_decompile | 0x298ac: sequence bswap + payload fed into HMAC, producing an 8-byte tag |
| `ev-000028` | static_decompile | 0x2b83c: fork child process and loop the kill functions |
| `ev-000029` | static_decompile | 0x2c19c: prctl (syscall 172) wrapper for PR_SET_NAME |
| `ev-000030` | static_decompile | 0x2c0d8: open wrapper, flags 0x241\|0x20000 (O_TRUNC self-truncation) |
| `ev-000031` | static_decompile | 0x2cb24: fork wrapper (syscall 2) |
| `ev-000032` | static_decompile | 0x29414: HMAC-SHA256 implementation |
| `ev-000033` | static_decompile | 0x2d028: sigaction wrapper, used in main to set multiple signal handlers |
| `ev-000034` | static_script | Script decrypts built-in strings with the four-step XOR and parses .rodata pointer tables (UA/path/amplification payloads) |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
