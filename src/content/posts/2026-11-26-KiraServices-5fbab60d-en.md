---
title: "Malicious sample analysis: KiraServices (ELF · elf · 5fbab60d)"
published: 2026-11-26
draft: false
description: "Malicious (confidence: medium): KiraServices · botnet/backdoor · difficulty hard · static decompilation (dynamic execution yielded no runtime behavior)"
tags: ["KiraServices", "botnet", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-26-KiraServices-5fbab60d"
---

> [!WARNING]
> **Verdict: malicious** · Family **KiraServices** (unconfirmed) · Confidence **medium**
> 
> Aliases: Self Rep botnet, NeTiS botnet
> 
> Static decompilation and instruction-level analysis show that this ARM64 static ELF has full remote-control/botnet capabilities: four persistence mechanisms (systemd, cron, init.d, rc.local), process-name masquerading and anti-debugging, a custom TCP task channel encrypted with ChaCha20, a Discord gateway WebSocket command channel, and self-propagation logic that filters private networks before connecting to public addresses. When executed in isolation the program exits silently at once because it is not root, so no real outbound traffic was captured, but the code paths and string evidence corroborate each other.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **KiraServices** · Aliases Self Rep botnet, NeTiS botnet · _unconfirmed_ |
| Confidence | **medium** |
| Behavior class | botnet · backdoor |
| Difficulty | hard |
| First seen | 2026-11-24 12:40:53 |
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/5fbab60d9b176dbed720219cd4ea5f0ee65978c03114e62250f5de1186ddc2a8/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypts built-in string table</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Detects debugging/injection env</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Masquerades as common daemons</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Installs systemd service persistence</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Writes cron boot task</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `5fbab60d9b176dbed720219cd4ea5f0ee65978c03114e62250f5de1186ddc2a8` |
| MD5 | _Not recorded_ |
| Size | 731,504 bytes (714.4 KB) |
| Type | ELF · `elf` |

## Behavior Analysis

There are **11** behaviors in total, each backed by evidence, and all are statically available.

### 1. Decrypts built-in string table

`T1027` · Confidence **high** · Static

The built-in index-addressed string table is XOR-decrypted byte by byte with a 4-byte key, yielding masquerade words such as KIRASERVICES/SHOP/INSIDE/FEMBOY; the main flow calls this decryption routine early in execution.

> **Evidence**: FUN_0040ddc0 @0x40ddc0 XOR decryption loop; string table 0x4c2568, key table 0x4c08f0; ciphertext 0x47a580 decrypts to KIRASERVICES with key 0x1a
> 
> **Source**: `ref:cc2b0b2c55`

### 2. Detects debugging and injection environment

`T1622` · Confidence **high** · Static

Reads TracerPid from /proc/self/status and calls ptrace(PTRACE_TRACEME) for a self-check, while also inspecting the LD_PRELOAD, LD_AUDIT, GDB and STRACE environment variables; on a hit it changes the execution path.

> **Evidence**: 0x40dc4c references /proc/self/status and compares TracerPid; 0x40dd58/0x40dd80/0x40dd90/0x40dda0 reference LD_PRELOAD/LD_AUDIT/GDB/STRACE; 0x42e820 calls ptrace
> 
> **Source**: `ref:62c85bd54c` · `ref:4e6108fb92`

### 3. Masquerades as common daemons

`T1036.005` · Confidence **high** · Static

Embeds a name list including httpd/nginx/apache/lighttpd/sshd/telnetd/uhttpd/mini_httpd/dropbear/systemd/kthreadd/kswapd/kworker, combined with /proc/<pid>/cmdline scanning, used to masquerade the process name or suppress similar processes.

> **Evidence**: 0x47a3e0~0x47a4a0 process name list; 0x499624 /proc/%d/cmdline; 0x47a310 charset used to generate random names
> 
> **Source**: `ref:62c85bd54c` · `ref:4e6108fb92`

### 4. Installs systemd service persistence

`T1543.002` · Confidence **high** · Static

Writes a [Unit]/[Service] template (ExecStart=self path, Restart=always, WantedBy=multi-user.target) to /etc/systemd/system/%s.service, then runs systemctl enable %s.service.

> **Evidence**: 0x47a090 /etc/systemd/system; 0x47a0a8 /etc/systemd/system/%s.service; 0x40c5e0~0x40c7a0 assembly and write; 0x47a158 systemctl enable
> 
> **Source**: `ref:4e6108fb92` · `ref:62c85bd54c`

### 5. Writes cron boot task

`T1053.003` · Confidence **high** · Static

Runs crontab -l to read existing tasks, appends '@reboot <self path> &' and writes it back, achieving autostart after reboot.

> **Evidence**: 0x47a1e0 crontab -l 2>/dev/null; 0x47a1f8 (crontab -l 2>/dev/null; echo '@reboot %s &') | crontab -; 0x40c870~0x40c8d0
> 
> **Source**: `ref:4e6108fb92` · `ref:62c85bd54c`

### 6. Deploys init.d and rc.local

`T1037.004` · Confidence **high** · Static

Generates an /etc/init.d/%s start/stop script (with a BEGIN INIT INFO header) and appends an autostart command to /etc/rc.local, covering environments without systemd.

> **Evidence**: 0x47a238 /etc/init.d, 0x47a248 /etc/init.d/%s, 0x47a350 /etc/rc.local; 0x40c8e0~0x40caa0
> 
> **Source**: `ref:4e6108fb92` · `ref:62c85bd54c`

### 7. Enumerates public addresses for self-spread

`T1595.001` · Confidence **medium** · Static

Picks addresses at random from a built-in address table, filters private and reserved ranges such as 127/8, 10/8, 172.16/12, 192.168/16, 100.64/10 and 169.254/16, and only opens TCP connections to public addresses, sending a 16-byte handshake packet, a worm-like propagation trait.

> **Evidence**: FUN_0040b9d0 @0x40b9d0 address selection; FUN_0040b860 @0x40b860 private/reserved range check; 0x40af00 socket, 0x40af38 connect, 0x40af54 send; port constant 0xDD19
> 
> **Source**: `ref:067e854d5d`

### 8. Encrypted task channel

`T1573.001` · Confidence **high** · Static

Uses ChaCha20 ('expand 32-byte k' constant, 20 rounds, ror 16/12/8/7) to encrypt and decrypt task payloads in the TCP session; the receiver first checks the 4-byte magic 0xD12C8F4A, then reads ciphertext by a 2-byte length and decrypts and dispatches it.

> **Evidence**: 0x481290 'expand 32-byte k'; FUN_0040b020 @0x40b020 initialization; FUN_0040b0b0 @0x40b0b0 stream encryption; main loop compares 0xD12C8F4A
> 
> **Source**: `ref:8bc013f2e4` · `ev-000005`

### 9. Discord gateway command channel

`T1102.002` · Confidence **medium** · Static

Embeds a complete Discord Gateway WebSocket handshake template (GET /?v=9&encoding=json, Host: gateway[.]discord[.]gg, Upgrade: websocket, Sec-WebSocket-Key/Version) and a browser User-Agent pool, indicating that a third-party instant messaging service carries the command channel.

> **Evidence**: 0x4793e8 GET /?v=9&encoding=json HTTP/1.1; 0x47940a Host: gateway[.]discord[.]gg; 0x4796a8 Sec-WebSocket-Key; 0x479360~0x479420 UA pool
> 
> **Source**: `ref:62c85bd54c`

### 10. Collects host fingerprint

`T1082` · Confidence **high** · Static

Reads /proc/cpuinfo to parse 'cpu cores', reads /proc/mounts and /proc/<pid>/cmdline, retrieves the hostname, and reports the results with the handshake packet, for victim profiling and target selection.

> **Evidence**: 0x47a590 /proc/cpuinfo, 0x499680 cpu cores, 0x47a5a0 /proc/mounts, 0x499624 /proc/%d/cmdline; the main function reads and reports them after the handshake
> 
> **Source**: `ref:62c85bd54c` · `ev-000005`

### 11. Requires root to run

`T1078.003` · Confidence **medium** · Static

At startup it requires getuid==0; in a non-root environment initialization fails and it returns silently, reflecting a deployment premise aimed at root privileges on embedded devices/servers.

> **Evidence**: FUN_004005f0 @0x4005f0 starts by calling FUN_0042b0a0 (getuid-like) and requires a return of 0; when run with uid 1000 in isolation, exit=0 with no output
> 
> **Source**: `ev-000005` · `ev-000006`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: The above addresses come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `runtime-selected public IPv4 from encrypted bootstrap list (private/loopback ranges filtered)` | 6621 | c2 | Static | ⏳ Not observed |
| http | `gateway[.]discord[.]gg` | 80 | c2 | Static | ⏳ Not observed |

### Host

**Drop paths**

- `/etc/systemd/system/%s.service`
- `/etc/init.d/%s`
- `/etc/rc.local`
- `/dev/shm/`
- `/var/tmp/`
- `/var/run/`
- `/usr/local/bin/`

**Services**

- `<name>.service (systemd, ExecStart=<self>, Restart=always, WantedBy=multi-user.target)`

**Scheduled tasks**

- `@reboot <self> & (crontab)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `encrypted IPv4 bootstrap list, decrypted at runtime; only public addresses selected` | Yes | Static |
| `c2_port` | `6621 (0x19DD)` | Yes | Static |
| `protocol` | `TCP: 16-byte handshake, 4-byte magic 0xD12C8F4A, 2-byte length, ChaCha20-encrypted payload` | Yes | Static |
| `encryption_algo` | `ChaCha20 (20 rounds, 'expand 32-byte k')` | Yes | Static |
| `discord_gateway` | `gateway[.]discord[.]gg` | No | Static |
| `persistence_mechanisms` | `systemd service, crontab @reboot, /etc/init.d script, /etc/rc.local` | Yes | Static |
| `masquerade_names` | `httpd,nginx,apache,lighttpd,sshd,telnetd,uhttpd,mini_httpd,dropbear,systemd,kthreadd,ksoftirqd,kswapd,kworker` | No | Static |
| `campaign_id` | `KIRASERVICES` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not classify it as ransomware: ChaCha20 is used only for string and C2 channel encryption, and no file encryption, extension rewriting or ransom note was found.
- Do not assert that outbound traffic or DDoS actually occurred: the restricted environment had no network and was non-root, the program exited silently at startup, and no connections, sessions or attack traffic were captured.
- Do not apply a definite family name outright: KiraServices is a candidate name derived from the embedded campaign string and still lacks multi-engine or YARA corroboration.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Unpacking | No |

**Limitations and pending verification**

1. Isolated execution ran as a non-root user, and the program exited right after the root check (no output, no network events), so no runtime behavior evidence was obtained; all conclusions are based on static decompilation and instruction-level analysis.
2. The C2 address comes from an IPv4 list decrypted at runtime and could not be recovered; port 6621 was derived from the sockaddr write instruction, and a byte-order interpretation error is possible.
3. The Discord gateway is only static string evidence; no bot token or channel ID plaintext was seen, so it cannot be confirmed that this channel was actually enabled in this sample.
4. No vendor engine or YARA hit was obtained; the family name is provisional based on the embedded campaign string and needs external intelligence review.

## Evidence Index

<details>
<summary>Expand 9 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000004` | String extraction | Extracted 1,419 ASCII strings, hitting the Discord gateway handshake template, HTTP client template, systemd/cron/init.d/rc.local persistence templates, process name list and anti-debugging keywords |
| `ev-000005` | decompile.ghidra | Decompiled the main function FUN_004005f0: root check, socket/select main loop, ChaCha20 decryption and command dispatch |
| `ev-000006` | emu.qemu | Isolated ARM64 emulation execution, exit=0, no stdout/stderr, confirming the silent non-root exit |
| `ref:015d4e8403` | ELF structure parsing | AARCH64 EXEC, statically linked, entry=0x401100, no interp/DT_NEEDED |
| `ref:ce9e2566b8` | elf.sections | .text 495KB entropy 6.53, .rodata 116KB entropy 4.57, no packing features |
| `ref:4e6108fb92` | disasm.refs | Instruction-level reference map: persistence templates, /proc/self/status, LD_PRELOAD/LD_AUDIT/GDB/STRACE reference addresses |
| `ref:8bc013f2e4` | scan.rodata | 'expand 32-byte k' at 0x481290 and the 32-byte key at 0x481560, confirming ChaCha20 |
| `ref:067e854d5d` | disasm.range | Private/reserved range filtering at 0x40b860 and the socket/connect/send propagation logic from 0x40af00 |
| `ref:cc2b0b2c55` | script.xor | Single-byte XOR solving on the ciphertext at 0x47a580; key 0x1a yields words such as KIRASERVICES/SHOP/INSIDE/FEMBOY |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
