---
title: "Malware Analysis: Mirai (Sakura variant) (ELF · elf · da8a16ad)"
published: 2026-11-08
draft: false
description: "Malicious (medium confidence): Mirai (Sakura variant) · botnet · difficulty medium · Static decompilation (Linux dynamic execution produced no runtime behavior)"
tags: ["Mirai", "botnet", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-08-Mirai-Sakura-variant-da8a16ad"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Mirai (Sakura variant)** · Confidence **medium**
> 
> Aliases: Sakura_Bot, Sakura botnet, Mirai.Sakura
> 
> Decompilation confirms the program is a Linux/PowerPC Mirai-lineage DDoS botnet client: hardcoded C2 92.119.165[.]164:12345; after connecting it reports the local IP/port/architecture, receives remote commands starting with '!' and spawns TCP/UDP/VSE/DNS/CLDAP/LDAP/DISCORD attack threads, using raw sockets and forged source addresses. The source file name Sakura_Bot.c matches Mirai's standard function set (initConnection/processCmd/ftcp/atcp/dnsattack/getRandomIP/makeIPPacket, etc.).

## Overview

| Item | Content |
|:--|:--|
| Family | **Mirai (Sakura variant)** · aliases Sakura_Bot, Sakura botnet, Mirai.Sakura |
| Confidence | **medium** |
| Behavior class | botnet |
| Difficulty | medium |
| First seen | 2026-11-07 08:27:31 |
| Analysis method | Static decompilation (Linux dynamic execution produced no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/da8a16ad477f6f8cce793c18b2c9dcbea9e8ff745e973bdef164de398fdd2a60/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Double-fork, detach from TTY</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Hardcoded C2 reconnect</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Check-in leaks identity</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Probe local network identity</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1016</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Identify available service ports</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `da8a16ad477f6f8cce793c18b2c9dcbea9e8ff745e973bdef164de398fdd2a60` |
| MD5 | _not recorded_ |
| Size | 101,468 bytes (99.1 KB) |
| Type | ELF · `elf` |

## Behavior analysis

**11** behaviors in total, each backed by evidence, and all statically available.

### 1. Double-fork, detach from TTY

`T1564` · Confidence **high** · static

main forks twice in a row and the parent exits; the child calls setsid, chdir("/"), sets SIGHUP(0xd) to ignore, and continues running as a background daemon.

> **Evidence**: main @ 0x100083b0: fork; waitpid/exit; fork; exit; setsid; chdir("/"); signal(0xd, 1)
> 
> **Source**: `ev-000005`

### 2. Hardcoded C2 reconnect

`T1095` · Confidence **high** · static

initConnection reads "92.119.165[.]164:12345" from commServer[0], splits out the port on the colon, and establishes a TCP connection (30-second timeout); after a connection failure or disconnect the main loop sleeps 5 seconds and reconnects repeatedly.

> **Evidence**: initConnection @ 0x10008210: socket(2,1,0)+connectTimeout(...,0x1e); commServer symbol @ 0x10023370 → 0x10010b10 "92.119.165[.]164:12345"
> 
> **Source**: `ev-000006` · `call:call_8634c51fc2c4465ea34515bd` · `call:call_df4db7dd57a94a838b0b0d27`

### 3. Check-in leaks identity

`T1082` · Confidence **high** · static

After connecting it uses sockprintf to send "[1;95mDevice Connected: %s | Port: %s | Arch: %s", containing the local IP, the port judged exploitable (22 or Unknown Port) and the architecture name "Ppc".

> **Evidence**: main @ 0x100083b0 calls sockprintf (format string @0x100114c4); getArch @ 0x10005ff8 returns 0x100113f8 "Ppc"; getPortz @ 0x10006020 returns "22"/"Unknown Port"
> 
> **Source**: `ev-000005` · `ev-000011` · `ev-000012`

### 4. Probe local network identity

`T1016` · Confidence **high** · static

getOurIP UDP-connects to 8.8.8[.]8:53 and then getsockname to obtain the egress IP, reads /proc/net/route to find the default-route interface, and then uses ioctl(SIOCGIFHWADDR, 0x8927) to obtain the MAC address.

> **Evidence**: getOurIP @ 0x100005d0: inet_addr("8.8.8[.]8"), htons(0x35), open("/proc/net/route"), ioctl(fd,0x8927,...)
> 
> **Source**: `ev-000008`

### 5. Identify available service ports

`T1082` · Confidence **high** · static

getPortz uses access to check /usr/bin/python, /usr/bin/python3, /usr/bin/perl and /usr/sbin/telnetd in turn; if any exists it reports port 22, otherwise it reports Unknown Port, telling the C2 which services on the host are exploitable.

> **Evidence**: getPortz @ 0x10006020: access("/usr/bin/python"), "/usr/bin/python3", "/usr/bin/perl", "/usr/sbin/telnetd" → "22"/"Unknown Port" (strings @0x10011404/0x10010f28)
> 
> **Source**: `ev-000011` · `ev-000004`

### 6. Parse exclamation-mark commands

`T1095` · Confidence **high** · static

The main loop uses recvLine to read C2 data; only when the first character is '!' does it split the first token on spaces as the attack method name, uppercase it, and pass the remaining tokens as parameters to processCmd for dispatch.

> **Evidence**: main @ 0x100083b0: acStack_1058[0]=='!'、toupper、strtok(" ")、processCmd(local_10b0, local_1080)
> 
> **Source**: `ev-000005` · `ev-000007`

### 7. Spawn TCP/UDP floods

`T1498.001` · Confidence **high** · static

After parameter validation for TCP/UDP commands, processCmd calls listFork to spawn attack child processes that run ftcp/SendUDP, using raw sockets with random source addresses/random source ports to continuously send packets, supporting comma-separated multiple targets.

> **Evidence**: processCmd @ 0x10006120: strcmp("TCP")→ftcp @ 0x100025ac; strcmp("UDP")→SendUDP @ 0x10002130; listFork+_exit(0) each time
> 
> **Source**: `ev-000007`

### 8. Three reflection-amplification protocols

`T1498.002` · Confidence **high** · static

Built-in DNS, CLDAP and LDAP reflection-amplification attacks: it builds query payloads and loops with getRandomIP to forge source addresses, makeIPPacket to assemble packets and sendto to the target, producing reflected/amplified traffic.

> **Evidence**: dnsattack @ 0x100052b0: build_dns_query + getRandomIP + makeIPPacket + sendto; cldapattack @ 0x10005654; ldapattack @ 0x10005a30; build_ldap_search @ 0x10005dd4; build_dns_query @ 0x10004fb4
> 
> **Source**: `ev-000010` · `call:call_a2ced84f066c4731b0184084`

### 9. VSE protocol amplification attack

`T1498.002` · Confidence **high** · static

Built-in VSE attack (Valve Source Engine query amplification): it uses the "TSource Engine Query" payload to build UDP packets and, together with random source addresses, sends them to the target game/query port.

> **Evidence**: vseattack @ 0x10002f38 + makevsepacket @ 0x10002eec; vse_payload @ 0x10010ebc = "TSource Engine Query rfdknjms"
> 
> **Source**: `call:call_df4db7dd57a94a838b0b0d27` · `call:call_a2ced84f066c4731b0184084`

### 10. Send packets with forged source addresses

`T1498.001` · Confidence **high** · static

All flood/reflection functions share getRandomIP to generate random source IPs (optionally mask-limited), and makeIPPacket/csum/tcpcsum assemble the IP/UDP/TCP packets and checksums themselves, demonstrating source-address forgery capability.

> **Evidence**: getRandomIP @ 0x10000478; makeIPPacket @ 0x10002044; csum @ 0x10001e00; tcpcsum @ 0x10001f40; discordattack uses getRandomIP(...)+makeIPPacket(...)+csum(...)
> 
> **Source**: `ev-000009` · `call:call_a2ced84f066c4731b0184084`

### 11. DISCORD voice flood

`T1498.001` · Confidence **high** · static

discordattack uses destination port 443 (0x1bb) by default, a raw UDP socket, random source IPs, and an 8-byte fixed payload "discord_payload" plus random padding to continuously send forged-source packets to the target.

> **Evidence**: discordattack @ 0x10005c4c: param_2==0 → 0x1bb; memcpy(buf+0x1c, &discord_payload_6464, 8); getRandomIP + sendto loop
> 
> **Source**: `ev-000009`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; under the analysis environment's network isolation no successful connection or session was observed, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `92.119.165[.]164` | 12345 | c2 | static | ⏳ not observed |

### Host

- **No host IOCs recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `92.119.165[.]164` | yes | static |
| `c2_port` | `12345` | yes | static |
| `transport` | `raw TCP (SOCK_STREAM), 30-second connect timeout, 5-second reconnect after disconnect` | yes | static |
| `c2_protocol` | `plaintext line protocol; only commands starting with '!' are handled, parameters are space-separated and only case-normalized` | yes | static |
| `attack_methods` | `TCP,UDP,VSE,STDHEX,STD,NFODROP,OVHKILL,XMAS,CRUSH,STOMP,STOP,PPS,DNS,CLDAP,LDAP,DISCORD` | no | static |
| `campaign_marker` | `dayzddos.co` | no | static |
| `embedded_user_agents` | `Chrome 44/46/60/63/69, 7 Mozilla/5.0 strings in total (Windows NT 10.0/6.1/5.1, X11 Linux)` | no | static |
| `encryption_algo` | `null (no AES/SHA/MD5/TEA/CRC/Base64 cryptographic constants found)` | no | static |
| `install_path` | `-` | no | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not classify it as a stealer, ransomware or miner: the decompilation contains no credential reads, file encryption, wallet/pool or data-exfiltration logic; its core capability is remotely controlled DDoS attacks.
- Do not claim a persistence mechanism exists: the program only daemonizes via fork/setsid/chdir, and no autostart writes, cron, rc.local, service registration or self-copy code were found; if persistence exists it can only come from an external delivery chain, not the sample itself.
- Do not claim a confirmed C2 check-in or real network session: the C2 configuration comes from static strings/pointers, cross-architecture emulation obtained no successful connection or any response, and the C2's recoverability must remain static.
- Do not treat it as a general remote-control backdoor: the command set is limited to the built-in flood/reflection methods, with no shell execution, file upload/download or arbitrary command execution implementation.
- Do not apply a Windows host-IOC template: this sample is a 32-bit big-endian PowerPC Linux ELF and creates no registry keys, Windows services, scheduled tasks or mutexes.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (Linux dynamic execution produced no runtime behavior) |
| Unpacking | No |

**Limitations and pending verification**

1. The sample architecture is 32-bit big-endian PowerPC and cannot run natively in the x86 hardened execution environment; after cross-architecture emulation started, no observable output was produced before the timeout, and no real C2 connection, command interaction or attack traffic was obtained.
2. C2 92.119.165[.]164:12345 is confirmed only by static strings and the commServer pointer, not verified by a dynamic session, so it is marked static with pending_dynamic_verify=true.
3. The latter part of the processCmd decompilation output was truncated, and the specific dispatch code for DNS/CLDAP/LDAP/DISCORD/PPS/STOMP commands was not expanded one by one; their binding was cross-confirmed by command strings, function symbols and the dnsattack/discordattack implementations.
4. No persistence or download/update module was observed; it cannot be ruled out that the scanner or loader script delivering this ELF provides persistence externally.
5. No real egress was performed, and all network indicators were statically recovered; the embedded Mozilla User-Agent strings exist only as masquerading constants, and no corresponding HTTP client logic was found.

## Evidence index

<details>
<summary>Expand 12 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | string extraction | String-extraction hits (including alphabet constants), confirming non-encrypted resources |
| `ev-000004` | string extraction | ASCII 1045 entries / UTF16LE 2 entries; includes C2, User-Agent, attack method names, telnetd paths, etc. |
| `ev-000005` | decompile.function | Decompile main @ 0x100083b0: daemonization, C2 connection, banner reporting, '!' command loop |
| `ev-000006` | decompile.function | Decompile initConnection @ 0x10008210: commServer selection, colon port split, socket+connectTimeout(30s) |
| `ev-000007` | decompile.function | Decompile processCmd @ 0x10006120: TCP/UDP/VSE/STDHEX/STD/NFODROP/OVHKILL/XMAS/CRUSH command branches and listFork |
| `ev-000008` | decompile.function | Decompile getOurIP @ 0x100005d0: 8.8.8[.]8 UDP probe, /proc/net/route, ioctl MAC retrieval |
| `ev-000009` | decompile.function | Decompile discordattack @ 0x10005c4c: default 443, forged source IP, raw UDP send loop |
| `ev-000010` | decompile.function | Decompile dnsattack @ 0x100052b0: build_dns_query+getRandomIP+makeIPPacket reflection amplification |
| `ev-000011` | decompile.function | Decompile getPortz @ 0x10006020: python/python3/perl/telnetd existence probe, reports 22 |
| `ev-000012` | decompile.function | Decompile getArch @ 0x10005ff8: returns "Ppc" |
| `call:call_a2ced84f066c4731b0184084` | decompile.symbols | 228 functions and a string list: confirms the Mirai function set, attack function entry points and attack method constants |
| `call:call_8634c51fc2c4465ea34515bd` | script | Parses .symtab/.sdata: commServer@0x10023370 has only 1 entry pointing to 0x10010b10 "92.119.165[.]164:12345"; currentServer@0x10023374 initial value -1; no execve/system/unlink symbols |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
