---
title: "Malware Sample Analysis: CatStorm (ELF · elf · 9e0eca4e)"
published: 2026-11-23
draft: false
description: "Malicious (confidence medium): CatStorm · botnet/miner · difficulty hard · dynamic sandbox + static decompilation"
tags: ["CatStorm", "botnet", "miner", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-23-CatStorm-9e0eca4e"
---

> [!WARNING]
> **Verdict: Malicious** · Family **CatStorm** (doubtful) · Confidence **medium**
> 
> Aliases: CatStorm Go DDoS bot, catstorm/Bot
> 
> This file is a MIPS big-endian ELF compiled with Go 1.25.0, embedding a complete DDoS botnet source tree (catstorm/Bot/Methods/l4, l7, process) and a Monero mining module; main.main concatenates the hardcoded address 45.61.182[.]32 with port 9111 and then calls net.Dial (tcp) to establish a control channel, and upon receiving commands dispatches to more than ten attack methods such as ack/dns/syn/udp/tcp/http. During actual execution in the isolated instance, it was observed attempting to write autostart files with 0755 permissions (denied by non-root privileges) and creating an outbound TCP socket; the malicious intent and capability are jointly confirmed by static symbols, strings, and runtime events.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **CatStorm** · aliases CatStorm Go DDoS bot, catstorm/Bot · _doubtful_ |
| Confidence | **medium** |
| Behavior class | botnet · miner |
| Difficulty | hard |
| First seen | 2026-11-21 18:07:12 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/9e0eca4e0acbd39ecfe98ac9fedf1cf5ae0354a9cf92910a96daea5a6d293790/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Direct C2 port 9111</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Attempted autostart file write</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002, T1053.003</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Outbound TCP socket</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Parse C2 commands, launch DDoS</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1498.001, T1059.004</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Abuse DNS and protocol amplification</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1498.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `9e0eca4e0acbd39ecfe98ac9fedf1cf5ae0354a9cf92910a96daea5a6d293790` |
| MD5 | _not recorded_ |
| Size | 6,619,351 bytes (6.3 MB) |
| Type | ELF · `elf` |

## Behavior Analysis

**10** behaviors in total, each with attached evidence; **8** are statically available and **2** were obtained through dynamic analysis.

### 1. Direct connection to C2 port 9111

`T1095` · confidence **high** · static

Loads the global strings 45.61.182[.]32 and 9111 from the read-only data section, concatenates them with a single-byte colon into 45.61.182[.]32:9111, then calls net.Dial with tcp as the network type to establish a control channel.

> **Evidence**: main.main 0x2f72d0 loads 0x64b478(45.61.182[.]32), 0x2f7490 loads 0x64b480(9111); 0x2f74b0-0x2f74cc calls runtime.concatstring3 with a colon (0x47d6d0); 0x2f7560 jal net.Dial, network=tcp@0x3ff270
> 
> **Source**: `ref:240e5980c7` · `ref:94457dd902` · `ref:0f43eeb107` · `ref:6372a6d1d7`

### 2. Attempted write of autostart file

`T1543.002, T1053.003` · confidence **high** · dynamic

At runtime, it opens and truncates a target file with 0755 permissions to drop a persistent copy, returning EACCES because it runs as an ordinary user; statically this corresponds to process.Persist through installSystemd copying itself to /lib/systemd/systemd-update and writing /etc/systemd/system/bot-update.service.

> **Evidence**: strace openat(AT_FDCWD, <path>, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0755) = -1 EACCES; process.Persist @0x2f50a0, installSystemd @0x2f5a40, installCron @0x2f565c, installInitd @0x2f5c48
> 
> **Source**: `ref:f30404a690` · `ref:0113621c00` · `ref:719961b497` · `ref:bc6b4cbe26`

### 3. Outbound TCP socket initiation

`T1095` · confidence **high** · dynamic

At runtime, it creates an AF_INET TCP socket and performs IPv6/IPv4 bind probing; under network namespace isolation no connect session to the C2 was completed; the static chain points to 45.61.182[.]32:9111.

> **Evidence**: strace socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_TCP)=6, followed by bind(AF_INET6) probing and close; no successful connect record
> 
> **Source**: `ref:0eacbcdf2c` · `ref:f30404a690` · `ref:5e15e08a75`

### 4. Parse C2 commands and launch DDoS

`T1498.001, T1059.004` · confidence **high** · static

Uses bufio.Scanner to read text commands line by line from the C2 connection; after splitting with strings.Fields, main.startAttack dispatches them to 16 attack vectors (ack, dns, syn, udp, tcp, tcp-stomp, tcp-bypass, udp-bypass, http, http-bypass, discord, fortnite, minecraft, ssh, pps, udp-pps).

> **Evidence**: within main.main, bufio.NewScanner/(*Scanner).Scan/Text, then after strings.Fields, 16 calls to main.startAttack(0x2fe184); method strings @0x4005f9(tcp-stomp), 0x400d7c(tcp-bypass/udp-bypass), 0x40145f(http-bypass)
> 
> **Source**: `ref:59f4eeedbb` · `ref:fe348e2fae` · `ref:f473e500be` · `ref:80645b0e11`

### 5. Abuse of DNS and protocol amplification

`T1498.002` · confidence **high** · static

Embeds a DNS query pool (1.1.1[.]1/1.0.0[.]1/8.8.8[.]8/8.8.4[.]4/9.9.9[.]9:53) to construct DNS flood packets; it also contains Fortnite, Minecraft, Discord, and SSH protocol floods plus HTTP-layer floods with forged Referer, forming reflection/amplification denial of service.

> **Evidence**: l4.initDnsPool@0x2e75b8, l4.buildDnsPacket@0x2e6e8c, l4.Dnsflood@0x2e771c; resolver list @0x3ffcd7; l7.Httpflood@0x2edd2c and referenced search-engine Referer strings
> 
> **Source**: `ref:80645b0e11` · `ref:e0995d6202` · `ref:d281b5f1bc`

### 6. Multi-path boot persistence

`T1543.002, T1053.003, T1037.004` · confidence **high** · static

Achieves autostart after reboot and login through five paths: a systemd service unit (Description=System Update Service, Restart=always, WantedBy=multi-user.target), /etc/cron.d and @reboot scheduled tasks, an /etc/init.d script, /etc/rc.local, and an /etc/profile.d script; the init script stop branch executes killall systemd-update.

> **Evidence**: installSystemd@0x2f5a40/installCron@0x2f565c/installCronDir@0x2f590c/installInitd@0x2f5c48/installRcLocal@0x2f5e50/installProfile@0x2f6010; unit template @0x41757a; paths @0x4071c2, 0x40dac5, 0x40a2d5; @reboot root system-update @0x402038
> 
> **Source**: `ref:80645b0e11` · `ref:f2cff81ca2` · `ref:bc6b4cbe26` · `ref:8adf084f3e` · `ref:719961b497`

### 7. Masquerading as system process names

`T1036.005` · confidence **medium** · static

At runtime, it rewrites process identifiers such as /proc/self/comm, blending in with system/service names including kworker/0:0, amazon, github, gitlab, docker, python, and systemd; it also provides a Protect routine to stay alive and terminate old instances.

> **Evidence**: process.Hide@0x2f4c58 (references /proc/self/comm), process.Protect@0x2f6128; masquerade name pool @0x3ff94a, 0x401f00; killall systemd-update 2>/dev/null @0x417f2c
> 
> **Source**: `ref:80645b0e11` · `ref:4bec64fe11` · `ref:bc6b4cbe26`

### 8. Embedded XMRig mining

`T1496` · confidence **high** · static

Compiled into the MoneroMiner module, it references miner parameters such as xmrig-mips, stratum+tcp://, and --donate-level, and can start Monero mining under C2 command to consume the victim host's computing power.

> **Evidence**: catstorm/Bot/Methods.MoneroMiner@0x2e4bd0 (source monero.go); strings xmrig-mips/stratum+tcp:///--donate-level @0x3f0d9a, 0x3ff94a
> 
> **Source**: `ref:80645b0e11` · `ref:d281b5f1bc` · `ref:df341679cc`

### 9. Report host resource fingerprint

`T1082, T1016` · confidence **high** · static

Collects total memory, total disk, CPU count, and runtime statistics; after formatting with strconv, reports them to the C2 together with the REGISTER linux mips banner, for attack scheduling and profit assessment.

> **Evidence**: main.main calls process.GetTotalRAM@0x2f47f4, GetTotalDisk@0x2f4a94, runtime.NumCPU, strconv.FormatFloat; REGISTER linux mips @0x404ed0; MemTotal in /proc/meminfo @0x400614
> 
> **Source**: `ref:59f4eeedbb` · `ref:fe348e2fae` · `ref:df341679cc`

### 10. Download updates for itself

`T1105` · confidence **medium** · static

Embeds a downloader path pool (curl/wget/tftp/axel/sftp, etc.) and the /tmp/.upd staging path; together with UPDATE_OK/UPDATE_FAIL responses it implements remote update or payload replacement.

> **Evidence**: /tmp/.upd @0x40060b; downloader path pool @0x401fad, 0x402c18; UPDATE_OK/UPDATE_FAIL @0x3f0d90, 0x3f19d9
> 
> **Source**: `ref:719961b497` · `ref:df341679cc` · `ref:d281b5f1bc`


## IOC (Defanged)

### Network

:::caution
**Pending dynamic verification**: the above address was obtained from static analysis; under the analysis environment's network isolation, no successful connection or session was observed, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `45[.]61[.]182[.]32:9111` | 9111 | c2 | static | ⏳ Not observed |

### Host

**Drop paths**

- `/tmp/.google`
- `/tmp/.upd`
- `/tmp/.cron`
- `/lib/systemd/systemd-update`
- `/usr/lib/systemd/systemd-update`
- `/etc/systemd/system/bot-update.service`
- `/etc/cron.d/system-update`
- `/etc/init.d/system-update`
- `/etc/profile.d/system-update.sh`
- `/etc/rc.local`

**Service**

- `bot-update.service (Description=System Update Service)`

**Scheduled tasks**

- `crontab entry: @reboot root system-update`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `45[.]61[.]182[.]32` | yes | static |
| `c2_port` | `9111` | yes | static |
| `protocol_banner` | `REGISTER linux mips` | yes | static |
| `install_path` | `/tmp/.google` | yes | static |
| `persist_systemd_binary` | `/lib/systemd/systemd-update` | yes | static |
| `persist_systemd_unit` | `/etc/systemd/system/bot-update.service` | yes | static |
| `persist_cron` | `/etc/cron.d/system-update` | yes | static |
| `persist_initd` | `/etc/init.d/system-update` | yes | static |
| `persist_profile` | `/etc/profile.d/system-update.sh` | yes | static |
| `update_staging` | `/tmp/.upd` | no | static |
| `miner_binary` | `xmrig-mips` | no | static |
| `dns_flood_resolvers` | `1.1.1[.]1:53,1.0.0[.]1:53,8.8.8[.]8:53,8.8.4[.]4:53,9.9.9[.]9:53` | no | static |

## Do Not Misjudge

:::important
The following conclusions **are easily misjudged**; keep this in mind when citing this report.

- It must not be called ransomware or a wiper: no file encryption, shadow copy deletion, or disk-wiping logic was found.
- It must not be claimed to have worm-like auto-scanning and weak-password brute-force propagation capability: the sample contains no port scanning or Telnet/SSH brute-force modules.
- It must not be claimed that a C2 session was obtained or data was successfully sent back: only socket creation was observed in the isolated network, with no successful connect or session.
- It must not be claimed that persistence files were successfully dropped: the runtime environment was non-root, the autostart file write was denied with EACCES, and only the attempted behavior can be confirmed.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | No |

**Limitations and Open Questions**

1. The isolated network is fail-closed; no session was established with 45.61.182[.]32:9111, so the C2 protocol and reported content are reconstructed only from static strings and the call chain; the C2 entry is marked static and pending dynamic re-verification.
2. The execution instance was non-root and the autostart file write was denied (EACCES), so the actual autostart effect after persistence drop could not be verified.
3. The sample is MIPS architecture and ran in qemu user mode; instruction-level timing, anti-debugging, and the full command-processing loop were not fully covered.
4. The decompiler did not recover Go symbols (functions are identified as FUN_xxxx); function semantics are mainly corroborated by the embedded pclntab symbol table, string constants, and call sites.
5. No completed connect, DNS query, or HTTP request was observed at runtime; attack methods are confirmed only by code and constants and were not actually triggered in this analysis.

## Evidence Index

<details>
<summary>Expand 21 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:1427c4337a` | ELF structure parsing | ELF32 big-endian MIPS, ET_EXEC, containing Go sections such as .gopclntab/.go.buildinfo, with no dynamic dependencies |
| `ref:2372118766` | Hashes and fingerprints | md5=56c13363e44c382b329a64295879b68b, sha256=9e0eca4e...3790 |
| `ref:7d81fddf03` | scan.entropy | Overall entropy 5.565, .text 5.105, no high-entropy packing characteristics |
| `ref:e3259118d1` | String extraction | Extracted 15055 ASCII strings, including the Go standard library and plaintext constants |
| `ref:708f52c736` | String extraction | Go source path table: catstorm/Bot/Methods/l4/*.go, l7/http.go, process/linux.go, monero.go |
| `ref:80645b0e11` | String extraction | Named function table: Ackflood/Dnsflood/Synflood/Tcpbypassflood/Httpflood, Persist/installSystemd/installCron, MoneroMiner |
| `ref:a9a356fe4a` | script | Parsed Go pclntab to obtain 6139 functions and addresses: main.main=0x2f7178, process.Persist=0x2f50a0, MoneroMiner=0x2e4bd0, etc. |
| `ref:240e5980c7` | script | Within main.main, 0x2f72d0/0x2f7308/0x2f7490 load global string headers 0x64b478/0x64b480/0x64b488 respectively |
| `ref:94457dd902` | script | Decoded 0x2f7400-0x2f7560: concatstring3(45.61.182[.]32, colon, 9111) followed by jal net.Dial, network=tcp |
| `ref:0f43eeb107` | script | Full .text scan of jal targets: main.main 0x2f7560 calls net.Dial |
| `ref:59f4eeedbb` | script | main.main call list: bufio.Scanner, strings.Fields, 16 startAttack calls, GetTotalRAM/Disk, SetKeepAlive |
| `ref:fe348e2fae` | script | Literals referenced by main.main: REGISTER linux mips, tcp-stomp, tcp-bypass, http-bypass, /tmp/.google, attack method names |
| `ref:df341679cc` | script | Located constants such as REGISTER linux mips banner, xmrig-mips/stratum+tcp://, UPDATE_OK/UPDATE_FAIL, priv-flood |
| `ref:719961b497` | script | Persistence path constants: /etc/cron.d/system-update, /etc/init.d/system-update, /etc/systemd/system/bot-update.service, /etc/profile.d/system-update.sh, /lib/systemd/systemd-update |
| `ref:f2cff81ca2` | script | systemd unit template: [Unit] Description=System Update Service, Restart=always, WantedBy=multi-user.target |
| `ref:8adf084f3e` | script | crontab entry @reboot root system-update and /etc/rc.local references |
| `ref:bc6b4cbe26` | script | killall systemd-update 2>/dev/null script fragment and @reboot constant |
| `ref:784dac248f` | dyn.exec | Isolated instance qemu-mips execution, exit=1, network_isolated=true, no standard output |
| `ref:5e15e08a75` | dyn.trace | strace 2819 system calls: autostart file write EACCES, TCP socket creation, IPv6 bind probing |
| `ref:f30404a690` | dyn.trace | Full trace tail: openat(...O_WRONLY\|O_CREAT\|O_TRUNC,0755)=-1 EACCES; socket(AF_INET,SOCK_STREAM)=6; exit_group(1) |
| `ref:0eacbcdf2c` | dyn.trace | Network-related call filtering: socket/setsockopt/bind, no successful connect record appears |

</details>

---

_The sample in this report is not public; IOCs have been defanged and are provided for security research only._
