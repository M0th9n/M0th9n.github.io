---
title: "Malware sample analysis: Prometei (ELF · elf · 7eca6c6a)"
published: 2026-11-23
draft: false
description: "Malicious (high confidence): Prometei · botnet/miner/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Prometei", "botnet", "miner", "downloader", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-23-Prometei-7eca6c6a"
---

> [!WARNING]
> **Verdict: malicious** · Family **Prometei** · Confidence **high**
> 
> Aliases: Prometei botnet, PROMETEI, Prometei miner
> 
> The sample is a UPX-packed Linux x86-64 program. Once unpacked it contains a complete P2P/CGI C2 client, crontab and systemd persistence code, a module download interface, and mining control commands; it hardcodes the prometei.cgi Tor/I2P/CGI endpoints and, in the isolated dynamic environment, actually started, attempted to write crontab, modify /etc/hosts, and listen on TCP/89. Static and dynamic evidence corroborate each other, so it is judged malicious.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Prometei** · aliases Prometei botnet, PROMETEI, Prometei miner |
| Confidence | **high** |
| Behavior class | botnet · miner · downloader |
| Difficulty | medium |
| First seen | 2026-11-22 22:29:53 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/7eca6c6addbaa2a42e035427ad71a131c994acf3d07cebe7a381657630403d8f/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Self-extracting UPX payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Read node config</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Callback to CGI C2</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Parse CMDv2 commands</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Listen on port 89</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `7eca6c6addbaa2a42e035427ad71a131c994acf3d07cebe7a381657630403d8f` |
| MD5 | _not recorded_ |
| Size | 449,079 bytes (438.6 KB) |
| Type | ELF · `elf` |

## Behavior Analysis

**12** behaviors in total, each backed by evidence; **7** are statically available and **5** were obtained through dynamic analysis.

### 1. Self-extracting UPX payload

`T1027` · confidence **high** · dynamic

The sample is packed with UPX 4.2.4; after startup it reads itself from /proc/self/exe and the entry stub decompresses the approximately 1.29MB static ELF main body, then mprotects the code segment as executable.

> **Evidence**: packed entry 0x15EB650; dynamic trace: mmap(0x401000,1049681) + mprotect(PROT_READ|PROT_EXEC)
> 
> **Sources**: `ev-000017` · `ev-000011`

### 2. Read node configuration

`T1027` · confidence **high** · static

Parses the appended JSON configuration (config/id/enckey/ParentId/ip/ParentIp/ParentHostname) and locates itself and the configuration via /proc/<pid>/exe, /usr/sbin/uplugplay, /etc/uplugplay.

> **Evidence**: '/proc/%d/exe' in FUN_00425fcb @0x425fcb; JSON at file offset 0x6d8f0
> 
> **Sources**: `ev-000059` · `ev-000012`

### 3. Callback to CGI C2

`T1071.001` · confidence **high** · static

Sends an HTTP GET /cgi-bin/p.cgi?r=0&auth=hash&i=<id>&enckey=<blob> to the C2 and completes node authentication using an auth token computed with SHA-256 and a base64 enckey.

> **Evidence**: FUN_0041a8b4 @0x41a8b4; string 0x502aa0
> 
> **Sources**: `ev-000013` · `ev-000059` · `ev-000008`

### 4. Parse CMDv2 commands

`T1071.001` · confidence **high** · static

The P2P session reads command frames starting with '_CMDv2_;<len>:' and dispatches them (configuration update, module delivery, mining start/stop), while exchanging node information through the HTTP/1.1 info header.

> **Evidence**: FUN_0042076d @0x42076d; string 0x502f69 '_CMDv2_;%d:'
> 
> **Sources**: `ev-000014` · `ev-000062`

### 5. Listen on port 89

`T1571` · confidence **high** · dynamic

After startup it creates a TCP socket and attempts to bind 0.0.0[.]0:89 and listen(4096) to receive peer commands as a P2P node; under unprivileged execution, bind returns EACCES.

> **Evidence**: dynamic trace: bind(sin_port=htons(89), 0.0.0[.]0) = -EACCES; listen(22,4096)
> 
> **Sources**: `ev-000017` · `ev-000058`

### 6. Write cron autostart

`T1053.003` · confidence **high** · dynamic

Executes crontab -l, constructs '@reboot <self> -cron' (task.cron) and writes it back with crontab -, attempting to run automatically after reboot; the dynamic environment was denied due to /var/spool/cron permissions.

> **Evidence**: FUN_00423701 @0x423701; dynamic stderr: crontabs/analyst/: fopen: Permission denied
> 
> **Sources**: `ev-000015` · `ev-000017`

### 7. Install systemd service

`T1543.002` · confidence **high** · static

Generates /lib/systemd/system/uplugplay.service (Description=UPlug, Type=forking, ExecStart=/usr/sbin/uplugplay) and calls systemctl daemon-reload/enable/start/stop to manage the service.

> **Evidence**: strings 0x424095 '[Unit]', 0x4241a5 '/lib/systemd/system/uplugplay.service', systemctl command strings
> 
> **Sources**: `ev-000005`

### 8. Tamper with hosts file

`T1565.001` · confidence **high** · dynamic

During execution it opens /etc/hosts with O_WRONLY|O_CREAT|O_APPEND, intending to write domain mappings; the dynamic environment returned EACCES due to lack of privileges.

> **Evidence**: dynamic trace: openat('/etc/hosts', O_WRONLY|O_CREAT|O_APPEND) = -EACCES
> 
> **Sources**: `ev-000017` · `ev-000062`

### 9. Download and deliver modules

`T1105` · confidence **medium** · static

The built-in HTTP client/server supports Content-disposition attachment delivery, fgetnormal and sha256hash verification, and can pull Prometei modules from the C2 and deliver them.

> **Evidence**: strings 0x502d38 'Content-disposition: attachment; filename=%s', 0x502ccf 'fgetnormal', 0x502db8 'sha256hash: %s'
> 
> **Sources**: `ev-000062` · `ev-000013`

### 10. Control mining tasks

`T1496` · confidence **medium** · static

Implements start_mining/stop_mining commands and reads /proc/stat, CPU and memory information; the code constructs HashPowerProject-related hash constants for mining submodule control.

> **Evidence**: strings 0x502f5b 'start_mining', 0x503199 'stop_mining'; FUN_00410a6b @0x410a6b
> 
> **Sources**: `ev-000062` · `ev-000066`

### 11. Collect host fingerprint

`T1082` · confidence **high** · static

Reads /etc/os-release, /etc/redhat-release, /etc/debian_version, /proc/cpuinfo, /proc/meminfo and /etc/resolv.conf, and calls hostnamectl/dmidecode to collect hardware and virtualization information, which is sent back in the info header.

> **Evidence**: strings 0x502xxx; the 'info: %s,%s\\%s,...' header of FUN_0042076d
> 
> **Sources**: `ev-000062` · `ev-000014`

### 12. Masquerade as legitimate process names

`T1036.005` · confidence **high** · dynamic

At startup it checks /usr/sbin/msdtc, msdtc2 and msdtc3, and masquerades or maintains compatibility using names such as uplugplay/upnpsetup/walker/updatecheckerd/pdefenderd/crashdump; dynamic observation recorded openat on /usr/sbin/msdtc*.

> **Evidence**: dynamic trace: openat('/usr/sbin/msdtc')/msdtc2/msdtc3 = ENOENT; service name list 0x42478c
> 
> **Sources**: `ev-000017` · `ev-000005`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; with the analysis environment's network isolated, no successful connection or session was observed, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://45[.]55[.]121[.]171/cgi-bin/p.cgi` | 80 | c2 | static | ⏳ not observed |
| http | `hxxp://103[.]176[.]111[.]176/cgi-bin/p.cgi` | 80 | c2 | static | ⏳ not observed |
| other | `hxxps://gb7ni5rgeexdcncj[.]onion/cgi-bin/prometei.cgi` | 443 | c2 | static | ⏳ not observed |
| other | `hxxp://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq[.]b32[.]i2p/cgi-bin/prometei.cgi` | 80 | c2 | static | ⏳ not observed |

### Host

**Drop paths**

- `/usr/sbin/uplugplay`
- `/etc/uplugplay`
- `/etc/CommId`
- `/lib/systemd/system/uplugplay.service`
- `/etc/hosts`
- `/tmp/debug.txt`
- `/etc/pcc0`
- `/etc/pcc1`
- `.ssh/pcc0`

**Services**

- `uplugplay.service`
- `Process masquerade names: uplugplay, upnpsetup, walker, netwalker, updatecheckerd, pdefenderd, crashdump, msdtc, msdtc2, msdtc3, smcard, smcard2, zsvc, nvsync`

**Scheduled tasks**

- `crontab: @reboot <self> -cron (task.cron)`
- `systemd: uplugplay.service (Type=forking, ExecStart=/usr/sbin/uplugplay)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `45[.]55[.]121[.]171; 103[.]176[.]111[.]176; gb7ni5rgeexdcncj[.]onion; mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq[.]b32[.]i2p` | yes | static |
| `c2_port` | `80 (HTTP); 443 (onion); local P2P listen 89` | no | static |
| `c2_uri` | `/cgi-bin/p.cgi; /cgi-bin/prometei.cgi` | yes | static |
| `node_id` | `IBQulJI4geplOAxw` | yes | static |
| `parent_id` | `3NM4VHR5SU73YP72HV` | yes | static |
| `parent_host` | `192[.]168[.]2[.]8 (W19-DC01)` | no | static |
| `enckey` | `base64 blob (128/129 bytes), used for the auth=hash&enckey= handshake` | yes | static |
| `encryption_algo` | `SHA-256 (auth=hash) + base64-encoded enckey` | no | static |
| `version` | `v4.42V_Unix64` | no | static |
| `install_paths` | `/usr/sbin/uplugplay; /etc/uplugplay; /lib/systemd/system/uplugplay.service` | no | static |
| `persistence` | `crontab @reboot <self> -cron; systemd uplugplay.service` | no | static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not assert that a session with the real C2 was established merely because prometei.cgi and p.cgi are hardcoded; this time only listening and connection logic was observed, and no complete HTTP request/response was obtained.
- Do not treat 192.168.2[.]8 / W19-DC01 as a public C2; it is the parent node/internal host information in the configuration.
- Do not claim that crontab was successfully written or that a systemd service was created; the dynamic run executed as an unprivileged user, and the relevant writes were rejected by the system.
- Do not treat HashPowerProject as a confirmed mining pool domain or wallet; no stratum address or wallet address was extracted.
- Do not misjudge it as a mere UPX packer or generic downloader; the unpacked main body contains complete P2P/C2, persistence and mining control logic.
- Do not take the dynamic bind EACCES as the absence of network behavior; the network namespace was isolated, and no successful outbound connection was seen.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | Yes (stage2 `7d544e1c6d2e27906d3164c506d6778f901ea959d4d8b7e8a0f6b3cf6cef7c7a`) |

**Limitations and pending verification**

1. The dynamic run executed as the unprivileged analyst user; crontab/systemd writes were rejected, so the full successful path of reboot persistence could not be verified.
2. The network was in an isolated namespace; only socket/bind and connection logic was observed, with no successful connect or HTTP session obtained; all C2s are marked static and pending_dynamic_verify.
3. The enckey in the configuration is a base64 blob (about 128 bytes), and its exact decryption/signing purpose has not been fully recovered.
4. No mining pool address, wallet address or standalone mining submodule was obtained; start_mining/stop_mining only proves command capability.
5. The sample removed section headers and appended a JSON overlay after the UPX stream, so standard UPX tools must truncate the overlay before unpacking; the unpacked output was used only for static analysis.
6. No successful C2 session was observed, so it cannot be confirmed that the current C2 infrastructure is still online.

## Evidence Index

<details>
<summary>Expand 19 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000059` | String extraction | Appended JSON configuration extracted from the end of the original sample (id/enckey/ParentId/ip/ParentIp/ParentHostname) |
| `ev-000060` | String extraction | Overview of original sample strings, including the UPX 4.24 marker and configuration JSON |
| `ev-000001` | String extraction | ASCII strings and flag regex sampling from the original sample |
| `ev-000017` | dyn.exec | Isolated dynamic run: stdout Starting.../Usermode install...Fail; stderr crontab permission denied; trace shows bind 0.0.0[.]0:89 |
| `ev-000058` | dyn.exec | Isolated dynamic run reproduced, confirming the crontab persistence attempt and TCP/89 listening loop |
| `b4723d4005` | dyn.trace | strace trace: reads its own ELF, checks /usr/sbin/msdtc*, writing /etc/hosts denied, reads /etc/CommId, looks for the uplugplay path |
| `ev-000012` | decompile.ghidra | Decompiled main function 0x425fcb: config/path parsing, cron/systemd installation, command dispatch, mining control |
| `ev-000013` | decompile.ghidra | Decompiled 0x41a8b4: CGI C2 handshake with auth=hash and enckey usage |
| `ev-000014` | decompile.ghidra | Decompiled 0x42076d: P2P connection, info header, _CMDv2_ command frame parsing |
| `ev-000015` | decompile.ghidra | Decompiled 0x423701: crontab -l / @reboot ... -cron / crontab - persistence |
| `ev-000062` | String extraction | Unpacked main body strings: C2 URI templates, start_mining/stop_mining, systemd/cron, fingerprint collection |
| `ev-000066` | decompile.ghidra | Decompiled 0x410a6b: HashPowerProject-related hash constant construction |
| `ev-000011` | decompile.ghidra | Entry _start and __libc_start_main call |
| `ev-000005` | String extraction | Overview of unpacked main body strings: systemd unit, service name list, masquerade/persistence paths |
| `ev-000008` | Crypto constant identification | SHA-256 constant hits, supporting auth=hash and sha256hash verification |
| `ev-000010` | Crypto constant identification | base64 alphabet hits, supporting enckey encoding |
| `0769cd66e8` | unpack/upx script | Truncated the UPX trailer, appended the JSON overlay and unpacked successfully, obtaining a 1,288,624-byte main body |
| `ffc7d39167` | Hashing and fingerprinting | Original sample sha256/md5/sha1 and size |
| `afc547daf7` | ELF structure parsing | Original sample ELF structure: x86-64 EXEC, double UPX LOAD, no section headers |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
