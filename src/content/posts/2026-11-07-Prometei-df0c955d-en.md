---
title: "Malware Analysis: Prometei (ELF · elf · df0c955d)"
published: 2026-11-07
draft: false
description: "Malicious (high confidence): Prometei · botnet/backdoor/miner · difficulty hard · Static decompilation (Linux dynamic execution produced no runtime behavior)"
tags: ["Prometei", "botnet", "backdoor", "miner", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-07-Prometei-df0c955d"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Prometei** · Confidence **high**
> 
> After static unpacking and decompilation it is confirmed: the sample is a Linux x86-64 static ELF packed with a UPX 4.24 variant, embedding Prometei's C2 address table (clearnet IPs, a Tor .onion and an I2P b32 address, all with paths containing prometei.cgi), an HTTP task protocol, systemd/cron persistence, and miner start/stop commands. Functionally it is a remotely controllable botnet/backdoor with resource-hijacking capability.

## Overview

| Item | Content |
|:--|:--|
| Family | **Prometei** |
| Confidence | **high** |
| Behavior class | botnet · backdoor · miner |
| Difficulty | hard |
| First seen | 2026-11-04 19:28:30 |
| Analysis method | Static decompilation (Linux dynamic execution produced no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/df0c955d17c1b11fdf29f35b01762b312ce028bd1a0c90d9c2b1553ddc821796/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX variant self-extracts</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Built-in C2 address table</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001, T1090.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Poll HTTP for commands</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Install systemd service</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Write cron autostart</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `df0c955d17c1b11fdf29f35b01762b312ce028bd1a0c90d9c2b1553ddc821796` |
| MD5 | _not recorded_ |
| Size | 449,163 bytes (438.6 KB) |
| Type | ELF · `elf` |

## Behavior analysis

**11** behaviors in total, each backed by evidence, and all statically available.

### 1. UPX variant self-extraction

`T1027.002` · Confidence **high** · static

At startup the embedded NRV2E loader decompresses 5 compressed blocks into memory and executes them; the main code block uses the x86 filter with ftid=0x49, cto=0x2a, the whole-file entropy is about 7.94, and standard upx -d reports NotPackedException.

> **Evidence**: entry=0x15ec6a0; b_info@file 0x100 (0x270/0xbe, method 8); filter block@0x2d2 (0x100441, ftid 0x49); UPX! magic@0xec, UPX 4.24 banner@0x6c870
> 
> **Source**: `ev-000015` · `ev-000001` · `ev-000002`

### 2. Built-in C2 address table

`T1071.001, T1090.003` · Confidence **high** · static

Four hardcoded C2s: cleartext IP 177.221.180[.]26, dummy.zero placeholder domain, a Tor .onion and an I2P b32 address, all pointing to /cgi-bin/*.cgi; the C2 selection function switches to reading local configuration when /etc/pcc0 or ~/.ssh/pcc0 exists.

> **Evidence**: VA 0x537140/0x537180/0x5371c0/0x537200; FUN_0041a007@0x41a007; in main, 0x427b3d/0x427b5f load the .onion and .i2p addresses respectively
> 
> **Source**: `ev-000016` · `ev-000009`

### 3. Poll HTTP for commands

`T1071.001` · Confidence **high** · static

It polls for tasks with GET /cgi-bin/p.cgi?r=0&auth=hash&i=<botid>&enckey=<key>, parses HTTP/1.0 200/403/404 and Content-Length, and returns answ results according to the response.

> **Evidence**: format strings@file 0x102aa0/0x102ad5; HTTP/1.0 200 OK@0x102b58; error string 404 - Server %s offline@0x102eb4
> 
> **Source**: `ev-000011` · `ev-000014` · `ev-000009`

### 4. Install a systemd service

`T1543.002` · Confidence **high** · static

It assembles in memory [Unit]/Description=UPlugPlay/After=multi-user.target/[Service]/Type=forking/ExecStart/[Install]/WantedBy=multi-user.target, writes /lib/systemd/system/uplugplay.service, and runs systemctl daemon-reload, enable, start.

> **Evidence**: FUN_00423e78@0x423e78 inlines the unit template and systemctl commands; /usr/sbin/uplugplay@0x537260; uplugplay.service path string
> 
> **Source**: `ev-000012` · `ev-000004`

### 5. Write cron autostart

`T1053.003` · Confidence **medium** · static

It writes an @reboot entry through crontab to start updatecheckerd (updatechecker.d), and uses pkill to clean up old instances, ensuring it keeps running after reboot.

> **Evidence**: strings @reboot, -cron, crontab, updatechecker.d, pkill updatecheckerd (file 0x23747/0x23990/0x102f8d)
> 
> **Source**: `ev-000004` · `ev-000011`

### 6. Masquerade as system service names

`T1036.005` · Confidence **high** · static

It uses names such as uplugplay, upnpsetup, pdefenderd, nvsync, netwalker, msdtc, smcard, zsvc to disguise processes/files, and calls rename or cleanup routines to avoid conflicts with legitimate services.

> **Evidence**: name table file 0x102fe7-0x10311e; FUN_00422f13("uplugplay")/FUN_00422f13("upnpsetup")@0x423e78
> 
> **Source**: `ev-000004` · `ev-000012`

### 7. Collect host fingerprints

`T1082` · Confidence **high** · static

It reads /proc/cpuinfo, /proc/meminfo, /etc/os-release, /etc/redhat-release, /etc/debian_version, and calls dmidecode, hostnamectl, uname -a, uptime to collect hardware and system information, reporting in the info: %s,%s\%s,... format.

> **Evidence**: strings file 0x102931-0x102a36; report format string@0x102ef0; dmidecode --type baseboard@0x1029e7
> 
> **Source**: `ev-000004` · `ev-000011`

### 8. Probe the egress IP

`T1016` · Confidence **high** · static

It invokes nslookup against 8.8.8[.]8, 1.1.1[.]1, 114.114.114[.]114 and reads /etc/resolv.conf to determine online status and the egress address (C2 reports extip).

> **Evidence**: 8.8.8[.]8@file 0x102830; nslookup@0x14310; /etc/resolv.conf@0x10286e; &extip=@0x1029bab
> 
> **Source**: `ev-000004` · `ev-000011`

### 9. Download and verify modules

`T1105` · Confidence **high** · static

It uses wget/chkxwget/dbg_wget to download later modules or updates, computes SHA-256 (sha256hash: %s) for verification, then chmod +x and executes them from disk; on failure it takes the offline/bad file branch.

> **Evidence**: chkxwget@file 0x10314e; sha256hash: %s@0x102db8; chmod +x@0x23d9f; SHA-256 constants@0x102580/0x1025a0
> 
> **Source**: `ev-000004` · `ev-000011` · `ev-000005` · `ev-000007`

### 10. Start and stop the miner module

`T1496` · Confidence **medium** · static

It includes start_mining/stop_mining commands and the HashPowerProject configuration, allowing the C2 to remotely start and stop the cryptocurrency mining module.

> **Evidence**: start_mining@file 0x102f5b; stop_mining@0x103199; HashPowerProject@0x1026ab
> 
> **Source**: `ev-000004` · `ev-000011`

### 11. Remote task protocol

`T1059.004` · Confidence **high** · static

It implements the _CMDv2_;%d: task protocol, supporting remote commands such as chkport, tcp_bind, tcp_stop, udp_stop, set_cc0/set_cc1, get_pid, fgetnormal, fgetcrypt, fsha256, getinfo.

> **Evidence**: _CMDv2_;%d:@file 0x102f69; chkport@0x102e5b; tcp_bind@0x1031a5; set_cc1@0x103161; get_pid@0x102cbb
> 
> **Source**: `ev-000004` · `ev-000011`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: The addresses above were obtained from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://177[.]221[.]180[.]26/cgi-bin/p[.]cgi` | 80 | c2 | static | ⏳ not observed |
| http | `hxxp://dummy[.]zero/cgi-bin/prometei[.]cgi` | 80 | c2 | static | ⏳ not observed |
| http | `hxxps://gb7ni5rgeexdcncj[.]onion/cgi-bin/prometei[.]cgi` | 443 | c2 | static | ⏳ not observed |
| http | `hxxp://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq[.]b32[.]i2p/cgi-bin/prometei[.]cgi` | 80 | c2 | static | ⏳ not observed |

### Host

**Dropped paths**

- `/usr/sbin/uplugplay`
- `/etc/uplugplay`
- `/etc/CommId`
- `/etc/pcc0`
- `/etc/pcc1`
- `~/.ssh/pcc0`
- `/lib/systemd/system/uplugplay.service`
- `/tmp/debug.txt`

**Services**

- `uplugplay.service`

**Scheduled tasks**

- `cron: @reboot starts updatecheckerd (updatechecker.d)`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxp://177.221.180[.]26/cgi-bin/p.cgi; hxxp://dummy.zero/cgi-bin/prometei.cgi; hxxps://gb7ni5rgeexdcncj[.]onion/cgi-bin/prometei.cgi; hxxp://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p/cgi-bin/prometei.cgi` | yes | static |
| `install_path` | `/usr/sbin/uplugplay` | yes | static |
| `config_path` | `/etc/uplugplay; /etc/pcc0; /etc/pcc1; /etc/CommId` | no | static |
| `persistence` | `systemd /lib/systemd/system/uplugplay.service; cron @reboot updatecheckerd` | yes | static |
| `campaign_id` | `/etc/CommId (log format CommId: %s)` | no | static |
| `version` | `v4.42V_Unix64` | yes | static |
| `encryption_algo` | `SHA-256 (module/file verification); base64 alphabet; the C2 URL carries an enckey parameter` | no | static |
| `miner_module` | `start_mining / stop_mining; HashPowerProject` | no | static |
| `parent` | `ParentID / ParentHostname configuration keys` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- Do not judge it as Netwalker ransomware because of the string netwalker: that name is only a masquerading process/file name in this sample, and no file encryption, ransom note, or ransom behavior was seen.
- Do not claim real C2 outbound traffic was observed: the dynamic channel produced no observable telemetry in this run, and the C2 was obtained from static unpacking and still needs dynamic verification.
- Do not treat it as a standard UPX packer and run upx -d directly: the sample uses a UPX 4.24 variant with an x86 filter, and standard tools report NotPackedException.
- Do not assert that a local account was created based on the usermod string alone: no actual useradd/usermod execution path was seen in the decompilation.
- Do not treat the base64 alphabet or the string abcdefghijklmnopqrstuvwxyz{|} as a flag.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (Linux dynamic execution produced no runtime behavior) |
| Unpacking | Yes (stage2 `5928efb4ed3f13530ff482a9cc2b3ad931f2a580f1350e01011ec9cf4a5e53a9`) |

**Limitations and open questions**

1. Dynamic detonation did not succeed: the dynamic channel returned guest_rc=0 with no observable behavior/network events, so C2 and persistence behavior are marked as statically recovered and pending dynamic verification.
2. After unpacking in memory, the sample did not appear to release an independent miner module or second-stage executable; start_mining may be implemented by an internal thread or may depend on a later downloaded module, and the miner program itself was not obtained.
3. The manually rebuilt unpacked ELF retains the original program headers, but the original section header table is not in the compressed stream (e_shoff points beyond the end of the file), so section-level metadata cannot be recovered.
4. dummy.zero is more likely a placeholder/template domain, and whether it participates in actual resolution was not dynamically verified; the I2P b32 address cannot be resolved without an I2P environment.
5. Family attribution is based on the C2 path literal prometei.cgi, the version string, and TTP consistency; no vendor YARA/multi-engine reports were used for cross-confirmation in this run.
6. The sandbox network namespace is unreachable by default and no connect/socket events were observed; none of the C2s were actually contacted.

## Evidence index

<details>
<summary>Show 11 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000015` | evidence.record | Manual static unpacking script: identifies the UPX 4.24/NRV2E variant, decompresses 5 blocks one by one and reproduces the ftid=0x49 filter, rebuilding the ELF at entry 0x401ef0. |
| `ev-000016` | evidence.record | Byte-by-byte verification of the C2 table (0x537140/0x537180/0x5371c0/0x537200) and path strings such as /usr/sbin/uplugplay, /etc/pcc0, /etc/CommId in the unpacked output. |
| `ev-000012` | decompile.function | Decompiles FUN_00423e78: assembles the systemd unit, writes /lib/systemd/system/uplugplay.service, calls systemctl daemon-reload/enable/start. |
| `ev-000009` | decompile.function | Decompiles FUN_0041a007: C2 selection logic, default hxxp://177.221.180[.]26/cgi-bin/p.cgi, switching to local configuration when /etc/pcc0 or ~/.ssh/pcc0 exists. |
| `ev-000008` | decompile.function | Decompiles main(0x425fbe): reads configuration from /usr/sbin/uplugplay, /etc/uplugplay, handles argv, starts the C2 and install flow. |
| `ev-000011` | String extraction | Unpacked-output string scan: HTTP task formats, install/persistence texts, pkill updatecheckerd, Usermode/System install, etc. |
| `ev-000004` | String extraction | Unpacked-output string scan: systemd unit fragments, cron/@reboot, chmod +x, msdtc/zsvc/nvsync masquerade names, nslookup, etc. |
| `ev-000005` | Cryptographic constant identification | SHA-256 initial and round constants hit (0x102580/0x1025a0). |
| `ev-000007` | Cryptographic constant identification | Standard base64 alphabet hit (0x136320). |
| `ev-000001` | String extraction | Packed-file strings: contains the '9UPX!' fragment, indicating a UPX variant. |
| `ev-000002` | String extraction | Packed-file string statistics (2928 ASCII strings, overall high entropy), used for packing determination. |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
