---
title: "Malware Analysis: Prometei (ELF · elf · aa39b28a)"
published: 2026-10-30
draft: false
description: "Malicious (high confidence): Prometei · botnet/downloader/backdoor · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Prometei", "botnet", "downloader", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-30-Prometei-aa39b28a"
---

> [!WARNING]
> **Verdict: malicious** · Family **Prometei** · Confidence **high**
> 
> Aliases: Prometei botnet, Trojan.Prometei, Win32.Prometei
> 
> The sample is a UPX 4.24-packed x86_64 ELF with no section table, symbols or import table in the static file; at runtime it self-extracts the full implant. The unpacked payload contains a Prometei-style CGI callback protocol (/cgi-bin/p.cgi?r=0&auth=hash&i=%s&enckey=%s), a hard-coded C2 list, dual persistence via a systemd service and crontab, wget-based self-update, blacklist-based process cleanup and host fingerprint collection, providing full botnet-node capability.

## Overview

| Item | Content |
|:--|:--|
| Family | **Prometei** · aliases Prometei botnet, Trojan.Prometei, Win32.Prometei |
| Confidence | **high** |
| Behaviour class | botnet · downloader · backdoor |
| Difficulty | medium |
| First seen | 2026-10-30 13:54:41 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/aa39b28aa15bfb60099a0a9421529fda51426415443da2cbb9fc567a45375f08/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Runtime self-extracting payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">CGI-style C2 callback</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Built-in multi-channel C2 list</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1090</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Install systemd service</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Write crontab autostart</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `aa39b28aa15bfb60099a0a9421529fda51426415443da2cbb9fc567a45375f08` |
| MD5 | _not recorded_ |
| Size | 436,615 bytes (426.4 KB) |
| Type | ELF · `elf` |

## Behaviour analysis

**10** behaviours in total; each is tied to evidence, and all are statically recoverable.

### 1. Runtime self-extracting payload

`T1027.002` · Confidence **high** · static

The file is a UPX 4.24-packed self-extracting ELF: statically it has only 3 program headers and no section table, symbols or dynamic dependencies; the entry stub restores the full implant in memory via mmap/mprotect and jumps to the original entry 0x401ef0 (the hand-off completes at runtime address 0x4f8851).

> **Evidence**: entry 0x15de450 (rva 0x11de450) is the unpacking stub; the unpacked image has entry=0x401ef0, 10 program headers, sha256=536d7998d75a817364a817c69210129d482713b1a6353d5ec8f1c596f46fbe5d
> 
> **Source**: `ref:83aa5419cf` · `ref:804320f9a3` · `ref:3da554a720` · `ref:1aa217a483` · `ev-000008`

### 2. CGI-style C2 callback

`T1071.001` · Confidence **high** · static

Uses an HTTP GET to <C2>/cgi-bin/p.cgi with the query string r=0&auth=hash&i=<node ID>&enckey=<encryption key>, and uses the server response to decide subsequent commands and module updates.

> **Evidence**: unpacked .rodata 0x4f9370 "hxxp://%s/cgi-bin/p.cgi?r=0&auth=hash&i=%s&enckey=%s"; 0x4f93a5 "hxxp://%s/cgi-bin/p.cgi"
> 
> **Source**: `ref:1dd6207eaa` · `ev-000008`

### 3. Built-in multi-channel C2 list

`T1090` · Confidence **high** · static

Hard-codes four callback addresses: a cleartext IP, a Tor hidden service and an I2P address, plus a dummy.zero placeholder; it switches to a backup channel when the primary is unreachable.

> **Evidence**: 0x52d140 hxxp://152[.]36[.]128[.]18/cgi-bin/p[.]cgi; 0x52d1c0 hxxps://gb7ni5rgeexdcncj[.]onion/...; 0x52d200 i2p b32 address
> 
> **Source**: `ref:1dd6207eaa` · `ev-000008`

### 4. Install systemd service persistence

`T1543.002` · Confidence **high** · static

Drops itself as /usr/sbin/uplugplay, writes /lib/systemd/system/uplugplay.service (Type=forking, pulled in by multi-user.target), and runs systemctl daemon-reload / enable / start to establish persistence.

> **Evidence**: 0x52d260 /usr/sbin/uplugplay; in the 0x4f9xxx area: systemctl daemon-reload, systemctl enable uplugplay.service, systemctl start uplugplay.service, Type=forking
> 
> **Source**: `ref:1dd6207eaa` · `ev-000008`

### 5. Write crontab autostart

`T1053.003` · Confidence **high** · static

Reads the existing crontab (crontab -l, recognising the empty state when no jobs exist) and writes an @reboot line pointing at the resident program, as a redundant autostart channel beside systemd.

> **Evidence**: 0x4f9881 "crontab -l"; 0x4f988c "no crontab"; 0x41b2db "crontab "; "@reboot " and the task.cron template string
> 
> **Source**: `ref:1dd6207eaa` · `ev-000008`

### 6. Remove competing processes

`T1057` · Confidence **high** · static

Enumerates /proc/<pid>/exe, matches a built-in process-name blacklist (uplugplay, upnpsetup, walker, updatecheckerd, crashed.dump, msdtc, msdtc2, msdtc3, smcard, smcard2, zsvc, wlist.data) and runs pkill against updatecheckerd, clearing other families' footholds.

> **Evidence**: 0x4f98f1 "/proc/%s/exe", 0x4f9947 "/proc/%d/exe", 0x4f985d "pkill updatecheckerd", process-name table at 0x10xxxx "uplugplay,upnpsetup,walker,updatecheckerd,crashed.dump,msdtc,msdtc2,msdtc3,smcard,smcard2,zsvc,wlist.data"
> 
> **Source**: `ref:1dd6207eaa` · `ev-000008`

### 7. Fetch updates with wget and execute

`T1105` · Confidence **high** · static

Invokes wget variants (xwget/chkxwget/dbg_wget) to download a new version from C2, chmod +x (including chmod 777) and verifies it with sha256, then replaces itself to complete the upgrade.

> **Evidence**: 0x4f9a18 "xwget", 0x4f9a1e "chkxwget", 0x4f9a57 "dbg_wget", 0x4f9a60 "updatev4", 0x4f9574 "fsha256", 0x4f9688 "sha256hash: %s", 0x41b6ea/0x4fxx "chmod +x", 0x4f98xx "chmod 77"
> 
> **Source**: `ref:1dd6207eaa` · `ev-000008`

### 8. Collect host fingerprint

`T1082` · Confidence **high** · static

Reads /etc/os-release, /etc/redhat-release, /etc/debian_version, /proc/cpuinfo, /proc/meminfo, /proc/stat, /etc/localtime, the hostname and CPU information, and assembles the reporting payload (info { ... }, VERSION= section).

> **Evidence**: 0x4f9242 /etc/os-release; 0x4f9256 /etc/redhat-release; 0x4f926a /etc/debian_version; 0x4f927e /proc/cpuinfo; 0x4f92a1 /proc/meminfo; 0x41099d "info {"
> 
> **Source**: `ref:1dd6207eaa` · `ev-000008`

### 9. Disguise as system components

`T1036.005` · Confidence **high** · static

The resident file and service use system-component-style names and paths such as uplugplay (resembling udev/uplugplay), msdtc2 and pcc0/pcc1, lowering the chance of detection during manual inspection.

> **Evidence**: 0x52d260 /usr/sbin/uplugplay, 0x52d278 /etc/uplugplay, 0x52d2b9 msdtc, 0x52d2bf msdtc2, 0x52d2d0 /etc/pcc0, 0x52d2e0 /etc/pcc1
> 
> **Source**: `ref:1dd6207eaa` · `ev-000008`

### 10. Resolve domains with nslookup

`T1071.004` · Confidence **medium** · static

Invokes the system nslookup with 8.8.8[.]8 to resolve C2 domains, extracting the result from the "Non-authoritative answer:" / "Address: " text, bypassing local resolver defects or poisoning.

> **Evidence**: 0x40c646 "nslookup", 0x40c660 " 8.8.8[.]8", 0x40c775 "Non-authoritative answer:", 0x40c893 "Address: "
> 
> **Source**: `ref:1dd6207eaa`


## IOCs (defanged)

### Network

:::caution
**The real server side remains unverified**: the connections/handshakes above were completed against a local controlled emulation service; the real C2 responses and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://152[.]36[.]128[.]18/cgi-bin/p[.]cgi` | 80 | c2 | static | ⏳ not observed |
| http | `hxxps://gb7ni5rgeexdcncj[.]onion/cgi-bin/prometei[.]cgi` | 443 | c2 | static | ⏳ not observed |
| http | `hxxp://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq[.]b32[.]i2p/cgi-bin/prometei[.]cgi` | 80 | c2 | static | ⏳ not observed |

### Host

**Drop paths**

- `/usr/sbin/uplugplay`
- `/etc/uplugplay`
- `/etc/CommId`
- `/etc/pcc0`
- `/etc/pcc1`
- `/lib/systemd/system/uplugplay.service`
- `/tmp/debug.txt`

**Services**

- `uplugplay.service (systemd, Type=forking, multi-user.target)`

**Scheduled tasks**

- `crontab @reboot entry pointing at /usr/sbin/uplugplay`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `152.36.128[.]18; gb7ni5rgeexdcncj[.]onion; mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p` | yes | static |
| `c2_uri` | `/cgi-bin/p.cgi?r=0&auth=hash&i=%s&enckey=%s` | yes | static |
| `install_path` | `/usr/sbin/uplugplay` | yes | static |
| `bot_id_file` | `/etc/CommId` | yes | static |
| `persistence` | `/lib/systemd/system/uplugplay.service + crontab @reboot` | yes | static |
| `campaign_id` | `node records with config=1: 4f4Zp6P98JGW1t4z / o2TLna5M57JbwfT5` | no | static |
| `encryption_algo` | `-` | no | dynamic |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- It cannot be classified as ransomware: the sample contains no file-encryption, extension-rewriting or ransom-note logic; walker/netwalker are only noise strings.
- Do not claim real C2 egress or mining activity was observed: this detonation produced no observable telemetry, and this Linux module contains no mining-pool or miner binary strings.
- Do not infer attribution or the actor behind it: only hard-coded infrastructure and code traits are available, with no signature or infrastructure-registration attribution evidence.
- The exact encryption algorithm behind the enckey field was not recovered; do not describe it as AES/RSA.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | yes (stage2 `536d7998d75a817364a817c69210129d482713b1a6353d5ec8f1c596f46fbe5d`) |

**Limitations and pending verification**

1. Dynamic sandbox detonation returned guest_rc=0 with no telemetry (no file/network events), so real egress was not observed; the C2 and persistence behaviours are static conclusions marked pending_dynamic_verify.
2. The dynamic channel was unavailable, so the systemd/crontab drop and wget update flow were not reproduced in the isolated instance.
3. The sample is statically linked and stripped, so function-level symbol names were not recovered; behaviours are located via string references and unpacked code ranges.
4. The enckey encryption algorithm and the C2 response command set were not recovered (they need real egress or a server-side sample).
5. This Linux module contains no mining component; Prometei's usual mining/credential-theft capabilities would be delivered by later modules, which were not obtained this time.

## Evidence index

<details>
<summary>Expand 9 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256=aa39b28a…5f08, md5=a02cd8856ccf06b2ebd8e9fc9d7f50f0, size=436615 |
| `ev-000002` | ELF structure parser | e_type=EXEC, x86_64, entry 0x15de450, only 3 program headers (RW 18MB / RX 433981 / GNU_STACK), no section table, symbols or dependencies |
| `ev-000003` | elf.sections | Segment table: 0x400000 RW filesz 4096 memsz 18303064; 0x1575000 R-X filesz 433981 |
| `ev-000004` | disasm.function | Entry stub disassembly: call/pop base retrieval, bit-stream decoding, open/readlink/mmap/mprotect syscall sequence |
| `ev-000005` | String extraction | Readable fragments in the wrapper: nslookup, Non-authoritative, config, enckey, usermod, Type=forking etc. |
| `ev-000006` | ELF structure parser | Unpacked ELF: entry 0x401ef0, 10 program headers, R-X segment 0x401000 size 1013841 |
| `ev-000007` | String extraction | Unpacked strings: C2 URLs, /usr/sbin/uplugplay, /etc/CommId, systemctl, crontab, chmod +x, /proc/%d/exe, /etc/os-release etc. |
| `ev-000008` | evidence.record | Instruction-level emulation of the unpacking process with the recovered image sha256, OEP and C2/path list (self-reported) |
| `ev-000009` | evidence.record | Parsing of the JSON node configuration fragment appended to the wrapper tail (self-reported) |

</details>

---

_The sample behind this report is not public; IOCs are defanged. For security research only._
