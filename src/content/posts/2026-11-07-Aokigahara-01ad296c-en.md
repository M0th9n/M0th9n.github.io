---
title: "Malware Analysis: Aokigahara (PE · exe · 01ad296c)"
published: 2026-11-07
draft: false
description: "Malicious (medium confidence): Aokigahara · stealer/loader · difficulty medium · Dynamic sandbox analysis + static decompilation"
tags: ["Aokigahara", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-07-Aokigahara-01ad296c"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Aokigahara** · Confidence **medium**
> 
> Aliases: AOKIGAHARA Stealer, AKG Stealer
> 
> After detonation in a real sandbox, the sample process was observed resolving the C2 domain farenaw[.]cc and initiating a connection to port 443; memory forensics found an independent PE (base 0x140000000, MEM_PRIVATE/RWX) implanted in the process but absent from the module list. This in-memory module contains complete credential-stealing logic for browser credentials, cookies, credit cards, cryptocurrency wallets, Discord/Telegram/Steam sessions, Outlook/VPN/FTP/RDP, password managers, and AI sessions such as Claude Code/Codex/Cursor/Copilot/Gemini, along with anti-VM checks, CIS geolocation evasion, and a custom X25519 C2 protocol. The outer layer is a UPX-packed, name-obfuscated Go loader, forming a multi-stage stealer chain.

## Overview

| Item | Content |
|:--|:--|
| Family | **Aokigahara** · aliases AOKIGAHARA Stealer, AKG Stealer |
| Confidence | **medium** |
| Behavior class | stealer · loader |
| Difficulty | medium |
| First seen | 2026-11-05 23:40:16 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/01ad296c490b0e70f63e12f2a676503236cd8f1b1bc68cad2a6e17829ac1350b/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX unpack and in-memory implant</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded config</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Resolve C2 domain and connect</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">X25519 handshake, chunked upload</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1573.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Steal browser credentials</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `01ad296c490b0e70f63e12f2a676503236cd8f1b1bc68cad2a6e17829ac1350b` |
| MD5 | _not recorded_ |
| Size | 1,078,200 bytes (1.0 MB) |
| Type | PE · `exe` |

## Behavior analysis

**11** behaviors in total, each backed by evidence; **8** are statically available and **3** were obtained through dynamic analysis.

### 1. UPX unpacking and in-memory implantation

`T1620` · Confidence **high** · dynamic

The outer layer is a UPX-packed 64-bit Go loader; at runtime it maps an independent 223,967-byte PE (base 0x140000000, MEM_PRIVATE, RWX, not in the module list) inside its own process, and that in-memory module executes the subsequent stealing logic.

> **Evidence**: memory scan reports implanted_pe=1; module 0x140000000 protection=0x40, is_listed_module=0; memory dump dd0000 is a 3,854,242-byte unpacked Go image
> 
> **Source**: `ref:096bca7f99` · `ref:615027d816` · `ref:affe77b528`

### 2. Decrypting the embedded configuration

`T1140` · Confidence **high** · static

When the implanted module starts it decrypts the embedded configuration and prints 'CONFIG: decrypted'; the configuration yields C2 host farenaw[.]cc, path /gate, port 443, Gate Token, Build ID, and Session/HWID.

> **Evidence**: memory dump contains 'CONFIG: decrypted', 'farenaw[.]cc', 'X-Gate-Token: 2cf1ee26...', '/gate' and '/gate/handshake'
> 
> **Source**: `ref:a9ca4d641b`

### 3. Resolving the C2 domain and connecting

`T1071.001` · Confidence **high** · dynamic

After startup it resolves farenaw[.]cc, and the sample process then initiates a TCP connection to 192.0.2[.]123:443; the DNS resolution time matches the in-memory 'SENDER: connecting...' log (a few seconds after startup).

> **Evidence**: network monitoring: after the domain 'farenaw[.]cc' was resolved, process 6024 requested TCP 192.0.2[.]123:443
> 
> **Source**: `ref:096bca7f99` · `ref:a9ca4d641b`

### 4. X25519 handshake and chunked upload

`T1573.002` · Confidence **high** · static

Custom HTTPS C2 protocol: POST /gate/handshake completes the X25519 key exchange, then uploads in chunks via /gate/chunk and finishes with /gate/complete, carrying authentication headers such as X-Gate-Token/X-Session/X-HWID.

> **Evidence**: implanted-module strings '%s/handshake', '%s/chunk', '%s/complete', 'X-KEX: x25519'; code branch https→port 0x1bb (443), http→0x50 (80)
> 
> **Source**: `ref:a9ca4d641b` · `ref:23c630a3cd`

### 5. Stealing browser credentials

`T1555.003` · Confidence **high** · static

It walks Chromium-based browsers (Chrome/Edge/Brave/Opera/Vivaldi/Yandex/360/QQ) and Firefox/Thunderbird, extracting Login Data, Cookies, Web Data (credit cards/autofill), History, logins.json/key4.db, and handles app-bound/DPAPI encrypted keys.

> **Evidence**: implanted-module strings 'Browser/Passwords.txt', '%s\Login Data', '%s\Network\Cookies', 'logins.json', 'key4.db', 'app_bound_encrypted_key'
> 
> **Source**: `ref:a9ca4d641b`

### 6. Stealing wallets and AI sessions

`T1555` · Confidence **high** · static

It collects 30+ cryptocurrency wallets (wallet.dat, Exodus/Electrum/MetaMask/Phantom, etc.), Discord/Telegram/Steam tokens, Outlook/VPN/FTP/RDP/password managers, and credentials and configuration for Claude Code/Codex/Cursor/Windsurf/Copilot/Gemini.

> **Evidence**: implanted-module strings 'Wallets/Desktop/%s', 'Messengers/Discord/Tokens.txt', 'AISessions/ClaudeCode/credentials.json', 'Games/Steam/Tokens.txt'
> 
> **Source**: `ref:a9ca4d641b`

### 7. Capturing the screen

`T1113` · Confidence **high** · static

It invokes screenshot capabilities and saves the result as Screenshot.jpg as part of the uploaded data.

> **Evidence**: implanted-module strings 'Screenshot.jpg' and module name 'screenshot'
> 
> **Source**: `ref:a9ca4d641b`

### 8. Reading the clipboard

`T1115` · Confidence **high** · static

It reads system clipboard contents and writes them to Clipboard.txt, capturing sensitive text such as passwords and wallet addresses.

> **Evidence**: implanted-module strings 'Clipboard.txt' and module name 'clipboard'
> 
> **Source**: `ref:a9ca4d641b`

### 9. Geolocation check to avoid CIS

`T1614` · Confidence **high** · dynamic

After startup it requests ip-api[.]com/json/?fields=query,countryCode,city,isp, uses the country code to determine whether the host is in the CIS; on a hit it prints 'CIS: blocked' and exits.

> **Evidence**: network monitoring: DNS 'ip-api[.]com' and GET /json/?fields=query,countryCode,city,isp; strings 'CIS: blocked'/'CIS: passed'
> 
> **Source**: `ref:096bca7f99` · `ref:a9ca4d641b`

### 10. Detecting virtual machines and debugging

`T1497.001` · Confidence **high** · static

It detects virtualized environments through CPUID brand strings such as VBoxVBox/KVMKVMKVM, processes vmtoolsd/VBoxService/xenservice, and the vmware/virtualbox registry keys; on a hit it prints 'ANTI_VM: detected, exiting'.

> **Evidence**: implanted-module strings 'VBoxVBox', 'KVMKVMKVM', 'vmtoolsd', 'SOFTWARE\vmware, Inc.\vmware Tools', 'ANTI_VM: detected, exiting'
> 
> **Source**: `ref:a9ca4d641b`

### 11. Collecting host and process inventory

`T1082` · Confidence **high** · static

It gathers OS version/CPU/memory/disk/screen/language/uptime/AV/process list/installed software/environment variables, outputting sysinfo, ProcessList.txt, InstalledSoftware.txt and more.

> **Evidence**: implanted-module strings 'OS: %s (Build %lu)', 'ProcessList.txt', 'InstalledSoftware.txt', 'AV: None detected'
> 
> **Source**: `ref:a9ca4d641b`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: The addresses above were obtained from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| dns | `farenaw[.]cc` | 443 | c2 | dynamic | — |
| https | `hxxps://farenaw[.]cc:443/gate` | 443 | c2 | static | ⏳ not observed |

### Host

**Mutexes**

- `Global\%08lx`

**Dropped paths**

- `\\.\pipe\akg_%lx_%lx`
- `%TEMP%\akg_%08lx.tmp`
- `%TEMP%\akg_ff_%lx.tmp`
- `akg_debug.txt`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `farenaw[.]cc` | yes | dynamic |
| `c2_port` | `443` | yes | static |
| `c2_path` | `/gate` | yes | static |
| `gate_token` | `2cf1ee26245ec93e677bda4829527a63a10b21feaba83ba9d047bd01e37f0aa8` | yes | static |
| `build_id` | `f88119eb` | no | static |
| `session_id` | `39a782f748cb244c2c409dbe700afee9` | no | static |
| `hwid` | `E9F2B627` | no | static |
| `key_exchange` | `x25519` | yes | static |
| `pipe_pattern` | `\\.\pipe\akg_%lx_%lx` | no | static |
| `debug_log` | `akg_debug.txt` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- Do not judge it as ransomware or a wiper: the sample contains AES/X25519 cryptographic constants and file-collection modules, but no file encryption, ransom notes, shadow-copy deletion, or destructive behavior was found.
- Do not treat ip-api[.]com as C2: it is a public IP geolocation service used only for country/region evasion checks.
- Do not claim data exfiltration was confirmed: the sandbox only observed DNS resolution of the C2 domain and a TCP connection to 443; the /gate handshake and chunked upload never appeared in plaintext network logs.
- Do not treat it as an ordinary UPX-packed sample based on the section name alone; the outer layer is a Go loader and the real payload is an independent PE implanted in memory.
- Do not classify it as a downloader: no stage-2 download from C2 was observed; the second stage is implanted in memory by the outer loader.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `c486ae6620e01e3dd7ad0864de579f8809016ab2bc54b726db5e597b7b76bf34`) |

**Limitations and open questions**

1. The complete C2 handshake/upload was not confirmed in plaintext network logs: the sandbox captured only DNS resolution of farenaw[.]cc and a TCP connection to 443, and HTTPS content was not decrypted; /gate/handshake, /gate/chunk and /gate/complete come from in-memory strings and code branches.
2. The outer Go loader is obfuscated in a garble-like manner (randomized function names); its decryption/injection implementation was not recovered function by function; the existence and execution of the implanted PE are proven by memory forensics.
3. The implanted module was obtained only as a memory image; host security software prevented reading it from disk; its strings and configuration come from offline parsing of the memory dump (self-reported evidence, medium confidence).
4. No persistence, file drop, lateral movement, or successful data exfiltration was observed; these capabilities cannot be ruled out.
5. The family name Aokigahara comes from the sample's self-naming (debug log/config key/pipe prefix); no external vendor naming cross-validation is available.

## Evidence index

<details>
<summary>Show 9 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprints | sha256=01ad296c490b0e70f63e12f2a676503236cd8f1b1bc68cad2a6e17829ac1350b |
| `ev-000008` | Sample triage | UPX section names, UPX1 entropy 8.0, only 4 imported symbols, packing likelihood 85% |
| `ev-000009` | Import table parsing | Imports only KERNEL32: LoadLibraryA/ExitProcess/GetProcAddress/VirtualProtect |
| `ev-000010` | unpack.detect | Classified as UPX packer, confidence 0.9 |
| `ev-000011` | unpack.auto | Emulated 500001 instructions without locating the OEP (large UPX+LZMA payload) |
| `ev-000012` | Dynamic analysis platform | Real sandbox detonation: process 6024, implanted module dump, timeline/network monitoring logs packaged |
| `ev-000013` | PE structure parsing | Unpacked Go image 3,854,242 bytes, imports 56 DLLs |
| `ev-000014` | evidence.record | Offline parsing of the memory dump: configuration, C2, family self-naming, module inventory, anti-VM strings |
| `c2_evidence:01ad296c` | Connection evidence extraction | Dynamic network monitoring recorded 1 connection attempt to ip-api[.]com:443; no complete session was captured |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
