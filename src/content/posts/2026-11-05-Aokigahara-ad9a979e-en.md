---
title: "Malware Analysis: Aokigahara (PE · exe · ad9a979e)"
published: 2026-11-05
draft: false
description: "Malicious (medium confidence): Aokigahara · stealer/loader · difficulty hard · dynamic sandbox + static decompilation"
tags: ["Aokigahara", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-05-Aokigahara-ad9a979e"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Aokigahara** (uncertain) · Confidence **medium**
> 
> After detonation in a real Windows dynamic sandbox, an unlisted 64-bit PE image (base 0x140000000, RWX private memory) appeared in the sample process's own memory (pid 1824); the image contains the 'AOKIGAHARA DEBUG LOG' debug banner and complete browser/wallet/messaging credential-collection paths. The sample process then sent an X25519 handshake request to farenaw[.]cc:443 and uploaded three data types (sysinfo, screenshot, filegraber) in chunks, finishing with COMPLETE. The isolated network recorded only sample-side requests and received no server response, so the C2 session is marked pending dynamic verification.

## Overview

| Item | Content |
|:--|:--|
| Family | **Aokigahara** · _uncertain_ |
| Confidence | **medium** |
| Behavior class | stealer · loader |
| Difficulty | hard |
| First seen | 2026-11-02 23:08:57 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ad9a979e68a411ca15f5d003c37ada725d02c34d6c1b7f34c4dbbbed39a8dd4f/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Map stage-2 payload in memory</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">observed</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded config</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Detect VM environment</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">observed</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Export browser passwords</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Steal session cookies</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `ad9a979e68a411ca15f5d003c37ada725d02c34d6c1b7f34c4dbbbed39a8dd4f` |
| MD5 | _not recorded_ |
| Size | 10,383,768 bytes (9.9 MB) |
| Type | PE · `exe` |

## Behavior analysis

**12** behaviors in total, each backed by evidence; **10** are statically recoverable and **2** were obtained through dynamic analysis.

### 1. Map stage-2 payload in memory

`T1620` · Confidence **high** · dynamic

The Go loader maps an unlisted 64-bit PE image (base 0x140000000, 0x35000 bytes, sha256 d64f88ab…) inside its own process with MEM_PRIVATE, RWX(0x40) attributes, decrypts configuration and starts the stealer module there; memory forensics also records that the image has a complete PE header, 10 sections and is not a system module.

> **Evidence**: memory forensics report: module=140000000, is_listed_module=0, has_pe=1, protection=0x40, 10 sections; the sample imports VirtualAlloc/VirtualFree/CreateThread/GetProcAddress
> 
> **Source**: `ref:36b2726a32` · `ref:e2147ac215` · `ev-000020`

### 2. Decrypt embedded config

`T1027` · Confidence **high** · static

The second stage decrypts runtime configuration from the .stgcfg section (4096 bytes, entropy 7.19), printing 'CONFIG: decrypted' on success and falling back to defaults with 'CONFIG: failed, using defaults' on failure; the configuration holds the C2 and collection switches.

> **Evidence**: stage2 section table .stgcfg @VA 0x21000; strings at 0x22163 'CONFIG: decrypted', 0x22175 'CONFIG: failed, using defaults'
> 
> **Source**: `ev-000020`

### 3. Detect VM environment

`T1497.001` · Confidence **high** · dynamic

At startup it queries traces such as vmware Tools, VirtualBox Guest Additions, the VBoxGuest/vmci services and WDAGUtilityAccount, and on a hit prints 'ANTI_VM: detected, exiting' and exits; at runtime it also leaves 3 code patches near advapi32's GetUserNameA, apparently forging the username/evading analysis.

> **Evidence**: stage2 strings SOFTWARE\vmware, Inc.\vmware Tools / SOFTWARE\Oracle\VirtualBox Guest Additions / SYSTEM\...\Services\VBoxGuest / WDAGUtilityAccount (0x2282a-0x228eb); memory forensics records advapi32 patches 4a8f0/4a8f6/4a8fd
> 
> **Source**: `ev-000020` · `ev-000022` · `ref:36b2726a32`

### 4. Export browser passwords

`T1555.003` · Confidence **high** · static

It reads Login Data, Web Data, logins.json and key4.db from Chromium-based browsers (Chrome/Edge/Brave/Opera/Vivaldi/Yandex/360/QQ/Cent/Arc and others) and Firefox-based browsers (Firefox/Waterfox/Pale Moon/Floorp and others), decrypts them with PK11SDR_Decrypt and aggregates them into Browser/Passwords.txt, CreditCards.txt, Autofill.txt and History.txt.

> **Evidence**: strings '%s\Login Data', 'Browser/Passwords.txt', 'Browser/CreditCards.txt', 'PK11SDR_Decrypt' (0x24054), '%s\Web Data'
> 
> **Source**: `ev-000020`

### 5. Steal session cookies

`T1539` · Confidence **high** · static

It copies each browser's Cookies database and Local State, handles the app_bound_encrypted_key/local_stored_cvc used by newer Chrome's App-Bound encryption, and includes a 'STATUS:NO_ABE' branch; output goes to Browser/Cookies/*_Cookies.txt.

> **Evidence**: strings '%s\Network\Cookies', 'app_bound_encrypted_key', 'local_stored_cvc', 'STATUS:NO_ABE', 'Browser/Cookies/%s_Cookies.txt'
> 
> **Source**: `ev-000020` · `ref:fa2696b2ad`

### 6. Grab wallet and FTP credentials

`T1555.003` · Confidence **high** · static

It walks desktop/browser-extension wallets (Exodus, Electrum, Atomic, Coinomi, WalletWasabi, Monero, TokenPocket, MetaMask and others) and FTP client configurations (FileZilla, WinSCP, CoreFTP, FlashFXP, SmartFTP), writing to the Wallets/ and FTP/ directories.

> **Evidence**: strings 'Exodus\exodus.wallet', 'Wallets/Extensions/%s', 'FTP/WinSCP/Sessions.txt', 'Software\Martin Prikryl\WinSCP 2\Sessions'
> 
> **Source**: `ev-000020`

### 7. Harvest messaging and gaming sessions

`T1539` · Confidence **high** · static

It packages Telegram (including Kotatogram/64Gram/AyuGram/Unigram branches) tdata, Discord tokens and Web session leveldb, Steam loginusers/config refresh tokens, and Roblox .ROBLOSECURITY plus Battle.net/Epic/Riot/Minecraft gaming credentials.

> **Evidence**: strings 'Messengers/Telegram/tdata', 'dQw4w9WgXcQ' (Discord token prefix), 'Games/Steam/Tokens.txt', 'Games/Roblox/cookies.txt', '.ROBLOSECURITY'
> 
> **Source**: `ev-000020`

### 8. Read AI tool tokens

`T1552.001` · Confidence **high** · static

It collects local tokens and configuration of AI/cloud tools such as Claude Code, Codex, Copilot, Gemini, Cursor, Windsurf, AWS and Kiro (AISessions/*), including .aws\credentials, state.vscdb, config.json and .env.

> **Evidence**: strings 'AISessions/ClaudeCode/credentials.json', 'AISessions/AWS/credentials', 'cursorAuth/accessToken', 'AISessions/Windsurf/Tokens.txt'
> 
> **Source**: `ev-000020`

### 9. Screenshot and clipboard collection

`T1113` · Confidence **high** · dynamic

It produces a screen capture (Screenshot.jpg) and clipboard text (Clipboard.txt), and the filegraber module grabs files from the Desktop/Documents/Downloads directories; the isolated network request log shows POST request bodies for the screenshot and filegraber chunks.

> **Evidence**: isolated network HTTP request log: POST /gate/chunk headers X-Chunk: screenshot (index 1, 20874 B), X-Chunk: filegraber (index 2, 557 B); strings 'Screenshot.jpg', 'Clipboard.txt'
> 
> **Source**: `ev-000021` · `ev-000020` · `ref:36b2726a32`

### 10. X25519 handshake to C2

`T1573.002` · Confidence **high** · dynamic

The sample process sends POST /gate/handshake to farenaw[.]cc:443 with a 32-byte X25519 public key body and X-Build-ID/X-HWID/X-Gate-Token/X-Session headers, then transfers data over the encrypted session.

> **Evidence**: isolated network HTTP request log: POST /gate/handshake Host: farenaw[.]cc, Content-Length: 32, X-KEX: x25519, X-Build-ID: 86b8b3da, X-HWID: E9F2B627
> 
> **Source**: `ref:36b2726a32` · `ev-000021`

### 11. Chunked encrypted exfiltration

`T1041` · Confidence **high** · dynamic

It splits the collection into X-Total=20 chunks, POSTs /gate/chunk in order with X-Chunk (sysinfo/screenshot/filegraber) and X-Chunk-Index, and sends POST /gate/complete (body 'COMPLETE') to end the session.

> **Evidence**: isolated network HTTP request log: three POST /gate/chunk (X-Chunk: sysinfo/screenshot/filegraber, X-Chunk-Index 0/1/2, X-Total: 20) plus one POST /gate/complete, body=COMPLETE, all to farenaw[.]cc:443
> 
> **Source**: `ref:36b2726a32` · `ev-000021`

### 12. Query egress IP and geolocation

`T1614` · Confidence **high** · dynamic

Using User-Agent 'Mozilla/5.0' it requests hxxp://ip-api[.]com/json/?fields=query,countryCode,city,isp to obtain the egress IP, country/city and ISP, for victim profiling or environment checks.

> **Evidence**: isolated network HTTP request log: GET /json/?fields=query,countryCode,city,isp Host: ip-api[.]com, source process pid 1824
> 
> **Source**: `ev-000021` · `ref:36b2726a32`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the isolated analysis network, so the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://farenaw[.]cc/gate/handshake` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://farenaw[.]cc/gate/chunk` | 443 | exfil | static | ⏳ not observed |
| http | `hxxps://farenaw[.]cc/gate/complete` | 443 | exfil | static | ⏳ not observed |

### Host

**Dropped paths**

- `%TEMP%\akg_debug.txt`
- `%TEMP%\akg_%08lx.tmp`
- `%TEMP%\akg_%lx_%lx.tmp`
- `%TEMP%\akg_ff_%lx.tmp`
- `\\.\pipe\akg_%lx_%lx`

**Registry**

- `HKCU\Software\Valve\Steam (reads the Steam install path and account configuration)`
- `HKCU\Software\Valve\Steam\Users (reads Steam accounts/tokens)`
- `HKLM\SOFTWARE\vmware, Inc.\vmware Tools (VM detection)`
- `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions (VM detection)`
- `HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest (VM detection)`
- `HKLM\SYSTEM\CurrentControlSet\Services\vmci (VM detection)`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `farenaw[.]cc` | yes | static |
| `c2_base_path` | `/gate (POST /gate/handshake, /gate/chunk, /gate/complete)` | yes | static |
| `key_exchange` | `x25519 (handshake body is a 32-byte public key, header field X-KEX: x25519)` | yes | static |
| `upload_headers` | `X-Build-ID / X-Session / X-HWID / X-Gate-Token / X-Chunk / X-Chunk-Index / X-Total` | yes | static |
| `build_id` | `86b8b3da` | no | dynamic |
| `session_id` | `84402f62bfcec6a9f992f5d8b2fb87fe` | no | dynamic |
| `hwid` | `E9F2B627` | no | dynamic |
| `geoip_lookup` | `hxxp://ip-api[.]com/json/?fields=query,countryCode,city,isp` | no | dynamic |
| `config_blob` | `stage-2 .stgcfg section (4096 bytes, entropy 7.19) encrypted configuration; at runtime prints 'CONFIG: decrypted' and falls back to defaults on failure` | yes | static |
| `chunk_total` | `20 (declared by X-Total); three chunks (sysinfo/screenshot/filegraber) were actually observed` | no | dynamic |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not call it ransomware or a file encryptor: although it contains an AES implementation and walks many file paths, no file encryption, extension rewriting or ransom note was observed.
- Do not claim injection into other processes or remote control: the second-stage payload resides in the sample's own process (pid 1824) private memory at 0x140000000, with no OpenProcess/CreateRemoteThread/cross-process write evidence.
- Do not claim persistence: no Run key, service, scheduled task or startup-folder write was observed.
- Do not treat ip-api[.]com as C2 infrastructure: it is a public geolocation service used only for egress IP/region probing.
- Do not provide plaintext of the exfiltrated content: the upload body is encrypted with the session key, so only chunk type names and lengths can be confirmed, not the credentials themselves.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | yes (stage2 `d64f88ab888e1eb68465c44cb11197099c03b3eeacc97cfe78b87988a65721a3`) |

**Limitations and pending verification**

1. The stage-2 .stgcfg configuration is a high-entropy encrypted block that could not be statically decrypted; the C2 host and protocol fields come from dynamic observation.
2. X-Total declares 20 chunks, but only sysinfo/screenshot/filegraber were observed before the run ended; the other collection categories were not actually triggered.
3. The mutex name is assembled at runtime from machine information (only 'MUTEX: already running' logic was seen), and the concrete name was not obtained.
4. The Go loader's string literals are encrypted/obfuscated, so its internal decision logic cannot be reconstructed statically; loader-side judgments rely mainly on memory forensics and the import surface.
5. The memory-dumped second-stage payload was blocked from being written back to disk by a security policy on the analysis host, and its parsing (section table/import table/strings) was done in memory.
6. No keylogging, lateral movement or persistence has been observed, so they are not listed as behavioral conclusions.

## Evidence index

<details>
<summary>Expand 6 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hashing and fingerprinting | sha256/md5/sha1 and file size 10383768 |
| `ev-000003` | scan.entropy | .text entropy 6.001 (not packed) |
| `ev-000017` | cryptographic constant identification | AES forward/inverse S-boxes and SHA-256 round constants at offsets 0x992ba0/0x992ca0 |
| `ev-000020` | evidence.record | In-memory parsing of the stage-2 payload: AOKIGAHARA stealer, .stgcfg encrypted configuration, collection paths and C2 protocol strings |
| `ev-000021` | evidence.record | Network monitoring log parsing: farenaw[.]cc handshake/chunk/complete interactions and ip-api[.]com queries |
| `ev-000022` | evidence.record | Go 1.24.5 + garble obfuscation, self-signed certificate, embedded high-entropy payload block, advapi32 runtime patches |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
