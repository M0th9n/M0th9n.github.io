---
title: "Malware Analysis: GoldSpins Grabber (PE · exe · 230f506b)"
published: 2026-11-09
draft: false
description: "Malicious (low confidence): GoldSpins Grabber · stealer/injector · difficulty medium · Dynamic sandbox + static decompilation"
tags: ["GoldSpins Grabber", "stealer", "injector", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-09-GoldSpins-Grabber-230f506b"
---

> [!WARNING]
> **Verdict: Malicious** · Family **GoldSpins Grabber** (uncertain) · Confidence **low**
> 
> Static decompilation confirms it is a one-shot in-memory credential stealer: it enumerates Chromium/Firefox credentials and cookies, crypto wallets, Discord/Telegram/Steam/Roblox tokens, password managers and FTP/VPN configuration, takes a screenshot, then uploads a ZIP to hxxps://goldspins[.]club/gate. The real dynamic environment further observed it dropping a built-in DLL, launching headless msedge, DNS queries for goldspins.club / ip-api[.]com, and a 97,756-byte ZIP POST carrying X-Build-ID=582501ca, X-HWID and X-Token headers (containing Screenshot.jpg, FileGrabber/TextFiles and DetectedDomains.txt), so it is judged malicious with runtime self-evidence.

## Overview

| Item | Content |
|:--|:--|
| Family | **GoldSpins Grabber** · _uncertain_ |
| Confidence | **low** |
| Behavior class | stealer · injector |
| Difficulty | medium |
| First seen | 2026-11-06 07:01:23 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/230f506bb813f4950bba612d0804ce34a1fee8bf24e8d068ac9a34979f0a835b/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Anti-sandbox and anti-debug</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Drop built-in payload DLL</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Launch headless browser</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Inject into browser to steal</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Decrypt browser data</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `230f506bb813f4950bba612d0804ce34a1fee8bf24e8d068ac9a34979f0a835b` |
| MD5 | _not recorded_ |
| Size | 1,482,240 bytes (1.4 MB) |
| Type | PE · `exe` |

## Behavior analysis

**10** behaviors in total, each backed by evidence; **6** are statically available and **4** were obtained through dynamic analysis.

### 1. Anti-sandbox and anti-debug

`T1497.001` · Confidence **high** · static

At startup it chains four checks: the length of consecutive hex digits in its own executable name, the current process name, the system process list and HKLM registry key names; if any keyword such as sandboxie/cuckoo/procmon/wireshark/fiddler/x64dbg/ollydbg/windbg/IDA/processhacker/vmware/VirtualBox/QEMU/Xen/Parallels matches, it exits. The keyword table is obfuscated with XOR 0x5A and decoded at runtime.

> **Evidence**: FUN_140007fb0 calls FUN_140007df0/FUN_140007690/FUN_140007890/FUN_140007b60 in turn; RegOpenKeyExA(HKLM), Process32First/Next, GetModuleFileNameA; emulation shows RegOpenKeyExA receiving the XOR-decoded string.
> 
> **Source**: `ev-000036` · `ev-000038` · `ev-000039` · `ev-000040` · `ev-000025` · `ref:f9c2607a4b`

### 2. Drop built-in payload DLL

`T1027` · Confidence **high** · dynamic

It extracts payload_v3.dll from an MZ image embedded in .data (rva 0xf8820, 0x4a00 bytes) to %TEMP%\<8 hex digits>.dll. This dynamic run observed C:\Users\analyst\AppData\Local\Temp\0043820B.dll being created.

> **Evidence**: FUN_140008500 checks the MZ header and writes %TEMP%\%08X.dll via CreateFileA/WriteFile; dynamic file-creation event TargetFilename=C:\Users\analyst\AppData\Local\Temp\0043820B.dll.
> 
> **Source**: `ev-000032` · `ref:f19ab4471d`

### 3. Launch headless browser

`T1106` · Confidence **high** · dynamic

It locates Chrome/Edge/Brave installation paths and uses CreateProcessA to launch "<browser>" --headless --disable-gpu --no-sandbox --disable-software-rasterizer, preparing a host process for later injection and App-Bound Encryption key decryption. Dynamic observation shows msedge.exe starting with the above command line.

> **Evidence**: FUN_140009f70 builds the headless arguments and calls CreateProcessA; dynamic process-creation event Image=msedge.exe, CommandLine contains --headless --disable-gpu --no-sandbox --disable-software-rasterizer.
> 
> **Source**: `ev-000034` · `ev-000035` · `ref:f19ab4471d`

### 4. Inject into browser to steal

`T1055` · Confidence **high** · static

It injects payload_v3.dll into the headless browser using VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryA). The DLL reads app_bound_encrypted_key from the browser's Local State, decrypts the 32-byte App-Bound Encryption key through the IElevator COM interface and writes it to C:\Windows\Temp\payload_log.txt; the main program polls the log, extracts the Key and caches it in memory.

> **Evidence**: FUN_14000a320 injection chain; FUN_140009700 polls payload_log.txt and parses the 32-byte key as hex; payload_v3.dll exports elevator_init/elevator_decrypt_key and uses CoCreateInstance/CoSetProxyBlanket.
> 
> **Source**: `ev-000033` · `ev-000026` · `ref:3cadef3374` · `ref:f19ab4471d`

### 5. Decrypts browser data

`T1555.003` · Confidence **high** · static

Using an embedded SQLite, it reads Chrome/Edge/Brave cookies, Login Data and Web Data, calls CryptUnprotectData for DPAPI, and decrypts v10/v20 cookies with BCrypt AES-GCM; it also reads Firefox cookies.sqlite and logins.json and attempts PK11SDR_Decrypt.

> **Evidence**: FUN_1400f26a0 main collection function; strings "SELECT host_key, name, encrypted_value...", "CryptUnprotectData", "BCryptDecrypt", "%s\\Local State", "SELECT host, name, value...".
> 
> **Source**: `ev-000027` · `ev-000029` · `ev-000024` · `ref:4636600a8b`

### 6. Collects wallets and tokens

`T1555` · Confidence **high** · static

It traverses more than 40 browser wallet extensions and desktop wallets (MetaMask, Phantom, TrustWallet, Exodus, Electrum, Ledger Live, Monero, Bitcoin Core, etc.) and collects Discord Tokens, Telegram tdata, Steam JWT, Roblox Cookies, Google Refresh Tokens, password managers (Bitwarden/1Password/KeePass/Dashlane/NordPass), FileZilla and OpenVPN/WireGuard/CyberGhost configuration.

> **Evidence**: string tables Wallets/Extensions/%s_%s, Wallets/Desktop/%s, Discord/Tokens.txt, Telegram/tdata, Gaming/Steam/MemoryTokens.txt, Browsers/Google Accounts/RefreshTokens.txt, PasswordManagers/*, FTP/FileZilla/recentservers.xml, VPN/*.
> 
> **Source**: `ev-000024` · `ev-000027`

### 7. Screenshots and packages data for exfiltration

`T1041` · Confidence **high** · dynamic

Using GDI BitBlt + GDI+ it generates Screenshot.jpg, packages the screenshot, FileGrabber/TextFiles documents and DetectedDomains.txt into a ZIP, and uploads it to hxxps://goldspins[.]club/gate via WinHTTP POST. Dynamic packet capture shows Content-Length=97756, with request headers X-Build-ID: 582501ca, X-HWID: 6431AF93-E7480E04, X-Token: hSgOlyXfIkv1ED5zLWqKn9p4HAZu0wJY.

> **Evidence**: FUN_14000c670 WinHttpOpen/Connect/OpenRequest(POST)/SendRequest, UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"; the dynamic POST /gate ZIP contains Screenshot.jpg, FileGrabber/TextFiles/*.txt and DetectedDomains.txt.
> 
> **Source**: `ev-000028` · `ev-000027` · `ref:f19ab4471d`

### 8. Queries egress IP geolocation

`T1016` · Confidence **high** · dynamic

Before uploading it requests ip-api[.]com's /line/?fields=countryCode,query to obtain the egress IP and country code, presumably for geo-based decisions or data labeling. This domain is a public IP geolocation service, not attacker infrastructure.

> **Evidence**: dynamic DNS query for ip-api[.]com and GET /line/?fields=countryCode,query (Host: ip-api[.]com, User-Agent: Mozilla/5.0).
> 
> **Source**: `ref:f19ab4471d`

### 9. Reports Clipper status

`T1071.001` · Confidence **medium** · static

A code path exists to send status reports to hxxps://goldspins[.]club/clipper, with X-Clipper-Status values installed/already_installed/failed/not_embedded; this run did not observe that request, nor any actual clipboard monitoring or address replacement.

> **Evidence**: FUN_14000d1b0 concatenates "%s/clipper" and POSTs, building Content-Type: text/plain, X-Build-ID, X-HWID, X-Clipper-Status and optional X-Token headers.
> 
> **Source**: `ev-000030`

### 10. Obfuscates strings and APIs

`T1027` · Confidence **high** · static

Many sensitive strings are stored XOR 0x5A-encrypted (anti-sandbox lists, wallet/browser keywords, etc.); APIs from WinHTTP, advapi32, crypt32, bcrypt, iphlpapi and others are resolved at runtime through hash constants, evading static import signatures.

> **Evidence**: FUN_140007160 fills the API pointer table with FUN_140008250(hash1, hash2); FUN_140007b60/FUN_140007690/FUN_140007890 XOR 0x5A strings in place before comparing.
> 
> **Source**: `ev-000037` · `ev-000024` · `ev-000025`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to these targets (repeatedly retried within a short period).
:::

:::caution
**Real server side still unverified**: the above connections/handshakes were completed against a local controlled emulation service, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://goldspins[.]club/gate` | 443 | c2 | dynamic | observed |
| http | `hxxps://goldspins[.]club/clipper` | 443 | download | dynamic | observed |

### Host

**Dropped paths**

- `%TEMP%\<8 hex digits>.dll`
- `C:\Windows\Temp\payload_log.txt`
- `%LOCALAPPDATA%\Temp\grabber_pipe.txt`
- `\\.\pipe\grabber_<pid>_<tid>`
- `Local\grabber_shm_<pid>_<tid>`
- `\\.\pipe\grabber_dummy`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `goldspins[.]club` | yes | dynamic |
| `c2_url` | `hxxps://goldspins[.]club/gate` | yes | dynamic |
| `c2_port` | `443` | yes | dynamic |
| `build_id` | `582501ca` | yes | dynamic |
| `auth_token` | `hSgOlyXfIkv1ED5zLWqKn9p4HAZu0wJY` | yes | dynamic |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` | yes | dynamic |
| `clipper_endpoint` | `hxxps://goldspins[.]club/clipper` | no | static |
| `clipper_status_values` | `installed\|already_installed\|failed\|not_embedded` | no | static |
| `ip_check_url` | `hxxp://ip-api[.]com/line/?fields=countryCode,query` | no | dynamic |
| `hwid` | `generated at runtime; observed value 6431AF93-E7480E04` | no | dynamic |
| `encryption_algo` | `Chromium data: DPAPI + AES-GCM (BCryptDecrypt); Chrome App-Bound Encryption: IElevator COM` | no | static |
| `embedded_payload` | `payload_v3.dll, 18944 bytes, sha256 5f7d95ef0a18e315d572ae57ad94ef08d8ff892785e7e034d4ad113c417464fb` | yes | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not call it ransomware/a wiper: it does not encrypt or delete user files and has no ransom note; BCrypt/DPAPI are only used to decrypt browser cookies/keys.
- Do not call it a persistent backdoor or RAT: it creates no Run key, service or scheduled task, and the dynamic run shows no command loop or long-term residence.
- Do not call it a generic downloader/dropper: the embedded payload_v3.dll is only a Chrome App-Bound Encryption helper module, and no download or execution of an arbitrary second stage was observed.
- Do not treat ip-api[.]com as attacker C2: it is a public IP geolocation query service used only to determine egress IP/country.
- Do not claim clipboard hijacking exists: the code contains a /clipper status-report path, but no clipboard monitoring or wallet-address replacement was observed in this run.
- Do not claim registry persistence: the registry is only read for anti-VM detection and installed-software enumeration.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. This dynamic run did not trigger the /clipper report, nor was any actual clipboard hijacking observed; that path is confirmed only by static code.
2. No targeted memory forensics was performed on the msedge process, so whether the DLL successfully loaded into the browser process was not directly observed; the injection conclusion rests on the injection code, the dropped Temp DLL and the headless msedge process creation.
3. After XOR 0x5A decoding, the anti-sandbox strings have spelling variants (e.g. sandfox/vmwaro/procmonroxo), so some keyword matches may fail; this does not affect the overall theft conclusion.
4. The HWID generation algorithm was not fully recovered; only the observed runtime value 6431AF93-E7480E04 is recorded.
5. No persistence, self-deletion or clipboard hijacking was observed; the service response content returned by the C2 was not obtained.
6. The sample embeds a static SQLite library and retains debug sections, making static reading easy; however, some string decoding has variants, so the actual decrypted results should prevail.

## Evidence index

<details>
<summary>Expand 22 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hashing & fingerprints | sha256/md5/sha1 and imphash |
| `ev-000003` | scan.entropy | .text entropy 6.263, no high-entropy packed section |
| `ev-000024` | string extraction | browser/wallet/token/screenshot/upload strings and paths |
| `ev-000002` | import table parsing | 9 DLLs/211 symbols, including GDI+, and Crypt32/CreateRemoteThread related to indirect WinHTTP calls |
| `ev-000036` | decompile.ghidra | FUN_140007fb0 anti-VM master switch |
| `ev-000038` | decompile.ghidra | FUN_140007df0 enumerates HKLM registry key names for anti-VM checks |
| `ev-000039` | decompile.ghidra | FUN_140007690 enumerates process names for anti-analysis checks |
| `ev-000040` | decompile.ghidra | FUN_140007890 checks its own file name/keywords |
| `ev-000032` | decompile.ghidra | FUN_140008500 extracts the embedded MZ to %TEMP% |
| `ev-000034` | decompile.ghidra | FUN_140009f70 launches the browser with headless arguments via CreateProcessA |
| `ev-000033` | decompile.ghidra | FUN_14000a320 VirtualAllocEx/WriteProcessMemory/CreateRemoteThread injection |
| `ev-000026` | decompile.ghidra | FUN_140009700 polls payload_log.txt after injection to extract the 32-byte key |
| `ev-000027` | decompile.ghidra | FUN_1400f26a0 main collection flow (browser/wallets/screenshot etc.) |
| `ev-000028` | decompile.ghidra | FUN_14000c670 WinHTTP POST upload implementation |
| `ev-000030` | decompile.ghidra | FUN_14000d1b0 /clipper status reporting |
| `ev-000037` | decompile.ghidra | FUN_140007160 hash-constant API resolution |
| `ref:3cadef3374` | pe.exports | payload_v3.dll exports elevator_init/decrypt_key etc. |
| `ref:f9c2607a4b` | dyn.run | emulation observed API hash resolution, HKLM anti-VM queries and Grabber banner |
| `ref:f19ab4471d` | dynamic analysis platform | real dynamic: drops Temp DLL, launches headless msedge, DNS queries goldspins.club/ip-api[.]com, POST /gate uploads ZIP |
| `c2_evidence:230f506b` | connection evidence extraction | dynamic network monitoring recorded 1 connection attempt to goldspins[.]club:443; no complete session captured |
| `telemetry:230f506b` | dynamic telemetry | dynamic telemetry recorded: monitoring component registry events 1; monitoring component process/file events 116; ETW short-lived process events 1; tool/system noise filtered 26 |
| `etw:230f506b:5800` | process event monitoring | short-lived process event: 230f506bb813f4950bba612d0804ce34a1fee8bf24e8d068ac9a34979f0a835b.exe (pid 5800; MD5=043AEA82EA3D8CF809FFF5A7801814AD,SHA256=230F506BB813F4950BBA612D0804CE34A1FEE8BF24E8D068AC9A34979F0A835B,IMPHASH=3F8E2AB76B7440ED45BE9591BF586EBE) |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
