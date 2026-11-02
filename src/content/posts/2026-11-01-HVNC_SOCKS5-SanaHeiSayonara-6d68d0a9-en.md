---
title: "Malware Analysis: HVNC_SOCKS5 (SanaHeiSayonara) (PE · exe · 6d68d0a9)"
published: 2026-11-01
draft: false
description: "Malicious (medium confidence): HVNC_SOCKS5 (SanaHeiSayonara) · stealer/rat/backdoor · difficulty medium · dynamic sandbox + static decompilation"
tags: ["HVNC_SOCKS5", "stealer", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-01-HVNC_SOCKS5-SanaHeiSayonara-6d68d0a9"
---

> [!WARNING]
> **Verdict: malicious** · Family **HVNC_SOCKS5 (SanaHeiSayonara)** (doubtful) · Confidence **medium**
> 
> Aliases: SanaHeiSayonara HVNC, Krutyak HVNC loader
> 
> A 64-bit C++ remote-access/stealer program: statically confirmed are UAC-bypass self-elevation, Defender exclusions, C2 address retrieval from a Steam profile dead drop, Chromium credential decryption, wallet collection, and keyboard hooks. In the dynamic sandbox it actually started (a second instance with the same process name) and requests to steamcommunity[.]com/id/l5jgtd78uhn43987f89w plus persistent encrypted TCP callbacks to mitmatmet[.]com:1010 were observed.

## At a glance

| Item | Content |
|:--|:--|
| Family | **HVNC_SOCKS5 (SanaHeiSayonara)** · Aliases SanaHeiSayonara HVNC, Krutyak HVNC loader · _doubtful_ |
| Confidence | **Medium** |
| Behavior classes | stealer · rat · backdoor |
| Difficulty | medium |
| First seen | 2026-11-01 11:49:02 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/6d68d0a96c8bc726cbe3bf6f6253fb0ccae50627e966b8606f3582ef65eacec7/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UAC bypass self-elevation</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1548.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Add AV exclusions</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Steam dead-drop C2 lookup</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Encrypted C2 callback</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1573</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Decrypt browser credentials</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `6d68d0a96c8bc726cbe3bf6f6253fb0ccae50627e966b8606f3582ef65eacec7` |
| MD5 | _not recorded_ |
| Size | 1,747,456 bytes (1.7 MB) |
| Type | PE · `exe` |

## Behavior analysis

**9** behaviors in total, each backed by evidence: **6** are obtainable statically and **3** were obtained through dynamic analysis.

### 1. UAC bypass self-elevation

`T1548.002` · Confidence **High**

Checks whether the current token is already elevated; if not, it uses ComputerDefaults.exe as the host, bypasses UAC through the ICMLuaUtil CLSID 201ef99a-7fa0-444c-9399-19ba84f12a1a with ncalrpc debug/token duplication, and restarts itself with the original command line.

> **Evidence**: FUN_1400019f0 @0x1400019f0 calls ComputerDefaults.exe, DbgUiSetThreadDebugObject, NtDuplicateObject; FUN_140003af0 checks TokenElevation; FUN_140002560 restarts via GetCommandLineW
> 
> **Source**: `ev-000016` · `ev-000022` · `ev-000031` · `ref:89b6288ca3`

### 2. Adds antivirus exclusions

`T1562.001` · Confidence **High** · Static

Starts powershell.exe and writes Get-ScheduledJob and Add-MpPreference -ExclusionPath/-ExclusionProcess through a pipe, adding itself and its directory to the Defender exclusion list.

> **Evidence**: FUN_140001510 @0x140001510 CreateProcessW + CreatePipe + WriteFile; the Add-MpPreference script starts at string 0x14018d410
> 
> **Source**: `ev-000015` · `ev-000033`

### 3. Steam dead-drop address retrieval

`T1102` · Confidence **High** · Dynamic

Issues an HTTPS request to steamcommunity[.]com/id/l5jgtd78uhn43987f89w and extracts og:title with a regular expression as the hostname; if that fails it falls back to the embedded domain mitmatmet[.]com.

> **Evidence**: FUN_140013770 @0x140013770 calls FUN_140013f50("steamcommunity[.]com", path, 443) and matches <meta property="og:title">; FUN_140001190 passes id/l5jgtd78uhn43987f89w and mitmatmet[.]com
> 
> **Source**: `ev-000020` · `ev-000021` · `ev-000018` · `ev-000033` · `ev-000034`

### 4. Encrypted C2 callback

`T1573` · Confidence **High** · Dynamic

At a fixed interval it resolves and connects to mitmatmet[.]com:1010 and exchanges unreadable binary blocks (20/48-byte and 16-byte block patterns observed), forming an encrypted beacon/task channel.

> **Evidence**: dynamic network monitoring: mitmatmet[.]com resolved from 03:27:36; the same-named process established 79 connections to 192.0.2[.]123:1010; static FUN_140013900 @0x140013900 re-fetches the address every 240s; strings include "expand 32-byte k" and BCrypt GCM
> 
> **Source**: `ev-000023` · `ev-000021` · `ev-000018` · `ev-000034` · `ref:89b6288ca3`

### 5. Decrypts browser credentials

`T1555.003` · Confidence **High** · Static

Locates Chrome/Edge/Brave/Opera Local State, extracts encrypted_key and app_bound_encrypted_key, decrypts with DPAPI first and then recovers the v20 key with Google Chromekey1/BCrypt AES-GCM, which is used to decrypt cookies, logins, and credit_cards query results.

> **Evidence**: FUN_140003ea0 @0x140003ea0: CryptUnprotectData, BCryptOpenAlgorithmProvider/BCryptDecrypt, strings "Google Chromekey1", "app_bound_encrypted_key", SQLite SELECT ... FROM logins/cookies/credit_cards
> 
> **Source**: `ev-000017` · `ev-000033`

### 6. Collects wallet data

`T1005` · Confidence **High** · Static

Enumerates wallet directories/files for Exodus, Atomic, Guarda, Armory, Komodo, Wasabi, Electrum, Coinomi, and packages them for exfiltration.

> **Evidence**: strings starting at 0x19bd20: %APPDATA%\Exodus\exodus.wallet, %APPDATA%\atomic\Local Storage\leveldb, %APPDATA%\Guarda, %APPDATA%\Armory, %APPDATA%\WalletWasabi\Client\Wallets, %APPDATA%\Electrum\wallets, %LOCALAPPDATA%\Coinomi\Coinomi\wallets
> 
> **Source**: `ev-000033`

### 7. Keyboard hook logging

`T1056.001` · Confidence **High** · Static

Installs a WH_KEYBOARD_LL global keyboard hook and writes keystrokes to keylog.txt; another thread periodically reads the file and sends it to the controller.

> **Evidence**: FUN_140019650 @0x140019650 calls SetWindowsHookExW(0xd, FUN_140018920) and enters the message loop; FUN_1400198f0/FUN_1400192e0 loop reading the file and call FUN_1400106d0; string keylog.txt @0x14018fa28
> 
> **Source**: `ev-000024` · `ev-000030` · `ev-000033`

### 8. Creates a hidden desktop

`T1219` · Confidence **High** · Static

Creates or opens a hidden desktop under a custom name (WinSta0\Default and derived desktop names) and combines desktop switching with PrintWindow/StretchBlt screen capture to implement HVNC remote operation.

> **Evidence**: FUN_140014360 @0x140014360: OpenDesktopW/CreateDesktopW, SetThreadDesktop; imports PrintWindow, StretchBlt, OpenInputDesktop; string WinSta0\Default @0x14018d530
> 
> **Source**: `ev-000028` · `ev-000033`

### 9. Unpacks payload and installs a driver

`T1105` · Confidence **High** · Static

Uses PowerShell Expand-Archive to extract C:\ProgramData\Krutyak.zip into C:\ProgramData and invokes deviceinstaller to install usbmmIdd.inf (the usbmmidd virtual display driver), then runs enableidd 1.

> **Evidence**: strings @0x14018d2b0: $archpath = "C:\ProgramData\Krutyak.zip"; ... Expand-Archive; @0x14019cdb0: %ws\%ws install %ws\usbmmIdd.inf usbmmidd; @0x14019ce18: enableidd 1
> 
> **Source**: `ev-000033`


## IOC (de-weaponized)

### Network

:::note
**Connections were observed dynamically**: the sample actually initiated TCP connections to these targets (repeated retries within a short period).
:::

:::caution
**The real server side is still unverified**: the connections/handshakes above were completed against a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://steamcommunity[.]com/id/l5jgtd78uhn43987f89w` | 443 | c2 | Dynamic | Observed |
| tcp | `mitmatmet[.]com` | 1010 | c2 | Dynamic | — |

### Host

**Mutex**

- `SanaHeiSayonarac`
- `SanaHeiSayonarad`
- `SanaHeiSayonarae`
- `SanaHeiSayonaraf`
- `SanaHeiSayonarag`
- `%s_SanaHeiSayonarah`
- `%s_SanaHeiSayonarai`

**Drop paths**

- `%LOCALAPPDATA%\SanaHeiSayonaraa`
- `%LOCALAPPDATA%\SanaHeiSayonaraG`
- `C:\ProgramData\Krutyak.zip`
- `C:\ProgramData\usbmmidd_v2`
- `keylog.txt`

**Services**

- `usbmmidd`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `mitmatmet[.]com:1010 (fallback); steamcommunity[.]com/id/l5jgtd78uhn43987f89w (dead-drop)` | Yes | Dynamic |
| `dead_drop_url` | `hxxps://steamcommunity[.]com/id/l5jgtd78uhn43987f89w` | Yes | Dynamic |
| `campaign_id` | `l5jgtd78uhn43987f89w` | Yes | Static |
| `mutex` | `SanaHeiSayonara{c..g} / %s_SanaHeiSayonara{h,i}` | Yes | Static |
| `install_archive` | `C:\ProgramData\Krutyak.zip` | No | Static |
| `driver_package` | `C:\ProgramData\usbmmidd_v2 (usbmmIdd.inf, deviceinstaller64.exe, enableidd 1)` | No | Static |
| `encryption_algo` | `ChaCha20 ("expand 32-byte k") and AES-GCM (BCrypt) for communications/configuration; BCrypt hashing as well` | No | Static |
| `keylog_file` | `keylog.txt` | No | Static |
| `browser_targets` | `Chrome / Edge / Brave / Opera / Firefox: cookies, logins, credit_cards, extensions and Local State` | No | Static |
| `wallet_targets` | `Exodus, Atomic, Guarda, Armory, Komodo, Wasabi, Electrum, Coinomi` | No | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing this report.

- Do not classify it as ransomware: the sample implements no file encryption or ransom text; AES-GCM/ChaCha20 are used only for communications, configuration, and browser key decryption.
- Do not say it uses a kernel privilege-escalation vulnerability: the UAC bypass only elevates itself to administrator and does not exploit a kernel bug.
- Do not treat the request to steamcommunity[.]com as normal browsing activity: that URL is a hardcoded dead-drop resolution path used to obtain a fallback C2 host.
- Do not assert that the SOCKS5 proxy or HVNC session was actually activated in this environment: only exports, imports, and code paths prove the capability, and dynamic analysis observed only beacons.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. The sandbox has no real internet access, so responses and follow-up tasks from mitmatmet[.]com:1010 were not obtained; only encrypted bytes were seen on 1010 and the plaintext protocol cannot be reconstructed.
2. The Steam profile response was blocked by the local network, so the real og:title was not obtained, and therefore whether the dead drop replaces the fallback domain cannot be confirmed.
3. The download/extraction of C:\ProgramData\Krutyak.zip and the usbmmidd driver installation were not observed; those behaviors come from code and strings and represent capability rather than established fact.
4. The SOCKS5 proxy, the HVNC remote session, and actual wallet packaging/exfiltration were not triggered in this dynamic window; all are statically inferred.
5. The family name HVNC_SOCKS5/SanaHeiSayonara comes from the build name and mutex prefix; there is no third-party engine or public-report cross-validation, so attribution is doubtful.

## Evidence index

<details>
<summary>Expand 21 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hash_scan | sha256=6d68...acec7, md5=1ccc4246..., imphash=ee100517e971d046ed1372570e0e5361 |
| `ev-000002` | import_hash | imphash ee100517e971d046ed1372570e0e5361 |
| `ev-000014` | string_scan | ASCII 7847 entries / UTF-16LE 827 entries (flag hits are charset noise, not credentials) |
| `ev-000015` | static_decompile | FUN_140001510 writes the Defender exclusion script through powershell |
| `ev-000016` | static_decompile | FUN_1400019f0 bypasses UAC with ComputerDefaults/ICMLuaUtil and a debug token |
| `ev-000017` | static_decompile | FUN_140003ea0 decrypts Chromium encrypted_key and app_bound_encrypted_key (BCrypt GCM) |
| `ev-000018` | static_decompile | FUN_140013f50 WinHTTP request/download wrapper |
| `ev-000019` | static_decompile | FUN_1400014c0 creates the SanaHeiSayonarad mutex and exits if it already exists |
| `ev-000020` | static_decompile | FUN_140013770 requests the Steam profile and parses og:title as the hostname |
| `ev-000021` | static_decompile | FUN_140001190 main flow: mutex, Defender exclusions, Steam lookup, mitmatmet[.]com fallback, thread creation |
| `ev-000022` | static_decompile | FUN_140002560 calls the UAC bypass with the original command line when not elevated |
| `ev-000023` | static_decompile | FUN_140013900 refreshes the C2 address every 240 seconds |
| `ev-000024` | static_decompile | FUN_140019650 installs WH_KEYBOARD_LL and enters the message loop |
| `ev-000028` | static_decompile | FUN_140014360 OpenDesktopW/CreateDesktopW creates a hidden desktop |
| `ev-000030` | static_decompile | FUN_1400192e0 reads the keylog file and sends it |
| `ev-000031` | static_decompile | FUN_140003af0 reads TokenElevation |
| `ev-000032` | static_decompile | FUN_140019cc0 creates the SanaHeiSayonarac mutex |
| `ev-000033` | string_extraction | Self-written script extracts mutex, C2, dead-drop path, Krutyak/usbmmidd, wallet, and keylog strings by offset |
| `ev-000034` | dynamic_log_analysis | Self-written script parses sandbox network monitoring: Steam GET, mitmatmet[.]com DNS and 79 encrypted TCP connections on port 1010, second same-named process |
| `ref:89b6288ca3` | dynamic_sandbox | Real sandbox detonation: process 7736 started and produced memory dumps, after which same-named process 1756 appeared and went online; no hollowing hit |
| `c2_evidence:6d68d0a9` | Connection evidence extraction | Dynamic network monitoring recorded 3 connection attempts to maps[.]windows[.]com:443, steamcommunity[.]com:443; no complete session captured |

</details>

---

_This report's sample is not public; IOCs have been de-weaponized and are for security research only._
