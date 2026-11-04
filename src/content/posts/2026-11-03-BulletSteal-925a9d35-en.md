---
title: "Malware Analysis: BulletSteal (PE · exe · 925a9d35)"
published: 2026-11-03
draft: false
description: "Malicious (medium confidence): BulletSteal · stealer/rat · difficulty hard · dynamic sandbox + static decompilation"
tags: ["BulletSteal", "stealer", "rat", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-03-BulletSteal-925a9d35"
---

> [!WARNING]
> **Verdict: Malicious** · Family **BulletSteal** (uncertain) · Confidence **medium**
> 
> Aliases: BulletStealer, HVNC_SOCKS5
> 
> In the real dynamic sandbox the sample stayed resident, resolved its address from jujupuluz[.]icu, and periodically sent 20-byte encrypted handshakes to 1010/TCP; static analysis recovered complete malicious capabilities: C2 handshake, hidden-desktop remote control, keyboard/clipboard monitoring, browser credential and wallet theft, Defender exclusions, and fake-update privilege escalation.

## Overview

| Item | Content |
|:--|:--|
| Family | **BulletSteal** · aliases BulletStealer, HVNC_SOCKS5 · _uncertain_ |
| Confidence | **medium** |
| Behavior class | stealer · rat |
| Difficulty | hard |
| First seen | 2026-11-01 11:34:31 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/925a9d35a32e1a6a1ce1ae4b9ff09e289184d4d925d700752c99f15ab04296dd/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Establish encrypted C2 channel</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Poll Steam for identity</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Create hidden desktop</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Screenshot and stream frames</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1113</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Global keystroke logging</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `925a9d35a32e1a6a1ce1ae4b9ff09e289184d4d925d700752c99f15ab04296dd` |
| MD5 | _not recorded_ |
| Size | 1,748,480 bytes (1.7 MB) |
| Type | PE · `exe` |

## Behavior analysis

**12** behaviors in total, each backed by evidence; **10** statically recoverable, **2** obtained through dynamic analysis.

### 1. Establish encrypted C2 channel

`T1095` · Confidence **high** · dynamic

It resolves jujupuluz[.]icu to its 1010/TCP address and connects; it sends a 20-byte handshake (16-byte fixed magic ':a1+L{yWL920K7=' + 4-byte bot identifier) and validates a 16-byte magic in the reply; after disconnection it reconnects every 240 seconds.

> **Evidence**: 0x1400106d0 getaddrinfo/socket/connect + send(0x14)/recv(0x10) magic comparison; 0x1400013ed loads jujupuluz.icu; 0x140013900 Sleep(240000) reconnect loop; dynamic: DNS jujupuluz[.]icu and 20-byte randomized payload on TCP 1010
> 
> **Source**: `ev-000018` · `ev-000015` · `ev-000016` · `ref:5dcffbd8ff`

### 2. Poll Steam for identity

`T1102` · Confidence **high** · dynamic

It uses WinHTTP to access steamcommunity[.]com/id/fknfm59m0j38kd0u4t and extracts the page's <meta property="og:title"> content as the bot display name, falling back to an empty name on failure; the period is synchronized with C2 reconnection.

> **Evidence**: 0x140013770 reads <meta property="og:title"> and fills in the name; 0x140013f50 uses WinHTTP; dynamic: GET /id/fknfm59m0j38kd0u4t
> 
> **Source**: `ev-000019` · `ev-000015` · `ev-000016`

### 3. Create hidden desktop

`T1219` · Confidence **high** · static

It creates or opens a hidden desktop with an 'A'/'U' suffix, saves the OpenInputDesktop handle and switches with SetThreadDesktop in the thread, rendering target programs inside the hidden desktop via PrintWindow/StretchBlt to achieve HVNC remote operation; it also prepares the usbmmidd_v2 virtual display driver.

> **Evidence**: 0x140014360 OpenDesktopW/CreateDesktopW; 0x1400013e0 OpenInputDesktop; SetThreadDesktop call sites 0x140014ca1 etc.; strings C:\ProgramData\usbmmidd_v2, usbmmIdd.inf
> 
> **Source**: `ev-000017` · `ev-000015` · `ev-000014`

### 4. Screenshot and stream frames

`T1113` · Confidence **high** · static

It calls PrintWindow on the target window and uses StretchBlt/CreateCompatibleBitmap/CreateDIBSection to produce bitmaps, encoding them to JPEG via GDI+ for playback by the controller.

> **Evidence**: PrintWindow call site 0x140015c93; StretchBlt 0x14001476f, 0x140014820; imports GdipSaveImageToStream/GdipGetImageEncoders; string image/jpeg
> 
> **Source**: `ev-000014` · `ref:fa60173f28` · `ev-000017`

### 5. Global keystroke logging

`T1056.001` · Confidence **high** · static

It installs a global low-level keyboard hook and a WinEvent hook, using GetKeyboardState/ToUnicodeEx to reconstruct keys and the foreground window title, writing keylog.txt for exfiltration.

> **Evidence**: SetWindowsHookExW 0x140019790; GetKeyboardState 0x140018aef; ToUnicodeEx 0x140018b2e; SetWinEventHook 0x140017403; string keylog.txt
> 
> **Source**: `ev-000014` · `ref:fa60173f28`

### 6. Clipboard monitoring and replacement

`T1115` · Confidence **high** · static

It registers a clipboard format listener, reads CF_TEXT/CF_UNICODETEXT and other formats, and can actively write to replace the clipboard (often used to swap wallet addresses).

> **Evidence**: AddClipboardFormatListener; OpenClipboard 0x140016b62/0x140018c67; GetClipboardData 0x140018c76; SetClipboardData 0x140016bd7
> 
> **Source**: `ref:fa60173f28` · `ev-000014`

### 7. Steal browser credentials

`T1555.003` · Confidence **high** · static

It walks the Chrome/Edge/Brave/Opera/Firefox user directories, copies Login Data, Cookies, and Web Data, executes SQL to read logins/cookies/credit_cards, and decrypts using DPAPI and AES-GCM (reading the key from Local State).

> **Evidence**: strings SELECT origin_url, username_value, password_value FROM logins; SELECT ... FROM cookies; credit_cards; CryptUnprotectData/BCryptDecrypt/NCryptOpenKey imports; 0x140001190 main flow loads config
> 
> **Source**: `ev-000014` · `ev-000015` · `ref:fa60173f28`

### 8. Harvest wallet files

`T1005` · Confidence **high** · static

It enumerates wallet directories for Electrum, Exodus, Guarda, Atomic, Armory, Coinomi, Komodo, Wasabi, etc., plus Local Storage/leveldb, packages them, and exfiltrates them.

> **Evidence**: path strings such as %APPDATA%\Electrum\wallets, %APPDATA%\Exodus\exodus.wallet, %APPDATA%\Guarda\Local Storage\leveldb, %LOCALAPPDATA%\Coinomi\Coinomi\wallets
> 
> **Source**: `ev-000014`

### 9. Disable Defender protection

`T1562.001` · Confidence **high** · static

It starts powershell.exe and writes Add-MpPreference -ExclusionPath / -ExclusionProcess scripts through the pipe, adding its own directory and process to Defender exclusions, while running Get-ScheduledJob to probe scheduled tasks.

> **Evidence**: 0x140001510 CreateProcessW(powershell.exe)+WriteFile pipes three Add-MpPreference scripts; string Get-ScheduledJob
> 
> **Source**: `ev-000020` · `ev-000014`

### 10. Fake update to bypass UAC

`T1548.002` · Confidence **medium** · static

It uses a fake Windows security update/Phone Link binding prompt to induce user confirmation, then calls auto-elevating proxies such as ComputerDefaults.exe, winver.exe, or rundll32 shell32.dll #61 to execute the payload.

> **Evidence**: strings C:\Windows\System32\ComputerDefaults.exe, winver.exe, rundll32 "C:\Windows\System32\shell32.dll" #61, ms-phone:, "an important system and security update."
> 
> **Source**: `ev-000014`

### 11. Proxy internal network traffic

`T1090` · Confidence **medium** · static

The module's export name is HVNC_SOCKS5.exe, and it embeds WS2_32 raw-socket forwarding logic, able to establish a SOCKS5 proxy channel on the victim host for the attacker to access the internal network laterally.

> **Evidence**: export DLL name HVNC_SOCKS5.exe; socket/connect/select/recv/send calls around 0x1400106d0 and 0x140013770; WS2_32 raw socket imports (send/recv/select/getsockname/ioctlsocket)
> 
> **Source**: `ref:69b55c7f0b` · `ev-000018` · `ref:fa60173f28`

### 12. Collect host and device information

`T1125` · Confidence **medium** · static

It reads username, computer name/domain, OS version, and hardware information, and enumerates camera/audio devices via Media Foundation, creating source readers with audio/video capture capability.

> **Evidence**: 0x140001190 GetUserNameW/GetComputerNameExW; MFEnumDeviceSources/MFCreateSourceReaderFromMediaSource/MFCreateVideoRendererActivate imports; string camera!
> 
> **Source**: `ev-000015` · `ref:fa60173f28` · `ev-000014`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (retrying multiple times within a short period).
:::

:::caution
**Real server side still unverified**: the connection/handshake above was completed with a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `jujupuluz[.]icu` | 1010 | c2 | dynamic | — |
| http | `hxxps://steamcommunity[.]com/id/fknfm59m0j38kd0u4t` | 443 | other | dynamic | observed |

### Host

**Mutexes**

- `BulletStealGrayColorg`
- `%s_BulletStealGrayColorh`
- `%s_BulletStealGrayColori`

**Drop paths**

- `%LOCALAPPDATA%\BulletStealGrayColora`
- `%LOCALAPPDATA%\BulletStealGrayColorb`
- `%LOCALAPPDATA%\BulletStealGrayColorc`
- `%LOCALAPPDATA%\BulletStealGrayColord`
- `%LOCALAPPDATA%\BulletStealGrayColore`
- `%LOCALAPPDATA%\BulletStealGrayColorf`
- `%LOCALAPPDATA%\BulletStealGrayColorg`
- `C:\ProgramData\Krutyak.zip`
- `C:\ProgramData\usbmmidd_v2`
- `C:\ProgramData\usbmmidd_v2\usbmmIdd.inf`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `jujupuluz[.]icu` | yes | static |
| `c2_port` | `1010` | yes | static |
| `c2_auth_magic` | `':a1+L{yWL920K7=` | yes | static |
| `steam_profile_path` | `id/fknfm59m0j38kd0u4t` | no | dynamic |
| `install_path` | `%LOCALAPPDATA%\BulletStealGrayColora` | yes | static |
| `mutex` | `BulletStealGrayColorg` | yes | static |
| `build_tag` | `BulletStealGrayColor` | yes | static |
| `encryption_algo` | `AES-GCM (BCrypt) + DPAPI(CryptUnprotectData) used for unsealing browser keys/credentials` | no | static |
| `driver_package` | `C:\ProgramData\Krutyak.zip -> C:\ProgramData\usbmmidd_v2` | no | static |

## Must not claim

:::important
The following conclusions are **prone to misjudgment**; take care when citing this report.

- Do not judge it ransomware: no file encryption/ransom notes were found; the AES-GCM and DPAPI calls are used to unseal browser keys and for communication encryption.
- Do not assert registry Run key, service, or scheduled-task persistence: the import table has only RegOpenKeyExW/RegGetValueW reads, with no RegSetValueEx/CreateService/schtasks write calls; currently only Defender exclusions and multiple copies of itself are confirmed.
- Do not treat the public family name as confirmed attribution: BulletSteal comes only from the sample's own build string, lacking multi-engine/YARA cross-validation.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The dynamic session captured only encrypted TCP heartbeats and never reached the command stage; SOCKS5 forwarding and actual HVNC remote operation were not reproduced in a real session.
2. The usbmmidd_v2 driver package (C:\ProgramData\Krutyak.zip) was not observed being dropped/extracted in this run; the driver installation conclusion comes from static strings and scripts.
3. Browser credential, cookie, and wallet-file theft are proven by SQL statements, path strings, and the import table; reads of real user data were not observed in the sandbox (no browser profiles in the environment).
4. The persistence method could not be confirmed: no registry write, service, or scheduled-task creation calls were found; only multiple %LOCALAPPDATA% copy names and a single-instance mutex were seen.
5. The C2 payload was not decrypted; the bot ID, command format, and exfiltration package structure were not obtained.

## Evidence index

<details>
<summary>Expand 14 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hashing and fingerprints | sha256/md5/sha1 and file size |
| `ev-000002` | scan.imphash | imphash=ee100517e971d046ed1372570e0e5361 |
| `ref:db920215da` | PE structure parsing | PE32+ x64 GUI, 6 sections, no resources/debug directory, entry RVA 0x13C2F0 |
| `ref:69b55c7f0b` | pe.exports | export DLL name HVNC_SOCKS5.exe, 78 exports (cJSON) |
| `ref:fa60173f28` | import table parsing | 21 DLLs/364 symbols: WS2_32, WinHTTP, GDI/GDI+, MF, CRYPT32, bcrypt, ncrypt, USER32 hooks/desktop/clipboard |
| `ev-000014` | string extraction | 6066 ASCII/522 UTF-16 strings (browser SQL, wallet paths, Krutyak.zip, usbmmidd, Add-MpPreference, etc.) |
| `ev-000015` | decompile.function | FUN_140001190 main flow: WSAStartup, OpenInputDesktop, GetUserNameW/GetComputerNameExW, loading jujupuluz.icu and Steam path |
| `ev-000016` | decompile.function | FUN_140013900 240-second reconnect loop |
| `ev-000017` | decompile.function | FUN_140014360 creates/opens hidden desktop (A/U suffix) |
| `ev-000018` | decompile.function | FUN_1400106d0 getaddrinfo(1010)/socket/connect + 20-byte handshake and 16-byte magic validation |
| `ev-000019` | decompile.function | FUN_140013770 fetches steamcommunity profile page og:title as bot name |
| `ev-000020` | decompile.function | FUN_140001510 starts powershell to write Add-MpPreference exclusions |
| `ref:5dcffbd8ff` | dynamic analysis platform | real dynamic detonation: sample ran as pid 2600/1688; network monitoring recorded DNS jujupuluz[.]icu 42 times, TCP 1010 encrypted heartbeats, GET steamcommunity[.]com/id/fknfm59m0j38kd0u4t; memory forensics found no injection |
| `c2_evidence:925a9d35` | connection evidence extraction | dynamic network monitoring recorded 1 connection attempt to steamcommunity[.]com:443; no complete session captured |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
