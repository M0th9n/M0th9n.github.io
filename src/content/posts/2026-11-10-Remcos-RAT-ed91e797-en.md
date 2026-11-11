---
title: "Malware Analysis: Remcos RAT (PE · exe · ed91e797)"
published: 2026-11-10
draft: false
description: "Malicious (high confidence): Remcos RAT · rat/stealer · difficulty medium · Dynamic sandbox + static decompilation"
tags: ["Remcos", "rat", "stealer", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-10-Remcos-RAT-ed91e797"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Remcos RAT** · Confidence **high**
> 
> Aliases: Remcos, Remote Control System, Rmc, Remcos Pro 7.3.1
> 
> Static decompilation confirmed that the sample decrypts the Remcos configuration from the RCDATA resource SETTINGS with RC4 (three C2 sets, mutex Rmc-G46BB4, group name jardon); in an isolated Windows 10 dynamic sandbox, the sample was observed initiating TCP connections to 203.202.232[.]26 on ports 14641/14642/14643 and sending a complete login packet containing the hostname, username, and group name, which is typical remote-access trojan behavior.

## Overview

| Item | Content |
|:--|:--|
| Family | **Remcos RAT** · Aliases Remcos, Remote Control System, Rmc, Remcos Pro 7.3.1 |
| Confidence | **high** |
| Behavior class | rat · stealer |
| Difficulty | medium |
| First seen | 2026-11-08 08:30:06 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ed91e797ca9c4e4eebab32a142579df03627aeec35539daf43bbc17f7943ae89/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">RC4-decrypt embedded config</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Callback to three C2 ports</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Exfiltrate host fingerprint</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Keylogging and clipboard</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Steal browser credentials</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `ed91e797ca9c4e4eebab32a142579df03627aeec35539daf43bbc17f7943ae89` |
| MD5 | _not recorded_ |
| Size | 537,088 bytes (524.5 KB) |
| Type | PE · `exe` |

## Behavior analysis

**9** behaviors in total, each backed by evidence; **7** are statically available and **2** were obtained through dynamic analysis.

### 1. RC4-decrypt embedded config

`T1027` · Confidence **high** · static

From the RCDATA resource SETTINGS (offset 0x7E9CC, 709 bytes), it reads the first byte 0xA7 as the key length, takes the following 167 bytes as the RC4 key, and decrypts the remaining 541 bytes to obtain the C2, group name, mutex, install path, and other configuration.

> **Evidence**: 0x41FA84 FindResourceA("SETTINGS", RT_RCDATA=10); 0x414E65 splits key/ciphertext by the first byte; 0x407BA2 RC4 KSA; 0x407C11 RC4 PRGA
> 
> **Source**: `ev-000016` · `ev-000017` · `ev-000020` · `ev-000021` · `ev-000022`

### 2. Callback to three C2 ports

`T1095` · Confidence **high** · dynamic

After running, it connects to TCP 14641, 14642, and 14643 on 203.202.232[.]26 in sequence according to the configuration, and sends a Remcos login packet containing host and user information.

> **Evidence**: dynamic network log: pid 7048 requested TCP 203.202.232[.]26:14641 / 14642 / 14643; the raw listener captured the login packet, header 24 04 FF 00 56 03 00 00
> 
> **Source**: `ref:3499ffcdab` · `ev-000022` · `ev-000023`

### 3. Exfiltrate host fingerprint

`T1082` · Confidence **high** · dynamic

The login packet carries the computer name DESKTOP-7QK4M2P, username analyst, Windows 10 Home China (64 bit), CPU model, NIC, and installation data path, for the controller to identify the victim.

> **Evidence**: plaintext fields of the dynamic login packet: DESKTOP-7QK4M2P / analyst / Windows 10 Home China (64 bit) / i5-12500H / C:\Users\analyst\rem\jardon.dat
> 
> **Source**: `ev-000023` · `ref:3499ffcdab`

### 4. Keylogging and clipboard

`T1056.001` · Confidence **high** · static

Imports and calls SetWindowsHookExA, ToUnicodeEx, and GetKeyboardState to implement keylogging, and reads/writes the clipboard, marking content in the log with [Text copied/pasted from clipboard].

> **Evidence**: USER32 imports SetWindowsHookExA/ToUnicodeEx/GetKeyboardState/GetClipboardData; strings offset 456744 'Online Keylogger Started', 457302 '[Text copied to clipboard]'
> 
> **Source**: `ref:ce6c98fabb` · `ref:ed631441ae`

### 5. Steal browser credentials

`T1555.003` · Confidence **high** · static

Enumerates the Chrome, Edge, Brave, Yandex, Opera, and Firefox profile directories, reads Login Data, Cookies, Network\Cookies, logins.json, key3.db, and cookies.sqlite, and has a trace-clearing function.

> **Evidence**: strings '\Google\Chrome\User Data', '\Microsoft\Edge\User Data', '\Mozilla\Firefox\Profiles\', '\Login Data', '\logins.json', 'RecoverCookies', '[Cleared browsers logins and cookies.]'
> 
> **Source**: `ref:ed631441ae` · `ev-000012`

### 6. Screenshots and microphone recording

`T1113` · Confidence **high** · static

Captures the screen via BitBlt/GetDIBits and encodes it as JPEG/PNG with GDI+, collects microphone audio via waveInOpen/waveInAddBuffer, and saves to the Screenshots and MicRecords directories.

> **Evidence**: GDI32 BitBlt/GetDIBits, gdiplus GdipSaveImageToStream, WINMM waveInOpen/waveInAddBuffer; strings 'wnd_%04i%02i%02i_%02i%02i%02i', 'MicRecords', 'image/jpeg'
> 
> **Source**: `ref:ce6c98fabb` · `ref:ed631441ae`

### 7. Remote commands and file transfer

`T1059.003` · Confidence **high** · static

Creates cmd.exe/powershell pipes to execute commands, uses URLDownloadToFileW/InternetOpenUrlW to download files, reads files and uploads them to the controller, and ShellExecute executes dropped files.

> **Evidence**: KERNEL32 CreateProcessW/CreatePipe/PeekNamedPipe; urlmon URLDownloadToFileW; WININET InternetOpenUrlW; strings 'Downloading file: ', 'Uploading file to Controller: ', 'Executing file: ', '-ExecutionPolicy Bypass -File "'
> 
> **Source**: `ref:ce6c98fabb` · `ref:ed631441ae`

### 8. Detect debugging and virtual environments

`T1622, T1497.001` · Confidence **high** · static

Through IsDebuggerPresent, GetThreadContext hardware breakpoint checks, rdtsc timing differences, PEB fs:[0x30] access, and cpuid, it probes for debugger/virtual machine environments.

> **Evidence**: IsDebuggerPresent/GetThreadContext imports; rdtsc @ rva 0x1F854; PEB fs:[0x30] @ rva 0x4C91F; cpuid @ rva 0x1FF2D
> 
> **Source**: `ref:c6a4c1ca2d`

### 9. UAC bypass and autostart

`T1548.002` · Confidence **medium** · static

Built-in CMSTPLUA COM elevation code (Elevation:Administrator!new:), plus autostart write logic for the HKCU Run key, service startup, and scheduled tasks.

> **Evidence**: strings offset 455884 'Elevation:Administrator!new:', 455944 '{3E5FC7F9-9A51-4367-9063-A120244FBEC7}', 459160 '\Software\Microsoft\Windows\CurrentVersion\Run\', 'SetSvcStartup', 'sc.exe'
> 
> **Source**: `ref:ed631441ae` · `ref:ce6c98fabb`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (retrying multiple times within a short period).
:::

:::caution
**Real server side still unverified**: the above connection/handshake was completed with a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `203.202.232[.]26` | 14641 | c2 | dynamic | observed |
| tcp | `203.202.232[.]26` | 14642 | c2 | dynamic | observed |
| tcp | `203.202.232[.]26` | 14643 | c2 | dynamic | observed |

### Host

**Mutex**

- `Rmc-G46BB4`

**Dropped paths**

- `%USERPROFILE%\rem\remcos.exe`
- `%USERPROFILE%\rem\jardon.dat`
- `%USERPROFILE%\rem\Screenshots`
- `%USERPROFILE%\rem\MicRecords`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Remcos`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `203.202.232[.]26` | yes | dynamic |
| `c2_port` | `14641,14642,14643` | yes | dynamic |
| `protocol` | `Custom TCP; login packet is plaintext, third field of the configuration is 0 (TLS not enabled)` | yes | dynamic |
| `mutex` | `Rmc-G46BB4` | yes | dynamic |
| `campaign_id` | `jardon` | no | dynamic |
| `install_path` | `%USERPROFILE%\rem\remcos.exe` | yes | static |
| `data_path` | `%USERPROFILE%\rem\jardon.dat` | no | dynamic |
| `encryption_algo` | `RC4 (first byte of the SETTINGS resource is the 167-byte key length)` | yes | static |
| `license_hash` | `518623F80A34DBC0774CC6ED9E261BD9` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- Do not judge it as ransomware based only on BitBlt/GDI+ and file operation APIs; the sample has no code path that encrypts user files, and no ransomware behavior was observed.
- Do not claim that this run wrote the Run key or created a service; dynamic telemetry shows the Run key was unchanged before and after execution, and no new service was found.
- Do not claim that a second-stage payload was downloaded or executed; no download, drop, or new process was observed during the dynamic phase.
- Ports 14641/14642/14643 on 203.202.232[.]26 are primary/backup ports within the same configuration and should not be split into three independent C2s.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. The dynamic phase only captured the login packet sent by the sample to the C2; no server response or task instruction was received, so the control channel's bidirectional interaction capability is unverified.
2. The configuration was recovered by static RC4 decryption; the group name, mutex, and C2 in the dynamic login packet match it; the install and persistence paths come from the configuration and login packet, and actual disk writes were not observed.
3. The sample was run directly from the analysis directory, so the self-install flow was not triggered; therefore files under %USERPROFILE%\rem and the autostart entry did not appear in this dynamic run.
4. Memory dumps and full-process scanning found no signs of process hollowing/injection; imports such as WriteProcessMemory/SetThreadContext only show the capability exists and cannot prove it was used.
5. Telemetry showed no changes to Defender exclusions, services, or scheduled tasks; the related persistence descriptions are inferences from static code paths.

## Evidence index

<details>
<summary>Show 17 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprinting | sha256/md5/sha1, size 537088 bytes |
| `ev-000004` | scan.entropy | .text entropy 6.639, no high-entropy encrypted section seen |
| `ev-000016` | decompile.ghidra | 0x41FA84: FindResourceA reads the RCDATA resource named SETTINGS |
| `ev-000017` | decompile.ghidra | 0x414E65: the first byte is the key length; splits key and ciphertext, then calls RC4 decryption |
| `ev-000020` | decompile.ghidra | 0x407BA2: RC4 KSA (256-entry state initialization and permutation) |
| `ev-000021` | decompile.ghidra | 0x407C11: RC4 PRGA (byte-by-byte XOR decryption) |
| `ev-000022` | evidence.record | The script decrypts SETTINGS with the above algorithm, obtaining three C2 sets, group name jardon, mutex, and install/data paths |
| `ev-000023` | evidence.record | Extracts the three-port connections and complete login packet fields of pid 7048 from dynamic sandbox artifacts |
| `ev-000027` | String extraction | String evidence: Remcos identifiers, browser credential paths, keylogging/clipboard, UAC, download/upload, Run key |
| `ev-000013` | Cryptographic constant identification | SHA-256 constants (for hashing/verification); no AES/DES constants found |
| `ref:ce6c98fabb` | Import table parsing | 285 imports: keyboard hook, clipboard, screenshot, recording, network, process, and registry APIs |
| `ref:c6a4c1ca2d` | unpack.antidebug | IsDebuggerPresent/GetThreadContext/rdtsc/PEB/cpuid anti-debug and virtual environment detection |
| `ref:3499ffcdab` | Dynamic analysis platform | Isolated Windows 10 sandbox detonation: process 7048 created, 3 C2 callbacks, 6 memory dumps, no injection hits |
| `ref:9852296be7` | unpack.detect | Not packed; the entry code can be analyzed directly |
| `c2_evidence:ed91e797` | Connection evidence extraction | Dynamic network monitoring recorded 5 connection attempts to 203.202.232[.]26:14641, 203.202.232[.]26:14642, 203.202.232[.]26:14643; no complete session was captured |
| `telemetry:ed91e797` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 123; ETW short-lived process events 1; filtered tool/system noise 27 |
| `etw:ed91e797:7048` | Process event monitoring | Short-lived process event: ed91e797ca9c4e4eebab32a142579df03627aeec35539daf43bbc17f7943ae89.exe (pid 7048; MD5=3AC9FE62B05AA373958650EDE3FC4843,SHA256=ED91E797CA9C4E4EEBAB32A142579DF03627AEEC35539DAF43BBC17F7943AE89,IMPHASH=117B0E98FCD98802425109064482959B) |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
