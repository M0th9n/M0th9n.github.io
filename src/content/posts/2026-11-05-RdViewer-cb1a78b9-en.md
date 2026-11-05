---
title: "Malware Analysis: RdViewer (PE · exe · cb1a78b9)"
published: 2026-11-05
draft: false
description: "Malicious (high confidence): RdViewer · rat/dropper · difficulty medium · dynamic sandbox + static decompilation"
tags: ["RdViewer", "rat", "dropper", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-05-RdViewer-cb1a78b9"
---

> [!WARNING]
> **Verdict: Malicious** · Family **RdViewer** · Confidence **high**
> 
> Aliases: RdViewer RAT, RdViewer remote control, KuaiAn RdViewer
> 
> The sample is an installer disguised as a disk management tool: it drops rdservice.exe, diskmgr.exe, host.dat and cfg.ini from its own resources to C:\ProgramData\host, and registers and starts the Rd_Service service; the dropped diskmgr.exe repeatedly connects out to 118.25.151[.]128:7788 in the dynamic sandbox, sending custom binary heartbeats, which is covert deployment of a remote-control component rather than normal software distribution.

## Overview

| Item | Content |
|:--|:--|
| Family | **RdViewer** · aliases RdViewer RAT, RdViewer remote control, KuaiAn RdViewer |
| Confidence | **high** |
| Behavior class | rat · dropper |
| Difficulty | medium |
| First seen | 2026-11-01 18:05:43 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/cb1a78b9a84034d03c92e59bb106a8feb8d26813495925e86aa7efcec160f10e/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Drop embedded RAT components</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Register auto-start service</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Masquerade as disk manager</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Resource check evasion</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Connect to RAT server</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">observed</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `cb1a78b9a84034d03c92e59bb106a8feb8d26813495925e86aa7efcec160f10e` |
| MD5 | _not recorded_ |
| Size | 25,624,592 bytes (24.4 MB) |
| Type | PE · `exe` |

## Behavior analysis

**8** behaviors in total, each backed by evidence; **7** are statically recoverable and **1** was obtained through dynamic analysis.

### 1. Drop embedded RAT components

`T1105` · Confidence **high** · static

It drops RDSERVICE (rdservice.exe, 2,637,128B), DISKMGR (diskmgr.exe, 22,848,528B), HOSTDAT (host.dat) and CFGINI (cfg.ini) from its own FILE resources to C:\ProgramData\host.

> **Evidence**: FUN_004011b0 @0x4011b0 calls FindResourceW/LoadResource/WriteFile; FUN_00401550 @0x401550 writes the four target paths in sequence
> 
> **Source**: `ref:7b3e18e5f4` · `ref:bbb1542f6a` · `ref:424fececda`

### 2. Register auto-start service

`T1543.003` · Confidence **high** · static

With administrator rights it calls CreateServiceW to create the Rd_Service service (display name DMService, ImagePath pointing to C:\ProgramData\host\dmservice.exe), then StartServiceW to start it, achieving boot-time auto-start residency.

> **Evidence**: FUN_00401550 @0x401550 CreateServiceW/StartServiceW; manifest requestedExecutionLevel=requireAdministrator; in the dynamic sandbox dmservice.exe (pid 884) ran from this path
> 
> **Source**: `ref:bbb1542f6a` · `ref:1a184bc168` · `ref:6287d40da1`

### 3. Masquerade as disk manager

`T1036.005` · Confidence **high** · static

It names the dropped files dmservice.exe/diskmgr.exe and forges their version information as Disk Manager Service Installer / Disk Manager Tool (SelfDev Studio), storing them in C:\ProgramData\host to blend into operations directories.

> **Evidence**: main program VS_VERSION_INFO: FileDescription=Disk Manager Service Installer, InternalName=dm_loader.exe, ProductName=Disk Manager Tool; drop path C:\ProgramData\host\*.exe
> 
> **Source**: `ref:424fececda` · `ref:bbb1542f6a`

### 4. Resource check evasion

`T1497.001` · Confidence **high** · static

At startup it counts physical cores with GetLogicalProcessorInformation and exits immediately when there are fewer than 2 physical cores or less than 4000MB of physical memory, avoiding execution in sandbox/low-spec analysis environments.

> **Evidence**: FUN_00401050 @0x401050 GetLogicalProcessorInformation; FUN_00401550 GlobalMemoryStatusEx then threshold check and return 0
> 
> **Source**: `ref:2a46cb2f75` · `ref:bbb1542f6a`

### 5. Kill old RAT processes

`T1489` · Confidence **high** · static

It enumerates a process snapshot and, on finding an old same-named process, ends it with OpenProcess+TerminateProcess; before installing it also stops and deletes the old Rd_Service service via ControlService/DeleteService, then recreates it.

> **Evidence**: FUN_00401340 @0x401340 CreateToolhelp32Snapshot/Process32FirstW/OpenProcess/TerminateProcess; FUN_00401550 ControlService/DeleteService
> 
> **Source**: `ref:7d5a43cd6f` · `ref:bbb1542f6a`

### 6. Connect to RAT server

`T1071` · Confidence **high** · dynamic

The dropped diskmgr.exe repeatedly opens TCP connections to 118.25.151[.]128:7788, sending a 44-byte custom binary frame (81 78 17 01 1C 00 00 00 + 36 bytes of data), and retries periodically after connection timeouts.

> **Evidence**: dynamic network log: diskmgr.exe (pid 7332) -> 118.25.151[.]128:7788, RawTCP 44-byte frame, multiple reconnects from 03:43:12
> 
> **Source**: `ref:1a184bc168` · `ref:b254a76354`

### 7. Drop encrypted host configuration

`T1027` · Confidence **medium** · static

The dropped cfg.ini and host.dat hold base64-encoded, 16-byte-aligned ciphertext fields (Self=32B, User=16B, host=48B, mark=32B) used to carry host and user identifier configuration.

> **Evidence**: CFGINI content [Main] Self=/User=; HOSTDAT content [Main] host=/mark=; each field decodes from base64 to 16-byte-aligned ciphertext
> 
> **Source**: `ref:424fececda` · `ref:7b3e18e5f4`

### 8. Built-in remote desktop control

`T1219` · Confidence **high** · static

rdservice.exe is the RdViewer remote-desktop server, with screen capture (GDI BitBlt/StretchBlt), keyboard/mouse input, clipboard/printer/network-share enumeration, WTS session notifications, and a WebRTC remote-control channel based on sgcWebSockets/RTCMultiConnection.

> **Evidence**: RDSERVICE strings TMouse/TLoginCredentialService/GetDC/BitBlt/OpenClipboard/WTSRegisterSessionNotification; the memory image hits D:\work\RdViewer\...\strfunc.pas and the rdviewer[.]com user-agreement URL
> 
> **Source**: `ref:d87e4aaf50` · `ref:d831fef60f` · `ref:1ff4bf99f9`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (multiple retries within a short period).
:::

:::caution
**Real server side still unverified**: the connections/handshakes above were completed with a local controlled emulation service, and the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `118.25.151[.]128:7788` | 7788 | c2 | dynamic | observed |

### Host

**Dropped paths**

- `C:\ProgramData\host\`
- `C:\ProgramData\host\dmservice.exe`
- `C:\ProgramData\host\diskmgr.exe`
- `C:\ProgramData\host\host.dat`
- `C:\ProgramData\host\cfg.ini`

**Registry**

- `HKLM\SYSTEM\CurrentControlSet\Services\Rd_Service`

**Services**

- `Rd_Service (display name DMService, ImagePath=C:\ProgramData\host\dmservice.exe)`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `118.25.151[.]128:7788` | yes | dynamic |
| `install_path` | `C:\ProgramData\host` | yes | static |
| `service_name` | `Rd_Service` | yes | static |
| `service_display_name` | `DMService` | yes | static |
| `config_files` | `cfg.ini / host.dat; all field values are base64-encoded, 16-byte-aligned ciphertext (Self=32B, User=16B, host=48B, mark=32B)` | no | static |
| `protocol_frame` | `44-byte binary frame: 81 78 17 01 1C 00 00 00 + 36 bytes of data` | no | dynamic |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not judge the main program packed solely from .rsrc entropy 7.963: the high entropy comes from the embedded 22.8MB PECompact-packed diskmgr.exe, and the loader itself is not packed.
- No credential theft, browser-data exfiltration or file encryption was observed; it should not be classified as a stealer or ransomware.
- Do not assert that host.dat uses AES, or claim that the host name was decrypted from the configuration; the C2 address comes from runtime network observation, and the configuration decryption logic was not recovered.
- rdviewer[.]com is the RdViewer product website/protocol domain and should not be reported as a C2 IOC.
- The sample requires administrator privileges to install the service; its complete behavior was not verified in a non-administrator context.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. cfg.ini/host.dat are 16-byte-aligned base64 ciphertext, and the decryption algorithm and key were not recovered; the C2 address comes from runtime network observation rather than configuration decryption.
2. diskmgr.exe is PECompact-packed, limiting static imports/strings; this analysis relies on the memory image and dynamic behavior.
3. Only the heartbeat connection was observed in the sandbox (the custom protocol was not answered); screen control, file transfer and similar capabilities come from component characteristics and code structure and were not actually triggered in this session.
4. dmservice.exe ran within the sampling window, but no independent memory dump of it was obtained, and the server-side protocol implementation was not verified function by function.

## Evidence index

<details>
<summary>Expand 20 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:9d6ffc9c6a` | sample triage | Main program hashes/section entropy/import surface/packing score: .rsrc entropy 7.963, 25624592 bytes |
| `ref:6287d40da1` | PE structure parsing | PE32 GUI, 6 sections, resource directory 25,487,712 bytes, entry 0x401c50 |
| `ref:d43be434b4` | import table parsing | Only KERNEL32/ADVAPI32, 90 imports in total, including FindResourceW/CreateServiceW/StartServiceW/TerminateProcess |
| `ev-000032` | decompile.function | entry calls FUN_00401f70 / FUN_00401a60 |
| `ev-000034` | decompile.function | FUN_00401550: CPU/memory check, service stop-delete-recreate, drop 4 files, create Rd_Service |
| `ev-000035` | decompile.function | FUN_004011b0: FindResourceW/LoadResource/WriteFile resource drop |
| `ev-000039` | decompile.function | FUN_00401050: GetLogicalProcessorInformation counts physical cores |
| `ev-000040` | decompile.function | FUN_00401340: process snapshot enumeration and TerminateProcess |
| `ref:c0c2de9ec6` | PE structure parsing | RDSERVICE resource is a 32-bit PE, a Delphi program, exporting rdService.exe, 13 imported DLLs |
| `ref:5ca8f804ac` | pe.exports | Exports dll_name=rdService.exe, including __dbk_fcall_wrapper (Delphi) |
| `ref:d831fef60f` | import table parsing | RDSERVICE imports GDI/user32/WTSAPI32/advapi32, including BitBlt/OpenClipboard/WTSRegisterSessionNotification/CreateProcessAsUserW |
| `ref:3ec3a4e7d2` | PE structure parsing | DISKMGR resource is a 32-bit PE, 22.8MB, .text writable and executable, abnormal export directory |
| `ref:a30b148cf3` | unpack.detect | DISKMGR judged PECompact-packed, strategy emulate_to_oep |
| `ref:b254a76354` | dynamic analysis platform | Real dynamic detonation: main process pid 7680, early dump 38,189,915 bytes, rollback completed |
| `ref:1ff4bf99f9` | hashing and fingerprinting | RDSERVICE sha256=7ed2a077a1ce34fcb182e5135ae75ad7bd96207c3204c9f343095f967bfa109f |
| `ref:8a3ce691e1` | hashing and fingerprinting | DISKMGR sha256=e9518c1cf8d5c58f25f50fe2911ce2de86aba766e91a5efa86450607528245ba |
| `ev-000036` | evidence.record | Resource directory/version information and configuration field decoding results |
| `ev-000037` | evidence.record | Isolated network log: diskmgr.exe -> 118.25.151[.]128:7788, 44-byte frame; process path C:\ProgramData\host |
| `ev-000038` | evidence.record | Memory image strings: rdviewer[.]com user agreement, D:\work\RdViewer source path, WebRTC components |
| `c2_evidence:cb1a78b9` | connection evidence extraction | Dynamic network monitoring recorded 3 connection attempts to 118.25.151[.]128:7788; no complete session captured |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
