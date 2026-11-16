---
title: "Malware Analysis: Unclassified Delphi Wallet Stealer (PE · exe · d7fa54fc)"
published: 2026-11-15
draft: false
description: "Malicious (medium confidence): Unclassified Delphi wallet stealer · stealer · difficulty medium · dynamic sandbox + static decompilation"
tags: ["未分类 Delphi", "stealer", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-15-未分类-Delphi-钱包窃密木马-d7fa54fc"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Unclassified Delphi wallet stealer** (uncertain) · Confidence **Medium**
> 
> In the dynamic sandbox the sample self-copied to %LOCALAPPDATA%\Nvidia\Windows\Temp\F19C6B8F\WindowsTouchService.exe, registered a scheduled task named PowerPoint Pen Task with schtasks, and had the Task Scheduler service relaunch that copy; the copy resolved index[.]brew-reef[.]lat and issued a /health liveness probe plus an encoded-path data upload; the unpacked memory image contains a mutex, the C2 address, and wallet and browser-extension data lists, which together form wallet-stealer behavior.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Unclassified Delphi wallet stealer** · _uncertain_ |
| Confidence | **Medium** |
| Behavior class | stealer |
| Difficulty | medium |
| First seen | 2026-11-13 00:02:21 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Self-copy to Nvidia dir</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Register scheduled task</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.005</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Query task existence</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.005</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Mutex prevents re-run</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">HTTPS beacon check-in</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066` |
| MD5 | _not recorded_ |
| Size | 3,027,968 bytes (2.9 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**10** behaviors in total, each backed by evidence; **5** are statically available and **5** were obtained through dynamic analysis.

### 1. Self-copy to Nvidia directory

`T1036.005` · Confidence **High** · Dynamic

The process copied itself in full to %LOCALAPPDATA%\Nvidia\Windows\Temp\F19C6B8F\WindowsTouchService.exe; the copy's hash is identical to the original sample, using an NVIDIA directory and a service-style filename to avoid attention.

> **Evidence**: Dynamic file-creation event: PID 4964 wrote C:\Users\analyst\AppData\Local\Nvidia\Windows\Temp\F19C6B8F\WindowsTouchService.exe; unpacked image offsets 0x324b0/0x32500 also contain %LOCALAPPDATA% and WindowsTouchService.exe
> 
> **Source**: `ref:5541863fe4` · `ref:0754225322`

### 2. Register scheduled task for persistence

`T1053.005` · Confidence **High** · Dynamic

Calls schtasks.exe to create a scheduled task named PowerPoint Pen Task whose action points at the copy above; the task is then launched by the Task Scheduler service (the copy's PID 4876 has svchost.exe as its parent).

> **Evidence**: Dynamic process creation: schtasks /create /tn "PowerPoint Pen Task" /tr "C:\Users\analyst\AppData\Local\Nvidia\Windows\Temp\F19C6B8F\WindowsTouchService.exe"; unpacked image offset 0x32760 stores the same task name
> 
> **Source**: `ref:5541863fe4` · `ref:0754225322`

### 3. Query task existence

`T1053.005` · Confidence **Medium** · Dynamic

Uses schtasks /query /tn "%s" to check whether the scheduled task is already registered, for first-run detection and to avoid duplicate registration.

> **Evidence**: Unpacked image offset 0x32728 holds the string schtasks /query /tn "%s"; dynamic logs recorded schtasks /query /tn "PowerPoint Pen Task"
> 
> **Source**: `ref:0754225322`

### 4. Mutex prevents multiple runs

`T1480` · Confidence **Medium** · Static

Creates the named mutex Global\E3E7B4C756F984CD to ensure only one instance runs per host.

> **Evidence**: Unpacked image offset 0x32480 holds the UTF-16 string Global\E3E7B4C756F984CD; imports CreateMutexW/OpenMutexW (IAT region 0x35540)
> 
> **Source**: `ref:0754225322`

### 5. HTTPS beacon check-in

`T1071.001` · Confidence **High** · Dynamic

Uses built-in WinINet to connect to hxxps://index[.]brew-reef[.]lat/, first probing with GET /health, with the User-Agent spoofed as an Opera/Chrome browser.

> **Evidence**: Network monitoring: DNS index[.]brew-reef[.]lat, TCP 443, "GET /health HTTP/1.1", Host: index[.]brew-reef[.]lat; unpacked image offsets 0x33448/0x33fa0/0x33530 store the C2, /health and the UA
> 
> **Source**: `ref:47e114b197` · `ref:0754225322`

### 6. Encoded-path data exfiltration

`T1071.001` · Confidence **High** · Dynamic

Encodes collected results with a fixed character table and appends them to the URL path, exfiltrating via GET /<about 500-byte encoded string>.html; the path templates are %s://%s/l/%s and %s%s.html.

> **Evidence**: Network monitoring: GET /auwzaagzqvzyrjshwzfrkyzvwzwdonzyhcwzfrwzms/.../dvrjivmskbwdmsshqvwzob.html, Host: index[.]brew-reef[.]lat; unpacked image 0x2de20 '%s://%s/l/%s', 0x2de40 '%s%s.html', 0x677d0 character table ABCDEFGHIJKLMNOPQRSTUVWXYZ{|}~
> 
> **Source**: `ref:47e114b197` · `ref:0754225322`

### 7. Steal wallet files

`T1555` · Confidence **High** · Static

Enumerates desktop wallet data from a built-in list: the wallet/leveldb directories and *.keys files of Exodus, Electrum/Electrum-LTC, Coinomi, Guarda, Ledger Live and Monero GUI, staged for exfiltration.

> **Evidence**: Unpacked image UTF-16 configuration 0x2f3f0-0x323b0: %APPDATA%\Exodus\exodus.wallet\*.*, %APPDATA%\Electrum\wallets\*.*, %LOCALAPPDATA%\Coinomi\Coinomi\wallets\*.*, %USERPROFILE%\Documents\Monero\wallets\*.keys, %APPDATA%\Ledger Live\Local Storage\leveldb\*.*
> 
> **Source**: `ref:0754225322` · `ref:cfb6fc9a82`

### 8. Read browser wallet databases

`T1539` · Confidence **High** · Static

Reads Chrome/Edge/Opera/Opera GX/Brave user data and the Local Storage\leveldb of atomic/Exodus/Guarda, and collects data from the Local Extension Settings of more than 30 wallet extensions.

> **Evidence**: Unpacked image: %LOCALAPPDATA%\Google\Chrome\User Data, %LOCALAPPDATA%\Microsoft\Edge\User Data, %APPDATA%\Opera Software\Opera GX Stable, Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\*.* (MetaMask) and others at 0x2f300-0x323b0
> 
> **Source**: `ref:0754225322`

### 9. Enumerate AV and fingerprints

`T1518.001` · Confidence **High** · Static

Queries ROOT\SecurityCenter2 AntiVirusProduct via WMI and reads the OS version registry, computer name, username, language and bitness, assembling JSON fields such as guid/system/antivirus/localeName.

> **Evidence**: Unpacked image: ROOT\SecurityCenter2, SELECT * FROM AntiVirusProduct (0x34670/0x346a8), SOFTWARE\Microsoft\Windows NT\CurrentVersion (0x34310), JSON keys guid/system/bits/localeName/iCountry/antivirus/computername/username/userDomain/buildId/thread (0x33640-0x33730); imports CoCreateInstance/RegQueryValueExW
> 
> **Source**: `ref:0754225322`

### 10. Built-in anti-debug anti-VM

`T1497.001` · Confidence **High** · Static

The wrapper uses rdtsc timing deltas, int 2Dh and cpuid to detect virtual machines and debuggers; when the emulation environment fails the self-check it shows Initialization error 3 and exits with 0xdeadc0de.

> **Evidence**: Static identification: inside .GN} rva 0x1F2B84(rdtsc), 0x20ED3D(int 2Dh), 0x2493F4(cpuid); emulated execution reaches MessageBoxW("Initialization error 3") then ExitProcess(0xdeadc0de)
> 
> **Source**: `ref:e0fd398b9e` · `ref:c5892d94db`


## IOCs (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (multiple retries within a short period).
:::

:::caution
**Real server side still unverified**: the above connection/handshake was completed with a local controlled emulation service; the real C2's responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://index[.]brew-reef[.]lat/` | 443 | c2 | Dynamic | Observed |
| http | `hxxp://index[.]brew-reef[.]lat/` | 80 | c2 | Static | ⏳ Not observed |

### Host

**Mutexes**

- `Global\E3E7B4C756F984CD`

**Dropped paths**

- `%LOCALAPPDATA%\Nvidia\Windows\Temp\<8-hex-digit>\WindowsTouchService.exe`

**Scheduled tasks**

- `PowerPoint Pen Task`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `index[.]brew-reef[.]lat` | Yes | Dynamic |
| `c2_port` | `443` | Yes | Dynamic |
| `c2_uri` | `/health; /l/<encoded string>.html` | Yes | Dynamic |
| `install_path` | `%LOCALAPPDATA%\Nvidia\Windows\Temp\<8-hex-digit>\WindowsTouchService.exe` | Yes | Dynamic |
| `task_name` | `PowerPoint Pen Task` | Yes | Dynamic |
| `mutex` | `Global\E3E7B4C756F984CD` | No | Static |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0[.]0 Safari/537.36 OPR/114.0.0[.]0` | No | Dynamic |
| `build_id` | `dfc20934` | No | Static |
| `uri_encoding` | `fixed character table (mapping over the full printable ASCII range ABCDEFGHIJKLMNOPQRSTUVWXYZ{\|}~) appended into the path; exact algorithm not fully recovered` | No | Static |

## What Not to Misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not classify it as ransomware/wiper: no file encryption or disk destruction was observed; the core objective is stealing wallet and browser data.
- Do not claim a second-stage payload was downloaded and executed: dynamic analysis recorded only liveness probes and data-exfiltration requests; no new executable landed.
- Do not claim a service or Run-key autostart was created: telemetry shows no service/autostart writes by this sample; persistence relies on the scheduled task.
- Do not assert keylogging merely because SetWindowsHookExW is imported: no hook-installation event was observed dynamically; this is a static capability only.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `bb8b3248aaa6f716eb13abcde1bf9cf698949eafe544e085c00dda4bfb1c4c8f`) |

**Limitations and pending verification**

1. No multi-engine verdict or family YARA hit; the family name is undetermined and classification relies only on configuration and behavior.
2. Static disassembly is limited by the wrapper (a single high-entropy section, entry in an encrypted region, emulation self-check failing with Initialization error 3); function-level details come mainly from the unpacked memory image and dynamic behavior.
3. C2 responses were returned by the fake network; real commands/panel protocol were not observed; URL path encoding is confirmed only as a mapping over a printable character table, with the exact algorithm not fully recovered.
4. Keylogging, process enumeration and process creation are import capabilities of the unpacked image; not all were triggered dynamically and none were counted as observed behaviors.
5. Persistence relies on the scheduled task; if it is blocked, only first execution and manual execution of the self-copy remain.
6. Telemetry did not record the task XML or file-write details; the task action path and the parent-child relationship were cross-corroborated from process-creation and file-creation event timelines.

## Evidence Index

<details>
<summary>Expand 12 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash calculation | sha256=d7fa54fc…c066, md5=8d8b9c21d51ad17ada6895888149bd1f |
| `ev-000002` | Import hash calculation | imphash=3b33063fa6540cfc510bd20fcc99cc96 |
| `ev-000008` | Section entropy analysis | Executable section .GN} entropy 7.952, accounting for most of the file |
| `ev-000009` | Structure triage | Packing likelihood 25%, sole signal is very few imports (3) |
| `ev-000019` | Dynamic sandbox timeline/system telemetry | Self-copy path, schtasks creation of PowerPoint Pen Task, Task Scheduler launching copy PID 4876 |
| `ev-000020` | Network monitoring log | DNS index[.]brew-reef[.]lat; GET /health and GET /<encoded>.html, Host and Opera UA |
| `ev-000021` | Unpacked memory image strings | C2 and /health, mutex, task name, wallet and extension lists, WMI AV query, fingerprint JSON keys |
| `c2_evidence:d7fa54fc` | Connection evidence extraction | Dynamic network monitoring recorded 2 connection attempts to index[.]brew-reef[.]lat:443; no complete session captured |
| `telemetry:d7fa54fc` | Dynamic telemetry | Dynamic telemetry recorded: monitoring components process/file events 136; ETW short-lived process events 3; filtered tool/system noise 27 |
| `etw:d7fa54fc:4964` | Process event monitoring | Short-lived process event: d7fa54fc22418134af1b33b923d2a2d76e3ecf871e3dfd337b46d0aea7b1c066.exe (pid 4964; MD5=8D8B9C21D51AD17ADA6895888149BD1F,SHA256=D7FA54FC22418134AF1B33B923D2A2D76E3ECF871E3DFD337B46D0AEA7B1C066,IMPHASH=3B33063FA6540CFC510BD20FCC99CC96) |
| `etw:d7fa54fc:4580` | Process event monitoring | Short-lived process event: WindowsTouchService.exe (pid 4580; MD5=8D8B9C21D51AD17ADA6895888149BD1F,SHA256=D7FA54FC22418134AF1B33B923D2A2D76E3ECF871E3DFD337B46D0AEA7B1C066,IMPHASH=3B33063FA6540CFC510BD20FCC99CC96) |
| `etw:d7fa54fc:4876` | Process event monitoring | Short-lived process event: WindowsTouchService.exe (pid 4876; MD5=8D8B9C21D51AD17ADA6895888149BD1F,SHA256=D7FA54FC22418134AF1B33B923D2A2D76E3ECF871E3DFD337B46D0AEA7B1C066,IMPHASH=3B33063FA6540CFC510BD20FCC99CC96) |

</details>

---

_This report's sample is not public, IOCs are defanged, and it is for security research only._
