---
title: "Malware Analysis: ValleyRAT / Winos (candidate) (PE · exe · ab6dc65b)"
published: 2026-11-14
draft: false
description: "Malicious (low confidence): ValleyRAT / Winos (candidate) · loader/rat/injector · difficulty hard · dynamic sandbox + static decompilation"
tags: ["ValleyRAT", "loader", "rat", "injector", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-14-ValleyRAT-Winos-候选-ab6dc65b"
---

> [!WARNING]
> **Verdict: Malicious** · Family **ValleyRAT / Winos (candidate)** (uncertain) · Confidence **Low**
> 
> Aliases: ValleyRAT, Winos 4.0, SilverFox-related loader chain
> 
> The full multi-stage delivery chain was observed in the real dynamic sandbox: a 7z self-extracting archive dropped the iMyFone-signed Engine-Infra.exe to %TEMP% and launched it; the latter staged itself and the Qt5Core/MSVC runtime into C:\ProgramData\mgr_agent_v2 and restarted, then dropped and executed C:\ProgramData\PoExplorer.exe, created the scheduled task ConfigDebug_amd64_debug, and PoExplorer repeatedly resolved new-label[.]club and connected over TCP :3333; memory forensics also showed the main image header of that process replaced, an unmapped module with 529 patches, and cp/dp/sid/tag/buildId/av/monitors configuration. The chain is consistent with a loader plus remote-control backdoor and clearly avoids normal installation paths and signature verification.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **ValleyRAT / Winos (candidate)** · aliases ValleyRAT, Winos 4.0, SilverFox-related loader chain · _uncertain_ |
| Confidence | **Low** |
| Behavior class | loader · rat · injector |
| Difficulty | hard |
| First seen | 2026-11-12 00:23:06 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ab6dc65bff1fcf2082974b906384d9ed9cc902deec33c0589d11d7a31df51e6c/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">SFX delivers online component</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Sideload signed iMyFone component</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Restart from staging directory</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Drop and execute PoExplorer</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Hollow and inject PoExplorer</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `ab6dc65bff1fcf2082974b906384d9ed9cc902deec33c0589d11d7a31df51e6c` |
| MD5 | _not recorded_ |
| Size | 7,496,236 bytes (7.1 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**12** behaviors in total, each backed by evidence; **2** are static and **10** obtained through dynamic analysis.

### 1. SFX delivers online component

`T1204.002` · Confidence **High** · Dynamic

The 7z self-extracting module unpacks embedded files to %TEMP% and launches Engine-Infra.exe per the configured RunProgram.

> **Evidence**: SFX configuration at file offset 0x2DF45: InstallPath="%TEMP%", RunProgram="%T%\Engine-Infra.exe"; dynamic process chain 4060→2480 at %TEMP%\Engine-Infra.exe.
> 
> **Source**: `ev-000027` · `ev-000007` · `ev-000028`

### 2. Sideload signed iMyFone component

`T1574.002` · Confidence **High** · Dynamic

Launches the DigiCert EV-signed iMyFone Engine-Infra.exe and loads Qt5Core.dll and other dependencies from the same directory, using a legitimate signature to reduce alerts.

> **Evidence**: Engine-Infra.exe certificate fields include Shenzhen iMyFone Technology/DigiCert; at runtime it loads Qt5Core.dll, msvcp120.dll and msvcr120.dll from %TEMP%.
> 
> **Source**: `ev-000016` · `ev-000008` · `ev-000028`

### 3. Restart from staging directory

`T1036.005` · Confidence **High** · Dynamic

Copies itself and the Qt5Core/MSVC runtime to C:\ProgramData\mgr_agent_v2 and restarts from that directory.

> **Evidence**: Host telemetry 04:01:45 consecutively creates mgr_agent_v2\Engine-Infra.exe, Qt5Core.dll, msvcp120.dll, msvcp_win.dll, msvcr120.dll, ucrtbase.dll; 04:01:46 PID 5632 starts from that path.
> 
> **Source**: `ev-000028`

### 4. Drop and execute PoExplorer

`T1105` · Confidence **High** · Dynamic

Writes C:\ProgramData\PoExplorer.exe from the staging directory and immediately launches that process.

> **Evidence**: Host telemetry 04:02:35 PID 5632 creates C:\ProgramData\PoExplorer.exe, and PID 1824 is created in the same second to execute it.
> 
> **Source**: `ev-000028`

### 5. Hollow and inject PoExplorer

`T1055.012` · Confidence **High** · Dynamic

The DOS/PE headers, entry point and section table of the PoExplorer main image are replaced, and memory also contains an unmapped module with 529 patches, consistent with process hollowing or code injection.

> **Evidence**: Memory forensics report: is_pe_replaced=1, ep_modified=1, sec_hdr_modified=1; 529 patches in the unmapped module at 0x8d0000, 3 patches in ntdll.
> 
> **Source**: `ev-000028`

### 6. Create scheduled task persistence

`T1053.005` · Confidence **High** · Dynamic

Creates a scheduled task named ConfigDebug_amd64_debug through the Task Scheduler and writes a .job file under Windows\Tasks.

> **Evidence**: Host telemetry 04:02:51: PID 5632 creates C:\Windows\Tasks\ConfigDebug_amd64_debug.job while svchost creates C:\Windows\System32\Tasks\ConfigDebug_amd64_debug.
> 
> **Source**: `ev-000028`

### 7. Resolve C2 domain

`T1071.004` · Confidence **High** · Dynamic

PoExplorer.exe repeatedly resolves new-label[.]club, with network monitoring returning a fake-network address.

> **Evidence**: Host telemetry DNS event QueryName=new-label[.]club at 04:02:53, 04:03:40, 04:04:25, result 192.0.2[.]123.
> 
> **Source**: `ev-000028`

### 8. TCP 3333 callback

`T1095` · Confidence **High** · Dynamic

PoExplorer.exe repeatedly initiates TCP connections to 192.0.2[.]123:3333, consistent with a control-port callback.

> **Evidence**: Network monitoring log 04:02:53/04:03:35/04:03:40/04:04:20/04:04:25: PoExplorer.exe (1824) requested TCP 192.0.2[.]123:3333.
> 
> **Source**: `ev-000028`

### 9. Collect host and screen information

`T1082` · Confidence **High** · Dynamic

The in-memory configuration JSON collects computer name, username, memory, UAC, CPU, monitor resolution and refresh rate, version and build identifier for host profiling and the remote-control session.

> **Evidence**: Plaintext JSON at 0x6052B7 in the memory dump: computer/user/ram/uac/cpu/ver/iver/ts/cp/dp/sid/tag/buildId/av/monitors.
> 
> **Source**: `ev-000028`

### 10. Identify antivirus status

`T1518.001` · Confidence **High** · Dynamic

The configuration reports the av field as Windows Defender(OFF), indicating it probes security-software status before coming online.

> **Evidence**: JSON field av="VwBpAG4AZABvAHcAcwAgAEQAZQBmAGUAbgBkAGUAcgAoAE8ARgBGACkA" (Base64 decodes to Windows Defender(OFF)).
> 
> **Source**: `ev-000028`

### 11. Embedded encrypted resource files

`T1027.009` · Confidence **Medium** · Static

Drops sampleragent.bin (5.6MB, with 0x404E bytes of English-like text followed by a PNG chunk container of 687 IDATs) and watcherserver.dat (126KB) as later payload or configuration resources.

> **Evidence**: 7z archive directory contains sampleragent.bin/watcherserver.dat; sampleragent.bin from 0x404E is a big-endian 0x2000 IDAT chunk sequence, ending with IEND plus CRC.
> 
> **Source**: `ev-000027`

### 12. Abuse legitimate code signing

`T1553.002` · Confidence **Medium** · Static

Uses the iMyFone DigiCert EV-signed binary as a whitelisted host to conceal the subsequent sideloading and payload delivery.

> **Evidence**: Certificate fields inside Engine-Infra.exe: Shenzhen iMyFone Technology Co., Ltd, DigiCert EV Code Signing, ocsp/crl[.]digicert[.]com.
> 
> **Source**: `ev-000016` · `ev-000008`


## IOC (Defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the isolated analysis network, and the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| dns | `new-label[.]club` | 53 | c2 | Static | ⏳ Not observed |
| tcp | `new-label[.]club` | 3333 | c2 | Static | ⏳ Not observed |
| tcp | `new-label[.]club` | 3334 | exfil | Static | ⏳ Not observed |

### Host

**Drop paths**

- `%TEMP%\Engine-Infra.exe`
- `%TEMP%\Qt5Core.dll`
- `%TEMP%\sampleragent.bin`
- `%TEMP%\watcherserver.dat`
- `%ProgramData%\mgr_agent_v2\Engine-Infra.exe`
- `%ProgramData%\mgr_agent_v2\Qt5Core.dll`
- `%ProgramData%\mgr_agent_v2\msvcp120.dll`
- `%ProgramData%\mgr_agent_v2\msvcp_win.dll`
- `%ProgramData%\mgr_agent_v2\msvcr120.dll`
- `%ProgramData%\mgr_agent_v2\ucrtbase.dll`
- `%ProgramData%\PoExplorer.exe`
- `%ALLUSERSPROFILE%\PoExplorer.exe`

**Scheduled tasks**

- `ConfigDebug_amd64_debug`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `['new-label[.]club']` | Yes | Static |
| `c2_port` | `3333` | Yes | Static |
| `data_port` | `3334` | No | Static |
| `install_path` | `C:\ProgramData\mgr_agent_v2` | No | Dynamic |
| `payload_path` | `C:\ProgramData\PoExplorer.exe` | No | Dynamic |
| `task_name` | `ConfigDebug_amd64_debug` | No | Dynamic |
| `build_id` | `main` | No | Static |
| `campaign_tag` | `new` | No | Static |
| `bot_sid` | `VUSURWIV` | No | Static |
| `version` | `0.1.32` | No | Static |
| `av_status` | `Windows Defender(OFF)` | No | Static |
| `encryption_algo` | `-` | No | Static |

## What Not to Assume

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing the report.

- Do not claim a C2 session was established or data exfiltration succeeded: only DNS resolution and TCP connect attempts were observed, with no application-layer request/response, check-in packet or exfiltrated content.
- Do not claim this is an official iMyFone installer or that iMyFone developed the malware: the signed component is a sideloaded/abused host, and the SFX flow of extracting to %TEMP% and directly running a service component does not match normal installation logic.
- Do not claim service persistence or a registry Run key: MFLocalService/MFResident are only strings, no service was actually created, and the Run key did not change.
- Do not claim credentials, browser data or files were stolen: no related file access or exfiltration was observed; the configuration only reflects host and monitor information collection.
- Do not assign it to a definitive family: there is no YARA, vendor engine or public report cross-validation; ValleyRAT/Winos is only a candidate based on similar behavior and configuration shape.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes |

**Limitations and items to verify**

1. For C2 only DNS resolution and TCP 3333 connection attempts were observed, with no application-layer session or response; therefore the c2 entries are recorded as static plus pending_dynamic_verify.
2. Family attribution has no YARA, vendor engine or public report cross-validation; ValleyRAT/Winos is a candidate and the family field is marked uncertain.
3. The 0x404E prefix of sampleragent.bin is English-like random text; the following 687 IDATs cannot be decompressed into a valid PNG, so decryption is incomplete and the payload's role is inferred.
4. The Authenticode signature of Engine-Infra.exe was not cryptographically verified; the signature origin is judged only from certificate fields and the presence of a security directory.
5. The on-disk PoExplorer.exe original file was not captured, only the memory image; its on-disk hash is unknown, and the memory image shows a replaced header.
6. Some telemetry events have UtcTime inconsistent with the event time (10-12 vs 11-14), possibly due to guest clock or time-setting anomalies; no time-tampering behavior is inferred from this.
7. The sandbox baseline itself has outbound traffic from MicrosoftEdgeUpdate, Windows Update and others; C2 attribution uses only new-label[.]club:3333 and PoExplorer.exe-related events.
8. 192.0.2[.]123 is a reserved test address used by network monitoring, not a real C2 IP; port 3334 comes only from configuration and no actual connection was observed.

## Evidence Index

<details>
<summary>Show 16 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | Outer SFX sha256/md5/sha1 |
| `ev-000007` | String extraction | Outer 7z SFX module strings (7-Zip SFX 1.4.0 beta / 9.15 beta) |
| `ev-000008` | Hash and fingerprint | Engine-Infra.exe sha256 and Rich header |
| `ev-000016` | String extraction | Engine-Infra strings: MFLocalService, Maifeng/iMyFone, MFResident.exe, QtService |
| `ev-000017` | decompile.function | Decompiled QtService command line and service-install branch |
| `ev-000018` | decompile.function | Decompiled service start and HandlerThread |
| `ev-000019` | Hash and fingerprint | Qt5Core.dll sha256 |
| `ev-000022` | scan.entropy | Qt5Core .text entropy 6.501 (not packed) |
| `ev-000027` | evidence.record | 7z static unpacking, SFX configuration, hashes of four stage files, sampleragent PNG chunk structure |
| `ev-000028` | evidence.record | Sandbox process chain, file creation, scheduled task, DNS/TCP, memory forensics, configuration JSON |
| `ref:667f30b308` | disasm.function | Code at Qt5Core 0x2130 converting the sampleragent.bin pointer to UTF-16 |
| `ref:f9b7a86634` | PE structure parsing | Qt5Core 7089 exports, normal 5-section structure |
| `telemetry:ab6dc65b` | Dynamic telemetry | Dynamic telemetry recorded: 147 process/file events from monitored components; 3 ETW short-lived process events; 28 tool/system noise entries filtered |
| `etw:ab6dc65b:4060` | Process event monitoring | Short-lived process event: ab6dc65bff1fcf2082974b906384d9ed9cc902deec33c0589d11d7a31df51e6c.exe (pid 4060; MD5=BF4DFFC81084F6453CD050CADA628844,SHA256=AB6DC65BFF1FCF2082974B906384D9ED9CC902DEEC33C0589D11D7A31DF51E6C,IMPHASH=B5A014D7EEB4C2042897567E1288A095) |
| `etw:ab6dc65b:2480` | Process event monitoring | Short-lived process event: Engine-Infra.exe (pid 2480; MD5=CF01F8E53800DC303F0066DBED915078,SHA256=FDB9FEC2A2809B72C4897955EAA4B960BBC46C183EE15ED706F66DB4E3D46484,IMPHASH=A4AD602AAB365EFF6CA7FB2CD8E12944) |
| `etw:ab6dc65b:5632` | Process event monitoring | Short-lived process event: Engine-Infra.exe (pid 5632; MD5=CF01F8E53800DC303F0066DBED915078,SHA256=FDB9FEC2A2809B72C4897955EAA4B960BBC46C183EE15ED706F66DB4E3D46484,IMPHASH=A4AD602AAB365EFF6CA7FB2CD8E12944) |

</details>

---

_This sample is not public; IOCs are defanged. For security research only._
