---
title: "Malicious sample analysis: AnyDesk RAT (tech support scam deployment) (PE · exe · 20b0dfbd)"
published: 2026-11-25
draft: false
description: "Malicious (confidence: medium): AnyDesk RAT (tech support scam deployment) · rat/dropper · difficulty easy · dynamic sandbox + static decompilation"
tags: ["AnyDesk", "rat", "dropper", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-25-AnyDesk-RAT-tech-support-scam-deployment-20b0dfbd"
---

> [!WARNING]
> **Verdict: malicious** · Family **AnyDesk RAT (tech support scam deployment)** (unconfirmed) · Confidence **medium**
> 
> Aliases: AnyDesk abuse, Remote access tool abuse, Soporte Online scam, RemoteAdmin.AnyDesk
> 
> The sample is an unsigned WinRAR self-extracting (SFX) wrapper with a RAR5 archive appended at the end of the file; the archive comment carries silent-install directives (Path=C:\SOPORTE ONLINE, Setup=AnyDesk.exe, Silent=1, Overwrite=1, Update=U). In a real dynamic environment, the sample process writes out C:\SOPORTE ONLINE\Anydesk.exe on its own and launches that AnyDesk client with --local-service / --local-control, repeatedly resolves boot[.]net[.]anydesk[.]com and initiates connections to 443/80/6568, forming a channel that can be remotely taken over by a third party. Combined with the Spanish "online support" wording and the silent, interaction-free installation, this is judged to be a malicious delivery that abuses legitimate remote-control software to perform unauthorized remote access.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **AnyDesk RAT (tech support scam deployment)** · Aliases AnyDesk abuse, Remote access tool abuse, Soporte Online scam, RemoteAdmin.AnyDesk · _unconfirmed_ |
| Confidence | **medium** |
| Behavior class | rat · dropper |
| Difficulty | easy |
| First seen | 2026-11-25 00:23:13 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/20b0dfbd5078bcec058e44295d27b2e26b044bcd546e51802982e0d08fcfce19/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Embedded RAR payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Silently drops AnyDesk</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Launches remote-control client</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Spawns service/control processes</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Connects to AnyDesk relay</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `20b0dfbd5078bcec058e44295d27b2e26b044bcd546e51802982e0d08fcfce19` |
| MD5 | _Not recorded_ |
| Size | 5,967,951 bytes (5.7 MB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **7** behaviors in total, each backed by evidence; **3** are statically available and **4** were obtained through dynamic analysis.

### 1. Embedded RAR payload

`T1027.009` · Confidence **high** · Static

The outer PE is a WinRAR self-extracting stub (its resources contain "WinRAR self-extracting archive" and installer/extraction wizard strings); a RAR5 archive is appended starting at file offset 0x4FC00, and the archive comment carries automatic extraction directives: Path=C:\SOPORTE ONLINE, Setup=AnyDesk.exe, Silent=1, Overwrite=1, Update=U.

> **Evidence**: RAR5 header at 0x4FC00; comment text 'Path=C:\SOPORTE ONLINE / Setup=AnyDesk.exe / Silent=1'; 'WinRAR self-extracting archive' in .rsrc
> 
> **Source**: `ref:3686049d34` · `ref:87b03789a1` · `ref:d8512f933c`

### 2. Silently drops AnyDesk

`T1105` · Confidence **high** · Dynamic

Without any user interaction, the sample process writes C:\SOPORTE ONLINE\Anydesk.exe (5,656,872 bytes, matching the entry in the archive), and the directory is created by the sample itself.

> **Evidence**: process-creation telemetry: pid 1464 (sample) -> File created C:\SOPORTE ONLINE\Anydesk.exe; memory scan shows module path C:\SOPORTE ONLINE\Anydesk.exe
> 
> **Source**: `ref:292dbb8687` · `ref:69694ad529`

### 3. Launches the remote-control client

`T1219` · Confidence **high** · Dynamic

It launches the main process (pid 5668) as "C:\SOPORTE ONLINE\AnyDesk.exe" (FileVersion 9.0.5, Company AnyDesk Software GmbH) with working directory C:\SOPORTE ONLINE, entering the AnyDesk client running state.

> **Evidence**: process-creation telemetry pid 5668: Image=C:\SOPORTE ONLINE\Anydesk.exe, CommandLine="C:\SOPORTE ONLINE\AnyDesk.exe"
> 
> **Source**: `ref:3b88b9183b` · `ref:292dbb8687`

### 4. Spawns service and control processes

`T1219` · Confidence **high** · Dynamic

The main process then spawns two child processes, "--local-service" (pid 5040) and "--local-control" (pid 3756), entering the service and control modes that can accept remote sessions.

> **Evidence**: process-creation telemetry: pid 5040 CommandLine="C:\SOPORTE ONLINE\AnyDesk.exe" --local-service; pid 3756 CommandLine="C:\SOPORTE ONLINE\AnyDesk.exe" --local-control
> 
> **Source**: `ref:3b88b9183b` · `ref:292dbb8687`

### 5. Connects to the AnyDesk relay

`T1571` · Confidence **high** · Dynamic

At runtime it repeatedly resolves boot[.]net[.]anydesk[.]com (15 times within the analysis window) and initiates TCP connections to 443, 80 and 6568; the in-memory runtime configuration is ad.anynet.boot_addrs=boot[.]net[.]anydesk[.]com, ad.anynet.conn_methods=connect:443;connect:80;socks:443;direct:443;direct:80;direct:6568.

> **Evidence**: DNS telemetry: Anydesk.exe (pid 5040) QueryName=boot[.]net[.]anydesk[.]com; network monitoring: Anydesk.exe -> 443/80/6568; memory string ad.anynet.conn_methods=...
> 
> **Source**: `ref:306a7a2185` · `ref:2c741353ae` · `ref:292dbb8687`

### 6. Abuses a legitimate code signature

`T1553.002` · Confidence **high** · Static

The inner Anydesk.exe carries a valid AnyDesk Software GmbH code signature (DigiCert Trusted G4 Code Signing chain, 2024 timestamp certificate), while the outer SFX dropper is unsigned; at runtime the system also performs OCSP/CRL checks on its certificate. The legitimate signature lowers AV detection and user suspicion.

> **Evidence**: signature check Status=Valid, Signer=CN=AnyDesk Software GmbH; outer Status=NotSigned; network monitoring shows ocsp[.]digicert[.]com / crl*.digicert.com queries
> 
> **Source**: `ref:8f2214a302` · `ref:a04be79c51` · `ref:306a7a2185`

### 7. Masquerades as an online-support entry point

`T1204.002` · Confidence **high** · Static

The archive comment uses the Spanish "El comentario siguiente contiene secuencias de órdenes para auto extracción", the install directory is named C:\SOPORTE ONLINE (online support), and the SFX installer-wizard UI and "Install" button lure the user into executing it — social-engineering delivery.

> **Evidence**: Spanish RAR comment text; resource strings 'Install'/'Extraction progress'/'WinRAR self-extracting archive'
> 
> **Source**: `ref:3686049d34` · `ref:d8512f933c`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: The above addresses come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `boot[.]net[.]anydesk[.]com` | 443 | c2 | Static | ⏳ Not observed |

### Host

**Drop path**

- `C:\SOPORTE ONLINE\`
- `C:\SOPORTE ONLINE\Anydesk.exe`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `install_path` | `C:\SOPORTE ONLINE` | Yes | Static |
| `setup_command` | `Setup=AnyDesk.exe` | Yes | Static |
| `silent` | `1` | Yes | Static |
| `overwrite` | `1` | No | Static |
| `update_mode` | `U` | No | Static |
| `payload_name` | `Anydesk.exe` | Yes | Static |
| `payload_sha256` | `12c8bece29b5d0ce88f8e0d0cc339f6f90803e1ad80898c658e188f50b6f997e` | Yes | Static |
| `payload_version` | `AnyDesk 9.0.5[.]0` | No | Static |
| `payload_signer` | `CN=AnyDesk Software GmbH, O=AnyDesk Software GmbH, C=DE (DigiCert code signing, Status Valid)` | No | Static |
| `c2_hosts` | `boot[.]net[.]anydesk[.]com` | Yes | Static |
| `c2_port` | `443;80;6568` | No | Static |
| `network_methods` | `connect:443;connect:80;socks:443;direct:443;direct:80;direct:6568` | No | Static |
| `archive_format` | `RAR5 SFX, archive start offset 0x4FC00, method v6:8M:m3` | Yes | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not claim process injection or hollowing: the memory scan only shows module-header alignment differences (REALIGNED dump), the module path is the on-disk C:\SOPORTE ONLINE\Anydesk.exe, and no replaced/implanted PE or shellcode was observed.
- Do not judge the inner AnyDesk as a custom trojan or backdoor variant: it is the official AnyDesk Software GmbH-signed 9.0.5 client, and no modified code sections or self-configuration injection were found.
- Do not report ransomware, data theft or persistence behavior: no file encryption, credential reading or data packaging/outbound transfer was observed, nor service installation, Run keys or scheduled-task creation.
- Do not claim a session was established with the attacker's C2: only DNS queries and TCP connection attempts to AnyDesk's official bootstrap server boot[.]net[.]anydesk[.]com were seen, and no complete request/response was obtained.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `12c8bece29b5d0ce88f8e0d0cc339f6f90803e1ad80898c658e188f50b6f997e`) |

**Limitations and pending verification**

1. The dynamic observation window was about 2 minutes and no complete AnyDesk session was observed: no relay-*.net.anydesk.com resolution and no complete TLS interaction, so C2 session capability is unverified and the related items remain pending_dynamic_verify.
2. No configuration-file writes under %APPDATA%\AnyDesk were captured, so it cannot be confirmed whether an AnyDesk ID or unattended password was preconfigured; only the default boot_addrs / conn_methods were seen in memory.
3. No persistence mechanisms such as service installation, Run keys or scheduled tasks were observed; their appearance over a longer runtime or after user interaction cannot be excluded.
4. IsDebuggerPresent, PEB access and cpuid in the outer SFX are ordinary CRT/SFX code; no targeted anti-debug or anti-VM logic was observed, so they are not treated as anti-analysis conclusions.
5. The inner signature was verified by the system as Valid (both certificate chain and timestamp passed); no manual recomputation of the signature digest was performed.

## Evidence Index

<details>
<summary>Expand 21 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:5f945d0345` | Sample triage | Outer PE hash/imphash/entropy/packing score 0, 6 sections, nothing anomalous |
| `ref:f7cbe1aff3` | PE structure parsing | Outer PE32 GUI, entry RVA 0x20780, SizeOfImage 487424, file 5.97MB, large overlay present |
| `ref:4aca8d6961` | Import table parsing | Only KERNEL32/OLEAUT32/gdiplus, 155 imports in total, consistent with an SFX stub |
| `ref:3686049d34` | bash (overlay carve) | RAR5 header at offset 0x4FC00, comment contains Path=C:\SOPORTE ONLINE / Setup=AnyDesk.exe / Silent=1 / Overwrite=1 / Update=U |
| `ref:87b03789a1` | bash (archive list) | RAR5 archive contains 1 file Anydesk.exe, 5,656,872 bytes, entry time 2025-04-24 |
| `ref:72447ee329` | bash (archive extract + hash) | Extracted Anydesk.exe, sha256=12c8bece29b5d0ce88f8e0d0cc339f6f90803e1ad80898c658e188f50b6f997e |
| `ref:7fc12ca22f` | PE structure parsing | Inner PE32 GUI, 8 sections, has SECURITY directory (Authenticode), no import table (self-resolving) |
| `ref:a04be79c51` | openssl pkcs7 | Signature certificate chain: AnyDesk Software GmbH <- DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1 <- DigiCert Trusted Root G4, with DigiCert Timestamp 2024 |
| `ref:8f2214a302` | Get-AuthenticodeSignature | Inner Status=Valid, Signer=CN=AnyDesk Software GmbH; outer Status=NotSigned |
| `ref:e7c1f80b60` | bash (version resource) | Assembly version 9.0.5[.]0, description AnyDesk screen sharing and remote control software |
| `ref:d8512f933c` | bash (resource strings) | Resources contain SFX wizard strings such as WinRAR self-extracting archive, Install, Extraction progress |
| `ref:a43de593f0` | Dynamic analysis platform | Real dynamic detonation completed: 39 polls, 1 candidate process, 10 memory dump files, artifact zip archived and rolled back |
| `ref:292dbb8687` | telemetry (process/file/DNS) | Sample pid 1464 created C:\SOPORTE ONLINE\Anydesk.exe; AnyDesk launched with empty args/--local-service/--local-control; continuous queries to boot[.]net[.]anydesk[.]com |
| `ref:3b88b9183b` | telemetry (process create) | Full command lines and working directories of pid 5668/5040/3756, all pointing to C:\SOPORTE ONLINE |
| `ref:69694ad529` | memory scan | main_image_path=C:\SOPORTE ONLINE\Anydesk.exe for the three Anydesk.exe processes, no PE replacement/implant, only header alignment differences |
| `ref:306a7a2185` | network monitor | boot[.]net[.]anydesk[.]com resolved 15 times; Anydesk.exe made 5 connection attempts each to 443/80/6568; also ocsp/crl[.]digicert[.]com |
| `ref:2c741353ae` | memory forensics | Runtime config ad.anynet.boot_addrs=boot[.]net[.]anydesk[.]com, conn_methods=connect:443;connect:80;socks:443;direct:443;direct:80;direct:6568, proxy not enabled |
| `ref:0595b470af` | unpack.antidebug | Only ordinary CRT/SFX code such as IsDebuggerPresent/PEB access/cpuid, no targeted anti-analysis |
| `ref:c5a1c399c1` | telemetry (defender/amsi) | No related events from Defender or AMSI; system service changes came only from the network-monitoring component itself |
| `telemetry:20b0dfbd` | Dynamic telemetry | Dynamic telemetry recorded: 1 registry event from the monitoring component; 134 process/file events from the monitoring component; 1 ETW short-lived process event; 22 tool/system noise entries filtered |
| `etw:20b0dfbd:1464` | Process event monitoring | Short-lived process event: 20b0dfbd5078bcec058e44295d27b2e26b044bcd546e51802982e0d08fcfce19.exe (pid 1464; MD5=FA8012510E5487AD37FFAE0D202996CF,SHA256=20B0DFBD5078BCEC058E44295D27B2E26B044BCD546E51802982E0D08FCFCE19,IMPHASH=0AE9E38912FF6BD742A1B9E5C003576A) |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
