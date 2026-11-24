---
title: "Malware Sample Analysis: HubEncrypt (PE · exe · 8092dfb1)"
published: 2026-11-23
draft: false
description: "Malicious (low confidence): HubEncrypt · loader/injector/backdoor · difficulty medium · dynamic sandbox + static decompilation"
tags: ["HubEncrypt", "loader", "injector", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-23-HubEncrypt-8092dfb1"
---

> [!WARNING]
> **Verdict: malicious** · Family **HubEncrypt** (unconfirmed) · Confidence **low**
> 
> Aliases: suspected RansomHub-associated component, Office sideload delivery chain (HubEncrypt_win64)
> 
> The sample is a 7-Zip self-extracting shell that releases and runs components impersonating Microsoft Office: the signed Wizard-Config.exe (original name firstrun.exe) sideloads the unsigned MSOCF.DLL from the same directory, then copies itself and its dependencies to %ProgramData%\DOTNETauthenticate_v11 and starts again, writing out and executing %TEMP%\PortaProfiler.exe. The dynamic sandbox actually observed this process chain, the scheduled task HubEncrypt_win64, the Startup-folder entry BIT9A15.tmp, and PortaProfiler.exe resolving new-label[.]club and making a TCP connection to port 3333; memory forensics also show that PortaProfiler.exe's main-module PE header was replaced and that an injected module carries 548 code patches. Delivery, persistence, and C2 communication were all directly observed, so the sample is judged malicious.

## At a Glance

| Item | Details |
|:--|:--|
| Family | **HubEncrypt** · aliases suspected RansomHub-associated component, Office sideload delivery chain (HubEncrypt_win64) · _unconfirmed_ |
| Confidence | **low** |
| Behavior class | loader · injector · backdoor |
| Difficulty | medium |
| First seen | 2026-11-22 16:51:15 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/8092dfb138915fe5cfebe80d393d5c9bc131a8783205eb2df7bece3e8873e1e8/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Self-extracting shell drop</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Signed host sideloads DLL</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Drops to ProgramData, restarts</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Drops and injects PortaProfiler</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Scheduled-task persistence</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.005</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identifiers

| Item | Value |
|:--|:--|
| SHA-256 | `8092dfb138915fe5cfebe80d393d5c9bc131a8783205eb2df7bece3e8873e1e8` |
| MD5 | _not recorded_ |
| Size | 5,563,395 bytes (5.3 MB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **9** behaviors in total, each backed by evidence; **3** are static and **6** were obtained through dynamic analysis.

### 1. Self-Extracting Shell Delivery

`T1027` · confidence **high** · static

The main program appends 5,375,232 bytes of data after its PE sections, beginning with the 7z signature; it can extract 13 files (including Wizard-Config.exe, MSOCF.DLL, pipeline.db, stencil-data.tmp, and Office manifests/runtime libraries), and the shell strings explicitly identify it as 7z SFX 1.4.0 beta / 7-Zip 9.15 beta.

> **Evidence**: the 37 7A BC AF 27 1C signature appears at main-file offset 188,236; strings include '7z SFX' and '7-Zip version: 9.15 beta'.
> 
> **Sources**: `ev-000001` · `ev-000011`

### 2. Signed Host Sideloads DLL

`T1574.002` · confidence **high** · dynamic

The extracted Wizard-Config.exe has Microsoft Office / firstrun.exe version information (16.0.4266.1001) and carries an Authenticode directory, and its import table explicitly references 12 exports of MSOCF.dll; the MSOCF.DLL placed in the same directory imitates Microsoft Office Client Frame in its version information but has a security directory size of 0 (unsigned), forming a typical signed-host sideload.

> **Evidence**: Wizard-Config.exe imports ?CreateTheApp@Frame@MsoCF@@, ?Start@Frame@MsoCF@@, etc.; MSOCF.DLL version information is Microsoft Office Client Frame, security directory size 0; dynamic process chain 744→6876→4360.
> 
> **Sources**: `ev-000013` · `ev-000023` · `ev-000033` · `ev-000035` · `ev-000037`

### 3. Dropped to ProgramData and Restarted

`T1036.005` · confidence **high** · dynamic

Dynamic observation shows Wizard-Config.exe copying itself, MSOCF.DLL, vcruntime140.dll, msvcp140.dll, msvcp_win.dll, and ucrtbase.dll to C:\ProgramData\DOTNETauthenticate_v11, launching itself again from that directory, and then continuing to drop the next stage.

> **Evidence**: dynamic timeline: %TEMP%\Wizard-Config.exe → C:\ProgramData\DOTNETauthenticate_v11\Wizard-Config.exe (pid 4360), with DLLs written to the same directory.
> 
> **Sources**: `ev-000035`

### 4. PortaProfiler Drop and Injection

`T1055.012` · confidence **high** · dynamic

The Wizard-Config.exe under ProgramData writes out and launches %TEMP%\PortaProfiler.exe; memory forensics show that this process (pid 6260) had its main-module PE header replaced and that an injected module carries 548 code patches, consistent with process hollowing/module replacement executing a payload.

> **Evidence**: in the dynamic timeline, 4360 creates and launches PortaProfiler.exe; memory forensics report is_pe_replaced=1 and 970000 module patches=548.
> 
> **Sources**: `ev-000035`

### 5. Scheduled Task Persistence

`T1053.005` · confidence **high** · dynamic

Dynamic observation shows Wizard-Config.exe creating C:\Windows\Tasks\HubEncrypt_win64.job, after which the Task Scheduler service creates C:\Windows\System32\Tasks\HubEncrypt_win64 to continue execution after a restart.

> **Evidence**: endpoint telemetry: process 4360 creates HubEncrypt_win64.job; svchost (Task Scheduler service) creates the HubEncrypt_win64 task file.
> 
> **Sources**: `ev-000035`

### 6. Autostart Entry in Startup Folder

`T1547.001` · confidence **medium** · dynamic

During execution the Startup folder is written with BIT9A15.tmp, forming a second autostart path based on user logon.

> **Evidence**: endpoint telemetry: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\BIT9A15.tmp created (multiple writes).
> 
> **Sources**: `ev-000035`

### 7. C2 Resolution and Connection Establishment

`T1095` · confidence **medium** · dynamic

During execution PortaProfiler.exe repeatedly resolves new-label[.]club and initiates connections to 3333/TCP on that domain; the port had no listener and no application-layer request or response was obtained, so only the C2 destination and connection attempts can be confirmed.

> **Evidence**: network monitoring and endpoint DNS events: PortaProfiler.exe (pid 6260) queries new-label[.]club 4 times and connects to TCP 3333 4 times; no complete session.
> 
> **Sources**: `ev-000036`

### 8. High-Entropy Payload Files Pending Decryption

`T1027` · confidence **medium** · static

Inside the extracted package, pipeline.db (293,532 bytes, entropy 6.69) and stencil-data.tmp (5,356,310 bytes, entropy 7.97) are both high-entropy data with no plaintext header; both file names appear in MSOCF.DLL's data region, so they are judged to be encrypted configuration/payload containers for later stages, and their plaintext was not recovered this time.

> **Evidence**: MSOCF.DLL data region contains pipeline.db (UTF-16) and stencil-data.tmp; both files have entropy 6.69/7.97 and no MZ/7z/PK header.
> 
> **Sources**: `ev-000034` · `ev-000037`

### 9. Disguised Office Components and Weak Constants

`T1036.005` · confidence **medium** · static

Several components use Microsoft Office version information, file names, and manifests (excel/powerpnt/msaccess/Graph, etc.), while the main program masquerades as an installation/configuration wizard; the static constant scan identified only CRC32 and no standard AES/SHA constants, indicating that the encryption algorithm does not appear directly as standard constant tables.

> **Evidence**: MSOCF.DLL version information Microsoft Office Client Frame; the extracted package contains Office application manifests; constant scan hits CRC32 @0x7888.
> 
> **Sources**: `ev-000023` · `ev-000033` · `ev-000012`


## IOCs (Defanged)

### Network

:::caution
**Pending dynamic verification**: the above address comes from static analysis; no successful connection or session was observed under the analysis environment's network isolation, so the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `new-label[.]club` | 3333 | c2 | static | ⏳ not observed |

### Host

**Drop paths**

- `%TEMP%\Wizard-Config.exe`
- `%TEMP%\PortaProfiler.exe`
- `%ProgramData%\DOTNETauthenticate_v11\Wizard-Config.exe`
- `%ProgramData%\DOTNETauthenticate_v11\MSOCF.DLL`
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\BIT9A15.tmp`

**Scheduled tasks**

- `HubEncrypt_win64`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `new-label[.]club` | yes | static |
| `c2_port` | `3333` | yes | static |
| `install_path` | `C:\ProgramData\DOTNETauthenticate_v11` | yes | dynamic |
| `loader_dll` | `MSOCF.DLL` | yes | dynamic |
| `persistence_task` | `HubEncrypt_win64` | yes | dynamic |
| `startup_entry` | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\BIT9A15.tmp` | no | dynamic |
| `stage2_files` | `pipeline.db; stencil-data.tmp` | no | static |

## Do Not Misjudge

:::important
The following conclusions **are easily misjudged**; please note them when citing this report.

- Do not conclude from the scheduled-task name HubEncrypt_win64 alone that the sample has completed file encryption or dropped a ransom note; no file encryption, extension changes, or ransom instructions were observed within the run window.
- Do not label new-label[.]club as a C2 with a complete session established; this time only DNS resolution and a TCP 3333 connection were observed, with no application-layer request/response obtained.
- Do not treat Microsoft Update, certificate revocation, and Edge update traffic seen during execution as sample C2; these are normal outbound traffic from system components.
- The 4 random flag-like fragments appearing in the extracted package and memory are not flags and cannot serve as challenge answers or family identifiers.
:::

## Analysis Method and Limitations

| Item | Details |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | yes |

**Limitations and Pending Verification**

1. Only DNS resolution and TCP 3333 connection attempts for new-label[.]club were obtained, with no application-layer request/response, so the C2 is still marked as statically recovered and pending dynamic re-verification.
2. pipeline.db and stencil-data.tmp are high-entropy data; the decryption algorithm, key, and plaintext were not recovered, so it cannot be confirmed whether they contain a next-stage PE and the full configuration.
3. MSOCF.DLL obtains sensitive APIs through dynamic resolution, and its decryption, injection, and download logic have not been fully recovered; decompilation failed to list functions.
4. The specific command line of the scheduled task HubEncrypt_win64 and the actual contents of the Startup entry BIT9A15.tmp were not collected, so the post-persistence execution parameters are unknown.
5. No events related to security components (Defender/AMSI) were obtained, so it cannot be determined whether the sample actively disables or bypasses security protection.
6. The 970000 module seen in memory carries Qihoo 360 EaInstHelper version information, and its specific role in the attack chain could not be confirmed.

## Evidence Index

<details>
<summary>Expand 18 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash | Main sample SHA-256/MD5/SHA-1 and size 5,563,395 bytes |
| `ev-000011` | String extraction | Main sample strings contain 7z SFX / 7-Zip 9.15 identifiers and many 7z shell hints |
| `ev-000012` | Cryptographic constant scan | Only CRC32 constant @0x7888 identified |
| `ev-000013` | Hash | Wizard-Config.exe SHA-256 |
| `ev-000023` | Hash | MSOCF.DLL SHA-256 |
| `ev-000033` | String extraction | Wizard-Config.exe imports MSOCF.dll and Microsoft Office firstrun identifiers |
| `ev-000034` | String extraction | pipeline.db / stencil-data.tmp appear in MSOCF.DLL data region |
| `ev-000035` | Dynamic sandbox | Process chain, ProgramData copy, PortaProfiler drop, scheduled-task and Startup-folder persistence, in-memory module replacement |
| `ev-000036` | Network monitoring | PortaProfiler.exe resolves new-label[.]club and connects to TCP 3333; no complete session |
| `ev-000037` | Static script | Component version information/signature directories and entropy statistics for pipeline.db and stencil-data.tmp |
| `ref:3d1b0b42e0` | PE structure parsing | Main program is 32-bit GUI, 4 sections, no anomalies, no packing signals |
| `ref:3cce64d896` | PE structure parsing | Wizard-Config.exe is 64-bit GUI with a 6,824-byte security directory |
| `ref:43ffc4db01` | PE structure parsing | MSOCF.DLL is a 64-bit DLL with 44 exports and security directory 0 |
| `telemetry:8092dfb1` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events: 156; ETW short-lived process events: 4; filtered tool/system noise: 22 |
| `etw:8092dfb1:744` | Process event monitoring | Short-lived process event: 8092dfb138915fe5cfebe80d393d5c9bc131a8783205eb2df7bece3e8873e1e8.exe (pid 744; MD5=2CE641240487F73C3E049ED3C98F68BE,SHA256=8092DFB138915FE5CFEBE80D393D5C9BC131A8783205EB2DF7BECE3E8873E1E8,IMPHASH=B5A014D7EEB4C2042897567E1288A095) |
| `etw:8092dfb1:6876` | Process event monitoring | Short-lived process event: Wizard-Config.exe (pid 6876; MD5=70829E775D55C0E4DD8CA1DB90AC521B,SHA256=C2E672544D39D1EF00FB5E03633F6A48A229D9FFA5F5F6C7ACB3F86EF44E2AD6,IMPHASH=0C44D537BD2CFF3C818EDD2ACB5AEBD4) |
| `etw:8092dfb1:4360` | Process event monitoring | Short-lived process event: Wizard-Config.exe (pid 4360; MD5=70829E775D55C0E4DD8CA1DB90AC521B,SHA256=C2E672544D39D1EF00FB5E03633F6A48A229D9FFA5F5F6C7ACB3F86EF44E2AD6,IMPHASH=0C44D537BD2CFF3C818EDD2ACB5AEBD4) |
| `etw:8092dfb1:6260` | Process event monitoring | Short-lived process event: PortaProfiler.exe (pid 6260; MD5=3E963E13C6AB3091E0384DCF4539A03D,SHA256=F41BFA204E937824BBC509EC0716DF5DF62E174B73070D1FD80D3FB67A23B669,IMPHASH=1518655AF3F7BA1430A0C6949E443660) |

</details>

---

_The sample in this report is not public; IOCs have been defanged; for security research only._
