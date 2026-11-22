---
title: "Malware sample analysis: WannaCrypt (PE · exe · 2d5fb939)"
published: 2026-11-21
draft: false
description: "Malicious (high confidence): WannaCrypt · ransomware/dropper · difficulty medium · dynamic sandbox + static decompilation"
tags: ["WannaCrypt", "ransomware", "dropper", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-21-WannaCrypt-2d5fb939"
---

> [!WARNING]
> **Verdict: malicious** · family **WannaCrypt** · confidence **high**
> 
> Aliases: WannaCrypt0r 2.0, WannaCry 2.0, WCry, WNCRY, WanaCrypt0r
> 
> The sample is a three-level nested WannaCry (WanaCrypt0r 2.0) drop/install chain: the outer layer is a 64-bit DLL (export PlayGame) that reads "4-byte length + PE" data from resource W/101, writes it to C:\Windows\mssecsvr.exe, and launches it with a hidden window; the extracted 32-bit mssecsvr.exe then registers a system service named mssecsvc2.1, autostarts through the service control manager with the "-m security" parameter, contacts WannaCry's signature killswitch domain, and contains a built-in WinRAR self-extracting archive (resource R/1831, containing a RAR archive and tasksche.exe strings). Static evidence and real dynamic observations (service registered successfully, service process launched by services.exe, DNS+HTTP requests, SMB2 session attempt) corroborate each other.

## At a glance

| Item | Value |
|:--|:--|
| Family | **WannaCrypt** · aliases WannaCrypt0r 2.0, WannaCry 2.0, WCry, WNCRY, WanaCrypt0r |
| Confidence | **high** |
| Behavior class | ransomware · dropper |
| Difficulty | medium |
| First seen | 2026-11-19 12:15:11 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/2d5fb9397c6b3ba4ff4c083d5c756b53321ee5beb84b118ca919aa7088036812/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Drops mssecsvr.exe</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Launches dropped file hidden</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Registers autostart service</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Fakes security center service name</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Probes killswitch domain</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
</svg>

## Sample identifiers

| Item | Value |
|:--|:--|
| SHA-256 | `2d5fb9397c6b3ba4ff4c083d5c756b53321ee5beb84b118ca919aa7088036812` |
| MD5 | _not recorded_ |
| Size | 5,298,176 bytes (5.1 MB) |
| Type | PE · `exe` |

## Behavior analysis

**7** behaviors in total, each with evidence attached; **3** of them are statically obtainable and **4** were obtained through dynamic analysis.

### 1. Drops mssecsvr.exe

`T1027.009` · confidence **high** · static

The DLL export PlayGame reads resource W/101 through FindResourceA/LoadResource/LockResource, treats the first 4 bytes as the length and the following data as a PE image, and writes it to C:\Windows\mssecsvr.exe (GENERIC_WRITE/CREATE_ALWAYS/FILE_ATTRIBUTE_SYSTEM).

> **Evidence**: rva 0x1014: FindResourceA(resource 101,"W")→LockResource→[rdi] reads length→lea rdx,[rdi+4]→CreateFileA("C:\\Windows\\mssecsvr.exe")→WriteFile→CloseHandle; strings C:\\%s\\%s / WINDOWS / mssecsvr.exe; resource W/101 at rva 0x110a4, with an MZ header immediately after the 4-byte data length
> 
> **Source**: `ev-000020` · `ev-000041` · `ref:fdefa7a684` · `ref:47f3de954a` · `ref:3f3823da6b`

### 2. Launches dropped file hidden

`T1106` · confidence **high** · static

After writing, it launches that path with CreateProcessA; lpApplicationName is empty, the command line is the dropped path, and CREATE_NO_WINDOW (0x08000000) plus the STARTUPINFOA hidden-window flag make the child run without a UI.

> **Evidence**: rva 0x10F8: lea rdx,[path]; [rsp+0x28]=0x08000000; [rsp+0x70]=0x68(cb); [rsp+0xac]=0x81; call qword ptr [IAT CreateProcessA]; rva 0x11A4(PlayGame) calls 0x12DC to format the path, 0x1014 to drop, and 0x10F8 to launch
> 
> **Source**: `ev-000020` · `ref:0225f30a1c` · `ref:ccc15c25b3` · `ref:fdefa7a684`

### 3. Registers autostart service

`T1543.003` · confidence **high** · dynamic

The mssecsvr.exe stage creates a service named mssecsvc2.1 (display name faked as Microsoft Security Center (2.1) Service), running as the LocalSystem account with automatic startup, with the service image path being the sample itself plus the "-m security" parameter; the service control manager then relaunches it as a service process.

> **Evidence**: telemetry service snapshot: services["mssecsvc2.1"]={object_name:"LocalSystem", display_name:"Microsoft Security Center (2.1) Service", image_path:"C:\\dyn\\samples\\04bbe...exe -m security", type:"16", start:"2"}; event log: PID 4140 image=sample command_line="... -m security" parent=services.exe; registry HKLM\SYSTEM\CurrentControlSet\Services\mssecsvc2.1 (ImagePath/Start=2).
> 
> **Source**: `ref:3535e85a60` · `ev-000041`

### 4. Fakes security center service name

`T1036.005` · confidence **high** · dynamic

The sample carries the strings mssecsvc2.1, Microsoft Security Center (2.1) Service, and %s -m security, and at runtime registers the service display name as "Microsoft Security Center (2.1) Service", borrowing a system security component name to reduce the chance of notice.

> **Evidence**: sample strings from offset 0x31308 contain mssecsvc2.1 / Microsoft Security Center (2.1) Service / %s -m security in sequence; the dynamic service snapshot shows the display name matches the actual registration.
> 
> **Source**: `ev-000041` · `ref:4a67f2af1e` · `ref:3535e85a60`

### 5. Probes killswitch domain

`T1071.001` · confidence **high** · dynamic

It requests WannaCry's signature domain www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff[.]com over HTTP (DNS resolution first, then GET /); this check is the family's switch for deciding whether it is in an analysis environment; network monitoring recorded the DNS query and the complete HTTP request.

> **Evidence**: network monitoring: DNS received an A query for 'www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff[.]com', then the sample process (PID 4992 and service instance PID 4140) initiated TCP 80 and sent 'GET / HTTP/1.1' / 'Host: www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff[.]com'; imports include WININET InternetOpenA/InternetOpenUrlA.
> 
> **Source**: `ref:3535e85a60` · `ref:2cf511ddfc` · `ref:4a67f2af1e`

### 6. Embedded WinRAR self-extracting archive

`T1027.009` · confidence **high** · static

The resource directory of mssecsvr.exe carries a WinRAR self-extracting module (resource R/1831, 2,061,938 bytes) with RAR archive data immediately inside; the sample strings also give tasksche.exe and C:\%s\qeriuwjhrf, indicating that the later ransomware component is released from this SFX archive.

> **Evidence**: resource R/1831 at rva 0x3100a4 is an MZ/PE SFX module, with a 'Rar!' archive header starting at module offset 0x33000; SFX module strings include Software\\WinRAR SFX, SetupCode, SavePath; sample strings at offset 0x3136c have tasksche.exe and around 0x31308 C:\\%s\\qeriuwjhrf.
> 
> **Source**: `ev-000041` · `ref:c8c017f4af` · `ref:9bb19188e1`

### 7. SMB lateral movement attempt

`T1210` · confidence **medium** · dynamic

During the run the sample initiates an SMB2 session to 91[.]215[.]143[.]1 (Negotiate to \\91[.]215[.]143[.]1\IPC$, carrying constructed fields such as EPATH_REPLACE/PIPE), consistent with this family's worm-like lateral movement using the SMB vulnerability.

> **Evidence**: raw network monitoring packets: after 'FF 53 4D 42' (SMB2) Negotiate, \\91.215.143[.]1\IPC$ and fields such as EPATH_REPLACE__????? and \\PIPE\\ appear, target port 445, originating from the host where the sample was dropped.
> 
> **Source**: `ref:3535e85a60`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff[.]com` | 80 | c2 | Static | ⏳ not observed |

### Host

**Dropped paths**

- `C:\Windows\mssecsvr.exe`
- `C:\Windows\tasksche.exe`
- `C:\Windows\qeriuwjhrf`

**Registry**

- `HKLM\SYSTEM\CurrentControlSet\Services\mssecsvc2.1`

**Services**

- `mssecsvc2.1 (display name: Microsoft Security Center (2.1) Service)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `killswitch_domain` | `www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff[.]com` | No | Dynamic |
| `c2_hosts` | `www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff[.]com (used only for killswitch liveness probing; no tasking channel seen)` | No | Static |
| `install_path` | `C:\Windows\mssecsvr.exe` | Yes | Static |
| `drop_path` | `C:\Windows\tasksche.exe` | Yes | Static |
| `service_name` | `mssecsvc2.1` | Yes | Dynamic |
| `service_display_name` | `Microsoft Security Center (2.1) Service` | Yes | Dynamic |
| `service_cmdline` | `<own path> -m security` | Yes | Dynamic |
| `payload_container` | `WinRAR SFX (resource R/1831, containing a RAR archive)` | Yes | Static |

## Do not misjudge

:::important
The conclusions below are **easily misjudged**; take care when citing this report.

- Do not describe it as a generic backdoor or remote-control trojan: apart from the killswitch liveness probe, no tasking channel, module delivery, or remote-control session was observed this time.
- Do not claim that file encryption occurred or a ransom note was generated this time: the killswitch domain was successfully answered by local network monitoring in the sandbox, the sample exited early by design, and the ransom-note count during the observation period was 0.
- Do not treat 91[.]215[.]143[.]1 as a fixed C2 address: it is the target of runtime SMB scanning/lateral probing and may change with the environment.
- Do not judge the embedded WinRAR SFX module itself as an independent malicious payload: it is only the packaging container used by the family, and the ransomware body lies inside its RAR archive (not unpacked this time).
- Do not assume that the outer file can be double-clicked directly just because it has an .exe suffix: the file is actually a DLL (export PlayGame) and must be invoked by a loader.
:::

## Analysis method and limitations

| Item | Value |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The final ransomware module tasksche.exe is inside the RAR archive within the WinRAR SFX package, which was not unpacked this time, so the encryption algorithm, key management, and file traversal logic were not confirmed at the code level.
2. The killswitch domain was answered by local network monitoring in the sandbox (both DNS and HTTP succeeded), and the sample exited early by design, so the complete ransomware chain after file encryption, ransom-note delivery, and persistence was not observed; its encryption capability cannot be ruled out on this basis.
3. The outer DLL needs a loader (for example, calling it as an exported function) to trigger the drop logic; no path where the outer layer is directly executed by the system was observed.
4. The SMB session target 91[.]215[.]143[.]1 is a runtime scan target, characterized as a lateral-movement attempt rather than fixed infrastructure, with medium confidence.
5. No vendor-engine or YARA naming corroboration was obtained this time; family attribution is based on consistency of the sample's signature strings, resource structure, and dynamic behavior.

## Evidence index

<details>
<summary>Expand 9 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash & fingerprint | outer sample hash sha256=2d5fb939..., size 5,298,176 bytes |
| `ev-000002` | scan.imphash | outer imphash=0cdadfa1098d845dd3b4cf92625b5f04 |
| `ref:3f3823da6b` | PE structure parsing | AMD64 DLL, 6 sections, .rsrc 5,243,392 bytes, resource directory rva 0x11000 |
| `ev-000020` | String extraction | outer strings include C:\%s\%s, WINDOWS, mssecsvr.exe, confirming the drop path template |
| `ref:fdefa7a684` | disasm.function | rva 0x1014 is the resource-read→CreateFileA/WriteFile drop sequence; rva 0x10F8 is the CreateProcessA hidden launch |
| `ev-000041` | PE structure parsing | stage2 resource R/1831 is a 2,061,938-byte MZ/PE SFX module with a Rar! archive at internal offset 0x33000 |
| `ref:4a67f2af1e` | String extraction | stage2 strings include mssecsvc2.1, Microsoft Security Center (2.1) Service, %s -m security, tasksche.exe, killswitch domain |
| `ref:c8c017f4af` | String extraction | stage3 SFX module strings include Software\WinRAR SFX, SetupCode, SavePath, confirming the SFX container |
| `ref:3535e85a60` | Dynamic analysis platform | real dynamic run: service process launched by services.exe with "-m security", killswitch domain DNS/HTTP requests, SMB2 session attempt, artifacts packaged |

</details>

---

_This report's sample is not public, IOCs are defanged, for security research only._
