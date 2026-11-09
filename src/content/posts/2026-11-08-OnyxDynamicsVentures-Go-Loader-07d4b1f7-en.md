---
title: "Malware Analysis: OnyxDynamicsVentures Go Loader (PE · exe · 07d4b1f7)"
published: 2026-11-08
draft: false
description: "Malicious (low confidence): OnyxDynamicsVentures Go Loader · loader/implant · difficulty hard · Dynamic sandbox analysis + static decompilation"
tags: ["OnyxDynamicsVentures", "loader", "implant", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-08-OnyxDynamicsVentures-Go-Loader-07d4b1f7"
---

> [!WARNING]
> **Verdict: Malicious** · Family **OnyxDynamicsVentures Go Loader** (uncertain) · Confidence **low**
> 
> Aliases: Onyx Dynamics Ventures
> 
> Observed in a real isolated environment: the main process writes and launches %TEMP%\dex.exe, then sends encrypted HTTP POSTs to a fixed IP, and an implanted native PE plus shellcode appears in explorer.exe memory; combined with the heavily obfuscated Go main module and the child process with forged version information, this is judged to be a malicious multi-stage loader.

## Overview

| Item | Content |
|:--|:--|
| Family | **OnyxDynamicsVentures Go Loader** · alias Onyx Dynamics Ventures · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · implant |
| Difficulty | hard |
| First seen | 2026-11-07 18:17:07 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/07d4b1f763d1d9479635e58980100f90d7fd4fa89808cac1c97e91607e0ad6ca/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Drop and launch dex.exe</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105; T1106</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Forge Briani updater</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Beacon to fixed IP</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001; T1573</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Inject PE into explorer</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.002</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Random-symbol Go module</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `07d4b1f763d1d9479635e58980100f90d7fd4fa89808cac1c97e91607e0ad6ca` |
| MD5 | _not recorded_ |
| Size | 5,219,256 bytes (5.0 MB) |
| Type | PE · `exe` |

## Behavior analysis

**10** behaviors in total, each backed by evidence; **6** are statically available and **4** were obtained through dynamic analysis.

### 1. Drop and launch dex.exe

`T1105; T1106` · Confidence **high** · dynamic

The main process writes dex.exe under %TEMP% and then creates a child process with that path; the child PID forms a clear parent-child chain with the sample process.

> **Evidence**: Process-creation telemetry: ProcessId 2360 produces File created TargetFilename=%TEMP%\dex.exe; then Image=%TEMP%\dex.exe (PID 1324) starts with the sample as its parent.
> 
> **Source**: `ref:71a1e5e9d4` · `ref:e749bbd816`

### 2. Forge Briani updater

`T1036.005` · Confidence **high** · dynamic

The child process carries forged version resources: FileVersion 2.4.9[.]0, Description 'Briani Updater', Product 'Briani', Company 'Clitrusciar', OriginalFileName 'Briani-app.exe', with system32 as its working directory.

> **Evidence**: In process-creation telemetry, the version-information fields of dex.exe do not match its file name.
> 
> **Source**: `ref:71a1e5e9d4`

### 3. Beacon to fixed IP

`T1071.001; T1573` · Confidence **high** · dynamic

The sample process sends an HTTP POST / to 95[.]217[.]96[.]240:80 with Content-Type application/json and a 132-character Base64 (97 bytes decoded) high-entropy request body.

> **Evidence**: Network monitoring capture: sample process (2360) requested TCP 95[.]217[.]96[.]240:80; then HTTP records 'POST / HTTP/1.1', 'Content-Type: application/json', 'Content-Length: 132' and a Base64 body.
> 
> **Source**: `ref:9267022c7f` · `ref:e749bbd816`

### 4. Inject PE into explorer

`T1055.002` · Confidence **medium** · dynamic

A memory scan found a MEM_PRIVATE executable region in explorer.exe (PID 5208) at base 0x2ea0000, 0xb0000 bytes, containing a PE header, 8 sections and shellcode; it was dumped as 2ea0000.shc and 2eab000.dll.

> **Evidence**: Memory-scan report: main_image_path=explorer.exe, implanted_pe=1, has_shellcode=1, protection=0x40, is_listed_module=0; the injected PE's SHA256=2763364eb6bf347a62b997c729c6e8482713f048e5639fc28b78fef79710e673.
> 
> **Source**: `ref:963c6abc41` · `ref:76848631bf` · `ref:06e9f6b4a4` · `ref:5830f16814`

### 5. Random-symbol obfuscated Go module

`T1027` · Confidence **high** · static

The main module is a statically linked Go 1.24.5 program; all 37 functions in the main package use random names (such as scyph, xgojxGMoy, dzLWDcpn2H1) and are mixed with large amounts of dead println code, while retaining the build module path OnyxDynamicsVentures.

> **Evidence**: Symbol table and decompilation results: main.(*AdfhyvMPy7Q).scyph and other random names; main.main contains 1500+ calls, many of them dead runtime.print* code; Go build info in .data contains 'path OnyxDynamicsVentures'.
> 
> **Source**: `ref:381b790c4d` · `ref:b7c181365c` · `ref:c49ff078c1` · `ref:6d580c8b1a`

### 6. Resolve Win32 APIs at runtime

`T1106` · Confidence **high** · static

The static import table contains only 46 symbols from kernel32.dll; other APIs from ntdll/ws2_32/advapi32 are resolved and called at runtime through syscall.LoadLibrary, GetProcAddress and LazyProc.Call.

> **Evidence**: Import table dll_count=1 (kernel32, 46 symbols); the call graph shows main.* calling syscall.(*LazyProc).Call / LoadLibrary / GetProcAddress in multiple places; strings include ntdll.dll, ws2_32.dll, advapi32.dll.
> 
> **Source**: `ref:66502a8eec` · `ref:c3c787b92e` · `ref:d44659eb05`

### 7. Collect host and network fingerprints

`T1082; T1012` · Confidence **medium** · static

The binary links resolution paths for NIC, domain, volume, user and registry query APIs (GetAdaptersAddresses, GetAdaptersInfo, NetGetJoinInformation, GetVolumeNameForVolumeMountPointW, ConvertSidToStringSidW, GetUserNameExW, RegQueryValueExW), giving it host fingerprinting capability.

> **Evidence**: The above API names appear in the string table (Go syscall lazy-resolution table), together with GetComputerNameW, GetSystemInfo and others.
> 
> **Source**: `ref:d44659eb05`

### 8. Linked service and registry operations

`T1543.003; T1547.001` · Confidence **medium** · static

The binary contains resolution paths for OpenSCManagerW/OpenServiceW/QueryServiceStatus and RegCreateKeyExW/RegSetValueExW/RegDeleteValueW, giving it service-control and registry-write capability; no actual new Run key or service was observed in this run.

> **Evidence**: Strings hit the above APIs; the Run key before and after the run retained only OneDrive and SecurityHealth, with no new entries.
> 
> **Source**: `ref:d44659eb05` · `ref:71a1e5e9d4`

### 9. Built-in suspicious drop paths

`T1036.005` · Confidence **medium** · static

The binary hardcodes two non-system directory paths: C:\Program Files (x86)\sotho\githinyuasp.txt and C:\Program Files\scotland\mccaaninnaett.inf, which may be used in later stages to write configuration or perform INF-related operations.

> **Evidence**: String-scan offsets 0x35603a and 0x356f98; the same region also contains 'Main file name provided' and 'application buffer large enough data, trying extract code'.
> 
> **Source**: `ref:d44659eb05`

### 10. Carries code-signing data

`T1553.002` · Confidence **medium** · static

The PE security directory contains 8120 bytes of Authenticode data, and the certificate chain involves DigiCert Assured ID Root CA / DigiCert Trusted G4 series; signature validity was not cryptographically verified.

> **Evidence**: PE data directory SECURITY: rva=0x4F8400, size=8120; strings contain DigiCert OCSP/CRL addresses.
> 
> **Source**: `ref:fe02cdb9df` · `ref:d44659eb05`


## IOC (defanged)

### Network

:::note
**A connection was dynamically observed**: the sample actually initiated a TCP connection to this target (with several retries within a short period).
:::

:::caution
**The real server side remains unverified**: the above connection/handshake was completed with a local controlled emulation service, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://95[.]217[.]96[.]240/` | 80 | c2 | dynamic | observed |

### Host

**Dropped paths**

- `%TEMP%\dex.exe`
- `C:\Program Files (x86)\sotho\githinyuasp.txt`
- `C:\Program Files\scotland\mccaaninnaett.inf`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `95[.]217[.]96[.]240` | yes | dynamic |
| `c2_port` | `80` | yes | dynamic |
| `c2_uri` | `/` | yes | dynamic |
| `beacon_format` | `HTTP POST; Content-Type: application/json; Base64 body (132 chars)` | yes | dynamic |
| `staging_path` | `%TEMP%\dex.exe` | yes | dynamic |
| `campaign_id` | `OnyxDynamicsVentures` | no | static |
| `install_path` | `C:\Program Files (x86)\sotho\githinyuasp.txt` | no | static |
| `encryption_algo` | `unidentified; AES and SHA-256 constants present; beacon body is high-entropy Base64 (97 bytes decoded)` | no | static |
| `go_runtime` | `go1.24.5; CGO_ENABLED=0; GOOS=windows; GOARCH=amd64; -trimpath=true` | no | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- No mass file encryption or ransom note was observed (ransom_notes=0), so it should not be judged as ransomware.
- No LSASS access or browser credential-file reads were observed, so it should not be judged a stealer on that basis.
- Only one outbound HTTP POST was captured, with no server response or delivered command obtained; the completeness of the command-and-control protocol is unknown, so it should not be asserted that a full remote-control session exists.
- The dex.exe file itself was not recovered (open failed), so its internal implementation, final payload family and configuration cannot be confirmed.
- Built-in strings such as gate-check, soft-focus, color-pass, set-review and 'Film dailies review queue' should not be treated as real domains or businesses; they are more likely obfuscation strings or decoys.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. Only one outbound POST was captured, with no server response or follow-up command recorded; the C2 command protocol and persistence capability are unverified.
2. dex.exe had already exited or could not be opened during scanning (open_failed=87), and the file itself was not recovered, so its family attribution and internal configuration are unknown.
3. The injector of the PE implanted in explorer.exe was not directly proven by the call chain; it is inferred only from the sample→dex.exe parent-child chain and the timeline.
4. Registry/service writes are only static capability judgments based on linked APIs; the Run key did not change before or after the run, and no actual persistence was observed.
5. Many functions in the Go main module have random names and are mixed with dead code, and the static strings contain obfuscated/decoy content, so static-layer conclusions have limited confidence.
6. The Authenticode signature was only parsed down to the certificate chain and data directory; signature validity was not verified.
7. Only the request side of the C2 was observed, with no response obtained, so it is not confirmed whether a complete session exists.

## Evidence index

<details>
<summary>Expand 24 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:15240bf255` | sample triage | Hashes, section entropy, import count, packing score and structural anomalies (0 anomalies, packing 0) |
| `ref:fe02cdb9df` | PE structure parsing | PE64 header, 8 sections, entry 0x70B80, SECURITY directory 8120 bytes, Go build characteristics |
| `ref:66502a8eec` | import-table parsing | Only 46 symbols from kernel32.dll, imphash d42595b695fc008ef2c56aabd8efd68e |
| `ref:d44659eb05` | string extraction | Custom paths, strings such as emirp/scene/flow/gate-check, advapi32/ws2_32 API names |
| `ref:62fd7d19e1` | crypto constant identification | AES S-box/inverse S-box, SHA-256 K constants, TEA delta |
| `ref:381b790c4d` | decompile.symbols | 2169 functions, main.* randomly named |
| `ref:6d580c8b1a` | decompile.function | main.main located at RVA 0xC9F20 |
| `ref:b7c181365c` | pclntab | Parsed 37 main-package functions and random method names |
| `ref:c3c787b92e` | callgraph | main.* calls to LazyProc.Call/LoadLibrary/GetProcAddress/WSAStartup |
| `ref:c49ff078c1` | mem-scan | Hits for OnyxDynamicsVentures, dex.exe, emirp and other strings in process memory |
| `ref:c02173474a` | dynamic analysis platform | Real dynamic detonation: candidate process PID 2360, 5 dumps, hollows results and rollback |
| `ref:e749bbd816` | telemetry+network | ETW: child process dex.exe (PID 1324, parent 2360); network monitoring: POST 95[.]217[.]96[.]240:80 |
| `ref:9267022c7f` | network-capture | Sample process 2360 sends an application/json POST to 95[.]217[.]96[.]240:80 with a 132-byte Base64 request body |
| `ref:71a1e5e9d4` | sysmon-telemetry | 2360 creates %TEMP%\dex.exe; 1324 starts with 'Briani Updater' version info; no new Run key |
| `ref:963c6abc41` | memory-forensics | explorer.exe (PID 5208) detected with implanted_pe=1, has_shellcode=1, dumped 2ea0000.shc/2eab000.dll |
| `ref:76848631bf` | artifact-package | Dynamic artifacts include memory dumps, network logs, process timeline and hash manifest |
| `ref:06e9f6b4a4` | hashes and fingerprints | Implanted PE SHA256=2763364e..., imphash=3819dc02..., MinGW-style 8-section DLL |
| `ref:5830f16814` | import-table parsing | Implanted DLL depends on kernel32/user32/ntdll, including IsDebuggerPresent, VirtualProtect, etc. |
| `ref:4079cfa6f4` | section-table parsing | Implanted DLL has 8 sections (.text/.rdata/.data/.pdata/.fptable/.tls/_RDATA/.reloc) |
| `ref:80820d15c4` | string extraction | Implanted DLL has only 1060 ASCII strings and no readable C2, suggesting runtime decryption |
| `c2_evidence:07d4b1f7` | connection evidence extraction | Dynamic network monitoring recorded 1 connection attempt to 95.217.96[.]240:80; no complete session captured |
| `telemetry:07d4b1f7` | dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 112; ETW short-lived process events 2; tool/system noise filtered 27 |
| `etw:07d4b1f7:2360` | process event monitoring | Short-lived process event: 07d4b1f763d1d9479635e58980100f90d7fd4fa89808cac1c97e91607e0ad6ca.exe (pid 2360; MD5=81E31923CFF2646A2B7C3112E9AB13C0,SHA256=07D4B1F763D1D9479635E58980100F90D7FD4FA89808CAC1C97E91607E0AD6CA,IMPHASH=D42595B695FC008EF2C56AABD8EFD68E) |
| `etw:07d4b1f7:1324` | process event monitoring | Short-lived process event: dex.exe (pid 1324; MD5=0EBF04631F6023B5C2A7149C192B2F09,SHA256=5BA916C49724FF6985E1F53C41D6B4E8AB81DF547A3726BB60D58E36AAADDC4B,IMPHASH=353E10C266C3446F0B89B28FD1733CF8) |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
