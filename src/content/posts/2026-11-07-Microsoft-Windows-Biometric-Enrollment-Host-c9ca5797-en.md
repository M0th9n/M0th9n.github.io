---
title: "Malware Analysis: Microsoft Windows Biometric Enrollment Host (PE · exe · c9ca5797)"
published: 2026-11-07
draft: false
description: "Benign (high confidence): Microsoft Windows Biometric Enrollment Host · benign · difficulty easy · Dynamic sandbox analysis + static decompilation"
tags: ["Microsoft Windows", "benign", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-07-Microsoft-Windows-Biometric-Enrollment-Host-c9ca5797"
---

> [!NOTE]
> **Verdict: Benign** · Family **Microsoft Windows Biometric Enrollment Host** · Confidence **high**
> 
> Aliases: BioEnrollmentHost.exe, Windows Hello biometric enrollment host, Biometric Enrollment Host
> 
> This file is the Microsoft-signed Windows component BioEnrollmentHost.exe (Biometric Enrollment Host, the Windows Hello biometric enrollment UI host). The file digest recomputed per Authenticode rules (excluding CheckSum, the Security directory entry, and the certificate table) is 8f2b2a7ee30ec7f03338a2c4c8b4da44e3c156b7c7d63ef82c4f578dbcba0559, byte-for-byte identical to the SpcIndirectDataContent digest in the signed PKCS#7, showing the file has not been modified since Microsoft signed it; the signature status is valid, the signer is CN=Microsoft Windows, and the timestamp was issued by Microsoft Time-Stamp Service. The static import surface contains only WinRT/CRT and thread/synchronization APIs, with no imports related to networking, file writing, registry, services, scheduled tasks, or process injection; in an isolated dynamic sandbox the sample started successfully and loaded Windows.UI.Xaml/wincorlib, with no network requests, no child processes, and no files written throughout; memory scanning found no hooks, replacement, implantation, or reflective loading. Overall it is judged to be a benign system component reported as a false positive.

## Overview

| Item | Content |
|:--|:--|
| Family | **Microsoft Windows Biometric Enrollment Host** · aliases BioEnrollmentHost.exe, Windows Hello biometric enrollment host, Biometric Enrollment Host |
| Confidence | **high** |
| Behavior class | benign |
| Difficulty | easy |
| First seen | 2026-11-04 15:19:02 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/c9ca5797b92076943247208f2159ae169802b159555341b7adeee6f7dd387886/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Verify Microsoft signature</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">N/A</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Load WinRT XAML UI</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">N/A</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Start biometric enrollment host</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">N/A</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">No network egress at runtime</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">N/A</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">No persistence, no file drop</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">N/A</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `c9ca5797b92076943247208f2159ae169802b159555341b7adeee6f7dd387886` |
| MD5 | _not recorded_ |
| Size | 508,456 bytes (496.5 KB) |
| Type | PE · `exe` |

## Behavior analysis

**6** behaviors in total, each backed by evidence; **2** are statically available and **4** were obtained through dynamic analysis.

### 1. Verify the Microsoft digital signature

`N/A` · Confidence **high** · static

The embedded certificate table (offset 0x725C0, length 0x9C28) is a PKCS#7 signature; the PE digest recomputed per Authenticode rules exactly matches the digest in the signed SpcIndirectDataContent, the signature status is valid, the signer is CN=Microsoft Windows (thumbprint D8FB0CC66A08061B42D46D03546F0D42CBC49B7C), with a Microsoft Time-Stamp Service timestamp.

> **Evidence**: certificate table off=0x725C0 size=0x9C28; recomputed digest 8f2b2a7ee30ec7f03338a2c4c8b4da44e3c156b7c7d63ef82c4f578dbcba059 matches the PKCS#7 digest; signature status Valid
> 
> **Source**: `ref:13713a5d44` · `ref:3f62c32dfd` · `ref:53a6b5f75c`

### 2. Load the WinRT XAML interface

`N/A` · Confidence **high** · static

It imports wincorlib.DLL and WinRT interfaces related to Windows.UI.Xaml/Windows.Foundation; strings include type names such as Windows.UI.Xaml.Window, Windows.UI.Xaml.Controls.Frame, and BioEnrollment.Host.HostFrame, indicating the process hosts the XAML user interface for Windows Hello biometric enrollment.

> **Evidence**: imports wincorlib.DLL (62 symbols); UTF-16 strings 0x515D8 'Windows.UI.Xaml.Window', 0x51878 'BioEnrollment.Host.HostFrame'
> 
> **Source**: `ref:9bb83ed89c` · `ref:a5bab6ceda` · `ref:d8f1b6885b`

### 3. Start the biometric enrollment host

`N/A` · Confidence **high** · dynamic

After being dropped in an isolated dynamic sandbox, the sample process (PID 8056) was created normally and stayed alive, loading system modules such as ntdll/kernel32/combase/wincorlib/Windows.UI.Xaml/ws2_32; it spawned no child processes during execution, consistent with an ordinary XAML host.

> **Evidence**: sandbox timeline PID 8056, module list includes C:\Windows\System32\wincorlib.DLL and Windows.UI.Xaml.dll; only 1 candidate process
> 
> **Source**: `ref:ed806a0db5` · `ref:1a0582157f` · `ref:520a2dc405`

### 4. No network egress at runtime

`N/A` · Confidence **high** · dynamic

The process made no DNS/TCP/UDP requests within the dynamic observation window; all requests in the network monitoring log came from existing system update, search, browser, and other processes. The static import table likewise contains no socket/wininet/winhttp/WinHTTP network APIs.

> **Evidence**: network monitoring logs filtered by process name/PID show no request records for c9ca5797…/8056; no network APIs among the 27 imported DLLs
> 
> **Source**: `ref:ed806a0db5` · `ref:9bb83ed89c` · `ref:5c29d01de3`

### 5. No persistence or file drop

`N/A` · Confidence **high** · dynamic

The import table does not contain RegCreateKey/RegSetValue, CreateFileW, WriteFile, CreateService, schtasks or other registry, file-writing, service, or scheduled-task APIs; during dynamic observation the process created no files.

> **Evidence**: 217 imported symbols, no Reg*/file-write/service/scheduled-task APIs; sandbox dump records 0 files for this PID
> 
> **Source**: `ref:9bb83ed89c` · `ref:1a0582157f`

### 6. No injection or hooking in memory

`N/A` · Confidence **high** · dynamic

Memory scanning of the running sample process checked 29 modules, reporting 0 hooked, 0 replaced, 0 modified PE headers, 0 IAT hooks, and 0 implanted modules; a system-wide hollowing scan likewise found 0 suspicious items.

> **Evidence**: PE scan SUMMARY: Total scanned 29, Hooked 0, Replaced 0, Hdrs Modified 0, IAT Hooks 0, Implanted 0, Total suspicious 0
> 
> **Source**: `ref:ed806a0db5` · `ref:520a2dc405`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis method and limitations" at the end).
:::

### Host

- **No host IOC was recovered.**

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- Do not judge it as malware merely because the sample was in an isolated directory or appeared in a malware delivery source — the signature digest matches the file content byte for byte, proving it is an unmodified original Microsoft binary.
- Do not interpret strings such as Windows Hello/Face/Iris/Fingerprint/SecurityKey as backdoor functionality for stealing biometrics or credentials — these are view-model and control names of the built-in biometric enrollment UI.
- Do not treat the process loading ws2_32.dll as C2 communication evidence — that module is loaded indirectly by XAML/system components, the process itself makes no network requests, and the static import table has no network APIs.
- Do not claim the sample has persistence, process injection, download, or lateral-movement behavior — neither the import surface nor dynamic observation shows such evidence.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. The offline environment did not query certificate revocation status (CRL/OCSP); however, the file digest and the digest in the signature match exactly, the chain is Microsoft Windows Production PCA 2011 → Microsoft Root Certificate Authority 2010, and local signature verification returned valid.
2. Dynamic observation covers only a single detonation window of about 2 minutes and did not simulate the interactive biometric enrollment flow; the conclusions of no network requests and no file drops are based on behavior and network monitoring logs within that window.
3. The component depends on Windows Hello/biometric broker to complete the full business flow; the sandbox did not trigger actual fingerprint/facial/security-key enrollment interactions, so its complete UI behavior in a real Windows Hello flow cannot be assessed.
4. The sample is an AppContainer/WinRT application, and some extended behavior may be performed on its behalf by system broker processes; this observation covers only the directly launched process.

## Evidence index

<details>
<summary>Show 11 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:15cb599287` | Sample triage | Hash/imphash/Rich header/section entropy/import statistics, packing.score=0, anomaly_count=0 |
| `ref:99ac563635` | PE structure parsing | AMD64 GUI PE, 6 sections, entry rva=0x4C9F0, signature directory rva=0x725C0 size=39976, with APPCONTAINER/GUARD_CF/DYNAMIC_BASE |
| `ref:9bb83ed89c` | Import table parsing | 27 DLLs/217 symbols, only WinRT/CRT/thread-synchronization APIs; no networking, file-write, registry, service, or injection-related imports |
| `ref:a5bab6ceda` | String extraction | 947 ASCII / 239 UTF-16 strings, including BioEnrollmentHost.pdb, Windows.UI.Xaml, BioEnrollment.* view-model strings; no C2/URL/flag hits |
| `ref:13713a5d44` | script (bash) | Recomputed digest per Authenticode rules 8f2b2a7ee30ec7f03338a2c4c8b4da44e3c156b7c7d63ef82c4f578dbcba059, matching the PKCS#7 digest |
| `ref:3f62c32dfd` | script (bash) | openssl smime -verify succeeded; local signature verification Status=Valid, signer CN=Microsoft Windows, thumbprint D8FB0CC6…, timestamp issued by Microsoft Time-Stamp Service |
| `ref:21dc7c77fd` | script (bash) | Version resource: CompanyName=Microsoft Corporation, FileDescription=Biometric Enrollment Host, OriginalFilename=BioEnrollmentHost.exe, FileVersion=10.0.19041.4355 |
| `ref:37ddb42aef` | script (bash) | String/debug paths: shellcommon\shell\auth\enrollment\bio\app\host\App.xaml.cpp, BioEnrollmentHost.pdb, BioEnrollment.Face/Iris/Fingerprint/SecurityKey type names |
| `ref:ed806a0db5` | Dynamic analysis platform | Isolated dynamic sandbox drop: process PID 8056 created and alive, loading wincorlib/Windows.UI.Xaml; memory scan of 29 modules found 0 suspicious; full hollowing scan 0; no files produced |
| `ref:1a0582157f` | Dynamic analysis platform | Timeline: only 1 candidate process, no child processes spawned, dump records 0 files, plugin process has no network-related events |
| `ref:5c29d01de3` | Dynamic analysis platform | Network monitoring logs: requesters are svchost/SearchApp/msedge and other system and browser processes; no requests from sample PID 8056 |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
