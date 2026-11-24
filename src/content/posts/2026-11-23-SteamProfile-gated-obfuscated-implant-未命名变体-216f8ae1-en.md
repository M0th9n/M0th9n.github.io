---
title: "Malware sample analysis: SteamProfile-gated obfuscated implant (unnamed variant) (PE · exe · 216f8ae1)"
published: 2026-11-23
draft: false
description: "Malicious (low confidence): SteamProfile-gated obfuscated implant (unnamed variant) · backdoor · difficulty medium · dynamic sandbox + static decompilation"
tags: ["backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-23-SteamProfile-gated-obfuscated-implant-未命名变体-216f8ae1"
---

> [!WARNING]
> **Verdict: malicious** · Family **SteamProfile-gated obfuscated implant (unnamed variant)** (uncertain) · Confidence **low**
> 
> Aliases: Steam Community dead-drop client, obfuscated x64 loader/RAT (string-encrypted)
> 
> The sample is a heavily obfuscated 64-bit Windows implant: in the static file all business strings are encrypted and the import table is trimmed to only 20 basic APIs, and at the entry point modules are dynamically resolved and loaded through obfuscated constant arithmetic; after it actually runs in the dynamic sandbox, the sample process itself writes a startup entry into the current user's Run key (value name light-theme, data set to its own path) and continuously issues HTTP requests to a fixed Steam Community profile page at steamcommunity[.]com on a roughly 30-second cycle. The combination of persistence + periodic callback + fully hidden strings is enough to classify it directly as a malicious implant.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **SteamProfile-gated obfuscated implant (unnamed variant)** · aliases Steam Community dead-drop client, obfuscated x64 loader/RAT (string-encrypted) · _uncertain_ |
| Confidence | **low** |
| Behavior class | backdoor |
| Difficulty | medium |
| First seen | 2026-11-22 16:58:57 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/216f8ae18eca087ef83446686514577e03c68bb8a3ce1381661d3d34821b6aaf/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Writes Run key for autostart</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.001</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">30s beacon to profile page</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Runtime string table decryption</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Dynamically resolves/loads modules</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Loads screenshot and recon deps</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1113</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `216f8ae18eca087ef83446686514577e03c68bb8a3ce1381661d3d34821b6aaf` |
| MD5 | _not recorded_ |
| Size | 2,253,312 bytes (2.1 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**7** behaviors in total, each with attached evidence; **3** are statically obtainable and **4** were obtained through dynamic analysis.

### 1. Run Key Autostart

`T1547.001` · Confidence **high** · Dynamic

About 6 seconds after execution, the sample process itself creates the value light-theme under HKU\S-1-5-21-...-1000\SOFTWARE\Microsoft\Windows\CurrentVersion\Run, with data set to the sample's own absolute path, achieving logon autostart.

> **Evidence**: System event telemetry at 01:01:11 registry value set event: ProcessId 6200 = sample, TargetObject=...\Run\light-theme, Details=C:\dyn\samples\216f8ae1...exe; the same value name light-theme also appears in the sample's decrypted string table
> 
> **Source**: `ev-000011` · `ev-000010`

### 2. 30-Second Profile Beacon

`T1102` · Confidence **high** · Dynamic

Starting about 16 seconds after launch, the sample repeatedly issues HTTP requests to a fixed Steam Community profile page at steamcommunity[.]com at a fixed cycle of about 30 seconds (GET /id/765611991592232669/, UA Mozilla/5.0, Cache-Control: no-cache), observed 6 times within the run window, forming a heartbeat-style callback.

> **Evidence**: The DNS query for steamcommunity[.]com was initiated by pid 6200; network monitoring captured the same sample process's GET /id/765611991592232669/ and Host: steamcommunity[.]com six times at 01:01:22 / 01:01:52 / 01:02:23 / 01:02:53 / 01:03:23 / 01:03:53
> 
> **Source**: `ev-000011` · `ev-000010`

### 3. Runtime String Table Decryption

`T1027` · Confidence **high** · Static

The .rdata/.data entropy in the file is 7.538/7.996 respectively and contains no plaintext business strings (only import names remain); the sample decrypts the string table into the heap only at runtime, after which the mutex suffix, theme name, Steam profile URL, HELLO protocol format, etc. become visible; this shows that static characteristics are systematically hidden.

> **Evidence**: .rdata entropy 7.538 (off 0x209000), .data entropy 7.996 (off 0x214200); whole-file string extraction found 0 plaintext business strings; the decrypted string table appears at 0x9da52d in the memory dump
> 
> **Source**: `ev-000005` · `ev-000006` · `ev-000009` · `ev-000010`

### 4. Dynamic Module Resolution and Loading

`T1129` · Confidence **high** · Dynamic

At the entry point, APIs are not used through the static import table; instead, function addresses are computed via constant XOR/pointer arithmetic obfuscation and modules such as advapi32, shell32, ole32, iphlpapi, wininet, ws2_32, psapi, combase, sechost, d3d11, dxgi, rpcrt4 are loaded one by one with LoadLibraryA, evading import table detection and providing registry, network, process and graphics functionality.

> **Evidence**: At entry 0x1400F5430, sub rsp,0x28 followed by movabs constant arithmetic then call r8; during behavior emulation, pc 0x1400334ca-0x140033372d consecutively LoadLibraryA(advapi32/shell32/ole32/iphlpapi/wininet/ws2_32/psapi/combase/sechost/d3d11/dxgi/rpcrt4)
> 
> **Source**: `ref:a01aaeadd1` · `ref:6e53d506fc` · `ev-000003`

### 5. Screenshot and Collection Dependency Loading

`T1113` · Confidence **medium** · Dynamic

The sample actively loads d3d11.dll and dxgi.dll (common dependencies for desktop duplication/screenshot) as well as psapi.dll, iphlpapi.dll, GetForegroundWindow/IsWindowVisible/GetFocus and other window and host information collection surfaces, providing screen capture and process/environment enumeration capabilities; no actual image file was captured within this run window.

> **Evidence**: Behavior emulation pc 0x1400336bb LoadLibraryA(d3d11.dll), 0x1400336f6 LoadLibraryA(dxgi.dll) and psapi/iphlpapi loading; static imports USER32.GetForegroundWindow/IsWindowVisible/GetFocus/GetProcessWindowStation, GDI32.GetStockObject
> 
> **Source**: `ref:6e53d506fc` · `ref:d8e55c004f`

### 6. Single-Instance Mutex Naming

`T1480` · Confidence **low** · Static

The decrypted string table shows two global mutex names Global\{{081F2F64-1503-2D62-555E-C9FD8082EAC0}}_Admin and ..._User, used to distinguish single-instance execution between administrator and standard user; no system event of mutex creation was directly captured within this run window.

> **Evidence**: Plaintext mutexes Global\{{081F2F64-1503-2D62-555E-C9FD8082EAC0}}_Admin / _User at 0x144c9 and 0x9da52d in the memory dump
> 
> **Source**: `ev-000010`

### 7. HELLO Panel Handshake Protocol

`T1071.001` · Confidence **medium** · Static

The built-in protocol format string HELLO|%s|%s|%s|%s|%s|v3.3F|%s|%s|%s (reporting version v3.3F, nine fields carrying identity/environment information), together with the %s@%s and hxxps://%s:%hu/ address concatenation formats, indicates the existence of a handshake/heartbeat channel reporting to a remote panel.

> **Evidence**: Decrypted at 0x9da59d-0x9da5a9 in the memory dump are %s@%s and HELLO|%s|%s|%s|%s|%s|v3.3F|%s|%s|%s; also seen are hxxps://%s:%hu/ and hxxps://%s/%s/%s
> 
> **Source**: `ev-000010`


## IOC (Defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated a TCP connection to this target (multiple retries within a short period).
:::

:::caution
**Real server side still unverified**: the above connection/handshake was completed with a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence Source | Dynamic Observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://steamcommunity[.]com/id/765611991592232669/` | 443 | panel | Dynamic | Observed |

### Host

**Mutexes**

- `Global\{{081F2F64-1503-2D62-555E-C9FD8082EAC0}}_Admin`
- `Global\{{081F2F64-1503-2D62-555E-C9FD8082EAC0}}_User`

**Registry**

- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\light-theme`

### Configuration

| Key | Value | Required | Evidence Source |
|:--|:--|:--|:--|
| `c2_hosts` | `steamcommunity[.]com` | Yes | Dynamic |
| `c2_uri` | `/id/765611991592232669/` | Yes | Dynamic |
| `c2_port` | `443` | Yes | Dynamic |
| `user_agent` | `Mozilla/5.0` | Yes | Dynamic |
| `beacon_period_sec` | `30` | No | Dynamic |
| `registry_run_value` | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\light-theme` | Yes | Dynamic |
| `mutex` | `Global\{{081F2F64-1503-2D62-555E-C9FD8082EAC0}}_Admin / _User` | No | Static |
| `protocol_hello` | `HELLO\|%s\|%s\|%s\|%s\|%s\|v3.3F\|%s\|%s\|%s` | No | Static |
| `build_version` | `v3.3F` | No | Static |
| `campaign_flags` | `nocrp_on; light-theme; --elevated` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note this when citing this report.

- Do not claim the sample has stolen account credentials, browser data or Steam sessions: no reads of browser/Steam directories were observed within the run window, and there were no outbound requests carrying data.
- Do not claim the sample performed process injection/process hollowing: memory scanning rated 0 suspicious implants for this process, and no child processes were spawned at runtime.
- Do not treat steamcommunity[.]com as the attacker's private C2 domain: it is a legitimate public site, the sample only accesses one fixed user profile page on it, possibly for authorization/dead-drop verification; the real panel host did not appear in this window.
- Do not classify this sample as ransomware or wiper: no file encryption, deletion or shadow copy destruction behavior was seen.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and To Be Verified**

1. The sample's .rdata/.data are fully encrypted and strings are decrypted on demand, so static analysis cannot recover the complete configuration and code semantics; control flow is obfuscated, with constant XOR arithmetic + indirect calls at the entry point, and full deobfuscation was not performed.
2. Only HTTP requests to the fixed profile page at steamcommunity[.]com were captured; no real panel session corresponding to the HELLO protocol was obtained, so the real C2 host, port and encryption method remain unconfirmed (the HELLO protocol entry is marked as a static inference).
3. Capabilities such as screenshot (d3d11/dxgi), process enumeration (psapi) and mutex single-instance come from module loading and decrypted strings; no screenshot output, process traversal results or mutex creation events were directly observed within the run window, so the confidence of related conclusions is treated as medium/low.
4. No complete file-system-level operation records were obtained, so whether the sample read browser/Steam data cannot be determined from these artifacts.
5. The family naming lacks cross-validation from vendor naming, YARA or public sandbox reports; it is registered only as a candidate and marked uncertain.

## Evidence Index

<details>
<summary>Expand 18 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprinting | sha256=216f8ae1...; md5=3b61a16fce9eff5f4b20a384aceef89b; size 2253312 bytes |
| `ev-000002` | scan.imphash | imphash=bc051e8081fce700a2904976020c7b00 |
| `ev-000003` | scan.rich | Rich header present, 6 MSVC toolchain records, richhash=227e4c8928441e706fb7a3f687e67bf5 |
| `ev-000004` | scan.entropy | .text entropy 6.654 |
| `ev-000005` | scan.entropy | .rdata entropy 7.538 (high) |
| `ev-000006` | scan.entropy | .data entropy 7.996 (high) |
| `ev-000009` | String extraction | String extraction: 792 ASCII strings, all code-byte-like, no plaintext business strings, no flag hits |
| `ev-000010` | Scripted forensics | Extracted the runtime decrypted string table from the memory dump (_Admin/_User/light-theme/Steam profile URL/nocrp_on/HELLO protocol, etc.) |
| `ev-000011` | Scripted forensics | Parsed dynamic sandbox telemetry and network monitoring: Run key light-theme write, steamcommunity[.]com DNS and 6 HTTP requests, no child processes, memory scan 0 suspicious |
| `ref:ce26b78dd2` | PE structure parsing | AMD64 GUI executable, 5 sections, entry RVA 0xF5430, no exports/resources/TLS/LoadConfig, no structural anomalies |
| `ref:d8e55c004f` | Import table parsing | 5 DLLs / 20 import symbols (KERNEL32, WS2_32 ordinals 8/14/111, USER32, GDI32, ole32), no CRT/no static LoadLibrary/GetProcAddress imports |
| `ref:a01aaeadd1` | disasm.function | Obfuscation stub from entry 0x1400F5430: movabs constants + pointer arithmetic + indirect call/jmp, dynamically resolving APIs |
| `ref:8ad6c8afb6` | unpack.detect | Static packer detection: no known packer hit (packed=false, confidence=0) |
| `ref:6e53d506fc` | dyn.run | Behavior emulation: LoadLibraryA advapi32/shell32/ole32/iphlpapi/wininet/ws2_32/psapi/combase/sechost/d3d11/dxgi/rpcrt4 |
| `ref:5bf347a4bd` | Dynamic analysis platform | Real dynamic detonation: the sample process started and kept running, producing memory dump, network monitoring and telemetry; no new child processes within the observation window |
| `c2_evidence:216f8ae1` | Connection evidence extraction | Dynamic network monitoring recorded 8 connection attempts to steamcommunity[.]com:443; no complete session captured |
| `telemetry:216f8ae1` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 113; ETW short-lived process events 1; filtered tool/system noise 23 |
| `etw:216f8ae1:6200` | Process event monitoring | Short-lived process event: 216f8ae18eca087ef83446686514577e03c68bb8a3ce1381661d3d34821b6aaf.exe (pid 6200; MD5=3B61A16FCE9EFF5F4B20A384ACEEF89B,SHA256=216F8AE18ECA087EF83446686514577E03C68BB8A3CE1381661D3D34821B6AAF,IMPHASH=2EDDB0DD356374D338CC10CE8C8B6680) |

</details>

---

_The sample in this report is not public, IOCs have been defanged, for security research only._
