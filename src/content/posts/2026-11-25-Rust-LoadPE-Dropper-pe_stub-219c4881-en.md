---
title: "Malicious sample analysis: Rust LoadPE Dropper (pe_stub) (PE · exe · 219c4881)"
published: 2026-11-25
draft: false
description: "Malicious (confidence: low): Rust LoadPE Dropper (pe_stub) · loader/dropper/injector · difficulty medium · dynamic sandbox + static decompilation"
tags: ["LoadPE", "loader", "dropper", "injector", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-25-Rust-LoadPE-Dropper-pe_stub-219c4881"
---

> [!WARNING]
> **Verdict: malicious** · Family **Rust LoadPE Dropper (pe_stub)** (unconfirmed) · Confidence **low**
> 
> Aliases: loadpe, pe_stub, bundle_deploy
> 
> The sample is a Rust-written PE loader with 9.4MB of text padding: its import surface combines resource dropping, process hollowing (VirtualAllocEx/WriteProcessMemory/GetThreadContext/SetThreadContext/ResumeThread) and ShellExecuteExW launch capability; .rdata retains source paths such as src\main.rs, src\loadpe_child.rs, src\bundle_deploy.rs and runtime log templates such as "loadpe (self-hollow, no drop)", "drop written ->", "packed self removed after child ok", "excl: phase begin (UAC may appear)"; decompilation confirms it decrypts the built-in PE with AES-256-GCM through bcrypt.dll and validates the MZ header. Version resources masquerade as sihost.exe/Desktop Window Manager. Taken together, it is a malicious delivery loader (loader/dropper).

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **Rust LoadPE Dropper (pe_stub)** · Aliases loadpe, pe_stub, bundle_deploy · _unconfirmed_ |
| Confidence | **low** |
| Behavior class | loader · dropper · injector |
| Difficulty | medium |
| First seen | 2026-11-23 16:33:43 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/219c48815fd9fb9091255d4f97d8070cffcd74900ebfd6648c00512a5731cda1/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Self-hollow and map PE</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Drop and launch child process</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Clean up dropped traces</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1070.004</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">No child process at runtime</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `219c48815fd9fb9091255d4f97d8070cffcd74900ebfd6648c00512a5731cda1` |
| MD5 | _Not recorded_ |
| Size | 11,237,648 bytes (10.7 MB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **10** behaviors in total, each backed by evidence; **8** are statically available and **2** were obtained through dynamic analysis.

### 1. Decrypt the embedded payload

`T1140` · Confidence **high** · Static

It dynamically resolves the BCrypt* interfaces via LoadLibraryA("bcrypt.dll")+GetProcAddress, sets up AES-256-GCM with BCryptOpenAlgorithmProvider("AES") and ChainingModeGCM (32-byte key, 12-byte nonce, 16-byte tag), takes the parameters from the EXPL structure at the payload tail and decrypts, then checks whether the first two bytes of the result are MZ.

> **Evidence**: decompilation at 0x140002714: BCryptGenerateSymmetricKey(...,0x20) + pbNonce/cbNonce=0xc + cbAuthData=0x10; 0x140002d8c validates the tail 0x4C505845("EXPL") and versions 1/2/3
> 
> **Source**: `ev-000017` · `ev-000018`

### 2. Self-hollow and map the PE

`T1620` · Confidence **high** · Static

The loader retains a "loadpe (self-hollow, no drop)" path: after resolving NtQueryInformationProcess/NtUnmapViewOfSection it unmaps the image in its own process and remaps the decrypted PE, and tries to handle CFG validation with RtlAddFunctionTable/SetProcessValidCallTargets, avoiding calls to LoadLibrary.

> **Evidence**: 0x1400061ba/0x1400061e3 reference NtQueryInformationProcess, NtUnmapViewOfSection; strings "loadpe (self-hollow, no drop)" "loadpe ok (child survived alive window)"; kernel32!SetProcessValidCallTargets string
> 
> **Source**: `ev-000011` · `ev-000013`

### 3. Drop to disk and launch a child process

`T1106` · Confidence **high** · Static

When self-mapping fails it falls back to disk dropping: writes the decrypted PE to %LOCALAPPDATA%\LocalApp_<random suffix>\Application.exe (and tries directories such as ProgramData\dll|sys), then launches it with CreateProcessW or ShellExecuteExW, logging "drop written -> …" and "child launched, drop kept @ …".

> **Evidence**: import table CreateProcessW @iat 0x34040, ShellExecuteExW @iat 0x34080; strings "disk drop -> " "spawn: staged " "Application.exe" "LOCALAPPDATA" "LocalApp_"
> 
> **Source**: `ref:1067b91fbe` · `ev-000011`

### 4. Clean up dropped traces

`T1070.004` · Confidence **high** · Static

Before launch it deletes old dropped files with DeleteFileW, removes its own packed file after the child starts successfully ("packed self removed after child ok"), and decides by PE_STUB_KEEP_MOTW whether to handle Zone.Identifier (Mark-of-the-Web).

> **Evidence**: DeleteFileW(local_d0) call in the decompilation at 0x140005223; strings "packed self removed after child ok" ":Zone.Identifier" "PE_STUB_KEEP_MOTW"
> 
> **Source**: `ev-000013` · `ev-000011`

### 5. Masquerade as a system component

`T1036.005` · Confidence **high** · Static

Version resources masquerade as Windows components: CompanyName=MS Windows Platform, ProductName=Desktop Window Manager, InternalName=sihost, OriginalFilename=sihost.exe, FileDescription=Windows Runtime Library; there is also the builder's default "Local Application (4f6595c8)" string table.

> **Evidence**: RT_VERSION resource StringTable: OriginalFilename=sihost.exe / ProductName=Desktop Window Manager; GUI subsystem, no window logic
> 
> **Source**: `ref:b40a1fd8c9` · `ev-000011`

### 6. Probe the target runtime

`T1082` · Confidence **high** · Static

Before choosing a path it probes the host environment: strings cover mscoree.dll/clr.dll/hostfxr.dll (.NET), Qt5/Qt6/qwindows.dll, Microsoft.UI.Xaml/WindowsAppRuntime/WinUI, libssl, AyuGram, and directory names such as RUNTIMES\WIN-X64\NATIVE, used to decide between in-proc mapping and disk launch ("skip inproc -> disk (GUI/TLS/WinUI)").

> **Evidence**: string table from 0x35ed0: mscoree.dll clr.dll hostfxr.dll … Qt5 Qt6 qwindows.dll libssl AyuGram; 0x349c8 WindowsAppRuntime/MddBootstrap
> 
> **Source**: `ev-000011` · `ev-000016`

### 7. UAC elevation attempt

`T1548.002` · Confidence **medium** · Static

The drop stage logs "excl: phase begin (UAC may appear)" and "excl: UAC/prime begin", and attempts to launch the dropped file with elevated privileges through ShellExecuteExW (runas semantics), retrying other directories on failure.

> **Evidence**: strings "excl: phase begin (UAC may appear)" "excl: UAC/prime begin/end" "excl launch dir ->"; ShellExecuteExW import @iat 0x34080
> 
> **Source**: `ev-000011`

### 8. Resolve sensitive APIs at runtime

`T1027` · Confidence **high** · Static

Beyond the import table, key capabilities (BCrypt encryption and decryption, NtQueryInformationProcess/NtUnmapViewOfSection) are resolved at runtime through LoadLibraryA/GetProcAddress, reducing the readability of the import surface.

> **Evidence**: 0x140002744 LoadLibraryA("bcrypt.dll") + GetProcAddress chain; 0x1400061e3 references the NtUnmapViewOfSection string
> 
> **Source**: `ev-000017` · `ref:1067b91fbe`

### 9. No child process spawned at runtime

`T1106` · Confidence **high** · Dynamic

Dropped and executed in an isolated Windows environment for 150 seconds, only the sample's own process was observed (a single candidate PID); no descendant processes, dropped files or child-process chains appeared, and memory scanning found no injection, image replacement or PE header modification, indicating the self-mapping/disk-execution chain did not complete in this run.

> **Evidence**: dynamic timeline: candidate_count=1, dumped_pids empty, hollows count=0; memory scan Total suspicious=0; ETW recorded only the sample's own creation
> 
> **Source**: `ref:95a75ad258` · `ref:bbd81fe68a` · `ref:a0222a8462`

### 10. No network egress or persistence at runtime

`T1071` · Confidence **high** · Dynamic

Network monitoring recorded no DNS/HTTP session from the sample process during the observation window (only update and certificate traffic from system processes), and telemetry comparison showed no changes to Run startup entries, services or Defender exclusions; no C2 communication or persistence writes were observed.

> **Evidence**: network monitoring log contains only system processes such as svchost/monitoring component/EdgeUpdate; telemetry Run keys and services identical before and after; no connection records for the sample PID
> 
> **Source**: `ref:f0512169a5` · `ref:991d0702de` · `ref:b578fad4ba`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis Method and Limitations" at the end for the reason).
:::

### Host

**Drop paths**

- `%LOCALAPPDATA%\LocalApp_<random suffix>\Application.exe`
- `%TEMP%\pe_stub_spawn.log`
- `%TEMP%\pe_stub_fail.log`
- `%PROGRAMDATA%\dll`
- `%PROGRAMDATA%\sys`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `encryption_algo` | `AES-256-GCM (BCryptOpenAlgorithmProvider("AES")+ChainingModeGCM, 32-byte key, 12-byte nonce, 16-byte tag)` | Yes | Static |
| `payload_container_format` | `EXPL footer at the tail: version 1/2/3 correspond to 0x4c/0x70/0x78-byte fixed-size structures containing key/nonce/authdata/plaintext length` | Yes | Static |
| `env_flag` | `PE_STUB_KEEP_MOTW (environment variable switch controlling whether dropped files keep Zone.Identifier)` | No | Static |
| `drop_filename` | `Application.exe` | No | Static |
| `log_files` | `pe_stub_spawn.log / pe_stub_fail.log (PE_STUB_SPAWN_LOG)` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not assert that the sample has successfully implanted or already dropped and executed a payload: in the dynamic window there was no child process, no dropped file, and no injection trace in the memory scan.
- Do not classify it as ransomware merely because AES-GCM decryption and the words "encrypt/entropy_codec" appear: there is no behavioral evidence of traversing or encrypting user files.
- Do not attribute the embedded payload to a specific malware family (such as Amadey, StealC, etc.): the payload was not obtained, and no YARA/multi-engine/config strings support it.
- Do not treat the "_falsetrue{" fragment hit by the string scan as a flag or configuration: it sits in the Rust demangle string table and is compiler/runtime noise.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The embedded payload could not be decrypted: resource #6258 is 524288 bytes of high-entropy ciphertext plus about 1 MB of repeated manifest text padding, and no EXPL footer exists at the tail, so the AES key/nonce could not be obtained and stage2 was not extracted.
2. Within the dynamic observation window the sample did not drop, inject or communicate externally, and no API-level call sequence was obtained; only Speakeasy emulation was available and it stopped at CRT initialization, so it is impossible to judge from this whether decryption ever executed.
3. No C2 address, URL or configuration string was found, and the c2 field is empty; it cannot be ruled out that the payload contains network capability but was not decrypted.
4. Family attribution is only a behavioral name (pe_stub/loadpe), lacking vendor naming and multi-engine data; confidence is low and uncertain=true.
5. Paths in host_iocs come from string templates and a directory word list (LocalApp_, Application.exe, pe_stub_*.log, ProgramData\dll|sys); their actual creation was not observed in this run.

## Evidence Index

<details>
<summary>Expand 17 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1 and file size 11237648 |
| `ev-000002` | scan.imphash | imphash=ed8e3ce678659cdefbf4193bc755be3f |
| `ev-000003` | scan.rich | Rich header, 10 MSVC toolchain records |
| `ev-000004` | scan.entropy | .text entropy 6.374 (not packed) |
| `ev-000011` | String extraction | 360728 ASCII strings extracted, including loadpe/bundle_deploy/EXPL-related templates and flag noise hits |
| `ev-000012` | Cryptographic constant identification | standard base64 alphabet constant @0x340e6 |
| `ev-000013` | decompile.ghidra | main(FUN_140005223) decompilation: logging, DeleteFileW cleanup and payload handling calls |
| `ev-000017` | decompile.ghidra | FUN_140002714: BCrypt AES-GCM decryption wrapper (32-byte key, 12-byte nonce, 16-byte tag) |
| `ev-000018` | decompile.ghidra | FUN_140002d8c: parses the tail EXPL version 1/2/3 structure and validates MZ |
| `ref:1067b91fbe` | Import table parsing | Import surface: resource dropping, process hollowing, CreateProcessW/ShellExecuteExW, registry and file operations |
| `ref:b40a1fd8c9` | pe.resources | Resource enumeration and version information (sihost.exe masquerade, Local Application) |
| `ref:95a75ad258` | Dynamic analysis platform | Real detonation timeline in the isolated environment: 1 candidate process, no child processes |
| `ref:bbd81fe68a` | Dynamic analysis platform | Memory scan summary: Total suspicious=0, hollows 0 |
| `ref:f0512169a5` | Dynamic analysis platform | Network monitoring log: no sample process sessions |
| `ref:991d0702de` | Dynamic analysis platform | Telemetry before/after comparison: no changes to Run keys/services/Defender exclusions |
| `telemetry:219c4881` | Dynamic telemetry | Dynamic telemetry recorded: 109 process/file events from the monitoring component; 1 ETW short-lived process event; 22 tool/system noise events filtered |
| `etw:219c4881:3920` | Process event monitoring | Short-lived process event: 219c48815fd9fb9091255d4f97d8070cffcd74900ebfd6648c00512a5731cda1.exe (pid 3920; MD5=0B71302466DD23D7F1F9E7458A5D9A82,SHA256=219C48815FD9FB9091255D4F97D8070CFFCD74900EBFD6648C00512A5731CDA1,IMPHASH=ED8E3CE678659CDEFBF4193BC755BE3F) |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
