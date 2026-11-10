---
title: "Malware Analysis: Unattributed Themida-packed fake installer (other · iso · ca8e5a8d)"
published: 2026-11-09
draft: false
description: "Malicious (low confidence): Unattributed Themida-packed fake installer · dropper/loader · difficulty hard · Static decompilation (dynamic execution yielded no runtime behavior)"
tags: ["dropper", "loader"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-09-Unattributed-Themida-packed-fake-installer-ca8e5a8d"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Unattributed Themida-packed fake installer** (uncertain) · Confidence **low**
> 
> Aliases: S8035FGRD_SW02CMIP_EDCIP, Blur Interactive fake installer
> 
> The ISO9660 image is a delivery container whose README explicitly tells the victim to bypass the Windows SmartScreen warning. The only executable it carries is an unsigned 64-bit GUI program that requests administrator rights, is protected by Themida (.themida W^X section, 7.96-entropy .boot, a single import), carries forged publisher/version metadata and a 2088 compile timestamp, and contains rdtsc timing checks, int 2Dh and cpuid probes. Emulation shows the stub resolving user32/advapi32/ntdll/shell32/shlwapi at runtime. This combination is consistent with a packed fake-installer malware loader and not with a legitimate product.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unattributed Themida-packed fake installer** · aliases S8035FGRD_SW02CMIP_EDCIP, Blur Interactive fake installer · _uncertain_ |
| Confidence | **low** |
| Behavior class | dropper · loader |
| Difficulty | hard |
| First seen | 2026-11-07 19:10:08 |
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ca8e5a8d645c1084d2eee77e146589cc6a28cb9616106f177b167630c444c97b/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">ISO container bypasses MOTW</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Lure user into allowing installer</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Request administrator rights</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1548</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Packer hides program logic</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Entry bytes self-decrypt</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `ca8e5a8d645c1084d2eee77e146589cc6a28cb9616106f177b167630c444c97b` |
| MD5 | _not recorded_ |
| Size | 15,357,952 bytes (14.6 MB) |
| Type | other · `iso` |

## Behavior analysis

**9** behaviors in total, each backed by evidence, and all are statically available.

### 1. ISO container bypasses MOTW

`T1553.005` · Confidence **high** · static

The sample is an ISO9660 image; mounting it exposes INSTALL0;1 and README_1;1. Files opened from a mounted image do not carry Mark-of-the-Web, so attachment/SmartScreen warnings are suppressed.

> **Evidence**: ISO9660 root: INSTALL0;1 LBA 25, 15,303,168 bytes; README_1;1 LBA 7498, 762 bytes
> 
> **Source**: `ev-000009` · `ref:5a77ef5718`

### 2. Lure user into allowing installer

`T1204.002` · Confidence **high** · static

README_1;1 tells the user that a SmartScreen warning is expected and instructs clicking 'More Info' then 'Run Anyway', asserting the unsigned installer is safe because the authors are a small non-profit team.

> **Evidence**: README_1;1 text: 'click on "More Info", then "Run Anyway"'
> 
> **Source**: `ev-000009`

### 3. Request administrator rights

`T1548` · Confidence **high** · static

The embedded application manifest sets requestedExecutionLevel to requireAdministrator, so the packed payload runs elevated after user consent.

> **Evidence**: Manifest resource type 24 id 1: requestedExecutionLevel level="requireAdministrator"
> 
> **Source**: `ev-000010` · `ref:b942c4fa41`

### 4. Packer hides program logic

`T1027.002` · Confidence **high** · static

The executable contains a writable+executable .themida section and a 7.96-entropy .boot section holding the entry point; the import table exposes only GetModuleHandleA, so original code and strings are hidden.

> **Evidence**: .themida characteristics 0xE0000080 (RWX), .boot entropy 7.964 at RVA 0x11B8000, imports: kernel32!GetModuleHandleA only
> 
> **Source**: `ref:8de7d54bba` · `ref:8a582ea1ea` · `ref:6ce0a3570f` · `ref:32d9477fcc` · `ref:b942c4fa41`

### 5. Entry bytes self-decrypt

`T1140` · Confidence **high** · static

The entry stub in .boot runs a byte-wise decode loop (mov al,[rsi]; inc rsi; mov [rdi],al; add dl,dl; jne/jae) before transferring control, consistent with a self-decrypting packer stub.

> **Evidence**: RVA 0x11B806F-0x11B80F6 entry decode loop; entry VA 0x15B8058
> 
> **Source**: `ref:860f2fe816`

### 6. Resolves APIs at runtime

`T1027.007` · Confidence **high** · static

During user-mode emulation the stub calls LoadLibraryA for user32.dll, advapi32.dll, ntdll.dll, shell32.dll and shlwapi.dll and GetProcAddress for SetLastError/GetLastError, resolving APIs at runtime instead of through the import table.

> **Evidence**: Emulation API trace: LoadLibraryA(user32.dll/advapi32.dll/ntdll.dll/shell32.dll/shlwapi.dll), GetProcAddress(SetLastError/GetLastError) at PC 0x13F59C1-0x13EDE50
> 
> **Source**: `ref:425ebe4b03` · `ref:05e4e95312`

### 7. Anti-debug timing checks

`T1622` · Confidence **high** · static

The image contains rdtsc-based timing checks and int 2Dh instructions in both the unnamed code section and the .boot section, used to detect debuggers/single-stepping.

> **Evidence**: unpack.antidebug: rdtsc at RVA 0x32CFD and 0x11EB43B; int 2Dh at RVA 0x4C8EB and 0x11D24B6
> 
> **Source**: `ref:acc8a9c0a2`

### 8. Probes virtualization environment

`T1497.001` · Confidence **high** · static

cpuid instructions at fixed code locations are used for VM/debugger fingerprinting before the payload executes.

> **Evidence**: cpuid at RVA 0x1DC51 (unnamed code section) and 0x11BC5E2 (.boot)
> 
> **Source**: `ref:acc8a9c0a2`

### 9. Forges vendor version information

`T1036.005` · Confidence **high** · static

The version resource impersonates a product identity ('Blur Interactive'/'BlurSoftworks', OriginalFilename S8035FGRD_SW02CMIP_EDCIP.exe, Copyright 2026) with an empty ProductName, a future compile timestamp and no Authenticode signature.

> **Evidence**: VS_VERSIONINFO strings; PE timestamp 0xDF4BF6AA; Security data directory RVA/size = 0
> 
> **Source**: `ev-000010` · `ref:11e093f984` · `ref:b942c4fa41`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis method and limitations" at the end for the reason).
:::

### Host

- **No host IOC was recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `container` | `ISO9660 volume 'S8035FGRD_SW02CMIP_EDCIP_Secure' containing INSTALL0;1 (PE64, 15,303,168 bytes) and README_1;1 (762 bytes)` | yes | static |
| `install_privilege` | `requireAdministrator (embedded manifest)` | yes | static |
| `packer` | `Themida (.themida W^X section, .boot entry section, single import GetModuleHandleA)` | no | static |
| `original_filename` | `S8035FGRD_SW02CMIP_EDCIP.exe` | yes | static |
| `publisher_identity` | `CompanyName 'Blur Interactive', LegalTrademarks 'BlurSoftworks', ProductName empty` | no | static |
| `compile_timestamp` | `0xDF4BF6AA (decodes to 2088-09-13, forged/future)` | no | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not name a specific malware family (e.g. Lumma, StealC, Vidar) or claim credential/data theft: no config, stealer strings, C2 or second stage was recovered.
- Do not claim any C2 host, URL or port: the .boot payload is encrypted and no plaintext network indicator is visible.
- Do not treat the TEA/XTEA delta constant at file offset 0xA0FBD3 as proof of payload config encryption; it lies inside the packed region and may belong to the protector runtime.
- Do not call the installer benign despite the README's assertion that it is unsigned only because the authors are a non-profit team.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Unpacking | No |

**Limitations and pending verification**

1. Themida OEP was not reached: automatic unpacking exceeded the 500,001-instruction budget and user-mode emulation stopped after 8 API calls inside the protector VM, so the payload body and its strings remain encrypted.
2. No C2, mutex, install path, registry key, service or campaign ID was recovered; those fields are intentionally empty rather than guessed.
3. No live sandbox detonation was performed (static-only tier). The verdict rests on the container delivery, identity/signature forgery, packer and anti-analysis code, not on observed exfiltration.
4. Family attribution is uncertain; no vendor engine or YARA match was available in this environment.
5. Emulation covered only the protector/bootstrap stage; no payload-level API behavior (file, registry, network) was observed.

## Evidence index

<details>
<summary>Expand 14 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000009` | evidence.record | ISO9660/Joliet parsing: volume label, two files (INSTALL0;1, README_1;1), README SmartScreen-bypass text |
| `ev-000010` | evidence.record | PE resource parsing: version info, requireAdministrator manifest, icon, forged timestamp, no signature |
| `ev-000005` | string extraction | ISO string extraction: file names INSTALL0;1 / README_1;1, DOS stub, .themida/.idata section names |
| `ev-000006` | cryptographic constant identification | TEA/XTEA delta 0x9E3779B9 at offset 0xA0FBD3 (inside packed .boot region) |
| `ref:b942c4fa41` | PE structure parsing | PE64 headers: 6 sections, entry 0x11B8058 in .boot, security directory 0, timestamp 3745914922 |
| `ref:8de7d54bba` | unpack.detect | Themida detection, confidence 0.9; emulate_to_oep strategy |
| `ref:8a582ea1ea` | section table parsing | Section table and entropy: .themida RWX, .boot 7.964 |
| `ref:6ce0a3570f` | scan.entropy | Whole-file entropy 7.993; three high-entropy sections |
| `ref:32d9477fcc` | import table parsing | Single import kernel32!GetModuleHandleA, imphash a56f115ee5ef2625bd949acaeec66b76 |
| `ref:11e093f984` | hashing & fingerprints | MD5 8c6464501df15e894ea8d98feb9c9f39, SHA-256 627dc3ef0c80bac796aa8256847b0d6922c4eab38809da577e9d4ba554243260 |
| `ref:acc8a9c0a2` | unpack.antidebug | rdtsc, int 2Dh and cpuid probes at concrete RVAs in code and .boot |
| `ref:860f2fe816` | disasm.function | Entry stub byte-wise decode loop at RVA 0x11B806F |
| `ref:425ebe4b03` | dyn.run | Emulation API trace: LoadLibraryA/GetProcAddress runtime resolution |
| `ref:4f1f2c4ce0` | unpack.auto | Automatic unpacking failed at instruction budget; no OEP found |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
