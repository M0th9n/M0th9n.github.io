---
title: "Malicious sample analysis: PcyybSDK Side-Loader (other · iso · 01154a77)"
published: 2026-11-25
draft: false
description: "Malicious (confidence: medium): PcyybSDK Side-Loader · loader · difficulty hard · pure static analysis"
tags: ["PcyybSDK Side", "loader"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-25-PcyybSDK-Side-Loader-01154a77"
---

> [!WARNING]
> **Verdict: malicious** · Family **PcyybSDK Side-Loader** (doubtful) · Confidence **medium**
> 
> Aliases: pcyyb_sdk_dll.dll sideloader, Androws SDK DLL side-loader, Tencent YYB SDK impersonation loader
> 
> The ISO contains an Androws extension host EXE validly signed by Tencent, plus a pcyyb_sdk_dll.dll of the same name that is statically referenced by the host's import table. The DLL's .text/.rdata/.data sections carry no raw data; the roughly 4 MB payload is concentrated in a high-entropy .TEXT2 (entropy 7.98), the entry point and TLS directory lie inside the encrypted section, and the entry bootstrap then jumps into a loader containing direct syscalls; its version information reads Setup 2.6.9[.]1 / Company .T., the signing subject is self-signed CN=BenchByte AI, while the host EXE's Tencent signature digest verifies. A legitimate Tencent host plus a packed same-name DLL not signed by Tencent forms a clear DLL side-loading execution chain, so it is judged a malicious loader; the encrypted payload was not decrypted, and the family cannot yet be mapped to an existing naming.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **PcyybSDK Side-Loader** · Aliases pcyyb_sdk_dll.dll sideloader, Androws SDK DLL side-loader, Tencent YYB SDK impersonation loader · _doubtful_ |
| Confidence | **medium** |
| Behavior class | loader |
| Difficulty | hard |
| First seen | 2026-11-25 11:51:14 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/01154a7727e5ca63054637cf0145aedd60be752288a2af7006bac5a9a8487456/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Side-load Tencent-signed host</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Impersonate Tencent SDK metadata</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Packed 4 MB encrypted payload</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Entry hidden in encrypted section</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Direct syscalls</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `01154a7727e5ca63054637cf0145aedd60be752288a2af7006bac5a9a8487456` |
| MD5 | _Not recorded_ |
| Size | 6,813,696 bytes (6.5 MB) |
| Type | other · `iso` |

## Behavior Analysis

There are **7** behaviors in total, each backed by evidence, and all are statically available.

### 1. Side-load Tencent-signed host

`T1574.002` · Confidence **high** · Static

The ISO places both the Tencent-validly-signed Androws extension EXE and a same-name pcyyb_sdk_dll.dll; the host import table statically references 34 functions of this DLL, and at startup it loads the replaced DLL from its own directory first, forming a DLL side-loading execution chain.

> **Evidence**: host EXE import table pcyyb_sdk_dll.dll 34 entries (IAT rva from 0xBD4E0); the ISO root contains both the EXE and PCYYB_SDK_DLL.DLL
> 
> **Source**: `ref:b17614d318` · `ref:732ac153bb`

### 2. Impersonate Tencent SDK metadata

`T1036.005` · Confidence **high** · Static

The side-loaded DLL exports 129 SDK interfaces of pcyyb_sdk_dll.dll (LaunchApp, UpdateEngine, ReportDomainSnifferResult, etc.), but its version information reads Setup / 2.6.9[.]1 / Company .T. / Copyright 2026, inconsistent with the claimed Tencent SDK identity; this is name and metadata disguise.

> **Evidence**: export table 129 pcyyb APIs; VS_VERSION_INFO FileDescription=Setup, FileVersion=2.6.9[.]1, CompanyName=.T.
> 
> **Source**: `ref:497453e82b` · `ref:8c2d4c82a9`

### 3. Packed 4 MB encrypted payload

`T1027.002` · Confidence **high** · Static

The RawPtr/RawSize of sections such as .text/.rdata/.data/.pdata are all 0; the effective content is concentrated in .TEXT2 (file offset 0x1200, RawSize 0x3DBC00, about 4 MB) with section entropy 7.98, matching a packed/encrypted payload layout.

> **Evidence**: .TEXT2 VA 0x42E000 RawPtr 0x1200 RawSz 0x3DBC00 entropy 7.98; the other code/data sections RawSz=0
> 
> **Source**: `ref:174649b7ba` · `ref:375efddfb9`

### 4. Entry hidden in encrypted section

`T1620` · Confidence **medium** · Static

Both the PE entry 0x6B231B and the TLS directory 0x6B3530 fall inside the high-entropy .TEXT2; the entry is a push rbp / pushfq / movabs / call bootstrap sequence that jumps to 0x1807BFD6D, indicating control transfers only after decryption or mapping — not normal compiler output.

> **Evidence**: AddressOfEntryPoint=0x6B231B; TLS=0x6B3530; 0x6B231B: push rbp; pushfq; movabs rbp,0x8C90B9B7BB1F399A; call 0x1807BFD6D
> 
> **Source**: `ref:39b6acc40c` · `ref:50e2e97b14`

### 5. Direct system calls

`T1106` · Confidence **medium** · Static

The bootstrap path executes 0F 05 (syscall) near 0x1807BFD6D along with pushfq/popfq and rsp realignment, entering kernel calls directly instead of going through normal Win32 APIs — a loader trait for evading user-mode hooks.

> **Evidence**: 0x1807BFD6D: shr bp,0x1B; lea rbp,[...]; push [rsp+8]; popfq; lea rsp,[rsp+0x10]; call 0x1807F0961; syscall
> 
> **Source**: `ref:c75ce883b9`

### 6. Self-signed spoofed publisher

`T1553.002` · Confidence **high** · Static

The DLL's Authenticode digest matches its signed content (sha256 A6A4CDD5…), but the signing subject is a self-signed certificate CN=BenchByte AI (with a 2026-11-25 timestamp), not Tencent; the same-package host EXE's Tencent signature digest (9F0FAFBB…) verifies, so the signature mismatch is concentrated in the replaced DLL.

> **Evidence**: DLL SpcIndirectData sha256=A6A4CDD5CE9578AD…, cert subject CN=BenchByte AI; EXE SpcIndirectData sha256=9F0FAFBB7E70B797…, subject=Tencent Technology (Shenzhen) Company Limited
> 
> **Source**: `ref:6ae9aeb92f` · `ref:df493cb918` · `ref:be19566be3`

### 7. Host persistence and install resume

`T1547.001` · Confidence **medium** · Static

The host EXE strings include a RunOnce key, the TencentInstallState/TencentInstallResume values, and the resume-install URL ms-windows-store://DownloadsAndUpdates?resumeInstall=true, and create the Local\SM0:… mutex and access SOFTWARE\Tencent\Androws; these are the Tencent host's install-recovery logic, and no persistence belonging to the encrypted payload itself was found.

> **Evidence**: UTF-16 strings: SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce, TencentInstallState, TencentInstallResume, rundll32 url,OpenURL ms-windows-store://…; Local\SM0:%lu:%lu:%hs
> 
> **Source**: `ref:79ad280e3f` · `ref:7c01c42ab2`


## IOCs (defanged)

### Network

:::note
**No C2 / network IOCs were recovered** (see "Analysis Method and Limitations" at the end for the reason).
:::

### Host

**Mutex**

- `Local\SM0:%lu:%lu:%hs`

**Drop paths**

- `pcyyb_sdk_dll.dll (side-loaded from the same directory as the host EXE)`

**Registry**

- `SOFTWARE\Tencent\Androws (host component; root key not resolved statically)`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce (host install resume; root key not resolved statically)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `loader_technique` | `DLL side-loading: a legitimate Tencent Androws EXE loads the replaced pcyyb_sdk_dll.dll from its own directory` | Yes | Static |
| `imitated_module` | `pcyyb_sdk_dll.dll (Tencent PC Yingyongbao / Androws SDK)` | Yes | Static |
| `payload_section` | `.TEXT2, RawSize 0x3DBC00 (about 4 MB), entropy 7.98` | Yes | Static |
| `payload_encrypted` | `true (high entropy, not decrypted)` | Yes | Static |
| `entry_point` | `0x6B231B (inside the encrypted .TEXT2 region)` | Yes | Static |
| `packer` | `unknown custom PE loader (direct-syscall bootstrap code)` | No | Static |
| `encryption_algo` | `not recovered` | No | Static |
| `publisher_dll` | `CN=BenchByte AI (self-signed)` | No | Static |
| `publisher_host` | `Tencent Technology (Shenzhen) Company Limited (Authenticode digest verifies)` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not judge the whole ISO legitimate just from the package EXE's valid Tencent signature: the signature covers only the host EXE, and the same-name DLL's signing subject is self-signed BenchByte AI.
- Do not treat yybadaccess.3g[.]qq[.]com / yybadaccess[.]sparta[.]html5[.]qq[.]com as malicious C2: they are Tencent access/telemetry domains of the host component, the encrypted payload has not been decrypted, and there is no evidence of malicious callback.
- Do not attribute this DLL to a specific family such as ValleyRAT or AsyncRAT: the 4 MB encrypted payload was not decrypted and cannot be compared with existing families.
- Do not claim that real network communication, registry writes, or persistence were observed: this is pure static analysis, and the sample was not executed.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. Pure static analysis with no isolated dynamic execution channel; no network, registry, or process behavior was observed at runtime.
2. The roughly 4 MB .TEXT2 encrypted payload was not memory-decrypted/unpacked, so the payload's C2, config, or family traits were not obtained.
3. The side-loaded DLL's signing subject is self-signed CN=BenchByte AI (2026-11-25 timestamp), and its real identity and issuance origin cannot be verified offline.
4. The Tencent domains, RunOnce, and registry strings inside the host EXE belong to install/telemetry logic and have not been shown to be abusable by the payload for persistence or callback.
5. No online cross-validation with vendor intelligence or public sandbox reports was performed; the family judgment rests only on local static evidence.

## Evidence Index

<details>
<summary>Expand 15 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:ee5c817bc6` | Sample triage | Host EXE triage: no packing signal, 7 imported DLLs/184 symbols, SHA256 52c199ff… |
| `ref:b17614d318` | Import table parsing | Host EXE imports 34 SDK functions of pcyyb_sdk_dll.dll |
| `ref:7c01c42ab2` | pe.version | Host version information: Company=Tencent, Product/InternalName=Androws, FileVersion=1.1001.86.0 |
| `ref:732ac153bb` | iso.extract | ISO9660 file listing with per-file SHA256: the EXE, PCYYB_SDK_DLL.DLL, and VC runtime libraries |
| `ref:497453e82b` | PE structure parsing | DLL section table/version/imports/129 exports: Company=.T., FileDescription=Setup, Version=2.6.9[.]1 |
| `ref:174649b7ba` | PE structure parsing | DLL raw section layout: code/data sections RawSz=0, .TEXT2 RawSz=0x3DBC00, entropy 7.98 |
| `ref:375efddfb9` | unpack.detect | DLL judged packed; signal: executable section .TEXT2 high entropy 7.98 |
| `ref:39b6acc40c` | PE structure parsing | DLL entry 0x6B231B, TLS 0x6B3530, ImageBase 0x180000000 |
| `ref:50e2e97b14` | disasm.function | Entry 0x6B231B bootstrap sequence: push rbp/pushfq/movabs/call 0x1807BFD6D |
| `ref:c75ce883b9` | disasm.function | The loader path at 0x1807BFD6D contains syscall (0F 05) and stack realignment |
| `ref:6ae9aeb92f` | cert.parse | Certificate subjects: EXE=Tencent Technology (Shenzhen); DLL=CN=BenchByte AI (self-signed) |
| `ref:df493cb918` | cert.parse | DLL SpcIndirectData sha256=A6A4CDD5…, matches the file's Authenticode digest |
| `ref:be19566be3` | cert.parse | EXE Authenticode sha256=9F0FAFBB…, matches the signed-content digest, Tencent signature valid |
| `ref:79ad280e3f` | String extraction | Host UTF-16 strings: Tencent access domains, SOFTWARE\Tencent\Androws, RunOnce, mutex template |
| `ref:8c2d4c82a9` | String extraction | DLL export/import and string surface: 129 pcyyb SDK names, BeaconClient export, certificate subject |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
