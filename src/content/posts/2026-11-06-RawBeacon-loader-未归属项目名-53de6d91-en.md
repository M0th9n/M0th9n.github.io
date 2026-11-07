---
title: "Malware Analysis: RawBeacon loader (unattributed) (PE · dll · 53de6d91)"
published: 2026-11-06
draft: false
description: "Malicious (medium confidence): RawBeacon loader (unattributed) · loader · difficulty hard · static decompilation (DLL not loaded by host)"
tags: ["RawBeacon", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-06-RawBeacon-loader-未归属项目名-53de6d91"
---

> [!WARNING]
> **Verdict: Malicious** · Family **RawBeacon loader (unattributed project name)** (uncertain) · Confidence **medium**
> 
> Aliases: rawbeacon.dll, goopdate.dll masquerade component, RunPayload loader
> 
> Decompiling the outer export DllEntry reveals a complete manual mapper: it allocates image space with VirtualAlloc(0x6a180000,0x6f000), copies the embedded PE section by section, fixes relocations, resolves imports via LoadLibraryA/GetProcAddress from the import table and then calls the inner entry point, and uses lstrcmpA to find the export name RunPayload and call it directly; the inner RunPayload then executes a position-independent payload with VirtualAlloc(RWX,0x63a2e)+memcpy+FlushInstructionCache. This chain is a typical reflective loader (covert execution of embedded code) and does not match the behavior of a normal update component.

## Overview

| Item | Content |
|:--|:--|
| Family | **RawBeacon loader (unattributed project name)** · aliases rawbeacon.dll, goopdate.dll masquerade component, RunPayload loader · _uncertain_ |
| Confidence | **medium** |
| Behavior class | loader |
| Difficulty | hard |
| First seen | 2026-11-05 10:21:15 |
| Analysis method | Static decompilation (DLL not loaded by host; dynamic did not take effect) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/53de6d9138476ce0d55fa6a1449d16189478f81f7cd2983580af0e8c8b247a1a/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Masquerade as Google updater</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Manual-map embedded DLL</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Call payload by export name</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Execute fileless payload</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Embedded PIC loader</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `53de6d9138476ce0d55fa6a1449d16189478f81f7cd2983580af0e8c8b247a1a` |
| MD5 | _not recorded_ |
| Size | 447,960 bytes (437.5 KB) |
| Type | PE · `dll` |

## Behavior analysis

**8** behaviors in total, each backed by evidence, and all are statically recoverable.

### 1. Masquerade as Google update component

`T1036.005` · Confidence **high** · static

The outer DLL's export table uses DLL name goopdate.dll and exports only DllEntry, impersonating the name of a Google Update component to evade name-based detection.

> **Evidence**: PE export table dll_name=goopdate.dll, export DllEntry RVA 0x1610
> 
> **Source**: `ref:61d32f12b6`

### 2. Manual-map embedded DLL

`T1620` · Confidence **high** · static

DllEntry allocates 0x6f000 bytes at the fixed address 0x6a180000, copies the first 0x400 bytes of the embedded image and each section's data, fixes relocations as IMAGE_REL_BASED_HIGHLOW, walks the import table calling LoadLibraryA/GetProcAddress to fill the IAT, and then calls the inner image entry point.

> **Evidence**: 0x650c1610 VirtualAlloc(0x6a180000,0x6f000,0x3000,0x40) + per-section memcpy + relocation/import resolution
> 
> **Source**: `ref:7a2aba74bf`

### 3. Call payload by export name

`T1620` · Confidence **high** · static

After mapping, it uses lstrcmpA to match "RunPayload" in the export name table and calls the corresponding function address on a hit, chaining activation of the embedded component by name.

> **Evidence**: 0x650c1610 lstrcmpA(..., "RunPayload") then call [export address table]
> 
> **Source**: `ref:7a2aba74bf` · `ref:5a89550279`

### 4. Execute fileless payload

`T1055` · Confidence **high** · static

The inner export RunPayload calls VirtualAlloc(0,0x63a2e,PAGE_EXECUTE_READWRITE) to allocate read-write-execute memory, copies 408,110 bytes from the image .rdata (RVA 0x4044), calls FlushInstructionCache and then directly calls that buffer, so the payload never lands on disk as a file.

> **Evidence**: 0x6a1814f0 VirtualAlloc(0,0x63a2e,0x3000,0x40); memcpy(dst,0x6a184044,0x63a2e); FlushInstructionCache; call dst
> 
> **Source**: `ref:76e6328e85`

### 5. Embedded position-independent loader

`T1027` · Confidence **medium** · static

Starting at .rdata RVA 0x4044 is a position-independent compiled code blob: its entry is a function with an 0x8C4-byte stack frame that calls memset/memcpy itself, reads PE header fields (e_lfanew/section table), allocates page memory and builds a mapping using 0x1000/0x10000 alignment parameters, and also contains a hash-resolution function that dispatches APIs by constant comparison, used to load subsequent payloads in memory.

> **Evidence**: inner RVA 0x4044: 55 8B EC 83 E4 F8 81 EC C4 08 00 00; the cmp edx,imm32 hash-dispatch sequence at 0x5EE0
> 
> **Source**: `ref:d352a70532`

### 6. Hidden encrypted payload container

`T1140` · Confidence **medium** · static

The inner .rdata at RVA 0x6146 holds 399,660 characters of base64 text, which decodes to a 299,744-byte container (version=1, a 0xC0-byte key/signature block, length 0x49210); the 299,536-byte body has entropy 7.98 and is an encrypted or compressed follow-on payload that cannot be directly recovered statically.

> **Evidence**: base64 @ file offset 0x5A26 (inner RVA 0x6146), decoded header 01000000C00000001092040010920400
> 
> **Source**: `ev-000019`

### 7. Carries an individual signing certificate

`T1553.002` · Confidence **high** · static

The outer DLL carries a structurally valid Authenticode signature: the root is Microsoft Identity Verification Root Certificate Authority 2020 and the leaf certificate subject is the individual ISABEL ALEJANDRA FLORES, used to increase trust at execution time and interfere with signature-reputation verdicts.

> **Evidence**: security directory file offset 0x69C00 size 0x39D8, PKCS#7 leaf certificate CN=ISABEL ALEJANDRA FLORES
> 
> **Source**: `ev-000020`

### 8. Backup decoy file paths

`T1204.002` · Confidence **low** · static

The outer .rdata also stores the UTF-16 strings cam_numbers_39d9b1.pdf, win.dll and the format string "%s%s", and imports GetTempPathW/CopyFileW/ShellExecuteExW/wsprintfW, a capability combination for building a temp-directory path, writing a decoy document and launching it.

> **Evidence**: outer .rdata off 0x1e60-0x1ed6 contains cam_numbers_39d9b1.pdf / win.dll / %s%s; imports GetTempPathW, CopyFileW, ShellExecuteExW
> 
> **Source**: `ref:6251094f9a` · `ref:54aca43490`


## IOC (defanged)

### Network

:::note
**No C2 / network IOCs were recovered** (see "Analysis method and limitations" at the end for why).
:::

### Host

**Dropped paths**

- `%TEMP%\win.dll`
- `%TEMP%\cam_numbers_39d9b1.pdf`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `embedded_payload_container` | `inner .rdata RVA 0x6146 holds 399,660 base64 characters → 299,744-byte container: version=1, 0xC0-byte key/signature block, two 0x00049210 length fields, 299,536-byte body from 0xD0 (entropy 7.98, encrypted/compressed)` | yes | static |
| `install_path` | `%TEMP%\win.dll` | no | static |
| `decoy_document` | `%TEMP%\cam_numbers_39d9b1.pdf` | no | static |
| `signer_subject` | `C=US, ST=in, L=East Chicago, O=ISABEL ALEJANDRA FLORES, CN=ISABEL ALEJANDRA FLORES (issuer: Microsoft ID Verified CS AOC CA 04)` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- No real outbound connection was observed, so do not claim a confirmed C2 domain/IP or communication protocol.
- Do not claim the sample actually writes the cam_numbers_*.pdf decoy and calls ShellExecuteExW — only strings and related imports were seen; no call chain or runtime evidence was obtained.
- Do not treat the goopdate.dll/Google Update name as a genuine component, and do not conclude from it that the sample is related to Google.
- The embedded 292KB payload was not decrypted, so do not claim its ultimate function is infostealing, RAT, ransomware or mining.
- Certificate revocation and timestamp status were not checked, so do not claim the signature is valid or revoked.
- No dynamically dropped files were observed, so do not claim persistence (service/scheduled task/registry).
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (DLL not loaded by host; dynamic did not take effect) |
| Unpacking | no |

**Limitations and pending verification**

1. The sample is a DLL with a non-standard entry export (DllEntry), was not loaded by a host after delivery, and the dynamic sandbox produced no new process and captured no sample-side DNS/TCP records, so there is no dynamic behavior evidence; reproduced=false.
2. The embedded 299,536-byte payload is high-entropy encrypted/compressed data, and the decryption algorithm and key are in position-independent code in .rdata and were not recovered; the follow-on capabilities (C2, persistence, infostealing, etc.) remain unknown.
3. cam_numbers_39d9b1.pdf and win.dll are only a combination of strings and imports; the call site was not located, and the drop/decoy behavior is pending dynamic verification.
4. Only the subject and chain were parsed structurally from the certificate; revocation, validity period and signature integrity were not cryptographically checked.
5. Although the dynamic tier was enabled, there was no real detonation result, so all dynamic c2/config fields remain pending_dynamic_verify.

## Evidence index

<details>
<summary>Expand 8 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hashing and fingerprinting | sha256/md5/sha1 and file size confirmed |
| `ev-000002` | scan.imphash | imphash=aacb2e69d0124c38c8150f18be1a9539 |
| `ev-000014` | decompile.ghidra | DllEntry @0x650c1610: manual-maps the embedded PE, resolves imports, calls by the RunPayload name |
| `ev-000016` | decompile.ghidra | RunPayload @0x6a1814f0: RWX allocation + memcpy .rdata + FlushInstructionCache + call |
| `ev-000016` | disasm.function | instruction-level confirmation of VirtualAlloc 0x63a2e / memcpy 0x6a184044 in RunPayload |
| `ev-000019` | scripted forensics | base64 container decode: 299,744 bytes, header version=1/0xC0/0x49210, body entropy 7.98 |
| `ev-000020` | scripted forensics | Authenticode PKCS#7 parsing: Microsoft signing chain, leaf subject ISABEL ALEJANDRA FLORES |
| `c2_evidence:53de6d91` | connection evidence extraction | dynamic network monitoring recorded 2 connection attempts to maps[.]windows[.]com:443; no complete session captured |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
