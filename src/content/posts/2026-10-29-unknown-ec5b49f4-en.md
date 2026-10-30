---
title: "Malware Analysis: unknown (PE · exe · ec5b49f4)"
published: 2026-10-29
draft: false
description: "Malicious (low confidence): unknown · loader · difficulty hard · dynamic sandbox + static decompilation"
tags: ["loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-29-unknown-ec5b49f4"
---

> [!WARNING]
> **Verdict: malicious** · Family **unknown** (uncertain) · Confidence **low**
> 
> This 64-bit PE disguises itself as a Microsoft Windows system component through its resource version information (InternalName/OriginalFilename=rundll32.exe, yet ProductName is Storage Optimizer). The code is heavily obfuscated and includes rdtsc timing-delta, int 2Dh and cpuid anti-debug/anti-VM checks; the entry point locates the 2.1 MB .b6fc41 section through its own section table and, after calling VirtualProtect to make it writable, transforms it in place — consistent with a packing loader. In a real dynamic sandbox no network, file or child-process behaviour appeared after the process started (possibly because the anti-VM checks took effect), so malicious intent is highly suspicious rather than behaviourally proven, and confidence is medium.

## Overview

| Item | Content |
|:--|:--|
| Family | **unknown** · _uncertain_ |
| Confidence | **low** |
| Behaviour class | loader |
| Difficulty | hard |
| First seen | 2026-10-29 07:19:20 |
| Analysis method | dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ec5b49f42dbb22e479c9bc173239c4db7eae86f0e154564b09ba2bfe41743ff7/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Masquerade as a system component</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Probe the virtual machine environment</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">rdtsc timing-delta anti-debugging</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">int 2Dh anti-debugging</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">In-place transform of an encrypted section</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `ec5b49f42dbb22e479c9bc173239c4db7eae86f0e154564b09ba2bfe41743ff7` |
| MD5 | _not recorded_ |
| Size | 7,940,096 bytes (7.6 MB) |
| Type | PE · `exe` |

## Behaviour analysis

**8** behaviours were recovered, each with supporting evidence, and all are static.

### 1. Masquerade as a system component

`T1036.005` · confidence **high** · static

The resource version information claims to be Microsoft (R) Windows (R) / Windows System Component, with internal name and original filename rundll32.exe, yet the product name is Storage Optimizer and the version is 7.0.27114.752 — a self-contradictory identity.

> **Evidence**: .rsrc VS_VERSIONINFO: CompanyName=Microsoft (R) Windows (R), InternalName=rundll32, OriginalFilename=rundll32.exe, ProductName=Storage Optimizer
> 
> **Source**: `ev-000012` · `ref:01f19284c0`

### 2. Probe the virtual machine environment

`T1497.001` · confidence **medium** · static

The code contains a cpuid instruction used to probe the virtualisation/debugging environment (at rva 0x5824e), an environment-awareness branch.

> **Evidence**: 0x5824e cpuid
> 
> **Source**: `ref:adf25d778f`

### 3. rdtsc timing-delta anti-debugging

`T1622` · confidence **medium** · static

Reads the timestamp with rdtsc and compares the delta, used to detect single-stepping or debugger pauses (at rva 0x8a20).

> **Evidence**: 0x8a20 rdtsc timing delta
> 
> **Source**: `ref:adf25d778f`

### 4. int 2Dh anti-debugging

`T1622` · confidence **high** · static

Executes int 2Dh to trigger the debugger-related exception path (at rva 0x4ec90, bytes cd 2d).

> **Evidence**: 0x4ec90 cd 2d
> 
> **Source**: `ref:adf25d778f` · `ref:ab6c94b126`

### 5. In-place transform of an encrypted section

`T1027.002` · confidence **high** · static

The entry point reads the VA and size of .b6fc41 from its own section table (rva 0x314f) and, after calling VirtualProtect(0x140592000, 0x205000, PAGE_READWRITE) at rva 0x3174, processes the 2.1 MB section in place; during emulation the section showed self-shifting writes in 8-byte strides, indicating a runtime unpacking/decryption routine.

> **Evidence**: 0x314f mov rax,[rip+0x58ab52] (VirtualProtect IAT); 0x3174 call rax; emulation arguments addr=0x140592000 size=0x205000 prot=4
> 
> **Source**: `ref:eac10f3cd1` · `ref:068989a379` · `ref:06afaff139`

### 6. Minimal import table

`T1027` · confidence **high** · static

Imports only 17 functions from 3 DLLs (KERNEL32/GDI32/ADVAPI32), with none of the network, process or file APIs such as WinInet/WinHTTP/WS2_32/CreateProcess/CreateFile — the real capability is hidden in the encrypted payload.

> **Evidence**: pe.imports: 3 DLL / 17 symbols; imphash a8a0fef9c36f2c07ecd49e85e9a605eb
> 
> **Source**: `ref:5ac3092533` · `ev-000002`

### 7. Chained obfuscation of entry-point code

`T1027` · confidence **high** · static

The entry point (rva 0x1000) and subsequent functions consist of many opaque predicates, random constant loads and chained calls (0x28e90→0x2e650→0x3c290→…), plus a call $+5 self-locating trick that obtains the current instruction address, markedly raising the cost of static analysis.

> **Evidence**: rva 0x1000 entry; 0x2f1c e8 0000000f (call $+5); .pdata 77 function ranges
> 
> **Source**: `ref:aa052904e7` · `ref:fcb11081b1` · `ev-000003`

### 8. Lack of readable strings

`T1027` · confidence **medium** · static

The 7.9 MB file contains only 622 ASCII and 23 UTF-16 strings, with no UI text, URLs or messages; the resource section holds only version information, with no icon or manifest — consistent with a loader rather than a normal GUI application.

> **Evidence**: scan.strings: ascii_count=622, utf16_count=23, flag_hits=0; .rsrc only RT_VERSION
> 
> **Source**: `ref:01f19284c0` · `ev-000010` · `ev-000009`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis method and limitations" below).
:::

### Host

- **No host IOC was recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `protected_payload_section` | `.b6fc41 @ rva 0x592000, size 0x205000 (2,117,632 bytes)` | yes | static |
| `payload_runtime_transform` | `VirtualProtect(PAGE_READWRITE) + in-place transform (call site rva 0x314f/0x3174)` | yes | static |
| `masquerade_product_name` | `Storage Optimizer` | no | static |
| `masquerade_original_filename` | `rundll32.exe` | no | static |
| `build_identifiers` | `Comments=e92d20eb09dc263b945832fde3b943a1d46ea9323863468c3ce43adba4be9085d9; PrivateBuild=e6385ee8e9bf34cea73abee2e97230727e920592107c` | no | static |
| `c2_hosts` | `-` | no | dynamic |

## Don't misread this

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- Do not claim that a C2 or outbound connection exists: no network request from this process was captured during real dynamic execution, and the network log contained only traffic from system components.
- Do not assert ransomware, stealing or mining: no file encryption, browser credential access, mining-pool domains or related strings were observed.
- Do not claim the second stage was recovered or give its hash: decryption of the 2.1 MB encrypted section was not completed in emulation; only the in-place transform call was confirmed.
- Do not treat the Microsoft attribution in the version information as a legitimate signature: the file has no Authenticode security directory, and the version information contradicts the product name.
- Do not attribute it to a specific family: no configuration, mutex or matchable family trait was extracted.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | dynamic sandbox analysis + static decompilation |
| Unpacked | no |

**Limitations and open questions**

1. Real dynamic execution showed only process startup and system module loading; no subsequent payload behaviour was observed, so C2 and persistence cannot be confirmed.
2. The anti-VM/anti-debug checks (cpuid, rdtsc, int 2Dh) may cause an early exit inside the sandbox, limiting the dynamic conclusions.
3. The encrypted section .b6fc41 could not be decrypted during emulation (after executing more than 286 million instructions it was still in the transform stage), so the family and real capability remain unconfirmed.
4. The import surface is deliberately compressed; network and execution capability may be resolved dynamically by the decrypted code and are invisible statically.
5. The purpose of the two hexadecimal identifiers in the version information's Comments/PrivateBuild could not be confirmed (possibly build/configuration identifiers, but there is no evidence).

## Evidence index

<details>
<summary>Show 16 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hashing | sha256=ec5b49f42dbb22e479c9bc173239c4db7eae86f0e154564b09ba2bfe41743ff7, size=7940096 |
| `ev-000002` | scan.imphash | imphash=a8a0fef9c36f2c07ecd49e85e9a605eb |
| `ev-000003` | scan.rich | Rich header with 4 toolchain records (MSVC) |
| `ev-000004` | scan.entropy | .19ae9b entropy 6.474 |
| `ev-000005` | scan.entropy | .e64fe3 entropy 3.151 |
| `ev-000008` | scan.entropy | .b6fc41 entropy 4.072 |
| `ev-000010` | string extraction | ascii 622 / utf16 23, no flags/URLs |
| `ev-000012` | evidence.record | Script parsed the version resource and section table: masquerading as rundll32/Storage Optimizer; randomised section names; no relocations/signature |
| `ev-000013` | evidence.record | Custom emulation: VirtualProtect(.b6fc41,0x205000,RW) at rva 0x3174, in-place transform not completed |
| `ref:aa052904e7` | PE structure parse | AMD64 GUI PE, image_base 0x140000000, entry 0x1000, 6 sections, no anomalies |
| `ref:5ac3092533` | import table parse | 3 DLL / 17 imports (KERNEL32/GDI32/ADVAPI32) |
| `ref:adf25d778f` | unpack.antidebug | rdtsc(rva 0x8a20), int 2Dh(0x4ec90), cpuid(0x5824e) |
| `ref:d0b18c036b` | unpack.detect | No known packer signature matched (packed=false) |
| `ref:eac10f3cd1` | dyn.run | VirtualProtect(0x140592000,0x205000,4) — standalone emulation observation |
| `ref:3bb560b64a` | dynamic analysis platform | Real sandbox: pid 964 started, no new processes / no dump, closed after 20 s of silence |
| `ref:15b9a9b106` | crypto constant scan | No AES/SHA/MD5/TEA/base64 constant hits |

</details>

---

_This sample is not shared; IOCs are defanged. For security research only._
