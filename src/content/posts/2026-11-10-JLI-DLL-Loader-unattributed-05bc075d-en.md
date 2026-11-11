---
title: "Malware Analysis: JLI DLL Loader (unattributed) (PE · exe · 05bc075d)"
published: 2026-11-10
draft: false
description: "Malicious (low confidence): JLI DLL Loader (unattributed) · loader · difficulty medium · static decompilation (dynamic execution yielded no runtime behavior)"
tags: ["JLI", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-10-JLI-DLL-Loader-unattributed-05bc075d"
---

> [!WARNING]
> **Verdict: malicious** · Family **JLI DLL Loader (unattributed)** (uncertain) · Confidence **low**
> 
> Aliases: loader.dll JLI loader, jli.dll-disguised loader
> 
> This file is an executable DLL, yet it disguises itself with the full export/import surface of the Java launch library jli.dll (export name loader.dll + 14 JLI_* entries); it is UPX-packed, and after unpacking it carries base64url text totalling 473,362 characters in .rdata/.data, which decodes to 355,021 bytes of headerless data with entropy 7.99, and is restored using a 210-entry chunk index table at RVA 0x9ADB0 together with a runtime-shuffled base64 alphabet (SplitMix64 shuffle). This is a typical loader construction for DLL sideloading/embedded second-stage payloads; no Java launch logic that a legitimate jli.dll should have was found.

## Overview

| Item | Content |
|:--|:--|
| Family | **JLI DLL Loader (unattributed)** · aliases loader.dll JLI loader, jli.dll-disguised loader · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader |
| Difficulty | medium |
| First seen | 2026-11-08 17:42:49 |
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/05bc075d609943ef13d07e9fe5033ca89a031221e92fb6e6df305bbdff751c3b/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX packing hides code</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Impersonate jli.dll exports</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Sideload entry masquerade</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Embedded encrypted second-stage payload</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.013</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Chunk index reassembles payload</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `05bc075d609943ef13d07e9fe5033ca89a031221e92fb6e6df305bbdff751c3b` |
| MD5 | _not recorded_ |
| Size | 440,320 bytes (430.0 KB) |
| Type | PE · `exe` |

## Behavior analysis

**7** behaviors in total, each with attached evidence, all statically obtainable.

### 1. UPX packing hides code

`T1027.002` · Confidence **high** · static

The sample is delivered with UPX sections (UPX0/UPX1/UPX2); the entry point lies in the writable-executable self-decrypting section UPX1, entropy 7.999; after unpacking it is restored to 6 regular PE sections.

> **Evidence**: pe.sections: UPX0/UPX1/UPX2, UPX1 entropy 7.999; unpack.detect: packer=upx, confidence 0.9
> 
> **Source**: `ev-000008` · `ref:81717b94c6`

### 2. Impersonating the jli.dll export surface

`T1036.005` · Confidence **high** · static

The export table declares the DLL name loader.dll and exports 14 JLI_* entries such as JLI_Launch/JLI_MemAlloc/JLI_CmdToArgs; the import surface is exactly the same as the genuine jli.dll, but the image size and content both differ from the genuine jli.dll; this is masquerading as a legitimate system component name.

> **Evidence**: pe.exports: loader.dll / 14 exports; pe.imports: KERNEL32.DLL(84)+api-ms-win-core-synch-l1-2-0.dll(2); genuine jli.dll 87,152B vs unpacked image 642,560B
> 
> **Source**: `ref:af2ad2834d` · `ref:a0544a3d09` · `ev-000016`

### 3. Sideloading entry masquerade

`T1574.002` · Confidence **medium** · static

Legitimate export names such as JLI_Launch(0x180002866) serve as call entry points, and the export stub passes through 0x180002E59 into the internal initialization chain; this construction is meant to execute its own code after being loaded by a host program under the jli.dll name.

> **Evidence**: 0x180002866 JLI_Launch: call 0x180002E59; entry 0xC1A0 → 0xC060; export names correspond one-to-one with jli.dll
> 
> **Source**: `ref:af2ad2834d` · `ref:39c87f97b1` · `ref:4d09a2a672`

### 4. Embedded encrypted second-stage payload

`T1027.013` · Confidence **high** · static

.rdata and .data each begin with a run of pure base64url text (233,154 + 240,208 characters); decoded, it is 355,021 bytes with entropy 7.99, all 256 byte values present and no MZ/PK/ELF header, constituting encrypted/compressed next-stage data.

> **Evidence**: .rdata from RVA 0x1B000, 233,154 characters; .data from RVA 0x60000, 240,208 characters; decoded 355,021 bytes, entropy 7.99
> 
> **Source**: `ev-000017` · `ref:b7eec4e578`

### 5. Chunk index reassembles payload

`T1140` · Confidence **medium** · static

At RVA 0x9ADB0 there are 210 {VA,length} chunk index entries; the entries point into the two text runs above; the chunks are concatenated end to end, so that the complete encoded string can be reassembled by index at runtime.

> **Evidence**: RVA 0x9ADB0: 210 {VA,length} entries; e.g. 0x1800600A5/0xC2B, 0x18001B0E0/0x512, 0x18001B5F2/0xD39
> 
> **Source**: `ev-000017`

### 6. Runtime shuffled base64

`T1140` · Confidence **high** · static

The function at RVA 0x1B83 loads SplitMix64 constants and performs a Fisher-Yates shuffle on the 64-byte base64 alphabet at .rdata 0x54E38 (swapping the alphabet bytes on the stack in place), then decodes the payload with the shuffled alphabet, defeating standard base64 recognition.

> **Evidence**: 0x1B83: movabs 0x9E3779B97F4A7C15 / 0xBF58476D1CE4E5B9 / 0x94D049BB133111EB; .rdata 0x54E38 alphabet; swap [rsp+rbx+0x1F]/[rsp+rdx+0x20]
> 
> **Source**: `ref:c82d5cf8af` · `ref:365b3b313a` · `ev-000017`

### 7. Dynamically resolve system APIs

`T1129` · Confidence **medium** · static

The import table retains only a few KERNEL32 functions (LoadLibraryA/GetProcAddress/VirtualProtect etc.); the remaining capabilities must be resolved at runtime via GetProcAddress and are called indirectly through function pointers in .data.

> **Evidence**: pe.imports: LoadLibraryA/GetProcAddress/VirtualProtect; 0x1C31 call qword ptr [.data] indirect call
> 
> **Source**: `ref:a0544a3d09` · `ref:c82d5cf8af`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (reason: see "Analysis method and limitations" at the end).
:::

### Host

- **No host IOC was recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `payload_encoding` | `base64url text + a shuffled alphabet generated at runtime with a SplitMix64 shuffle` | yes | static |
| `payload_size` | `473362 characters encoded, 355021 bytes after decoding (two runs: 233154 characters from RVA 0x1B000, 240208 characters from RVA 0x60000)` | yes | static |
| `chunk_index_table` | `RVA 0x9ADB0, 210 {VA,length} chunk index entries (e.g. 0x1800600A5/0xC2B, 0x18001B0E0/0x512)` | yes | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- It should not be called ransomware or an infostealer: no code related to file encryption, credential reading or browser-data collection was found.
- It should not be claimed that a C2 or download address was confirmed: static analysis extracted no usable URL/IP/domain, and no outbound session was observed in the sandbox.
- It should not be claimed that the sample can run standalone: this file is a DLL, and delivering it directly as an executable will not produce a new process; no sample-related child process appeared in the dynamic run.
- It should not be claimed that process injection or persistence was observed: there is no corresponding API call chain, registry, service or scheduled-task evidence.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Unpacking | Yes (stage2 `6c3dc4eea58cf0babc559652126f230d2b8cffd5de1a0040195dfbd7bf2372b6`) |

**Limitations and pending verification**

1. The DLL was only delivered directly in an isolated sandbox; no new process, network request or memory dump was observed, so there is no runtime malicious-behavior evidence.
2. For the embedded 355,021-byte payload, only decoding and structural location were completed; no recognizable next-stage PE/script could be decrypted, so its function (download, injection or theft) cannot be confirmed.
3. Family attribution lacks vendor-engine/YARA/public-report corroboration and is only a candidate judgment based on export-surface masquerading and the embedded encrypted payload.
4. Anti-debug features such as rdtsc/int 2Dh/cpuid hit inside the packed section lie in compressed data, may be false positives, and were not used as conclusions.

## Evidence index

<details>
<summary>Expand 11 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256=05bc075d...; md5=35fa8e6578f4eae5ece1c045b35940b2; size=440320 |
| `ev-000008` | Sample triage | packing likelihood 85%: very few imports (4), W^X section, UPX0 section name |
| `ref:39c87f97b1` | PE structure parsing | PE64 DLL, 3 sections UPX0/UPX1/UPX2, image_base=0x180000000, entry RVA 0xA32B0 |
| `ref:af2ad2834d` | pe.exports | DLL name loader.dll, 14 exports (7 named JLI_* + 7 unnamed aliases) |
| `ref:a0544a3d09` | Import table parsing | unpacked image imports: KERNEL32.DLL 84 items + api-ms-win-core-synch-l1-2-0.dll 2 items |
| `ref:c82d5cf8af` | disasm.function | SplitMix64 constants and alphabet shuffle/swap instructions at 0x1B83 |
| `ref:365b3b313a` | Cryptographic constant identification | base64 url-safe alphabet @0x53638; 0x9E3779B9 constant (NIST/SplitMix mix) |
| `ref:c84ce61f56` | Dynamic analysis platform | sandbox detonation 120s: candidate processes 0, dumps 0, hollows scans 0, rolled back |
| `ev-000016` | evidence.record | comparison of static unpacked image (642,560B) with genuine jli.dll (87,152B) export/import surfaces |
| `ev-000017` | evidence.record | two base64url payload runs decoded to 355,021 bytes (entropy 7.99), 210 chunk index entries, runtime-shuffled alphabet |
| `telemetry:05bc075d` | Dynamic telemetry | dynamic telemetry recorded: monitoring component process/file events 91; filtered tool/system noise 27 |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
