---
title: "Malware Analysis: JLI launcher DLL loader (PE · exe · 8cd439c7)"
published: 2026-11-03
draft: false
description: "Malicious (low confidence): JLI launcher DLL loader · loader · difficulty hard · dynamic sandbox + static decompilation"
tags: ["JLI", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-03-JLI-launcher-DLL-loader-8cd439c7"
---

> [!WARNING]
> **Verdict: Malicious** · Family **JLI launcher DLL loader** (uncertain) · Confidence **low**
> 
> Aliases: loader.dll, jli.dll sideload
> 
> A 64-bit DLL (internal name loader.dll) exports the Java launcher interface JLI_*; .rdata and .data each embed a roughly 207 KB / 211 KB URL-safe base64 high-entropy blob; a TLS callback decodes embedded key constants before entry and writes state into the thread TLS block; the core logic sits in a roughly 24 KB function flattened through a jump table and is triggered via the exported JLI_Launch; the code contains IsDebuggerPresent, rdtsc, and cpuid checks. All of the above was directly observed through decompilation and structural forensics; direct delivery in the isolated dynamic environment did not show payload execution, so dynamic behavior evidence is limited.

## Overview

| Item | Content |
|:--|:--|
| Family | **JLI launcher DLL loader** · aliases loader.dll, jli.dll sideload · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader |
| Difficulty | hard |
| First seen | 2026-11-02 23:05:45 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/8cd439c7280a220a58cafe479982556ebe8581e53d953684f48a748e2b4b91bc/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Fake Java launcher exports</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Embed two high-entropy blobs</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">TLS callback preloads key</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Anti-debug and timing checks</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Control-flow flattening</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `8cd439c7280a220a58cafe479982556ebe8581e53d953684f48a748e2b4b91bc` |
| MD5 | _not recorded_ |
| Size | 725,504 bytes (708.5 KB) |
| Type | PE · `exe` |

## Behavior analysis

**7** behaviors in total, each backed by evidence, all statically recoverable.

### 1. Fake Java launcher exports

`T1036.005` · Confidence **high** · static

The DLL's internal name is loader.dll with 14 export entries, of which all 7 named exports are JLI_* (JLI_Launch at rva 0x46765, JLI_MemAlloc at rva 0x9F70, etc.), copying the export surface of Java's jli.dll so it can be loaded/called by name from java.exe or other hosts.

> **Evidence**: pe.exports: dll_name=loader.dll, JLI_Launch@rva 0x46765; ordinals 8–14 are duplicate unnamed exports
> 
> **Source**: `ref:727d61db92` · `ref:79c1212c90`

### 2. Embed two high-entropy blobs

`T1027.009` · Confidence **high** · static

.rdata at rva 0x1A000 and .data at rva 0x6A000 each contain a URL-safe base64 text (276131 / 281785 characters), decoding to 207096 / 211338 bytes with entropy 7.993 and no MZ/PK structural signature, together about 58% of the file — consistent with encrypted payload or padding.

> **Evidence**: scan.crypto base64url alphabet@off 0x5D6DD; script decodes off 0x19200/0x68600 to entropy 7.993
> 
> **Source**: `ref:4da3775715` · `ref:4e23308b34` · `ref:d92a09e617`

### 3. TLS callback preloads key

`T1027` · Confidence **high** · static

The PE's TLS callback array (VA 0x180066C00) registers tls_callback_0@0x1C70; on process attach/detach the callback calls FUN_180001250, which uses a rolling XOR starting from immediate 0xCD366C7249B2043C and incrementing by 0x8AB57BE74F48E1FB per round to decode 7 qwords at .rdata 0x5E448 and 4 shorts at 0x5E494, writes them into the current thread TLS block, and sets TLS+0x53 to 1.

> **Evidence**: tls_callback_0@0x1C70 -> FUN_180001250@0x1250; TLS AddressOfCallbacks=0x180066C00 (array first entry 0x180001C70)
> 
> **Source**: `ref:9a429899e1` · `ref:52ae289ec2` · `ref:85f908a6ff`

### 4. Anti-debug and timing checks

`T1622` · Confidence **high** · static

It imports IsDebuggerPresent (called at runtime at 0xFA83), and the code section also contains rdtsc (rva 0x4BBD) and cpuid (rva 0xC1C2) instructions for timing-delta measurement and virtualization/debugger environment probing.

> **Evidence**: unpack.antidebug: IsDebuggerPresent(import), rdtsc@rva 0x4BBD, cpuid@rva 0xC1C2
> 
> **Source**: `ref:14fafe638c` · `ref:7b8758449e`

### 5. Control-flow flattening

`T1027` · Confidence **medium** · static

The core function FUN_18000330A (rva 0x330A–0x92D5, about 24 KB) implements state-machine-style indirect jumps through 32-bit offset jump tables at .data 0x5ED48 and elsewhere, and is called from 7 sites (including 0xB6A1/0xB6B3 inside JLI_Launch); only GetProcessHeap/HeapAlloc inside the function are direct IAT calls, while everything else is resolved at runtime.

> **Evidence**: decompile FUN_18000330A: jmp [&LAB_180005D8A + *(int*)(&DAT_18005E748 + 0x600)]; call sites 0xB6A1/0xB6B3 and 5 others
> 
> **Source**: `ref:79c1212c90` · `ref:e744ee88b4`

### 6. Construct fake module FkPlX.dll

`T1620` · Confidence **medium** · static

FUN_18000B6BF allocates a 0x400-byte object and writes the wide-character module name "FkPlX.dll" (.rdata rva 0x5E480) plus section-description fields (Characteristics 0x140012, size 0x412, name length 0x14), registering an in-memory module that does not correspond to any file on disk; the function is called from inside the flattened main function at 0x740D.

> **Evidence**: FUN_18000B6BF@0x18000B6BF; utf16 'FkPlX.dll' @off 0x5D680; call site 0x18000740D
> 
> **Source**: `ref:ce2a42d8ef` · `ref:dc5bfd14d7`

### 7. Main logic triggered only via export

`T1574.002` · Confidence **high** · static

DllMain (entry 0xBC10 -> FUN_18000BAD0) performs only MSVC CRT initialization; the malicious main logic is triggered by the exported JLI_Launch (0xB6AD) calling FUN_18000330A, so running this DLL as an executable or merely loading it does not execute the payload.

> **Evidence**: decompile FUN_18000BAD0/FUN_18000BA70 (CRT init only); JLI_Launch -> FUN_18000330A
> 
> **Source**: `ref:5c1ed9628c` · `ref:0edda4837f` · `ref:79c1212c90`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC recovered** (see "Analysis method and limitations" at the end).
:::

### Host

- **No host IOC recovered.**

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `payload_blob_1` | `.rdata rva 0x1A000: 276131 chars URL-safe base64, decodes to 207096 bytes, entropy 7.993 (no MZ/PK header)` | yes | static |
| `payload_blob_2` | `.data rva 0x6A000: 281785 chars URL-safe base64, decodes to 211338 bytes, entropy 7.993 (no MZ/PK header)` | yes | static |
| `fake_module_name` | `FkPlX.dll` | no | static |
| `key_material_source` | `TLS callback FUN_180001250 uses rolling XOR to decode 7 qwords at .rdata rva 0x5E448 and 4 shorts at 0x5E494` | yes | static |
| `encryption_algo` | `unknown (no standard AES/SHA/CRC constants; both blobs remain high-entropy after decoding, algorithm not recovered)` | yes | static |
| `export_interface` | `JLI_CmdToArgs,JLI_GetStdArgc,JLI_GetStdArgs,JLI_InitArgProcessing,JLI_Launch,JLI_MemAlloc,JLI_MemFree` | no | static |

## Must not claim

:::important
The following conclusions are **prone to misjudgment**; take care when citing this report.

- Do not conclude it is ransomware or a wiper: no file encryption, shadow copy deletion, or ransom-note strings were found.
- Do not claim a verified C2 domain or IP: the dynamic sandbox observed no outbound traffic from the sample itself; domains in network logs all belong to Windows system components.
- Do not claim dropping or persistence was completed: no file writes, registry modifications, services, or scheduled-task creation were observed.
- Do not equate the two base64 blobs with known-family signatures: they decode to high-entropy unrecognizable data, and no second-stage PE or configuration was recovered.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The sample is a DLL whose main logic sits behind the exported JLI_Launch; executing the file directly in the isolated environment triggers only DllMain/CRT, no payload execution behavior was obtained, so reproduced=false.
2. Both base64 blobs decode to entropy 7.99 with no PE/archive signature; the static stage could not recover a second-stage payload or configuration, and the encryption algorithm is unknown.
3. The core logic is control-flow flattened with indirect jump-table jumps; decompilation covers only the entry dispatch and could not fully recover the semantics.
4. No runtime IOC such as C2, drop paths, or mutexes was observed; related fields are left empty rather than guessed.
5. The svchost / MicrosoftEdgeUpdate / SIHClient traffic in the dynamic timeline is system-component behavior unrelated to this sample.

## Evidence index

<details>
<summary>Expand 19 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:462ef6f66c` | sample triage | hash/imphash/section entropy/packing score: packing.score=0, 0 anomalies, 3 imported DLLs |
| `ref:d92a09e617` | PE structure parsing | AMD64 DLL, image_base 0x180000000, entry rva 0xBC10, 6 sections, TLS/EXPORT/IMPORT directories |
| `ref:727d61db92` | pe.exports | dll_name=loader.dll, 14 exports, 7 named JLI_* exports |
| `ref:7b8758449e` | import table parsing | 3 DLLs / 91 symbols, including VirtualProtect, LoadLibraryA, GetProcAddress, CreateFileW, WriteFile, IsDebuggerPresent, GetSystemTimes |
| `ref:ead6517159` | string extraction | string scan: loader.dll, JLI_* export names, FkPlX.dll, base64 alphabet; no plaintext URL/path found |
| `ref:79c1212c90` | decompile.function | JLI_Launch@0xB6AD only calls FUN_18000330A(0x330A) |
| `ref:52ae289ec2` | decompile.function | FUN_180001250: rolling XOR decodes 7 qwords at .rdata 0x5E448 and 4 shorts at 0x5E494 and writes them to TLS |
| `ref:9a429899e1` | decompile.function | tls_callback_0@0x1C70: calls FUN_180001250 on DLL_PROCESS_ATTACH/DETACH |
| `ref:ce2a42d8ef` | decompile.function | FUN_18000B6BF: builds a 0x400-byte module/section description structure containing the wide-character name FkPlX.dll |
| `ref:5c1ed9628c` | decompile.function | FUN_18000BAD0 (DllMain): takes only the CRT initialization branch |
| `ref:14fafe638c` | unpack.antidebug | IsDebuggerPresent import, rdtsc@0x4BBD, cpuid@0xC1C2 |
| `ref:4da3775715` | cryptographic constant identification | URL-safe base64 alphabet @off 0x5D6DD |
| `ref:4e23308b34` | script | decodes both base64 blobs: 276131→207096 bytes, 281785→211338 bytes, both entropy 7.993, no MZ/PK signature |
| `ref:85f908a6ff` | script | parses the TLS directory: AddressOfIndex rva 0xB0B94, callback array first entry VA 0x180001C70 |
| `ref:e744ee88b4` | script | statically scans IAT call sites: only GetProcessHeap/HeapAlloc inside the flattened function are direct import calls |
| `ref:d1f3c8e846` | dyn.run | emulation executed only CRT initialization, 31 APIs, no file/network/registry behavior |
| `ref:7f741255b8` | unpack.detect | no known packer identified, packed=false |
| `ref:2fdf2e5dfb` | dynamic analysis platform | isolated delivery: 532 polls, 0 new process candidates, no sample outbound traffic, rolled back afterwards |
| `ref:dc5bfd14d7` | script | UTF-16 string extraction: FkPlX.dll @off 0x5D680, the rest CRT area names/API set names |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
