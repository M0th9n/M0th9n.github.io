---
title: "Malware sample analysis: Unclassified PE64 loader (TLS-table decode + API hashing) (PE · exe · c47f0cb5)"
published: 2026-11-21
draft: false
description: "Malicious (low confidence): Unclassified PE64 loader (TLS-table decode + API hashing) · loader · difficulty hard · dynamic sandbox + static decompilation"
tags: ["loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-21-Unclassified-PE64-loader-TLS-table-decode-API-hashing-c47f0cb5"
---

> [!WARNING]
> **Verdict: malicious** · family **Unclassified PE64 loader (TLS-table decode + API hashing)** (uncertain) · confidence **low**
> 
> The PE64 DLL has no exports; its main body runs only from the TLS callback and the DllMain/CRT path: at load time it decodes 4 data tables into TLS storage with a rolling additive key and resolves APIs dynamically through a 54-entry ordered hash table using binary search; the import surface retains only CRT plus GetSystemFirmwareTable, IsDebuggerPresent, MessageBoxW and other anti-analysis/fingerprinting calls; .rdata is padded with random base64url strings and sequences of English words to hide strings. This combination is typical of a sideload-style loader/implant component, hence malicious. No C2 or stage-2 payload was recovered this time, so the malicious determination rests on the mechanism itself rather than behavioral consequences.

## At a glance

| Item | Value |
|:--|:--|
| Family | **Unclassified PE64 loader (TLS-table decode + API hashing)** · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader |
| Difficulty | hard |
| First seen | 2026-11-19 19:24:54 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/c47f0cb5a0c51d908fbcc38be70ade963762e4f4adca8fb32f33440cb9af4376/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">TLS callback decodes data tables</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Binary-search hash table for APIs</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.007</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Reads SMBIOS fingerprint</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Detects debugger</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Changes page protection at runtime</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
</svg>

## Sample identifiers

| Item | Value |
|:--|:--|
| SHA-256 | `c47f0cb5a0c51d908fbcc38be70ade963762e4f4adca8fb32f33440cb9af4376` |
| MD5 | _not recorded_ |
| Size | 663,625 bytes (648.1 KB) |
| Type | PE · `exe` |

## Behavior analysis

**9** behaviors in total, each with evidence attached; **7** of them are statically obtainable and **2** were obtained through dynamic analysis.

### 1. TLS callback decodes data tables

`T1027` · confidence **high** · static

The TLS callback, on DLL_PROCESS_ATTACH/DETACH, decodes 4 tables (26×u64@0x7C6E0, 16×u32@0x7C9B0, 14×u16@0x7CD64, 19×u8@0x7F190) into TLS block +0x58…+0x186 with a rolling additive key and sets the initialization flag at +0x185, so the main logic never appears on the regular import/export surface.

> **Evidence**: rva 0x7D650 loop: tables + rolling constants 0x471e43be6bb4579f / 0xd528883b9283d9bf; tls_callback_0@rva 0x45D30
> 
> **Source**: `ref:22dcab34c9` · `ref:f339080e20` · `ref:8a6943122e`

### 2. Binary-search hash table for APIs

`T1027.007` · confidence **medium** · static

A 54-entry ascending sorted 32-bit hash table (0x7CACC) combined with binary search is used to resolve the required API addresses dynamically, avoiding sensitive function names in the import table.

> **Evidence**: rva 0xD7DD: mov r11d,0x36; lea rdx,[rip+0x6f23b]=0x7CACC; binary-search index mov esi,[rdx+rax*4]
> 
> **Source**: `ref:8a6943122e`

### 3. Reads SMBIOS fingerprint

`T1497.001` · confidence **high** · static

GetSystemFirmwareTable is imported and retained (IAT 0x97320), allowing the raw SMBIOS firmware table to be read for hardware/virtual-machine fingerprinting and anti-analysis.

> **Evidence**: pe_imports: kernel32.dll!GetSystemFirmwareTable, iat_rva=0x97320
> 
> **Source**: `ref:084de1a61c`

### 4. Detects debugger

`T1622` · confidence **high** · static

IsDebuggerPresent is imported, and at 0x70A5F in .text there is an indirect call to its IAT slot (0x8F120), giving it debugger-detection capability.

> **Evidence**: IAT rva 0x8F120; call qword ptr [rip+disp] @rva 0x70A5F
> 
> **Source**: `ref:084de1a61c` · `ref:5d7fc30c92`

### 5. Empty exports require a host loader

`T1574.002` · confidence **medium** · static

It is a PE64 DLL with an empty export table (export_count=0); the entry point lies in the DllMain/CRT path in .text, so it can only be executed through internal paths after being loaded by a host process, which matches the sideload delivery form.

> **Evidence**: pe_parse: characteristics=DLL, export RVA=0; entry rva 0x79A00
> 
> **Source**: `ref:44e8311ad3` · `ref:c76c197550` · `ref:555982cf02`

### 6. Rewritten import table hides CRT

`T1027` · confidence **high** · static

The import directory contains 116 DLL entries and 116 symbols, many of them single-symbol duplicate kernel32.dll entries, with CRT and API-set resolution data coexisting, consistent with a loader repack/import-table rebuild.

> **Evidence**: pe_imports: dll_count=116, symbol_count=116, multiple single-symbol kernel32.dll entries
> 
> **Source**: `ref:084de1a61c`

### 7. Random-string padding obfuscation

`T1027` · confidence **high** · static

The .rdata range 0x7D242–0x8C5B0 is filled alternately with random base64url strings and coherent English word sequences, acting as a string/config obfuscation layer and interfering with static searches (the scanner only hits the alphabet string).

> **Evidence**: 0x7D2B0 technical English string adjacent to a base64url string; 0x7E9B8 'find live we three different…'; strings only hits abcdefghijklmnopqrstuvwxyz{|}
> 
> **Source**: `ref:cbf3da05f6` · `ref:dcb7e61b56` · `ref:26b530cd71`

### 8. Changes page protection at runtime

`T1027` · confidence **high** · dynamic

Inside the user-mode emulation window, at pc=0x15FAFAE2CAE it calls VirtualProtect(0x15FAFB0C000,0x100,PAGE_READONLY), adjusting the protection attributes of the .tls/data page.

> **Evidence**: dyn observation: kernel32.VirtualProtect args [0x15fafb0c000,0x100,0x2] ret=1
> 
> **Source**: `ref:f7d38e489e`

### 9. No outbound activity at load time

`T1106` · confidence **high** · dynamic

The emulation window recorded 21 API calls in total; apart from CRT initialization (FlsAlloc/FlsSetValue/InitializeCriticalSectionEx/GetProcessHeap/VirtualProtect), no file, network, or registry operations appeared, and the main logic can only unfold after a host call.

> **Evidence**: dyn observation: api_count=21, file_access/network_events/registry_access all empty
> 
> **Source**: `ref:f7d38e489e`


## IOCs (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis method and limitations" at the end).
:::

### Host

- **No host IOC was recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `-` | Yes | Static |
| `mutex` | `-` | No | Static |
| `install_path` | `-` | No | Static |
| `encryption_algo` | `rolling additive delta over 4 TLS tables (u64/u32/u16/u8), init flag at TLS+0x185; no standard cipher matched (TEA delta constant is only a coincidental 0x9E3779B9 hit)` | No | Static |
| `api_hash_table` | `54-entry sorted u32 table @rva 0x7CACC, binary-search resolver @rva 0xD7DD` | Yes | Static |
| `tls_tables` | `0x7C6E0 (26x8), 0x7C9B0 (16x4), 0x7CD64 (14x2), 0x7F190 (19x1) -> TLS +0x58/+0x128/+0x168/+0x186` | Yes | Static |

## Do not misjudge

:::important
The conclusions below are **easily misjudged**; take care when citing this report.

- Do not assert that it ultimately delivers a Java/JAR payload based solely on the embedded path C:\Users\Test\Desktop\jre21in\java.exe; that path is more likely compile-time residue or packaging configuration.
- Do not assert that a complete anti-virtualization decision logic exists based solely on the GetSystemFirmwareTable import; this time only the import and callable surface were proven, and no decision branch was observed.
- Do not treat the random base64url strings or English word sequences in .rdata as C2, keys, or campaign IDs; no usable network indicator was obtained this time.
- Do not classify it as ransomware/stealer: no encryption, credential theft, outbound connection, or registry/service write was observed.
- Do not assert that DLL sideloading hijacking has occurred; it can only be confirmed as a DLL with empty exports that has the form of being sideloaded by a host.
:::

## Analysis method and limitations

| Item | Value |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The sample is an exportless DLL and cannot be detonated as a standalone process; no process/network/memory evidence from the real sandbox was obtained this time, and the dynamic conclusions come only from user-mode emulation.
2. The API hash table has not yet been reduced to symbol names, so the specific function set it resolves dynamically cannot be confirmed.
3. No configuration, C2, mutex, or install path was extracted; family attribution cannot be determined and is marked uncertain as a candidate.
4. The large number of random base64url strings and English word sequences in .rdata may be obfuscation padding or may carry an encrypted configuration; they were not decrypted this time.

## Evidence index

<details>
<summary>Expand 11 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:77f864625a` | Hash & fingerprint | sha256/md5/imphash baseline |
| `ref:44e8311ad3` | PE structure parsing | PE64 DLL, no exports, entry rva 0x79A00, 8 sections |
| `ref:084de1a61c` | Import table parsing | 116-entry import table, including GetSystemFirmwareTable/IsDebuggerPresent/MessageBoxW |
| `ref:cbf3da05f6` | String extraction | String and alphabet hits, .rdata padding traits |
| `ref:a4b6eccb3f` | Cryptographic constant identification | Only TEA delta constant hit (0x9E3779B9) |
| `ref:22dcab34c9` | decompile.function | tls_callback_0 calls FUN_0x7D650 |
| `ref:f339080e20` | decompile.function | Rolling additive decoding of 4 tables written into TLS |
| `ref:8a6943122e` | disasm.function | Decode loop and 54-entry hash-table binary search |
| `ref:555982cf02` | decompile.function | DllMain/CRT initialization path |
| `ref:f7d38e489e` | dyn.run | 21 API calls, no file/network/registry actions |
| `ref:dcb7e61b56` | script | Hex verification of .rdata padding structure |

</details>

---

_This report's sample is not public, IOCs are defanged, for security research only._
