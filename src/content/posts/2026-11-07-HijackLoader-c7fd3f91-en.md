---
title: "Malware Analysis: HijackLoader (PE · exe · c7fd3f91)"
published: 2026-11-07
draft: false
description: "Malicious (low confidence): HijackLoader · loader · difficulty hard · Dynamic sandbox analysis + static decompilation"
tags: ["Hijack", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-07-HijackLoader-c7fd3f91"
---

> [!WARNING]
> **Verdict: Malicious** · Family **HijackLoader** (uncertain) · Confidence **low**
> 
> Aliases: IDAT Loader, loader.dll JLI sideloader
> 
> A 64-bit DLL (internal name loader.dll) exporting the complete JLI_* interface, matching the import surface of the Java launcher jli.dll one-to-one, providing a DLL sideloading hijack surface; .rdata/.data holds 209 multi-layer encoded entries totaling 544,211 bytes (base64url bit-skipping + XOR/LCG + custom LZ), accompanied by control-flow flattening and anti-debugging probes; no legitimate JVM call paths expected of a Java launcher are present. These conclusions are directly supported by decompilation, structural parsing, and local behavior emulation.

## Overview

| Item | Content |
|:--|:--|
| Family | **HijackLoader** · aliases IDAT Loader, loader.dll JLI sideloader · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader |
| Difficulty | hard |
| First seen | 2026-11-03 23:35:57 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/c7fd3f91a48fddc1ba61b91c6b059299c809215bff45fd01dbb601ca95242221/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Fake Java launcher exports</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">TLS callback writes markers</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Detect debugger and VM</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded string table</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Silent exit when run standalone</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `c7fd3f91a48fddc1ba61b91c6b059299c809215bff45fd01dbb601ca95242221` |
| MD5 | _not recorded_ |
| Size | 732,672 bytes (715.5 KB) |
| Type | PE · `exe` |

## Behavior analysis

**9** behaviors in total, each backed by evidence; **8** are statically available and **1** was obtained through dynamic analysis.

### 1. Masquerade as Java launcher exports

`T1574.002` · Confidence **high** · static

The module's internal name is loader.dll, exporting JLI_Launch, JLI_InitArgProcessing, JLI_GetStdArgs, JLI_GetStdArgc, JLI_MemAlloc, JLI_MemFree, JLI_CmdToArgs and 7 ordinal aliases of the same names; the export surface corresponds exactly to the Java launcher jli.dll, allowing it to be sideloaded by java.exe according to the DLL search order.

> **Evidence**: export table RVA 0x6A9A8 dll_name=loader.dll; JLI_Launch RVA 0x16A4; ordinals 8-14 reuse the RVAs of ordinals 1-7
> 
> **Source**: `ref:ae35feeedb` · `ref:a07a460aa6`

### 2. TLS callback writes markers

`T1027` · Confidence **high** · static

The PE header registers a TLS callback (RVA 0xA510), which on DLL/thread attach writes constants such as 0xae0882db4e12d9c3, 0xd68d6341, 0xd9d3bb9f and flag bytes into the TLS block; later code decides whether to continue executing based on values at TLS+0x50/+0x60.

> **Evidence**: TLS directory RVA 0x66550 -> callback RVA 0xA510 -> FUN_1800015b0 (RVA 0x15B0)
> 
> **Source**: `ref:a2b75125bb` · `ref:f1b94cd82d`

### 3. Detect debuggers and virtual machines

`T1622` · Confidence **high** · static

It imports IsDebuggerPresent, and the code contains rdtsc timing differences and cpuid probes (RVA 0x9CF9, 0xC452), typical anti-debugging/anti-VM checks.

> **Evidence**: IAT 438456 IsDebuggerPresent; rdtsc @ RVA 0x9CF9; cpuid @ RVA 0xC452
> 
> **Source**: `ref:f85af4e0b2` · `ref:898f18cd3e`

### 4. Decrypt the embedded string table

`T1140` · Confidence **high** · static

It takes 209 encrypted strings (544,211 bytes total), treats each 64-character block by dropping 1 bit and base64url-decoding it, XORs with a key stream generated by LCG/xorshift, and finally applies custom LZ decompression; the decoder is at FUN_1800088cf and the XOR loop near RVA 0x3C4E.

> **Evidence**: table @0xB0C18 with 209 entries; FUN_1800088cf (RVA 0x88CF) contains a 64-entry reverse lookup table and LZ back-reference copying; 0x3C4E imul 0x54eeddff96585e01
> 
> **Source**: `ref:b7b9057a0a` · `ref:2fac977dee` · `ref:dd36158d1b`

### 5. Control-flow flattening obfuscation

`T1027` · Confidence **high** · static

The entry dispatch and subsequent logic are expanded via jump tables and computed gotos (FUN_180002196, FUN_180009347, FUN_18000A593, etc.), so the decompiler cannot recover direct call relations, significantly raising the cost of static reading.

> **Evidence**: end of FUN_180002196 (*(code*)(&LAB_1800057D3+*(int*)(&DAT_1800624BC+0x294/0x4B0))); FUN_180009347 likewise dispatches at offsets 0x38/0x7C/0x88/0xCC
> 
> **Source**: `ref:f702470691` · `ref:0b0efe2e23`

### 6. Resolve sensitive APIs at runtime

`T1027` · Confidence **high** · static

Static imports are only 89 kernel32/user32/synchronization APIs, with no networking, process injection, or crypto library interfaces; LoadLibraryA/LoadLibraryExW + GetProcAddress are used for runtime resolution (emulation observed the real call chain LoadLibraryExW("api-ms-win-core-fibers-l1-1-2") and GetProcAddress("FlsGetValue2")).

> **Evidence**: IAT from RVA 0x6AF80, 736 bytes; emulation events pc=0x18000E357 LoadLibraryExW, pc=0x18000E488 GetProcAddress
> 
> **Source**: `ref:898f18cd3e` · `ref:38711e055d`

### 7. Validate the host and command line

`T1497.001` · Confidence **medium** · static

It imports GetCommandLineA/GetCommandLineW, GetStartupInfoW, GetModuleFileNameW, GetEnvironmentStringsW, GetCurrentDirectoryW, GetFullPathNameW, giving it a conditional surface to decide whether to execute the payload based on host process name/command line/environment.

> **Evidence**: IAT 438160/438168 GetCommandLineA/W; 438272 GetModuleFileNameW; 438328 GetStartupInfoW; 438224 GetEnvironmentStringsW
> 
> **Source**: `ref:898f18cd3e`

### 8. File-drop and traversal capabilities

`T1083` · Confidence **medium** · static

It imports CreateFileW, SetFilePointerEx, WriteFile, FlushFileBuffers, FindFirstFileExW/FindNextFileW/FindClose, GetTempPathW, GetWindowsDirectoryW, GetSystemDirectoryW, giving it file-writing and directory-traversal capabilities; no actual file-operation events appeared in this dynamic observation.

> **Evidence**: IAT 438024 CreateFileW; 438072 FindFirstFileExW; 438080 FindNextFileW; 438648 WriteFile; 438376 GetTempPathW
> 
> **Source**: `ref:898f18cd3e`

### 9. Silent exit when run standalone

`T1497.001` · Confidence **high** · dynamic

When launched as a normal executable in the isolated environment, the process exits on its own within seconds without creating child processes or producing file/registry/network events; the original encoding table in the memory dump remains undecrypted, indicating that payload execution depends on a specific host context rather than standalone operation.

> **Evidence**: dynamic timeline: two same-named processes start successively and disappear before the dump; in the memory image 'zOa5ZYoXzI3P3vs' is still ciphertext and appears only once
> 
> **Source**: `ref:02f18f9c76` · `ref:348b83898b` · `ref:99aae65d0a`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis method and limitations" at the end).
:::

### Host

- **No host IOC was recovered.**

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `internal_dll_name` | `loader.dll` | yes | static |
| `pdb_path` | `LLD PDB.efork.pdb` | no | static |
| `export_surface` | `JLI_Launch/JLI_InitArgProcessing/JLI_GetStdArgs/JLI_GetStdArgc/JLI_MemAlloc/JLI_MemFree/JLI_CmdToArgs (+7 ordinal aliases)` | yes | static |
| `encryption_algo` | `base64url (drop 1 bit per 64 chars) -> XOR (LCG 0x54eeddff96585e01/0xa00cdb6684d853f5 + xorshift) -> custom LZ decompression` | yes | static |
| `string_table_items` | `209` | yes | static |
| `string_table_bytes` | `544211` | yes | static |
| `c2_hosts` | `-` | yes | dynamic |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- No network event was observed, so its download/callback capability must not be asserted, and no specific C2 domain or IP should be given.
- No process injection, process hollowing, ransomware, or credential-theft call chain was seen, so it must not be classed as injector/ransomware/stealer.
- The JLI_* exports are a masquerade, not a legitimate Java component; it must not be treated as a normal JDK file or misjudged as benign.
- The configuration could not be decrypted in this run, so it must not be claimed that C2, mutex, install path, or persistence items were extracted.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. The sample is a DLL whose export surface targets a Java launcher host; the isolated environment has no such host, so direct detonation only produced process start-exit, and the decrypted payload behavior was not observed.
2. The XOR seeds for the 209-entry string table come from runtime context (not file constants) and cannot be recovered statically, so c2/config/host_iocs could not be obtained; those items are marked dynamic and their pending-verification status was not cleared.
3. Only basic APIs are visible in the static import surface; if the payload stage requires networking/injection capabilities, they should be obtained through runtime dynamic resolution, and no evidence was obtained in this run.
4. Family attribution is a candidate (HijackLoader/IDAT Loader), based on the export masquerade and obfuscation implementation characteristics, lacking configuration or C2 corroboration.

## Evidence index

<details>
<summary>Show 18 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:5a42436a09` | Sample triage | Hash/imphash/section entropy/packing score 0/anomalies 0 |
| `ref:75a88e53e0` | PE structure parsing | PE64 DLL, image_base 0x180000000, 6 sections, TLS/export/debug directories |
| `ref:ae35feeedb` | pe.exports | dll_name=loader.dll, 14 exports (JLI_*) |
| `ref:898f18cd3e` | Import table parsing | 3 DLLs / 89 imports, no network/injection/crypto APIs |
| `ref:f85af4e0b2` | unpack.antidebug | IsDebuggerPresent + rdtsc + cpuid, three anti-analysis techniques |
| `ref:7c9fcd6cb8` | unpack.detect | No known packer identified |
| `ref:a2b75125bb` | decompile.function | TLS callback RVA 0xA510 |
| `ref:f1b94cd82d` | decompile.function | TLS callback writes constants/flags into the TLS block |
| `ref:b7b9057a0a` | decompile.function | FUN_1800088cf: 64-entry reverse lookup table + XOR + LZ decoder |
| `ref:f702470691` | decompile.function | FUN_180002196 computed-goto dispatcher |
| `ref:0b0efe2e23` | decompile.function | FUN_180009347 computed-goto dispatcher |
| `ref:2fac977dee` | script | Parses the 0xB0C18 table: 209 entries, 544,211 bytes total; locates the XOR loop |
| `ref:a07a460aa6` | script | Extracted 'LLD PDB.efork.pdb', 'loader.dll' and JLI_* export names from the string region |
| `ref:38711e055d` | dyn.run | Emulation observed the LoadLibraryExW+GetProcAddress call chain, with no file/network behavior |
| `ref:02f18f9c76` | Dynamic analysis platform | Original sample detonation: no new processes/no dumps/no network |
| `ref:348b83898b` | Dynamic analysis platform | Host emulation stub detonation: 2 processes started then exited, 6 memory dumps |
| `ref:99aae65d0a` | script | The encoding table in memory dumps is still ciphertext, with no plaintext C2/URL |
| `c2_evidence:c7fd3f91` | Connection evidence extraction | Dynamic network monitoring recorded 2 connection attempts to maps[.]windows[.]com:443, ocsp[.]digicert[.]com:443; no complete session was captured |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
