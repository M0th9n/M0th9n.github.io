---
title: "Malware Analysis: Unattributed JLI-masquerading loader (loader.dll) (PE · exe · 6897cd75)"
published: 2026-11-17
draft: false
description: "Malicious (low confidence): Unattributed JLI-masquerading loader (loader.dll) · loader/implant · difficulty hard · static decompilation (dynamic execution yielded no runtime behavior)"
tags: ["loader", "implant", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-17-Unattributed-JLI-masquerading-loader-loader.dll-6897cd75"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Unattributed JLI-masquerading loader (loader.dll)** (uncertain) · Confidence **low**
> 
> Aliases: jli.dll hijack loader, loader.dll UPX loader
> 
> The sample is an AMD64 DLL (PE Characteristics=DLL, entry point DllMain), packed with UPX 3.x and distributed with an .exe extension; the restored internal DLL name is loader.dll, and its export names exactly match the Java launcher library jli.dll, but exports such as JLI_Launch are all empty stubs that merely hand control to an internal dispatch function using constant obfuscation and table-based indirect jumps and then return 0; at the start of .data sits 226,235 characters of base64url-encoded data decoding to 169,676 bytes of high-entropy data (entropy 7.994), and the whole file contains no plaintext address, path or command. The combination of packing + masquerading as a runtime module + encrypted payload + control-flow obfuscation matches the loader form of "loading a subsequent encrypted payload via DLL side-loading". Because the payload is not decrypted and the DLL was not loaded by a host, its final functionality cannot yet be determined, so the confidence is medium-high.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unattributed JLI-masquerading loader (loader.dll)** · aliases jli.dll hijack loader, loader.dll UPX loader · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · implant |
| Difficulty | hard |
| First seen | 2026-11-13 20:00:27 |
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/6897cd75ff8b2a4063aa496851af05101ef9d149ac22d3e74df44f5c0f03670a/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX-packed, renamed and distributed</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Masquerade jli.dll exports</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">All exports are empty stubs</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Built-in 169KB encrypted payload</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.013</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Constant-obfuscated table jumps</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `6897cd75ff8b2a4063aa496851af05101ef9d149ac22d3e74df44f5c0f03670a` |
| MD5 | _not recorded_ |
| Size | 441,344 bytes (431.0 KB) |
| Type | PE · `exe` |

## Behavior analysis

**8** behaviors in total, each backed by evidence, all statically recoverable.

### 1. UPX-packed, renamed and distributed

`T1027.002` · Confidence **high** · static

The sample is a 441,344-byte AMD64 DLL (PE Characteristics=DLL, GUI subsystem, unsigned); its section table contains only UPX0/UPX1/UPX2, UPX1 has entropy 7.999 and only 5 imported symbols. The UPX unpacker fully restores a normal 643,584-byte image containing .text/.rdata/.data/.pdata/.tls/.reloc, showing the outer layer is just a compression packer.

> **Evidence**: scan.triage section table UPX0/UPX1/UPX2, UPX1 entropy 7.999; the import table at 0x6B8B0, file offset 0x6B890, imports only LoadLibraryA/GetProcAddress/VirtualProtect/WaitOnAddress/GetFocus; unpacked file 643,584 bytes
> 
> **Source**: `ev-000008` · `ev-000004` · `ev-000002` · `ref:a13c91742b` · `ref:a9378dbeaf`

### 2. Masquerade jli.dll exports

`T1036.005` · Confidence **high** · static

The restored DLL's internal name is loader.dll; its export table contains 7 named exports that exactly match the Java launcher library jli.dll (JLI_Launch, JLI_GetStdArgs, JLI_GetStdArgc, JLI_CmdToArgs, JLI_InitArgProcessing, JLI_MemAlloc, JLI_MemFree), followed by 7 unnamed ordinal exports (8-14) that repeatedly point to the same set of RVAs — a legitimate jli.dll would not have anonymous duplicate exports.

> **Evidence**: export directory rva 0x617F8; export name table file off 0x6B99E: 'loader.dll', 'JLI_CmdToArgs', 'JLI_GetStdArgc', etc.; ordinals 8-14 unnamed
> 
> **Source**: `ref:f1950f967f` · `ev-000011`

### 3. All exports are empty stubs

`T1027` · Confidence **high** · static

Exports such as JLI_Launch(0x18000AECF), JLI_GetStdArgs(0x180001982), JLI_MemAlloc(0x180009E22), JLI_MemFree(0x180009CE8), JLI_CmdToArgs(0x180009CFD) and JLI_GetStdArgc(0x18000BC83) all perform a single state check, then call the same internal function 0x180001A7D and return 0; the real JVM loading, command-line parsing and memory-allocation logic is entirely absent, and the export table serves only as an entry point that triggers the internal flow when called by a host.

> **Evidence**: decompile JLI_MemAlloc/JLI_MemFree/JLI_CmdToArgs/JLI_GetStdArgc are all FUN_180001a7d; return 0;
> 
> **Source**: `ev-000022` · `ev-000032` · `ev-000033` · `ev-000034` · `ev-000035`

### 4. Built-in 169KB encrypted payload

`T1027.013` · Confidence **high** · static

The start of .data (rva 0x64000) is a 226,235-character URL-safe base64 string decoding to 169,676 bytes: entropy 7.994, no repeated 16-byte blocks, and IOC values of about 0.004 for k=1..16, indicating encrypted/compressed data rather than plaintext; no URL, file path or command appears anywhere in the file. Immediately after it are 210 16-byte records (rva|0x80000000, 1, size, 0) contiguously covering .rdata/.data from rva 0x1B000-0x9B3BB, resembling a runtime mapping/decryption section table.

> **Evidence**: 226,235-character base64url from file off 0x62400; decodes to 169,676 bytes, entropy 7.994; 210 section records from 0x997F0
> 
> **Source**: `ev-000040` · `ev-000021` · `ref:a25f4529f6` · `ref:6aac9a82d6`

### 5. Constant-obfuscated table jumps

`T1027` · Confidence **medium** · static

The dispatch function 0x180001A7D performs indirect jumps as (&LAB_180001FAC + table entry), with table entries in .rdata 0x59294; code after 0x180001FAC repeatedly uses constants in the 0x3966C6xx / 0x6CEF76xx range (0x3966C6D3, 0x3966C6F2, 0x6CEF76BE, etc.) combined with movsxd/jmp rax to dispatch, and decompilation reports "Could not recover jumptable" extensively, consistent with control-flow flattening/a custom interpreter.

> **Evidence**: 0x180001A7D: jmp &LAB_180001FAC + *(int*)(&DAT_180059294+0x27C/0x5A0); 0x180001FEC: xor ebx,0x3966C6D3; the same pattern from 0x180002206
> 
> **Source**: `ev-000024` · `ref:5c2503b55a` · `ref:390147662c` · `ev-000037`

### 6. TLS callback participates in initialization

`T1497.001` · Confidence **medium** · static

The PE's TLS directory (rva 0x5EDC0) registers callback 0x180001A60 (tls_callback_0), which executes 0x1800018A0 on DLL_PROCESS_ATTACH/DETACH, writing a batch of constants into the thread TLS template block +0x08..+0x25 and setting +0x22 to 1; export functions then read the 32-bit marker values at TLS+0x40 and +0x78 to decide branches, forming an early execution path isolated from the normal static view.

> **Evidence**: TLS directory rva 0x5EDC0; tls_callback_0 @0x180001A60 → FUN_1800018A0 writes +0x22=1; JLI_Launch compares TLS+0x78==0x8CE61C75
> 
> **Source**: `ev-000027` · `ev-000029` · `ref:f713c34dbf` · `ev-000022`

### 7. Probe foreground window and process time

`T1010, T1497.003` · Confidence **medium** · static

After the TLS marker hits, JLI_Launch calls GetForegroundWindow / GetFocus / GetWindowRect; JLI_GetStdArgs calls GetCurrentProcess / GetThreadId / GetProcessTimes / FileTimeToSystemTime. The query results are discarded and actually only used to change subsequent branches or fill structures, consistent with environment and time side-channel probing (an unattended environment usually has no foreground window).

> **Evidence**: JLI_Launch @0x18000AECF: GetForegroundWindow/GetFocus/GetWindowRect; JLI_GetStdArgs @0x180001982: GetProcessTimes/FileTimeToSystemTime
> 
> **Source**: `ev-000022` · `ev-000023`

### 8. Designed for host side-loading

`T1574.002` · Confidence **medium** · static

The file lands with an .exe extension, but the PE is a DLL (entry DllMain, and DllMain only performs CRT initialization), with the internal name loader.dll, exporting the jli interfaces a host expects; as soon as a host process (e.g. java.exe) loads this module from the same directory and calls any export, the internal flow at 0x180001A7D is triggered, matching the delivery form of DLL side-loading/proxy loading.

> **Evidence**: PE Characteristics=DLL + export names match jli.dll + all export stubs forward to 0x180001A7D + DllMain only calls __DllMainCRTStartup
> 
> **Source**: `ref:d0eee70122` · `ref:f1950f967f` · `ev-000024` · `ev-000025` · `ev-000030`


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
| `container` | `UPX 3.x packer (sections UPX0/UPX1/UPX2, UPX1 entropy 7.999), restorable to a 643,584-byte, 6-section original DLL` | yes | static |
| `internal_dll_name` | `loader.dll` | yes | static |
| `masquerade_as` | `jli.dll (Java launcher library) export interface` | yes | static |
| `embedded_payload` | `URL-safe base64 string, file offset 0x62400 (rva 0x64000), 226,235 characters → 169,676 bytes` | yes | static |
| `payload_encryption` | `unknown custom/stream encryption (entropy 7.994; 169,676 is not a multiple of 16 bytes; only the base64url alphabet detected, no AES/SHA/RC4 constants)` | yes | static |
| `runtime_range_table` | `210 16-byte records (rva\|0x80000000, 1, size, 0) from file off 0x997F0, contiguously covering .rdata/.data from rva 0x1B000-0x9B3BB` | no | static |
| `c2_hosts` | `-` | yes | static |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- No specific malicious function (remote control/stealing/downloading/ransomware, etc.) can be determined from this: the 169,676-byte payload has not been decrypted, and the sample has no imports related to networking, registry or process creation.
- The JLI_* export names or the loader.dll name cannot be taken as evidence that "the sample is a Java program" or as evidence of family attribution: there are no jvm.dll, JNI or java-related strings in the binary, and export interfaces can be forged.
- It cannot be claimed that C2, outbound connections or persistence were observed: the live dynamic sandbox showed no network requests, child processes or registry writes related to this sample.
- The IsDebuggerPresent import cannot be used to assert anti-debug protection: that import is a routine reference from the statically linked UCRT, and no calls were observed in dynamic emulation either.
- The base64 string in .data cannot be treated as plaintext configuration or a directly readable C2 list; once decoded it is high-entropy encrypted data.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Unpacking | yes (stage2 `419d2b4539de3805c0a77f979ef8ba952be6e310901f27aafe46a8a8cf1f1a12`) |

**Limitations and pending verification**

1. The sample is a DLL (PE Characteristics=DLL, entry DllMain); after automatic submission to the sandbox it produced no child processes and no network requests or file writes related to the sample, so the final payload's functionality, C2 and persistence method were not dynamically confirmed.
2. The built-in 169,676-byte payload uses custom/stream encryption (entropy 7.994, not a multiple of 16 bytes, only the base64url alphabet detected, no AES/SHA/RC4 constants) and cannot be decrypted statically; the decryption flow is in the obfuscated dispatcher, and pure CPU emulation fails right at the TLS read (invalid_mem@0x58, 0x180001993).
3. The sample has no digital signature (Security directory is 0) and its compile timestamp corresponds to 2026-11-13; there are no YARA hits, multi-engine verdicts or public sandbox reports for cross-validation, so the family attribution is only a candidate.
4. The purpose of the 210 (rva|0x80000000, 1, size, 0) records immediately following the payload (suspected runtime mapping/decryption section table) is inferred and not dynamically verified.
5. The export stubs were never called in the sandbox, so the chain "calling an export triggers decryption" is a judgment based on static control flow and still lacks runtime evidence.

## Evidence index

<details>
<summary>Expand 12 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:d0eee70122` | PE structure parsing | original file: AMD64 DLL, 3 sections (UPX0/1/2), entry rva 0xA3770, unsigned |
| `ev-000008` | sample triage | packing likelihood 85%: UPX section names, W^X, 5 imported symbols |
| `ref:81415375e3` | unpack.detect | determined UPX, confidence 0.9 |
| `ref:a9378dbeaf` | upx -d | restored the original 643,584-byte DLL (sha256 419d2b45…) |
| `ref:f1950f967f` | pe.exports | loader.dll has 14 exports, 7 named JLI_* exports + 7 anonymous duplicates |
| `ev-000022` | decompile | JLI_Launch @0x18000AECF: window queries then calls FUN_180001a7d, return 0 |
| `ev-000024` | decompile | FUN_180001a7d: TLS marker write + table-based indirect jumps |
| `ev-000027` | decompile | tls_callback_0 @0x180001A60: executes FUN_1800018A0 on ATTACH/DETACH |
| `ev-000040` | script | extracted and decoded the 226,235-character base64url in .data → 169,676 bytes of high-entropy data, located 210 section records |
| `ref:9ec27e421f` | crypto constant identification | only the URL-safe base64 alphabet detected (rva 0x576DC), no block-cipher constants |
| `ref:810a677e1f` | dynamic analysis platform | live dynamic sandbox submission for 150 seconds: 0 candidate processes, 0 memory dumps, no sample-related network requests, object rolled back |
| `telemetry:6897cd75` | dynamic telemetry | dynamic telemetry recorded: monitoring component 97 process/file events; 27 filtered tool/system noise entries |

</details>

---

_The sample in this report is not public; IOCs are defanged, for security research only._
