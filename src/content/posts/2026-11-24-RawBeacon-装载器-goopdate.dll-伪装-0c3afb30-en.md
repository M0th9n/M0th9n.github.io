---
title: "Malicious sample analysis: RawBeacon loader (goopdate.dll disguise) (PE · dll · 0c3afb30)"
published: 2026-11-24
draft: false
description: "Malicious (confidence: low): RawBeacon loader (goopdate.dll disguise) · loader/dropper · difficulty hard · static decompilation (dynamic execution yielded no runtime behavior)"
tags: ["RawBeacon 装载器", "loader", "dropper", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-24-RawBeacon-装载器-goopdate.dll-伪装-0c3afb30"
---

> [!WARNING]
> **Verdict: malicious** · Family **RawBeacon loader (goopdate.dll disguise)** (unconfirmed) · Confidence **low**
> 
> Aliases: rawbeacon.dll loader, goopdate.dll sideload loader
> 
> The decompilation evidence speaks for itself: the DLL masquerades as the Google Update component goopdate.dll, and its sole exported function DllEntry internally opens the decoy file cam_numbers_825e2c.pdf under %TEMP%, while using VirtualAlloc(0x3000,0x40) to manually map an embedded PE (rawbeacon.dll, SizeOfImage 0x6f000), fixing relocations, manually resolving its import table, calling its entry point, and locating and executing RunPayload via its export table; RunPayload then executes an embedded PIC loader in RWX memory, and this loader covertly resolves 22 system APIs (including RtlDecompressBuffer) through PEB traversal and custom hashing, and conceals the roughly 300KB final payload with a dual layer of base64 + byte-wise XOR + LZNT1. All of the above are reflective in-memory loading and payload concealment, with no legitimate software purpose.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **RawBeacon loader (goopdate.dll disguise)** · Aliases rawbeacon.dll loader, goopdate.dll sideload loader · _unconfirmed_ |
| Confidence | **low** |
| Behavior class | loader · dropper |
| Difficulty | hard |
| First seen | 2026-11-24 12:12:51 |
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/0c3afb30eca4de018a7a3aa42ab43acc4a3c998595ba1802da876feffb419bcc/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Masquerade as Google Update</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Drop and open PDF decoy</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Manually map embedded DLL</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Execute RunPayload by export name</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">RWX execution of embedded shellcode</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `0c3afb30eca4de018a7a3aa42ab43acc4a3c998595ba1802da876feffb419bcc` |
| MD5 | _Not recorded_ |
| Size | 447,960 bytes (437.5 KB) |
| Type | PE · `dll` |

## Behavior Analysis

There are **9** behaviors in total, each backed by evidence, and all are statically available.

### 1. Masquerade as Google Update component

`T1036.005` · Confidence **high** · Static

The DLL's own export table has the DLL name goopdate.dll and only one exported function, DllEntry, used to impersonate the Google Update component and be invoked by a host via sideloading.

> **Evidence**: pe.exports: dll_name=goopdate.dll, symbols=[DllEntry @ rva 0x1610]
> 
> **Source**: `ref:6d995fcc0a`

### 2. Drop and open PDF decoy

`T1204.002` · Confidence **high** · Static

It obtains the %TEMP% path, copies win.dll from its own directory to cam_numbers_825e2c.pdf, then opens this "document" with ShellExecuteExW(fMask=0x400, nShow=1) to create the illusion of normally reading a PDF.

> **Evidence**: FUN_693414e0 @ 0x693414e0: GetTempPathW -> wsprintfW(L"%s%s", tmp, L"cam_numbers_825e2c.pdf") -> GetModuleFileNameW/wcsrchr -> CopyFileW -> ShellExecuteExW
> 
> **Source**: `ref:71f0bb7ef8` · `ref:827290c4ca`

### 3. Manually map embedded DLL

`T1620` · Confidence **high** · Static

DllEntry first allocates 0x6f000 bytes of read-write-execute memory with VirtualAlloc (preferred base 0x6a180000), memcpys section by section according to the embedded image's section table, walks .reloc to fix relocations, then fills the IAT with LoadLibraryA/GetProcAddress per import-table entry.

> **Evidence**: DllEntry @ 0x69341610: VirtualAlloc(0x6a180000,0x6f000,0x3000,0x40); memcpy loop; \*puVar3 = \*puVar3 + delta; LoadLibraryA/GetProcAddress filling
> 
> **Source**: `ev-000016` · `ref:36903b2a81`

### 4. Execute RunPayload by export name

`T1620` · Confidence **high** · Static

After mapping completes it calls the embedded image entry point, then manually parses its export table, matches the string "RunPayload" with lstrcmpA, and calls that export directly through a function pointer.

> **Evidence**: DllEntry @ 0x69341610 tail: lstrcmpA(export_name, "RunPayload") == 0 -> call [puVar7 + export address]
> 
> **Source**: `ev-000016`

### 5. RWX execution of embedded shellcode

`T1620` · Confidence **high** · Static

The RunPayload export of the embedded rawbeacon.dll allocates 0x63a2e bytes of RWX memory, copies in the 408110-byte shellcode at its own rva 0x4044, and calls it directly after FlushInstructionCache, forming a fileless, position-independent loading chain.

> **Evidence**: RunPayload @ rawbeacon rva 0x14f0: VirtualAlloc(0,0x63a2e,0x3000,0x40) -> memcpy(&DAT_6a184044,0x63a2e) -> GetCurrentProcess/FlushInstructionCache -> (*_Dst)
> 
> **Source**: `ev-000025` · `ref:e26d924ebf`

### 6. Hidden resolution of system APIs via hashing

`T1027` · Confidence **high** · Static

The PIC loader walks the PEB module list and matches module and function names with a custom hash (ROR13 with seed 0xf4283c27), resolving 22 APIs including LoadLibraryA/GetProcAddress/VirtualAlloc/VirtualProtect/VirtualQuery/MapViewOfFile/CreateFileMappingA/RtlDecompressBuffer, leaving none of these names in the import table.

> **Evidence**: FUN_00402624 @ 0x402624 hash loop (uVar4=0xf4283c27; ror13; -0x20 when c>0x60) + FUN_0040299e PEB module walk; all 22 constants in FUN_004026f0 mapped to kernel32/ntdll export names
> 
> **Source**: `ev-000032` · `ev-000031` · `ref:743642c1a9`

### 7. Decrypt and decompress embedded payload

`T1140` · Confidence **high** · Static

The loader dispatches decoding by container entry type: type 1 is byte-wise repeating-key XOR, and type 4 calls RtlDecompressBuffer (format 2 = LZNT1) to decompress; the result is then mapped into memory per the PE section table and the entry point is jumped to.

> **Evidence**: FUN_00402bc3 @ 0x402bc3: dst[i] ^= key[i % keylen]; in entry @ 0x401000, (*pcStack_80c)(2, this, size, src, len, &out) corresponds to RtlDecompressBuffer(LZNT1)
> 
> **Source**: `ev-000033` · `ev-000028`

### 8. base64 concealment of encrypted payload

`T1027` · Confidence **high** · Static

The shellcode data region carries 399660 characters of pure base64 text (98% of the entire 408110-byte payload); after decoding it is 299744 bytes of high-entropy data with entropy 7.987, making static strings and YARA signatures hard to hit.

> **Evidence**: 399660 base64 characters starting at file offset 0x5a26; decoded length 299744, entropy 7.987; header 01000000c00000001092040010920400
> 
> **Source**: `ref:7ebccaae7c`

### 9. Abuse of a valid code signature

`T1553.002` · Confidence **medium** · Static

The outer DLL carries a 14808-byte Authenticode signature; the issuance chain is Microsoft ID Verified CS AOC CA 03, the signing subject is the individual ISABEL ALEJANDRA FLORES, and the timestamp is 2026-11-24, making the file show a "verified publisher" in its file properties.

> **Evidence**: SECURITY directory rva 433152 size 14808 (file offset 0x69C00); openssl parsing PKCS#7: subject=ISABEL ALEJANDRA FLORES, issuer=Microsoft ID Verified CS AOC CA 03
> 
> **Source**: `ref:859742b4b3` · `ref:7ebccaae7c`


## IOCs (defanged)

### Network

:::note
**No C2 / network IOCs were recovered** (see "Analysis Method and Limitations" at the end).
:::

### Host

**Drop path**

- `%TEMP%\cam_numbers_825e2c.pdf`
- `<DLL directory>\win.dll`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `api_resolution` | `PEB walk + custom ROR13 (seed=0xf4283c27, uppercase-accumulating) hash; module hashes kernel32.dll=0xb0af8c96 / ntdll.dll=0xef561b93; 22 API constants in total` | Yes | Static |
| `payload_encoding` | `embedded 399660-character base64 text -> 299744 bytes of high-entropy data (entropy 7.987), container header 01000000 c0000000 10920400 10920400` | Yes | Static |
| `encryption_algo` | `byte-wise repeating-key XOR (FUN_00402bc3) + RtlDecompressBuffer (COMPRESSION_FORMAT_LZNT1=2) decompression, dispatched by container entry type 1/2/3/4` | Yes | Static |
| `decoy_document` | `%TEMP%\cam_numbers_825e2c.pdf (actually a copy of win.dll, opened by ShellExecuteExW)` | Yes | Static |
| `c2_hosts` | `-` | Yes | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not assert that it is ransomware or a stealer: the final ~300KB payload was not decrypted, and no file encryption, credential reading, or browser data access was observed.
- No C2 address/port can be given: the loader layer has no ws2_32/wininet/WinHTTP imports, the encrypted payload was not unpacked, and the sandbox produced no network session.
- Do not claim successful execution on a real host: the sample is a DLL and requires a host EXE to call the exported DllEntry; sandbox submission produced no new process.
- Do not treat goopdate.dll as an official Google component, and do not attribute the source based solely on the signing subject (the signature may be an abused/resold certificate).
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution yielded no runtime behavior) |
| Unpacking | No |

**Limitations and pending verification**

1. The final payload (299744 bytes of high-entropy data) was not decrypted: the container entry layout and keys are constructed dynamically inside the PIC loader, and static analysis only reached the decoding-algorithm layer, so the C2, beacon URI, crypto suite, and family attribution cannot be confirmed.
2. The dynamic sandbox channel obtained no behavior this time: the sample is a DLL and no host in the guest called DllEntry; within the observation window there were no new processes, no memory dumps, and no network sessions, and network monitoring had no parseable connections.
3. Emulation (user-mode API emulation) advanced only to the CRT initialization stage (InitializeCriticalSection/_initterm/GetModuleHandleA/DisableThreadLibraryCalls, 8 calls in total) and did not enter the DllEntry loading logic, so it cannot serve as a behavioral basis.
4. The Authenticode signature was only parsed for certificate subject and issuance chain; revocation/timestamp validity checks were not performed, and it was not confirmed whether the certificate was revoked or resold.
5. The embedded image was compiled with MinGW-w64 (GCC 9.3/10), and its PE characteristics are hand-built/stripped of symbols, so the author's environment cannot be inferred from compiler information.

## Evidence Index

<details>
<summary>Expand 16 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:5ba04f1191` | Sample triage | sha256/md5/imphash aacb2e69d0124c38c8150f18be1a9539, 10 sections, no anomalies, packing.score=0 |
| `ref:859742b4b3` | PE structure parsing | PE32 i386 DLL, ImageBase 0x69340000, entry rva 0x13b0, SECURITY directory 14808 bytes |
| `ref:6d995fcc0a` | pe.exports | Export DLL name goopdate.dll, sole export DllEntry @ rva 0x1610 |
| `ref:7892c94bb4` | Import table parsing | Only KERNEL32/msvcrt/SHELL32/USER32, 36 symbols in total, including CopyFileW/GetTempPathW/GetModuleFileNameW/ShellExecuteExW/VirtualAlloc |
| `ref:827290c4ca` | String extraction | Hits on strings such as cam_numbers_825e2c.pdf, win.dll, RunPayload, kernel32.dll (offsets 0x1e60/0x1e78/0x1ed1) |
| `ref:36903b2a81` | PE structure parsing | Embedded stage1 PE: ImageBase 0x6a180000, SizeOfImage 0x6f000, exports rawbeacon.dll!RunPayload |
| `ev-000016` | decompile.function | DllEntry manually maps the embedded PE, fixes relocations, resolves imports, calls the entry point, and calls RunPayload by name |
| `ev-000037` | decompile.function | FUN_693414e0 copies win.dll from the same directory to %TEMP%\cam_numbers_825e2c.pdf and opens it with ShellExecuteExW |
| `ev-000025` | decompile.function | RunPayload allocates 0x63a2e RWX memory, memcpys the embedded shellcode, and calls it after FlushInstructionCache |
| `ev-000028` | decompile.function | PIC loader entry: parses PE sections, dispatches XOR/LZNT1 decoding by type 1/2/3/4, and maps and executes |
| `ev-000032` | decompile.function | Custom hash function: seed 0xf4283c27, ROR13 + uppercase accumulation, used for hidden API resolution |
| `ref:743642c1a9` | evidence.record | All 22 API hash constants mapped to kernel32/ntdll export names (computed by script) |
| `ref:7ebccaae7c` | evidence.record | base64 payload geometry (399660 characters -> 299744 bytes, entropy 7.987) and Authenticode signing subject (computed by script) |
| `ref:6be75a1a90` | Dynamic analysis platform | Rollback-start-submission observation: candidates=0, empty=true, no process/dump/network events |
| `ref:0d43e8ed00` | dyn.run | User-mode emulation reached only CRT initialization (8 API calls), did not enter the DllEntry main logic |
| `telemetry:0c3afb30` | Dynamic telemetry | Dynamic telemetry recorded: 91 process/file events from the monitoring component; 22 tool/system noise entries filtered out |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
