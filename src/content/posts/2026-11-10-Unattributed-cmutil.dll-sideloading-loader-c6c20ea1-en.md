---
title: "Malware Analysis: Unattributed cmutil.dll sideloading loader (PE · exe · c6c20ea1)"
published: 2026-11-10
draft: false
description: "Malicious (low confidence): Unattributed cmutil.dll sideloading loader · loader/injector/dropper · difficulty hard · Static decompilation (dynamic execution produced no runtime behavior)"
tags: ["loader", "injector", "dropper", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-10-Unattributed-cmutil.dll-sideloading-loader-c6c20ea1"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Unattributed cmutil.dll sideloading loader** (uncertain) · Confidence **low**
> 
> Decompilation and user-mode emulation jointly confirmed: the file is an x64 loader disguised as cmutil.dll, embedding a 958682-byte encrypted payload that is restored into a complete PE32+ through three rounds of positional addition, whole-segment reversal, and adjacent-byte swapping; it then resolves injection APIs such as VirtualAllocEx/WriteProcessMemory/CreateRemoteThread/GetThreadContext/SetThreadContext and NtCreateSection/NtMapViewOfSection/NtUnmapViewOfSection, changes the memory protection of 9 MessageBox/DialogBox functions, and installs a WH_CBT hook. The export table, version information, and digital signature are all decoys.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unattributed cmutil.dll sideloading loader** · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · injector · dropper |
| Difficulty | hard |
| First seen | 2026-11-07 16:32:24 |
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/c6c20ea175d882477847c3f18d2f9fcf40c12cb83d049c1105f8f4f660586a40/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Fake cmutil.dll exports</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Forged version and signature</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded PE payload</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Validate PE header, drop temp file</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Process hollowing injects payload</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `c6c20ea175d882477847c3f18d2f9fcf40c12cb83d049c1105f8f4f660586a40` |
| MD5 | _not recorded_ |
| Size | 1,009,640 bytes (986.0 KB) |
| Type | PE · `exe` |

## Behavior analysis

**9** behaviors in total, each backed by evidence, and all statically available.

### 1. Fake cmutil.dll exports

`T1574.002` · Confidence **high** · static

Exports 57 RAS Connection Manager APIs (CmFree/CmMalloc/CmStrStrA/GetOSVersion/IsLogonAsSystem, etc.) under the internal name cmutil.dll, so that the sideloading host does not fail due to missing symbols when resolving the import table.

> **Evidence**: pe.exports: dll_name=cmutil.dll, ordinal_base=1, count=57, .edata RVA 0xF9000
> 
> **Source**: `ref:ea68241aec`

### 2. Forged version and signature

`T1553.002` · Confidence **high** · static

Writes the random company name yCYrOmYjqTirgB and version 2.7.9[.]214 into the resource section, and appends a 7144-byte WIN_CERTIFICATE (type=2, DigiCert timestamp chain) at the end of the file to boost credibility.

> **Evidence**: StringFileInfo CompanyName/ProductName=yCYrOmYjqTirgB; WIN_CERTIFICATE len=7144 rev=0x200 type=2 @ off 1002496
> 
> **Source**: `ref:59839b43ae` · `ref:07668d641e`

### 3. Decrypt embedded PE payload

`T1027.009` · Confidence **high** · static

Copies the 958682-byte data in .rdata to the heap, then restores a complete PE32+ (sha256 deefc7fa…) through three rounds of positional addition, whole-segment reversal, and adjacent-byte swapping, and hands it to the injector.

> **Evidence**: FUN_2783f2200 @0x2783f2200 three rounds of add byte[i], i*k+c; called by FUN_2783f4960 @0x2783f4960, keys -2/-0x5a/-0x12
> 
> **Source**: `ev-000033` · `ev-000032` · `ref:d8a0f39572`

### 4. Validate PE header and drop temp file

`T1105` · Confidence **high** · static

After validating that the buffer is MZ/PE, machine=0x8664, optional magic=0x20B, and SizeOfImage is valid, it calls GetTempPathW, builds a temporary file name (prefix td), writes it to disk with CreateFileW at 0xC0010000 access, and then executes it via CreateProcessW/injection.

> **Evidence**: FUN_2783f32c0 @0x2783f32c0: *buf=='M''Z', buf[e_lfanew+4..5]==0x8664, magic==0x20b, GetTempPathW+GetTempFileNameW+CreateFileW(0xc0010000)
> 
> **Source**: `ev-000031` · `ref:46e1c83b4d`

### 5. Process hollowing to inject the payload

`T1055.012` · Confidence **high** · static

Resolves and calls NtCreateSection/NtMapViewOfSection/NtUnmapViewOfSection/NtQueryInformationProcess/NtWriteVirtualMemory, together with VirtualAllocEx/WriteProcessMemory/CreateRemoteThread/GetThreadContext/SetThreadContext/ResumeThread, to write the decrypted PE into the target process and execute it.

> **Evidence**: FUN_2783f2df0 resolves WriteProcessMemory/VirtualAllocEx/CreateRemoteThread/WaitForSingleObject/GetThreadContext/SetThreadContext/TerminateProcess/FlushInstructionCache/LdrLoadDll; FUN_2783f32c0 resolves NtCreateSection/NtMapViewOfSection/NtUnmapViewOfSection/NtWriteVirtualMemory/NtQueryInformationProcess/NtClose
> 
> **Source**: `ev-000029` · `ev-000031` · `ref:635123fef6`

### 6. Install WH_CBT hook

`T1055` · Confidence **high** · static

After dynamically resolving the API, it calls SetWindowsHookExW(5, callback 0x2783f2440, NULL, GetCurrentThreadId); the callback directly returns 1 for windows with class name #32770, and passes the rest to CallNextHookEx.

> **Evidence**: user32.SetWindowsHookExW(WH_CBT, 0x2783f2440, 0x0, 0x434), emulation PC=0x2783f270b; FUN_2783f2440 compares L"#32770"
> 
> **Source**: `ev-000027` · `ev-000028` · `ref:635123fef6`

### 7. Hijack dialog APIs

`T1055` · Confidence **high** · static

For MessageBoxW/A, MessageBoxExW/A, MessageBoxIndirectW/A, DialogBoxParamW/A, and SoftModalMessageBox one by one, it changes the protection to PAGE_EXECUTE_READWRITE via VirtualProtectEx and overwrites the entry point, suppressing popups and error prompts to remain silent.

> **Evidence**: kernel32.VirtualProtectEx(hProcess=-1, lpAddress=MessageBoxW/…, 6, PAGE_EXECUTE_READWRITE, …) 9 consecutive times, PC=0x2783f239e
> 
> **Source**: `ev-000030` · `ref:635123fef6`

### 8. Enumerate processes to locate the target

`T1057` · Confidence **medium** · static

The string table contains CreateToolhelp32Snapshot/Process32FirstW/Process32NextW/OpenProcess/GetShellWindow/GetWindowThreadProcessId, indicating that it enumerates processes and uses the process owning the shell window as the injection candidate.

> **Evidence**: XOR 0x40 decoded string table @0x2783f9400: Process32NextW/Process32FirstW/CreateToolhelp32Snapshot/OpenProcess/GetShellWindow/GetWindowThreadProcessId
> 
> **Source**: `ref:c9161d8ec0` · `ev-000029`

### 9. Pad with noise to counter detection

`T1027.001` · Confidence **high** · static

.rdata is padded with 270KB of linear recurrence (stepping 0x16 every 2 bytes, with no code references) and 582KB of high-entropy data to inflate the file to nearly 1MB; the second-stage .rdata is also stuffed with many misspelled fake identifiers to interfere with string and size heuristics.

> **Evidence**: scan.triage: .rdata entropy 7.999/963072 bytes; statistics show 0x22200-0x64200 satisfies byte[i]-byte[i-2]==0x16; stage2 .rdata from 0x7b008 contains truncated strings such as dowstream6hidden/servr_dep
> 
> **Source**: `ev-000005` · `ref:b081f04c8c` · `ev-000034`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis method and limitations" at the end for the reason).
:::

### Host

**Dropped paths**

- `%TEMP%\td????.tmp`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `embedded_payload_sha256` | `deefc7fa1918dc94b5ac88865f6a775de4f541009e7517b6865ad3de1f52ce9b` | yes | static |
| `embedded_payload_format` | `PE32+ x64, 5 sections, entry RVA 0x5f100, no import table, .data 309KB obfuscated` | yes | static |
| `payload_cipher` | `Custom positional addition cipher: 3 rounds of byte += i*k + c (k=-31/-13/-7, c=0xFE/0xA6/0xEE), with whole-segment reversal and adjacent-byte swapping in between; not AES/RC4` | yes | static |
| `injection_api_set` | `VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, GetThreadContext, SetThreadContext, ResumeThread, VirtualProtectEx, TerminateProcess, FlushInstructionCache, NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection, NtWriteVirtualMemory, NtQueryInformationProcess` | yes | static |
| `hooked_ui_apis` | `MessageBoxW/A, MessageBoxExW/A, MessageBoxIndirectW/A, DialogBoxParamW/A, SoftModalMessageBox` | yes | static |
| `hook_type` | `SetWindowsHookExW(WH_CBT=5, callback 0x2783f2440, hMod=NULL, current thread)` | yes | static |
| `c2_hosts` | `-` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- Do not judge it as a legitimate RAS/Microsoft component just from the cmutil.dll export table, version information, and digital signature—exports, version, and signature are all forgeable cover.
- No network connection, DNS query, or HTTP session was observed in this run, so it cannot be called a downloader or said to have a C2 server.
- The available evidence only covers loading, dropping, and injection; no credential theft, encryption ransomware, mining, or lateral movement was seen, so it should not be classified as stealer/ransomware/miner.
- The sample is a DLL and the real sandbox produced no new process, so it cannot be claimed that persistence was completed or that it executed successfully in a host process.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Unpacking | Yes (stage2 `deefc7fa1918dc94b5ac88865f6a775de4f541009e7517b6865ad3de1f52ce9b`) |

**Limitations and open questions**

1. The second stage is a heavily obfuscated x64 PE (no import table, entry full of invalid instructions and PEB access); function-level recovery was not completed, and its C2, configuration, and final payload type are unknown.
2. In the real sandbox the DLL had no host to load it, producing no new process, file, or network events; dynamic conclusions come only from user-mode emulation and static inference.
3. No vendor engine or YARA corroboration was obtained, so family attribution can only be left blank and marked uncertain.
4. The temporary file name is generated at runtime by GetTempFileNameW; the specific file name and path cannot be determined statically, and only the form %TEMP%\td????.tmp can be given.
5. The injection target process is determined by runtime process enumeration results; the specific PID or process name cannot be determined statically.

## Evidence index

<details>
<summary>Show 24 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprinting | sha256/md5/sha1/size baseline |
| `ev-000005` | scan.entropy | .rdata entropy 7.999 (963072 bytes), suggesting encrypted or padding data |
| `ev-000016` | String extraction | First-layer string extraction, no URL/domain/flag seen |
| `ev-000017` | decompile.ghidra | DllMain CRT wrapper function 0x2783f101d |
| `ev-000024` | decompile.ghidra | 0x2783f4a50: DisableThreadLibraryCalls + calls 0x2783f31b0 (payload entry) |
| `ev-000025` | decompile.ghidra | 0x2783f31b0: resolves APIs, GetModuleHandleA(user32), calls 0x2783f2740 and 0x2783f2550 |
| `ev-000027` | decompile.ghidra | 0x2783f2550: SetWindowsHookExW(5, 0x2783f2440, 0, tid) |
| `ev-000029` | decompile.ghidra | 0x2783f2df0: resolves WriteProcessMemory/VirtualAllocEx/CreateRemoteThread and other injection APIs |
| `ev-000030` | decompile.ghidra | 0x2783f2740: processes user32 dialog/message-box APIs one by one |
| `ev-000031` | decompile.ghidra | 0x2783f32c0: PE header validation, temp file drop, and execution/injection |
| `ev-000032` | decompile.ghidra | 0x2783f4960: copies the .rdata encrypted block, calls 0x2783f2200 to decrypt, hands off to 0x2783f32c0 |
| `ev-000033` | decompile.ghidra | 0x2783f2200: custom cipher of three rounds of positional addition + reversal + odd/even swapping |
| `ev-000034` | String extraction | Second-stage .rdata truncated fake identifier strings (noise) |
| `ref:ea68241aec` | pe.exports | cmutil.dll 57 exports (Cm*/GetOS*/IsLogonAsSystem) |
| `ref:59839b43ae` | decompile.symbols | Resource version information yCYrOmYjqTirgB / 2.7.9[.]214 / cmutil.dll |
| `ref:07668d641e` | manual | WIN_CERTIFICATE type=2 len=7144 and DigiCert timestamp chain |
| `ref:c9161d8ec0` | manual | XOR 0x40 decoded string table: process enumeration/injection/hook API list |
| `ref:b081f04c8c` | script | Counts the .rdata padding region (0x22200-0x64200, byte[i]-byte[i-2]=0x16) |
| `ref:d8a0f39572` | script | Applies the FUN_2783f2200 forward transform to recover MZ/PE32+, length 958682 |
| `ref:46e1c83b4d` | script | Parses the second-stage PE header: 5 sections, entry 0x5f100, no import table |
| `ref:b9183ac6c5` | PE structure parsing | stage2.bin PE32+ structure profile (no imports/exports) |
| `ref:635123fef6` | dyn.run | Emulation: resolves injection APIs, 9 VirtualProtectEx(MessageBox*) calls, SetWindowsHookExW(WH_CBT) |
| `ref:2d26d737c2` | Dynamic analysis platform | Real sandbox polled 442 times, 0 new processes and dumps, DLL not executed without a host |
| `telemetry:c6c20ea1` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 92; filtered tool/system noise 27 |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
