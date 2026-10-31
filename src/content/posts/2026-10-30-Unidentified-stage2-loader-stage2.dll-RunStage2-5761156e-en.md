---
title: "Malware Analysis: Unidentified stage2 loader (stage2.dll/RunStage2) (PE · exe · 5761156e)"
published: 2026-10-30
draft: false
description: "Malicious (low confidence): Unidentified stage2 loader (stage2.dll/RunStage2) · loader/dropper/injector · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Unidentified stage2 loader", "loader", "dropper", "injector", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-30-Unidentified-stage2-loader-stage2.dll-RunStage2-5761156e"
---

> [!WARNING]
> **Verdict: malicious** · Family **Unidentified stage2 loader (stage2.dll/RunStage2)** (uncertain) · Confidence **low**
> 
> Static analysis decrypted an embedded Russian-language decoy document and launched it through explorer; after de-shuffling, the tail overlay decrypted into a stage2 PE with process-injection capability; in the real dynamic sandbox the sample process (pid 676) repeatedly made HTTP GET callbacks to 151.244.30[.]118:80.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unidentified stage2 loader (stage2.dll/RunStage2)** · _uncertain_ |
| Confidence | **low** |
| Behaviour class | loader · dropper · injector |
| Difficulty | medium |
| First seen | 2026-10-29 06:28:26 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/5761156e111a1a20364b9c6f91afa524533a24bbd73217bbb0add2d492cd89cf/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Read overlay payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Decrypt decoy container</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Drop Russian decoy PDF</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Open PDF via explorer</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">HTTP GUID-path callback</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `5761156e111a1a20364b9c6f91afa524533a24bbd73217bbb0add2d492cd89cf` |
| MD5 | _not recorded_ |
| Size | 523,476 bytes (511.2 KB) |
| Type | PE · `exe` |

## Behaviour analysis

**8** behaviours in total, each tied to evidence; **7** are statically recoverable and **1** was obtained dynamically.

### 1. Read its own overlay payload

`T1027` · Confidence **high** · static

After GetModuleFileNameW obtains its own path, CreateFileW/ReadFile open itself; it computes the overlay start from the last section's page-aligned RVA+VirtualSize and reads all appended data into heap memory.

> **Evidence**: 0x140004197: GetModuleFileNameW/CreateFileW/GetFileSize/SetFilePointerEx/ReadFile; 0x1400042da parses the PE section table to compute the aligned length
> 
> **Source**: `ev-000018`

### 2. Decrypt the embedded decoy container

`T1140` · Confidence **high** · static

Decrypts the data at .text rva 0x4710, length 0x1cf23, with a custom xorshift stream cipher (seed 0x7afffe80), producing a [count][nameLen][dataLen][name][data] container with count=1.

> **Evidence**: 0x140003ce2 stream-cipher implementation (xorshift/mul 0x9e3779b1/add 0xfef3133e/rol26); 0x140003999 parses the container; seed@rva 0x21634=0x7afffe80, length@0x4708=0x1cf23
> 
> **Source**: `ev-000019` · `ev-000016` · `ev-000033`

### 3. Drop the Russian decoy PDF

`T1027.009` · Confidence **high** · static

Writes the container's only file, Запрос.pdf (118,535 bytes, %PDF-1.7), to %LOCALAPPDATA%\Temp\ or (fallback) %TEMP%\, then closes the handle.

> **Evidence**: 0x140003999: CreateFileA(GENERIC_WRITE/CREATE_ALWAYS)+WriteFile; during dynamic emulation file_access create/write of 118535 bytes to C:\Windows\temp\\Запрос.pdf
> 
> **Source**: `ev-000016` · `ev-000033` · `ref:0fd46fad6e`

### 4. Open the PDF via explorer

`T1204.002` · Confidence **high** · static

ShellExecuteA(NULL, "open", "explorer.exe", <decoy path>, NULL, SW_SHOW) has explorer open the document on its behalf, avoiding the direct CreateProcess trail.

> **Evidence**: end of 0x140003999: ShellExecuteA(hwnd=0, "open", "explorer.exe", path, 0, 5); dynamic emulation pc=0x140003c91
> 
> **Source**: `ev-000016` · `ref:0fd46fad6e`

### 5. De-shuffle and decrypt stage 2

`T1140` · Confidence **high** · static

Applies a 32-segment pseudo-random gap-removal de-shuffle to the overlay (0x58ad4 bytes), then decrypts the first 0x24c00 bytes with seed 0x7fbb2404, yielding an AMD64 PE (stage2.dll, export RunStage2, EntryPoint 0x31a0).

> **Evidence**: 0x140004423 de-shuffle (parameters 0x58ad4/0x3aa00/seed 0xefbf3105/5/58/0/3, segment-length table@0x21660); 0x140001603 calls 0x140003ce2 to decrypt; 0x140001d2d chains the calls
> 
> **Source**: `ev-000022` · `ev-000026` · `ev-000029` · `ev-000033`

### 6. Inject and execute the stage-2 module

`T1055.012` · Confidence **medium** · static

stage2 has imports and dynamically resolved strings such as VirtualAllocEx/WriteProcessMemory/VirtualProtectEx/GetThreadContext/SetThreadContext/ResumeThread/NtUnmapViewOfSection/NtCreateSection/NtMapViewOfSection/CreateProcessInternalW, forming a remote process injection/hollowing execution chain; the main sample hands this module and a data buffer to the loader through a function pointer.

> **Evidence**: stage2 string table 0x1dd1c-0x1de0b: ZwQueryVirtualMemory/NtUnmapViewOfSection/NtMapViewOfSection/NtCreateSection/CreateProcessInternalW; 0x1400032f6 calls indirectly through DAT_140027780+ctx[0]
> 
> **Source**: `ev-000033` · `ev-000031`

### 7. HTTP GUID-path callback

`T1071.001` · Confidence **high** · dynamic

The sample process (pid 676) repeatedly issues GET /66ccc916-eeea-4c41-a612-445cf6ef5a1c to 151.244.30[.]118:80 with User-Agent Mozilla/5.0, retrying about every 0.5 seconds until the sandbox stopped it.

> **Evidence**: network-monitoring log: 'Diverter 5761156e...exe (676) requested TCP 151.244.30[.]118:80', then 'GET /66ccc916-eeea-4c41-a612-445cf6ef5a1c HTTP/1.1' (about 110 times in 8 seconds)
> 
> **Source**: `ref:1f73be6e83` · `ref:e1a9987fae`

### 8. Forged vendor version information

`T1036.005` · Confidence **high** · static

Resource version information masquerades as CompanyName=Jacobson Logistics, FileDescription=Shell Plugin Broker, OriginalFilename=shellpluginhost.exe, FileVersion=9.52.8111.397, with no digital signature.

> **Evidence**: VS_VERSION_INFO string table (extracted by decompile.symbols): Jacobson Logistics / Shell Plugin Broker / shellpluginhost.exe
> 
> **Source**: `ref:76c099623b`


## IOCs (defanged)

### Network

:::note
**Connection observed dynamically**: the sample actually initiated TCP connections to this target (retrying several times within a short period).
:::

:::caution
**The real server side remains unverified**: the connections above were completed against a local controlled emulation service; the real C2 responses and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://151.244[.]30[.]118/66ccc916-eeea-4c41-a612-445cf6ef5a1c` | 80 | c2 | dynamic | observed |

### Host

**Drop paths**

- `%TEMP%\Запрос.pdf`
- `%LOCALAPPDATA%\Temp\Запрос.pdf`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `decoy_document` | `Запрос.pdf` | yes | static |
| `drop_path` | `%TEMP%\Запрос.pdf (prefers %LOCALAPPDATA%\Temp\Запрос.pdf)` | no | static |
| `encryption_algo` | `custom stream cipher: xorshift32 generates state, key=(state*0x9e3779b1+0xfef3133e), byte-by-byte XOR; feedback state=rol26(cipher_dword^state); decoy container seed=0x7afffe80, stage2 seed=0x7fbb2404` | yes | static |
| `payload_transform` | `32-segment pseudo-random gap-removal de-shuffle (seed=0xefbf3105, parameters 5/58/0/3, segment-length table 22-24) then decrypt the first 0x24c00 bytes` | yes | static |
| `stage2_module` | `stage2.dll (export RunStage2, AMD64, ImageBase 0x180000000, EntryPoint 0x31a0)` | yes | static |
| `c2_endpoint` | `hxxp://151.244[.]30[.]118/66ccc916-eeea-4c41-a612-445cf6ef5a1c` | yes | dynamic |
| `user_agent` | `Mozilla/5.0` | no | dynamic |
| `beacon_behavior` | `continuous GET of the same GUID path at ~0.5s intervals (~110 times in 8s)` | no | dynamic |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not classify as ransomware/wiper: no user-file encryption, deletion or ransom message was observed.
- Do not describe the decoy PDF as an exploit document: it contains no /JS, /JavaScript, /OpenAction, /Launch, /EmbeddedFile, /AA or /URI action.
- Do not claim persistence was confirmed: no Run key, service or scheduled-task write was observed this run.
- Do not classify as an infostealer: no browser-credential, keylogging, clipboard or wallet behaviour was observed.
- Do not assert family attribution: apart from build artifacts and callback traits, no family-specific identifier was obtained.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | yes (stage2 `a8f9df819ff42e8d50423075989162d48fef10c51b47bd2c4b0a5a00b88a0959`) |

**Limitations and pending verification**

1. The C2 address and GUID path come only from dynamic observation; no cleartext IP was found in the static payload (presumably decrypted at runtime), so the C2 is marked dynamic.
2. stage2's full config, later delivered content and injection target process could not be observed: the memory-forensics sample was taken early, before the injection region was captured.
3. The sandbox window was limited; no persistence, privilege escalation or data-exfiltration traffic was observed, and no C2 response was obtained.
4. The decoy PDF itself has no script actions; it serves as a social-engineering lure and cannot confirm the final payload type of the chain.
5. The sample contains much unreachable obfuscated code and a custom encryptor; static function boundaries are approximately recovered by decompilation, and some constant semantics depend on runtime behaviour.
6. The GUID in the callback URL may be a victim/session identifier rather than a fixed C2 path.

## Evidence index

<details>
<summary>Expand 17 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Sample triage | sha256/md5/sha1/imphash and overall triage |
| `ev-000008` | Sample triage | Packing likelihood 35%, .text entropy 7.879 |
| `ev-000016` | decompile.function | 0x140003999 container parsing + file drop + ShellExecuteA |
| `ev-000018` | decompile.function | 0x140004197 self-read of the file's tail overlay |
| `ev-000019` | decompile.function | 0x140003ce2 custom stream cipher |
| `ev-000022` | decompile.function | 0x140004423 32-segment gap-removal de-shuffle |
| `ev-000026` | decompile.function | 0x140001603 decrypts the stage2 buffer |
| `ev-000029` | decompile.function | 0x140001d2d chains de-shuffle and decryption |
| `ev-000031` | decompile.function | 0x1400032f6 calls the loader through a function pointer |
| `ev-000032` | evidence.record | Script reproduced decryption/de-shuffle (contains a pre-correction placeholder hash, superseded by ev-000033) |
| `ev-000033` | evidence.record | Size/hash/exports/imports of the decoy PDF and stage2 PE |
| `ev-000034` | evidence.record | Decoy PDF has no script/action keywords |
| `ref:1f73be6e83` | Dynamic analysis platform | Real sandbox detonation, timeline and output package (incl. network-monitoring logs) |
| `ref:0fd46fad6e` | dyn.run | Emulation observed file writes and ShellExecuteA |
| `ref:76c099623b` | decompile.symbols | Version information and import/string tables |
| `ref:e1a9987fae` | network log | pid 676 requests 151.244.30[.]118:80 and the raw GET path |
| `c2_evidence:5761156e` | Connection evidence extraction | Dynamic network monitoring recorded 29 connection attempts to 151.244.30[.]118:80, 151[.]244[.]30[.]118:80, 224.0.0[.]251:5353, 239.255.255[.]250:1900, arc[.]msn[.]com:443, config[.]edge[.]skype[.]com:443, edge[.]microsoft[.]com:443, ntp[.]msn[.]cn:443, www[.]bing[.]com:443; the full session was not captured |

</details>

---

_The sample behind this report is not public; IOCs are defanged. For security research only._
