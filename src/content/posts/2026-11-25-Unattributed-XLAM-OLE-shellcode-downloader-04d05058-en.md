---
title: "Malicious sample analysis: Unattributed XLAM/OLE shellcode downloader (other · xlam · 04d05058)"
published: 2026-11-25
draft: false
description: "Malicious (confidence: low): Unattributed XLAM/OLE shellcode downloader · downloader/loader · difficulty medium · pure static analysis"
tags: ["downloader", "loader"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-25-Unattributed-XLAM-OLE-shellcode-downloader-04d05058"
---

> [!WARNING]
> **Verdict: malicious** · Family **Unattributed XLAM/OLE shellcode downloader** (unconfirmed) · Confidence **low**
> 
> Aliases: OLE shellcode JS downloader, XLAM downloader
> 
> The OLE container was statically unpacked in an isolated environment and reproduced with CPU-level instruction emulation: the in-stream shellcode first decrypts second-stage code with a rolling XOR, the second stage resolves APIs dynamically by walking the PEB, downloads a .js from a public Cloudflare R2 bucket, drops it to %APPDATA% and hands it to ShellExecuteW for execution. The download and execution chain is complete and reproducible, so it is judged a malicious downloader/loader.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **Unattributed XLAM/OLE shellcode downloader** · Aliases OLE shellcode JS downloader, XLAM downloader · _unconfirmed_ |
| Confidence | **low** |
| Behavior class | downloader · loader |
| Difficulty | medium |
| First seen | 2026-11-25 14:00:08 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/04d05058662e29b714743fb20525d8da4d1b5a99d9a4184e2bbb67e1b9957773/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Masquerade as Excel add-in</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.008</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Embedded obfuscated shellcode</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Rolling XOR decrypts stage two</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">PEB walk resolves APIs</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.007</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Download JS to %APPDATA%</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `04d05058662e29b714743fb20525d8da4d1b5a99d9a4184e2bbb67e1b9957773` |
| MD5 | _Not recorded_ |
| Size | 971,264 bytes (948.5 KB) |
| Type | other · `xlam` |

## Behavior Analysis

There are **6** behaviors in total, each backed by evidence, and all are statically available.

### 1. Masquerade as an Excel add-in

`T1036.008` · Confidence **high** · Static

The file extension is .xlam, but the OLE compound document contains only one OLe10nAtivE data stream (961514 bytes) and one empty store with a random name; there is no Workbook or VBA project stream, so it cannot work as a normal Excel add-in — this is file-type masquerading.

> **Evidence**: OLE directory contains only 'OLe10nAtivE'(961514B) and 'Uhuj49KQMKo68mKF1TW6JHJ'(0B), no Workbook/VBA streams
> 
> **Source**: `ref:7b17e225f5` · `ev-000003`

### 2. Embedded obfuscated shellcode

`T1027` · Confidence **high** · Static

From offset 0x331 in the OLe10nAtivE stream is jump-obfuscated x86 shellcode, using call/pop to obtain the current address and masking the real control flow with many short jumps and dead code.

> **Evidence**: 0x331 jmp 0x415; 0x415 call 0x43d; 0x43d pop esi; 0x353 xor dword [esi],ebx
> 
> **Source**: `ref:4e9b9d27a3` · `ev-000003`

### 3. Rolling XOR decrypts stage two

`T1140` · Confidence **high** · Static

The decryption key is advanced with state=state*0x69ec269d+0x370eddbb, XORing [esi] DWORD by DWORD, and after decrypting the 0x2b9 bytes of second-stage shellcode at 0x457..0x710 it jumps into execution.

> **Evidence**: 0x385 imul ebx,ebx,0; 0x344 add ebx,0x370eddbb; 0x976 imul ebx,ebx,0x69ec269d; write range 0x457-0x70f
> 
> **Source**: `ev-000003` · `ref:159d85844a`

### 4. PEB walk resolves APIs

`T1027.007` · Confidence **high** · Static

The second-stage shellcode reads the PEB pointed to by fs:[0x30], walks the loaded-module list to locate kernel32, then resolves APIs such as LoadLibraryW and GetProcAddress dynamically from embedded strings, so the sample's static import table is empty.

> **Evidence**: 0x62d mov edx, fs:[0x30]; strings kernel32 / LoadLibraryW / GetProcAddress
> 
> **Source**: `ref:d3af40ec29` · `ev-000003`

### 5. Download JS to %APPDATA%

`T1105` · Confidence **high** · Static

It calls ExpandEnvironmentStringsW to expand %APPDATA%\dimpason.js, then resolves URLDownloadToFileW from UrlMon and downloads umasonwast.js from r2.dev to that path.

> **Evidence**: 0x4e2 UTF-16 '%APPDATA%\dimpason.js'; 0x54e UTF-16 download URL; 0x52a 'URLDownloadToFileW'
> 
> **Source**: `ref:1ae3f2710e` · `ev-000003`

### 6. Execute the downloaded JS

`T1059.007` · Confidence **high** · Static

It resolves ShellExecuteW from shell32 and executes the downloaded %APPDATA%\dimpason.js with the open verb, then calls ExitProcess to end its own process.

> **Evidence**: 0x5f2 'ShellExecuteW'; 0x619 'ExitProcess'
> 
> **Source**: `ref:1ae3f2710e` · `ev-000003`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: The above addresses come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://pub-3fba11404095422aba9bf21639f42cff[.]r2[.]dev/umasonwast[.]js` | 443 | download | Static | ⏳ Not observed |

### Host

**Drop paths**

- `%APPDATA%\dimpason.js`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `pub-3fba11404095422aba9bf21639f42cff[.]r2[.]dev` | Yes | Static |
| `download_url` | `hxxps://pub-3fba11404095422aba9bf21639f42cff[.]r2[.]dev/umasonwast[.]js` | Yes | Static |
| `install_path` | `%APPDATA%\dimpason.js` | Yes | Static |
| `encryption_algo` | `rolling XOR, key advanced by the LCG recurrence state=state*0x69ec269d+0x370eddbb` | No | Static |
| `ole_stream` | `OLe10nAtivE` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not assert that the .xlam extension means Excel can open it and run macros: there is no Workbook/VBA stream and no XLM macro in the file.
- Do not assert that the sample successfully downloaded over the network or checked in to a C2: this was static analysis and CPU-level emulation, and no real network session was obtained.
- Do not treat the 941527-byte uniform alphanumeric region as decrypted payload or configuration: the second-stage shellcode does not reference that region.
- Do not classify it as a stealer or ransomware family: the available evidence only goes as far as downloading and executing JavaScript, and the follow-on payload type is unknown.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. This was pure static analysis and CPU-level instruction emulation, not a real sandbox detonation; the actual download and execution results were not observed.
2. The OLE structure contains no Workbook/VBA stream, so Excel cannot execute it directly as an add-in; the actual delivery and loading path is unknown.
3. The 941527 bytes of uniform alphanumeric data (entropy 5.954) are not referenced by the second-stage shellcode; their purpose is unknown and they may be padding or unused data.
4. No vendor naming or YARA signature was obtained, so only a descriptive family candidate can be given, marked uncertain.
5. No persistence, registry, service, scheduled-task or mutex behavior was observed.
6. The remote umasonwast.js was not downloaded; the follow-on payload type and behavior are unknown.

## Evidence Index

<details>
<summary>Expand 4 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000003` | evidence.record | olefile extracted the OLe10nAtivE stream; a custom x86 CPU emulator executed the shellcode from 0x331, decrypted 0x457-0x710 and exported second-stage strings/APIs/URLs |
| `ref:4e9b9d27a3` | disasm.bytes | Shellcode disassembly from offset 0x331: jmp/call/pop and the xor [esi],ebx decryption loop |
| `ref:1ae3f2710e` | String extraction | APIs, %APPDATA%\dimpason.js and the r2.dev download URL strings in the decrypted second-stage code |
| `ref:7b17e225f5` | String extraction | OLE stream name OLe10nAtivE and 941527 bytes of alphanumeric data in the original .xlam |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
