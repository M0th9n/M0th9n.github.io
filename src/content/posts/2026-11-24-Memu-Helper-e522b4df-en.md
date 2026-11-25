---
title: "Malicious sample analysis: Memu Helper (PE · exe · e522b4df)"
published: 2026-11-24
draft: false
description: "Malicious (confidence: low): Memu Helper · spyware/injector · difficulty hard · dynamic sandbox + static decompilation"
tags: ["Memu Helper", "spyware", "injector", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-24-Memu-Helper-e522b4df"
---

> [!WARNING]
> **Verdict: malicious** · Family **Memu Helper** (unconfirmed) · Confidence **low**
> 
> Aliases: MEmu Helper, Memu.exe
> 
> This 64-bit PE is unsigned; its version resource claims Memu Helper/Memu Networks Ltd, and the code uses strong obfuscation such as control-flow flattening, jump tables, constant encryption/decryption and TLS-pointer magic-number self-checks. Static imports include a global key-state query (GetAsyncKeyState) and focus/desktop window and window-thread enumeration. In the dynamic sandbox, after the sample process started, memory forensics found in explorer.exe a 64-bit PE module with no backing file on disk and an RWX (MEM_PRIVATE) shellcode region; the injected module imports foreground window/class name/window rectangle query APIs, consistent with process injection and window/input monitoring capability. The overall verdict is malicious, but the direct call chain between the injection and the sample, as well as the C2 and plaintext configuration, has not yet been obtained.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **Memu Helper** · Aliases MEmu Helper, Memu.exe · _unconfirmed_ |
| Confidence | **low** |
| Behavior class | spyware · injector |
| Difficulty | hard |
| First seen | 2026-11-22 09:43:11 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/e522b4df3aa6528186299cce0a75e01d7a549271873a16426a6fad891f490bc2/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Inject into explorer.exe</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Monitor foreground window</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1010</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Read global key states</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Embedded encoded data pools</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Obfuscated control flow and constants</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `e522b4df3aa6528186299cce0a75e01d7a549271873a16426a6fad891f490bc2` |
| MD5 | _Not recorded_ |
| Size | 825,344 bytes (806.0 KB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **8** behaviors in total, each backed by evidence; **6** are statically available and **2** were obtained through dynamic analysis.

### 1. Inject into explorer.exe

`T1055.012` · Confidence **medium** · Dynamic

After the sample ran, memory forensics detected in explorer.exe a 64-bit PE module that is not in the module list and has no backing file on disk, plus a MEM_PRIVATE PAGE_EXECUTE_READWRITE shellcode region (the PE sits at region base +0x4000), indicating that follow-on code is hosted through process injection.

> **Evidence**: explorer.exe pid 4128: implanted_pe=1, has_shellcode=1, protection=0x40, mapping_type=MEM_PRIVATE, unreachable_file=1; injected module dump sha256=a49e4767...
> 
> **Source**: `ref:b615d86c7c`

### 2. Monitor foreground window

`T1010` · Confidence **medium** · Dynamic

The module injected into explorer.exe imports GetForegroundWindow, GetClassNameW, GetWindowRect and IsWindowEnabled, giving it the ability to enumerate the foreground window and its class name/rectangle and to track the user's activity context.

> **Evidence**: injected module import table user32.dll: GetForegroundWindow/GetClassNameW/GetWindowRect/IsWindowEnabled
> 
> **Source**: `ref:b615d86c7c`

### 3. Read global key states

`T1056.001` · Confidence **high** · Static

The main program's startup flow calls GetAsyncKeyState(0x11) to read the Ctrl key state and statically imports global key query capability, which can be used for hotkey checks or keyboard monitoring.

> **Evidence**: rva 0x122a call GetAsyncKeyState(0x11) (FUN_140001110); IAT rva 0x77f00
> 
> **Source**: `ref:8ff02b7a2a` · `ref:3f40bbf9e7`

### 4. Embedded encoded data pools

`T1027` · Confidence **high** · Static

Embeds 212 segments of encoded data in .rdata/.data, indexed by a {ptr,len} table and decoded/decrypted by index at runtime, a typical way of hiding payloads and configuration.

> **Evidence**: {ptr,len} table from 0xc5038 (first entry ptr=0x140027000,len=0x9c); the two data pools start at rva 0x27000 and 0x7b000
> 
> **Source**: `ref:96c015c6c1` · `ref:4040b411ea`

### 5. Obfuscated control flow and constants

`T1027` · Confidence **high** · Static

Key functions use control-flow flattening, indirect jump tables, and constants XORed with keys derived via SPLITMIX64; decompilation shows many unreachable branches and encrypted constants, significantly raising the cost of static analysis.

> **Evidence**: FUN_140001110 @0x14000128d indirect jump; FUN_14000c1f0 constant-table XOR decryption; FUN_14000bf70 mixing derivation using 0x9e3779b97f4a7c15
> 
> **Source**: `ref:8ff02b7a2a` · `ref:3ce190af4b` · `ref:c1b686f810`

### 6. Masqueraded vendor and version

`T1036.005` · Confidence **high** · Static

The resource version information claims Memu Helper / Memu Networks Ltd / 2.9.8.5020 / Memu.exe, but the file has no digital signature, and the vendor name does not match the known MEmu publisher, showing brand masquerading traits.

> **Evidence**: VS_VERSION_INFO strings @0xc72a0 'Memu Helper', @0xc735e 'Memu Networks Ltd'; SECURITY data directory size=0
> 
> **Source**: `ref:4040b411ea` · `ref:b18592aada`

### 7. Enumerate windows and processes

`T1010` · Confidence **high** · Static

Enumerates the focus window, the desktop window, and their owning thread/process IDs, and determines window state with IsIconic/IsZoomed/IsWindowEnabled/GetClientRect, providing information for later monitoring or overlay positioning.

> **Evidence**: FUN_14000bf70 @rva 0xbf70 calls GetFocus/GetDesktopWindow/GetWindowThreadProcessId/GetClientRect
> 
> **Source**: `ref:c1b686f810`

### 8. TLS self-check anti-analysis

`T1497.001` · Confidence **medium** · Static

A check of the magic number at a TLS pointer offset and of a private-key decoding table determines whether key branches execute, and runtime checks such as IsDebuggerPresent are retained, giving it anti-debugging/anti-sandbox properties.

> **Evidence**: FUN_14000bf70: *(int*)(TLS+0xb8) == -0x2281050a(-0x2281050a); FUN_14000c1f0 initializes the TLS private table
> 
> **Source**: `ref:c1b686f810` · `ref:3ce190af4b`


## IOCs (defanged)

### Network

:::note
**No C2 / network IOCs were recovered** (see "Analysis Method and Limitations" at the end for the reason).
:::

### Host

- **No host IOCs were recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `embedded_blob_count` | `212 segments of {ptr,len}-indexed encoded data, totaling about 583,595 characters, spread across two pools in .rdata (from rva 0x27000) and .data (from rva 0x7b000)` | No | Static |
| `blob_encoding` | `custom 32-symbol alphabet (0-9 and some lowercase letters, missing a/f/g/p), data separated by '_' every 44 characters` | No | Static |
| `crypto_scheme` | `constant tables + SPLITMIX64-style mixing to derive keys, combined with XOR decryption (statically identified, plaintext not recovered)` | No | Static |
| `c2_hosts` | `not obtained (no outbound traffic from the sample observed in the dynamic window)` | Yes | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not assert that keyboard content was fully logged and sent back merely because GetAsyncKeyState is imported: this analysis observed neither a keystroke log file dropped to disk nor any network egress.
- The direct causal relationship between the module injected into explorer.exe and this sample has not been proven by a call chain/injection event, and other components of the host environment are possible; it can only be treated as a strong correlated observation.
- No C2 address, plaintext configuration or family-specific strings were obtained, so it should not be claimed that this sample belongs to a specific RAT/stealer family.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. No outbound traffic from the sample itself was observed in the dynamic window (network monitoring only recorded system update/browser update traffic), and the C2 was not obtained.
2. The direct call chain between the injected module in explorer.exe and the sample was not obtained (no injection-related ETW events); the attribution is an inference with medium confidence.
3. The 212 segments of encoded data have not been fully decoded, and their plaintext purpose (UI resources/scripts/configuration/payload) is unconfirmed.
4. Only one VK_CONTROL query via GetAsyncKeyState was seen, so full keystroke-logging behavior cannot be concluded from it.
5. The sample uses the GUI subsystem, and the automated environment performed no UI interaction, so some UI-related logic may not have executed.

## Evidence Index

<details>
<summary>Expand 10 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1 and imphash |
| `ev-000003` | scan.entropy | .text entropy 6.54, all sections <7.0, no whole-file packing traits |
| `ev-000013` | decompile.ghidra | FUN_140001110 control-flow flattening and GetAsyncKeyState(0x11) |
| `ev-000014` | decompile.ghidra | FUN_14000bf70 window enumeration and SPLITMIX64 derivation |
| `ev-000015` | decompile.ghidra | FUN_14000601f wide-character paths and CreateFileW/SetFileTime wrappers |
| `ev-000016` | decompile.ghidra | FUN_14000c1f0 TLS private table constant decryption |
| `ev-000017` | decompile.ghidra | FUN_14000c127 NtWriteFile wrapper |
| `call:call_1a329c757c0a41ec8a45c834` | Dynamic analysis platform | Dynamic sandbox run timeline, memory scanning and injected module evidence |
| `telemetry:e522b4df` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 108; ETW short-lived process events 1; filtered tool/system noise 22 |
| `etw:e522b4df:4480` | Process event monitoring | Short-lived process event: e522b4df3aa6528186299cce0a75e01d7a549271873a16426a6fad891f490bc2.exe (pid 4480; MD5=659F7FB6F900041C4B80B0261042E981,SHA256=E522B4DF3AA6528186299CCE0A75E01D7A549271873A16426A6FAD891F490BC2,IMPHASH=1D06A1CB5556761EA9E76B9B76D17970) |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
