---
title: "Malware Analysis: BlueWorksLabs Go Loader (PE · exe · 0f68bebc)"
published: 2026-11-22
draft: false
description: "Malicious (low confidence): BlueWorksLabs Go Loader · loader/rat/spyware · medium difficulty · dynamic sandbox + static decompilation"
tags: ["BlueWorksLabs", "loader", "rat", "spyware", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-22-BlueWorksLabs-Go-Loader-0f68bebc"
---

> [!WARNING]
> **Verdict: Malicious** · Family **BlueWorksLabs Go Loader** (uncertain) · Confidence **Low**
> 
> Aliases: BlueWorksLabs, sy3theo[.]tattoo panel, bf5eea7e campaign identifier
> 
> The sample is a UPX-packed Go program with obfuscated symbols; after actually running in the isolated Windows environment it resolves and calls back to sy3theo[.]tattoo, sends a plaintext HTTP registration beacon carrying tag/exp/hwid to port 443, and then uploads binary data as multipart; an injected native executable module appears in the same process's private memory, containing the same 32-character campaign identifier bf5eea7eb9dd0adade73f83a0970f1eb as the beacon and exposing desktop handles and GDI screen-capture interfaces. All of the above were directly observed at runtime, so it is assessed as malicious.

## Overview

| Item | Content |
|:--|:--|
| Family | **BlueWorksLabs Go Loader** · aliases BlueWorksLabs, sy3theo[.]tattoo panel, bf5eea7e campaign identifier · _uncertain_ |
| Confidence | **Low** |
| Behavior classes | loader · rat · spyware |
| Difficulty | medium |
| First seen | 2026-11-19 23:48:23 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/0f68bebc56a491a29e49ee246b0ac47fbe9092507fbd75fcfaed88d7854eaed5/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Double UPX wrapping</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Obfuscated Go symbols</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Hidden encrypted payload</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Self-inject native module</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Call back to C2</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `0f68bebc56a491a29e49ee246b0ac47fbe9092507fbd75fcfaed88d7854eaed5` |
| MD5 | _Not recorded_ |
| Size | 1,286,024 bytes (1.2 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**9** behaviors in total, each backed by evidence; **3** are static and **6** were obtained dynamically.

### 1. Double UPX Wrapping

`T1027.002` · Confidence **High** · Static

The sample is a 64-bit PE with only 4 import symbols and section names UPX0/UPX1/UPX2; UPX0 and UPX1 are both writable and executable, and UPX1 entropy is 7.915, consistent with UPX packing.

> **Evidence**: scan.triage/pe.parse: UPX0/UPX1 are W^X, import_dll_count=1, 4 import symbols, packing score 0.85; unpack.detect identifies upx.
> 
> **Source**: `ref:57cc08dbaa` · `ref:d1a7120601` · `ref:8e548b8a3e` · `ref:d645e22f9b`

### 2. Obfuscated Go Symbols

`T1027` · Confidence **High** · Static

After unpacking it is a Go 1.24.5 program with module path BlueWorksLabs; all 78 main-package function names are random strings (garble style), and build parameters include -trimpath, weakening statically readable semantics.

> **Evidence**: Go buildinfo at unpacked image rva 0x2fb000; pclntab (magic 0xfffffff1, nfunc=2291) yields random function names such as main.FNJOSzDbwb7y.
> 
> **Source**: `ref:8aa62d116d`

### 3. Hidden Encrypted Payload

`T1140` · Confidence **Medium** · Static

The unpacked image has a contiguous high-entropy block of about 0x51000 bytes with entropy 7.7-8.0 at rva 0x1f0000-0x240000, and the binary contains AES forward/inverse S-box constants, consistent with an encrypted embedded payload.

> **Evidence**: 32KB entropy scan: entropy 7.7-8.0 from 0x1f0000; scan.crypto hits AES S-box @ off 0x302940 and inverse S-box @ 0x302a40.
> 
> **Source**: `ref:43cb34267d` · `ref:ca6149b667`

### 4. Self-Inject Native Module

`T1055` · Confidence **High** · Dynamic

After the sample runs, a 264,351-byte executable PE image with 4 sections appears at private memory 0x140000000 in the same process and does not appear in the loaded-module list, indicating a manually mapped implant module.

> **Evidence**: Memory scan: implanted_pe=1, hdr_modified=1, module=0x140000000, module_size=0x4091F, mapping_type=MEM_PRIVATE, protection=0x40.
> 
> **Source**: `ref:df8afade51` · `ref:eb9eaee973`

### 5. Call Back to Designated C2

`T1071.001` · Confidence **High** · Dynamic

After resolving sy3theo[.]tattoo, the process sends a plaintext HTTP POST to 192.0.2[.]123:443 with Host sy3theo[.]tattoo; this is the only C2 domain throughout.

> **Evidence**: Network monitoring: pid 3656 → TCP 192.0.2[.]123:443, HTTPListener records POST /, Host: sy3theo[.]tattoo.
> 
> **Source**: `ref:df8afade51` · `ref:23d991c996`

### 6. Report Host Fingerprint

`T1082` · Confidence **High** · Dynamic

The first beacon reports tag=bf5eea7eb9dd0adade73f83a0970f1eb, exp=1794982993, hwid=7b14dee56f09a06933c6bd6f0ae8df1f as application/x-www-form-urlencoded, using the campaign identifier, expiry time and machine fingerprint for registration/licensing checks.

> **Evidence**: Body of the first POST in network monitoring: tag=bf5eea7eb9dd0adade73f83a0970f1eb&exp=1794982993&hwid=7b14dee56f09a06933c6bd6f0ae8df1f (Content-Length: 89).
> 
> **Source**: `ref:23d991c996` · `ref:eb9eaee973`

### 7. Upload Encrypted Data

`T1041` · Confidence **High** · Dynamic

After the registration beacon, the same process uploads 1,259 bytes of binary as multipart/form-data (access_token empty, type=0, file filename=data), then sends another 6-byte application/octet-stream request to continue interacting.

> **Evidence**: Multipart request in network monitoring (boundary=He2BV7uuigcy9L3PmX7, Content-Length: 1259) and a 6-byte octet-stream request (de 35 dc 35 bc 1d).
> 
> **Source**: `ref:23d991c996`

### 8. Screen-Capture Capability

`T1113` · Confidence **High** · Dynamic

The injected module imports desktop and GDI interfaces such as CreateDesktopW/OpenDesktopW, GetDC/GetWindowDC/GetWindowRect, BitBlt/CreateCompatibleBitmap/GetDIBits, along with CoCreateInstance/CoSetProxyBlanket for COM calls, giving it the ability to capture the desktop.

> **Evidence**: Memory-dump module import table: user32.GetDC/GetWindowDC/CreateDesktopW/OpenDesktopW, gdi32.BitBlt/CreateCompatibleBitmap/GetDIBits, combase.CoCreateInstance/CoSetProxyBlanket.
> 
> **Source**: `ref:8d2d9071fc` · `ref:1c24598b39` · `ref:eb9eaee973`

### 9. Masquerade as Browser Traffic

`T1036` · Confidence **High** · Dynamic

All C2 requests uniformly use a Chrome/117 User-Agent and conventional form and multipart upload headers, blending the traffic with browser web access.

> **Evidence**: All 3 POSTs in network monitoring carry Mozilla/5.0 ... Chrome/117.0.0[.]0 Safari/537.36.
> 
> **Source**: `ref:23d991c996`


## IOC (Defanged)

### Network

:::note
**Connection dynamically observed**: The sample actually initiated TCP connections to this target (multiple retries within a short period).
:::

:::caution
**Real server side still unverified**: The connections/handshakes above were completed with a local controlled simulation service; the real C2 responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://sy3theo[.]tattoo/` | 443 | c2 | dynamic | Observed |
| http | `hxxp://sy3theo[.]tattoo/` | 443 | exfil | dynamic | Observed |

### Host

**Drop paths**

- `%TEMP%\box-<pid>-<id>.dat (binary format string "box-%d-%d.dat"; no actual file drop observed)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `sy3theo[.]tattoo` | Yes | dynamic |
| `c2_port` | `443` | Yes | dynamic |
| `c2_uri` | `/` | Yes | dynamic |
| `campaign_tag` | `bf5eea7eb9dd0adade73f83a0970f1eb` | Yes | dynamic |
| `license_expiry` | `exp=1794982993 (2026-11-18T06:23:13Z), consistent with the plaintext 18.11.2026 in the module` | Yes | dynamic |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0[.]0 Safari/537.36` | Yes | dynamic |
| `encryption_algo` | `AES (binary contains standard/inverse S-box; upload body is ciphertext, not decrypted)` | No | static |
| `upload_fields` | `access_token, type, file(filename=data)` | No | dynamic |

## Common Misinterpretations

:::important
The following conclusions are **easy to misinterpret**; keep them in mind when citing this report.

- Do not judge it as ransomware merely because AES S-boxes and high-entropy data blocks exist in the binary; no file encryption, extension tampering or ransom instructions were observed during execution.
- Do not equate the injected module's GDI/COM imports with full remote control, keylogging or credential theft; this run only confirms screen-capture interfaces and network capability, and no keyboard/mouse hooks or browser credential reads were observed.
- Do not describe the POST on port 443 as a TLS-encrypted channel; what network monitoring captured is a plaintext HTTP request.
- Do not attribute the WinDivert1.3/PROCMON25 services newly added in the dynamic environment to the sample; they are components introduced by the analysis facility itself, and the sample created no services.
- Do not treat the family name as a definite conclusion without vendor-engine/family-name corroboration; the current family name is a candidate based on the module path and campaign identifier.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacked | Yes (stage2 `8b8a02c8e00d7c134b7ac0cc40ab52b5ebe43d3b58911cf0f672897e17551da9`) |

**Limitations and pending verification**

1. File-system behavior was not fully collected (system-call-level tracing artifacts were not archived with this analysis package) and no actual dropped file was observed; %TEMP%\box-%d-%d.dat is only a format string in the binary and cannot be used to assert a file was created.
2. No persistence, privilege escalation, credential theft or keylogging was observed: the registry Run keys and service list were unchanged before and after, and there were no child processes.
3. Network monitoring only replays default responses and did not obtain a real C2 response body; the command channel and remote-control command set could not be recovered.
4. The uploaded 1,259-byte payload is ciphertext on the wire and was not decrypted, so whether it contains a screen image, system information or other data cannot be confirmed.
5. Family attribution lacks vendor-engine/public-intelligence cross-validation and the family is a candidate name; the campaign identifier bf5eea7eb9dd0adade73f83a0970f1eb can serve as a search/correlation clue.
6. The dynamic environment applies host-side preprocessing of virtualization traces, so whether the sample itself contains anti-VM/anti-debug logic could not be statically confirmed (strings are obfuscated/encrypted).

## Evidence Index

<details>
<summary>Expand 21 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:57cc08dbaa` | Sample triage | Original sample hash/section entropy/packing score 0.85 |
| `ref:d1a7120601` | PE structure parse | PE64 header/section table/data directories, UPX0/UPX1 are W^X |
| `ref:8e548b8a3e` | Import table parse | Only 4 KERNEL32 imports, imphash 6ed4f5f04d62b18d96b26d6db7c18840 |
| `ref:d645e22f9b` | unpack.detect | Identified as UPX-packed (confidence 0.9) |
| `ref:5fd6e05df2` | unpack.auto | Automatic OEP location exceeded budget; unpacking was later completed by custom emulation |
| `ref:e02c3bff92` | String extraction | Strings of the original packed sample (Go build ID, runtime fragments) |
| `ref:712014f3fd` | dyn.run | Emulated execution passed the UPX stub into the Go runtime (from pc 0x472add) |
| `ref:df8afade51` | Dynamic analysis platform | Real dynamics: single-process detonation, memory dumps, timeline and network artifacts |
| `ref:4ff1e3f9fb` | PE structure parse | Unpacked PE from the memory dump (3,727,266 bytes, 56 imported DLLs) |
| `ref:8d2d9071fc` | PE structure parse | Injected native module (base 0x140000000, 4 sections) |
| `ref:1c24598b39` | String extraction | Injected-module strings (including campaign identifier and driver/interface names) |
| `ref:b9bb13f7b1` | Import table parse | Unpacked PE import surface (Go runtime API set, imphash eed0c0f0bfab67fc8a46397a2961c0c3) |
| `ref:ca6149b667` | Cryptographic constant identification | AES forward/inverse S-boxes and SHA-256 round constants |
| `ref:bbef417c14` | decompile.symbols | Function identification on the unpacked PE (no Go symbols, functions shown by address) |
| `ref:8aa62d116d` | evidence.record | Go buildinfo/pclntab parse (module BlueWorksLabs, garble function names, entry rva 0x72380) |
| `ref:43cb34267d` | evidence.record | Custom emulation unpacking of UPX and high-entropy block location |
| `ref:eb9eaee973` | evidence.record | Campaign identifier/expiry location and pointer references inside the injected module |
| `ref:23d991c996` | evidence.record | Network-monitoring log parse: 3 POSTs, tag/exp/hwid, multipart upload, 6-byte request |
| `c2_evidence:0f68bebc` | Connection evidence extraction | Dynamic network monitoring recorded 1 connection attempt to sy3theo[.]tattoo:443; no complete session captured |
| `telemetry:0f68bebc` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component 116 process/file events; 1 ETW short-lived process event; 22 tool/system noise events filtered |
| `etw:0f68bebc:3656` | Process event monitoring | Short-lived process event: 0f68bebc56a491a29e49ee246b0ac47fbe9092507fbd75fcfaed88d7854eaed5.exe (pid 3656; MD5=D1C23949BF4FF61BFAEF0A83FC4D39AD,SHA256=0F68BEBC56A491A29E49EE246B0AC47FBE9092507FBD75FCFAED88D7854EAED5,IMPHASH=00000000000000000000000000000000) |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
