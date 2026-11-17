---
title: "Malware Analysis: SolidMetricCollective (PE · exe · 7c500ab9)"
published: 2026-11-17
draft: false
description: "Malicious (low confidence): SolidMetricCollective · loader/rat · difficulty hard · dynamic sandbox + static decompilation"
tags: ["SolidMetricCollective", "loader", "rat", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-17-SolidMetricCollective-7c500ab9"
---

> [!WARNING]
> **Verdict: Malicious** · Family **SolidMetricCollective** (uncertain) · Confidence **low**
> 
> Aliases: Solid Metric Collective signed Go loader
> 
> The sample is a UPX-packed Go program; after unpacking it was confirmed to use garble obfuscation and to masquerade as legitimate software with a self-signed code-signing certificate. In the live dynamic sandbox it resolved and connected back to blapt[.]tattoo:443, first reporting tag/exp/hwid fingerprints and then uploading encrypted data via multipart; an unregistered module (MEM_PRIVATE, base 0x140000000) was detected in the same process memory, with screen/active-desktop capture and LZMA decompression capabilities and the same campaign tag embedded. These behaviors are corroborated by network monitoring, memory forensics and static decompilation.

## Overview

| Item | Content |
|:--|:--|
| Family | **SolidMetricCollective** · aliases Solid Metric Collective signed Go loader · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · rat |
| Difficulty | hard |
| First seen | 2026-11-13 20:33:44 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/7c500ab902c6ed54912c6fceac3cf133caf710106750a14bbd04e1e2580eaacf/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX unpack and load main module</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Forge code-signing certificate</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Inject native module in-process</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.002</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Capture screen and active desktop</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1113</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Connect back to C2 domain</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `7c500ab902c6ed54912c6fceac3cf133caf710106750a14bbd04e1e2580eaacf` |
| MD5 | _not recorded_ |
| Size | 1,209,792 bytes (1.2 MB) |
| Type | PE · `exe` |

## Behavior analysis

**9** behaviors in total, each backed by evidence; **4** were obtained statically and **5** through dynamic analysis.

### 1. UPX unpack and load main module

`T1027.002` · Confidence **high** · static

The outer layer is a UPX-packed 64-bit PE (UPX0/UPX1/UPX2, UPX1 entropy 8.0, only 4 imports); unpacking yields a 5.9 MB Go 1.21.1 main module (sha256 f0282a85…).

> **Evidence**: section names UPX0/UPX1/UPX2; UPX1 entropy 8.0; upx -d restores 5901760 bytes
> 
> **Source**: `ref:d8fb592173` · `ref:4e6132755a` · `ref:d72365535b`

### 2. Forge code-signing certificate

`T1553.002` · Confidence **high** · static

The file tail carries a PKCS#7 code signature; the certificate is self-signed (subject=issuer=Solid Metric Collective, valid 2026-11-06 to 2027-11-13) and was not issued by a trusted CA, being used to masquerade as legitimate software.

> **Evidence**: WIN_CERTIFICATE @0x59EE00, length 0x1FC0; openssl parses subject=issuer=Solid Metric Collective
> 
> **Source**: `ref:9e794babac` · `ref:67119a44eb`

### 3. Inject native module in-process

`T1055.002` · Confidence **high** · dynamic

An unregistered executable module exists inside the main program's own process (base 0x140000000, MEM_PRIVATE, not a module-list entry), and the monitoring component flags it as implanted_pe; the main program imports VirtualAlloc/VirtualProtect/CreateThread/GetThreadContext/SetThreadContext to support in-process mapping and execution.

> **Evidence**: monitoring component: module 140000000 / MEM_PRIVATE / is_listed_module=0 / implanted_pe=1; Go imports VirtualAlloc, VirtualProtect, CreateThread
> 
> **Source**: `ref:0b9911592d` · `ref:6b195c2543` · `ref:a52aa20709`

### 4. Capture screen and active desktop

`T1113` · Confidence **high** · dynamic

The injected 252 KB module imports GetDC/GetWindowDC/BitBlt/CreateCompatibleDC/CreateCompatibleBitmap/GetDIBits as well as OpenDesktopW/GetForegroundWindow/GetKeyboardLayout, giving it the capability to capture screen and active-desktop content.

> **Evidence**: 140000000.exe import table: BitBlt, GetDIBits, GetDC, OpenDesktopW, GetForegroundWindow
> 
> **Source**: `ref:3606b693a4` · `ref:a52aa20709`

### 5. Connect back to C2 domain and check in

`T1071.001` · Confidence **high** · dynamic

The sample resolves blapt[.]tattoo and connects to port 443 over plaintext HTTP; requests carry a fixed Chrome/117 UA and Host: blapt[.]tattoo, which is HTTP-protocol C2.

> **Evidence**: network monitor log: 6004 requested TCP 192.0.2[.]123:443; POST / HTTP/1.1, Host: blapt[.]tattoo
> 
> **Source**: `ref:0b9911592d` · `ref:03f1c49013`

### 6. Report host fingerprint and tag

`T1082` · Confidence **high** · dynamic

The check-in request body is tag=bf5eea7eb9dd0adade73f83a0970f1eb&exp=1794540729&hwid=9e9004d73381f66733c6bd6fcb6e2b9b, submitting the campaign tag, expiry time and device fingerprint to the C2.

> **Evidence**: POST body tag=…&exp=…&hwid=…; the injected module embeds the same tag string
> 
> **Source**: `ref:03f1c49013` · `ref:a7c8d10118`

### 7. Exfiltrate encrypted data

`T1041` · Confidence **medium** · dynamic

It then uploads 1243 bytes of binary data to the same C2 as multipart/form-data (fields access_token, type=0, file=data), followed by a 6-byte binary POST in an encrypted/packed format; no plaintext was exposed in the traffic.

> **Evidence**: multipart body contains access_token/type/file; the file part is high-entropy binary; a trailing 6-byte application/octet-stream POST
> 
> **Source**: `ref:03f1c49013`

### 8. LZMA-decompress built-in payload

`T1140` · Confidence **medium** · static

The injected module contains an LZMA decoding implementation (0x4020 dictionary, multiplicative-hash match table) used to decompress embedded next-stage data in memory.

> **Evidence**: FUN_140002bb0 decompilation: 0x4020 dictionary, 0x61C8864F multiplicative hash, match length encoding
> 
> **Source**: `ref:9e72fbe5d3`

### 9. Obfuscated symbols and strings

`T1027` · Confidence **high** · static

The Go main module uses garble-style obfuscation: main-package function names are replaced with random identifiers (e.g. main.aul1Z8i5kw), string literals are decrypted on demand, there is almost no business plaintext in the static file, and the build used -trimpath.

> **Evidence**: COFF symbols main.aul1Z8i5kw / main.h7Ylgg180; build info contains -trimpath=true; no blapt[.]tattoo plaintext statically
> 
> **Source**: `ref:7c8d2372cc` · `ref:a7c8d10118` · `ref:af5e0024a9`


## IOC (defanged)

### Network

:::note
**Connection observed dynamically**: the sample actually initiated TCP connections to this target (multiple retries within a short time).
:::

:::caution
**The real server side remains unverified**: the above connections/handshake were completed with a local controlled simulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://blapt[.]tattoo:443/` | 443 | c2 | dynamic | observed |
| http | `hxxp://blapt[.]tattoo:443/` | 443 | exfil | dynamic | observed |

### Host

**Dropped paths**

- `%WINDIR%\System32\<64-bit hex random name>`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `blapt[.]tattoo` | yes | dynamic |
| `c2_port` | `443` | yes | dynamic |
| `c2_uri` | `/` | yes | dynamic |
| `campaign_tag` | `bf5eea7eb9dd0adade73f83a0970f1eb` | yes | dynamic |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0[.]0 Safari/537.36` | yes | dynamic |
| `checkin_params` | `tag, exp, hwid` | yes | dynamic |
| `upload_part_names` | `access_token, type, file` | no | dynamic |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Comparison of before/after system snapshots found no new HKCU/HKLM Run keys, services or scheduled tasks, so it cannot be claimed that the sample has persistence capability.
- No child-process creation, credential reading or browser-data access was observed, so it cannot be classified as a stealer.
- The uploaded 1243 bytes are encrypted binary; it cannot be asserted that the content is a screenshot or account credentials.
- The self-signed certificate and collection APIs only prove masquerading and capability; they cannot be used to attribute a particular vendor family.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | yes (stage2 `f0282a857abfaa212681fe3945dc4b559ef270b443720be73d5f717ec808573b`) |

**Limitations and pending verification**

1. The C2's HTTP responses were simulated by the sandbox network service; no real commands or follow-up payloads were obtained, so the tasks delivered by the C2 cannot be confirmed.
2. Go strings are obfuscated and decrypted on demand; apart from a few runtime strings there is no business plaintext in the static file, and the full configuration was mainly recovered through memory forensics.
3. System snapshot comparison showed no new Run keys, services, scheduled tasks or Defender exclusions; persistence capability was not confirmed.
4. No child-process creation, credential-file reading or browser-data access was observed.
5. `%WINDIR%\System32\<64-bit hex name>` appeared only in runtime memory strings; actual disk writing could not be confirmed.
6. The injected module is a memory-reconstructed artifact and its import table may be incomplete; its internal functions were judged only from decompilation and the import surface, and no actual screen-capture calls were observed.

## Evidence index

<details>
<summary>Expand 19 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:d8fb592173` | sample triage | original sample: UPX section names, UPX1 entropy 8.0, 4 imports, 85% packing likelihood |
| `ref:4e6132755a` | unpack.detect | determined UPX-packed, policy upx_unpack |
| `ref:624c10072a` | PE structure parsing | original PE structure: AMD64, 3 sections, entry 0x6006E0, W^X anomaly |
| `ref:943dba855b` | import table parsing | original sample imports only 4 KERNEL32 functions |
| `ref:7c8d2372cc` | sample triage | normal PE after unpacking, 8 sections, 45 imports, no packing indicators |
| `ref:6b195c2543` | import table parsing | after unpacking imports VirtualAlloc/VirtualProtect/CreateThread/SetThreadContext etc. |
| `ref:e56a1b67aa` | disasm.function | main.main disassembly, control-flow flattening, strings decrypted on demand |
| `ref:a7c8d10118` | decompile.symbols | 316 functions and string table, contains the campaign tag; main function names randomized |
| `ref:67119a44eb` | openssl (bash) | parses the PKCS#7 signature: self-signed Solid Metric Collective certificate and DigiCert timestamp chain |
| `ref:9e794babac` | evidence.record | certificate fields and self-signed conclusion (script-registered) |
| `ref:0b9911592d` | dynamic analysis platform | live dynamic sandbox detonation: process 6004, monitoring component targeted dump, timeline and network logs |
| `ref:a52aa20709` | PE structure parsing | injected module 140000000.exe structure: AMD64, 4 sections, 35 DLL imports |
| `ref:3606b693a4` | import table parsing | injected module imports BitBlt/GetDC/GetDIBits/OpenDesktopW etc. |
| `ref:9e72fbe5d3` | decompile.function | FUN_140002bb0 is an LZMA decoding implementation |
| `ref:03f1c49013` | evidence.record | network log parsing: blapt[.]tattoo check-in, multipart upload, 6-byte POST |
| `ref:af5e0024a9` | evidence.record | memory dump strings compared with the injected module tag |
| `c2_evidence:7c500ab9` | connection evidence extraction | dynamic network monitoring recorded 2 connection attempts to blapt[.]tattoo:443; no full session captured |
| `telemetry:7c500ab9` | dynamic telemetry | dynamic telemetry recorded: monitoring component 135 process/file events; 1 ETW short-lived process event; 27 filtered tool/system noise entries |
| `etw:7c500ab9:6004` | process event monitoring | short-lived process event: 7c500ab902c6ed54912c6fceac3cf133caf710106750a14bbd04e1e2580eaacf.exe (pid 6004; MD5=6C671644D6FD5CD57310ED3A7B7C52E3,SHA256=7C500AB902C6ED54912C6FCEAC3CF133CAF710106750A14BBD04E1E2580EAACF,IMPHASH=00000000000000000000000000000000) |

</details>

---

_The sample in this report is not public; IOCs are defanged, for security research only._
