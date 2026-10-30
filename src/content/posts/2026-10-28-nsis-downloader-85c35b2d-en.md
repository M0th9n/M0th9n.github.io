---
title: "Malware Analysis: Unattributed NSIS downloader (PE · exe · 85c35b2d)"
published: 2026-10-28
draft: false
description: "Malicious (low confidence): Unattributed NSIS downloader · downloader/dropper · difficulty medium · dynamic sandbox + static decompilation"
tags: ["downloader", "dropper", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-28-nsis-downloader-85c35b2d"
---

> [!WARNING]
> **Verdict: malicious** · Family **Unattributed NSIS downloader** (uncertain) · Confidence **low**
> 
> A PE32 NSIS 3.06 Unicode installer actually ran inside an isolated Windows sandbox: it loaded winhttp/wininet/urlmon/dnsapi/ws2_32 in-process, resolved x0[.]at and issued an HTTPS GET to hxxps://x0[.]at/Kp7v.bin with a forged Firefox 157 UA, retrying 11 times within about 100 seconds; the image carries a self-signed fake certificate (CN=Squamify) and randomly generated dictionary-word version information; the 1.4 MB of files bundled in the installer are constant-filled decoys, and the only high-entropy blob has no executable header. Dynamic observation captured the remote payload fetch and the drop into a hidden directory, while static analysis captured the masquerading and evasion constructs, so it is judged to be a malicious downloader/dropper.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unattributed NSIS downloader** · _uncertain_ |
| Confidence | **low** |
| Behaviour class | downloader · dropper |
| Difficulty | medium |
| First seen | 2026-10-28 10:54:58 |
| Analysis method | dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/85c35b2dd5fa36ab0ae8943b6673e9655d66427b7c84b3792fc7c046bdb622bf/) |

## Attack chain

<svg viewBox="0 0 720 226" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="150" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="38" fill="currentColor" font-weight="600" font-size="14">Config decryption</text>
<text x="250" y="38" fill="currentColor" fill-opacity="0.65" font-size="12.5">AES decrypts embedded config</text>
<text x="250" y="56" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="92" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="92" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="96" fill="currentColor" font-weight="600" font-size="14">Masqueraded drop</text>
<text x="250" y="96" fill="currentColor" fill-opacity="0.65" font-size="12.5">copied to %LocalAppData%</text>
<text x="250" y="114" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<rect x="586" y="81" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="96" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="150" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="150" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="154" fill="currentColor" font-weight="600" font-size="14">Connect to C2</text>
<text x="250" y="154" fill="currentColor" fill-opacity="0.65" font-size="12.5">Raw TCP to hardcoded C2</text>
<text x="250" y="172" fill="currentColor" fill-opacity="0.4" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="139" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="154" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `85c35b2dd5fa36ab0ae8943b6673e9655d66427b7c84b3792fc7c046bdb622bf` |
| MD5 | _not recorded_ |
| Size | 552,632 bytes (539.7 KB) |
| Type | PE · `exe` |

## Behaviour analysis

**8** behaviours were recovered, each with supporting evidence; **4** are static and **4** come from dynamic analysis.

### 1. Masquerades as Danish calculation software

`T1036.005` · confidence **high** · static

The sample is an NSIS 3.06 (Unicode) self-extracting installer whose UI and install directory masquerade as a Danish energy calculation tool (Energiteknik / kalkulationsformlerne), while the version information uses random dictionary words (CompanyName=communalising, InternalName=sanders blodhvnens.exe, ProductName=fugledderkops sadomasochismen nednormeret).

> **Evidence**: pe.parse: subsystem GUI, 5 sections, entry rva 0x34C5; NSIS header at file off 0x3C810 (magic NullsoftInst), version string 'Nullsoft Install System v3.06'; script string '%PROGRAMFILES%\Energiteknik\kalkulationsformlerne\upknit'
> 
> **Source**: `ref:d8c0ce8dc6` · `ref:6cfa65711f` · `ref:4eca17e8b7`

### 2. Uses a self-signed fake certificate

`T1553.002` · confidence **high** · static

The PE security directory carries an Authenticode signature, but the certificate is self-signed (subject=issuer=CN=Squamify, C=GB), valid from 2026-09-08 to 2027-09-08, used to create the appearance of a "signed installer".

> **Evidence**: file off 0x85BE8 WIN_CERTIFICATE (type 2, 4816 B); PKCS#7 signer cert: subject=C=GB, O=Squamify, OU=slantways Illiannas Remodification , CN=Squamify; issuer identical
> 
> **Source**: `ref:ae7bba0517`

### 3. Drops constant-filled decoy files

`T1027.001` · confidence **high** · static

The NSIS package's five "data files" total about 1.4 MB; four of them are single-byte constant filler (0x4E/0x17/0x56/0xD9, entropy 0.16), while Mimmest is a high-entropy blob (7.67) containing only large amounts of a repeated 4-byte pattern and no MZ/PE header. These files do not constitute an executable payload; they serve as size inflation and detection noise.

> **Evidence**: section entropy .text 6.495 / whole 7.369; extracted: baglande.roe 0x4E x230678, benelux.per 0x17 x304506, coequalness.for 0x56 x630262, fordjelsens.rak 0xD9 x649348; Mimmest entropy 7.67, 0 MZ at page starts
> 
> **Source**: `ref:67780c0084` · `ref:6b2969295f`

### 4. Writes into a hidden Templates directory

`T1036.005` · confidence **high** · dynamic

At runtime it drops files into %APPDATA%\Microsoft\Windows\Templates\Energiteknik\kalkulationsformlerne\upknit rather than the usual Program Files; the full drop path and the installer progress string "djelsens.rak... 100%" were captured from memory.

> **Evidence**: process minidump @0x6CDEE27 UTF-16 'C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Templates\Energiteknik\kalkulationsformlerne\upknit\Desmosis\Lejevrdiberegningsreglens\'; @0x6F5ADCF 'djelsens.rak... 100%'
> 
> **Source**: `ref:aba1498190` · `ref:43dc74ac8d`

### 5. Downloads a remote payload in-process

`T1105` · confidence **high** · dynamic

The running sample process resolves x0[.]at and issues an HTTPS GET to hxxps://x0[.]at/Kp7v.bin with a forged Firefox 157 User-Agent and Cache-Control: no-cache, performing an in-process download of the second stage.

> **Evidence**: network monitoring: 'Received A request for domain x0.at' (23:40:07) + 'GET /Kp7v.bin HTTP/1.1' / 'Host: x0.at' / 'User-Agent: ...rv:157.0...Firefox/157.0'; minidump @0x6CFFC1F & @0x6D2B127 'hxxps://x0.at/Kp7v.bin'
> 
> **Source**: `ref:9051288944` · `ref:f55b194d99` · `ref:ddab4c4c7d`

### 6. Retries the download every ten seconds

`T1105` · confidence **high** · dynamic

The same URL was requested 11 times within about 100 seconds (roughly once every 10 seconds, from 23:40:08 to 23:41:49), indicating that the download result was not accepted and the sample entered a retry loop.

> **Evidence**: 11 entries of 'GET /Kp7v.bin HTTP/1.1' in the network monitoring log, 10-11 s apart; the same pid 6064 keeps opening TCP 192.0.2[.]123:443
> 
> **Source**: `ref:9051288944` · `ref:2bc6cccbca`

### 7. Loads network components in-process

`T1071.001` · confidence **high** · dynamic

While running, the sample process loads winhttp.dll, wininet.dll, urlmon.dll, dnsapi.dll, ws2_32.dll and IPHLPAPI.DLL, so all network access happens inside its own process; no child-process creation was observed.

> **Evidence**: process module scan (65 modules) includes winhttp/wininet/urlmon/dnsapi/ws2_32/IPHLPAPI; only the sample pid 6064 is alive in the process table, the rest are system processes
> 
> **Source**: `ref:dd10aae79a` · `ref:512e1b78e5` · `ref:cb96860fc2`

### 8. Forges version metadata

`T1036.005` · confidence **high** · static

The version resource declares FileVersion/ProductVersion 3.3.0[.]0, but the company name, product name and internal name are all random English/Danish dictionary combinations inconsistent with the actual NSIS 3.06 stub, used to lower heuristic suspicion.

> **Evidence**: version info: FileDescription='hammerers inkassoen stegersers', InternalName='sanders blodhvnens.exe', LegalCopyright='medisterplsen', ProductName='fugledderkops sadomasochismen nednormeret'
> 
> **Source**: `ref:6cfa65711f` · `ref:d8c0ce8dc6`


## IOC (defanged)

### Network

:::note
**Connection observed dynamically**: the sample actually opened TCP connections to this target (retrying several times within a short period).
:::

:::caution
**Still unverified on the real server side**: the connections/handshakes above were completed with a locally controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://x0[.]at/Kp7v.bin` | 443 | download | dynamic | observed |

### Host

**Drop paths**

- `%APPDATA%\Microsoft\Windows\Templates\Energiteknik\kalkulationsformlerne\upknit\`
- `%APPDATA%\Microsoft\Windows\Templates\Energiteknik\kalkulationsformlerne\upknit\Desmosis\Lejevrdiberegningsreglens\fordjelsens.rak`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `download_url` | `hxxps://x0[.]at/Kp7v.bin` | yes | dynamic |
| `install_path` | `%APPDATA%\Microsoft\Windows\Templates\Energiteknik\kalkulationsformlerne\upknit` | yes | dynamic |
| `http_user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0` | no | dynamic |
| `installer_framework` | `Nullsoft Install System v3.06 (Unicode, deflate)` | no | static |
| `code_signing` | `self-signed Authenticode, C=GB, O=Squamify, OU=slantways Illiannas Remodification, CN=Squamify (2026-09-08..2027-09-08)` | no | static |
| `decoy_payloads` | `Mimmest (272220 B, entropy 7.67), baglande.roe (233016 B, 0x4E filler), Gnaskeriet (157965 B), Desmosis\benelux.per (307508 B, 0x17 filler), Desmosis\coequalness.for (636578 B, 0x56 filler), Desmosis\Lejevrdiberegningsreglens\fordjelsens.rak (655728 B, 0xD9 filler)` | no | static |

## Don't misread this

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- Do not assert that it is ransomware or a stealer merely because of the high-entropy blob or the self-signed certificate: dynamically only the download and file drops were observed, with no encryption, credential access or data exfiltration.
- Do not describe x0[.]at as a C2 panel/callback address: it is a payload hosting point, and the sample only performs one-shot download retries with no heartbeat or command interaction.
- Do not assert that persistence exists (Run keys/services/scheduled tasks): this dynamic run observed no registry or service writes, and statically only the path string is present.
- Do not treat the constant-filled files inside the NSIS package as executed executables: they have no PE header, and no child process was created at runtime.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | dynamic sandbox analysis + static decompilation |
| Unpacked | no |

**Limitations and open questions**

1. The second stage Kp7v.bin was not obtained: network monitoring substituted a fake response for the real site, and all 11 downloader retries never reached the execution flow, so the family and final payload type cannot be confirmed.
2. No per-event telemetry of file/registry writes was obtained, so persistence and autostart entries could not be confirmed; host_iocs.registry/services/tasks are therefore left empty.
3. The sample is a 32-bit GUI installer that depends on wizard interaction; the observed drop and download happened about 1 minute after interaction and do not cover every path after installation completes.

## Evidence index

<details>
<summary>Show 15 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:d8c0ce8dc6` | PE structure parse | PE32 GUI, 5 sections, entry rva 0x34C5, image base 0x400000, 7 imported DLLs, 0 exports |
| `ref:cb96860fc2` | import table parse | 165 imports / 7 DLLs, imphash 6e7f9a29f2c85394521a08b9f31f6275; no static socket/WinINet imports |
| `ref:6b2969295f` | scan.entropy | whole-file entropy 7.369; .text 6.495; .rdata 5.014; .data 4.156; .rsrc 5.912 |
| `ref:4eca17e8b7` | string extraction | ev-000001: 896 ASCII / 51 UTF-16 strings; NSIS integrity messages and no embedded flag/URL |
| `ref:6cfa65711f` | archive listing (static) | NSIS 3.06 Unicode, deflate, headers 15716 B; extracted file inventory and fake version metadata |
| `ref:67780c0084` | archive extraction (static) | 6 data files + 3 NSIS plugins + bitmap; per-file sha256 and constant-byte filler statistics |
| `ref:ae7bba0517` | certificate parsing (static) | self-signed Authenticode cert: CN=Squamify, C=GB, subject==issuer, SHA256, valid 2026-09-08..2027-09-08 |
| `ref:2bc6cccbca` | dynamic analysis platform | real Windows sandbox detonation: 33 polls, pid 6064, 6 detonator dumps, no child process, auto-revert |
| `ref:f55b194d99` | string extraction | ev-000002: network-monitor log strings, 367 ASCII entries incl. HTTP requests |
| `ref:9051288944` | log analysis | 11x 'GET /Kp7v.bin' with Host: x0.at, Firefox/157.0 UA, 10 s retry interval |
| `ref:ddab4c4c7d` | memory forensics | process minidump: UTF-16/ASCII 'hxxps://x0.at/Kp7v.bin' at 0x6CFFC1F/0x6D2B127 and HTTP request headers |
| `ref:aba1498190` | memory forensics | process minidump: UTF-16 install path under %APPDATA%\Microsoft\Windows\Templates\...\upknit |
| `ref:dd10aae79a` | module scan | 65 modules in sample process; 1 modified (ntdll patch), 0 injected PE/shellcode |
| `ref:512e1b78e5` | process enumeration | only sample pid 6064 alive; svchost/monitoring components/system otherwise; no spawned child |
| `c2_evidence:85c35b2d` | connection evidence extraction | dynamic network monitoring recorded 14 connection attempts to x0[.]at:443; no complete session captured |

</details>

---

_This sample is not shared; IOCs are defanged. For security research only._
