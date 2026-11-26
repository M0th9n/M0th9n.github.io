---
title: "Malicious sample analysis: HijackLoader (PE · exe · 26194ae0)"
published: 2026-11-25
draft: false
description: "Malicious (confidence: low): HijackLoader · loader/downloader/injector · difficulty hard · dynamic sandbox + static decompilation"
tags: ["Hijack", "loader", "downloader", "injector", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-25-HijackLoader-26194ae0"
---

> [!WARNING]
> **Verdict: malicious** · Family **HijackLoader** (unconfirmed) · Confidence **low**
> 
> Aliases: IDAT Loader, Google Drive loader, winmm sideload downloader
> 
> In the dynamic sandbox the sample creates and masquerades as C:\Windows\SysWOW64\svchost.exe (the command line still points to the sample's own path) and implants an executable PE of about 0x33000 bytes into that process; after running, that payload issues download requests to drive[.]usercontent[.]google[.]com, and contains built-in /info, /service and /dll polling logic against 185[.]156[.]73[.]98 as well as code to sideload winmm.exe + WINMM.dll under %TEMP%. Although the sample carries a 360 code signature, the signature hash does not match the file, so it cannot be treated as trusted on that basis.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **HijackLoader** · Aliases IDAT Loader, Google Drive loader, winmm sideload downloader · _unconfirmed_ |
| Confidence | **low** |
| Behavior class | loader · downloader · injector |
| Difficulty | hard |
| First seen | 2026-11-25 00:13:21 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/26194ae00bd4cc4cdd09810b244b5e536c1dc66a048b85bd7985cb94a99621aa/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypts resource, jumps to exec</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009 / T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Masquerades as svchost, injects</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012 / T1036.005</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Downloads from Google Drive</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105 / T1071.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Polls C2 for commands</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Drops winmm sideload component</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `26194ae00bd4cc4cdd09810b244b5e536c1dc66a048b85bd7985cb94a99621aa` |
| MD5 | _Not recorded_ |
| Size | 872,720 bytes (852.3 KB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **9** behaviors in total, each backed by evidence; **6** are statically available and **3** were obtained through dynamic analysis.

### 1. Decrypts resource and jumps to execution

`T1027.009 / T1140` · Confidence **high** · Static

FormCreate of the Tkkjhh form takes data from its own resource (type RTIRTWERQQ, name TJERTIER6, 203508 bytes), walks the resource and calls VirtualAlloc to allocate executable memory, copies the data in a loop, decrypts it using GetTickCount/QueryPerformanceCounter in the computation, and finally executes jmp edx into the decrypted buffer.

> **Evidence**: FormCreate @ 0x884D4; strings rtirtwerqq/tjertier6/VirtualAlloc @ 0x88730-0x88758; 0x4886FB jmp edx; resource RVA 0x9BF3C, size 203508
> 
> **Source**: `ref:e748c53e8c` · `ref:7b3ea66452` · `ref:efa19676bd` · `ref:c1eacd1610`

### 2. Masquerades as svchost and injects

`T1055.012 / T1036.005` · Confidence **high** · Dynamic

The sample creates a C:\Windows\SysWOW64\svchost.exe child process (PID 648, command line still the sample path, forming the masquerade), then implants a MEM_PRIVATE executable PE module c20000 (0x33000 bytes, PE header replaced) into that process; memory forensics classifies it as hollowing/implant injection.

> **Evidence**: process timeline: PID 648 C:\Windows\SysWOW64\svchost.exe created by the sample at 00:07:46; memory forensics on process 648 reports replaced=1, implanted_pe=1, MEM_PRIVATE, module c20000(0x33000)
> 
> **Source**: `ref:9213969c74` · `ref:c096262690` · `ref:9e785a25e2`

### 3. Downloads from Google Drive

`T1105 / T1071.001` · Confidence **high** · Dynamic

The injected svchost uses WinINet (InternetOpenA/InternetConnectA/HttpOpenRequestA/HttpSendRequestA) to access drive[.]usercontent[.]google[.]com and GET the download URL for the specified id; the network-monitoring log captured the complete Host and path of that request.

> **Evidence**: decompiled FUN_00c21b67 shows the hardcoded URL and InternetConnectA port 0x1BB(443); network log resolved drive[.]usercontent[.]google[.]com at 12:07:47 and captured GET /download?id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY... at 12:07:49 (Host: drive[.]usercontent[.]google[.]com)
> 
> **Source**: `ref:ec39b3d175` · `ref:a12c0dd6f4` · `ref:d245cfea91`

### 4. Polls C2 for commands

`T1071.001` · Confidence **high** · Static

The payload embeds 185[.]156[.]73[.]98; it first polls /info and waits for a 10-100 byte response, then assembles /service with a SUB= parameter, parses the server response, looks up the function pointer by the name updateSW and executes it in a loop every 2 seconds, forming a remote-command channel.

> **Evidence**: decompiled FUN_00c241a9 polls /info (Sleep 3000), decodes the response and calls updateSW; FUN_00c211ec uses 185_156_73_98_service with 0x2F XOR restoration; strings 185.156.73[.]98, 185.156.73[.]98/service, /info, /dll, SUB=, updateSW
> 
> **Source**: `ref:1510dbc0b1` · `ref:ac5fabcd52` · `ref:695461321f` · `ref:7f9b74c635`

### 5. Drops the winmm sideload component

`T1574.002` · Confidence **high** · Static

The payload creates a randomly named directory (8-29 characters) under %TEMP%, writes winmm.exe and WINMM.dll (strings restored with 0x2F XOR), then launches winmm.exe via ShellExecuteExA to achieve DLL sideload execution.

> **Evidence**: decompiled FUN_00c23525: GetTempPathA→CreateDirectoryA(random name)→write \WINMM.dll and \winmm.exe; FUN_00c23472: ShellExecuteExA + WaitForSingleObject(60s); strings offset 0x2E880/0x2E914
> 
> **Source**: `ref:d2407446fa` · `ref:7abe81ca50` · `ref:695461321f`

### 6. Memory-maps the downloaded PE

`T1620` · Confidence **medium** · Static

The payload performs PE parsing and manual mapping of the downloaded data, including failure branches for Size/DOS header/DOS header size/IMAGE_NT_SIGNATURE/Machine/section alignment checks, allocates memory, writes the image and jumps to execute it — reflective loading.

> **Evidence**: strings Size is not valid!, DOS header is not valid!, DOS header size is not valid!, Signature != IMAGE_NT_SIGNATURE!, FileHeader.Machine != HOST_MACHINE!, Section alignment invalid!, ERROR_OUTOFMEMORY! @ 0x29F68-0x2A044; VirtualAlloc/VirtualProtect imports
> 
> **Source**: `ref:c1eacd1610` · `ref:bad8dc77b1` · `ref:0486d81efd`

### 7. Writes a registry autostart entry

`T1547.001` · Confidence **medium** · Static

The payload's code path calls RegCreateKeyExA/RegOpenKeyExA/RegSetValueExA, creating and writing key values under HKEY_CURRENT_USER(0x80000001), giving it registry persistence capability; the specific key/value names were not obtained within the analysis window.

> **Evidence**: FUN_00c24647 @ 0xc24647 calls RegCreateKeyExA(HKCU, ...), RegSetValueExA; the function is called from the main flow and the key/value names are passed as function parameters and were not recovered in plaintext
> 
> **Source**: `ref:16b729c85d`

### 8. Random delays to evade the sandbox

`T1497.003` · Confidence **high** · Static

Before its main flow the injected payload waits a random Sleep(1000-5000ms), and stage one also includes a loop delay of about 32.5 million GetTickCount iterations, used to outlast the observation window of automated sandboxes.

> **Evidence**: FUN_00c24800 Sleep(FUN_00c23201(1000,5000)); FUN_00c241a9 Sleep(FUN_00c23201(1000,4000)); FormCreate 0x488603 mov esi,0x1EF6154 loops calling 0x4067E8
> 
> **Source**: `ref:54e131ef55` · `ref:1510dbc0b1` · `ref:7b3ea66452`

### 9. Probes a numeric domain

`T1071.004` · Confidence **medium** · Dynamic

During execution the masqueraded svchost process issues an A/AAAA query about every 4 seconds for the fixed 25-digit numeric domain 6789556796767367618366156.local, continuing for about 2.5 minutes — DNS-side beaconing/probing behavior.

> **Evidence**: network-monitoring log: multiple "Received A/AAAA request for domain '6789556796767367618366156.local'"; the process timeline attributes the queries to PID 648 (C:\Windows\SysWOW64\svchost.exe), 37 in total
> 
> **Source**: `ref:db698ddb6f` · `ref:d245cfea91`


## IOCs (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (multiple retries within a short period).
:::

:::caution
**Real server side still unverified**: the above connections/handshakes were completed with a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://185[.]156[.]73[.]98/service` | 80 | c2 | Static | ⏳ Not observed |
| http | `hxxp://185[.]156[.]73[.]98/info` | 80 | c2 | Static | ⏳ Not observed |
| http | `hxxp://185[.]156[.]73[.]98/dll` | 80 | download | Static | ⏳ Not observed |
| http | `hxxps://drive[.]usercontent[.]google[.]com/download?id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY&export=download&authuser=0&confirm=t` | 443 | download | Dynamic | Observed |

### Host

**Drop path**

- `%TEMP%\<random 8-29 character directory>\WINMM.dll`
- `%TEMP%\<random 8-29 character directory>\winmm.exe`
- `C:\Windows\SysWOW64\svchost.exe`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `185[.]156[.]73[.]98` | Yes | Static |
| `c2_port` | `80` | Yes | Static |
| `c2_uri` | `/service,/info,/dll` | Yes | Static |
| `download_url` | `hxxps://drive[.]usercontent[.]google[.]com/download?id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY&export=download&authuser=0&confirm=t` | Yes | Dynamic |
| `drop_dir` | `%TEMP%\<random 8-29 character directory>` | Yes | Static |
| `dropped_files` | `winmm.exe, WINMM.dll` | Yes | Static |
| `command_id` | `updateSW` | No | Static |
| `http_header` | `SUB=` | No | Static |
| `dns_lookup_name` | `6789556796767367618366156[.]local` | No | Dynamic |
| `encryption_algo` | `Windows CryptoAPI (CryptAcquireContextW/CryptCreateHash/CryptDeriveKey/CryptDecrypt)` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not judge it as trustworthy or legitimate because it carries a Qihoo 360 code signature: the signature's Authenticode hash does not match this file (HashMismatch), making it an invalid/reused signature.
- Do not claim a successful C2 session was established with 185[.]156[.]73[.]98: no complete requests/responses to /service, /info or /dll were observed within the dynamic window, and the related content comes only from static extraction.
- Do not claim specific registry autostart key or value names were observed: only the RegCreateKeyExA/RegSetValueExA call path is confirmed, and no key-value evidence was obtained.
- Do not classify it as ransomware or a data-destruction program: no file encryption, ransom notes or bulk deletion behavior was found.
- Do not treat the Google Drive download content as having successfully landed and executed: network monitoring returned an emulated response, and no real second-stage file was obtained.
- Do not attribute the analysis environment's own scheduled tasks, PowerShell or forensic-tool processes to the sample.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `bb1f3dd1e39530421e8288244f59575f47b52fa7f787820a9c62d727c9724908`) |

**Limitations and pending verification**

1. The Google Drive download returned a fake response in the emulated network and no real second-stage file was obtained, so subsequent C2 interactions such as /service were not triggered; the C2-related entries are statically extracted and await re-verification in a real environment.
2. Many strings in the injected payload are encrypted with Windows CryptoAPI; only the plaintext IP, paths, download URL and command names were recovered, while registry key names, User-Agent and the complete configuration were not restored.
3. Resolution of the numeric domain 6789556796767367618366156.local did not succeed (invalid name returned), so its purpose (beacon/tunnel/host probing) cannot be further confirmed.
4. In the process timeline the recorded time of some DNS events is inconsistent with the process creation time; the report uses only the process attribution and query content and draws no conclusion from that time field.
5. The 360 code signature attached to the sample does not match the file hash, so it cannot be determined whether this is signature theft, post-signing tampering or signature splicing.
6. Delphi decompilation support is limited; the resource decryption and jump-to-execution in stage one are inferred mainly from disassembly and post-run injection results.
7. No actual writes of persistence key values were seen within the analysis window, nor any network session with 185[.]156[.]73[.]98.

## Evidence Index

<details>
<summary>Expand 27 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:e41fc7d13c` | Sample triage | Sample hash/imphash/section entropy/import-surface triage, .rsrc entropy 7.195 |
| `ref:1d45348bd2` | PE structure parsing | PE32 GUI program, 8 sections, ImageBase 0x400000, entry RVA 0x88ACC, security directory points to the last 13584 bytes of the file |
| `ref:efa19676bd` | pe.resources | Named resource RTIRTWERQQ/TJERTIER6 size 203508; form resources TKKJHH etc. |
| `ref:e748c53e8c` | disasm.function | Tkkjhh FormCreate disassembly: references rtirtwerqq/tjertier6/VirtualAlloc and allocates/moves data |
| `ref:7b3ea66452` | script | FormCreate tail disassembly: GetTickCount loop, XOR decryption, 0x4886FB jmp edx into the decrypted buffer |
| `ref:6a835aa598` | powershell.Authenticode | Signature status HashMismatch, signature hash does not match file content |
| `ref:fac518da2e` | openssl.pkcs7 | Signature chain includes a code-signing certificate for C=HK O=QIHU 360 SOFTWARE CO. LIMITED, issued by VeriSign Class 3 Code Signing 2010 CA |
| `ref:9213969c74` | Dynamic analysis platform | Real dynamic detonation completed, producing a process timeline, memory dumps, network logs and telemetry packages |
| `ref:c096262690` | script | Memory forensics result: svchost.exe (PID 648) has a replaced PE implanted module c20000(0x33000); sample PID 3040 was dumped |
| `ref:9e785a25e2` | script | Telemetry event: PID 648 C:\Windows\SysWOW64\svchost.exe was created during the run, with the command line pointing to the sample path |
| `ref:d245cfea91` | script | 37 numeric-domain DNS queries by process 648 and 1 query for drive[.]usercontent[.]google[.]com |
| `ref:db698ddb6f` | script | Network-monitoring log captured A/AAAA queries for 6789556796767367618366156.local |
| `ref:a12c0dd6f4` | script | Network-monitoring log captured DNS and HTTP GET for drive[.]usercontent[.]google[.]com (complete Host header) |
| `ref:7704d0d2f7` | PE structure parsing | Payload PE32 recovered from memory: ImageBase 0xC20000, entry 0xB2D9, 6 sections |
| `ref:0486d81efd` | Import table parsing | Payload imports CryptAcquireContextW/CryptDecrypt, WinINet, RegCreateKeyExA/RegSetValueExA, ShellExecuteExA etc. |
| `ref:695461321f` | script | Payload plaintext strings: 185.156.73[.]98, /service, /info, /dll, SUB=, updateSW, \winmm.exe, \WINMM.dll |
| `ref:ec39b3d175` | decompile.ghidra | FUN_00c21b67: hardcoded Google Drive download URL, requests via WinINet port 443 |
| `ref:ac5fabcd52` | decompile.ghidra | FUN_00c211ec: uses 185_156_73_98_service with 0x2F XOR restoration |
| `ref:1510dbc0b1` | decompile.ghidra | FUN_00c241a9: polls /info and server responses, looks up the function pointer by updateSW and loops execution |
| `ref:d2407446fa` | decompile.ghidra | FUN_00c23525: drops \WINMM.dll and \winmm.exe in a random %TEMP% directory |
| `ref:7abe81ca50` | decompile.ghidra | FUN_00c23472: ShellExecuteExA launches the dropped file and waits 60 seconds |
| `ref:16b729c85d` | decompile.ghidra | FUN_00c24647: RegCreateKeyExA/RegOpenKeyExA/RegSetValueExA writes HKCU key values |
| `ref:54e131ef55` | decompile.ghidra | FUN_00c24800: download, /service assembly, winmm component drop and command-line branches |
| `ref:c1eacd1610` | script | Payload PE manual-mapping validation strings (DOS/NT headers, section alignment, etc.) and C2 path strings |
| `c2_evidence:26194ae0` | Connection evidence extraction | Dynamic network monitoring recorded 1 connection attempt to drive[.]usercontent[.]google[.]com:443; no complete session captured |
| `telemetry:26194ae0` | Dynamic telemetry | Dynamic telemetry recorded: 157 process/file events from the monitoring component; 1 ETW short-lived process event; 22 tool/system noise entries filtered |
| `etw:26194ae0:3040` | Process event monitoring | Short-lived process event: 26194ae00bd4cc4cdd09810b244b5e536c1dc66a048b85bd7985cb94a99621aa.exe (pid 3040; MD5=304ED0907138D26691F4B970F09BB9A2,SHA256=26194AE00BD4CC4CDD09810B244B5E536C1DC66A048B85BD7985CB94A99621AA,IMPHASH=00000000000000000000000000000000) |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
