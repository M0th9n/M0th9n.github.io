---
title: "Malware sample analysis: Lumma Stealer (candidate) (PE · exe · 875f4f70)"
published: 2026-11-19
draft: false
description: "Malicious (low confidence): Lumma Stealer (candidate) · stealer/loader · difficulty hard · dynamic sandbox + static decompilation"
tags: ["Lumma", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-19-Lumma-Stealer-candidate-875f4f70"
---

> [!WARNING]
> **Verdict: malicious** · Family **Lumma Stealer (candidate)** (doubtful) · Confidence **low**
> 
> Aliases: LummaC2, policyuntaxed[.]cc campaign
> 
> The sample is a 32-bit GUI PE with an empty import table; its entry point walks the PEB itself and dynamically resolves APIs via MurmurHash3 hashing. Once XORed with 0x5A, static strings expose browser-credential-theft indicators such as logins, SQLite format 3, passwordValue and chrome-extension://. In a real Windows sandbox the sample runs as pid 976 and sends DoH POST /dns-query to port 443 of 8.8.8[.]8/8.8.4[.]4/1.1.1[.]1/1.0.0[.]1, resolving object[.]policyuntaxed[.]cc and then telegra[.]ph, and leaves a runtime-decrypted C2/host-identifier configuration in process memory. Masquerading as a legitimate audio service, covert C2 resolution and browser credential theft together support the malicious verdict.

## Overview

| Item | Details |
|:--|:--|
| Family | **Lumma Stealer (candidate)** · aliases LummaC2, policyuntaxed[.]cc campaign · _doubtful_ |
| Confidence | **Low** |
| Behavior class | stealer · loader |
| Difficulty | hard |
| First seen | 2026-11-18 00:45:41 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/875f4f7091850c5e47950f0c13f86f5e4194fc81d99b9ad14d6aa6ee85094fa7/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Fake audio service component</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Empty imports, hash-resolved API</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.007</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">XOR-decrypt built-in strings</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Parse browser login database</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Hide C2 via DoH queries</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.004</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `875f4f7091850c5e47950f0c13f86f5e4194fc81d99b9ad14d6aa6ee85094fa7` |
| MD5 | _not recorded_ |
| Size | 726,528 bytes (709.5 KB) |
| Type | PE · `exe` |

## Behavior analysis

**8** behaviors in total, each with attached evidence; **7** were obtained statically and **1** through dynamic analysis.

### 1. Masquerades as an audio service component

`T1036.005` · Confidence **high** · Static

The PE manifest and version resource describe it as Realtek.Audio.RtkAudioService / RtkAudioService.exe / Realtek HD Audio Background Service; the file name, vendor and description all point to a legitimate audio component, a typical system-component masquerade.

> **Evidence**: version resource starts at file offset 0xab04c; OriginalFilename=RtkAudioService.exe; assemblyIdentity name=Realtek.Audio.RtkAudioService
> 
> **Source**: `ref:88c4d56d11` · `ref:37f5a8c685`

### 2. Empty imports, hash-based API resolution

`T1027.007` · Confidence **high** · Static

The import directory is empty (0 DLLs, 0 imported symbols). The entry point first calls 0x431070, which reads the PEB via fs:[0x30]; from 0x4016eb onward it hashes API names with MurmurHash3 (constant 0x5BD1E995) and then dynamically resolves the needed functions by hash, so the real API surface is invisible statically.

> **Evidence**: pe_parse IMPORT rva=0/size=0; entry 0x401000 -> 0x431070; 0x431078 mov eax, fs:[0x30]; 0x5BD1E995 constant appears from rva 0x16eb
> 
> **Source**: `ref:6c9cdb3a11` · `ref:0d2607d987` · `ref:23f34883a0` · `ref:d80b304765`

### 3. XOR-decrypts built-in strings

`T1140` · Confidence **high** · Static

Sensitive strings are stored in .rdata XORed with the single byte 0x5A. Decoding by that rule yields plaintext such as logins, SQLite format 3, password, passwordValue, passwords, chrome-extension:// and NtCreateProcess.

> **Evidence**: XOR 0x5A starting at file offset 0x7d979 yields logins; 0x7d981 SQLite format 3; 0x7d9e9 passwordValue; 0x7db69 chrome-extension://; 0x7ff21 NtCreateProcess
> 
> **Source**: `ref:b87d3159df` · `ref:997ecd18c4`

### 4. Parses browser login databases

`T1555.003` · Confidence **medium** · Static

The decoded logins, SQLite format 3, passwordValue, passwords and chrome-extension:// indicate the sample can read Chromium/Firefox login databases (the logins table) and extension data, targeting browser-saved account credentials. No actual file reads or exfiltration were captured during the dynamic window.

> **Evidence**: 0x7d979 logins; 0x7d981 SQLite format 3; 0x7d9e9 passwordValue; 0x7da29 passwords; 0x7db69 chrome-extension://
> 
> **Source**: `ref:b87d3159df`

### 5. Hides C2 via DoH queries

`T1071.004` · Confidence **high** · Dynamic

The sample process sends POST /dns-query (application/dns-message) to port 443 of 8.8.8[.]8, 8.8.4[.]4 (dns[.]google) and 1.1.1[.]1, 1.0.0[.]1 (cloudflare-dns[.]com), first querying object[.]policyuntaxed[.]cc and then telegra[.]ph. Using public DNS over HTTPS services instead of conventional DNS hides the resolution of the real C2 domain.

> **Evidence**: network monitoring recorded pid 976: TCP 8.8.8[.]8:443, 8.8.4[.]4:443, 1.1.1[.]1:443, 1.0.0[.]1:443; DoH messages qname=object[.]policyuntaxed[.]cc, telegra[.]ph
> 
> **Source**: `ref:6e7c3cf8d0` · `ref:94c16a582e` · `ref:b87d3159df`

### 6. Reads machine GUID as identifier

`T1082` · Confidence **high** · Static

The runtime-decrypted configuration contains the Registry Machine Software Microsoft Cryptography path, MachineGuid, FallbackGUID and COMPUTERNAME=, indicating the sample reads the host MachineGuid (falling back to an all-zero GUID when absent) and folds it into the host identifier/beacon parameters.

> **Evidence**: memory config area dump+0x5b1fd shows Machine Software Microsoft Cryptography; +0x5b23d MachineGuid; +0x5b255 FallbackGUID; +0x5b3b5 COMPUTERNAME=
> 
> **Source**: `ref:94c16a582e` · `ref:b87d3159df`

### 7. Prepares ETW evasion

`T1562.006` · Confidence **medium** · Static

The runtime configuration contains both EtwEventWrite and AddVectoredExceptionHandler, indicating the sample locates the ETW event-write function and registers a vectored exception handler, used to block telemetry and to handle anti-debug/exception control flow.

> **Evidence**: memory config area dump+0x5b1b9 EtwEventWrite; +0x5b1d1 AddVectoredExceptionHandler
> 
> **Source**: `ref:94c16a582e` · `ref:b87d3159df`

### 8. Injection target points to Notepad

`T1055.012` · Confidence **low** · Static

The configuration keeps the System32 notepad.exe path, and the decoded built-in strings include native process APIs such as NtCreateProcess, suggesting it may use system Notepad as a process injection/process hollowing host; this dynamic run captured no notepad child process, so whether injection executed is unconfirmed.

> **Evidence**: memory config area dump+0x5b19b System32 notepad.exe; 0x7ff21 decodes to NtCreateProcess
> 
> **Source**: `ref:94c16a582e` · `ref:b87d3159df`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| dns | `object.policyuntaxed[.]cc` | 443 | c2 | Static | ⏳ Not observed |
| dns | `telegra[.]ph` | 443 | dead-drop | Static | ⏳ Not observed |

### Host

**Registry**

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `object.policyuntaxed[.]cc` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `c2_protocol` | `DNS over HTTPS: POST /dns-query, Content-Type: application/dns-message` | Yes | Static |
| `doh_resolvers` | `8.8.8[.]8, 8.8.4[.]4 (dns[.]google), 1.1.1[.]1, 1.0.0[.]1 (cloudflare-dns[.]com)` | Yes | Static |
| `dead_drop_host` | `telegra[.]ph` | No | Static |
| `bot_id_source` | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid` | Yes | Static |
| `fallback_guid` | `00000000-0000-0000-0000-000000000000` | No | Static |
| `campaign_token` | `a2a756bbd8e014767d241a3b2df56734` | No | Static |
| `http_headers` | `Accept; Content-Type; Content-Length; Host` | Yes | Static |
| `inject_target` | `%WINDIR%\System32\notepad.exe` | No | Static |
| `string_obfuscation` | `Single-byte XOR 0x5A` | Yes | Static |
| `api_resolution` | `Resolve APIs dynamically after hashing names with MurmurHash3` | Yes | Static |

## Common misjudgments

:::important
The following conclusions **are easy to misjudge**; please take care when citing this report.

- Do not assert from the logins/SQLite strings that this run actually stole browser credentials — the dynamic window only showed DoH resolution and config decryption, with no login-database file reads or credential exfiltration.
- Do not read comsvcs.t0.dmp as a credential dump of lsass — the file is a process minidump whose content is only a module list, with no lsass access or MiniDumpWriteDump behavior observed.
- Do not treat telegra[.]ph directly as a malicious C2 server — it is a legitimate publishing service being abused; only a DoH query was seen this time, with no content download.
- Do not claim a successful C2 callback — public DoH returned no usable address in the sandbox, and no complete request/response for object[.]policyuntaxed[.]cc appeared.
:::

## Analysis method and limitations

| Item | Details |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The C2 address was decrypted at runtime and confirmed in memory, but public DoH returned no valid A record in the sandbox, and no complete request/response to object[.]policyuntaxed[.]cc was observed; the C2 is recorded as static/pending dynamic review.
2. Browser credential theft capability is inferred from hidden strings and SQLite-related strings; no actual file reads or exfiltration were captured during the dynamic window.
3. The notepad.exe injection target comes from a configuration string; no child process or injection behavior was captured, so the injection chain is unconfirmed.
4. The sample's import table is empty and its configuration is decrypted at runtime, so the call chain cannot be fully reconstructed statically; API resolution relies on runtime hashes and not every API was restored individually.
5. comsvcs.t0.dmp is a process minidump, not a comsvcs.dll module; no evidence of lsass access was found.

## Evidence index

<details>
<summary>Expand 13 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1 and file size, confirming they match the provided hash |
| `ev-000007` | Sample triage | Triage: 0 imported symbols, 5 sections, no high-entropy packing signals |
| `ev-000008` | String extraction | ASCII/UTF-16 string extraction, including Realtek masquerade resource text |
| `ev-000009` | String extraction | Longer string extraction, showing audio-service masquerade copy |
| `ev-000010` | Cryptographic constant identification | TEA/XTEA delta 0x9E3779B9 constant (as a hash/constant clue) |
| `ev-000014` | String extraction | Process memory config-area strings: object[.]policyuntaxed[.]cc, MachineGuid, FallbackGUID, COMPUTERNAME=, campaign token, notepad.exe, etc. |
| `ev-000015` | evidence.record | Results of a script decoding the 0x5A strings and parsing memory config/dynamic network logs |
| `ref:6e7c3cf8d0` | Dynamic analysis platform | Real Windows sandbox detonation record: sample started as pid 976, DoH network requests and memory dump artifacts |
| `ref:0d2607d987` | disasm.function | Entry 0x401000 calls 0x431070 |
| `ref:23f34883a0` | disasm.function | Entry logic of 0x431070 reading the PEB and hash-resolving APIs |
| `ref:d80b304765` | disasm.function | MurmurHash3 (0x5BD1E995) implementation around rva 0x16eb |
| `telemetry:875f4f70` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 96; ETW short-lived process events 1; filtered tool/system noise 27 |
| `etw:875f4f70:976` | Process event monitoring | Short-lived process event: 875f4f7091850c5e47950f0c13f86f5e4194fc81d99b9ad14d6aa6ee85094fa7.exe (pid 976; MD5=78EC9BADE8CDDE43CBC5A3A2F27C199C,SHA256=875F4F7091850C5E47950F0C13F86F5E4194FC81D99B9AD14D6AA6EE85094FA7,IMPHASH=00000000000000000000000000000000) |

</details>

---

_The sample in this report is not public; IOCs are defanged; for security research only._
