---
title: "Malware Analysis: Unclassified .NET Loader (ConfuserEx-style protected) (PE · exe · 468fda82)"
published: 2026-11-03
draft: false
description: "Malicious (low confidence): Unclassified .NET Loader (ConfuserEx-style protected) · loader/backdoor · difficulty hard · dynamic sandbox + static decompilation"
tags: ["loader", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-03-Unclassified-.NET-Loader-ConfuserEx-style-protected-468fda82"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Unclassified .NET Loader (ConfuserEx-style protected)** (uncertain) · Confidence **low**
> 
> After real execution in the isolated Windows 10 environment, the process continuously accessed the fixed IP:port 185[.]91[.]69[.]99:8898 via HTTP GET /ping and reconnected several times within about 2 minutes; meanwhile the sample is an IL-only .NET program embedding multiple encrypted resources with reflective loading/dynamic API resolution capability, consistent with typical in-memory loader/backdoor-channel behavior.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unclassified .NET Loader (ConfuserEx-style protected)** · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · backdoor |
| Difficulty | hard |
| First seen | 2026-11-01 11:37:11 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/468fda829a6e1a7bb3789a31509e272e823e4ef20b4b81311ef2a81393441ef5/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Poll C2 heartbeat endpoint</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Delay egress by 30 seconds</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.003</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded resources</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.013</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Reflectively load later payload</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Resolve system APIs dynamically</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `468fda829a6e1a7bb3789a31509e272e823e4ef20b4b81311ef2a81393441ef5` |
| MD5 | _not recorded_ |
| Size | 831,488 bytes (812.0 KB) |
| Type | PE · `exe` |

## Behavior analysis

**6** behaviors in total, each backed by evidence; **4** statically recoverable, **2** obtained through dynamic analysis.

### 1. Poll C2 heartbeat endpoint

`T1071.001` · Confidence **high** · dynamic

About 30 seconds after startup, the process sends HTTP GET /ping to 185[.]91[.]69[.]99:8898 (Connection: Keep-Alive), retrying roughly every 5 seconds, then reconnects again after about 2 minutes.

> **Evidence**: memory forensics 0x7F4CB4: 'GET /ping HTTP/1.1 Host: 185.91.69[.]99:8898 Connection: Keep-Alive'; network monitoring PID 7500 -> TCP 185.91.69[.]99:8898 at 08:55:25/30/35 and 08:57:40/45
> 
> **Source**: `ref:bf28020ec5` · `ref:a2e7a697a8` · `ref:0bd1c512c9`

### 2. Delay egress by 30 seconds

`T1497.003` · Confidence **medium** · dynamic

It performs its first egress only about 30 seconds after process creation, reducing visible behavior within the sandbox observation window.

> **Evidence**: process created 20:54:55, first TCP connection 20:55:25; PE timeline and network-log timestamps agree
> 
> **Source**: `ref:0bd1c512c9` · `ref:8c68cd1fe1`

### 3. Decrypt embedded resources

`T1027.013` · Confidence **high** · static

It embeds 4 managed resources that are decrypted/decompressed at runtime via AES/Rijndael, TripleDES, and GZip/Deflate; the largest resource is 483,380 bytes.

> **Evidence**: PE resource directory starting at RVA 0x52F14 holds 4 consecutive resources; #Strings contains AesCryptoServiceProvider / RijndaelManaged / TripleDES / GZipStream / DeflateStream
> 
> **Source**: `ref:855a31ca28` · `ref:d4e270a0ce`

### 4. Reflectively load later payload

`T1620` · Confidence **medium** · static

It loads and executes later payloads from memory streams through reflection interfaces such as Assembly.Load / GetManifestResourceStream / GetEntryPoint.

> **Evidence**: TypeRef/MemberRef includes Assembly.Load, GetManifestResourceStream, GetEntryPoint, CreateDecryptor, CryptoStream, DeflateStream
> 
> **Source**: `ref:d4e270a0ce` · `ref:93db342174`

### 5. Resolve system APIs dynamically

`T1106` · Confidence **high** · static

The static imports are only LoadLibrary/GetProcAddress (kernel32), with other sensitive APIs resolved dynamically by name; metadata retains parameter names VirtualAlloc/WriteProcessMemory/VirtualProtect/OpenProcess.

> **Evidence**: ImplMap has 2 rows, ModuleRef=kernel32; #Strings from off 0x49DB0 contains lpAddress/flAllocationType/flProtect/hProcess/lpBaseAddress/flNewProtect/dwDesiredAccess/bInheritHandle/dwProcessId
> 
> **Source**: `ref:93db342174` · `ref:d4e270a0ce`

### 6. Obfuscated IL control flow

`T1027` · Confidence **high** · static

Method bodies are rewritten into switch/constant dispatch control flow with randomized symbol names, and SuppressIldasmAttribute is set, raising the cost of static analysis.

> **Evidence**: the IL of entry method RVA 0x21C4 contains switch [109,68,439] and beq 990/989 dispatch; all 391 type and 2192 method names are random strings
> 
> **Source**: `ref:81597e7896` · `ref:855a31ca28`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (retrying multiple times within a short period).
:::

:::caution
**Real server side still unverified**: the connection/handshake above was completed with a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://185[.]91[.]69[.]99:8898/ping` | 8898 | c2 | dynamic | observed |

### Host

- **No host IOC recovered.**

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `185[.]91[.]69[.]99:8898` | yes | dynamic |
| `c2_path` | `/ping` | yes | dynamic |
| `http_method` | `GET` | no | dynamic |
| `embedded_resources` | `4 encrypted managed resources (10887 / 2336 / 483380 / 454 bytes)` | yes | static |
| `encryption_algo` | `AES/Rijndael + TripleDES + GZip/Deflate (resource decryption)` | no | static |
| `campaign_id` | `-` | no | static |

## Must not claim

:::important
The following conclusions are **prone to misjudgment**; take care when citing this report.

- No file encryption, mass deletion, or ransom notes were observed; it cannot be judged ransomware/wiper.
- No browser credential, wallet, clipboard, or keystroke logging behavior was observed; it cannot be judged a stealer.
- The 483,380-byte encrypted second-stage resource was not decrypted and matched no family signature string, so it cannot be asserted to belong to any known RAT/loader family.
- Process/module scanning found no signs of process injection or hollowing, so cross-process injection cannot be asserted.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The second stage (483,380-byte encrypted resource) could not be successfully decrypted, so the final payload type and family cannot be confirmed.
2. Network monitoring recorded only requests and obtained no server response; the download/command-execution chain was not observed.
3. No registry, file, or service persistence evidence was collected; persistence capability is unknown.
4. The family judgment is based only on the sample's own static features and dynamic behavior and is low confidence; later sample correlation is needed to confirm.

## Evidence index

<details>
<summary>Expand 12 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:ff430bb56a` | sample triage | hash, section entropy 7.421, no imports, 60% packing likelihood |
| `ref:855a31ca28` | PE structure parsing | AMD64 .NET IL-only, 2 sections, CLI header and resource directory RVA 0x52F14/0x795B1 |
| `ref:d4e270a0ce` | string extraction | 2770 ASCII/61 UTF-16 strings extracted, including AES/Rijndael/TripleDES/GZip/Deflate/Assembly/reflection and WinAPI parameter names |
| `ref:0bd1c512c9` | dynamic analysis platform | real dynamic detonation: PID 7500, timeline/network/memory dump packaged, process rolled back |
| `ref:bf28020ec5` | script (dump string extraction) | extracted the complete HTTP request GET /ping Host: 185.91.69[.]99:8898 from process memory 0x7F4CB4 |
| `ref:a2e7a697a8` | script (network log extraction) | network logs show the sample process requesting TCP 185.91.69[.]99:8898 at 08:55:25/30/35 and 08:57:40/45 |
| `ref:8c68cd1fe1` | script (timeline extraction) | detonation timeline: created 20:54:55, first egress 20:55:25, closed 20:57:52 |
| `ref:93db342174` | script (metadata parsing) | ImplMap has only 2 rows, ModuleRef=kernel32 (LoadLibrary/GetProcAddress) |
| `ref:81597e7896` | script (IL disassembly) | entry method RVA 0x21C4 IL is switch/constant-dispatch control flow |
| `ref:adfa51a589` | script (memory context) | config-region context contains deflate/Connection/Keep-Alive and the HTTP request string |
| `ref:c4a346ef2c` | script (PE carve) | memory dump contains only 1 BSJB metadata header; no second .NET assembly found |
| `c2_evidence:468fda82` | connection evidence extraction | dynamic network monitoring recorded 5 connection attempts to 185.91.69[.]99:8898; no complete session captured |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
