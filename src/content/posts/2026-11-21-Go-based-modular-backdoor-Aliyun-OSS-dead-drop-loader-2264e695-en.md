---
title: "Malware sample analysis: Go-based modular backdoor (Aliyun OSS dead-drop loader) (PE · exe · 2264e695)"
published: 2026-11-21
draft: false
description: "Malicious (low confidence): Go-based modular backdoor (Aliyun OSS dead-drop loader) · backdoor/loader/implant · difficulty hard · dynamic sandbox + static decompilation"
tags: ["Go-based modular", "backdoor", "loader", "implant", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-21-Go-based-modular-backdoor-Aliyun-OSS-dead-drop-loader-2264e695"
---

> [!WARNING]
> **Verdict: malicious** · family **Go-based modular backdoor (Aliyun OSS dead-drop loader)** (uncertain) · confidence **low**
> 
> Aliases: wheel01st domain family
> 
> After the sample starts as a 64-bit PE, within the analysis window its own process (PID 1776) makes an HTTPS request to 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com: GET /tad (User-Agent: 3M), and network monitoring captured the complete request line and Host header; meanwhile its 32 MB .data section embeds the complete Go runtime and dependency string table (Go buildinf, go[.]mongodb[.]org, protobuf, golang[.]org/x/net) as well as the hardcoded domain wheel01st-ru[.]crossout[.]net. The program's actual code is only about 125 KB, with the rest being embedded payload and padding data, consistent with a "loader disguised as legitimate software plus embedded Go backdoor" structure, hence malicious.

## At a glance

| Item | Value |
|:--|:--|
| Family | **Go-based modular backdoor (Aliyun OSS dead-drop loader)** · aliases wheel01st domain family · _uncertain_ |
| Confidence | **low** |
| Behavior class | backdoor · loader · implant |
| Difficulty | hard |
| First seen | 2026-11-20 21:07:41 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/2264e6958399df51e2f9c244f8c9dfc85fba3f55ec942a45afdc94035dad284a/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Fetches tasking from Aliyun bucket</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Go implant resident in memory</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Embedded hardcoded callback domain</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Fakes Tencent component appearance</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Carries oversized padding payload</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identifiers

| Item | Value |
|:--|:--|
| SHA-256 | `2264e6958399df51e2f9c244f8c9dfc85fba3f55ec942a45afdc94035dad284a` |
| MD5 | _not recorded_ |
| Size | 32,320,160 bytes (30.8 MB) |
| Type | PE · `exe` |

## Behavior analysis

**7** behaviors in total, each with evidence attached; **5** of them are statically obtainable and **2** were obtained through dynamic analysis.

### 1. Fetches tasking from Aliyun bucket

`T1071.001` · confidence **high** · dynamic

About 40 seconds after process start it makes an HTTPS request to 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com:443, with request line GET /tad, User-Agent 3M, and the Host header pointing to that object-storage domain.

> **Evidence**: network monitoring log: '2264e69...exe (1776) requested TCP 192.0.2[.]123:443', followed by 'GET /tad HTTP/1.1 / User-Agent: 3M / Host: 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com'
> 
> **Source**: `ref:0c2984b08b`

### 2. Go implant resident in memory

`T1027` · confidence **medium** · dynamic

The memory image during the process lifetime contains symbols and paths such as the Go runtime, protobuf (duration.proto/timestamp.proto), google[.]golang[.]org/grpc, and go[.]mongodb[.]org, indicating that what actually executes is an embedded Go backdoor rather than the surface C++ component.

> **Evidence**: minidump of PID 1776 contains strings 'Go buildinf:', 'go[.]mongodb[.]org', 'duration.proto', 'google[.]golang[.]org', etc., and wheel01st-ru[.]crossout[.]net appears three times
> 
> **Source**: `ref:0ec81dae14` · `ref:6dc96c6c0e`

### 3. Embedded hardcoded callback domain

`T1071.001` · confidence **high** · static

The file's .data section hardcodes wheel01st-ru[.]crossout[.]net (three copies), identical to the same string in runtime memory, forming a backup/upstream C2 domain.

> **Evidence**: static search hits offsets 0x2d45e4 / 0xa2a7b4 / 0x19c42d4, and it also appears in the memory dump
> 
> **Source**: `ref:80bbbfe1c4`

### 4. Fakes Tencent component appearance

`T1036` · confidence **medium** · static

The resource section writes Tencent version information (LegalCopyright 'Tencent Corporation', version 3.37.1[.]426) and includes code-signing directory entries pointing to DigiCert and Tencent Technology (Shenzhen), to lower the vigilance of users and static detection.

> **Evidence**: PE resource VS_VERSION_INFO @0x1ecf34e; security directory RVA 0x1ED000, containing CN=Tencent Technology (Shenzhen) Company Limited certificate
> 
> **Source**: `ref:ea71e090e3`

### 5. Carries oversized padding payload

`T1027.002` · confidence **high** · static

.text is only about 125 KB while .data reaches 31.9 MB, most of which is zero padding and RTTI, fonts, and file-type tables from unrelated projects, with actual code accounting for a tiny fraction, a payload-stuffing and size-inflation technique.

> **Evidence**: pe.parse: .text size_of_raw_data=125440, .data size_of_raw_data=31979520; .data entropy 4.105 and contains unrelated strings such as RPCS3/Qt/Courier Prime
> 
> **Source**: `ref:c394d7e925` · `ref:1c5c80b48f`

### 6. Dynamically resolves APIs at runtime

`T1129` · confidence **medium** · static

The import table retains only 88 basic APIs, including LoadLibraryA/W, GetProcAddress, and VirtualAlloc, used to load capability modules on demand at runtime, consistent with a loader/plugin-style backdoor structure.

> **Evidence**: pe.imports: KERNEL32 LoadLibraryA iat_rva 0x20048, GetProcAddress 0x20038, VirtualAlloc 0x20280
> 
> **Source**: `ref:681cbc24ab`

### 7. Anti-debugging and exception-dispatch probing

`T1622` · confidence **low** · static

It imports IsDebuggerPresent, SetUnhandledExceptionFilter, and RtlCaptureContext/RtlVirtualUnwind, giving it debugger and environment probing capability (no anti-analysis action resulting from this was observed in this run).

> **Evidence**: IAT: IsDebuggerPresent @0x20270, SetUnhandledExceptionFilter @0x202D0, RtlVirtualUnwind @0x202C0
> 
> **Source**: `ref:681cbc24ab`


## IOCs (defanged)

### Network

:::note
**A connection was dynamically observed**: the sample actually initiated a TCP connection to this target (with multiple retries within a short period).
:::

:::caution
**The real server side remains unverified**: the above connection/handshake was completed with a local controlled emulation service, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com/tad` | 443 | c2 | Dynamic | Observed |
| dns | `wheel01st-ru[.]crossout[.]net` | 0 | c2 | Static | ⏳ not observed |

### Host

- **No host IOC was recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com\|wheel01st-ru[.]crossout[.]net` | Yes | Dynamic |
| `c2_port` | `443` | Yes | Dynamic |
| `c2_uri` | `/tad` | Yes | Dynamic |
| `user_agent` | `3M` | Yes | Dynamic |
| `transport` | `HTTPS, object-storage bucket as the tasking channel` | No | Dynamic |
| `payload_language` | `Go, with protobuf and MongoDB driver` | No | Static |
| `install_path` | `-` | No | Static |

## Do not misjudge

:::important
The conclusions below are **easily misjudged**; take care when citing this report.

- Do not assert that the sample is an official Tencent release component: version resources and signature directories can be copied or abused, and the certificate chain and signature validity must be verified independently.
- Do not assert that process injection, scheduled tasks, or registry persistence occurred: memory scanning found no implanted PE/shellcode, and no registry or service writes were observed.
- Do not assert that data has been exfiltrated: only one GET /tad request was captured, and no response body or upload behavior was seen.
- Do not assert that wheel01st-ru[.]crossout[.]net was actually connected in this run: it appears only in static strings and memory, with no corresponding network session.
- Do not conclude that ransomware encryption or a custom encrypted protocol exists just from AES/SHA-256 constants: these constants are in the embedded data and general libraries.
:::

## Analysis method and limitations

| Item | Value |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The dynamic channel captured only one outbound request (GET /tad), with no response content, so the tasking type cannot be determined.
2. No child process creation, file write, or registry/service/scheduled-task change was observed; persistence capability is unknown.
3. Complete extraction and recovery of the Go payload embedded in .data was not completed (most of .data is padding, and the payload boundaries are undetermined), so the payload hash is empty.
4. The Authenticode certificate chain was not validated, and signature attribution is based only on the certificate subject description in the directory.
5. The callback to wheel01st-ru[.]crossout[.]net did not occur in this run, and external network or a longer observation window is needed to confirm it.
6. At the static level there are many RTTI and resource strings from unrelated projects, which may interfere with string-based family classification.

## Evidence index

<details>
<summary>Expand 14 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:1c5c80b48f` | Sample triage | hash/imphash/section entropy and packing score (packing.score=0) |
| `ref:cc4bf94422` | Hash & fingerprint | sha256 and imphash=20abbe0f6ab059ea4a375bcb6b8a717b |
| `ref:c394d7e925` | PE structure parsing | section table: .text 125440 bytes / .data 31979520 bytes |
| `ref:681cbc24ab` | Import table parsing | 4 DLLs, 88 symbols, including LoadLibrary/GetProcAddress/VirtualAlloc/IsDebuggerPresent |
| `ref:ea71e090e3` | String extraction | resource-section Tencent version information 3.37.1[.]426 and copyright string |
| `ref:80bbbfe1c4` | static-grep | three offsets of wheel01st-ru[.]crossout[.]net and Go buildinf/mongo dependency names |
| `ref:bc0b0c7c07` | decompile.ghidra | FUN_140002fd0 decompilation, confirmed as thin-shell C++ startup logic |
| `ref:48a31897ef` | Dynamic analysis platform | real dynamic run: PID 1776 detonation, 34 polls, timeline and memory dump produced |
| `ref:0c2984b08b` | network-monitor | sample process requests 192.0.2[.]123:443 and sends GET /tad, Host=3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com, UA=3M |
| `ref:0ec81dae14` | memory-forensics | process memory dump contains Go runtime, protobuf, mongo driver, and C2 domain |
| `ref:3d5156c9bd` | dyn.run | emulation stayed at CRT initialization and did not reproduce network behavior, so real dynamic evidence is authoritative |
| `c2_evidence:2264e695` | Connection evidence extraction | dynamic network monitoring recorded 1 connection attempt to 3byy0j[.]oss-cn-beijing[.]aliyuncs[.]com:443; full session not captured |
| `telemetry:2264e695` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 110; ETW short-lived process events 1; filtered tool/system noise 18 |
| `etw:2264e695:1776` | Process event monitoring | Short-lived process event: 2264e6958399df51e2f9c244f8c9dfc85fba3f55ec942a45afdc94035dad284a.exe (pid 1776; MD5=9CBE0AA9E2217AEE24F80162EFBEF7D4,SHA256=2264E6958399DF51E2F9C244F8C9DFC85FBA3F55EC942A45AFDC94035DAD284A,IMPHASH=20ABBE0F6AB059EA4A375BCB6B8A717B) |

</details>

---

_This report's sample is not public, IOCs are defanged, for security research only._
