---
title: "Malware Analysis: W64 socket loader (block_api hash loader) (PE · exe · 66c32801)"
published: 2026-11-07
draft: false
description: "Malicious (low confidence): W64 socket loader (block_api hash loader) · downloader/loader · difficulty medium · Dynamic sandbox analysis + static decompilation"
tags: ["downloader", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-07-W64-socket-loader-block_api-hash-loader-66c32801"
---

> [!WARNING]
> **Verdict: Malicious** · Family **W64 socket loader (block_api hash loader)** (uncertain) · Confidence **low**
> 
> Aliases: x64 hash-resolution downloader, w64 check-in loader, XOR-0x99 stage-2 downloader
> 
> Decompilation shows the entry point resolving APIs by PEB hashing, building the hardcoded address 103[.]149[.]93[.]150, establishing a raw TCP connection (port 8084), and sending a w64 check-in packet; it then receives data, XORs each byte with 0x99 into RWX memory and executes it; in the real dynamic sandbox the same process did initiate that TCP connection and send the check-in packet (the connection timed out and no second stage was obtained).

## Overview

| Item | Content |
|:--|:--|
| Family | **W64 socket loader (block_api hash loader)** · aliases x64 hash-resolution downloader, w64 check-in loader, XOR-0x99 stage-2 downloader · _uncertain_ |
| Confidence | **low** |
| Behavior class | downloader · loader |
| Difficulty | medium |
| First seen | 2026-11-04 00:56:59 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/66c32801f7888c76b23f54992482c2175a6826f94eb53760d0c633c28f4cb01a/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Resolve imports by hash</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Load network libraries</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Assemble hardcoded C2 address</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Socket connect to 8084</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Send the w64 check-in packet</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `66c32801f7888c76b23f54992482c2175a6826f94eb53760d0c633c28f4cb01a` |
| MD5 | _not recorded_ |
| Size | 3,584 bytes (3.5 KB) |
| Type | PE · `exe` |

## Behavior analysis

**7** behaviors in total, each backed by evidence; **5** are statically available and **2** were obtained through dynamic analysis.

### 1. Resolve imports by hash-walking

`T1027` · Confidence **high** · static

The entry point reads the PEB via gs:[0x60], walks module export tables, and resolves APIs by comparing ror13-style hashes one by one; the import table retains only KERNEL32!Sleep.

> **Evidence**: 0x14000145c hash-resolution function; 0x140001495 mov rax, gs:[0x60]; PE imports only Sleep
> 
> **Source**: `ref:dedc23179a` · `ref:e013029059` · `ref:aaa77a28c6`

### 2. Dynamically load network libraries

`T1129` · Confidence **high** · static

Through the resolved LoadLibraryA it loads user32.dll, ws2_32.dll, and msvcrt.dll in turn, preparing exports for subsequent winsock and formatting calls.

> **Evidence**: 0x14000105x consecutive call LoadLibraryA; strings 'user32.dll'/'ws2_32.dll'/'msvcrt.dll'
> 
> **Source**: `ref:967052c453` · `ref:f4745f772d`

### 3. Assemble the hardcoded C2 address

`T1095` · Confidence **high** · static

It assembles the string 103.149.93[.]150 from immediate segments and writes it into sockaddr_in as the connection target.

> **Evidence**: from 0x1400011cf mov dword '103.'/'149.'/'93.1'/'50', wsprintf concatenation before 0x140001257
> 
> **Source**: `ref:7cb2310859` · `ref:f4745f772d`

### 4. Socket connection to 8084

`T1095` · Confidence **high** · dynamic

It calls WSAStartup(0x202) and socket(AF_INET,SOCK_STREAM,IPPROTO_TCP), then connects to 103.149.93[.]150:8084; on failure it retries every 10 seconds.

> **Evidence**: 0x14000129d WSAStartup; 0x1400012c9 socket; 0x140001321 Sleep(10000) inside the connect loop
> 
> **Source**: `ref:f4745f772d` · `ref:7cb2310859` · `ref:0982a741d1`

### 5. Send the w64 check-in packet

`T1095` · Confidence **high** · dynamic

After the connection succeeds it sends a 44-byte check-in packet: 'w64 ' + network-order port (0x1F94=8084) + '103.149.93[.]150' + zero padding.

> **Evidence**: dynamic network monitoring 0x77 36 34 20 20 20 1F 94 31 30 33 2E 31 34 39 2E 39 33 2E 31 35 30; multiple sends from code at 0x140001335
> 
> **Source**: `ref:0982a741d1` · `ref:7cb2310859`

### 6. XOR-0x99 payload decryption

`T1140` · Confidence **high** · static

It loops recv for chunks of up to 0x64000 bytes, XORs each byte with 0x99, and accumulates them into an allocated buffer until the peer closes.

> **Evidence**: 0x14000141f xor byte ptr [rcx+rdi], 0x99; 0x140001438 call recv
> 
> **Source**: `ref:7cb2310859` · `ref:f4745f772d`

### 7. Allocate RWX and execute the payload

`T1620` · Confidence **high** · static

It requests about 30 MB of PAGE_EXECUTE_READWRITE memory, closesocket after decryption, and directly calls that buffer to execute the second stage inside its own process.

> **Evidence**: 0x1400013f9 VirtualAlloc(0,0x1c9c380,0x1000,0x40); 0x140001446 call rdi
> 
> **Source**: `ref:7cb2310859` · `ref:f4745f772d`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated a TCP connection to this target (with several retries in a short period).
:::

:::caution
**The real server side remains unverified**: the above connection/handshake was completed with a local controlled emulation service, and the real C2's responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `103[.]149[.]93[.]150` | 8084 | c2 | dynamic | observed |

### Host

- **No host IOC was recovered.**

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `103[.]149[.]93[.]150` | yes | dynamic |
| `c2_port` | `8084` | yes | dynamic |
| `encryption_algo` | `single-byte XOR 0x99 (applied byte by byte to the second-stage data received by recv)` | yes | static |
| `beacon_prefix` | `w64 (followed by the network-order port, local/target IP string and zero padding, 44 bytes in total)` | yes | dynamic |
| `stage2_exec` | `VirtualAlloc(NULL, 30000000, MEM_COMMIT, PAGE_EXECUTE_READWRITE); after receiving recv chunks (<=409600) it decrypts in place and executes directly in-process` | yes | static |
| `build_string_candidate` | `log_de.log` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- It should not be judged as ransomware or an infostealer: no file encryption, credential reading, or browser data collection was found.
- Do not claim the second-stage payload or complete instruction set was obtained: the real dynamic C2 connection timed out and no response data was received.
- Do not treat the in-memory string 'log_de.log' directly as a confirmed C2 domain: no DNS resolution of that name was observed dynamically, and its purpose is undetermined.
- Memory forensics finding no injection or module replacement only describes this run, and cannot be used to conclude the sample is harmless overall.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. C2 103[.]149[.]93[.]150:8084 did not respond in the dynamic sandbox and the connection timed out; the second-stage payload was not obtained, so its final capabilities, persistence, and lateral behavior cannot be confirmed.
2. The purpose of the 'log_de.log' string built into the sample is undetermined: no DNS resolution of that name was observed dynamically, so it cannot be confirmed as a backup C2.
3. Memory forensics scanning found no injection or module replacement, but this is based on a single run that never received a second stage and cannot be extrapolated to later stages.
4. No code-signing or PDB path information is available, and family attribution lacks external engine/YARA/public-report corroboration; the family is a candidate label.
5. The isolated environment did not allow real external connections; network conclusions come from passive records of a fake network service.

## Evidence index

<details>
<summary>Show 8 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprints | sha256/md5/sha1 and file size 3584 |
| `ev-000002` | scan.imphash | imphash=e82dd51b077167be63c004bed23d0c1e |
| `ev-000003` | scan.rich | Rich header with 4 toolchain records, richhash=f74c346ecbd50a4203aa4437d0f039c4 |
| `ev-000007` | Sample triage | 3 sections, 0 anomalies, only 1 imported symbol (Sleep) |
| `ev-000008` | String extraction | user32/ws2_32/msvcrt, 'w64 ', '%s%s' strings |
| `ev-000009` | decompile.ghidra | Entry decompilation: resolve APIs, connect to C2, recv+XOR 0x99, RWX execution |
| `ev-000010` | evidence.record | Dynamic artifact parsing: TCP 103.149.93[.]150:8084, 44-byte w64 check-in packet, connection timeout, memory strings |
| `c2_evidence:66c32801` | Connection evidence extraction | Dynamic network monitoring recorded 2 connection attempts to 103.149.93[.]150:8084, maps[.]windows[.]com:443; no complete session was captured |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
