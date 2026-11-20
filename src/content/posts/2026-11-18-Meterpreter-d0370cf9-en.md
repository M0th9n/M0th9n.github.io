---
title: "Malware Sample Analysis: Meterpreter (PE · exe · d0370cf9)"
published: 2026-11-18
draft: false
description: "Malicious (medium confidence): Meterpreter · loader/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Meterpreter", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-18-Meterpreter-d0370cf9"
---

> [!WARNING]
> **Verdict: malicious** · Family **Meterpreter** (doubtful) · Confidence **medium**
> 
> Aliases: Metasploit x64 reverse_tcp stager, msfvenom staged loader, MSF shellcode stager
> 
> This is a 3.5 KB 64-bit PE stager: the entry point resolves APIs via PEB traversal plus dual hashing (module name + export name, ror13), loads user32/ws2_32/msvcrt at runtime, then establishes a TCP socket back to 116.62.172[.]147:443, retrying every 10 seconds on failure; after connecting it sends a fixed check-in banner, then allocates 30 MB of PAGE_EXECUTE_READWRITE memory, recv's the second stage in chunks, XORs each byte with 0x99, and calls it directly for execution. Static decompilation/disassembly and the real TCP connection request in the dynamic sandbox corroborate each other.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Meterpreter** · aliases Metasploit x64 reverse_tcp stager, msfvenom staged loader, MSF shellcode stager · _Doubtful_ |
| Confidence | **Medium** |
| Behavior class | loader · downloader |
| Difficulty | medium |
| First seen | 2026-11-17 00:42:27 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/d0370cf97c5960654ba39198d3fe41916d0b6ce03a4b8726d785f402a2985fcd/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Hash-walk PEB for APIs</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Load network libs at runtime</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Callback to fixed IP:443</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Send 40-byte check-in</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Allocate 30MB executable memory</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `d0370cf97c5960654ba39198d3fe41916d0b6ce03a4b8726d785f402a2985fcd` |
| MD5 | _not recorded_ |
| Size | 3,584 bytes (3.5 KB) |
| Type | PE · `exe` |

## Behavior Analysis

**7** behaviors in total, each backed by evidence; **6** are available statically and **1** was obtained through dynamic analysis.

### 1. Hash-walk PEB for APIs

`T1027` · Confidence **high** · Static

Retrieves the PEB via gs:[0x60], walks the export tables along the Ldr module list, and resolves APIs by ror13 + uppercasing + dual hashing of module name/export name; the import table keeps only the single symbol Sleep to evade static detection.

> **Evidence**: 0x14000145c hash-resolution function; 0x14000148d reads gs:[0x60]; PE import table only KERNEL32!Sleep
> 
> **Source**: `ref:af7bb7af10` · `ref:4e956ff90e` · `ref:a32f2d702e`

### 2. Load network libraries at runtime

`T1129` · Confidence **high** · Static

Dynamically loads user32.dll, ws2_32.dll, msvcrt.dll in memory; these dependencies do not appear in the PE import table; the emulation process recorded three LoadLibraryA calls and their parameter strings.

> **Evidence**: 0x140001051 / 0x14000106f / 0x14000108d call rax (LoadLibraryA); emulation API records parameters user32.dll / ws2_32.dll / msvcrt.dll; memory forensics module list contains ws2_32, msvcrt, user32
> 
> **Source**: `ref:1321795876` · `ref:5fd7ed4ebf` · `ref:3494585f8b`

### 3. Callback to fixed IP port 443

`T1095` · Confidence **high** · Dynamic

Calls WSAStartup(0x202), WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP), concatenates the configured 116.62.172[.]147 into a string and connects to TCP 443; on connection failure it enters Sleep(10000) and retries indefinitely.

> **Evidence**: 0x1400012a4 call [rbp-0x30] (WSAStartup, 0x202); 0x140001321 call rsi (connect, sockaddr 0xbb010002=port 443); 0x140001341 call qword ptr [rip+0xce9] (Sleep, 10000); sandbox network log pid 1828 requests TCP 116.62.172[.]147:443
> 
> **Source**: `ref:5fd7ed4ebf` · `ref:10307a3555`

### 4. Send 40-byte check-in banner

`T1095` · Confidence **high** · Static

After the connection is established, it repeatedly calls send to transmit a 40-byte fixed handshake: 6 bytes "w64 ", a 2-byte port in network order, four IP text segments (116./62.1/72.1/47) and 16 bytes of zero padding, used to identify itself to the peer.

> **Evidence**: from 0x140001335, 10 consecutive call rdi (send), with lengths 6/2/4×8 in sequence; the first packet string "w64 " is constructed from the immediate 0x20343677 near 0x1400012d5
> 
> **Source**: `ref:5fd7ed4ebf` · `ref:8b2f9dc2d1`

### 5. Allocate 30 MB of executable memory

`T1620` · Confidence **high** · Static

Calls VirtualAlloc(0, 0x1C9C380, MEM_COMMIT, PAGE_EXECUTE_READWRITE) to allocate about 30 MB of read-write-executable memory as the landing buffer for the second-stage payload.

> **Evidence**: 0x1400013e8 mov edx, 0x1c9c380; 0x1400013f9 call qword ptr [rbp-0x20] (VirtualAlloc, r8d=0x1000, r9d=0x40)
> 
> **Source**: `ref:6fdc33e0da`

### 6. Chunked retrieval of stage two

`T1105` · Confidence **high** · Static

In a loop, repeatedly recv's data in 0x64000 chunks and appends it to the executable buffer above, until the peer closes or an error occurs, achieving fileless payload transfer.

> **Evidence**: 0x140001438 call r15 (recv, r8d=0x64000); 0x14000143c compares the return value and accumulates it into the offset
> 
> **Source**: `ref:6fdc33e0da`

### 7. XOR 0x99 then jump to execute

`T1140` · Confidence **high** · Static

In-place XORs each received byte with 0x99 to decode it, then closesocket and directly calls the buffer's first address, executing the second stage as code.

> **Evidence**: 0x14000141f xor byte ptr [rcx+rdi], 0x99; 0x140001443 call qword ptr [rbp-0x18] (closesocket); 0x140001446 call rdi (execute payload)
> 
> **Source**: `ref:6fdc33e0da`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (multiple retries within a short time).
:::

:::caution
**Real server side still unverified**: the above connection/handshake was completed with a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `116[.]62[.]172[.]147:443` | 443 | c2 | Dynamic | Observed |

### Host

- **No host IOC was recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `116[.]62[.]172[.]147` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `transport` | `raw TCP reverse_tcp stager (WSAStartup→WSASocket→connect)` | Yes | Static |
| `stage_xor_key` | `0x99` | Yes | Static |
| `stage_alloc_size` | `0x1C9C380 (30000000)` | No | Static |
| `handshake_banner` | `w64 (6 bytes) + port 2 bytes + IP text segments + zero padding, 40 bytes total` | No | Static |
| `temp_path_template` | `%TEMP%\log_de.log` | No | Static |

## Do Not Misjudge

:::important
The following conclusions **are easy to misjudge**; note this when citing this report.

- Do not call it ransomware or a credential-stealing trojan: the sample contains no file encryption, credential reading, or browser data access code, and no such behavior appeared in sandbox telemetry.
- Do not assert that it successfully came online or delivered a second stage: the sandbox recorded only one TCP connection request to 116.62.172[.]147:443, with no application-layer session and no recv data returned.
- Do not claim that %TEMP%\log_de.log or any dropped file was created: that path is only assembled from GetTempPathA and sprintf; no file creation or write was observed.
- Do not claim persistence exists: neither the static code nor the dynamic telemetry contains service, scheduled task, or registry Run key operations.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The second-stage payload was not obtained: the C2 did not respond, so the final payload type (Meterpreter or otherwise) and subsequent capabilities cannot be confirmed.
2. Only one TCP connection request was recorded for the C2, with no complete request/response, so the c2 is still marked recoverability=static and pending_dynamic_verify=true.
3. The specific API names resolved are inferred from the dynamic emulation's LoadLibraryA records, Winsock parameter shapes, and the PEB/export-table traversal logic; all 13 hashes were not recomputed offline one by one.
4. The %TEMP%\log_de.log assembled with GetTempPathA in the code was not observed to be actually written, and its purpose is unknown.
5. The PE has no digital signature and no version resources; the compile timestamp only reflects the build toolchain and cannot be used as an attribution basis.

## Evidence Index

<details>
<summary>Expand 10 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashes and fingerprints | sha256=d0370cf97c5960654ba39198d3fe41916d0b6ce03a4b8726d785f402a2985fcd, md5=dab5e1bbe23c59893df1473c00e7a43f, 3584 bytes |
| `ev-000002` | scan.imphash | imphash=e82dd51b077167be63c004bed23d0c1e |
| `ev-000003` | scan.rich | Rich header 4 MSVC toolchain records, richhash=f74c346ecbd50a4203aa4437d0f039c4 |
| `ev-000008` | String extraction | 70 ASCII strings, no flag hits; visible ws2_/msvcrt/user32 fragments and 'w64' data |
| `ev-000009` | decompile.ghidra | entry @0x140001000 decompilation: hash-resolved APIs, WSAStartup/WSASocket/connect/send, VirtualAlloc(30000000,0x40), XOR 0x99 after recv and call |
| `call:call_8da1849f40d64f7cb4378b39` | Dynamic analysis platform | Real dynamic: 2 processes launched (pid 1828/2696), recorded timeline and memory forensics artifacts, rolled back |
| `call:call_791ceddf6ab7426bbc8bf3f0` | sandbox.log | Network monitoring log line 223: d0370...exe (1828) requested TCP 116.62.172[.]147:443 |
| `c2_evidence:d0370cf9` | Connection evidence extraction | Dynamic network monitoring recorded 1 connection attempt to 116.62.172[.]147:443; no complete session captured |
| `telemetry:d0370cf9` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 107; ETW short-lived process events 1; filtered tool/system noise 30 |
| `etw:d0370cf9:1828` | Process event monitoring | Short-lived process event: d0370cf97c5960654ba39198d3fe41916d0b6ce03a4b8726d785f402a2985fcd.exe (pid 1828; MD5=DAB5E1BBE23C59893DF1473C00E7A43F,SHA256=D0370CF97C5960654BA39198D3FE41916D0B6CE03A4B8726D785F402A2985FCD,IMPHASH=E82DD51B077167BE63C004BED23D0C1E) |

</details>

---

_The sample in this report is not public; IOCs have been defanged and are for security research only._
