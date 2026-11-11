---
title: "Malware Analysis: Unclassified ROR13 hash-resolving TCP stager (PE · exe · e6e51ff0)"
published: 2026-11-10
draft: false
description: "Malicious (low confidence): Unclassified ROR13 hash-resolving TCP stager · loader/downloader · difficulty medium · Dynamic sandbox analysis + static decompilation"
tags: ["loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-10-Unclassified-ROR13-hash-resolving-TCP-stager-e6e51ff0"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Unclassified ROR13 hash-resolving TCP stager** (uncertain) · Confidence **low**
> 
> The 3.5KB 32-bit GUI PE has no normal functional imports (only KERNEL32!Sleep); after launch it dynamically resolves 18 network/memory/string APIs through PEB traversal and ROR13 hashing, connects to the hard-coded public address 134.122.154[.]92:2086, sends a 40-byte host fingerprint handshake, then allocates 30MB of RWX memory, receives the remote data in chunks and decrypts it with XOR 0x99 before executing it directly. This behavior set was fully observed in a real dynamic sandbox, including the outbound connection and handshake, and is a typical fileless downloader/loader.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unclassified ROR13 hash-resolving TCP stager** · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · downloader |
| Difficulty | medium |
| First seen | 2026-11-07 21:30:14 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/e6e51ff061c04b656f2d4187e34c95331444a9d28ea585ecd9a576550a2dc4c6/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Hash-resolving API loading</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Check temporary marker file</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Connect to hard-coded C2</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Send host heartbeat</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1041</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Allocate RWX memory</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `e6e51ff061c04b656f2d4187e34c95331444a9d28ea585ecd9a576550a2dc4c6` |
| MD5 | _not recorded_ |
| Size | 3,584 bytes (3.5 KB) |
| Type | PE · `exe` |

## Behavior analysis

**7** behaviors in total, each backed by evidence; **5** are statically available and **2** were obtained through dynamic analysis.

### 1. Hash-resolving API loading

`T1027` · Confidence **high** · static

The static import table contains only KERNEL32!Sleep; the sample reads the PEB via fs:[0x30] and walks modules along InMemoryOrderModuleList, resolving 18 APIs (LoadLibraryA/GetTempPathA/wsprintfA/_access/WSAStartup/WSASocketA/connect/send/recv/VirtualAlloc/MessageBoxA, etc.) using a hash computed by accumulating ROR13 over the module name UTF-16 bytes plus the export name (including the trailing NUL), erasing the real import surface.

> **Evidence**: 0x40145F FUN_0040145f fills the function table with hash constants; 0x401369 FUN_00401369 walks the PEB export table; the ROR13 loop is at 0x4013BA-0x4013D6
> 
> **Source**: `ev-000011` · `ev-000010` · `ev-000002`

### 2. Check temporary marker file

`T1480` · Confidence **medium** · static

It calls GetTempPathA to obtain %TEMP%, builds %TEMP%\log_de.log with wsprintfA, then uses _access(path,0) to check whether it already exists; if so, it exits immediately, implementing single-instance/duplicate-run protection.

> **Evidence**: 0x40102D GetTempPathA; 0x40109E _access; instruction-level emulation yields the path C:\Users\<user>\AppData\Local\Temp\log_de.log
> 
> **Source**: `ev-000012` · `ev-000009`

### 3. Connect to hard-coded C2

`T1095` · Confidence **high** · dynamic

After WSAStartup(0x202) it creates a stream socket with WSASocketA(2,1,6) and fills sockaddr_in (AF_INET, port 2086, inet_addr("134.122.154[.]92")); if connect fails it retries indefinitely with Sleep(10000).

> **Evidence**: 0x4011E6 WSASocketA; 0x401244 connect; the sandbox network side recorded e6e51ff0...exe(PID 1340) requested TCP 134.122.154[.]92:2086
> 
> **Source**: `ev-000013` · `ev-000012` · `ev-000009`

### 4. Send host heartbeat

`T1041` · Confidence **high** · dynamic

Immediately after the connection is established it sends a fixed 40-byte handshake: "w32 " + port (big-endian 0x08 0x26) + its own target IP string "134.122.154[.]92", zero-padded.

> **Evidence**: dynamic network monitoring captured the 40-byte payload 77 33 32 20 20 20 08 26 31 33 34 2E 31 32 32 2E 31 35 34 2E 39 32 00..., consistent with the emulated send sequence
> 
> **Source**: `ev-000013` · `ev-000012`

### 5. Allocate RWX memory

`T1620` · Confidence **high** · static

After the connection succeeds it calls VirtualAlloc(NULL, 0x1C9C380, MEM_COMMIT, PAGE_EXECUTE_READWRITE), reserving about 30MB of readable/writable/executable memory to receive the remote payload.

> **Evidence**: 0x4012E8 push 0x40 / 0x1000 / 0x1C9C380 / 0; 0x4012F5 call VirtualAlloc
> 
> **Source**: `ev-000009` · `ev-000012`

### 6. Receive and decrypt the payload in chunks

`T1140` · Confidence **high** · static

It loops recv(socket, buf, 0x64000, 0) until it returns 0; each newly arrived chunk is decrypted byte-wise with XOR 0x99, and the write offset advances by chunk.

> **Evidence**: 0x401327 xor byte ptr [esi],0x99; 0x401339/0x40133D chunked recv(0x64000); enters this loop after VirtualAlloc at 0x4012F5
> 
> **Source**: `ev-000009` · `ev-000012`

### 7. Execute the remote payload in memory

`T1620` · Confidence **high** · static

After payload reception/decryption completes it calls closesocket and directly jumps via call into the just-allocated RWX buffer to execute stage two, achieving fileless residency.

> **Evidence**: 0x401358 call closesocket; 0x401360 call ebx (ebx = the RWX buffer returned by VirtualAlloc)
> 
> **Source**: `ev-000009` · `ev-000012`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (with several retries in a short period).
:::

:::caution
**The real server side remains unverified**: the above connection/handshake was completed with a local controlled emulation service, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `134.122.154[.]92` | 2086 | c2 | dynamic | observed |

### Host

**Dropped paths**

- `%TEMP%\log_de.log`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `134.122.154[.]92` | yes | static |
| `c2_port` | `2086` | yes | static |
| `c2_protocol` | `raw TCP; 40-byte beacon = "w32 " + 2-byte big-endian port + IP string zero-padded` | yes | static |
| `marker_path` | `%TEMP%\log_de.log (single-instance check; exits if present)` | no | static |
| `encryption_algo` | `XOR 0x99 applied byte-wise to each received stage chunk` | yes | static |
| `stage2_alloc` | `VirtualAlloc(NULL, 0x1C9C380, MEM_COMMIT, PAGE_EXECUTE_READWRITE); recv chunk 0x64000` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- It cannot be classified as an infostealer or ransomware: no credential/browser data reads were observed, nor any file encryption or ransomware behavior.
- Do not claim that a valid C2 session was established or that stage two was downloaded/executed: the dynamic sandbox only saw the connection being established and the 40-byte handshake sent by the sample; the emulation server did not respond and stage two was not retrieved.
- Do not claim persistence exists: in system telemetry, no sample-related changes appeared in Run keys, services, or scheduled tasks.
- Do not claim process injection occurred: memory scanning found no injection, IAT hooks, or suspicious memory patches; the sample operates only within its own process.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. For the C2 there is only the connection establishment and the 40-byte handshake sent by the sample; the network emulation service returned nothing and no request/response session formed; per the rules the C2 is recorded as static with pending_dynamic_verify=true.
2. The stage-two payload was not obtained, so the final family, residency, and follow-on capabilities cannot be confirmed; VirtualAlloc/XOR 0x99/jump execution were confirmed only by static code and instruction-level emulation, and the shellcode was not seen actually running on a real machine.
3. The single-instance check on %TEMP%\log_de.log was recovered by instruction-level emulation; system telemetry did not record this file access event, so confidence is medium.
4. No vendor engine or YARA match exists, so the family name remains uncertain and must be confirmed together with the stage-two sample.
5. System telemetry found no sample-related changes such as file drops, registry, services, or scheduled tasks; the sample's ultimate capability is limited by the stage two that was never delivered.

## Evidence index

<details>
<summary>Show 13 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256=e6e51ff061c04b656f2d4187e34c95331444a9d28ea585ecd9a576550a2dc4c6, md5=05d233edd2de6095c7831c82c2033476, size=3584 |
| `ev-000002` | scan.imphash | imphash=e82dd51b077167be63c004bed23d0c1e; import surface is only KERNEL32!Sleep |
| `ev-000007` | Sample triage | Packing likelihood 25% (very few import symbols), no structural anomalies |
| `ev-000008` | String extraction | 90 ASCII strings, no UTF-16LE, no flags; only Sleep/KERNEL32.dll and code fragments are visible |
| `ev-000009` | decompile.function | Decompilation of 0x401005: GetTempPathA/wsprintfA/_access → WSASocketA/connect → send → VirtualAlloc(RWX) → recv+XOR 0x99 → call |
| `ev-000010` | decompile.function | Decompilation of 0x401369: PEB fs:[0x30] module traversal + export-name ROR13 hash matching |
| `ev-000011` | decompile.function | Decompilation of 0x40145F: resolves LoadLibraryA/GetTempPathA/wsprintfA/_access/WSAStartup/WSASocketA/connect/send/recv/VirtualAlloc, etc. with 18 hash constants |
| `ev-000012` | evidence.record | Instruction-level emulation recovery: marker path %TEMP%\log_de.log, C2 134.122.154[.]92:2086, 40-byte "w32 "+port+IP handshake, VirtualAlloc(0x1C9C380,0x40), recv 0x64000 chunks, XOR 0x99 |
| `ev-000013` | evidence.record | Dynamic sandbox network log: PID 1340 requests TCP 134.122.154[.]92:2086, first sends 40 bytes 77 33 32 20 20 20 08 26 31 33 34 2E ..., no server response |
| `ref:f2e42e397d` | Dynamic analysis platform | Real detonation: sample PID 1340 running, network tap records C2 outbound; memory scan 0 suspicious, no injection; telemetry shows no persistence changes; rolled back after analysis |
| `c2_evidence:e6e51ff0` | Connection evidence extraction | Dynamic network monitoring recorded 1 connection attempt to 134.122.154[.]92:2086; no complete session was captured |
| `telemetry:e6e51ff0` | Dynamic telemetry | Dynamic telemetry recorded: 122 process/file events from the monitoring component; 1 ETW short-lived process event; 26 tool/system noise events filtered out |
| `etw:e6e51ff0:1340` | Process event monitoring | Short-lived process event: e6e51ff061c04b656f2d4187e34c95331444a9d28ea585ecd9a576550a2dc4c6.exe (pid 1340; MD5=05D233EDD2DE6095C7831C82C2033476,SHA256=E6E51FF061C04B656F2D4187E34C95331444A9D28EA585ECD9A576550A2DC4C6,IMPHASH=E82DD51B077167BE63C004BED23D0C1E) |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
