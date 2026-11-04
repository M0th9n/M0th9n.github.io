---
title: "Malware Analysis: Metasploit Meterpreter stager (x64 reverse_tcp) (PE · exe · be9c4db2)"
published: 2026-11-03
draft: false
description: "Malicious (medium confidence): Metasploit Meterpreter stager (x64 reverse_tcp) · loader/downloader · difficulty easy · dynamic sandbox + static decompilation"
tags: ["Metasploit Meterpreter", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-03-Metasploit-Meterpreter-stager-x64-reverse_tcp-be9c4db2"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Metasploit Meterpreter stager (x64 reverse_tcp)** (uncertain) · Confidence **medium**
> 
> Aliases: Meterpreter, MSF block_api stager, reverse_tcp stager
> 
> The sample really started in the isolated Windows sandbox (PID 116) and actively initiated a TCP callback to 103.30.76[.]206:443 after launch; the code itself implements hash-based dynamic API resolution, socket callback, a large RWX allocation, chunked receive with XOR 0x99 decryption, and direct execution, making it a typical memory-loading remote-control stager.

## Overview

| Item | Content |
|:--|:--|
| Family | **Metasploit Meterpreter stager (x64 reverse_tcp)** · aliases Meterpreter, MSF block_api stager, reverse_tcp stager · _uncertain_ |
| Confidence | **medium** |
| Behavior class | loader · downloader |
| Difficulty | easy |
| First seen | 2026-11-02 04:28:31 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Hash-walk API resolution</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Load network libraries</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Connect to C2 port 443</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Send w64 callback handshake</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Allocate 30MB executable memory</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `be9c4db2624c8b747073e80245eb0611fd82b4c92c937f1ac1d7646a8bf36583` |
| MD5 | _not recorded_ |
| Size | 3,584 bytes (3.5 KB) |
| Type | PE · `exe` |

## Behavior analysis

**7** behaviors in total, each backed by evidence; **6** statically recoverable, **1** obtained through dynamic analysis.

### 1. Hash-walk API resolution

`T1027` · Confidence **high** · static

It reads the PEB via gs:[0x60], walks InLoadOrderModuleList and the export tables, and matches APIs by a ror13 + uppercase-character additive hash; the static import table keeps only Sleep to reduce visibility.

> **Evidence**: 0x14000145C mov rax,gs:[0x60]; 0x1400014D1 ror edx,0xD; 0x14000151A cmp eax(hash_func+hash_dll),ebp
> 
> **Source**: `ref:a5c96862db` · `ref:849fd6ce07`

### 2. Load network libraries

`T1129` · Confidence **high** · static

It calls the dynamically resolved LoadLibraryA to load user32.dll, ws2_32.dll, and msvcrt.dll in sequence.

> **Evidence**: 0x140001024 resolves hash 0x0726774C(LoadLibraryA); 0x140001030/0x140001054/0x140001078 write the dll names and call rbx
> 
> **Source**: `ref:b334c5b268` · `ref:bead9d643b`

### 3. Connect to C2 port 443

`T1095` · Confidence **high** · dynamic

It builds sockaddr_in (AF_INET, port bytes 0x01BB, target 103.30.76[.]206) and calls connect; on failure it loops with Sleep(10000). Inside the sandbox this process was really observed initiating a TCP connection to 103.30.76[.]206:443.

> **Evidence**: 0x1400012DC mov dword [rbp-0x40],0xBB010002; 0x14000130C Sleep(10000); 0x140001321 call connect; sandbox event pid 116 requested TCP 103.30.76[.]206:443
> 
> **Source**: `ref:bead9d643b` · `ref:64b18ae47f` · `ref:2a5f67c413`

### 4. Send w64 callback handshake

`T1571` · Confidence **medium** · static

After a successful connection it first sends the 6 bytes "w64 ", then 2 bytes of network-order port 0x01BB(443), 4 bytes of IP fragments ("103."/"30.7"/"6.20"/"6"), and four 4-byte reserved fields.

> **Evidence**: 0x140001327 lea r8d,[rax+6]; 0x140001332 lea rdx,[rbp-0x80]("w64 "); 0x140001337 call send; then consecutive sends of 6/2/4/4/4/4/4/4 bytes
> 
> **Source**: `ref:bead9d643b` · `ev-000009`

### 5. Allocate 30MB executable memory

`T1620` · Confidence **high** · static

It calls VirtualAlloc(0, 30000000, 0x1000, 0x40) to reserve about 28.6MB of PAGE_EXECUTE_READWRITE buffer for hosting the second stage.

> **Evidence**: 0x1400013DB mov edx,0x01C9C380; 0x1400013ED call [rbp-0x20](VirtualAlloc), r8=0x1000, r9=0x40
> 
> **Source**: `ref:bead9d643b` · `ev-000009`

### 6. Receive and XOR-decrypt payload

`T1140` · Confidence **high** · static

It loops recv(sock, buf, 0x64000), XORs each byte with 0x99 into the RWX buffer while accumulating the length, until recv no longer returns a positive value.

> **Evidence**: 0x140001438 call recv(0x64000); 0x14000141F xor byte ptr [rcx+rdi],0x99; 0x140001441 add esi,eax
> 
> **Source**: `ref:bead9d643b` · `ev-000009`

### 7. Close socket and execute payload

`T1620` · Confidence **high** · static

After receiving, it closes the socket and directly calls into the decrypted RWX region to execute the second stage, never touching disk.

> **Evidence**: 0x140001443 call [rbp-0x18](closesocket); 0x140001446 call rdi(RWX base)
> 
> **Source**: `ref:bead9d643b` · `ev-000009`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the address above comes from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `103.30.76[.]206:443` | 443 | c2 | static | ⏳ not observed |

### Host

- **No host IOC recovered.**

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `103.30.76[.]206` | yes | static |
| `c2_port` | `443` | yes | static |
| `protocol` | `raw TCP; first a 6-byte 'w64 ' header, then 2 bytes of network-order port and 4 bytes of IP fragments plus four 4-byte reserved fields` | yes | static |
| `encryption_algo` | `XOR 0x99 (byte-wise XOR applied to the received second stage)` | yes | static |
| `stage_alloc_size` | `30000000 bytes RWX (VirtualAlloc MEM_COMMIT/PAGE_EXECUTE_READWRITE)` | no | static |

## Must not claim

:::important
The following conclusions are **prone to misjudgment**; take care when citing this report.

- Do not assert from the 30MB RWX memory alone that the sample has injected into other processes: no cross-process writes, thread hijacking, or hollowing were observed.
- No second-stage payload was received, so its final functionality cannot be asserted to be information theft, ransomware, mining, or lateral movement.
- No services/scheduled tasks/registry Run keys or dropped files were observed, so persistence capability cannot be determined.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The second-stage payload was not obtained (C2 returned no data), so its final capabilities, full configuration, and family details cannot be confirmed.
2. The callback attempt was recorded by network monitoring (requested TCP), but no session/response content was obtained; the raw TCP payload after the handshake was not parsed at the application layer, so the payload content is unknown.
3. The exact semantics of the msvcrt helper calls (building the "log_de.log" string, initializing the 0x80 buffer) were not finally confirmed and are not used as conclusions.
4. Emulation of the sample did not return a result within the time limit; the final conclusions rely only on real sandbox observation and static evidence.
5. No persistence, file drops, or process injection behaviors were observed; related capabilities are not inferred.

## Evidence index

<details>
<summary>Expand 10 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hashing and fingerprints | sha256/md5/sha1 and file size |
| `ref:6349dd7802` | sample triage | 3 sections, normal entropy, only 1 Sleep import, no structural anomalies |
| `ref:849fd6ce07` | import table parsing | only KERNEL32.dll!Sleep, imphash e82dd51b077167be63c004bed23d0c1e |
| `ev-000008` | string extraction | no plaintext C2/URL; only dll name fragments and format-string fragments |
| `ref:bead9d643b` | disasm.function | full entry disassembly: hash resolution, WSA/connect, RWX allocation, recv+XOR 0x99, execution |
| `ref:b334c5b268` | decompile.function | entry C pseudocode: load 3 DLLs, build C2, download and execute |
| `ref:a5c96862db` | disasm.function | 0x145C resolver: PEB walk + ror13 hash comparison |
| `ref:64b18ae47f` | dynamic analysis platform | real sandbox detonation: PID 116 process created, memory dump and network observation produced, rolled back afterwards |
| `ref:2a5f67c413` | bash | network monitoring log: be9c…exe (116) requested TCP 103.30.76[.]206:443 |
| `ev-000009` | decompile.ghidra | Ghidra pseudocode and string constants |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
