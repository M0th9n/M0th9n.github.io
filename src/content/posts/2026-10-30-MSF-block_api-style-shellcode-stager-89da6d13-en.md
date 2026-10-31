---
title: "Malware Analysis: MSF block_api-style shellcode stager (PE · exe · 89da6d13)"
published: 2026-10-30
draft: false
description: "Malicious (low confidence): MSF block_api-style shellcode stager · downloader/loader · difficulty easy · dynamic sandbox + static decompilation"
tags: ["MSF block_api-style shellcode stager", "downloader", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-30-MSF-block_api-style-shellcode-stager-89da6d13"
---

> [!WARNING]
> **Verdict: malicious** · Family **MSF block_api-style shellcode stager** (uncertain) · Confidence **low**
> 
> Aliases: Metasploit-style reverse TCP stager, ROR13 hash-resolving shellcode loader
> 
> Static analysis recovered the complete download-and-execute stager: it walks the PEB and resolves APIs by ROR13 hash, connects to the hard-coded 176[.]97[.]117[.]157:80, sends a 40-byte registration packet, XORs each byte of the received stage-2 with 0x99, writes it into 30MB of RWX memory and calls it directly. In the real sandbox the process did initiate a TCP connection to 176[.]97[.]117[.]157:80 and then exited.

## Overview

| Item | Content |
|:--|:--|
| Family | **MSF block_api-style shellcode stager** · aliases Metasploit-style reverse TCP stager, ROR13 hash-resolving shellcode loader · _uncertain_ |
| Confidence | **low** |
| Behaviour class | downloader · loader |
| Difficulty | easy |
| First seen | 2026-10-28 19:32:19 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/89da6d134da1f71ca1ebba3eca2d429034a011fb74dcd45b287c06b71bb11b9f/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Hash-resolve imported APIs</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Load three DLLs dynamically</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Build temp-dir marker</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1083</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Connect to hard-coded C2</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Send w64 registration packet</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `89da6d134da1f71ca1ebba3eca2d429034a011fb74dcd45b287c06b71bb11b9f` |
| MD5 | _not recorded_ |
| Size | 3,584 bytes (3.5 KB) |
| Type | PE · `exe` |

## Behaviour analysis

**9** behaviours in total, each tied to evidence; **8** are statically recoverable and **1** was obtained dynamically.

### 1. Hash-resolve imported APIs

`T1027` · Confidence **high** · static

Does not rely on the import table: it walks the PEB's InLoadOrderModuleList over loaded modules, computes a ROR13 running hash separately for the module name (UTF-16LE with trailing NUL) and the export name (ASCII with trailing NUL), and returns the function address on a summed match.

> **Evidence**: FUN_14000145c (rva 0x145c): mov rax, gs:[0x60] → [rax+0x18] → [rdx+0x10]; loop ror edx,0xd / cmp byte,0x61 / add edx,-0x20
> 
> **Source**: `ref:11370cb44f` · `ref:8b3e2c9450` · `ref:3610939526`

### 2. Dynamically load three DLLs

`T1129` · Confidence **high** · static

Uses the resolved LoadLibraryA to load user32.dll, ws2_32.dll and msvcrt.dll in turn, preparing the modules needed for later network and string operations.

> **Evidence**: rva 0x104f/0x106d/0x108b call rbx (LoadLibraryA), stack constants 'user32.dll'/'ws2_32.dll'/'msvcrt.dll'; emulation also records three kernel32.LoadLibraryA calls
> 
> **Source**: `ref:ca5b5accd7` · `ref:11327c8a79` · `ref:087b9aee80`

### 3. Build temp-directory marker

`T1083` · Confidence **high** · static

Calls GetTempPathA to obtain %TEMP%, then sprintf("%s%s%s") builds %TEMP%\log_de.log and checks its existence with _access(path,0); it proceeds to network activity only if the file does not exist, otherwise it exits.

> **Evidence**: rva 0x1133 call GetTempPathA(0x80, buf); rva 0x117f sprintf; rva 0x1188 call _access; memory forensics shows C:\Users\analyst\AppData\Local\Temp\log_de.log
> 
> **Source**: `ref:ca5b5accd7` · `ref:3610939526` · `ref:d35ab028b8`

### 4. Connect to hard-coded C2

`T1095` · Confidence **high** · dynamic

After WSAStartup(0x202) it creates an AF_INET/SOCK_STREAM/TCP socket, resolves and connects to 176[.]97[.]117[.]157:80; on failure it retries indefinitely with Sleep(10000).

> **Evidence**: constants 0x006B8029=WSAStartup, 0xE0DF0FEA=WSASocketA, 0x6174A599=connect; sockaddr_in=0x50000002(AF_INET,port 80); rva 0x1321 call connect; rva 0x130c Sleep(0x2710) retry
> 
> **Source**: `ref:ca5b5accd7` · `ref:2cb8f5b269` · `ref:d35ab028b8` · `ref:3610939526`

### 5. Send w64 registration packet

`T1095` · Confidence **high** · static

After the connection is established it sends a fixed 40 bytes in sequence: 'w64 ' (6 bytes) + network-order port 0x0050 (2 bytes) + '176.97.117[.]157' (16 bytes) + 16 bytes of zero, acting as a registration/heartbeat header.

> **Evidence**: rva 0x1335/0x139e/0x13c4/0x13ea/0x1410/0x1436/0x1482/0x14a8/0x14ce consecutive call send; stack constants 'w64 ' and '176.'+'97.1'+'17.1'+'57'
> 
> **Source**: `ref:2cb8f5b269` · `ref:3610939526` · `ref:d35ab028b8`

### 6. Allocate 30MB of RWX memory

`T1620` · Confidence **high** · static

VirtualAlloc(0, 0x1C9C380, MEM_COMMIT|MEM_RESERVE(0x1000), PAGE_EXECUTE_READWRITE(0x40)) requests about 30MB of readable/writable/executable memory as the stage-2 landing area.

> **Evidence**: rva 0x14f9 call qword ptr [rbp-0x20]; immediates edx=0x1C9C380, r8d=0x1000, r9d=0x3c+4=0x40
> 
> **Source**: `ref:2cb8f5b269` · `ref:ca5b5accd7` · `ref:3610939526`

### 7. Receive stage-2 in a loop

`T1105` · Confidence **high** · static

Loops recv(sock, buf+offset, 0x64000, 0) into the RWX buffer until recv returns <=0 (server closes the connection), implementing a length-prefix-free streaming download.

> **Evidence**: rva 0x1438 call r15 (recv); r12d=0x64000; loop cmp eax,r14d / jge
> 
> **Source**: `ref:2cb8f5b269` · `ref:ca5b5accd7`

### 8. Decrypt with XOR 0x99

`T1140` · Confidence **high** · static

XORs each byte received by recv in place with 0x99 to obtain the cleartext stage-2; the key is a hard-coded single byte.

> **Evidence**: rva 0x141f: 80 34 39 99 → xor byte ptr [rcx+rdi], 0x99
> 
> **Source**: `ref:2cb8f5b269` · `ref:3610939526`

### 9. Execute stage-2 in memory

`T1620` · Confidence **high** · static

After closesocket it directly calls the first address of the decrypted buffer, executing the downloaded stage-2 inside its own process (no file dropped).

> **Evidence**: rva 0x1523 call closesocket; rva 0x152e call rdi (rdi = VirtualAlloc return address)
> 
> **Source**: `ref:2cb8f5b269` · `ref:ca5b5accd7`


## IOCs (defanged)

### Network

:::note
**Connection observed dynamically**: the sample actually initiated TCP connections to this target (retrying several times within a short period).
:::

:::caution
**The real server side remains unverified**: the connections above were completed against a local controlled emulation service; the real C2 responses and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `176[.]97[.]117[.]157` | 80 | c2 | dynamic | observed |

### Host

**Drop paths**

- `%TEMP%\log_de.log`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `176[.]97[.]117[.]157` | yes | dynamic |
| `c2_port` | `80` | yes | dynamic |
| `transport` | `raw TCP (WSASocketA/connect/send/recv)` | yes | static |
| `handshake_magic` | `w64` | yes | static |
| `handshake_layout` | `6-byte magic + 2-byte network-order port + 16-byte IP string + 16-byte reserved (0)` | yes | static |
| `stage_xor_key` | `0x99` | yes | static |
| `stage_recv_chunk` | `0x64000 (409600)` | no | static |
| `rwx_alloc_size` | `0x1C9C380 (30000000)` | no | static |
| `marker_path` | `%TEMP%\log_de.log` | no | static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- It should not be classified as ransomware/theft: the sample performs no file encryption, credential or browser-data reads, or persistence writes; it is only a stager that downloads and executes a later payload.
- The family should not be set directly to Meterpreter or a specific RAT: it can only be confirmed to use Metasploit block_api-style hash resolution and stager structure, and the 40-byte 'w64' packet and %TEMP%\log_de.log marker are not stock Meterpreter behaviour.
- Do not assert stage-2's function (remote control/theft/mining etc.): the sandbox did not obtain valid stage-2 content, so the final capability is unknown.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The stage-2 payload was not successfully retrieved (the dynamic sandbox provided no valid stage), so its final capability is unknown; the family is only a candidate based on code lineage and is marked uncertain.
2. The mapping of API names to constant strings was produced by a self-written script reproducing the sample's hash algorithm and cross-checked against runtime memory resolution, so it is inferential evidence.
3. %TEMP%\log_de.log is only checked for existence; no creation or writing was observed, so its single-instance or persistence semantics cannot be confirmed.
4. Dynamically only one TCP connection and send were observed; stage-2 download completion and successful execution were not observed.

## Evidence index

<details>
<summary>Expand 10 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1/imphash, file 3584 bytes |
| `ev-000007` | Sample triage | 3 sections, normal entropy, only 1 imported symbol, no structural anomalies, packing score 0.25 |
| `ev-000008` | String extraction | 70 ASCII strings, no cleartext C2/flag; DLL-name fragments visible |
| `ev-000009` | decompile.function | Main function FUN_140001008 pseudocode: load DLLs, GetTempPathA, _access, WSAStartup/WSASocketA/connect/send, VirtualAlloc, recv+XOR, execute |
| `ev-000010` | decompile.function | Resolver FUN_14000145c: PEB walk + ROR13 hash comparison against the export table |
| `ev-000011` | evidence.record | Script reproduced the hash algorithm, matching all 13 constants to API names; reconstructed 'w64 '/176.97.117[.]157:80/XOR 0x99/%TEMP%\log_de.log |
| `ref:2cb8f5b269` | disasm.function | rva 0x1301-0x152e call sites: connect, 9 sends, VirtualAlloc, recv, xor 0x99, closesocket, call stage |
| `ref:11327c8a79` | dyn.run | Emulation recorded 3 kernel32.LoadLibraryA calls (user32/ws2_32/msvcrt) |
| `ref:d35ab028b8` | Dynamic analysis platform | Real sandbox: process initiated TCP to 176.97.117[.]157:80; loaded user32/ws2_32/msvcrt; process then exited; memory forensics shows 'w64 ', '176.97.117[.]157', %TEMP%\log_de.log |
| `c2_evidence:89da6d13` | Connection evidence extraction | Dynamic network monitoring recorded 1 connection attempt to 176.97.117[.]157:80; the full session was not captured |

</details>

---

_The sample behind this report is not public; IOCs are defanged. For security research only._
