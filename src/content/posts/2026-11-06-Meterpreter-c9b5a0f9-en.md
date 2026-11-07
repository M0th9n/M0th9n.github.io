---
title: "Malware Analysis: Meterpreter (PE · exe · c9b5a0f9)"
published: 2026-11-06
draft: false
description: "Malicious (high confidence): Meterpreter · loader/rat · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Meterpreter", "loader", "rat", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-06-Meterpreter-c9b5a0f9"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Meterpreter** · Confidence **high**
> 
> Aliases: Metasploit Meterpreter, msfvenom meterpreter/reverse_http (x64), Meterpreter reverse_http stager
> 
> Static: the .data section embeds an 893-byte payload encrypted with a 4-byte repeating XOR; once decrypted it is a Metasploit x64 Meterpreter reverse_http stager (PEB traversal + ROR13 resolution of wininet, hardcoded 192.168.28[.]128:6666, URI /qRh2, spoofed MSIE 10.0 UA). Dynamic: inside the sandbox the sample process creates the named pipe \\.\pipe\MSSE-2265-server, the decrypted plaintext stager appears in memory, and it sends GET /qRh2 to 192.168.28[.]128:6666 (the UA matches the embedded string), while the process stays resident and sleeping.

## Overview

| Item | Content |
|:--|:--|
| Family | **Meterpreter** · aliases Metasploit Meterpreter, msfvenom meterpreter/reverse_http (x64), Meterpreter reverse_http stager |
| Confidence | **high** |
| Behavior class | loader · rat |
| Difficulty | medium |
| First seen | 2026-11-05 15:19:41 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/c9b5a0f9a56bf6b79b11550ddc560f1c0b863e86653afed1d11746e27e4fc910/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Self-pipe staging</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">4-byte XOR decrypt</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Allocate and execute</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Resolve APIs via PEB</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Spoofed-UA C2 callback</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic observed</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `c9b5a0f9a56bf6b79b11550ddc560f1c0b863e86653afed1d11746e27e4fc910` |
| MD5 | _not recorded_ |
| Size | 19,456 bytes (19.0 KB) |
| Type | PE · `exe` |

## Behavior analysis

**7** behaviors in total, each backed by evidence; **5** are statically recoverable and **2** were obtained through dynamic analysis.

### 1. Self-pipe staging

`T1105` · Confidence **high** · static

The main thread builds \\.\pipe\MSSE-<n>-server from GetTickCount%0x26aa, starts a thread that acts as the pipe server and writes the embedded encrypted blob from .data, while the same process acts as the client and reads it back from the same pipe, completing an in-memory staging loop.

> **Evidence**: 0x4017F8 sprintf("%c%c%c%c%c%c%c%c%cMSSE-%d-server") + CreateThread(0x4016E6); 0x401630 CreateNamedPipeA/ConnectNamedPipe/WriteFile; 0x401704 CreateFileA/ReadFile
> 
> **Source**: `ref:401346c7f0` · `ref:febc5328cc` · `ref:0d5b914056` · `ref:3dd292ebf8`

### 2. 4-byte XOR decryption

`T1140` · Confidence **high** · static

The 893-byte blob read back is XORed byte by byte with the 4-byte repeating key 8B F5 0E 80, recovering the plaintext x64 shellcode.

> **Evidence**: rep logic inside 0x401595: dst[i] = src[i] ^ key[i & 3]; structure .data+0x0=0x2630, +0x4=0x37D(893), +0x8 key, +0x14 ciphertext
> 
> **Source**: `ref:62bc6e7ffe` · `ref:6d4917704d` · `ref:50f5888ce8`

### 3. Allocate and execute in memory

`T1620` · Confidence **high** · static

VirtualAlloc(PAGE_READWRITE) allocates memory the size of the payload, the decrypted result is copied in, VirtualProtect changes it to PAGE_EXECUTE_READ (0x20), and CreateThread executes it directly, never touching disk.

> **Evidence**: 0x401595: VirtualAlloc(...,0x3000,4) → memcpy loop → VirtualProtect(...,0x20) → CreateThread(0x401560); the plaintext stage header fc4883e4f0e8c8000000 appears in the runtime memory dump
> 
> **Source**: `ref:62bc6e7ffe` · `ref:50f5888ce8`

### 4. Resolve APIs via PEB

`T1027` · Confidence **high** · static

The shellcode walks gs:[0x60] through PEB→Ldr→InLoadOrderModuleList to locate modules, matches ROR13 hashes and resolves LoadLibraryA/InternetOpenA and others GetProcAddress-style; the network APIs have no static imports.

> **Evidence**: stage offset 0x00-0xC4: mov rdx,gs:[rdx+0x60] traverses Ldr; hashes 0x0726774C LoadLibraryA, 0xA779563A InternetOpenA
> 
> **Source**: `ref:b802be11db` · `ref:6d4917704d`

### 5. Spoofed-UA C2 callback

`T1071.001` · Confidence **high** · dynamic

Using Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0) as the UA, it sends a GET request to hxxp://192[.]168[.]28[.]128:6666/qRh2 with Connection: Keep-Alive and Cache-Control: no-cache.

> **Evidence**: dynamic network log: sample PID 6224 requested TCP 192.168.28[.]128:6666, HTTPListener recorded GET /qRh2 HTTP/1.1 + Host/UA; static InternetConnectA port argument r8d=0x1A0A (6666)
> 
> **Source**: `ref:c4382b53bf` · `ref:b092ff7d85` · `ref:6d4917704d`

### 6. Fetch stage two over HTTP

`T1105` · Confidence **medium** · dynamic

The stager calls InternetOpenA/InternetConnectA/HttpOpenRequestA/HttpSendRequestA, then loops InternetReadFile to read response chunks, writes them into VirtualAlloc(0x400000) memory and jumps to execute stage two.

> **Evidence**: stage offset 0xD0-0x30: after resolving wininet, HttpSendRequestA→InternetReadFile loop (0x56A2B5F0)+VirtualAlloc(0x40/0x1000); only one request was made and no subsequent metsrv behavior was seen
> 
> **Source**: `ref:b092ff7d85` · `ref:b802be11db` · `ref:c4382b53bf`

### 7. Sleep loop keeps process alive

`T1497.003` · Confidence **high** · static

After initialization and payload execution the main thread enters an infinite Sleep(10000) loop and the process stays resident; before the pipe read there is also a Sleep(0x400) retry wait.

> **Evidence**: 0x403040: FUN_00401950; FUN_004017F8; do { Sleep(10000); } while(true); 0x4017A6 Sleep(0x400) retry
> 
> **Source**: `ref:d85c8f3d31` · `ref:bfb9dc3277`


## IOC (defanged)

### Network

:::note
**A connection was observed dynamically**: the sample actually initiated TCP connections to this target (retried several times within a short period).
:::

:::caution
**The real server side is still unverified**: the connection/handshake above was completed with a local controlled emulation service, so the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://192[.]168[.]28[.]128:6666/qRh2` | 6666 | c2 | static | observed |

### Host

- **No host IOCs were recovered.**

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `192[.]168[.]28[.]128` | yes | static |
| `c2_port` | `6666` | yes | static |
| `c2_uri` | `/qRh2` | yes | static |
| `user_agent` | `Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)` | yes | static |
| `staging_pipe` | `\\.\pipe\MSSE-<GetTickCount%0x26aa>-server` | yes | static |
| `encryption_algo` | `4-byte repeating XOR, key 8B F5 0E 80` | yes | static |
| `embedded_stage_size` | `893` | yes | static |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not judge it as a Cobalt Strike SMB Beacon merely from the \\.\pipe\MSSE-%d-server pipe naming: the embedded payload and runtime behavior are both those of a Metasploit Meterpreter x64 reverse_http stager.
- No file drop, registry write, service installation or scheduled task was observed, so do not report dropper persistence behavior.
- No credential theft, file encryption or bulk data exfiltration was observed, so do not classify it as stealer/ransomware/wiper; only a single HTTP GET attempt to fetch stage two was seen.
- The C2 address 192[.]168[.]28[.]128 is a private-range address intercepted by the sandbox fake network; it cannot be used to infer real external infrastructure or real attacker attribution.
- The outer loader has no signature or version resource and is MinGW-compiled, and has not been matched precisely to a known family; the family verdict applies only to the decrypted and executed Meterpreter payload.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | yes (stage2 `deacb44440abccffbd48e71e18bc9b5a07a8664663bceb3c5277fc8317031908`) |

**Limitations and pending verification**

1. Stage two (metsrv) was not confirmed as delivered/executed in this dynamic observation: the fake-network response to GET /qRh2 does not constitute a valid stage, and the process stays resident with no subsequent command, file or network behavior, so the RAT's full command capability was not exercised.
2. The URI and port are directly readable from the decrypted payload (/qRh2, InternetConnectA port 0x1A0A=6666) and match the dynamic request; the server-side interaction after the request cannot be reproduced without a real C2 environment.
3. The outer loader is MinGW-compiled with no signature or version information and was not matched precisely to a known family; its pipe-staging implementation may be custom or repackaged.
4. The sample runs silently under the WINDOWS_GUI subsystem with no console output, so no additional clues could be obtained from a user-visible interface.
5. The dynamic conclusions come from a single sandbox detonation and memory forensics; no anti-VM/anti-debug behavior was observed, but no long-dwell observation was performed.

## Evidence index

<details>
<summary>Expand 19 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:4194066e64` | sample triage | triage: sha256/imphash, 9 sections, all entropies <6, packing score 0 |
| `ref:80a60e9277` | PE structure parsing | x64 GUI PE, timestamp 0, entry RVA 0x14C0, import table RVA 0x9000 |
| `ref:c642a03844` | import table parsing | only KERNEL32/msvcrt; includes CreateNamedPipeA/ConnectNamedPipe/CreateFileA/ReadFile/WriteFile/VirtualAlloc/VirtualProtect/CreateThread |
| `ref:03b2457dea` | string extraction | strings '%c%c%c%c%c%c%c%c%cMSSE-%d-server', Mingw-w64 runtime, GCC 9.x |
| `ref:401346c7f0` | decompile.function | 0x4017F8: builds \\.\pipe\MSSE-<tick%0x26aa>-server, CreateThread(0x4016E6) and 0x4017A6 |
| `ref:febc5328cc` | decompile.function | 0x401630: CreateNamedPipeA/ConnectNamedPipe/WriteFile pipe server |
| `ref:0d5b914056` | decompile.function | 0x401704: CreateFileA(pipe)/ReadFile reads the payload back |
| `ref:62bc6e7ffe` | decompile.function | 0x401595: 4-byte repeating XOR decryption + VirtualAlloc + VirtualProtect(0x20) + CreateThread |
| `ref:bfb9dc3277` | decompile.function | 0x4017A6: Sleep(0x400) retry read, then calls 0x401595 to execute |
| `ref:d85c8f3d31` | decompile.function | 0x403040: after initialization do { Sleep(10000); } while(true) resident |
| `ref:b802be11db` | disasm.bytes | decrypted stage 0x00-0xC4: PEB/Ldr traversal + ROR13 hash resolution (block_api) |
| `ref:b092ff7d85` | disasm.bytes | decrypted stage 0x100-0x190: InternetOpenA/InternetConnectA (port 0x1A0A)/HttpOpenRequestA/HttpSendRequestA |
| `ref:6d4917704d` | evidence.record | self-written script: decrypted the .data 893B payload, obtained host 192.168.28[.]128, port 6666, URI /qRh2, UA, sha256=deacb444... |
| `ref:97eeeb998c` | dynamic analysis platform | real dynamic detonation: process PID 6224 was born and stayed resident; timeline/memory dump/isolated network log packaged and rolled back |
| `ref:c4382b53bf` | sandbox(network log) | PID 6224 requested TCP 192.168.28[.]128:6666; HTTP GET /qRh2 + spoofed UA + Host header |
| `ref:50f5888ce8` | sandbox(memory dump) | process memory contains plaintext stager header fc4883e4f0e8c8000000 and 'GET /qRh2 HTTP/1.1', UA string |
| `ref:3dd292ebf8` | sandbox(memory dump) | process memory contains pipe instance '\\.\pipe\MSSE-2265-server' and the decrypted stage sha256 |
| `ref:753a2e32b7` | sandbox(monitoring component target list) | PID 6224 existed and later GONE; no hollows hit, no new child process |
| `c2_evidence:c9b5a0f9` | connection evidence extraction | dynamic network monitoring recorded 3 connection attempts to 192.168.28[.]128:6666, 192[.]168[.]28[.]128:80 and maps[.]windows[.]com:443; no complete session captured |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
