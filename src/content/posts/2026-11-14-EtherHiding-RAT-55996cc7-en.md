---
title: "Malware Analysis: EtherHiding RAT (PE · exe · 55996cc7)"
published: 2026-11-14
draft: false
description: "Malicious (medium confidence): EtherHiding RAT · dropper/backdoor · difficulty hard · dynamic sandbox + static decompilation"
tags: ["EtherHiding", "dropper", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-14-EtherHiding-RAT-55996cc7"
---

> [!WARNING]
> **Verdict: Malicious** · Family **EtherHiding RAT** (uncertain) · Confidence **Medium**
> 
> Aliases: EtherRAT-like, EtherHiding loader/backdoor
> 
> Real execution in the dynamic sandbox: the sample dropped and launched a disguised copy at %LOCALAPPDATA%\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe, then wrote HKCU\Environment\UserInitMprLogonScript for logon autostart; the dropped copy periodically requested api.telegra[.]ph and three Polygon JSON-RPC nodes, and attempted to upgrade to a WebSocket control channel at wss://lookup[.]wavegrid79[.]lol/kmtkcw. File delivery, persistence and C2 requests were independently observed; it is assessed as a malicious backdoor.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **EtherHiding RAT** · aliases EtherRAT-like, EtherHiding loader/backdoor · _uncertain_ |
| Confidence | **Medium** |
| Behavior class | dropper · backdoor |
| Difficulty | hard |
| First seen | 2026-11-11 02:32:33 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/55996cc76b81dccfbe6b7d3720f25ab9569e5dbe7c54cd2db18cbeca71376e40/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Drop masqueraded system copy</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Logon script autostart</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1037.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Decrypt high-entropy section</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Resolve smart-contract C2</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Read Telegram dead drop</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `55996cc76b81dccfbe6b7d3720f25ab9569e5dbe7c54cd2db18cbeca71376e40` |
| MD5 | _not recorded_ |
| Size | 2,908,160 bytes (2.8 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**9** behaviors in total, each backed by evidence; **6** are static and **3** obtained through dynamic analysis.

### 1. Drop masqueraded system copy

`T1036.005` · Confidence **High** · Dynamic

Writes the embedded payload to %LOCALAPPDATA%\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe and launches that copy; system events record both the file creation (PID 3176) and the new process creation (PID 4892).

> **Evidence**: 01:04:59 file creation C:\Users\analyst\AppData\Local\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe (Image=PID 3176) + process start from the same path 0.15s later (PID 4892)
> 
> **Source**: `ref:7207a2fe5c` · `ref:c46b3223c6`

### 2. Logon script autostart

`T1037.001` · Confidence **High** · Dynamic

Sets HKCU\Environment\UserInitMprLogonScript to the disguised copy above so the malware runs automatically when the user logs on.

> **Evidence**: Registry value write: HKU\S-1-5-21-...\Environment\UserInitMprLogonScript = C:\Users\analyst\AppData\Local\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe (PID 3176)
> 
> **Source**: `ref:7207a2fe5c` · `ref:c46b3223c6`

### 3. Decrypt high-entropy section

`T1027.002` · Confidence **High** · Static

The .text/.rdata/.data/.4E] sections of the PE all have SizeOfRawData 0 on disk; the real code and configuration live in the .l3c section with entropy 7.95, and the post-run memory image contains executable code and plaintext configuration, indicating a self-decryption/unpacking stage.

> **Evidence**: .l3c RVA 0x1C0000 size 0x2C59B0 entropy 7.952; EP RVA 0x3BF785 inside .l3c; memory image has 2 unpacked sections
> 
> **Source**: `ref:36e325e09e` · `ref:849fed78dc` · `ref:f794b7c06a`

### 4. Resolve smart-contract C2

`T1102` · Confidence **High** · Static

The dropped copy POSTs eth_call to three Polygon JSON-RPC nodes rpc[.]hostdefi[.]com, matic[.]rpc[.]sentio[.]xyz and polygon[.]gateway[.]tenderly[.]co, contract 0xC95DDD2C9a7F7fe53Ffd226E02421d020C880Bd7, method 0xb6154dab, and parses controller information from the on-chain return value.

> **Evidence**: Network monitoring log: POST / and /api/rpc/polygon, body is eth_call, to=0xC95DDD2C..., data=0xb6154dab
> 
> **Source**: `ref:e370c3d67d` · `ref:11618b7cef` · `ref:1eb7fa2bea`

### 5. Read Telegram dead drop

`T1102.001` · Confidence **High** · Static

Requests /getPage/Cedar-meadow-valley-10-30?return_content=false from api.telegra[.]ph and extracts the description field from the returned page as fallback configuration.

> **Evidence**: Network monitoring log GET /getPage/Cedar-meadow-valley-10-30?return_content=false; memory image .data RVA 0x10B68/0x10B88/0x10BB8 holds the page identifier and parsing string
> 
> **Source**: `ref:e370c3d67d` · `ref:1eb7fa2bea`

### 6. Upgrade WebSocket channel

`T1071.001` · Confidence **High** · Static

Uses WinHTTP to request hxxps://lookup[.]wavegrid79[.]lol/kmtkcw and initiates a WebSocket Upgrade (Connection: Upgrade, Sec-WebSocket-Key) to establish the command-and-control channel.

> **Evidence**: Imports WinHttpWebSocketCompleteUpgrade @IAT 0x11360; network log repeatedly shows GET /kmtkcw HTTP/1.1 + Upgrade: websocket, Host: lookup[.]wavegrid79[.]lol
> 
> **Source**: `ref:a222c2558e` · `ref:e370c3d67d` · `ref:4a46c2781c`

### 7. Collect host fingerprint

`T1082` · Confidence **Medium** · Static

Calls GetComputerNameW, GetUserNameW, GlobalMemoryStatusEx, GetUserDefaultUILanguage and GetSystemDefaultUILanguage to collect hostname, username, memory and system language fingerprints.

> **Evidence**: Runtime IAT: kernel32.GetComputerNameW @0x113E0, GetUserNameW @0x113F8, GetUserDefaultUILanguage @0x11B18, GetSystemDefaultUILanguage @0x11B28, GlobalMemoryStatusEx @0x113D0
> 
> **Source**: `ref:a222c2558e` · `ref:1eb7fa2bea`

### 8. Resolve APIs dynamically

`T1027.007` · Confidence **High** · Dynamic

The IAT rebuilt in memory contains GetModuleHandleA, LoadLibraryA and GetProcAddress; with only 5 decoy imports on disk, it loads network, registry and other APIs on demand at runtime.

> **Evidence**: Rebuilt IAT 0x1BF058: kernel32.GetModuleHandleA / LoadLibraryA / GetProcAddress / HeapAlloc / HeapFree / FatalExit
> 
> **Source**: `ref:826a0cfd9f`

### 9. Identify VirtualBox environment

`T1497.001` · Confidence **Medium** · Static

Around RVA 0x42FA00 it compares strings such as "VirtualBox"/"Virtual" byte by byte, which is virtual-machine environment probing.

> **Evidence**: RVA 0x42FA00 byte sequence 41 80 7C 08 02 72 ... 41 80 39 56 ... (immediates spell r/t/u/a/l/B/o/x, V/i/r/t/u/a/l)
> 
> **Source**: `ref:b3e08951b7`


## IOC (Defanged)

### Network

:::note
**Connections were dynamically observed**: the sample actually initiated TCP connections to these targets (retried several times within a short period).
:::

:::caution
**The real server side remains unverified**: the above connections/handshakes were completed with a local controlled emulation service; the real C2 responses and payloads are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://lookup[.]wavegrid79[.]lol/kmtkcw` | 443 | c2 | Dynamic | Observed |
| other | `hxxps://rpc[.]hostdefi[.]com/api/rpc/polygon` | 443 | c2 | Dynamic | Observed |
| other | `hxxps://matic[.]rpc[.]sentio[.]xyz` | 443 | c2 | Dynamic | Observed |
| other | `hxxps://polygon[.]gateway[.]tenderly[.]co` | 443 | c2 | Dynamic | Observed |
| other | `Polygon contract 0xC95DDD2C9a7F7fe53Ffd226E02421d020C880Bd7 / selector 0xb6154dab` | - | c2 | Static | ⏳ Not observed |
| http | `hxxps://api[.]telegra[.]ph/getPage/Cedar-meadow-valley-10-30?return_content=false` | 443 | download | Dynamic | Observed |

### Host

**Mutex**

- `Global\0179BD0D60273EEF`

**Drop paths**

- `%LOCALAPPDATA%\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe`

**Registry**

- `HKCU\Environment\UserInitMprLogonScript`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `lookup[.]wavegrid79[.]lol` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `c2_uri` | `/kmtkcw` | Yes | Static |
| `c2_protocol` | `WebSocket over HTTPS (WinHTTP Upgrade)` | Yes | Static |
| `dead_drop_page` | `api.telegra[.]ph/getPage/Cedar-meadow-valley-10-30?return_content=false` | No | Static |
| `blockchain_contract` | `0xC95DDD2C9a7F7fe53Ffd226E02421d020C880Bd7` | Yes | Static |
| `blockchain_selector` | `0xb6154dab` | Yes | Static |
| `blockchain_rpc` | `rpc[.]hostdefi[.]com/api/rpc/polygon; matic[.]rpc[.]sentio[.]xyz; polygon[.]gateway[.]tenderly[.]co` | Yes | Static |
| `mutex` | `Global\0179BD0D60273EEF` | Yes | Static |
| `install_path` | `%LOCALAPPDATA%\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe` | Yes | Dynamic |
| `persistence` | `HKCU\Environment\UserInitMprLogonScript = %LOCALAPPDATA%\Realtek\System\Cache\35307B05\YourPhoneBackgroundBroker.exe` | Yes | Dynamic |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0[.]0 Safari/537.36` | No | Static |
| `embedded_hex_blob_1` | `abde1360384f9ce569f7982ad5832487cdcca591143da43c8dd23cd980b38771f0aef182ce905c81a812417b5662c096` | No | Static |
| `embedded_hex_blob_2` | `30ea7f6e2d6af0d8ca2fe3e73b551f770e4812bdf80314c5919fd02c16aa1034` | No | Static |

## What Not to Assume

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing the report.

- Do not assess it as ransomware: no file encryption, shadow-copy deletion or ransom note was observed (ransom note count was 0 during the dynamic run).
- Do not claim the second stage was downloaded from the internet: the second stage was decrypted from embedded encrypted data and written to disk for execution; no HTTP file download was observed.
- Do not claim command interaction with the C2 or exfiltration of host data: only DNS queries, HTTP requests and WebSocket Upgrade attempts were observed, with no complete application-layer response/session.
- Do not claim credential, wallet or clipboard theft capability: no related API calls or browser/wallet directory access were observed.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `2328a19d75e98020ed4eb47018e2846af1344c16c4dd1c71cbb3379980553a26`) |

**Limitations and items to verify**

1. On the C2 side only DNS queries, HTTP eth_call requests and WebSocket Upgrade requests were observed; no application-layer response or command was obtained, so all C2 entries are recorded as static + pending_dynamic_verify.
2. Mutex creation/check events were not directly observed; the mutex comes from strings in the runtime image plus the CreateMutexW import, with medium confidence.
3. Static anti-debug scanning found rdtsc / int 2Dh / cpuid hits in the high-entropy section, but random-byte false positives could not be excluded, so these were not accepted as conclusions.
4. The first ~2.3MB of .l3c remains high-entropy (~7.99) in memory, possibly an encrypted payload/plugin not yet decrypted; this report does not cover its function.
5. For the second stage only the realigned memory image was obtained, not the original on-disk file; the hash in recovered refers to the memory image, not a disk file.
6. The sandbox performed virtual-machine environment masquerading, so the sample's VirtualBox check did not trigger; that check is only a static disassembly observation.
7. Because there was no complete C2 session, specific backdoor functions such as remote shell, file theft and keylogging were not observed; the behavior classification is based on the architecture of persistence + a WebSocket control channel.

## Evidence Index

<details>
<summary>Show 15 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:a8b8bac13f` | Static triage | Hash/imphash/section entropy/import surface: .l3c entropy 7.952, only 5 imported symbols, packing score 0.25 |
| `ref:36e325e09e` | PE structure parsing | AMD64 GUI, 6 sections, EP RVA 0x3BF785 in .l3c; four sections have SizeOfRawData 0, .l3c raw data 0x2C5A00 @0x600 |
| `ref:7f6cd44d95` | Import table parsing | On-disk imports only lstrlenA/DialogBoxParamW/ExtractIconExW/GetROP2/CoCreateGuid |
| `ref:849fed78dc` | Packer detection | Assessed packed=true, strategy emulate_to_oep; signals are .l3c high entropy and very few imports |
| `ref:826a0cfd9f` | Memory forensics | PE image rebuilt IAT: GetModuleHandleA/LoadLibraryA/GetProcAddress/HeapAlloc/HeapFree/FatalExit @0x1BF058 |
| `ref:1eb7fa2bea` | Memory forensics | Second-stage .data plaintext configuration: mutex Global\0179BD0D60273EEF, Realtek cache path, UserInitMprLogonScript, RPC/contract/page/UA |
| `ref:4a46c2781c` | Memory forensics | Full URL hxxps://lookup[.]wavegrid79[.]lol/kmtkcw and session identifier in the runtime heap |
| `ref:a222c2558e` | Memory forensics | Second-stage imports: ws2_32.WSAStartup, winhttp.* (including WinHttpWebSocketCompleteUpgrade), CreateMutexW, RegOpenKeyExW/RegQueryValueExW |
| `ref:7207a2fe5c` | System event telemetry | File creation (PID 3176) → registry UserInitMprLogonScript write → process start from same path (PID 4892) → repeated DNS queries |
| `ref:e370c3d67d` | Network monitoring | eth_call(0xb6154dab → 0xC95DDD2C...), telegra[.]ph page request, WebSocket Upgrade GET /kmtkcw |
| `ref:b3e08951b7` | Disassembly | Byte-by-byte comparison of VirtualBox/Virtual strings at RVA 0x42FA00 |
| `ref:c183b5f9fd` | Dynamic sandbox | Revert → detonate → poll; captured PID 3176 and dropped copy PID 4892, memory dump and timeline collected |
| `c2_evidence:55996cc7` | Connection evidence extraction | Dynamic network monitoring recorded 41 connection attempts to api[.]telegra[.]ph:443, lookup[.]wavegrid79[.]lol:443, matic[.]rpc[.]sentio[.]xyz:443, polygon[.]gateway[.]tenderly[.]co:443, rpc[.]hostdefi[.]com:443; no complete session captured |
| `telemetry:55996cc7` | Dynamic telemetry | Dynamic telemetry recorded: 143 process/file events from monitored components; 1 ETW short-lived process event; 27 tool/system noise entries filtered |
| `etw:55996cc7:3176` | Process event monitoring | Short-lived process event: 55996cc76b81dccfbe6b7d3720f25ab9569e5dbe7c54cd2db18cbeca71376e40.exe (pid 3176; MD5=AA92AD5C2C0620CC61D06D87D09BA5B8,SHA256=55996CC76B81DCCFBE6B7D3720F25AB9569E5DBE7C54CD2DB18CBECA71376E40,IMPHASH=80809665711013F1BD93814069E02A29) |

</details>

---

_This sample is not public; IOCs are defanged. For security research only._
