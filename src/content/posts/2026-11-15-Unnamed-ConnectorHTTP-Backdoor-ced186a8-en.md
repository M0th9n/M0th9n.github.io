---
title: "Malware Analysis: Unnamed ConnectorHTTP Backdoor (PE · exe · ced186a8)"
published: 2026-11-15
draft: false
description: "Malicious (low confidence): Unnamed ConnectorHTTP Backdoor · backdoor/rat · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Unnamed ConnectorHTTP", "backdoor", "rat", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-15-Unnamed-ConnectorHTTP-Backdoor-ced186a8"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Unnamed ConnectorHTTP Backdoor** (uncertain) · Confidence **Low**
> 
> Static analysis recovered the RC4-encrypted embedded C2 configuration (host minecraf-world-register[.]io.vn, port 443, POST /api/v1/updates, custom header X-Beacon-Id) and confirmed that the program resolves 123 APIs dynamically via PEB/export-table hashing (including CreateProcessA/CreatePipe/ReadFile/WriteFile, InternetOpenA/HttpSendRequestA, socket/connect/recv, etc.); the main loop dispatches remote commands, file transfer and socket forwarding by packet type. In the dynamic sandbox the sample actually started, resolved the same domain and sent 671 homogeneous HTTP POST beacons in a row, matching the static configuration word for word, so it is judged a backdoor with remote-control capability.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Unnamed ConnectorHTTP Backdoor** · _uncertain_ |
| Confidence | **Low** |
| Behavior class | backdoor · rat |
| Difficulty | medium |
| First seen | 2026-11-14 00:26:12 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded C2 config</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Hash-resolve system APIs</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">HTTP beacon polls C2</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Plaintext HTTP on 443</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Remote shell commands</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900` |
| MD5 | _not recorded_ |
| Size | 104,448 bytes (102.0 KB) |
| Type | PE · `exe` |

## Behavior Analysis

**9** behaviors in total, each backed by evidence; **7** are statically available and **2** were obtained through dynamic analysis.

### 1. Decrypt embedded C2 configuration

`T1027` · Confidence **High** · Static

Reads a [u32 length][RC4 ciphertext][16-byte key] structure from the start of .rdata (file offset 0x17C00 / RVA 0x1A000), decrypts 233 bytes with standard RC4 and sequentially parses out the C2 host, port, URI, HTTP method and custom request header; it also generates 16 bytes of random session data used as a communication identifier.

> **Evidence**: 0x140003e8e parses the configuration; 0x14000d630 RC4 KSA / 0x14000d720 PRGA; blob off 0x17C00
> 
> **Source**: `ev-000029` · `ev-000031` · `ev-000032` · `ev-000036` · `ev-000038` · `ev-000039` · `ev-000051`

### 2. Hash-resolve system APIs

`T1027` · Confidence **High** · Static

Walks the PEB's loaded-module list and matches module base names and export names by a 32-bit hash h=0x624, h=h*0x21+lowercase character, dynamically resolving 123 APIs; the import table therefore keeps only KERNEL32/msvcrt CRT functions, hiding the real capability surface.

> **Evidence**: 0x140010e5a PEB walk; 0x140010d80/0x140010ded hash functions; 0x14000477e resolution table
> 
> **Source**: `ev-000044` · `ev-000045` · `ev-000047` · `ev-000048` · `ev-000028` · `ev-000052`

### 3. HTTP beacon polling of C2

`T1071.001` · Confidence **High** · Dynamic

Periodically sends POST /api/v1/updates to minecraf-world-register[.]io.vn:443 through WinINet, with X-Beacon-Id: <Base64 session data>, a fixed UA, Content-Length: 0 and Keep-Alive; 671 homogeneous requests were recorded within 4 minutes in this run.

> **Evidence**: Dynamic network monitoring: POST /api/v1/updates HTTP/1.1, Host: minecraf-world-register[.]io.vn; 0x14000ea87 main loop; 0x14000477e resolves InternetOpenA/HttpSendRequestA
> 
> **Source**: `ev-000053` · `ev-000051` · `ev-000023` · `ev-000052`

### 4. Plaintext HTTP on port 443

`T1571` · Confidence **High** · Dynamic

The configured port is 443, but communication is actually plaintext HTTP/1.1 (no TLS handshake), abusing the common HTTPS port to evade simple port/protocol filtering.

> **Evidence**: Network monitoring captured the complete plaintext HTTP request on 443; configuration c2_port=443, c2_uri=/api/v1/updates
> 
> **Source**: `ev-000053` · `ev-000051`

### 5. Remote shell command execution

`T1059.003` · Confidence **High** · Static

The command-handling chain uses CreateProcessA to create processes, CreatePipe/PeekNamedPipe/ReadFile/WriteFile to forward stdout and stdin, and encapsulates results into 0x25/0x27 packet types for the return channel; a 0x103 error ends the session.

> **Evidence**: CreateProcessA/CreatePipe/PeekNamedPipe/ReadFile/WriteFile call chain and 0x25/0x27 packet types at 0x140010920
> 
> **Source**: `ev-000043` · `ev-000052` · `ev-000023`

### 6. File upload/download management

`T1105,T1083` · Confidence **Medium** · Static

0x14000da30 uses a state machine to open the target file, ReadFile it in chunks and report progress via 0x20-type packets; 0x14000e520 maintains another kind of transfer entry; the resolution table includes CreateFileA/CopyFileA/MoveFileA/DeleteFileA/FindFirstFileA/GetLogicalDrives and other file-management functions.

> **Evidence**: 0x14000da30 file-chunk reads and 0x20 packets; 0x14000e520 transfer-entry state machine; 0x14000477e file API resolution
> 
> **Source**: `ev-000040` · `ev-000041` · `ev-000052`

### 7. Socket forwarding/proxy

`T1090` · Confidence **Medium** · Static

0x140010920 uses ioctlsocket(FIONREAD=0x4004667f) on type=2 handles to get the pending length, then recv reads data, and calls half-close/close; the resolution table also contains accept/bind/listen/select, providing a code path to relay the C2 channel to local or intranet sockets (port forwarding/proxy). No command was received in this run, so it was not actually triggered.

> **Evidence**: 0x140010920 ioctlsocket 0x4004667f + recv; 0x14000477e resolves accept/bind/listen/select
> 
> **Source**: `ev-000043` · `ev-000052`

### 8. Named-pipe inter-process communication

`T1559` · Confidence **Medium** · Static

Resolves CreateNamedPipeA/WaitNamedPipeA/SetNamedPipeHandleState/DisconnectNamedPipe and builds pipe names with the format string \\.\pipe\%08lx, used for communication between local components or instances.

> **Evidence**: String \\.\pipe\%08lx @ rva 0x1A234 (off 0x17954); 0x140007b9c/0x14000851c pipe-handle management; 0x14000477e resolves named-pipe APIs
> 
> **Source**: `ev-000013` · `ev-000050` · `ev-000049` · `ev-000052`

### 9. Host fingerprint collection

`T1082,T1016,T1033` · Confidence **High** · Static

Early in the connection it assembles an approximately 0x11c-byte host-information packet using GetAdaptersInfo, GetComputerNameExA, GetUserNameA, RtlGetVersion, GetTimeZoneInformation, GetLocalTime and others, serializes it and passes it to the communication object to send as the first connection data.

> **Evidence**: 0x14000439e collects host information; 0x140003a9e serializes; 0x14000ea87 sends this data first when establishing the connection
> 
> **Source**: `ev-000027` · `ev-000025` · `ev-000023` · `ev-000052`


## IOCs (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (multiple retries within a short period).
:::

:::caution
**Real server side still unverified**: the above connection/handshake was completed with a local controlled emulation service; the real C2's responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://minecraf-world-register[.]io[.]vn/api/v1/updates` | 443 | c2 | Dynamic | Observed |

### Host

- **No host IOCs were recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `minecraf-world-register[.]io.vn` | Yes | Dynamic |
| `c2_port` | `443` | Yes | Dynamic |
| `c2_uri` | `/api/v1/updates` | Yes | Dynamic |
| `http_method` | `POST` | Yes | Dynamic |
| `http_header` | `X-Beacon-Id` | Yes | Dynamic |
| `user_agent` | `Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0` | Yes | Dynamic |
| `header_encoding` | `base64` | No | Dynamic |
| `encryption_algo` | `RC4 (KSA+PRGA) for embedded config blob; 16-byte key appended after ciphertext` | Yes | Static |
| `config_magic` | `0xBE4C0149` | No | Static |
| `config_blob_location` | `file_off=0x17C00 rva=0x1A000 len=253 (u32=233 + 233 ciphertext + 16 key)` | No | Static |
| `separator` | `\r\n` | No | Static |
| `config_timestamp_unix` | `1742829843` | No | Static |

## What Not to Misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not judge it ransomware/wiper: no file encryption, shadow-copy deletion or mass-destruction logic and no corresponding API resolution were found.
- Do not judge it a stealer/banker: no browser-data, credential-store or keyboard/screen-capture APIs or call chains were found, and no related reads/writes were observed dynamically.
- Do not claim persistence: this run observed no service, startup item, registry Run key or scheduled-task writes; the resolved API table also contains no corresponding write functions, and the sample resembles an in-memory beacon.
- Do not claim process injection or credential dumping occurred: memory scanning found no replaced/implanted modules, and there was no child process or LSASS access by this sample dynamically.
- Do not treat "has token-related APIs" as token theft actually performed: token-related functions appear only in the API resolution table, and no actual call chain was observed.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The dynamic sandbox recorded only the client's HTTP requests, and the server returned no parseable task instructions; therefore remote shell, file transfer and socket forwarding capabilities are judged from static call chains without dynamic execution confirmation.
2. No persistence or autostart behavior was observed; however, this run was short, so it cannot be asserted that long-term residency capability does not exist.
3. No process injection or credential dumping was observed; this only means it was not found in this run and memory scan, and later instructions cannot be ruled out.
4. The PE compile timestamp is 2026-10-24, later than the sample's usual appearance time, and may be forged or reflect a build-environment clock anomaly.
5. The family name lacks vendor-engine/YARA cross-validation; the candidate is given only from the configuration magic, RTTI class names, request headers and behavior traits, marked uncertain.
6. The C2 domain resolves to a reserved test address in the sandbox fake network; real infrastructure connectivity was not verified.

## Evidence Index

<details>
<summary>Expand 29 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1 and file size |
| `ev-000002` | scan.imphash | imphash=2eb0e19e399049c7d933ef4e6502cd2a |
| `ev-000013` | String extraction | Strings: \\.\pipe\%08lx, ConnectorHTTP/Connector RTTI, api-ms-win-/ext-ms- |
| `ev-000023` | decompile.function | Main loop 0x14000ea87: connect, receive packet, command dispatch, reply |
| `ev-000025` | decompile.function | 0x140003a9e serializes host information and 16-byte session data |
| `ev-000026` | decompile.function | 0x14000365e constructs the config/session object and generates 16 bytes of random data |
| `ev-000027` | decompile.function | 0x14000439e collects host fingerprint information |
| `ev-000028` | decompile.function | 0x14000477e builds the hash table for dynamic module and API resolution |
| `ev-000029` | decompile.function | 0x140003e8e embedded configuration structure parsing flow |
| `ev-000031` | decompile.function | 0x140001480 config blob pointer = 0x14001a000 |
| `ev-000032` | decompile.function | 0x14000148d config blob length = 0xfd |
| `ev-000036` | decompile.function | 0x14000d83c configuration decryption entry (KSA+PRGA) |
| `ev-000038` | decompile.function | 0x14000d630 RC4 KSA |
| `ev-000039` | decompile.function | 0x14000d720 RC4 PRGA |
| `ev-000040` | decompile.function | 0x14000da30 file-chunk reading and 0x20 packet state machine |
| `ev-000041` | decompile.function | 0x14000e520 transfer-entry state machine and 0x8437 packet type |
| `ev-000043` | decompile.function | 0x140010920 pipe/socket handling and 0x25/0x27 return |
| `ev-000044` | decompile.function | 0x140010e5a PEB InMemoryOrderModuleList walk |
| `ev-000045` | decompile.function | 0x140010f00 export-table hash matching and API resolution |
| `ev-000047` | decompile.function | 0x140010d80 name hash h=h*0x21+c |
| `ev-000048` | decompile.function | 0x140010ded module-name hash (wide characters) |
| `ev-000049` | decompile.function | 0x14000851c multi-channel handle read/close |
| `ev-000050` | decompile.function | 0x140007b9c creates pipe/handle objects |
| `ev-000051` | evidence.record | Script: RC4-decrypt and parse the embedded configuration |
| `ev-000052` | evidence.record | Script: recompute the hash algorithm and enumerate 123 dynamically resolved APIs |
| `ev-000053` | evidence.record | Script: summary of dynamic sandbox DNS/HTTP beacons and memory-scan results |
| `c2_evidence:ced186a8` | Connection evidence extraction | Dynamic network monitoring recorded 307 connection attempts to minecraf-world-register[.]io[.]vn:443; no complete session captured |
| `telemetry:ced186a8` | Dynamic telemetry | Dynamic telemetry recorded: monitoring components process/file events 117; ETW short-lived process events 1; filtered tool/system noise 27 |
| `etw:ced186a8:7212` | Process event monitoring | Short-lived process event: ced186a8664f5ed95a4f516d04e614a27d2407536dd69b5cb8c0045cd3db1900.exe (pid 7212; MD5=A293B28028115D676FCA89E38FE8A441,SHA256=CED186A8664F5ED95A4F516D04E614A27D2407536DD69B5CB8C0045CD3DB1900,IMPHASH=2EB0E19E399049C7D933EF4E6502CD2A) |

</details>

---

_This report's sample is not public, IOCs are defanged, and it is for security research only._
