---
title: "Malware analysis: Unattributed shellcode stager (PE · exe · dffa6d46)"
published: 2026-11-26
draft: false
description: "Malicious (low confidence): Unattributed shellcode stager · downloader/loader · difficulty easy · dynamic sandbox + static decompilation"
tags: ["downloader", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-26-Unattributed-shellcode-stager-dffa6d46"
---

> [!WARNING]
> **Verdict: malicious** · Family **Unattributed shellcode stager** (uncertain) · Confidence **low**
> 
> Aliases: unattributed shellcode loader, custom shellcode stager, shellcode downloader
> 
> The sample is a 3,584-byte PE64 stub that statically imports only Sleep; at runtime it self-resolves 13 system APIs through PEB traversal + ROR13 hashing, connects to the hardcoded address 8.210.131[.]228:443, sends a 40-byte custom beacon, then allocates 30 MB of read-write-execute memory, loops receiving remote data and decrypting it in place with a single-byte 0x99 XOR, and finally calls that memory buffer directly for execution. In the dynamic sandbox the process was actually observed issuing a DNS query for 8.210.131[.]228 and a TCP 443 connection, a typical in-memory shellcode download/load behavior; judged malicious.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Unattributed shellcode stager** · aliases unattributed shellcode loader, custom shellcode stager, shellcode downloader · _uncertain_ |
| Confidence | **low** |
| Behavior class | downloader · loader |
| Difficulty | easy |
| First seen | 2026-11-24 02:29:23 |
| Analysis method | dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/dffa6d4603b3e7926da0d7ca4a39f7cb044751598539f948d30bd1df16645644/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Resolve system APIs by hash</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Load network libraries</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Check temp marker file</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1083</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Connect to hardcoded C2</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Send beacon handshake</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `dffa6d4603b3e7926da0d7ca4a39f7cb044751598539f948d30bd1df16645644` |
| MD5 | _not recorded_ |
| Size | 3,584 bytes (3.5 KB) |
| Type | PE · `exe` |

## Behavior analysis

**9** behaviors in total, each backed by evidence; **7** are available statically and **2** were obtained through dynamic analysis.

### 1. Resolve system APIs by hash

`T1027` · Confidence **high** · Static

Reads the PEB via GS:[0x60] and walks InLoadOrderModuleList, computing ROR13 accumulation and sums separately over module names (UTF-16, with terminating 0) and export function names (ASCII), comparing them against built-in hash constants to resolve 13 APIs: LoadLibraryA, VirtualAlloc, GetTempPathA, WSAStartup, WSASocketA, connect, send, recv, closesocket, gethostbyname, inet_addr, wsprintfA and _access; the import table contains only Sleep.

> **Evidence**: 0x145C resolver: gs:[0x60]→PEB→[0x18]→Ldr→[0x10] list; ror 0xD accumulation at 0x14D1/0x150A; 13 hash constants including 0x726774C, 0x6B8029
> 
> **Source**: `ref:b3d862000d` · `ref:afeefb5c35`

### 2. Load network libraries

`T1129` · Confidence **high** · Dynamic

Calls the self-resolved LoadLibraryA to load user32.dll, ws2_32.dll and msvcrt.dll in turn, preparing functions for later network communication (Winsock), string formatting (wsprintfA) and temporary-file checks (_access).

> **Evidence**: three call LoadLibraryA at 0x1051/0x106F/0x108D; the module list from the memory scan shows user32.dll, ws2_32.dll, msvcrt.dll plus network dependencies such as mswsock.dll and dnsapi.dll
> 
> **Source**: `ref:e30a3b9a8d` · `ref:6d05dee171` · `ref:3a4c7a7ee0`

### 3. Check temp marker file

`T1083` · Confidence **high** · Static

Uses GetTempPathA to get the %TEMP% path, then wsprintfA to build "%TEMP%\log_de.log", and calls _access(path, 0) to check whether the file exists, exiting immediately if so as a single-instance guard; there is no code that creates the file.

> **Evidence**: 0x1133 GetTempPathA(0x80, buf); 0x117F wsprintfA("%s%s%s")→log_de.log; 0x1188 call _access; 0x1194 je exit
> 
> **Source**: `ref:d33d0777ea` · `ref:afeefb5c35`

### 4. Direct connection to hardcoded C2

`T1095` · Confidence **high** · Dynamic

Concatenates the built-in fragments "8.21"+"0.13"+"1.22"+"8" into the IP literal 8.210.131[.]228, initializes Winsock with WSAStartup(0x202), creates an AF_INET/SOCK_STREAM/IPPROTO_TCP socket, obtains the address via gethostbyname and falls back to inet_addr, connects to 8.210.131[.]228:443, and retries after Sleep(10000) on failure. In the dynamic sandbox the process actually issued a DNS query for 8.210.131[.]228 and a TCP 443 connection.

> **Evidence**: IP fragments pushed at 0x11CF/0x11DF/0x11EF/0x11FB; wsprintfA concatenation at 0x1295; WSAStartup(0x202) at 0x12A4; WSASocketA(2,1,6) at 0x12C9; gethostbyname at 0x12E7; connect at 0x1321 (sockaddr port 0x01BB=443); network log: dffa...exe (4772) requested TCP 8.210.131[.]228:443
> 
> **Source**: `ref:e913684ff3` · `ref:47462d82b5` · `ref:966ee212d9`

### 5. Send beacon handshake

`T1095` · Confidence **high** · Static

After a successful connection it calls send repeatedly: first the 6-byte magic "w64 ", then the 2-byte network-order port (0x01BB), then the IP string in 4-byte fragments ("8.21", "0.13", "1.22", "8\0\0\0") padded with 16 zero bytes, for a 40-byte custom beacon in total.

> **Evidence**: 0x1335 send("w64 "); 0x134E send(2-byte port); 0x1361/0x1373/0x1385/0x1397 send(IP fragments); 0x13B0-0x13E1 send(4 zero dwords)
> 
> **Source**: `ref:e913684ff3` · `ref:d33d0777ea`

### 6. Allocate RWX execution memory

`T1620` · Confidence **high** · Static

Calls VirtualAlloc(NULL, 0x1C9C380 (30,000,000 bytes, about 28.6 MB), 0x1000 (MEM_COMMIT), 0x40 (PAGE_EXECUTE_READWRITE)) to allocate a large read-write-execute buffer; exits on failure.

> **Evidence**: 0x13F9 mov edx,0x1C9C380; mov r8d,0x1000; lea r9d,[rsi+0x3C]=0x40; call [rbp-0x20]
> 
> **Source**: `ref:e913684ff3`

### 7. Receive remote payload

`T1105` · Confidence **high** · Static

Loops on recv(socket, buf+offset, 0x64000, 0) to append remote data into the freshly allocated RWX buffer until recv returns a value less than or equal to 0, with the accumulated length tracked in an offset variable.

> **Evidence**: 0x1438 call r15(recv); r8d=0x64000; after recv returns, cmp eax,0 / jge back to the loop
> 
> **Source**: `ref:e913684ff3`

### 8. XOR-decrypt the payload

`T1140` · Confidence **high** · Static

Performs an in-place XOR 0x99 on every byte received by this recv (xor byte ptr [rcx+rdi], 0x99); that is, the remote payload is transmitted with single-byte 0x99 XOR encoding and the decrypted result stays in RWX memory.

> **Evidence**: 0x141F xor byte [rcx+rdi],0x99; 0x1425 cmp r8d,eax / jb 0x1415 loop
> 
> **Source**: `ref:e913684ff3`

### 9. Execute the payload directly from memory

`T1620` · Confidence **high** · Static

After receiving finishes, closesocket closes the socket, then mov rcx,rbx / call rdi jumps directly into the RWX buffer to execute the decrypted shellcode, without touching disk or creating a child process at any point.

> **Evidence**: 0x1443 call [rbp-0x18] (closesocket); 0x1446 call rdi (rdi=VirtualAlloc-returned buffer)
> 
> **Source**: `ref:e913684ff3` · `ref:bae7388936`


## IOCs (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (multiple retries within a short period).
:::

:::caution
**Real server side still unverified**: the above connections/handshakes were completed with a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `8.210.131[.]228:443` | 443 | c2 | Dynamic | Observed |

### Host

**Drop paths**

- `%TEMP%\log_de.log`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `8.210.131[.]228` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `transport` | `raw TCP (WSASocketA AF_INET/SOCK_STREAM/IPPROTO_TCP), reconnect every 10 seconds on failure` | Yes | Static |
| `handshake_magic` | `w64 (6 bytes) + port 2 bytes + 16-byte IP string fragments + 16 bytes of zero padding, 40 bytes in total` | Yes | Static |
| `payload_xor_key` | `0x99 (single-byte XOR, decrypted in place in memory on receipt)` | Yes | Static |
| `exec_method` | `VirtualAlloc(0x1C9C380, MEM_COMMIT, PAGE_EXECUTE_READWRITE) then directly call the buffer for execution` | Yes | Static |
| `single_instance_marker` | `%TEMP%\log_de.log (only checked for existence with _access, never created)` | No | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; take care when citing this report.

- Do not assert that the final payload was obtained or executed: the C2 returned no data during the dynamic window, stage2 was not captured, and the final payload's capabilities remain unknown.
- Do not assert persistence, service or registry modification: the code contains no disk/registry write APIs, telemetry shows no file creation events for this process, and _access was only used to check whether %TEMP%\log_de.log exists.
- Do not attribute this to ransomware or an infostealer: the code contains no file enumeration, encrypted exfiltration or browser credential access logic.
- Do not assert a specific family based only on the "w64" magic or the hash-resolution style: both are common across multiple loaders/frameworks and there is no unique family fingerprint.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | dynamic sandbox analysis + static decompilation |
| Unpacked | No |

**Limitations and pending verification**

1. The C2 returned no payload and stage2 was not obtained; its final function (RAT/stealer/ransomware, etc.) cannot be determined, so the family attribution must remain unattributed.
2. Dynamics observed only a DNS query and a TCP 443 connection attempt, with no complete request/response session, so the c2 entry is recorded as statically recovered and marked pending dynamic verification.
3. Within the dynamic window the process terminated abnormally after connecting (WerFault), so runtime behavior in the receive/decrypt/execute stages could not be observed; conclusions for those stages come from static disassembly.
4. The static analysis is based on disassembly and a self-written ROR13 hash-mapping script (checked against the local system DLL export tables); no vendor YARA or public-intelligence comparison was used.
5. The memory scan found no anomalous injection/hooking, which is an inevitable consequence of no remote payload being received in this run; it does not mean the sample lacks later injection capability.

## Evidence index

<details>
<summary>Expand 20 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:2060c7832d` | Sample triage | sha256/md5/imphash, 3 sections, 1 imported symbol, packing probability 25% (only because imports are so few) |
| `ref:2b3dc3c3cf` | PE structure parsing | PE64, AMD64, GUI subsystem, entry 0x1000, 16KB image, no anomalous sections |
| `ref:ebd8550d72` | Import table parsing | only KERNEL32.dll!Sleep, imphash e82dd51b077167be63c004bed23d0c1e |
| `ref:7135777e59` | String extraction | 70 ASCII strings, including ws2_32/msvcrt/user32 concatenation fragments and log_de fragments |
| `ref:e30a3b9a8d` | disasm.function | first 120 instructions from entry 0x1000: LoadLibraryA×3, 13 hash resolutions, GetTempPathA/wsprintfA/_access, IP fragments and wsprintfA concatenation |
| `ref:bae7388936` | cfg.function | 18 basic blocks in the entry CFG, including the connect-retry loop, receive-decrypt loop and final call to the buffer |
| `ref:e913684ff3` | disasm.function | 140 instructions from 0x1290: WSAStartup/WSASocketA/gethostbyname/connect, 40-byte send, VirtualAlloc RWX, recv+XOR 0x99, closesocket, call payload |
| `ref:b3d862000d` | disasm.function | 0x145C hash resolver: PEB/Ldr traversal + ROR13 module-name/function-name comparison |
| `ref:afeefb5c35` | script | self-written script sums ROR13 over module names in UTF-16 (with NUL) + function names in ASCII (with NUL), exactly matching all 13 hashes to 13 APIs |
| `ref:6d05dee171` | dyn.run | emulated execution observed LoadLibraryA(user32.dll/ws2_32.dll/msvcrt.dll) |
| `ref:2c0388c859` | Dynamic analysis platform | sandbox detonation: pid 4772, timeline, 5 dumps, network and telemetry artifacts packaged and rolled back |
| `ref:47462d82b5` | sandbox.log | network monitoring log: dffa...exe (4772) requested TCP 8.210.131[.]228:443 |
| `ref:966ee212d9` | sandbox.telemetry | monitoring component: DNS query from pid 4772 for 8.210.131[.]228 (QueryStatus 0) |
| `ref:b8ecb391d7` | sandbox.telemetry | monitoring component event sequence: 4772 process creation, DNS query, WerFault, t0/t3 memory scans |
| `ref:3a4c7a7ee0` | memory.scan | pid 4772 memory scan: module list contains ws2_32/user32/msvcrt, no suspicious injected regions at t0/t3 (0 suspicious in total) |
| `ref:d33d0777ea` | manual.hexdump | raw .text bytes: string concatenation constants such as "log_"/"de."/"log", "8.21"/"0.13"/"1.22"/"8", "w64 " |
| `ref:34075c6580` | Dynamic artifact collection | artifact zip manifest: network monitoring logs, monitoring component/ETW, memory scan reports, process/module dumps |
| `c2_evidence:dffa6d46` | Connection evidence extraction | dynamic network monitoring recorded 1 connection attempt to 8.210.131[.]228:443; no complete session was captured |
| `telemetry:dffa6d46` | Dynamic telemetry | dynamic telemetry recorded: 115 process/file events from the monitoring component; 1 ETW short-lived process event; 26 tool/system noise events filtered out |
| `etw:dffa6d46:4772` | Process event monitoring | short-lived process event: dffa6d4603b3e7926da0d7ca4a39f7cb044751598539f948d30bd1df16645644.exe (pid 4772; MD5=7F0439FBD3689890DF30B881B29C3D99,SHA256=DFFA6D4603B3E7926DA0D7CA4A39F7CB044751598539F948D30BD1DF16645644,IMPHASH=E82DD51B077167BE63C004BED23D0C1E) |

</details>

---

_The sample in this report is not public; the IOCs have been defanged and are provided for security research only._
