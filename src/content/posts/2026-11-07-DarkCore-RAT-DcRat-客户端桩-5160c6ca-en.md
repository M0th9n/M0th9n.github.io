---
title: "Malware Analysis: DarkCore RAT (DcRat client stub) (PE · exe · 5160c6ca)"
published: 2026-11-07
draft: false
description: "Malicious (medium confidence): DarkCore RAT (DcRat client stub) · rat/backdoor/injector · difficulty hard · Dynamic sandbox analysis + static decompilation"
tags: ["DarkCore", "rat", "backdoor", "injector", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-07-DarkCore-RAT-DcRat-客户端桩-5160c6ca"
---

> [!WARNING]
> **Verdict: Malicious** · Family **DarkCore RAT (DcRat client stub)** (uncertain) · Confidence **medium**
> 
> Aliases: DcRat, DarkCore, DCRat candidate
> 
> A 64-bit native client stub exporting DcInjEntry/DcCloakProcess/DcHjAct/DcHjSet, with built-in AES-256-GCM configuration decryption, remote configuration retrieval, custom binary protocol check-in, process injection, and anti-VM/anti-debugging; it was executed in an isolated Windows sandbox and continuously attempted TCP connections to 2.27.4[.]184:49812, with the decrypted host/port and a successful getaddrinfo log visible in memory, constituting directly reproducible malicious remote-control check-in behavior.

## Overview

| Item | Content |
|:--|:--|
| Family | **DarkCore RAT (DcRat client stub)** · aliases DcRat, DarkCore, DCRat candidate · _uncertain_ |
| Confidence | **medium** |
| Behavior class | rat · backdoor · injector |
| Difficulty | hard |
| First seen | 2026-11-06 06:59:16 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/5160c6ca466626650a1bd5cb2918d756ed101a721bb31c4d7611c62e9427597f/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded config</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Fetch remote config</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Direct C2 port check-in</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Send HELLO registration</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Inject into host process</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `5160c6ca466626650a1bd5cb2918d756ed101a721bb31c4d7611c62e9427597f` |
| MD5 | _not recorded_ |
| Size | 608,256 bytes (594.0 KB) |
| Type | PE · `exe` |

## Behavior analysis

**12** behaviors in total, each backed by evidence; **11** are statically available and **1** was obtained through dynamic analysis.

### 1. Decrypt embedded configuration

`T1027` · Confidence **high** · static

After startup it uses CNG AES-256-GCM (32-byte key, 12-byte nonce, 16-byte tag) to decrypt the configuration block in .data2, with a fallback path on failure; the module loader also has PVM\x02 container decryption and rolling XOR decoding.

> **Evidence**: FUN_14004bc98 (BCryptOpenAlgorithmProvider("AES") + ChainingModeGCM + BCryptDecrypt); FUN_14004dfa4 validates the PVM\x02 header and calls decryption; FUN_14002870c is a SHA-256 KDF
> 
> **Source**: `ref:75dc2a0d6d` · `ref:9caf81bdef` · `ref:cdd12e527e`

### 2. Fetch remote configuration

`T1105` · Confidence **high** · static

It uses WinHTTP to GET the URL from the configuration (fixed UA Mozilla/5.0) and supports rewriting pastebin[.]com/raw/<id> into a download address; the first non-comment line of the returned text is parsed as host:port and written into the global C2 host and port fields, with no re-fetch within 60 seconds.

> **Evidence**: FUN_14000be0c: strings "hxxps://"/"hxxp://"/"pastebin[.]com"/"/raw/", calls WinHttpQueryDataAvailable/WinHttpReadData, writes results to DAT_14008f3c0 and DAT_14009900a
> 
> **Source**: `ref:25910a007a` · `ref:9ba17d3133`

### 3. Direct C2 port check-in

`T1571` · Confidence **high** · dynamic

When run standalone it resolves the configured host and repeatedly connects to 2.27.4[.]184:49812 over raw TCP, retrying every 10–20 seconds and not exiting for several minutes.

> **Evidence**: sandbox timeline pid 8040; network monitoring recorded 13 TCP 2.27.4[.]184:49812 connection attempts from 02:46:27 to 02:49:51; process heap memory shows "49812", "2.27.4[.]184", "getaddrinfo ret=0"
> 
> **Source**: `ref:0c27c1d45e` · `ref:19055b45e0` · `ref:f4928adee5`

### 4. Send HELLO registration packet

`T1095` · Confidence **high** · static

After the connection is established it sends a HELLO check-in packet using the custom binary protocol OpMap_v2, with the client identity shaped like INJ-<pid>-<tid>; logs show "HS OK sending HELLO" and "HELLO SENT OK - ONLINE".

> **Evidence**: FUN_140010fe0 handshake flow; strings 0x76230 "native KDF ok", 0x76240 "HS OK sending HELLO", 0x76260 "INJ-%08lX-%08lX", 0x76288 "HELLO SENT OK - ONLINE"
> 
> **Source**: `ref:4ff94afb05` · `ref:9ba17d3133`

### 5. Inject into a host process

`T1055` · Confidence **high** · static

It exports DcInjEntry as the injection entry: it reads its own module base and SizeOfImage for marking, cleans up %TEMP%\wctk.dat / wcti.dat, creates and waits on the WctSync_<pid> event, initializes internal state, and enters the main loop; companion exports DcHjAct/DcHjSet control the hijack switches.

> **Evidence**: 0x14002e478 DcInjEntry (VirtualQuery checks MZ/PE, DeleteFileA wctk.dat/wcti.dat, OpenEventA WctSync_%lu); 0x14004aa68 DcHjAct / 0x14004aa78 DcHjSet
> 
> **Source**: `ref:3cb407c9ef` · `ref:ee0ea0bf4c` · `ref:f301bf0db6`

### 6. Disguise as the svchost process

`T1036.005` · Confidence **high** · static

It exports DcCloakProcess, which by default disguises itself as C:\Windows\System32\svchost.exe when no target name is given, and calls CFG valid-call-target setup and process-information modification routines to hide injection traces.

> **Evidence**: 0x14002e448 DcCloakProcess default parameter L"C:\\Windows\\System32\\svchost.exe"; then calls FUN_14004422c / FUN_140046974 / FUN_140045620; string SetProcessValidCallTargets
> 
> **Source**: `ref:7cb584cdc2` · `ref:9ba17d3133`

### 7. Detect virtual machine environments

`T1497.001` · Confidence **high** · static

It walks processes and system information; on names such as vboxservice.exe, vgauthservice.exe, vmusrvc.exe, qemu-ga.exe, vboxtray.exe, vmtoolsd.exe, vmwaretray.exe, vmwareuser.exe, or on detecting WDAGUtilityAccount, the DESKTOP- prefix, or USBSTOR records, it exits immediately, logging ANTI_VM HIT / ANTI_SANDBOX HIT.

> **Evidence**: VM process-name list starting at string 0x771e8; 0x76500 "ANTI_VM HIT exit", 0x76530 "ANTI_SANDBOX HIT exit", 0x76560 FLAGS ad/vm/sb/etw/amsi/uh/dump/masq; imports for process snapshot creation and QueryFullProcessImageNameW
> 
> **Source**: `ref:bc4c5209fd` · `ref:9ba17d3133`

### 8. Anti-debugging self-check

`T1622` · Confidence **high** · static

It performs an anti-debugging self-check through SEH, IsDebuggerPresent, debug flags, and exception dispatch paths; on a hit it records ANTI_DEBUG HIT and exits; in injection mode some environment-exit logic can be skipped.

> **Evidence**: strings 0x764b0 "ANTI_DEBUG SEH 0x%08lX", 0x764d0 "ANTI_DEBUG HIT exit", 0x764e8 "ANTI_DEBUG CHECK ok"; imports IsDebuggerPresent/SetUnhandledExceptionFilter/RtlCaptureContext
> 
> **Source**: `ref:9ba17d3133` · `ref:bc4c5209fd`

### 9. Load remote plugins

`T1105` · Confidence **high** · static

It receives PVM\x02 module blocks pushed by the server, dispatches them by id and loads them in memory; modules may carry an injection flag; logs include modpush id/blob/inj and module dispatch information such as ModDisp and RegEx exports.

> **Evidence**: FUN_14004dfa4 parses PVM\x02 (magic+length+AES-GCM ciphertext); strings 0x75e10 "modpush id=0x%02X blob=%u inj=%d", 0x77bd0 "RegEx exports init/initex/disp/shut", 0x77c20 "ModDisp enter 0x%02X"
> 
> **Source**: `ref:9caf81bdef` · `ref:9ba17d3133`

### 10. Built-in PowerShell remote control

`T1059.001` · Confidence **high** · static

It embeds a complete interactive PowerShell session implementation: launching powershell.exe/pwsh.exe, framing stdout/stderr with ::__DCPS_META__::/::__DCPS_END__::, supporting #B64# scripts and control commands such as :cmd/:psreset/:pskill, forming a fileless remote command execution channel.

> **Evidence**: PowerShell runspace/pipeline scripts and DCPS protocol markers in strings 0x74b90–0x75bc8; 0x75770 ::dcscript:: / 0x75780 ::dcps::; CreateProcessA + CreatePipe + PeekNamedPipe
> 
> **Source**: `ref:9ba17d3133` · `ref:bc4c5209fd`

### 11. Clean up temporary payloads

`T1070.004` · Confidence **high** · static

The injection entry first deletes %TEMP%\wctk.dat and %TEMP%\wcti.dat, and uses wcts.log/wctt.log to record its own events during execution, reducing forensic artifacts on disk.

> **Evidence**: 0x14002e478: GetTempPathA followed by wsprintfA("%swctk.dat"/"%swcti.dat") and DeleteFileA; log file names wcts.log / wctt.log
> 
> **Source**: `ref:3cb407c9ef` · `ref:9ba17d3133`

### 12. Read registry hives

`T1012` · Confidence **medium** · static

It builds the %s\Windows\System32\config\SOFTWARE path to read offline registry hives, and has registry read/write capabilities such as RegEnumValue/RegDeleteValue/RegSetValueEx, used for host/system information collection and configuration tampering.

> **Evidence**: string 0x76640 "%s\\Windows\\System32\\config\\SOFTWARE"; imports RegEnumValueW/RegQueryValueExW/RegSetValueExW/RegDeleteTreeW; memory shows the Software\Microsoft\Windows\CurrentVersion path
> 
> **Source**: `ref:9ba17d3133` · `ref:bc4c5209fd` · `ref:cdcbe41f93`


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
| tcp | `2.27.4[.]184` | 49812 | c2 | dynamic | observed |
| https | `2.27.4[.]184` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://pastebin[.]com/raw/<id>` | 443 | download | static | ⏳ not observed |

### Host

**Mutexes**

- `Local\DCSI%s`
- `Local\DCSS%s`
- `Local\WDINJ%s`
- `Local\WD%08X`
- `Local\W%02X%02X%02X%02X%02X%02X%02X%02X`
- `Local\DCWDFLAG`
- `WctSync_<pid> (event object name)`

**Dropped paths**

- `%TEMP%\wctk.dat`
- `%TEMP%\wcti.dat`
- `%TEMP%\wcts.log`
- `%TEMP%\wctt.log`
- `%TEMP%\dc%08lx%04x.dll`
- `%TEMP%\%08X%08X.exe`
- `%USERPROFILE%\Desktop\dc_hrdp_debug.log`
- `C:\Users\Public\Desktop\<dropped_name>`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run (path visible in runtime memory; the specific value name was not recovered)`
- `SYSTEM\CurrentControlSet\Services\WinSxAutoInstallService`

**Services**

- `WinSxAutoInstallService`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `2.27.4[.]184` | yes | dynamic |
| `c2_port` | `49812` | yes | dynamic |
| `c2_transport` | `raw TCP (built-in WinHTTP wrapper; also supports http/https and default port 443)` | yes | static |
| `config_loader` | `supports fetching the first line host:port from pastebin[.]com/raw/<id> or any http(s) URL to override the configuration` | no | static |
| `user_agent` | `Mozilla/5.0` | no | static |
| `encryption_algo` | `AES-256-GCM (32-byte key, 12-byte nonce, 16-byte tag) + SHA-256 KDF; modules also have a rolling XOR layer after decryption` | yes | static |
| `campaign_id` | `DARKCORE01` | no | static |
| `protocol` | `custom binary protocol OpMap_v2; the HELLO check-in carries an INJ-<pid>-<tid> identity` | yes | static |
| `plugins` | `ph-media-key-v1 / ph-media-n-c-v1; exported plugin capabilities such as RD_SetCaptureMode, HVNC_SetTorMode, HVNC_SetWssMode` | no | static |
| `install_path` | `%TEMP% (wctk.dat / wcti.dat / dc<hex>.dll)` | no | static |
| `mutex_family` | `Local\DC* / Local\W* / Local\WDINJ*` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- Do not judge it as a browser password stealer or ransomware merely because of generic imports such as CryptUnprotectData or bcrypt/AES — these are general capabilities for configuration/module encryption and DPAPI.
- Do not describe 2.27.4[.]184:49812 as the only or permanent C2; the configuration can be updated at runtime from a remote URL, and built-in https/443 and pastebin download paths exist.
- Do not claim complete remote-control command execution was observed: this run only saw check-in connection attempts and in-memory configuration, with no server-side task received.
- Do not treat this file as a standalone backdoor EXE; it is a client stub exporting an injection entry, usually deployed by a loader/host process.
- Do not assert that all communication goes over HTTP just because WinHTTP is imported: the observed transport was raw TCP.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. With no server listener, no command dispatch, plugin download, or persistence writes after HELLO were observed; the C2 host/port was confirmed only by network behavior and process-memory strings.
2. The configuration file is AES-256-GCM ciphertext, and complete plaintext fields were not recovered statically (such as the ID in the configuration URL, the persistence registry value name, and the full mutex string); runtime memory and network evidence take precedence.
3. Persistence clues come from strings and the CurrentVersion path in memory; no actual registry write was observed, and no service creation action was observed for the service name WinSxAutoInstallService either.
4. The process memory image contains many system module strings, and some registry paths may come from system DLLs, so those entries are marked medium confidence.
5. The family name is based on the sample's self-identifying strings (DARKCORE01/[DarkCore]/Dc* exports/DCPS); public naming may differ, so it remains uncertain.
6. Within the dynamic observation window the sample spawned no child processes and produced no capturable dropped files; modular capabilities are proven only by code and strings.

## Evidence index

<details>
<summary>Show 17 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprints | sha256=5160c6ca466626650a1bd5cb2918d756ed101a721bb31c4d7611c62e9427597f, size 608256 |
| `ev-000002` | scan.imphash | imphash=513cd6674933d27c38b7beb90a5ff371 |
| `ref:33e97eefee` | PE structure parsing | PE32+ AMD64 GUI, 9 sections, 4 exports, section names include .pvmut/.fptable, no structural anomalies |
| `ref:bc4c5209fd` | Import table parsing | 289 imports: WS2_32/WinHTTP/bcrypt/CryptUnprotectData/registry/process and thread enumeration/ReadProcessMemory/CreateProcess |
| `ref:196a87c547` | pe.exports | client_stub.exe exports DcCloakProcess(0x2e448), DcHjAct(0x4aa68), DcHjSet(0x4aa78), DcInjEntry(0x2e478) |
| `ref:9ba17d3133` | String extraction | Extracted 1896 ASCII/207 UTF-16 strings: DarkCore, DCPS, PVM modules, anti-VM list, wctk.dat, pastebin, etc. |
| `ref:25910a007a` | decompile | FUN_14000be0c implements http(s)/pastebin configuration fetching and host:port parsing (WinHTTP) |
| `ref:4ff94afb05` | decompile | FUN_140010fe0 implements C2 connection, SHA-256 KDF, HELLO handshake and machine fingerprint |
| `ref:75dc2a0d6d` | decompile | FUN_14004bc98 is the AES-256-GCM decryption routine (ChainingModeGCM) |
| `ref:9caf81bdef` | decompile | FUN_14004dfa4 parses the PVM\x02 module container and decrypts/dispatches modules |
| `ref:3cb407c9ef` | decompile | DcInjEntry injection entry: VirtualQuery self-check, deletes wctk.dat/wcti.dat, WctSync event synchronization |
| `ref:7cb584cdc2` | decompile | DcCloakProcess disguises itself as C:\Windows\System32\svchost.exe by default |
| `ref:0c27c1d45e` | Dynamic analysis platform | Real detonation in an isolated environment: pid 8040 ran for 4 minutes, process timeline and 6 memory dumps collected, environment rolled back |
| `ref:19055b45e0` | network.observe | Sample process made 13 TCP connections to 2.27.4[.]184:49812 (02:46–02:49), no child processes/dropped files |
| `ref:f4928adee5` | memory.forensics | Process heap memory shows 49812, 2.27.4[.]184, getaddrinfo ret=0, confirming the runtime configuration was decrypted |
| `ref:5ba7ccb1b0` | memory.forensics | Memory image confirms DARKCORE01, %swctk.dat, native KDF, HELLO, OpMap_v2, client_stub export names and other source-code assets |
| `c2_evidence:5160c6ca` | Connection evidence extraction | Dynamic network monitoring recorded 14 connection attempts to 2.27.4[.]184:49812, config[.]edge[.]skype[.]com:80, maps[.]windows[.]com:443; no complete session was captured |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
