---
title: "Malware Analysis: PureCrypter (PE · exe · 40553ae7)"
published: 2026-11-10
draft: false
description: "Malicious (medium confidence): PureCrypter · stealer/loader · difficulty hard · Dynamic sandbox + static decompilation"
tags: ["PureCrypter", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-10-PureCrypter-40553ae7"
---

> [!WARNING]
> **Verdict: Malicious** · Family **PureCrypter** (uncertain) · Confidence **medium**
> 
> Aliases: PureCrypter Loader, PCLoader, PureCoder loader / PureLogs-style stealer payload
> 
> The file really executes in an isolated sandbox: after creating a global mutex it copies itself to C:\ProgramData\SystemData\30d4fdf211293635\iq.exe, writes launch.hta and starts that copy via the mshta.exe proxy; the copy loads the CLR, patches amsi.dll and clr.dll, then runs an in-memory .NET payload and continuously initiates TCP connections to 45.192.214[.]54:56001 (with 127.0.0[.]1:56001-56003 fallbacks); the in-memory protobuf configuration and payload strings show that it has browser/wallet credential theft, host fingerprinting, screenshot and scheduled-task persistence capabilities.

## Overview

| Item | Content |
|:--|:--|
| Family | **PureCrypter** · aliases PureCrypter Loader, PCLoader, PureCoder loader / PureLogs-style stealer payload · _uncertain_ |
| Confidence | **medium** |
| Behavior class | stealer · loader |
| Difficulty | hard |
| First seen | 2026-11-10 12:17:01 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/40553ae76fe40e685da891af1eb2f51989a6044e4dc547f5cba9499a2b2ff6b0/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Applies Rockstar certificate</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Decrypts built-in C2 config</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Drops copy into ProgramData</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Runs HTA via mshta</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1218.005</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Creates global mutex</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `40553ae76fe40e685da891af1eb2f51989a6044e4dc547f5cba9499a2b2ff6b0` |
| MD5 | _not recorded_ |
| Size | 5,847,456 bytes (5.6 MB) |
| Type | PE · `exe` |

## Behavior analysis

**12** behaviors in total, each backed by evidence; **7** are statically available and **5** were obtained through dynamic analysis.

### 1. Applies a Rockstar certificate

`T1027` · Confidence **high** · static

The PE security directory points to a 3488-byte Authenticode signature at 0x322C00, with the signing subject Take-Two Interactive Software, Inc. / Rockstar Games and a validity period from 2011-09-21 to 2013-09-20; after the end of the certificate table (0x3239A0) about 2,555,904 bytes of high-entropy data are still appended, the .rdata section entropy is 7.999, and the signature does not cover the appended content.

> **Evidence**: Security directory RVA=0x322C00 size=3488; strings 'VeriSign Class 3 Code Signing 2010 CA' / 'Take-Two Interactive Software, Inc.' / 'Rockstar Games' at 0x322D14-0x322E4D; data after 0x3239A0 runs to EOF
> 
> **Source**: `ref:d854d3212c` · `ref:cf00150776` · `ref:4f95768d62`

### 2. Decrypt the built-in C2 configuration

`T1140` · Confidence **high** · dynamic

From the host process memory a protobuf-serialized configuration was recovered: field 1 repeats hosts '127.0.0[.]1' and '45.192.214[.]54'; field 2 ports 56001/56002/56003; field 3 is a 3220-byte base64 server certificate; field 4 'Default'; field 8 'APPDATA'. The loader assembly contains components such as TripleDES/GZip/PayloadSource.zip/PCLoader.

> **Evidence**: Memory dump protobuf message from 0x5B88E: 0A09 '127.0.0[.]1', 0A0D '45.192.214[.]54', 10 C1B503=56001, 10 C2B503=56002, 10 C3B503=56003, 1A 94 19=3220-byte certificate
> 
> **Source**: `ref:a3cb256ec1` · `ref:87ef37565c` · `ref:a221a5fea7`

### 3. Drop a copy into ProgramData

`T1036.005` · Confidence **high** · dynamic

The sample process creates the C:\ProgramData\SystemData\30d4fdf211293635 directory and writes a copy of itself as iq.exe in the same directory; it then uses GetFileAttributesW to check whether that path exists.

> **Evidence**: File creation event: Image=C:\dyn\samples\<sha>.exe → TargetFilename=C:\ProgramData\SystemData\30d4fdf211293635\iq.exe; emulation trace CreateDirectoryW('C:','C:\ProgramData','C:\ProgramData\SystemData', ...\30d4fdf211293635') + GetFileAttributesW('...\iq.exe')
> 
> **Source**: `ref:1080dc8621` · `ref:ae43a88804`

### 4. Execute the HTA via mshta

`T1218.005` · Confidence **high** · dynamic

About 140ms after writing launch.hta it executes that HTA with mshta.exe, and about 4 seconds later iq.exe is launched, forming a "system binary proxy execution" chain.

> **Evidence**: TargetFilename=C:\ProgramData\SystemData\30d4fdf211293635\launch.hta (created by PID 3788); CommandLine=C:\Windows\System32\mshta.exe "C:\ProgramData\SystemData\30d4fdf211293635\launch.hta"; then Image=...\iq.exe
> 
> **Source**: `ref:1080dc8621` · `ref:a54cbd8afd`

### 5. Create a global mutex

`T1480` · Confidence **high** · static

It calls CreateMutexA to create the global named mutex 'Global\A0e5e656d338bd7cc', used for single-instance control / avoiding duplicate infection.

> **Evidence**: CreateMutexA(0,0,"Global\\A0e5e656d338bd7cc") @pc 0x57298b
> 
> **Source**: `ref:ae43a88804` · `ref:658c65a205`

### 6. Patch AMSI to bypass detection

`T1562.001` · Confidence **medium** · dynamic

After the copy process loads the CLR, the code sections of amsi.dll and clr.dll are modified in place (1 and 12 patches respectively), consistent with evasion that disables AMSI scanning before execution.

> **Evidence**: Memory scan PID 2512: is_managed=1; modified.patched=2; amsi.dll patches=1, clr.dll patches=12
> 
> **Source**: `ref:c7c855843d`

### 7. TLS callback to C2

`T1573.002` · Confidence **high** · dynamic

iq.exe (PID 2512) repeatedly initiates TCP connections to the external address 45.192.214[.]54:56001 and polls 127.0.0[.]1:56001/56002/56003 as fallbacks; the payload contains SslStream/AuthenticateAsClient/RemoteCertificateValidationCallback and an embedded certificate, and the channel is TLS-encrypted.

> **Evidence**: Network redirect log: iq.exe (2512) requested TCP 45.192.214[.]54:56001 (multiple times, about 11s apart), 127.0.0[.]1:56001/56002/56003; payload #US contains 'SslStream', 'AuthenticateAsClient', 'RemoteCertificateValidationCallback'
> 
> **Source**: `ref:392a05ad89` · `ref:a3cb256ec1` · `ref:987477424f`

### 8. Steal browser wallet data

`T1555.003` · Confidence **high** · static

The stealer module enumerates the User Data directories and Local Storage\leveldb of browsers such as Chrome/Edge/Brave/QQBrowser/Vivaldi/Orbitum, and locates 40+ cryptocurrency wallet extensions (MetaMask, Phantom, Trust Wallet, Coinbase Wallet, Keplr, Ronin, Math Wallet, TronLink, etc.), while also targeting wallet and messaging data such as Telegram Desktop, Foxmail, Electrum/Exodus/Atomic.

> **Evidence**: payload #US: 'Google\Chrome\User Data\', 'Local Storage', 'leveldb', 'nkbihfbeogaeaoehlefnkodbefgpgknn'(MetaMask), 'bfnaelmomeimhlpmgjnjophhpkkoljpa'(Phantom), 'fnjhmkhhmkbjkkabndcnnogagogbneec'(Ronin), 'Telegram Desktop', 'Foxmail', 'Electrum', 'Exodus', 'Atomic Wallet'
> 
> **Source**: `ref:987477424f`

### 9. Enumerate AV products and fingerprints

`T1518.001` · Confidence **high** · static

It uses WMI to query root\SecurityCenter2 with 'SELECT * FROM AntiVirusProduct', the serial numbers of Win32_Processor/Win32_DiskDrive/Win32_PhysicalMemory and the OS version, and enumerates camera-class PnP devices, for host fingerprinting and victim-surface determination.

> **Evidence**: payload #US: 'root\SecurityCenter2', 'SELECT * FROM AntiVirusProduct', 'Win32_Processor', 'Win32_DiskDrive', 'SerialNumber', 'SELECT Caption FROM Win32_OperatingSystem', 'SELECT * FROM Win32_PnPEntity WHERE (PNPClass = \'Image\' OR PNPClass = \'Camera\')'
> 
> **Source**: `ref:987477424f`

### 10. Register a scheduled task

`T1053.005` · Confidence **medium** · static

The payload embeds a PowerShell persistence script: Register-ScheduledTask -TaskName '<name>', with a 5-minute repetition interval and RunLevel Highest, delivered via powershell.exe -NoProfile -ExecutionPolicy Bypass -Enc <gzip+base64>.

> **Evidence**: payload #US: "Register-ScheduledTask -TaskName '" ... "-RepetitionInterval (New-TimeSpan -Minutes 5))", "-NoProfile -ExecutionPolicy Bypass -Enc " and the immediately following H4sIA... base64(gzip) data block
> 
> **Source**: `ref:987477424f`

### 11. Take screenshots and record windows

`T1113` · Confidence **high** · static

It captures the screen using CopyFromScreen/primary-screen size/JPEG encoding parameters, and combines GetForegroundWindow/GetWindowText/GetLastInputInfo to collect the foreground window title and idle time.

> **Evidence**: payload #Strings/#US: 'CopyFromScreen', 'get_PrimaryScreen', 'ImageCodecInfo', 'image/jpeg', 'Quality', 'GetForegroundWindow', 'GetWindowText', 'GetLastInputInfo'
> 
> **Source**: `ref:987477424f`

### 12. Dynamically resolve APIs for injection

`T1055` · Confidence **medium** · static

The stealer module loads code from the embedded 'inner.dll' resource and uses GetDelegateForFunctionPointer to resolve kernel32 functions at runtime (the strings are split into 'Virtual '+'Alloc', 'Write '+'Process '+'Memory', 'Open '+'Process', 'kernel '+'32.dll'); together with the host's imported WriteProcessMemory/FlushInstructionCache, it has the capability to inject into other processes.

> **Evidence**: payload #Strings contains 'inner.dll', 'GetDelegateForFunctionPointer', 'GetProcAddress', 'LoadLibrary'; #US contains the split forms 'Virtual ', 'Alloc', 'Write ', 'Process ', 'Memory', 'Open ', 'Process', 'kernel ', '32.dll'; the host imports WriteProcessMemory(rva 0x232666C), FlushInstructionCache(0x2326670)
> 
> **Source**: `ref:987477424f` · `ref:01c248de91` · `ref:a221a5fea7`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (multiple retries within a short period).
:::

:::caution
**The real server side remains unverified**: the above connections/handshakes were completed with a locally controlled emulation service, and the real C2's responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `45[.]192[.]214[.]54` | 56001 | c2 | dynamic | observed |
| tcp | `127[.]0[.]0[.]1` | 56001 | fallback | static | ⏳ not observed |

### Host

**Mutexes**

- `Global\A0e5e656d338bd7cc`

**Dropped paths**

- `%ProgramData%\SystemData\30d4fdf211293635\iq.exe`
- `%ProgramData%\SystemData\30d4fdf211293635\launch.hta`
- `%APPDATA%`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `45.192.214[.]54; 127.0.0[.]1` | yes | static |
| `c2_port` | `56001, 56002, 56003` | yes | static |
| `tls_certificate` | `embedded 3220-byte base64 X.509 certificate, used for SslStream server certificate pinning` | yes | dynamic |
| `campaign_id` | `Default` | no | dynamic |
| `install_root_env` | `APPDATA` | no | dynamic |
| `config_serialization` | `protobuf (protobuf-net)` | no | static |
| `encryption_algo` | `loader-embedded payload: TripleDES/CBC + GZip; stealer module: AES/Rijndael + SHA1/MD5 + RSA` | yes | static |
| `mutex` | `Global\A0e5e656d338bd7cc` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- Do not call it ransomware: the sample does not bulk-encrypt user files or drop ransom notes; the TripleDES/AES in the code is used only for payload protection and C2 communication.
- Do not claim a C2 session was successfully established or check-in confirmed: only connection attempts were observed, the emulated network environment has no request/response records for the corresponding port, and C2 availability is unverified.
- Do not claim the sample wrote registry autostart entries or created services: host telemetry shows no additions to the Run keys or the service list before and after this run, and persistence is only seen as a "scheduled task" capability string.
- Do not call its digital signature valid or trusted: the signature comes from an old certificate issued to Take-Two/Rockstar in 2011–2013, and about 2.4MB of data is appended after the certificate table, which the signature does not cover.
- Do not conclude injection occurred solely from the WriteProcessMemory import: that import appears in the host loader, and actual injection behavior was not dynamically confirmed.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `fe3cce3b0f338aa00c8c38f0e949f212269b42fef798d554eb3ce4d8677d955e`) |

**Limitations and open questions**

1. Only connection attempts to the C2 were seen (45.192.214[.]54:56001 and loopback 56001-56003), and there is no corresponding listener/session in the emulated network environment, so the C2 entry is marked static + pending_dynamic_verify; the end-to-end protocol and check-in credentials are unconfirmed.
2. The text content of launch.hta was not captured (the write occurred after the memory dump); its specific command behavior is inferred from the file-creation and mshta launch events.
3. The global mutex name comes from the decryption/emulation path rather than real runtime observation and is treated as statically recovered.
4. The payload's .NET module is obfuscated with Eazfuscator, so class/method names are unreadable; behavior determinations are based on retained string constants (wallet extension IDs, browser paths, WMI queries, PowerShell commands), and their execution was not dynamically verified item by item.
5. Capabilities such as scheduled-task persistence, screenshots and injection are inferred only from payload strings and the import table, and no corresponding side effects were observed in this run (no new scheduled task, no injection observed).
6. The exact family of the delivered .NET stealer module could not be confirmed; the family field uses the loader candidate name and is marked uncertain.
7. The 2,555,904 bytes of high-entropy data after the certificate at the end of the on-disk file were not decrypted offline (the loader reads its own file and decrypts in memory); its content is based on the in-memory extract.
8. Limited by the sandbox duration, the process ran for only about 4 minutes before being terminated, so long-term persistence/multi-stage download behavior may not have unfolded.

## Evidence index

<details>
<summary>Show 21 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:bf011593b4` | Sample triage | Hash/imphash/section entropy/import statistics: sha256 matches the task, .rdata entropy 7.999, only 3 imported DLLs and 39 symbols, no exports |
| `ref:d854d3212c` | PE structure parsing | PE structure: I386, GUI, EP=0x11B0, 5 sections, SECURITY directory RVA 0x322C00 size 3488, ImageBase 0x400000 |
| `ref:01c248de91` | Import table parsing | Import table: kernel32(36)/advapi32(2)/shell32(1), including CreateFileW/ReadFile/GetFileSizeEx/WriteProcessMemory/ShellExecuteW |
| `ref:cf00150776` | raw-string-scan(script) | Overlay strings: VeriSign Class 3 Code Signing 2010 CA, Take-Two Interactive Software, Inc., Rockstar Games |
| `ref:4f95768d62` | raw-bytes(script) | File tail: after the certificate table ends at 0x3239A0, contiguous high-entropy data continues to EOF, overlay about 2,555,904 bytes |
| `ref:983a14d2b8` | unpack.antidebug | Static anti-debugging features: rdtsc timing delta (0x11D4), int 2Dh (0x7250D), cpuid probe (0x6E9E9) |
| `ref:ae43a88804` | dyn.run | Emulation behavior: CreateMutexA('Global\A0e5e656d338bd7cc'), step-by-step CreateDirectoryW to C:\ProgramData\SystemData\30d4fdf211293635, GetFileAttributesW checking iq.exe, creation of 4 threads |
| `ref:bf479ed570` | Dynamic analysis platform | Real detonation in an isolated environment: rollback → drop → polling → memory dump → teardown, producing a timeline, module dumps and network logs |
| `ref:14062fd62d` | watch-timeline | Timeline: candidate process PID 3788 (the sample itself); 6 memory dumps (t0/t3), no hollows hits |
| `ref:c7c855843d` | memory-scan-report | PID 2512 = C:\ProgramData\SystemData\30d4fdf211293635\iq.exe, is_managed=1; code patches: amsi.dll 1, clr.dll 12 |
| `ref:1080dc8621` | host-telemetry | Events: PID 3788 creates ...\iq.exe and ...\launch.hta; mshta.exe executes launch.hta; then iq.exe starts |
| `ref:a54cbd8afd` | host-telemetry | Full set of host process/file events: confirms the mshta.exe command line points to launch.hta and the PID 2512 command line points to iq.exe |
| `ref:392a05ad89` | network-redirect-log | iq.exe (2512) repeatedly requests TCP 45.192.214[.]54:56001 and polls 127.0.0[.]1:56001/56002/56003 |
| `ref:a3cb256ec1` | protobuf-decode(script) | In-memory protobuf configuration: hosts=127.0.0[.]1/45.192.214[.]54, ports=56001/56002/56003, 3220-byte base64 certificate, campaign='Default', install_env='APPDATA' |
| `ref:a221a5fea7` | dotnet-metadata(script) | In-memory loader assembly metadata: #Strings/#US contain PCLoader, Loader.exe, PayloadSource.zip, protobuf-net.dll, TripleDES, GZipStream, CreateDecryptor and key/IV constants |
| `ref:987477424f` | dotnet-metadata(script) | In-memory stealer module metadata: #Strings 763 entries (GClass/smethod obfuscation, inner.dll, SslStream, GetDelegateForFunctionPointer), #US 257 entries (wallet extension IDs, browser directories, WMI queries, scheduled-task PowerShell, screenshot APIs) |
| `ref:1d808b01f5` | memory-strings(script) | In-memory context: the path 'C:\ProgramData\SystemData\30d4fdf211293635\iq.exe' and the '127.0.0[.]1'/'45.192.214[.]54' configuration appear adjacent |
| `ref:5c51656586` | carve-hash(script) | In-memory extract hashes: Loader.exe 7d46e86c…, stealer module fe3cce3b…, protobuf-net.dll b2a66e98… |
| `c2_evidence:40553ae7` | Connection evidence extraction | Dynamic network monitoring recorded 21 connection attempts to 45.192.214[.]54:56001; no complete session was captured |
| `telemetry:40553ae7` | Dynamic telemetry | Dynamic telemetry recorded: 113 process/file events from the monitoring component; 1 ETW short-lived process event; 27 filtered tool/system noise entries |
| `etw:40553ae7:3788` | Process event monitoring | Short-lived process event: 40553ae76fe40e685da891af1eb2f51989a6044e4dc547f5cba9499a2b2ff6b0.exe (pid 3788; MD5=0E6E40FE43DBEFCCFFE3369404D6BBA3,SHA256=40553AE76FE40E685DA891AF1EB2F51989A6044E4DC547F5CBA9499A2B2FF6B0,IMPHASH=E0B25321278E667FDD841600D9F41DCE) |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
