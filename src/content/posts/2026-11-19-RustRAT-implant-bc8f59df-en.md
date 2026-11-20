---
title: "Malware Analysis: RustRAT-implant (PE · exe · bc8f59df)"
published: 2026-11-19
draft: false
description: "Malicious (medium confidence): RustRAT-implant · rat/backdoor/stealer · difficulty medium · dynamic sandbox + static decompilation"
tags: ["RustRAT", "rat", "backdoor", "stealer", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-19-RustRAT-implant-bc8f59df"
---

> [!WARNING]
> **Verdict: Malicious** · Family **RustRAT-implant** (uncertain) · Confidence **medium**
> 
> Aliases: Rust implant RAT, WindowsHelper RAT
> 
> The sample is a remote-access trojan written in Rust (source paths implant\src\*.rs). Static analysis shows a complete remote-control command dispatcher (shell, keylog, dump cookies, screenshot, download/upload, persist, elevate, sleep, exit) with the corresponding implementation dependencies (GetAsyncKeyState, BitBlt/GetDIBits, CryptUnprotectData, rusqlite reading browser Login Data/Cookies, WSASocket/connect). In the dynamic sandbox, after running, the sample copies itself into the user's startup folder Startup\WindowsHelper.exe (file creation event) and repeatedly dials back over TCP to 144.172.111[.]127:20222 every 5 seconds, sending a 4-byte length prefix plus an AES-encrypted payload each time, which is a typical encrypted-channel RAT callback.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **RustRAT-implant** · aliases Rust implant RAT, WindowsHelper RAT · _uncertain_ |
| Confidence | **Medium** |
| Behavior class | rat · backdoor · stealer |
| Difficulty | medium |
| First seen | 2026-11-17 00:42:01 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/bc8f59df0718ef65a5f5a828161572d17b447ebbb5760cd3a977da0a196ca77f/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Self-copy into Startup</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.001</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Encrypted C2 callback</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1573.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Built-in RAT command set</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Steal browser credentials</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Keylogging</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `bc8f59df0718ef65a5f5a828161572d17b447ebbb5760cd3a977da0a196ca77f` |
| MD5 | _not recorded_ |
| Size | 1,740,288 bytes (1.7 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**11** behaviors in total, each backed by evidence; **9** are statically available and **2** were obtained through dynamic analysis.

### 1. Self-copy into Startup

`T1547.001` · Confidence **High** · Dynamic

About 3 seconds after process start, it writes a copy of itself into the current user's Startup folder with the filename WindowsHelper.exe (host telemetry file creation event, source PID 1516), gaining logon autostart capability.

> **Evidence**: dynamic event: File created TargetFilename=C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsHelper.exe, ProcessId=1516, RuleName=T1023
> 
> **Source**: `ref:9a21e3cfa3` · `ref:43676d5143`

### 2. Encrypted C2 callback

`T1573.001` · Confidence **High** · Dynamic

Connects over raw TCP to 144.172.111[.]127:20222 and retries about every 5 seconds after connection refused/no response; each frame starts with a 4-byte big-endian length 0x69 followed by an AES-encrypted payload.

> **Evidence**: network monitoring: bc8f59...exe (1516) requested TCP 144.172.111[.]127:20222 5 times in total; each RawTCP session had the length prefix 00 00 00 69
> 
> **Source**: `ref:b55628f4a0` · `ref:9bc1f14731`

### 3. Built-in RAT command set

`T1105` · Confidence **High** · Static

The binary contains a complete server-side command set: Shell, Keylog(Start/Stop/Dump), Screenshot, Download, Upload, Sleep, Mouse, SysInfo, Procs, ListDir, Urls, Persist, Elevate, Exit, with corresponding ServerMessage variants and the command strings sysinfo/procs/ls/urls/programs/exts/pw/cookies/shot/persist/keylog/ctl.

> **Evidence**: string clusters at 0x152170 and 0x151568: 'sysinfoprocslsurlsprogramsextspwcookies', 'struct variant ServerMessage::Download/Upload/Sleep'
> 
> **Source**: `ref:d2198238b5`

### 4. Steal browser credentials

`T1555.003` · Confidence **High** · Static

Uses rusqlite to open the Chrome/Edge Login Data and Cookies databases, executes SELECT origin_url, username_value, password_value FROM logins and SELECT host_key, name, encrypted_value FROM cookies, and uses CryptUnprotectData to decrypt the DPAPI-protected password/Cookie values.

> **Evidence**: string 0x153455 'SELECT host_key, name, encrypted_value FROM cookies'; 0x1524xx 'GoogleUser DataLogin DataSELECT origin_url, username_value, password_value FROM logins'; imports crypt32!CryptUnprotectData
> 
> **Source**: `ref:d2198238b5` · `ref:cbb590aa19`

### 5. Keylogging

`T1056.001` · Confidence **High** · Static

Polls GetAsyncKeyState and records keystrokes against a VK mapping table, supporting keylog start/stop/dump commands to send the records back; the key table includes shift symbols such as ')!@#$%^&*('.

> **Evidence**: imports user32!GetAsyncKeyState; strings 0x15217e 'keylogger iniciado ... keylog ctl keylogger parado keylog(vazio)'; 0x1536e7 ')!@#$%^&*(' and implant\src\keylogger.rs
> 
> **Source**: `ref:cbb590aa19` · `ref:d2198238b5`

### 6. Screen capture

`T1113` · Confidence **High** · Static

Captures the desktop bitmap via GetDC/BitBlt/CreateCompatibleBitmap/GetDIBits, encodes it with the png crate and returns it in Screenshot/ScreenshotStream messages.

> **Evidence**: imports gdi32!BitBlt/GetDIBits, user32!GetDC; strings 0x152fba 'falha ao capturar tela implant\src\screenshot.rs', 'ScreenshotStream'
> 
> **Source**: `ref:cbb590aa19` · `ref:d2198238b5`

### 7. Remote command execution

`T1059.003` · Confidence **High** · Static

Uses cmd.exe /e:ON /v:OFF /d /c to execute commands issued by the server side (Shell message) and returns stdout/stderr; the implementation uses CreateProcessW + named pipes/asynchronous IO to read the output.

> **Evidence**: strings 'cmd.exe /e:ON /v:OFF /d /c' and '\\cmd.exe\\'; imports CreateProcessW, NtCreateNamedPipeFile, NtReadFile/NtWriteFile; 'struct variant ServerMessage::Shell'
> 
> **Source**: `ref:d2198238b5` · `ref:cbb590aa19`

### 8. Masquerade as Microsoft component

`T1036.005` · Confidence **High** · Static

Resource version information masquerades as Microsoft Corporation's 'Assistente do Windows', with OriginalFilename WindowsHelper.exe, and the dropped filename likewise uses WindowsHelper.exe to reduce suspicion from users and manual investigation.

> **Evidence**: version resource 0x1a4736: CompanyName=Microsoft Corporation, FileDescription=Assistente do Windows, OriginalFilename=WindowsHelper.exe; dynamic process attributes are consistent
> 
> **Source**: `ref:d2198238b5` · `ref:9a21e3cfa3`

### 9. Mimic UAC elevation flow

`T1548.002` · Confidence **Medium** · Static

Contains a built-in Elevate command and the Portuguese message 'prompt UAC enviado a vitima, aguarde aceitar', which can pop a UAC prompt to the victim to request administrator privileges and, once accepted, continue running with high privileges.

> **Evidence**: strings 0x153c11 'persistencia instalada (Run key)', 0x153c1f 'falha ao pedir elevacao', 0x153c31 'elevate', 'prompt UAC enviado a vitima, aguarde aceitar'
> 
> **Source**: `ref:d2198238b5`

### 10. Encrypted embedded data

`T1027` · Confidence **Medium** · Static

A 2048-byte high-entropy overlay with a full byte distribution sits at the end of the file, and .text repeatedly uses VirtualProtect to switch the .fptable section between read-only and writable for decryption table lookups, indicating a custom data structure decrypted at runtime; the configuration does not appear in plaintext.

> **Evidence**: overlay 0x1a8600-0x1a8e00 (2048 bytes, 256 distinct byte values); rva 0x145210: VirtualProtect(0x1a9000, 0x100, PAGE_READONLY)
> 
> **Source**: `ref:f038d6102d` · `ref:9bc1f14731`

### 11. Collect host and process information

`T1082` · Confidence **High** · Static

Responds to SysInfo/Procs commands, collecting hostname, username, admin flag, OS version, CPU cores/architecture, memory, disks and process list (CreateToolhelp32Snapshot/Process32FirstW) to form the check-in handshake data.

> **Evidence**: string 0x151568 'hostnameusernameis_adminos_versioncpu_corescpu_archram_total_mbram_used_mbuptime_secsdisk_total_gbdisk_free_gbpidppidthreadsnameis_dirsizeurltitle'; imports CreateToolhelp32Snapshot/Process32FirstW/Process32NextW
> 
> **Source**: `ref:d2198238b5` · `ref:cbb590aa19`


## IOC (Defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (multiple retries within a short time).
:::

:::caution
**The real server side is still unverified**: the above connections/handshakes were completed against a local controlled emulation service, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `144[.]172[.]111[.]127:20222` | 20222 | c2 | Dynamic | Observed |

### Host

**Drop paths**

- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsHelper.exe`
- `%APPDATA%\Microsoft\Start Menu\Startup\WindowsHelper.exe`
- `%APPDATA%\Microsoft\Start Menu\Startup\WindowsHelper.old`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `144[.]172[.]111[.]127` | Yes | Static |
| `c2_port` | `20222` | Yes | Static |
| `protocol` | `raw TCP; each frame has a 4-byte big-endian length prefix + AES-encrypted payload (plaintext is the serde_json structure Hello/{id,ok,is_binary,tag,data})` | Yes | Static |
| `encryption_algo` | `AES (aes-0.8.4 crate; payload entropy is high and each frame's ciphertext differs)` | Yes | Static |
| `install_path` | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsHelper.exe` | No | Dynamic |
| `backup_path` | `%APPDATA%\Microsoft\Start Menu\Startup\WindowsHelper.old` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not conclude that the sample steals LSASS based on comsvcs.dll/MiniDump artifacts: the rundll32 comsvcs MiniDump in the sandbox is a memory dump of the sample process performed by the analysis side; the action belongs to the analysis tool itself, not the sample.
- Do not judge it as ransomware or a wiper: no file encryption, renaming, deletion or shadow-copy deletion was observed, and neither imports nor strings show such capability.
- Do not claim that a C2 session was successfully established or that commands were received: the sandbox observed only connection attempts and one-way report frames; the C2 server did not respond and the session was not completed.
- Do not claim that Run key persistence is confirmed: strings mention the Run key, but telemetry shows the HKCU/HKLM Run values unchanged and no actual write was observed.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The C2 endpoint was observed in the dynamic sandbox only through connection attempts and encrypted report frames; the server never replied, so its true ownership and command capability cannot be confirmed; treat it as unverified (pending_dynamic_verify=true).
2. Run key persistence: the string 'persistencia instalada (Run key)' exists, but the sandbox telemetry's Run keys match the baseline and no specific key/value name was captured, so host_iocs.registry is left empty.
3. The 2048-byte high-entropy overlay and the runtime decryption logic of .fptable did not yield the plaintext configuration/keys, so the C2 parameters cannot be reproduced directly from the static bytes.
4. Limited by the single sandbox run duration and the unresponsive C2, capabilities such as browser credential export, keylogging, screenshots and remote shell have only static code evidence and were not triggered in this dynamic run (they require server-issued commands).
5. The sample is a GUI subsystem without console output; instruction-level emulation only reached Rust runtime initialization and provided no additional behavior evidence.

## Evidence Index

<details>
<summary>Expand 14 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:d83bbbb33b` | Sample triage | Hash/imphash/per-section entropy/packing score; sha256=bc8f59..., packing.score=0, 7 sections, .rsrc entropy 7.112 |
| `ref:a670897612` | PE structure parsing | PE64 GUI, entry rva 0x13b7e8, imports 10 DLLs/213 symbols, 7 sections, 0 exceptions |
| `ref:cbb590aa19` | Import table parsing | Imports GetAsyncKeyState/BitBlt/GetDIBits/CryptUnprotectData/CreateProcessW/WSASocketW/connect/CreateToolhelp32Snapshot etc. |
| `ref:d2198238b5` | String extraction | Hit RAT command strings, browser SQL, implant source paths and masqueraded version resources |
| `ref:f12460618d` | Instruction-level emulation | Instruction-level emulation only executed Rust runtime initialization (36 API calls), no network behavior |
| `ref:9bc1f14731` | Dynamic sandbox | Real sandbox detonation: sample PID 1516 ran, producing a timeline, memory dumps and network monitoring logs; rolled back after completion |
| `ref:b55628f4a0` | Dynamic sandbox/network monitoring | 5 TCP connection attempts to 144.172.111[.]127:20222; RawTCP recorded encrypted frames with the length prefix 00 00 00 69 |
| `ref:9a21e3cfa3` | Dynamic sandbox/host telemetry | Host telemetry file creation and process events: the sample created Startup\WindowsHelper.exe; Run keys match the baseline |
| `ref:f038d6102d` | script | Bytes 0x1a8600-0x1a8e00 at the end of the file are a 2048-byte high-entropy overlay with 256 distinct byte values |
| `ref:65d8b4537d` | disasm.function | rva 0xc900 onward contains serde deserialization and network handling functions, including getaddrinfo calls |
| `ref:19170f44be` | script | Parses UTF-16 strings and version resources (Assistente do Windows / WindowsHelper.exe) |
| `c2_evidence:bc8f59df` | Connection evidence extraction | Dynamic network monitoring recorded 5 connection attempts to 144.172.111[.]127:20222; no complete session captured |
| `telemetry:bc8f59df` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 113; ETW short-lived process events 1; filtered tool/system noise 27 |
| `etw:bc8f59df:1516` | Process event monitoring | Short-lived process event: bc8f59df0718ef65a5f5a828161572d17b447ebbb5760cd3a977da0a196ca77f.exe (pid 1516; MD5=0639DFA49F3D977D587D7AF370F7F0AD,SHA256=BC8F59DF0718EF65A5F5A828161572D17B447EBBB5760CD3A977DA0A196CA77F,IMPHASH=9F55D5D034347970B96EDD3AE7DF91A4) |

</details>

---

_The sample in this report is not public; IOCs have been defanged. For security research only._
