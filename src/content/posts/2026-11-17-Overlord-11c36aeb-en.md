---
title: "Malware sample analysis: Overlord (PE · exe · 11c36aeb)"
published: 2026-11-17
draft: false
description: "Malicious (confidence high): Overlord · rat/backdoor/dropper · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Overlord", "rat", "backdoor", "dropper", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-17-Overlord-11c36aeb"
---

> [!WARNING]
> **Verdict: malicious** · family **Overlord** (uncertain) · confidence **high**
> 
> Aliases: overlord-client, Overlord Agent, Overlord RAT
> 
> During real dynamic execution, the parent process was observed dropping and launching a second executable under %TEMP%, and that child process then initiated a WebSocket connection to 13[.]49[.]245[.]161:5173; its memory image contains the Go build information overlord-client/cmd/agent and strings for a complete remote-control capability set including keylogging, clipboard, screen/camera capture, remote console, file transfer, process manipulation and kernel display driver installation, making it a typical two-stage remote access trojan.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Overlord** · aliases overlord-client, Overlord Agent, Overlord RAT · _uncertain_ |
| Confidence | **High** |
| Behavior class | rat · backdoor · dropper |
| Difficulty | medium |
| First seen | 2026-11-16 07:38:09 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/11c36aeb45abc189e341d22bc1490c07f7e97866f4dc45bce51fd99dfaeaafeb/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Fake installer and signature</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Embedded encrypted payload</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Drop and execute temp copy</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">WebSocket callback</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Log keystrokes</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `11c36aeb45abc189e341d22bc1490c07f7e97866f4dc45bce51fd99dfaeaafeb` |
| MD5 | _not recorded_ |
| Size | 9,714,376 bytes (9.3 MB) |
| Type | PE · `exe` |

## Behavior analysis

There are **12** behaviors in total, each backed by evidence; **10** are statically obtainable and **2** were obtained through dynamic analysis.

### 1. Fake installer package and signature

`T1036.001` · confidence **high** · static

The PE version information is forged as Ironwood Technologies' Ironwood Setup / Ironwood Suite 1.0.13[.]0, and it carries a code-signing certificate whose subject is Blue Oak Systems; the two are inconsistent, used to impersonate a legitimate installer.

> **Evidence**: resource section VS_VERSION_INFO strings Ironwood Setup / Setup_9a33ad34.exe (off 0xE2E0) and the certificate string Blue Oak Systems in the signature area; SECURITY directory at end of file rva 9712640(0x943400)
> 
> **Source**: `ev-000016` · `ref:7383b0de3d` · `ref:a3f245333d`

### 2. Embedded encrypted payload

`T1027.009` · confidence **high** · static

The image contains 4 data sections with entropy 8.0 (.data$1–.data$4, about 9.3MB in total); the main program addresses them using the FNV-1a constant 0xcbf29ce484222325 and decrypts the buffer with a rolling-key XOR loop, then decompresses with zlib 1.3.1, forming the unpacking routine for the next-stage payload.

> **Evidence**: section table .data$1 rva 0x6f000/size 0x269000, .data$2 rva 0x2d8000, .data$3 rva 0x485000, .data$4 rva 0x73f000; entry jmp 0x14000a980->0x140008280; from 0x1400083c0 an xor decryption loop, calls 0x14000a380/0x14000a420/0x14000a7e0; .rdata contains inflate 1.3.1 and 0123456789abcdef
> 
> **Source**: `ev-000011` · `ev-000012` · `ev-000013` · `ev-000014` · `ref:65b5415c8b` · `ev-000016`

### 3. Drop and execute a temporary copy

`T1106` · confidence **high** · dynamic

The parent process (the fake installer) writes an executable named with ten hexadecimal digits, d9c8e700d9.exe, into %TEMP% and creates a child process to run from that path; the child's hash differs from the parent sample, indicating that what is dropped is a decrypted standalone payload rather than a copy of the original file.

> **Evidence**: process audit: PID 5484 creates C:\Users\analyst\AppData\Local\Temp\d9c8e700d9.exe and starts PID 7812; child SHA256 a7455c544aad7000f768d855fe2de64d0e91bae41f9b9ab0f0b0717566277377
> 
> **Source**: `ref:32c989ce1a` · `ref:f753d0c7a3` · `ref:5f1262dc2e`

### 4. WebSocket callback

`T1071.001` · confidence **high** · dynamic

After running, the child process initiates a WebSocket (wss) connection to port 5173/TCP on 13[.]49[.]245[.]161; two endpoints, wss://13.49.245[.]161:5173 and wss://127.0.0[.]1:5173, are present in memory, and requests carry an x-agent-token authentication header; three reconnections were observed during the observation window (about 45–75 seconds apart), with no application-layer response received.

> **Evidence**: network monitoring at 01:51:19 / 01:52:33 / 01:53:47 records d9c8e700d9.exe(7812) -> 13.49.245[.]161:5173; memory strings wss://13.49.245[.]161:5173, 13.49.245[.]161:5173, x-agent-token
> 
> **Source**: `ref:1f23b0e88d` · `ref:e12e86a0b1` · `ref:6e74733082` · `ref:5f1262dc2e`

### 5. Log keystrokes

`T1056.001` · confidence **medium** · static

A built-in keylogger module uses GetAsyncKeyState / GetKeyboardState and a message window to capture keystrokes, supports remotely issuing keylog_delete to clear the log, and converts keys into readable text for exfiltration.

> **Evidence**: memory strings keylog_delete, GetAsyncKeyState, GetKeyboardState, and a key-name table such as [LEFT WIN]/[TAB]/[ESC]/[CTRL]; code path overlord-client/cmd/agent
> 
> **Source**: `ref:6e74733082` · `ref:0d7ff793cc`

### 6. Read and write the system clipboard

`T1115` · confidence **medium** · static

Provides clipboard_get / clipboard_set commands, calling OpenClipboard / GetClipboardData / SetClipboardData to read or write the victim's clipboard contents, which can be used to steal passwords or replace content.

> **Evidence**: memory strings clipboard_get, clipboard_set, SetClipboardData, OpenClipboard, GetClipboardData
> 
> **Source**: `ref:6e74733082` · `ref:0d7ff793cc`

### 7. Capture screen and camera

`T1113` · confidence **medium** · static

Captures the screen via DXGI/GDI and the screenshot library and pushes the desktop image over a WebRTC channel (backstage stream / backstage capture), and supports camera enumeration, frame-rate setting and audio capture (malgo/MFTEnumEx), which can be started or stopped remotely.

> **Evidence**: memory strings backstage capture: stream display=%d fps, webcam_start/webcam_select/webcam_set_fps, dxgi factory, gdi blt: createDIBSection, MFTEnumEx, webrtc_publish/webrtc_p2p_ice
> 
> **Source**: `ref:e12e86a0b1` · `ref:0d7ff793cc`

### 8. Remote console execution

`T1059` · confidence **medium** · static

A built-in pseudo-terminal/command console (console_start / console_input / console_output) can execute commands and scripts remotely and invokes PowerShell with -ExecutionPolicy Bypass, returning script_result / command_result.

> **Evidence**: memory strings console_start/console_input/console_output/console_resize, conpty(UserExistsError/conpty v0.1.4), -ExecutionPolicy, wscript.exe, script_result, command_result
> 
> **Source**: `ref:6e74733082` · `ref:0d7ff793cc` · `ref:e12e86a0b1`

### 9. File upload, download and execution

`T1105` · confidence **medium** · static

Supports commands such as file_download / file_execute / file_dirsize, transfers files in msgpack chunks, lists directories and directly executes downloaded files on the victim host (including RDI reflective loading parameters).

> **Evidence**: memory strings file_download, file_execute: %s, file_dirsize: %s, chunk/transferId/maxResults, RDI_SEARCH_PATH/RDI_DLL_SECTION/RDI_REPLACE_PATH
> 
> **Source**: `ref:e12e86a0b1` · `ref:6e74733082` · `ref:0d7ff793cc`

### 10. Enumerate and terminate processes

`T1057` · confidence **medium** · static

Has process listing, suspend/resume and termination capabilities (process_list / process_kill, NtSuspendProcess / NtResumeProcess), and attempts to obtain SeDebugPrivilege to operate on higher-privilege processes.

> **Evidence**: memory strings process_list, process_kill: %d, NtSuspendProcess, NtResumeProcess, SeDebugPrivilege
> 
> **Source**: `ref:6e74733082` · `ref:0d7ff793cc`

### 11. Install a virtual display driver

`T1543.003` · confidence **medium** · static

Can download driver.zip and call the SetupDi* family of interfaces to install the Virtual-Display-Driver indirect display driver (/add-driver), used to maintain a remote desktop image on hosts without a physical monitor; it also uses the GitHub releases API as a proxy self-update source.

> **Evidence**: memory strings driver.zip, /add-driver, SetupDiCreateDeviceInfoW/SetupDiSetSelectedDevice/SetupDiCallClassInstaller, no virtual monitor adapter found, hxxps://api[.]github[.]com/repos/VirtualDrivers/Virtual-Display-Driver/releases/latest, agent_update[win]
> 
> **Source**: `ref:e12e86a0b1` · `ref:0d7ff793cc`

### 12. Reflectively load plugins

`T1620` · confidence **medium** · static

Plugin modules can be delivered over HTTP and mapped into the process via reflective loading (RDI_*), without touching disk; together with the accompanying plugin load / plugin_event / plugin_unload commands, this is an in-memory code loading capability.

> **Evidence**: memory strings plugin load http, plugin_event, plugin_unload, RDI_SEARCH_PATH, RDI_DLL_SECTION, RDI_REPLACE_PATH, reflective, [plugin] loaded %s
> 
> **Source**: `ref:0d7ff793cc` · `ref:6e74733082`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (multiple retries within a short period).
:::

:::caution
**Real server side still unverified**: the above connections/handshakes were completed against a local controlled emulation service; the real C2's response and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| other | `wss://13[.]49[.]245[.]161:5173` | 5173 | c2 | dynamic | Observed |

### Host

**Mutex**

- `Global\Overlord`

**Drop paths**

- `%TEMP%\d9c8e700d9.exe`
- `<agent_dir>\config\settings.json`
- `<agent_dir>\config\server_index.json`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `13[.]49[.]245[.]161` | yes | static |
| `c2_port` | `5173` | yes | static |
| `c2_scheme` | `wss` | yes | static |
| `auth_header` | `x-agent-token` | yes | static |
| `protocol` | `msgpack over websocket (nhooyr[.]io/websocket v1.8.10)` | yes | static |
| `mutex` | `Global\Overlord` | yes | static |
| `config_files` | `config/settings.json; config/server_index.json` | no | static |
| `drop_path` | `%TEMP%\<10-hex>.exe` | yes | dynamic |
| `update_source` | `hxxps://api[.]github[.]com/repos/VirtualDrivers/Virtual-Display-Driver/releases/latest` | no | static |
| `module_path` | `overlord-client/cmd/agent` | no | static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not claim a C2 session was established or that the bot successfully came online: network monitoring recorded only three TCP connection attempts to 13[.]49[.]245[.]161:5173, with no application-layer request/response or session record.
- Do not judge the high-entropy data of .data$1–.data$4 as ransomware-encrypted files: they are embedded next-stage payloads, and no file encryption or ransomware behavior was observed this time.
- Do not claim the sample wrote Run keys, the startup folder or installed services: the related strings only prove the capability exists, and this telemetry showed no persistence writes.
- Do not treat the sample as a legitimate installer: the signature subject (Blue Oak Systems) and the version information (Ironwood Technologies) are inconsistent, and the actual behavior is dropping a remote-control agent.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. Only TCP connection attempts were observed for the C2, with no application-layer session/response; the address comes from runtime memory and network targets and is stored encrypted in the static file, so the C2 record is marked static + pending_dynamic_verify.
2. No persistence behavior was observed (no events for Run keys, the startup folder or service installation); the corresponding strings exist in the code and would require longer residency and reboot observation to confirm.
3. Functions such as keylogging, clipboard, screen/camera, remote console, file transfer, process manipulation, driver installation and plugin loading are triggered only when the controller delivers commands; this assessment is based solely on command strings and dependency libraries in the child process memory, without item-by-item dynamic reproduction, so confidence is medium.
4. No decrypted stage2 file suitable for direct static analysis could be produced; second-stage information comes from the child process memory image and the process audit hashes.
5. System security components generated no alert events, which only indicates this run was not blocked and does not affect the malicious verdict.

## Evidence index

<details>
<summary>Expand 20 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprinting | Sample SHA256/MD5/SHA1 and size 9,714,376 bytes |
| `ev-000011` | scan.entropy | .data$1 entropy 8.0, 2,527,232 bytes |
| `ev-000012` | scan.entropy | .data$2 entropy 8.0, 1,757,184 bytes |
| `ev-000013` | scan.entropy | .data$3 entropy 8.0, 2,859,008 bytes |
| `ev-000014` | scan.entropy | .data$4 entropy 8.0, 2,139,092 bytes |
| `ev-000016` | String extraction | Resource section forged version information Ironwood Setup / Setup_9a33ad34.exe and zlib inflate 1.3.1 strings |
| `ref:a3f245333d` | PE structure parsing | 12 sections, SECURITY directory at end of file (1,736 bytes), entry RVA 0xA980 |
| `ref:7040091307` | Import table parsing | Imports only three symbols: GetModuleHandleW/Sleep/MessageBoxW |
| `ref:65b5415c8b` | disasm.function | FNV-1a constant and rolling XOR decryption loop from 0x8280 |
| `ref:7383b0de3d` | script | Signing certificate subject Blue Oak Systems(Installer), valid 2026-11-13 to 2027-12-18 |
| `ref:32c989ce1a` | script | Process audit records parent process 5484 creating and starting %TEMP%\d9c8e700d9.exe(7812) and its hash |
| `ref:1f23b0e88d` | script | Network monitoring records 7812 connecting three times to 13.49.245[.]161:5173 |
| `ref:e12e86a0b1` | script | Child process memory image extraction of wss://13.49.245[.]161:5173 and remote-control capability strings |
| `ref:6e74733082` | script | Memory strings Global\Overlord, x-agent-token, keylog/clipboard/desktop/webcam commands |
| `ref:570172a674` | script | Go build info path=overlord-client/cmd/agent, mod=overlord-client |
| `ref:0d7ff793cc` | script | Memory strings config/settings.json, driver.zip, /add-driver, RDI_* etc. |
| `c2_evidence:11c36aeb` | Connection evidence extraction | Dynamic network monitoring recorded 4 connection attempts to 13.49.245[.]161:5173; no complete session captured |
| `telemetry:11c36aeb` | Dynamic telemetry | Dynamic telemetry recorded: 103 process/file events from the monitoring component; 2 ETW short-lived process events; 27 tool/system noise items filtered |
| `etw:11c36aeb:5484` | Process event monitoring | Short-lived process event: 11c36aeb45abc189e341d22bc1490c07f7e97866f4dc45bce51fd99dfaeaafeb.exe (pid 5484; MD5=08D20B0891B248D0AD0687C931542097,SHA256=11C36AEB45ABC189E341D22BC1490C07F7E97866F4DC45BCE51FD99DFAEAAFEB,IMPHASH=0AE6AD12FF19E0707BF0CE97CFEB8F45) |
| `etw:11c36aeb:7812` | Process event monitoring | Short-lived process event: d9c8e700d9.exe (pid 7812; MD5=CE7D304CB06CAB4AD53D626262BB1183,SHA256=A7455C544AAD7000F768D855FE2DE64D0E91BAE41F9B9AB0F0B0717566277377,IMPHASH=8322AF7713E010D39E373D3A5F031D51) |

</details>

---

_The sample in this report is not public; IOCs have been defanged, for security research only._
