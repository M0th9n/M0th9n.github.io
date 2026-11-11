---
title: "Malware Analysis: Serai RAT (PE · exe · ff67e66d)"
published: 2026-11-10
draft: false
description: "Malicious (low confidence): Serai RAT · rat/backdoor/spyware · difficulty medium · Static decompilation (dynamic execution produced no runtime behavior)"
tags: ["Serai", "rat", "backdoor", "spyware", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-10-Serai-RAT-ff67e66d"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Serai RAT** (uncertain) · Confidence **low**
> 
> Aliases: SeraiBawang client, Serai RustRAT
> 
> The sample is a remote-control trojan client written in Rust: it embeds a C2 host and port, install file name, mutex, and anti-VM switch; it has complete RAT functions such as remote desktop/webcam/keyboard and mouse injection/command execution/file upload and download/SOCKS proxy, and embeds two persistence paths: a Run key and an at-logon scheduled task. In the emulation sandbox the process started successfully and loaded network/media components, but produced no outbound or drop behavior (consistent with the built-in virtual machine detection branch).

## Overview

| Item | Content |
|:--|:--|
| Family | **Serai RAT** · Aliases SeraiBawang client, Serai RustRAT · _uncertain_ |
| Confidence | **low** |
| Behavior class | rat · backdoor · spyware |
| Difficulty | medium |
| First seen | 2026-11-10 12:07:42 |
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ff67e66da1391e2d9cf3b5ea22b178771e7db0fe885885d318d3bb9d03d14827/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Connect to built-in C2</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Masquerade as kernel process</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Write Run key autostart</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Register logon scheduled task</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Detect VM and sandbox</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `ff67e66da1391e2d9cf3b5ea22b178771e7db0fe885885d318d3bb9d03d14827` |
| MD5 | _not recorded_ |
| Size | 1,084,956 bytes (1.0 MB) |
| Type | PE · `exe` |

## Behavior analysis

**12** behaviors in total, each backed by evidence, and all statically available.

### 1. Connect to built-in C2

`T1095` · Confidence **high** · static

Uses the hardcoded host and port SeraiBawang-39045[.]portmap[.]host:39045 to establish a TCP session; frames carry a length prefix, the session uses ChaCha20-Poly1305 encryption, and the token is encrypted with the server public key during the handshake.

> **Evidence**: configuration string at RVA 0x104002 (VA 0x140104002); 'Not full frame / Too short / Packet too big!' in common\src\connection.rs; chacha20poly1305-0.9.1 crate path string; the client has EncryptionRequest/EncryptionResponse/EncryptionAck packets.
> 
> **Source**: `ref:8e0230d08a` · `ref:fe4bd9cf57` · `ref:39336feb57`

### 2. Masquerade as kernel process

`T1036.005` · Confidence **high** · static

Installs itself as %LOCALAPPDATA%\system\ntoskrnls.exe, with file version information masquerading as the Microsoft Windows operating system (FileDescription=NT Kernel & System, OriginalFilename=ntkrnlmp.exe).

> **Evidence**: PE version resource UTF-16 strings and configuration strings 'ntoskrnls.exe'/'system'; installation code strings 'Installing client to ', 'Invalid install folder.', client\src\service\install.rs.
> 
> **Source**: `ref:131c9929ae` · `ref:32f583a303` · `ref:fe4bd9cf57`

### 3. Write Run key autostart

`T1547.001` · Confidence **high** · static

Through reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v <name> /d <path> /f it establishes current-user logon autostart.

> **Evidence**: string 'addHKCU\Software\Microsoft\Windows\CurrentVersion\Run/v/d/f' (reg add argument concatenation template).
> 
> **Source**: `ref:506c7ceae8`

### 4. Register logon scheduled task

`T1053.005` · Confidence **high** · static

Through schtasks /create /f /sc onlogon /rl highest /tn "<name>" /tr '"<path>"' it registers a high-privilege logon-triggered task as the second persistence path.

> **Evidence**: string 'schtasks /create /f /sc onlogon /rl highest /tn "' (including placeholders for task name and execution path).
> 
> **Source**: `ref:506c7ceae8`

### 5. Detect virtual machines and sandboxes

`T1497.001` · Confidence **high** · static

Queries Win32_ComputerSystem Manufacturer/Model via WMI and compares them against microsoft corporation, vmware, and VIRTUALBOX; it also loads SbieDll.dll to detect the Sandboxie environment.

> **Evidence**: strings 'SELECT Manufacturer, Model FROM Win32_ComputerSystem', 'microsoft corporation', 'vmware', 'VIRTUALBOX', 'SbieDll.dll', module path client\src\service\anti_vm.rs.
> 
> **Source**: `ref:506c7ceae8` · `ref:fe4bd9cf57`

### 6. Anti-debug probing

`T1622` · Confidence **high** · static

Calls IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess, and NtSetInformationThread to detect debuggers; reads the AeDebug configuration and calls OutputDebugString, providing anti-debug/anti-analysis capability.

> **Evidence**: imports IsDebuggerPresent/NtQueryInformationProcess; strings 'CheckRemoteDebuggerPresent', 'NtSetInformationThread', 'SeDebugPrivilege', 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug', 'OutputDebugString'.
> 
> **Source**: `ref:fa811f8391` · `ref:506c7ceae8`

### 7. Screenshots and remote desktop

`T1113` · Confidence **high** · static

Uses BitBlt/GetDIBits/CreateCompatibleBitmap to capture the desktop screen, compresses it as JPEG, and sends it back via RemoteDesktopFrame packets; supports multi-monitor enumeration and remote desktop configuration.

> **Evidence**: imports gdi32!BitBlt/GetDIBits/CreateCompatibleBitmap, user32!EnumDisplayMonitors; strings 'JPEG compression failed (screenshot)', 'Failed to send remote desktop frame', 'RemoteDesktopFrame', client\src\features\remote_desktop.rs.
> 
> **Source**: `ref:fa811f8391` · `ref:39336feb57`

### 8. Webcam frame capture

`T1125` · Confidence **high** · static

Enumerates video capture devices via Media Foundation and reads the video stream, sending captured frames back as WebcamResult; includes device capability and format negotiation logic.

> **Evidence**: imports mf!MFEnumDeviceSources, mfreadwrite!MFCreateSourceReaderFromMediaSource, mfplat!MFCreateAttributes/MFCreateSample; strings 'MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME', 'MediaFoundation Camera', client\src\features\webcam.rs.
> 
> **Source**: `ref:fa811f8391` · `ref:39336feb57`

### 9. Inject keyboard and mouse

`T1056.001` · Confidence **high** · static

Uses SendInput/keybd_event/mouse_event/SetCursorPos to synthesize keyboard and mouse input, and GetKeyState to read key states, achieving remote control of the host.

> **Evidence**: imports user32!SendInput/keybd_event/mouse_event/SetCursorPos/GetKeyState; strings 'KeyboardInputData', 'MouseClickData'.
> 
> **Source**: `ref:fa811f8391` · `ref:506c7ceae8`

### 10. Execute commands with hidden windows

`T1059.001` · Confidence **high** · static

Executes system commands and scripts through cmd.exe /c and powershell -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -Command, returning results via ShellOutput packets; it also plays speech through a temporary VBS + cscript.

> **Evidence**: strings 'powershell-NoLogo-NoProfile-NonInteractive-WindowStyleHidden-Command', 'cmd.exe /e:ON /v:OFF /d /c', 'echo ... temp_speech.vbs&&cscript//nologo', 'ShellOutput', common\src\shell.rs.
> 
> **Source**: `ref:506c7ceae8` · `ref:39336feb57`

### 11. File upload and download

`T1105` · Confidence **high** · static

Implements DownloadFile/UploadFile packets and file browsing, can drop files onto the victim host and upload stolen files, and includes temporary directory write logic.

> **Evidence**: packet names 'UploadFile', 'DonwloadFileResult' (original spelling), 'FileData', 'Failed to write file to temp directory', 'file_name' field.
> 
> **Source**: `ref:39336feb57`

### 12. SOCKS proxy forwarding

`T1090` · Confidence **medium** · static

Built-in SOCKS proxy module and reverse_proxy_port configuration can use the controlled host as a network proxy egress, expanding the attacker's access surface.

> **Evidence**: source path common\src\socks.rs; ClientInfo field 'reverse_proxy_port'; 'SockState'/'Afd' asynchronous socket state strings.
> 
> **Source**: `ref:39336feb57` · `ref:506c7ceae8`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: The above address was obtained from static analysis; no successful connection or session was observed under the network-isolated analysis environment, and the real C2's responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `SeraiBawang-39045.portmap[.]host` | 39045 | c2 | static | ⏳ not observed |

### Host

**Mutex**

- `The Strongest Battleground (candidate mutex name)`

**Dropped paths**

- `%LOCALAPPDATA%\system\ntoskrnls.exe`
- `%TEMP%\temp_speech.vbs`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

**Scheduled tasks**

- `Logon-triggered scheduled task (/sc onlogon /rl highest, task name determined by the configuration)`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `SeraiBawang-39045.portmap[.]host` | yes | static |
| `c2_port` | `39045` | yes | static |
| `protocol` | `TCP length-prefixed framing; session ChaCha20-Poly1305 AEAD, token encrypted with the server public key during the handshake` | yes | static |
| `encryption_algo` | `ChaCha20-Poly1305` | yes | static |
| `install_file_name` | `ntoskrnls.exe` | yes | static |
| `install_folder` | `system (under %LOCALAPPDATA%)` | yes | static |
| `mutex` | `The Strongest Battleground (candidate value)` | no | static |
| `anti_vm_detection` | `enabled (config item present, includes virtualization platform/VirtualBox/Sandboxie detection)` | no | static |
| `enable_hidden` | `config item present (boolean value not confirmed from the serialized block)` | no | static |
| `unattended_mode` | `config item present (boolean value not confirmed from the serialized block)` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- Not ransomware: no file encryption, shadow copy deletion, encrypted ransom note, or bulk file rewriting logic was seen.
- Not a credential stealer: no browser password store, wallet, clipboard credential, or lsass read path was seen.
- Do not claim that this run successfully made outbound connections or dropped persistence on a real host: the dynamic phase only observed process startup and module loading, with no DNS/TCP requests and no file or registry writes.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Unpacking | No |

**Limitations and open questions**

1. During the dynamic phase the sample process ran for about 3 minutes; network monitoring recorded no DNS queries or TCP connections for this process, and system telemetry recorded no file/registry writes; this may be triggered by the built-in anti-VM/anti-sandbox logic, and behavior on a real host may differ.
2. The C2 session was never established, so all C2 fields in c2 and config are marked recoverability=static, pending_dynamic_verify=true.
3. The install_folder and mutex values in config are inferred from adjacent strings in the configuration block; the serialized field order was not confirmed byte by byte, so deviation is possible.
4. The family name is inferred from built-in identifiers and the source directory structure, without same-source comparison against public family libraries.

## Evidence index

<details>
<summary>Show 18 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:ef2bf30897` | Sample triage | Hash/imphash/section table/packing score (packing=0, 25 imported DLLs, 269 symbols) |
| `ref:131c9929ae` | PE structure parsing | AMD64 PE, entry RVA 0xBE5DC, 7 sections, TLS/debug directories, version resource section |
| `ref:fa811f8391` | Import table parsing | Import table: ws2_32/gdi32/mf*/pdh/user32/SendInput and other 269 symbols |
| `ref:16eb2f0b1f` | String extraction | ASCII/UTF-16 string statistics (4211/23) |
| `ref:5b4a47e26e` | unpack.detect | Packing routing (entry section writable, emulate_to_oep recommended; no known packer signature) |
| `ref:8e0230d08a` | addr.translate | Configuration block file offset 0x100E02 → RVA 0x104002 / VA 0x140104002 |
| `ref:fe4bd9cf57` | byte-level static dump | Raw configuration block, anti-VM/persistence/anti-debug strings, and length-prefix structure |
| `ref:506c7ceae8` | string search | ClientConfig fields, Run key/scheduled task command templates, anti_vm.rs and SbieDll detection |
| `ref:32f583a303` | UTF-16 resource scan | Version resource masquerading as NT Kernel & System / ntkrnlmp.exe / Microsoft Corporation |
| `ref:39336feb57` | string inventory | RAT feature surface: remote_desktop/webcam/fun/collectors/socks/shell/packets, ChaCha20-Poly1305 dependency |
| `ref:e4d3e5033b` | Dynamic analysis platform | Real dynamic: after delivery the sample PID 6444 started, 29 polls, 3 memory dumps, closed out and rolled back |
| `ref:fcd3110979` | timeline read | Timeline: candidate process 6444 first appeared at 03:33:20, with no child process/GONE records |
| `ref:a861d6fac7` | network log read | Network monitoring log: no DNS/TCP records for the sample process (only noise such as system updates) |
| `ref:956d6e40ae` | dump string scan | Memory dumps contain the configuration block and feature strings; the monitoring component reports no injection/no hooks |
| `ref:4431bd08b3` | telemetry read | System telemetry: only sample process creation recorded; no new Run key entries, no persistence writes observed |
| `ref:9b6a59a0f2` | telemetry read | Collection status and session event cross-check (no related Defender/AMSI alerts) |
| `telemetry:ff67e66d` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 97; ETW short-lived process events 1; filtered tool/system noise 27 |
| `etw:ff67e66d:6444` | Process event monitoring | Short-lived process event: ff67e66da1391e2d9cf3b5ea22b178771e7db0fe885885d318d3bb9d03d14827.exe (pid 6444; MD5=5AE7BEE777CA78D37F84571FD0173416,SHA256=FF67E66DA1391E2D9CF3B5EA22B178771E7DB0FE885885D318D3BB9D03D14827,IMPHASH=172F147ED81A86935B63248026265D72) |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
