---
title: "Malware Analysis: Remcos RAT (other · vbe · bd2201ac)"
published: 2026-11-22
draft: false
description: "Malicious (high confidence): Remcos RAT · rat/backdoor/stealer · medium difficulty · static analysis only"
tags: ["Remcos", "rat", "backdoor", "stealer"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-22-Remcos-RAT-bd2201ac"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Remcos RAT** · Confidence **High**
> 
> Aliases: Remcos, Remcos Pro, Remote Control
> 
> The .vbe is actually a plaintext VBScript downloader: it writes a randomly named .ps1 to C:\Temp and executes it with powershell.exe -nop -ep bypass -file in a hidden window; the inner PowerShell sequentially uses Base64, GZip, AES-256-CBC and XOR to decrypt the ConfuserEx-obfuscated .NET loader DEVVV.dll, then hands a 537,600-byte native PE to DEVVV.WHORE::LAUNCHER for hosting into aspnet_compiler.exe. The native payload strings explicitly contain Remcos v7.3.1 Pro, BreakingSecurity.net, Remcos Agent initialized, Watchdog module activated and others, and a complete Remcos configuration was decrypted in emulated memory (C2 203.202.232[.]212:4047, mutex Rmc-ELYARJ, dropped remcos.exe). The conclusions are supported by layer-by-layer decoding, PE structure/imports, strings and isolated emulation memory.

## Overview

| Item | Content |
|:--|:--|
| Family | **Remcos RAT** · aliases Remcos, Remcos Pro, Remote Control |
| Confidence | **High** |
| Behavior classes | rat · backdoor · stealer |
| Difficulty | medium |
| First seen | 2026-11-20 08:51:30 |
| Analysis method | Static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/bd2201aca49ea9a68238326ae87b32597daa3ae7c761a981db1978a71c365309/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Write and hide script execution</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Multi-layer memory payload</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Reflectively load .NET loader</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Spoof system compiler host</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded C2 config</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `bd2201aca49ea9a68238326ae87b32597daa3ae7c761a981db1978a71c365309` |
| MD5 | _Not recorded_ |
| Size | 3,366,116 bytes (3.2 MB) |
| Type | other · `vbe` |

## Behavior Analysis

**11** behaviors in total, each backed by evidence, and all are static.

### 1. Write and Hide Script Execution

`T1059.001` · Confidence **High** · Static

The VBScript restores the embedded Base64 text and writes it to C:\Temp\<8 uppercase random letters>.ps1, starts it with powershell.exe -nop -ep bypass -file in a hidden window, and deletes the script after execution.

> **Evidence**: g_encodedPayload decoding + Const PS_LAUNCH_CMD = "powershell.exe -nop -ep bypass -file """; WScript.Shell.Run g_launchCommand, 0, True; StepRemoveArtifacts deletes the temp ps1
> 
> **Source**: `ev-000007` · `ref:3ac0cc2b84`

### 2. Multi-Layer Memory Payload Decoding

`T1027` · Confidence **High** · Static

The first PowerShell layer uses Base64->GZip->AES-256-CBC/PKCS7 (embedded key/IV, with SHA-256 verification of the packed ciphertext) to decrypt the second script; the second layer then uses repeating-key XOR (ZZaDazKA6@@^^) to decrypt the .NET loader.

> **Evidence**: PS Secure Loader - Layered Engine (v2) comments; Test-HashMatches/Expand-GZipBytes/Invoke-AesDecrypt; the repeating-key XOR loop in ConvertFrom-MaskedBlob
> 
> **Source**: `ev-000007`

### 3. Reflectively Load .NET Loader

`T1620` · Confidence **High** · Static

The second script loads DEVVV.dll in memory via [Reflection.Assembly]::Load and reflectively invokes the LAUNCHER static method of the DEVVV.WHORE type, without dropping the loader to disk.

> **Evidence**: [Reflection.Assembly]::Load in Invoke-InMemoryAssembly; GetType('DEVVV.WHORE') / GetMethod('LAUNCHER'); strings DEVVV.dll, WHORE, LAUNCHER
> 
> **Source**: `ev-000001` · `ev-000007` · `ref:d8b1a3ec28`

### 4. Spoof System Compiler Host

`T1036` · Confidence **Medium** · Static

LAUNCHER receives the host path C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe and the native PE byte array; the loader contains fields such as CreateProcess/process and thread handles/shellcode/LoadLibraryA, intending to place the Remcos payload into a legitimate .NET compiler process.

> **Evidence**: stage2 script $hostExe='C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe'; loader strings processInformation/startupInfo/applicationName/commandLine/processHandle/threadHandle/shellcode/LoadLibraryA/GetProcAddress
> 
> **Source**: `ev-000001` · `ev-000007` · `ref:d8b1a3ec28`

### 5. Decrypt Embedded C2 Configuration

`T1027` · Confidence **High** · Static

The native PE reads and decrypts the configuration from resource SETTINGS (RVA 0x8a5cc, length 0x4b5=1205), obtaining C2 203.202.232[.]212:4047, mutex Rmc-ELYARJ, drop name remcos.exe, directory name doc, log logs.dat and others.

> **Evidence**: Emulation PC 0x41fa9b calls FindResourceA(hModule,"SETTINGS",0xa), then LoadResource/LockResource/SizeofResource=0x4b5; after emulation the heap at 0x9470 holds the plaintext configuration 203.202.232[.]212:4047:1
> 
> **Source**: `ev-000008` · `ref:374ee2ae49`

### 6. Connect to C2 and Maintain Session

`T1571` · Confidence **High** · Static

The payload imports WS2_32 (socket/connect/send/recv etc.) and TLS 1.3-related implementations, and connects to 203.202.232[.]212:4047 per the configuration to establish the remote-control channel.

> **Evidence**: WS2_32.dll imports ord 19/115/3/23/12/111/16/4 and getaddrinfo; strings 'Connecting | ', 'Connected | ', 'Connection Error: Unable to create socket'; first configuration field 203.202.232[.]212:4047
> 
> **Source**: `ref:4137b052ce` · `ev-000008`

### 7. Keylogging and Clipboard Theft

`T1056.001` · Confidence **High** · Static

Implements keylogging via SetWindowsHookExA/GetKeyboardState/ToUnicodeEx, and reads/replaces clipboard content via OpenClipboard/GetClipboardData/SetClipboardData.

> **Evidence**: USER32 imports SetWindowsHookExA(@0x462264 IAT), GetKeyboardState, ToUnicodeEx, OpenClipboard, GetClipboardData, SetClipboardData; strings 'Online Keylogger Started', 'Offline Keylogger Started', '[Text copied to clipboard]'
> 
> **Source**: `ref:4137b052ce` · `ref:3377cb5c7e`

### 8. Screenshots and Microphone Recording

`T1113` · Confidence **High** · Static

Uses BitBlt/StretchBlt/GDI+ to capture the screen and waveInOpen/waveInStart to record the microphone, storing them in the Screenshots and MicRecords directories for the controller to retrieve.

> **Evidence**: GDI32 BitBlt/StretchBlt/CreateCompatibleBitmap; gdiplus GdipLoadImageFromStream/GdipSaveImageToStream; WINMM waveInOpen/waveInStart/waveInAddBuffer; configuration fields Screenshots, MicRecords
> 
> **Source**: `ref:4137b052ce` · `ref:3377cb5c7e` · `ev-000008`

### 9. Remote Commands and File Delivery

`T1105` · Confidence **High** · Static

Has the ability to execute cmd.exe/powershell.exe, create pipes/processes, and download files via URLDownloadToFileW/InternetOpenUrlW, with download success/failure strings.

> **Evidence**: KERNEL32 CreateProcessW/CreateProcessA/CreatePipe/PeekNamedPipe; urlmon URLDownloadToFileW/URLOpenBlockingStreamW; WININET InternetOpenUrlW/InternetReadFile; strings 'Downloading file: ', 'Downloaded file: '
> 
> **Source**: `ref:4137b052ce` · `ref:3377cb5c7e`

### 10. Watchdog Restart Keep-Alive

`T1547.001` · Confidence **Medium** · Static

Contains a Watchdog module that checks process liveness and restarts it after an abnormal exit; payload strings include sc.exe, rmclient.exe, fsutil.exe, svchost.exe and registry startup/service-related operations.

> **Evidence**: Strings 'Watchdog module activated', 'Remcos restarted by watchdog!', 'Watchdog launch failed!', 'SetSvcStartup', 'GetStartups', HKLM/HKCU/HKCR/HKU/HKCC; imports RegCreateKeyExW/RegSetValueExW
> 
> **Source**: `ref:3377cb5c7e` · `ref:4137b052ce`

### 11. Anti-Debugging and Environment Probing

`T1622` · Confidence **Medium** · Static

The payload imports IsDebuggerPresent and enumerates processes, system version and display/session information; loader strings include Kill/FailFast and others, giving it anti-analysis and environment-determination capability.

> **Evidence**: KERNEL32 IsDebuggerPresent(@IAT 0x462200), CreateToolhelp32Snapshot/Process32FirstW/Process32NextW, GetVersionExW, EnumDisplaySettingsW; loader strings Kill, FailFast, Debugger
> 
> **Source**: `ref:4137b052ce` · `ref:d8b1a3ec28`


## IOC (Defanged)

### Network

:::caution
**Pending dynamic verification**: The addresses above were obtained statically; no successful connection or session was observed under the isolated analysis network, so the real C2 responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `203.202.232[.]212` | 4047 | c2 | static | ⏳ Not observed |

### Host

**Mutexes**

- `Rmc-ELYARJ`

**Drop paths**

- `%APPDATA%\doc\remcos.exe`
- `%APPDATA%\doc\logs.dat`
- `%APPDATA%\doc\Screenshots`
- `%APPDATA%\doc\MicRecords`
- `C:\Temp\<8 uppercase letters>.ps1`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `203.202.232[.]212` | Yes | static |
| `c2_port` | `4047` | Yes | static |
| `mutex` | `Rmc-ELYARJ` | Yes | static |
| `install_path` | `%APPDATA%\doc\remcos.exe` | Yes | static |
| `log_file` | `logs.dat` | No | static |
| `screenshot_dir` | `Screenshots` | No | static |
| `audio_capture_dir` | `MicRecords` | No | static |
| `campaign_id` | `C2F9765B8459AF94E02C347A711FE487` | No | static |
| `encryption_algo` | `Base64 + GZip + AES-256-CBC/PKCS7 (outer); XOR (loader)` | No | static |
| `watchdog` | `enabled` | No | static |

## Common Misinterpretations

:::important
The following conclusions are **easy to misinterpret**; keep them in mind when citing this report.

- Do not call it ransomware or a wiper: no evidence of file encryption, shadow-copy deletion or disk wiping was found; the payload is a RAT.
- Do not claim a real C2 session was obtained or that 203.202.232[.]212:4047 was confirmed online: the C2 configuration comes from static/emulated decryption, and no real outbound connection was made.
- Do not treat DEVVV.dll as the final malicious payload: it is only a ConfuserEx-obfuscated .NET loader, and the final payload is the Remcos native PE in memory.
- Do not describe the sample as actually detonated on this host: this run only loaded resources and memory snapshots in an isolated emulation environment, without execution on the real Windows host.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Static analysis only |
| Unpacked | Yes (stage2 `fd8966550751d9616115529d2188295adcefe4eff57df5a158c27861ea984d2e`) |

**Limitations and pending verification**

1. This analysis was static plus user-mode emulation only; the sample was not executed on a real Windows host and no real outbound connection was made, so whether the C2 is online, the real session and returned content remain unverified.
2. C2, mutex, install path and build identifier come from decryption results in emulated process memory (self-reported evidence, confidence capped at 0.7) and need re-checking in a real sandbox with network isolation and traffic capture.
3. The .NET loader is ConfuserEx-obfuscated (ConfusedByAttribute, invisible-character naming, control-flow proxies) and its injection implementation was not fully recovered; the host and injection method are inferred from its P/Invoke/field strings and call arguments.
4. Persistence and registry/service/scheduled-task behavior are inferred only from strings and imported APIs and were not confirmed through telemetry or dynamic diffing.
5. The SETTINGS resource decryption algorithm of the native PE was not fully reverse-engineered; the plaintext configuration was read from process memory after emulated execution, without independently recomputing the encryption algorithm.
6. The ip-api[.]com query string appears in the payload and is only used for geographic/network information probing; it should not be treated as C2.

## Evidence Index

<details>
<summary>Expand 5 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | .NET loader strings: DEVVV.dll/WHORE/LAUNCHER/shellcode/processHandle/CreateProcess-related fields |
| `ev-000005` | String extraction | Native PE strings: Remcos v7.3.1 Pro, BreakingSecurity.net, Watchdog, Keylogger, Screenshots, MicRecords etc. |
| `ev-000006` | decompile.ghidra | FUN_0041fa35 decompilation, supporting confirmation of resource/string handling code |
| `ev-000007` | evidence.record | Static layer-by-layer decoding of the delivery chain: VBE -> PS1 -> AES/XOR -> .NET DLL + native PE |
| `ev-000008` | evidence.record | Isolated emulation memory snapshot decrypting the Remcos SETTINGS plaintext (C2/mutex/drop path/build identifier) |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
