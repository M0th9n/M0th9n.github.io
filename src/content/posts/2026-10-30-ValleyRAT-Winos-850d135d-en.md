---
title: "Malware Analysis: ValleyRAT (Winos) (PE · exe · 850d135d)"
published: 2026-10-30
draft: false
description: "Malicious (medium confidence): ValleyRAT (Winos) · dropper/rat/backdoor · difficulty medium · dynamic sandbox + static decompilation"
tags: ["ValleyRAT", "dropper", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-30-ValleyRAT-Winos-850d135d"
---

> [!WARNING]
> **Verdict: malicious** · Family **ValleyRAT (Winos)** (uncertain) · Confidence **medium**
> 
> Aliases: ValleyRAT, Winos, Winos 4.0
> 
> The sample is an Inno Setup installer disguised as "Data Run Guide". In the dynamic sandbox it dropped and ran %APPDATA%\hrjhh\hrjhh.exe and a log.dll in the same directory; hrjhh.exe is actually a renamed legitimate NBMSClient/BarClientView client that statically imports log.dll, and the malicious log.dll, once side-loaded, implanted 2 VMProtect-protected PEs into the process; hrjhh.exe then continuously resolved and connected to rfjp93sina[.]top:443 (DoH template hxxps://%s/dns-query?dns=%s) while also running a Quark browser installer. Installer + side-loading + process injection + covert C2 heartbeat form a complete malicious delivery chain.

## Overview

| Item | Content |
|:--|:--|
| Family | **ValleyRAT (Winos)** · aliases ValleyRAT, Winos, Winos 4.0 · _uncertain_ |
| Confidence | **medium** |
| Behaviour class | dropper · rat · backdoor |
| Difficulty | medium |
| First seen | 2026-10-27 23:46:21 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/850d135d3ff871f88c96e5a6b889b1f454944ffdd35b2fce5e3fa1d049d8bf70/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Fake installer drops payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Side-load a legit client</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1574.002</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Inject VMProtect backdoor</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.002</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Resolve C2 over DoH</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Periodic C2 heartbeat</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `850d135d3ff871f88c96e5a6b889b1f454944ffdd35b2fce5e3fa1d049d8bf70` |
| MD5 | _not recorded_ |
| Size | 5,430,309 bytes (5.2 MB) |
| Type | PE · `exe` |

## Behaviour analysis

**12** behaviours in total, each tied to evidence; **6** are statically recoverable and **6** were obtained dynamically.

### 1. Fake installer drops payload

`T1204.002` · Confidence **high** · dynamic

The Inno Setup 6.9.3 installer masquerades with AppName "Data Run Guide" and forged Microsoft copyright information; after execution it drops hrjhh.exe and log.dll into %APPDATA%\hrjhh and launches htfgqdowfk.exe from %TEMP%.

> **Evidence**: PE export SetupLdr.e32; install data signature "Inno Setup Setup Data (6.9.3)" @0x43ce5e; dynamic sandbox timeline: PID 1628=%APPDATA%\hrjhh\hrjhh.exe, PID 5860=%TEMP%\htfgqdowfk.exe
> 
> **Source**: `ref:f3587a48ce` · `ref:2cd8ba2c8e` · `ref:d55f56cc4f` · `ref:5e799c57a7` · `ev-000028`

### 2. Side-load a legitimate client

`T1574.002` · Confidence **high** · dynamic

The dropped hrjhh.exe is actually a renamed legitimate NBMSClient/BarClientView client (PDB D:\slave\workspace\AppBcClient\startbc\startbc.cpp); its import table statically imports log.dll, and the malicious log.dll placed in the same directory is then loaded, forming a DLL side-load.

> **Evidence**: hrjhh.exe memory image import descriptor item 4 name=log.dll @RVA 0x31570; module list 0x6f3c0000 log.dll; strings D:\slave\workspace\AppBcClient\startbc\startbc.cpp, NBMSClient\BarClientView.exe
> 
> **Source**: `ref:242c110b48` · `ref:c00bb9d598` · `ref:20a9b83342` · `ref:5e799c57a7` · `ev-000028`

### 3. Inject VMProtect backdoor

`T1055.002` · Confidence **high** · dynamic

The malicious log.dll is a high-entropy self-decrypting wrapper; after loading it implants 2 executable PE modules into the hrjhh.exe process (0x27a0000 and 0x28b0000, containing a .vmp0 section and the export name Fuck), forming the in-memory backdoor core.

> **Evidence**: memory scan implanted PE=2; 28b0000.dll .vmp0 entropy 7.91, unpack_detect=vmprotect(0.9); the 27a0000 region contains a PE and shellcode at +0x1973; export Fuck
> 
> **Source**: `ref:5e799c57a7` · `ref:6e0604e26e` · `ref:3d404386b3` · `ref:0e33f3cae8` · `ref:be3585b187` · `ref:dfc239c619`

### 4. Resolve C2 over a DoH tunnel

`T1071.001` · Confidence **high** · dynamic

The backdoor uses WinHttp.WinhttpRequest.5.1 to send DNS-over-HTTPS queries to hxxps://rfjp93sina[.]top/dns-query?dns=..., wrapping C2 traffic inside HTTPS/DoH.

> **Evidence**: memory strings WinHttp.WinhttpRequest.5.1 and hxxps://%s/dns-query?dns=%s; network monitoring resolved rfjp93sina[.]top 25 times, with hrjhh.exe holding TCP 443
> 
> **Source**: `ev-000028` · `ref:5e799c57a7`

### 5. Periodic C2 heartbeat

`T1071.001` · Confidence **high** · dynamic

hrjhh.exe keeps connecting to rfjp93sina[.]top:443 at roughly 5-second intervals; in 2 minutes 25 DNS resolutions and continuous TCP 443 connections were observed, a stable C2 heartbeat.

> **Evidence**: network monitoring 09:16:25–09:18:32: hrjhh.exe(1628) resolves rfjp93sina[.]top then requests TCP 192.0.2[.]123:443 each time
> 
> **Source**: `ref:5e799c57a7` · `ev-000028`

### 6. Write Run key autostart

`T1547.001` · Confidence **medium** · static

The backdoor config contains HKCU\Software\Microsoft\Windows\CurrentVersion\Run\RacMan, used to register hrjhh.exe as a logon autostart entry for the current user.

> **Evidence**: memory strings HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\RacMan (0x1d9469) and the HKCU\...\Run\RacMan config record
> 
> **Source**: `ev-000028` · `ref:242c110b48`

### 7. Register the RacMan service

`T1543.003` · Confidence **medium** · static

The backdoor can create/delete system services, and its config references HKLM\SYSTEM\CurrentControlSet\Services\RacMan ImagePath/Group/wow64, used for service-based persistence.

> **Evidence**: 28b0000.dll imports CreateServiceA/OpenSCManagerA/OpenServiceA/DeleteService; string HKLM\...\Services\RacMan\ImagePath
> 
> **Source**: `ref:1e9c7021f9` · `ev-000028`

### 8. Keystroke and window logging

`T1056.001` · Confidence **high** · static

The backdoor imports keyboard-hook and foreground-window APIs, able to install a global keyboard hook and collect foreground window titles/class names, giving it keylogging capability.

> **Evidence**: 28b0000.dll imports SetWindowsHookExA, CallNextHookEx, GetKeyState, GetForegroundWindow, GetWindowTextA, GetClassNameA
> 
> **Source**: `ref:1e9c7021f9`

### 9. Screen and camera capture

`T1113` · Confidence **medium** · static

The backdoor imports screen/cursor/font-related GDI APIs and loads avicap32/winmm/msvfw32 in-process, giving it screen-capture and camera-capture capability together with the Scrnshot.dll plugin.

> **Evidence**: 28b0000.dll imports GetDC/GetCursorPos/CreateFontA/GetDeviceCaps; the hrjhh process loads avicap32.dll, winmm.dll, msvfw32.dll; string %s\Scrnshot.dll
> 
> **Source**: `ref:1e9c7021f9` · `ref:5e799c57a7` · `ev-000028`

### 10. Remote command execution via pipes

`T1059.003` · Confidence **medium** · static

The backdoor imports CreateProcessA and CreateNamedPipeA and uses the named pipes \\.\Pipe\1351827 / \\.\Pipe\%d to execute remote commands and return output.

> **Evidence**: 28b0000.dll imports CreateProcessA, CreateNamedPipeA; memory strings \\.\Pipe\1351827 and \\.\Pipe\%d
> 
> **Source**: `ref:1e9c7021f9` · `ev-000028`

### 11. Process enumeration and token theft

`T1134.002` · Confidence **high** · static

The backdoor enumerates processes, opens them and can inject across sessions: VirtualAllocEx/WriteProcessMemory/GetThreadContext/SetThreadContext, plus WTSQueryUserToken/DuplicateTokenEx/CreateProcessAsUserA to steal user tokens.

> **Evidence**: 28b0000.dll imports CreateToolhelp32Snapshot, Process32First/Next, OpenProcess, VirtualAllocEx, WriteProcessMemory, WTSQueryUserToken, DuplicateTokenEx, CreateProcessAsUserA
> 
> **Source**: `ref:1e9c7021f9`

### 12. Bundle the Quark browser installer

`T1105` · Confidence **high** · dynamic

The installer also drops and runs the Quark browser mini-installer, which reports install/usage statistics to track[.]lc[.]quark[.]cn and px[.]effirst[.]com, using legitimate software as cover for the backdoor.

> **Evidence**: network monitoring: htfgqdowfk.exe(5860) requests track[.]lc[.]quark[.]cn/collect and px[.]effirst[.]com/api/v1/jstrace/upload; the file is %TEMP%\htfgqdowfk.exe
> 
> **Source**: `ref:5e799c57a7` · `ev-000028`


## IOCs (defanged)

### Network

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://rfjp93sina[.]top/dns-query` | 443 | c2 | dynamic | — |

### Host

**Drop paths**

- `%APPDATA%\hrjhh\hrjhh.exe`
- `%APPDATA%\hrjhh\log.dll`
- `%APPDATA%\hrjhh\dsp_bridge.dll`
- `%APPDATA%\hrjhh\Scrnshot.dll`
- `%APPDATA%\hrjhh\Language.dll`
- `%APPDATA%\hrjhh\Box.ini`
- `%APPDATA%\hrjhh\Update.xml`
- `%APPDATA%\hrjhh\Update.log`
- `%TEMP%\htfgqdowfk.exe`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\RacMan`
- `HKLM\SYSTEM\CurrentControlSet\Services\RacMan`

**Services**

- `RacMan`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `rfjp93sina[.]top` | yes | dynamic |
| `c2_port` | `443` | yes | dynamic |
| `c2_protocol` | `DNS-over-HTTPS via WinHttp.WinhttpRequest.5.1, template hxxps://%s/dns-query?dns=%s` | yes | static |
| `install_path` | `%APPDATA%\hrjhh` | yes | dynamic |
| `service_name` | `RacMan` | no | static |
| `run_key` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\RacMan` | no | static |
| `group_name` | `Default` | no | static |
| `plugin_modules` | `dsp_bridge.dll;Scrnshot.dll;Language.dll;Box.ini;Update.xml;Update.log` | no | static |
| `encryption_algo` | `CryptoAPI RSA import/decrypt (CryptAcquireContextW + CryptImportKey + CryptDecrypt)` | no | static |
| `pipe_name` | `\\.\Pipe\1351827` | no | static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not treat the bundled Quark browser installer (htfgqdowfk.exe) as the final malicious payload; it is promotional/normal software, and the real backdoor is the VMProtect module injected after hrjhh.exe side-loads log.dll.
- Do not conclude that hrjhh.exe itself is the malicious body just because it contains strings such as cmd.exe and CreatePipe; it is a legitimate NBMSClient/BarClientView client that was renamed and abused for side-loading.
- Do not claim the real C2 IP or server response was obtained; the sandbox is a fake-network environment and only domain resolution and a 443 connection were observed.
- Do not claim the sample has ransomware/file-encryption or browser-credential-theft capability; the available evidence supports only RAT/backdoor and information collection.
- Do not assert a Telegram C2 merely from the string "Telegram"; no api[.]telegram[.]org or related domain/traffic was observed.
- Do not assert that family attribution has been confirmed by a vendor engine or YARA; ValleyRAT/Winos is a candidate based on TTPs and component naming.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The sandbox is a fake-network environment where only domain resolution of rfjp93sina[.]top and a TCP 443 connection were observed; the real C2 IP, certificate and server response were not obtained, and the DoH tunnel payload is unknown.
2. The HKCU Run key and HKLM RacMan service come from memory strings and imported API capability; the guest registry was not read directly to confirm actual writes, so they are recorded as static.
3. hrjhh.exe's on-disk file was not retrieved, only recovered from the process memory image; its digital signature, original file hash and disk attributes could not be verified.
4. The VMProtect backdoor was not unpacked; keylogging, screen capture, remote command and token theft capabilities are inferred from the import table and memory strings, not individually verified at runtime.
5. log.dll is a self-decrypting wrapper whose export names are mixed with system function names such as ADSI/LDAP/OpenGL; it was not fully unpacked, so its internal module boundaries cannot be confirmed.
6. Family attribution (ValleyRAT/Winos) is inferred from TTPs and component naming, not directly confirmed by a vendor engine or YARA.

## Evidence index

<details>
<summary>Expand 16 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash calculation | sha256=850d135d3ff871f88c96e5a6b889b1f454944ffdd35b2fce5e3fa1d049d8bf70, size 5430309 |
| `ref:f3587a48ce` | PE structure parser | PE32 GUI, entry RVA 0xAD054, 11 sections, 2 exports |
| `ref:2cd8ba2c8e` | Export table parser | DLL name SetupLdr.e32, exports dbkFCallWrapperAddr and __dbk_fcall_wrapper, confirming the Inno Setup loader |
| `ref:f08493d0e3` | Import table parser | 5 DLLs/150 imports, incl. CreateProcessW, VirtualAlloc, FindResourceW, CreateThread |
| `ref:d55f56cc4f` | String scan | Inno Setup 6.9.3/6.5.0 strings, SetupLdr, TInstItem and other installer traits |
| `ref:5e799c57a7` | Dynamic sandbox timeline | After detonation: process 1628=hrjhh.exe, 5860=htfgqdowfk.exe; memory scan found 2 implanted PEs; artifacts include network-monitoring logs and memory dumps |
| `ref:20a9b83342` | PE structure parser | log.dll: 11 sections, W^X section, 113 exports, TLS |
| `ref:dfc239c619` | Packing detection | log.dll judged a self-decrypting wrapper, .text/.jfiS/.YAaj high entropy and the entry section writable |
| `ref:6e0604e26e` | PE structure parser | 28b0000.dll: 6 sections incl. .vmp0 (827392 bytes), 1 export |
| `ref:0e33f3cae8` | Packing detection | 28b0000.dll judged VMProtect, confidence 0.9 |
| `ref:be3585b187` | Export table parser | 28b0000.dll's only export name Fuck @RVA 0x1756C |
| `ref:1e9c7021f9` | Import table parser | 28b0000.dll imports 15 DLLs/243 symbols, incl. process enumeration, injection, services, registry, keyboard, screen capture, WinINet/WinHTTP, CryptoAPI, Token |
| `ref:242c110b48` | String scan | hrjhh.exe memory-image strings include the NBMSClient/BarClientView PDB and the D:\slave\workspace\AppBcClient path |
| `ref:c00bb9d598` | PE structure parser | hrjhh.exe memory image is PE32 GUI, 6 sections, image base 0x160000, import descriptor points at log.dll |
| `ev-000028` | Script analysis | Parsed network monitoring and minidump: C2 rfjp93sina[.]top:443, DoH template, RacMan persistence, plugin paths, Quark statistics reporting, hrjhh.exe statically importing log.dll |
| `c2_evidence:850d135d` | Connection evidence extraction | Dynamic network monitoring recorded 1 connection attempt to g[.]live[.]com:80; the full session was not captured |

</details>

---

_The sample behind this report is not public; IOCs are defanged. For security research only._
