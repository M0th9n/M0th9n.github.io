---
title: "Malware Analysis: Remcos (other · vbe · f90ebc7c)"
published: 2026-11-14
draft: false
description: "Malicious (high confidence): Remcos · rat/backdoor/stealer · difficulty medium · pure static analysis"
tags: ["Remcos", "rat", "backdoor", "stealer"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-14-Remcos-f90ebc7c"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Remcos** · Confidence **High**
> 
> Aliases: RemcosRAT, Remote Control System, RMCS, Remcos Pro
> 
> The sample uses a VBScript dropper to write and launch PowerShell, decrypts a second-stage script with AES-256-CBC, then restores the .NET reflective loader DEVV.dll with Base64+XOR, and finally loads Remcos 7.3.1 Pro RAT through the aspnet_compiler.exe host. The final PE's SETTINGS resource can be statically decrypted to recover the real C2, mutex and configuration for keylogging, clipboard, screenshots, browser credentials and other RAT modules; its function matches a malicious remote-access backdoor.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Remcos** · aliases RemcosRAT, Remote Control System, RMCS, Remcos Pro |
| Confidence | **High** |
| Behavior class | rat · backdoor · stealer |
| Difficulty | medium |
| First seen | 2026-11-11 14:15:28 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/f90ebc7cb5c0f8fadeb38b86b02671bbf5b9bb5939d66ce7a5d081da60f65fa6/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Write and run PS script</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">AES-decrypt in-memory script</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Reflectively load .NET assembly</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Run payload via system process</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Poll sentinel process</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1057</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `f90ebc7cb5c0f8fadeb38b86b02671bbf5b9bb5939d66ce7a5d081da60f65fa6` |
| MD5 | _not recorded_ |
| Size | 3,419,661 bytes (3.3 MB) |
| Type | other · `vbe` |

## Behavior Analysis

**12** behaviors in total, each backed by evidence, and all obtained statically.

### 1. Write and run PS script

`T1059.001` · Confidence **High** · Static

Decodes the embedded Base64 payload into a PowerShell script, writes C:/Temp/<8 random uppercase letters>.ps1, launches it with powershell.exe -nop -ep bypass -file, and then deletes the script.

> **Evidence**: .vbe off 0x00A7 constant WORK_DIR=C:/Temp/, off 0x00C7 SCRIPT_EXT=.ps1, off 0x00DF PS_LAUNCH=powershell.exe -nop -ep bypass -file; PhaseWriteScript/PhaseExecute/PhaseCleanup run in sequence
> 
> **Source**: `ref:f21412ef2f` · `ref:9766d573f2`

### 2. AES-decrypt in-memory script

`T1140` · Confidence **High** · Static

Decrypts the 1.87 MB second-stage script with a built-in AES-256-CBC key and IV, and executes it inside the current PowerShell process through Invoke-Expression.

> **Evidence**: payload.ps1 contains $encryptedPayload, AesManaged (CBC/PKCS7, BlockSize=128), Invoke-AESDecryption and Invoke-Expression $decryptedScript
> 
> **Source**: `ref:9f3e7e9d44` · `ref:672ee2e1d4`

### 3. Reflectively load .NET assembly

`T1620` · Confidence **High** · Static

The second-stage script applies Base64+XOR (key ZZaDazKA6@@^^) to encodedChunk, Base64-decodes it into the .NET assembly DEVV.dll, loads it reflectively with Assembly.Load and calls DEVV.WHORE.LAUNCHER.

> **Evidence**: stage2.bin off 0x0CE3 $maskingKey=ZZaDazKA6@@^^; off 0x0651 [System.Reflection.Assembly]::Load; DEVV.dll #Strings contains LAUNCHER/DEVV.dll/mscoree
> 
> **Source**: `ref:62a031f72f` · `ref:0e8b5028fe` · `ref:b71e0eab73`

### 4. Run payload via system process

`T1055` · Confidence **Medium** · Static

Passes the legitimate aspnet_compiler.exe path and a 537,600-byte PE to LAUNCHER; the loader metadata contains LoadLibraryA/GetProcAddress/Ntdll/Process/GetProcessById, indicating it loads the payload using a system process as host (injection details were not confirmed instruction by instruction).

> **Evidence**: stage2.bin off 0x0C8D $execHost=C:/Windows/Microsoft.NET/Framework/v4.0.30319/aspnet_compiler.exe; DEVV.dll #Strings contains LoadLibraryA, GetProcAddress, Ntdll, Process, GetProcessById
> 
> **Source**: `ref:62a031f72f` · `ref:b71e0eab73`

### 5. Poll sentinel process

`T1057` · Confidence **High** · Static

Every 5 seconds it uses Get-Process to check whether aspnet_compiler exists, triggering the payload only when the target process is absent to avoid host concurrency and detection.

> **Evidence**: stage2.bin off 0x0C80 SentinelName=aspnet_compiler, off 0x0CB4 PollDelay=5; Test-SentinelAbsent calls Get-Process
> 
> **Source**: `ref:62a031f72f`

### 6. Deploy Remcos RAT

`T1219` · Confidence **High** · Static

The final PE is Remcos 7.3.1 Pro; the SETTINGS resource is RC4-restored to C2 45.141.148[.]75:24040, mutex Rmc-RJJW9C and remote-control capabilities.

> **Evidence**: stage4 off 0x70684 Remcos Agent initialized (, off 0x7583E Remcos v, off 0x7584C © BreakingSecurity.net; decompile 0x41FA84 reads FindResourceA(SETTINGS,10), 0x414E65 parses the configuration
> 
> **Source**: `ref:832b9679eb` · `ref:672ee2e1d4` · `ref:28008768b2`

### 7. Keylogging

`T1056.001` · Confidence **High** · Static

Records keystrokes through SetWindowsHookExA/GetKeyboardState/ToUnicodeEx; strings include Online/Offline Keylogger Started.

> **Evidence**: USER32 SetWindowsHookExA IAT rva 0x62358, GetKeyboardState 0x623C0, ToUnicodeEx 0x62398; off 0x6F78C Offline Keylogger Started, 0x6F828 Online Keylogger Started
> 
> **Source**: `ref:832b9679eb` · `ref:fe1f91224b`

### 8. Clipboard content theft

`T1115` · Confidence **High** · Static

Reads and replaces clipboard content through OpenClipboard/GetClipboardData/SetClipboardData; strings include markers such as [Text copied to clipboard].

> **Evidence**: USER32 OpenClipboard/GetClipboardData/SetClipboardData (IAT rva 0x62420/0x62404/0x62458); off 0x6F9CA [End of clipboard], 0x6FA56 [Text copied to clipboard]
> 
> **Source**: `ref:832b9679eb` · `ref:fe1f91224b`

### 9. Screenshots

`T1113` · Confidence **High** · Static

Captures the screen through BitBlt/StretchBlt/GetDIBits and GDI+ JPEG/PNG encoding, with the filename template wnd_%04i%02i%02i_%02i%02i%02i.

> **Evidence**: GDI32 BitBlt/StretchBlt/GetDIBits IAT rva 0x62064/0x62064/0x6206C; gdiplus GdipSaveImageToStream 0x62410; UTF-16 image/jpeg, image/png, wnd_%04i%02i%02i_%02i%02i%02i
> 
> **Source**: `ref:832b9679eb` · `ref:fe1f91224b`

### 10. Steal browser credentials

`T1555.003` · Confidence **High** · Static

Enumerates Chrome/Edge/Brave/Yandex/Opera/Firefox user data directories, reads Login Data, Cookies, logins.json and key3.db, and recovers cookies.

> **Evidence**: UTF-16 strings Login Data / Cookies / Network/Cookies / Google/Chrome/User Data / Mozilla/Firefox/Profiles / logins.json / key3.db; function name RecoverCookies
> 
> **Source**: `ref:fe1f91224b` · `ref:6d0dd9a821`

### 11. Registry Run key persistence

`T1547.001` · Confidence **Medium** · Static

Imports RegCreateKeyExW/RegSetValueExW and contains the Software/Microsoft/Windows/CurrentVersion/Run path, providing startup configuration capability (no actual write was dynamically observed).

> **Evidence**: ADVAPI32 RegCreateKeyExW IAT rva 0x62204, RegSetValueExW 0x62214; UTF-16 string Software/Microsoft/Windows/CurrentVersion/Run
> 
> **Source**: `ref:832b9679eb` · `ref:fe1f91224b`

### 12. Remote download and execute

`T1105` · Confidence **Medium** · Static

Imports URLDownloadToFileW/InternetOpenUrlW and CreateProcessA; strings include Downloading/Executing file, supporting remote file download and execution.

> **Evidence**: urlmon URLDownloadToFileW IAT rva 0x62428, WININET InternetOpenUrlW 0x62428; KERNEL32 CreateProcessA 0x6224C; off 0x6F574 Downloading file: , 0x6F624 Executing file:
> 
> **Source**: `ref:832b9679eb` · `ref:fe1f91224b`


## IOC (Defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the isolated analysis network, and the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `45.141.148[.]75` | 24040 | c2 | Static | ⏳ Not observed |

### Host

**Mutexes**

- `Rmc-RJJW9C`

**Drop paths**

- `C:\Temp\<8 random uppercase letters>.ps1`
- `C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `45.141.148[.]75` | Yes | Static |
| `c2_port` | `24040` | Yes | Static |
| `c2_protocol` | `tcp` | No | Static |
| `mutex` | `Rmc-RJJW9C` | Yes | Static |
| `install_path` | `remcos.exe` | No | Static |
| `log_file` | `logs.dat` | No | Static |
| `screenshots_dir` | `Screenshots` | No | Static |
| `audio_dir` | `MicRecords` | No | Static |
| `license_key` | `6E9A3D80F7475B0D3C94380D00D174C6` | No | Static |
| `encryption_algo` | `RC4 (34-byte key) for SETTINGS resource; AES-256-CBC for PowerShell stage` | No | Static |
| `c2_tls` | `TLS-capable; embedded self-signed X.509 certificate/key material` | No | Static |
| `geolocation_url` | `hxxps://pro.ip-api[.]com/line/?key=QPVvv1rHQJD2pd2&fields=25948155` | No | Static |
| `builder` | `Remcos 7.3.1 Pro (BreakingSecurity)` | No | Static |

## What Not to Assume

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing the report.

- Do not claim real communication or a session with 45.141.148[.]75:24040 was observed in the dynamic sandbox; this C2 comes from static decryption and has not been verified over the real network.
- Do not treat hxxps://pro.ip-api[.]com as C2: it is a public service address the sample uses for geolocation lookup.
- Do not assert the sample actually wrote the Run key or completed process injection into aspnet_compiler.exe; these are capabilities shown by code, imports and strings, not dynamically confirmed.
- Do not classify the sample as ransomware or a generic downloader just because of multi-layer AES/RC4 obfuscation; the final payload is the Remcos RAT, and the obfuscation is only used for delivery.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | Yes (stage2 `76144fe545141cc05a622af710913e13609d31c50a2b79c23e5068e95f4f199c`) |

**Limitations and items to verify**

1. Pure static analysis; the sample was not detonated in an isolated dynamic environment. reproduced=false, and C2 communication, persistence writes and injection effects have no runtime evidence.
2. The SETTINGS configuration was RC4-restored statically; whether C2 enables TLS in this build and the actual binding between certificate and port were not dynamically verified.
3. The LAUNCHER method of DEVV.dll was not decompiled to IL instruction by instruction; its injection method is inferred from passed arguments and metadata strings (LoadLibraryA/GetProcAddress/Ntdll/Process), with medium confidence.
4. Browser credentials, keylogging, clipboard, screenshots, microphone and remote file operations are confirmed as built-in capabilities by imported APIs and strings; actual runtime results were not observed.
5. The embedded X.509 certificate has an abnormal validity period (2026-2147), possibly generated by the builder; its purpose and peer-verification logic were not verified.

## Evidence Index

<details>
<summary>Show 16 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:f21412ef2f` | String extraction | .vbe plaintext strings: C:/Temp/, .ps1, powershell -nop -ep bypass -file, Base64 payload |
| `ref:9f3e7e9d44` | String extraction | payload.ps1 strings: PS Secure Loader, AesManaged, Invoke-Expression |
| `ref:62a031f72f` | String extraction | stage2.bin strings: Restore-MaskedPayload, Assembly.Load, aspnet_compiler, sentinel polling |
| `ref:63d2621747` | script | Reproduces stage3/stage4 per the sample algorithm and computes SHA-256 |
| `ref:f969ca7943` | PE structure parsing | stage3 DEVV.dll: PE32 DLL, imports only mscoree._CorDllMain |
| `ref:0e8b5028fe` | String extraction | stage3 strings: DEVV.dll, LAUNCHER, mscoree, System.Reflection |
| `ref:b71e0eab73` | script | stage3 .NET metadata: #Strings contains LAUNCHER/LoadLibraryA/GetProcAddress/Ntdll/Process/GetProcessById |
| `ref:721bccf01f` | PE structure parsing | stage4 PE32 GUI, 537,600 bytes, 5 sections, 11 imported DLLs |
| `ref:832b9679eb` | Import table parsing | stage4 import table: keyboard/clipboard/screenshot/microphone/browser/network/registry/process-injection APIs |
| `ref:fe1f91224b` | script | stage4 strings: Remcos markers, browser data paths, Run key, download/execute and configuration fields |
| `ref:6d0dd9a821` | String extraction | stage4 string scan: TLS, download, browser paths etc. |
| `ref:28008768b2` | decompile | 0x41FA84: FindResourceA reads RT_RCDATA SETTINGS |
| `ref:3b325ab8d3` | decompile | 0x414E65: reads the SETTINGS resource and splits key/ciphertext |
| `ref:384c1f1c72` | script | RC4 with the 34-byte key from the resource, decrypting readable configuration |
| `ref:224db4a8ef` | script | Full configuration fields: C2, mutex, exe, logs.dat, Screenshots, MicRecords, license, X.509 certificate |
| `ref:672ee2e1d4` | evidence.record | Multi-stage decode chain and final configuration summary (self-described evidence) |

</details>

---

_This sample is not public; IOCs are defanged. For security research only._
