---
title: "Malware Sample Analysis: Agent Tesla (PE · exe · 30eed7cc)"
published: 2026-11-23
draft: false
description: "Malicious (confidence medium): Agent Tesla · stealer/loader · difficulty hard · dynamic sandbox + static decompilation"
tags: ["Agent Tesla", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-23-Agent-Tesla-30eed7cc"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Agent Tesla** (suspected) · Confidence **medium**
> 
> Aliases: AgentTesla, OriginLogger, Negasteal
> 
> The sample is a .NET NativeAOT program disguised as Birch Desktop Utility / peridot.dll v3.7.2.6. In the dynamic sandbox it survived for about 3 minutes, during which an argument-less csc.exe process appeared; memory forensics showed that the process's original PE header had been replaced, that a MEM_MAPPED injected .NET assembly existed in its working set, and that amsi.dll, clr.dll, and ntdll.dll had been memory-patched. After the injected assembly ran, it decrypted a complete credential-stealing string table (browser login databases, Windows Vault, mail/FTP/VNC/VPN clients, keylogging, screenshots, Tor and mail/FTP/Web panel exfiltration templates), making it clearly information-stealing malware.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Agent Tesla** · aliases AgentTesla, OriginLogger, Negasteal · _suspected_ |
| Confidence | **medium** |
| Behavior class | stealer · loader |
| Difficulty | hard |
| First seen | 2026-11-23 07:32:35 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/30eed7cc22eca8d8e9bdbc77413b05a1a3b5f18426c153f084981fde111bd4cc/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Disguised as desktop utility brand</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Execution via injected compiler process</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">AMSI bypass via memory patching</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Decrypt built-in stealing string table</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Steal browser and system credentials</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `30eed7cc22eca8d8e9bdbc77413b05a1a3b5f18426c153f084981fde111bd4cc` |
| MD5 | _not recorded_ |
| Size | 1,780,286 bytes (1.7 MB) |
| Type | PE · `exe` |

## Behavioral Analysis

**10** behaviors in total, each backed by evidence; **7** were obtained statically and **3** through dynamic analysis.

### 1. Disguised as a Desktop Utility Brand

`T1036.005` · Confidence **high** · Static

The PE resource version information is disguised as CompanyName=Birch, ProductName=Birch Desktop Utility, InternalName/OriginalFilename=peridot.dll, FileVersion 3.7.2[.]6, with manifest name Birch.DesktopUtility; the binary is an unsigned NativeAOT .NET single file, intended to lower suspicion from users and endpoint protection.

> **Evidence**: VS_VERSION_INFO at file offset 0x139194 (Birch Desktop Utility / peridot.dll); manifest assemblyIdentity name="Birch.DesktopUtility" at 0x13943c; the string "Fatal error. .NET runtime failed to initialize." together with CoreCLR runtime strings indicates NativeAOT .NET
> 
> **Source**: `ref:9c68760627` · `ref:8accf5bb75` · `ref:f80506a6e0`

### 2. Execution via Injected Compiler Process

`T1055.012` · Confidence **high** · Dynamic

Within the analysis window, C:\Windows\Microsoft[.]NET\Framework\v4.0.30319\csc.exe (PID 2420) started with no arguments and remained alive; memory forensics shows its main module's PE header was replaced (DOS/file/NT headers and entry point all modified) and a MEM_MAPPED portable executable implant existed in its working set (base 0x260000), consistent with process hollowing / assembly memory injection.

> **Evidence**: memory forensics report: main_image_path=csc.exe, is_managed=1, headers_scan is_pe_replaced=1/ep_modified=1/nt_hdr_modified=1; workingset_scan has_pe=1 @0x260000 size 0x1cc000; system telemetry at 17:27:51 created csc.exe (command line is only the image path), at 17:30:57 the process was still being scanned
> 
> **Source**: `ref:ab478739dd` · `ref:456b1985f9` · `ref:fa5fe72aea`

### 3. AMSI Bypass via Memory Patching

`T1562.001` · Confidence **high** · Dynamic

In the injected csc.exe, 1 code patch was found in amsi.dll, 12 patches in clr.dll, and 2 patches in ntdll.dll — disabling AMSI scanning at runtime and tampering with CLR/syscall paths so the encrypted .NET stealing module could be loaded and executed.

> **Evidence**: memory forensics code_scan: amsi.dll patches=1, clr.dll patches=12, ntdll.dll patches=2; clr.dll patch offsets 0x100e4-0x10cd8 (labels patch_0..patch_11)
> 
> **Source**: `ref:ab478739dd`

### 4. Decrypting the Built-in Stealing String Table

`T1027` · Confidence **high** · Dynamic

Complete plaintext string tables that do not exist in the static file appear in the injected process's memory: install/persistence templates (%insname%, %insfolder%, %insregname%, %startupfolder%), Tor configuration templates (%tordir%, %hash%, %torpass%), exfiltration templates (%ftphost%, %ftpuser%, %ftppassword%, %urlkey%, %PostURL%), and lists of browser/credential client paths, indicating that the payload decrypts strings in memory and then executes.

> **Evidence**: from memory offset 0x9b3d8a in the injected process: "%startupfolder%\\%insfolder%\\%insname%", "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "%tordir%\\Data\\Tor"; from 0x9b64b0: "hxxp://127.0.0[.]1:", "POST", "%PostURL%"; from 0x9b6712: Tor download address
> 
> **Source**: `ref:77ef06292d` · `ref:eba426a687`

### 5. Stealing Browser and System Credentials

`T1555.003` · Confidence **high** · Static

The payload contains parsers for Chromium-based browsers (Chrome/Edge/Opera/Yandex/Brave/Vivaldi/360/QQ/UC/CocCoc/Torch/7Star/Citrio, etc.) "Login Data"/"Local State" and for Firefox logins.json, signons.sqlite, key3.db/key4.db, cookies.sqlite, and enumerates Windows Vault GUIDs (Windows Web Password Credential, Windows Credentials, Web Credentials, etc.) to read system-saved passwords; it also includes RDP Credential Manager extraction logic.

> **Evidence**: from injected process memory 0x9b4c7e: "\\Default\\Login Data", "logins", "cookies.sqlite", "key4.db", "Windows Web Password Credential", "Windows Credential Picker Protector", "RDP", "credentialpolicy", "blob"; payload .NET metadata contains references to vaultcli.dll/VaultEnumerateVaults/VaultGetItem
> 
> **Source**: `ref:77ef06292d` · `ref:59d3b9b646`

### 6. Keylogging and Clipboard Capture

`T1056.001` · Confidence **high** · Static

The payload references SetWindowsHookEx, CallNextHookEx, GetKeyboardState, ToUnicodeEx, MapVirtualKey, GetKeyboardLayout, GetForegroundWindow/GetWindowText and hooks into the clipboard viewer chain (SetClipboardViewer/ChangeClipboardChain), producing keylogs with HTML color markup (KL_*.html) and clipboard text records ("Copied Text:").

> **Evidence**: payload .NET metadata: SetWindowsHookEx, ToUnicodeEx, GetKeyboardState, ChangeClipboardChain, get_Clipboard; injected process memory contains "KL_", "Copied Text: ", "{ALT+TAB}"/"{CAPSLOCK}" key name templates and color #00ba66
> 
> **Source**: `ref:59d3b9b646` · `ref:77ef06292d`

### 7. Screenshots and Host Information Collection

`T1113` · Confidence **high** · Static

The payload uses Graphics.CopyFromScreen + Bitmap/ImageFormat.Jpeg to capture screenshots (SC_*.jpeg), and uses WMI queries on Win32_Processor, Win32_NetworkAdapterConfiguration, Win32_BaseBoard plus SystemInformation to collect hostname, username, OS version, CPU, memory, IP/MAC, and motherboard serial number, building a victim profile.

> **Evidence**: injected process memory contains "SELECT * FROM Win32_Processor", "Win32_NetworkAdapterConfiguration", "IPEnabled", "MacAddress", "Win32_BaseBoard", "SerialNumber", "SC_.jpeg", "Screenshot", "image/jpeg"; payload metadata contains get_Screen/CopyFromScreen/ManagementObjectSearcher
> 
> **Source**: `ref:77ef06292d` · `ref:59d3b9b646`

### 8. Deploying a Covert Tor Channel

`T1090.003` · Confidence **high** · Static

The payload embeds a torrc template (DataDirectory %tordir%\Data\Tor, ControlPort 9051, CookieAuthentication 1, hashedcontrolpassword %hash%, AvoidDiskWrites 1) and plans to download Tor 9.5.3 from hxxps://www.theonionrouter[.]com/.../tor-win32-0.4.3[.]6.zip, then launch tor.exe, wait for "Bootstrapped 100%", and issue SIGNAL NEWNYM through control port 9051, hiding callbacks/exfiltration inside the Tor network.

> **Evidence**: injected process memory 0x9b6522-0x9b6712: "AUTHENTICATE \"%torpass%\"", "SIGNAL NEWNYM", "ControlPort 9051", "hashedcontrolpassword %hash%", "Bootstrapped 100%", tor-win32-0.4.3[.]6.zip download address
> 
> **Source**: `ref:eba426a687` · `ref:77ef06292d`

### 9. Multi-Channel Exfiltration of Stolen Logs

`T1048.003` · Confidence **high** · Static

The payload implements SMTP attachment sending (MailMessage/SmtpClient, with an account configuration model), FTP upload (FtpWebRequest, %ftphost%/%ftpuser%/%ftppassword%), Web panel HTTP POST (webpanel/PostURL/%urlkey%), and multipart/form-data chat_id/document upload, packaging keylogs, screenshots, cookies, and credentials into CO_*.zip, SC_*.jpeg, and KL_*.html for exfiltration.

> **Evidence**: injected process memory: "webpanel", "PostURL", "multipart/form-data; boundary=", "chat_id", "sendDocument", "CO_", "SC_", "KL_", "application/zip", "%ftphost%/%ftpuser%%ftppassword%"
> 
> **Source**: `ref:77ef06292d` · `ref:eba426a687`

### 10. Autostart via Run Key

`T1547.001` · Confidence **medium** · Static

The payload embeds persistence templates: copy itself to %startupfolder%\%insfolder%\%insname%, write HKCU\Software\Microsoft\Windows\CurrentVersion\Run (value name %insregname%) and the Load value of HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows, and handle StartupApproved\Run to avoid the startup entry being disabled; no actual registry writes or file drops were observed during this analysis window.

> **Evidence**: injected process memory 0x9b3e84: "%startupfolder%\\%insfolder%\\%insname%", "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "%insregname%", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\R", "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "Load"
> 
> **Source**: `ref:eba426a687` · `ref:77ef06292d`


## IOCs (Defanged)

### Network

:::note
**No C2 / network IOCs were recovered** (see "Analysis Method and Limitations" at the end).
:::

### Host

**Drop paths**

- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\%insfolder%\%insname%`
- `%TEMP%\ (runtime temp file templates: CO_*.zip / SC_*.jpeg / KL_*.html / log.tmp)`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run (value name %insregname%)`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`
- `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows (value Load)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `payload_injection_host` | `C:\Windows\Microsoft[.]NET\Framework\v4.0.30319\csc.exe` | Yes | Dynamic |
| `exfil_channels` | `SMTP(MailClient/SmtpClient attachment) + FTP(FtpWebRequest) + Web panel HTTP POST(%urlkey%/%PostURL%) + optional Telegram-style multipart upload` | Yes | Static |
| `tor_channel` | `Built-in torrc template: DataDirectory %tordir%\Data\Tor / ControlPort 9051 / CookieAuthentication 1 / hashedcontrolpassword %hash%` | No | Static |
| `tor_install_source` | `hxxps://www.theonionrouter[.]com/dist[.]torproject[.]org/torbrowser/9.5.3/tor-win32-0.4.3[.]6.zip` | No | Static |
| `persistence_templates` | `%startupfolder%\%insfolder%\%insname%; HKCU\...\CurrentVersion\Run:%insregname%; HKCU\...\Windows NT\CurrentVersion\Windows:Load; StartupApproved record` | Yes | Static |
| `credential_targets` | `Chromium/Firefox browser logins and cookies (all variants); Windows Vault; Windows RDP; FileZilla/WinSCP/SmartFTP/FlashFXP/CoreFTP/WS_FTP/FTPGetter; The Bat!/Outlook/Foxmail/Becky!/eM Client/Mailbird/PocoMail/IncrediMail/Eudora/Claws Mail; Pidgin/Trillian; UltraVNC/TightVNC; DynDNS/No-IP/Psi+/OpenVPN/NordVPN/PIA/IDM/MySQL Workbench` | Yes | Static |
| `campaign_id` | `-` | No | Static |

## Avoid Misjudging

:::important
The following conclusions are **easy to misjudge**; please take note when citing this report.

- Do not claim the sample completed data exfiltration: network monitoring recorded no outbound connections from the sample process or its injected process during the analysis window; SMTP/FTP/Web panel/Tor are only built-in capabilities and templates of the payload.
- Do not classify it as ransomware or a wiper: no file encryption, deletion, or ransom-note behaviors or strings were found.
- Do not claim persistence was established: the Run key, Startup folder, and Windows Load value appear only in decrypted template strings; telemetry contains no corresponding registry writes or file creation events.
- Do not claim lateral movement occurred: no SMB/remote service creation or remote host connections were observed; the only injection target was the local csc.exe.
- Do not directly attribute the injected process's parent to the sample: system telemetry does not record a parent process field; the parent-child relationship is inferred from the timeline and the single malicious actor.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. No external C2 addresses, keys, mutexes, or campaign IDs were recovered: the payload configuration is decrypted at runtime, and no plaintext C2 or .onion addresses appear in the static file or either of the two memory dumps.
2. Network monitoring recorded no connections from the sample process or its injected process, so the C2 list is empty; exfiltration can only be assessed as a built-in capability, not as something that occurred.
3. The parent process field of the injected csc.exe does not appear in system telemetry; "the sample created this process" is inferred from the timeline (an argument-less csc.exe appeared 44 seconds after the sample started, and no other malicious actor existed in the window), not from direct parent-child evidence.
4. The payload .NET assembly is obfuscated (type/method names renamed to one or two letters, user strings encrypted); readable information comes from in-memory plaintext string tables and metadata references, so family attribution is based on feature matching rather than vendor naming.
5. Defender and AMSI events are empty in the telemetry, so it cannot be confirmed whether endpoint protection alerted on or blocked the sample.
6. The sandbox guest was rolled back after analysis, and no runtime-dropped files were retained; persistence and residence paths are all inferred from templates.

## Evidence Index

<details>
<summary>Expand 18 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:9696b2a8be` | Sample triage | M1 triage: prefix/suffix hashes, 6 sections, entropy, import surface, and packing score 0 |
| `ref:f80506a6e0` | PE structure parsing | PE structure: AMD64, GUI subsystem, 6 sections (.text/.rdata/.data/.pdata/.fptable/.rsrc), unsigned data directory |
| `ref:0a59e3baa0` | Import table parsing | 5 DLLs / 146 imports, including bcrypt, ole32, KERNEL32, and KERNELBASE (NativeAOT runtime shape) |
| `ref:8accf5bb75` | String extraction | Strings contain "Fatal error. .NET runtime failed to initialize." and CoreCLR/.NET Runtime markers, confirming NativeAOT .NET |
| `ref:9c68760627` | String extraction | Resource section strings: Birch Desktop Utility / peridot.dll / v3.7.2.6 / manifest Birch.DesktopUtility |
| `ref:387a4ecebf` | Cryptographic constant identification | Hit TEA/XTEA golden-ratio constant 0x9E3779B9 (obfuscated string decryption constant) |
| `ref:0c3c268324` | dyn.run | Emulation ran only to .NET runtime initialization (FlsAlloc/VirtualProtect) and did not enter business logic |
| `ref:957e51302c` | unpack.detect | Statically determined to be unpacked (packed=false) |
| `ref:18024335f5` | Dynamic analysis platform | Real dynamic run: sample PID 4032 executed, 6 memory dumps captured, no new child processes recorded in the window |
| `ref:fa5fe72aea` | watch.timeline | Timeline: sample 4032 spawned, two dump rounds t0/t3, no hollows hits |
| `ref:456b1985f9` | telemetry.sysmon | System telemetry process creation: sample 4032, argument-less csc.exe 2420 (17:27:51), injection tool scan record |
| `ref:ab478739dd` | memory.forensics | csc.exe 2420 memory forensics: main module PE header replacement, MEM_MAPPED injected PE at 0x260000, amsi/clr/ntdll code patches |
| `ref:59d3b9b646` | metadata.parse | Injected assembly metadata: references to SetWindowsHookEx/ToUnicodeEx/VaultGetItem/WebClient/SmtpClient/BCrypt, etc. |
| `ref:77ef06292d` | memory.strings | Decrypted string tables in injected process memory: browser/mail/FTP/VNC/VPN credential targets, exfiltration templates, Tor templates, keylogger templates |
| `ref:eba426a687` | memory.strings | Exfiltration and Tor details in memory: webpanel/PostURL/%urlkey%/ControlPort 9051/hashedcontrolpassword/download address |
| `ref:3aa704b08e` | hash.artifacts | Recovered artifact hashes: asm_big.bin / asm_small.bin / 260000.csc.exe |
| `telemetry:30eed7cc` | Dynamic telemetry | Dynamic telemetry recorded: monitor component process/file events 120; ETW short-lived process events 1; tool/system noise filtered 22 |
| `etw:30eed7cc:4032` | Process event monitoring | Short-lived process event: 30eed7cc22eca8d8e9bdbc77413b05a1a3b5f18426c153f084981fde111bd4cc.exe (pid 4032; MD5=5010B8399509839408562B25414645BC,SHA256=30EED7CC22ECA8D8E9BDBC77413B05A1A3B5F18426C153F084981FDE111BD4CC,IMPHASH=34C1613AD57F5792B6BB9A7A4B724D84) |

</details>

---

_The sample in this report is not public; IOCs have been defanged; for security research only._
