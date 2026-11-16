---
title: "Malware Analysis: Agent Tesla (other · vbe · fdbdf977)"
published: 2026-11-15
draft: false
description: "Malicious (high confidence): Agent Tesla · stealer/injector/loader · difficulty medium · purely static analysis"
tags: ["Agent Tesla", "stealer", "injector", "loader"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-15-Agent-Tesla-fdbdf977"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Agent Tesla** · Confidence **High**
> 
> Aliases: AgentTesla, OriginLogger
> 
> The sample is a plaintext VBScript dropper with a fake .vbe extension: it first drops and launches an embedded PowerShell script, which decrypts a second PowerShell layer with AES-256-CBC and then restores a .NET injector and the final PE via Base64+repeated-key XOR; the injector hollows the final PE into aspnet_compiler.exe. The final payload has browser/email/FTP credential theft, keylogging, clipboard collection, screen capture and SMTP/Telegram exfiltration capabilities, making it a typical Agent Tesla family stealer. Every step above is directly confirmed by static decryption, strings and PE/CLI metadata, with no legitimate business function seen.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Agent Tesla** · aliases AgentTesla, OriginLogger |
| Confidence | **High** |
| Behavior class | stealer · injector · loader |
| Difficulty | medium |
| First seen | 2026-11-13 13:39:05 |
| Analysis method | Purely static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/fdbdf9779f45ab3732628f78bd7c4c4f3862285edae7dd3e0d2908e48f192336/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Drop and run PowerShell</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Two-layer payload decryption</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Reflectively load .NET injector</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Hollow into legitimate host</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Keylog user input</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `fdbdf9779f45ab3732628f78bd7c4c4f3862285edae7dd3e0d2908e48f192336` |
| MD5 | _not recorded_ |
| Size | 706,317 bytes (689.8 KB) |
| Type | other · `vbe` |

## Behavior Analysis

**11** behaviors in total, each backed by evidence, and all are statically available.

### 1. Drop and run PowerShell

`T1059.001` · Confidence **High** · Static

The VBScript decodes the embedded Base64 into a .ps1 file under C:\Temp\, then executes it with powershell.exe -nop -ep bypass -file and deletes the script afterwards.

> **Evidence**: vbe off 0x139 g_payloadB64; PhaseWriteScript writes C:\Temp\<random>.ps1; PhaseExecute calls g_shell.Run with -nop -ep bypass
> 
> **Source**: `ref:7c4137b89c` · `ev-000004`

### 2. Two-layer decryption of embedded payload

`T1140` · Confidence **High** · Static

The first PowerShell layer decrypts a large Base64 blob with a hardcoded AES-256-CBC key/IV; the second layer restores Base64 with repeated-key XOR and decodes it into a .NET assembly.

> **Evidence**: stage1.ps1 $encryptedPayload; AES key f8fb6c0d...; stage2.ps1 ConvertFrom-MaskedBlob, XOR key ZZaDazKA6@@^^
> 
> **Source**: `ev-000004`

### 3. Reflectively load the .NET injector

`T1620` · Confidence **High** · Static

The second-layer script loads a 64,000-byte assembly in memory via [Reflection.Assembly]::Load and reflectively calls static method LAUNCHER of type DEVV.WHORE.

> **Evidence**: stage2.ps1 Invoke-InMemoryAssembly: [Reflection.Assembly]::Load; type DEVV.WHORE, method LAUNCHER; stage3 PE/CLI headers confirm a .NET DLL
> 
> **Source**: `ev-000004` · `ev-000001` · `ref:0a2e59969d`

### 4. Hollow into a legitimate host

`T1055.012` · Confidence **High** · Static

The injector creates a suspended process targeting aspnet_compiler.exe, unmaps its image, allocates memory, writes the PE headers and sections, rewrites the thread context and resumes execution, completing process hollowing.

> **Evidence**: stage3 UTF-16 off 0xc2d8 CreateProcessA, 0xc246 VirtualAllocEx, 0xc264 WriteProcessMemory, 0xc2ae ZwUnmapViewOfSection, 0xc1aa SetThreadContext, 0xc190 ResumeThread, 0xc0de 'Failed to update PEB'; stage2 passes hostExe and the embedded PE
> 
> **Source**: `ev-000001` · `ref:0a2e59969d` · `ev-000004`

### 5. Keylogging to steal input

`T1056.001` · Confidence **High** · Static

The payload installs a global keyboard hook and records the foreground window and keystrokes, forming a keyboard log.

> **Evidence**: stage4 off 0xe688 SetWindowsHookExA; 0x10451 StartKeylogger; #Strings KeyLogger/KeyboardProc/GetForegroundWindow
> 
> **Source**: `ev-000002` · `ev-000006`

### 6. Steal browser-saved credentials

`T1555.003` · Confidence **High** · Static

Enumerates dozens of browser profiles including Chrome/Edge/Brave/Firefox, reads Login Data/logins.json, and decrypts saved usernames and passwords with DPAPI or NSS.

> **Evidence**: stage4 UTF-16 off 0x12d5e 'Login Data' and other paths; 0xeaa8 CryptUnprotectData; #Strings NSS_Init/PK11SDR_Decrypt/password_value
> 
> **Source**: `ev-000002` · `ev-000006`

### 7. Read email and FTP credentials

`T1555` · Confidence **High** · Static

Reads Outlook profiles and registry, the Foxmail install path, Thunderbird/SeaMonkey profiles and FileZilla recentservers.xml, extracting accounts and passwords.

> **Evidence**: stage4 off 0x12ace Foxmail.url.mailto; Outlook Profiles registry key; FileZilla recentservers.xml; POP3/IMAP/SMTP/HTTP Password fields
> 
> **Source**: `ev-000002` · `ev-000006`

### 8. Screen capture and clipboard collection

`T1113, T1115` · Confidence **High** · Static

Captures the screen on a timer and reads clipboard contents, returning them as separate log categories.

> **Evidence**: stage4 off 0x10de0 TakeScreenshot; 0xea69 GetClipboardData; #Strings ClipboardVault/ScreenshotVault/OpenClipboard
> 
> **Source**: `ev-000002` · `ev-000006`

### 9. Email and Telegram exfiltration

`T1048` · Confidence **High** · Static

Packages stolen credentials, keyboard logs, screenshots and host information, and exfiltrates them via SMTP(587) email or the Telegram Bot sendDocument API.

> **Evidence**: stage4 UTF-16 off 0x11a89 mail[.]merchantinvestnetwork[.]com; 0x11a27/0x11ac7 two accounts; 0x11ee7 api[.]telegram[.]org/bot and 0x11f21 /sendDocument?chat_id=; #SMTPEnabled/#TGEnabled switches
> 
> **Source**: `ev-000006` · `ev-000002`

### 10. Disable security and system tools

`T1562.001` · Confidence **Medium** · Static

The payload contains code paths to disable Windows Defender, Task Manager, Registry Editor and the command prompt, reducing the victim's ability to investigate.

> **Evidence**: stage4 off 0xe6e1 DisableWD; 0x1047a Taskmgr_Disabler; 0x1048b Registeries_Disabler; #Strings CMD_Disabler/EmptyBlocker
> 
> **Source**: `ev-000002` · `ev-000006`

### 11. Probe IP and geolocation

`T1016` · Confidence **High** · Static

Obtains the victim's public IP, country and time information through external IP-echo and geolocation services, attaching them to the exfiltration email.

> **Evidence**: stage4 US 'hxxp://checkip[.]dyndns[.]org/' and 'hxxps://reallyfreegeoip[.]org/xml/'; INFO_SystemIP/INFO_Country/INFO_Date_Time fields
> 
> **Source**: `ev-000002` · `ev-000006`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| smtp | `mail[.]merchantinvestnetwork[.]com` | 587 | exfil | Static | ⏳ Not observed |
| telegram | `hxxps://api[.]telegram[.]org/bot<TOKEN>/sendDocument?chat_id=<ID>` | 443 | exfil | Static | ⏳ Not observed |

### Host

**Dropped paths**

- `C:\Temp\<8 random uppercase letters>.ps1`
- `C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe`
- `%APPDATA%\UserData.txt`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `mail[.]merchantinvestnetwork[.]com; api[.]telegram[.]org` | Yes | Static |
| `c2_port` | `587 (SMTP); 443 (Telegram)` | Yes | Static |
| `c2_uri` | `hxxps://api[.]telegram[.]org/bot<TOKEN>/sendDocument?chat_id=<ID>` | No | Static |
| `smtp_accounts` | `rocky@merchantinvestnetwork[.]com; rocee@merchantinvestnetwork[.]com` | Yes | Static |
| `smtp_password` | `69)}!t9lT9om:b!&` | Yes | Static |
| `encryption_algo` | `AES-256-CBC (first layer); Base64+repeated-key XOR (second layer); AES-GCM/TripleDES/DPAPI (inside payload)` | Yes | Static |
| `aes_key` | `f8fb6c0d59cc8079de52d6a91ecc283bd63253b9ce8676c476056f8d3d00dafa` | Yes | Static |
| `aes_iv` | `42df37eb27d3b70287401a7048f9b10c` | Yes | Static |
| `xor_key` | `ZZaDazKA6@@^^` | Yes | Static |
| `injector_host` | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe` | Yes | Static |
| `log_path` | `%APPDATA%\UserData.txt` | No | Static |

## What Not to Misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not classify it as ransomware: although the sample uses AES/TripleDES, no file-walking encryption, extension rewriting or ransom notice was found; its cryptography only protects configuration/credentials and exfiltration.
- Do not classify it as a downloader: each stage payload is embedded and decrypted layer by layer, and no runtime logic to download the next stage over HTTP/FTP was observed.
- Do not assert persistence was established: static analysis found no Run key, service or scheduled-task writes, and it cannot be inferred that it is resident merely from common stealer behavior.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Purely static analysis |
| Unpacking | Yes (stage2 `fe0c88cdf01e3ba06f1bae487812f96b7b314671972b2cf87507d08a4266c955`) |

**Limitations and pending verification**

1. This environment performed static analysis only and did not detonate in an isolated Windows environment, so the SMTP and Telegram exfiltration channels and the process-hollowing result were not dynamically verified; C2 is uniformly marked static with pending_dynamic_verify=true.
2. The Telegram Bot token, chat_id and FTP host/password were not recovered in plaintext, possibly because they are encrypted at build time or generated at runtime; currently only the Telegram Bot API call template and the #FTPEnabled switch can be confirmed.
3. No persistence code was observed, and delivery/re-residency via an external email attachment, archive or macro document cannot be ruled out.
4. The stage3 injector is name-obfuscated; the injection implementation was judged from its UTF-16 API names, failure messages and call parameters, without dynamic memory forensics.
5. Browser/email-client credential reading depends on the software and user configuration actually present on the victim host, and the static stage cannot confirm how much data was actually stolen.

## Evidence Index

<details>
<summary>Expand 8 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000004` | Scripted forensics | Extracted Base64 from the .vbe, decoded the first PS1 layer, decrypted the second PS1 layer with the embedded AES-256-CBC key/IV, restored stage3/stage4 via XOR/Base64, and recorded SHA-256 at each stage and the injection host. |
| `ev-000006` | evidence.record(manual) | Extracted the SMTP server/account/password, Telegram API template, IP-probing addresses and theft/anti-analysis capability strings from stage4 string offsets. |
| `ev-000001` | String extraction | stage3 injector strings: CreateProcessA/ZwUnmapViewOfSection/VirtualAllocEx/WriteProcessMemory/SetThreadContext/ResumeThread, plus hollowing-failure messages such as 'Failed to update PEB'. |
| `ev-000002` | String extraction | stage4 payload strings: browser Login Data paths, Outlook/Foxmail/FileZilla credentials, SetWindowsHookExA, clipboard/screenshot, SMTP/Telegram exfiltration and anti-analysis class names. |
| `ev-000005` | Cryptographic constant identification | MD5 T-table constants identified in stage3 (off 0xf200), indicating the injector uses MD5 internally. |
| `ref:0a2e59969d` | PE structure parsing | stage3 is a 32-bit .NET DLL (only mscoree imported, no anomalous section table), consistent with the reflective loader description. |
| `ref:7a0ebd471f` | PE structure parsing | stage4 is a 32-bit .NET GUI PE (only mscoree imported, 3 sections), the final stealing payload. |
| `ref:7c4137b89c` | String extraction | Original .vbe string evidence: WORK_DIR=C:\Temp\, PS_LAUNCH=powershell.exe -nop -ep bypass -file, g_payloadB64 starting Base64. |

</details>

---

_This report's sample is not public, IOCs are defanged, and it is for security research only._
