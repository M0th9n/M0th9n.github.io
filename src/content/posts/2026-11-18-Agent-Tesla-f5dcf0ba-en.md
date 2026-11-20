---
title: "Malware Analysis: Agent Tesla (other · vbe · f5dcf0ba)"
published: 2026-11-18
draft: false
description: "Malicious (high confidence): Agent Tesla · stealer/loader/spyware · difficulty hard · pure static analysis"
tags: ["Agent Tesla", "stealer", "loader", "spyware"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-18-Agent-Tesla-f5dcf0ba"
---

> [!WARNING]
> **Verdict: malicious** · Family **Agent Tesla** · Confidence **high**
> 
> Aliases: AgentTesla, Agent-Tesla
> 
> The sample is a plaintext VBScript wrapper (.vbe): it first drops and runs PowerShell, then decrypts the second-stage PowerShell via Base64 + GZip + AES-256-CBC/PKCS7, afterwards recovers the .NET loader with a fixed XOR key, and loads the CloudServices assembly by reflectively invoking DEVVV.WHORE.LAUNCHER. That CloudServices assembly contains SMTP, FTP and Telegram exfiltration channels, plus browser/email client credential theft, keylogging, clipboard theft, screenshots and disabling of security tools, giving it full information-stealer capability.

## Overview

| Item | Content |
|:--|:--|
| Family | **Agent Tesla** · aliases AgentTesla, Agent-Tesla |
| Confidence | **high** |
| Behaviour class | stealer · loader · spyware |
| Difficulty | hard |
| First seen | 2026-11-16 16:00:02 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/f5dcf0baa347c29202f8c4cf7ca69f5e3e2d1a627fba29e9a20209f45489313d/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Drop and run PowerShell</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.005; T1059.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded PowerShell</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027; T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">XOR-recover .NET payload</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027; T1140</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Reflectively load payload assembly</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Poll sentinel, trigger after delay</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `f5dcf0baa347c29202f8c4cf7ca69f5e3e2d1a627fba29e9a20209f45489313d` |
| MD5 | _not recorded_ |
| Size | 692,060 bytes (675.8 KB) |
| Type | other · `vbe` |

## Behaviour analysis

**12** behaviours in total, each tied to evidence, and all statically recoverable.

### 1. Drop and run PowerShell

`T1059.005; T1059.001` · Confidence **high** · static

The VBE wrapper creates a .ps1 named with 8 random uppercase letters in C:\Temp\ and runs it silently with powershell.exe -nop -ep bypass -file, then deletes the temporary script.

> **Evidence**: original .vbe off 0x00b4 constant TEMP_DIR=C:\Temp\, off 0x00ef PS_LAUNCH_CMD=powershell.exe -nop -ep bypass -file; StepDecodeAndWrite/StepInvoke/StepRemoveArtifacts
> 
> **Source**: `ref:3bbbb40ff4` · `ev-000003`

### 2. Decrypt the embedded PowerShell

`T1027; T1140` · Confidence **high** · static

The first-stage PowerShell verifies the SHA-256 of the embedded GZip ciphertext, decompresses it, then decrypts the second-stage script with a hardcoded AES-256 key and IV in CBC/PKCS7.

> **Evidence**: in stage1.ps1 $B64_Key=UeYqzFDWifEEtogvXiIzCbr/B4b3Nq1iP+IHTzWzNL8=, $B64_IV=5YrDgjSfmp7p7goaohQbIQ==, Expand-GZipBytes/Invoke-AesDecrypt
> 
> **Source**: `ev-000003`

### 3. XOR-recover the .NET payload

`T1027; T1140` · Confidence **high** · static

The second-stage script first decodes the Base64 text, then applies repeating-key XOR with the fixed 13-byte key ZZaDazKA6@@^^, yielding the .NET assembly in Base64 form, which it decodes again.

> **Evidence**: stage2.ps1 function ConvertFrom-MaskedBlob; $xorKey=ZZaDazKA6@@^^; $encodedFragment length 0x1A000
> 
> **Source**: `ev-000003`

### 4. Reflectively load the payload assembly

`T1620` · Confidence **high** · static

The script calls [Reflection.Assembly]::Load to load the recovered .NET DLL and reflectively executes type DEVVV.WHORE, method LAUNCHER, passing the aspnet_compiler.exe path and the second PE byte array as arguments.

> **Evidence**: stage2.ps1 Invoke-InMemoryAssembly; TypeName 'DEVVV.WHORE'; MethodName 'LAUNCHER'; $hostExe=C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe
> 
> **Source**: `ev-000003`

### 5. Poll a sentinel, then trigger after a delay

`T1497` · Confidence **high** · static

The loader uses aspnet_compiler as a sentinel process, checking every 5 seconds; it continues executing the payload only when the sentinel process is absent, forming a delay/environment evasion.

> **Evidence**: stage2.ps1 Start-WatchLoop: $Sentinel="aspnet_compiler", $IntervalSeconds=5, Test-ProcessAbsent
> 
> **Source**: `ev-000003`

### 6. Disable Task Manager and Registry

`T1562.001` · Confidence **medium** · static

The payload contains Taskmgr_Disabler, Registeries_Disabler and DisableWD related methods/strings, used to disable Task Manager, Registry Editor and security-protection related functionality.

> **Evidence**: extraData.pe #Strings off 0x1047a 'Taskmgr_Disabler', off 0x1048b 'Registeries_Disabler', off 0x0e6e1 'DisableWD'
> 
> **Source**: `ev-000004` · `ref:488c53a4b7`

### 7. Steal browser-saved passwords

`T1555.003` · Confidence **high** · static

It walks the profile directories of browsers such as Chrome, Edge, Firefox, Opera, Brave, Vivaldi, QQ, 360 and UC, reads Login Data/logins.json, and decrypts the stored account passwords using DPAPI, BCrypt AES-GCM, TripleDES, etc.

> **Evidence**: extraData.pe off 0x13527 UTF-16 '\Google\Chrome\User Data\Default\Login Data'; classes/methods CredentialModel, SQLiteHandler, FFDecryptor, MozilSpeed, AesGcm, BCrypt, CryptUnprotectData
> 
> **Source**: `ev-000004` · `ref:488c53a4b7`

### 8. Keylogging and clipboard theft

`T1056.001; T1115` · Confidence **high** · static

It installs a keyboard hook via SetWindowsHookExA/GetKeyboardState and starts KeyLogger, while reading and replacing clipboard content to steal copied data.

> **Evidence**: extraData.pe off 0x0e688 'SetWindowsHookExA', off 0x10451 'StartKeylogger', off 0x10260 'ClipboardReplacer', off 0x0f5d1 'GetKeyboardState'
> 
> **Source**: `ev-000004` · `ref:488c53a4b7`

### 9. Screenshot and package for exfiltration

`T1113` · Confidence **high** · static

It invokes screenshot functionality to produce .png files, uploads them to the / SCREENSHOT / directory via FTP STOR, or exfiltrates them as email/Telegram attachments.

> **Evidence**: extraData.pe off 0x10de0 'TakeScreenshot'; method name 'ScreenshotSender'; #US strings ' / SCREENSHOT / ', '.png', 'STOR'
> 
> **Source**: `ev-000004`

### 10. Exfiltrate stolen data via SMTP

`T1048` · Confidence **high** · static

It uses System.Net.Mail.SmtpClient to connect to mail[.]merchantinvestnetwork[.]com:587, authenticates with bossy@merchantinvestnetwork[.]com, and sends UserData.txt, screenshots, etc. as multipart attachments to bosskkk@merchantinvestnetwork[.]com.

> **Evidence**: extraData.pe off 0x11a27 / RVA 0x13827 '#SMTPEnabled' and the SMTP host, account, password and recipient; off 0x11a89 mail[.]merchantinvestnetwork[.]com; SmtpClient/MailMessage/multipart/form-data
> 
> **Source**: `ev-000004` · `ref:942b62e991`

### 11. Collect email client credentials

`T1555` · Confidence **high** · static

It reads Outlook profile registry keys and decrypts IMAP/POP3/HTTP/SMTP passwords, while also parsing Foxmail's Account.rec0 to obtain email accounts and passwords.

> **Evidence**: extraData.pe #US 'GetOutlookPasswords'/'decryptOutlookPassword'; Outlook Profiles keys; 'Foxmail', '\\Accounts\\Account.rec0', 'POP3Password'
> 
> **Source**: `ev-000004`

### 12. Probe IP and support multi-channel exfiltration

`T1016; T1102; T1048` · Confidence **high** · static

It obtains the victim's public IP and country via checkip[.]dyndns[.]org and reallyfreegeoip[.]org, and retains fallback exfiltration paths such as FTP and Telegram sendDocument.

> **Evidence**: extraData.pe off 0x11d2f 'checkip[.]dyndns[.]org', off 0x11e21 'reallyfreegeoip[.]org', off 0x11eeb / RVA 0x13CEB 'hxxps://api[.]telegram[.]org/bot'; '#FTPEnabled', '#TGEnabled', '/sendDocument?chat_id='
> 
> **Source**: `ev-000004` · `ref:474acee977`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; under the analysis environment's network isolation no successful connection or session was observed, and the real C2 responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| smtp | `mail[.]merchantinvestnetwork[.]com` | 587 | exfil | static | ⏳ not observed |
| telegram | `hxxps://api[.]telegram[.]org/bot` | 443 | exfil | static | ⏳ not observed |

### Host

**Drop paths**

- `C:\Temp\<8 uppercase letters>.ps1`
- `%APPDATA%\Google\Chrome\User Data\Default\Login Data`
- `%APPDATA%\Microsoft\Edge\User Data\Default\Login Data`
- `%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json`
- `%APPDATA%\FileZilla\recentservers.xml`
- `%APPDATA%\Thunderbird\Profiles\*`

**Registry**

- `HKCU\Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676`
- `HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676`
- `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676`
- `HKCU\Software\Classes\Foxmail.url.mailto\Shell\open\command`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `mail[.]merchantinvestnetwork[.]com; api[.]telegram[.]org` | yes | static |
| `c2_port` | `587` | yes | static |
| `smtp_user` | `bossy@merchantinvestnetwork[.]com` | yes | static |
| `smtp_password` | `2)D?sbbRb+m_{l8%` | yes | static |
| `smtp_recipient` | `bosskkk@merchantinvestnetwork[.]com` | yes | static |
| `telegram_api_base` | `hxxps://api[.]telegram[.]org/bot` | no | static |
| `ip_check_url` | `hxxp://checkip[.]dyndns[.]org/` | no | static |
| `geo_ip_url` | `hxxps://reallyfreegeoip[.]org/xml/` | no | static |
| `encryption_algo` | `loader: Base64 -> GZip -> AES-256-CBC/PKCS7; stage2: Base64 + repeating-key XOR; stealer secrets: DPAPI/BCrypt AES-GCM/TripleDES` | yes | static |
| `install_path` | `not recovered (the sample does not explicitly carry an install path)` | no | static |
| `mutex` | `not found` | no | static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not judge the payload as ransomware just because it uses AES-GCM/BCrypt/TripleDES; these algorithms are used to decrypt browser/email client credentials and loader data.
- Do not assert the sample actually used the FTP and Telegram exfiltration paths just because they exist in the code; static analysis only confirms the capability, and the fully recovered and enabled channel is SMTP.
- Do not treat checkip[.]dyndns[.]org and reallyfreegeoip[.]org as C2; they are public IP and geolocation lookup services.
- Do not claim registry writes, scheduled tasks or autostart persistence were observed; the sample was not executed this time and the related persistence fields were not recovered.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | yes (stage2 `ffb8cc4aa981225f783cd5f7a22db6f33afa8f2a1162bfb5a2623700815353a7`) |

**Limitations and pending verification**

1. This is a pure static analysis; the sample was not detonated in a dynamic sandbox, reproduced=false; all C2 and configuration are static decryption results, pending_dynamic_verify=true.
2. The Telegram bot token, FTP credentials and campaign_id were not recovered from the sample; for Telegram/FTP only the existence of code paths can be confirmed.
3. DEVVV.WHORE.LAUNCHER is .NET-obfuscated (invisible Unicode type names, control-flow flattening); the exact way it injects into/loads aspnet_compiler.exe was not dynamically confirmed.
4. No persistence fields such as a mutex, install path or scheduled task/service were found; runtime generation cannot be ruled out.

## Evidence index

<details>
<summary>Expand 9 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:3bbbb40ff4` | String extraction | Plaintext script strings from the original .vbe: C:\Temp\, powershell.exe -nop -ep bypass -file, StepDecodeAndWrite/StepInvoke/StepRemoveArtifacts |
| `ev-000003` | evidence.record | Four-layer payload chain reproduced by script: hashes, AES keys/IV and XOR key for stage1/stage2/payload_assembly.dll/extraData.pe |
| `ev-000004` | evidence.record | extraData.pe configuration and capability extraction: SMTP account/password/recipient, Telegram API, IP/geo lookup, browser/email/keyboard/clipboard/screenshot/security-tool-disabling capabilities |
| `ev-000002` | String extraction | extraData.pe string scan: .NET resources, configuration and capability identifiers in #Strings/#US |
| `ref:22c6109667` | PE structure parser | extraData.pe PE structure: I386, .NET, 3 sections, entry RVA 0x17FCE, only mscoree.dll imported |
| `ref:52eacba3e2` | PE structure parser | payload_assembly.dll PE structure: I386 DLL, 3 sections, entry RVA 0x100AE |
| `ref:942b62e991` | addr.translate | extraData.pe off 0x11A27 → RVA 0x13827 / VA 0x413827 (SMTP configuration area) |
| `ref:474acee977` | addr.translate | extraData.pe off 0x11EEB → RVA 0x13CEB / VA 0x413CEB (Telegram API string) |
| `ref:f692fb9682` | Import table parser | extraData.pe's only import is mscoree.dll!_CorExeMain, confirming a managed assembly |

</details>

---

_The sample behind this report is not public; IOCs are defanged. For security research only._
