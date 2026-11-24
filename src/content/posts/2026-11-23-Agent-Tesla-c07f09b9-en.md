---
title: "Malware Sample Analysis: Agent Tesla (other · vbe · c07f09b9)"
published: 2026-11-23
draft: false
description: "Malicious (high confidence): Agent Tesla · stealer/loader/dropper · difficulty hard · pure static analysis"
tags: ["Agent Tesla", "stealer", "loader", "dropper"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-23-Agent-Tesla-c07f09b9"
---

> [!WARNING]
> **Verdict: malicious** · Family **Agent Tesla** · Confidence **high**
> 
> Aliases: AgentTesla, OriginLogger, Origin Logger
> 
> The sample is actually a plaintext VBS downloader/loader disguised as a VBE: it drops and stealthily executes PowerShell, passes SHA-256 verification plus multi-layer GZip and AES-256-CBC decryption, then uses XOR+Base64 to recover the .NET loader DEVVV.dll, and finally injects the Agent Tesla information-stealing payload (internal name CloudServices.exe) into the legitimate host aspnet_compiler.exe. The payload's plaintext configuration includes SMTP recipients, account credentials, and Telegram/FTP fallback exfiltration switches, and provides browser/email/FTP credential theft, keylogging, clipboard capture, and screenshot capabilities; the entire chain is self-evidenced by layer-by-layer static decryption and string/structural evidence.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Agent Tesla** · Aliases AgentTesla, OriginLogger, Origin Logger |
| Confidence | **High** |
| Behavior class | stealer · loader · dropper |
| Difficulty | hard |
| First seen | 2026-11-23 06:52:31 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/c07f09b938a879280282d717345fe11e59e41e6e743e20077816708a7f0a3e7e/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Drop and stealthily run PS1</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Multi-layer AES decryption</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Reflectively load .NET assembly</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Poll process to trigger injection</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1057</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Inject into legitimate host process</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055.012</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `c07f09b938a879280282d717345fe11e59e41e6e743e20077816708a7f0a3e7e` |
| MD5 | _Not recorded_ |
| Size | 692,714 bytes (676.5 KB) |
| Type | other · `vbe` |

## Behavior Analysis

A total of **12** behaviors, each backed by evidence, all statically obtainable.

### 1. Drop and Stealthily Execute PS1

`T1059.001` · Confidence **high** · Static

The VBE decodes the embedded base64 into a PowerShell script and writes it to C:\Temp\<8 random uppercase letters>.ps1, silently launches it with powershell.exe -nop -ep bypass -file, and deletes the script immediately after execution.

> **Evidence**: Sub Main/PrepareDirectory/Invoke/RemoveArtifacts; Const PS_LAUNCH_CMD="powershell.exe -nop -ep bypass -file """
> 
> **Source**: `ev-000003` · `ev-000006`

### 2. Multi-layer AES Payload Decryption

`T1140` · Confidence **high** · Static

stage1 first performs a SHA-256 integrity check on the base64 payload, then GZip decompression and AES-256-CBC/PKCS7 decryption (hardcoded key/IV), and finally executes the plaintext script via [ScriptBlock]::Create.

> **Evidence**: Test-HashMatches / Expand-GZipBytes / Invoke-AesDecrypt; Key=pdfeOSwww6IsD4/mw2kc2lIKTEf093BLnnd/MomoAYA=
> 
> **Source**: `ev-000003` · `ev-000006`

### 3. Reflectively Load .NET Assembly

`T1620` · Confidence **high** · Static

stage2 applies Base64 and repeating-key XOR (ZZaDazKA6@@^^) to encodedFragment to recover DEVVV.dll, loads it via [Reflection.Assembly]::Load, and reflectively invokes DEVVV.WHORE.LAUNCHER.

> **Evidence**: Invoke-InMemoryAssembly; TypeName 'DEVVV.WHORE'; MethodName 'LAUNCHER'; xorKey 'ZZaDazKA6@@^^'
> 
> **Source**: `ev-000004` · `ev-000006`

### 4. Poll Process to Trigger Injection

`T1057` · Confidence **high** · Static

stage2 checks the aspnet_compiler process every 5 seconds, triggers a payload injection once only when the process is absent, then continues looping.

> **Evidence**: Start-WatchLoop: Test-ProcessAbsent -Name 'aspnet_compiler'; Start-Sleep -Seconds 5
> 
> **Source**: `ev-000004`

### 5. Inject into a Legitimate Host Process

`T1055.012` · Confidence **medium** · Static

DEVVV.LAUNCHER receives the aspnet_compiler.exe path and the CloudServices.exe byte array, creates a host process, then uses parameters such as process handle, thread handle, memory allocation type, memory protection, and shellcode to complete memory writing/execution, consistent with process hollowing or injection.

> **Evidence**: metadata strings applicationName/commandLine/startupInfo/processInformation/processHandle/threadHandle/allocationType/protect/shellcode; kernel32 LoadLibraryA/GetProcAddress
> 
> **Source**: `ev-000002` · `ev-000004` · `ev-000006`

### 6. Obfuscated Loader Evades Analysis

`T1027` · Confidence **high** · Static

The loader bears a Confuser.Core 1.6.0+447341964f marker and SuppressIldasmAttribute/ConfusedByAttribute, and constructs duplicated #Strings/#GUID/#Blob metadata streams, hindering routine .NET decompilation and static review.

> **Evidence**: strings 'Confuser.Core 1.6.0+447341964f', SuppressIldasmAttribute, ConfusedByAttribute; duplicate metadata stream warning
> 
> **Source**: `ev-000002` · `ev-000006`

### 7. Steal Browser-Saved Credentials

`T1555.003` · Confidence **high** · Static

Enumerates Login Data, logins.json, and recentservers.xml from Chrome/Edge/Brave/Opera/Firefox/Thunderbird/FileZilla, and decrypts account credentials using CryptUnprotectData, AES-GCM, and NSS_Init/PK11SDR_Decrypt.

> **Evidence**: strings Login Data, logins.json, \Local State, CryptUnprotectData, NSS_Init/PK11SDR_Decrypt, FileZilla recentservers.xml
> 
> **Source**: `ev-000001`

### 8. Keylogging and Clipboard Theft

`T1056.001` · Confidence **high** · Static

Hooks keyboard input via SetWindowsHookExA/KeyboardProc, and polls OpenClipboard/GetClipboardData to capture clipboard text for exfiltration.

> **Evidence**: SetWindowsHookExA, KeyboardProc, GetKeyboardState, VKCodeToUnicode, OpenClipboard/GetClipboardData
> 
> **Source**: `ev-000001`

### 9. Screenshot and Exfiltrate via SMTP

`T1048.003` · Confidence **high** · Static

Captures the screen and saves it as .png, aggregates hostname, IP, country, date, and credential text, and sends it via SMTP through mail[.]merchantinvestnetwork[.]com:587 to bosskkk@merchantinvestnetwork[.]com.

> **Evidence**: strings .png / SCREENSHOT / #SMTPEnabled / mail[.]merchantinvestnetwork[.]com / 587 / bosskkk@merchantinvestnetwork[.]com
> 
> **Source**: `ev-000001` · `ev-000005`

### 10. Multi-channel Fallback Exfiltration

`T1102` · Confidence **high** · Static

Enables Telegram Bot sendDocument and FTP STOR as fallback exfiltration channels, forming SMTP/Telegram/FTP multi-channel exfiltration capability.

> **Evidence**: hxxps://api[.]telegram[.]org/bot, /sendDocument?chat_id=, #TGEnabled, #FTPEnabled, STOR
> 
> **Source**: `ev-000001` · `ev-000005`

### 11. Collect Host and Geolocation Information

`T1082` · Confidence **high** · Static

Visits checkip[.]dyndns[.]org to obtain the public IP, then reallyfreegeoip[.]org to resolve the country, and packages them with username, machine name, and date into the exfiltrated content.

> **Evidence**: hxxp://checkip[.]dyndns[.]org/, hxxps://reallyfreegeoip[.]org/xml/, PC INFO/Client Name/IP/Country
> 
> **Source**: `ev-000001` · `ev-000005`

### 12. Steal Email and FTP Credentials

`T1555` · Confidence **high** · Static

Reads the Outlook Profiles registry, Foxmail Account.rec0, and FileZilla recentservers.xml, extracting account credentials for email clients and FTP.

> **Evidence**: Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676, Foxmail.exe/Account.rec0, FileZilla recentservers.xml
> 
> **Source**: `ev-000001`


## IOCs (Defanged)

### Network

:::caution
**Pending dynamic verification**: the above addresses come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's response and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| smtp | `mail[.]merchantinvestnetwork[.]com` | 587 | exfil | Static | ⏳ Not observed |
| telegram | `hxxps://api[.]telegram[.]org/bot` | 443 | exfil | Static | ⏳ Not observed |

### Host

**Drop path**

- `C:\Temp\<8 random uppercase letters>.ps1`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `mail[.]merchantinvestnetwork[.]com; api[.]telegram[.]org` | Yes | Static |
| `c2_port` | `587 (SMTP)` | Yes | Static |
| `c2_uri` | `hxxps://api[.]telegram[.]org/bot/sendDocument?chat_id=` | No | Static |
| `smtp_user` | `bossy@merchantinvestnetwork[.]com` | Yes | Static |
| `smtp_password` | `2)D?sbbRb+m_{l8%` | Yes | Static |
| `smtp_recipient` | `bosskkk@merchantinvestnetwork[.]com` | Yes | Static |
| `encryption_algo` | `Load chain: Base64 + GZip + AES-256-CBC/PKCS7; browser credentials: DPAPI / AES-GCM / NSS` | No | Static |
| `campaign_id` | `NOVA` | No | Static |
| `exfil_channels` | `SMTP enabled; FTP, Telegram, screenshots, keylogging, clipboard all enabled` | No | Static |
| `telegram_token` | `Not recovered in plaintext (possibly in resources or encrypted configuration)` | No | Dynamic |

## Do Not Misjudge

:::important
The following conclusions are **prone to misjudgment**; please note them when citing this report.

- Do not judge the sample as ransomware or a crypter merely because it uses AES/GZip encryption; its ultimate goal is credential theft.
- This is a purely static analysis; do not claim that SMTP/Telegram/FTP exfiltration was successfully executed or that a C2 session was established.
- Do not assert that the injection definitely landed in aspnet_compiler.exe; the injection chain is inferred from reflection call parameters and obfuscated API strings and still awaits dynamic verification.
- DEVVV.dll is a custom ConfuserEx-obfuscated loader and should not be used alone as the final payload family name.
- Without evidence, do not claim that the sample created registry Run keys, scheduled tasks, or system service persistence.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | Yes (stage2 `ffb8cc4aa981225f783cd5f7a22db6f33afa8f2a1162bfb5a2623700815353a7`) |

**Limitations and pending verification**

1. Purely static analysis: the sample was not detonated on a system, and no actual process injection, registry writes, or outbound sessions were observed.
2. The Telegram bot token/chat_id and the FTP host and credentials do not appear in plaintext and may reside in resources or encrypted configuration, requiring runtime memory/network observation to supplement.
3. DEVVV.dll is obfuscated with ConfuserEx 1.6, and the injection method (process hollowing or thread injection) is inferred from API/parameter names, without instruction-by-instruction confirmation.
4. The SMTP endpoint and account credentials come from payload plaintext strings; server reachability and credential validity were not verified.
5. No static evidence was obtained for host-side persistence, mutexes, or service behavior, and no inferences are made in this report.

## Evidence Index

<details>
<summary>Expand 12 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | CloudServices.exe strings: Agent Tesla traits, SMTP configuration, browser/email/FTP credential paths, keylogging/clipboard/screenshot APIs |
| `ev-000002` | String extraction | DEVVV.dll strings: ConfuserEx 1.6, LoadLibraryA/GetProcAddress, processHandle/threadHandle/allocationType/protect/shellcode |
| `ev-000003` | evidence.record | Static parsing of the VBE and stage1: base64→PS1, SHA-256/GZip/AES-256-CBC decryption, C:\Temp drop and stealthy execution |
| `ev-000004` | evidence.record | stage2 Base64+XOR recovers DEVVV.dll and CloudServices.exe, recording the aspnet_compiler.exe host and reflection call entry point |
| `ev-000005` | evidence.record | Extracts plaintext configuration such as SMTP/Telegram/FTP/screenshot/keylogging from CloudServices.exe |
| `ev-000006` | evidence.record | Verifies and records SHA-256 of the original sample, stage scripts, and final payload |
| `ref:b5c38789d4` | PE structure parsing | DEVVV.dll PE structure: 32-bit .NET DLL, single import mscoree |
| `ref:789b73e5b4` | PE structure parsing | CloudServices.exe PE structure: 32-bit GUI executable, three sections .text/.rsrc/.reloc |
| `ref:65a52461cc` | Import table parsing | DEVVV.dll imports only mscoree.dll!_CorDllMain, imphash dae02f32a21e03ce65412f6e56942daa |
| `ref:d6e86c20ca` | decompile.symbols | DEVVV.dll metadata/strings: CreateProcess parameter names and injection-related fields, Confuser marker |
| `ref:01910324a2` | String extraction | CloudServices.exe string evidence (corresponds to ev-000001) |
| `ref:d4be587272` | String extraction | DEVVV.dll string evidence (corresponds to ev-000002) |

</details>

---

_The sample in this report is not publicly available; IOCs have been defanged and are provided for security research only._
