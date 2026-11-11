---
title: "Malware Analysis: AppHelper (PE · exe · 7eef7f97)"
published: 2026-11-10
draft: false
description: "Malicious (high confidence): AppHelper · stealer/rat · difficulty medium · dynamic sandbox + static decompilation"
tags: ["AppHelper", "stealer", "rat", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-10-AppHelper-7eef7f97"
---

> [!WARNING]
> **Verdict: malicious** · Family **AppHelper** · Confidence **high**
> 
> Aliases: Stealerium, AppCore, LimerBoy Stealer
> 
> The sample is a .NET infostealer: decompiled IL shows a CRYPTED: config embedded in AppHelper.Config, StringsCrypt decrypts it with PBKDF2-SHA1(1000)+AES-256-CBC, and the Collector/KeyLog/Swapper modules cover browser credentials, Windows Vault, keylogging and clipboard wallet swapping; it actually executed in an isolated Windows sandbox (process 1772), and the complete configuration plus Telegram/Discord/AnonFiles exfiltration code were recovered from a memory dump of the monitoring component.

## Overview

| Item | Content |
|:--|:--|
| Family | **AppHelper** · aliases Stealerium, AppCore, LimerBoy Stealer |
| Confidence | **high** |
| Behavior class | stealer · rat |
| Difficulty | medium |
| First seen | 2026-11-10 12:16:15 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/7eef7f970e715511722f09a3af6e503432e376542faa9386da6693ea2fb78f0a/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded config</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Detect debugger and VM</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001, T1622</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Create single-instance mutex</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1480</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Telegram report exfil</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1567, T1102</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Discord webhook exfil</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1567, T1102</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `7eef7f970e715511722f09a3af6e503432e376542faa9386da6693ea2fb78f0a` |
| MD5 | _not recorded_ |
| Size | 185,856 bytes (181.5 KB) |
| Type | PE · `exe` |

## Behavior analysis

**12** behaviors in total, each with attached evidence, all statically obtainable.

### 1. Decrypt embedded config

`T1140` · Confidence **high** · static

The .cctor of AppHelper.Config embeds Telegram/Discord/AnonFiles/wallet addresses with the CRYPTED: prefix; StringsCrypt.Decrypt uses Rfc2898DeriveBytes(cryptKey,saltBytes,1000) to derive an AES-256-CBC key and decrypts them at startup.

> **Evidence**: Config::.cctor @rva 0x0C0B0 (49328) stsfld TelegramAPI; StringsCrypt::Decrypt @rva 0x13E6C (81516) set_KeySize(256)/set_BlockSize(128)/Rfc2898DeriveBytes/RijndaelManaged
> 
> **Source**: `ev-000008`

### 2. Detect debugger and VM

`T1497.001, T1622` · Confidence **high** · static

The EnvCheck module enumerates 36 analysis processes (procmon/x64dbg/fakenet etc.), 8 sandbox DLLs (SbieDll/cmdvrt etc.), virtualization platform/VirtualBox/QEMU registry and BIOS/GPU artifacts; on a hard-feature hit it exits immediately, while soft features are only recorded.

> **Evidence**: EnvCheck::.cctor @rva 0x10D9C string table 'processhacker','x64dbg','fakenet','SbieDll','vmware','virtualbox'; VmArtifacts/Debugger/Emulator methods
> 
> **Source**: `ref:707878d0db` · `ev-000006`

### 3. Create single-instance mutex

`T1480` · Confidence **medium** · static

Creates a mutex with the Mutex value abb688d8ca89c08e610c7b9ce42819db from the configuration, avoiding duplicate execution on the same victim machine.

> **Evidence**: Config::.cctor stsfld Mutex; AppHelper.Core.MutexControl class; memory string 'Global\'
> 
> **Source**: `ev-000008` · `ref:707878d0db`

### 4. Telegram exfiltration of reports

`T1567, T1102` · Confidence **high** · static

Through the sendMessage/sendDocument/sendPhoto/editMessageText endpoints of api[.]telegram[.]org/bot<token>, it sends system information, credential archives, screenshots and keylogs to chat_id -5360484904, and polls for commands with getUpdates.

> **Evidence**: strings 'hxxps://api[.]telegram[.]org/bot','/sendDocument','/getUpdates?timeout=25&offset=','{"chat_id":"'; Telegram::SendReport/SendDocument
> 
> **Source**: `ev-000008` · `ref:707878d0db` · `ev-000006`

### 5. Discord webhook exfiltration

`T1567, T1102` · Confidence **high** · static

Sends JSON text and multipart files (report.png, archives) through the Discord webhook in the configuration, as a fallback exfiltration channel besides Telegram.

> **Evidence**: strings '{"content":"","username":"AppHelper"}','application/json','files[0]','report.png'; AppHelper.DiscordWebhook class
> 
> **Source**: `ev-000008` · `ref:707878d0db`

### 6. Steal browser credentials

`T1555.003` · Confidence **high** · static

Collects Login Data, Web Data, Cookies, History and Bookmarks from Chromium/Edge/Firefox, and decrypts passwords, cookies and credit-card data with DPAPI/AES-GCM(app_bound)/NSS PK11SDR.

> **Evidence**: Collector.Chromium::Crypto/Cookies/Passwords, Collector.Firefox::Decryptor(NSS_Init/PK11SDR_Decrypt), strings 'Login Data','Local State','logins.json','app_bound_encrypted_key'
> 
> **Source**: `ref:707878d0db` · `ev-000006`

### 7. Steal Windows credentials

`T1555.004` · Confidence **high** · static

Calls CredEnumerateW and VaultGetItem_WIN7/WIN8 to enumerate Windows Credential Manager and IE/Edge Vault entries, and uses CryptUnprotectData to recover plaintext passwords.

> **Evidence**: strings 'CredEnumerateW','VaultGetItem_WIN7','VaultGetItem_WIN8','CryptUnprotectData'; Collector.InternetExplorer::VaultCli / CredentialManager
> 
> **Source**: `ref:707878d0db` · `ev-000006`

### 8. Keylogging

`T1056.001` · Confidence **high** · static

A SetWindowsHookEx(WH_KEYBOARD_LL) low-level keyboard hook continuously records keystrokes, writes them by date to logs\keylogger and packages them for sending to Telegram.

> **Evidence**: strings 'WHKEYBOARDLL','LowLevelKeyboardProc','logs\\keylogger\\'; KeyLog::SetHook/HookCallback/StartKeyLog
> 
> **Source**: `ref:707878d0db` · `ev-000006`

### 9. Screenshot and webcam capture

`T1113` · Confidence **high** · static

DesktopScreenshot captures the desktop via GDI and saves Desktop.jpg; WebcamScreenshot uses capCreateCaptureWindowA to capture the webcam (disabled in this configuration with WebcamScreenshot=0).

> **Evidence**: strings 'capCreateCaptureWindowA','\\Desktop.jpg','\\Webcam.jpg','WebcamScreenshot : Camera screenshot failed'; Config::.cctor WebcamScreenshot='0'
> 
> **Source**: `ev-000008` · `ref:707878d0db` · `ev-000006`

### 10. Swap clipboard wallet addresses

`T1115` · Confidence **high** · static

Swapper monitors btc/eth/xlm/ltc/bch addresses in the clipboard and replaces them with attacker wallets, hijacking the transfer destination.

> **Evidence**: Config::.cctor SwapperAddresses' 5 decrypted wallet addresses; Swapper::Clipboard/EventManager/RegexPatterns
> 
> **Source**: `ev-000008` · `ref:707878d0db`

### 11. Install boot autostart

`T1547.001, T1053.005` · Confidence **high** · static

The Startup module writes MicrosoftEdgeUpdateCore to HKCU\...\CurrentVersion\Run, and creates a scheduled task with the same name and a Startup-folder shortcut MicrosoftEdgeUpdateCore.lnk, masquerading as an Edge update.

> **Evidence**: strings 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run','MicrosoftEdgeUpdateCore','MicrosoftEdgeUpdateCore.lnk','/C schtasks /Create /F /TN MicrosoftEdgeUpdateCore'; Startup::Install/CreateTask/CreateStartupShortcut
> 
> **Source**: `ref:707878d0db` · `ev-000006`

### 12. Telegram remote control

`T1059.003, T1105` · Confidence **high** · static

RemoteControl polls getUpdates and parses /cmd, /download, /grab, /screenshot, /camera, /keylogs, /report, /uninstall, executing shell commands, downloading and running files, packaging data to send back, and self-destructing.

> **Evidence**: strings '/getUpdates?offset=-1','/cmd <command> - run shell command','cmd.exe','/download <url> - download + run','uninstalling, bye'; AppHelper.RemoteControl 16 methods
> 
> **Source**: `ref:707878d0db` · `ev-000006`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the above addresses were obtained by static analysis; under the analysis environment's network isolation no successful connection or session was observed, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| telegram | `hxxps://api[.]telegram[.]org/bot8813953757:AAHbLwK_WJwDWt5jEZATB71y6LCG7lcW2hY` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://discord[.]com/api/webhooks/1568282257024614400/nDixFRFIsi4Km2okO7_L_1a64TRdnNhhBoDYUed-_knUfChzlztu7hSfGrKpqt6iHfk9` | 443 | exfil | static | ⏳ not observed |
| http | `hxxps://api[.]anonfilesnew[.]com/upload?key=AFuoJboasAXaRNSEPMB2XxHztd80488b` | 443 | exfil | static | ⏳ not observed |

### Host

**Mutex**

- `abb688d8ca89c08e610c7b9ce42819db`

**Dropped paths**

- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\MicrosoftEdgeUpdateCore.lnk`

**Registry**

- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MicrosoftEdgeUpdateCore`

**Scheduled tasks**

- `MicrosoftEdgeUpdateCore`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `api[.]telegram[.]org, discord[.]com, api[.]anonfilesnew[.]com` | yes | static |
| `telegram_bot_token` | `8813953757:AAHbLwK_WJwDWt5jEZATB71y6LCG7lcW2hY` | yes | static |
| `telegram_chat_id` | `-5360484904` | yes | static |
| `discord_webhook` | `hxxps://discord[.]com/api/webhooks/1568282257024614400/nDixFRFIsi4Km2okO7_L_1a64TRdnNhhBoDYUed-_knUfChzlztu7hSfGrKpqt6iHfk9` | yes | static |
| `anonfiles_api_key` | `AFuoJboasAXaRNSEPMB2XxHztd80488b` | no | static |
| `mutex` | `abb688d8ca89c08e610c7b9ce42819db` | yes | static |
| `version` | `1.5` | yes | static |
| `build_id` | `build 2026-11-06 0726` | yes | static |
| `encryption_algo` | `AES-256-CBC + PBKDF2-SHA1(1000, salt 16B) for embedded config; DPAPI/AES-GCM/NSS for browser secrets` | yes | static |
| `wallet_swap_addresses` | `btc=bc1qq60adlr3hgkhtrdtfssyhtc3le2nnzyl0ttsfn; eth=0x413c0bD3328D0d0ED060212d67dEa94035d757d7; xlm=GAKBKOBKFX3GFPT3RXWHKBACLZPZEHZBV2GX34X7AO3MDUEVPNEOUGFT; ltc=LgpHxu9igHZyy2EUrFXSpHgTKakrTLv2se; bch=qrlmd760p6weruha00ljypkqkaqly0ndcgv2zdemqt` | no | static |
| `second_stage_url` | `--- (disabled)` | no | static |
| `module_flags` | `EnvCheck=1,Autorun=1,StartDelay=1,StayAwake=1,KeyLogModule=1,SwapperModule=1,WebcamScreenshot=0` | yes | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- The sample is not ransomware: AES/BCrypt is used only to decrypt the embedded configuration and browser/credential data; no file encryption or ransom note was found.
- The sample is not a pure downloader/dropper: SecondStageUrl is configured as '---' (disabled), and the main body is a complete infostealer; the mere presence of a SecondStage class does not mean it performed a second-stage download.
- The string hit 'z0{0|0}' is part of the program's character table/keyboard-layout data, not a flag, and should not be used as an IOC or an answer.
- No Telegram/Discord/AnonFiles request or session was observed in this run; it must not be claimed that the C2 was online or that data was exfiltrated.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The C2/exfiltration configuration was recovered by static decryption (AES-256-CBC), not from a dynamic session; on the dynamic side no Telegram/Discord/AnonFiles DNS or HTTP request was observed, so it is marked static + pending_dynamic_verify per the rules.
2. The Run keys, services and scheduled tasks in the runtime telemetry are consistent before and after execution; no autostart entry was observed actually being written; Autorun/scheduled task/startup shortcut are static code evidence.
3. WebcamScreenshot is disabled in the configuration; whether keylogging/screenshots/clipboard swapping actually produced files was not observed in this run.
4. Family naming differs between sources: the sample's product name is AppHelper, while its code modules are highly consistent with the open-source Stealerium family, so it is listed under aliases.

## Evidence index

<details>
<summary>Expand 18 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256=7eef7f...78f0a; md5=77c0461e5d6c4bbd72c822755dbf0a41 |
| `ev-000004` | Sample triage | 2 sections, 0 imports, packing likelihood 0.25 |
| `ev-000002` | scan.entropy | .text entropy 5.773 (not packed) |
| `ev-000006` | String extraction | extracted 1462 ASCII/1094 UTF-16 strings, including AppHelper/Collector/Telegram/Discord/Vault etc. |
| `ev-000005` | String extraction | 'z0{0\|0}' hit is a character-table fragment, not a flag |
| `ev-000007` | decompile.function | Main @0x14001066c is CIL, which Ghidra cannot recover (only confirms .NET managed code) |
| `ev-000008` | evidence.record | dnfile/dncil statically parsed IL and decrypted the CRYPTED config, obtaining Telegram/Discord/AnonFiles/wallet/mutex |
| `ref:ad8dd73ad4` | Sample triage | M1 triage: no imports, no exports, two sections .text/.rsrc |
| `ref:ae0e6610bf` | PE structure parsing | AMD64 .NET GUI, image base 0x140000000, entry 0x140000000, only .text/.rsrc |
| `ref:707878d0db` | decompile.symbols | 536 named functions: Config/StringsCrypt/Collector/KeyLog/Swapper/Telegram/RemoteControl/Startup/EnvCheck |
| `ref:410b576bd0` | unpack.detect | not packed (confidence 0.45, only very few import signals) |
| `ref:c427626ee0` | unpack.antidebug | static anti-debug features 0 (anti-analysis logic is in managed EnvCheck, not native) |
| `ref:bdf95c4503` | Dynamic analysis platform | sample was delivered to the isolated win10 guest's auto-detonation directory |
| `ref:046671c19f` | Dynamic analysis platform | process 1772 running C:\dyn\samples\...exe, network monitoring/monitoring component online |
| `ref:a73bad2313` | Memory dump | monitoring component made a targeted dump of PID 1772, obtaining 184MB of memory and .NET modules |
| `ref:2ab362c722` | Dynamic artifact collection | collected network monitoring/ETW/telemetry/monitoring component artifacts (zip 158MB) |
| `telemetry:7eef7f97` | Dynamic telemetry | dynamic telemetry recorded: monitoring component registry events 4; monitoring component process/file events 99; ETW short-lived process events 1; system service events 4; filtered tool/system noise 27 |
| `etw:7eef7f97:1772` | Process event monitoring | short-lived process event: 7eef7f970e715511722f09a3af6e503432e376542faa9386da6693ea2fb78f0a.exe (pid 1772; MD5=77C0461E5D6C4BBD72C822755DBF0A41,SHA256=7EEF7F970E715511722F09A3AF6E503432E376542FAA9386DA6693EA2FB78F0A,IMPHASH=00000000000000000000000000000000) |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
