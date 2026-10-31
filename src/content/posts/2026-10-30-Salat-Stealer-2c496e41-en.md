---
title: "Malware Analysis: Salat Stealer (PE · exe · 2c496e41)"
published: 2026-10-30
draft: false
description: "Malicious (medium confidence): Salat Stealer · stealer/rat/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Salat Stealer", "stealer", "rat", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-30-Salat-Stealer-2c496e41"
---

> [!WARNING]
> **Verdict: malicious** · Family **Salat Stealer** (uncertain) · Confidence **medium**
> 
> Aliases: Salat, salat-stealer, WeBRat
> 
> A 64-bit Go infostealer/RAT: it carries a TEA-encrypted config and a TCP C2, and can steal browser and wallet credentials, collect Telegram/Discord/Steam data, keylog, stream screen/camera/microphone, execute remote commands and manage files, persist via scheduled tasks, bypass UAC and self-delete. All of these capabilities are directly evidenced by decompiled function names, string constants and the config table.

## Overview

| Item | Content |
|:--|:--|
| Family | **Salat Stealer** · aliases Salat, salat-stealer, WeBRat · _uncertain_ |
| Confidence | **medium** |
| Behaviour class | stealer · rat · downloader |
| Difficulty | medium |
| First seen | 2026-10-30 03:45:45 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/2c496e41d45ee787edef9c8dec4fe59e68a0d99746c899a6aabc6cbb36419bd6/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded C2 config</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">TCP callback C2:7777</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Steal browser credentials</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Steal crypto wallets</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Steal IM data</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `2c496e41d45ee787edef9c8dec4fe59e68a0d99746c899a6aabc6cbb36419bd6` |
| MD5 | _not recorded_ |
| Size | 7,546,347 bytes (7.2 MB) |
| Type | PE · `exe` |

## Behaviour analysis

**12** behaviours in total; each is tied to evidence, and all are statically recoverable.

### 1. Decrypt embedded C2 config

`T1140` · Confidence **high** · static

During start-up initialisation it calls TEA-related routines (applyTeaCryptor/teaDecryptB64) on embedded encrypted strings, then assembles the C2 host, port and keys from the string-descriptor table in .data, so the cleartext config never touches disk.

> **Evidence**: main.init 0x2c16c0, main.init.0 0x2df420, main.applyTeaCryptor 0x2defa0, main.teaDecryptB64 0x2df240; strings 'handshake: aes cipher' and the config descriptor table at VA 0x1406F2B90
> 
> **Source**: `ev-000023` · `ev-000021`

### 2. TCP callback C2:7777

`T1095` · Confidence **high** · static

Establishes a long-lived raw TCP connection to 45.61.177[.]70:7777, receives the server public key during the handshake and derives an AES session key, after which all command frames are encrypted with AES-GCM.

> **Evidence**: main.connectTCP 0x2cdb00, main.runSession 0x2cdd80, (*session).handshake 0x2cd520; strings 'handshake: recv pubkey' / 'handshake: gcm' / 'recvLoop'; config host=45.61.177[.]70, port=7777
> 
> **Source**: `ev-000023` · `ev-000021`

### 3. Steal browser credentials

`T1555.003` · Confidence **high** · static

Enumerates Chromium- and Gecko-family browser profile directories, copies Login Data/Cookies/Web Data, and decrypts logins, cookies and card data using DPAPI, AES-GCM, App-Bound and NSS PBE/PBES2; temporary copies use the .tmp_salat suffix.

> **Evidence**: main.stealChromium 0x2d9ee0, main.stealGecko 0x2db100, main.extractChromiumLoginsFull 0x2c4c00, main.decryptAppBoundKey 0x2c38e0, main.decryptNSSPBE 0x2c6f80; strings 'Login Data.tmp_salat', 'Local State', 'logins.json', 'key4.db'
> 
> **Source**: `ev-000021` · `ev-000022`

### 4. Steal crypto wallets

`T1555` · Confidence **high** · static

Walks major browser extensions and desktop wallet directories (MetaMask, Phantom, Exodus, TON_Wallet, OKX, Keplr, TronLink etc.) and packages wallet data and extension storage for exfiltration.

> **Evidence**: main.stealWallets 0x2dc160, main.stealChromiumExtensions 0x2dea20; strings 'MetaMask', 'TON_Wallet', 'exodus.wallet', 'Phantom', 'Extensions'
> 
> **Source**: `ev-000021` · `ev-000023`

### 5. Steal instant-messaging data

`T1555` · Confidence **high** · static

Collects the Telegram tdata directory, Discord LevelDB/tokens and Steam config and login files, outputting UserInformation.txt and an archive for exfiltration.

> **Evidence**: main.stealTelegram 0x2db740, main.stealDiscord 0x2dd0a0, main.stealSteam 0x2dbac0, main.isDiscordToken 0x2de980; strings 'tdata', 'discordleveldb', 'config.vdf', 'UserInformation.txt'
> 
> **Source**: `ev-000021`

### 6. Keylogging to kl.dat

`T1056.001` · Confidence **high** · static

Installs a global keyboard hook and records keystrokes, writing the log to Windows\kl.dat for later commands to read and exfiltrate.

> **Evidence**: main.startKeylogger 0x2cb5a0, main.getKeyloggerData 0x2cb820, main.resolveVK 0x2c8b00; strings 'Windows\kl.dat', 'UnhookWindowsHookEx', 'ToUnicodeEx'
> 
> **Source**: `ev-000021` · `ev-000022`

### 7. Live screen streaming and remote control

`T1113` · Confidence **high** · static

Periodically captures the screen, encodes it as JPEG/Base64 and streams it, while parsing coordinates and virtual-key values from the server and injecting mouse move/click/wheel and keyboard events for interactive remote control.

> **Evidence**: main.captureScreenshotB64 0x2d1c80, main.(*session).tcpStreamScreen 0x2d1da0, main.handleInputArgs 0x2c91c0, main.keyEvent 0x2c90c0; strings 'img:', 'moved=%d,%d', 'click=%d,%d', 'mouse_event'
> 
> **Source**: `ev-000021` · `ev-000022`

### 8. Camera and microphone capture

`T1125` · Confidence **high** · static

Invokes ffmpeg (dropped to %TEMP%\ffmpeg.exe) with dshow to capture camera video and audio (including stereo mix/virtual audio devices), streaming it back on command.

> **Evidence**: main.(*session).tcpStreamCam 0x2d2d20, main.(*session).tcpStreamMic 0x2d25a0, main.listCameras 0x2d4a20; strings '${TEMP}\ffmpeg.exe', 'dshow', 'stereo mix', 'audio=virtual-audio-capturer'
> 
> **Source**: `ev-000021`

### 9. Remote commands and file management

`T1059.003` · Confidence **high** · static

Implements exec/listdir/listdrives/download/dlexec commands: execute arbitrary commands, enumerate disk directories, download and run external executables (saved as dlexec_*.exe), and provide a SOCKS5 proxy channel.

> **Evidence**: main.execCommand 0x2d3700, main.listDir 0x2d39e0, main.downloadFile 0x2cc260, main.p2pSocks 0x2d4e20; strings 'dlexec_*.exe', 'exec', 'p2pSocks target: %s'
> 
> **Source**: `ev-000021` · `ev-000023`

### 10. Scheduled-task persistence

`T1053.005` · Confidence **medium** · static

Generates a Windows scheduled-task XML and registers it through Task Scheduler under a random task name for boot autostart, installs itself into the user directory and hides the file attributes; it also has logic to relaunch as the normal user (relaunchAsUser).

> **Evidence**: main.newTask 0x2caaa0, main.staticinstall 0x2ca280, main.getInstallPath 0x2cb320, main.setFileHiddenSystem 0x2cb520; string 'hxxp://schemas[.]microsoft[.]com/windows/2004/02/mit/task'
> 
> **Source**: `ev-000021` · `ev-000022`

### 11. UAC bypass elevation

`T1548.002` · Confidence **high** · static

Bypasses UAC through two paths, fodhelper.exe and the CMSTPLUA COM interface (ICMLuaUtil), to gain higher privileges for reading more user data and performing system-level operations.

> **Evidence**: main.Elevate 0x2cc720, main.elevateFodhelper 0x2cc900, main.elevateCMSTPLUA 0x2cc7c0; strings 'fodhelper.exe', 'CMSTPLUA', 'IElevator'
> 
> **Source**: `ev-000021`

### 12. Self-delete to erase traces

`T1070.004` · Confidence **high** · static

On receiving an uninstall command it starts cmd/powershell to delete its own file after a delay, cleans up temporary files and installation entries, and ends its residency.

> **Evidence**: main.selfDelete 0x2cccc0, main.Suicide 0x2ccc40; strings 'ping 127.0.0[.]1 -n 3 > nul & del /f /q "%s"', 'uninstalling'
> 
> **Source**: `ev-000021`


## IOCs (defanged)

### Network

:::caution
**The real server side remains unverified**: the connections above were completed against a local controlled emulation service; the real C2 responses and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `45.61.177[.]70` | 7777 | c2 | static | ⏳ not observed |

### Host

**Mutex**

- `WEBR_GNFQTONRFL0J`

**Drop paths**

- `%WINDIR%\kl.dat`
- `%TEMP%\webrat_wp.jpg`
- `%TEMP%\dlexec_*.exe`
- `<browser profile directory>\*.tmp_salat`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_host` | `45.61.177[.]70` | yes | static |
| `c2_port` | `7777` | yes | static |
| `agent_tag` | `WEBR_GNFQTONRFL0J` | no | static |
| `campaign_token` | `c3db08fee0270c6c65cb` | no | static |
| `tea_key_candidate` | `dreamdancerjntr` | no | static |
| `secondary_key_candidate` | `b7c91087babb7324` | no | static |
| `aes_key_hex_candidate` | `ef18cc61e8bd200e4a0e095005bc1112` | no | static |
| `encryption_algo` | `TEA (config strings) + RSA key exchange + AES-GCM session` | yes | static |
| `feature_flags` | `all 4 boolean switches true (browser/wallet/keylogger/IM collection modules)` | no | static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- It is not ransomware: the sample only enumerates disk capacity and collects information; no user-file encryption or ransom-note logic was found (the enumeration string is a PowerShell disk-usage query, and the sandbox reported ransom_notes=0).
- It is not a fileless/memory-only sample: it is a statically linked Go PE of about 7.5 MB with install and persistence code, requiring a dropped file to run.
- Do not assert the C2 successfully came online or describe the exact exfiltrated content: the C2 is recovered only from static config, and the dynamic network log could not be read.
- Do not describe the purpose of dreamdancerjntr / b7c91087babb7324 / ef18cc61e8bd200e4a0e095005bc1112 as confirmed: they are candidate key materials in the config table, and their exact roles (TEA key, session key, AES key) have not been verified at runtime.
- Do not assert the delivery channel or initial access method (phishing attachment, cracked software, bundled installer etc.); there is no such evidence inside the sample.
- Do not treat import-table APIs such as CreateMutexW/OpenProcess as behaviour conclusions on their own; use the call chains (functions listed) instead.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The dynamic sandbox completed detonation and produced candidate process dumps, but the archived artifacts sit on a path unreachable from the analysis host, so the process timeline, dynamic network log and memory-dump contents could not be read; reproduced=false, and all behaviour conclusions come from static evidence.
2. Emulation (user-mode API emulation) exits during Go runtime initialisation (ExitProcess(2)) and cannot observe network or file behaviour, serving only as a compatibility reference.
3. C2 45.61.177[.]70:7777 and the config keys all come from the static string-descriptor table; actual connectivity and the exfiltration protocol have not been dynamically verified and are marked pending_dynamic_verify.
4. The mutex name WEBR_GNFQTONRFL0J is inferred from the config-table field order, the WEBR_ prefix and the CreateMutexW import, not confirmed by runtime enumeration.
5. The scheduled-task name, install directory name and registry key name are generated randomly or assembled at runtime and were not captured statically, so host_iocs leaves them empty.

## Evidence index

<details>
<summary>Expand 7 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256=2c496e41d45ee787edef9c8dec4fe59e68a0d99746c899a6aabc6cbb36419bd6, size=7546347 |
| `ev-000021` | String extraction | 19458 ASCII / 71 UTF-16 strings, incl. kl.dat, .tmp_salat, webrat_wp.jpg, dlexec, fodhelper, browser/wallet paths and other key strings |
| `ev-000022` | decompile.ghidra | Decompiled main.main (0x1402cc040): after string comparisons it calls the install, Steal, self-delete and relaunch logic |
| `ev-000023` | Scripted forensics | Parsed the Go pclntab (7500 functions) and the .data config descriptor table, recovering host=45.61.177[.]70:7777, tag/key strings and main.* function addresses |
| `ref:77875dffd2` | PE structure parser | AMD64 PE, 8 sections, entry RVA 0x87DC0, no packing anomalies, only kernel32 imported |
| `ref:0ee4513f32` | Import table parser | Only 48 kernel32.dll imports (VirtualAlloc/Thread context/CreateThread etc.), the typical Go runtime import surface |
| `ref:dc119569d1` | Sample triage | Entropy and section table normal (.text 6.22), packing.score=0, anomaly_count=0 |

</details>

---

_The sample behind this report is not public; IOCs are defanged. For security research only._
