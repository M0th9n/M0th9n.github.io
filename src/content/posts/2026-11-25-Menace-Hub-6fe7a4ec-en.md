---
title: "Malicious sample analysis: Menace Hub (PE · exe · 6fe7a4ec)"
published: 2026-11-25
draft: false
description: "Malicious (confidence: medium): Menace Hub · stealer/rat/backdoor · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Menace Hub", "stealer", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-25-Menace-Hub-6fe7a4ec"
---

> [!WARNING]
> **Verdict: malicious** · Family **Menace Hub** · Confidence **medium**
> 
> Aliases: MenaceAgent, MENACE HUB v3.5, Menace Stealer/RAT
> 
> Decompilation confirms the sample has full credential-theft and remote-control capability: early in startup it restores the ntdll .text section, patches AMSI and ETW functions, and hides a thread with NtSetInformationThread; it polls for commands through the Discord Bot API and uploads files back; it steals browser cookies/passwords/credit cards, Discord and Roblox tokens, and various crypto wallets; it has keylogging, screen capture, webcam and microphone capture; and it writes a Run key and an ONLOGON scheduled task for autostart. The sample executed successfully in an isolated Windows 10 sandbox (PID 2860), but because it did not carry the MNC2 config trailer (no webhook/bot token) it produced no outbound connections; the malicious intent and capability evidence are sufficient.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **Menace Hub** · Aliases MenaceAgent, MENACE HUB v3.5, Menace Stealer/RAT |
| Confidence | **medium** |
| Behavior class | stealer · rat · backdoor |
| Difficulty | medium |
| First seen | 2026-11-25 11:07:49 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/6fe7a4eca94dde26b24d00d6e7688dba77c855b17bd65d553d4f4096252a7d23/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Cripple AMSI and debug checks</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001, T1622</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Read and decrypt embedded config</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Poll Discord commands</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Remote shell and file transfer</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001, T1059.003, T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Single process in sandbox</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `6fe7a4eca94dde26b24d00d6e7688dba77c855b17bd65d553d4f4096252a7d23` |
| MD5 | _Not recorded_ |
| Size | 1,933,312 bytes (1.8 MB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **12** behaviors in total, each backed by evidence; **10** are statically available and **2** were obtained through dynamic analysis.

### 1. Cripple AMSI and debug checks

`T1562.001, T1622` · Confidence **high** · Static

Early in startup it reads ntdll.dll from System32 and overwrites the in-memory .text section to clear user-mode hooks; it locates and overwrites amsi!AmsiScanBuffer with mov eax,0x80070005; ret, overwrites ntdll!EtwEventWrite with xor eax,eax; ret, and calls NtSetInformationThread(ThreadHideFromDebugger=0x11) to hide the thread; it also resolves APIs dynamically via FNV-1a hashing to avoid import-table traces.

> **Evidence**: FUN_140135e00 @0x135e00 (ntdll .text restore, AMSI/ETW patches); 0x136048 mov edx,0x11 + call NtSetInformationThread; the hash-resolution loop uses base value 0x14650fb0739d0383
> 
> **Source**: `ev-000015` · `ev-000019`

### 2. Read and decrypt embedded config

`T1140` · Confidence **high** · Static

It obtains its own path via GetModuleFileNameW and reads the entire file with CreateFileW, checking whether the last 4 bytes equal the magic 'MNC2' (0x32434e4d) and its preceding length field; it uses xorshift32(seed=0xf975b183) to decrypt a 28-byte default API base hxxps://discord[.]com/api/v10, and allows the environment variable MENACE_API_BASE to override it. This sample has no MNC2 trailer, so no webhook/bot token was loaded.

> **Evidence**: config loader 0x13641b cmp dword,0x32434e4d; GetModuleFileNameW@0x64d00; CreateFileW@0x2ee7d; decryption function FUN_1400632c0 @0x632c0; ciphertext rva 0x1529c0
> 
> **Source**: `ev-000016` · `ev-000019`

### 3. Poll Discord commands

`T1071.001` · Confidence **high** · Static

It polls Discord's /channels/<channel_id>/messages?limit=25&after=<id> with the 'Authorization: Bot <token>' header and parses author/content to issue commands; it supports commands such as !sh, !ps, !ls, !cat, !find, !rm, !get, !put, !dl, !zip, !kill, !shot, !cam, !mic, !play, !wall, !keylog, !grab, and returns results and files via multipart (payload_json + files[0]).

> **Evidence**: strings /messages?limit=25&after= (0x13d05a), Content-Disposition: form-data; name="payload_json" (0x13d5a8), command table 0x140076-0x140bca; WinHttpSendRequest@0x43ba0; 'Bot ' prefix 0x140999
> 
> **Source**: `ev-000014` · `ev-000019`

### 4. Remote shell and file transfer

`T1059.001, T1059.003, T1105` · Confidence **high** · Static

It launches cmd.exe /c (chcp 65001) or powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File <temporary .ps1> via CreateProcessW and sends back output after truncating/timing out; it supports upload (!put downloads from a URL and writes it), download (!get reads a file), directory listing, zip packaging, and terminating processes by PID.

> **Evidence**: CreateProcessW call sites 0x31124 / 0x3cb8e / 0x4f382; strings cmd.exe /c chcp 65001>nul & (0x13e950), powershell.exe -NoProfile -NonInteractive ... -File (0x13e9f0), mh_%lu_%d.ps1
> 
> **Source**: `ev-000014` · `ev-000019`

### 5. Collect host and antivirus information

`T1082, T1016, T1552.001` · Confidence **high** · Static

It enumerates WTS sessions, reads the Windows version, CPU/GPU descriptions, installed software, Defender real-time protection and exclusion paths from the registry, runs netsh advfirewall and netsh wlan show profile name=... key=clear to obtain firewall state and plaintext WiFi passwords, and queries hxxps://ipwho.is/ for the public IP and country/time zone, producing a recon report.

> **Evidence**: strings $ErrorActionPreference='SilentlyContinue'; Get-CimInstance ... AntiVirusProduct (0x13ec78), cmd.exe /c chcp 65001>nul & netsh wlan show profile name= (0x13eef8), hxxps://ipwho.is/ (0x13d106); WTSEnumerateSessionsW / WTSQuerySessionInformationW imports
> 
> **Source**: `ev-000014` · `ev-000019`

### 6. Steal browser credentials and wallets

`T1555.003, T1555, T1539` · Confidence **high** · Static

It runs SQLite queries against the Cookies, Login Data, and Web Data of Chrome, Edge, Brave, Chromium, Vivaldi, Yandex, and Opera, and decrypts cookies/logins/credit_cards with DPAPI and BCrypt AES-GCM; it walks the directories of Exodus, Electrum, Atomic, Coinomi, Bitcoin/Litecoin/Dogecoin/Ethereum/Monero/Zcash, Guarda, Binance, Coinbase Wallet, Ledger Live, Trezor Suite, Phantom, Solflare, and MetaMask extensions, and packages the wallet files into a zip.

> **Evidence**: SELECT host_key,name,encrypted_value... (0x13dad0); CryptUnprotectData@0x4c651; wallet paths utf16 0x13f870-0x13fe28; 'No known wallet files' message 0x1404f8
> 
> **Source**: `ev-000014` · `ev-000019`

### 7. Steal chat and game tokens

`T1528, T1539` · Confidence **high** · Static

It scans the .ldb/.log files under Local Storage\leveldb of discord/discordptb/discordcanary in %APPDATA%, extracts token candidates, and calls /users/@me to validate them; it reads the .ROBLOSECURITY cookie and requests hxxps://users[.]roblox[.]com/v1/users/authenticated to determine whether the account is active or banned.

> **Evidence**: utf16 0x13d788 Local Storage\leveldb, 0x13d49d .ROBLOSECURITY, 0x141228 hxxps://users[.]roblox[.]com/v1/users/authenticated; ascii 0x13d350 /users/@me, 0x140388 no discord token in LevelDB
> 
> **Source**: `ev-000014` · `ev-000019`

### 8. Keylog keystrokes

`T1056.001` · Confidence **high** · Static

It calls SetWindowsHookExW to install a low-level keyboard hook and uses GetAsyncKeyState to record keystrokes, converting them to markers such as [TAB]/[BKSP]/[ESC]/[CAPS]/[DEL]/arrow keys before writing them to a .keys log; it supports remote control via !keylog start/stop/dump/clear.

> **Evidence**: SetWindowsHookExW call site 0x46827; GetAsyncKeyState call site 0x65025; strings [TAB] (0x13f094), hook installed - keys land in .keys (0x140620)
> 
> **Source**: `ev-000019` · `ev-000014`

### 9. Screenshot, audio recording, and webcam

`T1113, T1125, T1123` · Confidence **high** · Static

It captures the screen with GetDC+BitBlt and encodes it as PNG with GDI+; it captures a single webcam frame through Media Foundation (MFEnumDeviceSources/MFCreateSourceReaderFromMediaSource); it records RIFF/WAV audio through waveInOpen/waveInStart, and uploads the results via multipart.

> **Evidence**: BitBlt call site 0x36ed7; waveInOpen call site 0x2f1eb; GdipSaveImageToStream / GdipGetImageEncoders imports; strings webcam unavailable (0x14032d), no input device / mic blocked (0x1402e5)
> 
> **Source**: `ev-000019` · `ev-000014`

### 10. Copy itself and persist at logon

`T1547.001, T1053.005` · Confidence **high** · Static

It copies itself to %LOCALAPPDATA%\MENACE_HUB\MenaceAgent.exe and %APPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe; it writes the MENACE_UPDATER and EdgeUpdateCore values to HKCU\Software\Microsoft\Windows\CurrentVersion\Run and runs schtasks /Create /F /SC ONLOGON /TN <name>; when MENACE_PERSIST_DRYRUN is non-empty it skips the registry and scheduled task.

> **Evidence**: FUN_140057b90 @0x57b90 contains RegCreateKeyExW(Run) + RegSetValueExW; FUN_140066510 @0x66510 concatenates 'schtasks /Create /F /SC ONLOGON /TN '; strings EdgeUpdateCore/MENACE_UPDATER (utf16 0x13cf6c)
> 
> **Source**: `ev-000017` · `ev-000018`

### 11. Single-process run in the sandbox

`T1204.002` · Confidence **high** · Dynamic

The sample was dropped into an isolated Windows 10 sandbox and launched under its original filename (PID 2860, process-creation event 2026-11-25 18:08:56 UTC); this was the only candidate process in the entire observation window, and it created no child processes.

> **Evidence**: dynamic-monitoring timeline events[0] pid=2860, name=<sha256>.exe; system process-creation event CommandLine="C:\dyn\samples\<sha256>.exe"; PE memory scan found no injection/hollowing
> 
> **Source**: `ev-000020`

### 12. No outbound network activity at runtime

`T1071.001` · Confidence **high** · Dynamic

During the observation window 02:08:57–02:11:59 this PID made no DNS/HTTP/HTTPS requests and did not connect to discord[.]com; this is consistent with the sample carrying no MNC2 config (no webhook/bot token), indicating that this build does not establish C2 without a config.

> **Evidence**: the network-monitoring log shows no requests from pid 2860 in this period; telemetry shows no new MenaceAgent/MENACE_UPDATER/EdgeUpdateCore Run keys/services/scheduled tasks
> 
> **Source**: `ev-000020`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: The above addresses come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://discord[.]com/api/v10` | 443 | c2 | Static | ⏳ Not observed |
| http | `hxxps://discord[.]com/api/webhooks/<webhook_id>/<webhook_token> (provided by the MNC2 config; not included in this sample)` | 443 | exfil | Static | ⏳ Not observed |

### Host

**Mutex**

- `Local\MenaceAgentV2`

**Drop paths**

- `%LOCALAPPDATA%\MENACE_HUB\MenaceAgent.exe`
- `%APPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`
- `%LOCALAPPDATA%\MENACE_HUB\.agent`
- `%LOCALAPPDATA%\MENACE_HUB\.agent_cursor`
- `%LOCALAPPDATA%\MENACE_HUB\.jobs`
- `%APPDATA%\.keys`
- `%TEMP%\mh_<pid>_<n>.db`
- `%TEMP%\mh_<pid>_<n>.ps1`
- `%TEMP%\mh_play_<n>.wav`
- `%TEMP%\mh_wall_<n>.png`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MENACE_UPDATER`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\EdgeUpdateCore`

**Scheduled tasks**

- `MENACE_UPDATER`
- `EdgeUpdateCore`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_api_base` | `hxxps://discord[.]com/api/v10` | Yes | Static |
| `c2_webhook` | `provided by the MNC2 config at the exe tail; this sample has no MNC2 trailer and does not include it` | Yes | Static |
| `bot_token` | `provided by the MNC2 config at the exe tail; not included in this sample` | Yes | Static |
| `config_container` | `exe tail: 4-byte big-endian length + config body + magic 'MNC2' (0x32434e4d)` | Yes | Static |
| `mutex` | `Local\MenaceAgentV2` | Yes | Static |
| `install_path` | `%LOCALAPPDATA%\MENACE_HUB\MenaceAgent.exe` | Yes | Static |
| `persistence_shadow` | `%APPDATA%\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe` | Yes | Static |
| `encryption_algo` | `browser secrets use DPAPI(CryptUnprotectData) + BCrypt AES-GCM; the API base uses xorshift32(seed=0xf975b183) single-byte XOR stream encryption` | No | Static |
| `runtime_switches` | `MENACE_API_BASE / MENACE_PERSIST_DIR / MENACE_PERSIST_SHADOW_DIR / MENACE_NO_PERSIST / MENACE_PERSIST_DRYRUN / MENACE_CFG_ONLY / MENACE_NO_NET / MENACE_NO_WAKE / MENACE_NO_FAKE / MENACE_HEARTBEAT_S / MENACE_AGENT_TTL` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not conclude the sample is harmless because this run produced no network traffic: the code has full Discord remote-control, credential-theft, keylogging, and autostart capability.
- Do not treat hxxps://discord[.]com/api/v10 as a confirmed live C2 session; this sample carries no MNC2 config, and there were no requests/responses during the observation window.
- Do not judge it as ransomware merely because it uses BCrypt/DPAPI; encryption is only used to decrypt browser-saved credentials and config, and no file encryption or ransom note was seen.
- Do not treat Microsoft Corporation / RuntimeHost / 2.4.1[.]0 in the version resource as a real signer or origin; the file has no digital signature, and this information is disguised.
- Do not treat the wallet-path list as proof of successful theft; it is only a collection-and-packaging capability in the code, and no dropped files were observed in this run.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The sample carries no MNC2 config trailer, so there was no webhook/bot token at runtime and no C2 outbound activity was observed in the sandbox; the C2 capability is confirmed only by static decryption and code paths and is marked static + pending_dynamic_verify.
2. The memory dump taken at process creation did not include config/tokens later present in the heap; the operator channel ID, webhook, and bot token could not be confirmed.
3. The dynamic observation window was about 3 minutes and produced no outbound activity; longer heartbeats, reconnects, or persistence in a configured environment cannot be ruled out.
4. The persistence code has skip switches such as MENACE_PERSIST_DRYRUN; this telemetry showed no Run key/scheduled task landing, which is no basis to deny its autostart capability on a real host.
5. The analysis environment provided no real Discord-side responses, so the end-to-end behavior of command parsing and file upload could not be verified.

## Evidence Index

<details>
<summary>Expand 10 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1 and file size (1,933,312 bytes) |
| `ev-000014` | String extraction | String extraction: ASCII 2874 / UTF16 230, flag hits 0; contains brand and config clues |
| `ev-000015` | decompile.ghidra | FUN_140135e00: ntdll .text restore, AMSI/ETW patches, NtSetInformationThread thread hiding |
| `ev-000016` | decompile.ghidra | FUN_1400632c0: MENACE_API_BASE read and xorshift32 decryption of the default Discord API base |
| `ev-000017` | decompile.ghidra | FUN_140057b90: copies itself, HKCU Run keys MENACE_UPDATER/EdgeUpdateCore, DRYRUN switch |
| `ev-000018` | decompile.ghidra | FUN_140066510: concatenates and executes schtasks /Create /SC ONLOGON /TN |
| `ev-000019` | Scripted forensics | Self-written script: no MNC2 trailer, decrypt API base, key strings/offsets and API call sites (self-reported) |
| `ev-000020` | evidence.record(manual) | Manual review of dynamic artifacts: PID 2860 single process, no network requests, no persistence keys, memory scan no injection (self-reported) |
| `telemetry:6fe7a4ec` | Dynamic telemetry | Dynamic telemetry recorded: monitoring-component process/file events 103; ETW short-lived process events 1; filtered tool/system noise 22 |
| `etw:6fe7a4ec:2860` | Process event monitoring | Short-lived process event: 6fe7a4eca94dde26b24d00d6e7688dba77c855b17bd65d553d4f4096252a7d23.exe (pid 2860; MD5=07D9EFEE2DCFC88DA7EA6A56F183B4B7,SHA256=6FE7A4ECA94DDE26B24D00D6E7688DBA77C855B17BD65D553D4F4096252A7D23,IMPHASH=1A4B4585C0B8C28A05E9E73E9C52F883) |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
