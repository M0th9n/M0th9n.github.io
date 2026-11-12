---
title: "Malware Sample Analysis: ChickenStealer (PE · exe · 859af3d0)"
published: 2026-11-11
draft: false
description: "Malicious (high confidence): ChickenStealer · stealer · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Chicken", "stealer", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-11-ChickenStealer-859af3d0"
---

> [!WARNING]
> **Verdict: malicious** · Family **ChickenStealer** · Confidence **high**
> 
> Aliases: ChickenStl, Disco, LummaStealer (as named by individual engines; not adopted)
> 
> The sample is a full-featured stealer written in x64 C++: statically visible theft of browser credentials/cookies/credit cards/autofill/history, wallet and VPN/SSH configuration collection, clipboard reading, desktop screenshots, ZIP packaging, and Telegram Bot exfiltration; in the dynamic sandbox, IP probe requests, three Telegram exfiltration requests (sendMessage/sendPhoto/sendDocument), a PowerShell child process that adds a Defender exclusion path, and a callback attempt to 127.0.0[.]1:8080 were actually observed. Static and dynamic behavior agree; judged to be malicious stealer software.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **ChickenStealer** · Aliases ChickenStl, Disco, LummaStealer (as named by individual engines; not adopted) |
| Confidence | **High** |
| Behavior class | stealer |
| Difficulty | medium |
| First seen | 2026-11-10 12:11:57 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/859af3d02dbe7bc7ce1fba0396539b1fd37149615293c92e18def55e566b3294/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Anti-debug delay start</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1622</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Hidden window, mutex</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Add Defender exclusion</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Inject browser for key</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Steal browser credentials</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `859af3d02dbe7bc7ce1fba0396539b1fd37149615293c92e18def55e566b3294` |
| MD5 | _not recorded_ |
| Size | 695,296 bytes (679.0 KB) |
| Type | PE · `exe` |

## Behavior Analysis

**11** behaviors in total, each with attached evidence; **9** are statically available and **2** were obtained through dynamic analysis.

### 1. Anti-debug delayed start

`T1622` · Confidence **high** · Static

After startup it first sleeps for 8 seconds, then checks for a debugger in sequence with IsDebuggerPresent, CheckRemoteDebuggerPresent, PEB.BeingDebugged/NtGlobalFlag, and NtQueryInformationProcess (ProcessDebugPort=7, ProcessDebugFlags=0x1e); on a hit it shows the message box 'Im sorry but you cant debug this application!' and calls ExitProcess.

> **Evidence**: 0x140019210 decompiled: Sleep(8000), IsDebuggerPresent, CheckRemoteDebuggerPresent, GetProcAddress(ntdll!NtQueryInformationProcess), MessageBoxA/ExitProcess
> 
> **Source**: `ev-000014`

### 2. Hidden window and mutex

`T1564.003` · Confidence **high** · Static

Hides the console window and creates the global mutex Global\WinHost_SysUpdate_88492019; if it already exists (ERROR_ALREADY_EXISTS) the sample exits immediately, achieving single-instance residency.

> **Evidence**: 0x140019210: GetConsoleWindow/ShowWindow(hwnd,0)/FreeConsole; 0x19325 CreateMutexA('Global\\WinHost_SysUpdate_88492019'), GetLastError==0xB7 branch
> 
> **Source**: `ev-000014`

### 3. Add Defender exclusion

`T1562.001` · Confidence **high** · Dynamic

Checks whether it is running with administrator privileges; if so, it uses CreateProcessA to launch a hidden-window PowerShell that runs Add-MpPreference -ExclusionPath to add its own path to the Defender exclusion list. The PowerShell child process (PID 5480) was indeed observed in the dynamic run, but the exclusion list was empty at wrap-up, so the write could not be confirmed as successful.

> **Evidence**: 0x140009dc0: OpenProcessToken/GetTokenInformation(TokenElevation) → CreateProcessA('powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Add-MpPreference -ExclusionPath @(\'<own path>\')"'); dynamic monitoring component child process PID 5480
> 
> **Source**: `ev-000013` · `ev-000028`

### 4. Inject into browser to obtain key

`T1055` · Confidence **high** · Static

Starts the target browser process with CreateProcessW in a suspended state, writes 0x330 bytes of shellcode and a 0x8a8-byte parameter block into it, executes them with CreateRemoteThread, and then retrieves a 32-byte result with ReadProcessMemory; this path is used to call the IElevator COM interface to decrypt Chrome's app_bound_encrypted_key (App-Bound Encryption).

> **Evidence**: 0x14002f3c0: LoadLibraryA(ole32/oleaut32), GetProcAddress(CoInitializeEx/CoCreateInstance/CoSetProxyBlanket), CreateProcessW(CREATE_SUSPENDED), VirtualAllocEx, WriteProcessMemory(FUN_14002b660 shellcode), CreateRemoteThread, ReadProcessMemory, TerminateProcess
> 
> **Source**: `ev-000021`

### 5. Steal browser credentials

`T1555.003` · Confidence **high** · Static

Walks the profile directories of Chromium-based browsers (Chrome/Edge/Brave/Opera/Vivaldi/Yandex/360/QQ) and of Firefox/Waterfox/LibreWolf, exports Login Data passwords, Cookies, credit cards, autofill, and history, and writes them in Netscape format as Cookies.txt/Logins.txt/BankCards.txt/Autofills.txt/History.txt.

> **Evidence**: 0x140031d20 scans User Data\<Profile>\Login Data, Local State, Cookies; SQL 'SELECT origin_url, username_value, password_value FROM logins', 'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, cvc_encrypted FROM credit_cards'; strings @0x86d80/0x86e70/0x87060
> 
> **Source**: `ev-000026` · `ev-000010`

### 6. Collect wallets and configuration

`T1005` · Confidence **high** · Static

Searches for wallet.dat and desktop wallet data such as Exodus/Electrum/Atomic, as well as the Local Extension Settings of browser extensions such as MetaMask/Phantom/Rabby; it also collects VPN/proxy (WireGuard, OpenVPN, Clash, v2rayN), cloud and developer credentials (.aws, .azure, .kube, .docker, .git-credentials, .npmrc), and SSH/RDP client sessions.

> **Evidence**: string region 0x8b288–0x8b630 (wallets/wallet.dat/MetaMask/Exodus/extension IDs), 0x86048–0x86138 (.aws/.kube/.docker/.git-credentials/.npmrc), 0x885f8 (Terminal Server Client); dispatched and executed by CryptoModule/AdminDevModule
> 
> **Source**: `ev-000010`

### 7. Screenshot and read clipboard

`T1113` · Confidence **medium** · Static

Creates a compatible bitmap via GDI and captures the desktop with BitBlt, saving it as screenshot.jpg through GDI+; it also reads clipboard text into Clipboard.txt and exfiltrates it along with the report.

> **Evidence**: imports GDI32!CreateCompatibleDC/CreateCompatibleBitmap/BitBlt and gdiplus!GdipCreateBitmapFromHBITMAP/GdipSaveImageToFile; 0x14000ad90 calls OpenClipboard/GetClipboardData/CloseClipboard; strings 'screenshot.jpg'@0x858c0, 'Clipboard.txt'@0x850c8
> 
> **Source**: `ev-000010` · `ev-000016`

### 8. Package logs as ZIP

`T1560.001` · Confidence **high** · Static

Creates a staging directory under %TEMP% named by PID+timestamp, collects the output of each module, packages it as ChickenLogs.zip, and generates Summary.txt/Information.txt reports.

> **Evidence**: 0x1400033a0 calls GetTempPathA and builds the directory from the '~tmp_' prefix + PID + TickCount; 0x14000c370 aggregates Brute.txt/Tokens.txt/Cookies.txt/History.txt etc. and writes 'ChickenLogs.zip' (strings @0x858e8/0x855e0)
> 
> **Source**: `ev-000027` · `ev-000016`

### 9. Telegram exfiltration

`T1567.002` · Confidence **high** · Dynamic

Calls the Telegram Bot API with a built-in bot token and chat_id: sendMessage sends a victim host overview (HTML format), sendPhoto sends the desktop screenshot, and sendDocument sends ChickenLogs.zip.

> **Evidence**: 0x140010cc0 builds 'hxxps://api[.]telegram[.]org/bot<token>/sendMessage'; 0x140010810 '/sendPhoto'; 0x140010360 '/sendDocument' (application/zip); dynamic network monitoring recorded three POST requests
> 
> **Source**: `ev-000020` · `ev-000024` · `ev-000028`

### 10. Callback to HTTP gateway

`T1071.001` · Confidence **medium** · Static

POSTs the ZIP as multipart/form-data to the configured hxxp://127.0.0[.]1:8080/gate and /api/gate (build-time placeholder addresses); in the sandbox only TCP connection attempts to 127.0.0[.]1:8080 were observed, and no HTTP session was established.

> **Evidence**: 0x14000fe70/0x1400100f0 → 0x1400116b0 (----WebKitFormBoundary multipart POST, application/zip); config written by 0x1400031b0; dynamically only 'requested TCP 127.0.0[.]1:8080' was seen
> 
> **Source**: `ev-000012` · `ev-000023` · `ev-000028`

### 11. Enumerate host and game information

`T1082` · Confidence **high** · Static

Collects computer name/username/HWID (registry MachineGuid)/CPU/GPU/memory/disk/power supply/motherboard/BIOS, installed software, Wi-Fi profiles (keyMaterial obtained via the WLAN API), USB/portable devices, the process list, and game account data for Steam/Epic/Riot/Minecraft/miHoYo, among others.

> **Evidence**: 0x140019210 instantiates SystemInfoModule→BrowserModule→MessengerModule→ScreenshotModule→AIModule→CryptoModule→SoftwareModule→GamesModule→WifiModule→AdminDevModule in order; strings 0x8b020–0x8b1c0 (hwid/cpu/bios/ProductKey) and 0x8b630 WLAN API imports
> 
> **Source**: `ev-000014` · `ev-000010`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated a TCP connection to this target (multiple retries within a short period).
:::

:::caution
**Real server side still unverified**: the above connection/handshake was completed with a locally controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence Source | Dynamic Observation |
|:--|:--|--:|:--|:--|:--|
| telegram | `hxxps://api[.]telegram[.]org/bot8919186852:AAEjTtp7vwrqRVtKiiHSVe2vCXiqQJX8sDc/sendDocument` | 443 | exfil | Dynamic | Observed |
| http | `hxxp://127[.]0[.]0[.]1:8080/gate` | 8080 | c2 | Static | ⏳ Not observed |
| http | `hxxp://127[.]0[.]0[.]1:8080/api/gate` | 8080 | c2 | Static | ⏳ Not observed |
| http | `hxxps://api[.]ipify[.]org; hxxps://ipv4[.]icanhazip[.]com; hxxps://checkip[.]amazonaws[.]com; hxxps://api64[.]ipify[.]org; hxxps://icanhazip[.]com` | 443 | other | Static | ⏳ Not observed |

### Host

**Mutex**

- `Global\WinHost_SysUpdate_88492019`

**Drop paths**

- `%TEMP%\~tmp_<pid>_<tick>\`
- `%TEMP%\~sys_<pid>_<tick>\`
- `%TEMP%\ChickenLogs.zip`
- `%TEMP%\screenshot.jpg`
- `%TEMP%\<staging>\Browsers\`
- `%TEMP%\<staging>\Wallets\`
- `%TEMP%\<staging>\Games\`
- `%TEMP%\<staging>\Wifi_Networks.txt`
- `%TEMP%\<staging>\Clipboard.txt`

### Configuration

| Key | Value | Required | Evidence Source |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxp://127[.]0[.]0[.]1:8080/gate; hxxp://127[.]0[.]0[.]1:8080/api/gate (build-time placeholder addresses)` | Yes | Static |
| `telegram_bot_token` | `8919186852:AAEjTtp7vwrqRVtKiiHSVe2vCXiqQJX8sDc` | Yes | Static |
| `telegram_chat_id` | `8980143221` | Yes | Static |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0[.]0 Safari/537.36` | No | Static |
| `mutex` | `Global\WinHost_SysUpdate_88492019` | Yes | Static |
| `staging_dir` | `%TEMP%\~tmp_ or %TEMP%\~sys_ + <pid>_<tick>` | No | Static |
| `archive_name` | `ChickenLogs.zip` | No | Static |
| `credential_decryption` | `Browser Local State/app_bound_encrypted_key is decrypted via process injection calling the IElevator COM interface to obtain a 32-byte key, then BCrypt (AES-GCM) decrypts Login Data/Cookies; Firefox uses logins.json and key4.db` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- It is not ransomware or a wiper: no file encryption, shadow copy deletion, ransom note, or destructive write logic was found; all collection behavior is theft.
- No persistence was observed: no service creation, scheduled tasks, or Run/RunOnce registry writes were seen; the only residency mechanism is the global mutex (single instance), so do not report it as a persistent backdoor.
- 127.0.0[.]1:8080 is a build-time placeholder (loopback) address and must not be treated as a real internet C2; in the sandbox there were only TCP connection attempts, with no HTTP session.
- Do not call it a generic process injector just because of CreateRemoteThread/VirtualAllocEx: the injection target is the browser process, and the purpose is to obtain the App-Bound Encryption key.
- Although the Add-MpPreference command was started in the dynamic run, the Defender ExclusionPath was empty at wrap-up, so it cannot be asserted that the exclusion was successfully written.
- Do not call it LummaStealer: the sample identifies itself as ChickenStealer, and only individual engines give it the Lumma name.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The built-in C2s (127.0.0[.]1:8080/gate, /api/gate) are loopback placeholder addresses; only TCP connection attempts were seen in the sandbox, with no HTTP request/response, so they are handled as static recovery and keep the pending dynamic verification marker.
2. The Telegram HTTP responses were synthesized by the sandbox's fake network; this only proves that the sample sent an exfiltration request carrying the bot token, not that a real attacker received the data.
3. The Defender exclusion command was indeed started, but the exclusion list was empty at wrap-up, so the successful write of the exclusion cannot be confirmed.
4. The analysis guest contained no real browser credentials, wallets, or VPN configuration, so the actual content and volume of stolen data could not be observed.
5. No persistence, lateral movement, privilege-escalation exploitation, or ransomware behavior was observed, and conclusions must not be extended on that basis.

## Evidence Index

<details>
<summary>Show 17 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | SHA256/MD5/SHA1 and file size 695296 |
| `ev-000002` | scan.imphash | imphash=34ff47a53573aada51bd1f365b715f07 |
| `ev-000010` | String extraction | Extracted configuration, browser/wallet/Telegram strings and addresses |
| `ev-000012` | decompile.ghidra | 0x1400031b0 builds the gate URL, Telegram token, chat_id, UA |
| `ev-000013` | decompile.ghidra | 0x140009dc0 checks elevation and launches Add-MpPreference exclusion path |
| `ev-000014` | decompile.ghidra | 0x140019210 anti-debug, mutex, and dispatch of ten stealing modules |
| `ev-000016` | decompile.ghidra | 0x14000c370 aggregates logs of each type and generates the report |
| `ev-000020` | decompile.ghidra | 0x140010360 Telegram sendDocument uploads the ZIP |
| `ev-000021` | decompile.ghidra | 0x14002f3c0 starts the browser process and injects shellcode to retrieve the 32-byte key |
| `ev-000023` | decompile.ghidra | 0x14000fe70 uploads the ZIP as multipart to the configured URL |
| `ev-000024` | decompile.ghidra | 0x140010cc0 Telegram sendMessage exfiltrates the host overview |
| `ev-000026` | decompile.ghidra | 0x140031d20 walks browser profiles and Login Data/Local State |
| `ev-000027` | decompile.ghidra | 0x1400033a0 creates a staging directory in %TEMP% as ~tmp_+PID+Tick |
| `ev-000028` | evidence.record | Dynamic sandbox observation: DNS/IP probes, POSTs to three Telegram endpoints, PowerShell Add-MpPreference, connection attempts to 127.0.0[.]1:8080 |
| `c2_evidence:859af3d0` | Connection evidence extraction | Dynamic network monitoring recorded 3 connection attempts to api[.]telegram[.]org:443; no complete session captured |
| `telemetry:859af3d0` | Dynamic telemetry | Dynamic telemetry recorded: 116 process/file events from the monitoring component; 1 ETW short-lived process event; 27 tool/system noise entries filtered |
| `etw:859af3d0:3412` | Process event monitoring | Short-lived process event: 859af3d02dbe7bc7ce1fba0396539b1fd37149615293c92e18def55e566b3294.exe (pid 3412; MD5=3FFE9B94FDD07511C2C8A92D0BF2E8CF,SHA256=859AF3D02DBE7BC7CE1FBA0396539B1FD37149615293C92E18DEF55E566B3294,IMPHASH=34FF47A53573AADA51BD1F365B715F07) |

</details>

---

_The sample in this report is not public; IOCs are defanged; for security research only._
