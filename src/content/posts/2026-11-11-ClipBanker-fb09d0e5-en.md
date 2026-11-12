---
title: "Malware Sample Analysis: ClipBanker (PE · exe · fb09d0e5)"
published: 2026-11-11
draft: false
description: "Malicious (medium confidence): ClipBanker · stealer/injector/backdoor · difficulty hard · static decompilation (dynamic execution produced no runtime behavior)"
tags: ["ClipBanker", "stealer", "injector", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-11-ClipBanker-fb09d0e5"
---

> [!WARNING]
> **Verdict: malicious** · Family **ClipBanker** (disputed) · Confidence **medium**
> 
> Aliases: Mikey, Trojan.Win64.ClipBanker, Win64.MalwareX-gen
> 
> Decompilation confirms it is a multi-functional stealer: it embeds the https[:]//doxbin[.]cy:2083 backend address and the /init and /upload protocols, reads SystemBiosVersion from HARDWARE\DESCRIPTION\System\BIOS for anti-VM checks, replaces clipboard wallet addresses with hardcoded BTC/ETH/TRX/LTC/SOL addresses, and provides complete modules for browser credentials/Cookies, Discord token grabbing and spreading, code injection into the Discord/Exodus clients, BIP39 mnemonic and wallet file scanning, screenshots and host fingerprint collection, self-copy to %LOCALAPPDATA%\WindowsRecovery\Update.exe with HKCU Run autostart, and a wss:// remote control channel. The static evidence comes directly from decompiled function logic and inline string constants; the malicious intent is clear.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **ClipBanker** · Aliases Mikey, Trojan.Win64.ClipBanker, Win64.MalwareX-gen · _disputed_ |
| Confidence | **Medium** |
| Behavior class | stealer · injector · backdoor |
| Difficulty | hard |
| First seen | 2026-11-10 17:24:00 |
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/fb09d0e5393ebb9060ea26c2050d7ff3bd6efee340a7d1173be94a44d07be51f/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Connect hardcoded backend</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Tamper clipboard wallet</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1115</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Steal browser credentials</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Grab Discord tokens</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1528</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Discord worm spreading</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1534</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `fb09d0e5393ebb9060ea26c2050d7ff3bd6efee340a7d1173be94a44d07be51f` |
| MD5 | _not recorded_ |
| Size | 3,322,880 bytes (3.2 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**12** behaviors in total, each with attached evidence, and all are statically available.

### 1. Callback to hardcoded backend

`T1071.001` · Confidence **high** · Static

After startup it uses https[:]//doxbin[.]cy:2083 as the default backend and requests /?action=init through a dynamically resolved WinHTTP interface to fetch configuration/authorization, with an X-License-Key header; if the backend is unavailable or no license is configured, it exits along the error path.

> **Evidence**: FUN_1400422c0 @0x1400422c0 inlines 'hxxps://doxbin[.]cy:2083'; 0x42ea6 '?action=init'; 0x43c35 'X-License-Key: '; 0x74b3d dynamically resolves winhttp.dll
> 
> **Source**: `ev-000020` · `ev-000025`

### 2. Tamper with clipboard wallet

`T1115` · Confidence **high** · Static

Identifies wallet addresses in the clipboard using BTC/ETH/TRX/LTC/SOL/DOGE regular expressions and replaces hits with built-in attacker addresses; implemented via OpenClipboard/GetClipboardData/SetClipboardData, and logs 'Crypto clipper: Success'.

> **Evidence**: FUN_140082f30 @0x140082f30 writes replacement addresses by coin type; 0x823b6 onward are BTC/ETH/TRX/LTC/SOL addresses; 0x82864 'Crypto clipper: Success'; 0x399b onward are address regexes
> 
> **Source**: `ev-000021` · `ev-000025`

### 3. Steal browser credentials

`T1555.003` · Confidence **high** · Static

Targets browsers such as Chrome/Edge/Brave/Opera/Opera GX/Vivaldi/Yandex/Firefox, extracting Cookies, Login Data passwords, Web Data autofill/bank cards/IBAN, and refresh tokens, and decrypts them with DPAPI and App-Bound Encryption bypass logic.

> **Evidence**: 0x65fcd '\Google\Chrome\User Data'; 0x1e9d12 '\Network\Cookies/\Login Data/\Web Data'; 0x1f1cb3 'SELECT guid, value_encrypted FROM local_stored_c...'; 0x6d1e9 'Ciphertext too short for AES-GCM decryption'
> 
> **Source**: `ev-000025`

### 4. Grab Discord tokens

`T1528` · Confidence **high** · Static

Scans the local leveldb and session files of Discord/DiscordPTB/DiscordCanary, extracts and validates user tokens, aggregates them into 'Discord Tokens.txt', and uploads the file.

> **Evidence**: 0x8ad01 'discord/discordcanary/discordptb'; 0x865b8 'leveldb'; 0x84f14 'Discord grabber:'; 0x9bf28 'Discord injection: Success'
> 
> **Source**: `ev-000025`

### 5. Discord worm spreading

`T1534` · Confidence **high** · Static

Uses the stolen tokens to call /api/v9/users/@me/channels and guild channel endpoints, mass-sends the backend-delivered worm_message to DM/channel contacts, achieving account-level self-propagation, and handles 429 rate limits and invalid tokens.

> **Evidence**: 0x8e850 'Discord spread:'; 0x964ce '/api/v9/users/@me/channels'; 0x9740d '/api/v9/guilds/'; 0x92917 'X-RateLimit-Bucket'; 0x45d4c 'spread_*' config keys
> 
> **Source**: `ev-000025`

### 6. Inject into Discord and Exodus

`T1554` · Confidence **high** · Static

Rewrites modules/discord_desktop_core/index.js in the Discord installation directory to inject remote-control JS; it also unpacks Exodus's app.asar, modifies the CSP of wallet.html and main/index.js, and then repacks it in order to hijack wallet interactions.

> **Evidence**: 0x993ee '\modules\discord_desktop_core'; 0x9975d '\index.js'; 0x9a81a 'LICENSE_PLACEHOLDER'; 0xa67ea 'src/app/main/index.js'; 0xa6f83 'CSP tag not found in wallet.html'; 0xa8503 'Failed to write patched app.asar'
> 
> **Source**: `ev-000025`

### 7. Establish WSS remote control channel

`T1071.001` · Confidence **high** · Static

Establishes a WebSocket long connection to wss://<backend_host>/stream?token=, receives and executes commands such as list_drives/list_dir/download_file/upload_file/exec/run_exe/kill/delete/mkdir/rename/file_stat, forming full remote control capability.

> **Evidence**: FUN_14010c200 @0x14010c200 inlines 'wss://' and parses the port (default 0x1bb=443); 0x10c459 '/stream?token='; 0x102907 'cmdcommandexec_resultoutput'; 0x10a547 'Remote control: Connected'
> 
> **Source**: `ev-000024` · `ev-000025`

### 8. Collect fingerprint and screenshot

`T1082, T1113` · Confidence **high** · Static

Collects computer name, username, volume serial number, disk serial number, BIOS/motherboard serial number, GPU, MAC, Windows ID, screen resolution, time zone, and memory information, and captures the screen with GDI/GDI+ for upload as JPEG.

> **Evidence**: 0x6c03d 'username'; 0x70ab6 'SYSTEM\CurrentControlSet\Services\disk\Enum'; 0x6b8c9 'screen_r'; 0xc7da1 'GdiplusStartup failed for memory screenshot'; 0x7696a 'image/jpeg'
> 
> **Source**: `ev-000025`

### 9. Scan mnemonics and wallets

`T1005` · Confidence **high** · Static

Recursively scans disks, Desktop, Downloads, Documents, and OneDrive directories, identifies mnemonics against the BIP39 wordlist, and matches seed/secret/passphrase keywords; it also packages wallet files for Exodus, Electrum, Electrum-LTC, Armory, Bytecoin, Jaxx, Ethereum, Guarda, Coinomi, Monero, and others.

> **Evidence**: 0xceb83 'BIP39_Phrases.txt'; 0xb0586 'secret/passphrase'; 0x78574 '\Exodus\exodus.wallet'; 0x7886b 'backupselectrumElectrum'; 0x78e09 'Bytecoin'; 0x7ab51 'Wallets/'
> 
> **Source**: `ev-000025`

### 10. Self-copy and autostart at login

`T1547.001` · Confidence **high** · Static

Copies itself to %LOCALAPPDATA%\WindowsRecovery\Update.exe and sets it hidden, and writes HKCU\Software\Microsoft\Windows\CurrentVersion\Run to autostart at login; it uses the Global\WindowsRecoveryInstance mutex to ensure a single instance and the Global\WindowsRecoveryExit event to signal exit.

> **Evidence**: FUN_1400e7d90 @0x1400e7d90 calls CreateDirectoryW, SetFileAttributesW(0x80), writes HKCU Run; 0xe8420 inlines 'Global\WindowsRecoveryInstance'; 0xe14f0 inlines 'Global\WindowsRecoveryExit'; 0xe84xx 'Autostart installed (HKCU Run)'
> 
> **Source**: `ev-000023` · `ev-000025`

### 11. Anti-VM and kill analysis tools

`T1497.001, T1562.001` · Confidence **high** · Static

Reads SystemBiosVersion from HARDWARE\DESCRIPTION\System\BIOS and treats the host as a virtual machine if it contains vbox/vmware/virtual/qemu; it enumerates processes and terminates analysis tools such as IDA, x64dbg, WinDbg, Ghidra, Fiddler, Wireshark, Process Hacker, the monitoring component, and monitoring component/HollowsHunter.

> **Evidence**: FUN_140056140 @0x140056140 reads the BIOS version and matches vbox/vmware/virtual/qemu; 0x56b5d-0x59e27 tool list; 0x5a154 'OpenProcess...TerminateProcess'; imports CreateToolhelp32Snapshot/OpenProcess/TerminateProcess
> 
> **Source**: `ev-000022` · `ev-000025` · `ev-000003`

### 12. Bundle and replace host EXE

`T1027` · Confidence **medium** · Static

Built-in Binder/EXE Replacer: it can append a payload carrying the 'BND!' marker to the end of a host EXE, replace the icon group and resources, and then run it, used to bundle the trojan with a normal program and disguise it.

> **Evidence**: 0x62300 'EXE Replacer: Starting Runtime Binding'; 0x5cb1c 'EXE Replacer'; 0x61620 'bnd.exe'; 0x61afb 'Binder: failed to start bound application'; imports FindResourceExW/UpdateResourceW/EndUpdateResourceW
> 
> **Source**: `ev-000025` · `ev-000007`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the above addresses were obtained from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence Source | Dynamic Observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://doxbin[.]cy:2083` | 2083 | c2 | Static | ⏳ Not observed |
| other | `wss://<backend_host>/stream?token=` | 443 | c2 | Static | ⏳ Not observed |
| http | `hxxps://discord[.]com/api/v9` | 443 | exfil | Static | ⏳ Not observed |

### Host

**Mutex**

- `Global\WindowsRecoveryInstance`

**Drop paths**

- `%LOCALAPPDATA%\WindowsRecovery\Update.exe`
- `%LOCALAPPDATA%\WindowsRecovery`
- `%APPDATA%\Exodus\exodus.wallet`
- `%APPDATA%\Exodus\backups`
- `%APPDATA%\Electrum\wallets`
- `%APPDATA%\Telegram Desktop\tdata`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

### Configuration

| Key | Value | Required | Evidence Source |
|:--|:--|:--|:--|
| `backend_url` | `hxxps://doxbin[.]cy:2083` | Yes | Static |
| `c2_hosts` | `doxbin[.]cy` | Yes | Static |
| `c2_port` | `2083` | Yes | Static |
| `init_endpoint` | `/?action=init` | Yes | Static |
| `upload_endpoint` | `/?action=upload&type=` | Yes | Static |
| `license_header` | `X-License-Key (no plaintext license built in; must be supplied at runtime/delivered by the backend)` | Yes | Static |
| `mutex` | `Global\WindowsRecoveryInstance` | No | Static |
| `kill_event` | `Global\WindowsRecoveryExit` | No | Static |
| `install_path` | `%LOCALAPPDATA%\WindowsRecovery\Update.exe` | Yes | Static |
| `autostart_registry` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Yes | Static |
| `encryption_algo` | `AES-GCM (BCrypt) used to encrypt uploaded data` | No | Static |
| `remote_control_endpoint` | `wss://<backend_host>/stream?token=` | No | Static |
| `wallet_replacement_addresses` | `BTC bc1q88sfcjthknff8ljm7l4vjr83f3z0waezcr92; ETH 0x80EB1438CF1F93f368113c54E56684c41cDc68; TRX TTdzBZaLn9chv8sJriT7PknrhfG3xCWP; LTC LXKh6UNfsUigqWJ3woUtFP9AE6eYtNyb; SOL 6Gk84SVN1rZFTHyvu6Smsk1HFigxvCNUcNFb6RQVzkJzSOLDMKeWh37sD8zUUMu4gPsbnMtpok3LNmb` | No | Static |
| `features` | `exe_replace, exodus_inject, discord_inject, discord_grabber, bip39, screenshot, systeminfo, extensions, wallets, keywords, telegram, desktop_apps, firefox, vs_projects, remote_desktop, worm_enabled, anti_vm` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not judge it as ransomware merely because AES-GCM/BCrypt appear: the encryption is used only for uploaded data, and no file encryption or ransom note logic was found.
- Do not claim a real outbound connection succeeded: no DNS/HTTP/WSS request from this process was observed in this sandbox run; all C2s are statically recovered and need later dynamic verification.
- Do not claim that HKCU Run was written or that WindowsRecovery\Update.exe was dropped: the Run key showed no change in dynamic telemetry and the path was not found; the related behavior comes from code logic.
- Do not treat this sample as a pure dropper/loader: no download and execution of an external payload from the network was observed; what is built in is Binder/EXE Replacer capability.
- Do not treat VirusTotal labels as the sole basis: the sample was not uploaded, and VT only provides hash-level external corroboration.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Unpacking | No |

**Limitations and pending verification**

1. Neither of the two real sandbox submissions showed malicious behavior: after creation the process was immediately suspended by the monitoring component and an early-termination dump was attempted (the early dump was 0 bytes), after which it disappeared; network monitoring contained no DNS/HTTP/WSS records from this process, and telemetry showed no relevant changes to the Run key or file system, so reproduced=false.
2. The analysis guest runs on a VMware virtualization platform (VMware signatures are visible in BIOS/CPUID/drivers), so the sample's anti-VM logic (FUN_140056140) will match 'vmware' and may exit immediately; the sample also depends on the backend /init and a license, no plaintext license key is present in the binary, and it likewise exits when the backend is unreachable — either could explain the dynamic silence.
3. Upload encryption uses AES-GCM, but the key/derivation was not recovered in this file; the 59-byte XOR constant used at runtime (FUN_140082f30) could not be decoded into readable plaintext and may be secondary configuration/identification.
4. The Binder/EXE Replacer's bundled payload was not found inside the sample file (no overlay, no embedded PE resource), so its stage2 content is unknown; the resource section contains only version information.
5. The C2, persistence, injection, and clipboard replacement are all static decompilation/string evidence and have not yet been confirmed by a real session or memory forensics.

## Evidence Index

<details>
<summary>Show 17 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1 and file size 3322880 |
| `ev-000002` | Hash and fingerprint | imphash=96c988111beae19d6f75f54b89a75585 |
| `ev-000003` | scan.rich | Rich header with 14 MSVC toolchain records |
| `ev-000004` | scan.entropy | .text entropy 6.526, no high-entropy encrypted section found |
| `ev-000011` | String extraction | ASCII/UTF-16 string extraction (8691/284 entries) |
| `ev-000018` | Cryptographic constant identification | CRC32 constants (non-core) |
| `ev-000019` | Cryptographic constant identification | Standard base64 alphabet |
| `ev-000020` | decompile.ghidra | FUN_1400422c0 decompiled: inlines the hxxps://doxbin[.]cy:2083 default backend |
| `ev-000021` | decompile.ghidra | FUN_140082f30 decompiled: built-in multi-chain wallet addresses and clipboard replacement logic |
| `ev-000022` | decompile.ghidra | FUN_140056140 decompiled: BIOS SystemBiosVersion anti-VM detection |
| `ev-000023` | decompile.ghidra | FUN_1400e7d90 decompiled: copy to WindowsRecovery\Update.exe/HKCU Run autostart |
| `ev-000024` | decompile.ghidra | FUN_14010c200 decompiled: wss:// remote control channel and port parsing |
| `ev-000025` | evidence.record | Self-written script recovered inline string constants: IOC/endpoints/feature switches/wallet addresses/mutex |
| `ref:a8687de8e9` | Dynamic analysis platform | Dynamic sandbox polling: after creation the sample process 4008 was suspended and dumped, producing no child process or network behavior |
| `ref:7bf986ca22` | Dynamic artifact collection | Artifacts collected after the second submission: network monitoring logs and telemetry; Run key unchanged, no C2 session |
| `ref:95747d741e` | Dynamic analysis platform | Guest process table: the sample process had exited, with no residual child processes |
| `telemetry:fb09d0e5` | Dynamic telemetry | Dynamic telemetry recorded: 3 registry events from the monitoring component; 59 process/file events from the monitoring component; 3 system service events; 25 tool/system noise entries filtered |

</details>

---

_The sample in this report is not public; IOCs are defanged; for security research only._
