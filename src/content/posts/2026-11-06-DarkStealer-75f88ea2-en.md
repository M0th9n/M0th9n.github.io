---
title: "Malware Analysis: DarkStealer (PE · exe · 75f88ea2)"
published: 2026-11-06
draft: false
description: "Malicious (medium confidence): DarkStealer · stealer/loader/injector · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Dark", "stealer", "loader", "injector", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-06-DarkStealer-75f88ea2"
---

> [!WARNING]
> **Verdict: Malicious** · Family **DarkStealer** (uncertain) · Confidence **medium**
> 
> Aliases: Dark-Stealer, Dark Stealer, @DarkStealer404 build
> 
> The sample is a PyInstaller-packed Python infostealer. After real execution in the dynamic sandbox it resolves and contacts api[.]ipify[.]org/httpbin[.]org/api[.]myip[.]com in turn (public-IP discovery), then repeatedly resolves api[.]telegram[.]org and uploads files via the Bot API, falling back to catbox.moe, upload[.]gofile[.]io and 0x0.st when that fails; the static script contains Chrome/Firefox credential and cookie decryption, App-Bound Encryption bypass, Discord token and Telegram session-directory theft, wallet extension data collection, PowerShell screenshots with hidden VBS+Run-key persistence, and cryptocurrency address clipboard replacement.

## Overview

| Item | Content |
|:--|:--|
| Family | **DarkStealer** · aliases Dark-Stealer, Dark Stealer, @DarkStealer404 build · _uncertain_ |
| Confidence | **medium** |
| Behavior class | stealer · loader · injector |
| Difficulty | medium |
| First seen | 2026-11-03 15:03:59 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/75f88ea2bc7f6b9c258d2254d68bdf62b7ce2bc2c1fd49c466f3af213f59422c/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Detect VM and analysis tools</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Public IP profiling</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1016</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic observed</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Decrypt Chrome credentials</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Bypass App-Bound encryption</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1134.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Steal cookies via remote debugging</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `75f88ea2bc7f6b9c258d2254d68bdf62b7ce2bc2c1fd49c466f3af213f59422c` |
| MD5 | _not recorded_ |
| Size | 34,027,016 bytes (32.5 MB) |
| Type | PE · `exe` |

## Behavior analysis

**13** behaviors in total, each backed by evidence; **11** are statically recoverable and **2** were obtained through dynamic analysis.

### 1. Detect virtual machines and analysis tools

`T1497.001` · Confidence **high** · static

At startup it compares hostname/username/GPU/OS/process/IP blacklists (including vmtoolsd.exe, vboxservice.exe, wireshark.exe, x64dbg.exe, ida64.exe, processhacker.exe, pestudio.exe, joeboxcontrol.exe; GPUs 'vmware SVGA 3D', 'virtualbox Graphics Adapter'; usernames WDAGUtilityAccount/runneradmin etc.) and exits on a hit.

> **Evidence**: blackListedIPS/blackListedHostname/blackListedGPU/blackListedProcesses lists and check_* functions in the entry script; PE imports CreateToolhelp32Snapshot/Process32FirstW (rva 209232/209240)
> 
> **Source**: `ref:8a81869bf1` · `ref:80fe281c4a`

### 2. Public IP profiling

`T1016` · Confidence **high** · dynamic

It requests api[.]ipify[.]org, httpbin[.]org/ip and api[.]myip[.]com in turn to obtain the egress IP, and marks 'Unknown IP' if parsing fails, for victim profiling and blacklist decisions.

> **Evidence**: get_ip(service_url) and the ip_services list; the dynamic sandbox resolved the three domains in succession between 07:07:21 and 07:07:33
> 
> **Source**: `ref:87dad7b966` · `ref:5c13982afb`

### 3. Decrypt Chrome credentials

`T1555.003` · Confidence **high** · static

It copies Login Data/Ya Passman Data into a temporary database, decrypts passwords along the v10 (DPAPI+AES-GCM)/v20 branches, and writes them line by line to Passwords.txt; when no key is available it outputs '[No decryption keys]'.

> **Evidence**: get_passwords: SELECT origin_url, username_value, password_value FROM logins; CryptUnprotectData, MODE_GCM, decrypt_password
> 
> **Source**: `ref:5c13982afb` · `ref:418a6c8e26`

### 4. Bypass App-Bound encryption

`T1134.002` · Confidence **high** · static

For Chrome 127+'s v20 app-bound key, it first unpacks it through the COM elevation service/DPAPI, then decrypts the AES key with a hardcoded XOR key and ChaCha20-Poly1305; when necessary it enables SeDebugPrivilege and duplicates the lsass.exe token to impersonate and read the system-level key.

> **Evidence**: get_app_bound_key/decrypt_with_cng/derive_v20_master_key; NCryptOpenStorageProvider/NCryptDecrypt; constant '@B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787'
> 
> **Source**: `ref:418a6c8e26` · `ref:8a81869bf1`

### 5. Steal cookies via remote debugging

`T1539` · Confidence **high** · static

When direct reading of the Cookies database fails, it launches the victim browser with --remote-debugging-port=9876 --headless=new --user-data-dir, requests hxxp://localhost:9876/json for webSocketDebuggerUrl, connects over WebSocket and issues Network.enable/Network.getAllCookies to retrieve all cookies.

> **Evidence**: inside get_cookie, '--remote-debugging-port=9876', 'Network.getAllCookies', 'webSocketDebuggerUrl', and the requests+websocket call chain
> 
> **Source**: `ref:418a6c8e26`

### 6. Export Firefox credentials and cookies

`T1555.003` · Confidence **high** · static

It copies key4.db/logins.json/cookies.sqlite, decrypts the master key per NSS format with 3DES or AES-CBC, then decrypts encryptedUsername/encryptedPassword and moz_cookies.

> **Evidence**: getKey: SELECT item1,item2 FROM metaData; SELECT a11,a102 FROM nssPrivate; decrypt3DES/decrypt_aes/PKCS7unpad
> 
> **Source**: `ref:418a6c8e26`

### 7. Collect credit cards and autofill

`T1555.004` · Confidence **high** · static

It reads the card number/CVV/expiry/cardholder from the credit_cards table of the Chromium 'Web Data' database and exports historical autofill entries from the autofill table to Credit Cards.txt and Autofills.txt respectively.

> **Evidence**: get_credit_cards: SELECT ... FROM credit_cards; get_autofill: SELECT * FROM autofill
> 
> **Source**: `ref:418a6c8e26`

### 8. Steal Discord and Telegram sessions

`T1528` · Confidence **high** · static

It walks the leveldb store under %APPDATA%\discord to extract and DPAPI-decrypt Discord tokens; it also runs taskkill /IM Telegram.exe /FT and then copies the %APPDATA%\Telegram Desktop\tdata session directory.

> **Evidence**: discord_folder/leveldb_paths/decrypted_token, 'taskkill /IM Telegram.exe /FT', 'Telegram Desktop'/'tdata'
> 
> **Source**: `ref:8a81869bf1` · `ref:966ab3244f`

### 9. Hunt wallets and seed phrases

`T1005` · Confidence **high** · static

It searches Desktop/Documents/Downloads for files by keywords (wallet/mnemonic/seed/passphrase/metamask/exodus/paypal etc.) and extensions, enumerates the LevelDB directories of 30+ wallet extension IDs such as MetaMask, Trust, Phantom and OKX, and packages them into Wallets.

> **Evidence**: search_sensitive_files' search_keywords/folders_to_search/MAX_TOTAL_SIZE; get_extensions_wallet's wallet extension ID list (nkbihfbeogaeaoehlefnkodbefgpgknn etc.)
> 
> **Source**: `ref:966ab3244f` · `ref:8a81869bf1`

### 10. Screenshot, package and upload

`T1113` · Confidence **high** · static

It uses PowerShell (Add-Type System.Windows.Forms.Drawing + CopyFromScreen) to produce Screenshot.png, zips it together with all stolen text and sends it back in the order Telegram→catbox→gofile→0x0.st.

> **Evidence**: take_screenshot's PS script; create_zip_archive_catbox/upload_to_catbox/upload_to_gofile/upload_to_0x0/send_telegram_document
> 
> **Source**: `ref:8a81869bf1`

### 11. Telegram bot exfiltration

`T1567.002` · Confidence **high** · dynamic

It uploads the zip via Bot API sendDocument (with a caption carrying catbox/gofile/0x0 mirror links), falling back to sendMessage for links; in the dynamic sandbox it repeatedly resolved api[.]telegram[.]org from 07:07:37 and switched to catbox.moe/gofile[.]io/0x0.st from 07:09.

> **Evidence**: TOKEN_BOT/CHAT_ID and 'hxxps://api[.]telegram[.]org/bot' + '/sendDocument'; dynamic DNS records ipify→telegram→catbox→gofile→0x0.st
> 
> **Source**: `ref:87dad7b966` · `ref:8a81869bf1` · `ref:6e61490618`

### 12. Write Run-key persistence

`T1547.001` · Confidence **medium** · static

It drops a base64+XOR-obfuscated PowerShell payload and a clipboard-hijack script into a hidden directory, generates a .vbs launcher with attrib +h +s, and registers HKCU\...\Run\<random name>=wscript.exe <vbs> for user-level autostart.

> **Evidence**: run_clipper/install_dir/vbs_content/reg_cmds; 'attrib +h +s', 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'wscript.exe'
> 
> **Source**: `ref:8a81869bf1`

### 13. Replace wallet addresses in clipboard

`T1115` · Confidence **high** · static

A PowerShell infinite loop reads the clipboard every 500 ms, matches BTC/ETH/LTC/USDT/SOL/XRP/TON/DOGE/ADA/XLM/BCH addresses by regex and replaces them with the attacker's addresses, while keeping itself alive with a hidden window and high-priority/background threads.

> **Evidence**: the $addy address table and while($true){[System.Windows.Forms.Clipboard]::GetText} replacement loop in the embedded PowerShell; $beacon executed via [scriptblock]::Create
> 
> **Source**: `ref:8a81869bf1`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the isolated analysis network, so the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| telegram | `hxxps://api[.]telegram[.]org/bot8896670610:AAEk0SFei5wIZex0ZYUs4f5-pfzcAmvfpw/sendDocument` | 443 | exfil | static | ⏳ not observed |
| telegram | `hxxps://api[.]telegram[.]org/bot<token>/sendMessage (chat ID 8593010908)` | 443 | panel | static | — |
| http | `hxxps://catbox[.]moe/user/api[.]php` | 443 | exfil | static | ⏳ not observed |
| http | `hxxps://upload[.]gofile[.]io/uploadFile (with api[.]gofile[.]io/servers selection)` | 443 | exfil | static | ⏳ not observed |
| http | `hxxps://0x0[.]st` | 443 | exfil | static | ⏳ not observed |
| http | `hxxps://api[.]ipify[.]org?format=json / hxxps://httpbin[.]org/ip / hxxps://api[.]myip[.]com` | 443 | other | static | ⏳ not observed |

### Host

**Dropped paths**

- `%LOCALAPPDATA%\Bunny\<MM-DD-YY_HH-MM-SS>\ (stolen-data staging directory, containing Zip, NameFile.zip)`
- `%LOCALAPPDATA%\Bunny\<timestamp>\Screenshot.png (PowerShell CopyFromScreen screenshot)`
- `%LOCALAPPDATA%\Bunny\<timestamp>\Passwords.txt / Cookies.txt / Autofills.txt / Credit Cards.txt / History.txt / Wallets.txt (plaintext theft results)`
- `%LOCALAPPDATA%\Bunny\<timestamp>\<random name>.vbs (hidden-attribute persistence launcher, attrib +h +s)`
- `%LOCALAPPDATA%\Bunny\<timestamp>\<random name>.ps1 (PowerShell payload/clipboard hijack script)`
- `%APPDATA%\discord\Local Storage\leveldb\ (Discord token source)`
- `%APPDATA%\Telegram Desktop\tdata\ (Telegram session data source)`

**Registry**

- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\<random name> = wscript.exe "%LOCALAPPDATA%\Bunny\<...>\<random name>.vbs"`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `api[.]telegram[.]org (Bot API), fallback image hosts catbox.moe / gofile[.]io / 0x0.st` | yes | static |
| `telegram_bot_token` | `8896670610:AAEk0SFei5wIZex0ZYUs4f5-pfzcAmvfpw` | yes | static |
| `telegram_chat_id` | `8593010908` | yes | static |
| `install_path` | `%LOCALAPPDATA%\Bunny\<timestamp>\` | no | static |
| `persistence` | `HKCU\...\CurrentVersion\Run points to a hidden .vbs (wscript.exe launches powershell -w hidden -ExecutionPolicy Bypass -File <ps1>)` | no | static |
| `encryption_algo` | `DPAPI(CryptUnprotectData) + AES-256-GCM(Chrome v10) + ChaCha20-Poly1305(App-Bound v20) + 3DES/AES-CBC(NSS key4.db)` | no | static |
| `campaign_id` | `Telegram:Dark-Stealer @DarkStealer404 / t.me/DarkStealer404 \| @Bo2o444` | no | static |
| `clipper_addresses` | `BTC bc1qfpt6ljm7j2edsjn6f8aqst9qu6x55dgyfz30hw; ETH/BNB/SHIB/PEPE 0x8e977c00EfeF0e3C9a044C0641e2648F7731425d; LTC ltc1qfcrpmxw742lcef435526lwdqynt8ersmt4yha7; USDT/TRX TUCra7c48byL4xHfZWnXgmJDuPw9upTPz2; SOL 5EWvLKWj66rsVwdoUjTygujjSfusEXfTRbhvS5TBi1My` | no | static |
| `ip_check_services` | `api[.]ipify[.]org, httpbin[.]org/ip, api[.]myip[.]com` | no | static |
| `work_time` | `WorkTime / WorkName runtime window and hostname profiling fields` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not treat 181.214.153[.]11 as a C2: it sits with 'AppOnFly-VPS', 'vboxuser', 'BEE7370C-8C0C-4...' and others in the anti-sandbox blacklist data section, i.e. a detected hosting-environment characteristic, not a callback target.
- Do not report ransomware/wiper: the sample only reads and copies user files, with no encryption, deletion or destructive writes; pycryptodome's AES/ChaCha20 is used only to decrypt browser and NSS key stores.
- Do not report RAT/backdoor: no keylogging, remote screen control, arbitrary command delivery or interactive reverse shell was seen; the PowerShell payload is local clipboard hijacking and autostart, not a remote-control channel.
- Do not report worm/lateral movement: no USB propagation, SMB/PsExec/WMI lateral movement or domain reconnaissance code was seen.
- Do not report miner: no mining pool address, Stratum protocol or mining library traces.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The dynamic phase only observed DNS resolution and upload requests being received by the fake network; no Telegram server response was obtained and no plaintext credentials were extracted from the memory dump, so the credential ciphertext itself was not seen.
2. Persistence (hidden VBS + HKCU Run key) and the clipboard-hijack sub-payload are static reconstructions; the corresponding registry writes and PowerShell process events were not captured within the dynamic window and need review under a longer window or dedicated monitoring.
3. The sandbox guest used a cloaked configuration and the sample's anti-VM check did not trigger an exit, but that does not mean it would also execute in a normal vmware/virtualbox environment.
4. The family name is the sample's self-described brand (copyright string in output files), not cross-validated with vendor engines/YARA rules, so aliases may differ.
5. The validity and ownership of the Telegram Bot token / chat ID were not checked online; the values are presented faithfully as embedded in the sample.

## Evidence index

<details>
<summary>Expand 13 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hashing and fingerprinting | sha256=75f88ea2…9422c, md5=dd5d790644ef62d0ce238067fedbac55, size=34027016 |
| `ev-000002` | scan.imphash | imphash=e3e80a143805ea18936c8f612e25d363 |
| `ev-000003` | scan.rich | Rich header 11 toolchain records, richhash=a5ab84cd6b0f32306530937074b2749c |
| `ev-000004` | scan.entropy | .text entropy 6.486 (low, not packed) |
| `ev-000018` | string extraction | ascii 9394 / utf16 113; no real flag hits |
| `ref:177b341c3e` | PE structure parsing | PE32+ AMD64 GUI, 7 sections, entry rva 59248, image 708608, no anomalies |
| `ref:80fe281c4a` | import table parsing | 5 DLLs/150 symbols: CreateToolhelp32Snapshot/Process32FirstW, CreateProcessW, GetTokenInformation, VirtualProtect, GetProcAddress |
| `ref:ea346b8ffc` | script(extract) | located the PyInstaller cookie (88 bytes from EOF, pyver=311, pylib=python311.dll), unpacked 83 CArchive entries and the entry script sys_core_a24e56c0 (28296462B) |
| `ref:8a81869bf1` | script(strings) | readable constants of the entry script: Telegram bot token/chat id, catbox/gofile/0x0.st, App-Bound decryption constants, blacklists, wallet extension ID table, embedded PowerShell clipboard-hijack script |
| `ref:418a6c8e26` | script(strings) | function names and SQL, DPAPI/NCrypt/ChaCha20-Poly1305 call strings for get_passwords/get_app_bound_key/get_cookie/getKey/get_credit_cards etc. |
| `ref:6e61490618` | dynamic analysis platform | real detonation: pid 7456 started and produced 6 memory dumps; timeline records candidate processes and rollback status |
| `ref:87dad7b966` | sandbox.watch(log) | network monitoring: 07:07:21-33 resolves api[.]ipify[.]org/httpbin[.]org/api[.]myip[.]com; from 07:07:37 repeatedly api[.]telegram[.]org; 07:09:11-24 catbox.moe/upload[.]gofile[.]io/api[.]gofile[.]io/0x0.st |
| `ref:57180ad96d` | string extraction | raw PE string layer: exposes only the bootstrapper and resources, no plaintext C2 (all C2 is inside the compressed archive) |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
