---
title: "Malware Analysis: VNS Stealer (PE · exe · ba80f101)"
published: 2026-10-29
draft: false
description: "Malicious (medium confidence): VNS Stealer · stealer/loader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["VNS Stealer", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-29-VNS-Stealer-ba80f101"
---

> [!WARNING]
> **Verdict: Malicious** · Family **VNS Stealer** (uncertain) · Confidence **medium**
> 
> Aliases: VNS, vns_stealer, wvbots
> 
> In the dynamic sandbox the sample actually executed (PID 3728), issuing /ver, /upd, /report/1221 and /cmd requests to hxxp://pcboost[.]duckdns[.]org, and uploaded a 45994-byte application/octet-stream ZIP containing FileGrabber/, Keys/, Passwords/ and Screenshots/screen.png; on the static side the same C2 configuration was decrypted, and the import table and strings show that it systematically collects browser credentials, cookies, crypto wallets, clipboard, screen and WiFi configuration.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **VNS Stealer** · aliases VNS, vns_stealer, wvbots · _uncertain_ |
| Confidence | **Medium** |
| Behavior class | stealer · loader |
| Difficulty | medium |
| First seen | 2026-10-29 07:00:24 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ba80f101c6a045a2eb0aa281e5166895306baa249f1d4494fe4e70171fab3684/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt built-in C2 config</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Contact C2, upload steal pack</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Package and grab user files</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1005</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Poll for commands and updates</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Decrypt saved browser passwords</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `ba80f101c6a045a2eb0aa281e5166895306baa249f1d4494fe4e70171fab3684` |
| MD5 | _not recorded_ |
| Size | 2,161,664 bytes (2.1 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**12** behaviors in total, each backed by evidence; **7** were obtained statically and **5** through dynamic analysis.

### 1. Decrypt built-in C2 configuration

`T1027` · Confidence **High** · Static

At startup, single-byte XOR 0x5A decrypts the ciphertext at .rdata 0x18AB60, yielding two /report/1221 reporting addresses (domain + fallback IP).

> **Evidence**: 0x2CCD: 41 80 F7 5A (xor r15b, 0x5a);0x2C74: lea rcx, [rip+0x187EE5] → rva 0x18AB60;decrypted result hxxp://pcboost[.]duckdns[.]org/report/1221|hxxp://45.61.162[.]202/report/1221
> 
> **Sources**: `ref:886d5940b2` · `ref:ac68ba9af1` · `ref:0f755843f3`

### 2. Contact C2 and upload steal pack

`T1071.001` · Confidence **High** · Dynamic

Sends POST /report/1221 to pcboost[.]duckdns[.]org:80 via WinHTTP with Content-Type application/octet-stream, carrying chunk headers such as X-Hwid, X-Log-Id, X-Build-Id: v7 and X-Chunk; a single packet is 45994 bytes.

> **Evidence**: network monitoring: POST /report/1221 HTTP/1.1, Host: pcboost[.]duckdns[.]org, X-Build-Id: v7, X-Hwid: 2d074bd2e39b62bc, Content-Length: 45994;sample PID 3728 initiated TCP 80
> 
> **Sources**: `ref:c94108d0b4` · `ref:4d6ffe4b84`

### 3. Package and grab user files

`T1005` · Confidence **High** · Dynamic

The collected results are compressed into a ZIP and then uploaded; the archive contains the fixed directories FileGrabber/, Keys/, Passwords/ and Screenshots/, with desktop document copies stored under FileGrabber as "<prefix>_filename".

> **Evidence**: the upload body captured by network monitoring starts with PK\x03\x04, entry names FileGrabber/, FileGrabber/desktop.ini, Keys/keys.json, Passwords/passwords.txt, Screenshots/screen.png
> 
> **Sources**: `ref:481bb38f62` · `ref:c94108d0b4`

### 4. Poll for commands and updates

`T1105` · Confidence **High** · Dynamic

Before and after reporting it GETs /ver and /upd to check version/updates, and immediately after the upload completes it GETs /cmd to pull remote commands, giving it the ability to be tasked remotely and to receive new versions.

> **Evidence**: network monitoring sequence: GET /ver → GET /upd → POST /report/1221 → GET /cmd, Host all pcboost[.]duckdns[.]org
> 
> **Sources**: `ref:ed32f82051` · `ref:c94108d0b4`

### 5. Decrypt saved browser passwords

`T1555.003` · Confidence **High** · Static

Locates the User Data / Login Data / logins.json of 20+ Chromium-based browsers and Firefox, reads app_bound_encrypted_key and encrypted_key from Local State, recovers account passwords with BCrypt PBKDF2+AES and CryptUnprotectData, and when necessary bridges decryption through elevation_service.exe.

> **Evidence**: imports bcrypt.dll (BCryptDeriveKeyPBKDF2/BCryptDecrypt) and CryptUnprotectData;strings 'app_bound_encrypted_key', '/Login Data', 'SELECT host_key,name,... FROM cookies', 'abe: INJECT ok key=', '/bridge.dll', 'elevation_service.exe'
> 
> **Sources**: `ref:4d6ffe4b84` · `ref:f806734643` · `ref:7b7a47ee33`

### 6. Export browser cookies

`T1539` · Confidence **High** · Static

Opens the browser cookies database with SQLite, executes SELECT host_key,name,encrypted_value,... FROM cookies, and parses Firefox's moz_cookies / key4.db, outputting a Netscape-format cookie file.

> **Evidence**: strings 'SELECT host_key,name,encrypted_value,path,value,is_secure,is_httponly,expires_utc FROM cookies', '# Netscape HTTP Cookie File', 'SELECT host,name,value,... FROM moz_cookies', '/cookies.sqlite', '/key4.db'
> 
> **Sources**: `ref:f806734643`

### 7. Collect crypto wallet files

`T1005` · Confidence **High** · Static

Enumerates wallet directories such as Exodus, Electrum, Electrum-LTC, Coinomi, Bitcoin, Litecoin, Zcash, Dash, Dogecoin and the Ethereum keystore, and grabs the Local Extension Settings of browser wallet extensions.

> **Evidence**: strings '\\Exodus\\exodus.wallet', '\\Electrum\\wallets', '\\Bitcoin\\wallet.dat', '\\Ethereum\\keystore', '\\Local Extension Settings\\', '/wallets.json', extension ID hmeobnfnfcmdkdcmlblgagmfpfboieaf
> 
> **Sources**: `ref:f806734643`

### 8. Screenshot the current desktop

`T1113` · Confidence **High** · Dynamic

Uses GetDC/CreateCompatibleBitmap/BitBlt to capture the current screen and encode it as PNG, entering the upload package as Screenshots/screen.png.

> **Evidence**: imports GDI32 GetDC/BitBlt/GetDIBits/CreateCompatibleDC;upload ZIP entry Screenshots/screen.png (PNG header 89 50 4E 47)
> 
> **Sources**: `ref:4d6ffe4b84` · `ref:481bb38f62`

### 9. Read clipboard contents

`T1115` · Confidence **High** · Static

Opens the clipboard, reads text and writes it to clipboard.txt, included in the exfiltration set.

> **Evidence**: imports OpenClipboard/GetClipboardData/CloseClipboard;string '\\clipboard.txt'
> 
> **Sources**: `ref:4d6ffe4b84` · `ref:f806734643`

### 10. Export WiFi profiles

`T1552.001` · Confidence **High** · Static

Runs netsh wlan show profiles and netsh wlan export profile folder=..., dropping WiFi profiles containing plaintext/encrypted keys into the vns_wifi directory and exfiltrating them.

> **Evidence**: strings 'netsh wlan export profile folder="', 'netsh wlan show profiles', '\\wifi', '\\_profiles.txt', '\\vns_wifi'
> 
> **Sources**: `ref:f806734643`

### 11. Collect host fingerprint and geolocation

`T1082` · Confidence **High** · Dynamic

Reads computer name/user/domain/OS/CPU/memory/MAC/disk volumes/processes/installed software, and requests ip-api[.]com/json for the public IP and geolocation, merging them into UserInformation.txt / SystemInfo.txt.

> **Evidence**: network monitoring: GET /json/?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query, Host: ip-api[.]com;strings 'cpu=','ram_mb=','gpu=','screen=','mac=','hwid','[SystemInfo]','[Installed software]','/processes.txt'
> 
> **Sources**: `ref:c94108d0b4` · `ref:f806734643`

### 12. Write autostart and self-delete

`T1547.001` · Confidence **Medium** · Static

Creates Global\\vns_stealer_mutex to guarantee a single instance, copies itself to %LOCALAPPDATA%\\vns\\ and maintains startup under the VnsService name / registry Run key, then uses cmd /c del /f /q to clean up the dropped file.

> **Evidence**: strings 'Global\\vns_stealer_mutex', 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'VnsService', '\\vns', 'cmd /c del /f /q "';imports CreateMutexA/RegCreateKeyExA/RegSetValueExA/CopyFileA
> 
> **Sources**: `ref:f806734643` · `ref:4d6ffe4b84`


## IOC (Defanged)

### Network

:::caution
**The real server side is still unverified**: the above connections/handshakes were completed with a local controlled emulation service, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://pcboost[.]duckdns[.]org/report/1221` | 80 | c2 | Static | ⏳ Not observed |
| http | `hxxp://45[.]61[.]162[.]202/report/1221` | 80 | c2 | Static | ⏳ Not observed |

### Host

**Mutex**

- `Global\\vns_stealer_mutex`

**Drop paths**

- `%LOCALAPPDATA%\\vns\\`
- `%TEMP%\\vns_g_*.tmp`
- `%TEMP%\\vns_wifi\\`
- `%TEMP%\\vns_progress.txt`
- `%TEMP%\\vns_crypto.txt`

**Registry**

- `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`

**Service**

- `VnsService`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxp://pcboost[.]duckdns[.]org/report/1221 \| hxxp://45[.]61[.]162[.]202/report/1221` | Yes | Static |
| `campaign_id` | `1221` | Yes | Dynamic |
| `build_id` | `v7` | No | Dynamic |
| `mutex` | `Global\\vns_stealer_mutex` | Yes | Static |
| `user_agent` | `Mozilla/5.0` | No | Dynamic |
| `c2_endpoints` | `/ver (version check), /upd (update), /report/{campaign} (upload), /cmd (command polling)` | Yes | Dynamic |
| `encryption_algo` | `Built-in config is obfuscated with single-byte XOR 0x5A; browser keys use BCrypt PBKDF2 + AES and CryptUnprotectData for DPAPI; the upload package is ZIP (directory names visible, contents encrypted/compressed)` | Yes | Static |
| `exfil_format` | `ZIP: FileGrabber/, Keys/, Passwords/, Screenshots/` | Yes | Dynamic |
| `grabber_patterns` | `*.txt,*.pdf,*.doc,*.docx,*.jpg,*.wallet,*.key,*key*,*wallet*,*backup*,*token*` | No | Static |
| `geoip_service` | `hxxp://ip-api[.]com/json/ (fields: status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query)` | No | Dynamic |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- It should not be judged as ransomware: although the sample imports VSSAPI and contains delete commands, no bulk encryption of user files, deletion of shadow copies or ransom-note drops were observed; the core observed behavior is credential theft and file exfiltration.
- It should not be claimed that the sample injected into or replaced other processes: memory forensics scanning showed no implanted PE and no IAT/jump hooks in the sample process; the sample exits on its own after completing reporting.
- It should not be claimed that the fallback C2 45.61.162[.]202 was actually used: dynamically only pcboost[.]duckdns[.]org was observed; the IP appears only in the static configuration and was never triggered.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. Registry Run key persistence, VnsService service creation and self-deletion are inferred only from strings and imports; no registry/service telemetry was collected in this run, and dynamic re-verification is needed.
2. The fallback IP 45.61.162[.]202 was not triggered dynamically (domain resolution succeeded and went through the primary channel), so its availability is unverified.
3. The upload body is compressed/encrypted; only the collection directories and file names are visible from the ZIP central directory, and the specific stolen account passwords could not be recovered.
4. ip-api[.]com is a public geolocation service; it is information enrichment rather than attacker infrastructure and should not be a blocking target.
5. Ghidra decompilation returned 0 functions for this sample; function-level conclusions are based on cross-validation of disassembly, the import table, strings and dynamic observations.

## Evidence Index

<details>
<summary>Expand 15 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:5177c891df` | Dynamic analysis platform | Dynamic detonation: 28 polls, sample PID 3728 running, 6 memory dumps, network and timeline artifacts collected |
| `ref:c94108d0b4` | network-log | DNS/HTTP sequence: /ver, /upd, POST /report/1221, GET /cmd for pcboost[.]duckdns[.]org and the ip-api[.]com query, including X-Hwid/X-Build-Id headers |
| `ref:481bb38f62` | network-log | Upload body is ZIP: FileGrabber/, Keys/, Passwords/passwords.txt, Screenshots/screen.png |
| `ref:ed32f82051` | network-log | Full C2 sequence: /ver → /upd → POST /report/1221 → GET /cmd |
| `ref:84aba74b48` | archive | Artifact inventory: timeline, memory dumps and network logs packaged |
| `ref:cd92d96448` | memory-forensics | Sample process loads vssapi/winhttp/bcrypt/iphlpapi; 34 modules scanned, 0 suspicious |
| `ref:886d5940b2` | disasm.function | 0x2CCD xor r15b,0x5a;0x2C74 lea rcx,[rip+0x187EE5] points to the 0x18AB60 config ciphertext |
| `ref:ac68ba9af1` | script | XOR 0x5A decrypts the ciphertext at 0x189B60 to hxxp://pcboost[.]duckdns[.]org/report/1221\|hxxp://45.61.162[.]202/report/1221 |
| `ref:0f755843f3` | addr.translate | Config ciphertext off 0x189B60 → rva 0x18AB60 (.rdata) |
| `ref:4d6ffe4b84` | Import table parsing | 235 imports including WinHTTP/bcrypt/CryptUnprotectData/VSSAPI/clipboard/GDI/IPHLPAPI/Run registry |
| `ref:f806734643` | String extraction | Browser/wallet/IM/WiFi/host information collection strings and the vns_* family fingerprint |
| `ref:7b7a47ee33` | Crypto constant identification | CRC32 and base64 alphabet constants |
| `ref:1c9380373e` | PE structure parsing | PE64 GUI, imagebase 0x140000000, 7 sections, unpacked |
| `ref:a02f39b51c` | Sample triage | Entropy 6.49/5.76, packing score 0, anomalies 0 |
| `ref:6d8c4fd2a6` | Dynamic analysis platform | Sandbox guest ready, 172 baseline processes, sample count 0 |

</details>

---

_The sample in this report is not public; IOCs have been defanged; for security research only._
