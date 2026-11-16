---
title: "Malware Analysis: Santa Grabber (PE · exe · edc59856)"
published: 2026-11-14
draft: false
description: "Malicious (high confidence): Santa Grabber · stealer/downloader · difficulty hard · static decompilation (no runtime behavior obtained)"
tags: ["Santa Grabber", "stealer", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-14-Santa-Grabber-edc59856"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Santa Grabber** · Confidence **High**
> 
> Aliases: Santa, Santagrabber, Santa Stealer
> 
> The file is a pkg-packaged Node.js application masquerading as GoXLR Utility (package.json name=goxlr-utility, version=1.2.5). The index.js extracted from the overlay, after deobfuscation, contains complete stealing logic: it reads Discord tokens, Chromium/Firefox browser cookies/login data/autofill, Exodus and browser wallet extensions, keylogs and screenshots, and exfiltrates via a Discord webhook, a cafebabe[.]cc compatible webhook and catbox[.]moe/GoFile uploads; it also writes HKCU Run, the Startup folder and a scheduled task for persistence, and includes anti-VM checks plus dropping the cheatsan[.]club executable.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Santa Grabber** · aliases Santa, Santagrabber, Santa Stealer |
| Confidence | **High** |
| Behavior class | stealer · downloader |
| Difficulty | hard |
| First seen | 2026-11-11 02:17:23 |
| Analysis method | Static decompilation (no runtime behavior obtained) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/edc59856abfb63319dc82ad03960595f62945ba34149fb2a4829252dae743e3d/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Unpack obfuscated payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Masquerade as GoXLR tool</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Dual-channel data return</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1041</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Archive exfiltration to cloud</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1567.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Steal Discord tokens</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `edc59856abfb63319dc82ad03960595f62945ba34149fb2a4829252dae743e3d` |
| MD5 | _not recorded_ |
| Size | 58,588,291 bytes (55.9 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**12** behaviors in total, each backed by evidence, and all obtained statically.

### 1. Unpack obfuscated payload

`T1027` · Confidence **High** · Static

The PE overlay is a pkg virtual filesystem; gunzipping entry by entry yields a 538805-byte obfuscator[.]io-obfuscated index.js, and statically reproducing its custom base64 string table (5808 entries) and array rotation recovers the plaintext strings and constants.

> **Evidence**: Overlay file offset 0x23D5800; index.js 538805 bytes after decompression; string table 5808 entries, rotation value 143
> 
> **Source**: `ev-000108`

### 2. Masquerade as GoXLR tool

`T1036.005` · Confidence **High** · Static

package.json claims to be goxlr-utility 1.2.5 (the official GoXLR control tool), and the embedded runtime is exported as node.exe, yet the build path is under the santa-WEEK project — a typical name masquerade.

> **Evidence**: package.json: name=goxlr-utility, version=1.2.5; build path C:\snapshot\chas\Bot\temp_builds\santa-WEEK-9F6AE8BFA27C
> 
> **Source**: `ev-000108` · `ref:ee5c040477`

### 3. Dual-channel data return

`T1041` · Confidence **High** · Static

Simultaneously sends messages/archives to a Discord webhook on canary[.]discord[.]com and a compatible webhook on cafebabe[.]cc, implemented as postToBoth and sendZipToWebhook; the latter serves as a fallback/panel channel.

> **Evidence**: const webhook="hxxps://canary[.]discord[.]com/api/webhooks/1568032154561019976/..."; dualhook="hxxps://cafebabe[.]cc/api/webhooks/179231388932405535/..."; postToBoth/sendZipToWebhook
> 
> **Source**: `ev-000108`

### 4. Archive exfiltration to cloud

`T1567.002` · Confidence **High** · Static

Packs the collected results into a ZIP, tries GoFile first, and on failure calls catbox[.]moe user/api.php for upload; the returned URL is then written into the return message.

> **Evidence**: uploadToGoFile(...) / uploadToCatbox(...); request hxxps://catbox[.]moe/user/api.php; log "uploadToCatbox: starting"
> 
> **Source**: `ev-000108`

### 5. Steal Discord tokens

`T1539` · Confidence **High** · Static

Walks the Local Storage leveldb of %APPDATA%\discord, discordcanary, discordptb and discorddevelopment, extracts tokens with BROWSER_TOKEN_REGEX, calls DPAPI to decrypt values prefixed with dQw4w9WgXcQ, and further calls the Discord API for account profile, billing/relationships and other information.

> **Evidence**: discordPaths four paths; BROWSER_TOKEN_REGEX=/mfa\.[\w-]{84}|[\w-]{24}\.[\w-]{6}\.[\w-]{27}/g; DISCORD_ENC_PREFIX="dQw4w9WgXcQ:"; Dpapi.unprotectData; discord[.]com/api/v9/users/@me
> 
> **Source**: `ev-000109`

### 6. Read browser credentials

`T1555.003` · Confidence **High** · Static

Reads Cookies, Login Data and Web Data for Chrome, Edge, Brave, Vivaldi, Opera/Opera GX, Yandex, Chromium, Epic and Amigo, querying them with sql.js; for Firefox/Waterfox it reads cookies.sqlite and logins.json and calls PK11SDR_Decrypt through nss3.dll.

> **Evidence**: getTargets: Local\Google\Chrome, Local\BraveSoftware\Brave-Browser, Roaming\Opera Software\Opera GX etc.; cookies.sqlite/logins.json; nss3.dll + PK11SDR_Decrypt; sql.js Database.exec
> 
> **Source**: `ev-000109`

### 7. Package wallets and extensions

`T1555` · Confidence **High** · Static

Collects Exodus exodus.wallet (chacha20poly1305 decryption) and browser extension data for Metamask, Phantom, Coinbase, Rabby, Keplr, Ronin, Trust, Math, Zerion and others, packages them into %TEMP%\<username>_WalletBackup and exfiltrates them.

> **Evidence**: collectAllWallets/getExodusWallet("exodus.wallet"); copyWalletExtensions extension ID table; tempDir=path.join(os.tmpdir, username+"_WalletBackup")
> 
> **Source**: `ev-000109`

### 8. Keylogging and screenshots

`T1056.001` · Confidence **High** · Static

Loads GetAsyncKeyState through ffi to collect keystrokes; uses wmic logicaldisk to enumerate volume names and produces screenshots/monitor_N.png screen captures, both included in the exfiltration content.

> **Evidence**: ffi.Library(..., {GetAsyncKeyState: ["int16", ["int"]]}); captureScreens; wmic logicaldisk get volumename; screenshots/monitor_
> 
> **Source**: `ev-000109`

### 9. Write startup persistence

`T1547.001` · Confidence **High** · Static

installStartup copies itself into the current user's Startup folder and runs reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsSecurityHealthService", while also attempting schtasks /create /sc onlogon to create a logon scheduled task.

> **Evidence**: installStartup; reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsSecurityHealthService; schtasks /create /tn ... /sc onlogon; Start Menu\Programs\Startup
> 
> **Source**: `ev-000108`

### 10. Drop cheat program

`T1105` · Confidence **High** · Static

shouldDropCheat/dropAndRunCheatExe download xyzallahuakbar1337.exe from cheatsan[.]club and launch it, using the __CHEAT_LAUNCHED_KEY environment variable to avoid repeated execution; it acts as both downloader and decoy distributor.

> **Evidence**: CHEAT_EXE_URL="hxxps://cheatsan[.]club/xyzallahuakbar1337.exe"; shouldDropCheat; dropAndRunCheatExe; __CHEAT_LAUNCHED_KEY
> 
> **Source**: `ev-000108`

### 11. Evade virtual-machine analysis

`T1497.001` · Confidence **High** · Static

advancedVMCheck checks MAC prefixes for virtualization platform/VirtualBox/QEMU, the vboxservice/vmtoolsd/qemu processes and driver files such as VBoxMouse.sys; on a hit it calls process.exit to stop running in an analysis environment.

> **Evidence**: advancedVMCheck sits after the decryptor and is immediately followed by if(advancedVMCheck)process.exit; MAC prefixes 00:0C:29, 00:50:56, 08:00:27, 00:16:3E; VBoxMouse.sys; vboxservice/vmtoolsd
> 
> **Source**: `ev-000109`

### 12. Collect host and RDP intelligence

`T1082` · Confidence **High** · Static

getRdpInfo uses quser and reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" to detect RDP sessions and extract client IP/session name; GetIp obtains the public IP and geolocation via myexternalip[.]com and ipapi[.]co for victim profiling.

> **Evidence**: getRdpInfo: execSync("quser"), reg query HKCU\Software\Microsoft\Terminal Server Client\Default; GetIp: hxxps://www[.]myexternalip[.]com/raw, hxxps://ipapi[.]co/; RDP_SERVER_IP=85.11.167[.]82
> 
> **Source**: `ev-000109`


## IOC (Defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the isolated analysis network, and the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://canary[.]discord[.]com/api/webhooks/1568032154561019976/flfNZhu2wPZaNUWUspPKVQQEtcCw_qkMMOQT9loJv_K5Z8ewqiOWz4GjFP9bfdUVIYF1` | 443 | exfil | Static | ⏳ Not observed |
| http | `hxxps://cafebabe[.]cc/api/webhooks/179231388932405535/3R0dD_a0xzlad-RpQcZZWbc9xiYURRqh7hUXItbDRM94j9PcMoyzaTIK1EnV3a0CLE4P` | 443 | panel | Static | ⏳ Not observed |
| http | `hxxps://cheatsan[.]club/xyzallahuakbar1337[.]exe` | 443 | download | Static | ⏳ Not observed |
| http | `hxxps://catbox[.]moe/user/api.php` | 443 | exfil | Static | ⏳ Not observed |

### Host

**Drop paths**

- `%APPDATA%\discord\Local Storage\leveldb`
- `%APPDATA%\discordcanary\Local Storage\leveldb`
- `%APPDATA%\discordptb\Local Storage\leveldb`
- `%APPDATA%\discorddevelopment\Local Storage\leveldb`
- `%LOCALAPPDATA%\Google\Chrome\User Data`
- `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data`
- `%APPDATA%\Opera Software\Opera GX`
- `%APPDATA%\Mozilla\Firefox\Profiles`
- `%TEMP%\<username>_WalletBackup`
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<name>.exe`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

**Scheduled tasks**

- `<name> - schtasks /create /sc onlogon`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `canary[.]discord[.]com; cafebabe[.]cc` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `c2_uri` | `/api/webhooks/1568032154561019976/flfNZhu2wPZaNUWUspPKVQQEtcCw_qkMMOQT9loJv_K5Z8ewqiOWz4GjFP9bfdUVIYF1; /api/webhooks/179231388932405535/3R0dD_a0xzlad-RpQcZZWbc9xiYURRqh7hUXItbDRM94j9PcMoyzaTIK1EnV3a0CLE4P` | Yes | Static |
| `download_url` | `hxxps://cheatsan[.]club/xyzallahuakbar1337[.]exe` | No | Static |
| `upload_endpoints` | `hxxps://catbox[.]moe/user/api.php; GoFile upload (code fallback after catbox failure)` | No | Static |
| `persistence_run_value` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSecurityHealthService` | Yes | Static |
| `campaign_id` | `santa-WEEK-9F6AE8BFA27C` | No | Static |
| `rdp_fallback_ip` | `85[.]11[.]167[.]82` | No | Static |
| `credential_decryption` | `Windows DPAPI + Firefox NSS PK11SDR + chacha20poly1305 (Exodus)` | No | Static |

## What Not to Assume

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing the report.

- Do not assess it as ransomware/encryptor just because the code uses DPAPI, chacha20poly1305 or AES: those algorithms are only used to decrypt stolen browser/wallet data; no encryption of user files or ransom demand was observed.
- Do not assess it as a wiper or destructive sample: no logic to mass-delete/overwrite user files was found; unlink/rmSync in the code only cleans temporary archives and directories.
- Do not treat 85.11.167[.]82 as a connected C2 server: it is only a fallback display value in getRdpInfo when the RDP client IP cannot be obtained, and no network connection to it was found.
- Do not assume it shares an origin with the official GoXLR Utility: the goxlr-utility name in package.json is a masquerade, and the actual payload is an independently built stealer.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (no runtime behavior obtained) |
| Unpacking | No |

**Limitations and items to verify**

1. The sample was not actually detonated in the dynamic sandbox this run; all C2, exfiltration endpoints and persistence commands come from static unpacking/deobfuscation, with recoverability uniformly marked static and pending_dynamic_verify=true.
2. The sample embeds virtualization platform/VirtualBox/QEMU detection (MAC prefixes, driver files, services/processes), and may directly process.exit in common virtualized analysis environments; real dynamic observation requires a host that evades this check or prior patching.
3. The specific GoFile upload API endpoint does not form a complete URL in plaintext; only the uploadToGoFile field and fallback logic are visible, so it is not listed as a separate IOC.
4. index.js uses obfuscator[.]io string-table and control-flow obfuscation; strings and main function semantics were recovered, but individual dynamically assembled registry value names/scheduled task names require runtime to determine.
5. The family name comes from the sample's own footer and build path (Santa | @Santagrabber, santa-WEEK); the correspondence of this naming in public threat intelligence was not verified in this environment.

## Evidence Index

<details>
<summary>Show 10 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | md5=cf0aa9136423836bd92fc7c7164aa13c, sha1=9ff3874a5602a9519c6a5522f13288ee4eab4f11, sha256=edc59856abfb63319dc82ad03960595f62945ba34149fb2a4829252dae743e3d, size=58588291 |
| `ev-000002` | scan.imphash | imphash=5aa213c13ebbefe9c0a30df030df0286 |
| `ev-000003` | scan.rich | Rich header with 18 toolchain records, richhash=b5fb0d62897893e03122aedc628c638c |
| `ref:2c74089bf0` | PE structure parsing | AMD64 PE, 7 sections, image base 0x140000000, entry RVA 0x125DDB8, subsystem WINDOWS_CUI, export_count=28122 |
| `ref:8828d25ce7` | Import table parsing | 11 DLLs / 384 imported symbols, including WS2_32, ADVAPI32, CRYPT32, dbghelp, PSAPI and others |
| `ref:ee5c040477` | pe.exports | Export name node.exe, 28122 exports, typical V8/Node.js runtime symbols (v8::internal etc.) |
| `ref:d7a8f2a199` | unpack.detect | packed=false, packer=null, no atypical packer signals |
| `ref:db6b0b6fa6` | String extraction | Hits for pkg/prelude, PKG_DUMMY_ENTRYPOINT, node_modules, OpenSSL CRYPTOGAMS etc., indicating a pkg-packaged Node.js application |
| `ev-000108` | evidence.record (script) | Unpacked the pkg overlay and extracted index.js (538805 bytes), statically reproduced the obfuscator[.]io base64 string table and rotation, recovered webhook/dualhook/download URL/catbox/RDP IP/persistence commands |
| `ev-000109` | evidence.record (script) | Enumerated stealing capabilities: Discord tokens, browser cookies/logins/autofill, wallets and extensions, keylogging, screenshots, RDP/host information, anti-VM checks |

</details>

---

_This sample is not public; IOCs are defanged. For security research only._
