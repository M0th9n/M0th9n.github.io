---
title: "Malware Analysis: Bridge Agent / Backstage (PE · exe · d356ef60)"
published: 2026-11-06
draft: false
description: "Malicious (medium confidence): Bridge Agent / Backstage · stealer/rat · difficulty hard · dynamic sandbox + static decompilation"
tags: ["Bridge Agent", "stealer", "rat", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-06-Bridge-Agent-Backstage-d356ef60"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Bridge Agent / Backstage** (uncertain) · Confidence **medium**
> 
> Aliases: BridgeAgent, Backstage, rxclient, rxinj
> 
> In the isolated dynamic environment the sample runs on its own and uploads a 21,640,997-byte forensics.zip to the hardcoded IP 176.65.144[.]46:443 using multipart; runtime memory and temporary directories show it concurrently collecting browser credentials, wallets, instant-messaging, SSH, cloud and Wi-Fi configuration, and generating a 54,542,958-byte LSASS memory dump. Data collection, credential theft and exfiltration to a fixed address were all directly observed.

## Overview

| Item | Content |
|:--|:--|
| Family | **Bridge Agent / Backstage** · aliases BridgeAgent, Backstage, rxclient, rxinj · _uncertain_ |
| Confidence | **medium** |
| Behavior class | stealer · rat |
| Difficulty | hard |
| First seen | 2026-11-03 14:36:10 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/d356ef60fbcb9b6903823a87ae6f146fc879f84813076a9ebd343b1ac3e35ea2/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Collect browser credentials</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic observed</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Inject into browser for keys</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1055</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic observed</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Dump LSASS credentials</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1003.001</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic observed</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Steal wallets and chat data</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic observed</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Collect Wi-Fi and system creds</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `d356ef60fbcb9b6903823a87ae6f146fc879f84813076a9ebd343b1ac3e35ea2` |
| MD5 | _not recorded_ |
| Size | 10,748,438 bytes (10.3 MB) |
| Type | PE · `exe` |

## Behavior analysis

**10** behaviors in total, each backed by evidence; **3** are statically recoverable and **7** were obtained through dynamic analysis.

### 1. Collect browser credentials

`T1555.003` · Confidence **high** · dynamic

It enumerates the user profile directories of Chrome, Edge, Brave, Opera, Vivaldi, Firefox and Yandex, extracts Cookies, Passwords, Cards, IBANs, Tokens and Local Extension Settings, and copies the entire profile to the output directory.

> **Evidence**: strings near RVA 0x26a6a1 (file offset 0x2690a1) 'Google\Chrome\User Data … Cookies … PASSWORDS … CARDS … IBANS … TOKENS'; dynamic memory shows output\Browsers\installed_browsers.txt and [CHROMIUM]/[FIREFOX]/[WALLETS] collected logs.
> 
> **Source**: `ref:60d4ce909d` · `ref:a83af8f3c6` · `ref:544e0b5ea9`

### 2. Inject into browsers to steal keys

`T1055` · Confidence **high** · dynamic

It drops the embedded helper.exe into %TEMP%\rxinj_<timestamp>\ and reads the App-Bound Encryption Key / Copilot App-Bound Encryption Key plus Cookies, Passwords, Cards, IBANs and Tokens through a named pipe; loader logs show it allocating memory in the target process via direct syscalls, writing data and creating a remote thread.

> **Evidence**: the embedded helper.exe (1,423,360 bytes) starts at file offset 0x108fc2; its strings include 'App-Bound Encryption Key', '__DLL_PIPE_COMPLETION_SIGNAL__', 'Allocating memory in target process via syscall...', 'Creating remote thread via syscall...'; dynamic memory shows the path ...\Temp\rxinj_1793917890002939300\helper.exe.
> 
> **Source**: `ref:60d4ce909d` · `ref:a83af8f3c6`

### 3. Dump LSASS credentials

`T1003.001` · Confidence **high** · dynamic

It drops lss.exe into %TEMP%\rxlss_<timestamp>\, generates a memory dump of lsass.exe and writes it to output\mimikatz-credentials\lss.dmp; the runtime log records 'dump 54542958 bytes'.

> **Evidence**: the embedded lss.exe (16,896 bytes, no import table, pure syscalls) starts at file offset 0x264aa0; file offset 0x268cac contains '[LSASS] running lss.exe...', 'lss.dmp', 'mimikatz-credentials'; dynamic memory contains '[INFO] [LSASS] dump 54542958 bytes' and output\mimikatz-credentials\lss.dmp.
> 
> **Source**: `ref:d3fb77fedb` · `ref:6060cd3615` · `ref:f296979c36`

### 4. Steal wallets and chat data

`T1555` · Confidence **high** · dynamic

It copies data from wallets such as Exodus, Ledger Live, Trezor Suite, Electrum, Sparrow, Atomic, Guarda, Monero GUI and Bitcoin Core, as well as Telegram, Discord, Slack, Signal, Outlook, Steam, note-taking and remote-access tool configuration.

> **Evidence**: strings 'bitcoin-qt.exe', 'monero-wallet-gui.exe', 'Ledger Live.exe', 'Trezor Suite.exe' and '[TELEGRAM] collected', '[CHAT] collected', '[STEAM] collected', '[REMOTE_ACCESS] collected'.
> 
> **Source**: `ref:60d4ce909d` · `ref:a83af8f3c6`

### 5. Collect Wi-Fi and system credentials

`T1555` · Confidence **high** · static

It runs netsh wlan show profiles to export Wi-Fi configuration, and reads the Windows Vault, RDP connection records (Default.rdp), whoami /groups, environment variables and the installed-software list.

> **Evidence**: strings 'powershell-Command netsh wlan show profiles', 'wifi_networks.txt', 'WindowsVault', 'Default.rdp', 'privileges.txt', 'system_env.txt', 'installed_software.txt'.
> 
> **Source**: `ref:60d4ce909d`

### 6. Double ZIP packaging of data

`T1560.001` · Confidence **high** · static

35 collection threads run in parallel; a FAST ZIP is produced at T+90 seconds and a COMPLETE ZIP at T+300 seconds, and code comments stress never skipping any data.

> **Evidence**: strings '[MAIN] DUAL TRANSMISSION STRATEGY', 'Fast ZIP at 90s + Complete ZIP at 5min (NEVER SKIPS DATA)', '[PARALLEL] waiting for all 35 collectors to complete'.
> 
> **Source**: `ref:60d4ce909d`

### 7. Upload forensics package to fixed IP

`T1041` · Confidence **high** · dynamic

It uploads the ZIP as multipart/form-data to hxxps://176[.]65[.]144[.]46/api/forensics with x-device-id, x-signature, x-country and x-public-ip headers and protocol, message_id, type, device_id, sequence, sent_at, country, public_ip, size_bytes and zip_file fields; a single upload of 21,640,997 bytes was observed.

> **Evidence**: dynamic: PID 7256 initiates TCP 176.65.144[.]46:443; the HTTP request is POST /api/forensics, content-length 21642465, type=forensics.zip, size_bytes=21640997; static strings at file offsets 0x2694ba/0x2694d8/0x269521.
> 
> **Source**: `ref:544e0b5ea9` · `ref:b35981618a` · `ref:debd9c13f6`

### 8. Geolocation lookup for evasion

`T1614` · Confidence **high** · dynamic

It requests hxxp://ip-api[.]com/json/?fields=countryCode to obtain the egress country, and the device ID uses the form XX_<public IP>; the configuration shows GEO_BLOCKING_ENABLED=false.

> **Evidence**: dynamic GET /json/?fields=countryCode, Host: ip-api[.]com; strings '[GEO] Geo-blocking disabled (GEO_BLOCKING_ENABLED=false)' and 'countryCode'.
> 
> **Source**: `ref:544e0b5ea9` · `ref:60d4ce909d`

### 9. Stage components in temporary directories

`T1074.001` · Confidence **high** · dynamic

Under %LOCALAPPDATA%\Temp it creates the rxclient_<timestamp>, rxinj_<timestamp> and rxlss_<timestamp> directories for collection results, helper.exe and lss.exe respectively; the rxclient directory is cleaned up after the task ends.

> **Evidence**: dynamic memory paths 'C:\Users\<user>\AppData\Local\Temp\rxclient_1793917877417917500\output', '...\rxinj_1793917890002939300\helper.exe', '...\rxlss_1793917890231685800\lss.exe'.
> 
> **Source**: `ref:a83af8f3c6` · `ref:f296979c36`

### 10. Bundled remote-control component

`T1219` · Confidence **medium** · static

After the data of its last section the main program appends a complete 7,533,734-byte PE (bridge.exe); its strings indicate a remote-control agent with a Backstage workspace, private-CA WebSocket, ConPTY command line, clipboard and input injection and browser-profile migration, and it sets up an HKCU Run autostart; this component was not seen executing in this observation window.

> **Evidence**: appended PE from file offset 0x30F600; strings 'bridge-agent-v5.1.4-chrome-launch-fidelity', 'Local\BridgeAgent-', 'HKCU\Software\Microsoft\Windows\CurrentVersion\RunBridgeAgent', 'X-Bridge-Server-Time'.
> 
> **Source**: `ref:bd70bd6229` · `ref:d47603756a`


## IOC (defanged)

### Network

:::note
**A connection was observed dynamically**: the sample actually initiated TCP connections to this target (retried several times within a short period).
:::

:::caution
**The real server side is still unverified**: the connection/handshake above was completed with a local controlled emulation service, so the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://176[.]65[.]144[.]46/api/forensics` | 443 | exfil | dynamic | observed |
| http | `hxxps://176[.]65[.]144[.]46/api/agent/connect` | 443 | c2 | dynamic | observed |

### Host

**Mutexes**

- `Local\BridgeAgent-<session id>`

**Dropped paths**

- `%LOCALAPPDATA%\Temp\rxclient_<timestamp>\output`
- `%LOCALAPPDATA%\Temp\rxclient_<timestamp>\output\octo-fingerprint.json`
- `%LOCALAPPDATA%\Temp\rxclient_<timestamp>\output\mimikatz-credentials\lss.dmp`
- `%LOCALAPPDATA%\Temp\rxinj_<timestamp>\helper.exe`
- `%LOCALAPPDATA%\Temp\rxlss_<timestamp>\lss.exe`
- `%ProgramData%\BridgeAgent`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BridgeAgent`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `176.65.144[.]46:443` | yes | static |
| `exfil_endpoint` | `/api/forensics` | yes | dynamic |
| `connect_endpoint` | `/api/agent/connect` | yes | static |
| `upload_type` | `forensics.zip` | yes | dynamic |
| `request_headers` | `X-Device-ID; X-Signature; X-Country; X-Public-IP` | yes | dynamic |
| `device_id_format` | `XX_<public_ip>` | yes | dynamic |
| `geo_lookup` | `hxxp://ip-api[.]com/json/?fields=countryCode` | no | dynamic |
| `geo_blocking_enabled` | `false` | no | static |
| `zip_schedule` | `fast=90s; complete=300s` | yes | static |
| `encryption_algo` | `none (plain ZIP in multipart/form-data)` | no | dynamic |
| `mutex` | `Local\BridgeAgent-<session id>` | no | static |
| `install_path` | `%ProgramData%\BridgeAgent` | no | static |
| `persistence` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\BridgeAgent` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- It is not ransomware: no file encryption, extension tampering or ransom note was found; the behavior centers on theft and exfiltration.
- It is not a miner: no mining pool address, mining library or hashrate-related component was found.
- No worm-like propagation or lateral-movement execution was observed: '[LATERAL] collected' only means remote-access configuration was collected, not that lateral movement occurred.
- The appended bridge.exe was not observed executing in this run, so it cannot be asserted that it completed installation or persistence.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. Per the isolation requirement no real internet connection was made, so the C2 domain, server ownership and TLS certificate information could not be obtained; only the hardcoded IP and port were confirmed.
2. The appended bridge.exe remote-control component did not execute within this observation window; its persistence and remote-control capabilities are inferred from static strings.
3. No plaintext configuration block was located; configuration items were recovered from static strings and dynamic request fields, and any additional encrypted configuration could not be confirmed.
4. The LSASS dump file was generated but not further parsed, so the specific account passwords in it cannot be listed.
5. The family naming lacks public-engine or rule cross-validation; 'Bridge Agent / Backstage' is a candidate attribution based on built-in identifiers.

## Evidence index

<details>
<summary>Expand 14 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:1614b1909c` | sample triage | hashes, section entropy, packing score 0, import-surface statistics |
| `ref:4b4e2baba2` | PE structure parsing | AMD64 GUI PE, 5 sections, entry RVA 0x101f80, image size 0x312000 |
| `ref:6cd264693f` | import table parsing | 17 DLLs/182 imports, including ws2_32, crypt32, secur32, ntdll file and pipe APIs |
| `ref:60d4ce909d` | string extraction | collector, wallet, browser, LSASS, C2 and dual-ZIP strategy strings |
| `ref:bd70bd6229` | PE structure parsing | appended tail PE: 6 sections, image 0x736000, GUI subsystem |
| `ref:d47603756a` | import table parsing | appended PE imports USER32/CRYPT32/CreatePseudoConsole and other remote-control-related APIs |
| `ref:d3fb77fedb` | PE structure parsing | embedded lss.exe: 4 sections, no imports, console subsystem |
| `ref:6060cd3615` | import table parsing | lss.exe import table empty (pure syscalls) |
| `ref:544e0b5ea9` | dynamic analysis platform | real sample detonation: process 7256 kept running, memory dump and network redirect logs captured |
| `ref:b35981618a` | script | extracted POST /api/forensics request headers, multipart fields and the 21,640,997-byte size from network monitoring logs |
| `ref:debd9c13f6` | script | confirmed TCP 176.65.144[.]46:443 and the ip-api[.]com query from network monitoring logs |
| `ref:a83af8f3c6` | script | extracted rxclient/rxinj/rxlss paths, octo-fingerprint.json and C2 strings from the memory dump |
| `ref:f296979c36` | script | extracted '[INFO] [LSASS] dump 54542958 bytes' and the mimikatz-credentials\lss.dmp path from runtime memory |
| `c2_evidence:d356ef60` | connection evidence extraction | dynamic network monitoring recorded 5 connection attempts to 176.65.144[.]46:443 and ip-api[.]com:80; no complete session captured |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
