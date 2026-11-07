---
title: "Malware Analysis: SalatStealer (PE · exe · 68a2ae3c)"
published: 2026-11-07
draft: false
description: "Malicious (high confidence): SalatStealer · stealer/rat/backdoor · difficulty hard · Dynamic sandbox analysis + static decompilation"
tags: ["Salat", "stealer", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-07-SalatStealer-68a2ae3c"
---

> [!WARNING]
> **Verdict: Malicious** · Family **SalatStealer** · Confidence **high**
> 
> Aliases: Salat, Salat RAT, salat/2.0
> 
> The sample process really executed in a dynamic sandbox and periodically connected out to two .cn domains, POSTing data to the /qqkb/ path; combined with built-in browser credential theft, keylogging, screen/webcam capture, token theft and remote command modules, it is judged to be hybrid information-stealing and remote-control malware.

## Overview

| Item | Content |
|:--|:--|
| Family | **SalatStealer** · aliases Salat, Salat RAT, salat/2.0 |
| Confidence | **high** |
| Behavior class | stealer · rat · backdoor |
| Difficulty | hard |
| First seen | 2026-11-04 14:42:18 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/68a2ae3c48e8da2c291354023c92330193589430024477765cb1acf26717f61d/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Resolve C2 domains via DoH</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.004</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Exfiltrate to dual domains</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1041</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Steal browser credentials</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Collect sessions and wallets</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Log keys and screenshot</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001, T1113</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `68a2ae3c48e8da2c291354023c92330193589430024477765cb1acf26717f61d` |
| MD5 | _not recorded_ |
| Size | 6,495,232 bytes (6.2 MB) |
| Type | PE · `exe` |

## Behavior analysis

**11** behaviors in total, each backed by evidence; **9** are statically available and **2** were obtained through dynamic analysis.

### 1. Resolve C2 domains via DoH

`T1071.004` · Confidence **high** · dynamic

It queries the DoH interfaces of 1.1.1[.]1, 8.8.8[.]8, and dns.google to obtain C2 domain addresses, bypassing local DNS monitoring.

> **Evidence**: dynamic: process 7308 connected to 1.1.1[.]1:443/8.8.8[.]8:443, requesting /dns-query?name=morkovka[.]cn and /resolve?name=sa1atik[.]cn; static strings 0x4B01EB, 0x4CFFD8.
> 
> **Source**: `ref:8a13a267b8` · `ref:b0fdf2ab16`

### 2. Exfiltrate data to two domains

`T1041` · Confidence **high** · dynamic

After successful resolution it sends HTTP POSTs to the /qqkb/ path of both domains, carrying host and stolen data, and reconnects periodically.

> **Evidence**: dynamic: about 30 seconds after startup it POSTs /qqkb/, with Host morkovka[.]cn and sa1atik[.]cn; it then reconnects about every 20 seconds, UA salat/2.0.
> 
> **Source**: `ref:8a13a267b8` · `ref:b0fdf2ab16`

### 3. Steal browser credentials

`T1555.003` · Confidence **high** · static

It enumerates Chromium/Gecko user profiles, extracts cookies, login credentials, autofill and extension data, decrypting with CryptUnprotectData and the Local State master key.

> **Evidence**: strings 0x4A6278 src/makelog/invdump/chrome.rs, 0x4A6296 gecko.rs, 0x4AD16F Local State/app_bound_encrypted_key, 0x4A3287 Browsers/Logins_; imports CryptUnprotectData.
> 
> **Source**: `ref:b0fdf2ab16` · `ref:3b4d64aae0`

### 4. Collect sessions and wallets

`T1539` · Confidence **high** · static

It collects Telegram tdata, Discord/Steam/Roblox tokens and local encrypted wallets, and queries balances through public-chain RPC.

> **Evidence**: strings 0x4A2FD7 telegram candidates, 0x4A2FEE DiscordTokens.txt, 0x4A304D SteamTokens.txt, 0x4A30A6 zipping wallets; dynamic DNS queries for toncenter[.]com, tonapi[.]io, eth[.]drpc[.]org, etc.
> 
> **Source**: `ref:b0fdf2ab16` · `ref:8a13a267b8`

### 5. Log keystrokes and take screenshots

`T1056.001, T1113` · Confidence **high** · static

It installs a global keyboard hook and polls key states, uses GDI to capture screen pixels, producing keylogs and screenshots.

> **Evidence**: strings 0x4D1DBC keytest-quit-helper, 0x4D1E38 SetWindowsHookExW returned NULL; imports GetAsyncKeyState, SetWindowsHookExW, BitBlt, GetDIBits.
> 
> **Source**: `ref:b0fdf2ab16` · `ref:3b4d64aae0`

### 6. Enable webcam and audio recording

`T1125` · Confidence **high** · static

It enumerates video devices through Media Foundation and captures webcam frames, while collecting microphone data through an audio library.

> **Evidence**: strings 0x4A7400 src/camera.rs, 0x4A6B08 src/sound.rs; imports MFEnumDeviceSources, MFTEnumEx, D3D11CreateDevice and cpal-related symbols.
> 
> **Source**: `ref:b0fdf2ab16` · `ref:3b4d64aae0`

### 7. Execute remote commands

`T1059` · Confidence **high** · static

It ships shell, file manager, task manager, process suspend/resume, and upload/download modules, and can execute operator commands and return their output.

> **Evidence**: strings 0x4A297B src/shell.rs, 0x4A7458 src/execute.rs, 0x4A789A src/filemanager.rs, 0x4A7990 src/taskmanager.rs; imports CreateProcessW, CreatePipe, NtSuspendProcess/NtResumeProcess.
> 
> **Source**: `ref:b0fdf2ab16` · `ref:3b4d64aae0`

### 8. Steal tokens across sessions

`T1134.001` · Confidence **high** · static

It enumerates session and process tokens, duplicates/impersonates SYSTEM or logged-on user tokens, switches to the active session, and creates processes with that token.

> **Evidence**: strings 0x4D2480 OpenProcessToken, 0x4D24D0 SetTokenInformation(TokenSessionId=), 0x4D16A8 CreateProcessWithTokenW, 0x4D1F9A migrate_session; imports WTSQueryUserToken, DuplicateTokenEx, CreateProcessAsUserW.
> 
> **Source**: `ref:b0fdf2ab16` · `ref:3b4d64aae0`

### 9. Register services and autostart

`T1547.001, T1543.003` · Confidence **medium** · static

It writes the current user's Run key and has the ability to create/start Windows services, used for boot autostart and privilege retention.

> **Evidence**: strings 0x4D1A11 SOFTWARE\Microsoft\Windows\CurrentVersion\Run, 0x4ABF60 OpusUpdateOpusSvc; imports RegSetValueExW, CreateServiceW, StartServiceW.
> 
> **Source**: `ref:b0fdf2ab16` · `ref:3b4d64aae0`

### 10. Add Defender exclusions

`T1562.001` · Confidence **high** · static

It embeds a base64-encoded PowerShell script that calls Add-MpPreference to add Program Files, AppData, and LocalAppData to Defender exclusion paths.

> **Evidence**: base64 at offset 0x4AE838 decodes to PowerShell: Add-MpPreference -ExclusionPath (ProgramFiles, ProgramFilesX86, ApplicationData, LocalApplicationData).
> 
> **Source**: `ref:b0fdf2ab16`

### 11. RDP tunnel and intranet proxy

`T1572, T1021.001` · Confidence **medium** · static

It contains RDP child sessions, WebSocket/QUIC/HTTP3 tunnels, and proxy modules, able to establish remote desktop and intranet forwarding channels on the controlled endpoint.

> **Evidence**: strings rdp_child/src/rdp/*, 0x4A6F71 connect p2_server tunnel, 0x4A6998 src/proxy.rs, 0x4A6B48 tokio-tungstenite, 0x4A6690 h3/quinn; imports WTSEnableChildSessions, WTSQueryUserToken.
> 
> **Source**: `ref:b0fdf2ab16` · `ref:3b4d64aae0`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated a TCP connection to this target (with several retries in a short period).
:::

:::caution
**The real server side remains unverified**: the above connection/handshake was completed with a local controlled emulation service, and the real C2's responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://morkovka[.]cn/qqkb/` | 443 | c2 | dynamic | observed |
| http | `hxxps://sa1atik[.]cn/qqkb/` | 443 | c2 | dynamic | observed |

### Host

**Mutexes**

- `Global\WEBR_FL0APC6K5F44`

**Dropped paths**

- `%APPDATA%\Local\<browser profile data>`
- `%LOCALAPPDATA%\<browser profile data>`
- `%ProgramFiles%\<install_dir>\opus-installscript`
- `%ProgramFiles(x86)%\<install_dir>\opus-installscript`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

**Services**

- `OpusUpdate`
- `OpusSvc`

**Scheduled tasks**

- `OpusElvMigrate`
- `OpusElvScreen`
- `OpusElvChild`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `morkovka[.]cn, sa1atik[.]cn` | yes | dynamic |
| `c2_path` | `/qqkb/` | yes | dynamic |
| `user_agent` | `salat/2.0` | yes | static |
| `dns_over_https` | `1.1.1[.]1, 8.8.8[.]8, dns.google` | no | dynamic |
| `mutex` | `Global\WEBR_FL0APC6K5F44` | no | static |
| `persistence_run_key` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | no | static |
| `service_names` | `OpusUpdate, OpusSvc` | no | static |
| `install_marker` | `opus-installscript, opus-runscript, opus-child-stdin` | no | static |
| `encryption_algo` | `AES-GCM/ChaCha20-Poly1305; TLS 1.3 (rustls) for C2 transport` | no | static |
| `defender_exclusion_script` | `base64 PowerShell Add-MpPreference exclusion paths` | no | static |
| `browser_targets` | `Chromium/Gecko cookies, logins, tokens, autofill` | yes | static |
| `wallet_and_session_targets` | `Telegram tdata, Discord/Steam/Roblox tokens, crypto wallets, Ethereum/TON RPC` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- No file encryption, shadow-copy deletion, or ransom note was seen, so it cannot be classed as ransomware/wiper.
- It ships complete data-theft and remote-control modules; it is not merely a downloader/loader that fetches later payloads.
- The real C2 IP was not captured; domains are resolved through DoH, and 1.1.1[.]1/8.8.8[.]8 are resolution channels, not C2 servers.
- Successful privilege escalation, actual service registration, or installation-directory drops were not directly observed during the dynamic run; those capabilities come mainly from code strings and the API surface.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. No plaintext configuration was extracted statically; C2 domains come from dynamic DoH resolution and POST request observation.
2. The final names of the install directory, service registration, and scheduled tasks were not directly confirmed within the dynamic window; IOCs are inferred from embedded strings.
3. Capabilities such as RDP child sessions and camera/audio capture are proven by module paths and the API surface but were not actually triggered in the sandbox.
4. The real C2 IP was not resolved (the network was safely redirected), so only domain-level IOCs are kept.
5. Family naming is based on the embedded salat/2.0 identifier and callback domains, without cross-confirmation from vendor engines or YARA rules.

## Evidence index

<details>
<summary>Show 9 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprints | sha256/md5/sha1 and file size |
| `ref:260dbdc87a` | Sample triage | 6 sections, entropy 6.37/6.44, no packing, 40 DLLs/415 imports |
| `ref:ccc8eeb9ea` | PE structure parsing | PE64 GUI, entry RVA 0x3885A0, no anomalies |
| `ref:3b4d64aae0` | Import table parsing | CryptUnprotectData, SetWindowsHookExW, WTSQueryUserToken, CreateServiceW, etc. |
| `ev-000009` | String extraction | Rust project paths, browser/wallet/Telegram targets and C2-related strings |
| `ev-000013` | Cryptographic constant identification | AES S-box, SHA-256, CRC32, base64 constants |
| `ref:379b82c521` | unpack.detect | No packing detected |
| `ref:8a13a267b8` | Dynamic analysis platform | Real run PID 7308; DoH resolution of morkovka[.]cn/sa1atik[.]cn, POST /qqkb/, UA salat/2.0 |
| `c2_evidence:68a2ae3c` | Connection evidence extraction | Dynamic network monitoring recorded 123 connection attempts to 1.1.1[.]1:443, 1[.]1[.]1[.]1:443, 1rpc[.]io:443, 8.8.8[.]8:443, base-mainnet[.]public[.]blastapi[.]io:443, base[.]api[.]pocket[.]network:443, base[.]gateway[.]tenderly[.]co:443, dns[.]google:443, gateway[.]tenderly[.]co:443, mainnet[.]base[.]org:443, morkovka[.]cn:443, rpc[.]baseazul[.]dev:443, sa1atik[.]cn:443; no complete session was captured |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
