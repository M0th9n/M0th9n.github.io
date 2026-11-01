---
title: "Malware Analysis: Unattributed Go-based stealer/RAT (v0.28.2) (PE · exe · ba5f005a)"
published: 2026-10-31
draft: false
description: "Malicious (low confidence): Unattributed Go-based stealer/RAT (v0.28.2) · stealer/rat/backdoor · difficulty medium · dynamic sandbox + static decompilation"
tags: ["stealer", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-31-Unattributed-Go-based-stealer-RAT-v0.28.2-ba5f005a"
---

> [!WARNING]
> **Verdict: malicious** · Family **Unattributed Go-based stealer/RAT (v0.28.2)** (uncertain) · Confidence **low**
> 
> The sample is a UPX-packed 32-bit Go program that actually ran inside an isolated Windows environment and kept reaching out (TCP/443, UDP/443), and a memory image recovered the complete payload; the payload's strings contain SQL queries for browser login credentials/cookies, collection of crypto wallets and Telegram/Discord/Steam data, clipboard/screen/webcam capture, remote shell/port forwarding, scheduled-task persistence and QUIC/WebSocket plus DoH communication code, which in functional terms makes it a credential stealer and a remote-control backdoor.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unattributed Go-based stealer/RAT (v0.28.2)** · _uncertain_ |
| Confidence | **low** |
| Behaviour class | stealer · rat · backdoor |
| Difficulty | medium |
| First seen | 2026-10-29 00:45:20 |
| Analysis method | dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ba5f005a7d4c9969ef3152be044ea3875d598e0838fa4f905e5491f129cc4cc5/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX self-unpacks payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Steal browser logins</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Dump cookies, autofill</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Harvest wallets, TON</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555, T1005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">QUIC/DoH covert C2</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001, T1573</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `ba5f005a7d4c9969ef3152be044ea3875d598e0838fa4f905e5491f129cc4cc5` |
| MD5 | _not recorded_ |
| Size | 3,592,878 bytes (3.4 MB) |
| Type | PE · `exe` |

## Behaviour analysis

**12** behaviours in total, each backed by evidence; **11** of them are statically observable and **1** was obtained through dynamic analysis.

### 1. UPX self-extraction loads the payload

`T1027.002` · Confidence **high** · static

The file is a three-section UPX self-extracting structure (UPX0/UPX1/UPX2), with the entry point inside the high-entropy writable-executable section UPX1; at runtime it restores roughly 12.9 MB of Go payload in memory.

> **Evidence**: UPX1 entropy 8.0; only 4 imports (LoadLibraryA/GetProcAddress/VirtualProtect/ExitProcess); in-memory payload entry rva 0xC54020.
> 
> **Source**: `ev-000008` · `ev-000005` · `ref:6143f4c3f4` · `ref:327dc29626`

### 2. Steal browser login credentials

`T1555.003` · Confidence **high** · static

Walks the profile directories of mainstream browsers and uses SQLite queries to read saved usernames/passwords and decrypt the browser master key.

> **Evidence**: strings 'SELECT origin_url, action_url, username_value, password_value, date_created FROM logins', Firefox 'SELECT item1,item2 FROM metaData WHERE id = password', 'key4.db', 'logins.json', 'Local State'.
> 
> **Source**: `ref:8e3e4ea0f1` · `ev-000039`

### 3. Export cookies and autofill

`T1539` · Confidence **high** · static

Reads the browser cookie and autofill databases, exporting host/path/expiry and the encrypted values.

> **Evidence**: strings 'SELECT name,encrypted_value,host_key,path,expires_utc FROM cookies WHERE length(encrypted_value) > 0', 'SELECT name, value, host, path, expiry FROM moz_cookies', 'Autofills', 'cookies.sqlite'.
> 
> **Source**: `ref:8e3e4ea0f1`

### 4. Harvest crypto wallets and TON

`T1555, T1005` · Confidence **high** · static

Scans browser wallet extensions and local wallet directories, reads wallet keys/addresses, and bundles the TON blockchain library to handle TON wallets.

> **Evidence**: wallet name list Metamask/Phantom/Keplr/TronLink/Exodus/Electrum and others; 'Crypto\Roaming', 'Electrum\wallets', 'XMR.PT'; dependency github[.]com/xssnick/tonutils-go@v1.16.0.
> 
> **Source**: `ref:8e3e4ea0f1` · `ref:22e1ccc08c`

### 5. Steal Discord, Telegram and Steam sessions

`T1528, T1555` · Confidence **high** · static

Extracts Discord tokens, Telegram tdata sessions and Steam login information.

> **Evidence**: strings 'Clients\DiscordTokens.txt', '$appdata\discord', 'tdata', 'loginusers.vdf', 'SteamPath', 'found tg process'.
> 
> **Source**: `ref:8e3e4ea0f1` · `ref:22e1ccc08c`

### 6. Monitor clipboard and screen

`T1115, T1113` · Confidence **high** · static

Reads clipboard contents (including wallet addresses/passwords) and calls a screenshot library to capture the screen.

> **Evidence**: API strings GetClipboardData/SetClipboardData/OpenClipboard; 'Clipboard:', 'PrintScreen'; symbols salat/screenshot.CaptureRect.
> 
> **Source**: `ref:8e3e4ea0f1` · `ref:22e1ccc08c`

### 7. Capture webcam and microphone

`T1125` · Confidence **high** · static

Obtains webcam video and microphone audio through an ffmpeg-style capture pipeline for viewing by the remote side.

> **Evidence**: symbols ffwcam/ffwmic/DesktopFF; strings 'aformat=sample_fmts=s32:channel_layouts=mono:sample_rates=32000', 'audio= video='.
> 
> **Source**: `ref:22e1ccc08c`

### 8. Expose a remote shell and port forwarding

`T1059, T1090` · Confidence **high** · static

Bundles a remote shell, port forwarding and chunked file-transfer capability, sending and receiving commands and data over WebSocket.

> **Evidence**: symbols startShell/stopShell/shellProc/portFwd/recvWss/wsMessage/chunkSize; strings 'cmd.Run failed with %s', 'taskkill /F /PID'.
> 
> **Source**: `ref:22e1ccc08c`

### 9. Register a scheduled task for persistence

`T1053.005` · Confidence **high** · static

Registers/deletes scheduled tasks through the Task Scheduler COM interface, configured to start only when a network is available in order to stay alive.

> **Evidence**: interface/property strings ITaskService, RegisterTaskDefinition, StartBoundary, RunOnlyIfNetworkAvailable, error registering task; dependency capnspacehook/taskmaster.
> 
> **Source**: `ref:22e1ccc08c` · `ref:881f995d64`

### 10. Abuse tokens to elevate privileges

`T1134` · Confidence **medium** · static

Adjusts process privileges and duplicates/abuses access tokens so that it can read protected processes and browser data.

> **Evidence**: strings RtlAdjustPrivilege, OpenProcessToken, DuplicateTokenEx, CopySid, 'OpenProcess failed: %v', 'lsass.exe'.
> 
> **Source**: `ref:8e3e4ea0f1`

### 11. Covert callbacks over QUIC and DoH

`T1071.001, T1573` · Confidence **high** · dynamic

Uses QUIC/HTTP3 and WebSocket as the command channel and resolves the C2 domain over DoH to evade DNS monitoring.

> **Evidence**: dependency quic-go@v0.38.1; strings 1.1.1[.]1/dns-query, cloudflare-dns[.]com/dns-query, dns.google/resolve, bestConnMethod, http3 DISABLED; dynamically observed process 1768 repeatedly connecting to UDP 1.1.1[.]1:443 and TCP simulated-network address:443 (128 TCP 443 connections in total).
> 
> **Source**: `ref:21fbc7a749` · `ref:881f995d64` · `ref:9188bc1dfc`

### 12. Embedded WASM module loading

`T1027.009` · Confidence **medium** · static

The payload embeds two WebAssembly modules that are interpreted at runtime by wazero, hiding part of the logic.

> **Evidence**: memory image offsets 0x69C6A0 and 0xB56B38 both hold the '00 61 73 6D 01 00 00 00' magic; dependency tetratelabs/wazero@v1.8.2.
> 
> **Source**: `ref:22e1ccc08c` · `ref:881f995d64`


## IOC (defanged)

### Network

:::note
**Connections were dynamically observed**: the sample actually initiated TCP connections to this target (retrying several times within a short window).
:::

:::caution
**The real server side remains unverified**: the connections/handshakes above were completed against a locally controlled emulation service, so the real C2's responses and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| other | `hxxps://1[.]1[.]1[.]1/dns-query` | 443 | c2 | dynamic | observed |
| other | `hxxps://cloudflare-dns[.]com/dns-query` | 443 | c2 | static | ⏳ not observed |
| other | `hxxps://dns[.]google/resolve` | 443 | c2 | static | ⏳ not observed |
| other | `C2 host hidden behind DoH (not recovered)` | 443 | c2 | dynamic | ⏳ not observed |

### Host

**Drop paths**

- `%LOCALAPPDATA%\<browser>\User Data\Local State`
- `%LOCALAPPDATA%\<browser>\User Data\Default\Login Data`
- `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\key4.db`
- `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\logins.json`
- `%APPDATA%\discord\Local Storage\leveldb`
- `%APPDATA%\<wallet>\Crypto\Roaming`
- `%TEMP%\chunk`
- `%APPDATA%\<app>\Clients\DiscordTokens.txt`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `version` | `0.28.2 (x86)` | no | static |
| `c2_transport` | `QUIC/HTTP3 + WebSocket (gorilla/websocket)` | yes | static |
| `dns_resolvers` | `1.1.1[.]1 / cloudflare-dns[.]com / dns.google (DoH)` | yes | static |
| `c2_host` | `unresolved (DoH-resolved at runtime; not recovered)` | yes | dynamic |
| `c2_port` | `443` | no | dynamic |
| `persistence` | `Windows Task Scheduler COM (RegisterTaskDefinition)` | no | static |
| `encryption_algo` | `AES-CBC (browser master key), X25519, DPAPI` | no | static |
| `browser_targets` | `Chrome/Chromium-based, Firefox, Edge, Brave, Opera and 30+ other browsers` | no | static |
| `wallet_targets` | `MetaMask/Phantom/Keplr/TronLink/Exodus/Electrum/TON wallets and others` | no | static |
| `capabilities` | `credential/cookie/wallet/Discord/Telegram/Steam/clipboard/screen/webcam/mic/shell/port-forward/file-transfer` | no | static |

## Don't misread this

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- It cannot be judged ransomware: no bulk encryption of user files, ransom note, shadow-copy deletion or backup destruction was seen; the AES/CBC constants are used to decrypt the browser master key, not to encrypt files.
- It cannot be judged a miner: no mining-pool address, Stratum protocol or xmrig-related strings were found, and no pool connection was observed during the dynamic run.
- Worm-like lateral movement cannot be asserted: no SMB/PsExec/remote service creation or other lateral behaviour was observed.
- Membership of a named commercial family cannot be asserted: vendor signatures, YARA hits and readable configuration are all missing, so the family attribution remains doubtful.
- The rdtsc/int 2Dh/cpuid hits in the UPX decompression stub are runtime characteristics of the packer and are not grounds for concluding that the sample actively performs anti-debugging.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | dynamic sandbox analysis + static decompilation |
| Unpacked | yes (stage2 `086db9c7dc770690474e48b74e1be1a0c23934d94d812ab8dae7954e32d8c9fd`) |

**Limitations and open questions**

1. The actual C2 domain was not recovered: the sample resolves preferentially over DoH (1.1.1[.]1 / cloudflare-dns[.]com / dns.google), and the simulated-network DNS cannot record plaintext queries.
2. The 192.0.2[.]123:443 seen in the dynamic observations is the simulated-network reply address of the isolated environment, not the real C2, and must not be used as an external IOC.
3. The recovered payload comes from a process memory image (rebuilt according to memory alignment) and may differ in section layout from the original packed file on disk; its hash identifies that memory image only.
4. No concrete records of persistence actions such as scheduled tasks or registry writes were observed; the persistence capability is inferred from code/strings and was not closed out dynamically.
5. No signature or configuration allowing the family to be named was obtained; the family field is only a capability description and has low confidence.
6. The anti-debug heuristic hits triggered by the UPX decompression stub were not dynamically verified as the sample's own behaviour.

## Evidence index

<details>
<summary>Show 17 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hash and fingerprint | SHA256/MD5/SHA1 and file size 3,592,878 bytes |
| `ev-000008` | sample triage | packer likelihood 85%, UPX section names, W^X, only 4 imports |
| `ref:6143f4c3f4` | import table parsing | original imports are only KERNEL32: LoadLibraryA/ExitProcess/GetProcAddress/VirtualProtect |
| `ref:327dc29626` | unpack.detect | identified as UPX, confidence 0.9 |
| `ref:cafc67b8d0` | unpack.antidebug | rdtsc/int 2Dh/cpuid hits inside the UPX1 section (packer stub) |
| `ref:9188bc1dfc` | dynamic analysis platform | real detonation succeeded, PID 1768 stayed alive and produced 16 memory dump files |
| `ref:f7e6706ca5` | sandbox.timeline | timeline: 1 candidate process, hollows scan of 2 suspicious objects |
| `ref:97090bbd97` | memory dump | dump report: PID 1768 is a 32-bit unmanaged process, main module 0xC55000 bytes |
| `ref:9a5b32b80a` | dynamic artefact collection | simulated-network logs and dump import leads; the sample opened a large number of 443 connections |
| `ref:33aa545e67` | PE structure parsing | in-memory payload PE structure: I386, 3 sections, entry rva 0xC54020 |
| `ev-000039` | string extraction | in-memory payload strings: Go build ID, QUIC frames, wallet/browser related strings |
| `ref:881f995d64` | strings | Go build information, module dependencies, DoH endpoints and QUIC library |
| `ref:8e3e4ea0f1` | strings | browser SQL queries, wallet list, Discord/Telegram/Steam paths, task-scheduler and token APIs |
| `ref:21fbc7a749` | strings | configuration/domain extraction and simulated-network event counts: 1768 opened 128 TCP and UDP connections to 443 |
| `ref:22e1ccc08c` | strings | remote-control capability symbols (shell/portFwd/ffwcam/ffwmic) and two WASM magic values |
| `ref:dda6b8e31f` | strings | ransomware/miner keywords excluded; no named-family marker found |
| `c2_evidence:ba5f005a` | connection evidence extraction | dynamic network monitoring recorded 130 connection attempts to 1.1.1[.]1:443, sa1atik[.]cn:443, ton[.]access[.]orbs[.]network:443, tonapi[.]io:443; no complete session was captured |

</details>

---

_This sample is not shared; IOCs are defanged. For security research only._
