---
title: "Malware Sample Analysis: SalatStealer (PE · exe · 374d0e88)"
published: 2026-11-11
draft: false
description: "Malicious (medium confidence): SalatStealer · rat/stealer/backdoor · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Salat", "rat", "stealer", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-11-SalatStealer-374d0e88"
---

> [!WARNING]
> **Verdict: malicious** · Family **SalatStealer** (uncertain) · Confidence **medium**
> 
> Aliases: Salat, Salat Stealer, LummaStealer (naming used by some engines)
> 
> The sample is a stealer/remote-control program written in Go: statically it contains complete function chains for browser password and cookie decryption, Discord/Telegram/Steam session theft, keylogging, desktop/camera/microphone streaming, remote shell, SOCKS5 proxy, privilege escalation and LSASS location; in the dynamic sandbox, after startup the process continuously sends HTTP beacons to sa1atik[.]cn:443 and polls TON blockchain DNS to resolve a fallback address, behavior consistent with a stealer RAT.

## Overview

| Item | Content |
|:--|:--|
| Family | **SalatStealer** · aliases Salat, Salat Stealer, LummaStealer (naming used by some engines) · _uncertain_ |
| Confidence | **Medium** |
| Behavior class | rat · stealer · backdoor |
| Difficulty | medium |
| First seen | 2026-11-11 05:26:20 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/374d0e8898a40eac478e4139d2ba5134286eebd6de569c8103dc080c3f6ba558/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Resolve TON covert address</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102,T1568.002</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">HTTPS beacon callback</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Steal browser credentials</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555.003,T1539</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Steal chat and Steam sessions</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1539,T1555</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Keylogging</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1056.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `374d0e8898a40eac478e4139d2ba5134286eebd6de569c8103dc080c3f6ba558` |
| MD5 | _Not recorded_ |
| Size | 12,570,838 bytes (12.0 MB) |
| Type | PE · `exe` |

## Behavior analysis

**11** behaviors in total, each backed by evidence; **8** are available statically and **3** were obtained through dynamic analysis.

### 1. Resolve TON covert address

`T1102,T1568.002` · Confidence **high** · Dynamic

After startup it calls public TON APIs to resolve the remoteadministratortool[.]ton and webratxaye1 records, replacing a hardcoded C2 with blockchain DNS so that infrastructure can be swapped at any time.

> **Evidence**: Dynamic network log: GET tonapi[.]io/v2/dns/remoteadministratortool[.]ton/resolve; POST ton[.]access[.]orbs[.]network/route/1/mainnet/toncenter-api-v2/runGetMethod (dnsresolve: webratxaye1)
> 
> **Source**: `ev-000039`

### 2. HTTPS beacon callback

`T1071.001` · Confidence **high** · Dynamic

The process sends GET /sa1at/ to sa1atik[.]cn:443 about every 15 seconds, with an 88-byte binary request body and a User-Agent of Go-http-client/1.1.

> **Evidence**: Dynamic network log: Host: sa1atik[.]cn; GET /sa1at/; Content-Length: 88; process PID 2940 repeats continuously
> 
> **Source**: `ev-000039`

### 3. Steal browser credentials

`T1555.003,T1539` · Confidence **high** · Static

Enumerates Login Data, Cookies, Autofill and Token_Network of browsers such as Chrome/Edge/Brave/Firefox/Yandex/Opera, decrypts them with DPAPI, App-Bound Encryption and NSS PBE, and packages the result.

> **Evidence**: main.getChromeLogins 0x4f2dc0, main.GetChromiumMasterKeys 0x4f8090, main.getGeckoLogins 0x4eac00; strings Browsers\Token_Network\Cookies, Ya Passman Data, Login Data
> 
> **Source**: `ev-000037` · `ev-000035`

### 4. Steal chat and Steam sessions

`T1539,T1555` · Confidence **high** · Static

Reads session data such as Discord tokens, Telegram tdata and Steam configuration/SSFN for subsequent account takeover.

> **Evidence**: main.getDiscord 0x4eb850, main.getSteams 0x4ef1b0, main.decodeSteam 0x4eeb50; strings Clients\DiscordTokens.txt, Local\Packages\TelegramDesktop
> 
> **Source**: `ev-000037` · `ev-000035`

### 5. Keylogging

`T1056.001` · Confidence **high** · Static

Installs a keyboard hook and continuously records keystrokes and the foreground window title, forming an input log.

> **Evidence**: main.startKeylogger 0x4caae0, main.keyPressCallback 0x4d17e0, main.runKeylogger 0x4d1e30; string Active window
> 
> **Source**: `ev-000035`

### 6. Screen, camera and microphone capture

`T1113,T1125` · Confidence **high** · Static

Streams the desktop image, camera image and microphone audio on command from the control side.

> **Evidence**: main.(*wsSess).ffdesktop 0x4c7860, ffwcam 0x4c8c00, ffwmic 0x4c8350, main.screenStream 0x4cadf0
> 
> **Source**: `ev-000035`

### 7. Remote shell execution

`T1059.003,T1105` · Confidence **high** · Static

Receives commands through a WebSocket session, calls cmd/PowerShell to execute them and can download follow-up payloads.

> **Evidence**: main.(*wsSess).execCommand 0x4c7730, main.shellCommand 0x4e53f0, main.downloadFile 0x4cafd0; strings wmic, /PID, RES::443
> 
> **Source**: `ev-000035` · `ev-000037`

### 8. Built-in SOCKS5 proxy

`T1090` · Confidence **high** · Static

Opens a SOCKS5/P2P proxy on the victim host, providing the attacker with traffic relay and intranet pivoting capability.

> **Evidence**: main.proxySocks 0x4cdb50, main.p2pSocks 0x4cd8f0, main.(*socks5Conn).handshake 0x4ce580; string 1080
> 
> **Source**: `ev-000035`

### 9. Privilege escalation and token theft

`T1134.001,T1003.001` · Confidence **medium** · Static

Attempts to enable privileges, duplicate the SYSTEM token and locate the LSASS process, preparing for high-privilege data theft.

> **Evidence**: main.Elevate 0x4fc0e0, main.impersonateSystem 0x4f9660, main.findLsassProcess 0x4f8de0, main.NtQuerySystemHandles 0x4fb7d0
> 
> **Source**: `ev-000035`

### 10. Single-instance mutex

`T1480` · Confidence **high** · Dynamic

Creates a Global\WEBR_<12 random chars> mutex to ensure only one instance runs on the same host.

> **Evidence**: String Global\WEBR_93FBTYWPXRVS in the process memory dump (the same file also has a Global\version template)
> 
> **Source**: `ev-000039`

### 11. Installation and self-deletion

`T1547.001,T1070.004` · Confidence **medium** · Static

Has the ability to copy itself to a random directory, write a startup entry and self-delete when conditions are met; this run did not observe actual disk drops or startup entry writes.

> **Evidence**: main.staticinstall 0x4da540, main.selfDelete 0x4fbad0, main.Suicide 0x4dc030; strings bibawin.exe, SOFTWARE\Microsoft\Windows\CurrentVersion\Run
> 
> **Source**: `ev-000037`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (multiple retries within a short time).
:::

:::caution
**Real server side still unverified**: the above connection/handshake was completed with a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://sa1atik[.]cn/sa1at/` | 443 | c2 | Dynamic | Observed |
| dns | `remoteadministratortool[.]ton` | 443 | c2 | Static | ⏳ Not observed |
| other | `TON dnsresolve: webratxaye1 @ Ef_lZ1T4NCb2mwkme9h2rJfESCE0W34ma9lWp7-_uY3zXDvq` | 443 | c2 | Static | ⏳ Not observed |

### Host

**Mutexes**

- `Global\WEBR_93FBTYWPXRVS`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `sa1atik[.]cn` | Yes | Dynamic |
| `c2_port` | `443` | Yes | Dynamic |
| `c2_uri` | `/sa1at/` | Yes | Dynamic |
| `beacon_method` | `GET, Content-Type application/octet-stream, Content-Length 88` | No | Dynamic |
| `ton_dns_name` | `remoteadministratortool[.]ton` | Yes | Static |
| `ton_dns_record` | `webratxaye1` | Yes | Static |
| `ton_contract` | `Ef_lZ1T4NCb2mwkme9h2rJfESCE0W34ma9lWp7-_uY3zXDvq` | Yes | Static |
| `mutex` | `Global\WEBR_<12 random chars> (this run: Global\WEBR_93FBTYWPXRVS)` | Yes | Dynamic |
| `install_name` | `bibawin.exe` | No | Static |
| `socks5_port` | `1080` | No | Static |
| `exfil_file_ext` | `.jpg,.txt` | No | Static |
| `encryption_algo` | `Browser key decryption: Chromium AES-GCM+DPAPI/App-Bound Encryption (IElevator Edge/Brave), Firefox NSS ASN.1 PBE (3DES/AES), Steam VDF` | No | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing this report.

- Do not classify the sample as ransomware just because it has browser password decryption capability; no file encryption or ransom note was found this time.
- Do not treat the TON resolution request as having obtained the real fallback C2; only the request was observed in the sandbox, and no resolution response was received.
- Do not assert that persistence was completed without observing disk drops and startup entry writes; this time system telemetry saw no modification of registry Run keys, services or scheduled tasks by the sample.
- Do not misjudge the 12 MB Go program as an installer or benign tool; the in-house module names and the stealer/remote-control function chain all point to a malicious RAT.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. Within the dynamic window only HTTP requests to sa1atik[.]cn were captured and no valid response was obtained, so the commands/configuration delivered by the control side are unknown.
2. The TON resolution request received no real response inside the sandbox, so the fallback C2 pointed to by TON can only be confirmed on the request side (domain, record name, contract address); the final address was not retrieved.
3. No file drops, Run key, service or scheduled task writes were observed; persistence and installation behavior come from static functions and strings and were not triggered in this run.
4. Only the mutex and generic configuration strings appear in the dynamic memory dump; values such as sa1atik[.]cn/webratxaye1 are constructed at runtime, so the C2 conclusions are based on the network monitoring logs.
5. Browser/Steam/Discord data theft was not completed for exfiltration inside the sandbox; those entries are judgments of code capability rather than results of this run.

## Evidence index

<details>
<summary>Expand 9 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprinting | SHA256 374d0e88…ba558, MD5 a38088c54bb339bd87b465b6788626d0 |
| `ev-000002` | scan.imphash | imphash 1aae8bf580c846f39c71c05898e57e88 |
| `ev-000035` | String extraction | extracted 37490 ASCII/268 UTF-16 strings, including browser/Telegram/Discord/Steam paths and Go symbols |
| `ev-000037` | decompile.ghidra | decompiled main.main (RVA 0x4d5410), revealing configuration strings such as bibawin.exe, SOFTWARE\...\Run, browser and Telegram paths |
| `ev-000039` | evidence.record | summary of dynamic network monitoring/memory dumps/telemetry and Go symbol table extraction results (sa1atik[.]cn beacon, TON resolution, mutex) |
| `ref:6729bf803a` | Dynamic analysis platform | real dynamic sandbox detonation: PID 2940 starts and stays resident, capturing network, memory and telemetry artifacts |
| `c2_evidence:374d0e88` | Connection evidence extraction | dynamic network monitoring recorded 12 connection attempts to sa1atik[.]cn:443; no complete session captured |
| `telemetry:374d0e88` | Dynamic telemetry | dynamic telemetry recorded: 233 process/file events from monitoring components; 1 ETW short-lived process event; 27 filtered tool/system noise entries |
| `etw:374d0e88:2940` | Process event monitoring | Short-lived process event: 374d0e8898a40eac478e4139d2ba5134286eebd6de569c8103dc080c3f6ba558.exe (pid 2940; MD5=A38088C54BB339BD87B465B6788626D0,SHA256=374D0E8898A40EAC478E4139D2BA5134286EEBD6DE569C8103DC080C3F6BA558,IMPHASH=00000000000000000000000000000000) |

</details>

---

_The sample in this report is not public; IOCs have been defanged; for security research only._
