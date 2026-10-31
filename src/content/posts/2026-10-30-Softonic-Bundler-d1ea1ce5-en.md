---
title: "Malware Analysis: Softonic Bundler (PE · exe · d1ea1ce5)"
published: 2026-10-30
draft: false
description: "Grey/PUA (high confidence): Softonic Bundler · pua_bundler/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Softonic Bundler", "pua", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-30-Softonic-Bundler-d1ea1ce5"
---

> [!CAUTION]
> **Verdict: grey/PUA** · Family **Softonic Bundler** · Confidence **high**
> 
> Aliases: Softonic_2, Softonic Downloader, PUA.Softonic
> 
> A runtime memory dump recovered the complete paid-promotion delivery logic (detects Chrome/Slack/.NET, pulls product config from CloudFront, downloads and executes bundled installers, reports JSON telemetry) and the Softonic_2 campaign identifier; the file is signed with a Softonic EV certificate. No encryption, theft or persistence backdoor was found, so it is classified as a bundle-promotion PUA.

## Overview

| Item | Content |
|:--|:--|
| Family | **Softonic Bundler** · aliases Softonic_2, Softonic Downloader, PUA.Softonic |
| Confidence | **high** |
| Behaviour class | pua_bundler · downloader |
| Difficulty | medium |
| First seen | 2026-10-28 00:24:29 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/d1ea1ce5d9ba4b6456afd412abbb86d5ae540f4db0c2ee1719fe7ce6ebc9e970/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Inno self-extracting loader</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Probe installed browsers</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1012</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Collect host fingerprint</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1082</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Fetch delivery config</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Download bundle installer</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `d1ea1ce5d9ba4b6456afd412abbb86d5ae540f4db0c2ee1719fe7ce6ebc9e970` |
| MD5 | _not recorded_ |
| Size | 2,132,400 bytes (2.0 MB) |
| Type | PE · `exe` |

## Behaviour analysis

**8** behaviours in total; each is tied to evidence, and all are statically recoverable.

### 1. Inno self-extracting loader

`T1204.002` · Confidence **high** · static

The file is an Inno Setup 6.7.0 installer exporting SetupLdr.e32/__dbk_fcall_wrapper; at runtime it reads install data from itself at 0xCF177/0xCD400 using /SL5="$C00BC,848247,840704,<exe>".

> **Evidence**: pe.exports dll_name=SetupLdr.e32; memory string /SL5="$C00BC,848247,840704,..."; data header 'Inno Setup Setup Data (6.7.0)' @0xCF177
> 
> **Source**: `ref:ca9ae6d764` · `ev-000099`

### 2. Probe installed browser applications

`T1012` · Confidence **high** · static

Reads SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe, Software\Google\Chrome\BLBeacon\version, {commonpf}\Google\Chrome\Application\chrome.exe, SOFTWARE\Slack and Uninstall entries, and .NET NDP v4\Full, to decide which products to deliver.

> **Evidence**: memory UTF-16 constants @0x4b2d88/0x4b2e5f/0x4b3002/0x4abdf6/0x4b6a1f
> 
> **Source**: `ev-000099`

### 3. Collect host fingerprint

`T1082` · Confidence **high** · static

Reads MachineGuid, Windows NT CurrentVersion UBR, CPU model/frequency, memory and disk space, and OS bitness, for conditional delivery and telemetry.

> **Evidence**: memory constants MachineGuid @0x4a3a4f, SOFTWARE\Microsoft\Cryptography @0x4a3a79, HARDWARE\DESCRIPTION\System\CentralProcessor\0 @0x4b63ba
> 
> **Source**: `ev-000099`

### 4. Fetch delivery config over HTTPS

`T1071.001` · Confidence **high** · static

Uses WinHttp.WinHttpRequest.5.1 to GET hxxps://dviqfidnuw7nn[.]cloudfront[.]net/o and parses the returned JSON product/rule list (prv/plv/l/a/i/s/u/o fields).

> **Evidence**: memory constants hxxps://dviqfidnuw7nn[.]cloudfront[.]net/o @0x4aae01, 'GET' @0x4aa0f7, WinHttp.WinHttpRequest.5.1 @0x4aa067
> 
> **Source**: `ev-000099`

### 5. Download bundled installers

`T1105` · Confidence **high** · static

Downloads product installers from hxxps://dviqfidnuw7nn[.]cloudfront[.]net/f/ into {tmp}\component, handling .exe/.msi/.zip; for zip it extracts and takes the executable inside.

> **Evidence**: memory constants hxxps://dviqfidnuw7nn[.]cloudfront[.]net/f/ @0x4bc408/0x4bc71e, '{tmp}\component' @0x4bd833, 'no executable in zip' @0x4bde90
> 
> **Source**: `ev-000099`

### 6. Silently execute installers

`T1204.002` · Confidence **high** · static

Executes downloaded .exe/.msi via the shell 'open' verb, records states such as execution failed/finish: Success/FAILED.png, and the completion page can tick "run product".

> **Evidence**: memory constants 'open' @0x4be901/0x4becba/0x4bfc26, 'execution failed' @0x4be6f1, 'finish: Success' @0x4bef3d
> 
> **Source**: `ev-000099`

### 7. Report conversion telemetry

`T1041` · Confidence **high** · static

Sends a POST application/json to hxxps://dviqfidnuw7nn[.]cloudfront[.]net/zbd containing makedate/scheme/subdomain/slack/insights and MachineGuid, with an Authorization header in Signature= form.

> **Evidence**: memory constants 'POST' @0x4ad25a, 'Authorization'/'Signature=' @0x4ad45e/0x4ad48c, '"insights":' @0x4acba8
> 
> **Source**: `ev-000099`

### 8. Valid signature as delivery cover

`T1553.002` · Confidence **high** · static

The installer carries a valid Authenticode signature (SOFTONIC INTERNATIONAL SA, Sectigo EV), reducing the chance of reputation-based blocking at download and execution.

> **Evidence**: Get-AuthenticodeSignature: Status=Valid, Subject=CN=SOFTONIC INTERNATIONAL SA
> 
> **Source**: `ref:bc595b1712`


## IOCs (defanged)

### Network

:::caution
**The real server side remains unverified**: the connections above were completed against a local controlled emulation service; the real C2 responses and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://dviqfidnuw7nn[.]cloudfront[.]net/o` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://dviqfidnuw7nn[.]cloudfront[.]net/zbd` | 443 | exfil | static | ⏳ not observed |
| http | `hxxps://dviqfidnuw7nn[.]cloudfront[.]net/f/` | 443 | download | static | ⏳ not observed |

### Host

**Drop paths**

- `%TEMP%\is-<random>.tmp\<sha256>.tmp`
- `%TEMP%\component`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `dviqfidnuw7nn[.]cloudfront[.]net` | yes | static |
| `config_url` | `hxxps://dviqfidnuw7nn[.]cloudfront[.]net/o` | yes | static |
| `telemetry_url` | `hxxps://dviqfidnuw7nn[.]cloudfront[.]net/zbd` | yes | static |
| `download_base` | `hxxps://dviqfidnuw7nn[.]cloudfront[.]net/f/` | yes | static |
| `campaign_id` | `Softonic_2` | no | static |
| `analytics_namespace` | `zb_analytics` | no | static |
| `framework_version` | `4.6.6` | no | static |
| `transport` | `WinHttp.WinHttpRequest.5.1 (GET/POST application/json, Authorization: Signature=)` | yes | static |
| `targeting_checks` | `Chrome/Firefox/Slack/.NET version and install state; MachineGuid, CPU, RAM, disk, OS version` | no | static |
| `publisher` | `SOFTONIC INTERNATIONAL SA (EV code signing, certificate valid 2026-01-28 to 2027-01-29)` | no | static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- It is not ransomware: no file encryption, ransom notes or shadow-copy deletion were found.
- It is not an infostealer: the script only reads browser/Slack install state and environment data such as MachineGuid, without touching browser credentials, cookies, wallets or keystrokes.
- Do not claim real C2 communication or downloads were observed: automated detonation recorded no CloudFront requests; the C2/download addresses come from script constants in runtime memory.
- Do not judge it benign because of the valid Softonic EV signature: the signature only proves the publisher identity and does not exclude the installer bundling third-party promotional software.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The Inno Setup 6.7.0 install-data format is relatively new and the available unpacker cannot parse it, so the embedded setup data/product list files could not be extracted.
2. The sandbox only completed start-up and the wizard stage with no user clicks, so /o config fetching, /f/ download and bundled installation were not actually triggered, and no CloudFront traffic was observed.
3. The C2 and download addresses are script constants (static); recoverability is marked static with pending_dynamic_verify=true, and their current availability was not confirmed with a simulated network.
4. The specific product list, downloaded file hashes and final install names depend on the remote /o response and were not obtained.
5. The sample is a 32-bit GUI installer requiring interaction; memory forensics only covers the loaded install engine and script logic, not the remote-delivery stage.

## Evidence index

<details>
<summary>Expand 6 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:de56f3edae` | PE structure parser | PE32 GUI, 11 sections, entry RVA 0xADE60, SECURITY directory present (RVA 0x205D40, size 11376), no structural anomalies. |
| `ref:ca9ae6d764` | pe.exports | Exports dll_name=SetupLdr.e32, symbols dbkFCallWrapperAddr/__dbk_fcall_wrapper, confirming the Inno Setup loader. |
| `ref:e9e4603f7e` | Import table parser | 5 DLLs/150 symbols, incl. FindResourceW/LoadResource/LockResource/SizeofResource (install-data resource loading). |
| `ref:91e2500d96` | Dynamic sandbox | Real detonation: pid 4888 started; within 120s no new process, no hollowing/injection; network monitoring saw no CloudFront/DNS requests. |
| `ev-000099` | evidence.record | Script constants extracted from the process memory dump: CloudFront /o, /zbd, /f/, Softonic_2, zb_analytics, browser/Slack/.NET checks, download/execute and telemetry logic. |
| `ref:bc595b1712` | bash | Version info and signature: ProductName=Softonic--International (SA), FileVersion=4.0.2[.]0; Authenticode valid, signer CN=SOFTONIC INTERNATIONAL SA (Sectigo EV). |

</details>

---

_The sample behind this report is not public; IOCs are defanged. For security research only._
