---
title: "Malware Analysis: MintsLoader (PE · exe · ba15e72c)"
published: 2026-11-03
draft: false
description: "Malicious (low confidence): MintsLoader · downloader/loader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Mints", "downloader", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-03-MintsLoader-ba15e72c"
---

> [!WARNING]
> **Verdict: Malicious** · Family **MintsLoader** (uncertain) · Confidence **low**
> 
> Aliases: MintLoader
> 
> The sample is an NSIS installer; after running, the same process continuously issues periodic HTTP GETs (roughly every 10 seconds, Firefox UA) to hxxp://109.248.151[.]106/VzDeNIilOBcrr195.bin, and the requests were fully observed by real dynamic-sandbox network monitoring; meanwhile its Authenticode signature digest does not match the file content, its version information is forged from random words, and the installer is stuffed with several MB of constant-padding files and randomly named decoy files. Overall it is downloader/loader-class malware.

## Overview

| Item | Content |
|:--|:--|
| Family | **MintsLoader** · aliases MintLoader · _uncertain_ |
| Confidence | **low** |
| Behavior class | downloader · loader |
| Difficulty | medium |
| First seen | 2026-11-03 06:44:32 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ba15e72ccec9f88b88d0a0c5c141ff66d21ad050f277427182fbb7061854b780/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Grafted invalid code signature</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Forge installer version info</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Stuff with megabytes of padding</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Lay down random-name decoy dirs</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Execute as NSIS installer</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `ba15e72ccec9f88b88d0a0c5c141ff66d21ad050f277427182fbb7061854b780` |
| MD5 | _not recorded_ |
| Size | 648,168 bytes (633.0 KB) |
| Type | PE · `exe` |

## Behavior analysis

**8** behaviors in total, each backed by evidence; **4** statically recoverable, **4** obtained through dynamic analysis.

### 1. Grafted invalid code signature

`T1553.002` · Confidence **high** · static

The PE carries an Authenticode signature and RFC3161 timestamp with signer CN=Fileside (issued by Certum), but the embedded SHA-256 digest does not match the file digest recomputed per spec, indicating signature grafting or post-signing tampering; it cannot be treated as a trust basis.

> **Evidence**: SECURITY directory RVA/offset 0x9D178, size 4720; embedded digest 1768f394… vs computed deaed425…
> 
> **Source**: `ev-000012` · `ref:828deee609`

### 2. Forge installer version info

`T1036.005` · Confidence **high** · static

VERSIONINFO uses meaningless random words: OriginalFilename/InternalName=pygmean ageing.exe, CompanyName=isobutene moity, ProductName=beylic fedtlderstvlens classable, Comments=unsole, LegalCopyright=choir huldskab, and the file name is unrelated to the installed content.

> **Evidence**: resource-section VERSIONINFO strings (UTF-16, file offset about 0x1E6xx-0x1E9xx)
> 
> **Source**: `ev-000011` · `ref:3480ae8653`

### 3. Stuff with megabytes of padding

`T1027` · Confidence **high** · static

The NSIS data area carries two multi-MB constant-padding files (0xA8 repeated 2,926,106 bytes; '6' repeated 4,454,307 bytes) plus 137KB/160KB high-entropy nonsensical data blocks, used to inflate the installer and evade size/content detection; they themselves are not executed.

> **Evidence**: calphurnia.fem 0xA8×2926106 (entropy 0.16); fusiformis.opm 0x36×4454307 (entropy 0.16); Pragmatism entropy 7.77
> 
> **Source**: `ev-000011`

### 4. Lay down random-name decoy dirs

`T1036` · Confidence **medium** · dynamic

The installer drops the Mimoses\Hovedindgange tree (real JPEG photos plus ini/txt files with random-word names) into a randomly named path under the user profile; the output directory string is visible in process memory, but the on-disk file list was not captured.

> **Evidence**: memory string C:\Users\analyst\Larikin203\Mimoses\Hovedindgange\; archive entries Mimoses\Hovedindgange\*.jpg/*.ini
> 
> **Source**: `ev-000013` · `ev-000011`

### 5. Execute as NSIS installer

`T1204.002` · Confidence **high** · static

The file is a 32-bit NSIS 3 Unicode installer ($PLUGINSDIR\System.dll) launched with the GUI subsystem; the sample relies on the user running the installer to trigger the subsequent download logic, and the PE body contains no malicious code.

> **Evidence**: pe_parse entry RVA 0x358D / subsystem GUI; overlay@0x1EE00 is an NSIS package containing the System.dll plugin
> 
> **Source**: `ref:828deee609` · `ev-000011`

### 6. HTTP callback to fetch payload

`T1071.001` · Confidence **high** · dynamic

The sample process sends GET /VzDeNIilOBcrr195.bin to 109.248.151[.]106:80 with a naked-IP Host header, a spoofed Firefox 157 UA, and no Cookie/Referer; the response is supposed to be the next-stage binary (the sandbox only replays emulated responses).

> **Evidence**: network event 19:29:32 GET /VzDeNIilOBcrr195.bin Host: 109.248.151[.]106; the same URL string in memory with winhttp/urlmon loading traces
> 
> **Source**: `ref:849a787224` · `ev-000013`

### 7. Download executable second stage

`T1105` · Confidence **medium** · dynamic

The request path is a random string .bin, consistent with a loader pattern that downloads and loads a next-stage PE; this run did not obtain the real server response, so the second-stage content and execution chain could not be confirmed.

> **Evidence**: GET /VzDeNIilOBcrr195.bin appears periodically; the process has loaded winhttp.dll/urlmon.dll/wininet.dll
> 
> **Source**: `ref:849a787224` · `ev-000013`

### 8. Ten-second download retry cycle

`T1105` · Confidence **high** · dynamic

The same download request repeats about every 10 seconds and continues until observation ends (13 times from 19:29:32 to 19:31:53), showing a fixed-interval poll after download failure rather than a one-shot request.

> **Evidence**: network timeline 19:29:32 / 19:29:42 / … / 19:31:53, one GET of the same path every 10s
> 
> **Source**: `ref:849a787224`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (retrying multiple times within a short period).
:::

:::caution
**Real server side still unverified**: the connection/handshake above was completed with a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://109[.]248[.]151[.]106/VzDeNIilOBcrr195[.]bin` | 80 | c2 | dynamic | observed |

### Host

**Drop paths**

- `%USERPROFILE%\Larikin203\Mimoses\Hovedindgange\`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `109.248.151[.]106` | yes | dynamic |
| `c2_url` | `hxxp://109[.]248[.]151[.]106/VzDeNIilOBcrr195[.]bin` | yes | dynamic |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0` | no | dynamic |
| `beacon_interval_sec` | `10` | no | dynamic |
| `install_path` | `%USERPROFILE%\Larikin203\Mimoses\Hovedindgange\` | no | static |
| `signature_subject` | `C=DE, L=Berlin, O=Fileside, CN=Fileside (Certum Code Signing 2021 CA; digest mismatch)` | no | static |

## Must not claim

:::important
The following conclusions are **prone to misjudgment**; take care when citing this report.

- It must not be called ransomware or a wiper: no file encryption, mass deletion, or ransom notes were observed.
- It must not be called an information stealer: no browser credential, wallet, clipboard, or document collection behaviors were observed.
- Its persistence must not be asserted: no Run key, service, scheduled task, or Startup folder writes were observed.
- The CN=Fileside signature must not be treated as proof this is official Fileside software: the signature digest does not match the file content, so it is a grafted/invalid signature.
- The JPEGs, random ini/txt files, and multi-MB padding files inside the installer must not be treated as malicious payloads: they were not observed executing.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The second-stage payload was not obtained: the sandbox network is emulated replay, the real server response is unknown, and subsequent stealing/remote-control/mining capabilities cannot be confirmed; stage2 is empty.
2. No filesystem write list was collected: the decoy directory appears only in process memory strings, so it cannot be proven that files were dropped or what their exact list is.
3. Family attribution is a candidate (MintsLoader-like): there is no direct correspondence to vendor naming/YARA or config decryption strings, and confidence is low.
4. NSIS script header parsing reports BadCmd=13 in 7z, so the full install script could not be recovered; the install/download logic is inferred from dynamic behavior and memory strings.
5. No privilege escalation, UAC bypass, or injection behavior was observed; if the second stage contains such capabilities, they would not have been visible in this run.

## Evidence index

<details>
<summary>Expand 13 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hashing and fingerprints | sha256=ba15e72c…, md5=f1f1f53f…, size=648168 |
| `ev-000002` | scan.imphash | imphash=573bb7b41bc641bd95c0f5eec13c233b |
| `ref:828deee609` | PE structure parsing | PE32 i386, entry RVA 0x358D, subsystem GUI, 5 sections, SECURITY directory 0x9D178/4720, no anomalies |
| `ref:3480ae8653` | string extraction | ASCII 1206 / UTF-16 50 strings, including NSIS error strings and the forged VERSIONINFO |
| `ref:4cbb998e7d` | import table parsing | 7 DLLs / 163 symbols; NSIS runtime imports such as registry, ShellExecute, and file copy |
| `ref:849a787224` | dynamic analysis platform | real dynamic: PID 1348 requests 109.248.151[.]106:80 GET /VzDeNIilOBcrr195.bin every 10s; process table/memory dump/network log packaged |
| `ref:cbe5604e9b` | dyn.run | emulation completed only NSIS loader initialization (55 APIs), no file/network behavior |
| `ref:6a819f2189` | unpack.detect | no packing detected (packed=false) |
| `ref:48ec8bf950` | unpack.antidebug | no anti-debugging/anti-analysis techniques identified |
| `ev-000011` | scripted forensics | NSIS unpack inventory: decoy photos/random ini/multi-MB padding files + System.dll |
| `ev-000012` | scripted forensics | Authenticode digest mismatch, signer Fileside/Certum, signing time 2025-03-04 |
| `ev-000013` | scripted forensics | process memory contains the C2 URL and the %USERPROFILE%\Larikin203\Mimoses\Hovedindgange\ path |
| `c2_evidence:ba15e72c` | connection evidence extraction | dynamic network monitoring recorded 20 connection attempts to 109.248.151[.]106:80, 109[.]248[.]151[.]106:80; no complete session captured |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
