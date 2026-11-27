---
title: "Malicious sample analysis: NSIS_Downloader (PE · exe · 74a5ddeb)"
published: 2026-11-26
draft: false
description: "Malicious (confidence: low): NSIS_Downloader · downloader/dropper · difficulty medium · dynamic sandbox + static decompilation"
tags: ["downloader", "dropper", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-26-NSIS_Downloader-74a5ddeb"
---

> [!WARNING]
> **Verdict: malicious** · Family **NSIS_Downloader** (unconfirmed) · Confidence **low**
> 
> Aliases: NSIS dropper, Discord CDN loader
> 
> The sample is an installer packed with Nullsoft Install System v3.02.1: the unpacked content is not normal software but 4 pure filler files (about 25.6MB in total, entropy ≈0.16) plus 3 images and 5 Danish lorem-ipsum texts and other decoys; after running, the program repeatedly spawns same-named child processes from its own image path, and the child processes request JUfHv82.bin over HTTPS from a fixed Discord attachment address on cdn[.]discordapp[.]com, spoofing the User-Agent as Firefox/160.0, retrying about every 10 seconds after failure, 17 times in total within the observation window. This download address is not a distribution channel of any legitimate software, and the downloaded content does not go through any signature/verification process, which is typical first-stage downloader behavior; the overall verdict is malicious.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **NSIS_Downloader** · Aliases NSIS dropper, Discord CDN loader · _unconfirmed_ |
| Confidence | **low** |
| Behavior class | downloader · dropper |
| Difficulty | medium |
| First seen | 2026-11-26 14:00:08 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Unpacks decoys to user profile</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Restarts itself from same path</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Masquerades as normal installer</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Downloads payload from Discord</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Dynamically loads WinINet</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917` |
| MD5 | _Not recorded_ |
| Size | 1,201,664 bytes (1.1 MB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **7** behaviors in total, each backed by evidence; **3** are statically available and **4** were obtained through dynamic analysis.

### 1. Unpacks decoy files to user profile

`T1027` · Confidence **high** · Dynamic

Using the installer UI it unpacks 16 entries into %USERPROFILE%\Sopsaisana58: 4 large single-byte filler files, 3 real JPEGs, 5 Danish lorem-ipsum text/ini files, 2 unknown blobs (skotjet 150310 bytes, Gadeteatret 25341 bytes) and the System.dll plugin. In memory, NSIS progress strings such as "Output folder:" "Extract: skotjet... 100%" and object-manager paths such as \??\C:\Users\analyst\Sopsaisana58\skotjet are visible, showing that the unpacking actually happened.

> **Evidence**: process memory 0x10057e 'Output folder: C:\Users\analyst\Sopsaisana58', 0x14966e 'Extract: skotjet... 100%', 0x125f9e '\??\C:\Users\analyst\Sopsaisana58\skotjet'; appended-data unpack manifest 16 entries (overlay offset 162304)
> 
> **Source**: `ev-000012` · `ev-000013` · `ev-000014` · `ev-000015`

### 2. Restarts itself from the same path

`T1036` · Confidence **high** · Dynamic

During execution it spawns multiple same-named child processes from its own image path: the detonating process (pid 6804) starts pid 5436 and then pid 3848, and pid 3848 starts pid 4680; all four have the sample's image path and identical hashes, used to switch execution branches and spread the download behavior across new processes.

> **Evidence**: process creation events: 6804→5436, 6804→3848, 3848→4680, Image=C:\dyn\samples\<sha256>.exe, command line '"<path>.exe" ', hash identical to the sample
> 
> **Source**: `ev-000015`

### 3. Masquerades as a normal installer

`T1036.005` · Confidence **high** · Static

PE version information is assembled from random English words: OriginalFilename=discoursing coracoprocoracoid.exe, FileVersion/ProductVersion 1.1.0[.]0, Comments=pontificator unbarbarized stereophony, LegalTrademarks=stemmelben slingrefises; the interface uses the standard NSIS "Setup" wizard with a product name made of random words, impersonating a normal software installer.

> **Evidence**: version resource OriginalFilename=discoursing coracoprocoracoid.exe; script string table 'Nullsoft Install System v3.02.1' + ' Setup'; appended data SubType=NSIS-3 Unicode
> 
> **Source**: `ev-000012` · `ev-000013`

### 4. Downloads payload from Discord

`T1071.001` · Confidence **high** · Dynamic

The child process requests JUfHv82.bin over HTTPS from the fixed Discord attachment path on cdn[.]discordapp[.]com, with a spoofed Firefox/160.0 User-Agent and Cache-Control: no-cache; since the download receives no normal response, it retries about every 10 seconds, for 17 GETs in total within the observation window.

> **Evidence**: network monitoring log: pid 3848 requested TCP <sinkhole>:443 ×17, followed by HTTP GET /attachments/1574386543248801863/1575464094113472542/JUfHv82.bin?... HTTP/1.1 (UA: Mozilla/5.0 ... Firefox/160.0); the full URL appears at process memory 0x6babaa6
> 
> **Source**: `ev-000014` · `ev-000015`

### 5. Dynamically loads WinINet

`T1106` · Confidence **medium** · Dynamic

The static import table contains only kernel32/user32/gdi32/shell32/advapi32/comctl32/ole32, without wininet/winhttp; in the running process memory C:\Windows\SYSTEM32\WININET.DLL, urlmon.dll, %SystemRoot%\system32\mswsock.dll and the complete request line/headers appear, showing that the download capability is resolved and called at runtime through the installer plugin (System.dll's Alloc/Call).

> **Evidence**: memory near 0x6b93e83: 'C:\Windows\SYSTEM32\WININET.DLL', '...\urlmon.dll', '%SystemRoot%\system32\ms wsock.dll' and 'GET /attachments/... HTTP/1.1'; the script string table contains '\System.dll', 'Alloc', 'Call'; the import table has no wininet
> 
> **Source**: `ev-000014` · `ev-000013`

### 6. Built-in decoy registry keys and random paths

`T1112` · Confidence **medium** · Static

The script string table embeds a batch of random key names and random directories/file names, such as Software\Microsoft\Windows\CurrentVersion\Soony, ...\krestiane, ...\Aaretagenes, Software\Access\Disabled, and \baadevrfts\Imperforata.exe, Tuberizations\yapness.exe, \Dysanalyte\blockholer.ini, etc.; these names are unrelated to the installer's real functionality and are used to create noise and interfere with string/behavior-based verdicts. This analysis did not observe the sample actually writing these registry keys or creating these files in the system telemetry.

> **Evidence**: in the script string table (header block offset 162336, decompressed 10866 bytes): 'Software\Microsoft\Windows\CurrentVersion\Soony\', 'Tuberizations\yapness.exe', 'C:\Windows\system32\Tuberizations\yapness.exe'; no corresponding registry write events in telemetry
> 
> **Source**: `ev-000013`

### 7. Filler files inflate sample size

`T1027` · Confidence **high** · Static

The 4 unpacked files brevforsendelser.flu (9.18MB), degauss.ski (6.62MB), oprrerene.she (5.15MB) and shirtband.mic (4.65MB) total about 25.6MB with entropy about 0.16; more than 99% of the bytes are the same repeated value and carry no executable logic, used only to bloat the installer, dilute the real logic and interfere with feature extraction.

> **Evidence**: per-file statistics after unpacking: entropy 0.16, uniq=256, the most frequent byte accounts for 99.0% (0x04 in brevforsendelser.flu accounts for 9,093,450/9,184,071 bytes)
> 
> **Source**: `ev-000012`


## IOCs (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (retrying several times within a short period).
:::

:::caution
**Real server side still unverified**: the connections/handshakes above were completed against a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://cdn[.]discordapp[.]com/attachments/1574386543248801863/1575464094113472542/JUfHv82[.]bin?ex=6b0960c6&is=6b080f46&hm=f48fc4b0e1d411c4315568f29f5b9338fa8423b78627eca5c6cbffbc1eea9512` | 443 | download | Dynamic | Observed |

### Host

**Drop paths**

- `%USERPROFILE%\Sopsaisana58`
- `%USERPROFILE%\Sopsaisana58\skotjet`
- `C:\Windows\system32\Tuberizations\yapness.exe`
- `%USERPROFILE%\Sopsaisana58\baadevrfts\Imperforata.exe`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Soony`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\krestiane`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Aaretagenes`
- `HKCU\Software\Access\Disabled`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `cdn[.]discordapp[.]com` | Yes | Static |
| `c2_url` | `hxxps://cdn[.]discordapp[.]com/attachments/1574386543248801863/1575464094113472542/JUfHv82[.]bin?ex=6b0960c6&is=6b080f46&hm=f48fc4b0e1d411c4315568f29f5b9338fa8423b78627eca5c6cbffbc1eea9512` | Yes | Static |
| `install_path` | `%USERPROFILE%\Sopsaisana58` | Yes | Static |
| `http_user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:160.0) Gecko/20100101 Firefox/160.0` | No | Static |
| `retry_interval_sec` | `10` | No | Static |
| `encryption_algo` | `unknown (the download URL does not appear in plaintext in the script string table; inferred to be decrypted/concatenated at runtime, algorithm not confirmed)` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not claim that the second-stage payload was obtained or executed: all download requests were taken over by the fake service on the isolated network, the real JUfHv82.bin content was not obtained within the analysis window, and no payload execution was observed.
- Do not claim that the sample established persistence: in the system telemetry no sample process wrote Run keys, registered services or created scheduled tasks, and there is no evidence that any startup item/service was created.
- Do not treat these decoy registry keys/random paths as implemented functionality: they appear only in the installer script's string table, and this analysis observed no actual writes or creation.
- Do not classify it as an infostealer/ransomware/miner or process-injection family: the memory scan found no injection traces (the number of suspicious modules in the scanned process is 0), and there is no evidence of file traversal, credential reading or encryption behavior.
- Do not treat the Discord attachment URL as a confirmed usable C2 channel: only outbound GETs were observed, with no real server response, and the signature parameters (ex/is/hm) in the URL indicate that it is a temporary download link.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The second stage (JUfHv82.bin) could not be retrieved: all download requests were answered/taken over by the fake service on the isolated network and no real content was obtained, so the subsequent behavior, encryption method and final family cannot be confirmed.
2. The C2 session has only outbound requests and no real server response, so the c2 entry is marked as statically recovered and remains pending dynamic verification; the download URL itself comes from running process memory, not from the script plaintext.
3. No filesystem snapshot of the analyzed system was obtained: the decoy files' landing is inferred only from the 'Output folder:'/'Extract:' progress strings in process memory and the \??\ object-manager paths, without per-file verification.
4. The registry key names come from the installer script text, and the system telemetry shows no sample process writing these keys; the related entries are intent rather than accomplished fact.
5. The memory scan found no injection or module hollowing (suspicious module count is 0), but this cannot rule out injection capability in later stages.
6. The sample's download URL does not appear in the script plaintext strings and is presumed to be produced by encrypted configuration or runtime concatenation; the specific algorithm was not located.

## Evidence Index

<details>
<summary>Expand 12 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256=74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917, md5=df603e63f979d42b422b356191822b74, imphash=b34f154ec913d2d2c435cbd644e91687, size 1201664 bytes |
| `ev-000011` | String extraction | String extraction: ascii 1810 / utf16le 40; visible NSIS installer strings (verifying installer, NSIS Error), SeShutdownPrivilege, [Rename], %s%S.dll, etc. |
| `ev-000012` | Scripted forensics | Static unpacking of the NSIS appended data: overlay offset 162304, SubType=NSIS-3 Unicode, 16 entries; 4 single-byte filler files totaling about 25.6MB (entropy 0.16), 3 JPEGs, 5 Danish texts, 2 unknown blobs, System.dll plugin |
| `ev-000013` | Scripted forensics | raw-deflate decompressed the 10866-byte header block at offset 162336, obtaining the NSIS string table: install directory \Sopsaisana58, Nullsoft Install System v3.02.1, System.dll/Alloc/Call, random registry keys and random .exe/ini paths; the table contains no http/discord plaintext |
| `ev-000014` | Scripted forensics | String scan of the full memory image of the sample child process retrieved from the dynamic sandbox: complete Discord attachment URL, GET request line, spoofed Firefox/160.0 UA, Host/Cache-Control headers, WININET.DLL/urlmon.dll/mswsock.dll paths, install directory C:\Users\analyst\Sopsaisana58 |
| `ev-000015` | Scripted forensics | Dynamic sandbox summary: same-path self-spawned process chain 6804→5436/3848→4680; on the network-monitoring side, 17 GETs to the same attachment URL on cdn[.]discordapp[.]com (about 10s apart); no Run key/service/scheduled task writes in telemetry; suspicious module count of the scanned process 0 |
| `c2_evidence:74a5ddeb` | Connection evidence extraction | Dynamic network monitoring recorded 17 connection attempts to cdn[.]discordapp[.]com:443; no complete session was captured |
| `telemetry:74a5ddeb` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component registry events 1; monitoring component process/file events 139; ETW short-lived process events 4; filtered tool/system noise 25 |
| `etw:74a5ddeb:6804` | Process event monitoring | Short-lived process event: 74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917.exe (pid 6804; MD5=DF603E63F979D42B422B356191822B74,SHA256=74A5DDEB4BA368A82963256B59F255E04F2ABB2B5A19D440C2326345C2A8E917,IMPHASH=B34F154EC913D2D2C435CBD644E91687) |
| `etw:74a5ddeb:5436` | Process event monitoring | Short-lived process event: 74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917.exe (pid 5436; MD5=DF603E63F979D42B422B356191822B74,SHA256=74A5DDEB4BA368A82963256B59F255E04F2ABB2B5A19D440C2326345C2A8E917,IMPHASH=B34F154EC913D2D2C435CBD644E91687) |
| `etw:74a5ddeb:3848` | Process event monitoring | Short-lived process event: 74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917.exe (pid 3848; MD5=DF603E63F979D42B422B356191822B74,SHA256=74A5DDEB4BA368A82963256B59F255E04F2ABB2B5A19D440C2326345C2A8E917,IMPHASH=B34F154EC913D2D2C435CBD644E91687) |
| `etw:74a5ddeb:4680` | Process event monitoring | Short-lived process event: 74a5ddeb4ba368a82963256b59f255e04f2abb2b5a19d440c2326345c2a8e917.exe (pid 4680; MD5=DF603E63F979D42B422B356191822B74,SHA256=74A5DDEB4BA368A82963256B59F255E04F2ABB2B5A19D440C2326345C2A8E917,IMPHASH=B34F154EC913D2D2C435CBD644E91687) |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
