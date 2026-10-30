---
title: "Malware Analysis: WSF PowerShell Downloader (commodity) (other · wsf · 382e2bd0)"
published: 2026-10-28
draft: false
description: "Malicious (low confidence): WSF PowerShell Downloader (commodity) · downloader/loader/dropper · difficulty easy · pure static analysis"
tags: ["downloader", "loader", "dropper", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-28-wsf-downloader-382e2bd0"
---

> [!WARNING]
> **Verdict: malicious** · Family **WSF PowerShell Downloader (commodity)** (uncertain) · Confidence **low**
> 
> Aliases: JScript.WSF.Downloader, WSF.PS1.Loader
> 
> The sample is a plaintext-readable WSF/JScript script (4,295 bytes) that lays out a complete download-and-execute chain: "request a fixed HTTPS address → read the response body → write it to C:\Temp\<random 8 uppercase characters>.ps1 → execute it hidden with powershell.exe -nop -ep bypass -file". Api.run fires unconditionally at the entry point, with no user interaction and no legitimacy check.

## Overview

| Item | Content |
|:--|:--|
| Family | **WSF PowerShell Downloader (commodity)** · aliases JScript.WSF.Downloader, WSF.PS1.Loader · _uncertain_ |
| Confidence | **low** |
| Behaviour class | downloader · loader · dropper |
| Difficulty | easy |
| First seen | 2026-10-28 13:51:16 |
| Analysis method | pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/382e2bd0a1b1bf18cdf94438ec898450b05b12577e6f2f3579019518d0bb2f5a/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Fetch the PS1 payload from a fixed URL</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Create the C:\Temp staging directory</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Write the script file under a random name</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Launch PowerShell in a hidden window</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Bypass the execution policy and profile</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `382e2bd0a1b1bf18cdf94438ec898450b05b12577e6f2f3579019518d0bb2f5a` |
| MD5 | _not recorded_ |
| Size | 4,295 bytes (4.2 KB) |
| Type | other · `wsf` |

## Behaviour analysis

**6** behaviours were recovered, each with supporting evidence, and all of them are static.

### 1. Fetch the PS1 payload from a fixed URL

`T1105` · confidence **high** · static

Issues a synchronous GET to a fixed address through MSXML2.XMLHTTP, verifies status==200, then treats responseText as the script content to be executed.

> **Evidence**: offset 0x00B9(185) string hxxps://hotelsalamander[.]pl/.../KMK.PS1; offset 0x04E1(1249) this.http.open('GET', url, false); offset 0x0571(1393) responseText
> 
> **Source**: `ev-000001` · `ev-000002`

### 2. Create the C:\Temp staging directory

`T1074` · confidence **high** · static

Uses FileSystemObject.FolderExists/CreateFolder to ensure C:\Temp\ exists, as the staging directory where the second-stage payload lands.

> **Evidence**: offset 0x0124(292) this.directory = 'C:\\Temp\\'; offset 0x02E4(740) this.fs.CreateFolder(dirPath)
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Write the script file under a random name

`T1036` · confidence **high** · static

Generates an 8-character random string with Math.random.toString(36).substring(2,10), upper-cases it, appends the .ps1 suffix, and overwrites the file with the downloaded content using CreateTextFile, evading detection based on a fixed filename.

> **Evidence**: offset 0x07B6(1974) Math.random.toString(36).substring(2, 10); offset 0x07FB(2043) return randPart.toUpperCase + '.ps1'; offset 0x03C7(967) CreateTextFile
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Launch PowerShell in a hidden window

`T1059.001` · confidence **high** · static

Uses WScript.Shell.Run(cmd, 0, true) to start powershell.exe -nop -ep bypass -file "C:\Temp\<RANDOM>.ps1" with window style 0 (hidden), and waits synchronously for it to finish.

> **Evidence**: offset 0x06BF(1727) this.sh.Run(cmd, 0, true); offset 0x0917(2327) 'powershell.exe -nop -ep bypass -file "' + path + '"'
> 
> **Source**: `ev-000001` · `ev-000002`

### 5. Bypass the execution policy and profile

`T1562.001` · confidence **high** · static

The launch arguments always use -nop (do not load the profile) and -ep bypass (bypass the PowerShell execution policy), weakening restrictions on script execution.

> **Evidence**: offset 0x0917(2327) command line contains -nop -ep bypass
> 
> **Source**: `ev-000001` · `ev-000002`

### 6. Automatic execution entry in the WSF host

`T1059.007` · confidence **high** · static

The script is embedded in a .wsf as <script language="JScript"> and calls Api.run directly at the end, triggering the full download-and-execute pipeline without user interaction; the URL/directory can later be overridden through the global ScriptAPI.config.

> **Evidence**: offset 0x001E(30) <script language="JScript">; offset 0x1057(4183) Api.run; offset 0x1061(4225) this.ScriptAPI = Api;
> 
> **Source**: `ev-000001` · `ev-000002`


## IOC (defanged)

### Network

:::caution
**The real server side remains unverified**: the connections/handshakes above were completed against a locally controlled emulation service, so the real C2's responses and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://hotelsalamander[.]pl/wp-includes/rest-api/lfszonm/vtsdyif/gtwmhfx/KMK.PS1` | 443 | download | static | ⏳ not observed |

### Host

**Drop paths**

- `C:\Temp\`
- `C:\Temp\<8 random uppercase characters>.ps1`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `hotelsalamander[.]pl` | yes | static |
| `download_url` | `hxxps://hotelsalamander[.]pl/wp-includes/rest-api/lfszonm/vtsdyif/gtwmhfx/KMK.PS1` | yes | static |
| `install_path` | `C:\Temp\<RANDOM8>.ps1` | yes | static |
| `launch_command` | `powershell.exe -nop -ep bypass -file "<path>"` | yes | static |
| `retry_max_attempts` | `2` | no | static |

## Don't misread this

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- Do not judge it to be ransomware or a stealer: the sample contains no file encryption, credential reading, browser-data collection or bulk-exfiltration code, and its only network behaviour is a single GET download.
- Do not judge that persistence is present: no registry Run keys, scheduled tasks, service installation or startup-folder writes were found.
- Do not claim the final payload family or the full C2 infrastructure has been confirmed: the KMK.PS1 body was not obtained, and neither its second-stage behaviour nor the subsequent C2 was observed.
- Do not describe it as having lateral movement or worm-like propagation: there is no SMB/RDP/remote-execution code.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | pure static analysis |
| Unpacked | no |

**Limitations and open questions**

1. This format has no isolated dynamic channel, so all conclusions come from static review of the plaintext source and strings, and the sample was not actually executed.
2. The download address hxxps://hotelsalamander[.]pl/... is the path of a suspected compromised WordPress site; no real request was made during analysis, so whether it is still live and what payload it returns are unknown.
3. The content of the second-stage KMK.PS1, its persistence method, its final family attribution and the real C2 were all unavailable; the relevant fields are left blank and marked pending dynamic verification.
4. The file hash was obtained by local read-only verification (self-reported evidence) and was not compared against external intelligence sources; the first-seen time is unknown.
5. No host persistence artefacts such as mutexes, registry entries, services or scheduled tasks were found, but that only means the first-stage script does not contain them; it does not mean the second stage lacks them.

## Evidence index

<details>
<summary>Show 2 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | string extraction | Extracted 123 ASCII strings (0 UTF-16LE), giving the byte offsets of key strings such as the URL, C:\Temp, CreateTextFile, MSXML2.XMLHTTP and the powershell command line. |
| `ev-000002` | evidence.record | Local read-only verification: sha256/md5/size, plus byte-level re-checks of the single URL, drop directory, random file name, launch arguments and retry count, confirming the absence of persistence and encryption code. |

</details>

---

_This sample is not shared; IOCs are defanged. For security research only._
