---
title: "Malicious sample analysis: WSF PowerShell Downloader (other · wsf · 55ea024e)"
published: 2026-11-24
draft: false
description: "Malicious (confidence: low): WSF PowerShell Downloader · downloader/dropper · difficulty easy · pure static analysis"
tags: ["WSF", "downloader", "dropper", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-24-WSF-PowerShell-Downloader-55ea024e"
---

> [!WARNING]
> **Verdict: malicious** · Family **WSF PowerShell Downloader** (unconfirmed) · Confidence **low**
> 
> Aliases: JScript/Wsf.Downloader, PowerShell stager, WSF downloader dropper
> 
> The file is a plaintext Windows Script File (JScript); on startup it immediately calls ScriptAPI.run, downloads hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/PWKMK.ps1 over HTTPS GET via MSXML2.XMLHTTP, writes the response with Scripting.FileSystemObject to a randomly named 8-character .ps1 under C:\Temp\, and then executes powershell.exe -nop -ep bypass -file in a hidden window via WScript.Shell.Run(...,0,true). The script has no other business functionality; the behavior chain is complete and can be confirmed directly from the source, making it a malicious bootstrap script that downloads and delivers a follow-on PowerShell payload.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **WSF PowerShell Downloader** · Aliases JScript/Wsf.Downloader, PowerShell stager, WSF downloader dropper · _unconfirmed_ |
| Confidence | **low** |
| Behavior class | downloader · dropper |
| Difficulty | easy |
| First seen | 2026-11-23 06:48:35 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/55ea024e1028f67c5b5c1912336d3225951d4884e078446c4602023bea7e502b/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Auto-execute on script load</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.007</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Create temp staging directory</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Download remote script over HTTPS</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Write PowerShell with random name</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Execute PowerShell in hidden window</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `55ea024e1028f67c5b5c1912336d3225951d4884e078446c4602023bea7e502b` |
| MD5 | _Not recorded_ |
| Size | 5,430 bytes (5.3 KB) |
| Type | other · `wsf` |

## Behavior Analysis

There are **6** behaviors in total, each backed by evidence, and all are statically available.

### 1. Auto-executes when the script loads

`T1059.007` · Confidence **high** · Static

The file is a WSF in <job> form; after the JScript body is defined, it directly calls ScriptAPI.run at off 5298, entering the download flow without user arguments or interaction, and attaches ScriptAPI to the global object for later reuse.

> **Evidence**: off 5298: ScriptAPI.run; off 5369: global.ScriptAPI = ScriptAPI;
> 
> **Source**: `ev-000001`

### 2. Create a temp staging directory

`T1074` · Confidence **high** · Static

Checks for and creates C:\Temp\ via ActiveXObject('Scripting.FileSystemObject') as the drop location for the follow-on payload.

> **Evidence**: off 385: directory: 'C:\\Temp\\'; off 1293 ActiveXObject('Scripting.FileSystemObject'); off 1424 fso.FolderExists/CreateFolder
> 
> **Source**: `ev-000001`

### 3. Download the remote script over HTTPS

`T1105` · Confidence **high** · Static

Uses MSXML2.XMLHTTP to synchronously GET hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/PWKMK.ps1, taking the response body only when the status code is 200, and swallowing exceptions to retry with maxAttempts=2 on failure.

> **Evidence**: off 1973 ActiveXObject('MSXML2.XMLHTTP'); off 2082 xhr.open('GET', url, false); off 2128 xhr.send; off 2157 status === 200
> 
> **Source**: `ev-000001`

### 4. Write PowerShell to disk under a random name

`T1105` · Confidence **high** · Static

Writes the downloaded content via FileSystemObject.CreateTextFile to C:\Temp\ under an 8-character uppercase alphanumeric filename generated by Math.random plus a .ps1 suffix, avoiding a fixed filename.

> **Evidence**: off 2453 randomToken(length); off 2733 return dir + randomToken(8) + '.ps1'; off 1558 fso.CreateTextFile(path, true)
> 
> **Source**: `ev-000001`

### 5. Execute PowerShell in a hidden window

`T1059.001` · Confidence **high** · Static

Builds the command powershell.exe -nop -ep bypass -file "<staged path>" and executes it via WScript.Shell.Run(cmd, 0, true) with a hidden window and wait-for-exit, bypassing the execution policy and showing no console.

> **Evidence**: off 2840 powershell.exe -nop -ep bypass -file; off 1860 shell.Run(cmd, 0, true)
> 
> **Source**: `ev-000001`

### 6. Run silently with no pop-up

`T1564.003` · Confidence **high** · Static

The second parameter of WScript.Shell.Run is 0 (hidden window) and the third is true (wait for the process to exit), making the download and execution invisible to the user.

> **Evidence**: off 1860: shell.Run(cmd, 0, true)
> 
> **Source**: `ev-000001`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: The above address comes from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/PWKMK[.]ps1` | 443 | download | Static | ⏳ Not observed |

### Host

**Drop paths**

- `C:\Temp\`
- `C:\Temp\<8-char random uppercase alphanumeric>.ps1`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `whispragency[.]com` | Yes | Static |
| `payload_url` | `hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/PWKMK[.]ps1` | Yes | Static |
| `install_path` | `C:\Temp\` | Yes | Static |
| `staged_filename_pattern` | `%RANDOM8%.ps1 (uppercase alphanumeric)` | Yes | Static |
| `launch_command` | `powershell.exe -nop -ep bypass -file "<staged_path>"` | Yes | Static |
| `download_retry` | `maxAttempts=2` | No | Static |
| `encryption_algo` | `none (neither the script nor the communications are encrypted)` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not assert it is ransomware, a stealer, or a miner: the source contains only downloading, dropping, and execution; no file encryption, credential reading, or mining-pool logic appears.
- Do not assert persistence capability: no registry Run key, scheduled task, service, or startup-directory write was found in the source.
- Do not assert the final payload family or attribution to specific C2 infrastructure: the remote PWKMK.ps1 was not obtained in this static analysis, and its content and subsequent behavior are unknown.
- Do not describe whispragency[.]com as a confirmed long-term C2 panel: currently it can only be proven that the URL is used for a one-off PowerShell script download.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. This is the pure static tier; no isolated dynamic channel is available for this format, so no runtime network, process, or file events were obtained.
2. The sample is not PE/ELF, so structural parsing and emulation tools do not apply; the conclusions are based entirely on the script source and strings.
3. The remote PowerShell payload was not downloaded, so its functionality, final family, follow-on C2, and persistence method cannot be confirmed; the related fields are pending dynamic or external-network review.
4. The resolved address, certificate, and availability of whispragency[.]com in a real environment cannot be confirmed; the network IOCs come only from source constants.

## Evidence Index

<details>
<summary>Expand 1 tool evidence entry</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | Static string extraction (152 ASCII strings), fully recovering the WSF source, including key evidence such as the download URL, C:\Temp\ path, ActiveX objects, random filename, and PowerShell launch command. |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
