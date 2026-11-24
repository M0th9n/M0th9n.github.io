---
title: "Malicious sample analysis: WSF PowerShell Loader (other · wsf · 27957fd6)"
published: 2026-11-23
draft: false
description: "Malicious (confidence: medium): WSF PowerShell Loader · downloader/loader · difficulty easy · pure static analysis"
tags: ["WSF", "downloader", "loader", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-23-WSF-PowerShell-Loader-27957fd6"
---

> [!WARNING]
> **Verdict: malicious** · Family **WSF PowerShell Loader** (unconfirmed) · Confidence **medium**
> 
> Aliases: JScript WSF downloader, PowerShell stager
> 
> The sample is a Windows Script File written in plaintext JScript whose source can be read directly: it downloads a PowerShell script from hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/KMK.ps1 via MSXML2.XMLHTTP, writes it to a randomly named .ps1 under C:\Temp\, and executes powershell.exe -nop -ep bypass -file in a hidden window, forming a typical downloader/loader chain. The download and execution logic is directly proven by the source code and does not rely on heuristic judgment.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **WSF PowerShell Loader** · Aliases JScript WSF downloader, PowerShell stager · _unconfirmed_ |
| Confidence | **medium** |
| Behavior class | downloader · loader |
| Difficulty | easy |
| First seen | 2026-11-23 06:53:26 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/27957fd69ffe2579e76bd091186af4f47d6fa244afa6539783d8e9db1a77664c/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Create Temp staging directory</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Fetch remote script over HTTPS</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Auto-retry twice on failure</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Write script with random name</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Execute payload in hidden window</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `27957fd69ffe2579e76bd091186af4f47d6fa244afa6539783d8e9db1a77664c` |
| MD5 | _Not recorded_ |
| Size | 4,161 bytes (4.1 KB) |
| Type | other · `wsf` |

## Behavior Analysis

There are **7** behaviors in total, each backed by evidence, and all are statically available.

### 1. Create Temp staging directory

`T1074` · Confidence **high** · Static

Calls FolderExists/CreateFolder of Scripting.FileSystemObject to ensure the C:\Temp\ directory exists as the drop location for the downloaded payload.

> **Evidence**: scan.strings off 0x1A6 'fs.FolderExists' / off 0x1FD 'fs.CreateFolder'; default config off 0x722 "directory: 'C:\Temp\'"
> 
> **Source**: `ev-000001` · `ev-000002`

### 2. Fetch remote script over HTTPS

`T1105` · Confidence **high** · Static

Uses MSXML2.XMLHTTP to issue a synchronous GET to a fixed URL, expecting a 200 response and then taking the response body as the script to be executed.

> **Evidence**: off 0x169 new ActiveXObject('MSXML2.XMLHTTP'); off 0x427 http.open('GET', url, false); off 0x456 http.send; URL off 0x6D0
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Auto-retry twice on failure

`T1071.001` · Confidence **high** · Static

The download is wrapped in a retry, attempting the same URL up to 3 times with maxAttempts=2, exiting only when a non-empty response is returned, improving delivery success under weak networks or single points of failure.

> **Evidence**: off 0x903 retry loop 'for (i=0;i<=attempts;i++)'; off 0x747 maxAttempts: 2
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Write script with random name

`T1036` · Confidence **high** · Static

Writes the downloaded response body to a file under C:\Temp\ whose name is an 8-character uppercase alphanumeric string generated by Math.random, with the extension fixed to .ps1; it terminates if the download is empty.

> **Evidence**: off 0x8A9 randomName: 'Math.random.toString(36).slice(2, 10).toUpperCase + .ps1'; off 0xBDC fs.CreateTextFile / writeText
> 
> **Source**: `ev-000001` · `ev-000002`

### 5. Execute payload in hidden window

`T1059.001` · Confidence **high** · Static

Launches powershell.exe via WScript.Shell.Run with window parameter 0 and wait mode true to execute the just-written .ps1, with the WSH host as the parent process.

> **Evidence**: off 0x535 shell.Run(cmd, 0, true); off 0xC1C command line 'powershell.exe -nop -ep bypass -file "<path>"'; off 0xC6A execHidden
> 
> **Source**: `ev-000001` · `ev-000002`

### 6. Bypass PowerShell policy

`T1562.001` · Confidence **high** · Static

The command line carries -nop (do not load profiles) and -ep bypass (bypass execution policy), so the remote script can run directly on hosts with the default restricted policy.

> **Evidence**: off 0xC1C command-line string 'powershell.exe -nop -ep bypass -file'
> 
> **Source**: `ev-000001` · `ev-000002`

### 7. Expose script interface

`T1059.001` · Confidence **medium** · Static

After execution, it attaches the internal Api object to WSH's this.ScriptAPI, retaining the run/config/reset methods so that subsequent scripts in the same host context can reuse the download and execution capability.

> **Evidence**: off 0xFC7 makeApi; off 0xFFB this.ScriptAPI = Api; off 0xE1A run/config/reset methods
> 
> **Source**: `ev-000001` · `ev-000002`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: The above address comes from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/KMK[.]ps1` | 443 | download | Static | ⏳ Not observed |

### Host

**Drop path**

- `C:\Temp\`
- `C:\Temp\<8-char uppercase random alphanumeric>.ps1`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `whispragency[.]com` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `c2_uri` | `/cnokulg/nlcayps/knarics/KMK.ps1` | Yes | Static |
| `download_dir` | `C:\Temp\` | Yes | Static |
| `download_filename` | `Math.random.toString(36).slice(2,10).toUpperCase + '.ps1' (8-char uppercase alphanumeric)` | Yes | Static |
| `exec_command` | `powershell.exe -nop -ep bypass -file "<downloaded .ps1>"` | Yes | Static |
| `max_attempts` | `2` | No | Static |
| `encryption_algo` | `none (plaintext HTTP response written directly to disk, no decryption step)` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not classify this as ransomware or a stealer: the source only performs downloading and PowerShell execution; no file encryption, credential collection, or data exfiltration code was found.
- Do not assert persistence: no registry Run key, scheduled task, service installation, or startup-directory write logic was found.
- Do not assert that the sample successfully beaconed out, dropped files, or executed: this is a pure static analysis, the sample was not run, and neither C2 reachability nor the real content of KMK.ps1 has been verified.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. This is a pure static analysis; the sample was not run, and no runtime evidence such as network responses, dropped files, or child processes was obtained.
2. The content and final behavior of the remote KMK.ps1 are unknown; it may contain persistence, information theft, or other payloads, which cannot be inferred from this sample.
3. Whether the domain whispragency[.]com currently resolves and whether the URL still distributes payloads have not been verified.
4. No engine/YARA hits are available; the family name is a generic description based on code structure and does not represent a confirmed vendor naming.
5. The sample is a text script, so PE/ELF structural parsing tools do not apply; the behavioral conclusions come from source-string and logic review.

## Evidence Index

<details>
<summary>Expand 2 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | 123 ASCII strings, each with its offset; includes key constants such as ActiveXObject/XMLHTTP/shell.Run/remote URL/C:\Temp/powershell command. |
| `ev-000002` | evidence.record | Static parsing and hash verification: sha256 matches the sample name, confirming plaintext with no obfuscation, and reconstructs the full download → drop → hidden execution chain. |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
