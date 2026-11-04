---
title: "Malware Analysis: JScript/PowerShell Downloader (unattributed) (other · jse · 2e561ad3)"
published: 2026-11-03
draft: false
description: "Malicious (low confidence): JScript/PowerShell Downloader (unattributed) · downloader/dropper · difficulty easy · static analysis only"
tags: ["downloader", "dropper"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-03-JScript-PowerShell-Downloader-unattributed-2e561ad3"
---

> [!WARNING]
> **Verdict: Malicious** · Family **JScript/PowerShell Downloader (unattributed)** (uncertain) · Confidence **low**
> 
> The sample is readable plaintext JScript: it downloads a PowerShell script from a hardcoded HTTP address, writes it to C:\Temp\, executes it with a hidden window, and establishes triple persistence via a scheduled task, a Startup-folder shortcut, and a registry Run key. The code contains no legitimate software functionality, and the download, execution, and persistence chain is complete and self-evident.

## Overview

| Item | Content |
|:--|:--|
| Family | **JScript/PowerShell Downloader (unattributed)** · _uncertain_ |
| Confidence | **low** |
| Behavior class | downloader · dropper |
| Difficulty | easy |
| First seen | 2026-11-03 06:44:16 |
| Analysis method | Static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/2e561ad32eaa0f2f6a2f8df2d3b543749fa52847f6fd8526096a2d9ed1869a32/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Download remote PowerShell script</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Write random script to temp dir</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Run payload in hidden window</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Register scheduled task persistence</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Drop Startup folder shortcut</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `2e561ad32eaa0f2f6a2f8df2d3b543749fa52847f6fd8526096a2d9ed1869a32` |
| MD5 | _not recorded_ |
| Size | 5,948 bytes (5.8 KB) |
| Type | other · `jse` |

## Behavior analysis

**7** behaviors in total, each backed by evidence, all statically recoverable.

### 1. Download remote PowerShell script

`T1105` · Confidence **high** · static

It performs a synchronous GET via MSXML2.XMLHTTP to the hardcoded address hxxp://clw-trucks[.]top/xcd/246[.]ps1, and on status code 200 uses responseText as the next-stage script content.

> **Evidence**: off 112 REMOTE_URL; off 1656 fetchPayload; off 1690 createCOM('MSXML2.XMLHTTP'); off 1753 xhr.open('GET', url, false)
> 
> **Source**: `ev-000001` · `ev-000002`

### 2. Write random script to temp dir

`T1105` · Confidence **high** · static

It creates the C:\Temp\ directory and names the dropped file with 10 random uppercase letters plus a .ps1 suffix, writing the downloaded content into it.

> **Evidence**: off 170 TEMP_DIR: 'C:\\Temp\\'; off 1000 writeFile/CreateTextFile; off 5440 CONFIG.TEMP_DIR + randomName('.ps1')
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Run payload in hidden window

`T1059.001` · Confidence **high** · static

It calls WScript.Shell.Run with powershell.exe -nop -ep bypass -windowstyle hidden -file to execute the just-written .ps1, bypassing execution policy and hiding the window.

> **Evidence**: off 1990 psCommand; off 2034 '-nop -ep bypass'; off 2154 builds powershell.exe; off 5656 shell.Run(..., 0, true)
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Register scheduled task persistence

`T1053.005` · Confidence **high** · static

Via the Schedule.Service COM object it registers a scheduled task named sys in the task root whose action runs the dropped script with a hidden window, triggered on logon with a 5-minute delay and retrying every 5 minutes up to 3 times on failure.

> **Evidence**: off 203 TASK_NAME: 'sys'; off 2265 Schedule.Service; off 2677 register; off 3976 RegisterTaskDefinition; off 3076 Delay=PT5M; off 3876 RestartCount=3
> 
> **Source**: `ev-000001` · `ev-000002`

### 5. Drop Startup folder shortcut

`T1547.001` · Confidence **high** · static

It creates a randomly named .lnk in the user Startup folder whose target is powershell.exe with arguments to run the dropped script in a hidden window, window style 7 (minimized), then saves it.

> **Evidence**: off 4207 makeStartupLink; off 4315 SpecialFolders('Startup'); off 4504 TargetPath='powershell.exe'; off 4681 lnk.Save
> 
> **Source**: `ev-000001` · `ev-000002`

### 6. Write registry Run key

`T1547.001` · Confidence **high** · static

Via WScript.Shell.RegWrite it writes a REG_SZ to HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHealthMonitor whose value is the PowerShell command that runs the dropped script in a hidden window.

> **Evidence**: off 334 REG_PATH; off 414 REG_VALUE: 'SystemHealthMonitor'; off 4831 addRunKey; off 5044 RegWrite(key, val, 'REG_SZ')
> 
> **Source**: `ev-000001` · `ev-000002`

### 7. Disguise as Microsoft maintenance task

`T1036.004` · Confidence **high** · static

It sets the new scheduled task's description to Windows System Maintenance Utility and its author to Microsoft Corporation, impersonating a legitimate system maintenance component to lower visibility.

> **Evidence**: off 2857 RegistrationInfo.Description='Windows System Maintenance Utility'; off 2947 RegistrationInfo.Author='Microsoft Corporation'
> 
> **Source**: `ev-000001` · `ev-000002`


## IOC (defanged)

### Network

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://clw-trucks[.]top/xcd/246[.]ps1` | 80 | download | static | — |

### Host

**Drop paths**

- `C:\Temp\<RANDOM10>.ps1`
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<RANDOM10>.lnk`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHealthMonitor`

**Scheduled tasks**

- `\sys`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `clw-trucks[.]top (hxxp://clw-trucks[.]top/xcd/246[.]ps1)` | yes | static |
| `download_url` | `hxxp://clw-trucks[.]top/xcd/246[.]ps1` | yes | static |
| `install_path` | `C:\Temp\<RANDOM10>.ps1` | yes | static |
| `task_name` | `sys` | yes | static |
| `task_delay_minutes` | `5` | no | static |
| `task_restart` | `RestartInterval=PT5M, RestartCount=3` | no | static |
| `registry_run_value` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHealthMonitor` | yes | static |
| `powershell_flags` | `-nop -ep bypass -windowstyle hidden -file` | yes | static |
| `encryption_algo` | `none` | no | static |

## Must not claim

:::important
The following conclusions are **prone to misjudgment**; take care when citing this report.

- It cannot be judged ransomware or an information stealer: the code has no file encryption, credential reading, browser data collection, or exfiltration logic; its behavior is limited to download, execution, and persistence.
- The specific capabilities of the remote 246.ps1 must not be attributed to this file: that stage payload was not obtained, and its final functionality, hash, and C2 were not observed.
- The task name sys and forged Microsoft metadata alone must not place it in a named family: there are no family signature strings, config structures, or multi-engine corroboration.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static analysis only |
| Unpacking | no |

**Limitations and pending verification**

1. The static-only tier has no isolated dynamic channel for JSE, so the download, disk drop, scheduled-task registration, shortcut, and registry write were not observed on a real host; these are code-level inferences.
2. The remote hxxp://clw-trucks[.]top/xcd/246[.]ps1 was not obtained; the second-stage payload content and final capabilities are unknown.
3. The domain's current resolution and liveness were not verified, and no real outbound connection was made.
4. Family attribution is unclear; it is classified by behavior as a JScript/PowerShell downloader.
5. At runtime it may return early due to COM component availability, permissions, or network conditions; the actual drop success rate was not verified.

## Evidence index

<details>
<summary>Expand 2 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | string extraction | extracted all 169 ASCII strings from the sample, hitting REMOTE_URL, TEMP_DIR, TASK_NAME, REG_PATH, REG_VALUE and key API strings such as MSXML2.XMLHTTP, Schedule.Service, RegWrite. |
| `ev-000002` | evidence.record | section-by-section static audit of the plaintext source, recording file offsets, config items, and behavior mappings for each functional block (self-reported evidence). |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
