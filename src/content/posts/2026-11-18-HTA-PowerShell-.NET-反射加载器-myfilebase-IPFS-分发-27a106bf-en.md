---
title: "Malware Analysis: HTA/PowerShell .NET reflective loader (myfilebase/IPFS distribution) (other · hta · 27a106bf)"
published: 2026-11-18
draft: false
description: "Malicious (low confidence): HTA/PowerShell .NET reflective loader (myfilebase/IPFS distribution) · loader/downloader · difficulty easy · pure static analysis"
tags: ["HTA", "loader", "downloader", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-18-HTA-PowerShell-.NET-反射加载器-myfilebase-IPFS-分发-27a106bf"
---

> [!WARNING]
> **Verdict: malicious** · Family **HTA/PowerShell .NET reflective loader (myfilebase/IPFS distribution)** (uncertain) · Confidence **low**
> 
> Aliases: HTA loader, PowerShell downloader
> 
> The sample is an HTA script: it launches 64-bit PowerShell through WScript.Shell in a hidden window; the inline script first removes inserted fixed junk strings, then restores a 2287-byte PowerShell script using "custom 64-character table substitution + Base64 decoding + per-byte subtraction with a 24-byte key" and executes it directly with iex. The script downloads text carrying <<STT>>/<<D>> markers from three IP addresses in random order, extracts the content between the markers, Base64-decodes it, loads the .NET assembly reflectively in memory, and reflectively invokes the runss method of type myprogram.Homees, passing an external IPFS address. The execution chain, in-memory loading and remote code retrieval are all directly visible malicious behavior, with no legitimate software characteristics.

## Overview

| Item | Content |
|:--|:--|
| Family | **HTA/PowerShell .NET reflective loader (myfilebase/IPFS distribution)** · aliases HTA loader, PowerShell downloader · _uncertain_ |
| Confidence | **low** |
| Behaviour class | loader · downloader |
| Difficulty | easy |
| First seen | 2026-11-16 08:02:04 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/27a106bf1227c1dd79791e153912bf90cbd5a0e3ea431f9dd31deca8af6dfab8/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Run HTA in a hidden window</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Insert junk strings to obfuscate</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Hidden PowerShell execution</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Decrypt and run inline script</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Randomly fetch payload from 3 IPs</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `27a106bf1227c1dd79791e153912bf90cbd5a0e3ea431f9dd31deca8af6dfab8` |
| MD5 | _not recorded_ |
| Size | 22,360 bytes (21.8 KB) |
| Type | other · `hta` |

## Behaviour analysis

**8** behaviours in total, each tied to evidence, and all statically recoverable.

### 1. Run HTA in a hidden window

`T1564.003` · Confidence **high** · static

HTA:APPLICATION turns off the border, taskbar button and system menu and minimizes the window, and when execution ends the script calls window.close to exit by itself, so the user sees no interface.

> **Evidence**: <HTA:APPLICATION BORDER=none SHOWINTASKBAR=no SYSMENU=no WINDOWSTATE=minimize> at off=57..272; window.close at off=22298
> 
> **Source**: `ev-000001`

### 2. Insert junk strings to obfuscate

`T1027` · Confidence **high** · static

A fixed string aghreeSn is inserted into every VBScript string fragment; at runtime Replace deletes it before the fragments are concatenated into the full command, so the static strings and command cannot be read directly.

> **Evidence**: 500+ occurrences of 'aghreeSn' starting at off=386; off=21737/22156 Replace(aq2LXNZEl, "aghreeSn", "")
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Hidden PowerShell execution

`T1059.001` · Confidence **high** · static

Through CreateObject("WScript.Shell").Run with window style 0 it executes cmd /c %SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe with the inline script appended as a parameter, using SysNative to move from the 32-bit host to the 64-bit interpreter.

> **Evidence**: off=674..729 assemble ...\SysNative\WindowsPowerShell\v1.0\powershell.exe; off=22156 WScript.Shell; off=22259 shell.Run aq2LXNZEl, 0, False
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Decrypt and execute the inline script

`T1140` · Confidence **high** · static

The inline PowerShell maps the ciphertext back to standard Base64 with a custom 64-character table, decodes it, then subtracts the 24-byte key from each byte modulo 256, restoring the 2287-byte script, which it finally executes directly with iex, avoiding disk writes.

> **Evidence**: ciphertext $vA9Li2, key $sPKZvMb4OI=[byte[]](0xE1,0x34,0x9F,...) at off≈1736..19385; decoded result 2287 bytes (stage2.ps1); iex $oUNp54NAe
> 
> **Source**: `ev-000001` · `ev-000002`

### 5. Random download from three addresses

`T1105` · Confidence **high** · static

Using System.Net.WebClient.DownloadData, it first shuffles the order of the three http addresses with Get-Random, then tries them one by one, switching to the next on failure, improving availability and evading single-point blocking.

> **Evidence**: stage2.ps1: DownloadDataFromLinks + Get-Random; the three URLs are decoded by _ebrFj into hxxp://64.224.17[.]115/img/1.jpg, hxxp://129.121.148[.]240/img/pics/1.jpg, hxxp://155.103.71[.]164/1.jpg
> 
> **Source**: `ev-000002`

### 6. Extract the marker and load reflectively

`T1620` · Confidence **high** · static

It locates <<STT>> and <<D>> in the downloaded text, extracts the content between them, Base64-decodes it, then loads the .NET assembly in memory with [Reflection.Assembly]::Load, producing no executable file on disk.

> **Evidence**: stage2.ps1: IndexOf('<<STT>>')/IndexOf('<<D>>') + Substring + FromBase64String + [System.Reflection.Assembly]::Load($b5)
> 
> **Source**: `ev-000002`

### 7. Reflectively invoke the runss entry point

`T1620` · Confidence **high** · static

It takes type myprogram.Homees from the loaded assembly, reflectively obtains method runss and invokes it with six arguments — an external IPFS address, "0", an empty string, "Msbuild", "0" and "x86" — handing control to the remote module.

> **Evidence**: stage2.ps1: GetType('myprogram.Homees'); GetMethod('runss').Invoke($null, [object[]]($b9, '0', '', 'Msbuild', '0', 'x86'))
> 
> **Source**: `ev-000002`

### 8. Three-second delay to evade detection

`T1497.003` · Confidence **high** · static

Before any network request it runs Start-Sleep -Seconds 3 and forces TLS 1.2, reducing the probability of network activity being triggered inside an automated sandbox's observation window.

> **Evidence**: stage2.ps1: [Net.ServicePointManager]::SecurityProtocol = Tls12; Start-Sleep -Seconds 3
> 
> **Source**: `ev-000002`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; under the analysis environment's network isolation no successful connection or session was observed, and the real C2 responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://64.224.17[.]115/img/1[.]jpg` | 80 | download | static | ⏳ not observed |
| http | `hxxp://129.121.148[.]240/img/pics/1[.]jpg` | 80 | download | static | ⏳ not observed |
| http | `hxxp://155.103.71[.]164/1[.]jpg` | 80 | download | static | ⏳ not observed |
| http | `hxxps://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmaJZLLPnnnUHM4sxM7eRj3Qc9eywuopZ5vPe5DCXR1PAr` | 443 | download | static | ⏳ not observed |

### Host

- **No host IOCs were recovered.**

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `64.224.17[.]115; 129.121.148[.]240; 155.103.71[.]164; misleading-lime-termite[.]myfilebase[.]com` | yes | static |
| `c2_uri` | `/img/1.jpg; /img/pics/1.jpg; /1.jpg; /ipfs/QmaJZLLPnnnUHM4sxM7eRj3Qc9eywuopZ5vPe5DCXR1PAr` | yes | static |
| `loader_chain` | `HTA -> VBScript string assembly -> powershell.exe (SysNative) -> iex -> WebClient.DownloadData -> Assembly.Load -> reflection invoke` | yes | static |
| `assembly_type` | `myprogram.Homees` | yes | static |
| `assembly_method` | `runss` | yes | static |
| `payload_markers` | `<<STT>> ... <<D>>` | yes | static |
| `encoding` | `custom 64-char alphabet substitution + Base64 + per-byte subtract key (24 bytes) ; second layer: 16-char table hex + XOR 0x16` | yes | static |
| `relay_url` | `hxxps://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmaJZLLPnnnUHM4sxM7eRj3Qc9eywuopZ5vPe5DCXR1PAr` | no | static |
| `launch_path` | `%SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe` | yes | static |
| `initial_delay_seconds` | `3` | no | static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not assert that the final payload belongs to a specific family or has stealer/RAT capabilities: the .NET module carrying the functionality is delivered remotely, and no sample was obtained this time, so it cannot be analyzed.
- Do not claim the sample wrote to the registry, created services or scheduled tasks, or established persistence: no such calls exist in the statically recovered scripts.
- Do not claim the sample actually used MSBuild proxy execution: "Msbuild" is only passed as a string argument to the remote module's runss method, and msbuild.exe was not seen being created.
- Do not treat the three IP addresses as the only or final C2: they are currently only proven to be payload distribution addresses, were not actually accessed, and the backchannel is unknown.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | no |

**Limitations and pending verification**

1. Pure static analysis; the sample was not detonated in a sandbox and no dynamic behavior is available for confirmation; all network conclusions come from script recovery.
2. None of the three download addresses or the IPFS link was accessed, so it cannot be confirmed whether they are currently alive, what they return, or the real file hashes.
3. The .NET payload was not obtained, so the final functionality (RAT/stealer/ransomware, etc.), configuration and real C2 backchannel cannot be determined.
4. The literal IPFS link in the script starts with s:// (missing the http prefix); this report treats it as https, and the actual runtime-assembled result should prevail.
5. No multi-engine or family signature data is available; the family is described only by the payload chain and marked pending.

## Evidence index

<details>
<summary>Expand 3 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | String extraction: 442 ASCII strings, including HTA:APPLICATION attributes, VBScript concatenation fragments and the aghreeSn obfuscation marker |
| `ev-000002` | evidence.record | A self-written script fully recovered the HTA first-stage command and the 2287-byte second-stage PowerShell (including the three download URLs, IPFS address, markers and reflection call arguments) |
| `ev-000003` | evidence.record | Sample hashes and format: sha256/md5/sha1, 22360 bytes, HTA text |

</details>

---

_The sample behind this report is not public; IOCs are defanged. For security research only._
