---
title: "Malware Analysis: WSF PowerShell Downloader (other · wsf · df00d262)"
published: 2026-10-29
draft: true
description: "Malicious (low confidence): WSF PowerShell Downloader · downloader/dropper/loader · difficulty easy · static analysis only"
tags: ["downloader", "dropper", "loader", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-29-wsf-downloader-df00d262"
---

> [!WARNING]
> **Verdict: malicious** · Family **WSF PowerShell Downloader** (uncertain) · Confidence **low**
> 
> Aliases: PowerShell stager, WSF dropper
> 
> The script is plaintext JScript (a WSF container) with a complete, readable execution chain: it synchronously GETs a remote PowerShell script with MSXML2.XMLHTTP, writes it to a randomly named .ps1 under C:\Temp\, then executes it hidden with powershell.exe -nop -ep bypass -file; there is no user interaction and no legitimate business logic.

## Overview

| Item | Content |
|:--|:--|
| Family | **WSF PowerShell Downloader** · aliases PowerShell stager, WSF dropper · _uncertain_ |
| Confidence | **low** |
| Behaviour class | downloader · dropper · loader |
| Difficulty | easy |
| First seen | 2026-10-29 09:01:39 |
| Analysis method | static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/df00d2622fb6f50f3030fbe5a873e96c3e5810c412c0c3fd71e8bafb35f3ba20/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Execute JScript through the script host</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.007</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Download the remote PowerShell</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Create the drop directory</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Write the script under a random name</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Execute the payload in a hidden window</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `df00d2622fb6f50f3030fbe5a873e96c3e5810c412c0c3fd71e8bafb35f3ba20` |
| MD5 | _not recorded_ |
| Size | 5,933 bytes (5.8 KB) |
| Type | other · `wsf` |

## Behaviour analysis

**7** behaviours were recovered, each with supporting evidence, and all are static.

### 1. Execute JScript through the script host

`T1059.007` · confidence **high** · static

The file is a .wsf job file containing a <script language="JScript"> block with CDATA code, parsed and executed by Windows Script Host; on load it invokes an IIFE and runs engine.run, with no user interaction required.

> **Evidence**: off 0x1E '<script language="JScript">'; off 0x1555 'engine.run;'
> 
> **Source**: `ev-000001` · `ev-000002`

### 2. Download the remote PowerShell

`T1105` · confidence **high** · static

Uses ActiveXObject('MSXML2.XMLHTTP') to download hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK.PS1 with a synchronous GET request, and takes the response body as the next-stage payload when the status code is 200.

> **Evidence**: address constant at off 0x13A; off 0x2D0 'var xhr = new ActiveXObject('MSXML2.XMLHTTP')'; off 0x5B6 'xhr.open('GET', url, false)'
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Create the drop directory

`T1105` · confidence **high** · static

Before execution it uses FileSystemObject.FolderExists/CreateFolder to check for and create C:\Temp\; on failure the whole pipeline short-circuits, the typical preparation of a payload staging directory.

> **Evidence**: off 0x3AB 'Env.ensureFolder(state.directory)'; off 0x417 'fso.CreateFolder(path)'
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Write the script under a random name

`T1105` · confidence **high** · static

Takes 8 characters from Math.random.toString(36), converts them to upper case and assembles a .ps1 filename, then uses CreateTextFile to write the downloaded content to C:\Temp\ in one go; the filename differs on every run, making static signature matching harder.

> **Evidence**: off 0x79C 'function randomScriptName'; off 0x81F "return seed.toUpperCase + '.ps1'"; off 0xC55 'Env.writeText(targetPath, state.payload)'
> 
> **Source**: `ev-000001` · `ev-000002`

### 5. Execute the payload in a hidden window

`T1564` · confidence **high** · static

Calls WScript.Shell.Run with window style 0 (hidden) and waitOnReturn=true to launch powershell.exe -nop -ep bypass -file "<random name>.ps1", invisible in the user interface.

> **Evidence**: off 0xD67 'Env.spawnHidden('; off 0xD6F "powershell.exe -nop -ep bypass -file"; off 0x691 'shell.Run(commandLine, 0, true)'
> 
> **Source**: `ev-000001` · `ev-000002`

### 6. Bypass execution-policy restrictions

`T1562.001` · confidence **high** · static

The PowerShell launch arguments use -nop (do not load the profile) and -ep bypass (ignore the execution policy), deliberately sidestepping script execution restrictions to clear the way for the subsequent download/execute module.

> **Evidence**: off 0xD6F command-line string '-nop -ep bypass -file'
> 
> **Source**: `ev-000001` · `ev-000002`

### 7. Retry the download on failure

`T1105` · confidence **medium** · static

The download package is wrapped in try/catch and do/while, with at most 3 attempts (maxAttempts=2, loop condition triesLeft>=0), to tolerate transient network failures or a single blocked request.

> **Evidence**: off 0x9C5 'var triesLeft = state.maxAttempts'; off 0xB4B 'while (triesLeft >= 0)'
> 
> **Source**: `ev-000001` · `ev-000002`


## IOC (defanged)

### Network

:::caution
**The real server side remains unverified**: the connections/handshakes above were completed with a local controlled emulation service, and the real C2's responses and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK[.]PS1` | 443 | download | static | ⏳ not observed |

### Host

**Drop paths**

- `C:\Temp\`
- `C:\Temp\<8 uppercase random characters>.ps1`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK[.]PS1` | yes | static |
| `download_dir` | `C:\Temp\` | yes | static |
| `install_path` | `C:\Temp\<8 uppercase random characters>.ps1` | yes | static |
| `exec_commandline` | `powershell.exe -nop -ep bypass -file "C:\Temp\<RAND>.ps1"` | yes | static |
| `retry_count` | `maxAttempts=2 (the do/while tests triesLeft>=0, so at most 3 attempts in practice)` | no | static |
| `encryption_algo` | `-` | no | static |
| `campaign_id` | `-` | no | static |

## Don't misread this

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- Do not claim that persistence exists: the script contains no registry writes, no service installation, no scheduled tasks and no start-up-folder drops.
- Do not claim it is a stealer/ransomware/miner family: this sample contains no credential collection, file encryption or mining-related code, and the final payload KMK.PS1 was not obtained, so its function is unknown.
- Do not attribute the sample on the strength of the domain alone: denizcerceve[.]com is very likely a compromised legitimate site, and the /images/... path has the appearance of normal site-directory camouflage.
- Do not claim that encryption or obfuscation was used: the script is entirely plaintext, has no decoding/decryption routines, and scanning found no cryptographic constants.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | static analysis only |
| Unpacked | no |

**Limitations and open questions**

1. Static-only tier: this format has no isolated dynamic channel and the sample was not executed, so the network download and the PowerShell drop/execution are code inferences not confirmed at runtime.
2. The remote payload KMK.PS1 was not obtained (the analysis environment has no outbound access); its real function, whether it performs a second download, its C2 heartbeat and any persistence are all unknown.
3. The ownership of denizcerceve[.]com and whether it was compromised cannot be verified offline; the domain may already have been taken down or its content changed.
4. No vendor engine or YARA rule comparison was used, so the family attribution lacks external intelligence support and only a behaviour-descriptive name can be given.

## Evidence index

<details>
<summary>Show 2 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | string extraction | Extracted 159 ASCII strings (0 UTF-16), hitting the C2 URL, C:\Temp\, COM object names and the powershell command line; 0 flag hits. |
| `ev-000002` | evidence.record | Read the script line by line and, together with string offsets, confirmed the complete execution chain (download → drop → hidden execution) and the absence of persistence/encryption; self-reported evidence with a confidence ceiling of 0.7. |

</details>

---

_This sample is not shared; IOCs are defanged. For security research only._
