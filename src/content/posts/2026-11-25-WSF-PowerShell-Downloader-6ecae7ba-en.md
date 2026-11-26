---
title: "Malicious sample analysis: WSF PowerShell Downloader (other · wsf · 6ecae7ba)"
published: 2026-11-25
draft: false
description: "Malicious (confidence: medium): WSF PowerShell Downloader · downloader/dropper · difficulty easy · pure static analysis"
tags: ["WSF", "downloader", "dropper", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-25-WSF-PowerShell-Downloader-6ecae7ba"
---

> [!WARNING]
> **Verdict: malicious** · Family **WSF PowerShell Downloader** (unconfirmed) · Confidence **medium**
> 
> Aliases: JScript/WSF downloader, PowerShell stager
> 
> The sample is a plaintext, readable Windows Script File (JScript) that fully implements the chain "create temp directory → fetch a PowerShell script from a remote HTTPS address via MSXML2.XMLHTTP → write it to C:\Temp under a random filename → execute it hidden with powershell.exe -nop -ep bypass"; it has no legitimate business function and no user interaction or authorization notice, making it a typical script downloader/dropper. The conclusion comes directly from the script source, with no real detonation, so no dynamic-level evidence is given.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **WSF PowerShell Downloader** · Aliases JScript/WSF downloader, PowerShell stager · _unconfirmed_ |
| Confidence | **medium** |
| Behavior class | downloader · dropper |
| Difficulty | easy |
| First seen | 2026-11-25 10:23:52 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/6ecae7bae50c5865b7c37a867fac8d8b8a5650cfd534ed3e2e5cd9304f7932bb/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Create temp drop directory</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Fetch remote script over HTTPS</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Retry download up to three times</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Write staged script under random name</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Launch PowerShell with policy bypass</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `6ecae7bae50c5865b7c37a867fac8d8b8a5650cfd534ed3e2e5cd9304f7932bb` |
| MD5 | _Not recorded_ |
| Size | 3,813 bytes (3.7 KB) |
| Type | other · `wsf` |

## Behavior Analysis

There are **8** behaviors in total, each backed by evidence, and all are statically available.

### 1. Create a temp drop directory

`T1074.001` · Confidence **high** · Static

It calls FileSystemObject.FolderExists to check C:\Temp and creates it with CreateFolder if absent, using it as the drop directory for the follow-on payload.

> **Evidence**: offsets 844-900: FolderExists / CreateFolder('C:\Temp\')
> 
> **Source**: `ev-000001`

### 2. Fetch the remote script over HTTPS

`T1105` · Confidence **high** · Static

Through MSXML2.XMLHTTP it issues a synchronous GET for hxxps://whispragency[.]com/.../111KMK.ps1 and reads responseText as the payload content only when the HTTP status code is 200.

> **Evidence**: offsets 1307 open('GET',ctx.address,false); 1366 send; 1400 status===200; 1448 responseText
> 
> **Source**: `ev-000001`

### 3. Retry the download three times

`T1105` · Confidence **high** · Static

The download loop runs from attempt=0 to maxAttempts=2, retrying up to 3 times on exceptions or non-200 responses, improving delivery success on weak networks or behind blocking.

> **Evidence**: offset 1220 for(attempt=0;attempt<=ctx.maxAttempts;attempt++); offset 1573 attempt===ctx.maxAttempts
> 
> **Source**: `ev-000001`

### 4. Write the staged script under a random name

`T1074.001` · Confidence **high** · Static

It generates an 8-character uppercase random name with Math.random.toString(36).substring(2,10).toUpperCase, writes C:\Temp\<random name>.ps1 via CreateTextFile and closes the file handle.

> **Evidence**: offset 1933 random suffix; 2014 targetPath=directory+suffix+'.ps1'; 2088 CreateTextFile; 2155 Write; 2195 Close
> 
> **Source**: `ev-000001`

### 5. Launch PowerShell with policy bypass

`T1059.001` · Confidence **high** · Static

It calls WScript.Shell.Run to execute powershell.exe -nop -ep bypass -file "<targetPath>" with a hidden window (parameter 0) and waits for it to finish (bWaitOnReturn=true).

> **Evidence**: offset 2224 shell.Run; 2252 command line '-nop -ep bypass -file'; 2330 window style 0
> 
> **Source**: `ev-000001`

### 6. Execute the payload in a hidden window

`T1564.003` · Confidence **high** · Static

The Run window-style parameter is 0 with wait-for-return, so the PowerShell second stage runs without any visible window, reducing user awareness.

> **Evidence**: offsets 2330-2350 Run(...,0,true)
> 
> **Source**: `ev-000001`

### 7. Blend traffic on port 443

`T1071.001` · Confidence **high** · Static

The download address uses the https protocol and port 443, blending the malicious fetch into ordinary encrypted web traffic and evading coarse port-based detection.

> **Evidence**: offset 600 initial address 'hxxps://whispragency[.]com/.../111KMK.ps1'
> 
> **Source**: `ev-000001`

### 8. Expose a rewritable configuration interface

`T1059.001` · Confidence **medium** · Static

The script wraps run/config/reset into window.ScriptAPI, where config(key,value) can directly rewrite the remote address, working directory and retry count, making it easy for a delivery operator to reuse with different payloads and infrastructure.

> **Evidence**: offset 3374 config:function(key,value); 3524 currentContext[key]=value; 3743 this.ScriptAPI=api
> 
> **Source**: `ev-000001`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: The above addresses come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/111KMK.ps1` | 443 | download | Static | ⏳ Not observed |

### Host

**Drop paths**

- `C:\Temp\`
- `C:\Temp\%RANDOM%8UPPER%.ps1`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `whispragency[.]com` | Yes | Static |
| `download_url` | `hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/111KMK.ps1` | Yes | Static |
| `install_path` | `C:\Temp\` | Yes | Static |
| `payload_filename_pattern` | `<8-character uppercase random string>.ps1` | Yes | Static |
| `execution_command` | `powershell.exe -nop -ep bypass -file "<targetPath>"` | Yes | Static |
| `retry_policy` | `maxAttempts=2 (loop 0..2, at most 3 attempts in total)` | No | Static |
| `encryption_algo` | `none (the script is plaintext; the payload is written to disk as responseText verbatim)` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not use this file to assert the functionality, family or harm type of the final PowerShell payload — the remote 111KMK.ps1 was not obtained or analyzed.
- Do not claim the sample uses encryption, obfuscation or an encoding container — the CDATA contains plaintext, readable JScript, and the payload is written to disk as responseText verbatim.
- Do not claim persistence behavior (registry Run keys, scheduled tasks, services) — there is no persistence API call anywhere in the source.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. This was pure static analysis; the sample was not executed and no sandbox detonation was performed, reproduced=false; the actual network callback and PowerShell behavior were not observed.
2. The remote payload hxxps://whispragency[.]com/cnokulg/nlcayps/knarics/111KMK.ps1 was not obtained in the default offline environment; its content, final C2 and family attribution are unknown, and the related C2 is marked static with pending_dynamic_verify=true.
3. A .wsf is neither PE nor ELF, so the structural parsing of pe.*/elf.* and scan.hashes/scan.triage does not apply; the file hash and type were computed by static script reading (ev-000002).
4. ScriptAPI.config can rewrite the remote address at runtime, but no external caller or configuration-delivery behavior was observed, so this is described only as a code capability.

## Evidence Index

<details>
<summary>Expand 2 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | 118 ASCII strings, fully reconstructing the script logic and the hxxps://whispragency[.]com/.../111KMK.ps1 download address, C:\Temp drop path and powershell.exe -nop -ep bypass command line |
| `ev-000002` | evidence.record | Static reading and hashing: 3813-byte XML/JScript, sha256=6ecae7...32bb, md5=0c0cef99..., no hidden/encrypted binary blocks |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
