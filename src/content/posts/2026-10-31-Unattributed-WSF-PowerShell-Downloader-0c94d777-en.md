---
title: "Malware Analysis: Unattributed WSF/PowerShell Downloader (other · wsf · 0c94d777)"
published: 2026-10-31
draft: false
description: "Malicious (low confidence): Unattributed WSF/PowerShell Downloader · downloader/loader · difficulty easy · pure static analysis"
tags: ["downloader", "loader", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-31-Unattributed-WSF-PowerShell-Downloader-0c94d777"
---

> [!WARNING]
> **Verdict: malicious** · Family **Unattributed WSF/PowerShell Downloader** (uncertain) · Confidence **low**
> 
> Aliases: JScript WSF downloader, KMK.PS1 loader, WSF PowerShell dropper
> 
> The sample is an unobfuscated Windows Script File (JScript) whose full source can be read directly: upon execution it creates C:\Temp\, synchronously GETs the hardcoded hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK[.]PS1 with MSXML2.XMLHTTP, writes the returned text to C:\Temp\<8-character random name>.ps1, and then launches it in a hidden window with powershell.exe -nop -ep bypass -file. This chain has no legitimate use and is typical download-drop-execute (downloader/loader) behaviour; the second-stage PS1 was neither obtained nor executed dynamically, so the highest evidence level was not used and no runtime conclusion is treated as observed.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unattributed WSF/PowerShell Downloader** · aliases JScript WSF downloader, KMK.PS1 loader, WSF PowerShell dropper · _uncertain_ |
| Confidence | **low** |
| Behaviour class | downloader · loader |
| Difficulty | easy |
| First seen | 2026-10-30 11:54:05 |
| Analysis method | pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/0c94d77776c08b660932586745e3e5c65c6754217c992e62a0a7e8a90f9b7fd9/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Parse WSF, run JScript</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.007</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Create staging directory</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Synchronous HTTPS GET</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Receive remote PS1 payload</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Retry twice on failure</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `0c94d77776c08b660932586745e3e5c65c6754217c992e62a0a7e8a90f9b7fd9` |
| MD5 | _not recorded_ |
| Size | 3,591 bytes (3.5 KB) |
| Type | other · `wsf` |

## Behaviour analysis

**9** behaviours were recovered, each with supporting evidence, and all of them are static.

### 1. Parse WSF, run JScript

`T1059.007` · confidence **high** · static

The file has a <job><script language="JScript"> structure with the script body inside CDATA; Api.run executes immediately on load with no user interaction, and the host is usually wscript.exe/cscript.exe.

> **Evidence**: off 0x1E '<script language="JScript">'; off 0xDB1 'Api.run;'; off 0xDC5 'this.ScriptAPI = Api;'
> 
> **Source**: `ev-000001`

### 2. Create staging directory

`T1074.001` · confidence **high** · static

Checks whether C:\Temp\ exists through Scripting.FileSystemObject and creates it with CreateFolder if absent, preparing the drop location; on failure it exits entirely.

> **Evidence**: off 0x404 fs.FolderExists(State.dir); off 0x434 fs.CreateFolder(State.dir)
> 
> **Source**: `ev-000001`

### 3. Synchronous HTTPS GET

`T1071.001` · confidence **high** · static

Issues a synchronous GET to the hardcoded URL through MSXML2.XMLHTTP (http.open('GET', url, false); http.send), and only when status===200 takes responseText as the payload.

> **Evidence**: off 0x5AF http.open('GET', State.url, false); off 0x5E4 http.send; off 0x602 http.status === 200
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Receive remote PS1 payload

`T1105` · confidence **high** · static

Treats the HTTP response body as PowerShell script content without any validation of size or content, and falls back to null on failure, entering the retry branch.

> **Evidence**: off 0x62E result = http.responseText; on exception, off 0x68D result = null
> 
> **Source**: `ev-000001`

### 5. Retry twice on failure

`T1105` · confidence **high** · static

The do/while loop retries at most 2 times (State.retries=2) until non-empty content is obtained, improving delivery success under transient network failures.

> **Evidence**: off 0x153 retries: 2; off 0x6FB while (result === null && triesLeft-- > 0)
> 
> **Source**: `ev-000001` · `ev-000002`

### 6. Drop the script under a random name

`T1105` · confidence **high** · static

Generates an 8-character random filename from the A-Z0-9 pool and writes the downloaded content to C:\Temp\<random name>.ps1 with CreateTextFile/Write/Close, so the dropped filename cannot be predicted.

> **Evidence**: off 0x831 pool='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; off 0x936 CreateTextFile(target, true); off 0x971 handle.Write(script)
> 
> **Source**: `ev-000001`

### 7. Launch PowerShell to execute it

`T1059.001` · confidence **high** · static

Starts powershell.exe -nop -ep bypass -file "<dropped script>" through WScript.Shell.Run, handing execution to the second-stage script.

> **Evidence**: off 0x9B3 sh.Run('powershell.exe -nop -ep bypass -file "' + target + '"', 0, true)
> 
> **Source**: `ev-000001` · `ev-000002`

### 8. Disable execution-policy restrictions

`T1562.001` · confidence **high** · static

The command line always carries -nop (NoProfile) and -ep bypass (ExecutionPolicy Bypass), weakening PowerShell's default script execution and configuration restrictions.

> **Evidence**: off 0x9B3 the '-nop -ep bypass' arguments in the command line
> 
> **Source**: `ev-000001`

### 9. Run silently in a hidden window

`T1564.003` · confidence **high** · static

Run(cmd, 0, true) starts with window style 0 and waits synchronously for return, so the user never sees a console window on screen.

> **Evidence**: off 0x9E9 Run's intWindowStyle parameter is 0 and bWaitOnReturn is true
> 
> **Source**: `ev-000001`


## IOC (defanged)

### Network

:::caution
**The real server side remains unverified**: the connections/handshakes above were completed against a locally controlled emulation service, so the real C2's responses and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK[.]PS1` | 443 | download | static | ⏳ not observed |

### Host

**Drop paths**

- `C:\Temp\`
- `C:\Temp\<8-character A-Z0-9 random name>.ps1`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `denizcerceve[.]com (hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK[.]PS1)` | yes | static |
| `payload_url` | `hxxps://denizcerceve[.]com/images/a1zxnfu/rvzokey/ljfinqt/KMK[.]PS1` | yes | static |
| `stage2_filename` | `KMK.PS1` | yes | static |
| `install_path` | `C:\Temp\<8-character A-Z0-9 random name>.ps1` | yes | static |
| `staging_dir` | `C:\Temp\` | yes | static |
| `launch_cmdline` | `powershell.exe -nop -ep bypass -file "<staged .ps1>"` | yes | static |
| `retry_count` | `2` | no | static |
| `encryption_algo` | `none (plaintext HTTP response written straight to disk, no encoding/encryption)` | no | static |
| `control_interface` | `this.ScriptAPI.config(key, value) can rewrite the URL/directory/retry count inside the host` | no | static |

## Don't misread this

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- No persistence mechanism was found (no registry Run keys, no services, no scheduled tasks, no startup-folder writes), so it should not be called a persistent backdoor.
- The sample contains no credential reading, browser-data collection or file encryption code, so it should not be classified as a stealer / ransomware; it is only the first hop of a delivery chain.
- The second-stage KMK.PS1 was not obtained or executed, so its final payload type (RAT/miner/ransomware, etc.) is unknown; this file alone should not be used to assert the final family or capabilities.
- It cannot be confirmed whether denizcerceve[.]com is dedicated infrastructure registered by the attacker or a legitimate site being abused (its image directory path looks like that of a compromised CMS), so it should not be directly characterised as a dedicated C2 panel.
- The script is plaintext-readable with no encoding or encryption layer, so it should not be classified as a packed or obfuscated sample.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | pure static analysis |
| Unpacked | no |

**Limitations and open questions**

1. The sample was not executed, so all runtime conclusions (actual requests, disk writes, process creation) are inferences from reading the source directly and were not confirmed by observation.
2. The second stage hxxps://denizcerceve[.]com/.../KMK[.]PS1 was not downloaded, so its payload content, final behaviour and family attribution are unknown; the c2 entry is a delivery address rather than an interactive C2 and is marked pending dynamic verification.
3. The current status and ownership of the domain denizcerceve[.]com were not verified (no external/DNS lookup was performed); the PATH looks like the image directory of a compromised site, but this cannot be proven.
4. No threat intelligence or vendor naming is available for cross-validation, so the family field is a candidate placeholder with uncertain=true.
5. The sidecar file *.zip is an encrypted archive (not the sample itself) and was not part of this analysis.

## Evidence index

<details>
<summary>Show 2 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | string extraction | String extraction: 105 ASCII / 0 UTF-16LE strings, recovering the key strings and offsets needed to reconstruct the full script semantics (URL, C:\Temp\, the three COM objects, the sh.Run command line, the retry count). |
| `ev-000002` | evidence.record | Self-written script verifying the hash and structured configuration: sha256 matches the filename, md5=8eccc460cc282502e90d97970d570b9c, 3591 bytes, CRLF; extracts the URL/COM objects/staging directory/launch command line/retry count and confirms there is no encoding obfuscation anywhere in the file. |

</details>

---

_This sample is not shared; IOCs are defanged. For security research only._
