---
title: "Malware Analysis: JSE PowerShell Downloader (other · jse · a6770ca3)"
published: 2026-11-14
draft: false
description: "Malicious (low confidence): JSE PowerShell Downloader · downloader/loader · difficulty easy · pure static analysis"
tags: ["JSE", "downloader", "loader"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-14-JSE-PowerShell-Downloader-a6770ca3"
---

> [!WARNING]
> **Verdict: Malicious** · Family **JSE PowerShell Downloader** (uncertain) · Confidence **Low**
> 
> Aliases: JScript downloader, PowerShell payload dropper
> 
> The sample is an unobfuscated plaintext JScript downloader. The source directly shows the complete attack chain: it creates the C:\Temp staging directory, performs a synchronous HTTPS GET via MSXML2.XMLHTTP to download hxxps://www[.]studio-cf[.]com/5f8bwp/C1KMK.ps1, writes the response body as a .ps1 with an 8-character random uppercase filename, then uses WScript.Shell.Run to launch powershell.exe -nop -ep bypass -file in a hidden window. The behavior of downloading and executing a remote script is fully visible in the source and does not depend on an external engine verdict.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **JSE PowerShell Downloader** · aliases JScript downloader, PowerShell payload dropper · _uncertain_ |
| Confidence | **Low** |
| Behavior class | downloader · loader |
| Difficulty | easy |
| First seen | 2026-11-12 07:42:12 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/a6770ca3b3072d5033614da556532f2dfb0c227caedbc3ccf2a7dc073fe790b3/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Create staging directory</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Fetch payload over HTTPS</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Download remote script</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Write script with random name</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Execute with hidden window</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `a6770ca3b3072d5033614da556532f2dfb0c227caedbc3ccf2a7dc073fe790b3` |
| MD5 | _not recorded_ |
| Size | 4,836 bytes (4.7 KB) |
| Type | other · `jse` |

## Behavior Analysis

**8** behaviors in total, each backed by evidence, and all obtained statically.

### 1. Create staging directory

`T1074.001` · Confidence **High** · Static

Uses Scripting.FileSystemObject to check for and create the C:\Temp\ directory as the later payload drop location.

> **Evidence**: f.CreateFolder(dirPath) around offset 1060, directory constant 'C:\\Temp\\' (offset 223)
> 
> **Source**: `ev-000001`

### 2. Fetch payload over HTTPS

`T1071.001` · Confidence **High** · Static

Uses MSXML2.XMLHTTP to issue a synchronous GET to hxxps://www.studio-cf[.]com/5f8bwp/C1KMK.ps1 and, on status 200, takes responseText as the next-stage content.

> **Evidence**: offset 2083 xhr.open('GET', url, false); offset 2133 xhr.send; URL constant offset 155
> 
> **Source**: `ev-000001`

### 3. Download remote script

`T1105` · Confidence **High** · Static

Downloads PowerShell script content from the remote site, constituting inbound tool transfer; on failure it retries up to 2 times.

> **Evidence**: offset 2017 while (attempt <= attempts), attempts defaults to 2; stageDownload calls net.fetch
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Write script with random name

`T1105` · Confidence **High** · Static

Writes the downloaded content via CreateTextFile to a .ps1 file under C:\Temp\ named with 8 random uppercase alphanumeric characters, making file identification harder.

> **Evidence**: offset 1384 Math.random.toString(36).substring(2, 10); offset 1562 CreateTextFile(filePath, true); offset 1625 handle.Write(content)
> 
> **Source**: `ev-000001`

### 5. Execute with hidden window

`T1564.003` · Confidence **High** · Static

Calls WScript.Shell.Run to start powershell.exe with window style 0 (hidden) and waits for completion, so the payload runs invisibly to the user.

> **Evidence**: offset 2960 shell.Run(command, 0, true)
> 
> **Source**: `ev-000001`

### 6. Bypass execution policy

`T1562.001` · Confidence **High** · Static

The command line uses -nop -ep bypass to disable PowerShell profile loading and bypass the execution policy, directly running the downloaded script.

> **Evidence**: offset 2868 command string 'powershell.exe -nop -ep bypass -file "' + scriptPath
> 
> **Source**: `ev-000001` · `ev-000002`

### 7. Run as JScript

`T1059.007` · Confidence **High** · Static

The script runs as Windows Script Host JScript, instantiating FileSystemObject, WScript.Shell and MSXML2.XMLHTTP via ActiveXObject and caching them for reuse.

> **Evidence**: offset 513 new ActiveXObject(progId); offsets 648/713/768 create FileSystemObject, WScript.Shell, MSXML2.XMLHTTP respectively
> 
> **Source**: `ev-000001`

### 8. Reset remote configuration

`T1105` · Confidence **Medium** · Static

Exposes config/reset interfaces that can rewrite or restore the remote address, staging directory and retry count, facilitating payload URL changes on a second delivery.

> **Evidence**: offset 4097 config(key, value) modifies runtime.settings; offset 4340 reset restores the default URL
> 
> **Source**: `ev-000001`


## IOC (Defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the isolated analysis network, and the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://www.studio-cf[.]com/5f8bwp/C1KMK.ps1` | 443 | download | Static | ⏳ Not observed |

### Host

**Drop paths**

- `C:\Temp\`
- `C:\Temp\%RANDOM%.ps1`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `www.studio-cf[.]com` | Yes | Static |
| `c2_url` | `hxxps://www.studio-cf[.]com/5f8bwp/C1KMK.ps1` | Yes | Static |
| `staging_dir` | `C:\Temp\` | Yes | Static |
| `payload_filename_pattern` | `%RANDOM_8_UPPER%.ps1` | Yes | Static |
| `retry_count` | `2` | No | Static |
| `launch_command` | `powershell.exe -nop -ep bypass -file "C:\Temp\<RANDOM>.ps1"` | Yes | Static |

## What Not to Assume

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing the report.

- Do not assess it as ransomware, a stealer or a miner just because of PowerShell download and execution: the script has no file-encryption, credential-collection or mining-pool code, and the downloaded PowerShell payload content was not obtained.
- Do not claim the sample established a C2 session or successfully called back: only the HTTPS GET download address is confirmed from source; no request/response was observed in a real network environment.
- Do not claim persistence (registry Run key, scheduled task, service): no persistence API or command appears in the source.
- Do not treat studio-cf[.]com as attacker-owned infrastructure outright: the domain may be a compromised legitimate site and requires further confirmation with hosted content.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and items to verify**

1. This was pure static analysis; the sample was not run and the remote URL was not accessed, so whether hxxps://www.studio-cf[.]com/5f8bwp/C1KMK.ps1 is still reachable and its actual content cannot be confirmed.
2. The second-stage PowerShell script was not obtained, so its final behavior (such as information theft, persistence, lateral movement) cannot be determined; behavior_class reflects only the first-stage download/loader capability.
3. There is no network session or sandbox behavior telemetry; C2 entries are marked as statically extracted, pending dynamic verification.
4. The script has no family-specific characteristics; the family field is named by behavior type and attribution is uncertain.
5. The sample path shows .jse, but the content is actually unencoded plaintext JScript (not Microsoft JScript Encoded), possibly re-saved or rewritten.

## Evidence Index

<details>
<summary>Show 2 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | 133 ASCII strings, 0 UTF-16LE, 0 flag hits; fully recovered the script source, including the remote URL, C:\Temp\ path, ActiveXObject/XMLHTTP/CreateTextFile/WScript.Shell.Run and the powershell.exe -nop -ep bypass -file command. |
| `ev-000002` | evidence.record | Statically read the plaintext JScript and computed hashes (sha256 matches the sample, md5 be7ad4a1b9b4db1a524e44136519acd0, sha1 85e27450f6da593fa4f2a23b70130b42710d7916); summarized the download-write-hidden-execute call chain and confirmed the sample was not executed. |

</details>

---

_This sample is not public; IOCs are defanged. For security research only._
