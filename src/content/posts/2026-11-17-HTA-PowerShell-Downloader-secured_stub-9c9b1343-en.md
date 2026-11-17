---
title: "Malware Sample Analysis: HTA PowerShell Downloader (secured_stub) (other · hta · 9c9b1343)"
published: 2026-11-17
draft: false
description: "Malicious (medium confidence): HTA PowerShell Downloader (secured_stub) · downloader/loader · difficulty easy · pure static analysis"
tags: ["HTA", "downloader", "loader", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-17-HTA-PowerShell-Downloader-secured_stub-9c9b1343"
---

> [!WARNING]
> **Verdict: Malicious** · Family **HTA PowerShell Downloader (secured_stub)** (uncertain) · Confidence **medium**
> 
> Aliases: SecuredStub HTA dropper
> 
> The sample is an HTA file masquerading as System Uptime. Its built-in RC4 + custom-alphabet Base64 string decryption logic, reconstructed at code level, reveals a complete download-and-execute chain: it synchronously downloads a PowerShell script from hxxp://45.136.5[.]82/23/secured_stub.ps1?JPG, writes it to a randomly named .ps1 under %TEMP%, executes it with -ExecutionPolicy Bypass -WindowStyle Hidden to hide the window, and then deletes the dropped file. This behavior itself is a typical malicious downloader/loader and needs no external engine verdict.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **HTA PowerShell Downloader (secured_stub)** · Alias SecuredStub HTA dropper · _uncertain_ |
| Confidence | **medium** |
| Behavior class | downloader · loader |
| Difficulty | easy |
| First seen | 2026-11-16 15:44:05 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/9c9b13435910c1db025ca3f062ebe7375901f9736276972437bdf322d6be20e5/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Masquerades as system uptime</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">RC4-decrypts string table</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Randomizes dropped filename</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Downloads remote PS1 script</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Writes to temp directory</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `9c9b13435910c1db025ca3f062ebe7375901f9736276972437bdf322d6be20e5` |
| MD5 | _not recorded_ |
| Size | 20,322 bytes (19.8 KB) |
| Type | other · `hta` |

## Behavior Analysis

There are **9** behaviors in total, each backed by evidence, and all are available statically.

### 1. Masquerades as System Uptime

`T1036.005` · Confidence **high** · Static

HTA:APPLICATION sets the application name to System Uptime, minimizes the window, and hides it from the taskbar, to masquerade as a system uptime component.

> **Evidence**: file offset 0-189: APPLICATIONNAME="System Uptime", SHOWINTASKBAR="no", WINDOWSTATE="minimize"
> 
> **Source**: `ev-000001`

### 2. RC4-Decrypts String Table

`T1140` · Confidence **high** · Static

Built-in RC4 and custom-alphabet Base64 decryption functions restore configuration keys, API names, and command strings at runtime; not all plaintext can be read directly statically.

> **Evidence**: string decryption _0x5694/_0x20df/_0x1113 starting at offset 12730; decryption script restores 90 main strings and 36 configuration strings
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Randomizes Dropped Filename

`T1036` · Confidence **high** · Static

Under %TEMP%, generates a dropped filename from 12 random uppercase letters plus .ps1, avoiding detection and cleanup based on fixed filenames.

> **Evidence**: offset 2272 function _0x5aeae0: nameLength=12, alphabet=ABCDEFGHIJKLMNOPQRSTUVWXYZ, suffix .ps1
> 
> **Source**: `ev-000002`

### 4. Downloads Remote PS1 Script

`T1105` · Confidence **high** · Static

Uses MSXML2.XMLHTTP to synchronously GET the remote PowerShell script from hxxp://45.136.5[.]82/23/secured_stub.ps1?JPG.

> **Evidence**: offset 3155 function _0x279773 uses MSXML2.XMLHTTP.open('GET', url, false); offset 800 configuration url assignment
> 
> **Source**: `ev-000001` · `ev-000002`

### 5. Writes to Temp Directory

`T1105` · Confidence **high** · Static

When the HTTP status code is 200, uses Scripting.FileSystemObject.CreateTextFile to write the response body to a random .ps1 file under %TEMP% and closes the handle.

> **Evidence**: offset 3453 function _0x1b64e7: CreateTextFile(path,true)/Write/Close; main flow checks status 0xc8
> 
> **Source**: `ev-000002`

### 6. Executes Script in Hidden Window

`T1059.001` · Confidence **high** · Static

Uses WScript.Shell.Run to launch the dropped script with powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File, with window style 0 and without waiting for the process to exit.

> **Evidence**: offset 5313 function _0x1ca3f9 calls WScript.Shell.Run; offset 5828 command string 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "'
> 
> **Source**: `ev-000001` · `ev-000002`

### 7. Bypasses Execution Policy

`T1562.001` · Confidence **high** · Static

The PowerShell command line explicitly includes -ExecutionPolicy Bypass, bypassing the local script execution policy restrictions.

> **Evidence**: offset 5828 command string contains -ExecutionPolicy Bypass
> 
> **Source**: `ev-000001` · `ev-000002`

### 8. Deletes Dropped Script

`T1070.004` · Confidence **high** · Static

After 3000 ms, checks whether the dropped file exists and calls DeleteFile to delete it, removing disk traces.

> **Evidence**: offset 4459 function _0x2a874e FileExists/DeleteFile; configuration cleanupDelay=0xbb8 (3000 ms)
> 
> **Source**: `ev-000002`

### 9. Closes Window After Execution

`T1564.003` · Confidence **high** · Static

After deletion completes, calls window.close to end the HTA window; the download-failure branch also closes the window directly to shorten exposure time.

> **Evidence**: offset 6030 function _0x3a1899 calls window.close; main flow else branch window.close
> 
> **Source**: `ev-000002`


## IOCs (Defanged)

### Network

:::caution
**Pending dynamic verification**: The above addresses were obtained through static analysis. No successful connection or session was observed in the network-isolated analysis environment, and the real C2 responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://45[.]136[.]5[.]82/23/secured_stub[.]ps1?JPG` | 80 | download | Static | ⏳ Not observed |

### Host

**Dropped path**

- `%TEMP%\<12 random uppercase letters>.ps1`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `45.136.5[.]82` | Yes | Static |
| `c2_port` | `80` | Yes | Static |
| `c2_uri` | `/23/secured_stub.ps1?JPG` | Yes | Static |
| `download_method` | `GET` | No | Static |
| `http_client` | `MSXML2.XMLHTTP` | No | Static |
| `temp_dir` | `%TEMP%` | Yes | Static |
| `filename_length` | `12` | No | Static |
| `filename_alphabet` | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` | No | Static |
| `file_extension` | `.ps1` | Yes | Static |
| `cleanup_delay_ms` | `3000` | No | Static |
| `launch_command` | `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "<path>"` | Yes | Static |
| `encryption_algo` | `RC4 + custom-alphabet Base64 (string obfuscation)` | No | Static |

## Do Not Misjudge

:::important
The following conclusions **are easy to misjudge**; please note them when citing this report.

- The sample cannot be identified as ransomware, a stealer, or a RAT: static analysis only confirms that it downloads and executes a PowerShell script; the final script content was not obtained, and subsequent capabilities are unknown.
- There is no evidence that the sample writes to the registry, creates scheduled tasks or services, or implements persistence; it should not be claimed to have residency capability.
- It should not be attributed to a specific vendor-named family based merely on the single IP/URL or string characteristics; the family name in this report is only a description of the delivery-chain behavior.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and Pending Verification**

1. This time only static analysis was performed; the sample was not detonated in a real isolated environment, and the content of secured_stub.ps1 was not retrieved; the availability of the remote service, the actual delivered payload, and subsequent behavior were not verified.
2. The remote script content is unknown, so the final payload type (such as stealer, RAT, miner) cannot be determined; related fields are left blank or marked pending dynamic verification.
3. The sample is not PE/ELF, so conventional executable structure, import table, and section analysis do not apply; hashes and format were computed by a local byte-reading script.
4. The C2 and configuration all come from code-level decryption and constant reads, marked static and pending_dynamic_verify=true, and not confirmed by a network session.

## Evidence Index

<details>
<summary>Expand 3 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | Static string extraction: 397 ASCII strings; plaintext includes the HTA masquerade header, configuration assignment lines, MSXML2.XMLHTTP/WScript.Shell/Scripting.FileSystemObject, and PowerShell command-line fragments. |
| `ev-000002` | evidence.record | Self-written decryption script reproduces RC4 + custom-alphabet Base64, restores the complete configuration and execution chain, and cross-validates against the sample's _0x1113 configuration array indexes. |
| `ev-000003` | evidence.record | Local byte reading: 20322 bytes, ASCII/CRLF HTA; sha256=9c9b13435910c1db025ca3f062ebe7375901f9736276972437bdf322d6be20e5, md5=c0518ff04706c91792aca3d76adcc8ee. |

</details>

---

_The sample in this report is not public; IOCs have been defanged; for security research only._
