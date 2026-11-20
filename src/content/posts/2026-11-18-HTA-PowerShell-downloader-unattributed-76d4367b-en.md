---
title: "Malware Analysis: HTA PowerShell downloader (unattributed) (other · hta · 76d4367b)"
published: 2026-11-18
draft: false
description: "Malicious (low confidence): HTA PowerShell downloader (unattributed) · downloader/loader · difficulty medium · pure static analysis"
tags: ["HTA", "downloader", "loader", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-18-HTA-PowerShell-downloader-unattributed-76d4367b"
---

> [!WARNING]
> **Verdict: malicious** · Family **HTA PowerShell downloader (unattributed)** (uncertain) · Confidence **low**
> 
> The VBScript embedded in the HTA assembles, after noise removal, a PowerShell command that runs hidden; PowerShell first decodes the second-stage script using a custom alphabet + Base64 + XOR, then downloads data disguised as JPG from three hardcoded IPs, extracts the Base64 between <<STT>> and <<D>> and reflectively loads the .NET assembly, finally calling its method with Msbuild/x86 arguments. The whole chain is clear downloader-loader behavior, and the code itself is direct evidence of malicious intent; however, everything was statically decoded and was not executed on a real host.

## Overview

| Item | Content |
|:--|:--|
| Family | **HTA PowerShell downloader (unattributed)** · _uncertain_ |
| Confidence | **low** |
| Behaviour class | downloader · loader |
| Difficulty | medium |
| First seen | 2026-11-16 15:44:11 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/76d4367b1fbcdb020ea7f94e9aea1ac40dcbca536b21f8053574e1a9ab166afa/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Run HTA in a hidden window</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Remove noise, recover command</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Launch PowerShell hidden</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Decode script with custom alphabet</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Poll multiple IPs for payload</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `76d4367b1fbcdb020ea7f94e9aea1ac40dcbca536b21f8053574e1a9ab166afa` |
| MD5 | _not recorded_ |
| Size | 21,887 bytes (21.4 KB) |
| Type | other · `hta` |

## Behaviour analysis

**8** behaviours in total, each tied to evidence, and all statically recoverable.

### 1. Run HTA in a hidden window

`T1564.003` · Confidence **high** · static

HTA:APPLICATION sets BORDER=none, SHOWINTASKBAR=no and WINDOWSTATE=minimize, and the script calls window.close at the end, so the whole execution has no visible interface.

> **Evidence**: HTA:APPLICATION attributes at off 0x30-0x2E0; window.close at the end
> 
> **Source**: `ev-000001`

### 2. Remove noise to recover the command

`T1027` · Confidence **high** · static

The VBScript builds the command with 393 string concatenations, then uses Replace to delete 548 occurrences of the fixed noise token "jkkbjnjm", recovering the complete PowerShell command line.

> **Evidence**: a9JsrcpKj = a9JsrcpKj & "..."; Replace(a9JsrcpKj, "jkkbjnjm", "")
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Launch PowerShell stealthily

`T1059.001` · Confidence **high** · static

Through CreateObject("WScript.Shell").Run it hidden-executes cmd /c %SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe and passes the embedded obfuscated script; SysNative is used to bypass WOW64 redirection and call 64-bit PowerShell.

> **Evidence**: CreateObject("WScript.Shell").Run a9JsrcpKj, 0, False; the command line contains cmd /c %SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Decode the script with a custom alphabet

`T1140` · Confidence **high** · static

PowerShell maps the custom alphabet string back to standard Base64; after FromBase64String decoding it subtracts the 21-byte key byte by byte, obtaining the second-stage script, which it executes with iex.

> **Evidence**: $friMPmCR custom alphabet; $dCxgl5M 21-byte key; [Convert]::FromBase64String; iex $vq3Ues
> 
> **Source**: `ev-000002`

### 5. Poll multiple IPs to download the payload

`T1105` · Confidence **high** · static

The second stage uses System.Net.WebClient to randomly order the JPG paths on three hardcoded IPs and then calls DownloadData in turn, returning the data as soon as one succeeds.

> **Evidence**: DownloadDataFromLinks: $a1.DownloadData($a3); URLs hxxp://64.224.17[.]115/img/1.jpg, hxxp://129.121.148[.]240/img/pics/1.jpg, hxxp://155.103.71[.]164/1.jpg
> 
> **Source**: `ev-000002`

### 6. Extract the markers and reflectively load .NET

`T1620` · Confidence **high** · static

It locates the two markers <<STT>> and <<D>> in the downloaded content, takes the substring between them, Base64-decodes it, then loads the .NET assembly in memory with [Reflection.Assembly]::Load.

> **Evidence**: $a9='<<STT>>'; $b0='<<D>>'; [System.Convert]::FromBase64String($b4); [System.Reflection.Assembly]::Load($b5)
> 
> **Source**: `ev-000002`

### 7. Invoke the loader and specify the target process

`T1055` · Confidence **medium** · static

After reflective loading it obtains and invokes method runss of type myprogram.Homees, with arguments in order: the reversed IPFS address, '0', an empty string, 'Msbuild', '0', 'x86', handing the injection target process name and architecture to the downstream loader.

> **Evidence**: $b7.GetMethod('run'+'ss').Invoke($null, [object[]]($b9,'0','','Msbuild','0','x86'))
> 
> **Source**: `ev-000002`

### 8. IPFS gateway as a fallback payload source

`T1105` · Confidence **medium** · static

The script passes the reverse-stored myfilebase[.]com IPFS gateway address as an argument to the .NET loader for a second retrieval if the primary IP downloads fail; the stored string lacks the http prefix, which the loader fills in.

> **Evidence**: after reversal s://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmWnAEko87xHCkk88NUJGxMeDYCszeBjURHeYiBM4j2ccr (the original string is truncated via Substring(0, Length-15))
> 
> **Source**: `ev-000002`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; under the analysis environment's network isolation no successful connection or session was observed, and the real C2 responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://64[.]224[.]17[.]115/img/1.jpg` | 80 | download | static | ⏳ not observed |
| http | `hxxp://129[.]121[.]148[.]240/img/pics/1.jpg` | 80 | download | static | ⏳ not observed |
| http | `hxxp://155[.]103[.]71[.]164/1.jpg` | 80 | download | static | ⏳ not observed |
| http | `hxxps://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmWnAEko87xHCkk88NUJGxMeDYCszeBjURHeYiBM4j2ccr` | 443 | download | static | ⏳ not observed |

### Host

**Drop paths**

- `%SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `64.224.17[.]115, 129.121.148[.]240, 155.103.71[.]164` | yes | static |
| `fallback_url` | `hxxps://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmWnAEko87xHCkk88NUJGxMeDYCszeBjURHeYiBM4j2ccr` | no | static |
| `payload_markers` | `<<STT>> ... <<D>>` | yes | static |
| `encryption_algo` | `stage1: custom base64 alphabet + 21-byte subtract key (0xAD,0x7A,0x14,0x0A,0x71,0xE3,0xC2,0x50,0x2B,0x1D,0xC6,0x8A,0x9F,0x3C,0xB4,0xEA,0x2E,0xED,0xF7,0x10,0x1D); stage2 strings: LUT '2fiEqFLy3VCsl6o7' + XOR 0x49` | yes | static |
| `injection_target` | `Msbuild` | no | static |
| `architecture` | `x86` | no | static |
| `install_path` | `-` | no | static |
| `campaign_id` | `-` | no | static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not claim the sample was detonated on a real host or in a sandbox with observed download, injection or persistence; all conclusions in this report come from static decoding of the HTA/script.
- Do not assert the family and functionality of the final payload (stealer, ransomware, RAT, etc.); neither the remote .NET assembly nor the IPFS payload was obtained.
- Do not claim the sample created persistence items (registry/scheduled tasks/services); no such code is seen in the scripts.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | no |

**Limitations and pending verification**

1. The sample was not executed; there are no sandbox network or memory observations; all C2 and behaviour are statically recovered, recoverability=static and pending_dynamic_verify=true.
2. The three download IPs and the IPFS gateway were not accessed during analysis, so their current liveness and returned content cannot be confirmed.
3. The .NET assembly between <<STT>>..<<D>> and the IPFS secondary payload could not be obtained, so the injection implementation, final family and follow-on behaviour cannot be confirmed.
4. The IPFS address is stored reversed in the original script with the http prefix truncated; the scheme in this report is completed from context.
5. No AV/YARA hits were obtained; the family name is a candidate and marked uncertain.

## Evidence index

<details>
<summary>Expand 2 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | Extracted ASCII/UTF-16 strings from the HTA, confirming structures such as the HTA:APPLICATION attributes, a9JsrcpKj concatenation fragments and CreateObject(WScript.Shell). |
| `ev-000002` | evidence.record | Self-written Python static deobfuscation: removed noise to recover the VBScript command, decoded the second-stage PowerShell, and decoded the download URL/IPFS address and .NET call arguments (the sample was not executed). |

</details>

---

_The sample behind this report is not public; IOCs are defanged. For security research only._
