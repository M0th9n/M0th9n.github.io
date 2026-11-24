---
title: "Malware Analysis: EtherHiding (other · msi · ffd3f75d)"
published: 2026-11-22
draft: false
description: "Malicious (medium confidence): EtherHiding · loader/backdoor/implant · medium difficulty · static analysis only"
tags: ["EtherHiding", "loader", "backdoor", "implant", "MSI"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-22-EtherHiding-ffd3f75d"
---

> [!WARNING]
> **Verdict: Malicious** · Family **EtherHiding** (uncertain) · Confidence **Medium**
> 
> Aliases: Node.js EtherHiding loader, Node.js blockchain dead-drop implant
> 
> The MSI installer contains two custom actions: one runs a batch file with cmd.exe and the other runs a VBScript hidden with wscript.exe; the batch file downloads the Node runtime from nodejs[.]org and renames node.exe to SetupHost[.]exe, while the VBScript starts that host hidden to execute JavaScript disguised as .xml. The script is obfuscated by a custom bytecode virtual machine; after decoding, it resolves the C2 address through an Ethereum smart-contract dead drop, loops against the panel /api/ path to pull tasks, and dynamically executes the returned code with new Function, making it a remote-control implant.

## Overview

| Item | Content |
|:--|:--|
| Family | **EtherHiding** · aliases Node.js EtherHiding loader, Node.js blockchain dead-drop implant · _uncertain_ |
| Confidence | **Medium** |
| Behavior classes | loader · backdoor · implant |
| Difficulty | medium |
| First seen | 2026-11-22 10:58:43 |
| Analysis method | Static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ffd3f75dc955f02cd4a2a75952669fe6627c79f1b1f2533f2fc3bbb345daf2da/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Custom action triggers payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1218.007</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Download Node as host</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Fake xml runs JS</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.008</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Blockchain resolves C2</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Poll panel for tasks</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `ffd3f75dc955f02cd4a2a75952669fe6627c79f1b1f2533f2fc3bbb345daf2da` |
| MD5 | _Not recorded_ |
| Size | 39,424 bytes (38.5 KB) |
| Type | other · `msi` |

## Behavior Analysis

**9** behaviors in total, each backed by evidence, and all are static.

### 1. Custom Action Triggers Payload

`T1218.007` · Confidence **High** · Static

The MSI CustomAction executes the dropped scripts during installation with two commands: [SystemFolder]cmd.exe /c "[dir]ConfigureProduct.cmd" and wscript.exe //B //Nologo "[dir]4glrodx5s.vbs" …

> **Evidence**: MSI CustomAction strings in the 30012–30600 range; wscript.exe arguments include 4glrodx5s.vbs, EmbeddedHost\SetupHost[.]exe, NCPaZsSrJXdD.xml
> 
> **Source**: `ev-000009` · `ev-000010`

### 2. Download Node as Host

`T1105` · Confidence **High** · Static

The batch file uses PowerShell to decode the built-in base64 into hxxps://nodejs[.]org/dist/v18.19.0/node-v18.19.0-win-x64.zip, downloads it to %TEMP% with System32\curl.exe, extracts it with tar.exe and renames node.exe to EmbeddedHost\SetupHost[.]exe.

> **Evidence**: ConfigureProduct.cmd contains PACKAGE_SRC_B64=aHR0cHM6Ly9ub2RlanMub3JnL2Rpc3QvdjE4LjE5LjAvbm9kZS12MTguMTkuMC13aW4teDY0LnppcA== and curl/tar/ren calls
> 
> **Source**: `ev-000010`

### 3. Fake xml Runs JS

`T1036.008` · Confidence **High** · Static

The MSI File table installs random CAB member 9zcwfbdl.xml as NCPaZsSrJXdD.xml, and the VBScript uses WScript.Shell.Run to start SetupHost[.]exe (i.e. node.exe) hidden and execute that .xml as a script, achieving file-type masquerading.

> **Evidence**: File table maps 9zcwfbdl.xml|NCPaZsSrJXdD.xml; iNsMUqg28zax content is CreateObject("WScript.Shell").Run ... CLng(0), False
> 
> **Source**: `ev-000009` · `ev-000010`

### 4. Blockchain Resolves C2 Address

`T1102.001` · Confidence **High** · Static

The implant concurrently sends eth_call to 7 Ethereum JSON-RPC endpoints (to=0xdf64c4d1…, data=0x7d434425+0x977928…), parses the returned string per ABI and votes to select the C2 URL, falling back to the built-in panel address on failure.

> **Evidence**: Deobfuscated strings 'hxxps://rpc[.]flashbots[.]net/fast' etc., 'eth_call', '0x7d434425', contract 0xdf64c4d1fa017fc565e6564b117bd6ba8437953f
> 
> **Source**: `ev-000010`

### 5. Poll Panel for Tasks

`T1071.001` · Confidence **High** · Static

Loops GET requests to {C2}/api/{random4hex}/{UUID}/{random4hex}.{png|jpg|gif|css|ico|webp}?{id|token|key|b|q|s|v}={build} with a per-request timeout of about 120 seconds; successful rounds are about 0.5 seconds apart, after a connection error it randomly switches address and waits about 5 seconds, and it re-resolves the blockchain address about every 300 seconds.

> **Evidence**: fetch(_cm, {signal}) in _aq; the URL is built from '/api/' and '.png/.jpg/.gif/.css/.ico/.webp'; log strings 'Polling: ', 'Poll failed: '
> 
> **Source**: `ev-000010`

### 6. Dynamically Execute Remote Code

`T1059.007` · Confidence **High** · Static

Inserts the panel response body (longer than 10 bytes) into new Function("require","process","Buffer","console","__dirname","__filename","log","return (async=>{"+task+"})") and awaits execution, equivalent to arbitrary Node.js remote code execution.

> **Evidence**: new Function string concatenation in the JS + 'Task executed' / 'Task error: ' logs
> 
> **Source**: `ev-000010`

### 7. Generate Random Install Location

`T1074.001` · Confidence **High** · Static

Derives a directory name from the md5 of COMPUTERNAME and USERNAME and creates a random multi-level directory under one of Microsoft/Windows/Programs/Packages/Google and Services/Components/Assemblies/Extensions/Modules in %LOCALAPPDATA%, writing a base64(JSON) configuration (including a randomUUID-generated client identifier) and a sha1-named log file.

> **Evidence**: LOCALAPPDATA/USERPROFILE/AppData/Local and two word lists in _e; mkdirSync(recursive), writeFileSync(base64), appendFileSync logging
> 
> **Source**: `ev-000010`

### 8. Evade EDR Environment

`T1518.001` · Confidence **Medium** · Static

The MSI RegLocator/properties contain SENTINELONE_DIR and the condition string NOT SENTINELONE_DIR, used to skip the corresponding actions when a SentinelOne installation directory is detected.

> **Evidence**: MSI strings 'SENTINELONE_DIR … NOT SENTINELONE_DIR' (about the 28989–29650 range)
> 
> **Source**: `ev-000001` · `ev-000009`

### 9. Hide Windows and Clean Traces

`T1564.003` · Confidence **High** · Static

Starts itself in the background with start "" /MIN, the VBScript runs hidden with window mode 0 and wscript //B runs without prompts; the downloaded package is deleted with del /q after use, and RemoveFile is configured to clean temporary files.

> **Evidence**: start /MIN, wscript //B //Nologo, del /q in ConfigureProduct.cmd; MSI RemoveFile/RemoveTempFiles entries
> 
> **Source**: `ev-000009` · `ev-000010`


## IOC (Defanged)

### Network

:::caution
**Pending dynamic verification**: The addresses above were obtained statically; no successful connection or session was observed under the isolated analysis network, so the real C2 responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://fortic[.]eastus[.]cloudapp[.]azure[.]com` | 443 | c2 | static | ⏳ Not observed |
| other | `Ethereum eth_call selector 0x7d434425 -> contract 0xdf64c4d1fa017fc565e6564b117bd6ba8437953f (argument 0x977928898a80c7228d8c2e80dfa42ff75f746f56), returns C2 URL` | 443 | c2 | static | ⏳ Not observed |
| http | `hxxps://rpc[.]flashbots[.]net/fast and 6 other Ethereum JSON-RPC endpoints (tenderly/mevblocker/blastapi/publicnode/drpc/merkle)` | 443 | c2 | static | ⏳ Not observed |

### Host

**Drop paths**

- `%LOCALAPPDATA%\<Microsoft|Windows|Programs|Packages|Google>\<Services|Components|Assemblies|Extensions|Modules>\<4hex>\ (random install directory derived from md5(COMPUTERNAME+USERNAME))`
- `%LOCALAPPDATA%\...\<4hex>\<first 8 chars of md5(install dir)> (base64(JSON) client identifier/config)`
- `%LOCALAPPDATA%\...\<4hex>\<first 8 chars of sha1(install dir+"l")> (runtime log)`
- `%TEMP%\MbZidXdN_GKnCJe6CuQ_PostApply.log`
- `%TEMP%\MbZidXdN_GKnCJe6CuQ_<random>.zip (Node runtime download package, deleted after use)`
- `%<system drive>\Program Files\SentinelOne (only as an EDR presence check target)`

**Registry**

- `HKCU\Software\MbZidXdN\GKnCJe6CuQ (root key inferred from the MSI Registry table, not dynamically confirmed)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `hxxps://fortic[.]eastus[.]cloudapp[.]azure[.]com` | Yes | static |
| `c2_contract` | `0xdf64c4d1fa017fc565e6564b117bd6ba8437953f` | Yes | static |
| `c2_selector` | `0x7d434425` | Yes | static |
| `c2_contract_arg` | `0x977928898a80c7228d8c2e80dfa42ff75f746f56` | Yes | static |
| `rpc_fallbacks` | `hxxps://mainnet[.]gateway[.]tenderly[.]co; hxxps://rpc[.]flashbots[.]net/fast; hxxps://rpc[.]mevblocker[.]io; hxxps://eth-mainnet[.]public[.]blastapi[.]io; hxxps://ethereum-rpc[.]publicnode[.]com; hxxps://eth[.]drpc[.]org; hxxps://eth[.]merkle[.]io` | No | static |
| `build_id` | `0ea3559d-1abc-4bd2-b595-58b778d21cd9` | Yes | static |
| `task_uri_pattern` | `{c2}/api/{rand4hex}/{uuid}/{rand4hex}.{png\|jpg\|gif\|css\|ico\|webp}?{id\|token\|key\|b\|q\|s\|v}={build}` | Yes | static |
| `install_path_pattern` | `%LOCALAPPDATA%\<wordA>\<wordB>\<4hex> (wordA/wordB selected by the first 4 hex chars of md5(COMPUTERNAME+USERNAME))` | Yes | static |
| `encryption_algo` | `none (only md5/sha1 used to generate file names; communication and files not encrypted)` | No | static |
| `runtime_host` | `node.exe (downloaded from nodejs[.]org and renamed SetupHost[.]exe)` | Yes | static |

## Common Misinterpretations

:::important
The following conclusions are **easy to misinterpret**; keep them in mind when citing this report.

- Do not call it ransomware or an encryptor: the deobfuscated code only uses md5/sha1 to derive file and log names, with no file-encryption or ransom logic.
- Do not call it traditional PE process injection: all logic runs in Node.js user-mode scripts, and no VirtualAllocEx/CreateRemoteThread-style injection was found.
- Do not treat the nodejs[.]org download address as C2: that URL is only used to fetch the official Node runtime as a legitimate host, and the real controller is fortic[.]eastus[.]cloudapp[.]azure[.]com plus the Ethereum contract resolution result.
- Do not claim credential/browser-data theft was observed: this static analysis found no related file-access logic, and it cannot be classified as a stealer on this basis.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Static analysis only |
| Unpacked | No |

**Limitations and pending verification**

1. This was static analysis only and no usable dynamic channel was enabled; installation-time behavior is inferred from MSI tables and embedded scripts, with no runtime network/process observations.
2. The C2 address and configuration were obtained by static deobfuscation, with recoverability marked static and pending_dynamic_verify=true; no real session with the panel occurred.
3. The MSI stream names were character-level modified and the Registry table Root column was not parsed table by table; the root key of HKCU\Software\MbZidXdN\GKnCJe6CuQ is an inferred value.
4. No scheduled tasks or services were actually created or observed; the implant itself does not contain these persistence methods, and persistence relies mainly on MSI installation and files in the random directory.
5. Deobfuscation relies on a reproduced bytecode VM interpreter (9 opcodes), and all 145 strings were decoded one by one; any runtime secondary decryption is outside this coverage.
6. The sample format is neither PE nor ELF, so conventional structural tools do not apply, and the conclusions rest on the compound-document structure, CAB contents and script semantics.

## Evidence Index

<details>
<summary>Expand 2 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000009` | String extraction | MSI string extraction: ProductName/Manufacturer/CustomAction/File table names, SENTINELONE_DIR condition etc. (58 ascii, 13 utf16le, including table strings in the 28989–30600 range) |
| `ev-000010` | evidence.record | Script parsing of the compound document, CAB and 3 payloads extraction, bytecode VM reproduction decoding 145 strings, and recovery of the Node.js implant logic and C2 configuration |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
