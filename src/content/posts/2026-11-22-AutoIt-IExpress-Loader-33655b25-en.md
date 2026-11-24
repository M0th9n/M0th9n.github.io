---
title: "Malware Analysis: AutoIt IExpress Loader (PE · exe · 33655b25)"
published: 2026-11-22
draft: false
description: "Malicious (low confidence): AutoIt IExpress Loader · loader/dropper · medium difficulty · dynamic sandbox + static decompilation"
tags: ["AutoIt IExpress", "loader", "dropper", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-22-AutoIt-IExpress-Loader-33655b25"
---

> [!WARNING]
> **Verdict: Malicious** · Family **AutoIt IExpress Loader** (uncertain) · Confidence **Low**
> 
> Aliases: ColorSync Dynamics loader, IExpress + AutoIt reflective loader
> 
> The file is an IExpress self-extracting package modified from Microsoft's Win32 Cabinet Self-Extractor (wextract), embedding a 1.5MB CAB in its resources. After extraction it drops the genuine AutoIt3 interpreter and a compiled/encrypted Bond.au3 script, and uses cmd /c explorer.exe Hampton.lnk to create a shortcut pointing to AutoIt3.exe Bond.au3 for a second-stage launch. The statically recovered AutoIt script implements a hand-written PE reflective mapping, AMSI bypass, analysis-environment checks, scheduled-task persistence and a masquerading directory under %APPDATA%; the dynamic sandbox fully observed the "self-extract → AutoIt → explorer → AutoIt script" process chain. It is assessed as a malicious loader/dropper.

## Overview

| Item | Content |
|:--|:--|
| Family | **AutoIt IExpress Loader** · aliases ColorSync Dynamics loader, IExpress + AutoIt reflective loader · _uncertain_ |
| Confidence | **Low** |
| Behavior classes | loader · dropper |
| Difficulty | medium |
| First seen | 2026-11-20 17:10:54 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/33655b25377b44ca1fc1ee24c36a5e31e01926c217ee54113a3eb0213768ab39/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Unpack self-extractor</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Shortcut launches script</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Reflective PE mapping</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Bypass AMSI scanning</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Probe analysis environment</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `33655b25377b44ca1fc1ee24c36a5e31e01926c217ee54113a3eb0213768ab39` |
| MD5 | _Not recorded_ |
| Size | 1,806,336 bytes (1.7 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**8** behaviors in total, each backed by evidence; **6** are static and **2** were obtained dynamically.

### 1. Unpack Self-Extracting Payload

`T1027.009` · Confidence **High** · Dynamic

As an IExpress self-extracting package, it extracts AutoIt3.exe and Bond.au3 from the embedded CAB into %TEMP%\IXP000.TMP and launches them; the resource-section SED directive is cmd /c explorer.exe Hampton.lnk & timeout /t 8 /nobreak.

> **Evidence**: Dynamic process/file events: PID 4000 created %TEMP%\IXP000.TMP\AutoIt3.exe at 23:42:23; SED command string at static offset 0x1B62E8; .rsrc contains an MSCF CAB.
> 
> **Source**: `ref:357abbfdd8` · `ref:6a93ced2cf` · `ref:712c25af9b` · `ref:39066d348c`

### 2. Shortcut Launches Script

`T1204.002` · Confidence **High** · Dynamic

After extraction, AutoIt3.exe /AutoIt3ExecuteLine calls FileCreateShortcut to create Hampton.lnk (target AutoIt3.exe, argument Bond.au3), then opens it with explorer.exe Hampton.lnk, and explorer launches C:\Users\<user>\AppData\Local\Temp\IXP000.TMP\AutoIt3.exe Bond.au3.

> **Evidence**: Dynamic process chain (same timeline): cmd.exe /c explorer.exe Hampton.lnk -> explorer.exe Hampton.lnk -> AutoIt3.exe Bond.au3 (parent explorer.exe, PID 4140).
> 
> **Source**: `ref:6a93ced2cf` · `ref:357abbfdd8`

### 3. Reflective PE Mapping

`T1620` · Confidence **High** · Static

The AutoIt script implements a hand-written PE loader: parse IMAGE_DOS_HEADER/IMAGE_NT_HEADERS, allocate executable memory, copy by section, resolve imports and fix relocations, and finally call the entry point with DllCallAddress, executing the embedded payload without a PE file on disk.

> **Evidence**: Script plaintext strings contain word Magic;byte MajorLinkerVersion;...;dword NumberOfRvaAndSizes and the IMAGE_DOS_HEADER structure; the function body uses DllCall(kernel32!VirtualAlloc/GetProcAddress) and DllCallAddress(entry).
> 
> **Source**: `ref:39066d348c` · `ref:ed82ddd346`

### 4. Bypass AMSI Scanning

`T1562.001` · Confidence **Medium** · Static

The script decodes amsi.dll and AmsiScanBuffer strings and locates/patches the AMSI scanning function during the loading flow to evade memory/script content detection (AMSI bypass).

> **Evidence**: Decoded strings match 'amsi.dll', 'AmsiScanBuffer'; the script calls ntdll/kernel32 to resolve exports and modify memory.
> 
> **Source**: `ref:39066d348c`

### 5. Probe Analysis Environment

`T1497.001` · Confidence **Medium** · Static

The script embeds virtualization/sandbox/antivirus process lists (vmtoolsd.exe, VBoxTray.exe, SandboxieRpcSs.exe, avastui.exe, bdagent.exe) and exits early on a match, avoiding unfolding follow-up payloads in an analysis environment.

> **Evidence**: Decoded strings contain vmware/vbox/sandboxie/avast/bitdefender process names; dynamically, the AutoIt script process exits about 2 seconds after launch with no follow-up behavior.
> 
> **Source**: `ref:39066d348c` · `ref:6a93ced2cf`

### 6. Scheduled Task Persistence

`T1053.005` · Confidence **Medium** · Static

The script carries a complete scheduled-task XML (URI \SpectraFox, LogonType InteractiveToken, RunLevel HighestAvailable, ExecutionTimeLimit PT0S) and can call schtasks to create a task, re-launching the loader after boot/logon.

> **Evidence**: Decoded strings: <RegistrationInfo><URI>\SpectraFox</URI>, <RunLevel>HighestAvailable</RunLevel>, <LogonType>InteractiveToken</LogonType>, hxxp://schemas[.]microsoft[.]com/windows/2004/02/mit/task.
> 
> **Source**: `ref:39066d348c`

### 7. Masquerading Directory Drop

`T1036.005` · Confidence **Medium** · Static

Stores H.au3, AutoIt3.exe, notfound.dat and SpectraFox.lnk in a vendor-lookalike directory %APPDATA%\ColorSync Dynamics\; the file and directory names show masquerading/evasion traits.

> **Evidence**: Decoded paths: \ColorSync Dynamics\H.au3, \ColorSync Dynamics\AutoIt3.exe, \ColorSync Dynamics\notfound.dat, \ColorSync Dynamics\SpectraFox.lnk.
> 
> **Source**: `ref:39066d348c`

### 8. Embedded Encrypted Large Payload

`T1027.013` · Confidence **High** · Static

The script assembles a 392,926-byte payload from 215 hexadecimal string segments and, after processing with a runtime key/self-decrypting stub, hands it to the reflective mapper; this payload is the final executable and cannot be statically recovered as a PE.

> **Evidence**: $DUVISMREQ is assembled from 215 hexadecimal fragments of 3,638 chars (785,852 hex chars total); payload entropy about 7.997, length 392926 ≡ 14 (mod 16); 16-byte repeated key material D3B105F5B61A538037ECE4099F40FB06 present.
> 
> **Source**: `ref:39066d348c` · `ref:ed82ddd346`


## IOC (Defanged)

### Network

:::note
**No C2 / network IOC recovered** (see "Analysis Method and Limitations" at the end).
:::

### Host

**Drop paths**

- `%TEMP%\IXP000.TMP\AutoIt3.exe`
- `%TEMP%\IXP000.TMP\Bond.au3`
- `%TEMP%\IXP000.TMP\Hampton.lnk`
- `%APPDATA%\ColorSync Dynamics\H.au3`
- `%APPDATA%\ColorSync Dynamics\AutoIt3.exe`
- `%APPDATA%\ColorSync Dynamics\notfound.dat`
- `%APPDATA%\ColorSync Dynamics\SpectraFox.lnk`

**Scheduled tasks**

- `\SpectraFox`
- `\Integrating`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `install_path` | `%APPDATA%\ColorSync Dynamics\` | Yes | static |
| `dropped_files` | `H.au3;AutoIt3.exe;notfound.dat;SpectraFox.lnk` | Yes | static |
| `scheduled_task_name` | `\SpectraFox` | No | static |
| `embedded_payload_size` | `392926` | Yes | static |
| `payload_protection` | `hex-embedded + runtime decryption/self-decrypting stub + reflective PE mapping` | Yes | static |
| `loader_technique` | `AutoIt hand-written PE mapper (parses IMAGE_DOS_HEADER/IMAGE_NT_HEADERS, VirtualAlloc, calls entry via DllCallAddress)` | Yes | static |

## Common Misinterpretations

:::important
The following conclusions are **easy to misinterpret**; keep them in mind when citing this report.

- Do not judge it as benign or a "legitimate self-extracting tool" because the sample carries Microsoft wextract version information/signature appearance; the CAB embedded in .rsrc and the AutoIt loader are the actual behavior.
- No C2 session was observed (network monitoring shows only the system's own traffic); do not fabricate C2 addresses/ports, and do not conclude from this that it is a remote-control/stealer family.
- Do not claim that scheduled tasks/registry keys were actually created: currently there is only evidence of task XML and command strings inside the script, and dynamic telemetry shows no such creation events.
- Reflective mapping happens inside the AutoIt process; no cross-process injection or process hollowing was observed, so do not report it as injector/process hollowing.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacked | Yes (stage2 `956ff12aac9252d44069817a7733a233f504ea9632aff082819b56603dd56501`) |

**Limitations and pending verification**

1. The embedded 392,926-byte payload could not be decrypted statically (XOR/16-byte repeated-key/AES attempts all failed), so the final C2, family attribution and payload function cannot be confirmed; live-host memory forensics (capturing AutoIt process memory after decryption/mapping) is needed.
2. In the dynamic sandbox the AutoIt script process exits within seconds of launch, producing no network connections, persistence writes or child processes; combined with the virtualization/sandbox process list in the script, this is inferred to be an environment-check-driven exit, but that is an inference rather than direct observation.
3. No memory dump was obtained after the .au3 loader executed (the process lifetime was too short), so reflective mapping/AMSI bypass rest on static script evidence only, without runtime memory corroboration.
4. No host persistence (scheduled task/Run key) was observed actually landing in this run; the related capabilities come from plaintext strings and task XML inside the script.
5. AutoIt3.exe is a signed genuine interpreter and does not imply its behavior is legitimate; that binary itself contains no malicious logic.

## Evidence Index

<details>
<summary>Expand 10 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1/imphash/rich header |
| `ev-000004` | scan.entropy | Per-section entropy: .rsrc entropy 7.976 (embedded compressed CAB) |
| `ev-000011` | String extraction | String extraction; wextract/IExpress traits already visible in the short-string pass |
| `ev-000015` | String extraction | Long-string pass hit SED commands: cmd /c explorer.exe Hampton.lnk and AutoIt3.exe /AutoIt3ExecuteLine FileCreateShortcut(...) |
| `ev-000016` | evidence.record | Static unpacking/script recovery/string decoding (CAB, Bond.au3, AutoIt3.exe, 1,819 plaintext strings, scheduled task and path IOCs) |
| `ev-000017` | evidence.record | Static decryption attempts on the embedded 391KB payload and the failure conclusion |
| `telemetry:33655b25` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component 2 registry events; monitoring component 127 process/file events; 3 ETW short-lived process events; 26 tool/system noise events filtered |
| `etw:33655b25:4000` | Process event monitoring | Short-lived process event: 33655b25377b44ca1fc1ee24c36a5e31e01926c217ee54113a3eb0213768ab39.exe (pid 4000; MD5=A75F7EB5D62E36C994DF43B2D26A87A4,SHA256=33655B25377B44CA1FC1EE24C36A5E31E01926C217EE54113A3EB0213768AB39,IMPHASH=89A4228E8581F783C2AB1992D9178F8E) |
| `etw:33655b25:4952` | Process event monitoring | Short-lived process event: AutoIt3.exe (pid 4952; MD5=80CDD5F19D704A001589976BAE277BAB,SHA256=5D69A932A077FEE044B193C28E84564143F5C7E51079AB48E88FEF74AB0B77B7,IMPHASH=3614AFAB8D930EE31934510EDB015CDC) |
| `etw:33655b25:4140` | Process event monitoring | Short-lived process event: AutoIt3.exe (pid 4140; MD5=80CDD5F19D704A001589976BAE277BAB,SHA256=5D69A932A077FEE044B193C28E84564143F5C7E51079AB48E88FEF74AB0B77B7,IMPHASH=3614AFAB8D930EE31934510EDB015CDC) |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
