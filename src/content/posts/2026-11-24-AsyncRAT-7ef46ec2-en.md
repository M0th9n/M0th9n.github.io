---
title: "Malicious sample analysis: AsyncRAT (PE · exe · 7ef46ec2)"
published: 2026-11-24
draft: false
description: "Malicious (confidence: high): AsyncRAT · rat · difficulty medium · dynamic sandbox + static decompilation"
tags: ["AsyncRAT", "rat", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-24-AsyncRAT-7ef46ec2"
---

> [!WARNING]
> **Verdict: malicious** · Family **AsyncRAT** · Confidence **high**
> 
> Aliases: Async Client, AsyncClientnoanti, AsyncRAT 0.5.7B
> 
> The sample's outer layer is a ConfuserEx-protected .NET program (the import table contains only mscoree.dll!_CorExeMain; there is a writable and executable section with entropy 8.0 and a ConfusedByAttribute). At runtime it decrypts and loads the AsyncClientnoanti assembly in memory; in the dynamic sandbox the sample drops %APPDATA%\cvbt.exe, creates multiple autostart configurations, and continuously initiates TCP connections to two external domains and three non-standard ports. The statically decrypted configuration (host, port, version, mutex, install path, group) matches the dynamic observations exactly, and the malicious nature is clear.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **AsyncRAT** · Aliases Async Client, AsyncClientnoanti, AsyncRAT 0.5.7B |
| Confidence | **high** |
| Behavior class | rat |
| Difficulty | medium |
| First seen | 2026-11-24 12:20:08 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/7ef46ec27e5874d4e7c50fb1af113361f7b9b9675b7bc2a4ab4d5c8235e669e1/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt and load RAT in memory</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Install copy to AppData</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Create logon scheduled task</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Write Run key for autostart</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Connect to C2 and rotate ports</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `7ef46ec27e5874d4e7c50fb1af113361f7b9b9675b7bc2a4ab4d5c8235e669e1` |
| MD5 | _Not recorded_ |
| Size | 183,296 bytes (179.0 KB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **9** behaviors in total, each backed by evidence; **6** are statically available and **3** were obtained through dynamic analysis.

### 1. Decrypt and load the RAT in memory

`T1620` · Confidence **high** · Dynamic

The outer .NET packer decrypts the payload from a high-entropy executable section, maps the AsyncClientnoanti assembly into memory and executes it; no plaintext payload exists on disk.

> **Evidence**: Memory scan shows a MEM_PRIVATE .NET PE at 0x400000 (header replaced, implanted PE=1), with the module AsyncClientnoanti; the outer section 'a\n\t~n\b$f' has entropy 7.998.
> 
> **Source**: `ev-000012` · `ev-000003` · `ev-000009` · `ref:c35f33dc83`

### 2. Install a copy to AppData

`T1036.005` · Confidence **high** · Dynamic

Copies itself to %APPDATA%\cvbt.exe and executes it; this copy then spawns multiple further instances.

> **Evidence**: Dynamic process events show cmd.exe launching C:\Users\analyst\AppData\Roaming\cvbt.exe, whose hash matches the original sample, which in turn spawns two more cvbt.exe processes, 4932/4220.
> 
> **Source**: `ev-000012` · `ev-000011`

### 3. Create a logon scheduled task

`T1053.005` · Confidence **high** · Static

Executes schtasks via cmd to create a highest-privilege logon-triggered scheduled task whose name is the program filename (cvbt) and which points to its own path.

> **Evidence**: In the IL of the Install method, ldstr '/c schtasks /create /f /sc onlogon /rl highest /tn "' and ' /tr \"' are concatenated and then passed to Process.Start.
> 
> **Source**: `ev-000013`

### 4. Write a Run key for autostart

`T1547.001` · Confidence **high** · Static

Restores the reversed string to Software\Microsoft\Windows\CurrentVersion\Run and writes the value name cvbt with the quoted own path as data.

> **Evidence**: IL: ldstr '\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS' → Strings.StrReverse → RegistryKey.SetValue(filename, "\"path\"").
> 
> **Source**: `ev-000013`

### 5. Connect to C2 and rotate ports

`T1571` · Confidence **high** · Dynamic

Resolves the two domains in the configuration and sequentially tries the three non-standard ports 8879, 5437, and 8867 to establish an encrypted C2 channel.

> **Evidence**: Network monitoring logs record 49 TCP connection attempts by cvbt.exe(4220) to 5437/8879/8867, plus DNS queries for the two C2 domains (25/17 times).
> 
> **Source**: `ev-000012` · `ev-000011`

### 6. Create a mutex to prevent double launch

`T1480` · Confidence **high** · Static

Creates the named mutex AsyncMutex_6SI8OuPTm at startup and exits if it already exists, ensuring single-instance execution.

> **Evidence**: Program.Main calls MutexControl.CreateMutex; configuration decryption yields MTX=AsyncMutex_6SI8OuPTm.
> 
> **Source**: `ev-000013` · `ev-000011`

### 7. Mark the process as critical

`T1562.001` · Confidence **high** · Static

After obtaining debug privilege it calls RtlSetProcessIsCritical, so that terminating the process can trigger a system crash, improving resistance to termination.

> **Evidence**: ProcessCritical.Set IL: Process.EnterDebugMode → kernel32!RtlSetProcessIsCritical; called by Program.Main after installation.
> 
> **Source**: `ev-000013`

### 8. Terminate same-named processes

`T1057` · Confidence **medium** · Static

Enumerates processes and kills other instances with the same name as itself, avoiding multi-instance conflicts and facilitating replacement with the installed copy.

> **Evidence**: Process.GetProcesses + name comparison + Process.Kill in Install IL.
> 
> **Source**: `ev-000013` · `ev-000012`

### 9. Restart via a self-deletion script

`T1070.004` · Confidence **high** · Static

Generates a batch file in %TEMP% that restarts itself after a delay and deletes the original file, covering the drop traces.

> **Evidence**: In IL, GetTempFileName + '.bat', writing '@echo off', 'timeout 3 > NUL', 'START "" "path"', 'DEL "filename" /f /q' and then executing it.
> 
> **Source**: `ev-000013`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: The above address comes from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `rortyfivev[.]chickenkiller[.]com` | 8879 | c2 | Static | ⏳ Not observed |
| tcp | `gortyfivev[.]crabdance[.]com` | 8879 | c2 | Static | ⏳ Not observed |

### Host

**Mutex**

- `AsyncMutex_6SI8OuPTm`

**Drop paths**

- `%APPDATA%\cvbt.exe`
- `%TEMP%\<random name>.bat`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\cvbt`

**Scheduled tasks**

- `cvbt (schtasks /create /f /sc onlogon /rl highest)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `rortyfivev[.]chickenkiller[.]com,gortyfivev[.]crabdance[.]com` | Yes | Static |
| `c2_ports` | `8879,5437,8867` | Yes | Static |
| `mutex` | `AsyncMutex_6SI8OuPTm` | Yes | Static |
| `install_path` | `%APPDATA%\cvbt.exe` | Yes | Static |
| `install_file` | `cvbt.exe` | Yes | Static |
| `version` | `0.5.7B` | Yes | Static |
| `campaign_id` | `Default3` | No | Static |
| `encryption_algo` | `AES-256-CBC (PBKDF2-HMAC-SHA1 with 50000 iterations, HMAC-SHA256 verification)` | Yes | Static |
| `server_certificate_cn` | `AsyncRAT Server` | No | Static |
| `anti_analysis` | `false (built-in anti-virtualization/anti-debug code not enabled)` | No | Static |
| `install` | `true` | Yes | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not classify it as ransomware or a data encryptor: AES/Rijndael is used only for encrypting configuration fields and C2 communications; no file encryption or ransom behavior was found.
- Do not mistake the outer 'server1.exe'/ConfuserEx shell for the final family; the real payload is AsyncRAT 0.5.7B in memory.
- Do not claim that a C2 session was completed or commands were received in the dynamic environment: only DNS resolution and TCP connection attempts were observed, with no application-layer request/response.
- Do not claim the sample executed anti-virtualization logic this time: Anti=false in the configuration; the anti-analysis code exists but was not enabled.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `f4be3a7e1f5f08090c7d9fe3de95971e2e3aae3637569e6fa6715fb17c89c2c7`) |

**Limitations and pending verification**

1. Within the dynamic window only DNS resolution of the two C2 domains and TCP connection attempts to 5437/8879/8867 were observed; no complete application-layer session formed, so C2 is handled as statically recovered and marked for pending dynamic review.
2. Artifact archiving is incomplete (some large process dumps were not retrieved); configuration decryption is based on the AsyncClientnoanti module exported from the memory scan; the decryption results were cross-validated against the dynamically observed domains and ports.
3. No runtime differential telemetry of the registry/scheduled tasks was obtained this time; the persistence-write conclusions come from the disassembly call chain rather than runtime registry observation.
4. The sample has built-in virtualization-platform/VirtualBox/SbieDll/debugger/small-disk checks, but Anti=false in the configuration; the anti-analysis logic was not observed to actually trigger this time.
5. No real external network was used, so the C2 panel's liveness, the check-in payload content, and subsequent command capability cannot be confirmed.

## Evidence Index

<details>
<summary>Expand 9 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1 and file size |
| `ev-000002` | scan.imphash | imphash=f34d5f2d4577ed6d9ceec516c1f5a744 (.NET single-import characteristic) |
| `ev-000003` | scan.entropy | Executable section 'a\n\t~n\b$f' entropy 7.998 |
| `ev-000008` | PE structure parsing | Writable and executable section anomaly |
| `ev-000009` | Sample triage | Packing likelihood 0.45, very few import symbols |
| `ev-000010` | String extraction | String surface (no plaintext configuration directly matched, consistent with encrypted-configuration characteristics) |
| `ev-000011` | evidence.record | AsyncRAT configuration decryption results (host/port/version/mutex/install path/group/certificate) |
| `ev-000012` | evidence.record | Dynamic sandbox timeline, process creation, network connections, and memory module observations |
| `ev-000013` | evidence.record | AsyncRAT key method IL recovery (install/persistence/anti-analysis/critical process/self-deletion) |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
