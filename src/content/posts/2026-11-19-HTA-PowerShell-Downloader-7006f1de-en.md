---
title: "Malware sample analysis: HTA PowerShell Downloader (other · hta · 7006f1de)"
published: 2026-11-19
draft: false
description: "Malicious (low confidence): HTA PowerShell Downloader · downloader/dropper · difficulty easy · pure static analysis"
tags: ["HTA", "downloader", "dropper", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-19-HTA-PowerShell-Downloader-7006f1de"
---

> [!WARNING]
> **Verdict: malicious** · Family **HTA PowerShell Downloader** (uncertain) · Confidence **low**
> 
> Aliases: HTA/PSDownloader, System Uptime HTA stager, secured_stub loader
> 
> The sample is a 7664-byte plaintext HTA (no encoding, no encryption, no hidden appended data); the script immediately executes the full delivery chain on window load: it uses MSXML2.XMLHTTP to synchronously GET hxxp://104[.]168[.]70[.]178/187/secured_stub[.]ps1?IMAGE[.]PNG to download a PowerShell script, writes it via Scripting.FileSystemObject to a .ps1 in %TEMP% named with 12 random uppercase letters, then uses WScript.Shell.Run to execute it hidden as powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File, deletes the dropped script 3 seconds later and closes the window. Downloading and silently executing a remote script is clearly malicious delivery behavior, and the interface is disguised as "System Uptime" to evade user detection.

## At a glance

| Item | Content |
|:--|:--|
| Family | **HTA PowerShell Downloader** · aliases HTA/PSDownloader, System Uptime HTA stager, secured_stub loader · _uncertain_ |
| Confidence | **Low** |
| Behavior class | downloader · dropper |
| Difficulty | easy |
| First seen | 2026-11-18 10:18:04 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/7006f1de4a2c355cd4255e58df89accb487c2ea8fa61c894ae7f42057da06e51/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Fake system uptime</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Build random temp file</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Sync-download remote script</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Write temp PowerShell</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Bypass execution policy</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `7006f1de4a2c355cd4255e58df89accb487c2ea8fa61c894ae7f42057da06e51` |
| MD5 | _Not recorded_ |
| Size | 7,664 bytes (7.5 KB) |
| Type | other · `hta` |

## Behavior analysis

**7** behaviors in total, each with attached evidence, all statically obtainable.

### 1. Fake system uptime

`T1036` · Confidence **high** · Static

The HTA application declares APPLICATIONNAME="System Uptime" with the same title, CAPTION="no", BORDER="none", SHOWINTASKBAR="no", WINDOWSTATE="minimize", so the window is minimized and absent from the taskbar, disguising the delivery behavior as a system tool.

> **Evidence**: HTA:APPLICATION block, string offsets 42 (APPLICATIONNAME) / 116 (SHOWINTASKBAR) / 140 (WINDOWSTATE) / 205 (title)
> 
> **Source**: `ev-000001`

### 2. Build a random temp file

`T1074` · Confidence **high** · Static

Expands %TEMP% via WScript.Shell.ExpandEnvironmentStrings, then appends 12 random A-Z letters and the .ps1 suffix, generating a hard-to-predict drop path.

> **Evidence**: FileService.tempDir(off=2307), randomName(off=2440), nameLength=12(off=918), alphabet(off=972)
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Synchronous remote script download

`T1105` · Confidence **high** · Static

Creates ActiveXObject("MSXML2.XMLHTTP"), synchronously requests hxxp://104[.]168[.]70[.]178/187/secured_stub[.]ps1?IMAGE[.]PNG via open("GET", url, false), and checks whether the return status is 200, otherwise terminating the flow.

> **Evidence**: Settings.url(off=820), NetworkService.fetch(off=3622: open/send), status!==200 check(off=6207)
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Write temporary PowerShell

`T1074.001` · Confidence **high** · Static

Writes the HTTP response's responseText over the previously generated random .ps1 file in %TEMP% via Scripting.FileSystemObject.CreateTextFile.

> **Evidence**: FileService.write(off=2753: CreateTextFile(path,true) / file.Write), persist stage(off=6344)
> 
> **Source**: `ev-000001` · `ev-000002`

### 5. Start with execution policy bypass

`T1059.001` · Confidence **high** · Static

Starts powershell.exe via WScript.Shell.Run with fixed arguments -ExecutionPolicy Bypass -WindowStyle Hidden -File "<dropped script>", i.e. bypassing the PowerShell execution policy and directly executing the downloaded script.

> **Evidence**: powershellArgs(off=1049), ProcessService.runHidden(off=4265: command assembly / Com.shell.Run(off=4448))
> 
> **Source**: `ev-000001` · `ev-000002`

### 6. Run without a visible window

`T1564.003` · Confidence **high** · Static

Run's window style parameter is 0 and it does not wait for a return; together with -WindowStyle Hidden this leaves the child process with no visible window, and the HTA main window itself is also minimized and hidden.

> **Evidence**: Com.shell.Run(command, 0, false)(off=4448); WINDOWSTATE="minimize"(off=140)
> 
> **Source**: `ev-000001`

### 7. Delayed deletion of the dropped script

`T1070.004` · Confidence **high** · Static

After starting the child process it sets a 3000ms timer that deletes the .ps1 in %TEMP% and calls window.close when it expires; if any stage throws an exception it likewise deletes the dropped file and closes the window, reducing disk residue.

> **Evidence**: cleanupDelay=3000(off=943), schedule-cleanup stage(off=6564: setTimeout/DeleteFile/window.close), failure cleanup(off=7403)
> 
> **Source**: `ev-000001` · `ev-000002`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the above addresses come from static analysis; no successful connection or session was observed under the isolated analysis network, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://104[.]168[.]70[.]178/187/secured_stub[.]ps1?IMAGE[.]PNG` | 80 | download | Static | ⏳ Not observed |

### Host

**Dropped paths**

- `%TEMP%\<12 random uppercase letters>.ps1`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `104.168.70[.]178` | Yes | Static |
| `c2_port` | `80` | Yes | Static |
| `c2_uri` | `/187/secured_stub.ps1?IMAGE[.]PNG` | Yes | Static |
| `download_path` | `%TEMP%\<12 random A-Z letters>.ps1` | Yes | Static |
| `powershell_command` | `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "<script_path>"` | Yes | Static |
| `cleanup_delay_ms` | `3000` | No | Static |
| `encryption_algo` | `none` | No | Static |

## Do not misjudge

:::important
The following conclusions **are easy to misjudge**; keep them in mind when citing this report.

- Must not be called ransomware or an infostealer: this file contains no file encryption, browser credential, keylogging or data exfiltration logic; it merely downloads and executes remote PowerShell.
- Must not assert the content, family or ultimate purpose of the second-stage secured_stub.ps1: this run did not obtain that response body, and payload-related conclusions lack evidentiary support.
- Must not claim persistence was established: the sample does not write Run keys, services, scheduled tasks or the startup folder; the setTimeout is only an in-process 3-second delay cleanup.
- Must not claim the network request was actually sent or received by a server: the sample was not detonated in a real environment, and URL reachability, returned content and C2 liveness are all unverified.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. This run is pure static analysis: this format has no isolated dynamic channel in the current environment, the sample was not executed, and all behavior conclusions come from section-by-section reading of its plaintext script.
2. The second stage hxxp://104[.]168[.]70[.]178/187/secured_stub[.]ps1?IMAGE[.]PNG was not downloaded; the final payload type, subsequent C2 and external connections are unknown, and related fields are left empty and marked pending dynamic confirmation.
3. The C2's recoverability is recorded as static with pending_dynamic_verify=true: the address was only read from the script, with no real request/response session to corroborate its liveness.
4. There is no available vendor naming, digital signature or family characteristic string; the family determination is only a behavior-family-level description, with low confidence.
5. No attribution or reputation check was performed on IP 104.168.70[.]178 (no external network), and its hosting attributes are unknown.

## Evidence index

<details>
<summary>Show 2 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | Extracted 151 ASCII strings with offsets: HTA application declaration, Settings.url(off=820), powershellArgs(off=1049), three ActiveXObjects, stages and cleanup logic; no flag hits, no UTF-16 strings. |
| `ev-000002` | evidence.record | Self-written script verified file integrity (7664 bytes, 0 NULs, no large base64 blocks, only 1 URL/1 IP, ending at </html>) and reconstructed the five-stage delivery pipeline, while recomputing sha256 and md5. |

</details>

---

_The sample in this report is not public; IOCs have been defanged; for security research only._
