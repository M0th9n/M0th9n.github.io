---
title: "Malware Analysis: ScreenConnect (PE · exe · 1fe8c02f)"
published: 2026-11-17
draft: false
description: "Malicious (high confidence): ScreenConnect · rat/backdoor · difficulty medium · dynamic sandbox + static decompilation"
tags: ["ScreenConnect", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-17-ScreenConnect-1fe8c02f"
---

> [!WARNING]
> **Verdict: Malicious** · Family **ScreenConnect** · Confidence **high**
> 
> Aliases: ConnectWise Control, ScreenConnect Client, ScreenConnect RAT
> 
> The sample is a vendor-signed ScreenConnect client installer, but the embedded configuration points the relay to 192.166.82[.]26:8041 and disables the tray icon, the connection balloon and the under-control banner; in the live run it created a LocalSystem auto-start service, registered a logon credential provider and a Safe Mode persistence entry, and the installed client process kept connecting to that relay. This is the typical use of legitimate remote-control software reconfigured into an unauthorized remote-access channel, so it is judged malicious.

## Overview

| Item | Content |
|:--|:--|
| Family | **ScreenConnect** · aliases ConnectWise Control, ScreenConnect Client, ScreenConnect RAT |
| Confidence | **high** |
| Behavior class | rat · backdoor |
| Difficulty | medium |
| First seen | 2026-11-16 15:41:22 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/1fe8c02fd04ac95a923527f34466bd815fc6cb8ac100120f688b1893574b0296/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Drop and install remote-control client</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Create auto-start system service</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Connect to controlled relay server</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Register logon credential provider</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1556</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Write Safe Mode persistence</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1112</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `1fe8c02fd04ac95a923527f34466bd815fc6cb8ac100120f688b1893574b0296` |
| MD5 | _not recorded_ |
| Size | 5,642,768 bytes (5.4 MB) |
| Type | PE · `exe` |

## Behavior analysis

**9** behaviors in total, each backed by evidence; **2** were obtained statically and **7** through dynamic analysis.

### 1. Drop and install remote-control client

`T1219` · Confidence **high** · dynamic

The sample is a WiX Burn bootstrapper embedding 5 .NET components and the ScreenConnect installer; after extraction it calls msiexec /i to install ScreenConnect client 25.2.4.9229 into Program Files (x86).

> **Evidence**: resources FILES/SCREENCONNECT.CORE, SCREENCONNECT.WINDOWS, SCREENCONNECT.WINDOWSINSTALLER; msiexec /i %TEMP%\ScreenConnect\25.2.4.9229\8622b665acfa39f0\ScreenConnect.msi; msiexec creates files in the installation directory
> 
> **Source**: `ev-000051` · `ev-000052` · `ref:5862c80c3d`

### 2. Create auto-start system service

`T1543.003` · Confidence **high** · dynamic

The installer registers a service named ScreenConnect Client (8622b665acfa39f0) through services.exe; it runs as LocalSystem with startup type automatic (Start=2), and its ImagePath carries the relay parameters directly.

> **Evidence**: HKLM\System\CurrentControlSet\Services\ScreenConnect Client (8622b665acfa39f0)\Start = DWORD 0x2; service installation event 7045; process pid 6616
> 
> **Source**: `ev-000052` · `ref:a8259de3a7`

### 3. Connect to controlled relay server

`T1219` · Confidence **high** · dynamic

After installation, ScreenConnect.ClientService.exe repeatedly initiates TCP connections to 192.166.82[.]26:8041 in Guest access mode, carrying the instance identifier and a pre-set session ID, waiting for the operator to connect.

> **Evidence**: network monitor log: ScreenConnect.ClientService.exe (pid 6616) requested TCP 192.166.82[.]26:8041 (multiple times); command line ?e=Access&y=Guest&h=192.166.82[.]26&p=8041&s=50698413-e915-42dd-a257-fcd7670e0944
> 
> **Source**: `ev-000051` · `ev-000052`

### 4. Register logon credential provider

`T1556` · Confidence **high** · dynamic

msiexec registers the Credential Provider CLSID {6FF59A85-BC37-4CD4-2F83-3B812406AD99}, whose InprocServer32 points to ScreenConnect.WindowsCredentialProvider.dll, so the remote-control component can load at the logon screen.

> **Evidence**: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-2F83-3B812406AD99} = ScreenConnect Client (8622b665acfa39f0) Credential Provider; HKCR\CLSID\{6FF59A85-...}\InprocServer32 = ...\ScreenConnect.WindowsCredentialProvider.dll
> 
> **Source**: `ev-000052`

### 5. Write Safe Mode persistence

`T1112` · Confidence **high** · dynamic

The installer writes a service entry with the same name under HKLM\System\CurrentControlSet\Control\SafeBoot\Network, so the service still loads when booting into Safe Mode with Networking.

> **Evidence**: SafeBoot\Network\ScreenConnect Client (8622b665acfa39f0)\(Default) = Service
> 
> **Source**: `ev-000052`

### 6. Register sc protocol for one-click connection

`T1112` · Confidence **high** · dynamic

It creates the HKCR\sc-8622b665acfa39f0 protocol handler with shell\open\command pointing to ScreenConnect.WindowsClient.exe, so an sc-<instance> link can launch the client and connect in one click.

> **Evidence**: HKCR\sc-8622b665acfa39f0\shell\open\command\(Default) = "...\ScreenConnect.WindowsClient.exe"
> 
> **Source**: `ev-000052`

### 7. Hide tray icon and notification banners

`T1564` · Confidence **high** · static

The embedded app.config sets ShowSystemTrayIcon, ShowBalloonOnConnect and Support/Access/ShouldShowUnderControlBanner all to false, and disables the automatic consent prompt when no user process is running, making the remote control hard for the user to notice.

> **Evidence**: app.config at file offset 0x54D3D4: ShowSystemTrayIcon=false; ShowBalloonOnConnect=false; ShouldShowUnderControlBanner=false; AutoConsentIfUserProcessNotRunning=false
> 
> **Source**: `ev-000051`

### 8. Deploy backstage and file-management components

`T1219` · Confidence **high** · dynamic

The installer also drops WindowsBackstageShell.exe, WindowsFileManager.exe and WindowsAuthenticationPackage.dll to disk, providing remote backstage command, file transfer and credential-package registration capabilities.

> **Evidence**: msiexec file creation: Program Files (x86)\ScreenConnect Client (8622b665acfa39f0)\ScreenConnect.WindowsBackstageShell.exe / WindowsFileManager.exe / WindowsAuthenticationPackage.dll
> 
> **Source**: `ev-000052`

### 9. Abuse vendor code signing

`T1553.002` · Confidence **high** · static

The installer carries a valid Authenticode code signature from ConnectWise, LLC (issued by DigiCert), which can leverage vendor reputation to bypass signature-based blocking; the signature only proves the binary's origin and does not mean the configured relay belongs to legitimate operations.

> **Evidence**: Authenticode certificate subject CN=Connectwise, LLC, serial number 0xb9360051bccf66642998998d5ba97ce, valid 2022-08-17 to 2025-08-15
> 
> **Source**: `ev-000051` · `ref:51c2f521d7`


## IOC (defanged)

### Network

:::note
**Connection observed dynamically**: the sample actually initiated TCP connections to this target (multiple retries within a short time).
:::

:::caution
**The real server side remains unverified**: the above connections/handshake were completed with a local controlled simulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `192[.]166[.]82[.]26:8041` | 8041 | c2 | dynamic | observed |

### Host

**Dropped paths**

- `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)\`
- `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)\ScreenConnect.ClientService.exe`
- `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)\ScreenConnect.WindowsClient.exe`
- `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)\ScreenConnect.WindowsCredentialProvider.dll`
- `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)\ScreenConnect.WindowsBackstageShell.exe`
- `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)\ScreenConnect.WindowsFileManager.exe`
- `%TEMP%\ScreenConnect\25.2.4.9229\8622b665acfa39f0\`

**Registry**

- `HKLM\System\CurrentControlSet\Services\ScreenConnect Client (8622b665acfa39f0)`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-2F83-3B812406AD99}`
- `HKCR\CLSID\{6FF59A85-BC37-4CD4-2F83-3B812406AD99}\InprocServer32`
- `HKLM\System\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (8622b665acfa39f0)`
- `HKCR\sc-8622b665acfa39f0\shell\open\command`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{9A597075-529B-9FA0-6F02-0510504CA30D}`

**Services**

- `ScreenConnect Client (8622b665acfa39f0)`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `192[.]166[.]82[.]26` | yes | static |
| `c2_port` | `8041` | yes | static |
| `c2_uri` | `?e=Access&y=Guest` | yes | static |
| `instance_id` | `8622b665acfa39f0` | yes | static |
| `session_id` | `50698413-e915-42dd-a257-fcd7670e0944` | no | static |
| `campaign_id` | `JDOOODD` | no | static |
| `install_path` | `%ProgramFiles(x86)%\ScreenConnect Client (8622b665acfa39f0)` | yes | static |
| `service_name` | `ScreenConnect Client (8622b665acfa39f0)` | yes | static |
| `service_account` | `LocalSystem` | yes | static |
| `ui_stealth` | `ShowSystemTrayIcon=false; ShowBalloonOnConnect=false; SupportShowUnderControlBanner=false; AccessShowUnderControlBanner=false; ShouldShowUnderControlBanner=false; AutoConsentIfUserProcessNotRunning=false` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not classify it as ransomware or a stealer: no file encryption, browser credential export or data-return content was observed; the dynamic phase only captured relay connection attempts.
- Do not treat it as benign just because the binary carries a valid vendor signature: the signature only proves the installer was issued by ConnectWise; the relay address and hidden-UI configuration point to a third-party controller.
- Do not claim that a remote-control session was successfully established: only TCP connection attempts were recorded in the sandbox; no relay authentication or session traffic was captured.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. Only TCP connection attempts to the relay were recorded inside the sandbox, and full authentication/session traffic was not obtained; the C2 is marked as statically recovered and kept pending dynamic confirmation.
2. No plaintext of the installed client configuration file was extracted from disk; the relay, instance and session parameters come from the embedded Burn configuration, the service ImagePath and the process command line.
3. No actual remote operations such as keyboard/mouse control, file transfer or backstage shell were observed, because the relay side did not respond.
4. No scheduled task or Run key persistence was found, and no Defender exclusion writes were observed.
5. The signing certificate is valid until 2025-08-15; certificate chain revocation status was not checked in the offline environment.

## Evidence index

<details>
<summary>Expand 12 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:3f47b0361f` | sample triage | PE triage: 5 sections, .rsrc entropy 7.45, 3 imported DLLs, no packing indicators |
| `ref:5862c80c3d` | PE structure parsing | PE32 GUI, entry RVA 0x14AD, resource directory 5.47MB, signature table 95KB |
| `ref:f74413c1a4` | import table parsing | imports mscoree CorBindToRuntimeEx, KERNEL32 resource/file APIs, OLEAUT32 |
| `ref:d4c7fd0b2e` | string extraction | 20857 strings; hits on WiX/ScreenConnect installer component names |
| `ref:a8259de3a7` | dynamic artifact collection | real dynamic artifact package: telemetry, network monitoring, memory dumps |
| `ev-000051` | evidence.record | static extraction: embedded Burn configuration, hidden app.config entries, signature subject |
| `ev-000052` | evidence.record | dynamic telemetry: service, credential provider, Safe Mode, protocol handler, relay connection |
| `ref:36284d613d` | memory dump | ClientService.exe memory dump |
| `ref:681a976c1d` | memory dump | WindowsClient.exe memory dump |
| `c2_evidence:1fe8c02f` | connection evidence extraction | dynamic network monitoring recorded 4 connection attempts to 192.166.82[.]26:8041; no full session captured |
| `telemetry:1fe8c02f` | dynamic telemetry | dynamic telemetry recorded: 1 new service (ScreenConnect Client (8622b665acfa39f0)); monitoring component 16 registry events; monitoring component 116 process/file events; 1 ETW short-lived process event; 5 system service events; 43 filtered tool/system noise entries |
| `etw:1fe8c02f:7192` | process event monitoring | short-lived process event: 1fe8c02fd04ac95a923527f34466bd815fc6cb8ac100120f688b1893574b0296.exe (pid 7192; MD5=D442BCBCE7DBAB15930408261452A21D,SHA256=1FE8C02FD04AC95A923527F34466BD815FC6CB8AC100120F688B1893574B0296,IMPHASH=9771EE6344923FA220489AB01239BDFD) |

</details>

---

_The sample in this report is not public; IOCs are defanged, for security research only._
