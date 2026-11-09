---
title: "Malware Analysis: ScreenConnect (other · msi · 2ec27605)"
published: 2026-11-08
draft: false
description: "Malicious (high confidence): ScreenConnect · rat/backdoor · difficulty medium · Pure static analysis"
tags: ["ScreenConnect", "rat", "backdoor", "MSI"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-08-ScreenConnect-2ec27605"
---

> [!WARNING]
> **Verdict: Malicious** · Family **ScreenConnect** · Confidence **high**
> 
> Aliases: ConnectWise Control, ConnectWise ScreenConnect, ScreenConnect Client
> 
> The installer is an unsigned custom ScreenConnect 25.2.4.9229 client; both the MSI database and system.config are pinned to the external relay pridaworldcity[.]shop:8041, joining with the Access/Guest role; it also registers an auto-start service, safe-mode persistence, an LSA authentication package, a logon credential provider and a URL protocol handler. The embedded PE carries a ConnectWise signature but the certificate has been revoked. No sample was executed; maliciousness rests on direct static evidence from the installer configuration and persistence registrations.

## Overview

| Item | Content |
|:--|:--|
| Family | **ScreenConnect** · aliases ConnectWise Control, ConnectWise ScreenConnect, ScreenConnect Client |
| Confidence | **high** |
| Behavior class | rat · backdoor |
| Difficulty | medium |
| First seen | 2026-11-08 10:54:27 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/2ec27605d8a42fea6ef86e6f8b7fd416c2ef598f5e912333c5c4c0ec14a47314/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Install auto-start remote service</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Write safe-mode persistence key</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1112</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Register LSA auth package</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Register logon credential provider</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1556</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Connect to attacker relay</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `2ec27605d8a42fea6ef86e6f8b7fd416c2ef598f5e912333c5c4c0ec14a47314` |
| MD5 | _not recorded_ |
| Size | 14,385,152 bytes (13.7 MB) |
| Type | other · `msi` |

## Behavior analysis

**9** behaviors in total, each backed by evidence, and all statically available.

### 1. Install auto-start remote-control service

`T1543.003` · Confidence **high** · static

The MSI ServiceInstall table creates a Win32 own-process service named ScreenConnect Client (5776edccd59d9568) with StartType=2 (auto start) and Arguments passing SERVICE_CLIENT_LAUNCH_PARAMETERS directly; ServiceControl starts the service, and ServiceConfig sets the first/second failure action to restart.

> **Evidence**: ServiceInstall row ServiceType=16, StartType=2, Arguments=[SERVICE_CLIENT_LAUNCH_PARAMETERS]; ServiceControl Event=163; ServiceConfig First/SecondFailureActionType=restart
> 
> **Source**: `ev-000023`

### 2. Write safe-mode persistence key

`T1112` · Confidence **high** · static

The Registry table writes the value 'Service' under HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (5776edccd59d9568), so the service is still loaded in safe mode (with networking).

> **Evidence**: Registry table reg3831C0C36D9CE44BC3E6FAE6F161BEA8: Root=2(HKLM), Key=SYSTEM\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME], Value=Service
> 
> **Source**: `ev-000023`

### 3. Register LSA authentication package

`T1547.002` · Confidence **high** · static

The Registry table appends ScreenConnect.WindowsAuthenticationPackage.dll to HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages, registering a custom LSA authentication package.

> **Evidence**: Registry table regB33BA5DF8D6A3B0A5B5032B6CB3E561B: Root=2, Key=SYSTEM\CurrentControlSet\Control\Lsa, Name=Authentication Packages, Value=[~][#ScreenConnect.WindowsAuthenticationPackage.dll]
> 
> **Source**: `ev-000023` · `ev-000002`

### 4. Register logon credential provider

`T1556` · Confidence **high** · static

The Registry table registers CLSID {6FF59A85-BC37-4CD4-1515-049683AF130A}\InprocServer32 pointing to ScreenConnect.WindowsCredentialProvider.dll and adds it to the Credential Providers list, allowing the client to hook the Windows logon UI.

> **Evidence**: Registry table reg86A6324C.../regA0D3A6DD.../regCC376884...; CREDENTIAL_PROVIDER_CLASS_ID={6FF59A85-BC37-4CD4-1515-049683AF130A}
> 
> **Source**: `ev-000023`

### 5. Connect to attacker relay

`T1071` · Confidence **high** · static

Both the ClientLaunchParametersConstraint in system.config and the MSI launch parameters pin h=pridaworldcity[.]shop, p=8041, k=<RSA-2048 public key>; after starting, the client connects to that relay to establish a session channel.

> **Evidence**: ClientLaunchParametersConstraint at system.config offset 410; MSI Property SERVICE_CLIENT_LAUNCH_PARAMETERS; k decodes to PUBLICKEYBLOB / RSA-2048
> 
> **Source**: `ev-000001` · `ev-000023`

### 6. Configure guest access without authentication

`T1219` · Confidence **medium** · static

The same launch parameters contain e=Access&y=Guest, so the client joins the relay with the Access/Guest role; combined with the relay-side guest policy, an operator can establish a remote-control session without holding the target's local credentials.

> **Evidence**: SERVICE_CLIENT_LAUNCH_PARAMETERS = ?e=Access&y=Guest&h=pridaworldcity[.]shop&p=8041&k=...
> 
> **Source**: `ev-000023` · `ev-000001`

### 7. Deliver remote shell components

`T1105` · Confidence **high** · static

The installer deploys ScreenConnect.WindowsBackstageShell.exe and ScreenConnect.WindowsFileManager.exe; ClientService strings include TryRunCommandMessageCommand, FileMessage, TransferFilesMessage, ClipboardBlobMessage and TrySendSas, forming remote command/file/clipboard handling chains.

> **Evidence**: ScreenConnect.WindowsBackstageShell.exe and ScreenConnect.WindowsFileManager.exe in the MSI File table/strings; ClientService strings TryRunCommandMessageCommand, FileMessage, TransferFilesMessage, ClipboardBlobMessage, TrySendSas
> 
> **Source**: `ev-000022` · `ev-000002`

### 8. Register URL protocol to launch client

`T1112` · Confidence **high** · static

The Registry table registers the URL protocol sc-5776edccd59d9568 with the open command "[INSTALLLOCATION]ScreenConnect.WindowsClient.exe" "%1", so a crafted link can launch the client.

> **Evidence**: Registry table regED314AE69CE5D835D523FB365C82C36B: Key=[URL_SCHEME]\shell\open\command, Value="[INSTALLLOCATION]ScreenConnect.WindowsClient.exe" "%1"
> 
> **Source**: `ev-000023`

### 9. Hide tray icon and notifications

`T1564` · Confidence **high** · static

app.config sets AccessShowSystemTrayIcon, ShowSystemTrayIcon, ShowBalloonOnConnect and ShowBalloonOnHide to false, so at runtime it avoids showing the tray icon and connection/hide notifications as much as possible.

> **Evidence**: app.config offsets 1474-1805: Support/Access/ShowSystemTrayIcon=false; ShowBalloonOnConnect/OnHide=false
> 
> **Source**: `ev-000025`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; under the analysis environment's network isolation no successful connection or session was observed, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `pridaworldcity[.]shop` | 8041 | c2 | static | ⏳ not observed |

### Host

**Dropped paths**

- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)`
- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)\ScreenConnect.ClientService.exe`
- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)\ScreenConnect.WindowsClient.exe`
- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)\ScreenConnect.WindowsBackstageShell.exe`
- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)\ScreenConnect.WindowsFileManager.exe`
- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)\ScreenConnect.WindowsCredentialProvider.dll`
- `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)\ScreenConnect.WindowsAuthenticationPackage.dll`

**Registry**

- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (5776edccd59d9568)`
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6FF59A85-BC37-4CD4-1515-049683AF130A}\InprocServer32`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-1515-049683AF130A}`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Classes\sc-5776edccd59d9568\shell\open\command`

**Services**

- `ScreenConnect Client (5776edccd59d9568)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `pridaworldcity[.]shop` | yes | static |
| `c2_port` | `8041` | yes | static |
| `relay_public_key` | `BgIAAACkAABSU0ExAAgAAAEAAQCZH6bqCBgUL5EZDH0N/2gP0+i5KpkjnYNAVpO6XLmjkQnKtg4qcM4qmC7bSuMBbm6Pr8zSf2Vq0SDOHQHhZawgbF1CEmSufaEnE6xpGwemG6F0HgzCNTtdzjUXtJGTDWZej1aWcWaNV2XFFdwmJE0z2jk6g7pmcEyycRaVdI8O0eFPQpqxsQS7LJeTnxfLZtlSdq9C/61Z8xRYH53S+RqlhcFllbiApB0sdWN8ZmZBPr/4EM2pvkM9En20Apqw4gN4csI+ssfoDsKWj2sWt5q5Kd7cB/Ho8wP6HdraGyKZfGgMp3EjpJwnSqWps+6RDDqXu3iOcrf9djtNP7tOO8+/` | yes | static |
| `relay_key_type` | `RSA-2048` | no | static |
| `encryption_algo` | `RSA-2048` | no | static |
| `instance_id` | `5776edccd59d9568` | yes | static |
| `access_mode` | `Access / Guest` | yes | static |
| `service_name` | `ScreenConnect Client (5776edccd59d9568)` | yes | static |
| `install_path` | `%ProgramFiles%\ScreenConnect Client (5776edccd59d9568)` | yes | static |
| `product_version` | `25.2.4.9229` | no | static |
| `url_scheme` | `sc-5776edccd59d9568` | no | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not treat the presence of BackstageShell/FileManager as remote command execution or file theft that already happened: static analysis only sees the components and message-handling code, with no actual session observed.
- Do not classify it as ransomware/wiper: no encryption, deletion, ransom or destructive code was found; this is an abused RMM client.
- Do not claim a C2 session or successful connection to pridaworldcity[.]shop was observed: the sample was not executed, and the C2 comes only from static configuration.
- Do not assert that the embedded ScreenConnect binaries were tampered with by the attacker: they carry a ConnectWise signature (the certificate has been revoked by its issuer), and the main maliciousness comes from the custom configuration, the unsigned MSI and the persistence registrations.
- Do not attribute it to a specific ransomware group or campaign based on the domain alone; infrastructure correlation and campaign evidence are lacking.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. Pure static analysis: the sample was not executed, emulated or detonated in a sandbox, so real network connections, session establishment, command execution or credential reads cannot be confirmed.
2. Installer structure anomaly: after the MSI's Default.cab stream, multiple additional CABs with increasing file counts are appended (14→20 files), and some resources were truncated during extraction (Client.Override.resources claims 323648 bytes but only 32767 bytes were obtained); this does not affect the main configuration and PE component judgments, but completeness is in doubt.
3. The Authenticode certificate status of the embedded PE is 'A certificate was explicitly revoked by its issuer'; the MSI itself is unsigned. The binary's origin or integrity cannot be confirmed from this.
4. The C2/relay configuration was statically extracted and is marked recoverability=static with pending_dynamic_verify=true; no real session or fake-network logs were obtained.
5. pridaworldcity[.]shop was not resolved over the network, so the domain's current ownership, DNS records or whether it is still active cannot be confirmed.
6. It cannot be attributed to a specific actor/ransomware group; ScreenConnect is a legitimate RMM product, and deployment by a legitimate administrator could be normal operations.
7. MSI CustomActions such as FixupServiceArguments were not decompiled one by one, and service parameters may be further corrected at install time; however, the relay configuration in the Property and system.config is sufficient to locate the C2.

## Evidence index

<details>
<summary>Expand 10 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000023` | evidence.record (MSI database parsing) | Property/ServiceInstall/ServiceControl/ServiceConfig/Registry/Directory tables: relay, service, safe mode, LSA, credential provider, URL scheme |
| `ev-000024` | evidence.record (Authenticode) | MSI unsigned; ServiceExe/WindowsClient signer is ConnectWise, certificate revoked |
| `ev-000001` | string extraction | ClientLaunchParametersConstraint in system.config: h=pridaworldcity[.]shop&p=8041&k=... |
| `ev-000002` | string extraction | Command/file/clipboard/credential handling strings in ScreenConnect.ClientService.dll |
| `ev-000022` | string extraction | Component names, ProductCode, Credential Provider GUID and other strings in the MSI |
| `ev-000025` | string extraction | Tray-icon/notification hiding settings in app.config |
| `ref:f1d2c11080` | PE structure parsing | ServiceExeWithService imports service and registry APIs such as CreateServiceW/StartServiceW/RegSetValueExW |
| `ref:1bcf719020` | hashes and fingerprints | ServiceExeWithService SHA256=f048400c23add8c75abe189393d33c873c02c74eeaf43d47b950c8d643763b35; imphash=48809c7ee5e417210ac66dca4db818df |
| `ref:366e8cc684` | CAB extraction | Default.cab extracted 17 files (PE/configuration/resources) |
| `ref:0477e3830c` | hash calculation | SHA256 list of extracted components |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
