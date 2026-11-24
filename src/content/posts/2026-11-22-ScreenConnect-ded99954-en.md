---
title: "Malware Analysis: ScreenConnect (other · msi · ded99954)"
published: 2026-11-22
draft: false
description: "Malicious (high confidence): ScreenConnect · rat/backdoor · medium difficulty · static analysis only"
tags: ["ScreenConnect", "rat", "backdoor", "MSI"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-22-ScreenConnect-ded99954"
---

> [!WARNING]
> **Verdict: Malicious** · Family **ScreenConnect** · Confidence **High**
> 
> Aliases: ConnectWise Control, ConnectWise ScreenConnect, ScreenConnect Client, ScreenConnect RAT
> 
> The MSI is built with the official ScreenConnect toolchain and uses ConnectWise-signed components, but its service launch parameters are customized to ?h=188.253.28[.]5&p=8041, and app.config disables the tray icon, connection notification and controlled-session banner; installation also registers a boot-start service, an LSA authentication package, a credential provider, a SafeBoot network entry and a custom URL scheme. This combination matches the weaponization of a legitimate remote-control tool into a covert backdoor, so it is assessed as a malicious RAT/backdoor.

## Overview

| Item | Content |
|:--|:--|
| Family | **ScreenConnect** · aliases ConnectWise Control, ConnectWise ScreenConnect, ScreenConnect Client, ScreenConnect RAT |
| Confidence | **High** |
| Behavior classes | rat · backdoor |
| Difficulty | medium |
| First seen | 2026-11-20 01:57:28 |
| Analysis method | Static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ded99954032a139212f19cc66fd170ea5266e5301b95abf4a4139a57f51a88ba/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Register autostart RAT service</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Connect to relay host</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Disable tray and notices</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.008</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Register LSA auth package</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Register credential provider</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1556</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `ded99954032a139212f19cc66fd170ea5266e5301b95abf4a4139a57f51a88ba` |
| MD5 | _Not recorded_ |
| Size | 13,471,744 bytes (12.8 MB) |
| Type | other · `msi` |

## Behavior Analysis

**8** behaviors in total, each backed by evidence, and all are static.

### 1. Register Autostart RAT Service

`T1543.003` · Confidence **High** · Static

During installation it creates a Windows service named 'ScreenConnect Client (9101ab61b8839c58)' with display name 'Remote Control' and launch parameters ?h=188.253.28[.]5&p=8041, and configures automatic restart on failure for boot autostart and persistence.

> **Evidence**: MSI ServiceInstall/ServiceControl/ServiceConfig tables; ServiceExeWithService -> ScreenConnect.ClientService.exe
> 
> **Source**: `ev-000037` · `ev-000029`

### 2. Connect to Relay Host

`T1071.001` · Confidence **High** · Static

The service actively connects to 188.253.28[.]5:8041 using the '?h=188.253.28[.]5&p=8041' parameters and negotiates the remote-control channel using the RSA1 session envelope in the k parameter.

> **Evidence**: system.config ClientLaunchParametersConstraint; MSI Property SERVICE_CLIENT_LAUNCH_PARAMETERS
> 
> **Source**: `ev-000039` · `ev-000037`

### 3. Disable Tray and Connection Notifications

`T1564.008` · Confidence **High** · Static

app.config sets ShowSystemTrayIcon, ShowConnectedNotification, SupportShowUnderControlBanner and AccessShowUnderControlBanner all to false, hiding visible prompts of the remote-control session.

> **Evidence**: ScreenConnect.SystemSettings settings in extracted/app.config all have value=false
> 
> **Source**: `ev-000039`

### 4. Register LSA Authentication Package

`T1547.002` · Confidence **High** · Static

Appends ScreenConnect.WindowsAuthenticationPackage.dll to Authentication Packages under HKLM\SYSTEM\CurrentControlSet\Control\Lsa, extending the system logon authentication flow.

> **Evidence**: Registry table regB33BA5DF... Root=2(HKLM) Key='SYSTEM\CurrentControlSet\Control\Lsa' Name='Authentication Packages'
> 
> **Source**: `ev-000037` · `ev-000038`

### 5. Register Credential Provider

`T1556` · Confidence **High** · Static

Registers {6FF59A85-BC37-4CD4-D1CE-1A3BA4B0092C} under HKLM Credential Providers and HKCR\CLSID, with InprocServer32 pointing to ScreenConnect.WindowsCredentialProvider.dll, allowing it to participate in Windows logon credential handling.

> **Evidence**: Registry table regCC376884...(Credential Providers) / regA0D3A6DD...(CLSID InprocServer32)
> 
> **Source**: `ev-000037`

### 6. Register Custom URL Protocol

`T1112` · Confidence **High** · Static

Registers the HKCR\sc-9101ab61b8839c58 protocol with shell\open\command pointing to ScreenConnect.WindowsClient.exe "%1", allowing the client to be launched via a link or parameter.

> **Evidence**: Registry table reg239C9CCD/regED314AE6, Root=0(HKCR), Key='[URL_SCHEME]\shell\open\command'
> 
> **Source**: `ev-000037`

### 7. Write SafeBoot Network Entry

`T1112` · Confidence **High** · Static

Writes HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\<service name> = 'Service', allowing the RAT service to start even in Safe Mode with Networking.

> **Evidence**: Registry table reg3831C0C3... Root=2(HKLM) Key='System\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME]'
> 
> **Source**: `ev-000037`

### 8. Drop Remote-Control Component Suite

`T1219` · Confidence **High** · Static

Extracts from the embedded CAB and installs 20 ScreenConnect components (WindowsClient, ClientService, BackstageShell, FileManager, CredentialProvider, AuthenticationPackage etc.), providing interactive desktop control, background command execution and file transfer.

> **Evidence**: MSI File table 20 entries; Default.cab unpacks to same-named files; WindowsClient.exe sha256=da7697...; ServiceExeWithService sha256=8c7e1f...
> 
> **Source**: `ev-000038` · `ev-000023` · `ev-000029`


## IOC (Defanged)

### Network

:::caution
**Pending dynamic verification**: The addresses above were obtained statically; no successful connection or session was observed under the isolated analysis network, so the real C2 responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `188.253.28[.]5` | 8041 | c2 | static | ⏳ Not observed |

### Host

**Drop paths**

- `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)\ScreenConnect.ClientService.exe`
- `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)\ScreenConnect.WindowsClient.exe`
- `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)\ScreenConnect.WindowsBackstageShell.exe`
- `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)\ScreenConnect.WindowsFileManager.exe`
- `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)\ScreenConnect.WindowsCredentialProvider.dll`
- `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)\ScreenConnect.WindowsAuthenticationPackage.dll`

**Registry**

- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (9101ab61b8839c58) = Service`
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages += ScreenConnect.WindowsAuthenticationPackage.dll`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-D1CE-1A3BA4B0092C}`
- `HKCR\CLSID\{6FF59A85-BC37-4CD4-D1CE-1A3BA4B0092C}\InprocServer32 = ScreenConnect.WindowsCredentialProvider.dll`
- `HKCR\sc-9101ab61b8839c58\shell\open\command = "ScreenConnect.WindowsClient.exe" "%1"`

**Services**

- `ScreenConnect Client (9101ab61b8839c58)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `188.253.28[.]5` | Yes | static |
| `c2_port` | `8041` | Yes | static |
| `service_name` | `ScreenConnect Client (9101ab61b8839c58)` | Yes | static |
| `service_display_name` | `Remote Control` | No | static |
| `install_path` | `%ProgramFiles%\ScreenConnect Client (9101ab61b8839c58)` | Yes | static |
| `url_scheme` | `sc-9101ab61b8839c58` | No | static |
| `credential_provider_clsid` | `{6FF59A85-BC37-4CD4-D1CE-1A3BA4B0092C}` | No | static |
| `product_version` | `25.3.4.9288` | No | static |
| `c2_session_envelope` | `k=BgIAAACkAABSU0Ex... (276-byte RSA1 session envelope, server RSA public-key wrap)` | No | static |
| `encryption_algo` | `RSA session envelope (tag 'RSA1')` | No | static |
| `stealth_ui` | `ShowSystemTrayIcon=false; ShowConnectedNotification=false; SupportShowUnderControlBanner=false` | No | static |

## Common Misinterpretations

:::important
The following conclusions are **easy to misinterpret**; keep them in mind when citing this report.

- Do not judge it clean because the components are legitimately signed by ConnectWise: the signature only shows the components come from a legitimate source, while the installer has been reconfigured into a covert RAT connecting to 188.253.28[.]5:8041.
- No evidence of ransomware encryption, bulk browser-credential theft or worm-like lateral spreading was found; it should not be classified as ransomware, stealer or botnet.
- This MSI is a complete installer, not a dropper: the embedded CustomActionLibrary/WixCA are ScreenConnect/WiX installer custom-action DLLs, not an independent next-stage parent, and should not be described as a dropper delivery chain.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Static analysis only |
| Unpacked | Yes |

**Limitations and pending verification**

1. Static analysis only: the MSI and its components were not executed; C2 and behavior come from installation tables, configuration files and signature/hash evidence, recoverability=static, pending_dynamic_verify=true.
2. The k parameter is a 276-byte session envelope wrapped with the server RSA public key (tag 'RSA1'); without the private key the relay-side session identifier or active session cannot be decrypted; only the relay address and port can be obtained from the plaintext h/p.
3. This format did not enable the isolated dynamic channel, so no actual outbound connection, screen control, credential capture, service start or LSA/credential-provider effect was observed.
4. In offline Authenticode verification some signing chains return unknown status due to missing online revocation/timestamp information; unsigned managed DLLs are normal for this distribution and do not mean the files were tampered with.
5. The real intent of the owner of 188.253.28[.]5:8041 cannot be confirmed; it is listed as a RAT relay solely based on this installer's configuration.

## Evidence Index

<details>
<summary>Expand 7 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000022` | String extraction | MSI string extraction, hits ScreenConnect.* component file names and installation identifiers |
| `ev-000023` | Sample triage | ScreenConnect.WindowsClient.exe hash/sections/packing score |
| `ev-000029` | Sample triage | ServiceExeWithService hash/imports/Rich header |
| `ev-000037` | evidence.record | MSI database table export: C2 launch parameters, services, registry, install path, product information |
| `ev-000038` | evidence.record | MSI embedded CAB unpacking with 20 component hashes and Authenticode signing status |
| `ev-000039` | evidence.record | system.config/app.config connection parameters and stealth switches, k session envelope structure |
| `ev-000040` | evidence.record | Embedded custom-action DLL version resources: ScreenConnect.InstallerActions and WiXCA |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
