---
title: "Malware Analysis: ScreenConnect (PE · exe · 079fe697)"
published: 2026-11-05
draft: false
description: "Malicious (high confidence): ScreenConnect · rat/backdoor · difficulty easy · dynamic sandbox + static decompilation"
tags: ["ScreenConnect", "rat", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-05-ScreenConnect-079fe697"
---

> [!WARNING]
> **Verdict: Malicious** · Family **ScreenConnect** · Confidence **high**
> 
> Aliases: ConnectWise Control, ConnectWise ScreenConnect, ScreenConnect Client
> 
> The sample is a ScreenConnect (ConnectWise Control) client installer carrying a valid ConnectWise digital signature, but the session parameters of the embedded MSI are hardcoded to an external operator instance, instance-kiscll; it installs an auto-start service running as LocalSystem and registers a credential provider and an LSA authentication package, forming a fully featured remote-control implant aimed at an unknown third party. The signature only proves the build origin, not the instance ownership or authorization of use.

## Overview

| Item | Content |
|:--|:--|
| Family | **ScreenConnect** · aliases ConnectWise Control, ConnectWise ScreenConnect, ScreenConnect Client |
| Confidence | **high** |
| Behavior class | rat · backdoor |
| Difficulty | easy |
| First seen | 2026-11-02 16:07:06 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/079fe697069f4fa94a73754d356e3084053427fed92cea0f2c7e2ea4298c10d8/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Embedded relay config</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Install auto-start service</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Logon-screen RAT</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1556</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Hook LSA auth package</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1547.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Drop multi-component RAT</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `079fe697069f4fa94a73754d356e3084053427fed92cea0f2c7e2ea4298c10d8` |
| MD5 | _not recorded_ |
| Size | 12,842,552 bytes (12.2 MB) |
| Type | PE · `exe` |

## Behavior analysis

**8** behaviors in total, each backed by evidence, and all are statically recoverable.

### 1. Embedded relay configuration

`T1071.001` · Confidence **high** · static

The embedded MSI's SERVICE_CLIENT_LAUNCH_PARAMETERS property hardcodes e=Access&y=Guest session parameters, the relay host h=instance-kiscll-relay[.]screenconnect[.]com, port p=443 and the server RSA public key k; after installation the service uses these parameters verbatim to connect back.

> **Evidence**: MSI Property table SERVICE_CLIENT_LAUNCH_PARAMETERS; SC_PAYLOAD offset 2574456 resource #10
> 
> **Source**: `ev-000060`

### 2. Install auto-start service

`T1543.003` · Confidence **high** · static

The MSI ServiceInstall table creates a service named "ScreenConnect Client (10dfa41e812005bd)" with ServiceType=16 (own process), StartType=2 (auto), DisplayName="Remote Control" and the relay parameters above as its command line, so it stays resident as a service over the long term.

> **Evidence**: msilib ServiceInstall row: StartType=2, ServiceType=16, Arguments=[SERVICE_CLIENT_LAUNCH_PARAMETERS]
> 
> **Source**: `ev-000060`

### 3. Logon-screen remote control

`T1556` · Confidence **high** · static

The MSI Registry table points the InprocServer32 of CLSID {6FF59A85-BC37-4CD4-4997-70E0A190F289} to ScreenConnect.WindowsCredentialProvider.dll and registers it in the Credential Providers list, so the remote-control component can be loaded at the Windows logon screen, covering lock-screen and logon scenarios.

> **Evidence**: Registry table reg484EC307914B152DDA21A85E972FFE8A: CLSID\...\InprocServer32 -> WindowCredentialProvider.dll
> 
> **Source**: `ev-000060` · `ev-000045`

### 4. Hook LSA authentication package

`T1547.005` · Confidence **high** · static

The MSI Registry table appends ScreenConnect.WindowsAuthenticationPackage.dll to the Authentication Packages value under HKLM\SYSTEM\CurrentControlSet\Control\Lsa, injecting a custom authentication package into the logon authentication flow.

> **Evidence**: Registry table reg27BFB9E3BAD4AA096A74DD0F76D17ED5: SYSTEM\CurrentControlSet\Control\Lsa Authentication Packages
> 
> **Source**: `ev-000060` · `ev-000044`

### 5. Drop multi-component RAT

`T1219` · Confidence **high** · static

The MSI File table drops 18 components (ClientService, WindowsClient, BackstageShell, FileManager, the Core/Client/Windows managed libraries, the credential provider and the authentication package) into the install directory, forming a complete remote-desktop, backstage shell, file-management and logon-session control capability.

> **Evidence**: 18 rows in the MSI File table; strings ScreenConnect.WindowsBackstageShell.exe / ScreenConnect.WindowsFileManager.exe / ScreenConnect.ClientService.exe
> 
> **Source**: `ev-000060` · `ref:1dda566b1c`

### 6. Register URL scheme

`T1546` · Confidence **high** · static

The MSI Registry table creates HKCR\sc-10dfa41e812005bd and shell\open\command pointing to ScreenConnect.WindowsClient.exe "%1", so external links can launch the client directly and pass session parameters.

> **Evidence**: Registry table regED314AE69CE5D835D523FB365C82C36B: [URL_SCHEME]\shell\open\command
> 
> **Source**: `ev-000060`

### 7. Persist in safe mode

`T1112` · Confidence **high** · static

The MSI Registry table writes "Service" under HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME], so the service is still loaded in safe mode (with networking), making removal harder.

> **Evidence**: Registry table reg3831C0C36D9CE44BC3E6FAE6F161BEA8: SafeBoot\Network\[SERVICE_NAME] = Service
> 
> **Source**: `ev-000060`

### 8. Connect back to relay on 443

`T1071.001` · Confidence **medium** · static

After installation the service opens an outbound session to instance-kiscll-relay[.]screenconnect[.]com:443 as configured (ScreenConnect carries relay traffic over HTTP(S)) and waits for the operator to connect and issue control commands.

> **Evidence**: config h=...&p=443; this dynamic run did not observe the connection (installation did not complete)
> 
> **Source**: `ev-000060`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the isolated analysis network, so the real C2 responses and payloads remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://instance-kiscll-relay[.]screenconnect[.]com` | 443 | c2 | static | ⏳ not observed |

### Host

**Dropped paths**

- `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)\ScreenConnect.ClientService.exe`
- `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)\ScreenConnect.WindowsClient.exe`
- `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)\ScreenConnect.WindowsBackstageShell.exe`
- `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)\ScreenConnect.WindowsFileManager.exe`
- `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)\ScreenConnect.WindowsCredentialProvider.dll`
- `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)\ScreenConnect.WindowsAuthenticationPackage.dll`

**Registry**

- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa (Authentication Packages appends ScreenConnect.WindowsAuthenticationPackage.dll)`
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (10dfa41e812005bd)`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-4997-70E0A190F289}`
- `HKCR\CLSID\{6FF59A85-BC37-4CD4-4997-70E0A190F289}\InprocServer32`
- `HKCR\sc-10dfa41e812005bd\shell\open\command`

**Services**

- `ScreenConnect Client (10dfa41e812005bd)`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `instance-kiscll-relay[.]screenconnect[.]com` | yes | static |
| `c2_port` | `443` | yes | static |
| `instance_name` | `kiscll` | yes | static |
| `instance_id` | `10dfa41e812005bd` | yes | static |
| `service_launch_parameters` | `?e=Access&y=Guest&h=instance-kiscll-relay[.]screenconnect[.]com&p=443&k=BgIAAACkAABSU0ExAAgAAAEAAQABkytvcpYvQRJ%2b3DTPa0GCVP%2fQzmrHhAs%2blgU3UTQC1n3umKCmw%2f1omAeRte8Jhiman0dSse1p6tJrYzgcY7bvHOXisKjGACElGZD02daWxt%2bkeiietMYVLtLlL%2fp69oN%2fUnkyY3PQhCF%2f6F5xeC91C%2b5WMCrkxzZUIiRIjgdoq8gRJ%2f%2bHIaBJ9GI7kGZPwrbh%2bzIHb5sEwNHWmI%2b26BJCUGT3z244vGsxVdNnaom3UC4EXssITfPcMhicRNZvHsDJnXKElEM%2f%2bzAY1%2fJPqpPt%2fIXYOxjUxWkbJL%2fJe0PZlJGhIk%2b9gpOM1hq1xjfeHlJygMy%2bVTYO61QmFE8NG7XL` | yes | static |
| `encryption_algo` | `RSA-2048 (CAPI PUBLICKEYBLOB "RSA1", aiKeyAlg=CALG_RSA_KEYX) used for relay identity verification` | no | static |
| `service_name` | `ScreenConnect Client (10dfa41e812005bd)` | yes | static |
| `install_path` | `%ProgramFiles%\ScreenConnect Client (10dfa41e812005bd)` | yes | static |
| `url_scheme` | `sc-10dfa41e812005bd` | no | static |
| `product_version` | `26.7.6.9783` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not classify it as ransomware or a wiper: no file encryption, shadow-copy deletion or disk-destruction logic was found in the sample or the embedded MSI.
- Do not claim it has autonomous lateral-spread capability: the sample itself only installs and runs the remote-control client; lateral movement requires manual action by the remote operator and cannot be attributed to the binary.
- Do not treat the valid ConnectWise digital signature as proof of safety or benignity: the signature only proves the vendor built it; instance ownership and purpose cannot be proven by the signature.
- Do not assert the C2 went online successfully without traffic evidence: this dynamic run did not complete the installation and no network request to the relay was observed.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | yes (stage2 `ac0c4b51f6d244e1dc70890c9490dabea4973597a89bf7269ca8d4e32e584ad4`) |

**Limitations and pending verification**

1. This real dynamic run only saw the outer installer process staying resident and the MSI installation did not complete, so service creation, file drops, registry writes and the callback are all inferred from the static MSI tables and configuration (recoverability=static); the C2 connection is marked pending_dynamic_verify.
2. The relay domain is ConnectWise cloud-managed relay infrastructure, and the identity of the operator of instance kiscll cannot be confirmed from the sample itself; passive DNS/certificate data and network logs for the domain are needed for further attribution.
3. The installed ScreenConnect.ClientService.exe was not obtained for running, so whether the runtime configuration matches the MSI-embedded parameters could not be checked.
4. The sample uses ScreenConnect's normal installation mechanism; in an environment with elevation and interaction available, its behavior could be more complete than what was observed here.

## Evidence index

<details>
<summary>Expand 8 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hashing and fingerprinting | sha256/md5/sha1 and file size 12842552 bytes |
| `ev-000002` | scan.imphash | imphash=cd305a01d034d1a4ac62cbed1ae36be7, imports only mscoree/KERNEL32/OLEAUT32 (.NET host) |
| `ev-000007` | scan.entropy | .rsrc entropy 7.808 (12.7MB), matching a large embedded packed resource |
| `ev-000039` | string extraction | hits on WiX/installer strings, the ScreenConnect component list and GUIDs |
| `ev-000044` | string extraction | hits on AuthenticationPackageFilesX86_64 and WindowsAuthenticationPackage.dll |
| `ev-000045` | string extraction | hits on CredentialProviderFilesX86_64 and WindowsCredentialProvider.dll |
| `ev-000052` | string extraction | hits on the MSI config GUID and URL_SCHEME/service parameter context |
| `ev-000060` | scripted forensics | parsed SC_PAYLOAD and all key tables of the embedded MSI, extracted the relay, service, registry and component lists; verified the outer Authenticode signature is valid |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
