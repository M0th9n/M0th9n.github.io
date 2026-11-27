---
title: "Malware Sample Analysis: ScreenConnect (other · msi · a39c509e)"
published: 2026-11-26
draft: false
description: "Malicious (high confidence): ScreenConnect · rat/backdoor · difficulty medium · pure static analysis"
tags: ["ScreenConnect", "rat", "backdoor", "MSI"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-26-ScreenConnect-a39c509e"
---

> [!WARNING]
> **Verdict: Malicious** · Family **ScreenConnect** · Confidence **High**
> 
> Aliases: ConnectWise Control, ScreenConnect RAT, ScreenConnect Client
> 
> This file is a ScreenConnect client installer validly signed by ConnectWise, LLC (not tampered with), but it is preconfigured to run as an auto-start service under LocalSystem and connect as Guest to the fixed relay instance-yu0lau-relay[.]screenconnect[.]com:443, while also registering an LSA authentication package, a credential provider, a SafeBoot-with-Networking persistence key, and the Backstage Shell/File Manager components. The combination of a legitimately signed remote-control component with a fixed relay and high-privilege residency is a typical RMM-abuse remote-control delivery, with persistent remote control, credential interaction and file transfer capabilities.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **ScreenConnect** · aliases ConnectWise Control, ScreenConnect RAT, ScreenConnect Client |
| Confidence | **High** |
| Behavior class | rat · backdoor |
| Difficulty | medium |
| First seen | 2026-11-24 00:44:43 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/a39c509eef5c8de1438b7cbe0933e17113cca572a6f64c6bf8384986353173b3/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Installs auto-start service</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Connects to fixed relay node</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1219</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Attaches LSA auth package</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1556</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Registers credential provider</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1556</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Writes SafeBoot persistence</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1112</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `a39c509eef5c8de1438b7cbe0933e17113cca572a6f64c6bf8384986353173b3` |
| MD5 | _not recorded_ |
| Size | 10,260,480 bytes (9.8 MB) |
| Type | other · `msi` |

## Behavior Analysis

**8** behaviors in total, each backed by evidence, and all obtainable statically.

### 1. Installs an Auto-Start Service

`T1543.003` · Confidence **High** · Static

Installs an auto-start service named ScreenConnect Client (f03edb1838cd757d) under LocalSystem (ServiceType=16, StartType=2, ErrorControl=1; an empty StartName means LocalSystem), with the service launch arguments using the preconfigured remote connection URI directly.

> **Evidence**: MSI ServiceInstall table Name=[SERVICE_NAME], StartType=2, StartName empty; ServiceControl Event=163; Arguments="[SERVICE_CLIENT_LAUNCH_PARAMETERS]"
> 
> **Source**: `ev-000066` · `ev-000065`

### 2. Connects to a Fixed Relay Node

`T1219` · Confidence **High** · Static

The service connects as a guest (?e=Access&y=Guest) to the ScreenConnect relay at instance-yu0lau-relay[.]screenconnect[.]com:443, carrying a fixed 2048-bit RSA public key to establish sessions, letting the operator initiate remote-control connections without confirmation on the target side.

> **Evidence**: MSI Property SERVICE_CLIENT_LAUNCH_PARAMETERS @off≈3596288; ClientLaunchParametersConstraint in the embedded system.config @off=410
> 
> **Source**: `ev-000050` · `ev-000065`

### 3. Attaches an LSA Authentication Package

`T1556` · Confidence **High** · Static

Appends ScreenConnect.WindowsAuthenticationPackage.dll to HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages so the package loads with LSA and can intervene in credential interaction during logon/unlock.

> **Evidence**: Registry table reg27BFB9E3...: Root=2(HKLM), Key=SYSTEM\CurrentControlSet\Control\Lsa, Name=Authentication Packages, Value=[~][#ScreenConnect.WindowsAuthenticationPackage.dll]
> 
> **Source**: `ev-000066` · `ev-000065`

### 4. Registers a Credential Provider

`T1556` · Confidence **High** · Static

Registers COM CLSID {6FF59A85-BC37-4CD4-410E-264908C38164}, with InprocServer32 pointing to ScreenConnect.WindowsCredentialProvider.dll, and writes the Credential Providers key (both x64 and ARM64 sets), providing a custom logon and credential-interaction UI for remote sessions.

> **Evidence**: Registry reg484EC3... InprocServer32=[#ScreenConnect.WindowsCredentialProvider.dll]; reg20D6DF... Credential Providers\{CLSID}; embedded DLL strings include ProcessCredentialProviderMessage/EnsureStoredCredentialsState
> 
> **Source**: `ev-000066` · `ev-000065` · `ev-000023`

### 5. Writes SafeBoot Persistence

`T1112` · Confidence **High** · Static

Creates a key named after the service under HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network with value Service, so the service still starts in Safe Mode with Networking, strengthening persistence.

> **Evidence**: Registry table reg3831C0C3...: Key=System\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME], Value=Service
> 
> **Source**: `ev-000066` · `ev-000065`

### 6. Deploys the Remote Shell Component

`T1059` · Confidence **Medium** · Static

Installs ScreenConnect.WindowsBackstageShell.exe (Backstage background shell); this official component provides an interactive command-execution channel for the remote operator.

> **Evidence**: File/Component table BackstageShellFiles -> ScreenConnect.WindowsBackstageShell.exe (73272 bytes, sha256 853ad96a...); MSI strings include the BackstageShellFiles component name
> 
> **Source**: `ev-000065` · `ev-000067`

### 7. Deploys the File Manager

`T1105` · Confidence **Medium** · Static

Installs ScreenConnect.WindowsFileManager.exe, giving the remote operator file browsing, upload/download and remote execution entry points.

> **Evidence**: File/Component table FileManagerFiles -> ScreenConnect.WindowsFileManager.exe (93752 bytes, sha256 022f9645...); MSI strings include the FileManagerFiles component name
> 
> **Source**: `ev-000065` · `ev-000067`

### 8. Automatic Service Restart on Failure

`T1543.003` · Confidence **High** · Static

Configures the service failure recovery actions as restart/restart/none via ServiceConfig; after the service process is terminated, the system automatically restarts it to maintain residency.

> **Evidence**: ServiceConfig table: FirstFailureActionType=restart, SecondFailureActionType=restart, ThirdFailureActionType=none
> 
> **Source**: `ev-000066` · `ev-000065`


## IOCs (Defanged)

### Network

:::caution
**Pending dynamic verification**: the above addresses were obtained by static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `instance-yu0lau-relay[.]screenconnect[.]com` | 443 | c2 | Static | ⏳ Not observed |

### Host

**Drop paths**

- `%ProgramFiles%\ScreenConnect Client (f03edb1838cd757d)\`
- `%ProgramFiles%\ScreenConnect Client (f03edb1838cd757d)\ScreenConnect.ClientService.exe`
- `%ProgramFiles%\ScreenConnect Client (f03edb1838cd757d)\ScreenConnect.WindowsClient.exe`
- `%ProgramFiles%\ScreenConnect Client (f03edb1838cd757d)\ScreenConnect.WindowsCredentialProvider.dll`
- `%ProgramFiles%\ScreenConnect Client (f03edb1838cd757d)\ScreenConnect.WindowsAuthenticationPackage.dll`

**Registry**

- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa (Authentication Packages += ScreenConnect.WindowsAuthenticationPackage.dll)`
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (f03edb1838cd757d)`
- `HKCR\CLSID\{6FF59A85-BC37-4CD4-410E-264908C38164}\InprocServer32`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-410E-264908C38164}`
- `HKCR\sc-f03edb1838cd757d`

**Service**

- `ScreenConnect Client (f03edb1838cd757d)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `instance-yu0lau-relay[.]screenconnect[.]com` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `c2_uri` | `?e=Access&y=Guest&h=instance-yu0lau-relay[.]screenconnect[.]com&p=443&k=<RSA-2048 public key>&t=WA` | Yes | Static |
| `service_name` | `ScreenConnect Client (f03edb1838cd757d)` | Yes | Static |
| `install_path` | `%ProgramFiles%\ScreenConnect Client (f03edb1838cd757d)` | Yes | Static |
| `service_account` | `LocalSystem` | No | Static |
| `service_start_type` | `auto` | Yes | Static |
| `encryption_algo` | `RSA-2048 (CALG_RSA_SIGN; client public key carried in launch URI)` | No | Static |
| `instance_id` | `instance-yu0lau` | No | Static |
| `client_tag` | `f03edb1838cd757d` | No | Static |
| `product_version` | `26.7.9.9792` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please take note when citing this report.

- Do not conclude from the embedded RSA public key or k= parameter alone that the sample uses custom encryption/credential-stealing modules; the key is the standard session public key the ScreenConnect client uses to connect to the relay.
- Do not judge it fully benign just because the MSI and embedded PEs carry a valid ConnectWise signature; the risk comes from the legitimately signed remote-control component being configured to connect to a fixed relay and reside with high privileges.
- Do not claim detonation on a real host or observation of outbound connections/session establishment; this was pure static analysis, and C2 reachability was not verified.
- Do not treat BackstageShell.exe / FileManager.exe as independent malicious payloads; they are official ScreenConnect feature components.
- Do not assert that the instance-yu0lau relay necessarily belongs to the attacker; its ownership needs network-side or tenant-side intelligence confirmation.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and Pending Verification**

1. This is pure static analysis (no isolated dynamic channel exists for this format); the install was not executed, and relay connectivity or session establishment was not verified; C2 entries are marked static with pending_dynamic_verify=true.
2. Service creation, registry writes, LSA authentication package loading and SafeBoot persistence all come from the install logic declared in MSI tables; their actual effects were not observed on a real host.
3. The ownership and purpose of the instance-yu0lau relay cannot be confirmed statically and need network-side/tenant-side intelligence support.
4. One LZX-compressed folder in the CAB (ServiceExeWithService / ServiceExeWithoutService, 95288 bytes each) could not be fully extracted; the similar component ScreenConnect.ClientService.dll was extracted and analyzed via signature and strings.
5. The MSI compound document has 2504 sectors of 4096 bytes, of which only 914 are referenced by streams; offsets 3600384 and 5816320 each hold an unreferenced old Default.cab copy, and old ProductCodes remain in _StringData — build residue, not used as evidence of malicious functionality.
6. No runtime behaviors such as C2 sessions, registry/service drops or process injection were obtained; the dynamic channel was not enabled (reproduced=false).

## Evidence Index

<details>
<summary>Expand 7 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000050` | String extraction | Extracted ClientLaunchParametersConstraint from the embedded system.config, containing instance-yu0lau-relay[.]screenconnect[.]com:443 and RSA public key parameters (off=410) |
| `ev-000065` | String extraction | MSI long-string extraction hit the complete Property/Registry/ServiceInstall/File data blocks, including SERVICE_CLIENT_LAUNCH_PARAMETERS, Lsa\Authentication Packages, SafeBoot\Network, Credential Providers, the service name and 18 embedded filenames (off≈3596288) |
| `ev-000066` | evidence.record | Read-only parsing of MSI database tables: full row values for Property/CustomAction/ServiceInstall/ServiceControl/ServiceConfig/Registry/Media/File/Component/Feature/InstallExecuteSequence/LaunchCondition/Upgrade |
| `ev-000067` | evidence.record | Extracted the embedded Default.cab and unpacked 18 files, computing sha256; verified Authenticode signatures of the MSI and main PEs (CN=ConnectWise, LLC, Valid); parsed the RSA-2048 public key; tallied CFB sector usage and unreferenced cab copies |
| `ev-000023` | String extraction | ScreenConnect.ClientService.dll strings: method names such as ProcessCredentialProviderMessage, EnsureStoredCredentialsState, MaintainEphemeralUsers, TryStart/CreateProcessAsUser, supporting credential provider and service-side process management capability |
| `ev-000049` | String extraction | ScreenConnect.WindowsClient.exe strings: method names related to screen capture/DXGI, clipboard, remote sessions and the control panel, supporting its remote-control client nature |
| `ev-000045` | String extraction | MSI summary string statistics (ascii 780 / utf16le 350), showing the WiX Toolset 3.11 build marker and ScreenConnect.InstallerActions custom action names |

</details>

---

_The sample in this report is not public; IOCs are defanged and provided for security research only._
