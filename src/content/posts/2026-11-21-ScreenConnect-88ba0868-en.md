---
title: "Malware sample analysis: ScreenConnect (PE · exe · 88ba0868)"
published: 2026-11-21
draft: false
description: "Malicious (high confidence): ScreenConnect · rat/implant · difficulty medium · dynamic sandbox + static decompilation"
tags: ["ScreenConnect", "rat", "implant", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-21-ScreenConnect-88ba0868"
---

> [!WARNING]
> **Verdict: malicious** · family **ScreenConnect** · confidence **high**
> 
> Aliases: ConnectWise Control, ScreenConnect Client, ScreenConnect RAT
> 
> The file is a ScreenConnect (ConnectWise Control) client installer carrying a valid ConnectWise signature; it is legitimate remote-control software itself. However, the launch parameters of its embedded MSI hardcode an unknown self-hosted relay instance-lwmknd-relay[.]screenconnect[.]com:443 and preset the session in Guest/Access mode. The installer registers an autostart service, a URL protocol handler, and a logon credential provider, and hooks an LSA authentication package, giving it full interactive remote-control and persistence capability. This matches the typical form of an attacker delivering ScreenConnect as a remote access trojan, hence malicious.

## At a glance

| Item | Value |
|:--|:--|
| Family | **ScreenConnect** · aliases ConnectWise Control, ScreenConnect Client, ScreenConnect RAT |
| Confidence | **high** |
| Behavior class | rat · implant |
| Difficulty | medium |
| First seen | 2026-11-19 01:07:08 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Embedded encrypted payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Verifies and drops MSI</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Installs a system service</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Registers URL protocol</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1546</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">CLR loaded in sandbox</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
</svg>

## Sample identifiers

| Item | Value |
|:--|:--|
| SHA-256 | `88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2` |
| MD5 | _not recorded_ |
| Size | 12,842,552 bytes (12.2 MB) |
| Type | PE · `exe` |

## Behavior analysis

**10** behaviors in total, each with evidence attached; **8** of them are statically obtainable and **2** were obtained through dynamic analysis.

### 1. Embedded encrypted payload

`T1027.009` · confidence **high** · static

The .rsrc resource section carries 12,758,552 bytes of high-entropy data; the FILES resource contains five PE/managed assemblies (EntryPoint, Resolver, ScreenConnect.Core, ScreenConnect.Windows, ScreenConnect.WindowsInstaller), and the type-10 resource SC_PAYLOAD is a 10,256,668-byte custom container whose first 284 bytes are an RSA1 key/signature header and where a complete OLE compound document (MSI) begins at 0x11C.

> **Evidence**: .rsrc resource table: SC_PAYLOAD rva 0x278878 size 10256668; bytes d0cf11e0a1b11ae1 at offset 0x11C
> 
> **Source**: `ev-000007` · `ev-000060`

### 2. Verifies and drops MSI

`T1140` · confidence **medium** · static

The bootstrapper is a requireAdministrator mixed-mode program that imports mscoree!CorBindToRuntimeEx and FindResourceW/LoadResource/SizeofResource/WriteFile; the EntryPoint assembly contains methods such as PayloadStuffingTechnique, GetOriginalPayload, ReadSizePrefixedBytes, and SignedMsiFileContents, which first read the payload by length prefix, verify the RSA1 signature, and then hand it to the WindowsInstaller component to modify and install to disk.

> **Evidence**: import mscoree!CorBindToRuntimeEx; resource FILES/_EntryPoint strings PayloadStuffingTechnique, ReadSizePrefixedBytes, SignedMsiFileContents
> 
> **Source**: `ev-000060` · `ev-000059`

### 3. Installs a system service

`T1543.003` · confidence **high** · static

The embedded MSI's ServiceInstall table installs a service named "ScreenConnect Client (260a7850ff837e46)" with ServiceType=16, StartType=2(auto), and ErrorControl=1, with the image being ScreenConnect.ClientService.exe under Program Files and launch parameters carrying the relay access string, achieving an autostart resident control channel.

> **Evidence**: MSI ServiceInstall: Name=[SERVICE_NAME], StartType=2, ServiceType=16, Arguments=[SERVICE_CLIENT_LAUNCH_PARAMETERS]
> 
> **Source**: `ev-000060`

### 4. Registers URL protocol

`T1546` · confidence **high** · static

It writes HKCR\sc-260a7850ff837e46 as a URL Protocol and points shell\open\command to "...\ScreenConnect.WindowsClient.exe" "%1", so an external link can directly launch the remote-session client.

> **Evidence**: MSI Registry table: Root=0( HKCR ), Key=[URL_SCHEME], Value=shell\open\command
> 
> **Source**: `ev-000060`

### 5. Hijacks logon credential interface

`T1556` · confidence **high** · static

It registers CLSID {6FF59A85-BC37-4CD4-8385-DCD77FB81F24}\InprocServer32 to point to ScreenConnect.WindowsCredentialProvider.dll and registers it under the Credential Providers key, so the operator can initiate a remote session from the Windows logon/credential screen.

> **Evidence**: MSI Registry table: CLSID\[CREDENTIAL_PROVIDER_CLASS_ID]\InprocServer32, Authentication\Credential Providers\[CREDENTIAL_PROVIDER_CLASS_ID]
> 
> **Source**: `ev-000060`

### 6. Hooks LSA authentication package

`T1556` · confidence **high** · static

It appends ScreenConnect.WindowsAuthenticationPackage.dll to the Authentication Packages multi-string under HKLM\SYSTEM\CurrentControlSet\Control\Lsa, hooking the remote-control component into the local authentication flow.

> **Evidence**: MSI Registry table: Root=2(HKLM), Key=SYSTEM\CurrentControlSet\Control\Lsa, Name=Authentication Packages
> 
> **Source**: `ev-000060`

### 7. Registers safe-mode startup

`T1543.003` · confidence **medium** · static

It creates a key with the same name as the service under HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network, so the remote-control service still loads with the system in safe mode (with networking).

> **Evidence**: MSI Registry table: System\CurrentControlSet\Control\SafeBoot\Network\[SERVICE_NAME], Component=Service
> 
> **Source**: `ev-000060`

### 8. Configures self-hosted relay

`T1219` · confidence **high** · static

The MSI property SERVICE_CLIENT_LAUNCH_PARAMETERS presets "?e=Access&y=Guest&h=instance-lwmknd-relay[.]screenconnect[.]com&p=443&k=<RSA1 guest verification public key>"; after installation the client makes outbound connections to that 443/TCP relay as Guest/Access, with the operator being an unknown self-hosted instance lwmknd.

> **Evidence**: h= and p= fields in MSI Property table SERVICE_CLIENT_LAUNCH_PARAMETERS
> 
> **Source**: `ev-000060`

### 9. CLR loaded in sandbox

`T1204.002` · confidence **medium** · dynamic

When run in the isolated Windows guest, installer process pid 3540 stayed resident after startup; memory forensics dumped the process twice and extracted the 8.7 MB CLR runtime module 6dcd0000.clr.dll, proving that the bootstrapper loaded and executed the embedded managed assembly at runtime.

> **Evidence**: dynamic observation timeline: pid 3540 born, t0/t3 memory dumps; module 6dcd0000.clr.dll extracted
> 
> **Source**: `ev-000061`

### 10. Installation and outbound connection not advanced

`T1219` · confidence **medium** · dynamic

No msiexec child process appeared during the dynamic observation window, and the MSI install log and dropped-file list were empty; the network monitoring log also contained no DNS/TCP records from the sample process, and no relay session was established, indicating that the installation flow did not complete in the non-interactive guest and the C2 channel was not verified at runtime.

> **Evidence**: network monitoring log contains only system-process traffic; msi_files.json is empty; timeline 22:20:01–22:22:00 has no new processes
> 
> **Source**: `ev-000061`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `instance-lwmknd-relay[.]screenconnect[.]com` | 443 | c2 | Static | ⏳ not observed |

### Host

**Dropped paths**

- `%ProgramFiles%\ScreenConnect Client (260a7850ff837e46)\ScreenConnect.ClientService.exe`
- `%ProgramFiles%\ScreenConnect Client (260a7850ff837e46)\ScreenConnect.WindowsClient.exe`
- `%ProgramFiles%\ScreenConnect Client (260a7850ff837e46)\ScreenConnect.WindowsCredentialProvider.dll`
- `%ProgramFiles%\ScreenConnect Client (260a7850ff837e46)\ScreenConnect.WindowsAuthenticationPackage.dll`
- `%ProgramFiles%\ScreenConnect Client (260a7850ff837e46)\system.config`

**Registry**

- `HKLM\SYSTEM\CurrentControlSet\Services\ScreenConnect Client (260a7850ff837e46)`
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\ScreenConnect Client (260a7850ff837e46)`
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages (appends ScreenConnect.WindowsAuthenticationPackage.dll)`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6FF59A85-BC37-4CD4-8385-DCD77FB81F24}`
- `HKCR\CLSID\{6FF59A85-BC37-4CD4-8385-DCD77FB81F24}\InprocServer32 = ...\ScreenConnect.WindowsCredentialProvider.dll`
- `HKCR\sc-260a7850ff837e46 (URL Protocol)`
- `HKCR\sc-260a7850ff837e46\shell\open\command = "...\ScreenConnect.WindowsClient.exe" "%1"`

**Services**

- `ScreenConnect Client (260a7850ff837e46) — StartType=2(auto), ServiceType=16(own process), command line contains relay launch parameters`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `instance-lwmknd-relay[.]screenconnect[.]com` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `c2_uri` | `?e=Access&y=Guest&h=instance-lwmknd-relay[.]screenconnect[.]com&p=443` | Yes | Static |
| `campaign_id` | `instance lwmknd (Client instance ID 260a7850ff837e46)` | No | Static |
| `install_path` | `%ProgramFiles%\ScreenConnect Client (260a7850ff837e46)` | Yes | Static |
| `service_name` | `ScreenConnect Client (260a7850ff837e46)` | Yes | Static |
| `url_scheme` | `sc-260a7850ff837e46` | No | Static |
| `product_code` | `{CAA6CA9E-5E51-E6BD-1D18-B9F00ABF33A7}` | No | Static |
| `credential_provider_clsid` | `{6FF59A85-BC37-4CD4-8385-DCD77FB81F24}` | No | Static |
| `encryption_algo` | `RSA-2048(RSA1) signature/key wrapping; payload is size-prefix wrapped + embedded MSI` | No | Static |

## Do not misjudge

:::important
The conclusions below are **easily misjudged**; take care when citing this report.

- Do not judge it benign just because both the original EXE and the embedded MSI carry a valid ConnectWise signature: the signature only proves vendor origin and does not prove that the self-hosted relay configured by this installer is not attacker-controlled.
- Do not assert that the sample has stolen credentials or logged keystrokes: installing the credential provider and LSA authentication package only represents capability and persistence surface, and no credential exfiltration was observed during the dynamic window.
- Do not classify this sample as ransomware or a worm: no file encryption, shadow-copy deletion, or self-propagation code was found; its behavior surface is remote access and persistence.
:::

## Analysis method and limitations

| Item | Value |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `5e1ff08fb7d66e02acacd97b46cd6bde531b95ca049ccd0e008cfa1c5c35ea29`) |

**Limitations and pending verification**

1. Dynamic channel: the sample stayed resident in the non-interactive guest but spawned no child process, wrote no install log, and made no outbound connection; the artifact-collection stage timed out, the large memory dumps could not be retrieved, and the guest was reverted.
2. C2 has only static evidence: the relay domain and port were extracted from the embedded MSI properties, and network monitoring did not capture any DNS or TLS session for that domain, so the C2 is marked static with pending_dynamic_verify=true.
3. The post-install registry/service state was not verified: the sample did not complete installation, and no runtime diff of the HKLM service entry or LSA authentication package changes was obtained.
4. The payload verification/release details of EntryPoint come from managed-assembly method names and imported APIs by inference; the IL was not decompiled item by item.

## Evidence index

<details>
<summary>Expand 7 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash & fingerprint | sha256=88ba086844d48ef6e5c50cb645ee1cd1d02756f4e530114a00d70f2a876d5ec2, size=12842552 |
| `ev-000002` | scan.imphash | imphash=cd305a01d034d1a4ac62cbed1ae36be7 |
| `ev-000003` | scan.rich | Rich header with 12 toolchain records, richhash=a498773e40e07b36d0f4a2dab1633f09 |
| `ev-000007` | scan.entropy | .rsrc entropy 7.808, size 12,759,040, indicating an embedded compressed/encrypted payload in resources |
| `ev-000059` | String extraction | Extracted 65,469 ASCII and 4,954 UTF-16LE strings, including ScreenConnect resource identifiers |
| `ev-000060` | evidence.record | Self-written parsing: extracted the SC_PAYLOAD embedded MSI, read the relay/service/registry/CLSID configuration, and verified the ConnectWise signature |
| `ev-000061` | evidence.record | Dynamic observation summary: pid 3540 started and loaded CLR, installation did not advance, no outbound connection |

</details>

---

_This report's sample is not public, IOCs are defanged, for security research only._
