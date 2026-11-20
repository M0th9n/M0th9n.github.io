---
title: "Malware sample analysis: Action1 Agent (other · msi · c5f41fff)"
published: 2026-11-19
draft: false
description: "Gray/PUA (high confidence): Action1 Agent · implant · difficulty medium · pure static analysis"
tags: ["Action1 Agent", "implant", "MSI"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-19-Action1-Agent-c5f41fff"
---

> [!CAUTION]
> **Verdict: gray/PUA** · Family **Action1 Agent** · Confidence **high**
> 
> Aliases: Action1, Action1 RMM, A1Agent
> 
> The sample is a remote management (RMM) agent installer officially issued by Action1 Corporation with a valid digital signature: the MSI product information, the version information of the embedded action1_agent.exe and the signing subject are consistent, and no tampering, credential theft, ransomware or destructive code was found. It installs as a LocalSystem auto-start service and calls back to the vendor cloud, with remote command execution, remote desktop, software distribution and reboot/shutdown capabilities; it is a dual-use remote management tool that can be abused, classified as riskware/PUA.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Action1 Agent** · aliases Action1, Action1 RMM, A1Agent |
| Confidence | **High** |
| Behavior class | implant |
| Difficulty | medium |
| First seen | 2026-11-17 20:00:06 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/c5f41fff34f1e18dad19bff448bdb7952d7886908c292fe570b5695c5e91850b/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Install auto-start service</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Write tenant key config</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1112</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Enable crash dump collection</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1112</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">HTTPS callback to mgmt cloud</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Embedded cert mutual auth</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1573.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `c5f41fff34f1e18dad19bff448bdb7952d7886908c292fe570b5695c5e91850b` |
| MD5 | _Not recorded_ |
| Size | 7,139,328 bytes (6.8 MB) |
| Type | other · `msi` |

## Behavior analysis

**10** behaviors in total, each with attached evidence, all statically obtainable.

### 1. Install auto-start system service

`T1543.003` · Confidence **high** · Static

The MSI creates the auto-start service A1Agent under the LocalSystem account, pointing to action1_agent.exe, and starts the service after installation.

> **Evidence**: ServiceInstall: A1Agent/action1_agent.exe/LocalSystem/start type 16(auto); ServiceControl starts the service; IAT CreateServiceW(7303440), StartServiceCtrlDispatcherW(7303448)
> 
> **Source**: `ev-000018`

### 2. Write tenant key configuration

`T1112` · Confidence **high** · Static

During installation it writes the RSA private key, X.509 client certificate, customer ID, install directory and MSI product code to HKLM\Software\Action1\Agent.

> **Evidence**: Registry table: under HKLM\Software\Action1\Agent PrivateKey|Certificate|CustomerId|MSI|INSTALLDIR; Property A1_PRIVATEKEY/A1_CERTIFICATE/A1_CUSTOMERID
> 
> **Source**: `ev-000018` · `ev-000020`

### 3. Enable crash dump collection

`T1112` · Confidence **high** · Static

Configures the Windows Error Reporting local dump directory, dump type and count for action1_agent.exe, action1_update.exe and action1_remote.exe.

> **Evidence**: Registry table: under HKLM\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\<exe> DumpFolder=[INSTALLDIR]CrashDumps, DumpType=2, DumpCount=2
> 
> **Source**: `ev-000018`

### 4. HTTPS callback to management cloud

`T1071.001` · Confidence **high** · Static

Connects over HTTPS via WinHTTP to the vendor management endpoint server[.]action1[.]com and the relay relay[.]action1[.]com, and uploads/downloads files according to built-in URI templates.

> **Evidence**: IAT WinHttpOpen(7304844), WinHttpConnect(7304840), WinHttpOpenRequest(7304832), WinHttpSendRequest(7304848); strings server[.]action1[.]com@0x79ebc8, relay[.]action1[.]com@0x7d5eec
> 
> **Source**: `ref:ed84731c01` · `ev-000020`

### 5. Embedded certificate mutual authentication

`T1573.002` · Confidence **high** · Static

Uses the X.509 certificate and RSA private key embedded in the installer for client certificate authentication to the management endpoint, and establishes an encrypted channel with system certificate store APIs.

> **Evidence**: MSI Property A1_CERTIFICATE(CN=ca[.]app[.]action1[.]com)+A1_PRIVATEKEY; IAT CertOpenStore(7303464), CertFindCertificateInStore(7303476); cryptographic constants hit AES/SHA-256
> 
> **Source**: `ev-000018` · `ev-000019` · `ev-000010`

### 6. Remote command execution

`T1059.001` · Confidence **medium** · Static

Built-in RunPowershell/runaction command channel; the server can issue commands, which are executed by creating processes as the target session user or with LocalSystem privileges.

> **Evidence**: UTF-16 strings RunPowershell, runaction, command, powershell.exe; IAT CreateProcessAsUserW(7303368), WTSQueryUserToken(7305080), LogonUserW(7303356), CreateProcessW(7304012)
> 
> **Source**: `ev-000020` · `ref:ed84731c01`

### 7. Download and update payload

`T1105` · Confidence **high** · Static

Fetches files from the built-in download path or the S3 package repository according to the URI delivered by the server, and performs install/upgrade through the MSI transaction interface.

> **Evidence**: Strings hxxps://{}/builtin/{}_builtin/file.dat{}, /customers/custom/{}/{}/file.dat{}, a1-backend-packages[.]s3[.]amazonaws[.]com; IAT CreateTransaction(7305160), CommitTransaction(7305156); bundled 7z.dll unpacking
> 
> **Source**: `ev-000020` · `ref:ed84731c01`

### 8. Enable remote desktop control

`T1219` · Confidence **high** · Static

Drops the TightVNC-derived action1_remote.exe with the package; it can capture the screen, inject keyboard and mouse input, access the clipboard and create processes with the user token.

> **Evidence**: action1_remote.exe version info FileDescription=Remote Server; string TightVNC@0xcee21; IAT BitBlt(819344), GetDIBits(819380), SendInput(820236), SetWindowsHookExW(820300), CreateProcessAsUserW(819232)
> 
> **Source**: `ref:aa817ab1a6` · `ev-000020`

### 9. Enumerate hosts and sessions

`T1082;T1057;T1018` · Confidence **high** · Static

Enumerates processes, logon sessions, network shares and the computer name, and collects device fingerprints such as agent.guid, system.id and disk.serial for reporting.

> **Evidence**: IAT Process32FirstW(7303716), WTSEnumerateSessionsW(7305084), NetShareGetInfo(7304460), GetComputerNameExW(7303548); config keys agent.guid/system.id/disk.serial
> 
> **Source**: `ref:ed84731c01` · `ev-000020`

### 10. Remote reboot or shutdown

`T1529` · Confidence **high** · Static

Provides remote reboot/shutdown and cancel-reboot commands, calls the system shutdown interface and maintains reboot countdown state.

> **Evidence**: IAT InitiateSystemShutdownExW(7303296), AbortSystemShutdownW(7303300); strings reboot, shutdown, cancelreboot, reboot_countdown
> 
> **Source**: `ref:ed84731c01` · `ev-000020`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the above addresses come from static analysis; no successful connection or session was observed under the isolated analysis network, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://server[.]action1[.]com/` | 443 | c2 | Static | ⏳ Not observed |
| http | `hxxps://relay[.]action1[.]com/` | 443 | relay | Static | ⏳ Not observed |
| http | `hxxps://a1-backend-packages[.]s3[.]amazonaws[.]com/` | 443 | download | Static | ⏳ Not observed |

### Host

**Mutexes**

- `Global\Action1_AgentConnectedToServerEvent`
- `Action1_InstalledSoftwareMutex`

**Dropped paths**

- `%WINDIR%\Action1\action1_agent.exe`
- `%WINDIR%\Action1\action1_remote.exe`
- `%WINDIR%\Action1\7z.dll`
- `%WINDIR%\Action1\CrashDumps`

**Registry**

- `HKLM\Software\Action1\Agent\PrivateKey`
- `HKLM\Software\Action1\Agent\Certificate`
- `HKLM\Software\Action1\Agent\CustomerId`
- `HKLM\Software\Action1\Agent\MSI`
- `HKLM\Software\Action1\Agent\INSTALLDIR`
- `HKLM\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\action1_agent.exe`

**Services**

- `A1Agent (Action1 Agent)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `server[.]action1[.]com, relay[.]action1[.]com` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `c2_uri` | `/builtin/{}/builtin/file.dat{}, /customers/custom/{}/{}/file.dat{}` | Yes | Static |
| `customer_id` | `f314fe20-d754-11f1-aa9a-777ddf71d172` | Yes | Static |
| `install_path` | `%WINDIR%\Action1` | Yes | Static |
| `service_name` | `A1Agent` | Yes | Static |
| `encryption_algo` | `TLS/OpenSSL; AES/SHA-256/RC4 primitives present` | No | Static |
| `client_certificate` | `embedded X.509, CN=ca[.]app[.]action1[.]com` | Yes | Static |
| `private_key` | `embedded RSA private key (MSI Property A1_PRIVATEKEY)` | Yes | Static |
| `mutex` | `Global\Action1_AgentConnectedToServerEvent` | No | Static |
| `proxy_config` | `agent.proxy.hostname/port/username/password; agent.use.proxy` | No | Static |

## Do not misjudge

:::important
The following conclusions **are easy to misjudge**; keep them in mind when citing this report.

- Do not assert that it is a malicious backdoor or RAT based solely on remote command/remote desktop capability: the sample is validly signed by Action1 Corporation, the installer has not been tampered with after signing, and no credential theft, ransomware or destructive code was found.
- Do not treat server[.]action1[.]com / relay[.]action1[.]com / a1-backend-packages[.]s3[.]amazonaws[.]com as attacker C2; these are Action1's official management cloud and package repository.
- This time the MSI was not actually installed or run, so it cannot be claimed that service creation, registry writes, file drops or real network connections were observed; these all come from static declarations in the installer and binaries.
- Do not conclude it is an infostealer because the MSI carries an RSA private key and a customer certificate; that material is used for the agent's client authentication to its tenant management endpoint.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. This run is at the pure static level: the MSI was not installed and the agent was not run; service creation, registry writes, file drops and network connections are installer declarations or code capabilities, not dynamically confirmed.
2. The C2 domains, port and URIs come from MSI/binary strings and are marked as statically recovered with dynamic verification pending; port 443 is inferred from HTTPS usage.
3. The embedded customer ID and certificate may correspond to a specific tenant; the offline environment cannot verify their ownership or whether this is abuse activity.
4. The agent is a large statically linked C++ program (with OpenSSL/curl/boost/libtorrent); not all code paths were decompiled function by function, and the exact protocol details of remote command and download execution still require dynamic verification.

## Evidence index

<details>
<summary>Show 9 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000018` | evidence.record | Read-only MSI table parsing: product/service/registry/custom actions/tenant key and customer ID |
| `ev-000019` | evidence.record | Authenticode signature verification: MSI and main payload signatures valid, signer CN=Action1 Corporation |
| `ev-000020` | evidence.record | Post-CAB-unpack payload strings/version info: vendor domains, config keys, named objects and remote control capabilities |
| `ev-000001` | String extraction | action1_agent.exe string extraction (28,331 ASCII / 2,223 UTF-16) |
| `ev-000010` | Cryptographic constant identification | action1_agent.exe cryptographic constants: AES/SHA-256/CRC32/base64 |
| `ref:28957d6555` | PE structure parsing | action1_agent.exe PE profile: 32-bit, 5 sections, no anomalies, 24 imported DLLs |
| `ref:ed84731c01` | Import table parsing | action1_agent.exe import table: service control/WinHTTP/WS2_32/certificate/process and shutdown APIs |
| `ref:217ca3ec2a` | PE structure parsing | action1_remote.exe PE profile: 32-bit GUI subsystem, 5 sections, no anomalies |
| `ref:aa817ab1a6` | Import table parsing | action1_remote.exe import table: screen capture/input injection/clipboard/token and named pipes |

</details>

---

_The sample in this report is not public; IOCs have been defanged; for security research only._
