---
title: "Malware Analysis: RDPWrap (other · msi · 9899ffec)"
published: 2026-11-09
draft: false
description: "Gray/PUA (high confidence): RDPWrap · backdoor · difficulty medium · Pure static analysis"
tags: ["RDPWrap", "backdoor", "MSI"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-09-RDPWrap-9899ffec"
---

> [!CAUTION]
> **Verdict: Gray/PUA** · Family **RDPWrap** · Confidence **high**
> 
> Aliases: RDP Wrapper Library, HackTool:Win32/RDPWrap, HackTool.RDPWrap, Stas'M RDP Wrapper
> 
> This MSI is an installer package for the same-origin RDP Wrapper Library 1.6.2. Decompilation confirms that RDPWInst replaces TermService's ServiceDll and restarts the service, and that rdpwrap.dll hooks/patches termsrv.dll's licensing and session policies to allow multi-user RDP. This behavior bypasses Windows Terminal Services licensing restrictions and constitutes a HackTool/PUA; no credential theft, C2 or third-party payload was found, so it is not judged malicious.

## Overview

| Item | Content |
|:--|:--|
| Family | **RDPWrap** · aliases RDP Wrapper Library, HackTool:Win32/RDPWrap, HackTool.RDPWrap, Stas'M RDP Wrapper |
| Confidence | **high** |
| Behavior class | backdoor |
| Difficulty | medium |
| First seen | 2026-11-07 12:04:25 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/9899ffecf141ab4535ec702facbf2b4233903b428b862f3a87e635d09c6244de/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Unpack MSI and drop components</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Write Terminal Services DLL</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Restart service to load DLL</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1569.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Hook licensing policy queries</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Memory-patch session limits</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `9899ffecf141ab4535ec702facbf2b4233903b428b862f3a87e635d09c6244de` |
| MD5 | _not recorded_ |
| Size | 655,360 bytes (640.0 KB) |
| Type | other · `msi` |

## Behavior analysis

**9** behaviors in total, each backed by evidence, and all are statically available.

### 1. Unpacks MSI and extracts components

`T1027.009` · Confidence **high** · static

The MSI CustomAction table invokes RDPWInst.exe with type 18 and the install command -i -o; RDPWInst then extracts RDPW32/RDPW64 (rdpwrap.dll), various RDPCLIP versions, RFXVMT and CONFIG (rdpwrap.ini) from RT_RCDATA resources into the target directory.

> **Evidence**: MSI CustomAction=InstallAction/RDPWInst -i -o; FUN_0043d0f8 @ 0x43d0f8 calls 0x43cc44 to extract RDPW32/RDPW64/RDPCLIP/RFXVMT/CONFIG; RT_RCDATA resource table at 0x3ca6c-0x3cc60.
> 
> **Source**: `ev-000044` · `ev-000036` · `ev-000045`

### 2. Write Terminal Services DLL

`T1543.003` · Confidence **high** · static

RDPWInst opens HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters and writes ServiceDll pointing to rdpwrap.dll; on 64-bit environments it also prepares a reg.exe add command to write REG_EXPAND_SZ.

> **Evidence**: FUN_0043c598 @ 0x43c598 calls SetValue(\"ServiceDll\") on key \\SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters; a reg.exe add command is assembled at 0x43c860.
> 
> **Source**: `ev-000035` · `ev-000038`

### 3. Restart Terminal Service to load DLL

`T1569.002` · Confidence **high** · static

The install/update path enables SeDebugPrivilege, terminates TermService-related processes and restarts TermService so that svchost loads the replaced ServiceDll.

> **Evidence**: FUN_0043f7a4 @ 0x43f7a4: SeDebugPrivilege -> TerminateProcess -> restart TermService; FUN_0043a7bc @ 0x43a7bc reads the TermService ImagePath.
> 
> **Source**: `ev-000037` · `ev-000038`

### 4. Hook licensing policy queries

`T1562.001` · Confidence **high** · static

rdpwrap.dll hooks SLGetWindowsInformationDWORD and CSLQuery::Initialize so that Terminal Services receives forged results when querying licensing/policy, thereby bypassing single-session and licensing restrictions.

> **Evidence**: RDPW64 strings \"Hook SLGetWindowsInformationDWORD\", \"Hook SLGetWindowsInformationDWORDWrapper\", \"Hook CSLQuery::Initialize\"; configuration keys SLPolicyHookNT60/SLPolicyHookNT61.
> 
> **Source**: `ev-000045`

### 5. Memory patches bypass session limits

`T1562.001` · Confidence **high** · static

Using offsets in rdpwrap.ini matching the termsrv.dll version, it applies in-memory patches to functions such as CEnforcementCore::GetInstanceOfTSLicense, CSessionArbitrationHelper::IsSingleSessionPerUserEnabled and CDefPolicy::Query.

> **Evidence**: RDPW64 strings \"Patch CEnforcementCore::GetInstanceOfTSLicense\", \"Patch CSessionArbitrationHelper::IsSingleSessionPerUserEnabled\", \"Patch CDefPolicy::Query\"; imports WriteProcessMemory/ReadProcessMemory/SuspendThread/ResumeThread.
> 
> **Source**: `ev-000045` · `ev-000016`

### 6. Enables multi-user Remote Desktop

`T1133` · Confidence **high** · static

The bundled rdpwrap.ini's [SLPolicy] sets AllowRemoteConnections, AllowMultipleSessions, AllowAppServerMode and others to 1, and sets limits such as MaxUserSessions to 0/1000, permitting concurrent RDP sessions.

> **Evidence**: CONFIG resource [SLPolicy]: TerminalServices-RemoteConnectionManager-AllowMultipleSessions=1, MaxUserSessions=0, 8dc86f1d-9969-4379-91c1-06fe1dc60575-MaxSessions=1000.
> 
> **Source**: `ev-000045`

### 7. Downloads latest INI configuration

`T1105` · Confidence **high** · static

It uses WinINet to download rdpwrap.ini from the stascorp/rdpwrap GitHub raw address; -i -o (the MSI default install arguments) uses online-install mode, falling back to the bundled CONFIG on failure.

> **Evidence**: FUN_0043cf60 @ 0x43cf60: InternetOpenW -> InternetOpenUrlW -> InternetReadFile; URL at 0x3c460: hxxps://raw[.]githubusercontent[.]com/stascorp/rdpwrap/master/res/rdpwrap.ini; FUN_0043f7a4 prints a GitHub error when the download fails.
> 
> **Source**: `ev-000039` · `ev-000037` · `ev-000036`

### 8. Replaces RDP clipboard components

`T1554` · Confidence **high** · static

When %SystemRoot%\System32\rdpclip.exe or rfxvmt.dll is missing, it drops the embedded copy for the matching architecture/version to work with the hooked Terminal Services.

> **Evidence**: FUN_0043d0f8 @ 0x43d0f8: selects rdpclip6032/6064/6132/6164 or rfxvmt32/64 by architecture/version and writes %SystemRoot%\System32\rdpclip.exe, rfxvmt.dll.
> 
> **Source**: `ev-000036` · `ev-000045`

### 9. Probes Terminal Service configuration

`T1012` · Confidence **high** · static

Before installing it reads TermService's ImagePath and Parameters\ServiceDll, accepting only an svchost.exe host with termsrv.dll/rdpwrap.dll, and aborts if it encounters a third-party TermService library or a custom host.

> **Evidence**: FUN_0043a7bc @ 0x43a7bc: reads ImagePath and Parameters ServiceDll of \\SYSTEM\\CurrentControlSet\\Services\\TermService, matching svchost.exe, termsrv.dll, rdpwrap.dll.
> 
> **Source**: `ev-000038`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis method and limitations" at the end for the reason).
:::

### Host

**Dropped paths**

- `%ProgramFiles%\RDP Wrapper\rdpwrap.dll`
- `%ProgramFiles%\RDP Wrapper\rdpwrap.ini`
- `%SystemRoot%\System32\rdpwrap.dll`
- `%SystemRoot%\System32\rdpclip.exe`
- `%SystemRoot%\System32\rfxvmt.dll`
- `%SystemRoot%\System32\termsrv.dll`
- `%SystemRoot%\rdpwrap.txt`
- `%ProgramData%\Package Cache\{37EA5771-3352-4A52-9FAC-9297331DAEBD}\RDPWInst.exe`

**Registry**

- `HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters\ServiceDll`
- `HKLM\SYSTEM\CurrentControlSet\Services\TermService\ImagePath`
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Licensing Core`
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\Clip Redirector`
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\DND Redirector`
- `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\AddIns\Dynamic VC`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

**Services**

- `TermService (ServiceDll rewritten to rdpwrap.dll and the service restarted)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `install_path` | `%ProgramFiles%\RDP Wrapper\rdpwrap.dll` | yes | static |
| `install_path_alt` | `%SystemRoot%\System32\rdpwrap.dll` | no | static |
| `service_name` | `TermService` | yes | static |
| `service_dll_registry` | `HKLM\SYSTEM\CurrentControlSet\Services\TermService\Parameters\ServiceDll` | yes | static |
| `config_file` | `%ProgramFiles%\RDP Wrapper\rdpwrap.ini` | yes | static |
| `update_url` | `hxxps://raw[.]githubusercontent[.]com/stascorp/rdpwrap/master/res/rdpwrap.ini` | no | static |
| `encryption_algo` | `none` | no | static |
| `c2_hosts` | `-` | no | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not judge it a credential-stealing trojan or RAT: no credential/browser-data collection, keylogging or command-and-control callback was found.
- Do not judge it a generic dropper: the MSI only installs same-origin RDP Wrapper components, its embedded CAB contains only RDPWInst, and no third-party malicious payload is dropped.
- Do not claim that a C2 or real network session was observed: the only external address is the official INI update source, and this was a pure static analysis with no sample execution.
- Do not claim that it created new backdoor accounts or changed account passwords: the code focuses on the Terminal Services service and licensing policy and does not involve account management.
- Do not judge it ransomware/wiper because of the service/registry writes: there is no encryption, deletion or destruction of user data.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. Pure static analysis: the MSI, RDPWInst or embedded DLLs were not run; the service/registry writes, termsrv.dll patch results and network access are inferred from code paths and were not dynamically verified.
2. The post-install multi-session RDP effect and system stability were not verified on a real Windows host.
3. Firewall configuration is only visible as the "Configuring firewall..." prompt string; no concrete netsh/COM call was located, so it is not listed as a confirmed behavior.
4. The publisher's code signature was not independently verified; the family judgment mainly relies on embedded version information, product name and component consistency.
5. No C2 or outbound session was found; whether the official GitHub raw update address is accessed depends on the -o/-w arguments and the network environment.
6. No mutex was found; no memory forensics or dynamic behavior observation was performed.

## Evidence index

<details>
<summary>Expand 10 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000044` | msi.parse | parsed the MSI tables and embedded media CAB: ProductName=RDP Wrapper Library 1.6.2, CustomAction installs with RDPWInst -i -o, the CAB's only file is RDPWInst.exe (sha256 ac92d4c6...297753). |
| `ev-000001` | hashing & fingerprints | RDPWInst.exe hashes: md5=3288c284561055044c489567fd630ac2, sha256=ac92d4c6397eb4451095949ac485ef4ec38501d7bb6f475419529ae67e297753. |
| `ev-000035` | decompile | FUN_0043c598 @ 0x43c598: writes TermService\Parameters ServiceDll and builds a reg.exe add fallback command. |
| `ev-000036` | decompile | FUN_0043d0f8 @ 0x43d0f8: extracts CONFIG/RDPW32/RDPW64/RDPCLIP/RFXVMT, downloads/falls back to rdpwrap.ini, replaces rdpclip.exe/rfxvmt.dll. |
| `ev-000037` | decompile | FUN_0043f7a4 @ 0x43f7a4: downloads the INI from GitHub, compares update times, acquires SeDebugPrivilege, terminates and restarts TermService. |
| `ev-000038` | decompile | FUN_0043a7bc @ 0x43a7bc: reads TermService ImagePath and ServiceDll, validating svchost.exe/termsrv.dll/rdpwrap.dll. |
| `ev-000039` | decompile | FUN_0043cf60 @ 0x43cf60: uses WinINet InternetOpenW/InternetOpenUrlW/InternetReadFile to download the remote INI. |
| `ev-000016` | sample triage | RDPW64 resource hashes and structure: sha256=798af20db39280f90a1d35f2ac2c1d62124d1f5218a2a0fa29d87a13340bd3e4, exports ServiceMain/SvchostPushServiceGlobals. |
| `ev-000025` | sample triage | RDPW32 resource hashes and structure: sha256=861ad4bbf682b35affda23fab92c8db945f3fa34f78177843c87802d1fd02020, exports ServiceMain/SvchostPushServiceGlobals. |
| `ev-000045` | script.resource | extracted and inspected RT_RCDATA: rdpwrap.dll exports/hooks/patch strings, rdpwrap.ini SLPolicy and version offsets, and rdpclip/rfxvmt resource names. |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
