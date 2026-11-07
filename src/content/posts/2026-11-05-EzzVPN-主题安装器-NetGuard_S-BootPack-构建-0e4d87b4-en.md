---
title: "Malware Analysis: EzzVPN-themed installer (NetGuard_S / BootPack build) (PE · exe · 0e4d87b4)"
published: 2026-11-05
draft: false
description: "Malicious (low confidence): EzzVPN-themed installer (NetGuard_S / BootPack build) · dropper/pua_bundler · difficulty hard · dynamic sandbox + static decompilation"
tags: ["dropper", "pua", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-05-EzzVPN-主题安装器-NetGuard_S-BootPack-构建-0e4d87b4"
---

> [!WARNING]
> **Verdict: Malicious** · Family **EzzVPN-themed installer (NetGuard_S / BootPack build)** (uncertain) · Confidence **low**
> 
> Aliases: EzzVPN Premium Client Setup, NetGuard_S installer, BootPack.e32 loader
> 
> The sample is an installer/dropper that uses a commercial VPN client as its shell and forges a vendor signature through a self-built private CA: both the root and intermediate CA are self-signed (the root certificate has issuer==subject, and the leaf and CA were issued within about one second before signing), and a public timestamping service is used to extend the apparent "signature validity"; the stub probes the Wine compatibility layer early at startup; the setup data block signature was changed to 'NetGuard_S Setup Data (6.7.0)', the internal unit names are BootPackAndSetup.*, and the export name is BootPack.e32, deliberately hiding the installer's identity; 7.57MB of high-entropy (per-256KB entropy ≈7.999) encrypted/compressed payload is appended outside the sections. The sample executed in the real sandbox and self-extracted a 32-bit copy under %TEMP%, but the installation wizard did not complete, so the final payload's function was not directly observed.

## Overview

| Item | Content |
|:--|:--|
| Family | **EzzVPN-themed installer (NetGuard_S / BootPack build)** · aliases EzzVPN Premium Client Setup, NetGuard_S installer, BootPack.e32 loader · _uncertain_ |
| Confidence | **low** |
| Behavior class | dropper · pua_bundler |
| Difficulty | hard |
| First seen | 2026-11-04 14:54:07 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/0e4d87b44ccd91af41c14719d39bd3362091a93aaea573c0038432abd70c266d/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Forge code-signing certs</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Detect Wine emulation</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Rename setup engine</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Embedded encrypted payload</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Self-extract to temp dir</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">observed</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `0e4d87b44ccd91af41c14719d39bd3362091a93aaea573c0038432abd70c266d` |
| MD5 | _not recorded_ |
| Size | 8,593,424 bytes (8.2 MB) |
| Type | PE · `exe` |

## Behavior analysis

**6** behaviors in total, each backed by evidence; **5** are statically recoverable and **1** was obtained through dynamic analysis.

### 1. Forge code-signing certificates

`T1553.002` · Confidence **high** · static

The PE embeds an Authenticode signature, but the chain is self-built: the root certificate 'Software Trust Root 557E06' is self-signed, it issues 'Code Signing CA 557E06', which in turn issues the leaf CN=ClearPath Networking Ltd. (OU=Engineering, L=San Jose, ST=California, C=US). The issuance times of the root, CA and leaf are all within about one second before signing, and a public timestamping service timestamped it; the chain cannot reach a public trusted root, so Windows shows an unknown publisher.

> **Evidence**: certificate table file off=0x82FE68 size=10408; leaf serial=6aa86f66842652b9e4be548fa05c0df396819881, validity 2026-11-04 13:40:04Z→2028-11-03; root cert issuer==subject
> 
> **Source**: `ref:c41e7b6124` · `ref:20e017086a`

### 2. Detect Wine emulation

`T1497.001` · Confidence **high** · static

Early at startup it first obtains the module base with GetModuleHandleW("ntdll.dll"), then uses GetProcAddress to query the export "wine_get_version" to determine whether it is running under the Wine compatibility layer; afterwards VerSetConditionMask/VerifyVersionInfoW checks the system version. This probing appears before the installation UI, indicating anti-analysis/environment recognition.

> **Evidence**: emulation API trace pc=0x40E109 GetProcAddress(ret=0xFEEE0000, 'wine_get_version'), pc=0x4056FF VerifyVersionInfoW; the string wine_get_version is at .text file off 0x00D510
> 
> **Source**: `ref:e40f13771a` · `ref:dce356513a`

### 3. Rename setup engine

`T1027` · Confidence **high** · static

The setup data block signature was changed to 'NetGuard_S Setup Data (6.7.0)' (standard Inno Setup uses 'Inno Setup Setup Data (x.y.z)'), and the loader stores the same constant for validation; internal Delphi unit names are BootPackAndSetup.InstFunc / BootPackAndSetup.Messages / Compression.LZMA1SmallDecompressor, and the export table DLL name is BootPack.e32. The renaming and custom units hide the real installer origin and evade signature-based detection.

> **Evidence**: data block signature off=0x6FC27D; loader constant off=0xB530C; exports 'BootPack.e32'/'__dbk_fcall_wrapper'/'dbkFCallWrapperAddr'; unit name table off≈0xAFB52
> 
> **Source**: `ref:20e017086a` · `ref:b2f9374ce8` · `ref:ded64dd285`

### 4. Embedded encrypted payload

`T1027.002` · Confidence **high** · static

After the end of all sections (0x0F6800) it appends 7,573,352 bytes of high-entropy data (per-256KB entropy about 7.999, starting magic 7A6C621A), immediately followed by 10,408 bytes of Authenticode certificate; this region does not belong to any section and can only be expanded by the running installer with its LZMA1/encryption components, so the file list and payload cannot be read statically.

> **Evidence**: PE parsing: section raw data ends at off=0x0F6800, security directory points to off=0x82FE68; entropy scan of 29 256KB windows all ≈7.999; magic 7A6C621A at 0x0F6800
> 
> **Source**: `ref:5b03866a6b` · `ref:02b646215e` · `ref:1fc5415ced`

### 5. Self-extract to temp dir

`T1036.005` · Confidence **high** · dynamic

In real dynamic execution the sample starts as itself (pid 3924), then creates a same-named .tmp copy under %TEMP%\is-<random>.tmp\ and executes it as a 32-bit WOW64 process (pid 440); the copy loads winhttp.dll, ws2_32.dll, mpr.dll, comdlg32.dll, wtsapi32.dll and other components. At scan time the process memory showed no injection, IAT hooks or replaced images.

> **Evidence**: dynamic timeline pid 3924 → %TEMP%\is-F239MFSCLY.tmp\<sha256>.tmp (pid 440); process module list includes winhttp.dll/ws2_32.dll; the temporary path string appears in memory dumps
> 
> **Source**: `ref:711ea6866c` · `ref:6de561a3a6` · `ref:728354e3d6`

### 6. Collect system disk information

`T1497.001` · Confidence **medium** · static

Through VerifyVersionInfoW/GetVersionExW/GetSystemInfo/GetVolumeInformationW/GetDriveTypeW/GetTempPathW it collects the system version, volume information, drive types and temporary directory. These calls are consistent with a normal installer's environment adaptation and are not malicious by themselves, but combined with the Wine probe they show environment-recognition intent.

> **Evidence**: IAT rva: GetSystemInfo=783320, GetVolumeInformationW=783204, GetDriveTypeW=783212, VerifyVersionInfoW=783344, GetTempPathW=783324, GetVersionExW=783340
> 
> **Source**: `ref:349f9fc5e4` · `ref:e40f13771a`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (reasons in "Analysis method and limitations" at the end).
:::

### Host

**Dropped paths**

- `%TEMP%\is-<10 random chars>.tmp\<original filename>.tmp`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `installer_engine` | `NetGuard_S Setup Data (6.7.0) / BootPackAndSetup (export DLL name BootPack.e32)` | yes | static |
| `product_name` | `EzzVPN Premium` | yes | static |
| `product_version` | `ProductVersion 1.1.43 / FileVersion 1.1.43[.]125` | no | static |
| `company_name` | `EzzVPN Soft` | no | static |
| `builder_comment` | `This installation was built with DataPack...` | no | static |
| `signature_issuer` | `CN=ClearPath Networking Ltd. (self-signed root 'Software Trust Root 557E06')` | yes | static |
| `payload_blob` | `file offset 0x0F6800, size 7573352 bytes, entropy 7.999/256KB, magic 7A6C621A` | yes | static |
| `c2_hosts` | `-` | no | dynamic |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not assert that a specific malware family or backdoor was dropped: the installation wizard did not complete and the unpacked payload was not obtained; the family is only a candidate at the branding and builder level, uncertain=true.
- Do not assert the existence of a C2 or persistence: within the real dynamic window no network request initiated by the sample itself was observed, nor any service, scheduled task or Run key write.
- Do not conclude process injection or privilege escalation merely from VirtualAlloc/VirtualProtect/CreateProcessW/AdjustTokenPrivileges in the import table — these calls match a normal installer's memory decompression, child-process launch and closing of locked files, and no cross-process write was observed.
- Do not report ransomware/stealer because of the high-entropy trailing data: the high-entropy block is the installer's encrypted/compressed resource, and no file encryption, credential reading or data exfiltration was seen.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The installation wizard requires manual interaction and did not complete within the dynamic window; no dropped files, services, scheduled tasks or network callback were observed, so the payload's nature and family are unconfirmed.
2. The 7,573,352 bytes of trailing data could not be statically expanded with LZMA1 under multiple parameter sets, suggesting another encryption layer or non-standard packaging; the file list and drop paths cannot be obtained statically.
3. The Wine probe (GetProcAddress("wine_get_version")) was directly observed through instruction-level emulation; the real sandbox only produced process/memory snapshots and no API-level call log, so the timing of this behavior in a real environment was not re-verified.
4. The digest of the signature CMS was not re-validated, so it can only be confirmed that the certificate chain is self-built and untrusted, not that the file was modified after signing.
5. The installer process's internal unit names and copyright information can be set arbitrarily by the builder and cannot serve as sole attribution evidence.

## Evidence index

<details>
<summary>Expand 14 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hashing and fingerprinting | sha256=0e4d87b44ccd91af41c14719d39bd3362091a93aaea573c0038432abd70c266d, size=8593424 |
| `ev-000002` | scan.imphash | imphash=88016fcdef7f227c62171d0afad9aae4 |
| `ref:02b646215e` | PE structure parsing | PE32 Delphi/C++Builder layout, 11 sections, sections end at off=0x0F6800, security directory off=0x82FE68 size=10408 |
| `ref:349f9fc5e4` | import table parsing | 5 DLLs/150 symbols: kernel32/user32/advapi32/oleaut32/comctl32, including CreateProcessW/OpenProcessToken/AdjustTokenPrivileges/RegOpenKeyExW/RegQueryValueExW/VerifyVersionInfoW |
| `ref:b2f9374ce8` | pe.exports | Export DLL name BootPack.e32, exports dbkFCallWrapperAddr and __dbk_fcall_wrapper |
| `ref:75fe6d3b7a` | resource strings | Version info: EzzVPN Premium Client Setup 1.1.43[.]125 / EzzVPN Soft / 'This installation was built with DataPack...' |
| `ref:20e017086a` | string scan | Data block signature 'NetGuard_S Setup Data (6.7.0)' (off 0x6FC27D) and loader constant (off 0xB530C); ClearPath/DigiCert strings in the certificate |
| `ref:c41e7b6124` | certificate parse | Self-signed root 'Software Trust Root 557E06' → 'Code Signing CA 557E06' → leaf CN=ClearPath Networking Ltd., issuance times clustered at 2026-11-04 13:40:02–13:40:04Z |
| `ref:5b03866a6b` | overlay analysis | Entropy of 29 256KB windows from 0x0F6800 all ≈7.999, magic 7A6C621A |
| `ref:ded64dd285` | string scan | Internal units BootPackAndSetup.InstFunc/Messages, Compression.LZMA1SmallDecompressor, Shared.SetupEntFunc |
| `ref:e40f13771a` | emulation | API trace: GetModuleHandleW(ntdll.dll)→GetProcAddress('wine_get_version'), VerSetConditionMask/VerifyVersionInfoW |
| `ref:711ea6866c` | sandbox watch | pid 3924 starts, pid 440 runs %TEMP%\is-F239MFSCLY.tmp\<sha256>.tmp, no child processes/C2, rollback on exit |
| `ref:6de561a3a6` | memory scan | Scan of the sample and temporary copy processes: Total suspicious=0, no injection/IAT hooks; the temporary copy loads winhttp/ws2_32 and others |
| `ref:728354e3d6` | memory dump strings | The memory dump contains '\REGISTRY\USER\...\is-F239MFSCLY.tmp\<sha>.tmp' and EzzVPN version information, with no dropped files/registry write traces |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
