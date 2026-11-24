---
title: "Malware Analysis: Astronexx Installer (PE · exe · 1453f354)"
published: 2026-11-22
draft: false
description: "Gray/PUA (medium confidence): Astronexx Installer · pua_bundler/loader · medium difficulty · dynamic sandbox + static decompilation"
tags: ["Astronexx Installer", "pua", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-22-Astronexx-Installer-1453f354"
---

> [!CAUTION]
> **Verdict: Gray/PUA** · Family **Astronexx Installer** (uncertain) · Confidence **Medium**
> 
> Aliases: Fake BitComet Installer package, Astronexx signed encrypted installer
> 
> The sample is a self-extracting installer built with Inno Setup 6.7; its version resource claims to be BitComet Installer 2.23.11[.]2 while the signing subject is Astronexx, so the product vendor and the signing vendor are inconsistent; the installation data is entirely high-entropy (about 8.0) after the plaintext version header, and the program contains built-in password and ChaCha20 encryption support, a suspicious packing method that evades static detection. Dynamic execution only showed it dropping the installation engine into %TEMP% and staying resident waiting, without dropping files or contacting the network without a password. Overall it is assessed as a potentially unwanted/bundled installer; the specific payload could not be examined because of the encryption.

## Overview

| Item | Content |
|:--|:--|
| Family | **Astronexx Installer** · aliases Fake BitComet Installer package, Astronexx signed encrypted installer · _uncertain_ |
| Confidence | **Medium** |
| Behavior classes | pua_bundler · loader |
| Difficulty | medium |
| First seen | 2026-11-21 00:30:21 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/1453f3543d436969a05a641894d511a128a11030d79b9af16b8b430d42faedaf/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Fake BitComet installer</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Valid code signature</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Encrypted setup data</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Drop setup engine to temp</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Wait for setup password</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `1453f3543d436969a05a641894d511a128a11030d79b9af16b8b430d42faedaf` |
| MD5 | _Not recorded_ |
| Size | 3,028,296 bytes (2.9 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**6** behaviors in total, each backed by evidence; **3** are static and **3** were obtained dynamically.

### 1. Fake BitComet Installer

`T1036` · Confidence **High** · Static

The PE version resource declares FileDescription=BitComet Installer, ProductName=BitComet, FileVersion and ProductVersion=2.23.11[.]2, with CompanyName empty; the actual signing subject is Astronexx, a masquerade with inconsistent product-vendor identity.

> **Evidence**: Version resource StringFileInfo: BitComet Installer / BitComet / 2.23.11[.]2; certificate Subject=CN=Astronexx, O=Astronexx, C=IL
> 
> **Source**: `call_795df3fa82fe47d5a224aee8` · `call_e70e896488ec48e4a575c20b`

### 2. Valid Code Signature

`T1553.002` · Confidence **High** · Static

The file carries a valid Authenticode signature whose subject is Astronexx, issued through Sectigo Public Code Signing CA R36 with a DigiCert timestamp (2026-02-11), allowing it to pass security policies based on "unsigned/invalid signature".

> **Evidence**: Get-AuthenticodeSignature: Status=Valid, Signer CN=Astronexx; certificate validity 2024-11-14 to 2026-11-15
> 
> **Source**: `call_e70e896488ec48e4a575c20b` · `call_a80bbe1588654bad80704b67`

### 3. Encrypted Setup Data

`T1027` · Confidence **High** · Static

At file offset 0x19E7AD is the plaintext header "Inno Setup Setup Data (6.7.0)"; the following 1,319,291 bytes have entropy 8.0 and the setup manifest and file names cannot be read out; the program contains TSetupEncryptionKey/TSetupEncryptionNonce and a ChaCha20 implementation and prompts for a /PASSWORD= password, indicating the setup data is password-encrypted.

> **Evidence**: 0x19E7AD "Inno Setup Setup Data (6.7.0)"; following data entropy 8.0; strings TSetupEncryptionKey, TSetupEncryptionNonce, ChaCha20.pas, Please specify the password using the /PASSWORD= command line parameter
> 
> **Source**: `call_15ccacd4f6c74b96bf9eb14c` · `call_8e05d519aa844dd8bcbdbd98` · `ev-000017`

### 4. Drop Setup Engine to Temp Directory

`T1036.005` · Confidence **High** · Dynamic

At runtime the parent process drops the Inno Setup engine to %TEMP%\is-UXFOYWE0NV.tmp\<installer file name>.tmp and starts it with /SL5="$40112,1697709,940544,..."; the value 1697709 (0x19E7AD) is exactly the offset of the encrypted setup data.

> **Evidence**: Dynamic events: PID 5000 → PID 6864, command line contains /SL5="$40112,1697709,940544,C:\dyn\samples\<sha256>.exe"; image path %TEMP%\is-UXFOYWE0NV.tmp\<sha256>.tmp
> 
> **Source**: `call_c03dc7b5b2f84658b502bbf1` · `call_791882527a8c42eca742d5d5` · `call_34fd32155a7740a2a8dbbdc5`

### 5. Wait Resident for Setup Password

`T1204.002` · Confidence **Medium** · Dynamic

The engine process in the temp directory runs with Setup/Uninstall version information and stays alive throughout the observation window (about two minutes) without creating further setup sub-processes, consistent with a password-protected installer waiting for user password input; it needs user interaction to continue.

> **Evidence**: Memory forensics still scans PID 6864 about 2 minutes after sample launch; within the timeline the process has no follow-up child process and no file drop
> 
> **Source**: `call_69026298c7384a7a91fc7d0a` · `call_791882527a8c42eca742d5d5`

### 6. Create Temporary Setup Child Process

`T1106` · Confidence **High** · Dynamic

The parent process starts the setup engine in the temp directory via CreateProcessW, forming the only visible process chain for this sample in the analysis window; the import surface also includes VirtualAlloc/VirtualProtect/VirtualQuery and other APIs, but no injection behavior was observed.

> **Evidence**: Import table CreateProcessW (IAT RVA 783164), VirtualProtect (783096), VirtualAlloc (783312); dynamic process creation event PID 5000 → PID 6864
> 
> **Source**: `call_e3344d6bed30403ca6bea057` · `call_34fd32155a7740a2a8dbbdc5`


## IOC (Defanged)

### Network

:::note
**No C2 / network IOC recovered** (see "Analysis Method and Limitations" at the end).
:::

### Host

**Drop paths**

- `%TEMP%\is-<random>.tmp\<installer file name>.tmp`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `encryption_algo` | `ChaCha20 (Inno Setup 6.7 encrypted setup data)` | Yes | static |
| `password_required` | `true (the installer requires a /PASSWORD= password)` | Yes | static |
| `setup_data_offset` | `0x19E7AD (1,697,709)` | No | static |
| `setup_data_entropy` | `8.0 (1,319,291 bytes, no readable file manifest)` | No | static |
| `payload_recovered` | `false (no password obtained, encrypted payload not decrypted)` | Yes | static |

## Common Misinterpretations

:::important
The following conclusions are **easy to misinterpret**; keep them in mind when citing this report.

- Do not claim the sample installed BitComet or delivered any specific malicious payload: the setup data was not decrypted without a password, and no install directory, dropped file or payload execution was observed at runtime.
- Do not conclude that it is an official BitComet release merely because the signature is valid: the signing subject is Astronexx, inconsistent with the BitComet in the version resource.
- Do not treat the presence of APIs such as VirtualAlloc/VirtualProtect/VirtualQuery in the import table as evidence of injection or in-memory malware: the call chain is unproven, and dynamic observation only shows child-process creation.
- Do not write the analysis environment's own network-interception services or system certificate traffic as the sample's C2/outbound behavior; no network request initiated by the sample process was recorded in the analysis window.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacked | No |

**Limitations and pending verification**

1. The setup data is password-encrypted (ChaCha20) and the password was not obtained, so the file manifest, setup script, final dropped components and any follow-up payload cannot be extracted.
2. Dynamic execution did not enter a password, so only the engine-drop and resident-wait stages were observed; no C2, persistence, service or scheduled task was observed, which does not rule out later malicious behavior.
3. Network monitoring only recorded the system's own certificate/update traffic and no DNS/HTTP/TCP request from the sample process, so the C2 list is empty.
4. Comparison of state before and after execution found no files, registry autostart entries, services or scheduled-task changes attributable to the sample; the newly added network-interception services are analysis-environment components.
5. No multi-engine or public sandbox results were used; family attribution is based on signature and packing traits and is uncertain.

## Evidence Index

<details>
<summary>Expand 16 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `call_07c8b16ab39e4fbfb68431fd` | Static triage | Hash, section entropy, import/export surface and structural anomaly triage |
| `call_91361dea97c34b81a8ab7346` | Static structure parse | PE header/data directories/section table: SECURITY directory 11,296 bytes, section layout and entry point |
| `call_e3344d6bed30403ca6bea057` | Import table parse | 150 imported symbols, including CreateProcessW, VirtualAlloc, VirtualProtect, VirtualQuery |
| `call_b8840142616246be8f98c1b8` | Export table parse | Exports SetupLdr.e32, dbkFCallWrapperAddr, __dbk_fcall_wrapper, confirming the Inno Setup loader |
| `call_078bffcb814d4837a7edf88e` | String scan | ASCII/UTF-16 strings and Inno Setup, encryption/password-related strings |
| `call_a80bbe1588654bad80704b67` | Signature and overlay script | Locates setup data at 0x19E7AD, parses the signing certificate chain and signer Astronexx |
| `call_e70e896488ec48e4a575c20b` | Signature verification | Authenticode Status=Valid, signer CN=Astronexx, timestamp 2026-02-11 |
| `call_15ccacd4f6c74b96bf9eb14c` | Overlay entropy analysis | 1,319,291 bytes of setup data with entropy 8.0, no readable file manifest |
| `ev-000017` | Self-report script verification | Combined script conclusions: encrypted setup data, valid signature, version resource and memory search results |
| `call_c03dc7b5b2f84658b502bbf1` | Dynamic sandbox observation | Revert→detonate→poll→memory-forensics timeline and dump list |
| `call_791882527a8c42eca742d5d5` | Memory forensics | PID 5000 is the sample itself, PID 6864 is the Setup/Uninstall engine dropped under %TEMP% |
| `call_34fd32155a7740a2a8dbbdc5` | System event log | Process creation/registry/service event comparison: sample process chain and no autostart changes |
| `call_1783bf1c5ab34e41a0bb0a99` | Network monitoring log | Only system certificate/update traffic in the analysis window, no network request from the sample process |
| `telemetry:1453f354` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component 116 process/file events; 2 ETW short-lived process events; 22 tool/system noise events filtered |
| `etw:1453f354:5000` | Process event monitoring | Short-lived process event: 1453f3543d436969a05a641894d511a128a11030d79b9af16b8b430d42faedaf.exe (pid 5000; MD5=6DAA57A6DE2089247B285729EF63E985,SHA256=1453F3543D436969A05A641894D511A128A11030D79B9AF16B8B430D42FAEDAF,IMPHASH=88016FCDEF7F227C62171D0AFAD9AAE4) |
| `etw:1453f354:6864` | Process event monitoring | Short-lived process event: 1453f3543d436969a05a641894d511a128a11030d79b9af16b8b430d42faedaf.tmp (pid 6864; MD5=FFF07A0E94AE80F0F88A1DF40BEEE103,SHA256=DF9F982BDF4DE66D23BC423B5992E1590A72417E65F5C87397702F386D7E05AD,IMPHASH=4F3A70412C909E6E8F69020F0BEE4F39) |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
