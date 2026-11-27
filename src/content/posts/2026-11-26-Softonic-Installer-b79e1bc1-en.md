---
title: "Malware Sample Analysis: Softonic Installer (PE · exe · b79e1bc1)"
published: 2026-11-26
draft: false
description: "Gray/PUA (medium confidence): Softonic Installer · pua_bundler · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Softonic Installer", "pua", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-26-Softonic-Installer-b79e1bc1"
---

> [!CAUTION]
> **Verdict: Gray/PUA** · Family **Softonic Installer** (doubtful) · Confidence **Medium**
> 
> Aliases: Softonic Downloader, Softonic Bundler
> 
> The sample is a Windows installer built with Inno Setup 6.7.0, whose version resource and Authenticode signature consistently point to SOFTONIC INTERNATIONAL SA (signature valid, file untampered). The 50112-byte setup data segment starting at offset 0xCF177 and the following 1.22MB file data segment are entirely high-entropy (7.996/8.000), consistent with Inno Setup 6.5+ data encryption, so the install manifest cannot be enumerated statically; in the dynamic sandbox the sample only completed self-extraction and launched the install wizard, waiting for user interaction, with no network connections, persistence or dropped files observed. Given its identity as a Softonic download portal installer and the fact that its payload is encrypted and hidden, it is characterized as a potentially unwanted bundled installer (PUA) rather than an explicitly malicious payload.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Softonic Installer** · aliases Softonic Downloader, Softonic Bundler · _doubtful_ |
| Confidence | **Medium** |
| Behavior class | pua_bundler |
| Difficulty | medium |
| First seen | 2026-11-24 00:59:20 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/b79e1bc1e64eee64ad28259d78e944330f3ff7419e2ff4a40d879221796f2e6b/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Self-extract and restart in temp dir</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Install wizard awaits interaction</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204.002</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Setup data fully encrypted</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">EV signature lowers alerts</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Product identity unifies to brand</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `b79e1bc1e64eee64ad28259d78e944330f3ff7419e2ff4a40d879221796f2e6b` |
| MD5 | _not recorded_ |
| Size | 2,132,432 bytes (2.0 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**6** behaviors in total, each backed by evidence; **4** are static findings and **2** were obtained through dynamic analysis.

### 1. Self-Extracts and Restarts in the Temp Directory

`T1140` · Confidence **High** · Dynamic

After running as an Inno Setup bootstrapper, the sample writes the embedded Setup component to %TEMP%\is-D58ML0UQO0.tmp\<sample name>.tmp and launches that copy with the /SL5="$50112,848247,840704,<original sample path>" argument; process-creation monitoring recorded the 1612 → 6384 parent-child relationship and the full command line.

> **Evidence**: ETW process-creation event: pid 6384 image=C:\Users\analyst\AppData\Local\Temp\is-D58ML0UQO0.tmp\b79e...tmp, parent_pid=1612, command_line contains /SL5="$50112,848247,840704,..."
> 
> **Source**: `call:call_6df460ce762644a1ade3c2b3` · `call:call_972a23975cf4420eb48b9664`

### 2. Install Wizard Awaits Interaction

`T1204.002` · Confidence **High** · Dynamic

The extracted Setup process (pid 6384) loads components such as winhttp.dll, ws2_32.dll and shell32.dll, but throughout the observation window it stayed at the interactive install wizard stage: it created no business child processes and made no dropped files or registry/service changes.

> **Evidence**: Monitoring component report Total suspicious: 0 (pid 1612 and 6384); the before/after telemetry diff only added the analysis environment's own entries (network monitoring root certificate, WinDivert/monitoring component services, Edge update events); the network monitoring host list was all system component domains
> 
> **Source**: `call:call_1546eec2a0` · `call:call_7255018828ea473b94aa1ea5` · `call:call_3941405e44e04500b9ab319d`

### 3. Setup Data Fully Encrypted

`T1027` · Confidence **High** · Static

The Inno Setup data segment at offset 0xCF177 has only a 64-byte plaintext signature 'Inno Setup Setup Data (6.7.0)'; the data after it and the file data block after 0xDB537 have entropies of 7.996 and 8.000 respectively, consistent with Inno Setup 6.5+ ChaCha20 data encryption, so the files, registry entries and [Run] entries to be installed cannot be enumerated statically.

> **Evidence**: setup data entropy 7.996; file data segment (898359–2121056) entropy 8.000; no UTF-16 file path strings within the segment
> 
> **Source**: `call:call_9a8a314703744677a96d81ca` · `call:call_8803968b93854502b6e6f1fb`

### 4. EV Signature Lowers Alerts

`T1553.002` · Confidence **High** · Static

The PE carries a complete Authenticode signature; the signing subject is SOFTONIC INTERNATIONAL SA's EV code-signing certificate, the signature is Valid and covers all embedded encrypted data, and the timestamp was issued by the DigiCert 2026 timestamp service; running it triggers no signature alerts.

> **Evidence**: Get-AuthenticodeSignature → Status=Valid, Signer CN=SOFTONIC INTERNATIONAL SA (OID.2.5.4[.]15=Private Organization, SERIALNUMBER=A62134341), Timestamper=DigiCert SHA256 RSA4096 Timestamp controlled emulation service 2026 1
> 
> **Source**: `call:call_1fc0d1b10f474131a6f80ae4` · `call:call_aa2eb22b27c04a79b7af799a`

### 5. Product Identity Uniformly the Brand Name

`T1036` · Confidence **Medium** · Static

The version resource declares no specific product: FileDescription, ProductName and CompanyName are all 'Softonic--International (SA)', OriginalFileName is empty, and only the 4.0.2[.]0 version number remains; the resource section has only a generic icon and built-in message table, with no identifying product documentation or help links.

> **Evidence**: RT_VERSION string table (size=1412, rva=0xDA5A8): FileDescription='Softonic--International (SA)', OriginalFileName empty; RT_ICON 100 is a 128x128 PNG
> 
> **Source**: `call:call_df732c3f43124729be028938` · `call:call_7f6dd28610cd4218bd4b80cc`

### 6. Installer Framework Traits Complete

`T1587.001` · Confidence **High** · Static

The PE export table's DLL name is SetupLdr.e32 and exports __dbk_fcall_wrapper; the section names .itext/.didata/.edata/.reloc and the import surface (105 kernel32 APIs including FindResourceW/LoadResource/LockResource/SizeofResource, advapi32 token and registry APIs, user32 window/message-loop APIs) fully match a Delphi-written Inno Setup bootstrapper; RT_RCDATA 11111 in .rsrc holds the 'rDlPtS' bootstrap offset table.

> **Evidence**: pe.exports dll_name=SetupLdr.e32; RT_RCDATA 11111 header 72 44 6c 50 74 53 ('rDlPtS'), isomorphic with file offset 0xCC554
> 
> **Source**: `call:call_283012560dea4f948641e382` · `call:call_bb8ea93a13d04efe900127f5` · `call:call_15485681a33e49129d399906`


## IOCs (Defanged)

### Network

:::note
**No C2 / network IOCs were recovered** (see "Analysis Method and Limitations" at the end).
:::

### Host

**Drop paths**

- `%TEMP%\is-<random string>.tmp\<sample name>.tmp`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `installer_framework` | `Inno Setup 6.7.0 (Embarcadero Delphi Win32 compiler 36.0)` | Yes | Static |
| `payload_encryption` | `Inno Setup setup-data/file encryption; setup data segment entropy 7.996, file data segment entropy 8.000, undecryptable without the password` | Yes | Static |
| `setup_data_offset` | `file offset 0xCF177 (848247), 50112 bytes long; after it, 898359 to 2121056 is compressed/encrypted file data` | No | Static |
| `product_version` | `4.0.2[.]0 / ©2026 Softonic--International (SA)` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please take note when citing this report.

- Do not assert that the sample stole or forged the Softonic certificate: the signature chain validates, the signing subject matches the company information in the version resource, and the file was not tampered with by a third party.
- Do not assert the presence of C2, persistence, injection or credential theft: within the dynamic window there were no sample outbound connections, no registry/service/scheduled-task changes, and the monitoring component found no injection or suspicious memory regions.
- Do not classify it as ransomware, a miner or a backdoor: neither its code nor behavior shows any such traits; it is merely an interactive installer for an encrypted payload.
- Do not treat the dynamically observed 'comsvcs' dump as evidence of credential theft: it is a process snapshot artifact of the analysis environment itself; the sample did not call MiniDump-related interfaces.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and Pending Verification**

1. Both the setup data (50112 bytes) and file data (about 1.22MB) are Inno Setup 6.5+ encrypted with entropy near 8.0; without the password the install manifest cannot be enumerated nor bundled components extracted, so the specific bundled software, install paths and [Run] entries could not be confirmed.
2. During the dynamic window the install wizard stayed on an interactive page and was never clicked through; no dropped files, registry writes or network requests were observed; an empty c2 only means none was observed, not that none exists.
3. The sandbox guest used a Romanian locale; network monitoring and system events were mixed with system traffic such as Edge updates and certificate CRL checks, which were excluded from the analysis; all newly added telemetry diff entries belong to the analysis infrastructure itself (network monitoring root certificate, WinDivert/monitoring component services).
4. No third-party detection engine or YARA hit results were obtained; the family classification rests on the signing subject, version resource and packaging framework, and is a medium-confidence inference.

## Evidence Index

<details>
<summary>Expand 18 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `call:call_15485681a33e49129d399906` | Sample triage | PE hashes/section table/import surface/packing score 0, no structural anomalies |
| `call:call_bb8ea93a13d04efe900127f5` | PE structure parsing | 11 sections, I386 GUI, entry 0x0B1E20, security directory 11376 bytes, resource directory 0xD7060 |
| `call:call_283012560dea4f948641e382` | pe.exports | Exported DLL name SetupLdr.e32, exports __dbk_fcall_wrapper |
| `call:call_df732c3f43124729be028938` | python/pefile resource enumeration | RT_VERSION points to Softonic 4.0.2[.]0; RT_RCDATA 11111 is the rDlPtS bootstrap offset table; signature 11376 bytes |
| `call:call_1fc0d1b10f474131a6f80ae4` | PowerShell Get-AuthenticodeSignature | Signature Valid, signer CN=SOFTONIC INTERNATIONAL SA, timestamp DigiCert 2026 |
| `call:call_aa2eb22b27c04a79b7af799a` | openssl pkcs7 | Certificate chain: Sectigo EV R36 → Root R46 → AAA; timestamp chain DigiCert G4 |
| `call:call_8803968b93854502b6e6f1fb` | python manual overlay parsing | 'Inno Setup Setup Data (6.7.0)' at 0xCF177; the 50112-byte setup data segment contains random bytes, no readable file table |
| `call:call_9a8a314703744677a96d81ca` | python entropy calculation | Setup data segment entropy 7.996, following file data segment entropy 8.000 |
| `call:call_972a23975cf4420eb48b9664` | Dynamic analysis platform | Rollback → detonation → 33 polls, sole candidate pid 1612, process and module memory dumps generated at t0/t3, full hollows scan 0 hits, rolled back after wrap-up |
| `call:call_6df460ce762644a1ade3c2b3` | ETW/process timeline parsing | pid 1612 creates pid 6384 (%TEMP%\is-D58ML0UQO0.tmp\*.tmp /SL5="$50112,848247,840704,..."), recording both SHA256/imphash |
| `call:call_1546eec2a0` | Monitoring component report parsing | pid 1612 Total suspicious 0 / 6384 Total suspicious 0, no Hooked/IAT Hooks/Implanted |
| `call:call_3941405e44e04500b9ab319d` | Network monitoring log parsing | Sample pids 1612/6384 made no DNS/TCP requests; the host list was all Edge/Windows Update/certificate CRL |
| `call:call_7255018828ea473b94aa1ea5` | Telemetry diff | services +2 (WinDivert/monitoring component), certificates +4 (fakenet.flare, DigiCert EV Root, all analysis infrastructure), no changes to defender/events/run_keys |
| `call:call_fbddd6b36c5a4e918b12ce36` | strings | Version/signature area contains 'SOFTONIC INTERNATIONAL SA' |
| `call:call_7f6dd28610cd4218bd4b80cc` | String extraction | Delphi RTTI (TSetupHeader/TSetupEncryptionKey/TSetupEncryptionNonce), 'Inno Setup Setup Data (6.7.0)', '.itext/.didata/.edata' |
| `telemetry:b79e1bc1` | Dynamic telemetry | Dynamic telemetry recorded: 114 monitoring component process/file events; 2 ETW short-lived process events; 22 tool/system noise entries filtered |
| `etw:b79e1bc1:1612` | Process event monitoring | Short-lived process event: b79e1bc1e64eee64ad28259d78e944330f3ff7419e2ff4a40d879221796f2e6b.exe (pid 1612; MD5=48CA02BDF2D4F348B6404556C85748D8,SHA256=B79E1BC1E64EEE64AD28259D78E944330F3FF7419E2FF4A40D879221796F2E6B,IMPHASH=88016FCDEF7F227C62171D0AFAD9AAE4) |
| `etw:b79e1bc1:6384` | Process event monitoring | Short-lived process event: b79e1bc1e64eee64ad28259d78e944330f3ff7419e2ff4a40d879221796f2e6b.tmp (pid 6384; MD5=FA1C977A4003CC0793201A6F1711BB6D,SHA256=3A62AE0D102CFF66FBA0A1F0B9BCDF116AD369C3C4F0212EB21A53C766C75A7D,IMPHASH=4F3A70412C909E6E8F69020F0BEE4F39) |

</details>

---

_The sample in this report is not public; IOCs are defanged and provided for security research only._
