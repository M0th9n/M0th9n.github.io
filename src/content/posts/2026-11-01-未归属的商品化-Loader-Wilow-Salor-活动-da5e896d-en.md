---
title: "Malware Analysis: Unattributed commodity loader (Wilow/Salor campaign) (PE · exe · da5e896d)"
published: 2026-11-01
draft: false
description: "Malicious (low confidence): Unattributed commodity loader (Wilow/Salor campaign) · loader/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-01-未归属的商品化-Loader-Wilow-Salor-活动-da5e896d"
---

> [!WARNING]
> **Verdict: malicious** · Family **Unattributed commodity loader (Wilow/Salor campaign)** (doubtful) · Confidence **low**
> 
> The sample is a 64-bit C++ loader: statically there is an AES table, high-entropy .rdata, WinHTTP/registry/WMI imports, and payload.exe drop logic; during real dynamic execution it loads wbemprox/wbemsvc/fastprox (WMI calls occur), and the decrypted download address hxxp://107[.]175[.]82[.]242:9000/wilow/salor[.]bin along with MSFT_MpPreference.Add ExclusionPath/ExclusionExtension/AttackSurfaceReductionOnlyExclusions type information appears in its own process memory; decompilation confirms it writes the downloaded content to disk and then launches it with CreateProcessA.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Unattributed commodity loader (Wilow/Salor campaign)** · _doubtful_ |
| Confidence | **Low** |
| Behavior classes | loader · downloader |
| Difficulty | medium |
| First seen | 2026-11-01 11:35:51 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/da5e896dddab566d7db265b5e8945d71820f991ac03a806f409470608dad23f7/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt built-in config</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">WMI adds AV exclusions</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Download remote payload</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Launch dropped payload</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Filename taken from URL</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `da5e896dddab566d7db265b5e8945d71820f991ac03a806f409470608dad23f7` |
| MD5 | _not recorded_ |
| Size | 205,312 bytes (200.5 KB) |
| Type | PE · `exe` |

## Behavior analysis

**7** behaviors in total, each backed by evidence: **5** are obtainable statically and **2** were obtained through dynamic analysis.

### 1. Decrypts built-in configuration

`T1027` · Confidence **High** · Static

The program embeds the AES forward S-box and multiple T-tables, .rdata entropy is 7.75, and at runtime plaintext download URLs and paths appear in heap memory, showing that configuration/strings are AES-decrypted before use.

> **Evidence**: AES S-box @ file off 0x15400; .rdata entropy 7.75; plaintext URL at heap memory 0x1F896
> 
> **Source**: `ref:f17cdbb0a4` · `ref:3581c89291` · `ev-000021`

### 2. Adds antivirus exclusions via WMI

`T1562.001` · Confidence **High** · Dynamic

Calls MSFT_MpPreference.Add through WMI to add ExclusionPath, ExclusionExtension, and AttackSurfaceReductionOnlyExclusions (ASR) exclusions to Defender, using .sys/.dll/.ps1/.bat/.cmd extensions and directories such as C:\Windows\Temp and C:\Users\Public to widen the allowed range.

> **Evidence**: dynamically loads wbemprox.dll/wbemsvc.dll/fastprox.dll; in-memory type information MSFT_MpPreference/ExecMethod/ExclusionPath; plaintext string root\Microsoft\Windows\Defender
> 
> **Source**: `ref:5c12eb99bd` · `ev-000021` · `ref:2a46bae45a`

### 3. Downloads a remote payload

`T1105` · Confidence **Medium** · Dynamic

Embeds the URL hxxp://107[.]175[.]82[.]242:9000/wilow/salor[.]bin; together with the WinHTTP imports and the write-to-disk/execute functions it forms a download-land-launch chain; no actual HTTP request was observed in this execution.

> **Evidence**: URL at memory 0x1F896; imports WinHttpOpenRequest(WINHTTP.dll); FUN_140005050 writes to disk then calls FUN_140004f64
> 
> **Source**: `ev-000021` · `ref:2a46bae45a` · `ref:5c12eb99bd`

### 4. Launches the payload after dropping it

`T1106` · Confidence **High** · Static

FUN_140005050 uses CreateFileA(CREATE_ALWAYS) to write the download buffer, and after WriteFile succeeds it directly starts the file with CreateProcessA, with empty launch parameters and without waiting for exit.

> **Evidence**: 0x140005050: CreateFileA/WriteFile -> FUN_140004f64; 0x140004f64: CreateProcessA(param_1, NULL, ...)
> 
> **Source**: `ref:dcc183def3` · `ref:ac907c6e99`

### 5. Derives the drop filename from the URL

`T1036` · Confidence **Medium** · Static

FUN_140004e11 takes the filename after the last '/' in the URL; when it is empty it falls back to the fixed string payload.exe, so the on-disk filename can be controlled remotely.

> **Evidence**: 0x140004e11 returns "payload.exe" or the last URL segment; string payload.exe @ file off 0x152FA
> 
> **Source**: `ref:366065b05d` · `ref:ccddbbde37`

### 6. Mass zero-argument API calls

`T1497.001` · Confidence **Medium** · Static

The function at 0x140009260 performs zero-argument calls in sequence against more than 20 imported functions from WinHTTP, WMI, registry, crypto, GDI screen capture, network enumeration, and the certificate store — an interference/probing call sequence that cannot be used to infer real functionality.

> **Evidence**: 0x140009260–0x140009450 consecutive call [thunk] (ecx/edx/r8/r9 zeroed)
> 
> **Source**: `ref:ac746cb9b1`

### 7. Timing and PEB anti-analysis

`T1497.003` · Confidence **Medium** · Static

The code contains rdtsc timing checks and direct gs:[0x60] PEB access, used to detect debugging/virtualized environments.

> **Evidence**: rdtsc sequence @ rva 68521 (.text); PEB access @ rva 4147
> 
> **Source**: `ref:d95cc49527`


## IOC (de-weaponized)

### Network

:::caution
**Pending dynamic verification**: the addresses above were obtained statically; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://107[.]175[.]82[.]242:9000/wilow/salor[.]bin` | 9000 | download | Static | ⏳ Not observed |

### Host

**Drop paths**

- `%APPDATA%`
- `%LOCALAPPDATA%`
- `%TEMP%`
- `C:\Windows\Temp`
- `C:\Users\Public`
- `payload.exe`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `107.175.82[.]242:9000` | Yes | Dynamic |
| `payload_url` | `hxxp://107[.]175[.]82[.]242:9000/wilow/salor[.]bin` | Yes | Dynamic |
| `drop_filename` | `payload.exe (fallback when the URL's last segment is empty or unavailable)` | Yes | Static |
| `install_dirs` | `%APPDATA%; %LOCALAPPDATA%; %TEMP%; C:\Windows\Temp; C:\Users\Public` | No | Static |
| `encryption_algo` | `AES (built-in S-box and T-tables; configuration/strings are decrypted at runtime)` | Yes | Static |
| `defense_evasion` | `WMI root\Microsoft\Windows\Defender: MSFT_MpPreference.Add(ExclusionPath, ExclusionExtension, AttackSurfaceReductionOnlyExclusions)` | Yes | Dynamic |
| `campaign_id` | `-` | No | Dynamic |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing this report.

- Do not judge it as ransomware or a stealer: no file encryption, shadow-copy deletion, browser credential store/SQLite reads, or CryptUnprotectData call chain was found; the sample downloads an executable payload rather than encrypting victim files.
- Do not assert screen-monitoring, window-enumeration, or certificate-theft capability merely from imports of BitBlt/EnumWindows/GetAdaptersInfo/CertOpenSystemStoreA: these APIs are concentrated in one zero-argument "API impulse" function, and no real call chain was seen.
- Do not assert that outbound contact or download was completed in this run: no TCP/HTTP request to 107[.]175[.]82[.]242:9000 and no child process creation were observed during the dynamic window; the C2 and download stages still need review.
- Do not assert persistence or process injection: only RegSetValueExA is imported, no registry write was observed; WriteProcessMemory/VirtualAllocEx/CreateRemoteThread are not imported.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. This dynamic execution observed only WMI defense evasion and configuration decryption, and did not trigger the actual download/drop/execute; the download address, payload.exe drop, and CreateProcessA chain rest on static decompilation plus runtime memory evidence and are marked pending dynamic review.
2. The second stage salor.bin was not obtained, so its family, encryption, and ultimate purpose cannot be determined.
3. The sample AES-encrypts its configuration and assembles some paths at runtime, so not all configuration keys and persistence switches could be enumerated.
4. No registry writes, services, scheduled tasks, or other persistence behavior were observed; the absence of such findings does not mean the capability is absent.
5. Only one short detonation (about 2 minutes of observation) was performed; long-term residence and post-reboot behavior were not verified.

## Evidence index

<details>
<summary>Expand 15 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:ed3b912079` | PE structure parsing | AMD64 PE, 8 sections, entry rva 0xBB64, no structural anomalies, imports 23 DLLs |
| `ref:3714b0d91c` | Hash and fingerprint | sha256/imphash baseline |
| `ref:2a46bae45a` | Import table parsing | WinHTTP/WMI(OLE)/registry/CryptoAPI/GDI/network enumeration/certificate store import surface |
| `ref:3581c89291` | Sample triage | .rdata entropy 7.75, no packer signals; per-section entropy and hashes |
| `ref:f17cdbb0a4` | Crypto constant identification | AES forward S-box @ 0x15400 |
| `ref:ccddbbde37` | String extraction | Plaintext strings such as payload.exe |
| `ref:68a3929a54` | unpack.detect | packed=false, no unpacking needed |
| `ref:d95cc49527` | unpack.antidebug | rdtsc timing and PEB access |
| `ref:5c12eb99bd` | Dynamic analysis platform | Real detonation pid 2416, process alive, no child processes; memory dumps and module list |
| `ev-000021` | evidence.record | Memory dump search: URL, WMI Exclusions type information, host directories, and process names |
| `ref:dcc183def3` | decompile.function | FUN_140005050 writes to disk then CreateProcessA |
| `ref:ac907c6e99` | decompile.function | FUN_140004f64 CreateProcessA launches the dropped file |
| `ref:366065b05d` | decompile.function | FUN_140004e11 takes the filename from the URL, falling back to payload.exe |
| `ref:ac746cb9b1` | disasm.function | 0x9260 zero-argument batch calls to imported APIs (interference sequence) |
| `ref:b3e848c68a` | dyn.run | Emulation executed only CRT initialization and never reached the body (dynamic results rely on the real sandbox) |

</details>

---

_This report's sample is not public; IOCs have been de-weaponized and are for security research only._
