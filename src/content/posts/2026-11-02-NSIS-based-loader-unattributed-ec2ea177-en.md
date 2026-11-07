---
title: "Malware Analysis: NSIS-based loader (unattributed) (PE · exe · ec2ea177)"
published: 2026-11-02
draft: false
description: "Malicious (low confidence): NSIS-based loader (unattributed) · loader/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-02-NSIS-based-loader-unattributed-ec2ea177"
---

> [!WARNING]
> **Verdict: malicious** · Family **NSIS-based loader (unattributed)** (doubtful) · Confidence **low**
> 
> Aliases: NSIS dropper, NSIS fake installer loader, NSIS silent-installer loader
> 
> In the dynamic sandbox the installer process actually issued HTTP download requests to 185[.]29[.]10[.]102:80, with the full request visible in process memory; static parsing also shows silent installation, extraction of 14 data/decoy files plus loading of the System.dll plugin, registration of a remote DLL, and self-signed certificate masquerade.

## At a glance

| Item | Content |
|:--|:--|
| Family | **NSIS-based loader (unattributed)** · Aliases NSIS dropper, NSIS fake installer loader, NSIS silent-installer loader · _doubtful_ |
| Confidence | **Low** |
| Behavior classes | loader · downloader |
| Difficulty | medium |
| First seen | 2026-11-02 08:03:12 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ec2ea17710d05c629c3c4a399dfdb301eb3498dab02b71c975197be782455dce/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Silent fake install</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Pad with decoy files</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Call System.dll plugin</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1106</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Register remote DLL</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1129</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Loop-download payload</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `ec2ea17710d05c629c3c4a399dfdb301eb3498dab02b71c975197be782455dce` |
| MD5 | _not recorded_ |
| Size | 665,808 bytes (650.2 KB) |
| Type | PE · `exe` |

## Behavior analysis

**9** behaviors in total, each backed by evidence; **7** are obtainable statically and **2** were obtained through dynamic analysis.

### 1. Silent install of disguised components

`T1036.005` · Confidence **High** · Static

Runs in NSIS silent mode, dropping 14 data/decoy files (including 4 single-byte padding decoys) into %PROGRAMFILES%\Vaar220\counterembargo\Colorability224 and dropping the System.dll plugin into $PLUGINSDIR, masquerading as a normal application installer.

> **Evidence**: NSIS firstheader flags=0x306A (includes the silent bit); after decompressing the header, EXTRACTFILE instructions 130-143 (14 data files) and 102 (System.dll); install-directory string $PROGRAMFILES\Vaar220\counterembargo\Colorability224
> 
> **Source**: `ev-000014` · `ev-000010` · `ref:a083ca3d38`

### 2. Pad with large decoy files

`T1027` · Confidence **High** · Static

Drops four 278KB-904KB single-byte padding files plus JPG/INI/TXT text, inflating the package to a normal size and interfering with static judgment.

> **Evidence**: falsifiability.pre/Bulningen.pur/heteroalbumose.ube/undualises.odd are 95%-99% filled with 0xF1/0xC9/0x8A/0x07 respectively; Torturofret's MZ has an out-of-range e_lfanew
> 
> **Source**: `ev-000013` · `ev-000010`

### 3. Invoke System.dll plugin

`T1106` · Confidence **High** · Static

Drops the NSIS System.dll into $PLUGINSDIR and calls its Call export through REGISTERDLL, preparing for subsequent native API calls.

> **Evidence**: NSIS instruction 105: REGISTERDLL $PLUGINSDIR\System.dll "Call"; the first stream of the data block unpacks into a 12,288-byte MZ file
> 
> **Source**: `ev-000010` · `ref:0ffa31b392`

### 4. Register remote DLL

`T1129` · Confidence **Medium** · Static

Calls DllRegisterServer on $INSTDIR\verdensherredmmernes.dll; that DLL is not among the 15 embedded files and must be obtained by remote download, forming a download-then-load chain.

> **Evidence**: NSIS instruction 122: REGISTERDLL $INSTDIR\verdensherredmmernes.dll "DllRegisterServer"; string table contains DllRegisterServer
> 
> **Source**: `ev-000010` · `ref:ec3a3d96d6`

### 5. Loop-download remote payload

`T1105` · Confidence **High** · Dynamic

The installer process requests /zRVZRgnIWQzkRMbTfrq107[.]bin from 185[.]29[.]10[.]102:80 with a Firefox UA, retrying about every 10 seconds in a download loop.

> **Evidence**: network monitoring: ec2ea...exe (PID 4896) repeatedly requests TCP 185[.]29[.]10[.]102:80, GET /zRVZRgnIWQzkRMbTfrq107[.]bin from 21:49:25; process memory contains the same request
> 
> **Source**: `ref:8a5a73c745` · `ev-000011`

### 6. HTTP masquerades as browser traffic

`T1071.001` · Confidence **High** · Dynamic

Uses Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0 as its User-Agent and adds Cache-Control: no-cache, disguising the download traffic as browser requests.

> **Evidence**: the User-Agent in the network log matches the full request headers at process memory 0x565F158
> 
> **Source**: `ref:8a5a73c745` · `ev-000011`

### 7. Write decoy registry keys

`T1112` · Confidence **Medium** · Static

Through RegCreateKeyExW/RegSetValueExW it writes or deletes values under HKCU\Software\Microsoft\Windows\CurrentVersion (stool, fastlaasningerne, reargument) and HKLM\SOFTWARE\whitecapping\lapfuls\Begyndelsestider156.

> **Evidence**: NSIS instructions 64/155/164/165 carry the above key names; imports include RegCreateKeyExW/RegSetValueExW/RegDeleteValueW/RegDeleteKeyW
> 
> **Source**: `ev-000015` · `ref:0ffa31b392`

### 8. Self-signed certificate masquerade

`T1553.002` · Confidence **High** · Static

Signs the installer with a self-signed Authenticode certificate (C=FR, O=Ganglioneuroma, OU=Hvlvene Udbetal Smittebrerne, CN=Ganglioneuroma), creating the appearance of "signed software".

> **Evidence**: PE security directory offset 0xA1620, WIN_CERTIFICATE length 4784, subject and issuer identical
> 
> **Source**: `ev-000012`

### 9. Recover C2 config at runtime

`T1027.013` · Confidence **High** · Static

The C2 URL and User-Agent have 0 hits in an ASCII/UTF-16 search of the on-disk image and appear only in process memory, showing that the configuration is generated or decrypted at runtime to evade static string detection.

> **Evidence**: searching the whole PE for 185[.]29[.]10[.]102 / zRVZRgn... / Mozilla / Firefox yields 0 hits; ANSI URL at memory 0x90351351, UTF-16 path at 0x564197C
> 
> **Source**: `ev-000011`


## IOC (de-weaponized)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to this target (retrying several times within a short period).
:::

:::caution
**Real server side still unverified**: the connections/handshakes above were completed against a local controlled emulation service; the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://185[.]29[.]10[.]102/zRVZRgnIWQzkRMbTfrq107[.]bin` | 80 | download | Dynamic | Observed |

### Host

**Drop paths**

- `%PROGRAMFILES%\Vaar220\counterembargo\Colorability224\`
- `%PROGRAMFILES%\Vaar220\counterembargo\Colorability224\verdensherredmmernes.dll`

**Registry**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\stool`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\fastlaasningerne\`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\reargument`
- `HKLM\SOFTWARE\whitecapping\lapfuls\Begyndelsestider156`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `185[.]29[.]10[.]102` | Yes | Dynamic |
| `download_url` | `hxxp://185[.]29[.]10[.]102/zRVZRgnIWQzkRMbTfrq107[.]bin` | Yes | Dynamic |
| `http_user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0` | Yes | Dynamic |
| `install_path` | `%PROGRAMFILES%\Vaar220\counterembargo\Colorability224` | Yes | Static |
| `registered_dll` | `%INSTDIR%\verdensherredmmernes.dll` | No | Static |
| `retry_interval_seconds` | `10` | No | Dynamic |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing this report.

- Do not classify it as ransomware or an info-stealer: the second-stage payload was not obtained, and no file encryption, browser-credential/clipboard theft, or lateral movement was observed.
- Do not claim the sample created services or scheduled tasks: no corresponding API calls, service names, or scheduled-task strings were seen statically or dynamically.
- Do not treat the 15 embedded files as functional components: 4 large files are single-byte padding, 3 are JPG, and the rest are mostly random-word text or high-entropy data with no executable structure; none contained a valid PE.
- Do not assert the sample used regsvr32.exe: the registration is done by calling DllRegisterServer inside the installer process, and no regsvr32 child process was observed.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. The second-stage download did not obtain a valid payload (the request kept retrying until observation ended), so family attribution and final capabilities cannot be confirmed.
2. The C2 URL and User-Agent are not visible in the on-disk image and were recovered only from process memory; they cannot be extracted statically.
3. The registry writes come from NSIS script instructions and imported APIs; no live registry diff was performed.
4. No child processes, services, scheduled tasks, or process injection were observed; later stages may still have these capabilities.
5. The sample is 32-bit and the environment was 64-bit Windows 10; behavior may differ on other systems.
6. The signing certificate is self-signed and cannot serve as evidence of a trusted publisher.

## Evidence index

<details>
<summary>Expand 15 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1 and size |
| `ev-000002` | scan.imphash | imphash=f4639a0b3116c2cfc71144b88a929cfd |
| `ev-000009` | String extraction | ASCII/UTF-16 string extraction (no flag hits) |
| `ref:a083ca3d38` | Sample triage | M1 triage: 0 anomalies, packing.score=0, 5 sections |
| `ref:0ffa31b392` | Import table parsing | 7 DLLs/163 symbols, including RegCreateKeyExW/RegSetValueExW/GetProcAddress |
| `ref:63f93971eb` | PE structure parsing | PE32/i386, entry RVA 0x3552, overlay start 323584 |
| `ev-000010` | static unpack + NSIS header decode | 15 embedded files, install directory, System.dll plugin, DllRegisterServer instruction |
| `ev-000011` | memory dump analysis | Full HTTP request and URL/UA offsets in memory |
| `ev-000012` | certificate parse | Self-signed certificate CN=Ganglioneuroma |
| `ev-000013` | embedded file byte statistics | 4 single-byte padding large files; Torturofret is not a valid PE |
| `ev-000014` | NSIS firstheader parse | flags=0x306A (silent + force CRC) |
| `ev-000015` | NSIS instruction decode | Registry keys and write/delete instructions |
| `ref:8a5a73c745` | dynamic sandbox | Real detonation timeline and network request observation |
| `ref:3ddc379c91` | anti-debug static scan | No anti-debugging techniques found |
| `c2_evidence:ec2ea177` | Connection evidence extraction | Dynamic network monitoring recorded 22 connection attempts to 185.29.10[.]102:80, 185[.]29[.]10[.]102:80, displaycatalog[.]mp[.]microsoft[.]com:80; no complete session captured |

</details>

---

_This report's sample is not public; IOCs have been de-weaponized and are for security research only._
