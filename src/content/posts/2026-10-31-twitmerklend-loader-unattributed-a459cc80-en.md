---
title: "Malware Analysis: twitmerklend-loader (unattributed) (PE · exe · a459cc80)"
published: 2026-10-31
draft: false
description: "Malicious (low confidence): twitmerklend-loader (unattributed) · loader/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["twitmerklend", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-31-twitmerklend-loader-unattributed-a459cc80"
---

> [!WARNING]
> **Verdict: malicious** · Family **twitmerklend-loader (unattributed)** (uncertain) · Confidence **low**
> 
> Detonated for real inside an isolated Windows 10 guest: after starting, the sample process first resolves the domain twitmerklend[.]com, which is never present in cleartext inside the file, and then opens its own outbound connection on 443; the complete HTTPS C2 URL (hxxps://twitmerklend[.]com/<uuid>/<uuid>) can be read directly from its process memory. The static code also carries WMI antivirus enumeration, cmd/PowerShell command execution, file-timestamp tampering and hash-based dynamic API resolution; this combination matches a remote-control loader.

## Overview

| Item | Content |
|:--|:--|
| Family | **twitmerklend-loader (unattributed)** · _uncertain_ |
| Confidence | **low** |
| Behaviour class | loader · downloader |
| Difficulty | medium |
| First seen | 2026-10-30 14:34:32 |
| Analysis method | dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/a459cc80f8ad88b4e68b4ba073d2a4d7b34ca1072c1201551a09ae8ccd8dd8f6/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">HTTPS callback to C2</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.001</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Enumerate antivirus</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1518.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Parse remote config</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Execute cmd commands</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.003</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">PowerShell policy bypass</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `a459cc80f8ad88b4e68b4ba073d2a4d7b34ca1072c1201551a09ae8ccd8dd8f6` |
| MD5 | _not recorded_ |
| Size | 259,072 bytes (253.0 KB) |
| Type | PE · `exe` |

## Behaviour analysis

**8** behaviours were recovered, each with supporting evidence; **7** of them are static and **1** was obtained through dynamic analysis.

### 1. HTTPS callback to C2

`T1071.001` · confidence **high** · dynamic

After starting, it opens an outbound connection to twitmerklend[.]com:443 and builds a task-request URL of the form hxxps://twitmerklend[.]com/<uuid>/<uuid> in memory.

> **Evidence**: Sandbox network log: 'Received A request for domain twitmerklend[.]com' + pid 4936 requested TCP 192.0.2[.]123:443; the full URL at memory offset 0x20838f
> 
> **Source**: `ref:19d61a85c2` · `ev-000024` · `ref:2fb9df9f74`

### 2. Enumerate antivirus software

`T1518.001` · confidence **high** · static

Connects to root\SecurityCenter2 over COM/WMI, executes SELECT * FROM AntivirusProduct and reads displayName to collect the list of installed antivirus products.

> **Evidence**: 0x40b4d0: CoCreateInstance→ConnectServer(root\SecurityCenter2)→ExecQuery(XOR-restored WQL query)→Get(displayName); strings 0x430400/0x43042e
> 
> **Source**: `ev-000020` · `ev-000012`

### 3. Parse the remote configuration

`T1105` · confidence **medium** · static

The C2 response body is first zlib-decompressed and then parsed as JSON / a field table (settings/run/status etc.), with follow-up actions chosen from the returned values.

> **Evidence**: 0x405fe0: WinINet-style request→FUN_0040add0 reads the response→FUN_004031e0 inflate→FUN_00408ac0 parse→values taken by the decrypted field names
> 
> **Source**: `ev-000023` · `ev-000019`

### 4. Execute cmd commands

`T1059.003` · confidence **high** · static

Runs cmd.exe /c "<command>" through the ShellExecuteEx open/runas verb, and can request administrator rights depending on configuration.

> **Evidence**: 0x40f720: verb is 'open' or 'runas'; the command line is assembled from cmd.exe + "/c \"%s\""; strings 0x430510/0x43047c/0x430634/0x430470
> 
> **Source**: `ev-000021` · `ev-000022` · `ev-000012`

### 5. PowerShell policy bypass

`T1059.001` · confidence **high** · static

Starts PowerShell with -ExecutionPolicy Bypass -NoProfile together with -EncodedCommand / -Command / -File to run the delivered content.

> **Evidence**: strings 0x430520 / 0x430590 / 0x430650; command lines assembled from the cmd/PowerShell templates at 0x40f720
> 
> **Source**: `ev-000012` · `ev-000022`

### 6. Tamper with file timestamps

`T1070.006` · confidence **medium** · static

Imports LocalFileTimeToFileTime/SystemTimeToFileTime/SetFileTime, giving it the ability to disguise the timestamps of dropped files as those of system files.

> **Evidence**: import table KERNEL32: SetFileTime / LocalFileTimeToFileTime / SystemTimeToFileTime
> 
> **Source**: `ref:90c5c899f3`

### 7. Hash-based dynamic API resolution

`T1027` · confidence **medium** · static

Without relying on the import table, it resolves APIs at runtime by module index + 32-bit hash and then calls them indirectly (e.g. ShellExecuteEx and WMI/network-related functions).

> **Evidence**: 0x4189b0(module_idx, hash) called repeatedly, followed by (*func); e.g. 0x83e9e133 (ShellExecuteEx path)
> 
> **Source**: `ev-000018` · `ev-000021`

### 8. XOR-obfuscated strings

`T1027` · confidence **high** · static

Sensitive wide strings are stored XORed byte by byte with a 4-byte repeating key and are only decrypted and used at runtime (e.g. the WQL query).

> **Evidence**: at 0x40b4d0, local_7e is XORed cyclically with the 4-byte key at 0x4303fc, restoring 'SELECT * FROM AntivirusProduct'
> 
> **Source**: `ev-000020`


## IOC (defanged)

### Network

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://twitmerklend[.]com/31aa8434-bc4d-511f-910d-adbab2766b4f/22d0642c-c560-5532-a5ee-70fb76dc49ef` | 443 | c2 | dynamic | — |

### Host

- **No host IOC was recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `twitmerklend[.]com` | yes | dynamic |
| `c2_url` | `hxxps://twitmerklend[.]com/31aa8434-bc4d-511f-910d-adbab2766b4f/22d0642c-c560-5532-a5ee-70fb76dc49ef` | yes | dynamic |
| `http_client` | `WinHTTP (HTTP/1.1, GET/POST)` | no | static |
| `av_discovery_query` | `WMI root\SecurityCenter2 : SELECT * FROM AntivirusProduct (field displayName)` | no | static |
| `cmd_exec_template` | `cmd.exe /c "%s" ; ShellExecuteEx verb open\|runas` | no | static |
| `ps_exec_template` | `powershell -ExecutionPolicy Bypass -NoProfile -EncodedCommand\|-Command\|-File "%s"` | no | static |
| `payload_encoding` | `zlib inflate (inflate 1.1.3) + CRC32` | no | static |

## Don't misread this

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- It must not be stated that the sample has downloaded or executed a second-stage payload: within the observation window only DNS resolution and the 443 connection were seen, with no dropped file, child process or service creation.
- It must not be attributed to a specific family (e.g. BumbleBee/HijackLoader): there is no YARA, vendor naming or family-specific string to support it, and the family field is a candidate marked uncertain.
- It must not be claimed to have credential-theft / ransomware / mining capability: no browser credentials, wallets or file-encryption paths were found in the code or the behaviour.
- The 'runas' and '--headless' templates must not be treated as executed behaviour: only the static templates are visible, and no corresponding process creation was observed.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | dynamic sandbox analysis + static decompilation |
| Unpacked | no |

**Limitations and open questions**

1. The C2 domain and the full URL do not appear in the static file as cleartext or simple XOR and can only be recovered from process memory at runtime; static analysis cannot directly produce this IOC.
2. No TLS application-layer request/response content was seen within the observation window (the network side recorded only domain resolution and TCP 443 connection establishment), so the second-stage payload, task instructions and persistence method all remain unconfirmed.
3. No file writes, registry modifications, scheduled tasks or service creation were observed; the related capabilities come only from the import table and code paths and are static inferences.
4. The PowerShell and --headless browser launch templates and the runas privilege-escalation branch were not triggered in this run, so their actual use cases are unknown.
5. Family attribution lacks YARA / multi-engine / public-report support; only a candidate name is given from the code and configuration characteristics, hence the low confidence.

## Evidence index

<details>
<summary>Show 13 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hash and fingerprint | sha256/md5/sha1 and sample size 259072 |
| `ev-000003` | scan.rich | Rich header with 13 records, MSVC toolchain |
| `ev-000012` | string extraction | String extraction: HTTP/1.1, root\SecurityCenter2, cmd.exe, PowerShell -EncodedCommand, --headless etc. |
| `ref:90c5c899f3` | import table parse | 82 imports: CreateFileW/WriteFile/SetFileTime, CoCreateInstance, IsDebuggerPresent etc. |
| `ev-000019` | decompile.ghidra | 0x40a880: WinINet/WinHTTP request construction (GET + HTTP/1.1) |
| `ev-000020` | decompile.ghidra | 0x40b4d0: WMI root\SecurityCenter2 enumerates AntivirusProduct/displayName and XOR-restores the WQL |
| `ev-000021` | decompile.ghidra | 0x40f720: ShellExecuteEx verb open/runas + cmd.exe /c + PowerShell templates |
| `ev-000022` | decompile.ghidra | 0x40f720 full pseudocode (including the EncodedCommand/--headless branches) |
| `ev-000023` | decompile.ghidra | 0x405fe0: C2 response read→inflate→configuration field parsing |
| `ref:2fb9df9f74` | dynamic analysis platform | Real dynamic detonation: pid 4936 running, memory dump and timeline |
| `ref:19d61a85c2` | bash (log parse) | Sandbox network log: twitmerklend[.]com resolution + sample pid 4936 TCP 443 |
| `ev-000024` | evidence.record | Full C2 URL and loaded modules recovered from the memory dump |
| `c2_evidence:a459cc80` | connection evidence extraction | Dynamic network monitoring recorded 1 connection attempt to ctldl[.]windowsupdate[.]com:443; the full session was not captured |

</details>

---

_This sample is not shared; IOCs are defanged. For security research only._
