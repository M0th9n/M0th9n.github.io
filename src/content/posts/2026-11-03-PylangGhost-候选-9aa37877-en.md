---
title: "Malware Analysis: PylangGhost (candidate) (PE · exe · 9aa37877)"
published: 2026-11-03
draft: false
description: "Malicious (low confidence): PylangGhost (candidate) · loader/downloader/implant · difficulty medium · dynamic sandbox + static decompilation"
tags: ["PylangGhost", "loader", "downloader", "implant", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-03-PylangGhost-候选-9aa37877"
---

> [!WARNING]
> **Verdict: Malicious** · Family **PylangGhost (candidate)** (uncertain) · Confidence **low**
> 
> Aliases: Python-embeddable loader, Contagious Interview Python implant style
> 
> Decompilation shows the program decrypts its embedded strings, downloads the official embeddable Python from python[.]org, drops it into a disguised system directory, installs pip, then fetches main.py and app.pyd from a remote CDN and creates a process to run them; it also retrieves a payload address from an on-chain contract via Polygon JSON-RPC eth_call. The chain exists only to load and run external code.

## Overview

| Item | Content |
|:--|:--|
| Family | **PylangGhost (candidate)** · aliases Python-embeddable loader, Contagious Interview Python implant style · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · downloader · implant |
| Difficulty | medium |
| First seen | 2026-10-31 14:57:23 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/9aa3787766dedfaa707e029d7426763de7acbbfee452d57dcce6a6ddbf65208d/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded string table</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Crash after sandbox checks</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Fetch config from blockchain</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Download Python runtime</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Deploy interpreter in fake dir</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `9aa3787766dedfaa707e029d7426763de7acbbfee452d57dcce6a6ddbf65208d` |
| MD5 | _not recorded_ |
| Size | 1,139,712 bytes (1.1 MB) |
| Type | PE · `exe` |

## Behavior analysis

**10** behaviors in total, each backed by evidence, all statically recoverable.

### 1. Decrypt embedded string table

`T1027` · Confidence **high** · static

On startup it XORs .rdata constants with an adjacent 16-byte key, bulk-recovering URLs, directory names, and request templates.

> **Evidence**: FUN_00401011 @0x401011: buf[i]=DAT_0047796c[i]^DAT_00477990[i&0xf]; similar loops at 0x401040-0x4018xx
> 
> **Source**: `ref:a22614e1f9` · `ref:77a2f591a6`

### 2. Crash after sandbox checks

`T1497.001` · Confidence **high** · static

It checks C: free space, physical memory, processor architecture, and system uptime, and executes an illegal instruction to terminate if the conditions are not met, evading analysis environments.

> **Evidence**: 0x4011bb GetDiskFreeSpaceExW; 0x4011da GetTickCount64; 0x401211 GlobalMemoryStatusEx; 0x40124d GetSystemInfo; 0x4023e1 invalidInstructionException
> 
> **Source**: `ref:a22614e1f9`

### 3. Fetch config from blockchain

`T1102` · Confidence **high** · static

It sends eth_call to 8 Polygon RPC nodes, queries contract 0x9c0a..., and treats the returned data as location information for the later payload.

> **Evidence**: 0x77a04 JSON: {"jsonrpc":"2.0","method":"eth_call","params":[{"to":"..."}; contract 0x9c0a507300fd902787bb193d80fca5ce6e1bff9a; RPC list 0x77ad5-0x77c05
> 
> **Source**: `ref:77a2f591a6` · `ref:a22614e1f9`

### 4. Download Python runtime

`T1105` · Confidence **high** · static

It downloads python-3.12.7-embed-amd64.zip over HTTPS and saves it as python.zip.

> **Evidence**: 0x77cd4 decrypts to hxxps://www[.]python[.]org/ftp/python/3.12.7/python-3.12.7-embed-amd64[.]zip; 0x77d2a python.zip
> 
> **Source**: `ref:ee14d1f0f2` · `ref:a692564263`

### 5. Deploy interpreter in fake dir

`T1036.005` · Confidence **high** · static

It extracts the interpreter to %LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex, imitating a Microsoft system component path.

> **Evidence**: 0x77c88 LOCALAPPDATA; 0x77ca4 Microsoft\Windows\NtProfileIndex; 0x77d44 python.exe
> 
> **Source**: `ref:ee14d1f0f2` · `ref:a692564263`

### 6. Rewrite _pth and install pip

`T1059.006` · Confidence **high** · static

It changes '#import site' in python312._pth to 'import site', then runs get-pip.py to install pip and the requirements.

> **Evidence**: 0x77d7c '#import site'->0x77d98 'import site'; 0x77db3 bootstrap[.]pypa[.]io/get-pip.py; 0x77e01 Scripts\pip.exe
> 
> **Source**: `ref:ee14d1f0f2` · `ref:a692564263`

### 7. Fetch Python payloads

`T1105` · Confidence **high** · static

It downloads main.py and the native extension app.pyd from the CDN's /cdn/e/42a522313d92 and /cdn/e/36f2c0035ef9.

> **Evidence**: 0x77fc7 main.py; 0x78001 app.pyd; 0x77fa4/0x77fde /cdn/e/ paths
> 
> **Source**: `ref:ee14d1f0f2` · `ref:a692564263`

### 8. Create process to run payload

`T1059.006` · Confidence **high** · static

It uses CreateProcessW to launch python.exe main.py --host ... --env ... and sets PYTHONDONTWRITEBYTECODE.

> **Evidence**: 0x5e2d call CreateProcessW (IAT thunk 0x76050); 0x78018 --host; 0x7802e --env; 0x77f3b PYTHONDONTWRITEBYTECODE
> 
> **Source**: `ref:4b720339d9` · `ref:a692564263`

### 9. Impersonate browser requests to CDN

`T1071.001` · Confidence **high** · static

The request headers fix a Chrome 120 UA and carry x-cdn-origin-verify: trusted-upstream to pass CDN origin checks.

> **Evidence**: 0x77e61 Mozilla/5.0 ... Chrome/120; 0x77ee0 x-cdn-origin-verify; 0x77f03 trusted-upstream
> 
> **Source**: `ref:ee14d1f0f2`

### 10. Establish HTTPS egress

`T1071.001` · Confidence **high** · static

It uses Winsock to resolve domains and connect to 443, and sends/receives data through a self-implemented HTTP/TLS client.

> **Evidence**: 0x165a1 getaddrinfo; 0x16d02 connect; 0x2ee06 WSAStartup; TLS constants 'expand 32-byte k' and 'c hs traffic'
> 
> **Source**: `ref:8c6aaf9e37` · `ref:a692564263`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| other | `Polygon JSON-RPC eth_call -> contract 0x9c0a507300fd902787bb193d80fca5ce6e1bff9a (dead-drop resolver)` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://www[.]python[.]org/ftp/python/3.12.7/python-3.12.7-embed-amd64[.]zip` | 443 | download | static | ⏳ not observed |
| http | `hxxps://bootstrap[.]pypa[.]io/get-pip[.]py` | 443 | download | static | ⏳ not observed |
| http | `hxxps://<runtime-resolved-cdn-host>/cdn/e/42a522313d92 (main.py)` | 443 | download | static | ⏳ not observed |
| http | `hxxps://<runtime-resolved-cdn-host>/cdn/e/36f2c0035ef9 (app.pyd)` | 443 | download | static | ⏳ not observed |
| http | `hxxps://<runtime-resolved-cdn-host>/cdn/5ef451455923 (requirements.txt)` | 443 | download | static | ⏳ not observed |

### Host

**Drop paths**

- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\python.exe`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\python312._pth`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\main.py`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\app.pyd`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\requirements.txt`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\Scripts\pip.exe`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `polygon-rpc[.]com; 1rpc[.]io/matic; polygon-public.nodies.app; rpc-mainnet.matic.quiknode.pro; polygon-bor-rpc[.]publicnode[.]com; endpoints[.]omniatech[.]io/v1/matic/mainnet/public; api[.]zan[.]top/polygon-mainnet; polygon.rpc.subquery.network/public` | yes | static |
| `eth_contract` | `0x9c0a507300fd902787bb193d80fca5ce6e1bff9a` | yes | static |
| `download_paths` | `/cdn/5ef451455923 -> requirements.txt; /cdn/e/42a522313d92 -> main.py; /cdn/e/36f2c0035ef9 -> app.pyd (host resolved at runtime)` | yes | static |
| `install_path` | `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex` | yes | static |
| `python_distribution` | `python-3.12.7-embed-amd64.zip` | yes | static |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0[.]0 Safari/537.36` | no | static |
| `string_obfuscation` | `repeating-key XOR, 16-byte key stored adjacent to ciphertext` | no | static |
| `runtime_args` | `python.exe main.py --host <value> --env <value>` | yes | static |

## Must not claim

:::important
The following conclusions are **prone to misjudgment**; take care when citing this report.

- Do not report ransomware/wiper: no file encryption, deletion, or volume destruction behavior was seen; the chain stops at downloading and running external scripts.
- Do not assert persistence was established: no service, scheduled task, or Run key writes were observed; registry access is read-only queries only.
- Do not treat python[.]org and bootstrap[.]pypa[.]io as malicious C2: they are legitimate software distribution sources being abused.
- Do not attribute it to a specific APT on this basis: the family name is only a candidate, lacking hash, YARA, or multi-engine cross-verification.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. Samples of the second stage main.py and app.pyd were not obtained, so their functionality (remote control/stealing) cannot be determined.
2. The CDN hostname is resolved at runtime; static analysis can recover only the /cdn/ paths, not the complete download URL.
3. The on-chain contract's return content requires an online query to Polygon RPC; no real egress was made this time, so the eth_call return value and final C2 still await dynamic confirmation.
4. No C2 session attributable to the sample was obtained within the dynamic window; network-side evidence is mostly static decryption.
5. The specific registry key/value names queried were not recovered in this static decoding and cannot be listed as IOCs.

## Evidence index

<details>
<summary>Expand 10 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:e6a7d8195f` | sample triage | hash/imphash/entropy/packing score: unpacked, 5 DLLs/48 symbols imported |
| `ref:391ecf7ebd` | PE structure parsing | AMD64 GUI, entry 0x401000, 7 sections, no anomalies |
| `ref:e0d822314a` | import table parsing | CreateProcessW/RegQueryValueExA/WS2_32/CRYPT32 and other imports |
| `ref:a22614e1f9` | decompile.function | FUN_00401011: XOR decryption loop + anti-sandbox checks + RPC/contract strings |
| `ref:a692564263` | decompile.function | FUN_00402494: Python download/extract/pip/main.py/app.pyd/CreateProcessW |
| `ref:ee14d1f0f2` | script | recovered 25 strings via adjacent-key XOR (LOCALAPPDATA, python download, pip, CDN paths) |
| `ref:77a2f591a6` | script | scanned .rdata ciphertext blocks, recovered Polygon RPC list, contract address, and eth_call JSON template |
| `ref:4b720339d9` | script | thunk cross-references: CreateProcessW@0x5e2d, connect@0x16d02, getaddrinfo@0x165a1 |
| `ref:adc58b321d` | dynamic analysis platform | real sandbox detonation: 1 candidate process, 6 memory dumps, timeline generated |
| `ref:3113ee7db7` | script | read timeline and network monitoring logs: single process resident, no child processes |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
