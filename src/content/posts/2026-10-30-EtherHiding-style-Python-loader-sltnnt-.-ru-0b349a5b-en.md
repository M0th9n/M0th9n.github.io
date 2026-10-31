---
title: "Malware Analysis: EtherHiding-style Python loader (sltnnt[.]ru) (PE · exe · 0b349a5b)"
published: 2026-10-30
draft: false
description: "Malicious (low confidence): EtherHiding-style Python loader (sltnnt[.]ru) · loader/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["EtherHiding", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-30-EtherHiding-style-Python-loader-sltnnt-.-ru-0b349a5b"
---

> [!WARNING]
> **Verdict: malicious** · Family **EtherHiding-style Python loader (sltnnt[.]ru)** (uncertain) · Confidence **low**
> 
> Aliases: EtherHiding loader, Python RAT installer, NtProfileIndex loader
> 
> Decompilation exposes the full delivery chain: all 16-byte-XOR-obfuscated strings are decrypted in place inside the entry function, yielding 8 Polygon JSON-RPC endpoints and an eth_call contract dead drop (contract 0x9c0a507300fd902787bb193d80fca5ce6e1bff9a, selector 0xce6d41de), the download site sltnnt[.]ru and its /cdn/ paths, the %LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex install directory, and the full logic to download the python-3.12.7 embedded interpreter + get-pip + requirements.txt and then launch app.pyd as python.exe main.py --host --env; the entry also gates on CPU model, system-drive capacity and uptime against sandboxes. Real execution in the sandbox observed the sample relaunching itself as two processes, and the decrypted CPU-model constant is visible in the memory image.

## Overview

| Item | Content |
|:--|:--|
| Family | **EtherHiding-style Python loader (sltnnt[.]ru)** · aliases EtherHiding loader, Python RAT installer, NtProfileIndex loader · _uncertain_ |
| Confidence | **low** |
| Behaviour class | loader · downloader |
| Difficulty | medium |
| First seen | 2026-10-28 19:49:54 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/0b349a5b1a1d1d40b3fbaf1a794c94f569770ce5a9a4bdf8cbeb198627a9da12/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt the string table</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Compare QEMU CPU name</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Exit on disk/uptime checks</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Fetch config via contract</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1102</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Self-copy second launch</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1497.001</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `0b349a5b1a1d1d40b3fbaf1a794c94f569770ce5a9a4bdf8cbeb198627a9da12` |
| MD5 | _not recorded_ |
| Size | 1,139,712 bytes (1.1 MB) |
| Type | PE · `exe` |

## Behaviour analysis

**10** behaviours in total, each tied to evidence; **9** are statically recoverable and **1** was obtained dynamically.

### 1. Decrypt the string table in place

`T1027` · Confidence **high** · static

From entry 0x401011 the sample decrypts more than 40 embedded strings by XORing each character with a 16-byte key (out[i]=key[i&0xf]^data[i]); every URL, path, contract address and command-line argument exists encrypted in the file, invisible to ordinary static string scans.

> **Evidence**: 0x401076 xor r8b,[rax+rcx]; data blocks at rva 0x9eba8 / 0x7796c / 0x77c88, with the 16-byte key immediately after
> 
> **Source**: `ev-000014` · `ev-000012`

### 2. Compare QEMU processor name

`T1497.001` · Confidence **high** · static

Reads ProcessorNameString from HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0 and compares it with the hard-coded "Intel Core Processor (Broadwell)" (the default QEMU CPU model), branching into the capacity gate on a match.

> **Evidence**: RegOpenKeyExA@0x401191 / RegQueryValueExA@0x40233c; strings rva 0x9eba8 / 0x9ebe6 / 0x9ec09
> 
> **Source**: `ev-000015` · `ev-000014` · `ev-000012`

### 3. Exit based on capacity and uptime

`T1497.001` · Confidence **high** · static

Calls GetDiskFreeSpaceExW("C:\\") for total system-drive capacity and GetTickCount64 for uptime: if capacity is below about 105GB, or falls in the roughly 200-240GB range, or uptime is under about 41 minutes, or low memory (<6.5GB) coincides with a particular CPU architecture, it executes a ud2 illegal instruction to crash the process without doing any business action.

> **Evidence**: GetDiskFreeSpaceExW@0x4011b6 / 0x40126b / 0x4023b4, GetTickCount64@0x4011d5, GlobalMemoryStatusEx@0x40120c, crash point 0x4023e1 invalidInstructionException
> 
> **Source**: `ev-000015` · `ev-000012`

### 4. Pull config from a contract dead drop

`T1102` · Confidence **high** · static

Builds {"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x9c0a507300fd902787bb193d80fca5ce6e1bff9a","data":"0xce6d41de"},"latest"],"id":1} and queries 8 public Polygon JSON-RPC endpoints in turn, treating the return value as its config/next-hop source so it keeps working when domains are blocked.

> **Evidence**: JSON templates rva 0x779f4 / 0x77a3a / 0x77a54, contract 0x779a0, selector 0x779da, endpoints 0x77a78-0x77bcf
> 
> **Source**: `ev-000014` · `ev-000012`

### 5. Download payload from sltnnt

`T1071.001` · Confidence **high** · static

With a Chrome/120 User-Agent and the custom header x-cdn-origin-verify: trusted-upstream, it accesses /cdn/5ef451455923, /cdn/e/42a522313d92 and /cdn/e/36f2c0035ef9 on hxxps://sltnnt[.]ru to retrieve requirements.txt, main.py and app.pyd respectively.

> **Evidence**: sltnnt[.]ru rva 0x9d9f8 (reference 0x4022d0); /cdn path references 0x40280b / 0x402b0d / 0x402ba4; UA rva 0x77e61
> 
> **Source**: `ev-000014` · `ev-000012`

### 6. Install a Python runtime environment

`T1105` · Confidence **high** · static

Downloads python-3.12.7-embed-amd64.zip as python.zip and extracts it into the install directory, rewrites python312._pth (toggling between #import site and import site), downloads get-pip.py to bootstrap pip, then runs Scripts\pip.exe to install the requirements.txt dependencies.

> **Evidence**: python[.]org package URL rva 0x77cd4, python.zip 0x77d2a, python312._pth 0x77d5e, get-pip.py 0x77db3, Scripts\pip.exe 0x77e01; references 0x402553-0x4027c0
> 
> **Source**: `ev-000014` · `ev-000012`

### 7. Launch the Python backdoor process

`T1059.006` · Confidence **high** · static

Uses CreateProcessW to start python.exe inside the install directory with a command line containing main.py, app.pyd, --host and --env, distinguishing install / AppHost run modes, then waits for exit with WaitForSingleObject and GetExitCodeProcess.

> **Evidence**: CreateProcessW@0x4075ac (inside main) and 0x405e2d; command-line builder 0x407400-0x4075e6; argument strings 0x77fc7 / 0x78001 / 0x78018 / 0x7802e / 0x77f76 / 0x77f8d
> 
> **Source**: `ev-000015` · `ev-000014`

### 8. Decrypt retrieved files with AES

`T1140` · Confidence **medium** · static

FUN_00407a78 assembles an external-downloader command line of the form "-k -s -X PUT -H ... -o <local file> <URL>" and runs it with CreateProcessW, then reads the file back with NtCreateFile and decrypts it using a base64 32-byte embedded key and the embedded AES S-box/T-tables before use.

> **Evidence**: 0x407a78 arguments "-k"(0x6b2d)/"-s"/"-X"/"PUT"/"-H"/"-o"; NtCreateFile 0x407879; AES tables 0x508180 and 0x4d0240; key rva 0xd01ac
> 
> **Source**: `ev-000013` · `ev-000015`

### 9. Read and write files through native APIs

`T1106` · Confidence **medium** · static

File I/O for dropped files uses NtCreateFile / NtSetInformationFile / ReadFile / WriteFile instead of Win32 high-level wrappers, and GetFileAttributesW probes target paths, making it easier to control the existence and timestamps of dropped files.

> **Evidence**: NtCreateFile@0x407879 / 0x415051, NtSetInformationFile@0x404362 / 0x4078a6, WriteFile@0x415696, GetFileAttributesW@0x40733b
> 
> **Source**: `ev-000015`

### 10. Self-copy second launch

`T1497.001` · Confidence **medium** · dynamic

In the dynamic sandbox the first process (pid 4436) started, and about one second later a second instance (pid 4876) from the same path appeared; both exited before making any network request, consistent with the self-restart + anti-sandbox gate at the entry point.

> **Evidence**: dynamic timeline: pid 4436 born 23:56:11.9, pid 4876 born 23:56:12.9, same path ...\samples\<sha256>.exe; memory image contains the decrypted "Intel Core Processor" constant
> 
> **Source**: `ref:a169437c6a`


## IOCs (defanged)

### Network

:::caution
**The real server side remains unverified**: the connections/handshakes above were completed against a local controlled emulation service; the real C2 responses and delivered content are still unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://sltnnt[.]ru` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://sltnnt[.]ru/cdn/5ef451455923` | 443 | download | static | ⏳ not observed |
| http | `hxxps://sltnnt[.]ru/cdn/e/42a522313d92` | 443 | download | static | ⏳ not observed |
| http | `hxxps://sltnnt[.]ru/cdn/e/36f2c0035ef9` | 443 | download | static | ⏳ not observed |
| http | `hxxps://polygon-rpc[.]com` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://rpc-mainnet[.]matic[.]quiknode[.]pro` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://polygon-public[.]nodies[.]app` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://1rpc[.]io/matic` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://polygon-bor-rpc[.]publicnode[.]com` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://api[.]zan[.]top/polygon-mainnet` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://polygon[.]rpc[.]subquery[.]network/public` | 443 | c2 | static | ⏳ not observed |
| http | `hxxps://endpoints[.]omniatech[.]io/v1/matic/mainnet/public` | 443 | c2 | static | ⏳ not observed |

### Host

**Drop paths**

- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\python.zip`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\python.exe`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\python312._pth`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\get-pip.py`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\Scripts\pip.exe`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\requirements.txt`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\main.py`
- `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex\app.pyd`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `sltnnt[.]ru` | yes | static |
| `c2_paths` | `/cdn/5ef451455923 (requirements.txt); /cdn/e/42a522313d92 (main.py); /cdn/e/36f2c0035ef9 (app.pyd)` | yes | static |
| `blockchain_rpc_endpoints` | `8 Polygon JSON-RPC endpoints: polygon-rpc[.]com / rpc-mainnet.matic.quiknode.pro / polygon-public.nodies.app / 1rpc[.]io/matic / polygon-bor-rpc[.]publicnode[.]com / api[.]zan[.]top / polygon.rpc.subquery.network / endpoints[.]omniatech[.]io` | yes | static |
| `smart_contract` | `0x9c0a507300fd902787bb193d80fca5ce6e1bff9a (eth_call selector 0xce6d41de, config dead drop)` | yes | static |
| `install_path` | `%LOCALAPPDATA%\Microsoft\Windows\NtProfileIndex` | yes | static |
| `payload_argv` | `python.exe main.py --host <c2> --env <env> (mode: install / AppHost)` | yes | static |
| `encryption_algo` | `AES (embedded 32-byte key, base64 "dK9mT3nR7xQ2pL8wF4jH6yB1cN5gA0sZ12345678abc=") + 16-byte XOR string obfuscation + ChaCha20-Poly1305 (TLS session)` | yes | static |
| `user_agent` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0[.]0 Safari/537.36` | no | static |
| `http_header` | `x-cdn-origin-verify: trusted-upstream` | no | static |
| `campaign_id` | `3003170a-66f7-4989-943f-b16099549156` | no | static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- It cannot be classified as ransomware or a wiper: no file-encryption loop, shadow-copy deletion, extension rewriting or ransom note was seen, and no ransom note was generated in the sandbox.
- It cannot be classified as a stealer: no reads of browser credential stores, cryptocurrency wallets or chat-app data were observed; the app.pyd that performs the actual theft was not retrieved, so its capability is unknown.
- Do not claim registry Run keys, services or scheduled tasks were established for persistence: the import table only contains RegOpenKeyExA/RegQueryValueExA reads (to read the CPU name), with no registry-writing API at all; no evidence of a persistence mechanism was obtained.
- Do not treat python[.]org and bootstrap[.]pypa[.]io as malicious infrastructure: they are official distribution sites, used only to obtain the legitimate Python runtime and pip.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | no |

**Limitations and pending verification**

1. The payload stage never triggered: the sandbox is a fresh VM whose system-drive capacity and uptime fall inside the sample's exclusion ranges, so the sample deliberately crashed with ud2 before downloading; the actual sltnnt[.]ru and Polygon RPC requests were therefore not observed by network monitoring, and all C2/config data comes from static decryption (pending_dynamic_verify=true).
2. app.pyd / main.py / requirements.txt were not retrieved, so the specific function of the downstream Python payload (remote control, theft or otherwise) cannot be confirmed; the behaviour classification covers only the loader itself.
3. The AES ciphertext stored in the same section as the 32-byte key could not be decrypted offline: the decrypted config depends on data retrieved from C2 or the contract and is not available statically.
4. No evidence of a persistence mechanism was obtained: the entry logic contains no registry writes, service or scheduled-task creation; persistence may happen in the Python stage and cannot be verified.
5. Dynamically only two process creations and exits were observed; no child process, file write or injection was captured, and memory scanning found no hooks or module replacement.

## Evidence index

<details>
<summary>Expand 14 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1 and file size 1139712 |
| `ev-000002` | scan.imphash | imphash=73f461c771aef77ec43d53a0c54f0c8d |
| `ev-000003` | scan.entropy | .text entropy 6.369, no high-entropy sections |
| `ev-000010` | String extraction | Static string scan: 1392 ASCII strings, no cleartext URLs/paths (all obfuscated) |
| `ev-000011` | decompile.function | entry@0x401000 only calls 0x401011 then RtlExitUserProcess |
| `ev-000012` | decompile.function | main@0x401011: string decryption + anti-sandbox gate + config parsing + download/install chain |
| `ev-000013` | decompile.function | FUN_00407a78@0x407a78: external-downloader command-line assembly + read-back + AES decryption |
| `ev-000014` | Scripted forensics | Reproduced the XOR string decryption, outputting 44 cleartext config items |
| `ev-000015` | Scripted forensics | Back-traced import stubs to the actual call sites of 48 APIs |
| `ref:b0ed339b24` | PE structure parser | PE structure: AMD64/7 sections/no resources/no Rich/48 imports |
| `ref:726d7c905c` | Import table parser | Import surface: ntdll/kernel32/advapi32/crypt32/ws2_32 |
| `ref:4ccabd3fb2` | unpack.detect | Not packed (packed=false) |
| `ref:a169437c6a` | Dynamic analysis platform | Dynamic detonation: 2 candidate processes, timeline and memory image packed, no network/file behaviour |
| `ref:5a0de6c0e2` | cfg.function | 177 basic blocks and call targets of main |

</details>

---

_The sample behind this report is not public; IOCs are defanged. For security research only._
