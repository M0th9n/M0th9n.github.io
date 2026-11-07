---
title: "Malware Analysis: Hijack Loader (IDAT) candidate (PE · exe · 5bf9af44)"
published: 2026-11-07
draft: false
description: "Malicious (low confidence): Hijack Loader (IDAT) candidate · loader/downloader · difficulty medium · Dynamic sandbox analysis + static decompilation"
tags: ["Hijack", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-07-Hijack-Loader-IDAT-候选-5bf9af44"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Hijack Loader (IDAT) candidate** (uncertain) · Confidence **low**
> 
> Aliases: IDAT Loader, signed-binary loader, signature-abuse downloader
> 
> After launch the sample downloads an encrypted payload from a public cloud drive, decrypts it in memory, and manually maps and executes it; in an isolated sandbox an HTTP download request exactly matching the embedded string was dynamically observed; its 360 code signature check returns HashMismatch (the content was modified after signing), making it a signature-abuse + downloader/loader chain.

## Overview

| Item | Content |
|:--|:--|
| Family | **Hijack Loader (IDAT) candidate** · aliases IDAT Loader, signed-binary loader, signature-abuse downloader · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · downloader |
| Difficulty | medium |
| First seen | 2026-11-06 00:40:23 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/5bf9af4450ec63c2b592f054ba876cb40b96678363d8bdc49455e9a7dd3bfcd9/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Tamper 360 signature</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1553.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Stage-2 hidden in resource</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Decrypt resource to RWX</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Download payload over HTTP</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">AES-decrypt the download</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `5bf9af4450ec63c2b592f054ba876cb40b96678363d8bdc49455e9a7dd3bfcd9` |
| MD5 | _not recorded_ |
| Size | 1,152,272 bytes (1.1 MB) |
| Type | PE · `exe` |

## Behavior analysis

**8** behaviors in total, each backed by evidence; **7** are statically available and **1** was obtained through dynamic analysis.

### 1. Tamper with the 360 signature

`T1553.002` · Confidence **high** · static

The file carries a VeriSign code signature from QIHU 360 SOFTWARE CO. LIMITED, but the Authenticode check returns HashMismatch, indicating the content was modified after signing — signature abuse to reduce alerts.

> **Evidence**: Authenticode check: Status=HashMismatch, Signer=CN=QIHU 360 SOFTWARE CO. LIMITED (Symantec Class 3 SHA256 Code Signing CA)
> 
> **Source**: `ev-000024`

### 2. Stage-2 payload hidden in a resource

`T1027.009` · Confidence **high** · static

The Delphi host stores 203,508 bytes of high-entropy data in a custom resource type rtirtwerqq / name tjertier6 (the first 4 bytes are the payload length 202,240), carrying the next stage without relying on external files.

> **Evidence**: resource RVA 0xE3C7C, size 0x31AF4; first field 0x31600; at 0x4C9852 push 'tjertier6'/'rtirtwerqq' then call resource stream creation
> 
> **Source**: `ev-000022` · `ev-000011` · `ev-000010`

### 3. Decrypt the resource into RWX memory

`T1620` · Confidence **high** · static

The entry FormCreate allocates PAGE_EXECUTE_READWRITE memory via GetProcAddress(GetModuleHandleA('kernel32'),'VirtualAlloc'), de-pads and reorders rows from 322 to 320 bytes, applies position-dependent XOR decoding, and finally jumps into the freshly decrypted executable buffer with push/ret.

> **Evidence**: 0x4C9877 GetModuleHandleA('kernel32'); 0x4C987D GetProcAddress('VirtualAlloc'); 0x4C98A1/0x4C98C1 VirtualAlloc(size+0x140, MEM_COMMIT=0x1000, PAGE_EXECUTE_READWRITE=0x40); 0x4C99CB ret jump
> 
> **Source**: `ev-000019` · `ev-000022`

### 4. Download payload over HTTP

`T1105` · Confidence **high** · dynamic

The second-stage PE builds InternetOpenA/InternetConnectA/HttpOpenRequestA/HttpSendRequestA requests to download a file identified by a Google Drive id from drive[.]usercontent[.]google[.]com; the sandbox network log shows a GET request exactly matching the embedded string.

> **Evidence**: 0x401975 contains InternetOpenA/InternetConnectA(port 0x50)/HttpOpenRequestA/HttpSendRequestA; 0x42A1A8 URL constant; network log 03:04:47 GET /download?id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY...
> 
> **Source**: `ev-000015` · `ev-000023` · `ev-000012`

### 5. AES-decrypt the downloaded content

`T1140` · Confidence **high** · static

It uses CryptoAPI (Microsoft Enhanced RSA and AES Cryptographic Provider) to derive an AES-128 key from a SHA-256 hash and CryptDecrypt the downloaded data in 160-byte blocks, yielding the executable next stage.

> **Evidence**: 0x402F8D: CryptAcquireContextW → CryptCreateHash(0x800C) → CryptHashData → CryptDeriveKey(0x660E) → CryptDecrypt loop, block size 0xA0
> 
> **Source**: `ev-000018` · `ev-000012`

### 6. Manually map the PE and call an export

`T1129` · Confidence **high** · static

It manually maps the decrypted buffer as a PE (validating DOS/NT headers, section alignment, allocating and rewriting page protections), then resolves exports by ordinal/name and calls updateSW, executing the payload without dropping it to disk.

> **Evidence**: mapping error strings such as 'DOS header is not valid!'/'Signature != IMAGE_NT_SIGNATURE!'/'alignedImageSize != AlignValueUp!'; at 0x4041A9 it resolves 'updateSW' and then calls (*pcVar11) in a loop
> 
> **Source**: `ev-000017` · `ev-000016` · `ev-000012`

### 7. Write registry persistence

`T1547.001` · Confidence **medium** · static

It uses RegCreateKeyExA/RegSetValueExA to create a subkey under HKEY_CURRENT_USER and write a REG_SZ value; the key/value names are decrypted at runtime from an embedded passphrase.

> **Evidence**: 0x40467A RegCreateKeyExA(hKey=0x80000001=HKEY_CURRENT_USER, ...); 0x4046BE RegSetValueExA(type=REG_SZ)
> 
> **Source**: `ev-000017` · `ev-000012`

### 8. Random delays to evade sandboxes

`T1497.003` · Confidence **high** · static

After startup it sleeps for a random 1000–5000 ms, and the download/load loop retries with Sleep(2000–3000 ms), stretching the sandbox observation window and reducing automated-analysis success rates.

> **Evidence**: 0x4041A9: Sleep(random 1000~4000); Sleep(3000) in the loop; 0x404800: Sleep(random 1000~5000); 0x40457F Sleep(2000) in the loop
> 
> **Source**: `ev-000016` · `ev-000017`


## IOC (defanged)

### Network

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://drive[.]usercontent[.]google[.]com/download?id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY&export=download&authuser=0&confirm=t` | 80 | download | dynamic | — |

### Host

**Dropped paths**

- `%TEMP%\<runtime-decrypted directory>\service (built by concatenating '/service' onto the GetTempPathA result)`

**Registry**

- `HKCU\<runtime-decrypted subkey> (RegCreateKeyExA/RegSetValueExA writes REG_SZ)`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `drive[.]usercontent[.]google[.]com` | yes | dynamic |
| `download_url` | `hxxp://drive[.]usercontent[.]google[.]com/download?id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY&export=download&authuser=0&confirm=t` | yes | dynamic |
| `http_headers` | `Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1 ; Accept-Language: ru-RU,ru;q=0.9,en;q=0.8 ; Accept-Charset: iso-8859-1, utf-8, utf-16, *;q=0.1 ; Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0` | no | static |
| `encryption_algo` | `AES-128 (CALG_AES_128, CryptoAPI), key derived by SHA-256 (CALG_SHA_256) from an embedded passphrase string; the passphrase constant A1B2C3D4E5F6G7H8 is statically visible` | yes | static |
| `export_name` | `updateSW` | yes | static |
| `persistence` | `RegCreateKeyExA + RegSetValueExA(REG_SZ) under HKEY_CURRENT_USER` | no | static |
| `campaign_markers` | `mixeleven / mixtwelve / mixthirt / mixsix / uniqjjtwo / /service` | no | static |
| `stage2_sha256` | `551600eccf6cd51db03d465b96218e286acba1056eab90c01e4d17b336c57cc1` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- Do not assert that this file is a legitimate 360 program: its digital signature check returns HashMismatch, meaning the content was modified after signing.
- Do not assert that the final payload family and purpose are confirmed: the downloaded content was intercepted by the isolated network and the real next-stage sample was not obtained.
- Do not assert ransomware/file-encryption behavior: no file encryption, ransom note, or shadow-copy deletion was observed in this run.
- Do not assert that the public cloud drive address is itself a traditional C2 server: it is a payload hosting/download point, and no command-and-control channel was observed.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `551600eccf6cd51db03d465b96218e286acba1056eab90c01e4d17b336c57cc1`) |

**Limitations and open questions**

1. The second stage's registry subkey, written value name, drop directory name, mutex and other strings are encrypted at runtime, and their exact text could not be recovered statically.
2. The final downloaded payload was not obtained (the network was isolated and redirected, returning non-real content), so the next-stage family and C2 cannot be given.
3. Memory forensics was collected about 34 seconds after launch, possibly before the random delay ended, so the mapped payload image was not captured; memory scanning reported no injected/hollowed modules.
4. Sandbox polling found no new child processes; the payload executes inside the original process as an exported function, which is expected behavior rather than the sample failing to run.
5. The family name is a candidate (low confidence), based only on the combination of tradecraft, lacking public fingerprint or configuration-field corroboration.

## Evidence index

<details>
<summary>Show 13 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprints | Sample sha256/md5/imphash |
| `ev-000002` | scan.imphash | imphash=3427ca46131c1a1a2c4ea2922a963ba0 |
| `ev-000010` | scan.entropy | .rsrc entropy 7.249 (high) |
| `ev-000011` | String extraction | Host strings and Delphi resource strings |
| `ev-000012` | String extraction | stage2 strings: Google Drive URL, updateSW, /service, AES passphrase, etc. |
| `ev-000015` | decompile.ghidra | stage2 HTTP download function FUN_00401975 |
| `ev-000016` | decompile.ghidra | stage2 main flow: download → AES decrypt → map → call updateSW |
| `ev-000017` | decompile.ghidra | stage2 install/registry/delay and path logic FUN_00404800 |
| `ev-000018` | decompile.ghidra | stage2 CryptoAPI AES-128 decryption function FUN_00402F8D |
| `ev-000022` | evidence.record | Resource decryption recovered the stage2 PE (sha256 5516...) |
| `ev-000023` | evidence.record | Sandbox network log observed the cloud-drive download request (with stage2 characteristic request headers) |
| `ev-000024` | evidence.record | Authenticode check HashMismatch, signer 360 |
| `c2_evidence:5bf9af44` | Connection evidence extraction | Dynamic network monitoring recorded 1 connection attempt to maps[.]windows[.]com:443; no complete session was captured |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
