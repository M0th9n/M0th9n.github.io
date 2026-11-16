---
title: "Malware Analysis: VRM Stealer (Credential Stealer Delivered by Private/Custom Crypter) (PE · exe · 9a9646a9)"
published: 2026-11-15
draft: false
description: "Malicious (medium confidence): VRM Stealer (credential stealer delivered by a private/custom crypter) · stealer · difficulty hard · static decompilation (dynamic execution produced no runtime behavior)"
tags: ["VRM", "stealer", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-15-VRM-Stealer-私有-定制-crypter-投递的凭据窃取器-9a9646a9"
---

> [!WARNING]
> **Verdict: Malicious** · Family **VRM Stealer (credential stealer delivered by a private/custom crypter)** (uncertain) · Confidence **Medium**
> 
> The file is a self-decrypting payload loader: main(0x140002a30) locates a container header (magic 0x9f8a3bb43f221fc7) inside the image's own randomly named section 'zdvylx' (RVA 0x2F000), de-interleaves 240-byte data runs / 240-byte holes, decrypts with AES-256-CBC using the container-embedded 32-byte key and 16-byte IV (restored via an xorshift32 stream), then calls RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF) to produce a 2,806,223-byte inner image, checks magic 0x3e8f4a71c62b9d05, maps it into memory per a custom section table and transfers execution. This report reproduces the entire decrypt/decompress chain; the recovered inner code is a credential stealer: it embeds a full SQLite3 engine to read Chromium-family browser databases, with strings for Chrome / Edge / Brave / Opera / Opera GX, '\Local State', '-wal'/'-shm', Telegram 'tdata\'/'user_data'/'media_cache'/'stickers', wallets 'PRIVATE_KEY|0x'/'keyRingType'/'keyRingName'/'mnemonic/' and 'steamid:', plus winhttp network-stack placeholder strings and the uplink JSON fields '"build_id":' / '"hwid":'. The outer version resource masquerades as Blue Microphones' Blue Sherpa 2.2.0[.]0, a typical lure disguise.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **VRM Stealer (credential stealer delivered by a private/custom crypter)** · _uncertain_ |
| Confidence | **Medium** |
| Behavior class | stealer |
| Difficulty | hard |
| First seen | 2026-11-13 12:11:59 |
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/9a9646a99eca2179c1e92a44ce11ca437b55a41fdf4c140bf3554bf30dfcb736/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">De-interleave compressed blob</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Decompress inner image</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Hash-resolve hidden APIs</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Map into memory and run</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `9a9646a99eca2179c1e92a44ce11ca437b55a41fdf4c140bf3554bf30dfcb736` |
| MD5 | _not recorded_ |
| Size | 5,357,568 bytes (5.1 MB) |
| Type | PE · `exe` |

## Behavior Analysis

**11** behaviors in total, each backed by evidence, and all are statically available.

### 1. Decrypt embedded encrypted payload

`T1140` · Confidence **High** · Static

main extracts 32 bytes of key material and 16 bytes of IV material from its own 'zdvylx' section, restores them via XOR with an xorshift32(seed=0xfcdc579a) keystream, then performs AES-256-CBC decryption through BCryptOpenAlgorithmProvider("AES") + ChainingModeCBC (ciphertext 2,591,616 bytes).

> **Evidence**: 0x140003cd0 / 0x140003bd0 keystream restoration; 0x140003830 contains bcrypt.dll strings, "AES", "ChainingModeCBC" and BCryptDecrypt calls; section 'zdvylx' RVA 0x2F000
> 
> **Source**: `ev-000024` · `ev-000021` · `ev-000022` · `ev-000023`

### 2. De-interleave to extract the compressed blob

`T1027` · Confidence **High** · Static

Before decryption it copies blocks according to container header fields 0x38/0x3C/0x40/0x44/0x48: after every 240 bytes of valid data it skips a 240-byte hole, rearranging the 5,183,488-byte section content into 2,591,616 contiguous ciphertext bytes.

> **Evidence**: Loop at 0x140002a30 calling FUN_14001a7b0; header fields [+0x40]=0x278b80, [+0x44]=0x600, [+0x48]=0x00f000f0
> 
> **Source**: `ev-000017`

### 3. Decompress to recover the inner image

`T1027` · Confidence **High** · Static

The decrypted result is passed to RtlDecompressBufferEx (format 4 = XPRESS Huffman) and decompressed into a 2,806,223-byte inner image; it verifies that the first 8 bytes equal 0x3e8f4a71c62b9d05, reads 7 section-table entries of 28 bytes each, and rebuilds the image in memory.

> **Evidence**: At 0x140003e90, FUN_140001280(0xe345ccb3)/FUN_140001280(0x6a365bf1) calls (4, dst, size, src, size, &out, ws); check constant 0x3e8f4a71c62b9d05 near 0x140003ffb
> 
> **Source**: `ev-000020` · `ev-000019`

### 4. Hash-resolve hidden APIs

`T1027` · Confidence **High** · Static

It resolves APIs by walking module export tables with a custom hash h = (c|0x20) ^ (h*0x21), h^=0x22719744, avoiding exposure of sensitive function names such as VirtualAlloc / CreateThread / RtlDecompressBufferEx / BCrypt* in the import table.

> **Evidence**: Hash function at 0x1400014c0; export-table walk by hash at 0x140001000; compression-related APIs fetched with 0xe345ccb3 / 0x6a365bf1 at 0x140003e90
> 
> **Source**: `ev-000018` · `ev-000020`

### 5. Map into memory and execute

`T1620` · Confidence **High** · Static

The recovered inner image never touches disk: it allocates memory per the section table, copies .text/.rdata/.data/.pdata/.init/.rsrc/.reloc sections and applies relocations, then hands control to the inner entry point (0x140003e90 assembles the structure, and main continues the call).

> **Evidence**: At 0x140003e90, a 28-byte section-table loop copy (piVar17 advances by 7 dwords) + FUN_140004820/FUN_140003520 write the image
> 
> **Source**: `ev-000020` · `ev-000017`

### 6. Masquerade as an audio-software publisher

`T1036.005` · Confidence **High** · Static

The version resource is forged as Blue Microphones LLC's Blue Sherpa 2.2.0[.]0 (OriginalFilename BlueSherpa.exe, LegalCopyright 2025), unrelated to its real function, to lower the vigilance of users and endpoint protection.

> **Evidence**: .rsrc version information: CompanyName 'Blue Microphones LLC', FileDescription 'Blue Sherpa', OriginalFilename 'BlueSherpa.exe'
> 
> **Source**: `ev-000010` · `ev-000013`

### 7. Steal browser credentials

`T1555.003` · Confidence **High** · Static

The inner code embeds a full SQLite3 engine (including 'SQLite format 3', sqlite_master queries, json_* functions, -wal/-shm handling) and hardcodes Chrome / Edge / Brave / Opera / Opera GX with '\Local State', 'ReadCookie'/'SetCookie' and other symbols, used to read cookies, login data and autofill databases.

> **Evidence**: Recovered image .rdata from offset 0x2E1xx: 'Chrome','Edge','Brave','Opera','Opera GX','/Local State','-wal','-shm','_meta.json'; SQLite engine strings ('SQLite format 3', 'sqlite_master')
> 
> **Source**: `ev-000020`

### 8. Steal Telegram sessions

`T1555` · Confidence **High** · Static

Hardcodes the Telegram Desktop data directory structure 'tdata\\', 'user_data', 'media_cache', 'mediaCache', 'stickers', 'emoji_cache', used to package session data (tdata allows direct account takeover).

> **Evidence**: Recovered image .rdata near offset 0x1F8xx: 'tdata\', 'user_data', 'mediaCache', 'media_cache', 'stickers', 'emoji_cache', 'dumps'
> 
> **Source**: `ev-000020`

### 9. Harvest wallet private keys and mnemonics

`T1552.001` · Confidence **Medium** · Static

Contains wallet/keystore signature strings 'PRIVATE_KEY|0x', 'keyRingType', 'keyRingName', 'keyhex', 'mnemonic/', 'steamid:', indicating it enumerates local crypto wallets and Steam session files and extracts private keys/mnemonics.

> **Evidence**: Recovered image .rdata offsets 0x20Bxx-0x22Cxx: 'PRIVATE_KEY|0x','keyRingType','keyRingName','keyhex','mnemonic/','steamid:'
> 
> **Source**: `ev-000020`

### 10. Report host fingerprint

`T1041` · Confidence **High** · Static

The inner module wraps HTTP sessions with winhttp (placeholder strings 'winhttpopen=', 'connect=', 'openreq=', 'send=', 'recv=', ' body=', 'http='), and reports host fingerprints and stolen results to the server as JSON containing '"build_id":', '"hwid":', '"data":'; uplink data is encrypted with AES-GCM ('[AES-GCM failed]', '[no AES key]', ECDH_P256/HASH).

> **Evidence**: Recovered image .rdata offset 0x1E4xx (build_id/hwid), 0x1F9xx (winhttp placeholders), 0x1FE4x ([AES-GCM failed]); import string table includes winhttp/BCrypt family
> 
> **Source**: `ev-000020`

### 11. Detect debuggers

`T1622` · Confidence **Medium** · Static

The inner module imports/uses NtQueryInformationProcess (commonly paired with ProcessDebugPort/ProcessDebugFlags checks), and the outer layer also imports IsDebuggerPresent, used to curb behavior under debugging.

> **Evidence**: Recovered image import string table includes 'NtQueryInformationProcess' (.rdata 0x1E3xx); outer layer imports IsDebuggerPresent (iat_rva 0x1C190)
> 
> **Source**: `ev-000020` · `ev-000003`


## IOCs (defanged)

### Network

:::note
**No C2 / network IOCs were recovered** (see "Analysis Method and Limitations" at the end for the reason).
:::

### Host

- **No host IOCs were recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `crypter_encryption_algo` | `AES-256-CBC (BCrypt, key/IV restored from the container header via an xorshift32 stream)` | Yes | Static |
| `payload_container_magic` | `0x9f8a3bb43f221fc7 (locates the section) / 0x3e8f4a71c62b9d05 (inner image)` | Yes | Static |
| `payload_compression` | `RtlDecompressBufferEx, COMPRESSION_FORMAT_XPRESS_HUFF (4)` | Yes | Static |
| `payload_storage_layout` | `alternating 240-byte data blocks + 240-byte holes` | Yes | Static |
| `build_pdb_path` | `C:\Users\Administrator\Desktop\Desktop\vrm new\out\release\app.pdb` | No | Static |
| `c2_hosts` | `unknown (no plaintext domain/URL recovered from static data)` | Yes | Static |

## What Not to Misjudge

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not report it as ransomware / wiper: no file-encryption loop, extension rewriting or ransom-note strings were found; the inner behavior surface is credential collection.
- Do not claim real C2 egress or a C2 session was observed in the sandbox: this sandbox run retrieved no successful session, the C2 count is zero, and network behavior is only a static capability inference.
- Do not assert the sample wrote registry entries, created services or scheduled tasks: no corresponding dynamic telemetry was obtained, and the registry/service/task entries under host_iocs are empty.
- Do not treat 'Blue Microphones / Blue Sherpa' as legitimate software signed by a real publisher: the version resource contradicts the self-decrypting loader chain and is a disguise.
- Do not confirm a specific commercial family name (such as Lumma / Vidar / RedLine): the build path 'vrm new' alone only supports candidates marked uncertain.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (dynamic execution produced no runtime behavior) |
| Unpacking | Yes (stage2 `303b3b6b00c61ec77fef4cb4c8f7440c4c2af3e9c1d44b6d93c5d06a7f5e9ab8`) |

**Limitations and pending verification**

1. Both sandbox runs (revert->start->drop->poll->artifact collection) timed out at the interface layer, and the sample was not confirmed executed within the observation window; therefore reproduced=false, C2 is empty, and there is no network/registry/file dynamic evidence.
2. Plaintext C2 domains, URI and port were not recovered: the inner configuration appears to be derived at runtime (the string region contains many non-plaintext printable sequences) and the uplink uses ECDH_P256 + AES-GCM, so the endpoints were not solved statically.
3. The inner image is a custom container with the MZ header removed and cannot run directly as a standalone PE; it has not yet been single-stepped to network initialization in an emulator.
4. Family attribution rests only on the build path 'vrm new' and the log name 'VRM-%04d%02d%02d', lacking vendor naming or YARA-rule cross-validation.
5. 'NtQueryInformationProcess' appears only in the import string table; the specific detection logic was not confirmed at the disassembly level, hence medium confidence.

## Evidence Index

<details>
<summary>Expand 14 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000003` | Sample triage | 8 sections, 'zdvylx' occupies 5,183,456 bytes (entropy 4.981), no packing signals; imports 108 symbols |
| `ev-000010` | scan.entropy | .rsrc entropy 2.872, containing only a 1 KB version resource |
| `ev-000013` | String extraction | Overview of outer ASCII/UTF-16 strings, no plaintext URLs seen |
| `ev-000015` | decompile.ghidra | __scrt_common_main_seh: standard MSVC startup flow, calls main(0x140002a30) |
| `ev-000017` | decompile.ghidra | main(0x140002a30): locate container -> de-interleave block copy -> decrypt -> decompress -> map |
| `ev-000018` | decompile.ghidra | 0x1400014c0 API hash function (0x1505/0x21/0x22719744) |
| `ev-000019` | decompile.ghidra | 0x1400024e0 locates the container by section-head 8-byte 0x9f8a3bb43f221fc7, returning the section base and +0x50 data region |
| `ev-000020` | decompile.ghidra | 0x140003e90: RtlGetCompressionWorkSpaceSize/RtlDecompressBufferEx(4), verifies 0x3e8f4a71c62b9d05 and rebuilds the 7-entry section table |
| `ev-000021` | decompile.ghidra | 0x140003cd0: XORs 32 bytes of key material with an xorshift32 stream |
| `ev-000022` | decompile.ghidra | 0x140003bd0: warms up 9 rounds then XORs 16 bytes of IV material |
| `ev-000023` | decompile.ghidra | 0x140004310: xorshift32 (<<13, >>17, <<5) |
| `ev-000024` | decompile.ghidra | 0x140003830: bcrypt.dll / AES / ChainingModeCBC / BCryptGenerateSymmetricKey / BCryptDecrypt |
| `ev-000025` | decompile.ghidra | 0x140001f70: custom byte-stream decoder (alternate 0x20 flag branch) |
| `telemetry:9a9646a9` | Dynamic telemetry | Dynamic telemetry recorded: monitoring components registry events 4; monitoring components process/file events 85; system service events 4; filtered tool/system noise 27 |

</details>

---

_This report's sample is not public, IOCs are defanged, and it is for security research only._
