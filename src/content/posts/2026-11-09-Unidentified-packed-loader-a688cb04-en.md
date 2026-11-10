---
title: "Malware Analysis: Unidentified packed loader (PE · exe · a688cb04)"
published: 2026-11-09
draft: false
description: "Malicious (low confidence): Unidentified packed loader · loader/injector/backdoor · difficulty hard · Dynamic sandbox + static decompilation"
tags: ["loader", "injector", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-09-Unidentified-packed-loader-a688cb04"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Unidentified packed loader** (uncertain) · Confidence **low**
> 
> Aliases: NGENUITY.exe loader (fake HyperX), furtifivik loader
> 
> The sample is a 64-bit GUI loader: it forges HyperX NGENUITY 4.3.11[.]0 version resources but has no vendor signature; the .didat section carries a 5.77MB payload encrypted with a custom magic; API resolution is hidden through PEB traversal and export-table hashing; at runtime it uses ntdll's XPRESS-HUFF decompression interface to restore a second-stage PE in memory and replaces the module image header inside a running browser process; in real dynamic execution the process repeatedly called back to two domains on port 443 (HTTP POST, X-Campaign-ID: main). Multiple independent pieces of evidence corroborate each other, so it is judged a malicious loader/backdoor dropper.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unidentified packed loader** · aliases NGENUITY.exe loader (fake HyperX), furtifivik loader · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · injector · backdoor |
| Difficulty | hard |
| First seen | 2026-11-06 09:02:31 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/a688cb046e2c5b7be525fc0970b290262f9edd7e2815cf64e7cf1f990bd78e72/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Forge vendor version information</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Pad with unrelated imports as cover</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Hide API resolution behind hashes</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.007</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Embed encrypted compressed payload</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.013</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Implant seven-section PE in memory</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `a688cb046e2c5b7be525fc0970b290262f9edd7e2815cf64e7cf1f990bd78e72` |
| MD5 | _not recorded_ |
| Size | 5,946,368 bytes (5.7 MB) |
| Type | PE · `exe` |

## Behavior analysis

**10** behaviors in total, each backed by evidence; **6** are statically available and **4** were obtained through dynamic analysis.

### 1. Forges vendor version information

`T1036.005` · Confidence **high** · static

The PE version resource is forged as HyperX NGENUITY 4.3.11[.]0 (CompanyName=HyperX, OriginalFilename=NGENUITY.exe), but the security directory is empty with no vendor digital signature, and the import surface does not match genuine peripheral-management software.

> **Evidence**: resource-section version strings HyperX NGENUITY / NGENUITY.exe; SECURITY data directory rva=0,size=0
> 
> **Source**: `ref:c56baa27f7` · `ref:b05e6615f4`

### 2. Pad with unrelated imports as cover

`T1027` · Confidence **medium** · static

Of the import table's 110 symbols, 33 APIs from USER32/GDI32/ADVAPI32/OLE32/SHLWAPI/VERSION have no call/mov reference anywhere in the executable sections and merely make the program look like ordinary GUI software.

> **Evidence**: a full RIP-relative reference scan of IAT range 0x1C000-0x1C3C8 shows only KERNEL32 CRT functions are called
> 
> **Source**: `ref:9c885e6594` · `ref:372bb099b4`

### 3. Hide API resolution behind hashes

`T1027.007` · Confidence **high** · static

It walks the PEB load list to locate kernel32/kernelbase/ntdll by module-name hash, then manually parses export tables to obtain function addresses by hash (djb2 variant with a final XOR 0xF8121CB6).

> **Evidence**: 0x140001000 PEB traversal; 0x140001280 export-table parsing; 0x140001490 name hashing
> 
> **Source**: `ref:fd27a86f36` · `ref:362bbe8f18`

### 4. Embed encrypted compressed payload

`T1027.013` · Confidence **high** · static

The .didat section carries a 5,771,888-byte payload starting with magic 0x3E8F4A71C62B9D05, followed by a 0x50-byte header (with length fields at 0x38/0x3C/0x40) and ciphertext; roughly 55% of the block is zero bytes.

> **Evidence**: .didat RVA 0x2F000, first 8 bytes ed ac a8 64 09 22 96 ee; 0x1400024E0 locates the section by this magic
> 
> **Source**: `ref:362bbe8f18` · `ev-000009`

### 5. Decompresses second-stage payload

`T1140` · Confidence **high** · static

Using hash-resolved RtlGetCompressionWorkSpaceSize / RtlDecompressBufferEx (format 4, XPRESS-HUFF), it decompresses the second-stage data in memory and verifies the custom magic at the head of the output buffer.

> **Evidence**: 0x140003E90 resolves ntdll export hashes 0x39264741/0xB055D003 and calls the decompression routines
> 
> **Source**: `ref:ddc572537f` · `ref:fd27a86f36`

### 6. Implants seven-section PE in memory

`T1620` · Confidence **high** · dynamic

A 2.87MB PE with 7 sections (.text/.rdata/.data/.pdata/.init/.rsrc/.reloc) appears in the sandbox process's private memory at 0x140000000, with its entry point in .init, and it is not a disk-file mapping.

> **Evidence**: memory scan implanted_pe=1, module_size=0x2BD000, mapping_type=MEM_PRIVATE
> 
> **Source**: `ref:d5acbea132` · `ref:c4723712b7`

### 7. Replaces browser image header

`T1055.012` · Confidence **high** · dynamic

The module header of the running msedge.exe process is rewritten (DOS header/NT header/section table/entry point all modified), and the section layout of its 5.98MB image matches the dropped sample exactly (including .didat), consistent with image-replacement injection.

> **Evidence**: memory scan is_pe_replaced=1, section table .data/.textbss/.gfids/.debug/.reloc/.edata/.didat/.rsrc
> 
> **Source**: `ref:c1e9f22260` · `ref:d5acbea132`

### 8. Periodically calls back to two domains

`T1071.001` · Confidence **high** · dynamic

Within about 2.5 minutes the sample process made 14 connection attempts to port 443, with HTTP request Host values furtifivik[.]net and futifivikbaackip[.]net in turn, carrying the request header X-Campaign-ID: main and a 133-byte body.

> **Evidence**: network monitoring: sample.exe (pid 1680) requested TCP 192.0.2[.]123:443; POST Host=furtifivik[.]net, Content-Length: 133
> 
> **Source**: `ref:d239be030d` · `ref:d5acbea132`

### 9. Loads network/crypto components

`T1071` · Confidence **high** · dynamic

At runtime it loads winhttp/ws2_32/dnsapi/mswsock/schannel/crypt32/ncrypt/mskeyprotect/webio and other modules, showing that network and TLS communication is performed in memory and does not appear in the static import table.

> **Evidence**: memory-scan module list includes winhttp.dll, ws2_32.dll, dnsapi.dll, ncrypt.dll, schannel.dll, webio.dll
> 
> **Source**: `ref:d5acbea132` · `ref:372bb099b4`

### 10. Collects host fingerprint for seeding

`T1082` · Confidence **high** · static

It reads system time, performance counter, local time, processor architecture, ACP, temp directory, LCID and keyboard type, and mixes/iterates them with the constant 0x26BFDC68 to generate a seed for payload keys/checks.

> **Evidence**: 0x140005E70 calls GetSystemInfo/GetLocalTime/GetACP/GetKeyboardType/GetUserDefaultLCID/GetTempPathW
> 
> **Source**: `ref:1372433372` · `ref:22ff621437`


## IOC (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually initiated TCP connections to these targets (repeatedly retried within a short period).
:::

:::caution
**Real server side still unverified**: the above connections/handshakes were completed against a local controlled emulation service, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://furtifivik[.]net/` | 443 | c2 | dynamic | observed |
| http | `hxxp://futifivikbaackip[.]net/` | 443 | c2 | dynamic | observed |

### Host

- **No host IOC was recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `furtifivik[.]net; futifivikbaackip[.]net` | yes | dynamic |
| `c2_port` | `443` | yes | dynamic |
| `campaign_id` | `main` | no | dynamic |
| `campaign_header` | `X-Campaign-ID` | no | dynamic |
| `beacon_body_size` | `133` | no | dynamic |
| `payload_container` | `custom header magic 0x3E8F4A71C62B9D05 + stream cipher + XPRESS-HUFF compression` | yes | static |
| `api_hash_seed` | `djb2 variant, final XOR 0xF8121CB6` | no | static |
| `payload_seed` | `0x26BFDC68` | no | static |

## Must not be misjudged

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not treat it as an official or benign file merely because the version resource says HyperX NGENUITY: it has no vendor signature, and its actual behavior is payload decryption/loading and process injection.
- No file encryption, deletion or ransom note was observed, so it cannot be classified as ransomware or a wiper.
- No credential/browser-data reading or exfiltrated content was observed (only a 133-byte beacon was intercepted), so it cannot be asserted to be a stealer.
- The POST body and real C2 IP were not obtained, so no specific IP, URI path or command protocol should be invented.
- No registry/service/scheduled-task telemetry evidence was obtained, so it cannot be claimed that the sample established persistence.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `e59cbf27a4849ccc0f4bd575810ff642cd56ca99151a9793e64d95f3938652e6`) |

**Limitations and pending verification**

1. The second-stage payload was only taken whole from process memory in its image layout, without recovering its complete executable file or internal configuration; its .rdata shows only C++/CRT strings, and the C2 and command-handling logic are further processed in memory.
2. The C2 HTTP body was not retained, only its 133-byte length and the Host/custom headers, so the command protocol and returned content cannot be determined.
3. No telemetry evidence was obtained for registry, services, scheduled tasks, certificate stores or Defender exclusions, so persistence capability is unverified.
4. The replaced msedge.exe image belongs to a browser process already present in the environment; the exact syscall sequence of the injection was not recorded frame by frame and is inferred from memory-scan results.
5. The family cannot be confirmed: no YARA hit, multi-engine verdict or public report is available, so the family field is treated as uncertain.
6. The real dynamic run was observed only in a controlled network environment; the intercepted 192.0.2[.]123 is a network-emulation address and does not represent the real C2 IP.

## Evidence index

<details>
<summary>Expand 21 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hashing & fingerprints | sha256/md5/sha1/imphash computation |
| `ev-000002` | scan.imphash | imphash=e2d31538a87edde17ea0bef61047ecdf |
| `ev-000009` | scan.entropy | .didat section 5,771,888 bytes, entropy 4.575 |
| `ref:b05e6615f4` | PE structure parsing | 8 sections, ImageBase 0x140000000, no SECURITY directory, entry 0x6388 |
| `ref:372bb099b4` | import table parsing | import table with 7 DLLs and 110 symbols |
| `ref:c9ac968992` | string extraction | ASCII/UTF-16 string extraction (including obfuscated strings in .textbss) |
| `ref:c56baa27f7` | manual-parse | resource-section VS_VERSION_INFO: HyperX NGENUITY 4.3.11[.]0 / NGENUITY.exe |
| `ref:362bbe8f18` | decompile.ghidra | 0x1400024E0 locates the .didat section by 0x3E8F4A71C62B9D05 |
| `ref:22ff621437` | decompile.ghidra | 0x140002A30 main flow: locate section, decompress, execute stage-2 |
| `ref:ddc572537f` | decompile.ghidra | 0x140003E90 uses ntdll hash-resolved exports to decompress stage-2 |
| `ref:6f0ca2f8d0` | decompile.ghidra | 0x140001F70 instruction-length decode/validation logic |
| `ref:1372433372` | decompile.ghidra | 0x140005E70 collects host information to generate the seed |
| `ref:fd27a86f36` | manual-script | module/API hash reversal: kernel32=0xC61224C3, kernelbase=0xF29A0B57, ntdll=0x1108B1E7 |
| `ref:9c885e6594` | manual-script | IAT cross-reference scan: imports such as USER32/GDI32/ADVAPI32 have no references |
| `ref:d5acbea132` | dynamic analysis platform | real detonation: pid 1680, 6 process dumps, memory scan finds 1 implanted PE |
| `ref:d239be030d` | manual-script | network log: furtifivik[.]net / futifivikbaackip[.]net, POST 133 bytes, X-Campaign-ID: main |
| `ref:c1e9f22260` | manual-script | msedge.exe process module header replaced; 5.98MB image section layout matches the sample |
| `ref:c4723712b7` | manual-script | extracted a 2.87MB seven-section stage-2 PE from the memory dump, sha256=e59cbf27... |
| `c2_evidence:a688cb04` | connection evidence extraction | dynamic network monitoring recorded 30 connection attempts to furtifivik[.]net:443, futifivikbaackip[.]net:443; no complete session captured |
| `telemetry:a688cb04` | dynamic telemetry | dynamic telemetry recorded: monitoring component process/file events 123; ETW short-lived process events 1; tool/system noise filtered 27 |
| `etw:a688cb04:1680` | process event monitoring | short-lived process event: a688cb046e2c5b7be525fc0970b290262f9edd7e2815cf64e7cf1f990bd78e72.exe (pid 1680; MD5=A6524A72039FAD96888F3982AD018ADD,SHA256=A688CB046E2C5B7BE525FC0970B290262F9EDD7E2815CF64E7CF1F990BD78E72,IMPHASH=E2D31538A87EDDE17EA0BEF61047ECDF) |

</details>

---

_This report's sample is not public, and IOCs are defanged; for security research only._
