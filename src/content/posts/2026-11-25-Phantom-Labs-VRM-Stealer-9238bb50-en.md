---
title: "Malicious sample analysis: Phantom-Labs VRM Stealer (PE · exe · 9238bb50)"
published: 2026-11-25
draft: false
description: "Malicious (confidence: medium): Phantom-Labs VRM Stealer · stealer/loader · difficulty hard · dynamic sandbox + static decompilation"
tags: ["Phantom-Labs VRM", "stealer", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-25-Phantom-Labs-VRM-Stealer-9238bb50"
---

> [!WARNING]
> **Verdict: malicious** · Family **Phantom-Labs VRM Stealer** (doubtful) · Confidence **medium**
> 
> Aliases: VRM Stealer, phantom-labs.vault stealer
> 
> The file masquerades as audio-device companion software Blue Sherpa 2.2.0[.]0 (Blue Microphones LLC) but is actually a self-decrypting dropper: at runtime it decrypts an embedded container into a 2.88 MB 64-bit PE and executes it in private executable memory at the original base 0x140000000; the in-memory payload uses WinHTTP to call back to heysunlab[.]fun:443 via HTTPS POST /sync, carrying a fixed auth header X-Auth-Token and an ephemeral ECDH public key, and reads Steam login state (loginusers, steamid, web_secure, CEF cookies) before encrypting and exfiltrating it. The file has no digital signature, its section names are scrambled, it has no Rich header, and the debug directory holds forged content. All of the above behavior was directly observed in a real run (memory forensics detected the implanted PE, and network monitoring captured the full request headers and body).

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **Phantom-Labs VRM Stealer** · Aliases VRM Stealer, phantom-labs.vault stealer · _doubtful_ |
| Confidence | **medium** |
| Behavior class | stealer · loader |
| Difficulty | hard |
| First seen | 2026-11-25 09:44:59 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/9238bb50f85bd34f3c8127ef7860e6df0ceb631f3c1d0be546716e36ef35aa0f/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt and release PE in memory</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Parse embedded encrypted container</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Spoof vendor version info</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Resolve system APIs by hash</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.007</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Steal Steam session tokens</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1555</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `9238bb50f85bd34f3c8127ef7860e6df0ceb631f3c1d0be546716e36ef35aa0f` |
| MD5 | _Not recorded_ |
| Size | 5,802,496 bytes (5.5 MB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **10** behaviors in total, each backed by evidence; **5** are statically available and **5** were obtained through dynamic analysis.

### 1. Decrypt and release PE payload in memory

`T1027.009` · Confidence **high** · Dynamic

The process maps a 2.88 MB 64-bit PE (7 sections, .text about 2.39 MB) at base 0x140000000 in MEM_PRIVATE + PAGE_EXECUTE_READWRITE private memory; this region is not a loaded module but an independent image implanted at runtime.

> **Evidence**: memory scan report implanted_pe=1, module 140000000 size 0x2bd000, protection 0x40, mapping MEM_PRIVATE; dump file 140000000.exe sha256 6b295a1bca1d887e253d958cf1d8edf31935ba85198aa48a81849d087dda7888
> 
> **Source**: `ref:310897aeb1` · `ref:1af92d4316`

### 2. Parse the embedded encrypted container

`T1027.009` · Confidence **high** · Static

main first walks the PE section table and finds the container section whose first 8 bytes are 0x9E3779B97F4A7C15 (RVA 0x2F000, size 0x55E200), then reassembles the container into a contiguous buffer from sparse records of 192-byte data blocks at a fixed stride, validates the sub-block magic 0x3e8f4a71c62b9d05, and parses 0x1c-byte table entries.

> **Evidence**: FUN_1400024e0 compares 0x9E3779B97F4A7C15; FUN_140003e90 validates 0x3e8f4a71c62b9d05 and iterates in 0x1c-byte steps; section RVA 0x2F000 capacity 5,628,416 bytes
> 
> **Source**: `ref:a9e6e0427b` · `ref:b371c7f942` · `ref:4227a0d254`

### 3. Spoof vendor version information

`T1036.005` · Confidence **high** · Static

The resource section carries complete version information for Blue Microphones LLC / Blue Sherpa 2.2.0[.]0 / BlueSherpa.exe, but the file has no Authenticode signature; the PE section table has been rewritten with misplaced and duplicate names such as .sxdata/.textbss/.idata/.tls/.edata, the Rich header is missing, and the debug directory is forged (type 13, pointing at the COFF symbol-name area).

> **Evidence**: pe.parse: 8 sections with duplicate .sxdata/.edata, rich=false, SECURITY directory 0; UTF-16 version strings Blue Sherpa / 2.2.0[.]0; VS_VERSION_INFO in .rsrc
> 
> **Source**: `ref:4227a0d254` · `ref:36525b2e30` · `ref:d6d4f57db2`

### 4. Resolve system APIs by hash

`T1027.007` · Confidence **medium** · Static

The outer program does not call key routines through a normal import table; it looks up module handles and exported functions by constant hashes (e.g. 0xd5a13ff for the module, 0x2574e559/0xac07721b for functions), and during container parsing it completes decryption and validation through function-pointer callbacks.

> **Evidence**: FUN_140001000(0xd5a13ff) followed by FUN_140001280(handle,0x2574e559)/0xac07721b, returning function pointers that are called in FUN_140003e90
> 
> **Source**: `ref:b371c7f942` · `ref:adb3774aa3`

### 5. Steal Steam session tokens

`T1555` · Confidence **high** · Dynamic

The payload decrypts Steam credential-collection logic in memory: it parses loginusers records, outputs account/steamid/token/web_secure fields, and counts cookies (including CEF storage) and pairs; for accounts whose tokens cannot be decrypted it records diagnostics rather than skipping them.

> **Evidence**: in-memory plaintext strings loginusers, steamid: , web_secure: , -> cookies= , # diag: cef , account: (web-session) , # diag: loginusers not read, etc.
> 
> **Source**: `ref:7309bcedf5` · `ref:661eedc6ad`

### 6. ECDH-encrypted data upload

`T1573.001` · Confidence **high** · Dynamic

The payload imports and calls BCryptGenerateKeyPair/BCryptExportKey/BCryptSecretAgreement/BCryptDeriveKey to perform ephemeral ECDH negotiation, then wraps the uploaded content with AES-GCM; the HTTP body is a JSON envelope containing encrypted/salt/nonce/iterations/digest/kdf, with an ephemeral public key in EK:04… form appended at the end of the request.

> **Evidence**: payload import table bcrypt.BCryptSecretAgreement/BCryptDeriveKey/BCryptEncrypt; in memory {"encrypted":…,"salt":…,"nonce":…,"iterations":…,"digest":…,"kdf"} and the seed string .phantom-labs.vault.seed.; POST body tail EK:04760963e0cd3def…
> 
> **Source**: `ref:5f66805ca2` · `ref:661eedc6ad` · `ref:e0a325db6c`

### 7. HTTPS callback to C2 for exfiltration

`T1041` · Confidence **high** · Dynamic

The payload uses WinHTTP to send HTTPS POST /sync to heysunlab[.]fun:443 with a fixed auth header X-Auth-Token, Content-Type: text/plain, and a rotating browser UA; after the first request it retries every 3–5 seconds for about 90 seconds.

> **Evidence**: network-monitoring records: DNS query heysunlab[.]fun; 9238bb50….exe (2112) requested TCP 192.0.2[.]123:443; HTTPListener443 received POST /sync, X-Auth-Token: VRM-x9k4p2Q8rTmL5Ws1
> 
> **Source**: `ref:8c4c7b0c96` · `ref:e0a325db6c`

### 8. Monitor clipboard contents

`T1115` · Confidence **medium** · Static

The payload registers a windowless message loop (RegisterClassExW/CreateWindowExW/DispatchMessageW) and calls AddClipboardFormatListener to continuously receive clipboard-change messages, and its collection logic reads clipboard text.

> **Evidence**: the payload's rebuilt import table includes user32.AddClipboardFormatListener/RemoveClipboardFormatListener/RegisterClassExW/DispatchMessageW
> 
> **Source**: `ref:5f66805ca2`

### 9. Erase memory forensics traces

`T1070` · Confidence **high** · Dynamic

After the container is used, the outer program zeroes the entire container section before changing it from RW back to read-only, then requests write access to the page holding its own PE headers and exits immediately, so the memory image contains neither the container plaintext nor complete headers.

> **Evidence**: VirtualProtect(0x14002f000,0x55e200,4) → zero → VirtualProtect(...,1); then VirtualProtect(0x140000000,0x400,4) and ExitProcess(0) (emulated call sequence pc 0x140005ca4/0x140005cc2/0x140005bbe/0x140005b43)
> 
> **Source**: `ref:f109d64216` · `ref:3b701413c3`

### 10. Collect host fingerprint information

`T1082` · Confidence **medium** · Static

The payload imports and calls interfaces for volume serial number, free disk space, logical processor topology, memory status, time zone, and locale, producing a host fingerprint that is reported along with the exfiltrated data.

> **Evidence**: payload import table kernel32.GetVolumeInformationW/GetDiskFreeSpaceW/GetLogicalProcessorInformation/GlobalMemoryStatusEx/GetTimeZoneInformation/GetLocaleInfoEx; the outer FUN_140005e70 also mixes GetComputerNameW/GetSystemMetrics/GetTickCount into seed derivation
> 
> **Source**: `ref:5f66805ca2` · `ref:1c8c4180e8`


## IOCs (defanged)

### Network

:::note
**Connection dynamically observed**: the sample actually made TCP connections to this target (retried several times within a short period).
:::

:::caution
**Real server side still unverified**: the above connections/handshakes were completed with a local controlled emulation service, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://heysunlab[.]fun/sync` | 443 | exfil | Dynamic | Observed |

### Host

- **No host IOCs were recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `heysunlab[.]fun` | Yes | Dynamic |
| `c2_uri` | `/sync` | Yes | Dynamic |
| `auth_token` | `VRM-x9k4p2Q8rTmL5Ws1 (request header X-Auth-Token)` | Yes | Dynamic |
| `encryption_algo` | `ECDH (BCryptGenerateKeyPair/BCryptSecretAgreement/BCryptDeriveKey) + AES-GCM, envelope with encrypted/salt/nonce/iterations/digest/kdf fields` | Yes | Static |
| `campaign_id` | `phantom-labs / VRM (PBKDF2 seed string .phantom-labs.vault.seed., token prefix VRM-)` | No | Static |
| `user_agent` | `rotates browser UA per request (Firefox/137.0, Edge/136, Edge/135, etc.)` | No | Dynamic |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not judge it ransomware: BCrypt symmetric encryption is used only for wrapping C2 exfiltration, and no bulk file encryption, shadow-copy deletion, or ransom note was observed (the sandbox's ransom-note count is 0).
- Do not treat the version information as a trustworthy source: the Blue Sherpa/Blue Microphones LLC wording is a forgeable resource, the file has no digital signature, and the section table/debug directory are obviously rewritten.
- Do not claim confirmed persistence: neither memory nor sandbox artifacts contain evidence of Run keys, scheduled tasks, service installation, or startup-folder writes.
- Do not treat it as a pure downloader: the stage-2 payload is released from the embedded container in memory and executed in place, and no executable file landing on disk was observed.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `6b295a1bca1d887e253d958cf1d8edf31935ba85198aa48a81849d087dda7888`) |

**Limitations and pending verification**

1. Payload strings are decrypted at runtime and there is no plaintext config in static .rdata; the C2 and token come from memory forensics and network monitoring.
2. The sandbox network is an emulated environment and client TLS validation failed, causing the same request to retry every 3–5 seconds for about 90 seconds; the observation is therefore the complete request (method, path, auth header, request-body tail) rather than a successful server-side response, and the server's returned content and subsequent commands could not be obtained.
3. No persistence, injection into other processes, or secondary download was observed, and such capabilities cannot be asserted on this basis.
4. Some routines used to decrypt the outer container derive from machine fingerprints (computer name/CPU/time zone, etc.), so reproducing the decryption offline depends on the real host environment.

## Evidence Index

<details>
<summary>Expand 19 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:36525b2e30` | Hash and fingerprint | sha256=9238bb50…aa0f, imphash=7825189a0024596d121cb759a21f3300, no Rich header |
| `ref:4227a0d254` | PE structure parsing | AMD64 GUI, 8 sections, section names misplaced/duplicated, SECURITY directory empty, entry RVA 0x63C0 |
| `ref:adb3774aa3` | Import table parsing | 7 imported DLLs/108 symbols, no network or process-injection APIs, consistent with an outer dropper |
| `ref:a05cbec966` | decompile.function | main(FUN_140002a30) parses the container and calls FUN_140003e90 |
| `ref:a9e6e0427b` | decompile.function | FUN_1400024e0 locates the container section by 0x9E3779B97F4A7C15 |
| `ref:b371c7f942` | decompile.function | FUN_140003e90 validates 0x3e8f4a71c62b9d05 and parses 0x1c-byte entries |
| `ref:3b701413c3` | decompile.function | FUN_140005be0 zeroes the container section and switches page protection |
| `ref:f109d64216` | dyn.run | Emulated call sequence shows VirtualProtect on 0x2F000/0x55E200 and write-protection changes to its own PE headers, followed by ExitProcess |
| `ref:1af92d4316` | Dynamic analysis platform | Real run: pid 2112 dumped, 11 memory artifacts including an implanted PE dump |
| `ref:310897aeb1` | memory-scan-report | implanted_pe=1, MEM_PRIVATE base 140000000, size 0x2bd000, protection 0x40 |
| `ref:5f66805ca2` | imports-of-dump | Payload imports bcrypt ECDH/AES, winhttp, clipboard listening, SHGetKnownFolderPath, and system-fingerprint APIs |
| `ref:7309bcedf5` | memory-strings | memory plaintext: hxxps://heysunlab[.]fun/sync, X-Auth-Token, loginusers/steamid/web_secure, sqlite statements |
| `ref:661eedc6ad` | memory-strings | JSON envelope {"encrypted","salt","nonce","iterations","digest","kdf"} and .phantom-labs.vault.seed., build path …\vrm new\out\release\app.pdb |
| `ref:8c4c7b0c96` | network-log | DNS query heysunlab[.]fun and connection from process 2112 to 192.0.2[.]123:443 |
| `ref:e0a325db6c` | network-log | POST /sync, X-Auth-Token: VRM-x9k4p2Q8rTmL5Ws1, UA rotation, request-body tail EK:04… |
| `ref:be8bbc87df` | memory-strings | context of the UA rotation strings and EK: public-key field in memory |
| `c2_evidence:9238bb50` | Connection evidence extraction | Dynamic network monitoring recorded 18 connection attempts to heysunlab[.]fun:443; no complete session captured |
| `telemetry:9238bb50` | Dynamic telemetry | Dynamic telemetry recorded: monitoring-component process/file events 139; ETW short-lived process events 1; filtered tool/system noise 22 |
| `etw:9238bb50:2112` | Process event monitoring | Short-lived process event: 9238bb50f85bd34f3c8127ef7860e6df0ceb631f3c1d0be546716e36ef35aa0f.exe (pid 2112; MD5=6CDE024FB9FA6304258FAB37534FC045,SHA256=9238BB50F85BD34F3C8127EF7860E6DF0CEB631F3C1D0BE546716E36EF35AA0F,IMPHASH=7825189A0024596D121CB759A21F3300) |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
