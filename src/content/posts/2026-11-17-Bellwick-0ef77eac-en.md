---
title: "Malware Sample Analysis: Bellwick (PE · exe · 0ef77eac)"
published: 2026-11-17
draft: false
description: "Malicious (low confidence): Bellwick · loader/downloader · difficulty hard · dynamic sandbox + static decompilation"
tags: ["Bellwick", "loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-17-Bellwick-0ef77eac"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Bellwick** (uncertain) · Confidence **low**
> 
> Aliases: Bellwick DoH loader
> 
> The sample uses resources and version information masquerading as a Realtek audio service; its import table is empty, and the entry point executes after being decrypted by an obfuscated dispatcher. After real detonation in an isolated sandbox, the sample proactively queries bucket[.]bellwick[.]cc and telegra[.]ph against public resolvers over DNS-over-HTTPS, and decrypts in memory the C2 domain, HTTP header fields, and host-fingerprint-related configuration. This combination of behaviors has no legitimacy for a normal audio service and is judged a malicious loader/downloader.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Bellwick** · Alias Bellwick DoH loader · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · downloader |
| Difficulty | hard |
| First seen | 2026-11-16 15:25:40 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/0ef77eac80b0f0addda266a68d4fa754c73e53bc453a4595ca13173e04434166/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Masquerades as Realtek audio service</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Obfuscated entry dispatcher</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Resolves APIs at runtime</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Resolves C2 domain via DoH</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.004</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Connects to public DoH resolvers</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1573</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `0ef77eac80b0f0addda266a68d4fa754c73e53bc453a4595ca13173e04434166` |
| MD5 | _not recorded_ |
| Size | 720,896 bytes (704.0 KB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **7** behaviors in total, each backed by evidence; **5** are available statically and **2** were obtained through dynamic analysis.

### 1. Masquerades as Realtek Audio Service

`T1036.005` · Confidence **high** · Static

The resource section contains a manifest and version information for Realtek HD Audio, claiming the company is Realtek Semiconductor Corp. and the file description is Realtek HD Audio Manager, and names the sample RtkAudioService.exe to masquerade as a legitimate audio service.

> **Evidence**: Resource .rsrc (rva 0xd3000) manifest name="Realtek.Audio.RtkAudioService"; version string FileDescription=Realtek HD Audio Manager; the process creation record also shows this masquerading description
> 
> **Source**: `ref:5520ccbd36` · `ref:792822e31a`

### 2. Obfuscated Entry Dispatcher

`T1027` · Confidence **high** · Static

The entry point 0x401000 only executes call 0x4192f4 then ret; the real logic is at 0x4192f4. At runtime it heavily uses constant hash computation and retf far returns to form a dispatcher; inside 0x41c481, magic numbers such as 0x1337/0xbaad/0xbeef/0xdead branch to subsequent jumps, which is clear code obfuscation.

> **Evidence**: 0x401000 call 0x4192f4; ret; 0x4192f4 is the real main logic; 0x41c481 compares ax,0x1337 / 0xbaad / 0xbeef / 0xc0de / 0xdead and jumps
> 
> **Source**: `ref:372107d846` · `ref:fdc185685f` · `ref:8225af3184`

### 3. Runtime API Resolution

`T1027` · Confidence **high** · Static

The PE import and export tables are both empty. At runtime the sample locates and loads modules such as sspicli, schannel, ncrypt, and bcrypt by itself and invokes system APIs through in-memory dispatch, evading static import analysis.

> **Evidence**: import table dll_count=0 / symbol_count=0; in-memory module list contains sspicli.dll, schannel.dll, ncrypt.dll, bcrypt.dll, rpcrt4.dll
> 
> **Source**: `ref:f45f975287` · `ref:9e5170f4eb` · `ref:792822e31a`

### 4. DoH C2 Domain Resolution

`T1071.004` · Confidence **high** · Dynamic

The sample queries A records against public resolvers via HTTPS POST /dns-query (Host: dns[.]google or cloudflare-dns[.]com): first bucket[.]bellwick[.]cc, then telegra[.]ph, hiding domain resolution through DNS-over-HTTPS.

> **Evidence**: Network monitoring: POST /dns-query; Host: dns[.]google; body 'bucketbellwickcc...'; then Host: cloudflare-dns[.]com, body 'telegraph...'
> 
> **Source**: `ref:792822e31a`

### 5. Connects to Public DoH Resolvers

`T1573` · Confidence **high** · Dynamic

Within about 25 seconds it repeatedly initiates TCP connections to port 443 of 8.8.8[.]8, 8.8.4[.]4, 1.1.1[.]1, and 1.0.0[.]1, completing TLS and DoH requests over those connections.

> **Evidence**: Network monitoring timeline: process 7744 requested TCP 8.8.8[.]8:443 / 8.8.4[.]4:443 / 1.1.1[.]1:443 / 1.0.0[.]1:443 (04:29:38–04:30:03)
> 
> **Source**: `ref:792822e31a`

### 6. Collects Host Fingerprint

`T1082` · Confidence **medium** · Static

The sample reads the registry MachineGuid and reads COMPUTERNAME, USERDOMAIN, environment variables, and other information to generate a victim machine identifier; the full environment block and values such as DESKTOP-7QK4M2P are visible in memory.

> **Evidence**: memory plaintext: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid, FallbackGUID, COMPUTERNAME=DESKTOP-7QK4M2P, USERDOMAIN=DESKTOP-7QK4M2P, full environment variable block
> 
> **Source**: `ref:792822e31a`

### 7. In-Memory C2 Config Decryption

`T1140` · Confidence **medium** · Static

The configuration file is encrypted on disk with an unknown algorithm; after execution, plaintext configuration appears in the in-memory heap: C2 domain bucket[.]bellwick[.]cc, HTTP header fields Host/Accept/Content-Type/Content-Length, the 32-digit hexadecimal identifier a995a64757a751ca7b61c118f8aa3dc9, and an all-zero GUID.

> **Evidence**: memory forensics: 'bucket[.]bellwick[.]cc' at 0x211b82/0x211ba2/0x211d12; Accept/Content-Type/Content-Length/Host starting at 0x211bc2; 32-digit hex identifier at 0x211ce2; these plaintexts do not exist in the sample file (single-byte XOR/ADD also does not hit)
> 
> **Source**: `ref:792822e31a`


## IOCs (Defanged)

### Network

:::caution
**Pending dynamic verification**: The above addresses were obtained through static analysis. No successful connection or session was observed in the network-isolated analysis environment, and the real C2 responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://bucket[.]bellwick[.]cc/` | 443 | c2 | Static | ⏳ Not observed |
| http | `hxxps://telegra[.]ph/` | 443 | download | Static | ⏳ Not observed |

### Host

- **No host IOCs were recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `bucket[.]bellwick[.]cc` | Yes | Static |
| `c2_port` | `443` | Yes | Static |
| `c2_uri` | `/` | No | Static |
| `doh_resolvers` | `8.8.8[.]8 / 8.8.4[.]4 (SNI dns[.]google), 1.1.1[.]1 / 1.0.0[.]1 (SNI cloudflare-dns[.]com), POST /dns-query` | Yes | Static |
| `dead_drop_host` | `telegra[.]ph` | No | Static |
| `campaign_id` | `a995a64757a751ca7b61c118f8aa3dc9` | No | Static |
| `bot_id_sources` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid; COMPUTERNAME; USERDOMAIN; environment variable block` | Yes | Static |
| `config_encryption` | `unknown (ciphertext in file; plaintext appears only in memory at runtime; single-byte XOR/ADD does not match)` | No | Static |

## Do Not Misjudge

:::important
The following conclusions **are easy to misjudge**; please note them when citing this report.

- It cannot be asserted that a second-stage payload was successfully downloaded or executed: only DoH domain resolution and connection attempts were observed; no complete request/response session to bucket[.]bellwick[.]cc or telegra[.]ph was captured, and no dropped file or child process was found.
- It cannot be judged as stealer or ransomware on this basis: no file enumeration, credential reading, browser data access, or encryption/destruction behavior was observed.
- telegra[.]ph cannot be treated directly as malicious infrastructure: the public Telegraph domain may merely be used as a dead-drop resolution carrier, and classification requires the specific page path.
- Persistence cannot be claimed: no registry autorun, service installation, or scheduled task creation was observed.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and Pending Verification**

1. The configuration is encrypted in the file with an unknown algorithm and could not be recovered by static analysis; the C2 and configuration items come from sandbox memory plaintext, and a complete request/response session to bucket[.]bellwick[.]cc is still missing, so c2/config are uniformly marked recoverability=static and pending_dynamic_verify=true.
2. The DoH request side was fully captured, but the resolver did not return the real upstream answer, so the domain resolution result and subsequent C2 interaction content cannot be confirmed.
3. The sample exits by itself after about 25 seconds; no persistence, file drop, or child process was observed; it cannot be ruled out that its behavior terminated early due to the network/virtual environment.
4. The family name is based only on C2 domain clustering and lacks vendor naming, signatures, or YARA corroboration; family is marked uncertain=true.

## Evidence Index

<details>
<summary>Expand 14 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hash/entropy/triage | sha256/segment entropy/packing likelihood (25%, only due to 0 imports) |
| `ref:5520ccbd36` | PE structure parsing | I386 GUI, entry 0x1000, 5 sections, .rsrc and .reloc, import/export directories both 0 |
| `ref:f45f975287` | Import table parsing | dll_count=0, symbol_count=0, imphash empty |
| `ref:9e5170f4eb` | Packing detection | packed=false, the only signal is very few imported symbols |
| `ref:c4a3e15950` | String scan | 1429 ASCII / 29 UTF-16 strings, no flag hits; many audio-domain decoy strings |
| `ref:372107d846` | Entry disassembly | 0x401000: call 0x4192f4; ret |
| `ref:fdc185685f` | Main logic disassembly | 0x4192f4 builds dispatch using constants and hash calls |
| `ref:8225af3184` | Dispatcher disassembly | 0x41c481 compares magic numbers such as 0x1337/0xbaad/0xbeef/0xc0de/0xdead |
| `ref:cf51bc3001` | CPU emulation | Stops after executing 18 instructions due to invalid memory access, indicating dependence on the real runtime environment |
| `ref:d40e80364a` | Function identification | Failed to identify a function table, further corroborating strong obfuscation |
| `ref:0a51e6c932` | Behavior emulation | The emulation environment produced no API/network events |
| `ref:792822e31a` | Dynamic sandbox | Real detonation: process 7744 ran for about 25 seconds, capturing DoH queries for bucket[.]bellwick[.]cc / telegra[.]ph, 443 connections to 4 public resolvers, in-memory plaintext configuration, and module list |
| `telemetry:0ef77eac` | Dynamic telemetry | Dynamic telemetry recorded: monitoring component process/file events 94; ETW short-lived process event 1; filtered tool/system noise 27 |
| `etw:0ef77eac:7744` | Process event monitoring | Short-lived process event: 0ef77eac80b0f0addda266a68d4fa754c73e53bc453a4595ca13173e04434166.exe (pid 7744; MD5=8AC9D410BB716F766C0857821FE2781E,SHA256=0EF77EAC80B0F0ADDDA266A68D4FA754C73E53BC453A4595CA13173E04434166,IMPHASH=00000000000000000000000000000000) |

</details>

---

_The sample in this report is not public; IOCs have been defanged; for security research only._
