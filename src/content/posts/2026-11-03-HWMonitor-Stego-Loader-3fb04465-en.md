---
title: "Malware Analysis: HWMonitor Stego Loader (PE · exe · 3fb04465)"
published: 2026-11-03
draft: false
description: "Malicious (low confidence): HWMonitor Stego Loader · loader/dropper · difficulty hard · dynamic sandbox + static decompilation"
tags: ["HWMonitor Stego", "loader", "dropper", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-03-HWMonitor-Stego-Loader-3fb04465"
---

> [!WARNING]
> **Verdict: Malicious** · Family **HWMonitor Stego Loader** (uncertain) · Confidence **low**
> 
> Aliases: HWMonitor Pro disguising loader, PureCrypter-like .NET stego loader
> 
> Decompiling the main program confirms it is a .NET steganographic loader: the RGB pixels of the resource bitmap TW1 are read pixel by pixel into 92160 bytes and recovered into a complete PE32 .NET assembly (HWMonitor.dll), which is then reflectively loaded via a runtime-concatenated 'L'+'oad' through VB LateBinding calling AppDomain.Load, instantiated with Activator.CreateInstance, and hooked into the form. The complete loading chain was statically reproduced in this environment, and the outer layer is disguised with a full WinForms business interface.

## Overview

| Item | Content |
|:--|:--|
| Family | **HWMonitor Stego Loader** · aliases HWMonitor Pro disguising loader, PureCrypter-like .NET stego loader · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · dropper |
| Difficulty | hard |
| First seen | 2026-11-03 06:43:43 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/3fb044653334e89c68176d670bedbec83c2e09a2a609b4814eee1575fda6da2d/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">PE hidden in image stego</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Reflectively load in-memory assembly</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Split config from hex string</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Concatenate API name at runtime</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Disguise as mountain hut app</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `3fb044653334e89c68176d670bedbec83c2e09a2a609b4814eee1575fda6da2d` |
| MD5 | _not recorded_ |
| Size | 2,665,984 bytes (2.5 MB) |
| Type | PE · `exe` |

## Behavior analysis

**7** behaviors in total, each backed by evidence, all statically recoverable.

### 1. PE hidden in image stego

`T1027.003` · Confidence **high** · static

The resource bitmap TW1 (177x176, 32bpp) is read column-major pixel by pixel through the R/G/B channels, accumulating to 92160 bytes that form a complete PE32 .NET assembly starting with MZ — hiding the second stage inside an ordinary image resource.

> **Evidence**: RadioTelescopeDecoder.Produce @0x10c34; pixel-collection callback <...Produce>b__0 @0x111d4 calls GetPixel and appends R/G/B; HutForm.InitializeComponent @0x4be0 passes sampleBudget=92160
> 
> **Source**: `ev-000008` · `ev-000005`

### 2. Reflectively load in-memory assembly

`T1620` · Confidence **high** · static

At runtime it concatenates 'L' and 'oad' into 'Load', hands it to VB LateBinding to invoke on AppDomain.CurrentDomain, and loads the assembly from the decoded byte array without writing any file to disk.

> **Evidence**: 0x4a83-0x4aa9: get_CurrentDomain / Concat('L','oad') / LateBinding::LateGet; 0x4ab5 Assembly::GetExportedTypes
> 
> **Source**: `ev-000008` · `ev-000005`

### 3. Split config from hex string

`T1140` · Confidence **high** · static

The static field intConn's value consists of hex fragments separated by '4F 49 4C'; after Split, [1] and [3] yield '4342677A' (the resource name CBgz) and an empty string, which together with 'MountainHut' form 3 constructor arguments, then Activator.CreateInstance instantiates the payload's exported type.

> **Evidence**: HutForm::.cctor @0x6a0e; 0x4abd-0x4af3: Split / newarr String / Activator::CreateInstance
> 
> **Source**: `ev-000008`

### 4. Concatenate API name at runtime

`T1027` · Confidence **high** · static

The sensitive method name 'Load' is split into two constants concatenated on the stack, so static string scanning cannot see the complete reflective-load call.

> **Evidence**: HutForm.InitializeComponent @0x4be0, 0x4a89/0x4a8e ldstr 'L'/'oad' + 0x4a93 String::Concat
> 
> **Source**: `ev-000005` · `ev-000008`

### 5. Disguise as mountain hut app

`T1036` · Confidence **high** · static

The outer layer is a fully functional WinForms 'Mountain Hut' lodge supply simulation featuring HutForm/HutSetupForm/SupplyForm/SeasonForm/ReportForm, a DataSet, and extensive UI resources, using a normal business appearance to mask startup-time payload loading.

> **Evidence**: assembly oqNZ, version info ProductName/FileDescription='Mountain Hut', CompanyName='Alpine Supply Systems'; types/resources in scan.strings and metadata
> 
> **Source**: `ev-000005` · `ev-000002`

### 6. Single high-entropy hidden section

`T1027.002` · Confidence **high** · static

The PE has only .text (entropy 7.91, about 2.66MB) and .rsrc sections, with empty import/export tables and image resources mixed with IL inside .text, defeating conventional static criteria based on the import surface/section names.

> **Evidence**: .text rva 0x2000 entropy 7.91; import_dll_count=0; section count=2; entry_point.rva=0 (pure managed entry resolved by the CLR)
> 
> **Source**: `ev-000002` · `ev-000004` · `ev-000001`

### 7. Embedded monitor program disguise

`T1036` · Confidence **medium** · static

The second stage self-reports as HWMonitor 2.8 (HWMonitor.dll), with metadata containing 'HWMonitor Pro', 'CPUID SARL 2026', and hardware-monitoring descriptions, while also carrying MD5/AES/RSA constants and protection-runtime features such as Reflection.Emit/GetManifestResourceStream; its authenticity was not verified.

> **Evidence**: payload Assembly=HWMonitor 2.8, Module=HWMonitor.dll; strings 'HWMonitor Pro'/'CPUID SARL'/'Professional-grade hardware monitoring...'; MD5 T-table @0x15dbe
> 
> **Source**: `ev-000006` · `ev-000007` · `ev-000008`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC recovered** (see "Analysis method and limitations" at the end).
:::

### Host

- **No host IOC recovered.**

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `embedded_payload_resource` | `TW1 (177x176 Bitmap, decode cap 92160 bytes)` | yes | static |
| `decode_budget_bytes` | `92160` | yes | static |
| `payload_assembly` | `HWMonitor 2.8 / HWMonitor.dll` | yes | static |
| `payload_sha256` | `be02d40783e5f695449a8d700f27a11cee7443bc3bb75fe554314a0ba15ad576` | yes | static |
| `loader_member` | `AppDomain.Load(byte[]) via Microsoft.VisualBasic LateBinding` | yes | static |
| `activation_args` | `4342677A\|''\|MountainHut (obtained by splitting intConn on '4F 49 4C')` | yes | static |
| `activation_resource` | `CBgz (929x977 Bitmap, ASCII of '4342677A' is CBgz)` | no | static |
| `decoy_application` | `Mountain Hut / oqNZ.exe (WinForms lodge supply simulation, Alpine Supply Systems)` | yes | static |

## Must not claim

:::important
The following conclusions are **prone to misjudgment**; take care when citing this report.

- Do not assert C2 or egress behavior: no URL/domain/public IP was found in the main program or the payload, the payload references only local .NET libraries, and the dynamic sandbox did not produce a usable network timeline.
- Do not assert stealing/ransomware/mining capability: no browser data, wallet, file encryption, or mining-pool operations were observed; these capabilities have no supporting evidence.
- Do not judge it as conventional packing from .text high entropy alone: that section holds .NET metadata/IL together with image resources — a managed-program plus stego-payload combination, not a native UPX-style packer.
- Do not treat the name 'HWMonitor Pro' directly as a known malicious family signature: there is no vendor engine or YARA corroboration, and the payload also contains game/level strings inconsistent with the genuine product; authenticity remains to be verified.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | yes (stage2 `be02d40783e5f695449a8d700f27a11cee7443bc3bb75fe554314a0ba15ad576`) |

**Limitations and pending verification**

1. The isolated dynamic sandbox's observation request did not return within the timeout, so no process/memory/network timeline was obtained and reproduced=false; all conclusions come from static decompilation and payload extraction.
2. No C2, URL, domain, or public IP was found, so no network IOC can be given; it cannot be ruled out that the payload enables network capabilities only under specific conditions.
3. The second-stage assembly has obvious .NET obfuscation/protection features (random resource names, Reflection.Emit, AES/RSA/MD5 constants); its internal behavior was not method-by-method recovered, and its true purpose and relationship to genuine HWMonitor Pro were not verified.
4. The outer PE has entry_point.rva=0 and an empty import table, a pure managed entry form; it cannot be ruled out that some resources or metadata were deliberately crafted to interfere with analysis.
5. Although the dynamic tier invoked isolated sandbox primitives, the timeout yielded no usable artifacts; this must not be taken to mean the sample has no malicious behavior.

## Evidence index

<details>
<summary>Expand 8 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | hashing and fingerprints | sha256=3fb044653334e89c68176d670bedbec83c2e09a2a609b4814eee1575fda6da2d, size=2665984 |
| `ev-000002` | scan.entropy | .text section entropy 7.91 (high), covering off 512..2664448 |
| `ev-000003` | scan.entropy | .rsrc section entropy 4.149 |
| `ev-000004` | sample triage | packing likelihood 0.60: executable section high entropy 7.91, 0 import symbols |
| `ev-000005` | string extraction | main-program strings: MountainHut forms/DataSet/resource keys TW1, CBgz, Screenshot_2026_04_11_230907, etc. |
| `ev-000006` | string extraction | second-stage strings: HWMonitor.dll / HWMonitor Pro / CPUID SARL / crypto and reflection API names |
| `ev-000007` | cryptographic constant identification | second stage hits MD5 T-table @0x15dbe |
| `ev-000008` | evidence.record | script reproduces decoding: TW1 bitmap -> 92160 bytes -> MZ/PE assembly sha256 be02d407..., and extracts activation arguments |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
