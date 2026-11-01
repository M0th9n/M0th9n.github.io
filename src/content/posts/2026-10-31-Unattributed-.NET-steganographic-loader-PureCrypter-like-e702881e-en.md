---
title: "Malware Analysis: Unattributed .NET steganographic loader (PureCrypter-like) (PE · exe · e702881e)"
published: 2026-10-31
draft: false
description: "Malicious (low confidence): Unattributed .NET steganographic loader (PureCrypter-like) · loader/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["loader", "downloader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-31-Unattributed-.NET-steganographic-loader-PureCrypter-like-e702881e"
---

> [!WARNING]
> **Verdict: malicious** · Family **Unattributed .NET steganographic loader (PureCrypter-like)** (uncertain) · Confidence **low**
> 
> Aliases: HillGather loader, HWMonitor stage-2 loader
> 
> The sample is a .NET WinForms program whose tail logic decodes a 48,640-byte .NET assembly out of an embedded bitmap resource, loads it in memory through AppDomain.Load, and then invokes its entry point by reflection; that stage-2 assembly in turn takes another bitmap resource from the host assembly, preparing to keep loading. The loader body, the steganographic container and the reflective invocation are each confirmed directly from disassembly/decompilation.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unattributed .NET steganographic loader (PureCrypter-like)** · aliases HillGather loader, HWMonitor stage-2 loader · _uncertain_ |
| Confidence | **low** |
| Behaviour class | loader · downloader |
| Difficulty | medium |
| First seen | 2026-10-29 06:43:20 |
| Analysis method | dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/e702881e545e69338b7b9c7934b8a950d5aea71dec005e4a359bce0dd1422452/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Ranch simulator UI</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Bitmap hides stage 2</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.003</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">In-memory assembly</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Reflection entry call</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Stage 2 reads host res</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `e702881e545e69338b7b9c7934b8a950d5aea71dec005e4a359bce0dd1422452` |
| MD5 | _not recorded_ |
| Size | 560,128 bytes (547.0 KB) |
| Type | PE · `exe` |

## Behaviour analysis

**7** behaviours in total, each backed by evidence, and all of them statically observable.

### 1. Ranch simulator disguise

`T1036.005` · Confidence **high** · static

It starts as a fully functional ranch/flock itinerary simulation WinForms UI (HillForm/TeamForm/FlockForm/GatherForm/ReportForm); the real loading logic sits at the tail of HillForm.InitializeComponent and only fires once the user opens the main form.

> **Evidence**: HillForm.InitializeComponent IL 0x072e–0x07ac (the load runs immediately after the controls are added to pnlControlBar)
> 
> **Source**: `ref:ff69c0f8ec` · `ref:35732d46e7` · `ref:9127f0d9dd`

### 2. Stage-2 payload hidden in a bitmap

`T1027.003` · Confidence **high** · static

Reads the R/G/B channels of the dzh bitmap in .resources (128x127, 32bpp) in column-major order, reconstructing 48,640 bytes of data whose header is 'MZ', i.e. a complete .NET assembly.

> **Evidence**: HillForm.Run 0x4624 / ReadPixelBytes 0x4658; resource dzh at file offset 0x17e32; reconstructed result sha256=b9ef8fef5b455817a626806044ae6567cb1f7bafaa7d17a7724a02a25f90d2d2
> 
> **Source**: `ref:9127f0d9dd`

### 3. In-memory loading of the hidden assembly

`T1620` · Confidence **high** · static

Calls AppDomain.CurrentDomain.Load(byte[]) to load the byte array obtained above directly as an in-memory assembly, so no stage-2 file ever appears on disk.

> **Evidence**: IL 0x0738 call Run; 0x0744 MethodSpec (AppDomain.Load(byte[])); 0x0749 callvirt System.AppDomain::Load
> 
> **Source**: `ref:ff69c0f8ec` · `ref:9127f0d9dd`

### 4. Reflective invocation of the stage-2 entry

`T1620` · Confidence **high** · static

Takes the second type of the loaded assembly (GetTypes[1]), then its first method (GetMethods[0]), and invokes it through Microsoft.VisualBasic LateBinding.LateCall in "Invoke" mode with 3 string arguments, so static analysis cannot see the call target directly.

> **Evidence**: IL 0x0750 GetTypes → 0x0785 Type::GetMethods → 0x0791 ldstr 'Invoke' → 0x07ac LateBinding::LateCall
> 
> **Source**: `ref:ff69c0f8ec` · `ref:9127f0d9dd`

### 5. Stage 2 pulls another host resource

`T1027.003` · Confidence **medium** · static

The loaded HWMonitor.dll references Assembly.GetEntryAssembly, ResourceManager.GetObject, Image.GetPixel/SetPixel and RestoreOriginalBitmap, indicating that it keeps taking another bitmap resource (ulHS, PNG 457x505) from the host (HillGather) assembly and may write back / overwrite the original image, forming a multi-stage loading chain.

> **Evidence**: stage-2 metadata MethodRef: Assembly::GetEntryAssembly, ResourceManager::GetObject, Bitmap::GetPixel/SetPixel, method RestoreOriginalBitmap(0x28cc)
> 
> **Source**: `ref:5f540ef524` · `ref:fa77c8ac76` · `ref:9127f0d9dd`

### 6. String encryption to evade detection

`T1027` · Confidence **high** · static

The stage-1 .cctor assembles static fields from a hex code-point string of the form "413 43B 430 43C 443 440 20" (which decodes to the Cyrillic "Гламур "), and at runtime splits the value on that separator with Regex.Split; user strings in the stage-2 assembly are likewise stored as numeric/letter encodings that must be restored at runtime.

> **Evidence**: HillForm..cctor 0x6fbf: ldstr '413 43B ...' → stsfld dv; InitializeComponent 0x075d Regex::Split
> 
> **Source**: `ref:ff69c0f8ec` · `ref:fa77c8ac76`

### 7. Overlay panel hides interaction

`T1564.003` · Confidence **medium** · static

The stage-2 assembly builds an overlay from the Panel subclass GamePanel + Form1 + Timer, and uses ProcessCmdKey, GetPixel/SetPixel and RestoreOriginalBitmap for screen-level drawing/restoration; no standalone visible window or console output was found.

> **Evidence**: stage-2 types GamePanel/Form1, MethodRef TextRenderer::DrawText, Bitmap::SetPixel, method RestoreOriginalBitmap
> 
> **Source**: `ref:5f540ef524` · `ref:fa77c8ac76`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis method and limitations" at the end for why).
:::

### Host

- **No host IOCs were recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `stage2_container` | `Embedded resource dzh (Bitmap, BMP 128x127x32bpp, file offset 0x17e32)` | yes | static |
| `stage2_decode` | `per-pixel read: H=127, i∈[0,48640), x=(i/3)/H, y=(i/3)%H, bytes taken as R/G/B in order` | yes | static |
| `stage2_exec` | `AppDomain.CurrentDomain.Load(byte[]) → GetTypes[1] → GetMethods[0] → LateBinding.LateCall(..., "Invoke", {0,{s1,s2,"HillGather"}})` | yes | static |
| `stage3_container` | `entry assembly resource ulHS (Bitmap, PNG 457x505 RGBA), read by the stage-2 assembly` | no | static |
| `string_encoding` | `stage-1 .cctor concatenates code-point strings: Гламур + hex string ('413 43B 430 43C 443 440 20' as the separator)` | yes | static |
| `c2_hosts` | `not recovered` | no | dynamic |

## Don't misread this

:::important
The following conclusions are **easy to get wrong**; keep them in mind when citing this report.

- Do not claim that C2 or any outbound behaviour was observed: statically the sample imports only mscoree!CorExeMain, neither the stage-1 nor the stage-2 metadata references System.Net/WebClient/Socket, and the dynamic detonation returned no network logs either.
- Do not treat the string hxxp://hillfarmgather[.]org/schema/gather.xsd as a C2 or download address: it is a namespace constant for XML export, and the program has no network-calling surface.
- Do not assert a specific family name or final purpose (credential theft / ransomware / remote control): the stage-3 payload has not been recovered and the stage-2 strings are decoded at runtime, so there is no corroborating family marker.
- Do not claim that persistence exists (service / scheduled task / registry autorun): no corresponding API references or dropped configuration were found.
- Do not treat HillGatherRecord.xml / HillGatherSchema.xsd as malicious dropped files: they are file names used by the UI's export/validation feature.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | dynamic sandbox analysis + static decompilation |
| Unpacked | yes (stage2 `b9ef8fef5b455817a626806044ae6567cb1f7bafaa7d17a7724a02a25f90d2d2`) |

**Limitations and open questions**

1. The real dynamic detonation produced no result (the sandbox start/drop-monitoring process returned no usable artefacts), so there is no runtime network, memory or file-drop evidence; reproduced=false.
2. The stage-2 assembly is obfuscated (method names 1AAA1/3AAA1/…, strings decoded at runtime), and the extraction algorithm and final purpose of the stage-3 payload (ulHS, PNG 457x505) have not been recovered.
3. Neither the stage-1 nor the stage-2 metadata references System.Net/WebClient/Socket; if network capability exists, it can only reside in the not-yet-recovered stage-3 payload or be reached indirectly through reflection.
4. The sample is assembled with .NET reflection/steganography, so static conclusions may be skewed for the obfuscated parts; the family attribution is a candidate rather than a settled finding.

## Evidence index

<details>
<summary>Show 8 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:05105c9f20` | sample triage | sha256=e702881e…, .text entropy 7.58, only 1 imported symbol, packer likelihood 0.6 |
| `ref:ff69c0f8ec` | PE structure parsing | I386 PE, 3 sections, entry 0x89d32, import directory only 79 bytes, CLI/COM directory present |
| `ref:f75392f457` | import table parsing | the only import is mscoree.dll!_CorExeMain (.NET program) |
| `ref:35732d46e7` | string extraction | strings extracted, hitting resource/namespace strings (HillGather, dzh, ulHS, etc.) |
| `ref:5f540ef524` | PE structure parsing | the recovered stage-2 payload is an I386 DLL, .NET, 3 sections, module size 48640 |
| `ref:fa77c8ac76` | string extraction | stage-2 payload strings: GetTypes/GetMethods/Invoke/LateBinding/GetEntryAssembly/GetPixel/SetPixel, etc. |
| `ref:9127f0d9dd` | scripted forensics | decodes the dzh bitmap resource with the sample's own algorithm, yielding a 48,640-byte .NET assembly HWMonitor.dll beginning with MZ |
| `ref:d37b1c0e9b` | dynamic analysis platform | the dynamic environment started but never ran the dropped sample; no sample process/network artefacts |

</details>

---

_This sample is not shared; IOCs are defanged. For security research only._
