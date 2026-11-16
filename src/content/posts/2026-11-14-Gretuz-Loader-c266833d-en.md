---
title: "Malware Analysis: Gretuz Loader (PE · exe · c266833d)"
published: 2026-11-14
draft: false
description: "Malicious (medium confidence): Gretuz Loader · loader · difficulty hard · static decompilation (no runtime behavior obtained)"
tags: ["Gretuz", "loader", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-14-Gretuz-Loader-c266833d"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Gretuz Loader** (uncertain) · Confidence **Medium**
> 
> Aliases: loader.dll masquerading JLI loader
> 
> The original file is a UPX-packed 64-bit DLL that exports 14 JLI_* names to masquerade as a Java launcher; after static unpacking it reveals a TLS-callback rolling-XOR decryption routine, control-flow flattening, a table of 202 custom-encoded payload segments, and runtime resolution via LoadLibraryA/GetProcAddress. It has the capability to load a next-stage payload and a clear intent to hide, but no executable host was obtained in this run, so no drop or outbound connection was observed.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Gretuz Loader** · aliases loader.dll masquerading JLI loader · _uncertain_ |
| Confidence | **Medium** |
| Behavior class | loader |
| Difficulty | hard |
| First seen | 2026-11-12 23:49:50 |
| Analysis method | Static decompilation (no runtime behavior obtained) |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/c266833d1ca0b41a8d455a13202b76a9fdc734ea556ced624f2b90d0ecd122f7/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Masquerade as Java launcher exports</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">UPX packing evades static detection</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">TLS callback decrypts embedded data</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">202-segment encoded payload table</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Control-flow flattening hides logic</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `c266833d1ca0b41a8d455a13202b76a9fdc734ea556ced624f2b90d0ecd122f7` |
| MD5 | _not recorded_ |
| Size | 450,560 bytes (440.0 KB) |
| Type | PE · `exe` |

## Behavior Analysis

**7** behaviors in total, each backed by evidence, and all obtained statically.

### 1. Masquerade as Java launcher exports

`T1036.005` · Confidence **High** · Static

The unpacked module is named loader.dll and exports 14 JLI_* symbols; the real JLI_Launch merely calls an obfuscated dispatcher and returns 0, with none of the normal Java launcher logic.

> **Evidence**: Export table JLI_Launch@rva 0x1794; decompile JLI_Launch -> FUN_180001e5a
> 
> **Source**: `ref:d57a5e0698` · `ref:1d2ab520d9`

### 2. UPX packing evades static detection

`T1027.002` · Confidence **High** · Static

The original sample has only UPX0/UPX1/UPX2 sections, UPX1 entropy 7.999 and just 5 imported symbols; static unpacking restores a normal PE containing .text/.rdata/.data/.pdata/.tls/.reloc.

> **Evidence**: UPX1 entropy 7.999; after upx -d, 743936 bytes, sha256=ffe87766…
> 
> **Source**: `ref:6be8571823` · `ref:37faff4851` · `ref:812b033128`

### 3. TLS callback decrypts embedded data

`T1027` · Confidence **High** · Static

On process/thread attach, the TLS callback calls FUN_18000a820 to decrypt 20 bytes in .rdata with a rolling XOR (initial value 0x606c874b, step 0x130294a7), then decrypts 10 bytes into the TLS block with 0x7e97/0x2575, using a flag byte to prevent re-execution.

> **Evidence**: tls_callback_0@0x18000aba0 -> FUN_18000a820; xor 0x606c874b, step 0x130294a7
> 
> **Source**: `ref:535c703744` · `ref:9a9d4be437`

### 4. 202-segment encoded payload table

`T1027` · Confidence **Medium** · Static

Starting at rva 0xB3AC0 at the tail of .data there is a 202-entry {pointer,length} table pointing into two isomorphic text regions in .rdata (294130 chars from 0x1B000) and .data (281279 chars from 0x6F000); the character set is exactly 32 symbols with entropy about 5.0, consistent with a custom-alphabet base32, and blocks range from 91 to 4487 chars, i.e. an encoded payload stored in chunks.

> **Evidence**: table rva 0xB3AC0; 202 entries; total 575409 chars; references at 0x390A/0x54D3
> 
> **Source**: `ref:ae04d8330c` · `ref:9bd4f2158f`

### 5. Control-flow flattening hides logic

`T1027` · Confidence **High** · Static

Core functions use a relative-offset jump table plus opaque predicates (TLS flag, memory allocation results) as a flattened dispatcher; the decompiler repeatedly reports an unrecoverable jumptable, so the code can only be read as basic-block fragments.

> **Evidence**: FUN_180001e5a indirect jump at 0x180002037; FUN_180009488 and others index the table at rva 0xB3AC0
> 
> **Source**: `ref:335715f930` · `ref:753ae77bb1`

### 6. Resolve API names at runtime

`T1027` · Confidence **High** · Static

The import table contains only CRT symbols; the real capability APIs are resolved at runtime through FUN_18000ab52 (LoadLibraryA + GetProcAddress), keeping LoadLibrary, process and network functions out of the import table.

> **Evidence**: FUN_18000ab52: LoadLibraryA -> GetProcAddress; import table has only 83 CRT/synchronization/window symbols
> 
> **Source**: `ref:1601ea20da` · `ref:a9c80925bc`

### 7. Preset suspected next-stage module name

`T1574.002` · Confidence **Medium** · Static

Next to the TLS constant area there is a UTF-16 module name W23ib.dll, pointing to a randomly named DLL that may be loaded later; no file drop or load of this name was observed in this run.

> **Evidence**: UTF-16 'W23ib.dll' at rva 0x63F6C; reference at 0xAA11
> 
> **Source**: `ref:dcb3be10b8` · `ref:7e8ccf22a6`


## IOC (Defanged)

### Network

:::note
**No C2 / network IOC recovered** (reason in "Analysis Method and Limitations" below).
:::

### Host

- **No host IOC recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `encryption_algo` | `TLS callback rolling XOR + custom 32-symbol alphabet encoded payload` | Yes | Static |
| `payload_module_name` | `W23ib.dll` | No | Static |
| `encoded_blob_size` | `202 segments / 575409 chars (.rdata 294130 + .data 281279)` | No | Static |

## What Not to Assume

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing the report.

- Do not assert that process injection or reflective loading occurred: this run only statically confirms the encoded payload and runtime API resolution capability; the DLL was not loaded by a host in the sandbox.
- Do not assert a usable C2 address or any outbound connection: no plaintext URL/IP remains after unpacking, and sandbox network monitoring saw no session.
- Do not assert that W23ib.dll was dropped or loaded: only a UTF-16 name string was seen, with no file or process evidence.
- Do not classify it as ransomware or a stealer: no file-encryption or credential-access behavior was found.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Static decompilation (no runtime behavior obtained) |
| Unpacking | Yes (stage2 `ffe87766f7ee26d57508f630f54f79cfe65888e1e9825bf0aa1fba1e5cbc5437`) |

**Limitations and items to verify**

1. The dynamic sandbox produced no new process (the DLL needs a Java/jpackage launcher-like host), so the dynamic channel is empty.
2. The custom 32-symbol alphabet and 202-segment encoded payload were not decrypted to plaintext; C2, install path and configuration could not be extracted.
3. Control-flow flattening leaves the decompiler pseudocode incomplete; some logic is inferred only from disassembly fragments.
4. No public engine or family comparison result was available; the family name is provisional, based on the PDB path and export names.

## Evidence Index

<details>
<summary>Show 17 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:6be8571823` | Sample triage | Original sample has three UPX sections, UPX1 entropy 7.999, packing score 0.85 |
| `ref:361c21b281` | PE structure parsing | Original PE: AMD64 DLL, entry 0xBCA10, 3 sections |
| `ref:37faff4851` | unpack.detect | Identified as UPX, strategy upx_unpack |
| `ref:812b033128` | evidence.record | Static unpack result sha256=ffe87766… |
| `ref:eaa4335efb` | Sample triage | Unpacked: normal PE with 6 sections, 83 imports, 14 exports |
| `ref:a9c80925bc` | Import table parsing | Only CRT/synchronization/user32 symbols, no network/process APIs |
| `ref:d57a5e0698` | pe.exports | 14 JLI_* exports, DLL name loader.dll |
| `ref:1d2ab520d9` | decompile.function | JLI_Launch only calls FUN_180001e5a |
| `ref:535c703744` | decompile.function | TLS callback calls FUN_18000a820 |
| `ref:9a9d4be437` | decompile.function | Rolling XOR decrypts 30 bytes into the TLS block |
| `ref:335715f930` | decompile.function | FUN_180001e5a flattened dispatcher + indirect jump |
| `ref:ae04d8330c` | evidence.record | 202-segment {pointer,length} encoded payload table |
| `ref:7e8ccf22a6` | String extraction | No plaintext URL/C2, only W23ib.dll and similar |
| `ref:23fbba7b82` | dyn.run | Emulation only reaches CRT init, no file/network behavior |
| `ref:cd3eb34302` | Dynamic analysis platform | After detonation no new process, no dump, no network session |
| `ref:7e8ccf22a6` | String extraction | UTF-16 module name W23ib.dll |
| `telemetry:c266833d` | Dynamic telemetry | Dynamic telemetry recorded: 101 process/file events from monitored components; 27 tool/system noise entries filtered |

</details>

---

_This sample is not public; IOCs are defanged. For security research only._
