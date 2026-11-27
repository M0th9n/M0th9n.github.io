---
title: "Malicious sample analysis: HijackLoader (PE · exe · aabe62b0)"
published: 2026-11-26
draft: false
description: "Malicious (confidence: low): HijackLoader · loader/dropper · difficulty hard · dynamic sandbox + static decompilation"
tags: ["Hijack", "loader", "dropper", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-26-HijackLoader-aabe62b0"
---

> [!WARNING]
> **Verdict: malicious** · Family **HijackLoader** (uncertain) · Confidence **low**
> 
> Aliases: IDAT Loader, Hijack Loader
> 
> The sample appears as a UPX-packed 64-bit DLL, with its export table forged into the JLI_* interfaces of the Java launcher jli.dll (DLL name loader.dll, containing duplicate-ordinal exports); the sections embed about 290,000 characters of high-entropy encrypted data and a 216-entry segment description table, the core logic is converted to a private VM/control-flow flattening, and strings are decrypted with stack-based keys mixed by XOR. Decompilation and emulation show that its load path only performs CRT initialisation, and the real payload is decrypted and executed by the VM when the host calls JLI_Launch — a typical detection-evading loader. No real C2 communication was observed within the run window.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **HijackLoader** · Aliases IDAT Loader, Hijack Loader · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · dropper |
| Difficulty | hard |
| First seen | 2026-11-23 17:44:48 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/aabe62b0a4d18efc05b34c30c523081c92c33f116cd6610956e3b50010c6a930/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX multi-layer packing</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Forges Java launcher exports</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Embeds large encrypted payload</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.009</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Private VM flattening obfuscation</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Resolves API addresses at runtime</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.007</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `aabe62b0a4d18efc05b34c30c523081c92c33f116cd6610956e3b50010c6a930` |
| MD5 | _Not recorded_ |
| Size | 717,312 bytes (700.5 KB) |
| Type | PE · `exe` |

## Behavior Analysis

There are **9** behaviors in total, each backed by evidence; **7** are statically available and **2** were obtained through dynamic analysis.

### 1. UPX multi-layer packing

`T1027.002` · Confidence **high** · Static

It is packed with a UPX0/UPX1/UPX2 three-section layout; UPX1 has entropy 7.755 and is writable and executable, the import table has only 5 symbols left, and the static characteristics match UPX.

> **Evidence**: scan.triage: packing.score=0.85, section names UPX0/UPX1/UPX2, UPX1 entropy 7.755; unpack.detect judges packer=upx
> 
> **Source**: `ref:f6fe8000a4` · `ref:669ceeb21c` · `ref:9617e8a390`

### 2. Forged Java launcher exports

`T1036.005` · Confidence **high** · Static

After unpacking, the DLL's internal name is loader.dll and it exports 14 Java-launcher interfaces such as JLI_CmdToArgs/JLI_Launch/JLI_MemAlloc, with ordinals 8-14 duplicating 1-7 — a fabricated masquerade export table.

> **Evidence**: pe.exports: dll_name=loader.dll, 14 symbols (7 named + 7 duplicate ordinals), JLI_Launch is only a 5-byte jump to 0x180001AEE
> 
> **Source**: `ref:77c43da146` · `ref:e3330227d4` · `ref:2b12cca353`

### 3. Embedded large encrypted payload

`T1027.009` · Confidence **high** · Static

In .rdata it embeds 294059 characters of base64url ciphertext, which decodes to 220544 bytes with entropy 7.9993; the same-range section in .data also holds a 216-entry {pointer,length} descriptor table that cuts the whole ciphertext block into 102 consecutive segments and concatenates them into a 651126-character encrypted stream.

> **Evidence**: .rdata from RVA 0x1A000, 294059 characters; .data RVA 0xC53B0 descriptor table 216 entries; decode/concatenate script produced 488344 bytes, entropy 7.9996
> 
> **Source**: `ref:712329baef` · `ref:a1ce9fe891` · `ref:6762535fbd`

### 4. Private VM flattening obfuscation

`T1027` · Confidence **high** · Static

JLI_Launch is changed to a 5-byte entry that jumps into the control-flow-flattening dispatcher at 0x180001AEE: state is taken from a stack constant table and dispatched through a jump table, and around 0x180006D81 an XOR loop processes the buffer byte by byte with the stack-based key table.

> **Evidence**: decompile 0x180001AEE shows jumptable dispatch; disasm 0x180006D81 shows the `xor byte ptr [rcx], dl` loop and secondary dispatch; around 0x1800097D0 appear PRNG constants 0x9E3779B97F4A7C15/0xBF58476D1CE4E5A7/0x94D049BB133111EB with a 64-byte shuffle
> 
> **Source**: `ref:859a0c2a1e` · `ref:8fd803cffa` · `ref:941b99c2da` · `ref:1f54f9259f`

### 5. Decrypts strings at runtime

`T1140` · Confidence **medium** · Static

Strings and configuration are not stored in plaintext in static data; they must be decrypted at runtime by the VM dispatcher together with the stack-based key table and PRNG shuffle before use; static scanning found no plaintext URL, path or command.

> **Evidence**: the XOR decryption loop at 0x180006D81 + the hash shuffle at 0x1800096B6/0x1800097D0; scan.strings on the unpacked file yielded only CRT language tables and alphabets, no network/path strings
> 
> **Source**: `ref:941b99c2da` · `ref:52a7e91157` · `ref:a1ce9fe891`

### 6. Dynamically resolves API addresses

`T1027.007` · Confidence **high** · Dynamic

After UPX self-extraction completes, the loader resolves and fills 89 imported function pointers one by one via LoadLibraryA + GetProcAddress, including LoadLibraryA/GetProcAddress/VirtualProtect, rather than relying entirely on the static import table.

> **Evidence**: emulation observation: after LoadLibraryA(KERNEL32.DLL), consecutive GetProcAddress calls resolve CloseHandle/CreateFileW/.../VirtualProtect; then VirtualProtect(0x180000000,0x1000,0x40)
> 
> **Source**: `ref:ae260b77f0` · `ref:61c52650d2`

### 7. Stays in CRT during load

`T1106` · Confidence **high** · Dynamic

When loaded as a DLL, DllMain only performs CRT initialisation (GetSystemTimeAsFileTime/QueryPerformanceCounter/FlsAlloc/VirtualProtect etc.) and returns, creating no files, threads or network connections; the malicious logic requires the host to call the exported function to trigger.

> **Evidence**: emulation observed 31 API calls, all CRT initialisation; decompile entry/DllMain shows __security_init_cookie + Fls callback registration; sandbox timeline has 0 new processes, network monitoring has no sample-related domains
> 
> **Source**: `ref:af4155f9d0` · `ref:554eab6c62` · `ref:83ba3f50dd` · `ref:cfb5ebd132`

### 8. Anti-debugging and CPU probing

`T1622` · Confidence **medium** · Static

It imports IsDebuggerPresent and uses cpuid at .text RVA 0xBF72 for CPU/virtual-machine feature probing, an anti-analysis check.

> **Evidence**: unpack.antidebug: IsDebuggerPresent(import) + cpuid code @ RVA 0xBF72; pe.imports contains IsDebuggerPresent
> 
> **Source**: `ref:a569efa0f3` · `ref:61c52650d2`

### 9. DLL form waits for a host

`T1129` · Confidence **high** · Static

The file extension is .exe, but the PE header characteristics are DLL and DllMain has no malicious action; it actually needs a host such as java.exe to load it and call JLI_Launch before entering the VM payload path.

> **Evidence**: pe.parse: characteristics=DLL, subsystem=GUI, entry is DllMainCRTStartup; direct sandbox submission observed no execution
> 
> **Source**: `ref:6762535fbd` · `ref:554eab6c62` · `ref:cfb5ebd132`


## IOCs (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis Method and Limitations" at the end of this report).
:::

### Host

- **No host IOC was recovered.**

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `loader_entry` | `exports JLI_Launch (RVA 0xA162) -> 0x180001AEE VM dispatcher` | Yes | Static |
| `embedded_payload` | `.rdata from RVA 0x1A000, 294059-character base64url ciphertext (about 220544 bytes, entropy 7.999)` | Yes | Static |
| `embedded_key_material` | `.data RVA 0x6D000 / 0x6D049, 180 characters total (73+107) base64url strings` | No | Static |
| `segment_table` | `.data from RVA 0xC53B0, 216-entry {ptr,len,0} descriptor table, 102 segments consecutively covering the whole ciphertext block, 651126 characters in total` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not assert that C2 egress occurred: within the run window network monitoring recorded only Windows system baseline traffic, with no sample-related domains or IPs.
- Do not assert that the sample writes to disk, creates services, scheduled tasks or registry entries: no corresponding file/registry/service events were observed, and the load stage performs only CRT initialisation.
- Do not take the JLI_* export names as evidence that the sample is a legitimate Java runtime library: the export table has only 14 entries with ordinals 8-14 duplicated, and JLI_Launch is only a 5-byte jump into a private VM — forged.
- Do not assert TEA/XTEA use based on the scanned 0x9E3779B9 constant: that value appears in the low 32 bits of the SplitMix64/PRNG constant 0x9E3779B97F4A7C15.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | Yes (stage2 `b494f10188017a89b472982b3818ce86a74749de501a8ddc44e0da0a4f8054f0`) |

**Limitations and pending verification**

1. The embedded payload is encrypted by a private VM + PRNG shuffle; no plaintext C2/configuration was obtained statically, and the decryption key for the 294059-character ciphertext could not be recovered.
2. The sample is a DLL, and direct sandbox submission cannot trigger JLI_Launch; with no java.exe host, DllMain only performs CRT initialisation, so no real malicious behavior or network session was obtained.
3. The family determination is only a candidate: no family strings, configuration or plaintext payload were obtained to map one-to-one to a known family.
4. Manual emulation of the string-decryption routine was limited by TLS/runtime global initialisation and could not run fully to the plaintext-output stage.
5. On the network side only Windows system baseline traffic (Windows Update/OCSP etc.) was observed, which does not constitute C2 evidence for the sample.

## Evidence Index

<details>
<summary>Expand 26 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:f6fe8000a4` | Sample triage | Hash/imphash/section entropy/packing score: packing.score=0.85, UPX0-2, UPX1 entropy 7.755, 5 imports |
| `ref:9617e8a390` | PE structure parsing | Original PE: AMD64 DLL, 3 sections, entry RVA 0xCA470, 14 exports |
| `ref:77c43da146` | pe.exports | Original export table: dll_name=loader.dll, JLI_* 14 entries in total, with duplicate ordinals |
| `ref:669ceeb21c` | unpack.detect | Packer detection: packer=upx, confidence 0.9, strategy upx_unpack |
| `ref:64e6e99490` | evidence.record | Static `upx -d` unpacking result and the unpacked artifact sha256 |
| `ref:6762535fbd` | PE structure parsing | Unpacked PE: 6 sections .text/.rdata/.data/.pdata/.tls/.reloc, entry RVA 0xB9C0, DLL |
| `ref:e3330227d4` | pe.exports | Unpacked export table: loader.dll + 14 JLI_* entries (duplicate ordinals) |
| `ref:61c52650d2` | Import table parsing | Unpacked imports: 89 symbols, KERNEL32/user32/api-ms-win-core-synch |
| `ref:788240d3d0` | Hash and fingerprint | Unpacked artifact sha256=b494f101...854f0 |
| `ref:eef040bd2c` | scan.entropy | Unpacked whole-file entropy 6.549, .rdata 6.251, .data 6.117 |
| `ref:712329baef` | evidence.record | Parsing result of the embedded ciphertext block/key material/216-entry segment table |
| `ref:2b12cca353` | decompile.function | JLI_Launch(RVA 0xA162): 5-byte call to 0x180001AEE then return |
| `ref:859a0c2a1e` | decompile.function | 0x180001AEE: stack key constants + jumptable flattening dispatch |
| `ref:941b99c2da` | disasm.function | 0x180006D81: XOR decryption loop and state dispatch |
| `ref:1f54f9259f` | disasm.function | 0x1800097D0: SplitMix64/PRNG constants and 64-byte shuffle |
| `ref:52a7e91157` | decompile.function | 0x1800096B6: state-dispatched string-handling routine |
| `ref:554eab6c62` | decompile.function | DllMainCRTStartup: security cookie + CRT initialisation |
| `ref:83ba3f50dd` | decompile.function | User DllMain: Fls callback registration and other CRT logic, no malicious action |
| `ref:a569efa0f3` | unpack.antidebug | Anti-debugging: IsDebuggerPresent import + cpuid @ RVA 0xBF72 |
| `ref:27fe08862d` | Cryptographic constant identification | 0x9E3779B9 constant hit (actually the low 32 bits of a PRNG constant) |
| `ref:af4155f9d0` | dyn.run | Unpacked DLL emulation: 31 APIs, all CRT initialisation, no file/network |
| `ref:ae260b77f0` | dyn.run | Original PE emulation: after UPX unpacking, LoadLibraryA/GetProcAddress resolve 89 imports |
| `ref:bdb1b1b0b4` | emu.run | Cold-start emulation from JLI_Launch: stopped at 0x1800019C6 when the TLS pointer was missing |
| `ref:cfb5ebd132` | Dynamic analysis platform | Sandbox submission: 755 polls, 0 candidate processes, hollows only hit fakenet.exe, rolled back |
| `ref:a1ce9fe891` | String extraction | Unpacked strings: 419 ASCII/90 UTF-16, no plaintext URL/path/flag |
| `telemetry:aabe62b0` | Dynamic telemetry | Dynamic telemetry recorded: 102 process/file events from the monitoring component; 22 tool/system noise entries filtered |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
