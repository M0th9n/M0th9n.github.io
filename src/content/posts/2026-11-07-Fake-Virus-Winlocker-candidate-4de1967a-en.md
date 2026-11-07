---
title: "Malware Analysis: Fake-Virus Winlocker (candidate) (PE · exe · 4de1967a)"
published: 2026-11-07
draft: false
description: "Malicious (low confidence): Fake-Virus Winlocker (candidate) · ransomware · difficulty hard · Dynamic sandbox analysis + static decompilation"
tags: ["Fake-Virus Winlocker", "ransomware", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-07-Fake-Virus-Winlocker-candidate-4de1967a"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Fake-Virus Winlocker (candidate)** (uncertain) · Confidence **low**
> 
> Aliases: Winlocker, Fake VIRUS locker, Ransom.Win32.Winlocker (candidate)
> 
> A 64-bit GUI PE with empty import and resource tables, whose entry point and many functions are obfuscated with opaque predicates; after real execution in an isolated sandbox, paired lock-screen/ransom texts ('This is a VIRUS!!!! Do you want to run the file?' and 'To remove the window, you must CRYPT FILE!', title 'Warning') were recovered from the process's private memory. Together with rdtsc/cpuid anti-analysis, manual PEB API resolution, and runtime string decryption, this is a typical Winlocker/ransomware-type malicious program. However, no file encryption, persistence, or outbound connection was observed within the sandbox time window.

## Overview

| Item | Content |
|:--|:--|
| Family | **Fake-Virus Winlocker (candidate)** · aliases Winlocker, Fake VIRUS locker, Ransom.Win32.Winlocker (candidate) · _uncertain_ |
| Confidence | **low** |
| Behavior class | ransomware |
| Difficulty | hard |
| First seen | 2026-11-06 14:57:55 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/4de1967a36849e08f2396f983363692c6fb288dc7382c20b7c0320741177dceb/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Strip the import table</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Walk PEB for modules</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Decrypt strings at runtime</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Show fake virus prompt</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1204</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Display lock-screen ransom</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1486</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `4de1967a36849e08f2396f983363692c6fb288dc7382c20b7c0320741177dceb` |
| MD5 | _not recorded_ |
| Size | 1,384,960 bytes (1.3 MB) |
| Type | PE · `exe` |

## Behavior analysis

**8** behaviors in total, each backed by evidence; **5** are statically available and **3** were obtained through dynamic analysis.

### 1. Strip the import table

`T1027` · Confidence **high** · static

The PE import directory is empty (IMPORT RVA=0, size=0), and the export table and resource directory are empty as well; the program has no statically imported symbols, so every system API must be resolved by itself at runtime.

> **Evidence**: pe.parse: data_directories[1] IMPORT rva=0 size=0; scan.triage: import_dll_count=0 / import_symbol_count=0
> 
> **Source**: `ref:f9a68b1201` · `ref:8807d06e90`

### 2. Walk the PEB to find modules

`T1027` · Confidence **high** · static

It obtains the PEB via gs:[0x60], walks the loaded-module list through InInitializationOrderLinks (+0x20), reads FullDllName (+0x48 length / +0x50 buffer) and copies the module path byte by byte, then calls custom hashing and resolution routines to complete API binding.

> **Evidence**: RVA 0x14538: mov rax, qword ptr gs:[0x60]; then walks the [r14+0x20] list, reads [r14+0x48]/[r14+0x50], calls 0x3900B4AE8 (hash) and 0x390024A60 (resolve)
> 
> **Source**: `ref:53b2c65f07` · `ref:44f8a0e4d7`

### 3. Decrypt strings at runtime

`T1027` · Confidence **high** · dynamic

The file contains no readable functional strings (static analysis finds only 426 ASCII strings, all code fragments), while plaintext environment blocks and functional texts appear in bulk in the process's private memory, indicating that strings are decrypted at runtime and written to heap memory.

> **Evidence**: scan.strings: ascii_count=426, flag_hits=0; memory forensics: complete plaintext prompt strings appear starting at 0x20FD38ABE40
> 
> **Source**: `ref:45202b7198` · `ref:91f4da466b`

### 4. Show a fake virus confirmation prompt

`T1204` · Confidence **medium** · dynamic

The decrypted memory contains the text 'This is a VIRUS!!!! Do you want to run the file?' and the title 'Warning', a social-engineering popup that uses a "virus warning" to induce the user to confirm/execute.

> **Evidence**: memory 0x20FD38ABE40 = 'This is a VIRUS!!!! Do you want to run the file?'; 0x20FD38B35A0 = 'Warning'
> 
> **Source**: `ref:45202b7198`

### 5. Display a lock-screen ransom prompt

`T1486` · Confidence **medium** · dynamic

The decrypted memory contains 'To remove the window, you must CRYPT FILE!', a screen-lock/ransom prompt; within the sandbox time window no file was encrypted and no ransom note was written to disk, so the logic did not trigger or did not reach the encryption stage.

> **Evidence**: memory 0x20FD38ABE72 = 'To remove the window, you must CRYPT FILE!'
> 
> **Source**: `ref:45202b7198`

### 6. rdtsc timing anti-debugging

`T1497.003` · Confidence **high** · static

At RVA 0x19EE it reads a timestamp with rdtsc, takes the difference, computes it modulo 0x47 and adds 10 as a delay/randomization parameter, a timing-based anti-debugging and environment probe.

> **Evidence**: RVA 0x19EE: rdtsc; shl rdx,0x20; or rax,rdx; div rcx (0x47); add eax,0xa; call 0x390002578
> 
> **Source**: `ref:a96bc655fb` · `ref:44f8a0e4d7`

### 7. cpuid environment probing

`T1497.001` · Confidence **medium** · static

The code contains a cpuid sequence that reads CPU/virtualization characteristics and, together with the rdtsc check, determines whether it is running in a virtual machine or debugger.

> **Evidence**: unpack.antidebug reports cpuid (VM/debug probe) @ RVA 187967 (0x2DE3F)
> 
> **Source**: `ref:44f8a0e4d7`

### 8. Constant-hash obfuscation of symbols

`T1027` · Confidence **high** · static

Around RVA 0x30F0F it performs a rolling hash with 0x9E3779B9 as the increment (h = (h ^ (b<<8)) + 0x9E3779B9, followed by shift/multiply mixing) to hide API/string names; the constant appears in the hash loop, not in a TEA encryption round.

> **Evidence**: RVA 0x30F0E add eax,0x9E3779B9; followed by shr/shl/imul mixing; scan.crypto misreports the same constant as a TEA/XTEA delta
> 
> **Source**: `ref:4926bc2fcc` · `ref:fa93f2042e`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis method and limitations" at the end).
:::

### Host

- **No host IOC was recovered.**

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `messagebox_text_run_prompt` | `This is a VIRUS!!!! Do you want to run the file?` | yes | dynamic |
| `winlocker_message` | `To remove the window, you must CRYPT FILE!` | yes | dynamic |
| `window_title` | `Warning` | no | dynamic |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- Do not conclude from the 0x9E3779B9 constant alone that the sample uses TEA/XTEA file encryption — the disassembly shows the constant inside a rolling hash loop, with no TEA encryption rounds.
- No file encryption, ransom note on disk, or desktop/input locking was observed, so it cannot be asserted that the sample completed encryption or that a working decryptor exists.
- Network monitoring recorded no outbound connection from the sample itself, so no C2 domain or IP can be given.
- No child processes, process injection, or service/scheduled-task persistence were observed, so it cannot be classified as an injector, downloader, or loader.
- The family name is only a candidate: two prompt texts are insufficient to map one-to-one to a known family, and no specific family should be asserted publicly.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. After launch the sample waits for user interaction; the sandbox observation window did not trigger subsequent logic, so encryption/persistence/outbound paths were not observed.
2. With an empty import table and all strings decrypted at runtime, the complete configuration cannot be recovered statically; no C2, mutex, install path, or encryption algorithm fields were obtained.
3. The texts recovered from memory prove they were decrypted and resident, but no window-display event or user interaction result was directly captured.
4. Family fingerprints are insufficient: no YARA hits, no configuration extraction, and no multi-engine labels to compare.
5. The .text section is heavily obfuscated and full control-flow recovery was not completed; function-level semantics cover only the entry point, PEB resolution, hashing, and anti-debugging fragments.

## Evidence index

<details>
<summary>Show 13 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hashing and fingerprints | sha256=4de1967a36849e08f2396f983363692c6fb288dc7382c20b7c0320741177dceb, md5=cb201373d521bfed5555838bf099c366, size=1384960 |
| `ev-000002` | pe.parse / scan.rich | PE64 GUI, 4 sections, IMPORT/EXPORT/RESOURCE directories all zero, Rich header with 5 MSVC toolchain records |
| `ev-000008` | String extraction | Only 426 ASCII strings statically, no UTF-16 strings, no functional prompt strings |
| `ev-000009` | Cryptographic constant identification | 0x9E3779B9 constant hit (later confirmed by disassembly as part of a rolling hash, not TEA) |
| `ev-000012` | decompile.entry | Entry function is mostly constant arithmetic/opaque predicates and switch dispatch, typical control-flow obfuscation |
| `ref:53b2c65f07` | disasm.function | gs:[0x60] obtains the PEB, walks the module list and reads FullDllName, calls hash/resolve routines |
| `ref:a96bc655fb` | disasm.function | RVA 0x19EE rdtsc timing difference, modulo 0x47 then add 0x0A |
| `ref:44f8a0e4d7` | unpack.antidebug | Statically identifies rdtsc timing, PEB access (gs:[0x60]), cpuid (VM/debug probe) |
| `ref:3a5ce3ff22` | Dynamic analysis platform | Sandbox detonation and rollback; pid 8076 resident, two targeted memory dumps and full scans completed; no new child processes |
| `ref:7a4c780d09` | network-log | No outbound traffic from the sample process in network monitoring logs; domains are all system update/certificate traffic |
| `ref:45202b7198` | memory-forensics | Process private memory at 0x20FD38ABE40/0x20FD38ABE72/0x20FD38B35A0 recovered the virus prompt, lock-screen ransom text and Warning title |
| `ref:4926bc2fcc` | disasm.function | Rolling hash/mixing loop involving 0x9E3779B9, confirming it is not TEA encryption |
| `c2_evidence:4de1967a` | Connection evidence extraction | Dynamic network monitoring recorded 2 connection attempts to maps[.]windows[.]com:443; no complete session was captured |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
