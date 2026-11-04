---
title: "Malware Analysis: Unattributed MSI reflective loader (other · msi · 9666fe7e)"
published: 2026-11-03
draft: false
description: "Malicious (low confidence): Unattributed MSI reflective loader · loader/dropper · difficulty medium · dynamic sandbox + static decompilation"
tags: ["loader", "dropper", "MSI"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-03-Unattributed-MSI-reflective-loader-9666fe7e"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Unattributed MSI reflective loader** (uncertain) · Confidence **low**
> 
> The only custom action in the MSI database, Type=4166, is a 64-bit VBScript action hooked at InstallExecuteSequence number 1534 (NOT REMOVE). During installation it pulls a PowerShell script from the Binary table, writes it to %TEMP%, and runs it with a hidden PowerShell window; that PowerShell then reflectively reads a second Binary stream, reverses a custom transposition to recover a 1.43 MB PE32+ x64 payload, and maps and executes it manually. The entire chain can be recovered from in-package bytes and scripts, making this a typical fileless/reflective-loading installer.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unattributed MSI reflective loader** · _uncertain_ |
| Confidence | **low** |
| Behavior class | loader · dropper |
| Difficulty | medium |
| First seen | 2026-11-01 17:17:42 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/9666fe7e1ff1f42bc8e9035cb54358dfeab009970ed005d3e2c9ecd1b54a40dc/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Hidden VBScript on install</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.005</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Read script from package</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Spawn hidden PowerShell</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Decode second-stage loader</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Transpose embedded PE</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `9666fe7e1ff1f42bc8e9035cb54358dfeab009970ed005d3e2c9ecd1b54a40dc` |
| MD5 | _not recorded_ |
| Size | 3,032,064 bytes (2.9 MB) |
| Type | other · `msi` |

## Behavior analysis

**9** behaviors in total, each backed by evidence, all statically recoverable.

### 1. Hidden VBScript on install

`T1059.005` · Confidence **high** · static

The MSI custom action PQKh1GUxbiud is Type=4166 (VBScript, 64-bit script, continue on error), placed at step 1534 of InstallExecuteSequence with condition NOT REMOVE, executing immediately after InstallInitialize(1500) without user interaction.

> **Evidence**: CustomAction table: Type=4166, Source=pTSPSnJ00twr, Target=C2wYrqeGRUN; InstallExecuteSequence: PQKh1GUxbiud=1534
> 
> **Source**: `ev-000096`

### 2. Read script from package

`T1140` · Confidence **high** · static

The VBScript executes Session.Database.OpenView with SELECT `Data` FROM `Binary` WHERE `Name`='orAiO4EgE7', writing the in-package PowerShell script to %TEMP%\<random>.ps1 via ADODB.Stream in windows-1252 encoding.

> **Evidence**: VBScript: ivygsiq="SELECT `Data` FROM `Binary` WHERE `Name`='orAiO4EgE7'"; ADODB.Stream.SaveToFile dyhca,2
> 
> **Source**: `ev-000097`

### 3. Spawn hidden PowerShell

`T1059.001` · Confidence **high** · static

It runs %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File <temp ps1> <MSI path>, waits for completion, then deletes the temporary script.

> **Evidence**: ckcj="""" & ybpsnhhz & """ -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & dyhca ...; sefltemlri.Run ckcj,0,True
> 
> **Source**: `ev-000097`

### 4. Decode second-stage loader

`T1027` · Confidence **high** · static

PowerShell reconstructs a 10090-byte reflective loader from an embedded decimal dot-pair string ('a.b' -> b*16+a), then executes it in the same process with [powershell]::Create.AddScript, never touching disk.

> **Evidence**: $vJ7g1y3E9GZup.Add([byte]([int]$G5xvZ0n[1]*16+[int]$G5xvZ0n[0])); $YVcf5k9cWXTj.AddScript($mFfXYu7EuB8p)
> 
> **Source**: `ev-000097`

### 5. Transpose embedded PE

`T1140` · Confidence **high** · static

The reflective loader uses Reflection.Emit to declare msi.dll's MsiOpenDatabase/MsiDatabaseOpenView/MsiViewExecute/MsiViewFetch/MsiRecordReadStream, reads Binary stream SfILm5Js, and applies a transposition described by a 4-byte header (stride 2, offset 0, reverse flag 0) to recover a PE32+ x64 file (sha256 1fa8d8fe..., 1430016 bytes).

> **Evidence**: $Vj9izBm3YRlsH='SfILm5Js'; $o1675[$r5219]=$KeZy0hIuw4mWuD[4+($r5219*$w8159)+$f9811]; e_lfanew check + machine 0x20B
> 
> **Source**: `ev-000097`

### 6. Manually map and execute payload

`T1620` · Confidence **high** · static

If the CLR directory is 0, it uses VirtualAlloc/VirtualProtect to map the payload into memory per the PE header layout and calls the entry point; if the CLR directory is non-zero it instead uses Assembly.Load, a form of reflective code loading.

> **Evidence**: $d7PeWRDT0v::VirtualAlloc(...12288,4); VirtualProtect; [Reflection.Assembly]::Load($KeZy0hIuw4mWuD); EntryPoint.Invoke
> 
> **Source**: `ev-000097` · `ref:78892cdf68`

### 7. Disguised as an equalizer application

`T1036.005` · Confidence **medium** · static

The payload carries forged version information (Media Code Core / Equalizer Renderer Desktop / equalizer_renderer), 25 bitmap resources, and GUI window imports (CreateWindowExA/RegisterClassA/ShowWindow) to masquerade as a normal desktop program; the code section is also padded with large amounts of meaningless instructions and random constants.

> **Evidence**: VS_VERSION_INFO: CompanyName=Media Code Core, FileDescription=Equalizer Management and Refactor Service; .rsrc contains 25 BITMAP; imports USER32 CreateWindowExA/RegisterClassA/ShowWindow
> 
> **Source**: `ref:850390c96b` · `ref:78892cdf68` · `ref:cf94d56592`

### 8. Drop low-entropy marker file

`T1036` · Confidence **high** · static

The File/Component/Directory tables extract a 36-byte file from cab1.cab to %LOCALAPPDATA%\L4PjdK9K3\lAJ3abdB.ini containing two random tokens plus a 16-hex-digit string, usable as an infection/campaign marker.

> **Evidence**: File: dljO6DyTNmT1K -> lAJ3abdB.ini, 36 bytes, Component FLlml5rFIbrOu, Directory JM1crRaqKS3(LocalAppDataFolder); cab content TLvrxBmv FxwJ3gkF6 fa5371cd64b61a55
> 
> **Source**: `ev-000096`

### 9. Encrypted second-stage data section

`T1027` · Confidence **high** · static

In the recovered PE, .rdata is about 551 KB with entropy 7.998, almost entirely random over the first 0x8D000 bytes; .text is only 46 KB and full of invalid instructions, indicating the final functional payload is still encrypted/obfuscated and cannot be extracted statically.

> **Evidence**: .rdata rva=53248 size=551424 entropy=7.998; .text entropy=6.028; entry at 0x1000 is jmp 0x140001000
> 
> **Source**: `ref:bea450dde0` · `ref:850390c96b` · `ref:985b898bed`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC recovered** (see "Analysis method and limitations" at the end).
:::

### Host

**Drop paths**

- `%LOCALAPPDATA%\L4PjdK9K3\lAJ3abdB.ini`
- `%TEMP%\<random>.ps1`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `custom_action` | `PQKh1GUxbiud / Type=4166 / Source=pTSPSnJ00twr / Target=C2wYrqeGRUN / Sequence=1534 / Condition=NOT REMOVE` | yes | static |
| `binary_ps1_stream` | `orAiO4EgE7 (84305 bytes, PowerShell decoding shell)` | yes | static |
| `binary_payload_stream` | `SfILm5Js (2860036 bytes, transposed PE32+ x64)` | yes | static |
| `payload_decode_params` | `header[0]=2 (stride), header[1]=0 (offset), header[2]=0 (reverse), data taken as byte[4+i*stride+offset]` | yes | static |
| `install_path` | `%LOCALAPPDATA%\L4PjdK9K3\lAJ3abdB.ini` | yes | static |
| `marker_content` | `TLvrxBmv FxwJ3gkF6 fa5371cd64b61a55` | no | static |
| `product_code` | `{7EF695EE-EE0C-4231-B342-0043193AB92A}` | yes | static |
| `upgrade_code` | `{000D8C9B-FC91-4BE1-8A76-4614ADD918A6}` | no | static |
| `install_scope` | `per-user (MSIINSTALLPERUSER=1)` | no | static |
| `env_var` | `VjOAY8awfi5zo (carries the original MSI path, passed to PowerShell)` | no | static |
| `stage2_sha256` | `1fa8d8fe397706f55fe93ace8a4e19ae06d52d5affa078e7d9d9b56ac205a38a` | no | static |
| `encryption_algo` | `custom transposition (outer) + second-stage .rdata encrypted with an unknown algorithm (about 512 KB, entropy 7.998), not decrypted` | no | static |

## Must not claim

:::important
The following conclusions are **prone to misjudgment**; take care when citing this report.

- Do not call it ransomware or a stealer: no file encryption or credential/browser data access behaviors were observed.
- Do not claim C2 beaconing or download activity: no URL/IP was found statically, emulation produced no network events, and c2 is empty.
- Do not assert persistence via services or scheduled tasks: no such items were found in the MSI tables or the code.
- Do not treat the high-entropy .rdata region as the final RAT payload or a specific family: that region has not been decrypted.
- Do not treat the MSI uninstall registry entry as malicious persistence evidence: it is standard Windows Installer registration.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | yes (stage2 `1fa8d8fe397706f55fe93ace8a4e19ae06d52d5affa078e7d9d9b56ac205a38a`) |

**Limitations and pending verification**

1. This was pure static analysis: the MSI installation flow was not executed, and the recovered PE was not run on a real host; all behaviors come from script/database/PE structure evidence, reproduced=false.
2. The second-stage PE's .rdata (1.43 MB file, about 512 KB .rdata) is high-entropy encrypted data with no recovered key/algorithm, so its final C2, stealing, or remote-control functionality cannot be confirmed and c2 is empty.
3. User-mode instruction emulation of the recovered PE stopped after only 2 APIs (InitializeCriticalSection, __acrt_iob_func) with no file/network/registry events, so runtime behaviors cannot be ruled out on that basis.
4. No vendor engine or YARA corroboration was obtained, so family attribution is uncertain (uncertain=true); it is classified as an MSI reflective loader purely by technical chain.
5. MSI installation creates a directory under %LOCALAPPDATA% and writes the .ini; the actual user-directory path varies by environment.

## Evidence index

<details>
<summary>Expand 10 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000096` | evidence.record | Read-only parse of the MSI database: CustomAction Type=4166/VBScript/seq1534, three Binary streams, File/Component/Directory drop paths and marker content, ProductCode/UpgradeCode |
| `ev-000097` | evidence.record | Recovered execution chain: VBScript reads Binary orAiO4EgE7, writes %TEMP% ps1 and runs hidden PowerShell; PowerShell decodes the 10090-byte reflective loader from decimal pairs; reads SfILm5Js, reverses the transposition to recover the PE and manually maps/Assembly.Loads it |
| `ref:850390c96b` | PE structure parsing | Recovered payload structure: PE32+ x64 GUI, 7 sections, entry RVA 36934, CLR directory 0, .rsrc 806824 bytes |
| `ref:78892cdf68` | Import table parsing | Recovered payload imports: KERNEL32 (VirtualAlloc/VirtualProtect/VirtualQuery/thread pool), USER32 window APIs, MSVC CRT; imphash 241b6302ab625ed2e79213b6b4dfdeb2 |
| `ref:bea450dde0` | scan.entropy | Recovered payload section entropy: .rdata 7.998 (encrypted/compressed), .text 6.028, overall 4.741 |
| `ref:cf94d56592` | String extraction | Recovered payload strings: version info/import names/large amounts of code bytes; no URL or C2 seen |
| `ref:5a8eaf0bcc` | String extraction | Raw MSI string scan: 3183 ASCII, 292 UTF-16; ProductCode, ComponentId and other installation database strings visible |
| `ref:03766d62e6` | dyn.run | Recovered payload user-mode emulation: only InitializeCriticalSection and __acrt_iob_func executed, no file/network/registry events |
| `ref:985b898bed` | disasm.function | Entry-point disassembly: 0x140001000 first sets global state and calls 0x140001020; includes PEB access and CRT initialization |
| `ref:d5336f7ac0` | disasm.function | TLS callback disassembly: 0x14000b340 is a standard CRT TLS initialization loop, not anti-debugging |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
