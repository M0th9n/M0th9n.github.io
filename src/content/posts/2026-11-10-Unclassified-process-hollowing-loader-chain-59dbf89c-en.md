---
title: "Malware Analysis: Unclassified process-hollowing loader chain (other · vbe · 59dbf89c)"
published: 2026-11-10
draft: false
description: "Malicious (low confidence): Unclassified process-hollowing loader chain · dropper/loader · difficulty medium · Static analysis only"
tags: ["dropper", "loader"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-10-Unclassified-process-hollowing-loader-chain-59dbf89c"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Unclassified process-hollowing loader chain** (uncertain) · Confidence **low**
> 
> Multi-layer static decryption and .NET IL decompilation together attest to a complete attack chain: a script disguised as a .vbe embeds a 2 MB Base64 PowerShell script, which decrypts stage-two PowerShell with AES-256-CBC, then decrypts and reflectively loads a .NET assembly with Base64+XOR; that assembly resolves kernel32/ntdll's VirtualAllocEx/WriteProcessMemory/ReadProcessMemory/ZwUnmapViewOfSection/CreateProcessA/SetThreadContext/ResumeThread, defines the corresponding delegates and PROCESS_INFORMATION/STARTUPINFO structures, and together with the target path aspnet_compiler.exe and 284672-byte high-entropy PE passed in by PowerShell, constitutes a typical process-hollowing injection loader. It was not actually detonated, and the C2 was not recovered.

## Overview

| Item | Content |
|:--|:--|
| Family | **Unclassified process-hollowing loader chain** · _uncertain_ |
| Confidence | **low** |
| Behavior class | dropper · loader |
| Difficulty | medium |
| First seen | 2026-11-08 16:24:18 |
| Analysis method | Static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/59dbf89c137441569e22add76ff1208a846c6b5cd1e695d2960bace52df7765e/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Disguised VBE dropper script</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Drop randomly named PS1</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Run PS1 in hidden window</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">AES-decrypt the next stage</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Reflectively load .NET injector</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `59dbf89c137441569e22add76ff1208a846c6b5cd1e695d2960bace52df7765e` |
| MD5 | _not recorded_ |
| Size | 2,059,104 bytes (2.0 MB) |
| Type | other · `vbe` |

## Behavior analysis

**9** behaviors in total, each backed by evidence, and all are statically available.

### 1. Disguised VBE dropper script

`T1036` · Confidence **high** · static

The file is distributed with a .vbe extension, but the actual payload begins with the readable text "Option Explicit" and is not in VBE-encoded format; this is extension masquerading to evade file-type-based blocking.

> **Evidence**: from file offset 0x0 is plaintext VBScript; the single line of m_b64Payload in the file is 2,056,024 characters long (line 13)
> 
> **Source**: `ev-000011`

### 2. Drop a randomly named PS1

`T1059.001` · Confidence **high** · static

The script checks for and creates the C:\Temp\ directory, generates a .ps1 named with 8 random uppercase letters, and writes content decoded from the embedded Base64 via MSXML2.DOMDocument.

> **Evidence**: Const WORK_ROOT="C:\Temp\"; Const TMP_SUFFIX=".ps1"; RandomTag picks A-Z 8 times; m_fs.CreateTextFile(m_stagePath, True)
> 
> **Source**: `ev-000011`

### 3. Execute the PS1 in a hidden window

`T1564.003` · Confidence **high** · static

It calls "powershell.exe -nop -ep bypass -file <script>" via WScript.Shell.Run with window parameter 0 (hidden) and waits for it to return, then deletes the dropped script.

> **Evidence**: Const PS_INVOKE="powershell.exe -nop -ep bypass -file """; m_wsh.Run m_launchCmd, 0, True; CleanupArtifacts -> DeleteFile
> 
> **Source**: `ev-000011`

### 4. AES-decrypt the next stage

`T1140` · Confidence **high** · static

The first-stage PowerShell decrypts 1,123,568 bytes of embedded ciphertext with AES-256-CBC/PKCS7; the key and IV are both hard-coded as Base64, and the decrypted result is passed to Invoke-Expression for execution.

> **Evidence**: New-Object System.Security.Cryptography.AesManaged; $aes.Mode=CBC; $aes.Padding=PKCS7; Invoke-Expression $decryptedScript
> 
> **Source**: `ev-000011`

### 5. Reflectively load the .NET injector

`T1620` · Confidence **high** · static

The second-stage PowerShell restores data with Base64+XOR (key SKaDazKA6@@^^), then Base64-decodes a .NET assembly, loads it in memory via [Reflection.Assembly]::Load, and reflectively invokes FILED.WHORE::LAUNCHER.

> **Evidence**: $xorKey="SKaDazKA6@@^^"; [Reflection.Assembly]::Load($Image); GetType('FILED.WHORE').GetMethod('LAUNCHER')
> 
> **Source**: `ev-000011` · `ev-000002`

### 6. Hollow and inject into a system process

`T1055.012` · Confidence **medium** · static

In its static constructor the .NET assembly resolves CreateProcessA, ZwUnmapViewOfSection, VirtualAllocEx, WriteProcessMemory, ReadProcessMemory, Get/SetThreadContext, and ResumeThread from kernel32/ntdll, and defines the corresponding delegates and process/thread structures; together with the aspnet_compiler.exe path and PE bytes passed in by the caller, it implements the process-hollowing chain of creating a suspended process, unmapping the image, writing the payload, changing the thread context, and resuming the thread.

> **Evidence**: in FILED.WHORE::.cctor, ldstr 'VirtualAllocEx'/'WriteProcessMemory'/'ZwUnmapViewOfSection'/'CreateProcessA' followed by GetProcAddress and stored into _virtualAllocEx/_writeProcessMemory/_zwUnmapViewOfSection/_createProcessA; the type table contains PROCESS_INFORMATION, STARTUPINFO, ResumeThreadDelegate, etc.
> 
> **Source**: `ev-000010` · `ev-000011`

### 7. Poll the sentinel process before injecting

`T1057` · Confidence **high** · static

Before injection it loops using Get-Process to check whether aspnet_compiler is already running; if present it retries every 5 seconds, and only when absent does it perform the injection, avoiding duplicate injection and waiting for the target process to exit.

> **Evidence**: function Test-ProcessAbsent { Get-Process -Name $ProcessName }; Start-BeaconLoop parameters SentinelName="aspnet_compiler", IntervalSeconds=5
> 
> **Source**: `ev-000011`

### 8. Load a high-entropy PE in memory

`T1027.002` · Confidence **high** · static

The injected body is a 284,672-byte PE32 with only one .text section of entropy 7.99 and an empty import table; the entry point is a self-decrypting/self-jumping stub, and it does not touch disk after injection, making it an in-memory packed payload.

> **Evidence**: injected PE: e_lfanew=0xB8, 1 section .text entropy 7.994, import/export directories both empty, entry RVA 0x2760 starts with push ebp/mov ebp,esp/sub esp,0x658 unpacking code; the first 32 bytes of the file header are a PE jump stub 4D 5A 45 52 E8 00 00 00 00 58 83 E8 09...
> 
> **Source**: `ev-000001` · `ev-000011`

### 9. Erase traces of the dropped script

`T1070.004` · Confidence **high** · static

Immediately after PowerShell returns it deletes the randomly named .ps1 generated under C:\Temp, reducing on-disk forensic traces.

> **Evidence**: Sub CleanupArtifacts: If m_fs.FileExists(m_stagePath) Then m_fs.DeleteFile m_stagePath, True
> 
> **Source**: `ev-000011`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (see "Analysis method and limitations" at the end for the reason).
:::

### Host

**Dropped paths**

- `C:\Temp\<8 uppercase letters>.ps1`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `runtime_root` | `C:\Temp\` | no | static |
| `stage_path_pattern` | `C:\Temp\<8 uppercase letters A-Z>.ps1` | yes | static |
| `launch_command` | `powershell.exe -nop -ep bypass -file "C:\Temp\<RANDOM>.ps1"` | yes | static |
| `encryption_algo` | `AES-256-CBC/PKCS7 (stage1->stage2); Base64+XOR (stage2->.NET assembly)` | yes | static |
| `aes_key_b64` | `eNAQTmnt6oRTrGYQruVoPeTZ1dlZ/F4hfA+d1HTyy/s=` | yes | static |
| `aes_iv_b64` | `hzN0jIJpWlFDwY7mLQBsFA==` | yes | static |
| `xor_key` | `SKaDazKA6@@^^` | yes | static |
| `dotnet_entrypoint` | `FILED.WHORE::LAUNCHER` | yes | static |
| `hollow_target` | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe` | yes | static |
| `sentinel_process` | `aspnet_compiler` | yes | static |
| `poll_interval_seconds` | `5` | no | static |
| `c2_hosts` | `-` | no | static |

## What not to claim

:::important
The following conclusions are **easy to misinterpret**; please note them when citing this report.

- Do not classify it as ransomware or an infostealer just because the .NET assembly references RijndaelManaged/AesCryptoServiceProvider/MD5CryptoServiceProvider: no file encryption, browser credential, or keylogging logic was seen statically.
- Do not claim outbound C2, downloading, or data exfiltration: all payloads are embedded, and no URL, domain, IP, or socket call appears statically.
- Do not claim that a Service1 service was installed or that the registry/scheduled tasks were written: the ServiceBase-derived class is only template residue, and no service installation or registry-writing code was seen.
- Do not attribute the injected payload to a specific family (such as Remcos/Agent Tesla, etc.): no configuration, family identifier, or C2 was extracted, so the family cannot be determined.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static analysis only |
| Unpacking | Yes (stage2 `6f5e5b62d1048251c1141402fdb3e941d21c51b3b91584495d002ced29f6259a`) |

**Limitations and open questions**

1. This format has no isolated dynamic channel and was not actually detonated, reproduced=false; all behavior conclusions come from static decoding and decompilation, and whether the injection succeeded and how the final payload behaves were not dynamically observed.
2. The .NET assembly uses compression/encryption obfuscation (metadata method bodies are only stubs, a randomly named 1628-byte high-entropy resource resists common deflate/lzma decompression); the actual injection implementation of LAUNCHER could not be statically recovered, and the process-hollowing conclusion is based on its import surface, delegate signatures, structure definitions, and call parameters.
3. The injected PE32 is a single-section high-entropy packed payload; in pure CPU emulation the entry stub entered a loop and did not finish decrypting, so the final module, configuration, and C2 could not be recovered.
4. Statically no URL/IP/domain was found and c2 is empty; if later dynamic analysis shows network behavior, it should be added as a new IOC.
5. A same-named zip (AES-encrypted archive) exists in the same directory and was not included in this analysis; the family cannot be determined, family.uncertain=true.

## Evidence index

<details>
<summary>Show 11 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | Injected PE string extraction: 454 ASCII strings, no URL/command/family identifier |
| `ev-000002` | Hash and fingerprint | Reflectively loaded .NET assembly sha256=6f5e5b62d1048251c1141402fdb3e941d21c51b3b91584495d002ced29f6259a |
| `ev-000003` | scan.imphash | .NET assembly imphash=dae02f32a21e03ce65412f6e56942daa |
| `ev-000004` | scan.entropy | .NET assembly .text section entropy 5.939 |
| `ev-000005` | scan.entropy | .NET assembly .sdata section entropy 6.638 |
| `ev-000006` | scan.entropy | .NET assembly .rsrc section entropy 2.733 |
| `ev-000007` | scan.entropy | .NET assembly .reloc section entropy 0.082 |
| `ev-000008` | Sample triage | .NET assembly packing likelihood 25% (very few import symbols) |
| `ev-000009` | Cryptographic constant identification | .NET assembly hits MD5 T-table constants |
| `ev-000010` | String extraction | .NET assembly metadata strings: FILED.dll, Service1, ResumeThreadDelegate, SetThreadContextDelegate, etc. |
| `ev-000011` | evidence.record | Local static decoding chain: VBE->PS1(Base64)->PS2(AES-256-CBC)->.NET(Base64+XOR)->injected PE; IL decompilation confirms the process-hollowing API bindings and the FILED.WHORE::LAUNCHER entry |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
