---
title: "Malware Analysis: FILED Loader (other · vbe · 78bb8d2b)"
published: 2026-11-05
draft: false
description: "Malicious (medium confidence): FILED Loader · loader/injector · difficulty hard · static analysis only"
tags: ["FILED", "loader", "injector"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-05-FILED-Loader-78bb8d2b"
---

> [!WARNING]
> **Verdict: Malicious** · Family **FILED Loader** (uncertain) · Confidence **medium**
> 
> Aliases: FILED.WHORE, MZER/aspnet_compiler loader
> 
> Through static multi-layer decoding and IL decompilation, the complete attack chain was recovered directly: a hidden-window PowerShell launch, AES-256/XOR decoding, in-memory reflective loading of a .NET assembly, and injection of a PE into the legitimate aspnet_compiler.exe in suspended mode; every conclusion traces back to file bytes, strings and disassembly/decompilation results.

## Overview

| Item | Content |
|:--|:--|
| Family | **FILED Loader** · aliases FILED.WHORE, MZER/aspnet_compiler loader · _uncertain_ |
| Confidence | **medium** |
| Behavior class | loader · injector |
| Difficulty | hard |
| First seen | 2026-11-04 15:57:49 |
| Analysis method | Static analysis only |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/78bb8d2beb60bf28a7b6138dce4eca11bb5eabbe5ffa9015c302f510e642ed89/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Base64-decode payload</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Drop temp script</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1074.001</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Launch PowerShell hidden</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">AES-decrypt next stage</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">XOR-restore .NET payload</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identity

| Item | Value |
|:--|:--|
| SHA-256 | `78bb8d2beb60bf28a7b6138dce4eca11bb5eabbe5ffa9015c302f510e642ed89` |
| MD5 | _not recorded_ |
| Size | 2,000,848 bytes (1.9 MB) |
| Type | other · `vbe` |

## Behavior analysis

**10** behaviors in total, each backed by evidence, and all are statically recoverable.

### 1. Base64-decode payload

`T1140` · Confidence **high** · static

The VBScript passes m_b64Payload to MSXML2.DOMDocument (bin.base64) for decoding, reads it out as UTF-8 through ADODB.Stream, and obtains the full PowerShell script text.

> **Evidence**: m_b64Payload assignment in the VBE; MSXML2.DOMDocument and ADODB.Stream calls inside StepMaterializeScript
> 
> **Source**: `ref:10f9e4e06d` · `ref:2b650aa7db`

### 2. Drop temp script

`T1074.001` · Confidence **high** · static

Creates a .ps1 file under C:\Temp\ with an 8-character uppercase random name and writes the decoded script content into it.

> **Evidence**: Const WORK_ROOT="C:\Temp\"; RandomTag generates [A-Z]{8}; m_fs.CreateTextFile(m_stagePath, True)
> 
> **Source**: `ref:10f9e4e06d`

### 3. Launch PowerShell hidden

`T1059.001` · Confidence **high** · static

Through WScript.Shell.Run it executes powershell.exe -nop -ep bypass -file <ps1> with window parameter 0 (hidden) and waits synchronously for it to finish.

> **Evidence**: Const PS_INVOKE="powershell.exe -nop -ep bypass -file """; m_wsh.Run m_launchCmd, 0, True
> 
> **Source**: `ref:10f9e4e06d`

### 4. AES-decrypt next stage

`T1140` · Confidence **high** · static

The second-stage script uses an embedded AES-256 key and IV with CBC/PKCS7 to decrypt $encryptedPayload, recovering the next PowerShell layer.

> **Evidence**: Invoke-AESDecryption: Aes.Create / CipherMode.CBC / PaddingMode.PKCS7; key=b64 FIPAHE6eSqLMU4rJ5xWP/lFJesQFi3USEdP+ecpMHe0=, iv=b64 /jtW/qodA8KR5ArS0fbWUg==
> 
> **Source**: `ref:cb40333703` · `ref:2b650aa7db`

### 5. XOR-restore .NET payload

`T1027` · Confidence **high** · static

The third-stage script Base64-decodes $encBlob, then applies cyclic XOR with the UTF-8 key SKaDazKA6@@^^ to obtain Base64 text, which it decodes a second time into a .NET assembly.

> **Evidence**: Expand-ObfuscatedPayload: $plain[$idx] = $enc[$idx] -bxor $key[$idx % $klen]; $xormaterial = "SKaDazKA6@@^^"
> 
> **Source**: `ref:705f4ec640` · `ref:2b650aa7db`

### 6. Reflectively load assembly

`T1620` · Confidence **high** · static

It loads the .NET assembly in memory through [Reflection.Assembly]::Load and invokes it reflectively via ClassPath 'FILED.WHORE' and Method 'LAUNCHER'.

> **Evidence**: [Reflection.Assembly]::Load($Image); GetType('FILED.WHORE').GetMethod('LAUNCHER').Invoke($null,$invokeParams)
> 
> **Source**: `ref:705f4ec640` · `ref:2b650aa7db`

### 7. Probe host process

`T1057` · Confidence **high** · static

It loops calling Get-Process -Name aspnet_compiler to check whether the host is already running, and performs the injection only when the process is absent, avoiding repeat infection.

> **Evidence**: Test-ProcessAbsent: Get-Process -Name $SentinelName; Start-BeaconLoop default SentinelName="aspnet_compiler"
> 
> **Source**: `ref:705f4ec640`

### 8. Inject into legitimate system process

`T1055` · Confidence **high** · static

LAUNCHER creates C:\Windows\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe with CREATE_SUSPENDED (0x8000004), allocates memory with VirtualAllocEx (0x3000, PAGE_EXECUTE_READWRITE), writes the PE sections with WriteProcessMemory, executes from the image entry point with CreateRemoteThread, and finally calls ResumeThread.

> **Evidence**: FILED.WHORE::LAUNCHER IL: createFlags=0x8000004; VirtualAllocEx(SizeOfImage,0x3000,0x40); WriteProcessMemory; CreateRemoteThread; ResumeThread
> 
> **Source**: `ref:8f6f0f1ef5` · `ref:2b650aa7db`

### 9. Inject MZER-wrapped payload

`T1027.002` · Confidence **high** · static

The injected payload is a 284,672-byte self-locating PE image beginning with 'MZER'; the stub obtains its base with call/pop, reads e_lfanew=0xB8, takes AddressOfEntryPoint and jumps. The native image has a single .text section and no import table.

> **Evidence**: stage5 offset 0 is 4D 5A 45 52 (MZER); e_lfanew=0xB8; entry rva=0x2760; .text entropy 7.994; imports 0
> 
> **Source**: `ref:a43473f3a9` · `ref:931ebd9b8f` · `ref:f2ac1a2cd9` · `ref:2b650aa7db`

### 10. Delete staging script

`T1070.004` · Confidence **high** · static

After PowerShell starts, CleanupArtifacts deletes the .ps1 under C:\Temp to reduce traces on disk.

> **Evidence**: CleanupArtifacts: If m_fs.FileExists(m_stagePath) Then m_fs.DeleteFile m_stagePath, True
> 
> **Source**: `ref:10f9e4e06d`


## IOC (defanged)

### Network

:::note
**No C2 / network IOC was recovered** (reasons in "Analysis method and limitations" at the end).
:::

### Host

**Dropped paths**

- `C:\Temp\`
- `C:\Temp\[A-Z]{8}.ps1`
- `%WINDIR%\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `-` | no | static |
| `launch_command` | `powershell.exe -nop -ep bypass -file <C:\Temp\[A-Z]{8}.ps1>` | yes | static |
| `staging_path` | `C:\Temp\[A-Z]{8}.ps1` | yes | static |
| `encryption_algo` | `AES-256-CBC/PKCS7 (second stage); Base64+XOR (third stage)` | yes | static |
| `aes_key_b64` | `FIPAHE6eSqLMU4rJ5xWP/lFJesQFi3USEdP+ecpMHe0=` | yes | static |
| `aes_iv_b64` | `/jtW/qodA8KR5ArS0fbWUg==` | yes | static |
| `xor_key` | `SKaDazKA6@@^^` | yes | static |
| `injection_target` | `%WINDIR%\Microsoft.NET\Framework\v4.0.30319\aspnet_compiler.exe` | yes | static |
| `assembly_class` | `FILED.WHORE` | yes | static |
| `assembly_method` | `LAUNCHER` | yes | static |

## What not to claim

:::important
The following conclusions are **easy to misjudge**; keep them in mind when citing this report.

- Do not classify it as ransomware/wiper: the sample contains no file encryption, shadow-copy deletion or overwrite logic; the available evidence supports only the load-and-inject chain.
- Do not treat aspnet_compiler.exe as a malicious file or a primary IOC: it is a legitimate Microsoft system component that is injected into and serves only as host process.
- Do not claim a C2 domain or IP was confirmed: static multi-layer decoding found no network configuration, and the final payload body is high-entropy data that requires dynamic execution or further decryption.
- Do not assume it is a VBE-encoded file based on the .vbe extension: the content is actually plaintext VBScript, executed only by Windows Script Host.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Static analysis only |
| Unpacking | yes (stage2 `5f1eb3f4e57fbad168b6af1ee572784f6c3481f44c0bebb48aa32e0c11bb8102`) |

**Limitations and pending verification**

1. Static analysis only; the sample was neither executed nor emulated. The final MZER payload body is high-entropy (7.994) data with no import table and was not decrypted, so its final function and C2 cannot be confirmed.
2. No persistence (service/registry/scheduled task) was observed; it cannot be ruled out that later payloads establish persistence in memory.
3. The family name is a candidate based on embedded assembly naming (FILED.dll, FILED.WHORE::LAUNCHER) and has no cross-confirmation from external engines or public reports.
4. The injection depends on .NET Framework 4.x and aspnet_compiler.exe being present on the target; the actual injection success rate and subsequent behavior were not dynamically verified.
5. The file extension is .vbe, but the content is plaintext VBScript that requires Windows Script Host to parse and execute.

## Evidence index

<details>
<summary>Expand 9 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:10f9e4e06d` | string extraction | Original .vbe strings: Const WORK_ROOT="C:\Temp\", Const PS_INVOKE="powershell.exe -nop -ep bypass -file """, m_b64Payload |
| `ref:cb40333703` | string extraction | stage2 strings: "PS Secure Loader - Advanced Decryption Engine", $encryptedPayload and the AES ciphertext block |
| `ref:705f4ec640` | string extraction | stage3 strings: Expand-ObfuscatedPayload, Reflective Assembly Runner, Test-ProcessAbsent, Get-Process |
| `ref:8f6f0f1ef5` | sample triage | stage4 .NET assembly sha256=41753c17…, .text entropy 5.75, normal .sdata/.rsrc/.reloc structure |
| `ref:931ebd9b8f` | sample triage | stage5 .text entropy 7.994 (high), imports 0, sha256=5f1eb3f4… |
| `ref:f2ac1a2cd9` | import table parsing | stage5 import table is empty (0 DLLs / 0 symbols) |
| `ref:a43473f3a9` | disasm.function | stage5 rva 0x2760 function body: stack constant initialization with repeated call 0x401090 |
| `ref:7922eb8ea0` | string extraction | stage5 has only 454 short ASCII strings, with no readable C2/configuration strings |
| `ref:2b650aa7db` | evidence.record | Static decoding chain and IL decompilation: four-layer hashes, AES/XOR keys, CreateProcess/VirtualAllocEx/WriteProcessMemory/CreateRemoteThread call sequence |

</details>

---

_This report's sample is not public; IOCs are defanged and for security research only._
