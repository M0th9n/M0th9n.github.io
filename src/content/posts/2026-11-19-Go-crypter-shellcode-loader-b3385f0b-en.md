---
title: "Malware sample analysis: Go crypter shellcode loader (PE · exe · b3385f0b)"
published: 2026-11-19
draft: false
description: "Malicious (low confidence): Go crypter shellcode loader · loader/backdoor · difficulty medium · dynamic sandbox + static decompilation"
tags: ["crypter", "loader", "backdoor", "PE"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-19-Go-crypter-shellcode-loader-b3385f0b"
---

> [!WARNING]
> **Verdict: malicious** · Family **Go crypter shellcode loader** (uncertain) · Confidence **low**
> 
> Aliases: crypter_persist, Go OneDrive loader
> 
> The sample is a Go-compiled shellcode loader (crypter): statically visible are main.runStage1/2/3 and main.DecryptAES, with three embedded AES-CBC ciphertexts; at runtime it copies itself under the name C:\ProgramData\OneDrive.exe, creates a logon-triggered scheduled task via schtasks, attempts to add a Defender exclusion for C:\ProgramData, and writes the decrypted shellcode into RWX memory before creating a thread to execute it. In the dynamic sandbox, the OneDrive.exe process spawned by the sample resolves the domain nxbase[.]im about every 5 seconds and attempts TCP 7777 connections, showing typical remote-control callback behavior.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Go crypter shellcode loader** · aliases crypter_persist, Go OneDrive loader · _uncertain_ |
| Confidence | **Low** |
| Behavior class | loader · backdoor |
| Difficulty | medium |
| First seen | 2026-11-16 15:00:13 |
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/b3385f0b6c15c5abe66c6f62af3fa1306f5ee3e7ea58731300b1fa0585808f27/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Decrypt embedded shellcode</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Execute shellcode in RWX memory</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1620</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Drop as fake OneDrive</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Register logon task</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1053.005</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Periodic C2 callback</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `b3385f0b6c15c5abe66c6f62af3fa1306f5ee3e7ea58731300b1fa0585808f27` |
| MD5 | _Not recorded_ |
| Size | 2,396,672 bytes (2.3 MB) |
| Type | PE · `exe` |

## Behavior analysis

**7** behaviors in total, each with attached evidence; **6** are statically obtainable and **1** was obtained through dynamic analysis.

### 1. Decrypt embedded shellcode

`T1140` · Confidence **high** · Static

Copies the three AES-CBC ciphertexts in .rdata (0x1D560, 0x11D60, 0x19400 bytes) to a heap buffer and calls main.DecryptAES (which derives the key internally via main.DeriveKey) to decrypt; if the length is not a multiple of 16 it reports "payload is not a multiple of the block size", and on failure it reports "decryption failed: %w".

> **Evidence**: main.DecryptAES @rva 0xea310 → 0xe9fb0; ciphertext rva 0x12a2d0 / 0xff170 / 0x110ed0; strings "payload is not a multiple of the block size"@0x4f9521, "decryption failed: %w"@0x4f2f61
> 
> **Source**: `ev-000013` · `ref:db14d4cf66` · `ref:117c5443b7`

### 2. Execute shellcode in RWX memory

`T1620` · Confidence **high** · Static

Allocates executable memory with VirtualAlloc(0x3000=PAGE_EXECUTE_READWRITE, MEM_COMMIT), copies the decrypted payload in, then calls CreateThread to start the shellcode, printing "[1]/[2]/[3] Shellcode thread started" per stage.

> **Evidence**: from rva 0xea43a: mov [eax+8],0x3000; mov [eax+0xc],4; call [0x63a4c4](VirtualAlloc); then call [0x63a4d0](CreateThread); string "Shellcode thread started"
> 
> **Source**: `ref:98556fceb8` · `ref:078b774f91`

### 3. Drop as fake OneDrive

`T1036.005` · Confidence **high** · Static

Copies itself to C:\ProgramData\OneDrive.exe and runs under that name; in the sandbox the corresponding process is OneDrive.exe (PID 4208).

> **Evidence**: string "C:\ProgramData\OneDrive.exe"@VA 0x4f50c3; logs "install dir ready: %s" "self-copied (%d bytes) -> %s"; dynamic process OneDrive.exe (4208)
> 
> **Source**: `ref:078b774f91` · `ref:cd9c889a87`

### 4. Register logon scheduled task

`T1053.005` · Confidence **high** · Static

Executes schtasks /Create through a hidden-window cmd.exe, registering the scheduled task "\Microsoft\Windows\Scheduled\Maintenance_314F38" with a logon trigger (ONLOGON), and on success prints "Persistence status: OK (scheduled task wired for next logon)".

> **Evidence**: strings in main.installPersistence "schtasks /Create: cErr=%v cOut=%s"@0x4f6ed2, "\Microsoft\Windows\Scheduled\Maintenance_314F38"@VA 0x4fa0f8, "ONLOGON"; disasm around rva 0xec11d builds the schtasks arguments
> 
> **Source**: `ref:161bb4e60a` · `ref:078b774f91`

### 5. Add Defender exclusion

`T1562.001` · Confidence **high** · Static

Prefers calling Windows Defender's MpCmdRun.exe with "-AddExclusion -ExclusionPath C:\ProgramData", and falls back to PowerShell's "Add-MpPreference -ExclusionPath" on failure, to evade scanning of that directory.

> **Evidence**: strings "defender: running: \"%s\" -AddExclusion -Path %q" "Add-MpPreference -ExclusionPath \"%s\"" "defender: MpCmdRun = %s" "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"; main.applyDefenderExclusion
> 
> **Source**: `ref:078b774f91`

### 6. Hidden-window command invocation

`T1059.003` · Confidence **medium** · Static

Executes commands such as schtasks and PowerShell through C:\Windows\System32\cmd.exe with a hidden window, avoiding a console window popup.

> **Evidence**: strings "C:\Windows\System32\cmd.exe" "powershell -NoProfile" "hiddenCmd"; disasm around rva 0xec0e0 calls hiddenCmd (0x4ea7b0)
> 
> **Source**: `ref:161bb4e60a` · `ref:078b774f91`

### 7. Periodic C2 callback

`T1095` · Confidence **high** · Dynamic

The payload process OneDrive.exe resolves the domain nxbase[.]im about every 5 seconds and attempts TCP 7777 connections, lasting about 2 minutes until the sandbox wraps up, consistent with beacon polling.

> **Evidence**: dynamic network log: DNS A request nxbase[.]im; OneDrive.exe (4208) requested TCP 192.0.2[.]123:7777 (repeated about every 5 s), first at 00:43:51
> 
> **Source**: `ref:cd9c889a87` · `ref:4d35384391`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the above addresses come from static analysis; no successful connection or session was observed under the isolated analysis network, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `nxbase[.]im` | 7777 | c2 | Static | ⏳ Not observed |

### Host

**Dropped paths**

- `%ProgramData%\OneDrive.exe`
- `%SystemDrive%\crypter_persist.log`

**Scheduled tasks**

- `\Microsoft\Windows\Scheduled\Maintenance_314F38`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `nxbase[.]im` | Yes | Static |
| `c2_port` | `7777` | Yes | Static |
| `install_path` | `%ProgramData%\OneDrive.exe` | Yes | Static |
| `persistence_task` | `\Microsoft\Windows\Scheduled\Maintenance_314F38` | Yes | Static |
| `encryption_algo` | `AES-128-CBC (each of the three stages embeds its own 16-byte key/IV, derived at runtime via DeriveKey)` | Yes | Static |
| `defender_exclusion_path` | `C:\ProgramData` | No | Static |
| `log_path` | `%SystemDrive%\crypter_persist.log` | No | Static |

## Do not misjudge

:::important
The following conclusions **are easy to misjudge**; keep them in mind when citing this report.

- Do not judge it as ransomware or a file encryptor: AES is used only to decrypt the embedded shellcode, and no file encryption, extension changes or ransom notes were observed in the sandbox.
- Do not claim a C2 session was established or commands were received: only DNS resolution and periodic TCP connection attempts were observed, with no complete requests/responses.
- Do not claim credentials were stolen or lateral movement occurred: the sample's calls to comsvcs.dll-related exports appeared only in the analysis-side process dump flow, and this behavior was not observed from the sample itself.
- Do not claim registry writes or service creation: Defender exclusion and persistence are both implemented through command-line tools, and no telemetry evidence of registry/service writes was read.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. Although the three embedded ciphertexts have been located with their rva and embedded key/IV, the runtime key is derived a second time via main.DeriveKey; direct static AES-CBC decryption did not yield recognizable plaintext, so the plaintext shellcode/final configuration was not recovered.
2. For C2 only DNS resolution and TCP connection attempts (about every 5 s) exist, with no complete requests/responses; c2 and c2_hosts/c2_port in config are therefore recorded as static + pending_dynamic_verify, and it cannot be asserted that a callback succeeded or commands were delivered.
3. The sandbox timeline only records the sample's own process (PID 1060) and the subsequent OneDrive.exe (PID 4208); no runtime telemetry was captured for the scheduled task, Defender exclusion, registry or services, so these conclusions are based on code paths and string evidence.
4. The final payload's communication protocol and command format are unknown, so it cannot be confirmed whether it is a RAT, a downloader or an in-memory injector; the behavior_class backdoor is a functional inference based on periodic callbacks.
5. The sample family has no public naming to align with; the family confidence is low and uncertain=true.

## Evidence index

<details>
<summary>Show 15 tool evidence items</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | Hash and fingerprint | sha256/md5/sha1 and file size 2396672 |
| `ev-000002` | scan.imphash | imphash=5f77bccf23632019202250229664e21b |
| `ev-000003` | scan.entropy | .text entropy 6.186, no high-entropy packer characteristics |
| `ev-000011` | Cryptographic constant identification | AES forward/inverse S-box @off 0x2305e0 / 0x2306e0 |
| `ev-000013` | evidence.record | Script locates the rva of the three AES-CBC ciphertexts and the embedded key/IV |
| `ref:e5414e42f0` | PE structure parsing | PE32 I386 GUI, 6 sections, entry rva 0x88650, image base 0x400000, no anomalies |
| `ref:17f833c032` | Import table parsing | only kernel32.dll with 46 imports, consistent with Go runtime characteristics |
| `ref:078b774f91` | String extraction | hits key strings such as the OneDrive.exe path, scheduled task name, Defender exclusion, and stage/shellcode logs |
| `ref:bd5a893200` | disasm.function | runStage1 copies 0x1d560 bytes of ciphertext and calls decryption with key/IV |
| `ref:db14d4cf66` | disasm.function | DecryptAES validates the length and reports payload/decryption errors |
| `ref:98556fceb8` | disasm.function | VirtualAlloc(PAGE_EXECUTE_READWRITE)+CreateThread executes the payload |
| `ref:161bb4e60a` | disasm.function | installPersistence builds schtasks /Create and status logs |
| `ref:4d35384391` | Dynamic analysis platform | rollback→detonation→polling 27 times, sample process PID 1060, rollback after wrap-up |
| `ref:c5de758b2e` | sandbox.timeline | timeline only the sample's own process, 5 memory dumps, hollows full scan 1 item |
| `ref:cd9c889a87` | sandbox.fakenet | OneDrive.exe(4208) periodically resolves nxbase[.]im and connects TCP 7777 (about every 5s) |

</details>

---

_The sample in this report is not public; IOCs have been defanged; for security research only._
