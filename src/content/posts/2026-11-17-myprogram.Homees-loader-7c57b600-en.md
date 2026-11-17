---
title: "Malware Sample Analysis: myprogram.Homees loader (other · hta · 7c57b600)"
published: 2026-11-17
draft: false
description: "Malicious (low confidence): myprogram.Homees loader · downloader/loader · difficulty medium · pure static analysis"
tags: ["downloader", "loader", "Script"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-17-myprogram.Homees-loader-7c57b600"
---

> [!WARNING]
> **Verdict: malicious** · Family **myprogram.Homees loader** (doubtful) · Confidence **low**
> 
> Aliases: Homees loader, HTA PowerShell downloader
> 
> The sample is an HTA disguised as a system page; the script splits the real command into hundreds of fragments and inserts the junk string dIpdbcpc, removes the junk strings at runtime, and assembles the %SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe command; the second-stage PowerShell uses a custom alphabet and a 16-byte key to decrypt the download logic, extracts a Base64 .NET assembly from JPEGs on three hardcoded IPs and loads it reflectively, then calls the payload entry point with parameters such as an IPFS address. The entire chain has been fully reconstructed from the file bytes and has no legitimate software purpose.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **myprogram.Homees loader** · aliases Homees loader, HTA PowerShell downloader · _Doubtful_ |
| Confidence | **Low** |
| Behavior class | downloader · loader |
| Difficulty | medium |
| First seen | 2026-11-16 08:02:06 |
| Analysis method | Pure static analysis |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/7c57b600932d784aab952029de50fbe6ff376422e4540d8e555c79d9b94ba763/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Launch with hidden window</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564.003</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Junk-character command obfuscation</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027;T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Launch PowerShell via WScript.Shell</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.001;T1059.005</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Custom alphabet plus XOR decryption</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140;T1027</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Sleep, then fetch images from 3 hosts</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105;T1071.001;T1497.003</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `7c57b600932d784aab952029de50fbe6ff376422e4540d8e555c79d9b94ba763` |
| MD5 | _not recorded_ |
| Size | 21,979 bytes (21.5 KB) |
| Type | other · `hta` |

## Behavior Analysis

**9** behaviors in total, each backed by evidence, all available statically.

### 1. Launch with hidden window

`T1564.003` · Confidence **high** · Static

HTA:APPLICATION sets the window state to minimized and hides the taskbar button and system menu; immediately after the script finishes, window.close closes the host window.

> **Evidence**: HTA offset 0x118 WINDOWSTATE="minimize", 0x102 SYSMENU="no", 0x559d window.close
> 
> **Source**: `ev-000001`

### 2. Junk-character command obfuscation

`T1027;T1140` · Confidence **high** · Static

Splits the complete command into hundreds of string fragments, inserts the fixed junk string dIpdbcpc into each, and at the end of execution uses Replace to remove all junk strings at once before concatenating.

> **Evidence**: from HTA offset 0x170 the first fragment aFI1ocJxF is concatenated; 0x536c Replace(aFI1ocJxF, "dIpdbcpc", "")
> 
> **Source**: `ev-000001` · `ev-000002`

### 3. Launch PowerShell via WScript.Shell

`T1059.001;T1059.005` · Confidence **high** · Static

Obtains an execution object with CreateObject("WScript.Shell") and calls Run to start %SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe in a hidden window asynchronously, passing a long argument string.

> **Evidence**: HTA offset 0x5554 CreateObject, 0x5576 shell.Run; reconstructed command prefix cmd /c %SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe
> 
> **Source**: `ev-000001` · `ev-000002`

### 4. Custom alphabet plus XOR decryption

`T1140;T1027` · Confidence **high** · Static

The second-stage script restores all strings with the _mfh function (alphabet 6QYMqaSIoED7ztw2, two characters combined into a byte, then XOR 0x36); for embedded data, it first remaps the custom alphabet back to standard Base64, then subtracts the 16-byte key byte by byte and runs iex on the result.

> **Evidence**: the second-stage PowerShell's _mfh function, $pHuCTgF data block, $cH5urrG key, and the iex at the end
> 
> **Source**: `ev-000002`

### 5. Sleep, then fetch images from three hosts

`T1105;T1071.001;T1497.003` · Confidence **high** · Static

Forces TLS 1.2 and runs Start-Sleep for 3 seconds, then uses WebClient to request .jpg addresses on three hardcoded IPs in random order, returning the content of whichever request succeeds first.

> **Evidence**: second-stage script SecurityProtocol=Tls12, Start-Sleep -Seconds 3, DownloadDataFromLinks, and three URL literals
> 
> **Source**: `ev-000003`

### 6. Extract .NET from the image and load it

`T1620;T1027.009` · Confidence **high** · Static

Extracts Base64 data from the HTTP response text using <<STT>> and <<D>> as boundaries; after decoding with Convert.FromBase64String, loads the .NET assembly reflectively inside the PowerShell process via Assembly.Load.

> **Evidence**: second-stage script $a9=<<STT>>, $b0=<<D>>, IndexOf/Substring extraction, Reflection.Assembly::Load
> 
> **Source**: `ev-000003`

### 7. Reflectively invoke the payload entry point

`T1620` · Confidence **high** · Static

Gets the runs method of type myprogram.Homees and invokes it reflectively, passing six parameters: the IPFS address, "0", an empty string, "Msbuild", "0", "x86".

> **Evidence**: second-stage script $b6.GetType("mypr"+"ogram.Homees") and GetMethod("run"+"ss").Invoke(...)
> 
> **Source**: `ev-000003`

### 8. IPFS gateway delivers the next stage

`T1105;T1071.001` · Confidence **high** · Static

The URL passed to the payload as a parameter is stored reversed; once restored it points to the IPFS gateway at myfilebase[.]com with path QmREcHA2N7FKb3Hzegws5wPajK5wRY4qQt9FNEeLyi7kJr, used to retrieve subsequent payloads.

> **Evidence**: second-stage script $b9, after reversal and trimming the last 15 characters, yields misleading-lime-termite[.]myfilebase[.]com/ipfs/QmREc…
> 
> **Source**: `ev-000003`

### 9. Mix in irrelevant code to hinder analysis

`T1027` · Confidence **high** · Static

The script mixes in a CheckNumber parity-check function unrelated to the payload and prints the top five processes by CPU usage twice, before and after loading, to hinder manual reading.

> **Evidence**: HTA offset 0x53a4 CheckNumber function; two occurrences of Get-Process | Sort-Object CPU | Format-Table in the second-stage script
> 
> **Source**: `ev-000001` · `ev-000003`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://64[.]224[.]17[.]115/img/1.jpg` | 80 | download | Static | ⏳ Not observed |
| http | `hxxp://129[.]121[.]148[.]240/img/pics/1.jpg` | 80 | download | Static | ⏳ Not observed |
| http | `hxxp://155[.]103[.]71[.]164/1.jpg` | 80 | download | Static | ⏳ Not observed |
| http | `hxxps://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmREcHA2N7FKb3Hzegws5wPajK5wRY4qQt9FNEeLyi7kJr` | 443 | download | Static | ⏳ Not observed |

### Host

**Drop paths**

- `%SYSTEMROOT%\SysNative\WindowsPowerShell\v1.0\powershell.exe`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `64[.]224[.]17[.]115;129[.]121[.]148[.]240;155[.]103[.]71[.]164` | Yes | Static |
| `payload_url` | `hxxps://misleading-lime-termite[.]myfilebase[.]com/ipfs/QmREcHA2N7FKb3Hzegws5wPajK5wRY4qQt9FNEeLyi7kJr` | Yes | Static |
| `download_markers` | `<<STT>> / <<D>>` | Yes | Static |
| `encryption_algo` | `Stage 1: custom alphabet remapping + Base64 + byte-by-byte subtraction with a 16-byte key (key=4b8c6f638c001ab4da07ebcc08246fd9); stage 2: 6QYMqaSIoED7ztw2 alphabet base16 combination + XOR 0x36` | Yes | Static |
| `reflective_entry` | `myprogram.Homees.runs` | Yes | Static |
| `loader_process_param` | `Msbuild` | No | Static |
| `architecture` | `x86` | No | Static |
| `sleep_seconds` | `3` | No | Static |
| `stage2_sha256` | `5d8aced526a1df2042bf4cf4252a7bfba47a4231c760fa42934eab2312b41326` | Yes | Static |

## Do Not Misjudge

:::important
The following conclusions **are easy to misjudge**; note this when citing this report.

- The family and specific functionality of the final .NET payload cannot be asserted: the assembly was not obtained this time; only the loading and invocation entry points were seen.
- Do not assert file drops, registry persistence, services, or scheduled tasks: the HTA chain completes in memory, and the static evidence contains no disk writes or autostart operations.
- Do not treat 64.224.17[.]115, 129.121.148[.]240, and 155.103.71[.]164 as C2 controllers: they only handle image-host-style loader distribution.
- Do not assert that the sample has credential theft, ransomware, or remote-control capabilities: the current evidence covers only downloading and reflective loading.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Pure static analysis |
| Unpacking | No |

**Limitations and pending verification**

1. This format has no isolated dynamic channel; this is a pure static analysis, the sample was not run, and neither network behavior nor subsequent payloads were observed.
2. The three download hosts and myfilebase[.]com were not accessed (no network by default); the final .NET assembly could not be obtained, so its functionality and the real C2 cannot be confirmed.
3. The protocol prefix of the IPFS address was truncated when stored (the tail was cut after reversing the string); https and port 443 are inferred from the script's TLS 1.2 setting and require dynamic confirmation.
4. The sample depends on the SysNative path on 64-bit systems; on a 32-bit host or when this path is unavailable, the script may fail outright, and the actual success rate was not verified.
5. The semantics of "Msbuild" and "x86" in the payload parameters can only be inferred from their names as execution target and architecture; their specific purpose requires obtaining the assembly to confirm.

## Evidence Index

<details>
<summary>Expand 3 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | Extracted 437 ASCII strings from the original HTA, confirming the HTA:APPLICATION hidden-window configuration, the aFI1ocJxF concatenation chain, and the locations of key statements such as Replace/CreateObject/shell.Run/window.close. |
| `ev-000002` | evidence.record | Reconstructed the first-stage command line using the script's own concatenation and replacement logic, and decrypted the 2257-byte second-stage PowerShell using its custom alphabet/Base64/XOR algorithm (sha256=5d8aced5…1326). |
| `ev-000003` | evidence.record | Restored all obfuscated strings in stage 2: the three JPEG download addresses, the <<STT>>/<<D>> markers, the reflective entry point myprogram.Homees.runs, the reversed IPFS address, and the six invocation parameters. |

</details>

---

_The sample in this report is not public; IOCs have been defanged and are for security research only._
