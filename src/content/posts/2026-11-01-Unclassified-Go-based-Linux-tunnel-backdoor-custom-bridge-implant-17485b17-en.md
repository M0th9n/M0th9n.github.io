---
title: "Malware Analysis: Unclassified Go-based Linux tunnel/backdoor (custom bridge implant) (ELF · elf · 17485b17)"
published: 2026-11-01
draft: false
description: "Malicious (low confidence): Unclassified Go-based Linux tunnel/backdoor (custom bridge implant) · backdoor/implant · difficulty medium · dynamic sandbox + static decompilation"
tags: ["backdoor", "implant", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-01-Unclassified-Go-based-Linux-tunnel-backdoor-custom-bridge-implant-17485b17"
---

> [!WARNING]
> **Verdict: malicious** · Family **Unclassified Go-based Linux tunnel/backdoor (custom bridge implant)** (doubtful) · Confidence **low**
> 
> Aliases: Go bridge implant, smux-based Linux backdoor
> 
> In isolated Linux dynamic analysis the sample was observed immediately initiating TCP connections to the hardcoded 154.36.183[.]100:18089 and continuously reconnecting; statically, systemd/upstart/init.d/OpenRC service persistence templates, busybox invocations, history cleanup, and LD_PRELOAD clues are also visible, consistent with remote-control/tunnel backdoor characteristics.

## At a glance

| Item | Content |
|:--|:--|
| Family | **Unclassified Go-based Linux tunnel/backdoor (custom bridge implant)** · Aliases Go bridge implant, smux-based Linux backdoor · _doubtful_ |
| Confidence | **Low** |
| Behavior classes | backdoor · implant |
| Difficulty | medium |
| First seen | 2026-10-30 00:06:09 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/17485b175a4ca46adbce11efa571f875fb530922b9cc7d5ad60078846ce0f603/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Callback to hardcoded C2</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Reconnect every 5s</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1008</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Install system service</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1543.002</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">inittab persistence</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1037.004</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Deploy busybox tools</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1059.004</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `17485b175a4ca46adbce11efa571f875fb530922b9cc7d5ad60078846ce0f603` |
| MD5 | _not recorded_ |
| Size | 7,864,320 bytes (7.5 MB) |
| Type | ELF · `elf` |

## Behavior analysis

**12** behaviors in total, each backed by evidence: **10** are obtainable statically and **2** were obtained through dynamic analysis.

### 1. Callback to a hardcoded C2

`T1095` · Confidence **High** · Dynamic

After startup it initiates TCP connections to 154.36.183[.]100:18089; it keeps trying even when connections fail.

> **Evidence**: system-call trace connect(6, {sa_family=AF_INET, sin_port=htons(18089), sin_addr=inet_addr("154.36.183[.]100")}) appears repeatedly
> 
> **Source**: `ev-000023` · `ev-000027` · `ev-000030` · `ev-000036`

### 2. Five-second reconnect keepalive

`T1008` · Confidence **Medium** · Dynamic

After a connection failure or abnormal server data it reconnects at roughly 5-second intervals to keep the C2 channel alive.

> **Evidence**: strings "Error data from server, and will be reconnected in five seconds"@0x4bccaa and "The connection server failed and will be reconnected in five seconds, error"@0x4be4c8; multiple connect calls dynamically observed
> 
> **Source**: `ev-000045` · `ev-000023` · `ev-000027`

### 3. Install a system service for autostart

`T1543.002` · Confidence **High** · Static

Embeds systemd/upstart/init.d/OpenRC service templates and can register itself as a system service for boot autostart.

> **Evidence**: service templates ExecStart={{.Path|cmdEscape}}@0x4c0651, #!/sbin/openrc-run@0x4bfff7, ### BEGIN INIT INFO@0x4c0a25; /etc/init.d/@0x4a5b2b
> 
> **Source**: `ev-000044` · `ev-000043`

### 4. inittab persistence

`T1037.004` · Confidence **Medium** · Static

References /etc/inittab and /etc/init.d/, with the capability to persist through traditional init scripts/inittab.

> **Evidence**: /etc/inittab@0x4a5b3a; /etc/init.d/@0x4a5b2b
> 
> **Source**: `ev-000043`

### 5. Deploy busybox tools

`T1059.004` · Confidence **Medium** · Static

Uses the /bin/busybox and /tmp/busybox paths to drop or invoke busybox for executing system commands.

> **Evidence**: /bin/busybox@0x4a5b18; /tmp/busybox@0x4a5b6c
> 
> **Source**: `ev-000043`

### 6. Clear command history

`T1070.003` · Confidence **Medium** · Static

Sets HISTFILE=/tmp/.del, redirecting shell history to a temporary file to hide operational traces.

> **Evidence**: HISTFILE=/tmp/.del@0x4a880d
> 
> **Source**: `ev-000043`

### 7. LD_PRELOAD injection

`T1574.006` · Confidence **Medium** · Static

Contains LD_PRELOAD=%s and LD_PARAMS=%s, possibly hijacking target processes through preloading by the dynamic linker.

> **Evidence**: LD_PRELOAD=%s@0x4a6341; LD_PARAMS=%s@0x4a5cab
> 
> **Source**: `ev-000043`

### 8. Local SOCKS proxy

`T1090` · Confidence **Medium** · Static

Contains socks5, socks bind/connects, and 127.0.0[.]1:6103 / 127.0.0[.]1:53, giving it local proxy/forwarding capability.

> **Evidence**: socks5@0x4a3b42; 127.0.0[.]1:6103@0x4a4e31; 127.0.0[.]1:53@0x4a5b8b; socks connects@0x4a6710
> 
> **Source**: `ev-000043` · `ev-000045`

### 9. smux encrypted tunnel

`T1573` · Confidence **Medium** · Static

Uses smux multiplexing to carry custom encrypted data, including nonce direction and ciphertext length validation.

> **Evidence**: mux:packer: newpack content is nil@0x4b2aac; received invalid encrypted data size %d@0x4b577a; write data to remote wrong nonce direction@0x4aae33
> 
> **Source**: `ev-000045`

### 10. Probe host and processes

`T1082` · Confidence **Medium** · Static

Reads host and process information such as /proc/1/comm, /proc/%d/stat, /etc/passwd, /etc/group, /etc/hosts, /etc/resolv.conf, and /run/user/%s.

> **Evidence**: /proc/1/comm@0x4a5b50; /run/user/%s@0x4a5b5c; /etc/passwd, /etc/group, /etc/hosts, /etc/resolv.conf strings
> 
> **Source**: `ev-000043`

### 11. Cloud storage channel

`T1567.002` · Confidence **Medium** · Static

Embeds the Aliyun OSS SDK, with the capability to upload/download files through object storage.

> **Evidence**: aliyun_v4_request@0x4a80a0; x-oss-* constants; uploadSpeed/downloadSpeed and "The file is larger than 30M..."@0x4ba64f
> 
> **Source**: `ev-000044`

### 12. Create a web_user account

`T1136.001` · Confidence **Low** · Static

Contains "the web_user may have been occupied!", possibly creating/occupying a web_user account on the host or management panel.

> **Evidence**: the web_user may have been occupied!@0x4b3f63; /etc/passwd string
> 
> **Source**: `ev-000045` · `ev-000043`


## IOC (de-weaponized)

### Network

:::caution
**Pending dynamic verification**: the addresses above were obtained statically; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| tcp | `154[.]36[.]183[.]100:18089` | 18089 | c2 | Static | ⏳ Not observed |

### Host

**Drop paths**

- `/home/vbccsb`
- `/tmp/busybox`
- `/bin/busybox`
- `/tmp/log_de.log`
- `/tmp/log_de-0.log`
- `/tmp/.del`
- `/etc/init.d/<service>`
- `/etc/inittab`

**Services**

- `systemd/upstart/init.d/OpenRC service (name derived from install path/binary name)`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `154[.]36[.]183[.]100` | Yes | Dynamic |
| `c2_port` | `18089` | Yes | Dynamic |
| `persistence` | `systemd/upstart/init.d/OpenRC service; /etc/inittab; busybox` | Yes | Static |
| `install_path` | `/home/vbccsb` | No | Static |
| `log_paths` | `/tmp/log_de.log,/tmp/log_de-0.log (TMPDIR-overridable)` | No | Static |
| `local_proxy_listeners` | `127[.]0[.]0[.]1:6103,127[.]0[.]0[.]1:53` | No | Static |
| `encryption_algo` | `custom stream/block cipher with nonce direction (unconfirmed)` | No | Static |
| `cloud_storage_sdk` | `Aliyun OSS (aliyun_v4_request / x-oss-*)` | No | Static |
| `campaign_id` | `-` | No | Static |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing this report.

- Do not judge it as ransomware or a file encryptor from the AES S-box alone; the AES constants come from the Go standard library crypto/aes, and no file encryption or ransomware behavior was observed.
- Do not determine it to be a miner; no stratum/xmrig/wallet/pool strings were found, and no mining behavior was observed.
- Do not claim that data was exfiltrated or commands were received without a successfully established C2 session; this dynamic run observed only TCP connect attempts, with outbound network isolated.
- The family cannot be confirmed as known tools such as nps, frp, or Stowaway; the corresponding proprietary strings and configuration keys are missing.
- LD_PRELOAD injection cannot be confirmed to have actually executed; it is currently only a static string clue.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. Outbound network is isolated; only connect attempts to 154.36.183[.]100:18089 were captured (ENETUNREACH), no C2 session was established, and commands, protocol plaintext, or returned data could not be obtained.
2. It was not run as root, so service/inittab persistence writes did not actually land; capability is shown only by embedded templates and path strings.
3. Family attribution is uncertain: Go symbols are obfuscated and no proprietary string of a known family matched; it can only be described as a custom Go tunnel/backdoor.
4. The encryption algorithm is not fully confirmed: the AES S-box belongs to the Go standard library, the nonce/ciphertext lengths in the protocol suggest custom encryption, but the key and algorithm mode are unknown.
5. The specific use of Aliyun OSS (configuration delivery, file upload/exfiltration, or updates) was not observed dynamically.
6. 127.0.0[.]1:6103 and 127.0.0[.]1:53 are only static strings; no listening or proxy session was observed.

## Evidence index

<details>
<summary>Expand 12 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000018` | dyn.exec | Isolated Linux dynamic run; the sample kept running and timed out; no stdout/stderr. |
| `ev-000019` | dyn.trace | execve("./prog") succeeded, confirming the sample actually started. |
| `ev-000020` | dyn.trace | Read /sys/kernel/mm/transparent_hugepage/hpage_pmd_size (Go runtime behavior). |
| `ev-000022` | dyn.trace | AF_NETLINK NETLINK_ROUTE socket, enumerating network interfaces. |
| `ev-000023` | dyn.trace | connect 154.36.183[.]100:18089, returned ENETUNREACH. |
| `ev-000027` | dyn.trace | Second connect to 154.36.183[.]100:18089, confirming reconnect behavior. |
| `ev-000030` | dyn.trace | Third connect to 154.36.183[.]100:18089. |
| `ev-000036` | dyn.trace | Fourth connect to 154.36.183[.]100:18089. |
| `ev-000042` | decompile.function | Decompiled FUN_007de2a0: reads TMPDIR, joins log_de.log/log_de-0.log, operates on /home/vbccsb. |
| `ev-000043` | evidence.record | Custom persistence/host strings and pclntab parsing (self-reported evidence). |
| `ev-000044` | evidence.record | System service templates and Aliyun OSS SDK strings (self-reported evidence). |
| `ev-000045` | evidence.record | Custom C2/protocol message strings (self-reported evidence). |

</details>

---

_This report's sample is not public; IOCs have been de-weaponized and are for security research only._
