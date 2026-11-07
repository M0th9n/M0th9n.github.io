---
title: "Malware Analysis: six_sayven (ELF · elf · fb8ae821)"
published: 2026-11-02
draft: false
description: "Malicious (low confidence): six_sayven · botnet/backdoor · difficulty hard · dynamic sandbox + static decompilation"
tags: ["botnet", "backdoor", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-02-six_sayven-fb8ae821"
---

> [!WARNING]
> **Verdict: malicious** · Family **six_sayven** (doubtful) · Confidence **low**
> 
> Aliases: Hajime-like DHT/DoH P2P botnet
> 
> The static structure is a statically linked, symbol-stripped 32-bit big-endian MIPS ELF embedding DoH/DHT/Ed25519/Salsa20 plus /bin/sh, watchdog devices, and raw sockets; executed via qemu-user in an isolated hardened instance, it directly exhibited prctl name changes, access to /dev/watchdog, RAW socket requests, a connection to 8.8.8[.]8:53, creation of the abstract UNIX socket six_sayven-63464 and a connection to 127.0.0[.]1:63464 — a P2P botnet program capable of persisting on IoT devices.

## At a glance

| Item | Content |
|:--|:--|
| Family | **six_sayven** · Aliases Hajime-like DHT/DoH P2P botnet · _doubtful_ |
| Confidence | **Low** |
| Behavior classes | botnet · backdoor |
| Difficulty | hard |
| First seen | 2026-11-02 08:45:33 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/fb8ae821d6e1fe9fb1d34ccc505937a528b7ce2e9392745f89cc6d9c94d4351f/) |

## Attack chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">DoH bootstrap discovery</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.004</text>
<text x="613" y="38" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="84" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">DHT signed discovery</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1571</text>
<text x="613" y="88" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Random process-name masquerade</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Disable watchdog</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Create raw sockets</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1095</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample identification

| Item | Value |
|:--|:--|
| SHA-256 | `fb8ae821d6e1fe9fb1d34ccc505937a528b7ce2e9392745f89cc6d9c94d4351f` |
| MD5 | _not recorded_ |
| Size | 560,956 bytes (547.8 KB) |
| Type | ELF · `elf` |

## Behavior analysis

**11** behaviors in total, each backed by evidence; **5** are obtainable statically and **6** were obtained through dynamic analysis.

### 1. DoH bootstrap discovery

`T1071.004` · Confidence **Medium** · Static

Sends DNS-over-HTTPS requests via HTTPS POST /dns-query (Accept: application/dns-message) to cloudflare-dns[.]com / dns[.]google for bootstrap peer discovery, evading local DNS monitoring.

> **Evidence**: .rodata 0x47de90 'cloudflare-dns[.]com'; 0x47dea4 'dns.google'; 0x47deb8 'POST /dns-query HTTP/1.1'
> 
> **Source**: `ev-000001` · `ref:ef87b3bba7`

### 2. DHT signed discovery

`T1571` · Confidence **Medium** · Static

Uses BitTorrent DHT (BEP5) messages get_peers/put/ping with bencode templates for node discovery and command distribution; messages carry 64-byte Ed25519 signatures and z-base32-encoded info_hash values.

> **Evidence**: .rodata 0x47e010 'd1:ad2:id20:'; 0x47e030 '3:seqi%llde3:sig64:'; 0x47e120 z-base32 alphabet; 0x47e148 'SigEd25519 no Ed25519 collisions'
> 
> **Source**: `ev-000001` · `ev-000005`

### 3. Random process-name masquerade

`T1036` · Confidence **High** · Dynamic

After startup it calls prctl(PR_SET_NAME) to change the process name to a random string (venj38 in this observation), evading process-name-based detection and manual triage.

> **Evidence**: dynamic event prctl(PR_SET_NAME, "venj38")
> 
> **Source**: `ref:e46213bbbc` · `ev-000010`

### 4. Disable watchdog

`T1562.001` · Confidence **High** · Dynamic

Probes and attempts to open /dev/watchdog and /dev/misc/watchdog read-write, preventing watchdog resets from rebooting the device and sustaining long-term persistence.

> **Evidence**: strace access("/dev/watchdog"); openat("/dev/watchdog", O_RDWR); access("/dev/misc/watchdog")
> 
> **Source**: `ev-000026` · `ev-000027` · `ev-000028` · `ev-000029`

### 5. Create raw sockets

`T1095` · Confidence **High** · Dynamic

Requests AF_INET/SOCK_RAW (IPPROTO_UDP and IPPROTO_TCP) raw sockets, enabling spurious-source UDP/SYN flooding; this run was denied by the kernel with EPERM because it ran with reduced privileges.

> **Evidence**: strace socket(AF_INET, SOCK_RAW, IPPROTO_UDP) = -1 EPERM; socket(AF_INET, SOCK_RAW, IPPROTO_TCP) = -1 EPERM
> 
> **Source**: `ev-000024` · `ev-000025`

### 6. Probe local network

`T1016` · Confidence **High** · Dynamic

Opens a UDP connection to 8.8.8[.]8:53 and calls getsockname to obtain the egress address, then enumerates NIC MAC/IP addresses via ioctl 0x8912/0x8921 to choose a source address for scanning.

> **Evidence**: FUN_00401508 @0x401508: socket/connect/getsockname + ioctl 0x8912; strace connect(3, 8.8.8[.]8:53)
> 
> **Source**: `ev-000009` · `ev-000031`

### 7. Local bridge channel

`T1090` · Confidence **High** · Dynamic

Creates the abstract UNIX socket six_sayven-63464 and connects to 127.0.0[.]1:63464; on success it prints a banner to the console and enters the local bridge/forwarding role.

> **Evidence**: strace bind(AF_UNIX, sun_path=@"six_sayven-63464"); connect(127.0.0[.]1:63464); write(1, "wow i guess im finna bridge now")
> 
> **Source**: `ev-000010` · `ref:e46213bbbc`

### 8. Invoke system shell

`T1059.004` · Confidence **Medium** · Static

Embeds the /bin/sh, "sh", and "-c" strings, giving it the ability to execute delivered shell commands, which can be used to issue DDoS commands or secondary payloads.

> **Evidence**: .rodata 0x47dd24 '/bin/sh'; 0x47dd28 'sh'; 0x47dd30 '-c'
> 
> **Source**: `ev-000001` · `ev-000011`

### 9. Verify encrypted payload

`T1140` · Confidence **Medium** · Static

Embeds SHA-256/SHA-1/MD5 digests and Salsa20 (expand 32-byte k)/Ed25519 code for P2P message integrity verification and encryption/decryption.

> **Evidence**: crypto constants off 0x7f300/0x7f320; .rodata 0x47f2b0 'expand 32-byte k'
> 
> **Source**: `ev-000004` · `ev-000005` · `ev-000006` · `ev-000007`

### 10. Write OOM weight

`T1562.001` · Confidence **Low** · Static

Uses the /proc/%d/oom_score_adj and /proc/%d/oom_adj path templates to adjust the process OOM score, making it less likely to be killed by the kernel's memory reclamation.

> **Evidence**: .rodata 0x47dbdc 'oom_score_adj'; 0x47dbec 'oom_adj'; 0x47dd00 '/proc/%d/%s'
> 
> **Source**: `ev-000001`

### 11. Daemonize and change root

`T1564` · Confidence **Medium** · Dynamic

Calls chdir("/") to switch the working directory and persists on the device in daemon fashion (a fork/waitpid-related system-call sequence exists).

> **Evidence**: strace chdir("/"); fork/waitpid call sequence in main @0x4016ec
> 
> **Source**: `ref:e46213bbbc` · `ev-000008`


## IOC (de-weaponized)

### Network

:::caution
**Pending dynamic verification**: the addresses above were obtained statically; no successful connection or session was observed under the analysis environment's network isolation, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| other | `BitTorrent DHT (BEP5) P2P swarm (get_peers/put/ping, Ed25519-signed)` | 6881 | c2 | Static | ⏳ Not observed |
| http | `hxxps://cloudflare-dns[.]com/dns-query` | 443 | c2 | Static | ⏳ Not observed |
| http | `hxxps://dns[.]google/dns-query` | 443 | c2 | Static | ⏳ Not observed |

### Host

**Drop paths**

- `/dev/watchdog`
- `/dev/misc/watchdog`
- `/bin/sh`
- `/dev/urandom`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `BitTorrent DHT (BEP5) peer network; node discovery and command distribution are performed over DHT, no hardcoded C2 domain/IP was found` | Yes | Static |
| `bootstrap_dns` | `cloudflare-dns[.]com, dns[.]google (DoH POST /dns-query, application/dns-message)` | Yes | Static |
| `bot_tag` | `six_sayven` | No | Static |
| `local_bridge` | `AF_UNIX abstract socket six_sayven-63464 + TCP 127.0.0[.]1:63464` | No | Dynamic |
| `signature_scheme` | `Ed25519 (3:sig64: field, 64-byte signature)` | Yes | Static |
| `encryption_algo` | `Salsa20/ChaCha20 (expand 32-byte k), SHA-256, SHA-1, MD5` | No | Static |
| `process_name` | `set at runtime to a random string via prctl(PR_SET_NAME) (observed venj38)` | No | Dynamic |

## Do not misjudge

:::important
The following conclusions are **easy to misjudge**; keep this in mind when citing this report.

- Do not assert that the sample has already launched a DDoS: only the raw-socket request was observed being denied, with no actual attack traffic or victim.
- Do not assert hardcoded C2 domains/IPs: addressing relies on the DHT peer network and DoH bootstrap, and neither static nor dynamic analysis yielded a directly reachable C2 address.
- Do not classify it as ransomware or an info-stealer: no file encryption, credential collection, or browser data access was observed.
- Do not assert from the six_sayven string alone that this is a mature, publicly named family: the name is only the sample's own tag and has no vendor/YARA cross-validation.
:::

## Analysis method and limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | No |

**Limitations and open questions**

1. The run instance used unshare -n with full network isolation, so DHT peer discovery, DoH resolution, and the post-bridge command channel were never actually triggered; the C2 endpoint is only statically inferred and marked pending dynamic verification.
2. RAW socket requests were denied with EPERM because of reduced privileges, so the actual DDoS message construction and transmission could not be observed.
3. Family attribution rests only on the sample's own tag and protocol features, without cross-validation from vendor engines or YARA rules; confidence is low.
4. Some key strings (such as the runtime banner) are encrypted/encoded in the file, and their decryption configuration could not be fully recovered statically.

## Evidence index

<details>
<summary>Expand 17 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000001` | String extraction | ASCII+UTF16LE string extraction, hitting DoH/DHT/Ed25519/Salsa20/watchdog/oom and other key strings |
| `ev-000003` | String extraction | String extraction summary (566 ASCII / 3 UTF-16LE) |
| `ev-000004` | Crypto constant identification | SHA-256 initial constants @0x7f300 |
| `ev-000005` | Crypto constant identification | SHA-256 round constants @0x7f320 |
| `ev-000006` | Crypto constant identification | SHA-1 initial constants @0x7e100 |
| `ev-000007` | Crypto constant identification | MD5 initial constants @0x7e100 |
| `ev-000008` | decompile.ghidra | Entry function decompilation: __libc_start_main into 0x4016ec |
| `ev-000009` | decompile.ghidra | FUN_00401508 decompilation: connect 8.8.8[.]8:53 + getsockname + ioctl 0x8912/0x8921 to obtain egress address/MAC |
| `ev-000010` | dyn.exec | Hardened instance bare-metal execution: MIPS BE run via qemu-user, exit code 0, banner printed |
| `ev-000024` | dyn.trace.strace | socket(AF_INET, SOCK_RAW, IPPROTO_UDP) denied with EPERM |
| `ev-000025` | dyn.trace.strace | socket(AF_INET, SOCK_RAW, IPPROTO_TCP) denied with EPERM |
| `ev-000026` | dyn.trace.strace | access("/dev/watchdog") |
| `ev-000027` | dyn.trace.strace | openat("/dev/watchdog", O_RDWR) |
| `ev-000028` | dyn.trace.strace | access("/dev/misc/watchdog") |
| `ev-000029` | dyn.trace.strace | openat("/dev/misc/watchdog", O_RDWR) |
| `ev-000031` | dyn.trace.strace | connect(3, 8.8.8[.]8:53) for local address probing |
| `ref:e46213bbbc` | dyn.trace.strace | Full strace: prctl name change, chdir("/"), abstract UNIX socket six_sayven-63464, 127.0.0[.]1:63464 connection, banner output |

</details>

---

_This report's sample is not public; IOCs have been de-weaponized and are for security research only._
