---
title: "Malware Analysis: Linux/ARM DoH-Tunnel Backdoor (unattributed) (ELF · elf · ffa6a217)"
published: 2026-10-29
draft: false
description: "Malicious (low confidence): Linux/ARM DoH-Tunnel Backdoor (unattributed) · backdoor/implant · difficulty medium · dynamic sandbox + static decompilation"
tags: ["backdoor", "implant", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-10-29-Linux-ARM-DoH-Tunnel-Backdoor-unattributed-ffa6a217"
---

> [!WARNING]
> **Verdict: malicious** · Family **Linux/ARM DoH-Tunnel Backdoor (unattributed)** (uncertain) · Confidence **low**
> 
> The 32-bit ARM sample was actually executed in a hardened Linux analysis instance, directly observing a double-fork daemon, a process name masquerading as libssl.so, binding of the abstract UNIX socket @fdrunkkkk@@@@5, writing of /proc/self/oom_score_adj=-1000, and TLS connection attempts to public DNS-over-HTTPS resolvers such as 8.8.8[.]8/1.1.1[.]1/9.9.9[.]9 on port 443; combined with static decompilation, it is confirmed to use POST /dns-query with a custom-encoded DNS tunnel to send and receive command data. The analysis environment has no external network and all connections were refused, so no successful callback or command execution was observed.

## At a Glance

| Item | Content |
|:--|:--|
| Family | **Linux/ARM DoH-Tunnel Backdoor (unattributed)** · _uncertain_ |
| Confidence | **low** |
| Behavior class | backdoor · implant |
| Difficulty | medium |
| First seen | 2026-10-29 06:33:35 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/ffa6a2173ab38292e4f095e608bd8a744eb2a4bb0591acd9eb9ebfe544e8ea6a/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Double-fork daemon</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1564</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Masquerades as libssl.so</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1036.005</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="134" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Abstract control socket</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1559</text>
<rect x="586" y="123" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="138" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="184" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="184" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Raises OOM immunity</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1562.001</text>
<rect x="586" y="173" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="188" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="234" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="234" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Callback via public DoH</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1071.004</text>
<rect x="586" y="223" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="238" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `ffa6a2173ab38292e4f095e608bd8a744eb2a4bb0591acd9eb9ebfe544e8ea6a` |
| MD5 | _not recorded_ |
| Size | 481,920 bytes (470.6 KB) |
| Type | ELF · `elf` |

## Behavior Analysis

**9** behaviors in total, each backed by evidence; **3** of them are obtainable statically and **6** were obtained through dynamic analysis.

### 1. Double-Fork Daemon

`T1564` · Confidence **high** · Dynamic

Secondary fork + setsid to detach from the session, redirect stdin/stdout/stderr to /dev/null, and stay resident in the background.

> **Evidence**: Dynamic events: clone(90)->setsid->clone(92)->dup2(4,0/1/2); entry 0x8190, main 0xd484
> 
> **Source**: `ref:ef353ffb33` · `ref:4c59457e66` · `ref:3ef991b956`

### 2. Masquerades as libssl.so

`T1036.005` · Confidence **high** · Dynamic

After startup it calls prctl(PR_SET_NAME, "libssl.so") to change the process display name, impersonating a process related to the system TLS library.

> **Evidence**: Dynamic event prctl(PR_SET_NAME, "libssl.so"); statically there are numerous wolfSSL/TLS strings corroborating the plausibility of the masquerade
> 
> **Source**: `ref:ef353ffb33` · `ref:202f89ddb9`

### 3. Occupies an Abstract Control Socket

`T1559` · Confidence **high** · Dynamic

Binds and listens on the abstract UNIX socket @fdrunkkkk@@@@5 (backlog=1), used as a single-instance lock and local command channel.

> **Evidence**: Dynamic events bind(AF_UNIX, sun_path=@"fdrunkkkk@@@@5") + listen(1); the string is located at file offset 0x669a8
> 
> **Source**: `ref:ef353ffb33` · `ref:202f89ddb9`

### 4. Raises the OOM Immunity Value

`T1562.001` · Confidence **high** · Dynamic

Writes -1000 to /proc/self/oom_score_adj, attempting to reduce the probability of being terminated by the system OOM killer.

> **Evidence**: Dynamic events openat("/proc/self/oom_score_adj", O_WRONLY) + write("-1000") returns EACCES
> 
> **Source**: `ref:ef353ffb33`

### 5. Callback via Public DoH

`T1071.004` · Confidence **high** · Dynamic

Initiates TLS connections to port 443 of public resolvers such as 8.8.8[.]8/1.1.1[.]1/9.9.9[.]9, using domains such as dns.google as Host/SNI, sends POST /dns-query requests, and blends C2 traffic into normal DoH resolution.

> **Evidence**: 0xe478 constructs the DoH request ("POST /dns-query HTTP/1.1" at 0x66a40); dynamic events connect :443 to 8.8.8[.]8, 4.4.8[.]8, 1.1.1[.]1, 1.0.0[.]1, 9.9.9[.]9, and others
> 
> **Source**: `ref:0ec1694b0b` · `ref:ef353ffb33` · `ref:202f89ddb9`

### 6. Builds DNS Tunnel Queries

`T1001` · Confidence **high** · Static

Uses a custom base64 alphabet to encode data into the DNS query name, assembles the 2-byte transaction ID, query type and CLASS=1 itself, and sends it out over TCP 443 DoH.

> **Evidence**: The embedded alphabet string in 0xe478 is located at 0x66a00; builds a DNS message with the 0x0100 flag and QDCOUNT=1
> 
> **Source**: `ref:0ec1694b0b` · `ref:202f89ddb9`

### 7. Decodes Hidden IPs from TXT

`T1001` · Confidence **high** · Static

Parses DNS TXT (type=0x10) responses, splits entries by '|', and applies XOR (0x6b/0x9e/0x3f/0x2a) to hexadecimal nibbles to recover a list of dotted IPv4 addresses.

> **Evidence**: 0xfdf8 decoding function; 0xebac/0xf408 filter by TXT record type and split by '|'
> 
> **Source**: `ref:5dcd44b8a5` · `ref:a01fc398b3` · `ref:ebc5205315`

### 8. Wipes Process Arguments

`T1070` · Confidence **medium** · Static

After startup it performs memset on the argv/environment area, erasing command-line and argument traces and increasing the difficulty of post-incident forensics.

> **Evidence**: 0xd310 computes the end of the argv area and memsets(ptr,0,len); called by main 0xd484 before daemonization
> 
> **Source**: `ref:a814d82e72` · `ref:3ef991b956`

### 9. Detects Parent Process Liveness

`T1622` · Confidence **medium** · Dynamic

Prints "father?" to standard output and uses fork/UNIX sockets for parent/child and single-instance checks, affecting the startup path and debugging behavior.

> **Evidence**: Dynamic event write(1,"father?") immediately followed by clone/setsid; this string has no plaintext form in the static string table and is generated at runtime
> 
> **Source**: `ref:ef353ffb33` · `ref:3ef991b956`


## IOCs (Defanged)

### Network

:::caution
**The real server side remains unverified**: the connections/handshakes above were completed against a locally controlled emulation service, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxps://dns[.]google/dns-query (direct connect 8[.]8[.]8[.]8:443, SNI/Host=dns[.]google)` | 443 | c2 | Static | ⏳ Not observed |
| http | `hxxps://cloudflare-dns[.]com/dns-query (direct connect 1[.]1[.]1[.]1 / 1[.]0[.]0[.]1:443)` | 443 | c2 | Static | ⏳ Not observed |
| http | `hxxps://dns[.]quad9[.]net/dns-query (direct connect 9[.]9[.]9[.]9:443; fallback address constants are stored in host byte order, actual connect 112[.]112[.]112[.]149)` | 443 | c2 | Static | ⏳ Not observed |
| http | `hxxps://dns[.]adguard-dns[.]com/dns-query (fallback address constants are stored in host byte order, actual connect 14[.]14[.]140[.]94 / 15[.]15[.]140[.]94)` | 443 | c2 | Static | ⏳ Not observed |

### Host

**Mutex**

- `Abstract UNIX socket @fdrunkkkk@@@@5`

**Drop paths**

- `/dev/null`
- `/proc/self/exe`
- `/dev/urandom`
- `/etc/resolv.conf`
- `/etc/hosts`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `dns[.]google, cloudflare-dns[.]com, dns[.]quad9[.]net, dns[.]adguard-dns[.]com (as DoH Host/SNI)` | Yes | Static |
| `c2_ips` | `8[.]8[.]8[.]8, 4[.]4[.]8[.]8, 1[.]1[.]1[.]1, 1[.]0[.]0[.]1, 9[.]9[.]9[.]9, 112[.]112[.]112[.]149, 14[.]14[.]140[.]94, 15[.]15[.]140[.]94` | Yes | Dynamic |
| `transport` | `HTTPS POST /dns-query, Content-Type: application/dns-message, TLS 1.3 (statically linked wolfSSL)` | Yes | Static |
| `dns_tunnel_encoding` | `Query names are encoded with a custom base64 alphabet; TXT record bodies are split by '\|' and IPv4 addresses are recovered with XOR 0x6b/0x9e/0x3f/0x2a` | No | Static |
| `mutex` | `@fdrunkkkk@@@@5` | Yes | Dynamic |
| `process_name` | `libssl.so` | Yes | Dynamic |
| `launch_argument` | `argv[1] serves as the tunnel label/domain base; exits directly when the argument is missing` | Yes | Static |
| `encryption_algo` | `TLS13-AES256-GCM-SHA384` | No | Static |

## Do Not Misjudge

:::important
The following conclusions **are easy to misjudge**; please note this when citing this report.

- It cannot be judged as ransomware or an infostealer: no file encryption, credential/browser data, or keyring collection code was found.
- It cannot be judged that a C2 connection succeeded or that commands were received: the analysis environment has no external network, and all 443/53 connections returned ENETUNREACH.
- It cannot be judged to have scanning, self-propagation, or DDoS capability: no scanner, exploit, or attack command table was seen.
- It cannot be concluded from the embedded /bin/sh and system alone that it can execute arbitrary commands: that string belongs to the statically linked C runtime, and no call-chain evidence on the malicious side was obtained.
- A specific family cannot be determined from this sample: there is no external intelligence, YARA, or multi-engine result support, and the family field is only an unattributed candidate.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The analysis environment has no external network; the DoH session and the DNS tunnel application-layer protocol can only be reconstructed at the static level, and no real commands, file drops, or lateral behavior were observed.
2. The process name masquerade, abstract socket, OOM immunity and DoH callback are all real execution observations; a successful C2 callback and subsequent payloads still await verification in a networked environment.
3. Family attribution lacks external intelligence/multi-engine corroboration; only an unattributed candidate is given based on behavioral characteristics.
4. Decompilation contains type-inference noise; the semantics of a few stack constant structures (such as the 0x50-byte handshake buffer) are not fully confirmed.
5. No persistence writes such as cron/systemd/rc were observed, but this cannot be taken to mean it lacks persistence capability.

## Evidence Index

<details>
<summary>Expand 12 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ref:f9c7ee691f` | ELF structure parsing | ELF32 ARM little-endian, EXEC, statically linked, entry VA 0x8190, 3 PT_LOAD segments, no NEEDED |
| `ref:57eb6d0cad` | elf.sections | .text 419988 bytes entropy 6.07, .rodata 41392 bytes entropy 6.60, no high-entropy encrypted section |
| `ref:202f89ddb9` | String extraction | Hits on the DoH request template, four DoH domains, the custom base64 alphabet, @fdrunkkkk@@@@5, and libssl/TLS-related strings |
| `ref:8232b44f6f` | Cryptographic constant identification | AES/SHA-1/SHA-256/MD5 constants (AES inverse S-box, SHA-256 initial values, etc.), corresponding to the statically linked crypto library |
| `ref:4c59457e66` | decompile.function | entry 0x8190 standard glibc startup path, resolving main=0xd484 |
| `ref:3ef991b956` | decompile.function | main 0xd484: requires argv[1], sets up the AF_UNIX listener, daemonization, DoH connection and command loop |
| `ref:0ec1694b0b` | decompile.function | 0xe478: builds the DNS query and TLS connection and sends POST /dns-query, validates the response header |
| `ref:ebc5205315` | decompile.function | 0xf408: fetches A/TXT records via direct UDP/53 to 8.8.8[.]8 and parses entries |
| `ref:a01fc398b3` | decompile.function | 0xebac: parses DNS TXT (type 0x10) responses, splits by '\|', decodes entries one by one |
| `ref:5dcd44b8a5` | decompile.function | 0xfdf8: recovers IPv4 from encoded strings with XOR 0x6b/0x9e/0x3f/0x2a |
| `ref:a814d82e72` | decompile.function | 0xd310: computes the end of the argv area and memsets the command line to zero |
| `ref:ef353ffb33` | dyn.trace | Actual execution syscall sequence: daemonization, PR_SET_NAME=libssl.so, bind @fdrunkkkk@@@@5, oom_score_adj write, connections to 8.8.8[.]8/1.1.1[.]1/9.9.9[.]9 etc. on 443 and 53 (all ENETUNREACH) |

</details>

---

_The sample in this report is not public; IOCs have been defanged and are provided for security research only._
